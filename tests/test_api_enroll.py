"""Enrollment: /v1/enroll/begin challenge flow, /v1/enroll/finish verification,
/v1/enroll/renew claim rotation (enrollment-spec sections 2.1-2.5).
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import time
import uuid
from typing import Any

import pytest
import relay_client

from apns_relay.grants import canonical_claims, issue_grant, sha256_token
from apns_relay.signing import generate_keypair
from tests.conftest import (
    APP_ID,
    BUNDLE_ID,
    DEST_TOKEN,
    OTHER_APP_ID,
    OTHER_BUNDLE_ID,
    OTHER_TENANT_ID,
    TENANT_ID,
    b64,
    do_push,
    enroll,
    make_root,
    mint_assertion,
    mint_attestation,
    post_signed,
    push_payload,
    register_tenant,
)


def set_config(env: Any, **app_changes: Any) -> None:
    apps = tuple(
        dataclasses.replace(app, **app_changes) if app.id == APP_ID else app
        for app in env.state.config.apps
    )
    env.state.config = dataclasses.replace(env.state.config, apps=apps)


def begin(
    env: Any, *, app: str = APP_ID, tenant_id: str = TENANT_ID, destination: str = DEST_TOKEN
) -> tuple[dict, str]:
    """POST /v1/enroll/begin and return (response body, pushed nonce)."""
    response = env.client.post(
        "/v1/enroll/begin",
        json={"app": app, "tenantId": tenant_id, "destinationToken": destination},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    nonce = env.apns.challenge_for(body["challengeId"])["body"]["relay-challenge"]["nonce"]
    return body, nonce


def finish_payload(
    env: Any,
    begin_body: dict,
    nonce: str,
    *,
    tenant_id: str = TENANT_ID,
    root: Any = None,
    rp_id: str = BUNDLE_ID,
    kinds: tuple[str, ...] = ("alert",),
    pubkey: str | None = None,
    ttl: int | None = None,
    assertion_nonce: str | None = None,
    corrupt: bool = False,
    attestation: str | None = None,
    assertion: str | None = None,
) -> dict:
    if attestation is None:
        root = root or env.roots["production"]
        attestation, cred_key = mint_attestation(root, rp_id=rp_id)
        assertion = mint_assertion(
            cred_key,
            nonce=assertion_nonce or nonce,
            server_challenge=begin_body["serverChallenge"],
            rp_id=rp_id,
            corrupt=corrupt,
        )
    if pubkey is None:
        pubkey = generate_keypair()[1]
    payload: dict[str, Any] = {
        "challengeId": begin_body["challengeId"],
        "attestation": attestation,
        "assertion": assertion,
        "tenantId": tenant_id,
        "tenantPubkey": pubkey,
        "kinds": list(kinds),
    }
    if ttl is not None:
        payload["ttl"] = ttl
    return payload


def post_finish(env: Any, payload: dict):
    return env.client.post("/v1/enroll/finish", json=payload)


# -- begin ---------------------------------------------------------------------------


def test_begin_shape_and_challenge_push(env, clock) -> None:
    register_tenant(env.client)
    body, nonce = begin(env)
    challenge_id = body["challengeId"]
    uuid.UUID(challenge_id)  # well-formed uuid
    assert isinstance(body["serverChallenge"], str) and len(body["serverChallenge"]) > 20
    assert body["expiresAt"] == int(clock.time()) + 600

    call = env.apns.challenge_for(challenge_id)
    assert call["headers"]["apns-topic"] == BUNDLE_ID
    assert call["headers"]["apns-push-type"] == "background"
    assert call["headers"]["apns-priority"] == "5"
    assert call["headers"]["apns-expiration"] == str(int(clock.time()) + 600)
    assert call["body"]["aps"] == {"content-available": 1}
    assert call["body"]["relay-challenge"] == {"id": challenge_id, "nonce": nonce}
    assert env.state.metrics.values["enrolls_total"] == {"begin": 1}


def test_begin_falls_through_to_production(env, clock) -> None:
    register_tenant(env.client)
    env.apns.queue.append((410, "BadDeviceToken"))  # sandbox rejects this token
    body, _nonce = begin(env)
    assert len(env.apns.calls) == 2
    assert env.apns.calls[1]["url"] == f"https://api.push.apple.com/3/device/{DEST_TOKEN}"
    challenge, failure = env.store.pop_challenge(body["challengeId"], clock.time())
    assert failure is None
    assert challenge.environment == "production"


def test_begin_all_environments_rejected(env) -> None:
    register_tenant(env.client)
    env.apns.queue.extend([(410, "BadDeviceToken"), (410, "BadDeviceToken")])
    response = env.client.post(
        "/v1/enroll/begin",
        json={"app": APP_ID, "tenantId": TENANT_ID, "destinationToken": DEST_TOKEN},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalidDestination", "detail": "BadDeviceToken"}
    challenge_id = env.apns.calls[0]["body"]["relay-challenge"]["id"]
    assert env.store.pop_challenge(challenge_id, time.time()) == (None, "unknown_challenge")


def test_begin_retryable_failure_stops_iteration(env) -> None:
    register_tenant(env.client)
    env.apns.queue.append((429, "TooManyRequests"))
    response = env.client.post(
        "/v1/enroll/begin",
        json={"app": APP_ID, "tenantId": TENANT_ID, "destinationToken": DEST_TOKEN},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalidDestination", "detail": "TooManyRequests"}
    assert len(env.apns.calls) == 1  # production never attempted


def test_begin_empty_reason_falls_back_to_outcome(env) -> None:
    register_tenant(env.client)
    env.apns.queue.append((500, ""))
    response = env.client.post(
        "/v1/enroll/begin",
        json={"app": APP_ID, "tenantId": TENANT_ID, "destinationToken": DEST_TOKEN},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalidDestination", "detail": "retryable"}


def test_begin_unknown_app(env) -> None:
    response = env.client.post(
        "/v1/enroll/begin",
        json={"app": "no-such-app", "tenantId": TENANT_ID, "destinationToken": DEST_TOKEN},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "unknown_app"}


def test_begin_disabled_app(env) -> None:
    register_tenant(env.client)
    set_config(env, enabled=False)
    response = env.client.post(
        "/v1/enroll/begin",
        json={"app": APP_ID, "tenantId": TENANT_ID, "destinationToken": DEST_TOKEN},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "unknown_app"}


def test_begin_unknown_tenant(env) -> None:
    response = env.client.post(
        "/v1/enroll/begin",
        json={"app": APP_ID, "tenantId": "ghost.example.com", "destinationToken": DEST_TOKEN},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "unknown_tenant"}


def test_begin_rate_limited(env) -> None:
    register_tenant(env.client)
    for i in range(10):
        begin(env, destination=f"{i:064x}")
    blocked = env.client.post(
        "/v1/enroll/begin",
        json={"app": APP_ID, "tenantId": TENANT_ID, "destinationToken": DEST_TOKEN},
    )
    assert blocked.status_code == 429
    assert blocked.json() == {"error": "rate_limited"}


def test_begin_invalid_destination_token_format(env) -> None:
    register_tenant(env.client)
    response = env.client.post(
        "/v1/enroll/begin",
        json={"app": APP_ID, "tenantId": TENANT_ID, "destinationToken": "not-hex!" * 5},
    )
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_request"


# -- finish: happy path ---------------------------------------------------------------


def test_finish_grant_and_consent(env, clock) -> None:
    token = register_tenant(env.client)
    begin_body, nonce = begin(env)
    payload = finish_payload(env, begin_body, nonce)
    response = post_finish(env, payload)
    assert response.status_code == 200, response.text
    body = response.json()

    consent = body["consent"]
    assert set(consent) == {
        "tenant",
        "app",
        "appDisplayName",
        "kinds",
        "boundAt",
        "expiresAt",
        "environment",
    }
    assert consent["tenant"] == TENANT_ID
    assert consent["app"] == APP_ID
    assert consent["appDisplayName"] == "Test App"
    assert consent["kinds"] == ["alert"]
    assert consent["boundAt"] == int(clock.time())
    assert consent["expiresAt"] - consent["boundAt"] == 3600
    assert consent["environment"] == "sandbox"

    assert env.store.tenant(TENANT_ID, APP_ID).pubkey == payload["tenantPubkey"]
    assert env.store.tenant(TENANT_ID, APP_ID).token_digest == relay_client_token_digest(token)

    claims = relay_client.grant_claims(body["grant"])
    assert claims == {
        "jti": claims["jti"],
        "iss": env.state.issuer_id,
        "tok": "sha256:" + sha256_token(DEST_TOKEN),
        "ten": TENANT_ID,
        "tpk": payload["tenantPubkey"],
        "app": APP_ID,
        "kinds": ["alert"],
        "env": "sandbox",
        "iat": int(clock.time()),
        "exp": int(clock.time()) + 3600,
        "ttl": 3600,
    }
    uuid.UUID(claims["jti"])
    assert env.state.metrics.values["enrolls_total"] == {"begin": 1, "finish": 1}


def relay_client_token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def test_finish_challenge_is_single_use(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    first = post_finish(env, finish_payload(env, begin_body, nonce))
    assert first.status_code == 200, first.text
    second = post_finish(env, finish_payload(env, begin_body, nonce))
    assert second.status_code == 400
    assert second.json() == {"error": "unknown_challenge"}


@pytest.mark.parametrize(("requested", "expected"), [(100, 900), (999_999, 86_400), (None, 3600)])
def test_finish_ttl_clamped(env, clock, requested: int | None, expected: int) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    payload = finish_payload(env, begin_body, nonce, ttl=requested)
    response = post_finish(env, payload)
    assert response.status_code == 200, response.text
    claims = relay_client.grant_claims(response.json()["grant"])
    assert claims["ttl"] == expected
    assert claims["exp"] - claims["iat"] == expected


# -- finish: failures -------------------------------------------------------------------


def test_finish_unknown_challenge(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    payload = finish_payload(env, begin_body, nonce)
    payload["challengeId"] = "11111111-2222-3333-4444-555555555555"
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "unknown_challenge"}


def test_finish_expired_challenge(env, clock) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    clock.advance(601)
    response = post_finish(env, finish_payload(env, begin_body, nonce))
    assert response.status_code == 400
    assert response.json() == {"error": "challenge_expired"}


def test_finish_tenant_mismatch(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    response = post_finish(env, finish_payload(env, begin_body, nonce, tenant_id=OTHER_TENANT_ID))
    assert response.status_code == 400
    assert response.json() == {"error": "challenge_tenant_mismatch"}


def test_finish_app_removed_after_begin(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    env.state.config = dataclasses.replace(
        env.state.config,
        apps=tuple(app for app in env.state.config.apps if app.id != APP_ID),
    )
    response = post_finish(env, finish_payload(env, begin_body, nonce))
    assert response.status_code == 400
    assert response.json() == {"error": "unknown_app"}


def test_finish_app_disabled_after_begin(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    set_config(env, enabled=False)
    response = post_finish(env, finish_payload(env, begin_body, nonce))
    assert response.status_code == 400
    assert response.json() == {"error": "unknown_app"}


def test_finish_tenant_deleted_after_begin(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    env.store.delete_tenant(TENANT_ID, APP_ID)
    response = post_finish(env, finish_payload(env, begin_body, nonce))
    assert response.status_code == 400
    assert response.json() == {"error": "unknown_tenant"}


def test_finish_attest_root_not_configured(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    env.state.config = dataclasses.replace(
        env.state.config,
        enrollment=dataclasses.replace(env.state.config.enrollment, attest_root_certs={}),
    )
    response = post_finish(env, finish_payload(env, begin_body, nonce))
    assert response.status_code == 400
    assert response.json() == {"error": "attestation_unavailable"}


def test_finish_attest_root_unreadable(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    garbage = env.base / "garbage-root.pem"
    garbage.write_bytes(b"this is not a certificate")
    env.state.config = dataclasses.replace(
        env.state.config,
        enrollment=dataclasses.replace(
            env.state.config.enrollment, attest_root_certs={"production": garbage}
        ),
    )
    response = post_finish(env, finish_payload(env, begin_body, nonce))
    assert response.status_code == 400
    assert response.json() == {"error": "attestation_unavailable"}


def test_finish_malformed_attestation_b64(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    payload = finish_payload(env, begin_body, nonce)
    payload["attestation"] = "!!!not-base64!!!" * 2
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "malformed_attestation"}


def test_finish_attestation_not_cbor(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    payload = finish_payload(env, begin_body, nonce)
    payload["attestation"] = b64(b"this is not cbor at all")
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "malformed_attestation"}


def test_finish_malformed_assertion_b64(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    payload = finish_payload(env, begin_body, nonce)
    payload["assertion"] = "!!!not-base64!!!" * 2
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "malformed_assertion"}


def test_finish_attestation_app_id_mismatch(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    attestation, cred_key = mint_attestation(env.roots["production"], rp_id="com.other.bundle")
    assertion = mint_assertion(
        cred_key, nonce=nonce, server_challenge=begin_body["serverChallenge"]
    )
    payload = finish_payload(env, begin_body, nonce, attestation=attestation, assertion=assertion)
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "app_id_mismatch"}


def test_finish_attestation_chain_verify_failed(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    stranger_root = make_root("Stranger Root")
    attestation, cred_key = mint_attestation(stranger_root, rp_id=BUNDLE_ID)
    assertion = mint_assertion(
        cred_key, nonce=nonce, server_challenge=begin_body["serverChallenge"]
    )
    payload = finish_payload(env, begin_body, nonce, attestation=attestation, assertion=assertion)
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "chain_verify_failed"}


def test_finish_attestation_cert_expired(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    attestation, cred_key = mint_attestation(
        env.roots["production"], rp_id=BUNDLE_ID, expired_leaf=True
    )
    assertion = mint_assertion(
        cred_key, nonce=nonce, server_challenge=begin_body["serverChallenge"]
    )
    payload = finish_payload(env, begin_body, nonce, attestation=attestation, assertion=assertion)
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "cert_expired"}


def test_finish_assertion_signature_invalid(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    response = post_finish(env, finish_payload(env, begin_body, nonce, corrupt=True))
    assert response.status_code == 400
    assert response.json() == {"error": "assertion_signature_invalid"}


def test_finish_assertion_nonce_mismatch(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    payload = finish_payload(env, begin_body, nonce, assertion_nonce="wrong-nonce-value")
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "assertion_signature_invalid"}


def test_finish_kinds_not_allowed(env) -> None:
    register_tenant(env.client, TENANT_ID, OTHER_APP_ID)
    begin_body, nonce = begin(env, app=OTHER_APP_ID, destination="ab" * 32)
    payload = finish_payload(env, begin_body, nonce, rp_id=OTHER_BUNDLE_ID, kinds=("background",))
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "kinds_not_allowed"}


def test_finish_invalid_pubkey(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    payload = finish_payload(env, begin_body, nonce, pubkey="A" * 44)
    response = post_finish(env, payload)
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_pubkey"}


def test_finish_rate_limited(env) -> None:
    register_tenant(env.client)
    begin_body, nonce = begin(env)
    for _ in range(9):
        begin_body, nonce = begin(env)
    blocked = post_finish(env, finish_payload(env, begin_body, nonce))
    assert blocked.status_code == 429
    assert blocked.json() == {"error": "rate_limited"}


# -- renew ------------------------------------------------------------------------------


def renew(env: Any, enrolled: Any, *, ttl: int | None = None):
    payload: dict[str, Any] = {"grant": enrolled.grant}
    if ttl is not None:
        payload["ttl"] = ttl
    return post_signed(
        env.client, "/v1/enroll/renew", payload, enrolled.token, enrolled.private_key
    )


def crafted_grant(env: Any, enrolled: Any, **overrides: Any) -> str:
    params: dict[str, Any] = {
        "token_digest": sha256_token(enrolled.destination),
        "tenant_id": enrolled.tenant_id,
        "tenant_pubkey": enrolled.pubkey,
        "app_id": APP_ID,
        "kinds": list(enrolled.kinds),
        "environment": "sandbox",
        "ttl": 3600,
    }
    params.update(overrides)
    return issue_grant(env.state.issuer_key, env.state.issuer_id, **params)


def test_renew_rotates_jti_and_preserves_claims(env, clock) -> None:
    enrolled = enroll(env)
    response = renew(env, enrolled)
    assert response.status_code == 200, response.text
    body = response.json()
    old = relay_client.grant_claims(enrolled.grant)
    new = relay_client.grant_claims(body["grant"])
    assert new["jti"] != old["jti"]
    for claim in ("iss", "tok", "ten", "tpk", "app", "kinds", "env"):
        assert new[claim] == old[claim]
    assert new["iat"] == int(clock.time())
    assert new["ttl"] == 3600
    assert new["exp"] - new["iat"] == 3600
    assert body["expiresAt"] == new["exp"]
    assert env.state.metrics.values["enrolls_total"]["renew"] == 1


@pytest.mark.parametrize(("requested", "expected"), [(100, 900), (999_999, 86_400)])
def test_renew_ttl_clamped(env, clock, requested: int, expected: int) -> None:
    enrolled = enroll(env)
    response = renew(env, enrolled, ttl=requested)
    assert response.status_code == 200, response.text
    claims = relay_client.grant_claims(response.json()["grant"])
    assert claims["ttl"] == expected
    assert claims["exp"] - claims["iat"] == expected


def test_renew_expired_grant(env, clock) -> None:
    enrolled = enroll(env, ttl=900)
    clock.advance(901)
    response = renew(env, enrolled)
    assert response.status_code == 403
    assert response.json() == {"error": "grant_expired"}


def test_renew_revoked_grant(env) -> None:
    enrolled = enroll(env)
    revoked = post_signed(
        env.client,
        "/v1/revoke",
        {"grant": enrolled.grant},
        enrolled.token,
        enrolled.private_key,
    )
    assert revoked.status_code == 200, revoked.text
    response = renew(env, enrolled)
    assert response.status_code == 403
    assert response.json() == {"error": "grant_revoked"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"tenant_id": OTHER_TENANT_ID},  # wrong `ten`
        {"tenant_pubkey": "B" * 44},  # right `ten`, wrong `tpk`
        {"app_id": OTHER_APP_ID},  # right `ten`+`tpk`, wrong `app`
    ],
)
def test_renew_grant_mismatch(env, overrides: dict) -> None:
    enrolled = enroll(env)
    grant = crafted_grant(env, enrolled, **overrides)
    response = post_signed(
        env.client, "/v1/enroll/renew", {"grant": grant}, enrolled.token, enrolled.private_key
    )
    assert response.status_code == 403
    assert response.json() == {"error": "grant_mismatch"}


def test_renew_malformed_grant(env) -> None:
    enrolled = enroll(env)
    response = post_signed(
        env.client,
        "/v1/enroll/renew",
        {"grant": "v1.aaaa.bbbb"},
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}


def test_renew_grant_bad_signature(env) -> None:
    enrolled = enroll(env)
    grant = enrolled.grant
    tampered = grant[:8] + ("A" if grant[8] != "A" else "B") + grant[9:]
    response = post_signed(
        env.client,
        "/v1/enroll/renew",
        {"grant": tampered},
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}


def test_renew_grant_missing_required_claim(env) -> None:
    enrolled = enroll(env)
    claims = relay_client.grant_claims(enrolled.grant)
    claims.pop("ttl")
    response = post_signed(
        env.client,
        "/v1/enroll/renew",
        {"grant": sign_claims(env, claims)},
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}


def sign_claims(env: Any, claims: dict) -> str:
    raw = canonical_claims(claims)
    signature = env.state.issuer_key.sign(raw)
    return f"v1.{b64u(raw)}.{b64u(signature)}"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def test_renew_app_disabled(env) -> None:
    enrolled = enroll(env)
    set_config(env, enabled=False)
    response = renew(env, enrolled)
    assert response.status_code == 403
    assert response.json() == {"error": "app_disabled"}


def test_push_works_after_renew_with_new_grant(env, clock) -> None:
    enrolled = enroll(env)
    response = renew(env, enrolled)
    assert response.status_code == 200, response.text
    renewed = response.json()["grant"]
    pushed = do_push(
        env.client, push_payload(enrolled, grant=renewed), enrolled.token, enrolled.private_key
    )
    assert pushed.status_code == 200, pushed.text
    assert pushed.json()["result"] == "accepted"
