"""POST /v1/revoke: jti denylisting (spec §2.6), idempotent on expiry.

A revoked jti is denylisted until its natural exp; a subsequent push with the
same grant is refused with ``grant_revoked``.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import pytest
import relay_client

from apns_relay.grants import canonical_claims, issue_grant, sha256_token
from tests.conftest import (
    APP_ID,
    OTHER_APP_ID,
    OTHER_TENANT_ID,
    do_push,
    enroll,
    post_signed,
    push_payload,
)


def revoke(env: Any, enrolled: Any, grant: str | None = None):
    return post_signed(
        env.client,
        "/v1/revoke",
        {"grant": grant or enrolled.grant},
        enrolled.token,
        enrolled.private_key,
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


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sign_claims(env: Any, claims: dict) -> str:
    raw = canonical_claims(claims)
    signature = env.state.issuer_key.sign(raw)
    return f"v1.{b64u(raw)}.{b64u(signature)}"


def test_revoke_denylists_jti_and_blocks_next_push(env) -> None:
    enrolled = enroll(env)
    jti = relay_client.grant_claims(enrolled.grant)["jti"]
    response = revoke(env, enrolled)
    assert response.status_code == 200, response.text
    assert response.json() == {"revoked": jti}
    assert env.store.is_denied([jti], time.time())
    assert env.state.metrics.values["revocations_total"] == {"ok": 1}

    pushed = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert pushed.status_code == 403
    assert pushed.json() == {"error": "grant_revoked"}


def test_revoke_expired_grant_stores_nothing(env, clock) -> None:
    enrolled = enroll(env, ttl=900)
    jti = relay_client.grant_claims(enrolled.grant)["jti"]
    clock.advance(901)
    response = revoke(env, enrolled)
    assert response.status_code == 200, response.text
    assert response.json() == {"revoked": jti}
    assert not env.store.is_denied([jti], clock.time())
    assert env.store.list_denied(clock.time()) == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"tenant_id": OTHER_TENANT_ID},  # wrong `ten`
        {"tenant_pubkey": "B" * 44},  # right `ten`, wrong `tpk`
        {"app_id": OTHER_APP_ID},  # right `ten`+`tpk`, wrong `app`
    ],
)
def test_revoke_grant_mismatch(env, overrides: dict) -> None:
    enrolled = enroll(env)
    grant = crafted_grant(env, enrolled, **overrides)
    response = revoke(env, enrolled, grant)
    assert response.status_code == 403
    assert response.json() == {"error": "grant_mismatch"}


def test_revoke_malformed_grant(env) -> None:
    enrolled = enroll(env)
    response = revoke(env, enrolled, "v1.aaaa.bbbb")
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}


def test_revoke_grant_bad_signature(env) -> None:
    enrolled = enroll(env)
    grant = enrolled.grant
    tampered = grant[:8] + ("A" if grant[8] != "A" else "B") + grant[9:]
    response = revoke(env, enrolled, tampered)
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}


def test_revoke_grant_missing_required_claim(env) -> None:
    enrolled = enroll(env)
    claims = relay_client.grant_claims(enrolled.grant)
    claims.pop("kinds")
    response = revoke(env, enrolled, sign_claims(env, claims))
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}


def test_revoke_is_idempotent_while_grant_valid(env) -> None:
    enrolled = enroll(env)
    first = revoke(env, enrolled)
    second = revoke(env, enrolled)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert env.state.metrics.values["revocations_total"] == {"ok": 2}
