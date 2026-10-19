"""POST /v1/push: grant verification order, quotas, payload policy, outcomes.

Handler order (api.py): app → grant → kind → environment → denylist →
payload build → quota → APNs. APNs results are HTTP 200 with the result
vocabulary; policy failures are stable machine codes.
"""

from __future__ import annotations

import base64
import dataclasses
from typing import Any

import httpx
import pytest
import relay_client

from apns_relay.grants import issue_grant, sha256_token
from apns_relay.signing import generate_keypair
from tests.conftest import (
    APP_ID,
    BUNDLE_ID,
    DEST_TOKEN,
    DEST_TOKEN_2,
    OTHER_APP_ID,
    OTHER_TENANT_ID,
    do_push,
    enroll,
    post_signed,
    push_payload,
    register_tenant,
)

ALERT_CONTENT: dict[str, Any] = {"alert": {"title": "t", "body": "b"}}


def set_config(env: Any, **app_changes: Any) -> None:
    """Point the live state's config at a copy with one App modified."""
    apps = tuple(
        dataclasses.replace(app, **app_changes) if app.id == APP_ID else app
        for app in env.state.config.apps
    )
    env.state.config = dataclasses.replace(env.state.config, apps=apps)


def crafted_grant(env: Any, enrolled: Any, **overrides: Any) -> str:
    """Mint a grant with the relay's own issuer key (test-controlled claims)."""
    params: dict[str, Any] = {
        "token_digest": sha256_token(DEST_TOKEN),
        "tenant_id": enrolled.tenant_id,
        "tenant_pubkey": enrolled.pubkey,
        "app_id": APP_ID,
        "kinds": ["alert"],
        "environment": "sandbox",
        "ttl": 3600,
    }
    params.update(overrides)
    return issue_grant(env.state.issuer_key, env.state.issuer_id, **params)


# -- happy path + APNs result vocabulary -------------------------------------------


def test_push_accepted(env) -> None:
    enrolled = enroll(env)
    response = do_push(
        env.client,
        push_payload(enrolled, eventId="evt-1", expiresAt=1_700_000_999),
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"result": "accepted", "apnsId": "APNS-ID-OK", "detail": None}
    call = env.apns.calls[-1]
    assert call["headers"]["apns-topic"] == BUNDLE_ID
    assert call["headers"]["apns-push-type"] == "alert"
    assert call["headers"]["apns-priority"] == "10"
    assert call["headers"]["apns-collapse-id"] == "evt-1"
    assert call["headers"]["apns-expiration"] == "1700000999"
    assert call["body"] == {"aps": {"alert": {"title": "t", "body": "b"}}}
    assert env.state.metrics.values["pushes_total"] == {"accepted": 1}


@pytest.mark.parametrize(
    ("queued", "result", "detail"),
    [
        ((410, "Unregistered"), "invalidDestination", "Unregistered"),
        ((429, "TooManyRequests"), "retryable", "TooManyRequests"),
        ((400, "PayloadTooLarge"), "rejected", "PayloadTooLarge"),
        ((403, "ExpiredProviderToken"), "retryable", "ExpiredProviderToken"),
    ],
)
def test_push_apns_outcomes(env, queued: tuple, result: str, detail: str) -> None:
    enrolled = enroll(env)
    env.apns.queue.append(queued)
    response = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert response.status_code == 200, response.text
    assert response.json() == {"result": result, "apnsId": None, "detail": detail}
    assert env.state.metrics.values["pushes_total"] == {result: 1}


def test_push_network_error_is_retryable(env) -> None:
    enrolled = enroll(env)
    env.apns.queue.append(httpx.ConnectError("no route to host"))
    response = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert response.status_code == 200, response.text
    assert response.json() == {"result": "retryable", "apnsId": None, "detail": "network_error"}


def test_live_activity_topic_and_type(env) -> None:
    enrolled = enroll(env, kinds=["liveActivity"])
    response = do_push(
        env.client,
        push_payload(
            enrolled,
            kind="liveActivity",
            content={"liveActivity": {"event": "update", "timestamp": 1_700_000_000}},
        ),
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 200, response.text
    call = env.apns.calls[-1]
    assert call["headers"]["apns-topic"] == f"{BUNDLE_ID}.push-type.liveactivity"
    assert call["headers"]["apns-push-type"] == "liveactivity"
    assert call["headers"]["apns-priority"] == "5"
    assert call["body"]["aps"] == {"event": "update", "timestamp": 1_700_000_000}


def test_background_push(env) -> None:
    enrolled = enroll(env, kinds=["background"])
    response = do_push(
        env.client,
        push_payload(enrolled, kind="background", content={"background": {"payload": {"n": 1}}}),
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 200, response.text
    call = env.apns.calls[-1]
    assert call["headers"]["apns-topic"] == BUNDLE_ID
    assert call["headers"]["apns-push-type"] == "background"
    assert call["headers"]["apns-priority"] == "5"
    assert call["body"] == {"aps": {"content-available": 1}, "background": {"n": 1}}


def test_sealed_blob_passed_through_blind(env) -> None:
    enrolled = enroll(env)
    sealed = base64.b64encode(b"s" * 16).decode()
    response = do_push(
        env.client,
        push_payload(enrolled, content={**ALERT_CONTENT, "sealed": sealed}),
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 200, response.text
    assert env.apns.calls[-1]["body"]["sealed"] == sealed


# -- failure codes in handler order --------------------------------------------------


def test_push_requires_enrollment(env) -> None:
    token = register_tenant(env.client)
    private_key, _pubkey = generate_keypair()
    payload = {
        "grant": "v1.aaaa.bbbb",
        "destinationToken": DEST_TOKEN,
        "kind": "alert",
        "content": ALERT_CONTENT,
    }
    response = do_push(env.client, payload, token, private_key)
    assert response.status_code == 401
    assert response.json() == {"error": "enrollment_required"}


def test_push_malformed_grant_is_400(env) -> None:
    enrolled = enroll(env)
    response = do_push(
        env.client,
        push_payload(enrolled, grant="v1.aaaa.bbbb"),
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}


def test_push_grant_bad_signature_is_400(env) -> None:
    enrolled = enroll(env)
    grant = enrolled.grant
    tampered = grant[:8] + ("A" if grant[8] != "A" else "B") + grant[9:]
    response = do_push(
        env.client, push_payload(enrolled, grant=tampered), enrolled.token, enrolled.private_key
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}


def test_push_grant_expired(env, clock) -> None:
    enrolled = enroll(env, ttl=900)
    clock.advance(901)
    response = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert response.status_code == 403
    assert response.json() == {"error": "grant_expired"}


def test_push_grant_revoked_via_revoke_endpoint(env) -> None:
    enrolled = enroll(env)
    revoked = post_signed(
        env.client, "/v1/revoke", {"grant": enrolled.grant}, enrolled.token, enrolled.private_key
    )
    assert revoked.status_code == 200, revoked.text
    response = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert response.status_code == 403
    assert response.json() == {"error": "grant_revoked"}


def test_push_app_disabled(env) -> None:
    enrolled = enroll(env)
    set_config(env, enabled=False)
    response = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert response.status_code == 403
    assert response.json() == {"error": "app_disabled"}
    assert env.state.metrics.values["failures_total"]["app_disabled"] == 1


def test_push_app_removed_from_config(env) -> None:
    enrolled = enroll(env)
    env.state.config = dataclasses.replace(
        env.state.config,
        apps=tuple(app for app in env.state.config.apps if app.id != APP_ID),
    )
    response = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert response.status_code == 403
    assert response.json() == {"error": "app_disabled"}


def test_push_kind_not_allowed_by_grant(env) -> None:
    enrolled = enroll(env)  # grant kinds == ["alert"]
    response = do_push(
        env.client,
        push_payload(enrolled, kind="background", content={"background": {"payload": {}}}),
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 403
    assert response.json() == {"error": "kind_not_allowed"}


def test_push_kind_not_allowed_by_config(env) -> None:
    enrolled = enroll(env, kinds=["alert", "background"])
    set_config(env, kinds=("alert",))
    response = do_push(
        env.client,
        push_payload(enrolled, kind="background", content={"background": {"payload": {}}}),
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 403
    assert response.json() == {"error": "kind_not_allowed"}


def test_push_environment_not_allowed(env) -> None:
    enrolled = enroll(env)  # grant env == sandbox (challenge accepted there first)
    set_config(env, environments=("production",))
    response = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert response.status_code == 403
    assert response.json() == {"error": "environment_not_allowed"}


def test_push_destination_mismatch(env) -> None:
    enrolled = enroll(env)
    response = do_push(
        env.client,
        push_payload(enrolled, destination=DEST_TOKEN_2),
        enrolled.token,
        enrolled.private_key,
    )
    assert response.status_code == 403
    assert response.json() == {"error": "destination_mismatch"}


def test_push_app_mismatch(env) -> None:
    enrolled = enroll(env)
    grant = crafted_grant(env, enrolled, app_id=OTHER_APP_ID)
    response = do_push(
        env.client, push_payload(enrolled, grant=grant), enrolled.token, enrolled.private_key
    )
    assert response.status_code == 403
    assert response.json() == {"error": "app_mismatch"}


def test_push_tenant_mismatch(env) -> None:
    enrolled = enroll(env)
    grant = crafted_grant(env, enrolled, tenant_id=OTHER_TENANT_ID)
    response = do_push(
        env.client, push_payload(enrolled, grant=grant), enrolled.token, enrolled.private_key
    )
    assert response.status_code == 403
    assert response.json() == {"error": "tenant_mismatch"}


def test_push_destination_denied_by_token_hash(env) -> None:
    enrolled = enroll(env)
    claims = relay_client.grant_claims(enrolled.grant)
    env.store.deny(claims["tok"], float(claims["exp"]))
    response = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert response.status_code == 403
    assert response.json() == {"error": "grant_revoked"}


# -- quotas (burst 5/min, daily 10, token 3/min) --------------------------------------


def test_push_burst_rate_limited(env, clock) -> None:
    enrolled = enroll(env)
    # Distinct destinations keep the per-token cap (3/min) out of the way so
    # only the tenant-wide burst (5/min) is under test.
    for i in range(5):
        accepted = push_to_index(env, enrolled, i)
        assert accepted.status_code == 200, accepted.text
    limited = push_to_index(env, enrolled, 5)
    assert limited.status_code == 429
    assert limited.json() == {"error": "rate_limited"}
    assert env.state.metrics.values["failures_total"]["rate_limited"] == 1


def push_to_index(env, enrolled, index: int):
    destination = f"{index:064x}"
    grant = crafted_grant(env, enrolled, token_digest=sha256_token(destination))
    return do_push(
        env.client,
        push_payload(enrolled, destination=destination, grant=grant),
        enrolled.token,
        enrolled.private_key,
    )


def test_push_token_rate_limited(env, clock) -> None:
    enrolled = enroll(env)
    for _ in range(3):
        accepted = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
        assert accepted.status_code == 200, accepted.text
    limited = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert limited.status_code == 429
    assert limited.json() == {"error": "token_rate_limited"}
    assert env.state.metrics.values["failures_total"]["token_rate_limited"] == 1


def test_push_daily_quota_exhausted(env, clock) -> None:
    enrolled = enroll(env)
    for round_index in range(2):
        for step in range(5):
            accepted = push_to_index(env, enrolled, round_index * 5 + step)
            assert accepted.status_code == 200, accepted.text
        clock.advance(61)  # step outside the burst window, stay inside the day
    limited = push_to_index(env, enrolled, 10)
    assert limited.status_code == 429
    assert limited.json() == {"error": "quota_exhausted"}
    assert env.state.metrics.values["failures_total"]["quota_exhausted"] == 1


# -- payload policy (422 with payload.py codes) ----------------------------------------


def push_and_expect_payload_error(env, enrolled, **payload_kwargs: Any):
    response = do_push(
        env.client, push_payload(enrolled, **payload_kwargs), enrolled.token, enrolled.private_key
    )
    assert response.status_code == 422, response.text
    return response


def test_push_unknown_top_level_field(env) -> None:
    # PushContent is extra="forbid", so a top-level content key beyond
    # {alert, background, liveActivity, sealed} dies in model validation
    # before payload.py's own unknown-field check.
    enrolled = enroll(env)
    response = do_push(
        env.client,
        push_payload(enrolled, content={**ALERT_CONTENT, "bogus": "TOPSECRET-MARKER"}),
        enrolled.token,
        enrolled.private_key,
    )
    assert_invalid_request(response, "TOPSECRET-MARKER")
    assert response.json()["detail"] == [
        {"loc": ["body", "content", "bogus"], "msg": "Extra inputs are not permitted"}
    ]


def test_push_unknown_alert_field_does_not_echo_value(env) -> None:
    enrolled = enroll(env)
    response = push_and_expect_payload_error(
        env, enrolled, content={"alert": {"title": "t", "hacked": "SECRET-VALUE"}}
    )
    assert response.json() == {"error": "unknown_field", "detail": "content.alert.hacked"}
    assert "SECRET-VALUE" not in response.text


def test_push_title_too_long(env) -> None:
    enrolled = enroll(env)
    response = push_and_expect_payload_error(
        env, enrolled, content={"alert": {"title": "x" * 65, "body": "b"}}
    )
    assert response.json() == {"error": "title_too_long"}


def test_push_empty_alert_object(env) -> None:
    enrolled = enroll(env)
    response = push_and_expect_payload_error(env, enrolled, content={"alert": {}})
    assert response.json() == {"error": "invalid_payload"}


def test_push_missing_alert_section(env) -> None:
    enrolled = enroll(env)
    response = push_and_expect_payload_error(env, enrolled, content={})
    assert response.json() == {"error": "invalid_payload"}


def test_push_sealed_too_long(env) -> None:
    enrolled = enroll(env)
    sealed = base64.b64encode(b"x" * 1025).decode()
    response = push_and_expect_payload_error(
        env, enrolled, content={**ALERT_CONTENT, "sealed": sealed}
    )
    assert response.json() == {"error": "sealed_too_long"}


def test_push_sealed_bad_base64(env) -> None:
    enrolled = enroll(env)
    response = push_and_expect_payload_error(
        env, enrolled, content={**ALERT_CONTENT, "sealed": "not base64!!"}
    )
    assert response.json() == {"error": "invalid_payload"}


def test_push_background_unknown_field(env) -> None:
    enrolled = enroll(env, kinds=["background"])
    response = push_and_expect_payload_error(
        env, enrolled, kind="background", content={"background": {"nope": 1}}
    )
    assert response.json() == {"error": "unknown_field", "detail": "content.background.nope"}


def test_push_background_too_long(env) -> None:
    enrolled = enroll(env, kinds=["background"])
    response = push_and_expect_payload_error(
        env, enrolled, kind="background", content={"background": {"payload": {"blob": "x" * 600}}}
    )
    assert response.json() == {"error": "background_too_long"}


def test_push_background_missing_section(env) -> None:
    enrolled = enroll(env, kinds=["background"])
    response = push_and_expect_payload_error(env, enrolled, kind="background", content={})
    assert response.json() == {"error": "invalid_payload"}


@pytest.mark.parametrize(
    "live_content",
    [
        {},  # no event
        {"event": "bogus"},
        {"event": "update", "timestamp": "now"},
        {"event": "update", "staleDate": True},
        {"event": "update", "dismissalDate": "1"},
        {"event": "update", "state": "not-structured"},
    ],
)
def test_push_live_activity_invalid_content(env, live_content: dict) -> None:
    enrolled = enroll(env, kinds=["liveActivity"])
    response = push_and_expect_payload_error(
        env, enrolled, kind="liveActivity", content={"liveActivity": live_content}
    )
    assert response.json() == {"error": "invalid_payload"}


def test_push_live_activity_state_too_long(env) -> None:
    enrolled = enroll(env, kinds=["liveActivity"])
    response = push_and_expect_payload_error(
        env,
        enrolled,
        kind="liveActivity",
        content={"liveActivity": {"event": "update", "state": {"blob": "x" * 600}}},
    )
    assert response.json() == {"error": "background_too_long"}


# -- request-model 422 (invalid_request; inputs never echoed) --------------------------


def assert_invalid_request(response: Any, marker: str) -> None:
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["error"] == "invalid_request"
    for item in body["detail"]:
        assert "loc" in item and "msg" in item
        assert "input" not in item
    assert marker not in response.text


def test_push_rejects_unknown_request_field(env) -> None:
    enrolled = enroll(env)
    response = do_push(
        env.client,
        push_payload(enrolled, leakField="MARKER-DEADBEEF"),
        enrolled.token,
        enrolled.private_key,
    )
    assert_invalid_request(response, "MARKER-DEADBEEF")


def test_push_rejects_non_hex_destination(env) -> None:
    enrolled = enroll(env)
    response = do_push(
        env.client,
        push_payload(enrolled, destination="zzMARKER" + "z" * 24),
        enrolled.token,
        enrolled.private_key,
    )
    assert_invalid_request(response, "MARKER")


def test_push_rejects_overlong_event_id(env) -> None:
    enrolled = enroll(env)
    response = do_push(
        env.client,
        push_payload(enrolled, eventId="MARKER" + "e" * 60),
        enrolled.token,
        enrolled.private_key,
    )
    assert_invalid_request(response, "MARKER")


def test_failures_metric_counts_invalid_request(env) -> None:
    enrolled = enroll(env)
    do_push(env.client, push_payload(enrolled, leakField="x"), enrolled.token, enrolled.private_key)
    assert env.state.metrics.values["failures_total"]["invalid_request"] == 1
