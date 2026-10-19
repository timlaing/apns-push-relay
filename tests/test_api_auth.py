"""Signed-request authentication on /v1/push (spec §2.4 error matrix).

Each test drives one failure code out of ``authenticate``: token → tenant →
stored pubkey → timestamp → nonce → signature → single-use nonce → touch.
The push body is always shape-valid so authentication is the only thing that
can fail.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from apns_relay.signing import generate_keypair
from tests.conftest import (
    APP_ID,
    DEST_TOKEN,
    DEST_TOKEN_2,
    OTHER_TENANT_ID,
    TENANT_ID,
    Enrolled,
    do_push,
    enroll,
    make_signed,
    push_payload,
    register_tenant,
)

PUSH = "/v1/push"

DEAD_GRANT_PAYLOAD: dict[str, Any] = {
    "grant": "v1.aaaa.bbbb",
    "destinationToken": DEST_TOKEN,
    "kind": "alert",
    "content": {"alert": {"title": "t", "body": "b"}},
}


@pytest.fixture
def enrolled(env) -> Enrolled:
    return enroll(env)


def sign_push(
    enrolled: Enrolled,
    *,
    timestamp: Any = None,
    nonce: Any = None,
    payload: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, str]]:
    return make_signed(
        enrolled.token,
        enrolled.private_key,
        PUSH,
        payload if payload is not None else push_payload(enrolled),
        timestamp=timestamp,
        nonce=nonce,
    )


def send(client: Any, body: bytes, headers: dict[str, str]):
    return client.request("POST", PUSH, content=body, headers=headers)


# -- header presence / shape ------------------------------------------------------


def test_absent_authorization_header(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled)
    del headers["authorization"]
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "missing_token"}


def test_non_bearer_authorization_header(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled)
    headers["authorization"] = "Basic dXNlcjpwYXNz"
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "missing_token"}


def test_unknown_tenant_token(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled)
    headers["authorization"] = "Bearer tnt_never_registered_here"
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "unknown_tenant"}


def test_registered_but_not_enrolled(env) -> None:
    token = register_tenant(env.client)
    private_key, _pubkey = generate_keypair()
    response = do_push(env.client, DEAD_GRANT_PAYLOAD, token, private_key)
    assert response.status_code == 401
    assert response.json() == {"error": "enrollment_required"}


# -- timestamp ---------------------------------------------------------------------


def test_missing_x_relay_time(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled)
    del headers["x-relay-time"]
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_timestamp"}


def test_non_integer_timestamp(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled, timestamp="not-a-number")
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_timestamp"}


def test_timestamp_too_old(env, clock, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled, timestamp=int(clock.time()) - 301)
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "stale_timestamp"}


def test_timestamp_too_far_future(env, clock, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled, timestamp=int(clock.time()) + 301)
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "stale_timestamp"}


def test_timestamp_at_skew_boundary_is_accepted(env, clock, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled, timestamp=int(clock.time()) - 300)
    response = send(env.client, body, headers)
    assert response.status_code == 200, response.text


# -- nonce --------------------------------------------------------------------------


def test_missing_nonce(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled)
    del headers["x-relay-nonce"]
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_nonce"}


def test_nonce_too_short(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled, nonce="abc")
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_nonce"}


def test_nonce_too_long(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled, nonce="n" * 129)
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_nonce"}


# -- signature -----------------------------------------------------------------------


def test_missing_signature(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled)
    del headers["x-relay-signature"]
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_signature"}


def test_signature_with_bad_base64_chars(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled)
    headers["x-relay-signature"] = "!!not*base64!!"
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_signature"}


def test_wrong_signature(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled)
    signature = headers["x-relay-signature"]
    headers["x-relay-signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_signature"}


def test_tampered_body_after_signing(env, enrolled: Enrolled) -> None:
    _body, headers = sign_push(enrolled)
    tampered = json.dumps(push_payload(enrolled, destination=DEST_TOKEN_2)).encode()
    response = env.client.request("POST", PUSH, content=tampered, headers=headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_signature"}


def test_signature_for_a_different_path(env, enrolled: Enrolled) -> None:
    body, headers = make_signed(
        enrolled.token, enrolled.private_key, "/v1/pushx", push_payload(enrolled)
    )
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_signature"}


def test_signature_from_another_tenant_keypair(env, enrolled: Enrolled) -> None:
    # A2: a signature spliced onto another tenant's token must not verify.
    other = enroll(env, tenant_id=OTHER_TENANT_ID)
    body, headers = sign_push(other)
    headers["authorization"] = f"Bearer {enrolled.token}"
    response = send(env.client, body, headers)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_signature"}


# -- replay + liveness ----------------------------------------------------------------


def test_replayed_signed_request_is_rejected(env, enrolled: Enrolled) -> None:
    body, headers = sign_push(enrolled)
    first = send(env.client, body, headers)
    assert first.status_code == 200, first.text
    second = send(env.client, body, headers)
    assert second.status_code == 401
    assert second.json() == {"error": "replayed_nonce"}


def test_authenticated_request_refreshes_last_seen(env, clock, enrolled: Enrolled) -> None:
    assert env.store.tenant(TENANT_ID, APP_ID).last_seen == clock.time()
    clock.advance(120)
    response = do_push(env.client, push_payload(enrolled), enrolled.token, enrolled.private_key)
    assert response.status_code == 200, response.text
    assert env.store.tenant(TENANT_ID, APP_ID).last_seen == clock.time()


def test_registration_alone_does_not_refresh_last_seen(env, clock) -> None:
    register_tenant(env.client)
    assert env.store.tenant(TENANT_ID, APP_ID).last_seen == clock.time()
    clock.advance(120)
    register_tenant(env.client, tenant_id=OTHER_TENANT_ID)
    assert env.store.tenant(TENANT_ID, APP_ID).last_seen == clock.time() - 120
