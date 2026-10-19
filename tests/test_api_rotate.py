"""POST /v1/rotate: proof-of-possession credential rotation (spec §2.7).

Handler order (api.py): authenticate (current token + Ed25519 + single-use
nonce) → App enabled → pubkey shape → atomic binding replace. The previous
token dies immediately; grants bound to the old pubkey stop verifying
(``tenant_mismatch`` on push, ``grant_mismatch`` on renew) until the device
re-enrolls with the replacement key.
"""

from __future__ import annotations

import dataclasses
import hashlib
import time
from typing import Any

import pytest

from apns_relay.signing import generate_keypair
from tests.conftest import (
    APP_ID,
    TENANT_ID,
    enroll,
    make_signed,
    post_signed,
    push_payload,
    register_tenant,
)


def rotate(
    env: Any,
    enrolled: Any,
    pubkey: str,
    *,
    token: str | None = None,
    private_key: Any | None = None,
    **sign_kwargs: Any,
) -> Any:
    return post_signed(
        env.client,
        "/v1/rotate",
        {"pubkey": pubkey},
        token or enrolled.token,
        private_key or enrolled.private_key,
        **sign_kwargs,
    )


# -- happy path ----------------------------------------------------------------


def test_rotate_replaces_token_and_binds_new_key(env) -> None:
    enrolled = enroll(env)
    _new_private, new_pubkey = generate_keypair()
    response = rotate(env, enrolled, new_pubkey)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tenant"] == TENANT_ID
    assert body["app"] == APP_ID
    assert body["token"].startswith("tnt_")
    assert body["token"] != enrolled.token
    assert isinstance(body["rotated_at"], int)
    assert env.state.metrics.values["rotations_total"] == {"ok": 1}
    # The old token is dead immediately, whatever signature accompanies it.
    stale = rotate(env, enrolled, new_pubkey)
    assert stale.status_code == 401, stale.text
    assert stale.json() == {"error": "unknown_tenant"}


def test_old_grant_dies_and_reenroll_restores_delivery(env) -> None:
    enrolled = enroll(env)
    new_private, new_pubkey = generate_keypair()
    new_token = rotate(env, enrolled, new_pubkey).json()["token"]

    # The outstanding grant is bound to the old pubkey.
    stale_push = post_signed(env.client, "/v1/push", push_payload(enrolled), new_token, new_private)
    assert stale_push.status_code == 403, stale_push.text
    assert stale_push.json() == {"error": "tenant_mismatch"}

    stale_renew = post_signed(
        env.client,
        "/v1/enroll/renew",
        {"grant": enrolled.grant},
        new_token,
        new_private,
    )
    assert stale_renew.status_code == 403, stale_renew.text
    assert stale_renew.json() == {"error": "grant_mismatch"}

    # Re-enrolling under the rotated binding with the replacement keypair
    # (TOFU passes: the stored pubkey IS the one being enrolled).
    renewed = enroll(env, token=new_token, private_key=new_private, pubkey=new_pubkey)
    ok = post_signed(env.client, "/v1/push", push_payload(renewed), new_token, new_private)
    assert ok.status_code == 200, ok.text
    assert ok.json()["result"] == "accepted"
    call = env.apns.calls[-1]
    assert call["body"] == {"aps": {"alert": {"title": "t", "body": "b"}}}


def test_rotate_with_current_pubkey_is_token_rotation(env) -> None:
    enrolled = enroll(env)
    response = rotate(env, enrolled, enrolled.pubkey)
    assert response.status_code == 200, response.text
    new_token = response.json()["token"]
    assert new_token != enrolled.token
    tenant = env.store.tenant(TENANT_ID, APP_ID)
    assert tenant is not None
    assert tenant.pubkey == enrolled.pubkey  # key untouched
    # Grants bind the destination-token hash and pubkey — not the tenant
    # token — so the outstanding grant keeps working under the new token.
    ok = post_signed(
        env.client, "/v1/push", push_payload(enrolled), new_token, enrolled.private_key
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["result"] == "accepted"


# -- authentication ------------------------------------------------------------


def test_rotate_unsigned_is_rejected(env) -> None:
    enrolled = enroll(env)
    response = env.client.post("/v1/rotate", json={"pubkey": enrolled.pubkey})
    assert response.status_code == 401, response.text
    assert response.json() == {"error": "missing_token"}


def test_rotate_signed_with_foreign_key_is_rejected(env) -> None:
    enrolled = enroll(env)
    foreign_private, _ = generate_keypair()
    response = rotate(env, enrolled, enrolled.pubkey, private_key=foreign_private)
    assert response.status_code == 401, response.text
    assert response.json() == {"error": "invalid_signature"}


def test_rotate_stale_timestamp_is_rejected(env) -> None:
    enrolled = enroll(env)
    response = rotate(env, enrolled, enrolled.pubkey, timestamp=int(time.time()) - 3600)
    assert response.status_code == 401, response.text
    assert response.json() == {"error": "stale_timestamp"}


def test_rotate_before_first_enrollment_is_rejected(env) -> None:
    # Registered but never enrolled: no pubkey bound, nothing to verify with.
    token = register_tenant(env.client)
    foreign_private, foreign_pubkey = generate_keypair()
    response = post_signed(
        env.client, "/v1/rotate", {"pubkey": foreign_pubkey}, token, foreign_private
    )
    assert response.status_code == 401, response.text
    assert response.json() == {"error": "enrollment_required"}


def test_rotate_after_tenant_revoked_is_unknown(env) -> None:
    enrolled = enroll(env)
    env.store.delete_tenant(TENANT_ID, APP_ID)
    response = rotate(env, enrolled, enrolled.pubkey)
    assert response.status_code == 401, response.text
    assert response.json() == {"error": "unknown_tenant"}


def test_rotate_binding_loss_mid_request_returns_unknown_tenant(
    env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revoked between authenticate and the replace must not mint a token."""
    enrolled = enroll(env)
    monkeypatch.setattr(env.store, "rotate_binding", lambda *args, **kwargs: False)
    response = rotate(env, enrolled, enrolled.pubkey)
    assert response.status_code == 401, response.text
    assert response.json() == {"error": "unknown_tenant"}


# -- request shape -------------------------------------------------------------


def test_rotate_rejects_malformed_pubkey(env) -> None:
    enrolled = enroll(env)
    response = rotate(env, enrolled, "A" * 44)  # 33 bytes once base64-decoded
    assert response.status_code == 400, response.text
    assert response.json() == {"error": "invalid_pubkey"}


def test_rotate_short_pubkey_is_unprocessable(env) -> None:
    enrolled = enroll(env)
    body, headers = make_signed(
        enrolled.token, enrolled.private_key, "/v1/rotate", {"pubkey": "too-short"}
    )
    response = env.client.request("POST", "/v1/rotate", content=body, headers=headers)
    assert response.status_code == 422, response.text
    assert response.json()["error"] == "invalid_request"


def test_rotate_unknown_field_is_forbidden(env) -> None:
    enrolled = enroll(env)
    body, headers = make_signed(
        enrolled.token,
        enrolled.private_key,
        "/v1/rotate",
        {"pubkey": enrolled.pubkey, "environment": "production"},
    )
    response = env.client.request("POST", "/v1/rotate", content=body, headers=headers)
    assert response.status_code == 422, response.text
    assert response.json()["error"] == "invalid_request"
    # Nothing rotated: the original token still authenticates.
    tenant = env.store.tenant(TENANT_ID, APP_ID)
    assert tenant is not None
    assert tenant.token_digest == hashlib.sha256(enrolled.token.encode()).hexdigest()


def test_rotate_disabled_app_is_forbidden(env) -> None:
    enrolled = enroll(env)
    apps = tuple(
        dataclasses.replace(app, enabled=False) if app.id == APP_ID else app
        for app in env.state.config.apps
    )
    env.state.config = dataclasses.replace(env.state.config, apps=apps)
    response = rotate(env, enrolled, enrolled.pubkey)
    assert response.status_code == 403, response.text
    assert response.json() == {"error": "app_disabled"}
