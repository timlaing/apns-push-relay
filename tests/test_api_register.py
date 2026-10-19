"""POST /v1/register: response shape, callback proof, conflicts, rate limit.

Handler order per the spec: per-IP rate limit → App resolution → callback
ownership proof → store. Each failure returns a stable machine code.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from apns_relay.callback import CallbackError
from apns_relay.config import RegistrationConfig
from apns_relay.store import TENANT_TTL
from tests.conftest import APP_ID, DEFAULT_QUOTA, TENANT_ID, register_tenant


def set_config(env: Any, **app_changes: Any) -> None:
    """Point the live state's config at a copy with one App modified."""
    apps = tuple(
        dataclasses.replace(app, **app_changes) if app.id == APP_ID else app
        for app in env.state.config.apps
    )
    env.state.config = dataclasses.replace(env.state.config, apps=apps)


def register_post(env: Any, payload: dict, **kwargs: Any):
    return env.client.post("/v1/register", json=payload, **kwargs)


# -- response shape -------------------------------------------------------------


def test_register_201_shape(env, clock) -> None:
    response = register_post(env, {"id": TENANT_ID, "app": APP_ID})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["tenant"] == TENANT_ID
    assert body["app"] == APP_ID
    assert body["token"].startswith("tnt_")
    assert body["quota"] == DEFAULT_QUOTA
    assert body["registered_at"] == int(clock.time())
    assert body["expires_at"] - body["registered_at"] == TENANT_TTL
    assert env.state.metrics.values["registers_total"] == {"ok": 1}
    assert env.store.tenant(TENANT_ID, APP_ID).token_digest != body["token"]


def test_register_unknown_app(env) -> None:
    response = register_post(env, {"id": TENANT_ID, "app": "no-such-app"})
    assert response.status_code == 400
    assert response.json() == {"error": "unknown_app"}


def test_register_disabled_app_is_unknown_to_unauthenticated_caller(env) -> None:
    # Spec note in api.py: disabled Apps are indistinguishable from unknown
    # ones on unauthenticated routes (no config-state disclosure).
    set_config(env, enabled=False)
    response = register_post(env, {"id": TENANT_ID, "app": APP_ID})
    assert response.status_code == 400
    assert response.json() == {"error": "unknown_app"}


def test_register_id_exists_conflicts(env) -> None:
    register_tenant(env.client)
    response = register_post(env, {"id": TENANT_ID, "app": APP_ID})
    assert response.status_code == 409
    assert response.json() == {"error": "id_exists"}


# -- callback ownership proof ----------------------------------------------------


def test_callback_required_but_omitted(env) -> None:
    set_config(env, registration=RegistrationConfig(callback_required=True))
    response = register_post(env, {"id": TENANT_ID, "app": APP_ID})
    assert response.status_code == 400
    assert response.json() == {"error": "callback_required"}


def test_callback_required_satisfied(env) -> None:
    set_config(env, registration=RegistrationConfig(callback_required=True))
    response = register_post(
        env, {"id": TENANT_ID, "app": APP_ID, "callback": "https://hooks.example.com/cb"}
    )
    assert response.status_code == 201, response.text
    assert len(env.callback.calls) == 1
    call = env.callback.calls[0]
    assert call["id"] == TENANT_ID
    assert call["kind"] == "registration"
    assert isinstance(call["nonce"], str) and call["nonce"]


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/cb",  # not https
        "https://hooks.example.com:8443/cb",  # not port 443
        "https://user@hooks.example.com/cb",  # userinfo forbidden
    ],
)
def test_callback_invalid_url_rejected(env, url: str) -> None:
    response = register_post(env, {"id": TENANT_ID, "app": APP_ID, "callback": url})
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_callback"}
    assert env.callback.calls == []


def test_callback_host_must_match_tenant_id(env) -> None:
    response = register_post(
        env, {"id": TENANT_ID, "app": APP_ID, "callback": "https://evil.example.org/cb"}
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_callback"}
    assert env.callback.calls == []


@pytest.mark.parametrize("mode", ["wrong", "error", "empty"])
def test_callback_verification_failed(env, mode: str) -> None:
    env.callback.mode = mode
    response = register_post(
        env, {"id": TENANT_ID, "app": APP_ID, "callback": "https://hooks.example.com/cb"}
    )
    assert response.status_code == 400
    assert response.json() == {"error": "callback_verification_failed"}


def test_callback_transport_error_is_invalid_callback(env, monkeypatch) -> None:
    # The `except CallbackError` around verify_callback in api.py: the fake
    # transport never raises, so raise from the patched call directly.
    async def boom(url: str, tenant_id: str, nonce: str, **kwargs: Any) -> bool:
        raise CallbackError("invalid_callback")

    monkeypatch.setattr("apns_relay.api.verify_callback", boom)
    response = register_post(
        env, {"id": TENANT_ID, "app": APP_ID, "callback": "https://hooks.example.com/cb"}
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_callback"}


# -- per-IP rate limiting ---------------------------------------------------------


def test_rate_limit_checked_before_app_resolution(env) -> None:
    outcomes = []
    for i in range(11):
        response = register_post(env, {"id": f"t{i}.example.com", "app": "no-such-app"})
        outcomes.append((response.status_code, response.json().get("error")))
    assert outcomes[:10] == [(400, "unknown_app")] * 10
    assert outcomes[10] == (429, "rate_limited")
    assert env.state.metrics.values["failures_total"]["unknown_app"] == 10
    assert env.state.metrics.values["failures_total"]["rate_limited"] == 1


def test_rate_limit_bucket_is_per_forwarded_ip(env) -> None:
    first = {"x-forwarded-for": "203.0.113.9"}
    for i in range(10):
        response = register_post(env, {"id": f"a{i}.example.com", "app": APP_ID}, headers=first)
        assert response.status_code == 201, response.text
    limited = register_post(env, {"id": "a10.example.com", "app": APP_ID}, headers=first)
    assert limited.status_code == 429
    assert limited.json() == {"error": "rate_limited"}
    # A different forwarded client gets its own window.
    other = register_post(
        env, {"id": "fresh.example.com", "app": APP_ID}, headers={"x-forwarded-for": "198.51.100.7"}
    )
    assert other.status_code == 201, other.text


def test_rate_limit_window_expires(env, clock) -> None:
    for i in range(10):
        response = register_post(env, {"id": f"w{i}.example.com", "app": APP_ID})
        assert response.status_code == 201, response.text
    blocked = register_post(env, {"id": "w10.example.com", "app": APP_ID})
    assert blocked.status_code == 429
    clock.advance(61)
    after_window = register_post(env, {"id": "w11.example.com", "app": APP_ID})
    assert after_window.status_code == 201, after_window.text
