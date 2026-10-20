"""App factory and cross-cutting behaviour: health/metrics, error handlers,
lifespan sweep machinery, env boot path and grant-issuer key loading (app.py).
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from apns_relay.app import _sweep_loop, create_app
from apns_relay.checks import load_issuer_key
from apns_relay.config import ConfigError, RelayConfig
from apns_relay.store import Store
from tests.conftest import (
    ADMIN_TOKEN,
    APP_ID,
    DEST_TOKEN,
    MASTER_SECRET,
    TENANT_ID,
    load_test_config,
    register_tenant,
    write_config,
)

ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def _config_for(tmp_path: Path) -> RelayConfig:
    """Local instance dir (keys + config.yaml) → loaded RelayConfig."""
    base = tmp_path / "instance"
    base.mkdir(parents=True, exist_ok=True)
    return load_test_config(write_config(base))


def _write_pem(path: Path, key: Any) -> Path:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


# -- health / metrics -----------------------------------------------------------------


def test_health(env) -> None:
    response = env.client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_metrics_render_prometheus_text(env) -> None:
    empty = env.client.get("/metrics")
    assert empty.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
    assert "relay_requests_total" not in empty.text  # nothing completed yet

    env.client.get("/health")
    after = env.client.get("/metrics")
    assert "# TYPE relay_requests_total counter" in after.text
    # health + the first scrape (each request's counter lands after its body)
    assert 'relay_requests_total{label="200"} 2' in after.text
    assert after.text.endswith("\n")


def test_failures_total_counts_every_failure_class(env) -> None:
    assert env.client.get("/v1/push").status_code == 405  # HTTPException
    assert env.client.get("/admin/tenants").status_code == 401  # ApiError
    assert env.client.post("/v1/register", json={"app": APP_ID}).status_code == 422

    metrics = env.client.get("/metrics").text
    assert 'relay_failures_total{label="method_not_allowed"} 1' in metrics
    assert 'relay_failures_total{label="bad_admin_token"} 1' in metrics
    assert 'relay_failures_total{label="invalid_request"} 1' in metrics


# -- error handler shapes ----------------------------------------------------------------


def test_unknown_route_is_not_found(env) -> None:
    response = env.client.get("/definitely/not/a/route")
    assert response.status_code == 404
    assert response.json() == {"error": "not_found"}
    event = env.state.events.entries[-1]
    assert event["status"] == 404
    assert event["code"] == "not_found"
    assert event["path"] == "<unmatched>"


def test_wrong_method_is_method_not_allowed(env) -> None:
    response = env.client.put("/health")
    assert response.status_code == 405
    assert response.json() == {"error": "method_not_allowed"}

    push = env.client.get("/v1/push")  # GET on the real route
    assert push.status_code == 405
    assert push.json() == {"error": "method_not_allowed"}
    assert env.state.events.entries[-1]["path"] == "/v1/push"


def test_validation_error_never_echoes_input(env) -> None:
    marker = "SECRET-MARKER-deadbeef0f"
    response = env.client.post(
        "/v1/register", json={"id": "t.example.com", "app": APP_ID, "smuggled": marker}
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "invalid_request"
    detail = body["detail"]
    assert detail
    for item in detail:
        assert set(item) == {"loc", "msg"}  # no "input" echo
        assert item["loc"][0] == "body"
    assert marker not in response.text


def test_api_error_handler_includes_detail(env) -> None:
    register_tenant(env.client)
    # both configured environments reject the challenge push
    env.apns.queue[:] = [(400, "BadDeviceToken"), (400, "BadDeviceToken")]
    response = env.client.post(
        "/v1/enroll/begin",
        json={"app": APP_ID, "tenantId": TENANT_ID, "destinationToken": DEST_TOKEN},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalidDestination", "detail": "BadDeviceToken"}
    metrics = env.client.get("/metrics").text
    assert 'relay_failures_total{label="invalidDestination"} 1' in metrics


def test_unhandled_exception_returns_internal_error(tmp_path: Path) -> None:
    config = _config_for(tmp_path)
    app = create_app(config, master_secret=MASTER_SECRET, store=Store(config.database))

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("boom")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/boom")
        assert response.status_code == 500
        assert response.json() == {"error": "internal_error"}

        events = list(app.state.relay.events.entries)
        assert events[-1]["status"] == 500
        assert events[-1]["code"] == "internal_error"

        metrics = client.get("/metrics").text
        assert 'relay_requests_total{label="500"} 1' in metrics
        assert 'relay_failures_total{label="internal_error"} 1' in metrics


# -- create_app: env boot path ----------------------------------------------------------------


def test_create_app_boots_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path / "instance"
    base.mkdir(parents=True, exist_ok=True)
    config_path = write_config(base)
    monkeypatch.setenv("RELAY_CONFIG", str(config_path))
    monkeypatch.setenv("RELAY_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("RELAY_MASTER_SECRET", "s" * 32)

    app = create_app()
    with TestClient(app) as client:
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/admin/status", headers=ADMIN_HEADERS).status_code == 200
        wrong = {"Authorization": "Bearer " + "b" * 32}
        assert client.get("/admin/status", headers=wrong).status_code == 401


@pytest.mark.parametrize("secret", [None, "x" * 31], ids=["unset", "too-short"])
def test_create_app_env_master_secret_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, secret: str | None
) -> None:
    base = tmp_path / "instance"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("RELAY_CONFIG", str(write_config(base)))
    monkeypatch.setenv("RELAY_ADMIN_TOKEN", ADMIN_TOKEN)
    if secret is None:
        monkeypatch.delenv("RELAY_MASTER_SECRET", raising=False)
    else:
        monkeypatch.setenv("RELAY_MASTER_SECRET", secret)
    with pytest.raises(ConfigError, match="RELAY_MASTER_SECRET must be at least 32 characters"):
        create_app()


def test_create_app_env_admin_token_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "instance"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("RELAY_CONFIG", str(write_config(base)))
    monkeypatch.setenv("RELAY_MASTER_SECRET", "s" * 32)
    monkeypatch.delenv("RELAY_ADMIN_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="admin token not provided"):
        create_app()


def test_create_app_explicit_config_requires_master_secret(tmp_path: Path) -> None:
    config = _config_for(tmp_path)
    with pytest.raises(ValueError, match="master_secret is required"):
        create_app(config)


def test_create_app_explicit_config_rejects_short_secret(tmp_path: Path) -> None:
    config = _config_for(tmp_path)
    with pytest.raises(ConfigError, match="master secret must be at least 32 characters"):
        create_app(config, master_secret=b"m" * 31)


# -- load_issuer_key ---------------------------------------------------------------------------


def test_load_issuer_key_accepts_ed25519(tmp_path: Path) -> None:
    path = _write_pem(tmp_path / "issuer.pem", Ed25519PrivateKey.generate())
    key = load_issuer_key(path)
    assert isinstance(key, Ed25519PrivateKey)


def test_load_issuer_key_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_issuer_key(tmp_path / "absent.pem")


def test_load_issuer_key_garbage_pem(tmp_path: Path) -> None:
    path = tmp_path / "issuer.pem"
    path.write_bytes(b"totally not a PEM key\n")
    with pytest.raises(ConfigError, match="not a valid PEM key"):
        load_issuer_key(path)


def test_load_issuer_key_rejects_non_ed25519(tmp_path: Path) -> None:
    path = _write_pem(tmp_path / "issuer.pem", ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(ConfigError, match="must be an Ed25519 key"):
        load_issuer_key(path)


# -- lifespan / prune machinery -------------------------------------------------------------


def test_maybe_prune_sweeps_on_request_path(env, monkeypatch: pytest.MonkeyPatch) -> None:
    pruned: list[float] = []
    monkeypatch.setattr(env.state, "prune_interval", 0.0)
    monkeypatch.setattr(env.state, "prune", pruned.append)
    assert env.client.get("/health").status_code == 200
    assert len(pruned) == 1  # one lazy sweep per request once the interval has elapsed
    assert pruned[0] > 0


async def test_sweep_loop_prunes_repeatedly_and_cancels(
    env, monkeypatch: pytest.MonkeyPatch
) -> None:
    pruned: list[float] = []
    monkeypatch.setattr(env.state, "prune_interval", 0.01)
    monkeypatch.setattr(env.state, "prune", pruned.append)
    task = asyncio.create_task(_sweep_loop(env.state))
    await asyncio.sleep(0.06)
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
    assert task.cancelled()
    assert len(pruned) >= 2  # pruned once per sweep tick, repeatedly


def test_prune_expires_idle_tenant_and_prunes_state(clock, env) -> None:
    register_tenant(env.client)
    assert env.store.count_tenants() == 1
    assert (
        env.store.check_and_record(
            TENANT_ID,
            APP_ID,
            "blind-index",
            clock.t,
            burst_per_min=5,
            daily=10,
            token_burst_per_min=3,
        )
        is None
    )
    assert env.store.claim_nonce("n" * 64, clock.t) is True
    env.store.put_challenge(
        "challenge-1", APP_ID, TENANT_ID, "d" * 64, "nonce-1", "server-1", "sandbox", clock.t + 600
    )
    assert env.state.limiter.allow("probe-key", 5, 60.0, clock.t) is True

    clock.advance(31 * 86400)
    env.state.prune(clock.t)

    assert env.store.count_tenants() == 0
    assert env.state.metrics.snapshot()["tenants_expired_total"] == {"": 1}
    with env.store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM usage").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == 0
    assert env.state.limiter._hits == {}


def test_lifespan_finally_skips_cancel_when_task_cleared(env) -> None:
    task = env.state.sweep_task
    assert task is not None
    assert not task.done()
    # cancel inside the portal loop, then let the loop settle during a request
    assert env.client.portal is not None
    env.client.portal.call(task.cancel)
    assert env.client.get("/health").status_code == 200
    assert task.done()
    # detach: lifespan shutdown must take the `is None` branch (skip cancel/await)
    env.state.sweep_task = None
