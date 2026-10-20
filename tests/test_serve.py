"""Split listeners: admin API on 8000, public API on 8001, one process.

The container run path (serve.py) serves both from one AppState, so the
metrics, recent-request log and rate limiter stay global. The public
listener has no /admin routes at all; the admin listener has no public
API; one signal stops both.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import signal
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apns_relay import serve
from apns_relay.app import create_app, create_listeners
from tests.conftest import ADMIN_TOKEN, MASTER_SECRET, make_root, write_config


def _split(env, config=None) -> tuple[FastAPI, FastAPI]:
    """(admin, public) with injected store — the same split serve.py builds."""
    cfg = config if config is not None else env.config
    kwargs: dict = {"master_secret": MASTER_SECRET, "store": env.store}
    admin = create_app(cfg, **kwargs, public=False, admin=True)
    public = create_app(cfg, **kwargs, public=True, admin=False)
    return admin, public


def _stub(_scope, _receive, _send) -> None:
    """Minimal ASGI app for wiring tests (never served for real)."""


def test_public_listener_has_no_admin_routes(env) -> None:
    _admin, public = _split(env)
    with TestClient(public) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/metrics").status_code == 200
        # the public API itself still answers (auth envelope, not a 404)
        assert client.post("/v1/push").status_code == 401
        assert client.get("/admin/status").status_code == 404


def test_admin_listener_serves_the_cli_targets_only(env) -> None:
    admin, _public = _split(env)
    with TestClient(admin) as client:
        # the token-gated admin API is here …
        assert client.get("/admin/status").status_code == 401
        # … and so are the CLI's other targets …
        assert client.get("/health").status_code == 200
        assert client.get("/metrics").status_code == 200
        # … but not the public API
        assert client.post("/v1/push").status_code == 404


def test_docs_live_on_the_public_listener_only(env) -> None:
    config = dataclasses.replace(
        env.config, server=dataclasses.replace(env.config.server, swagger_ui=True)
    )
    admin, public = _split(env, config=config)
    with TestClient(public) as client:
        assert client.get("/docs").status_code == 200
    with TestClient(admin) as client:
        assert client.get("/docs").status_code == 404


def test_api_root_is_a_docs_pointer_on_public_only(env, monkeypatch) -> None:
    admin, public = _split(env)
    with TestClient(public) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"docs": "https://timlaing.github.io/apns-push-relay/"}
        # DOCS_DOMAIN is read per request — the image bakes it, .env needn't
        monkeypatch.setenv("DOCS_DOMAIN", "docs.example.org")
        assert client.get("/").json() == {"docs": "https://docs.example.org/"}
    with TestClient(admin) as client:
        assert client.get("/").status_code == 404


def test_servers_bind_admin_8000_and_public_8001() -> None:
    servers = serve._servers(_stub, _stub)  # type: ignore[arg-type]
    assert (
        [server.config.port for server in servers]
        == [
            serve.ADMIN_PORT,
            serve.PUBLIC_PORT,
        ]
        == [8000, 8001]
    )
    assert all(isinstance(server, serve._QuietServer) for server in servers)
    for server in servers:
        server.install_signal_handlers()  # no-op: wiring lives in _serve


def test_serve_stops_both_listeners_on_one_signal(monkeypatch) -> None:
    exited: list[int] = []

    async def fake_serve(self) -> None:
        while not self.should_exit:
            await asyncio.sleep(0.001)
        exited.append(self.config.port)

    monkeypatch.setattr(uvicorn.Server, "serve", fake_serve)

    async def run() -> None:
        task = asyncio.create_task(serve._serve(_stub, _stub))  # type: ignore[arg-type]
        await asyncio.sleep(0.05)  # let handlers register and loops poll
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.wait_for(task, timeout=5)

    asyncio.run(run())
    assert sorted(exited) == [serve.ADMIN_PORT, serve.PUBLIC_PORT]


def test_main_builds_the_listeners_and_runs_the_loop(monkeypatch) -> None:
    ran: list[object] = []

    def fake_run(coroutine) -> None:
        coroutine.close()
        ran.append(coroutine)

    monkeypatch.setattr(serve, "create_listeners", lambda: (_stub, _stub))
    monkeypatch.setattr(serve.asyncio, "run", fake_run)
    serve.main()
    assert len(ran) == 1


def test_create_listeners_reads_env_and_splits_the_surface(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "instance"
    base.mkdir(parents=True)
    root_path = base / "production-root.pem"
    root_path.write_bytes(make_root("Prod Root").pem)
    config_path = write_config(base, roots={"production": root_path})
    monkeypatch.setenv("RELAY_CONFIG", str(config_path))
    monkeypatch.setenv("RELAY_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("RELAY_MASTER_SECRET", MASTER_SECRET.decode())

    admin, public = create_listeners()
    with TestClient(admin) as client:
        assert client.get("/admin/status").status_code == 401
    with TestClient(public) as client:
        assert client.get("/admin/status").status_code == 404
        assert client.get("/health").status_code == 200
