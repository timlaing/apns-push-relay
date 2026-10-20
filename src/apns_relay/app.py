"""Application factory: state, wiring, middleware, lifespan.

``create_app()`` is a uvicorn ``--factory`` target reading ``RELAY_CONFIG``,
``RELAY_ADMIN_TOKEN`` and ``RELAY_MASTER_SECRET`` from the environment.
Tests construct it with an explicit config + injected store/sender.
``create_listeners()`` (same env) returns the split (admin, public) pair
that ``serve.py`` binds on ports 8000/8001.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from importlib.metadata import version
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .admin import admin_router
from .api import v1_router
from .apns import APNsSender, KeyRegistry
from .config import ConfigError, RelayConfig, load_config
from .errors import ApiError
from .metrics import EventLog, Metrics
from .ratelimit import RateLimiter
from .signing import sha256hex
from .store import Store

DEFAULT_CONFIG = "/etc/apns-relay/config.yaml"
# The API root (/) answers with a JSON pointer to the docs site; the docs
# land on this repo's GitHub Pages project URL. The image bakes
# DOCS_DOMAIN over this default for operators hosting docs elsewhere.
DEFAULT_DOCS_DOMAIN = "timlaing.github.io/apns-push-relay"


def load_issuer_key(path: Path) -> Ed25519PrivateKey:
    """Grant-issuer key: a single Ed25519 private key in a PEM file (v1)."""
    try:
        key = load_pem_private_key(path.read_bytes(), password=None)
    except FileNotFoundError:
        raise ConfigError(f"enrollment.grant_issuer_key not found: {path}") from None
    except ValueError:
        raise ConfigError(f"enrollment.grant_issuer_key is not a valid PEM key: {path}") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigError(f"enrollment.grant_issuer_key must be an Ed25519 key: {path}")
    return key


@dataclass
class AppState:
    config: RelayConfig
    store: Store
    registry: KeyRegistry
    sender: APNsSender
    issuer_key: Ed25519PrivateKey
    issuer_id: str
    master_secret: bytes
    metrics: Metrics = field(default_factory=Metrics)
    events: EventLog = field(default_factory=EventLog)
    limiter: RateLimiter = field(default_factory=RateLimiter)
    # The config file backing this run — set when booted from $RELAY_CONFIG
    # (or passed explicitly); lets /admin/apps edit the live config.
    config_path: Path | None = None
    started_at: float = field(default_factory=time.time)
    last_prune: float = 0.0
    prune_interval: float = 3600.0
    callback_client: httpx.AsyncClient | None = None
    sweep_task: asyncio.Task | None = None

    @property
    def issuer_public(self):
        return self.issuer_key.public_key()

    def maybe_prune(self, now: float) -> None:
        if now - self.last_prune >= self.prune_interval:
            self.last_prune = now
            self.prune(now)

    def prune(self, now: float) -> None:
        expired = self.store.expire_tenants(now)
        if expired:
            # Count only — tenant ids are never logged or labelled.
            self.metrics.inc("tenants_expired_total", amount=len(expired))
        self.store.prune_usage(now)
        self.store.prune_nonces(now)
        self.store.prune_challenges(now)
        self.limiter.prune(now)


async def _sweep_loop(state: AppState) -> None:
    """Hourly sweep even when idle (PLAN §3.4); request path also sweeps lazily."""
    while True:
        await asyncio.sleep(state.prune_interval)
        state.prune(time.time())


def build_state(
    config: RelayConfig,
    *,
    master_secret: bytes,
    store: Store | None = None,
    sender: APNsSender | None = None,
    callback_client: httpx.AsyncClient | None = None,
    config_path: Path | None = None,
) -> AppState:
    """Construct state; key loading + JWT pre-signature fail fast at boot."""
    if len(master_secret) < 32:
        raise ConfigError("master secret must be at least 32 characters")
    state_store = store if store is not None else Store(config.database)
    registry = KeyRegistry(config.enabled_apps)
    state_sender = sender if sender is not None else APNsSender(registry)
    issuer_key = load_issuer_key(config.enrollment.grant_issuer_key)
    issuer_id = sha256hex(issuer_key.public_key().public_bytes_raw())[:16]
    return AppState(
        config=config,
        store=state_store,
        registry=registry,
        sender=state_sender,
        issuer_key=issuer_key,
        issuer_id=issuer_id,
        master_secret=master_secret,
        callback_client=callback_client,
        config_path=config_path,
    )


def _from_env() -> tuple[RelayConfig, bytes, Path]:
    path = Path(os.environ.get("RELAY_CONFIG", DEFAULT_CONFIG))
    config = load_config(str(path), admin_token=os.environ.get("RELAY_ADMIN_TOKEN"))
    secret = os.environ.get("RELAY_MASTER_SECRET", "")
    if len(secret) < 32:
        raise ConfigError("RELAY_MASTER_SECRET must be at least 32 characters")
    return config, secret.encode(), path


def create_app(
    config: RelayConfig | None = None,
    *,
    master_secret: bytes | None = None,
    store: Store | None = None,
    sender: APNsSender | None = None,
    callback_client: httpx.AsyncClient | None = None,
    public: bool = True,
    admin: bool = True,
    config_path: Path | None = None,
) -> FastAPI:
    """Assemble the app. Both sides default on (single-listener runs); the
    compose deployment splits them — see ``create_listeners``."""
    if config is None:
        config, master_secret, config_path = _from_env()
    elif master_secret is None:
        raise ValueError("master_secret is required when config is passed explicitly")
    state = build_state(
        config,
        master_secret=master_secret,
        store=store,
        sender=sender,
        callback_client=callback_client,
        config_path=config_path,
    )
    return _assemble(state, public=public, admin=admin)


def create_listeners() -> tuple[FastAPI, FastAPI]:
    """(admin_app, public_app) sharing one AppState — the compose run path.

    ``serve.py`` binds them on separate ports in a single process (admin on
    8000, public on 8001): the metrics/event state stays global and SQLite
    keeps its single writer.
    """
    config, master_secret, config_path = _from_env()
    state = build_state(config, master_secret=master_secret, config_path=config_path)
    return (
        _assemble(state, public=False, admin=True),
        _assemble(state, public=True, admin=False),
    )


def _validation_detail(exc: RequestValidationError) -> list[dict]:
    """Field locations and messages only — inputs are never echoed back
    (they may contain destination tokens or grant material)."""
    return [
        {"loc": [str(part) for part in err.get("loc", ())], "msg": err.get("msg", "")}
        for err in exc.errors()
    ]


def _assemble(state: AppState, *, public: bool, admin: bool) -> FastAPI:
    """Build a FastAPI app from shared state for one side of the split.

    ``public=True`` serves /v1, /health, /metrics (+docs when enabled);
    ``admin=True`` serves /admin, /health and /metrics (the CLI's targets).
    Both flags on = the whole surface in one listener (tests, bare runs).
    """

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        state.maybe_prune(time.time())
        state.sweep_task = asyncio.create_task(_sweep_loop(state))
        try:
            yield
        finally:
            if state.sweep_task is not None:
                state.sweep_task.cancel()
                with suppress(asyncio.CancelledError):
                    await state.sweep_task
            await state.sender.aclose()

    # Interactive API docs (Swagger UI / ReDoc / schema) are an operator
    # opt-in (server.swagger_ui) and live on the public listener only.
    swagger = state.config.server.swagger_ui and public
    app = FastAPI(
        title="apns-push-relay",
        # Schema version tracks the package version (releases are v* tags).
        version=version("apns-push-relay"),
        # Interactive API docs are an operator opt-in (server.swagger_ui);
        # disabled, these routes do not exist at all (404).
        docs_url="/docs" if swagger else None,
        redoc_url="/redoc" if swagger else None,
        openapi_url="/openapi.json" if swagger else None,
        lifespan=lifespan,
    )
    app.state.relay = state

    if public:

        @app.get("/", include_in_schema=False)
        async def docs_pointer() -> dict[str, str]:
            """API root: JSON pointer to the docs site (landing on GitHub Pages)."""
            domain = os.environ.get("DOCS_DOMAIN", DEFAULT_DOCS_DOMAIN)
            return {"docs": f"https://{domain}/"}

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        request.state.event_code = exc.code
        state.metrics.inc("failures_total", exc.code)
        return exc.response()

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        request.state.event_code = "invalid_request"
        state.metrics.inc("failures_total", "invalid_request")
        return JSONResponse(
            status_code=422,
            content={"error": "invalid_request", "detail": _validation_detail(exc)},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(
            exc.status_code, f"http_{exc.status_code}"
        )
        request.state.event_code = code
        state.metrics.inc("failures_total", code)
        return JSONResponse(status_code=exc.status_code, content={"error": code})

    @app.exception_handler(Exception)
    async def _internal_error(_request: Request, _exc: Exception) -> JSONResponse:
        # Unclassified failures still answer with a machine code (PLAN §3.4);
        # ServerErrorMiddleware re-raises afterwards so the server logs the
        # traceback. The observe middleware maps the event to `internal_error`.
        state.metrics.inc("failures_total", "internal_error")
        return JSONResponse(status_code=500, content={"error": "internal_error"})

    @app.middleware("http")
    async def observe(request: Request, call_next):
        started = time.perf_counter()
        request.state.event_code = "ok"
        state.maybe_prune(time.time())
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            latency_ms = (time.perf_counter() - started) * 1000
            route = request.scope.get("route")
            path = getattr(route, "path", "<unmatched>")
            code = getattr(request.state, "event_code", "ok")
            if status >= 500 and code == "ok":
                code = "internal_error"
            state.events.record(
                ts=time.time(),
                path=path,
                status=status,
                code=code,
                latency_ms=latency_ms,
            )
            state.metrics.inc("requests_total", str(status))

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(
            state.metrics.render_prometheus(),
            media_type="text/plain; version=0.0.4",
        )

    if public:
        app.include_router(v1_router(state))
    if admin:
        app.include_router(admin_router(state))
    return app
