"""Internal admin API behind ``RELAY_ADMIN_TOKEN`` (PLAN §3.1, §5).

Serves the ``relay`` CLI. Never proxied by nginx — ``/admin`` returns 404 at
the edge (deploy/nginx.conf.template), so the only path in is the Docker
network. Responses expose counts, statuses and machine codes only: no tokens,
grants, payloads or destination material (PLAN §3.4).
"""

from __future__ import annotations

import hmac
import time
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Request

from . import configedit
from .config import ConfigError
from .errors import BadRequest, Conflict, NotFound, Unauthorized
from .models import AdminAppEntry, AdminDenylistEntry, AdminReissueRequest, AdminTenantRef
from .signing import mint_tenant_token, token_digest

if TYPE_CHECKING:
    from .app import AppState

DEFAULT_DENY_SECONDS = 86400  # when `expires` is omitted: one day


def admin_router(state: AppState) -> APIRouter:
    router = APIRouter(prefix="/admin", tags=["admin"], include_in_schema=False)

    async def require_admin(request: Request) -> None:
        header = request.headers.get("authorization", "")
        supplied = header[len("Bearer ") :] if header.startswith("Bearer ") else ""
        if not supplied or not hmac.compare_digest(supplied, state.config.admin_token):
            raise Unauthorized("bad_admin_token")

    admin = Depends(require_admin)

    @router.get("/status", dependencies=[admin])
    async def status() -> dict:
        now = time.time()
        return {
            "version": version("apns-push-relay"),
            "status": "ok",
            "uptimeSeconds": int(now - state.started_at),
            "tenants": state.store.count_tenants(),
            "denylisted": len(state.store.list_denied(now)),
            "apps": [
                {
                    "id": app.id,
                    "enabled": app.enabled,
                    "keyId": app.key_id,
                    "environments": list(app.environments),
                    "kinds": list(app.kinds),
                    "quota": {
                        "burst_per_min": app.quota.burst_per_min,
                        "daily": app.quota.daily,
                        "token_burst_per_min": app.quota.token_burst_per_min,
                    },
                    "grantTtl": {
                        "min": app.grant_ttl.min,
                        "max": app.grant_ttl.max,
                        "default": app.grant_ttl.default,
                    },
                    "attestEnvironment": app.attest_environment,
                }
                for app in state.config.apps
            ],
            "metrics": state.metrics.snapshot(),
        }

    @router.get("/tenants", dependencies=[admin])
    async def tenants(app: str | None = Query(default=None)) -> dict:
        rows = state.store.list_tenants(app)
        return {
            "tenants": [
                {
                    "tenant": row.id,
                    "app": row.app,
                    "registeredAt": int(row.registered_at),
                    "lastSeen": int(row.last_seen),
                }
                for row in rows
            ]
        }

    @router.get("/tenants/verify", dependencies=[admin])
    async def verify(
        tenant: str = Query(min_length=1),
        app: str | None = Query(default=None),
    ) -> dict:
        for row in state.store.list_tenants(app):
            if row.id == tenant:
                return {
                    "exists": True,
                    "tenant": row.id,
                    "app": row.app,
                    "registeredAt": int(row.registered_at),
                    "lastSeen": int(row.last_seen),
                }
        raise NotFound("unknown_tenant")

    @router.post("/tenants/revoke", dependencies=[admin])
    async def revoke_tenant(body: AdminTenantRef) -> dict:
        removed = state.store.delete_tenant(body.tenant, body.app)
        if removed == 0:
            raise NotFound("unknown_tenant")
        # Immediate: the next authenticated request fails with unknown_tenant
        # (PLAN §3.4 revocation).
        return {"revoked": removed}

    @router.post("/tenants/reissue", dependencies=[admin])
    async def reissue_tenant(body: AdminReissueRequest) -> dict:
        token = mint_tenant_token()
        if not state.store.set_token(body.tenant, body.app, token_digest(token)):
            raise NotFound("unknown_tenant")
        return {"tenant": body.tenant, "app": body.app, "token": token}

    @router.get("/denylist", dependencies=[admin])
    async def denylist() -> dict:
        now = time.time()
        return {
            "entries": [
                {"key": key, "expires": int(expires)}
                for key, expires in state.store.list_denied(now)
            ]
        }

    @router.post("/denylist", dependencies=[admin])
    async def denylist_add(body: AdminDenylistEntry) -> dict:
        expires = body.expires
        if expires is None:
            expires = int(time.time()) + DEFAULT_DENY_SECONDS
        if expires <= time.time():
            raise BadRequest("invalid_expiry")
        state.store.deny(body.key, float(expires))
        return {"key": body.key, "expires": expires}

    @router.get("/logs", dependencies=[admin])
    async def logs(
        since: float | None = Query(default=None),
        errors: bool = Query(default=False),
    ) -> dict:
        return {"events": state.events.recent(since=since, errors_only=errors)}

    # -- config-file app management (the file is the source of truth; the
    # running state picks changes up on restart) -----------------------------

    def _config_file() -> Path:
        if state.config_path is None:
            raise BadRequest("no_config_file", "server did not boot from a config file")
        return state.config_path

    @router.get("/apps", dependencies=[admin])
    async def apps() -> dict:
        """The config file's apps, entries as written (config-shaped)."""
        return {"apps": configedit.list_apps(_config_file())}

    @router.get("/keys", dependencies=[admin])
    async def keys() -> dict:
        """APNs signing key ids present beside the config (keys/AuthKey_*.p8)."""
        return {"keys": configedit.discover_keys(_config_file())}

    @router.post("/apps", dependencies=[admin], status_code=201)
    async def apps_add(body: AdminAppEntry) -> dict:
        config_path = _config_file()
        entry: dict = body.model_dump()
        if not entry["display_name"]:
            entry["display_name"] = entry["id"]
        if not entry["kinds"]:
            entry["kinds"] = (
                ["alert", "background", "liveActivity"]
                if entry["live_activity"]
                else ["alert", "background"]
            )
        if any(app.get("id") == entry["id"] for app in configedit.list_apps(config_path)):
            raise Conflict("app_exists", f"app id {entry['id']!r} already exists")
        # operator-facing defaults live with the config format, not the API
        entry["registration"] = {"callback_required": False}
        entry["quota"] = dict(configedit.DEFAULT_QUOTA)
        entry["grant_ttl"] = dict(configedit.DEFAULT_GRANT_TTL)
        try:
            configedit.add_app(config_path, entry)
        except ConfigError as exc:
            raise BadRequest("invalid_app", str(exc)) from None
        return {"app": entry, "restartRequired": True}

    @router.delete("/apps/{app_id}", dependencies=[admin])
    async def apps_remove(app_id: str) -> dict:
        config_path = _config_file()
        if not any(app.get("id") == app_id for app in configedit.list_apps(config_path)):
            raise NotFound("unknown_app")
        try:
            configedit.remove_app(config_path, app_id)
        except ConfigError as exc:
            # the last-app guard: the config must keep at least one app
            raise BadRequest("last_app", str(exc)) from None
        return {"removed": app_id, "restartRequired": True}

    return router
