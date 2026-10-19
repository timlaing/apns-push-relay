"""Internal admin API behind ``RELAY_ADMIN_TOKEN`` (PLAN §3.1, §5).

Serves the ``relay`` CLI. Never proxied by nginx — ``/admin`` returns 404 at
the edge (deploy/nginx.conf.template), so the only path in is the Docker
network. Responses expose counts, statuses and machine codes only: no tokens,
grants, payloads or destination material (PLAN §3.4).
"""

from __future__ import annotations

import hmac
import time
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Request

from .errors import BadRequest, NotFound, Unauthorized
from .models import AdminDenylistEntry, AdminReissueRequest, AdminTenantRef
from .signing import mint_tenant_token, token_digest

if TYPE_CHECKING:
    from .app import AppState

DEFAULT_DENY_SECONDS = 86400  # when `expires` is omitted: one day


def admin_router(state: AppState) -> APIRouter:
    router = APIRouter(prefix="/admin", tags=["admin"])

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

    return router
