"""Wire models. Every request model uses ``extra="forbid"`` — unknown fields
are a hard rejection, per PLAN §3.2/§3.3 (M5: oversized fields → 422)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Kind = Literal["alert", "background", "liveActivity"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(Strict):
    id: str = Field(min_length=1, max_length=253)
    app: str = Field(min_length=1, max_length=64)
    callback: str | None = Field(default=None, max_length=2048)


class RegisterResponse(BaseModel):
    tenant: str
    app: str
    token: str
    quota: dict[str, int]
    registered_at: int
    expires_at: int


class RotateRequest(Strict):
    """Replacement Ed25519 signing key (spec §2.7). The request is signed
    with the CURRENT binding — proof of possession — and the tenant token
    rotates in the same call."""

    pubkey: str = Field(min_length=40, max_length=128)


class RotateResponse(BaseModel):
    tenant: str
    app: str
    token: str
    rotated_at: int


class PushContent(Strict):
    """Content is keyed by kind (PLAN §3.2) plus the kind-independent sealed
    blob. The section for ``kind`` is required — enforced in payload build."""

    alert: dict[str, Any] | None = None
    background: dict[str, Any] | None = None
    liveActivity: dict[str, Any] | None = None
    sealed: str | None = None


class PushRequest(Strict):
    grant: str = Field(min_length=8, max_length=8192)
    destinationToken: str = Field(min_length=32, max_length=2000, pattern=r"^[0-9a-fA-F]{32,2000}$")
    kind: Kind
    eventId: str | None = Field(default=None, max_length=64)
    expiresAt: int | None = None
    content: PushContent


class PushResponse(BaseModel):
    result: Literal["accepted", "invalidDestination", "retryable", "rejected"]
    apnsId: str | None = None
    detail: str | None = None


class EnrollBeginRequest(Strict):
    app: str = Field(min_length=1, max_length=64)
    tenantId: str = Field(min_length=1, max_length=253)
    destinationToken: str = Field(min_length=32, max_length=2000, pattern=r"^[0-9a-fA-F]{32,2000}$")


class EnrollBeginResponse(BaseModel):
    challengeId: str
    serverChallenge: str
    expiresAt: int


class EnrollFinishRequest(Strict):
    challengeId: str = Field(min_length=8, max_length=128)
    attestation: str = Field(min_length=16, max_length=65536)
    assertion: str = Field(min_length=16, max_length=65536)
    tenantId: str = Field(min_length=1, max_length=253)
    tenantPubkey: str = Field(min_length=40, max_length=128)
    kinds: list[Kind] = Field(min_length=1, max_length=3)
    ttl: int | None = None


class EnrollFinishResponse(BaseModel):
    grant: str
    consent: dict[str, Any]


class EnrollRenewRequest(Strict):
    grant: str = Field(min_length=8, max_length=8192)
    ttl: int | None = None


class EnrollRenewResponse(BaseModel):
    grant: str
    expiresAt: int


class RevokeRequest(Strict):
    grant: str = Field(min_length=8, max_length=8192)


class RevokeResponse(BaseModel):
    revoked: str


class ErrorBody(BaseModel):
    error: str
    detail: str | None = None


# -- admin API (CLI-facing; never proxied by nginx) ---------------------------


class AdminTenantRef(Strict):
    tenant: str = Field(min_length=1, max_length=253)
    app: str | None = Field(default=None, max_length=64)


class AdminReissueRequest(Strict):
    tenant: str = Field(min_length=1, max_length=253)
    app: str = Field(min_length=1, max_length=64)


class AdminDenylistEntry(Strict):
    """A denylist key is a grant ``jti`` (uuid) or ``sha256:<hex>`` token hash."""

    key: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^(sha256:[0-9a-f]{64}|[A-Za-z0-9_-]{16,64})$",
    )
    expires: int | None = None
