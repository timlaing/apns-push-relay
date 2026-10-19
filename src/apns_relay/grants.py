"""Ed25519-signed destination-bound grants (enrollment-spec §2.3).

Grant = ``v1.<b64u(claims)>.<b64u(sig)>``. Verification is database-free:
signature → issuer key, expiry, denylist (small), token-hash binding, tenant
binding, allowed kinds. The topic and APNs environment are never caller
supplied — they are resolved from ``app`` via operator config.
"""

from __future__ import annotations

import base64
import json
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .config import AppKeyConfig
from .signing import sha256hex

GRANT_VERSION = "v1"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_claims(claims: dict) -> bytes:
    return json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()


def issue_grant(
    issuer_key: Ed25519PrivateKey,
    issuer_id: str,
    *,
    token_digest: str,
    tenant_id: str,
    tenant_pubkey: str,
    app_id: str,
    kinds: list[str],
    environment: str,
    ttl: int,
    now: float | None = None,
) -> str:
    current = int(time.time() if now is None else now)
    claims = {
        "jti": str(uuid.uuid4()),
        "iss": issuer_id,
        "tok": f"sha256:{token_digest}",
        "ten": tenant_id,
        "tpk": tenant_pubkey,
        "app": app_id,
        "kinds": sorted(kinds),
        "env": environment,
        "iat": current,
        "exp": current + ttl,
        "ttl": ttl,
    }
    body = _b64u(canonical_claims(claims))
    sig = _b64u(issuer_key.sign(canonical_claims(claims)))
    return f"{GRANT_VERSION}.{body}.{sig}"


class GrantError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_grant(grant: str, issuer_public: Ed25519PublicKey) -> dict:
    """Verify signature + structure. Returns claims. Raises GrantError."""
    parts = grant.split(".")
    if len(parts) != 3 or parts[0] != GRANT_VERSION:
        raise GrantError("malformed_grant")
    try:
        raw_claims, raw_sig = _unb64u(parts[1]), _unb64u(parts[2])
    except (ValueError, TypeError):
        raise GrantError("malformed_grant") from None
    try:
        issuer_public.verify(raw_sig, raw_claims)
    except (InvalidSignature, ValueError):
        raise GrantError("bad_signature") from None
    try:
        claims = json.loads(raw_claims)
    except ValueError:
        raise GrantError("malformed_grant") from None
    if not isinstance(claims, dict):
        raise GrantError("malformed_grant")
    return claims


def verify_grant_for_push(
    grant: str,
    issuer_public: Ed25519PublicKey,
    *,
    app: AppKeyConfig,
    destination_token_digest: str,
    tenant_id: str,
    tenant_pubkey: str,
    kind: str,
    now: float | None = None,
) -> dict:
    """Full delivery-path check. Returns claims or raises GrantError."""
    claims = parse_grant(grant, issuer_public)
    current = time.time() if now is None else now
    if claims.get("exp", 0) <= current:
        raise GrantError("grant_expired")
    if claims.get("app") != app.id:
        raise GrantError("app_mismatch")
    if claims.get("ten") != tenant_id or claims.get("tpk") != tenant_pubkey:
        raise GrantError("tenant_mismatch")
    if claims.get("tok") != f"sha256:{destination_token_digest}":
        raise GrantError("destination_mismatch")
    if kind not in claims.get("kinds", []):
        raise GrantError("kind_not_allowed")
    return claims


def grant_topic(app: AppKeyConfig, kind: str) -> str:
    """Resolve the APNs topic from the validated request kind.

    ``kind`` has already been checked against the grant's allowed kinds and the
    App's configured kinds, so this is trusted. The topic is never caller
    supplied — it derives from operator config (App bundle ID).
    """
    if kind == "liveActivity":
        return app.live_activity_topic
    return app.topic


def sha256_token(token: str) -> str:
    return sha256hex(token.encode())
