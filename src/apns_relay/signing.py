"""Ed25519 request signing (token-bound canonical message) and token minting.

Canonical message (PLAN §3.2, enrollment-spec §2.4):

    message = SHA256HEX(tenant_token) \\n method \\n path \\n timestamp \\n
              nonce \\n SHA256HEX(body)

The tenant token is *digested* into the signed message, never raw, so the
canonical string is safe to log and a leaked signature is useless with any
other or substituted token.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_SKEW = 300  # ±5 minutes


def sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mint_tenant_token() -> str:
    """Relay-generated tenant token. Always ``tnt_`` + base64url secret."""
    return "tnt_" + secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    """SHA-256 of a tenant token — the only form ever persisted."""
    return sha256hex(token.encode())


def b64u_decode(value: str) -> bytes:
    """base64url decode, alphabet-strict.

    ``validate=True`` rejects anything outside the (translated) base64
    alphabet instead of silently discarding it, so every signature and
    claims segment has exactly one valid encoding.
    """
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def canonical_message(
    token: str, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    return "\n".join(
        (token_digest(token), method.upper(), path, timestamp, nonce, sha256hex(body))
    ).encode()


def sign(
    private_key: Ed25519PrivateKey,
    token: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    """Return a base64url Ed25519 signature over the canonical message."""
    sig = private_key.sign(canonical_message(token, method, path, timestamp, nonce, body))
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def verify(
    public_key: Ed25519PublicKey,
    token: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    signature_b64: str,
    *,
    now: float | None = None,
) -> str | None:
    """Verify a signature and the timestamp skew window.

    Returns ``None`` on success, otherwise a machine-readable failure code
    (``invalid_timestamp`` | ``stale_timestamp`` | ``invalid_signature``) so the
    route can surface a precise error. Nonce single-use enforcement lives in
    the store (it needs persistence); this function is pure.
    """
    try:
        ts = int(timestamp)
    except ValueError:
        return "invalid_timestamp"
    current = time.time() if now is None else now
    if abs(current - ts) > MAX_SKEW:
        return "stale_timestamp"
    try:
        sig = b64u_decode(signature_b64)
    except (ValueError, TypeError):
        return "invalid_signature"
    try:
        public_key.verify(
            sig,
            canonical_message(token, method, path, timestamp, nonce, body),
        )
    except (InvalidSignature, ValueError):
        return "invalid_signature"
    return None


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate a tenant Ed25519 keypair. Returns (private, public_b64)."""
    private = Ed25519PrivateKey.generate()
    public_b64 = (
        base64.urlsafe_b64encode(private.public_key().public_bytes_raw()).decode().rstrip("=")
    )
    return private, public_b64


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    raw = b64u_decode(value)
    if len(raw) != 32:
        raise ValueError("Ed25519 public keys are 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)
