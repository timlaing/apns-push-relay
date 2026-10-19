"""Async APNs sender with a multi-key registry and per-kid JWT cache.

Each app-specific ``.p8`` gets its own cached ES256 provider token, keyed by
Key ID because the JWT ``kid`` header must match the signing key.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from .config import AppKeyConfig

SANDBOX_HOST = "api.sandbox.push.apple.com"
PRODUCTION_HOST = "api.push.apple.com"
JWT_TTL = 3000  # Apple allows 60 min; refresh at 50 min


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def load_p256_key(path: Path) -> EllipticCurvePrivateKey:
    """Load an ``.p8`` provider key. Must be P-256 (Apple requirement)."""
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, EllipticCurvePrivateKey):
        raise ValueError(f"{path}: not an EC private key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"{path}: APNs requires a P-256 (secp256r1) key")
    return key


def sign_provider_jwt(key: EllipticCurvePrivateKey, key_id: str, team_id: str) -> str:
    """ES256 provider token: header {alg, kid}, claims {iss, iat}."""
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "ES256", "kid": key_id}).encode())
    claims = _b64url(json.dumps({"iss": team_id, "iat": now}).encode())
    message = f"{header}.{claims}".encode()
    der_sig = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_sig)
    signature = _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"{header}.{claims}.{signature}"


@dataclass
class PushResult:
    outcome: str  # accepted | invalidDestination | retryable | rejected
    apns_id: str | None = None
    status: int = 0
    reason: str = ""


class KeyRegistry:
    """Holds one loaded P-256 key + cached JWT per app. Validated at boot."""

    def __init__(self, apps: tuple[AppKeyConfig, ...]) -> None:
        self._keys: dict[str, EllipticCurvePrivateKey] = {}
        self._jwt: dict[str, tuple[str, float]] = {}
        self._meta: dict[str, AppKeyConfig] = {}
        for app in apps:
            key = load_p256_key(app.key_file)
            self._keys[app.id] = key
            self._meta[app.id] = app
            # Pre-sign one JWT per key at boot so misconfig (bad team/key id
            # pairing) fails fast rather than at first push.
            self._jwt[app.id] = (
                sign_provider_jwt(key, app.key_id, app.team_id),
                time.time(),
            )

    def jwt(self, app_id: str) -> str:
        # ``invalidate()`` drops the cache entry; a missing entry re-mints
        # below (unknown apps still raise KeyError via ``self._meta``).
        token, at = self._jwt.get(app_id, ("", 0.0))
        if time.time() - at >= JWT_TTL:
            meta = self._meta[app_id]
            token = sign_provider_jwt(self._keys[app_id], meta.key_id, meta.team_id)
            self._jwt[app_id] = (token, time.time())
        return token

    def invalidate(self, app_id: str) -> None:
        """Drop the cached JWT so the next push re-signs (post key rotation)."""
        self._jwt.pop(app_id, None)


class APNsSender:
    def __init__(self, registry: KeyRegistry, client: httpx.AsyncClient | None = None) -> None:
        self._registry = registry
        self._client = client or httpx.AsyncClient(http2=True, timeout=10)

    async def aclose(self) -> None:
        await self._client.aclose()

    def _host(self, environment: str) -> str:
        return SANDBOX_HOST if environment == "sandbox" else PRODUCTION_HOST

    async def send(
        self,
        app: AppKeyConfig,
        *,
        device_token: str,
        topic: str,
        environment: str,
        payload: dict,
        push_type: str,
        priority: int,
        expiration: int | None = None,
        collapse_id: str | None = None,
    ) -> PushResult:
        if environment not in app.environments:
            return PushResult("rejected", status=400, reason="environment_not_allowed")
        headers = {
            "authorization": f"bearer {self._registry.jwt(app.id)}",
            "apns-topic": topic,
            "apns-push-type": push_type,
            "apns-priority": str(priority),
        }
        if expiration is not None:
            headers["apns-expiration"] = str(expiration)
        if collapse_id is not None:
            headers["apns-collapse-id"] = collapse_id
        url = f"https://{self._host(environment)}/3/device/{device_token}"
        try:
            resp = await self._client.post(url, content=_encode_payload(payload), headers=headers)
        except httpx.HTTPError:
            return PushResult("retryable", status=0, reason="network_error")
        apns_id = resp.headers.get("apns-id")
        if resp.status_code == 200:
            return PushResult("accepted", apns_id=apns_id, status=200)
        reason = _resp_reason(resp)
        return PushResult(
            _map_reason(resp.status_code, reason),
            apns_id=apns_id,
            status=resp.status_code,
            reason=reason,
        )


def _resp_reason(resp: httpx.Response) -> str:
    try:
        return str(resp.json().get("reason", ""))
    except ValueError:
        return ""


def _map_reason(status: int, reason: str) -> str:
    if status == 410 or reason in (
        "Unregistered",
        "BadDeviceToken",
        "DeviceTokenNotForTopic",
    ):
        return "invalidDestination"
    if status == 429 or status >= 500:
        return "retryable"
    if status == 403 and reason == "ExpiredProviderToken":
        return "retryable"
    return "rejected"


def _encode_payload(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
