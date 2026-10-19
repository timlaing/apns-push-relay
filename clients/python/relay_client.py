"""Reference client for apns-push-relay (M8).

Single-file, stdlib-HTTP implementation of the tenant protocol: canonical
request signing (byte-for-byte identical to ``apns_relay.signing``), the
registration and push contracts, and the three-leg enrollment flow. The only
third-party requirement is ``cryptography`` for Ed25519.

Interoperability guarantee: ``sign_headers()`` output is asserted against a
shared fixture *and* accepted end-to-end by the relay's test suite
(``tests/test_contract_signing.py``), so other language implementations can
reproduce this file's bytes exactly.

    client = RelayClient("https://api.push.example.org", token, private_key)
    client.register("hooks.example.com", "my-app")
    result = client.push(grant, device_token, "alert",
                         {"alert": {"title": "hi", "body": "there"}})
    assert result["result"] in {"accepted", "invalidDestination",
                                "retryable", "rejected"}
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

__all__ = [
    "RelayApiError",
    "RelayClient",
    "canonical_message",
    "grant_claims",
    "sign_headers",
]

Transport = Callable[[str, str, dict[str, str], bytes], tuple[int, bytes]]


class RelayApiError(Exception):
    """Non-2xx from the relay: carries status + machine error code."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(f"{status} {code}{' ' + detail if detail else ''}")
        self.status = status
        self.code = code
        self.detail = detail


def canonical_message(
    token: str, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    """The exact bytes Ed25519 signs — mirrors apns_relay.signing.canonical_message.

    message = SHA256HEX(token) \\n METHOD \\n path \\n timestamp \\n nonce \\n
              SHA256HEX(body)
    """
    return "\n".join(
        (
            hashlib.sha256(token.encode()).hexdigest(),
            method.upper(),
            path,
            timestamp,
            nonce,
            hashlib.sha256(body).hexdigest(),
        )
    ).encode()


def sign_headers(
    private_key: Any,  # Ed25519PrivateKey (cryptography)
    token: str,
    method: str,
    path: str,
    body: bytes,
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Headers for a signed route: bearer token + time/nonce/signature."""
    ts = str(timestamp if timestamp is not None else int(time.time()))
    nonce = nonce or secrets.token_urlsafe(16)
    message = canonical_message(token, method, path, ts, nonce, body)
    signature = base64.urlsafe_b64encode(private_key.sign(message)).decode().rstrip("=")
    return {
        "authorization": f"Bearer {token}",
        "x-relay-time": ts,
        "x-relay-nonce": nonce,
        "x-relay-signature": signature,
    }


def grant_claims(grant: str) -> dict[str, Any]:
    """DECODE ONLY — does not verify the signature. Inspection/tests only;
    the relay verifies grants itself and so should anything security-relevant."""
    parts = grant.split(".")
    if len(parts) != 3:
        raise ValueError("malformed grant")
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    if not isinstance(claims, dict):
        raise ValueError("malformed grant")
    return claims


def _urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes
) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url, data=body if body else None, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class RelayClient:
    """Talks to one relay instance as one tenant.

    ``transport`` is ``(method, url, headers, body) -> (status, bytes)`` —
    defaults to urllib; tests inject a fake or a live in-process app.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        private_key: Any,  # Ed25519PrivateKey
        *,
        transport: Transport | None = None,
        now: Callable[[], int] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.private_key = private_key
        self._transport = transport or _urllib_transport
        self._now = now or (lambda: int(time.time()))

    # -- plumbing -----------------------------------------------------------

    def build_request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        signed: bool = False,
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> tuple[str, bytes, dict[str, str]]:
        """Return ``(path, body_bytes, headers)`` — the exact request to send."""
        body = (
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
            if payload is not None
            else b""
        )
        headers = {"content-type": "application/json"}
        if signed:
            headers.update(
                sign_headers(
                    self.private_key,
                    self.token,
                    method,
                    path,
                    body,
                    timestamp=timestamp if timestamp is not None else self._now(),
                    nonce=nonce,
                )
            )
        return path, body, headers

    def request(
        self, method: str, path: str, payload: dict[str, Any] | None = None, *, signed: bool = False
    ) -> Any:
        path, body, headers = self.build_request(method, path, payload, signed=signed)
        status, raw = self._transport(method, f"{self.base_url}{path}", headers, body)
        parsed: Any
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        if status >= 400:
            code = parsed.get("error", "error") if isinstance(parsed, dict) else "error"
            detail = parsed.get("detail", "") if isinstance(parsed, dict) else ""
            raise RelayApiError(status, code, detail if isinstance(detail, str) else "")
        return parsed

    # -- protocol -----------------------------------------------------------

    def register(self, tenant_id: str, app: str, callback: str | None = None) -> dict:
        payload: dict[str, Any] = {"id": tenant_id, "app": app}
        if callback is not None:
            payload["callback"] = callback
        return self.request("POST", "/v1/register", payload)

    def push(
        self,
        grant: str,
        destination_token: str,
        kind: str,
        content: dict[str, Any],
        *,
        event_id: str | None = None,
        expires_at: int | None = None,
    ) -> dict:
        payload: dict[str, Any] = {
            "grant": grant,
            "destinationToken": destination_token,
            "kind": kind,
            "content": content,
        }
        if event_id is not None:
            payload["eventId"] = event_id
        if expires_at is not None:
            payload["expiresAt"] = expires_at
        return self.request("POST", "/v1/push", payload, signed=True)

    def rotate(self, new_pubkey: str) -> dict:
        """Rotate this tenant's signing key and token (spec §2.7).

        Signed with the CURRENT token/keypair — proof of possession. The
        response's ``token`` replaces the current one, and subsequent
        requests must be signed with the new keypair passed here; devices
        re-enroll with ``new_pubkey`` (grants bound to the old key stop
        verifying).
        """
        return self.request("POST", "/v1/rotate", {"pubkey": new_pubkey}, signed=True)

    def enroll_begin(self, app: str, tenant_id: str, destination_token: str) -> dict:
        return self.request(
            "POST",
            "/v1/enroll/begin",
            {"app": app, "tenantId": tenant_id, "destinationToken": destination_token},
        )

    def enroll_finish(
        self,
        challenge_id: str,
        attestation: str,
        assertion: str,
        tenant_id: str,
        tenant_pubkey: str,
        kinds: list[str],
        ttl: int | None = None,
    ) -> dict:
        payload: dict[str, Any] = {
            "challengeId": challenge_id,
            "attestation": attestation,
            "assertion": assertion,
            "tenantId": tenant_id,
            "tenantPubkey": tenant_pubkey,
            "kinds": kinds,
        }
        if ttl is not None:
            payload["ttl"] = ttl
        return self.request("POST", "/v1/enroll/finish", payload)

    def enroll_renew(self, grant: str, ttl: int | None = None) -> dict:
        payload: dict[str, Any] = {"grant": grant}
        if ttl is not None:
            payload["ttl"] = ttl
        return self.request("POST", "/v1/enroll/renew", payload, signed=True)

    def revoke(self, grant: str) -> dict:
        return self.request("POST", "/v1/revoke", {"grant": grant}, signed=True)
