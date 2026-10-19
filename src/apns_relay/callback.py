"""SSRF-hardened HTTPS callback for registration ownership proof.

Ports family-vpn's ``PublicHTTPS``/``https_url`` (relay_service.py:20,
relay_protocol.py:20). The callback is a one-shot ownership challenge: the
relay POSTs a signed nonce and requires an echo. Only public HTTPS on port 443
is allowed, DNS is resolved once and pinned, and any non-global address is
rejected — so the callback cannot be used to probe the relay's internal
network.
"""

from __future__ import annotations

import hmac
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit

import httpx


class CallbackError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validate_callback_url(url: str) -> str:
    """HTTPS, port 443, no userinfo/query/fragment. Returns normalized URL."""
    try:
        parsed = urlsplit(url)
        # ``parsed.port`` raises ValueError for a non-numeric or out-of-range
        # port; that is attacker-controlled input, so fold it into the same
        # invalid_callback answer as every other parse failure.
        port = parsed.port
    except ValueError:
        raise CallbackError("invalid_callback") from None
    if parsed.scheme != "https":
        raise CallbackError("invalid_callback")
    if not parsed.hostname:
        raise CallbackError("invalid_callback")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CallbackError("invalid_callback")
    if port not in (None, 443):
        raise CallbackError("invalid_callback")
    return url.rstrip("/")


def callback_host_matches_id(host: str, tenant_id: str) -> bool:
    """Callback host must equal the claimed id or a subdomain of it.

    Otherwise the proof proves nothing about the claimed identity.
    """
    host = host.lower().rstrip(".")
    tenant_id = tenant_id.lower().rstrip(".")
    return host == tenant_id or host.endswith("." + tenant_id)


def _resolve_public(host: str) -> str:
    """Resolve once; reject if any address is non-global (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise CallbackError("invalid_callback") from None
    if not infos:
        raise CallbackError("invalid_callback")
    addresses = {row[4][0] for row in infos}
    for addr in addresses:
        try:
            if not ipaddress.ip_address(addr).is_global:
                raise CallbackError("invalid_callback")
        except ValueError:
            raise CallbackError("invalid_callback") from None
    return sorted(addresses)[0]


async def verify_callback(
    url: str,
    tenant_id: str,
    nonce: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 10.0,
) -> bool:
    """POST the challenge and require the nonce echoed back within the timeout.

    Returns True only on a 2xx whose body echoes the nonce. All failures —
    network, non-2xx, wrong echo — return False. DNS is resolved once and the
    connection is pinned to that address with TLS SNI/verification against the
    original hostname.
    """
    url = validate_callback_url(url)
    host = urlsplit(url).hostname or ""
    if not callback_host_matches_id(host, tenant_id):
        return False
    try:
        address = _resolve_public(host)
    except CallbackError:
        return False

    pinned = httpx.URL(url).copy_with(host=address)
    headers = {"host": host}
    payload = {"id": tenant_id, "kind": "registration", "nonce": nonce}
    own = client is None
    http = client or httpx.AsyncClient(timeout=timeout, verify=_pinned_context(host))
    try:
        resp = await http.post(str(pinned), json=payload, headers=headers)
    except httpx.HTTPError:
        return False
    finally:
        if own:
            await http.aclose()
    if resp.status_code not in (200, 204):
        return False
    if resp.status_code == 204:
        return False  # must echo the nonce; empty body proves nothing
    try:
        body = resp.json()
    except ValueError:
        return False
    if not isinstance(body, dict):
        return False
    return hmac.compare_digest(str(body.get("nonce", "")), nonce)


def _pinned_context(host: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    return ctx
