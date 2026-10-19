"""Unit tests for the SSRF-hardened ownership callback (PLAN §3.1, spec A8):
URL validation, tenant/host matching, pinned DNS resolution, and the
one-shot nonce echo."""

from __future__ import annotations

import json
import socket
import ssl

import httpx
import pytest

from apns_relay.callback import (
    CallbackError,
    callback_host_matches_id,
    validate_callback_url,
    verify_callback,
)
from apns_relay.callback import (
    _resolve_public as real_resolve_public,
)

TENANT = "hooks.example.com"


# -- validate_callback_url -----------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        pytest.param(
            "https://hooks.example.com/hook", "https://hooks.example.com/hook", id="plain"
        ),
        pytest.param(
            "https://hooks.example.com:443/hook",
            "https://hooks.example.com:443/hook",
            id="explicit-443",
        ),
        pytest.param(
            "https://hooks.example.com/hook/",
            "https://hooks.example.com/hook",
            id="trailing-slash-stripped",
        ),
        pytest.param(
            "https://sub.hooks.example.com/hook",
            "https://sub.hooks.example.com/hook",
            id="subdomain",
        ),
    ],
)
def test_validate_callback_url_accepts(url: str, expected: str) -> None:
    assert validate_callback_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        pytest.param("http://hooks.example.com/hook", id="not-https"),
        pytest.param("https:///hook", id="missing-host"),
        pytest.param("https://user@hooks.example.com/hook", id="userinfo"),
        pytest.param("https://user:pass@hooks.example.com/hook", id="password"),
        pytest.param("https://hooks.example.com/hook?x=1", id="query"),
        pytest.param("https://hooks.example.com/hook#frag", id="fragment"),
        pytest.param("https://hooks.example.com:8443/hook", id="non-443-port"),
        pytest.param("https://hooks.example.com:abc/hook", id="non-numeric-port"),
        pytest.param("https://hooks.example.com:99999/hook", id="port-out-of-range"),
        pytest.param("https://[::1", id="urlsplit-valueerror"),
    ],
)
def test_validate_callback_url_rejects(url: str) -> None:
    with pytest.raises(CallbackError) as exc:
        validate_callback_url(url)
    assert exc.value.code == "invalid_callback"


# -- callback_host_matches_id --------------------------------------------------


@pytest.mark.parametrize(
    ("host", "tenant_id", "expected"),
    [
        pytest.param("hooks.example.com", "hooks.example.com", True, id="exact"),
        pytest.param("sub.hooks.example.com", "hooks.example.com", True, id="subdomain"),
        pytest.param("a.b.hooks.example.com", "hooks.example.com", True, id="deep-subdomain"),
        pytest.param("HOOKS.Example.COM", "hooks.example.com", True, id="case-insensitive"),
        pytest.param("hooks.example.com", "HOOKS.EXAMPLE.COM", True, id="case-tenant"),
        pytest.param("hooks.example.com.", "hooks.example.com", True, id="trailing-dot-host"),
        pytest.param("hooks.example.com", "hooks.example.com.", True, id="trailing-dot-tenant"),
        pytest.param("evil.example.net", "hooks.example.com", False, id="unrelated"),
        pytest.param("evilexamples.com", "examples.com", False, id="suffix-glued"),
        pytest.param("examples.com.evil.net", "examples.com", False, id="suffix-prefixed"),
        pytest.param("notexamples.com", "examples.com", False, id="suffix-inside"),
        pytest.param("evil.examples.com", "examples.com", True, id="real-subdomain"),
        pytest.param("examplexcom", "example.com", False, id="not-a-domain-suffix"),
    ],
)
def test_callback_host_matches_id(host: str, tenant_id: str, expected: bool) -> None:
    assert callback_host_matches_id(host, tenant_id) is expected


# -- _resolve_public (SSRF guard; the autouse fixture only patches verify_callback) ---


def _gai_rows(ips: list[str]) -> list[tuple]:
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443)) for ip in ips]


def test_resolve_public_sorted_first_global_address(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _gai_rows(["93.184.216.34", "8.8.8.8"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: rows)
    # Sorted lexicographically, not in DNS order: "8.8.8.8" < "93.184.216.34".
    assert real_resolve_public("hooks.example.com") == "8.8.8.8"


def test_resolve_public_empty_result_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])
    with pytest.raises(CallbackError) as exc:
        real_resolve_public("hooks.example.com")
    assert exc.value.code == "invalid_callback"


@pytest.mark.parametrize(
    "ips",
    [
        pytest.param(["127.0.0.1"], id="loopback"),
        pytest.param(["10.1.2.3"], id="rfc1918"),
        pytest.param(["169.254.1.1"], id="link-local"),
        pytest.param(["100.64.0.1"], id="carrier-nat"),
        pytest.param(["::1"], id="ipv6-loopback"),
        pytest.param(["8.8.8.8", "127.0.0.1"], id="mixed-resolves-rejected"),
    ],
)
def test_resolve_public_non_global_rejected(
    monkeypatch: pytest.MonkeyPatch, ips: list[str]
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _gai_rows(ips))
    with pytest.raises(CallbackError) as exc:
        real_resolve_public("hooks.example.com")
    assert exc.value.code == "invalid_callback"


def test_resolve_public_non_ip_result_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("not-an-ip", 443))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: rows)
    with pytest.raises(CallbackError) as exc:
        real_resolve_public("hooks.example.com")
    assert exc.value.code == "invalid_callback"


def test_resolve_public_gaierror_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_getaddrinfo(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", failing_getaddrinfo)
    with pytest.raises(CallbackError) as exc:
        real_resolve_public("does-not-exist.invalid")
    assert exc.value.code == "invalid_callback"


# -- verify_callback -----------------------------------------------------------


def _echo_handler(seen: list[httpx.Request]):
    """Record the request; echo the nonce exactly as the spec requires."""

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"nonce": json.loads(request.content)["nonce"]})

    return handler


async def test_verify_callback_success() -> None:
    seen: list[httpx.Request] = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(_echo_handler(seen)))
    ok = await verify_callback(
        "https://hooks.example.com/register-hook", TENANT, "nonce-123", client=client
    )
    assert ok is True
    assert len(seen) == 1
    request = seen[0]
    # DNS resolved once and pinned: connected to the IP, hostname kept for SNI.
    assert str(request.url) == "https://93.184.216.34/register-hook"
    assert request.headers["host"] == TENANT
    assert json.loads(request.content) == {
        "id": TENANT,
        "kind": "registration",
        "nonce": "nonce-123",
    }
    assert not client.is_closed  # caller-owned client must not be closed


@pytest.mark.parametrize(
    "response_factory",
    [
        pytest.param(
            lambda request: httpx.Response(200, json={"nonce": "not-the-nonce"}), id="wrong-echo"
        ),
        pytest.param(lambda request: httpx.Response(500, json={"error": "boom"}), id="server-500"),
        pytest.param(lambda request: httpx.Response(403), id="forbidden"),
        pytest.param(lambda request: httpx.Response(204), id="no-content"),
        pytest.param(lambda request: httpx.Response(200), id="empty-body"),
        pytest.param(
            lambda request: httpx.Response(
                200, content=b"<html>hi</html>", headers={"content-type": "text/html"}
            ),
            id="non-json",
        ),
        pytest.param(lambda request: httpx.Response(200, json=["not", "a", "dict"]), id="non-dict"),
        pytest.param(lambda request: httpx.Response(200, json={"nonce": None}), id="null-nonce"),
    ],
)
async def test_verify_callback_rejects_response(response_factory) -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(response_factory))
    ok = await verify_callback("https://hooks.example.com/hook", TENANT, "nonce-1", client=client)
    assert ok is False


async def test_verify_callback_host_mismatch_returns_false() -> None:
    seen: list[httpx.Request] = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(_echo_handler(seen)))
    ok = await verify_callback("https://evil.example.net/hook", TENANT, "nonce-1", client=client)
    assert ok is False
    assert seen == []  # rejected before any request leaves the relay


async def test_verify_callback_resolve_failure_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing_resolve(host: str) -> str:
        raise CallbackError("invalid_callback")

    monkeypatch.setattr("apns_relay.callback._resolve_public", failing_resolve)
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}))
    )
    ok = await verify_callback("https://hooks.example.com/hook", TENANT, "nonce-1", client=client)
    assert ok is False


async def test_verify_callback_transport_error_returns_false() -> None:
    def raising_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = httpx.AsyncClient(transport=httpx.MockTransport(raising_handler))
    ok = await verify_callback("https://hooks.example.com/hook", TENANT, "nonce-1", client=client)
    assert ok is False


@pytest.mark.parametrize(
    "url",
    [
        pytest.param("http://hooks.example.com/hook", id="not-https"),
        pytest.param("https://hooks.example.com:8443/hook", id="bad-port"),
    ],
)
async def test_verify_callback_invalid_url_raises(url: str) -> None:
    with pytest.raises(CallbackError) as exc:
        await verify_callback(url, TENANT, "nonce-1")
    assert exc.value.code == "invalid_callback"


async def test_verify_callback_own_client_created_and_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[httpx.AsyncClient] = []
    seen: list[httpx.Request] = []
    kwargs_seen: list[dict] = []
    real_async_client = httpx.AsyncClient  # capture before patching the name

    def factory(*args, **kwargs) -> httpx.AsyncClient:
        kwargs_seen.append(kwargs)
        client = real_async_client(transport=httpx.MockTransport(_echo_handler(seen)))
        created.append(client)
        return client

    # callback.py resolves httpx.AsyncClient on the shared httpx module; with
    # no client passed it builds its own (verify= pinned SSL context) and the
    # finally clause must aclose it.
    monkeypatch.setattr(httpx, "AsyncClient", factory)
    ok = await verify_callback("https://hooks.example.com/hook", TENANT, "nonce-own")
    assert ok is True
    assert len(created) == 1
    assert created[0].is_closed  # finally: await http.aclose() ran
    assert kwargs_seen[0]["timeout"] == 10.0
    assert isinstance(kwargs_seen[0]["verify"], ssl.SSLContext)
