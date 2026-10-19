"""Unit tests for the APNs layer: P-256 keys, provider JWTs, registry cache,
request headers, and the APNs outcome mapping."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apns_relay.apns import (
    JWT_TTL,
    PRODUCTION_HOST,
    SANDBOX_HOST,
    APNsSender,
    KeyRegistry,
    load_p256_key,
    sign_provider_jwt,
)
from tests.conftest import (
    APP_ID,
    BUNDLE_ID,
    DEST_TOKEN,
    KEY_ID,
    OTHER_APP_ID,
    TEAM_ID,
    load_test_config,
    write_config,
)


def _b64u_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _write_key(path: Path, key: Any) -> Path:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


class StubAPNs:
    """Records requests; replays queued outcomes.

    Queue items: ``httpx.Response`` returned as-is, an ``Exception`` raised
    inside the handler, or ``(status, reason)`` answered as a JSON error body.
    """

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.queue: list[Any] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if not self.queue:
            return httpx.Response(200, headers={"apns-id": "APNS-ID-OK"})
        item = self.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, httpx.Response):
            return item
        status, reason = item
        return httpx.Response(status, json={"reason": reason})


# -- fixtures ------------------------------------------------------------------


@pytest.fixture
def config(tmp_path: Path) -> Any:
    return load_test_config(write_config(tmp_path, include_second_app=True))


@pytest.fixture
def app(config: Any) -> Any:
    return config.app(APP_ID)


@pytest.fixture
def stub() -> StubAPNs:
    return StubAPNs()


@pytest.fixture
def sender(config: Any, stub: StubAPNs) -> APNsSender:
    return APNsSender(
        KeyRegistry(config.enabled_apps),
        client=httpx.AsyncClient(transport=httpx.MockTransport(stub.handler)),
    )


def _send(sender: APNsSender, app: Any, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = {
        "device_token": DEST_TOKEN,
        "topic": app.topic,
        "environment": "sandbox",
        "payload": {"aps": {"alert": {"title": "t", "body": "b"}}},
        "push_type": "alert",
        "priority": 10,
    }
    kwargs.update(overrides)
    return sender.send(app, **kwargs)


# -- load_p256_key -------------------------------------------------------------


def test_load_p256_key_accepts_p256(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    path = _write_key(tmp_path / f"AuthKey_{KEY_ID}.p8", key)
    loaded = load_p256_key(path)
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    assert isinstance(loaded.curve, ec.SECP256R1)
    assert loaded.private_numbers() == key.private_numbers()


@pytest.mark.parametrize(
    "make_key",
    [
        pytest.param(Ed25519PrivateKey.generate, id="ed25519"),
        pytest.param(
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), id="rsa"
        ),
    ],
)
def test_load_p256_key_rejects_non_ec_key(tmp_path: Path, make_key: Any) -> None:
    path = _write_key(tmp_path / "AuthKey_NOTAKEYID.p8", make_key())
    with pytest.raises(ValueError, match="not an EC private key"):
        load_p256_key(path)


def test_load_p256_key_rejects_wrong_curve(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    path = _write_key(tmp_path / "AuthKey_NOTAKEYID.p8", key)
    with pytest.raises(ValueError, match="P-256"):
        load_p256_key(path)


# -- sign_provider_jwt ---------------------------------------------------------


def test_sign_provider_jwt_header_claims_and_signature(clock: Any) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    token = sign_provider_jwt(key, KEY_ID, TEAM_ID)
    header_b64, claims_b64, sig_b64 = token.split(".")
    header = json.loads(_b64u_decode(header_b64))
    claims = json.loads(_b64u_decode(claims_b64))
    assert header == {"alg": "ES256", "kid": KEY_ID}
    assert claims["iss"] == TEAM_ID
    assert claims["iat"] == int(clock.t)
    raw_sig = _b64u_decode(sig_b64)
    assert len(raw_sig) == 64
    der_sig = utils.encode_dss_signature(
        int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big")
    )
    # Signature verifies against the public key over "<header>.<claims>".
    key.public_key().verify(
        der_sig, f"{header_b64}.{claims_b64}".encode(), ec.ECDSA(hashes.SHA256())
    )


# -- KeyRegistry ---------------------------------------------------------------


def test_registry_presigns_jwt_per_app(config: Any, clock: Any) -> None:
    registry = KeyRegistry(config.enabled_apps)
    for app_id in (APP_ID, OTHER_APP_ID):
        header = json.loads(_b64u_decode(registry.jwt(app_id).split(".")[0]))
        assert header == {"alg": "ES256", "kid": KEY_ID}


def test_registry_rejects_bad_key_at_boot(tmp_path: Path) -> None:
    config_path = write_config(tmp_path)
    _write_key(tmp_path / "keys" / f"AuthKey_{KEY_ID}.p8", Ed25519PrivateKey.generate())
    config = load_test_config(config_path)
    with pytest.raises(ValueError, match="not an EC private key"):
        KeyRegistry(config.enabled_apps)


def test_registry_jwt_cached_until_ttl(config: Any, clock: Any) -> None:
    registry = KeyRegistry(config.enabled_apps)
    first = registry.jwt(APP_ID)
    assert registry.jwt(APP_ID) == first  # untouched within the TTL
    clock.advance(JWT_TTL - 1)
    assert registry.jwt(APP_ID) == first  # one second short of expiry
    clock.advance(1)
    refreshed = registry.jwt(APP_ID)
    assert refreshed != first  # iat moved with the clock → new token
    assert registry.jwt(APP_ID) == refreshed  # refresh is itself cached


def test_registry_invalidate_remints(config: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    registry = KeyRegistry(config.enabled_apps)
    registry.jwt(APP_ID)
    registry.invalidate(APP_ID)
    minted: list[tuple[str, str]] = []

    def fake_sign(key: Any, key_id: str, team_id: str) -> str:
        minted.append((key_id, team_id))
        return "fresh-jwt"

    monkeypatch.setattr("apns_relay.apns.sign_provider_jwt", fake_sign)
    # The dropped cache entry must re-mint rather than KeyError.
    assert registry.jwt(APP_ID) == "fresh-jwt"
    assert minted == [(KEY_ID, TEAM_ID)]
    # ...and the freshly minted token is cached again.
    assert registry.jwt(APP_ID) == "fresh-jwt"
    assert len(minted) == 1


def test_registry_jwt_unknown_app_raises_keyerror(config: Any) -> None:
    registry = KeyRegistry(config.enabled_apps)
    with pytest.raises(KeyError):
        registry.jwt("no-such-app")


def test_registry_invalidate_unknown_app_is_a_noop(config: Any) -> None:
    registry = KeyRegistry(config.enabled_apps)
    registry.invalidate("no-such-app")  # pop() with default: nothing to drop


# -- APNsSender.send -----------------------------------------------------------


async def test_send_accepted_sandbox_request(sender: APNsSender, stub: StubAPNs, app: Any) -> None:
    payload = {"aps": {"alert": {"title": "t", "body": "b"}}}
    result = await _send(sender, app, payload=payload)
    assert result.outcome == "accepted"
    assert result.status == 200
    assert result.apns_id == "APNS-ID-OK"
    assert result.reason == ""

    assert len(stub.calls) == 1
    request = stub.calls[0]
    assert request.url.host == SANDBOX_HOST
    assert request.url.path == f"/3/device/{DEST_TOKEN}"
    headers = request.headers
    assert headers["apns-topic"] == app.topic
    assert headers["apns-push-type"] == "alert"
    assert headers["apns-priority"] == "10"
    assert "apns-expiration" not in headers
    assert "apns-collapse-id" not in headers
    token = headers["authorization"].removeprefix("bearer ")
    assert json.loads(_b64u_decode(token.split(".")[0]))["kid"] == KEY_ID
    assert json.loads(request.content) == payload


async def test_send_production_live_activity_headers(
    sender: APNsSender, stub: StubAPNs, app: Any
) -> None:
    result = await _send(
        sender,
        app,
        topic=app.live_activity_topic,
        environment="production",
        push_type="liveactivity",
        priority=10,
        expiration=1_700_000_000,
        collapse_id="event-abc",
    )
    assert result.outcome == "accepted"
    request = stub.calls[0]
    assert request.url.host == PRODUCTION_HOST
    assert request.headers["apns-topic"] == f"{BUNDLE_ID}.push-type.liveactivity"
    assert request.headers["apns-push-type"] == "liveactivity"
    assert request.headers["apns-expiration"] == "1700000000"
    assert request.headers["apns-collapse-id"] == "event-abc"


async def test_send_environment_not_allowed_makes_no_request(
    sender: APNsSender, stub: StubAPNs, app: Any
) -> None:
    result = await _send(sender, app, environment="development")
    assert result.outcome == "rejected"
    assert result.status == 400
    assert result.reason == "environment_not_allowed"
    assert result.apns_id is None
    assert stub.calls == []  # rejected before any HTTP


@pytest.mark.parametrize(
    ("queue_item", "expected_outcome", "expected_reason"),
    [
        pytest.param((410, "Unregistered"), "invalidDestination", "Unregistered", id="410"),
        pytest.param(
            (400, "BadDeviceToken"), "invalidDestination", "BadDeviceToken", id="bad-token"
        ),
        pytest.param(
            (400, "DeviceTokenNotForTopic"),
            "invalidDestination",
            "DeviceTokenNotForTopic",
            id="wrong-topic",
        ),
        pytest.param((429, "TooManyRequests"), "retryable", "TooManyRequests", id="429"),
        pytest.param((500, "InternalServerError"), "retryable", "InternalServerError", id="500"),
        pytest.param((503, "Shutdown"), "retryable", "Shutdown", id="503"),
        pytest.param(
            (403, "ExpiredProviderToken"),
            "retryable",
            "ExpiredProviderToken",
            id="expired-token",
        ),
        pytest.param(
            (403, "InvalidProviderToken"), "rejected", "InvalidProviderToken", id="403-other"
        ),
        pytest.param((400, "PayloadTooLarge"), "rejected", "PayloadTooLarge", id="too-large"),
        pytest.param((400, "TopicDisallowed"), "rejected", "TopicDisallowed", id="400-other"),
    ],
)
async def test_send_maps_apns_outcomes(
    sender: APNsSender,
    stub: StubAPNs,
    app: Any,
    queue_item: tuple[int, str],
    expected_outcome: str,
    expected_reason: str,
) -> None:
    stub.queue.append(queue_item)
    result = await _send(sender, app, payload={})
    assert result.outcome == expected_outcome
    assert result.status == queue_item[0]
    assert result.reason == expected_reason
    assert result.apns_id is None  # APNs error responses carry no apns-id here


@pytest.mark.parametrize(
    "transport_error",
    [
        pytest.param(httpx.ConnectError("no route to host"), id="connect-error"),
        pytest.param(httpx.TimeoutException("timed out"), id="timeout"),
    ],
)
async def test_send_transport_errors_are_retryable(
    sender: APNsSender, stub: StubAPNs, app: Any, transport_error: Exception
) -> None:
    stub.queue.append(transport_error)
    result = await _send(sender, app, payload={})
    assert (result.outcome, result.status, result.reason) == ("retryable", 0, "network_error")


@pytest.mark.parametrize(
    "error_response",
    [
        pytest.param(
            httpx.Response(
                400, content=b"<html>nope</html>", headers={"content-type": "text/html"}
            ),
            id="non-json",
        ),
        pytest.param(httpx.Response(400, json={"timestamp": 123}), id="no-reason-field"),
    ],
)
async def test_send_error_body_without_reason_falls_back(
    sender: APNsSender, stub: StubAPNs, app: Any, error_response: httpx.Response
) -> None:
    stub.queue.append(error_response)
    result = await _send(sender, app, payload={})
    assert (result.outcome, result.status, result.reason) == ("rejected", 400, "")


async def test_send_error_response_passthrough_apns_id(
    sender: APNsSender, stub: StubAPNs, app: Any
) -> None:
    stub.queue.append(
        httpx.Response(500, json={"reason": "Shutdown"}, headers={"apns-id": "APNS-ID-ERR"})
    )
    result = await _send(sender, app, payload={})
    assert result.outcome == "retryable"
    assert result.apns_id == "APNS-ID-ERR"


async def test_sender_aclose(config: Any, stub: StubAPNs) -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(stub.handler))
    sender = APNsSender(KeyRegistry(config.enabled_apps), client=client)
    await sender.aclose()
    assert client.is_closed
