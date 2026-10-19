"""Canonical request-signing contract: relay ⇄ reference client byte-for-byte.

The golden fixture (``tests/fixtures/canonical.json``) was authored by hand from
the spec — PLAN §3.2 / ``docs/getting-started.md`` §2 / enrollment-spec §2.4 —
and pins the digests and the exact six-line message, so neither implementation
can drift without a test failing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from pathlib import Path

import pytest
import relay_client
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apns_relay.signing import canonical_message as relay_canonical_message
from apns_relay.signing import sha256hex, verify
from tests.conftest import APP_ID, BASE_URL, TENANT_ID, enroll, push_payload

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "canonical.json"
GOLDEN = json.loads(FIXTURE_PATH.read_text())


def test_relay_canonical_message_matches_golden_fixture() -> None:
    inputs = GOLDEN["inputs"]
    body = inputs["body"].encode()
    timestamp = str(inputs["timestamp"])

    # Pinned digests: recomputed here with hashlib and must equal the fixture's.
    assert hashlib.sha256(inputs["token"].encode()).hexdigest() == GOLDEN["token_digest"]
    assert hashlib.sha256(body).hexdigest() == GOLDEN["body_digest"]
    assert sha256hex(body) == GOLDEN["body_digest"]

    message = relay_canonical_message(
        inputs["token"], inputs["method"], inputs["path"], timestamp, inputs["nonce"], body
    )
    assert message == GOLDEN["canonical_message"].encode()
    # Six lines in spec order; the input method is lowercase and uppercased.
    assert message.decode().split("\n") == [
        GOLDEN["token_digest"],
        "POST",
        inputs["path"],
        timestamp,
        inputs["nonce"],
        GOLDEN["body_digest"],
    ]


def test_reference_client_canonical_message_matches_golden_fixture() -> None:
    inputs = GOLDEN["inputs"]
    body = inputs["body"].encode()
    message = relay_client.canonical_message(
        inputs["token"],
        inputs["method"],
        inputs["path"],
        str(inputs["timestamp"]),
        inputs["nonce"],
        body,
    )
    assert message == GOLDEN["canonical_message"].encode()


def test_both_implementations_agree_on_random_inputs() -> None:
    methods = ["post", "GET", "Put", "delete", "pOst"]
    paths = ["/v1/push", "/v1/enroll/renew", "/v1/revoke", "/v1/push/"]
    for _ in range(25):
        method = secrets.choice(methods)
        path = secrets.choice(paths)
        timestamp = str(secrets.randbelow(10**10) + 10**9)
        nonce = secrets.token_urlsafe(secrets.randbelow(24) + 8)
        body = secrets.token_bytes(secrets.randbelow(256))
        token = "tnt_" + secrets.token_hex(8)
        context = f"method={method!r} path={path!r} ts={timestamp} nonce={nonce!r}"
        assert relay_client.canonical_message(
            token, method, path, timestamp, nonce, body
        ) == relay_canonical_message(token, method, path, timestamp, nonce, body), context


def test_reference_client_end_to_end_interop(env) -> None:
    """Full round trip: register + signed push via RelayClient into the ASGI app."""

    def forward(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        assert url.startswith(BASE_URL), f"unexpected url {url}"
        request = env.client.build_request(
            method, url[len(BASE_URL) :], headers=headers, content=body
        )
        response = env.client.send(request)
        return response.status_code, response.content

    # register is unsigned — token/key are irrelevant until the relay mints one.
    bootstrap = relay_client.RelayClient(BASE_URL, token="", private_key=None, transport=forward)
    token = bootstrap.register(TENANT_ID, APP_ID)["token"]

    enrolled = enroll(env, token=token)
    client = relay_client.RelayClient(BASE_URL, token, enrolled.private_key, transport=forward)

    payload = push_payload(enrolled)
    result = client.request("POST", "/v1/push", payload, signed=True)
    assert result == {"result": "accepted", "apnsId": "APNS-ID-OK", "detail": None}

    # Error envelope surfaces as RelayApiError with status + machine code.
    with pytest.raises(relay_client.RelayApiError) as excinfo:
        client.register(TENANT_ID, APP_ID)
    error = excinfo.value
    assert (error.status, error.code) == (409, "id_exists")
    assert str(error) == "409 id_exists"


def test_grant_claims_roundtrip() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    claims = {
        "app": "test-app",
        "env": "production",
        "exp": 1792252500,
        "iat": 1792230900,
        "jti": "6f1c2b3d-4e5f-6789-abcd-ef0123456789",
        "kinds": ["alert", "background"],
        "ten": "hooks.example.com",
        "tok": "sha256:" + "ab" * 32,
        "tpk": "dXBiYXNlNjR1cmxwdWJrZXk",
        "ttl": 21600,
    }
    # Spec §2.3: claims are canonical JSON (sorted keys, no whitespace).
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(private_key.sign(payload)).decode().rstrip("=")
    grant = f"v1.{encoded}.{signature}"
    assert relay_client.grant_claims(grant) == claims


@pytest.mark.parametrize(
    "grant",
    [
        "not-a-grant",
        "v1.only-two-parts",
        "v1." + base64.urlsafe_b64encode(b"[1,2]").decode() + ".x",
    ],
)
def test_grant_claims_rejects_malformed_grants(grant: str) -> None:
    with pytest.raises(ValueError, match="malformed grant"):
        relay_client.grant_claims(grant)


def test_sign_headers_injectable_timestamp_and_nonce() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    token = "tnt_injectable-0001"
    body = b'{"grant":"v1.x"}'
    headers = relay_client.sign_headers(
        private_key,
        token,
        "post",
        "/v1/push",
        body,
        timestamp=1792230900,
        nonce="fixed-nonce-0001",
    )
    assert headers["authorization"] == f"Bearer {token}"
    assert headers["x-relay-time"] == "1792230900"
    assert headers["x-relay-nonce"] == "fixed-nonce-0001"
    # The relay's own verifier accepts the client's signature over the same bytes.
    failure = verify(
        private_key.public_key(),
        token,
        "post",
        "/v1/push",
        "1792230900",
        "fixed-nonce-0001",
        body,
        headers["x-relay-signature"],
        now=1792230900.0,
    )
    assert failure is None
