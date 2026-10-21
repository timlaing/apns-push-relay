"""Ed25519 request signing: canonical message, token minting, verify codes."""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apns_relay.signing import (
    MAX_SKEW,
    canonical_message,
    generate_keypair,
    mint_tenant_token,
    public_key_from_b64,
    sha256hex,
    sign,
    token_digest,
    verify,
)
from tests.conftest import Clock

TOKEN = "tnt_test-token-value"
BODY = b'{"grant":"g","kind":"alert"}'
PATH = "/v1/push"
NONCE = "nonce-1"


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, str]:
    return generate_keypair()


def test_sha256hex_vector() -> None:
    assert sha256hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_mint_tenant_token_shape() -> None:
    token = mint_tenant_token()
    assert token.startswith("tnt_")
    assert re.fullmatch(r"tnt_[A-Za-z0-9_-]{43}", token), token


def test_mint_tenant_token_uniqueness() -> None:
    tokens = {mint_tenant_token() for _ in range(20)}
    assert len(tokens) == 20


def test_token_digest() -> None:
    assert token_digest("tnt_x") == hashlib.sha256(b"tnt_x").hexdigest()


def test_canonical_message_exact_bytes() -> None:
    message = canonical_message(TOKEN, "post", PATH, "1700000000", NONCE, BODY)
    expected = "\n".join(
        (
            sha256hex(TOKEN.encode()),
            "POST",
            PATH,
            "1700000000",
            NONCE,
            sha256hex(BODY),
        )
    ).encode()
    assert message == expected
    assert b"TOKEN" not in message  # token is digested, never raw


def test_sign_verify_roundtrip(keypair: tuple[Ed25519PrivateKey, str], clock: Clock) -> None:
    private, public_b64 = keypair
    ts = str(int(clock.t))
    signature = sign(private, TOKEN, "POST", PATH, ts, NONCE, BODY)
    assert "=" not in signature
    assert (
        verify(
            public_key_from_b64(public_b64),
            TOKEN,
            "POST",
            PATH,
            ts,
            NONCE,
            BODY,
            signature,
        )
        is None
    )


def test_verify_invalid_timestamp(keypair: tuple[Ed25519PrivateKey, str]) -> None:
    private, public_b64 = keypair
    signature = sign(private, TOKEN, "POST", PATH, "not-a-number", NONCE, BODY)
    assert (
        verify(
            public_key_from_b64(public_b64),
            TOKEN,
            "POST",
            PATH,
            "not-a-number",
            NONCE,
            BODY,
            signature,
        )
        == "invalid_timestamp"
    )


def test_verify_stale_timestamp_past(keypair: tuple[Ed25519PrivateKey, str], clock: Clock) -> None:
    private, public_b64 = keypair
    ts = str(int(clock.t - MAX_SKEW - 1))
    signature = sign(private, TOKEN, "POST", PATH, ts, NONCE, BODY)
    assert (
        verify(public_key_from_b64(public_b64), TOKEN, "POST", PATH, ts, NONCE, BODY, signature)
        == "stale_timestamp"
    )


def test_verify_stale_timestamp_future(
    keypair: tuple[Ed25519PrivateKey, str], clock: Clock
) -> None:
    private, public_b64 = keypair
    ts = str(int(clock.t + MAX_SKEW + 1))
    signature = sign(private, TOKEN, "POST", PATH, ts, NONCE, BODY)
    assert (
        verify(public_key_from_b64(public_b64), TOKEN, "POST", PATH, ts, NONCE, BODY, signature)
        == "stale_timestamp"
    )


@pytest.mark.parametrize("offset", [-MAX_SKEW, MAX_SKEW])
def test_verify_skew_boundary_accepted(
    keypair: tuple[Ed25519PrivateKey, str], clock: Clock, offset: int
) -> None:
    private, public_b64 = keypair
    ts = str(int(clock.t + offset))
    signature = sign(private, TOKEN, "POST", PATH, ts, NONCE, BODY)
    assert (
        verify(public_key_from_b64(public_b64), TOKEN, "POST", PATH, ts, NONCE, BODY, signature)
        is None
    )


def test_verify_garbage_b64_signature(keypair: tuple[Ed25519PrivateKey, str], clock: Clock) -> None:
    _, public_b64 = keypair
    ts = str(int(clock.t))
    assert (
        verify(public_key_from_b64(public_b64), TOKEN, "POST", PATH, ts, NONCE, BODY, "A")
        == "invalid_signature"
    )


def test_verify_rejects_malleable_signature_encoding(
    keypair: tuple[Ed25519PrivateKey, str], clock: Clock
) -> None:
    """Decoding is alphabet-strict: characters outside the base64 alphabet
    used to be silently discarded, giving one signature many encodings."""
    private, public_b64 = keypair
    ts = str(int(clock.t))
    signature = sign(private, TOKEN, "POST", PATH, ts, NONCE, BODY)
    malleable = f"{signature[:8]} {signature[8:]}"  # a discarded space
    assert (
        verify(public_key_from_b64(public_b64), TOKEN, "POST", PATH, ts, NONCE, BODY, malleable)
        == "invalid_signature"
    )


def test_verify_wrong_key(keypair: tuple[Ed25519PrivateKey, str], clock: Clock) -> None:
    private, _ = keypair
    _, other_b64 = generate_keypair()
    ts = str(int(clock.t))
    signature = sign(private, TOKEN, "POST", PATH, ts, NONCE, BODY)
    assert (
        verify(public_key_from_b64(other_b64), TOKEN, "POST", PATH, ts, NONCE, BODY, signature)
        == "invalid_signature"
    )


@pytest.mark.parametrize(
    ("field", "overrides"),
    [
        ("token", {"token": "tnt_substituted"}),
        ("method", {"method": "PUT"}),
        ("path", {"path": "/v1/other"}),
        ("nonce", {"nonce": "nonce-2"}),
        ("body", {"body": b"{}"}),
    ],
)
def test_verify_tampered_inputs(
    keypair: tuple[Ed25519PrivateKey, str],
    clock: Clock,
    field: str,
    overrides: dict[str, Any],
) -> None:
    del field
    private, public_b64 = keypair
    ts = str(int(clock.t))
    signature = sign(private, TOKEN, "POST", PATH, ts, NONCE, BODY)
    kwargs: dict[str, Any] = {
        "token": TOKEN,
        "method": "POST",
        "path": PATH,
        "timestamp": ts,
        "nonce": NONCE,
        "body": BODY,
    }
    kwargs.update(overrides)
    assert (
        verify(public_key_from_b64(public_b64), signature_b64=signature, **kwargs)
        == "invalid_signature"
    )


def test_verify_uses_wall_clock_when_now_omitted(
    keypair: tuple[Ed25519PrivateKey, str], clock: Clock
) -> None:
    private, public_b64 = keypair
    ts = str(int(clock.t))
    signature = sign(private, TOKEN, "POST", PATH, ts, NONCE, BODY)
    clock.advance(2 * MAX_SKEW + 60)
    assert (
        verify(public_key_from_b64(public_b64), TOKEN, "POST", PATH, ts, NONCE, BODY, signature)
        == "stale_timestamp"
    )


def test_generate_keypair_distinct_and_raw_length() -> None:
    private1, public1 = generate_keypair()
    _private2, public2 = generate_keypair()
    assert isinstance(private1, Ed25519PrivateKey)
    assert public1 != public2
    raw = base64.urlsafe_b64decode(public1 + "=" * (-len(public1) % 4))
    assert len(raw) == 32


def test_public_key_from_b64_roundtrip(keypair: tuple[Ed25519PrivateKey, str]) -> None:
    private, public_b64 = keypair
    public = public_key_from_b64(public_b64)
    # Verifies exactly the message the private key signed.
    message = b"roundtrip"
    signature = base64.urlsafe_b64encode(private.sign(message)).decode().rstrip("=")
    public.verify(base64.urlsafe_b64decode(signature + "=="), message)


@pytest.mark.parametrize("length", [31, 33, 0])
def test_public_key_from_b64_bad_length(length: int) -> None:
    value = base64.urlsafe_b64encode(b"\x01" * length).decode().rstrip("=")
    with pytest.raises(ValueError, match="32 bytes"):
        public_key_from_b64(value)
