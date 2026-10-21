"""Grants: issue/parse claim shape, parse failures, push-verification matrix."""

from __future__ import annotations

import base64
import hashlib
import uuid
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apns_relay.config import (
    AppKeyConfig,
    CapsConfig,
    GrantTtlConfig,
    QuotaConfig,
    RegistrationConfig,
)
from apns_relay.grants import (
    GRANT_VERSION,
    GrantError,
    canonical_claims,
    grant_topic,
    issue_grant,
    parse_grant,
    sha256_token,
    verify_grant_for_push,
)

TOKEN_DIGEST = "d" * 64
TENANT_ID = "hooks.example.com"
TENANT_PUBKEY = "p" * 43
APP_ID = "test-app"
BUNDLE_ID = "com.example.testapp"


@pytest.fixture
def issuer() -> tuple[Ed25519PrivateKey, Any]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


@pytest.fixture
def app() -> AppKeyConfig:
    return AppKeyConfig(
        id=APP_ID,
        display_name="Test App",
        bundle_id=BUNDLE_ID,
        team_id="TESTTEAM01",
        key_file=Path("keys/AuthKey_TESTKEYID1.p8"),
        key_id="TESTKEYID1",
        environments=("sandbox", "production"),
        kinds=("alert", "background", "liveActivity"),
        live_activity=True,
        attest_environment="production",
        registration=RegistrationConfig(),
        caps=CapsConfig(),
        quota=QuotaConfig(burst_per_min=5, daily=10, token_burst_per_min=3),
        grant_ttl=GrantTtlConfig(min=900, max=86400, default=3600),
    )


def mint(
    issuer_key: Ed25519PrivateKey,
    *,
    now: float = 1_800_000_000,
    ttl: int = 3600,
    kinds: list[str] | None = None,
    app_id: str = APP_ID,
    tenant_id: str = TENANT_ID,
    tenant_pubkey: str = TENANT_PUBKEY,
    token_digest: str = TOKEN_DIGEST,
    environment: str = "sandbox",
) -> str:
    return issue_grant(
        issuer_key,
        "relay-test-issuer",
        token_digest=token_digest,
        tenant_id=tenant_id,
        tenant_pubkey=tenant_pubkey,
        app_id=app_id,
        kinds=kinds if kinds is not None else ["alert"],
        environment=environment,
        ttl=ttl,
        now=now,
    )


def reissue(issuer_key: Ed25519PrivateKey, claims: dict[str, Any]) -> str:
    """Sign arbitrary claims with the issuer key (for malformed-claim cases)."""
    body = base64.urlsafe_b64encode(canonical_claims(claims)).decode().rstrip("=")
    sig = issuer_key.sign(canonical_claims(claims))
    signature = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{GRANT_VERSION}.{body}.{signature}"


# -- issue/parse claim shape ----------------------------------------------------


def test_issue_grant_claim_shape(issuer: tuple[Ed25519PrivateKey, Any]) -> None:
    private, public = issuer
    now = 1_800_000_000
    grant = mint(private, now=now, ttl=7200, kinds=["alert", "background"])
    assert grant.startswith(f"{GRANT_VERSION}.")

    claims = parse_grant(grant, public)
    assert claims["iss"] == "relay-test-issuer"
    assert claims["tok"] == f"sha256:{TOKEN_DIGEST}"
    assert claims["ten"] == TENANT_ID
    assert claims["tpk"] == TENANT_PUBKEY
    assert claims["app"] == APP_ID
    assert claims["kinds"] == ["alert", "background"]
    assert claims["env"] == "sandbox"
    assert claims["iat"] == now
    assert claims["exp"] == now + 7200
    assert claims["ttl"] == 7200


def test_issue_grant_jti_is_uuid_and_unique(issuer: tuple[Ed25519PrivateKey, Any]) -> None:
    private, public = issuer
    grant1 = mint(private)
    grant2 = mint(private)
    jti1, jti2 = parse_grant(grant1, public)["jti"], parse_grant(grant2, public)["jti"]
    assert str(uuid.UUID(jti1)) == jti1
    assert jti1 != jti2
    assert grant1 != grant2


def test_issue_grant_kinds_sorted(issuer: tuple[Ed25519PrivateKey, Any]) -> None:
    private, public = issuer
    grant = mint(private, kinds=["liveActivity", "alert", "background"])
    assert parse_grant(grant, public)["kinds"] == ["alert", "background", "liveActivity"]


def test_issue_grant_uses_wall_clock(issuer: tuple[Ed25519PrivateKey, Any], clock) -> None:
    private, public = issuer
    grant = issue_grant(
        private,
        "relay-test-issuer",
        token_digest=TOKEN_DIGEST,
        tenant_id=TENANT_ID,
        tenant_pubkey=TENANT_PUBKEY,
        app_id=APP_ID,
        kinds=["alert"],
        environment="sandbox",
        ttl=60,
    )
    claims = parse_grant(grant, public)
    assert claims["iat"] == int(clock.t)


# -- parse failures ---------------------------------------------------------------


def test_parse_wrong_version(issuer: tuple[Ed25519PrivateKey, Any]) -> None:
    private, public = issuer
    grant = mint(private)
    v2 = "v2" + grant[2:]
    with pytest.raises(GrantError) as exc:
        parse_grant(v2, public)
    assert exc.value.code == "malformed_grant"


@pytest.mark.parametrize("broken", ["v1.only-two", "v1.a.b.c.d", "not-a-grant", "v1..."])
def test_parse_wrong_part_count(issuer: tuple[Ed25519PrivateKey, Any], broken: str) -> None:
    _, public = issuer
    with pytest.raises(GrantError) as exc:
        parse_grant(broken, public)
    assert exc.value.code == "malformed_grant"


def test_parse_bad_b64_part(issuer: tuple[Ed25519PrivateKey, Any]) -> None:
    _, public = issuer
    # "A" has an invalid base64 length (raises binascii.Error on decode);
    # must surface as malformed_grant, never an unhandled exception.
    with pytest.raises(GrantError) as exc:
        parse_grant(f"{GRANT_VERSION}.A.A", public)
    assert exc.value.code == "malformed_grant"


def test_parse_rejects_malleable_encoding(issuer: tuple[Ed25519PrivateKey, Any]) -> None:
    """Decoding is alphabet-strict: a junk character inside a segment used
    to be silently discarded, so one grant had many valid encodings."""
    private, public = issuer
    version, claims, sig = mint(private).split(".")
    malleable = f"{version}.{claims[:8]} {claims[8:]}.{sig}"
    with pytest.raises(GrantError) as exc:
        parse_grant(malleable, public)
    assert exc.value.code == "malformed_grant"


def test_parse_bad_signature(issuer: tuple[Ed25519PrivateKey, Any]) -> None:
    _, public = issuer
    other_private = Ed25519PrivateKey.generate()
    grant = mint(other_private)
    with pytest.raises(GrantError) as exc:
        parse_grant(grant, public)
    assert exc.value.code == "bad_signature"


def test_parse_non_json_claims(issuer: tuple[Ed25519PrivateKey, Any]) -> None:
    private, public = issuer
    body = base64.urlsafe_b64encode(b"not json at all").decode().rstrip("=")
    sig = base64.urlsafe_b64encode(private.sign(b"not json at all")).decode().rstrip("=")
    with pytest.raises(GrantError) as exc:
        parse_grant(f"{GRANT_VERSION}.{body}.{sig}", public)
    assert exc.value.code == "malformed_grant"


def test_parse_non_dict_claims(issuer: tuple[Ed25519PrivateKey, Any]) -> None:
    private, public = issuer
    raw = b"[1, 2, 3]"
    body = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(private.sign(raw)).decode().rstrip("=")
    with pytest.raises(GrantError) as exc:
        parse_grant(f"{GRANT_VERSION}.{body}.{sig}", public)
    assert exc.value.code == "malformed_grant"


# -- verify_grant_for_push ---------------------------------------------------------


def verify(app: AppKeyConfig, grant: str, public: Any, **overrides: Any) -> dict:
    kwargs: dict[str, Any] = {
        "app": app,
        "destination_token_digest": TOKEN_DIGEST,
        "tenant_id": TENANT_ID,
        "tenant_pubkey": TENANT_PUBKEY,
        "kind": "alert",
        "now": 1_800_000_000 + 1,
    }
    kwargs.update(overrides)
    return verify_grant_for_push(grant, public, **kwargs)


def test_verify_happy_path(issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig) -> None:
    private, public = issuer
    claims = verify(app, mint(private), public)
    assert claims["app"] == APP_ID


def test_verify_expired(issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig) -> None:
    private, public = issuer
    grant = mint(private, now=1_800_000_000, ttl=60)
    with pytest.raises(GrantError) as exc:
        verify(app, grant, public, now=1_800_000_060)
    assert exc.value.code == "grant_expired"


def test_verify_exactly_at_exp_is_expired(
    issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig
) -> None:
    private, public = issuer
    grant = mint(private, now=1_800_000_000, ttl=60)
    # exp <= now is expired; one second earlier is still valid
    with pytest.raises(GrantError) as exc:
        verify(app, grant, public, now=1_800_000_060)
    assert exc.value.code == "grant_expired"
    assert verify(app, grant, public, now=1_800_000_059)


def test_verify_missing_exp_claim(issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig) -> None:
    private, public = issuer
    grant = reissue(private, {"app": APP_ID, "kinds": ["alert"]})
    with pytest.raises(GrantError) as exc:
        verify(app, grant, public)
    assert exc.value.code == "grant_expired"


def test_verify_app_mismatch(issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig) -> None:
    private, public = issuer
    with pytest.raises(GrantError) as exc:
        verify(app, mint(private, app_id="other-app"), public)
    assert exc.value.code == "app_mismatch"


def test_verify_missing_app_claim(issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig) -> None:
    private, public = issuer
    claims = {
        "exp": 1_800_003_600,
        "tok": f"sha256:{TOKEN_DIGEST}",
        "ten": TENANT_ID,
        "tpk": TENANT_PUBKEY,
        "kinds": ["alert"],
    }
    with pytest.raises(GrantError) as exc:
        verify(app, reissue(private, claims), public)
    assert exc.value.code == "app_mismatch"


@pytest.mark.parametrize("overrides", [{"tenant_id": "other.example.com"}, {"tenant_pubkey": "x"}])
def test_verify_tenant_mismatch(
    issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig, overrides: dict[str, Any]
) -> None:
    private, public = issuer
    grant = mint(private, **overrides)
    with pytest.raises(GrantError) as exc:
        verify(app, grant, public)
    assert exc.value.code == "tenant_mismatch"


def test_verify_destination_mismatch(
    issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig
) -> None:
    private, public = issuer
    with pytest.raises(GrantError) as exc:
        verify(app, mint(private), public, destination_token_digest="e" * 64)
    assert exc.value.code == "destination_mismatch"


def test_verify_kind_not_allowed(issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig) -> None:
    private, public = issuer
    grant = mint(private, kinds=["alert"])
    with pytest.raises(GrantError) as exc:
        verify(app, grant, public, kind="background")
    assert exc.value.code == "kind_not_allowed"


def test_verify_missing_kinds_claim(
    issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig
) -> None:
    private, public = issuer
    claims = {
        "exp": 1_800_003_600,
        "tok": f"sha256:{TOKEN_DIGEST}",
        "ten": TENANT_ID,
        "tpk": TENANT_PUBKEY,
        "app": APP_ID,
    }
    with pytest.raises(GrantError) as exc:
        verify(app, reissue(private, claims), public)
    assert exc.value.code == "kind_not_allowed"


def test_verify_uses_wall_clock(
    issuer: tuple[Ed25519PrivateKey, Any], app: AppKeyConfig, clock
) -> None:
    private, public = issuer
    grant = mint(private, now=clock.t, ttl=60)
    assert verify_grant_for_push(
        grant,
        public,
        app=app,
        destination_token_digest=TOKEN_DIGEST,
        tenant_id=TENANT_ID,
        tenant_pubkey=TENANT_PUBKEY,
        kind="alert",
    )
    clock.advance(61)
    with pytest.raises(GrantError) as exc:
        verify_grant_for_push(
            grant,
            public,
            app=app,
            destination_token_digest=TOKEN_DIGEST,
            tenant_id=TENANT_ID,
            tenant_pubkey=TENANT_PUBKEY,
            kind="alert",
        )
    assert exc.value.code == "grant_expired"


# -- helpers ------------------------------------------------------------------------


def test_grant_topic(app: AppKeyConfig) -> None:
    assert grant_topic(app, "liveActivity") == f"{BUNDLE_ID}.push-type.liveactivity"
    assert grant_topic(app, "alert") == BUNDLE_ID
    assert grant_topic(app, "background") == BUNDLE_ID


def test_sha256_token() -> None:
    assert sha256_token("tnt_x") == hashlib.sha256(b"tnt_x").hexdigest()


def test_canonical_claims_deterministic() -> None:
    claims = {"b": 1, "a": "x"}
    assert canonical_claims(claims) == b'{"a":"x","b":1}'
    assert canonical_claims(dict(reversed(list(claims.items())))) == canonical_claims(claims)
    assert isinstance(canonical_claims(claims), bytes)


def test_grant_error_is_value_error() -> None:
    assert issubclass(GrantError, ValueError)
    assert GrantError("some_code").code == "some_code"
