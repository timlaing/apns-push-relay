"""Unit tests for App Attest verification (enrollment-spec §2.2).

The conftest mints wire-format attestations/assertions against a test root CA;
these tests cover the happy paths plus every structural rejection the relay
performs, building authData/CBOR by hand where the parsing internals need it.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from apns_relay.attest import (
    AAGUID_BY_ATTEST_ENV,
    APPLE_ATTEST_NONCE_OID,
    AttestedCredential,
    AttestError,
    _extract_credential,
    load_attest_root,
    verify_assertion,
    verify_attestation,
)
from tests.conftest import (
    BUNDLE_ID,
    OTHER_BUNDLE_ID,
    _cose_key,
    _make_cert,
    _nonce_extension,
    _point,
    _rp_hash,
    make_root,
    mint_assertion,
    mint_attestation,
)

# Minimum-size assertion authenticatorData: rpIdHash(32) + flags(1) + counter(4).
_AD37 = _rp_hash(BUNDLE_ID) + b"\x01" + (1).to_bytes(4, "big")

# The challenge pair every minter defaults to; verify_* calls must pass the
# same values (the leaf certificate's nonce extension commits to them).
_NONCE = "test-nonce"
_SERVER_CHALLENGE = "test-challenge"
_PRODUCTION_AAGUID = AAGUID_BY_ATTEST_ENV["production"]


@pytest.fixture
def root():
    return make_root("Test Attest Root")


@pytest.fixture
def other_root():
    return make_root("Unrelated Root")


def _attestation(root, **kwargs) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    """Mint an attestation and return the CBOR bytes verify_attestation takes."""
    kwargs.setdefault("nonce", _NONCE)
    kwargs.setdefault("server_challenge", _SERVER_CHALLENGE)
    token, cred_key = mint_attestation(root, **kwargs)
    return base64.b64decode(token), cred_key


def _reserialized(root, **fields) -> bytes:
    """Mint a valid attestation, overwrite top-level CBOR fields, re-encode."""
    token, _ = mint_attestation(root, server_challenge=_SERVER_CHALLENGE)
    obj = cbor2.loads(base64.b64decode(token))
    obj.update(fields)
    return cbor2.dumps(obj)


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _credential(root) -> tuple[AttestedCredential, ec.EllipticCurvePrivateKey]:
    attestation, cred_key = _attestation(root)
    credential = verify_attestation(
        attestation,
        root=root.cert,
        expected_rp_id=BUNDLE_ID,
        expected_aaguid=None,
        nonce=_NONCE.encode(),
        server_challenge=_SERVER_CHALLENGE.encode(),
    )
    return credential, cred_key


def _auth_data(
    cose: bytes,
    *,
    cred_id: bytes = b"c" * 32,
    declared_len: int | None = None,
    rp_id: str = BUNDLE_ID,
) -> bytes:
    length = len(cred_id) if declared_len is None else declared_len
    return (
        _rp_hash(rp_id)
        + b"\x41"
        + (1).to_bytes(4, "big")
        + bytes(range(16))
        + length.to_bytes(2, "big")
        + cred_id
        + cose
    )


# -- verify_attestation: happy paths -------------------------------------------


def test_verify_attestation_happy(root) -> None:
    attestation, cred_key = _attestation(root)
    credential = verify_attestation(
        attestation,
        root=root.cert,
        expected_rp_id=BUNDLE_ID,
        expected_aaguid=_PRODUCTION_AAGUID,
        nonce=_NONCE.encode(),
        server_challenge=_SERVER_CHALLENGE.encode(),
    )
    assert isinstance(credential, AttestedCredential)
    assert isinstance(credential.public_key, ec.EllipticCurvePublicKey)
    assert isinstance(credential.public_key.curve, ec.SECP256R1)
    assert credential.aaguid == _PRODUCTION_AAGUID
    # credentialId defaults to SHA-256 of the credential key's X9.62 point,
    # and the leaf certificate carries that same key (spec §2.2 step 3).
    assert credential.credential_id == hashlib.sha256(_point(cred_key.public_key())).digest()
    assert credential.public_key.public_numbers() == cred_key.public_key().public_numbers()


def test_verify_attestation_aaguid_unpinned(root) -> None:
    attestation, _ = _attestation(root)
    credential = verify_attestation(
        attestation,
        root=root.cert,
        expected_rp_id=BUNDLE_ID,
        expected_aaguid=None,
        nonce=_NONCE.encode(),
        server_challenge=_SERVER_CHALLENGE.encode(),
    )
    assert credential.aaguid == _PRODUCTION_AAGUID


def test_verify_attestation_intermediate_chain(root) -> None:
    attestation, cred_key = _attestation(root, intermediate=True)
    credential = verify_attestation(
        attestation,
        root=root.cert,
        expected_rp_id=BUNDLE_ID,
        expected_aaguid=None,
        nonce=_NONCE.encode(),
        server_challenge=_SERVER_CHALLENGE.encode(),
    )
    assert credential.credential_id == hashlib.sha256(_point(cred_key.public_key())).digest()


# -- verify_attestation: malformed objects -------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param({"fmt": "none"}, id="fmt"),
        pytest.param({"attStmt": []}, id="attstmt-not-dict"),
        pytest.param({"authData": "not-bytes"}, id="authdata-not-bytes"),
    ],
)
def test_verify_attestation_malformed_fields(root, fields) -> None:
    attestation = _reserialized(root, **fields)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation,
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "malformed_attestation"


def test_verify_attestation_not_a_dict(root) -> None:
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            cbor2.dumps([1, 2, 3]),
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "malformed_attestation"


def test_verify_attestation_garbage_cbor(root) -> None:
    # cbor2 decode failures (CBORDecodeEOF/CBORDecodeError are not ValueError
    # subclasses) must still surface as AttestError, not escape to a 500.
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            b"notcbor",
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "malformed_attestation"


@pytest.mark.parametrize(
    "att_stmt",
    [
        pytest.param({}, id="x5c-absent"),
        pytest.param({"x5c": "nope"}, id="x5c-not-a-list"),
    ],
)
def test_verify_attestation_missing_x5c(root, att_stmt) -> None:
    attestation = _reserialized(root, attStmt=att_stmt)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation,
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "missing_x5c"


def test_verify_attestation_empty_chain(root) -> None:
    attestation = _reserialized(root, attStmt={"x5c": []})
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation,
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "empty_chain"


@pytest.mark.parametrize(
    "x5c_entry",
    [pytest.param(b"not-a-cert", id="garbage-der"), pytest.param(12345, id="not-bytes")],
)
def test_verify_attestation_unparseable_x5c(root, x5c_entry) -> None:
    attestation = _reserialized(root, attStmt={"x5c": [x5c_entry]})
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation,
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "malformed_attestation"


def test_verify_attestation_app_id_mismatch(root) -> None:
    attestation, _ = _attestation(root, rp_id=OTHER_BUNDLE_ID)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation,
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "app_id_mismatch"


def test_verify_attestation_expired_leaf(root) -> None:
    # Hand-built because conftest.mint_attestation(expired_leaf=True) currently
    # raises ValueError (see report): the leaf is rebuilt with past validity
    # dates but the same authData, so the nonce extension still binds.
    attestation, cred_key = _attestation(root)
    obj = cbor2.loads(attestation)
    now = datetime.now(UTC)
    expired = (
        x509.CertificateBuilder()
        .subject_name(_name("expired"))
        .issuer_name(root.cert.subject)
        .public_key(cred_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now - timedelta(days=1))
        .add_extension(
            x509.UnrecognizedExtension(
                APPLE_ATTEST_NONCE_OID,
                _nonce_extension(obj["authData"], _NONCE, _SERVER_CHALLENGE),
            ),
            critical=False,
        )
        .sign(root.key, hashes.SHA256())
    )
    obj["attStmt"]["x5c"] = [expired.public_bytes(serialization.Encoding.DER)]
    with pytest.raises(AttestError) as exc:
        _verify_bound(cbor2.dumps(obj), root)
    assert exc.value.code == "cert_expired"


def test_verify_attestation_chain_verify_failed(root, other_root) -> None:
    # Genuine structure signed under a *different* root: the signature check fails.
    attestation, _ = _attestation(other_root)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation,
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "chain_verify_failed"


def test_verify_attestation_bad_chain_key(root) -> None:
    # x5c = [valid leaf, RSA certificate]: the issuer's key is not EC.
    attestation = _reserialized(root)
    obj = cbor2.loads(attestation)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    rsa_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("rsa-issuer"))
        .issuer_name(_name("rsa-issuer"))
        .public_key(rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(rsa_key, hashes.SHA256())
    )
    obj["attStmt"]["x5c"].append(rsa_cert.public_bytes(serialization.Encoding.DER))
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            cbor2.dumps(obj),
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "bad_chain_key"


def test_verify_attestation_signature_algorithm_without_hash(root) -> None:
    # A leaf signed with Ed25519 has no hash algorithm for ECDSA: that must
    # read as a failed chain verification, not escape as TypeError.
    attestation = _reserialized(root)
    obj = cbor2.loads(attestation)
    ed_key = ed25519.Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    now = datetime.now(UTC)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("ed25519-leaf"))
        .issuer_name(_name("ed25519-leaf"))
        .public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(ed_key, None)
    )
    obj["attStmt"]["x5c"] = [leaf.public_bytes(serialization.Encoding.DER)]
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            cbor2.dumps(obj),
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "chain_verify_failed"


def test_verify_attestation_aaguid_mismatch(root) -> None:
    attestation, _ = _attestation(root)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation,
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=b"\x00" * 16,
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "aaguid_mismatch"


@pytest.mark.parametrize(
    ("mint_aaguid", "expected_aaguid"),
    [
        pytest.param("development", "production", id="dev-attestation-prod-pin"),
        pytest.param("production", "development", id="prod-attestation-dev-pin"),
    ],
)
def test_verify_attestation_aaguid_environment_pin(root, mint_aaguid, expected_aaguid) -> None:
    # The AAGUID must match the App's attest_environment in both directions
    # (spec §2.2 step 3.6).
    attestation, _ = _attestation(root, aaguid=AAGUID_BY_ATTEST_ENV[mint_aaguid])
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation,
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=AAGUID_BY_ATTEST_ENV[expected_aaguid],
            nonce=_NONCE.encode(),
            server_challenge=_SERVER_CHALLENGE.encode(),
        )
    assert exc.value.code == "aaguid_mismatch"


# -- _verify_binding: authData ↔ leaf-certificate binding (spec §2.2 v1.1) ------


def _verify_bound(attestation: bytes, root, **kwargs) -> None:
    """verify_attestation with the default challenge pair; callers assert the error."""
    kwargs.setdefault("expected_rp_id", BUNDLE_ID)
    kwargs.setdefault("expected_aaguid", None)
    verify_attestation(
        attestation,
        root=root.cert,
        nonce=_NONCE.encode(),
        server_challenge=_SERVER_CHALLENGE.encode(),
        **kwargs,
    )


def test_verify_attestation_nonce_extension_missing(root) -> None:
    # Rebuild the leaf without Apple's nonce extension: authData is unsigned,
    # so a genuine chain carrying no extension proves nothing about it.
    attestation, cred_key = _attestation(root)
    obj = cbor2.loads(attestation)
    leaf = _make_cert(signer=root, public_key=cred_key.public_key(), cn="no-nonce-extension")
    obj["attStmt"]["x5c"] = [leaf.public_bytes(serialization.Encoding.DER)]
    with pytest.raises(AttestError) as exc:
        _verify_bound(cbor2.dumps(obj), root)
    assert exc.value.code == "nonce_extension_missing"


@pytest.mark.parametrize(
    ("verify_nonce", "verify_challenge"),
    [
        pytest.param("wrong-nonce", _SERVER_CHALLENGE, id="wrong-nonce"),
        pytest.param(_NONCE, "wrong-challenge", id="wrong-server-challenge"),
    ],
)
def test_verify_attestation_attestation_nonce_mismatch(
    root, verify_nonce, verify_challenge
) -> None:
    # The leaf extension commits to the exact pushed challenge pair; a
    # different pair at verify time cannot reproduce the digest.
    attestation, _ = _attestation(root)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation,
            root=root.cert,
            expected_rp_id=BUNDLE_ID,
            expected_aaguid=None,
            nonce=verify_nonce.encode(),
            server_challenge=verify_challenge.encode(),
        )
    assert exc.value.code == "attestation_nonce_mismatch"


@pytest.mark.parametrize(
    "nonce_value",
    [
        pytest.param(b"\x30\x22\x04\x20" + b"\x00" * 16, id="truncated-digest"),
        pytest.param(b"\x30\x23\x04\x20" + b"\x00" * 32, id="bad-der-header"),
    ],
)
def test_verify_attestation_malformed_nonce_extension(root, nonce_value) -> None:
    # The extension value must be one of the accepted DER framings wrapping
    # exactly32 digest bytes.
    attestation, cred_key = _attestation(root)
    obj = cbor2.loads(attestation)
    leaf = _make_cert(
        signer=root, public_key=cred_key.public_key(), cn="bad-nonce", nonce_value=nonce_value
    )
    obj["attStmt"]["x5c"] = [leaf.public_bytes(serialization.Encoding.DER)]
    with pytest.raises(AttestError) as exc:
        _verify_bound(cbor2.dumps(obj), root)
    assert exc.value.code == "attestation_nonce_mismatch"


def test_verify_attestation_plain_octet_string_nonce_accepted(root) -> None:
    # The plain SEQUENCE { OCTET STRING } framing carries the same digest and
    # is accepted alongside Apple's [1] EXPLICIT framing.
    attestation = _attestation(root, explicit_nonce_tag=False)[0]
    verify_attestation(
        attestation,
        root=root.cert,
        expected_rp_id=BUNDLE_ID,
        expected_aaguid=_PRODUCTION_AAGUID,
        nonce=_NONCE.encode(),
        server_challenge=_SERVER_CHALLENGE.encode(),
    )


def test_verify_attestation_fmt_apple_appattest_accepted(root) -> None:
    # Real attestation objects have used both fmt strings; neither is a
    # security property (the chain + nonce binding is), so both are accepted.
    attestation = _reserialized(root, fmt="apple-appattest")
    verify_attestation(
        attestation,
        root=root.cert,
        expected_rp_id=BUNDLE_ID,
        expected_aaguid=_PRODUCTION_AAGUID,
        nonce=_NONCE.encode(),
        server_challenge=_SERVER_CHALLENGE.encode(),
    )


def test_verify_attestation_forged_auth_data_rejected(root) -> None:
    # A genuine chain replayed alongside forged authData (attacker's counter,
    # AAGUID, ...): the leaf's nonce extension no longer matches, so the
    # unsigned authData cannot be swapped in (spec §7 amendment 1, threat A4).
    attestation, _ = _attestation(root)
    obj = cbor2.loads(attestation)
    forged = bytearray(obj["authData"])
    forged[36] ^= 0x01  # tamper with the counter (bytes 33-36) — unsigned data
    obj["authData"] = bytes(forged)
    with pytest.raises(AttestError) as exc:
        _verify_bound(cbor2.dumps(obj), root)
    assert exc.value.code == "attestation_nonce_mismatch"


def test_verify_attestation_credential_id_mismatch(root) -> None:
    # A credentialId that is not SHA-256(leaf public key) means the certified
    # key was never attested (spec §2.2 step 3.3).
    attestation, _ = _attestation(root, credential_id=b"custom-cred-id")
    with pytest.raises(AttestError) as exc:
        _verify_bound(attestation, root)
    assert exc.value.code == "credential_id_mismatch"


def _hand_built_auth_data(
    *, leaf_key: ec.EllipticCurvePrivateKey, cose_key: ec.EllipticCurvePublicKey, counter: int
) -> bytes:
    cred_id = hashlib.sha256(_point(leaf_key.public_key())).digest()
    return (
        _rp_hash(BUNDLE_ID)
        + b"\x41"
        + counter.to_bytes(4, "big")
        + _PRODUCTION_AAGUID
        + len(cred_id).to_bytes(2, "big")
        + cred_id
        + _cose_key(cose_key)
    )


def _hand_built_attestation(root, *, auth_data: bytes, leaf_key) -> bytes:
    leaf = _make_cert(
        signer=root,
        public_key=leaf_key.public_key(),
        cn="hand-built",
        nonce_value=_nonce_extension(auth_data, _NONCE, _SERVER_CHALLENGE),
    )
    return cbor2.dumps(
        {
            "fmt": "apple",
            "attStmt": {"x5c": [leaf.public_bytes(serialization.Encoding.DER)]},
            "authData": auth_data,
        }
    )


def test_verify_attestation_credential_key_mismatch(root) -> None:
    # credId hashes the leaf key while authData's COSE key is a *different*
    # key: the attested pair and the certified key are not one (spec §2.2 3.3).
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    auth_data = _hand_built_auth_data(leaf_key=leaf_key, cose_key=other_key.public_key(), counter=0)
    attestation = _hand_built_attestation(root, auth_data=auth_data, leaf_key=leaf_key)
    with pytest.raises(AttestError) as exc:
        _verify_bound(attestation, root)
    assert exc.value.code == "credential_key_mismatch"


def test_verify_attestation_counter_nonzero(root) -> None:
    # Attestation authData carries counter 0; counters advance only in
    # assertions (spec §2.2 step 3.5). mint_attestation hardcodes 0, so this
    # authData is built by hand.
    cred_key = ec.generate_private_key(ec.SECP256R1())
    auth_data = _hand_built_auth_data(leaf_key=cred_key, cose_key=cred_key.public_key(), counter=1)
    attestation = _hand_built_attestation(root, auth_data=auth_data, leaf_key=cred_key)
    with pytest.raises(AttestError) as exc:
        _verify_bound(attestation, root)
    assert exc.value.code == "counter_nonzero"


def test_verify_attestation_binding_bad_chain_key(root) -> None:
    # The leaf's own public key is not EC: it has no X9.62 point to derive
    # the credentialId from. The chain still verifies (the root signs it).
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cred_key = ec.generate_private_key(ec.SECP256R1())
    auth_data = _hand_built_auth_data(leaf_key=cred_key, cose_key=cred_key.public_key(), counter=0)
    attestation = _hand_built_attestation(root, auth_data=auth_data, leaf_key=rsa_key)
    with pytest.raises(AttestError) as exc:
        _verify_bound(attestation, root)
    assert exc.value.code == "bad_chain_key"


# -- _extract_credential: authData parsing internals ---------------------------


def test_extract_credential_happy() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cred = _extract_credential(_auth_data(_cose_key(key.public_key()), cred_id=b"device-cred-1"))
    assert cred.credential_id == b"device-cred-1"
    assert cred.aaguid == bytes(range(16))
    assert cred.public_key.public_numbers() == key.public_key().public_numbers()


def test_extract_credential_auth_data_too_short() -> None:
    with pytest.raises(AttestError) as exc:
        _extract_credential(b"\x00" * 54)  # one byte under the 55-byte minimum
    assert exc.value.code == "auth_data_short"


def test_extract_credential_cred_id_truncated() -> None:
    auth_data = _auth_data(b"", cred_id=b"x" * 10, declared_len=64)
    with pytest.raises(AttestError) as exc:
        _extract_credential(auth_data)
    assert exc.value.code == "cred_id_truncated"


def test_extract_credential_missing_cose_key() -> None:
    # Exactly the 55-byte minimum with an empty COSE region: the CBOR decode
    # failure (CBORDecodeEOF) must map to AttestError, not escape.
    auth_data = _auth_data(b"", cred_id=b"")
    assert len(auth_data) == 55
    with pytest.raises(AttestError) as exc:
        _extract_credential(auth_data)
    assert exc.value.code == "bad_cose_key"


def test_extract_credential_undecodable_cose_key() -> None:
    with pytest.raises(AttestError) as exc:
        _extract_credential(_auth_data(b"\xa1"))  # map header with no entries
    assert exc.value.code == "bad_cose_key"


def test_extract_credential_cose_key_not_a_dict() -> None:
    with pytest.raises(AttestError) as exc:
        _extract_credential(_auth_data(cbor2.dumps([1, 2])))
    assert exc.value.code == "bad_cose_key"


@pytest.mark.parametrize(
    ("kty", "crv"),
    [pytest.param(1, 1, id="bad-kty"), pytest.param(2, 2, id="bad-crv")],
)
def test_extract_credential_unsupported_cose_key(kty: int, crv: int) -> None:
    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    cose = cbor2.dumps(
        {
            1: kty,
            3: -7,
            -1: crv,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )
    with pytest.raises(AttestError) as exc:
        _extract_credential(_auth_data(cose))
    assert exc.value.code == "unsupported_cose_key"


@pytest.mark.parametrize(
    ("x", "y"),
    [
        pytest.param(b"\xff" * 32, b"\xff" * 32, id="off-curve"),
        pytest.param(b"\x00" * 31, b"\x00" * 32, id="wrong-length"),
    ],
)
def test_extract_credential_bad_cose_point(x: bytes, y: bytes) -> None:
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})
    with pytest.raises(AttestError) as exc:
        _extract_credential(_auth_data(cose))
    assert exc.value.code == "bad_cose_point"


# -- verify_assertion ----------------------------------------------------------


def test_verify_assertion_valid(root) -> None:
    credential, cred_key = _credential(root)
    assertion = mint_assertion(cred_key, nonce="nonce-1", server_challenge="challenge-1")
    counter = verify_assertion(
        base64.b64decode(assertion),
        credential=credential,
        nonce=b"nonce-1",
        server_challenge=b"challenge-1",
        expected_rp_id=BUNDLE_ID,
    )
    assert counter == 2


def test_verify_assertion_accepts_trailing_auth_data_bytes(root) -> None:
    # conftest's short_auth_data flag appends 8 bytes *after* the counter
    # (45 bytes total). The relay checks a 37-byte minimum and the signature
    # covers the whole authenticatorData, so this still verifies — counter 2.
    credential, cred_key = _credential(root)
    assertion = mint_assertion(cred_key, nonce="n", server_challenge="s", short_auth_data=True)
    counter = verify_assertion(
        base64.b64decode(assertion),
        credential=credential,
        nonce=b"n",
        server_challenge=b"s",
        expected_rp_id=BUNDLE_ID,
    )
    assert counter == 2


def test_verify_assertion_auth_data_too_short(root) -> None:
    credential, _ = _credential(root)
    payload = cbor2.dumps({"signature": b"\x00" * 64, "authenticatorData": b"\x00" * 36})
    with pytest.raises(AttestError) as exc:
        verify_assertion(
            payload,
            credential=credential,
            nonce=b"n",
            server_challenge=b"s",
            expected_rp_id=BUNDLE_ID,
        )
    assert exc.value.code == "auth_data_short"


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"notcbor", id="garbage-cbor"),
        pytest.param(cbor2.dumps([1, 2]), id="not-a-dict"),
        pytest.param(cbor2.dumps({"authenticatorData": _AD37}), id="missing-signature"),
        pytest.param(cbor2.dumps({"signature": b"\x00" * 64}), id="missing-authdata"),
        pytest.param(
            cbor2.dumps({"signature": "not-bytes", "authenticatorData": _AD37}),
            id="signature-not-bytes",
        ),
        pytest.param(
            cbor2.dumps({"signature": b"\x00" * 64, "authenticatorData": "not-bytes"}),
            id="authdata-not-bytes",
        ),
    ],
)
def test_verify_assertion_malformed(root, payload: bytes) -> None:
    credential, _ = _credential(root)
    with pytest.raises(AttestError) as exc:
        verify_assertion(
            payload,
            credential=credential,
            nonce=b"n",
            server_challenge=b"s",
            expected_rp_id=BUNDLE_ID,
        )
    assert exc.value.code == "malformed_assertion"


def test_verify_assertion_wrong_signer(root) -> None:
    credential, cred_key = _credential(root)
    assertion = mint_assertion(cred_key, nonce="n", server_challenge="s", corrupt=True)
    with pytest.raises(AttestError) as exc:
        verify_assertion(
            base64.b64decode(assertion),
            credential=credential,
            nonce=b"n",
            server_challenge=b"s",
            expected_rp_id=BUNDLE_ID,
        )
    assert exc.value.code == "assertion_signature_invalid"


def test_verify_assertion_wrong_nonce(root) -> None:
    credential, cred_key = _credential(root)
    assertion = mint_assertion(cred_key, nonce="right", server_challenge="s")
    with pytest.raises(AttestError) as exc:
        verify_assertion(
            base64.b64decode(assertion),
            credential=credential,
            nonce=b"wrong",
            server_challenge=b"s",
            expected_rp_id=BUNDLE_ID,
        )
    assert exc.value.code == "assertion_signature_invalid"


def test_verify_assertion_wrong_server_challenge(root) -> None:
    credential, cred_key = _credential(root)
    assertion = mint_assertion(cred_key, nonce="n", server_challenge="right")
    with pytest.raises(AttestError) as exc:
        verify_assertion(
            base64.b64decode(assertion),
            credential=credential,
            nonce=b"n",
            server_challenge=b"wrong",
            expected_rp_id=BUNDLE_ID,
        )
    assert exc.value.code == "assertion_signature_invalid"


def test_verify_assertion_app_id_mismatch(root) -> None:
    # The assertion's own rpIdHash is re-checked against the configured bundle
    # ID before the signature (spec §2.2 step 4).
    credential, cred_key = _credential(root)
    assertion = mint_assertion(cred_key, nonce="n", server_challenge="s", rp_id=OTHER_BUNDLE_ID)
    with pytest.raises(AttestError) as exc:
        verify_assertion(
            base64.b64decode(assertion),
            credential=credential,
            nonce=b"n",
            server_challenge=b"s",
            expected_rp_id=BUNDLE_ID,
        )
    assert exc.value.code == "app_id_mismatch"


# -- load_attest_root ----------------------------------------------------------


def test_load_attest_root_valid(tmp_path: Path, root) -> None:
    path = tmp_path / "attest-root.pem"
    path.write_bytes(root.pem)
    cert = load_attest_root(path)
    assert isinstance(cert, x509.Certificate)
    assert cert.subject == root.cert.subject


def test_load_attest_root_missing_file(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        load_attest_root(tmp_path / "absent.pem")


def test_load_attest_root_invalid_pem(tmp_path: Path) -> None:
    path = tmp_path / "broken.pem"
    path.write_bytes(b"this is not a certificate\n")
    with pytest.raises(ValueError):
        load_attest_root(path)
