"""Unit tests for App Attest verification (enrollment-spec §2.2).

The conftest mints wire-format attestations/assertions against a test root CA;
these tests cover the happy paths plus every structural rejection the relay
performs, building authData/CBOR by hand where the parsing internals need it.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from apns_relay.attest import (
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
    _rp_hash,
    make_root,
    mint_assertion,
    mint_attestation,
)

# Minimum-size assertion authenticatorData: rpIdHash(32) + flags(1) + counter(4).
_AD37 = _rp_hash(BUNDLE_ID) + b"\x01" + (1).to_bytes(4, "big")


@pytest.fixture
def root():
    return make_root("Test Attest Root")


@pytest.fixture
def other_root():
    return make_root("Unrelated Root")


def _attestation(root, **kwargs) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    """Mint an attestation and return the CBOR bytes verify_attestation takes."""
    token, cred_key = mint_attestation(root, **kwargs)
    return base64.b64decode(token), cred_key


def _reserialized(root, **fields) -> bytes:
    """Mint a valid attestation, overwrite top-level CBOR fields, re-encode."""
    token, _ = mint_attestation(root)
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
    credential_id = b"device-credential-001"
    attestation, _ = _attestation(root, credential_id=credential_id)
    credential = verify_attestation(
        attestation,
        root=root.cert,
        expected_rp_id=BUNDLE_ID,
        expected_aaguid=bytes(range(16)),
    )
    assert isinstance(credential, AttestedCredential)
    assert isinstance(credential.public_key, ec.EllipticCurvePublicKey)
    assert isinstance(credential.public_key.curve, ec.SECP256R1)
    assert credential.aaguid == bytes(range(16))
    assert credential.credential_id == credential_id


def test_verify_attestation_aaguid_unpinned(root) -> None:
    attestation, _ = _attestation(root)
    credential = verify_attestation(
        attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
    )
    assert credential.aaguid == bytes(range(16))


def test_verify_attestation_intermediate_chain(root) -> None:
    attestation, _ = _attestation(root, intermediate=True, credential_id=b"intermediate-cred")
    credential = verify_attestation(
        attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
    )
    assert credential.credential_id == b"intermediate-cred"


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
            attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
        )
    assert exc.value.code == "malformed_attestation"


def test_verify_attestation_not_a_dict(root) -> None:
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            cbor2.dumps([1, 2, 3]), root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
        )
    assert exc.value.code == "malformed_attestation"


def test_verify_attestation_garbage_cbor(root) -> None:
    # cbor2 decode failures (CBORDecodeEOF/CBORDecodeError are not ValueError
    # subclasses) must still surface as AttestError, not escape to a 500.
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            b"notcbor", root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
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
            attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
        )
    assert exc.value.code == "missing_x5c"


def test_verify_attestation_empty_chain(root) -> None:
    attestation = _reserialized(root, attStmt={"x5c": []})
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
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
            attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
        )
    assert exc.value.code == "malformed_attestation"


def test_verify_attestation_app_id_mismatch(root) -> None:
    attestation, _ = _attestation(root, rp_id=OTHER_BUNDLE_ID)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
        )
    assert exc.value.code == "app_id_mismatch"


def test_verify_attestation_expired_leaf(root) -> None:
    attestation, _ = _attestation(root, expired_leaf=True)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
        )
    assert exc.value.code == "cert_expired"


def test_verify_attestation_chain_verify_failed(root, other_root) -> None:
    # Genuine structure signed under a *different* root: the signature check fails.
    attestation, _ = _attestation(other_root)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
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
            cbor2.dumps(obj), root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
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
            cbor2.dumps(obj), root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=None
        )
    assert exc.value.code == "chain_verify_failed"


def test_verify_attestation_aaguid_mismatch(root) -> None:
    attestation, _ = _attestation(root)
    with pytest.raises(AttestError) as exc:
        verify_attestation(
            attestation, root=root.cert, expected_rp_id=BUNDLE_ID, expected_aaguid=b"\x00" * 16
        )
    assert exc.value.code == "aaguid_mismatch"


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
    )
    assert counter == 2


def test_verify_assertion_auth_data_too_short(root) -> None:
    credential, _ = _credential(root)
    payload = cbor2.dumps({"signature": b"\x00" * 64, "authenticatorData": b"\x00" * 36})
    with pytest.raises(AttestError) as exc:
        verify_assertion(payload, credential=credential, nonce=b"n", server_challenge=b"s")
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
        verify_assertion(payload, credential=credential, nonce=b"n", server_challenge=b"s")
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
        )
    assert exc.value.code == "assertion_signature_invalid"


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
