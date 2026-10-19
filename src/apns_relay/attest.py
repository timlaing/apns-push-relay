"""Apple App Attest verification (enrollment-spec §2.2).

Verifies the attestation x5c chain to Apple's App Attestation Root, extracts
the credential public key, and verifies an assertion over
``SHA256(nonce ‖ serverChallenge)``.

The security properties fixed here (chain, app ID binding, environment,
single-use serverChallenge, nonce binding) are what the spec mandates. Exact
CBOR field handling follows Apple's current App Attest verification document
and must be validated against a physical device before production use (M4).

The Apple App Attestation Root certificate is loaded from a PEM file supplied
by the operator (``attest_root_cert``), never hardcoded.
"""

from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey


class AttestError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AttestedCredential:
    public_key: EllipticCurvePublicKey
    aaguid: bytes
    credential_id: bytes


def load_attest_root(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _verify_chain(
    x5c: list[bytes], root: x509.Certificate, now: datetime
) -> list[x509.Certificate]:
    if not x5c:
        raise AttestError("empty_chain")
    try:
        certs = [x509.load_der_x509_certificate(der) for der in x5c]
    except (TypeError, ValueError):
        # x5c comes straight from the (unauthenticated) client: a non-bytes or
        # unparseable "certificate" must fail as a 400, not escape as TypeError.
        raise AttestError("malformed_attestation") from None
    leaf = certs[0]
    if leaf.not_valid_after_utc < now or leaf.not_valid_before_utc > now:
        raise AttestError("cert_expired")
    # Each cert must verify against its issuer; the last must chain to the root.
    chain = [*certs, root]
    for subject, issuer in itertools.pairwise(chain):
        pub = issuer.public_key()
        if not isinstance(pub, EllipticCurvePublicKey):
            raise AttestError("bad_chain_key")
        try:
            pub.verify(
                subject.signature,
                subject.tbs_certificate_bytes,
                ec.ECDSA(subject.signature_hash_algorithm),
            )
        # TypeError: signature algorithm has no hash (e.g. Ed25519 → None);
        # ValueError: unrecognized algorithm OID — both mean "cannot verify".
        except (InvalidSignature, TypeError, ValueError):
            raise AttestError("chain_verify_failed") from None
    return certs


def _extract_credential(auth_data: bytes) -> AttestedCredential:
    """Parse App Attest authenticator data.

    Layout: rpIdHash(32) ‖ flags(1) ‖ counter(4) ‖ aaguid(16) ‖
    credIdLen(2, BE) ‖ credId ‖ COSE_Key(CBOR).
    """
    if len(auth_data) < 55:
        raise AttestError("auth_data_short")
    offset = 37  # rpIdHash(32) + flags(1) + counter(4)
    aaguid = auth_data[offset : offset + 16]
    offset += 16
    cred_len = int.from_bytes(auth_data[offset : offset + 2], "big")
    offset += 2
    if len(auth_data) < offset + cred_len:
        raise AttestError("cred_id_truncated")
    cred_id = auth_data[offset : offset + cred_len]
    offset += cred_len
    try:
        cose = cbor2.loads(auth_data[offset:])
    except (ValueError, cbor2.CBORDecodeError):
        raise AttestError("bad_cose_key") from None
    if not isinstance(cose, dict):
        raise AttestError("bad_cose_key")
    # COSE EC2 key: 1=kty(2), 3=alg, -1=crv(1=P-256), -2=x, -3=y
    if cose.get(1) != 2 or cose.get(-1) != 1:
        raise AttestError("unsupported_cose_key")
    x, y = cose.get(-2), cose.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
        raise AttestError("bad_cose_point")
    try:
        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    except ValueError:
        # x/y are client-supplied: 32 bytes each need not be a point on P-256.
        raise AttestError("bad_cose_point") from None
    return AttestedCredential(public_key=pub, aaguid=aaguid, credential_id=cred_id)


def verify_attestation(
    attestation_b64: bytes,
    *,
    root: x509.Certificate,
    expected_rp_id: str,
    expected_aaguid: bytes | None,
    now: datetime | None = None,
) -> AttestedCredential:
    """Verify an attestation object and return the credential public key.

    ``expected_rp_id`` is the App's bundle ID. ``expected_aaguid`` pins the
    Apple AAGUID when known (None skips the pin — used until the constant is
    confirmed against a physical device in M4).
    """
    current = now or datetime.now(UTC)
    try:
        obj = cbor2.loads(attestation_b64)
    except (ValueError, cbor2.CBORDecodeError):
        raise AttestError("malformed_attestation") from None
    if not isinstance(obj, dict):
        raise AttestError("malformed_attestation")
    fmt, att_stmt, auth_data = obj.get("fmt"), obj.get("attStmt"), obj.get("authData")
    if fmt != "apple" or not isinstance(att_stmt, dict) or not isinstance(auth_data, bytes):
        raise AttestError("malformed_attestation")
    # Spec §2.2(3): the attested app ID (rpIdHash) must equal the configured
    # bundle ID — this is what stops a genuine build of a *different* app.
    if hashlib.sha256(expected_rp_id.encode()).digest() != auth_data[:32]:
        raise AttestError("app_id_mismatch")
    x5c = att_stmt.get("x5c")
    if not isinstance(x5c, list):
        raise AttestError("missing_x5c")
    _verify_chain(x5c, root, current)
    cred = _extract_credential(auth_data)
    if expected_aaguid is not None and cred.aaguid != expected_aaguid:
        raise AttestError("aaguid_mismatch")
    return cred


def verify_assertion(
    assertion_b64: bytes,
    *,
    credential: AttestedCredential,
    nonce: bytes,
    server_challenge: bytes,
) -> bytes:
    """Verify an assertion over SHA256(nonce ‖ serverChallenge). Returns counter.

    The nonce is the single-use value pushed to the device; binding it into the
    signed data proves the signer received the challenge push (token
    possession). Returns the authenticator counter for replay resistance.
    """
    try:
        obj = cbor2.loads(assertion_b64)
    except (ValueError, cbor2.CBORDecodeError):
        raise AttestError("malformed_assertion") from None
    if not isinstance(obj, dict):
        raise AttestError("malformed_assertion")
    sig, auth_data = obj.get("signature"), obj.get("authenticatorData")
    if not isinstance(sig, bytes) or not isinstance(auth_data, bytes):
        raise AttestError("malformed_assertion")
    if len(auth_data) < 37:
        raise AttestError("auth_data_short")
    client_data_hash = hashlib.sha256(nonce + server_challenge).digest()
    message = auth_data + client_data_hash
    try:
        credential.public_key.verify(sig, message, ec.ECDSA(_sha256()))
    except InvalidSignature:
        raise AttestError("assertion_signature_invalid") from None
    return int.from_bytes(auth_data[33:37], "big")


def _sha256():
    from cryptography.hazmat.primitives import hashes

    return hashes.SHA256()
