"""Shared fixtures: config/keys, fake APNs + callback, app client, flows.

Everything is ephemeral per test — keys, database and roots are generated
into ``tmp_path``. The App Attest credentials are *fabricated* against a
test root CA (same wire format as Apple's), which exercises every check the
relay performs; validation against a physical device remains M4.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time as _time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import cbor2
import httpx
import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "clients" / "python"))

import relay_client  # noqa: E402

from apns_relay.apns import APNsSender, KeyRegistry  # noqa: E402
from apns_relay.app import create_app  # noqa: E402
from apns_relay.config import RelayConfig, load_config  # noqa: E402
from apns_relay.signing import generate_keypair  # noqa: E402
from apns_relay.store import Store  # noqa: E402

# -- fixed test identities -----------------------------------------------------

APP_ID = "test-app"
OTHER_APP_ID = "second-app"
BUNDLE_ID = "com.example.testapp"
OTHER_BUNDLE_ID = "com.example.second"
TEAM_ID = "TESTTEAM01"
KEY_ID = "TESTKEYID1"
TENANT_ID = "hooks.example.com"
OTHER_TENANT_ID = "other.example.com"
DEST_TOKEN = "ab" * 32  # 64 hex chars
DEST_TOKEN_2 = "cd" * 32
MASTER_SECRET = b"m" * 32
ADMIN_TOKEN = "a" * 32
BASE_URL = "https://relay.test"

DEFAULT_QUOTA = {"burst_per_min": 5, "daily": 10, "token_burst_per_min": 3}


# -- config + keys ------------------------------------------------------------


def write_config(
    base: Path,
    *,
    callback_required: bool = False,
    roots: dict[str, Path] | None = None,
    quota: dict[str, int] | None = None,
    kinds: list[str] | None = None,
    environments: list[str] | None = None,
    ttl: dict[str, int] | None = None,
    include_second_app: bool = False,
    caps: dict[str, int] | None = None,
) -> Path:
    """Materialize an instance directory (keys + config.yaml) and return its path."""
    keys = base / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    provider = ec.generate_private_key(ec.SECP256R1())
    (keys / f"AuthKey_{KEY_ID}.p8").write_bytes(
        provider.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    (keys / "issuer.pem").write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    chosen_kinds = kinds or ["alert", "background", "liveActivity"]
    app: dict[str, Any] = {
        "id": APP_ID,
        "display_name": "Test App",
        "bundle_id": BUNDLE_ID,
        "team_id": TEAM_ID,
        "key_file": f"keys/AuthKey_{KEY_ID}.p8",
        "environments": environments or ["sandbox", "production"],
        "kinds": chosen_kinds,
        "live_activity": "liveActivity" in chosen_kinds,
        "attest_environment": "production",
        "registration": {"callback_required": callback_required},
        "quota": quota or dict(DEFAULT_QUOTA),
        "grant_ttl": ttl or {"min": 900, "max": 86400, "default": 3600},
    }
    if caps:
        app["caps"] = caps
    apps = [app]
    if include_second_app:
        apps.append(
            {
                "id": OTHER_APP_ID,
                "bundle_id": OTHER_BUNDLE_ID,
                "team_id": TEAM_ID,
                "key_file": f"keys/AuthKey_{KEY_ID}.p8",
                "environments": ["sandbox", "production"],
                "kinds": ["alert"],
                "live_activity": False,
                "attest_environment": "production",
                "quota": dict(DEFAULT_QUOTA),
            }
        )

    enrollment: dict[str, Any] = {"grant_issuer_key": "keys/issuer.pem", "challenge_ttl": 600}
    if roots:
        enrollment["attest_root_certs"] = {k: str(v) for k, v in roots.items()}
    config = {
        "server": {"api_domain": "api.test.example", "docs_domain": "docs.test.example"},
        "enrollment": enrollment,
        "storage": {"database": "relay.db"},
        "apps": apps,
    }
    path = base / "config.yaml"
    path.write_text(yaml.safe_dump(config))
    return path


def load_test_config(path: Path) -> RelayConfig:
    return load_config(path, admin_token=ADMIN_TOKEN)


# -- fake App Attest -----------------------------------------------------------


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


@dataclass
class RootCA:
    key: EllipticCurvePrivateKey
    cert: x509.Certificate

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)


def make_root(common: str = "Test App Attest Root") -> RootCA:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common))
        .issuer_name(_name(common))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return RootCA(key=key, cert=cert)


def _issue_leaf(root: RootCA, public_key: ec.EllipticCurvePublicKey, cn: str) -> x509.Certificate:
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(root.cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
    )
    return builder.sign(root.key, hashes.SHA256())


def _rp_hash(rp_id: str) -> bytes:
    return hashlib.sha256(rp_id.encode()).digest()


def _cose_key(public: ec.EllipticCurvePublicKey) -> bytes:
    numbers = public.public_numbers()
    return cbor2.dumps(
        {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )


def mint_attestation(
    root: RootCA,
    *,
    rp_id: str = BUNDLE_ID,
    credential_id: bytes | None = None,
    expired_leaf: bool = False,
    intermediate: bool = False,
) -> tuple[str, EllipticCurvePrivateKey]:
    """Fabricate a valid Apple-format attestation object (b64 CBOR).

    Returns ``(attestation_b64, credential_private_key)`` — the key that must
    sign the assertion.
    """
    cred_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = credential_id or hashlib.sha256(b"cred").digest()

    # The attested *credential* key lives in authData; the leaf cert carries
    # an independent key (Apple's leaf binds them; the relay never checks).
    cert_key = ec.generate_private_key(ec.SECP256R1())
    if expired_leaf:
        now = datetime.now(UTC)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(_name("expired"))
            .issuer_name(root.cert.subject)
            .public_key(cert_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now - timedelta(days=1))
            .sign(root.key, hashes.SHA256())
        )
        x5c = [leaf.public_bytes(serialization.Encoding.DER)]
    elif intermediate:
        inter_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        inter = (
            x509.CertificateBuilder()
            .subject_name(_name("Test Intermediate"))
            .issuer_name(root.cert.subject)
            .public_key(inter_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .sign(root.key, hashes.SHA256())
        )
        leaf = _issue_leaf(RootCA(key=inter_key, cert=inter), cert_key.public_key(), "leaf")
        x5c = [
            leaf.public_bytes(serialization.Encoding.DER),
            inter.public_bytes(serialization.Encoding.DER),
        ]
    else:
        leaf = _issue_leaf(root, cert_key.public_key(), "attest-leaf")
        x5c = [leaf.public_bytes(serialization.Encoding.DER)]

    rp_hash = _rp_hash(rp_id)
    aaguid = bytes(range(16))
    auth_data = (
        rp_hash
        + b"\x41"  # flags: UP | AT
        + (1).to_bytes(4, "big")  # counter
        + aaguid
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + _cose_key(cred_key.public_key())
    )
    att_obj = cbor2.dumps({"fmt": "apple", "attStmt": {"x5c": x5c}, "authData": auth_data})
    return b64(att_obj), cred_key


def mint_assertion(
    cred_key: EllipticCurvePrivateKey,
    *,
    nonce: str,
    server_challenge: str,
    rp_id: str = BUNDLE_ID,
    corrupt: bool = False,
    short_auth_data: bool = False,
) -> str:
    ad = (
        _rp_hash(rp_id)
        + b"\x01"
        + (2).to_bytes(4, "big")
        + (b"\x00" * 8 if short_auth_data else b"")
    )
    message = ad + hashlib.sha256(nonce.encode() + server_challenge.encode()).digest()
    other = ec.generate_private_key(ec.SECP256R1())
    signer = cred_key if not corrupt else other
    signature = signer.sign(message, ec.ECDSA(hashes.SHA256()))
    return b64(cbor2.dumps({"signature": signature, "authenticatorData": ad}))


# -- fakes ---------------------------------------------------------------------


class FakeAPNs:
    """Records every APNs request; replays queued (status, reason) outcomes."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.queue: list[Any] = []  # None → 200, (status, reason), or an Exception

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(
            {
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": json.loads(request.content),
            }
        )
        if not self.queue:
            return httpx.Response(200, headers={"apns-id": "APNS-ID-OK"})
        item = self.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        status, reason = item
        return httpx.Response(status, json={"reason": reason})

    @property
    def challenge_calls(self) -> list[dict[str, Any]]:
        return [c for c in self.calls if "relay-challenge" in c["body"]]

    def challenge_for(self, challenge_id: str) -> dict[str, Any]:
        for call in self.challenge_calls:
            if call["body"]["relay-challenge"]["id"] == challenge_id:
                return call
        raise AssertionError(f"no challenge push for {challenge_id}")


class FakeCallback:
    """Ownership-callback endpoint: echoes the nonce (or misbehaves on demand)."""

    def __init__(self) -> None:
        self.mode = "echo"  # echo | wrong | error | empty
        self.calls: list[dict[str, Any]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        self.calls.append(payload)
        if self.mode == "echo":
            return httpx.Response(200, json={"nonce": payload.get("nonce")})
        if self.mode == "wrong":
            return httpx.Response(200, json={"nonce": "not-the-nonce"})
        if self.mode == "empty":
            return httpx.Response(204)
        return httpx.Response(500, json={"error": "boom"})


# -- app fixture ---------------------------------------------------------------


@dataclass
class Env:
    client: TestClient
    config: RelayConfig
    state: Any  # AppState
    store: Store
    apns: FakeAPNs
    callback: FakeCallback
    base: Path
    roots: dict[str, RootCA]
    keys: dict[str, Any]  # "issuer" -> Path


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Callbacks resolve to a public address without touching real DNS."""
    monkeypatch.setattr("apns_relay.callback._resolve_public", lambda host: "93.184.216.34")


@pytest.fixture
def env(tmp_path: Path) -> Env:
    base = tmp_path / "instance"
    roots = {"production": make_root("Prod Root"), "development": make_root("Dev Root")}
    root_paths = {k: base / f"{k}-root.pem" for k in roots}
    base.mkdir(parents=True, exist_ok=True)
    for name, root in roots.items():
        root_paths[name].write_bytes(root.pem)
    config_path = write_config(base, roots=root_paths, include_second_app=True)
    config = load_test_config(config_path)
    store = Store(config.database)
    fake_apns = FakeAPNs()
    sender = APNsSender(
        KeyRegistry(config.enabled_apps),
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake_apns.handler)),
    )
    fake_cb = FakeCallback()
    callback_client = httpx.AsyncClient(transport=httpx.MockTransport(fake_cb.handler))
    app = create_app(
        config,
        master_secret=MASTER_SECRET,
        store=store,
        sender=sender,
        callback_client=callback_client,
    )
    with TestClient(app) as client:
        yield Env(
            client=client,
            config=config,
            state=app.state.relay,
            store=store,
            apns=fake_apns,
            callback=fake_cb,
            base=base,
            roots=roots,
            keys={"issuer": base / "keys" / "issuer.pem"},
        )


class Clock:
    """Controllable wall clock (patches time.time globally while active)."""

    def __init__(self, start: int = 1_800_000_000) -> None:
        self.t = float(start)

    def time(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    c = Clock()
    monkeypatch.setattr(_time, "time", c.time)
    return c


# -- flow helpers --------------------------------------------------------------


def register_tenant(
    client: TestClient,
    tenant_id: str = TENANT_ID,
    app: str = APP_ID,
    callback: str | None = None,
) -> str:
    payload: dict[str, Any] = {"id": tenant_id, "app": app}
    if callback is not None:
        payload["callback"] = callback
    response = client.post("/v1/register", json=payload)
    assert response.status_code == 201, response.text
    return response.json()["token"]


def make_signed(
    token: str,
    private_key: Any,
    path: str,
    payload: dict[str, Any],
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(payload).encode()
    headers = relay_client.sign_headers(
        private_key, token, "POST", path, body, timestamp=timestamp, nonce=nonce
    )
    headers["content-type"] = "application/json"
    return body, headers


def post_signed(
    client: TestClient,
    path: str,
    payload: dict[str, Any],
    token: str,
    private_key: Any,
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> httpx.Response:
    body, headers = make_signed(token, private_key, path, payload, timestamp=timestamp, nonce=nonce)
    return client.request("POST", path, content=body, headers=headers)


@dataclass
class Enrolled:
    grant: str
    consent: dict[str, Any]
    token: str
    private_key: Any
    pubkey: str
    tenant_id: str
    destination: str
    kinds: list[str]


def enroll(
    env: Env,
    *,
    tenant_id: str = TENANT_ID,
    token: str | None = None,
    kinds: list[str] | None = None,
    destination: str = DEST_TOKEN,
    ttl: int | None = None,
    app: str = APP_ID,
    root: RootCA | None = None,
    extra_finish: dict[str, Any] | None = None,
) -> Enrolled:
    """Full happy-path enrollment: register → begin → finish."""
    kinds = kinds or ["alert"]
    token = token if token is not None else register_tenant(env.client, tenant_id, app)
    private_key, pubkey = generate_keypair()
    root = root or env.roots["production"]
    bundle = env.config.app(app).bundle_id

    begin = env.client.post(
        "/v1/enroll/begin",
        json={"app": app, "tenantId": tenant_id, "destinationToken": destination},
    )
    assert begin.status_code == 200, begin.text
    challenge_id = begin.json()["challengeId"]
    server_challenge = begin.json()["serverChallenge"]
    nonce = env.apns.challenge_for(challenge_id)["body"]["relay-challenge"]["nonce"]

    attestation, cred_key = mint_attestation(root, rp_id=bundle)
    assertion = mint_assertion(
        cred_key, nonce=nonce, server_challenge=server_challenge, rp_id=bundle
    )
    finish_payload: dict[str, Any] = {
        "challengeId": challenge_id,
        "attestation": attestation,
        "assertion": assertion,
        "tenantId": tenant_id,
        "tenantPubkey": pubkey,
        "kinds": kinds,
    }
    if ttl is not None:
        finish_payload["ttl"] = ttl
    if extra_finish:
        finish_payload.update(extra_finish)
    finish = env.client.post("/v1/enroll/finish", json=finish_payload)
    assert finish.status_code == 200, finish.text
    body = finish.json()
    return Enrolled(
        grant=body["grant"],
        consent=body["consent"],
        token=token,
        private_key=private_key,
        pubkey=pubkey,
        tenant_id=tenant_id,
        destination=destination,
        kinds=kinds,
    )


def push_payload(
    enrolled: Enrolled,
    *,
    kind: str = "alert",
    content: dict[str, Any] | None = None,
    destination: str | None = None,
    grant: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    if content is None:
        content = {"alert": {"title": "t", "body": "b"}} if kind == "alert" else {}
    payload: dict[str, Any] = {
        "grant": grant or enrolled.grant,
        "destinationToken": destination or enrolled.destination,
        "kind": kind,
        "content": content,
    }
    payload.update(extra)
    return payload


def do_push(
    client: TestClient,
    payload: dict[str, Any],
    token: str,
    private_key: Any,
    **sign_kwargs: Any,
) -> httpx.Response:
    return post_signed(client, "/v1/push", payload, token, private_key, **sign_kwargs)
