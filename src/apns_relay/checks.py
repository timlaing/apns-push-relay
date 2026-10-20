"""The doctor pre-flight checks, shared by the CLI and the admin API.

``relay doctor --offline`` runs them against a machine's own files (the
container-entrypoint gate, before anything listens); ``GET /admin/doctor``
runs the same checks inside the running server process, so the answers
reflect the files and environment that actually serve traffic.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from . import attest as attest_mod
from .apns import KeyRegistry
from .attest import AttestError, fetch_attest_root, load_attest_root
from .config import ConfigError, RelayConfig
from .signing import sha256hex
from .store import Store


def load_issuer_key(path: Path) -> Ed25519PrivateKey:
    """Grant-issuer key: a single Ed25519 private key in a PEM file (v1)."""
    try:
        key = load_pem_private_key(path.read_bytes(), password=None)
    except FileNotFoundError:
        raise ConfigError(f"enrollment.grant_issuer_key not found: {path}") from None
    except ValueError:
        raise ConfigError(f"enrollment.grant_issuer_key is not a valid PEM key: {path}") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigError(f"enrollment.grant_issuer_key must be an Ed25519 key: {path}")
    return key


def fetch_attest_roots(
    config: RelayConfig,
    transport: httpx.BaseTransport | None,
    *,
    only_missing: bool,
    ok: Any,
    fail: Any,
    note: Any,
) -> int:
    """Download the App Attest root into every configured path.

    With ``only_missing`` (container startup) existing files are left alone —
    the boot never depends on the network. Otherwise each path is
    re-downloaded (``relay fetch-roots`` / ``doctor --fetch-roots`` = update).
    Returns the number of failures.
    """
    url = config.enrollment.attest_root_url
    if not url:
        fail("fetch-roots", "enrollment.attest_root_url is not set")
        return 1
    failures = 0
    seen: set[Path] = set()
    for environment, root_path in sorted(config.enrollment.attest_root_certs.items()):
        if root_path in seen:
            continue  # environments may share one root file — fetch it once
        seen.add(root_path)
        if only_missing and root_path.exists():
            note(f"fetch-root[{environment}]", f"{root_path} present — skipped")
            continue
        try:
            root = fetch_attest_root(url, root_path, transport=transport)
        except AttestError as exc:
            failures += 1
            fail(f"fetch-root[{environment}]", f"{root_path}: {exc}")
            continue
        ok(f"fetch-root[{environment}]", f"{root_path} ({root.subject.rfc4514_string()})")
    return failures


def run_checks(
    config: RelayConfig,
    *,
    config_path: Path | None,
    fetch_roots: bool,
    transport: httpx.BaseTransport | None = None,
) -> list[dict[str, str]]:
    """Every pre-flight check as ``{"check", "status", "detail"}`` rows —
    the config row first; a failing check never stops the run."""
    rows: list[dict[str, str]] = [
        {
            "check": "config",
            "status": "ok",
            "detail": f"{len(config.apps)} app(s)"
            + (f" from {config_path}" if config_path is not None else ""),
        }
    ]

    def ok(label: str, detail: str) -> None:
        rows.append({"check": label, "status": "ok", "detail": detail})

    def fail(label: str, detail: str) -> None:
        rows.append({"check": label, "status": "fail", "detail": detail})

    def warn(label: str, detail: str) -> None:
        rows.append({"check": label, "status": "warn", "detail": detail})

    def note(label: str, detail: str) -> None:
        rows.append({"check": label, "status": "note", "detail": detail})

    if fetch_roots:
        fetch_attest_roots(config, transport, only_missing=False, ok=ok, fail=fail, note=note)

    try:
        registry = KeyRegistry(config.enabled_apps)
        del registry
        ok("apns-keys", f"{len(config.enabled_apps)} key(s), JWT pre-signed at boot")
    except Exception as exc:  # report any key failure, keep checking
        fail("apns-keys", str(exc))

    try:
        issuer = load_issuer_key(config.enrollment.grant_issuer_key)
        issuer_id = sha256hex(issuer.public_key().public_bytes_raw())[:16]
        ok("issuer-key", f"Ed25519 id={issuer_id}")
    except ConfigError as exc:
        fail("issuer-key", str(exc))

    if not config.enrollment.attest_root_certs:
        note(
            "attest-roots",
            "none configured — enroll/finish fails closed until App Attest roots are supplied (M4)",
        )
    for environment, root_path in sorted(config.enrollment.attest_root_certs.items()):
        try:
            root = load_attest_root(root_path)
        except (OSError, ValueError) as exc:
            fail(f"attest-root[{environment}]", str(exc))
            continue
        fingerprint = root.fingerprint(hashes.SHA256()).hex()
        days_left = (root.not_valid_after_utc - datetime.now(UTC)).days
        detail = (
            f"{root_path} ({root.subject.rfc4514_string()};"
            f" sha256={fingerprint[:16]}; expires {root.not_valid_after_utc.date()})"
        )
        if days_left < 0:
            fail(f"attest-root[{environment}]", f"{detail} — EXPIRED")
        elif days_left < 90:
            warn(f"attest-root[{environment}]", f"{detail} — expires in {days_left}d")
        else:
            ok(f"attest-root[{environment}]", detail)
        if fingerprint != attest_mod.APPLE_ATTEST_ROOT_SHA256:
            warn(
                f"attest-root[{environment}]",
                "sha256 differs from the pinned Apple root — fine if this is"
                " your own root; after an Apple rotation, verify the new"
                " fingerprint and update APPLE_ATTEST_ROOT_SHA256 in a release",
            )

    secret = os.environ.get("RELAY_MASTER_SECRET", "")
    if len(secret) >= 32:
        ok("master-secret", "present (>=32 chars)")
    else:
        fail("master-secret", "RELAY_MASTER_SECRET missing or shorter than 32 characters")

    try:
        Store(config.database)
        ok("database", str(config.database))
    except Exception as exc:
        fail("database", str(exc))
    return rows
