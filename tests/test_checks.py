"""The doctor checks themselves (``apns_relay.checks``) — the logic behind
``relay doctor --offline`` and ``GET /admin/doctor``.

Rows are asserted directly (``{"check", "status", "detail"}`` dicts); the
CLI/admin layers only render them and count failures.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import yaml
from cryptography.hazmat.primitives import hashes

import apns_relay.attest as attest_mod
from apns_relay.checks import run_checks
from apns_relay.config import RelayConfig, load_config
from tests.conftest import ADMIN_TOKEN, KEY_ID, make_root, write_config

MASTER = "m" * 32


def _instance(tmp_path: Path, *, roots: bool = True) -> tuple[RelayConfig, Path]:
    """A loaded config + its path: one app, keys, issuer key, optional root."""
    base = tmp_path / "instance"
    base.mkdir(parents=True, exist_ok=True)
    root_paths = None
    if roots:
        root = base / "production-root.pem"
        root.write_bytes(make_root("Prod Root").pem)
        root_paths = {"production": root}
    config_path = write_config(base, roots=root_paths)
    return load_config(config_path, admin_token=ADMIN_TOKEN), config_path


def _run(
    config: RelayConfig,
    monkeypatch: pytest.MonkeyPatch,
    *,
    config_path: Path | None = None,
    **kwargs,
) -> list[dict[str, str]]:
    monkeypatch.setenv("RELAY_MASTER_SECRET", MASTER)
    kwargs.setdefault("fetch_roots", False)
    return run_checks(config, config_path=config_path, **kwargs)


def _statuses(rows: list[dict[str, str]], check: str) -> list[str]:
    return [row["status"] for row in rows if row["check"] == check]


def _pin(monkeypatch: pytest.MonkeyPatch, root) -> None:
    """Point the pinned SHA-256 at a minted root (rotation-style update)."""
    monkeypatch.setattr(
        attest_mod, "APPLE_ATTEST_ROOT_SHA256", root.cert.fingerprint(hashes.SHA256()).hex()
    )


# -- config row ----------------------------------------------------------------


def test_config_row_names_path_and_app_count(tmp_path: Path, monkeypatch) -> None:
    config, config_path = _instance(tmp_path)
    rows = _run(config, monkeypatch, config_path=config_path)
    assert rows[0] == {
        "check": "config",
        "status": "ok",
        "detail": f"1 app(s) from {config_path}",
    }


def test_config_row_without_a_path(tmp_path: Path, monkeypatch) -> None:
    config, _ = _instance(tmp_path)
    rows = _run(config, monkeypatch, config_path=None)
    assert rows[0] == {"check": "config", "status": "ok", "detail": "1 app(s)"}


# -- happy path + individual checks ---------------------------------------------


def test_happy_path_everything_ok_except_pin_warn(tmp_path: Path, monkeypatch) -> None:
    config, config_path = _instance(tmp_path)
    rows = _run(config, monkeypatch, config_path=config_path)
    assert [row["status"] for row in rows if row["status"] == "fail"] == []
    assert _statuses(rows, "apns-keys") == ["ok"]
    assert _statuses(rows, "issuer-key") == ["ok"]
    assert _statuses(rows, "attest-root[production]") == ["ok", "warn"]  # pin differs
    assert _statuses(rows, "master-secret") == ["ok"]
    assert _statuses(rows, "database") == ["ok"]
    detail = next(row["detail"] for row in rows if row["check"] == "attest-root[production]")
    assert "sha256=" in detail and "expires " in detail
    warn = [row for row in rows if row["check"] == "attest-root[production]"][1]
    assert "sha256 differs from the pinned Apple root" in warn["detail"]


def test_short_master_secret_fails_but_checks_continue(tmp_path: Path, monkeypatch) -> None:
    config, config_path = _instance(tmp_path)
    monkeypatch.setenv("RELAY_MASTER_SECRET", "too-short")
    rows = run_checks(config, config_path=config_path, fetch_roots=False)
    assert _statuses(rows, "master-secret") == ["fail"]
    assert "RELAY_MASTER_SECRET missing" in rows[-2]["detail"]
    assert _statuses(rows, "apns-keys") == ["ok"]  # later checks still ran
    assert _statuses(rows, "database") == ["ok"]


def test_missing_apns_key_fails_but_checks_continue(tmp_path: Path, monkeypatch) -> None:
    config, config_path = _instance(tmp_path)
    (config_path.parent / "keys" / f"AuthKey_{KEY_ID}.p8").unlink()
    rows = _run(config, monkeypatch, config_path=config_path)
    assert _statuses(rows, "apns-keys") == ["fail"]
    assert _statuses(rows, "issuer-key") == ["ok"]
    assert _statuses(rows, "database") == ["ok"]


def test_missing_issuer_key_fails(tmp_path: Path, monkeypatch) -> None:
    config, config_path = _instance(tmp_path)
    (config_path.parent / "keys" / "issuer.pem").unlink()
    rows = _run(config, monkeypatch, config_path=config_path)
    assert _statuses(rows, "issuer-key") == ["fail"]
    detail = next(row["detail"] for row in rows if row["check"] == "issuer-key")
    assert "grant_issuer_key not found" in detail


def test_broken_attest_root_fails_but_run_continues(tmp_path: Path, monkeypatch) -> None:
    config, config_path = _instance(tmp_path)
    (config_path.parent / "production-root.pem").write_bytes(b"not a certificate")
    rows = _run(config, monkeypatch, config_path=config_path)
    assert _statuses(rows, "attest-root[production]") == ["fail"]
    assert _statuses(rows, "issuer-key") == ["ok"]


def test_no_attest_roots_notes_and_passes(tmp_path: Path, monkeypatch) -> None:
    config, config_path = _instance(tmp_path, roots=False)
    rows = _run(config, monkeypatch, config_path=config_path)
    assert _statuses(rows, "attest-roots") == ["note"]
    note = next(row for row in rows if row["check"] == "attest-roots")
    assert "none configured" in note["detail"]
    assert [row for row in rows if row["status"] == "fail"] == []


def test_unwritable_database_path_fails(tmp_path: Path, monkeypatch) -> None:
    config, config_path = _instance(tmp_path, roots=False)
    raw = yaml.safe_load(config_path.read_text())
    raw["storage"]["database"] = "blocker/relay.db"  # parent is a regular file
    config_path.write_text(yaml.safe_dump(raw))
    (config_path.parent / "blocker").write_text("not a directory")
    config = load_config(config_path, admin_token=ADMIN_TOKEN)
    rows = _run(config, monkeypatch)
    assert _statuses(rows, "database") == ["fail"]
    assert _statuses(rows, "apns-keys") == ["ok"]


# -- attest-root expiry / pin ----------------------------------------------------


def test_root_matching_pin_has_no_warn(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "instance"
    root = make_root("Prod Root")
    root_path = base / "production-root.pem"
    config = load_config(
        write_config(base, roots={"production": root_path}), admin_token=ADMIN_TOKEN
    )
    root_path.write_bytes(root.pem)
    _pin(monkeypatch, root)
    rows = _run(config, monkeypatch)
    assert _statuses(rows, "attest-root[production]") == ["ok"]


def test_root_expired_fails(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "instance"
    expired = make_root("Expired Root", expired_days=2)
    root_path = base / "production-root.pem"
    config = load_config(
        write_config(base, roots={"production": root_path}), admin_token=ADMIN_TOKEN
    )
    root_path.write_bytes(expired.pem)
    rows = _run(config, monkeypatch)
    assert _statuses(rows, "attest-root[production]") == ["fail", "warn"]  # expired + pin
    detail = next(row["detail"] for row in rows if row["status"] == "fail")
    assert "EXPIRED" in detail


def test_root_expiring_soon_warns_but_does_not_fail(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "instance"
    aging = make_root("Aging Root", valid_days=30)
    root_path = base / "production-root.pem"
    config = load_config(
        write_config(base, roots={"production": root_path}), admin_token=ADMIN_TOKEN
    )
    root_path.write_bytes(aging.pem)
    rows = _run(config, monkeypatch)
    assert _statuses(rows, "attest-root[production]") == ["warn", "warn"]  # expiry + pin
    assert any("expires in" in row["detail"] for row in rows)
    assert [row for row in rows if row["status"] == "fail"] == []


def test_root_missing_file_fails(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "instance"
    config = load_config(
        write_config(base, roots={"production": base / "absent.pem"}), admin_token=ADMIN_TOKEN
    )
    rows = _run(config, monkeypatch)
    assert _statuses(rows, "attest-root[production]") == ["fail"]


# -- fetch_roots=True (doctor --fetch-roots / admin ?fetch_roots=true) -----------


def test_fetch_roots_downloads_then_checks(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "instance"
    dest = base / "apple-attest-root.pem"
    config = load_config(write_config(base, roots={"production": dest}), admin_token=ADMIN_TOKEN)
    rotated = make_root("Rotated Root")
    _pin(monkeypatch, rotated)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=rotated.pem))
    rows = _run(config, monkeypatch, fetch_roots=True, transport=transport)
    assert _statuses(rows, "fetch-root[production]") == ["ok"]
    assert dest.read_bytes() == rotated.pem
    assert _statuses(rows, "attest-root[production]") == ["ok"]  # checked after download


def test_fetch_roots_download_failure_fails_check(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "instance"
    dest = base / "apple-attest-root.pem"
    config = load_config(write_config(base, roots={"production": dest}), admin_token=ADMIN_TOKEN)
    transport = httpx.MockTransport(lambda request: httpx.Response(503))
    rows = _run(config, monkeypatch, fetch_roots=True, transport=transport)
    assert _statuses(rows, "fetch-root[production]") == ["fail"]
    assert "HTTP 503" in rows[1]["detail"]
    assert not dest.exists()  # nothing written on failure


def test_fetch_roots_without_a_url_fails(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "instance"
    config = load_config(
        write_config(base, roots={"production": base / "root.pem"}, attest_root_url=None),
        admin_token=ADMIN_TOKEN,
    )
    rows = _run(config, monkeypatch, fetch_roots=True)
    assert _statuses(rows, "fetch-roots") == ["fail"]
    assert "attest_root_url is not set" in rows[1]["detail"]
