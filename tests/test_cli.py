"""``relay`` CLI (PLAN §5) — exercised through ``cli.main.main`` with mock transports.

Doctor is offline (env-driven); every HTTP command gets an ``httpx.MockTransport``
that records the request it saw and replays a canned response, so no network,
no server and no admin API are involved.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml
from cryptography.hazmat.primitives import hashes

import apns_relay.attest as attest_mod
from apns_relay.cli.main import CliError, _call, _duration_to_seconds, main
from tests.conftest import ADMIN_TOKEN, APP_ID, KEY_ID, TENANT_ID, make_root, write_config

SECRET = "s" * 32
FROZEN_TS = 1_800_000_000  # the clock fixture's start
NOW_ISO = "2027-01-15 08:00:00Z"  # _iso(FROZEN_TS)
NOW_ISO_10 = "2027-01-15 08:00:10Z"  # _iso(FROZEN_TS + 10)

STATUS_JSON = {
    "status": "ok",
    "uptimeSeconds": 42,
    "tenants": 3,
    "denylisted": 1,
    "apps": [
        {
            "id": "test-app",
            "enabled": True,
            "keyId": "TESTKEYID1",
            "environments": ["sandbox", "production"],
            "kinds": ["alert"],
            "quota": {"burst_per_min": 5, "daily": 10, "token_burst_per_min": 3},
            "grantTtl": {"min": 900, "max": 86400, "default": 3600},
            "attestEnvironment": "production",
        },
        {
            "id": "second-app",
            "enabled": False,
            "keyId": "TESTKEYID1",
            "environments": ["sandbox"],
            "kinds": ["background"],
            "quota": {"burst_per_min": 1, "daily": 2, "token_burst_per_min": 3},
            "grantTtl": {"min": 900, "max": 86400, "default": 900},
            "attestEnvironment": "production",
        },
    ],
    "metrics": {
        "pushes_total": {"": 2, "accepted": 1},
        "failures_total": {"bad_admin_token": 4},
    },
}


@pytest.fixture(autouse=True)
def _clean_relay_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate every CLI env var; tests opt in explicitly."""
    for var in ("RELAY_CONFIG", "RELAY_ADMIN_TOKEN", "RELAY_MASTER_SECRET", "RELAY_API_URL"):
        monkeypatch.delenv(var, raising=False)


def _auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELAY_ADMIN_TOKEN", ADMIN_TOKEN)


def _doctor_env(monkeypatch: pytest.MonkeyPatch, config: Path) -> None:
    monkeypatch.setenv("RELAY_CONFIG", str(config))
    monkeypatch.setenv("RELAY_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("RELAY_MASTER_SECRET", SECRET)


def _instance(tmp_path: Path, *, roots: bool = True) -> Path:
    base = tmp_path / "instance"
    base.mkdir(parents=True, exist_ok=True)
    root_paths = None
    if roots:
        root = base / "production-root.pem"
        root.write_bytes(make_root("Prod Root").pem)
        root_paths = {"production": root}
    return write_config(base, roots=root_paths)


# -- doctor (offline) ----------------------------------------------------------


def test_doctor_happy_path(tmp_path: Path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path)
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "all checks passed" in out
    assert "ok    config: 1 app(s)" in out
    assert "ok    apns-keys: 1 key(s)" in out
    assert "ok    issuer-key: Ed25519 id=" in out
    assert f"ok    attest-root[production]: {config.parent / 'production-root.pem'}" in out
    assert "ok    master-secret: present (>=32 chars)" in out
    assert "ok    database:" in out


def test_doctor_config_not_found(tmp_path: Path, monkeypatch, capsys) -> None:
    _doctor_env(monkeypatch, tmp_path / "absent.yaml")
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  config" in out
    assert "config not found" in out
    assert "doctor: 1 check failed" in out


def test_doctor_config_invalid_yaml(tmp_path: Path, monkeypatch, capsys) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("apps: [broken\n")
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  config" in out
    assert "invalid YAML" in out
    assert "doctor: 1 check failed" in out


def test_doctor_missing_admin_token_fails_config_check(tmp_path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path)
    monkeypatch.setenv("RELAY_CONFIG", str(config))
    monkeypatch.setenv("RELAY_MASTER_SECRET", SECRET)
    # RELAY_ADMIN_TOKEN deliberately unset: config check fails and doctor
    # reports before any later check runs.
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  config" in out
    assert "admin token not provided" in out
    assert "apns-keys" not in out
    assert "doctor: 1 check failed" in out


def test_doctor_short_master_secret_fails_but_checks_continue(
    tmp_path, monkeypatch, capsys
) -> None:
    config = _instance(tmp_path)
    _doctor_env(monkeypatch, config)
    monkeypatch.setenv("RELAY_MASTER_SECRET", "too-short")
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "ok    config" in out
    assert "ok    apns-keys" in out
    assert "ok    issuer-key" in out
    assert "FAIL  master-secret" in out
    assert "doctor: 1 check(s) failed" in out


def test_doctor_missing_apns_key_fails_but_checks_continue(tmp_path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path)
    (config.parent / "keys" / f"AuthKey_{KEY_ID}.p8").unlink()
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  apns-keys" in out
    assert "ok    issuer-key" in out  # remaining checks still run
    assert "ok    master-secret" in out
    assert "ok    database" in out


def test_doctor_missing_issuer_key(tmp_path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path)
    (config.parent / "keys" / "issuer.pem").unlink()
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "ok    apns-keys" in out
    assert "FAIL  issuer-key" in out
    assert "grant_issuer_key not found" in out
    assert "doctor: 1 check(s) failed" in out


def test_doctor_broken_attest_root(tmp_path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path)
    (config.parent / "production-root.pem").write_bytes(b"not a certificate")
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  attest-root[production]" in out
    assert "ok    issuer-key" in out  # root failure doesn't stop the run
    assert "doctor: 1 check(s) failed" in out


def test_doctor_without_attest_roots_notes_and_passes(tmp_path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path, roots=False)
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "note  attest-roots: none configured" in out
    assert "all checks passed" in out


def test_doctor_unwritable_database_path(tmp_path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path, roots=False)
    raw = yaml.safe_load(config.read_text())
    raw["storage"]["database"] = "blocker/relay.db"  # parent is a regular file
    config.write_text(yaml.safe_dump(raw))
    (config.parent / "blocker").write_text("not a directory")
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  apns-keys" not in out
    assert "ok    database" not in out
    assert "FAIL  database" in out
    assert "doctor: 1 check(s) failed" in out


# -- doctor attest-root checks + fetch-roots -----------------------------------


def _pin(monkeypatch: pytest.MonkeyPatch, root) -> None:
    """Point the pinned SHA-256 at a minted root (rotation-style update)."""
    monkeypatch.setattr(
        attest_mod, "APPLE_ATTEST_ROOT_SHA256", root.cert.fingerprint(hashes.SHA256()).hex()
    )


def _no_network(request: httpx.Request) -> httpx.Response:
    raise AssertionError("no request should be sent")


def test_doctor_root_detail_shows_fingerprint_expiry_and_pin_warn(
    tmp_path, monkeypatch, capsys
) -> None:
    # _instance's minted root will not match the real Apple pin: warn, not fail.
    config = _instance(tmp_path)
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "ok    attest-root[production]:" in out
    assert "sha256=" in out
    assert "expires " in out
    assert "warn  attest-root[production]: sha256 differs from the pinned Apple root" in out
    assert "all checks passed" in out


def test_doctor_root_matching_pin_has_no_warn(tmp_path, monkeypatch, capsys) -> None:
    base = tmp_path / "instance"
    root = make_root("Prod Root")
    root_path = base / "production-root.pem"
    config = write_config(base, roots={"production": root_path})
    root_path.write_bytes(root.pem)
    _pin(monkeypatch, root)
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "warn  attest-root" not in out
    assert "all checks passed" in out


def test_doctor_root_expired_fails(tmp_path, monkeypatch, capsys) -> None:
    base = tmp_path / "instance"
    expired = make_root("Expired Root", expired_days=2)
    root_path = base / "production-root.pem"
    config = write_config(base, roots={"production": root_path})
    root_path.write_bytes(expired.pem)
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  attest-root[production]:" in out
    assert "EXPIRED" in out


def test_doctor_root_expiring_soon_warns_but_passes(tmp_path, monkeypatch, capsys) -> None:
    base = tmp_path / "instance"
    aging = make_root("Aging Root", valid_days=30)
    root_path = base / "production-root.pem"
    config = write_config(base, roots={"production": root_path})
    root_path.write_bytes(aging.pem)
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "warn  attest-root[production]:" in out
    assert "expires in" in out
    assert "all checks passed" in out


def test_doctor_root_missing_file_fails(tmp_path, monkeypatch, capsys) -> None:
    base = tmp_path / "instance"
    config = write_config(base, roots={"production": base / "absent.pem"})
    _doctor_env(monkeypatch, config)
    assert main(["doctor"]) == 1
    assert "FAIL  attest-root[production]" in capsys.readouterr().out


def test_fetch_roots_downloads_missing_file(tmp_path, monkeypatch, capsys) -> None:
    base = tmp_path / "instance"
    dest = base / "apple-attest-root.pem"
    config = write_config(base, roots={"production": dest})
    root = make_root("Fetched Root")
    _pin(monkeypatch, root)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=root.pem))
    _doctor_env(monkeypatch, config)
    assert main(["fetch-roots"], transport=transport) == 0
    out = capsys.readouterr().out
    assert "ok    fetch-root[production]:" in out
    assert dest.read_bytes() == root.pem


def test_fetch_roots_if_missing_skips_existing_without_network(
    tmp_path, monkeypatch, capsys
) -> None:
    config = _instance(tmp_path)  # already has production-root.pem on disk
    _doctor_env(monkeypatch, config)
    assert main(["fetch-roots", "--if-missing"], transport=httpx.MockTransport(_no_network)) == 0
    out = capsys.readouterr().out
    assert "present — skipped" in out
    assert (config.parent / "production-root.pem").exists()


def test_fetch_roots_update_overwrites_existing(tmp_path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path)
    rotated = make_root("Rotated Root")
    _pin(monkeypatch, rotated)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=rotated.pem))
    _doctor_env(monkeypatch, config)
    assert main(["fetch-roots"], transport=transport) == 0
    assert (config.parent / "production-root.pem").read_bytes() == rotated.pem


def test_fetch_roots_shared_path_fetched_once(tmp_path, monkeypatch, capsys) -> None:
    base = tmp_path / "instance"
    dest = base / "apple-attest-root.pem"
    config = write_config(base, roots={"development": dest, "production": dest})
    root = make_root("Fetched Root")
    _pin(monkeypatch, root)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=root.pem)

    _doctor_env(monkeypatch, config)
    assert main(["fetch-roots"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert len(calls) == 1
    assert out.count("ok    fetch-root") == 1


def test_fetch_roots_disabled_url_fails(tmp_path, monkeypatch, capsys) -> None:
    base = tmp_path / "instance"
    dest = base / "apple-attest-root.pem"
    config = write_config(base, roots={"production": dest}, attest_root_url=None)
    _doctor_env(monkeypatch, config)
    assert main(["fetch-roots"], transport=httpx.MockTransport(_no_network)) == 1
    assert "FAIL  fetch-roots: enrollment.attest_root_url is not set" in capsys.readouterr().out


def test_fetch_roots_no_roots_configured(tmp_path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path, roots=False)
    _doctor_env(monkeypatch, config)
    assert main(["fetch-roots"], transport=httpx.MockTransport(_no_network)) == 0
    assert "no attest_root_certs configured" in capsys.readouterr().out


def test_fetch_roots_bad_config_fails(tmp_path, monkeypatch, capsys) -> None:
    _doctor_env(monkeypatch, tmp_path / "absent.yaml")
    assert main(["fetch-roots"], transport=httpx.MockTransport(_no_network)) == 1
    assert "FAIL  config:" in capsys.readouterr().out


def test_doctor_fetch_roots_flag_downloads_and_checks(tmp_path, monkeypatch, capsys) -> None:
    base = tmp_path / "instance"
    dest = base / "apple-attest-root.pem"
    config = write_config(base, roots={"production": dest})
    rotated = make_root("Rotated Root")
    _pin(monkeypatch, rotated)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=rotated.pem))
    _doctor_env(monkeypatch, config)
    assert main(["doctor", "--fetch-roots"], transport=transport) == 0
    out = capsys.readouterr().out
    assert "ok    fetch-root[production]:" in out
    assert "ok    attest-root[production]:" in out
    assert dest.read_bytes() == rotated.pem
    assert "all checks passed" in out


def test_doctor_fetch_roots_download_failure_fails_check(tmp_path, monkeypatch, capsys) -> None:
    base = tmp_path / "instance"
    dest = base / "apple-attest-root.pem"
    config = write_config(base, roots={"production": dest})
    transport = httpx.MockTransport(lambda request: httpx.Response(503))
    _doctor_env(monkeypatch, config)
    assert main(["doctor", "--fetch-roots"], transport=transport) == 1
    out = capsys.readouterr().out
    assert "FAIL  fetch-root[production]:" in out
    assert "HTTP 503" in out
    assert not dest.exists()  # nothing written on failure


# -- status / metrics / logs ---------------------------------------------------


def test_status_renders_snapshot(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/admin/status"
        assert request.headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
        return httpx.Response(200, json=STATUS_JSON)

    assert main(["status"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "status:  ok" in out
    assert "uptime:  42s" in out
    assert "tenants: 3   denylisted: 1" in out
    assert "apps:" in out
    assert "  test-app (enabled, key TESTKEYID1, envs: sandbox, production, kinds: alert)" in out
    assert "  second-app (disabled, key TESTKEYID1, envs: sandbox, kinds: background)" in out
    assert (
        "    quota: 5/min burst, 10/day, 3/min per token; grant ttl 900..86400s default 3600s"
        in out
    )
    assert (
        "    quota: 1/min burst, 2/day, 3/min per token; grant ttl 900..86400s default 900s" in out
    )
    assert "metrics:" in out
    assert "  failures_total: bad_admin_token=4" in out
    assert "  pushes_total: total=2, accepted=1" in out


def test_status_json_error_maps_to_exit_1(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "not_found", "detail": "nope"})

    assert main(["status"], transport=httpx.MockTransport(handler)) == 1
    err = capsys.readouterr().err
    assert "error: GET /admin/status → 404 not_found nope" in err


def test_status_non_json_error_is_generic(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500, content=b"<html>boom</html>", headers={"content-type": "text/html"}
        )

    assert main(["status"], transport=httpx.MockTransport(handler)) == 1
    err = capsys.readouterr().err
    assert "error: GET /admin/status → 500 error" in err


def test_metrics_text_passthrough(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    body = '# TYPE relay_requests_total counter\nrelay_requests_total{label="200"} 7\n'

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/metrics"
        return httpx.Response(200, text=body, headers={"content-type": "text/plain"})

    assert main(["metrics"], transport=httpx.MockTransport(handler)) == 0
    assert capsys.readouterr().out == body  # byte-for-byte passthrough


def test_metrics_error_exits_1(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    assert main(["metrics"], transport=httpx.MockTransport(handler)) == 1
    assert "error: GET /metrics → 503" in capsys.readouterr().err


def test_logs_empty_events(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return httpx.Response(200, json={"events": []})

    assert main(["logs"], transport=httpx.MockTransport(handler)) == 0
    assert capsys.readouterr().out == "(no events)\n"
    assert seen == [{}]  # no params when --errors/--since are omitted


def test_logs_formats_events(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    events = [
        {
            "ts": FROZEN_TS,
            "status": 200,
            "code": "ok",
            "path": "/v1/push",
            "latencyMs": 12.5,
        },
        {
            "ts": FROZEN_TS + 10,
            "status": 401,
            "code": "invalid_signature",
            "path": "/v1/enroll/finish",
            "latencyMs": 3,
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"events": events})

    assert main(["logs"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [
        f"{NOW_ISO}  {200:<3}  {'ok':<24} {'/v1/push':<28} 12.5ms",
        f"{NOW_ISO_10}  {401:<3}  {'invalid_signature':<24} {'/v1/enroll/finish':<28} 3ms",
    ]


def test_logs_errors_flag(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return httpx.Response(200, json={"events": []})

    assert main(["logs", "--errors"], transport=httpx.MockTransport(handler)) == 0
    capsys.readouterr()
    assert seen == [{"errors": "true"}]


def test_logs_since_sends_epoch_window(monkeypatch, capsys, clock) -> None:
    _auth(monkeypatch)
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return httpx.Response(200, json={"events": []})

    assert main(["logs", "--since", "1h"], transport=httpx.MockTransport(handler)) == 0
    capsys.readouterr()
    since = int(seen[0]["since"])
    assert abs(since - (FROZEN_TS - 3600)) <= 2  # now - 1h, within tolerance
    assert "errors" not in seen[0]


def test_logs_bad_since_duration(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not call the API with a bad duration")

    assert main(["logs", "--since", "x"], transport=httpx.MockTransport(handler)) == 1
    assert "bad duration" in capsys.readouterr().err


# -- tenant --------------------------------------------------------------------


def test_tenant_list_rows_with_app_filter(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    payload = {
        "tenants": [
            {
                "tenant": TENANT_ID,
                "app": APP_ID,
                "registeredAt": FROZEN_TS,
                "lastSeen": FROZEN_TS,
            }
        ]
    }
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=payload)

    assert main(["tenant", "list", "--app", APP_ID], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert f"{TENANT_ID:<32} {APP_ID:<20} registered {NOW_ISO}  last seen {NOW_ISO}\n" in out
    assert dict(seen[0].url.params) == {"app": APP_ID}
    assert seen[0].url.path == "/admin/tenants"


def test_tenant_list_empty(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return httpx.Response(200, json={"tenants": []})

    assert main(["tenant", "list"], transport=httpx.MockTransport(handler)) == 0
    assert capsys.readouterr().out == "(no tenants)\n"
    assert seen == [{}]


def test_tenant_verify_found(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    payload = {
        "exists": True,
        "tenant": TENANT_ID,
        "app": APP_ID,
        "registeredAt": FROZEN_TS,
        "lastSeen": FROZEN_TS,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert dict(request.url.params) == {"tenant": TENANT_ID, "app": APP_ID}
        return httpx.Response(200, json=payload)

    assert (
        main(
            ["tenant", "verify", TENANT_ID, "--app", APP_ID],
            transport=httpx.MockTransport(handler),
        )
        == 0
    )
    out = capsys.readouterr().out
    assert f"exists: tenant={TENANT_ID} app={APP_ID} last seen {NOW_ISO}\n" in out


def test_tenant_verify_unknown_exits_1(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert dict(request.url.params) == {"tenant": "ghost.example.com"}
        return httpx.Response(404, json={"error": "unknown_tenant"})

    assert (
        main(["tenant", "verify", "ghost.example.com"], transport=httpx.MockTransport(handler)) == 1
    )
    err = capsys.readouterr().err
    assert "error: GET /admin/tenants/verify → 404 unknown_tenant" in err


def test_tenant_revoke_rows(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"revoked": 2})

    assert main(["tenant", "revoke", TENANT_ID], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "revoked 2 row(s); next request fails with unknown_tenant" in out
    assert seen == [{"tenant": TENANT_ID, "app": None}]


def test_tenant_revoke_unknown_exits_1(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "unknown_tenant"})

    assert (
        main(
            ["tenant", "revoke", "ghost.example.com", "--app", APP_ID],
            transport=httpx.MockTransport(handler),
        )
        == 1
    )
    assert "unknown_tenant" in capsys.readouterr().err


def test_tenant_reissue_prints_new_token(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    new_token = "tnt_replacement-0123456789abcdef"
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"tenant": TENANT_ID, "app": APP_ID, "token": new_token})

    assert (
        main(
            ["tenant", "reissue", TENANT_ID, "--app", APP_ID],
            transport=httpx.MockTransport(handler),
        )
        == 0
    )
    out = capsys.readouterr().out
    assert f"new token for {TENANT_ID}/{APP_ID}:\n{new_token}\n" in out
    assert seen == [{"tenant": TENANT_ID, "app": APP_ID}]


def test_tenant_reissue_unknown_exits_1(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "unknown_tenant"})

    assert (
        main(
            ["tenant", "reissue", "ghost.example.com", "--app", APP_ID],
            transport=httpx.MockTransport(handler),
        )
        == 1
    )
    assert "unknown_tenant" in capsys.readouterr().err


def test_tenant_reissue_requires_app(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["tenant", "reissue", TENANT_ID])
    assert excinfo.value.code == 2
    assert "--app" in capsys.readouterr().err


# -- denylist ------------------------------------------------------------------


def test_denylist_list_empty(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"entries": []})

    assert main(["denylist", "list"], transport=httpx.MockTransport(handler)) == 0
    assert capsys.readouterr().out == "(denylist empty)\n"


def test_denylist_list_entries(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    key = "sha256:" + "ab" * 32

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"entries": [{"key": key, "expires": FROZEN_TS}]})

    assert main(["denylist", "list"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert f"{key:<72} expires {NOW_ISO}\n" in out


def test_denylist_add_default_expiry(clock, monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    key = "sha256:" + "cd" * 32
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        return httpx.Response(200, json=body)

    assert main(["denylist", "add", key], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert seen == [{"key": key, "expires": FROZEN_TS + 86400}]  # default 24h from now
    assert f"denied {key} until " in out


def test_denylist_add_custom_expiry(clock, monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    key = "jti-01234567-89ab-cdef"
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        return httpx.Response(200, json=body)

    assert (
        main(
            ["denylist", "add", key, "--expires", "2h"],
            transport=httpx.MockTransport(handler),
        )
        == 0
    )
    capsys.readouterr()
    assert seen == [{"key": key, "expires": FROZEN_TS + 7200}]


def test_denylist_add_api_422_exits_1(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"error": "invalid_request"})

    assert main(["denylist", "add", "not-a-key"], transport=httpx.MockTransport(handler)) == 1
    err = capsys.readouterr().err
    assert "error: POST /admin/denylist → 422 invalid_request" in err


# -- env / transport / parser --------------------------------------------------


def test_missing_admin_token_for_http_command(monkeypatch, capsys) -> None:
    # RELAY_ADMIN_TOKEN removed by the autouse fixture.

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request should be sent without an admin token")

    assert main(["status"], transport=httpx.MockTransport(handler)) == 1
    assert "error: RELAY_ADMIN_TOKEN is not set" in capsys.readouterr().err


def test_relay_api_url_env_override(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    monkeypatch.setenv("RELAY_API_URL", "http://admin.internal:9999")
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=STATUS_JSON)

    assert main(["status"], transport=httpx.MockTransport(handler)) == 0
    capsys.readouterr()
    assert seen[0].startswith("http://admin.internal:9999/admin/status")


def test_connect_error_reports_request_failed(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        raise httpx.ConnectError("connection refused", request=request)

    assert main(["status"], transport=httpx.MockTransport(handler)) == 1
    err = capsys.readouterr().err
    assert "error: request failed: connection refused" in err
    assert seen[0].startswith("http://127.0.0.1:8000/")  # default RELAY_API_URL


def test_no_args_exits_2(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2
    assert "usage: relay" in capsys.readouterr().err


def test_unknown_subcommand_exits_2(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["frobnicate"])
    assert excinfo.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


# -- unit: duration parsing and _call error mapping -----------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [("90", 90), ("15m", 900), ("1h", 3600), ("7d", 604800)],
)
def test_duration_to_seconds(value: str, expected: int) -> None:
    assert _duration_to_seconds(value) == expected


def test_duration_to_seconds_rejects_garbage() -> None:
    with pytest.raises(CliError) as excinfo:
        _duration_to_seconds("x")
    assert "bad duration" in str(excinfo.value)


def test_call_returns_none_for_empty_body() -> None:
    client = httpx.Client(
        base_url="http://relay.local", transport=httpx.MockTransport(lambda r: httpx.Response(200))
    )
    assert _call(client, "GET", "/admin/x") is None


def test_call_returns_text_for_non_json_success() -> None:
    client = httpx.Client(
        base_url="http://relay.local",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text="plain body")),
    )
    assert _call(client, "GET", "/admin/x") == "plain body"


def test_call_error_with_detail_appends_suffix() -> None:
    client = httpx.Client(
        base_url="http://relay.local",
        transport=httpx.MockTransport(
            lambda r: httpx.Response(404, json={"error": "gone", "detail": "why"})
        ),
    )
    with pytest.raises(CliError) as excinfo:
        _call(client, "GET", "/admin/x")
    assert str(excinfo.value) == "GET /admin/x → 404 gone why"


def test_call_error_without_detail_has_no_suffix() -> None:
    client = httpx.Client(
        base_url="http://relay.local",
        transport=httpx.MockTransport(lambda r: httpx.Response(400, json={"error": "bad_request"})),
    )
    with pytest.raises(CliError) as excinfo:
        _call(client, "POST", "/admin/x")
    assert str(excinfo.value) == "POST /admin/x → 400 bad_request"


def test_call_error_with_non_dict_json_body() -> None:
    client = httpx.Client(
        base_url="http://relay.local",
        transport=httpx.MockTransport(lambda r: httpx.Response(500, json=["boom"])),
    )
    with pytest.raises(CliError) as excinfo:
        _call(client, "GET", "/admin/x")
    assert str(excinfo.value) == "GET /admin/x → 500 error"
