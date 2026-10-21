"""``relay`` CLI (PLAN §5) — exercised through ``cli.main.main`` with mock transports.

Doctor is offline (env-driven); every HTTP command gets an ``httpx.MockTransport``
that records the request it saw and replays a canned response, so no network,
no server and no admin API are involved.
"""

from __future__ import annotations

import io
import json
import re
import sys
from importlib.metadata import version as package_version
from pathlib import Path

import httpx
import pytest
import typer.main as typer_main
from cryptography.hazmat.primitives import hashes
from typer import _click as vendored_click

import apns_relay.attest as attest_mod
import apns_relay.cli.main as cli_main
from apns_relay.cli.main import CliError, _call, _duration_to_seconds, main
from tests.conftest import ADMIN_TOKEN, APP_ID, TENANT_ID, make_root, write_config

SECRET = "s" * 32
FROZEN_TS = 1_800_000_000  # the clock fixture's start
NOW_ISO = "2027-01-15 08:00:00Z"  # _iso(FROZEN_TS)
NOW_ISO_10 = "2027-01-15 08:00:10Z"  # _iso(FROZEN_TS + 10)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip rich's ANSI styling from captured output.

    CI forces colour on (TTY_COMPATIBLE/FORCE_COLOR), which wraps styled runs
    in escape sequences and splits phrases like ``"Usage: relay"`` across run
    boundaries; assertions read the plain text underneath.
    """
    return _ANSI_RE.sub("", text)


STATUS_JSON = {
    "version": "9.9.9-test",
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
    monkeypatch.setenv("COLUMNS", "260")  # rich tables: keep rows on one line


def _instance(tmp_path: Path, *, roots: bool = True) -> Path:
    base = tmp_path / "instance"
    base.mkdir(parents=True, exist_ok=True)
    root_paths = None
    if roots:
        root = base / "production-root.pem"
        root.write_bytes(make_root("Prod Root").pem)
        root_paths = {"production": root}
    return write_config(base, roots=root_paths)


# -- doctor (admin API) ----------------------------------------------------------


_DOCTOR_PAYLOAD = {
    "failures": 0,
    "checks": [
        {"check": "config", "status": "ok", "detail": "1 app(s) from /etc/apns-relay/config.yaml"},
        {"check": "apns-keys", "status": "ok", "detail": "1 key(s), JWT pre-signed at boot"},
        {"check": "master-secret", "status": "ok", "detail": "present (>=32 chars)"},
    ],
}


def test_doctor_queries_the_admin_api(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    monkeypatch.setenv("COLUMNS", "260")  # rich tables: keep rows on one line

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/admin/doctor"
        assert request.url.params["fetch_roots"] == "false"
        assert request.headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
        return httpx.Response(200, json=_DOCTOR_PAYLOAD)

    assert main(["doctor"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "╭─ doctor ─" in out
    assert "apns-keys" in out
    assert "present (>=32 chars)" in out
    assert "doctor: all checks passed" in out


def test_doctor_json_prints_the_api_payload(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_DOCTOR_PAYLOAD)

    assert main(["doctor", "--json"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == _DOCTOR_PAYLOAD
    assert "doctor:" not in out  # JSON mode: no human summary line


def test_doctor_fetch_roots_flag_reaches_the_server(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["fetch_roots"] = request.url.params["fetch_roots"]
        return httpx.Response(200, json=_DOCTOR_PAYLOAD)

    assert main(["doctor", "--fetch-roots"], transport=httpx.MockTransport(handler)) == 0
    assert seen["fetch_roots"] == "true"


def test_doctor_failures_exit_1(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    payload = {
        "failures": 1,
        "checks": [
            {"check": "config", "status": "ok", "detail": "1 app(s)"},
            {"check": "issuer-key", "status": "fail", "detail": "grant_issuer_key not found: /x"},
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    assert main(["doctor"], transport=httpx.MockTransport(handler)) == 1
    out = capsys.readouterr().out
    assert "doctor: 1 check(s) failed" in out


def test_doctor_unreachable_api_is_a_clean_error(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    assert main(["doctor"], transport=httpx.MockTransport(handler)) == 1
    err = capsys.readouterr().err
    assert "error: request failed" in err  # no traceback, the usual error panel


def test_doctor_requires_admin_token(monkeypatch, capsys) -> None:
    monkeypatch.delenv("RELAY_ADMIN_TOKEN", raising=False)
    assert main(["doctor"]) == 1
    assert "RELAY_ADMIN_TOKEN is not set" in capsys.readouterr().err


# -- doctor --offline (the container-entrypoint pre-flight) ----------------------


def test_doctor_offline_happy_path(tmp_path: Path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path)
    _doctor_env(monkeypatch, config)
    assert main(["doctor", "--offline"]) == 0
    out = capsys.readouterr().out
    assert "╭─ doctor ─" in out
    assert "all checks passed" in out
    assert "1 app(s) from" in out
    assert "1 key(s), JWT pre-signed" in out
    assert "Ed25519 id=" in out
    assert str(config.parent / "production-root.pem") in out
    assert "present (>=32 chars)" in out
    assert "database" in out


def test_doctor_offline_json_reports_checks(tmp_path: Path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path)
    _doctor_env(monkeypatch, config)
    assert main(["doctor", "--offline", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["failures"] == 0
    assert payload["checks"][0]["check"] == "config"
    by_name = {row["check"]: row["status"] for row in payload["checks"]}
    assert by_name["master-secret"] == "ok"
    assert by_name["database"] == "ok"


def test_doctor_offline_failures_exit_1(tmp_path: Path, monkeypatch, capsys) -> None:
    config = _instance(tmp_path)
    _doctor_env(monkeypatch, config)
    monkeypatch.setenv("RELAY_MASTER_SECRET", "too-short")
    assert main(["doctor", "--offline", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["failures"] == 1
    failed = [row for row in payload["checks"] if row["status"] == "fail"]
    assert [row["check"] for row in failed] == ["master-secret"]


def test_doctor_offline_config_not_found(tmp_path: Path, monkeypatch, capsys) -> None:
    _doctor_env(monkeypatch, tmp_path / "absent.yaml")
    assert main(["doctor", "--offline"]) == 1
    out = capsys.readouterr().out
    assert "config not found" in out
    assert "doctor: 1 check(s) failed" in out


def test_doctor_offline_config_invalid_yaml(tmp_path: Path, monkeypatch, capsys) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("apps: [broken\n")
    _doctor_env(monkeypatch, config)
    assert main(["doctor", "--offline"]) == 1
    out = capsys.readouterr().out
    assert "invalid YAML" in out
    assert "doctor: 1 check(s) failed" in out


def test_doctor_offline_missing_admin_token_fails_config_check(
    tmp_path, monkeypatch, capsys
) -> None:
    config = _instance(tmp_path)
    monkeypatch.setenv("RELAY_CONFIG", str(config))
    monkeypatch.setenv("RELAY_MASTER_SECRET", SECRET)
    # RELAY_ADMIN_TOKEN deliberately unset: the config row fails and no
    # later check runs.
    assert main(["doctor", "--offline"]) == 1
    out = capsys.readouterr().out
    assert "admin token not provided" in out
    assert "apns-keys" not in out
    assert "doctor: 1 check(s) failed" in out


# -- fetch-roots -----------------------------------------------------------------


def _pin(monkeypatch: pytest.MonkeyPatch, root) -> None:
    """Point the pinned SHA-256 at a minted root (rotation-style update)."""
    monkeypatch.setattr(
        attest_mod, "APPLE_ATTEST_ROOT_SHA256", root.cert.fingerprint(hashes.SHA256()).hex()
    )


def _no_network(request: httpx.Request) -> httpx.Response:
    raise AssertionError("no request should be sent")


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


# -- status / metrics / logs ---------------------------------------------------


def test_version_command(capsys) -> None:
    assert main(["version"]) == 0
    out = capsys.readouterr().out
    assert "╭─ version ─" in out
    assert f"relay {package_version('apns-push-relay')}" in out


def test_version_json(capsys) -> None:
    assert main(["version", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"version": package_version("apns-push-relay")}


def test_status_renders_snapshot(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    monkeypatch.setenv("COLUMNS", "220")  # rich tables: keep rows on one line

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/admin/status"
        assert request.headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
        return httpx.Response(200, json=STATUS_JSON)

    assert main(["status"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "status" in out and "ok" in out
    assert "uptime" in out and "42s" in out
    assert "version" in out and "9.9.9-test" in out
    assert "tenants" in out and "denylisted" in out
    assert "test-app" in out and "second-app" in out
    assert "enabled" in out and "disabled" in out
    assert "TESTKEYID1" in out
    assert "sandbox, production" in out and "background" in out
    assert "5/min burst, 10/day, 3/min per token" in out
    assert "900..86400s default 3600s" in out
    assert "metrics" in out
    assert "failures_total" in out
    assert "bad_admin_token=4" in out
    assert "pushes_total" in out
    assert "total=2, accepted=1" in out


def test_status_json(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=STATUS_JSON)

    assert main(["status", "--json"], transport=httpx.MockTransport(handler)) == 0
    assert json.loads(capsys.readouterr().out) == STATUS_JSON


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

    assert main(["metrics", "--prom"], transport=httpx.MockTransport(handler)) == 0
    assert capsys.readouterr().out == body  # byte-for-byte passthrough


def test_metrics_error_exits_1(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    assert main(["metrics", "--prom"], transport=httpx.MockTransport(handler)) == 1
    assert "error: GET /metrics → 503" in capsys.readouterr().err


def test_metrics_renders_table(monkeypatch, capsys) -> None:
    """Default mode reads the status snapshot and renders the legend table."""
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/admin/status"
        return httpx.Response(200, json=STATUS_JSON)

    assert main(["metrics"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "╭─ metrics ─" in out
    assert "failures_total" in out and "bad_admin_token=4" in out
    assert "pushes_total" in out and "total=2, accepted=1" in out


def test_metrics_json(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/admin/status"
        return httpx.Response(200, json=STATUS_JSON)

    assert main(["metrics", "--json"], transport=httpx.MockTransport(handler)) == 0
    assert json.loads(capsys.readouterr().out) == STATUS_JSON["metrics"]


def test_metrics_empty(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={**STATUS_JSON, "metrics": {}})

    assert main(["metrics"], transport=httpx.MockTransport(handler)) == 0
    assert "(no metrics yet)" in capsys.readouterr().out


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
    monkeypatch.setenv("COLUMNS", "160")  # rich tables: keep rows on one line
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
    assert TENANT_ID in out
    assert APP_ID in out
    assert "registered" in out and "last seen" in out  # column headers
    assert NOW_ISO in out  # row timestamps
    assert dict(seen[0].url.params) == {"app": APP_ID}
    assert seen[0].url.path == "/admin/tenants"


def test_tenant_list_empty(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return httpx.Response(200, json={"tenants": []})

    assert main(["tenant", "list"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "╭─ tenants ─" in out and "(no tenants)" in out
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
    assert main(["tenant", "reissue", TENANT_ID]) == 2
    err = capsys.readouterr().err
    assert "--app" in err
    assert "Usage:" in err  # errors are followed by the command's help


# -- denylist ------------------------------------------------------------------


def test_denylist_list_empty(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"entries": []})

    assert main(["denylist", "list"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "╭─ denylist ─" in out and "(denylist empty)" in out


def test_denylist_list_entries(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    monkeypatch.setenv("COLUMNS", "160")  # rich tables: keep rows on one line
    key = "sha256:" + "ab" * 32

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"entries": [{"key": key, "expires": FROZEN_TS}]})

    assert main(["denylist", "list"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert key in out
    assert NOW_ISO in out


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
    assert main([]) == 2
    # no_args_is_help prints the root help before exiting
    assert "Usage: relay" in _plain(capsys.readouterr().out)


def test_unknown_subcommand_exits_2(capsys) -> None:
    assert main(["frobnicate"]) == 2
    err = _plain(capsys.readouterr().err)
    assert "No such command 'frobnicate'." in err
    assert "Usage: relay" in err  # error is followed by help


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


# -- monitor (live dashboard) ---------------------------------------------------


def test_monitor_once_renders_frame(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/admin/status":
            return httpx.Response(200, json=STATUS_JSON)
        return httpx.Response(
            200,
            json={
                "events": [
                    {
                        "ts": FROZEN_TS,
                        "status": 200,
                        "code": "accepted",
                        "path": "/v1/push",
                        "latencyMs": 9,
                    }
                ]
            },
        )

    assert main(["monitor", "--once"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "test-app" in out
    assert "uptime" in out
    assert "recent requests" in out
    assert "/v1/push" in out
    assert [request.url.path for request in seen] == ["/admin/status", "/admin/logs"]
    assert dict(seen[1].url.params) == {}


def test_monitor_once_errors_flag_filters_events(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/admin/status":
            return httpx.Response(200, json=STATUS_JSON)
        return httpx.Response(200, json={"events": []})

    assert main(["monitor", "--once", "--errors"], transport=httpx.MockTransport(handler)) == 0
    capsys.readouterr()
    assert dict(seen[1].url.params) == {"errors": "true"}


def test_monitor_loop_renders_until_interrupt(monkeypatch) -> None:
    _auth(monkeypatch)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/admin/status":
            return httpx.Response(200, json=STATUS_JSON)
        return httpx.Response(200, json={"events": []})

    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) > 1:  # first cycle completes; Ctrl-C on the next one
            raise KeyboardInterrupt

    monkeypatch.setattr(cli_main.time, "sleep", fake_sleep)
    assert main(["monitor"], transport=httpx.MockTransport(handler)) == 0
    assert calls.count("/admin/status") == 2  # initial frame + one refresh
    assert sleeps == [5.0, 5.0]  # --interval default


def test_usage_error_without_context_shows_root_help(monkeypatch, capsys) -> None:
    real_command = typer_main.get_command(cli_main.app)

    class FailingCommand:
        def __call__(self, **_kwargs) -> int:
            raise vendored_click.exceptions.UsageError("kaboom")

        def make_context(self, *args, **kwargs):
            return real_command.make_context(*args, **kwargs)

    monkeypatch.setattr(typer_main, "get_command", lambda _app: FailingCommand())
    assert cli_main.main(["doctor"]) == 2
    err = _plain(capsys.readouterr().err)
    assert "error: kaboom" in err
    assert "Usage: relay" in err  # falls back to the root help


# -- app add / remove / list (admin API: /admin/apps) ---------------------------


TEAM = "TEAMID0001"
OTHER_KEY = "ZZZZZZ9999"

APPS_JSON = {
    "apps": [
        {
            "id": "alpha",
            "bundle_id": "com.example.alpha",
            "team_id": TEAM,
            "key_id": "ABCDEF0123",
            "environments": ["sandbox", "production"],
        },
        {
            "id": "beta",
            "bundle_id": "com.example.beta",
            "team_id": "TEAMID0002",
            "key_id": OTHER_KEY,
            "environments": ["production"],
        },
    ]
}


def test_app_list_renders_table(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    monkeypatch.setenv("COLUMNS", "220")  # rich tables: keep rows on one line

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/admin/apps"
        assert request.headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
        return httpx.Response(200, json=APPS_JSON)

    assert main(["app", "list"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "apps" in out
    assert "alpha" in out and "com.example.alpha" in out
    assert "ABCDEF0123" in out
    assert "sandbox, production" in out
    assert "beta" in out and "TEAMID0002" in out


def test_app_list_json(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/admin/apps"
        return httpx.Response(200, json=APPS_JSON)

    assert main(["app", "list", "--json"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == APPS_JSON  # the API payload, verbatim
    assert "╭─" not in out  # JSON only, no table


def test_app_list_requires_admin_token(monkeypatch, capsys) -> None:
    # app commands are API clients now — no token, no request
    monkeypatch.delenv("RELAY_ADMIN_TOKEN", raising=False)
    assert main(["app", "list"]) == 1
    assert "RELAY_ADMIN_TOKEN is not set" in capsys.readouterr().err


def test_config_flag_rejected_on_every_command(capsys) -> None:
    """--config is gone: app commands go through the admin API, the offline
    checks resolve $RELAY_CONFIG / the container default only."""
    for argv in (
        ["app", "list", "--config", "x.yaml"],
        [
            "app",
            "add",
            "--config",
            "x.yaml",
            "--yes",
            "--bundle-id",
            "com.example.demo",
            "--team-id",
            TEAM,
            "--key-id",
            "ABCDEF0123",
        ],
        ["app", "remove", "alpha", "--config", "x.yaml"],
        ["doctor", "--config", "x.yaml"],
        ["fetch-roots", "--config", "x.yaml"],
    ):
        assert main(argv) == 2  # click UsageError → our exit 2
        assert "--config" in capsys.readouterr().err  # unknown option


def test_app_add_noninteractive(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/admin/apps"
        body = json.loads(request.content)
        assert body == {
            "id": "demo",
            "display_name": "Demo App",
            "bundle_id": "com.example.demo",
            "team_id": TEAM,
            "key_id": "ABCDEF0123",
            "environments": ["sandbox"],
            "kinds": ["alert", "background"],
            "live_activity": False,
            "attest_environment": "development",
        }
        return httpx.Response(201, json={"app": body, "restartRequired": True})

    argv = [
        "app",
        "add",
        "--yes",
        "--key-id",
        "ABCDEF0123",
        "--id",
        "demo",
        "--bundle-id",
        "com.example.demo",
        "--team-id",
        TEAM,
        "--display-name",
        "Demo App",
        "--environment",
        "sandbox",
        "--kind",
        "alert",
        "--kind",
        "background",
        "--no-live-activity",
        "--attest-environment",
        "development",
    ]
    assert main(argv, transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "added demo" in out
    assert "restart the relay to apply" in out
    # the pre-confirm summary is one field per line
    assert "Adding demo:" in out
    assert "  bundle=com.example.demo" in out
    assert "  key=AuthKey_ABCDEF0123.p8" in out
    assert "  attest=development" in out


def test_app_add_json(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        body = json.loads(request.content)
        return httpx.Response(201, json={"app": body, "restartRequired": True})

    argv = [
        "app",
        "add",
        "--yes",
        "--json",
        "--key-id",
        "ABCDEF0123",
        "--id",
        "demo",
        "--bundle-id",
        "com.example.demo",
        "--team-id",
        TEAM,
    ]
    assert main(argv, transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["restartRequired"] is True
    assert payload["app"]["id"] == "demo"
    assert payload["app"]["key_id"] == "ABCDEF0123"
    assert payload["app"]["bundle_id"] == "com.example.demo"
    # stdout is machine-readable: no human summary, ok line, or restart note
    assert "Adding" not in out
    assert "added demo" not in out
    assert "restart the relay" not in out


def test_app_add_yes_requires_flags(monkeypatch, capsys) -> None:
    # prompts disabled → identity flags must be present; nothing is sent

    def fail(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    assert (
        main(
            ["app", "add", "--yes", "--bundle-id", "com.example.demo"],
            transport=httpx.MockTransport(fail),
        )
        == 1
    )
    err = capsys.readouterr().err
    assert "--yes requires" in err
    assert "--team-id" in err and "--key-id" in err


def test_app_add_yes_derives_id_from_bundle(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["id"] == "demo"  # last bundle component
        assert body["display_name"] == "demo"
        assert body["environments"] == ["sandbox", "production"]
        assert body["kinds"] == ["alert", "background", "liveActivity"]
        assert body["live_activity"] is True
        return httpx.Response(201, json={"app": body, "restartRequired": True})

    assert (
        main(
            [
                "app",
                "add",
                "--yes",
                "--key-id",
                "ABCDEF0123",
                "--bundle-id",
                "com.example.demo",
                "--team-id",
                TEAM,
            ],
            transport=httpx.MockTransport(handler),
        )
        == 0
    )
    assert "added demo" in capsys.readouterr().out


def test_app_add_interactive_picks_key(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    monkeypatch.setenv("COLUMNS", "160")
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin/keys":
            # key discovery is the server's: it scans keys/ beside its config
            return httpx.Response(200, json={"keys": ["ABCDEF0123", OTHER_KEY]})
        assert request.url.path == "/admin/apps"
        seen["body"] = json.loads(request.content)
        return httpx.Response(201, json={"app": seen["body"], "restartRequired": True})

    monkeypatch.setattr(sys, "stdin", io.StringIO("com.example.demo\nTEAMID0001\n1\n\ny\n"))
    assert main(["app", "add"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "Available keys:" in out
    assert "1. AuthKey_ABCDEF0123.p8" in out
    assert f"2. AuthKey_{OTHER_KEY}.p8" in out
    assert "added demo" in out
    assert seen["body"]["key_id"] == "ABCDEF0123"  # type: ignore[index]


def test_app_add_invalid_key_number(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"keys": ["ABCDEF0123"]})

    monkeypatch.setattr(sys, "stdin", io.StringIO("9\n"))
    assert (
        main(
            ["app", "add", "--bundle-id", "com.example.demo", "--team-id", TEAM],
            transport=httpx.MockTransport(handler),
        )
        == 1
    )
    assert "expected a key number 1..1" in capsys.readouterr().err


def test_app_add_no_keys_errors(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"keys": []})

    assert (
        main(
            ["app", "add", "--bundle-id", "com.example.demo", "--team-id", TEAM],
            transport=httpx.MockTransport(handler),
        )
        == 1
    )
    assert "no AuthKey_<KEYID>.p8 found" in capsys.readouterr().err


def test_app_add_declined_confirmation(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no POST after a declined prompt")

    monkeypatch.setattr(sys, "stdin", io.StringIO("n\n"))
    assert (
        main(
            [
                "app",
                "add",
                "--key-id",
                "ABCDEF0123",
                "--id",
                "demo",
                "--bundle-id",
                "com.example.demo",
                "--team-id",
                TEAM,
            ],
            transport=httpx.MockTransport(handler),
        )
        == 0
    )
    assert "added" not in capsys.readouterr().out


def test_app_add_eof_aborts(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))  # EOF at the first prompt
    assert main(["app", "add"], transport=httpx.MockTransport(_no_network)) == 1
    assert "aborted" in capsys.readouterr().err


def test_app_add_api_error_surfaces_detail(monkeypatch, capsys) -> None:
    _auth(monkeypatch)
    monkeypatch.setenv("COLUMNS", "220")  # the Error panel must not wrap the detail

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "error": "invalid_app",
                "detail": "bundle_id: must look like a reverse-DNS identifier",
            },
        )

    assert (
        main(
            [
                "app",
                "add",
                "--yes",
                "--key-id",
                "ABCDEF0123",
                "--id",
                "demo",
                "--bundle-id",
                "com.example.demo",
                "--team-id",
                TEAM,
            ],
            transport=httpx.MockTransport(handler),
        )
        == 1
    )
    err = _plain(capsys.readouterr().err)
    assert "invalid_app" in err
    assert "reverse-DNS" in err
    assert "Usage: relay app add" in err  # errors still teach the command


def test_app_remove_declined_confirmation(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no DELETE after a declined prompt")

    monkeypatch.setattr(sys, "stdin", io.StringIO("n\n"))
    assert main(["app", "remove", "alpha"], transport=httpx.MockTransport(handler)) == 0
    assert "removed" not in capsys.readouterr().out


def test_app_remove_yes(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        assert request.url.path == "/admin/apps/alpha"
        return httpx.Response(200, json={"removed": "alpha", "restartRequired": True})

    assert main(["app", "remove", "alpha", "--yes"], transport=httpx.MockTransport(handler)) == 0
    out = capsys.readouterr().out
    assert "removed alpha" in out
    assert "restart the relay to apply" in out


def test_app_remove_json(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        assert request.url.path == "/admin/apps/alpha"
        return httpx.Response(200, json={"removed": "alpha", "restartRequired": True})

    assert (
        main(
            ["app", "remove", "alpha", "--yes", "--json"],
            transport=httpx.MockTransport(handler),
        )
        == 0
    )
    out = capsys.readouterr().out
    assert json.loads(out) == {"removed": "alpha", "restartRequired": True}
    assert "removed alpha from config.yaml" not in out  # machine-readable stdout


def test_app_remove_unknown_id_errors(monkeypatch, capsys) -> None:
    _auth(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "unknown_app"})

    assert main(["app", "remove", "ghost", "--yes"], transport=httpx.MockTransport(handler)) == 1
    assert "unknown_app" in capsys.readouterr().err
