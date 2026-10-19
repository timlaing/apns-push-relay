"""``relay`` — admin CLI for the APNs push relay (PLAN §5).

Commands hit the internal admin API (``RELAY_API_URL``, default
``http://127.0.0.1:8000``) with ``RELAY_ADMIN_TOKEN``; ``relay doctor`` is
fully offline (config + keys + JWT pre-sign pre-flight) and is what the
container entrypoint runs before serving. Output is counts, statuses and
machine codes only — never tokens beyond a freshly minted ``reissue``.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from ..apns import KeyRegistry
from ..app import DEFAULT_CONFIG, load_issuer_key
from ..attest import load_attest_root
from ..config import ConfigError, load_config
from ..signing import sha256hex
from ..store import Store

DEFAULT_API_URL = "http://127.0.0.1:8000"

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class CliError(Exception):
    """User-facing CLI failure (bad input, API error, missing env)."""


def _duration_to_seconds(value: str) -> int:
    """Parse ``90`` / ``15m`` / ``1h`` / ``7d`` into seconds."""
    unit = value[-1]
    if unit in _DURATION_UNITS:
        number = value[:-1]
        multiplier = _DURATION_UNITS[unit]
    else:
        number = value
        multiplier = 1
    try:
        amount = int(number)
    except ValueError:
        raise CliError(f"bad duration {value!r} (use 90, 15m, 1h, 7d)") from None
    return amount * multiplier


def _api_client(transport: httpx.BaseTransport | None) -> httpx.Client:
    token = os.environ.get("RELAY_ADMIN_TOKEN", "")
    if not token:
        raise CliError("RELAY_ADMIN_TOKEN is not set")
    base_url = os.environ.get("RELAY_API_URL", DEFAULT_API_URL)
    return httpx.Client(
        base_url=base_url,
        headers={"authorization": f"Bearer {token}"},
        timeout=10.0,
        transport=transport,
    )


def _call(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    json: Any = None,
    params: dict[str, Any] | None = None,
) -> Any:
    response = client.request(method, path, json=json, params=params)
    if response.status_code >= 400:
        code, detail = "error", ""
        try:
            body = response.json()
            if isinstance(body, dict):
                code = str(body.get("error", code))
                detail = str(body.get("detail") or "")
        except ValueError:
            pass
        suffix = f" {detail}" if detail else ""
        raise CliError(f"{method} {path} → {response.status_code} {code}{suffix}")
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return response.text


def _iso(epoch: float | int) -> str:
    return datetime.fromtimestamp(int(epoch), UTC).strftime("%Y-%m-%d %H:%M:%SZ")


# -- doctor (offline) ---------------------------------------------------------


def cmd_doctor(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    del args, transport  # offline: no API client
    failures = 0

    def ok(label: str, detail: str) -> None:
        print(f"ok    {label}: {detail}")

    def fail(label: str, detail: str) -> None:
        nonlocal failures
        failures += 1
        print(f"FAIL  {label}: {detail}")

    config_path = os.environ.get("RELAY_CONFIG", DEFAULT_CONFIG)
    try:
        config = load_config(config_path, admin_token=os.environ.get("RELAY_ADMIN_TOKEN"))
    except ConfigError as exc:
        fail("config", str(exc))
        print("doctor: 1 check failed")
        return 1
    ok("config", f"{len(config.apps)} app(s) from {config_path}")

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
        print(
            "note  attest-roots: none configured — enroll/finish fails closed"
            " until App Attest roots are supplied (M4)"
        )
    for environment, root_path in sorted(config.enrollment.attest_root_certs.items()):
        try:
            root = load_attest_root(root_path)
            ok(f"attest-root[{environment}]", f"{root_path} ({root.subject.rfc4514_string()})")
        except (OSError, ValueError) as exc:
            fail(f"attest-root[{environment}]", str(exc))

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

    if failures:
        print(f"doctor: {failures} check(s) failed")
        return 1
    print("doctor: all checks passed")
    return 0


# -- status / metrics / logs ---------------------------------------------------


def cmd_status(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    del args
    with _api_client(transport) as client:
        data = _call(client, "GET", "/admin/status")
    print(f"status:  {data['status']}")
    print(f"uptime:  {data['uptimeSeconds']}s")
    print(f"tenants: {data['tenants']}   denylisted: {data['denylisted']}")
    print("apps:")
    for app in data["apps"]:
        flag = "enabled" if app["enabled"] else "disabled"
        quota = app["quota"]
        ttl = app["grantTtl"]
        print(
            f"  {app['id']} ({flag}, key {app['keyId']},"
            f" envs: {', '.join(app['environments'])}, kinds: {', '.join(app['kinds'])})"
        )
        print(
            f"    quota: {quota['burst_per_min']}/min burst,"
            f" {quota['daily']}/day, {quota['token_burst_per_min']}/min per token;"
            f" grant ttl {ttl['min']}..{ttl['max']}s default {ttl['default']}s"
        )
    print("metrics:")
    for name, labels in sorted(data["metrics"].items()):
        rendered = ", ".join(
            f"{label or 'total'}={count}" for label, count in sorted(labels.items())
        )
        print(f"  {name}: {rendered}")
    return 0


def cmd_metrics(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    del args
    with _api_client(transport) as client:
        response = client.get("/metrics")
    if response.status_code >= 400:
        raise CliError(f"GET /metrics → {response.status_code}")
    print(response.text, end="")
    return 0


def cmd_logs(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    params: dict[str, Any] = {}
    if args.since:
        params["since"] = int(time.time()) - _duration_to_seconds(args.since)
    if args.errors:
        params["errors"] = "true"
    with _api_client(transport) as client:
        data = _call(client, "GET", "/admin/logs", params=params or None)
    events = data["events"]
    if not events:
        print("(no events)")
        return 0
    for event in events:
        latency = event["latencyMs"]
        print(
            f"{_iso(event['ts'])}  {event['status']:<3}  {event['code']:<24}"
            f" {event['path']:<28} {latency}ms"
        )
    return 0


# -- tenant -------------------------------------------------------------------


def cmd_tenant_list(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    with _api_client(transport) as client:
        data = _call(
            client, "GET", "/admin/tenants", params={"app": args.app} if args.app else None
        )
    rows = data["tenants"]
    if not rows:
        print("(no tenants)")
        return 0
    for row in rows:
        print(
            f"{row['tenant']:<32} {row['app']:<20} registered {_iso(row['registeredAt'])}"
            f"  last seen {_iso(row['lastSeen'])}"
        )
    return 0


def cmd_tenant_verify(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    params: dict[str, Any] = {"tenant": args.id}
    if args.app:
        params["app"] = args.app
    with _api_client(transport) as client:
        data = _call(client, "GET", "/admin/tenants/verify", params=params)
    print(f"exists: tenant={data['tenant']} app={data['app']} last seen {_iso(data['lastSeen'])}")
    return 0


def cmd_tenant_revoke(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    with _api_client(transport) as client:
        data = _call(
            client,
            "POST",
            "/admin/tenants/revoke",
            json={"tenant": args.id, "app": args.app},
        )
    print(f"revoked {data['revoked']} row(s); next request fails with unknown_tenant")
    return 0


def cmd_tenant_reissue(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    with _api_client(transport) as client:
        data = _call(
            client,
            "POST",
            "/admin/tenants/reissue",
            json={"tenant": args.id, "app": args.app},
        )
    print(f"new token for {data['tenant']}/{data['app']}:")
    print(data["token"])
    return 0


# -- denylist -----------------------------------------------------------------


def cmd_denylist_list(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    del args
    with _api_client(transport) as client:
        data = _call(client, "GET", "/admin/denylist")
    entries = data["entries"]
    if not entries:
        print("(denylist empty)")
        return 0
    for entry in entries:
        print(f"{entry['key']:<72} expires {_iso(entry['expires'])}")
    return 0


def cmd_denylist_add(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    expires = int(time.time()) + _duration_to_seconds(args.expires)
    with _api_client(transport) as client:
        data = _call(client, "POST", "/admin/denylist", json={"key": args.key, "expires": expires})
    print(f"denied {data['key']} until {_iso(data['expires'])}")
    return 0


# -- parser -------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="relay",
        description="Admin CLI for apns-push-relay (internal admin API or offline checks).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="offline: config + keys + JWT pre-sign + secrets").set_defaults(
        func=cmd_doctor
    )
    sub.add_parser("status", help="health, tenants, quota config, metric snapshot").set_defaults(
        func=cmd_status
    )
    sub.add_parser("metrics", help="Prometheus text snapshot (scrape-friendly)").set_defaults(
        func=cmd_metrics
    )

    logs = sub.add_parser("logs", help="redacted request events (codes/latency only)")
    logs.add_argument("--errors", action="store_true", help="only 4xx/5xx outcomes")
    logs.add_argument(
        "--since", metavar="DURATION", help="e.g. 15m, 1h, 7d (default: all buffered)"
    )
    logs.set_defaults(func=cmd_logs)

    tenant = sub.add_parser("tenant", help="tenant lifecycle")
    tenant_sub = tenant.add_subparsers(dest="tenant_command", required=True)
    t_list = tenant_sub.add_parser("list", help="list registered tenants")
    t_list.add_argument("--app", help="filter by App id")
    t_list.set_defaults(func=cmd_tenant_list)
    t_verify = tenant_sub.add_parser("verify", help="check a tenant exists")
    t_verify.add_argument("id")
    t_verify.add_argument("--app", help="filter by App id")
    t_verify.set_defaults(func=cmd_tenant_verify)
    t_revoke = tenant_sub.add_parser("revoke", help="immediately delete a tenant (kill switch)")
    t_revoke.add_argument("id")
    t_revoke.add_argument("--app", help="restrict to one App (default: all rows)")
    t_revoke.set_defaults(func=cmd_tenant_revoke)
    t_reissue = tenant_sub.add_parser("reissue", help="mint a replacement token")
    t_reissue.add_argument("id")
    t_reissue.add_argument("--app", required=True, help="App the token belongs to")
    t_reissue.set_defaults(func=cmd_tenant_reissue)

    deny = sub.add_parser("denylist", help="grant jti / destination-token-hash denylist")
    deny_sub = deny.add_subparsers(dest="denylist_command", required=True)
    d_list = deny_sub.add_parser("list", help="list live entries")
    d_list.set_defaults(func=cmd_denylist_list)
    d_add = deny_sub.add_parser("add", help="deny a jti or sha256:<hex> token hash")
    d_add.add_argument("key")
    d_add.add_argument("--expires", default="24h", metavar="DURATION", help="default 24h")
    d_add.set_defaults(func=cmd_denylist_add)
    return parser


def main(argv: list[str] | None = None, *, transport: httpx.BaseTransport | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.func(args, transport))
    except (CliError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"error: request failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
