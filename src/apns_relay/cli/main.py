"""``relay`` — admin CLI for the APNs push relay (PLAN §5).

Typer + rich. Commands hit the internal admin API (``RELAY_API_URL``, default
``http://127.0.0.1:8000``) with ``RELAY_ADMIN_TOKEN``; ``relay doctor`` is
fully offline (config + keys + JWT pre-sign pre-flight) and is what the
container entrypoint runs before serving. ``relay monitor`` renders a live
dashboard; ``relay app add/remove`` edits ``config.yaml`` offline. Output is
counts, statuses and machine codes only — never tokens beyond a freshly
minted ``reissue``. Every error is followed by the command's help.
"""

from __future__ import annotations

import functools
import io
import os
import sys
import time
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import typer
from cryptography.hazmat.primitives import hashes
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.table import Table
from typer import _click as _vendored_click  # typer >= 0.27 vendors click

from .. import attest as attest_mod
from .. import configedit
from ..apns import KeyRegistry
from ..app import DEFAULT_CONFIG, load_issuer_key
from ..attest import AttestError, fetch_attest_root, load_attest_root
from ..config import ConfigError, RelayConfig, load_config
from ..signing import sha256hex
from ..store import Store

DEFAULT_API_URL = "http://127.0.0.1:8000"

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

out = Console(soft_wrap=True)  # line-oriented output: never re-wrap long paths
err = Console(stderr=True, soft_wrap=True)

# Test/injection seam: when set, used instead of the real network.
_TRANSPORT: httpx.BaseTransport | None = None

app = typer.Typer(
    help="Admin CLI for apns-push-relay (internal admin API or offline checks).",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
tenant_app = typer.Typer(help="tenant lifecycle", no_args_is_help=True)
denylist_app = typer.Typer(help="grant jti / destination-token-hash denylist", no_args_is_help=True)
config_app = typer.Typer(help="add/remove apps in config.yaml (offline)", no_args_is_help=True)
app.add_typer(tenant_app, name="tenant")
app.add_typer(denylist_app, name="denylist")
app.add_typer(config_app, name="app")


class CliError(Exception):
    """User-facing CLI failure (bad input, API error, missing env)."""


def _help_text(ctx: typer.Context) -> str:
    """Capture typer's rich help page as a string.

    typer >= 0.27 renders help itself: ``ctx.get_help()`` prints the page to
    stdout and returns ``''``, so redirect stdout and hand the text back —
    error handling prints it to stderr alongside the error message.
    """
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        ctx.get_help()
    return buffer.getvalue()


def _print_help(ctx: typer.Context) -> None:
    err.print(_help_text(ctx), end="", markup=False, highlight=False)


def _guard(fn: Any) -> Any:
    """On error: red error line + the command's help, then exit 1."""

    @functools.wraps(fn)
    def wrapper(ctx: typer.Context, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(ctx, *args, **kwargs)
        except (CliError, ConfigError, OSError) as exc:  # OSError: file writes, ro mounts
            err.print(f"[bold red]error:[/] {exc}")
            _print_help(ctx)
            raise typer.Exit(1) from None
        except httpx.HTTPError as exc:
            err.print(f"[bold red]error:[/] request failed: {exc}")
            _print_help(ctx)
            raise typer.Exit(1) from None

    return wrapper


def _config_path() -> Path:
    return Path(os.environ.get("RELAY_CONFIG", DEFAULT_CONFIG))


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


def _iso(epoch: float | int) -> str:
    return datetime.fromtimestamp(int(epoch), UTC).strftime("%Y-%m-%d %H:%M:%SZ")


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


# -- doctor (offline) ---------------------------------------------------------


def _fetch_attest_roots(
    config: RelayConfig,
    transport: httpx.BaseTransport | None,
    *,
    only_missing: bool,
    ok: Any,
    fail: Any,
) -> int:
    """Download the App Attest root into every configured path.

    With ``only_missing`` (container startup) existing files are left alone —
    the boot never depends on the network. Otherwise each path is
    re-downloaded (``relay fetch-roots`` / ``relay doctor --fetch-roots`` =
    update). Returns the number of failures.
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
            out.print(
                f"note  fetch-root[{environment}]: {escape(str(root_path))} present — skipped"
            )
            continue
        try:
            root = fetch_attest_root(url, root_path, transport=transport)
        except AttestError as exc:
            failures += 1
            fail(f"fetch-root[{environment}]", f"{root_path}: {exc}")
            continue
        ok(f"fetch-root[{environment}]", f"{root_path} ({root.subject.rfc4514_string()})")
    return failures


def _doctor_report(config: RelayConfig, transport: httpx.BaseTransport | None) -> int:
    """Run every offline check; returns the number of failures."""
    failures = 0

    def ok(label: str, detail: str) -> None:
        out.print(f"[green]ok[/green]    {escape(label)}: {escape(detail)}")

    def fail(label: str, detail: str) -> None:
        nonlocal failures
        failures += 1
        out.print(f"[bold red]FAIL[/bold red]  {escape(label)}: {escape(detail)}")

    def warn(label: str, detail: str) -> None:
        out.print(f"[yellow]warn[/yellow]  {escape(label)}: {escape(detail)}")

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
        out.print(
            "note  attest-roots: none configured — enroll/finish fails closed"
            " until App Attest roots are supplied (M4)"
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
    return failures


@app.command()
@_guard
def doctor(
    ctx: typer.Context,
    fetch_roots: bool = typer.Option(
        False, "--fetch-roots", help="re-download the App Attest root(s) first"
    ),
) -> None:
    """Offline pre-flight: config + keys + JWT pre-sign + secrets."""
    del ctx
    config_path = os.environ.get("RELAY_CONFIG", DEFAULT_CONFIG)
    try:
        config = load_config(config_path, admin_token=os.environ.get("RELAY_ADMIN_TOKEN"))
    except ConfigError as exc:
        out.print(f"[bold red]FAIL[/bold red]  config: {exc}")
        out.print("doctor: 1 check failed")
        raise typer.Exit(1) from None
    out.print(f"[green]ok[/green]    config: {len(config.apps)} app(s) from {config_path}")

    failures = 0
    if fetch_roots:

        def ok(label: str, detail: str) -> None:
            out.print(f"[green]ok[/green]    {escape(label)}: {escape(detail)}")

        def fail(label: str, detail: str) -> None:
            out.print(f"[bold red]FAIL[/bold red]  {escape(label)}: {escape(detail)}")

        failures += _fetch_attest_roots(config, _TRANSPORT, only_missing=False, ok=ok, fail=fail)
    failures += _doctor_report(config, _TRANSPORT)

    if failures:
        out.print(f"doctor: {failures} check(s) failed")
        raise typer.Exit(1)
    out.print("doctor: all checks passed")


@app.command()
@_guard
def fetch_roots(
    ctx: typer.Context,
    if_missing: bool = typer.Option(
        False, "--if-missing", help="skip paths that already have a file (container startup)"
    ),
) -> None:
    """Download/update the App Attest root(s) (pinned SHA-256)."""
    del ctx
    config_path = os.environ.get("RELAY_CONFIG", DEFAULT_CONFIG)
    try:
        config = load_config(config_path, admin_token=os.environ.get("RELAY_ADMIN_TOKEN"))
    except ConfigError as exc:
        out.print(f"[bold red]FAIL[/bold red]  config: {exc}")
        raise typer.Exit(1) from None

    def ok(label: str, detail: str) -> None:
        out.print(f"[green]ok[/green]    {escape(label)}: {escape(detail)}")

    def fail(label: str, detail: str) -> None:
        out.print(f"[bold red]FAIL[/bold red]  {escape(label)}: {escape(detail)}")

    if not config.enrollment.attest_root_certs:
        out.print("note  fetch-roots: no attest_root_certs configured — nothing to fetch")
        return
    failures = _fetch_attest_roots(config, _TRANSPORT, only_missing=if_missing, ok=ok, fail=fail)
    if failures:
        raise typer.Exit(1)


# -- status / metrics / logs / monitor ----------------------------------------


def _status_view(data: dict[str, Any]) -> Group:
    head = Table(box=None, pad_edge=False)
    head.add_column("field", style="bold cyan")
    head.add_column("value")
    head.add_row("status", str(data["status"]))
    head.add_row("uptime", f"{data['uptimeSeconds']}s")
    head.add_row("tenants", str(data["tenants"]))
    head.add_row("denylisted", str(data["denylisted"]))

    apps = Table(box=None, pad_edge=False, title="apps")
    apps.add_column("id")
    apps.add_column("state")
    apps.add_column("key")
    apps.add_column("envs")
    apps.add_column("kinds")
    apps.add_column("quota")
    apps.add_column("ttl")
    for entry in data["apps"]:
        quota = entry["quota"]
        ttl = entry["grantTtl"]
        apps.add_row(
            str(entry["id"]),
            "enabled" if entry["enabled"] else "disabled",
            str(entry["keyId"]),
            ", ".join(entry["environments"]),
            ", ".join(entry["kinds"]),
            (
                f"{quota['burst_per_min']}/min burst, {quota['daily']}/day,"
                f" {quota['token_burst_per_min']}/min per token"
            ),
            f"{ttl['min']}..{ttl['max']}s default {ttl['default']}s",
        )

    metrics = Table(box=None, pad_edge=False, title="metrics")
    metrics.add_column("metric")
    metrics.add_column("labels")
    metrics.add_column("count", justify="right")
    for name, labels in sorted(data["metrics"].items()):
        rendered = ", ".join(
            f"{label or 'total'}={count}" for label, count in sorted(labels.items())
        )
        metrics.add_row(name, rendered, "")
    return Group(head, apps, metrics)


@app.command()
@_guard
def status(ctx: typer.Context) -> None:
    """Health, tenants, quota config, metric snapshot."""
    del ctx
    with _api_client(_TRANSPORT) as client:
        data = _call(client, "GET", "/admin/status")
    out.print(_status_view(data))


@app.command()
@_guard
def metrics(ctx: typer.Context) -> None:
    """Prometheus text snapshot (scrape-friendly)."""
    del ctx
    with _api_client(_TRANSPORT) as client:
        response = client.get("/metrics")
    if response.status_code >= 400:
        raise CliError(f"GET /metrics → {response.status_code}")
    out.print(response.text, end="")


@app.command()
@_guard
def logs(
    ctx: typer.Context,
    errors: bool = typer.Option(False, "--errors", help="only 4xx/5xx outcomes"),
    since: str = typer.Option("", "--since", metavar="DURATION", help="e.g. 15m, 2h, 7d"),
) -> None:
    """Redacted request events (codes/latency only)."""
    del ctx
    params: dict[str, Any] = {}
    if since:
        params["since"] = int(time.time()) - _duration_to_seconds(since)
    if errors:
        params["errors"] = "true"
    with _api_client(_TRANSPORT) as client:
        data = _call(client, "GET", "/admin/logs", params=params or None)
    events = data["events"]
    if not events:
        out.print("(no events)")
        return
    for event in events:
        latency = event["latencyMs"]
        out.print(
            f"{_iso(event['ts'])}  {event['status']:<3}  {event['code']:<24}"
            f" {event['path']:<28} {latency}ms"
        )


def _monitor_frame(errors: bool) -> Group:
    params: dict[str, Any] = {"errors": "true"} if errors else None
    with _api_client(_TRANSPORT) as client:
        status_data = _call(client, "GET", "/admin/status")
        logs_data = _call(client, "GET", "/admin/logs", params=params)

    recent = Table(box=None, pad_edge=False, title="recent requests")
    recent.add_column("ts")
    recent.add_column("status", justify="right")
    recent.add_column("code")
    recent.add_column("path")
    recent.add_column("ms", justify="right")
    for event in logs_data["events"][-8:]:
        recent.add_row(
            _iso(event["ts"]),
            str(event["status"]),
            str(event["code"]),
            str(event["path"]),
            str(event["latencyMs"]),
        )
    return Group(_status_view(status_data), recent)


@app.command()
@_guard
def monitor(
    ctx: typer.Context,
    interval: float = typer.Option(5.0, "-i", "--interval", min=0.5, help="refresh seconds"),
    errors: bool = typer.Option(False, "--errors", help="tail error outcomes only"),
    once: bool = typer.Option(False, "--once", help="render one frame and exit (scripting)"),
) -> None:
    """Live dashboard: health, apps, metrics and recent requests."""
    del ctx
    if once:
        out.print(_monitor_frame(errors))
        return
    try:
        with Live(_monitor_frame(errors), console=out, refresh_per_second=4) as live:
            while True:
                time.sleep(interval)
                live.update(_monitor_frame(errors))
    except KeyboardInterrupt:
        raise typer.Exit(0) from None


# -- tenant -------------------------------------------------------------------


@tenant_app.command("list")
@_guard
def tenant_list(
    ctx: typer.Context, app_filter: str = typer.Option("", "--app", help="filter by App id")
) -> None:
    """List registered tenants."""
    del ctx
    with _api_client(_TRANSPORT) as client:
        data = _call(
            client, "GET", "/admin/tenants", params={"app": app_filter} if app_filter else None
        )
    rows = data["tenants"]
    if not rows:
        out.print("(no tenants)")
        return
    table = Table(box=None, pad_edge=False)
    table.add_column("tenant")
    table.add_column("app")
    table.add_column("registered")
    table.add_column("last seen")
    for row in rows:
        table.add_row(row["tenant"], row["app"], _iso(row["registeredAt"]), _iso(row["lastSeen"]))
    out.print(table)


@tenant_app.command("verify")
@_guard
def tenant_verify(
    ctx: typer.Context,
    tenant_id: str = typer.Argument(..., help="tenant id"),
    app_filter: str = typer.Option("", "--app", help="filter by App id"),
) -> None:
    """Check a tenant exists."""
    del ctx
    params: dict[str, Any] = {"tenant": tenant_id}
    if app_filter:
        params["app"] = app_filter
    with _api_client(_TRANSPORT) as client:
        data = _call(client, "GET", "/admin/tenants/verify", params=params)
    out.print(
        f"exists: tenant={data['tenant']} app={data['app']} last seen {_iso(data['lastSeen'])}"
    )


@tenant_app.command("revoke")
@_guard
def tenant_revoke(
    ctx: typer.Context,
    tenant_id: str = typer.Argument(..., help="tenant id"),
    app_filter: str = typer.Option("", "--app", help="restrict to one App id (default: all rows)"),
) -> None:
    """Immediately delete a tenant (kill switch)."""
    del ctx
    with _api_client(_TRANSPORT) as client:
        data = _call(
            client,
            "POST",
            "/admin/tenants/revoke",
            json={"tenant": tenant_id, "app": app_filter or None},
        )
    out.print(f"revoked {data['revoked']} row(s); next request fails with unknown_tenant")


@tenant_app.command("reissue")
@_guard
def tenant_reissue(
    ctx: typer.Context,
    tenant_id: str = typer.Argument(..., help="tenant id"),
    app_filter: str = typer.Option(..., "--app", help="App the token belongs to"),
) -> None:
    """Mint a replacement token."""
    del ctx
    with _api_client(_TRANSPORT) as client:
        data = _call(
            client,
            "POST",
            "/admin/tenants/reissue",
            json={"tenant": tenant_id, "app": app_filter},
        )
    out.print(f"new token for {data['tenant']}/{data['app']}:")
    out.print(data["token"])


# -- denylist -----------------------------------------------------------------


@denylist_app.command("list")
@_guard
def denylist_list(ctx: typer.Context) -> None:
    """List live entries."""
    del ctx
    with _api_client(_TRANSPORT) as client:
        data = _call(client, "GET", "/admin/denylist")
    entries = data["entries"]
    if not entries:
        out.print("(denylist empty)")
        return
    table = Table(box=None, pad_edge=False)
    table.add_column("key")
    table.add_column("expires")
    for entry in entries:
        table.add_row(entry["key"], _iso(entry["expires"]))
    out.print(table)


@denylist_app.command("add")
@_guard
def denylist_add(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="jti or sha256:<hex> token hash"),
    expires: str = typer.Option("24h", "--expires", metavar="DURATION", help="default 24h"),
) -> None:
    """Deny a jti or sha256:<hex> token hash."""
    del ctx
    expires_at = int(time.time()) + _duration_to_seconds(expires)
    with _api_client(_TRANSPORT) as client:
        data = _call(client, "POST", "/admin/denylist", json={"key": key, "expires": expires_at})
    out.print(f"denied {data['key']} until {_iso(data['expires'])}")


# -- app (config.yaml editing, offline) ---------------------------------------


@config_app.command("list")
@_guard
def app_list(ctx: typer.Context) -> None:
    """List apps from config.yaml (offline)."""
    del ctx
    entries = configedit.list_apps(_config_path())
    table = Table(box=None, pad_edge=False)
    for column in ("id", "bundle_id", "team_id", "key_id", "environments"):
        table.add_column(column)
    for entry in entries:
        environments = entry.get("environments", [])
        table.add_row(
            str(entry.get("id", "")),
            str(entry.get("bundle_id", "")),
            str(entry.get("team_id", "")),
            str(entry.get("key_id", "")),
            ", ".join(environments) if isinstance(environments, list) else str(environments),
        )
    out.print(table)


@config_app.command("add")
@_guard
def app_add(
    ctx: typer.Context,
    key_id: str = typer.Option("", "--key-id", help="10-char APNs key id (default: pick)"),
    app_id: str = typer.Option("", "--id", help="config id (default: from bundle id)"),
    bundle_id: str = typer.Option("", "--bundle-id", help="bundle identifier only"),
    team_id: str = typer.Option("", "--team-id", help="10-char Apple Team ID"),
    display_name: str = typer.Option("", "--display-name"),
    attest_environment: str = typer.Option("production", "--attest-environment"),
    environment: list[str] = typer.Option(
        [], "--environment", help="sandbox|production (repeatable; default both)"
    ),
    kind: list[str] = typer.Option([], "--kind", help="alert|background|liveActivity (repeatable)"),
    live_activity: bool = typer.Option(True, "--live-activity/--no-live-activity"),
    yes: bool = typer.Option(False, "--yes", "-y", help="accept defaults, no prompts"),
) -> None:
    """Add an app to config.yaml (picks from keys/ when --key-id is omitted)."""
    del ctx
    config_path = _config_path()
    if yes:
        missing = [
            flag
            for flag, value in (
                ("--bundle-id", bundle_id),
                ("--team-id", team_id),
                ("--key-id", key_id),
            )
            if not value
        ]
        if missing:
            raise CliError(f"--yes requires {', '.join(missing)} (prompts are disabled)")
    if not bundle_id:
        bundle_id = typer.prompt("Bundle id (bundle identifier only, e.g. com.example.myapp)")
    if not team_id:
        team_id = typer.prompt("Apple Team ID (10 chars)")
    if not key_id:
        available = configedit.discover_keys(config_path)
        if not available:
            raise CliError(
                f"no AuthKey_<KEYID>.p8 found in {configedit.keys_dir(config_path)} —"
                " drop the key there first"
            )
        out.print("Available keys:")
        for index, candidate in enumerate(available, start=1):
            out.print(f"  {index}. AuthKey_{candidate}.p8")
        choice = typer.prompt("Key number", type=int)
        if not 1 <= choice <= len(available):
            raise CliError(f"expected a key number 1..{len(available)}")
        key_id = available[choice - 1]
    if not app_id:
        suggestion = bundle_id.rsplit(".", 1)[-1].lower()
        app_id = suggestion if yes else typer.prompt("App id (config name)", default=suggestion)
    if not display_name:
        display_name = app_id
    environments = environment or ["sandbox", "production"]
    kinds = kind or (
        ["alert", "background", "liveActivity"] if live_activity else ["alert", "background"]
    )
    entry: dict[str, Any] = {
        "id": app_id,
        "display_name": display_name,
        "bundle_id": bundle_id,
        "team_id": team_id,
        "key_id": key_id,
        "environments": environments,
        "kinds": kinds,
        "live_activity": live_activity and "liveActivity" in kinds,
        "attest_environment": attest_environment,
        "registration": {"callback_required": False},
        "quota": dict(configedit.DEFAULT_QUOTA),
        "grant_ttl": dict(configedit.DEFAULT_GRANT_TTL),
    }
    out.print(
        f"Adding {app_id}: bundle={bundle_id} team={team_id} key=AuthKey_{key_id}.p8"
        f" envs={','.join(environments)} kinds={','.join(kinds)}"
        f" attest={attest_environment}"
    )
    if not yes and not typer.confirm(f"Write {app_id} to {config_path.name}?"):
        raise typer.Exit(0)
    configedit.add_app(config_path, entry)
    out.print(f"[green]ok[/green]    added {app_id} to {config_path} (backup: config.yaml.bak)")
    out.print("next: relay doctor")


@config_app.command("remove")
@_guard
def app_remove(
    ctx: typer.Context,
    app_id: str = typer.Argument(..., help="app id to remove"),
    yes: bool = typer.Option(False, "--yes", "-y", help="no confirmation prompt"),
) -> None:
    """Remove an app from config.yaml."""
    del ctx
    config_path = _config_path()
    if not yes and not typer.confirm(f"Remove {app_id!r} from {config_path.name}?"):
        raise typer.Exit(0)
    configedit.remove_app(config_path, app_id)
    out.print(f"[green]ok[/green]    removed {app_id} from {config_path} (backup: config.yaml.bak)")


# -- entrypoint ---------------------------------------------------------------


def main(argv: list[str] | None = None, *, transport: httpx.BaseTransport | None = None) -> int:
    """Console-script entry: parse ``argv`` (default: sys.argv) → exit code."""
    global _TRANSPORT
    _TRANSPORT = transport
    command = typer.main.get_command(app)
    try:
        result = command(
            args=list(sys.argv[1:] if argv is None else argv),
            prog_name="relay",
            standalone_mode=False,
        )
    except typer.Abort:
        err.print("[bold red]aborted[/]")
        return 1
    except _vendored_click.exceptions.UsageError as exc:  # bad args / unknown cmd
        if not isinstance(exc, _vendored_click.exceptions.NoArgsIsHelpError):
            # NoArgsIsHelpError already printed the help it wants shown.
            err.print(f"[bold red]error:[/] {exc.format_message()}")
            if exc.ctx is not None:
                _print_help(exc.ctx)
            else:  # group-level errors carry no context — show the root help
                root_ctx = command.make_context("relay", [], resilient_parsing=True)
                _print_help(root_ctx)
        return 2
    # standalone_mode=False: click RETURNS exit codes (help, typer.Exit)
    # instead of raising them; a normal command returns None.
    return int(result) if isinstance(result, int) else 0
