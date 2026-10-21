"""``relay`` — admin CLI for the APNs push relay (PLAN §5).

Typer + rich. Commands hit the internal admin API (``RELAY_API_URL``, default
``http://127.0.0.1:8000``) with ``RELAY_ADMIN_TOKEN``; ``relay doctor``
verifies the running server through the admin API (``--offline`` checks a
machine's own files — the container-entrypoint pre-flight, before anything
listens). ``relay monitor`` renders a live dashboard; ``relay app add/remove``
edits ``config.yaml`` via the admin API. Output is counts, statuses and
machine codes only — never tokens beyond a freshly minted ``reissue``.
Every error is followed by the command's help.
"""

from __future__ import annotations

import functools
import io
import json
import os
import sys
import time
from contextlib import redirect_stdout
from datetime import UTC, datetime
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import typer
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typer import _click as _vendored_click  # typer >= 0.27 vendors click

from ..app import DEFAULT_CONFIG
from ..checks import fetch_attest_roots, run_checks
from ..config import ConfigError, load_config

DEFAULT_API_URL = "http://127.0.0.1:8000"

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

out = Console(soft_wrap=True)  # line-oriented output: never re-wrap long paths
err = Console(stderr=True, soft_wrap=True)


def _section(title: str, renderable: Any, *, border_style: str = "none") -> Panel:
    """A help-style section: rounded panel with a left-aligned legend title
    (``╭─ Options ──────╮``, matching typer's CLI help panels)."""
    return Panel(
        renderable, title=title, title_align="left", box=box.ROUNDED, border_style=border_style
    )


# Test/injection seam: when set, used instead of the real network.
_TRANSPORT: httpx.BaseTransport | None = None

app = typer.Typer(
    help="Admin CLI for the apns-push-relay server.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
tenant_app = typer.Typer(help="Manage registered tenants.", no_args_is_help=True)
denylist_app = typer.Typer(
    help="Manage the grant and destination-token denylist.", no_args_is_help=True
)
config_app = typer.Typer(help="Manage apps in config.yaml.", no_args_is_help=True)
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
            err.print(
                _section("Error", f"[bold red]error:[/] {escape(str(exc))}", border_style="red")
            )
            _print_help(ctx)
            raise typer.Exit(1) from None
        except httpx.HTTPError as exc:
            err.print(
                _section(
                    "Error",
                    f"[bold red]error:[/] request failed: {escape(str(exc))}",
                    border_style="red",
                )
            )
            _print_help(ctx)
            raise typer.Exit(1) from None

    return wrapper


def _config_path() -> Path:
    """$RELAY_CONFIG, else the container default (offline checks only —
    app management goes through the admin API)."""
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
    _warn_cleartext(base_url)
    return httpx.Client(
        base_url=base_url,
        headers={"authorization": f"Bearer {token}"},
        timeout=10.0,
        transport=transport,
    )


def _warn_cleartext(base_url: str) -> None:
    """The admin token rides in the Authorization header — say so before
    sending it over plain HTTP to anything beyond loopback."""
    parsed = urlsplit(base_url)
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "::1", "localhost"):
        err.print(f"[yellow]warning:[/] admin token sent over plain HTTP to {escape(base_url)}")


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


# -- doctor / fetch-roots ------------------------------------------------------


def _doctor_section(rows: list[dict[str, str]]) -> Panel:
    """The doctor checks as a legend-section table."""
    styles = {"ok": "green", "warn": "yellow", "fail": "bold red", "note": "yellow"}
    table = Table(box=box.SIMPLE)
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")
    for row in rows:
        table.add_row(
            escape(row["check"]),
            Text(row["status"], style=styles.get(row["status"], "")),
            escape(row["detail"]),
        )
    return _section("doctor", table)


@app.command()
@_guard
def doctor(
    ctx: typer.Context,
    fetch_roots: bool = typer.Option(
        False, "--fetch-roots", help="re-download the App Attest root(s) first"
    ),
    offline: bool = typer.Option(
        False, "--offline", help="check this machine's files instead of the running server"
    ),
    json_out: bool = typer.Option(False, "--json", help="machine-readable JSON"),
) -> None:
    """Verify the relay is configured correctly before it serves traffic."""
    del ctx
    if offline:
        config_path = _config_path()
        try:
            config = load_config(config_path, admin_token=os.environ.get("RELAY_ADMIN_TOKEN"))
        except ConfigError as exc:
            rows: list[dict[str, str]] = [{"check": "config", "status": "fail", "detail": str(exc)}]
        else:
            rows = run_checks(
                config, config_path=config_path, fetch_roots=fetch_roots, transport=_TRANSPORT
            )
    else:
        with _api_client(_TRANSPORT) as client:
            payload = _call(
                client,
                "GET",
                "/admin/doctor",
                params={"fetch_roots": str(fetch_roots).lower()},
            )
        rows = payload["checks"]
    failures = sum(1 for row in rows if row["status"] == "fail")
    if json_out:
        out.print(
            json.dumps({"failures": failures, "checks": rows}, indent=2, sort_keys=True),
            markup=False,
        )
    else:
        out.print(_doctor_section(rows))
        if failures:
            out.print(f"doctor: {failures} check(s) failed")
        else:
            out.print("doctor: all checks passed")
    if failures:
        raise typer.Exit(1)


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
    config_path = str(_config_path())
    try:
        config = load_config(config_path, admin_token=os.environ.get("RELAY_ADMIN_TOKEN"))
    except ConfigError as exc:
        out.print(f"[bold red]FAIL[/bold red]  config: {exc}")
        raise typer.Exit(1) from None

    def ok(label: str, detail: str) -> None:
        out.print(f"[green]ok[/green]    {escape(label)}: {escape(detail)}")

    def fail(label: str, detail: str) -> None:
        out.print(f"[bold red]FAIL[/bold red]  {escape(label)}: {escape(detail)}")

    def note(label: str, detail: str) -> None:
        out.print(f"note  {escape(label)}: {escape(detail)}")

    if not config.enrollment.attest_root_certs:
        out.print("note  fetch-roots: no attest_root_certs configured — nothing to fetch")
        return
    failures = fetch_attest_roots(
        config, _TRANSPORT, only_missing=if_missing, ok=ok, fail=fail, note=note
    )
    if failures:
        raise typer.Exit(1)


# -- version ------------------------------------------------------------------


@app.command("version")
def version_cmd(
    json_out: bool = typer.Option(False, "--json", help="machine-readable JSON"),
) -> None:
    """Print the relay version."""
    if json_out:
        out.print(
            json.dumps({"version": package_version("apns-push-relay")}, indent=2, sort_keys=True),
            markup=False,
        )
        return
    out.print(_section("version", f"relay {package_version('apns-push-relay')}"))


# -- status / metrics / logs / monitor ----------------------------------------


def _metrics_section(metrics: dict[str, Any]) -> Panel:
    """The metrics block as a legend section (status and ``relay metrics``)."""
    if not metrics:
        return _section("metrics", "(no metrics yet)")
    table = Table(box=box.SIMPLE)
    table.add_column("metric")
    table.add_column("labels")
    table.add_column("count", justify="right")
    for name, labels in sorted(metrics.items()):
        rendered = ", ".join(
            f"{label or 'total'}={count}" for label, count in sorted(labels.items())
        )
        table.add_row(name, rendered, str(sum(labels.values())))
    return _section("metrics", table)


def _status_view(data: dict[str, Any]) -> Group:
    head = Table(box=box.SIMPLE)
    head.add_column("field", style="bold cyan")
    head.add_column("value")
    head.add_row("version", str(data["version"]))
    head.add_row("status", str(data["status"]))
    head.add_row("uptime", f"{data['uptimeSeconds']}s")
    head.add_row("tenants", str(data["tenants"]))
    head.add_row("denylisted", str(data["denylisted"]))

    apps = Table(box=box.SIMPLE)
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

    return Group(
        _section("status", head),
        _section("apps", apps),
        _metrics_section(data["metrics"]),
    )


@app.command()
@_guard
def status(
    ctx: typer.Context,
    json_out: bool = typer.Option(False, "--json", help="machine-readable JSON"),
) -> None:
    """Version, health, tenants, quota config and metric snapshot."""
    del ctx
    with _api_client(_TRANSPORT) as client:
        data = _call(client, "GET", "/admin/status")
    if json_out:
        out.print(json.dumps(data, indent=2, sort_keys=True), markup=False)
        return
    out.print(_status_view(data))


@app.command()
@_guard
def metrics(
    ctx: typer.Context,
    json_out: bool = typer.Option(False, "--json", help="machine-readable JSON"),
    prom: bool = typer.Option(False, "--prom", help="raw Prometheus text (GET /metrics)"),
) -> None:
    """Metric snapshot."""
    del ctx
    if prom:
        with _api_client(_TRANSPORT) as client:
            response = client.get("/metrics")
        if response.status_code >= 400:
            raise CliError(f"GET /metrics → {response.status_code}")
        out.print(response.text, end="")
        return
    with _api_client(_TRANSPORT) as client:
        data = _call(client, "GET", "/admin/status")
    if json_out:
        out.print(json.dumps(data["metrics"], indent=2, sort_keys=True), markup=False)
        return
    out.print(_metrics_section(data["metrics"]))


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

    recent = Table(box=box.SIMPLE)
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
    return Group(_status_view(status_data), _section("recent requests", recent))


@app.command()
@_guard
def monitor(
    ctx: typer.Context,
    interval: float = typer.Option(5.0, "-i", "--interval", min=0.5, help="refresh seconds"),
    errors: bool = typer.Option(False, "--errors", help="tail error outcomes only"),
    once: bool = typer.Option(False, "--once", help="render one frame and exit (scripting)"),
) -> None:
    """Live dashboard: version, health, apps, metrics and recent requests."""
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
    ctx: typer.Context, app_filter: str = typer.Option("", "--app", help="filter by app id")
) -> None:
    """List registered tenants."""
    del ctx
    with _api_client(_TRANSPORT) as client:
        data = _call(
            client, "GET", "/admin/tenants", params={"app": app_filter} if app_filter else None
        )
    rows = data["tenants"]
    if not rows:
        out.print(_section("tenants", "(no tenants)"))
        return
    table = Table(box=box.SIMPLE)
    table.add_column("tenant")
    table.add_column("app")
    table.add_column("registered")
    table.add_column("last seen")
    for row in rows:
        table.add_row(row["tenant"], row["app"], _iso(row["registeredAt"]), _iso(row["lastSeen"]))
    out.print(_section("tenants", table))


@tenant_app.command("verify")
@_guard
def tenant_verify(
    ctx: typer.Context,
    tenant_id: str = typer.Argument(..., help="tenant id"),
    app_filter: str = typer.Option("", "--app", help="filter by app id"),
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
    app_filter: str = typer.Option("", "--app", help="restrict to one app id (default: all rows)"),
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
    app_filter: str = typer.Option(..., "--app", help="app id the token belongs to"),
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
        out.print(_section("denylist", "(denylist empty)"))
        return
    table = Table(box=box.SIMPLE)
    table.add_column("key")
    table.add_column("expires")
    for entry in entries:
        table.add_row(entry["key"], _iso(entry["expires"]))
    out.print(_section("denylist", table))


@denylist_app.command("add")
@_guard
def denylist_add(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="jti or sha256:<hex> token hash"),
    expires: str = typer.Option(
        "24h", "--expires", metavar="DURATION", help="denial duration (default: 24h)"
    ),
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
def app_list(
    ctx: typer.Context,
    json_out: bool = typer.Option(False, "--json", help="machine-readable JSON"),
) -> None:
    """List apps from config.yaml."""
    del ctx
    with _api_client(_TRANSPORT) as client:
        data = _call(client, "GET", "/admin/apps")
    if json_out:
        out.print(json.dumps(data, indent=2, sort_keys=True), markup=False)
        return
    table = Table(box=box.SIMPLE)
    for column in ("id", "bundle_id", "team_id", "key_id", "environments"):
        table.add_column(column)
    for entry in data["apps"]:
        environments = entry.get("environments", [])
        table.add_row(
            str(entry.get("id", "")),
            str(entry.get("bundle_id", "")),
            str(entry.get("team_id", "")),
            str(entry.get("key_id", "")),
            ", ".join(environments) if isinstance(environments, list) else str(environments),
        )
    out.print(_section("apps", table))


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
    json_out: bool = typer.Option(False, "--json", help="machine-readable JSON"),
) -> None:
    """Add an app to config.yaml (picks a key when --key-id is omitted)."""
    del ctx
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
        with _api_client(_TRANSPORT) as client:
            available = _call(client, "GET", "/admin/keys")["keys"]
        if not available:
            raise CliError(
                "no AuthKey_<KEYID>.p8 found beside the server's config — drop the key there first"
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
    body: dict[str, Any] = {
        "id": app_id,
        "display_name": display_name,
        "bundle_id": bundle_id,
        "team_id": team_id,
        "key_id": key_id,
        "environments": environments,
        "kinds": kinds,
        "live_activity": live_activity and "liveActivity" in kinds,
        "attest_environment": attest_environment,
    }
    if not json_out:
        out.print(f"Adding {app_id}:")
        out.print(f"  bundle={bundle_id}")
        out.print(f"  team={team_id}")
        out.print(f"  key=AuthKey_{key_id}.p8")
        out.print(f"  envs={','.join(environments)}")
        out.print(f"  kinds={','.join(kinds)}")
        out.print(f"  attest={attest_environment}")
    if not yes and not typer.confirm(f"Add {app_id} to config.yaml?"):
        raise typer.Exit(0)
    with _api_client(_TRANSPORT) as client:
        created = _call(client, "POST", "/admin/apps", json=body)
    if json_out:
        out.print(json.dumps(created, indent=2, sort_keys=True), markup=False)
        return
    out.print(f"[green]ok[/green]    added {app_id} to config.yaml (backup: config.yaml.bak)")
    out.print("note  restart the relay to apply (running state unchanged until then)")


@config_app.command("remove")
@_guard
def app_remove(
    ctx: typer.Context,
    app_id: str = typer.Argument(..., help="app id to remove"),
    yes: bool = typer.Option(False, "--yes", "-y", help="no confirmation prompt"),
    json_out: bool = typer.Option(False, "--json", help="machine-readable JSON"),
) -> None:
    """Remove an app from config.yaml."""
    del ctx
    if not yes and not typer.confirm(f"Remove {app_id!r} from config.yaml?"):
        raise typer.Exit(0)
    with _api_client(_TRANSPORT) as client:
        data = _call(client, "DELETE", f"/admin/apps/{app_id}")
    if json_out:
        out.print(json.dumps(data, indent=2, sort_keys=True), markup=False)
        return
    out.print(f"[green]ok[/green]    removed {app_id} from config.yaml (backup: config.yaml.bak)")
    out.print("note  restart the relay to apply (running state unchanged until then)")


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
