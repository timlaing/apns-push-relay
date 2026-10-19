"""Configuration schema and loader for the APNs push relay.

Every hostname, key, quota and policy in the relay comes from ``config.yaml``.
No hostname is hardcoded anywhere in the codebase — self-hosters substitute
their own. See ``deploy/config.yaml.example``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
KEY_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,254}$")

KINDS = ("alert", "background", "liveActivity")
ENVIRONMENTS = ("sandbox", "production")
ATTEST_ENVIRONMENTS = ("development", "production")

# Spec §2.5: operator sets bounds; tenants pick a TTL within them.
GRANT_TTL_MIN_BOUND = 900
GRANT_TTL_MAX_BOUND = 86400


class ConfigError(ValueError):
    """Raised for any invalid or unsafe configuration."""


def _expect(mapping: dict[str, Any], key: str, kind: type, ctx: str) -> Any:
    if key not in mapping:
        raise ConfigError(f"{ctx}: missing required key '{key}'")
    value = mapping[key]
    if kind is float:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ConfigError(f"{ctx}.{key}: expected number")
        return float(value)
    if not isinstance(value, kind):
        raise ConfigError(f"{ctx}.{key}: expected {kind.__name__}")
    return value


def _int_range(mapping: dict[str, Any], key: str, low: int, high: int, ctx: str) -> int:
    value = _expect(mapping, key, int, ctx)
    if not low <= value <= high:
        raise ConfigError(f"{ctx}.{key}: {value} outside {low}..{high}")
    return value


def _str_list(
    mapping: dict[str, Any], key: str, allowed: tuple[str, ...], ctx: str
) -> tuple[str, ...]:
    value = _expect(mapping, key, list, ctx)
    if not value:
        raise ConfigError(f"{ctx}.{key}: must not be empty")
    for item in value:
        if not isinstance(item, str) or item not in allowed:
            raise ConfigError(f"{ctx}.{key}: invalid entry {item!r}")
    if len(set(value)) != len(value):
        raise ConfigError(f"{ctx}.{key}: duplicate entries")
    return tuple(value)


@dataclass(frozen=True)
class ServerConfig:
    api_domain: str
    docs_domain: str
    public_scheme: str = "https"

    def validate(self) -> None:
        for name, value in (("api_domain", self.api_domain), ("docs_domain", self.docs_domain)):
            if not value or " " in value or "/" in value:
                raise ConfigError(f"server.{name}: expected bare hostname, got {value!r}")
        if self.public_scheme not in ("https",):
            raise ConfigError("server.public_scheme: only 'https' is supported")


@dataclass(frozen=True)
class GrantTtlConfig:
    min: int
    max: int
    default: int

    def clamp(self, requested: int | None) -> int:
        """Spec §2.5: omitted → default; out of bounds → clamp, never error."""
        if requested is None:
            return self.default
        return max(self.min, min(self.max, requested))


@dataclass(frozen=True)
class CapsConfig:
    title: int = 64
    subtitle: int = 64
    body: int = 200
    sealed: int = 1024
    category: int = 32
    thread: int = 64
    background: int = 512


@dataclass(frozen=True)
class QuotaConfig:
    burst_per_min: int
    daily: int
    token_burst_per_min: int


@dataclass(frozen=True)
class RegistrationConfig:
    callback_required: bool = False


@dataclass(frozen=True)
class AppKeyConfig:
    """One APNs app: an app-specific ``.p8`` key and its policy.

    ``team_id`` is required per key (multi-team support). ``key_id`` may be
    omitted and is derived from the ``AuthKey_<ID>.p8`` filename.
    """

    id: str
    display_name: str
    bundle_id: str
    team_id: str
    key_file: Path
    key_id: str
    environments: tuple[str, ...]
    kinds: tuple[str, ...]
    live_activity: bool
    attest_environment: str
    registration: RegistrationConfig
    caps: CapsConfig
    quota: QuotaConfig
    grant_ttl: GrantTtlConfig
    enabled: bool = True

    @property
    def topic(self) -> str:
        return self.bundle_id

    @property
    def live_activity_topic(self) -> str:
        return f"{self.bundle_id}.push-type.liveactivity"


def _derive_key_id(key_file: Path) -> str:
    """Key ID is not inside the ``.p8``; Apple encodes it in the filename."""
    name = key_file.name
    match = re.match(r"^AuthKey_([A-Z0-9]{10})\.p8$", name)
    if match:
        return match.group(1)
    raise ConfigError(
        f"key_file {name!r}: filename must be AuthKey_<KEYID>.p8 or set key_id explicitly"
    )


def _parse_app(raw: dict[str, Any], base: Path) -> AppKeyConfig:
    if not isinstance(raw, dict):
        raise ConfigError("apps[?]: expected mapping")
    ctx = f"apps[{raw.get('id', '?')}]"

    app_id = _expect(raw, "id", str, ctx)
    if not APP_ID_RE.match(app_id):
        raise ConfigError(f"{ctx}.id: invalid app id {app_id!r}")

    bundle_id = _expect(raw, "bundle_id", str, ctx)
    if not BUNDLE_ID_RE.match(bundle_id):
        raise ConfigError(f"{ctx}.bundle_id: invalid bundle id {bundle_id!r}")

    team_id = _expect(raw, "team_id", str, ctx)
    if not TEAM_ID_RE.match(team_id):
        raise ConfigError(f"{ctx}.team_id: expected 10 alphanumeric chars, got {team_id!r}")

    key_file_raw = _expect(raw, "key_file", str, ctx)
    key_file = Path(key_file_raw)
    if not key_file.is_absolute():
        key_file = base / key_file

    key_id_raw = raw.get("key_id")
    if key_id_raw is None:
        key_id = _derive_key_id(key_file)
    elif isinstance(key_id_raw, str) and KEY_ID_RE.match(key_id_raw):
        key_id = key_id_raw
        # Boot validation: explicit key_id must agree with an AuthKey_ filename
        # when the filename encodes one (PLAN §4 key rotation).
        match = re.match(r"^AuthKey_([A-Z0-9]{10})\.p8$", key_file.name)
        if match and match.group(1) != key_id:
            raise ConfigError(f"{ctx}: key_id {key_id} does not match filename {key_file.name!r}")
    else:
        raise ConfigError(f"{ctx}.key_id: expected 10 alphanumeric chars, got {key_id_raw!r}")

    display_name = raw.get("display_name", app_id)
    if not isinstance(display_name, str) or not (1 <= len(display_name) <= 64):
        raise ConfigError(f"{ctx}.display_name: expected string of 1..64 chars")

    environments = _str_list(raw, "environments", ENVIRONMENTS, ctx)
    kinds = _str_list(raw, "kinds", KINDS, ctx)

    live_activity = _expect(raw, "live_activity", bool, ctx)
    if live_activity and "liveActivity" not in kinds:
        raise ConfigError(f"{ctx}: live_activity=true requires 'liveActivity' in kinds")

    attest_environment = _expect(raw, "attest_environment", str, ctx)
    if attest_environment not in ATTEST_ENVIRONMENTS:
        raise ConfigError(f"{ctx}.attest_environment: expected one of {ATTEST_ENVIRONMENTS}")

    reg_raw = raw.get("registration", {})
    if not isinstance(reg_raw, dict):
        raise ConfigError(f"{ctx}.registration: expected mapping")
    unknown = set(reg_raw) - {"callback_required"}
    if unknown:
        raise ConfigError(f"{ctx}.registration: unknown keys {sorted(unknown)}")
    callback_required = reg_raw.get("callback_required", False)
    if not isinstance(callback_required, bool):
        raise ConfigError(f"{ctx}.registration.callback_required: expected bool")
    registration = RegistrationConfig(callback_required=callback_required)

    caps_raw = raw.get("caps", {})
    if not isinstance(caps_raw, dict):
        raise ConfigError(f"{ctx}.caps: expected mapping")
    unknown = set(caps_raw) - {f.name for f in CapsConfig.__dataclass_fields__.values()}
    if unknown:
        raise ConfigError(f"{ctx}.caps: unknown keys {sorted(unknown)}")
    caps = CapsConfig(**{k: _int_range(caps_raw, k, 1, 4096, f"{ctx}.caps") for k in caps_raw})

    quota_raw = _expect(raw, "quota", dict, ctx)
    quota = QuotaConfig(
        burst_per_min=_int_range(quota_raw, "burst_per_min", 1, 10000, f"{ctx}.quota"),
        daily=_int_range(quota_raw, "daily", 1, 10_000_000, f"{ctx}.quota"),
        token_burst_per_min=_int_range(quota_raw, "token_burst_per_min", 1, 10000, f"{ctx}.quota"),
    )

    ttl_raw = raw.get("grant_ttl", {})
    if not isinstance(ttl_raw, dict):
        raise ConfigError(f"{ctx}.grant_ttl: expected mapping")
    unknown = set(ttl_raw) - {"min", "max", "default"}
    if unknown:
        raise ConfigError(f"{ctx}.grant_ttl: unknown keys {sorted(unknown)}")
    lo = (
        _int_range(ttl_raw, "min", GRANT_TTL_MIN_BOUND, GRANT_TTL_MAX_BOUND, f"{ctx}.grant_ttl")
        if "min" in ttl_raw
        else GRANT_TTL_MIN_BOUND
    )
    hi = (
        _int_range(ttl_raw, "max", GRANT_TTL_MIN_BOUND, GRANT_TTL_MAX_BOUND, f"{ctx}.grant_ttl")
        if "max" in ttl_raw
        else GRANT_TTL_MAX_BOUND
    )
    if lo > hi:
        raise ConfigError(f"{ctx}.grant_ttl: min {lo} > max {hi}")
    default = (
        _int_range(ttl_raw, "default", lo, hi, f"{ctx}.grant_ttl")
        if "default" in ttl_raw
        else min(hi, 21600)
    )
    grant_ttl = GrantTtlConfig(min=lo, max=hi, default=default)

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError(f"{ctx}.enabled: expected bool")

    return AppKeyConfig(
        id=app_id,
        display_name=display_name,
        bundle_id=bundle_id,
        team_id=team_id,
        key_file=key_file,
        key_id=key_id,
        environments=environments,
        kinds=kinds,
        live_activity=live_activity,
        attest_environment=attest_environment,
        registration=registration,
        caps=caps,
        quota=quota,
        grant_ttl=grant_ttl,
        enabled=enabled,
    )


@dataclass(frozen=True)
class EnrollmentConfig:
    grant_issuer_key: Path
    challenge_ttl: int = 600
    # Environment-specific App Attestation root certs supplied by the operator
    # (development vs production attestations chain to different roots). Paths
    # resolve relative to the config file. Attestation verification fails closed
    # (enroll/finish → attestation_unavailable) when the root for the App's
    # attest_environment is absent — roots are never hardcoded.
    attest_root_certs: dict[str, Path] = field(default_factory=dict)

    def root_for(self, environment: str) -> Path | None:
        return self.attest_root_certs.get(environment)


@dataclass(frozen=True)
class RelayConfig:
    server: ServerConfig
    enrollment: EnrollmentConfig
    apps: tuple[AppKeyConfig, ...]
    database: Path
    admin_token: str = field(repr=False)

    def app(self, app_id: str) -> AppKeyConfig:
        for app in self.apps:
            if app.id == app_id:
                return app
        raise KeyError(app_id)

    @property
    def enabled_apps(self) -> tuple[AppKeyConfig, ...]:
        return tuple(a for a in self.apps if a.enabled)


_TOP_KEYS = {"server", "enrollment", "apps", "storage"}


def load_config(path: str | Path, *, admin_token: str | None = None) -> RelayConfig:
    """Load and validate ``config.yaml``.

    ``admin_token`` comes from the environment (``RELAY_ADMIN_TOKEN``), never
    from the YAML file — keeping secrets out of the config tree.
    """
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text())
    except FileNotFoundError:
        raise ConfigError(f"config not found: {path}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from None
    if not isinstance(raw, dict):
        raise ConfigError("config: top level must be a mapping")

    unknown = set(raw) - _TOP_KEYS
    if unknown:
        raise ConfigError(f"config: unknown top-level keys {sorted(unknown)}")

    server_raw = _expect(raw, "server", dict, "config")
    server = ServerConfig(
        api_domain=_expect(server_raw, "api_domain", str, "server"),
        docs_domain=_expect(server_raw, "docs_domain", str, "server"),
        public_scheme=server_raw.get("public_scheme", "https"),
    )
    server.validate()

    enroll_raw = _expect(raw, "enrollment", dict, "config")
    issuer = Path(_expect(enroll_raw, "grant_issuer_key", str, "enrollment"))
    if not issuer.is_absolute():
        issuer = path.parent / issuer
    unknown = set(enroll_raw) - {"grant_issuer_key", "challenge_ttl", "attest_root_certs"}
    if unknown:
        raise ConfigError(f"enrollment: unknown keys {sorted(unknown)}")
    challenge_ttl = (
        _int_range(enroll_raw, "challenge_ttl", 60, 3600, "enrollment")
        if "challenge_ttl" in enroll_raw
        else 600
    )
    roots_raw = enroll_raw.get("attest_root_certs", {})
    if not isinstance(roots_raw, dict):
        raise ConfigError("enrollment.attest_root_certs: expected mapping")
    roots: dict[str, Path] = {}
    for env_name, cert_path in roots_raw.items():
        if env_name not in ATTEST_ENVIRONMENTS:
            raise ConfigError(f"enrollment.attest_root_certs: unexpected environment {env_name!r}")
        if not isinstance(cert_path, str):
            raise ConfigError(f"enrollment.attest_root_certs.{env_name}: expected path")
        resolved = Path(cert_path)
        if not resolved.is_absolute():
            resolved = path.parent / resolved
        roots[env_name] = resolved
    enrollment = EnrollmentConfig(
        grant_issuer_key=issuer, challenge_ttl=challenge_ttl, attest_root_certs=roots
    )

    storage_raw = raw.get("storage", {})
    if not isinstance(storage_raw, dict):
        raise ConfigError("storage: expected mapping")
    unknown = set(storage_raw) - {"database"}
    if unknown:
        raise ConfigError(f"storage: unknown keys {sorted(unknown)}")
    database = Path(storage_raw.get("database", "/var/lib/apns-relay/relay.db"))
    if not database.is_absolute():
        database = path.parent / database

    apps_raw = _expect(raw, "apps", list, "config")
    if not apps_raw:
        raise ConfigError("config: at least one app is required")
    apps = tuple(_parse_app(item, path.parent) for item in apps_raw)
    ids = [a.id for a in apps]
    if len(set(ids)) != len(ids):
        raise ConfigError(f"config: duplicate app ids {sorted(ids)}")

    if admin_token is None:
        raise ConfigError("admin token not provided (set RELAY_ADMIN_TOKEN)")
    if len(admin_token) < 32:
        raise ConfigError("admin token must be at least 32 characters")

    return RelayConfig(
        server=server,
        enrollment=enrollment,
        apps=apps,
        database=database,
        admin_token=admin_token,
    )
