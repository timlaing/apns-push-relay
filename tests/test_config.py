"""Config loader: exhaustive validation of every ConfigError path and defaults."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from apns_relay.attest import APPLE_ATTEST_ROOT_URL
from apns_relay.config import (
    ConfigError,
    GrantTtlConfig,
    _expect,
    load_config,
)
from tests.conftest import ADMIN_TOKEN, KEY_ID, TEAM_ID, load_test_config

Mutator = Callable[[dict[str, Any]], None]


# -- helpers -------------------------------------------------------------------


def valid_app() -> dict[str, Any]:
    return {
        "id": "test-app",
        "display_name": "Test App",
        "bundle_id": "com.example.testapp",
        "team_id": TEAM_ID,
        "key_id": KEY_ID,
        "environments": ["sandbox", "production"],
        "kinds": ["alert", "background", "liveActivity"],
        "live_activity": True,
        "attest_environment": "production",
        "registration": {"callback_required": False},
        "caps": {"title": 64},
        "quota": {"burst_per_min": 5, "daily": 10, "token_burst_per_min": 3},
        "grant_ttl": {"min": 900, "max": 86400, "default": 3600},
    }


def valid_config() -> dict[str, Any]:
    return {
        "server": {},
        "enrollment": {"grant_issuer_key": "keys/issuer.pem", "challenge_ttl": 600},
        "storage": {"database": "relay.db"},
        "apps": [valid_app()],
    }


def dump(tmp_path: Path, raw: Any) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(raw if isinstance(raw, str) else yaml.safe_dump(raw))
    return path


def load(tmp_path: Path, raw: Any, *, admin_token: str | None = ADMIN_TOKEN) -> Any:
    return load_config(dump(tmp_path, raw), admin_token=admin_token)


def drop(section: str | None, key: str) -> Mutator:
    def mutate(raw: dict[str, Any]) -> None:
        del (raw[section] if section else raw)[key]

    return mutate


def set_in(section: str | None, key: str, value: Any) -> Mutator:
    def mutate(raw: dict[str, Any]) -> None:
        (raw[section] if section else raw)[key] = value

    return mutate


def set_app(key: str, value: Any) -> Mutator:
    def mutate(raw: dict[str, Any]) -> None:
        raw["apps"][0][key] = value

    return mutate


def set_app_in(section: str, key: str, value: Any) -> Mutator:
    def mutate(raw: dict[str, Any]) -> None:
        raw["apps"][0][section][key] = value

    return mutate


def drop_app_in(section: str, key: str) -> Mutator:
    def mutate(raw: dict[str, Any]) -> None:
        del raw["apps"][0][section][key]

    return mutate


def drop_app(key: str) -> Mutator:
    def mutate(raw: dict[str, Any]) -> None:
        del raw["apps"][0][key]

    return mutate


def del_app(key: str) -> Mutator:
    def mutate(raw: dict[str, Any]) -> None:
        del raw["apps"][0][key]

    return mutate


def check(tmp_path: Path, mutate: Mutator, match: str) -> None:
    raw = valid_config()
    mutate(raw)
    with pytest.raises(ConfigError, match=match):
        load(tmp_path, raw)


# -- top-level structure ------------------------------------------------------


def test_missing_config_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="config not found"):
        load_config(tmp_path / "nope.yaml", admin_token=ADMIN_TOKEN)


def test_invalid_yaml(tmp_path: Path) -> None:
    dump(tmp_path, "server: [\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(tmp_path / "config.yaml", admin_token=ADMIN_TOKEN)


@pytest.mark.parametrize("raw", ["just a string", "42", "- 1\n- 2\n"])
def test_top_level_not_mapping(tmp_path: Path, raw: str) -> None:
    dump(tmp_path, raw)
    with pytest.raises(ConfigError, match="top level must be a mapping"):
        load_config(tmp_path / "config.yaml", admin_token=ADMIN_TOKEN)


# -- load_config error matrix -------------------------------------------------


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (drop(None, "server"), "missing required key 'server'"),
        (set_in(None, "server", 5), "config.server: expected dict"),
        # the historical inert keys are gone: even well-formed values are unknown now
        (set_in("server", "api_domain", "api.push.example.org"), "server: unknown keys"),
        (set_in("server", "docs_domain", "push.example.org"), "server: unknown keys"),
        (set_in("server", "public_scheme", "https"), "server: unknown keys"),
        (set_in("server", "swagger_ui", "yes"), r"server.swagger_ui: expected bool"),
        (set_in("server", "bogus", 1), "server: unknown keys"),
        (set_in(None, "bogus", 1), "unknown top-level keys"),
        (drop(None, "enrollment"), "missing required key 'enrollment'"),
        (set_in(None, "enrollment", "x"), "config.enrollment: expected dict"),
        (drop("enrollment", "grant_issuer_key"), "missing required key 'grant_issuer_key'"),
        (set_in("enrollment", "grant_issuer_key", 5), "grant_issuer_key: expected str"),
        (set_in("enrollment", "bogus", 1), "enrollment: unknown keys"),
        (set_in("enrollment", "challenge_ttl", 10), "challenge_ttl: 10 outside 60..3600"),
        (set_in("enrollment", "challenge_ttl", 4000), "challenge_ttl: 4000 outside 60..3600"),
        (set_in("enrollment", "challenge_ttl", "600"), "challenge_ttl: expected int"),
        (set_in("enrollment", "attest_root_certs", ["x"]), "attest_root_certs: expected mapping"),
        (
            set_in("enrollment", "attest_root_certs", {"staging": "r.pem"}),
            "unexpected environment 'staging'",
        ),
        (
            set_in("enrollment", "attest_root_certs", {"production": 5}),
            "attest_root_certs.production: expected path",
        ),
        (set_in("enrollment", "attest_root_url", 5), "attest_root_url: expected string or null"),
        (set_in(None, "storage", 3), "storage: expected mapping"),
        (set_in("storage", "bogus", 1), "storage: unknown keys"),
        (drop(None, "apps"), "missing required key 'apps'"),
        (set_in(None, "apps", "test-app"), "config.apps: expected list"),
        (set_in(None, "apps", [5]), "apps\\[\\?\\]: expected mapping"),
        (set_in(None, "apps", ["not-a-mapping"]), "apps\\[\\?\\]: expected mapping"),
        (set_in(None, "apps", [{"bundle_id": "com.example.x"}]), "missing required key 'id'"),
        (set_app("id", 5), "id: expected str"),
        (set_app("id", "Test-App"), "invalid app id"),
        (set_app("id", "a" * 64), "invalid app id"),
        (drop_app("id"), "missing required key 'id'"),
        (set_app("bundle_id", "x"), "invalid bundle id"),
        (set_app("bundle_id", "com example"), "invalid bundle id"),
        (drop_app("bundle_id"), "missing required key 'bundle_id'"),
        (set_app("team_id", "SHORT"), "team_id: expected 10 alphanumeric"),
        (set_app("team_id", 1234567890), "team_id: expected str"),
        (drop_app("team_id"), "missing required key 'team_id'"),
        (drop_app("key_id"), "missing required key 'key_id'"),
        (set_app("key_id", "short"), "key_id: expected 10 alphanumeric"),
        (set_app("key_id", 1234567890), "key_id: expected str"),
        (set_app("key_file", "keys/rotated.p8"), "'key_file' was removed"),
        (set_app("display_name", 5), "display_name: expected string of 1..64 chars"),
        (set_app("display_name", ""), "display_name: expected string of 1..64 chars"),
        (set_app("display_name", "x" * 65), "display_name: expected string of 1..64 chars"),
        (drop_app("environments"), "missing required key 'environments'"),
        (set_app("environments", []), "environments: must not be empty"),
        (set_app("environments", ["cloud"]), "environments: invalid entry"),
        (set_app("environments", [5]), "environments: invalid entry"),
        (set_app("environments", ["sandbox", "sandbox"]), "environments: duplicate entries"),
        (drop_app("kinds"), "missing required key 'kinds'"),
        (set_app("kinds", ["sms"]), "kinds: invalid entry"),
        (set_app("kinds", ["alert", "alert"]), "kinds: duplicate entries"),
        (drop_app("live_activity"), "missing required key 'live_activity'"),
        (set_app("live_activity", "true"), "live_activity: expected bool"),
        (
            set_app("kinds", ["alert"]),
            "live_activity=true requires 'liveActivity' in kinds",
        ),
        (drop_app("attest_environment"), "missing required key 'attest_environment'"),
        (set_app("attest_environment", "staging"), "attest_environment: expected one of"),
        (set_app("registration", ["x"]), "registration: expected mapping"),
        (set_app_in("registration", "bogus", 1), "registration: unknown keys"),
        (
            set_app_in("registration", "callback_required", "yes"),
            "callback_required: expected bool",
        ),
        (set_app("caps", ["x"]), "caps: expected mapping"),
        (set_app_in("caps", "bogus", 1), "caps: unknown keys"),
        (set_app_in("caps", "title", 0), "caps.title: 0 outside 1..4096"),
        (set_app_in("caps", "body", 4097), "caps.body: 4097 outside 1..4096"),
        (drop_app("quota"), "missing required key 'quota'"),
        (set_app("quota", 5), "quota: expected dict"),
        (set_app_in("quota", "burst_per_min", "5"), "burst_per_min: expected int"),
        (drop_app_in("quota", "daily"), "missing required key 'daily'"),
        (set_app_in("quota", "daily", 0), "daily: 0 outside 1..10000000"),
        (set_app_in("quota", "daily", 10_000_001), "daily: 10000001 outside 1..10000000"),
        (set_app_in("quota", "burst_per_min", 10001), "burst_per_min: 10001 outside 1..10000"),
        (
            set_app_in("quota", "token_burst_per_min", 10001),
            "token_burst_per_min: 10001 outside 1..10000",
        ),
        (set_app("grant_ttl", ["x"]), "grant_ttl: expected mapping"),
        (set_app_in("grant_ttl", "bogus", 1), "grant_ttl: unknown keys"),
        (set_app_in("grant_ttl", "min", 899), "grant_ttl.min: 899 outside 900..86400"),
        (set_app_in("grant_ttl", "max", 86401), "grant_ttl.max: 86401 outside 900..86400"),
        (set_app_in("grant_ttl", "default", 899), "grant_ttl.default: 899 outside 900..86400"),
        (set_app("enabled", "yes"), "enabled: expected bool"),
    ],
)
def test_config_error_matrix(tmp_path: Path, mutate: Mutator, match: str) -> None:
    check(tmp_path, mutate, match)


def test_admin_token_missing(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="admin token not provided"):
        load(tmp_path, valid_config(), admin_token=None)


def test_admin_token_too_short(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="at least 32 characters"):
        load(tmp_path, valid_config(), admin_token="x" * 31)


def test_duplicate_app_ids(tmp_path: Path) -> None:
    raw = valid_config()
    raw["apps"].append(valid_app())
    with pytest.raises(ConfigError, match="duplicate app ids"):
        load(tmp_path, raw)


def test_grant_ttl_min_greater_than_max(tmp_path: Path) -> None:
    raw = valid_config()
    raw["apps"][0]["grant_ttl"] = {"min": 5000, "max": 1000}
    with pytest.raises(ConfigError, match="grant_ttl: min 5000 > max 1000"):
        load(tmp_path, raw)


# -- happy path + defaults ----------------------------------------------------


def test_config_may_have_no_apps(tmp_path: Path) -> None:
    raw = valid_config()
    raw["apps"] = []
    config = load(tmp_path, raw)
    assert config.apps == ()  # an empty apps: list is a valid config


def test_valid_config_resolves_paths_and_defaults(tmp_path: Path) -> None:
    raw = valid_config()
    del raw["enrollment"]["challenge_ttl"]
    del raw["apps"][0]["display_name"]
    del raw["apps"][0]["registration"]
    del raw["apps"][0]["grant_ttl"]
    config = load(tmp_path, raw)

    assert config.server.swagger_ui is False  # opt-in default when omitted
    assert config.enrollment.grant_issuer_key == tmp_path / "keys/issuer.pem"
    assert config.enrollment.challenge_ttl == 600
    assert config.database == tmp_path / "relay.db"
    assert config.app("test-app").display_name == "test-app"
    assert config.app("test-app").registration.callback_required is False
    assert config.app("test-app").grant_ttl == GrantTtlConfig(min=900, max=86400, default=21600)


def test_swagger_ui_opt_in_survives_config_loading(tmp_path: Path) -> None:
    """``server.swagger_ui: true`` must reach ServerConfig through load_config.

    (The field used to be skipped by the loader — only dataclasses.replace()
    could turn docs on, so the documented config knob silently did nothing.)
    """
    raw = valid_config()
    raw["server"]["swagger_ui"] = True
    config = load(tmp_path, raw)
    assert config.server.swagger_ui is True


def test_challenge_ttl_boundaries_accepted(tmp_path: Path) -> None:
    for ttl in (60, 3600):
        raw = valid_config()
        raw["enrollment"]["challenge_ttl"] = ttl
        assert load(tmp_path, raw).enrollment.challenge_ttl == ttl


def test_grant_ttl_default_capped_by_max(tmp_path: Path) -> None:
    raw = valid_config()
    raw["apps"][0]["grant_ttl"] = {"max": 1800}
    config = load(tmp_path, raw)
    assert config.app("test-app").grant_ttl == GrantTtlConfig(min=900, max=1800, default=1800)


def test_absolute_paths_kept(tmp_path: Path) -> None:
    raw = valid_config()
    raw["enrollment"]["grant_issuer_key"] = "/etc/relay/issuer.pem"
    raw["enrollment"]["attest_root_certs"] = {"production": "/abs/prod-root.pem"}
    raw["storage"]["database"] = "/var/lib/other/relay.db"
    config = load(tmp_path, raw)

    assert config.enrollment.grant_issuer_key == Path("/etc/relay/issuer.pem")
    assert config.enrollment.root_for("production") == Path("/abs/prod-root.pem")
    assert config.database == Path("/var/lib/other/relay.db")
    assert config.app("test-app").key_file == tmp_path / f"keys/AuthKey_{KEY_ID}.p8"


def test_relative_root_resolved_and_root_for(tmp_path: Path) -> None:
    raw = valid_config()
    raw["enrollment"]["attest_root_certs"] = {"production": "roots/prod.pem"}
    config = load(tmp_path, raw)
    assert config.enrollment.root_for("production") == tmp_path / "roots/prod.pem"
    assert config.enrollment.root_for("development") is None


def test_attest_root_url_default(tmp_path: Path) -> None:
    config = load(tmp_path, valid_config())
    assert config.enrollment.attest_root_url == APPLE_ATTEST_ROOT_URL


def test_attest_root_url_explicit(tmp_path: Path) -> None:
    raw = valid_config()
    raw["enrollment"]["attest_root_url"] = "https://mirror.example/root.pem"
    assert load(tmp_path, raw).enrollment.attest_root_url == "https://mirror.example/root.pem"


def test_attest_root_url_null_disables_fetch(tmp_path: Path) -> None:
    raw = valid_config()
    raw["enrollment"]["attest_root_url"] = None
    assert load(tmp_path, raw).enrollment.attest_root_url is None


def test_defaults_when_sections_omitted(tmp_path: Path) -> None:
    raw = valid_config()
    del raw["storage"]
    del raw["apps"][0]["grant_ttl"]
    config = load(tmp_path, raw)
    assert config.database == Path("/var/lib/apns-relay/relay.db")
    assert config.app("test-app").grant_ttl == GrantTtlConfig(min=900, max=86400, default=21600)


# -- app key handling ---------------------------------------------------------


def test_key_id_from_config_names_derived_file(tmp_path: Path) -> None:
    config = load(tmp_path, valid_config())
    assert config.app("test-app").key_id == KEY_ID
    assert config.app("test-app").key_file == tmp_path / f"keys/AuthKey_{KEY_ID}.p8"


def test_key_file_rejected_with_migration_hint(tmp_path: Path) -> None:
    raw = valid_config()
    raw["apps"][0]["key_file"] = f"keys/AuthKey_{KEY_ID}.p8"
    with pytest.raises(ConfigError, match="'key_file' was removed"):
        load(tmp_path, raw)


# -- enabled apps, app(), topics ----------------------------------------------


def test_disabled_app_excluded_from_enabled_apps(tmp_path: Path) -> None:
    raw = valid_config()
    raw["apps"][0]["enabled"] = False
    config = load(tmp_path, raw)
    assert config.app("test-app").enabled is False
    assert config.enabled_apps == ()


def test_config_app_lookup_and_topics(tmp_path: Path) -> None:
    config = load(tmp_path, valid_config())
    app = config.app("test-app")
    assert app.topic == "com.example.testapp"
    assert app.live_activity_topic == "com.example.testapp.push-type.liveactivity"
    with pytest.raises(KeyError):
        config.app("no-such-app")


def test_enabled_apps_excludes_only_disabled(tmp_path: Path) -> None:
    raw = valid_config()
    second = valid_app()
    second["id"] = "second-app"
    second["bundle_id"] = "com.example.second"
    second["live_activity"] = False
    second["kinds"] = ["alert"]
    second["enabled"] = False
    raw["apps"].append(second)
    config = load(tmp_path, raw)
    assert [a.id for a in config.enabled_apps] == ["test-app"]


def test_admin_token_not_in_repr(tmp_path: Path) -> None:
    config = load(tmp_path, valid_config())
    assert ADMIN_TOKEN not in repr(config)


def test_load_test_config_helper(tmp_path: Path) -> None:
    config = load_test_config(dump(tmp_path, valid_config()))
    assert config.admin_token == ADMIN_TOKEN


# -- GrantTtlConfig.clamp and _expect float branch ----------------------------


@pytest.mark.parametrize(
    ("requested", "expected"),
    [(None, 3600), (1, 900), (100_000, 86400), (3600, 3600), (900, 900), (86400, 86400)],
)
def test_grant_ttl_clamp(requested: int | None, expected: int) -> None:
    ttl = GrantTtlConfig(min=900, max=86400, default=3600)
    assert ttl.clamp(requested) == expected


def test_expect_float_accepts_numbers() -> None:
    assert _expect({"x": 2}, "x", float, "ctx") == 2.0
    assert _expect({"x": 2.5}, "x", float, "ctx") == 2.5


@pytest.mark.parametrize("value", [True, "s", None, [1]])
def test_expect_float_rejects_others(value: Any) -> None:
    with pytest.raises(ConfigError, match=r"ctx\.x: expected number"):
        _expect({"x": value}, "x", float, "ctx")
