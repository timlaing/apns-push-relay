"""In-place ``config.yaml`` editing for ``relay app add`` / ``app remove``.

Round-trip YAML (ruamel) so operator comments, key order and formatting
survive the edit; a one-time ``config.yaml.bak`` backup is written before
the first change per run. All validation errors raise ``ConfigError`` —
the CLI maps them to a red error plus command help.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .config import APP_ID_RE, BUNDLE_ID_RE, KEY_ID_RE, TEAM_ID_RE, ConfigError

DEFAULT_QUOTA: dict[str, int] = {"burst_per_min": 60, "daily": 10000, "token_burst_per_min": 30}
DEFAULT_GRANT_TTL: dict[str, int] = {"min": 900, "max": 86400, "default": 21600}


def _yaml() -> YAML:
    yaml = YAML()  # round-trip mode: comments, order and style survive
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    # Never reflow the operator's long lines (flow mappings, URLs) —
    # the emitter would otherwise wrap anything past its default width.
    yaml.width = 4096
    return yaml


def load_document(config_path: Path) -> Any:
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {config_path}")
    with config_path.open() as handle:
        document = _yaml().load(handle)
    if not isinstance(document, dict) or not isinstance(document.get("apps"), list):
        raise ConfigError(f"{config_path}: expected a mapping with an 'apps' list")
    return document


def save_document(config_path: Path, document: Any) -> None:
    backup = config_path.with_name(f"{config_path.name}.bak")
    shutil.copy2(config_path, backup)
    with config_path.open("w") as handle:
        _yaml().dump(document, handle)


def keys_dir(config_path: Path) -> Path:
    return config_path.parent / "keys"


def discover_keys(config_path: Path) -> list[str]:
    """Key IDs of every ``AuthKey_<KEYID>.p8`` directly under ``config_dir/keys``.

    Flat on purpose: the loader looks keys up at ``keys/AuthKey_<key_id>.p8``,
    so a nested file would be pickable here but unbootable there.
    """
    directory = keys_dir(config_path)
    if not directory.is_dir():
        return []
    found = {
        path.stem.removeprefix("AuthKey_")
        for path in directory.glob("AuthKey_*.p8")
        if KEY_ID_RE.match(path.stem.removeprefix("AuthKey_"))
    }
    return sorted(found)


def validate_app_entry(entry: dict[str, Any], config_path: Path) -> None:
    app_id = entry.get("id")
    if not isinstance(app_id, str) or not APP_ID_RE.match(app_id):
        raise ConfigError(f"app id {app_id!r}: expected [a-z0-9-] (1..63 chars)")
    bundle_id = entry.get("bundle_id")
    if not isinstance(bundle_id, str) or not BUNDLE_ID_RE.match(bundle_id):
        raise ConfigError(f"bundle id {bundle_id!r}: expected reverse-DNS, e.g. com.example.app")
    team_id = entry.get("team_id")
    if not isinstance(team_id, str) or not TEAM_ID_RE.match(team_id):
        raise ConfigError(f"team id {team_id!r}: expected 10 alphanumeric chars")
    key_id = entry.get("key_id")
    if not isinstance(key_id, str) or not KEY_ID_RE.match(key_id):
        raise ConfigError(f"key id {key_id!r}: expected 10 alphanumeric chars")
    if not keys_dir(config_path).joinpath(f"AuthKey_{key_id}.p8").is_file():
        raise ConfigError(
            f"keys/AuthKey_{key_id}.p8 not found next to {config_path.name}"
            " — drop the .p8 there first"
        )


def add_app(config_path: Path, entry: dict[str, Any]) -> None:
    """Validate and append an app entry to ``config.yaml``."""
    document = load_document(config_path)
    validate_app_entry(entry, config_path)
    if any(item.get("id") == entry["id"] for item in document["apps"] if isinstance(item, dict)):
        raise ConfigError(f"app id {entry['id']!r} already exists in {config_path.name}")
    document["apps"].append(entry)
    save_document(config_path, document)


def remove_app(config_path: Path, app_id: str) -> None:
    """Delete an app entry from ``config.yaml`` (an empty ``apps:`` list is allowed)."""
    document = load_document(config_path)
    remaining = [
        item
        for item in document["apps"]
        if not (isinstance(item, dict) and item.get("id") == app_id)
    ]
    if len(remaining) == len(document["apps"]):
        raise ConfigError(f"no app with id {app_id!r} in {config_path.name}")
    document["apps"] = remaining
    save_document(config_path, document)


def list_apps(config_path: Path) -> list[dict[str, Any]]:
    document = load_document(config_path)
    return [dict(item) for item in document["apps"] if isinstance(item, dict)]
