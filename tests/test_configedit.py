"""configedit — round-trip ``config.yaml`` editing behind ``relay app add/remove``.

Every validation error is a ``ConfigError`` (the CLI prints it plus help); the
happy paths must preserve operator comments and write a backup.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apns_relay import configedit
from apns_relay.config import ConfigError

VALID_ENTRY = {
    "id": "demo",
    "bundle_id": "com.example.demo",
    "team_id": "TEAMID0001",
    "key_id": "ABCDEF0123",
    "environments": ["sandbox", "production"],
}


def _config(tmp_path: Path, apps_yaml: str = "  - id: alpha\n") -> Path:
    path = tmp_path / "config.yaml"
    path.write_text("# operator comment\napps:\n" + apps_yaml)
    return path


def _key(tmp_path: Path, key_id: str = "ABCDEF0123") -> Path:
    keys = tmp_path / "keys"
    keys.mkdir(exist_ok=True)
    path = keys / f"AuthKey_{key_id}.p8"
    path.write_text("dummy")
    return path


# -- load / save ---------------------------------------------------------------


def test_load_document_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="config file not found"):
        configedit.load_document(tmp_path / "absent.yaml")


def test_load_document_top_level_list(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("- just\n- a list\n")
    with pytest.raises(ConfigError, match="expected a mapping with an 'apps' list"):
        configedit.load_document(path)


def test_load_document_apps_not_a_list(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("apps: nope\n")
    with pytest.raises(ConfigError, match="expected a mapping with an 'apps' list"):
        configedit.load_document(path)


def test_load_document_happy(tmp_path: Path) -> None:
    document = configedit.load_document(_config(tmp_path))
    assert [item["id"] for item in document["apps"]] == ["alpha"]


def test_keys_dir_sits_beside_config(tmp_path: Path) -> None:
    config = _config(tmp_path)
    assert configedit.keys_dir(config) == tmp_path / "keys"


def test_save_document_writes_backup(tmp_path: Path) -> None:
    config = _config(tmp_path)
    document = configedit.load_document(config)
    document["apps"].append({"id": "second"})
    configedit.save_document(config, document)
    assert (tmp_path / "config.yaml.bak").is_file()
    assert "second" in config.read_text()


# -- key discovery --------------------------------------------------------------


def test_discover_keys_without_directory(tmp_path: Path) -> None:
    config = _config(tmp_path)
    assert configedit.discover_keys(config) == []


def test_discover_keys_sorted_unique_filtered(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _key(tmp_path, "ZZZZZZ9999")
    _key(tmp_path, "ABCDEF0123")
    nested = tmp_path / "keys" / "prod"
    nested.mkdir()
    (nested / "AuthKey_NESTED0001.p8").write_text("dummy")  # nested → ignored (loader is flat)
    (tmp_path / "keys" / "notakey.p8").write_text("")  # no AuthKey_ prefix
    (tmp_path / "keys" / "AuthKey_short.p8").write_text("")  # id not 10 chars
    assert configedit.discover_keys(config) == ["ABCDEF0123", "ZZZZZZ9999"]


# -- validation -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("id", "Bad Id", "app id"),
        ("bundle_id", "x", "bundle id"),
        ("team_id", "SHORT", "team id"),
        ("key_id", "short", "key id"),
    ],
)
def test_validate_rejects_bad_fields(tmp_path: Path, field: str, value: str, match: str) -> None:
    entry = {**VALID_ENTRY, field: value}
    with pytest.raises(ConfigError, match=match):
        configedit.validate_app_entry(entry, tmp_path / "config.yaml")


def test_validate_requires_key_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"not found next to config\.yaml"):
        configedit.validate_app_entry(VALID_ENTRY, tmp_path / "config.yaml")


def test_validate_accepts_entry_with_key(tmp_path: Path) -> None:
    _key(tmp_path)
    configedit.validate_app_entry(VALID_ENTRY, tmp_path / "config.yaml")  # no raise


# -- add / remove ----------------------------------------------------------------


def test_add_app_round_trip_preserves_comments(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _key(tmp_path)
    configedit.add_app(config, dict(VALID_ENTRY))
    text = config.read_text()
    assert "# operator comment" in text
    assert "key_id: ABCDEF0123" in text
    assert (tmp_path / "config.yaml.bak").is_file()


def test_add_app_round_trip_keeps_long_lines_unwrapped(tmp_path: Path) -> None:
    """The emitter must not reflow the operator's long lines (flow mappings
    such as caps:) when it rewrites the file."""
    caps_line = (
        "    caps: { title: 64, subtitle: 64, body: 200, sealed: 1024,"
        " category: 32, background: 512 }"
    )
    config = _config(tmp_path, apps_yaml=f"  - id: alpha\n{caps_line}\n")
    _key(tmp_path)
    configedit.add_app(config, dict(VALID_ENTRY))
    assert caps_line in config.read_text()


def test_add_app_rejects_duplicate_id(tmp_path: Path) -> None:
    config = _config(tmp_path, apps_yaml="  - id: demo\n")
    _key(tmp_path)
    with pytest.raises(ConfigError, match="already exists"):
        configedit.add_app(config, dict(VALID_ENTRY))


def test_remove_app_missing_id(tmp_path: Path) -> None:
    config = _config(tmp_path, apps_yaml="  - id: alpha\n  - id: beta\n")
    with pytest.raises(ConfigError, match="no app with id 'ghost'"):
        configedit.remove_app(config, "ghost")


def test_remove_app_refuses_last_entry(tmp_path: Path) -> None:
    config = _config(tmp_path, apps_yaml="  - id: alpha\n")
    with pytest.raises(ConfigError, match="refusing to remove"):
        configedit.remove_app(config, "alpha")


def test_remove_app_success(tmp_path: Path) -> None:
    config = _config(tmp_path, apps_yaml="  - id: alpha\n  - id: beta\n")
    configedit.remove_app(config, "alpha")
    text = config.read_text()
    assert "alpha" not in text and "beta" in text
    assert (tmp_path / "config.yaml.bak").is_file()


def test_list_apps_skips_non_mapping_entries(tmp_path: Path) -> None:
    config = _config(tmp_path, apps_yaml="  - just-a-string\n  - id: alpha\n")
    assert [entry["id"] for entry in configedit.list_apps(config)] == ["alpha"]
