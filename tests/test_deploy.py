"""Static assertions over ``deploy/`` (PLAN §6) — reads files only, never edits them."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from apns_relay.config import ConfigError, load_config
from tests.conftest import ADMIN_TOKEN

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"

# config.py `_TOP_KEYS` — the loader rejects any other top-level key.
CONFIG_TOP_KEYS = {"server", "enrollment", "apps", "storage"}


def _nginx() -> str:
    return (DEPLOY / "nginx.conf.template").read_text()


def _location_block(conf: str, header: str) -> str:
    """Return the ``location <header>`` block, brace-matched."""
    start = conf.index(f"location {header}")
    depth = 0
    for index in range(start, len(conf)):
        char = conf[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return conf[start : index + 1]
    raise AssertionError(f"unterminated location block: {header}")


# -- nginx ---------------------------------------------------------------------


def test_admin_docs_and_openapi_return_404_at_the_edge() -> None:
    conf = _nginx()
    for header in ("/admin {", "/docs {", "/openapi.json {"):
        block = _location_block(conf, header)
        assert "return 404" in block, header


def test_rate_limit_zone_declared_and_applied_to_v1() -> None:
    conf = _nginx()
    match = re.search(r"limit_req_zone\s+\S+\s+zone=(\w+):", conf)
    assert match, "limit_req_zone must declare a named zone"
    zone = match.group(1)
    v1 = _location_block(conf, "/v1/ {")
    assert f"limit_req zone={zone} " in v1


def test_request_body_capped_at_16k() -> None:
    assert "client_max_body_size 16k;" in _nginx()


def test_v1_proxies_to_relay_internal_port() -> None:
    v1 = _location_block(_nginx(), "/v1/ {")
    assert "proxy_pass http://relay:8000;" in v1


def test_acme_challenge_location_present() -> None:
    block = _location_block(_nginx(), "/.well-known/acme-challenge/ {")
    assert "root /var/www/certbot;" in block


# -- docker compose ------------------------------------------------------------


def _compose() -> dict:
    return yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())


def test_relay_secrets_injected_via_environment() -> None:
    env = _compose()["services"]["relay"]["environment"]
    assert env["RELAY_ADMIN_TOKEN"].startswith("${RELAY_ADMIN_TOKEN")
    assert env["RELAY_MASTER_SECRET"].startswith("${RELAY_MASTER_SECRET")


def test_nginx_publishes_80_and_443_relay_stays_internal() -> None:
    compose = _compose()
    assert {"80:80", "443:443"} <= set(compose["services"]["nginx"]["ports"])
    assert "ports" not in compose["services"]["relay"]


def test_certbot_present_with_issue_and_renewal_wiring() -> None:
    compose = _compose()
    certbot = compose["services"]["certbot"]
    script = "\n".join(certbot["entrypoint"])
    assert "certbot certonly --webroot" in script  # issue-if-missing
    assert "certbot renew" in script
    assert "sleep 43200" in script  # renew loop every 12h
    # shares the ACME webroot with nginx so the challenge location serves it
    assert "certbot-www:/var/www/certbot" in compose["services"]["nginx"]["volumes"]


# -- Dockerfile + entrypoints ---------------------------------------------------


def test_dockerfile_entrypoint_and_command() -> None:
    dockerfile = (DEPLOY / "Dockerfile").read_text()
    entrypoint = next(line for line in dockerfile.splitlines() if line.startswith("ENTRYPOINT"))
    assert "relay-entrypoint" in entrypoint  # runs `relay doctor` pre-flight
    assert "COPY deploy/relay-entrypoint.sh /usr/local/bin/relay-entrypoint" in dockerfile
    cmd = next(line for line in dockerfile.splitlines() if line.startswith("CMD"))
    assert "uvicorn" in cmd
    assert "apns_relay.app:create_app" in cmd
    assert "--factory" in cmd


def test_entrypoint_runs_doctor_before_exec() -> None:
    script = (DEPLOY / "relay-entrypoint.sh").read_text()
    assert "set -eu" in script
    assert script.index("relay doctor") < script.index('exec "$@"')


# -- config.yaml.example --------------------------------------------------------


def test_example_config_is_valid_yaml_with_schema_keys() -> None:
    raw = yaml.safe_load((DEPLOY / "config.yaml.example").read_text())
    assert isinstance(raw, dict)
    assert set(raw) == CONFIG_TOP_KEYS


def test_example_config_loads_structurally() -> None:
    """Structural parse only — key files need not exist for load_config()."""
    path = DEPLOY / "config.yaml.example"
    config = load_config(path, admin_token=ADMIN_TOKEN)
    assert config.server.api_domain == "api.push.example.org"
    assert config.server.public_scheme == "https"
    assert config.enrollment.challenge_ttl == 600
    assert config.enrollment.grant_issuer_key == path.parent / "keys/issuer.pem"
    assert config.enrollment.attest_root_certs == {}
    assert config.database == Path("/var/lib/apns-relay/relay.db")
    app = config.apps[0]
    assert app.id == "my-app"
    assert app.key_id == "XXXXXXXXXX"
    assert app.environments == ("sandbox", "production")
    assert app.kinds == ("alert", "background", "liveActivity")
    assert app.live_activity is True
    assert app.quota.daily == 5000
    assert app.grant_ttl.default == 21600


def test_example_config_takes_admin_token_from_env_only() -> None:
    with pytest.raises(ConfigError, match="admin token not provided"):
        load_config(DEPLOY / "config.yaml.example")
