"""Static assertions over ``deploy/`` (PLAN §6) — reads files only, never edits them."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from apns_relay.attest import APPLE_ATTEST_ROOT_URL
from apns_relay.config import ConfigError, load_config
from tests.conftest import ADMIN_TOKEN

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"

# config.py `_TOP_KEYS` — the loader rejects any other top-level key.
CONFIG_TOP_KEYS = {"server", "enrollment", "apps", "storage"}


def _nginx() -> str:
    return (DEPLOY / "nginx.conf.template").read_text()


def _location_blocks(conf: str, header: str) -> list[str]:
    """Return every ``location <header>`` block, brace-matched."""
    blocks = []
    for match in re.finditer(re.escape(f"location {header}"), conf):
        start = match.start()
        depth = 0
        for index in range(start, len(conf)):
            char = conf[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(conf[start : index + 1])
                    break
        else:
            raise AssertionError(f"unterminated location block: {header}")
    return blocks


def _location_block(conf: str, header: str) -> str:
    """Return the first ``location <header>`` block, brace-matched."""
    blocks = _location_blocks(conf, header)
    assert blocks, f"no location block: {header}"
    return blocks[0]


# -- nginx ---------------------------------------------------------------------


def test_admin_returns_404_at_the_edge() -> None:
    """Both server blocks 404 /admin — port 80 included because it proxies in
    behind-proxy mode and must never forward the admin API."""
    blocks = _location_blocks(_nginx(), "/admin")
    assert len(blocks) == 2
    for block in blocks:
        assert "return 404" in block
        assert "proxy_pass" not in block


def test_port_80_redirect_opt_out_for_tls_terminating_proxies() -> None:
    """Plain port-80 traffic upgrades to HTTPS. With FORCE_HTTPS=0 (this nginx
    behind a proxy that already terminated TLS) requests carrying
    X-Forwarded-Proto: https are served instead of redirected. The `if`
    contains only `return` — the documented-safe nginx pattern."""
    conf = _nginx()
    assert re.search(
        r"map \$http_x_forwarded_proto \$force_https \{[^}]*default 1;"
        r"[^}]*https\s+\$\{FORCE_HTTPS\};",
        conf,
    ), "map must default to redirect, taking the https case from ${FORCE_HTTPS}"
    block = _location_block(conf, "/ {")  # first `location /` is port 80's
    assert "if ($force_https)" in block
    assert "return 301 https://${API_DOMAIN}$request_uri;" in block
    assert "proxy_pass http://relay:8001;" in block
    assert "proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;" in block


def test_swagger_routes_proxy_to_the_relay() -> None:
    """/docs, /redoc and /openapi.json reach the relay, which serves them
    only when server.swagger_ui is enabled (404 by default otherwise)."""
    conf = _nginx()
    for header in ("/docs {", "/redoc {", "/openapi.json {"):
        block = _location_block(conf, header)
        assert "proxy_pass http://relay:8001;" in block, header
        assert "return 404" not in block, header


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
    assert "proxy_pass http://relay:8001;" in v1


def test_api_root_proxies_to_the_relay() -> None:
    """/ is answered by the relay (a JSON pointer to the docs site); the
    docs domain is baked into the relay image, not rendered by nginx."""
    block = _location_block(_nginx(), "/ {")
    assert "proxy_pass http://relay:8001;" in block
    assert "DOCS_DOMAIN" not in _nginx()


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


def test_nginx_publishes_80_and_443_relay_is_loopback_only() -> None:
    """nginx is the public edge; both relay listeners bind host-loopback —
    the admin API on 8000 (CLI target), the public API + Swagger on 8001,
    never LAN/Internet-facing."""
    compose = _compose()
    assert {"80:80", "443:443"} <= set(compose["services"]["nginx"]["ports"])
    assert set(compose["services"]["relay"]["ports"]) == {
        "127.0.0.1:8000:8000",
        "127.0.0.1:8001:8001",
    }


def test_nginx_proxies_only_to_the_public_listener() -> None:
    """Every upstream is the public listener (8001); the admin listener
    (8000) has no route through the edge at all."""
    conf = _nginx()
    targets = re.findall(r"proxy_pass (http://relay:\d+);", conf)
    assert targets and set(targets) == {"http://relay:8001"}


def test_nginx_force_https_only_disablable_via_operator_env() -> None:
    """The compose default keeps port 80 redirecting unconditionally; only an
    explicit FORCE_HTTPS=0 in .env (behind a TLS proxy) can turn that off."""
    env = _compose()["services"]["nginx"]["environment"]
    assert env["FORCE_HTTPS"] == "${FORCE_HTTPS:-1}"


def test_relay_mounts_instance_dir_rw_keys_stay_ro() -> None:
    """In-container config management: app add/remove edit config.yaml and
    write config.yaml.bak on the host; the keys dir stays read-only."""
    volumes = _compose()["services"]["relay"]["volumes"]
    assert "./:/etc/apns-relay" in volumes
    assert "./keys:/etc/apns-relay/keys:ro" in volumes
    assert not any("config.yaml" in mount for mount in volumes)


def test_relay_service_prefers_the_published_image() -> None:
    """The published GHCR image is the primary run path; build: stays as the
    from-source fallback (compose builds when no image is available). The
    image tracks `latest` — no tag interpolation — so image updaters
    (Watchtower, What's Up Docker) can see releases."""
    relay = _compose()["services"]["relay"]
    assert relay["image"] == "ghcr.io/timlaing/apns-push-relay:latest"
    assert "build" in relay
    assert "RELAY_TAG" not in (DEPLOY / "docker-compose.yml").read_text()


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
    # one process, two listeners: admin 8000 + public 8001 (serve.py)
    assert cmd == 'CMD ["python", "-m", "apns_relay.serve"]'
    expose = next(line for line in dockerfile.splitlines() if line.startswith("EXPOSE"))
    assert expose == "EXPOSE 8000 8001"


def test_docs_domain_baked_into_the_image() -> None:
    """The API root's docs pointer comes from the image env, with the
    project's GitHub Pages URL as the default."""
    dockerfile = (DEPLOY / "Dockerfile").read_text()
    assert "DOCS_DOMAIN=timlaing.github.io/apns-push-relay" in dockerfile


def test_entrypoint_runs_doctor_before_exec() -> None:
    script = (DEPLOY / "relay-entrypoint.sh").read_text()
    assert "set -eu" in script
    assert script.index("relay doctor") < script.index('exec "$@"')


def test_entrypoint_fetches_missing_roots_before_doctor() -> None:
    """Startup fetch is best-effort (--if-missing, non-fatal); doctor is the gate."""
    script = (DEPLOY / "relay-entrypoint.sh").read_text()
    commands = [line for line in script.splitlines() if line.startswith("relay ")]
    assert commands[0].startswith("relay fetch-roots --if-missing ||")
    assert commands[1] == "relay doctor"


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
    assert config.server.swagger_ui is False
    assert config.enrollment.challenge_ttl == 600
    assert config.enrollment.grant_issuer_key == path.parent / "keys/issuer.pem"
    assert config.enrollment.attest_root_url == APPLE_ATTEST_ROOT_URL
    assert config.enrollment.attest_root_certs == {
        "development": Path("/var/lib/apns-relay/apple-attest-root.pem"),
        "production": Path("/var/lib/apns-relay/apple-attest-root.pem"),
    }
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
