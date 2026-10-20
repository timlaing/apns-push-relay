"""server.swagger_ui: opt-in Swagger UI / ReDoc / schema on the API host.

The routes exist only when the operator enables them in config; disabled
(the default), /docs, /redoc and /openapi.json do not exist at all. The
admin API is never in the schema and stays token-gated either way.
"""

from __future__ import annotations

import dataclasses
from importlib.metadata import version

from fastapi.testclient import TestClient

from apns_relay.app import create_app


def _swagger_app(env):
    config = dataclasses.replace(
        env.config, server=dataclasses.replace(env.config.server, swagger_ui=True)
    )
    return create_app(config, master_secret=b"m" * 32, store=env.store)


def test_swagger_routes_do_not_exist_by_default(env) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert env.client.get(path).status_code == 404, path


def test_swagger_ui_opt_in_serves_docs_and_schema(env) -> None:
    with TestClient(_swagger_app(env)) as client:
        page = client.get("/docs")
        assert page.status_code == 200
        assert "swagger" in page.text.lower()
        assert client.get("/redoc").status_code == 200

        schema = client.get("/openapi.json")
        assert schema.status_code == 200
        paths = schema.json()["paths"]
        assert "/v1/rotate" in paths and "/v1/push" in paths
        # The admin API is never in the schema (include_in_schema=False).
        assert not any(path.startswith("/admin") for path in paths)


def test_admin_stays_token_gated_when_swagger_enabled(env) -> None:
    with TestClient(_swagger_app(env)) as client:
        response = client.get("/admin/status")
        assert response.status_code == 401
        assert response.json() == {"error": "bad_admin_token"}


def test_schema_version_tracks_package_version(env) -> None:
    """The schema's info.version is the package version (releases = v* tags)."""
    with TestClient(_swagger_app(env)) as client:
        schema = client.get("/openapi.json").json()
    assert schema["info"]["version"] == version("apns-push-relay")
