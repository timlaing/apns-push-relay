"""Admin API: bearer auth, status/tenants/reissue/denylist/logs (PLAN §3.1/§3.4/§5).

Every route sits behind the shared ``require_admin`` dependency; responses are
checked both for shape and for the privacy invariant — no tenant tokens, grants
or destination material may appear in any admin response (PLAN §3.4).
"""

from __future__ import annotations

from importlib.metadata import version as package_version
from typing import Any

import pytest

from tests.conftest import (
    ADMIN_TOKEN,
    APP_ID,
    DEFAULT_QUOTA,
    KEY_ID,
    OTHER_APP_ID,
    OTHER_TENANT_ID,
    TENANT_ID,
    do_push,
    enroll,
    push_payload,
    register_tenant,
)

ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

JTI_KEY = "550e8400-e29b-41d4-a716-446655440000"  # uuid-shaped grant jti
DIGEST_KEY = "sha256:" + "ab" * 32  # destination-token hash form


def _get(env: Any, path: str, **kwargs: Any):
    return env.client.get(path, headers=ADMIN_HEADERS, **kwargs)


def _post(env: Any, path: str, json: dict[str, Any]):
    return env.client.post(path, headers=ADMIN_HEADERS, json=json)


# -- auth ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "wrong"},
        {"Authorization": "Bearer wrong-token"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
    ],
    ids=["missing", "raw", "wrong-token", "no-value", "empty-value"],
)
def test_status_rejects_bad_admin_token(env, headers: dict[str, str]) -> None:
    response = env.client.get("/admin/status", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"error": "bad_admin_token"}


def test_admin_token_shared_across_routes(env) -> None:
    for path in ("/admin/status", "/admin/tenants", "/admin/denylist", "/admin/logs"):
        assert _get(env, path).status_code == 200, path
    # a wrong token fails on a route the pass-case didn't cover — same dependency
    denied = env.client.get(
        "/admin/tenants/verify",
        params={"tenant": TENANT_ID},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}x"},
    )
    assert denied.status_code == 401
    assert denied.json() == {"error": "bad_admin_token"}


# -- GET /admin/status ----------------------------------------------------------


def test_status_reports_shape_and_metrics(env) -> None:
    token = register_tenant(env.client)  # 201 — the only completed request so far
    response = _get(env, "/admin/status")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == package_version("apns-push-relay")
    assert body["status"] == "ok"
    assert body["uptimeSeconds"] >= 0
    assert body["tenants"] == 1
    assert body["denylisted"] == 0

    assert [app["id"] for app in body["apps"]] == [APP_ID, OTHER_APP_ID]
    assert body["apps"][0] == {
        "id": APP_ID,
        "enabled": True,
        "keyId": KEY_ID,
        "environments": ["sandbox", "production"],
        "kinds": ["alert", "background", "liveActivity"],
        "quota": dict(DEFAULT_QUOTA),
        "grantTtl": {"min": 900, "max": 86400, "default": 3600},
        "attestEnvironment": "production",
    }
    second = body["apps"][1]
    assert second["id"] == OTHER_APP_ID
    assert second["kinds"] == ["alert"]
    assert second["grantTtl"] == {"min": 900, "max": 86400, "default": 21600}

    # snapshot as of the handler: the status request itself is not yet counted
    assert body["metrics"] == {"requests_total": {"201": 1}, "registers_total": {"ok": 1}}
    assert token not in response.text


# -- GET /admin/tenants ---------------------------------------------------------


def test_tenants_empty(env) -> None:
    response = _get(env, "/admin/tenants")
    assert response.status_code == 200
    assert response.json() == {"tenants": []}


def test_tenants_lists_rows_without_leaking_token(env) -> None:
    token = register_tenant(env.client)
    response = _get(env, "/admin/tenants")
    assert response.status_code == 200
    tenants = response.json()["tenants"]
    assert len(tenants) == 1
    row = tenants[0]
    assert set(row) == {"tenant", "app", "registeredAt", "lastSeen"}
    assert row["tenant"] == TENANT_ID
    assert row["app"] == APP_ID
    assert isinstance(row["registeredAt"], int)
    assert isinstance(row["lastSeen"], int)
    assert token not in response.text


def test_tenants_app_filter(env) -> None:
    register_tenant(env.client, TENANT_ID, APP_ID)
    register_tenant(env.client, OTHER_TENANT_ID, OTHER_APP_ID)
    match = _get(env, "/admin/tenants", params={"app": APP_ID})
    assert match.status_code == 200
    rows = match.json()["tenants"]
    assert [row["tenant"] for row in rows] == [TENANT_ID]
    assert all(row["app"] == APP_ID for row in rows)

    unknown = _get(env, "/admin/tenants", params={"app": "no-such-app"})
    assert unknown.status_code == 200
    assert unknown.json() == {"tenants": []}


# -- GET /admin/tenants/verify ---------------------------------------------------


def test_verify_existing_tenant(env) -> None:
    token = register_tenant(env.client)
    response = _get(env, "/admin/tenants/verify", params={"tenant": TENANT_ID})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"exists", "tenant", "app", "registeredAt", "lastSeen"}
    assert body["exists"] is True
    assert body["tenant"] == TENANT_ID
    assert body["app"] == APP_ID
    assert isinstance(body["registeredAt"], int)
    assert isinstance(body["lastSeen"], int)
    assert token not in response.text


def test_verify_unknown_tenant_or_wrong_app_404(env) -> None:
    register_tenant(env.client)  # registered for APP_ID only
    ghost = _get(env, "/admin/tenants/verify", params={"tenant": "ghost.example.com"})
    assert ghost.status_code == 404
    assert ghost.json() == {"error": "unknown_tenant"}

    wrong_app = _get(
        env, "/admin/tenants/verify", params={"tenant": TENANT_ID, "app": OTHER_APP_ID}
    )
    assert wrong_app.status_code == 404
    assert wrong_app.json() == {"error": "unknown_tenant"}


# -- POST /admin/tenants/revoke ----------------------------------------------------


def test_revoke_with_app_removes_one_registration_and_access(env) -> None:
    token = register_tenant(env.client, TENANT_ID, APP_ID)
    register_tenant(env.client, TENANT_ID, OTHER_APP_ID)
    enrolled = enroll(env, token=token)

    response = _post(env, "/admin/tenants/revoke", {"tenant": TENANT_ID, "app": APP_ID})
    assert response.status_code == 200
    assert response.json() == {"revoked": 1}
    # the other App's registration survives
    remaining = _get(env, "/admin/tenants").json()["tenants"]
    assert [row["app"] for row in remaining] == [OTHER_APP_ID]

    # revocation is immediate: the old signed request is dead (PLAN §3.4)
    stale = do_push(env.client, push_payload(enrolled), token, enrolled.private_key)
    assert stale.status_code == 401
    assert stale.json() == {"error": "unknown_tenant"}


def test_revoke_without_app_removes_every_registration(env) -> None:
    register_tenant(env.client, TENANT_ID, APP_ID)
    register_tenant(env.client, TENANT_ID, OTHER_APP_ID)
    response = _post(env, "/admin/tenants/revoke", {"tenant": TENANT_ID})
    assert response.status_code == 200
    assert response.json() == {"revoked": 2}
    assert _get(env, "/admin/tenants").json() == {"tenants": []}


def test_revoke_unknown_tenant_404(env) -> None:
    response = _post(env, "/admin/tenants/revoke", {"tenant": "ghost.example.com", "app": APP_ID})
    assert response.status_code == 404
    assert response.json() == {"error": "unknown_tenant"}


# -- POST /admin/tenants/reissue -----------------------------------------------------


def test_reissue_rotates_token_preserving_enrollment(env) -> None:
    enrolled = enroll(env)
    old_token = enrolled.token

    response = _post(env, "/admin/tenants/reissue", {"tenant": TENANT_ID, "app": APP_ID})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"tenant", "app", "token"}
    assert body["tenant"] == TENANT_ID
    assert body["app"] == APP_ID
    new_token = body["token"]
    assert new_token != old_token
    assert new_token.startswith("tnt_")

    stale = do_push(env.client, push_payload(enrolled), old_token, enrolled.private_key)
    assert stale.status_code == 401
    assert stale.json() == {"error": "unknown_tenant"}

    # pubkey and grant survive the rotation: a push with the new token is accepted
    fresh = do_push(env.client, push_payload(enrolled), new_token, enrolled.private_key)
    assert fresh.status_code == 200, fresh.text
    assert fresh.json()["result"] == "accepted"


def test_reissue_unknown_tenant_404(env) -> None:
    response = _post(env, "/admin/tenants/reissue", {"tenant": "ghost.example.com", "app": APP_ID})
    assert response.status_code == 404
    assert response.json() == {"error": "unknown_tenant"}


def test_reissue_requires_app(env) -> None:
    register_tenant(env.client)
    response = _post(env, "/admin/tenants/reissue", {"tenant": TENANT_ID})
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_request"


# -- denylist ------------------------------------------------------------------------


def test_denylist_empty(env) -> None:
    response = _get(env, "/admin/denylist")
    assert response.status_code == 200
    assert response.json() == {"entries": []}


def test_denylist_add_defaults_to_one_day(clock, env) -> None:
    response = _post(env, "/admin/denylist", {"key": JTI_KEY})
    assert response.status_code == 200
    assert response.json() == {"key": JTI_KEY, "expires": int(clock.t) + 86400}

    listing = _get(env, "/admin/denylist")
    assert listing.json() == {"entries": [{"key": JTI_KEY, "expires": int(clock.t) + 86400}]}

    # expiry is enforced at read time: past-expiry entries drop out
    clock.advance(86401)
    after = _get(env, "/admin/denylist")
    assert after.json() == {"entries": []}


def test_denylist_explicit_expiry_accepted(clock, env) -> None:
    expires = int(clock.t) + 7200
    response = _post(env, "/admin/denylist", {"key": DIGEST_KEY, "expires": expires})
    assert response.status_code == 200
    assert response.json() == {"key": DIGEST_KEY, "expires": expires}
    entries = _get(env, "/admin/denylist").json()["entries"]
    assert entries == [{"key": DIGEST_KEY, "expires": expires}]


def test_denylist_rejects_past_expiry(clock, env) -> None:
    response = _post(env, "/admin/denylist", {"key": DIGEST_KEY, "expires": int(clock.t) - 1})
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_expiry"}
    assert _get(env, "/admin/denylist").json() == {"entries": []}


@pytest.mark.parametrize(
    "key",
    ["short", "sha256:xyz", "not a valid key!!", "x" * 200],
    ids=["too-short", "bad-digest", "bad-shape", "too-long"],
)
def test_denylist_rejects_invalid_key_shape(env, key: str) -> None:
    response = _post(env, "/admin/denylist", {"key": key})
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "invalid_request"
    assert all(item["loc"] == ["body", "key"] for item in body["detail"])


def test_denylist_accepts_digest_and_jti_key_shapes(clock, env) -> None:
    for key in (JTI_KEY, DIGEST_KEY):
        response = _post(env, "/admin/denylist", {"key": key})
        assert response.status_code == 200, response.text
        assert response.json() == {"key": key, "expires": int(clock.t) + 86400}
    entries = _get(env, "/admin/denylist").json()["entries"]
    assert {entry["key"] for entry in entries} == {JTI_KEY, DIGEST_KEY}
    assert all(entry["expires"] == int(clock.t) + 86400 for entry in entries)


# -- GET /admin/logs ------------------------------------------------------------------


def test_logs_empty_fresh_instance(env) -> None:
    response = _get(env, "/admin/logs")
    assert response.status_code == 200
    assert response.json() == {"events": []}


def test_logs_records_redacted_events(clock, env) -> None:
    token = register_tenant(env.client)
    assert env.client.get("/nope").status_code == 404
    assert env.client.post("/v1/register", json={"app": APP_ID}).status_code == 422

    response = _get(env, "/admin/logs")
    assert response.status_code == 200
    events = response.json()["events"]
    # the logs request itself is recorded only after its body is built
    assert [event["status"] for event in events] == [201, 404, 422]
    assert [event["code"] for event in events] == ["ok", "not_found", "invalid_request"]
    assert [event["path"] for event in events] == ["/v1/register", "<unmatched>", "/v1/register"]
    for event in events:
        assert set(event) == {"ts", "status", "code", "path", "latencyMs"}
        assert isinstance(event["ts"], int)
        assert isinstance(event["latencyMs"], float)
    assert token not in response.text


def test_logs_errors_only_filter(clock, env) -> None:
    register_tenant(env.client)
    env.client.get("/nope")
    env.client.post("/v1/register", json={"app": APP_ID})

    response = _get(env, "/admin/logs", params={"errors": "true"})
    events = response.json()["events"]
    assert [event["status"] for event in events] == [404, 422]
    assert all(event["status"] >= 400 for event in events)


def test_logs_since_filter(clock, env) -> None:
    register_tenant(env.client)  # ts = clock.t
    clock.advance(10)
    env.client.get("/nope")  # ts = clock.t + 10

    later = _get(env, "/admin/logs", params={"since": int(clock.t) - 5})
    assert [event["status"] for event in later.json()["events"]] == [404]

    future = _get(env, "/admin/logs", params={"since": int(clock.t) + 100})
    assert future.json() == {"events": []}


# -- privacy sweep ---------------------------------------------------------------------


def test_admin_responses_never_contain_secret_material(env) -> None:
    token = register_tenant(env.client)
    enrolled = enroll(env, token=token)
    pushed = do_push(env.client, push_payload(enrolled), token, enrolled.private_key)
    assert pushed.status_code == 200

    # (/admin/tenants/reissue excluded: it deliberately mints a fresh token)
    paths = [
        "/admin/status",
        "/admin/tenants",
        f"/admin/tenants/verify?tenant={TENANT_ID}",
        "/admin/denylist",
        "/admin/logs",
    ]
    bodies: list[str] = []
    for path in paths:
        response = _get(env, path)
        assert response.status_code == 200, path
        bodies.append(response.text)

    for secret in (token, enrolled.grant, enrolled.destination):
        for body_text in bodies:
            assert secret not in body_text
