"""End-to-end smoke: register → enroll → push → admin sees it."""

from __future__ import annotations

from tests.conftest import (
    ADMIN_TOKEN,
    BUNDLE_ID,
    TENANT_ID,
    do_push,
    enroll,
    push_payload,
    register_tenant,
)


def test_full_flow(env) -> None:
    token = register_tenant(env.client)
    enrolled = enroll(env, token=token)
    assert enrolled.consent["tenant"] == TENANT_ID
    assert enrolled.consent["appDisplayName"] == "Test App"

    response = do_push(env.client, push_payload(enrolled), token, enrolled.private_key)
    assert response.status_code == 200, response.text
    assert response.json() == {"result": "accepted", "apnsId": "APNS-ID-OK", "detail": None}

    call = env.apns.calls[-1]
    assert call["headers"]["apns-push-type"] == "alert"
    assert call["headers"]["apns-topic"] == BUNDLE_ID
    assert call["headers"]["apns-priority"] == "10"
    # The challenge push was accepted on sandbox first, so the grant (and all
    # pushes for it) use that environment — never a caller-chosen one.
    assert call["url"] == f"https://api.sandbox.push.apple.com/3/device/{enrolled.destination}"

    status = env.client.get("/admin/status", headers={"authorization": f"Bearer {ADMIN_TOKEN}"})
    assert status.status_code == 200
    body = status.json()
    assert body["status"] == "ok"
    assert body["tenants"] == 1
    assert body["metrics"]["pushes_total"]["accepted"] == 1
