"""Payload translation: allowlists, caps, sealed rules, priority mapping."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from apns_relay.config import CapsConfig
from apns_relay.payload import PayloadError, build_payload, priority_for

CAPS = CapsConfig(title=64, subtitle=64, body=200, sealed=16, category=32, thread=64, background=32)
ALERT = {"title": "t", "body": "b"}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# -- alert ----------------------------------------------------------------------


def test_alert_build() -> None:
    payload = build_payload("alert", {"alert": ALERT}, CAPS)
    assert payload == {"aps": {"alert": {"title": "t", "body": "b"}}}


def test_alert_all_fields() -> None:
    alert = {
        "title": "t",
        "subtitle": "s",
        "body": "b",
        "category": "c",
        "thread": "th",
        "sound": "default",
    }
    payload = build_payload("alert", {"alert": alert}, CAPS)
    assert payload["aps"]["alert"] == alert


@pytest.mark.parametrize(
    ("field", "limit"),
    [("title", 64), ("subtitle", 64), ("body", 200), ("category", 32), ("thread", 64)],
)
def test_alert_field_caps(field: str, limit: int) -> None:
    ok = {field: "x" * limit}
    assert build_payload("alert", {"alert": ok}, CAPS)["aps"]["alert"] == ok
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": {field: "x" * (limit + 1)}}, CAPS)
    assert exc.value.code == f"{field}_too_long"


def test_alert_sound_capped_by_category() -> None:
    # sound uses caps.category as its limit
    assert build_payload("alert", {"alert": {"sound": "x" * 32}}, CAPS)
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": {"sound": "x" * 33}}, CAPS)
    assert exc.value.code == "sound_too_long"


def test_alert_cap_counts_bytes_not_chars() -> None:
    # 4 chars but 8 UTF-8 bytes against a 6-byte cap
    caps = CapsConfig(title=6)
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": {"title": "éééé"}}, caps)
    assert exc.value.code == "title_too_long"
    assert build_payload("alert", {"alert": {"title": "éé"}}, caps)


@pytest.mark.parametrize("bad", [5, "text", ["x"], None])
def test_alert_not_a_dict(bad: Any) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": bad}, CAPS)
    assert exc.value.code == "invalid_payload"


def test_alert_empty_dict() -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": {}}, CAPS)
    assert exc.value.code == "invalid_payload"


@pytest.mark.parametrize("bad", [{"zzz": 1}, {"title": "t", "aaa": 1}])
def test_alert_unknown_fields(bad: dict[str, Any]) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": bad}, CAPS)
    assert exc.value.code == "unknown_field"
    assert exc.value.detail is not None
    assert exc.value.detail.startswith("content.alert.")


@pytest.mark.parametrize("bad", [5, 3.5, None, True])
def test_alert_field_not_string(bad: Any) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": {"title": bad}}, CAPS)
    assert exc.value.code == "invalid_payload"


# -- background ------------------------------------------------------------------


def test_background_build() -> None:
    payload = build_payload("background", {"background": {"payload": {"a": 1}}}, CAPS)
    assert payload == {"aps": {"content-available": 1}, "background": {"a": 1}}


def test_background_list_payload() -> None:
    payload = build_payload("background", {"background": {"payload": [1, 2]}}, CAPS)
    assert payload["background"] == [1, 2]


@pytest.mark.parametrize("bad", ["str", 5, None, True])
def test_background_payload_wrong_type(bad: Any) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("background", {"background": {"payload": bad}}, CAPS)
    assert exc.value.code == "invalid_payload"


def test_background_payload_over_cap() -> None:
    blob = {"k": "x" * 100}
    with pytest.raises(PayloadError) as exc:
        build_payload("background", {"background": {"payload": blob}}, CAPS)
    assert exc.value.code == "background_too_long"


def test_background_unknown_field() -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("background", {"background": {"payload": {}, "oops": 1}}, CAPS)
    assert exc.value.code == "unknown_field"
    assert exc.value.detail == "content.background.oops"


@pytest.mark.parametrize("bad", [5, "x", ["payload"]])
def test_background_not_a_dict(bad: Any) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("background", {"background": bad}, CAPS)
    assert exc.value.code == "invalid_payload"


@pytest.mark.parametrize("bad", [5, "x", ["event"]])
def test_live_activity_not_a_dict(bad: Any) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("liveActivity", {"liveActivity": bad}, CAPS)
    assert exc.value.code == "invalid_payload"


def test_background_json_compact_encoding() -> None:
    # ensure_ascii=False + compact separators: {"a": "é"} is 10 bytes
    caps = CapsConfig(background=10)
    assert build_payload("background", {"background": {"payload": {"a": "é"}}}, caps)
    with pytest.raises(PayloadError):
        build_payload("background", {"background": {"payload": {"a": "éé"}}}, caps)


# -- liveActivity ----------------------------------------------------------------


def test_live_activity_start_minimal() -> None:
    payload = build_payload("liveActivity", {"liveActivity": {"event": "start"}}, CAPS)
    assert payload == {"aps": {"event": "start"}}


def test_live_activity_full() -> None:
    inner = {
        "event": "update",
        "timestamp": 1_800_000_000,
        "state": {"k": "v"},
        "staleDate": 1_800_003_600,
        "dismissalDate": 1_800_007_200,
    }
    payload = build_payload("liveActivity", {"liveActivity": inner}, CAPS)
    assert payload == {
        "aps": {
            "event": "update",
            "timestamp": 1_800_000_000,
            "state": {"k": "v"},
            "staleDate": 1_800_003_600,
            "dismissalDate": 1_800_007_200,
        }
    }


@pytest.mark.parametrize("event", ["start", "update", "end"])
def test_live_activity_events(event: str) -> None:
    payload = build_payload("liveActivity", {"liveActivity": {"event": event}}, CAPS)
    assert payload["aps"]["event"] == event


@pytest.mark.parametrize("event", ["begin", 5, None])
def test_live_activity_invalid_event(event: Any) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("liveActivity", {"liveActivity": {"event": event}}, CAPS)
    assert exc.value.code == "invalid_payload"


def test_live_activity_missing_event() -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("liveActivity", {"liveActivity": {"timestamp": 1}}, CAPS)
    assert exc.value.code == "invalid_payload"


@pytest.mark.parametrize("field", ["timestamp", "staleDate", "dismissalDate"])
@pytest.mark.parametrize("bad", ["1", 1.5, True, None])
def test_live_activity_int_fields(field: str, bad: Any) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("liveActivity", {"liveActivity": {"event": "update", field: bad}}, CAPS)
    assert exc.value.code == "invalid_payload"


@pytest.mark.parametrize("bad", ["state", 5, None])
def test_live_activity_state_wrong_type(bad: Any) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("liveActivity", {"liveActivity": {"event": "update", "state": bad}}, CAPS)
    assert exc.value.code == "invalid_payload"


def test_live_activity_state_over_cap() -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload(
            "liveActivity",
            {"liveActivity": {"event": "update", "state": {"k": "x" * 100}}},
            CAPS,
        )
    assert exc.value.code == "background_too_long"


def test_live_activity_unknown_field() -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("liveActivity", {"liveActivity": {"event": "end", "zzz": 1}}, CAPS)
    assert exc.value.code == "unknown_field"
    assert exc.value.detail == "content.liveActivity.zzz"


# -- sealed ----------------------------------------------------------------------


def test_sealed_passthrough() -> None:
    blob = b64(b"opaque-encrypted")
    payload = build_payload("alert", {"alert": ALERT, "sealed": blob}, CAPS)
    assert payload["sealed"] == blob
    assert payload["aps"]["alert"] == ALERT


def test_sealed_exact_cap() -> None:
    blob = b64(b"x" * 16)
    assert build_payload("alert", {"alert": ALERT, "sealed": blob}, CAPS)["sealed"] == blob


def test_sealed_over_cap() -> None:
    blob = b64(b"x" * 17)
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": ALERT, "sealed": blob}, CAPS)
    assert exc.value.code == "sealed_too_long"


def test_sealed_invalid_b64() -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": ALERT, "sealed": "not base64!!"}, CAPS)
    assert exc.value.code == "invalid_payload"


@pytest.mark.parametrize("bad", [b"x", 5, {"k": "v"}, None])
def test_sealed_not_a_string(bad: Any) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": ALERT, "sealed": bad}, CAPS)
    assert exc.value.code == "invalid_payload"


# -- top level --------------------------------------------------------------------


def test_unknown_top_level_field() -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"alert": ALERT, "nope": 1}, CAPS)
    assert exc.value.code == "unknown_field"
    assert exc.value.detail == "content.nope"


def test_multiple_unknown_fields_reports_sorted_first() -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload("alert", {"zzz": 1, "alert": ALERT, "aaa": 2}, CAPS)
    assert exc.value.detail == "content.aaa"


@pytest.mark.parametrize("kind", ["sms", "Alert", "", "alerts"])
def test_invalid_kind(kind: str) -> None:
    with pytest.raises(PayloadError) as exc:
        build_payload(kind, {}, CAPS)
    assert exc.value.code == "invalid_payload"


@pytest.mark.parametrize(
    ("kind", "expected"), [("alert", 10), ("background", 5), ("liveActivity", 5)]
)
def test_priority_for(kind: str, expected: int) -> None:
    assert priority_for(kind) == expected


def test_priority_for_unknown_kind() -> None:
    with pytest.raises(KeyError):
        priority_for("sms")
