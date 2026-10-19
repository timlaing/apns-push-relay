"""Build APNs payloads from the generic structured request (PLAN §3.2).

``content`` is keyed by kind, each section carrying only that kind's fields,
plus a kind-independent ``sealed`` blob:

    content = {
      "alert":        {title, subtitle, body, category, thread, sound},
      "background":   {payload: <structured ≤ caps.background bytes>},
      "liveActivity": {event, timestamp, state, staleDate, dismissalDate},
      "sealed":       "<opaque base64 — relay passes it blind>",
    }

Every section is an explicit allowlist: unknown keys are rejected, never
passed through to APNs (the relay is a whitelist translator, notifications.md
§"Proposed REST interface"). Text fields are length-capped against the App's
configured ``caps``. The ``sealed`` blob is encrypted app↔backend at pairing
time — the relay never inspects or logs it.
"""

from __future__ import annotations

import base64
import binascii
import json

from .config import CapsConfig

PRIORITY_BY_KIND = {"alert": 10, "background": 5, "liveActivity": 5}
# Push-to-start ("start") is deferred — PLAN §1: it requires
# attributes-type/attributes, which the structured content does not carry.
LA_EVENTS = ("update", "end")

TOP_LEVEL_FIELDS = ("alert", "background", "liveActivity", "sealed")
ALERT_FIELDS = ("title", "subtitle", "body", "category", "thread", "sound")
BACKGROUND_FIELDS = ("payload",)
LA_FIELDS = ("event", "timestamp", "state", "staleDate", "dismissalDate")


class PayloadError(ValueError):
    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def _reject_unknown(section: dict, allowed: tuple[str, ...], where: str) -> None:
    unknown = set(section) - set(allowed)
    if unknown:
        key = sorted(unknown)[0]
        raise PayloadError("unknown_field", f"{where}.{key}")


def _capped(value: str, limit: int, field: str, caps: CapsConfig) -> str:
    if not isinstance(value, str):
        raise PayloadError("invalid_payload")
    if len(value.encode()) > limit:
        raise PayloadError(f"{field}_too_long")
    return value


def _cap_alert(alert: dict, caps: CapsConfig) -> dict:
    _reject_unknown(alert, ALERT_FIELDS, "content.alert")
    out: dict = {}
    for field in ALERT_FIELDS:
        if field in alert:
            limit = caps.category if field == "sound" else getattr(caps, field)
            out[field] = _capped(alert[field], limit, field, caps)
    if not out:
        raise PayloadError("invalid_payload")
    return out


def _build_alert(content: dict, caps: CapsConfig) -> dict:
    """Wire alert text into ``aps.alert``; category/thread/sound live at the
    ``aps`` level where APNs actually reads them (anything else is dropped by
    APNs silently, so the relay must translate, not copy)."""
    alert = content.get("alert")
    if not isinstance(alert, dict):
        raise PayloadError("invalid_payload")
    fields = _cap_alert(alert, caps)
    aps: dict = {}
    text = {k: fields[k] for k in ("title", "subtitle", "body") if k in fields}
    if text:
        aps["alert"] = text
    if "category" in fields:
        aps["category"] = fields["category"]
    if "thread" in fields:
        aps["thread-id"] = fields["thread"]
    if "sound" in fields:
        aps["sound"] = fields["sound"]
    return {"aps": aps}


def _build_background(content: dict, caps: CapsConfig) -> dict:
    inner = content.get("background")
    if not isinstance(inner, dict):
        raise PayloadError("invalid_payload")
    _reject_unknown(inner, BACKGROUND_FIELDS, "content.background")
    blob = inner.get("payload")
    if not isinstance(blob, (dict, list)):
        raise PayloadError("invalid_payload")
    encoded = json.dumps(blob, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode()) > caps.background:
        raise PayloadError("background_too_long")
    return {"aps": {"content-available": 1}, "background": blob}


def _build_live_activity(content: dict, caps: CapsConfig) -> dict:
    inner = content.get("liveActivity")
    if not isinstance(inner, dict):
        raise PayloadError("invalid_payload")
    _reject_unknown(inner, LA_FIELDS, "content.liveActivity")
    event = inner.get("event")
    if event not in LA_EVENTS:
        raise PayloadError("invalid_payload")
    # ActivityKit reads hyphenated aps keys; the wire format keeps camelCase
    # and the relay translates. Push-to-start is deferred (PLAN §1): it needs
    # attributes-type/attributes, which this API does not carry — reject
    # rather than accept a push APNs would drop.
    aps: dict = {"event": event}
    timestamp = inner.get("timestamp")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        raise PayloadError("invalid_payload")
    aps["timestamp"] = timestamp
    for field, apns_key in (("staleDate", "stale-date"), ("dismissalDate", "dismissal-date")):
        if field in inner:
            if not isinstance(inner[field], int) or isinstance(inner[field], bool):
                raise PayloadError("invalid_payload")
            aps[apns_key] = inner[field]
    if "state" in inner:
        state = inner["state"]
        if not isinstance(state, (dict, list)):
            raise PayloadError("invalid_payload")
        encoded = json.dumps(state, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode()) > caps.background:
            raise PayloadError("background_too_long")
        aps["content-state"] = state
    return {"aps": aps}


def build_payload(kind: str, content: dict, caps: CapsConfig) -> dict:
    """Translate validated structured ``content`` into an APNs payload dict."""
    _reject_unknown(content, TOP_LEVEL_FIELDS, "content")
    if kind == "alert":
        payload = _build_alert(content, caps)
    elif kind == "background":
        payload = _build_background(content, caps)
    elif kind == "liveActivity":
        payload = _build_live_activity(content, caps)
    else:
        raise PayloadError("invalid_payload")

    if "sealed" in content:
        sealed = content["sealed"]
        if not isinstance(sealed, str):
            raise PayloadError("invalid_payload")
        try:
            raw = base64.b64decode(sealed, validate=True)
        except (binascii.Error, ValueError):
            raise PayloadError("invalid_payload") from None
        if len(raw) > caps.sealed:
            raise PayloadError("sealed_too_long")
        # Passed through verbatim — never decoded, never logged.
        payload["sealed"] = sealed
    return payload


def priority_for(kind: str) -> int:
    return PRIORITY_BY_KIND[kind]
