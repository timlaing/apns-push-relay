"""Metrics, event log, per-IP rate limiter and X-Forwarded-For parsing."""

from __future__ import annotations

from collections import deque
from typing import Any

from starlette.datastructures import Headers
from starlette.requests import Request

from apns_relay.metrics import EventLog, Metrics
from apns_relay.ratelimit import RateLimiter, client_ip

# -- Metrics --------------------------------------------------------------------


def test_inc_defaults_and_amount() -> None:
    metrics = Metrics()
    metrics.inc("pushes")
    metrics.inc("pushes")
    metrics.inc("pushes", amount=3)
    assert metrics.snapshot() == {"pushes": {"": 5}}


def test_inc_with_label() -> None:
    metrics = Metrics()
    metrics.inc("pushes", "accepted")
    metrics.inc("pushes", "rejected")
    metrics.inc("pushes", "accepted")
    assert metrics.snapshot() == {"pushes": {"accepted": 2, "rejected": 1}}


def test_snapshot_is_a_copy() -> None:
    metrics = Metrics()
    metrics.inc("pushes", "accepted")
    snapshot = metrics.snapshot()
    snapshot["pushes"]["accepted"] = 99
    snapshot["new-metric"] = {"": 1}
    assert metrics.snapshot() == {"pushes": {"accepted": 1}}


def test_render_prometheus_label_and_plain() -> None:
    metrics = Metrics()
    metrics.inc("pushes", "accepted", 2)
    metrics.inc("pushes", "rejected")
    metrics.inc("starts")
    rendered = metrics.render_prometheus()
    assert rendered == (
        "# TYPE relay_pushes counter\n"
        'relay_pushes{label="accepted"} 2\n'
        'relay_pushes{label="rejected"} 1\n'
        "# TYPE relay_starts counter\n"
        "relay_starts 1\n"
    )


def test_render_prometheus_sorted_metric_names() -> None:
    metrics = Metrics()
    metrics.inc("zebra")
    metrics.inc("alpha")
    lines = metrics.render_prometheus().splitlines()
    assert lines[0] == "# TYPE relay_alpha counter"
    assert lines[2] == "# TYPE relay_zebra counter"


def test_render_prometheus_empty() -> None:
    # No metrics → just the trailing newline
    assert Metrics().render_prometheus() == "\n"


# -- EventLog -------------------------------------------------------------------


def record(log: EventLog, ts: float, status: int = 200, code: str = "ok") -> None:
    log.record(ts=ts, path="/v1/push", status=status, code=code, latency_ms=1.23456)


def test_record_entry_shape() -> None:
    log = EventLog()
    record(log, 1_800_000_000.7, status=429, code="rate_limited")
    entry = log.recent()[0]
    assert entry == {
        "ts": 1_800_000_000,  # truncated to int
        "path": "/v1/push",
        "status": 429,
        "code": "rate_limited",
        "latencyMs": 1.23,
    }


def test_recent_filters_since() -> None:
    log = EventLog()
    for ts in (100.4, 200.4, 300.4):
        record(log, ts)
    # ts is truncated to int on record; since compares against the int
    assert [e["ts"] for e in log.recent(since=200)] == [200, 300]
    assert [e["ts"] for e in log.recent(since=200.5)] == [300]
    assert [e["ts"] for e in log.recent(since=201)] == [300]
    assert len(log.recent(since=0)) == 3


def test_recent_errors_only() -> None:
    log = EventLog()
    record(log, 100, status=200)
    record(log, 200, status=404, code="not_found")
    record(log, 300, status=500, code="boom")
    errors = log.recent(errors_only=True)
    assert [e["status"] for e in errors] == [404, 500]


def test_recent_since_and_errors_only_combined() -> None:
    log = EventLog()
    record(log, 100, status=500, code="old")
    record(log, 200, status=200)
    record(log, 300, status=429, code="rate_limited")
    entries = log.recent(since=150, errors_only=True)
    assert [e["code"] for e in entries] == ["rate_limited"]


def test_maxlen_eviction() -> None:
    log = EventLog(maxlen=3)
    for ts in range(100, 106):
        record(log, float(ts))
    entries = log.recent()
    assert len(entries) == 3
    assert [e["ts"] for e in entries] == [103, 104, 105]


def test_recent_empty_log() -> None:
    assert EventLog().recent() == []


# -- RateLimiter ----------------------------------------------------------------


def make_request(
    headers: dict[str, str] | None = None, client: tuple[str, int] | None = ("203.0.113.9", 44321)
) -> Request:
    raw = Headers(headers or {})
    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": "/v1/register",
        "headers": raw.raw,
        "client": client,
    }
    return Request(scope)


def test_allow_up_to_limit() -> None:
    limiter = RateLimiter()
    for i in range(3):
        assert limiter.allow("ip-1", 3, 60.0, 100.0 + i) is True
    assert limiter.allow("ip-1", 3, 60.0, 103.0) is False


def test_allow_is_per_key() -> None:
    limiter = RateLimiter()
    assert limiter.allow("ip-1", 1, 60.0, 100.0) is True
    assert limiter.allow("ip-1", 1, 60.0, 100.0) is False
    assert limiter.allow("ip-2", 1, 60.0, 100.0) is True


def test_window_eviction_frees_slot() -> None:
    limiter = RateLimiter()
    assert limiter.allow("ip-1", 1, 60.0, 100.0) is True
    assert limiter.allow("ip-1", 1, 60.0, 159.9) is False  # still inside window
    assert limiter.allow("ip-1", 1, 60.0, 160.0) is True  # hit at exactly cutoff evicted


def test_prune_drops_stale_and_empty_keys() -> None:
    limiter = RateLimiter()
    limiter.allow("stale", 5, 60.0, 100.0)
    limiter.allow("fresh", 5, 60.0, 700.0)
    # "empty": deque exists but holds no hits (window fully evicted)
    limiter._hits["empty"] = deque()
    limiter.prune(700.0)
    assert "stale" not in limiter._hits
    assert "empty" not in limiter._hits
    assert "fresh" in limiter._hits


def test_prune_noop_when_all_recent() -> None:
    limiter = RateLimiter()
    limiter.allow("ip-1", 5, 60.0, 700.0)
    limiter.prune(700.0)
    assert "ip-1" in limiter._hits


# -- client_ip --------------------------------------------------------------------


def test_client_ip_last_forwarded_entry() -> None:
    request = make_request({"x-forwarded-for": "198.51.100.7, 203.0.113.9"})
    assert client_ip(request) == "203.0.113.9"


def test_client_ip_strips_whitespace() -> None:
    request = make_request({"x-forwarded-for": "198.51.100.7,203.0.113.9 , 192.0.2.1"})
    assert client_ip(request) == "192.0.2.1"


def test_client_ip_single_entry() -> None:
    request = make_request({"x-forwarded-for": "198.51.100.7"})
    assert client_ip(request) == "198.51.100.7"


def test_client_ip_falls_back_to_peer() -> None:
    assert client_ip(make_request()) == "203.0.113.9"


def test_client_ip_no_client_scope() -> None:
    request = make_request(client=None)
    assert client_ip(request) == "unknown"


def test_client_ip_empty_header_falls_back() -> None:
    assert client_ip(make_request({"x-forwarded-for": ""})) == "203.0.113.9"
