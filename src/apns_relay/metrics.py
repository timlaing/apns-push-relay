"""In-process metrics and a bounded redacted event log.

Privacy rules (PLAN §3.4): metrics and events carry route templates, status
codes, machine error codes and latency only — never tokens, grants, payloads,
tenant ids or destination tokens. The event log feeds ``GET /admin/logs``
(``relay logs``); metrics render Prometheus text at ``GET /metrics``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Metrics:
    """name → label → count. Labels are low-cardinality machine codes only."""

    values: dict[str, dict[str, int]] = field(default_factory=dict)

    def inc(self, name: str, label: str = "", amount: int = 1) -> None:
        bucket = self.values.setdefault(name, {})
        bucket[label] = bucket.get(label, 0) + amount

    def snapshot(self) -> dict[str, dict[str, int]]:
        return {name: dict(labels) for name, labels in self.values.items()}

    def render_prometheus(self) -> str:
        lines: list[str] = []
        for name in sorted(self.values):
            lines.append(f"# TYPE relay_{name} counter")
            for label, count in sorted(self.values[name].items()):
                if label:
                    lines.append(f'relay_{name}{{label="{label}"}} {count}')
                else:
                    lines.append(f"relay_{name} {count}")
        return "\n".join(lines) + "\n"


@dataclass
class EventLog:
    """Bounded deque of redacted request outcomes (outcome/latency/codes)."""

    maxlen: int = 1000
    entries: deque[dict[str, Any]] = field(init=False)

    def __post_init__(self) -> None:
        self.entries = deque(maxlen=self.maxlen)

    def record(self, *, ts: float, path: str, status: int, code: str, latency_ms: float) -> None:
        self.entries.append(
            {
                "ts": int(ts),
                "path": path,
                "status": status,
                "code": code,
                "latencyMs": round(latency_ms, 2),
            }
        )

    def recent(
        self, *, since: float | None = None, errors_only: bool = False
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for entry in self.entries:
            if since is not None and entry["ts"] < since:
                continue
            if errors_only and entry["status"] < 400:
                continue
            out.append(entry)
        return out
