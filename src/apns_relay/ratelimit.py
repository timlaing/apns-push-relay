"""Per-IP sliding-window rate limiting for unauthenticated endpoints.

nginx ``limit_req`` is the outer layer (deploy/nginx.conf.template); these
bounds hold even if the relay is reached directly on the internal network.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from fastapi import Request

REGISTER_LIMIT = (10, 60.0)  # (count, window seconds) per IP per route class
ENROLL_LIMIT = (10, 60.0)


@dataclass
class RateLimiter:
    _hits: dict[str, deque[float]] = field(default_factory=dict)

    def allow(self, key: str, limit: int, window: float, now: float) -> bool:
        hits = self._hits.setdefault(key, deque())
        cutoff = now - window
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= limit:
            return False
        hits.append(now)
        return True

    def prune(self, now: float) -> None:
        """Drop keys with no recent hits so the map cannot accumulate."""
        stale = [key for key, hits in self._hits.items() if not hits or hits[-1] <= now - 600]
        for key in stale:
            self._hits.pop(key, None)


def client_ip(request: Request) -> str:
    """Last X-Forwarded-For entry — nginx appends the real client address on
    the one hop that reaches the relay, so trailing spoofed entries are
    discarded. Falls back to the direct peer when the header is absent."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"
