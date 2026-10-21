"""Dual-listener serving (the container run path).

One process, two ports: the admin API on 8000 and the public API on 8001,
built from a single AppState so the metrics, recent-request log and rate
limiter stay global and SQLite keeps its single writer. Compose publishes
only these on host loopback (the CLI's default target is the admin port);
nginx is the public port's client and never routes /admin.

Run as ``python -m apns_relay.serve`` (the image CMD).
"""

from __future__ import annotations

import asyncio
import signal

import uvicorn
from fastapi import FastAPI

from .app import create_listeners

ADMIN_PORT = 8000
PUBLIC_PORT = 8001


class _QuietServer(uvicorn.Server):
    """uvicorn.Server without its per-server signal wiring: one handler
    stops both listeners together (see ``_serve``)."""

    def install_signal_handlers(self) -> None:
        """Signals are wired once in ``_serve``."""


def _servers(admin: FastAPI, public: FastAPI) -> list[uvicorn.Server]:
    # No uvicorn access log: it prints request lines verbatim, and admin
    # query strings carry tenant ids (the app's own event log and metrics
    # carry the operational picture without them — PLAN §3.4).
    config = {"host": "0.0.0.0", "access_log": False}
    return [
        _QuietServer(uvicorn.Config(admin, port=ADMIN_PORT, **config)),
        _QuietServer(uvicorn.Config(public, port=PUBLIC_PORT, **config)),
    ]


async def _serve(admin: FastAPI, public: FastAPI) -> None:
    servers = _servers(admin, public)
    loop = asyncio.get_running_loop()

    def stop(_signum: int) -> None:
        for server in servers:
            server.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop, sig)
    await asyncio.gather(*(server.serve() for server in servers))


def main() -> None:
    admin, public = create_listeners()
    asyncio.run(_serve(admin, public))


if __name__ == "__main__":
    main()
