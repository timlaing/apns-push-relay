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
    return [
        _QuietServer(uvicorn.Config(admin, host="0.0.0.0", port=ADMIN_PORT)),
        _QuietServer(uvicorn.Config(public, host="0.0.0.0", port=PUBLIC_PORT)),
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
