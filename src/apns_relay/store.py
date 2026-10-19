"""SQLite persistence: tenants, single-use nonces, quotas, denylist, challenges.

Design rules (PLAN §2, enrollment-spec §2.1/§2.6):
- No device table. Destination tokens are never persisted raw — only SHA-256
  digests, and only in short-lived challenge rows.
- ``last_seen`` is shared across a tenant's per-App registrations: any
  authenticated request refreshes every row for that tenant id; registration
  itself does not refresh it (it inherits the tenant's current value).
- 30-day non-use expiry hard-deletes the whole tenant (all its per-App
  registrations), cascading usage rows.
- Denylist entries carry their own natural purge time (the grant's ``exp``).
- WAL mode; single writer (uvicorn --workers 1); mutations are transactions.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

NONCE_TTL = 600  # 10-minute single-use replay window (PLAN §3.2)
DAILY_WINDOW = 86400
MINUTE_WINDOW = 60
TENANT_TTL = 30 * 86400  # PLAN §3.4

TENANT_BUCKET = "_t"  # usage bucket for tenant-wide burst/daily counts

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants(
    id            TEXT NOT NULL,
    app           TEXT NOT NULL,
    token_digest  TEXT NOT NULL UNIQUE,
    pubkey        TEXT NOT NULL DEFAULT '',
    registered_at REAL NOT NULL,
    last_seen     REAL NOT NULL,
    PRIMARY KEY(id, app)
);
CREATE TABLE IF NOT EXISTS nonces(
    digest TEXT PRIMARY KEY,
    at     REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS usage(
    id     TEXT NOT NULL,
    app    TEXT NOT NULL,
    bucket TEXT NOT NULL,
    at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS usage_recent ON usage(id, app, at);
CREATE INDEX IF NOT EXISTS usage_bucket ON usage(id, app, bucket, at);
CREATE TABLE IF NOT EXISTS denylist(
    key     TEXT PRIMARY KEY,
    expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges(
    challenge_id   TEXT PRIMARY KEY,
    app            TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    token_digest   TEXT NOT NULL,
    nonce          TEXT NOT NULL,
    server_challenge TEXT NOT NULL,
    environment    TEXT NOT NULL,
    expires_at     REAL NOT NULL
);
"""


@dataclass(frozen=True)
class Tenant:
    id: str
    app: str
    token_digest: str
    pubkey: str
    registered_at: float
    last_seen: float


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    app: str
    tenant_id: str
    token_digest: str
    nonce: str
    server_challenge: str
    environment: str


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(_SCHEMA)
        with contextlib.suppress(OSError):
            os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> Tenant:
        return Tenant(
            id=row["id"],
            app=row["app"],
            token_digest=row["token_digest"],
            pubkey=row["pubkey"],
            registered_at=row["registered_at"],
            last_seen=row["last_seen"],
        )

    # -- tenants -----------------------------------------------------------

    def register_tenant(self, id: str, app: str, digest: str, now: float) -> bool:
        """Create an ``(id, app)`` registration. False if it already exists.

        The new row inherits the tenant's existing shared ``last_seen`` (any
        other App for the same id) so registration never refreshes liveness;
        a brand-new tenant starts at ``now``. ``pubkey`` is set later at
        ``enroll/finish``.
        """
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                prior = db.execute(
                    "SELECT MAX(last_seen) FROM tenants WHERE id=?", (id,)
                ).fetchone()[0]
                db.execute(
                    "INSERT INTO tenants(id, app, token_digest, pubkey,"
                    " registered_at, last_seen) VALUES(?,?,?,?,?,?)",
                    (id, app, digest, "", now, prior if prior is not None else now),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def set_token(self, id: str, app: str, digest: str) -> bool:
        """Rotate a tenant's token. False if the registration is gone."""
        with self.connect() as db:
            cur = db.execute(
                "UPDATE tenants SET token_digest=? WHERE id=? AND app=?",
                (digest, id, app),
            )
        return cur.rowcount > 0

    def set_pubkey(self, id: str, app: str, pubkey: str) -> bool:
        """Set the tenant's Ed25519 signing key — only while unset (TOFU).

        ``enroll/finish`` is unauthenticated by design (App Attest proves the
        device), so the stored key must never be replaced here; the conditional
        write also makes two concurrent first-enrollments safe. False if the
        registration is gone or a key is already set (spec §2.4).
        """
        with self.connect() as db:
            cur = db.execute(
                "UPDATE tenants SET pubkey=? WHERE id=? AND app=? AND pubkey=''",
                (pubkey, id, app),
            )
        return cur.rowcount > 0

    def tenant_by_token(self, digest: str) -> Tenant | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT id, app, token_digest, pubkey, registered_at, last_seen FROM tenants"
                " WHERE token_digest=?",
                (digest,),
            ).fetchone()
        return None if row is None else self._row(row)

    def tenant(self, id: str, app: str) -> Tenant | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT id, app, token_digest, pubkey, registered_at, last_seen FROM tenants"
                " WHERE id=? AND app=?",
                (id, app),
            ).fetchone()
        return None if row is None else self._row(row)

    def touch(self, id: str, now: float) -> None:
        """Refresh last_seen for EVERY registration of the tenant (shared)."""
        with self.connect() as db:
            db.execute("UPDATE tenants SET last_seen=? WHERE id=?", (now, id))

    def list_tenants(self, app: str | None = None) -> list[Tenant]:
        query = "SELECT id, app, token_digest, pubkey, registered_at, last_seen FROM tenants"
        params: tuple[object, ...] = ()
        if app is not None:
            query += " WHERE app=?"
            params = (app,)
        query += " ORDER BY id, app"
        with self.connect() as db:
            rows = db.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def count_tenants(self) -> int:
        with self.connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM tenants").fetchone()[0])

    def expire_tenants(self, now: float) -> list[str]:
        """Delete tenants idle > 30 days — ALL their per-App registrations.

        Idle is evaluated per tenant (max ``last_seen`` across its rows) so a
        tenant whose rows were created at different times expires as a unit.
        Returns the removed tenant ids (for counting only — never logged).
        """
        cutoff = now - TENANT_TTL
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT id FROM tenants GROUP BY id HAVING MAX(last_seen) < ?",
                (cutoff,),
            ).fetchall()
            removed = [r["id"] for r in rows]
            for tenant_id in removed:
                db.execute("DELETE FROM tenants WHERE id=?", (tenant_id,))
                db.execute("DELETE FROM usage WHERE id=?", (tenant_id,))
        return removed

    def delete_tenant(self, id: str, app: str | None = None) -> int:
        """Admin revoke: remove one registration, or every registration of
        the tenant when ``app`` is omitted. Returns rows removed."""
        with self.connect() as db:
            if app is None:
                cur = db.execute("DELETE FROM tenants WHERE id=?", (id,))
                db.execute("DELETE FROM usage WHERE id=?", (id,))
            else:
                cur = db.execute("DELETE FROM tenants WHERE id=? AND app=?", (id, app))
                db.execute("DELETE FROM usage WHERE id=? AND app=?", (id, app))
        return cur.rowcount

    # -- nonces -------------------------------------------------------------

    def claim_nonce(self, digest: str, now: float) -> bool:
        """Atomically claim a nonce. False on replay within the window."""
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("DELETE FROM nonces WHERE at<?", (now - NONCE_TTL,))
                if db.execute("SELECT 1 FROM nonces WHERE digest=?", (digest,)).fetchone():
                    return False
                db.execute("INSERT INTO nonces(digest, at) VALUES(?,?)", (digest, now))
        except sqlite3.IntegrityError:
            return False
        return True

    def prune_nonces(self, now: float) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM nonces WHERE at<?", (now - NONCE_TTL,))

    # -- quotas ---------------------------------------------------------------

    def check_and_record(
        self,
        id: str,
        app: str,
        blind: str,
        now: float,
        *,
        burst_per_min: int,
        daily: int,
        token_burst_per_min: int,
    ) -> str | None:
        """Enforce + record one push. Returns None or a failure code.

        Three limits, all charged per (tenant, App):
        - tenant-wide burst (bucket ``_t``) → ``rate_limited``
        - per destination-token burst (bucket = blind index) →
          ``token_rate_limited``
        - tenant-wide daily (bucket ``_t``) → ``quota_exhausted``

        The destination token only appears as a keyed blind index — the
        plaintext token is never stored (PLAN §2).
        """
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            tenant_minute = db.execute(
                "SELECT COUNT(*) FROM usage WHERE id=? AND app=? AND bucket=? AND at>?",
                (id, app, TENANT_BUCKET, now - MINUTE_WINDOW),
            ).fetchone()[0]
            if tenant_minute >= burst_per_min:
                return "rate_limited"
            token_minute = db.execute(
                "SELECT COUNT(*) FROM usage WHERE id=? AND app=? AND bucket=? AND at>?",
                (id, app, blind, now - MINUTE_WINDOW),
            ).fetchone()[0]
            if token_minute >= token_burst_per_min:
                return "token_rate_limited"
            day = db.execute(
                "SELECT COUNT(*) FROM usage WHERE id=? AND app=? AND bucket=? AND at>?",
                (id, app, TENANT_BUCKET, now - DAILY_WINDOW),
            ).fetchone()[0]
            if day >= daily:
                return "quota_exhausted"
            db.execute(
                "INSERT INTO usage(id, app, bucket, at) VALUES(?,?,?,?)",
                (id, app, TENANT_BUCKET, now),
            )
            db.execute(
                "INSERT INTO usage(id, app, bucket, at) VALUES(?,?,?,?)",
                (id, app, blind, now),
            )
        return None

    def usage_count(self, id: str, app: str, now: float) -> int:
        """Pushes charged today (tenant bucket) — for status/quota burn."""
        with self.connect() as db:
            return int(
                db.execute(
                    "SELECT COUNT(*) FROM usage WHERE id=? AND app=? AND bucket=? AND at>?",
                    (id, app, TENANT_BUCKET, now - DAILY_WINDOW),
                ).fetchone()[0]
            )

    def prune_usage(self, now: float) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM usage WHERE at<?", (now - DAILY_WINDOW,))

    # -- denylist (jti or destination-token hash) ------------------------------

    def deny(self, key: str, expires: float) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO denylist(key, expires) VALUES(?,?)",
                (key, expires),
            )

    def is_denied(self, keys: list[str], now: float) -> bool:
        """True if any key (grant jti, or ``sha256:…`` token hash) is listed."""
        if not keys:
            return False
        with self.connect() as db:
            db.execute("DELETE FROM denylist WHERE expires<?", (now,))
            placeholders = ",".join("?" for _ in keys)
            row = db.execute(
                # placeholders are generated `?` only; all values are bound.
                f"SELECT 1 FROM denylist WHERE key IN ({placeholders})",  # noqa: S608
                keys,
            ).fetchone()
        return row is not None

    def list_denied(self, now: float) -> list[tuple[str, float]]:
        with self.connect() as db:
            db.execute("DELETE FROM denylist WHERE expires<?", (now,))
            rows = db.execute("SELECT key, expires FROM denylist ORDER BY key").fetchall()
        return [(r["key"], r["expires"]) for r in rows]

    # -- enrollment challenges --------------------------------------------------

    def put_challenge(
        self,
        challenge_id: str,
        app: str,
        tenant_id: str,
        token_digest: str,
        nonce: str,
        server_challenge: str,
        environment: str,
        expires_at: float,
    ) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO challenges(challenge_id, app, tenant_id,"
                " token_digest, nonce, server_challenge, environment, expires_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (
                    challenge_id,
                    app,
                    tenant_id,
                    token_digest,
                    nonce,
                    server_challenge,
                    environment,
                    expires_at,
                ),
            )

    def pop_challenge(self, challenge_id: str, now: float) -> tuple[Challenge | None, str | None]:
        """Atomically fetch-and-delete a challenge (single-use, even on
        failure). Returns ``(challenge, None)`` or ``(None, fail_code)``."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM challenges WHERE challenge_id=?", (challenge_id,)
            ).fetchone()
            if row is None:
                return None, "unknown_challenge"
            db.execute("DELETE FROM challenges WHERE challenge_id=?", (challenge_id,))
            if row["expires_at"] < now:
                return None, "challenge_expired"
            return (
                Challenge(
                    challenge_id=row["challenge_id"],
                    app=row["app"],
                    tenant_id=row["tenant_id"],
                    token_digest=row["token_digest"],
                    nonce=row["nonce"],
                    server_challenge=row["server_challenge"],
                    environment=row["environment"],
                ),
                None,
            )

    def prune_challenges(self, now: float) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM challenges WHERE expires_at<?", (now,))
