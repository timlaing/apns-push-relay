"""SQLite store: tenants, nonces, quotas, denylist, challenges, expiry."""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from apns_relay.store import (
    DAILY_WINDOW,
    MINUTE_WINDOW,
    NONCE_TTL,
    TENANT_TTL,
    Store,
)

ID = "hooks.example.com"
OTHER_ID = "other.example.com"
APP = "test-app"
APP2 = "second-app"
DIGEST = "a" * 64
DIGEST2 = "b" * 64
BLIND = "blind-index-1"
T0 = 1_800_000_000.0


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "sub" / "relay.db")


# -- tenants -------------------------------------------------------------------


def test_register_tenant_fresh(store: Store) -> None:
    assert store.register_tenant(ID, APP, DIGEST, T0) is True
    tenant = store.tenant(ID, APP)
    assert tenant is not None
    assert tenant.id == ID
    assert tenant.app == APP
    assert tenant.token_digest == DIGEST
    assert tenant.pubkey == ""
    assert tenant.registered_at == T0
    assert tenant.last_seen == T0


def test_register_tenant_duplicate_is_false(store: Store) -> None:
    assert store.register_tenant(ID, APP, DIGEST, T0) is True
    assert store.register_tenant(ID, APP, DIGEST2, T0 + 5) is False
    assert store.tenant(ID, APP).token_digest == DIGEST  # unchanged


def test_register_same_id_other_app_inherits_last_seen(store: Store) -> None:
    assert store.register_tenant(ID, APP, DIGEST, T0) is True
    later = T0 + 500
    store.touch(ID, later)
    assert store.register_tenant(ID, APP2, DIGEST2, T0 + 600) is True
    assert store.tenant(ID, APP2).last_seen == later


def test_set_token_hit_and_miss(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    assert store.set_token(ID, APP, DIGEST2) is True
    assert store.tenant_by_token(DIGEST2) is not None
    assert store.set_token("ghost.example.com", APP, DIGEST) is False


def test_set_pubkey_hit_and_miss(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    assert store.set_pubkey(ID, APP, "pk-1") is True
    assert store.tenant(ID, APP).pubkey == "pk-1"
    assert store.set_pubkey("ghost.example.com", APP, "pk") is False


def test_rotate_binding_hit_and_miss(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    store.set_pubkey(ID, APP, "pk-1")
    assert store.rotate_binding(ID, APP, DIGEST2, "pk-2") is True
    tenant = store.tenant(ID, APP)
    assert tenant is not None
    assert tenant.token_digest == DIGEST2
    assert tenant.pubkey == "pk-2"
    assert store.rotate_binding("ghost.example.com", APP, DIGEST, "pk") is False


def test_tenant_by_token_miss(store: Store) -> None:
    assert store.tenant_by_token(DIGEST) is None


def test_tenant_miss(store: Store) -> None:
    assert store.tenant(ID, APP) is None


def test_touch_refreshes_every_registration(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    store.register_tenant(ID, APP2, DIGEST2, T0)
    store.touch(ID, T0 + 10)
    assert store.tenant(ID, APP).last_seen == T0 + 10
    assert store.tenant(ID, APP2).last_seen == T0 + 10
    # Other tenants unaffected
    store.register_tenant(OTHER_ID, APP, "c" * 64, T0)
    store.touch(ID, T0 + 20)
    assert store.tenant(OTHER_ID, APP).last_seen == T0


def test_touch_missing_id_is_noop(store: Store) -> None:
    store.touch("ghost.example.com", T0)  # must not raise


def test_list_tenants_all_and_filtered(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    store.register_tenant(ID, APP2, DIGEST2, T0)
    store.register_tenant(OTHER_ID, APP, "c" * 64, T0)
    all_tenants = store.list_tenants()
    # ORDER BY id, app — 'second-app' sorts before 'test-app'
    assert [(t.id, t.app) for t in all_tenants] == [(ID, APP2), (ID, APP), (OTHER_ID, APP)]
    assert [(t.id, t.app) for t in store.list_tenants(APP)] == [(ID, APP), (OTHER_ID, APP)]
    assert store.list_tenants("unknown-app") == []


def test_count_tenants(store: Store) -> None:
    assert store.count_tenants() == 0
    store.register_tenant(ID, APP, DIGEST, T0)
    store.register_tenant(ID, APP2, DIGEST2, T0)
    assert store.count_tenants() == 2


def test_expire_tenants_removes_idle(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    store.register_tenant(OTHER_ID, APP, "c" * 64, T0)
    store.touch(OTHER_ID, T0 + TENANT_TTL - 10)
    # usage row for the expiring tenant must cascade
    store.check_and_record(
        ID,
        APP,
        BLIND,
        T0,
        burst_per_min=5,
        daily=10,
        token_burst_per_min=3,
    )
    removed = store.expire_tenants(T0 + TENANT_TTL + 1)
    assert removed == [ID]
    assert store.tenant(ID, APP) is None
    # usage rows for the expired tenant cascade-deleted
    assert store.usage_count(ID, APP, T0 + 1) == 0
    # Other tenant (refreshed just inside the window) survives
    assert store.tenant(OTHER_ID, APP) is not None


def test_expire_tenants_per_tenant_unit(store: Store) -> None:
    # Two registrations: one refreshed recently, one idle — the tenant (max
    # last_seen across rows) survives as a unit and the idle row is kept.
    store.register_tenant(ID, APP, DIGEST, T0)
    store.register_tenant(ID, APP2, DIGEST2, T0)
    store.touch(ID, T0 + TENANT_TTL - 10)
    assert store.expire_tenants(T0 + TENANT_TTL) == []
    assert store.tenant(ID, APP) is not None
    assert store.tenant(ID, APP2) is not None
    # With both rows idle, the whole tenant goes at once.
    removed = store.expire_tenants(T0 + 2 * TENANT_TTL)
    assert removed == [ID]
    assert store.tenant(ID, APP) is None
    assert store.tenant(ID, APP2) is None


def test_expire_tenants_noop_when_all_fresh(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    assert store.expire_tenants(T0 + 10) == []


def test_delete_tenant_with_app(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    store.register_tenant(ID, APP2, DIGEST2, T0)
    assert store.delete_tenant(ID, APP) == 1
    assert store.tenant(ID, APP) is None
    assert store.tenant(ID, APP2) is not None


def test_delete_tenant_without_app_removes_all(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    store.register_tenant(ID, APP2, DIGEST2, T0)
    assert store.delete_tenant(ID) == 2
    assert store.tenant(ID, APP) is None
    assert store.tenant(ID, APP2) is None


def test_delete_tenant_cascades_usage_with_app(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    store.register_tenant(ID, APP2, DIGEST2, T0)
    quota = {"burst_per_min": 100, "daily": 1000, "token_burst_per_min": 100}
    store.check_and_record(ID, APP, BLIND, T0, **quota)
    store.check_and_record(ID, APP2, BLIND, T0, **quota)
    store.delete_tenant(ID, APP)
    assert store.usage_count(ID, APP, T0 + 1) == 0
    assert store.usage_count(ID, APP2, T0 + 1) == 1


def test_delete_tenant_cascades_usage_without_app(store: Store) -> None:
    store.register_tenant(ID, APP, DIGEST, T0)
    store.register_tenant(ID, APP2, DIGEST2, T0)
    quota = {"burst_per_min": 100, "daily": 1000, "token_burst_per_min": 100}
    store.check_and_record(ID, APP, BLIND, T0, **quota)
    store.check_and_record(ID, APP2, BLIND, T0, **quota)
    store.delete_tenant(ID)
    assert store.usage_count(ID, APP, T0 + 1) == 0
    assert store.usage_count(ID, APP2, T0 + 1) == 0


def test_delete_tenant_missing_is_zero(store: Store) -> None:
    assert store.delete_tenant(ID) == 0
    assert store.delete_tenant(ID, APP) == 0


# -- nonces --------------------------------------------------------------------


def test_claim_nonce_first_and_replay(store: Store) -> None:
    assert store.claim_nonce(DIGEST, T0) is True
    assert store.claim_nonce(DIGEST, T0 + 1) is False
    assert store.claim_nonce(DIGEST2, T0) is True  # different nonce is fine


def test_claim_nonce_expired_window_allows_reclaim(store: Store) -> None:
    assert store.claim_nonce(DIGEST, T0) is True
    # Exactly at the TTL boundary the old row is still present (strict <)
    assert store.claim_nonce(DIGEST, T0 + NONCE_TTL) is False
    assert store.claim_nonce(DIGEST, T0 + NONCE_TTL + 1) is True


def test_claim_nonce_race_integrity_error_is_replay(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The defensive INSERT-conflict path (concurrent claim) returns False."""

    class FlakyConn:
        def __init__(self, db: sqlite3.Connection) -> None:
            self._db = db

        def execute(self, sql: str, *args: object) -> sqlite3.Cursor:
            if sql.strip().startswith("INSERT INTO nonces"):
                raise sqlite3.IntegrityError("UNIQUE constraint failed: nonces.digest")
            return self._db.execute(sql, *args)

        def __getattr__(self, name: str) -> object:
            return getattr(self._db, name)

    real_connect = Store.connect

    @contextlib.contextmanager
    def flaky_connect(this: Store) -> Iterator[FlakyConn]:
        with real_connect(this) as db:
            yield FlakyConn(db)

    monkeypatch.setattr(Store, "connect", flaky_connect)
    assert store.claim_nonce(DIGEST, T0) is False


def test_prune_nonces(store: Store) -> None:
    store.claim_nonce(DIGEST, T0)
    store.claim_nonce(DIGEST2, T0 + NONCE_TTL + 5)
    store.prune_nonces(T0 + NONCE_TTL + 1)
    # Old row pruned: reclaim succeeds; recent row still blocks
    assert store.claim_nonce(DIGEST, T0 + NONCE_TTL + 1) is True
    assert store.claim_nonce(DIGEST2, T0 + NONCE_TTL + 1) is False


# -- quotas --------------------------------------------------------------------


QUOTA = {"burst_per_min": 5, "daily": 10, "token_burst_per_min": 3}


def quota_args(**overrides: float) -> dict:
    return {**QUOTA, **overrides}


def test_check_and_record_success(store: Store) -> None:
    assert store.check_and_record(ID, APP, BLIND, T0, **quota_args()) is None
    assert store.check_and_record(ID, APP, BLIND, T0 + 1, **quota_args()) is None
    assert store.usage_count(ID, APP, T0 + 2) == 2


def test_check_and_record_tenant_rate_limited(store: Store) -> None:
    for i in range(5):
        assert store.check_and_record(ID, APP, f"blind-{i}", T0 + i, **quota_args()) is None
    assert store.check_and_record(ID, APP, "blind-5", T0 + 5, **quota_args()) == "rate_limited"
    # Rejected pushes are not recorded
    assert store.usage_count(ID, APP, T0 + 6) == 5


def test_check_and_record_token_rate_limited(store: Store) -> None:
    for _ in range(3):
        assert store.check_and_record(ID, APP, BLIND, T0, **quota_args()) is None
    assert store.check_and_record(ID, APP, BLIND, T0, **quota_args()) == "token_rate_limited"


def test_check_and_record_quota_exhausted(store: Store) -> None:
    quota = quota_args(burst_per_min=100, daily=2, token_burst_per_min=100)
    assert store.check_and_record(ID, APP, "b1", T0, **quota) is None
    assert store.check_and_record(ID, APP, "b2", T0 + 1, **quota) is None
    assert store.check_and_record(ID, APP, "b3", T0 + 2, **quota) == "quota_exhausted"


def test_check_and_record_minute_window_slides(store: Store) -> None:
    quota = quota_args(burst_per_min=1)
    assert store.check_and_record(ID, APP, BLIND, T0, **quota) is None
    # Row still inside the window blocks (strict at > now - MINUTE_WINDOW)
    assert store.check_and_record(ID, APP, BLIND, T0 + MINUTE_WINDOW - 1, **quota) == "rate_limited"
    # Exactly at the cutoff the row drops out and the slot frees
    assert store.check_and_record(ID, APP, BLIND, T0 + MINUTE_WINDOW, **quota) is None


def test_check_and_record_charges_tenant_bucket_only_for_usage_count(
    store: Store,
) -> None:
    quota = quota_args()
    store.check_and_record(ID, APP, "b1", T0, **quota)
    store.check_and_record(ID, APP, "b2", T0, **quota)
    # usage_count counts only the tenant bucket rows, not per-token rows
    assert store.usage_count(ID, APP, T0 + 1) == 2
    # Other app's usage is separate
    assert store.usage_count(ID, APP2, T0 + 1) == 0


def test_usage_count_outside_daily_window(store: Store) -> None:
    store.check_and_record(ID, APP, BLIND, T0, **quota_args())
    # Strict at > cutoff: counted at the boundary minus epsilon, gone at it
    assert store.usage_count(ID, APP, T0 + DAILY_WINDOW - 1) == 1
    assert store.usage_count(ID, APP, T0 + DAILY_WINDOW) == 0


def test_prune_usage(store: Store) -> None:
    store.check_and_record(ID, APP, BLIND, T0, **quota_args())
    store.check_and_record(ID, APP, BLIND, T0 + DAILY_WINDOW + 100, **quota_args())
    store.prune_usage(T0 + DAILY_WINDOW + 1)
    assert store.usage_count(ID, APP, T0 + DAILY_WINDOW + 200) == 1


# -- denylist ------------------------------------------------------------------


def test_deny_and_is_denied(store: Store) -> None:
    store.deny("jti-1", T0 + 3600)
    assert store.is_denied(["jti-1"], T0) is True
    assert store.is_denied(["jti-2"], T0) is False
    assert store.is_denied([], T0) is False  # short-circuit, no query


def test_is_denied_purges_expired_entries(store: Store) -> None:
    store.deny("jti-1", T0 + 10)
    assert store.is_denied(["jti-1"], T0 + 11) is False
    assert store.list_denied(T0 + 11) == []  # purged from disk too


def test_deny_replaces_existing(store: Store) -> None:
    store.deny("jti-1", T0 + 10)
    store.deny("jti-1", T0 + 100)
    assert store.is_denied(["jti-1"], T0 + 20) is True
    assert store.list_denied(T0 + 20) == [("jti-1", T0 + 100)]


def test_list_denied_ordered(store: Store) -> None:
    store.deny("b-key", T0 + 100)
    store.deny("a-key", T0 + 200)
    assert store.list_denied(T0) == [("a-key", T0 + 200), ("b-key", T0 + 100)]


def test_list_denied_empty(store: Store) -> None:
    assert store.list_denied(T0) == []


# -- challenges ----------------------------------------------------------------


def put(store: Store, challenge_id: str = "ch-1", expires_at: float = T0 + 600) -> None:
    store.put_challenge(challenge_id, APP, ID, DIGEST, "nonce", "srv-ch", "sandbox", expires_at)


def test_pop_challenge_happy_path(store: Store) -> None:
    put(store)
    challenge, fail = store.pop_challenge("ch-1", T0)
    assert fail is None
    assert challenge is not None
    assert challenge.challenge_id == "ch-1"
    assert challenge.app == APP
    assert challenge.tenant_id == ID
    assert challenge.token_digest == DIGEST
    assert challenge.nonce == "nonce"
    assert challenge.server_challenge == "srv-ch"
    assert challenge.environment == "sandbox"


def test_pop_challenge_is_single_use(store: Store) -> None:
    put(store)
    assert store.pop_challenge("ch-1", T0)[1] is None
    challenge, fail = store.pop_challenge("ch-1", T0)
    assert challenge is None
    assert fail == "unknown_challenge"


def test_pop_challenge_unknown(store: Store) -> None:
    challenge, fail = store.pop_challenge("nope", T0)
    assert challenge is None
    assert fail == "unknown_challenge"


def test_pop_challenge_expired(store: Store) -> None:
    put(store, expires_at=T0 + 10)
    challenge, fail = store.pop_challenge("ch-1", T0 + 11)
    assert challenge is None
    assert fail == "challenge_expired"
    # Consumed even on failure: a second pop is unknown, not expired
    assert store.pop_challenge("ch-1", T0 + 11)[1] == "unknown_challenge"


def test_pop_challenge_not_expired_at_boundary(store: Store) -> None:
    put(store, expires_at=T0 + 10)
    challenge, fail = store.pop_challenge("ch-1", T0 + 10)
    assert fail is None
    assert challenge is not None


def test_prune_challenges(store: Store) -> None:
    put(store, "ch-old", T0 + 10)
    put(store, "ch-new", T0 + 600)
    store.prune_challenges(T0 + 11)
    assert store.pop_challenge("ch-old", T0 + 11)[1] == "unknown_challenge"
    assert store.pop_challenge("ch-new", T0 + 11)[1] is None


# -- file handling ---------------------------------------------------------------


def test_store_creates_parent_dirs_and_private_file(tmp_path: Path) -> None:
    db_path = tmp_path / "deeply" / "nested" / "relay.db"
    Store(db_path)
    assert db_path.exists()
    mode = os.stat(db_path).st_mode & 0o777
    assert mode == 0o600


def test_store_chmod_failure_is_swallowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def exploding_chmod(path: object, mode: int) -> None:
        raise OSError("read-only filesystem")

    monkeypatch.setattr(os, "chmod", exploding_chmod)
    store = Store(tmp_path / "relay.db")  # must not raise
    assert store.count_tenants() == 0
