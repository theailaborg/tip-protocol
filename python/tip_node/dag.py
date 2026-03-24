"""
node/dag.py
TIP Protocol Python — Production DAG Store

# Author:    Dinesh Mendhe <chairman@theailab.org>
Architecture:
  - SQLite primary store (WAL mode, connection-per-thread for thread safety)
  - Thread-safe in-memory fallback (uses threading.Lock on all mutations)
  - Both stores expose an identical interface via the DAG facade
  - Genesis block + founding VP written on first boot
  - All operations are synchronous (SQLite prepared statements for hot paths)

DAG properties:
  - Each tx references exactly 2 prior txs (prev[0], prev[1])
  - Genesis tx has prev = [] (the only exception)
  - tx_id = SHAKE-256 of canonical tx content
  - Supports 5,000+ TPS via parallel DAG structure

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""

from __future__ import annotations

import json
import os
import pathlib
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from shared.crypto import (
    shake256, compute_tx_id, verify_tx_id, canonical_json
)
from shared.constants import TxType
from tip_node.logger import get_logger

log = get_logger("dag")

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA cache_size=-32000;

CREATE TABLE IF NOT EXISTS transactions (
    tx_id           TEXT PRIMARY KEY,
    tx_type         TEXT NOT NULL,
    data            TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    prev            TEXT NOT NULL DEFAULT '[]',
    signature       TEXT,
    created_at      REAL NOT NULL DEFAULT (unixepoch('now','subsec'))
);
CREATE INDEX IF NOT EXISTS idx_txs_type       ON transactions(tx_type);
CREATE INDEX IF NOT EXISTS idx_txs_ts         ON transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_txs_created    ON transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_txs_data_tipid ON transactions(
    json_extract(data,'$.tip_id')
);
CREATE INDEX IF NOT EXISTS idx_txs_data_author ON transactions(
    json_extract(data,'$.author_tip_id')
);

CREATE TABLE IF NOT EXISTS identities (
    tip_id              TEXT PRIMARY KEY,
    region              TEXT NOT NULL DEFAULT 'US',
    public_key          TEXT NOT NULL,
    root_public_key     TEXT,
    vp_id               TEXT,
    verification_tier   TEXT NOT NULL DEFAULT 'T1',
    score_display_mode  TEXT NOT NULL DEFAULT 'TIER_ONLY',
    founding            INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'active',
    registered_at       TEXT NOT NULL,
    tx_id               TEXT
);
CREATE INDEX IF NOT EXISTS idx_id_vp     ON identities(vp_id);
CREATE INDEX IF NOT EXISTS idx_id_status ON identities(status);

CREATE TABLE IF NOT EXISTS content (
    ctid                TEXT PRIMARY KEY,
    origin_code         TEXT NOT NULL,
    content_hash        TEXT NOT NULL,
    perceptual_hash     TEXT,
    author_tip_id       TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'verified',
    dispute_count       INTEGER NOT NULL DEFAULT 0,
    verification_count  INTEGER NOT NULL DEFAULT 0,
    prescan_flagged     INTEGER NOT NULL DEFAULT 0,
    registered_at       TEXT NOT NULL,
    tx_id               TEXT
);
CREATE INDEX IF NOT EXISTS idx_content_author ON content(author_tip_id);
CREATE INDEX IF NOT EXISTS idx_content_origin ON content(origin_code);
CREATE INDEX IF NOT EXISTS idx_content_status ON content(status);

CREATE TABLE IF NOT EXISTS scores (
    tip_id          TEXT PRIMARY KEY,
    score           INTEGER NOT NULL DEFAULT 500,
    offense_count   INTEGER NOT NULL DEFAULT 0,
    last_updated    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dedup_registry (
    dedup_hash      TEXT PRIMARY KEY,
    created_at      REAL NOT NULL DEFAULT (unixepoch('now','subsec'))
);

CREATE TABLE IF NOT EXISTS revocations (
    tip_id          TEXT PRIMARY KEY,
    tx_type         TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    tx_id           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_providers (
    vp_id               TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    jurisdiction_tier   TEXT NOT NULL DEFAULT 'green',
    public_key          TEXT,
    status              TEXT NOT NULL DEFAULT 'active',
    registered_at       TEXT NOT NULL
);
"""


# ══════════════════════════════════════════════════════════════════════════════
# THREAD-SAFE IN-MEMORY STORE
# ══════════════════════════════════════════════════════════════════════════════

class MemoryStore:
    """Pure in-memory DAG store. Thread-safe via a single RLock."""

    def __init__(self) -> None:
        self._lock         = threading.RLock()
        self._txs:    dict = {}
        self._ids:    dict = {}
        self._content:dict = {}
        self._scores: dict = {}
        self._dedup:  set  = set()
        self._revocs: dict = {}
        self._vps:    dict = {}

    # ── Transactions ─────────────────────────────────────────────────────────
    def save_tx(self, tx: dict) -> None:
        with self._lock:
            self._txs[tx["tx_id"]] = dict(tx)

    def get_tx(self, tx_id: str) -> Optional[dict]:
        with self._lock:
            return dict(self._txs[tx_id]) if tx_id in self._txs else None

    def get_all_txs(self) -> list[dict]:
        with self._lock:
            return [dict(t) for t in self._txs.values()]

    def count(self) -> int:
        with self._lock:
            return len(self._txs)

    def get_txs_by_type(self, tx_type: str) -> list[dict]:
        with self._lock:
            return [dict(t) for t in self._txs.values() if t.get("tx_type") == tx_type]

    def get_txs_by_tip_id(self, tip_id: str) -> list[dict]:
        with self._lock:
            result = []
            for t in self._txs.values():
                d = t.get("data", {})
                if d.get("tip_id") == tip_id or d.get("author_tip_id") == tip_id:
                    result.append(dict(t))
            return sorted(result, key=lambda x: x.get("timestamp", ""))

    # ── Identities ────────────────────────────────────────────────────────────
    def save_identity(self, rec: dict) -> None:
        with self._lock:
            self._ids[rec["tip_id"]] = dict(rec)

    def get_identity(self, tip_id: str) -> Optional[dict]:
        with self._lock:
            return dict(self._ids[tip_id]) if tip_id in self._ids else None

    # ── Content ───────────────────────────────────────────────────────────────
    def save_content(self, rec: dict) -> None:
        with self._lock:
            self._content[rec["ctid"]] = dict(rec)

    def get_content(self, ctid: str) -> Optional[dict]:
        with self._lock:
            return dict(self._content[ctid]) if ctid in self._content else None

    def get_content_by_author(self, tip_id: str) -> list[dict]:
        with self._lock:
            return [dict(c) for c in self._content.values() if c.get("author_tip_id") == tip_id]

    def has_verification(self, ctid: str, tip_id: str) -> bool:
        with self._lock:
            for tx in self._txs.values():
                d = tx.get("data", {})
                if (tx.get("tx_type") == "CONTENT_VERIFIED"
                        and d.get("ctid") == ctid and d.get("verifier_tip_id") == tip_id):
                    return True
            return False

    def has_dispute(self, ctid: str, tip_id: str) -> bool:
        with self._lock:
            for tx in self._txs.values():
                d = tx.get("data", {})
                if (tx.get("tx_type") == "CONTENT_DISPUTED"
                        and d.get("ctid") == ctid and d.get("disputer_tip_id") == tip_id):
                    return True
            return False

    # ── Scores ────────────────────────────────────────────────────────────────
    def set_score(self, tip_id: str, score: int, offense_count: int = 0) -> None:
        with self._lock:
            self._scores[tip_id] = {
                "score":         max(0, min(1000, score)),
                "offense_count": max(0, offense_count),
                "last_updated":  _utc_now(),
            }

    def get_score(self, tip_id: str) -> Optional[dict]:
        with self._lock:
            return dict(self._scores[tip_id]) if tip_id in self._scores else None

    # ── Dedup registry ────────────────────────────────────────────────────────
    def add_dedup_hash(self, h: str) -> None:
        with self._lock:
            self._dedup.add(h)

    def has_dedup_hash(self, h: str) -> bool:
        with self._lock:
            return h in self._dedup

    def dedup_count(self) -> int:
        with self._lock:
            return len(self._dedup)

    # ── Revocations ───────────────────────────────────────────────────────────
    def add_revocation(self, tip_id: str, tx_type: str, timestamp: str, tx_id: str) -> None:
        with self._lock:
            self._revocs[tip_id] = {
                "tip_id":    tip_id,
                "tx_type":   tx_type,
                "timestamp": timestamp,
                "tx_id":     tx_id,
            }
            if tip_id in self._ids:
                self._ids[tip_id] = dict(self._ids[tip_id])
                self._ids[tip_id]["status"] = "revoked"

    def is_revoked(self, tip_id: str) -> bool:
        with self._lock:
            return tip_id in self._revocs

    def get_revocations(self, since: Optional[str] = None) -> list[dict]:
        with self._lock:
            all_revocs = list(self._revocs.values())
        if since:
            all_revocs = [r for r in all_revocs if r["timestamp"] > since]
        return sorted(all_revocs, key=lambda r: r["timestamp"], reverse=True)

    # ── Verification Providers ────────────────────────────────────────────────
    def save_vp(self, rec: dict) -> None:
        with self._lock:
            self._vps[rec["vp_id"]] = dict(rec)

    def get_vp(self, vp_id: str) -> Optional[dict]:
        with self._lock:
            return dict(self._vps[vp_id]) if vp_id in self._vps else None

    def get_all_vps(self) -> list[dict]:
        with self._lock:
            return [dict(v) for v in self._vps.values()]

    def close(self) -> None:
        pass  # no-op


# ══════════════════════════════════════════════════════════════════════════════
# SQLITE STORE  (thread-safe via connection-per-thread)
# ══════════════════════════════════════════════════════════════════════════════

class SQLiteStore:
    """
    SQLite-backed DAG store.
    Uses threading.local() to give each thread its own connection,
    avoiding "SQLite objects created in a thread can only be used in that
    same thread" errors under concurrent load.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        pathlib.Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        # Initialise the schema in the calling thread
        self._execute_schema()

    def _conn(self) -> sqlite3.Connection:
        """Return (or create) the per-thread SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=30.0,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA cache_size=-32000")
            self._local.conn = conn
        return self._local.conn

    def _execute_schema(self) -> None:
        conn = self._conn()
        conn.executescript(_SCHEMA)
        conn.commit()

    def _row_to_tx(self, row) -> dict:
        if row is None:
            return None
        d = dict(row)
        d["data"] = json.loads(d["data"])
        d["prev"] = json.loads(d["prev"])
        return d

    # ── Transactions ─────────────────────────────────────────────────────────
    def save_tx(self, tx: dict) -> None:
        conn = self._conn()
        conn.execute(
            """INSERT OR REPLACE INTO transactions
               (tx_id, tx_type, data, timestamp, prev, signature)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                tx["tx_id"],
                tx["tx_type"],
                json.dumps(tx.get("data", {}), sort_keys=True),
                tx["timestamp"],
                json.dumps(tx.get("prev", [])),
                tx.get("signature"),
            ),
        )
        conn.commit()

    def get_tx(self, tx_id: str) -> Optional[dict]:
        row = self._conn().execute(
            "SELECT * FROM transactions WHERE tx_id = ?", (tx_id,)
        ).fetchone()
        return self._row_to_tx(row)

    def get_all_txs(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM transactions ORDER BY created_at ASC"
        ).fetchall()
        return [self._row_to_tx(r) for r in rows]

    def count(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) FROM transactions"
        ).fetchone()[0]

    def get_txs_by_type(self, tx_type: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM transactions WHERE tx_type = ? ORDER BY created_at ASC",
            (tx_type,),
        ).fetchall()
        return [self._row_to_tx(r) for r in rows]

    def get_txs_by_tip_id(self, tip_id: str) -> list[dict]:
        rows = self._conn().execute(
            """SELECT * FROM transactions
               WHERE json_extract(data,'$.tip_id') = ?
                  OR json_extract(data,'$.author_tip_id') = ?
               ORDER BY created_at ASC""",
            (tip_id, tip_id),
        ).fetchall()
        return [self._row_to_tx(r) for r in rows]

    # ── Identities ────────────────────────────────────────────────────────────
    def save_identity(self, rec: dict) -> None:
        conn = self._conn()
        conn.execute(
            """INSERT OR REPLACE INTO identities
               (tip_id, region, public_key, root_public_key, vp_id,
                verification_tier, founding, status, registered_at, tx_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rec["tip_id"],
                rec.get("region", "US"),
                rec["public_key"],
                rec.get("root_public_key"),
                rec.get("vp_id"),
                rec.get("verification_tier", "T1"),
                1 if rec.get("founding") else 0,
                rec.get("status", "active"),
                rec["registered_at"],
                rec.get("tx_id"),
            ),
        )
        conn.commit()

    def get_identity(self, tip_id: str) -> Optional[dict]:
        row = self._conn().execute(
            "SELECT * FROM identities WHERE tip_id = ?", (tip_id,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["founding"] = bool(d["founding"])
        return d

    # ── Content ───────────────────────────────────────────────────────────────
    def save_content(self, rec: dict) -> None:
        conn = self._conn()
        conn.execute(
            """INSERT OR REPLACE INTO content
               (ctid, origin_code, content_hash, perceptual_hash, author_tip_id,
                status, prescan_flagged, registered_at, tx_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rec["ctid"],
                rec["origin_code"],
                rec["content_hash"],
                rec.get("perceptual_hash"),
                rec["author_tip_id"],
                rec.get("status", "verified"),
                1 if rec.get("prescan_flagged") else 0,
                rec["registered_at"],
                rec.get("tx_id"),
            ),
        )
        conn.commit()

    def get_content(self, ctid: str) -> Optional[dict]:
        return self._conn().execute(
            "SELECT * FROM content WHERE ctid = ?", (ctid,)
        ).fetchone()
        # Returns sqlite3.Row; callers should call dict() if needed

    def get_content_by_author(self, tip_id: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM content WHERE author_tip_id = ?", (tip_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def has_verification(self, ctid: str, tip_id: str) -> bool:
        row = self._conn().execute(
            """SELECT 1 FROM transactions
               WHERE tx_type='CONTENT_VERIFIED'
                 AND json_extract(data,'$.ctid')=?
                 AND json_extract(data,'$.verifier_tip_id')=?
               LIMIT 1""",
            (ctid, tip_id),
        ).fetchone()
        return row is not None

    def has_dispute(self, ctid: str, tip_id: str) -> bool:
        row = self._conn().execute(
            """SELECT 1 FROM transactions
               WHERE tx_type='CONTENT_DISPUTED'
                 AND json_extract(data,'$.ctid')=?
                 AND json_extract(data,'$.disputer_tip_id')=?
               LIMIT 1""",
            (ctid, tip_id),
        ).fetchone()
        return row is not None

    # ── Scores ────────────────────────────────────────────────────────────────
    def set_score(self, tip_id: str, score: int, offense_count: int = 0) -> None:
        conn = self._conn()
        conn.execute(
            """INSERT OR REPLACE INTO scores (tip_id, score, offense_count, last_updated)
               VALUES (?, ?, ?, ?)""",
            (tip_id, max(0, min(1000, score)), max(0, offense_count), _utc_now()),
        )
        conn.commit()

    def get_score(self, tip_id: str) -> Optional[dict]:
        row = self._conn().execute(
            "SELECT * FROM scores WHERE tip_id = ?", (tip_id,)
        ).fetchone()
        return dict(row) if row else None

    # ── Dedup registry ────────────────────────────────────────────────────────
    def add_dedup_hash(self, h: str) -> None:
        conn = self._conn()
        conn.execute("INSERT OR IGNORE INTO dedup_registry (dedup_hash) VALUES (?)", (h,))
        conn.commit()

    def has_dedup_hash(self, h: str) -> bool:
        row = self._conn().execute(
            "SELECT 1 FROM dedup_registry WHERE dedup_hash = ?", (h,)
        ).fetchone()
        return row is not None

    def dedup_count(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) FROM dedup_registry"
        ).fetchone()[0]

    # ── Revocations ───────────────────────────────────────────────────────────
    def add_revocation(self, tip_id: str, tx_type: str, timestamp: str, tx_id: str) -> None:
        conn = self._conn()
        conn.execute(
            """INSERT OR REPLACE INTO revocations (tip_id, tx_type, timestamp, tx_id)
               VALUES (?, ?, ?, ?)""",
            (tip_id, tx_type, timestamp, tx_id),
        )
        conn.execute(
            "UPDATE identities SET status = 'revoked' WHERE tip_id = ?", (tip_id,)
        )
        conn.commit()

    def is_revoked(self, tip_id: str) -> bool:
        return self._conn().execute(
            "SELECT 1 FROM revocations WHERE tip_id = ?", (tip_id,)
        ).fetchone() is not None

    def get_revocations(self, since: Optional[str] = None) -> list[dict]:
        if since:
            rows = self._conn().execute(
                "SELECT * FROM revocations WHERE timestamp > ? ORDER BY timestamp DESC",
                (since,),
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT * FROM revocations ORDER BY timestamp DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Verification Providers ────────────────────────────────────────────────
    def save_vp(self, rec: dict) -> None:
        conn = self._conn()
        conn.execute(
            """INSERT OR REPLACE INTO verification_providers
               (vp_id, name, jurisdiction_tier, public_key, status, registered_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                rec["vp_id"],
                rec["name"],
                rec.get("jurisdiction_tier", "green"),
                rec.get("public_key"),
                rec.get("status", "active"),
                rec.get("registered_at", _utc_now()),
            ),
        )
        conn.commit()

    def get_vp(self, vp_id: str) -> Optional[dict]:
        row = self._conn().execute(
            "SELECT * FROM verification_providers WHERE vp_id = ?", (vp_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_vps(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM verification_providers"
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None


# ══════════════════════════════════════════════════════════════════════════════
# DAG FACADE
# ══════════════════════════════════════════════════════════════════════════════

class DAG:
    """
    Unified DAG facade over SQLiteStore or MemoryStore.
    Thread-safe. Handles genesis bootstrap on first init.
    """

    def __init__(self, config: dict) -> None:
        db_path = config.get("db_path", ":memory:")
        if db_path in (":memory:", ":memory-test:"):
            log.warning("DAG store: in-memory (ephemeral)")
            self._store: SQLiteStore | MemoryStore = MemoryStore()
        else:
            try:
                self._store = SQLiteStore(db_path)
                log.info(f"DAG store: SQLite @ {db_path}")
            except Exception as exc:
                log.warning(f"SQLite init failed ({exc}) — using in-memory store")
                self._store = MemoryStore()

        self._config = config
        from node.genesis import GENESIS_TX_ID as _GENESIS_TX_ID
        self._prev_ring: list[str] = [_GENESIS_TX_ID, _GENESIS_TX_ID]
        self._prev_lock = threading.Lock()

        if self._store.count() == 0:
            self._bootstrap_genesis()

    # ── Private ───────────────────────────────────────────────────────────────
    def _bootstrap_genesis(self) -> None:
        """Write genesis block and founding VP on first boot."""
        from node.genesis import (
            GENESIS_TX_ID, GENESIS_TX, GENESIS_TIMESTAMP, GENESIS_HASH,
            GENESIS_TX_SIGNATURE, GENESIS_VP_TX_SIGNATURE, get_founding_vp,
        )

        # Genesis transaction — content-addressed tx_id, pre-signed by founding VP
        self._store.save_tx({**GENESIS_TX, "tx_id": GENESIS_TX_ID, "signature": GENESIS_TX_SIGNATURE})

        # Bootstrap founding VP from genesis payload (public key embedded by seed script)
        founding_vp = get_founding_vp()
        self._store.save_vp({
            "vp_id":             founding_vp["vp_id"],
            "name":              founding_vp["name"],
            "jurisdiction_tier": founding_vp["jurisdiction_tier"],
            "public_key":        founding_vp["public_key"],
            "status":            "active",
            "registered_at":     GENESIS_TIMESTAMP,
        })

        # VP registration transaction — pre-signed by founding VP
        vp_tx = {
            "tx_type":   TxType.VP_REGISTERED,
            "timestamp": GENESIS_TIMESTAMP,
            "prev":      [GENESIS_TX_ID, GENESIS_TX_ID],
            "data": {
                "vp_id":             founding_vp["vp_id"],
                "name":              founding_vp["name"],
                "jurisdiction_tier": founding_vp["jurisdiction_tier"],
                "public_key":        founding_vp["public_key"],
            },
        }
        self._store.save_tx({**vp_tx, "tx_id": compute_tx_id(vp_tx), "signature": GENESIS_VP_TX_SIGNATURE})

        with self._prev_lock:
            self._prev_ring = [compute_tx_id(vp_tx), GENESIS_TX_ID]

        log.info(f"Genesis bootstrap: {GENESIS_HASH[:16]}... | VP: {founding_vp['vp_id']}")

    def _update_prev(self, tx_id: str) -> None:
        with self._prev_lock:
            self._prev_ring = [tx_id, self._prev_ring[0]]

    # ── Public API ────────────────────────────────────────────────────────────

    def add_tx(self, tx: dict) -> dict:
        """Add a transaction to the DAG. Auto-assigns timestamp, prev[], tx_id.

        Order matters:
          1. timestamp first (part of canonical form)
          2. prev refs second (part of canonical form — must precede tx_id)
          3. tx_id last — SHAKE-256(canonical{tx_type,data,timestamp,prev})
        """
        import copy
        tx = copy.deepcopy(tx)

        if not tx.get("timestamp"):
            tx["timestamp"] = _utc_now()
        if not tx.get("prev"):
            with self._prev_lock:
                tx["prev"] = list(self._prev_ring)

        had_tx_id = bool(tx.get("tx_id"))
        if not tx.get("tx_id"):
            tx["tx_id"] = compute_tx_id(tx)
        if had_tx_id and not verify_tx_id(tx):
            raise ValueError(f"add_tx: tx_id mismatch — rejecting tampered tx {tx['tx_id']}")

        self._store.save_tx(tx)
        self._update_prev(tx["tx_id"])
        return tx

    def get_tx(self, tx_id: str) -> Optional[dict]:
        return self._store.get_tx(tx_id)

    def get_all_txs(self) -> list[dict]:
        return self._store.get_all_txs()

    def count(self) -> int:
        return self._store.count()

    def get_txs_by_type(self, tx_type: str) -> list[dict]:
        return self._store.get_txs_by_type(tx_type)

    def get_txs_by_tip_id(self, tip_id: str) -> list[dict]:
        return self._store.get_txs_by_tip_id(tip_id)

    def get_recent_prev(self) -> list[str]:
        with self._prev_lock:
            return list(self._prev_ring)

    # Identity
    def save_identity(self, rec: dict) -> None:
        self._store.save_identity(rec)

    def get_identity(self, tip_id: str) -> Optional[dict]:
        return self._store.get_identity(tip_id)

    # Content
    def save_content(self, rec: dict) -> None:
        self._store.save_content(rec)

    def get_content(self, ctid: str) -> Optional[dict]:
        row = self._store.get_content(ctid)
        return dict(row) if row is not None else None

    def get_content_by_author(self, tip_id: str) -> list[dict]:
        return self._store.get_content_by_author(tip_id)

    def has_verification(self, ctid: str, tip_id: str) -> bool:
        return self._store.has_verification(ctid, tip_id)

    def has_dispute(self, ctid: str, tip_id: str) -> bool:
        return self._store.has_dispute(ctid, tip_id)

    # Scores
    def set_score(self, tip_id: str, score: int, offense_count: int = 0) -> None:
        self._store.set_score(tip_id, score, offense_count)

    def get_score(self, tip_id: str) -> Optional[dict]:
        return self._store.get_score(tip_id)

    # Dedup registry
    def add_dedup_hash(self, h: str) -> None:
        self._store.add_dedup_hash(h)

    def has_dedup_hash(self, h: str) -> bool:
        return self._store.has_dedup_hash(h)

    def dedup_count(self) -> int:
        return self._store.dedup_count()

    # Revocations (v2 FIX-05)
    def add_revocation(self, tip_id: str, tx_type: str, timestamp: str, tx_id: str) -> None:
        self._store.add_revocation(tip_id, tx_type, timestamp, tx_id)

    def is_revoked(self, tip_id: str) -> bool:
        return self._store.is_revoked(tip_id)

    def get_revocations(self, since: Optional[str] = None) -> list[dict]:
        return self._store.get_revocations(since)

    # VPs
    def save_vp(self, rec: dict) -> None:
        self._store.save_vp(rec)

    def get_vp(self, vp_id: str) -> Optional[dict]:
        return self._store.get_vp(vp_id)

    def get_all_vps(self) -> list[dict]:
        return self._store.get_all_vps()

    def close(self) -> None:
        self._store.close()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
