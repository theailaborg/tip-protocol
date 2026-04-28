/**
 * @file @tip-protocol/node/src/dag.js
 * @description Federated Directed Acyclic Graph (DAG) store — Production Implementation
 *
 * Architecture:
 *   - SQLite primary store (WAL mode, NORMAL sync — fast + durable)
 *   - Pure in-memory fallback when better-sqlite3 is unavailable
 *   - Both stores expose an identical interface
 *   - Genesis block written on first boot from genesis.js constants
 *   - Every mutation (saveTx, saveIdentity, etc.) returns immediately
 *   - All reads are synchronous (SQLite prepared statements)
 *
 * DAG properties:
 *   - Each tx references exactly 2 prior txs (prev[0], prev[1])
 *   - Genesis tx has prev = [] (the only exception)
 *   - tx_id = SHAKE-256 of canonical tx content
 *   - Enables 5,000+ TPS via parallel processing
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const path = require("path");
const fs = require("fs");
const { shake256, computeTxId, verifyTxId } = require("../../shared/crypto");
const { TX_TYPES } = require("../../shared/constants");
const { log } = require("./logger");

// ─── SQLite loaded lazily ─────────────────────────────────────────────────────
let Database = null;
try { Database = require("better-sqlite3"); } catch { /* use in-memory */ }

// ─── Canonical row shapers (§14 snapshot-sync) ────────────────────────────
// Both stores project their row shapes through these before yielding from
// iterateCanonicalState. Single source of truth for which fields of each
// table participate in the state_merkle_root. Adding or removing a field
// here is a consensus-breaking change — every node in the network must
// upgrade simultaneously or commit rows will mismatch.
//
// Every column of each table IS included. This is only safe because every
// field is populated from tx data (tx.timestamp, tx.tx_id, tx.data.*) —
// never from Date.now() / unixepoch() / other local-clock sources.
// See setScore() and addDedupHash() for the determinism contract.
function _canonIdentity(r) {
  return {
    tip_id: r.tip_id,
    region: r.region,
    public_key: r.public_key,
    root_public_key: r.root_public_key || null,
    vp_id: r.vp_id || null,
    verification_tier: r.verification_tier,
    score_display_mode: r.score_display_mode || "TIER_ONLY",
    founding: r.founding ? 1 : 0,
    status: r.status,
    registered_at: r.registered_at,
    tx_id: r.tx_id || null,
  };
}
function _canonContent(r) {
  // Intentionally excluded: `dispute_count`, `verification_count`. Both are
  // dead columns today (always 0 — never written) and would trap a future
  // writer that updates them non-deterministically. Re-add if/when they
  // start being incremented from commit-handler with tx context.
  return {
    ctid: r.ctid,
    origin_code: r.origin_code,
    content_hash: r.content_hash,
    perceptual_hash: r.perceptual_hash || null,
    author_tip_id: r.author_tip_id,
    status: r.status,
    prescan_flagged: r.prescan_flagged ? 1 : 0,
    registered_at: r.registered_at,
    tx_id: r.tx_id || null,
  };
}
// Canonical projection for the `scores` table — included in
// `state_merkle_root` since `last_updated` is now sourced from
// `tx.timestamp` (deterministic across nodes; see #31).
function _canonScore(tip_id, v) {
  return {
    tip_id,
    score: v.score,
    offense_count: v.offense_count,
    last_updated: v.last_updated,
  };
}
function _canonDedup(hash, createdAt) {
  return { dedup_hash: hash, created_at: createdAt };
}
function _canonRevocation(r) {
  return {
    tip_id: r.tip_id,
    tx_type: r.tx_type,
    timestamp: r.timestamp,
    tx_id: r.tx_id,
  };
}
function _canonVP(r) {
  return {
    vp_id: r.vp_id,
    name: r.name,
    jurisdiction: r.jurisdiction,
    jurisdiction_tier: r.jurisdiction_tier,
    public_key: r.public_key || null,
    status: r.status,
    registered_at: r.registered_at,
  };
}
function _canonNode(r) {
  return {
    node_id: r.node_id,
    name: r.name || null,
    public_key: r.public_key,
    status: r.status,
    registered_at: r.registered_at,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// IN-MEMORY STORE
// ══════════════════════════════════════════════════════════════════════════════
class MemoryStore {
  constructor() {
    this._txs = new Map();  // tx_id -> tx
    this._identities = new Map();  // tip_id -> record
    this._content = new Map();  // ctid -> record
    this._scores = new Map();  // tip_id -> { score, offense_count, last_updated }
    this._dedup = new Set();  // dedup_hash strings (Poseidon field elements)
    this._revocations = new Map();  // tip_id -> { tip_id, tx_type, timestamp, tx_id }
    this._vps = new Map();  // vp_id -> record
    this._nodes = new Map();  // node_id -> record
    this._certs = new Map();  // cert hash -> certificate
    this._commits = new Map();  // round -> commit checkpoint record (§15)
    this._mempool = new Map();  // tx_id -> tx
  }

  // ── Transactions ─────────────────────────────────────────────────────────
  saveTx(tx) { this._txs.set(tx.tx_id, { ...tx }); }
  getTx(id) { return this._txs.get(id) || null; }
  getAllTxs() { return [...this._txs.values()]; }
  count() { return this._txs.size; }

  // §14/#49 snapshot full-history streaming. Ordered by tx_id so sender
  // + receiver hash rows in the same order → same txs_full_root. Mirrors
  // SQLiteStore.iterateAllTransactions for in-memory tests.
  *iterateAllTransactions() {
    for (const tx of [...this._txs.values()].sort((a, b) => a.tx_id.localeCompare(b.tx_id))) {
      yield tx;
    }
  }

  getTxsByType(type) {
    return [...this._txs.values()].filter(t => t.tx_type === type);
  }
  getTxsByTypeAndCtid(type, ctid) {
    return [...this._txs.values()].filter(t => t.tx_type === type && t.data?.ctid === ctid);
  }
  getTxsByTipId(tipId) {
    return [...this._txs.values()].filter(t =>
      t.data?.tip_id === tipId || t.data?.author_tip_id === tipId
    );
  }

  // ── Identities ────────────────────────────────────────────────────────────
  saveIdentity(rec) { this._identities.set(rec.tip_id, { ...rec }); }
  getIdentity(id) { return this._identities.get(id) || null; }
  getAllIdentities() { return [...this._identities.values()]; }

  // ── Content ───────────────────────────────────────────────────────────────
  saveContent(rec) { this._content.set(rec.ctid, { ...rec }); }
  getContent(ctid) { return this._content.get(ctid) || null; }
  updateContentStatus(ctid, status) {
    const rec = this._content.get(ctid);
    if (rec) this._content.set(ctid, { ...rec, status });
  }
  updateContentOrigin(ctid, originCode, status) {
    const rec = this._content.get(ctid);
    if (rec) this._content.set(ctid, { ...rec, origin_code: originCode, status });
  }
  getContentByStatus(status) {
    return [...this._content.values()].filter(c => c.status === status);
  }
  getCleanRecordEligible(cutoff) {
    const txs = [...this._txs.values()];
    return [...this._identities.values()]
      .filter(id => {
        const tipId = id.tip_id;
        if (id.status !== "active") return false;
        // Clean-record bonus is awarded for SUSTAINED clean behavior over
        // the full CLEAN_PERIOD_DAYS window. An identity registered after
        // `cutoff` (i.e. less than CLEAN_PERIOD_DAYS ago) hasn't been
        // around long enough to have a 90-day clean record yet.
        if (!id.registered_at || id.registered_at > cutoff) return false;
        const userTxs = txs.filter(t => t.data?.tip_id === tipId || t.data?.author_tip_id === tipId);
        const hasActivity = userTxs.some(t => t.timestamp >= cutoff);
        if (!hasActivity) return false;
        const hasUpheld = userTxs.some(t => t.tx_type === "ADJUDICATION_RESULT" && t.data?.verdict === "UPHELD" && t.timestamp >= cutoff);
        if (hasUpheld) return false;
        const hasBonus = userTxs.some(t => t.tx_type === "SCORE_UPDATE" && t.data?.reason === "clean_record_bonus" && t.timestamp >= cutoff);
        if (hasBonus) return false;
        return true;
      })
      .map(id => id.tip_id);
  }
  getContentByAuthor(tipId) {
    return [...this._content.values()].filter(c => c.author_tip_id === tipId);
  }

  hasVerification(ctid, tipId) {
    for (const tx of this._txs.values()) {
      if (tx.tx_type === "CONTENT_VERIFIED" &&
        tx.data?.ctid === ctid && tx.data?.verifier_tip_id === tipId) return true;
    }
    return false;
  }

  hasDispute(ctid, tipId) {
    for (const tx of this._txs.values()) {
      if (tx.tx_type === "CONTENT_DISPUTED" &&
        tx.data?.ctid === ctid && tx.data?.disputer_tip_id === tipId) return true;
    }
    return false;
  }

  // ── Scores ────────────────────────────────────────────────────────────────
  // Cache derived from replaying the tx log. With Commits 2+3 every score
  // mutation flows through commit-handler with a consensus-ordered tx in
  // hand — callers pass `tx.timestamp` as `lastUpdatedISO` so the column
  // is deterministic across nodes and the table is part of state_merkle_root
  // (issues.md Consensus #31).
  setScore(tipId, score, offenseCount = 0, lastUpdatedISO = null) {
    if (lastUpdatedISO == null) {
      throw new Error("setScore: lastUpdatedISO (from tx.timestamp) is required for deterministic state");
    }
    this._scores.set(tipId, {
      score: Math.max(0, Math.min(1000, score)),
      offense_count: offenseCount || 0,
      last_updated: lastUpdatedISO,
    });
  }
  getScore(tipId) { return this._scores.get(tipId) || null; }

  // ── Dedup registry ────────────────────────────────────────────────────────
  // `createdAt` is the unix-seconds timestamp of the tx that introduced this
  // dedup hash (derived from tx.timestamp). Deterministic — never Date.now().
  addDedupHash(hash, createdAt) {
    if (createdAt == null) {
      throw new Error("addDedupHash: createdAt (from tx.timestamp) is required for deterministic state");
    }
    if (this._dedup.has(hash)) return;
    this._dedup.add(hash);
    if (!this._dedupCreated) this._dedupCreated = new Map();
    this._dedupCreated.set(hash, createdAt);
  }
  hasDedupHash(hash) { return this._dedup.has(hash); }
  dedupCount() { return this._dedup.size; }

  // ── Revocations ───────────────────────────────────────────────────────────
  addRevocation(tipId, txType, timestamp, txId) {
    this._revocations.set(tipId, { tip_id: tipId, tx_type: txType, timestamp, tx_id: txId });
    const rec = this._identities.get(tipId);
    if (rec) this._identities.set(tipId, { ...rec, status: "revoked" });
  }
  isRevoked(tipId) { return this._revocations.has(tipId); }
  getRevocations(since) {
    const all = [...this._revocations.values()];
    return since ? all.filter(r => new Date(r.timestamp) > new Date(since)) : all;
  }

  // ── Verification Providers ────────────────────────────────────────────────
  saveVP(rec) { this._vps.set(rec.vp_id, { ...rec }); }
  getVP(vpId) { return this._vps.get(vpId) || null; }
  getAllVPs() { return [...this._vps.values()]; }

  // ── Nodes ───────────────────────────────────────────────────────────────
  saveNode(rec) { this._nodes.set(rec.node_id, { ...rec }); }
  getNode(nodeId) { return this._nodes.get(nodeId) || null; }
  getAllNodes() { return [...this._nodes.values()]; }

  // ── Certificates (Narwhal consensus) ──────────────────────────────────
  saveCertificate(cert) { this._certs.set(cert.hash, { ...cert }); }
  getCertificate(hash) { return this._certs.get(hash) || null; }
  getCertificatesByRound(round) {
    return [...this._certs.values()]
      .filter(c => c.round === round)
      .sort((a, b) => a.author_node_id.localeCompare(b.author_node_id));
  }
  getCertificateByAuthorRound(authorNodeId, round) {
    return [...this._certs.values()].find(c => c.author_node_id === authorNodeId && c.round === round) || null;
  }
  getLatestRound() {
    let max = 0;
    for (const c of this._certs.values()) { if (c.round > max) max = c.round; }
    return max;
  }
  // Earliest round with at least one cert still in storage. Returns 0 if
  // the certs table is empty. Used by the sync handler to detect when a
  // joiner's requested from_round falls below our GC horizon. Cheap: O(N)
  // on MemoryStore (necessary — no ordering), but sync requests are rare.
  getEarliestCertRound() {
    let min = 0;
    for (const c of this._certs.values()) {
      if (min === 0 || c.round < min) min = c.round;
    }
    return min;
  }
  getCertificatesFromRound(fromRound) {
    return [...this._certs.values()]
      .filter(c => c.round >= fromRound)
      .sort((a, b) => a.round !== b.round ? a.round - b.round : a.author_node_id.localeCompare(b.author_node_id));
  }
  certificateCount() { return this._certs.size; }
  // Cert GC (§2): drop every cert with round < cutoffRound. Returns number
  // of rows deleted. Callers must ensure the cutoff leaves enough history
  // for still-active consensus (parent refs, waiter, fast-forward).
  pruneCertificatesBefore(cutoffRound) {
    let n = 0;
    for (const [hash, cert] of this._certs) {
      if (cert.round < cutoffRound) {
        this._certs.delete(hash);
        n++;
      }
    }
    return n;
  }
  // In-memory store has no disk-backed pages to reclaim — no-op for parity.
  incrementalVacuum(_maxPages) { /* no-op */ }

  // ── Equivocation defense: votes_seen (§1) ───────────────────────────────
  // Key: "${round}:${author}". Mirrors SQLiteStore semantics.
  recordSeenVote(round, author, batchHash) {
    if (!this._votes) this._votes = new Map();
    const key = `${round}:${author}`;
    if (this._votes.has(key)) return false;
    this._votes.set(key, { round, author, batch_hash: batchHash });
    return true;
  }
  getSeenVote(round, author) {
    if (!this._votes) return null;
    return this._votes.get(`${round}:${author}`) || null;
  }
  pruneVotesSeenBefore(cutoffRound) {
    if (!this._votes) return 0;
    let n = 0;
    for (const [key, row] of this._votes) {
      if (row.round < cutoffRound) { this._votes.delete(key); n++; }
    }
    return n;
  }

  // ── Commit checkpoints (§15) ──────────────────────────────────────────
  saveCommit(rec) {
    if (this._commits.has(rec.round)) return; // idempotent like INSERT OR IGNORE
    this._commits.set(rec.round, { ...rec, committee: [...(rec.committee || [])] });
  }
  getCommit(round) { return this._commits.get(round) || null; }
  getLatestCommit() {
    let latest = null;
    for (const c of this._commits.values()) {
      if (!latest || c.round > latest.round) latest = c;
    }
    return latest;
  }
  getCommitsFromRound(fromRound) {
    return [...this._commits.values()]
      .filter(c => c.round >= fromRound)
      .sort((a, b) => a.round - b.round);
  }
  getLatestConsensusIndex() {
    let max = 0;
    for (const c of this._commits.values()) { if (c.consensus_index > max) max = c.consensus_index; }
    return max;
  }
  // #44 — consensus_meta singleton kv. Same contract as SQLiteStore.
  setConsensusMeta(key, value) {
    if (!this._consensusMeta) this._consensusMeta = new Map();
    this._consensusMeta.set(key, String(value));
  }
  getConsensusMeta(key) {
    if (!this._consensusMeta) return null;
    return this._consensusMeta.has(key) ? this._consensusMeta.get(key) : null;
  }
  // §14/#49 — see SQLiteStore.iterateAllCommitsExcept for the contract.
  *iterateAllCommitsExcept(latestRound) {
    const sorted = [...this._commits.values()].sort((a, b) => a.round - b.round);
    for (const c of sorted) {
      if (latestRound != null && latestRound > 0 && c.round === latestRound) continue;
      yield { ...c, committee: [...(c.committee || [])] };
    }
  }

  // ── Canonical derived state (§14 snapshot-sync) ─────────────────────────
  // Streaming iterator yielding { table, row } in a deterministic order
  // (table order fixed, rows sorted by primary key within each table).
  // Consumed by consensus/state-root.js to hash state row-by-row without
  // ever materialising the full state in memory.
  //
  // Consensus-critical: the set of tables, their order, the sort order, and
  // the field subset per row MUST be identical across all nodes — otherwise
  // the computed state_merkle_root diverges and the commit row forks.
  //
  // We include ALL rows (not just status='active'). Revoked identities,
  // suspended nodes, etc. are part of consensus state — two nodes that have
  // applied the same tx sequence must agree on the full set, including
  // terminal states. Filtering is a view concern, not a state concern.
  *iterateCanonicalState() {
    for (const r of [...this._identities.values()]
      .sort((a, b) => a.tip_id.localeCompare(b.tip_id))) {
      yield { table: "identities", row: _canonIdentity(r) };
    }
    for (const r of [...this._content.values()]
      .sort((a, b) => a.ctid.localeCompare(b.ctid))) {
      yield { table: "content", row: _canonContent(r) };
    }
    for (const [tip_id, v] of [...this._scores.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))) {
      yield { table: "scores", row: _canonScore(tip_id, v) };
    }
    for (const h of [...this._dedup].sort()) {
      const createdAt = this._dedupCreated ? this._dedupCreated.get(h) : null;
      yield { table: "dedup_registry", row: _canonDedup(h, createdAt) };
    }
    for (const r of [...this._revocations.values()]
      .sort((a, b) => a.tip_id.localeCompare(b.tip_id))) {
      yield { table: "revocations", row: _canonRevocation(r) };
    }
    for (const r of [...this._vps.values()]
      .sort((a, b) => a.vp_id.localeCompare(b.vp_id))) {
      yield { table: "verification_providers", row: _canonVP(r) };
    }
    for (const r of [...this._nodes.values()]
      .sort((a, b) => a.node_id.localeCompare(b.node_id))) {
      yield { table: "nodes", row: _canonNode(r) };
    }
  }

  // ── Transactions (DB-level) ────────────────────────────────────────────
  runInTransaction(fn) { return fn(); } // no-op wrapper for in-memory store

  // ── Persistent Mempool ────────────────────────────────────────────────
  saveMempoolTx(tx) { this._mempool.set(tx.tx_id, tx); }
  getMempoolTxs() { return [...this._mempool.values()]; }
  deleteMempoolTx(txId) { this._mempool.delete(txId); }
  deleteMempoolTxs(txIds) { for (const id of txIds) this._mempool.delete(id); }
  clearStaleMempoolTxs() { /* no-op for in-memory tests */ }
  mempoolCount() { return this._mempool.size; }

  close() { /* no-op for in-memory */ }
}

// ══════════════════════════════════════════════════════════════════════════════
// SQLITE STORE
// ══════════════════════════════════════════════════════════════════════════════
class SQLiteStore {
  constructor(dbPath) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = NORMAL");
    this.db.pragma("foreign_keys = ON");
    this.db.pragma("cache_size = -32000");   // 32 MB page cache

    // Cert GC (§2) requires the DB file to shrink after DELETE; SQLite's
    // default (auto_vacuum = NONE) leaves freed pages on a free-list but
    // never returns them to the filesystem. Switch to INCREMENTAL so pages
    // freed by pruneCertificatesBefore are reclaimable via PRAGMA
    // incremental_vacuum. Mode switch from NONE → INCREMENTAL only takes
    // effect after a full VACUUM on the existing DB — cheap on a fresh DB,
    // minutes on a multi-GB file. Skipped if already INCREMENTAL.
    //   0 = NONE, 1 = FULL, 2 = INCREMENTAL
    const currentAV = this.db.pragma("auto_vacuum", { simple: true });
    if (currentAV !== 2) {
      this.db.pragma("auto_vacuum = INCREMENTAL");
      // VACUUM rewrites the DB; it's a no-op on an empty file.
      this.db.exec("VACUUM");
    }

    this._migrate();
    this._prepare();
  }

  /**
   * Reclaim up to `maxPages` free pages back to the filesystem. Called from
   * bullshark after cert GC so the DB file actually shrinks. Safe to call
   * even when no pages are free (no-op in that case).
   *
   * Passing 0 or undefined reclaims ALL free pages. For large batches
   * prefer a bounded value (~1000) to keep the blocking time short — each
   * reclaimed page is ~4KB, so 1000 pages ≈ 4 MB per call, tens of ms.
   */
  incrementalVacuum(maxPages) {
    const n = (maxPages && maxPages > 0) ? `(${maxPages | 0})` : "";
    this.db.exec(`PRAGMA incremental_vacuum${n}`);
  }

  _migrate() {
    // GOTCHA: this SQL is a JS template literal, so any `${...}` in SQL
    // strings or comments evaluates as JS at runtime. If you reference an
    // undefined identifier in a comment (e.g. example placeholders), the
    // whole _migrate() throws and `initDAG`'s catch silently falls back
    // to MemoryStore — losing on-disk data on restart. Use angle brackets
    // <like_this> or backslash-escape `\${...}` for placeholder examples.
    this.db.exec(`
      -- ── Transactions ─────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS transactions (
        tx_id          TEXT PRIMARY KEY,
        tx_type        TEXT NOT NULL,
        data           TEXT NOT NULL,
        timestamp      TEXT NOT NULL,
        prev           TEXT NOT NULL DEFAULT '[]',
        signature      TEXT,
        created_at     INTEGER NOT NULL DEFAULT (unixepoch())
      );
      CREATE INDEX IF NOT EXISTS idx_txs_type       ON transactions(tx_type);
      CREATE INDEX IF NOT EXISTS idx_txs_ts         ON transactions(timestamp);
      CREATE INDEX IF NOT EXISTS idx_txs_created_at ON transactions(created_at);

      -- ── Identities ───────────────────────────────────────────────────
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
        creator_name        TEXT,
        tx_id               TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_id_vp     ON identities(vp_id);
      CREATE INDEX IF NOT EXISTS idx_id_status ON identities(status);

      -- ── Content ───────────────────────────────────────────────────────
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
        registered_url      TEXT,
        tx_id               TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_content_author ON content(author_tip_id);
      CREATE INDEX IF NOT EXISTS idx_content_origin ON content(origin_code);
      CREATE INDEX IF NOT EXISTS idx_content_status ON content(status);

      -- ── Trust Scores ──────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS scores (
        tip_id         TEXT PRIMARY KEY,
        score          INTEGER NOT NULL DEFAULT 500,
        offense_count  INTEGER NOT NULL DEFAULT 0,
        last_updated   TEXT NOT NULL
      );

      -- ── Dedup registry (ZK — Poseidon field elements, never raw inputs) ──
      -- created_at is unix-seconds from tx.timestamp (the REGISTER_IDENTITY tx
      -- that introduced this dedup hash). Must NOT be a DEFAULT (unixepoch())
      -- value — that would read the local clock and break the state_merkle_root.
      CREATE TABLE IF NOT EXISTS dedup_registry (
        dedup_hash  TEXT PRIMARY KEY,
        created_at  INTEGER NOT NULL
      );

      -- ── Revocations ───────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS revocations (
        tip_id      TEXT PRIMARY KEY,
        tx_type     TEXT NOT NULL,
        timestamp   TEXT NOT NULL,
        tx_id       TEXT NOT NULL
      );

      -- ── Verification Providers ────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS verification_providers (
        vp_id              TEXT PRIMARY KEY,
        name               TEXT NOT NULL,
        jurisdiction       TEXT NOT NULL DEFAULT 'US',
        jurisdiction_tier  TEXT NOT NULL DEFAULT 'green',
        public_key         TEXT,
        status             TEXT NOT NULL DEFAULT 'active',
        registered_at      TEXT NOT NULL
      );

      -- ── Nodes ───────────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS nodes (
        node_id         TEXT PRIMARY KEY,
        name            TEXT,
        public_key      TEXT NOT NULL,
        status          TEXT NOT NULL DEFAULT 'active',
        registered_at   TEXT NOT NULL
      );

      -- ── Consensus: Certificates (Narwhal) ─────────────────────────
      CREATE TABLE IF NOT EXISTS certificates (
        hash            TEXT PRIMARY KEY,
        round           INTEGER NOT NULL,
        author_node_id  TEXT NOT NULL,
        batch_data      TEXT NOT NULL,
        acknowledgments TEXT NOT NULL,
        parent_hashes   TEXT NOT NULL,
        signature       TEXT NOT NULL,
        -- BFT-Time: median(acks.signed_at) at cert creation, integer epoch ms.
        -- Default 0 keeps pre-BFT-Time DBs valid for inspection but Bullshark's
        -- monotonicity gate rejects anchors with timestamp <= floor, so a real
        -- network with 0-timestamp certs would halt at the next anchor (correct
        -- behavior — flags an upgrade boundary instead of silently mis-ordering).
        timestamp       INTEGER NOT NULL DEFAULT 0,
        created_at      INTEGER NOT NULL DEFAULT (unixepoch())
      );
      CREATE INDEX IF NOT EXISTS idx_cert_round ON certificates(round);
      CREATE INDEX IF NOT EXISTS idx_cert_author ON certificates(author_node_id, round);

      -- ── Consensus: Commit checkpoints (§15) ────────────────────────
      -- One row per Bullshark anchor commit. Durable record of
      -- "at round R, consensus agreed these nodes were the committee,
      --  this was the commit sequence number, this was the anchor cert."
      -- Enables Byzantine-robust state-snapshot sync (§14), commit-time
      -- committee divergence detection, and audit queries without
      -- replaying the DAG.
      CREATE TABLE IF NOT EXISTS commits (
        round             INTEGER PRIMARY KEY,
        anchor_cert_hash  TEXT NOT NULL,
        leader_node_id    TEXT NOT NULL,
        committee         TEXT NOT NULL,   -- JSON sorted array of node_ids
        support_count     INTEGER NOT NULL,
        consensus_index   INTEGER NOT NULL,
        committed_at      TEXT NOT NULL,   -- ISO8601 wall-clock
        -- §14 snapshot-sync fields (two separate roots, both signed by 2f+1 committee):
        state_merkle_root TEXT NOT NULL,   -- hash over canonical derived state tables (answers "is my app state at round R correct?")
        txs_merkle_root   TEXT NOT NULL,   -- merkle root of ordered tx_ids up to round R (answers "is tx X included?" for light clients)
        ack_signer_ids    TEXT NOT NULL,   -- JSON array of node_ids that ack'd the anchor cert
        ack_signatures    TEXT NOT NULL,   -- JSON array of hex signatures, same order as ack_signer_ids
        -- BFT-Time: each ack's signed_at (epoch ms), parallel array to
        -- ack_signatures/ack_signer_ids. The ack signature scope covers
        -- signed_at, so a snapshot joiner reconstructs the payload as
        -- "ack:<batch_hash>:<signer>:<signed_at>" to verify each signature.
        -- Without this, joiners cannot verify ack signatures on commits
        -- after the sender's certs have been GC'd.
        ack_signed_ats    TEXT NOT NULL DEFAULT '[]',  -- JSON array of integer epoch ms
        -- BFT-Time: cert.timestamp = median(acks.signed_at) at anchor commit.
        -- Canonical "consensus wall clock" for this round, deterministic
        -- across all nodes. Used by post-round logic (verdict triggers,
        -- audit logs) and by Bullshark's anchor-monotonicity gate on
        -- restart (read latest, set as floor for next anchor).
        cert_timestamp    INTEGER NOT NULL DEFAULT 0,
        -- #50: explicit copy of the anchor cert's batch_hash so this row
        -- stays self-contained for snapshot verification once cert GC has
        -- pruned the underlying cert. Without this, snapshot serving
        -- needs dag.getCertificate(anchor_cert_hash).batch.hash, which
        -- fails on idle federations whose latest commit drifts past
        -- gc_depth rounds. Joiner uses this to reconstruct the
        -- ack-signature payload (ack:<batch_hash>:<signer>:<signed_at>) each ack signed.
        anchor_batch_hash TEXT,            -- hex; nullable for back-compat with pre-#50 rows
        created_at        INTEGER NOT NULL DEFAULT (unixepoch())
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_commits_index ON commits(consensus_index);

      -- ── Consensus: Equivocation defense (§1) ──────────────────────
      -- Durable record of "what I've already attested to at (round, author)".
      -- Checked before signing any ack; refuse if a different batch_hash
      -- exists for the same (round, author). Prevents our node from being
      -- coerced (by peer equivocation or our own crash-restart) into signing
      -- two different attestations for the same logical position — which
      -- would let an author collect quorum on both of two conflicting
      -- batches and fork network state.
      --
      -- Bounded storage: pruned by _tryAdvanceRound on every round advance
      -- to a window of (current_round - VOTES_RETENTION_ROUNDS). Steady-state
      -- row count = VOTES_RETENTION_ROUNDS × committee_size (tens of rows).
      CREATE TABLE IF NOT EXISTS votes_seen (
        round       INTEGER NOT NULL,
        author      TEXT NOT NULL,
        batch_hash  TEXT NOT NULL,
        created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
        PRIMARY KEY (round, author)
      );
      CREATE INDEX IF NOT EXISTS idx_votes_round ON votes_seen(round);

      -- ── Consensus: Persistent Mempool ──────────────────────────────
      CREATE TABLE IF NOT EXISTS mempool (
        tx_id           TEXT PRIMARY KEY,
        tx_data         TEXT NOT NULL,
        received_at     INTEGER NOT NULL DEFAULT (unixepoch())
      );

      -- ── #44: Consensus singleton key-value store ───────────────────
      -- Tiny kv table for consensus state that's a single value rather
      -- than a per-event row. Currently used to persist the in-memory
      -- consensus_index counter (anchor count) so it survives restarts
      -- on idle federations — where commit rows are sparse and the
      -- counter would otherwise be lost / under-recovered.
      --
      -- Constant footprint regardless of update frequency: every write
      -- is INSERT OR REPLACE on the same primary key, so the table has
      -- one row per distinct key forever. Designed for low-cardinality
      -- singleton state; do NOT use for per-event data.
      CREATE TABLE IF NOT EXISTS consensus_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);

    // Backfill registered_url column for pre-existing content tables
    const contentCols = this.db.prepare("PRAGMA table_info(content)").all().map(c => c.name);
    if (!contentCols.includes("registered_url")) {
      this.db.exec("ALTER TABLE content ADD COLUMN registered_url TEXT");
    }
    // Backfill creator_name column for pre-existing identities tables
    const idCols = this.db.prepare("PRAGMA table_info(identities)").all().map(c => c.name);
    if (!idCols.includes("creator_name")) {
      this.db.exec("ALTER TABLE identities ADD COLUMN creator_name TEXT");
    }
    // #50: backfill anchor_batch_hash column for pre-existing commits tables.
    // Older rows (written before #50) have NULL — snapshot serving still
    // tries the cert lookup as a fallback for them, which fails if the
    // cert was GC'd (same pre-fix behaviour for old rows). Every new
    // commit written after this migration includes the column directly,
    // so going forward each commit row is self-contained.
    const commitCols = this.db.prepare("PRAGMA table_info(commits)").all().map(c => c.name);
    if (!commitCols.includes("anchor_batch_hash")) {
      this.db.exec("ALTER TABLE commits ADD COLUMN anchor_batch_hash TEXT");
    }
  }

  _prepare() {
    // Pre-compile hot-path statements for performance
    this._stmts = {
      saveTx: this.db.prepare(
        `INSERT OR IGNORE INTO transactions
           (tx_id,tx_type,data,timestamp,prev,signature)
         VALUES (?,?,?,?,?,?)`
      ),
      getTx: this.db.prepare("SELECT * FROM transactions WHERE tx_id=?"),
      getAllTxs: this.db.prepare("SELECT * FROM transactions ORDER BY created_at ASC"),
      countTxs: this.db.prepare("SELECT COUNT(*) AS n FROM transactions"),
      txsByType: this.db.prepare("SELECT * FROM transactions WHERE tx_type=? ORDER BY created_at ASC"),
      txsByTypeAndCtid: this.db.prepare(
        `SELECT * FROM transactions
         WHERE tx_type=? AND json_extract(data,'$.ctid')=?
         ORDER BY created_at ASC`
      ),
      txsByTipId: this.db.prepare(
        `SELECT * FROM transactions
         WHERE json_extract(data,'$.tip_id')=?
            OR json_extract(data,'$.author_tip_id')=?
         ORDER BY created_at ASC`
      ),

      saveIdentity: this.db.prepare(
        `INSERT OR REPLACE INTO identities
           (tip_id,region,public_key,root_public_key,vp_id,
            verification_tier,founding,status,registered_at,creator_name,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`
      ),
      getIdentity: this.db.prepare("SELECT * FROM identities WHERE tip_id=?"),
      getAllIdentities: this.db.prepare("SELECT * FROM identities WHERE status='active'"),

      saveContent: this.db.prepare(
        `INSERT OR REPLACE INTO content
           (ctid,origin_code,content_hash,perceptual_hash,author_tip_id,
            status,prescan_flagged,registered_at,registered_url,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?,?)`
      ),
      getContent: this.db.prepare("SELECT * FROM content WHERE ctid=?"),
      updateContentStatus: this.db.prepare("UPDATE content SET status=? WHERE ctid=?"),
      updateContentOrigin: this.db.prepare("UPDATE content SET origin_code=?, status=? WHERE ctid=?"),
      contentByAuthor: this.db.prepare("SELECT * FROM content WHERE author_tip_id=?"),
      contentByStatus: this.db.prepare("SELECT * FROM content WHERE status=?"),
      hasVerification: this.db.prepare(
        `SELECT 1 FROM transactions
         WHERE tx_type='CONTENT_VERIFIED'
           AND json_extract(data,'$.ctid')=?
           AND json_extract(data,'$.verifier_tip_id')=?
         LIMIT 1`
      ),
      hasDispute: this.db.prepare(
        `SELECT 1 FROM transactions
         WHERE tx_type='CONTENT_DISPUTED'
           AND json_extract(data,'$.ctid')=?
           AND json_extract(data,'$.disputer_tip_id')=?
         LIMIT 1`
      ),

      setScore: this.db.prepare(
        `INSERT OR REPLACE INTO scores (tip_id,score,offense_count,last_updated)
         VALUES (?,?,?,?)`
      ),
      getScore: this.db.prepare("SELECT * FROM scores WHERE tip_id=?"),

      addDedupHash: this.db.prepare("INSERT OR IGNORE INTO dedup_registry (dedup_hash, created_at) VALUES (?, ?)"),
      hasDedupHash: this.db.prepare("SELECT 1 FROM dedup_registry WHERE dedup_hash=?"),
      dedupCount: this.db.prepare("SELECT COUNT(*) AS n FROM dedup_registry"),

      addRevoc: this.db.prepare(
        `INSERT OR REPLACE INTO revocations (tip_id,tx_type,timestamp,tx_id)
         VALUES (?,?,?,?)`
      ),
      isRevoked: this.db.prepare("SELECT 1 FROM revocations WHERE tip_id=?"),
      revocAll: this.db.prepare("SELECT * FROM revocations ORDER BY timestamp DESC"),
      revocSince: this.db.prepare("SELECT * FROM revocations WHERE timestamp>? ORDER BY timestamp DESC"),
      revokeIdent: this.db.prepare("UPDATE identities SET status='revoked' WHERE tip_id=?"),

      saveVP: this.db.prepare(
        `INSERT OR REPLACE INTO verification_providers
           (vp_id,name,jurisdiction,jurisdiction_tier,public_key,status,registered_at)
         VALUES (?,?,?,?,?,?,?)`
      ),
      getVP: this.db.prepare("SELECT * FROM verification_providers WHERE vp_id=?"),
      getAllVPs: this.db.prepare("SELECT * FROM verification_providers"),

      saveNode: this.db.prepare(
        `INSERT OR REPLACE INTO nodes (node_id,name,public_key,status,registered_at)
         VALUES (?,?,?,?,?)`
      ),
      getNode: this.db.prepare("SELECT * FROM nodes WHERE node_id=?"),
      getAllNodes: this.db.prepare("SELECT * FROM nodes"),

      // Certificates — 8 columns including BFT-Time `timestamp`
      // (median of acks.signed_at at cert creation, integer epoch ms).
      saveCert: this.db.prepare(
        `INSERT OR IGNORE INTO certificates
           (hash,round,author_node_id,batch_data,acknowledgments,parent_hashes,signature,timestamp)
         VALUES (?,?,?,?,?,?,?,?)`
      ),
      getCert: this.db.prepare("SELECT * FROM certificates WHERE hash=?"),
      getCertsByRound: this.db.prepare("SELECT * FROM certificates WHERE round=? ORDER BY author_node_id"),
      getCertsByAuthorRound: this.db.prepare("SELECT * FROM certificates WHERE author_node_id=? AND round=?"),
      getLatestRound: this.db.prepare("SELECT MAX(round) AS latest FROM certificates"),
      getEarliestCertRound: this.db.prepare("SELECT MIN(round) AS earliest FROM certificates"),
      getCertsFromRound: this.db.prepare("SELECT * FROM certificates WHERE round>=? ORDER BY round ASC, author_node_id ASC"),
      countCerts: this.db.prepare("SELECT COUNT(*) AS n FROM certificates"),
      pruneCertsBefore: this.db.prepare("DELETE FROM certificates WHERE round < ?"),

      // Commit checkpoints (§15 base + §14 snapshot-sync fields + #50 + BFT-Time).
      // 14 columns: round, anchor_cert_hash, leader_node_id, committee,
      // support_count, consensus_index, committed_at, state_merkle_root,
      // txs_merkle_root, ack_signer_ids, ack_signatures, anchor_batch_hash,
      // ack_signed_ats, cert_timestamp.
      saveCommit: this.db.prepare(
        `INSERT OR IGNORE INTO commits
           (round,anchor_cert_hash,leader_node_id,committee,support_count,consensus_index,committed_at,
            state_merkle_root,txs_merkle_root,ack_signer_ids,ack_signatures,anchor_batch_hash,
            ack_signed_ats,cert_timestamp)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ),
      getCommit: this.db.prepare("SELECT * FROM commits WHERE round=?"),
      getCommitsFromRound: this.db.prepare(
        "SELECT * FROM commits WHERE round>=? ORDER BY round ASC"
      ),
      getLatestCommit: this.db.prepare(
        "SELECT * FROM commits ORDER BY round DESC LIMIT 1"
      ),
      getLatestConsensusIndex: this.db.prepare(
        "SELECT MAX(consensus_index) AS idx FROM commits"
      ),

      // #44: consensus_meta singleton kv accessors. INSERT OR REPLACE
      // because every write is a logical "set this key to this value"
      // — never appends; row count stays constant.
      setConsensusMeta: this.db.prepare(
        "INSERT OR REPLACE INTO consensus_meta (key, value) VALUES (?, ?)"
      ),
      getConsensusMeta: this.db.prepare(
        "SELECT value FROM consensus_meta WHERE key = ?"
      ),

      // §1 Equivocation defense — votes_seen
      saveSeenVote: this.db.prepare(
        `INSERT OR IGNORE INTO votes_seen
           (round,author,batch_hash)
         VALUES (?,?,?)`
      ),
      getSeenVote: this.db.prepare(
        "SELECT round, author, batch_hash FROM votes_seen WHERE round=? AND author=?"
      ),
      pruneVotesSeenBefore: this.db.prepare(
        "DELETE FROM votes_seen WHERE round < ?"
      ),

      // Persistent mempool
      saveMempoolTx: this.db.prepare("INSERT OR IGNORE INTO mempool (tx_id,tx_data) VALUES (?,?)"),
      getMempoolTxs: this.db.prepare("SELECT * FROM mempool ORDER BY received_at ASC"),
      deleteMempoolTx: this.db.prepare("DELETE FROM mempool WHERE tx_id=?"),
      clearMempoolBefore: this.db.prepare("DELETE FROM mempool WHERE received_at < ?"),
      countMempool: this.db.prepare("SELECT COUNT(*) AS n FROM mempool"),
    };
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  _parseTx(row) {
    if (!row) return null;
    return { ...row, data: JSON.parse(row.data), prev: JSON.parse(row.prev) };
  }

  // ── Transactions ─────────────────────────────────────────────────────────
  saveTx(tx) {
    this._stmts.saveTx.run(
      tx.tx_id, tx.tx_type,
      JSON.stringify(tx.data),
      tx.timestamp,
      JSON.stringify(tx.prev || []),
      tx.signature || null
    );
  }
  getTx(id) { return this._parseTx(this._stmts.getTx.get(id)); }
  getAllTxs() { return this._stmts.getAllTxs.all().map(r => this._parseTx(r)); }
  count() { return this._stmts.countTxs.get().n; }
  getTxsByType(type) { return this._stmts.txsByType.all(type).map(r => this._parseTx(r)); }
  getTxsByTypeAndCtid(type, ctid) { return this._stmts.txsByTypeAndCtid.all(type, ctid).map(r => this._parseTx(r)); }
  getTxsByTipId(tipId) { return this._stmts.txsByTipId.all(tipId, tipId).map(r => this._parseTx(r)); }
  // §14/#49 snapshot full-history streaming. Ordered by tx_id (PK index)
  // so sender + receiver hash rows in the same order → same txs_full_root.
  // Uses better-sqlite3 .iterate() so memory stays bounded at one row.
  *iterateAllTransactions() {
    for (const row of this.db.prepare("SELECT * FROM transactions ORDER BY tx_id ASC").iterate()) {
      yield this._parseTx(row);
    }
  }

  // ── Identities ────────────────────────────────────────────────────────────
  saveIdentity(rec) {
    this._stmts.saveIdentity.run(
      rec.tip_id, rec.region || "US",
      rec.public_key, rec.root_public_key || null,
      rec.vp_id || null, rec.verification_tier || "T1",
      rec.founding ? 1 : 0,
      rec.status || "active",
      rec.registered_at, rec.creator_name || null, rec.tx_id || null
    );
  }
  getIdentity(id) {
    const row = this._stmts.getIdentity.get(id);
    return row ? { ...row, founding: row.founding === 1 } : null;
  }
  getAllIdentities() {
    return this._stmts.getAllIdentities.all().map(r => ({ ...r, founding: r.founding === 1 }));
  }

  // ── Content ───────────────────────────────────────────────────────────────
  saveContent(rec) {
    this._stmts.saveContent.run(
      rec.ctid, rec.origin_code,
      rec.content_hash, rec.perceptual_hash || null,
      rec.author_tip_id,
      rec.status || "registered",
      rec.prescan_flagged ? 1 : 0,
      rec.registered_at, rec.registered_url || null, rec.tx_id || null
    );
  }
  getContent(ctid) { return this._stmts.getContent.get(ctid) || null; }
  updateContentStatus(ctid, status) { this._stmts.updateContentStatus.run(status, ctid); }
  updateContentOrigin(ctid, originCode, status) { this._stmts.updateContentOrigin.run(originCode, status, ctid); }
  getContentByAuthor(tipId) { return this._stmts.contentByAuthor.all(tipId); }
  getContentByStatus(status) { return this._stmts.contentByStatus.all(status); }
  hasVerification(ctid, tipId) { return !!this._stmts.hasVerification.get(ctid, tipId); }
  hasDispute(ctid, tipId) { return !!this._stmts.hasDispute.get(ctid, tipId); }

  getCleanRecordEligible(cutoff) {
    // Clean-record bonus eligibility: identity must be active, registered
    // for at least CLEAN_PERIOD_DAYS (`registered_at <= cutoff`), have had
    // some on-network activity inside the window, no UPHELD adjudication
    // inside the window, and no prior bonus inside the window.
    return this.db.prepare(`
      SELECT DISTINCT i.tip_id FROM identities i
      WHERE i.status = 'active'
        AND i.registered_at <= ?
        AND EXISTS (
          SELECT 1 FROM transactions t
          WHERE (json_extract(t.data,'$.tip_id') = i.tip_id
              OR json_extract(t.data,'$.author_tip_id') = i.tip_id)
            AND t.timestamp >= ?
        )
        AND NOT EXISTS (
          SELECT 1 FROM transactions t
          WHERE t.tx_type = 'ADJUDICATION_RESULT'
            AND json_extract(t.data,'$.author_tip_id') = i.tip_id
            AND json_extract(t.data,'$.verdict') = 'UPHELD'
            AND t.timestamp >= ?
        )
        AND NOT EXISTS (
          SELECT 1 FROM transactions t
          WHERE t.tx_type = 'SCORE_UPDATE'
            AND (json_extract(t.data,'$.tip_id') = i.tip_id
              OR json_extract(t.data,'$.author_tip_id') = i.tip_id)
            AND json_extract(t.data,'$.reason') = 'clean_record_bonus'
            AND t.timestamp >= ?
        )
    `).all(cutoff, cutoff, cutoff, cutoff).map(r => r.tip_id);
  }

  // ── Scores ────────────────────────────────────────────────────────────────
  // The scores table is a CACHE derived from replaying the tx log, but with
  // Commits 2+3 every score-mutating tx is consensus-ordered, so each commit
  // call on every node sees the same `tx.timestamp`. Pass it through as
  // `lastUpdatedISO` and the column becomes deterministic across nodes,
  // letting the table back into `state_merkle_root` (issues.md Consensus #31).
  setScore(tipId, score, offenseCount = 0, lastUpdatedISO = null) {
    if (lastUpdatedISO == null) {
      throw new Error("setScore: lastUpdatedISO (from tx.timestamp) is required for deterministic state");
    }
    this._stmts.setScore.run(
      tipId,
      Math.max(0, Math.min(1000, score)),
      offenseCount || 0,
      lastUpdatedISO
    );
  }
  getScore(tipId) { return this._stmts.getScore.get(tipId) || null; }

  // ── Dedup registry ────────────────────────────────────────────────────────
  // createdAt (unix seconds) must come from tx.timestamp — see MemoryStore.
  addDedupHash(hash, createdAt) {
    if (createdAt == null) {
      throw new Error("addDedupHash: createdAt (from tx.timestamp) is required for deterministic state");
    }
    this._stmts.addDedupHash.run(hash, createdAt);
  }
  hasDedupHash(hash) { return !!this._stmts.hasDedupHash.get(hash); }
  dedupCount() { return this._stmts.dedupCount.get().n; }

  // ── Revocations ───────────────────────────────────────────────────────────
  addRevocation(tipId, txType, timestamp, txId) {
    this._stmts.addRevoc.run(tipId, txType, timestamp, txId);
    this._stmts.revokeIdent.run(tipId);
  }
  isRevoked(tipId) { return !!this._stmts.isRevoked.get(tipId); }
  getRevocations(since) {
    return since
      ? this._stmts.revocSince.all(since)
      : this._stmts.revocAll.all();
  }

  // ── Verification Providers ────────────────────────────────────────────────
  saveVP(rec) {
    this._stmts.saveVP.run(
      rec.vp_id, rec.name,
      rec.jurisdiction || "US",
      rec.jurisdiction_tier || "green",
      rec.public_key || null,
      rec.status || "active",
      rec.registered_at || new Date().toISOString()
    );
  }
  getVP(vpId) { return this._stmts.getVP.get(vpId) || null; }
  getAllVPs() { return this._stmts.getAllVPs.all(); }

  // ── Nodes ───────────────────────────────────────────────────────────────
  saveNode(rec) {
    this._stmts.saveNode.run(
      rec.node_id, rec.name || null,
      rec.public_key,
      rec.status || "active",
      rec.registered_at || new Date().toISOString()
    );
  }
  getNode(nodeId) { return this._stmts.getNode.get(nodeId) || null; }
  getAllNodes() { return this._stmts.getAllNodes.all(); }

  // ── Certificates (Narwhal consensus) ──────────────────────────────────────
  saveCertificate(cert) {
    this._stmts.saveCert.run(
      cert.hash,
      cert.round,
      cert.author_node_id,
      JSON.stringify(cert.batch),
      JSON.stringify(cert.acknowledgments),
      JSON.stringify(cert.parent_hashes || []),
      cert.signature,
      Number(cert.timestamp || 0)
    );
  }
  getCertificate(hash) {
    const row = this._stmts.getCert.get(hash);
    return row ? this._parseCert(row) : null;
  }
  getCertificatesByRound(round) {
    return this._stmts.getCertsByRound.all(round).map(r => this._parseCert(r));
  }
  getCertificateByAuthorRound(authorNodeId, round) {
    const row = this._stmts.getCertsByAuthorRound.get(authorNodeId, round);
    return row ? this._parseCert(row) : null;
  }
  getLatestRound() {
    return this._stmts.getLatestRound.get().latest || 0;
  }
  // Earliest round with at least one cert still in storage. Returns 0 on
  // empty. O(1) via indexed MIN(round). Used by sync-handler to detect
  // below-GC-horizon joiner requests without loading the full cert table.
  getEarliestCertRound() {
    return this._stmts.getEarliestCertRound.get().earliest || 0;
  }
  getCertificatesFromRound(fromRound) {
    return this._stmts.getCertsFromRound.all(fromRound).map(r => this._parseCert(r));
  }
  certificateCount() {
    return this._stmts.countCerts.get().n;
  }
  // Cert GC (§2): drop every cert with round < cutoffRound. Returns rows
  // deleted. SQLite DELETE also removes the INSERT OR IGNORE dedup key so
  // the same cert hash would be accepted again if it re-arrived — by
  // design, since GC only targets rounds consensus has moved past.
  pruneCertificatesBefore(cutoffRound) {
    return this._stmts.pruneCertsBefore.run(cutoffRound).changes;
  }
  _parseCert(row) {
    if (!row) return null;
    return {
      ...row,
      batch: JSON.parse(row.batch_data),
      acknowledgments: JSON.parse(row.acknowledgments),
      parent_hashes: JSON.parse(row.parent_hashes),
    };
  }

  // ── Commit checkpoints (§15) ───────────────────────────────────────────────
  // One row per Bullshark anchor commit. Durable answer to:
  //   "what was the committee / consensus_index / anchor at round R?"
  // Populated by bullshark._checkAnchorCommit on every successful commit.
  saveCommit(rec) {
    this._stmts.saveCommit.run(
      rec.round,
      rec.anchor_cert_hash,
      rec.leader_node_id,
      JSON.stringify(rec.committee || []),
      rec.support_count,
      rec.consensus_index,
      rec.committed_at,
      rec.state_merkle_root,
      rec.txs_merkle_root,
      JSON.stringify(rec.ack_signer_ids || []),
      JSON.stringify(rec.ack_signatures || []),
      rec.anchor_batch_hash || null,        // #50: nullable — null on pre-fix rows or when the caller didn't pass it
      JSON.stringify(rec.ack_signed_ats || []),  // BFT-Time: parallel to ack_signatures
      Number(rec.cert_timestamp || 0),           // BFT-Time: median of acks.signed_at on the anchor cert
    );
  }
  getCommit(round) {
    const row = this._stmts.getCommit.get(round);
    return row ? this._parseCommit(row) : null;
  }
  getLatestCommit() {
    const row = this._stmts.getLatestCommit.get();
    return row ? this._parseCommit(row) : null;
  }
  getCommitsFromRound(fromRound) {
    return this._stmts.getCommitsFromRound.all(fromRound).map(r => this._parseCommit(r));
  }
  getLatestConsensusIndex() {
    return this._stmts.getLatestConsensusIndex.get().idx || 0;
  }
  // #44 — consensus_meta singleton kv (currently used to persist
  // consensus_index across restarts on idle federations).
  setConsensusMeta(key, value) {
    this._stmts.setConsensusMeta.run(key, String(value));
  }
  getConsensusMeta(key) {
    const row = this._stmts.getConsensusMeta.get(key);
    return row ? row.value : null;
  }
  // §14/#49 snapshot full-history streaming. Ordered by round (PK) so sender
  // + receiver hash commits in the same order → same commits_full_root.
  // Excludes the latest commit by design — that one already rides in
  // SnapshotHeader (round, anchor, acks, roots all live there). The caller
  // passes the latest round so we filter it out at the SQL level.
  *iterateAllCommitsExcept(latestRound) {
    const stmt = (latestRound != null && latestRound > 0)
      ? this.db.prepare("SELECT * FROM commits WHERE round != ? ORDER BY round ASC")
      : this.db.prepare("SELECT * FROM commits ORDER BY round ASC");
    const iter = (latestRound != null && latestRound > 0) ? stmt.iterate(latestRound) : stmt.iterate();
    for (const row of iter) {
      yield this._parseCommit(row);
    }
  }
  _parseCommit(row) {
    if (!row) return null;
    return {
      round: row.round,
      anchor_cert_hash: row.anchor_cert_hash,
      leader_node_id: row.leader_node_id,
      committee: JSON.parse(row.committee),
      support_count: row.support_count,
      consensus_index: row.consensus_index,
      committed_at: row.committed_at,
      state_merkle_root: row.state_merkle_root,
      txs_merkle_root: row.txs_merkle_root,
      ack_signer_ids: JSON.parse(row.ack_signer_ids),
      ack_signatures: JSON.parse(row.ack_signatures),
      // BFT-Time: parse JSON array; defaults to [] for any pre-BFT-Time
      // rows. cert_timestamp returns 0 for pre-BFT-Time rows (column has
      // a SQLite default of 0).
      ack_signed_ats: row.ack_signed_ats ? JSON.parse(row.ack_signed_ats) : [],
      cert_timestamp: row.cert_timestamp || 0,
      anchor_batch_hash: row.anchor_batch_hash || null,    // #50: null for pre-fix rows
    };
  }

  // ── Canonical derived state (§14 snapshot-sync) ───────────────────────────
  // See MemoryStore.iterateCanonicalState for the contract. SQLite version
  // uses prepared-statement cursors (better-sqlite3 iterate()) so rows flow
  // one at a time without loading the whole table. `ORDER BY <pk>` uses the
  // primary-key index, so sorting is free (no temp table / external sort).
  *iterateCanonicalState() {
    const db = this.db;
    for (const r of db.prepare("SELECT * FROM identities ORDER BY tip_id").iterate()) {
      yield { table: "identities", row: _canonIdentity({ ...r, founding: r.founding === 1 }) };
    }
    for (const r of db.prepare("SELECT * FROM content ORDER BY ctid").iterate()) {
      yield { table: "content", row: _canonContent({ ...r, prescan_flagged: r.prescan_flagged === 1 }) };
    }
    for (const r of db.prepare("SELECT tip_id, score, offense_count, last_updated FROM scores ORDER BY tip_id").iterate()) {
      yield { table: "scores", row: _canonScore(r.tip_id, r) };
    }
    for (const r of db.prepare("SELECT dedup_hash, created_at FROM dedup_registry ORDER BY dedup_hash").iterate()) {
      yield { table: "dedup_registry", row: _canonDedup(r.dedup_hash, r.created_at) };
    }
    for (const r of db.prepare("SELECT * FROM revocations ORDER BY tip_id").iterate()) {
      yield { table: "revocations", row: _canonRevocation(r) };
    }
    for (const r of db.prepare("SELECT * FROM verification_providers ORDER BY vp_id").iterate()) {
      yield { table: "verification_providers", row: _canonVP(r) };
    }
    for (const r of db.prepare("SELECT * FROM nodes ORDER BY node_id").iterate()) {
      yield { table: "nodes", row: _canonNode(r) };
    }
  }

  // ── Equivocation defense: votes_seen (§1) ──────────────────────────────────
  // recordSeenVote returns `true` if we inserted a new row, `false` if a row
  // for (round, author) already existed (the caller should then check the
  // stored batch_hash via getSeenVote before signing anything).
  recordSeenVote(round, author, batchHash) {
    const res = this._stmts.saveSeenVote.run(round, author, batchHash);
    return res.changes > 0;
  }
  getSeenVote(round, author) {
    return this._stmts.getSeenVote.get(round, author) || null;
  }
  pruneVotesSeenBefore(cutoffRound) {
    return this._stmts.pruneVotesSeenBefore.run(cutoffRound).changes;
  }

  // ── Persistent Mempool ────────────────────────────────────────────────────
  saveMempoolTx(tx) {
    this._stmts.saveMempoolTx.run(tx.tx_id, JSON.stringify(tx));
  }
  getMempoolTxs() {
    return this._stmts.getMempoolTxs.all().map(r => JSON.parse(r.tx_data));
  }
  deleteMempoolTx(txId) {
    this._stmts.deleteMempoolTx.run(txId);
  }
  deleteMempoolTxs(txIds) {
    const del = this._stmts.deleteMempoolTx;
    const batch = this.db.transaction((ids) => { for (const id of ids) del.run(id); });
    batch(txIds);
  }
  clearStaleMempoolTxs(beforeUnixSec) {
    this._stmts.clearMempoolBefore.run(beforeUnixSec);
  }
  mempoolCount() {
    return this._stmts.countMempool.get().n;
  }

  /**
   * Run a function inside a SQLite transaction (BEGIN → fn() → COMMIT).
   * If fn throws, the transaction is rolled back. Crash-safe.
   * @param {Function} fn  Function to run inside the transaction
   * @returns {*} Return value of fn
   */
  runInTransaction(fn) {
    return this.db.transaction(fn)();
  }

  close() {
    try { this.db.close(); } catch { /* ignore */ }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// DAG FACADE  —  single interface over either store
// ══════════════════════════════════════════════════════════════════════════════

function initDAG(config) {
  // ── Choose store ──────────────────────────────────────────────────────────
  let store;
  if (Database && config.dbPath !== ":memory:" && config.dbPath !== ":memory-test:") {
    try {
      store = new SQLiteStore(config.dbPath);
      log.info(`DAG store: SQLite @ ${config.dbPath}`);
    } catch (err) {
      log.warn(`SQLite init failed (${err.message}) — using in-memory store`);
      store = new MemoryStore();
    }
  } else {
    const reason = !Database ? "better-sqlite3 not installed" : "in-memory mode requested";
    log.warn(`DAG store: in-memory (${reason})`);
    store = new MemoryStore();
  }

  // ── Bootstrap: genesis block + founding VP ────────────────────────────────
  if (store.count() === 0) {
    _writeGenesisBlock(store, config);
  }

  // ── Recent tx ring buffer (last 2 tx IDs for prev[] on new txs) ───────────
  // Initialize from the two most recent txs in the DAG
  const allTxIds = store.getAllTxs().map(t => t.tx_id);
  let _prev = allTxIds.length >= 2
    ? [allTxIds[allTxIds.length - 1], allTxIds[allTxIds.length - 2]]
    : allTxIds.length === 1
      ? [allTxIds[0], allTxIds[0]]
      : [require("./genesis").GENESIS_TX_ID, require("./genesis").GENESIS_TX_ID];
  function _updatePrev(txId) { _prev = [txId, _prev[0]]; }

  // ── Public DAG API ────────────────────────────────────────────────────────
  const dag = {
    // ── Core transaction ops ───────────────────────────────────────────────
    addTx(tx) {
      // Order matters:
      // 1. timestamp first (part of canonical form)
      // 2. prev refs second (part of canonical form — must precede tx_id)
      // 3. tx_id last — SHAKE-256(canonical{tx_type,data,timestamp,prev})
      //
      // Auto-fill only fires when tx_id is NOT already set. A caller
      // that has committed to a tx_id has by construction committed to
      // a specific canonical form (timestamp + prev) — defaulting either
      // here would change the canonical bytes and break verifyTxId.
      // Genesis ships with `prev: []` on purpose; snapshot install and
      // committed-tx replay both pass tx_id and rely on this preservation.
      const hadTxId = !!tx.tx_id;
      if (!hadTxId) {
        if (!tx.timestamp) tx.timestamp = new Date().toISOString();
        if (!tx.prev || tx.prev.length === 0) tx.prev = [..._prev];
      }
      if (hadTxId && !verifyTxId(tx)) throw new Error(`addTx: tx_id mismatch — rejecting tampered tx ${tx.tx_id}`);

      if (!tx.tx_id) tx.tx_id = computeTxId(tx);
      store.saveTx(tx);
      _updatePrev(tx.tx_id);
      return tx;
    },
    getTx: (id) => store.getTx(id),
    getAllTxs: () => store.getAllTxs(),
    count: () => store.count(),
    getTxsByType: (type) => store.getTxsByType(type),
    getTxsByTypeAndCtid: (type, ctid) => store.getTxsByTypeAndCtid(type, ctid),
    getTxsByTipId: (tipId) => store.getTxsByTipId(tipId),
    getRecentPrev: () => [..._prev],

    // §14/#49 — streaming iterator over all rows in `transactions`,
    // ordered by tx_id. Used by snapshot sender to ship the full pre-
    // snapshot history. Receiver installs each row via addTx; addTx's
    // tightened auto-fill (no fill when tx_id is set) preserves
    // genesis-style `prev: []` correctly, and its per-row _updatePrev
    // leaves the ring at [highest_tx_id, second_highest] after the
    // batch — exactly what a fresh re-prime would compute.
    iterateAllTransactions: () => store.iterateAllTransactions(),

    // ── Identity ──────────────────────────────────────────────────────────
    saveIdentity: (rec) => store.saveIdentity(rec),
    getIdentity: (id) => store.getIdentity(id),
    getAllIdentities: () => store.getAllIdentities(),

    // ── Content ───────────────────────────────────────────────────────────
    saveContent: (rec) => store.saveContent(rec),
    getContent: (ctid) => store.getContent(ctid),
    updateContentStatus: (ctid, s) => store.updateContentStatus(ctid, s),
    updateContentOrigin: (ctid, o, s) => store.updateContentOrigin(ctid, o, s),
    getContentByAuthor: (id) => store.getContentByAuthor(id),
    getContentByStatus: (s) => store.getContentByStatus(s),
    getCleanRecordEligible: (cutoff) => store.getCleanRecordEligible(cutoff),
    hasVerification: (ctid, tipId) => store.hasVerification(ctid, tipId),
    hasDispute: (ctid, tipId) => store.hasDispute(ctid, tipId),

    // ── Scores ────────────────────────────────────────────────────────────
    setScore: (id, s, o, lastUpdatedISO) => store.setScore(id, s, o, lastUpdatedISO),
    getScore: (id) => store.getScore(id),

    // ── Dedup registry ────────────────────────────────────────────────────
    addDedupHash: (h, createdAt) => store.addDedupHash(h, createdAt),
    hasDedupHash: (h) => store.hasDedupHash(h),
    dedupCount: () => store.dedupCount(),

    // ── Canonical derived state (§14 snapshot-sync) ──────────────────────
    // Streaming iterator over all derived-state tables in deterministic
    // order. Consumed by consensus/state-root.js to hash row-by-row.
    iterateCanonicalState: () => store.iterateCanonicalState(),

    // ── Revocations (v2 FIX-05) ───────────────────────────────────────────
    addRevocation: (id, type, ts, txId) => store.addRevocation(id, type, ts, txId),
    isRevoked: (id) => store.isRevoked(id),
    getRevocations: (since) => store.getRevocations(since),

    // ── Verification Providers ────────────────────────────────────────────
    saveVP: (rec) => store.saveVP(rec),
    getVP: (id) => store.getVP(id),
    getAllVPs: () => store.getAllVPs(),

    // ── Nodes ────────────────────────────────────────────────────────────
    saveNode: (rec) => store.saveNode(rec),
    getNode: (id) => store.getNode(id),
    getAllNodes: () => store.getAllNodes(),

    // ── Certificates (Narwhal consensus) ─────────────────────────────────
    saveCertificate: (cert) => store.saveCertificate(cert),
    getCertificate: (hash) => store.getCertificate(hash),
    getCertificatesByRound: (round) => store.getCertificatesByRound(round),
    getCertificateByAuthorRound: (author, r) => store.getCertificateByAuthorRound(author, r),
    getLatestRound: () => store.getLatestRound(),
    getEarliestCertRound: () => store.getEarliestCertRound(),
    getCertificatesFromRound: (fromRound) => store.getCertificatesFromRound(fromRound),
    certificateCount: () => store.certificateCount(),
    pruneCertificatesBefore: (cutoff) => store.pruneCertificatesBefore(cutoff),
    incrementalVacuum: (maxPages) => store.incrementalVacuum(maxPages),

    // ── Commit checkpoints (§15 Bullshark anchor commits) ───────────────
    saveCommit: (rec) => store.saveCommit(rec),
    getCommit: (round) => store.getCommit(round),
    getLatestCommit: () => store.getLatestCommit(),
    getCommitsFromRound: (fromRound) => store.getCommitsFromRound(fromRound),
    getLatestConsensusIndex: () => store.getLatestConsensusIndex(),
    // #44 — consensus_meta singleton kv. setConsensusMeta replaces (not
    // appends) the row for `key`. getConsensusMeta returns null when the
    // key is missing — caller decides the fallback (e.g. bullshark falls
    // back to getLatestConsensusIndex() for legacy DBs).
    setConsensusMeta: (key, value) => store.setConsensusMeta(key, value),
    getConsensusMeta: (key) => store.getConsensusMeta(key),
    // §14/#49 streaming iterator over all rows in `commits` ordered by
    // round, EXCLUDING the latest (which already rides in SnapshotHeader
    // — round, anchor, acks, roots all live there). Used by snapshot
    // sender to ship full commit history for chain-of-trust audits.
    iterateAllCommitsExcept: (latestRound) => store.iterateAllCommitsExcept(latestRound),

    // ── Equivocation defense: votes_seen (§1) ────────────────────────────
    recordSeenVote: (round, author, batchHash) => store.recordSeenVote(round, author, batchHash),
    getSeenVote: (round, author) => store.getSeenVote(round, author),
    pruneVotesSeenBefore: (cutoff) => store.pruneVotesSeenBefore(cutoff),

    // ── Persistent Mempool ────────────────────────────────────────────────
    saveMempoolTx: (tx) => store.saveMempoolTx(tx),
    getMempoolTxs: () => store.getMempoolTxs(),
    deleteMempoolTx: (txId) => store.deleteMempoolTx(txId),
    deleteMempoolTxs: (txIds) => store.deleteMempoolTxs(txIds),
    clearStaleMempoolTxs: (before) => store.clearStaleMempoolTxs(before),
    mempoolCount: () => store.mempoolCount(),

    // ── DB Transactions ──────────────────────────────────────────────────
    runInTransaction: (fn) => store.runInTransaction(fn),

    close: () => store.close(),
  };

  return dag;
}

// ─── Write genesis block and founding VP into a fresh store ──────────────────
function _writeGenesisBlock(store, config) {
  const {
    GENESIS_TX_ID, GENESIS_TX, GENESIS_TIMESTAMP, GENESIS_HASH, GENESIS_PAYLOAD,
    GENESIS_TX_SIGNATURE, GENESIS_VP_TX_SIGNATURE, getFoundingVP,
  } = require("./genesis");

  // Genesis transaction — content-addressed tx_id, pre-signed by founding VP
  store.saveTx({ ...GENESIS_TX, tx_id: GENESIS_TX_ID, signature: GENESIS_TX_SIGNATURE });

  // Bootstrap founding VP from genesis payload (public key embedded by seed script)
  const foundingVP = getFoundingVP();

  store.saveVP({
    vp_id: foundingVP.vp_id,
    name: foundingVP.name,
    jurisdiction: foundingVP.jurisdiction,
    jurisdiction_tier: foundingVP.jurisdiction_tier,
    public_key: foundingVP.public_key,
    status: "active",
    registered_at: GENESIS_TIMESTAMP,
  });

  // VP registration transaction — pre-signed by founding VP
  const vpTx = {
    tx_type: TX_TYPES.VP_REGISTERED,
    timestamp: GENESIS_TIMESTAMP,
    prev: [GENESIS_TX_ID, GENESIS_TX_ID],
    data: {
      vp_id: foundingVP.vp_id,
      name: foundingVP.name,
      jurisdiction: foundingVP.jurisdiction,
      jurisdiction_tier: foundingVP.jurisdiction_tier,
      public_key: foundingVP.public_key,
    },
  };
  store.saveTx({ ...vpTx, tx_id: computeTxId(vpTx), signature: GENESIS_VP_TX_SIGNATURE });

  // Bootstrap founding identities from genesis_ring_keys (embedded by seed script)
  const ringKeys = GENESIS_PAYLOAD.genesis_ring_keys || [];
  const vpTxId = computeTxId(vpTx);
  let lastTxId = vpTxId;

  for (const member of ringKeys) {
    if (!member.tip_id || !member.public_key) continue;

    const mockZkProof = { pi_a: ["1", "2", "3"], pi_b: [["1", "2"], ["3", "4"], ["5", "6"]], pi_c: ["1", "2", "3"], protocol: "groth16", curve: "bn128" };
    const registeredAt = GENESIS_TIMESTAMP;
    const idTx = {
      tx_type: TX_TYPES.REGISTER_IDENTITY,
      timestamp: registeredAt,
      prev: [lastTxId, lastTxId],
      data: {
        tip_id: member.tip_id,
        region: member.region || "US",
        public_key: member.public_key,
        vp_id: foundingVP.vp_id,
        verification_tier: "T1",
        social_attested: true,
        founding: true,
        dedup_hash: member.dedup_hash,
        zk_proof: mockZkProof,
        vp_signature: member.vp_signature,
      },
    };
    const idTxId = computeTxId(idTx);
    store.saveTx({ ...idTx, tx_id: idTxId });

    store.saveIdentity({
      tip_id: member.tip_id,
      region: member.region || "US",
      public_key: member.public_key,
      vp_id: foundingVP.vp_id,
      verification_tier: "T1",
      founding: true,
      status: "active",
      registered_at: registeredAt,
      tx_id: idTxId,
    });

    if (member.dedup_hash) {
      // Genesis bootstrap — created_at derived from the genesis timestamp
      // (same on every node that ships the same genesis). Deterministic.
      store.addDedupHash(member.dedup_hash, Math.floor(new Date(GENESIS_TIMESTAMP).getTime() / 1000));
    }
    // Genesis seed score — last_updated sourced from GENESIS_TIMESTAMP so
    // every node bootstraps with an identical scores row (issue #31).
    store.setScore(member.tip_id, 550, 0, GENESIS_TIMESTAMP);
    lastTxId = idTxId;

    log.info(`Founding identity registered: ${member.tip_id}`);
  }

  // Bootstrap founding node from genesis payload (embedded by seed script)
  const foundingNode = GENESIS_PAYLOAD.founding_node;
  if (foundingNode && foundingNode.node_id && foundingNode.public_key) {
    const nodeTx = {
      tx_type: TX_TYPES.NODE_REGISTERED,
      timestamp: GENESIS_TIMESTAMP,
      prev: [lastTxId, lastTxId],
      data: {
        node_id: foundingNode.node_id,
        name: foundingNode.name,
        public_key: foundingNode.public_key,
        council_signature: foundingNode.council_signature,
        approving_vp_id: foundingNode.approving_vp_id,
      },
    };
    store.saveTx({ ...nodeTx, tx_id: computeTxId(nodeTx) });
    store.saveNode({
      node_id: foundingNode.node_id,
      name: foundingNode.name,
      public_key: foundingNode.public_key,
      status: "active",
      registered_at: GENESIS_TIMESTAMP,
    });
    log.info(`Founding node registered: ${foundingNode.node_id}`);
  }

  log.info(`Genesis block written. Chain: tip-mainnet-v2 | Hash: ${GENESIS_HASH.slice(0, 16)}...`);
  log.info(`Founding VP registered: ${foundingVP.vp_id}`);
  if (ringKeys.length > 0) log.info(`Genesis ring: ${ringKeys.length} founding identities`);
}

module.exports = { initDAG };
