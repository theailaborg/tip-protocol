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
  setScore(tipId, score, offenseCount = 0) {
    this._scores.set(tipId, {
      score: Math.max(0, Math.min(1000, score)),
      offense_count: offenseCount || 0,
      last_updated: new Date().toISOString(),
    });
  }
  getScore(tipId) { return this._scores.get(tipId) || null; }

  // ── Dedup registry ────────────────────────────────────────────────────────
  addDedupHash(hash) { this._dedup.add(hash); }
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
  getCertificatesFromRound(fromRound) {
    return [...this._certs.values()]
      .filter(c => c.round >= fromRound)
      .sort((a, b) => a.round !== b.round ? a.round - b.round : a.author_node_id.localeCompare(b.author_node_id));
  }
  certificateCount() { return this._certs.size; }

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
    this._migrate();
    this._prepare();
  }

  _migrate() {
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
      CREATE TABLE IF NOT EXISTS dedup_registry (
        dedup_hash  TEXT PRIMARY KEY,
        created_at  INTEGER NOT NULL DEFAULT (unixepoch())
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
        round            INTEGER PRIMARY KEY,
        anchor_cert_hash TEXT NOT NULL,
        leader_node_id   TEXT NOT NULL,
        committee        TEXT NOT NULL,   -- JSON sorted array of node_ids
        support_count    INTEGER NOT NULL,
        consensus_index  INTEGER NOT NULL,
        committed_at     TEXT NOT NULL,   -- ISO8601 wall-clock
        created_at       INTEGER NOT NULL DEFAULT (unixepoch())
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
    `);
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
            verification_tier,founding,status,registered_at,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?,?)`
      ),
      getIdentity: this.db.prepare("SELECT * FROM identities WHERE tip_id=?"),
      getAllIdentities: this.db.prepare("SELECT * FROM identities WHERE status='active'"),

      saveContent: this.db.prepare(
        `INSERT OR REPLACE INTO content
           (ctid,origin_code,content_hash,perceptual_hash,author_tip_id,
            status,prescan_flagged,registered_at,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?)`
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

      addDedupHash: this.db.prepare("INSERT OR IGNORE INTO dedup_registry (dedup_hash) VALUES (?)"),
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

      // Certificates
      saveCert: this.db.prepare(
        `INSERT OR IGNORE INTO certificates
           (hash,round,author_node_id,batch_data,acknowledgments,parent_hashes,signature)
         VALUES (?,?,?,?,?,?,?)`
      ),
      getCert: this.db.prepare("SELECT * FROM certificates WHERE hash=?"),
      getCertsByRound: this.db.prepare("SELECT * FROM certificates WHERE round=? ORDER BY author_node_id"),
      getCertsByAuthorRound: this.db.prepare("SELECT * FROM certificates WHERE author_node_id=? AND round=?"),
      getLatestRound: this.db.prepare("SELECT MAX(round) AS latest FROM certificates"),
      getCertsFromRound: this.db.prepare("SELECT * FROM certificates WHERE round>=? ORDER BY round ASC, author_node_id ASC"),
      countCerts: this.db.prepare("SELECT COUNT(*) AS n FROM certificates"),

      // Commit checkpoints (§15)
      saveCommit: this.db.prepare(
        `INSERT OR IGNORE INTO commits
           (round,anchor_cert_hash,leader_node_id,committee,support_count,consensus_index,committed_at)
         VALUES (?,?,?,?,?,?,?)`
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

  // ── Identities ────────────────────────────────────────────────────────────
  saveIdentity(rec) {
    this._stmts.saveIdentity.run(
      rec.tip_id, rec.region || "US",
      rec.public_key, rec.root_public_key || null,
      rec.vp_id || null, rec.verification_tier || "T1",
      rec.founding ? 1 : 0,
      rec.status || "active",
      rec.registered_at, rec.tx_id || null
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
      rec.registered_at, rec.tx_id || null
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
    return this.db.prepare(`
      SELECT DISTINCT i.tip_id FROM identities i
      WHERE i.status = 'active'
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
    `).all(cutoff, cutoff, cutoff).map(r => r.tip_id);
  }

  // ── Scores ────────────────────────────────────────────────────────────────
  setScore(tipId, score, offenseCount = 0) {
    this._stmts.setScore.run(
      tipId,
      Math.max(0, Math.min(1000, score)),
      offenseCount || 0,
      new Date().toISOString()
    );
  }
  getScore(tipId) { return this._stmts.getScore.get(tipId) || null; }

  // ── Dedup registry ────────────────────────────────────────────────────────
  addDedupHash(hash) { this._stmts.addDedupHash.run(hash); }
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
      cert.signature
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
  getCertificatesFromRound(fromRound) {
    return this._stmts.getCertsFromRound.all(fromRound).map(r => this._parseCert(r));
  }
  certificateCount() {
    return this._stmts.countCerts.get().n;
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
      rec.committed_at
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
    };
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
      if (!tx.timestamp) tx.timestamp = new Date().toISOString();
      if (!tx.prev || tx.prev.length === 0) tx.prev = [..._prev];
      const hadTxId = !!tx.tx_id;
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
    setScore: (id, s, o) => store.setScore(id, s, o),
    getScore: (id) => store.getScore(id),

    // ── Dedup registry ────────────────────────────────────────────────────
    addDedupHash: (h) => store.addDedupHash(h),
    hasDedupHash: (h) => store.hasDedupHash(h),
    dedupCount: () => store.dedupCount(),

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
    getCertificatesFromRound: (fromRound) => store.getCertificatesFromRound(fromRound),
    certificateCount: () => store.certificateCount(),

    // ── Commit checkpoints (§15 Bullshark anchor commits) ───────────────
    saveCommit: (rec) => store.saveCommit(rec),
    getCommit: (round) => store.getCommit(round),
    getLatestCommit: () => store.getLatestCommit(),
    getCommitsFromRound: (fromRound) => store.getCommitsFromRound(fromRound),
    getLatestConsensusIndex: () => store.getLatestConsensusIndex(),

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

    if (member.dedup_hash) store.addDedupHash(member.dedup_hash);
    store.setScore(member.tip_id, 550, 0);
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
