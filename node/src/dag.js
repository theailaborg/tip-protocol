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

const path   = require("path");
const fs     = require("fs");
const { shake256, computeTxId, verifyTxId } = require("../../shared/crypto");
const { TX_TYPES }               = require("../../shared/constants");
const { log }                    = require("./logger");

// ─── SQLite loaded lazily ─────────────────────────────────────────────────────
let Database = null;
try { Database = require("better-sqlite3"); } catch { /* use in-memory */ }

// ══════════════════════════════════════════════════════════════════════════════
// IN-MEMORY STORE
// ══════════════════════════════════════════════════════════════════════════════
class MemoryStore {
  constructor() {
    this._txs         = new Map();  // tx_id -> tx
    this._identities  = new Map();  // tip_id -> record
    this._content     = new Map();  // ctid -> record
    this._scores      = new Map();  // tip_id -> { score, offense_count, last_updated }
    this._dedup       = new Set();  // dedup_hash strings (Poseidon field elements)
    this._revocations = new Map();  // tip_id -> { tip_id, tx_type, timestamp, tx_id }
    this._vps         = new Map();  // vp_id -> record
  }

  // ── Transactions ─────────────────────────────────────────────────────────
  saveTx(tx) { this._txs.set(tx.tx_id, { ...tx }); }
  getTx(id)  { return this._txs.get(id) || null; }
  getAllTxs() { return [...this._txs.values()]; }
  count()    { return this._txs.size; }

  getTxsByType(type) {
    return [...this._txs.values()].filter(t => t.tx_type === type);
  }
  getTxsByTipId(tipId) {
    return [...this._txs.values()].filter(t =>
      t.data?.tip_id === tipId || t.data?.author_tip_id === tipId
    );
  }

  // ── Identities ────────────────────────────────────────────────────────────
  saveIdentity(rec) { this._identities.set(rec.tip_id, { ...rec }); }
  getIdentity(id)   { return this._identities.get(id) || null; }

  // ── Content ───────────────────────────────────────────────────────────────
  saveContent(rec)  { this._content.set(rec.ctid, { ...rec }); }
  getContent(ctid)  { return this._content.get(ctid) || null; }
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
      if (tx.tx_type === "CONTENT_DISPUTED" && !tx.data?.auto &&
          tx.data?.ctid === ctid && tx.data?.disputer_tip_id === tipId) return true;
    }
    return false;
  }

  // ── Scores ────────────────────────────────────────────────────────────────
  setScore(tipId, score, offenseCount = 0) {
    this._scores.set(tipId, {
      score:          Math.max(0, Math.min(1000, score)),
      offense_count:  offenseCount || 0,
      last_updated:   new Date().toISOString(),
    });
  }
  getScore(tipId) { return this._scores.get(tipId) || null; }

  // ── Dedup registry ────────────────────────────────────────────────────────
  addDedupHash(hash)  { this._dedup.add(hash); }
  hasDedupHash(hash)  { return this._dedup.has(hash); }
  dedupCount()        { return this._dedup.size; }

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
  getAllVPs()  { return [...this._vps.values()]; }

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
        jurisdiction_tier  TEXT NOT NULL DEFAULT 'green',
        public_key         TEXT,
        status             TEXT NOT NULL DEFAULT 'active',
        registered_at      TEXT NOT NULL
      );
    `);
  }

  _prepare() {
    // Pre-compile hot-path statements for performance
    this._stmts = {
      saveTx: this.db.prepare(
        `INSERT OR REPLACE INTO transactions
           (tx_id,tx_type,data,timestamp,prev,signature)
         VALUES (?,?,?,?,?,?)`
      ),
      getTx: this.db.prepare("SELECT * FROM transactions WHERE tx_id=?"),
      getAllTxs: this.db.prepare("SELECT * FROM transactions ORDER BY created_at ASC"),
      countTxs:  this.db.prepare("SELECT COUNT(*) AS n FROM transactions"),
      txsByType: this.db.prepare("SELECT * FROM transactions WHERE tx_type=? ORDER BY created_at ASC"),
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

      saveContent: this.db.prepare(
        `INSERT OR REPLACE INTO content
           (ctid,origin_code,content_hash,perceptual_hash,author_tip_id,
            status,prescan_flagged,registered_at,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?)`
      ),
      getContent:  this.db.prepare("SELECT * FROM content WHERE ctid=?"),
      contentByAuthor: this.db.prepare("SELECT * FROM content WHERE author_tip_id=?"),
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
           AND json_extract(data,'$.auto') IS NULL
         LIMIT 1`
      ),

      setScore: this.db.prepare(
        `INSERT OR REPLACE INTO scores (tip_id,score,offense_count,last_updated)
         VALUES (?,?,?,?)`
      ),
      getScore: this.db.prepare("SELECT * FROM scores WHERE tip_id=?"),

      addDedupHash:   this.db.prepare("INSERT OR IGNORE INTO dedup_registry (dedup_hash) VALUES (?)"),
      hasDedupHash:   this.db.prepare("SELECT 1 FROM dedup_registry WHERE dedup_hash=?"),
      dedupCount:     this.db.prepare("SELECT COUNT(*) AS n FROM dedup_registry"),

      addRevoc:    this.db.prepare(
        `INSERT OR REPLACE INTO revocations (tip_id,tx_type,timestamp,tx_id)
         VALUES (?,?,?,?)`
      ),
      isRevoked:   this.db.prepare("SELECT 1 FROM revocations WHERE tip_id=?"),
      revocAll:    this.db.prepare("SELECT * FROM revocations ORDER BY timestamp DESC"),
      revocSince:  this.db.prepare("SELECT * FROM revocations WHERE timestamp>? ORDER BY timestamp DESC"),
      revokeIdent: this.db.prepare("UPDATE identities SET status='revoked' WHERE tip_id=?"),

      saveVP: this.db.prepare(
        `INSERT OR REPLACE INTO verification_providers
           (vp_id,name,jurisdiction_tier,public_key,status,registered_at)
         VALUES (?,?,?,?,?,?)`
      ),
      getVP:    this.db.prepare("SELECT * FROM verification_providers WHERE vp_id=?"),
      getAllVPs: this.db.prepare("SELECT * FROM verification_providers"),
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
  getTx(id)    { return this._parseTx(this._stmts.getTx.get(id)); }
  getAllTxs()  { return this._stmts.getAllTxs.all().map(r => this._parseTx(r)); }
  count()      { return this._stmts.countTxs.get().n; }
  getTxsByType(type)   { return this._stmts.txsByType.all(type).map(r => this._parseTx(r)); }
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

  // ── Content ───────────────────────────────────────────────────────────────
  saveContent(rec) {
    this._stmts.saveContent.run(
      rec.ctid, rec.origin_code,
      rec.content_hash, rec.perceptual_hash || null,
      rec.author_tip_id,
      rec.status || "verified",
      rec.prescan_flagged ? 1 : 0,
      rec.registered_at, rec.tx_id || null
    );
  }
  getContent(ctid)            { return this._stmts.getContent.get(ctid) || null; }
  getContentByAuthor(tipId)   { return this._stmts.contentByAuthor.all(tipId); }
  hasVerification(ctid, tipId) { return !!this._stmts.hasVerification.get(ctid, tipId); }
  hasDispute(ctid, tipId)      { return !!this._stmts.hasDispute.get(ctid, tipId); }

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
  addDedupHash(hash)  { this._stmts.addDedupHash.run(hash); }
  hasDedupHash(hash)  { return !!this._stmts.hasDedupHash.get(hash); }
  dedupCount()        { return this._stmts.dedupCount.get().n; }

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
      rec.jurisdiction_tier || "green",
      rec.public_key || null,
      rec.status || "active",
      rec.registered_at || new Date().toISOString()
    );
  }
  getVP(vpId)  { return this._stmts.getVP.get(vpId) || null; }
  getAllVPs()   { return this._stmts.getAllVPs.all(); }

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
  let _prev = ["genesis-" + "0".repeat(16), "genesis-" + "0".repeat(16)];
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
    getTx:          (id)      => store.getTx(id),
    getAllTxs:       ()        => store.getAllTxs(),
    count:           ()        => store.count(),
    getTxsByType:    (type)    => store.getTxsByType(type),
    getTxsByTipId:   (tipId)   => store.getTxsByTipId(tipId),
    getRecentPrev:   ()        => [..._prev],

    // ── Identity ──────────────────────────────────────────────────────────
    saveIdentity:    (rec)     => store.saveIdentity(rec),
    getIdentity:     (id)      => store.getIdentity(id),

    // ── Content ───────────────────────────────────────────────────────────
    saveContent:       (rec)         => store.saveContent(rec),
    getContent:        (ctid)        => store.getContent(ctid),
    getContentByAuthor: (id)         => store.getContentByAuthor(id),
    hasVerification:   (ctid, tipId) => store.hasVerification(ctid, tipId),
    hasDispute:        (ctid, tipId) => store.hasDispute(ctid, tipId),

    // ── Scores ────────────────────────────────────────────────────────────
    setScore:        (id, s, o) => store.setScore(id, s, o),
    getScore:        (id)       => store.getScore(id),

    // ── Dedup registry ────────────────────────────────────────────────────
    addDedupHash:    (h)        => store.addDedupHash(h),
    hasDedupHash:    (h)        => store.hasDedupHash(h),
    dedupCount:      ()         => store.dedupCount(),

    // ── Revocations (v2 FIX-05) ───────────────────────────────────────────
    addRevocation:   (id, type, ts, txId) => store.addRevocation(id, type, ts, txId),
    isRevoked:       (id)       => store.isRevoked(id),
    getRevocations:  (since)    => store.getRevocations(since),

    // ── Verification Providers ────────────────────────────────────────────
    saveVP:          (rec)      => store.saveVP(rec),
    getVP:           (id)       => store.getVP(id),
    getAllVPs:        ()         => store.getAllVPs(),

    close:           ()         => store.close(),
  };

  return dag;
}

// ─── Write genesis block and founding VP into a fresh store ──────────────────
function _writeGenesisBlock(store, config) {
  const {
    GENESIS_TX_ID, GENESIS_TIMESTAMP, GENESIS_HASH, getFoundingVP,
  } = require("./genesis");
  const { generateMLDSAKeypair } = require("../../shared/crypto");

  // Genesis transaction
  const genesisTx = {
    tx_id:      GENESIS_TX_ID,
    tx_type:    "GENESIS",
    timestamp:  GENESIS_TIMESTAMP,
    prev:       [],
    data: {
      protocol:       "TIP",
      version:        "2.0.0",
      chain_id:       "tip-mainnet-v2",
      genesis_hash:   GENESIS_HASH,
      issuer:         "The AI Lab Intelligence Unobscured, Inc.",
      spec_url:       "https://theailab.org/trust-identity-protocol",
    },
    signature:      "genesis-self-signed",
  };
  store.saveTx(genesisTx);

  // Bootstrap founding VP from genesis.js constants
  const foundingVP = getFoundingVP();
  const vpKeypair  = generateMLDSAKeypair();

  store.saveVP({
    vp_id:             foundingVP.vp_id,
    name:              foundingVP.name,
    jurisdiction_tier: foundingVP.jurisdiction_tier,
    public_key:        vpKeypair.publicKey,
    status:            "active",
    registered_at:     GENESIS_TIMESTAMP,
  });

  // VP registration transaction
  const vpTx = {
    tx_type:   TX_TYPES.VP_REGISTERED,
    timestamp: GENESIS_TIMESTAMP,
    prev:      [GENESIS_TX_ID, GENESIS_TX_ID],
    data: {
      vp_id:             foundingVP.vp_id,
      name:              foundingVP.name,
      jurisdiction_tier: foundingVP.jurisdiction_tier,
      public_key:        vpKeypair.publicKey,
    },
    signature: "genesis-vp-bootstrap",
  };
  store.saveTx({ ...vpTx, tx_id: computeTxId(vpTx) });

  log.info(`Genesis block written. Chain: tip-mainnet-v2 | Hash: ${GENESIS_HASH.slice(0, 16)}...`);
  log.info(`Founding VP registered: ${foundingVP.vp_id}`);
}

module.exports = { initDAG };
