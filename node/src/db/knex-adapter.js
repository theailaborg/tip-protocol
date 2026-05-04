/**
 * @file @tip-protocol/node/src/db/knex-adapter.js
 * @description Async Knex adapter for server-side DBs (Postgres, MariaDB, MSSQL, Oracle).
 *
 * Mirror pattern: all reads go to an in-memory MemoryStore (sync, no await
 * needed at call sites). All writes go to: (1) the mirror immediately, and
 * (2) the DB asynchronously via fire-and-forget. The only async surface is
 * migrate() which must be awaited once at startup.
 *
 * This keeps every dag.js call-site synchronous — the 27 test files that use
 * initDAG() with ":memory:" continue to work without changes.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// MemoryStore is exported from dag.js. dag.js does NOT require knex-adapter at
// load time (only inside initDAGAsync), so by the time knex-adapter.js first
// loads, dag.js is fully cached — no circular-dep hazard.
const { MemoryStore } = require("../dag");
const { subjectTipId } = require("../tx-attribution");

// ─── Schema helpers ───────────────────────────────────────────────────────────
// Uses the Knex schema builder instead of raw DDL so the same code runs on
// PostgreSQL, MariaDB, MySQL, MSSQL, and Oracle without driver-specific SQL.
//
// Key decisions:
//  • ID / reference columns use string(col, 512) → VARCHAR(512), which can be
//    a primary key on every driver (raw TEXT PRIMARY KEY fails on MariaDB).
//  • Large payload columns (data, public_key, batch_data …) use text() →
//    TEXT / MEDIUMTEXT / CLOB depending on the driver.
//  • "tip_ctid" is used instead of "ctid" because PostgreSQL reserves "ctid"
//    as a system column. The adapter maps tip_ctid ↔ ctid transparently.
//  • All tables are created via hasTable → createTable, so re-running migrate()
//    on an existing database is safe (idempotent).

function _id(t, col)  { return t.string(col, 512); }
function _pk(t, col)  { return t.string(col, 512).primary(); }

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _j(v) {
  try { return JSON.parse(v || "null"); } catch { return null; }
}

function _parseTxRow(row) {
  return {
    tx_id:          row.tx_id,
    tx_type:        row.tx_type,
    data:           _j(row.data) || {},
    timestamp:      row.timestamp,
    prev:           _j(row.prev) || [],
    signature:      row.signature || null,
    subject_tip_id: row.subject_tip_id || null,
  };
}

function _parseCertRow(row) {
  return {
    hash:            row.hash,
    round:           row.round,
    author_node_id:  row.author_node_id,
    batch:           _j(row.batch_data) || {},
    acknowledgments: _j(row.acknowledgments) || [],
    parent_hashes:   _j(row.parent_hashes) || [],
    signature:       row.signature,
    timestamp:       Number(row.timestamp || 0),
  };
}

function _parseCommitRow(row) {
  return {
    round:              row.round,
    anchor_cert_hash:   row.anchor_cert_hash,
    leader_node_id:     row.leader_node_id,
    committee:          _j(row.committee) || [],
    support_count:      row.support_count,
    consensus_index:    row.consensus_index,
    committed_at:       row.committed_at,
    state_merkle_root:  row.state_merkle_root,
    txs_merkle_root:    row.txs_merkle_root,
    ack_signer_ids:     _j(row.ack_signer_ids) || [],
    ack_signatures:     _j(row.ack_signatures) || [],
    ack_signed_ats:     _j(row.ack_signed_ats) || [],
    cert_timestamp:     Number(row.cert_timestamp || 0),
    anchor_batch_hash:  row.anchor_batch_hash || null,
  };
}

// ─── KnexAdapter ─────────────────────────────────────────────────────────────

class KnexAdapter {
  constructor(driver, config, log) {
    this.log = log || { info: () => {}, warn: () => {}, error: () => {} };
    this.mirror = new MemoryStore();

    // Map driver aliases to Knex client names
    const clientMap = { postgres: "pg", mariadb: "mysql2", mysql: "mysql2", mssql: "mssql", sqlserver: "mssql", oracle: "oracledb" };
    const client = clientMap[driver] || driver;

    let connection;
    if (config.dbUrl) {
      connection = config.dbUrl;
    } else {
      connection = {
        host:     config.dbHost     || process.env.DB_HOST     || "localhost",
        port:     config.dbPort     || Number(process.env.DB_PORT || (driver === "postgres" ? 5432 : driver === "mssql" || driver === "sqlserver" ? 1433 : driver === "oracle" ? 1521 : 3306)),
        database: config.dbName     || process.env.DB_NAME     || "tip_protocol",
        user:     config.dbUser     || process.env.DB_USER     || "tip",
        password: config.dbPassword || process.env.DB_PASSWORD || "",
      };
      if (config.dbSsl || process.env.DB_SSL === "true") {
        connection.ssl = {
          rejectUnauthorized: config.dbSslRejectUnauthorized !== false && process.env.DB_SSL_REJECT_UNAUTHORIZED !== "false",
        };
      }
    }

    const knex = require("knex");
    this.knex = knex({
      client,
      connection,
      pool: {
        min: config.dbPoolMin != null ? config.dbPoolMin : Number(process.env.DB_POOL_MIN || 2),
        max: config.dbPoolMax != null ? config.dbPoolMax : Number(process.env.DB_POOL_MAX || 10),
      },
      acquireConnectionTimeout: 10000,
    });
  }

  // ── Startup ────────────────────────────────────────────────────────────────

  async migrate() {
    await this._ensureSchema();
    await this._hydrate();
    this.log.info("KnexAdapter: schema ready, mirror hydrated");
  }

  async _ensureSchema() {
    const db = this.knex;
    const ensure = async (name, defFn) => {
      if (!(await db.schema.hasTable(name))) {
        await db.schema.createTable(name, defFn);
      }
    };

    await ensure("transactions", t => {
      _pk(t, "tx_id");
      t.string("tx_type", 64).notNullable();
      t.text("data").notNullable();
      t.string("timestamp", 64).notNullable();
      t.text("prev").notNullable().defaultTo("[]");
      t.text("signature").nullable();
      _id(t, "subject_tip_id").nullable();
      t.bigInteger("created_at").notNullable().defaultTo(0);
      t.index("tx_type",       "idx_txs_type");
      t.index("timestamp",     "idx_txs_ts");
      t.index("created_at",    "idx_txs_created_at");
      t.index("subject_tip_id","idx_txs_subject");
    });

    await ensure("identities", t => {
      _pk(t, "tip_id");
      t.string("region", 8).notNullable().defaultTo("US");
      t.text("public_key").notNullable();
      t.text("root_public_key").nullable();
      _id(t, "vp_id").nullable();
      t.string("verification_tier",  8).notNullable().defaultTo("T1");
      t.string("score_display_mode", 32).notNullable().defaultTo("TIER_ONLY");
      t.integer("founding").notNullable().defaultTo(0);
      t.string("status", 32).notNullable().defaultTo("active");
      t.string("registered_at", 64).notNullable();
      t.text("creator_name").nullable();
      _id(t, "tx_id").nullable();
      t.index("vp_id",  "idx_id_vp");
      t.index("status", "idx_id_status");
    });

    await ensure("content", t => {
      // tip_ctid = application-level CTID; "ctid" is reserved in PostgreSQL
      t.string("tip_ctid", 512).primary();
      t.string("origin_code", 8).notNullable();
      t.string("content_hash", 128).notNullable();
      t.string("perceptual_hash", 128).nullable();
      _id(t, "author_tip_id").notNullable();
      t.string("status", 32).notNullable().defaultTo("verified");
      t.integer("dispute_count").notNullable().defaultTo(0);
      t.integer("verification_count").notNullable().defaultTo(0);
      t.integer("prescan_flagged").notNullable().defaultTo(0);
      t.string("registered_at", 64).notNullable();
      t.text("registered_url").nullable();
      _id(t, "tx_id").nullable();
      t.index("author_tip_id", "idx_content_author");
      t.index("origin_code",   "idx_content_origin");
      t.index("status",        "idx_content_status");
    });

    await ensure("scores", t => {
      _pk(t, "tip_id");
      t.integer("score").notNullable().defaultTo(500);
      t.integer("offense_count").notNullable().defaultTo(0);
      t.string("last_updated", 64).notNullable();
    });

    await ensure("dedup_registry", t => {
      t.string("dedup_hash", 512).primary();
      t.bigInteger("created_at").notNullable();
    });

    await ensure("revocations", t => {
      _pk(t, "tip_id");
      t.string("tx_type", 64).notNullable();
      t.string("timestamp", 64).notNullable();
      _id(t, "tx_id").notNullable();
    });

    await ensure("verification_providers", t => {
      _pk(t, "vp_id");
      t.string("name", 256).notNullable();
      t.string("jurisdiction",      8).notNullable().defaultTo("US");
      t.string("jurisdiction_tier", 16).notNullable().defaultTo("green");
      t.text("public_key").nullable();
      t.string("status", 32).notNullable().defaultTo("active");
      t.string("registered_at", 64).notNullable();
    });

    await ensure("nodes", t => {
      _pk(t, "node_id");
      t.text("name").nullable();
      t.text("public_key").notNullable();
      t.string("status", 32).notNullable().defaultTo("active");
      t.string("registered_at", 64).notNullable();
    });

    await ensure("certificates", t => {
      t.string("hash", 128).primary();
      t.integer("round").notNullable();
      _id(t, "author_node_id").notNullable();
      t.text("batch_data").notNullable();
      t.text("acknowledgments").notNullable();
      t.text("parent_hashes").notNullable();
      t.text("signature").notNullable();
      t.bigInteger("timestamp").notNullable().defaultTo(0);
      t.bigInteger("created_at").notNullable().defaultTo(0);
      t.index("round",                        "idx_cert_round");
      t.index(["author_node_id", "round"],    "idx_cert_author");
    });

    await ensure("commits", t => {
      t.integer("round").primary();
      t.string("anchor_cert_hash", 128).notNullable();
      _id(t, "leader_node_id").notNullable();
      t.text("committee").notNullable();
      t.integer("support_count").notNullable();
      t.integer("consensus_index").notNullable();
      t.string("committed_at", 64).notNullable();
      t.string("state_merkle_root", 128).notNullable();
      t.string("txs_merkle_root",   128).notNullable();
      t.text("ack_signer_ids").notNullable();
      t.text("ack_signatures").notNullable();
      t.text("ack_signed_ats").notNullable().defaultTo("[]");
      t.bigInteger("cert_timestamp").notNullable().defaultTo(0);
      t.string("anchor_batch_hash", 128).nullable();
      t.bigInteger("created_at").notNullable().defaultTo(0);
      t.unique(["consensus_index"], "idx_commits_index");
    });

    await ensure("votes_seen", t => {
      t.integer("round").notNullable();
      _id(t, "author").notNullable();
      t.string("batch_hash", 128).notNullable();
      t.bigInteger("created_at").notNullable().defaultTo(0);
      t.primary(["round", "author"]);
      t.index("round", "idx_votes_round");
    });

    await ensure("mempool", t => {
      t.string("tx_id", 128).primary();
      t.text("tx_data").notNullable();
      _id(t, "subject_tip_id").nullable();
      t.bigInteger("received_at").notNullable().defaultTo(0);
      t.index("subject_tip_id", "idx_mempool_subject");
    });

    await ensure("tx_rejections", t => {
      t.string("tx_id", 128).primary();
      t.string("reason", 64).notNullable();
      t.text("reason_detail").nullable();
      t.bigInteger("rejected_at_ms").notNullable();
      t.integer("rejected_at_round").nullable();
      _id(t, "dropper_node_id").notNullable();
      t.string("tx_type", 64).nullable();
      _id(t, "origin_node_id").nullable();
      t.text("tx_data").nullable();
      _id(t, "subject_tip_id").nullable();
      t.index("reason",         "idx_tx_rej_reason");
      t.index("rejected_at_ms", "idx_tx_rej_at");
      t.index("origin_node_id", "idx_tx_rej_origin");
      t.index("subject_tip_id", "idx_tx_rej_subject");
    });

    await ensure("consensus_meta", t => {
      t.string("key", 128).primary();
      t.text("value").notNullable();
    });
  }

  async _hydrate() {
    // Transactions
    const txRows = await this.knex("transactions").select("*");
    for (const row of txRows) {
      const tx = _parseTxRow(row);
      const subj = row.subject_tip_id || subjectTipId(tx) || null;
      this.mirror._txs.set(tx.tx_id, { ...tx, subject_tip_id: subj });
    }

    // Identities
    const idRows = await this.knex("identities").select("*");
    for (const row of idRows) {
      this.mirror._identities.set(row.tip_id, { ...row, founding: !!row.founding });
    }

    // Content
    const contentRows = await this.knex("content").select("*");
    for (const row of contentRows) {
      const mapped = { ...row, ctid: row.tip_ctid, prescan_flagged: !!row.prescan_flagged };
      delete mapped.tip_ctid;
      this.mirror._content.set(mapped.ctid, mapped);
    }

    // Scores
    const scoreRows = await this.knex("scores").select("*");
    for (const row of scoreRows) {
      this.mirror._scores.set(row.tip_id, { score: row.score, offense_count: row.offense_count, last_updated: row.last_updated });
    }

    // Dedup registry
    const dedupRows = await this.knex("dedup_registry").select("*");
    if (!this.mirror._dedupCreated) this.mirror._dedupCreated = new Map();
    for (const row of dedupRows) {
      this.mirror._dedup.add(row.dedup_hash);
      this.mirror._dedupCreated.set(row.dedup_hash, row.created_at);
    }

    // Revocations
    const revocRows = await this.knex("revocations").select("*");
    for (const row of revocRows) {
      this.mirror._revocations.set(row.tip_id, { ...row });
    }

    // Verification providers
    const vpRows = await this.knex("verification_providers").select("*");
    for (const row of vpRows) {
      this.mirror._vps.set(row.vp_id, { ...row });
    }

    // Nodes
    const nodeRows = await this.knex("nodes").select("*");
    for (const row of nodeRows) {
      this.mirror._nodes.set(row.node_id, { ...row });
    }

    // Certificates
    const certRows = await this.knex("certificates").select("*");
    for (const row of certRows) {
      const cert = _parseCertRow(row);
      this.mirror._certs.set(cert.hash, cert);
    }

    // Commits
    const commitRows = await this.knex("commits").select("*");
    for (const row of commitRows) {
      const commit = _parseCommitRow(row);
      this.mirror._commits.set(commit.round, commit);
    }

    // Votes seen
    const voteRows = await this.knex("votes_seen").select("*");
    if (!this.mirror._votes) this.mirror._votes = new Map();
    for (const row of voteRows) {
      this.mirror._votes.set(`${row.round}:${row.author}`, { round: row.round, author: row.author, batch_hash: row.batch_hash });
    }

    // Mempool
    const mempoolRows = await this.knex("mempool").select("*");
    for (const row of mempoolRows) {
      const tx = _j(row.tx_data) || {};
      this.mirror._mempool.set(row.tx_id, { tx, subject_tip_id: row.subject_tip_id });
    }

    // Tx rejections
    const rejRows = await this.knex("tx_rejections").select("*");
    for (const row of rejRows) {
      this.mirror._txRejections.set(row.tx_id, { ...row });
    }

    // Consensus meta
    const metaRows = await this.knex("consensus_meta").select("*");
    if (!this.mirror._consensusMeta) this.mirror._consensusMeta = new Map();
    for (const row of metaRows) {
      this.mirror._consensusMeta.set(row.key, row.value);
    }
  }

  // ── Fire-and-forget ────────────────────────────────────────────────────────

  _ff(fn) {
    fn().catch(err => this.log.warn(`KnexAdapter write failed: ${err.message}`));
  }

  // ── Transactions ───────────────────────────────────────────────────────────

  saveTx(tx) {
    this.mirror.saveTx(tx);
    const entry = this.mirror._txs.get(tx.tx_id);
    this._ff(() => this.knex("transactions").insert({
      tx_id:          tx.tx_id,
      tx_type:        tx.tx_type,
      data:           JSON.stringify(tx.data || {}),
      timestamp:      tx.timestamp,
      prev:           JSON.stringify(tx.prev || []),
      signature:      tx.signature || null,
      subject_tip_id: (entry && entry.subject_tip_id) || null,
    }).onConflict("tx_id").ignore());
  }

  getTx(id)              { return this.mirror.getTx(id); }
  getAllTxs()            { return this.mirror.getAllTxs(); }
  count()                { return this.mirror.count(); }
  getTxsByType(t)        { return this.mirror.getTxsByType(t); }
  getTxsByTypeAndCtid(t, c) { return this.mirror.getTxsByTypeAndCtid(t, c); }
  getTxsByTipId(id)      { return this.mirror.getTxsByTipId(id); }
  getTxsBySubject(id)    { return this.mirror.getTxsBySubject(id); }
  getRecentPrev()        { return this.mirror.getRecentPrev ? this.mirror.getRecentPrev() : []; }

  *iterateAllTransactions() { yield* this.mirror.iterateAllTransactions(); }

  // ── Identities ─────────────────────────────────────────────────────────────

  saveIdentity(rec) {
    this.mirror.saveIdentity(rec);
    this._ff(() => this.knex("identities").insert({
      tip_id:             rec.tip_id,
      region:             rec.region || "US",
      public_key:         rec.public_key,
      root_public_key:    rec.root_public_key || null,
      vp_id:              rec.vp_id || null,
      verification_tier:  rec.verification_tier || "T1",
      score_display_mode: rec.score_display_mode || "TIER_ONLY",
      founding:           rec.founding ? 1 : 0,
      status:             rec.status || "active",
      registered_at:      rec.registered_at,
      creator_name:       rec.creator_name || null,
      tx_id:              rec.tx_id || null,
    }).onConflict("tip_id").merge());
  }

  getIdentity(id)      { return this.mirror.getIdentity(id); }
  getAllIdentities()    { return this.mirror.getAllIdentities(); }

  // ── Content ────────────────────────────────────────────────────────────────

  saveContent(rec) {
    this.mirror.saveContent(rec);
    this._ff(() => this.knex("content").insert({
      tip_ctid:           rec.ctid,
      origin_code:        rec.origin_code,
      content_hash:       rec.content_hash,
      perceptual_hash:    rec.perceptual_hash || null,
      author_tip_id:      rec.author_tip_id,
      status:             rec.status || "verified",
      dispute_count:      rec.dispute_count || 0,
      verification_count: rec.verification_count || 0,
      prescan_flagged:    rec.prescan_flagged ? 1 : 0,
      registered_at:      rec.registered_at,
      registered_url:     rec.registered_url || null,
      tx_id:              rec.tx_id || null,
    }).onConflict("tip_ctid").merge());
  }

  getContent(ctid)                      { return this.mirror.getContent(ctid); }
  getContentByStatus(s)                 { return this.mirror.getContentByStatus(s); }
  getContentByAuthor(id)                { return this.mirror.getContentByAuthor(id); }
  getCleanRecordEligible(cutoff)        { return this.mirror.getCleanRecordEligible(cutoff); }
  hasVerification(ctid, tipId)          { return this.mirror.hasVerification(ctid, tipId); }
  hasDispute(ctid, tipId)               { return this.mirror.hasDispute(ctid, tipId); }

  updateContentStatus(ctid, status) {
    this.mirror.updateContentStatus(ctid, status);
    this._ff(() => this.knex("content").where("tip_ctid", ctid).update({ status }));
  }

  updateContentOrigin(ctid, originCode, status) {
    this.mirror.updateContentOrigin(ctid, originCode, status);
    this._ff(() => this.knex("content").where("tip_ctid", ctid).update({ origin_code: originCode, status }));
  }

  // ── Scores ─────────────────────────────────────────────────────────────────

  setScore(tipId, score, offenseCount, lastUpdatedISO) {
    this.mirror.setScore(tipId, score, offenseCount, lastUpdatedISO);
    this._ff(() => this.knex("scores").insert({
      tip_id:        tipId,
      score,
      offense_count: offenseCount || 0,
      last_updated:  lastUpdatedISO,
    }).onConflict("tip_id").merge());
  }

  getScore(id) { return this.mirror.getScore(id); }

  // ── Dedup registry ─────────────────────────────────────────────────────────

  addDedupHash(hash, createdAt) {
    this.mirror.addDedupHash(hash, createdAt);
    this._ff(() => this.knex("dedup_registry").insert({ dedup_hash: hash, created_at: createdAt }).onConflict("dedup_hash").ignore());
  }

  hasDedupHash(h)  { return this.mirror.hasDedupHash(h); }
  dedupCount()     { return this.mirror.dedupCount(); }

  // ── Canonical state iterator (§14 snapshot-sync) ──────────────────────────

  *iterateCanonicalState() { yield* this.mirror.iterateCanonicalState(); }

  // ── Revocations ────────────────────────────────────────────────────────────

  addRevocation(id, type, ts, txId) {
    this.mirror.addRevocation(id, type, ts, txId);
    this._ff(() => this.knex("revocations").insert({ tip_id: id, tx_type: type, timestamp: ts, tx_id: txId }).onConflict("tip_id").ignore());
  }

  isRevoked(id)            { return this.mirror.isRevoked(id); }
  getRevocations(since)    { return this.mirror.getRevocations(since); }

  // ── Verification Providers ─────────────────────────────────────────────────

  saveVP(rec) {
    this.mirror.saveVP(rec);
    this._ff(() => this.knex("verification_providers").insert({
      vp_id:             rec.vp_id,
      name:              rec.name,
      jurisdiction:      rec.jurisdiction || "US",
      jurisdiction_tier: rec.jurisdiction_tier || "green",
      public_key:        rec.public_key || null,
      status:            rec.status || "active",
      registered_at:     rec.registered_at,
    }).onConflict("vp_id").merge());
  }

  getVP(id)     { return this.mirror.getVP(id); }
  getAllVPs()    { return this.mirror.getAllVPs(); }

  // ── Nodes ──────────────────────────────────────────────────────────────────

  saveNode(rec) {
    this.mirror.saveNode(rec);
    this._ff(() => this.knex("nodes").insert({
      node_id:       rec.node_id,
      name:          rec.name || null,
      public_key:    rec.public_key,
      status:        rec.status || "active",
      registered_at: rec.registered_at,
    }).onConflict("node_id").merge());
  }

  getNode(id)    { return this.mirror.getNode(id); }
  getAllNodes()   { return this.mirror.getAllNodes(); }

  // ── Certificates ──────────────────────────────────────────────────────────

  saveCertificate(cert) {
    this.mirror.saveCertificate(cert);
    this._ff(() => this.knex("certificates").insert({
      hash:            cert.hash,
      round:           cert.round,
      author_node_id:  cert.author_node_id,
      batch_data:      JSON.stringify(cert.batch),
      acknowledgments: JSON.stringify(cert.acknowledgments),
      parent_hashes:   JSON.stringify(cert.parent_hashes || []),
      signature:       cert.signature,
      timestamp:       Number(cert.timestamp || 0),
    }).onConflict("hash").ignore());
  }

  getCertificate(hash)                    { return this.mirror.getCertificate(hash); }
  getCertificatesByRound(round)           { return this.mirror.getCertificatesByRound(round); }
  getCertificateByAuthorRound(a, r)       { return this.mirror.getCertificateByAuthorRound(a, r); }
  getLatestRound()                        { return this.mirror.getLatestRound(); }
  getEarliestCertRound()                  { return this.mirror.getEarliestCertRound(); }
  getCertificatesFromRound(from)          { return this.mirror.getCertificatesFromRound(from); }
  certificateCount()                      { return this.mirror.certificateCount(); }

  pruneCertificatesBefore(cutoffRound) {
    const n = this.mirror.pruneCertificatesBefore(cutoffRound);
    this._ff(() => this.knex("certificates").where("round", "<", cutoffRound).delete());
    return n;
  }

  incrementalVacuum(_maxPages) { /* no-op for server DBs */ }

  // ── Commit checkpoints ─────────────────────────────────────────────────────

  saveCommit(rec) {
    this.mirror.saveCommit(rec);
    this._ff(() => this.knex("commits").insert({
      round:             rec.round,
      anchor_cert_hash:  rec.anchor_cert_hash,
      leader_node_id:    rec.leader_node_id,
      committee:         JSON.stringify(rec.committee || []),
      support_count:     rec.support_count,
      consensus_index:   rec.consensus_index,
      committed_at:      rec.committed_at,
      state_merkle_root: rec.state_merkle_root,
      txs_merkle_root:   rec.txs_merkle_root,
      ack_signer_ids:    JSON.stringify(rec.ack_signer_ids || []),
      ack_signatures:    JSON.stringify(rec.ack_signatures || []),
      ack_signed_ats:    JSON.stringify(rec.ack_signed_ats || []),
      cert_timestamp:    Number(rec.cert_timestamp || 0),
      anchor_batch_hash: rec.anchor_batch_hash || null,
    }).onConflict("round").ignore());
  }

  getCommit(round)             { return this.mirror.getCommit(round); }
  getLatestCommit()            { return this.mirror.getLatestCommit(); }
  getCommitsFromRound(from)    { return this.mirror.getCommitsFromRound(from); }
  getLatestConsensusIndex()    { return this.mirror.getLatestConsensusIndex(); }

  setConsensusMeta(key, value) {
    this.mirror.setConsensusMeta(key, value);
    this._ff(() => this.knex("consensus_meta").insert({ key, value: String(value) }).onConflict("key").merge());
  }

  getConsensusMeta(key)        { return this.mirror.getConsensusMeta(key); }

  *iterateAllCommitsExcept(latestRound) { yield* this.mirror.iterateAllCommitsExcept(latestRound); }

  // ── Equivocation defense ──────────────────────────────────────────────────

  recordSeenVote(round, author, batchHash) {
    const isNew = this.mirror.recordSeenVote(round, author, batchHash);
    if (isNew) {
      this._ff(() => this.knex("votes_seen").insert({ round, author, batch_hash: batchHash }).onConflict(["round", "author"]).ignore());
    }
    return isNew;
  }

  getSeenVote(round, author) { return this.mirror.getSeenVote(round, author); }

  pruneVotesSeenBefore(cutoffRound) {
    const n = this.mirror.pruneVotesSeenBefore(cutoffRound);
    this._ff(() => this.knex("votes_seen").where("round", "<", cutoffRound).delete());
    return n;
  }

  // ── Persistent Mempool ─────────────────────────────────────────────────────

  saveMempoolTx(tx) {
    this.mirror.saveMempoolTx(tx);
    this._ff(() => this.knex("mempool").insert({
      tx_id:          tx.tx_id,
      tx_data:        JSON.stringify(tx),
      subject_tip_id: subjectTipId(tx) || null,
    }).onConflict("tx_id").ignore());
  }

  getMempoolTx(txId)            { return this.mirror.getMempoolTx(txId); }
  getMempoolTxs()               { return this.mirror.getMempoolTxs(); }
  getMempoolTxsByTipId(tipId)   { return this.mirror.getMempoolTxsByTipId(tipId); }

  deleteMempoolTx(txId) {
    this.mirror.deleteMempoolTx(txId);
    this._ff(() => this.knex("mempool").where("tx_id", txId).delete());
  }

  deleteMempoolTxs(txIds) {
    this.mirror.deleteMempoolTxs(txIds);
    if (txIds.length > 0) {
      this._ff(() => this.knex("mempool").whereIn("tx_id", txIds).delete());
    }
  }

  clearStaleMempoolTxs(beforeUnixSec) {
    // MemoryStore is a no-op; for DB we clean expired rows
    this._ff(() => this.knex("mempool").where("received_at", "<", beforeUnixSec).delete());
  }

  mempoolCount() { return this.mirror.mempoolCount(); }

  // ── Tx Rejections ─────────────────────────────────────────────────────────

  saveTxRejection(rec) {
    const inserted = this.mirror.saveTxRejection(rec);
    if (inserted) {
      const at = rec.rejected_at_ms != null ? rec.rejected_at_ms : Date.now();
      const txData = rec.tx_data == null ? null
        : (typeof rec.tx_data === "string" ? rec.tx_data : JSON.stringify(rec.tx_data));
      const subj = rec.tx_data && typeof rec.tx_data === "object" ? subjectTipId(rec.tx_data) : null;
      this._ff(() => this.knex("tx_rejections").insert({
        tx_id:             rec.tx_id,
        reason:            rec.reason,
        reason_detail:     rec.reason_detail || null,
        rejected_at_ms:    at,
        rejected_at_round: rec.rejected_at_round || null,
        dropper_node_id:   rec.dropper_node_id,
        tx_type:           rec.tx_type || null,
        origin_node_id:    rec.origin_node_id || null,
        tx_data:           txData,
        subject_tip_id:    subj,
      }).onConflict("tx_id").ignore());
    }
    return inserted;
  }

  getTxRejection(txId)                  { return this.mirror.getTxRejection(txId); }
  getTxRejectionsByReason(reason, opts) { return this.mirror.getTxRejectionsByReason(reason, opts); }
  getTxRejectionsByTipId(tipId)         { return this.mirror.getTxRejectionsByTipId(tipId); }
  countTxRejections()                   { return this.mirror.countTxRejections(); }

  // ── DB Transactions ────────────────────────────────────────────────────────
  // Mirror is already atomic (Map operations). DB writes from inside fn() are
  // individually fire-and-forgetted. Eventual consistency to DB is acceptable.

  runInTransaction(fn) { return fn(); }

  // ── Backfill ──────────────────────────────────────────────────────────────
  // Mirror is hydrated with correct subject_tip_ids during migrate().
  // Schedule async DB backfill for any null rows (non-critical).

  backfillSubjectTipId(_subjectTipIdFn) {
    this._backfillSubjectTipIdAsync().catch(err =>
      this.log.warn(`subject_tip_id DB backfill failed: ${err.message}`)
    );
    return { transactions: 0, mempool: 0, tx_rejections: 0 };
  }

  async _backfillSubjectTipIdAsync() {
    const nullTxs = await this.knex("transactions").select("tx_id", "tx_type", "data").whereNull("subject_tip_id");
    for (const row of nullTxs) {
      const subj = subjectTipId({ tx_type: row.tx_type, data: _j(row.data) || {} });
      if (subj) await this.knex("transactions").where("tx_id", row.tx_id).update({ subject_tip_id: subj });
    }
    const nullMp = await this.knex("mempool").select("tx_id", "tx_data").whereNull("subject_tip_id");
    for (const row of nullMp) {
      const tx = _j(row.tx_data) || {};
      const subj = subjectTipId(tx);
      if (subj) await this.knex("mempool").where("tx_id", row.tx_id).update({ subject_tip_id: subj });
    }
    const nullRej = await this.knex("tx_rejections").select("tx_id", "tx_data").whereNull("subject_tip_id");
    for (const row of nullRej) {
      const tx = _j(row.tx_data) || {};
      const subj = subjectTipId(tx);
      if (subj) await this.knex("tx_rejections").where("tx_id", row.tx_id).update({ subject_tip_id: subj });
    }
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  close() {
    try { this.knex.destroy(); } catch { /* ignore */ }
  }
}

module.exports = { KnexAdapter };
