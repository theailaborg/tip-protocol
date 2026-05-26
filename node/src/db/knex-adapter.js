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
const { nowMs } = require("../../../shared/time");

// ─── BIGINT → JS Number coercion (driver-agnostic, every Knex backend) ───────
// Every SQL driver TIP supports returns BIGINT differently in JS land:
//
//   pg:        INT8 → string  (precision-loss avoidance; JS Number can't
//                              hold 2^63 safely, so the driver punts)
//   mysql2:    BIGINT → string when supportBigNumbers is unset (same reason)
//   tedious:   BIGINT → string by default
//   oracledb:  NUMBER(19,0) → string (unless precision fits in JS safe int)
//   better-sqlite3 (used by the SQLite dag.js path, NOT Knex): INTEGER
//              → JS Number natively — no fix needed there.
//
// Every TIP bigint column carries either an epoch-ms timestamp (max ≈ 1.78e12
// — three orders of magnitude under MAX_SAFE_INTEGER) or a counter (round,
// rotation_number, consensus_index — all well below 2^32). None can ever
// approach the precision boundary, so coercing all BIGINT reads to Number is
// safe AND fixes a class of bugs where:
//   - the in-memory mirror hydrates with "1779253012162" (string) instead of
//     the integer, so `Number.isFinite(row.registered_at)` returns false in
//     the prescan-review trigger and the content is silently skipped;
//   - downstream arithmetic like `registered_at + decision_window_ms`
//     becomes a JS string concatenation ("1779253012162" + 172800000 =
//     "1779253012162172800000") instead of integer addition;
//   - the boundary timestamp middleware skips conversion (its `typeof v ===
//     "number"` value-gate rejects the string), leaking raw bigint strings
//     to API clients.
//
// Two layers of defence:
//
//   1. Driver-level type parsers / casts where the driver supports them
//      (pg setTypeParser + mysql2 connection typeCast). Zero per-row cost
//      once registered — values arrive in JS land already as Number.
//
//   2. Knex postProcessResponse fallback (_coerceBigIntRow below) catches
//      anything the driver layer missed — by-column-name allow-list so
//      it never touches VARCHAR fields that happen to contain digit-only
//      content. Universal: runs for every Knex query result regardless
//      of which driver is underneath.
//
// All TIP bigInteger columns either match the timestamp pattern (`*_at`,
// `*_at_ms`, `timestamp`, `cert_timestamp`, `last_updated`) or are explicit
// counters added to BIGINT_COLUMN_NAMES below.

// Pg-level parser — registered at module load so every pg connection
// (including the one Knex builds further down) inherits it. Idempotent:
// setTypeParser overwrites silently if called twice.
try {
  // OID 20 = int8 (bigint). Numeric literal avoids depending on the
  // pgTypes.builtins map shape.
  require("pg").types.setTypeParser(20, v => v === null ? null : Number(v));
} catch { /* pg not installed in this build — skip */ }

// Column-name allow-list for the Knex postProcessResponse fallback.
// `BIGINT_COLUMN_PATTERN` matches the codebase's timestamp naming
// conventions; `BIGINT_COLUMN_NAMES` lists extra explicit columns that
// don't follow the pattern. Together they identify exactly the columns
// declared as `t.bigInteger(...)` in the Knex schema.
const BIGINT_COLUMN_PATTERN = /^(timestamp|cert_timestamp|last_updated|.+_at|.+_at_ms)$/;
const BIGINT_COLUMN_NAMES = new Set([
  // Reserved for explicit additions that don't match the pattern (none
  // today — all current bigInteger columns are timestamps).
]);

function _isBigintColumn(key) {
  return BIGINT_COLUMN_PATTERN.test(key) || BIGINT_COLUMN_NAMES.has(key);
}

function _coerceBigIntRow(row) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return row;
  for (const key of Object.keys(row)) {
    const v = row[key];
    if (typeof v === "string" && _isBigintColumn(key) && /^-?\d+$/.test(v)) {
      const n = Number(v);
      if (Number.isSafeInteger(n)) row[key] = n;
    } else if (typeof v === "bigint") {
      // Some drivers (mysql2 with supportBigNumbers, oracledb with
      // certain configs) return BIGINT as a JS bigint. Same safe-integer
      // guarantee — coerce to Number.
      const n = Number(v);
      if (Number.isSafeInteger(n)) row[key] = n;
    }
  }
  return row;
}

function _knexPostProcessResponse(result) {
  if (!result) return result;
  if (Array.isArray(result)) {
    for (const row of result) _coerceBigIntRow(row);
    return result;
  }
  return _coerceBigIntRow(result);
}

// mysql2 connection-level type cast: applied per-cell on the result path,
// coerces BIGINT (MYSQL_TYPE_LONGLONG = 8) to JS Number before it reaches
// the Knex layer. Mirrors the pg type parser above.
function _mysql2TypeCast(field, next) {
  if (field.type === "LONGLONG" || field.type === "BIGINT") {
    const s = field.string();
    if (s === null) return null;
    const n = Number(s);
    return Number.isSafeInteger(n) ? n : s;
  }
  return next();
}

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

function _id(t, col) { return t.string(col, 512); }
function _pk(t, col) { return t.string(col, 512).primary(); }

// Detect duplicate-key errors across the supported drivers. We need this
// because Postgres's ON CONFLICT(col) only catches conflicts on the named
// column — a violation of any OTHER unique index on the same table still
// throws. Tables like `commits` carry multiple unique constraints (PK on
// round + unique on consensus_index), so we fall back to recognising the
// generic duplicate-key signal and swallowing it for "ignore" inserts.
//
//   Postgres   error.code === "23505"
//   MariaDB    error.code === "ER_DUP_ENTRY" (1062)  — Knex passes through
//   SQLite     error.code === "SQLITE_CONSTRAINT_UNIQUE" or PRIMARYKEY
//   Oracle     ORA-00001 in message
//   SQL Server error.number 2627/2601 OR "Cannot insert duplicate key"
function _isDuplicateKeyError(err) {
  if (!err) return false;
  const code = err.code || "";
  if (code === "23505") return true;                          // postgres
  if (code === "ER_DUP_ENTRY" || err.errno === 1062) return true;  // mariadb/mysql
  if (typeof code === "string" && code.startsWith("SQLITE_CONSTRAINT")) return true;
  if (err.number === 2627 || err.number === 2601) return true;     // mssql
  const msg = err.message || "";
  return /ORA-00001/.test(msg)
    || /Cannot insert duplicate key/.test(msg)
    || /duplicate key value violates unique constraint/.test(msg);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _j(v) {
  try { return JSON.parse(v || "null"); } catch { return null; }
}

function _parseTxRow(row) {
  // PG returns `bigint` columns as STRING (node-pg default — JS Number
  // can't safely hold the full bigint range). Coerce to Number here so
  // the mirror has consistent numeric timestamps regardless of whether
  // a tx arrived via live saveTx (numeric) or hydrate (string). Without
  // this, the activity-feed sort hits NaN on mixed comparisons and
  // string-timestamped txs drift out of order.
  return {
    tx_id: row.tx_id,
    tx_type: row.tx_type,
    data: _j(row.data) || {},
    timestamp: row.timestamp != null ? Number(row.timestamp) : row.timestamp,
    prev: _j(row.prev) || [],
    signature: row.signature || null,
    subject_tip_id: row.subject_tip_id || null,
  };
}

function _parseCertRow(row) {
  return {
    hash: row.hash,
    round: row.round,
    author_node_id: row.author_node_id,
    batch: _j(row.batch_data) || {},
    acknowledgments: _j(row.acknowledgments) || [],
    parent_hashes: _j(row.parent_hashes) || [],
    signature: row.signature,
    timestamp: Number(row.timestamp || 0),
  };
}

function _parseCommitRow(row) {
  return {
    round: row.round,
    anchor_cert_hash: row.anchor_cert_hash,
    leader_node_id: row.leader_node_id,
    committee: _j(row.committee) || [],
    support_count: row.support_count,
    consensus_index: row.consensus_index,
    committed_at: row.committed_at,
    state_merkle_root: row.state_merkle_root,
    txs_merkle_root: row.txs_merkle_root,
    ack_signer_ids: _j(row.ack_signer_ids) || [],
    ack_signatures: _j(row.ack_signatures) || [],
    ack_signed_ats: _j(row.ack_signed_ats) || [],
    cert_timestamp: Number(row.cert_timestamp || 0),
    anchor_batch_hash: row.anchor_batch_hash || null,
  };
}

// ─── KnexAdapter ─────────────────────────────────────────────────────────────

class KnexAdapter {
  constructor(driver, config, log) {
    this.log = log || { info: () => { }, warn: () => { }, error: () => { } };
    this.mirror = new MemoryStore();

    // Map driver aliases to Knex client names
    const clientMap = { postgres: "pg", mariadb: "mysql2", mysql: "mysql2", mssql: "mssql", sqlserver: "mssql", oracle: "oracledb" };
    const client = clientMap[driver] || driver;

    let connection;
    if (config.dbUrl) {
      connection = config.dbUrl;
    } else if (driver === "oracle" || driver === "oracledb") {
      const host = config.dbHost || process.env.DB_HOST || "localhost";
      const port = config.dbPort || Number(process.env.DB_PORT || 1521);
      const svc = config.dbName || process.env.DB_NAME || "FREEPDB1";
      connection = {
        connectString: `${host}:${port}/${svc}`,
        user: config.dbUser || process.env.DB_USER || "tip",
        password: config.dbPassword || process.env.DB_PASSWORD || "",
      };
    } else {
      connection = {
        host: config.dbHost || process.env.DB_HOST || "localhost",
        port: config.dbPort || Number(process.env.DB_PORT || (driver === "postgres" ? 5432 : driver === "mssql" || driver === "sqlserver" ? 1433 : 3306)),
        database: config.dbName || process.env.DB_NAME || "tip_protocol",
        user: config.dbUser || process.env.DB_USER || "tip",
        password: config.dbPassword || process.env.DB_PASSWORD || "",
      };
      if (config.dbSsl || process.env.DB_SSL === "true") {
        connection.ssl = {
          rejectUnauthorized: config.dbSslRejectUnauthorized !== false && process.env.DB_SSL_REJECT_UNAUTHORIZED !== "false",
        };
      }
      // Driver-level BIGINT coercion for mysql2/mariadb (see _mysql2TypeCast
      // banner). The pg type parser is registered at module load; mssql
      // and oracledb fall through to the universal postProcessResponse
      // fallback wired below.
      if (client === "mysql2") {
        connection.typeCast = _mysql2TypeCast;
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
      // Universal BIGINT → Number fallback. Runs after the driver-level
      // parser / typeCast (no-op when the driver already returned Number),
      // catches mssql / oracledb / any future driver that doesn't have a
      // native hook configured. By-column-name allow-list so VARCHAR
      // fields holding digit-only content (e.g. a stringly-typed numeric
      // id) are never touched.
      postProcessResponse: _knexPostProcessResponse,
    });
    this._isOracleDB = (driver === "oracle" || driver === "oracledb");
    // SQL Server also doesn't support Knex's .onConflict() — use INSERT + catch duplicate-key
    this._noOnConflict = this._isOracleDB || driver === "mssql" || driver === "sqlserver";
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
      t.bigInteger("timestamp").notNullable();
      t.text("prev").notNullable().defaultTo("[]");
      t.text("signature").nullable();
      _id(t, "subject_tip_id").nullable();
      // local_inserted_at = this node's `nowMs()` when the row was written.
      // Per-node by design. NOT in canonicalTx / tx_id / state_merkle_root.
      // For chain-time use `transactions.timestamp` (the author-signed value
      // bound into tx_id). See `local_inserted_at` semantic in the file
      // header.
      t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
      t.index("tx_type", "idx_txs_type");
      t.index("timestamp", "idx_txs_ts");
      t.index("local_inserted_at", "idx_txs_local_inserted_at");
      t.index("subject_tip_id", "idx_txs_subject");
    });

    // GH #60: public_key + algorithm live in entity_keys (DID-style
    // single source of truth). root_public_key dropped (orphaned scaffold).
    await ensure("identities", t => {
      _pk(t, "tip_id");
      t.string("region", 8).notNullable().defaultTo("US");
      _id(t, "vp_id").nullable();
      t.string("verification_tier", 8).notNullable().defaultTo("T1");
      t.string("score_display_mode", 32).notNullable().defaultTo("TIER_ONLY");
      t.string("tip_id_type", 32).notNullable().defaultTo("personal");  // personal | organization
      t.integer("founding").notNullable().defaultTo(0);
      t.string("status", 32).notNullable().defaultTo("active");
      // Opt-in to be selected as an adjudicator across all protocol roles
      // (Protocol Review reviewer, Stage 2 jury, Stage 3 expert panel).
      // Runtime filters at selection time decide which role a consenting
      // user lands in (score, content category, conflict-of-interest).
      t.integer("reviewer_consent").notNullable().defaultTo(0);
      // Denormalised user-picked interest slugs (canonical sort, deduped).
      // Source of truth is the chain of UPDATE_PROFILE txs; this column
      // is the read-side projection for activity feed / discovery /
      // recommendation. JSON-encoded array of strings.
      t.text("interests").notNullable().defaultTo("[]");
      t.bigInteger("registered_at").notNullable();
      t.text("creator_name").nullable();
      _id(t, "tx_id").nullable();
      t.index("vp_id", "idx_id_vp");
      t.index("status", "idx_id_status");
      t.index("tip_id_type", "idx_id_type");
    });

    // GH #60 — entity_keys: single source of truth for (public_key,
    // algorithm) of every identity, node, and VP across all time. Same
    // pattern as W3C DID verificationMethod[] / X.509 cert chains /
    // WebAuthn credentials / JWKS keysets. Append-only with
    // valid_from_ts / valid_to_ts ranges; KEY_ROTATED / KEY_RECOVERY
    // close the active row and append a new one. Historical-signature
    // verification reads the row whose validity range covers
    // tx.timestamp; API-time verification reads the active row
    // (valid_to_ts IS NULL).
    await ensure("entity_keys", t => {
      t.string("entity_type", 32).notNullable();           // 'identity' | 'node' | 'vp'
      t.text("entity_id").notNullable();
      t.text("public_key").notNullable();
      t.string("algorithm", 64).notNullable().defaultTo("ml-dsa-65");
      t.bigInteger("valid_from_ts").notNullable();
      t.bigInteger("valid_to_ts").nullable();              // NULL = still active
      _id(t, "source_tx_id").notNullable();                // REGISTER_IDENTITY | KEY_ROTATED | KEY_RECOVERY | genesis:<id>
      t.primary(["entity_type", "entity_id", "valid_from_ts"], "pk_entity_keys");
      t.index(["entity_type", "entity_id", "valid_to_ts"], "idx_entity_keys_active");
      t.index(["entity_type", "entity_id", "valid_from_ts"], "idx_entity_keys_time");
    });

    await ensure("content", t => {
      // tip_ctid = application-level CTID; "ctid" is reserved in PostgreSQL
      t.string("tip_ctid", 512).primary();
      t.string("origin_code", 8).notNullable();
      t.string("content_hash", 128).notNullable();
      t.string("perceptual_hash", 128).nullable();
      _id(t, "author_tip_id").notNullable();                       // = authors[0].tip_id (primary byline)
      _id(t, "signer_tip_id").notNullable();                       // the entity that produced the signature; differs from author in employed/hosted
      t.text("authors").nullable();                                 // JSON-encoded authors[] (5-key entries per CNA-2.2)
      t.string("attribution_mode", 32).notNullable().defaultTo("self");   // self / employed / hosted
      t.text("extras").nullable();                                  // JSON-encoded extension data
      t.string("cna_version", 32).notNullable();                    // CNA version this content was signed under
      t.string("status", 32).notNullable().defaultTo("verified");
      t.integer("dispute_count").notNullable().defaultTo(0);
      t.integer("verification_count").notNullable().defaultTo(0);
      t.integer("prescan_flagged").notNullable().defaultTo(0);
      t.float("prescan_probability").notNullable().defaultTo(0);          // raw classifier output
      t.string("prescan_tier", 16).notNullable().defaultTo("low");        // low|elevated|high|critical
      t.integer("override").notNullable().defaultTo(0);                   // creator confirmed OH despite HIGH/CRITICAL warning
      t.bigInteger("registered_at").notNullable();
      t.text("registered_urls").nullable();                         // JSON-encoded string[]; index 0 is the canonical / primary URL
      _id(t, "tx_id").nullable();
      t.index("author_tip_id", "idx_content_author");
      t.index("signer_tip_id", "idx_content_signer");
      t.index("origin_code", "idx_content_origin");
      t.index("status", "idx_content_status");
    });

    await ensure("scores", t => {
      _pk(t, "tip_id");
      t.integer("score").notNullable().defaultTo(500);
      t.integer("offense_count").notNullable().defaultTo(0);
      t.bigInteger("last_updated").notNullable();
    });

    await ensure("dedup_registry", t => {
      t.string("dedup_hash", 512).primary();
      t.bigInteger("created_at").notNullable();
      // Denormalized for fast hash→tip_id lookup (recovery pivot from
      // duplicate-registration; /v1/identity/by-dedup-hash endpoint).
      t.string("tip_id", 128);
    });

    await ensure("revocations", t => {
      _pk(t, "tip_id");
      t.string("tx_type", 64).notNullable();
      t.bigInteger("timestamp").notNullable();
      _id(t, "tx_id").notNullable();
    });

    // Domain bindings (org-only, canonical, in state_merkle_root).
    // expires_at + consecutive_failures are v2 renewal prep slots — set at
    // BIND commit to (verified_at + DOMAIN_HEALTHY_EXPIRY_MS, 0) and
    // untouched until the adaptive-expiry RENEW_DOMAIN scheduler ships.
    await ensure("domain_bindings", t => {
      t.string("domain", 253).primary();
      _id(t, "tip_id").notNullable();
      t.string("binding_state", 32).notNullable();
      t.string("method", 16).notNullable();
      t.bigInteger("claimed_at").notNullable();
      t.bigInteger("verified_at").notNullable();
      t.bigInteger("expires_at").notNullable();
      t.integer("consecutive_failures").notNullable().defaultTo(0);
      _id(t, "node_id").notNullable();
      t.text("claim_signature").notNullable();
      t.text("binding_signature").notNullable();
      _id(t, "tx_id").notNullable();
      t.index("tip_id", "idx_dom_bind_tip_id");
      t.index("binding_state", "idx_dom_bind_state");
      t.index("expires_at", "idx_dom_bind_expires");
    });

    // Pending domain claims (NOT canonical; per-node storage between
    // POST /register and POST /verify).
    await ensure("pending_domain_claims", t => {
      t.string("domain", 253).primary();
      _id(t, "tip_id").notNullable();
      t.string("method", 16).notNullable();
      t.bigInteger("claimed_at").notNullable();
      t.text("signature").notNullable();
      t.bigInteger("received_at").notNullable();
      t.index("tip_id", "idx_pending_dom_tip_id");
    });

    // GH #60: public_key + algorithm live in entity_keys.
    await ensure("verification_providers", t => {
      _pk(t, "vp_id");
      t.string("name", 256).notNullable();
      t.string("jurisdiction", 8).notNullable().defaultTo("US");
      t.string("jurisdiction_tier", 16).notNullable().defaultTo("green");
      t.string("status", 32).notNullable().defaultTo("active");
      t.bigInteger("registered_at").notNullable();
    });

    // GH #60: public_key + algorithm live in entity_keys.
    await ensure("nodes", t => {
      _pk(t, "node_id");
      t.text("name").nullable();
      t.string("status", 32).notNullable().defaultTo("active");
      t.bigInteger("registered_at").notNullable();
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
      // local_inserted_at = node-local write time. Chain-time for a cert
      // is `certificates.timestamp` (BFT-Time = median of acks.signed_at).
      t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
      t.index("round", "idx_cert_round");
      t.index(["author_node_id", "round"], "idx_cert_author");
    });

    await ensure("commits", t => {
      t.integer("round").primary();
      t.string("anchor_cert_hash", 128).notNullable();
      _id(t, "leader_node_id").notNullable();
      t.text("committee").notNullable();
      t.integer("support_count").notNullable();
      t.integer("consensus_index").notNullable();
      t.bigInteger("committed_at").notNullable();
      t.string("state_merkle_root", 128).notNullable();
      t.string("txs_merkle_root", 128).notNullable();
      t.text("ack_signer_ids").notNullable();
      t.text("ack_signatures").notNullable();
      t.text("ack_signed_ats").notNullable().defaultTo("[]");
      t.bigInteger("cert_timestamp").notNullable().defaultTo(0);
      t.string("anchor_batch_hash", 128).nullable();
      // local_inserted_at = node-local write time. Chain-time for a
      // commit is `commits.committed_at` (= anchor cert's BFT-Time).
      t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
      t.unique(["consensus_index"], "idx_commits_index");
    });

    await ensure("votes_seen", t => {
      t.integer("round").notNullable();
      _id(t, "author").notNullable();
      t.string("batch_hash", 128).notNullable();
      // local_inserted_at = when this node first observed the vote.
      // Pure operational dedup table; not in any canonical projection.
      t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
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
      t.index("reason", "idx_tx_rej_reason");
      t.index("rejected_at_ms", "idx_tx_rej_at");
      t.index("origin_node_id", "idx_tx_rej_origin");
      t.index("subject_tip_id", "idx_tx_rej_subject");
    });

    await ensure("consensus_meta", t => {
      t.string("key", 128).primary();
      t.text("value").notNullable();
    });

    await ensure("committee_history", t => {
      t.integer("rotation_number").primary();
      t.integer("effective_round").notNullable();
      t.text("committee").notNullable();
      t.integer("prev_rotation").nullable();
      t.text("signer_node_ids").notNullable().defaultTo("[]");
      t.text("signatures").notNullable().defaultTo("[]");
      t.text("payload_hash").nullable();
      t.bigInteger("committed_at").notNullable();
      // local_inserted_at = node-local write time. Chain-time for the
      // rotation is `committee_history.committed_at` (= committing cert's
      // BFT-Time).
      t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
      t.index("effective_round", "idx_committee_history_round");
    });

    // Curated taxonomy of slugs users pick from on their profile.
    // Seeded at first boot from INITIAL_INTERESTS_SEED; extended at
    // runtime by INTEREST_REGISTERED txs (VP-attested). Slug PK enforces
    // uniqueness at the DB layer.
    await ensure("interests_registry", t => {
      t.string("slug", 40).primary();
      t.string("label", 80).notNullable();
      t.string("category", 32).notNullable();
      t.bigInteger("registered_at").notNullable();
      t.string("registered_by_vp_id", 128).nullable();
      t.string("tx_id", 128).nullable();
      t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
      t.index("category", "idx_interests_registry_category");
    });

    // Prescan reviews (Phase 2 — human reviewing AI prescan flag).
    // See dag.js CREATE TABLE prescan_reviews for full schema rationale.
    await ensure("prescan_reviews", t => {
      t.string("review_id", 128).primary();
      // tip_ctid (not "ctid") — PostgreSQL reserves "ctid" as a system
      // column on every table, so naming a user column "ctid" causes
      // CREATE TABLE to fail. Same workaround as the `content` table:
      // store as tip_ctid in the DB, map back to ctid on hydrate / save.
      _id(t, "tip_ctid").notNullable();
      _id(t, "creator_tip_id").notNullable();
      _id(t, "assigned_reviewer").nullable();
      t.integer("triggered_at_round").notNullable();
      t.bigInteger("triggered_at_ms").nullable();
      t.integer("decided_at_round").nullable();
      t.integer("confirmed_at_round").nullable();
      t.bigInteger("confirmed_at_ms").nullable();
      t.string("state", 32).notNullable().defaultTo("triggered");
      t.text("decision_note").nullable();
      t.string("suggested_origin", 8).nullable();
      t.index("tip_ctid", "idx_prescan_reviews_ctid");
      t.index("state", "idx_prescan_reviews_state");
      t.index("assigned_reviewer", "idx_prescan_reviews_reviewer");
    });

    await ensure("rotation_participation", t => {
      _id(t, "node_id").notNullable();
      t.integer("rotation_number").notNullable();
      t.integer("count").notNullable().defaultTo(0);
      t.primary(["node_id", "rotation_number"]);
    });

    // Off-chain dispute body store. Per-node, NOT consensus state — see
    // MemoryStore.saveDisputeDetails for the rationale. Excluded from
    // iterateCanonicalState / state_merkle_root.
    await ensure("dispute_details", t => {
      t.string("evidence_hash", 128).primary();
      _id(t, "disputer_tip_id").notNullable();
      t.text("payload_json").notNullable();
      t.text("signature").notNullable();
      // local_inserted_at = when this node received the evidence body.
      // Off-chain store by design; no chain-time exists for this row.
      t.bigInteger("local_inserted_at").notNullable();
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
      let interests = [];
      if (typeof row.interests === "string" && row.interests.length > 0) {
        try { interests = JSON.parse(row.interests); } catch { interests = []; }
      }
      this.mirror._identities.set(row.tip_id, {
        ...row,
        founding: !!row.founding,
        reviewer_consent: !!row.reviewer_consent,
        interests,
      });
    }

    // Content — JSON-encoded columns (authors, extras, registered_urls) must be
    // decoded on read; the mirror expects arrays/objects, not JSON strings.
    const _decodeJson = (s, fallback) => {
      if (typeof s !== "string" || !s.length) return fallback;
      try { return JSON.parse(s); } catch { return fallback; }
    };
    const contentRows = await this.knex("content").select("*");
    for (const row of contentRows) {
      const urls = _decodeJson(row.registered_urls, []);
      const authors = _decodeJson(row.authors, []);
      const extras = _decodeJson(row.extras, {});
      const mapped = {
        ...row,
        ctid: row.tip_ctid,
        prescan_flagged: !!row.prescan_flagged,
        override: !!row.override,
        registered_urls: Array.isArray(urls) ? urls : [],
        authors: Array.isArray(authors) ? authors : [],
        extras: (extras && typeof extras === "object" && !Array.isArray(extras)) ? extras : {},
      };
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
    if (!this.mirror._dedupTipId) this.mirror._dedupTipId = new Map();
    for (const row of dedupRows) {
      this.mirror._dedup.add(row.dedup_hash);
      this.mirror._dedupCreated.set(row.dedup_hash, row.created_at);
      if (row.tip_id) this.mirror._dedupTipId.set(row.dedup_hash, row.tip_id);
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

    // GH #60 — entity_keys (single source of truth for keys across all time)
    const keyRows = await this.knex("entity_keys").select("*");
    for (const row of keyRows) {
      this.mirror._entityKeys.set(
        `${row.entity_type}:${row.entity_id}:${row.valid_from_ts}`,
        {
          entity_type: row.entity_type,
          entity_id: row.entity_id,
          public_key: row.public_key,
          algorithm: row.algorithm || "ml-dsa-65",
          valid_from_ts: Number(row.valid_from_ts),
          valid_to_ts: row.valid_to_ts == null ? null : Number(row.valid_to_ts),
          source_tx_id: row.source_tx_id,
        },
      );
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

    // Dispute details (off-chain dispute body)
    const detailRows = await this.knex("dispute_details").select("*");
    for (const row of detailRows) {
      this.mirror._disputeDetails.set(row.evidence_hash, { ...row });
    }

    // Domain bindings (canonical)
    const bindingRows = await this.knex("domain_bindings").select("*");
    for (const row of bindingRows) {
      this.mirror._domainBindings.set(row.domain, { ...row });
    }

    // Pending domain claims (per-node local)
    const pendingRows = await this.knex("pending_domain_claims").select("*");
    for (const row of pendingRows) {
      this.mirror._domainPending.set(row.domain, { ...row });
    }

    // Consensus meta
    const metaRows = await this.knex("consensus_meta").select("*");
    if (!this.mirror._consensusMeta) this.mirror._consensusMeta = new Map();
    for (const row of metaRows) {
      this.mirror._consensusMeta.set(row.key, row.value);
    }

    // Committee history
    const rotRows = await this.knex("committee_history").select("*");
    if (!this.mirror._committeeHistory) this.mirror._committeeHistory = new Map();
    for (const row of rotRows) {
      this.mirror._committeeHistory.set(row.rotation_number, {
        rotation_number: row.rotation_number,
        effective_round: row.effective_round,
        committee: _j(row.committee) || [],
        prev_rotation: row.prev_rotation == null ? null : row.prev_rotation,
        signer_node_ids: _j(row.signer_node_ids) || [],
        signatures: _j(row.signatures) || [],
        payload_hash: row.payload_hash || null,
        committed_at: row.committed_at,
      });
    }

    // Interests registry
    const interestRows = await this.knex("interests_registry").select("*");
    if (!this.mirror._interestsRegistry) this.mirror._interestsRegistry = new Map();
    for (const row of interestRows) {
      this.mirror._interestsRegistry.set(row.slug, {
        slug: row.slug,
        label: row.label,
        category: row.category,
        registered_at: Number(row.registered_at),
        registered_by_vp_id: row.registered_by_vp_id || null,
        tx_id: row.tx_id || null,
      });
    }

    // Rotation participation
    const rpRows = await this.knex("rotation_participation").select("*");
    if (!this.mirror._rotationParticipation) this.mirror._rotationParticipation = new Map();
    for (const row of rpRows) {
      this.mirror._rotationParticipation.set(`${row.node_id}|${row.rotation_number}`, row.count);
    }

    // Prescan reviews. tip_ctid → ctid translation on hydrate (same
    // pattern as the content table — see _ensureSchema comment).
    const prRows = await this.knex("prescan_reviews").select("*");
    if (!this.mirror._prescanReviews) this.mirror._prescanReviews = new Map();
    for (const row of prRows) {
      this.mirror._prescanReviews.set(row.review_id, {
        review_id: row.review_id,
        ctid: row.tip_ctid,
        creator_tip_id: row.creator_tip_id,
        assigned_reviewer: row.assigned_reviewer || null,
        triggered_at_round: row.triggered_at_round,
        triggered_at_ms: row.triggered_at_ms == null ? null : Number(row.triggered_at_ms),
        decided_at_round: row.decided_at_round == null ? null : row.decided_at_round,
        confirmed_at_round: row.confirmed_at_round == null ? null : row.confirmed_at_round,
        confirmed_at_ms: row.confirmed_at_ms == null ? null : Number(row.confirmed_at_ms),
        state: row.state,
        decision_note: row.decision_note || null,
        suggested_origin: row.suggested_origin || null,
      });
    }
  }

  // ── Fire-and-forget ────────────────────────────────────────────────────────
  //
  // FIFO chain ordering: writes to the SAME row from the SAME tick (e.g. two
  // SCORE_UPDATE txs in one anchor batch both targeting the same tip_id) used
  // to race — both `setScore` calls would dispatch independent promises, the
  // older write could land last, and the SQL row would diverge from the
  // synchronously-updated in-memory mirror. Chaining every write off the
  // previous one's settle-time guarantees order matches call order, so the
  // final SQL state matches the mirror. Failures are swallowed per-write so a
  // single bad write doesn't poison the chain for everyone behind it.
  _ff(fn) {
    this._ffChain = (this._ffChain || Promise.resolve())
      .then(() => fn())
      .catch(err => this.log.warn(`KnexAdapter write failed: ${err.message}`));
  }

  // Oracle and SQL Server don't support Knex's .onConflict(). For 'merge' we
  // use UPDATE-first: if the row already exists update it directly (no race);
  // only INSERT when the UPDATE affects 0 rows. If a concurrent writer sneaks
  // in between the 0-row UPDATE and our INSERT, the duplicate-key catch fires
  // a second UPDATE so our value still wins.
  async _dbInsert(table, pkCols, row, onConflict) {
    if (!this._noOnConflict) {
      const pks = Array.isArray(pkCols) ? pkCols : [pkCols];
      const q = this.knex(table).insert(row).onConflict(pks.length === 1 ? pks[0] : pks);
      const promise = onConflict === "merge" ? q.merge() : q.ignore();
      // Some tables carry MULTIPLE unique constraints (e.g. commits has PK
      // on round AND a unique index on consensus_index). ON CONFLICT(col)
      // only catches conflicts on `col`; a violation of any OTHER unique
      // index still bubbles up. For "ignore" mode we want to swallow ALL
      // duplicate-key errors — the mirror already has the row and the
      // DB constraint is just preventing a stale rewrite. Catch the
      // generic duplicate-key error here too.
      return promise.catch(err => {
        if (onConflict === "ignore" && _isDuplicateKeyError(err)) return;
        throw err;
      });
    }
    // Oracle / mssql path: UPDATE-first for merge, INSERT+ignore for ignore
    if (onConflict === "merge") {
      const pks = Array.isArray(pkCols) ? pkCols : [pkCols];
      const nonPk = Object.keys(row).filter(k => !pks.includes(k));
      if (nonPk.length > 0) {
        const updates = {};
        nonPk.forEach(k => { updates[k] = row[k]; });
        let q = this.knex(table);
        pks.forEach(pk => { q = q.where(pk, row[pk]); });
        const affected = await q.update(updates);
        if (affected === 0) {
          await this.knex(table).insert(row).catch(async err => {
            if (!_isDuplicateKeyError(err)) throw err;
            // Concurrent writer inserted between our 0-row UPDATE and INSERT;
            // re-apply our update so our value wins.
            let q2 = this.knex(table);
            pks.forEach(pk => { q2 = q2.where(pk, row[pk]); });
            return q2.update(updates);
          });
        }
        return;
      }
    }
    // 'ignore' or no non-PK columns to update: INSERT and swallow duplicate
    return this.knex(table).insert(row).catch(err => {
      if (!_isDuplicateKeyError(err)) throw err;
    });
  }

  // ── Transactions ───────────────────────────────────────────────────────────

  saveTx(tx) {
    this.mirror.saveTx(tx);
    const entry = this.mirror._txs.get(tx.tx_id);
    const row = {
      tx_id: tx.tx_id,
      tx_type: tx.tx_type,
      data: JSON.stringify(tx.data || {}),
      timestamp: tx.timestamp,
      prev: JSON.stringify(tx.prev || []),
      signature: tx.signature || null,
      subject_tip_id: (entry && entry.subject_tip_id) || null,
      local_inserted_at: nowMs(),
    };
    this._ff(() => this._dbInsert("transactions", "tx_id", row, "ignore"));
  }

  getTx(id) { return this.mirror.getTx(id); }
  getAllTxs() { return this.mirror.getAllTxs(); }
  count() { return this.mirror.count(); }
  getTxsByType(t) { return this.mirror.getTxsByType(t); }
  getTxsByTypeAndCtid(t, c) { return this.mirror.getTxsByTypeAndCtid(t, c); }
  getTxsByTipId(id) { return this.mirror.getTxsByTipId(id); }
  getTxsBySubject(id) { return this.mirror.getTxsBySubject(id); }
  getRecentPrev() { return this.mirror.getRecentPrev ? this.mirror.getRecentPrev() : []; }

  *iterateAllTransactions() { yield* this.mirror.iterateAllTransactions(); }

  // ── Identities ─────────────────────────────────────────────────────────────

  saveIdentity(rec) {
    this.mirror.saveIdentity(rec);
    // GH #60: public_key + algorithm auto-route to entity_keys (single
    // source of truth). The mirror handles in-memory; PG path persists
    // here by calling _saveActiveEntityKeyToDb. root_public_key dropped.
    if (rec.public_key) {
      this._saveActiveEntityKeyToDb({
        entity_type: "identity",
        entity_id: rec.tip_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.registered_at,
        source_tx_id: rec.tx_id || `genesis:${rec.tip_id}`,
      });
    }
    const row = {
      tip_id: rec.tip_id,
      region: rec.region || "US",
      vp_id: rec.vp_id || null,
      verification_tier: rec.verification_tier || "T1",
      score_display_mode: rec.score_display_mode || "TIER_ONLY",
      tip_id_type: rec.tip_id_type || "personal",
      founding: rec.founding ? 1 : 0,
      status: rec.status || "active",
      reviewer_consent: rec.reviewer_consent ? 1 : 0,
      interests: JSON.stringify(Array.isArray(rec.interests) ? rec.interests : []),
      registered_at: rec.registered_at,
      creator_name: rec.creator_name || null,
      tx_id: rec.tx_id || null,
    };
    this._ff(() => this._dbInsert("identities", "tip_id", row, "merge"));
  }

  getIdentity(id) { return this.mirror.getIdentity(id); }
  getAllIdentities() { return this.mirror.getAllIdentities(); }

  // ── entity_keys (GH #60) ─────────────────────────────────────────────────
  // PG/MariaDB write path. Closes any currently-active row for the
  // entity (sets valid_to_ts = new row's valid_from_ts) and inserts the
  // new active row (valid_to_ts = null). Idempotent on re-save of the
  // same active key. Used by saveIdentity/saveVP/saveNode auto-routing
  // AND by KEY_ROTATED / KEY_RECOVERY commit-handler apply.
  _saveActiveEntityKeyToDb({ entity_type, entity_id, public_key, algorithm, valid_from_ts, source_tx_id }) {
    this._ff(async () => {
      // Idempotency: if an active row exists with the same key+alg+valid_from_ts, skip.
      const existing = await this.knex("entity_keys")
        .where({ entity_type, entity_id })
        .whereNull("valid_to_ts")
        .first();
      if (existing
        && existing.public_key === public_key
        && existing.algorithm === algorithm
        && Number(existing.valid_from_ts) === Number(valid_from_ts)) {
        return;
      }
      await this.knex.transaction(async (trx) => {
        await trx("entity_keys")
          .where({ entity_type, entity_id })
          .whereNull("valid_to_ts")
          .update({ valid_to_ts: valid_from_ts });
        await trx("entity_keys").insert({
          entity_type, entity_id, public_key, algorithm,
          valid_from_ts, valid_to_ts: null, source_tx_id,
        });
      });
    });
  }

  saveEntityKey(rec) {
    this.mirror.saveEntityKey(rec);
    this._ff(() => this._dbInsert(
      "entity_keys",
      ["entity_type", "entity_id", "valid_from_ts"],
      {
        entity_type: rec.entity_type,
        entity_id: rec.entity_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.valid_from_ts,
        valid_to_ts: rec.valid_to_ts == null ? null : rec.valid_to_ts,
        source_tx_id: rec.source_tx_id,
      },
      "merge",
    ));
  }
  getActiveKey(entity_type, entity_id) { return this.mirror.getActiveKey(entity_type, entity_id); }
  getKeyValidAt(entity_type, entity_id, timestamp) { return this.mirror.getKeyValidAt(entity_type, entity_id, timestamp); }
  *iterateEntityKeys() { yield* this.mirror.iterateEntityKeys(); }
  clearEntityKeys() {
    this.mirror.clearEntityKeys();
    this._ff(() => this.knex("entity_keys").del());
  }

  // ── Content ────────────────────────────────────────────────────────────────

  saveContent(rec) {
    this.mirror.saveContent(rec);
    const urls = Array.isArray(rec.registered_urls) ? rec.registered_urls : [];
    const authors = Array.isArray(rec.authors) ? rec.authors : [];
    const extras = (rec.extras && typeof rec.extras === "object" && !Array.isArray(rec.extras)) ? rec.extras : {};
    const row = {
      tip_ctid: rec.ctid,
      origin_code: rec.origin_code,
      content_hash: rec.content_hash,
      perceptual_hash: rec.perceptual_hash || null,
      author_tip_id: rec.author_tip_id,
      signer_tip_id: rec.signer_tip_id,
      authors: JSON.stringify(authors),
      attribution_mode: rec.attribution_mode || "self",
      extras: JSON.stringify(extras),
      cna_version: rec.cna_version,
      status: rec.status || "verified",
      dispute_count: rec.dispute_count || 0,
      verification_count: rec.verification_count || 0,
      prescan_flagged: rec.prescan_flagged ? 1 : 0,
      prescan_probability: typeof rec.prescan_probability === "number" ? rec.prescan_probability : 0,
      prescan_tier: rec.prescan_tier || "low",
      override: rec.override ? 1 : 0,
      registered_at: rec.registered_at,
      registered_urls: JSON.stringify(urls),
      tx_id: rec.tx_id || null,
    };
    this._ff(() => this._dbInsert("content", "tip_ctid", row, "merge"));
  }

  getContent(ctid) { return this.mirror.getContent(ctid); }
  getContentByStatus(s) { return this.mirror.getContentByStatus(s); }
  getContentByAuthor(id) { return this.mirror.getContentByAuthor(id); }
  getCleanRecordEligible(cutoff) { return this.mirror.getCleanRecordEligible(cutoff); }
  hasVerification(ctid, tipId) { return this.mirror.hasVerification(ctid, tipId); }
  hasDispute(ctid, tipId) { return this.mirror.hasDispute(ctid, tipId); }

  // ── Dispute details (off-chain dispute body) ──────────────────────────────
  // Per-node store, NOT consensus state. Mirrors the in-memory map and
  // writes through to Knex so disputes survive restart.
  saveDisputeDetails(rec) {
    const fresh = this.mirror.saveDisputeDetails(rec);
    if (fresh) {
      this._ff(() => this._dbInsert("dispute_details", "evidence_hash", {
        evidence_hash: rec.evidence_hash,
        disputer_tip_id: rec.disputer_tip_id,
        payload_json: rec.payload_json,
        signature: rec.signature,
        local_inserted_at: rec.local_inserted_at,
      }, "ignore"));
    }
    return fresh;
  }
  getDisputeDetails(hash) { return this.mirror.getDisputeDetails(hash); }
  hasDisputeDetails(hash) { return this.mirror.hasDisputeDetails(hash); }
  deleteDisputeDetails(hash) {
    const removed = this.mirror.deleteDisputeDetails(hash);
    if (removed) {
      this._ff(() => this.knex("dispute_details").where("evidence_hash", hash).del());
    }
    return removed;
  }

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
    const row = { tip_id: tipId, score, offense_count: offenseCount || 0, last_updated: lastUpdatedISO };
    this._ff(() => this._dbInsert("scores", "tip_id", row, "merge"));
  }

  getScore(id) { return this.mirror.getScore(id); }

  // ── Dedup registry ─────────────────────────────────────────────────────────

  addDedupHash(hash, createdAt, tipId) {
    this.mirror.addDedupHash(hash, createdAt, tipId);
    this._ff(() => this._dbInsert("dedup_registry", "dedup_hash", { dedup_hash: hash, created_at: createdAt, tip_id: tipId || null }, "ignore"));
  }

  hasDedupHash(h) { return this.mirror.hasDedupHash(h); }
  getDedupRegistration(h) { return this.mirror.getDedupRegistration(h); }
  dedupCount() { return this.mirror.dedupCount(); }

  // ── Canonical state iterator (§14 snapshot-sync) ──────────────────────────

  *iterateCanonicalState() { yield* this.mirror.iterateCanonicalState(); }

  clearCanonicalState() {
    this.mirror.clearCanonicalState();
    // Fire DB deletes before snapshot rows arrive. Mirror is the authoritative
    // source for computeStateMerkleRoot; DB cleanup is for restart persistence.
    Promise.all([
      this.knex("identities").delete(),
      this.knex("content").delete(),
      this.knex("scores").delete(),
      this.knex("dedup_registry").delete(),
      this.knex("revocations").delete(),
      this.knex("verification_providers").delete(),
      this.knex("nodes").delete(),
      // GH #60 — entity_keys is canonical state too.
      this.knex("entity_keys").delete(),
    ]).catch(err => this.log.warn(`clearCanonicalState DB flush failed: ${err.message}`));
  }

  // ── Revocations ────────────────────────────────────────────────────────────

  addRevocation(id, type, ts, txId) {
    this.mirror.addRevocation(id, type, ts, txId);
    this._ff(() => this._dbInsert("revocations", "tip_id", { tip_id: id, tx_type: type, timestamp: ts, tx_id: txId }, "ignore"));
  }

  isRevoked(id) { return this.mirror.isRevoked(id); }
  getRevocation(id) { return this.mirror.getRevocation(id); }
  getRevocations(since) { return this.mirror.getRevocations(since); }

  // ── Domain bindings (canonical) + pending claims (local-only) ─────────────

  saveDomainBinding(rec) {
    this.mirror.saveDomainBinding(rec);
    const row = {
      domain: rec.domain,
      tip_id: rec.tip_id,
      binding_state: rec.binding_state,
      method: rec.method,
      claimed_at: rec.claimed_at,
      verified_at: rec.verified_at,
      expires_at: rec.expires_at,
      consecutive_failures: typeof rec.consecutive_failures === "number" ? rec.consecutive_failures : 0,
      node_id: rec.node_id,
      claim_signature: rec.claim_signature,
      binding_signature: rec.binding_signature,
      tx_id: rec.tx_id,
    };
    this._ff(() => this._dbInsert("domain_bindings", "domain", row, "merge"));
  }

  getDomainBinding(domain) { return this.mirror.getDomainBinding(domain); }
  getDomainBindingsByTipId(tipId) { return this.mirror.getDomainBindingsByTipId(tipId); }
  getAllDomainBindings() { return this.mirror.getAllDomainBindings(); }

  savePendingDomainClaim(rec) {
    this.mirror.savePendingDomainClaim(rec);
    const row = {
      domain: rec.domain,
      tip_id: rec.tip_id,
      method: rec.method,
      claimed_at: rec.claimed_at,
      signature: rec.signature,
      received_at: rec.received_at,
    };
    this._ff(() => this._dbInsert("pending_domain_claims", "domain", row, "merge"));
  }

  getPendingDomainClaim(domain) { return this.mirror.getPendingDomainClaim(domain); }

  deletePendingDomainClaim(domain) {
    const removed = this.mirror.deletePendingDomainClaim(domain);
    if (removed) {
      this._ff(() => this.knex("pending_domain_claims").where("domain", domain).del());
    }
    return removed;
  }

  // ── Verification Providers ─────────────────────────────────────────────────

  saveVP(rec) {
    this.mirror.saveVP(rec);
    // GH #60 — auto-route public_key + algorithm to entity_keys.
    if (rec.public_key) {
      this._saveActiveEntityKeyToDb({
        entity_type: "vp",
        entity_id: rec.vp_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.registered_at,
        source_tx_id: rec.tx_id || `genesis:${rec.vp_id}`,
      });
    }
    const row = {
      vp_id: rec.vp_id,
      name: rec.name,
      jurisdiction: rec.jurisdiction || "US",
      jurisdiction_tier: rec.jurisdiction_tier || "green",
      status: rec.status || "active",
      registered_at: rec.registered_at,
    };
    this._ff(() => this._dbInsert("verification_providers", "vp_id", row, "merge"));
  }

  getVP(id) { return this.mirror.getVP(id); }
  getAllVPs() { return this.mirror.getAllVPs(); }

  // ── Nodes ──────────────────────────────────────────────────────────────────

  saveNode(rec) {
    this.mirror.saveNode(rec);
    // GH #60 — auto-route public_key + algorithm to entity_keys.
    if (rec.public_key) {
      this._saveActiveEntityKeyToDb({
        entity_type: "node",
        entity_id: rec.node_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.registered_at,
        source_tx_id: rec.tx_id || `genesis:${rec.node_id}`,
      });
    }
    const row = {
      node_id: rec.node_id,
      name: rec.name || null,
      status: rec.status || "active",
      registered_at: rec.registered_at,
    };
    this._ff(() => this._dbInsert("nodes", "node_id", row, "merge"));
  }

  getNode(id) { return this.mirror.getNode(id); }
  getAllNodes() { return this.mirror.getAllNodes(); }

  // ── Certificates ──────────────────────────────────────────────────────────

  saveCertificate(cert) {
    this.mirror.saveCertificate(cert);
    const row = {
      hash: cert.hash,
      round: cert.round,
      author_node_id: cert.author_node_id,
      batch_data: JSON.stringify(cert.batch),
      acknowledgments: JSON.stringify(cert.acknowledgments),
      parent_hashes: JSON.stringify(cert.parent_hashes || []),
      signature: cert.signature,
      timestamp: Number(cert.timestamp || 0),
      local_inserted_at: nowMs(),
    };
    this._ff(() => this._dbInsert("certificates", "hash", row, "ignore"));
  }

  getCertificate(hash) { return this.mirror.getCertificate(hash); }
  getCertificatesByRound(round) { return this.mirror.getCertificatesByRound(round); }
  getCertificateByAuthorRound(a, r) { return this.mirror.getCertificateByAuthorRound(a, r); }
  getLatestRound() { return this.mirror.getLatestRound(); }
  getEarliestCertRound() { return this.mirror.getEarliestCertRound(); }
  getCertificatesFromRound(from) { return this.mirror.getCertificatesFromRound(from); }
  // §14/#49 — certs-in-range iterator used by snapshot streaming. Mirrors
  // the SQLiteStore generator. Delegates to the in-memory mirror, which has
  // the full cert window post-_hydrate.
  *iterateCertsByRoundRange(from, to) { yield* this.mirror.iterateCertsByRoundRange(from, to); }
  certificateCount() { return this.mirror.certificateCount(); }

  pruneCertificatesBefore(cutoffRound) {
    const n = this.mirror.pruneCertificatesBefore(cutoffRound);
    this._ff(() => this.knex("certificates").where("round", "<", cutoffRound).delete());
    return n;
  }

  incrementalVacuum(_maxPages) { /* no-op for server DBs */ }

  // ── Commit checkpoints ─────────────────────────────────────────────────────

  saveCommit(rec) {
    this.mirror.saveCommit(rec);
    const row = {
      round: rec.round,
      anchor_cert_hash: rec.anchor_cert_hash,
      leader_node_id: rec.leader_node_id,
      committee: JSON.stringify(rec.committee || []),
      support_count: rec.support_count,
      consensus_index: rec.consensus_index,
      committed_at: rec.committed_at,
      state_merkle_root: rec.state_merkle_root,
      txs_merkle_root: rec.txs_merkle_root,
      ack_signer_ids: JSON.stringify(rec.ack_signer_ids || []),
      ack_signatures: JSON.stringify(rec.ack_signatures || []),
      ack_signed_ats: JSON.stringify(rec.ack_signed_ats || []),
      cert_timestamp: Number(rec.cert_timestamp || 0),
      anchor_batch_hash: rec.anchor_batch_hash || null,
      local_inserted_at: nowMs(),
    };
    this._ff(() => this._dbInsert("commits", "round", row, "ignore"));
  }

  getCommit(round) { return this.mirror.getCommit(round); }
  getLatestCommit() { return this.mirror.getLatestCommit(); }
  getCommitsFromRound(from) { return this.mirror.getCommitsFromRound(from); }
  getLatestConsensusIndex() { return this.mirror.getLatestConsensusIndex(); }

  setConsensusMeta(key, value) {
    this.mirror.setConsensusMeta(key, value);
    this._ff(() => this._dbInsert("consensus_meta", "key", { key, value: String(value) }, "merge"));
  }

  getConsensusMeta(key) { return this.mirror.getConsensusMeta(key); }

  *iterateAllCommitsExcept(latestRound) { yield* this.mirror.iterateAllCommitsExcept(latestRound); }

  // ── Equivocation defense ──────────────────────────────────────────────────

  recordSeenVote(round, author, batchHash) {
    const isNew = this.mirror.recordSeenVote(round, author, batchHash);
    if (isNew) {
      this._ff(() => this._dbInsert("votes_seen", ["round", "author"], { round, author, batch_hash: batchHash, local_inserted_at: nowMs() }, "ignore"));
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
    this._ff(() => this._dbInsert("mempool", "tx_id", {
      tx_id: tx.tx_id,
      tx_data: JSON.stringify(tx),
      subject_tip_id: subjectTipId(tx) || null,
      received_at: nowMs(),
    }, "ignore"));
  }

  getMempoolTx(txId) { return this.mirror.getMempoolTx(txId); }
  getMempoolTxs() { return this.mirror.getMempoolTxs(); }
  getMempoolTxsByTipId(tipId) { return this.mirror.getMempoolTxsByTipId(tipId); }

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
      const at = rec.rejected_at_ms != null ? rec.rejected_at_ms : nowMs();
      const txData = rec.tx_data == null ? null
        : (typeof rec.tx_data === "string" ? rec.tx_data : JSON.stringify(rec.tx_data));
      const subj = rec.tx_data && typeof rec.tx_data === "object" ? subjectTipId(rec.tx_data) : null;
      this._ff(() => this._dbInsert("tx_rejections", "tx_id", {
        tx_id: rec.tx_id,
        reason: rec.reason,
        reason_detail: rec.reason_detail || null,
        rejected_at_ms: at,
        rejected_at_round: rec.rejected_at_round || null,
        dropper_node_id: rec.dropper_node_id,
        tx_type: rec.tx_type || null,
        origin_node_id: rec.origin_node_id || null,
        tx_data: txData,
        subject_tip_id: subj,
      }, "ignore"));
    }
    return inserted;
  }

  getTxRejection(txId) { return this.mirror.getTxRejection(txId); }
  getTxRejectionsByReason(reason, opts) { return this.mirror.getTxRejectionsByReason(reason, opts); }
  getTxRejectionsByTipId(tipId) { return this.mirror.getTxRejectionsByTipId(tipId); }
  countTxRejections() { return this.mirror.countTxRejections(); }

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

  // ── Committee history ──────────────────────────────────────────────────────

  saveCommitteeRotation(rec) {
    this.mirror.saveCommitteeRotation(rec);
    const row = {
      rotation_number: rec.rotation_number,
      effective_round: rec.effective_round,
      committee: JSON.stringify(rec.committee || []),
      prev_rotation: rec.prev_rotation == null ? null : rec.prev_rotation,
      signer_node_ids: JSON.stringify(rec.signer_node_ids || []),
      signatures: JSON.stringify(rec.signatures || []),
      payload_hash: rec.payload_hash || null,
      committed_at: rec.committed_at || nowMs(),
      local_inserted_at: nowMs(),
    };
    this._ff(() => this._dbInsert("committee_history", "rotation_number", row, "merge"));
  }

  getCommitteeRotation(n) { return this.mirror.getCommitteeRotation(n); }
  getLatestRotation() { return this.mirror.getLatestRotation(); }
  getCommitteeAtRound(r) { return this.mirror.getCommitteeAtRound(r); }
  *getRotationsFromGenesis() { yield* this.mirror.getRotationsFromGenesis(); }

  // ── Interests registry ─────────────────────────────────────────────────────

  saveInterest(rec) {
    this.mirror.saveInterest(rec);
    const row = {
      slug: rec.slug,
      label: rec.label,
      category: rec.category,
      registered_at: rec.registered_at,
      registered_by_vp_id: rec.registered_by_vp_id || null,
      tx_id: rec.tx_id || null,
      local_inserted_at: nowMs(),
    };
    this._ff(() => this._dbInsert("interests_registry", "slug", row, "merge"));
  }

  getInterest(slug) { return this.mirror.getInterest(slug); }
  getAllInterests() { return this.mirror.getAllInterests(); }
  interestCount() { return this.mirror.interestCount(); }

  // ── Prescan reviews ────────────────────────────────────────────────────────

  savePrescanReview(rec) {
    this.mirror.savePrescanReview(rec);
    // ctid → tip_ctid on save (PostgreSQL system-column collision).
    const row = {
      review_id: rec.review_id,
      tip_ctid: rec.ctid,
      creator_tip_id: rec.creator_tip_id,
      assigned_reviewer: rec.assigned_reviewer || null,
      triggered_at_round: rec.triggered_at_round,
      triggered_at_ms: rec.triggered_at_ms == null ? null : rec.triggered_at_ms,
      decided_at_round: rec.decided_at_round == null ? null : rec.decided_at_round,
      confirmed_at_round: rec.confirmed_at_round == null ? null : rec.confirmed_at_round,
      confirmed_at_ms: rec.confirmed_at_ms == null ? null : rec.confirmed_at_ms,
      state: rec.state || "triggered",
      decision_note: rec.decision_note || null,
      suggested_origin: rec.suggested_origin || null,
    };
    this._ff(() => this._dbInsert("prescan_reviews", "review_id", row, "merge"));
  }

  getPrescanReview(reviewId) { return this.mirror.getPrescanReview(reviewId); }
  getOpenPrescanReviewByCtid(ctid) { return this.mirror.getOpenPrescanReviewByCtid(ctid); }
  getPrescanReviewsByReviewer(tipId) { return this.mirror.getPrescanReviewsByReviewer(tipId); }
  getPrescanReviewsByCtid(ctid) { return this.mirror.getPrescanReviewsByCtid(ctid); }
  // Trigger-facing scan methods — read from the in-memory mirror.
  // The mirror is canonical for these (the trigger runs at every
  // round-end and needs O(1) read access); SQL-side equivalents
  // would be redundant.
  getContentsNeedingReview(nowMs) { return this.mirror.getContentsNeedingReview(nowMs); }
  getReviewsNeedingAutoEscalation(nowMs) { return this.mirror.getReviewsNeedingAutoEscalation(nowMs); }
  getReviewsNeedingAutoRecuse(nowMs) { return this.mirror.getReviewsNeedingAutoRecuse(nowMs); }

  // ── Rotation participation ─────────────────────────────────────────────────

  incrementRotationParticipation(nodeId, rotationNumber) {
    this.mirror.incrementRotationParticipation(nodeId, rotationNumber);
    const count = (this.mirror._rotationParticipation.get(`${nodeId}|${rotationNumber}`) || 0);
    this._ff(() => this._dbInsert("rotation_participation",
      ["node_id", "rotation_number"],
      { node_id: nodeId, rotation_number: rotationNumber, count },
      "merge"
    ));
  }

  getRotationParticipation(n) { return this.mirror.getRotationParticipation(n); }

  pruneRotationParticipationBefore(n) {
    const removed = this.mirror.pruneRotationParticipationBefore(n);
    this._ff(() => this.knex("rotation_participation").where("rotation_number", "<", n).delete());
    return removed;
  }

  setRotationParticipation(nodeId, rotationNumber, count) {
    this.mirror.setRotationParticipation(nodeId, rotationNumber, count);
    this._ff(() => this._dbInsert("rotation_participation",
      ["node_id", "rotation_number"],
      { node_id: nodeId, rotation_number: rotationNumber, count },
      "merge"
    ));
  }

  deleteRotationParticipationByRotation(rotationNumber) {
    const removed = this.mirror.deleteRotationParticipationByRotation(rotationNumber);
    this._ff(() => this.knex("rotation_participation").where("rotation_number", rotationNumber).delete());
    return removed;
  }

  *iterateRotationParticipationForSnapshot() {
    yield* this.mirror.iterateRotationParticipationForSnapshot();
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  close() {
    try { this.knex.destroy(); } catch { /* ignore */ }
  }
}

module.exports = { KnexAdapter };
