/**
 * @file @tip-protocol/node/src/config.js
 * @description Configuration loader with environment variable overrides.
 *
 * All settings can be overridden via environment variables.
 * Copy .env.example to .env and customise before starting the node.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { MEDIA_LIMITS } = require("../../shared/constants");
const { CONTENT_LIMITS } = require("../../shared/protocol-constants");

// Fail closed: dev-gated paths check NODE_ENV !== "production", so an unset
// NODE_ENV must behave as production, never as an open dev gate.
if (!process.env.NODE_ENV) process.env.NODE_ENV = "production";

// Read `${name}_FILE` (a mounted Docker/K8s secret, trimmed) when set, else the
// `${name}` env value. File wins so prod can keep the key off the environment.
function secretFromEnvOrFile(name) {
  const file = process.env[`${name}_FILE`];
  if (file) {
    try { return fs.readFileSync(file, "utf8").trim() || null; }
    catch (e) { throw new Error(`${name}_FILE is set to "${file}" but unreadable: ${e.message}`); }
  }
  return process.env[name] || null;
}

// Resolve the node keypair: TIP_NODE_CREDENTIALS_FILE (a .tip.json with both
// keys, written by seed.js/register-node.js) wins over the per-key env vars,
// so the .env never has to inline the secret.
function loadNodeKeypair() {
  const credFile = process.env.TIP_NODE_CREDENTIALS_FILE;
  if (credFile) {
    let doc;
    try { doc = JSON.parse(fs.readFileSync(credFile, "utf8")); }
    catch (e) { throw new Error(`TIP_NODE_CREDENTIALS_FILE "${credFile}" is unreadable or not valid JSON: ${e.message}`); }
    return { privateKey: doc.private_key || null, publicKey: doc.public_key || null };
  }
  return {
    privateKey: secretFromEnvOrFile("TIP_NODE_PRIVATE_KEY"),
    publicKey: secretFromEnvOrFile("TIP_NODE_PUBLIC_KEY"),
  };
}

function loadConfig() {
  // Generate a stable node ID from hostname + a fixed seed if not set
  const { shake256: _shake } = require("../../shared/crypto");
  const defaultNodeId = process.env.TIP_NODE_ID ||
    _shake(require("os").hostname() + "tip-node-v2")
      .slice(0, 16);

  const nodeKeys = loadNodeKeypair();

  return {
    // ── Node identity ──────────────────────────────────────────────────────────
    nodeId: defaultNodeId,
    nodeType: process.env.TIP_NODE_TYPE || "full",  // full | light | vp | archive
    region: process.env.TIP_REGION || "US",
    vpId: process.env.TIP_VP_ID || null,    // set if this is a VP node
    nodeVersion: require("../../package.json").version,

    // ── Network ───────────────────────────────────────────────────────────────
    port: parseInt(process.env.PORT || "4000", 10),
    host: process.env.HOST || "0.0.0.0",
    publicUrl: process.env.TIP_PUBLIC_URL || `http://localhost:4000`,
    publicIp: process.env.TIP_PUBLIC_IP || null,    // external IP for bootstrap_addr in health
    p2pPort: parseInt(process.env.TIP_P2P_PORT || "4001", 10),
    peers: parsePeers(process.env.TIP_PEERS),

    // ── Storage ───────────────────────────────────────────────────────────────
    dataDir: process.env.TIP_DATA_DIR || path.resolve(process.cwd(), "data"),
    dbPath: process.env.TIP_DB_PATH || path.resolve(process.cwd(), "data", "tip.db"),

    // ── Database (Knex adapter) ───────────────────────────────────────────────
    // dbDriver=sqlite → built-in SQLiteStore (default for dev/test)
    // dbDriver=postgres|mariadb|mysql|mssql|oracle → KnexAdapter
    dbDriver: process.env.DB_DRIVER || null,
    dbUrl: process.env.DATABASE_URL || null,
    dbHost: process.env.DB_HOST || "localhost",
    dbPort: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : null,
    dbName: process.env.DB_NAME || "tip_protocol",
    dbUser: process.env.DB_USER || "tip",
    dbPassword: process.env.DB_PASSWORD || "",
    dbSsl: process.env.DB_SSL === "true",
    dbSslRejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== "false",
    dbPoolMin: parseInt(process.env.DB_POOL_MIN || "2", 10),
    dbPoolMax: parseInt(process.env.DB_POOL_MAX || "10", 10),

    // ── Security ──────────────────────────────────────────────────────────────
    nodePrivateKey: nodeKeys.privateKey,
    nodePublicKey: nodeKeys.publicKey,

    // ── Rate limiting ─────────────────────────────────────────────────────────
    // Overridable via env for high-throughput dev / UAT runs that
    // intentionally fire many requests from one IP (the comprehensive
    // signature-unification UAT walks ~30 endpoints + polls tx commit
    // status, easily exceeding the prod default of 200/min).
    rateLimitWindow: parseInt(process.env.TIP_RATE_LIMIT_WINDOW_MS || `${60 * 1000}`, 10),
    rateLimitMax: parseInt(process.env.TIP_RATE_LIMIT_MAX || "200", 10),

    // ── DAG settings ──────────────────────────────────────────────────────────
    dagMaxPrevRefs: 2,            // each tx references 2 prior txs
    dagSyncInterval: 30 * 1000,    // 30 seconds between peer syncs

    // ── Trust scoring ─────────────────────────────────────────────────────────
    initialScore: 500,
    initialScoreAttested: 550,
    maxScore: 1000,
    minScore: 0,
    dailyVerifyScoreCap: 10,      // max score gain per day from verifications
    jurorMonthlyMax: 20,      // max jury cases per TIP-ID per 30 days

    // ── Pre-scan (v2 FIX-03) ──────────────────────────────────────────────────
    preScanEnabled: true,
    preScanDefaultThreshold: 0.85,

    // ── Scheduler interval (node-local tuning, not a protocol constant) ────────
    // Verdicts, score effects and clean-record bonuses are event-driven off
    // consensus commits; peer health is the only timed job left.
    peerHealthInterval: parseInt(process.env.TIP_PEER_HEALTH_MS || 30 * 1000, 10),            // 30 seconds

    // ── Media size limits (node-level, client-side enforcement) ────────────────
    mediaLimits: {
      max_video_bytes: parseInt(process.env.TIP_MAX_VIDEO_BYTES || MEDIA_LIMITS.max_video_bytes, 10),
      max_image_bytes: parseInt(process.env.TIP_MAX_IMAGE_BYTES || MEDIA_LIMITS.max_image_bytes, 10),
      max_audio_bytes: parseInt(process.env.TIP_MAX_AUDIO_BYTES || MEDIA_LIMITS.max_audio_bytes, 10),
      max_text_bytes: parseInt(process.env.TIP_MAX_TEXT_BYTES || MEDIA_LIMITS.max_text_bytes, 10),
      // Per-post media[] item ceiling. Comes from protocol-constants
      // (CONTENT_LIMITS.media_items_max), surfaced here so the schema
      // validator gates request size before storage IO.
      media_items_max: CONTENT_LIMITS.MEDIA_ITEMS_MAX,
    },

    // Express body-parser cap (genesis content_limits.request_body_max_bytes).
    // Surfaced here so api.js sets the limit from config (resolved after
    // ProtocolConstants init) rather than reaching into the throwing getter at
    // app-build time. Registrations carry a gzipped perceptual fingerprints
    // envelope, so this must comfortably exceed media+text JSON.
    requestBodyMaxBytes: CONTENT_LIMITS.REQUEST_BODY_MAX_BYTES,

    // ── Public API endpoint ─────────────────────────────────────────────────
    // This node's public-facing origin (https://host[:port]). Announced on
    // chain via NODE_ENDPOINT_UPDATED at boot when it differs from the
    // nodes row — peers redirect reviewers here for media this node holds.
    // Optional: nodes without a public surface simply never announce.
    apiEndpoint: process.env.TIP_API_ENDPOINT || null,

    // ── CORS ──────────────────────────────────────────────────────────────────
    corsOrigins: parseCorsOrigins(process.env.TIP_CORS_ORIGINS),

    // ── Logging ───────────────────────────────────────────────────────────────
    logLevel: process.env.TIP_LOG_LEVEL || "info",
  };
}

function parsePeers(envVal) {
  if (!envVal) return [];
  return envVal.split(",").map(p => p.trim()).filter(Boolean);
}

function parseCorsOrigins(envVal) {
  if (!envVal || envVal.trim() === "*") return "*";
  return envVal.split(",").map(o => o.trim()).filter(Boolean);
}

module.exports = { loadConfig };
