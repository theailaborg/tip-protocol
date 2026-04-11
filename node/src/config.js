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

const path   = require("path");

function loadConfig() {
  // Generate a stable node ID from hostname + a fixed seed if not set
  const { shake256: _shake } = require("../../shared/crypto");
  const defaultNodeId = process.env.TIP_NODE_ID ||
    _shake(require("os").hostname() + "tip-node-v2")
      .slice(0, 16);

  return {
    // ── Node identity ──────────────────────────────────────────────────────────
    nodeId:      defaultNodeId,
    nodeType:    process.env.TIP_NODE_TYPE    || "full",  // full | light | vp | archive
    region:      process.env.TIP_REGION       || "US",
    vpId:        process.env.TIP_VP_ID        || null,    // set if this is a VP node
    nodeVersion: require("../../package.json").version,

    // ── Network ───────────────────────────────────────────────────────────────
    port:        parseInt(process.env.PORT    || "4000", 10),
    host:        process.env.HOST             || "0.0.0.0",
    publicUrl:   process.env.TIP_PUBLIC_URL   || `http://localhost:4000`,
    peers:       parsePeers(process.env.TIP_PEERS),

    // ── Storage ───────────────────────────────────────────────────────────────
    dataDir:     process.env.TIP_DATA_DIR     || path.resolve(process.cwd(), "data"),
    dbPath:      process.env.TIP_DB_PATH      || path.resolve(process.cwd(), "data", "tip.db"),

    // ── Security ──────────────────────────────────────────────────────────────
    nodePrivateKey:  process.env.TIP_NODE_PRIVATE_KEY || null,
    nodePublicKey:   process.env.TIP_NODE_PUBLIC_KEY  || null,

    // ── Rate limiting ─────────────────────────────────────────────────────────
    rateLimitWindow:   60 * 1000,   // 1 minute
    rateLimitMax:      200,          // requests per window per IP

    // ── DAG settings ──────────────────────────────────────────────────────────
    dagMaxPrevRefs:    2,            // each tx references 2 prior txs
    dagSyncInterval:   30 * 1000,    // 30 seconds between peer syncs

    // ── Trust scoring ─────────────────────────────────────────────────────────
    initialScore:          500,
    initialScoreAttested:  550,
    maxScore:             1000,
    minScore:               0,
    dailyVerifyScoreCap:    10,      // max score gain per day from verifications
    jurorMonthlyMax:        20,      // max jury cases per TIP-ID per 30 days

    // ── Pre-scan (v2 FIX-03) ──────────────────────────────────────────────────
    preScanEnabled:        true,
    preScanDefaultThreshold: 0.85,

    // ── Merkle root publishing ─────────────────────────────────────────────────
    merklePublishInterval: 6 * 60 * 60 * 1000,  // every 6 hours

    // ── CORS ──────────────────────────────────────────────────────────────────
    corsOrigins: parseCorsOrigins(process.env.TIP_CORS_ORIGINS),

    // ── Logging ───────────────────────────────────────────────────────────────
    logLevel:    process.env.TIP_LOG_LEVEL || "info",
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
