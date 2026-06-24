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
const { computeTxId, verifyTxId } = require("../../shared/crypto");
const { nowMs } = require("../../shared/time");
const { TX_TYPES, PRESCAN_REVIEW_STATES } = require("../../shared/constants");
const { SCORE, CONTENT_GRACE, REVIEWER } = require("../../shared/protocol-constants");
const { subjectTipId, subjectTipIds } = require("./tx-attribution");
const { log } = require("./logger");

// ─── SQLite loaded lazily ─────────────────────────────────────────────────────
let Database = null;
try { Database = require("better-sqlite3"); } catch { /* use in-memory */ }

// ─── Knex SQLite migration runner ─────────────────────────────────────────────
// Runs the shared Knex migration files against a SQLite DB file before the
// SQLiteStore is constructed. Called from initDAGAsync when dbPath is set and
// better-sqlite3 is available. Runs every boot; Knex's migration tracker
// (knex_migrations table) makes it idempotent.
async function _runSqliteMigrations(dbPath) {
  const knexLib = require("knex");
  const migrationsDir = require("path").join(__dirname, "db/migrations");
  const k = knexLib({
    client: "better-sqlite3",
    connection: { filename: dbPath },
    useNullAsDefault: true,
    migrations: { directory: migrationsDir, loadExtensions: [".js"] },
  });
  try {
    await k.migrate.latest();
  } finally {
    await k.destroy();
  }
}

// ─── Canonical row shapers (§14 snapshot-sync) ────────────────────────────
// Both stores project their row shapes through these before yielding from
// iterateCanonicalState. Single source of truth for which fields of each
// table participate in the state_merkle_root. Adding or removing a field
// here is a consensus-breaking change — every node in the network must
// upgrade simultaneously or commit rows will mismatch.
//
// Every column of each table IS included. This is only safe because every
// field is populated from tx data (tx.timestamp, tx.tx_id, tx.data.*) —
// never from nowMs() / unixepoch() / other local-clock sources.
// See setScore() and addDedupHash() for the determinism contract.
function _canonIdentity(r) {
  // GH #60: public_key, algorithm, root_public_key removed.
  // public_key + algorithm participate in state_merkle_root via
  // entity_keys (see _canonEntityKey). root_public_key was orphaned
  // scaffolding for a recovery-anchor design that never landed; if a
  // recovery key is ever needed it slots into entity_keys as a
  // different key_type extension.
  return {
    tip_id: r.tip_id,
    region: r.region,
    vp_id: r.vp_id || null,
    verification_tier: r.verification_tier,
    score_display_mode: r.score_display_mode || "TIER_ONLY",
    tip_id_type: r.tip_id_type || "personal",
    founding: r.founding ? 1 : 0,
    status: r.status,
    // Independent opt-in per adjudication role (issue #107). Each defaults
    // to 0 (not opted in); only an explicit UPDATE_PROFILE toggle sets it.
    reviewer_consent: r.reviewer_consent ? 1 : 0,
    juror_consent: r.juror_consent ? 1 : 0,
    expert_consent: r.expert_consent ? 1 : 0,
    registered_at: r.registered_at,
    creator_name: r.creator_name || null,
    tx_id: r.tx_id || null,
  };
}
function _canonContent(r) {
  // Intentionally excluded: `dispute_count`, `verification_count`. Both are
  // dead columns today (always 0 — never written) and would trap a future
  // writer that updates them non-deterministically. Re-add if/when they
  // start being incremented from commit-handler with tx context.
  //
  // Every other column is included — fields are populated from tx.data
  // (deterministic across nodes), so any divergence on the persisted
  // row would indicate a code bug, and the merkle-root mismatch is
  // exactly where we want that bug surfaced.
  return {
    ctid: r.ctid,
    origin_code: r.origin_code,
    content_hash: r.content_hash,
    author_tip_id: r.author_tip_id,
    signer_tip_id: r.signer_tip_id,
    authors: Array.isArray(r.authors) ? r.authors : [],
    attribution_mode: r.attribution_mode || "self",
    extras: (r.extras && typeof r.extras === "object" && !Array.isArray(r.extras)) ? r.extras : {},
    cna_version: r.cna_version,
    status: r.status,
    prescan_flagged: r.prescan_flagged ? 1 : 0,
    prescan_probability: typeof r.prescan_probability === "number" ? r.prescan_probability : 0,
    prescan_tier: r.prescan_tier || "low",
    prescan_status: r.prescan_status || "completed",
    prescan_completed_at: typeof r.prescan_completed_at === "number" ? r.prescan_completed_at : null,
    prescan_assigned_node_id: r.prescan_assigned_node_id || null,
    prescan_content_type: r.prescan_content_type || null,
    prescan_overall_degraded: r.prescan_overall_degraded ? 1 : 0,
    content_type_hint: r.content_type_hint || null,
    override: r.override ? 1 : 0,
    registered_at: r.registered_at,
    registered_urls: Array.isArray(r.registered_urls) ? r.registered_urls : [],
    media: Array.isArray(r.media) ? r.media : [],
    media_canonical_hash: typeof r.media_canonical_hash === "string" ? r.media_canonical_hash : null,
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
function _canonDedup(hash, createdAt, tipId) {
  // Normalize created_at to string. Source of truth is a unix-seconds
  // bigint column, but the value reaches the mirror two ways:
  //   • genesis init — passes Number (Math.floor(getTime()/1000))
  //   • resume from DB — knex returns bigint as String (default node-pg
  //     behavior — bigints don't fit in JS Number safely).
  // Without normalization, a fresh-genesis joiner's state_merkle_root
  // diverges from a resumed peer's even though their dedup_registry
  // tables are byte-identical. Verified live 2026-05-06: node-5 stuck
  // in sync↔catching_up because dedup digest differed by Number-vs-String
  // canonical encoding.
  return {
    created_at: createdAt != null ? String(createdAt) : null,
    dedup_hash: hash,
    tip_id: tipId || null,
  };
}
function _canonRotationParticipation(r) {
  return {
    node_id: r.node_id,
    rotation_number: r.rotation_number,
    count: r.count,
  };
}
function _canonRevocation(r) {
  return {
    tip_id: r.tip_id,
    tx_type: r.tx_type,
    timestamp: r.timestamp,
    tx_id: r.tx_id,
  };
}
// Domain bindings: every column participates in state_merkle_root. The
// committed binding_state (verified | revoked) is the single source of
// truth across the federation; periodic re-verification will be handled
// by a consensus-emitted trigger so the public surface stays node-agnostic.
// `expires_at` + `consecutive_failures` are v2 prep slots — set at BIND
// commit (verified_at + DOMAIN_HEALTHY_EXPIRY_MS / 0) and untouched until
// the renewal scheduler + RENEW_DOMAIN tx land. Including them in canonical
// state now means v2 needs no migration.
// See schemas/bind-domain.js for the trust-model rationale.
function _canonDomainBinding(r) {
  return {
    domain: r.domain,
    tip_id: r.tip_id,
    binding_state: r.binding_state,
    method: r.method,
    claimed_at: r.claimed_at,
    verified_at: r.verified_at,
    expires_at: r.expires_at,
    consecutive_failures: typeof r.consecutive_failures === "number" ? r.consecutive_failures : 0,
    node_id: r.node_id,
    claim_signature: r.claim_signature,
    binding_signature: r.binding_signature,
    tx_id: r.tx_id,
  };
}
// Platform links: every column participates in state_merkle_root.
// handle may be null for platforms where the identifier is the profile_url.
// Signatures (user's claim cosig + node's body sig) are NOT stored here —
// both are reachable via tx_id from the transactions table (cosig is
// in tx.data.cosignatures[], node sig is tx.signature). Avoids
// duplicating crypto blobs and keeps the row focused on display state.
function _canonPlatformLink(r) {
  return {
    id: r.id,
    tip_id: r.tip_id,
    platform: r.platform,
    handle: r.handle || null,
    profile_url: r.profile_url,
    status: r.status,
    linked_at: r.linked_at,
    verified_at: r.verified_at,
    unlinked_at: r.unlinked_at ?? null,
    unlink_tx_id: r.unlink_tx_id ?? null,
    node_id: r.node_id,
    tx_id: r.tx_id,
  };
}
function _canonVP(r) {
  // GH #60: public_key in entity_keys, not here.
  return {
    vp_id: r.vp_id,
    name: r.name,
    jurisdiction: r.jurisdiction,
    jurisdiction_tier: r.jurisdiction_tier,
    status: r.status,
    registered_at: r.registered_at,
  };
}
function _canonNode(r) {
  // GH #60: public_key in entity_keys, not here.
  return {
    node_id: r.node_id,
    name: r.name || null,
    status: r.status,
    api_endpoint: r.api_endpoint || null,
    registered_at: r.registered_at,
  };
}
// GH #60 — canonical projection for the entity_keys table. Participates
// in state_merkle_root so the federation agrees byte-for-byte on every
// entity's key history. Sort by (entity_type, entity_id, valid_from_ts)
// in the iterator before computing the root.
function _canonEntityKey(r) {
  return {
    entity_type: r.entity_type,
    entity_id: r.entity_id,
    public_key: r.public_key,
    algorithm: r.algorithm || "ml-dsa-65",
    valid_from_ts: r.valid_from_ts,
    valid_to_ts: r.valid_to_ts == null ? null : r.valid_to_ts,
    source_tx_id: r.source_tx_id,
  };
}

// §4 + #34: canonical row shape for committee_history. Used to compute
// committee_history_root over the rotation chain (snapshot-side). NOT part
// of iterateCanonicalState — rotation rows are shipped in their own
// snapshot stream with their own root, independent of state_merkle_root.
// See snapshot-handler for the chain-of-trust walk that consumes these.
//
// Schema:
//   - committee: array of { node_id, public_key } records, sorted by node_id.
//     Carrying pubkeys IN the rotation (rather than relying on the snapshot's
//     nodes table) closes the chicken-and-egg verification gap: a fresh
//     joiner anchors trust at the LOCAL genesis founding_node (hardcoded in
//     their binary) and walks forward, adopting each rotation's pubkeys ONLY
//     after verifying the rotation's sigs against the previously-trusted
//     committee. Without this, snapshot verification would have to look up
//     pubkeys in the (peer-controlled) nodes table — a self-attestation loop
//     that admits the synthetic-snapshot attack.
//   - signer_node_ids: array of node_id strings (parallel order to signatures)
//   - signatures: array of hex sigs over `rotation:${payload_hash}:${signer_node_id}`
//
// Determinism contract: committee must be sorted by node_id before save;
// signer_node_ids sorted; signatures parallel to signer_node_ids (same
// indexes, same order). Genesis rotation 0 has prev_rotation=null and
// no signers/signatures (hardcoded trust anchor — joiner verifies it
// matches local genesis.founding_node before extending trust).
// Canonical projection for the `prescan_reviews` table — participates in
// state_merkle_root. A prescan-review represents a single instance of the
// human-reviewing-AI-flag pipeline that gates between prescan HIGH/CRITICAL
// flag and public CONTENT_DISPUTED. Decision fields (assigned_reviewer,
// decided_at_round, confirmed_at_round, decision_note, suggested_origin)
// may be null while the review is in flight.
function _canonPrescanReview(r) {
  return {
    review_id: r.review_id,
    ctid: r.ctid,
    creator_tip_id: r.creator_tip_id,
    assigned_reviewer: r.assigned_reviewer || null,
    triggered_at_round: r.triggered_at_round,
    // BFT cert.timestamp ms at the moment PRESCAN_REVIEW_TRIGGERED applied.
    // Drives the reviewer-SLA auto-recuse trigger — same deterministic-
    // clock pattern as confirmed_at_ms below.
    triggered_at_ms: r.triggered_at_ms == null ? null : r.triggered_at_ms,
    state: r.state,
    decided_at_round: r.decided_at_round == null ? null : r.decided_at_round,
    confirmed_at_round: r.confirmed_at_round == null ? null : r.confirmed_at_round,
    // BFT cert.timestamp ms at the moment PRESCAN_REVIEW_CONFIRMED applied
    // — required for the h=R+24 auto-escalation trigger to compute the
    // 24h creator-decision window deterministically. Rounds alone can't
    // be converted to wall-clock without scanning commits; storing the
    // cert.ts at apply time is one column and read-cheap.
    confirmed_at_ms: r.confirmed_at_ms == null ? null : r.confirmed_at_ms,
    decision_note: r.decision_note || null,
    suggested_origin: r.suggested_origin || null,
  };
}

// Canonical projection for the `interests_registry` table — participates
// in state_merkle_root so two nodes that have applied the same tx
// sequence must agree byte-for-byte on the registry. registered_at +
// registered_by_vp_id + tx_id are CANONICAL: they're set deterministically
// at commit time (tx.timestamp + d.approving_vp_id + tx.tx_id) and
// included so a snapshot-installer's row matches the genesis-seeded /
// commit-applied row exactly. Genesis-seeded rows carry
// registered_by_vp_id=null + tx_id=null on every node.
function _canonInterest(r) {
  return {
    slug: r.slug,
    label: r.label,
    category: r.category,
    registered_at: r.registered_at,
    registered_by_vp_id: r.registered_by_vp_id || null,
    tx_id: r.tx_id || null,
  };
}

function _canonCommitteeRotation(r) {
  const committee = Array.isArray(r.committee)
    ? r.committee
    : JSON.parse(r.committee || "[]");
  const signer_node_ids = Array.isArray(r.signer_node_ids)
    ? r.signer_node_ids
    : JSON.parse(r.signer_node_ids || "[]");
  const signatures = Array.isArray(r.signatures)
    ? r.signatures
    : JSON.parse(r.signatures || "[]");
  return {
    rotation_number: r.rotation_number,
    effective_round: r.effective_round,
    committee,
    prev_rotation: r.prev_rotation == null ? null : r.prev_rotation,
    signer_node_ids,
    signatures,
    payload_hash: r.payload_hash || null,
  };
}

// Binary string comparator for every ordering that mirrors a SQLite ORDER BY.
// localeCompare is ICU-locale-dependent ('tip://…' vs 'US-…' flips order vs
// BINARY collation), so it would diverge from SQLiteStore AND across machines —
// fatal for iterateCanonicalState / state_merkle_root.
function cmpBin(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

// ══════════════════════════════════════════════════════════════════════════════
// IN-MEMORY STORE
// ══════════════════════════════════════════════════════════════════════════════
class MemoryStore {
  constructor() {
    this._txs = new Map();  // tx_id -> tx
    this._identities = new Map();  // tip_id -> record (no public_key — see entity_keys)
    this._content = new Map();  // ctid -> record
    this._scores = new Map();  // tip_id -> { score, offense_count, last_updated }
    this._dedup = new Set();  // dedup_hash strings (Poseidon field elements)
    this._revocations = new Map();  // tip_id -> { tip_id, tx_type, timestamp, tx_id }
    this._vps = new Map();  // vp_id -> record (no public_key — see entity_keys)
    this._nodes = new Map();  // node_id -> record (no public_key — see entity_keys)
    // GH #60 — single source of truth for public_key + algorithm of every
    // identity/node/VP across all time. Append-only with valid_from_ts /
    // valid_to_ts ranges (DID / X.509 / JWKS pattern). KEY_ROTATED /
    // KEY_RECOVERY close the active row and append a new one. Verification
    // dispatchers (commit-handler at consensus replay) walk this with
    // tx.timestamp to verify historical sigs; API-time verification uses
    // the active row (valid_to_ts IS NULL).
    //
    // Key: `${entity_type}:${entity_id}:${valid_from_ts}` so we can
    // efficiently iterate per-entity history. Sorted by valid_from_ts.
    this._entityKeys = new Map();
    this._certs = new Map();  // cert hash -> certificate
    this._commits = new Map();  // round -> commit checkpoint record (§15)
    this._committeeHistory = new Map();  // rotation_number -> rotation record (§4 + #34)
    this._interestsRegistry = new Map(); // slug -> {slug, label, category, registered_at, registered_by_vp_id, tx_id}
    this._rotationParticipation = new Map();  // `${node_id}|${rotation_number}` -> count (#75)
    this._prescanReviews = new Map();  // review_id -> review record (human reviewing AI prescan flag)
    this._mempool = new Map();  // tx_id -> tx
    this._txRejections = new Map();  // tx_id -> rejection record (no-loss invariant)
    this._disputeDetails = new Map();  // evidence_hash -> dispute details record (off-chain dispute body, NOT consensus state)
    this._prescanJobs = new Map();     // job_id -> prescan-job row (node-local async classifier queue, NOT consensus state)
    this._domainBindings = new Map();  // domain -> binding record (canonical, in state_merkle_root)
    // Off-DAG perceptual similarity index (advisory; NOT consensus state, NOT in
    // state_merkle_root). Source of truth + derived candidate indexes.
    this._perceptualFingerprints = new Map(); // `${ctid}|${component_idx}` -> fingerprint row
    this._minhashBands = [];                    // text LSH index rows
    this._phashCodes = [];                      // image/video MIH index rows
    this._audioClips = new Map();               // `${ctid}|${component_idx}` -> { clip_id, ctid, component_idx, landmark_count }
    this._audioClipById = new Map();            // clip_id -> the same clip row (matcher resolves clip_id -> ctid)
    this._audioClipSeq = 0;                     // surrogate clip_id allocator (§8.1)
    this._audioLandmarks = [];                  // audio inverted-index rows { profile, hash, clip_id, t }
    this._domainPending = new Map();  // domain -> pending claim record (local-only, NOT canonical)
    this._platformLinks = new Map(); // key: `${tip_id}::${platform}`
  }

  // ── Transactions ─────────────────────────────────────────────────────────
  // Stamp `subject_tip_id` on the row so MemoryStore.getTxsByTipId can
  // mirror SQLite's indexed-column lookup. The activity-feed broadening
  // (jurors, verifiers, etc.) is implemented in subjectTipId — this
  // keeps both stores in lockstep with one helper.
  saveTx(tx) { this._txs.set(tx.tx_id, { ...tx, subject_tip_id: subjectTipId(tx) }); }
  getTx(id) { return this._txs.get(id) || null; }
  getAllTxs() { return [...this._txs.values()]; }
  count() { return this._txs.size; }

  // §14/#49 snapshot full-history streaming. Ordered by tx_id so sender
  // + receiver hash rows in the same order → same txs_full_root. Mirrors
  // SQLiteStore.iterateAllTransactions for in-memory tests.
  *iterateAllTransactions() {
    for (const tx of [...this._txs.values()].sort((a, b) => cmpBin(a.tx_id, b.tx_id))) {
      yield tx;
    }
  }

  getTxsByType(type) {
    return [...this._txs.values()].filter(t => t.tx_type === type);
  }
  getTxsByTypeAndCtid(type, ctid) {
    return [...this._txs.values()].filter(t => t.tx_type === type && t.data?.ctid === ctid);
  }
  // Narrow OR-pattern lookup (scoring scope). Matches the canonical
  // tip-id field for each tx type: `tip_id` (REGISTER_IDENTITY, SCORE_UPDATE…),
  // `signer_tip_id` (REGISTER_CONTENT — CNA-2.2 canonical), or
  // `author_tip_id` (UPDATE_ORIGIN / CONTENT_RETRACTED / ADJUDICATION_RESULT).
  getTxsByTipId(tipId) {
    return [...this._txs.values()].filter(t =>
      t.data?.tip_id === tipId
      || t.data?.signer_tip_id === tipId
      || t.data?.author_tip_id === tipId
    );
  }
  // Broad role-aware lookup via the denormalised subject_tip_id column.
  // Mirrors SQLiteStore.getTxsBySubject — used by the activity feed.
  //
  // Returned order matches identity-service.getActivity's canonical sort
  // (strict reverse-chronological): timestamp DESC, SCORE_UPDATE-before-
  // anchor (side-effect is logically latest in the causal chain), tx_id
  // DESC. Single source of truth for activity-feed ordering.
  getTxsBySubject(tipId) {
    // #40 — match ANY party (recomputed live from tx data), so multi-party
    // disputes/appeals surface in both the author's and disputer's feed, not
    // just the actor's. No persisted multi-subject index to drift/backfill.
    return [...this._txs.values()]
      .filter(t => subjectTipIds(t).includes(tipId))
      .sort((a, b) => {
        // Coerce — guards against any DB driver that returns timestamps
        // as strings (PG's node-pg returns bigint as string by default).
        const d = Number(b.timestamp) - Number(a.timestamp);
        if (d !== 0) return d;
        const ap = a.tx_type === "SCORE_UPDATE" ? 0 : 1;
        const bp = b.tx_type === "SCORE_UPDATE" ? 0 : 1;
        if (ap !== bp) return ap - bp;
        return a.tx_id < b.tx_id ? 1 : -1;
      });
  }

  // ── Identities ────────────────────────────────────────────────────────────
  // GH #60: public_key + algorithm auto-route to entity_keys (DID-style
  // single source of truth). Callers can keep passing them on `rec` —
  // identities row stores everything else, entity_keys holds the active
  // (public_key, algorithm) pair indexed by (entity_type, entity_id,
  // valid_from_ts). `root_public_key` is dropped — never written by any
  // service, never read by any code path beyond the canonical projection.
  saveIdentity(rec) {
    if (rec.public_key) {
      this._saveActiveEntityKey({
        entity_type: "identity",
        entity_id: rec.tip_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.registered_at,
        source_tx_id: rec.tx_id || `genesis:${rec.tip_id}`,
      });
    }
    const { public_key, algorithm, root_public_key, ...rest } = rec;
    void public_key; void algorithm; void root_public_key;  // explicit drop
    this._identities.set(rec.tip_id, { ...rest });
  }
  getIdentity(id) {
    const row = this._identities.get(id);
    if (!row) return null;
    const key = this._getActiveEntityKey("identity", id);
    return key ? { ...row, public_key: key.public_key, algorithm: key.algorithm } : { ...row };
  }
  getAllIdentities() {
    return [...this._identities.values()].map(row => {
      const key = this._getActiveEntityKey("identity", row.tip_id);
      return key ? { ...row, public_key: key.public_key, algorithm: key.algorithm } : { ...row };
    });
  }

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
  // Explorer list — newest-first, cursor-paginated. Returns up to
  // limit+1 rows so the caller can detect "has more" without a count
  // query. Cursor is an exclusive (registered_at, ctid) tuple; the
  // composite tiebreak makes pagination stable when several rows share
  // a timestamp.
  listContent({ author = null, origin = null, status = null, hasMedia = null, limit = 20, cursor = null } = {}) {
    let rows = [...this._content.values()];
    if (author) rows = rows.filter(c => c.author_tip_id === author);
    if (origin) rows = rows.filter(c => c.origin_code === origin);
    if (status) rows = rows.filter(c => c.status === status);
    if (hasMedia === true) rows = rows.filter(c => Array.isArray(c.media) && c.media.length > 0);
    rows.sort((a, b) => (b.registered_at - a.registered_at) || (a.ctid < b.ctid ? 1 : -1));
    if (cursor) {
      rows = rows.filter(c =>
        c.registered_at < cursor.t
        || (c.registered_at === cursor.t && c.ctid < cursor.c));
    }
    return rows.slice(0, limit + 1);
  }
  // M6 retention sweep — parity with SqliteStore.getContentWithMediaBefore.
  getContentWithMediaBefore(cutoffMs) {
    return [...this._content.values()].filter(c =>
      typeof c.registered_at === "number"
      && c.registered_at < cutoffMs
      && Array.isArray(c.media)
      && c.media.length > 0
    );
  }
  // M6 — Map<media_id, reference_count> across every content row. See
  // SqliteStore.getReferencedMediaIds for the contract.
  getReferencedMediaIds() {
    const out = new Map();
    for (const c of this._content.values()) {
      if (!Array.isArray(c.media)) continue;
      for (const m of c.media) {
        if (m && typeof m.media_id === "string") {
          out.set(m.media_id, (out.get(m.media_id) || 0) + 1);
        }
      }
    }
    return out;
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
        const userTxs = txs.filter(t =>
          t.data?.tip_id === tipId
          || t.data?.signer_tip_id === tipId
          || t.data?.author_tip_id === tipId
        );
        // Spec (TIP_Scoring_v2 Reputation §): the bonus requires the user
        // to have registered ≥1 OH or AA content during the window. Any
        // other activity (a juror reveal, a SCORE_UPDATE, an inbound
        // dispute) does NOT qualify — that would let idle high-score users
        // farm the bonus by sitting on jury duty.
        // REGISTER_CONTENT uses signer_tip_id (CNA-2.2 canonical field).
        const hasOhAaContent = userTxs.some(t =>
          t.tx_type === "REGISTER_CONTENT"
          && t.data?.signer_tip_id === tipId
          && (t.data?.origin_code === "OH" || t.data?.origin_code === "AA")
          && t.timestamp >= cutoff,
        );
        if (!hasOhAaContent) return false;
        const hasUpheld = userTxs.some(t => t.tx_type === "ADJUDICATION_RESULT" && t.data?.verdict === "UPHELD" && t.timestamp >= cutoff);
        if (hasUpheld) return false;
        // Match `clean_record_bonus` with or without the window-id suffix.
        // The trigger emits `clean_record_bonus:YYYY-MM-DD` so the
        // (tip_id, ctid, reason) dedup at commit-handler scopes per
        // window; legacy un-suffixed bonuses still match for backward-compat.
        const hasBonus = userTxs.some(t => t.tx_type === "SCORE_UPDATE"
          && typeof t.data?.reason === "string"
          && t.data.reason.startsWith("clean_record_bonus")
          && t.timestamp >= cutoff);
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
  // dedup hash (derived from tx.timestamp). Deterministic — never nowMs().
  // `tipId` is denormalized so the FE/VP can resolve "this gov-id maps to which
  // tip_id" in one indexed read (used by /v1/identity/by-dedup-hash and to
  // surface tip_id on duplicate-registration 409s for the recovery pivot).
  addDedupHash(hash, createdAt, tipId) {
    if (createdAt == null) {
      throw new Error("addDedupHash: createdAt (from tx.timestamp) is required for deterministic state");
    }
    if (this._dedup.has(hash)) return;
    this._dedup.add(hash);
    if (!this._dedupCreated) this._dedupCreated = new Map();
    this._dedupCreated.set(hash, createdAt);
    if (!this._dedupTipId) this._dedupTipId = new Map();
    if (tipId) this._dedupTipId.set(hash, tipId);
  }
  hasDedupHash(hash) { return this._dedup.has(hash); }
  dedupCount() { return this._dedup.size; }
  getDedupRegistration(hash) {
    if (!this._dedup.has(hash)) return null;
    return {
      dedup_hash: hash,
      created_at: this._dedupCreated ? this._dedupCreated.get(hash) || null : null,
      tip_id: this._dedupTipId ? this._dedupTipId.get(hash) || null : null,
    };
  }

  // ── Revocations ───────────────────────────────────────────────────────────
  addRevocation(tipId, txType, timestamp, txId) {
    this._revocations.set(tipId, { tip_id: tipId, tx_type: txType, timestamp, tx_id: txId });
    const rec = this._identities.get(tipId);
    if (rec) this._identities.set(tipId, { ...rec, status: "revoked" });
  }
  isRevoked(tipId) { return this._revocations.has(tipId); }
  getRevocation(tipId) { return this._revocations.get(tipId) || null; }
  getRevocations(since) {
    const all = [...this._revocations.values()];
    return since ? all.filter(r => r.timestamp > since) : all;
  }

  // ── Domain bindings (org-only; canonical, in state_merkle_root) ──────────
  saveDomainBinding(rec) {
    this._domainBindings.set(rec.domain, { ...rec });
  }
  getDomainBinding(domain) {
    return this._domainBindings.get(domain) || null;
  }
  getDomainBindingsByTipId(tipId) {
    return [...this._domainBindings.values()].filter(b => b.tip_id === tipId);
  }
  getAllDomainBindings() {
    return [...this._domainBindings.values()];
  }

  // ── Platform links (canonical, in state_merkle_root) ─────────────────────
  savePlatformLink(rec) {
    this._platformLinks.set(rec.id, { ...rec });
  }
  updatePlatformLinkStatus(tipId, platform, update) {
    const key = `${tipId}::${platform}`;
    const existing = this._platformLinks.get(key);
    if (existing) this._platformLinks.set(key, { ...existing, ...update });
  }
  getPlatformLink(tipId, platform) {
    return this._platformLinks.get(`${tipId}::${platform}`) || null;
  }
  getPlatformLinksByTipId(tipId) {
    return [...this._platformLinks.values()].filter(r => r.tip_id === tipId);
  }

  // ── Domain pending claims (local-only; NOT canonical, NOT in merkle root) ─
  // Stores the user-signed claim between POST /register and POST /verify.
  // Only the receiving node has the claim — verification re-establishes
  // the chain of trust via the user's signature on the canonical payload,
  // so no cross-node replication is required.
  savePendingDomainClaim(rec) {
    this._domainPending.set(rec.domain, { ...rec });
  }
  getPendingDomainClaim(domain) {
    return this._domainPending.get(domain) || null;
  }
  deletePendingDomainClaim(domain) {
    return this._domainPending.delete(domain);
  }

  // ── Verification Providers ────────────────────────────────────────────────
  saveVP(rec) {
    if (rec.public_key) {
      this._saveActiveEntityKey({
        entity_type: "vp",
        entity_id: rec.vp_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.registered_at,
        source_tx_id: rec.tx_id || `genesis:${rec.vp_id}`,
      });
    }
    const { public_key, algorithm, ...rest } = rec;
    void public_key; void algorithm;
    this._vps.set(rec.vp_id, { ...rest });
  }
  getVP(vpId) {
    const row = this._vps.get(vpId);
    if (!row) return null;
    const key = this._getActiveEntityKey("vp", vpId);
    return key ? { ...row, public_key: key.public_key, algorithm: key.algorithm } : { ...row };
  }
  getAllVPs() {
    return [...this._vps.values()].map(row => {
      const key = this._getActiveEntityKey("vp", row.vp_id);
      return key ? { ...row, public_key: key.public_key, algorithm: key.algorithm } : { ...row };
    });
  }

  // ── Nodes ───────────────────────────────────────────────────────────────
  saveNode(rec) {
    if (rec.public_key) {
      this._saveActiveEntityKey({
        entity_type: "node",
        entity_id: rec.node_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.registered_at,
        source_tx_id: rec.tx_id || `genesis:${rec.node_id}`,
      });
    }
    const { public_key, algorithm, ...rest } = rec;
    void public_key; void algorithm;
    this._nodes.set(rec.node_id, { api_endpoint: null, ...rest });
  }
  updateNodeEndpoint(nodeId, apiEndpoint, timestamp) {
    const row = this._nodes.get(nodeId);
    if (row) this._nodes.set(nodeId, { ...row, api_endpoint: apiEndpoint || null, updated_at: timestamp ?? null });
  }
  getNode(nodeId) {
    const row = this._nodes.get(nodeId);
    if (!row) return null;
    const key = this._getActiveEntityKey("node", nodeId);
    return key ? { ...row, public_key: key.public_key, algorithm: key.algorithm } : { ...row };
  }
  getAllNodes() {
    return [...this._nodes.values()].map(row => {
      const key = this._getActiveEntityKey("node", row.node_id);
      return key ? { ...row, public_key: key.public_key, algorithm: key.algorithm } : { ...row };
    });
  }

  // ── entity_keys (GH #60) ─────────────────────────────────────────────────
  // Single source of truth for (public_key, algorithm) of every identity,
  // node, and VP across all time. Append-only with valid_from_ts /
  // valid_to_ts ranges. KEY_ROTATED / KEY_RECOVERY apply: close the
  // active row (set valid_to_ts) and append a new one (valid_from_ts =
  // effective_at).
  _entityKeyId(entity_type, entity_id, valid_from_ts) {
    return `${entity_type}:${entity_id}:${valid_from_ts}`;
  }
  _saveActiveEntityKey({ entity_type, entity_id, public_key, algorithm, valid_from_ts, source_tx_id }) {
    // Saving an "active" row: close any currently-active row for this
    // entity (set its valid_to_ts to the new row's valid_from_ts), then
    // insert the new active row with valid_to_ts = null.
    const prev = this._getActiveEntityKey(entity_type, entity_id);
    if (prev) {
      // Skip if the active key is already this key — regardless of valid_from_ts.
      // saveIdentity passes valid_from_ts = registered_at (original registration
      // time) but entity_keys are managed by saveEntityKey after the first write;
      // KEY_ROTATED / KEY_RECOVERY set valid_from_ts = effectiveAt which never
      // equals registered_at. Requiring valid_from_ts to match would cause
      // UPDATE_PROFILE commits to close the correctly-placed active row and
      // insert a duplicate at valid_from_ts=registered_at, corrupting the mirror
      // state that KEY_RECOVERY reads to find which row to close.
      if (prev.public_key === public_key && prev.algorithm === algorithm) {
        return;
      }
      const prevKey = this._entityKeyId(entity_type, entity_id, prev.valid_from_ts);
      this._entityKeys.set(prevKey, { ...prev, valid_to_ts: valid_from_ts });
    }
    const key = this._entityKeyId(entity_type, entity_id, valid_from_ts);
    this._entityKeys.set(key, {
      entity_type, entity_id, public_key, algorithm,
      valid_from_ts, valid_to_ts: null, source_tx_id,
    });
  }
  saveEntityKey(rec) {
    // Generalised save — accepts a fully-specified row including
    // valid_to_ts. Used by snapshot install + KEY_ROTATED/KEY_RECOVERY
    // direct-write paths where the caller has already computed both
    // valid_from_ts and valid_to_ts.
    const key = this._entityKeyId(rec.entity_type, rec.entity_id, rec.valid_from_ts);
    this._entityKeys.set(key, {
      entity_type: rec.entity_type,
      entity_id: rec.entity_id,
      public_key: rec.public_key,
      algorithm: rec.algorithm || "ml-dsa-65",
      valid_from_ts: rec.valid_from_ts,
      valid_to_ts: rec.valid_to_ts == null ? null : rec.valid_to_ts,
      source_tx_id: rec.source_tx_id,
    });
  }
  _getActiveEntityKey(entity_type, entity_id) {
    // Iterate entity's history; return the row with valid_to_ts === null.
    for (const r of this._entityKeys.values()) {
      if (r.entity_type === entity_type && r.entity_id === entity_id && r.valid_to_ts === null) {
        return r;
      }
    }
    return null;
  }
  getActiveKey(entity_type, entity_id) {
    const r = this._getActiveEntityKey(entity_type, entity_id);
    return r ? { public_key: r.public_key, algorithm: r.algorithm } : null;
  }
  getKeyValidAt(entity_type, entity_id, timestamp) {
    // Find the row with valid_from_ts <= timestamp < (valid_to_ts || +Inf).
    // If multiple match, the one with greatest valid_from_ts wins (most
    // recent rotation that was active at the given time).
    let best = null;
    for (const r of this._entityKeys.values()) {
      if (r.entity_type !== entity_type || r.entity_id !== entity_id) continue;
      if (r.valid_from_ts > timestamp) continue;
      if (r.valid_to_ts != null && r.valid_to_ts <= timestamp) continue;
      if (!best || r.valid_from_ts > best.valid_from_ts) best = r;
    }
    return best ? { public_key: best.public_key, algorithm: best.algorithm } : null;
  }
  // Full key chain for one entity, oldest first — the raw material a
  // client walks to verify rotations from the tip_id-anchored root key
  // to the key valid at any given tx timestamp.
  getEntityKeyHistory(entityType, entityId) {
    return [...this._entityKeys.values()]
      .filter(r => r.entity_type === entityType && r.entity_id === entityId)
      .sort((a, b) => a.valid_from_ts - b.valid_from_ts)
      .map(r => ({
        public_key: r.public_key,
        algorithm: r.algorithm,
        valid_from_ts: r.valid_from_ts,
        valid_to_ts: r.valid_to_ts ?? null,
        source_tx_id: r.source_tx_id ?? null,
      }));
  }
  *iterateEntityKeys() {
    // For snapshot serialisation + state_merkle_root canonicalisation.
    // Sort deterministically by (entity_type, entity_id, valid_from_ts).
    const all = [...this._entityKeys.values()].sort((a, b) => {
      if (a.entity_type !== b.entity_type) return a.entity_type < b.entity_type ? -1 : 1;
      if (a.entity_id !== b.entity_id) return a.entity_id < b.entity_id ? -1 : 1;
      return a.valid_from_ts - b.valid_from_ts;
    });
    for (const r of all) yield r;
  }
  clearEntityKeys() {
    this._entityKeys.clear();
  }

  clearCanonicalState() {
    this._identities.clear();
    this._content.clear();
    this._scores.clear();
    this._dedup.clear();
    if (this._dedupCreated) this._dedupCreated.clear();
    // _dedupTipId survives addDedupHash with a falsy tipId, so a stale
    // mapping here resurfaces in canonical dedup rows after reinstall.
    if (this._dedupTipId) this._dedupTipId.clear();
    this._revocations.clear();
    this._vps.clear();
    this._nodes.clear();
    // GH #60 — entity_keys is canonical state too.
    this._entityKeys.clear();
    this._platformLinks.clear();
    // Every table that iterateCanonicalState yields MUST be cleared here,
    // otherwise leftover rows survive a snapshot install and contribute to
    // state_merkle_root → permanent Merkle divergence vs the snapshot author.
    this._domainBindings.clear();
    this._prescanReviews.clear();
    this._interestsRegistry.clear();
  }

  // ── Certificates (Narwhal consensus) ──────────────────────────────────
  saveCertificate(cert) { this._certs.set(cert.hash, { ...cert }); }
  getCertificate(hash) { return this._certs.get(hash) || null; }
  getCertificatesByRound(round) {
    return [...this._certs.values()]
      .filter(c => c.round === round)
      .sort((a, b) => cmpBin(a.author_node_id, b.author_node_id));
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
      .sort((a, b) => a.round !== b.round ? a.round - b.round : cmpBin(a.author_node_id, b.author_node_id));
  }
  // §69 — bounded iterator over certs in [fromRound, toRound] inclusive.
  // Yields in canonical (round, author_node_id) order — same as
  // SQLiteStore. Used by snapshot-handler to ship the K-round cert window
  // a joiner needs for runtime committee derivation.
  *iterateCertsByRoundRange(fromRound, toRound) {
    const sorted = [...this._certs.values()]
      .filter(c => c.round >= fromRound && c.round <= toRound)
      .sort((a, b) => a.round !== b.round
        ? a.round - b.round
        : cmpBin(a.author_node_id, b.author_node_id));
    for (const c of sorted) yield c;
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

  // ── Committee history (§4 + #34 — chain-of-trust) ────────────────────────
  // One row per committee rotation. Rotation 0 is bootstrapped at initDAG
  // from genesis.founding_node (no sigs — hardcoded trust anchor). Every
  // subsequent rotation requires 2f+1 sigs from the PREVIOUS committee.
  // Snapshot fast-sync ships these rows in their own stream + root; the
  // joiner walks the chain forward verifying each transition.
  saveCommitteeRotation(rec) {
    // Overwrite-on-conflict: mirrors SQLite's INSERT OR REPLACE so a
    // snapshot install carrying an authoritative rotation row overwrites
    // any prior local divergent row by (rotation_number) PK. Re-applying
    // the same row is still idempotent (all columns re-set to identical
    // canonical values).
    this._committeeHistory.set(rec.rotation_number, {
      rotation_number: rec.rotation_number,
      effective_round: rec.effective_round,
      committee: [...(rec.committee || [])],
      prev_rotation: rec.prev_rotation == null ? null : rec.prev_rotation,
      signer_node_ids: [...(rec.signer_node_ids || [])],
      signatures: [...(rec.signatures || [])],
      payload_hash: rec.payload_hash || null,
      committed_at: rec.committed_at || nowMs(),
    });
  }
  getCommitteeRotation(rotationNumber) {
    const rec = this._committeeHistory.get(rotationNumber);
    return rec ? { ...rec, committee: [...rec.committee], signer_node_ids: [...rec.signer_node_ids], signatures: [...rec.signatures] } : null;
  }
  getLatestRotation() {
    let latest = null;
    for (const r of this._committeeHistory.values()) {
      if (!latest || r.rotation_number > latest.rotation_number) latest = r;
    }
    return latest ? { ...latest, committee: [...latest.committee], signer_node_ids: [...latest.signer_node_ids], signatures: [...latest.signatures] } : null;
  }
  // Returns the committee in effect at the given round: latest rotation
  // whose effective_round <= round. If round predates rotation 0 (impossible
  // in practice once initDAG bootstraps), returns null.
  getCommitteeAtRound(round) {
    let best = null;
    for (const r of this._committeeHistory.values()) {
      if (r.effective_round > round) continue;
      if (!best || r.rotation_number > best.rotation_number) best = r;
    }
    return best ? { ...best, committee: [...best.committee], signer_node_ids: [...best.signer_node_ids], signatures: [...best.signatures] } : null;
  }
  // Streaming iterator over the entire chain in rotation_number order.
  // Used by snapshot sender (ship every rotation) and chain-of-trust walker.
  *getRotationsFromGenesis() {
    const sorted = [...this._committeeHistory.values()].sort((a, b) => a.rotation_number - b.rotation_number);
    for (const r of sorted) {
      yield { ...r, committee: [...r.committee], signer_node_ids: [...r.signer_node_ids], signatures: [...r.signatures] };
    }
  }

  // ── Interests registry ─────────────────────────────────────────────────
  // Curated vocabulary of interest slugs the user can pick from on their
  // profile. Genesis seeds the initial taxonomy from INITIAL_INTERESTS_SEED;
  // INTEREST_REGISTERED txs extend it at runtime. Slug is PK; overwrite-
  // on-conflict semantics match interests_registry's UPSERT pattern (same
  // shape as committee_history — peer-authoritative install wins).
  saveInterest(rec) {
    this._interestsRegistry.set(rec.slug, {
      slug: rec.slug,
      label: rec.label,
      category: rec.category,
      registered_at: rec.registered_at,
      registered_by_vp_id: rec.registered_by_vp_id || null,
      tx_id: rec.tx_id || null,
    });
  }
  getInterest(slug) {
    const r = this._interestsRegistry.get(slug);
    return r ? { ...r } : null;
  }
  // Full registry — used by GET /v1/interests and by UPDATE_PROFILE
  // validation to check that every user-picked slug exists.
  getAllInterests() {
    return [...this._interestsRegistry.values()]
      .sort((a, b) => cmpBin(a.slug, b.slug))
      .map(r => ({ ...r }));
  }
  interestCount() { return this._interestsRegistry.size; }

  // ── Prescan reviews ─────────────────────────────────────────────────
  // INSERT OR REPLACE semantics — the same review_id walks through its
  // state machine (triggered → confirmed → closed_accepted_private etc.)
  // via successive saves. Caller normalizes all preserved fields each
  // call (no partial-update semantics here).
  savePrescanReview(rec) {
    this._prescanReviews.set(rec.review_id, {
      review_id: rec.review_id,
      ctid: rec.ctid,
      creator_tip_id: rec.creator_tip_id,
      assigned_reviewer: rec.assigned_reviewer || null,
      triggered_at_round: rec.triggered_at_round,
      triggered_at_ms: rec.triggered_at_ms == null ? null : rec.triggered_at_ms,
      decided_at_round: rec.decided_at_round == null ? null : rec.decided_at_round,
      confirmed_at_round: rec.confirmed_at_round == null ? null : rec.confirmed_at_round,
      confirmed_at_ms: rec.confirmed_at_ms == null ? null : rec.confirmed_at_ms,
      state: rec.state || PRESCAN_REVIEW_STATES.TRIGGERED,
      decision_note: rec.decision_note || null,
      suggested_origin: rec.suggested_origin || null,
    });
  }
  getPrescanReview(reviewId) {
    const rec = this._prescanReviews.get(reviewId);
    return rec ? { ...rec } : null;
  }
  // Only one open review per CTID at a time — TRIGGERED OR CONFIRMED
  // (creator-decision window). Closed states are terminal.
  getOpenPrescanReviewByCtid(ctid) {
    let best = null;
    for (const r of this._prescanReviews.values()) {
      if (r.ctid !== ctid) continue;
      if (r.state !== PRESCAN_REVIEW_STATES.TRIGGERED
        && r.state !== PRESCAN_REVIEW_STATES.CONFIRMED) continue;
      if (!best || r.triggered_at_round > best.triggered_at_round) best = r;
    }
    return best ? { ...best } : null;
  }
  getPrescanReviewsByReviewer(reviewerTipId) {
    return [...this._prescanReviews.values()]
      .filter(r => r.assigned_reviewer === reviewerTipId)
      .sort((a, b) => b.triggered_at_round - a.triggered_at_round)
      .map(r => ({ ...r }));
  }
  getPrescanReviewsByCtid(ctid) {
    return [...this._prescanReviews.values()]
      .filter(r => r.ctid === ctid)
      .sort((a, b) => b.triggered_at_round - a.triggered_at_round)
      .map(r => ({ ...r }));
  }
  // Phase 2.5 trigger queries. Mirror the SQLite predicates in JS so the
  // memory-store path produces the same candidate set.
  //
  // Re-trigger gate: skip any ctid that already has a non-recused
  // prior review. The earlier predicate only looked for TRIGGERED /
  // CONFIRMED (open states) — that let CLOSED_* + ESCALATED_TO_DISPUTE
  // through, causing the trigger to fire again on every round after a
  // DISMISS/accept/etc., spawning a fresh reviewer + extra +5 bonus
  // every round. RECUSED is the only terminal state that intentionally
  // re-triggers (we need a new reviewer to take the case).
  getContentsNeedingReview(nowMs) {
    const cutoff = nowMs - CONTENT_GRACE.FLAGGED_MS;
    const out = [];
    for (const c of this._content.values()) {
      if (c.status !== "registered") continue;
      if (c.origin_code !== "OH") continue;
      // Async-prescan gates: only act on completed, non-degraded verdicts.
      // PENDING_PRESCAN rows wait; degraded verdicts get the
      // unflagged-content treatment downstream.
      if ((c.prescan_status || "completed") !== "completed") continue;
      if (c.prescan_overall_degraded) continue;
      if (c.prescan_tier !== "high" && c.prescan_tier !== "critical") continue;
      // Strict anchor: require prescan_completed_at. Falling back to
      // registered_at would silently grandfather data bugs (status
      // marked completed without a verdict time) and fire prematurely.
      // Legacy pre-async rows are excluded by design.
      const anchorMs = c.prescan_completed_at;
      if (!Number.isFinite(anchorMs) || anchorMs > cutoff) continue;
      const prior = [...this._prescanReviews.values()].filter(r =>
        r.ctid === c.ctid && r.state !== PRESCAN_REVIEW_STATES.RECUSED);
      if (prior.length > 0) continue;
      out.push({ ...c });
    }
    return out;
  }

  // Content rows still stuck in prescan_status='pending' past the
  // fail-open deadline. Surfaces the rows where the failover trigger
  // should emit a fail-open PRESCAN_COMPLETED so content can't get
  // stuck in PENDING_PRESCAN forever (API node dead, worker dead,
  // classifier permanently unreachable, etc.). Anchor is
  // registered_at — that's when the clock starts for "should have
  // had a verdict by now."
  getContentsStuckInPrescan(failOpenCutoffMs) {
    const out = [];
    for (const c of this._content.values()) {
      if (c.prescan_status !== "pending") continue;
      if (!Number.isFinite(c.registered_at)) continue;
      if (c.registered_at > failOpenCutoffMs) continue;
      out.push({ ...c });
    }
    return out;
  }
  getReviewsNeedingAutoEscalation(nowMs) {
    const cutoff = nowMs - REVIEWER.CREATOR_DECISION_WINDOW_MS;
    return [...this._prescanReviews.values()]
      .filter(r => r.state === PRESCAN_REVIEW_STATES.CONFIRMED
        && r.confirmed_at_ms != null
        && r.confirmed_at_ms <= cutoff)
      .sort((a, b) => a.confirmed_at_ms - b.confirmed_at_ms)
      .map(r => ({ ...r }));
  }
  getReviewsNeedingAutoRecuse(nowMs) {
    const cutoff = nowMs - REVIEWER.AUTO_RECUSE_AGE_MS;
    return [...this._prescanReviews.values()]
      .filter(r => r.state === PRESCAN_REVIEW_STATES.TRIGGERED
        && r.triggered_at_ms != null
        && r.triggered_at_ms <= cutoff)
      .sort((a, b) => a.triggered_at_ms - b.triggered_at_ms)
      .map(r => ({ ...r }));
  }

  // ── #75 rotation_participation accessors ─────────────────────────────
  // Counter per (node_id, rotation_number). Incremented on every Bullshark
  // anchor commit by bullshark.js (one increment for the leader, one per
  // ack-signer). Read at rotation boundary to compute next rotation's
  // committee. See table comment in CREATE TABLE for full semantics.
  incrementRotationParticipation(nodeId, rotationNumber) {
    const key = `${nodeId}|${rotationNumber}`;
    const current = this._rotationParticipation.get(key) || 0;
    this._rotationParticipation.set(key, current + 1);
  }
  getRotationParticipation(rotationNumber) {
    const out = [];
    const suffix = `|${rotationNumber}`;
    for (const [key, count] of this._rotationParticipation) {
      if (key.endsWith(suffix)) {
        const node_id = key.slice(0, -suffix.length);
        out.push({ node_id, count });
      }
    }
    return out;
  }
  pruneRotationParticipationBefore(rotationNumber) {
    let removed = 0;
    for (const key of this._rotationParticipation.keys()) {
      const idx = key.lastIndexOf("|");
      const r = Number(key.slice(idx + 1));
      if (r < rotationNumber) {
        this._rotationParticipation.delete(key);
        removed++;
      }
    }
    return removed;
  }
  // Idempotent absolute-set (NOT increment) — used by snapshot install to
  // overwrite the local count with the snapshot's authoritative value.
  // Re-running with the same args is a no-op; calling with a different count
  // replaces. Required because snapshot ships RP rows directly (not deltas).
  setRotationParticipation(nodeId, rotationNumber, count) {
    const key = `${nodeId}|${rotationNumber}`;
    this._rotationParticipation.set(key, count);
  }
  // Wipe all rows for a single rotation. Used by snapshot install BEFORE
  // applying the snapshot's RP rows for that rotation, so absent rows in
  // the snapshot become absent locally too. Without this, a stale local row
  // for (node_id, rotation) where the snapshot has no entry for that key
  // would leak past install and produce wrong tallies on the joiner.
  deleteRotationParticipationByRotation(rotationNumber) {
    let removed = 0;
    const suffix = `|${rotationNumber}`;
    for (const key of [...this._rotationParticipation.keys()]) {
      if (key.endsWith(suffix)) {
        this._rotationParticipation.delete(key);
        removed++;
      }
    }
    return removed;
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
      .sort((a, b) => cmpBin(a.tip_id, b.tip_id))) {
      yield { table: "identities", row: _canonIdentity(r) };
    }
    for (const r of [...this._content.values()]
      .sort((a, b) => cmpBin(a.ctid, b.ctid))) {
      yield { table: "content", row: _canonContent(r) };
    }
    for (const [tip_id, v] of [...this._scores.entries()]
      .sort((a, b) => cmpBin(a[0], b[0]))) {
      yield { table: "scores", row: _canonScore(tip_id, v) };
    }
    for (const h of [...this._dedup].sort()) {
      const createdAt = this._dedupCreated ? this._dedupCreated.get(h) : null;
      const tipId = this._dedupTipId ? this._dedupTipId.get(h) : null;
      yield { table: "dedup_registry", row: _canonDedup(h, createdAt, tipId) };
    }
    for (const r of [...this._revocations.values()]
      .sort((a, b) => cmpBin(a.tip_id, b.tip_id))) {
      yield { table: "revocations", row: _canonRevocation(r) };
    }
    for (const r of [...this._domainBindings.values()]
      .sort((a, b) => cmpBin(a.domain, b.domain))) {
      yield { table: "domain_bindings", row: _canonDomainBinding(r) };
    }
    for (const r of [...this._platformLinks.values()]
      .sort((a, b) => cmpBin(a.id, b.id))) {
      yield { table: "platform_links", row: _canonPlatformLink(r) };
    }
    for (const r of [...this._vps.values()]
      .sort((a, b) => cmpBin(a.vp_id, b.vp_id))) {
      yield { table: "verification_providers", row: _canonVP(r) };
    }
    for (const r of [...this._nodes.values()]
      .sort((a, b) => cmpBin(a.node_id, b.node_id))) {
      yield { table: "nodes", row: _canonNode(r) };
    }
    // GH #60 — entity_keys participates in state_merkle_root so the
    // federation agrees byte-for-byte on every identity/node/VP's key
    // history across all time. iterateEntityKeys yields rows sorted by
    // (entity_type, entity_id, valid_from_ts).
    for (const r of this.iterateEntityKeys()) {
      yield { table: "entity_keys", row: _canonEntityKey(r) };
    }
    for (const r of [...this._prescanReviews.values()]
      .sort((a, b) => cmpBin(a.review_id, b.review_id))) {
      yield { table: "prescan_reviews", row: _canonPrescanReview(r) };
    }
    for (const r of [...this._interestsRegistry.values()]
      .sort((a, b) => cmpBin(a.slug, b.slug))) {
      yield { table: "interests_registry", row: _canonInterest(r) };
    }
    // #75 rotation_participation is INTENTIONALLY excluded from state_merkle_root.
    // RP is real-time counter state that flickers as anchor walks process certs;
    // two nodes can have slightly different RP at the moment of commit (one
    // imported a cert the other hasn't yet). Including RP here would cause
    // state_merkle_root divergence between honest peers that converge later.
    // RP is shipped in its own snapshot stream (same pattern as committee_history
    // rotations) — see iterateRotationParticipationForSnapshot below.
  }

  // RP-snapshot iterator — separate from iterateCanonicalState because RP is
  // operational metadata that converges asynchronously, not consensus-stable
  // state. Sorted by (rotation_number, node_id) so the order matches the
  // SQLite iteration via PK index. Consumed by snapshot-handler Phase F.
  *iterateRotationParticipationForSnapshot() {
    const rpRows = [];
    for (const [key, count] of this._rotationParticipation) {
      const idx = key.lastIndexOf("|");
      rpRows.push({
        node_id: key.slice(0, idx),
        rotation_number: Number(key.slice(idx + 1)),
        count,
      });
    }
    rpRows.sort((a, b) => {
      if (a.rotation_number !== b.rotation_number) return a.rotation_number - b.rotation_number;
      return cmpBin(a.node_id, b.node_id);
    });
    for (const r of rpRows) {
      yield _canonRotationParticipation(r);
    }
  }

  // ── Transactions (DB-level) ────────────────────────────────────────────
  runInTransaction(fn) { return fn(); } // no-op wrapper for in-memory store

  // ── Persistent Mempool ────────────────────────────────────────────────
  // Stamp subject_tip_id on the entry alongside the tx so getMempoolTxsByTipId
  // can do the same indexed-column lookup as SQLiteStore.
  saveMempoolTx(tx) {
    this._mempool.set(tx.tx_id, { tx, subject_tip_id: subjectTipId(tx) });
  }
  getMempoolTx(txId) {
    const e = this._mempool.get(txId);
    return e ? e.tx : null;
  }
  getMempoolTxs() { return [...this._mempool.values()].map(e => e.tx); }
  getMempoolTxsByTipId(tipId) {
    return [...this._mempool.values()]
      .filter(e => subjectTipIds(e.tx).includes(tipId))   // #40 — any party
      .map(e => e.tx);
  }
  deleteMempoolTx(txId) { this._mempool.delete(txId); }
  deleteMempoolTxs(txIds) { for (const id of txIds) this._mempool.delete(id); }
  clearStaleMempoolTxs() { /* no-op for in-memory tests */ }
  mempoolCount() { return this._mempool.size; }

  // ── Tx Rejections (#64 follow-up: no-loss invariant) ──────────────────
  // Per-node observation log for txs that were admitted past the API but
  // never made it into dag.txs. First observation wins (idempotent on
  // tx_id) — peer re-broadcast of an already-rejected tx is a no-op.
  // NOT consensus state: each node's drop sites observe their own POV,
  // so this table intentionally diverges across nodes. Excluded from
  // iterateCanonicalState / state_merkle_root.
  saveTxRejection(rec) {
    if (this._txRejections.has(rec.tx_id)) return false;
    // tx_data is held as a JSON string, mirroring SQLite's TEXT column.
    // Reads parse it back on the way out — same pipeline both stores.
    const txData = rec.tx_data == null
      ? null
      : (typeof rec.tx_data === "string" ? rec.tx_data : JSON.stringify(rec.tx_data));
    // subject_tip_id from the tx body (when given), so getTxRejectionsByTipId
    // can mirror SQLiteStore's indexed-column lookup.
    const subj = rec.tx_data && typeof rec.tx_data === "object"
      ? subjectTipId(rec.tx_data)
      : null;
    this._txRejections.set(rec.tx_id, {
      tx_id: rec.tx_id,
      reason: rec.reason,
      reason_detail: rec.reason_detail || null,
      rejected_at_ms: rec.rejected_at_ms != null ? rec.rejected_at_ms : nowMs(),
      rejected_at_round: rec.rejected_at_round != null ? rec.rejected_at_round : null,
      dropper_node_id: rec.dropper_node_id,
      tx_type: rec.tx_type || null,
      origin_node_id: rec.origin_node_id || null,
      tx_data: txData,
      subject_tip_id: subj,
    });
    return true;
  }
  _parseRejectionRow(row) {
    if (!row) return null;
    return { ...row, tx_data: row.tx_data ? JSON.parse(row.tx_data) : null };
  }
  getTxRejection(txId) {
    return this._parseRejectionRow(this._txRejections.get(txId));
  }
  getTxRejectionsByReason(reason, opts = {}) {
    const since = opts.since != null ? opts.since : 0;
    const limit = opts.limit != null ? opts.limit : Infinity;
    const rows = [];
    for (const r of this._txRejections.values()) {
      if (r.reason !== reason) continue;
      if (r.rejected_at_ms < since) continue;
      rows.push(r);
    }
    rows.sort((a, b) => b.rejected_at_ms - a.rejected_at_ms);
    return rows.slice(0, limit).map(r => this._parseRejectionRow(r));
  }
  getTxRejectionsByTipId(tipId) {
    const rows = [];
    for (const r of this._txRejections.values()) {
      // #40 — recompute all parties from the preserved tx body (any party
      // match). Rejections without a body can't be attributed (same as before).
      const tx = r.tx_data ? JSON.parse(r.tx_data) : null;
      if (tx && subjectTipIds(tx).includes(tipId)) rows.push(r);
    }
    rows.sort((a, b) => b.rejected_at_ms - a.rejected_at_ms);
    return rows.map(r => this._parseRejectionRow(r));
  }
  countTxRejections() { return this._txRejections.size; }

  // ── Dispute details (off-chain dispute body) ──────────────────────────
  // Holds the disputer-submitted description + structured evidence array
  // bound by `evidence_hash` to a CONTENT_DISPUTED tx. NOT consensus state:
  // each node stores what it accepted-as-uploader or fetched-from-peers.
  // Excluded from iterateCanonicalState / state_merkle_root.
  saveDisputeDetails(rec) {
    if (this._disputeDetails.has(rec.evidence_hash)) return false;
    this._disputeDetails.set(rec.evidence_hash, {
      evidence_hash: rec.evidence_hash,
      disputer_tip_id: rec.disputer_tip_id,
      payload_json: rec.payload_json,
      signature: rec.signature,
      local_inserted_at: rec.local_inserted_at,
    });
    return true;
  }
  getDisputeDetails(hash) {
    return this._disputeDetails.get(hash) || null;
  }
  hasDisputeDetails(hash) {
    return this._disputeDetails.has(hash);
  }
  deleteDisputeDetails(hash) {
    return this._disputeDetails.delete(hash);
  }

  // ── Prescan jobs (node-local async classifier queue) ────────────────────
  // Worker queue. Per-node — NOT in state_merkle_root. Same pattern as
  // dispute_details: each node stores what it received locally. See
  // my-notes/ASYNC_PRESCAN_ARCHITECTURE.md § Worker process.
  enqueuePrescanJob(rec) {
    if (this._prescanJobs.has(rec.job_id)) return false;
    this._prescanJobs.set(rec.job_id, {
      job_id: rec.job_id,
      ctid: rec.ctid,
      payload: rec.payload,
      status: rec.status || "queued",
      claimed_at: null,
      claimed_by: null,
      retries: 0,
      last_error: null,
      created_at: rec.created_at,
      completed_at: null,
    });
    return true;
  }
  // ── Perceptual index writes (off-DAG, advisory; not mirrored elsewhere) ────
  savePerceptualFingerprint(rec) {
    this._perceptualFingerprints.set(`${rec.ctid}|${rec.component_idx}`, { ...rec });
  }
  saveMinhashBands(rows) {
    for (const r of rows) this._minhashBands.push({ ...r });
  }
  savePhashCodes(rows) {
    if (!rows || !rows.length) return;
    // Skip rows already present by (ctid, component_idx, frame): mirrors the
    // SQLite/Knex INSERT OR IGNORE so a re-ingest cannot duplicate frames.
    const have = new Set(this._phashCodes.map((c) => `${c.ctid}|${c.component_idx}|${c.frame}`));
    for (const r of rows) {
      const key = `${r.ctid}|${r.component_idx}|${r.frame}`;
      if (have.has(key)) continue;
      have.add(key);
      this._phashCodes.push({ ...r });
    }
  }
  getPerceptualFingerprint(ctid, componentIdx = 0) {
    return this._perceptualFingerprints.get(`${ctid}|${componentIdx}`) || null;
  }
  // LSH candidate-gen: ctids that share >= 1 band bucket with the query's bands.
  findMinhashCandidates(profile, bandHashes) {
    const want = new Set(bandHashes.map((h, i) => i + "|" + h));
    const ctids = new Set();
    for (const b of this._minhashBands) {
      if (b.profile === profile && want.has(b.band_idx + "|" + b.band_hash)) ctids.add(b.ctid);
    }
    return [...ctids];
  }
  // MIH candidate-gen: codes sharing >= 1 chunk value with the query's per-chunk
  // Hamming-1 neighborhoods (queryKeys = [[17 keys] x 16]).
  findPhashCandidates(profile, modality, queryKeys) {
    const sets = queryKeys.map((keys) => new Set(keys));
    const out = [];
    for (const c of this._phashCodes) {
      if (c.profile !== profile || c.modality !== modality) continue;
      for (let i = 0; i < 16; i++) {
        if (sets[i].has(c["c" + i])) { out.push(c); break; }
      }
    }
    return out;
  }
  // All phash codes for a ctid (a video's full frame set, for the overlap score).
  getPhashCodesByCtid(ctid) {
    return this._phashCodes.filter((c) => c.ctid === ctid);
  }
  // Audio (§8.1): a clip gets a surrogate clip_id its landmarks point at; the FULL
  // landmark_count (scoreRatio denom) is kept even when only a subset is indexed.
  getOrCreateAudioClip(ctid, componentIdx, landmarkCount) {
    const key = `${ctid}|${componentIdx}`;
    let clip = this._audioClips.get(key);
    if (clip) {
      clip.landmark_count = landmarkCount;
    } else {
      clip = { clip_id: ++this._audioClipSeq, ctid, component_idx: componentIdx, landmark_count: landmarkCount };
      this._audioClips.set(key, clip);
      this._audioClipById.set(clip.clip_id, clip);
    }
    return clip.clip_id;
  }
  saveAudioLandmarks(rows) {
    for (const r of rows) this._audioLandmarks.push({ ...r });
  }
  // Inverted-index candidate-gen: landmark rows whose hash is one the query carries.
  findAudioCandidates(profile, hashes) {
    const want = new Set(hashes);
    const out = [];
    for (const l of this._audioLandmarks) {
      if (l.profile === profile && want.has(l.hash)) out.push(l);
    }
    return out;
  }
  getAudioClip(clipId) {
    return this._audioClipById.get(clipId) || null;
  }
  getPrescanJob(jobId) {
    return this._prescanJobs.get(jobId) || null;
  }
  getPrescanJobByCtid(ctid) {
    for (const row of this._prescanJobs.values()) {
      if (row.ctid === ctid) return row;
    }
    return null;
  }
  // Atomic claim: prefer queued jobs (oldest first), then recover stuck
  // claimed jobs whose claimed_at is past the timeout. Returns the
  // claimed row or null if no work is available.
  claimPrescanJob({ workerId, now, claimTimeoutMs }) {
    const queued = [];
    const stuck = [];
    for (const row of this._prescanJobs.values()) {
      if (row.status === "queued") queued.push(row);
      else if (row.status === "claimed" && row.claimed_at < now - claimTimeoutMs) stuck.push(row);
    }
    queued.sort((a, b) => a.created_at - b.created_at);
    stuck.sort((a, b) => a.created_at - b.created_at);
    const next = queued[0] || stuck[0] || null;
    if (!next) return null;
    next.status = "claimed";
    next.claimed_at = now;
    next.claimed_by = workerId;
    return { ...next };
  }
  markPrescanJobDone(jobId, { completedAt }) {
    const row = this._prescanJobs.get(jobId);
    if (!row) return false;
    row.status = "done";
    row.completed_at = completedAt;
    row.last_error = null;
    return true;
  }
  markPrescanJobFailed(jobId, { lastError, completedAt }) {
    const row = this._prescanJobs.get(jobId);
    if (!row) return false;
    row.status = "failed";
    row.last_error = lastError || null;
    row.completed_at = completedAt;
    return true;
  }
  releasePrescanJobForRetry(jobId, { lastError }) {
    const row = this._prescanJobs.get(jobId);
    if (!row) return false;
    row.status = "queued";
    row.claimed_at = null;
    row.claimed_by = null;
    row.last_error = lastError || null;
    row.retries = (row.retries || 0) + 1;
    return true;
  }

  // No-op for parity with SQLiteStore.backfillSubjectTipId. MemoryStore
  // writes always populate the column at save time; nothing to retrofit.
  backfillSubjectTipId(_subjectTipId) {
    return { transactions: 0, mempool: 0, tx_rejections: 0 };
  }

  // No-op on the in-memory mirror: writes are synchronous, no chain to drain.
  // Matches the knex-adapter's `flush()` contract so the facade can call it
  // uniformly across all stores during shutdown.
  async flush() { /* no-op */ }
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
    // Base schema is the generated lockfile src/db/schema.sql (produced from
    // the Knex baseline migration by "npm run gen:schema"). The migration is
    // the single authored schema; this synchronous path execs that generated
    // SQL. Statements are CREATE ... IF NOT EXISTS, so it stays idempotent
    // after the Knex migration has already built the tables on a file-SQLite
    // node. Kept in lockstep with the migration by
    // tests/db/migration-baseline-schema.test.js. The conditional ALTERs below
    // upgrade pre-existing DBs whose CREATE TABLE predates a column (a
    // CREATE TABLE IF NOT EXISTS no-ops on an already-existing table).
    this.db.exec(fs.readFileSync(path.join(__dirname, "db", "schema.sql"), "utf8"));

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

    // Activity-feed denormalisation: backfill `subject_tip_id` on the
    // three tables that participate in the activity merge (committed +
    // pending + rejected). Two-phase migration:
    //   1. ALTER TABLE adds the column to existing schemas (no-op when
    //      the column already exists, e.g. fresh DBs whose CREATE TABLE
    //      defined it directly).
    //   2. CREATE INDEX runs unconditionally afterwards. Idempotent via
    //      IF NOT EXISTS, and deliberately not in the main exec block —
    //      placing it there fails on existing DBs because the column
    //      doesn't exist yet at CREATE TABLE IF NOT EXISTS time, which
    //      throws and cascades to the in-memory fallback (live-observed:
    //      node 2 lost its persisted state on first restart with this
    //      migration). Backfill values is deferred to
    //      `backfillSubjectTipId()` so it short-circuits when nothing
    //      needs filling.
    const txCols = this.db.prepare("PRAGMA table_info(transactions)").all().map(c => c.name);
    if (!txCols.includes("subject_tip_id")) {
      this.db.exec("ALTER TABLE transactions ADD COLUMN subject_tip_id TEXT");
    }
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_txs_subject ON transactions(subject_tip_id)");

    const mempoolCols = this.db.prepare("PRAGMA table_info(mempool)").all().map(c => c.name);
    if (!mempoolCols.includes("subject_tip_id")) {
      this.db.exec("ALTER TABLE mempool ADD COLUMN subject_tip_id TEXT");
    }
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_mempool_subject ON mempool(subject_tip_id)");

    const rejCols = this.db.prepare("PRAGMA table_info(tx_rejections)").all().map(c => c.name);
    if (!rejCols.includes("subject_tip_id")) {
      this.db.exec("ALTER TABLE tx_rejections ADD COLUMN subject_tip_id TEXT");
    }
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_tx_rej_subject ON tx_rejections(subject_tip_id)");
  }


  /**
   * Populate `subject_tip_id` on existing rows that pre-date the column.
   * Idempotent: WHERE subject_tip_id IS NULL skips already-backfilled
   * rows, so calling this on every startup costs ~O(remaining unbackfilled)
   * not O(total). Once the table is fully backfilled the WHERE clause
   * matches zero rows and the function returns immediately.
   *
   * Called from initDAG after the store is constructed so the helper
   * (`subjectTipId`) and store are both ready.
   *
   * @param {Function} subjectTipId  (tx) => tip_id|null
   * @returns {{ transactions: number, mempool: number, tx_rejections: number }}
   */
  backfillSubjectTipId(subjectTipId) {
    const result = { transactions: 0, mempool: 0, tx_rejections: 0 };

    // ── transactions ────────────────────────────────────────────────────
    // Iterate only rows whose column is still NULL (cheap after first run).
    // Rebuild the tx shape from the row's stored columns + parsed data
    // since subjectTipId reads tx.tx_type and tx.data.
    const txRows = this.db.prepare(
      "SELECT tx_id, tx_type, data FROM transactions WHERE subject_tip_id IS NULL"
    ).all();
    if (txRows.length > 0) {
      const update = this.db.prepare("UPDATE transactions SET subject_tip_id=? WHERE tx_id=?");
      const txn = this.db.transaction((rows) => {
        for (const r of rows) {
          let parsed;
          try { parsed = JSON.parse(r.data); } catch { continue; }
          const subj = subjectTipId({ tx_type: r.tx_type, data: parsed });
          if (subj) {
            update.run(subj, r.tx_id);
            result.transactions++;
          }
        }
      });
      txn(txRows);
    }

    // ── mempool ─────────────────────────────────────────────────────────
    const mempoolRows = this.db.prepare(
      "SELECT tx_id, tx_data FROM mempool WHERE subject_tip_id IS NULL"
    ).all();
    if (mempoolRows.length > 0) {
      const update = this.db.prepare("UPDATE mempool SET subject_tip_id=? WHERE tx_id=?");
      const txn = this.db.transaction((rows) => {
        for (const r of rows) {
          let tx;
          try { tx = JSON.parse(r.tx_data); } catch { continue; }
          const subj = subjectTipId(tx);
          if (subj) {
            update.run(subj, r.tx_id);
            result.mempool++;
          }
        }
      });
      txn(mempoolRows);
    }

    // ── tx_rejections ───────────────────────────────────────────────────
    const rejRows = this.db.prepare(
      "SELECT tx_id, tx_data FROM tx_rejections WHERE subject_tip_id IS NULL AND tx_data IS NOT NULL"
    ).all();
    if (rejRows.length > 0) {
      const update = this.db.prepare("UPDATE tx_rejections SET subject_tip_id=? WHERE tx_id=?");
      const txn = this.db.transaction((rows) => {
        for (const r of rows) {
          let tx;
          try { tx = JSON.parse(r.tx_data); } catch { continue; }
          const subj = subjectTipId(tx);
          if (subj) {
            update.run(subj, r.tx_id);
            result.tx_rejections++;
          }
        }
      });
      txn(rejRows);
    }

    return result;
  }

  _prepare() {
    // Pre-compile hot-path statements for performance
    this._stmts = {
      saveTx: this.db.prepare(
        `INSERT OR IGNORE INTO transactions
           (tx_id,tx_type,data,timestamp,prev,signature,subject_tip_id)
         VALUES (?,?,?,?,?,?,?)`
      ),
      getTx: this.db.prepare("SELECT * FROM transactions WHERE tx_id=?"),
      getAllTxs: this.db.prepare("SELECT * FROM transactions ORDER BY local_inserted_at ASC"),
      countTxs: this.db.prepare("SELECT COUNT(*) AS n FROM transactions"),
      txsByType: this.db.prepare("SELECT * FROM transactions WHERE tx_type=? ORDER BY local_inserted_at ASC"),
      txsByTypeAndCtid: this.db.prepare(
        `SELECT * FROM transactions
         WHERE tx_type=? AND json_extract(data,'$.ctid')=?
         ORDER BY local_inserted_at ASC`
      ),
      // OR-on-(tip_id, author_tip_id) — used by scoring.computeScore
      // which expects all txs whose score effect can land on tipId.
      // Score-affecting txs always reference the target via tip_id or
      // author_tip_id, so this scope is correct for scoring. The new
      // broad-role activity-feed lookup goes through `txsBySubject`
      // (separate column, indexed) — see getTxsBySubject below.
      txsByTipId: this.db.prepare(
        `SELECT * FROM transactions
         WHERE json_extract(data,'$.tip_id')=?
            OR json_extract(data,'$.author_tip_id')=?
         ORDER BY local_inserted_at ASC`
      ),
      // Indexed lookup via the denormalised subject_tip_id column.
      // Broader scope: a juror's vote, a verifier's verification, a
      // disputer's dispute all attribute to that user even though
      // they don't appear under tip_id/author_tip_id. Powers the
      // activity feed (see identity-service.getActivity).
      // ORDER BY matches identity-service.getActivity's canonical sort
      // (strict reverse-chronological): timestamp DESC, SCORE_UPDATE
      // first within ties (it's the logically-latest event), tx_id DESC.
      // Single source of truth for activity-feed ordering across the SQL
      // layer and the JS comparator.
      txsBySubject: this.db.prepare(
        `SELECT * FROM transactions
         WHERE subject_tip_id=?
         ORDER BY timestamp DESC,
                  CASE WHEN tx_type='SCORE_UPDATE' THEN 0 ELSE 1 END ASC,
                  tx_id DESC`
      ),

      saveIdentity: this.db.prepare(
        `INSERT OR REPLACE INTO identities
           (tip_id,region,vp_id,
            verification_tier,tip_id_type,founding,status,
            reviewer_consent,juror_consent,expert_consent,
            interests,
            registered_at,creator_name,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ),
      // GH #60 — JOIN with active entity_keys row so existing callers
      // of getIdentity(id).public_key keep working. valid_to_ts IS NULL
      // picks the currently-active key. Algorithm is also synthesised
      // for the dispatcher's algorithm-aware verification.
      getIdentity: this.db.prepare(
        `SELECT i.*, k.public_key AS public_key, k.algorithm AS algorithm
         FROM identities i
         LEFT JOIN entity_keys k
           ON k.entity_type='identity' AND k.entity_id=i.tip_id AND k.valid_to_ts IS NULL
         WHERE i.tip_id=?`
      ),
      getAllIdentities: this.db.prepare(
        `SELECT i.*, k.public_key AS public_key, k.algorithm AS algorithm
         FROM identities i
         LEFT JOIN entity_keys k
           ON k.entity_type='identity' AND k.entity_id=i.tip_id AND k.valid_to_ts IS NULL
         WHERE i.status='active'`
      ),

      saveContent: this.db.prepare(
        `INSERT OR REPLACE INTO content
           (tip_ctid,origin_code,content_hash,author_tip_id,signer_tip_id,
            authors,attribution_mode,extras,cna_version,
            status,prescan_flagged,prescan_probability,prescan_tier,
            prescan_status,prescan_completed_at,prescan_assigned_node_id,
            prescan_content_type,prescan_overall_degraded,content_type_hint,
            override,registered_at,registered_urls,media,media_canonical_hash,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ),
      getContent: this.db.prepare("SELECT * FROM content WHERE tip_ctid=?"),
      updateContentStatus: this.db.prepare("UPDATE content SET status=? WHERE tip_ctid=?"),
      updateContentOrigin: this.db.prepare("UPDATE content SET origin_code=?, status=? WHERE tip_ctid=?"),
      contentByAuthor: this.db.prepare("SELECT * FROM content WHERE author_tip_id=?"),
      contentByStatus: this.db.prepare("SELECT * FROM content WHERE status=?"),
      // M6 retention — content rows with media[] that pre-date a cutoff,
      // so the sweep walks only what could possibly be expired. Empty
      // `media` (JSON-encoded "[]" or NULL) is filtered out at the SQL
      // layer because text-only content carries no bytes to delete.
      contentWithMediaBefore: this.db.prepare(
        `SELECT * FROM content
         WHERE registered_at < ?
           AND media IS NOT NULL
           AND media <> '[]'`
      ),
      // Returns just the media JSON column for every content row — used
      // by the orphan sweep to build the "referenced media_id" set
      // without hydrating the full rows.
      contentMediaRefs: this.db.prepare(
        `SELECT media FROM content
         WHERE media IS NOT NULL
           AND media <> '[]'`
      ),
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

      addDedupHash: this.db.prepare("INSERT OR IGNORE INTO dedup_registry (dedup_hash, created_at, tip_id) VALUES (?, ?, ?)"),
      hasDedupHash: this.db.prepare("SELECT 1 FROM dedup_registry WHERE dedup_hash=?"),
      getDedupRegistration: this.db.prepare("SELECT dedup_hash, created_at, tip_id FROM dedup_registry WHERE dedup_hash=?"),
      dedupCount: this.db.prepare("SELECT COUNT(*) AS n FROM dedup_registry"),

      addRevoc: this.db.prepare(
        `INSERT OR REPLACE INTO revocations (tip_id,tx_type,timestamp,tx_id)
         VALUES (?,?,?,?)`
      ),
      isRevoked: this.db.prepare("SELECT 1 FROM revocations WHERE tip_id=?"),
      getRevoc: this.db.prepare("SELECT * FROM revocations WHERE tip_id=?"),
      revocAll: this.db.prepare("SELECT * FROM revocations ORDER BY timestamp DESC"),
      revocSince: this.db.prepare("SELECT * FROM revocations WHERE timestamp>? ORDER BY timestamp DESC"),
      revokeIdent: this.db.prepare("UPDATE identities SET status='revoked' WHERE tip_id=?"),

      // Domain bindings (canonical) + pending claims (local-only)
      saveDomainBinding: this.db.prepare(
        `INSERT OR REPLACE INTO domain_bindings
           (domain,tip_id,binding_state,method,claimed_at,verified_at,
            expires_at,consecutive_failures,node_id,
            claim_signature,binding_signature,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
      ),
      getDomainBinding: this.db.prepare("SELECT * FROM domain_bindings WHERE domain=?"),
      getDomainBindingsByTipId: this.db.prepare("SELECT * FROM domain_bindings WHERE tip_id=?"),
      getAllDomainBindings: this.db.prepare("SELECT * FROM domain_bindings"),

      savePlatformLink: this.db.prepare(
        `INSERT OR REPLACE INTO platform_links
         (id, tip_id, platform, handle, profile_url, status, linked_at, verified_at,
          unlinked_at, unlink_tx_id, node_id, tx_id)
         VALUES (@id, @tip_id, @platform, @handle, @profile_url, @status, @linked_at,
                 @verified_at, @unlinked_at, @unlink_tx_id, @node_id, @tx_id)`
      ),
      updatePlatformLinkStatus: this.db.prepare(
        `UPDATE platform_links SET status=@status, unlinked_at=@unlinked_at, unlink_tx_id=@unlink_tx_id
         WHERE tip_id=@tip_id AND platform=@platform`
      ),
      getPlatformLink: this.db.prepare(
        "SELECT * FROM platform_links WHERE tip_id=? AND platform=?"
      ),
      getPlatformLinksByTipId: this.db.prepare(
        "SELECT * FROM platform_links WHERE tip_id=?"
      ),

      savePendingDomainClaim: this.db.prepare(
        `INSERT OR REPLACE INTO pending_domain_claims
           (domain,tip_id,method,claimed_at,signature,received_at)
         VALUES (?,?,?,?,?,?)`
      ),
      getPendingDomainClaim: this.db.prepare("SELECT * FROM pending_domain_claims WHERE domain=?"),
      deletePendingDomainClaim: this.db.prepare("DELETE FROM pending_domain_claims WHERE domain=?"),

      saveVP: this.db.prepare(
        `INSERT OR REPLACE INTO verification_providers
           (vp_id,name,jurisdiction,jurisdiction_tier,status,registered_at)
         VALUES (?,?,?,?,?,?)`
      ),
      getVP: this.db.prepare(
        `SELECT v.*, k.public_key AS public_key, k.algorithm AS algorithm
         FROM verification_providers v
         LEFT JOIN entity_keys k
           ON k.entity_type='vp' AND k.entity_id=v.vp_id AND k.valid_to_ts IS NULL
         WHERE v.vp_id=?`
      ),
      getAllVPs: this.db.prepare(
        `SELECT v.*, k.public_key AS public_key, k.algorithm AS algorithm
         FROM verification_providers v
         LEFT JOIN entity_keys k
           ON k.entity_type='vp' AND k.entity_id=v.vp_id AND k.valid_to_ts IS NULL`
      ),

      saveNode: this.db.prepare(
        `INSERT OR REPLACE INTO nodes (node_id,name,status,api_endpoint,updated_at,registered_at)
         VALUES (?,?,?,?,?,?)`
      ),
      updateNodeEndpoint: this.db.prepare(
        "UPDATE nodes SET api_endpoint=?, updated_at=? WHERE node_id=?"
      ),
      getNode: this.db.prepare(
        `SELECT n.*, k.public_key AS public_key, k.algorithm AS algorithm
         FROM nodes n
         LEFT JOIN entity_keys k
           ON k.entity_type='node' AND k.entity_id=n.node_id AND k.valid_to_ts IS NULL
         WHERE n.node_id=?`
      ),
      getAllNodes: this.db.prepare(
        `SELECT n.*, k.public_key AS public_key, k.algorithm AS algorithm
         FROM nodes n
         LEFT JOIN entity_keys k
           ON k.entity_type='node' AND k.entity_id=n.node_id AND k.valid_to_ts IS NULL`
      ),

      // GH #60 — entity_keys statements.
      saveEntityKey: this.db.prepare(
        `INSERT OR REPLACE INTO entity_keys
           (entity_type,entity_id,public_key,algorithm,valid_from_ts,valid_to_ts,source_tx_id)
         VALUES (?,?,?,?,?,?,?)`
      ),
      getActiveEntityKey: this.db.prepare(
        `SELECT * FROM entity_keys
         WHERE entity_type=? AND entity_id=? AND valid_to_ts IS NULL`
      ),
      getKeyValidAt: this.db.prepare(
        // Pick the row whose validity range covers the timestamp;
        // among matching rows the greatest valid_from_ts wins (the
        // most recent rotation active at that time).
        `SELECT * FROM entity_keys
         WHERE entity_type=? AND entity_id=?
           AND valid_from_ts <= ?
           AND (valid_to_ts IS NULL OR valid_to_ts > ?)
         ORDER BY valid_from_ts DESC
         LIMIT 1`
      ),
      closeActiveEntityKey: this.db.prepare(
        // Used by KEY_ROTATED / KEY_RECOVERY apply to mark the prior
        // active key as expired at effective_at.
        `UPDATE entity_keys SET valid_to_ts=?
         WHERE entity_type=? AND entity_id=? AND valid_to_ts IS NULL`
      ),
      iterateEntityKeys: this.db.prepare(
        `SELECT * FROM entity_keys
         ORDER BY entity_type, entity_id, valid_from_ts`
      ),
      getEntityKeyHistory: this.db.prepare(
        `SELECT * FROM entity_keys
         WHERE entity_type=? AND entity_id=?
         ORDER BY valid_from_ts`
      ),
      clearEntityKeys: this.db.prepare("DELETE FROM entity_keys"),

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
      getCertsByRoundRange: this.db.prepare("SELECT * FROM certificates WHERE round>=? AND round<=? ORDER BY round ASC, author_node_id ASC"),
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

      // §4 + #34: committee_history accessors. saveCommitteeRotation uses
      // INSERT OR REPLACE so a snapshot install carrying an authoritative
      // rotation row overwrites any prior local divergent row by
      // (rotation_number) PK — no destructive clear step needed before
      // re-insert. Re-applying the same row is still idempotent (every
      // column re-set to the same canonical value).
      // getCommitteeAtRound is the hot-path read used by
      // participants.getActiveCommittee (every round). SQLite picks the
      // index on (effective_round) for the WHERE; the ORDER BY
      // rotation_number DESC LIMIT 1 narrows to the latest rotation at-or-
      // before the requested round in a single index scan.
      saveCommitteeRotation: this.db.prepare(
        `INSERT OR REPLACE INTO committee_history
           (rotation_number,effective_round,committee,prev_rotation,
            signer_node_ids,signatures,payload_hash,committed_at)
         VALUES (?,?,?,?,?,?,?,?)`
      ),
      getCommitteeRotation: this.db.prepare(
        "SELECT * FROM committee_history WHERE rotation_number=?"
      ),
      getLatestRotation: this.db.prepare(
        "SELECT * FROM committee_history ORDER BY rotation_number DESC LIMIT 1"
      ),
      getCommitteeAtRound: this.db.prepare(
        "SELECT * FROM committee_history WHERE effective_round<=? ORDER BY rotation_number DESC LIMIT 1"
      ),
      getRotationsFromGenesis: this.db.prepare(
        "SELECT * FROM committee_history ORDER BY rotation_number ASC"
      ),

      // Interests registry accessors. INSERT OR REPLACE so an
      // authoritative re-install (snapshot install correcting a row, or
      // re-registration via tx) overwrites by (slug) PK without a
      // destructive clear step. Re-applying identical data is idempotent.
      saveInterest: this.db.prepare(
        `INSERT OR REPLACE INTO interests_registry
           (slug, label, category, registered_at, registered_by_vp_id, tx_id)
         VALUES (?, ?, ?, ?, ?, ?)`
      ),
      getInterest: this.db.prepare(
        "SELECT * FROM interests_registry WHERE slug = ?"
      ),
      getAllInterests: this.db.prepare(
        "SELECT * FROM interests_registry ORDER BY slug ASC"
      ),
      interestCount: this.db.prepare(
        "SELECT COUNT(*) AS n FROM interests_registry"
      ),

      // Prescan-review accessors. INSERT OR REPLACE so the same row can
      // walk through its state machine (triggered → confirmed →
      // closed_accepted_private etc.) via successive saves.
      savePrescanReview: this.db.prepare(
        `INSERT OR REPLACE INTO prescan_reviews
           (review_id, tip_ctid, creator_tip_id, assigned_reviewer,
            triggered_at_round, triggered_at_ms,
            decided_at_round, confirmed_at_round,
            confirmed_at_ms, state, decision_note, suggested_origin)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
      ),
      getPrescanReview: this.db.prepare(
        "SELECT * FROM prescan_reviews WHERE review_id=?"
      ),
      // Only one open review per CTID at a time — state='triggered' OR
      // 'confirmed' (creator-decision window). Closed states are terminal.
      getOpenPrescanReviewByCtid: this.db.prepare(
        "SELECT * FROM prescan_reviews WHERE tip_ctid=? AND state IN ('triggered','confirmed') ORDER BY triggered_at_round DESC LIMIT 1"
      ),
      getPrescanReviewsByReviewer: this.db.prepare(
        "SELECT * FROM prescan_reviews WHERE assigned_reviewer=? ORDER BY triggered_at_round DESC"
      ),
      getPrescanReviewsByCtid: this.db.prepare(
        "SELECT * FROM prescan_reviews WHERE tip_ctid=? ORDER BY triggered_at_round DESC"
      ),
      // Phase 2.5 trigger queries. content.registered_at is integer epoch
      // ms; index on (status, prescan_tier) carries the high-selectivity
      // prefix and the time-window check is a direct integer comparison.
      //
      // origin_code = 'OH' is the "no UPDATE_ORIGIN" guard from the
      // design doc: after a self-correction, origin_code is AA/AG/MX,
      // so the content is no longer claiming human-only and there's
      // nothing for the reviewer to dispute.
      // The JOIN must include EVERY non-recused prior review state —
      // not just the open ones — so the trigger doesn't re-fire after
      // a DISMISS / accept-private / self-correct / dispute escalation
      // closes the case. RECUSED is the only terminal state that
      // intentionally re-triggers (new reviewer needed).
      getContentsNeedingReview: this.db.prepare(
        `SELECT c.* FROM content c
         LEFT JOIN prescan_reviews r
           ON r.tip_ctid = c.tip_ctid AND r.state != 'recused'
         WHERE c.status = 'registered'
           AND c.origin_code = 'OH'
           AND c.prescan_status = 'completed'
           AND c.prescan_overall_degraded = 0
           AND c.prescan_tier IN ('high','critical')
           AND r.review_id IS NULL
           AND c.prescan_completed_at IS NOT NULL
           AND c.prescan_completed_at <= ?`
      ),
      // Content rows stuck in prescan_status='pending' past the
      // fail-open deadline. Caller passes (now - prescan.fail_open_after_ms)
      // as the cutoff; rows registered before that haven't produced a
      // verdict and need a synthesised fail-open completion so they
      // don't sit in PENDING_PRESCAN forever (e.g. API node died after
      // enqueueing but before the worker emitted PRESCAN_COMPLETED).
      getContentsStuckInPrescan: this.db.prepare(
        `SELECT * FROM content
          WHERE prescan_status = 'pending'
            AND registered_at IS NOT NULL
            AND registered_at <= ?`
      ),
      // Reviews in state=confirmed whose 24h creator-decision window has
      // elapsed. confirmed_at_ms is set on CONFIRMED apply from cert.ts.
      getReviewsNeedingAutoEscalation: this.db.prepare(
        `SELECT * FROM prescan_reviews
         WHERE state = 'confirmed'
           AND confirmed_at_ms IS NOT NULL
           AND confirmed_at_ms <= ?
         ORDER BY confirmed_at_ms ASC`
      ),
      // Reviews in state=triggered whose reviewer SLA has elapsed —
      // candidates for node-emitted auto-recuse. triggered_at_ms is set
      // on TRIGGERED apply from cert.ts.
      getReviewsNeedingAutoRecuse: this.db.prepare(
        `SELECT * FROM prescan_reviews
         WHERE state = 'triggered'
           AND triggered_at_ms IS NOT NULL
           AND triggered_at_ms <= ?
         ORDER BY triggered_at_ms ASC`
      ),

      // #75 rotation_participation. UPSERT pattern (INSERT … ON CONFLICT)
      // increments the counter atomically — first sighting in a rotation
      // creates the row at count=1, subsequent sightings just bump count.
      incrementRotationParticipation: this.db.prepare(
        `INSERT INTO rotation_participation (node_id, rotation_number, count)
         VALUES (?, ?, 1)
         ON CONFLICT(node_id, rotation_number) DO UPDATE SET count = count + 1`
      ),
      getRotationParticipation: this.db.prepare(
        "SELECT node_id, count FROM rotation_participation WHERE rotation_number = ?"
      ),
      pruneRotationParticipationBefore: this.db.prepare(
        "DELETE FROM rotation_participation WHERE rotation_number < ?"
      ),
      // Absolute-set for snapshot install (REPLACE not increment).
      setRotationParticipation: this.db.prepare(
        `INSERT INTO rotation_participation (node_id, rotation_number, count)
         VALUES (?, ?, ?)
         ON CONFLICT(node_id, rotation_number) DO UPDATE SET count = excluded.count`
      ),
      // Wipe one rotation's rows — snapshot install pre-pass so absent rows
      // in the snapshot become absent locally too (see MemoryStore comment).
      deleteRotationParticipationByRotation: this.db.prepare(
        "DELETE FROM rotation_participation WHERE rotation_number = ?"
      ),
      // Streaming iterator for snapshot/state-root (PK-ordered).
      iterateRotationParticipation: this.db.prepare(
        "SELECT node_id, rotation_number, count FROM rotation_participation ORDER BY rotation_number, node_id"
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
      saveMempoolTx: this.db.prepare("INSERT OR IGNORE INTO mempool (tx_id,tx_data,subject_tip_id) VALUES (?,?,?)"),
      getMempoolTx: this.db.prepare("SELECT * FROM mempool WHERE tx_id=?"),
      getMempoolTxs: this.db.prepare("SELECT * FROM mempool ORDER BY received_at ASC"),
      // Indexed lookup for activity-feed merge of pending txs.
      // received_at ASC keeps oldest-first ordering, which the activity
      // API can either honor (queue order) or re-sort by tx.timestamp.
      getMempoolTxsByTipId: this.db.prepare(
        "SELECT * FROM mempool WHERE subject_tip_id=? ORDER BY received_at ASC"
      ),
      deleteMempoolTx: this.db.prepare("DELETE FROM mempool WHERE tx_id=?"),
      clearMempoolBefore: this.db.prepare("DELETE FROM mempool WHERE received_at < ?"),
      countMempool: this.db.prepare("SELECT COUNT(*) AS n FROM mempool"),

      // Tx rejections — #64 follow-up no-loss invariant. INSERT OR IGNORE
      // on tx_id PK so peer re-broadcast of an already-rejected tx is a
      // silent no-op; the original (most-informative) reason wins.
      saveTxRejection: this.db.prepare(
        `INSERT OR IGNORE INTO tx_rejections
           (tx_id,reason,reason_detail,rejected_at_ms,rejected_at_round,dropper_node_id,tx_type,origin_node_id,tx_data,subject_tip_id)
         VALUES (?,?,?,?,?,?,?,?,?,?)`
      ),
      getTxRejection: this.db.prepare("SELECT * FROM tx_rejections WHERE tx_id=?"),
      // Reverse-chronological so dashboards / outcome endpoint see most
      // recent first. Cap with LIMIT at the call site.
      getTxRejectionsByReason: this.db.prepare(
        `SELECT * FROM tx_rejections
         WHERE reason=? AND rejected_at_ms >= ?
         ORDER BY rejected_at_ms DESC
         LIMIT ?`
      ),
      // Indexed lookup for activity-feed merge of rejected txs.
      // DESC by rejected_at_ms so the most-recent failure shows first
      // (matches what a user looking at "what went wrong" expects).
      getTxRejectionsByTipId: this.db.prepare(
        `SELECT * FROM tx_rejections
         WHERE subject_tip_id=?
         ORDER BY rejected_at_ms DESC`
      ),
      // #40 — all rejections, most-recent first; filtered by subjectTipIds()
      // at read time so the counterparty of a failed dispute/appeal also sees it.
      getAllTxRejections: this.db.prepare(
        "SELECT * FROM tx_rejections ORDER BY rejected_at_ms DESC"
      ),
      countTxRejections: this.db.prepare("SELECT COUNT(*) AS n FROM tx_rejections"),

      // Dispute details (off-chain dispute body). INSERT OR IGNORE on
      // evidence_hash PK keeps re-uploads idempotent.
      saveDisputeDetails: this.db.prepare(
        `INSERT OR IGNORE INTO dispute_details
           (evidence_hash, disputer_tip_id, payload_json, signature, local_inserted_at)
         VALUES (?,?,?,?,?)`
      ),
      getDisputeDetails: this.db.prepare(
        "SELECT * FROM dispute_details WHERE evidence_hash=?"
      ),
      hasDisputeDetails: this.db.prepare(
        "SELECT 1 AS hit FROM dispute_details WHERE evidence_hash=?"
      ),
      deleteDisputeDetails: this.db.prepare(
        "DELETE FROM dispute_details WHERE evidence_hash=?"
      ),

      // Prescan jobs (node-local async classifier queue). INSERT OR IGNORE
      // on job_id PK keeps the API node's enqueue idempotent if it
      // re-fires for the same registration. Atomic claim primitive runs
      // a single UPDATE…RETURNING — SQLite's row-level locking handles
      // concurrent workers correctly.
      enqueuePrescanJob: this.db.prepare(
        `INSERT OR IGNORE INTO prescan_jobs
           (job_id, tip_ctid, payload, status, claimed_at, claimed_by, retries, last_error, created_at, completed_at)
         VALUES (?, ?, ?, 'queued', NULL, NULL, 0, NULL, ?, NULL)`
      ),
      getPrescanJob: this.db.prepare(
        "SELECT * FROM prescan_jobs WHERE job_id=?"
      ),
      getPrescanJobByCtid: this.db.prepare(
        "SELECT * FROM prescan_jobs WHERE tip_ctid=?"
      ),
      claimPrescanJob: this.db.prepare(
        `UPDATE prescan_jobs
            SET status='claimed', claimed_at=?, claimed_by=?
          WHERE job_id = (
            SELECT job_id FROM prescan_jobs
             WHERE status='queued'
                OR (status='claimed' AND claimed_at < ?)
             ORDER BY created_at
             LIMIT 1
          )
          RETURNING *`
      ),
      markPrescanJobDone: this.db.prepare(
        `UPDATE prescan_jobs
            SET status='done', completed_at=?, last_error=NULL
          WHERE job_id=?`
      ),
      markPrescanJobFailed: this.db.prepare(
        `UPDATE prescan_jobs
            SET status='failed', completed_at=?, last_error=?
          WHERE job_id=?`
      ),
      releasePrescanJobForRetry: this.db.prepare(
        `UPDATE prescan_jobs
            SET status='queued', claimed_at=NULL, claimed_by=NULL,
                last_error=?, retries=retries+1
          WHERE job_id=?`
      ),
      // Perceptual index (off-DAG, advisory).
      savePerceptualFingerprint: this.db.prepare(
        `INSERT OR REPLACE INTO perceptual_fingerprint
           (tip_ctid, component_idx, modality, profile, pipeline, quality, fingerprint, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ),
      saveMinhashBand: this.db.prepare(
        `INSERT OR IGNORE INTO minhash_band (profile, band_idx, band_hash, tip_ctid) VALUES (?, ?, ?, ?)`
      ),
      savePhashCode: this.db.prepare(
        `INSERT OR IGNORE INTO phash_code
           (tip_ctid, component_idx, frame, profile, modality, ts, quality, pdq,
            c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ),
      getPerceptualFingerprint: this.db.prepare(
        "SELECT tip_ctid AS ctid, component_idx, modality, profile, pipeline, quality, fingerprint, created_at FROM perceptual_fingerprint WHERE tip_ctid=? AND component_idx=?"
      ),
      findMinhashByBand: this.db.prepare(
        "SELECT tip_ctid AS ctid FROM minhash_band WHERE profile=? AND band_idx=? AND band_hash=?"
      ),
      getPhashCodesByCtid: this.db.prepare(
        "SELECT tip_ctid AS ctid, profile, modality, frame, ts, quality, pdq FROM phash_code WHERE tip_ctid=?"
      ),
      // Audio: surrogate clip_id (§8.1). Upsert refreshes the FULL landmark_count
      // and RETURNs the clip_id the landmark rows point at.
      upsertAudioClip: this.db.prepare(
        `INSERT INTO audio_clip (tip_ctid, component_idx, landmark_count)
         VALUES (?, ?, ?)
         ON CONFLICT(tip_ctid, component_idx) DO UPDATE SET landmark_count=excluded.landmark_count
         RETURNING clip_id`
      ),
      saveAudioLandmark: this.db.prepare(
        "INSERT OR IGNORE INTO audio_landmark (profile, hash, clip_id, t) VALUES (?, ?, ?, ?)"
      ),
      getAudioClip: this.db.prepare(
        "SELECT clip_id, tip_ctid AS ctid, component_idx, landmark_count FROM audio_clip WHERE clip_id=?"
      ),
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
      tx.signature || null,
      subjectTipId(tx)
    );
  }
  getTx(id) { return this._parseTx(this._stmts.getTx.get(id)); }
  getAllTxs() { return this._stmts.getAllTxs.all().map(r => this._parseTx(r)); }
  count() { return this._stmts.countTxs.get().n; }
  getTxsByType(type) { return this._stmts.txsByType.all(type).map(r => this._parseTx(r)); }
  getTxsByTypeAndCtid(type, ctid) { return this._stmts.txsByTypeAndCtid.all(type, ctid).map(r => this._parseTx(r)); }
  // Narrow OR-pattern lookup — scope matches scoring.computeScore's
  // requirements (tip_id || author_tip_id covers every score-affecting role).
  getTxsByTipId(tipId) { return this._stmts.txsByTipId.all(tipId, tipId).map(r => this._parseTx(r)); }
  // Broad role-aware lookup powering the activity feed. #40: recompute every
  // party live from tx data (any-party match) so multi-party disputes/appeals
  // surface in BOTH parties' feeds, not just the actor's. This is a dev-store
  // scan (SQLiteStore is dev/test default); production reads go through the
  // Knex in-memory mirror (MemoryStore.getTxsBySubject). Ordering mirrors that
  // comparator (timestamp DESC, SCORE_UPDATE-first, tx_id DESC).
  getTxsBySubject(tipId) {
    return this._stmts.getAllTxs.all()
      .map(r => this._parseTx(r))
      .filter(t => subjectTipIds(t).includes(tipId))
      .sort((a, b) => {
        const d = Number(b.timestamp) - Number(a.timestamp);
        if (d !== 0) return d;
        const ap = a.tx_type === "SCORE_UPDATE" ? 0 : 1;
        const bp = b.tx_type === "SCORE_UPDATE" ? 0 : 1;
        if (ap !== bp) return ap - bp;
        return a.tx_id < b.tx_id ? 1 : -1;
      });
  }
  // §14/#49 snapshot full-history streaming. Ordered by tx_id (PK index)
  // so sender + receiver hash rows in the same order → same txs_full_root.
  // Uses better-sqlite3 .iterate() so memory stays bounded at one row.
  *iterateAllTransactions() {
    for (const row of this.db.prepare("SELECT * FROM transactions ORDER BY tx_id ASC").iterate()) {
      yield this._parseTx(row);
    }
  }

  // ── Identities ────────────────────────────────────────────────────────────
  // GH #60: public_key + algorithm auto-route to entity_keys (single
  // source of truth, DID/X.509/JWKS pattern). The identities row stores
  // everything else. `root_public_key` is dropped — orphaned scaffold.
  saveIdentity(rec) {
    if (rec.public_key) {
      this._saveActiveEntityKey({
        entity_type: "identity",
        entity_id: rec.tip_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.registered_at,
        source_tx_id: rec.tx_id || `genesis:${rec.tip_id}`,
      });
    }
    this._stmts.saveIdentity.run(
      rec.tip_id, rec.region || "US",
      rec.vp_id || null, rec.verification_tier || "T1",
      rec.tip_id_type || "personal",
      rec.founding ? 1 : 0,
      rec.status || "active",
      rec.reviewer_consent ? 1 : 0,
      rec.juror_consent ? 1 : 0,
      rec.expert_consent ? 1 : 0,
      JSON.stringify(Array.isArray(rec.interests) ? rec.interests : []),
      rec.registered_at, rec.creator_name || null, rec.tx_id || null
    );
  }
  getIdentity(id) {
    const row = this._stmts.getIdentity.get(id);
    return row ? this._parseIdentityRow(row) : null;
  }
  getAllIdentities() {
    return this._stmts.getAllIdentities.all().map(r => this._parseIdentityRow(r));
  }
  _parseIdentityRow(row) {
    let interests = [];
    if (typeof row.interests === "string" && row.interests.length > 0) {
      try { interests = JSON.parse(row.interests); } catch { interests = []; }
    }
    return {
      ...row,
      founding: row.founding === 1,
      reviewer_consent: row.reviewer_consent === 1,
      juror_consent: row.juror_consent === 1,
      expert_consent: row.expert_consent === 1,
      interests,
    };
  }

  // ── Content ───────────────────────────────────────────────────────────────
  saveContent(rec) {
    // CNA-2.2 canonical fields stored on the row: authors[],
    // attribution_mode, extras, cna_version, registered_urls. JSON-
    // encode the array/object ones; the rest are scalars.
    const urls = Array.isArray(rec.registered_urls) ? rec.registered_urls : [];
    const authors = Array.isArray(rec.authors) ? rec.authors : [];
    const extras = (rec.extras && typeof rec.extras === "object" && !Array.isArray(rec.extras)) ? rec.extras : {};
    const media = Array.isArray(rec.media) ? rec.media : [];
    this._stmts.saveContent.run(
      rec.ctid, rec.origin_code,
      rec.content_hash,
      rec.author_tip_id, rec.signer_tip_id,
      JSON.stringify(authors),
      rec.attribution_mode || "self",
      JSON.stringify(extras),
      rec.cna_version,
      rec.status || "registered",
      rec.prescan_flagged ? 1 : 0,
      typeof rec.prescan_probability === "number" ? rec.prescan_probability : 0,
      rec.prescan_tier || "low",
      rec.prescan_status || "completed",
      typeof rec.prescan_completed_at === "number" ? rec.prescan_completed_at : null,
      rec.prescan_assigned_node_id || null,
      rec.prescan_content_type || null,
      rec.prescan_overall_degraded ? 1 : 0,
      rec.content_type_hint || null,
      rec.override ? 1 : 0,
      rec.registered_at, JSON.stringify(urls),
      JSON.stringify(media),
      typeof rec.media_canonical_hash === "string" ? rec.media_canonical_hash : null,
      rec.tx_id || null
    );
  }
  // SQL returns array/object columns as JSON-encoded TEXT. Decode all
  // of them on every read.
  _hydrateContent(row) {
    if (!row) return null;
    const decode = (s, fallback) => {
      if (typeof s !== "string" || !s.length) return fallback;
      try { return JSON.parse(s); } catch { return fallback; }
    };
    // DB column is `tip_ctid` (uniform across all backends); callers use `ctid`.
    const { tip_ctid, ...rest } = row;
    return {
      ...rest,
      ctid: tip_ctid,
      registered_urls: (() => { const v = decode(row.registered_urls, []); return Array.isArray(v) ? v : []; })(),
      authors: (() => { const v = decode(row.authors, []); return Array.isArray(v) ? v : []; })(),
      extras: (() => { const v = decode(row.extras, {}); return (v && typeof v === "object" && !Array.isArray(v)) ? v : {}; })(),
      media: (() => { const v = decode(row.media, []); return Array.isArray(v) ? v : []; })(),
    };
  }
  getContent(ctid) { return this._hydrateContent(this._stmts.getContent.get(ctid)); }
  updateContentStatus(ctid, status) { this._stmts.updateContentStatus.run(status, ctid); }
  updateContentOrigin(ctid, originCode, status) { this._stmts.updateContentOrigin.run(originCode, status, ctid); }
  getContentByAuthor(tipId) { return this._stmts.contentByAuthor.all(tipId).map(r => this._hydrateContent(r)); }
  getContentByStatus(status) { return this._stmts.contentByStatus.all(status).map(r => this._hydrateContent(r)); }
  // Explorer list — see MemoryStore.listContent for the contract.
  // Filters vary per call, so the statement is built dynamically; the
  // (status, author, origin) columns are indexed.
  listContent({ author = null, origin = null, status = null, hasMedia = null, limit = 20, cursor = null } = {}) {
    const where = [];
    const params = [];
    if (author) { where.push("author_tip_id = ?"); params.push(author); }
    if (origin) { where.push("origin_code = ?"); params.push(origin); }
    if (status) { where.push("status = ?"); params.push(status); }
    if (hasMedia === true) where.push("media IS NOT NULL AND media != '[]'");
    if (cursor) {
      where.push("(registered_at < ? OR (registered_at = ? AND tip_ctid < ?))");
      params.push(cursor.t, cursor.t, cursor.c);
    }
    const sql = `SELECT * FROM content${where.length ? " WHERE " + where.join(" AND ") : ""}
      ORDER BY registered_at DESC, tip_ctid DESC LIMIT ?`;
    params.push(limit + 1);
    return this.db.prepare(sql).all(...params).map(r => this._hydrateContent(r));
  }
  // M6 — content rows registered before `cutoffMs` that carry media[].
  getContentWithMediaBefore(cutoffMs) {
    return this._stmts.contentWithMediaBefore.all(cutoffMs).map(r => this._hydrateContent(r));
  }
  // M6 — Map<media_id, reference_count> across every content row.
  //   - Orphan sweep checks `.has(mediaId)` to decide if a stored object
  //     is referenced at all.
  //   - Content-retention sweep checks the count so dedup'd media (same
  //     bytes referenced by multiple ctids) only gets deleted when ALL
  //     referring rows are expired in the same pass.
  getReferencedMediaIds() {
    const out = new Map();
    for (const row of this._stmts.contentMediaRefs.iterate()) {
      try {
        const arr = JSON.parse(row.media);
        if (Array.isArray(arr)) {
          for (const m of arr) {
            if (m && typeof m.media_id === "string") {
              out.set(m.media_id, (out.get(m.media_id) || 0) + 1);
            }
          }
        }
      } catch { /* corrupt row — skip */ }
    }
    return out;
  }
  hasVerification(ctid, tipId) { return !!this._stmts.hasVerification.get(ctid, tipId); }
  hasDispute(ctid, tipId) { return !!this._stmts.hasDispute.get(ctid, tipId); }

  getCleanRecordEligible(cutoff) {
    // Clean-record bonus eligibility (TIP_Scoring_v2 Reputation §):
    //   - identity active and registered for at least CLEAN_PERIOD_DAYS
    //   - registered ≥1 OH or AA content inside the window (jury duty
    //     and other activity do NOT qualify — prevents idle score-farming)
    //   - no UPHELD adjudication against them inside the window
    //   - no prior clean_record_bonus inside the window
    return this.db.prepare(`
      SELECT DISTINCT i.tip_id FROM identities i
      WHERE i.status = 'active'
        AND i.registered_at <= ?
        AND EXISTS (
          SELECT 1 FROM transactions t
          WHERE t.tx_type = 'REGISTER_CONTENT'
            AND json_extract(t.data,'$.signer_tip_id') = i.tip_id
            AND json_extract(t.data,'$.origin_code') IN ('OH','AA')
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
            AND json_extract(t.data,'$.reason') LIKE 'clean_record_bonus%'
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
  // tipId denormalized for fast hash→tip_id lookups (see _canonDedup).
  addDedupHash(hash, createdAt, tipId) {
    if (createdAt == null) {
      throw new Error("addDedupHash: createdAt (from tx.timestamp) is required for deterministic state");
    }
    this._stmts.addDedupHash.run(hash, createdAt, tipId || null);
  }
  hasDedupHash(hash) { return !!this._stmts.hasDedupHash.get(hash); }
  getDedupRegistration(hash) {
    const row = this._stmts.getDedupRegistration.get(hash);
    return row ? { dedup_hash: row.dedup_hash, created_at: row.created_at, tip_id: row.tip_id || null } : null;
  }
  dedupCount() { return this._stmts.dedupCount.get().n; }

  // ── Revocations ───────────────────────────────────────────────────────────
  addRevocation(tipId, txType, timestamp, txId) {
    this.db.transaction(() => {
      this._stmts.addRevoc.run(tipId, txType, timestamp, txId);
      this._stmts.revokeIdent.run(tipId);
    })();
  }
  isRevoked(tipId) { return !!this._stmts.isRevoked.get(tipId); }
  getRevocation(tipId) { return this._stmts.getRevoc.get(tipId) || null; }
  getRevocations(since) {
    return since
      ? this._stmts.revocSince.all(since)
      : this._stmts.revocAll.all();
  }

  // ── Domain bindings (canonical) ──────────────────────────────────────────
  saveDomainBinding(rec) {
    this._stmts.saveDomainBinding.run(
      rec.domain, rec.tip_id, rec.binding_state, rec.method,
      rec.claimed_at, rec.verified_at,
      rec.expires_at,
      typeof rec.consecutive_failures === "number" ? rec.consecutive_failures : 0,
      rec.node_id,
      rec.claim_signature, rec.binding_signature, rec.tx_id,
    );
  }
  getDomainBinding(domain) { return this._stmts.getDomainBinding.get(domain) || null; }
  getDomainBindingsByTipId(tipId) { return this._stmts.getDomainBindingsByTipId.all(tipId); }
  getAllDomainBindings() { return this._stmts.getAllDomainBindings.all(); }

  // ── Platform links (canonical) ───────────────────────────────────────────
  savePlatformLink(rec) { this._stmts.savePlatformLink.run(rec); }
  updatePlatformLinkStatus(tipId, platform, update) {
    this._stmts.updatePlatformLinkStatus.run({ tip_id: tipId, platform, ...update });
  }
  getPlatformLink(tipId, platform) {
    return this._stmts.getPlatformLink.get(tipId, platform) || null;
  }
  getPlatformLinksByTipId(tipId) {
    return this._stmts.getPlatformLinksByTipId.all(tipId);
  }

  // ── Pending domain claims (local-only) ───────────────────────────────────
  savePendingDomainClaim(rec) {
    this._stmts.savePendingDomainClaim.run(
      rec.domain, rec.tip_id, rec.method, rec.claimed_at, rec.signature, rec.received_at,
    );
  }
  getPendingDomainClaim(domain) { return this._stmts.getPendingDomainClaim.get(domain) || null; }
  deletePendingDomainClaim(domain) {
    return this._stmts.deletePendingDomainClaim.run(domain).changes > 0;
  }

  // ── Verification Providers ────────────────────────────────────────────────
  saveVP(rec) {
    if (rec.public_key) {
      this._saveActiveEntityKey({
        entity_type: "vp",
        entity_id: rec.vp_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.registered_at || nowMs(),
        source_tx_id: rec.tx_id || `genesis:${rec.vp_id}`,
      });
    }
    this._stmts.saveVP.run(
      rec.vp_id, rec.name,
      rec.jurisdiction || "US",
      rec.jurisdiction_tier || "green",
      rec.status || "active",
      rec.registered_at || nowMs()
    );
  }
  getVP(vpId) { return this._stmts.getVP.get(vpId) || null; }
  getAllVPs() { return this._stmts.getAllVPs.all(); }

  // ── Nodes ───────────────────────────────────────────────────────────────
  saveNode(rec) {
    if (rec.public_key) {
      this._saveActiveEntityKey({
        entity_type: "node",
        entity_id: rec.node_id,
        public_key: rec.public_key,
        algorithm: rec.algorithm || "ml-dsa-65",
        valid_from_ts: rec.registered_at || nowMs(),
        source_tx_id: rec.tx_id || `genesis:${rec.node_id}`,
      });
    }
    this._stmts.saveNode.run(
      rec.node_id, rec.name || null,
      rec.status || "active",
      rec.api_endpoint || null,
      null,  // updated_at: null for new nodes (no update committed yet)
      rec.registered_at || nowMs()
    );
  }
  updateNodeEndpoint(nodeId, apiEndpoint, timestamp) {
    this._stmts.updateNodeEndpoint.run(apiEndpoint || null, timestamp ?? null, nodeId);
  }
  getNode(nodeId) { return this._stmts.getNode.get(nodeId) || null; }
  getAllNodes() { return this._stmts.getAllNodes.all(); }

  // ── entity_keys (GH #60) ─────────────────────────────────────────────────
  _saveActiveEntityKey({ entity_type, entity_id, public_key, algorithm, valid_from_ts, source_tx_id }) {
    this.db.transaction(() => {
      const prev = this._stmts.getActiveEntityKey.get(entity_type, entity_id);
      if (prev) {
        if (prev.public_key === public_key && prev.algorithm === algorithm && prev.valid_from_ts === valid_from_ts) {
          return;  // idempotent re-write (snapshot install replay)
        }
        this._stmts.closeActiveEntityKey.run(valid_from_ts, entity_type, entity_id);
      }
      this._stmts.saveEntityKey.run(
        entity_type, entity_id, public_key, algorithm,
        valid_from_ts, null, source_tx_id,
      );
    })();
  }
  saveEntityKey(rec) {
    // Generalised save (used by snapshot install + KEY_ROTATED/KEY_RECOVERY
    // direct-write paths). Caller has already computed both bounds.
    this._stmts.saveEntityKey.run(
      rec.entity_type, rec.entity_id, rec.public_key,
      rec.algorithm || "ml-dsa-65",
      rec.valid_from_ts,
      rec.valid_to_ts == null ? null : rec.valid_to_ts,
      rec.source_tx_id,
    );
  }
  getActiveKey(entity_type, entity_id) {
    const r = this._stmts.getActiveEntityKey.get(entity_type, entity_id);
    return r ? { public_key: r.public_key, algorithm: r.algorithm } : null;
  }
  getKeyValidAt(entity_type, entity_id, timestamp) {
    const r = this._stmts.getKeyValidAt.get(entity_type, entity_id, timestamp, timestamp);
    return r ? { public_key: r.public_key, algorithm: r.algorithm } : null;
  }
  // Full key chain for one entity, oldest first — parity with
  // MemoryStore.getEntityKeyHistory.
  getEntityKeyHistory(entityType, entityId) {
    return this._stmts.getEntityKeyHistory.all(entityType, entityId).map(r => ({
      public_key: r.public_key,
      algorithm: r.algorithm,
      valid_from_ts: r.valid_from_ts,
      valid_to_ts: r.valid_to_ts ?? null,
      source_tx_id: r.source_tx_id ?? null,
    }));
  }
  *iterateEntityKeys() {
    for (const r of this._stmts.iterateEntityKeys.iterate()) yield r;
  }
  clearEntityKeys() { this._stmts.clearEntityKeys.run(); }

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
  // §69 — bounded iterator over certs in [fromRound, toRound] inclusive.
  // See MemoryStore version for the contract.
  *iterateCertsByRoundRange(fromRound, toRound) {
    for (const row of this._stmts.getCertsByRoundRange.iterate(fromRound, toRound)) {
      yield this._parseCert(row);
    }
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

  // ── Committee history (§4 + #34 — chain-of-trust) ─────────────────────────
  // See MemoryStore.saveCommitteeRotation for the contract. Caller is
  // responsible for sorting committee + signer_node_ids and aligning
  // signatures parallel to signer_node_ids.
  saveCommitteeRotation(rec) {
    this._stmts.saveCommitteeRotation.run(
      rec.rotation_number,
      rec.effective_round,
      JSON.stringify(rec.committee || []),
      rec.prev_rotation == null ? null : rec.prev_rotation,
      JSON.stringify(rec.signer_node_ids || []),
      JSON.stringify(rec.signatures || []),
      rec.payload_hash || null,
      rec.committed_at || nowMs(),
    );
  }
  getCommitteeRotation(rotationNumber) {
    const row = this._stmts.getCommitteeRotation.get(rotationNumber);
    return row ? this._parseRotation(row) : null;
  }
  getLatestRotation() {
    const row = this._stmts.getLatestRotation.get();
    return row ? this._parseRotation(row) : null;
  }
  getCommitteeAtRound(round) {
    const row = this._stmts.getCommitteeAtRound.get(round);
    return row ? this._parseRotation(row) : null;
  }
  *getRotationsFromGenesis() {
    for (const row of this._stmts.getRotationsFromGenesis.iterate()) {
      yield this._parseRotation(row);
    }
  }

  // ── Interests registry ─────────────────────────────────────────────────
  saveInterest(rec) {
    this._stmts.saveInterest.run(
      rec.slug,
      rec.label,
      rec.category,
      rec.registered_at,
      rec.registered_by_vp_id || null,
      rec.tx_id || null,
    );
  }
  getInterest(slug) {
    const row = this._stmts.getInterest.get(slug);
    return row ? this._parseInterest(row) : null;
  }
  getAllInterests() {
    return this._stmts.getAllInterests.all().map(r => this._parseInterest(r));
  }
  interestCount() { return this._stmts.interestCount.get().n; }
  _parseInterest(row) {
    return {
      slug: row.slug,
      label: row.label,
      category: row.category,
      registered_at: row.registered_at,
      registered_by_vp_id: row.registered_by_vp_id || null,
      tx_id: row.tx_id || null,
    };
  }

  // ── Prescan reviews ─────────────────────────────────────────────────────
  savePrescanReview(rec) {
    this._stmts.savePrescanReview.run(
      rec.review_id,
      rec.ctid,
      rec.creator_tip_id,
      rec.assigned_reviewer || null,
      rec.triggered_at_round,
      rec.triggered_at_ms == null ? null : rec.triggered_at_ms,
      rec.decided_at_round == null ? null : rec.decided_at_round,
      rec.confirmed_at_round == null ? null : rec.confirmed_at_round,
      rec.confirmed_at_ms == null ? null : rec.confirmed_at_ms,
      rec.state || PRESCAN_REVIEW_STATES.TRIGGERED,
      rec.decision_note || null,
      rec.suggested_origin || null,
    );
  }
  _hydratePrescanReview(row) {
    if (!row) return null;
    // DB column is `tip_ctid` (uniform across all backends); callers use `ctid`.
    const { tip_ctid, ...rest } = row;
    return { ...rest, ctid: tip_ctid };
  }
  getPrescanReview(reviewId) {
    return this._hydratePrescanReview(this._stmts.getPrescanReview.get(reviewId));
  }
  getOpenPrescanReviewByCtid(ctid) {
    return this._hydratePrescanReview(this._stmts.getOpenPrescanReviewByCtid.get(ctid));
  }
  getPrescanReviewsByReviewer(reviewerTipId) {
    return this._stmts.getPrescanReviewsByReviewer.all(reviewerTipId).map(r => this._hydratePrescanReview(r));
  }
  getPrescanReviewsByCtid(ctid) {
    return this._stmts.getPrescanReviewsByCtid.all(ctid).map(r => this._hydratePrescanReview(r));
  }
  getContentsNeedingReview(nowMs) {
    return this._stmts.getContentsNeedingReview.all(nowMs - CONTENT_GRACE.FLAGGED_MS).map(r => this._hydrateContent(r));
  }
  getContentsStuckInPrescan(failOpenCutoffMs) {
    return this._stmts.getContentsStuckInPrescan.all(failOpenCutoffMs).map(r => this._hydrateContent(r));
  }
  getReviewsNeedingAutoEscalation(nowMs) {
    return this._stmts.getReviewsNeedingAutoEscalation.all(nowMs - REVIEWER.CREATOR_DECISION_WINDOW_MS).map(r => this._hydratePrescanReview(r));
  }
  getReviewsNeedingAutoRecuse(nowMs) {
    return this._stmts.getReviewsNeedingAutoRecuse.all(nowMs - REVIEWER.AUTO_RECUSE_AGE_MS).map(r => this._hydratePrescanReview(r));
  }

  // #75 rotation_participation — see MemoryStore version for the contract.
  incrementRotationParticipation(nodeId, rotationNumber) {
    this._stmts.incrementRotationParticipation.run(nodeId, rotationNumber);
  }
  getRotationParticipation(rotationNumber) {
    return this._stmts.getRotationParticipation.all(rotationNumber);
  }
  pruneRotationParticipationBefore(rotationNumber) {
    return this._stmts.pruneRotationParticipationBefore.run(rotationNumber).changes;
  }
  setRotationParticipation(nodeId, rotationNumber, count) {
    this._stmts.setRotationParticipation.run(nodeId, rotationNumber, count);
  }
  deleteRotationParticipationByRotation(rotationNumber) {
    return this._stmts.deleteRotationParticipationByRotation.run(rotationNumber).changes;
  }
  _parseRotation(row) {
    if (!row) return null;
    return {
      rotation_number: row.rotation_number,
      effective_round: row.effective_round,
      committee: JSON.parse(row.committee),
      prev_rotation: row.prev_rotation == null ? null : row.prev_rotation,
      signer_node_ids: JSON.parse(row.signer_node_ids || "[]"),
      signatures: JSON.parse(row.signatures || "[]"),
      payload_hash: row.payload_hash || null,
      committed_at: row.committed_at,
    };
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
      yield { table: "identities", row: _canonIdentity(r) };
    }
    for (const r of db.prepare("SELECT * FROM content ORDER BY tip_ctid").iterate()) {
      // _hydrateContent decodes JSON columns (authors, extras, registered_urls)
      // so _canonContent sees parsed values — matching the MemoryStore path.
      // Without this, JSON columns come through as strings and _canonContent's
      // Array.isArray / typeof === "object" checks fail, emitting defaults
      // and silently forking the state_merkle_root vs MemoryStore-backed nodes.
      // Boolean/int normalization (founding, prescan_flagged, override, etc.)
      // is handled inside _canonContent/_canonIdentity via `? 1 : 0` — works
      // for both SQLite int (0/1) and MemoryStore bool (true/false).
      yield { table: "content", row: _canonContent(this._hydrateContent(r)) };
    }
    for (const r of db.prepare("SELECT tip_id, score, offense_count, last_updated FROM scores ORDER BY tip_id").iterate()) {
      yield { table: "scores", row: _canonScore(r.tip_id, r) };
    }
    for (const r of db.prepare("SELECT dedup_hash, created_at, tip_id FROM dedup_registry ORDER BY dedup_hash").iterate()) {
      yield { table: "dedup_registry", row: _canonDedup(r.dedup_hash, r.created_at, r.tip_id) };
    }
    for (const r of db.prepare("SELECT * FROM revocations ORDER BY tip_id").iterate()) {
      yield { table: "revocations", row: _canonRevocation(r) };
    }
    for (const r of db.prepare("SELECT * FROM domain_bindings ORDER BY domain").iterate()) {
      yield { table: "domain_bindings", row: _canonDomainBinding(r) };
    }
    for (const r of db.prepare("SELECT * FROM platform_links ORDER BY id").iterate()) {
      yield { table: "platform_links", row: _canonPlatformLink(r) };
    }
    for (const r of db.prepare("SELECT * FROM verification_providers ORDER BY vp_id").iterate()) {
      yield { table: "verification_providers", row: _canonVP(r) };
    }
    for (const r of db.prepare("SELECT * FROM nodes ORDER BY node_id").iterate()) {
      yield { table: "nodes", row: _canonNode(r) };
    }
    // GH #60 — entity_keys participates in state_merkle_root.
    for (const r of this._stmts.iterateEntityKeys.iterate()) {
      yield { table: "entity_keys", row: _canonEntityKey(r) };
    }
    for (const r of db.prepare("SELECT * FROM prescan_reviews ORDER BY review_id").iterate()) {
      // Hydrate first so _canonPrescanReview sees `ctid` (DB column is tip_ctid),
      // matching the content path above.
      yield { table: "prescan_reviews", row: _canonPrescanReview(this._hydratePrescanReview(r)) };
    }
    for (const r of db.prepare("SELECT * FROM interests_registry ORDER BY slug").iterate()) {
      yield { table: "interests_registry", row: _canonInterest(r) };
    }
    // #75 rotation_participation is INTENTIONALLY excluded — see MemoryStore
    // version for rationale. RP ships in its own snapshot stream below.
  }

  clearCanonicalState() {
    this.db.transaction(() => {
      this.db.prepare("DELETE FROM identities").run();
      this.db.prepare("DELETE FROM content").run();
      this.db.prepare("DELETE FROM scores").run();
      this.db.prepare("DELETE FROM dedup_registry").run();
      this.db.prepare("DELETE FROM revocations").run();
      this.db.prepare("DELETE FROM verification_providers").run();
      this.db.prepare("DELETE FROM nodes").run();
      // GH #60 — entity_keys is canonical state too.
      this.db.prepare("DELETE FROM entity_keys").run();
      this.db.prepare("DELETE FROM platform_links").run();
      // Every table that iterateCanonicalState yields MUST be cleared here,
      // otherwise leftover rows survive a snapshot install and contribute
      // to state_merkle_root → permanent Merkle divergence.
      this.db.prepare("DELETE FROM domain_bindings").run();
      this.db.prepare("DELETE FROM prescan_reviews").run();
      this.db.prepare("DELETE FROM interests_registry").run();
    })();
  }

  // RP-snapshot iterator — see MemoryStore.iterateRotationParticipationForSnapshot.
  *iterateRotationParticipationForSnapshot() {
    for (const r of this._stmts.iterateRotationParticipation.iterate()) {
      yield _canonRotationParticipation(r);
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
    this._stmts.saveMempoolTx.run(tx.tx_id, JSON.stringify(tx), subjectTipId(tx));
  }
  getMempoolTx(txId) {
    const row = this._stmts.getMempoolTx.get(txId);
    return row ? JSON.parse(row.tx_data) : null;
  }
  getMempoolTxs() {
    return this._stmts.getMempoolTxs.all().map(r => JSON.parse(r.tx_data));
  }
  getMempoolTxsByTipId(tipId) {
    // #40 — any-party match recomputed from tx data (received_at ASC order).
    return this._stmts.getMempoolTxs.all()
      .map(r => JSON.parse(r.tx_data))
      .filter(tx => subjectTipIds(tx).includes(tipId));
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

  // ── Tx Rejections (#64 follow-up — no-loss invariant) ─────────────────────
  // Mirrors MemoryStore.saveTxRejection — INSERT OR IGNORE so the first
  // observation wins. Returns true if a new row was inserted, false if
  // a row for this tx_id already existed.
  saveTxRejection(rec) {
    const at = rec.rejected_at_ms != null ? rec.rejected_at_ms : nowMs();
    // tx_data is stored as JSON text. Callers usually pass the tx
    // object; tolerate a pre-stringified value too so a future drop
    // site that already has bytes in hand can pass them through.
    const txData = rec.tx_data == null
      ? null
      : (typeof rec.tx_data === "string" ? rec.tx_data : JSON.stringify(rec.tx_data));
    // subject_tip_id derived from the tx body (when available) so the
    // activity feed can merge a user's rejected txs into their feed
    // without re-parsing JSON per row at read time.
    const subj = rec.tx_data && typeof rec.tx_data === "object"
      ? subjectTipId(rec.tx_data)
      : null;
    const res = this._stmts.saveTxRejection.run(
      rec.tx_id,
      rec.reason,
      rec.reason_detail || null,
      at,
      rec.rejected_at_round != null ? rec.rejected_at_round : null,
      rec.dropper_node_id,
      rec.tx_type || null,
      rec.origin_node_id || null,
      txData,
      subj
    );
    return res.changes > 0;
  }
  // Parse tx_data back to an object on read so consumers (outcome
  // endpoint, replay tooling) get a uniform shape across both stores.
  _parseRejectionRow(row) {
    if (!row) return null;
    return { ...row, tx_data: row.tx_data ? JSON.parse(row.tx_data) : null };
  }
  getTxRejection(txId) {
    return this._parseRejectionRow(this._stmts.getTxRejection.get(txId));
  }
  getTxRejectionsByReason(reason, opts = {}) {
    const since = opts.since != null ? opts.since : 0;
    // SQLite has no Infinity; pass -1 to mean "no limit" (LIMIT -1 returns all rows).
    const limit = opts.limit != null && Number.isFinite(opts.limit) ? opts.limit : -1;
    return this._stmts.getTxRejectionsByReason
      .all(reason, since, limit)
      .map(r => this._parseRejectionRow(r));
  }
  getTxRejectionsByTipId(tipId) {
    // #40 — recompute every party from the preserved tx body (any-party match),
    // so the counterparty of a failed dispute/appeal also sees it. Rejections
    // without a body can't be attributed (same as before).
    return this._stmts.getAllTxRejections.all()
      .map(r => this._parseRejectionRow(r))
      .filter(r => r.tx_data && subjectTipIds(r.tx_data).includes(tipId));
  }
  countTxRejections() { return this._stmts.countTxRejections.get().n; }

  // ── Dispute details (off-chain dispute body) ────────────────────────────
  // Mirrors MemoryStore.saveDisputeDetails. Idempotent on evidence_hash —
  // re-uploads of the same payload are a silent no-op.
  // ── Prescan jobs (node-local async classifier queue) ───────────────────
  _hydratePrescanJob(row) {
    if (!row) return null;
    // DB column is `tip_ctid` (uniform across all backends); callers use `ctid`.
    const { tip_ctid, ...rest } = row;
    return { ...rest, ctid: tip_ctid };
  }
  enqueuePrescanJob(rec) {
    // payload is canonical JSON; pass as-is (SQLite BLOB column).
    const res = this._stmts.enqueuePrescanJob.run(
      rec.job_id, rec.ctid, rec.payload, rec.created_at,
    );
    return res.changes > 0;
  }
  getPrescanJob(jobId) {
    return this._hydratePrescanJob(this._stmts.getPrescanJob.get(jobId));
  }
  getPrescanJobByCtid(ctid) {
    return this._hydratePrescanJob(this._stmts.getPrescanJobByCtid.get(ctid));
  }
  // ── Perceptual index writes (off-DAG, advisory) ───────────────────────────
  savePerceptualFingerprint(rec) {
    this._stmts.savePerceptualFingerprint.run(
      rec.ctid, rec.component_idx, rec.modality, rec.profile,
      rec.pipeline, rec.quality, rec.fingerprint, rec.created_at,
    );
  }
  saveMinhashBands(rows) {
    for (const r of rows) this._stmts.saveMinhashBand.run(r.profile, r.band_idx, r.band_hash, r.ctid);
  }
  savePhashCodes(rows) {
    if (!rows || !rows.length) return;
    // INSERT OR IGNORE on (ctid, component_idx, frame): a re-ingest of the same
    // content (frames are fixed per ctid) is skipped, not duplicated. Duplicate
    // frames would inflate the matchVideo overlap denominator and degrade recall.
    for (const r of rows) {
      this._stmts.savePhashCode.run(
        r.ctid, r.component_idx, r.frame, r.profile, r.modality, r.ts, r.quality, r.pdq,
        r.c0, r.c1, r.c2, r.c3, r.c4, r.c5, r.c6, r.c7,
        r.c8, r.c9, r.c10, r.c11, r.c12, r.c13, r.c14, r.c15,
      );
    }
  }
  getPerceptualFingerprint(ctid, componentIdx = 0) {
    return this._stmts.getPerceptualFingerprint.get(ctid, componentIdx) || null;
  }
  findMinhashCandidates(profile, bandHashes) {
    const ctids = new Set();
    for (let i = 0; i < bandHashes.length; i++) {
      for (const r of this._stmts.findMinhashByBand.all(profile, i, bandHashes[i])) ctids.add(r.ctid);
    }
    return [...ctids];
  }
  // Dynamic SQL (variable IN-list size); one indexed seek per chunk OR'd together.
  findPhashCandidates(profile, modality, queryKeys) {
    const conds = [];
    const params = [profile, modality];
    for (let i = 0; i < 16; i++) {
      const keys = queryKeys[i];
      conds.push(`c${i} IN (${keys.map(() => "?").join(",")})`);
      for (const k of keys) params.push(k);
    }
    const sql =
      `SELECT DISTINCT tip_ctid AS ctid, profile, modality, frame, ts, quality, pdq
         FROM phash_code
        WHERE profile=? AND modality=? AND (${conds.join(" OR ")})
        ORDER BY tip_ctid, frame, pdq`;
    return this.db.prepare(sql).all(...params);
  }
  getPhashCodesByCtid(ctid) {
    return this._stmts.getPhashCodesByCtid.all(ctid);
  }
  getOrCreateAudioClip(ctid, componentIdx, landmarkCount) {
    return this._stmts.upsertAudioClip.get(ctid, componentIdx, landmarkCount).clip_id;
  }
  saveAudioLandmarks(rows) {
    for (const r of rows) this._stmts.saveAudioLandmark.run(r.profile, r.hash, r.clip_id, r.t);
  }
  // Dynamic SQL (variable IN-list size); one indexed seek over (profile, hash).
  findAudioCandidates(profile, hashes) {
    if (!hashes || !hashes.length) return [];
    const sql =
      `SELECT clip_id, hash, t FROM audio_landmark
        WHERE profile=? AND hash IN (${hashes.map(() => "?").join(",")})
        ORDER BY clip_id, t`;
    return this.db.prepare(sql).all(profile, ...hashes);
  }
  getAudioClip(clipId) {
    return this._stmts.getAudioClip.get(clipId) || null;
  }
  claimPrescanJob({ workerId, now, claimTimeoutMs }) {
    return this._hydratePrescanJob(this._stmts.claimPrescanJob.get(now, workerId, now - claimTimeoutMs));
  }
  markPrescanJobDone(jobId, { completedAt }) {
    return this._stmts.markPrescanJobDone.run(completedAt, jobId).changes > 0;
  }
  markPrescanJobFailed(jobId, { lastError, completedAt }) {
    return this._stmts.markPrescanJobFailed.run(completedAt, lastError || null, jobId).changes > 0;
  }
  releasePrescanJobForRetry(jobId, { lastError }) {
    return this._stmts.releasePrescanJobForRetry.run(lastError || null, jobId).changes > 0;
  }

  saveDisputeDetails(rec) {
    const res = this._stmts.saveDisputeDetails.run(
      rec.evidence_hash,
      rec.disputer_tip_id,
      rec.payload_json,
      rec.signature,
      rec.local_inserted_at,
    );
    return res.changes === 1;
  }
  getDisputeDetails(hash) {
    return this._stmts.getDisputeDetails.get(hash) || null;
  }
  hasDisputeDetails(hash) {
    return !!this._stmts.hasDisputeDetails.get(hash);
  }
  deleteDisputeDetails(hash) {
    return this._stmts.deleteDisputeDetails.run(hash).changes > 0;
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

  // No-op on SQLite: better-sqlite3 writes are synchronous, so there's no
  // background queue to drain. The knex adapter overrides this for Postgres/
  // MariaDB/MSSQL/Oracle where writes go through a fire-and-forget chain.
  async flush() { /* no-op */ }

  close() {
    try { this.db.close(); } catch { /* ignore */ }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// DAG FACADE  —  single interface over either store
// ══════════════════════════════════════════════════════════════════════════════

// ─── Shared post-store-selection init (sync) ─────────────────────────────────
// Called by both initDAG (SQLite/Memory) and initDAGAsync (Knex).
// Returns the public dag API object.
function _buildDagHandle(store, config) {
  // ── Bootstrap: genesis block + founding VP ────────────────────────────────
  if (store.count() === 0) {
    _writeGenesisBlock(store, config);
  }

  // ── Bootstrap: committee_history rotation 0 (§4 + #34) ────────────────────
  // Hardcoded trust anchor for the chain-of-trust walker. Committee at
  // genesis is [founding_node] with its pubkey carried inline so a fresh
  // joiner can verify rotation 1's signatures against the local genesis
  // (NOT against the peer-provided nodes table). No signers/signatures
  // on rotation 0 — genesis IS the trust anchor.
  //
  // Run unconditionally (not gated on store.count()) so existing DBs
  // without the row get populated on the next boot. Idempotent: skips
  // if rotation 0 already exists.
  _bootstrapCommitteeRotationZero(store);

  // ── Bootstrap: interests_registry from INITIAL_INTERESTS_SEED ─────────────
  // Curated taxonomy of profile interests. Same idempotency contract as
  // rotation 0 — runs every boot, UPSERTs per slug so re-running is a
  // no-op when data matches. Genesis-seeded rows carry
  // registered_by_vp_id=null (no signing VP at genesis).
  _bootstrapInterestsRegistry(store);

  // Activity-feed denormalisation: populate `subject_tip_id` for rows
  // that pre-date the column. Idempotent — second startup matches
  // zero rows and exits immediately. Without this, existing committed
  // txs on live nodes wouldn't surface in the activity feed.
  const filled = store.backfillSubjectTipId(subjectTipId);
  const totalFilled = filled.transactions + filled.mempool + filled.tx_rejections;
  if (totalFilled > 0) {
    log.info(`DAG: backfilled subject_tip_id on ${filled.transactions} txs, ${filled.mempool} mempool, ${filled.tx_rejections} rejections`);
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
        if (!tx.timestamp) tx.timestamp = nowMs();
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
    getTxsBySubject: (tipId) => store.getTxsBySubject(tipId),
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
    listContent: (opts) => store.listContent(opts),
    // M6 — used by the periodic media-retention sweep.
    getContentWithMediaBefore: (cutoffMs) => store.getContentWithMediaBefore(cutoffMs),
    getReferencedMediaIds: () => store.getReferencedMediaIds(),
    getCleanRecordEligible: (cutoff) => store.getCleanRecordEligible(cutoff),
    hasVerification: (ctid, tipId) => store.hasVerification(ctid, tipId),
    hasDispute: (ctid, tipId) => store.hasDispute(ctid, tipId),

    // ── Scores ────────────────────────────────────────────────────────────
    setScore: (id, s, o, lastUpdatedISO) => store.setScore(id, s, o, lastUpdatedISO),
    getScore: (id) => store.getScore(id),

    // ── Dedup registry ────────────────────────────────────────────────────
    addDedupHash: (h, createdAt, tipId) => store.addDedupHash(h, createdAt, tipId),
    hasDedupHash: (h) => store.hasDedupHash(h),
    getDedupRegistration: (h) => store.getDedupRegistration(h),
    dedupCount: () => store.dedupCount(),

    // ── Canonical derived state (§14 snapshot-sync) ──────────────────────
    // Streaming iterator over all derived-state tables in deterministic
    // order. Consumed by consensus/state-root.js to hash row-by-row.
    iterateCanonicalState: () => store.iterateCanonicalState(),
    clearCanonicalState: () => store.clearCanonicalState(),

    // ── Revocations (v2 FIX-05) ───────────────────────────────────────────
    addRevocation: (id, type, ts, txId) => store.addRevocation(id, type, ts, txId),
    isRevoked: (id) => store.isRevoked(id),
    getRevocation: (id) => store.getRevocation(id),
    getRevocations: (since) => store.getRevocations(since),

    // ── Domain bindings (canonical) + pending claims (local-only) ────────
    saveDomainBinding: (rec) => store.saveDomainBinding(rec),
    getDomainBinding: (domain) => store.getDomainBinding(domain),
    getDomainBindingsByTipId: (tipId) => store.getDomainBindingsByTipId(tipId),
    getAllDomainBindings: () => store.getAllDomainBindings(),
    savePendingDomainClaim: (rec) => store.savePendingDomainClaim(rec),
    getPendingDomainClaim: (domain) => store.getPendingDomainClaim(domain),
    deletePendingDomainClaim: (domain) => store.deletePendingDomainClaim(domain),

    // ── Platform links (canonical) ────────────────────────────────────────
    savePlatformLink: (rec) => store.savePlatformLink(rec),
    updatePlatformLinkStatus: (tipId, platform, update) => store.updatePlatformLinkStatus(tipId, platform, update),
    getPlatformLink: (tipId, platform) => store.getPlatformLink(tipId, platform),
    getPlatformLinksByTipId: (tipId) => store.getPlatformLinksByTipId(tipId),

    // ── Verification Providers ────────────────────────────────────────────
    saveVP: (rec) => store.saveVP(rec),
    getVP: (id) => store.getVP(id),
    getAllVPs: () => store.getAllVPs(),

    // ── Nodes ────────────────────────────────────────────────────────────
    saveNode: (rec) => store.saveNode(rec),
    updateNodeEndpoint: (nodeId, apiEndpoint, timestamp) => store.updateNodeEndpoint(nodeId, apiEndpoint, timestamp),
    getNode: (id) => store.getNode(id),
    getAllNodes: () => store.getAllNodes(),

    // ── entity_keys (GH #60) — single source of truth for keys ──────────
    // saveEntityKey writes a fully-specified row (caller supplies both
    // valid_from_ts and valid_to_ts). For "activate this new key + close
    // the prior one" semantics use _saveActiveEntityKey via saveIdentity
    // / saveVP / saveNode (auto-route from rec.public_key + algorithm).
    // KEY_ROTATED / KEY_RECOVERY apply uses closeActiveKey + saveEntityKey
    // directly so the close + insert is one atomic pair.
    saveEntityKey: (rec) => store.saveEntityKey(rec),
    getActiveKey: (entityType, entityId) => store.getActiveKey(entityType, entityId),
    // Historical-signature verification entry. Verifiers must pass
    // tx.timestamp so the right key is selected for that point in time.
    // Returns { public_key, algorithm } or null.
    getKeyValidAt: (entityType, entityId, timestamp) => store.getKeyValidAt(entityType, entityId, timestamp),
    getEntityKeyHistory: (entityType, entityId) => store.getEntityKeyHistory(entityType, entityId),
    iterateEntityKeys: () => store.iterateEntityKeys(),
    clearEntityKeys: () => store.clearEntityKeys(),

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

    // §69 — bounded iterator over `certificates` in [fromRound, toRound]
    // inclusive, in canonical (round, author_node_id) order. Used by
    // snapshot sender to ship the K-round window of recent certs that a
    // joiner needs for runtime committee derivation. Without these certs,
    // the joiner's getActiveCommittee derives a different K-window than
    // full-history nodes for the K rounds after snapshot install.
    iterateCertsByRoundRange: (fromRound, toRound) => store.iterateCertsByRoundRange(fromRound, toRound),

    // ── Committee history (§4 + #34 — chain-of-trust) ───────────────────
    // saveCommitteeRotation: write a rotation row (idempotent on rotation_number).
    // getCommitteeAtRound: hot-path read for participants.getActiveCommittee —
    //   returns the rotation in effect at the given round (latest whose
    //   effective_round <= round). Returns null if no rotations yet.
    // getCommitteeRotation(n): direct lookup by rotation_number.
    // getLatestRotation: most recent rotation row.
    // getRotationsFromGenesis: streaming iterator in rotation_number order;
    //   used by snapshot sender + chain-of-trust walker.
    saveCommitteeRotation: (rec) => store.saveCommitteeRotation(rec),
    getCommitteeRotation: (rotationNumber) => store.getCommitteeRotation(rotationNumber),
    getLatestRotation: () => store.getLatestRotation(),
    getCommitteeAtRound: (round) => store.getCommitteeAtRound(round),
    getRotationsFromGenesis: () => store.getRotationsFromGenesis(),

    // ── Interests registry — VP-attested taxonomy of profile interests ──
    // saveInterest: INSERT OR REPLACE. Genesis seed + commit-handler are
    //   the writers. Slug is PK; authoritative re-install overwrites by PK.
    // getInterest: O(1) lookup used by UPDATE_PROFILE validation +
    //   schema verifyTx for INTEREST_REGISTERED dedup.
    // getAllInterests: full taxonomy, used by GET /v1/interests.
    saveInterest: (rec) => store.saveInterest(rec),
    getInterest: (slug) => store.getInterest(slug),
    getAllInterests: () => store.getAllInterests(),
    interestCount: () => store.interestCount(),

    // ── Prescan reviews (Phase 2 — human reviewing AI prescan flag) ─────
    // savePrescanReview: INSERT OR REPLACE. The same review_id walks through
    //   its state machine (triggered → confirmed → closed_*) via successive
    //   saves; commit-handler is the sole writer.
    // getOpenPrescanReviewByCtid: returns the in-flight review for a CTID
    //   (state ∈ {triggered, confirmed}); used by self-correction closure
    //   hook in UPDATE_ORIGIN and by reviewer-decision validators.
    savePrescanReview: (rec) => store.savePrescanReview(rec),
    getPrescanReview: (reviewId) => store.getPrescanReview(reviewId),
    getOpenPrescanReviewByCtid: (ctid) => store.getOpenPrescanReviewByCtid(ctid),
    getPrescanReviewsByReviewer: (reviewerTipId) => store.getPrescanReviewsByReviewer(reviewerTipId),
    getPrescanReviewsByCtid: (ctid) => store.getPrescanReviewsByCtid(ctid),
    getContentsNeedingReview: (nowMs) => store.getContentsNeedingReview(nowMs),
    getContentsStuckInPrescan: (cutoffMs) => store.getContentsStuckInPrescan(cutoffMs),
    getReviewsNeedingAutoEscalation: (nowMs) => store.getReviewsNeedingAutoEscalation(nowMs),
    getReviewsNeedingAutoRecuse: (nowMs) => store.getReviewsNeedingAutoRecuse(nowMs),

    // #75 rotation participation tally
    incrementRotationParticipation: (nodeId, rotationNumber) => store.incrementRotationParticipation(nodeId, rotationNumber),
    getRotationParticipation: (rotationNumber) => store.getRotationParticipation(rotationNumber),
    pruneRotationParticipationBefore: (rotationNumber) => store.pruneRotationParticipationBefore(rotationNumber),
    setRotationParticipation: (nodeId, rotationNumber, count) => store.setRotationParticipation(nodeId, rotationNumber, count),
    deleteRotationParticipationByRotation: (rotationNumber) => store.deleteRotationParticipationByRotation(rotationNumber),
    iterateRotationParticipationForSnapshot: () => store.iterateRotationParticipationForSnapshot(),

    // ── Equivocation defense: votes_seen (§1) ────────────────────────────
    recordSeenVote: (round, author, batchHash) => store.recordSeenVote(round, author, batchHash),
    getSeenVote: (round, author) => store.getSeenVote(round, author),
    pruneVotesSeenBefore: (cutoff) => store.pruneVotesSeenBefore(cutoff),

    // ── Persistent Mempool ────────────────────────────────────────────────
    saveMempoolTx: (tx) => store.saveMempoolTx(tx),
    getMempoolTx: (txId) => store.getMempoolTx(txId),
    getMempoolTxs: () => store.getMempoolTxs(),
    getMempoolTxsByTipId: (tipId) => store.getMempoolTxsByTipId(tipId),
    deleteMempoolTx: (txId) => store.deleteMempoolTx(txId),
    deleteMempoolTxs: (txIds) => store.deleteMempoolTxs(txIds),
    clearStaleMempoolTxs: (before) => store.clearStaleMempoolTxs(before),
    mempoolCount: () => store.mempoolCount(),

    // ── Tx Rejections (#64 follow-up — no-loss invariant) ───────────────
    // Per-node observation log: every tx admitted past the API but
    // dropped before commit. Combined with `transactions` it seals the
    // invariant — any tx_id the API handed back is in exactly one of
    // the two tables. Drop sites call saveTxRejection; the outcome
    // endpoint reads getTxRejection.
    saveTxRejection: (rec) => store.saveTxRejection(rec),
    getTxRejection: (txId) => store.getTxRejection(txId),
    getTxRejectionsByReason: (reason, opts) => store.getTxRejectionsByReason(reason, opts),
    getTxRejectionsByTipId: (tipId) => store.getTxRejectionsByTipId(tipId),
    countTxRejections: () => store.countTxRejections(),

    // ── Dispute details (off-chain dispute body) ────────────────────────
    saveDisputeDetails: (rec) => store.saveDisputeDetails(rec),
    getDisputeDetails: (hash) => store.getDisputeDetails(hash),
    hasDisputeDetails: (hash) => store.hasDisputeDetails(hash),
    deleteDisputeDetails: (hash) => store.deleteDisputeDetails(hash),

    // ── Prescan jobs (node-local async classifier queue) ────────────────
    enqueuePrescanJob: (rec) => store.enqueuePrescanJob(rec),
    savePerceptualFingerprint: (rec) => store.savePerceptualFingerprint(rec),
    saveMinhashBands: (rows) => store.saveMinhashBands(rows),
    savePhashCodes: (rows) => store.savePhashCodes(rows),
    getPerceptualFingerprint: (ctid, idx) => store.getPerceptualFingerprint(ctid, idx),
    findMinhashCandidates: (profile, bandHashes) => store.findMinhashCandidates(profile, bandHashes),
    findPhashCandidates: (profile, modality, queryKeys) => store.findPhashCandidates(profile, modality, queryKeys),
    getPhashCodesByCtid: (ctid) => store.getPhashCodesByCtid(ctid),
    getOrCreateAudioClip: (ctid, idx, landmarkCount) => store.getOrCreateAudioClip(ctid, idx, landmarkCount),
    saveAudioLandmarks: (rows) => store.saveAudioLandmarks(rows),
    findAudioCandidates: (profile, hashes) => store.findAudioCandidates(profile, hashes),
    getAudioClip: (clipId) => store.getAudioClip(clipId),
    getPrescanJob: (jobId) => store.getPrescanJob(jobId),
    getPrescanJobByCtid: (ctid) => store.getPrescanJobByCtid(ctid),
    claimPrescanJob: (opts) => store.claimPrescanJob(opts),
    markPrescanJobDone: (jobId, opts) => store.markPrescanJobDone(jobId, opts),
    markPrescanJobFailed: (jobId, opts) => store.markPrescanJobFailed(jobId, opts),
    releasePrescanJobForRetry: (jobId, opts) => store.releasePrescanJobForRetry(jobId, opts),

    // ── DB Transactions ──────────────────────────────────────────────────
    runInTransaction: (fn) => store.runInTransaction(fn),

    flush: () => store.flush(),
    close: () => store.close(),
  };

  return dag;
}

// ─── Sync entry point (SQLite / MemoryStore) ─────────────────────────────────
// Used by all tests and non-Knex production paths. Never await this.
function initDAG(config) {
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
  return _buildDagHandle(store, config);
}

// ─── Async entry point (Knex / SQLite / MemoryStore) ─────────────────────────
// Used by node/src/index.js. Awaits KnexAdapter.migrate() for server-side DBs;
// falls back to initDAG() for SQLite and memory paths (resolves synchronously).
async function initDAGAsync(config) {
  const { createStore } = require("./db/index");
  const store = createStore(config, log);
  if (!store) {
    // SQLite or memory — run schema migrations then use sync path.
    const dbPath = config.dbPath || process.env.TIP_SQLITE_PATH;
    if (dbPath && Database) {
      await _runSqliteMigrations(dbPath);
    }
    return initDAG(config);
  }

  // Retry up to 5 times so the node tolerates the DB container starting after
  // the node container (profiles-based compose or slow DB init).
  const MAX_ATTEMPTS = 5;
  let lastErr;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      await store.migrate();
      log.info(`DAG store: Knex (${config.dbDriver || process.env.DB_DRIVER}) @ ${config.dbName || process.env.DB_NAME || "tip_protocol"}`);
      return _buildDagHandle(store, config);
    } catch (err) {
      lastErr = err;
      if (attempt < MAX_ATTEMPTS) {
        const delaySec = attempt * 2;
        log.warn(`Knex init attempt ${attempt}/${MAX_ATTEMPTS} failed: ${err.message} — retrying in ${delaySec}s`);
        await new Promise(r => setTimeout(r, delaySec * 1000));
      }
    }
  }

  log.warn(`Knex init failed after ${MAX_ATTEMPTS} attempts (${lastErr.message}) — falling back to SQLite/memory`);
  try { store.close(); } catch { /* ignore */ }
  return initDAG(config);
}

// ─── Write genesis block and founding VP into a fresh store ──────────────────
// §4 + #34: bootstrap committee_history rotation 0 from genesis.
// Hardcoded trust anchor — committee = [founding_node + its pubkey], no
// signers/signatures (genesis IS the trust anchor). Idempotent: skips
// if rotation 0 already exists, so existing DBs get backfilled on next
// boot without writing duplicates.
//
// payload_hash format: shake256(canonical{rotation_number, effective_round, committee})
// where committee is the JSON-canonical [{node_id, public_key}] array.
// Future rotations sign over this payload_hash, so genesis is just the
// "rotation 0" payload_hash with no signatures attached.
function _bootstrapCommitteeRotationZero(store) {
  if (store.getCommitteeRotation(0)) return;  // idempotent

  const { getGenesisPayload, GENESIS_TIMESTAMP } = require("./genesis");
  const { shake256, canonicalJson } = require("../../shared/crypto");

  const payload = getGenesisPayload();
  const founding = payload && payload.founding_node;
  if (!founding || !founding.node_id || !founding.public_key) {
    throw new Error(
      "Cannot bootstrap committee rotation 0: genesis.founding_node missing node_id or public_key. " +
      "Check shared/genesis.js or the genesis payload loaded into PC.init()."
    );
  }

  const committee = [{
    node_id: founding.node_id,
    public_key: founding.public_key,
  }];

  const payload_hash = shake256(canonicalJson({
    rotation_number: 0,
    effective_round: 0,
    committee,
  }));

  store.saveCommitteeRotation({
    rotation_number: 0,
    effective_round: 0,
    committee,
    prev_rotation: null,        // genesis: no predecessor
    signer_node_ids: [],         // genesis: hardcoded trust, no sigs needed
    signatures: [],
    payload_hash,
    committed_at: GENESIS_TIMESTAMP,
  });
}

function _bootstrapInterestsRegistry(store) {
  // Skip if any caller (test, fake store) doesn't implement the registry.
  if (typeof store.saveInterest !== "function") return;
  const { INITIAL_INTERESTS_SEED } = require("../../shared/constants");
  const { GENESIS_TIMESTAMP } = require("./genesis");
  for (const entry of INITIAL_INTERESTS_SEED) {
    store.saveInterest({
      slug: entry.slug,
      label: entry.label,
      category: entry.category,
      registered_at: GENESIS_TIMESTAMP,
      registered_by_vp_id: null,     // genesis-seeded — no signing VP
      tx_id: null,
    });
  }
}

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
    // tip_id_type + creator_name come from genesis_ring_keys (seed.js
    // embeds them per-member). Defaults to "personal" / null for any
    // historical entry that pre-dates the field.
    const memberType = member.tip_id_type || "personal";
    const memberCreatorName = member.creator_name || null;
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
        tip_id_type: memberType,
        creator_name: memberCreatorName,
        social_attested: true,
        founding: true,
        dedup_hash: member.dedup_hash,
        zk_proof: mockZkProof,
      },
      // GH #51 — founding VP attestation lives at tx.signature.
      signature: member.vp_signature,
    };
    const idTxId = computeTxId(idTx);
    store.saveTx({ ...idTx, tx_id: idTxId });

    store.saveIdentity({
      tip_id: member.tip_id,
      region: member.region || "US",
      public_key: member.public_key,
      vp_id: foundingVP.vp_id,
      verification_tier: "T1",
      tip_id_type: memberType,
      creator_name: memberCreatorName,
      founding: true,
      status: "active",
      registered_at: registeredAt,
      tx_id: idTxId,
    });

    if (member.dedup_hash) {
      // Genesis bootstrap — created_at derived from the genesis timestamp
      // (same on every node that ships the same genesis). Deterministic.
      store.addDedupHash(member.dedup_hash, Math.floor(GENESIS_TIMESTAMP / 1000), member.tip_id);
    }
    // Genesis seed score — `score.initial_identity` from genesis (per
    // spec, all identities start at the same baseline; founding members
    // gain trust through subsequent score events, not via a special
    // initial value). last_updated sourced from GENESIS_TIMESTAMP so
    // every node bootstraps with an identical scores row (#31), and the
    // value matches what commit-handler writes for the same
    // REGISTER_IDENTITY tx replay (#38).
    store.setScore(member.tip_id, SCORE.INITIAL_IDENTITY, 0, GENESIS_TIMESTAMP);
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
        approving_vp_id: foundingNode.approving_vp_id,
      },
      // GH #51 — approving VP signature lives at tx.signature.
      signature: foundingNode.council_signature,
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

module.exports = { initDAG, initDAGAsync, MemoryStore, SQLiteStore };
