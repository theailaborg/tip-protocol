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
const { subjectTipId } = require("./tx-attribution");
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
// never from nowMs() / unixepoch() / other local-clock sources.
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
    tip_id_type: r.tip_id_type || "personal",
    founding: r.founding ? 1 : 0,
    status: r.status,
    reviewer_consent: r.reviewer_consent ? 1 : 0,
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
    perceptual_hash: r.perceptual_hash || null,
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
    override: r.override ? 1 : 0,
    registered_at: r.registered_at,
    registered_urls: Array.isArray(r.registered_urls) ? r.registered_urls : [],
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
    dedup_hash: hash,
    created_at: createdAt != null ? String(createdAt) : null,
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
    this._committeeHistory = new Map();  // rotation_number -> rotation record (§4 + #34)
    this._rotationParticipation = new Map();  // `${node_id}|${rotation_number}` -> count (#75)
    this._prescanReviews = new Map();  // review_id -> review record (human reviewing AI prescan flag)
    this._mempool = new Map();  // tx_id -> tx
    this._txRejections = new Map();  // tx_id -> rejection record (no-loss invariant)
    this._disputeDetails = new Map();  // evidence_hash -> dispute details record (off-chain dispute body, NOT consensus state)
    this._domainBindings = new Map();  // domain -> binding record (canonical, in state_merkle_root)
    this._domainPending = new Map();  // domain -> pending claim record (local-only, NOT canonical)
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
    return [...this._txs.values()]
      .filter(t => t.subject_tip_id === tipId)
      .sort((a, b) => {
        const d = b.timestamp - a.timestamp;
        if (d !== 0) return d;
        const ap = a.tx_type === "SCORE_UPDATE" ? 0 : 1;
        const bp = b.tx_type === "SCORE_UPDATE" ? 0 : 1;
        if (ap !== bp) return ap - bp;
        return a.tx_id < b.tx_id ? 1 : -1;
      });
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
  saveVP(rec) { this._vps.set(rec.vp_id, { ...rec }); }
  getVP(vpId) { return this._vps.get(vpId) || null; }
  getAllVPs() { return [...this._vps.values()]; }

  // ── Nodes ───────────────────────────────────────────────────────────────
  saveNode(rec) { this._nodes.set(rec.node_id, { ...rec }); }
  getNode(nodeId) { return this._nodes.get(nodeId) || null; }
  getAllNodes() { return [...this._nodes.values()]; }

  clearCanonicalState() {
    this._identities.clear();
    this._content.clear();
    this._scores.clear();
    this._dedup.clear();
    if (this._dedupCreated) this._dedupCreated.clear();
    this._revocations.clear();
    this._vps.clear();
    this._nodes.clear();
  }

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
  // §69 — bounded iterator over certs in [fromRound, toRound] inclusive.
  // Yields in canonical (round, author_node_id) order — same as
  // SQLiteStore. Used by snapshot-handler to ship the K-round cert window
  // a joiner needs for runtime committee derivation.
  *iterateCertsByRoundRange(fromRound, toRound) {
    const sorted = [...this._certs.values()]
      .filter(c => c.round >= fromRound && c.round <= toRound)
      .sort((a, b) => a.round !== b.round
        ? a.round - b.round
        : a.author_node_id.localeCompare(b.author_node_id));
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
    if (this._committeeHistory.has(rec.rotation_number)) return; // idempotent like INSERT OR IGNORE
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
  // Clear all committee_history rows. Called by snapshot install before
  // re-installing the sender's rotation chain, so INSERT OR IGNORE can't
  // silently skip a corrected rotation for a rotation_number that this node
  // already had (from a divergent history after a byzantine_fork).
  clearCommitteeHistory() { this._committeeHistory.clear(); }

  // Streaming iterator over the entire chain in rotation_number order.
  // Used by snapshot sender (ship every rotation) and chain-of-trust walker.
  *getRotationsFromGenesis() {
    const sorted = [...this._committeeHistory.values()].sort((a, b) => a.rotation_number - b.rotation_number);
    for (const r of sorted) {
      yield { ...r, committee: [...r.committee], signer_node_ids: [...r.signer_node_ids], signatures: [...r.signatures] };
    }
  }

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
      if (c.prescan_tier !== "high" && c.prescan_tier !== "critical") continue;
      const registeredMs = c.registered_at ? c.registered_at : NaN;
      if (!Number.isFinite(registeredMs) || registeredMs > cutoff) continue;
      const prior = [...this._prescanReviews.values()].filter(r =>
        r.ctid === c.ctid && r.state !== PRESCAN_REVIEW_STATES.RECUSED);
      if (prior.length > 0) continue;
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
    for (const r of [...this._domainBindings.values()]
      .sort((a, b) => a.domain.localeCompare(b.domain))) {
      yield { table: "domain_bindings", row: _canonDomainBinding(r) };
    }
    for (const r of [...this._vps.values()]
      .sort((a, b) => a.vp_id.localeCompare(b.vp_id))) {
      yield { table: "verification_providers", row: _canonVP(r) };
    }
    for (const r of [...this._nodes.values()]
      .sort((a, b) => a.node_id.localeCompare(b.node_id))) {
      yield { table: "nodes", row: _canonNode(r) };
    }
    for (const r of [...this._prescanReviews.values()]
      .sort((a, b) => a.review_id.localeCompare(b.review_id))) {
      yield { table: "prescan_reviews", row: _canonPrescanReview(r) };
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
      return a.node_id.localeCompare(b.node_id);
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
      .filter(e => e.subject_tip_id === tipId)
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
      if (r.subject_tip_id === tipId) rows.push(r);
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

  // No-op for parity with SQLiteStore.backfillSubjectTipId. MemoryStore
  // writes always populate the column at save time; nothing to retrofit.
  backfillSubjectTipId(_subjectTipId) {
    return { transactions: 0, mempool: 0, tx_rejections: 0 };
  }

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
      -- subject_tip_id is a denormalised index column populated at write
      -- time from tx-attribution.subjectTipId(tx). The canonical value
      -- still lives inside the data JSON column; this column exists only
      -- to give getTxsByTipId / activity-feed queries an indexed lookup
      -- path. Nullable: org/system-level txs (VP_REGISTERED,
      -- NODE_REGISTERED, AI_CLASSIFIER_RESULT, APPEAL_RESULT) have no
      -- individual subject and never appear in any user's feed.
      CREATE TABLE IF NOT EXISTS transactions (
        tx_id              TEXT PRIMARY KEY,
        tx_type            TEXT NOT NULL,
        data               TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        prev               TEXT NOT NULL DEFAULT '[]',
        signature          TEXT,
        subject_tip_id     TEXT,
        -- local_inserted_at = this node's nowMs() when the row was
        -- written. Per-node by design. NOT in canonicalTx / tx_id /
        -- state_merkle_root. For chain-time use the timestamp column
        -- (the author-signed value bound into tx_id).
        local_inserted_at  INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
      );
      CREATE INDEX IF NOT EXISTS idx_txs_type              ON transactions(tx_type);
      CREATE INDEX IF NOT EXISTS idx_txs_ts                ON transactions(timestamp);
      CREATE INDEX IF NOT EXISTS idx_txs_local_inserted_at ON transactions(local_inserted_at);
      -- idx_txs_subject is created unconditionally below the ALTER block
      -- so existing DBs (which need ALTER TABLE first) don't fail here on
      -- a column that hasn't been added yet.

      -- ── Identities ───────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS identities (
        tip_id              TEXT PRIMARY KEY,
        region              TEXT NOT NULL DEFAULT 'US',
        public_key          TEXT NOT NULL,
        root_public_key     TEXT,
        vp_id               TEXT,
        verification_tier   TEXT NOT NULL DEFAULT 'T1',
        score_display_mode  TEXT NOT NULL DEFAULT 'TIER_ONLY',
        tip_id_type         TEXT NOT NULL DEFAULT 'personal',  -- personal | organization
        founding            INTEGER NOT NULL DEFAULT 0,
        status              TEXT NOT NULL DEFAULT 'active',
        -- Opt-in to be selected as an adjudicator across all protocol roles
        -- (Protocol Review reviewer, Stage 2 jury, Stage 3 expert panel).
        -- Runtime filters at selection time decide which role a consenting
        -- user lands in (score, content category, conflict-of-interest).
        reviewer_consent    INTEGER NOT NULL DEFAULT 0,
        registered_at INTEGER NOT NULL,
        creator_name        TEXT,
        tx_id               TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_id_vp        ON identities(vp_id);
      CREATE INDEX IF NOT EXISTS idx_id_status    ON identities(status);
      CREATE INDEX IF NOT EXISTS idx_id_type      ON identities(tip_id_type);

      -- ── Content ───────────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS content (
        ctid                TEXT PRIMARY KEY,
        origin_code         TEXT NOT NULL,
        content_hash        TEXT NOT NULL,
        perceptual_hash     TEXT,
        author_tip_id       TEXT NOT NULL,                  -- = authors[0].tip_id (primary byline) — indexed
        signer_tip_id       TEXT NOT NULL,                  -- the entity that produced the signature; differs from author in employed/hosted modes
        authors             TEXT,                            -- JSON-encoded authors[] (5-key entries per CNA-2.2)
        attribution_mode    TEXT NOT NULL DEFAULT 'self',    -- self / employed / hosted
        extras              TEXT,                            -- JSON-encoded extension data
        cna_version         TEXT NOT NULL,                   -- CNA version this content was signed under
        status              TEXT NOT NULL DEFAULT 'verified',
        dispute_count       INTEGER NOT NULL DEFAULT 0,
        verification_count  INTEGER NOT NULL DEFAULT 0,
        prescan_flagged     INTEGER NOT NULL DEFAULT 0,
        prescan_probability REAL NOT NULL DEFAULT 0,         -- raw classifier output [0.0, 1.0]
        prescan_tier        TEXT NOT NULL DEFAULT 'low',     -- low|elevated|high|critical (calibrated)
        override            INTEGER NOT NULL DEFAULT 0,      -- creator confirmed OH despite HIGH/CRITICAL warning
        registered_at INTEGER NOT NULL,
        registered_urls     TEXT,                            -- JSON-encoded string[]; index 0 is the canonical / primary URL
        tx_id               TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_content_author ON content(author_tip_id);
      CREATE INDEX IF NOT EXISTS idx_content_signer ON content(signer_tip_id);
      CREATE INDEX IF NOT EXISTS idx_content_origin ON content(origin_code);
      CREATE INDEX IF NOT EXISTS idx_content_status ON content(status);

      -- ── Trust Scores ──────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS scores (
        tip_id         TEXT PRIMARY KEY,
        score          INTEGER NOT NULL DEFAULT 500,
        offense_count  INTEGER NOT NULL DEFAULT 0,
        last_updated   INTEGER NOT NULL
      );

      -- ── Dedup registry (ZK — Poseidon field elements, never raw inputs) ──
      -- created_at is unix-seconds from tx.timestamp (the REGISTER_IDENTITY tx
      -- that introduced this dedup hash). Must NOT be a DEFAULT (unixepoch() * 1000)
      -- value — that would read the local clock and break the state_merkle_root.
      CREATE TABLE IF NOT EXISTS dedup_registry (
        dedup_hash  TEXT PRIMARY KEY,
        created_at  INTEGER NOT NULL
      );

      -- ── Revocations ───────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS revocations (
        tip_id      TEXT PRIMARY KEY,
        tx_type     TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        tx_id       TEXT NOT NULL
      );

      -- ── Domain bindings (org-only; canonical, in state_merkle_root) ──
      -- One row per verified domain. Written by commit-handler on every
      -- committed BIND_DOMAIN tx. binding_signature is the node's ML-DSA
      -- attestation over {binding_state, claim_signature, claimed_at,
      -- domain, method, node_id, tip_id, verified_at} — the canonical
      -- payload that schemas/bind-domain.verifyTx reconstructs.
      --
      -- expires_at + consecutive_failures are v2 renewal prep slots
      -- (adaptive-expiry RENEW_DOMAIN). Set at BIND commit to
      -- (verified_at + DOMAIN_HEALTHY_EXPIRY_MS, 0) and untouched until
      -- v2 ships. Including them in canonical state now avoids a second
      -- migration when the renewal scheduler lands.
      CREATE TABLE IF NOT EXISTS domain_bindings (
        domain                TEXT PRIMARY KEY,
        tip_id                TEXT NOT NULL,
        binding_state         TEXT NOT NULL,
        method                TEXT NOT NULL,
        claimed_at INTEGER NOT NULL,
        verified_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        consecutive_failures  INTEGER NOT NULL DEFAULT 0,
        node_id               TEXT NOT NULL,
        claim_signature       TEXT NOT NULL,
        binding_signature     TEXT NOT NULL,
        tx_id                 TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_dom_bind_tip_id  ON domain_bindings(tip_id);
      CREATE INDEX IF NOT EXISTS idx_dom_bind_state   ON domain_bindings(binding_state);
      CREATE INDEX IF NOT EXISTS idx_dom_bind_expires ON domain_bindings(expires_at);

      -- ── Pending domain claims (local-only; NOT in state_merkle_root) ─
      -- Stores the user-signed claim between POST /v1/domain/register
      -- and POST /v1/domain/verify. Per-node — the claim arrives at one
      -- node and verification is initiated against that same node. Once
      -- /verify succeeds and a BIND_DOMAIN tx commits, the row is removed.
      CREATE TABLE IF NOT EXISTS pending_domain_claims (
        domain      TEXT PRIMARY KEY,
        tip_id      TEXT NOT NULL,
        method      TEXT NOT NULL,
        claimed_at INTEGER NOT NULL,
        signature   TEXT NOT NULL,
        received_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_pending_dom_tip_id ON pending_domain_claims(tip_id);

      -- ── Verification Providers ────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS verification_providers (
        vp_id              TEXT PRIMARY KEY,
        name               TEXT NOT NULL,
        jurisdiction       TEXT NOT NULL DEFAULT 'US',
        jurisdiction_tier  TEXT NOT NULL DEFAULT 'green',
        public_key         TEXT,
        status             TEXT NOT NULL DEFAULT 'active',
        registered_at INTEGER NOT NULL
      );

      -- ── Nodes ───────────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS nodes (
        node_id         TEXT PRIMARY KEY,
        name            TEXT,
        public_key      TEXT NOT NULL,
        status          TEXT NOT NULL DEFAULT 'active',
        registered_at INTEGER NOT NULL
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
        timestamp         INTEGER NOT NULL DEFAULT 0,
        -- local_inserted_at = node-local write time. Chain-time for a
        -- cert is the timestamp column (BFT-Time = median of acks).
        local_inserted_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
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
        committed_at INTEGER NOT NULL,
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
        -- local_inserted_at = node-local write time. Chain-time for a
        -- commit is the committed_at column (= anchor cert's BFT-Time).
        local_inserted_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_commits_index ON commits(consensus_index);

      -- ── Committee history (§4 + #34 — chain-of-trust) ─────────────
      -- One row per committee rotation. Bootstrapped at initDAG with
      -- rotation 0 from genesis.founding_node (no sigs — hardcoded
      -- trust anchor). Every subsequent rotation requires 2f+1 sigs
      -- from the PREVIOUS committee, signed over payload_hash =
      -- shake256(canonical{rotation_number, effective_round, committee}).
      --
      -- Snapshot fast-sync ships these rows in their own stream with
      -- their own committee_history_root (separate from state_merkle_root).
      -- The joiner walks the chain forward from rotation 0 verifying
      -- each transition was signed by the previously-trusted committee.
      -- This catches the synthetic-snapshot attack: a fabricated chain
      -- collapses at the first link because the founding_node's sig
      -- can't be forged.
      --
      -- committee field schema: JSON array of { node_id, public_key }
      -- records, sorted by node_id. Carrying pubkeys IN the rotation
      -- (rather than relying on the snapshot's nodes table) is what
      -- breaks the chicken-and-egg in fresh-joiner verification — a
      -- fresh joiner anchors trust at local genesis (hardcoded
      -- founding_node + public_key in their binary) and adopts each
      -- rotation's pubkeys only after verifying its sigs against the
      -- previously-trusted committee.
      CREATE TABLE IF NOT EXISTS committee_history (
        rotation_number    INTEGER PRIMARY KEY,
        effective_round    INTEGER NOT NULL,
        committee          TEXT NOT NULL,    -- JSON [{node_id, public_key}], sorted by node_id
        prev_rotation      INTEGER,           -- NULL for rotation 0 (genesis)
        signer_node_ids    TEXT NOT NULL DEFAULT '[]',  -- JSON sorted node_ids array
        signatures         TEXT NOT NULL DEFAULT '[]',  -- JSON, parallel to signer_node_ids
        payload_hash       TEXT,              -- hex; what each signer signed
        committed_at INTEGER NOT NULL,
        -- local_inserted_at = node-local write time. Chain-time for a
        -- rotation is the committed_at column (= committing cert's
        -- BFT-Time).
        local_inserted_at  INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
      );
      CREATE INDEX IF NOT EXISTS idx_committee_history_round ON committee_history(effective_round);

      -- ── Prescan Reviews ─────────────────────────────────────────────
      -- Tracks human-reviewing-AI-flag instances. A row is created at h=48
      -- for HIGH/CRITICAL-flagged content the creator didn't self-correct.
      -- The state machine carries the review to a terminal outcome
      -- (closed_dismissed / closed_accepted_private / escalated_to_dispute
      -- / closed_self_correct). On DAG for federation consistency — any
      -- node selecting reviewers or surfacing badge state must agree.
      CREATE TABLE IF NOT EXISTS prescan_reviews (
        review_id            TEXT PRIMARY KEY,
        ctid                 TEXT NOT NULL,
        creator_tip_id       TEXT NOT NULL,
        assigned_reviewer    TEXT,                            -- NULL until REVIEW_TRIGGERED commits with the assignment
        triggered_at_round   INTEGER NOT NULL,
        triggered_at_ms      INTEGER,                          -- cert.ts ms at TRIGGERED apply; drives reviewer SLA auto-recuse
        decided_at_round     INTEGER,                          -- when reviewer DISMISSED or CONFIRMED
        confirmed_at_round   INTEGER,                          -- set on CONFIRMED; starts creator's 24h decision window
        confirmed_at_ms      INTEGER,                          -- cert.ts ms at CONFIRMED apply; drives h=R+24 auto-escalation
        state                TEXT NOT NULL DEFAULT 'triggered',
        decision_note        TEXT,                             -- reviewer's optional notes
        suggested_origin     TEXT                              -- on CONFIRMED: reviewer's recommended AA/AG/MX
      );
      CREATE INDEX IF NOT EXISTS idx_prescan_reviews_ctid ON prescan_reviews(ctid);
      CREATE INDEX IF NOT EXISTS idx_prescan_reviews_state ON prescan_reviews(state);
      CREATE INDEX IF NOT EXISTS idx_prescan_reviews_reviewer ON prescan_reviews(assigned_reviewer);

      -- ── #75 Rotation participation tally ───────────────────────────
      -- Per-author counter of "appearances in Bullshark anchors during
      -- rotation N's period". Incremented on every anchor commit (one
      -- increment for the leader, one per ack-signer). At each rotation
      -- boundary (consensus_index % COMMITTEE_ROTATION_INTERVAL_COMMITS
      -- == 0), the next rotation's committee is computed from these
      -- tallies: anyone with count >= ceil(INTERVAL_COMMITS *
      -- MIN_PARTICIPATION_PCT / 100), plus genesis members, qualifies.
      --
      -- The table is bit-identical across all nodes by Bullshark's BFT
      -- consensus property: every node sees the same anchor cert at
      -- consensus_index N (same leader, same ack_signer_ids), so every
      -- node's increments are identical, so the counters end up
      -- bit-identical, so the "qualified for next rotation?" boolean
      -- returns the same answer everywhere. This is what eliminates the
      -- §4 / #74 divergence at the source — committee derivation is
      -- now a deterministic function of BFT-attested state, not local
      -- cert-history.
      --
      -- Storage: at most active_committee_size × kept_rotations rows.
      -- For testnet (3-10 nodes, keep last 3 rotations) ~30 rows. Pruned
      -- via pruneRotationParticipationBefore. Never grows with chain
      -- length — distinct from the per-anchor logging approach we
      -- explicitly avoided (would have been ~1 GB/year).
      CREATE TABLE IF NOT EXISTS rotation_participation (
        node_id          TEXT NOT NULL,
        rotation_number  INTEGER NOT NULL,
        count            INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (node_id, rotation_number)
      );
      CREATE INDEX IF NOT EXISTS idx_rotation_participation_rotation
        ON rotation_participation(rotation_number);

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
        round              INTEGER NOT NULL,
        author             TEXT NOT NULL,
        batch_hash         TEXT NOT NULL,
        -- local_inserted_at = when this node first observed the vote.
        -- Pure operational dedup table; not in any canonical projection.
        local_inserted_at  INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        PRIMARY KEY (round, author)
      );
      CREATE INDEX IF NOT EXISTS idx_votes_round ON votes_seen(round);

      -- ── Consensus: Persistent Mempool ──────────────────────────────
      -- subject_tip_id mirrors transactions.subject_tip_id so the
      -- activity feed can show a user's still-pending txs alongside
      -- their committed ones in a single merged response.
      CREATE TABLE IF NOT EXISTS mempool (
        tx_id           TEXT PRIMARY KEY,
        tx_data         TEXT NOT NULL,
        subject_tip_id  TEXT,
        received_at     INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
      );
      -- idx_mempool_subject created unconditionally below the ALTER block.

      -- ── Tx Rejections (#64 follow-up — no-loss invariant) ─────────
      -- Records every tx that was admitted past the API layer but did
      -- not end up in transactions. Combined with the dag, this seals
      -- the invariant: every tx_id the API returned is either in the
      -- transactions table (committed) or here (dropped, with reason)
      -- — never both, never neither.
      --
      -- Per-node observation log, NOT consensus state. Each node's drop
      -- sites observe their own POV; rows intentionally diverge across
      -- nodes. Not included in state_merkle_root.
      --
      -- INSERT OR IGNORE on tx_id PK: first observation wins. Peer
      -- re-broadcast of an already-rejected tx is a silent no-op so
      -- the original (most-informative) reason is preserved.
      CREATE TABLE IF NOT EXISTS tx_rejections (
        tx_id              TEXT PRIMARY KEY,
        reason             TEXT NOT NULL,
        reason_detail      TEXT,
        rejected_at_ms     INTEGER NOT NULL,
        rejected_at_round  INTEGER,
        dropper_node_id    TEXT NOT NULL,
        tx_type            TEXT,
        origin_node_id     TEXT,
        -- Full tx body as JSON (signature, data, prev, timestamp).
        -- Populated by every drop site so a future operator-initiated
        -- replay path can re-validate and re-submit. Even terminal
        -- reasons (already_registered, equivocation) keep the body
        -- for forensics — uniform schema beats branching logic, and
        -- rejections are sparse relative to commits so storage cost
        -- is bounded.
        tx_data            TEXT,
        -- Mirrors transactions.subject_tip_id. Lets the activity feed
        -- merge a user's rejected txs with their committed + pending
        -- via one indexed query per source.
        subject_tip_id     TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_tx_rej_reason  ON tx_rejections(reason);
      CREATE INDEX IF NOT EXISTS idx_tx_rej_at      ON tx_rejections(rejected_at_ms);
      CREATE INDEX IF NOT EXISTS idx_tx_rej_origin  ON tx_rejections(origin_node_id);
      -- idx_tx_rej_subject created unconditionally below the ALTER block.

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

      -- ── Dispute details (off-chain dispute body) ──────────────────
      -- Holds the disputer-submitted description + structured evidence
      -- array, bound by evidence_hash to a CONTENT_DISPUTED tx. The hash
      -- is on-chain; the body is NOT. NOT consensus state — excluded
      -- from iterateCanonicalState / state_merkle_root. Per-node copies
      -- may legitimately diverge. INSERT OR IGNORE on evidence_hash PK
      -- keeps uploads idempotent. disputer_tip_id is stored (not
      -- derivable from signature alone) so reads can fetch the pubkey
      -- and re-verify the signature.
      CREATE TABLE IF NOT EXISTS dispute_details (
        evidence_hash      TEXT PRIMARY KEY,
        disputer_tip_id    TEXT NOT NULL,
        payload_json       TEXT NOT NULL,
        signature          TEXT NOT NULL,
        -- local_inserted_at = when this node received the evidence body.
        -- Off-chain store by design; no chain-time exists for this row.
        local_inserted_at  INTEGER NOT NULL
      );
    `);

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
           (tip_id,region,public_key,root_public_key,vp_id,
            verification_tier,tip_id_type,founding,status,reviewer_consent,
            registered_at,creator_name,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ),
      getIdentity: this.db.prepare("SELECT * FROM identities WHERE tip_id=?"),
      getAllIdentities: this.db.prepare("SELECT * FROM identities WHERE status='active'"),

      saveContent: this.db.prepare(
        `INSERT OR REPLACE INTO content
           (ctid,origin_code,content_hash,perceptual_hash,author_tip_id,signer_tip_id,
            authors,attribution_mode,extras,cna_version,
            status,prescan_flagged,prescan_probability,prescan_tier,override,
            registered_at,registered_urls,tx_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
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

      savePendingDomainClaim: this.db.prepare(
        `INSERT OR REPLACE INTO pending_domain_claims
           (domain,tip_id,method,claimed_at,signature,received_at)
         VALUES (?,?,?,?,?,?)`
      ),
      getPendingDomainClaim: this.db.prepare("SELECT * FROM pending_domain_claims WHERE domain=?"),
      deletePendingDomainClaim: this.db.prepare("DELETE FROM pending_domain_claims WHERE domain=?"),

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
      // INSERT OR IGNORE — re-applying the same rotation is a no-op so the
      // commit-handler doesn't need to dedup. getCommitteeAtRound is the
      // hot-path read used by participants.getActiveCommittee (every round).
      // SQLite picks the index on (effective_round) for the WHERE; the
      // ORDER BY rotation_number DESC LIMIT 1 narrows to the latest rotation
      // at-or-before the requested round in a single index scan.
      saveCommitteeRotation: this.db.prepare(
        `INSERT OR IGNORE INTO committee_history
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

      // Prescan-review accessors. INSERT OR REPLACE so the same row can
      // walk through its state machine (triggered → confirmed →
      // closed_accepted_private etc.) via successive saves.
      savePrescanReview: this.db.prepare(
        `INSERT OR REPLACE INTO prescan_reviews
           (review_id, ctid, creator_tip_id, assigned_reviewer,
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
        "SELECT * FROM prescan_reviews WHERE ctid=? AND state IN ('triggered','confirmed') ORDER BY triggered_at_round DESC LIMIT 1"
      ),
      getPrescanReviewsByReviewer: this.db.prepare(
        "SELECT * FROM prescan_reviews WHERE assigned_reviewer=? ORDER BY triggered_at_round DESC"
      ),
      getPrescanReviewsByCtid: this.db.prepare(
        "SELECT * FROM prescan_reviews WHERE ctid=? ORDER BY triggered_at_round DESC"
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
           ON r.ctid = c.ctid AND r.state != 'recused'
         WHERE c.status = 'registered'
           AND c.origin_code = 'OH'
           AND c.prescan_tier IN ('high','critical')
           AND r.review_id IS NULL
           AND c.registered_at <= ?`
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
  // Broad lookup via the denormalised subject_tip_id column. Includes
  // jurors, verifiers, disputers, and appellants. Powers the activity
  // feed; scoring still uses getTxsByTipId.
  getTxsBySubject(tipId) { return this._stmts.txsBySubject.all(tipId).map(r => this._parseTx(r)); }
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
      rec.tip_id_type || "personal",
      rec.founding ? 1 : 0,
      rec.status || "active",
      rec.reviewer_consent ? 1 : 0,
      rec.registered_at, rec.creator_name || null, rec.tx_id || null
    );
  }
  getIdentity(id) {
    const row = this._stmts.getIdentity.get(id);
    return row ? {
      ...row,
      founding: row.founding === 1,
      reviewer_consent: row.reviewer_consent === 1,
    } : null;
  }
  getAllIdentities() {
    return this._stmts.getAllIdentities.all().map(r => ({ ...r, founding: r.founding === 1 }));
  }

  // ── Content ───────────────────────────────────────────────────────────────
  saveContent(rec) {
    // CNA-2.2 canonical fields stored on the row: authors[],
    // attribution_mode, extras, cna_version, registered_urls. JSON-
    // encode the array/object ones; the rest are scalars.
    const urls = Array.isArray(rec.registered_urls) ? rec.registered_urls : [];
    const authors = Array.isArray(rec.authors) ? rec.authors : [];
    const extras = (rec.extras && typeof rec.extras === "object" && !Array.isArray(rec.extras)) ? rec.extras : {};
    this._stmts.saveContent.run(
      rec.ctid, rec.origin_code,
      rec.content_hash, rec.perceptual_hash || null,
      rec.author_tip_id, rec.signer_tip_id,
      JSON.stringify(authors),
      rec.attribution_mode || "self",
      JSON.stringify(extras),
      rec.cna_version,
      rec.status || "registered",
      rec.prescan_flagged ? 1 : 0,
      typeof rec.prescan_probability === "number" ? rec.prescan_probability : 0,
      rec.prescan_tier || "low",
      rec.override ? 1 : 0,
      rec.registered_at, JSON.stringify(urls), rec.tx_id || null
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
    return {
      ...row,
      registered_urls: (() => { const v = decode(row.registered_urls, []); return Array.isArray(v) ? v : []; })(),
      authors: (() => { const v = decode(row.authors, []); return Array.isArray(v) ? v : []; })(),
      extras: (() => { const v = decode(row.extras, {}); return (v && typeof v === "object" && !Array.isArray(v)) ? v : {}; })(),
    };
  }
  getContent(ctid) { return this._hydrateContent(this._stmts.getContent.get(ctid)); }
  updateContentStatus(ctid, status) { this._stmts.updateContentStatus.run(status, ctid); }
  updateContentOrigin(ctid, originCode, status) { this._stmts.updateContentOrigin.run(originCode, status, ctid); }
  getContentByAuthor(tipId) { return this._stmts.contentByAuthor.all(tipId).map(r => this._hydrateContent(r)); }
  getContentByStatus(status) { return this._stmts.contentByStatus.all(status).map(r => this._hydrateContent(r)); }
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
    this._stmts.saveVP.run(
      rec.vp_id, rec.name,
      rec.jurisdiction || "US",
      rec.jurisdiction_tier || "green",
      rec.public_key || null,
      rec.status || "active",
      rec.registered_at || nowMs()
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
      rec.registered_at || nowMs()
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
  clearCommitteeHistory() {
    this.db.prepare("DELETE FROM committee_history").run();
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
  getPrescanReview(reviewId) {
    return this._stmts.getPrescanReview.get(reviewId) || null;
  }
  getOpenPrescanReviewByCtid(ctid) {
    return this._stmts.getOpenPrescanReviewByCtid.get(ctid) || null;
  }
  getPrescanReviewsByReviewer(reviewerTipId) {
    return this._stmts.getPrescanReviewsByReviewer.all(reviewerTipId);
  }
  getPrescanReviewsByCtid(ctid) {
    return this._stmts.getPrescanReviewsByCtid.all(ctid);
  }
  getContentsNeedingReview(nowMs) {
    return this._stmts.getContentsNeedingReview.all(nowMs - CONTENT_GRACE.FLAGGED_MS);
  }
  getReviewsNeedingAutoEscalation(nowMs) {
    return this._stmts.getReviewsNeedingAutoEscalation.all(nowMs - REVIEWER.CREATOR_DECISION_WINDOW_MS);
  }
  getReviewsNeedingAutoRecuse(nowMs) {
    return this._stmts.getReviewsNeedingAutoRecuse.all(nowMs - REVIEWER.AUTO_RECUSE_AGE_MS);
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
    for (const r of db.prepare("SELECT * FROM content ORDER BY ctid").iterate()) {
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
    for (const r of db.prepare("SELECT dedup_hash, created_at FROM dedup_registry ORDER BY dedup_hash").iterate()) {
      yield { table: "dedup_registry", row: _canonDedup(r.dedup_hash, r.created_at) };
    }
    for (const r of db.prepare("SELECT * FROM revocations ORDER BY tip_id").iterate()) {
      yield { table: "revocations", row: _canonRevocation(r) };
    }
    for (const r of db.prepare("SELECT * FROM domain_bindings ORDER BY domain").iterate()) {
      yield { table: "domain_bindings", row: _canonDomainBinding(r) };
    }
    for (const r of db.prepare("SELECT * FROM verification_providers ORDER BY vp_id").iterate()) {
      yield { table: "verification_providers", row: _canonVP(r) };
    }
    for (const r of db.prepare("SELECT * FROM nodes ORDER BY node_id").iterate()) {
      yield { table: "nodes", row: _canonNode(r) };
    }
    for (const r of db.prepare("SELECT * FROM prescan_reviews ORDER BY review_id").iterate()) {
      yield { table: "prescan_reviews", row: _canonPrescanReview(r) };
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
    return this._stmts.getMempoolTxsByTipId.all(tipId).map(r => JSON.parse(r.tx_data));
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
    return this._stmts.getTxRejectionsByTipId
      .all(tipId)
      .map(r => this._parseRejectionRow(r));
  }
  countTxRejections() { return this._stmts.countTxRejections.get().n; }

  // ── Dispute details (off-chain dispute body) ────────────────────────────
  // Mirrors MemoryStore.saveDisputeDetails. Idempotent on evidence_hash —
  // re-uploads of the same payload are a silent no-op.
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
    clearCommitteeHistory: () => store.clearCommitteeHistory(),
    getCommitteeRotation: (rotationNumber) => store.getCommitteeRotation(rotationNumber),
    getLatestRotation: () => store.getLatestRotation(),
    getCommitteeAtRound: (round) => store.getCommitteeAtRound(round),
    getRotationsFromGenesis: () => store.getRotationsFromGenesis(),

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

    // ── DB Transactions ──────────────────────────────────────────────────
    runInTransaction: (fn) => store.runInTransaction(fn),

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
    // SQLite or memory — use the sync path (already wrapped in Promise by async)
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
      store.addDedupHash(member.dedup_hash, Math.floor(GENESIS_TIMESTAMP / 1000));
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

module.exports = { initDAG, initDAGAsync, MemoryStore };
