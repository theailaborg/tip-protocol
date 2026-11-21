/**
 * @file @tip-protocol/node/src/schemas/site-snapshot.js
 * @description Canonical schema for `SITE_SNAPSHOT`: one owner-signed record
 * per version of a whole protected website, chained per domain by seq.
 *
 * Trust model: SUBJECT-signed by the site's owner (or an active member of the
 * owning organization). An optional witness is the capturing VP's signature
 * over the same payload, carried as a VP cosignature (`witness_vp_id` +
 * `cosignatures`), outside the owner's signed bytes.
 *
 * Signed canonical payload (12 fields): ai_signals_hash, captured_at, domain,
 * page_count, pack_hash, prev_snapshot_tx (null for seq 1), profile, root,
 * seq, signer_tip_id, template_hash, wacz_hash. Every hash is SHAKE-256 hex.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError, canonicalJson, assertBounded } = require("./_common");
const { DOMAIN_SPEC } = require("./bind-domain");
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS, SITE_SNAPSHOT,
} = require("../../../shared/constants");
const { isValidMs, nowMs, toIso } = require("../../../shared/time");
const { siteSnapshotOn, SITE_SNAPSHOT_MS } = require("../validators/website-gate");
const { siteKey, liveBindingFor, mayPublishOn } = require("../validators/business-rules");

const TX_TYPE = TX_TYPES.SITE_SNAPSHOT;
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.SIGNER_TIP_ID;

const HASH_FIELDS = Object.freeze(["root", "template_hash", "wacz_hash", "pack_hash", "ai_signals_hash"]);
const TIP_ID_SPEC = Object.freeze({ field: "signer_tip_id", max: 512, pattern: /^tip:\/\/id\//, describe: "a tip://id/... string" });
const SIGNATURE_MAX = 16384;
const SIGNATURE_PATTERN = /^[0-9a-f]+$/;

// Stable prefixes: commit-handler maps them to tx_rejections reasons.
const STALE = "Snapshot is stale";
const WITNESS_INVALID = "Witness invalid";

function fail(status, error, code) {
  return { ok: false, status, error, code };
}

function throwIfFailed(r) {
  if (r && r.ok === false) throw schemaError(r.status, r.error, r.code);
}

function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  assertBounded(input.domain, { ...DOMAIN_SPEC, required: true });
  if (siteKey(input.domain) !== input.domain) {
    throw schemaError(400, "domain must be the site's name without www.", "domain_not_canonical");
  }
  if (!Number.isSafeInteger(input.seq) || input.seq < 1) {
    throw schemaError(400, "seq must be an integer >= 1", "seq_invalid");
  }
  if (!Object.prototype.hasOwnProperty.call(input, "prev_snapshot_tx")) {
    throw schemaError(400, "prev_snapshot_tx is required (null for seq 1)", "prev_snapshot_tx_required");
  }
  const prev = input.prev_snapshot_tx;
  if (input.seq === 1 ? prev !== null : (typeof prev !== "string" || !SITE_SNAPSHOT.TX_ID_PATTERN.test(prev))) {
    throw schemaError(400, "prev_snapshot_tx must be null for seq 1, otherwise the previous snapshot's tx_id", "prev_snapshot_tx_invalid");
  }
  for (const f of HASH_FIELDS) {
    if (typeof input[f] !== "string" || !SITE_SNAPSHOT.HASH_PATTERN.test(input[f])) {
      throw schemaError(400, `${f} must be 64 lowercase hex characters (SHAKE-256)`, `${f}_invalid`);
    }
  }
  if (!Number.isSafeInteger(input.page_count) || input.page_count < 1 || input.page_count > SITE_SNAPSHOT.MAX_PAGES) {
    throw schemaError(400, `page_count must be an integer from 1 to ${SITE_SNAPSHOT.MAX_PAGES}`, "page_count_invalid");
  }
  if (!SITE_SNAPSHOT.PROFILES.includes(input.profile)) {
    throw schemaError(400, `profile must be one of ${SITE_SNAPSHOT.PROFILES.join(", ")}`, "profile_invalid");
  }
  if (!isValidMs(input.captured_at)) {
    throw schemaError(400, "captured_at must be a valid epoch ms timestamp", "captured_at_invalid");
  }
  assertBounded(input.signer_tip_id, { ...TIP_ID_SPEC, required: true });
  return {
    ai_signals_hash: input.ai_signals_hash,
    captured_at: input.captured_at,
    domain: input.domain,
    page_count: input.page_count,
    pack_hash: input.pack_hash,
    prev_snapshot_tx: prev,
    profile: input.profile,
    root: input.root,
    seq: input.seq,
    signer_tip_id: input.signer_tip_id,
    template_hash: input.template_hash,
    wacz_hash: input.wacz_hash,
  };
}

function _isSignature(v) {
  return typeof v === "string" && v.length > 0 && v.length <= SIGNATURE_MAX && SIGNATURE_PATTERN.test(v);
}

/**
 * Authority, chain, rate and capture time for a well-formed payload, judged
 * at `atMs` (the API's now, or max(tx.timestamp, certificate time) at commit).
 */
function checkSnapshot(p, dag, atMs) {
  if (typeof dag.isRevoked === "function" && dag.isRevoked(p.signer_tip_id)) {
    return fail(403, `TIP-ID is revoked: ${p.signer_tip_id}`, "tip_id_revoked");
  }
  const binding = liveBindingFor(dag, p.domain, atMs);
  if (!binding) return fail(403, `${p.domain} is not a protected website`, "site_not_protected");
  if (!mayPublishOn(dag, { tip_id: binding.tip_id }, p.signer_tip_id)) {
    return fail(403, `Only the owner of ${p.domain} or a member of the owning organization can sign its snapshots`, "not_site_owner");
  }

  const latest = dag.getLatestSiteSnapshot(p.domain);
  const expectedSeq = latest ? latest.seq + 1 : 1;
  const expectedPrev = latest ? latest.tx_id : null;
  if (p.seq !== expectedSeq || p.prev_snapshot_tx !== expectedPrev) {
    return fail(409, `${STALE}: ${p.domain} expects seq ${expectedSeq} after ${expectedPrev || "none"}`, "site_snapshot_stale");
  }
  if (latest) {
    if (atMs - Number(latest.registered_at) < SITE_SNAPSHOT.MIN_INTERVAL_MS) {
      return fail(429, `A snapshot of ${p.domain} was recorded less than ${SITE_SNAPSHOT.MIN_INTERVAL_MS / 60000} minutes ago`, "site_snapshot_too_soon");
    }
    if (p.captured_at <= Number(latest.captured_at)) {
      return fail(400, "captured_at must be after the previous snapshot's", "captured_at_not_after_previous");
    }
  }
  if (p.captured_at > atMs + SITE_SNAPSHOT.CAPTURE_SKEW_MS) {
    return fail(400, "captured_at is in the future", "captured_at_in_future");
  }
  return { ok: true, binding };
}

// The witness signature itself is verified by the dispatcher through
// getCosignatureContract; this checks its shape and the VP's standing.
function checkWitness(d, dag) {
  if (d.witness_vp_id === undefined || d.witness_vp_id === null) {
    if (d.cosignatures !== undefined) {
      return fail(400, `${WITNESS_INVALID}: cosignatures without witness_vp_id`, "site_snapshot_witness_invalid");
    }
    return { ok: true };
  }
  const id = d.witness_vp_id;
  if (typeof id !== "string" || !SITE_SNAPSHOT.VP_ID_PATTERN.test(id)) {
    return fail(400, `${WITNESS_INVALID}: witness_vp_id must be a tip://vp/... id`, "site_snapshot_witness_invalid");
  }
  const c = d.cosignatures;
  if (!Array.isArray(c) || c.length !== 1 || c[0]?.signer_kind !== SIGNED_BY_KIND.VP
      || c[0]?.signer_ref !== id || !_isSignature(c[0]?.signature)) {
    return fail(400, `${WITNESS_INVALID}: expected exactly one VP cosignature by ${id}`, "site_snapshot_witness_invalid");
  }
  const vp = typeof dag.getVP === "function" ? dag.getVP(id) : null;
  if (!vp) return fail(412, `${WITNESS_INVALID}: VP not registered: ${id}`, "site_snapshot_witness_invalid");
  if (vp.status !== "active") {
    return fail(403, `${WITNESS_INVALID}: VP is not active: ${id} (status: ${vp.status})`, "site_snapshot_witness_invalid");
  }
  return { ok: true };
}

function getCosignatureContract(tx) {
  const d = tx?.data || {};
  if (d.witness_vp_id === undefined || d.witness_vp_id === null) return [];
  let body;
  try {
    body = buildSigningPayload(d);
  } catch {
    return [];   // malformed: the primary signature and verifyTx both reject it
  }
  return [{ kind: SIGNED_BY_KIND.VP, ref: d.witness_vp_id, body }];
}

/** tx.data for a signed payload and an optional witness `{ vp_id, signature }`. */
function buildTxData(payload, witness) {
  if (!witness) return { ...payload };
  return {
    ...payload,
    witness_vp_id: witness.vp_id,
    cosignatures: [{ signer_kind: SIGNED_BY_KIND.VP, signer_ref: witness.vp_id, signature: witness.signature }],
  };
}

/**
 * Request validator for POST /v1/site/snapshot.
 *
 * Body: the 12 signed fields, `signature` (the signer's, over the payload),
 * and optionally `witness: { vp_id, signature }` (the capturing VP's, over the
 * same payload). deps: { dag, now? }. Returns { payload, witness }.
 */
function validateRequest(body, deps = {}) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (!_isSignature(body.signature)) {
    throw schemaError(400, "signature is required (hex)", "signature_required");
  }
  const payload = buildSigningPayload(body);

  let witness = null;
  if (body.witness !== undefined && body.witness !== null) {
    const w = body.witness;
    if (typeof w !== "object" || typeof w.vp_id !== "string" || !SITE_SNAPSHOT.VP_ID_PATTERN.test(w.vp_id) || !_isSignature(w.signature)) {
      throw schemaError(400, "witness must be { vp_id: tip://vp/..., signature: hex }", "witness_invalid");
    }
    witness = { vp_id: w.vp_id, signature: w.signature };
  }

  const now = Number.isFinite(deps.now) ? deps.now : nowMs();
  if (!siteSnapshotOn(now)) {
    throw schemaError(409, `Site snapshots open on ${toIso(SITE_SNAPSHOT_MS)}`, "site_snapshot_not_open");
  }
  if (!deps.dag) return { payload, witness };
  const { dag } = deps;

  throwIfFailed(checkSnapshot(payload, dag, now));

  if (witness) {
    throwIfFailed(checkWitness(buildTxData(payload, witness), dag));
    const key = typeof dag.getKeyValidAt === "function" ? dag.getKeyValidAt("vp", witness.vp_id, now) : dag.getActiveKey("vp", witness.vp_id);
    if (!key || !verifyPayload(payload, witness.signature, key.public_key)) {
      throw schemaError(403, "Witness signature verification failed", "witness_invalid");
    }
  }

  if (typeof dag.getMempoolTxsByTipId === "function") {
    const pending = dag.getMempoolTxsByTipId(payload.signer_tip_id)
      .some(t => t.tx_type === TX_TYPE && t.data?.domain === payload.domain);
    if (pending) throw schemaError(409, `A snapshot of ${payload.domain} is already pending`, "site_snapshot_pending");
  }

  const identity = dag.getIdentity(payload.signer_tip_id);
  if (!identity || !identity.public_key) {
    throw schemaError(412, `Signer not registered: ${payload.signer_tip_id}`, "signer_not_registered");
  }
  if (!verifyPayload(payload, body.signature, identity.public_key)) {
    throw schemaError(403, "Signature verification failed", "signature_invalid");
  }
  return { payload, witness };
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * State-level verification at consensus replay. The signer's signature and
 * the witness cosignature are verified by the unified dispatcher.
 * opts.atMs: the commit's max(tx.timestamp, certificate time).
 */
function verifyTx(tx, dag, opts = {}) {
  const d = tx.data || {};
  const at = Number.isFinite(opts.atMs) ? opts.atMs : Number(tx.timestamp);
  if (!siteSnapshotOn(at)) {
    return fail(409, `Site snapshots open on ${toIso(SITE_SNAPSHOT_MS)}`, "site_snapshot_not_open");
  }
  let payload;
  try {
    payload = buildSigningPayload(d);
  } catch (err) {
    if (err && err.status) return fail(err.status, err.error, err.code);
    throw err;
  }
  const w = checkWitness(d, dag);
  if (!w.ok) return w;
  const s = checkSnapshot(payload, dag, at);
  return s.ok ? { ok: true } : s;
}

module.exports = {
  TX_TYPE,
  STALE,
  WITNESS_INVALID,
  validateRequest,
  buildSigningPayload,
  buildTxData,
  checkSnapshot,
  checkWitness,
  getCosignatureContract,
  sign,
  verifySignature,
  verifyTx,
  canonicalJson,
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
};
