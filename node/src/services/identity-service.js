"use strict";

const {
  shake256, generateTIPID, verifyTxId,
} = require("../../../shared/crypto");
const { verifyDedupProof } = require("../../../shared/zk");
const { TX_TYPES, TX_TYPE_SET } = require("../../../shared/constants");
const { SCORE } = require("../../../shared/protocol-constants");
const registerIdentitySchema = require("../schemas/register-identity");
const { schemaError, verifyPayload } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const { validate } = require("../middleware/validate");
const { log } = require("../logger");

const ACTIVITY_DEFAULT_LIMIT = 50;
const ACTIVITY_MAX_LIMIT = 200;

// Statuses the activity feed can include. Default is "committed" only —
// preserves back-compat for clients that pre-date the no-loss work.
const ACTIVITY_STATUSES = Object.freeze(["committed", "pending", "rejected"]);

function parseActivityQuery(query) {
  let limit = ACTIVITY_DEFAULT_LIMIT;
  if (query.limit !== undefined) {
    const n = Number(query.limit);
    if (!Number.isInteger(n) || n < 1 || n > ACTIVITY_MAX_LIMIT) {
      throw { status: 400, error: `limit must be an integer between 1 and ${ACTIVITY_MAX_LIMIT}` };
    }
    limit = n;
  }

  let before = null;
  if (query.before) {
    const t = Date.parse(query.before);
    if (Number.isNaN(t)) throw { status: 400, error: "before must be a valid ISO 8601 timestamp" };
    before = new Date(t).toISOString();
  }

  let types = null;
  if (query.types) {
    const list = String(query.types).split(",").map(s => s.trim()).filter(Boolean);
    const invalid = list.filter(t => !TX_TYPE_SET.has(t));
    if (invalid.length) throw { status: 400, error: `Unknown tx_type(s): ${invalid.join(", ")}` };
    if (list.length) types = new Set(list);
  }

  // ?include=committed,pending,rejected — opt-in to merge pending +
  // rejected streams into the feed. Default = committed only so
  // existing clients see no behavior change.
  let include = new Set(["committed"]);
  if (query.include) {
    const list = String(query.include).split(",").map(s => s.trim()).filter(Boolean);
    const invalid = list.filter(s => !ACTIVITY_STATUSES.includes(s));
    if (invalid.length) throw { status: 400, error: `Unknown status(es): ${invalid.join(", ")}. Allowed: ${ACTIVITY_STATUSES.join(", ")}` };
    include = new Set(list);
  }

  return { limit, before, types, include };
}

// Project a raw tx into a UI-shaped activity item: trims tx-internal fields
// (signatures, prev refs, dedup_hash, zk_proof) that the timeline doesn't
// need, surfaces the role this tip_id played in the tx, and keeps ctid +
// origin_code / status / delta / reason where present so the UI can render
// "Registered content X", "Verified Y", "Score +5 for Z" without a second call.
//
// `status` here is the lifecycle status (committed | pending | rejected),
// distinct from the `data.status` field on some tx types — the UI needs
// both so it can render "Pending: Verify content X" or
// "Rejected: Identity already registered".
function projectActivityItem(tx, tipId, status, extra = {}) {
  const d = tx.data || {};
  // Broader role set now that activity includes verifier/juror/etc. We
  // surface the single most-specific role for display; the UI can
  // ignore it but the field name lets a feed renderer template differently.
  let role = "other";
  if (d.tip_id === tipId) role = "subject";
  // signer_tip_id is the CNA-2.2 canonical field on REGISTER_CONTENT;
  // author_tip_id remains the field name on UPDATE_ORIGIN /
  // CONTENT_RETRACTED / ADJUDICATION_RESULT. Both map to the "author"
  // role for activity-feed display purposes.
  else if (d.signer_tip_id === tipId || d.author_tip_id === tipId) role = "author";
  else if (d.verifier_tip_id === tipId) role = "verifier";
  else if (d.disputer_tip_id === tipId) role = "disputer";
  else if (d.juror_tip_id === tipId) role = "juror";
  else if (d.appellant_tip_id === tipId) role = "appellant";

  return {
    tx_id: tx.tx_id,
    tx_type: tx.tx_type,
    timestamp: tx.timestamp,
    status,                                            // committed | pending | rejected
    role,
    ctid: d.ctid || null,
    origin_code: d.origin_code || null,
    data_status: d.status || null,                     // tx.data.status (verified/disputed/etc.)
    delta: typeof d.delta === "number" ? d.delta : null,
    reason: d.reason || null,
    related_tx_id: d.related_tx_id || null,
    ...extra,                                          // rejection-only fields injected by caller
  };
}

function createIdentityService({ dag, scoring, config, submitTx }) {

  async function register(body) {
    // Single envelope gate — schemas/register-identity owns shape + DAG
    // presence (VP must exist and be active). Spec: §1 of the
    // register-identity schema module.
    registerIdentitySchema.validateRequest(body, { dag });

    const {
      public_key, dedup_hash, zk_proof, vp_id, vp_signature,
    } = body;

    const { valid, error } = rules.canRegisterIdentity(dag, { dedup_hash, vp_id });
    if (!valid) {
      const code = error.message.startsWith("Identity already") ? "DUPLICATE_IDENTITY" : error.code;
      throw schemaError(error.status, error.message, code);
    }

    // Build the canonical signed payload, verify the VP's signature
    // over it. canonicalPayload is also written verbatim onto tx.data
    // (mirroring CNA-2.2 content-register pattern) so commit-handler
    // can replay buildSigningPayload(d) deterministically.
    const canonicalPayload = registerIdentitySchema.buildSigningPayload(body);
    const vp = registerIdentitySchema.resolveVP(vp_id, dag);
    if (!registerIdentitySchema.verifySignature(canonicalPayload, vp_signature, vp.public_key)) {
      throw schemaError(403, "VP signature verification failed", "signature_invalid");
    }

    const proofValid = await verifyDedupProof(dedup_hash, zk_proof);
    if (!proofValid) throw schemaError(400, "ZK proof verification failed", "zk_proof_invalid");

    const tipId = generateTIPID(canonicalPayload.region, public_key);
    const registeredAt = new Date().toISOString();
    const founding = false;

    const txBody = {
      tx_type: TX_TYPES.REGISTER_IDENTITY, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: {
        // ── Server-derived / tx-level fields ──────────────────────
        tip_id: tipId,
        vp_signature,
        founding,
        // ── Signed canonical fields (mirror canonicalPayload so
        //    commit-handler can replay buildSigningPayload(d))
        creator_name:      canonicalPayload.creator_name,
        dedup_hash:        canonicalPayload.dedup_hash,
        public_key:        canonicalPayload.public_key,
        region:            canonicalPayload.region,
        social_attested:   canonicalPayload.social_attested,
        tip_id_type:       canonicalPayload.tip_id_type,
        verification_tier: canonicalPayload.verification_tier,
        vp_id:             canonicalPayload.vp_id,
        zk_proof:          canonicalPayload.zk_proof,
      },
    };
    const signedTx = withTxId(txBody);

    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(signedTx);
    log.info(`Identity proposed: ${tipId} (type: ${canonicalPayload.tip_id_type}, tier: ${canonicalPayload.verification_tier}, vp: ${vp_id})`);

    // Note: direct dag.saveIdentity / addDedupHash / setScore happen in
    // commit-handler when the tx commits via consensus. API returns 202-style
    // "proposed" so client knows to expect async finalization.
    return {
      tip_id: tipId, public_key, tx_id: signedTx.tx_id,
      tip_id_type: canonicalPayload.tip_id_type,
      score: SCORE.INITIAL_IDENTITY, registered_at: registeredAt,
      confirmation: "proposed",
      ...(canonicalPayload.creator_name ? { creator_name: canonicalPayload.creator_name } : {}),
    };
  }

  function resolve(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const scoreData = scoring.getScore(tipId);
    const content = dag.getContentByAuthor(tipId);
    const revoked = dag.isRevoked(tipId);
    const tx = rec.tx_id ? dag.getTx(rec.tx_id) : null;
    const txValid = tx ? verifyTxId(tx) : false;
    const prevValid = tx && tx.prev ? tx.prev.every(p => !!dag.getTx(p)) : false;

    return {
      tip_id: rec.tip_id, region: rec.region, public_key: rec.public_key,
      vp_id: rec.vp_id, verification_tier: rec.verification_tier, founding: rec.founding,
      status: revoked ? "revoked" : rec.status, score: scoreData.score,
      tier: scoreData.tier.name, tier_color: scoreData.tier.color,
      content_count: content.length, registered_at: rec.registered_at,
      creator_name: rec.creator_name || null,
      verification: { tx_exists: !!tx, tx_id_valid: txValid, prev_valid: prevValid, on_dag: true },
    };
  }

  // Ownership-proof: client signs the canonical payload { challenge, tip_id }
  // (alphabetical key order, SHAKE-256 → ASCII-hex bytes → ML-DSA-65) —
  // same canonical-payload pattern the rest of the protocol uses.
  //
  // Binding `tip_id` into the signed bytes prevents a signature from being
  // replayed against a different TIP-ID (the old raw-challenge signing
  // had no such binding — a captured signature was valid for any TIP-ID
  // sharing the public key).
  function verifyOwnership(body) {
    validate(body, { tip_id: { required: true }, challenge: { required: true }, signature: { required: true } });
    const { tip_id, challenge, signature } = body;

    const identity = dag.getIdentity(tip_id);
    if (!identity) throw schemaError(404, "TIP-ID not found", "tip_id_not_found");
    if (dag.isRevoked(tip_id)) throw schemaError(403, "TIP-ID is revoked", "tip_id_revoked");

    const canonicalPayload = { challenge, tip_id };
    const valid = verifyPayload(canonicalPayload, signature, identity.public_key);
    if (!valid) throw schemaError(403, "Signature verification failed — you do not own this TIP-ID", "signature_invalid");

    const scoreData = scoring.getScore(tip_id);
    return {
      verified: true,
      tip_id,
      tip_id_type:       identity.tip_id_type || "personal",
      verification_tier: identity.verification_tier || "T1",
      region:            identity.region || "US",
      vp_id:             identity.vp_id || null,
      founding:          !!identity.founding,
      creator_name:      identity.creator_name || null,
      score:             scoreData.score,
      tier:              scoreData.tier.name,
      status:            identity.status,
    };
  }

  function getScore(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const { score, tier, offense_count } = scoring.getScore(tipId);
    const displayMode = rec.score_display_mode || "TIER_ONLY";

    return {
      tip_id: tipId, tier: tier.name, tier_label: tier.label, tier_color: tier.color,
      verified_since: rec.registered_at, content_count: dag.getContentByAuthor(tipId).length,
      status: dag.isRevoked(tipId) ? "revoked" : rec.status,
      creator_name: rec.creator_name || null,
      ...(displayMode === "FULL_PUBLIC" ? { score, offense_count } : {}),
    };
  }

  function getHistory(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const { score, tier, offense_count, history } = scoring.computeScore(tipId);
    return {
      tip_id: tipId, creator_name: rec.creator_name || null,
      score, tier: tier.name, offense_count, history,
    };
  }

  // Full per-identity activity feed: every tx where tipId played any
  // role (subject, author, verifier, disputer, juror, appellant) as
  // attributed by tx-attribution.subjectTipId. Distinct from getHistory()
  // which returns only score-affecting txs filtered through
  // `scoreTargetTipId` (narrower — only tip_id || author_tip_id).
  //
  // ?include=committed,pending,rejected merges in still-pending and
  // dropped txs from the mempool + tx_rejections tables so the UI can
  // show one consolidated "what happened to my submissions" view.
  // Default = committed only for back-compat.
  function getActivity(tipId, query = {}) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const { limit, before, types, include } = parseActivityQuery(query);
    const beforeMs = before ? new Date(before).getTime() : null;
    const inWindow = (ts) => beforeMs == null || new Date(ts).getTime() < beforeMs;
    const typeAllowed = (t) => !types || types.has(t);

    // Collect items from each requested stream. Each item carries its
    // lifecycle status so the UI can render appropriately.
    const items = [];

    if (include.has("committed")) {
      for (const tx of dag.getTxsBySubject(tipId)) {
        if (!typeAllowed(tx.tx_type)) continue;
        if (!inWindow(tx.timestamp)) continue;
        items.push(projectActivityItem(tx, tipId, "committed"));
      }
    }

    if (include.has("pending") && typeof dag.getMempoolTxsByTipId === "function") {
      for (const tx of dag.getMempoolTxsByTipId(tipId)) {
        if (!typeAllowed(tx.tx_type)) continue;
        if (!inWindow(tx.timestamp)) continue;
        items.push(projectActivityItem(tx, tipId, "pending"));
      }
    }

    if (include.has("rejected") && typeof dag.getTxRejectionsByTipId === "function") {
      for (const row of dag.getTxRejectionsByTipId(tipId)) {
        if (!typeAllowed(row.tx_type)) continue;
        // Rejected rows carry their own timestamp surrogate
        // (rejected_at_ms). Use the original tx timestamp when the
        // body is preserved (typical case); fall back to rejection
        // wall-clock so the entry still slots into the timeline.
        const tx = row.tx_data || { tx_id: row.tx_id, tx_type: row.tx_type, timestamp: new Date(row.rejected_at_ms).toISOString(), data: {} };
        if (!inWindow(tx.timestamp)) continue;
        items.push(projectActivityItem(tx, tipId, "rejected", {
          reason: row.reason,
          reason_detail: row.reason_detail,
          rejected_at: row.rejected_at_ms,
          rejected_at_round: row.rejected_at_round,
        }));
      }
    }

    // Canonical activity order — strict reverse-chronological:
    //   1. timestamp DESC                  — newer batch on top
    //   2. SCORE_UPDATE before anchor       — within a same-batch tie, the
    //                                         side-effect shows above its
    //                                         trigger because it's the
    //                                         logically-latest event in the
    //                                         causal chain ("latest on top"
    //                                         applies uniformly)
    //   3. tx_id DESC                       — final deterministic tie-break,
    //                                         stable across calls
    // Same rule mirrored in MemoryStore.getTxsBySubject and the SQL
    // ORDER BY — single source of truth.
    items.sort((a, b) => {
      const d = new Date(b.timestamp) - new Date(a.timestamp);
      if (d !== 0) return d;
      const ap = a.tx_type === "SCORE_UPDATE" ? 0 : 1;
      const bp = b.tx_type === "SCORE_UPDATE" ? 0 : 1;
      if (ap !== bp) return ap - bp;
      return a.tx_id < b.tx_id ? 1 : -1;
    });

    const total = items.length;
    const page = items.slice(0, limit);
    const nextCursor = page.length === limit && total > limit
      ? page[page.length - 1].timestamp
      : null;

    return {
      tip_id: tipId,
      creator_name: rec.creator_name || null,
      total,
      count: page.length,
      next_cursor: nextCursor,
      items: page,
    };
  }

  return { register, resolve, verifyOwnership, getScore, getHistory, getActivity };
}

module.exports = { createIdentityService };
