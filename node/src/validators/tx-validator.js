/**
 * @file @tip-protocol/node/src/validators/tx-validator.js
 * @description Production-grade transaction validator.
 *
 * Every transaction entering the DAG passes through this validator.
 * Invalid transactions are rejected with a detailed error.
 *
 * Validation layers:
 *   1. Schema validation  — required fields, types, value ranges
 *   2. Semantic validation — business rule enforcement
 *   3. Cryptographic validation — signature verification
 *   4. DAG integrity — prev[] references exist and are valid
 *   5. State validation — identity exists, not revoked, etc.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { mldsaVerify, canonicalTx, verifyTxId } = require("../../../shared/crypto");
const {
  TX_TYPES, TX_TYPE_SET, ORIGIN,
  CNA_VERSIONS, ATTRIBUTION_MODE_VALUES, TIP_ID_TYPE_VALUES,
  DOMAIN_VERIFICATION_METHOD_VALUES, DOMAIN_UNBIND_REASON_VALUES,
} = require("../../../shared/constants");
const { isValidDomain } = require("../schemas/register-domain");
const { PLATFORM_MAX_LENGTH: LINK_PLATFORM_MAX_LENGTH } = require("../schemas/link-platform");
const unlinkPlatformSchema = require("../schemas/unlink-platform");
const { getFoundingVP, getGenesisCommittee, getGenesisRing } = require("../genesis");
const { nowMs, isValidMs } = require("../../../shared/time");
const { SOCIAL_LINK } = require("../../../shared/protocol-constants");

// Validator accepts every tx type from the shared frozen set plus the
// "GENESIS" pseudo-type used only for the genesis bootstrap row, which
// isn't a regular tx and therefore isn't in TX_TYPES.
const KNOWN_TX_TYPES = new Set([...TX_TYPE_SET, "GENESIS"]);
const BOOTSTRAP_ONLY_TX_TYPES = new Set(["GENESIS"]);

// ─── Validation result helper ─────────────────────────────────────────────────
function pass() { return { valid: true, errors: [] }; }
function fail(...errors) { return { valid: false, errors }; }

// ─── Schema rules per transaction type ────────────────────────────────────────
const SCHEMA = {
  [TX_TYPES.REGISTER_IDENTITY]: {
    required: ["tip_id", "region", "public_key", "vp_id", "verification_tier", "dedup_hash", "zk_proof"],
    types: { tip_id: "string", region: "string", public_key: "string", vp_id: "string", dedup_hash: "string" },
  },
  [TX_TYPES.REGISTER_CONTENT]: {
    // CNA-2.2 wire contract — every field below MUST be on tx.data so
    // commit-handler can replay `buildSigningPayload(d, d.content_hash)`
    // deterministically. Deep validation (authors[] entry shape,
    // attribution_mode enum, registered_urls/extras types) is enforced
    // in validateBusinessRules below. Spec: docs/CONTENT_SIGNING.md.
    // GH #51: tx.signature carries the signer's signature; not a data field.
    required: [
      "ctid", "origin_code", "content_hash", "signer_tip_id",
      "cna_version", "authors",
    ],
    types: {
      ctid: "string", origin_code: "string", content_hash: "string",
      signer_tip_id: "string", cna_version: "string",
    },
  },
  [TX_TYPES.CONTENT_VERIFIED]: {
    required: ["ctid", "verifier_tip_id", "weighted_delta"],
    types: { ctid: "string", verifier_tip_id: "string" },
  },
  [TX_TYPES.BIND_DOMAIN]: {
    // Wire contract — every field is on tx.data so commit-handler can
    // replay bindDomainSchema.buildSigningPayload(d) deterministically.
    // Node attestation at tx.signature; user's claim cosig at
    // tx.data.cosignatures (verified by schema verifyTx).
    required: [
      "binding_state", "claimed_at", "domain", "method",
      "node_id", "tip_id", "verified_at",
    ],
    types: {
      binding_state: "string", claimed_at: "number",
      domain: "string", method: "string", node_id: "string", tip_id: "string",
      verified_at: "number",
    },
  },
  [TX_TYPES.UNBIND_DOMAIN]: {
    // GH #51: signature at tx.signature, not tx.data.unbind_signature.
    required: ["domain", "node_id", "reason", "revoked_at"],
    types: {
      domain: "string", node_id: "string", reason: "string",
      revoked_at: "number",
    },
  },
  [TX_TYPES.CONTENT_DISPUTED]: {
    required: ["ctid"],
    types: { ctid: "string" },
  },
  [TX_TYPES.ADJUDICATION_RESULT]: {
    // confirmed_origin is only present for UPHELD verdicts (it's the
    // jury's confirmed actual origin); DISMISSED / CONSERVATIVE_LABEL /
    // NO_QUORUM all leave it null. Don't require it across all verdicts.
    required: ["ctid", "declared_origin", "verdict"],
    types: { ctid: "string", verdict: "string" },
  },
  [TX_TYPES.SCORE_UPDATE]: {
    // `score_after` is no longer required at build-time. With #15, the
    // delta is applied by commit-handler against current cache state at
    // commit time — the producer doesn't (and shouldn't) know what the
    // post-state will be. The cache mutation lives in the SCORE_UPDATE
    // case of `_applyDerivedState`. If `score_after` is present we still
    // sanity-check its range (back-compat with legacy in-line writes).
    required: ["tip_id", "delta", "reason"],
    types: { tip_id: "string", delta: "number", score_after: "number" },
  },
  [TX_TYPES.REVOKE_VOLUNTARY]: {
    required: ["tip_id"],
    types: { tip_id: "string" },
  },
  [TX_TYPES.REVOKE_VP]: {
    required: ["tip_id", "reason_code", "evidence_hash", "issuing_vp_id"],
    types: { tip_id: "string", issuing_vp_id: "string" },
  },
  [TX_TYPES.REVOKE_DECEASED]: {
    required: ["tip_id", "issuing_vp_id"],
    types: { tip_id: "string" },
  },
  [TX_TYPES.REVOKE_DEVICE]: {
    required: ["tip_id"],
    types: { tip_id: "string" },
  },
  [TX_TYPES.VP_REGISTERED]: {
    required: ["vp_id", "name", "jurisdiction_tier", "public_key"],
    types: { vp_id: "string", name: "string" },
  },
  [TX_TYPES.UPDATE_PROFILE]: {
    // Sparse update — only `tip_id` is structurally required on data.
    // GH #51: subject's signature lives at tx.signature, not tx.data.
    // Preference field presence + types are enforced by
    // schemas/update-profile.validateRequest at API time and the
    // unified dispatcher at consensus replay. At least one known
    // preference field must be present; that check lives in the
    // schema module.
    required: ["tip_id"],
    types: { tip_id: "string" },
  },
  [TX_TYPES.PRESCAN_REVIEW_TRIGGERED]: {
    // Node-emitted system tx. Signature lives at tx.signature, not on
    // tx.data — so structure check covers only data fields. Deeper
    // validation in schemas/prescan-review-triggered.verifyTx.
    required: ["review_id", "ctid", "creator_tip_id", "assigned_reviewer_tip_id", "node_id", "triggered_at_round"],
    types: {
      review_id: "string", ctid: "string", creator_tip_id: "string",
      assigned_reviewer_tip_id: "string", node_id: "string",
      triggered_at_round: "number",
    },
  },
  [TX_TYPES.PRESCAN_REVIEW_DISMISSED]: {
    // GH #51: reviewer's signature lives at tx.signature, not tx.data.
    required: ["review_id", "reviewer_tip_id"],
    types: { review_id: "string", reviewer_tip_id: "string" },
  },
  [TX_TYPES.PRESCAN_REVIEW_RECUSED]: {
    // review_id is always required. reviewer_tip_id is user-recuse only;
    // node-emitted auto-recuse (data.auto = true) carries node_id
    // instead. Both paths sign via tx.signature; the schema module's
    // getSignatureContract branches on data.auto.
    required: ["review_id"],
    types: { review_id: "string" },
  },
  [TX_TYPES.PRESCAN_REVIEW_CONFIRMED]: {
    // GH #51: reviewer's signature lives at tx.signature, not tx.data.
    required: ["review_id", "reviewer_tip_id", "suggested_origin"],
    types: {
      review_id: "string", reviewer_tip_id: "string",
      suggested_origin: "string",
    },
  },
  [TX_TYPES.COMMITTEE_ROTATION]: {
    // Chain-of-trust rotation event. Deeper validation (rotation_number
    // monotonic, sigs from previous committee, ≥2f+1 quorum) lives in
    // commit-handler — those checks need DAG state and can't run in the
    // structure-only layer here. Aggregate sigs ride on
    // tx.data.cosignatures (signer_kind=node, signer_ref=node_id).
    required: ["rotation_number", "effective_round", "new_committee", "payload_hash", "cosignatures"],
    types: { rotation_number: "number", effective_round: "number", payload_hash: "string" },
  },
  // GH #60 — key rotation + VP-attested recovery. Signature lives at
  // tx.signature (OLD key signs KEY_ROTATED; VP signs KEY_RECOVERY).
  [TX_TYPES.KEY_ROTATED]: {
    required: ["tip_id", "new_public_key", "old_key_fingerprint", "effective_at"],
    types: {
      tip_id: "string", new_public_key: "string",
      old_key_fingerprint: "string", effective_at: "number",
    },
  },
  [TX_TYPES.KEY_RECOVERY]: {
    required: ["tip_id", "vp_id", "new_public_key", "recovery_evidence_hash", "replaces_pubkey", "effective_at", "zk_proof", "new_key_signature"],
    types: {
      tip_id: "string", vp_id: "string", new_public_key: "string",
      recovery_evidence_hash: "string", replaces_pubkey: "string",
      effective_at: "number", zk_proof: "object", new_key_signature: "string",
    },
  },
  // Interest taxonomy registry — VP-attested. Slug uniqueness + VP-active
  // + category-enum enforced at commit time by
  // schemas/interest-registered.verifyTx.
  [TX_TYPES.INTEREST_REGISTERED]: {
    required: ["category", "label", "slug", "approving_vp_id"],
    types: { slug: "string", label: "string", category: "string", approving_vp_id: "string" },
  },
};

// ─── Layer 1: Base structure ──────────────────────────────────────────────────
function validateStructure(tx) {
  const errors = [];

  if (!tx || typeof tx !== "object") { return fail("Transaction must be a non-null object"); }
  // (covered by null check above)
  if (!tx.tx_id) errors.push("tx_id is required");
  if (!tx.tx_type) errors.push("tx_type is required");
  if (!tx.timestamp) errors.push("timestamp is required");
  if (!tx.data || typeof tx.data !== "object") errors.push("data must be a non-null object");
  if (!Array.isArray(tx.prev)) errors.push("prev must be an array");

  if (errors.length) return fail(...errors);

  // tx_id: non-empty string; if hex must be 16-64 lowercase hex chars
  if (typeof tx.tx_id !== "string" || tx.tx_id.length < 8) {
    errors.push("tx_id must be a non-empty string (min 8 chars)");
  } else if (!tx.tx_id.startsWith("genesis") && !/^[0-9a-f]{64}$/.test(tx.tx_id)) {
    errors.push(`tx_id must be 64-char lowercase hex (SHAKE-256), got: "${tx.tx_id}"`);
  }

  // Timestamp must be a valid epoch ms integer
  if (!isValidMs(tx.timestamp)) {
    errors.push(`timestamp must be a valid epoch ms integer: ${tx.timestamp}`);
  } else if (tx.timestamp > nowMs() + 60_000) {
    // Must not be in the future (allow 60s clock skew)
    errors.push(`Transaction timestamp is in the future: ${tx.timestamp}`);
  }

  // tx_type must be a known type
  if (!KNOWN_TX_TYPES.has(tx.tx_type)) {
    errors.push(`Unknown tx_type: "${tx.tx_type}". Known types: ${[...KNOWN_TX_TYPES].join(", ")}`);
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Layer 2: Schema validation ───────────────────────────────────────────────
function validateSchema(tx) {
  const schema = SCHEMA[tx.tx_type];
  if (!schema) return pass(); // No schema defined — allow (e.g. GENESIS)

  const errors = [];

  // Check required fields
  for (const field of schema.required) {
    if (tx.data[field] === undefined || tx.data[field] === null || tx.data[field] === "") {
      errors.push(`Missing required field: data.${field}`);
    }
  }

  // Check types
  for (const [field, expectedType] of Object.entries(schema.types || {})) {
    if (tx.data[field] !== undefined && typeof tx.data[field] !== expectedType) {
      errors.push(`Field data.${field} must be ${expectedType}, got ${typeof tx.data[field]}`);
    }
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Layer 3: Business rules ──────────────────────────────────────────────────
function validateBusinessRules(tx, dag = null) {
  const errors = [];
  const d = tx.data;

  if (dag && dag.getLatestRound() > 1) {
    if (BOOTSTRAP_ONLY_TX_TYPES.has(tx.tx_type)) {
      return fail(`${tx.tx_type} is a bootstrap-only tx and cannot enter via gossip after round 1`);
    }
    if (tx.tx_type === TX_TYPES.VP_REGISTERED && d.vp_id === getFoundingVP().vp_id) {
      return fail(`VP_REGISTERED for the founding VP cannot enter via gossip after round 1`);
    }
    if (tx.tx_type === TX_TYPES.NODE_REGISTERED && getGenesisCommittee().has(d.node_id)) {
      return fail(`NODE_REGISTERED for founding node ${d.node_id} cannot enter via gossip after round 1`);
    }
    if (tx.tx_type === TX_TYPES.REGISTER_IDENTITY && getGenesisRing().has(d.tip_id)) {
      return fail(`REGISTER_IDENTITY for founding identity ${d.tip_id} cannot enter via gossip after round 1`);
    }
  }

  switch (tx.tx_type) {

    case TX_TYPES.REGISTER_IDENTITY: {
      // Founding members come only from genesis_ring (seed script), never from API transactions
      if (d.founding === true) {
        errors.push("founding flag cannot be set via transactions — founding members are defined in the genesis block");
      }
      // TIP-ID format: tip://id/[REGION]-[16hex]
      if (d.tip_id && !/^tip:\/\/id\/[A-Z]{2,}-[0-9a-f]{16}$/.test(d.tip_id)) {
        errors.push(`Invalid TIP-ID format: "${d.tip_id}". Expected: tip://id/[REGION]-[16hex]`);
      }
      // Verification tier must be T1–T4
      if (d.verification_tier && !["T1", "T2", "T3", "T4"].includes(d.verification_tier)) {
        errors.push(`Invalid verification_tier: "${d.verification_tier}". Must be T1, T2, T3, or T4`);
      }
      // dedup_hash must be a decimal string (BN128 field element from Poseidon circuit)
      if (d.dedup_hash && !/^\d{1,78}$/.test(d.dedup_hash)) {
        errors.push(`dedup_hash must be a decimal field element string (Poseidon output)`);
      }
      // tip_id_type, if present, must be in the canonical enum
      if (d.tip_id_type !== undefined && !TIP_ID_TYPE_VALUES.includes(d.tip_id_type)) {
        errors.push(`tip_id_type must be one of: ${TIP_ID_TYPE_VALUES.join(", ")}`);
      }
      // zk_proof must be a Groth16 proof object
      if (d.zk_proof !== undefined) {
        if (typeof d.zk_proof !== "object" || Array.isArray(d.zk_proof)) {
          errors.push(`zk_proof must be a Groth16 proof object`);
        } else if (!d.zk_proof.pi_a || !d.zk_proof.pi_b || !d.zk_proof.pi_c) {
          errors.push(`zk_proof must have pi_a, pi_b, pi_c fields`);
        }
      }
      break;
    }

    case TX_TYPES.REGISTER_CONTENT: {
      // CTID format: tip://c/[OH|AA|AG|MX]-[14hex]-[4hex]
      if (d.ctid && !/^tip:\/\/c\/(OH|AA|AG|MX)-[0-9a-f]{14}-[0-9a-f]{4}$/.test(d.ctid)) {
        errors.push(`Invalid CTID format: "${d.ctid}". Expected: tip://c/[ORIGIN]-[14hex]-[4hex]`);
      }
      // Origin code must be valid
      if (d.origin_code && !Object.keys(ORIGIN).includes(d.origin_code)) {
        errors.push(`Invalid origin_code: "${d.origin_code}". Must be OH, AA, AG, or MX`);
      }
      // Content hash must be 64-char hex (full SHAKE-256)
      if (d.content_hash && !/^[0-9a-f]{64}$/.test(d.content_hash)) {
        errors.push(`content_hash must be a 64-char hex string`);
      }
      // CNA version check (docs/CONTENT_SIGNING.md §13). Accept any
      // whitelisted CNA version so historical txs keep verifying after
      // a CNA bump.
      const supportedVersions = CNA_VERSIONS.REGISTER_CONTENT.versions;
      if (d.cna_version && !supportedVersions.includes(d.cna_version)) {
        errors.push(`Unsupported cna_version: "${d.cna_version}". Must be one of: ${supportedVersions.join(", ")}.`);
      }
      // authors[] must be a non-empty array of objects with tip://id/... tip_id
      if (d.authors !== undefined) {
        if (!Array.isArray(d.authors) || d.authors.length === 0) {
          errors.push("authors[] must be a non-empty array");
        } else {
          for (const a of d.authors) {
            if (!a || typeof a !== "object"
              || typeof a.tip_id !== "string"
              || !a.tip_id.startsWith("tip://id/")) {
              errors.push("authors[] entry must be an object with a tip://id/... tip_id");
              break;
            }
          }
        }
      }
      // attribution_mode (optional on tx.data — buildSigningPayload defaults
      // to "self"; if present here it MUST be in the canonical enum).
      if (d.attribution_mode !== undefined
        && !ATTRIBUTION_MODE_VALUES.includes(d.attribution_mode)) {
        errors.push(
          `Invalid attribution_mode: "${d.attribution_mode}". Must be one of: ${ATTRIBUTION_MODE_VALUES.join(", ")}`,
        );
      }
      // registered_urls (optional, default []): must be array of strings if present
      if (d.registered_urls !== undefined) {
        if (!Array.isArray(d.registered_urls)
          || d.registered_urls.some(u => typeof u !== "string")) {
          errors.push("registered_urls must be an array of strings");
        }
      }
      // extras (optional, default {}): must be a plain object if present
      if (d.extras !== undefined
        && (d.extras === null || typeof d.extras !== "object" || Array.isArray(d.extras))) {
        errors.push("extras must be an object (use {} for empty)");
      }
      break;
    }

    case TX_TYPES.SCORE_UPDATE: {
      // Score must be in valid range
      if (d.score_after !== undefined && (d.score_after < 0 || d.score_after > 1000)) {
        errors.push(`score_after must be 0–1000, got ${d.score_after}`);
      }
      if (d.link_tx_id) {
        const linkedTx = dag.getTx(d.link_tx_id);
        if (!linkedTx) {
          return { valid: false, errors: [`SCORE_UPDATE: linked LINK_PLATFORM tx not committed: ${d.link_tx_id}`] };
        }
      }
      break;
    }

    case TX_TYPES.BIND_DOMAIN: {
      if (d.tip_id && !d.tip_id.startsWith("tip://id/")) {
        errors.push(`tip_id must be a tip://id/... string`);
      }
      if (d.node_id && !d.node_id.startsWith("tip://node/")) {
        errors.push(`node_id must be a tip://node/... string`);
      }
      // Same regex normalizeDomain uses at API time. Mirrors the registry
      // pattern (or loopback in dev mode). Without this, a gossiped tx
      // with a garbage `domain` value reaches signature verification
      // before failing with an unhelpful diagnostic.
      if (d.domain && !isValidDomain(d.domain)) {
        errors.push(`domain must be a valid hostname: "${d.domain}"`);
      }
      if (d.method && !DOMAIN_VERIFICATION_METHOD_VALUES.includes(d.method)) {
        errors.push(`method must be one of: ${DOMAIN_VERIFICATION_METHOD_VALUES.join(", ")}`);
      }
      // binding_state on a committed BIND_DOMAIN tx is always "verified".
      // (Locally-computed states pending_verification / verification_failed
      // never reach the DAG.)
      if (d.binding_state && d.binding_state !== "verified") {
        errors.push(`BIND_DOMAIN binding_state must be "verified"`);
      }
      // Epoch ms + logical ordering. The node observes proof at verified_at
      // AFTER the user signed at claimed_at — reversed order indicates
      // either a clock skew exploit or a malformed tx.
      if (d.claimed_at !== undefined && !isValidMs(d.claimed_at)) {
        errors.push(`claimed_at must be a valid epoch ms timestamp`);
      }
      if (d.verified_at !== undefined && !isValidMs(d.verified_at)) {
        errors.push(`verified_at must be a valid epoch ms timestamp`);
      }
      if (isValidMs(d.claimed_at) && isValidMs(d.verified_at) && d.verified_at < d.claimed_at) {
        errors.push(`verified_at must not precede claimed_at`);
      }
      break;
    }

    case TX_TYPES.UNBIND_DOMAIN: {
      if (d.node_id && !d.node_id.startsWith("tip://node/")) {
        errors.push(`node_id must be a tip://node/... string`);
      }
      if (d.domain && !isValidDomain(d.domain)) {
        errors.push(`domain must be a valid hostname: "${d.domain}"`);
      }
      if (d.reason && !DOMAIN_UNBIND_REASON_VALUES.includes(d.reason)) {
        errors.push(`reason must be one of: ${DOMAIN_UNBIND_REASON_VALUES.join(", ")}`);
      }
      if (d.revoked_at !== undefined && !isValidMs(d.revoked_at)) {
        errors.push(`revoked_at must be a valid epoch ms timestamp`);
      }
      break;
    }

    case TX_TYPES.ADJUDICATION_RESULT: {
      // VERDICT names per shared/constants.js — UPHELD / DISMISSED /
      // CONSERVATIVE_LABEL / NO_QUORUM. The legacy v1 list (CLEARED,
      // OH_CONFIRMED_AG, ...) was inherited from before VERDICT was
      // centralised in shared/constants.js — this validator never fired
      // in production because ADJUDICATION_RESULT was written directly
      // by jury.js without going through commit-handler validation. Now
      // that #13 routes it through consensus, the list must match.
      const validVerdicts = ["UPHELD", "DISMISSED", "CONSERVATIVE_LABEL", "NO_QUORUM", "FACTUAL_FALSEHOOD"];
      if (d.verdict && !validVerdicts.includes(d.verdict)) {
        errors.push(`Invalid verdict: "${d.verdict}". Valid verdicts: ${validVerdicts.join(", ")}`);
      }
      break;
    }

    case TX_TYPES.VP_REGISTERED: {
      const validTiers = ["green", "amber"];
      if (d.jurisdiction_tier && !validTiers.includes(d.jurisdiction_tier)) {
        errors.push(`Invalid jurisdiction_tier: "${d.jurisdiction_tier}". VPs in red-tier jurisdictions cannot be accredited.`);
      }
      // VP-ID format
      if (d.vp_id && !d.vp_id.startsWith("tip://vp/")) {
        errors.push(`VP ID must start with "tip://vp/"`);
      }
      break;
    }

    case TX_TYPES.UPDATE_PROFILE: {
      // TIP-ID format check; deeper structural validation (strict-schema,
      // per-field types, at-least-one-field) lives in
      // schemas/update-profile.validateRequest at API time and
      // verifyTx at consensus replay.
      if (d.tip_id && !/^tip:\/\/id\/[A-Z]{2,}-[0-9a-f]{16}$/.test(d.tip_id)) {
        errors.push(`Invalid TIP-ID format: "${d.tip_id}". Expected: tip://id/[REGION]-[16hex]`);
      }
      break;
    }

    case TX_TYPES.LINK_PLATFORM: {
      if (typeof d.tip_id !== "string" || d.tip_id.length === 0) {
        errors.push("LINK_PLATFORM: tip_id is required");
      }
      if (typeof d.platform !== "string" || d.platform.length === 0) {
        errors.push("LINK_PLATFORM: platform is required");
      } else if (d.platform.length > LINK_PLATFORM_MAX_LENGTH) {
        errors.push(`LINK_PLATFORM: platform must be <= ${LINK_PLATFORM_MAX_LENGTH} chars`);
      }
      if (typeof d.profile_url !== "string" || !d.profile_url.startsWith("https://")) {
        errors.push("LINK_PLATFORM: profile_url is required (https:// URL)");
      }
      if (!Array.isArray(d.cosignatures) || d.cosignatures.length === 0) {
        errors.push("LINK_PLATFORM: cosignatures[] is required (subject claim sig)");
      }
      if (typeof d.node_id !== "string" || d.node_id.length === 0) {
        errors.push("LINK_PLATFORM: node_id is required");
      }
      if (errors.length > 0) break;

      const identity = dag.getIdentity(d.tip_id);
      if (!identity) {
        errors.push(`Cannot link platform: TIP-ID not found: ${d.tip_id}`);
        break;
      }

      const existingLink = dag.getPlatformLink(d.tip_id, d.platform);
      if (existingLink && existingLink.status === "active") {
        errors.push(`Platform "${d.platform}" already linked for ${d.tip_id}`);
      }
      break;
    }

    case TX_TYPES.UNLINK_PLATFORM: {
      // SUBJECT-signed: 4 canonical fields. No claim_signature flat field,
      // no node_id (user signs body directly; tx.signature carries the sig).
      // link_tx_id binds the signature to a specific LINK instance —
      // defeats replay against a re-linked active row.
      if (typeof d.tip_id !== "string" || d.tip_id.length === 0) {
        errors.push("UNLINK_PLATFORM: tip_id is required");
      }
      if (typeof d.platform !== "string" || d.platform.length === 0) {
        errors.push("UNLINK_PLATFORM: platform is required");
      }
      if (typeof d.link_tx_id !== "string" || d.link_tx_id.length === 0) {
        errors.push("UNLINK_PLATFORM: link_tx_id is required");
      }
      if (typeof d.claimed_at !== "number" || !Number.isFinite(d.claimed_at)) {
        errors.push("UNLINK_PLATFORM: claimed_at is required");
      }
      if (errors.length > 0) break;

      const link = dag.getPlatformLink(d.tip_id, d.platform);
      if (!link || link.status !== "active") {
        errors.push(`Platform "${d.platform}" is not actively linked for ${d.tip_id}`);
      } else if (link.tx_id !== d.link_tx_id) {
        errors.push(`UNLINK_PLATFORM: link_tx_id does not match active link instance for (${d.tip_id}, ${d.platform})`);
      }
      break;
    }

    case TX_TYPES.PRESCAN_REVIEW_TRIGGERED:
    case TX_TYPES.PRESCAN_REVIEW_DISMISSED:
    case TX_TYPES.PRESCAN_REVIEW_CONFIRMED:
    case TX_TYPES.PRESCAN_REVIEW_RECUSED: {
      // Format checks for ids present on each. Existence + state-machine
      // gating happens in the per-tx schema module's verifyTx.
      if (d.ctid && !/^tip:\/\/c\/(OH|AA|AG|MX)-[0-9a-f]{14}-[0-9a-f]{4}$/.test(d.ctid)) {
        errors.push(`Invalid CTID format: "${d.ctid}"`);
      }
      if (d.creator_tip_id && !/^tip:\/\/id\/[A-Z]{2,}-[0-9a-f]{16}$/.test(d.creator_tip_id)) {
        errors.push(`Invalid creator_tip_id format: "${d.creator_tip_id}"`);
      }
      if (d.reviewer_tip_id && !/^tip:\/\/id\/[A-Z]{2,}-[0-9a-f]{16}$/.test(d.reviewer_tip_id)) {
        errors.push(`Invalid reviewer_tip_id format: "${d.reviewer_tip_id}"`);
      }
      if (d.assigned_reviewer_tip_id && !/^tip:\/\/id\/[A-Z]{2,}-[0-9a-f]{16}$/.test(d.assigned_reviewer_tip_id)) {
        errors.push(`Invalid assigned_reviewer_tip_id format: "${d.assigned_reviewer_tip_id}"`);
      }
      if (tx.tx_type === TX_TYPES.PRESCAN_REVIEW_CONFIRMED
        && d.suggested_origin
        && !["AA", "AG", "MX"].includes(d.suggested_origin)) {
        errors.push(`Invalid suggested_origin: "${d.suggested_origin}". Must be one of: AA, AG, MX`);
      }
      break;
    }
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Layer 4: Cryptographic validation ────────────────────────────────────────
function validateCryptography(tx, authorPublicKey) {
  // Signature is optional in some internal flows (scheduler, etc.)
  if (!tx.signature || !authorPublicKey) return pass();

  // For SCORE_UPDATE and system transactions, skip sig check
  const skipSigTypes = new Set([
    TX_TYPES.SCORE_UPDATE,
    TX_TYPES.CONTENT_DISPUTED,
    "GENESIS",
  ]);
  if (skipSigTypes.has(tx.tx_type)) return pass();

  try {
    const valid = mldsaVerify(canonicalTx(tx), tx.signature, authorPublicKey);
    return valid ? pass() : fail("Signature verification failed — transaction may have been tampered with");
  } catch (err) {
    return fail(`Cryptographic verification error: ${err.message}`);
  }
}

// ─── Layer 5: DAG integrity ───────────────────────────────────────────────────
// When skipPrevCheck is true, prev-reference existence is not required. Used
// during sync replay: the tx's authenticity is already guaranteed by the BFT
// cert wrapping it, and some non-consensus writers (scheduler, scoring, jury)
// insert txs directly into the DAG without broadcasting them — see issue #13.
function validateDAGIntegrity(tx, dag, skipPrevCheck = false) {
  const errors = [];

  // tx_id must match content — detects any field-level tampering
  if (!verifyTxId(tx)) {
    errors.push(`tx_id does not match transaction content — transaction may have been tampered with`);
  }

  // Only system txs can have empty prev. GENESIS bootstraps the chain;
  // COMMITTEE_ROTATION is a system event — its tamper-evidence is the
  // 2f+1 committee sigs over payload_hash + chain-of-trust walker over
  // committee_history.prev_rotation, NOT user-tx prev refs. Coupling
  // rotation to a specific genesis tx_id breaks across DB-drifted
  // federations where peer DBs disagree on the genesis row.
  if (!tx.prev || tx.prev.length === 0) {
    if (tx.tx_type !== "GENESIS" && tx.tx_type !== TX_TYPES.COMMITTEE_ROTATION) {
      errors.push("Non-system tx must have prev references");
    }
    return errors.length ? { valid: false, errors } : pass();
  }

  // All prev references must exist in DAG (skipped during sync replay)
  if (!skipPrevCheck) {
    for (const prevId of tx.prev) {
      if (!prevId) { errors.push("Empty prev reference"); continue; }
      if (!dag.getTx(prevId)) {
        errors.push(`prev reference not found in DAG: ${prevId}`);
      }
    }
  }

  // Duplicate tx_id check
  if (!tx.tx_id.startsWith("genesis")) {
    const existing = dag.getTx(tx.tx_id);
    if (existing) {
      errors.push(`Duplicate tx_id: ${tx.tx_id} already exists in DAG`);
    }
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Layer 6: State validation (business state) ───────────────────────────────
function validateState(tx, dag) {
  const errors = [];
  const d = tx.data;

  switch (tx.tx_type) {

    case TX_TYPES.REGISTER_IDENTITY: {
      // TIP-ID must not already exist
      if (d.tip_id && dag.getIdentity(d.tip_id)) {
        errors.push(`TIP-ID already registered: ${d.tip_id}`);
      }
      // VP must exist and be active
      if (d.vp_id) {
        const vp = dag.getVP(d.vp_id);
        if (!vp) {
          errors.push(`VP not found: ${d.vp_id}. Register the VP before issuing identities.`);
        } else if (vp.status !== "active") {
          errors.push(`VP is not active: ${d.vp_id} (status: ${vp.status})`);
        }
      }
      break;
    }

    case TX_TYPES.REGISTER_CONTENT: {
      // Signer must exist on the DAG and not be revoked. Single
      // canonical signing path (CNA-2.2 per docs/CONTENT_SIGNING.md);
      // off-DAG signers are rejected at the API layer with 412
      // signer_not_registered, so a tx reaching this validator with an
      // unknown signer_tip_id indicates a malformed submission.
      if (d.signer_tip_id) {
        const identity = dag.getIdentity(d.signer_tip_id);
        if (!identity) {
          errors.push(`Signer TIP-ID not found: ${d.signer_tip_id}`);
        } else if (dag.isRevoked(d.signer_tip_id)) {
          errors.push(`Signer TIP-ID is revoked and cannot register content: ${d.signer_tip_id}`);
        }
      }
      // CTID must not already exist
      if (d.ctid && dag.getContent(d.ctid)) {
        errors.push(`CTID already registered: ${d.ctid}`);
      }
      break;
    }

    case TX_TYPES.CONTENT_VERIFIED:
    case TX_TYPES.CONTENT_DISPUTED: {
      // Content must exist
      if (d.ctid && !dag.getContent(d.ctid)) {
        errors.push(`Content not found: ${d.ctid}`);
      }
      break;
    }

    case TX_TYPES.REVOKE_VP:
    case TX_TYPES.REVOKE_VOLUNTARY:
    case TX_TYPES.REVOKE_DECEASED:
    case TX_TYPES.REVOKE_DEVICE: {
      // Target identity must exist
      if (d.tip_id && !dag.getIdentity(d.tip_id)) {
        errors.push(`Cannot revoke: TIP-ID not found: ${d.tip_id}`);
      }
      // Cannot double-revoke
      if (d.tip_id && dag.isRevoked(d.tip_id)) {
        errors.push(`TIP-ID is already revoked: ${d.tip_id}`);
      }
      break;
    }

    case TX_TYPES.UPDATE_PROFILE: {
      // Subject identity must exist + not be revoked. Deeper checks
      // (per-field types, at-least-one-field, strict-schema) live in
      // schemas/update-profile.verifyTx and validateRequest.
      if (d.tip_id && !dag.getIdentity(d.tip_id)) {
        errors.push(`Cannot update profile: TIP-ID not found: ${d.tip_id}`);
      }
      if (d.tip_id && dag.isRevoked(d.tip_id)) {
        errors.push(`Cannot update profile: TIP-ID is revoked: ${d.tip_id}`);
      }
      break;
    }

    case TX_TYPES.LINK_PLATFORM: {
      if (d.tip_id && dag.isRevoked(d.tip_id)) {
        errors.push(`TIP-ID is revoked: ${d.tip_id}`);
      }
      break;
    }

    case TX_TYPES.UNLINK_PLATFORM: {
      if (d.tip_id && dag.isRevoked(d.tip_id)) {
        errors.push(`TIP-ID is revoked: ${d.tip_id}`);
      }
      break;
    }

    case TX_TYPES.PRESCAN_REVIEW_TRIGGERED: {
      // Content must exist. Creator + reviewer existence checked in the
      // schema's verifyTx; node-existence + signature also there.
      if (d.ctid && !dag.getContent(d.ctid)) {
        errors.push(`Cannot trigger review: content not found: ${d.ctid}`);
      }
      // No duplicate open review per CTID (scheduler guards this too,
      // but consensus-replay must enforce). A nodes that emits a second
      // trigger after another node already triggered is byzantine.
      if (d.ctid) {
        const existing = dag.getOpenPrescanReviewByCtid(d.ctid);
        if (existing && existing.review_id !== d.review_id) {
          errors.push(`Cannot trigger review: an open review already exists for ${d.ctid} (review_id=${existing.review_id})`);
        }
      }
      break;
    }

    case TX_TYPES.PRESCAN_REVIEW_DISMISSED:
    case TX_TYPES.PRESCAN_REVIEW_CONFIRMED:
    case TX_TYPES.PRESCAN_REVIEW_RECUSED: {
      // Review existence + reviewer-assignment + state checks live in
      // schemas/prescan-review-*.resolveReview. This layer only does
      // identity-existence sanity.
      if (d.reviewer_tip_id && !dag.getIdentity(d.reviewer_tip_id)) {
        errors.push(`Reviewer TIP-ID not found: ${d.reviewer_tip_id}`);
      }
      break;
    }

    case TX_TYPES.PRESCAN_COMPLETED: {
      // Content row must exist (REGISTER_CONTENT applied first) — but
      // network reordering can deliver PRESCAN_COMPLETED before the
      // REGISTER_CONTENT for the same ctid. Commit-handler's apply
      // case is idempotent and defers gracefully, but at validate time
      // we reject so the tx returns to mempool and is reattempted next
      // round. node-existence + tier/probability consistency are checked
      // in schemas/prescan-completed.verifyTx via the unified dispatcher.
      if (d.ctid && !dag.getContent(d.ctid)) {
        errors.push(`Cannot apply PRESCAN_COMPLETED: content not found: ${d.ctid}`);
      }
      break;
    }
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Master validator ─────────────────────────────────────────────────────────

/**
 * Validate a transaction through all layers.
 *
 * @param {Object} tx                The transaction to validate
 * @param {Object} dag               The DAG store (for state/integrity checks)
 * @param {Object} [options]
 * @param {string} [options.authorPublicKey]  For signature verification
 * @param {boolean} [options.skipCrypto]      Skip crypto layer (for internal/system txs)
 * @param {boolean} [options.skipState]       Skip state layer (for sync from peers)
 * @param {boolean} [options.skipPrevCheck]   Skip prev-reference existence check (sync replay;
 *                                            chain integrity guaranteed by the BFT cert instead)
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
function validateTransaction(tx, dag, options = {}) {
  const { authorPublicKey, skipCrypto = false, skipState = false, skipPrevCheck = false } = options;

  // Layer 1: Structure
  const structResult = validateStructure(tx);
  if (!structResult.valid) {
    return { valid: false, errors: structResult.errors, layer: "structure" };
  }

  // Layer 2: Schema
  const schemaResult = validateSchema(tx);
  if (!schemaResult.valid) {
    return { valid: false, errors: schemaResult.errors, layer: "schema" };
  }

  // Layer 3: Business rules
  const businessResult = validateBusinessRules(tx, dag);
  if (!businessResult.valid) {
    return { valid: false, errors: businessResult.errors, layer: "business_rules" };
  }

  // Layer 4: Cryptography — removed. Node tx-level signature no longer used.
  // Body signatures (author/VP/verifier) are verified at the API endpoint level.
  // Node auth is at the gossip transport layer (challenge-response).

  // Layer 5: DAG integrity
  const dagResult = validateDAGIntegrity(tx, dag, skipPrevCheck);
  if (!dagResult.valid) {
    return { valid: false, errors: dagResult.errors, layer: "dag_integrity" };
  }

  // Layer 6: State validation (optional skip for peer sync)
  if (!skipState) {
    const stateResult = validateState(tx, dag);
    if (!stateResult.valid) {
      return { valid: false, errors: stateResult.errors, layer: "state" };
    }
  }

  return { valid: true, errors: [], layer: null };
}

module.exports = {
  validateTransaction,
  validateStructure,
  validateSchema,
  validateBusinessRules,
  validateCryptography,
  validateDAGIntegrity,
  validateState,
};
