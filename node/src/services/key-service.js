"use strict";

const { nowMs } = require("../../../shared/time");
const { TX_TYPES, SIGNATURE_ALGORITHM_DEFAULT } = require("../../../shared/constants");
const { verifyDedupProof } = require("../../../shared/zk");
const keyRotatedSchema = require("../schemas/key-rotated");
const keyRecoverySchema = require("../schemas/key-recovery");
const { schemaError } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const { withTxId } = require("./helpers");
const { log } = require("../logger");

// Canonical body fields per schema (alphabetical, mirrors buildSigningPayload).
const KEY_ROTATED_FIELDS = ["algorithm", "effective_at", "new_public_key", "old_key_fingerprint", "tip_id"];
const KEY_RECOVERY_FIELDS = ["algorithm", "new_public_key", "recovery_evidence_hash", "replaces_pubkey", "tip_id", "vp_id", "zk_proof"];

function _normaliseAlgorithm(value) {
  return value == null ? SIGNATURE_ALGORITHM_DEFAULT : value;
}

function _pickTxData(body, fields) {
  const out = {};
  for (const f of fields) out[f] = body[f];
  return out;
}

const keyHistorySchema = require("../schemas/key-history");

function createKeyService({ dag, submitTx }) {

  // KEY_ROTATED — user proves possession of CURRENT (OLD) key by signing
  // the canonical body with it. Time-anchored dispatcher (`getKeyValidAt`
  // at tx.timestamp) resolves the OLD key for verification because the
  // OLD row is still active at tx.timestamp (< effective_at). commit-
  // handler closes the OLD row and appends the NEW one atomically.
  function rotateKey(body) {
    const normalised = (body && typeof body === "object")
      ? { ...body, algorithm: _normaliseAlgorithm(body.algorithm) }
      : body;

    keyRotatedSchema.validateRequest(normalised, { dag });

    // Resolve OLD key (still active at API time — the rotation hasn't
    // committed yet). API-side signature check is fail-fast UX; consensus
    // replays the verification via the unified dispatcher.
    const oldKey = dag.getActiveKey("identity", normalised.tip_id);
    if (!oldKey || !oldKey.public_key) {
      throw schemaError(412, "no active key on file for tip_id", "no_active_key");
    }

    const canonicalPayload = keyRotatedSchema.buildSigningPayload(normalised);
    if (!keyRotatedSchema.verifySignature(canonicalPayload, normalised.signature, oldKey.public_key)) {
      throw schemaError(403, "OLD-key signature verification failed", "signature_invalid");
    }

    const timestamp = nowMs();
    if (canonicalPayload.effective_at < timestamp) {
      throw schemaError(400, "effective_at must be >= tx.timestamp", "effective_at_invalid");
    }

    const txBody = {
      tx_type: TX_TYPES.KEY_ROTATED, timestamp, prev: dag.getRecentPrev(),
      data: _pickTxData(canonicalPayload, KEY_ROTATED_FIELDS),
      signature: normalised.signature,
    };
    const signedTx = withTxId(txBody);

    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(signedTx);
    log.info(`Key rotation proposed: ${normalised.tip_id} (effective_at=${canonicalPayload.effective_at})`);
    return {
      tx_id: signedTx.tx_id, tip_id: normalised.tip_id,
      effective_at: canonicalPayload.effective_at,
      confirmation: "proposed",
    };
  }

  // KEY_RECOVERY — user has lost their CURRENT key and goes back to a VP
  // for off-chain re-verification. The VP signs the canonical body
  // attesting they re-verified the user; the chain installs the user's
  // NEW key. Same time-anchored dispatch path (VP's key valid at
  // tx.timestamp). On top of the VP signature, the user supplies a
  // fresh zk_proof bound to the SAME dedup_hash as their original
  // REGISTER_IDENTITY — recovery is only valid when the gov-id-bearing
  // witness matches, defending against a rogue VP recovering an
  // arbitrary identity.
  async function recoverKey(body) {
    const normalised = (body && typeof body === "object")
      ? { ...body, algorithm: _normaliseAlgorithm(body.algorithm) }
      : body;

    keyRecoverySchema.validateRequest(normalised, { dag });

    const vp = dag.getVP(normalised.vp_id);
    if (!vp || !vp.public_key) {
      throw schemaError(412, `VP has no active key: ${normalised.vp_id}`, "vp_no_active_key");
    }

    // CAS — the VP's replaces_pubkey must equal the live active key.
    // Replay defense (captured body can only commit once before state moves)
    // + concurrency guard (two simultaneous recoveries: one wins).
    const activeKey = dag.getActiveKey("identity", normalised.tip_id);
    if (!activeKey || activeKey.public_key !== normalised.replaces_pubkey) {
      throw schemaError(409, "replaces_pubkey does not match current active key", "state_changed");
    }

    // Look up the original REGISTER_IDENTITY for this tip_id to recover
    // the canonical dedup_hash, then verify the fresh zk_proof against it.
    // Mirrors the proof-check identity-service runs at first-time register.
    const identity = dag.getIdentity(normalised.tip_id);
    const originalTx = identity && identity.tx_id ? dag.getTx(identity.tx_id) : null;
    const originalDedupHash = originalTx && originalTx.data ? originalTx.data.dedup_hash : null;
    if (!originalDedupHash) {
      throw schemaError(412, "original dedup_hash unavailable for tip_id", "dedup_hash_unresolvable");
    }
    const proofValid = await verifyDedupProof(originalDedupHash, normalised.zk_proof);
    if (!proofValid) {
      throw schemaError(403, "zk_proof does not bind to original dedup_hash", "zk_proof_invalid");
    }

    const canonicalPayload = keyRecoverySchema.buildSigningPayload(normalised);
    if (!keyRecoverySchema.verifySignature(canonicalPayload, normalised.signature, vp.public_key)) {
      throw schemaError(403, "VP signature verification failed", "signature_invalid");
    }
    // Proof-of-possession: the NEW key must have signed the canonical body.
    // Blocks "ghost active key" rows from clients that lost the private key
    // before submission; chain only commits recoveries the submitter can use.
    if (!keyRecoverySchema.verifySignature(canonicalPayload, normalised.new_key_signature, normalised.new_public_key)) {
      throw schemaError(403, "new-key proof-of-possession failed", "new_key_signature_invalid");
    }

    // Chain stamps effective_at = tx.timestamp so recovery activates the
    // instant it commits — no future window for an attacker holding the
    // OLD key to submit a counter-rotation against the queued row.
    const timestamp = nowMs();

    const txBody = {
      tx_type: TX_TYPES.KEY_RECOVERY, timestamp, prev: dag.getRecentPrev(),
      data: {
        ..._pickTxData(canonicalPayload, KEY_RECOVERY_FIELDS),
        effective_at: timestamp,
        new_key_signature: normalised.new_key_signature,
      },
      signature: normalised.signature,
    };
    const signedTx = withTxId(txBody);

    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(signedTx);
    log.info(`Key recovery proposed: ${normalised.tip_id} via vp=${normalised.vp_id} (effective_at=${timestamp})`);
    return {
      tx_id: signedTx.tx_id, tip_id: normalised.tip_id, vp_id: normalised.vp_id,
      effective_at: timestamp,
      confirmation: "proposed",
    };
  }

  // Public key chain for an identity, oldest first. The client verifies
  // the chain itself: shake256(keys[0].public_key)[0:16] must equal the
  // tip_id hash segment, and each later key is introduced by the signed
  // KEY_ROTATED / KEY_RECOVERY tx in source_tx_id. Served for revoked
  // identities too — their historical signatures still need verifying.
  function getKeyHistory(tipId) {
    keyHistorySchema.validateRequest({ tip_id: tipId });
    const keys = dag.getEntityKeyHistory("identity", tipId);
    if (!keys.length) {
      throw { status: 404, error: `Unknown identity: ${tipId}`, code: "identity_not_found" };
    }
    return { tip_id: tipId, rotations: keys.length - 1, keys };
  }

  return { rotateKey, recoverKey, getKeyHistory };
}

module.exports = { createKeyService };
