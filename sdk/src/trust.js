/**
 * @file @tip-protocol/sdk/src/trust.js
 * @description TIP Trust Client — query scores, compute tiers, manage
 *              revocations, and verify ZK score proofs.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { getTier, SCORE_DISPLAY, TX_TYPES } = require("../../shared/constants");
const { shake256Multi }                    = require("../../shared/crypto");

class TIPTrustClient {
  constructor(config) {
    this._config = config;
  }

  async _fetch(path, options) {
    const { TIPClient } = require("./index");
    return new TIPClient(this._config)._fetch(path, options);
  }

  /**
   * Get trust score for a TIP-ID.
   * @param {string} tipId
   * @returns {Promise<{ score, tier, tier_label, tier_color, verified_since, content_count, status }>}
   */
  async getScore(tipId) {
    return this._fetch(`/v1/identity/${encodeURIComponent(tipId)}/score`);
  }

  /**
   * Get full score history (DAG replay) for a TIP-ID.
   * @param {string} tipId
   * @returns {Promise<Object>}
   */
  async getHistory(tipId) {
    return this._fetch(`/v1/identity/${encodeURIComponent(tipId)}/history`);
  }

  /**
   * Compute tier locally from a known score (no network call).
   * @param {number} score
   * @returns {{ name, label, color, min, max }}
   */
  computeTier(score) {
    return getTier(score);
  }

  /**
   * Generate a ZK score proof.
   * Allows proving "my score is above X" without revealing the actual number.
   * Uses a Pedersen-style commitment: commit(score, blinding_factor).
   *
   * @param {number} score          The actual score
   * @param {number} threshold      The claim being proven (e.g. 700 for jury eligibility)
   * @param {string} privateKey     To bind the proof to the TIP-ID
   * @returns {{ proof, threshold, above_threshold, commitment }}
   */
  generateScoreProof(score, threshold, privateKey) {
    if (score === undefined || threshold === undefined) {
      throw new Error("score and threshold are required");
    }
    const aboveThreshold = score >= threshold;
    const blindingFactor = shake256Multi(privateKey || "", Date.now().toString());
    const commitment     = shake256Multi(score.toString(), blindingFactor);

    return {
      commitment,
      threshold,
      above_threshold: aboveThreshold,
      // Proof string: in production replace with actual ZK-STARK proof
      proof: `zksc:${shake256Multi(commitment, threshold.toString(), aboveThreshold.toString())}`,
      blinding_factor: blindingFactor, // caller should store securely
    };
  }

  /**
   * Verify a ZK score proof received from another party.
   * @param {string} proof
   * @param {string} commitment
   * @param {number} threshold
   * @param {boolean} claimedAbove
   * @returns {boolean}
   */
  verifyScoreProof(proof, commitment, threshold, claimedAbove) {
    const expected = `zksc:${shake256Multi(commitment, threshold.toString(), claimedAbove.toString())}`;
    return proof === expected;
  }

  // ── Revocations ────────────────────────────────────────────────────────────

  /**
   * Get the current revocation list from this node.
   * @param {string} [since]  ISO timestamp — only fetch revocations after this date
   * @returns {Promise<Object>}
   */
  async getRevocations(since) {
    const qs = since ? `?since=${encodeURIComponent(since)}` : "";
    return this._fetch(`/v1/revocations${qs}`);
  }

  /**
   * Check if a TIP-ID is revoked (from revocation list).
   * @param {string} tipId
   * @returns {Promise<boolean>}
   */
  async isRevoked(tipId) {
    const rec = await this._fetch(`/v1/identity/${encodeURIComponent(tipId)}`);
    return rec.status === "revoked";
  }

  /**
   * Issue a revocation transaction.
   * Must be called by an authorised VP or the Council.
   *
   * @param {Object} options
   * @param {string} options.tipId
   * @param {string} options.txType       TX_TYPES.REVOKE_VP | REVOKE_VOLUNTARY | REVOKE_DECEASED | REVOKE_DEVICE
   * @param {string} options.reasonCode
   * @param {string} options.evidenceHash SHAKE-256 hash of supporting documentation
   * @param {string} options.issuingVpId
   * @param {string} options.signature    VP's ML-DSA-65 signature
   * @returns {Promise<Object>}
   */
  async revoke({ tipId, txType, reasonCode, evidenceHash, issuingVpId, signature }) {
    return this._fetch("/v1/revocations", {
      method: "POST",
      body: {
        tip_id:        tipId,
        tx_type:       txType,
        reason_code:   reasonCode,
        evidence_hash: evidenceHash,
        issuing_vp_id: issuingVpId,
        signature,
      },
    });
  }

  // ── Dedup (v2 FIX-02) ──────────────────────────────────────────────────────

  /**
   * Check uniqueness via ZK proof.
   * Returns { unique: boolean } — NEVER the underlying hash.
   *
   * @param {string} zkProof          Computed on-device by identity.computeZKProof()
   * @param {string} [hashCommitment] Optional Pedersen commitment
   * @returns {Promise<{ unique, duplicate, message }>}
   */
  async checkUniqueness(zkProof, hashCommitment) {
    return this._fetch("/v1/dedup/check", {
      method: "POST",
      body: { zk_proof: zkProof, hash_commitment: hashCommitment },
    });
  }

  /**
   * Get the Merkle root for dedup audit.
   * @returns {Promise<{ merkle_root, dedup_count, identity_count, generated }>}
   */
  async getMerkleRoot() {
    return this._fetch("/v1/dedup/merkle-root");
  }
}

module.exports = { TIPTrustClient };
