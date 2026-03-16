/**
 * @file @tip-protocol/sdk/src/identity.js
 * @description TIP Identity Client — register, resolve, manage TIP-IDs.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const {
  generateMLDSAKeypair,
  generateSLHDSAKeypair,
  generatePepper,
  shake256Multi,
  generateTIPID,
} = require("../../shared/crypto");

class TIPIdentityClient {
  constructor(config) {
    this._config = config;
  }

  async _fetch(path, options) {
    // Reuse parent's _fetch via config reference
    const { TIPClient } = require("./index");
    return new TIPClient(this._config)._fetch(path, options);
  }

  /**
   * Generate a fresh ML-DSA-65 keypair for a new identity.
   * IMPORTANT: The returned private key must be stored securely by the caller.
   * The node never stores private keys.
   *
   * @returns {{ publicKey, privateKey, rootPublicKey, rootPrivateKey, algorithm }}
   */
  generateKeypair() {
    const primary = generateMLDSAKeypair();
    const root    = generateSLHDSAKeypair();
    return {
      publicKey:      primary.publicKey,
      privateKey:     primary.privateKey,
      rootPublicKey:  root.publicKey,
      rootPrivateKey: root.privateKey,
      algorithm:      "ML-DSA-65 + SLH-DSA-128s",
    };
  }

  /**
   * Generate a device-side pepper (for dedup hash).
   * In production this runs inside the device secure enclave.
   * The pepper must NEVER be sent to or stored by the server.
   *
   * @returns {string} 256-bit hex pepper
   */
  generatePepper() {
    return generatePepper();
  }

  /**
   * Compute a ZK proof of uniqueness from the dedup inputs + pepper.
   * This is the commitment sent to the server during registration.
   * The server stores only this commitment, never the inputs.
   *
   * @param {Object} inputs
   * @param {string} inputs.govIdNormalized
   * @param {string} inputs.dateOfBirthISO
   * @param {string} inputs.countryCode
   * @param {string} inputs.facialEmbeddingHash
   * @param {string} inputs.pepper
   * @returns {string} ZK proof string
   */
  computeZKProof({ govIdNormalized, dateOfBirthISO, countryCode, facialEmbeddingHash, pepper }) {
    // In production: generate a proper ZK-SNARK proof
    // Here: commitment = SHAKE-256(hash + nonce) where hash stays on device
    const dedupHash = shake256Multi(govIdNormalized, dateOfBirthISO, countryCode, facialEmbeddingHash, pepper);
    const nonce     = shake256Multi("zkp-nonce", Date.now().toString());
    return `zkp:${shake256Multi(dedupHash, nonce)}`;
  }

  /**
   * Register a new identity on the TIP node.
   *
   * In a real deployment this is called by the VP's biometric verification
   * hardware after completing the four-layer stack. The client-side SDK
   * provides this method for VP integrations.
   *
   * @param {Object} options
   * @param {string} options.region           e.g. "US"
   * @param {string} options.vpId             ID of issuing VP
   * @param {string} options.zkDedupProof     ZK proof of uniqueness
   * @param {string} [options.verificationTier] "T1"|"T2"|"T3"|"T4" (default: T1)
   * @param {boolean} [options.socialAttested]  (default: false)
   * @param {boolean} [options.founding]        (default: false)
   * @returns {Promise<Object>} identity record including tip_id and keypair
   */
  async register({ region = "US", vpId, zkDedupProof, verificationTier = "T1", socialAttested = false, founding = false }) {
    if (!vpId)        throw new Error("vpId is required");
    if (!zkDedupProof) throw new Error("zkDedupProof is required. Compute this on-device before calling register().");

    const res = await this._fetch("/v1/identity/register", {
      method: "POST",
      body: {
        region,
        vp_id:              vpId,
        zk_dedup_proof:     zkDedupProof,
        verification_tier:  verificationTier,
        social_attested:    socialAttested,
        founding,
      },
    });

    return {
      tipId:          res.tip_id,
      privateKey:     res.private_key,
      publicKey:      res.public_key,
      rootPrivateKey: res.root_private_key,
      rootPublicKey:  res.root_public_key,
      txId:           res.tx_id,
      score:          res.score,
      registeredAt:   res.registered_at,
      message:        res.message,
      // Convenience raw fields
      ...res,
    };
  }

  /**
   * Resolve a TIP-ID to its full public record.
   * @param {string} tipId
   * @returns {Promise<Object>}
   */
  async resolve(tipId) {
    return this._fetch(`/v1/identity/${encodeURIComponent(tipId)}`);
  }

  /**
   * Get full score details for a TIP-ID.
   * @param {string} tipId
   * @returns {Promise<Object>}
   */
  async getScore(tipId) {
    return this._fetch(`/v1/identity/${encodeURIComponent(tipId)}/score`);
  }

  /**
   * Get full DAG transaction history for a TIP-ID (for score auditing).
   * @param {string} tipId
   * @returns {Promise<Object>}
   */
  async getHistory(tipId) {
    return this._fetch(`/v1/identity/${encodeURIComponent(tipId)}/history`);
  }

  /**
   * Compute a TIP-ID URI from a public key (local, no network call).
   * @param {string} region
   * @param {string} publicKeyHex
   * @returns {string}
   */
  computeTIPID(region, publicKeyHex) {
    return generateTIPID(region, publicKeyHex);
  }
}

module.exports = { TIPIdentityClient };
