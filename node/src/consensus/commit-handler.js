/**
 * @file @tip-protocol/node/src/consensus/commit-handler.js
 * @description Processes ordered transactions from Bullshark and commits to DAG.
 *
 * When Bullshark commits an anchor, it outputs a deterministically ordered
 * list of transactions. This handler:
 *   1. Validates each tx against current DAG state (may have changed since API time)
 *   2. Writes valid txs to DAG
 *   3. Updates derived state (identities, content, scores, revocations, etc.)
 *   4. Drops invalid txs with a log (e.g. content already registered by another node)
 *
 * This replaces the old replayDerivedState() from gossip.js with full validation
 * and support for all tx types including dispute, jury, and appeal.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES, CONTENT_STATUS } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const { verifyBodySignature, mldsaVerify, canonicalTx } = require("../../../shared/crypto");
const { getLogger } = require("../logger");

const log = getLogger("tip.commit");

/**
 * Create a commit handler.
 *
 * @param {Object} options
 * @param {Object} options.dag      DAG store
 * @param {Object} options.scoring  Scoring engine
 * @param {Object} options.config   Node config
 * @returns {Object} Commit handler
 */
function createCommitHandler({ dag, scoring, config }) {

  /**
   * Process an ordered batch of txs from Bullshark.
   * Each tx is validated against current state, written to DAG, and derived state updated.
   *
   * @param {Array<Object>} orderedTxs  Deterministically ordered txs from Bullshark
   * @param {number} round              The round number that committed these txs
   * @returns {{ committed: number, dropped: number }}
   */
  function commitOrderedTxs(orderedTxs, round) {
    let committed = 0;
    let dropped = 0;

    for (const tx of orderedTxs) {
      try {
        // Skip invalid txs
        if (!tx || !tx.tx_id || !tx.tx_type) {
          dropped++;
          continue;
        }

        // Skip if already in DAG (dedup — same tx may appear in multiple certificates)
        if (dag.getTx(tx.tx_id)) {
          continue;
        }

        // Validate tx structure and signatures before committing
        const validation = validateTransaction(tx, dag, { skipState: true });
        if (!validation.valid) {
          log.warn(`Round ${round}: rejected tx ${tx.tx_id.slice(0, 16)} (${tx.tx_type}) — validation: ${validation.errors.join("; ")}`);
          dropped++;
          continue;
        }

        // Verify body signatures (same checks as gossip verifyIncomingTx)
        if (!_verifyTxSignature(tx)) {
          log.warn(`Round ${round}: rejected tx ${tx.tx_id.slice(0, 16)} (${tx.tx_type}) — signature verification failed`);
          dropped++;
          continue;
        }

        // Write to DAG
        dag.addTx(tx);

        // Update derived state based on tx type
        _applyDerivedState(tx);

        committed++;
      } catch (err) {
        log.warn(`Round ${round}: dropped tx ${tx.tx_id?.slice(0, 16)} (${tx.tx_type}): ${err.message}`);
        dropped++;
      }
    }

    if (committed > 0 || dropped > 0) {
      log.info(`Round ${round}: committed ${committed} txs, dropped ${dropped}`);
    }

    return { committed, dropped };
  }

  /**
   * Apply derived state updates for a committed transaction.
   * Handles all tx types — identity, content, dispute, jury, appeal, revocation, governance.
   */
  function _applyDerivedState(tx) {
    const d = tx.data || {};

    switch (tx.tx_type) {

      // ── Identity ──────────────────────────────────────────────────────
      case TX_TYPES.REGISTER_IDENTITY:
        if (d.dedup_hash && !dag.hasDedupHash(d.dedup_hash)) {
          dag.addDedupHash(d.dedup_hash);
        }
        if (d.tip_id && !dag.getIdentity(d.tip_id)) {
          dag.saveIdentity({
            tip_id: d.tip_id,
            region: d.region || "US",
            public_key: d.public_key || "",
            root_public_key: d.root_public_key || "",
            vp_id: d.vp_id || "",
            verification_tier: d.verification_tier || "T1",
            founding: d.founding || false,
            status: "active",
            registered_at: tx.timestamp,
            tx_id: tx.tx_id,
          });
          // Initial score
          if (d.tip_id) {
            const initial = d.social_attested || d.attested ? 550 : 500;
            dag.setScore(d.tip_id, initial, 0);
          }
        }
        break;

      // ── Content ───────────────────────────────────────────────────────
      case TX_TYPES.REGISTER_CONTENT:
        if (d.ctid && !dag.getContent(d.ctid)) {
          dag.saveContent({
            ctid: d.ctid,
            origin_code: d.origin_code,
            content_hash: d.content_hash,
            perceptual_hash: d.perceptual_hash || null,
            author_tip_id: d.author_tip_id,
            status: d.prescan_flagged ? CONTENT_STATUS.PENDING_REVIEW : CONTENT_STATUS.REGISTERED,
            registered_at: tx.timestamp,
            tx_id: tx.tx_id,
          });
        }
        break;

      case TX_TYPES.UPDATE_ORIGIN:
        if (d.ctid && d.new_origin_code) {
          dag.updateContentOrigin(d.ctid, d.new_origin_code, CONTENT_STATUS.REGISTERED);
        }
        break;

      case TX_TYPES.CONTENT_RETRACTED:
        if (d.ctid) {
          dag.updateContentStatus(d.ctid, CONTENT_STATUS.RETRACTED);
        }
        break;

      // ── Verification ──────────────────────────────────────────────────
      case TX_TYPES.CONTENT_VERIFIED:
        // Score effect handled by scoring.computeScore() replay
        break;

      // ── Dispute ───────────────────────────────────────────────────────
      case TX_TYPES.CONTENT_DISPUTED:
        if (d.ctid) {
          dag.updateContentStatus(d.ctid, CONTENT_STATUS.DISPUTED);
        }
        break;

      // ── Adjudication ──────────────────────────────────────────────────
      case TX_TYPES.ADJUDICATION_RESULT:
        if (d.ctid) {
          if (d.verdict === "DISMISSED" || d.verdict === "CONSERVATIVE_LABEL") {
            dag.updateContentStatus(d.ctid, d.pre_dispute_status || CONTENT_STATUS.REGISTERED);
          } else if (d.verdict === "UPHELD" && d.confirmed_origin) {
            dag.updateContentOrigin(d.ctid, d.confirmed_origin, CONTENT_STATUS.VERIFIED);
          }
        }
        break;

      case TX_TYPES.APPEAL_RESULT:
        if (d.ctid && d.overturned) {
          if (d.stage2_verdict === "UPHELD" && d.declared_origin) {
            // Restore original origin + pre-dispute status
            dag.updateContentOrigin(d.ctid, d.declared_origin, CONTENT_STATUS.REGISTERED);
          } else if (d.confirmed_origin) {
            dag.updateContentOrigin(d.ctid, d.confirmed_origin, CONTENT_STATUS.VERIFIED);
          }
        }
        break;

      // ── Revocations ───────────────────────────────────────────────────
      case TX_TYPES.REVOKE_VOLUNTARY:
      case TX_TYPES.REVOKE_VP:
      case TX_TYPES.REVOKE_DECEASED:
      case TX_TYPES.REVOKE_DEVICE:
        if (d.tip_id && !dag.isRevoked(d.tip_id)) {
          dag.addRevocation(d.tip_id, tx.tx_type, tx.timestamp, tx.tx_id);
        }
        break;

      // ── Governance ────────────────────────────────────────────────────
      case TX_TYPES.VP_REGISTERED:
        if (d.vp_id && !dag.getVP(d.vp_id)) {
          dag.saveVP({
            vp_id: d.vp_id,
            name: d.name || "",
            jurisdiction_tier: d.jurisdiction_tier || "green",
            public_key: d.public_key || "",
            status: "active",
            registered_at: tx.timestamp,
          });
        }
        break;

      case TX_TYPES.NODE_REGISTERED:
        if (d.node_id && !dag.getNode(d.node_id)) {
          dag.saveNode({
            node_id: d.node_id,
            name: d.name || "",
            public_key: d.public_key || "",
            status: "active",
            registered_at: tx.timestamp,
          });
        }
        break;

      // ── Score updates, jury summons, votes — no derived state needed ──
      // These are recorded in the DAG; scoring.computeScore() replays them.
      case TX_TYPES.SCORE_UPDATE:
      case TX_TYPES.JURY_SUMMONS:
      case TX_TYPES.JURY_VOTE_COMMIT:
      case TX_TYPES.JURY_VOTE_REVEAL:
      case TX_TYPES.AI_CLASSIFIER_RESULT:
      case TX_TYPES.APPEAL_FILED:
      case TX_TYPES.MERKLE_ROOT_PUBLISHED:
        break;

      default:
        log.debug(`No derived state handler for tx type: ${tx.tx_type}`);
        break;
    }
  }

  /**
   * Verify body/node signature on a transaction.
   * Returns true only if the signature is verified against a known signer from our registry.
   * Returns false if unknown tx type, missing signer, or invalid signature.
   */
  function _verifyTxSignature(tx) {
    const d = tx.data || {};
    const tt = tx.tx_type;

    try {
      if (tt === TX_TYPES.REGISTER_CONTENT) {
        const identity = dag.getIdentity(d.author_tip_id);
        if (!identity || !d.signature) return false;
        return verifyBodySignature(d, d.signature, identity.public_key, ["author_tip_id", "origin_code", "content_hash"]);
      }

      if (tt === TX_TYPES.REGISTER_IDENTITY) {
        const vp = dag.getVP(d.vp_id);
        if (!vp || !d.vp_signature) return false;
        return verifyBodySignature(d, d.vp_signature, vp.public_key,
          ["region", "public_key", "dedup_hash", "zk_proof", "verification_tier", "vp_id", "social_attested"]);
      }

      if (tt === TX_TYPES.CONTENT_VERIFIED) {
        const verifier = dag.getIdentity(d.verifier_tip_id);
        if (!verifier || !d.signature) return false;
        return verifyBodySignature(d, d.signature, verifier.public_key, ["verifier_tip_id", "verdict"]);
      }

      if (tt === TX_TYPES.CONTENT_DISPUTED) {
        if (d.auto) {
          const node = dag.getNode(d.node_id);
          if (!node || !tx.signature) return false;
          return mldsaVerify(canonicalTx(tx), tx.signature, node.public_key);
        }
        const disputer = dag.getIdentity(d.disputer_tip_id);
        if (!disputer || !d.signature) return false;
        return verifyBodySignature(d, d.signature, disputer.public_key, ["disputer_tip_id", "reason", "evidence_hash"]);
      }

      if (tt === TX_TYPES.JURY_VOTE_COMMIT) {
        const juror = dag.getIdentity(d.juror_tip_id);
        if (!juror || !d.signature) return false;
        return verifyBodySignature(d, d.signature, juror.public_key, ["juror_tip_id", "commitment"]);
      }

      if (tt === TX_TYPES.JURY_VOTE_REVEAL) {
        const juror = dag.getIdentity(d.juror_tip_id);
        if (!juror || !d.signature) return false;
        const fields = d.confirmed_origin ? ["juror_tip_id", "vote", "salt", "confirmed_origin"] : ["juror_tip_id", "vote", "salt"];
        return verifyBodySignature(d, d.signature, juror.public_key, fields);
      }

      if ([TX_TYPES.REVOKE_VOLUNTARY, TX_TYPES.REVOKE_VP, TX_TYPES.REVOKE_DECEASED, TX_TYPES.REVOKE_DEVICE].includes(tt)) {
        const vp = dag.getVP(d.issuing_vp_id);
        if (!vp || !d.signature) return false;
        return verifyBodySignature(d, d.signature, vp.public_key,
          ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"]);
      }

      if (tt === TX_TYPES.VP_REGISTERED || tt === TX_TYPES.NODE_REGISTERED) {
        const vp = dag.getVP(d.approving_vp_id);
        if (!vp || !d.council_signature) return false;
        const fields = tt === TX_TYPES.VP_REGISTERED
          ? ["name", "jurisdiction_tier", "public_key", "approving_vp_id"]
          : ["name", "public_key", "approving_vp_id"];
        return verifyBodySignature(d, d.council_signature, vp.public_key, fields);
      }

      const NODE_SIGNED = [TX_TYPES.SCORE_UPDATE, TX_TYPES.ADJUDICATION_RESULT, TX_TYPES.APPEAL_RESULT,
      TX_TYPES.JURY_SUMMONS, TX_TYPES.AI_CLASSIFIER_RESULT, TX_TYPES.MERKLE_ROOT_PUBLISHED, TX_TYPES.APPEAL_FILED];
      if (NODE_SIGNED.includes(tt)) {
        const node = dag.getNode(d.node_id);
        if (!node || !tx.signature) return false;
        return mldsaVerify(canonicalTx(tx), tx.signature, node.public_key);
      }

    } catch (err) {
      log.warn(`Signature verification error for ${tt} tx ${tx.tx_id?.slice(0, 16)}: ${err.message}`);
      return false;
    }

    // Unknown tx type — reject
    log.warn(`Rejected unknown tx type: ${tt}`);
    return false;
  }

  return { commitOrderedTxs };
}

module.exports = { createCommitHandler };
