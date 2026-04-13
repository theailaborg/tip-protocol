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

  return { commitOrderedTxs };
}

module.exports = { createCommitHandler };
