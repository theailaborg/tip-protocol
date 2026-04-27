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
const { SCORE_EVENTS } = require("../../../shared/protocol-constants");
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
   * @param {Object} [opts]
   * @param {boolean} [opts.fromSync]   True when replaying txs freshly imported from a peer.
   *                                    Skips prev-reference existence check because some
   *                                    internal writers (scheduler, scoring, jury — see
   *                                    issue #13) insert txs directly into the DAG without
   *                                    broadcasting, so their tx_ids won't exist on this
   *                                    node. The BFT cert wrapping the tx provides the
   *                                    integrity guarantee that the prev-check normally would.
   * @returns {{ committed: number, dropped: number }}
   */
  function commitOrderedTxs(orderedTxs, round, opts = {}) {
    const { fromSync = false } = opts;
    // Phase 1: Validate all txs BEFORE writing anything
    const validated = [];
    let dropped = 0;

    for (const tx of orderedTxs) {
      if (!tx || !tx.tx_id || !tx.tx_type) {
        dropped++;
        continue;
      }

      // Skip if already in DAG
      if (dag.getTx(tx.tx_id)) continue;

      // Validate structure
      const validation = validateTransaction(tx, dag, { skipState: true, skipPrevCheck: fromSync });
      if (!validation.valid) {
        log.warn(`Round ${round}: rejected tx ${tx.tx_id.slice(0, 16)} (${tx.tx_type}) — ${validation.errors.join("; ")}`);
        dropped++;
        continue;
      }

      // Verify signature
      if (!_verifyTxSignature(tx)) {
        log.warn(`Round ${round}: rejected tx ${tx.tx_id.slice(0, 16)} (${tx.tx_type}) — signature failed`);
        dropped++;
        continue;
      }

      validated.push(tx);
    }

    // Phase 2: Write all validated txs in one atomic SQLite transaction
    let committed = 0;
    if (validated.length > 0) {
      try {
        dag.runInTransaction(() => {
          for (const tx of validated) {
            dag.addTx(tx);
            _applyDerivedState(tx);
            committed++;
          }
          // Remove committed txs from mempool in the same transaction
          const txIds = validated.map(t => t.tx_id);
          dag.deleteMempoolTxs(txIds);
        });
      } catch (err) {
        log.error(`Round ${round}: transaction commit failed — rolled back ${validated.length} txs: ${err.message}`);
        committed = 0;
        dropped += validated.length;
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
          // Unix seconds derived from the tx timestamp (deterministic across nodes).
          dag.addDedupHash(d.dedup_hash, Math.floor(new Date(tx.timestamp).getTime() / 1000));
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
            // #55: forward creator_name from tx.data so the VP-attested
            // display name persists in the DAG row. Column already exists
            // on `identities` (dag.js); this was the missing forward-through.
            creator_name: d.creator_name || null,
          });
          // Initial score (scores table is a cache, see Consensus issue #31).
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
            // #54: forward registered_url so the URL persists in the DAG row.
            // The column already exists on `content` (dag.js); this was the
            // missing forward-through from tx.data.
            registered_url: d.registered_url || null,
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
          if (d.author_tip_id && scoring) {
            scoring.applyScoreEvent(d.author_tip_id, SCORE_EVENTS.CONTENT_RETRACTION.delta, `Content retracted: ${d.ctid}`);
          }
        }
        break;

      // ── Verification ──────────────────────────────────────────────────
      case TX_TYPES.CONTENT_VERIFIED:
        // Score effect handled by scoring.computeScore() replay (reads weighted_delta from tx.data)
        // Update content status: registered → verified on first verification
        if (d.ctid) {
          const content = dag.getContent(d.ctid);
          if (content && content.status === CONTENT_STATUS.REGISTERED) {
            dag.updateContentStatus(d.ctid, CONTENT_STATUS.VERIFIED);
          }
        }
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
            jurisdiction: d.jurisdiction || "US",
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
        // Mirror content-service.js — include registered_url in the
        // signed-fields list when the client included it. Field list
        // drift between API and commit-handler is the #56 systemic
        // class; this case is #54.
        const fields = d.registered_url
          ? ["author_tip_id", "origin_code", "content_hash", "registered_url"]
          : ["author_tip_id", "origin_code", "content_hash"];
        return verifyBodySignature(d, d.signature, identity.public_key, fields);
      }

      if (tt === TX_TYPES.REGISTER_IDENTITY) {
        const vp = dag.getVP(d.vp_id);
        if (!vp || !d.vp_signature) return false;
        // Mirror identity-service.js — include creator_name when the VP
        // attested a display name. Same drift class as #54; tracked
        // separately as #55.
        const BASE_FIELDS = ["region", "public_key", "dedup_hash", "zk_proof", "verification_tier", "vp_id", "social_attested"];
        const fields = d.creator_name ? [...BASE_FIELDS, "creator_name"] : BASE_FIELDS;
        return verifyBodySignature(d, d.vp_signature, vp.public_key, fields);
      }

      if (tt === TX_TYPES.CONTENT_VERIFIED) {
        const verifier = dag.getIdentity(d.verifier_tip_id);
        if (!verifier || !d.signature) return false;
        return verifyBodySignature(d, d.signature, verifier.public_key, ["verifier_tip_id", "verdict"]);
      }

      if (tt === TX_TYPES.UPDATE_ORIGIN) {
        const author = dag.getIdentity(d.author_tip_id);
        if (!author || !d.signature) return false;
        return verifyBodySignature(d, d.signature, author.public_key, ["author_tip_id", "new_origin_code"]);
      }

      if (tt === TX_TYPES.CONTENT_RETRACTED) {
        const author = dag.getIdentity(d.author_tip_id);
        if (!author || !d.signature) return false;
        return verifyBodySignature(d, d.signature, author.public_key, ["author_tip_id"]);
      }

      if (tt === TX_TYPES.CONTENT_DISPUTED) {
        if (d.auto) {
          const node = dag.getNode(d.node_id);
          if (!node || !tx.signature) return false;
          return mldsaVerify(canonicalTx(tx), tx.signature, node.public_key);
        }
        const disputer = dag.getIdentity(d.disputer_tip_id);
        if (!disputer || !d.signature) return false;
        const disputeFields = d.claimed_origin ? ["disputer_tip_id", "reason", "claimed_origin", "evidence_hash"] : ["disputer_tip_id", "reason", "evidence_hash"];
        return verifyBodySignature(d, d.signature, disputer.public_key, disputeFields);
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

      if (tt === TX_TYPES.APPEAL_FILED) {
        if (d.appellant_tip_id === "SYSTEM_AUTO_ESCALATION") {
          // Auto-escalated by node on NO_QUORUM — verify node signature
          const node = dag.getNode(d.node_id);
          if (!node || !tx.signature) return false;
          return mldsaVerify(canonicalTx(tx), tx.signature, node.public_key);
        }
        // User-filed appeal — verify appellant signature
        const appellant = dag.getIdentity(d.appellant_tip_id);
        if (!appellant || !d.signature) return false;
        return verifyBodySignature(d, d.signature, appellant.public_key, ["appellant_tip_id"]);
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
          ? ["name", "jurisdiction", "jurisdiction_tier", "public_key", "approving_vp_id"]
          : ["name", "public_key", "approving_vp_id"];
        return verifyBodySignature(d, d.council_signature, vp.public_key, fields);
      }

      const NODE_SIGNED = [TX_TYPES.SCORE_UPDATE, TX_TYPES.ADJUDICATION_RESULT, TX_TYPES.APPEAL_RESULT,
      TX_TYPES.JURY_SUMMONS, TX_TYPES.AI_CLASSIFIER_RESULT, TX_TYPES.MERKLE_ROOT_PUBLISHED];
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
