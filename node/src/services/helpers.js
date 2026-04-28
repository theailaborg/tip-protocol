"use strict";

const {
  signTransaction, computeTxId,
} = require("../../../shared/crypto");
const { ORIGIN, PRESCAN_THRESHOLDS } = require("../../../shared/protocol-constants");
const { log } = require("../logger");

/**
 * Assign content-addressed tx_id (no node signature).
 */
function withTxId(txBody) {
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

/**
 * Sign a tx with the node's registered key (for auto/system txs only).
 */
function nodeSignedAuto(txBody, config) {
  txBody.data.node_id = config.nodeRegisteredId || config.nodeId;
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, config.nodePrivateKey);
}

/**
 * AI pre-scan for content origin mismatch detection.
 */
function preScanContent(content, originCode, creatorHistory) {
  if (originCode !== "OH") return { flagged: false, probability: 0 };

  const words = content.split(/\s+/);
  const wordCount = words.length;
  if (wordCount < 20) return { flagged: false, probability: 0.1 };

  const uniqueRatio = new Set(words).size / wordCount;
  const avgWordLen = words.reduce((s, w) => s + w.length, 0) / wordCount;
  const hasLongSentences = (content.match(/[.!?]/g) || []).length < wordCount / 25;

  let prob = 0;
  if (uniqueRatio < 0.55) prob += 0.2;
  if (avgWordLen > 5.5) prob += 0.15;
  if (hasLongSentences) prob += 0.1;

  const verifiedCount = creatorHistory?.verified_oh_count || 0;
  const threshold = verifiedCount > 200
    ? PRESCAN_THRESHOLDS.ceiling
    : verifiedCount > 50
      ? 0.90
      : PRESCAN_THRESHOLDS.default;

  return { flagged: prob > threshold, probability: prob, threshold };
}

/**
 * Create a tx submitter. Always routes through consensus mempool.
 * Single code path — consensus runs even with 1 node (quorum=1, instant commit).
 *
 * @param {Object} consensusRef  { current: consensus }
 * @returns {{ submitTx: Function, submitBatch: Function }}
 */
function createTxSubmitter(consensusRef) {
  /**
   * Submit a single tx to consensus mempool.
   * @param {Object} tx  Validated tx with tx_id
   * @returns {{ tx_id: string }}
   */
  function submitTx(tx) {
    if (!consensusRef?.current) throw { status: 503, error: "Consensus not available" };
    const result = consensusRef.current.addTx(tx);
    if (!result.added) throw { status: 503, error: `Transaction not accepted: ${result.reason}` };
    return { tx_id: tx.tx_id };
  }

  /**
   * Submit multiple txs as an atomic batch to consensus mempool.
   * All txs in the batch will be committed together or not at all.
   * Used for dispute (9 txs), appeal (4 txs), revocation cascade (2+ txs).
   * @param {Array<Object>} txs  Validated txs with tx_ids
   * @returns {{ tx_ids: string[], batch_id: string }}
   */
  function submitBatch(txs) {
    if (!consensusRef?.current) throw { status: 503, error: "Consensus not available" };
    if (!txs || txs.length === 0) throw { status: 400, error: "Empty batch" };

    const txIds = [];
    for (const tx of txs) {
      const result = consensusRef.current.addTx(tx);
      if (!result.added) {
        // Rollback: remove already-added txs from this batch
        for (const addedId of txIds) consensusRef.current.mempool.remove([addedId]);
        throw { status: 503, error: `Batch rejected: tx ${tx.tx_id?.slice(0, 16)} — ${result.reason}` };
      }
      txIds.push(tx.tx_id);
    }

    return { tx_ids: txIds, batch_id: txs[0].tx_id };
  }

  return { submitTx, submitBatch };
}

module.exports = {
  withTxId,
  nodeSignedAuto,
  createTxSubmitter,
  preScanContent,
};
