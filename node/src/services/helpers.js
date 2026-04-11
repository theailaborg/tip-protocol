"use strict";

const {
  signTransaction, computeTxId, shake256Multi,
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
 * Broadcast tx via gossip if available.
 */
function createBroadcast(gossipRef) {
  return (tx) => {
    if (!gossipRef || !gossipRef.current) return;
    try { gossipRef.current.broadcast(tx); }
    catch (err) { log.error(`Gossip broadcast failed for tx ${tx.tx_id}: ${err.message}`); }
  };
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
 * Compute Merkle root stub.
 */
function computeMerkleRoot(dag) {
  const count = dag.dedupCount();
  return shake256Multi(count.toString(), new Date().toISOString().slice(0, 10));
}

module.exports = {
  withTxId,
  nodeSignedAuto,
  createBroadcast,
  preScanContent,
  computeMerkleRoot,
};
