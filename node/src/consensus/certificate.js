/**
 * @file @tip-protocol/node/src/consensus/certificate.js
 * @description Narwhal certificate and batch creation, hashing, signing, and validation.
 *
 * A Batch contains txs proposed by a single node in one round.
 * A Certificate wraps a Batch with 2/3+ acknowledgments from other nodes,
 * proving data availability. Certificates form a DAG via parent_hashes.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256, mldsaSign, mldsaVerify, computeTxId } = require("../../../shared/crypto");
const { getLogger } = require("../logger");

const log = getLogger("tip.certificate");

// ─── Batch ───────────────────────────────────────────────────────────────────

/**
 * Create a batch from pending txs for the current round.
 * @param {number} round           Current consensus round
 * @param {string} authorNodeId    This node's registered ID
 * @param {Array}  txs             Transactions from the mempool
 * @param {string} privateKey      Node's ML-DSA-65 private key (hex)
 * @returns {{ round, author_node_id, txs, hash, signature }}
 */
function createBatch(round, authorNodeId, txs, privateKey) {
  const batch = {
    round,
    author_node_id: authorNodeId,
    txs,
    hash: null,
    signature: null,
  };

  // Hash: SHAKE-256(round + author + sorted tx_ids)
  const txIds = txs.filter(t => t && t.tx_id).map(t => t.tx_id).sort().join(",");
  batch.hash = shake256(`batch:${round}:${authorNodeId}:${txIds}`);

  // Sign the hash with node's private key
  batch.signature = mldsaSign(batch.hash, privateKey);

  return batch;
}

/**
 * Verify a batch's integrity and signature.
 * @param {Object} batch       The batch to verify
 * @param {string} publicKey   Author node's ML-DSA-65 public key from registry
 * @returns {{ valid: boolean, error?: string }}
 */
function verifyBatch(batch, publicKey) {
  if (!batch || !batch.hash || !batch.signature) {
    return { valid: false, error: "Batch missing hash or signature" };
  }

  // Recompute hash
  const txIds = (batch.txs || []).filter(t => t && t.tx_id).map(t => t.tx_id).sort().join(",");
  const expectedHash = shake256(`batch:${batch.round}:${batch.author_node_id}:${txIds}`);

  if (expectedHash !== batch.hash) {
    return { valid: false, error: "Batch hash mismatch" };
  }

  // Verify signature
  if (!mldsaVerify(batch.hash, batch.signature, publicKey)) {
    return { valid: false, error: "Batch signature invalid" };
  }

  return { valid: true };
}

// ─── BatchAck ────────────────────────────────────────────────────────────────

/**
 * Create an acknowledgment for a received batch.
 * @param {string} batchHash      Hash of the batch being acknowledged
 * @param {string} ackerNodeId    This node's registered ID
 * @param {string} privateKey     This node's ML-DSA-65 private key (hex)
 * @returns {{ batch_hash, acker_node_id, signature }}
 */
function createBatchAck(batchHash, ackerNodeId, privateKey) {
  const payload = `ack:${batchHash}:${ackerNodeId}`;
  return {
    batch_hash: batchHash,
    acker_node_id: ackerNodeId,
    signature: mldsaSign(payload, privateKey),
  };
}

/**
 * Verify a batch acknowledgment.
 * @param {Object} ack         The acknowledgment
 * @param {string} publicKey   Acker node's public key from registry
 * @returns {{ valid: boolean, error?: string }}
 */
function verifyBatchAck(ack, publicKey) {
  if (!ack || !ack.batch_hash || !ack.signature) {
    return { valid: false, error: "Ack missing batch_hash or signature" };
  }
  const payload = `ack:${ack.batch_hash}:${ack.acker_node_id}`;
  if (!mldsaVerify(payload, ack.signature, publicKey)) {
    return { valid: false, error: `Ack signature invalid from ${ack.acker_node_id}` };
  }
  return { valid: true };
}

// ─── Certificate ─────────────────────────────────────────────────────────────

/**
 * Create a certificate from a batch and its acknowledgments.
 * @param {number} round            Current round
 * @param {string} authorNodeId     This node's registered ID
 * @param {Object} batch            The batch (already signed)
 * @param {Array}  acknowledgments  BatchAck objects (2/3+ of nodes)
 * @param {Array}  parentHashes     Hashes of parent certificates from round - 1
 * @param {string} privateKey       Node's ML-DSA-65 private key (hex)
 * @returns {Object} Certificate
 */
function createCertificate(round, authorNodeId, batch, acknowledgments, parentHashes, privateKey) {
  const cert = {
    round,
    author_node_id: authorNodeId,
    batch,
    acknowledgments,
    parent_hashes: parentHashes,
    hash: null,
    signature: null,
  };

  // Hash: SHAKE-256(round + author + batch_hash + sorted parent hashes + sorted acker ids)
  const sortedParents = [...parentHashes].sort().join(",");
  const sortedAckers = acknowledgments.map(a => a.acker_node_id).sort().join(",");
  cert.hash = shake256(`cert:${round}:${authorNodeId}:${batch.hash}:${sortedParents}:${sortedAckers}`);

  // Sign the certificate hash
  cert.signature = mldsaSign(cert.hash, privateKey);

  return cert;
}

/**
 * Verify a certificate's integrity, signature, and acknowledgments.
 * @param {Object}   cert          The certificate
 * @param {Function} getNodeKey    (nodeId) => publicKey from registry
 * @param {number}   quorum        Minimum acks required (2/3 of total nodes)
 * @returns {{ valid: boolean, error?: string }}
 */
function verifyCertificate(cert, getNodeKey, quorum) {
  if (!cert || !cert.hash || !cert.signature || !cert.batch) {
    return { valid: false, error: "Certificate missing required fields" };
  }

  // Verify certificate hash
  const sortedParents = [...(cert.parent_hashes || [])].sort().join(",");
  const sortedAckers = (cert.acknowledgments || []).map(a => a.acker_node_id).sort().join(",");
  const expectedHash = shake256(
    `cert:${cert.round}:${cert.author_node_id}:${cert.batch.hash}:${sortedParents}:${sortedAckers}`
  );
  if (expectedHash !== cert.hash) {
    return { valid: false, error: "Certificate hash mismatch" };
  }

  // Verify author signature
  const authorKey = getNodeKey(cert.author_node_id);
  if (!authorKey) {
    return { valid: false, error: `Author ${cert.author_node_id} not in node registry` };
  }
  if (!mldsaVerify(cert.hash, cert.signature, authorKey)) {
    return { valid: false, error: "Certificate signature invalid" };
  }

  // Verify batch
  const batchResult = verifyBatch(cert.batch, authorKey);
  if (!batchResult.valid) {
    return { valid: false, error: `Batch invalid: ${batchResult.error}` };
  }

  // Verify acknowledgments
  const acks = cert.acknowledgments || [];
  if (acks.length < quorum) {
    return { valid: false, error: `Insufficient acks: ${acks.length} < ${quorum}` };
  }

  const seenAckers = new Set();
  for (const ack of acks) {
    if (seenAckers.has(ack.acker_node_id)) {
      return { valid: false, error: `Duplicate ack from ${ack.acker_node_id}` };
    }
    seenAckers.add(ack.acker_node_id);

    const ackerKey = getNodeKey(ack.acker_node_id);
    if (!ackerKey) {
      return { valid: false, error: `Acker ${ack.acker_node_id} not in node registry` };
    }
    const ackResult = verifyBatchAck(ack, ackerKey);
    if (!ackResult.valid) {
      return { valid: false, error: ackResult.error };
    }
    if (ack.batch_hash !== cert.batch.hash) {
      return { valid: false, error: `Ack batch_hash mismatch from ${ack.acker_node_id}` };
    }
  }

  return { valid: true };
}

/**
 * Compute the quorum threshold for a given number of nodes.
 * BFT requires 2f+1 where n >= 3f+1, so quorum = ceil(2n/3).
 * @param {number} nodeCount  Total registered nodes
 * @returns {number}
 */
function computeQuorum(nodeCount) {
  return Math.ceil((2 * nodeCount) / 3);
}

module.exports = {
  createBatch,
  verifyBatch,
  createBatchAck,
  verifyBatchAck,
  createCertificate,
  verifyCertificate,
  computeQuorum,
};
