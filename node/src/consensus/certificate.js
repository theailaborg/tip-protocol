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

const { nowMs } = require("../../../shared/time");

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
    log.warn(`Batch hash mismatch debug — expected: ${expectedHash.slice(0, 16)}, got: ${batch.hash.slice(0, 16)}, input: "batch:${batch.round}:${batch.author_node_id}:${txIds}"`);
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
 * Build the canonical payload an acker signs.
 * `signed_at` is part of the signed scope so no relayer (including the cert
 * author) can alter the timestamp without invalidating the signature. This
 * is the BFT-Time pattern (Tendermint, Sui, Aptos).
 *
 * @param {string} batchHash
 * @param {string} ackerNodeId
 * @param {number} signedAt    Integer epoch ms (nowMs())
 * @returns {string}
 */
function _ackSignPayload(batchHash, ackerNodeId, signedAt) {
  return `ack:${batchHash}:${ackerNodeId}:${signedAt}`;
}

/**
 * Create an acknowledgment for a received batch.
 * @param {string} batchHash      Hash of the batch being acknowledged
 * @param {string} ackerNodeId    This node's registered ID
 * @param {number} signedAt       Acker's wall-clock at sign time (epoch ms)
 * @param {string} privateKey     This node's ML-DSA-65 private key (hex)
 * @returns {{ batch_hash, acker_node_id, signed_at, signature }}
 */
function createBatchAck(batchHash, ackerNodeId, signedAt, privateKey) {
  if (!Number.isInteger(signedAt) || signedAt <= 0) {
    throw new Error(`createBatchAck: signed_at must be a positive integer ms, got ${signedAt}`);
  }
  return {
    batch_hash: batchHash,
    acker_node_id: ackerNodeId,
    signed_at: signedAt,
    signature: mldsaSign(_ackSignPayload(batchHash, ackerNodeId, signedAt), privateKey),
  };
}

/**
 * Verify a batch acknowledgment.
 * @param {Object} ack         The acknowledgment ({batch_hash, acker_node_id, signed_at, signature})
 * @param {string} publicKey   Acker node's public key from registry
 * @returns {{ valid: boolean, error?: string }}
 */
function verifyBatchAck(ack, publicKey) {
  if (!ack || !ack.batch_hash || !ack.signature) {
    return { valid: false, error: "Ack missing batch_hash or signature" };
  }
  if (!Number.isInteger(ack.signed_at) || ack.signed_at <= 0) {
    return { valid: false, error: `Ack signed_at must be a positive integer ms, got ${ack.signed_at}` };
  }
  const payload = _ackSignPayload(ack.batch_hash, ack.acker_node_id, ack.signed_at);
  if (!mldsaVerify(payload, ack.signature, publicKey)) {
    return { valid: false, error: `Ack signature invalid from ${ack.acker_node_id}` };
  }
  return { valid: true };
}

// ─── BFT Time helpers ────────────────────────────────────────────────────────

/**
 * Median of a list of integers. Used to derive `cert.timestamp` from
 * `acks.signed_at`. Tolerates up to f outliers in 2f+1 inputs — a single
 * byzantine acker cannot move the median.
 *
 * Even-count case uses floor((mid_low + mid_high) / 2) so every node
 * computes the identical integer (no floating-point determinism risk).
 *
 * @param {number[]} values
 * @returns {number}
 */
function computeMedianTimestamp(values) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error("computeMedianTimestamp: values must be a non-empty array");
  }
  for (const v of values) {
    if (!Number.isInteger(v) || v <= 0) {
      throw new Error(`computeMedianTimestamp: every value must be a positive integer ms, got ${v}`);
    }
  }
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  if (sorted.length % 2 === 0) {
    return Math.floor((sorted[mid - 1] + sorted[mid]) / 2);
  }
  return sorted[mid];
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
  // BFT Time — `cert.timestamp` is the median of acker wall-clocks at sign
  // time. Pure deterministic compute from the acks themselves, so any
  // receiver can recompute and verify it. No bump for monotonicity here —
  // cross-round monotonicity is enforced at Bullshark anchor commit, where
  // prev_anchor.timestamp is available from the never-GC'd `commits` table.
  const timestamp = computeMedianTimestamp(acknowledgments.map(a => a.signed_at));

  const cert = {
    round,
    author_node_id: authorNodeId,
    batch,
    acknowledgments,
    parent_hashes: parentHashes,
    timestamp,
    hash: null,
    signature: null,
  };

  // Hash input includes `timestamp` so any tampering invalidates cert.hash
  // and is caught by every receiver before they trust the timestamp.
  const sortedParents = [...parentHashes].sort().join(",");
  const sortedAckers = acknowledgments.map(a => a.acker_node_id).sort().join(",");
  cert.hash = shake256(`cert:${round}:${authorNodeId}:${batch.hash}:${sortedParents}:${sortedAckers}:${timestamp}`);

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
  if (!Number.isInteger(cert.timestamp) || cert.timestamp <= 0) {
    return { valid: false, error: `Certificate timestamp must be a positive integer ms, got ${cert.timestamp}` };
  }

  // Verify certificate hash (includes timestamp — tampering with the
  // timestamp invalidates the hash and gets caught here before any
  // downstream code trusts it).
  const sortedParents = [...(cert.parent_hashes || [])].sort().join(",");
  const sortedAckers = (cert.acknowledgments || []).map(a => a.acker_node_id).sort().join(",");
  const expectedHash = shake256(
    `cert:${cert.round}:${cert.author_node_id}:${cert.batch.hash}:${sortedParents}:${sortedAckers}:${cert.timestamp}`
  );
  if (expectedHash !== cert.hash) {
    log.warn(`Cert hash mismatch debug — expected: ${expectedHash.slice(0, 16)}, got: ${cert.hash.slice(0, 16)}`);
    log.warn(`  input: "cert:${cert.round}:${cert.author_node_id}:${cert.batch?.hash}:${sortedParents}:${sortedAckers}:${cert.timestamp}"`);
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

  // BFT Time — recompute median(acks.signed_at) and require equality with
  // cert.timestamp. The cert author cannot fabricate a timestamp; it must
  // be the deterministic median of the signed_at values that are
  // cryptographically bound to each acker's signature (via the ack hash
  // payload). One byzantine acker is tolerated (median rejects outliers);
  // f byzantine ackers cannot move the median past the honest middle.
  const expectedTimestamp = computeMedianTimestamp(acks.map(a => a.signed_at));
  if (cert.timestamp !== expectedTimestamp) {
    return {
      valid: false,
      error: `Certificate timestamp mismatch — expected median ${expectedTimestamp}, got ${cert.timestamp}`,
    };
  }

  return { valid: true };
}

/**
 * BFT quorum = ceil(2n/3): the smallest quorum that forces any two quorums to
 * overlap in an honest node (2q - n >= f+1). It's the ">2/3 of voting power" rule
 * of Sui/Tendermint/HotStuff (they use floor(2n/3)+1, equal except one stricter at
 * n divisible by 3). NOT 2f+1 — that only equals this at n=3f+1 and is unsafe
 * otherwise (n=5 it gives 3, which forks under one byzantine node). Single source
 * of truth — every caller MUST use this, never a hand-rolled formula.
 * @param {number} nodeCount  Committee size (n)
 * @returns {number}
 */
function computeQuorum(nodeCount) {
  return Math.ceil((2 * nodeCount) / 3);
}

/**
 * Smallest distinct-disagreer count at which we conclude we are the
 * byzantine minority and must halt our own consensus loop.
 *
 * Formal BFT: with at most f = floor((n-1)/3) byzantine peers, f+1
 * disagreers includes ≥1 honest peer — so we are the wrong one. Below
 * f+1, we can't tell who's wrong (could be us, could be them); the
 * per-peer ack-filter handles individual disagreers without halting.
 *
 * Floor of 2 for small federations (n=3): formal f+1 there is 1, but
 * a single disagreer carries no signal in a 3-node committee. We need
 * both other peers (= 2) to be certain we're wrong. For n>=4 the formal
 * f+1 is already >=2 so the floor is redundant — those values are
 * unchanged. For n<=1 there's nothing to compare against, so we return
 * Infinity (the threshold is never reached → halt never fires).
 *
 * Single source of truth — both anti-entropy and any future BFT-aware
 * caller MUST use this function instead of recomputing the formula.
 *
 * @param {number} committeeSize  Total committee members (n)
 * @returns {number}  threshold; Infinity if n<=1
 */
function bftHaltThreshold(committeeSize) {
  const n = Number(committeeSize) || 0;
  if (n <= 1) return Infinity;
  return Math.max(Math.floor((n - 1) / 3) + 1, 2);
}

module.exports = {
  createBatch,
  verifyBatch,
  createBatchAck,
  verifyBatchAck,
  computeMedianTimestamp,
  createCertificate,
  verifyCertificate,
  computeQuorum,
  bftHaltThreshold,
};
