/**
 * @file @tip-protocol/node/src/consensus/certificate-codec.js
 * @description Wire-format codec for Batch / BatchAck / Certificate.
 *
 * Single source of truth for protobuf <-> JS object translation of the
 * three consensus messages. Used by:
 *   - narwhal.js     (gossipsub broadcast / receive on CONSENSUS topic)
 *   - sync-handler.js (framed cert sync responses on /tip/sync/1.0.0)
 *
 * SEPARATION OF CONCERNS:
 *   - certificate.js     — domain logic (create/verify/hash/sign/median)
 *   - certificate-codec  — wire format (JS object <-> protobuf message)
 *
 * Why split? Two reasons:
 *
 *   1. Drift class. We previously had two pairs of ser/de doing the same
 *      job (one in narwhal, one in sync-handler). When BFT-Time added
 *      `signed_at` and `timestamp`, both copies had to update — easy to
 *      miss one and silently break sync. One codec, one update.
 *
 *   2. Concerns. Domain logic (what is a cert, how does it verify) is
 *      independent of wire format (how do we put it on the network). If
 *      we ever switch encodings (msgpack, JSON, Borsh) only the codec
 *      module changes; certificate.js stays put.
 *
 * FIELD NAMING:
 *   - JS objects use snake_case  (acker_node_id, batch_hash, signed_at)
 *   - Protobuf messages use camelCase (ackerNodeId, batchHash, signedAt)
 *     because protobufjs codegen emits camelCase by default.
 *   - Hashes: JS uses hex strings, protobuf uses raw bytes.
 *   - Timestamps: integer epoch ms on both sides; protobuf int64 returns
 *     a Long object when value > 2^32, so we coerce to plain Number.
 *     Safe up to Number.MAX_SAFE_INTEGER (year ~285K AD).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { bytesToHex, hexToBytes, bytesToUtf8 } = require("../network/proto");

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Coerce a protobuf int64 (Long object) or number to a plain JS Number.
 * Safe up to 2^53 — our timestamps are ~10^12 ms so we have ~3 orders of
 * magnitude of headroom.
 */
function _toInt(v) {
  if (v == null) return 0;
  if (typeof v === "object") return Number(v.toString());
  return Number(v);
}

// ─── Batch ───────────────────────────────────────────────────────────────────

function serializeBatch(batch) {
  return {
    round: batch.round,
    authorNodeId: batch.author_node_id,
    txs: (batch.txs || []).map(tx => ({
      txId: tx.tx_id || "",
      txType: tx.tx_type || "",
      timestamp: tx.timestamp || "",
      prev: tx.prev || [],
      data: Buffer.from(JSON.stringify(tx.data || {})),
      signature: hexToBytes(tx.signature),
    })),
    signature: hexToBytes(batch.signature),
    hash: hexToBytes(batch.hash),
  };
}

function deserializeBatch(msg) {
  if (!msg) return { round: 0, author_node_id: "", txs: [], signature: null, hash: null };
  return {
    round: msg.round || 0,
    author_node_id: msg.authorNodeId || "",
    txs: (msg.txs || []).map(tx => ({
      tx_id: tx.txId || "",
      tx_type: tx.txType || "",
      timestamp: tx.timestamp || "",
      prev: tx.prev || [],
      data: tx.data?.length ? (() => { try { return JSON.parse(bytesToUtf8(tx.data)); } catch { return {}; } })() : {},
      signature: bytesToHex(tx.signature),
    })),
    signature: bytesToHex(msg.signature),
    hash: bytesToHex(msg.hash),
  };
}

// ─── BatchAck ────────────────────────────────────────────────────────────────

function serializeBatchAck(ack) {
  return {
    batchHash: hexToBytes(ack.batch_hash),
    ackerNodeId: ack.acker_node_id || "",
    signature: hexToBytes(ack.signature),
    signedAt: ack.signed_at,
  };
}

function deserializeBatchAck(msg) {
  return {
    batch_hash: bytesToHex(msg.batchHash) || "",
    acker_node_id: msg.ackerNodeId || "",
    signature: bytesToHex(msg.signature) || "",
    signed_at: _toInt(msg.signedAt),
  };
}

// ─── Certificate ─────────────────────────────────────────────────────────────

function serializeCertificate(cert) {
  return {
    round: cert.round,
    authorNodeId: cert.author_node_id,
    batch: serializeBatch(cert.batch),
    acknowledgments: (cert.acknowledgments || []).map(serializeBatchAck),
    parentHashes: (cert.parent_hashes || []).map(h => hexToBytes(h)),
    signature: hexToBytes(cert.signature),
    hash: hexToBytes(cert.hash),
    timestamp: cert.timestamp,
  };
}

function deserializeCertificate(msg) {
  if (!msg) {
    return {
      round: 0,
      author_node_id: "",
      batch: deserializeBatch(null),
      acknowledgments: [],
      parent_hashes: [],
      signature: null,
      hash: null,
      timestamp: 0,
    };
  }
  return {
    round: msg.round || 0,
    author_node_id: msg.authorNodeId || "",
    batch: deserializeBatch(msg.batch),
    acknowledgments: (msg.acknowledgments || []).map(deserializeBatchAck),
    parent_hashes: (msg.parentHashes || []).map(h => bytesToHex(h)).filter(Boolean),
    signature: bytesToHex(msg.signature),
    hash: bytesToHex(msg.hash),
    timestamp: _toInt(msg.timestamp),
  };
}

module.exports = {
  serializeBatch,
  deserializeBatch,
  serializeBatchAck,
  deserializeBatchAck,
  serializeCertificate,
  deserializeCertificate,
};
