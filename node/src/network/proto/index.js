/**
 * @file Protobuf message type loader for TIP consensus protocol.
 *
 * Loads and caches all message types from tip-consensus.proto.
 * Usage:
 *   const { types } = require("./proto");
 *   const buffer = types.Certificate.encode(cert).finish();
 *   const decoded = types.Certificate.decode(buffer);
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const protobuf = require("protobufjs");
const { getLogger } = require("../../logger");

const log = getLogger("tip.proto");

let _root = null;
let _types = null;

/**
 * Load and cache Protobuf message types.
 * @returns {Promise<Object>} Map of message type name → protobufjs Type
 */
async function loadTypes() {
  if (_types) return _types;

  const protoPath = path.join(__dirname, "tip-consensus.proto");
  _root = await protobuf.load(protoPath);

  const TYPE_NAMES = [
    "tip.consensus.Transaction",
    "tip.consensus.Batch",
    "tip.consensus.BatchAck",
    "tip.consensus.Certificate",
    "tip.consensus.SyncRequest",
    "tip.consensus.SyncResponse",
    "tip.consensus.RoundAdvance",
    "tip.consensus.MempoolTx",
    "tip.consensus.Handshake",
    "tip.consensus.HandshakeAck",
    // §14 state-snapshot sync
    "tip.consensus.SnapshotRequest",
    "tip.consensus.SnapshotHeader",
    "tip.consensus.SnapshotStateRow",
    "tip.consensus.SnapshotEnd",
  ];

  _types = {};
  for (const fullName of TYPE_NAMES) {
    const shortName = fullName.split(".").pop();
    _types[shortName] = _root.lookupType(fullName);
  }

  log.info(`Protobuf types loaded: ${Object.keys(_types).join(", ")}`);
  return _types;
}

/**
 * Get cached types (must call loadTypes() first).
 * @returns {Object} Map of message type name → protobufjs Type
 */
function getTypes() {
  if (!_types) throw new Error("Protobuf types not loaded — call loadTypes() first");
  return _types;
}

/**
 * Encode a message to a Buffer.
 * @param {string} typeName  e.g. "Certificate"
 * @param {Object} payload   Plain JS object matching the proto schema
 * @returns {Buffer}
 */
function encode(typeName, payload) {
  const types = getTypes();
  const Type = types[typeName];
  if (!Type) throw new Error(`Unknown protobuf type: ${typeName}`);
  const errMsg = Type.verify(payload);
  if (errMsg) throw new Error(`Protobuf validation failed for ${typeName}: ${errMsg}`);
  return Buffer.from(Type.encode(Type.create(payload)).finish());
}

/**
 * Decode a Buffer to a plain JS object.
 * @param {string} typeName  e.g. "Certificate"
 * @param {Buffer|Uint8Array} buffer
 * @returns {Object}
 */
function decode(typeName, buffer) {
  const types = getTypes();
  const Type = types[typeName];
  if (!Type) throw new Error(`Unknown protobuf type: ${typeName}`);
  return Type.toObject(Type.decode(buffer), {
    longs: Number,
    bytes: Buffer,
    defaults: true,
  });
}

// ─── Byte-field conversion helpers ───────────────────────────────────────────
//
// protobufjs honours `bytes: Buffer` for top-level fields but may return
// Uint8Array for nested or repeated bytes. Uint8Array.toString("hex") silently
// ignores the encoding arg and returns comma-separated decimals, corrupting
// hashes at verify time. These helpers normalise both directions.

/**
 * Convert a bytes-like value (Buffer, Uint8Array, or hex string) to a hex string.
 */
function bytesToHex(b) {
  if (b == null) return null;
  if (typeof b === "string") return b;
  if (!b.length) return null;
  return Buffer.from(b).toString("hex");
}

/**
 * Convert a hex string (or bytes-like value) to a Buffer for protobuf encoding.
 */
function hexToBytes(h) {
  if (h == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(h)) return h;
  if (h instanceof Uint8Array) return Buffer.from(h);
  return Buffer.from(h, "hex");
}

/**
 * Convert a bytes-like value to a UTF-8 string (e.g. for JSON.parse).
 */
function bytesToUtf8(b) {
  if (b == null) return "";
  if (typeof b === "string") return b;
  if (!b.length) return "";
  return Buffer.from(b).toString();
}

module.exports = { loadTypes, getTypes, encode, decode, bytesToHex, hexToBytes, bytesToUtf8 };