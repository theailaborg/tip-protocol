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

module.exports = { loadTypes, getTypes, encode, decode };