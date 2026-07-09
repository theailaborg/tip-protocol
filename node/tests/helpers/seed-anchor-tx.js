/**
 * @file tests/helpers/seed-anchor-tx.js
 * @description Seed a REAL registration tx into the DAG and return its tx_id.
 * Owner-chain prevFor anchors an entity's first tx at its registration tx and
 * prev refs must resolve to committed txs (true in prod, no tx GC), so a
 * fabricated `tx_id: shake256("x")` breaks any tx the entity later signs.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { computeTxId } = require(path.resolve(__dirname, "../../../shared/crypto"));

/**
 * @param {Object} dag  initDAG handle
 * @param {string} txType  e.g. "REGISTER_IDENTITY"
 * @param {Object} data  minimal identifying payload (e.g. { tip_id })
 * @param {number} timestamp  epoch ms
 * @returns {string} the committed stub tx's content-addressed tx_id
 */
function seedAnchorTx(dag, txType, data, timestamp = 1767225600000) {
  const tx = { tx_type: txType, timestamp, prev: [], data, signature: "00" };
  tx.tx_id = computeTxId(tx);   // addTx verifies content-addressing
  dag.addTx(tx);
  return tx.tx_id;
}

module.exports = { seedAnchorTx };
