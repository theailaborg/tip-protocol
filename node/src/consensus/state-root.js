/**
 * @file @tip-protocol/node/src/consensus/state-root.js
 * @description §14 state-snapshot sync — cryptographic roots over a Bullshark commit.
 *
 * Two roots are written into every `commits` row, each with a distinct job:
 *
 *   state_merkle_root
 *     Hash over the full canonical derived-state (identities, content,
 *     dedup, revocations, VPs, nodes) after this commit's txs have been
 *     applied. Answers: "is my app-state at round R the same as yours?"
 *     Used by new joiners to verify a state snapshot they pulled matches
 *     the 2f+1 committee ack that committed this round — without having
 *     to replay the full DAG.
 *
 *   txs_merkle_root
 *     Merkle root over the ordered tx_ids committed at this round (only
 *     THIS commit's txs, not cumulative). Answers: "is tx X included in
 *     the block at round R?" — the inclusion-proof primitive used by
 *     light clients and cross-chain verifiers. Mirrors Ethereum's
 *     `transactions_root` and Tendermint's `data_hash`.
 *
 * Both values MUST be byte-identical on every honest node that applied
 * the same tx sequence — otherwise the commit row forks and §14 sync is
 * broken. See `dag._canonIdentity/_canonContent/...` for the single
 * source of truth on which fields participate.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const crypto = require("crypto");
const { shake256, canonicalJson } = require("../../../shared/crypto");

const EMPTY_STATE_ROOT = shake256("tip:state-root:empty");
const EMPTY_TXS_ROOT = shake256("tip:txs-root:empty");

/**
 * Incremental builder for the state_merkle_root. Used by both the server
 * (streaming `dag.iterateCanonicalState()`) and the client (receiving
 * SnapshotStateRow messages off the wire) — they feed identical rows in
 * identical order and arrive at identical roots.
 *
 * Structure:
 *   root = SHAKE-256( "tip:state-root:v1" || "\x00" ||
 *                     "<table1>:" || H(rows_of_table1) || "\x00" ||
 *                     "<table2>:" || H(rows_of_table2) || "\x00" ||
 *                     ... )
 *
 *   H(rows_of_tableK) = SHAKE-256( canonicalJson(row1) || "\n" ||
 *                                  canonicalJson(row2) || "\n" || ... )
 *
 * The inner `\n` is a length-free separator — safe because canonicalJson
 * never emits raw newlines inside a row (JSON escapes them).
 *
 * Table order is derived from order-of-first-appearance, which matches
 * the order `iterateCanonicalState` yields — consensus-stable on every node.
 *
 * Returns:
 *   {
 *     addRow(table, canonicalRowJson)  -- feed one row (string) OR
 *     addRowObject(table, rowObject)   -- feed one row (object, will canonicalize)
 *     finalize()                       -- produce the root hex string
 *     rowCount()                       -- total rows fed so far
 *   }
 */
function createStateRootBuilder() {
  const perTable = new Map();
  const order = [];
  let total = 0;
  let finalized = false;

  function _hasherFor(table) {
    let h = perTable.get(table);
    if (!h) {
      h = crypto.createHash("shake256", { outputLength: 32 });
      perTable.set(table, h);
      order.push(table);
    }
    return h;
  }

  function addRow(table, canonicalRowJson) {
    if (finalized) throw new Error("StateRootBuilder: finalize() already called");
    if (typeof table !== "string" || !table) throw new Error("addRow: table is required");
    const h = _hasherFor(table);
    h.update(canonicalRowJson, "utf8");
    h.update("\n", "utf8");
    total++;
  }

  function addRowObject(table, rowObject) {
    addRow(table, canonicalJson(rowObject));
  }

  function finalize() {
    if (finalized) throw new Error("StateRootBuilder: finalize() already called");
    finalized = true;
    if (order.length === 0) return EMPTY_STATE_ROOT;
    const outer = crypto.createHash("shake256", { outputLength: 32 });
    outer.update("tip:state-root:v1", "utf8");
    outer.update("\x00", "utf8");
    for (const table of order) {
      outer.update(table, "utf8");
      outer.update(":", "utf8");
      outer.update(perTable.get(table).digest("hex"), "utf8");
      outer.update("\x00", "utf8");
    }
    return outer.digest("hex");
  }

  return { addRow, addRowObject, finalize, rowCount: () => total };
}

/**
 * Compute state_merkle_root by streaming the DAG's canonical state through
 * the builder. Memory stays bounded at one row — scales to networks with
 * millions of rows, matches Cosmos IAVL / Ethereum MPT streaming readers.
 *
 * @param {Object} dag  DAG facade exposing iterateCanonicalState()
 * @returns {string}    64-char hex SHAKE-256 digest
 */
function computeStateMerkleRoot(dag) {
  const b = createStateRootBuilder();
  for (const { table, row } of dag.iterateCanonicalState()) {
    b.addRowObject(table, row);
  }
  return b.finalize();
}

/**
 * Compute txs_merkle_root as a binary SHAKE-256 Merkle tree over the
 * ordered tx_ids committed at this round. Leaf = `SHAKE-256("L" || tx_id)`;
 * internal = `SHAKE-256("N" || left || right)`. Odd levels duplicate the
 * last node (bitcoin-style) so every level's width is even.
 *
 * Domain-separated leaf/internal hashes (RFC 6962 style) prevent
 * second-preimage attacks where a 64-byte leaf could be mistaken for the
 * concatenation of two 32-byte internals.
 *
 * @param {Array<Object>} orderedTxs  Array of {tx_id, ...} in commit order
 * @returns {string}                  64-char hex SHAKE-256 digest
 */
function computeTxsMerkleRoot(orderedTxs) {
  if (!orderedTxs || orderedTxs.length === 0) return EMPTY_TXS_ROOT;

  let level = orderedTxs.map(t => shake256("L" + t.tx_id));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(shake256("N" + left + right));
    }
    level = next;
  }
  return level[0];
}

module.exports = {
  computeStateMerkleRoot,
  computeTxsMerkleRoot,
  createStateRootBuilder,
  EMPTY_STATE_ROOT,
  EMPTY_TXS_ROOT,
};
