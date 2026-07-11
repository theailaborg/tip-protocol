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
const merkle = require("../../../shared/merkle");
const { createSMT, EMPTY_SMT_ROOT } = require("../../../shared/smt");

const EMPTY_STATE_ROOT = EMPTY_SMT_ROOT();
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
// Per-table primary key extraction from the CANONICAL row , protocol spec,
// shared by the incremental tree (dag.js) and the streaming verifier below.
const STATE_PK = {
  identities: r => r.tip_id,
  content: r => r.ctid,
  scores: r => r.tip_id,
  dedup_registry: r => r.dedup_hash,
  revocations: r => r.tip_id,
  domain_bindings: r => r.domain,
  platform_links: r => r.id,
  verification_providers: r => r.vp_id,
  nodes: r => r.node_id,
  entity_keys: r => `${r.entity_type}:${r.entity_id}:${r.valid_from_ts}`,
  prescan_reviews: r => r.review_id,
  interests_registry: r => r.slug,
  protocol_params: r => `${r.param_key}\x00${r.effective_from_height}`,
  owner_heads: r => r.entity_key,
};

function stateLeafKey(table, pk) {
  return shake256(table + "\x00" + pk);
}

/**
 * Streaming state-root builder over canonical rows , SMT-backed (#88).
 * Insertion order no longer matters (tree is a pure function of the row
 * set), but callers keep streaming exactly as before.
 */
function createStateRootBuilder() {
  const smt = createSMT();
  let total = 0;
  let finalized = false;

  function _add(table, pk, canonicalRowJson) {
    if (finalized) throw new Error("StateRootBuilder: finalize() already called");
    smt.set(stateLeafKey(table, String(pk)), shake256(canonicalRowJson));
    total++;
  }

  function _pkOf(table) {
    const pkOf = STATE_PK[table];
    if (typeof table !== "string" || !pkOf) throw new Error(`StateRootBuilder: unknown canonical table "${table}"`);
    return pkOf;
  }

  // Object path (dag walk): pk from the object , no round-trip through JSON.
  function addRowObject(table, rowObject) {
    _add(table, _pkOf(table)(rowObject), canonicalJson(rowObject));
  }

  // Wire path (snapshot rows arrive as canonical strings). The snapshot
  // handler JSON.parses the same string for its own bookkeeping, so
  // parseability of real canonical rows is an existing wire invariant.
  function addRow(table, canonicalRowJson) {
    let row;
    try { row = JSON.parse(canonicalRowJson); }
    catch (err) { throw new Error(`row canonical_json parse failed: ${err.message}`); }
    _add(table, _pkOf(table)(row), canonicalRowJson);
  }

  function finalize() {
    if (finalized) throw new Error("StateRootBuilder: finalize() already called");
    finalized = true;
    return smt.root();
  }

  return { addRow, addRowObject, finalize, rowCount: () => total };
}

/**
 * Reference state root: stream the DAG's canonical rows through the
 * SMT-backed builder. Equivalent to dag.stateRoot() (which is O(1)); kept
 * as the independent cross-check the determinism tests assert against, and
 * used by snapshot verification.
 * @param {Object} dag  exposes iterateCanonicalState()
 * @returns {string}
 */
function computeStateMerkleRoot(dag) {
  const b = createStateRootBuilder();
  for (const { table, row } of dag.iterateCanonicalState()) {
    b.addRowObject(table, row);
  }
  return b.finalize();
}

/**
 * Diagnostic: per-table sub-root + row count over the canonical state.
 * Lets snapshot-install mismatches pinpoint WHICH table diverged (and how
 * many rows) instead of only seeing the aggregate root differ. Same leaf
 * function as the aggregate root, grouped by table.
 * @param {Object} dag  exposes iterateCanonicalState()
 * @returns {Array<{table:string,count:number,root:string}>}
 */
function computeStateMerkleRootPerTable(dag) {
  const byTable = new Map();
  for (const { table, row } of dag.iterateCanonicalState()) {
    let e = byTable.get(table);
    if (!e) { e = { smt: createSMT(), count: 0 }; byTable.set(table, e); }
    const pk = STATE_PK[table] ? STATE_PK[table](row) : JSON.stringify(row);
    e.smt.set(stateLeafKey(table, String(pk)), shake256(canonicalJson(row)));
    e.count++;
  }
  const out = [];
  for (const [table, e] of byTable) out.push({ table, count: e.count, root: e.smt.root().slice(0, 16) });
  return out;
}

/**
 * Compare the committed incremental SMT root against the independent reference
 * walk. A deterministic desync makes every node agree on the same wrong root, so
 * only this recompute catches it; the caller must halt on divergence. perTable is
 * set only on mismatch. O(state), call it throttled.
 * @param {Object} dag  exposes stateRoot() + iterateCanonicalState()
 * @returns {{consistent:boolean, incremental:string, reference:string, perTable:(Array|null)}}
 */
function verifyStateRootConsistency(dag) {
  const incremental = dag.stateRoot();
  const reference = computeStateMerkleRoot(dag);
  const consistent = incremental === reference;
  return { consistent, incremental, reference, perTable: consistent ? null : computeStateMerkleRootPerTable(dag) };
}

// Sliced variant of verifyStateRootConsistency for the periodic integrity
// timer: the synchronous walk is O(state) in ONE event-loop task (~0.5s at
// a few hundred rows, measured idle-stall spikes 2026-07-11). Yields every
// `yieldEvery` rows; state mutating mid-walk makes the reference meaningless,
// so the O(1) incremental root is read before and after and a mismatch
// returns { skipped: true } , the next cycle retries.
async function verifyStateRootConsistencyAsync(dag, { yieldEvery = 256 } = {}) {
  const before = dag.stateRoot();
  const b = createStateRootBuilder();
  let n = 0;
  for (const { table, row } of dag.iterateCanonicalState()) {
    b.addRowObject(table, row);
    if ((++n % yieldEvery) === 0) await new Promise((r) => setImmediate(r));
  }
  const reference = b.finalize();
  const incremental = dag.stateRoot();
  if (incremental !== before) return { skipped: true, consistent: true, incremental, reference: null, perTable: null };
  const consistent = incremental === reference;
  return { skipped: false, consistent, incremental, reference, perTable: consistent ? null : computeStateMerkleRootPerTable(dag) };
}

function computeTxsMerkleRoot(orderedTxs) {
  if (!orderedTxs || orderedTxs.length === 0) return EMPTY_TXS_ROOT;
  return merkle.computeRoot(orderedTxs.map(t => t.tx_id));
}

module.exports = {
  computeStateMerkleRoot,
  computeStateMerkleRootPerTable,
  verifyStateRootConsistency,
  verifyStateRootConsistencyAsync,
  STATE_PK,
  stateLeafKey,
  computeTxsMerkleRoot,
  createStateRootBuilder,
  EMPTY_STATE_ROOT,
  EMPTY_TXS_ROOT,
};
