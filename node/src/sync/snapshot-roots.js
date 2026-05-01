/**
 * @file @tip-protocol/node/src/sync/snapshot-roots.js
 * @description §14/#49 wire-format integrity roots for snapshot fast-sync.
 *
 * Two roots cover the pre-snapshot tx and commit history streamed
 * alongside SnapshotStateRow:
 *
 *   txs_full_root      — flat SHAKE-256 over canonical-JSON of every
 *                        row in `transactions`, in tx_id order.
 *   commits_full_root  — flat SHAKE-256 over canonical-JSON of every
 *                        row in `commits` EXCEPT the latest (the latest
 *                        already rides in SnapshotHeader), in round order.
 *
 * Distinct from `consensus/state-root.js`:
 *   state-root computes the consensus-critical roots that get baked into
 *   `commits` rows and signed by 2f+1 (state_merkle_root, txs_merkle_root).
 *   Those are CONSENSUS STATE.
 *
 *   The roots here are NOT in commit rows, NOT signed by 2f+1, and exist
 *   only as a stream-tampering checksum on the snapshot wire format.
 *   Computed fresh on each snapshot serve. SYNC LAYER.
 *
 * Both sender and receiver feed identical canonical-row sequences through
 * the same builder → arrive at identical hex digests. Mismatch on either
 * root rejects the snapshot install.
 *
 * Must match python/tip_node/snapshot_roots.py when that's lit up.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const crypto = require("crypto");
const { shake256, canonicalJson } = require("../../../shared/crypto");

const EMPTY_TXS_FULL_ROOT = shake256("tip:txs-full-root:empty");
const EMPTY_COMMITS_FULL_ROOT = shake256("tip:commits-full-root:empty");
const EMPTY_ROTATIONS_FULL_ROOT = shake256("tip:rotations-full-root:empty");

/**
 * Flat sequential SHAKE-256 builder.
 *
 * Structure:
 *   root = SHAKE-256( "<domain>" || "\x00" ||
 *                     canonicalJson(row1) || "\n" ||
 *                     canonicalJson(row2) || "\n" || ... )
 *
 * The `\n` separator is length-free; safe because canonicalJson never
 * emits raw newlines inside a row (JSON escapes them). The `\x00` after
 * the domain prefix prevents prefix-extension confusion between empty
 * and one-row inputs.
 */
function _createFullRootBuilder(domain, emptyRoot) {
  const h = crypto.createHash("shake256", { outputLength: 32 });
  let count = 0;
  let started = false;
  let finalized = false;

  function addRow(canonicalRowJson) {
    if (finalized) throw new Error("FullRootBuilder: finalize() already called");
    if (!started) {
      h.update(domain, "utf8");
      h.update("\x00", "utf8");
      started = true;
    }
    h.update(canonicalRowJson, "utf8");
    h.update("\n", "utf8");
    count++;
  }

  function addRowObject(rowObject) {
    addRow(canonicalJson(rowObject));
  }

  function finalize() {
    if (finalized) throw new Error("FullRootBuilder: finalize() already called");
    finalized = true;
    if (count === 0) return emptyRoot;
    return h.digest("hex");
  }

  return { addRow, addRowObject, finalize, rowCount: () => count };
}

function createTxsFullRootBuilder() {
  return _createFullRootBuilder("tip:txs-full-root:v1", EMPTY_TXS_FULL_ROOT);
}

function createCommitsFullRootBuilder() {
  return _createFullRootBuilder("tip:commits-full-root:v1", EMPTY_COMMITS_FULL_ROOT);
}

function createRotationsFullRootBuilder() {
  return _createFullRootBuilder("tip:rotations-full-root:v1", EMPTY_ROTATIONS_FULL_ROOT);
}

/**
 * Canonical projection of a tx row for snapshot hashing + wire form.
 * SnapshotTxRow.canonical_json on the wire MUST equal
 * canonicalJson(canonTx(tx)) on both sides.
 */
function canonTx(tx) {
  return {
    tx_id: tx.tx_id,
    tx_type: tx.tx_type,
    data: tx.data,
    timestamp: tx.timestamp,
    prev: tx.prev || [],
    signature: tx.signature || null,
  };
}

/**
 * Canonical projection of a commit row for snapshot hashing + wire form.
 * Field order matches the commits table schema. Same canonical form is
 * used by sender to populate SnapshotCommitRow.canonical_json and by
 * receiver to recompute the root and install via dag.saveCommit.
 */
function canonCommit(c) {
  return {
    round: c.round,
    anchor_cert_hash: c.anchor_cert_hash,
    // #50: included so post-#50 commit rows carry their self-contained
    // batch_hash through the wire and into the receiver's commits table.
    // null for pre-#50 rows — they ship as null, joiner stores null,
    // and snapshot-handler falls back to cert lookup if such a row is
    // ever served as the latest (only possible for old DBs that
    // existed before this column was migrated in).
    anchor_batch_hash: c.anchor_batch_hash || null,
    leader_node_id: c.leader_node_id,
    committee: c.committee || [],
    support_count: c.support_count,
    consensus_index: c.consensus_index,
    committed_at: c.committed_at,
    state_merkle_root: c.state_merkle_root,
    txs_merkle_root: c.txs_merkle_root,
    ack_signer_ids: c.ack_signer_ids || [],
    ack_signatures: c.ack_signatures || [],
    // BFT-Time: included so commits_full_root binds the timestamp +
    // signed_at array on every commit. Default fallbacks ([] and 0) keep
    // pre-BFT-Time rows hashable consistently across nodes during the
    // upgrade boundary, but post-upgrade these fields are always populated
    // on real commits.
    ack_signed_ats: c.ack_signed_ats || [],
    cert_timestamp: c.cert_timestamp || 0,
  };
}

/**
 * Canonical projection of a committee_history row for snapshot hashing
 * + wire form. SnapshotCommitteeRotationRow.canonical_json on the wire
 * MUST equal canonicalJson(canonRotation(r)) on both sides.
 *
 * Determinism contract: committee and signer_node_ids must be sorted
 * by caller before save (commit-handler enforces this for new rotations
 * via canCommitteeRotation; bootstrap rotation 0 sorts founding_node
 * trivially as a single-element array). signatures is parallel to
 * signer_node_ids.
 *
 * `committed_at` is DELIBERATELY EXCLUDED — it's wall-clock informational
 * and would diverge across nodes that wrote the row at slightly different
 * local times. Excluding it keeps the rotations_full_root deterministic
 * across nodes. Chain-of-trust walker reads everything it needs from
 * the canonical fields here; committed_at is informational only.
 */
function canonRotation(r) {
  return {
    rotation_number: r.rotation_number,
    effective_round: r.effective_round,
    committee: r.committee || [],
    prev_rotation: r.prev_rotation == null ? null : r.prev_rotation,
    signer_node_ids: r.signer_node_ids || [],
    signatures: r.signatures || [],
    payload_hash: r.payload_hash || null,
  };
}

/**
 * Compute rotations_full_root by streaming `dag.getRotationsFromGenesis()`.
 * Memory bounded at one row. Same wire-integrity role as txs_full_root /
 * commits_full_root — guards against truncation or tampering of the
 * rotation stream. The cryptographic chain-of-trust verification (sigs
 * from previous committee, anchored at LOCAL genesis) runs separately
 * AFTER the root match passes.
 */
function computeRotationsFullRoot(dag) {
  const b = createRotationsFullRootBuilder();
  for (const r of dag.getRotationsFromGenesis()) {
    b.addRowObject(canonRotation(r));
  }
  return b.finalize();
}

/**
 * Compute txs_full_root by streaming `dag.iterateAllTransactions()`.
 * Memory bounded at one row.
 */
function computeTxsFullRoot(dag) {
  const b = createTxsFullRootBuilder();
  for (const tx of dag.iterateAllTransactions()) {
    b.addRowObject(canonTx(tx));
  }
  return b.finalize();
}

/**
 * Compute commits_full_root by streaming `dag.iterateAllCommitsExcept(latest)`.
 * Excludes the latest commit (which rides in SnapshotHeader); both sender
 * and receiver pass the same `latestRound` so the iteration is identical.
 */
function computeCommitsFullRoot(dag, latestRound) {
  const b = createCommitsFullRootBuilder();
  for (const c of dag.iterateAllCommitsExcept(latestRound)) {
    b.addRowObject(canonCommit(c));
  }
  return b.finalize();
}

module.exports = {
  computeTxsFullRoot,
  computeCommitsFullRoot,
  computeRotationsFullRoot,
  createTxsFullRootBuilder,
  createCommitsFullRootBuilder,
  createRotationsFullRootBuilder,
  canonTx,
  canonCommit,
  canonRotation,
  EMPTY_TXS_FULL_ROOT,
  EMPTY_COMMITS_FULL_ROOT,
  EMPTY_ROTATIONS_FULL_ROOT,
};
