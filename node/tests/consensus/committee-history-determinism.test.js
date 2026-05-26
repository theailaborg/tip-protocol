/**
 * @file tests/consensus/committee-history-determinism.test.js
 * @description Regression guard for the invariant that committee_history
 * is byte-identical across all honest nodes for any given rotation_number.
 *
 * The clear-then-INSERT pattern in snapshot-handler was historically
 * defending against a class of divergence ("byzantine fork" → different
 * payload_hash for the same rotation_number) that consensus is supposed
 * to prevent upstream. This file pins that invariant explicitly so any
 * future change that breaks it shows up as a test failure rather than a
 * silent state divergence at the merkle root.
 *
 * Coverage:
 *   1. Multi-aggregator submission: three competing rotation txs for the
 *      same rotation_number (different cosignature accumulations) in one
 *      ordered batch → only the FIRST commits; second + third rejected.
 *   2. Cross-node determinism: two independent DAG instances given the
 *      same ordered batch produce byte-identical committee_history and
 *      transactions tables for COMMITTEE_ROTATION rows.
 *
 * Test fixture uses the same 4-node "test federation" pattern as the
 * adjacent commit-handler-committee-rotation.test.js: rotation 0 is
 * pre-installed with a controlled committee whose private keys are in
 * scope, so rotation 1 can be exercised with real ML-DSA signatures.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");

const { nowMs } = require("../../../shared/time");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, mldsaSign, shake256, canonicalJson,
} = require(path.join(SHARED, "crypto"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { GENESIS_TX_ID } = require(path.join(SRC, "genesis"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-driver";

function _tmpDbPath() {
  return path.join(os.tmpdir(), `tip-ch-determinism-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
}

function _cleanup(dbPath) {
  for (const ext of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
}

function _testCommittee(size = 4) {
  const committee = [];
  const keys = {};
  for (let i = 0; i < size; i++) {
    const kp = generateMLDSAKeypair();
    const node_id = `tip://node/test-${i}`;
    committee.push({ node_id, public_key: kp.publicKey });
    keys[node_id] = kp.privateKey;
  }
  committee.sort((a, b) => a.node_id.localeCompare(b.node_id));
  return { committee, keys };
}

function _replaceRotation0(dbPath, committee) {
  const Database = require("better-sqlite3");
  const raw = new Database(dbPath);
  try {
    raw.prepare("DELETE FROM committee_history").run();
    const payload_hash = shake256(canonicalJson({
      rotation_number: 0, effective_round: 0, committee,
    }));
    raw.prepare(
      `INSERT INTO committee_history (rotation_number, effective_round, committee, prev_rotation,
                                       signer_node_ids, signatures, payload_hash, committed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(0, 0, JSON.stringify(committee), null, '[]', '[]', payload_hash, 1767225600000);
  } finally {
    raw.close();
  }
}

/**
 * Build a rotation-N tx with sigs from the given signer subset of
 * prevCommittee. Different signer subsets → different cosignatures
 * array → different tx_id, even when rotation_number / effective_round /
 * new_committee / payload_hash are identical. Mirrors what happens
 * under multi-aggregator submission when each aggregator has
 * accumulated a different subset of prev-committee signatures.
 */
function _buildRotationTx({ rotation_number, effective_round, new_committee, signerNodeIds, prevKeys }) {
  const payload_hash = shake256(canonicalJson({
    rotation_number, effective_round, committee: new_committee,
  }));
  const cosignatures = signerNodeIds.map(signerId => ({
    signer_kind: "node",
    signer_ref:  signerId,
    signature:   mldsaSign(`rotation:${payload_hash}:${signerId}`, prevKeys[signerId]),
  }));
  const data = {
    rotation_number, effective_round, new_committee, payload_hash, cosignatures,
  };
  const tx = {
    tx_type: TX_TYPES.COMMITTEE_ROTATION,
    timestamp: 1777507200000,
    prev: [GENESIS_TX_ID, GENESIS_TX_ID],
    data,
  };
  tx.tx_id = shake256(canonicalJson({
    tx_type: tx.tx_type, data: tx.data, timestamp: tx.timestamp, prev: tx.prev,
  }));
  return tx;
}

function _setupNode() {
  const dbPath = _tmpDbPath();
  let dag = initDAG({ dbPath });
  dag.close();
  const { committee: prevCommittee, keys: prevKeys } = _testCommittee(4);
  _replaceRotation0(dbPath, prevCommittee);
  dag = initDAG({ dbPath });

  const driverKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "test-driver", public_key: driverKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  for (const m of prevCommittee) {
    dag.saveNode({
      node_id: m.node_id, name: "test", public_key: m.public_key,
      status: "active", registered_at: 1767225600000,
    });
  }

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: driverKp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });
  return { dag, handler, prevCommittee, prevKeys, dbPath };
}

// Build a shared batch of competing rotation-1 txs using the SAME
// prevCommittee + prevKeys so two independent nodes can apply the same
// canonical inputs and compare their resulting state.
function _buildCompetingBatch(prevCommittee, prevKeys) {
  const newCommittee = prevCommittee;   // re-attestation (membership unchanged)
  const ids = prevCommittee.map(m => m.node_id);
  // Three competing aggregators, each with a different signer subset
  // that still passes quorum (ceil(2*4/3) = 3):
  //   A: signers {0,1,2}     — exact quorum
  //   B: signers {0,1,3}     — exact quorum, different mix
  //   C: signers {0,1,2,3}   — full
  const txA = _buildRotationTx({
    rotation_number: 1, effective_round: 100, new_committee: newCommittee,
    signerNodeIds: [ids[0], ids[1], ids[2]], prevKeys,
  });
  const txB = _buildRotationTx({
    rotation_number: 1, effective_round: 100, new_committee: newCommittee,
    signerNodeIds: [ids[0], ids[1], ids[3]], prevKeys,
  });
  const txC = _buildRotationTx({
    rotation_number: 1, effective_round: 100, new_committee: newCommittee,
    signerNodeIds: [ids[0], ids[1], ids[2], ids[3]], prevKeys,
  });
  return [txA, txB, txC];
}

describe("committee_history determinism — invariant guard", () => {
  describe("multi-aggregator dedup on a single node", () => {
    test("3 competing rotation txs → exactly 1 commits, others land in tx_rejections", () => {
      const fx = _setupNode();
      try {
        const batch = _buildCompetingBatch(fx.prevCommittee, fx.prevKeys);
        const result = fx.handler.commitOrderedTxs(batch, 100);

        expect(result.committed).toBe(1);
        expect(result.dropped).toBe(2);

        // Exactly one COMMITTEE_ROTATION row in transactions
        const txs = fx.dag.getTxsByType(TX_TYPES.COMMITTEE_ROTATION) || [];
        expect(txs).toHaveLength(1);
        // The winner is batch[0] (first in consensus order)
        expect(txs[0].tx_id).toBe(batch[0].tx_id);

        // The two losers are persisted as rejections
        const rej0 = fx.dag.getTxRejection(batch[1].tx_id);
        const rej1 = fx.dag.getTxRejection(batch[2].tx_id);
        expect(rej0).toBeTruthy();
        expect(rej1).toBeTruthy();

        // Exactly one committee_history row for rotation 1
        const row = fx.dag.getCommitteeRotation(1);
        expect(row).toBeTruthy();
        expect(row.rotation_number).toBe(1);

        fx.dag.close();
      } finally {
        _cleanup(fx.dbPath);
      }
    });
  });

  describe("cross-node determinism", () => {
    // Two independent DAG instances simulate two honest nodes. Both
    // receive the SAME ordered batch (= what Bullshark anchor-commit
    // delivers identically to every honest node). They must end up with
    // byte-identical committee_history rows AND identical winning tx in
    // transactions. If this test ever fails, committee_history has
    // become non-deterministic and the merkle root will diverge across
    // nodes — chain halt.
    test("two nodes given the same ordered batch produce identical committee_history + transactions", () => {
      const fxA = _setupNode();
      // Build the batch from node A's prevCommittee/prevKeys, then mirror
      // those keys into node B so both nodes have the same "previous
      // committee" backdrop (= what happens in real federations:
      // rotation 0 is the bootstrap, identical across nodes).
      const batch = _buildCompetingBatch(fxA.prevCommittee, fxA.prevKeys);

      const fxB = (() => {
        const dbPath = _tmpDbPath();
        let dag = initDAG({ dbPath });
        dag.close();
        _replaceRotation0(dbPath, fxA.prevCommittee);
        dag = initDAG({ dbPath });
        const driverKp = generateMLDSAKeypair();
        dag.saveNode({
          node_id: NODE_ID, name: "test-driver", public_key: driverKp.publicKey,
          status: "active", registered_at: 1767225600000,
        });
        for (const m of fxA.prevCommittee) {
          dag.saveNode({
            node_id: m.node_id, name: "test", public_key: m.public_key,
            status: "active", registered_at: 1767225600000,
          });
        }
        const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: driverKp.privateKey };
        const scoring = initScoring(dag, config);
        const handler = createCommitHandler({ dag, scoring, config });
        return { dag, handler, dbPath };
      })();

      try {
        const rA = fxA.handler.commitOrderedTxs(batch, 100);
        const rB = fxB.handler.commitOrderedTxs(batch, 100);

        expect(rA).toEqual(rB);

        // committee_history: same row on both nodes
        const rowA = fxA.dag.getCommitteeRotation(1);
        const rowB = fxB.dag.getCommitteeRotation(1);
        expect(rowA).toBeTruthy();
        expect(rowB).toBeTruthy();
        // Compare the canonical-projection fields (committed_at is excluded
        // from rotations_full_root — see snapshot-roots.canonRotation; we
        // pin the same set here)
        const canon = (r) => ({
          rotation_number: r.rotation_number,
          effective_round: r.effective_round,
          committee:       r.committee,
          prev_rotation:   r.prev_rotation,
          signer_node_ids: r.signer_node_ids,
          signatures:      r.signatures,
          payload_hash:    r.payload_hash,
        });
        expect(canon(rowA)).toEqual(canon(rowB));

        // transactions: same single COMMITTEE_ROTATION row on both nodes
        const txsA = fxA.dag.getTxsByType(TX_TYPES.COMMITTEE_ROTATION) || [];
        const txsB = fxB.dag.getTxsByType(TX_TYPES.COMMITTEE_ROTATION) || [];
        expect(txsA).toHaveLength(1);
        expect(txsB).toHaveLength(1);
        expect(txsA[0].tx_id).toBe(txsB[0].tx_id);
        expect(txsA[0].tx_id).toBe(batch[0].tx_id);

        fxA.dag.close();
        fxB.dag.close();
      } finally {
        _cleanup(fxA.dbPath);
        _cleanup(fxB.dbPath);
      }
    });

    test("reordered batches DIVERGE — proves the invariant depends on consensus order, not local logic", () => {
      // Negative control: if two nodes were to receive DIFFERENT orderings
      // of the same competing-tx set (which Bullshark would never produce),
      // their committee_history would carry different winning sigs. This
      // test documents that property — the invariant relies on consensus
      // ordering, not on any local "always-pick-the-best-tx" tiebreaker.
      const fxA = _setupNode();
      const batch = _buildCompetingBatch(fxA.prevCommittee, fxA.prevKeys);
      // Build a second node sharing the same prevCommittee + keys
      const fxB = (() => {
        const dbPath = _tmpDbPath();
        let dag = initDAG({ dbPath });
        dag.close();
        _replaceRotation0(dbPath, fxA.prevCommittee);
        dag = initDAG({ dbPath });
        const driverKp = generateMLDSAKeypair();
        dag.saveNode({
          node_id: NODE_ID, name: "test-driver", public_key: driverKp.publicKey,
          status: "active", registered_at: 1767225600000,
        });
        for (const m of fxA.prevCommittee) {
          dag.saveNode({
            node_id: m.node_id, name: "test", public_key: m.public_key,
            status: "active", registered_at: 1767225600000,
          });
        }
        const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: driverKp.privateKey };
        const scoring = initScoring(dag, config);
        const handler = createCommitHandler({ dag, scoring, config });
        return { dag, handler, dbPath };
      })();
      try {
        fxA.handler.commitOrderedTxs(batch, 100);                 // order: A, B, C
        fxB.handler.commitOrderedTxs([batch[2], batch[1], batch[0]], 100);  // order: C, B, A

        const rowA = fxA.dag.getCommitteeRotation(1);
        const rowB = fxB.dag.getCommitteeRotation(1);
        // Winners differ: A picked batch[0], B picked batch[2] (different
        // cosignatures). committee_history diverges. This is the failure
        // mode consensus prevents — confirming that "committee_history
        // determinism" rests on consensus order, not on any local rule.
        expect(rowA.signer_node_ids).not.toEqual(rowB.signer_node_ids);

        fxA.dag.close();
        fxB.dag.close();
      } finally {
        _cleanup(fxA.dbPath);
        _cleanup(fxB.dbPath);
      }
    });
  });
});
