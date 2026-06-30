/**
 * @file tests/sync/snapshot-install-rotation-dedup.test.js
 * @description GH #32 / A11 — snapshot install path dedup gate for
 * COMMITTEE_ROTATION transactions.
 *
 * Pre-fix: snapshot install routed `dag.addTx(tx)` directly, bypassing
 * commit-handler._statefulCheck (rules.canCommitteeRotation enforces
 * rotation_number uniqueness). Two physical rotation txs for the same
 * rotation_number (e.g. divergent honest node-local proposals before
 * deterministic rotation tx_ids land) could BOTH end up in the
 * transactions table after fast-sync, bloating computeTxsMerkleRoot
 * and producing duplicate-tx rows queryable by rotation_number.
 *
 * Post-fix: install loop skips COMMITTEE_ROTATION txs whose
 * rotation_number already has a row in committee_history with matching
 * payload_hash. Mismatch is logged and proceeds (upstream
 * chain-of-trust verifier is the authoritative gate).
 *
 * Covers:
 *   - Snapshot install with existing rotation N (matching payload_hash)
 *     → physical tx NOT added; transactions count unchanged
 *   - Snapshot install with rotation N not in committee_history yet
 *     → physical tx added normally (control case)
 *   - Snapshot install with rotation N existing but payload_hash
 *     differs → log warn, proceed with addTx (defense-in-depth log
 *     only; upstream verifier handles the actual rejection)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, canonicalJson, computeTxId } = require(SHARED + "/crypto");
const { TX_TYPES } = require(SHARED + "/constants");
const { getGenesisPayload, GENESIS_TIMESTAMP } = require(SRC + "/genesis");
const { initDAG } = require(SRC + "/dag");
const { createSnapshotHandler } = require(SRC + "/sync/snapshot-handler");
const { loadTypes } = require(SRC + "/network/proto");

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

function _setup() {
  const dag = initDAG({ inMemory: true });
  const handler = createSnapshotHandler({
    dag,
    network: { node: {}, handle: async () => {} },
    isAuthorizedPeer: () => true,
  });
  return { dag, handler };
}

// Build a COMMITTEE_ROTATION tx with a deterministic tx_id for a given
// rotation_number + payload_hash + node_id (varying node_id varies the
// tx_id — that's exactly the pre-fix divergence case we're guarding).
function _rotationTx({ rotation_number, payload_hash, signer_node_ids = ["tip://node/A"], signatures = ["dead".repeat(16)] }) {
  const tx = {
    tx_type: TX_TYPES.COMMITTEE_ROTATION,
    timestamp: GENESIS_TIMESTAMP + rotation_number * 1000,
    prev: [],
    data: {
      rotation_number,
      effective_round: rotation_number,
      new_committee: [{ node_id: signer_node_ids[0], public_key: "00" }],
      payload_hash,
      signer_node_ids,
      signatures,
    },
  };
  tx.tx_id = computeTxId(tx);
  return tx;
}

// Build the minimal-shape SnapshotHeader the install transaction needs.
// `_installSnapshot` uses header for the final saveCommit row only; the
// dedup-gate path is exercised via `queues.txs`. Fill the fields that
// `dag.saveCommit` reads + a few that the install body coerces.
function _minimalHeader() {
  const founding = getGenesisPayload().founding_nodes[0];
  return {
    round: 1,
    anchorCertHash: Buffer.from("aa".repeat(32), "hex"),
    anchorBatchHash: Buffer.from("bb".repeat(32), "hex"),
    leaderNodeId: founding.node_id,
    committee: [{ node_id: founding.node_id, public_key: founding.public_key }],
    supportCount: 1,
    consensusIndex: 1,
    committedAt: GENESIS_TIMESTAMP + 10000,
    stateMerkleRoot: Buffer.from("00".repeat(32), "hex"),
    txsMerkleRoot: Buffer.from("00".repeat(32), "hex"),
    certTimestamp: GENESIS_TIMESTAMP + 9000,
    ackSignerIds: [],
    ackSignedAts: [],
    ackSignatures: [],
  };
}

describe("snapshot install COMMITTEE_ROTATION dedup (GH #32 / A11)", () => {

  test("rotation N already in committee_history with same payload_hash → tx NOT inserted", () => {
    const { dag, handler } = _setup();
    const payload = shake256(canonicalJson({ rotation_number: 5, ts: "fixed" }));

    // Pre-state: local committee_history already has rotation 5 with this payload.
    // (Mirrors the situation where this node has committed rotation 5 via its own
    // local consensus path, and a snapshot now pulls in a DIFFERENT physical tx
    // for the same rotation from a peer.)
    dag.saveCommitteeRotation({
      rotation_number: 5,
      effective_round: 5,
      committee: [{ node_id: "tip://node/A", public_key: "00" }],
      prev_rotation: 4,
      signer_node_ids: ["tip://node/A"],
      signatures: ["aa".repeat(16)],
      payload_hash: payload,
      committed_at: GENESIS_TIMESTAMP + 5000,
    });
    // Also persist the local physical tx so the test mirrors a real pre-state.
    const localTx = _rotationTx({
      rotation_number: 5,
      payload_hash: payload,
      signer_node_ids: ["tip://node/A"],
    });
    dag.addTx(localTx);
    const beforeCount = dag.getAllTxs().filter(t => t.tx_type === TX_TYPES.COMMITTEE_ROTATION && t.data.rotation_number === 5).length;
    expect(beforeCount).toBe(1);

    // Snapshot brings a DIFFERENT physical tx for the SAME rotation 5.
    // Different signer (B vs A) → different tx_id → would survive
    // INSERT OR IGNORE on tx_id PK without the dedup gate.
    const peerTx = _rotationTx({
      rotation_number: 5,
      payload_hash: payload,
      signer_node_ids: ["tip://node/B"],
    });
    expect(peerTx.tx_id).not.toBe(localTx.tx_id);

    const result = handler._installSnapshot(_minimalHeader(), {
      stateRows: [], txs: [peerTx], commits: [], rotations: [], certs: [], rp: [],
    });

    expect(result.rotation_txs_skipped).toBe(1);
    expect(result.txs).toBe(0);
    const afterCount = dag.getAllTxs().filter(t => t.tx_type === TX_TYPES.COMMITTEE_ROTATION && t.data.rotation_number === 5).length;
    expect(afterCount).toBe(1);  // unchanged
  });

  test("rotation N not in committee_history → tx installed normally (control)", () => {
    const { dag, handler } = _setup();
    const payload = shake256(canonicalJson({ rotation_number: 7, ts: "new" }));

    const peerTx = _rotationTx({
      rotation_number: 7,
      payload_hash: payload,
      signer_node_ids: ["tip://node/B"],
    });

    const result = handler._installSnapshot(_minimalHeader(), {
      stateRows: [], txs: [peerTx], commits: [], rotations: [], certs: [], rp: [],
    });

    expect(result.rotation_txs_skipped).toBe(0);
    expect(result.txs).toBe(1);
    expect(dag.getTx(peerTx.tx_id)).not.toBeNull();
  });

  test("rotation N exists but payload_hash differs → log warn, proceed (upstream verifier owns rejection)", () => {
    const { dag, handler } = _setup();
    const localPayload = shake256(canonicalJson({ rotation_number: 9, ts: "local" }));
    const peerPayload = shake256(canonicalJson({ rotation_number: 9, ts: "peer" }));
    expect(localPayload).not.toBe(peerPayload);

    dag.saveCommitteeRotation({
      rotation_number: 9,
      effective_round: 9,
      committee: [{ node_id: "tip://node/A", public_key: "00" }],
      prev_rotation: 8,
      signer_node_ids: ["tip://node/A"],
      signatures: ["aa".repeat(16)],
      payload_hash: localPayload,
      committed_at: GENESIS_TIMESTAMP + 9000,
    });

    const peerTx = _rotationTx({
      rotation_number: 9,
      payload_hash: peerPayload,
      signer_node_ids: ["tip://node/C"],
    });

    const result = handler._installSnapshot(_minimalHeader(), {
      stateRows: [], txs: [peerTx], commits: [], rotations: [], certs: [], rp: [],
    });

    // Divergent payload_hash: dedup gate does NOT skip (upstream
    // chain-of-trust verifier is the authoritative gate; this layer is
    // defense-in-depth log only). Tx is added; the warn line went to
    // the logger.
    expect(result.rotation_txs_skipped).toBe(0);
    expect(result.txs).toBe(1);
  });

  test("non-rotation txs pass through the dedup gate unchanged", () => {
    const { dag, handler } = _setup();
    const tx = {
      tx_type: TX_TYPES.SCORE_UPDATE,
      timestamp: GENESIS_TIMESTAMP + 1000,
      prev: [],
      data: { tip_id: "tip://id/US-aaaabbbbccccdddd", delta: 5, reason: "uat", node_id: "tip://node/A" },
    };
    tx.tx_id = computeTxId(tx);

    const result = handler._installSnapshot(_minimalHeader(), {
      stateRows: [], txs: [tx], commits: [], rotations: [], certs: [], rp: [],
    });

    expect(result.rotation_txs_skipped).toBe(0);
    expect(result.txs).toBe(1);
    expect(dag.getTx(tx.tx_id)).not.toBeNull();
  });
});
