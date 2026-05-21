/**
 * @file tests/consensus/commit-handler-committee-rotation.test.js
 * @description Tests for the COMMITTEE_ROTATION tx path in commit-handler
 * (§4 + #34 — chain-of-trust foundation).
 *
 * Covers:
 *   - Happy path: valid rotation tx commits + writes committee_history row
 *   - Sig verification: ≥2f+1 sigs from previous committee required
 *   - Sig verification: signers NOT in previous committee are ignored
 *   - Sig verification: duplicate signer_ids count once (anti-padding)
 *   - Tampered payload_hash → rejected
 *   - Tampered new_committee → payload_hash mismatch → rejected
 *   - Wrong rotation_number (gap, duplicate) → rejected
 *   - Duplicate rotation_number in same batch → only first lands
 *   - effective_round not monotonic → rejected
 *   - Malformed new_committee → rejected at structural validation
 *
 * Test fixture builds a 4-node "test federation" by replacing the
 * bootstrap rotation 0 (genesis founding_node) with a test committee
 * whose private keys we control. Tests then exercise rotation 1 →
 * rotation 2 transitions verifying real ML-DSA-65 signatures.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");

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

beforeAll(async () => {
  await initCrypto();
});

const NODE_ID = "tip://node/test-driver";

function _tmpDbPath() {
  return path.join(os.tmpdir(), `tip-cot-handler-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
}

function _cleanup(dbPath) {
  for (const ext of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
}

// Build a 4-node test "previous committee" with known keypairs.
// Returns: { committee: [{node_id, public_key}], keys: { node_id: privateKey } }
function _testCommittee(size = 4) {
  const committee = [];
  const keys = {};
  for (let i = 0; i < size; i++) {
    const kp = generateMLDSAKeypair();
    const node_id = `tip://node/test-${i}`;
    committee.push({ node_id, public_key: kp.publicKey });
    keys[node_id] = kp.privateKey;
  }
  // Sort canonical (committee must be sorted by node_id)
  committee.sort((a, b) => a.node_id.localeCompare(b.node_id));
  return { committee, keys };
}

// Replace the bootstrap rotation 0 with our test committee. This is the
// only way we can test rotation 1+ verification — we need private keys
// for the previous committee, and genesis founding_node's privkey isn't
// in genesis.js.
function _replaceRotation0(dbPath, committee) {
  const Database = require("better-sqlite3");
  const raw = new Database(dbPath);
  try {
    raw.prepare("DELETE FROM committee_history").run();
    const payload_hash = shake256(canonicalJson({
      rotation_number: 0,
      effective_round: 0,
      committee,
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

// Build a rotation N tx with sigs from prevCommittee's keys.
// signerNodeIds defaults to ALL of prevCommittee — caller can restrict.
function _buildRotationTx({
  rotation_number, effective_round, new_committee, prevCommittee, prevKeys,
  signerNodeIds, payloadHashOverride, signatureMutator,
}) {
  const payload_hash = payloadHashOverride || shake256(canonicalJson({
    rotation_number,
    effective_round,
    committee: new_committee,
  }));

  const signers = signerNodeIds || prevCommittee.map(m => m.node_id);
  const signatures = signers.map(signerId => {
    const message = `rotation:${payload_hash}:${signerId}`;
    const privKey = prevKeys[signerId];
    if (!privKey) return "00".repeat(32);  // bogus sig — for "signer not in committee" tests
    let sig = mldsaSign(message, privKey);
    if (signatureMutator) sig = signatureMutator(sig, signerId);
    return sig;
  });

  const data = {
    rotation_number,
    effective_round,
    new_committee,
    payload_hash,
    signer_node_ids: signers,
    signatures,
  };

  const tx = {
    tx_type: TX_TYPES.COMMITTEE_ROTATION,
    timestamp: 1777507200000,
    // Genesis-bridged prev so validateTransaction's "non-genesis must have
    // prev references" rule passes. genesis tx is in the DAG already from
    // bootstrap so prev-existence check resolves.
    prev: [GENESIS_TX_ID, GENESIS_TX_ID],
    data,
  };
  // Compute tx_id deterministically from canonical body
  tx.tx_id = shake256(canonicalJson({
    tx_type: tx.tx_type,
    data: tx.data,
    timestamp: tx.timestamp,
    prev: tx.prev,
  }));
  return tx;
}

function _setup() {
  const dbPath = _tmpDbPath();
  let dag = initDAG({ dbPath });
  dag.close();

  // Replace rotation 0 with test committee
  const { committee: prevCommittee, keys: prevKeys } = _testCommittee(4);
  _replaceRotation0(dbPath, prevCommittee);

  // Reopen (bootstrap is idempotent — sees rotation 0 exists)
  dag = initDAG({ dbPath });

  // Driver "node" (the entity submitting txs into the handler — irrelevant
  // to rotation semantics, but commit-handler config requires one)
  const driverKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "test-driver", public_key: driverKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  // Also register each previous-committee member as a registered node
  // so general validation paths (which look up node by node_id) don't
  // reject. This isn't strictly required for COMMITTEE_ROTATION (which
  // uses pubkeys from committee_history, not nodes table), but matches
  // what a real federation would have.
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

describe("commit-handler — COMMITTEE_ROTATION (§4 + #34)", () => {
  describe("happy path", () => {
    test("valid rotation: 4 sigs (full quorum) from previous committee → committed + row written", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        const newCommittee = [
          ...prevCommittee,
          { node_id: "tip://node/test-new", public_key: generateMLDSAKeypair().publicKey },
        ].sort((a, b) => a.node_id.localeCompare(b.node_id));

        const tx = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: newCommittee,
          prevCommittee,
          prevKeys,
        });

        const result = handler.commitOrderedTxs([tx], 100);
        expect(result.committed).toBe(1);
        expect(result.dropped).toBe(0);

        const written = dag.getCommitteeRotation(1);
        expect(written).not.toBeNull();
        expect(written.rotation_number).toBe(1);
        expect(written.effective_round).toBe(100);
        expect(written.committee).toEqual(newCommittee);
        expect(written.prev_rotation).toBe(0);
        expect(written.signer_node_ids).toHaveLength(4);
        expect(written.payload_hash).toBe(tx.data.payload_hash);

        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("valid rotation: 3-of-4 sigs (exact 2f+1 threshold) → accepted", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        // f=1 for n=4, quorum = 3
        const newCommittee = prevCommittee.slice(0, 3);
        const tx = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: newCommittee,
          prevCommittee,
          prevKeys,
          signerNodeIds: prevCommittee.slice(0, 3).map(m => m.node_id),
        });

        const result = handler.commitOrderedTxs([tx], 100);
        expect(result.committed).toBe(1);
        expect(dag.getCommitteeRotation(1)).not.toBeNull();
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });
  });

  describe("signature failures", () => {
    test("insufficient sigs (< 2f+1): 2-of-4 → rejected, no row written", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        const tx = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: prevCommittee.slice(0, 2),
          prevCommittee,
          prevKeys,
          signerNodeIds: prevCommittee.slice(0, 2).map(m => m.node_id),
        });
        const result = handler.commitOrderedTxs([tx], 100);
        expect(result.committed).toBe(0);
        expect(result.dropped).toBe(1);
        expect(dag.getCommitteeRotation(1)).toBeNull();
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("signer NOT in previous committee → that sig is ignored, quorum fails", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        // Build tx with 3 valid signers + 1 outsider. Outsider's sig
        // contributes 0 to validSigs → only 3 valid → quorum (3) met.
        // Then drop one valid signer — only 2 valid → fails.
        const outsiderKp = generateMLDSAKeypair();
        const outsiderId = "tip://node/outsider";
        const fakeKeys = { ...prevKeys, [outsiderId]: outsiderKp.privateKey };

        const tx = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: prevCommittee.slice(0, 2),
          prevCommittee,
          prevKeys: fakeKeys,
          // Outsider + only 2 of the 4 real committee members
          signerNodeIds: [outsiderId, prevCommittee[0].node_id, prevCommittee[1].node_id],
        });
        const result = handler.commitOrderedTxs([tx], 100);
        expect(result.committed).toBe(0);  // 2 valid sigs < quorum 3
        expect(dag.getCommitteeRotation(1)).toBeNull();
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("duplicate signer_ids count once (anti-padding)", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        // Repeat one signer 3x to fake a quorum of "3" — should count as 1
        const tx = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: prevCommittee.slice(0, 2),
          prevCommittee,
          prevKeys,
          signerNodeIds: [
            prevCommittee[0].node_id,
            prevCommittee[0].node_id,
            prevCommittee[0].node_id,
          ],
        });
        const result = handler.commitOrderedTxs([tx], 100);
        expect(result.committed).toBe(0);
        expect(dag.getCommitteeRotation(1)).toBeNull();
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("tampered payload_hash → rejected", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        // Generate a valid tx, then overwrite payload_hash with garbage.
        // Sigs no longer match the new payload_hash → fail.
        const tx = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: prevCommittee.slice(0, 3),
          prevCommittee,
          prevKeys,
          payloadHashOverride: "f".repeat(64),  // bogus
        });
        // Sigs were generated against the bogus hash, but the canonical-
        // derived expected hash will differ → rejected by hash-recomputation
        // check before sig verification even runs.
        const result = handler.commitOrderedTxs([tx], 100);
        expect(result.committed).toBe(0);
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("tampered new_committee (different from what was signed) → payload_hash mismatch → rejected", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        // Build sigs over committee A, then swap the committee for B.
        // payload_hash was computed for A; recomputing for B would differ.
        const committeeA = prevCommittee.slice(0, 3);
        const committeeB = [
          ...prevCommittee.slice(0, 2),
          { node_id: "tip://node/attacker", public_key: "deadbeef".repeat(8) },
        ].sort((a, b) => a.node_id.localeCompare(b.node_id));

        const txA = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: committeeA,
          prevCommittee,
          prevKeys,
        });
        // Tamper: swap committee but keep old sigs + payload_hash
        txA.data.new_committee = committeeB;

        const result = handler.commitOrderedTxs([txA], 100);
        expect(result.committed).toBe(0);
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("invalid signature bytes → that signer doesn't count", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        const tx = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: prevCommittee.slice(0, 3),
          prevCommittee,
          prevKeys,
          signerNodeIds: prevCommittee.slice(0, 3).map(m => m.node_id),
          signatureMutator: (sig, signerId) => {
            // Corrupt one signer's sig — flip a byte
            if (signerId === prevCommittee[0].node_id) return "00" + sig.slice(2);
            return sig;
          },
        });
        const result = handler.commitOrderedTxs([tx], 100);
        // 2 valid sigs (signer 1 corrupted, 2 + 3 valid) < quorum 3
        expect(result.committed).toBe(0);
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });
  });

  describe("monotonicity + dedup", () => {
    test("rotation_number gap (2 instead of 1) → rejected", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        const tx = _buildRotationTx({
          rotation_number: 2,  // skipping 1!
          effective_round: 100,
          new_committee: prevCommittee.slice(0, 3),
          prevCommittee,
          prevKeys,
        });
        const result = handler.commitOrderedTxs([tx], 100);
        expect(result.committed).toBe(0);
        expect(dag.getCommitteeRotation(2)).toBeNull();
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("duplicate rotation_number across batches → second rejected", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        const newCommittee = prevCommittee.slice(0, 3);
        const tx1 = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: newCommittee,
          prevCommittee,
          prevKeys,
        });
        const r1 = handler.commitOrderedTxs([tx1], 100);
        expect(r1.committed).toBe(1);

        // Try to commit a different rotation 1 in a later round
        const tx2 = _buildRotationTx({
          rotation_number: 1,
          effective_round: 200,
          new_committee: prevCommittee.slice(0, 2),
          prevCommittee,
          prevKeys,
        });
        const r2 = handler.commitOrderedTxs([tx2], 200);
        expect(r2.committed).toBe(0);
        // Stored rotation 1 unchanged from first
        expect(dag.getCommitteeRotation(1).effective_round).toBe(100);
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("duplicate rotation_number in same batch → only first lands", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        const tx1 = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: prevCommittee.slice(0, 3),
          prevCommittee,
          prevKeys,
        });
        const tx2 = _buildRotationTx({
          rotation_number: 1,  // dup
          effective_round: 200,
          new_committee: prevCommittee.slice(0, 2),
          prevCommittee,
          prevKeys,
        });
        const result = handler.commitOrderedTxs([tx1, tx2], 100);
        expect(result.committed).toBe(1);
        expect(result.dropped).toBe(1);
        expect(dag.getCommitteeRotation(1).effective_round).toBe(100);  // first wins
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("effective_round not monotonic (≤ prev) → rejected", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        // Land rotation 1 at effective_round=200
        const tx1 = _buildRotationTx({
          rotation_number: 1,
          effective_round: 200,
          new_committee: prevCommittee.slice(0, 3),
          prevCommittee,
          prevKeys,
        });
        const r1 = handler.commitOrderedTxs([tx1], 200);
        expect(r1.committed).toBe(1);

        // Now try rotation 2 with effective_round=200 (equal to prev) — must reject
        // (Need new sigs from rotation 1's committee to even reach the check)
        const rot1Committee = dag.getCommitteeRotation(1).committee;
        const rot1Keys = {};
        for (const m of rot1Committee) rot1Keys[m.node_id] = prevKeys[m.node_id];

        const tx2 = _buildRotationTx({
          rotation_number: 2,
          effective_round: 200,  // same as rotation 1
          new_committee: rot1Committee.slice(0, 2),
          prevCommittee: rot1Committee,
          prevKeys: rot1Keys,
        });
        const r2 = handler.commitOrderedTxs([tx2], 250);
        expect(r2.committed).toBe(0);
        expect(dag.getCommitteeRotation(2)).toBeNull();
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });
  });

  describe("structural validation", () => {
    test("empty new_committee → rejected", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        const tx = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: [],
          prevCommittee,
          prevKeys,
        });
        const result = handler.commitOrderedTxs([tx], 100);
        expect(result.committed).toBe(0);
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });

    test("malformed new_committee entries (missing public_key) → rejected", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        const tx = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: [{ node_id: "tip://node/x" }],  // no public_key!
          prevCommittee,
          prevKeys,
        });
        const result = handler.commitOrderedTxs([tx], 100);
        expect(result.committed).toBe(0);
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });
  });

  describe("multi-rotation chain", () => {
    test("sequential rotations 1 → 2 each verified against the previous committee", () => {
      const { dag, handler, prevCommittee, prevKeys, dbPath } = _setup();
      try {
        // Rotation 1: shrink to 3 members
        const rot1Committee = prevCommittee.slice(0, 3);
        const tx1 = _buildRotationTx({
          rotation_number: 1,
          effective_round: 100,
          new_committee: rot1Committee,
          prevCommittee,
          prevKeys,
        });
        expect(handler.commitOrderedTxs([tx1], 100).committed).toBe(1);

        // Rotation 2: shrink to 2 — must be signed by rotation 1's committee
        // (3 members, f=0, quorum=1). We have keys for all original 4, so
        // we can sign as any of rot1's members.
        const rot2Committee = rot1Committee.slice(0, 2);
        const rot1Keys = {};
        for (const m of rot1Committee) rot1Keys[m.node_id] = prevKeys[m.node_id];

        const tx2 = _buildRotationTx({
          rotation_number: 2,
          effective_round: 250,
          new_committee: rot2Committee,
          prevCommittee: rot1Committee,
          prevKeys: rot1Keys,
        });
        expect(handler.commitOrderedTxs([tx2], 250).committed).toBe(1);

        // Verify chain
        const chain = [...dag.getRotationsFromGenesis()];
        expect(chain).toHaveLength(3);
        expect(chain.map(r => r.rotation_number)).toEqual([0, 1, 2]);
        expect(chain[2].committee).toEqual(rot2Committee);

        // getCommitteeAtRound should return the right rotation per round
        expect(dag.getCommitteeAtRound(50).rotation_number).toBe(0);
        expect(dag.getCommitteeAtRound(150).rotation_number).toBe(1);
        expect(dag.getCommitteeAtRound(300).rotation_number).toBe(2);
        dag.close();
      } finally {
        _cleanup(dbPath);
      }
    });
  });
});
