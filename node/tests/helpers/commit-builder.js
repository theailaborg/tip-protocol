/**
 * @file tests/helpers/commit-builder.js
 * @description Test fixture: stand up an in-memory DAG with a single
 * signed Bullshark anchor commit at round R — committee nodes, anchor
 * certificate, state_merkle_root, txs_merkle_root, and 2f+1 valid ack
 * signatures — so snapshot / commit / sync tests can exercise the
 * verification path against a real committed state.
 *
 * Reusable beyond §14: Narwhal / Bullshark / commit-index tests all need
 * a DAG that's observably "at round R with a real commit row" without
 * having to spin consensus.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { generateMLDSAKeypair, mldsaSign, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { computeStateMerkleRoot, computeTxsMerkleRoot } = require(path.join(SRC, "consensus", "state-root"));

/**
 * Build a source DAG with a signed anchor commit.
 *
 * @param {Object} [opts]
 * @param {number}   [opts.committeeSize=1]  Number of committee nodes to register
 * @param {number}   [opts.dropSigs=0]       Number of tail sigs to omit (simulates quorum shortfall)
 * @param {number}   [opts.round=2]          Commit round number
 * @param {number}   [opts.seedTxs=0]        #49: number of synthetic committed
 *   transactions to seed into the source's `transactions` table (in
 *   addition to whatever the genesis bootstrap already inserts). Each
 *   seeded tx is a content-addressed `REGISTER_CONTENT` with `prev`
 *   chained to the previous tx_id, simulating the post-genesis history
 *   that snapshot Phase 1 must ship for joiners to resolve later
 *   `prev` references. Returned in `seededTxs`.
 * @param {Function} [opts.ackTransform]     Optional `(acks, fx) => acks` hook.
 *   `acks` is `{ signerIds: string[], signatures: string[] }`; `fx` exposes
 *   `committeeKeys`, `committee`, `anchorBatchHash` so tests can craft
 *   malformed ack arrays (non-committee signer, duplicates, corrupted sigs).
 *   Must mutate or return a new `{signerIds, signatures}`; return value wins.
 * @returns {{
 *   sourceDag, committee, committeeKeys,
 *   anchorCertHash, anchorBatchHash,
 *   stateRoot, txsRoot, consensusIndex, seededTxs,
 * }}
 */
function buildCommittedDag({ committeeSize = 1, dropSigs = 0, round = 2, seedTxs = 0, ackTransform } = {}) {
  const sourceDag = initDAG({ dbPath: ":memory:" });

  // Register committee nodes. Public key in the nodes table must match the
  // keypair used to sign acks — that's what lets a client later verify
  // signatures using only the snapshot's own nodes table.
  const committeeKeys = [];
  for (let i = 0; i < committeeSize; i++) {
    const kp = generateMLDSAKeypair();
    const nodeId = `COMMITTEE_NODE_${i}`;
    sourceDag.saveNode({
      node_id: nodeId,
      name: `node ${i}`,
      public_key: kp.publicKey,
      status: "active",
      registered_at: "2026-01-01T00:00:00.000Z",
    });
    committeeKeys.push({ nodeId, ...kp });
  }
  const committee = [...committeeKeys.map(k => k.nodeId)].sort();

  // Anchor cert's batch hash is what each ack signs. Deterministic mock —
  // the actual batch content doesn't matter for snapshot verification;
  // only the hash does (it's what the signature covers).
  const anchorBatchHash = shake256(`test-anchor-batch-round-${round}-${committee.join(",")}`);
  const anchorCertHash = shake256(`test-anchor-cert-${anchorBatchHash}`);
  const leaderNodeId = committeeKeys[0].nodeId;

  // Sign acks (omit trailing N for quorum-shortfall tests).
  let ackSignerIds = [];
  let ackSignatures = [];
  for (let i = 0; i < committeeKeys.length - dropSigs; i++) {
    const { nodeId, privateKey } = committeeKeys[i];
    const payload = `ack:${anchorBatchHash}:${nodeId}`;
    ackSignerIds.push(nodeId);
    ackSignatures.push(mldsaSign(payload, privateKey));
  }

  // Let callers craft malformed ack arrays (security tests: non-committee
  // signer, duplicates, corrupted sig bytes, etc.) after the default
  // signatures are produced.
  if (typeof ackTransform === "function") {
    const acks = { signerIds: ackSignerIds, signatures: ackSignatures };
    const fx = { committeeKeys, committee, anchorBatchHash };
    const transformed = ackTransform(acks, fx) || acks;
    ackSignerIds = transformed.signerIds;
    ackSignatures = transformed.signatures;
  }

  // Persist the anchor certificate. saveCertificate is used straight —
  // no signature check, we just need getCertificate(hash) to return the
  // correct batch.hash for the server-side handler.
  sourceDag.saveCertificate({
    hash: anchorCertHash,
    round,
    author_node_id: leaderNodeId,
    batch: {
      round,
      author_node_id: leaderNodeId,
      txs: [],
      hash: anchorBatchHash,
      signature: "00",
    },
    acknowledgments: ackSignerIds.map((id, i) => ({
      batch_hash: anchorBatchHash, acker_node_id: id, signature: ackSignatures[i],
    })),
    parent_hashes: [],
    signature: "00",
  });

  // Compute roots over current state (commits table is NOT in canonical
  // state, so saveCommit afterwards doesn't change the root).
  const stateRoot = computeStateMerkleRoot(sourceDag);
  const txsRoot = computeTxsMerkleRoot([]);

  const consensusIndex = 1;
  sourceDag.saveCommit({
    round,
    anchor_cert_hash: anchorCertHash,
    // #50: persist anchor_batch_hash directly so snapshot serving works
    // even after cert GC has pruned the cert. Mirrors what bullshark.js
    // writes in production.
    anchor_batch_hash: anchorBatchHash,
    leader_node_id: leaderNodeId,
    committee,
    support_count: committeeSize,
    consensus_index: consensusIndex,
    committed_at: "2026-01-01T00:00:00.000Z",
    state_merkle_root: stateRoot,
    txs_merkle_root: txsRoot,
    ack_signer_ids: ackSignerIds,
    ack_signatures: ackSignatures,
  });

  // §14/#49 — optional synthetic tx history. Seeded BEFORE the state-root
  // computation above? No — txsRoot covers orderedTxs of THIS commit
  // (empty per `txs: []` in the cert), not the full transactions table.
  // state_merkle_root covers derived state, not raw txs. So seeding here
  // (after roots are computed) is correct: it adds rows to `transactions`
  // for the snapshot's #49 full-history phase to ship, without
  // affecting the existing roots.
  //
  // Each tx is a content-addressed REGISTER_CONTENT with prev chained
  // off the previous one (or the source's existing _prev for the first).
  // Signature is a stub — snapshot Phase 1 doesn't re-verify signatures
  // (txs_full_root + 2f+1 ack on derived state are the snapshot-layer
  // guarantees; original signature was checked by source's commit-handler).
  const seededTxs = [];
  if (seedTxs > 0) {
    let chain = sourceDag.getRecentPrev();
    for (let i = 0; i < seedTxs; i++) {
      const txBody = {
        tx_type: "REGISTER_CONTENT",
        timestamp: new Date(2026, 0, 1, 0, 0, i).toISOString(),
        prev: [...chain],
        data: {
          ctid: `tip://content/seed-${i}`,
          origin_code: "OH",
          content_hash: shake256(`seed-content-${i}`),
          author_tip_id: "tip://id/seed-author",
        },
      };
      txBody.tx_id = computeTxId(txBody);
      txBody.signature = "00";
      sourceDag.addTx(txBody);          // submission path (no tx_id mismatch since we just computed it from current canonical)
      seededTxs.push(txBody);
      chain = [txBody.tx_id, chain[0]];
    }
  }

  return {
    sourceDag, committee, committeeKeys,
    anchorCertHash, anchorBatchHash,
    stateRoot, txsRoot, consensusIndex,
    seededTxs,
  };
}

module.exports = { buildCommittedDag };
