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
function buildCommittedDag({
  committeeSize = 1,
  dropSigs = 0,
  round = 2,
  seedTxs = 0,
  ackTransform,
  // Optional callback invoked BEFORE `state_merkle_root` is computed.
  // Use this to mutate any canonical-state row whose stable form must be
  // captured by the commit's state_merkle_root (e.g. modifying a score
  // away from its genesis default for snapshot drift-guard tests).
  // Receives the source DAG; return value ignored.
  preCommitMutate = null,
} = {}) {
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

  // Sign acks (omit trailing N for quorum-shortfall tests). Each ack carries
  // a `signed_at` integer epoch ms — a deterministic per-ack offset (1ms
  // apart) anchored 1ms past BFT_TIME_GENESIS_MS. Cert.timestamp = median
  // of these values, also deterministic and comfortably above the floor.
  const _bftT0 = new Date("2026-03-15T00:00:01.000Z").getTime();
  let ackSignerIds = [];
  let ackSignatures = [];
  let ackSignedAts = [];
  for (let i = 0; i < committeeKeys.length - dropSigs; i++) {
    const { nodeId, privateKey } = committeeKeys[i];
    const signedAt = _bftT0 + i; // 1ms apart per acker — strictly increasing
    const payload = `ack:${anchorBatchHash}:${nodeId}:${signedAt}`;
    ackSignerIds.push(nodeId);
    ackSignatures.push(mldsaSign(payload, privateKey));
    ackSignedAts.push(signedAt);
  }

  // Let callers craft malformed ack arrays (security tests: non-committee
  // signer, duplicates, corrupted sig bytes, etc.) after the default
  // signatures are produced.
  //
  // Pre-BFT-Time test transformers only mutate `signerIds` / `signatures`.
  // We auto-pad `signedAts` to match `signerIds.length` so the snapshot
  // verifier doesn't trip on the parallel-array length check before reaching
  // the actual security assertion (e.g. "non-committee signer rejected").
  // Padding uses the bft_t0 baseline — values that lie above the genesis
  // floor and below any real production timestamp.
  if (typeof ackTransform === "function") {
    const acks = { signerIds: ackSignerIds, signatures: ackSignatures, signedAts: ackSignedAts };
    const fx = { committeeKeys, committee, anchorBatchHash };
    const transformed = ackTransform(acks, fx) || acks;
    ackSignerIds = transformed.signerIds;
    ackSignatures = transformed.signatures;
    ackSignedAts = transformed.signedAts || ackSignedAts;
    // Pad / truncate to match signerIds length.
    if (ackSignedAts.length < ackSignerIds.length) {
      const start = ackSignedAts.length;
      for (let i = start; i < ackSignerIds.length; i++) {
        ackSignedAts.push(_bftT0 + i);
      }
    } else if (ackSignedAts.length > ackSignerIds.length) {
      ackSignedAts = ackSignedAts.slice(0, ackSignerIds.length);
    }
  }

  // cert.timestamp = median of acks.signed_at — same algorithm as
  // certificate.js computeMedianTimestamp. Deterministic across nodes.
  const _sortedTs = [...ackSignedAts].sort((a, b) => a - b);
  const _mid = _sortedTs.length >> 1;
  const certTimestamp = _sortedTs.length === 0
    ? _bftT0  // empty (drop-all-sigs tests) — fallback to floor+1 (still > genesis)
    : _sortedTs.length % 2 === 0
      ? Math.floor((_sortedTs[_mid - 1] + _sortedTs[_mid]) / 2)
      : _sortedTs[_mid];

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
      batch_hash: anchorBatchHash,
      acker_node_id: id,
      signature: ackSignatures[i],
      signed_at: ackSignedAts[i],
    })),
    parent_hashes: [],
    signature: "00",
    timestamp: certTimestamp,
  });

  // Optional caller-supplied mutation hook — runs BEFORE state_merkle_root
  // is computed so any state mutations are captured by the commit row's
  // root and round-trip through the snapshot stream correctly.
  if (typeof preCommitMutate === "function") {
    preCommitMutate(sourceDag);
  }

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
    // BFT-Time fields — joiner reconstructs ack payloads as
    // `ack:${anchor_batch_hash}:${signer}:${signed_at}` for verification,
    // and reads cert_timestamp as the canonical consensus wall-clock for
    // this anchor.
    ack_signed_ats: ackSignedAts,
    cert_timestamp: certTimestamp,
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
    // BFT-Time fields surfaced for tests that need to assert on them.
    ackSignedAts, certTimestamp,
  };
}

module.exports = { buildCommittedDag };
