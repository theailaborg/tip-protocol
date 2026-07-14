/**
 * @file tests/consensus/commit-handler-verified-cache.test.js
 * @description Consume-once locally-verified tx cache: commit skips the
 * redundant ML-DSA re-verify ONLY for tx_ids marked at this node's API
 * layer, exactly once; unmarked txs take the full verification path.
 *
 * A structurally-valid tx with a garbage signature distinguishes the two
 * paths by its persisted rejection detail: unmarked dies at "signature
 * failed"; marked crosses that gate and fails later (or commits).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, canonicalJson } = require(path.join(SHARED, "crypto"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { GENESIS_TX_ID } = require(path.join(SRC, "genesis"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));

beforeAll(async () => { await initCrypto(); });

function _identityTx() {
  const kp = generateMLDSAKeypair();
  const suffix = shake256(kp.publicKey).slice(0, 16);
  const data = {
    tip_id: `tip://id/US-${suffix}`,
    public_key: kp.publicKey,
    region: "US",
    dedup_hash: String(BigInt("0x" + suffix) % (2n ** 200n)),
    vp_id: "tip://vp/US-a47ca857e68d9b9f",
    vp_signature: "aa".repeat(64),
    verification_tier: "T1",
    zk_proof: { pi_a: [], pi_b: [], pi_c: [], publicSignals: [] },
    signature: "bb".repeat(64),
  };
  const tx = {
    tx_type: TX_TYPES.REGISTER_IDENTITY,
    timestamp: 1783036800000,
    prev: [GENESIS_TX_ID, GENESIS_TX_ID],
    data,
  };
  tx.tx_id = shake256(canonicalJson({ tx_type: tx.tx_type, data: tx.data, timestamp: tx.timestamp }));
  return tx;
}

function _setup(cache) {
  const dag = initDAG({ inMemory: true });
  const kp = generateMLDSAKeypair();
  const config = { nodeId: "tip://node/t", nodeRegisteredId: "tip://node/t", nodePrivateKey: kp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({
    dag, scoring, config,
    isLocallyVerified: cache ? (id) => cache.delete(id) : undefined,
  });
  return { dag, handler };
}

function _rejectionDetail(dag, txId) {
  const r = dag.getTxRejection(txId);
  return r ? `${r.reason_detail || r.reason || ""}` : null;
}

describe("commit-handler locally-verified cache", () => {
  test("unmarked garbage-sig tx dies at the signature gate", () => {
    const { dag, handler } = _setup(new Map());
    const tx = _identityTx();
    const r = handler.commitOrderedTxs([tx], 10);
    expect(r.committed).toBe(0);
    expect(_rejectionDetail(dag, tx.tx_id)).toContain("signature failed");
  });

  test("marked tx crosses the signature gate; mark consumed after its job", () => {
    const cache = new Map();
    const { dag, handler } = _setup(cache);
    const tx = _identityTx();
    cache.set(tx.tx_id, true);

    handler.commitOrderedTxs([tx], 10);
    const detail = _rejectionDetail(dag, tx.tx_id);
    // Whatever happens downstream, it is NOT the signature gate.
    expect(detail === null || !detail.includes("signature failed")).toBe(true);
    expect(cache.size).toBe(0);

    // Mark gone: an identical replay now dies at the signature gate again.
    const tx2 = _identityTx();
    handler.commitOrderedTxs([tx2], 11);
    expect(_rejectionDetail(dag, tx2.tx_id)).toContain("signature failed");
  });

  test("no cache wired: signature gate always active", () => {
    const { dag, handler } = _setup(null);
    const tx = _identityTx();
    const r = handler.commitOrderedTxs([tx], 10);
    expect(r.committed).toBe(0);
    expect(_rejectionDetail(dag, tx.tx_id)).toContain("signature failed");
  });
});
