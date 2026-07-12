/**
 * @file tests/consensus/tx-preverify.test.js
 * @description Drift seal for worker-pool tx pre-verification.
 *
 * collectTxSignatureInputs + raw verifyWithAlgorithm must produce the SAME
 * verdict as the sync dispatcher (verifyTxSignature) for every contract
 * shape , body-signed, envelope-signed , plus the pool's verifyRaw op in
 * both worker and sync-fallback modes. If the collector's message bytes ever
 * drift from the dispatcher's, pre-verified txs would commit with signatures
 * the sync path would have rejected.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initDAG } = require(path.join(SRC, "dag"));
const { initCrypto, generateMLDSAKeypair, shake256, computeTxId, verifyWithAlgorithm, signTransaction } = require(path.join(SHARED, "crypto"));

beforeAll(async () => { await initCrypto(); });
const { verifyTxSignature, collectTxSignatureInputs } = require(path.join(SRC, "schemas", "_common"));
const { SCHEMA_FOR_TX_TYPE } = require(path.join(SRC, "schemas", "_schema-map"));
const contentRegisterSchema = require(path.join(SRC, "schemas", "content-register"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { createCryptoPool } = require(path.join(SRC, "lib", "crypto-pool"));

const NODE_ID = "tip://node/preverify0000001";
const VP_ID = "tip://vp/US-preverify0001";
const AUTHOR_TIP = "tip://id/US-preverify0000aa";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const vpKp = generateMLDSAKeypair();
  const authorKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
  return { dag, nodeKp, authorKp };
}

function _contentTx(dag, authorKp, text) {
  const content_hash = shake256(text);
  const data = {
    ctid: `tip://c/OH-${content_hash.slice(0, 14)}-0001`,
    origin_code: "OH", content_hash, signer_tip_id: AUTHOR_TIP,
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR_TIP, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, registered_urls: [],
    cna_version: contentRegisterSchema.CURRENT_CNA_VERSION,
  };
  const sig = contentRegisterSchema.sign(contentRegisterSchema.buildSigningPayload(data, content_hash), authorKp.privateKey);
  const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1777507200000, data, signature: sig, prev: dag.prevFor(TX_TYPES.REGISTER_CONTENT, data) };
  tx.tx_id = computeTxId(tx);
  return tx;
}

function _nodeEnvelopeTx(dag, nodeKp) {
  const tx = {
    tx_type: TX_TYPES.PRESCAN_COMPLETED, timestamp: 1777507200000,
    data: {
      ctid: "tip://c/OH-aaaaaaaaaaaaaa-0001", node_id: NODE_ID, probability: 0.1,
      tier: "low", flagged: false, overall_degraded: false, content_type: "text",
      modality_results: [], classifier_version: "t", classifier_providers_used: "t",
      completed_at: 1777507200000, failed: false, failure_reason: null,
    },
    prev: dag.prevFor(TX_TYPES.PRESCAN_COMPLETED, { node_id: NODE_ID }),
  };
  tx.tx_id = computeTxId(tx);
  return signTransaction(tx, nodeKp.privateKey);
}

function _rawVerdict(tx, dag) {
  const collected = collectTxSignatureInputs(tx, SCHEMA_FOR_TX_TYPE[tx.tx_type] ?? null, dag);
  if (!collected.ok) return null;   // unresolvable: pre-verify skips, sync path decides
  return collected.inputs.every(it => verifyWithAlgorithm(it.message, it.signature, it.publicKey, it.algorithm));
}

function _syncVerdict(tx, dag) {
  return verifyTxSignature(tx, SCHEMA_FOR_TX_TYPE[tx.tx_type] ?? null, dag).ok;
}

describe("tx pre-verification drift seal (collector == sync dispatcher)", () => {
  test("body-signed tx: valid and tampered agree with the sync verdict", () => {
    const fx = _setup();
    const tx = _contentTx(fx.dag, fx.authorKp, "pv-body");
    expect(_syncVerdict(tx, fx.dag)).toBe(true);
    expect(_rawVerdict(tx, fx.dag)).toBe(true);

    const tampered = { ...tx, data: { ...tx.data, origin_code: "AA" } };
    expect(_syncVerdict(tampered, fx.dag)).toBe(false);
    expect(_rawVerdict(tampered, fx.dag)).toBe(false);
  });

  test("envelope-signed tx: valid and tampered agree with the sync verdict", () => {
    const fx = _setup();
    const tx = _nodeEnvelopeTx(fx.dag, fx.nodeKp);
    expect(_syncVerdict(tx, fx.dag)).toBe(true);
    expect(_rawVerdict(tx, fx.dag)).toBe(true);

    const tampered = { ...tx, data: { ...tx.data, probability: 0.99 } };
    expect(_syncVerdict(tampered, fx.dag)).toBe(false);
    expect(_rawVerdict(tampered, fx.dag)).toBe(false);
  });

  test("unresolvable signer: collector refuses (null verdict), never a false pass", () => {
    const fx = _setup();
    const tx = _contentTx(fx.dag, fx.authorKp, "pv-ghost");
    tx.data = { ...tx.data, signer_tip_id: "tip://id/US-nobody0000000000" };
    expect(_rawVerdict(tx, fx.dag)).toBeNull();
    expect(_syncVerdict(tx, fx.dag)).toBe(false);
  });
});

describe("cryptoPool.verifyRaw", () => {
  test("sync fallback (size 0) verifies resolved inputs", async () => {
    const fx = _setup();
    const pool = createCryptoPool({ size: 0 });
    const tx = _contentTx(fx.dag, fx.authorKp, "pv-pool-sync");
    const collected = collectTxSignatureInputs(tx, SCHEMA_FOR_TX_TYPE[tx.tx_type], fx.dag);
    expect(collected.ok).toBe(true);
    await expect(pool.verifyRaw(collected.inputs)).resolves.toBe(true);
    const bad = collected.inputs.map(it => ({ ...it, message: it.message + "00" }));
    await expect(pool.verifyRaw(bad)).resolves.toBe(false);
    pool.shutdown();
  });

  test("worker path (size 1) verifies resolved inputs", async () => {
    const fx = _setup();
    const pool = createCryptoPool({ size: 1 });
    const tx = _contentTx(fx.dag, fx.authorKp, "pv-pool-worker");
    const collected = collectTxSignatureInputs(tx, SCHEMA_FOR_TX_TYPE[tx.tx_type], fx.dag);
    await expect(pool.verifyRaw(collected.inputs)).resolves.toBe(true);
    const bad = collected.inputs.map(it => ({ ...it, signature: it.signature.slice(0, -2) + "ff" }));
    await expect(pool.verifyRaw(bad)).resolves.toBe(false);
    pool.shutdown();
  }, 30000);
});
