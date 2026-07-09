/**
 * @file tests/consensus/commit-handler-owner-chain.test.js
 * @description Stage 3 (#199): commit-time owner-chain prev[0] validation +
 * OWNER_HEAD_STALE rejection + node-side rebuild/requeue. Enforcement is
 * unconditional: prev[0] must equal the owner's committed head on every chain.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, computeTxId, shake256 } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, TX_REJECTION_REASON } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const contentRegisterSchema = require(path.join(SRC, "schemas", "content-register"));
const { ownerKey } = require(path.join(SRC, "consensus", "tx-owner"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/oc-test";
const VP_ID = "tip://vp/v1";
const AUTHOR_TIP = "tip://id/US-owner-chain-01";
const OWNER = ownerKey({ entityType: "identity", entityId: AUTHOR_TIP });

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const vpKp = generateMLDSAKeypair();
  const authorKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
  dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });
  return { dag, authorKp, handler };
}

function _contentTx(dag, authorKp, text, opts = {}) {
  const content_hash = shake256(text);
  const data = {
    ctid: `tip://c/OH-${content_hash.slice(0, 14)}-0001`,
    origin_code: "OH",
    content_hash,
    signer_tip_id: AUTHOR_TIP,
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR_TIP, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, registered_urls: [],
    cna_version: contentRegisterSchema.CURRENT_CNA_VERSION,
  };
  const sig = contentRegisterSchema.sign(contentRegisterSchema.buildSigningPayload(data, content_hash), authorKp.privateKey);
  const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1777507200000, data, signature: sig, prev: opts.prev || dag.prevFor(TX_TYPES.REGISTER_CONTENT, data) };
  tx.tx_id = computeTxId(tx);
  return tx;
}

describe("commit-handler — owner-chain prev validation + stale-head retry (#199)", () => {
  test("valid owner-chain prev commits and advances the owner head", () => {
    const fx = _setup();
    const tx = _contentTx(fx.dag, fx.authorKp, "oc-solo");
    const res = fx.handler.commitOrderedTxs([tx], 1);
    expect(res.committed).toBe(1);
    expect(fx.dag.getOwnerHead(OWNER)).toBe(tx.tx_id);
    expect(fx.dag.getTxRejection(tx.tx_id)).toBeNull();
  });

  test("two same-owner txs in one batch serialize: first commits, second is OWNER_HEAD_STALE + requeued", () => {
    const fx = _setup();
    const tx1 = _contentTx(fx.dag, fx.authorKp, "oc-first");
    const tx2 = _contentTx(fx.dag, fx.authorKp, "oc-second");
    expect(tx1.prev[0]).toBe(tx2.prev[0]);   // both raced against the same pre-batch head

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);
    expect(res.committed).toBe(1);           // only the first
    expect(fx.dag.getOwnerHead(OWNER)).toBe(tx1.tx_id);

    const rej = fx.dag.getTxRejection(tx2.tx_id);
    expect(rej).not.toBeNull();
    expect(rej.reason).toBe(TX_REJECTION_REASON.OWNER_HEAD_STALE);

    // Requeued: a rebuilt tx2 (prev[0] now == tx1) is back in the mempool.
    const requeued = fx.dag.getMempoolTxs().find(t => t.tx_type === TX_TYPES.REGISTER_CONTENT && t.data.content_hash === tx2.data.content_hash);
    expect(requeued).toBeTruthy();
    expect(requeued.prev[0]).toBe(tx1.tx_id);        // rebuilt against the new head
    expect(requeued.tx_id).not.toBe(tx2.tx_id);      // new content-addressed id
    expect(requeued.signature).toBe(tx2.signature);  // content signature unchanged

    // The requeued tx now commits cleanly on the next round.
    const res2 = fx.handler.commitOrderedTxs([requeued], 2);
    expect(res2.committed).toBe(1);
    expect(fx.dag.getOwnerHead(OWNER)).toBe(requeued.tx_id);
  });

});
