/**
 * @file tests/consensus/content-count-materialized.test.js
 * @description Read-model per-content counters (verification_count, dispute_count)
 * maintained in the commit-handler apply path. They are NOT in the merkle root;
 * correctness rests on being applied over the already-deduped `validated` set in
 * consensus order. These tests prove: the column equals the live tx count, it
 * counts only unique (deduped) actions, and it is independent per ctid.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, signTransaction, computeTxId, shake256 } = require(path.join(SHARED, "crypto"));
const { signPayload } = require(path.join(SRC, "schemas", "_common"));
const { TX_TYPES, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-count";
const VP_ID = "tip://vp/v1";
const AUTHOR_TIP = "tip://id/US-aabbccddeeff0011";
const V1_TIP = "tip://id/US-1111aaaa1111aaaa";
const V2_TIP = "tip://id/US-2222bbbb2222bbbb";
const CTID_A = "tip://c/OH-aaaaaaaaaaaaaa-0001";
const CTID_B = "tip://c/OH-bbbbbbbbbbbbbb-0001";
const T0 = 1777507200000;
const T1 = 1777507300000;

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const vpKp = generateMLDSAKeypair();
  const authorKp = generateMLDSAKeypair();
  const v1Kp = generateMLDSAKeypair();
  const v2Kp = generateMLDSAKeypair();

  dag.saveNode({ node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey, status: "active", registered_at: T0 });
  dag.saveVP({ vp_id: VP_ID, name: "test-vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: T0 });

  const mkIdentity = (tip_id, kp) => dag.saveIdentity({
    tip_id, region: "US", public_key: kp.publicKey, root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: T0, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id }),
  });
  mkIdentity(AUTHOR_TIP, authorKp);
  mkIdentity(V1_TIP, v1Kp);
  mkIdentity(V2_TIP, v2Kp);
  dag.setScore(AUTHOR_TIP, 750, 0, T0);
  dag.setScore(V1_TIP, 820, 0, T0);
  dag.setScore(V2_TIP, 820, 0, T0);

  const mkContent = (ctid) => dag.saveContent({
    ctid, origin_code: "OH", content_hash: shake256(`content:${ctid}`),
    author_tip_id: AUTHOR_TIP, signer_tip_id: AUTHOR_TIP,
    authors: [{ tip_id: AUTHOR_TIP, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: CONTENT_STATUS.REGISTERED, prescan_flagged: false, prescan_probability: 0.1,
    prescan_tier: "low", override: false, registered_at: T0, registered_urls: [],
    tx_id: shake256(`ctx:${ctid}`),
  });
  mkContent(CTID_A);
  mkContent(CTID_B);

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });
  return { dag, nodeKp, authorKp, v1Kp, v2Kp, handler };
}

function _verifyTx(fx, { ctid, verifierTipId, verifierKp, timestamp }) {
  const signature = signPayload({ verifier_tip_id: verifierTipId, ctid, verdict: "ORIGIN_CONFIRMED" }, verifierKp.privateKey);
  const txBody = {
    tx_type: TX_TYPES.CONTENT_VERIFIED, timestamp, prev: [],
    data: { ctid, verifier_tip_id: verifierTipId, verdict: "ORIGIN_CONFIRMED", weighted_delta: 2, author_tip_id: AUTHOR_TIP },
    signature,
  };
  txBody.prev = fx.dag.prevFor(txBody.tx_type, txBody.data);
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

function _disputeTx(fx, { ctid, sourceReviewId, timestamp }) {
  const txBody = {
    tx_type: TX_TYPES.CONTENT_DISPUTED, timestamp, prev: [],
    data: { ctid, reason: "creator_decision_window_expired", auto: true, node_id: NODE_ID, source_review_id: sourceReviewId, suggested_origin: "AG" },
  };
  txBody.prev = fx.dag.prevFor(txBody.tx_type, txBody.data);
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, fx.nodeKp.privateKey);
}

const liveVerify = (dag, ctid) => dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_VERIFIED, ctid).length;
const liveDispute = (dag, ctid) => dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid).length;

describe("materialized content counters — equal the live count, dedup, per-ctid", () => {

  test("verification_count increments per distinct verifier and equals the live count", () => {
    const fx = _setup();
    expect(fx.dag.getContent(CTID_A).verification_count || 0).toBe(0);

    const res = fx.handler.commitOrderedTxs([
      _verifyTx(fx, { ctid: CTID_A, verifierTipId: V1_TIP, verifierKp: fx.v1Kp, timestamp: T1 }),
      _verifyTx(fx, { ctid: CTID_A, verifierTipId: V2_TIP, verifierKp: fx.v2Kp, timestamp: T1 + 1000 }),
    ], 1);

    expect(res.committed).toBe(2);
    expect(fx.dag.getContent(CTID_A).verification_count).toBe(2);
    expect(fx.dag.getContent(CTID_A).verification_count).toBe(liveVerify(fx.dag, CTID_A));
  });

  test("duplicate verifier in one batch is deduped: counted once", () => {
    const fx = _setup();
    const res = fx.handler.commitOrderedTxs([
      _verifyTx(fx, { ctid: CTID_A, verifierTipId: V1_TIP, verifierKp: fx.v1Kp, timestamp: T1 }),
      _verifyTx(fx, { ctid: CTID_A, verifierTipId: V1_TIP, verifierKp: fx.v1Kp, timestamp: T1 + 1000 }),
    ], 1);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(1);
    expect(fx.dag.getContent(CTID_A).verification_count).toBe(1);
    expect(fx.dag.getContent(CTID_A).verification_count).toBe(liveVerify(fx.dag, CTID_A));
  });

  test("racing disputes for one ctid dedup to one; dispute_count equals the live count", () => {
    const fx = _setup();
    const res = fx.handler.commitOrderedTxs([
      _disputeTx(fx, { ctid: CTID_B, sourceReviewId: "rv_1", timestamp: T1 }),
      _disputeTx(fx, { ctid: CTID_B, sourceReviewId: "rv_2", timestamp: T1 + 1000 }),
    ], 1);

    expect(res.committed).toBe(1);
    expect(fx.dag.getContent(CTID_B).dispute_count).toBe(1);
    expect(fx.dag.getContent(CTID_B).dispute_count).toBe(liveDispute(fx.dag, CTID_B));
  });

  test("counters are independent per ctid", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([
      _verifyTx(fx, { ctid: CTID_A, verifierTipId: V1_TIP, verifierKp: fx.v1Kp, timestamp: T1 }),
      _disputeTx(fx, { ctid: CTID_B, sourceReviewId: "rv_1", timestamp: T1 + 1000 }),
    ], 1);

    expect(fx.dag.getContent(CTID_A).verification_count).toBe(1);
    expect(fx.dag.getContent(CTID_A).dispute_count || 0).toBe(0);
    expect(fx.dag.getContent(CTID_B).dispute_count).toBe(1);
    expect(fx.dag.getContent(CTID_B).verification_count || 0).toBe(0);
  });
});
