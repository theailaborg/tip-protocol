/**
 * @file tests/consensus/commit-handler-statechange-dedup.test.js
 * @description GH #87 (AG-7 follow-up): in-batch dedup for the 11 remaining
 * state-changing tx types. Phase 1 validates all txs against pre-batch DAG
 * state before Phase 2 writes anything, so two competing same-key txs in one
 * round both pass _statefulCheck. These tests prove the _dedupCheck cases
 * drop the second tx in canonical order — and never drop legitimate
 * different-key siblings.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC    = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, signTransaction, computeTxId, shake256,
} = require(path.join(SHARED, "crypto"));
const { signPayload } = require(path.join(SRC, "schemas", "_common"));
const {
  TX_TYPES, CONTENT_STATUS, PRESCAN_REVIEW_STATES, RECUSAL_REASONS,
  DOMAIN_UNBIND_REASONS, DOMAIN_BINDING_STATUS, TIP_ID_TYPES,
} = require(path.join(SHARED, "constants"));
const { initDAG }     = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));

const dismissedSchema      = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
const confirmedSchema      = require(path.join(SRC, "schemas", "prescan-review-confirmed"));
const keyRotatedSchema     = require(path.join(SRC, "schemas", "key-rotated"));
const keyRecoverySchema    = require(path.join(SRC, "schemas", "key-recovery"));
const bindDomainSchema     = require(path.join(SRC, "schemas", "bind-domain"));
const registerDomainSchema = require(path.join(SRC, "schemas", "register-domain"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID    = "tip://node/test-sc-dedup";
const VP_ID      = "tip://vp/v1";
const AUTHOR_TIP   = "tip://id/US-aabbccddeeff0011";
const VERIFIER_TIP = "tip://id/US-1111aaaa1111aaaa";
const REVIEWER_TIP = "tip://id/US-2222bbbb2222bbbb";
const ORG_TIP      = "tip://id/US-9999eeee9999eeee";
const TARGET_2_TIP = "tip://id/US-3333cccc3333cccc";
const CTID_A = "tip://c/OH-aaaaaaaaaaaaaa-0001";
const CTID_B = "tip://c/OH-bbbbbbbbbbbbbb-0001";
const T0 = 1777507200000;   // registered_at base for all fixture rows
const T1 = 1777507300000;   // tx timestamps (after T0)

// ─── Fixture ────────────────────────────────────────────────────────────────
function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp     = generateMLDSAKeypair();
  const vpKp       = generateMLDSAKeypair();
  const authorKp   = generateMLDSAKeypair();
  const verifierKp = generateMLDSAKeypair();
  const reviewerKp = generateMLDSAKeypair();
  const orgKp      = generateMLDSAKeypair();
  const target2Kp  = generateMLDSAKeypair();

  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: T0,
  });
  dag.saveVP({
    vp_id: VP_ID, name: "test-vp", jurisdiction: "US",
    jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active",
    registered_at: T0,
  });

  const mkIdentity = (tip_id, kp, extra = {}) => dag.saveIdentity({
    tip_id, region: "US", public_key: kp.publicKey, root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: T0, tx_id: shake256(`id:${tip_id}`), ...extra,
  });
  mkIdentity(AUTHOR_TIP, authorKp);
  mkIdentity(VERIFIER_TIP, verifierKp);
  mkIdentity(REVIEWER_TIP, reviewerKp, { reviewer_consent: true });
  mkIdentity(ORG_TIP, orgKp, { tip_id_type: TIP_ID_TYPES.ORGANIZATION });
  mkIdentity(TARGET_2_TIP, target2Kp);
  dag.setScore(AUTHOR_TIP, 750, 0, T0);
  dag.setScore(VERIFIER_TIP, 820, 0, T0);

  const mkContent = (ctid) => dag.saveContent({
    ctid, origin_code: "OH",
    content_hash: shake256(`content:${ctid}`), perceptual_hash: null,
    author_tip_id: AUTHOR_TIP, signer_tip_id: AUTHOR_TIP,
    authors: [{ tip_id: AUTHOR_TIP, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: CONTENT_STATUS.REGISTERED,
    prescan_flagged: false, prescan_probability: 0.1, prescan_tier: "low",
    override: false, registered_at: T0, registered_urls: [],
    tx_id: shake256(`ctx:${ctid}`),
  });
  mkContent(CTID_A);
  mkContent(CTID_B);

  const config  = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });

  return { dag, nodeKp, vpKp, authorKp, verifierKp, reviewerKp, orgKp, target2Kp, handler };
}

// Assert helper: tx2 dropped with an in-batch dedup detail, tx1 committed.
function _expectSecondDropped(fx, res, tx2, detailRe = /in batch|in this batch/i) {
  expect(res.committed).toBe(1);
  expect(res.dropped).toBe(1);
  const rejection = fx.dag.getTxRejection(tx2.tx_id);
  expect(rejection).not.toBeNull();
  expect(rejection.reason_detail).toMatch(detailRe);
}

// ─── Builders: CONTENT_DISPUTED (auto path — node-signed envelope) ──────────
// auto:true mirrors prescan-review-trigger._buildAutoDisputeTx — it bypasses
// the disputer-score stateful predicates (`if (d.auto) return {valid:true}`)
// so the test isolates the dedup behaviour.
function _makeAutoDisputeTx(fx, ctid, sourceReviewId, timestamp) {
  const txBody = {
    tx_type: TX_TYPES.CONTENT_DISPUTED,
    timestamp,
    prev: fx.dag.getRecentPrev(),
    data: {
      ctid,
      reason: "creator_decision_window_expired",
      auto: true,
      node_id: NODE_ID,
      source_review_id: sourceReviewId,
      suggested_origin: "AG",
    },
  };
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, fx.nodeKp.privateKey);
}

// ─── HIGH severity ───────────────────────────────────────────────────────────

describe("GH #87 HIGH — CONTENT_DISPUTED in-batch dedup", () => {

  test("two disputes for the same ctid in one batch: second dropped", () => {
    const fx = _setup();
    const tx1 = _makeAutoDisputeTx(fx, CTID_A, "rv_1", T1);
    const tx2 = _makeAutoDisputeTx(fx, CTID_A, "rv_2", T1 + 1000);

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    _expectSecondDropped(fx, res, tx2);
    expect(fx.dag.getTx(tx1.tx_id)).not.toBeNull();
  });

  test("disputes for different ctids in one batch: both commit", () => {
    const fx = _setup();
    const tx1 = _makeAutoDisputeTx(fx, CTID_A, "rv_1", T1);
    const tx2 = _makeAutoDisputeTx(fx, CTID_B, "rv_2", T1 + 1000);

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    expect(res.committed).toBe(2);
    expect(res.dropped).toBe(0);
  });
});
