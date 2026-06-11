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

// ─── Builders: prescan review family ────────────────────────────────────────
// TRIGGERED is node-signed (envelope); DISMISSED / CONFIRMED are
// reviewer-signed (BODY); auto-RECUSED is node-signed with auto:true —
// mirrors prescan-review-trigger._buildAutoRecuseTx.

function _makeTriggeredTx(fx, { reviewId, ctid, timestamp }) {
  const txBody = {
    tx_type: TX_TYPES.PRESCAN_REVIEW_TRIGGERED,
    timestamp,
    prev: fx.dag.getRecentPrev(),
    data: {
      review_id: reviewId,
      ctid,
      creator_tip_id: AUTHOR_TIP,
      assigned_reviewer_tip_id: REVIEWER_TIP,
      node_id: NODE_ID,
      triggered_at_round: 1,
    },
  };
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, fx.nodeKp.privateKey);
}

function _makeDismissedTx(fx, { reviewId, timestamp }) {
  const fields = { review_id: reviewId, reviewer_tip_id: REVIEWER_TIP, decision_note: null };
  const payload = dismissedSchema.buildSigningPayload(fields);
  const signature = dismissedSchema.sign(payload, fx.reviewerKp.privateKey);
  const txBody = {
    tx_type: TX_TYPES.PRESCAN_REVIEW_DISMISSED,
    timestamp, prev: fx.dag.getRecentPrev(), data: { ...fields }, signature,
  };
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

function _makeConfirmedTx(fx, { reviewId, timestamp }) {
  const fields = {
    review_id: reviewId, reviewer_tip_id: REVIEWER_TIP,
    suggested_origin: "AG", decision_note: null,
  };
  const payload = confirmedSchema.buildSigningPayload(fields);
  const signature = confirmedSchema.sign(payload, fx.reviewerKp.privateKey);
  const txBody = {
    tx_type: TX_TYPES.PRESCAN_REVIEW_CONFIRMED,
    timestamp, prev: fx.dag.getRecentPrev(), data: { ...fields }, signature,
  };
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

function _makeAutoRecusedTx(fx, { reviewId, timestamp }) {
  const txBody = {
    tx_type: TX_TYPES.PRESCAN_REVIEW_RECUSED,
    timestamp,
    prev: fx.dag.getRecentPrev(),
    data: {
      review_id: reviewId,
      auto: true,
      node_id: NODE_ID,
      recusal_reason: RECUSAL_REASONS.SLA_EXPIRED,
    },
  };
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, fx.nodeKp.privateKey);
}

// Commit a TRIGGERED review in its own earlier round so terminal-decision
// txs have an open review row to act on.
function _openReview(fx, reviewId, ctid, round) {
  const res = fx.handler.commitOrderedTxs([_makeTriggeredTx(fx, { reviewId, ctid, timestamp: T1 })], round);
  expect(res.committed).toBe(1);
}

describe("GH #87 HIGH — PRESCAN_REVIEW_TRIGGERED in-batch dedup", () => {

  test("two triggers for the same ctid in one batch: second dropped", () => {
    const fx = _setup();
    // Same review_id is the realistic race (deterministic id from ctid+round
    // on every node) — but tx_ids differ because node_id/timestamps differ.
    const tx1 = _makeTriggeredTx(fx, { reviewId: "rv_same", ctid: CTID_A, timestamp: T1 });
    const tx2 = _makeTriggeredTx(fx, { reviewId: "rv_same", ctid: CTID_A, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    _expectSecondDropped(fx, res, tx2);
  });

  test("byzantine: two triggers for same ctid with DIFFERENT review_ids: second dropped", () => {
    // The committed-history guard in _statefulCheck (getOpenPrescanReviewByCtid)
    // can't see in-batch siblings — two forged different review_ids for one
    // ctid would otherwise create two parallel open reviews. The ctid dedup
    // key closes exactly this hole.
    const fx = _setup();
    const tx1 = _makeTriggeredTx(fx, { reviewId: "rv_honest", ctid: CTID_A, timestamp: T1 });
    const tx2 = _makeTriggeredTx(fx, { reviewId: "rv_forged", ctid: CTID_A, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    _expectSecondDropped(fx, res, tx2);
    expect(fx.dag.getPrescanReview("rv_honest")).not.toBeNull();
    expect(fx.dag.getPrescanReview("rv_forged")).toBeNull();
  });

  test("triggers for different ctids in one batch: both commit", () => {
    const fx = _setup();
    const tx1 = _makeTriggeredTx(fx, { reviewId: "rv_a", ctid: CTID_A, timestamp: T1 });
    const tx2 = _makeTriggeredTx(fx, { reviewId: "rv_b", ctid: CTID_B, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    expect(res.committed).toBe(2);
    expect(res.dropped).toBe(0);
  });
});

describe("GH #87 HIGH — prescan terminal decisions: one per review_id per batch (cross-type)", () => {

  test("DISMISSED + DISMISSED for same review_id: second dropped", () => {
    const fx = _setup();
    _openReview(fx, "rv_1", CTID_A, 1);
    const tx1 = _makeDismissedTx(fx, { reviewId: "rv_1", timestamp: T1 + 2000 });
    const tx2 = _makeDismissedTx(fx, { reviewId: "rv_1", timestamp: T1 + 3000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 2);

    _expectSecondDropped(fx, res, tx2);
  });

  test("DISMISSED + auto-RECUSED for same review_id (SLA-boundary race): second dropped", () => {
    const fx = _setup();
    _openReview(fx, "rv_1", CTID_A, 1);
    const tx1 = _makeDismissedTx(fx, { reviewId: "rv_1", timestamp: T1 + 2000 });
    const tx2 = _makeAutoRecusedTx(fx, { reviewId: "rv_1", timestamp: T1 + 3000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 2);

    _expectSecondDropped(fx, res, tx2);
    // Review state reflects the FIRST decision only.
    expect(fx.dag.getPrescanReview("rv_1").state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);
  });

  test("CONFIRMED + DISMISSED for same review_id: second dropped", () => {
    const fx = _setup();
    _openReview(fx, "rv_1", CTID_A, 1);
    const tx1 = _makeConfirmedTx(fx, { reviewId: "rv_1", timestamp: T1 + 2000 });
    const tx2 = _makeDismissedTx(fx, { reviewId: "rv_1", timestamp: T1 + 3000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 2);

    _expectSecondDropped(fx, res, tx2);
  });

  test("decisions for different review_ids in one batch: both commit", () => {
    const fx = _setup();
    _openReview(fx, "rv_a", CTID_A, 1);
    _openReview(fx, "rv_b", CTID_B, 2);
    const tx1 = _makeDismissedTx(fx, { reviewId: "rv_a", timestamp: T1 + 2000 });
    const tx2 = _makeDismissedTx(fx, { reviewId: "rv_b", timestamp: T1 + 3000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 3);

    expect(res.committed).toBe(2);
    expect(res.dropped).toBe(0);
  });
});

// ─── Builders: key transitions ──────────────────────────────────────────────
// KEY_ROTATED: BODY-signed by the OLD (currently active) key — the
// dispatcher resolves it via getKeyValidAt(tip_id, tx.timestamp) because
// tx.timestamp < effective_at. KEY_RECOVERY: BODY-signed by the VP, plus
// new_key_signature proof-of-possession co-signed by the NEW key;
// effective_at is chain-stamped to tx.timestamp.

function _makeKeyRotatedTx(fx, { tipId, oldKp, timestamp }) {
  const newKp = generateMLDSAKeypair();
  const fields = {
    algorithm: "ml-dsa-65",
    effective_at: timestamp + 60_000,   // must be >= tx.timestamp
    new_public_key: newKp.publicKey,
    old_key_fingerprint: shake256(oldKp.publicKey).slice(0, 32),
    tip_id: tipId,
  };
  const payload = keyRotatedSchema.buildSigningPayload(fields);
  const signature = keyRotatedSchema.sign(payload, oldKp.privateKey);
  const txBody = {
    tx_type: TX_TYPES.KEY_ROTATED,
    timestamp, prev: fx.dag.getRecentPrev(), data: { ...fields }, signature,
  };
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

function _makeKeyRecoveryTx(fx, { tipId, replacesPubkey, timestamp }) {
  const newKp = generateMLDSAKeypair();
  const core = {
    algorithm: "ml-dsa-65",
    new_public_key: newKp.publicKey,
    recovery_evidence_hash: shake256("recovery-evidence"),
    replaces_pubkey: replacesPubkey,
    tip_id: tipId,
    vp_id: VP_ID,
    zk_proof: { pi_a: ["1"], pi_b: [["1"]], pi_c: ["1"] },
  };
  const payload = keyRecoverySchema.buildSigningPayload(core);
  const vpSignature  = keyRecoverySchema.sign(payload, fx.vpKp.privateKey);
  const newKeySig    = keyRecoverySchema.sign(payload, newKp.privateKey);
  const txBody = {
    tx_type: TX_TYPES.KEY_RECOVERY,
    timestamp,
    prev: fx.dag.getRecentPrev(),
    data: {
      ...core,
      effective_at: timestamp,          // chain-stamped: must equal tx.timestamp
      new_key_signature: newKeySig,
    },
    signature: vpSignature,
  };
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

describe("GH #87 HIGH — key transitions: one per tip_id per batch (cross-type)", () => {

  test("two KEY_ROTATED for same tip_id in one batch: second dropped", () => {
    const fx = _setup();
    const tx1 = _makeKeyRotatedTx(fx, { tipId: AUTHOR_TIP, oldKp: fx.authorKp, timestamp: T1 });
    const tx2 = _makeKeyRotatedTx(fx, { tipId: AUTHOR_TIP, oldKp: fx.authorKp, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    _expectSecondDropped(fx, res, tx2);
  });

  test("KEY_ROTATED + KEY_RECOVERY for same tip_id (cross-type): second dropped", () => {
    const fx = _setup();
    const tx1 = _makeKeyRotatedTx(fx, { tipId: AUTHOR_TIP, oldKp: fx.authorKp, timestamp: T1 });
    const tx2 = _makeKeyRecoveryTx(fx, {
      tipId: AUTHOR_TIP, replacesPubkey: fx.authorKp.publicKey, timestamp: T1 + 1000,
    });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    _expectSecondDropped(fx, res, tx2);
  });

  test("KEY_RECOVERY + KEY_ROTATED for same tip_id (recovery first): second dropped", () => {
    // Security-relevant ordering: a VP-attested recovery lands first; a
    // rotation still signed by the (compromised) old key in the same batch
    // must be dropped, not allowed to stomp the recovered key.
    const fx = _setup();
    const tx1 = _makeKeyRecoveryTx(fx, {
      tipId: AUTHOR_TIP, replacesPubkey: fx.authorKp.publicKey, timestamp: T1,
    });
    const tx2 = _makeKeyRotatedTx(fx, { tipId: AUTHOR_TIP, oldKp: fx.authorKp, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    _expectSecondDropped(fx, res, tx2);
  });

  test("KEY_ROTATED for two different tip_ids in one batch: both commit", () => {
    const fx = _setup();
    const tx1 = _makeKeyRotatedTx(fx, { tipId: AUTHOR_TIP, oldKp: fx.authorKp, timestamp: T1 });
    const tx2 = _makeKeyRotatedTx(fx, { tipId: TARGET_2_TIP, oldKp: fx.target2Kp, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    expect(res.committed).toBe(2);
    expect(res.dropped).toBe(0);
  });
});

// ─── Builder: REVOKE_* (VP-signed BODY: {tx_type, tip_id, issuing_vp_id}) ───
// tx_type is in the signed payload so a captured signature for one revoke
// type can't replay as another (see REVOKE_CONTRACT in schemas/_registry.js).
function _makeRevokeTx(fx, { txType, tipId, timestamp }) {
  const payload = { tx_type: txType, tip_id: tipId, issuing_vp_id: VP_ID };
  const signature = signPayload(payload, fx.vpKp.privateKey);
  const txBody = {
    tx_type: txType,
    timestamp,
    prev: fx.dag.getRecentPrev(),
    data: { tx_type: txType, tip_id: tipId, issuing_vp_id: VP_ID },
    signature,
  };
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

// ─── MED severity ────────────────────────────────────────────────────────────

describe("GH #87 MED — REVOKE_*: one revocation per tip_id per batch (cross-type)", () => {

  test("two REVOKE_VOLUNTARY for same tip_id in one batch: second dropped", () => {
    const fx = _setup();
    const tx1 = _makeRevokeTx(fx, { txType: TX_TYPES.REVOKE_VOLUNTARY, tipId: AUTHOR_TIP, timestamp: T1 });
    const tx2 = _makeRevokeTx(fx, { txType: TX_TYPES.REVOKE_VOLUNTARY, tipId: AUTHOR_TIP, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    _expectSecondDropped(fx, res, tx2);
    expect(fx.dag.isRevoked(AUTHOR_TIP)).toBe(true);
  });

  test("REVOKE_VOLUNTARY + REVOKE_DECEASED for same tip_id (cross-type): second dropped", () => {
    const fx = _setup();
    const tx1 = _makeRevokeTx(fx, { txType: TX_TYPES.REVOKE_VOLUNTARY, tipId: AUTHOR_TIP, timestamp: T1 });
    const tx2 = _makeRevokeTx(fx, { txType: TX_TYPES.REVOKE_DECEASED, tipId: AUTHOR_TIP, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    _expectSecondDropped(fx, res, tx2);
    expect(fx.dag.isRevoked(AUTHOR_TIP)).toBe(true);
  });

  test("REVOKE_DEVICE + REVOKE_VOLUNTARY for same tip_id (cross-type): second dropped", () => {
    // REVOKE_DEVICE currently revokes the whole identity (same
    // addRevocation path) — pin that assumption so any future
    // per-device revocation flow has to revisit this dedup key.
    const fx = _setup();
    const tx1 = _makeRevokeTx(fx, { txType: TX_TYPES.REVOKE_DEVICE, tipId: AUTHOR_TIP, timestamp: T1 });
    const tx2 = _makeRevokeTx(fx, { txType: TX_TYPES.REVOKE_VOLUNTARY, tipId: AUTHOR_TIP, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    _expectSecondDropped(fx, res, tx2);
    expect(fx.dag.isRevoked(AUTHOR_TIP)).toBe(true);
  });

  test("REVOKE_VOLUNTARY for two different tip_ids: both commit", () => {
    const fx = _setup();
    const tx1 = _makeRevokeTx(fx, { txType: TX_TYPES.REVOKE_VOLUNTARY, tipId: AUTHOR_TIP, timestamp: T1 });
    const tx2 = _makeRevokeTx(fx, { txType: TX_TYPES.REVOKE_VOLUNTARY, tipId: TARGET_2_TIP, timestamp: T1 + 1000 });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    expect(res.committed).toBe(2);
    expect(res.dropped).toBe(0);
    expect(fx.dag.isRevoked(AUTHOR_TIP)).toBe(true);
    expect(fx.dag.isRevoked(TARGET_2_TIP)).toBe(true);
  });
});
