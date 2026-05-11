/**
 * @file tests/consensus/commit-handler-rejections.test.js
 * @description Wiring tests for #64 follow-up — every commit-handler
 * drop site that has a tx_id must record a tx_rejection row so the
 * outcome endpoint can answer "what happened to my tx" with a
 * specific reason.
 *
 * Pairs with `tests/consensus/mempool.test.js` (mempool admit + TTL
 * eviction wiring) and `tests/dag/tx-rejections.test.js` (storage
 * layer). Together they seal the no-loss invariant at every stage
 * between API admission and committed DAG state.
 *
 * Drop sites covered:
 *   1. structural validation failure (tx-validator)
 *   2. signature verification failure
 *   3. business-rule revalidation — identity_already_registered
 *      (specific code mapped from the rule's error message)
 *   4. business-rule revalidation — content_already_registered
 *   5. business-rule revalidation — first-wins dedup (verdict races
 *      etc.) → generic REVALIDATION_FAILED with specific detail
 *   6. atomic transaction rollback (disk error during commit phase
 *      drops every previously-validated tx in the batch)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, signTransaction, computeTxId, shake256, signBody } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, TX_REJECTION_REASON, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));

beforeAll(async () => {
  await initCrypto();
});

const NODE_ID = "tip://node/test";

// ─── Fixture: minimal dag with a node + VP + author identity ───────────────
// Just enough state to make REGISTER_IDENTITY / REGISTER_CONTENT txs hit
// commit-handler's revalidation path without dragging in the full dispute
// machinery. Each test layers on whatever conflict it needs.
function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  // VP gets a real keypair so REGISTER_IDENTITY tests can produce a
  // valid `vp_signature` and reach the business-rule layer
  // (commit-handler verifies the body signature before the rule check).
  const vpKp = generateMLDSAKeypair();
  dag.saveVP({
    vp_id: "tip://vp/v1", name: "vp1", jurisdiction: "US",
    jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active",
    registered_at: "2026-01-01T00:00:00.000Z",
  });
  // Author identity gets a real keypair so REGISTER_CONTENT tests can
  // produce a valid `data.signature` and reach the business-rule layer.
  const authorTipId = "tip://id/author";
  const authorKp = generateMLDSAKeypair();
  dag.saveIdentity({
    tip_id: authorTipId, region: "US", public_key: authorKp.publicKey, root_public_key: "00",
    vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("id:author"),
  });
  dag.setScore(authorTipId, 750, 0, "2026-01-01T00:00:00.000Z");

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });

  return { dag, scoring, handler, config, nodeKp, vpKp, authorKp, authorTipId };
}

// REGISTER_IDENTITY signature scope — must match commit-handler exactly
// (commit-handler.js:_verifyTxSignature). Without `creator_name`, it's
// the BASE_FIELDS set below.
const REG_IDENTITY_SIGNED_FIELDS = ["region", "public_key", "dedup_hash", "zk_proof", "verification_tier", "vp_id", "social_attested"];
function _signRegisterIdentity(vpKp, data) {
  const signedFields = {};
  for (const f of REG_IDENTITY_SIGNED_FIELDS) if (data[f] !== undefined) signedFields[f] = data[f];
  return signBody(signedFields, vpKp.privateKey);
}

// REGISTER_CONTENT signs the canonical 9-field CNA-2.2 payload — see
// docs/CONTENT_SIGNING.md and node/src/schemas/content-register.js.
// This helper builds the same payload tx.data must carry so the
// commit-handler can re-verify, and signs it. Mutates `data` in-place
// to fill in the CNA-2.2 fields that ride alongside the signature.
const contentRegisterSchema = require(path.join(SRC, "schemas", "content-register"));
function _signRegisterContent(authorKp, data) {
  const tipId = data.signer_tip_id;
  if (!data.authors) {
    data.authors = [{ key_mode: "attribution", role: "byline", signed: false,
                       tip_id: tipId, tip_id_type: "personal" }];
  }
  if (!data.attribution_mode) data.attribution_mode = "self";
  if (!data.extras) data.extras = {};
  if (!data.registered_urls) data.registered_urls = [];
  if (!data.cna_version) data.cna_version = contentRegisterSchema.CURRENT_CNA_VERSION;
  const payload = contentRegisterSchema.buildSigningPayload(data, data.content_hash);
  return contentRegisterSchema.sign(payload, authorKp.privateKey);
}

function _signByNode(dag, nodeKp, txBody) {
  // Auto-fill prev from the live DAG ring — non-genesis txs require
  // valid prev[] refs at structural-validation time. Without this,
  // every test below would short-circuit on a "missing prev" error
  // before reaching the drop site we're actually trying to exercise.
  txBody.prev = txBody.prev && txBody.prev.length ? txBody.prev : dag.getRecentPrev();
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, nodeKp.privateKey);
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Structural validation failure → REVALIDATION_FAILED
// ═══════════════════════════════════════════════════════════════════════════

describe("commit-handler — structural validation failures", () => {
  test("schema-violating tx is dropped AND recorded with the validator's error", () => {
    const fx = _setup();
    // REGISTER_IDENTITY missing the required `tip_id` field. Schema fails;
    // commit-handler logs warn + drops. Pre-fix: no row, user sees 404.
    const tx = _signByNode(fx.dag, fx.nodeKp, {
      tx_type: TX_TYPES.REGISTER_IDENTITY,
      timestamp: "2026-04-30T00:00:00.000Z",
      prev: [],
      data: {
        // tip_id intentionally omitted
        region: "US",
        public_key: "00",
        vp_id: "tip://vp/v1",
        verification_tier: "T1",
        dedup_hash: "0xdeadbeef",
        zk_proof: { a: 1 },
      },
    });

    const res = fx.handler.commitOrderedTxs([tx], 42);
    expect(res.committed).toBe(0);
    expect(res.dropped).toBe(1);

    const row = fx.dag.getTxRejection(tx.tx_id);
    expect(row).not.toBeNull();
    expect(row.reason).toBe(TX_REJECTION_REASON.REVALIDATION_FAILED);
    expect(row.reason_detail).toMatch(/tip_id/i);  // validator's specific error
    expect(row.dropper_node_id).toBe(NODE_ID);
    expect(row.rejected_at_round).toBe(42);
    expect(row.tx_data).toEqual(tx);  // full body for replay
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Signature failure → REVALIDATION_FAILED with "signature failed"
// ═══════════════════════════════════════════════════════════════════════════

describe("commit-handler — signature verification failures", () => {
  test("tx with valid schema but bad signature is dropped AND recorded", () => {
    const fx = _setup();
    // SCORE_UPDATE that passes schema but is signed with the wrong key.
    // commit-handler verifies node-signed txs against the registered
    // node public_key — using a different node's key fails the check.
    const wrongKp = generateMLDSAKeypair();
    const tx = _signByNode(fx.dag, wrongKp, {
      tx_type: TX_TYPES.SCORE_UPDATE,
      timestamp: "2026-04-30T00:00:00.000Z",
      prev: [],
      data: {
        tip_id: fx.authorTipId,
        delta: 10,
        reason: "test",
        node_id: NODE_ID,  // claims to be from our node, but signed by a different key
      },
    });

    const res = fx.handler.commitOrderedTxs([tx], 42);
    expect(res.committed).toBe(0);
    expect(res.dropped).toBe(1);

    const row = fx.dag.getTxRejection(tx.tx_id);
    expect(row).not.toBeNull();
    expect(row.reason).toBe(TX_REJECTION_REASON.REVALIDATION_FAILED);
    expect(row.reason_detail).toBe("signature failed");
    expect(row.rejected_at_round).toBe(42);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Business-rule: identity_already_registered → specific reason code
// ═══════════════════════════════════════════════════════════════════════════

describe("commit-handler — business-rule revalidation: identity_already_registered", () => {
  test("dedup_hash already present in dag → IDENTITY_ALREADY_REGISTERED row", () => {
    const fx = _setup();
    // Decimal field-element string — the validator enforces this format
    // (Poseidon outputs are decimal-stringified BN128 elements).
    const dedupHash = "12345678901234567890";
    // Plant the dedup hash so the canRegisterIdentity rule fails at commit.
    fx.dag.addDedupHash(dedupHash, 1700000000);

    const data = {
      // tip://id/[REGION]-[16hex] — required by tx-validator before
      // business rules ever run.
      tip_id: "tip://id/US-1234567890abcdef",
      region: "US",
      public_key: "00",
      vp_id: "tip://vp/v1",
      verification_tier: "T1",
      dedup_hash: dedupHash,
      // Groth16 proof shape — validator only checks that pi_a/pi_b/pi_c
      // exist; the values are not crypto-verified at this layer.
      zk_proof: { pi_a: ["1"], pi_b: [["1"]], pi_c: ["1"] },
      social_attested: false,
    };
    data.vp_signature = _signRegisterIdentity(fx.vpKp, data);
    const tx = _signByNode(fx.dag, fx.nodeKp, {
      tx_type: TX_TYPES.REGISTER_IDENTITY,
      timestamp: "2026-04-30T00:00:00.000Z",
      prev: [],
      data,
    });

    const res = fx.handler.commitOrderedTxs([tx], 99);
    expect(res.committed).toBe(0);
    expect(res.dropped).toBe(1);

    const row = fx.dag.getTxRejection(tx.tx_id);
    // Specific reason code so the API consumer can disambiguate this
    // failure from a generic revalidation drop without parsing detail.
    expect(row.reason).toBe(TX_REJECTION_REASON.IDENTITY_ALREADY_REGISTERED);
    expect(row.reason_detail).toContain("Identity already registered");
    expect(row.rejected_at_round).toBe(99);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Business-rule: content_already_registered → specific reason code
// ═══════════════════════════════════════════════════════════════════════════

describe("commit-handler — business-rule revalidation: content_already_registered", () => {
  test("ctid already present in dag → CONTENT_ALREADY_REGISTERED row", () => {
    const fx = _setup();
    // CTID format: tip://c/[ORIGIN]-[14hex]-[4hex] (validator-enforced).
    const ctid = "tip://c/OH-1234567890abcd-1234";
    fx.dag.saveContent({
      ctid, origin_code: "OH", content_hash: shake256("c1"),
      author_tip_id: fx.authorTipId, status: CONTENT_STATUS.REGISTERED,
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`content:${ctid}`),
    });

    const data = {
      ctid,
      origin_code: "OH",
      content_hash: shake256("c2"),
      signer_tip_id: fx.authorTipId,
    };
    data.signature = _signRegisterContent(fx.authorKp, data);
    const tx = _signByNode(fx.dag, fx.nodeKp, {
      tx_type: TX_TYPES.REGISTER_CONTENT,
      timestamp: "2026-04-30T00:00:00.000Z",
      prev: [],
      data,
    });

    fx.handler.commitOrderedTxs([tx], 99);
    const row = fx.dag.getTxRejection(tx.tx_id);
    expect(row.reason).toBe(TX_REJECTION_REASON.CONTENT_ALREADY_REGISTERED);
    expect(row.reason_detail).toContain("Content already registered");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. Business-rule: dedup race → generic REVALIDATION_FAILED
// ═══════════════════════════════════════════════════════════════════════════

describe("commit-handler — business-rule revalidation: dedup loser → REVALIDATION_FAILED", () => {
  test("second ADJUDICATION_RESULT for same ctid in same batch is dropped + recorded with specific detail", () => {
    const fx = _setup();
    const ctid = "tip://content/dup-adj";
    // Fixture: content + dispute already in dag so adjudication has the
    // pre-conditions it needs for derived-state application.
    fx.dag.saveContent({
      ctid, origin_code: "OH", content_hash: shake256("c"), author_tip_id: fx.authorTipId,
      status: CONTENT_STATUS.DISPUTED, registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`c:${ctid}`),
    });

    const adj1 = _signByNode(fx.dag, fx.nodeKp, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-30T00:00:00.000Z",
      prev: [],
      data: { ctid, declared_origin: "OH", verdict: "DISMISSED", node_id: NODE_ID },
    });
    const adj2 = _signByNode(fx.dag, fx.nodeKp, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-30T00:00:01.000Z",  // different ts so tx_id differs
      prev: [],
      data: { ctid, declared_origin: "OH", verdict: "DISMISSED", node_id: NODE_ID },
    });

    fx.handler.commitOrderedTxs([adj1, adj2], 50);

    // First wins, second is rejected with generic code + specific detail.
    expect(fx.dag.getTx(adj1.tx_id)).not.toBeNull();   // committed
    expect(fx.dag.getTxRejection(adj1.tx_id)).toBeNull();

    const row = fx.dag.getTxRejection(adj2.tx_id);
    expect(row).not.toBeNull();
    expect(row.reason).toBe(TX_REJECTION_REASON.REVALIDATION_FAILED);
    expect(row.reason_detail).toContain("ADJUDICATION_RESULT already in this batch");
    expect(row.rejected_at_round).toBe(50);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. Atomic transaction rollback → all phase-1 winners dropped + recorded
//    Disk error during phase-2 write means every tx that already passed
//    schema/sig/business-rules in phase 1 is rolled back. Each one needs
//    a row so the user gets an answer.
// ═══════════════════════════════════════════════════════════════════════════

describe("commit-handler — atomic transaction rollback drops all validated txs", () => {
  test("rollback of N validated txs writes N rejection rows with the underlying error", () => {
    const fx = _setup();

    // Wrap dag.runInTransaction so it throws after the test sees its txs
    // start landing — simulates a real disk-write failure mid-batch.
    const realRunInTx = fx.dag.runInTransaction;
    fx.dag.runInTransaction = (fn) => {
      // Run the function so addTx etc. are exercised, then throw to
      // simulate SQLite raising mid-commit. better-sqlite3's tx wrapper
      // would already be auto-rolling back here, but the in-memory
      // store doesn't — what matters for this test is the catch
      // branch in commit-handler: it rolls back `committed`, marks
      // every `validated` tx as dropped, and records each one.
      try { return realRunInTx.call(fx.dag, fn); }
      finally { throw new Error("simulated disk failure"); }
    };

    const tx1 = _signByNode(fx.dag, fx.nodeKp, {
      tx_type: TX_TYPES.SCORE_UPDATE,
      timestamp: "2026-04-30T00:00:00.000Z",
      prev: [],
      data: { tip_id: fx.authorTipId, delta: 1, reason: "tx1", node_id: NODE_ID },
    });
    const tx2 = _signByNode(fx.dag, fx.nodeKp, {
      tx_type: TX_TYPES.SCORE_UPDATE,
      timestamp: "2026-04-30T00:00:01.000Z",
      prev: [],
      data: { tip_id: fx.authorTipId, delta: 1, reason: "tx2", node_id: NODE_ID },
    });

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 200);
    expect(res.committed).toBe(0);
    expect(res.dropped).toBe(2);

    for (const tx of [tx1, tx2]) {
      const row = fx.dag.getTxRejection(tx.tx_id);
      expect(row).not.toBeNull();
      expect(row.reason).toBe(TX_REJECTION_REASON.REVALIDATION_FAILED);
      expect(row.reason_detail).toContain("transaction rollback");
      expect(row.reason_detail).toContain("simulated disk failure");
      expect(row.rejected_at_round).toBe(200);
      expect(row.tx_data).toEqual(tx);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. Negative case: successfully-committed tx must NOT have a rejection row
//    Catches a future regression where someone wires the sink in the
//    success path by accident — that would make the outcome endpoint
//    return "rejected" for a tx that's actually in dag.txs.
// ═══════════════════════════════════════════════════════════════════════════

describe("commit-handler — committed txs do not appear in tx_rejections", () => {
  test("happy-path SCORE_UPDATE commits and leaves no rejection row", () => {
    const fx = _setup();
    const tx = _signByNode(fx.dag, fx.nodeKp, {
      tx_type: TX_TYPES.SCORE_UPDATE,
      timestamp: "2026-04-30T00:00:00.000Z",
      prev: [],
      data: { tip_id: fx.authorTipId, delta: 5, reason: "happy_path", node_id: NODE_ID },
    });
    const res = fx.handler.commitOrderedTxs([tx], 42);
    expect(res.committed).toBe(1);
    expect(fx.dag.getTx(tx.tx_id)).not.toBeNull();
    expect(fx.dag.getTxRejection(tx.tx_id)).toBeNull();
    expect(fx.dag.countTxRejections()).toBe(0);
  });
});
