/**
 * @file tests/consensus/commit-handler-register-dedup.test.js
 * @description AG-7: in-batch dedup for REGISTER_* tx types.
 *
 * Phase 1 validates all txs against current DAG state before Phase 2 writes
 * anything. Two concurrent registration txs for the same entity both see "not
 * yet registered" in Phase 1 and both pass _statefulCheck. Without in-batch
 * dedup they both land in `validated`, causing two outcomes:
 *
 *  a) _applyDerivedState defensive guards silently skip the second write
 *     → orphaned tx committed with no effect
 *  b) REGISTER_IDENTITY: same dedup_hash + different tip_id → the first tx
 *     writes the dedup_hash (blocking future registrations), but the second
 *     tx with the SAME dedup_hash writes a DIFFERENT identity because the
 *     guard only checks `!dag.hasDedupHash` — which is now true. Result: two
 *     TIP-IDs for one human. Breaks the one-human-one-TIP-ID invariant.
 *
 * Fix: add `_dedupCheck` cases for REGISTER_IDENTITY, REGISTER_CONTENT,
 * VP_REGISTERED, NODE_REGISTERED, INTEREST_REGISTERED, and BIND_DOMAIN.
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
const { TX_TYPES, TX_REJECTION_REASON, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { initDAG }     = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));

const registerIdentitySchema = require(path.join(SRC, "schemas", "register-identity"));
const contentRegisterSchema  = require(path.join(SRC, "schemas", "content-register"));
const interestRegisteredSchema = require(path.join(SRC, "schemas", "interest-registered"));
const { signPayload } = require(path.join(SRC, "schemas", "_common"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-reg-dedup";
const VP_ID   = "tip://vp/v1";
const AUTHOR_TIP = "tip://id/US-aabbccddeeff0011";

// ─── Fixture ────────────────────────────────────────────────────────────────
function _setup() {
  const dag    = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const vpKp   = generateMLDSAKeypair();
  const authorKp = generateMLDSAKeypair();

  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  dag.saveVP({
    vp_id: VP_ID, name: "test-vp", jurisdiction: "US",
    jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active",
    registered_at: 1767225600000,
  });
  dag.saveIdentity({
    tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey,
    root_public_key: "00", vp_id: VP_ID, verification_tier: "T1",
    founding: false, status: "active",
    registered_at: 1767225600000, tx_id: shake256("id:author"),
  });
  dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);

  const config  = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });

  return { dag, nodeKp, vpKp, authorKp, handler };
}

// ─── Signing helpers ─────────────────────────────────────────────────────────

function _signRegisterIdentity(vpKp, data) {
  const payload = registerIdentitySchema.buildSigningPayload(data);
  return registerIdentitySchema.sign(payload, vpKp.privateKey);
}

function _makeRegisterIdentityTx(dag, vpKp, data, timestamp) {
  const sig = _signRegisterIdentity(vpKp, data);
  const tx = {
    tx_type: TX_TYPES.REGISTER_IDENTITY,
    timestamp,
    prev: dag.getRecentPrev(),
    data,
    signature: sig,
  };
  tx.tx_id = computeTxId(tx);
  return tx;
}

function _signRegisterContent(authorKp, data) {
  if (!data.authors) {
    data.authors = [{ key_mode: "attribution", role: "byline", signed: false,
                       tip_id: data.signer_tip_id, tip_id_type: "personal" }];
  }
  if (!data.attribution_mode) data.attribution_mode = "self";
  if (!data.extras) data.extras = {};
  if (!data.registered_urls) data.registered_urls = [];
  if (!data.cna_version) data.cna_version = contentRegisterSchema.CURRENT_CNA_VERSION;
  const payload = contentRegisterSchema.buildSigningPayload(data, data.content_hash);
  return contentRegisterSchema.sign(payload, authorKp.privateKey);
}

function _makeRegisterContentTx(dag, authorKp, data, timestamp) {
  const sig = _signRegisterContent(authorKp, data);
  const tx = {
    tx_type: TX_TYPES.REGISTER_CONTENT,
    timestamp,
    prev: dag.getRecentPrev(),
    data,
    signature: sig,
  };
  tx.tx_id = computeTxId(tx);
  return tx;
}

function _signInterestRegistered(vpKp, data) {
  const payload = interestRegisteredSchema.buildSigningPayload(data);
  return interestRegisteredSchema.sign(payload, vpKp.privateKey);
}

function _makeInterestRegisteredTx(dag, vpKp, data, timestamp) {
  const sig = _signInterestRegistered(vpKp, data);
  const tx = {
    tx_type: TX_TYPES.INTEREST_REGISTERED,
    timestamp,
    prev: dag.getRecentPrev(),
    data,
    signature: sig,
  };
  tx.tx_id = computeTxId(tx);
  return tx;
}

function _makeVpRegisteredTx(dag, vpKp, data, timestamp) {
  const payload = {
    algorithm: data.algorithm || "ml-dsa-65",
    name: data.name,
    jurisdiction: data.jurisdiction,
    jurisdiction_tier: data.jurisdiction_tier,
    public_key: data.public_key,
    approving_vp_id: data.approving_vp_id,
  };
  const sig = signPayload(payload, vpKp.privateKey);
  const tx = {
    tx_type: TX_TYPES.VP_REGISTERED,
    timestamp,
    prev: dag.getRecentPrev(),
    data,
    signature: sig,
  };
  tx.tx_id = computeTxId(tx);
  return tx;
}

function _makeNodeRegisteredTx(dag, vpKp, data, timestamp) {
  const payload = {
    algorithm: data.algorithm || "ml-dsa-65",
    name: data.name,
    public_key: data.public_key,
    approving_vp_id: data.approving_vp_id,
  };
  const sig = signPayload(payload, vpKp.privateKey);
  const tx = {
    tx_type: TX_TYPES.NODE_REGISTERED,
    timestamp,
    prev: dag.getRecentPrev(),
    data,
    signature: sig,
  };
  tx.tx_id = computeTxId(tx);
  return tx;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("AG-7 — in-batch dedup for REGISTER_* tx types", () => {

  // ── REGISTER_IDENTITY ─────────────────────────────────────────────────────

  test("REGISTER_IDENTITY: second tx with same tip_id in batch is dropped", () => {
    const fx = _setup();
    const data = {
      tip_id: "tip://id/US-1234567890abcdef",
      region: "US",
      public_key: fx.authorKp.publicKey,
      vp_id: VP_ID,
      verification_tier: "T1",
      dedup_hash: "12345678901234567890",
      zk_proof: { pi_a: ["1"], pi_b: [["1"]], pi_c: ["1"] },
      social_attested: false,
    };

    const tx1 = _makeRegisterIdentityTx(fx.dag, fx.vpKp, data, 1777507200000);
    const tx2 = _makeRegisterIdentityTx(fx.dag, fx.vpKp, data, 1777507201000);

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(1);
    expect(fx.dag.getTxRejection(tx2.tx_id)).not.toBeNull();
    expect(fx.dag.getTxRejection(tx2.tx_id).reason_detail).toMatch(/already in this batch/i);
  });

  test("REGISTER_IDENTITY: same dedup_hash + different tip_id — second tx dropped (one-human invariant)", () => {
    // Critical: if both pass Phase 1 and reach Phase 2, _applyDerivedState's
    // dedup_hash guard skips the second write but SAVES the second identity
    // (different tip_id passes the `!dag.getIdentity` guard). Two TIP-IDs
    // for one human. The _dedupCheck fix prevents this.
    const fx = _setup();
    const SHARED_DEDUP_HASH = "99999999999999999999";
    const newKp1 = generateMLDSAKeypair();
    const newKp2 = generateMLDSAKeypair();

    const data1 = {
      tip_id: "tip://id/US-aaaaaaaabbbbbbbb",
      region: "US", public_key: newKp1.publicKey, vp_id: VP_ID,
      verification_tier: "T1", dedup_hash: SHARED_DEDUP_HASH,
      zk_proof: { pi_a: ["1"], pi_b: [["1"]], pi_c: ["1"] }, social_attested: false,
    };
    const data2 = {
      ...data1,
      tip_id: "tip://id/US-ccccccccdddddddd",   // different identity
      public_key: newKp2.publicKey,
      // same dedup_hash — same human trying to register a second TIP-ID
    };

    const tx1 = _makeRegisterIdentityTx(fx.dag, fx.vpKp, data1, 1777507200000);
    const tx2 = _makeRegisterIdentityTx(fx.dag, fx.vpKp, data2, 1777507201000);

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(1);

    // First identity registered
    expect(fx.dag.getIdentity("tip://id/US-aaaaaaaabbbbbbbb")).not.toBeNull();
    // Second identity must NOT exist — one human, one TIP-ID
    expect(fx.dag.getIdentity("tip://id/US-ccccccccdddddddd")).toBeNull();

    const rejection = fx.dag.getTxRejection(tx2.tx_id);
    expect(rejection).not.toBeNull();
    expect(rejection.reason_detail).toMatch(/dedup_hash/i);
  });

  // ── REGISTER_CONTENT ──────────────────────────────────────────────────────

  test("REGISTER_CONTENT: second tx with same ctid in batch is dropped", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-1234567890abcd-1234";
    const baseData = {
      ctid, origin_code: "OH", content_hash: shake256("content1"),
      signer_tip_id: AUTHOR_TIP,
    };
    // Each tx gets its own fresh data object so the signature covers its hash
    const data1 = { ...baseData };
    const data2 = { ...baseData, content_hash: shake256("content2") };

    const tx1 = _makeRegisterContentTx(fx.dag, fx.authorKp, data1, 1777507200000);
    const tx2 = _makeRegisterContentTx(fx.dag, fx.authorKp, data2, 1777507201000);

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 2);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(1);
    expect(fx.dag.getTxRejection(tx2.tx_id)).not.toBeNull();
    expect(fx.dag.getTxRejection(tx2.tx_id).reason_detail).toMatch(/already in this batch/i);

    // Only first content committed
    const content = fx.dag.getContent(ctid);
    expect(content).not.toBeNull();
    expect(content.content_hash).toBe(shake256("content1"));
  });

  // ── INTEREST_REGISTERED ───────────────────────────────────────────────────

  test("INTEREST_REGISTERED: second tx with same slug in batch is dropped", () => {
    const fx = _setup();
    const data1 = {
      slug: "machine-learning", label: "Machine Learning",
      category: "tech", approving_vp_id: VP_ID,
    };
    const data2 = {
      ...data1, label: "Machine Learning (Duplicate)",
    };

    const tx1 = _makeInterestRegisteredTx(fx.dag, fx.vpKp, data1, 1777507200000);
    const tx2 = _makeInterestRegisteredTx(fx.dag, fx.vpKp, data2, 1777507201000);

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 3);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(1);
    expect(fx.dag.getTxRejection(tx2.tx_id)).not.toBeNull();
    expect(fx.dag.getTxRejection(tx2.tx_id).reason_detail).toMatch(/already in this batch/i);
  });

  // ── VP_REGISTERED ─────────────────────────────────────────────────────────

  test("VP_REGISTERED: second tx with same vp_id in batch is dropped", () => {
    const fx = _setup();
    const newVpKp = generateMLDSAKeypair();
    const data = {
      vp_id: "tip://vp/new-vp",
      name: "New VP",
      jurisdiction: "US",
      jurisdiction_tier: "green",
      public_key: newVpKp.publicKey,
      approving_vp_id: VP_ID,
    };

    const tx1 = _makeVpRegisteredTx(fx.dag, fx.vpKp, data, 1777507200000);
    const tx2 = _makeVpRegisteredTx(fx.dag, fx.vpKp, data, 1777507201000);

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 4);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(1);
    expect(fx.dag.getTxRejection(tx2.tx_id)).not.toBeNull();
    expect(fx.dag.getTxRejection(tx2.tx_id).reason_detail).toMatch(/already in this batch/i);
  });

  // ── NODE_REGISTERED ───────────────────────────────────────────────────────

  test("NODE_REGISTERED: second tx with same node_id in batch is dropped", () => {
    const fx = _setup();
    const newNodeKp = generateMLDSAKeypair();
    const data = {
      node_id: "tip://node/new-node",
      name: "New Node",
      public_key: newNodeKp.publicKey,
      approving_vp_id: VP_ID,
    };

    const tx1 = _makeNodeRegisteredTx(fx.dag, fx.vpKp, data, 1777507200000);
    const tx2 = _makeNodeRegisteredTx(fx.dag, fx.vpKp, data, 1777507201000);

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 5);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(1);
    expect(fx.dag.getTxRejection(tx2.tx_id)).not.toBeNull();
    expect(fx.dag.getTxRejection(tx2.tx_id).reason_detail).toMatch(/already in this batch/i);
  });

  // ── Negative: different entities are not affected ─────────────────────────

  test("two REGISTER_IDENTITY txs for different tip_ids both commit (no false dedup)", () => {
    const fx = _setup();
    const kp1 = generateMLDSAKeypair();
    const kp2 = generateMLDSAKeypair();

    const data1 = {
      tip_id: "tip://id/US-1111111111111111",
      region: "US", public_key: kp1.publicKey, vp_id: VP_ID,
      verification_tier: "T1", dedup_hash: "11111111111111111111",
      zk_proof: { pi_a: ["1"], pi_b: [["1"]], pi_c: ["1"] }, social_attested: false,
    };
    const data2 = {
      tip_id: "tip://id/US-2222222222222222",
      region: "US", public_key: kp2.publicKey, vp_id: VP_ID,
      verification_tier: "T1", dedup_hash: "22222222222222222222",
      zk_proof: { pi_a: ["2"], pi_b: [["2"]], pi_c: ["2"] }, social_attested: false,
    };

    const tx1 = _makeRegisterIdentityTx(fx.dag, fx.vpKp, data1, 1777507200000);
    const tx2 = _makeRegisterIdentityTx(fx.dag, fx.vpKp, data2, 1777507201000);

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 6);

    expect(res.committed).toBe(2);
    expect(res.dropped).toBe(0);
    expect(fx.dag.getIdentity("tip://id/US-1111111111111111")).not.toBeNull();
    expect(fx.dag.getIdentity("tip://id/US-2222222222222222")).not.toBeNull();
  });

});
