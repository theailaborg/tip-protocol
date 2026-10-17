/**
 * @file tests/consensus/commit-handler-biometric-commit.test.js
 * @description Guards the commit-handler REGISTER_IDENTITY persistence line
 * for `biometric_commit` (identity-biometric-commit plan, Task 5).
 *
 * Routes a REAL, VP-signed REGISTER_IDENTITY tx through
 * `commitHandler.commitOrderedTxs` (the actual consensus-replay path — not
 * a direct `dag.saveIdentity` call, which would only exercise the Task 3
 * store path). This is sensitive to the
 * `biometric_commit: d.biometric_commit || null` line in
 * `_applyDerivedState`'s REGISTER_IDENTITY case: reverting that line makes
 * both tests below fail (verified via mutation testing — see PR notes).
 *
 * Mirrors the tx-construction + commit-invocation pattern established in
 * commit-handler-register-dedup.test.js (`_setup`, `_signRegisterIdentity`,
 * `_makeRegisterIdentityTx`).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC    = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, computeTxId,
} = require(path.join(SHARED, "crypto"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { initDAG }     = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));

const registerIdentitySchema = require(path.join(SRC, "schemas", "register-identity"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-biom-commit";
const VP_ID   = "tip://vp/v-biom-commit";

// ─── Fixture (mirrors commit-handler-register-dedup.test.js's _setup) ──────
function _setup() {
  const dag    = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const vpKp   = generateMLDSAKeypair();

  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  dag.saveVP({
    vp_id: VP_ID, name: "test-vp", jurisdiction: "US",
    jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active",
    registered_at: 1767225600000,
  });

  const config  = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });

  return { dag, nodeKp, vpKp, handler };
}

// ─── Signing helpers (identical pattern to commit-handler-register-dedup) ──

function _signRegisterIdentity(vpKp, data) {
  const payload = registerIdentitySchema.buildSigningPayload(data);
  return registerIdentitySchema.sign(payload, vpKp.privateKey);
}

function _makeRegisterIdentityTx(dag, vpKp, data, timestamp) {
  const sig = _signRegisterIdentity(vpKp, data);
  const tx = {
    tx_type: TX_TYPES.REGISTER_IDENTITY,
    timestamp,
    prev: [],
    data,
    signature: sig,
  };
  tx.prev = dag.prevFor(tx.tx_type, tx.data);
  tx.tx_id = computeTxId(tx);
  return tx;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("commit-handler REGISTER_IDENTITY — biometric_commit persistence", () => {

  test("committed tx carrying biometric_commit persists it onto the identity row", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const commit = "f".repeat(64);
    const data = {
      tip_id: "tip://id/US-aabbccddee001122",
      region: "US",
      public_key: kp.publicKey,
      vp_id: VP_ID,
      verification_tier: "T1",
      dedup_hash: "10000000000000000001",
      zk_proof: { pi_a: ["1"], pi_b: [["1"]], pi_c: ["1"] },
      biometric_commit: commit,
    };

    const tx = _makeRegisterIdentityTx(fx.dag, fx.vpKp, data, 1777507200000);
    const res = fx.handler.commitOrderedTxs([tx], 1);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(0);
    const identity = fx.dag.getIdentity(data.tip_id);
    expect(identity).not.toBeNull();
    // Guards commit-handler.js's `biometric_commit: d.biometric_commit || null`
    // line in _applyDerivedState's REGISTER_IDENTITY case — reverting that
    // line makes this assertion fail (identity.biometric_commit would be
    // undefined/null instead of the committed hex).
    expect(identity.biometric_commit).toBe(commit);
  });

  test("committed tx WITHOUT biometric_commit leaves the identity row's biometric_commit null (strip-rule round-trip)", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const data = {
      tip_id: "tip://id/US-aabbccddee003344",
      region: "US",
      public_key: kp.publicKey,
      vp_id: VP_ID,
      verification_tier: "T1",
      dedup_hash: "10000000000000000002",
      zk_proof: { pi_a: ["1"], pi_b: [["1"]], pi_c: ["1"] },
      // biometric_commit intentionally absent — canonical payload strips it.
    };

    const tx = _makeRegisterIdentityTx(fx.dag, fx.vpKp, data, 1777507201000);
    const res = fx.handler.commitOrderedTxs([tx], 2);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(0);
    const identity = fx.dag.getIdentity(data.tip_id);
    expect(identity).not.toBeNull();
    expect(identity.biometric_commit).toBeNull();
  });

});
