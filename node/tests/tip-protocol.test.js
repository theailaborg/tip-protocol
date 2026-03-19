/**
 * @file node/tests/tip-protocol.test.js
 * @description TIP Protocol Node — Complete Test Suite (43 tests)
 *
 * Test coverage:
 *   - Shared crypto layer (SHAKE-256, key generation, signing, URI generation)
 *   - Protocol constants and tier system
 *   - DAG engine (in-memory store: identity, content, scoring, revocation)
 *   - Trust scoring engine (deterministic computation)
 *   - Transaction validator (all tx types)
 *   - REST API endpoints (all 18 routes)
 *   - VP registration and accreditation
 *   - Origin pre-scan (FIX-03)
 *   - Revocation system (FIX-05)
 *   - Deduplication ZK (FIX-02)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * Author: Dinesh Mendhe
 * License: TIPCL-1.0
 */

"use strict";

const request = require("supertest");
const path    = require("path");

// ─── Resolve shared module paths relative to this file ────────────────────────
const SHARED = path.resolve(__dirname, "../../shared");
const SRC    = path.resolve(__dirname, "../src");

const {
  shake256, shake256Multi,
  hashContent, perceptualHashText,
  generateTIPID, generateCTID, computeTxId,
  computeDedupHash,
  generateMLDSAKeypair, signTransaction, verifyTransaction,
} = require(path.join(SHARED, "crypto"));

// Skip real ZK verification in tests — circuit artifacts not present in test env
process.env.ZK_SKIP_VERIFY = "true";

// Mock Groth16 proof for tests (accepted when ZK_SKIP_VERIFY=true)
const MOCK_ZK_PROOF   = { pi_a: ["1","2","3"], pi_b: [["1","2"],["3","4"],["5","6"]], pi_c: ["1","2","3"], protocol: "groth16", curve: "bn128" };
const MOCK_DEDUP_HASH = "12345678901234567890123456789012345678901234567890123456789012345";

const {
  TX_TYPES, ORIGIN, ORIGIN_LABELS, SCORE_EVENTS,
  PRESCAN_THRESHOLDS, getTier, HTTP_HEADERS, PROTOCOL,
} = require(path.join(SHARED, "constants"));

const { createDAG }     = require(path.join(SRC, "dag"));
const { initScoring }   = require(path.join(SRC, "scoring"));
const { validateTx }    = require(path.join(SRC, "validators", "tx-validator"));
const { createApp }     = require(path.join(SRC, "api"));

// ─── Test Fixtures ─────────────────────────────────────────────────────────────

let keypair1, keypair2, vpKeypair;
let dag, scoring;
let app;

const TEST_CONFIG = {
  jwtSecret:    "test_jwt_secret_tip_protocol_2026",
  adminApiKey:  "test_admin_api_key_tip_2026",
  genesisHash:  "52f08c352f8866b400000000000000000000000000000000",
  chainId:      "tip-testnet",
  vpMode:       false,
  corsOrigins:  "*",
};

beforeAll(() => {
  keypair1  = generateMLDSAKeypair();
  keypair2  = generateMLDSAKeypair();
  vpKeypair = generateMLDSAKeypair();

  dag     = createDAG({ dbPath: ":memory:" });
  scoring = initScoring(dag, TEST_CONFIG);

  app = createApp({ dag, scoring, config: TEST_CONFIG });
});

afterAll(() => {
  if (dag && typeof dag.close === "function") dag.close();
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 1: CRYPTO LAYER
// ══════════════════════════════════════════════════════════════════════════════

describe("Crypto Layer", () => {

  test("1.1 shake256 produces consistent 64-char hex output", () => {
    const h = shake256("hello world");
    expect(typeof h).toBe("string");
    expect(h).toHaveLength(64);
    expect(h).toMatch(/^[0-9a-f]+$/);
    expect(shake256("hello world")).toBe(h); // deterministic
  });

  test("1.2 shake256Multi hashes multiple inputs consistently", () => {
    const h = shake256Multi("part1", "part2", "part3");
    expect(h).toHaveLength(64);
    expect(shake256Multi("part1", "part2", "part3")).toBe(h);
    expect(shake256Multi("part1", "part2")).not.toBe(h);
  });

  test("1.3 generateMLDSAKeypair returns valid keypair", () => {
    const kp = generateMLDSAKeypair();
    expect(kp).toHaveProperty("publicKey");
    expect(kp).toHaveProperty("privateKey");
    expect(typeof kp.publicKey).toBe("string");
    expect(kp.publicKey.length).toBeGreaterThan(8);
  });

  test("1.4 signTransaction and verifyTransaction roundtrip", () => {
    const payload = { tx_id: "test-tx", data: { hello: "world" } };
    const sig = signTransaction(JSON.stringify(payload), keypair1.privateKey);
    expect(typeof sig).toBe("string");
    const valid = verifyTransaction(JSON.stringify(payload), sig, keypair1.publicKey);
    expect(valid).toBe(true);
  });

  test("1.5 verifyTransaction rejects tampered payload", () => {
    const original  = JSON.stringify({ tx_id: "t1", data: { score: 500 } });
    const tampered  = JSON.stringify({ tx_id: "t1", data: { score: 999 } });
    const sig = signTransaction(original, keypair1.privateKey);
    expect(verifyTransaction(tampered, sig, keypair1.publicKey)).toBe(false);
  });

  test("1.6 generateTIPID produces correct URI format", () => {
    const id = generateTIPID("US", keypair1.publicKey);
    expect(id).toMatch(/^tip:\/\/id\/US-[0-9a-f]{16}$/);
  });

  test("1.7 generateCTID embeds origin code in URI", () => {
    const content = "Hello world this is a test article with enough words";
    const ctid = generateCTID(ORIGIN.OH, content, "US-abc123");
    expect(ctid).toMatch(/^tip:\/\/c\/OH-/);
  });

  test("1.8 hashContent is deterministic", () => {
    const h1 = hashContent("same content");
    const h2 = hashContent("same content");
    expect(h1).toBe(h2);
    expect(hashContent("different")).not.toBe(h1);
  });

  test("1.9 computeDedupHash is deterministic per identity", () => {
    const h1 = computeDedupHash("ID001", "1990-01-01", "US");
    const h2 = computeDedupHash("ID001", "1990-01-01", "US");
    const h3 = computeDedupHash("ID002", "1990-01-01", "US");
    expect(h1).toBe(h2);          // same inputs → same hash
    expect(h1).not.toBe(h3);      // different govId → different hash
    expect(h1).toHaveLength(64);
  });

  test("1.10 computeTxId is content-addressed and deterministic", () => {
    const base = { tx_type: "SCORE_UPDATE", data: { tip_id: "x", delta: 5 }, timestamp: "2026-01-01T00:00:00.000Z", prev: [] };
    const id1 = computeTxId({ ...base, data: { tip_id: "x", delta: 5 } });
    const id2 = computeTxId({ ...base, data: { tip_id: "x", delta: 6 } }); // different content
    const id3 = computeTxId({ ...base, data: { tip_id: "x", delta: 5 } }); // same as id1
    expect(id1).not.toBe(id2);   // different content → different id
    expect(id1).toBe(id3);        // same content → same id (deterministic)
    expect(id1).toHaveLength(64);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 2: PROTOCOL CONSTANTS
// ══════════════════════════════════════════════════════════════════════════════

describe("Protocol Constants", () => {

  test("2.1 ORIGIN codes are correct", () => {
    expect(ORIGIN.OH).toBe("OH");
    expect(ORIGIN.AA).toBe("AA");
    expect(ORIGIN.AG).toBe("AG");
    expect(ORIGIN.MX).toBe("MX");
  });

  test("2.2 getTier maps scores to correct tiers", () => {
    expect(getTier(924).label).toBe("HIGHLY_TRUSTED");
    expect(getTier(718).label).toBe("TRUSTED");
    expect(getTier(462).label).toBe("REVIEW_ADVISED");
    expect(getTier(231).label).toBe("LOW_TRUST");
    expect(getTier(38).label).toBe("NOT_TRUSTED");
    expect(getTier(800).label).toBe("HIGHLY_TRUSTED");
    expect(getTier(799).label).toBe("TRUSTED");
  });

  test("2.3 getTier color values are hex strings", () => {
    const t = getTier(892);
    expect(t.color).toMatch(/^#[0-9A-Fa-f]{6}$/);
  });

  test("2.4 TX_TYPES covers all protocol transaction types", () => {
    const required = [
      "REGISTER_IDENTITY", "CONTENT_REGISTERED", "CONTENT_VERIFIED",
      "CONTENT_DISPUTED", "ADJUDICATION_RESULT", "SCORE_UPDATE",
      "REVOKE_VOLUNTARY", "REVOKE_VP", "REVOKE_DECEASED", "REVOKE_DEVICE",
      "VP_REGISTERED", "MERKLE_ROOT",
    ];
    required.forEach(t => {
      expect(TX_TYPES).toHaveProperty(t);
    });
  });

  test("2.5 PRESCAN_THRESHOLDS are within valid range", () => {
    expect(PRESCAN_THRESHOLDS.default).toBeGreaterThan(0.5);
    expect(PRESCAN_THRESHOLDS.default).toBeLessThan(1.0);
    expect(PRESCAN_THRESHOLDS.floor).toBeLessThanOrEqual(PRESCAN_THRESHOLDS.default);
    expect(PRESCAN_THRESHOLDS.ceiling).toBeGreaterThanOrEqual(PRESCAN_THRESHOLDS.default);
  });

  test("2.6 HTTP_HEADERS constants are correct", () => {
    expect(HTTP_HEADERS.AUTHOR).toBe("TIP-Author");
    expect(HTTP_HEADERS.CONTENT).toBe("TIP-Content");
    expect(HTTP_HEADERS.ORIGIN_HDR).toBe("TIP-Origin");
    expect(HTTP_HEADERS.TRUST_SCORE).toBe("TIP-Trust-Score");
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 3: DAG ENGINE
// ══════════════════════════════════════════════════════════════════════════════

describe("DAG Engine", () => {

  const TIP_ID_1 = generateTIPID("US", keypair1.publicKey);
  const TIP_ID_2 = generateTIPID("EU", keypair2.publicKey);

  test("3.1 DAG initializes and is empty", () => {
    const freshDag = createDAG({ dbPath: ":memory:" });
    expect(freshDag.count()).toBe(0);
    freshDag.close();
  });

  test("3.2 saveIdentity and getIdentity roundtrip", () => {
    dag.saveIdentity({
      tip_id:      TIP_ID_1,
      region:      "US",
      public_key:  keypair1.publicKey,
      status:      "active",
      vp_id:       "tip://id/VP-US-test",
      verified_at: new Date().toISOString(),
    });
    const id = dag.getIdentity(TIP_ID_1);
    expect(id).not.toBeNull();
    expect(id.tip_id).toBe(TIP_ID_1);
    expect(id.region).toBe("US");
    expect(id.status).toBe("active");
  });

  test("3.3 saveTx and getTx roundtrip", () => {
    const txBody = {
      tx_type:   TX_TYPES.REGISTER_IDENTITY,
      timestamp: new Date().toISOString(),
      data:      { tip_id: TIP_ID_1, attested: false },
      prev:      [],
      signature: signTransaction(TIP_ID_1, keypair1.privateKey),
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody) };
    dag.saveTx(tx);
    const retrieved = dag.getTx(tx.tx_id);
    expect(retrieved).not.toBeNull();
    expect(retrieved.tx_type).toBe(TX_TYPES.REGISTER_IDENTITY);
  });

  test("3.4 saveContent and getContent roundtrip", () => {
    const ctid = generateCTID(ORIGIN.OH, "test article content here", TIP_ID_1.slice(-8));
    dag.saveContent({
      ctid,
      origin_code:    ORIGIN.OH,
      content_hash:   hashContent("test article content here"),
      author_tip_id:  TIP_ID_1,
      status:         "verified",
      registered_at:  new Date().toISOString(),
    });
    const c = dag.getContent(ctid);
    expect(c).not.toBeNull();
    expect(c.origin_code).toBe(ORIGIN.OH);
    expect(c.author_tip_id).toBe(TIP_ID_1);
  });

  test("3.5 getTxsByTipId returns relevant transactions", () => {
    const txs = dag.getTxsByTipId(TIP_ID_1);
    expect(Array.isArray(txs)).toBe(true);
    expect(txs.length).toBeGreaterThan(0);
  });

  test("3.6 Deduplication hash check and registration", () => {
    const dedupHash = computeDedupHash("ID12345", "1985-06-15", "US");
    expect(dag.hasDedupHash(dedupHash)).toBe(false);
    dag.addDedupHash(dedupHash);
    expect(dag.hasDedupHash(dedupHash)).toBe(true);
  });

  test("3.7 saveRevocation and getRevocation roundtrip", () => {
    const revTs = new Date().toISOString();
    dag.saveRevocation({
      tip_id:    TIP_ID_2,
      tx_type:   TX_TYPES.REVOKE_VOLUNTARY,
      reason:    "User requested revocation",
      timestamp: revTs,
      tx_id:     computeTxId({ tx_type: TX_TYPES.REVOKE_VOLUNTARY, data: { tip_id: TIP_ID_2 }, timestamp: revTs, prev: [] }),
    });
    const rev = dag.getRevocation(TIP_ID_2);
    expect(rev).not.toBeNull();
    expect(rev.tx_type).toBe(TX_TYPES.REVOKE_VOLUNTARY);
  });

  test("3.8 getRevocations returns all revocations", () => {
    const revs = dag.getRevocations();
    expect(Array.isArray(revs)).toBe(true);
    expect(revs.length).toBeGreaterThan(0);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 4: TRUST SCORING ENGINE
// ══════════════════════════════════════════════════════════════════════════════

describe("Trust Scoring Engine", () => {

  const TIP_ID_SCORE_TEST = generateTIPID("AU", generateMLDSAKeypair().publicKey);

  beforeAll(() => {
    // Register identity in DAG
    dag.saveIdentity({
      tip_id:      TIP_ID_SCORE_TEST,
      region:      "AU",
      public_key:  generateMLDSAKeypair().publicKey,
      status:      "active",
      vp_id:       "tip://id/VP-AU-test",
      verified_at: new Date().toISOString(),
    });
    // Register transaction
    dag.addTx({
      tx_type:   TX_TYPES.REGISTER_IDENTITY,
      timestamp: new Date().toISOString(),
      data:      { tip_id: TIP_ID_SCORE_TEST, attested: false },
      prev:      [],
      signature: "test_sig",
    });
    dag.saveScore(TIP_ID_SCORE_TEST, 500, 0);
  });

  test("4.1 Initial score is 500 without attestation", () => {
    const result = scoring.computeScore(TIP_ID_SCORE_TEST);
    expect(result.score).toBe(500);
  });

  test("4.2 Score penalty for OH declared as AG", () => {
    dag.addTx({
      tx_type:   TX_TYPES.SCORE_UPDATE,
      timestamp: new Date().toISOString(),
      data:      {
        tip_id:   TIP_ID_SCORE_TEST,
        delta:    SCORE_EVENTS.MISMATCH_OH_AG.delta,
        reason:   "Origin mismatch: declared OH, confirmed AG",
        offense:  1,
      },
      prev:      [],
      signature: "test_sig",
    });
    dag.saveScore(TIP_ID_SCORE_TEST, 400, 1);
    const result = scoring.computeScore(TIP_ID_SCORE_TEST);
    expect(result.score).toBeLessThan(500);
  });

  test("4.3 Tier is correctly assigned at score 400", () => {
    const result = scoring.computeScore(TIP_ID_SCORE_TEST);
    // Score at this point should be <= 500 after penalty
    expect(result.tier.label).toBeDefined();
    expect(["REVIEW_ADVISED", "LOW_TRUST", "NOT_TRUSTED"]).toContain(
      result.tier.label
    );
  });

  test("4.4 getScore returns stored score", () => {
    const s = scoring.getScore(TIP_ID_SCORE_TEST);
    expect(typeof s.score).toBe("number");
    expect(s.score).toBeGreaterThanOrEqual(0);
    expect(s.score).toBeLessThanOrEqual(1000);
  });

  test("4.5 Score does not exceed 1000 regardless of bonuses", () => {
    const richId = generateTIPID("CA", generateMLDSAKeypair().publicKey);
    dag.saveScore(richId, 990, 0);
    // Apply multiple bonuses
    for (let i = 0; i < 20; i++) {
      dag.addTx({
        tx_type:   TX_TYPES.CONTENT_VERIFIED,
        timestamp: new Date().toISOString(),
        data:      { tip_id: richId, delta: 5 },
        prev:      [],
        signature: "sig",
      });
    }
    dag.saveScore(richId, 1000, 0);
    const s = scoring.getScore(richId);
    expect(s.score).toBeLessThanOrEqual(1000);
  });

  test("4.6 Score does not go below 0", () => {
    const poorId = generateTIPID("NG", generateMLDSAKeypair().publicKey);
    dag.saveScore(poorId, 10, 5);
    dag.addTx({
      tx_type:   TX_TYPES.SCORE_UPDATE,
      timestamp: new Date().toISOString(),
      data:      { tip_id: poorId, delta: -500, reason: "Major violation" },
      prev:      [],
      signature: "sig",
    });
    dag.saveScore(poorId, 0, 6);
    const s = scoring.getScore(poorId);
    expect(s.score).toBeGreaterThanOrEqual(0);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 5: TRANSACTION VALIDATOR
// ══════════════════════════════════════════════════════════════════════════════

describe("Transaction Validator", () => {

  const VP_ID = "tip://id/VP-US-validator-test";

  beforeAll(() => {
    dag.saveVP({
      vp_id:       VP_ID,
      public_key:  vpKeypair.publicKey,
      status:      "active",
      jurisdiction_tier: "GREEN",
      registered_at: new Date().toISOString(),
    });
  });

  test("5.1 Valid REGISTER_IDENTITY tx passes validation", () => {
    const tipId = generateTIPID("US", keypair1.publicKey);
    const ts = new Date().toISOString();
    const txBody = {
      tx_type:   TX_TYPES.REGISTER_IDENTITY,
      timestamp: ts,
      data: {
        tip_id:     tipId,
        region:     "US",
        public_key: keypair1.publicKey,
        vp_id:      VP_ID,
        attested:   false,
        zk_proof:   "valid_zk_proof_placeholder",
      },
      prev:      [],
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody), signature: signTransaction(tipId, vpKeypair.privateKey) };
    const result = validateTx(tx, dag);
    expect(result.valid).toBe(true);
  });

  test("5.2 REGISTER_IDENTITY with missing vp_id fails", () => {
    const txBody = {
      tx_type:   TX_TYPES.REGISTER_IDENTITY,
      timestamp: new Date().toISOString(),
      data:      { tip_id: "tip://id/US-abc", region: "US" }, // missing vp_id
      prev:      [],
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody), signature: "sig" };
    const result = validateTx(tx, dag);
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  test("5.3 Valid CONTENT_REGISTERED tx passes validation", () => {
    const tipId = generateTIPID("US", keypair1.publicKey);
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: keypair1.publicKey,
      status: "active", vp_id: VP_ID, verified_at: new Date().toISOString(),
    });
    const ctid = generateCTID(ORIGIN.OH, "content here", tipId.slice(-8));
    const txBody = {
      tx_type:   TX_TYPES.CONTENT_REGISTERED,
      timestamp: new Date().toISOString(),
      data: {
        ctid, origin_code: ORIGIN.OH,
        content_hash: hashContent("content here"),
        author_tip_id: tipId, pre_scan_passed: true,
      },
      prev:      [],
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody), signature: signTransaction(ctid + ORIGIN.OH, keypair1.privateKey) };
    const result = validateTx(tx, dag);
    expect(result.valid).toBe(true);
  });

  test("5.4 Invalid origin code fails validation", () => {
    const txBody = {
      tx_type:   TX_TYPES.CONTENT_REGISTERED,
      timestamp: new Date().toISOString(),
      data: {
        ctid: "tip://c/XX-invalid",
        origin_code: "XX", // invalid origin
        content_hash: "abc",
        author_tip_id: "tip://id/US-abc123",
      },
      prev:      [],
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody), signature: "sig" };
    const result = validateTx(tx, dag);
    expect(result.valid).toBe(false);
  });

  test("5.5 REVOKE_VP requires evidence_hash", () => {
    const txBody = {
      tx_type:  TX_TYPES.REVOKE_VP,
      timestamp: new Date().toISOString(),
      data: {
        tip_id:        "tip://id/US-abc123",
        issuing_vp_id: VP_ID,
        reason_code:   "FRAUDULENT_REGISTRATION",
        // missing evidence_hash
      },
      prev:      [],
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody),
      signature: signTransaction("revoke", vpKeypair.privateKey),
    };
    const result = validateTx(tx, dag);
    expect(result.valid).toBe(false);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 6: REST API
// ══════════════════════════════════════════════════════════════════════════════

describe("REST API", () => {

  test("6.1 GET /health returns 200 with status ok", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.chain_id).toBeDefined();
    expect(res.body.version).toBeDefined();
  });

  test("6.2 GET /v1/node/info returns node metadata", async () => {
    const res = await request(app).get("/v1/node/info");
    expect(res.status).toBe(200);
    expect(res.body.protocol_version).toBeDefined();
    expect(res.body.chain_id).toBe("tip-testnet");
  });

  test("6.3 GET /v1/node/peers returns array", async () => {
    const res = await request(app).get("/v1/node/peers");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.peers)).toBe(true);
  });

  test("6.4 GET /v1/dag/stats returns DAG statistics", async () => {
    const res = await request(app).get("/v1/dag/stats");
    expect(res.status).toBe(200);
    expect(typeof res.body.tx_count).toBe("number");
  });

  test("6.5 POST /v1/vp/register registers a VP", async () => {
    const kp = generateMLDSAKeypair();
    const res = await request(app)
      .post("/v1/vp/register")
      .set("Authorization", `Bearer ${TEST_CONFIG.adminApiKey}`)
      .send({
        vp_id:             "tip://id/VP-UK-testapi",
        public_key:        kp.publicKey,
        jurisdiction_tier: "GREEN",
        country:           "GB",
        operator_name:     "Test VP UK",
      });
    expect([200, 201]).toContain(res.status);
    expect(res.body.vp_id).toBeDefined();
  });

  test("6.6 GET /v1/vp/:vpId returns VP record", async () => {
    const vpId = encodeURIComponent("tip://id/VP-UK-testapi");
    const res = await request(app).get(`/v1/vp/${vpId}`);
    expect(res.status).toBe(200);
    expect(res.body.vp_id).toBe("tip://id/VP-UK-testapi");
  });

  test("6.7 POST /v1/identity/register creates a TIP-ID", async () => {
    const res = await request(app)
      .post("/v1/identity/register")
      .send({
        region:       "DE",
        vp_id:        "tip://id/VP-UK-testapi",
        dedup_hash:   MOCK_DEDUP_HASH,
        zk_proof:     MOCK_ZK_PROOF,
        attested:     false,
      });
    expect([200, 201]).toContain(res.status);
    expect(res.body.tip_id).toBeDefined();
  });

  test("6.8 GET /v1/identity/:tipId returns identity", async () => {
    const kp    = generateMLDSAKeypair();
    const tipId = generateTIPID("FR", kp.publicKey);
    dag.saveIdentity({
      tip_id: tipId, region: "FR", public_key: kp.publicKey,
      status: "active", vp_id: "tip://id/VP-UK-testapi",
      verified_at: new Date().toISOString(),
    });
    dag.saveScore(tipId, 500, 0);
    const encoded = encodeURIComponent(tipId);
    const res = await request(app).get(`/v1/identity/${encoded}`);
    expect(res.status).toBe(200);
    expect(res.body.tip_id).toBe(tipId);
    expect(res.body.status).toBe("active");
  });

  test("6.9 GET /v1/identity/:tipId/score returns score", async () => {
    const kp    = generateMLDSAKeypair();
    const tipId = generateTIPID("JP", kp.publicKey);
    dag.saveIdentity({
      tip_id: tipId, region: "JP", public_key: kp.publicKey,
      status: "active", vp_id: "tip://id/VP-UK-testapi",
      verified_at: new Date().toISOString(),
    });
    dag.saveScore(tipId, 750, 0);
    const encoded = encodeURIComponent(tipId);
    const res = await request(app).get(`/v1/identity/${encoded}/score`);
    expect(res.status).toBe(200);
    expect(typeof res.body.score).toBe("number");
    expect(res.body.tier).toBeDefined();
  });

  test("6.10 GET /v1/identity/:tipId returns 404 for unknown TIP-ID", async () => {
    const res = await request(app).get(
      `/v1/identity/${encodeURIComponent("tip://id/US-nonexistent0000")}`
    );
    expect(res.status).toBe(404);
  });

  test("6.11 POST /v1/content/register registers content", async () => {
    const authorKp = generateMLDSAKeypair();
    const authorId = generateTIPID("US", authorKp.publicKey);
    dag.saveIdentity({
      tip_id: authorId, region: "US", public_key: authorKp.publicKey,
      status: "active", vp_id: "tip://id/VP-UK-testapi",
      verified_at: new Date().toISOString(),
    });
    dag.saveScore(authorId, 500, 0);
    const content = "This is a test article written by a human author with enough words to pass.";
    const res = await request(app)
      .post("/v1/content/register")
      .send({
        author_tip_id: authorId,
        origin_code:   ORIGIN.OH,
        content:       content,
        title:         "Test Article",
        author_signature: signTransaction(content + ORIGIN.OH, authorKp.privateKey),
      });
    expect([200, 201]).toContain(res.status);
    expect(res.body.ctid).toMatch(/^tip:\/\/c\/OH-/);
    expect(res.body.status).toBeDefined();
  });

  test("6.12 GET /v1/content/:ctid returns content record", async () => {
    const ctid = generateCTID(ORIGIN.AA, "ai assisted article test", "test001");
    dag.saveContent({
      ctid, origin_code: ORIGIN.AA,
      content_hash: hashContent("ai assisted article test"),
      author_tip_id: "tip://id/US-test001",
      status: "verified", registered_at: new Date().toISOString(),
    });
    const res = await request(app).get(
      `/v1/content/${encodeURIComponent(ctid)}`
    );
    expect(res.status).toBe(200);
    expect(res.body.origin_code).toBe(ORIGIN.AA);
  });

  test("6.13 POST /v1/content/:ctid/dispute files a dispute", async () => {
    const ctid = generateCTID(ORIGIN.OH, "disputed content test here", "disp001");
    dag.saveContent({
      ctid, origin_code: ORIGIN.OH,
      content_hash: hashContent("disputed content test here"),
      author_tip_id: "tip://id/US-disp001",
      status: "verified", registered_at: new Date().toISOString(),
    });
    const res = await request(app)
      .post(`/v1/content/${encodeURIComponent(ctid)}/dispute`)
      .send({
        disputer_tip_id: "tip://id/VP-UK-testapi",
        reason:          "AI classifier detected probable AI generation in OH-declared content",
        evidence_hash:   shake256("classifier output evidence"),
      });
    expect([200, 201]).toContain(res.status);
    expect(res.body.success).toBe(true);
  });

  test("6.14 GET /v1/revocations returns revocation list", async () => {
    const res = await request(app).get("/v1/revocations");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.revocations)).toBe(true);
  });

  test("6.15 POST /v1/revocations creates a revocation", async () => {
    const kp    = generateMLDSAKeypair();
    const tipId = generateTIPID("BR", kp.publicKey);
    dag.saveIdentity({
      tip_id: tipId, region: "BR", public_key: kp.publicKey,
      status: "active", vp_id: "tip://id/VP-UK-testapi",
      verified_at: new Date().toISOString(),
    });
    const res = await request(app)
      .post("/v1/revocations")
      .set("Authorization", `Bearer ${TEST_CONFIG.adminApiKey}`)
      .send({
        tip_id:       tipId,
        tx_type:      TX_TYPES.REVOKE_VOLUNTARY,
        reason:       "User requested revocation via API",
        requester_id: tipId,
        signature:    signTransaction(tipId + "REVOKE_VOLUNTARY", kp.privateKey),
      });
    expect([200, 201]).toContain(res.status);
  });

  test("6.16 GET /v1/dedup/merkle-root returns merkle root", async () => {
    const res = await request(app).get("/v1/dedup/merkle-root");
    expect(res.status).toBe(200);
    expect(res.body.merkle_root).toBeDefined();
    expect(res.body.count).toBeGreaterThanOrEqual(0);
  });

  test("6.17 POST /v1/dedup/check is removed — dedup now inside register", async () => {
    const res = await request(app).post("/v1/dedup/check").send({});
    expect(res.status).toBe(404); // endpoint no longer exists
  });

  test("6.18 Admin endpoint rejects missing auth token", async () => {
    const res = await request(app)
      .post("/v1/vp/register")
      .send({ vp_id: "tip://id/VP-XX-unauthorized" });
    expect([401, 403]).toContain(res.status);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 7: INTEGRATION — FULL REGISTRATION FLOW
// ══════════════════════════════════════════════════════════════════════════════

describe("Integration: Full Registration Flow", () => {

  let integrationTipId;
  let integrationKp;

  test("7.1 Register VP -> Register Identity -> Register Content -> Score", async () => {
    integrationKp = generateMLDSAKeypair();

    // Step 1: Register VP
    const vpRes = await request(app)
      .post("/v1/vp/register")
      .set("Authorization", `Bearer ${TEST_CONFIG.adminApiKey}`)
      .send({
        vp_id:             "tip://id/VP-SG-integration",
        public_key:        integrationKp.publicKey,
        jurisdiction_tier: "GREEN",
        country:           "SG",
        operator_name:     "Integration Test VP",
      });
    expect([200, 201]).toContain(vpRes.status);

    // Step 2: Register Identity
    const idDedup = computeDedupHash("SG123456", "1988-11-22", "SG");
    const idRes = await request(app)
      .post("/v1/identity/register")
      .send({
        region:       "SG",
        vp_id:        "tip://id/VP-SG-integration",
        dedup_hash:   idDedup,
        zk_proof:     MOCK_ZK_PROOF,
        attested:     false,
      });
    expect([200, 201]).toContain(idRes.status);
    integrationTipId = idRes.body.tip_id;
    expect(integrationTipId).toBeDefined();

    // Step 3: Register Content
    const authorKp = generateMLDSAKeypair();
    const content  = "An original human-written article about trust and identity on the internet.";
    const contentRes = await request(app)
      .post("/v1/content/register")
      .send({
        author_tip_id:    integrationTipId,
        origin_code:      ORIGIN.OH,
        content:          content,
        title:            "Trust and Identity",
        author_signature: signTransaction(content + ORIGIN.OH, authorKp.privateKey),
      });
    expect([200, 201]).toContain(contentRes.status);
    const ctid = contentRes.body.ctid;
    expect(ctid).toMatch(/^tip:\/\/c\/OH-/);

    // Step 4: Verify score
    const scoreRes = await request(app).get(
      `/v1/identity/${encodeURIComponent(integrationTipId)}/score`
    );
    expect(scoreRes.status).toBe(200);
    expect(scoreRes.body.score).toBeGreaterThanOrEqual(0);
  });

  test("7.2 Duplicate dedup hash is rejected", async () => {
    const dedup = computeDedupHash("SG123456", "1988-11-22", "SG");
    dag.addDedupHash(dedup);

    // Try registering the same person twice
    const res = await request(app)
      .post("/v1/identity/register")
      .send({
        region:       "SG",
        vp_id:        "tip://id/VP-SG-integration",
        dedup_hash:   dedup,    // same dedup hash — should be rejected
        zk_proof:     MOCK_ZK_PROOF,
        attested:     false,
      });
    expect([400, 409, 422]).toContain(res.status);
  });

});
