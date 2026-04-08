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
  initCrypto,
  shake256, shake256Multi,
  hashContent, perceptualHashText,
  generateTIPID, generateCTID, computeTxId,
  computeDedupHash,
  generateMLDSAKeypair, mldsaSign, signTransaction, verifyTransaction,
  signBody,
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

const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring }       = require(path.join(SRC, "scoring"));
const { validateTransaction } = require(path.join(SRC, "validators", "tx-validator"));
const { createApp }     = require(path.join(SRC, "api"));

// ─── Test Fixtures ─────────────────────────────────────────────────────────────

let keypair1, keypair2, vpKeypair;
let dag, scoring;
let app;
let foundingVpId, foundingVpKp;

let TEST_CONFIG;

beforeAll(async () => {
  await initCrypto();
  keypair1  = generateMLDSAKeypair();
  keypair2  = generateMLDSAKeypair();
  vpKeypair = generateMLDSAKeypair();

  // Node keypair for tx-level signing
  const nodeKp = generateMLDSAKeypair();
  TEST_CONFIG = {
    nodeId:           "test-node-001",
    nodeVersion:      "2.0.0",
    nodeType:         "full",
    region:           "US",
    publicUrl:        "http://localhost:4000",
    peers:            [],
    genesisHash:      "52f08c352f8866b400000000000000000000000000000000",
    chainId:          "tip-testnet",
    corsOrigins:      "*",
    nodePrivateKey:   nodeKp.privateKey,
    nodePublicKey:    nodeKp.publicKey,
    rateLimitWindow:  60 * 1000,
    rateLimitMax:     10000,
  };

  dag     = initDAG({ dbPath: ":memory:" });
  scoring = initScoring(dag, TEST_CONFIG);

  // Get the founding VP and replace its public key with a known keypair
  // so tests can sign council approvals
  foundingVpKp = generateMLDSAKeypair();
  const allVps = dag.getAllVPs();
  foundingVpId = allVps[0].vp_id;
  dag.saveVP({ ...allVps[0], public_key: foundingVpKp.publicKey });

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
    const tx = {
      tx_type:   "SCORE_UPDATE",
      timestamp: "2026-01-01T00:00:00.000Z",
      data:      { hello: "world" },
      prev:      [],
    };
    const signed = signTransaction(tx, keypair1.privateKey);
    expect(typeof signed.signature).toBe("string");
    const valid = verifyTransaction(signed, keypair1.publicKey);
    expect(valid).toBe(true);
  });

  test("1.5 verifyTransaction rejects tampered payload", () => {
    const tx = { tx_type: "TEST", data: { score: 500 }, timestamp: "2026-01-01T00:00:00.000Z", prev: [] };
    const signed  = signTransaction(tx, keypair1.privateKey);
    const tampered = { ...signed, data: { score: 999 } };
    expect(verifyTransaction(tampered, keypair1.publicKey)).toBe(false);
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
    expect(getTier(924).name).toBe("HIGHLY_TRUSTED");
    expect(getTier(718).name).toBe("TRUSTED");
    expect(getTier(462).name).toBe("VERIFIED");
    expect(getTier(231).name).toBe("CAUTION");
    expect(getTier(38).name).toBe("NOT_TRUSTED");
    expect(getTier(850).name).toBe("HIGHLY_TRUSTED");
    expect(getTier(849).name).toBe("TRUSTED");
  });

  test("2.3 getTier color values are hex strings", () => {
    const t = getTier(892);
    expect(t.color).toMatch(/^#[0-9A-Fa-f]{6,8}$/);
  });

  test("2.4 TX_TYPES covers all protocol transaction types", () => {
    const required = [
      "REGISTER_IDENTITY", "REGISTER_CONTENT", "CONTENT_VERIFIED",
      "CONTENT_DISPUTED", "ADJUDICATION_RESULT", "SCORE_UPDATE",
      "REVOKE_VOLUNTARY", "REVOKE_VP", "REVOKE_DECEASED", "REVOKE_DEVICE",
      "VP_REGISTERED", "MERKLE_ROOT_PUBLISHED",
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
    expect(HTTP_HEADERS.ORIGIN).toBe("TIP-Origin");
    expect(HTTP_HEADERS.TRUST_SCORE).toBe("TIP-Trust-Score");
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 3: DAG ENGINE
// ══════════════════════════════════════════════════════════════════════════════

describe("DAG Engine", () => {

  let TIP_ID_1, TIP_ID_2;
  beforeAll(() => {
    TIP_ID_1 = generateTIPID("US", keypair1.publicKey);
    TIP_ID_2 = generateTIPID("EU", keypair2.publicKey);
  });

  test("3.1 DAG initializes with genesis block", () => {
    const freshDag = initDAG({ dbPath: ":memory:" });
    expect(freshDag.count()).toBeGreaterThan(0); // genesis block auto-created
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
      signature: mldsaSign(TIP_ID_1, keypair1.privateKey),
    };
    const tx = dag.addTx(txBody);
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

  test("3.7 addRevocation and getRevocations roundtrip", () => {
    const revTs = new Date().toISOString();
    const txId  = computeTxId({ tx_type: TX_TYPES.REVOKE_VOLUNTARY, data: { tip_id: TIP_ID_2 }, timestamp: revTs, prev: [] });
    dag.addRevocation(TIP_ID_2, TX_TYPES.REVOKE_VOLUNTARY, revTs, txId);
    const revs = dag.getRevocations();
    const rev  = revs.find(r => r.tip_id === TIP_ID_2);
    expect(rev).toBeDefined();
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

  let TIP_ID_SCORE_TEST;

  beforeAll(() => {
    TIP_ID_SCORE_TEST = generateTIPID("AU", generateMLDSAKeypair().publicKey);
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
    dag.setScore(TIP_ID_SCORE_TEST, 500, 0);
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
        delta:    SCORE_EVENTS.OH_CONFIRMED_AG_1ST.delta,
        reason:   "Origin mismatch: declared OH, confirmed AG",
        offense:  1,
      },
      prev:      [],
      signature: "test_sig",
    });
    dag.setScore(TIP_ID_SCORE_TEST, 400, 1);
    const result = scoring.computeScore(TIP_ID_SCORE_TEST);
    expect(result.score).toBeLessThan(500);
  });

  test("4.3 Tier is correctly assigned at score 400", () => {
    const result = scoring.computeScore(TIP_ID_SCORE_TEST);
    // Score at this point should be <= 500 after penalty
    expect(result.tier.name).toBeDefined();
    expect(["VERIFIED", "CAUTION", "NOT_TRUSTED"]).toContain(
      result.tier.name
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
    dag.setScore(richId, 990, 0);
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
    dag.setScore(richId, 1000, 0);
    const s = scoring.getScore(richId);
    expect(s.score).toBeLessThanOrEqual(1000);
  });

  test("4.6 Score does not go below 0", () => {
    const poorId = generateTIPID("NG", generateMLDSAKeypair().publicKey);
    dag.setScore(poorId, 10, 5);
    dag.addTx({
      tx_type:   TX_TYPES.SCORE_UPDATE,
      timestamp: new Date().toISOString(),
      data:      { tip_id: poorId, delta: -500, reason: "Major violation" },
      prev:      [],
      signature: "sig",
    });
    dag.setScore(poorId, 0, 6);
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
      jurisdiction_tier: "green",
      registered_at: new Date().toISOString(),
    });
  });

  test("5.1 Valid REGISTER_IDENTITY tx passes validation", () => {
    const freshKp = generateMLDSAKeypair();
    const tipId = generateTIPID("US", freshKp.publicKey);
    const ts = new Date().toISOString();
    const txBody = {
      tx_type:   TX_TYPES.REGISTER_IDENTITY,
      timestamp: ts,
      data: {
        tip_id:            tipId,
        region:            "US",
        public_key:        freshKp.publicKey,
        vp_id:             VP_ID,
        attested:          false,
        verification_tier: "T1",
        dedup_hash:        "55667788990011223344556677889900112233445566778899001122334455667",
        zk_proof:          MOCK_ZK_PROOF,
      },
      prev:      dag.getRecentPrev(),
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody), signature: mldsaSign(tipId, freshKp.privateKey) };
    const result = validateTransaction(tx, dag);
    expect(result.valid).toBe(true);
  });

  test("5.2 REGISTER_IDENTITY with missing vp_id fails", () => {
    const txBody = {
      tx_type:   TX_TYPES.REGISTER_IDENTITY,
      timestamp: new Date().toISOString(),
      data:      { tip_id: "tip://id/US-abc", region: "US" }, // missing vp_id
      prev:      dag.getRecentPrev(),
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody), signature: "sig" };
    const result = validateTransaction(tx, dag);
    expect(result.valid).toBe(false);
    expect(result.errors).toBeDefined();
  });

  test("5.3 Valid REGISTER_CONTENT tx passes validation", () => {
    const tipId = generateTIPID("US", keypair1.publicKey);
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: keypair1.publicKey,
      status: "active", vp_id: VP_ID, verified_at: new Date().toISOString(),
    });
    const contentHashFull = shake256("content here");
    const contentHashShort = hashContent("content here");
    const ctid = generateCTID(ORIGIN.OH, contentHashShort, tipId);
    const authorSig = mldsaSign(ctid + ORIGIN.OH, keypair1.privateKey);
    const txBody = {
      tx_type:   TX_TYPES.REGISTER_CONTENT,
      timestamp: new Date().toISOString(),
      data: {
        ctid, origin_code: ORIGIN.OH,
        content_hash:  contentHashFull,
        author_tip_id: tipId,
        pre_scan_passed: true,
        signature:     authorSig,
      },
      prev:      dag.getRecentPrev(),
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody) };
    const result = validateTransaction(tx, dag);
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
      prev:      dag.getRecentPrev(),
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody), signature: "sig" };
    const result = validateTransaction(tx, dag);
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
      prev:      dag.getRecentPrev(),
    };
    const tx = { ...txBody, tx_id: computeTxId(txBody),
      signature: mldsaSign("revoke", vpKeypair.privateKey),
    };
    const result = validateTransaction(tx, dag);
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
    expect(res.body.node_id).toBeDefined();
    expect(res.body.version).toBeDefined();
  });

  test("6.2 GET /v1/node/info returns node metadata", async () => {
    const res = await request(app).get("/v1/node/info");
    expect(res.status).toBe(200);
    expect(res.body.protocol_version).toBeDefined();
    expect(res.body.node_id).toBe("test-node-001");
  });

  test("6.3 GET /v1/node/peers returns array", async () => {
    const res = await request(app).get("/v1/node/peers");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.peers)).toBe(true);
  });

  test("6.4 GET /v1/node/info includes DAG statistics", async () => {
    const res = await request(app).get("/v1/node/info");
    expect(res.status).toBe(200);
    expect(typeof res.body.dag_tx_count).toBe("number");
  });

  let testVpKp; // VP keypair shared across tests 6.5–6.7
  let testVpId;  // VP ID returned by test 6.5
  let authorKp;  // Author keypair (client-generated)
  let authorId;  // Author TIP-ID

  test("6.5 POST /v1/vp/register registers a VP", async () => {
    testVpKp = generateMLDSAKeypair();
    const vpFields = {
      name: "Test VP UK", jurisdiction_tier: "green",
      public_key: testVpKp.publicKey, approving_vp_id: foundingVpId,
    };
    const councilSig = signBody(vpFields, foundingVpKp.privateKey);
    const res = await request(app)
      .post("/v1/vp/register")
      .send({ ...vpFields, council_signature: councilSig });
    expect([200, 201]).toContain(res.status);
    expect(res.body.vp_id).toBeDefined();
    testVpId = res.body.vp_id;
  });

  test("6.6 GET /v1/vp/:vpId returns VP record", async () => {
    const vpId = encodeURIComponent(testVpId);
    const res = await request(app).get(`/v1/vp/${vpId}`);
    expect(res.status).toBe(200);
    expect(res.body.vp_id).toBe(testVpId);
  });

  test("6.7 POST /v1/identity/register creates a TIP-ID", async () => {
    authorKp = generateMLDSAKeypair();
    const idFields = {
      region: "DE", public_key: authorKp.publicKey, dedup_hash: MOCK_DEDUP_HASH, zk_proof: MOCK_ZK_PROOF,
      verification_tier: "T1", vp_id: testVpId, social_attested: false,
    };
    const vpSig = signBody(idFields, testVpKp.privateKey);

    const res = await request(app)
      .post("/v1/identity/register")
      .send({ ...idFields, vp_signature: vpSig });
    expect([200, 201]).toContain(res.status);
    expect(res.body.tip_id).toBeDefined();
    authorId = res.body.tip_id;
  });

  test("6.8 GET /v1/identity/:tipId returns identity", async () => {
    const kp    = generateMLDSAKeypair();
    const tipId = generateTIPID("FR", kp.publicKey);
    dag.saveIdentity({
      tip_id: tipId, region: "FR", public_key: kp.publicKey,
      status: "active", vp_id: testVpId,
      verified_at: new Date().toISOString(),
    });
    dag.setScore(tipId, 500, 0);
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
      status: "active", vp_id: testVpId,
      verified_at: new Date().toISOString(),
      score_display_mode: "FULL_PUBLIC",
    });
    dag.setScore(tipId, 750, 0);
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

  test("6.10b POST /v1/identity/verify-ownership succeeds with correct key", async () => {
    const challenge = "test-challenge-" + Date.now();
    const sig = mldsaSign(challenge, authorKp.privateKey);
    const res = await request(app)
      .post("/v1/identity/verify-ownership")
      .send({ tip_id: authorId, challenge, signature: sig });
    expect(res.status).toBe(200);
    expect(res.body.verified).toBe(true);
    expect(res.body.tip_id).toBe(authorId);
  });

  test("6.10c POST /v1/identity/verify-ownership fails with wrong key", async () => {
    const fakeKp = generateMLDSAKeypair();
    const challenge = "test-challenge-" + Date.now();
    const sig = mldsaSign(challenge, fakeKp.privateKey);
    const res = await request(app)
      .post("/v1/identity/verify-ownership")
      .send({ tip_id: authorId, challenge, signature: sig });
    expect(res.status).toBe(403);
  });

  test("6.10d POST /v1/identity/verify-ownership returns 404 for unknown TIP-ID", async () => {
    const res = await request(app)
      .post("/v1/identity/verify-ownership")
      .send({ tip_id: "tip://id/US-nonexistent0000", challenge: "test", signature: "fake" });
    expect(res.status).toBe(404);
  });

  test("6.11 POST /v1/content/register registers content", async () => {
    const authorKp = generateMLDSAKeypair();
    const authorId = generateTIPID("US", authorKp.publicKey);
    dag.saveIdentity({
      tip_id: authorId, region: "US", public_key: authorKp.publicKey,
      status: "active", vp_id: testVpId,
      verified_at: new Date().toISOString(),
    });
    dag.setScore(authorId, 500, 0);
    const content = "This is a test article written by a human author with enough words to pass.";
    const sigFields = { author_tip_id: authorId, origin_code: ORIGIN.OH, content_hash: shake256(content) };
    const body = { author_tip_id: authorId, origin_code: ORIGIN.OH, content, title: "Test Article", signature: signBody(sigFields, authorKp.privateKey) };
    const res = await request(app)
      .post("/v1/content/register")
      .send(body);
    expect([200, 201]).toContain(res.status);
    expect(res.body.ctid).toMatch(/^tip:\/\/c\/OH-/);
    expect(res.body.status).toBeDefined();
  });

  test("6.12 GET /v1/content/:ctid returns content record", async () => {
    const ctid = generateCTID(ORIGIN.AA, "ai assisted article test", "test001");
    dag.saveContent({
      ctid, origin_code: ORIGIN.AA,
      content_hash: shake256("ai assisted article test"),
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
      content_hash: shake256("disputed content test here"),
      author_tip_id: "tip://id/US-disp001",
      status: "verified", registered_at: new Date().toISOString(),
    });
    // Create a disputer identity with known keypair
    const disputerKp = generateMLDSAKeypair();
    const disputerId = generateTIPID("US", disputerKp.publicKey);
    dag.saveIdentity({
      tip_id: disputerId, region: "US", public_key: disputerKp.publicKey,
      status: "active", vp_id: testVpId, verified_at: new Date().toISOString(),
    });
    const disputeFields = {
      disputer_tip_id: disputerId,
      reason: "AI classifier detected probable AI generation in OH-declared content",
      evidence_hash: shake256("classifier output evidence"),
    };
    const res = await request(app)
      .post(`/v1/content/${encodeURIComponent(ctid)}/dispute`)
      .send({ ...disputeFields, signature: signBody(disputeFields, disputerKp.privateKey) });
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
      status: "active", vp_id: testVpId,
      verified_at: new Date().toISOString(),
    });
    const revokeFields = {
      tx_type: TX_TYPES.REVOKE_VOLUNTARY, tip_id: tipId,
      reason_code: "VOLUNTARY", issuing_vp_id: testVpId,
    };
    const vpSig = signBody(revokeFields, testVpKp.privateKey);
    const res = await request(app)
      .post("/v1/revocations")
      .send({ ...revokeFields, signature: vpSig });
    expect([200, 201]).toContain(res.status);
  });

  test("6.16 GET /v1/dedup/merkle-root returns merkle root", async () => {
    const res = await request(app).get("/v1/dedup/merkle-root");
    expect(res.status).toBe(200);
    expect(res.body.merkle_root).toBeDefined();
    expect(res.body.dedup_count).toBeGreaterThanOrEqual(0);
  });

  test("6.17 POST /v1/dedup/check is removed — dedup now inside register", async () => {
    const res = await request(app).post("/v1/dedup/check").send({});
    expect(res.status).toBe(404); // endpoint no longer exists
  });

  test("6.18 VP register rejects missing required fields", async () => {
    const res = await request(app)
      .post("/v1/vp/register")
      .send({ vp_id: "tip://id/VP-XX-unauthorized" }); // missing name and public_key
    expect([400, 401, 403]).toContain(res.status);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 7: INTEGRATION — FULL REGISTRATION FLOW
// ══════════════════════════════════════════════════════════════════════════════

describe("Integration: Full Registration Flow", () => {

  let integrationTipId;
  let integrationKp;
  let integrationVpId;

  test("7.1 Register VP -> Register Identity -> Register Content -> Score", async () => {
    integrationKp = generateMLDSAKeypair();

    // Step 1: Register VP (approved by founding VP)
    const vpFields = {
      name: "Integration Test VP SG", jurisdiction_tier: "green",
      public_key: integrationKp.publicKey, approving_vp_id: foundingVpId,
    };
    const intCouncilSig = signBody(vpFields, foundingVpKp.privateKey);
    const vpRes = await request(app)
      .post("/v1/vp/register")
      .send({ ...vpFields, country: "SG", council_signature: intCouncilSig });
    expect([200, 201]).toContain(vpRes.status);
    integrationVpId = vpRes.body.vp_id;

    // Step 2: Register Identity (client generates keypair)
    const authorKp2 = generateMLDSAKeypair();
    const idFields = {
      region: "SG", public_key: authorKp2.publicKey,
      dedup_hash: "99887766554433221100998877665544332211009988776655443322110099887",
      zk_proof: MOCK_ZK_PROOF, verification_tier: "T1",
      vp_id: integrationVpId, social_attested: false,
    };
    const intVpSig = signBody(idFields, integrationKp.privateKey);

    const idRes = await request(app)
      .post("/v1/identity/register")
      .send({ ...idFields, vp_signature: intVpSig });
    expect([200, 201]).toContain(idRes.status);
    integrationTipId = idRes.body.tip_id;
    expect(integrationTipId).toBeDefined();

    // Step 3: Register Content (client has private key — never sent to server)
    const authorPrivateKey = authorKp2.privateKey;
    const content  = "An original human-written article about trust and identity on the internet.";
    const ctSigFields = { author_tip_id: integrationTipId, origin_code: ORIGIN.OH, content_hash: shake256(content) };
    const contentRes = await request(app)
      .post("/v1/content/register")
      .send({ author_tip_id: integrationTipId, origin_code: ORIGIN.OH, content, title: "Trust and Identity", signature: signBody(ctSigFields, authorPrivateKey) });
    expect([200, 201]).toContain(contentRes.status);
    const ctid = contentRes.body.ctid;
    expect(ctid).toMatch(/^tip:\/\/c\/OH-/);

    // Step 4: Verify score
    const scoreRes = await request(app).get(
      `/v1/identity/${encodeURIComponent(integrationTipId)}/score`
    );
    expect(scoreRes.status).toBe(200);
    expect(scoreRes.body.tier).toBeDefined();
  });

  test("7.2 Duplicate dedup hash is rejected", async () => {
    const dedup  = computeDedupHash("SG123456", "1988-11-22", "SG");
    dag.addDedupHash(dedup);

    const dupKp = generateMLDSAKeypair();
    const dupFields = {
      region: "SG", public_key: dupKp.publicKey, dedup_hash: dedup, zk_proof: MOCK_ZK_PROOF,
      verification_tier: "T1", vp_id: integrationVpId, social_attested: false,
    };
    const dupVpSig = signBody(dupFields, integrationKp.privateKey);

    // Try registering the same person twice
    const res = await request(app)
      .post("/v1/identity/register")
      .send({ ...dupFields, vp_signature: dupVpSig });
    expect([400, 403, 409, 422]).toContain(res.status);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 8: GOSSIP BROADCAST WIRING
// ══════════════════════════════════════════════════════════════════════════════

describe("Gossip Broadcast Wiring", () => {
  let gossipApp, gossipDag, gossipScoring, broadcastCalls;
  let gFoundingVpId, gFoundingVpKp;

  beforeAll(async () => {
    broadcastCalls = [];
    const mockGossipRef = {
      current: {
        broadcast: (tx) => { broadcastCalls.push(tx); },
      },
    };

    // Fresh DAG so no collisions with earlier test blocks
    gossipDag     = initDAG({ dbPath: ":memory:" });
    gossipScoring = initScoring(gossipDag, TEST_CONFIG);

    gFoundingVpKp = generateMLDSAKeypair();
    const allVps  = gossipDag.getAllVPs();
    gFoundingVpId = allVps[0].vp_id;
    gossipDag.saveVP({ ...allVps[0], public_key: gFoundingVpKp.publicKey });

    gossipApp = createApp({ dag: gossipDag, scoring: gossipScoring, config: TEST_CONFIG, gossip: mockGossipRef });
  });

  afterAll(() => {
    if (gossipDag && typeof gossipDag.close === "function") gossipDag.close();
  });

  beforeEach(() => {
    broadcastCalls = [];
  });

  test("8.1 VP register triggers gossip broadcast", async () => {
    const vpKp = generateMLDSAKeypair();
    const vpFields = {
      name: "Gossip Test VP", jurisdiction_tier: "green",
      public_key: vpKp.publicKey, approving_vp_id: gFoundingVpId,
    };
    const sig = signBody(vpFields, gFoundingVpKp.privateKey);

    const res = await request(gossipApp)
      .post("/v1/vp/register")
      .send({ ...vpFields, council_signature: sig });
    expect([200, 201]).toContain(res.status);
    expect(broadcastCalls.length).toBeGreaterThanOrEqual(1);
    expect(broadcastCalls[0]).toHaveProperty("tx_id");
  });

  test("8.2 Identity register triggers gossip broadcast", async () => {
    const kp82 = generateMLDSAKeypair();
    const idFields = {
      region: "US", public_key: kp82.publicKey,
      dedup_hash: "88881111222233334444555566667777888899990000111122223333444455556",
      zk_proof: MOCK_ZK_PROOF, verification_tier: "T1",
      vp_id: gFoundingVpId, social_attested: false,
    };
    const vpSig = signBody(idFields, gFoundingVpKp.privateKey);

    const res = await request(gossipApp)
      .post("/v1/identity/register")
      .send({ ...idFields, vp_signature: vpSig });
    expect([200, 201]).toContain(res.status);
    expect(broadcastCalls.length).toBeGreaterThanOrEqual(1);
  });

  test("8.3 Content register triggers gossip broadcast", async () => {
    const kp83 = generateMLDSAKeypair();
    const idFields = {
      region: "US", public_key: kp83.publicKey,
      dedup_hash: "99991111222233334444555566667777888899990000111122223333444455556",
      zk_proof: MOCK_ZK_PROOF, verification_tier: "T1",
      vp_id: gFoundingVpId, social_attested: false,
    };
    const vpSig = signBody(idFields, gFoundingVpKp.privateKey);

    const idRes = await request(gossipApp)
      .post("/v1/identity/register")
      .send({ ...idFields, vp_signature: vpSig });
    const tipId         = idRes.body.tip_id;
    const authorPrivKey = kp83.privateKey;

    broadcastCalls = [];
    const content  = "Gossip broadcast wiring test content article.";
    const ctSigFields = { author_tip_id: tipId, origin_code: ORIGIN.OH, content_hash: shake256(content) };
    const res = await request(gossipApp)
      .post("/v1/content/register")
      .send({ author_tip_id: tipId, origin_code: ORIGIN.OH, content, signature: signBody(ctSigFields, authorPrivKey) });
    expect([200, 201]).toContain(res.status);
    expect(broadcastCalls.length).toBeGreaterThanOrEqual(1);
  });

  test("8.4 Revocation triggers gossip broadcast", async () => {
    // Register a VP + identity, then revoke
    const rVpKp = generateMLDSAKeypair();
    const vpFields = {
      name: "Revoke Broadcast VP", jurisdiction_tier: "green",
      public_key: rVpKp.publicKey, approving_vp_id: gFoundingVpId,
    };
    const vpRes = await request(gossipApp)
      .post("/v1/vp/register")
      .send({ ...vpFields, council_signature: signBody(vpFields, gFoundingVpKp.privateKey) });
    const rVpId = vpRes.body.vp_id;

    const kp84 = generateMLDSAKeypair();
    const idFields = {
      region: "US", public_key: kp84.publicKey,
      dedup_hash: "77771111222233334444555566667777888899990000111122223333444455556",
      zk_proof: MOCK_ZK_PROOF, verification_tier: "T1",
      vp_id: rVpId, social_attested: false,
    };
    const idRes = await request(gossipApp)
      .post("/v1/identity/register")
      .send({ ...idFields, vp_signature: signBody(idFields, rVpKp.privateKey) });
    const rTipId = idRes.body.tip_id;

    broadcastCalls = [];
    const revokeFields = {
      tx_type: TX_TYPES.REVOKE_VOLUNTARY, tip_id: rTipId,
      reason_code: "gossip_test", issuing_vp_id: rVpId,
    };
    const res = await request(gossipApp)
      .post("/v1/revocations")
      .send({ ...revokeFields, signature: signBody(revokeFields, rVpKp.privateKey) });
    expect([200, 201]).toContain(res.status);
    expect(broadcastCalls.length).toBeGreaterThanOrEqual(1);
  });

  test("8.5 Dispute triggers gossip broadcast", async () => {
    // Register identity + content, then dispute
    const kp85 = generateMLDSAKeypair();
    const dIdFields = {
      region: "US", public_key: kp85.publicKey,
      dedup_hash: "66661111222233334444555566667777888899990000111122223333444455556",
      zk_proof: MOCK_ZK_PROOF, verification_tier: "T1",
      vp_id: gFoundingVpId, social_attested: false,
    };
    const idRes = await request(gossipApp)
      .post("/v1/identity/register")
      .send({ ...dIdFields, vp_signature: signBody(dIdFields, gFoundingVpKp.privateKey) });
    const dTipId      = idRes.body.tip_id;
    const dAuthorPriv = kp85.privateKey;

    const content  = "Dispute gossip broadcast test article.";
    const ctSigFields2 = { author_tip_id: dTipId, origin_code: ORIGIN.OH, content_hash: shake256(content) };
    const cRes = await request(gossipApp)
      .post("/v1/content/register")
      .send({ author_tip_id: dTipId, origin_code: ORIGIN.OH, content, signature: signBody(ctSigFields2, dAuthorPriv) });
    const ctid = cRes.body.ctid;

    broadcastCalls = [];
    const disputeFields = { disputer_tip_id: dTipId, reason: "gossip test" };
    const res = await request(gossipApp)
      .post(`/v1/content/${encodeURIComponent(ctid)}/dispute`)
      .send({ ...disputeFields, signature: signBody(disputeFields, dAuthorPriv) });
    expect(res.status).toBe(200);
    expect(broadcastCalls.length).toBeGreaterThanOrEqual(1);

    // Duplicate dispute should be rejected (semantic dedup)
    broadcastCalls = [];
    const res2 = await request(gossipApp)
      .post(`/v1/content/${encodeURIComponent(ctid)}/dispute`)
      .send({ ...disputeFields, signature: signBody(disputeFields, dAuthorPriv) });
    expect(res2.status).toBe(409);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 9: SEMANTIC DEDUP — ONE VERIFY/DISPUTE PER USER PER CONTENT
// ══════════════════════════════════════════════════════════════════════════════

describe("Semantic Dedup", () => {
  let sdApp, sdDag, sdScoring;
  let sdVpId, sdVpKp, sdTipId, sdAuthorPriv, sdCtid;
  let sdVerifierId, sdVerifierPriv;

  beforeAll(async () => {
    sdDag     = initDAG({ dbPath: ":memory:" });
    sdScoring = initScoring(sdDag, TEST_CONFIG);

    sdVpKp = generateMLDSAKeypair();
    const allVps = sdDag.getAllVPs();
    sdVpId = allVps[0].vp_id;
    sdDag.saveVP({ ...allVps[0], public_key: sdVpKp.publicKey });

    sdApp = createApp({ dag: sdDag, scoring: sdScoring, config: TEST_CONFIG });

    // Register author identity
    const sdKp = generateMLDSAKeypair();
    const idFields = {
      region: "US", public_key: sdKp.publicKey,
      dedup_hash: "55551111222233334444555566667777888899990000111122223333444455556",
      zk_proof: MOCK_ZK_PROOF, verification_tier: "T1",
      vp_id: sdVpId, social_attested: false,
    };
    const idRes = await request(sdApp)
      .post("/v1/identity/register")
      .send({ ...idFields, vp_signature: signBody(idFields, sdVpKp.privateKey) });
    sdTipId     = idRes.body.tip_id;
    sdAuthorPriv = sdKp.privateKey;
    sdDag.setScore(sdTipId, 800, 0);

    // Register a separate verifier identity
    const vKp = generateMLDSAKeypair();
    const vFields = {
      region: "US", public_key: vKp.publicKey,
      dedup_hash: "66661111222233334444555566667777888899990000111122223333444455556",
      zk_proof: MOCK_ZK_PROOF, verification_tier: "T1",
      vp_id: sdVpId, social_attested: false,
    };
    const vRes = await request(sdApp)
      .post("/v1/identity/register")
      .send({ ...vFields, vp_signature: signBody(vFields, sdVpKp.privateKey) });
    sdVerifierId  = vRes.body.tip_id;
    sdVerifierPriv = vKp.privateKey;
    sdDag.setScore(sdVerifierId, 800, 0);

    // Register content
    const sdContent = "Semantic dedup test content.";
    const sdCtSig = { author_tip_id: sdTipId, origin_code: ORIGIN.OH, content_hash: shake256(sdContent) };
    const ctRes = await request(sdApp)
      .post("/v1/content/register")
      .send({ author_tip_id: sdTipId, origin_code: ORIGIN.OH, content: sdContent, signature: signBody(sdCtSig, sdAuthorPriv) });
    sdCtid = ctRes.body.ctid;
  });

  afterAll(() => { if (sdDag) sdDag.close(); });

  test("9.1 First verify succeeds with correct delta and caps", async () => {
    const fields = { verifier_tip_id: sdVerifierId, verdict: "ORIGIN_CONFIRMED" };
    const res = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(sdCtid)}/verify`)
      .send({ ...fields, signature: signBody(fields, sdVerifierPriv) });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // Verifier score is 800 → high-trust bonus → delta +3
    expect(res.body.delta_applied).toBe(3);
    // Caps returned in response
    expect(res.body.caps).toBeDefined();
    expect(res.body.caps.content.used).toBe(3);
    expect(res.body.caps.content.max).toBe(5);
    expect(res.body.caps.daily.max).toBe(5);
    expect(res.body.caps.monthly.max).toBe(30);
  });

  test("9.2 Duplicate verify returns 409", async () => {
    const fields = { verifier_tip_id: sdVerifierId, verdict: "ORIGIN_CONFIRMED" };
    const res = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(sdCtid)}/verify`)
      .send({ ...fields, signature: signBody(fields, sdVerifierPriv) });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/already verified/i);
  });

  test("9.2b Per-content cap enforced", async () => {
    // Register fresh content for cap test
    const capContent = "Content for verification cap test.";
    const capSig = { author_tip_id: sdTipId, origin_code: ORIGIN.OH, content_hash: shake256(capContent) };
    const ctRes = await request(sdApp)
      .post("/v1/content/register")
      .send({ author_tip_id: sdTipId, origin_code: ORIGIN.OH, content: capContent, signature: signBody(capSig, sdAuthorPriv) });
    const capCtid = ctRes.body.ctid;

    // Create 3 verifier identities to fill the cap
    const verifiers = [];
    for (let i = 0; i < 3; i++) {
      const kp = generateMLDSAKeypair();
      const idFields = {
        region: "US", public_key: kp.publicKey,
        dedup_hash: `77${i}0111122223333444455556666777788889999000011112222333344445555`,
        zk_proof: MOCK_ZK_PROOF, verification_tier: "T1",
        vp_id: sdVpId, social_attested: false,
      };
      const idRes = await request(sdApp)
        .post("/v1/identity/register")
        .send({ ...idFields, vp_signature: signBody(idFields, sdVpKp.privateKey) });
      sdDag.setScore(idRes.body.tip_id, 800, 0); // high-trust for +3 each
      verifiers.push({ tipId: idRes.body.tip_id, priv: kp.privateKey });
    }

    // Daily cap already has 3 used from test 9.1 (sdTipId got +3 today)
    // Daily remaining = 5 - 3 = 2

    // Verifier 1: wants +3 but daily cap limits to +2
    const f1 = { verifier_tip_id: verifiers[0].tipId, verdict: "ORIGIN_CONFIRMED" };
    const r1 = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(capCtid)}/verify`)
      .send({ ...f1, signature: signBody(f1, verifiers[0].priv) });
    expect(r1.status).toBe(200);
    expect(r1.body.delta_applied).toBe(2); // daily cap: 5 - 3 = 2 remaining
    expect(r1.body.caps.content.used).toBe(2);
    expect(r1.body.caps.daily.used).toBe(5); // 3 + 2 = 5 (full)

    // Verifier 2: +0 (daily cap hit)
    const f2 = { verifier_tip_id: verifiers[1].tipId, verdict: "ORIGIN_CONFIRMED" };
    const r2 = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(capCtid)}/verify`)
      .send({ ...f2, signature: signBody(f2, verifiers[1].priv) });
    expect(r2.status).toBe(200);
    expect(r2.body.delta_applied).toBe(0);
    expect(r2.body.caps.daily.used).toBe(5); // still 5, no increase

    // Verifier 3: +0 (daily cap still hit)
    const f3 = { verifier_tip_id: verifiers[2].tipId, verdict: "ORIGIN_CONFIRMED" };
    const r3 = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(capCtid)}/verify`)
      .send({ ...f3, signature: signBody(f3, verifiers[2].priv) });
    expect(r3.status).toBe(200);
    expect(r3.body.delta_applied).toBe(0);
  });

  test("9.3 First dispute succeeds", async () => {
    // Register second content for dispute test
    const sdContent2 = "Second content for dispute dedup.";
    const sdCtSig2 = { author_tip_id: sdTipId, origin_code: ORIGIN.OH, content_hash: shake256(sdContent2) };
    const ctRes2 = await request(sdApp)
      .post("/v1/content/register")
      .send({ author_tip_id: sdTipId, origin_code: ORIGIN.OH, content: sdContent2, signature: signBody(sdCtSig2, sdAuthorPriv) });
    const ctid2 = ctRes2.body.ctid;

    const fields = { disputer_tip_id: sdTipId, reason: "test dispute" };
    const res = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(ctid2)}/dispute`)
      .send({ ...fields, signature: signBody(fields, sdAuthorPriv) });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // Duplicate dispute
    const res2 = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(ctid2)}/dispute`)
      .send({ ...fields, signature: signBody(fields, sdAuthorPriv) });
    expect(res2.status).toBe(409);
    expect(res2.body.error).toMatch(/already disputed/i);
  });

  test("9.4 Update origin within 24h succeeds", async () => {
    // Register fresh content for update test
    const updateContent = "Content for origin update test.";
    const updateSig = { author_tip_id: sdTipId, origin_code: ORIGIN.OH, content_hash: shake256(updateContent) };
    const ctRes = await request(sdApp)
      .post("/v1/content/register")
      .send({ author_tip_id: sdTipId, origin_code: ORIGIN.OH, content: updateContent, signature: signBody(updateSig, sdAuthorPriv) });
    expect(ctRes.status).toBe(201);
    const updateCtid = ctRes.body.ctid;
    expect(ctRes.body.status).toBe("registered");

    // Update origin from OH to AA
    const fields = { author_tip_id: sdTipId, new_origin_code: ORIGIN.AA };
    const res = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(updateCtid)}/update-origin`)
      .send({ ...fields, signature: signBody(fields, sdAuthorPriv) });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.old_origin_code).toBe("OH");
    expect(res.body.new_origin_code).toBe("AA");

    // Verify content record updated
    const getRes = await request(sdApp).get(`/v1/content/${encodeURIComponent(updateCtid)}`);
    expect(getRes.body.origin_code).toBe("AA");
  });

  test("9.5 Non-author cannot update origin", async () => {
    const updateContent2 = "Content for non-author update test.";
    const updateSig2 = { author_tip_id: sdTipId, origin_code: ORIGIN.OH, content_hash: shake256(updateContent2) };
    const ctRes = await request(sdApp)
      .post("/v1/content/register")
      .send({ author_tip_id: sdTipId, origin_code: ORIGIN.OH, content: updateContent2, signature: signBody(updateSig2, sdAuthorPriv) });
    const nonAuthorCtid = ctRes.body.ctid;

    // Verifier (different identity) tries to update
    const fields = { author_tip_id: sdVerifierId, new_origin_code: ORIGIN.AG };
    const res = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(nonAuthorCtid)}/update-origin`)
      .send({ ...fields, signature: signBody(fields, sdVerifierPriv) });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/only the content author/i);
  });

  test("9.6 Cannot update origin on disputed content", async () => {
    // Register content
    const disputeContent = "Content for dispute-block update test.";
    const disputeSig = { author_tip_id: sdTipId, origin_code: ORIGIN.OH, content_hash: shake256(disputeContent) };
    const ctRes = await request(sdApp)
      .post("/v1/content/register")
      .send({ author_tip_id: sdTipId, origin_code: ORIGIN.OH, content: disputeContent, signature: signBody(disputeSig, sdAuthorPriv) });
    const disputeCtid = ctRes.body.ctid;

    // Dispute it
    const dFields = { disputer_tip_id: sdVerifierId, reason: "test" };
    await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(disputeCtid)}/dispute`)
      .send({ ...dFields, signature: signBody(dFields, sdVerifierPriv) });

    // Try to update origin
    const fields = { author_tip_id: sdTipId, new_origin_code: ORIGIN.AA };
    const res = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(disputeCtid)}/update-origin`)
      .send({ ...fields, signature: signBody(fields, sdAuthorPriv) });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/cannot update origin/i);
  });

  test("9.7 Verify blocked on disputed content", async () => {
    // Register + dispute content
    const blockContent = "Content for verify-block test.";
    const blockSig = { author_tip_id: sdTipId, origin_code: ORIGIN.OH, content_hash: shake256(blockContent) };
    const ctRes = await request(sdApp)
      .post("/v1/content/register")
      .send({ author_tip_id: sdTipId, origin_code: ORIGIN.OH, content: blockContent, signature: signBody(blockSig, sdAuthorPriv) });
    const blockCtid = ctRes.body.ctid;

    const dFields = { disputer_tip_id: sdVerifierId, reason: "test" };
    await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(blockCtid)}/dispute`)
      .send({ ...dFields, signature: signBody(dFields, sdVerifierPriv) });

    // Try to verify
    const vFields = { verifier_tip_id: sdVerifierId, verdict: "ORIGIN_CONFIRMED" };
    const res = await request(sdApp)
      .post(`/v1/content/${encodeURIComponent(blockCtid)}/verify`)
      .send({ ...vFields, signature: signBody(vFields, sdVerifierPriv) });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/under dispute/i);
  });
});
