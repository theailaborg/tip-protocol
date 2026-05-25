"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../shared");
const SRC    = path.resolve(__dirname, "../src");

const { initCrypto, generateMLDSAKeypair } = require(SHARED + "/crypto");
const { TX_TYPES } = require(SHARED + "/constants");
const linkPlatformSchema = require(SRC + "/schemas/link-platform");
const registerSocialSchema = require(SRC + "/schemas/register-social");
const { validateTransaction } = require(SRC + "/validators/tx-validator");
const { initDAG } = require(SRC + "/dag");
const { withTxId } = require(SRC + "/services/helpers");
const { nowMs } = require(SHARED + "/time");
const { createIdentityService } = require(SRC + "/services/identity-service");
const { initScoring } = require(SRC + "/scoring");
const { SOCIAL_LINK } = require(SHARED + "/protocol-constants");
const request = require("supertest");
const express = require("express");
const { createRouter } = require(SRC + "/routes/identity");

beforeAll(async () => { await initCrypto(); });

test("TX_TYPES.UNLINK_PLATFORM is defined", () => {
  const { TX_TYPES } = require("../../shared/constants");
  expect(TX_TYPES.UNLINK_PLATFORM).toBe("UNLINK_PLATFORM");
});

describe("link-platform schema v2 (node-attested)", () => {
  test("PLATFORM_MAX_LENGTH is 50", () => {
    expect(linkPlatformSchema.PLATFORM_MAX_LENGTH).toBe(50);
  });

  test("buildSigningPayload produces 8 canonical fields alphabetically", () => {
    const payload = linkPlatformSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344",
      platform: "twitter",
      profile_url: "https://x.com/alice",
      handle: "alice",
      claimed_at: 1748000000000,
      verified_at: 1748000000001,
      node_id: "tip://node/n1",
      claim_signature: "aabbcc",
    });
    expect(Object.keys(payload)).toEqual([
      "claim_signature", "claimed_at", "handle", "node_id",
      "platform", "profile_url", "tip_id", "verified_at",
    ]);
  });

  test("buildSigningPayload accepts null handle (LinkedIn/Facebook)", () => {
    const payload = linkPlatformSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344",
      platform: "linkedin",
      profile_url: "https://www.linkedin.com/in/alice",
      handle: null,
      claimed_at: 1748000000000,
      verified_at: 1748000000001,
      node_id: "tip://node/n1",
      claim_signature: "aabbcc",
    });
    expect(payload.handle).toBeNull();
  });

  test("buildSigningPayload throws on missing claim_signature", () => {
    expect(() => linkPlatformSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344",
      platform: "twitter",
      profile_url: "https://x.com/alice",
      handle: "alice",
      claimed_at: 1748000000000,
      verified_at: 1748000000001,
      node_id: "tip://node/n1",
    })).toThrow();
  });

  test("sign + verifySignature round-trip (node signs)", async () => {
    const { privateKey, publicKey } = await generateMLDSAKeypair();
    const payload = linkPlatformSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344",
      platform: "twitter",
      profile_url: "https://x.com/alice",
      handle: "alice",
      claimed_at: 1748000000000,
      verified_at: 1748000000001,
      node_id: "tip://node/n1",
      claim_signature: "aabbcc",
    });
    const sig = linkPlatformSchema.sign(payload, privateKey);
    expect(linkPlatformSchema.verifySignature(payload, sig, publicKey)).toBe(true);
  });

  test("SIGNATURE_SCOPE and SIGNED_BY are exported", () => {
    const { SIGNATURE_SCOPE, SIGNED_BY_KIND } = require("../../shared/constants");
    expect(linkPlatformSchema.SIGNATURE_SCOPE).toBe(SIGNATURE_SCOPE.BODY);
    expect(linkPlatformSchema.SIGNED_BY).toBe(SIGNED_BY_KIND.NODE);
  });
});

describe("register-social schema", () => {
  test("buildSigningPayload produces 4 canonical fields alphabetically", () => {
    const payload = registerSocialSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344",
      platform: "twitter",
      profile_url: "https://x.com/alice",
      claimed_at: 1748000000000,
    });
    expect(Object.keys(payload)).toEqual(["claimed_at", "platform", "profile_url", "tip_id"]);
  });

  test("buildSigningPayload throws on missing tip_id", () => {
    expect(() => registerSocialSchema.buildSigningPayload({
      platform: "twitter", profile_url: "https://x.com/alice", claimed_at: 1748000000000,
    })).toThrow();
  });

  test("buildSigningPayload throws on missing profile_url", () => {
    expect(() => registerSocialSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344", platform: "twitter", claimed_at: 1748000000000,
    })).toThrow();
  });

  test("sign + verifySignature round-trip", async () => {
    const { privateKey, publicKey } = await generateMLDSAKeypair();
    const payload = registerSocialSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344",
      platform: "twitter",
      profile_url: "https://x.com/alice",
      claimed_at: 1748000000000,
    });
    const sig = registerSocialSchema.sign(payload, privateKey);
    expect(registerSocialSchema.verifySignature(payload, sig, publicKey)).toBe(true);
  });
});

describe("LINK_PLATFORM tx-validator", () => {
  let dag;
  let vpPub;
  let testTipId;

  beforeAll(async () => {
    dag = initDAG({ dbPath: ":memory:" });
    const { publicKey: vpKey } = await generateMLDSAKeypair();
    vpPub = vpKey;
    dag.saveVP({ vp_id: "tip://vp/test-vp-1", public_key: vpKey, status: "active", tx_id: "genesis-vp-1" });
    testTipId = "tip://id/IN-aabbccdd11223344";
    dag.saveIdentity({ tip_id: testTipId, public_key: vpKey, vp_id: "tip://vp/test-vp-1", tx_id: "genesis-id-1" });
  });

  function makeTx(overrides = {}) {
    return withTxId({
      tx_type: TX_TYPES.LINK_PLATFORM,
      timestamp: nowMs(),
      prev: ["genesis-id-1"],
      data: {
        tip_id: testTipId,
        platform: "youtube",
        handle: "@testchannel",
        linked_at: nowMs(),
        vp_id: "tip://vp/test-vp-1",
        vp_signature: "a".repeat(256),
        ...overrides,
      },
    });
  }

  test("valid LINK_PLATFORM tx passes shape validation (ignores sig for shape layer)", () => {
    const tx = makeTx();
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(true);
  });

  test("any non-empty platform string passes shape validation (e.g. myspace, x.com)", () => {
    const tx = makeTx({ platform: "myspace" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(true);
  });

  test("empty platform fails shape validation", () => {
    const tx = makeTx({ platform: "" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/platform/);
  });

  test("empty handle fails shape validation", () => {
    const tx = makeTx({ handle: "" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/handle/);
  });

  test("unknown tip_id fails state validation", () => {
    const tx = makeTx({ tip_id: "tip://id/US-ffffffffffffffff" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/TIP-ID not found/);
  });
});

describe("identityService.linkPlatform", () => {
  let dag2, scoring2, identityService2;
  let vpPriv, vpPub2, vpTipId;
  let userTipId;
  const submitted = [];

  beforeAll(async () => {
    dag2 = initDAG({ dbPath: ":memory:" });
    scoring2 = initScoring(dag2, { nodeId: "tip://node/test" });
    const { privateKey, publicKey } = await generateMLDSAKeypair();
    vpPriv = privateKey;
    vpPub2 = publicKey;
    vpTipId = "tip://vp/svc-test-vp";
    dag2.saveVP({ vp_id: vpTipId, public_key: vpPub2, status: "active", tx_id: "genesis-vp-svc" });
    userTipId = "tip://id/US-1122334455667788";
    dag2.saveIdentity({ tip_id: userTipId, public_key: vpPub2, vp_id: vpTipId, tx_id: "genesis-id-svc" });
    identityService2 = createIdentityService({
      dag: dag2, scoring: scoring2,
      config: { nodeId: "tip://node/test", nodePrivateKey: vpPriv, nodeRegisteredId: "tip://node/test" },
      submitTx: (tx) => submitted.push(tx),
    });
  });

  test("linkPlatform submits a LINK_PLATFORM tx and a paired SCORE_UPDATE tx", () => {
    submitted.length = 0;
    const linkedAt = nowMs();
    const payload = linkPlatformSchema.buildSigningPayload({
      tip_id: userTipId, platform: "youtube", handle: "@mychannel", linked_at: linkedAt,
    });
    const vpSig = linkPlatformSchema.sign(payload, vpPriv);
    const result = identityService2.linkPlatform({
      tipId: userTipId,
      platform: "youtube",
      handle: "@mychannel",
      linkedAt,
      vpId: vpTipId,
      vpSignature: vpSig,
    });
    expect(result.confirmation).toBe("proposed");
    expect(result.platform).toBe("youtube");
    expect(submitted).toHaveLength(2);
    expect(submitted[0].tx_type).toBe(TX_TYPES.LINK_PLATFORM);
    expect(submitted[1].tx_type).toBe(TX_TYPES.SCORE_UPDATE);
    expect(submitted[1].data.delta).toBe(SOCIAL_LINK.SOCIAL_LINK_BONUS);
    expect(submitted[1].data.tip_id).toBe(userTipId);
  });

  test("linkPlatform rejects duplicate platform", () => {
    const lp = submitted.find(t => t.tx_type === TX_TYPES.LINK_PLATFORM);
    dag2.addTx(lp);
    let caught;
    try {
      identityService2.linkPlatform({
        tipId: userTipId, platform: "youtube", handle: "@other", linkedAt: nowMs(),
        vpId: vpTipId, vpSignature: "x",
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeDefined();
    expect(caught.status).toBe(409);
    expect(caught.code).toBe("platform_already_linked");
    expect(caught.error).toMatch(/already linked/);
  });

  test("6th link earns score bonus, 7th link succeeds with score_delta 0 (no cap block)", async () => {
    const dag3 = initDAG({ dbPath: ":memory:" });
    const scoring3 = initScoring(dag3, { nodeId: "tip://node/cap-test" });
    const { privateKey: vPriv, publicKey: vPub } = await generateMLDSAKeypair();
    dag3.saveVP({ vp_id: "tip://vp/cap-vp", public_key: vPub, status: "active", tx_id: "g-vp" });
    const capTipId = "tip://id/US-ccddeeff00112233";
    dag3.saveIdentity({ tip_id: capTipId, public_key: vPub, vp_id: "tip://vp/cap-vp", tx_id: "g-id" });
    const submitted3 = [];
    const svc3 = createIdentityService({
      dag: dag3, scoring: scoring3,
      config: { nodeId: "tip://node/cap-test", nodePrivateKey: vPriv, nodeRegisteredId: "tip://node/cap-test" },
      submitTx: (tx) => { submitted3.push(tx); if (tx.tx_type === TX_TYPES.LINK_PLATFORM) dag3.addTx(tx); },
    });

    const platforms = ["youtube", "twitter", "instagram", "linkedin", "tiktok", "rooverse"];
    for (const plat of platforms) {
      const linkedAt = nowMs();
      const payload = linkPlatformSchema.buildSigningPayload({
        tip_id: capTipId, platform: plat, handle: `@${plat}`, linked_at: linkedAt,
      });
      const sig = linkPlatformSchema.sign(payload, vPriv);
      svc3.linkPlatform({ tipId: capTipId, platform: plat, handle: `@${plat}`, linkedAt, vpId: "tip://vp/cap-vp", vpSignature: sig });
    }

    // 7th link (new platform) must succeed but return score_delta 0
    const linkedAt7 = nowMs();
    const payload7 = linkPlatformSchema.buildSigningPayload({
      tip_id: capTipId, platform: "threads", handle: "@extra", linked_at: linkedAt7,
    });
    const result7 = svc3.linkPlatform({
      tipId: capTipId, platform: "threads", handle: "@extra", linkedAt: linkedAt7,
      vpId: "tip://vp/cap-vp", vpSignature: linkPlatformSchema.sign(payload7, vPriv),
    });
    expect(result7.confirmation).toBe("proposed");
    expect(result7.score_delta).toBe(0);
    expect(result7.score_tx_id).toBeNull();

    // Duplicate platform still throws 409
    const linkedAt8 = nowMs();
    const payload8 = linkPlatformSchema.buildSigningPayload({
      tip_id: capTipId, platform: "youtube", handle: "@dup", linked_at: linkedAt8,
    });
    let caught;
    try {
      svc3.linkPlatform({
        tipId: capTipId, platform: "youtube", handle: "@dup", linkedAt: linkedAt8,
        vpId: "tip://vp/cap-vp", vpSignature: linkPlatformSchema.sign(payload8, vPriv),
      });
    } catch (e) { caught = e; }
    expect(caught).toBeDefined();
    expect(caught.code).toBe("platform_already_linked");
  });
});

describe("dag platform_links CRUD", () => {
  test("savePlatformLink + getPlatformLink round-trip", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    dag.savePlatformLink({
      id: "tip://id/US-aabb::twitter",
      tip_id: "tip://id/US-aabb",
      platform: "twitter",
      handle: "@alice",
      profile_url: "https://x.com/alice",
      status: "active",
      linked_at: 1748000000000,
      verified_at: 1748000000001,
      expires_at: 1748000000001 + 365 * 24 * 3600 * 1000,
      consecutive_failures: 0,
      node_id: "tip://node/n1",
      claim_signature: "aaa",
      node_signature: "bbb",
      tx_id: "tx-1",
    });
    const row = dag.getPlatformLink("tip://id/US-aabb", "twitter");
    expect(row).not.toBeNull();
    expect(row.handle).toBe("@alice");
    expect(row.status).toBe("active");
  });

  test("getPlatformLinksByTipId returns all links for identity", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const base = {
      tip_id: "tip://id/US-ccdd",
      handle: "@x",
      profile_url: "https://example.com/x",
      status: "active",
      linked_at: 1748000000000,
      verified_at: 1748000000001,
      expires_at: 1748000000001 + 365 * 24 * 3600 * 1000,
      consecutive_failures: 0,
      node_id: "tip://node/n1",
      claim_signature: "aaa",
      node_signature: "bbb",
      tx_id: "tx-x",
    };
    dag.savePlatformLink({ ...base, id: "tip://id/US-ccdd::youtube", platform: "youtube", tx_id: "tx-1" });
    dag.savePlatformLink({ ...base, id: "tip://id/US-ccdd::github", platform: "github", tx_id: "tx-2" });
    const links = dag.getPlatformLinksByTipId("tip://id/US-ccdd");
    expect(links).toHaveLength(2);
    expect(links.map(l => l.platform).sort()).toEqual(["github", "youtube"]);
  });
});

describe("POST /v1/identity/:tipId/link-platform route", () => {
  let app;

  beforeAll(() => {
    app = express();
    app.use(express.json());
    const mockService = {
      register:        () => {},
      resolve:         () => {},
      verifyOwnership: () => {},
      getScore:        () => {},
      getHistory:      () => {},
      getActivity:     () => {},
      linkPlatform: ({ tipId, platform, handle }) => ({
        tip_id: tipId, platform, handle,
        tx_id: "mock-tx-id", score_tx_id: "mock-score-tx",
        score_delta: 5, confirmation: "proposed",
        linked_at: nowMs(),
      }),
    };
    app.use("/v1", createRouter({ identityService: mockService, profileService: {} }));
  });

  test("POST /v1/identity/:tipId/link-platform returns 202 with proposed", async () => {
    const res = await request(app)
      .post("/v1/identity/tip:%2F%2Fid%2FIN-aabbccdd11223344/link-platform")
      .send({ tip_id: "tip://id/IN-aabbccdd11223344", platform: "youtube", handle: "@ch", vp_id: "tip://vp/test", vp_signature: "abc" });
    expect(res.status).toBe(202);
    expect(res.body.confirmation).toBe("proposed");
    expect(res.body.score_delta).toBe(5);
  });
});
