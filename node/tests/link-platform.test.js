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

describe("LINK_PLATFORM tx-validator v2 (node-attested)", () => {
  let dag;
  let nodePub, nodePriv;
  let userPub, userPriv;
  let testTipId;

  beforeAll(async () => {
    dag = initDAG({ dbPath: ":memory:" });
    const nodeKeys = await generateMLDSAKeypair();
    nodePub = nodeKeys.publicKey;
    nodePriv = nodeKeys.privateKey;
    const userKeys = await generateMLDSAKeypair();
    userPub = userKeys.publicKey;
    userPriv = userKeys.privateKey;
    dag.saveNode({ node_id: "tip://node/n1", public_key: nodePub, status: "active", tx_id: "g-node" });
    testTipId = "tip://id/US-aabbccdd11223344";
    dag.saveIdentity({ tip_id: testTipId, public_key: userPub, vp_id: "tip://vp/v1", tx_id: "g-id" });
  });

  function makeClaimSig(overrides = {}) {
    const payload = registerSocialSchema.buildSigningPayload({
      tip_id: testTipId,
      platform: "twitter",
      profile_url: "https://x.com/alice",
      claimed_at: 1748000000000,
      ...overrides,
    });
    return registerSocialSchema.sign(payload, userPriv);
  }

  function makeTx(overrides = {}) {
    const claimSig = makeClaimSig();
    // Build a valid base payload first (for signing), then apply overrides to tx.data
    const baseData = {
      tip_id: testTipId,
      platform: "twitter",
      profile_url: "https://x.com/alice",
      handle: "alice",
      claimed_at: 1748000000000,
      verified_at: nowMs(),
      node_id: "tip://node/n1",
      claim_signature: claimSig,
    };
    const payload = linkPlatformSchema.buildSigningPayload(baseData);
    const nodeSig = linkPlatformSchema.sign(payload, nodePriv);
    // Apply overrides to data after signing (allows invalid fields to reach validator)
    const txData = { ...baseData, ...overrides };
    return withTxId({
      tx_type: TX_TYPES.LINK_PLATFORM,
      timestamp: nowMs(),
      signature: nodeSig,
      prev: ["g-id"],
      data: txData,
    });
  }

  test("valid LINK_PLATFORM tx passes shape validation", () => {
    const tx = makeTx();
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(true);
  });

  test("missing profile_url fails shape validation", () => {
    const tx = makeTx({ profile_url: undefined });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/profile_url/);
  });

  test("missing claim_signature fails shape validation", () => {
    const tx = makeTx({ claim_signature: "" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/claim_signature/);
  });

  test("unknown tip_id fails state validation", () => {
    const tx = makeTx({ tip_id: "tip://id/US-ffffffffffffffff" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/TIP-ID not found/);
  });
});

describe("identityService.linkPlatform v2 (node-attested)", () => {
  let dag2, scoring2, identityService2;
  let userPriv, userPub;
  let nodePriv;
  let userTipId;
  const submitted = [];

  beforeAll(async () => {
    dag2 = initDAG({ dbPath: ":memory:" });
    scoring2 = initScoring(dag2, { nodeId: "tip://node/test" });
    const userKeys = await generateMLDSAKeypair();
    userPriv = userKeys.privateKey;
    userPub = userKeys.publicKey;
    const nodeKeys = await generateMLDSAKeypair();
    nodePriv = nodeKeys.privateKey;
    const nodePub = nodeKeys.publicKey;
    dag2.saveNode({ node_id: "tip://node/test", public_key: nodePub, status: "active", tx_id: "g-node" });
    dag2.saveVP({ vp_id: "tip://vp/v1", public_key: nodePub, status: "active", tx_id: "g-vp" });
    userTipId = "tip://id/US-1122334455667788";
    dag2.saveIdentity({ tip_id: userTipId, public_key: userPub, vp_id: "tip://vp/v1", tx_id: "g-id" });
    identityService2 = createIdentityService({
      dag: dag2, scoring: scoring2,
      config: {
        nodeId: "tip://node/test",
        nodePrivateKey: nodePriv,
        nodeRegisteredId: "tip://node/test",
      },
      submitTx: (tx) => submitted.push(tx),
    });
  });

  function makeClaimSig(platform, profileUrl, claimedAt) {
    const payload = registerSocialSchema.buildSigningPayload({
      tip_id: userTipId, platform, profile_url: profileUrl, claimed_at: claimedAt,
    });
    return registerSocialSchema.sign(payload, userPriv);
  }

  test("linkPlatform calls verifyBio and submits LINK_PLATFORM + SCORE_UPDATE", async () => {
    submitted.length = 0;
    const claimedAt = nowMs();
    const claimSig = makeClaimSig("twitter", "https://x.com/alice", claimedAt);

    const bioFetcher = require(SRC + "/services/bio-fetcher");
    const origVerify = bioFetcher.verifyBio;
    bioFetcher.verifyBio = async () => ({ handle: "alice" });

    const result = await identityService2.linkPlatform({
      tipId: userTipId,
      platform: "twitter",
      profileUrl: "https://x.com/alice",
      claimSignature: claimSig,
      claimedAt,
    });

    bioFetcher.verifyBio = origVerify;

    expect(result.confirmation).toBe("proposed");
    expect(result.platform).toBe("twitter");
    expect(result.handle).toBe("alice");
    expect(submitted).toHaveLength(2);
    expect(submitted[0].tx_type).toBe(TX_TYPES.LINK_PLATFORM);
    expect(submitted[1].tx_type).toBe(TX_TYPES.SCORE_UPDATE);
    expect(submitted[1].data.delta).toBe(SOCIAL_LINK.SOCIAL_LINK_BONUS);
  });

  test("linkPlatform throws 409 on duplicate platform", async () => {
    const lp = submitted.find(t => t.tx_type === TX_TYPES.LINK_PLATFORM);
    dag2.addTx(lp);

    const bioFetcher = require(SRC + "/services/bio-fetcher");
    const origVerify = bioFetcher.verifyBio;
    bioFetcher.verifyBio = async () => ({ handle: "alice2" });

    let caught;
    try {
      await identityService2.linkPlatform({
        tipId: userTipId, platform: "twitter",
        profileUrl: "https://x.com/alice2",
        claimSignature: makeClaimSig("twitter", "https://x.com/alice2", nowMs()),
        claimedAt: nowMs(),
      });
    } catch (e) { caught = e; }

    bioFetcher.verifyBio = origVerify;
    expect(caught).toBeDefined();
    expect(caught.status).toBe(409);
    expect(caught.code).toBe("platform_already_linked");
  });

  test("linkPlatform throws 422 when TIP-ID not found in bio", async () => {
    const bioFetcher = require(SRC + "/services/bio-fetcher");
    const origVerify = bioFetcher.verifyBio;
    bioFetcher.verifyBio = async () => {
      throw { status: 422, error: "TIP-ID not found in bio", code: "tip_id_not_in_bio" };
    };

    const claimedAt422 = nowMs();
    let caught;
    try {
      await identityService2.linkPlatform({
        tipId: userTipId, platform: "instagram",
        profileUrl: "https://instagram.com/myhandle",
        claimSignature: makeClaimSig("instagram", "https://instagram.com/myhandle", claimedAt422),
        claimedAt: claimedAt422,
      });
    } catch (e) { caught = e; }

    bioFetcher.verifyBio = origVerify;
    expect(caught.status).toBe(422);
    expect(caught.code).toBe("tip_id_not_in_bio");
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
