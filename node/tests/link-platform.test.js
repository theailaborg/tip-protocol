"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../shared");
const SRC    = path.resolve(__dirname, "../src");

const { initCrypto, generateMLDSAKeypair } = require(SHARED + "/crypto");
const { TX_TYPES } = require(SHARED + "/constants");
const linkPlatformSchema = require(SRC + "/schemas/link-platform");
const registerSocialSchema = require(SRC + "/schemas/register-social");
const { signPayload } = require(SRC + "/schemas/_common");
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

  test("buildSigningPayload produces 7 canonical fields alphabetically (no claim_signature)", () => {
    const payload = linkPlatformSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344",
      platform: "twitter",
      profile_url: "https://x.com/alice",
      handle: "alice",
      claimed_at: 1748000000000,
      verified_at: 1748000000001,
      node_id: "tip://node/n1",
    });
    expect(Object.keys(payload)).toEqual([
      "claimed_at", "handle", "node_id",
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
    });
    expect(payload.handle).toBeNull();
  });

  test("buildSigningPayload appends 3 OAuth fields when present", () => {
    const payload = linkPlatformSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344",
      platform: "linkedin",
      profile_url: "https://www.linkedin.com/in/alice",
      handle: null,
      claimed_at: 1748000000000,
      verified_at: 1748000000001,
      node_id: "tip://node/n1",
      vp_id: "tip://vp/v1",
      vp_oauth_signature: "deadbeef",
      vp_oauth_verified_at: 1748000000000,
    });
    expect(Object.keys(payload).sort()).toEqual([
      "claimed_at", "handle", "node_id",
      "platform", "profile_url", "tip_id", "verified_at",
      "vp_id", "vp_oauth_signature", "vp_oauth_verified_at",
    ].sort());
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
      platform: "twitter", profile_url: "https://x.com/alice",
      claimed_at: 1748000000000,
    })).toThrow();
  });

  test("buildSigningPayload throws on missing profile_url", () => {
    expect(() => registerSocialSchema.buildSigningPayload({
      tip_id: "tip://id/US-aabbccdd11223344", platform: "twitter",
      claimed_at: 1748000000000,
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
    const { SIGNED_BY_KIND: SBK } = require("../../shared/constants");
    // Build a valid base payload first (for signing), then apply overrides to tx.data
    const baseData = {
      tip_id: testTipId,
      platform: "twitter",
      profile_url: "https://x.com/alice",
      handle: "alice",
      claimed_at: 1748000000000,
      verified_at: nowMs(),
      node_id: "tip://node/n1",
      cosignatures: [{
        signer_kind: SBK.SUBJECT,
        signer_ref:  testTipId,
        signature:   claimSig,
      }],
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

  test("missing cosignatures fails shape validation", () => {
    const tx = makeTx({ cosignatures: [] });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/cosignature/);
  });

  test("unknown tip_id fails state validation", () => {
    const tx = makeTx({ tip_id: "tip://id/US-ffffffffffffffff" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/TIP-ID not found/);
  });

  // #86 hardening: the (tip_id, platform) dedup + inline bonus match the
  // stored platform byte-for-byte, so verifyTx must reject a non-canonical
  // casing that a gossip-bypass / malicious-node tx could use to occupy a
  // second slot for the same real account.
  test("verifyTx rejects non-canonical platform casing", () => {
    const tx = makeTx({ platform: "Twitter" });
    const result = linkPlatformSchema.verifyTx(tx, dag);
    expect(result.ok).toBe(false);
    expect(result.code).toBe("platform_not_canonical");
  });

  test("verifyTx rejects an unknown platform", () => {
    const tx = makeTx({ platform: "myspace" });
    const result = linkPlatformSchema.verifyTx(tx, dag);
    expect(result.ok).toBe(false);
    expect(result.code).toBe("platform_not_canonical");
  });
});

describe("LINK_PLATFORM validateRequest — canonical platform (#86 hardening)", () => {
  function _body(overrides = {}) {
    return {
      tip_id: "tip://id/US-aabbccdd11223344",
      platform: "twitter",
      profile_url: "https://x.com/alice",
      claim_signature: "00",
      claimed_at: nowMs(),
      ...overrides,
    };
  }

  test("rejects non-canonical casing", () => {
    const body = _body({ platform: "Twitter" });
    let err;
    try { linkPlatformSchema.validateRequest(body, { now: body.claimed_at }); }
    catch (e) { err = e; }
    expect(err).toBeDefined();
    expect(err.code).toBe("platform_not_canonical");
  });

  test("accepts a canonical lowercase platform (no canonical/unknown error)", () => {
    const body = _body({ platform: "twitter" });
    // No deps.dag → returns after the stateless platform/url/oauth checks.
    let err;
    try { linkPlatformSchema.validateRequest(body, { now: body.claimed_at }); }
    catch (e) { err = e; }
    expect(err && err.code).not.toBe("platform_not_canonical");
    expect(err && err.code).not.toBe("unknown_platform");
  });

  test("accepts rooverse with a web.rooverse.app URL (OAuth-only platform)", () => {
    // Rooverse is a known platform; its profile_url matches the allowed host.
    // With no OAuth bundle the expected stop is oauth_required (403) — NOT
    // unknown_platform / invalid_profile_url. This is the exact case that was
    // returning HTTP 400 unknown_platform before rooverse was allow-listed.
    const body = _body({ platform: "rooverse", profile_url: "https://web.rooverse.app/user/alice" });
    let err;
    try { linkPlatformSchema.validateRequest(body, { now: body.claimed_at }); }
    catch (e) { err = e; }
    expect(err && err.code).not.toBe("unknown_platform");
    expect(err && err.code).not.toBe("invalid_profile_url");
    expect(err && err.code).toBe("oauth_required");
  });

  test("rejects rooverse with a non-rooverse profile_url domain", () => {
    const body = _body({ platform: "rooverse", profile_url: "https://evil.com/alice" });
    let err;
    try { linkPlatformSchema.validateRequest(body, { now: body.claimed_at }); }
    catch (e) { err = e; }
    expect(err && err.code).toBe("invalid_profile_url");
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
      // Simulate the commit handler: save LINK_PLATFORM txs to platform_links so
      // the duplicate check (getPlatformLink) works in subsequent test calls.
      submitTx: (tx) => {
        submitted.push(tx);
        if (tx.tx_type === TX_TYPES.LINK_PLATFORM) {
          // Mirror what commit-handler writes — display state + tx_id.
          // Signatures are reachable via tx_id from the transactions table.
          dag2.savePlatformLink({
            id: `${tx.data.tip_id}::${tx.data.platform}`,
            tip_id: tx.data.tip_id,
            platform: tx.data.platform,
            handle: tx.data.handle ?? null,
            profile_url: tx.data.profile_url,
            status: "active",
            linked_at: tx.data.verified_at,
            verified_at: tx.data.verified_at,
            node_id: tx.data.node_id,
            tx_id: tx.tx_id,
          });
        }
      },
    });
  });

  function makeClaimSig(platform, profileUrl, claimedAt) {
    const payload = registerSocialSchema.buildSigningPayload({
      tip_id: userTipId, platform, profile_url: profileUrl,
      claimed_at: claimedAt,
    });
    return registerSocialSchema.sign(payload, userPriv);
  }

  test("linkPlatform calls verifyBio and submits LINK_PLATFORM only (no separate SCORE_UPDATE — issue #86 Option A)", async () => {
    submitted.length = 0;
    // Use a bio-check platform (medium) — twitter is OAUTH_REQUIRED and would
    // reject without a VP proof before ever reaching verifyBio.
    const claimedAt = nowMs();
    const claimSig = makeClaimSig("medium", "https://medium.com/@alice", claimedAt);

    const bioFetcher = require(SRC + "/services/bio-fetcher");
    const origVerify = bioFetcher.verifyBio;
    bioFetcher.verifyBio = async () => ({ handle: "alice" });

    const result = await identityService2.linkPlatform({
      tipId: userTipId,
      platform: "medium",
      profileUrl: "https://medium.com/@alice",
      claimSignature: claimSig,
      claimedAt,
    });

    bioFetcher.verifyBio = origVerify;

    expect(result.confirmation).toBe("proposed");
    expect(result.platform).toBe("medium");
    expect(result.handle).toBe("alice");
    // Issue #86 Option A: bonus applied inline at consensus — no separate SCORE_UPDATE tx.
    expect(submitted).toHaveLength(1);
    expect(submitted[0].tx_type).toBe(TX_TYPES.LINK_PLATFORM);
    expect(result.score_delta).toBe(SOCIAL_LINK.SOCIAL_LINK_BONUS);
    expect(result.score_tx_id).toBeNull();
    // Cosignatures shape — user's claim sig rides as a SUBJECT cosig.
    expect(Array.isArray(submitted[0].data.cosignatures)).toBe(true);
    expect(submitted[0].data.cosignatures).toHaveLength(1);
    expect(submitted[0].data.cosignatures[0].signer_kind).toBe("subject");
    expect(submitted[0].data.cosignatures[0].signer_ref).toBe(userTipId);
    expect(submitted[0].data.claim_signature).toBeUndefined();
  });

  test("linkPlatform throws 409 on duplicate platform", async () => {
    // The submitTx mock already called savePlatformLink for the medium link above.
    // No manual dag2.addTx needed — getPlatformLink will find the active link.
    const bioFetcher = require(SRC + "/services/bio-fetcher");
    const origVerify = bioFetcher.verifyBio;
    bioFetcher.verifyBio = async () => ({ handle: "alice2" });

    const claimedAt409 = nowMs();
    let caught;
    try {
      // Attempt to link medium again (same platform already committed above).
      await identityService2.linkPlatform({
        tipId: userTipId, platform: "medium",
        profileUrl: "https://medium.com/@alice2",
        claimSignature: makeClaimSig("medium", "https://medium.com/@alice2", claimedAt409),
        claimedAt: claimedAt409,
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

    // Use soundcloud (bio-check platform, not OAUTH_REQUIRED, not yet linked) so
    // the request reaches verifyBio instead of hitting the duplicate-platform 409.
    const claimedAt422 = nowMs();
    let caught;
    try {
      await identityService2.linkPlatform({
        tipId: userTipId, platform: "soundcloud",
        profileUrl: "https://soundcloud.com/myhandle",
        claimSignature: makeClaimSig("soundcloud", "https://soundcloud.com/myhandle", claimedAt422),
        claimedAt: claimedAt422,
      });
    } catch (e) { caught = e; }

    bioFetcher.verifyBio = origVerify;
    expect(caught.status).toBe(422);
    expect(caught.code).toBe("tip_id_not_in_bio");
  });

  test("linkPlatform throws 403 when OAuth-required platform has no VP proof", async () => {
    const claimedAt = nowMs();
    let caught;
    try {
      await identityService2.linkPlatform({
        tipId: userTipId, platform: "instagram",
        profileUrl: "https://instagram.com/myhandle",
        claimSignature: makeClaimSig("instagram", "https://instagram.com/myhandle", claimedAt),
        claimedAt,
        // no vpOauthSignature / vpId
      });
    } catch (e) { caught = e; }
    expect(caught.status).toBe(403);
    expect(caught.code).toBe("oauth_required");
  });

  test("linkPlatform OAuth path: tx.data carries OAuth bundle + verifyTx re-verifies", async () => {
    submitted.length = 0;
    // Register a separate OAuth-attesting VP so we have a private key
    // to sign the OAuth proof with.
    const oauthVpKeys = await generateMLDSAKeypair();
    const oauthVpId = "tip://vp/oauth-test";
    dag2.saveVP({ vp_id: oauthVpId, public_key: oauthVpKeys.publicKey, status: "active", tx_id: "g-vp-oauth" });

    const profileUrl = "https://tiktok.com/@alice_oauth";
    const claimedAt = nowMs();
    const vpOauthVerifiedAt = nowMs();
    const vpOauthHandle = "alice_oauth";

    // VP signs the canonical 7-field OAuth attestation. Handle is the
    // VP's observation from the OAuth callback.
    const oauthProof = {
      claimed_at: claimedAt,
      handle: vpOauthHandle,
      platform: "tiktok",
      profile_url: profileUrl,
      tip_id: userTipId,
      verified_at: vpOauthVerifiedAt,
      vp_id: oauthVpId,
    };
    const vpOauthSignature = signPayload(oauthProof, oauthVpKeys.privateKey);

    const result = await identityService2.linkPlatform({
      tipId: userTipId,
      platform: "tiktok",
      profileUrl,
      claimSignature: makeClaimSig("tiktok", profileUrl, claimedAt),
      claimedAt,
      vpId: oauthVpId,
      vpOauthSignature,
      vpOauthHandle,
      vpOauthVerifiedAt,
    });

    expect(result.confirmation).toBe("proposed");
    const linkTx = submitted.find(t => t.tx_type === TX_TYPES.LINK_PLATFORM);
    expect(linkTx).toBeDefined();

    // tx.data.handle is the VP-attested handle (vp_oauth_handle).
    expect(linkTx.data.handle).toBe(vpOauthHandle);

    // OAuth bundle persisted into tx.data so replay can re-verify.
    expect(linkTx.data.vp_id).toBe(oauthVpId);
    expect(linkTx.data.vp_oauth_signature).toBe(vpOauthSignature);
    expect(linkTx.data.vp_oauth_verified_at).toBe(vpOauthVerifiedAt);
    // Node's own verified_at is a distinct timestamp from the VP's.
    expect(typeof linkTx.data.verified_at).toBe("number");
    // Claim sig lives in cosignatures array (canonical pattern), not as
    // a flat tx.data.claim_signature field.
    expect(linkTx.data.claim_signature).toBeUndefined();
    expect(linkTx.data.cosignatures).toHaveLength(1);

    // Replay round-trip — verifyTx must re-verify both the subject
    // cosignature AND the VP OAuth signature using tx.data alone.
    dag2.updatePlatformLinkStatus(userTipId, "tiktok", { status: "unlinked" });
    const verifyResult = linkPlatformSchema.verifyTx(linkTx, dag2);
    expect(verifyResult.ok).toBe(true);
  });

  test("linkPlatform OAuth replay rejects forged vp_oauth_signature", async () => {
    submitted.length = 0;
    const oauthVpKeys = await generateMLDSAKeypair();
    const oauthVpId = "tip://vp/oauth-forge-test";
    dag2.saveVP({ vp_id: oauthVpId, public_key: oauthVpKeys.publicKey, status: "active", tx_id: "g-vp-forge" });

    const profileUrl = "https://facebook.com/alice_forge";
    const claimedAt = nowMs();
    const vpOauthVerifiedAt = nowMs();
    const vpOauthHandle = "alice_forge";

    const oauthProof = {
      claimed_at: claimedAt,
      handle: vpOauthHandle,
      platform: "facebook",
      profile_url: profileUrl,
      tip_id: userTipId,
      verified_at: vpOauthVerifiedAt,
      vp_id: oauthVpId,
    };
    const vpOauthSignature = signPayload(oauthProof, oauthVpKeys.privateKey);

    await identityService2.linkPlatform({
      tipId: userTipId,
      platform: "facebook",
      profileUrl,
      claimSignature: makeClaimSig("facebook", profileUrl, claimedAt),
      claimedAt,
      vpId: oauthVpId,
      vpOauthSignature,
      vpOauthHandle,
      vpOauthVerifiedAt,
    });

    const linkTx = submitted.find(t => t.tx_type === TX_TYPES.LINK_PLATFORM);

    // Simulate pre-apply state for replay verification (same reason
    // as the OAuth round-trip test above).
    dag2.updatePlatformLinkStatus(userTipId, "facebook", { status: "unlinked" });

    // Tamper the OAuth signature on a clone and re-verify — must fail.
    const tampered = {
      ...linkTx,
      data: { ...linkTx.data, vp_oauth_signature: "00".repeat(linkTx.data.vp_oauth_signature.length / 2) },
    };
    const r = linkPlatformSchema.verifyTx(tampered, dag2);
    expect(r.ok).toBe(false);
    expect(r.code).toBe("vp_oauth_signature_invalid");
  });

  test("linkPlatform OAuth path for rooverse: full verifyTx replay round-trip", async () => {
    // rooverse-specific replay coverage. The OAuth replay path is platform-
    // agnostic, but rooverse is consensus-deployed to all nodes, so exercise it
    // explicitly to lock the VP↔node proof symmetry against future drift.
    submitted.length = 0;
    const oauthVpKeys = await generateMLDSAKeypair();
    const oauthVpId = "tip://vp/oauth-rooverse";
    dag2.saveVP({ vp_id: oauthVpId, public_key: oauthVpKeys.publicKey, status: "active", tx_id: "g-vp-rooverse" });

    // Mirrors the live VP flow: skip_url_match makes the user-typed
    // web.rooverse.app URL canonical, and the handle is the URL slug.
    const profileUrl = "https://web.rooverse.app/user/alice_roo";
    const claimedAt = nowMs();
    const vpOauthVerifiedAt = nowMs();
    const vpOauthHandle = "alice_roo";

    const oauthProof = {
      claimed_at: claimedAt,
      handle: vpOauthHandle,
      platform: "rooverse",
      profile_url: profileUrl,
      tip_id: userTipId,
      verified_at: vpOauthVerifiedAt,
      vp_id: oauthVpId,
    };
    const vpOauthSignature = signPayload(oauthProof, oauthVpKeys.privateKey);

    const result = await identityService2.linkPlatform({
      tipId: userTipId,
      platform: "rooverse",
      profileUrl,
      claimSignature: makeClaimSig("rooverse", profileUrl, claimedAt),
      claimedAt,
      vpId: oauthVpId,
      vpOauthSignature,
      vpOauthHandle,
      vpOauthVerifiedAt,
    });

    expect(result.confirmation).toBe("proposed");
    const linkTx = submitted.find(t => t.tx_type === TX_TYPES.LINK_PLATFORM);
    expect(linkTx).toBeDefined();
    expect(linkTx.data.platform).toBe("rooverse");
    expect(linkTx.data.handle).toBe(vpOauthHandle);

    // Replay round-trip — verifyTx must re-verify the subject cosignature AND
    // the VP OAuth signature from tx.data alone (the consensus replay path).
    dag2.updatePlatformLinkStatus(userTipId, "rooverse", { status: "unlinked" });
    const verifyResult = linkPlatformSchema.verifyTx(linkTx, dag2);
    expect(verifyResult.ok).toBe(true);
  });

  test("linkPlatform throws 400 for unknown platform", async () => {
    const claimedAt = nowMs();
    let caught;
    try {
      await identityService2.linkPlatform({
        tipId: userTipId, platform: "myspace",
        profileUrl: "https://myspace.com/alice",
        claimSignature: makeClaimSig("myspace", "https://myspace.com/alice", claimedAt),
        claimedAt,
      });
    } catch (e) { caught = e; }
    expect(caught.status).toBe(400);
    expect(caught.code).toBe("unknown_platform");
  });

  test("linkPlatform throws 400 for mismatched profile_url domain", async () => {
    const claimedAt = nowMs();
    let caught;
    try {
      await identityService2.linkPlatform({
        tipId: userTipId, platform: "github",
        profileUrl: "https://evil.com/alice",
        claimSignature: makeClaimSig("github", "https://evil.com/alice", claimedAt),
        claimedAt,
      });
    } catch (e) { caught = e; }
    expect(caught.status).toBe(400);
    expect(caught.code).toBe("invalid_profile_url");
  });

  test("linkPlatform throws 400 when claimed_at is older than 15 minutes", async () => {
    const staleClaimedAt = nowMs() - 16 * 60 * 1000; // 16 min ago
    let caught;
    try {
      await identityService2.linkPlatform({
        tipId: userTipId, platform: "github",
        profileUrl: "https://github.com/alice",
        claimSignature: makeClaimSig("github", "https://github.com/alice", staleClaimedAt),
        claimedAt: staleClaimedAt,
      });
    } catch (e) { caught = e; }
    expect(caught.status).toBe(400);
    expect(caught.code).toBe("claim_expired");
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
      node_id: "tip://node/n1",
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
      node_id: "tip://node/n1",
      tx_id: "tx-x",
    };
    dag.savePlatformLink({ ...base, id: "tip://id/US-ccdd::youtube", platform: "youtube", tx_id: "tx-1" });
    dag.savePlatformLink({ ...base, id: "tip://id/US-ccdd::github", platform: "github", tx_id: "tx-2" });
    const links = dag.getPlatformLinksByTipId("tip://id/US-ccdd");
    expect(links).toHaveLength(2);
    expect(links.map(l => l.platform).sort()).toEqual(["github", "youtube"]);
  });
});

describe("social link score cap — 7th platform earns no bonus", () => {
  let dag3, scoring3, svc3;
  let userPriv3, userPub3, nodePriv3;
  let uid3;
  const submitted3 = [];

  beforeAll(async () => {
    dag3 = initDAG({ dbPath: ":memory:" });
    scoring3 = initScoring(dag3, { nodeId: "tip://node/cap-test" });
    const uKeys = await generateMLDSAKeypair();
    userPriv3 = uKeys.privateKey;
    userPub3 = uKeys.publicKey;
    const nKeys = await generateMLDSAKeypair();
    nodePriv3 = nKeys.privateKey;
    const nodePub3 = nKeys.publicKey;
    dag3.saveNode({ node_id: "tip://node/cap-test", public_key: nodePub3, status: "active", tx_id: "g-node3" });
    dag3.saveVP({ vp_id: "tip://vp/cap", public_key: nodePub3, status: "active", tx_id: "g-vp3" });
    uid3 = "tip://id/US-cap0000cap00000";
    dag3.saveIdentity({ tip_id: uid3, public_key: userPub3, vp_id: "tip://vp/cap", tx_id: "g-id3" });
    svc3 = createIdentityService({
      dag: dag3, scoring: scoring3,
      config: { nodeId: "tip://node/cap-test", nodePrivateKey: nodePriv3, nodeRegisteredId: "tip://node/cap-test" },
      // Add each tx to the DAG so subsequent calls see the already-linked platforms.
      submitTx: (tx) => { submitted3.push(tx); dag3.addTx(tx); },
    });
  });

  function makeClaimSig3(platform, profileUrl, claimedAt) {
    const payload = registerSocialSchema.buildSigningPayload({
      tip_id: uid3, platform, profile_url: profileUrl,
      claimed_at: claimedAt,
    });
    return registerSocialSchema.sign(payload, userPriv3);
  }

  async function linkOne(platform, profileUrl) {
    const claimedAt = nowMs();
    const claimSig = makeClaimSig3(platform, profileUrl, claimedAt);
    return svc3.linkPlatform({ tipId: uid3, platform, profileUrl, claimSignature: claimSig, claimedAt });
  }

  const CAP_PLATFORMS = [
    { platform: "github",     profileUrl: "https://github.com/alice" },
    { platform: "reddit",     profileUrl: "https://reddit.com/user/alice" },
    { platform: "soundcloud", profileUrl: "https://soundcloud.com/alice" },
    { platform: "medium",     profileUrl: "https://medium.com/@alice" },
    { platform: "substack",   profileUrl: "https://alice.substack.com" },
    { platform: "devto",      profileUrl: "https://dev.to/alice" },
  ];

  test("platforms 1–6 each earn SOCIAL_LINK_BONUS", async () => {
    const bioFetcher = require(SRC + "/services/bio-fetcher");
    const origVerify = bioFetcher.verifyBio;
    bioFetcher.verifyBio = async ({ platform }) => ({ handle: `alice_${platform}` });

    for (const { platform, profileUrl } of CAP_PLATFORMS) {
      const result = await linkOne(platform, profileUrl);
      expect(result.score_delta).toBe(SOCIAL_LINK.SOCIAL_LINK_BONUS);
    }

    bioFetcher.verifyBio = origVerify;
  });

  test("7th platform link returns score_delta 0 (cap enforced)", async () => {
    const bioFetcher = require(SRC + "/services/bio-fetcher");
    const origVerify = bioFetcher.verifyBio;
    bioFetcher.verifyBio = async () => ({ handle: "alice_bluesky" });

    const result = await linkOne("bluesky", "https://bsky.app/profile/alice.bsky.social");

    bioFetcher.verifyBio = origVerify;
    expect(result.score_delta).toBe(0);
    expect(result.confirmation).toBe("proposed");

    // Issue #86 Option A: no SCORE_UPDATEs emitted for social links at all —
    // bonus applies inline at consensus via applyScoreEffect's LINK_PLATFORM case.
    const scoreTxs = submitted3.filter(t => t.tx_type === TX_TYPES.SCORE_UPDATE);
    expect(scoreTxs).toHaveLength(0);
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
      linkPlatform: ({ tipId, platform }) => ({
        tip_id: tipId, platform, handle: null,
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
      .send({ tip_id: "tip://id/IN-aabbccdd11223344", platform: "youtube", vp_id: "tip://vp/test", vp_signature: "abc" });
    expect(res.status).toBe(202);
    expect(res.body.confirmation).toBe("proposed");
    expect(res.body.score_delta).toBe(5);
  });
});
