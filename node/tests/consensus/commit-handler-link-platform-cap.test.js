/**
 * @file tests/consensus/commit-handler-link-platform-cap.test.js
 * @description Issue #86 (Option A): LINK_PLATFORM inline scoring.
 *
 * The score bonus for social-account linking is now applied inline at
 * consensus commit time inside applyScoreEffect's LINK_PLATFORM case,
 * using the accumulated (or DAG-queried) set of prior linked platforms
 * to enforce per-platform uniqueness and the MAX_SOCIAL_ACCOUNTS cap.
 *
 * No separate SCORE_UPDATE is emitted by the API for social-link bonuses.
 * The (tip_id, platform) structural check closes both attacks documented
 * in #86:
 *   Attack 1 — reason-string spoofing (same platform, varied reasons):
 *     impossible — bonus is driven by LINK_PLATFORM.data.platform, not
 *     by parsing a SCORE_UPDATE reason string.
 *   Attack 2 — phantom platforms (no LINK_PLATFORM tx):
 *     impossible — the bonus fires only when a LINK_PLATFORM tx commits.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC    = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, signTransaction, computeTxId, shake256 } =
  require(path.join(SHARED, "crypto"));
const { TX_TYPES, SIGNED_BY_KIND } = require(path.join(SHARED, "constants"));
const { SOCIAL_LINK } = require(path.join(SHARED, "protocol-constants"));
const { initDAG }     = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const linkPlatformSchema   = require(path.join(SRC, "schemas", "link-platform"));
const registerSocialSchema = require(path.join(SRC, "schemas", "register-social"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID    = "tip://node/test-cap";
const AUTHOR_TIP = "tip://id/author-cap";
const BASE_TS    = 1767225600000;

// Platforms that do NOT require VP OAuth proof (bio-scrape path).
// Avoids the VP-attestation machinery in verifyTx so the test focuses
// purely on the inline scoring logic.
const NON_OAUTH_PLATFORMS = ["github", "reddit", "soundcloud", "medium", "bluesky", "devto", "mastodon"];

// ─── setup ────────────────────────────────────────────────────────────────────
// nodeKp is reused for both node signature and as the identity's key pair —
// same key signs the LINK_PLATFORM envelope (node role) and the user claim
// cosignature (subject role), which is valid for in-process unit tests.
function _setup() {
  const dag    = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();

  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: BASE_TS,
  });
  dag.saveIdentity({
    tip_id: AUTHOR_TIP, region: "US", public_key: nodeKp.publicKey,
    root_public_key: "00", vp_id: "tip://vp/v1",
    verification_tier: "T1", founding: false, status: "active",
    registered_at: BASE_TS, tx_id: shake256("id:author-cap"),
  });
  // Use SCORE.INITIAL_IDENTITY (500) so computeScore replay from tx
  // history matches the commit-time score table (both start from 500).
  dag.setScore(AUTHOR_TIP, 500, 0, BASE_TS);

  const config  = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });

  return { dag, nodeKp, handler, scoring };
}

// Build a properly signed LINK_PLATFORM tx that passes _verifyTxSignature.
// tipId defaults to AUTHOR_TIP; ts offset avoids duplicate tx_ids in batches.
// Only use non-OAuth platforms (those not in OAUTH_REQUIRED_PLATFORMS) so
// verifyTx's VP-attestation gate doesn't fire in unit tests.
function _buildLinkTx(dag, nodeKp, platform, { tipId = AUTHOR_TIP, tsOffset = 0 } = {}) {
  const ts = BASE_TS + 10_000_000 + tsOffset;
  // Produce a valid profile URL for each platform's pattern in ALLOWED_PLATFORMS.
  const profileUrls = {
    github:     `https://github.com/${platform}alice`,
    reddit:     `https://reddit.com/u/${platform}alice`,
    soundcloud: `https://soundcloud.com/${platform}alice`,
    medium:     `https://medium.com/@${platform}alice`,
    bluesky:    `https://bsky.app/profile/${platform}alice`,
    devto:      `https://dev.to/${platform}alice`,
    mastodon:   `https://mastodon.social/@${platform}alice`,
    substack:   `https://${platform}alice.substack.com`,
  };
  const profileUrl = profileUrls[platform] || `https://github.com/${platform}alice`;

  // User (subject) claim sig — over the register-social payload
  const claimPayload = registerSocialSchema.buildSigningPayload({
    tip_id: tipId, platform, profile_url: profileUrl, claimed_at: ts,
  });
  const claimSig = registerSocialSchema.sign(claimPayload, nodeKp.privateKey);

  const txData = {
    tip_id: tipId,
    platform,
    profile_url: profileUrl,
    handle: "alice",
    claimed_at: ts,
    verified_at: ts,
    node_id: NODE_ID,
    cosignatures: [{
      signer_kind: SIGNED_BY_KIND.SUBJECT,
      signer_ref:  tipId,
      signature:   claimSig,
    }],
  };

  const sigPayload = linkPlatformSchema.buildSigningPayload(txData);
  const nodeSig    = linkPlatformSchema.sign(sigPayload, nodeKp.privateKey);

  const body = {
    tx_type:   TX_TYPES.LINK_PLATFORM,
    timestamp: ts,
    signature: nodeSig,
    prev:      dag.getRecentPrev(),
    data:      txData,
  };
  body.tx_id = computeTxId(body);
  return body;
}

// ─────────────────────────────────────────────────────────────────────────────

describe("Issue #86 — LINK_PLATFORM inline scoring at consensus", () => {

  test("first link on a fresh identity earns SOCIAL_LINK_BONUS", () => {
    const { dag, nodeKp, handler } = _setup();

    const scoreBefore = dag.getScore(AUTHOR_TIP).score;
    const tx = _buildLinkTx(dag, nodeKp, "github", { tsOffset: 0 });
    const res = handler.commitOrderedTxs([tx], 1);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(0);

    const scoreAfter = dag.getScore(AUTHOR_TIP).score;
    expect(scoreAfter - scoreBefore).toBe(SOCIAL_LINK.SOCIAL_LINK_BONUS);
  });

  test("six distinct platforms each earn SOCIAL_LINK_BONUS (happy path cap boundary)", () => {
    const { dag, nodeKp, handler } = _setup();
    const scoreBefore = dag.getScore(AUTHOR_TIP).score;

    const platforms = NON_OAUTH_PLATFORMS.slice(0, SOCIAL_LINK.MAX_SOCIAL_ACCOUNTS);
    for (let i = 0; i < platforms.length; i++) {
      const tx = _buildLinkTx(dag, nodeKp, platforms[i], { tsOffset: i * 100 });
      const res = handler.commitOrderedTxs([tx], i + 1);
      expect(res.committed).toBe(1);
    }

    const scoreAfter = dag.getScore(AUTHOR_TIP).score;
    expect(scoreAfter - scoreBefore).toBe(platforms.length * SOCIAL_LINK.SOCIAL_LINK_BONUS);
  });

  test("seventh unique platform: LINK_PLATFORM commits but earns no bonus (cap enforced inline)", () => {
    const { dag, nodeKp, handler } = _setup();

    const platforms = NON_OAUTH_PLATFORMS.slice(0, SOCIAL_LINK.MAX_SOCIAL_ACCOUNTS);
    for (let i = 0; i < platforms.length; i++) {
      handler.commitOrderedTxs([_buildLinkTx(dag, nodeKp, platforms[i], { tsOffset: i * 100 })], i + 1);
    }

    const scoreBefore = dag.getScore(AUTHOR_TIP).score;
    const tx7 = _buildLinkTx(dag, nodeKp, NON_OAUTH_PLATFORMS[SOCIAL_LINK.MAX_SOCIAL_ACCOUNTS], { tsOffset: 900 });
    const res = handler.commitOrderedTxs([tx7], 10);

    // LINK_PLATFORM itself must still commit — linking is unrestricted
    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(0);

    // But no bonus awarded once the cap is reached
    const scoreAfter = dag.getScore(AUTHOR_TIP).score;
    expect(scoreAfter - scoreBefore).toBe(0);
  });

  test("re-linking the same platform: applyScoreEffect detects isRelink and awards no bonus", () => {
    // Test the scoring logic directly via applyScoreEffect (pure function)
    // rather than through the full commit flow, because verifyTx correctly
    // rejects a LINK_PLATFORM while an active link exists (first-wins guard).
    // The important property is that if such a tx DID commit (e.g. post-unlink),
    // applyScoreEffect's linkedPlatforms check stops the duplicate bonus.
    const { applyScoreEffect, initialState } = require(path.join(SRC, "score-effects"));

    const linkTx = (platform) => ({
      tx_type: TX_TYPES.LINK_PLATFORM,
      tx_id:   `fake-tx-${platform}`,
      data:    { platform, tip_id: AUTHOR_TIP },
    });

    let state = initialState();
    const st1 = applyScoreEffect(linkTx("github"), state);
    expect(st1.delta).toBe(SOCIAL_LINK.SOCIAL_LINK_BONUS); // first link earns bonus
    expect(st1.linkedPlatforms.has("github")).toBe(true);

    state = st1;
    const st2 = applyScoreEffect(linkTx("github"), state);
    expect(st2.delta).toBe(0); // re-link: isRelink = true → no bonus
    expect(st2.score).toBe(st1.score); // score unchanged

    // Unlinking a platform does NOT remove it from linkedPlatforms —
    // the re-link guard is based on ever-linked history, not current status.
    // Verify the third link (different platform) still earns a bonus.
    state = st2;
    const st3 = applyScoreEffect(linkTx("reddit"), state);
    expect(st3.delta).toBe(SOCIAL_LINK.SOCIAL_LINK_BONUS);
  });

  test("cap is per-identity: a different identity still earns bonus even when AUTHOR is at cap", () => {
    const { dag, nodeKp, handler } = _setup();

    // Max out AUTHOR_TIP
    const platforms = NON_OAUTH_PLATFORMS.slice(0, SOCIAL_LINK.MAX_SOCIAL_ACCOUNTS);
    for (let i = 0; i < platforms.length; i++) {
      handler.commitOrderedTxs([_buildLinkTx(dag, nodeKp, platforms[i], { tsOffset: i * 100 })], i + 1);
    }

    // Register a different identity (reuse node key for simplicity)
    const OTHER_TIP = "tip://id/other-user-86";
    dag.saveIdentity({
      tip_id: OTHER_TIP, region: "US", public_key: nodeKp.publicKey,
      root_public_key: "00", vp_id: "tip://vp/v1",
      verification_tier: "T1", founding: false, status: "active",
      registered_at: BASE_TS, tx_id: shake256("id:other-86"),
    });
    dag.setScore(OTHER_TIP, 750, 0, BASE_TS);

    const scoreBefore = dag.getScore(OTHER_TIP).score;
    const tx = _buildLinkTx(dag, nodeKp, "github", { tipId: OTHER_TIP, tsOffset: 2000 });
    const res = handler.commitOrderedTxs([tx], 20);

    expect(res.committed).toBe(1);
    const scoreAfter = dag.getScore(OTHER_TIP).score;
    expect(scoreAfter - scoreBefore).toBe(SOCIAL_LINK.SOCIAL_LINK_BONUS);
  });

  test("computeScore replay matches commit-time score after inline bonuses", () => {
    const { dag, nodeKp, handler, scoring } = _setup();

    const platforms = NON_OAUTH_PLATFORMS.slice(0, 3);
    for (let i = 0; i < platforms.length; i++) {
      handler.commitOrderedTxs([_buildLinkTx(dag, nodeKp, platforms[i], { tsOffset: i * 100 })], i + 1);
    }

    const fromTable  = dag.getScore(AUTHOR_TIP).score;
    const fromReplay = scoring.computeScore(AUTHOR_TIP).score;
    expect(fromReplay).toBe(fromTable);
  });

  test("inline scoring uses platform field, not reason string (Attack 1 structurally impossible)", () => {
    const { dag, nodeKp, handler } = _setup();

    // Link github once — earns bonus
    handler.commitOrderedTxs([_buildLinkTx(dag, nodeKp, "github", { tsOffset: 0 })], 1);
    const scoreAfterFirst = dag.getScore(AUTHOR_TIP).score;

    // Re-link github with a different timestamp (different tx_id) — no second bonus
    handler.commitOrderedTxs([_buildLinkTx(dag, nodeKp, "github", { tsOffset: 9990 })], 2);
    const scoreAfterSecond = dag.getScore(AUTHOR_TIP).score;

    expect(scoreAfterSecond).toBe(scoreAfterFirst);
  });

  test("SCORE_UPDATE for non-social reason is unaffected by inline LINK_PLATFORM scoring", () => {
    const { dag, nodeKp, handler } = _setup();

    // First link earns inline bonus
    handler.commitOrderedTxs([_buildLinkTx(dag, nodeKp, "github", { tsOffset: 0 })], 1);
    const scoreAfterLink = dag.getScore(AUTHOR_TIP).score;

    // An unrelated SCORE_UPDATE (e.g. clean-record bonus) must still apply normally
    const cleanTx = (() => {
      const body = {
        tx_type:   TX_TYPES.SCORE_UPDATE,
        timestamp: BASE_TS + 20_000_000,
        prev:      dag.getRecentPrev(),
        data: { tip_id: AUTHOR_TIP, delta: 10, reason: "clean_record_bonus", node_id: NODE_ID },
      };
      body.tx_id = computeTxId(body);
      return signTransaction(body, nodeKp.privateKey);
    })();

    const res = handler.commitOrderedTxs([cleanTx], 5);
    expect(res.committed).toBe(1);
    expect(dag.getScore(AUTHOR_TIP).score).toBe(scoreAfterLink + 10);
  });

});
