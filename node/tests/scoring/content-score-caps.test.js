/**
 * @file tests/scoring/content-score-caps.test.js
 * @description Content-Score earning rules from the scoring spec
 * (TIP_Scoring_v2_Personal_Notes (2).md, "Content Score (0-350, hard cap)").
 *
 * Today's wiring:
 *   - VERIFY_CAPS.PER_CONTENT (=5) is enforced live by content-service.verify
 *     (the +1/+2/+3 each verification adds clamps to the per-content remainder).
 *   - VERIFY_CAPS.PER_DAY (=5) and PER_MONTH (=30) similarly clamp the per-author
 *     verification credits granted to a single creator's content.
 *   - Per-origin Content-bucket caps (oh_cap=200, aa/ag/mx_cap=100) live in
 *     genesis but no module reads them. Pinned here as a contract — when the
 *     bucket-aware engine lands, these caps must come from genesis (no
 *     hardcoded numbers in service code).
 *
 * Where production diverges from spec, the test name says so.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, signBody, tipNormalize,
} = require(path.join(SHARED, "crypto"));
const { TX_TYPES, CONTENT_STATUS, ORIGIN } = require(path.join(SHARED, "constants"));
const { VERIFY_CAPS } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));

const PROTO_CONSTANTS = require(path.resolve(__dirname, "../../../genesis-data/genesis.json")).protocol_constants;

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/test";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  dag.saveVP({
    vp_id: VP_ID, name: "vp1", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });

  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
    mediaLimits: { max_text_bytes: 1_000_000, max_image_bytes: 0, max_video_bytes: 0, max_audio_bytes: 0 },
  };
  const scoring = initScoring(dag, config);
  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); dag.addTx(tx); };
  const contentService = createContentService({ dag, scoring, config, submitTx });

  return { dag, scoring, contentService, submitted };
}

// Seed an identity with a chosen score so verification weighting is predictable.
function _seedIdentity(dag, tipId, kp, score = 750) {
  dag.saveIdentity({
    tip_id: tipId, region: "US",
    public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${tipId}`),
  });
  dag.setScore(tipId, score, 0, "2026-01-01T00:00:00.000Z");
}

// Seed content directly into the DAG. The service's register() submits a
// REGISTER_CONTENT tx that only materialises the row at commit-handler time;
// these tests don't run consensus, so we shortcut to dag.saveContent. The
// cap logic under test (content-service.verify) reads the row, not the tx.
function _seedContent(dag, ctid, authorTipId, origin = ORIGIN.OH) {
  dag.saveContent({
    ctid, origin_code: origin, content_hash: shake256(`c:${ctid}`),
    author_tip_id: authorTipId, status: CONTENT_STATUS.REGISTERED,
    registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256(`reg:${ctid}`),
  });
}

function _verifyOnce(contentService, ctid, verifierKp, verifierTipId) {
  const sig = signBody({ verifier_tip_id: verifierTipId, verdict: "ORIGIN_CONFIRMED" }, verifierKp.privateKey);
  return contentService.verify(ctid, { verifier_tip_id: verifierTipId, verdict: "ORIGIN_CONFIRMED", signature: sig });
}

// ─── Constants ──────────────────────────────────────────────────────────────

describe("content score — genesis constants match spec", () => {
  test("registration credit = +2", () => {
    expect(PROTO_CONSTANTS.content.registration_credit).toBe(2);
  });

  test("verification credit = +1 (community)", () => {
    expect(PROTO_CONSTANTS.content.verification_credit).toBe(1);
  });

  test("per-origin caps: OH 200, AA/AG/MX 100 each", () => {
    expect(PROTO_CONSTANTS.content.oh_cap).toBe(200);
    expect(PROTO_CONSTANTS.content.aa_cap).toBe(100);
    expect(PROTO_CONSTANTS.content.ag_cap).toBe(100);
    expect(PROTO_CONSTANTS.content.mx_cap).toBe(100);
  });

  test("per-content lifetime cap = +5", () => {
    expect(PROTO_CONSTANTS.content.per_content_lifetime_cap).toBe(5);
  });

  test("VERIFY_CAPS.PER_CONTENT mirrors the spec's per-content lifetime cap", () => {
    expect(VERIFY_CAPS.PER_CONTENT).toBe(PROTO_CONSTANTS.content.per_content_lifetime_cap);
  });
});

// ─── Live cap enforcement (what's actually wired today) ─────────────────────

describe("content score — VERIFY_CAPS.PER_CONTENT (+5 lifetime) is enforced live", () => {
  test("after enough verifications to saturate, weighted_delta clamps to 0", () => {
    const fx = _setup();

    const authorKp = generateMLDSAKeypair();
    const authorTipId = `tip://id/US-${shake256("a-pc-author").slice(0, 16)}`;
    _seedIdentity(fx.dag, authorTipId, authorKp, 750);
    const ctid = "tip://c/OH-aaaaaaaaaaaaaa-1111";
    _seedContent(fx.dag, ctid, authorTipId);

    let totalAwarded = 0;
    let lastDelta;
    // Seed enough distinct verifiers so per-day/per-month don't fire first.
    // base_delta = 2; per_content cap = 5. Two +2 verifications saturate to 4,
    // a third should clamp at 1 (max remaining), a fourth at 0.
    for (let i = 0; i < 4; i++) {
      const vKp = generateMLDSAKeypair();
      const vTip = `tip://id/US-${shake256(`verifier-pc-${i}`).slice(0, 16)}`;
      // Different authors so per-day/per-month for the AUTHOR's content
      // accumulate; verifier-side rate limit is in business-rules, not here.
      _seedIdentity(fx.dag, vTip, vKp, 700);
      lastDelta = _verifyOnce(fx.contentService, ctid, vKp, vTip).delta_applied;
      totalAwarded += lastDelta;
    }
    expect(totalAwarded).toBeLessThanOrEqual(VERIFY_CAPS.PER_CONTENT);
    expect(lastDelta).toBe(0);
  });

  test("HIGH_TRUST verifier gets +3 base (subject to per-content cap)", () => {
    const fx = _setup();
    const authorKp = generateMLDSAKeypair();
    const authorTipId = `tip://id/US-${shake256("a-htv2-author").slice(0, 16)}`;
    _seedIdentity(fx.dag, authorTipId, authorKp, 750);
    const ctid = "tip://c/OH-bbbbbbbbbbbbbb-2222";
    _seedContent(fx.dag, ctid, authorTipId);

    const vKp = generateMLDSAKeypair();
    const vTip = `tip://id/US-${shake256("verifier-htv").slice(0, 16)}`;
    _seedIdentity(fx.dag, vTip, vKp, 850); // >= HIGH_TRUST_MIN
    const out = _verifyOnce(fx.contentService, ctid, vKp, vTip);
    expect(out.delta_applied).toBe(VERIFY_CAPS.HIGH_TRUST_DELTA);
  });
});

describe("content score — VERIFY_CAPS daily/monthly throttle author credit", () => {
  test("per-author per-day cap clamps verification credits across that author's content", () => {
    const fx = _setup();

    const authorKp = generateMLDSAKeypair();
    const authorTipId = `tip://id/US-${shake256("a-day-author").slice(0, 16)}`;
    _seedIdentity(fx.dag, authorTipId, authorKp, 750);

    // Multiple distinct contents so per-content (=5) doesn't fire.
    const ctids = [];
    for (let i = 0; i < 6; i++) {
      const c = `tip://c/OH-cccccccccccccc-${(3000 + i).toString(16).padStart(4, "0")}`;
      _seedContent(fx.dag, c, authorTipId);
      ctids.push(c);
    }

    let totalToday = 0;
    for (let i = 0; i < ctids.length; i++) {
      const vKp = generateMLDSAKeypair();
      const vTip = `tip://id/US-${shake256(`verifier-day-${i}`).slice(0, 16)}`;
      _seedIdentity(fx.dag, vTip, vKp, 700);
      const d = _verifyOnce(fx.contentService, ctids[i], vKp, vTip).delta_applied;
      totalToday += d;
    }
    // Per-day cap on what the author can collect today.
    expect(totalToday).toBeLessThanOrEqual(VERIFY_CAPS.PER_DAY);
  });
});

// ─── Spec-forward gaps (NOT YET ENFORCED in production) ─────────────────────

describe.skip("content score — per-origin sub-bucket caps (spec, not yet enforced)", () => {
  test("OH-bucket caps a creator's OH-derived score at 200", () => {
    // Pin this when the bucket-aware engine lands. Today the engine
    // has a single combined `score`, so OH-vs-AA contribution is not
    // separately tracked. genesis.protocol_constants.content.oh_cap is
    // the source of truth — the test must read it, not hardcode 200.
  });

  test("AA/AG/MX caps clamp their respective buckets at 100 each", () => {
    // Same shape as the OH test once the bucket engine exists.
  });

  test("Cumulative Content sub-score cannot exceed 350 even when per-origin caps would allow more", () => {
    // (200 + 100 + 100 + 100 = 500; the 350 hard cap is the spec's tighter bound.)
  });
});
