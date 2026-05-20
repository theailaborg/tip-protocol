/**
 * @file tests/validators/dispute-rate-limit.test.js
 * @description Phase 3 — per-filer dispute rate limit. canDispute rejects
 * filings once a disputer has DISPUTE.MAX_PER_FILER_PER_WINDOW disputes
 * within the trailing DISPUTE.FILER_WINDOW_MS.
 *
 * Coverage:
 *   - Allows up to limit-1 filings within the window
 *   - Rejects the limit-th filing with status 429
 *   - Old filings outside the window don't count toward the cap
 *   - Auto-cascade CONTENT_DISPUTED (data.auto = true, node-issued)
 *     does NOT count against the disputer's quota — those have node_id
 *     not disputer_tip_id and represent system actions, not user filings
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const rules = require(path.join(SRC, "validators", "business-rules"));
const {
  TX_TYPES, CONTENT_STATUS, DISPUTE_REASON,
} = require(path.join(SHARED, "constants"));
const { DISPUTE } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const AUTHOR  = "tip://id/US-aaaaaaaaaaaaaaaa";
const FILER   = "tip://id/US-bbbbbbbbbbbbbbbb";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  for (const tip_id of [AUTHOR, FILER]) {
    dag.saveIdentity({
      tip_id, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${tip_id}`),
    });
  }
  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  // Filer score must be >= MIN_SCORE_TO_DISPUTE; author score is irrelevant.
  dag.setScore(FILER, 900, 0, new Date().toISOString());
  dag.setScore(AUTHOR, 700, 0, new Date().toISOString());
  return { dag, scoring };
}

function _seedContent(dag, ctid) {
  dag.saveContent({
    ctid, origin_code: "OH",
    content_hash: shake256(ctid), perceptual_hash: null,
    author_tip_id: AUTHOR, signer_tip_id: AUTHOR,
    authors: [{ tip_id: AUTHOR, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: CONTENT_STATUS.REGISTERED,
    prescan_flagged: false, prescan_probability: 0.1, prescan_tier: "low",
    override: false,
    registered_at: new Date().toISOString(),
    registered_urls: [], tx_id: shake256(`c:${ctid}`),
  });
}

function _addDisputeTx(dag, { ctid, disputer_tip_id, timestampMs, auto = false, node_id = null }) {
  const body = {
    tx_type: TX_TYPES.CONTENT_DISPUTED,
    timestamp: new Date(timestampMs).toISOString(),
    prev: [],
    data: auto
      ? { ctid, auto: true, node_id, reason: "system_cascade" }
      : { ctid, disputer_tip_id, reason: DISPUTE_REASON.ORIGIN_MISMATCH, declared_origin: "OH", claimed_origin: "AG" },
  };
  body.tx_id = computeTxId(body);
  dag.addTx(body);
}

describe("canDispute — Phase 3 per-filer rate limit", () => {

  test("allows the (limit-1)-th filing within the window", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-cccccccccccccc-0001";
    _seedContent(fx.dag, ctid);

    // Seed MAX_PER_FILER_PER_WINDOW - 1 prior disputes by FILER, all
    // recent (within the window).
    const now = Date.now();
    for (let i = 0; i < DISPUTE.MAX_PER_FILER_PER_WINDOW - 1; i++) {
      _addDisputeTx(fx.dag, {
        ctid: `tip://c/OH-prior${i.toString().padStart(8, "0")}-0001`,
        disputer_tip_id: FILER, timestampMs: now - i * 1000,
      });
    }

    // A fresh dispute on a different ctid should still be allowed.
    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: FILER, reason: DISPUTE_REASON.ORIGIN_MISMATCH, claimed_origin: "AG",
    });
    expect(r.valid).toBe(true);
  });

  test("rejects the limit-th filing with status 429", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-dddddddddddddd-0001";
    _seedContent(fx.dag, ctid);

    const now = Date.now();
    for (let i = 0; i < DISPUTE.MAX_PER_FILER_PER_WINDOW; i++) {
      _addDisputeTx(fx.dag, {
        ctid: `tip://c/OH-priorL${i.toString().padStart(7, "0")}-0001`,
        disputer_tip_id: FILER, timestampMs: now - i * 1000,
      });
    }

    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: FILER, reason: DISPUTE_REASON.ORIGIN_MISMATCH, claimed_origin: "AG",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(429);
    expect(r.error.message).toMatch(/dispute filing limit/i);
  });

  test("old filings outside the window do NOT count", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-eeeeeeeeeeeeee-0001";
    _seedContent(fx.dag, ctid);

    // All N prior disputes are older than the window → should not count.
    const tooOldMs = Date.now() - DISPUTE.FILER_WINDOW_MS - 60_000;
    for (let i = 0; i < DISPUTE.MAX_PER_FILER_PER_WINDOW; i++) {
      _addDisputeTx(fx.dag, {
        ctid: `tip://c/OH-old${i.toString().padStart(10, "0")}-0001`,
        disputer_tip_id: FILER, timestampMs: tooOldMs - i * 1000,
      });
    }
    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: FILER, reason: DISPUTE_REASON.ORIGIN_MISMATCH, claimed_origin: "AG",
    });
    expect(r.valid).toBe(true);
  });

  test("auto-cascade CONTENT_DISPUTED (data.auto=true) does NOT count toward the quota", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-ffffffffffffff-0001";
    _seedContent(fx.dag, ctid);

    // Seed (limit) auto-cascade disputes (e.g. REVOKE_VP cascade,
    // h=R+24 auto-escalation). These are system-issued — node_id, no
    // disputer_tip_id. Must not block a real user's first filing.
    const now = Date.now();
    for (let i = 0; i < DISPUTE.MAX_PER_FILER_PER_WINDOW + 2; i++) {
      _addDisputeTx(fx.dag, {
        ctid: `tip://c/OH-auto${i.toString().padStart(9, "0")}-0001`,
        timestampMs: now - i * 1000, auto: true, node_id: "tip://node/n1",
      });
    }

    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: FILER, reason: DISPUTE_REASON.ORIGIN_MISMATCH, claimed_origin: "AG",
    });
    expect(r.valid).toBe(true);
  });

  test("limit is per-filer, not global", () => {
    const fx = _setup();
    // Another opted-in filer also at limit shouldn't block our FILER.
    const OTHER = "tip://id/US-eeeeeeeeeeeeeeee";
    fx.dag.saveIdentity({
      tip_id: OTHER, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("other"),
    });
    fx.dag.setScore(OTHER, 900, 0, new Date().toISOString());

    const ctid = "tip://c/OH-ggggggggggggg1-0001";
    _seedContent(fx.dag, ctid);

    const now = Date.now();
    for (let i = 0; i < DISPUTE.MAX_PER_FILER_PER_WINDOW; i++) {
      _addDisputeTx(fx.dag, {
        ctid: `tip://c/OH-other${i.toString().padStart(8, "0")}-0001`,
        disputer_tip_id: OTHER, timestampMs: now - i * 1000,
      });
    }
    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: FILER, reason: DISPUTE_REASON.ORIGIN_MISMATCH, claimed_origin: "AG",
    });
    expect(r.valid).toBe(true);
  });
});
