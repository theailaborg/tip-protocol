/**
 * @file tests/tx-attribution-multiparty.test.js
 * @description Multi-party activity attribution (#40). A dispute/appeal must
 * surface in the feed of EVERY party it concerns, not just the actor who filed
 * it. Two layers:
 *
 *   1. subjectTipIds(tx) — pure mapping returns all parties (deduped, primary
 *      actor first). Single-party txs return a 1-element array; org/system and
 *      auto-cascade disputes still surface to the author (their content).
 *   2. getTxsBySubject(tipId) — both the author's and the disputer's lookup
 *      return the whole lifecycle, proven on SQLiteStore and MemoryStore (the
 *      Knex read path delegates to the MemoryStore mirror).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../shared");
const SRC = path.resolve(__dirname, "../src");
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { subjectTipId, subjectTipIds } = require(path.join(SRC, "tx-attribution"));
const { MemoryStore, SQLiteStore } = require(path.join(SRC, "dag"));

const AUTHOR = "tip://id/IN-author";
const DISPUTER = "tip://id/IN-disputer";
const APPELLANT = "tip://id/IN-appellant";

describe("subjectTipIds — multi-party mappings (#40)", () => {
  test("CONTENT_DISPUTED (user) → [disputer, author]", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.CONTENT_DISPUTED, data: { disputer_tip_id: DISPUTER, author_tip_id: AUTHOR } }))
      .toEqual([DISPUTER, AUTHOR]);
  });
  test("CONTENT_DISPUTED (auto-cascade, window-expiry) → [author] (author sees the dispute on their content)", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.CONTENT_DISPUTED, data: { auto: true, author_tip_id: AUTHOR } }))
      .toEqual([AUTHOR]);
  });
  test("CONTENT_DISPUTED (auto-cascade, reviewer escalation) → [reviewer-disputer, escalating author]", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.CONTENT_DISPUTED, data: { auto: true, disputer_tip_id: DISPUTER, escalated_by_tip_id: AUTHOR } }))
      .toEqual([DISPUTER, AUTHOR]);
  });
  test("ADJUDICATION_RESULT → [author, disputer] (disputer now sees the verdict)", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.ADJUDICATION_RESULT, data: { author_tip_id: AUTHOR, disputer_tip_id: DISPUTER } }))
      .toEqual([AUTHOR, DISPUTER]);
  });
  test("APPEAL_FILED (user) → [appellant, author, disputer]", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.APPEAL_FILED, data: { appellant_tip_id: APPELLANT, author_tip_id: AUTHOR, disputer_tip_id: DISPUTER } }))
      .toEqual([APPELLANT, AUTHOR, DISPUTER]);
  });
  test("APPEAL_FILED dedups when appellant is one of the parties", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.APPEAL_FILED, data: { appellant_tip_id: DISPUTER, author_tip_id: AUTHOR, disputer_tip_id: DISPUTER } }))
      .toEqual([DISPUTER, AUTHOR]);
  });
  test("APPEAL_FILED auto-escalation → [author, disputer] (no human appellant)", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.APPEAL_FILED, data: { appellant_tip_id: "SYSTEM_AUTO_ESCALATION", author_tip_id: AUTHOR, disputer_tip_id: DISPUTER } }))
      .toEqual([AUTHOR, DISPUTER]);
  });
  test("APPEAL_RESULT → [author, disputer] (was unattributed/null before #40)", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.APPEAL_RESULT, data: { author_tip_id: AUTHOR, disputer_tip_id: DISPUTER } }))
      .toEqual([AUTHOR, DISPUTER]);
  });
  test("single-party tx unchanged (REGISTER_IDENTITY → [tip_id])", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.REGISTER_IDENTITY, data: { tip_id: AUTHOR } })).toEqual([AUTHOR]);
  });
  test("org/system tx → [] (VP_REGISTERED)", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.VP_REGISTERED, data: { vp_id: "tip://vp/x" } })).toEqual([]);
  });
  test("falsy / missing fields are dropped, never null entries", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.ADJUDICATION_RESULT, data: { author_tip_id: AUTHOR } })).toEqual([AUTHOR]);
    expect(subjectTipIds({ tx_type: TX_TYPES.APPEAL_RESULT, data: {} })).toEqual([]);
  });
  test("subjectTipId wrapper returns primary actor, or null", () => {
    expect(subjectTipId({ tx_type: TX_TYPES.ADJUDICATION_RESULT, data: { author_tip_id: AUTHOR, disputer_tip_id: DISPUTER } })).toBe(AUTHOR);
    expect(subjectTipId({ tx_type: TX_TYPES.VP_REGISTERED, data: {} })).toBe(null);
  });
});

function _seed(dag) {
  const mk = (tx_id, tx_type, data, ts) => ({ tx_id, tx_type, data, timestamp: ts, prev: [], signature: "00" });
  dag.saveTx(mk("disp1", TX_TYPES.CONTENT_DISPUTED, { ctid: "c1", disputer_tip_id: DISPUTER, author_tip_id: AUTHOR }, 1000));
  dag.saveTx(mk("adj1", TX_TYPES.ADJUDICATION_RESULT, { ctid: "c1", author_tip_id: AUTHOR, disputer_tip_id: DISPUTER, verdict: "DISMISSED" }, 2000));
  dag.saveTx(mk("apres1", TX_TYPES.APPEAL_RESULT, { ctid: "c1", author_tip_id: AUTHOR, disputer_tip_id: DISPUTER, verdict: "DISMISSED" }, 3000));
  dag.saveTx(mk("auto1", TX_TYPES.CONTENT_DISPUTED, { ctid: "c2", auto: true, author_tip_id: AUTHOR }, 4000));
}

const STORES = [
  ["SQLiteStore", () => new SQLiteStore(":memory:")],
  ["MemoryStore", () => new MemoryStore()],
];

describe.each(STORES)("getTxsBySubject both-party lifecycle — %s (#40)", (_name, make) => {
  let dag;
  beforeEach(() => { dag = make(); _seed(dag); });

  const ids = (tipId) => dag.getTxsBySubject(tipId).map(t => t.tx_id).sort();

  test("disputer sees the dispute, the verdict AND the appeal result", () => {
    expect(ids(DISPUTER)).toEqual(["adj1", "apres1", "disp1"]);
  });
  test("author sees the dispute, the verdict, the appeal result AND the auto-cascade dispute on their content", () => {
    expect(ids(AUTHOR)).toEqual(["adj1", "apres1", "auto1", "disp1"]);
  });
  test("auto-cascade dispute (no human disputer) is in the author's feed, not the disputer's", () => {
    expect(ids(AUTHOR)).toContain("auto1");
    expect(ids(DISPUTER)).not.toContain("auto1");
  });
  test("an uninvolved party sees nothing", () => {
    expect(ids("tip://id/IN-stranger")).toEqual([]);
  });
});

// ─── Completeness guard ──────────────────────────────────────────────────────
// Every TX_TYPES value MUST be explicitly classified in subjectTipIds — a new
// tx type that forgets attribution would silently fall through to [] and never
// surface in any feed. The EXPECTED map is the single source of truth for which
// parties each tx attributes to; multi-party types list all parties. The normal
// (non-auto, user-filed) path is encoded here — auto/dedup variants are covered
// by the targeted tests above.
describe("subjectTipIds — completeness guard (every tx_type classified)", () => {
  const EXPECTED = {
    // Self-affecting (subject IS the tip_id)
    [TX_TYPES.REGISTER_IDENTITY]: ["tip_id"],
    [TX_TYPES.UPDATE_DEVICE_BINDING]: ["tip_id"],
    [TX_TYPES.UPDATE_PROFILE]: ["tip_id"],
    [TX_TYPES.LINK_PLATFORM]: ["tip_id"],
    [TX_TYPES.UNLINK_PLATFORM]: ["tip_id"],
    [TX_TYPES.KEY_ROTATED]: ["tip_id"],
    [TX_TYPES.KEY_RECOVERY]: ["tip_id"],
    [TX_TYPES.SCORE_UPDATE]: ["tip_id"],
    [TX_TYPES.REVOKE_VOLUNTARY]: ["tip_id"],
    [TX_TYPES.REVOKE_VP]: ["tip_id"],
    [TX_TYPES.REVOKE_DECEASED]: ["tip_id"],
    [TX_TYPES.REVOKE_DEVICE]: ["tip_id"],
    [TX_TYPES.BIND_DOMAIN]: ["tip_id"],
    // Author / actor single-party
    [TX_TYPES.REGISTER_CONTENT]: ["signer_tip_id"],
    [TX_TYPES.UPDATE_ORIGIN]: ["author_tip_id"],
    [TX_TYPES.CONTENT_RETRACTED]: ["author_tip_id"],
    [TX_TYPES.CONTENT_VERIFIED]: ["verifier_tip_id"],
    [TX_TYPES.JURY_SUMMONS]: ["juror_tip_id"],
    [TX_TYPES.JURY_VOTE_COMMIT]: ["juror_tip_id"],
    [TX_TYPES.JURY_VOTE_REVEAL]: ["juror_tip_id"],
    // Multi-party — prescan reviews
    [TX_TYPES.PRESCAN_REVIEW_TRIGGERED]: ["assigned_reviewer_tip_id", "creator_tip_id"],
    [TX_TYPES.PRESCAN_REVIEW_DISMISSED]: ["reviewer_tip_id", "creator_tip_id"],
    [TX_TYPES.PRESCAN_REVIEW_CONFIRMED]: ["reviewer_tip_id", "creator_tip_id"],
    [TX_TYPES.PRESCAN_REVIEW_RECUSED]: ["reviewer_tip_id", "creator_tip_id"],
    // Multi-party — disputes & appeals (#40)
    [TX_TYPES.CONTENT_DISPUTED]: ["disputer_tip_id", "author_tip_id"],
    [TX_TYPES.ADJUDICATION_RESULT]: ["author_tip_id", "disputer_tip_id"],
    [TX_TYPES.APPEAL_FILED]: ["appellant_tip_id", "author_tip_id", "disputer_tip_id"],
    [TX_TYPES.APPEAL_RESULT]: ["author_tip_id", "disputer_tip_id"],
    // Org / system / consensus — no human party
    [TX_TYPES.PRESCAN_COMPLETED]: [],
    [TX_TYPES.UNBIND_DOMAIN]: [],
    [TX_TYPES.AI_CLASSIFIER_RESULT]: [],
    [TX_TYPES.VP_REGISTERED]: [],
    [TX_TYPES.VP_SUSPENDED]: [],
    [TX_TYPES.NODE_REGISTERED]: [],
    [TX_TYPES.NODE_ENDPOINT_UPDATED]: [],
    [TX_TYPES.INTEREST_REGISTERED]: [],
    [TX_TYPES.COMMITTEE_ROTATION]: [],
  };

  const ALL_FIELDS = [
    "tip_id", "signer_tip_id", "author_tip_id", "disputer_tip_id", "appellant_tip_id",
    "verifier_tip_id", "juror_tip_id", "reviewer_tip_id", "assigned_reviewer_tip_id", "creator_tip_id",
  ];

  test("every TX_TYPES value is explicitly classified (no silent default)", () => {
    const missing = Object.values(TX_TYPES).filter((t) => !(t in EXPECTED));
    expect(missing).toEqual([]);
  });

  test("subjectTipIds returns exactly the expected parties for each tx type", () => {
    for (const [type, fields] of Object.entries(EXPECTED)) {
      const data = {};
      for (const f of ALL_FIELDS) data[f] = `val:${f}`;   // unique value per field
      const got = subjectTipIds({ tx_type: type, data });
      expect(new Set(got)).toEqual(new Set(fields.map((f) => `val:${f}`)));
    }
  });
});
