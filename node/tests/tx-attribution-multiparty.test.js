/**
 * @file tests/tx-attribution-multiparty.test.js
 * @description Multi-party activity attribution (#40). A dispute/appeal must
 * surface in the feed of EVERY party it concerns, not just the actor who filed
 * it. Two layers:
 *
 *   1. subjectTipIds(tx) — pure mapping returns all parties (deduped, primary
 *      actor first). Single-party txs return a 1-element array; org/system and
 *      auto-cascade txs return [].
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
  test("CONTENT_DISPUTED (auto-cascade) → [] (still unattributed)", () => {
    expect(subjectTipIds({ tx_type: TX_TYPES.CONTENT_DISPUTED, data: { auto: true, author_tip_id: AUTHOR } }))
      .toEqual([]);
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
  test("author sees the dispute filed against them, the verdict AND the appeal result", () => {
    expect(ids(AUTHOR)).toEqual(["adj1", "apres1", "disp1"]);
  });
  test("auto-cascade dispute is in NOBODY's feed", () => {
    expect(ids(AUTHOR)).not.toContain("auto1");
    expect(ids(DISPUTER)).not.toContain("auto1");
  });
  test("an uninvolved party sees nothing", () => {
    expect(ids("tip://id/IN-stranger")).toEqual([]);
  });
});
