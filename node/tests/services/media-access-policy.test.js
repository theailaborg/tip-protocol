/**
 * @file tests/services/media-access-policy.test.js
 * @description Pure-predicate tests for canAccessMedia. No real DAG —
 * fake an in-memory dag interface so we can drive every branch.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { canAccessMedia } = require(path.resolve(__dirname, "../../src/services/media-access-policy"));
const { PRESCAN_REVIEW_STATES, TX_TYPES } = require(path.resolve(__dirname, "../../../shared/constants"));

// txsByTypeAndCtid: a map of "<TX_TYPE>|<ctid>" → array of tx-shaped objects
// for the juror / expert tests. Tests pass tx objects with the minimal data
// the predicate inspects (data.juror_tip_id, data.is_appeal).
function fakeDag({ content = null, openReview = null, disputerSet = new Set(), txsByTypeAndCtid = {} } = {}) {
  return {
    getContent: (ctid) => (content && content.ctid === ctid ? content : null),
    getOpenPrescanReviewByCtid: (ctid) => (openReview && openReview.ctid === ctid ? openReview : null),
    hasDispute: (ctid, tipId) => disputerSet.has(`${ctid}|${tipId}`),
    getTxsByTypeAndCtid: (type, ctid) => txsByTypeAndCtid[`${type}|${ctid}`] || [],
  };
}

const CTID = "tip://c/OH-aabbccddeeff11-1234";
const AUTHOR = "tip://id/US-aaaaaaaaaaaaaaaa";
const REVIEWER = "tip://id/US-bbbbbbbbbbbbbbbb";
const DISPUTER = "tip://id/US-cccccccccccccccc";
const JUROR = "tip://id/US-eeeeeeeeeeeeeeee";
const EXPERT = "tip://id/US-ffffffffffffffff";
const OUTSIDER = "tip://id/US-dddddddddddddddd";

describe("canAccessMedia — author", () => {
  test("content.signer_tip_id match → role=author", () => {
    const dag = fakeDag({ content: { ctid: CTID, signer_tip_id: AUTHOR } });
    expect(canAccessMedia(dag, CTID, AUTHOR)).toEqual({ ok: true, role: "author" });
  });

  test("unknown ctid → 404 content_not_found", () => {
    const dag = fakeDag({});
    expect(canAccessMedia(dag, CTID, AUTHOR)).toMatchObject({ ok: false, status: 404, code: "content_not_found" });
  });
});

describe("canAccessMedia — assigned reviewer", () => {
  test("open TRIGGERED review with matching reviewer → role=assigned_reviewer", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      openReview: { ctid: CTID, assigned_reviewer: REVIEWER, state: PRESCAN_REVIEW_STATES.TRIGGERED },
    });
    expect(canAccessMedia(dag, CTID, REVIEWER)).toEqual({ ok: true, role: "assigned_reviewer" });
  });

  test("CONFIRMED state is still open (accept-private / escalation window) → role=assigned_reviewer", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      openReview: { ctid: CTID, assigned_reviewer: REVIEWER, state: PRESCAN_REVIEW_STATES.CONFIRMED },
    });
    expect(canAccessMedia(dag, CTID, REVIEWER)).toEqual({ ok: true, role: "assigned_reviewer" });
  });

  test("closed review state → no longer assigned_reviewer, falls through to 403", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      openReview: { ctid: CTID, assigned_reviewer: REVIEWER, state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED },
    });
    expect(canAccessMedia(dag, CTID, REVIEWER)).toMatchObject({ ok: false, status: 403, code: "forbidden" });
  });

  test("reviewer tip_id mismatch on open review → 403", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      openReview: { ctid: CTID, assigned_reviewer: REVIEWER, state: PRESCAN_REVIEW_STATES.TRIGGERED },
    });
    expect(canAccessMedia(dag, CTID, OUTSIDER)).toMatchObject({ ok: false, status: 403, code: "forbidden" });
  });
});

describe("canAccessMedia — disputer", () => {
  test("hasDispute(ctid, tipId) true → role=disputer", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      disputerSet: new Set([`${CTID}|${DISPUTER}`]),
    });
    expect(canAccessMedia(dag, CTID, DISPUTER)).toEqual({ ok: true, role: "disputer" });
  });

  test("no dispute on file → 403", () => {
    const dag = fakeDag({ content: { ctid: CTID, signer_tip_id: AUTHOR } });
    expect(canAccessMedia(dag, CTID, DISPUTER)).toMatchObject({ ok: false, status: 403, code: "forbidden" });
  });
});

describe("canAccessMedia — priority + outsider", () => {
  test("author + reviewer + disputer roles — author wins (first match)", () => {
    // Author shouldn't normally also be reviewer or disputer of their
    // own content, but the predicate must be deterministic: highest
    // priority match returned. author is the priority head.
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      openReview: { ctid: CTID, assigned_reviewer: AUTHOR, state: PRESCAN_REVIEW_STATES.TRIGGERED },
      disputerSet: new Set([`${CTID}|${AUTHOR}`]),
    });
    expect(canAccessMedia(dag, CTID, AUTHOR).role).toBe("author");
  });

  test("plain outsider → 403", () => {
    const dag = fakeDag({ content: { ctid: CTID, signer_tip_id: AUTHOR } });
    expect(canAccessMedia(dag, CTID, OUTSIDER)).toMatchObject({ ok: false, status: 403, code: "forbidden" });
  });
});

describe("canAccessMedia — juror (Stage-2)", () => {
  test("non-appeal JURY_SUMMONS for requester + no ADJUDICATION_RESULT → role=juror", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      txsByTypeAndCtid: {
        [`${TX_TYPES.JURY_SUMMONS}|${CTID}`]: [
          { data: { juror_tip_id: JUROR, is_appeal: false } },
        ],
      },
    });
    expect(canAccessMedia(dag, CTID, JUROR)).toEqual({ ok: true, role: "juror" });
  });

  test("juror loses access once ADJUDICATION_RESULT lands", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      txsByTypeAndCtid: {
        [`${TX_TYPES.JURY_SUMMONS}|${CTID}`]: [{ data: { juror_tip_id: JUROR, is_appeal: false } }],
        [`${TX_TYPES.ADJUDICATION_RESULT}|${CTID}`]: [{ data: {} }],
      },
    });
    expect(canAccessMedia(dag, CTID, JUROR)).toMatchObject({ ok: false, status: 403, code: "forbidden" });
  });

  test("appeal-flagged summons does NOT grant juror role (those are experts)", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      txsByTypeAndCtid: {
        [`${TX_TYPES.JURY_SUMMONS}|${CTID}`]: [{ data: { juror_tip_id: JUROR, is_appeal: true } }],
      },
    });
    // Expert wins via the next branch — but for THIS juror tip_id with
    // only an appeal summons, the juror branch shouldn't fire.
    const out = canAccessMedia(dag, CTID, JUROR);
    expect(out.role).not.toBe("juror");
  });

  test("requester without summons → 403 (random outsider)", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      txsByTypeAndCtid: {
        [`${TX_TYPES.JURY_SUMMONS}|${CTID}`]: [{ data: { juror_tip_id: JUROR, is_appeal: false } }],
      },
    });
    expect(canAccessMedia(dag, CTID, OUTSIDER)).toMatchObject({ ok: false, status: 403 });
  });
});

describe("canAccessMedia — expert reviewer (Stage-3)", () => {
  test("appeal JURY_SUMMONS for requester + no APPEAL_RESULT → role=expert_reviewer", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      txsByTypeAndCtid: {
        [`${TX_TYPES.JURY_SUMMONS}|${CTID}`]: [{ data: { juror_tip_id: EXPERT, is_appeal: true } }],
      },
    });
    expect(canAccessMedia(dag, CTID, EXPERT)).toEqual({ ok: true, role: "expert_reviewer" });
  });

  test("expert loses access once APPEAL_RESULT lands", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      txsByTypeAndCtid: {
        [`${TX_TYPES.JURY_SUMMONS}|${CTID}`]: [{ data: { juror_tip_id: EXPERT, is_appeal: true } }],
        [`${TX_TYPES.APPEAL_RESULT}|${CTID}`]: [{ data: {} }],
      },
    });
    expect(canAccessMedia(dag, CTID, EXPERT)).toMatchObject({ ok: false, status: 403, code: "forbidden" });
  });

  test("non-appeal summons does NOT grant expert role (those are jurors)", () => {
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      txsByTypeAndCtid: {
        [`${TX_TYPES.JURY_SUMMONS}|${CTID}`]: [{ data: { juror_tip_id: EXPERT, is_appeal: false } }],
      },
    });
    expect(canAccessMedia(dag, CTID, EXPERT).role).not.toBe("expert_reviewer");
  });

  test("ADJUDICATION_RESULT does NOT close Stage-3 (only APPEAL_RESULT does)", () => {
    // Stage-2 closed, Stage-3 still open (appeal filed after the
    // adjudication and is still in-flight). Expert retains access.
    const dag = fakeDag({
      content: { ctid: CTID, signer_tip_id: AUTHOR },
      txsByTypeAndCtid: {
        [`${TX_TYPES.JURY_SUMMONS}|${CTID}`]: [{ data: { juror_tip_id: EXPERT, is_appeal: true } }],
        [`${TX_TYPES.ADJUDICATION_RESULT}|${CTID}`]: [{ data: {} }],
      },
    });
    expect(canAccessMedia(dag, CTID, EXPERT)).toEqual({ ok: true, role: "expert_reviewer" });
  });
});
