/**
 * @file tests/validators/business-rules.test.js
 * @description Direct unit tests for the shared rule predicates.
 *
 * Covers each rule with at least one valid path and the most common
 * invalid paths. The whole point of this file is that the rules in
 * `validators/business-rules.js` are the single source of truth — if a
 * rule changes, this file is where the regression should fail loudly.
 *
 * Roundtrip behaviour (API accepts → state changes → commit drops) is
 * exercised in `tests/consensus/commit-handler-jury.test.js` and the
 * service-level tests; here we only test the pure predicate.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, computeTxId } = require(SHARED + "/crypto");
const { CONTENT_STATUS, TX_TYPES, VOTE } = require(SHARED + "/constants");
const { initDAG } = require(path.join(SRC, "dag"));
const rules = require(path.join(SRC, "validators", "business-rules"));

beforeAll(async () => { await initCrypto(); });

// ─── Fixture helpers ────────────────────────────────────────────────────────

function _seedDag() {
  const dag = initDAG({ dbPath: ":memory:" });

  // VP
  dag.saveVP({
    vp_id: "tip://vp/v1", name: "VP-1", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", root_public_key: "00", status: "active",
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("vp:v1"),
  });

  // Three identities: author, verifier, disputer
  for (const tipId of ["tip://id/author", "tip://id/verifier", "tip://id/disputer", "tip://id/juror"]) {
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
      vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${tipId}`),
    });
    dag.setScore(tipId, 750, 0, "2026-01-01T00:00:00.000Z");
  }

  // Content (status = REGISTERED)
  dag.saveContent({
    ctid: "tip://content/x", origin_code: "OH", content_hash: shake256("c1"),
    author_tip_id: "tip://id/author", status: CONTENT_STATUS.REGISTERED,
    registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256("content:x"),
  });

  return dag;
}

const STUB_SCORING = {
  getScore: (tipId) => ({ score: 750, tier: { name: "trusted" }, offense_count: 0 }),
};

// ─── canRegisterIdentity ────────────────────────────────────────────────────

describe("canRegisterIdentity", () => {
  test("VP active + dedup_hash unique → valid", () => {
    const dag = _seedDag();
    const r = rules.canRegisterIdentity(dag, { dedup_hash: "1234567890", vp_id: "tip://vp/v1" });
    expect(r.valid).toBe(true);
  });

  test("missing VP → 403", () => {
    const dag = _seedDag();
    const r = rules.canRegisterIdentity(dag, { dedup_hash: "x", vp_id: "tip://vp/missing" });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
  });

  test("dedup_hash already taken → 409", () => {
    const dag = _seedDag();
    dag.addDedupHash("1234567890", shake256("dup-tx"));
    const r = rules.canRegisterIdentity(dag, { dedup_hash: "1234567890", vp_id: "tip://vp/v1" });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(409);
  });
});

// ─── canRegisterContent ─────────────────────────────────────────────────────

describe("canRegisterContent", () => {
  test("valid author + free ctid → valid", () => {
    const dag = _seedDag();
    const r = rules.canRegisterContent(dag, {
      author_tip_id: "tip://id/author", ctid: "tip://content/new", origin_code: "OH",
    });
    expect(r.valid).toBe(true);
  });

  test("missing author → 404", () => {
    const dag = _seedDag();
    const r = rules.canRegisterContent(dag, {
      author_tip_id: "tip://id/missing", ctid: "tip://content/new", origin_code: "OH",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(404);
  });

  test("invalid origin_code → 400", () => {
    const dag = _seedDag();
    const r = rules.canRegisterContent(dag, {
      author_tip_id: "tip://id/author", ctid: "tip://content/new", origin_code: "ZZ",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(400);
  });

  test("ctid already registered → 409", () => {
    const dag = _seedDag();
    const r = rules.canRegisterContent(dag, {
      author_tip_id: "tip://id/author", ctid: "tip://content/x", origin_code: "OH",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(409);
  });
});

// ─── canVerify ──────────────────────────────────────────────────────────────

describe("canVerify", () => {
  test("happy path → valid", () => {
    const dag = _seedDag();
    const r = rules.canVerify(dag, {
      ctid: "tip://content/x", verifier_tip_id: "tip://id/verifier",
    });
    expect(r.valid).toBe(true);
  });

  test("self-verify → 403", () => {
    const dag = _seedDag();
    const r = rules.canVerify(dag, {
      ctid: "tip://content/x", verifier_tip_id: "tip://id/author",
    });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/your own/i);
  });

  test("retracted content → 403", () => {
    const dag = _seedDag();
    dag.saveContent({
      ctid: "tip://content/r", origin_code: "OH", content_hash: shake256("r"),
      author_tip_id: "tip://id/author", status: CONTENT_STATUS.RETRACTED,
      registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256("content:r"),
    });
    const r = rules.canVerify(dag, {
      ctid: "tip://content/r", verifier_tip_id: "tip://id/verifier",
    });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/retracted/i);
  });

  test("disputed content → 403", () => {
    const dag = _seedDag();
    dag.saveContent({
      ctid: "tip://content/d", origin_code: "OH", content_hash: shake256("d"),
      author_tip_id: "tip://id/author", status: CONTENT_STATUS.DISPUTED,
      registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256("content:d"),
    });
    const r = rules.canVerify(dag, {
      ctid: "tip://content/d", verifier_tip_id: "tip://id/verifier",
    });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/dispute/i);
  });
});

// ─── canDispute ─────────────────────────────────────────────────────────────

describe("canDispute", () => {
  test("score >= MIN + status REGISTERED → valid", () => {
    const dag = _seedDag();
    const r = rules.canDispute(dag, STUB_SCORING, {
      ctid: "tip://content/x", disputer_tip_id: "tip://id/disputer",
    });
    expect(r.valid).toBe(true);
  });

  test("disputer score below threshold → 403", () => {
    const dag = _seedDag();
    const lowScoring = { getScore: () => ({ score: 100 }) };
    const r = rules.canDispute(dag, lowScoring, {
      ctid: "tip://content/x", disputer_tip_id: "tip://id/disputer",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
  });

  test("content already disputed → 403", () => {
    const dag = _seedDag();
    dag.saveContent({
      ctid: "tip://content/d", origin_code: "OH", content_hash: shake256("d"),
      author_tip_id: "tip://id/author", status: CONTENT_STATUS.DISPUTED,
      registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256("content:d"),
    });
    const r = rules.canDispute(dag, STUB_SCORING, {
      ctid: "tip://content/d", disputer_tip_id: "tip://id/disputer",
    });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/already under dispute/i);
  });
});

// ─── canCommitVote ──────────────────────────────────────────────────────────

describe("canCommitVote", () => {
  function _seedSummons(dag, jurorTipId, commitDeadline, isAppeal = false) {
    const summonsBody = {
      tx_type: TX_TYPES.JURY_SUMMONS, timestamp: "2026-01-01T00:00:00.000Z", prev: [],
      data: {
        ctid: "tip://content/x", juror_tip_id: jurorTipId, dispute_tx_id: "d-1",
        commit_deadline: commitDeadline, reveal_deadline: "2099-01-01T00:00:00.000Z",
        is_appeal: isAppeal, node_id: "tip://node/n1",
      },
    };
    summonsBody.tx_id = computeTxId(summonsBody);
    summonsBody.signature = "00";
    dag.addTx(summonsBody);
  }

  test("summoned + within window → valid", () => {
    const dag = _seedDag();
    _seedSummons(dag, "tip://id/juror", "2026-04-30T00:00:00.000Z");
    const r = rules.canCommitVote(dag, {
      ctid: "tip://content/x", juror_tip_id: "tip://id/juror", is_appeal: false,
    }, { now: new Date("2026-04-15T00:00:00Z").getTime() });
    expect(r.valid).toBe(true);
  });

  test("not summoned → 403", () => {
    const dag = _seedDag();
    const r = rules.canCommitVote(dag, {
      ctid: "tip://content/x", juror_tip_id: "tip://id/juror", is_appeal: false,
    }, { now: Date.now() });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/not summoned/i);
  });

  test("commit window closed → 403", () => {
    const dag = _seedDag();
    _seedSummons(dag, "tip://id/juror", "2026-04-01T00:00:00.000Z");
    const r = rules.canCommitVote(dag, {
      ctid: "tip://content/x", juror_tip_id: "tip://id/juror", is_appeal: false,
    }, { now: new Date("2026-04-15T00:00:00Z").getTime() });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/Commit window has closed/);
  });
});

// ─── canRevealVote ──────────────────────────────────────────────────────────

describe("canRevealVote", () => {
  function _seedFlow(dag, jurorTipId, vote, salt) {
    const summonsBody = {
      tx_type: TX_TYPES.JURY_SUMMONS, timestamp: "2026-01-01T00:00:00.000Z", prev: [],
      data: {
        ctid: "tip://content/x", juror_tip_id: jurorTipId, dispute_tx_id: "d-1",
        commit_deadline: "2026-04-01T00:00:00.000Z", reveal_deadline: "2026-04-30T00:00:00.000Z",
        node_id: "tip://node/n1",
      },
    };
    summonsBody.tx_id = computeTxId(summonsBody);
    summonsBody.signature = "00";
    dag.addTx(summonsBody);

    const commitBody = {
      tx_type: TX_TYPES.JURY_VOTE_COMMIT, timestamp: "2026-04-01T00:00:00.000Z", prev: [],
      data: { ctid: "tip://content/x", juror_tip_id: jurorTipId, commitment: shake256(`${vote}:${salt}`), signature: "00" },
    };
    commitBody.tx_id = computeTxId(commitBody);
    dag.addTx(commitBody);
  }

  test("commitment matches + within window → valid", () => {
    const dag = _seedDag();
    _seedFlow(dag, "tip://id/juror", VOTE.MATCH, "saltA");
    const r = rules.canRevealVote(dag, {
      ctid: "tip://content/x", juror_tip_id: "tip://id/juror", is_appeal: false,
      vote: VOTE.MATCH, salt: "saltA",
    }, { now: new Date("2026-04-15T00:00:00Z").getTime(), shake256 });
    expect(r.valid).toBe(true);
  });

  test("commitment mismatch → 403", () => {
    const dag = _seedDag();
    _seedFlow(dag, "tip://id/juror", VOTE.MATCH, "saltA");
    const r = rules.canRevealVote(dag, {
      ctid: "tip://content/x", juror_tip_id: "tip://id/juror", is_appeal: false,
      vote: VOTE.MISMATCH, salt: "saltB",
    }, { now: new Date("2026-04-15T00:00:00Z").getTime(), shake256 });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/Vote does not match commitment/);
  });

  test("reveal window not yet open → 403", () => {
    const dag = _seedDag();
    _seedFlow(dag, "tip://id/juror", VOTE.MATCH, "saltA");
    const r = rules.canRevealVote(dag, {
      ctid: "tip://content/x", juror_tip_id: "tip://id/juror", is_appeal: false,
      vote: VOTE.MATCH, salt: "saltA",
    }, { now: new Date("2026-03-15T00:00:00Z").getTime(), shake256 });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/has not opened/);
  });

  test("reveal window closed → 403", () => {
    const dag = _seedDag();
    _seedFlow(dag, "tip://id/juror", VOTE.MATCH, "saltA");
    const r = rules.canRevealVote(dag, {
      ctid: "tip://content/x", juror_tip_id: "tip://id/juror", is_appeal: false,
      vote: VOTE.MATCH, salt: "saltA",
    }, { now: new Date("2026-05-15T00:00:00Z").getTime(), shake256 });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/has closed/);
  });
});

// ─── canRetract ─────────────────────────────────────────────────────────────

describe("canRetract", () => {
  test("author + status REGISTERED → valid", () => {
    const dag = _seedDag();
    const r = rules.canRetract(dag, { ctid: "tip://content/x", author_tip_id: "tip://id/author" });
    expect(r.valid).toBe(true);
  });

  test("non-author → 403", () => {
    const dag = _seedDag();
    const r = rules.canRetract(dag, { ctid: "tip://content/x", author_tip_id: "tip://id/verifier" });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
  });

  test("already retracted → 409", () => {
    const dag = _seedDag();
    dag.saveContent({
      ctid: "tip://content/r", origin_code: "OH", content_hash: shake256("r"),
      author_tip_id: "tip://id/author", status: CONTENT_STATUS.RETRACTED,
      registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256("content:r"),
    });
    const r = rules.canRetract(dag, { ctid: "tip://content/r", author_tip_id: "tip://id/author" });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(409);
  });

  test("disputed content → 403", () => {
    const dag = _seedDag();
    dag.saveContent({
      ctid: "tip://content/d", origin_code: "OH", content_hash: shake256("d"),
      author_tip_id: "tip://id/author", status: CONTENT_STATUS.DISPUTED,
      registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256("content:d"),
    });
    const r = rules.canRetract(dag, { ctid: "tip://content/d", author_tip_id: "tip://id/author" });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/under dispute/);
  });
});

// ─── canRevoke ──────────────────────────────────────────────────────────────

describe("canRevoke", () => {
  test("active VP + valid tx_type + identity exists → valid", () => {
    const dag = _seedDag();
    const r = rules.canRevoke(dag, {
      tx_type: TX_TYPES.REVOKE_VP, tip_id: "tip://id/author", issuing_vp_id: "tip://vp/v1",
    });
    expect(r.valid).toBe(true);
  });

  test("invalid tx_type → 400", () => {
    const dag = _seedDag();
    const r = rules.canRevoke(dag, {
      tx_type: "REVOKE_BANANA", tip_id: "tip://id/author", issuing_vp_id: "tip://vp/v1",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(400);
  });

  test("missing VP → 403", () => {
    const dag = _seedDag();
    const r = rules.canRevoke(dag, {
      tx_type: TX_TYPES.REVOKE_VP, tip_id: "tip://id/author", issuing_vp_id: "tip://vp/missing",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
  });

  test("missing identity → 404", () => {
    const dag = _seedDag();
    const r = rules.canRevoke(dag, {
      tx_type: TX_TYPES.REVOKE_VP, tip_id: "tip://id/missing", issuing_vp_id: "tip://vp/v1",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(404);
  });
});
