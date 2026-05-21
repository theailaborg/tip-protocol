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

  test("tip_id already registered → 409", () => {
    const dag = _seedDag();
    const r = rules.canRegisterIdentity(dag, {
      tip_id: "tip://id/author", dedup_hash: "fresh-hash", vp_id: "tip://vp/v1",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(409);
    expect(r.error.message).toMatch(/TIP-ID .* already registered/);
  });
});

// ─── canRegisterVp ──────────────────────────────────────────────────────────

describe("canRegisterVp", () => {
  test("free vp_id → valid", () => {
    const dag = _seedDag();
    const r = rules.canRegisterVp(dag, { vp_id: "tip://vp/new" });
    expect(r.valid).toBe(true);
  });

  test("vp_id already registered → 409", () => {
    const dag = _seedDag();
    const r = rules.canRegisterVp(dag, { vp_id: "tip://vp/v1" });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(409);
  });
});

// ─── canRegisterNode ────────────────────────────────────────────────────────

describe("canRegisterNode", () => {
  test("free node_id → valid", () => {
    const dag = _seedDag();
    const r = rules.canRegisterNode(dag, { node_id: "tip://node/fresh1111fresh22" });
    expect(r.valid).toBe(true);
  });

  test("node_id already registered → 409", () => {
    const dag = _seedDag();
    dag.saveNode({
      node_id: "tip://node/existing00001111", name: "n1", public_key: "00",
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
    const r = rules.canRegisterNode(dag, { node_id: "tip://node/existing00001111" });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(409);
  });
});

// ─── canRegisterContent ─────────────────────────────────────────────────────

describe("canRegisterContent", () => {
  test("valid signer + free ctid → valid", () => {
    const dag = _seedDag();
    const r = rules.canRegisterContent(dag, {
      signer_tip_id: "tip://id/author", ctid: "tip://content/new", origin_code: "OH",
    });
    expect(r.valid).toBe(true);
  });

  test("missing signer → 404", () => {
    const dag = _seedDag();
    const r = rules.canRegisterContent(dag, {
      signer_tip_id: "tip://id/missing", ctid: "tip://content/new", origin_code: "OH",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(404);
  });

  test("invalid origin_code → 400", () => {
    const dag = _seedDag();
    const r = rules.canRegisterContent(dag, {
      signer_tip_id: "tip://id/author", ctid: "tip://content/new", origin_code: "ZZ",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(400);
  });

  test("ctid already registered → 409", () => {
    const dag = _seedDag();
    const r = rules.canRegisterContent(dag, {
      signer_tip_id: "tip://id/author", ctid: "tip://content/x", origin_code: "OH",
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

  test("author cannot dispute their own content → 403", () => {
    const dag = _seedDag();
    const r = rules.canDispute(dag, STUB_SCORING, {
      ctid: "tip://content/x", disputer_tip_id: "tip://id/author",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
    expect(r.error.message).toMatch(/your own content/i);
  });

  test("signer (EMPLOYED / HOSTED mode) cannot dispute content they signed → 403", () => {
    const dag = _seedDag();
    // Override the seeded content row to model EMPLOYED attribution where
    // signer_tip_id != author_tip_id. The "you signed it" guard fires
    // independently of the author check.
    dag.saveContent({
      ctid: "tip://content/x", origin_code: "OH", content_hash: shake256("c1"),
      author_tip_id: "tip://id/author",
      signer_tip_id: "tip://id/disputer",
      status: CONTENT_STATUS.REGISTERED,
      registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256("content:x"),
    });
    const r = rules.canDispute(dag, STUB_SCORING, {
      ctid: "tip://content/x", disputer_tip_id: "tip://id/disputer",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
    expect(r.error.message).toMatch(/content you signed/i);
  });

  test("listed author in authors[] cannot dispute → 403", () => {
    const dag = _seedDag();
    dag.saveContent({
      ctid: "tip://content/x", origin_code: "OH", content_hash: shake256("c1"),
      author_tip_id: "tip://id/author",
      authors: [
        { tip_id: "tip://id/author", role: "primary" },
        { tip_id: "tip://id/disputer", role: "contributor" },
      ],
      status: CONTENT_STATUS.REGISTERED,
      registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256("content:x"),
    });
    const r = rules.canDispute(dag, STUB_SCORING, {
      ctid: "tip://content/x", disputer_tip_id: "tip://id/disputer",
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
    expect(r.error.message).toMatch(/listed as an author/i);
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

// ─── canCommitteeRotation (§4 + #34) ───────────────────────────────────────

describe("canCommitteeRotation", () => {
  const { generateMLDSAKeypair, mldsaSign, canonicalJson } = require(SHARED + "/crypto");
  const cryptoOpts = {
    shake256,
    canonicalJson,
    mldsaVerify: require(SHARED + "/crypto").mldsaVerify,
  };

  // Build a DAG with bootstrap rotation 0, then OVERRIDE rotation 0 with a
  // test committee whose private keys we control. Same setup pattern as
  // tests/consensus/commit-handler-committee-rotation.test.js — see that
  // file for why we have to bypass the genesis founding_node bootstrap.
  function _setupWithTestRotation0(size = 4) {
    const os = require("os");
    const fs = require("fs");
    const Database = require("better-sqlite3");
    const dbPath = path.join(os.tmpdir(), `tip-cot-rules-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);

    let dag = initDAG({ dbPath });
    dag.close();

    const committee = [];
    const keys = {};
    for (let i = 0; i < size; i++) {
      const kp = generateMLDSAKeypair();
      const node_id = `tip://node/test-${i}`;
      committee.push({ node_id, public_key: kp.publicKey });
      keys[node_id] = kp.privateKey;
    }
    committee.sort((a, b) => a.node_id.localeCompare(b.node_id));

    const raw = new Database(dbPath);
    raw.prepare("DELETE FROM committee_history").run();
    const payload_hash = shake256(canonicalJson({
      rotation_number: 0, effective_round: 0, committee,
    }));
    raw.prepare(
      `INSERT INTO committee_history (rotation_number, effective_round, committee, prev_rotation,
                                       signer_node_ids, signatures, payload_hash, committed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(0, 0, JSON.stringify(committee), null, '[]', '[]', payload_hash, '2026-01-01T00:00:00.000Z');
    raw.close();

    dag = initDAG({ dbPath });
    return { dag, committee, keys, dbPath };
  }

  function _signRotation(committee, keys, rec) {
    const payload_hash = shake256(canonicalJson({
      rotation_number: rec.rotation_number,
      effective_round: rec.effective_round,
      committee: rec.new_committee,
    }));
    const signers = committee.map(m => m.node_id);
    const signatures = signers.map(id => mldsaSign(`rotation:${payload_hash}:${id}`, keys[id]));
    return { ...rec, payload_hash, signer_node_ids: signers, signatures };
  }

  test("valid rotation 1 with full quorum sigs → valid", () => {
    const fx = _setupWithTestRotation0();
    try {
      const newCommittee = fx.committee.slice(0, 3);
      const rec = _signRotation(fx.committee, fx.keys, {
        rotation_number: 1, effective_round: 100, new_committee: newCommittee,
      });
      const r = rules.canCommitteeRotation(fx.dag, rec, cryptoOpts);
      expect(r.valid).toBe(true);
    } finally {
      fx.dag.close();
      try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
    }
  });

  test("rotation_number gap → 409", () => {
    const fx = _setupWithTestRotation0();
    try {
      const rec = _signRotation(fx.committee, fx.keys, {
        rotation_number: 2,  // skipping 1
        effective_round: 100, new_committee: fx.committee.slice(0, 3),
      });
      const r = rules.canCommitteeRotation(fx.dag, rec, cryptoOpts);
      expect(r.valid).toBe(false);
      expect(r.error.status).toBe(409);
      expect(r.error.message).toMatch(/non-monotonic/);
    } finally {
      fx.dag.close();
      try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
    }
  });

  test("malformed new_committee (no public_key) → 400", () => {
    const fx = _setupWithTestRotation0();
    try {
      const r = rules.canCommitteeRotation(fx.dag, {
        rotation_number: 1, effective_round: 100,
        new_committee: [{ node_id: "tip://node/x" }],
        payload_hash: "abc", signer_node_ids: [], signatures: [],
      }, cryptoOpts);
      expect(r.valid).toBe(false);
      expect(r.error.status).toBe(400);
    } finally {
      fx.dag.close();
      try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
    }
  });

  test("structural-only mode (no crypto helpers) → skips sig check", () => {
    const fx = _setupWithTestRotation0();
    try {
      // Without crypto opts, only structural + monotonicity checks run.
      // Useful for the proposer side to bail early before bothering with
      // signature collection.
      const r = rules.canCommitteeRotation(fx.dag, {
        rotation_number: 1, effective_round: 100,
        new_committee: fx.committee.slice(0, 3),
        // No payload_hash / signers / sigs — would fail crypto check
        payload_hash: "stub", signer_node_ids: [], signatures: [],
      }, /* no crypto opts */);
      expect(r.valid).toBe(true);
    } finally {
      fx.dag.close();
      try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
    }
  });

  // #68 Part A — quorum tightened from 2f+1 to ceil(2n/3).
  // Pre-fix: prevSize ≤ 3 → quorum=1 (single member could rotate alone).
  // Post-fix: prevSize=2→2, prevSize=3→2, prevSize=4→3, prevSize=5→4.
  describe("#68 Part A — ceil(2n/3) sig quorum", () => {
    function _signSubset(committee, keys, rec, signerCount) {
      const payload_hash = shake256(canonicalJson({
        rotation_number: rec.rotation_number,
        effective_round: rec.effective_round,
        committee: rec.new_committee,
      }));
      const signers = committee.slice(0, signerCount).map(m => m.node_id);
      const signatures = signers.map(id => mldsaSign(`rotation:${payload_hash}:${id}`, keys[id]));
      return { ...rec, payload_hash, signer_node_ids: signers, signatures };
    }

    test("prev size=2: 1 sig REJECTED (was accepted under 2f+1)", () => {
      const fx = _setupWithTestRotation0(2);
      try {
        const rec = _signSubset(fx.committee, fx.keys, {
          rotation_number: 1, effective_round: 100,
          new_committee: fx.committee.slice(0, 1),
        }, 1);
        const r = rules.canCommitteeRotation(fx.dag, rec, cryptoOpts);
        expect(r.valid).toBe(false);
        expect(r.error.status).toBe(403);
        expect(r.error.message).toMatch(/insufficient sigs.*need 2/);
      } finally {
        fx.dag.close();
        try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
      }
    });

    test("prev size=2: 2 sigs accepted", () => {
      const fx = _setupWithTestRotation0(2);
      try {
        const rec = _signSubset(fx.committee, fx.keys, {
          rotation_number: 1, effective_round: 100,
          new_committee: fx.committee,
        }, 2);
        const r = rules.canCommitteeRotation(fx.dag, rec, cryptoOpts);
        expect(r.valid).toBe(true);
      } finally {
        fx.dag.close();
        try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
      }
    });

    test("prev size=3: 1 sig REJECTED (was accepted under 2f+1)", () => {
      const fx = _setupWithTestRotation0(3);
      try {
        const rec = _signSubset(fx.committee, fx.keys, {
          rotation_number: 1, effective_round: 100,
          new_committee: fx.committee,
        }, 1);
        const r = rules.canCommitteeRotation(fx.dag, rec, cryptoOpts);
        expect(r.valid).toBe(false);
        expect(r.error.status).toBe(403);
        expect(r.error.message).toMatch(/insufficient sigs.*need 2/);
      } finally {
        fx.dag.close();
        try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
      }
    });

    test("prev size=3: 2 sigs accepted", () => {
      const fx = _setupWithTestRotation0(3);
      try {
        const rec = _signSubset(fx.committee, fx.keys, {
          rotation_number: 1, effective_round: 100,
          new_committee: fx.committee,
        }, 2);
        const r = rules.canCommitteeRotation(fx.dag, rec, cryptoOpts);
        expect(r.valid).toBe(true);
      } finally {
        fx.dag.close();
        try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
      }
    });

    test("prev size=4: 2 sigs REJECTED, 3 sigs accepted", () => {
      const fx = _setupWithTestRotation0(4);
      try {
        const recBad = _signSubset(fx.committee, fx.keys, {
          rotation_number: 1, effective_round: 100,
          new_committee: fx.committee,
        }, 2);
        let r = rules.canCommitteeRotation(fx.dag, recBad, cryptoOpts);
        expect(r.valid).toBe(false);
        expect(r.error.message).toMatch(/insufficient sigs.*need 3/);

        const recOk = _signSubset(fx.committee, fx.keys, {
          rotation_number: 1, effective_round: 100,
          new_committee: fx.committee,
        }, 3);
        r = rules.canCommitteeRotation(fx.dag, recOk, cryptoOpts);
        expect(r.valid).toBe(true);
      } finally {
        fx.dag.close();
        try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
      }
    });

    test("prev size=1: 1 sig accepted (genesis bootstrap)", () => {
      const fx = _setupWithTestRotation0(1);
      try {
        const rec = _signSubset(fx.committee, fx.keys, {
          rotation_number: 1, effective_round: 100,
          new_committee: fx.committee,
        }, 1);
        const r = rules.canCommitteeRotation(fx.dag, rec, cryptoOpts);
        expect(r.valid).toBe(true);
      } finally {
        fx.dag.close();
        try { require("fs").unlinkSync(fx.dbPath); } catch { /* ignore */ }
      }
    });
  });
});

// ─── canBindDomain ──────────────────────────────────────────────────────────

describe("canBindDomain", () => {
  function _makeFakeDag(bindings = {}) {
    return { getDomainBinding: (d) => bindings[d] || null };
  }

  test("no existing binding → valid", () => {
    const r = rules.canBindDomain(_makeFakeDag(), { tip_id: "tip://id/US-org1", domain: "acme.com" });
    expect(r.valid).toBe(true);
  });

  test("existing binding for SAME tip_id → valid (re-verify path)", () => {
    const dag = _makeFakeDag({
      "acme.com": { tip_id: "tip://id/US-org1", binding_state: "verified" },
    });
    const r = rules.canBindDomain(dag, { tip_id: "tip://id/US-org1", domain: "acme.com" });
    expect(r.valid).toBe(true);
  });

  test("existing VERIFIED binding for DIFFERENT tip_id → 409", () => {
    const dag = _makeFakeDag({
      "acme.com": { tip_id: "tip://id/US-org1", binding_state: "verified" },
    });
    const r = rules.canBindDomain(dag, { tip_id: "tip://id/US-org2", domain: "acme.com" });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(409);
    expect(r.error.message).toMatch(/already bound to a different TIP-ID/);
  });

  test("existing REVOKED binding for different tip_id → valid (claim becomes available)", () => {
    const dag = _makeFakeDag({
      "acme.com": { tip_id: "tip://id/US-org1", binding_state: "revoked" },
    });
    const r = rules.canBindDomain(dag, { tip_id: "tip://id/US-org2", domain: "acme.com" });
    expect(r.valid).toBe(true);
  });

  test("dag without getDomainBinding (older fixture) → valid no-op", () => {
    const r = rules.canBindDomain({}, { tip_id: "tip://id/US-org1", domain: "acme.com" });
    expect(r.valid).toBe(true);
  });
});
