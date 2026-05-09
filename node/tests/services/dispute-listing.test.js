/**
 * @file tests/services/dispute-listing.test.js
 * @description Tests for the read-only dispute views:
 *
 *   - listDisputesForTipId(tipId)  → { filed_by_me, against_me, juror_active, appealable }
 *   - getDisputeById(idOrPrefix)   → full case + projected status + timeline
 *   - getDisputeTimeline(idOrPrefix) → ordered event list + projected status
 *
 * No new tx types are introduced. Status is a pure projection of the DAG at
 * call time, so the tests assemble the same tx shapes the write path emits
 * (CONTENT_DISPUTED, AI_CLASSIFIER_RESULT, JURY_SUMMONS, JURY_VOTE_COMMIT/
 * REVEAL, ADJUDICATION_RESULT, APPEAL_FILED, APPEAL_RESULT) and walk the
 * service directly. HTTP wiring is intentionally not exercised here.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, computeTxId, shake256 } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, CONTENT_STATUS, VERDICT } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createDisputeService } = require(path.join(SRC, "services", "dispute-service"));

beforeAll(async () => {
  await initCrypto();
});

const NODE_ID = "tip://node/test";
const VP_ID = "tip://vp/v1";
const AUTHOR = "tip://id/author";
const DISPUTER = "tip://id/disputer";
const JUROR_A = "tip://id/juror-a";
const JUROR_B = "tip://id/juror-b";

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
  for (const tipId of [AUTHOR, DISPUTER, JUROR_A, JUROR_B]) {
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${tipId}`),
    });
    dag.setScore(tipId, 750, 0, "2026-01-01T00:00:00.000Z");
  }

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const service = createDisputeService({ dag, scoring, config, submitTx: () => { }, submitBatch: () => { } });
  return { dag, scoring, config, service };
}

function _addTx(dag, body) {
  const tx = { ...body, prev: body.prev || dag.getRecentPrev() };
  tx.tx_id = computeTxId(tx);
  tx.signature = body.signature || "00";
  dag.addTx(tx);
  return tx;
}

function _seedContent(dag, ctid, authorTipId = AUTHOR, status = CONTENT_STATUS.REGISTERED) {
  dag.saveContent({
    ctid, origin_code: "OH", content_hash: shake256(`c:${ctid}`),
    author_tip_id: authorTipId, status,
    registered_at: "2026-04-01T00:00:00.000Z", tx_id: shake256(`reg:${ctid}`),
  });
}

function _fileDispute(dag, ctid, opts = {}) {
  return _addTx(dag, {
    tx_type: TX_TYPES.CONTENT_DISPUTED,
    timestamp: opts.ts || "2026-04-29T00:00:00.000Z",
    data: {
      ctid,
      disputer_tip_id: opts.disputer || DISPUTER,
      author_tip_id: opts.author || AUTHOR,
      reason: opts.reason || "origin_mismatch",
      claimed_origin: opts.claimed_origin || "AG",
      declared_origin: opts.declared_origin || "OH",
      evidence_hash: opts.evidence_hash || shake256("ev"),
      pre_dispute_status: CONTENT_STATUS.REGISTERED,
      stake: 50,
      signature: "00",
    },
  });
}

function _summonsTx(dag, ctid, jurorTipId, opts = {}) {
  return _addTx(dag, {
    tx_type: TX_TYPES.JURY_SUMMONS,
    timestamp: opts.ts || "2026-04-29T00:00:01.000Z",
    data: {
      ctid,
      dispute_tx_id: opts.dispute_tx_id,
      juror_tip_id: jurorTipId,
      stake: 10, seed: "seed", identity_count: 4,
      commit_deadline: opts.commit_deadline || new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      reveal_deadline: opts.reveal_deadline || new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
      is_appeal: !!opts.is_appeal,
      node_id: NODE_ID,
    },
  });
}

// ════════════════════════════════════════════════════════════════════════════
// 1. listDisputesForTipId — three-bucket projection
// ════════════════════════════════════════════════════════════════════════════

describe("listDisputesForTipId", () => {
  test("rejects missing or malformed tip_id", () => {
    const fx = _setup();
    expect(() => fx.service.listDisputesForTipId())
      .toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/required/) }));
    expect(() => fx.service.listDisputesForTipId("not-a-tip-id"))
      .toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/invalid format/i) }));
    expect(() => fx.service.listDisputesForTipId("tip://c/abc"))
      .toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/invalid format/i) }));
  });

  test("filed_by_me lists disputes the disputer filed", () => {
    const fx = _setup();
    _seedContent(fx.dag, "tip://c/x");
    _seedContent(fx.dag, "tip://c/y");
    const d1 = _fileDispute(fx.dag, "tip://c/x", { ts: "2026-04-29T00:00:00.000Z" });
    const d2 = _fileDispute(fx.dag, "tip://c/y", { ts: "2026-04-29T01:00:00.000Z" });

    const out = fx.service.listDisputesForTipId(DISPUTER);
    expect(out.filed_by_me).toHaveLength(2);
    const ids = out.filed_by_me.map(d => d.dispute_tx_id);
    expect(ids).toEqual(expect.arrayContaining([d1.tx_id, d2.tx_id]));
    expect(out.filed_by_me[0].dispute_id).toHaveLength(12);
    expect(out.filed_by_me[0].status).toBe("submitted");
    expect(out.against_me).toHaveLength(0);
  });

  test("against_me lists disputes against the author's content", () => {
    const fx = _setup();
    _seedContent(fx.dag, "tip://c/x");
    _fileDispute(fx.dag, "tip://c/x");

    const out = fx.service.listDisputesForTipId(AUTHOR);
    expect(out.against_me).toHaveLength(1);
    expect(out.against_me[0].author_tip_id).toBe(AUTHOR);
    expect(out.filed_by_me).toHaveLength(0);
  });

  test("juror_active includes summons that need a commit", () => {
    const fx = _setup();
    _seedContent(fx.dag, "tip://c/x");
    const d = _fileDispute(fx.dag, "tip://c/x");
    _summonsTx(fx.dag, "tip://c/x", JUROR_A, { dispute_tx_id: d.tx_id });

    const out = fx.service.listDisputesForTipId(JUROR_A);
    expect(out.juror_active).toHaveLength(1);
    expect(out.juror_active[0].action).toBe("commit_required");
    expect(out.juror_active[0].role).toBe("juror");
    expect(out.juror_active[0].dispute_id).toHaveLength(12);
  });

  test("juror_active drops jurors who already revealed", () => {
    const fx = _setup();
    _seedContent(fx.dag, "tip://c/x");
    const d = _fileDispute(fx.dag, "tip://c/x");
    _summonsTx(fx.dag, "tip://c/x", JUROR_A, { dispute_tx_id: d.tx_id });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.JURY_VOTE_COMMIT,
      timestamp: "2026-04-29T00:00:02.000Z",
      data: { ctid: "tip://c/x", juror_tip_id: JUROR_A, commitment: "x", signature: "00" },
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.JURY_VOTE_REVEAL,
      timestamp: "2026-04-29T00:00:03.000Z",
      data: { ctid: "tip://c/x", juror_tip_id: JUROR_A, vote: "MATCH", salt: "s", confirmed_origin: null, signature: "00" },
    });

    const out = fx.service.listDisputesForTipId(JUROR_A);
    expect(out.juror_active).toHaveLength(0);
  });

  test("juror_active reflects committed → reveal_required transition", () => {
    const fx = _setup();
    _seedContent(fx.dag, "tip://c/x");
    const d = _fileDispute(fx.dag, "tip://c/x");
    const past = new Date(Date.now() - 60 * 1000).toISOString();
    const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    _summonsTx(fx.dag, "tip://c/x", JUROR_A, {
      dispute_tx_id: d.tx_id,
      commit_deadline: past,
      reveal_deadline: future,
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.JURY_VOTE_COMMIT,
      timestamp: "2026-04-29T00:00:02.000Z",
      data: { ctid: "tip://c/x", juror_tip_id: JUROR_A, commitment: "x", signature: "00" },
    });

    const out = fx.service.listDisputesForTipId(JUROR_A);
    expect(out.juror_active).toHaveLength(1);
    expect(out.juror_active[0].action).toBe("reveal_required");
    expect(out.juror_active[0].committed).toBe(true);
  });

  test("appealable surfaces a verdict where caller is author and window is open", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid);
    _fileDispute(fx.dag, ctid);
    const recentVerdict = new Date(Date.now() - 60 * 1000).toISOString();
    _addTx(fx.dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: recentVerdict,
      data: { ctid, verdict: VERDICT.UPHELD, declared_origin: "OH", confirmed_origin: "AG", author_tip_id: AUTHOR, node_id: NODE_ID },
    });

    const authorView = fx.service.listDisputesForTipId(AUTHOR);
    expect(authorView.appealable).toHaveLength(1);
    expect(authorView.appealable[0].role).toBe("author");

    const disputerView = fx.service.listDisputesForTipId(DISPUTER);
    expect(disputerView.appealable).toHaveLength(1);
    expect(disputerView.appealable[0].role).toBe("disputer");
  });

  test("appealable hides verdicts already appealed", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid);
    _fileDispute(fx.dag, ctid);
    _addTx(fx.dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: new Date(Date.now() - 60 * 1000).toISOString(),
      data: { ctid, verdict: VERDICT.UPHELD, declared_origin: "OH", author_tip_id: AUTHOR, node_id: NODE_ID },
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.APPEAL_FILED,
      timestamp: new Date(Date.now() - 30 * 1000).toISOString(),
      data: { ctid, appellant_tip_id: AUTHOR, signature: "00", stage2_verdict: VERDICT.UPHELD, stake: 100 },
    });

    const out = fx.service.listDisputesForTipId(AUTHOR);
    expect(out.appealable).toHaveLength(0);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 2. getDisputeById — projection by short-id prefix
// ════════════════════════════════════════════════════════════════════════════

describe("getDisputeById", () => {
  test("rejects malformed dispute_id", () => {
    const fx = _setup();
    expect(() => fx.service.getDisputeById())
      .toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/required/) }));
    expect(() => fx.service.getDisputeById("nothex"))
      .toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/invalid format/i) }));
    expect(() => fx.service.getDisputeById("ab"))
      .toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/invalid format/i) }));
  });

  test("returns 404-shaped error when no match", () => {
    const fx = _setup();
    expect(() => fx.service.getDisputeById("deadbeef0000"))
      .toThrow(expect.objectContaining({ status: 404, error: expect.stringMatching(/not found/i) }));
  });

  test("resolves by 12-hex prefix and returns full case + timeline", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid);
    const d = _fileDispute(fx.dag, ctid);

    const out = fx.service.getDisputeById(d.tx_id.slice(0, 12));
    expect(out.dispute_tx_id).toBe(d.tx_id);
    expect(out.dispute_id).toBe(d.tx_id.slice(0, 12));
    expect(out.ctid).toBe(ctid);
    expect(out.status).toBe("submitted");
    expect(out.timeline).toHaveLength(1);
    expect(out.timeline[0].event).toBe("filed");
    expect(out.content.author_tip_id).toBe(AUTHOR);
    expect(out.verdict).toBeNull();
    expect(out.appeal).toBeNull();
  });

  test("status projects through commit/reveal/awaiting/resolved", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid);
    const d = _fileDispute(fx.dag, ctid);

    const futureCommit = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const futureReveal = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
    _summonsTx(fx.dag, ctid, JUROR_A, { dispute_tx_id: d.tx_id, commit_deadline: futureCommit, reveal_deadline: futureReveal });
    expect(fx.service.getDisputeById(d.tx_id).status).toBe("commit_phase");

    _addTx(fx.dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-30T00:00:00.000Z",
      data: { ctid, verdict: VERDICT.DISMISSED, declared_origin: "OH", author_tip_id: AUTHOR, node_id: NODE_ID },
    });
    expect(fx.service.getDisputeById(d.tx_id).status).toBe("resolved_dismissed");
  });

  test("appeal block populates after APPEAL_FILED + APPEAL_RESULT", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid);
    const d = _fileDispute(fx.dag, ctid);
    _addTx(fx.dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-30T00:00:00.000Z",
      data: { ctid, verdict: VERDICT.UPHELD, declared_origin: "OH", confirmed_origin: "AG", author_tip_id: AUTHOR, node_id: NODE_ID },
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.APPEAL_FILED,
      timestamp: "2026-04-30T01:00:00.000Z",
      data: { ctid, appellant_tip_id: AUTHOR, signature: "00", stage2_verdict: VERDICT.UPHELD, stake: 100 },
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.APPEAL_RESULT,
      timestamp: "2026-04-30T02:00:00.000Z",
      data: { ctid, verdict: VERDICT.DISMISSED, overturned: true, stage2_verdict: VERDICT.UPHELD, node_id: NODE_ID },
    });

    const out = fx.service.getDisputeById(d.tx_id);
    expect(out.appeal).not.toBeNull();
    expect(out.appeal.appellant_tip_id).toBe(AUTHOR);
    expect(out.appeal.verdict).toBe(VERDICT.DISMISSED);
    expect(out.appeal.overturned).toBe(true);
    expect(out.status).toBe("appeal_dismissed");
  });

  test("episode boundary — second dispute on same ctid does not bleed into first", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid);
    const d1 = _fileDispute(fx.dag, ctid, { ts: "2026-04-29T00:00:00.000Z" });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-29T12:00:00.000Z",
      data: { ctid, verdict: VERDICT.DISMISSED, declared_origin: "OH", author_tip_id: AUTHOR, node_id: NODE_ID },
    });
    const d2 = _fileDispute(fx.dag, ctid, {
      ts: "2026-05-01T00:00:00.000Z",
      disputer: JUROR_B,
    });

    const first = fx.service.getDisputeById(d1.tx_id);
    expect(first.status).toBe("resolved_dismissed");
    expect(first.timeline.map(e => e.event)).toEqual(["filed", "verdict"]);

    const second = fx.service.getDisputeById(d2.tx_id);
    expect(second.status).toBe("submitted");
    expect(second.timeline.map(e => e.event)).toEqual(["filed"]);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 3. getDisputeTimeline — light shape used for polling deadlines
// ════════════════════════════════════════════════════════════════════════════

describe("getDisputeTimeline", () => {
  test("returns ordered events with status", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid);
    const d = _fileDispute(fx.dag, ctid);
    _addTx(fx.dag, {
      tx_type: TX_TYPES.AI_CLASSIFIER_RESULT,
      timestamp: "2026-04-29T00:00:01.000Z",
      data: { ctid, dispute_tx_id: d.tx_id, confidence: 0.8, routing: "escalate", node_id: NODE_ID },
    });

    const out = fx.service.getDisputeTimeline(d.tx_id.slice(0, 12));
    expect(out.dispute_id).toBe(d.tx_id.slice(0, 12));
    expect(out.timeline.map(e => e.event)).toEqual(["filed", "ai_screening"]);
    expect(out.status).toBe("screening");
  });
});
