/**
 * @file tests/services/identity-activity.test.js
 * @description Activity-feed tests for the no-loss extension —
 * `getActivity(tipId, { include })`. Three concerns:
 *
 *   1. Broad-scope attribution via `subject_tip_id`. Verifiers,
 *      jurors, disputers, and appellants now appear in their own
 *      activity feed. Pre-fix the feed only matched
 *      `data.tip_id || data.author_tip_id`.
 *
 *   2. Merge of pending + rejected streams when ?include=
 *      pending,rejected is set. Lets a UI render
 *      "what happened to my submissions" in one call.
 *
 *   3. Default = committed only — preserves back-compat for clients
 *      that don't opt into the broader streams.
 *
 * Drives the service directly (not the Express router) so failures
 * point at the merge logic rather than at HTTP wiring. The route
 * is a thin pass-through.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, computeTxId, shake256 } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, TX_REJECTION_REASON, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createIdentityService } = require(path.join(SRC, "services", "identity-service"));

beforeAll(async () => {
  await initCrypto();
});

const NODE_ID = "tip://node/test";
const VP_ID = "tip://vp/v1";

// ─── Fixture: VP, two identities (author + juror), one content row ─────────
function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  dag.saveVP({
    vp_id: VP_ID, name: "vp1", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  for (const tipId of ["tip://id/author", "tip://id/juror", "tip://id/verifier"]) {
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: 1767225600000, tx_id: shake256(`id:${tipId}`),
    });
    dag.setScore(tipId, 750, 0, 1767225600000);
  }

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const service = createIdentityService({ dag, scoring, config, submitTx: () => { } });
  return { dag, scoring, config, service };
}

function _addTx(dag, body) {
  const tx = { ...body, prev: body.prev || dag.getRecentPrev() };
  tx.tx_id = computeTxId(tx);
  tx.signature = "00";
  dag.addTx(tx);
  return tx;
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Broad-scope attribution — jurors / verifiers see their own activity
// ═══════════════════════════════════════════════════════════════════════════

describe("getActivity — broad-scope attribution (option B)", () => {
  test("juror sees their JURY_VOTE_COMMIT in their feed", () => {
    const fx = _setup();
    const ctid = "tip://content/x";
    fx.dag.saveContent({
      ctid, origin_code: "OH", content_hash: shake256("c"),
      author_tip_id: "tip://id/author", status: CONTENT_STATUS.DISPUTED,
      registered_at: 1775001600000, tx_id: shake256("c:x"),
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.JURY_VOTE_COMMIT,
      timestamp: 1777420800000,
      data: { ctid, juror_tip_id: "tip://id/juror", commitment: "abc", node_id: NODE_ID },
    });

    // Pre-fix this would have returned 0 items — getTxsByTipId only
    // matched tip_id || author_tip_id, neither of which is the juror.
    const out = fx.service.getActivity("tip://id/juror");
    const types = out.items.map(i => i.tx_type);
    expect(types).toContain(TX_TYPES.JURY_VOTE_COMMIT);
    const item = out.items.find(i => i.tx_type === TX_TYPES.JURY_VOTE_COMMIT);
    expect(item.role).toBe("juror");
    expect(item.status).toBe("committed");
  });

  test("verifier sees their CONTENT_VERIFIED in their feed (NEW behavior)", () => {
    const fx = _setup();
    const ctid = "tip://content/y";
    fx.dag.saveContent({
      ctid, origin_code: "OH", content_hash: shake256("c"),
      author_tip_id: "tip://id/author", status: CONTENT_STATUS.REGISTERED,
      registered_at: 1775001600000, tx_id: shake256("c:y"),
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.CONTENT_VERIFIED,
      timestamp: 1777420800000,
      data: { ctid, verifier_tip_id: "tip://id/verifier", weighted_delta: 3, author_tip_id: "tip://id/author" },
    });

    const out = fx.service.getActivity("tip://id/verifier");
    expect(out.items.map(i => i.tx_type)).toContain(TX_TYPES.CONTENT_VERIFIED);
    expect(out.items.find(i => i.tx_type === TX_TYPES.CONTENT_VERIFIED).role).toBe("verifier");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. ?include filter — default committed-only, opt-in for pending+rejected
// ═══════════════════════════════════════════════════════════════════════════

describe("getActivity — ?include filter merges pending + rejected", () => {
  function _seedFeed(fx) {
    const tipId = "tip://id/author";
    // 1 committed REGISTER_CONTENT
    _addTx(fx.dag, {
      tx_type: TX_TYPES.REGISTER_CONTENT,
      timestamp: 1777420800000,
      data: { ctid: "tip://c/OH-aaaaaaaaaaaaaa-1111", origin_code: "OH",
        content_hash: shake256("c1"), signer_tip_id: tipId, signature: "00" },
    });
    // 1 pending REGISTER_CONTENT (still in mempool, never committed)
    fx.dag.saveMempoolTx({
      tx_id: "p".repeat(64),
      tx_type: TX_TYPES.REGISTER_CONTENT,
      timestamp: 1777510800000,
      data: { signer_tip_id: tipId, ctid: "tip://c/OH-bbbbbbbbbbbbbb-2222" },
    });
    // 1 rejected REGISTER_IDENTITY (full body preserved for replay)
    fx.dag.saveTxRejection({
      tx_id: "r".repeat(64),
      reason: TX_REJECTION_REASON.IDENTITY_ALREADY_REGISTERED,
      reason_detail: "Identity already registered",
      rejected_at_ms: 1_700_000_000_000,
      rejected_at_round: 99,
      dropper_node_id: NODE_ID,
      tx_type: TX_TYPES.REGISTER_IDENTITY,
      tx_data: {
        tx_id: "r".repeat(64),
        tx_type: TX_TYPES.REGISTER_IDENTITY,
        timestamp: 1777514400000,
        data: { tip_id: tipId, region: "US" },
      },
    });
    return tipId;
  }

  test("default (no ?include) returns committed only — back-compat preserved", () => {
    const fx = _setup();
    const tipId = _seedFeed(fx);

    const out = fx.service.getActivity(tipId);
    const statuses = new Set(out.items.map(i => i.status));
    expect(statuses).toEqual(new Set(["committed"]));
    expect(out.items.length).toBeGreaterThan(0);
  });

  test("?include=committed,pending merges pending into the feed", () => {
    const fx = _setup();
    const tipId = _seedFeed(fx);

    const out = fx.service.getActivity(tipId, { include: "committed,pending" });
    const statuses = new Set(out.items.map(i => i.status));
    expect(statuses).toEqual(new Set(["committed", "pending"]));
  });

  test("?include=rejected returns only the rejected tx with reason fields", () => {
    const fx = _setup();
    const tipId = _seedFeed(fx);

    const out = fx.service.getActivity(tipId, { include: "rejected" });
    expect(out.items.length).toBe(1);
    const item = out.items[0];
    expect(item.status).toBe("rejected");
    expect(item.reason).toBe(TX_REJECTION_REASON.IDENTITY_ALREADY_REGISTERED);
    expect(item.reason_detail).toBe("Identity already registered");
    expect(item.rejected_at).toBe(1_700_000_000_000);
    expect(item.rejected_at_round).toBe(99);
  });

  test("?include=committed,pending,rejected returns the full union", () => {
    const fx = _setup();
    const tipId = _seedFeed(fx);

    const out = fx.service.getActivity(tipId, { include: "committed,pending,rejected" });
    const statuses = new Set(out.items.map(i => i.status));
    expect(statuses).toEqual(new Set(["committed", "pending", "rejected"]));
    // Sorted DESC by timestamp — rejected (Apr-30 02:00) > pending
    // (Apr-30 01:00) > committed (Apr-29 00:00).
    const tsOrder = out.items.map(i => i.timestamp);
    expect(tsOrder).toEqual([...tsOrder].sort().reverse());
  });

  test("400 on unknown ?include value (clear error, not silent ignore)", () => {
    const fx = _setup();
    expect(() => fx.service.getActivity("tip://id/author", { include: "weird,banana" }))
      .toThrow(expect.objectContaining({
        status: 400,
        error: expect.stringContaining("Unknown status(es): weird, banana"),
      }));
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Negative — non-existent identity still 404s, even with ?include
// ═══════════════════════════════════════════════════════════════════════════

describe("getActivity — defensive paths", () => {
  test("404 on unknown tip_id (no DAG identity row)", () => {
    const fx = _setup();
    expect(() => fx.service.getActivity("tip://id/US-deadbeefdeadbeef"))
      .toThrow(expect.objectContaining({ status: 404, error: "TIP-ID not found" }));
  });

  test("?types still filters across all merged streams", () => {
    // ?types takes precedence over status — if a user asks "show me my
    // REGISTER_CONTENT activity across pending + committed", they want
    // those tx types only, regardless of stream.
    const fx = _setup();
    const tipId = "tip://id/author";

    _addTx(fx.dag, {
      tx_type: TX_TYPES.REGISTER_CONTENT,
      timestamp: 1775001600000,
      data: { ctid: "tip://c/OH-cccccccccccccc-3333", origin_code: "OH",
        content_hash: shake256("c2"), signer_tip_id: tipId, signature: "00" },
    });
    fx.dag.saveMempoolTx({
      tx_id: "q".repeat(64),
      tx_type: TX_TYPES.SCORE_UPDATE,  // different type — should be filtered out
      timestamp: 1777507200000,
      data: { tip_id: tipId, delta: 5, reason: "test" },
    });

    const out = fx.service.getActivity(tipId, {
      include: "committed,pending",
      types: TX_TYPES.REGISTER_CONTENT,
    });
    const types = new Set(out.items.map(i => i.tx_type));
    expect(types).toEqual(new Set([TX_TYPES.REGISTER_CONTENT]));
  });
});
