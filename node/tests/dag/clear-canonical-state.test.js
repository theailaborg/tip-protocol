/**
 * @file tests/dag/clear-canonical-state.test.js
 * @description Regression: clearCanonicalState must purge EVERY table that
 * iterateCanonicalState yields, otherwise leftover rows survive a snapshot
 * install and contribute to state_merkle_root → permanent Merkle divergence
 * from the snapshot author.
 *
 * Bug fingerprint (pre-fix): clearCanonicalState in MemoryStore, SQLiteStore,
 * and KnexAdapter was missing `domain_bindings`, `prescan_reviews`, and
 * `interests_registry` — three tables that iterateCanonicalState yields into
 * the canonical projection. A node that had ever processed BIND_DOMAIN,
 * PRESCAN_REVIEW_TRIGGERED, or INTEREST_REGISTERED would compute a different
 * merkle root than a fresh snapshot author after install.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { computeStateMerkleRoot } = require(path.join(SRC, "consensus/state-root"));
const { PRESCAN_REVIEW_STATES } = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

function _setup() {
  return initDAG({ dbPath: ":memory:" });
}

function _seedAllCanonicalTables(dag) {
  // Plant at least one row in every table that iterateCanonicalState yields
  // so we can verify clearCanonicalState wipes everything.
  dag.saveIdentity({
    tip_id: "tip://id/US-aaaaaaaaaaaaaaaa", region: "US", public_key: "00",
    dedup_hash: "h1", zk_proof: "zk1", verification_tier: "T1",
    vp_id: "tip://vp/US-vvvvvvvvvvvvvvvv", status: "active",
    registered_at: 1000, tx_id: "tx_id_1", founding: false,
    reviewer_consent: false,
  });
  dag.saveContent({
    ctid: "tip://c/OH-1111111111111111-aaaa", origin_code: "OH",
    content_hash: "00".repeat(32), perceptual_hash: null,
    author_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa",
    signer_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa",
    authors: [], attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: "registered", override: false, registered_at: 1000,
    registered_urls: [], tx_id: "tx_content_1",
  });
  dag.saveDomainBinding({
    domain: "example.com", tip_id: "tip://id/US-aaaaaaaaaaaaaaaa",
    method: "dns", bound_at: 1000, tx_id: "tx_db_1",
  });
  dag.savePrescanReview({
    review_id: "rv_1", ctid: "tip://c/OH-1111111111111111-aaaa",
    creator_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa",
    assigned_reviewer: "tip://id/US-bbbbbbbbbbbbbbbb",
    triggered_at_round: 100, state: PRESCAN_REVIEW_STATES.TRIGGERED,
  });
  dag.saveInterest({
    slug: "ai-safety", label: "AI Safety", category: "tech",
    registered_at: 1000, registered_by_vp_id: "tip://vp/US-vvvvvvvvvvvvvvvv",
    tx_id: "tx_int_1",
  });
}

function _tablesIteratedByCanonicalState(dag) {
  const seen = new Set();
  for (const { table } of dag.iterateCanonicalState()) {
    seen.add(table);
  }
  return seen;
}

describe("clearCanonicalState — regression", () => {

  test("after clearCanonicalState, iterateCanonicalState yields zero rows from every table", () => {
    const dag = _setup();
    _seedAllCanonicalTables(dag);
    // Sanity: seeded rows are visible BEFORE clear
    const seenBefore = _tablesIteratedByCanonicalState(dag);
    expect(seenBefore.has("domain_bindings")).toBe(true);
    expect(seenBefore.has("prescan_reviews")).toBe(true);
    expect(seenBefore.has("interests_registry")).toBe(true);

    dag.clearCanonicalState();

    // After clear, the iterator must produce zero rows from any table.
    const yielded = [];
    for (const entry of dag.iterateCanonicalState()) yielded.push(entry);
    expect(yielded).toEqual([]);
  });

  test("domain_bindings is cleared (was missed pre-fix)", () => {
    const dag = _setup();
    _seedAllCanonicalTables(dag);
    dag.clearCanonicalState();
    expect(dag.getAllDomainBindings()).toEqual([]);
    expect(dag.getDomainBinding("example.com")).toBeNull();
  });

  test("prescan_reviews is cleared (was missed pre-fix)", () => {
    const dag = _setup();
    _seedAllCanonicalTables(dag);
    dag.clearCanonicalState();
    expect(dag.getPrescanReview("rv_1")).toBeNull();
  });

  test("interests_registry is cleared (was missed pre-fix)", () => {
    const dag = _setup();
    _seedAllCanonicalTables(dag);
    dag.clearCanonicalState();
    expect(dag.getInterest("ai-safety")).toBeNull();
  });

  test("two DAGs with different seed paths produce IDENTICAL state_merkle_root after clear", () => {
    // The promise of clearCanonicalState: any DAG, after clear, should look
    // identical from the merkle-root perspective. This proves the post-clear
    // state has zero canonical rows regardless of history.
    const a = _setup();
    a.clearCanonicalState();
    const rootA = computeStateMerkleRoot(a);

    const b = _setup();
    _seedAllCanonicalTables(b);
    // Sanity: seeded DAG produces a different root than the empty one
    expect(computeStateMerkleRoot(b)).not.toBe(rootA);
    b.clearCanonicalState();
    // After clear, root must match — proves NO canonical table escapes the
    // clear, including domain_bindings / prescan_reviews / interests_registry
    // which were missing pre-fix.
    expect(computeStateMerkleRoot(b)).toBe(rootA);
  });
});
