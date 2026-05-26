/**
 * @file tests/sync/snapshot-canonical-state-coverage.test.js
 * @description Regression guard: every table emitted by
 * `dag.iterateCanonicalState()` must have a matching case in
 * `snapshot-handler._installOneRow`.
 *
 * Why this guard exists:
 *   `iterateCanonicalState` is the canonical-state stream that feeds
 *   `computeStateMerkleRoot`. Every row in that stream participates in
 *   the consensus root.
 *
 *   The snapshot install path streams those same rows over the wire
 *   and calls `_installOneRow(table, row)` on the receiver. If a table
 *   is yielded by the iterator but NOT handled by `_installOneRow`, the
 *   row silently falls through to the `default` warn-and-drop branch.
 *   The joiner then has divergent local state from the rest of the
 *   federation — same merkle root claimed at install time, but the
 *   joiner's NEXT `computeStateMerkleRoot()` (e.g. on the next
 *   anti-entropy check) returns a different hash because their local
 *   table is empty.
 *
 * The test seeds at least one row in every canonical-state table on a
 * source DAG, streams the rows into a fresh sink DAG via
 * `_installOneRow`, then asserts the sink's `iterateCanonicalState`
 * yields the exact same row set. Any table that's emitted but not
 * installed shows up as a missing-row diff and fails the test.
 *
 * Removing any case from `_installOneRow` (e.g. `prescan_reviews` or
 * `interests_registry`) makes this test fail loudly.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { nowMs } = require(path.join(SHARED, "time"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createSnapshotHandler } = require(path.join(SRC, "sync", "snapshot-handler"));

beforeAll(async () => { await initCrypto(); });

function _tmpDbPath(label) {
  return path.join(os.tmpdir(), `tip-canon-cov-${label}-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
}

function _cleanup(dbPath) {
  for (const ext of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
}

/**
 * Populate the source DAG with at least one row in every table that
 * `iterateCanonicalState` is supposed to emit. When a new canonical-
 * state table is added (e.g. a future per-tx-type registry), seed it
 * here so the coverage assertion below still bites.
 */
function _seedCanonicalState(dag) {
  const ownerKp = generateMLDSAKeypair();
  const reviewerKp = generateMLDSAKeypair();
  const vpKp = generateMLDSAKeypair();
  const nodeKp = generateMLDSAKeypair();
  const T = 1779800000000;

  // VPs (also writes entity_keys row via auto-route)
  dag.saveVP({
    vp_id: "tip://vp/US-canontest",
    name: "Canon Test VP",
    jurisdiction: "US",
    jurisdiction_tier: "green",
    public_key: vpKp.publicKey,
    algorithm: "ml-dsa-65",
    status: "active",
    registered_at: T,
  });

  // Nodes (also writes entity_keys row)
  dag.saveNode({
    node_id: "tip://node/canontest",
    name: "Canon Test Node",
    public_key: nodeKp.publicKey,
    algorithm: "ml-dsa-65",
    status: "active",
    registered_at: T,
  });

  // Identities — personal (reviewer) + organization (content owner)
  dag.saveIdentity({
    tip_id: "tip://id/US-canontest-owner",
    region: "US",
    public_key: ownerKp.publicKey,
    algorithm: "ml-dsa-65",
    tip_id_type: "organization",
    status: "active",
    registered_at: T,
  });
  dag.saveIdentity({
    tip_id: "tip://id/US-canontest-reviewer",
    region: "US",
    public_key: reviewerKp.publicKey,
    algorithm: "ml-dsa-65",
    tip_id_type: "personal",
    status: "active",
    registered_at: T,
  });

  // Content
  dag.saveContent({
    ctid: "tip://ct/canontest-content-001",
    author_tip_id: "tip://id/US-canontest-owner",
    signer_tip_id: "tip://id/US-canontest-owner",
    origin_code: "OH",
    content_hash: "ab".repeat(32),
    cna_version: "2.2",
    authors: [],
    attribution_mode: "signer_authored",
    extras: {},
    registered_urls: [],
    status: "registered",
    registered_at: T,
  });

  // Scores
  dag.setScore("tip://id/US-canontest-owner", 700, 0, T);

  // Dedup registry
  dag.addDedupHash("dedup-canontest-001", T, "tip://id/US-canontest-owner");

  // Revocations
  dag.addRevocation(
    "tip://id/US-canontest-revoked",
    TX_TYPES.REVOKE_VOLUNTARY,
    T,
    "tx-canontest-revoke",
  );

  // Domain bindings
  dag.saveDomainBinding({
    domain: "canontest.example",
    tip_id: "tip://id/US-canontest-owner",
    binding_state: "verified",
    method: "auto",
    claimed_at: T,
    verified_at: T,
    expires_at: T + 30 * 24 * 60 * 60 * 1000,
    consecutive_failures: 0,
    node_id: "tip://node/canontest",
    claim_signature: "ab".repeat(32),
    binding_signature: "cd".repeat(32),
    tx_id: "tx-canontest-bind",
  });

  // Prescan reviews
  dag.savePrescanReview({
    review_id: "rv_canontest_001",
    ctid: "tip://ct/canontest-content-001",
    creator_tip_id: "tip://id/US-canontest-owner",
    assigned_reviewer: "tip://id/US-canontest-reviewer",
    triggered_at_round: 100,
    triggered_at_ms: T,
    state: "triggered",
  });

  // Interests registry — pre-seeded by _bootstrapInterestsRegistry on
  // first boot. Add one more to exercise the runtime-added shape.
  dag.saveInterest({
    slug: "canontest-extra",
    label: "Canon Test Extra Interest",
    category: "tech",
    registered_at: T,
    registered_by_vp_id: "tip://vp/US-canontest",
    tx_id: "tx-canontest-interest",
  });
}

/**
 * Materialize the source's canonical-state stream into a per-table
 * structure: { table -> [row, row, ...] }. Used both to drive the
 * install and to assert equality after install.
 */
function _collectCanonicalState(dag) {
  const out = {};
  for (const { table, row } of dag.iterateCanonicalState()) {
    (out[table] ||= []).push(row);
  }
  return out;
}

function _makeHandler(dag) {
  return createSnapshotHandler({
    dag,
    network: { node: {}, handle: async () => { } },
    isAuthorizedPeer: () => true,
  });
}

describe("snapshot install — canonical-state table coverage", () => {
  let sourceDbPath, sinkDbPath;
  let sourceDag, sinkDag;

  beforeEach(() => {
    sourceDbPath = _tmpDbPath("source");
    sinkDbPath = _tmpDbPath("sink");
    sourceDag = initDAG({ dbPath: sourceDbPath });
    sinkDag = initDAG({ dbPath: sinkDbPath });
  });

  afterEach(() => {
    try { sourceDag.close(); } catch { /* ignore */ }
    try { sinkDag.close(); } catch { /* ignore */ }
    _cleanup(sourceDbPath);
    _cleanup(sinkDbPath);
  });

  test("every table emitted by iterateCanonicalState is also installed by _installOneRow", () => {
    _seedCanonicalState(sourceDag);
    const sourceState = _collectCanonicalState(sourceDag);
    const sourceTables = Object.keys(sourceState).sort();

    // Sanity: the source actually has all the tables we expect. If
    // someone removes a table from iterateCanonicalState, this assertion
    // pins the expected coverage so the test still reflects reality.
    expect(sourceTables).toEqual(expect.arrayContaining([
      "identities",
      "content",
      "scores",
      "dedup_registry",
      "revocations",
      "verification_providers",
      "nodes",
      "entity_keys",
      "prescan_reviews",
      "interests_registry",
      "domain_bindings",
    ]));

    // Install every row into the sink via the exact snapshot-handler dispatcher.
    const handler = _makeHandler(sinkDag);
    for (const [table, rows] of Object.entries(sourceState)) {
      for (const row of rows) {
        handler._installOneRow(table, row);
      }
    }

    const sinkState = _collectCanonicalState(sinkDag);

    // For every table the source emitted, the sink must emit AT LEAST
    // the same rows. (Sink may emit more for tables that have a
    // bootstrap seed — e.g. interests_registry pre-installs the 30 seed
    // entries — but the source's runtime row must be present.)
    for (const table of sourceTables) {
      const sinkRows = sinkState[table] || [];
      for (const sourceRow of sourceState[table]) {
        const matched = sinkRows.some(r => _shallowEqual(r, sourceRow));
        if (!matched) {
          throw new Error(
            `Table "${table}" round-trip failed: source row not present on sink after install.\n` +
            `  source row: ${JSON.stringify(sourceRow)}\n` +
            `  sink has ${sinkRows.length} rows for this table\n` +
            `Likely cause: _installOneRow has no case for "${table}", so it fell through to the default warn-and-drop branch.\n` +
            `Add the missing case in node/src/sync/snapshot-handler.js _installOneRow.`,
          );
        }
      }
    }
  });

  test("a missing _installOneRow case is detected (negative control)", () => {
    // Simulate what would happen if a future change drops the handler
    // for a canonical-state table. We patch `_installOneRow` to skip
    // `interests_registry`, then assert the round-trip fails — proves
    // the assertion above actually catches drops, not just passes by
    // luck.
    _seedCanonicalState(sourceDag);
    const sourceState = _collectCanonicalState(sourceDag);

    const handler = _makeHandler(sinkDag);
    const installOneRow = handler._installOneRow;
    const skipping = "interests_registry";

    let droppedRowSurvived = true;
    for (const [table, rows] of Object.entries(sourceState)) {
      for (const row of rows) {
        if (table === skipping) continue;   // simulate the regression
        installOneRow(table, row);
      }
    }

    const sinkState = _collectCanonicalState(sinkDag);

    // Look for the source's runtime interests_registry row (NOT the
    // seed) on the sink. The seed rows pre-installed on the sink's
    // bootstrap will be there, but the source's runtime-added row
    // ("canontest-extra") should be missing because we skipped it.
    const runtimeSourceRow = sourceState[skipping].find(r => r.slug === "canontest-extra");
    expect(runtimeSourceRow).toBeDefined();

    const sinkHasRuntimeRow = (sinkState[skipping] || []).some(r => _shallowEqual(r, runtimeSourceRow));
    droppedRowSurvived = sinkHasRuntimeRow;

    // Negative control invariant: a dropped install case MUST leave the
    // sink missing the row. If this expectation flips to true, the
    // coverage assertion above is silently masking the drop and would
    // not catch a real regression.
    expect(droppedRowSurvived).toBe(false);
  });
});

function _shallowEqual(a, b) {
  if (a === b) return true;
  if (!a || !b || typeof a !== "object" || typeof b !== "object") return false;
  const ak = Object.keys(a);
  const bk = Object.keys(b);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    const av = a[k];
    const bv = b[k];
    if (av === bv) continue;
    if (Array.isArray(av) && Array.isArray(bv)) {
      if (av.length !== bv.length) return false;
      for (let i = 0; i < av.length; i++) if (!_shallowEqual(av[i], bv[i])) return false;
      continue;
    }
    if (av && bv && typeof av === "object" && typeof bv === "object") {
      if (!_shallowEqual(av, bv)) return false;
      continue;
    }
    return false;
  }
  return true;
}
