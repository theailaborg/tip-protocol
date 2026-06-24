/**
 * @file tests/protocol-params.test.js
 * @description The protocol_params temporal table (#39 Phase 1).
 *
 * What this pins:
 *   1. Genesis seeds every leaf of protocol_constants as a height-0 row, and
 *      the seeded value equals the genesis value byte-for-byte. This is the
 *      "no value moved" guard — the table is a faithful projection of the
 *      genesis params, not a re-interpretation.
 *   2. getProtocolParam resolves the ACTIVE value: the row with the greatest
 *      effective_from_height <= the queried height. A height>0 row shadows the
 *      seed only at/after its activation height — this is the replay-determinism
 *      contract (an old tx reads the value that was active at its height).
 *   3. The table is in state_merkle_root: MemoryStore and SQLiteStore emit
 *      byte-identical canonical rows, so two backends agree on every param.
 *   4. Rows are immutable per (param_key, effective_from_height): re-applying a
 *      row is a no-op (INSERT OR IGNORE), never a rewrite.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

const SRC = path.resolve(__dirname, "../src");
const SHARED = path.resolve(__dirname, "../../shared");
const { initDAG } = require(path.join(SRC, "dag"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));
const { canonicalJson } = require(path.join(SHARED, "crypto"));

// Same flatten rule the store seed uses: objects recurse, arrays/scalars leaf.
function flatten(obj, prefix = "", out = {}) {
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = v;
  }
  return out;
}

const GENESIS_FLAT = flatten(getGenesisPayload().protocol_constants);

let tmpDir;
const open = [];
beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-protocol-params-")); });
afterAll(() => {
  for (const d of open) { try { d.close(); } catch { /* closed */ } }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
let seq = 0;
function memDag() { const d = initDAG({ dbPath: ":memory:" }); open.push(d); return d; }
function sqlDag() { const d = initDAG({ dbPath: path.join(tmpDir, `pp-${seq++}.db`) }); open.push(d); return d; }

function ppRows(dag) {
  return [...dag.iterateCanonicalState()].filter(x => x.table === "protocol_params").map(x => x.row);
}

describe("protocol_params — genesis seed", () => {
  test("seeds one row per protocol_constants leaf at height 0", () => {
    const dag = memDag();
    const rows = ppRows(dag);
    expect(rows.length).toBe(Object.keys(GENESIS_FLAT).length);
    expect(rows.every(r => r.effective_from_height === 0)).toBe(true);
  });

  test("seeded value equals the genesis value for every key (no value moved)", () => {
    const dag = memDag();
    for (const key of Object.keys(GENESIS_FLAT)) {
      expect(dag.getProtocolParam(key)).toEqual(GENESIS_FLAT[key]);
    }
  });

  test("getActiveProtocolParams reconstructs the full flattened tree", () => {
    const dag = memDag();
    expect(dag.getActiveProtocolParams()).toEqual(GENESIS_FLAT);
  });
});

describe("protocol_params — temporal (as-of-height) reads", () => {
  test("a height>0 row shadows the seed only at/after its activation height", () => {
    const dag = memDag();
    const KEY = "jury.jury_stake";
    const seed = dag.getProtocolParam(KEY);          // genesis value
    dag.saveProtocolParam({ param_key: KEY, value: seed + 99, effective_from_height: 100, update_tx_id: "gov-tx-1" });

    // Before activation: still the seed (replay determinism for old txs).
    expect(dag.getProtocolParam(KEY, 0)).toEqual(seed);
    expect(dag.getProtocolParam(KEY, 99)).toEqual(seed);
    // At/after activation: the new value.
    expect(dag.getProtocolParam(KEY, 100)).toEqual(seed + 99);
    expect(dag.getProtocolParam(KEY, 1_000_000)).toEqual(seed + 99);
    // Default (no height) resolves to the latest.
    expect(dag.getProtocolParam(KEY)).toEqual(seed + 99);
  });

  test("getActiveProtocolParams is height-aware", () => {
    const dag = memDag();
    const KEY = "consensus.gc_depth";
    const seed = dag.getProtocolParam(KEY);
    dag.saveProtocolParam({ param_key: KEY, value: 999, effective_from_height: 50, update_tx_id: "gov-tx-2" });
    expect(dag.getActiveProtocolParams(49)[KEY]).toEqual(seed);
    expect(dag.getActiveProtocolParams(50)[KEY]).toEqual(999);
  });
});

describe("protocol_params — immutability", () => {
  test("re-applying a (param_key, height) row is a no-op, not a rewrite", () => {
    const dag = memDag();
    const KEY = "score.initial_identity";
    const seed = dag.getProtocolParam(KEY);
    // Attempt to overwrite the existing height-0 row with a different value.
    dag.saveProtocolParam({ param_key: KEY, value: seed + 1, effective_from_height: 0, update_tx_id: "evil" });
    expect(dag.getProtocolParam(KEY, 0)).toEqual(seed); // unchanged
  });
});

describe("protocol_params — cross-store determinism (state_merkle_root)", () => {
  test("MemoryStore and SQLiteStore emit byte-identical canonical rows", () => {
    const mem = memDag();
    const sql = sqlDag();
    expect(ppRows(sql).length).toBe(ppRows(mem).length);
    expect(canonicalJson(ppRows(sql))).toBe(canonicalJson(ppRows(mem)));
  });

  test("a height>0 governance row stays byte-identical across backends", () => {
    const mem = memDag();
    const sql = sqlDag();
    const rec = { param_key: "jury.appeal_stake", value: 42, effective_from_height: 7, update_tx_id: "gov-tx-3" };
    mem.saveProtocolParam(rec);
    sql.saveProtocolParam(rec);
    expect(canonicalJson(ppRows(sql))).toBe(canonicalJson(ppRows(mem)));
  });
});
