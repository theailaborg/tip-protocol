/**
 * @file node/tests/dag/snapshot-raw-transfer.test.js
 * @description The snapshot must ship columns that are not part of the state
 * root (org_type, operated_by) or a resyncing node silently loses them, while
 * the hashing path must keep using the whitelist so a mixed-version fleet still
 * agrees on the root.
 */

"use strict";

const { MemoryStore, SQLiteStore } = require("../../src/dag");

function seed(store) {
  store.saveIdentity({
    tip_id: "tip://id/GB-1111111111111111",
    region: "GB",
    vp_id: "tip://vp/US-2222222222222222",
    verification_tier: "T1",
    tip_id_type: "organization",
    status: "active",
    registered_at: 1786000000000,
    creator_name: "ACME LTD",
    org_type: "private-limited-company",
  });
  store.saveNode({
    node_id: "tip://node/3333333333333333",
    name: "Acme Node",
    status: "active",
    registered_at: 1786000000000,
    operated_by: "tip://id/GB-1111111111111111",
  });
}

function rowsFor(store, table, opts) {
  const out = [];
  for (const entry of store.iterateCanonicalState(opts)) {
    if (entry.table === table) out.push(entry.row);
  }
  return out;
}

describe("snapshot raw transfer", () => {
  let store;
  beforeEach(() => { store = new MemoryStore(); seed(store); });

  test("hashing projection omits the non-root columns", () => {
    // No flag = the hashing path. These fields must NOT appear, or the root
    // would change and a mixed-version fleet would fork.
    expect(rowsFor(store, "identities")[0]).not.toHaveProperty("org_type");
    expect(rowsFor(store, "nodes")[0]).not.toHaveProperty("operated_by");
  });

  test("raw transfer carries the non-root columns", () => {
    expect(rowsFor(store, "identities", { rawTransfer: true })[0].org_type)
      .toBe("private-limited-company");
    expect(rowsFor(store, "nodes", { rawTransfer: true })[0].operated_by)
      .toBe("tip://id/GB-1111111111111111");
  });

  test("raw transfer does not change the state root", () => {
    // The whole safety argument: only the transfer form changes, never the
    // hashed form, so every node computes the same root regardless of version.
    const before = store.stateRoot();
    for (const _ of store.iterateCanonicalState({ rawTransfer: true })) { /* drain */ }
    expect(store.stateRoot()).toBe(before);
  });

  test("a node with the column and one without hash identically", () => {
    // Simulates patched vs unpatched: same data, one carries the extra column.
    const patched = new MemoryStore();
    const unpatched = new MemoryStore();
    const base = {
      tip_id: "tip://id/GB-4444444444444444",
      region: "GB", vp_id: null, verification_tier: "T1",
      tip_id_type: "organization", status: "active",
      registered_at: 1786000000000, creator_name: "SAME LTD",
    };
    patched.saveIdentity({ ...base, org_type: "llc" });
    unpatched.saveIdentity({ ...base });
    expect(patched.stateRoot()).toBe(unpatched.stateRoot());
  });

  test("contentRaw still works as an alias", () => {
    // An un-updated caller must not silently fall back to canonical rows.
    expect(rowsFor(store, "identities", { contentRaw: true })[0].org_type)
      .toBe("private-limited-company");
  });

  // Adapter parity: the Postgres path delegates to the mirror (MemoryStore)
  // with opts threaded through, so covering Memory + SQLite covers all three.
  test("SQLiteStore honours rawTransfer the same way", () => {
    let sq;
    try { sq = new SQLiteStore(":memory:"); }
    catch { return; }   // better-sqlite3 unavailable in this environment
    seed(sq);
    const canonIds = rowsFor(sq, "identities");
    const rawIds = rowsFor(sq, "identities", { rawTransfer: true });
    expect(canonIds[0]).not.toHaveProperty("org_type");
    expect(rawIds[0].org_type).toBe("private-limited-company");

    const canonNodes = rowsFor(sq, "nodes");
    const rawNodes = rowsFor(sq, "nodes", { rawTransfer: true });
    expect(canonNodes[0]).not.toHaveProperty("operated_by");
    expect(rawNodes[0].operated_by).toBe("tip://id/GB-1111111111111111");
  });
});
