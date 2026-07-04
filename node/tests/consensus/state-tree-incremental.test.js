/**
 * @file tests/consensus/state-tree-incremental.test.js
 * @description The load-bearing invariant of #88: the incrementally
 * maintained state tree must ALWAYS equal a from-scratch rebuild, across
 * inserts, updates, deletes, and snapshot-style clears , and the streaming
 * verifier (createStateRootBuilder over iterateCanonicalState) must produce
 * the same root as the live dag.stateRoot(). If these ever disagree, honest
 * nodes fork.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { initCrypto, generateMLDSAKeypair, shake256 } =
  require(path.resolve(__dirname, "../../../shared/crypto"));
const PC = require(path.resolve(__dirname, "../../../shared/protocol-constants"));
const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const { initDAG } = require(path.resolve(__dirname, "../../src/dag"));
const { createStateRootBuilder } = require(path.resolve(__dirname, "../../src/consensus/state-root"));

beforeAll(async () => {
  PC.init(getGenesisPayload().protocol_constants);
  await initCrypto();
});

function streamingRoot(dag) {
  const b = createStateRootBuilder();
  for (const { table, row } of dag.iterateCanonicalState()) b.addRowObject(table, row);
  return b.finalize();
}

function newDag() { return initDAG({ inMemory: true }); }

const tip = (i) => `tip://id/US-${shake256("id" + i).slice(0, 16)}`;

const _kps = new Map();   // deterministic per index , two dags must agree
function kpFor(i) {
  if (!_kps.has(i)) _kps.set(i, generateMLDSAKeypair());
  return _kps.get(i);
}

function saveIdentity(dag, i, ts = 1783036800000) {
  const kp = kpFor(i);
  dag.saveIdentity({
    tip_id: tip(i), public_key: kp.publicKey, algorithm: "ml-dsa-65",
    region: "US", registered_at: ts, status: "active", verification_tier: "T1",
    dedup_hash: String(BigInt("0x" + shake256("d" + i).slice(0, 40))),
    tx_id: shake256("tx" + i),
  });
}

describe("#88 incremental state tree", () => {
  test("live root equals streaming-rebuild root after a mix of writes", () => {
    const dag = newDag();
    for (let i = 0; i < 60; i++) saveIdentity(dag, i);
    for (let i = 0; i < 30; i++) dag.setScore(tip(i), 400 + i, i % 3, 1783036800000 + i);
    for (let i = 0; i < 20; i++) dag.addDedupHash(String(BigInt("0x" + shake256("dd" + i).slice(0, 40))), 1783036800000 + i, tip(i));
    expect(dag.stateRoot()).toBe(streamingRoot(dag));
  });

  test("in-place rebuild reproduces the live root exactly", () => {
    const dag = newDag();
    for (let i = 0; i < 45; i++) saveIdentity(dag, i);
    for (let i = 0; i < 45; i++) dag.setScore(tip(i), 500 + i, 0, 1783036800000 + i);
    const live = dag.stateRoot();
    expect(dag.rebuildStateTree()).toBe(live);
    expect(dag.stateRoot()).toBe(live);      // rebuild left the tree intact
  });

  test("updates move the root and are path-independent", () => {
    const a = newDag(), b = newDag();
    for (let i = 0; i < 25; i++) { saveIdentity(a, i); saveIdentity(b, i); }
    // A scores ascending, B scores descending order , same final set
    for (let i = 0; i < 25; i++) a.setScore(tip(i), 600, 0, 1783036800000);
    for (let i = 24; i >= 0; i--) b.setScore(tip(i), 600, 0, 1783036800000);
    expect(a.stateRoot()).toBe(b.stateRoot());
    expect(a.stateRoot()).toBe(streamingRoot(a));
  });

  test("clearCanonicalState empties the tree and stays consistent with the walk", () => {
    const dag = newDag();
    for (let i = 0; i < 30; i++) saveIdentity(dag, i);
    const before = dag.stateRoot();
    dag.clearCanonicalState();
    expect(dag.stateRoot()).not.toBe(before);
    expect(dag.stateRoot()).toBe(streamingRoot(dag));   // both see zero rows
  });

  test("empty dag root matches the streaming builder's empty root", () => {
    const dag = newDag();
    expect(dag.stateRoot()).toBe(streamingRoot(dag));
  });
});
