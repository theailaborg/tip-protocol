/**
 * @file tests/db/knex-adapter-phash-order.test.js
 * @description getPhashCodesByCtid must return a video's frames in
 * (component_idx, frame) order whatever order they were written in: the
 * sampled video match compares evenly spaced frames of both sides, which only
 * line up on the same instants when both sides are in frame order.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const { KnexAdapter } = require("../../src/db/knex-adapter");

const logStub = { info() { }, warn() { }, error() { } };
const CTID = "tip://c/OH-phash-order-test";

function phashRow(componentIdx, frame) {
  const row = {
    ctid: CTID, component_idx: componentIdx, frame,
    profile: "cf-video-1", modality: "video", ts: frame / 5, quality: 100,
    pdq: (frame % 256).toString(16).padStart(2, "0").repeat(32),
  };
  for (let c = 0; c < 16; c++) row[`c${c}`] = (frame * 31 + c) & 0xffff;
  return row;
}

describe("phash rows read back in (component_idx, frame) order", () => {
  let a;
  let tmpDir;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-phash-order-"));
    a = new KnexAdapter("better-sqlite3", { dbName: path.join(tmpDir, "order.db") }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { a.close(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("scrambled writes across two components come back ordered", async () => {
    const n = 300;
    const rows = [];
    for (let i = 0; i < n; i++) rows.push(phashRow(1, (i * 173) % n)); // 173 coprime with 300: a permutation
    for (let i = 0; i < 20; i++) rows.push(phashRow(0, 19 - i));
    a.savePhashCodes(rows);
    await a._ffChain;

    const got = await a.getPhashCodesByCtid(CTID);
    expect(got).toHaveLength(n + 20);
    expect(got.slice(0, 20).map((r) => r.frame)).toEqual(Array.from({ length: 20 }, (_, i) => i));
    expect(got.slice(20).map((r) => r.frame)).toEqual(Array.from({ length: n }, (_, i) => i));
  });
});
