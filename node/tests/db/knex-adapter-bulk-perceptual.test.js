/**
 * @file tests/db/knex-adapter-bulk-perceptual.test.js
 * @description Bulk perceptual writes must chunk under the SQL bind-parameter
 * cap. A 6-minute audio clip's landmark set (~45k rows x 4 params) exceeded it
 * as one statement, so the whole write failed and the receiving node
 * fail-stopped (incident 2026-08-25).
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
const PROFILE = "cf-audio-landmark-1";

describe("bulk perceptual inserts chunk under the bind-parameter cap", () => {
  let a;
  let tmpDir;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-bulk-perc-"));
    a = new KnexAdapter("better-sqlite3", { dbName: path.join(tmpDir, "bulk.db") }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { a.close(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  async function count(table) {
    const row = await a.knex(table).count("* as n").first();
    return Number(row.n);
  }

  test("audio: a landmark set past the single-statement cap fully persists", async () => {
    // 20k rows x 4 params = 80k bind params, over both the Postgres (65535)
    // and SQLite (32766) caps if sent as one statement.
    const clipId = await a.getOrCreateAudioClip("tip://c/OH-bulkaudio-test", 0, 20000);
    const rows = [];
    for (let i = 0; i < 20000; i++) {
      rows.push({ profile: PROFILE, hash: i, clip_id: clipId, t: i % 4096 });
    }
    a.saveAudioLandmarks(rows);
    await a._ffChain;
    expect(await count("audio_landmark")).toBe(20000);
  });

  test("audio: chunked re-save of the same rows stays idempotent", async () => {
    const clipId = await a.getOrCreateAudioClip("tip://c/OH-bulkaudio-test", 0, 20000);
    const rows = [];
    for (let i = 0; i < 20000; i++) {
      rows.push({ profile: PROFILE, hash: i, clip_id: clipId, t: i % 4096 });
    }
    a.saveAudioLandmarks(rows);
    await a._ffChain;
    expect(await count("audio_landmark")).toBe(20000);
  });

  test("phash: a wide-row code set past the cap fully persists", async () => {
    // 24 columns per row: 2k rows = 48k bind params, over the SQLite cap.
    const rows = [];
    for (let i = 0; i < 2000; i++) {
      const row = {
        ctid: "tip://c/OH-bulkvideo-test", component_idx: 0, frame: i,
        profile: "cf-phash-pdq-1", modality: "video", ts: i / 5, quality: 100,
        pdq: "ab".repeat(32),
      };
      for (let c = 0; c < 16; c++) row[`c${c}`] = (i + c) & 0xffff;
      rows.push(row);
    }
    a.savePhashCodes(rows);
    await a._ffChain;
    expect(await count("phash_code")).toBe(2000);
  });

  test("minhash: small sets still persist through the chunked path", async () => {
    const rows = [];
    for (let b = 0; b < 32; b++) {
      rows.push({ ctid: "tip://c/OH-bulktext-test", profile: "cf-text-minhash-1", band_idx: b, band_hash: `h${b}` });
    }
    a.saveMinhashBands(rows);
    await a._ffChain;
    expect(await count("minhash_band")).toBe(32);
  });
});
