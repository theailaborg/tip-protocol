/**
 * @file tests/services/media-retention.test.js
 * @description M6 retention service — content sweep + orphan sweep.
 *
 * Drives the predicate via a fake DAG so the tests focus on retention
 * logic, not DAG plumbing. fs backend is used as a real storage to
 * exercise the delete + list contract end-to-end.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs/promises");
const os = require("os");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { TX_TYPES, PRESCAN_REVIEW_STATES } = require(path.join(SHARED, "constants"));
const { nowMs } = require(path.join(SHARED, "time"));
const { createMediaStorage } = require(path.join(SRC, "services/media-storage"));
const { createMediaRetention } = require(path.join(SRC, "services/media-retention"));

const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

beforeAll(() => {
  try { PC._resetForTesting(); } catch { /* not yet initialised */ }
  PC.init(getGenesisPayload().protocol_constants);
});

const CTID_A = "tip://c/OH-aaaaaaaaaaaaaa-1111";
const CTID_B = "tip://c/OH-bbbbbbbbbbbbbb-2222";
const DAY = 24 * 60 * 60 * 1000;

async function _scratch() {
  return fs.mkdtemp(path.join(os.tmpdir(), "tip-retention-"));
}

function _fakeDag({ contents = [], txsByTypeAndCtid = {}, openReviewByCtid = {} } = {}) {
  const byCtid = new Map(contents.map(c => [c.ctid, c]));
  return {
    getContent: (ctid) => byCtid.get(ctid) || null,
    getContentWithMediaBefore: (cutoff) => contents.filter(c =>
      (c.registered_at || 0) < cutoff
      && Array.isArray(c.media)
      && c.media.length > 0
    ),
    getReferencedMediaIds: () => {
      // Map<media_id, count> matches the real DAG contract — required
      // for dedup-safety predicate in sweepExpiredContent.
      const out = new Map();
      for (const c of contents) {
        for (const m of (c.media || [])) {
          if (m && typeof m.media_id === "string") {
            out.set(m.media_id, (out.get(m.media_id) || 0) + 1);
          }
        }
      }
      return out;
    },
    getOpenPrescanReviewByCtid: (ctid) => openReviewByCtid[ctid] || null,
    getTxsByTypeAndCtid: (type, ctid) => txsByTypeAndCtid[`${type}|${ctid}`] || [],
  };
}

async function _seedMedia(storage, label, mime = "image/png") {
  return storage.put(Buffer.from(label), { mime });
}

// ─── sweepExpiredContent ────────────────────────────────────────────────

describe("media-retention.sweepExpiredContent — happy path", () => {
  let root, storage;
  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
  });
  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("deletes media for ctid past retention window with no active roles", async () => {
    const m = await _seedMedia(storage, "alpha");
    const now = 1_800_000_000_000;
    const retention = 21 * DAY;
    const contents = [{
      ctid: CTID_A,
      registered_at: now - retention - DAY,  // expired by 1 day
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const ret = createMediaRetention({ dag: _fakeDag({ contents }), storage });
    const out = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(out.deleted).toBe(1);
    expect(out.skipped_active).toBe(0);
    expect((await storage.head(m.media_id)).exists).toBe(false);
  });
});

describe("media-retention.sweepExpiredContent — skip branches", () => {
  let root, storage;
  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
  });
  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  const retention = 21 * DAY;
  const now = 1_800_000_000_000;
  const expiredAt = now - retention - DAY;

  test("skips ctid with open dispute (CONTENT_DISPUTED > ADJUDICATION_RESULT)", async () => {
    const m = await _seedMedia(storage, "kept-by-dispute");
    const contents = [{
      ctid: CTID_A, registered_at: expiredAt,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const dag = _fakeDag({
      contents,
      txsByTypeAndCtid: {
        [`${TX_TYPES.CONTENT_DISPUTED}|${CTID_A}`]: [{ timestamp: expiredAt + DAY }],
      },
    });
    const ret = createMediaRetention({ dag, storage });
    const out = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(out.skipped_active).toBe(1);
    expect(out.deleted).toBe(0);
    expect((await storage.head(m.media_id)).exists).toBe(true);
  });

  test("skips ctid with open appeal (APPEAL_FILED > APPEAL_RESULT)", async () => {
    const m = await _seedMedia(storage, "kept-by-appeal");
    const contents = [{
      ctid: CTID_A, registered_at: expiredAt,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const dag = _fakeDag({
      contents,
      txsByTypeAndCtid: {
        [`${TX_TYPES.CONTENT_DISPUTED}|${CTID_A}`]: [{}],
        [`${TX_TYPES.ADJUDICATION_RESULT}|${CTID_A}`]: [{ timestamp: expiredAt }],
        [`${TX_TYPES.APPEAL_FILED}|${CTID_A}`]: [{ timestamp: expiredAt }],
      },
    });
    const ret = createMediaRetention({ dag, storage });
    const out = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(out.skipped_active).toBe(1);
    expect(out.deleted).toBe(0);
  });

  test("skips ctid with open prescan review (TRIGGERED / CONFIRMED)", async () => {
    const m = await _seedMedia(storage, "kept-by-review");
    const contents = [{
      ctid: CTID_A, registered_at: expiredAt,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const dag = _fakeDag({
      contents,
      openReviewByCtid: { [CTID_A]: { state: PRESCAN_REVIEW_STATES.TRIGGERED } },
    });
    const ret = createMediaRetention({ dag, storage });
    const out = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(out.skipped_active).toBe(1);
    expect(out.deleted).toBe(0);
  });

  test("respects cool-down clock: terminal APPEAL_RESULT 5 days ago → kept", async () => {
    // Cool-down clock anchors on the most recent terminal tx, not on
    // registered_at. If a dispute resolved yesterday, the 21-day window
    // restarts from then even if the content row is ancient.
    const m = await _seedMedia(storage, "cooling");
    const contents = [{
      ctid: CTID_A, registered_at: now - 365 * DAY,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const dag = _fakeDag({
      contents,
      txsByTypeAndCtid: {
        [`${TX_TYPES.APPEAL_FILED}|${CTID_A}`]: [{ timestamp: now - 30 * DAY }],
        [`${TX_TYPES.APPEAL_RESULT}|${CTID_A}`]: [{ timestamp: now - 5 * DAY }],
      },
    });
    const ret = createMediaRetention({ dag, storage });
    const out = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(out.skipped_cooling).toBe(1);
    expect(out.deleted).toBe(0);
    expect((await storage.head(m.media_id)).exists).toBe(true);
  });

  test("deletes when terminal tx is past the cool-down window", async () => {
    const m = await _seedMedia(storage, "post-cooldown");
    const contents = [{
      ctid: CTID_A, registered_at: now - 365 * DAY,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const dag = _fakeDag({
      contents,
      txsByTypeAndCtid: {
        [`${TX_TYPES.CONTENT_DISPUTED}|${CTID_A}`]: [{ timestamp: now - 90 * DAY }],
        [`${TX_TYPES.ADJUDICATION_RESULT}|${CTID_A}`]: [{ timestamp: now - 60 * DAY }],
      },
    });
    const ret = createMediaRetention({ dag, storage });
    const out = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(out.deleted).toBe(1);
  });
});

describe("media-retention.sweepExpiredContent — three-case retention clock", () => {
  let root, storage;
  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
  });
  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  const baseRetentionMs = 21 * DAY;
  const postAdjudicationMs = 7 * DAY;
  const postAppealMs = 7 * DAY;
  const now = 1_800_000_000_000;
  const opts = { baseRetentionMs, postAdjudicationMs, postAppealMs };

  test("CASE 1 — never disputed: deletable at registered_at + 21d (not before)", async () => {
    const m = await _seedMedia(storage, "case1-keep");
    // Just under 21d → keep
    const contents = [{
      ctid: CTID_A, registered_at: now - 21 * DAY + DAY,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const ret = createMediaRetention({ dag: _fakeDag({ contents }), storage });
    const out = await ret.sweepExpiredContent({ now, ...opts });
    // Pre-filter excludes rows registered after now - baseRetentionMs
    expect(out.candidates).toBe(0);
    expect((await storage.head(m.media_id)).exists).toBe(true);
  });

  test("CASE 1 — never disputed: registered 22d ago → DELETED", async () => {
    const m = await _seedMedia(storage, "case1-delete");
    const contents = [{
      ctid: CTID_A, registered_at: now - 22 * DAY,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const ret = createMediaRetention({ dag: _fakeDag({ contents }), storage });
    const out = await ret.sweepExpiredContent({ now, ...opts });
    expect(out.deleted).toBe(1);
  });

  test("CASE 2 — only ADJUDICATION_RESULT: 6d after adjudication → kept (cool-down)", async () => {
    // Registered 60d ago — would be eligible under case 1, but the
    // adjudication 6d ago wins and pushes the clock back.
    const m = await _seedMedia(storage, "case2-keep");
    const contents = [{
      ctid: CTID_A, registered_at: now - 60 * DAY,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const dag = _fakeDag({
      contents,
      txsByTypeAndCtid: {
        [`${TX_TYPES.CONTENT_DISPUTED}|${CTID_A}`]: [{ timestamp: now - 10 * DAY }],
        [`${TX_TYPES.ADJUDICATION_RESULT}|${CTID_A}`]: [{ timestamp: now - 6 * DAY }],
      },
    });
    const ret = createMediaRetention({ dag, storage });
    const out = await ret.sweepExpiredContent({ now, ...opts });
    expect(out.skipped_cooling).toBe(1);
    expect(out.deleted).toBe(0);
  });

  test("CASE 2 — only ADJUDICATION_RESULT: 8d after adjudication → DELETED", async () => {
    const m = await _seedMedia(storage, "case2-delete");
    const contents = [{
      ctid: CTID_A, registered_at: now - 60 * DAY,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const dag = _fakeDag({
      contents,
      txsByTypeAndCtid: {
        [`${TX_TYPES.CONTENT_DISPUTED}|${CTID_A}`]: [{ timestamp: now - 14 * DAY }],
        [`${TX_TYPES.ADJUDICATION_RESULT}|${CTID_A}`]: [{ timestamp: now - 8 * DAY }],
      },
    });
    const ret = createMediaRetention({ dag, storage });
    const out = await ret.sweepExpiredContent({ now, ...opts });
    expect(out.deleted).toBe(1);
  });

  test("CASE 3 — APPEAL_RESULT: 6d after appeal → kept; 8d → DELETED", async () => {
    const mKeep = await _seedMedia(storage, "case3-keep");
    const mDel  = await _seedMedia(storage, "case3-delete");
    const contents = [
      { ctid: CTID_A, registered_at: now - 60 * DAY,
        media: [{ media_id: mKeep.media_id, mime: "image/png" }] },
      { ctid: CTID_B, registered_at: now - 60 * DAY,
        media: [{ media_id: mDel.media_id, mime: "image/png" }] },
    ];
    const dag = _fakeDag({
      contents,
      txsByTypeAndCtid: {
        // CTID_A appeal-resolved 6d ago — still cooling
        [`${TX_TYPES.APPEAL_RESULT}|${CTID_A}`]: [{ timestamp: now - 6 * DAY }],
        // CTID_B appeal-resolved 8d ago — past cool-down
        [`${TX_TYPES.APPEAL_RESULT}|${CTID_B}`]: [{ timestamp: now - 8 * DAY }],
      },
    });
    const ret = createMediaRetention({ dag, storage });
    const out = await ret.sweepExpiredContent({ now, ...opts });
    expect(out.deleted).toBe(1);
    expect(out.skipped_cooling).toBe(1);
    expect((await storage.head(mKeep.media_id)).exists).toBe(true);
    expect((await storage.head(mDel.media_id)).exists).toBe(false);
  });

  test("CASE 3 — APPEAL_RESULT wins even when older adjudication exists", async () => {
    // Adjudication 30d ago would say "delete." But appeal-result 5d ago
    // pushes the clock forward.
    const m = await _seedMedia(storage, "appeal-overrides-adj");
    const contents = [{
      ctid: CTID_A, registered_at: now - 60 * DAY,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const dag = _fakeDag({
      contents,
      txsByTypeAndCtid: {
        [`${TX_TYPES.ADJUDICATION_RESULT}|${CTID_A}`]: [{ timestamp: now - 30 * DAY }],
        [`${TX_TYPES.APPEAL_FILED}|${CTID_A}`]:        [{ timestamp: now - 29 * DAY }],
        [`${TX_TYPES.APPEAL_RESULT}|${CTID_A}`]:       [{ timestamp: now - 5 * DAY }],
      },
    });
    const ret = createMediaRetention({ dag, storage });
    const out = await ret.sweepExpiredContent({ now, ...opts });
    expect(out.skipped_cooling).toBe(1);
    expect(out.deleted).toBe(0);
  });
});

describe("media-retention.sweepExpiredContent — dedup safety", () => {
  let root, storage;
  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
  });
  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("media_id referenced by two ctids — only one expired → bytes kept", async () => {
    // Same author posts the same image twice → dedup at storage means
    // single media_id, but two content rows reference it. If only one
    // row is past retention, we MUST keep the bytes for the other.
    const m = await _seedMedia(storage, "shared");
    const now = 1_800_000_000_000;
    const retention = 21 * DAY;
    const contents = [
      {
        ctid: CTID_A, registered_at: now - retention - 5 * DAY,
        media: [{ media_id: m.media_id, mime: "image/png" }]
      },
      {
        ctid: CTID_B, registered_at: now - DAY,    // fresh, not expired
        media: [{ media_id: m.media_id, mime: "image/png" }]
      },
    ];
    const ret = createMediaRetention({ dag: _fakeDag({ contents }), storage });
    const out = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(out.shared_with_active_ctid).toBe(1);
    expect(out.deleted).toBe(0);
    expect((await storage.head(m.media_id)).exists).toBe(true);
  });

  test("media_id referenced by two ctids — BOTH expired → bytes deleted", async () => {
    const m = await _seedMedia(storage, "shared-both-expired");
    const now = 1_800_000_000_000;
    const retention = 21 * DAY;
    const contents = [
      {
        ctid: CTID_A, registered_at: now - retention - 10 * DAY,
        media: [{ media_id: m.media_id, mime: "image/png" }]
      },
      {
        ctid: CTID_B, registered_at: now - retention - 5 * DAY,
        media: [{ media_id: m.media_id, mime: "image/png" }]
      },
    ];
    const ret = createMediaRetention({ dag: _fakeDag({ contents }), storage });
    const out = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(out.deleted).toBe(1);
    expect((await storage.head(m.media_id)).exists).toBe(false);
  });
});

describe("media-retention.sweepExpiredContent — idempotency", () => {
  let root, storage;
  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
  });
  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("re-running sweep after a delete doesn't throw; missing counter increments", async () => {
    const m = await _seedMedia(storage, "idem");
    const now = 1_800_000_000_000;
    const retention = 21 * DAY;
    const contents = [{
      ctid: CTID_A, registered_at: now - retention - DAY,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const ret = createMediaRetention({ dag: _fakeDag({ contents }), storage });
    const first = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(first.deleted).toBe(1);

    const second = await ret.sweepExpiredContent({ now, baseRetentionMs: retention, postAdjudicationMs: 7 * DAY, postAppealMs: 7 * DAY });
    expect(second.deleted).toBe(0);
    expect(second.missing).toBe(1);
  });
});

// ─── sweepOrphanUploads ─────────────────────────────────────────────────

describe("media-retention.sweepOrphanUploads", () => {
  let root, storage;
  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
  });
  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("deletes unreferenced media older than orphan window", async () => {
    const m = await _seedMedia(storage, "orphan-old");
    // Touch the sidecar so its created_at is 48h old (past 24h window).
    const metaPath = path.join(root, m.media_id.slice(0, 2), `${m.media_id.slice(2)}.meta.json`);
    const raw = JSON.parse(await fs.readFile(metaPath, "utf8"));
    const now = nowMs();
    raw.created_at = now - 48 * 60 * 60 * 1000;
    await fs.writeFile(metaPath, JSON.stringify(raw));

    const ret = createMediaRetention({ dag: _fakeDag({ contents: [] }), storage });
    const out = await ret.sweepOrphanUploads({ now, orphanWindowMs: 24 * 60 * 60 * 1000 });
    expect(out.deleted).toBe(1);
    expect((await storage.head(m.media_id)).exists).toBe(false);
  });

  test("keeps unreferenced media within orphan window (user still in flow)", async () => {
    const m = await _seedMedia(storage, "orphan-fresh");
    const ret = createMediaRetention({ dag: _fakeDag({ contents: [] }), storage });
    const out = await ret.sweepOrphanUploads({ now: nowMs(), orphanWindowMs: 24 * 60 * 60 * 1000 });
    expect(out.deleted).toBe(0);
    expect(out.kept_recent).toBe(1);
    expect((await storage.head(m.media_id)).exists).toBe(true);
  });

  test("keeps referenced media even if old (content-sweep's job, not orphan's)", async () => {
    const m = await _seedMedia(storage, "referenced-old");
    const metaPath = path.join(root, m.media_id.slice(0, 2), `${m.media_id.slice(2)}.meta.json`);
    const raw = JSON.parse(await fs.readFile(metaPath, "utf8"));
    const now = nowMs();
    raw.created_at = now - 90 * DAY;
    await fs.writeFile(metaPath, JSON.stringify(raw));

    const contents = [{
      ctid: CTID_A, registered_at: now - DAY,
      media: [{ media_id: m.media_id, mime: "image/png" }],
    }];
    const ret = createMediaRetention({ dag: _fakeDag({ contents }), storage });
    const out = await ret.sweepOrphanUploads({ now, orphanWindowMs: 24 * 60 * 60 * 1000 });
    expect(out.kept_referenced).toBe(1);
    expect(out.deleted).toBe(0);
    expect((await storage.head(m.media_id)).exists).toBe(true);
  });
});

// ─── init wiring + env gating ───────────────────────────────────────────

describe("initMediaRetention — env gating", () => {
  const { initMediaRetention } = require(path.join(SRC, "init-media-retention"));
  let root, storage;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
  });
  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("NODE_ENV=test → disabled (no setInterval)", () => {
    // jest sets NODE_ENV=test automatically
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "test";
    try {
      const h = initMediaRetention({ dag: _fakeDag({ contents: [] }), mediaStorage: storage });
      expect(h.running).toBe(false);
    } finally {
      process.env.NODE_ENV = orig;
    }
  });

  test("TIP_MEDIA_RETENTION_DISABLE=1 → disabled", () => {
    const origEnv = process.env.NODE_ENV;
    const origFlag = process.env.TIP_MEDIA_RETENTION_DISABLE;
    process.env.NODE_ENV = "production";
    process.env.TIP_MEDIA_RETENTION_DISABLE = "1";
    try {
      const h = initMediaRetention({ dag: _fakeDag({ contents: [] }), mediaStorage: storage });
      expect(h.running).toBe(false);
    } finally {
      process.env.NODE_ENV = origEnv;
      if (origFlag === undefined) delete process.env.TIP_MEDIA_RETENTION_DISABLE;
      else process.env.TIP_MEDIA_RETENTION_DISABLE = origFlag;
    }
  });

  test("backend missing list() → disabled gracefully", () => {
    const origEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const fakeStorage = { backend: "stub", head: () => {}, get: () => {}, delete: () => {} };
      const h = initMediaRetention({ dag: _fakeDag({ contents: [] }), mediaStorage: fakeStorage });
      expect(h.running).toBe(false);
    } finally {
      process.env.NODE_ENV = origEnv;
    }
  });

  test("enabled in non-test env — runOnce executes both sweeps", async () => {
    const origEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    // Long interval keeps the setInterval from firing during the test.
    process.env.TIP_MEDIA_RETENTION_SWEEP_INTERVAL_MS = String(60 * 60 * 1000);
    try {
      const h = initMediaRetention({ dag: _fakeDag({ contents: [] }), mediaStorage: storage });
      expect(h.running).toBe(true);
      const result = await h.runOnce();
      expect(result.content).toBeDefined();
      expect(result.orphan).toBeDefined();
      h.stop();
    } finally {
      process.env.NODE_ENV = origEnv;
      delete process.env.TIP_MEDIA_RETENTION_SWEEP_INTERVAL_MS;
    }
  });
});
