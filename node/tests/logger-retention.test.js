/**
 * @file tests/logger-retention.test.js
 * @description The logger's on-disk retention prune (runs at date rollover):
 * date-dirs older than TIP_LOG_RETENTION_DAYS are removed wholesale; dirs
 * older than TIP_DEBUG_LOG_RETENTION_DAYS (but within general retention) keep
 * everything except debug.log. Recent dirs are untouched. Non-date dirs are
 * never touched.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

function dayString(daysAgo) {
  const d = new Date(Date.now() - daysAgo * 86400000);
  return d.toISOString().slice(0, 10); // YYYY-MM-DD (UTC)
}

function seedDir(root, name) {
  const dir = path.join(root, name);
  fs.mkdirSync(dir, { recursive: true });
  for (const f of ["info.log", "error.log", "access.log", "debug.log"]) {
    fs.writeFileSync(path.join(dir, f), "x\n");
  }
  return dir;
}

// File logging is suppressed under Jest (JEST_WORKER_ID guard), so we can't
// drive the prune via writes. Load a fresh logger with the retention env we
// want and invoke the exported _pruneOldLogs directly against LOG_DIR , the
// exact function the date-rollover calls in production.
function runPrune(logDir, retentionDays, debugRetentionDays) {
  jest.resetModules();
  process.env.TIP_LOG_DIR = logDir;
  process.env.TIP_LOG_RETENTION_DAYS = String(retentionDays);
  process.env.TIP_DEBUG_LOG_RETENTION_DAYS = String(debugRetentionDays);
  const mod = require(path.resolve(__dirname, "../src/logger"));
  // sanity: env actually took effect on this fresh module
  expect(mod._retentionDays).toBe(retentionDays);
  expect(mod._debugRetentionDays).toBe(debugRetentionDays);
  mod._pruneOldLogs(dayString(0));
}

let root;
beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), "tip-logret-")); });
afterEach(() => { fs.rmSync(root, { recursive: true, force: true }); });

describe("logger retention prune", () => {
  test("deletes date-dirs older than general retention, keeps recent", () => {
    seedDir(root, dayString(20));   // old -> gone
    seedDir(root, dayString(15));   // old -> gone
    seedDir(root, dayString(5));    // within -> kept
    seedDir(root, dayString(1));    // within -> kept
    runPrune(root, 14, 14);   // first write -> prune runs

    expect(fs.existsSync(path.join(root, dayString(20)))).toBe(false);
    expect(fs.existsSync(path.join(root, dayString(15)))).toBe(false);
    expect(fs.existsSync(path.join(root, dayString(5)))).toBe(true);
    expect(fs.existsSync(path.join(root, dayString(1)))).toBe(true);
  });

  test("prunes only debug.log for dirs past debug retention but within general", () => {
    const d5 = seedDir(root, dayString(5));   // >3 debug, <14 general -> debug.log gone, rest kept
    const d1 = seedDir(root, dayString(1));   // within both -> untouched
    runPrune(root, 14, 3);

    expect(fs.existsSync(path.join(d5, "debug.log"))).toBe(false);
    expect(fs.existsSync(path.join(d5, "info.log"))).toBe(true);   // dir & other logs survive
    expect(fs.existsSync(path.join(d1, "debug.log"))).toBe(true);  // recent debug kept
  });

  test("never touches non-date directories", () => {
    fs.mkdirSync(path.join(root, "keys"), { recursive: true });
    fs.writeFileSync(path.join(root, "keys", "secret"), "s");
    seedDir(root, dayString(30));
    runPrune(root, 14, 14);

    expect(fs.existsSync(path.join(root, "keys", "secret"))).toBe(true);
    expect(fs.existsSync(path.join(root, dayString(30)))).toBe(false);
  });

  test("today's dir (age 0) is always kept even at aggressive retention", () => {
    seedDir(root, dayString(0));
    runPrune(root, 1, 1);   // aggressive: keep only today
    expect(fs.existsSync(path.join(root, dayString(0)))).toBe(true);
    expect(fs.existsSync(path.join(root, dayString(0), "info.log"))).toBe(true);
    expect(fs.existsSync(path.join(root, dayString(0), "debug.log"))).toBe(true);
  });
});
