/**
 * @file tests/_failures-summary-reporter.js
 * @description Tiny zero-deps Jest reporter that re-prints a "Failed
 * tests" block at the very end of a run, after Jest's summary lines.
 *
 * Why: with 500+ tests passing above the summary, individual ✗ blocks
 * scroll off most terminal heights — operators end up seeing only
 * `Tests: 1 failed, 510 passed`. This reporter rescues the per-test
 * detail and reprints it in one block where the eye lands at the end.
 *
 * Wired in `package.json` jest.reporters alongside "default".
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

class FailuresSummaryReporter {
  constructor(_globalConfig, _options) {
    this._failed = [];  // { file, name, message }
  }

  onTestResult(_test, testResult) {
    for (const r of testResult.testResults) {
      if (r.status !== "failed") continue;
      this._failed.push({
        file: path.relative(process.cwd(), testResult.testFilePath),
        name: r.fullName,
        // failureMessages[0] holds the formatted "Expected/Received +
        // code frame + stack" string Jest already built; trim heavy
        // stack noise to keep the summary tight.
        message: (r.failureMessages || []).map(m => _trimStack(m)).join("\n"),
      });
    }
  }

  onRunComplete(_contexts, _results) {
    if (this._failed.length === 0) return;

    const stream = process.stderr;
    stream.write(`\n${"═".repeat(74)}\n`);
    stream.write(`  Failed tests (${this._failed.length})\n`);
    stream.write(`${"═".repeat(74)}\n`);
    for (let i = 0; i < this._failed.length; i++) {
      const f = this._failed[i];
      stream.write(`\n[${i + 1}] ${f.file}\n`);
      stream.write(`    › ${f.name}\n\n`);
      // Indent the per-failure body so it's visually grouped under the
      // test name. Trim trailing blank lines for cleaner output.
      const body = f.message.replace(/\s+$/, "").split("\n").map(l => `    ${l}`).join("\n");
      stream.write(`${body}\n`);
    }
    stream.write(`\n${"═".repeat(74)}\n\n`);
  }
}

/**
 * Strip "at <fn> (...)" stack frames from a Jest failureMessage so
 * what's left is the assertion diff + the code-frame snippet — the
 * actually useful part. Keeps the first frame inside our test file as
 * a navigation pointer.
 */
function _trimStack(msg) {
  const lines = msg.split("\n");
  const out = [];
  let firstAtSeen = false;
  for (const line of lines) {
    if (/^\s+at /.test(line)) {
      if (!firstAtSeen && line.includes("/tests/")) {
        out.push(line);
        firstAtSeen = true;
      }
      // skip subsequent stack frames
      continue;
    }
    out.push(line);
  }
  return out.join("\n");
}

module.exports = FailuresSummaryReporter;
