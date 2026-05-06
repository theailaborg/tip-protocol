/**
 * @file @tip-protocol/node/src/logger.js
 * @description Production logger with split console/file thresholds and
 *              rate-limited helpers.
 *
 * Features:
 *   - Console output (colored by level) — threshold via TIP_CONSOLE_LEVEL
 *   - File logging: logs/{date}/error.log, info.log, debug.log
 *       - debug.log always captures EVERYTHING regardless of console level,
 *         so operators can investigate without losing detail when running
 *         a quiet console.
 *   - Source labels for tracing (e.g. [tip.api], [tip.narwhal])
 *   - rateWarn(key, ttlSec, ...msg): dedup repeating warnings by key
 *
 * Env vars:
 *   TIP_LOG_LEVEL        — file-level threshold for info.log (default: info)
 *   TIP_CONSOLE_LEVEL    — console threshold (default: info). Set to "warn"
 *                          in production for a quiet terminal; debug detail
 *                          still lands in debug.log.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const fs = require("fs");
const path = require("path");

// `notice` is a bypass tier: always printed to the console regardless of
// TIP_CONSOLE_LEVEL. Use for rare, operator-relevant events that should be
// visible even when running in quiet mode — startup, shutdown, consensus
// state transitions. For file purposes notice is stored at info level.
const LEVELS = { error: 0, warn: 1, info: 2, debug: 3, notice: 2 };
// Per-level ANSI colors so a busy terminal scans at a glance. Bright cyan
// for `notice` so the bypass tier visually pops above the regular flow.
const COLORS = { error: "\x1b[31m", warn: "\x1b[33m", info: "\x1b[32m", debug: "\x1b[90m", notice: "\x1b[96m" };
const RESET = "\x1b[0m";
const LOG_DIR = process.env.TIP_LOG_DIR || path.resolve(__dirname, "../logs");

const _fileMaxLevel = LEVELS[process.env.TIP_LOG_LEVEL || "info"] ?? LEVELS.info;
const _consoleMaxLevel = LEVELS[process.env.TIP_CONSOLE_LEVEL || process.env.TIP_LOG_LEVEL || "info"] ?? LEVELS.info;
let _streams = {};
let _currentDate = "";

// rateWarn dedup state: key → lastLoggedAtMs
const _rateLimited = new Map();

/**
 * Get or create write streams for today's log folder.
 */
function _getStreams() {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  if (today !== _currentDate) {
    // Close old streams
    for (const s of Object.values(_streams)) {
      try { s.end(); } catch { }
    }

    _currentDate = today;
    const dir = path.join(LOG_DIR, today);
    fs.mkdirSync(dir, { recursive: true });

    _streams = {
      error: fs.createWriteStream(path.join(dir, "error.log"), { flags: "a" }),
      info: fs.createWriteStream(path.join(dir, "info.log"), { flags: "a" }),
      debug: fs.createWriteStream(path.join(dir, "debug.log"), { flags: "a" }),
    };
  }
  return _streams;
}

/**
 * Format a log entry.
 */
// Per-process node tag — last 12 chars of TIP_NODE_ID (set by env). When
// multiple nodes share the same LOG_DIR (e.g. local dev with all 3 in one
// repo), this disambiguates which process emitted each line. Computed once
// at module load; if TIP_NODE_ID isn't set yet the tag is empty.
const _nodeTag = (() => {
  const id = process.env.TIP_NODE_ID || "";
  // Strip the `tip://node/` prefix if present so the visible portion is
  // the short hex; otherwise tail-12 of whatever was given.
  const tail = id.replace(/^tip:\/\/node\//, "").slice(-12);
  return tail ? ` [${tail}]` : "";
})();

function _format(level, source, args) {
  const ts = new Date().toISOString();
  const label = level.toUpperCase().padEnd(5);
  const src = source ? `[${source}] ` : "";
  const msg = args.map(a => (typeof a === "object" ? JSON.stringify(a) : String(a))).join(" ");
  return `[${ts}] [${label}]${_nodeTag} ${src}${msg}`;
}

// Skip file writes under Jest so the test runner doesn't pollute the
// production log files. Detected via JEST_WORKER_ID (set by Jest automatically
// on every worker process) or NODE_ENV=test. Console still gets everything
// per its usual threshold — tests can see their own output without spamming
// logs/{date}/*.log on disk.
const _suppressFileLogging = !!process.env.JEST_WORKER_ID || process.env.NODE_ENV === "test";

/**
 * Write to console and file. Console and file thresholds are independent:
 * - Console: levels ≤ _consoleMaxLevel (quiet by default in production).
 * - error.log: errors only.
 * - info.log: error + warn + info (gated by _fileMaxLevel for info).
 * - debug.log: everything, always. Operators can investigate without
 *              needing to change TIP_LOG_LEVEL and restart.
 */
function _write(level, source, args) {
  const levelNum = LEVELS[level];
  const line = _format(level, source, args);

  // Console output — separate threshold from file. `notice` bypasses the
  // threshold so startup / state-transition events always surface on the
  // terminal even when TIP_CONSOLE_LEVEL=warn. Errors / warns route to
  // stderr (Node convention — keeps clean stdout for piping); colored
  // by level so operators can scan a busy terminal.
  const forceConsole = level === "notice";
  if (forceConsole || levelNum <= _consoleMaxLevel) {
    const colored = (COLORS[level] || "") + line + RESET;
    if (level === "error") console.error(colored);
    else if (level === "warn") console.warn(colored);
    else console.log(colored);
  }

  if (_suppressFileLogging) return;

  // File output
  try {
    const streams = _getStreams();

    if (level === "error" && streams.error) {
      streams.error.write(line + "\n");
    }

    if (levelNum <= LEVELS.info && levelNum <= _fileMaxLevel && streams.info) {
      streams.info.write(line + "\n");
    }

    // debug.log captures all levels unconditionally
    if (streams.debug) {
      streams.debug.write(line + "\n");
    }
  } catch {
    // Don't crash if file logging fails
  }
}

/**
 * Create a logger with a source label.
 * Usage: const log = getLogger("tip.api");
 *        log.info("Server started on port 4000");
 *        → [2026-04-11T...] [INFO ] [tip.api] Server started on port 4000
 */
function getLogger(source) {
  return {
    error: (...args) => _write("error", source, args),
    warn: (...args) => _write("warn", source, args),
    info: (...args) => _write("info", source, args),
    debug: (...args) => _write("debug", source, args),

    /**
     * Notice: always shown on the console regardless of TIP_CONSOLE_LEVEL.
     * Use sparingly — only for rare, operator-relevant events that a quiet
     * terminal should still surface (startup, shutdown, consensus state
     * transitions, peer authorization, sync completion). File-level is info.
     */
    notice: (...args) => _write("notice", source, args),

    /**
     * Rate-limited warn: drops repeats of the same key within ttlSec.
     * Use for repeating transient conditions (peer unreachable, sync retries)
     * that would otherwise flood the log.
     */
    rateWarn(key, ttlSec, ...args) {
      const now = Date.now();
      const last = _rateLimited.get(key) || 0;
      if (now - last < ttlSec * 1000) return;
      _rateLimited.set(key, now);
      _write("warn", source, args);
    },
  };
}

// Default logger (backward compatible — no source label)
const log = getLogger("");

module.exports = { log, getLogger };
