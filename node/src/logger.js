/**
 * @file @tip-protocol/node/src/logger.js
 * @description Production logger with file rotation and structured output.
 *
 * Features:
 *   - Console output (colored by level)
 *   - File logging: logs/{date}/error.log, info.log, debug.log
 *   - Each level file contains that level AND above
 *   - Auto-creates date folders
 *   - Source labels for tracing (e.g. [tip.api], [tip.jury])
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const LOG_DIR = process.env.TIP_LOG_DIR || path.resolve(__dirname, "../logs");

let _maxLevel = LEVELS[process.env.TIP_LOG_LEVEL || "info"] ?? 2;
let _streams = {};
let _currentDate = "";

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
function _format(level, source, args) {
  const ts = new Date().toISOString();
  const label = level.toUpperCase().padEnd(5);
  const src = source ? `[${source}] ` : "";
  const msg = args.map(a => (typeof a === "object" ? JSON.stringify(a) : String(a))).join(" ");
  return `[${ts}] [${label}] ${src}${msg}`;
}

/**
 * Write to console and file.
 */
function _write(level, source, args) {
  const levelNum = LEVELS[level];
  if (levelNum > _maxLevel) return;

  const line = _format(level, source, args);

  // Console output
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);

  // File output — write to appropriate level files
  try {
    const streams = _getStreams();

    // error.log: errors only
    if (levelNum <= LEVELS.error && streams.error) {
      streams.error.write(line + "\n");
    }

    // info.log: error + warn + info
    if (levelNum <= LEVELS.info && streams.info) {
      streams.info.write(line + "\n");
    }

    // debug.log: all levels
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
  };
}

// Default logger (backward compatible — no source label)
const log = getLogger("");

module.exports = { log, getLogger };
