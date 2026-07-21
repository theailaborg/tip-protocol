/**
 * @file @tip-protocol/node/src/init-chunked-upload-cleanup.js
 * @description Periodic cleanup of expired chunked upload sessions and
 * abandoned S3 multipart uploads.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { log } = require("./logger");

const DEFAULT_INTERVAL_MS = 60 * 60 * 1000; // 1h

function _resolveInterval() {
  const raw = parseInt(process.env.TIP_CHUNKED_UPLOAD_CLEANUP_INTERVAL_MS || "", 10);
  if (Number.isInteger(raw) && raw > 0) return raw;
  return DEFAULT_INTERVAL_MS;
}

function initChunkedUploadCleanup({ chunkedUploadService }) {
  const noop = { stop() { /* */ }, running: false, runOnce: async () => null };

  if (process.env.NODE_ENV === "test") {
    log.info("Chunked upload cleanup disabled: NODE_ENV=test");
    return noop;
  }
  if (!chunkedUploadService || typeof chunkedUploadService.cleanupExpired !== "function") {
    return noop;
  }

  const intervalMs = _resolveInterval();
  let inFlight = false;
  let stopped = false;

  async function _tick() {
    if (inFlight) return null;
    inFlight = true;
    try {
      const result = await chunkedUploadService.cleanupExpired();
      if (result && result.removed > 0) {
        log.info(`Chunked upload cleanup: removed ${result.removed} expired sessions`);
      }
      return result;
    } catch (err) {
      log.error(`Chunked upload cleanup failed: ${err?.stack || err}`);
      return { error: err };
    } finally {
      inFlight = false;
    }
  }

  const handle = setInterval(_tick, intervalMs);
  if (typeof handle.unref === "function") handle.unref();
  log.notice(`Chunked upload cleanup started: interval=${intervalMs}ms`);

  return {
    runOnce: _tick,
    stop() {
      if (stopped) return;
      stopped = true;
      clearInterval(handle);
    },
    get running() { return !stopped; },
  };
}

module.exports = { initChunkedUploadCleanup };
