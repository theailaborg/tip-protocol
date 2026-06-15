/**
 * @file @tip-protocol/node/src/init-media-retention.js
 * @description Boot the periodic media-retention sweep. Mirrors the
 * init-prescan-worker pattern — owns startup orchestration for one
 * subsystem so index.js stays terse.
 *
 * Gating:
 *   - NODE_ENV=test                       → disabled (no setInterval)
 *   - TIP_MEDIA_RETENTION_DISABLE=1       → disabled
 *   - storage.list() not implemented      → disabled (logged)
 *
 * Cadence:
 *   - Default 6h. Override via TIP_MEDIA_RETENTION_SWEEP_INTERVAL_MS.
 *
 * Each tick runs the content sweep then the orphan sweep, serially.
 * Sweeps never overlap — if a tick is still running when the next
 * timer fires, the new tick is skipped (logged) until the previous
 * one finishes. Keeps storage IO bounded and avoids racing against
 * ourselves on the delete path.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { createMediaRetention } = require("./services/media-retention");
const { log } = require("./logger");

const DEFAULT_SWEEP_INTERVAL_MS = 6 * 60 * 60 * 1000;  // 6h

function _resolveInterval() {
  const raw = parseInt(process.env.TIP_MEDIA_RETENTION_SWEEP_INTERVAL_MS || "", 10);
  if (Number.isInteger(raw) && raw > 0) return raw;
  return DEFAULT_SWEEP_INTERVAL_MS;
}

/**
 * @param {Object} deps
 * @param {Object} deps.dag             DAG facade.
 * @param {Object} deps.mediaStorage    media-storage instance (fs or s3).
 * @returns {{ stop: () => void, running: boolean, runOnce: () => Promise<{content, orphan}> }}
 */
function initMediaRetention({ dag, mediaStorage }) {
  const noop = { stop() { /* */ }, running: false, runOnce: async () => null };

  if (process.env.NODE_ENV === "test") {
    log.info("Media retention disabled: NODE_ENV=test");
    return noop;
  }
  if (process.env.TIP_MEDIA_RETENTION_DISABLE === "1") {
    log.info("Media retention disabled via TIP_MEDIA_RETENTION_DISABLE=1");
    return noop;
  }
  if (!mediaStorage || typeof mediaStorage.list !== "function") {
    log.warn("Media retention NOT started: storage backend lacks list() — orphan sweep unsupported");
    return noop;
  }

  const retention = createMediaRetention({ dag, storage: mediaStorage });
  const intervalMs = _resolveInterval();
  let inFlight = false;
  let stopped = false;

  async function _tick() {
    if (inFlight) {
      log.warn("Media retention tick skipped: previous sweep still running");
      return null;
    }
    inFlight = true;
    try {
      const content = await retention.sweepExpiredContent();
      const orphan = await retention.sweepOrphanUploads();
      log.info(
        `Media retention swept: content { deleted=${content.deleted} skipped_active=${content.skipped_active} ` +
        `skipped_cooling=${content.skipped_cooling} shared=${content.shared_with_active_ctid} } ` +
        `orphan { deleted=${orphan.deleted} kept_referenced=${orphan.kept_referenced} ` +
        `kept_recent=${orphan.kept_recent} kept_no_meta=${orphan.kept_no_meta} }`,
      );
      return { content, orphan };
    } catch (err) {
      log.error(`Media retention sweep failed: ${err?.stack || err}`);
      return { error: err };
    } finally {
      inFlight = false;
    }
  }

  // First sweep is delayed by `intervalMs` rather than running immediately
  // at boot — gives the node a quiet warm-up before any IO-heavy work.
  const handle = setInterval(_tick, intervalMs);
  if (typeof handle.unref === "function") handle.unref();
  log.notice(`Media retention started: interval=${intervalMs}ms backend=${mediaStorage.backend}`);

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

module.exports = { initMediaRetention };
