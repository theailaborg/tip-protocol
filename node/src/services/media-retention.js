/**
 * @file @tip-protocol/node/src/services/media-retention.js
 * @description Periodic media-retention sweeps. Two independent passes:
 *
 *   sweepExpiredContent — three-case retention model:
 *
 *       never disputed              → registered_at + BASE_RETENTION_MS
 *       only ADJUDICATION_RESULT    → adjudication.ts + POST_ADJUDICATION_MS
 *       APPEAL_RESULT reached       → appeal.ts + POST_APPEAL_MS
 *
 *     Bytes survive while ANY role is still active (open prescan review /
 *     unresolved dispute / unresolved appeal). After the case-specific
 *     deadline lapses, eligible media is deleted — UNLESS the same
 *     media_id is referenced by another content row still inside its
 *     own window (dedup safety).
 *
 *   sweepOrphanUploads — for every object in storage older than
 *     ORPHAN_UPLOAD_MS that no content row references, delete the
 *     bytes. Catches "user uploaded then abandoned registration."
 *
 * Pure factory — no clocks, no DB writes, no IO outside the injected
 * `dag` and `storage`. The init module owns scheduling + env gating.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const {
  TX_TYPES, PRESCAN_REVIEW_STATES,
} = require("../../../shared/constants");
const { MEDIA_RETENTION } = require("../../../shared/protocol-constants");
const { nowMs } = require("../../../shared/time");

const OPEN_REVIEW_STATES = new Set([
  PRESCAN_REVIEW_STATES.TRIGGERED,
  PRESCAN_REVIEW_STATES.CONFIRMED,
]);

function _latestTs(txs) {
  let ms = 0;
  for (const t of txs) {
    if (typeof t.timestamp === "number" && t.timestamp > ms) ms = t.timestamp;
  }
  return ms;
}

function createMediaRetention({ dag, storage, log }) {
  if (!dag) throw new Error("media-retention: dag required");
  if (!storage) throw new Error("media-retention: storage required");
  const logger = log || console;

  // True when ANY role on this ctid still needs the bytes: open prescan
  // review, open dispute (CONTENT_DISPUTED.count > ADJUDICATION_RESULT.count),
  // or open appeal (APPEAL_FILED.count > APPEAL_RESULT.count). Mirrors the
  // inverse of canAccessMedia's reviewer/juror/expert branches — author
  // access doesn't keep bytes alive forever.
  function _hasActiveRole(ctid) {
    if (typeof dag.getOpenPrescanReviewByCtid === "function") {
      const r = dag.getOpenPrescanReviewByCtid(ctid);
      if (r && OPEN_REVIEW_STATES.has(r.state)) return true;
    }
    if (typeof dag.getTxsByTypeAndCtid !== "function") return false;
    const disputes = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid).length;
    const adjudications = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid).length;
    if (disputes > adjudications) return true;
    const appeals = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid).length;
    const appealResults = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_RESULT, ctid).length;
    if (appeals > appealResults) return true;
    return false;
  }

  // Three-case deletable-at computation. Returns the ms timestamp when
  // this content's media becomes eligible for deletion.
  //
  //   APPEAL_RESULT exists      → appeal.ts + POST_APPEAL_MS
  //   only ADJUDICATION_RESULT  → adjudication.ts + POST_ADJUDICATION_MS
  //   never disputed            → registered_at + BASE_RETENTION_MS
  //
  // Honors `opts` overrides (used by tests so they don't have to drive
  // genesis).
  function _deletableAt(content, opts) {
    const baseMs = opts?.baseRetentionMs ?? MEDIA_RETENTION.BASE_RETENTION_MS;
    const adjMs = opts?.postAdjudicationMs ?? MEDIA_RETENTION.POST_ADJUDICATION_MS;
    const appealMs = opts?.postAppealMs ?? MEDIA_RETENTION.POST_APPEAL_MS;

    if (typeof dag.getTxsByTypeAndCtid === "function") {
      const appeals = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_RESULT, content.ctid);
      if (appeals.length > 0) return _latestTs(appeals) + appealMs;
      const adjs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, content.ctid);
      if (adjs.length > 0) return _latestTs(adjs) + adjMs;
    }
    return (content.registered_at || 0) + baseMs;
  }

  async function sweepExpiredContent({ now = nowMs(), ...windowOpts } = {}) {
    const baseMs = windowOpts.baseRetentionMs ?? MEDIA_RETENTION.BASE_RETENTION_MS;

    // Coarse pre-filter: anything registered after `now - baseMs` can't
    // possibly be deletable yet, because even the never-disputed branch
    // needs at least BASE_RETENTION_MS to elapse since registration. The
    // per-row predicate may still skip individual rows (dispute / appeal
    // windows extend the wait), but this cuts the candidate set down to
    // "rows old enough to even consider."
    const candidates = typeof dag.getContentWithMediaBefore === "function"
      ? dag.getContentWithMediaBefore(now - baseMs)
      : [];

    // Global reference count: Map<media_id, count> across EVERY content
    // row. Required for dedup safety — same media_id referenced by two
    // ctids only gets deleted when ALL referrers are also expired.
    const globalRefs = typeof dag.getReferencedMediaIds === "function"
      ? dag.getReferencedMediaIds()
      : new Map();

    let skippedActive = 0, skippedCooling = 0, deleted = 0, missing = 0, shared = 0;
    const eligibleDrops = new Map();           // media_id → count of expired referrers

    for (const content of candidates) {
      if (_hasActiveRole(content.ctid)) { skippedActive += 1; continue; }
      if (_deletableAt(content, windowOpts) > now) { skippedCooling += 1; continue; }
      for (const m of (content.media || [])) {
        if (!m || typeof m.media_id !== "string") continue;
        eligibleDrops.set(m.media_id, (eligibleDrops.get(m.media_id) || 0) + 1);
      }
    }

    // Safe to delete only when every row referencing this media_id is
    // expired in the same pass (expiredCount === globalCount).
    for (const [mediaId, expiredCount] of eligibleDrops.entries()) {
      const total = globalRefs.get(mediaId) || 0;
      if (expiredCount < total) { shared += 1; continue; }
      try {
        const res = await storage.delete(mediaId);
        if (res && res.deleted) deleted += 1; else missing += 1;
      } catch (err) {
        logger.warn?.(`media-retention: delete failed for ${mediaId}: ${err?.message || err}`);
      }
    }

    return {
      candidates: candidates.length,
      skipped_active: skippedActive,
      skipped_cooling: skippedCooling,
      shared_with_active_ctid: shared,
      deleted,
      missing,
    };
  }

  async function sweepOrphanUploads({ now = nowMs(), orphanWindowMs } = {}) {
    const windowMs = typeof orphanWindowMs === "number"
      ? orphanWindowMs
      : MEDIA_RETENTION.ORPHAN_UPLOAD_MS;
    if (typeof storage.list !== "function") {
      throw new Error("media-retention: storage.list() not implemented by backend");
    }
    const referenced = typeof dag.getReferencedMediaIds === "function"
      ? dag.getReferencedMediaIds()
      : new Set();

    let scanned = 0, deleted = 0, kept_referenced = 0, kept_recent = 0, missing = 0, kept_no_meta = 0;
    for await (const entry of storage.list()) {
      scanned += 1;
      if (referenced.has(entry.media_id)) { kept_referenced += 1; continue; }
      // No sidecar → can't age it; leave alone. The next put rewrites the
      // sidecar with a fresh created_at, and the row gets swept then.
      if (entry.created_at == null) { kept_no_meta += 1; continue; }
      if (now - entry.created_at < windowMs) { kept_recent += 1; continue; }
      try {
        const res = await storage.delete(entry.media_id);
        if (res && res.deleted) deleted += 1; else missing += 1;
      } catch (err) {
        logger.warn?.(`media-retention: orphan delete failed for ${entry.media_id}: ${err?.message || err}`);
      }
    }
    return { scanned, deleted, missing, kept_referenced, kept_recent, kept_no_meta };
  }

  return { sweepExpiredContent, sweepOrphanUploads };
}

module.exports = { createMediaRetention };
