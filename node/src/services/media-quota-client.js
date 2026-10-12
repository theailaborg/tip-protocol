"use strict";

// Monthly media allowance, enforced by asking the operator's billing service
// (POST /api/media-quota/check before bytes move, /record after they verified;
// X-TIP-Quota-Key auth). Opt-in through config.mediaQuota; disabled, uploads
// behave exactly as before. Fails open: a slow or down service never blocks an
// upload, a remembered answer for the TIP-ID decides only while it is fresh.

const { nowMs } = require("../../../shared/time");
const { MEDIA_QUOTA_CLIENT } = require("../../../shared/constants");

function createMediaQuotaClient(opts = {}) {
  const url = String(opts.url ?? "").replace(/\/+$/, "");
  const key = opts.key ?? "";
  const timeoutMs = Number(opts.timeoutMs) || MEDIA_QUOTA_CLIENT.TIMEOUT_MS;
  const fetchImpl = opts.fetch ?? globalThis.fetch;
  const log = opts.log ?? console;
  const sleep = opts.sleep ?? (ms => new Promise(r => setTimeout(r, ms)));
  const now = opts.now ?? nowMs;
  const enabled = Boolean(url && key && typeof fetchImpl === "function");
  const lastKnown = new Map();   // tip_id -> { remaining_bytes, resets_at_ms, at }

  async function _post(path, body) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetchImpl(`${url}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "User-Agent": "TIP-Node/1.0",
          "X-TIP-Quota-Key": key,
        },
        body: JSON.stringify(body),
        signal: ac.signal,
      });
      const text = await res.text();
      let parsed = null;
      try { parsed = text ? JSON.parse(text) : null; } catch { /* keep null */ }
      if (!res.ok || !parsed) throw new Error(`HTTP ${res.status}`);
      return parsed;
    } finally {
      clearTimeout(timer);
    }
  }

  // Only a numeric remaining allowance is worth remembering. A billing
  // service with no monthly limit answers remaining_bytes null; remembering
  // that would make an outage refuse every upload (size <= null is false).
  function _remember(tipId, answer) {
    if (typeof answer.remaining_bytes !== "number") { lastKnown.delete(tipId); return; }
    if (lastKnown.size >= MEDIA_QUOTA_CLIENT.LAST_KNOWN_MAX) lastKnown.delete(lastKnown.keys().next().value);
    const resetsAtMs = typeof answer.resets_at === "number" ? answer.resets_at * 1000 : null;
    lastKnown.set(tipId, { remaining_bytes: answer.remaining_bytes, resets_at_ms: resetsAtMs, at: now() });
  }

  // A remembered answer is dropped once its month reset or it aged past the
  // TTL: a zero remaining from last month must not refuse this month's uploads.
  function _known(tipId) {
    const k = lastKnown.get(tipId);
    if (!k) return null;
    const t = now();
    if (t - k.at > MEDIA_QUOTA_CLIENT.LAST_KNOWN_TTL_MS || (k.resets_at_ms != null && t >= k.resets_at_ms)) {
      lastKnown.delete(tipId);
      return null;
    }
    return k;
  }

  /**
   * May this upload start? Resolves to the billing service's answer
   * ({allowed, used_bytes, allowance_bytes, remaining_bytes, resets_at, ...}),
   * or null when the client is disabled or the service could not be reached
   * and nothing fresh is known about this TIP-ID (meaning: let it through).
   */
  async function check({ tip_id, content_hash, size, tip_id_type }) {
    if (!enabled) return null;
    try {
      const body = { tip_id, content_hash, size };
      if (tip_id_type) body.tip_id_type = tip_id_type;
      const answer = await _post("/api/media-quota/check", body);
      if (typeof answer.allowed !== "boolean") throw new Error("malformed answer");
      _remember(tip_id, answer);
      return answer;
    } catch (err) {
      const known = _known(tip_id);
      log.warn?.(`media-quota check unavailable for ${tip_id}: ${err.message}${known ? " (using last known)" : " (allowing)"}`);
      if (!known) return null;
      return { allowed: size <= known.remaining_bytes, remaining_bytes: known.remaining_bytes, stale: true };
    }
  }

  /** Count a verified upload. Never throws; retries in the background. */
  async function record({ tip_id, content_hash, size, media_id }) {
    if (!enabled) return false;
    const body = { tip_id, content_hash, size, media_id };
    const retries = MEDIA_QUOTA_CLIENT.RECORD_RETRY_MS;
    for (let attempt = 0; ; attempt++) {
      try {
        const answer = await _post("/api/media-quota/record", body);
        _remember(tip_id, answer);
        return true;
      } catch (err) {
        if (attempt >= retries.length) {
          log.error?.(`media-quota record lost for ${tip_id} ${content_hash} (${size} bytes): ${err.message}`);
          return false;
        }
        await sleep(retries[attempt]);
      }
    }
  }

  return { enabled, check, record };
}

module.exports = { createMediaQuotaClient };
