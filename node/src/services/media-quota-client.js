"use strict";

// Monthly media allowance, enforced by asking the operator's billing service.
//
// Opt-in. With TIP_MEDIA_QUOTA_URL unset (the default) this client is
// disabled and uploads behave exactly as before, so other node operators are
// unaffected. The AI Lab's nodes point it at the Verification Portal, which
// keeps one ledger for every node host (POST /api/media-quota/check and
// /api/media-quota/record, authenticated with X-TIP-Quota-Key).
//
// It fails open: if the billing service is slow or down, an upload is never
// blocked by that, the last known answer for the TIP-ID is used, and a
// verified upload's record is retried a few times in the background.
//
// Env: TIP_MEDIA_QUOTA_URL (e.g. https://vp.theailab.org), TIP_MEDIA_QUOTA_KEY,
//      TIP_MEDIA_QUOTA_TIMEOUT_MS (default 3000).

const { nowMs } = require("../../../shared/time");

const DEFAULT_TIMEOUT_MS = 3000;
const RECORD_RETRIES = [2000, 10000, 60000];
const LAST_KNOWN_MAX = 5000;

function createMediaQuotaClient(opts = {}) {
  const url = String(opts.url ?? process.env.TIP_MEDIA_QUOTA_URL ?? "").replace(/\/+$/, "");
  const key = opts.key ?? process.env.TIP_MEDIA_QUOTA_KEY ?? "";
  const timeoutMs = Number(opts.timeoutMs ?? process.env.TIP_MEDIA_QUOTA_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS);
  const fetchImpl = opts.fetch ?? globalThis.fetch;
  const log = opts.log ?? console;
  const sleep = opts.sleep ?? (ms => new Promise(r => setTimeout(r, ms)));
  const enabled = Boolean(url && key && typeof fetchImpl === "function");
  const lastKnown = new Map();   // tip_id -> { remaining_bytes, at }

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
    if (lastKnown.size >= LAST_KNOWN_MAX) lastKnown.delete(lastKnown.keys().next().value);
    lastKnown.set(tipId, { remaining_bytes: answer.remaining_bytes, at: nowMs() });
  }

  /**
   * May this upload start? Resolves to the billing service's answer
   * ({allowed, used_bytes, allowance_bytes, remaining_bytes, resets_at, ...}),
   * or null when the client is disabled or the service could not be reached
   * and nothing is known about this TIP-ID (meaning: let it through).
   */
  async function check({ tip_id, content_hash, size }) {
    if (!enabled) return null;
    try {
      const answer = await _post("/api/media-quota/check", { tip_id, content_hash, size });
      if (typeof answer.allowed !== "boolean") throw new Error("malformed answer");
      _remember(tip_id, answer);
      return answer;
    } catch (err) {
      const known = lastKnown.get(tip_id);
      log.warn?.(`media-quota check unavailable for ${tip_id}: ${err.message}${known ? " (using last known)" : " (allowing)"}`);
      if (!known) return null;
      return { allowed: size <= known.remaining_bytes, remaining_bytes: known.remaining_bytes, stale: true };
    }
  }

  /** Count a verified upload. Never throws; retries in the background. */
  async function record({ tip_id, content_hash, size, media_id }) {
    if (!enabled) return false;
    const body = { tip_id, content_hash, size, media_id };
    for (let attempt = 0; ; attempt++) {
      try {
        const answer = await _post("/api/media-quota/record", body);
        _remember(tip_id, answer);
        return true;
      } catch (err) {
        if (attempt >= RECORD_RETRIES.length) {
          log.error?.(`media-quota record lost for ${tip_id} ${content_hash} (${size} bytes): ${err.message}`);
          return false;
        }
        await sleep(RECORD_RETRIES[attempt]);
      }
    }
  }

  return { enabled, check, record };
}

module.exports = { createMediaQuotaClient };
