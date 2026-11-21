"use strict";

// Website page allowance, enforced by asking the operator's billing service
// before a page of a protected site is registered (POST /api/websites/reserve,
// X-TIP-Quota-Key auth, same channel as the media allowance). Opt-in through
// config.websitePages; disabled, registrations behave exactly as before.
//
// Fails open: a slow or down service never blocks a page, except that a
// "this site is full" answer is remembered until its month resets (or for
// LAST_KNOWN_TTL_MS), so an outage cannot be used to run past the limit.

const { nowMs } = require("../../../shared/time");
const { MEDIA_QUOTA_CLIENT } = require("../../../shared/constants");

function createWebsitePagesClient(opts = {}) {
  const url = String(opts.url ?? "").replace(/\/+$/, "");
  const key = opts.key ?? "";
  const timeoutMs = Number(opts.timeoutMs) || MEDIA_QUOTA_CLIENT.TIMEOUT_MS;
  const fetchImpl = opts.fetch ?? globalThis.fetch;
  const log = opts.log ?? console;
  const now = opts.now ?? nowMs;
  const enabled = Boolean(url && key && typeof fetchImpl === "function");
  const full = new Map();   // owner tip_id -> { answer, resets_at_ms, at }
  const snapshotRefused = new Map();   // "owner|domain" -> { answer, until_ms }

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

  function _remember(owner, answer) {
    if (answer.allowed) { full.delete(owner); return; }
    if (full.size >= MEDIA_QUOTA_CLIENT.LAST_KNOWN_MAX) full.delete(full.keys().next().value);
    const resetsAtMs = typeof answer.resets_at === "number" ? answer.resets_at * 1000 : null;
    full.set(owner, { answer, resets_at_ms: resetsAtMs, at: now() });
  }

  function _knownFull(owner) {
    const k = full.get(owner);
    if (!k) return null;
    const t = now();
    if (t - k.at > MEDIA_QUOTA_CLIENT.LAST_KNOWN_TTL_MS || (k.resets_at_ms != null && t >= k.resets_at_ms)) {
      full.delete(owner);
      return null;
    }
    return k.answer;
  }

  /**
   * Count these pages against the site owner's plan. Resolves to the billing
   * service's answer ({allowed, reason, used, limit, sites_used, sites_limit,
   * resets_at, upgrade_url}), or null when the client is disabled or the
   * service could not be reached (meaning: let it through).
   */
  async function reserve({ owner_tip_id, signer_tip_id, domain, urls, ctid }) {
    if (!enabled) return null;
    try {
      const answer = await _post("/api/websites/reserve", { owner_tip_id, signer_tip_id, domain, urls, ctid });
      if (typeof answer.allowed !== "boolean") throw new Error("malformed answer");
      _remember(owner_tip_id, answer);
      return answer;
    } catch (err) {
      const known = _knownFull(owner_tip_id);
      log.warn?.(`website-pages reserve unavailable for ${owner_tip_id} ${domain}: ${err.message}${known ? " (site full, last known)" : " (allowing)"}`);
      return known ? { ...known, stale: true } : null;
    }
  }

  /**
   * How many websites the owner's plan protects: { sites_limit, plan,
   * upgrade_url }, or null when disabled or unreachable (let it through).
   */
  async function sitesLimit({ tip_id }) {
    if (!enabled) return null;
    try {
      const answer = await _post("/api/websites/sites", { tip_id });
      if (!Number.isInteger(answer.sites_limit)) throw new Error("malformed answer");
      return answer;
    } catch (err) {
      log.warn?.(`website-pages sites unavailable for ${tip_id}: ${err.message} (allowing)`);
      return null;
    }
  }

  function _knownRefusal(k) {
    const r = snapshotRefused.get(k);
    if (!r) return null;
    if (now() >= r.until_ms) { snapshotRefused.delete(k); return null; }
    return r.answer;
  }

  /**
   * Whether the owner's plan allows a snapshot of this site now: the billing
   * service's { allowed, reason, next_allowed_at (epoch s), upgrade_url }, or
   * null when disabled or unreachable (let it through). A refusal is kept until
   * next_allowed_at (at most LAST_KNOWN_TTL_MS), so an outage cannot skip it.
   */
  async function snapshotAllowed({ owner_tip_id, signer_tip_id, domain, page_count }) {
    if (!enabled) return null;
    const k = `${owner_tip_id}|${domain}`;
    try {
      const answer = await _post("/api/websites/snapshot", { owner_tip_id, signer_tip_id, domain, page_count });
      if (typeof answer.allowed !== "boolean") throw new Error("malformed answer");
      if (answer.allowed) {
        snapshotRefused.delete(k);
      } else {
        if (snapshotRefused.size >= MEDIA_QUOTA_CLIENT.LAST_KNOWN_MAX) snapshotRefused.delete(snapshotRefused.keys().next().value);
        const cap = now() + MEDIA_QUOTA_CLIENT.LAST_KNOWN_TTL_MS;
        const next = typeof answer.next_allowed_at === "number" ? answer.next_allowed_at * 1000 : cap;
        snapshotRefused.set(k, { answer, until_ms: Math.min(next, cap) });
      }
      return answer;
    } catch (err) {
      const known = _knownRefusal(k);
      log.warn?.(`website-pages snapshot check unavailable for ${owner_tip_id} ${domain}: ${err.message}${known ? " (refused, last known)" : " (allowing)"}`);
      return known ? { ...known, stale: true } : null;
    }
  }

  return { enabled, reserve, sitesLimit, snapshotAllowed };
}

module.exports = { createWebsitePagesClient };
