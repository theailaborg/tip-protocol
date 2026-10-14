"use strict";

// Team seats an organization may fill, decided by the operator's billing
// service. Consensus only enforces the fixed ceiling in
// _org-members.memberLimit; this client narrows it at the API, before an
// invite or an acceptance is relayed.
//
// Opt-in, same channel as the media allowance. With TIP_SEATS_URL (or
// TIP_MEDIA_QUOTA_URL) unset the client is disabled and every org gets
// ORG_MEMBERS.FREE_MEMBER_LIMIT. The AI Lab's nodes point it at the
// Verification Portal (POST /api/team-seats/check, X-TIP-Quota-Key).
//
// It never takes a seat away: if the billing service is slow or down, the
// last known allowance for the org is used, and without one the free limit.
//
// Env: TIP_SEATS_URL, TIP_SEATS_KEY (default to the TIP_MEDIA_QUOTA_ values),
//      TIP_SEATS_TIMEOUT_MS (default 3000).

const { ORG_MEMBERS } = require("../../../shared/constants");
const { nowMs } = require("../../../shared/time");

const DEFAULT_TIMEOUT_MS = 3000;
const FRESH_MS = 60 * 1000;
const LAST_KNOWN_MAX = 5000;

function createSeatAllowanceClient(opts = {}) {
  const url = String(opts.url ?? process.env.TIP_SEATS_URL ?? process.env.TIP_MEDIA_QUOTA_URL ?? "").replace(/\/+$/, "");
  const key = opts.key ?? process.env.TIP_SEATS_KEY ?? process.env.TIP_MEDIA_QUOTA_KEY ?? "";
  const timeoutMs = Number(opts.timeoutMs ?? process.env.TIP_SEATS_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;
  const fetchImpl = opts.fetch ?? globalThis.fetch;
  const log = opts.log ?? console;
  const now = opts.now ?? nowMs;
  const enabled = Boolean(url && key && typeof fetchImpl === "function");
  const lastKnown = new Map();   // org_tip_id -> { answer, at }

  const free = () => ({ limit: ORG_MEMBERS.FREE_MEMBER_LIMIT, plan: "free", upgrade_url: null });

  function _remember(orgTipId, answer) {
    if (lastKnown.size >= LAST_KNOWN_MAX) lastKnown.delete(lastKnown.keys().next().value);
    lastKnown.set(orgTipId, { answer, at: now() });
  }

  function _normalize(raw) {
    const limit = Number(raw && raw.limit);
    if (!Number.isInteger(limit) || limit < 0) throw new Error("malformed answer");
    return {
      limit: Math.max(limit, ORG_MEMBERS.FREE_MEMBER_LIMIT),
      plan: typeof raw.plan === "string" ? raw.plan : "free",
      upgrade_url: typeof raw.upgrade_url === "string" ? raw.upgrade_url : null,
    };
  }

  async function _post(orgTipId) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetchImpl(`${url}/api/team-seats/check`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "User-Agent": "TIP-Node/1.0",
          "X-TIP-Quota-Key": key,
        },
        body: JSON.stringify({ org_tip_id: orgTipId }),
        signal: ac.signal,
      });
      const text = await res.text();
      let parsed = null;
      try { parsed = text ? JSON.parse(text) : null; } catch { /* keep null */ }
      if (!res.ok || !parsed) throw new Error(`HTTP ${res.status}`);
      return _normalize(parsed);
    } finally {
      clearTimeout(timer);
    }
  }

  /** Seats this org may fill: { limit, plan, upgrade_url }. Never throws. */
  async function allowanceFor(orgTipId) {
    if (!enabled) return free();
    const known = lastKnown.get(orgTipId);
    if (known && now() - known.at < FRESH_MS) return known.answer;
    try {
      const answer = await _post(orgTipId);
      _remember(orgTipId, answer);
      return answer;
    } catch (err) {
      log.warn?.(`team-seats check unavailable for ${orgTipId}: ${err.message}${known ? " (using last known)" : " (free limit)"}`);
      return known ? known.answer : free();
    }
  }

  /** Last known allowance without a network call, for synchronous summaries. */
  function peek(orgTipId) {
    const known = enabled && lastKnown.get(orgTipId);
    return known ? known.answer : free();
  }

  return { enabled, allowanceFor, peek };
}

module.exports = { createSeatAllowanceClient };
