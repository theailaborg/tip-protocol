/**
 * @file @tip-protocol/node/src/reg-credit.js
 * @description Registration-credit rate-cap math, shared by the emitter
 * (best-effort) and the commit-handler (authoritative). Pure: the commit-handler
 * passes the frozen tx.timestamp so every node computes the identical clamp.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { REGISTER_CREDIT } = require("../../shared/constants");
const { toIso } = require("../../shared/time");

const MS_PER_DAY = 86_400_000;

// Author's reg_credit sums (UTC day / calendar-month windows around `atMs`,
// plus net lifetime) from SCORE_UPDATE txs { timestamp, data:{tip_id,reason,delta} }.
function regCreditSums(txs, tipId, atMs) {
  const dayStart = atMs - (atMs % MS_PER_DAY);
  const monthStart = dayStart - (Number(toIso(atMs).slice(8, 10)) - 1) * MS_PER_DAY;
  const mine = txs.filter(t => t.data && t.data.tip_id === tipId);
  const awards = mine.filter(t => String(t.data.reason || "").startsWith(REGISTER_CREDIT.AWARD_REASON_PREFIX));
  const sum = (arr) => arr.reduce((s, t) => s + (t.data.delta || 0), 0);
  return {
    netTotal: sum(mine.filter(t => String(t.data.reason || "").startsWith("reg_credit"))),
    dailySum: sum(awards.filter(t => t.timestamp >= dayStart)),
    monthlySum: sum(awards.filter(t => t.timestamp >= monthStart)),
  };
}

// Remaining award headroom (0..BASE): the smallest of the per-day, per-month,
// and lifetime-total ceilings.
function regCreditRemaining(sums) {
  return Math.min(
    REGISTER_CREDIT.BASE,
    Math.max(0, REGISTER_CREDIT.TOTAL - sums.netTotal),
    Math.max(0, REGISTER_CREDIT.PER_DAY - sums.dailySum),
    Math.max(0, REGISTER_CREDIT.PER_MONTH - sums.monthlySum),
  );
}

module.exports = { regCreditSums, regCreditRemaining };
