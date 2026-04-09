/**
 * @file @tip-protocol/node/src/jury.js
 * @description Jury selection and adjudication logic for TIP dispute resolution.
 *
 * Stage 2: Deterministic jury selection — same identities + dispute tx = same 7 jurors on any node.
 * Stage 3: Expert appeal selection — same algorithm, higher threshold.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256 } = require("../../shared/crypto");
const { JURY, APPEAL } = require("../../shared/constants");

/**
 * Deterministic seeded shuffle (Fisher-Yates with seed bytes instead of Math.random).
 * Same seed → same shuffle on any machine.
 */
function _seededShuffle(arr, seedHex) {
  const seedBytes = Buffer.from(seedHex, "hex");
  const shuffled = [...arr];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = seedBytes[i % seedBytes.length] % (i + 1);
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

/**
 * Pick N from shuffled list with geographic diversity cap.
 */
function _pickWithGeoCap(shuffled, count, maxPerRegion) {
  const selected = [];
  const regionCount = {};
  for (const id of shuffled) {
    const region = id.region || "XX";
    if ((regionCount[region] || 0) >= maxPerRegion) continue;
    regionCount[region] = (regionCount[region] || 0) + 1;
    selected.push(id.tip_id);
    if (selected.length === count) break;
  }
  return selected;
}

/**
 * Deterministic jury selection.
 * seed = SHAKE-256(dispute_tx_id + identity_count)
 * Eligible pool sorted by tip_id → seeded shuffle → geographic cap → pick 7.
 *
 * @param {Object} dag - DAG instance
 * @param {Object} scoring - Scoring instance
 * @param {string} disputeTxId - The dispute transaction ID
 * @param {string} authorTipId - Content author's TIP-ID (excluded)
 * @param {string} disputerTipId - Disputer's TIP-ID (excluded)
 * @returns {{ jurors: string[], insufficient: boolean, seed: string, identityCount: number }}
 */
function selectJury(dag, scoring, disputeTxId, authorTipId, disputerTipId) {
  const allIdentities = dag.getAllIdentities();
  const identityCount = allIdentities.length;

  // Deterministic seed: dispute tx (unpredictable) + identity count (verifiable set size)
  const seed = shake256(`${disputeTxId}:${identityCount}`);

  // Filter eligible jurors, sorted by tip_id for determinism across nodes
  const eligible = allIdentities
    .filter(id => {
      if (id.tip_id === authorTipId || id.tip_id === disputerTipId) return false;
      if (dag.isRevoked(id.tip_id)) return false;
      const s = scoring.getScore(id.tip_id);
      if (s.score < JURY.MIN_SCORE) return false;
      return true;
    })
    .sort((a, b) => a.tip_id.localeCompare(b.tip_id));

  if (eligible.length < JURY.SIZE) {
    return { jurors: eligible.map(e => e.tip_id), insufficient: true, seed, identityCount };
  }

  const shuffled = _seededShuffle(eligible, seed);
  const jurors = _pickWithGeoCap(shuffled, JURY.SIZE, JURY.MAX_SAME_COUNTRY);

  return { jurors, insufficient: jurors.length < JURY.SIZE, seed, identityCount };
}

/**
 * Deterministic expert selection for Stage 3 appeal.
 * Same algorithm as jury but higher score threshold and 3 experts.
 */
function selectExperts(dag, scoring, appealTxId, authorTipId, disputerTipId) {
  const allIdentities = dag.getAllIdentities();
  const identityCount = allIdentities.length;

  const seed = shake256(`${appealTxId}:${identityCount}`);

  const eligible = allIdentities
    .filter(id => {
      if (id.tip_id === authorTipId || id.tip_id === disputerTipId) return false;
      if (dag.isRevoked(id.tip_id)) return false;
      const s = scoring.getScore(id.tip_id);
      if (s.score < APPEAL.MIN_EXPERT_SCORE) return false;
      return true;
    })
    .sort((a, b) => a.tip_id.localeCompare(b.tip_id));

  if (eligible.length < APPEAL.EXPERT_COUNT) {
    return { experts: eligible.map(e => e.tip_id), insufficient: true, seed, identityCount };
  }

  const shuffled = _seededShuffle(eligible, seed);
  const experts = _pickWithGeoCap(shuffled, APPEAL.EXPERT_COUNT, 2);

  return { experts, insufficient: experts.length < APPEAL.EXPERT_COUNT, seed, identityCount };
}

module.exports = { selectJury, selectExperts };
