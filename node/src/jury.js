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

const { shake256, computeTxId, signTransaction } = require("../../shared/crypto");
const { JURY, APPEAL, DISPUTE, TX_TYPES, ORIGIN } = require("../../shared/constants");
const { log } = require("./logger");

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

/**
 * Helper: sign an auto/system tx with node keys.
 */
function _nodeSignedAuto(txBody, config) {
  txBody.data.node_id = config.nodeRegisteredId || config.nodeId;
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, config.nodePrivateKey);
}

/**
 * Tally jury votes and apply verdict + score effects.
 * Called when all jurors have revealed (or reveal window expires via scheduler).
 */
function tallyVerdictAndApply(ctid, reveals, summons, dag, scoring, config) {
  const matchCount    = reveals.filter(r => r.data?.vote === "MATCH").length;
  const mismatchCount = reveals.filter(r => r.data?.vote === "MISMATCH").length;
  const abstainCount  = reveals.filter(r => r.data?.vote === "ABSTAIN").length;
  const totalVotes    = matchCount + mismatchCount + abstainCount;

  // Quorum check: enough reveals AND enough actual votes (not just abstains)
  const nonAbstain = matchCount + mismatchCount;
  if (totalVotes < JURY.QUORUM || nonAbstain < JURY.MAJORITY_VOTE) {
    // No quorum — still penalize no-shows before returning
    const revealedIds = new Set(reveals.map(r => r.data.juror_tip_id));
    for (const s of summons) {
      if (!revealedIds.has(s.data.juror_tip_id)) {
        scoring.applyScoreEvent(s.data.juror_tip_id, -JURY.NO_SHOW_PENALTY, `Jury no-show on ${ctid}`);
      }
    }
    return { verdict: "NO_QUORUM", message: "Insufficient votes — escalate to Stage 3", matchCount, mismatchCount, abstainCount };
  }

  // Majority: need > 50% of non-abstain votes
  const majorityNeeded = Math.floor(nonAbstain / 2) + 1;
  const decision = mismatchCount >= majorityNeeded ? "UPHELD" : "DISMISSED";

  const rec = dag.getContent(ctid);
  const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
  const disputeData   = disputeTxs[0]?.data || {};
  const disputerTipId = disputeData.disputer_tip_id;
  const authorTipId   = rec?.author_tip_id;

  // Origin codes: declared (what author said) vs confirmed (majority of MISMATCH jurors)
  const declared_origin = disputeData.declared_origin || rec?.origin_code;
  let confirmed_origin = null;
  if (decision === "UPHELD") {
    const originVotes = reveals
      .filter(r => r.data?.vote === "MISMATCH" && r.data?.confirmed_origin)
      .map(r => r.data.confirmed_origin);
    const originCounts = {};
    for (const o of originVotes) originCounts[o] = (originCounts[o] || 0) + 1;
    confirmed_origin = Object.entries(originCounts).sort((a, b) => b[1] - a[1])[0]?.[0]
                     || disputeData.claimed_origin || null;
  }

  // Check for conservative label (AG declared, was actually OH — no penalty)
  const verdict = decision === "DISMISSED" ? "DISMISSED"
    : (declared_origin === ORIGIN.AG && confirmed_origin === ORIGIN.OH) ? "CONSERVATIVE_LABEL"
    : "UPHELD";

  // Write ADJUDICATION_RESULT tx
  const resultTx = _nodeSignedAuto({
    tx_type:   TX_TYPES.ADJUDICATION_RESULT,
    timestamp: new Date().toISOString(),
    prev:      dag.getRecentPrev(),
    data: {
      ctid,
      verdict,
      declared_origin,
      confirmed_origin,
      reason:          disputeData.reason,
      author_tip_id:   authorTipId,
      match_count:     matchCount,
      mismatch_count:  mismatchCount,
      abstain_count:   abstainCount,
      juror_votes:     reveals.map(r => ({ juror_tip_id: r.data.juror_tip_id, vote: r.data.vote })),
    },
  }, config);
  dag.addTx(resultTx);

  // Apply juror score effects
  const isTie = matchCount === mismatchCount;
  if (isTie) {
    log.info(`Jury tie on ${ctid}: ${matchCount}-${mismatchCount} — no juror score changes`);
  } else {
    const majorityVote = mismatchCount > matchCount ? "MISMATCH" : "MATCH";
    for (const reveal of reveals) {
      const jurorTipId = reveal.data.juror_tip_id;
      if (reveal.data.vote === "ABSTAIN") continue;
      if (reveal.data.vote === majorityVote) {
        scoring.applyScoreEvent(jurorTipId, JURY.MAJORITY_BONUS, `Jury majority vote on ${ctid}`);
      } else {
        scoring.applyScoreEvent(jurorTipId, -JURY.MINORITY_PENALTY, `Jury minority vote on ${ctid}`);
      }
    }
  }

  // No-show jurors (summoned but didn't reveal)
  const revealedIds = new Set(reveals.map(r => r.data.juror_tip_id));
  for (const s of summons) {
    if (!revealedIds.has(s.data.juror_tip_id)) {
      scoring.applyScoreEvent(s.data.juror_tip_id, -JURY.NO_SHOW_PENALTY, `Jury no-show on ${ctid}`);
    }
  }

  // Disputer effects
  if (verdict === "UPHELD" && disputerTipId) {
    scoring.applyScoreEvent(disputerTipId, DISPUTE.UPHELD_BONUS, `Dispute upheld on ${ctid}`);
  } else if (verdict === "DISMISSED" && disputerTipId) {
    scoring.applyScoreEvent(disputerTipId, -DISPUTE.DISPUTER_STAKE, `Dispute dismissed on ${ctid}`);
  }

  // Creator effects
  if (verdict === "UPHELD" && authorTipId) {
    const current = scoring.computeScore(authorTipId);
    if (confirmed_origin) {
      dag.updateContentOrigin(ctid, confirmed_origin, "verified");
      log.info(`Verdict UPHELD: ${ctid} origin ${declared_origin} → ${confirmed_origin}, creator ${authorTipId} penalty (score: ${current.score})`);
    }
  } else if (verdict === "DISMISSED" || verdict === "CONSERVATIVE_LABEL") {
    dag.updateContentStatus(ctid, "registered");
  }

  return { verdict, confirmed_origin, matchCount, mismatchCount, abstainCount, tx_id: resultTx.tx_id };
}

module.exports = { selectJury, selectExperts, tallyVerdictAndApply };
