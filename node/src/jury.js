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
const { TX_TYPES, ORIGIN, VOTE, VERDICT, CONTENT_STATUS } = require("../../shared/constants");
const { JURY, APPEAL, DISPUTE } = require("../../shared/protocol-constants");
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
 * Write JURY_SUMMONS txs for selected jurors/experts.
 * Shared by: dispute filing (jury), auto-escalation (jury NO_QUORUM), appeal filing (experts).
 */
function writeSummonsTxs(dag, config, ctid, disputeTxId, members, commitHours, revealHours, isAppeal = false) {
  const commitDeadline = new Date(Date.now() + commitHours * 3600000).toISOString();
  const revealDeadline = new Date(Date.now() + (commitHours + revealHours) * 3600000).toISOString();
  const timestamp = new Date().toISOString();

  for (const tipId of members.jurors || members.experts || []) {
    const summonsTx = _nodeSignedAuto({
      tx_type: TX_TYPES.JURY_SUMMONS,
      timestamp,
      prev: dag.getRecentPrev(),
      data: {
        ctid,
        dispute_tx_id: disputeTxId,
        juror_tip_id: tipId,
        stake: JURY.JUROR_STAKE,
        seed: members.seed,
        identity_count: members.identityCount,
        commit_deadline: commitDeadline,
        reveal_deadline: revealDeadline,
        is_appeal: isAppeal,
      },
    }, config);
    dag.addTx(summonsTx);
  }

  return { commitDeadline, revealDeadline };
}

/**
 * Penalize no-show jurors/experts (summoned but didn't reveal).
 */
function penalizeNoShows(reveals, summons, ctid, scoring) {
  const revealedIds = new Set(reveals.map(r => r.data.juror_tip_id));
  for (const s of summons) {
    if (!revealedIds.has(s.data.juror_tip_id)) {
      scoring.applyScoreEvent(s.data.juror_tip_id, -JURY.NO_SHOW_PENALTY, `No-show on ${ctid}`);
    }
  }
}

/**
 * Get majority confirmed_origin from MISMATCH voters.
 */
function getMajorityOrigin(reveals, fallbackOrigin) {
  const originVotes = reveals
    .filter(r => r.data?.vote === VOTE.MISMATCH && r.data?.confirmed_origin)
    .map(r => r.data.confirmed_origin);
  const counts = {};
  for (const o of originVotes) counts[o] = (counts[o] || 0) + 1;
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || fallbackOrigin || null;
}

/**
 * Tally jury votes and apply verdict + score effects.
 * Called when all jurors have revealed (or reveal window expires via scheduler).
 */
function tallyVerdictAndApply(ctid, reveals, summons, dag, scoring, config) {
  const matchCount = reveals.filter(r => r.data?.vote === VOTE.MATCH).length;
  const mismatchCount = reveals.filter(r => r.data?.vote === VOTE.MISMATCH).length;
  const abstainCount = reveals.filter(r => r.data?.vote === VOTE.ABSTAIN).length;
  const totalVotes = matchCount + mismatchCount + abstainCount;

  // Quorum check: enough reveals AND enough actual votes (not just abstains)
  const nonAbstain = matchCount + mismatchCount;
  if (totalVotes < JURY.QUORUM || nonAbstain < JURY.MAJORITY_VOTE) {
    penalizeNoShows(reveals, summons, ctid, scoring);

    // Auto-escalate to Stage 3 — free appeal (system-initiated)
    const rec = dag.getContent(ctid);
    const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
    const authorTipId = rec?.author_tip_id;
    const disputerTipId = disputeTxs[0]?.data?.disputer_tip_id;

    const appealTx = _nodeSignedAuto({
      tx_type: TX_TYPES.APPEAL_FILED, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(),
      data: { ctid, appellant_tip_id: "SYSTEM_AUTO_ESCALATION", stage2_verdict: VERDICT.NO_QUORUM, stake: 0 },
    }, config);
    dag.addTx(appealTx);

    const experts = selectExperts(dag, scoring, appealTx.tx_id, authorTipId, disputerTipId);
    writeSummonsTxs(dag, config, ctid, appealTx.tx_id, experts, APPEAL.COMMIT_WINDOW_HOURS, APPEAL.REVEAL_WINDOW_HOURS, true);

    log.info(`Jury NO_QUORUM on ${ctid} — auto-escalated to Stage 3 with ${experts.experts.length} experts`);
    return { verdict: VERDICT.NO_QUORUM, auto_appeal: true, experts: experts.experts, matchCount, mismatchCount, abstainCount };
  }

  // Majority: need > 50% of non-abstain votes
  const majorityNeeded = Math.floor(nonAbstain / 2) + 1;
  const decision = mismatchCount >= majorityNeeded ? VERDICT.UPHELD : VERDICT.DISMISSED;

  const rec = dag.getContent(ctid);
  const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
  const disputeData = disputeTxs[0]?.data || {};
  const disputerTipId = disputeData.disputer_tip_id;
  const authorTipId = rec?.author_tip_id;

  // Origin codes: declared (what author said) vs confirmed (majority of MISMATCH jurors)
  const declared_origin = disputeData.declared_origin || rec?.origin_code;
  let confirmed_origin = null;
  if (decision === VERDICT.UPHELD) {
    const originVotes = reveals
      .filter(r => r.data?.vote === VOTE.MISMATCH && r.data?.confirmed_origin)
      .map(r => r.data.confirmed_origin);
    const originCounts = {};
    for (const o of originVotes) originCounts[o] = (originCounts[o] || 0) + 1;
    confirmed_origin = Object.entries(originCounts).sort((a, b) => b[1] - a[1])[0]?.[0]
      || disputeData.claimed_origin || null;
  }

  // Check for conservative label (AG declared, was actually OH — no penalty)
  const verdict = decision === VERDICT.DISMISSED ? VERDICT.DISMISSED
    : (declared_origin === ORIGIN.AG && confirmed_origin === ORIGIN.OH) ? VERDICT.CONSERVATIVE_LABEL
      : VERDICT.UPHELD;

  // Write ADJUDICATION_RESULT tx
  const resultTx = _nodeSignedAuto({
    tx_type: TX_TYPES.ADJUDICATION_RESULT,
    timestamp: new Date().toISOString(),
    prev: dag.getRecentPrev(),
    data: {
      ctid,
      verdict,
      declared_origin,
      confirmed_origin,
      reason: disputeData.reason,
      author_tip_id: authorTipId,
      match_count: matchCount,
      mismatch_count: mismatchCount,
      abstain_count: abstainCount,
      juror_votes: reveals.map(r => ({ juror_tip_id: r.data.juror_tip_id, vote: r.data.vote })),
    },
  }, config);
  dag.addTx(resultTx);

  // Apply juror score effects
  const isTie = matchCount === mismatchCount;
  if (isTie) {
    log.info(`Jury tie on ${ctid}: ${matchCount}-${mismatchCount} — no juror score changes`);
  } else {
    const majorityVote = mismatchCount > matchCount ? VOTE.MISMATCH : VOTE.MATCH;
    for (const reveal of reveals) {
      const jurorTipId = reveal.data.juror_tip_id;
      if (reveal.data.vote === VOTE.ABSTAIN) continue;
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
  if (verdict === VERDICT.UPHELD && disputerTipId) {
    scoring.applyScoreEvent(disputerTipId, DISPUTE.UPHELD_BONUS, `Dispute upheld on ${ctid}`);
  } else if (verdict === VERDICT.DISMISSED && disputerTipId) {
    scoring.applyScoreEvent(disputerTipId, -DISPUTE.DISPUTER_STAKE, `Dispute dismissed on ${ctid}`);
  }

  // Creator effects
  if (verdict === VERDICT.UPHELD && authorTipId) {
    const current = scoring.computeScore(authorTipId);
    if (confirmed_origin) {
      dag.updateContentOrigin(ctid, confirmed_origin, CONTENT_STATUS.VERIFIED);
      log.info(`Verdict UPHELD: ${ctid} origin ${declared_origin} → ${confirmed_origin}, creator ${authorTipId} penalty (score: ${current.score})`);
    }
  } else if (verdict === VERDICT.DISMISSED || verdict === VERDICT.CONSERVATIVE_LABEL) {
    dag.updateContentStatus(ctid, disputeData.pre_dispute_status || CONTENT_STATUS.REGISTERED);
  }

  return { verdict, confirmed_origin, matchCount, mismatchCount, abstainCount, tx_id: resultTx.tx_id };
}

/**
 * Apply appeal verdict — can overturn or confirm Stage 2.
 * Expert decision is FINAL and IMMUTABLE.
 */
function applyAppealVerdict(ctid, reveals, summons, dag, scoring, config) {
  const matchCount = reveals.filter(r => r.data?.vote === VOTE.MATCH).length;
  const mismatchCount = reveals.filter(r => r.data?.vote === VOTE.MISMATCH).length;
  const abstainCount = reveals.filter(r => r.data?.vote === VOTE.ABSTAIN).length;
  const nonAbstain = matchCount + mismatchCount;

  // Need at least APPEAL.MIN_VOTES non-abstain votes from experts
  if (nonAbstain < APPEAL.MIN_VOTES) {
    penalizeNoShows(reveals, summons, ctid, scoring);

    // Default to DISMISSED — author wins if experts can't decide
    const dTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
    const preStatus = dTxs[0]?.data?.pre_dispute_status || CONTENT_STATUS.REGISTERED;

    // Write APPEAL_RESULT tx so DAG records the outcome
    const resultTx = _nodeSignedAuto({
      tx_type: TX_TYPES.APPEAL_RESULT,
      timestamp: new Date().toISOString(),
      prev: dag.getRecentPrev(),
      data: {
        ctid, verdict: VERDICT.DISMISSED, overturned: false, defaulted: true,
        match_count: matchCount, mismatch_count: mismatchCount, abstain_count: abstainCount,
      },
    }, config);
    dag.addTx(resultTx);

    dag.updateContentStatus(ctid, preStatus);
    log.info(`Appeal NO_QUORUM on ${ctid} — defaulted to DISMISSED, status restored to ${preStatus}`);
    return { verdict: VERDICT.DISMISSED, defaulted: true, tx_id: resultTx.tx_id, matchCount, mismatchCount, abstainCount };
  }

  // Same majority formula as jury: strict majority of non-abstain
  const majorityNeeded = Math.floor(nonAbstain / 2) + 1;
  const expertDecision = mismatchCount >= majorityNeeded ? VERDICT.UPHELD : VERDICT.DISMISSED;

  // Get Stage 2 verdict
  const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid);
  const stage2Verdict = adjTxs[0]?.data?.verdict;
  const appealTxs = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid);
  const appellantTipId = appealTxs[0]?.data?.appellant_tip_id;

  const rec = dag.getContent(ctid);
  const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
  const disputeData = disputeTxs[0]?.data || {};
  const authorTipId = rec?.author_tip_id;

  // Confirmed origin from expert MISMATCH votes
  let confirmed_origin = null;
  if (expertDecision === VERDICT.UPHELD) {
    const originVotes = reveals
      .filter(r => r.data?.vote === VOTE.MISMATCH && r.data?.confirmed_origin)
      .map(r => r.data.confirmed_origin);
    const originCounts = {};
    for (const o of originVotes) originCounts[o] = (originCounts[o] || 0) + 1;
    confirmed_origin = Object.entries(originCounts).sort((a, b) => b[1] - a[1])[0]?.[0]
      || disputeData.claimed_origin || null;
  }

  const declared_origin = disputeData.declared_origin || rec?.origin_code;
  const verdict = expertDecision === VERDICT.DISMISSED ? VERDICT.DISMISSED
    : (declared_origin === ORIGIN.AG && confirmed_origin === ORIGIN.OH) ? VERDICT.CONSERVATIVE_LABEL
      : VERDICT.UPHELD;

  const overturned = (stage2Verdict === VERDICT.UPHELD && verdict === VERDICT.DISMISSED)
    || (stage2Verdict === VERDICT.DISMISSED && verdict === VERDICT.UPHELD);

  // Write APPEAL_RESULT tx — FINAL
  const resultTx = _nodeSignedAuto({
    tx_type: TX_TYPES.APPEAL_RESULT,
    timestamp: new Date().toISOString(),
    prev: dag.getRecentPrev(),
    data: {
      ctid, verdict, overturned, stage2_verdict: stage2Verdict,
      declared_origin, confirmed_origin,
      match_count: matchCount, mismatch_count: mismatchCount, abstain_count: abstainCount,
      expert_votes: reveals.map(r => ({ juror_tip_id: r.data.juror_tip_id, vote: r.data.vote })),
    },
  }, config);
  dag.addTx(resultTx);

  // Appellant effects
  const preStatus = disputeData.pre_dispute_status || CONTENT_STATUS.REGISTERED;

  if (overturned && appellantTipId) {
    scoring.applyScoreEvent(appellantTipId, APPEAL.APPELLANT_STAKE + APPEAL.OVERTURN_BONUS, `Appeal overturned on ${ctid}`);

    // Reverse disputer's Stage 2 effect
    const disputerTipId = disputeData.disputer_tip_id;
    if (stage2Verdict === VERDICT.UPHELD && disputerTipId) {
      // Disputer got +5 at Stage 2 → take it back
      scoring.applyScoreEvent(disputerTipId, -DISPUTE.UPHELD_BONUS, `Appeal overturned: Stage 2 bonus reversed on ${ctid}`);
    } else if (stage2Verdict === VERDICT.DISMISSED && disputerTipId) {
      // Disputer lost -15 at Stage 2 → give it back
      scoring.applyScoreEvent(disputerTipId, DISPUTE.DISPUTER_STAKE, `Appeal overturned: Stage 2 penalty reversed on ${ctid}`);
    }

    if (stage2Verdict === VERDICT.UPHELD && authorTipId) {
      // Stage 2 penalized author → reverse: restore original origin + pre-dispute status
      scoring.computeScore(authorTipId);
      dag.updateContentOrigin(ctid, declared_origin, preStatus);
      log.info(`Appeal OVERTURNED: ${ctid} — penalty reversed, origin restored to ${declared_origin}, status to ${preStatus}`);
    } else if (stage2Verdict === VERDICT.DISMISSED) {
      // Stage 2 dismissed → experts say UPHELD: apply penalty, update origin
      if (confirmed_origin) {
        dag.updateContentOrigin(ctid, confirmed_origin, CONTENT_STATUS.VERIFIED);
      }
      log.info(`Appeal OVERTURNED: ${ctid} — Stage 2 dismissal reversed, experts confirm mismatch`);
    }
  } else if (!overturned && appellantTipId) {
    scoring.applyScoreEvent(appellantTipId, -APPEAL.APPELLANT_STAKE, `Appeal failed on ${ctid}`);
    if (verdict === VERDICT.UPHELD && confirmed_origin) {
      // Experts confirm UPHELD — verified by experts
      dag.updateContentOrigin(ctid, confirmed_origin, CONTENT_STATUS.VERIFIED);
    } else {
      // Experts confirm DISMISSED — restore pre-dispute status
      dag.updateContentStatus(ctid, preStatus);
    }
    log.info(`Appeal CONFIRMED: ${ctid} — Stage 2 stands, appellant loses ${APPEAL.APPELLANT_STAKE}`);
  }

  // Expert score effects
  const isTie = matchCount === mismatchCount;
  if (!isTie) {
    const majorityVote = mismatchCount > matchCount ? VOTE.MISMATCH : VOTE.MATCH;
    for (const reveal of reveals) {
      if (reveal.data.vote === VOTE.ABSTAIN) continue;
      if (reveal.data.vote === majorityVote) {
        scoring.applyScoreEvent(reveal.data.juror_tip_id, JURY.MAJORITY_BONUS, `Expert majority vote on ${ctid}`);
      } else {
        scoring.applyScoreEvent(reveal.data.juror_tip_id, -JURY.MINORITY_PENALTY, `Expert minority vote on ${ctid}`);
      }
    }
  }

  // No-show experts
  const revealedIds = new Set(reveals.map(r => r.data.juror_tip_id));
  for (const s of summons) {
    if (!revealedIds.has(s.data.juror_tip_id)) {
      scoring.applyScoreEvent(s.data.juror_tip_id, -JURY.NO_SHOW_PENALTY, `Expert no-show on ${ctid}`);
    }
  }

  return { verdict, overturned, confirmed_origin, matchCount, mismatchCount, abstainCount, tx_id: resultTx.tx_id };
}

module.exports = { selectJury, selectExperts, tallyVerdictAndApply, applyAppealVerdict };
