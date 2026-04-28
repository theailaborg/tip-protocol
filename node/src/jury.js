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
const { TX_TYPES, ORIGIN, VOTE, VERDICT, CONTENT_STATUS } = require("../../shared/constants");
const { JURY, APPEAL, DISPUTE } = require("../../shared/protocol-constants");
const { nodeSignedAuto } = require("./services/helpers");
const { getLogger } = require("./logger");

const log = getLogger("tip.jury");

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Filter reveal txs by `tx.timestamp <= reveal_deadline`. Third guard
 * (along with first-wins on ADJUDICATION_RESULT/APPEAL_RESULT and the
 * commit-handler reveal-window enforcement) that makes verdict
 * computation deterministic across nodes regardless of when each node's
 * scheduler tick fires.
 *
 * Both inputs are deterministic strings stored in DAG txs (frozen by
 * consensus), so every node — running this filter on the same committed
 * set of reveals — produces the same filtered list.
 */
function _filterRevealsByDeadline(reveals, summons) {
  if (!summons || summons.length === 0) return reveals;
  const revealDeadline = summons[0]?.data?.reveal_deadline;
  if (!revealDeadline) return reveals;
  const deadlineMs = new Date(revealDeadline).getTime();
  if (!Number.isFinite(deadlineMs)) return reveals;
  return reveals.filter(r => {
    if (!r?.timestamp) return false;
    const t = new Date(r.timestamp).getTime();
    return Number.isFinite(t) && t <= deadlineMs;
  });
}

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
 * Build a JURY_SUMMONS tx for a single juror/expert. Pure builder — does NOT
 * touch the DAG. Used by `buildAdjudicationBatch` for NO_QUORUM
 * auto-escalation; `dispute-service.js` and `appeal` paths still build their
 * own summons inline against the same fields (one tx_type, two callsites).
 */
function _buildSummonsTx({ ctid, disputeTxId, jurorTipId, seed, identityCount, commitDeadline, revealDeadline, isAppeal, timestamp, dag, config }) {
  return nodeSignedAuto({
    tx_type: TX_TYPES.JURY_SUMMONS,
    timestamp,
    prev: dag.getRecentPrev(),
    data: {
      ctid,
      dispute_tx_id: disputeTxId,
      juror_tip_id: jurorTipId,
      stake: JURY.JUROR_STAKE,
      seed,
      identity_count: identityCount,
      commit_deadline: commitDeadline,
      reveal_deadline: revealDeadline,
      is_appeal: isAppeal,
    },
  }, config);
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
 * Build the atomic batch of txs that represents a Stage-2 jury verdict.
 *
 * Pure builder — does NOT touch the DAG and does NOT mutate scores. The
 * returned `txs` array is meant to be submitted via `submitBatch(...)` so
 * every effect (verdict, juror scores, disputer outcome, no-show penalties)
 * flows through consensus. Commit-handler's per-tx-type cases apply the
 * derived state deterministically on every node, with first-wins guards
 * to drop duplicates produced by competing schedulers.
 *
 * Determinism guards in this builder:
 *   1. Reveals are filtered by `tx.timestamp <= summons.reveal_deadline`,
 *      so every node — running on the same committed reveal set — sees the
 *      same in-window reveals → same vote counts → same verdict.
 *   2. The DAG state read here (content, dispute, summons, reveals) is
 *      consensus-ordered and identical on every node.
 *
 * What's still non-deterministic: each node's batch is signed by its own
 * `config.nodePrivateKey`, so the produced tx_ids differ across nodes.
 * That's fine — `commit-handler.js` enforces first-wins per `ctid` for
 * ADJUDICATION_RESULT/APPEAL_RESULT and `(tip_id, ctid, reason)` for
 * SCORE_UPDATE, so only one batch's worth of effects lands.
 *
 * @param {string} ctid
 * @param {Array}  reveals  JURY_VOTE_REVEAL txs for this ctid
 * @param {Array}  summons  JURY_SUMMONS txs for this ctid
 * @param {Object} dag
 * @param {Object} scoring
 * @param {Object} config
 * @returns {{ txs: Array, verdict: string, ... }}
 */
function buildAdjudicationBatch(ctid, reveals, summons, dag, scoring, config) {
  const filteredReveals = _filterRevealsByDeadline(reveals, summons);

  const matchCount = filteredReveals.filter(r => r.data?.vote === VOTE.MATCH).length;
  const mismatchCount = filteredReveals.filter(r => r.data?.vote === VOTE.MISMATCH).length;
  const abstainCount = filteredReveals.filter(r => r.data?.vote === VOTE.ABSTAIN).length;
  const totalVotes = matchCount + mismatchCount + abstainCount;
  const nonAbstain = matchCount + mismatchCount;

  const timestamp = new Date().toISOString();
  const txs = [];
  const getRecentPrev = () => dag.getRecentPrev();

  const rec = dag.getContent(ctid);
  const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
  const disputeData = disputeTxs[0]?.data || {};
  const disputerTipId = disputeData.disputer_tip_id;
  const authorTipId = rec?.author_tip_id;
  const revealedIds = new Set(filteredReveals.map(r => r.data.juror_tip_id));

  // ── NO_QUORUM auto-escalation ─────────────────────────────────────────────
  if (totalVotes < JURY.QUORUM || nonAbstain < JURY.MAJORITY_VOTE) {
    const appealTx = nodeSignedAuto({
      tx_type: TX_TYPES.APPEAL_FILED,
      timestamp,
      prev: getRecentPrev(),
      data: { ctid, appellant_tip_id: "SYSTEM_AUTO_ESCALATION", stage2_verdict: VERDICT.NO_QUORUM, stake: 0 },
    }, config);
    txs.push(appealTx);

    const experts = selectExperts(dag, scoring, appealTx.tx_id, authorTipId, disputerTipId);
    const commitDeadline = new Date(Date.now() + APPEAL.COMMIT_WINDOW_HOURS * 3600000).toISOString();
    const revealDeadline = new Date(Date.now() + (APPEAL.COMMIT_WINDOW_HOURS + APPEAL.REVEAL_WINDOW_HOURS) * 3600000).toISOString();
    for (const expertTipId of experts.experts) {
      txs.push(_buildSummonsTx({
        ctid, disputeTxId: appealTx.tx_id, jurorTipId: expertTipId,
        seed: experts.seed, identityCount: experts.identityCount,
        commitDeadline, revealDeadline, isAppeal: true,
        timestamp, dag, config,
      }));
    }

    // No-show penalties
    for (const s of summons) {
      if (!revealedIds.has(s.data.juror_tip_id)) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: s.data.juror_tip_id, delta: -JURY.NO_SHOW_PENALTY,
          reason: `Jury no-show on ${ctid}`, ctid, relatedTxId: appealTx.tx_id,
          timestamp, getRecentPrev, config,
        }));
      }
    }

    log.info(`Jury NO_QUORUM on ${ctid} — auto-escalating to Stage 3 with ${experts.experts.length} experts (${txs.length} txs in batch)`);
    return { txs, verdict: VERDICT.NO_QUORUM, auto_appeal: true, experts: experts.experts, matchCount, mismatchCount, abstainCount };
  }

  // ── Quorum reached — compute verdict ──────────────────────────────────────
  const majorityNeeded = Math.floor(nonAbstain / 2) + 1;
  const decision = mismatchCount >= majorityNeeded ? VERDICT.UPHELD : VERDICT.DISMISSED;

  const declared_origin = disputeData.declared_origin || rec?.origin_code;
  let confirmed_origin = null;
  if (decision === VERDICT.UPHELD) {
    confirmed_origin = getMajorityOrigin(filteredReveals, disputeData.claimed_origin);
  }

  // CONSERVATIVE_LABEL: AG declared as OH — no penalty
  const verdict = decision === VERDICT.DISMISSED ? VERDICT.DISMISSED
    : (declared_origin === ORIGIN.AG && confirmed_origin === ORIGIN.OH) ? VERDICT.CONSERVATIVE_LABEL
      : VERDICT.UPHELD;

  // Author penalty embedded in the result tx so APPEAL_RESULT can reverse
  // the exact value if Stage 3 overturns. computeScore() picks this up
  // via the ADJUDICATION_RESULT replay path.
  const authorScoreDelta = (verdict === VERDICT.UPHELD && authorTipId)
    ? scoring.getAdjudicationDelta(authorTipId, { declared_origin, confirmed_origin, verdict })
    : 0;

  const resultTx = nodeSignedAuto({
    tx_type: TX_TYPES.ADJUDICATION_RESULT,
    timestamp,
    prev: getRecentPrev(),
    data: {
      ctid,
      verdict,
      declared_origin,
      confirmed_origin,
      reason: disputeData.reason,
      author_tip_id: authorTipId,
      author_score_delta: authorScoreDelta,
      // Persisted for commit-handler's content-status restore on
      // DISMISSED/CONSERVATIVE_LABEL — replaces the old direct
      // `dag.updateContentStatus` call from this function.
      pre_dispute_status: disputeData.pre_dispute_status || CONTENT_STATUS.REGISTERED,
      match_count: matchCount,
      mismatch_count: mismatchCount,
      abstain_count: abstainCount,
      juror_votes: filteredReveals.map(r => ({ juror_tip_id: r.data.juror_tip_id, vote: r.data.vote })),
    },
  }, config);
  txs.push(resultTx);

  // ── Juror score effects ───────────────────────────────────────────────────
  const isTie = matchCount === mismatchCount;
  if (!isTie) {
    const majorityVote = mismatchCount > matchCount ? VOTE.MISMATCH : VOTE.MATCH;
    for (const reveal of filteredReveals) {
      const jurorTipId = reveal.data.juror_tip_id;
      if (reveal.data.vote === VOTE.ABSTAIN) continue;
      const isMajority = reveal.data.vote === majorityVote;
      txs.push(scoring.buildScoreUpdateTx({
        tipId: jurorTipId,
        delta: isMajority ? JURY.MAJORITY_BONUS : -JURY.MINORITY_PENALTY,
        reason: `Jury ${isMajority ? "majority" : "minority"} vote on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    }
  }

  // No-show penalties
  for (const s of summons) {
    if (!revealedIds.has(s.data.juror_tip_id)) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: s.data.juror_tip_id, delta: -JURY.NO_SHOW_PENALTY,
        reason: `Jury no-show on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    }
  }

  // Disputer outcome
  if (verdict === VERDICT.UPHELD && disputerTipId) {
    txs.push(scoring.buildScoreUpdateTx({
      tipId: disputerTipId, delta: DISPUTE.UPHELD_BONUS,
      reason: `Dispute upheld on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
      timestamp, getRecentPrev, config,
    }));
  } else if (verdict === VERDICT.DISMISSED && disputerTipId) {
    txs.push(scoring.buildScoreUpdateTx({
      tipId: disputerTipId, delta: -DISPUTE.DISPUTER_STAKE,
      reason: `Dispute dismissed on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
      timestamp, getRecentPrev, config,
    }));
  }

  log.info(`Jury verdict ${verdict} on ${ctid} — ${matchCount}/${mismatchCount}/${abstainCount} match/mismatch/abstain (${txs.length} txs in batch)`);
  return { txs, verdict, confirmed_origin, matchCount, mismatchCount, abstainCount, tx_id: resultTx.tx_id };
}

/**
 * Build the atomic batch of txs for a Stage-3 expert appeal verdict.
 *
 * Pure builder — same contract as `buildAdjudicationBatch`:
 *  - Reveals filtered by reveal-deadline (third guard).
 *  - All score effects emitted as SCORE_UPDATE txs (with `data.ctid` and
 *    deterministic reasons so commit-handler can dedup competing batches).
 *  - Content-status / origin updates carried IN the APPEAL_RESULT tx data
 *    (`overturned`, `stage2_verdict`, `confirmed_origin`, `declared_origin`,
 *    `pre_dispute_status`); commit-handler.js's APPEAL_RESULT case applies
 *    the actual `dag.updateContentStatus` / `updateContentOrigin` mutation.
 *  - Stage-2 reversal on overturn: APPEAL_RESULT carries
 *    `original_author_delta` so commit-handler can produce a precise
 *    reverse-delta for the author. Juror score reversal for Stage-2's
 *    majority/minority is emitted as SCORE_UPDATE txs in this same batch.
 *
 * @returns {{ txs: Array, verdict: string, overturned: boolean, ... }}
 */
function buildAppealBatch(ctid, reveals, summons, dag, scoring, config) {
  const filteredReveals = _filterRevealsByDeadline(reveals, summons);

  const matchCount = filteredReveals.filter(r => r.data?.vote === VOTE.MATCH).length;
  const mismatchCount = filteredReveals.filter(r => r.data?.vote === VOTE.MISMATCH).length;
  const abstainCount = filteredReveals.filter(r => r.data?.vote === VOTE.ABSTAIN).length;
  const nonAbstain = matchCount + mismatchCount;

  const timestamp = new Date().toISOString();
  const txs = [];
  const getRecentPrev = () => dag.getRecentPrev();

  const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid);
  const stage2Verdict = adjTxs[0]?.data?.verdict;
  const stage2AuthorDelta = adjTxs[0]?.data?.author_score_delta || 0;
  const appealTxs = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid);
  const appellantTipId = appealTxs[0]?.data?.appellant_tip_id;

  const rec = dag.getContent(ctid);
  const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
  const disputeData = disputeTxs[0]?.data || {};
  const authorTipId = rec?.author_tip_id;
  const disputerTipId = disputeData.disputer_tip_id;
  const preStatus = disputeData.pre_dispute_status || CONTENT_STATUS.REGISTERED;

  const revealedIds = new Set(filteredReveals.map(r => r.data.juror_tip_id));

  // ── Insufficient experts → DISMISSED default ──────────────────────────────
  if (nonAbstain < APPEAL.MIN_VOTES) {
    const resultTx = nodeSignedAuto({
      tx_type: TX_TYPES.APPEAL_RESULT,
      timestamp,
      prev: getRecentPrev(),
      data: {
        ctid, verdict: VERDICT.DISMISSED, overturned: false, defaulted: true,
        stage2_verdict: stage2Verdict || null,
        pre_dispute_status: preStatus,
        match_count: matchCount, mismatch_count: mismatchCount, abstain_count: abstainCount,
      },
    }, config);
    txs.push(resultTx);

    for (const s of summons) {
      if (!revealedIds.has(s.data.juror_tip_id)) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: s.data.juror_tip_id, delta: -JURY.NO_SHOW_PENALTY,
          reason: `Expert no-show on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
          timestamp, getRecentPrev, config,
        }));
      }
    }

    log.info(`Appeal NO_QUORUM on ${ctid} — defaulted to DISMISSED (${txs.length} txs in batch)`);
    return { txs, verdict: VERDICT.DISMISSED, defaulted: true, tx_id: resultTx.tx_id, matchCount, mismatchCount, abstainCount };
  }

  // ── Quorum reached — compute expert verdict ───────────────────────────────
  const majorityNeeded = Math.floor(nonAbstain / 2) + 1;
  const expertDecision = mismatchCount >= majorityNeeded ? VERDICT.UPHELD : VERDICT.DISMISSED;

  const declared_origin = disputeData.declared_origin || rec?.origin_code;
  let confirmed_origin = null;
  if (expertDecision === VERDICT.UPHELD) {
    confirmed_origin = getMajorityOrigin(filteredReveals, disputeData.claimed_origin);
  }

  const verdict = expertDecision === VERDICT.DISMISSED ? VERDICT.DISMISSED
    : (declared_origin === ORIGIN.AG && confirmed_origin === ORIGIN.OH) ? VERDICT.CONSERVATIVE_LABEL
      : VERDICT.UPHELD;

  const overturned = (stage2Verdict === VERDICT.UPHELD && verdict === VERDICT.DISMISSED)
    || (stage2Verdict === VERDICT.DISMISSED && verdict === VERDICT.UPHELD);

  // Author-penalty delta for the OVERTURN-of-DISMISSED branch (Stage 2
  // dismissed; experts say UPHELD). Computed here so it lands in the tx
  // and commit-handler doesn't need to call scoring.getAdjudicationDelta.
  const overturnAuthorDelta = (overturned && stage2Verdict === VERDICT.DISMISSED && verdict === VERDICT.UPHELD && authorTipId)
    ? scoring.getAdjudicationDelta(authorTipId, { declared_origin, confirmed_origin, verdict })
    : 0;

  const resultTx = nodeSignedAuto({
    tx_type: TX_TYPES.APPEAL_RESULT,
    timestamp,
    prev: getRecentPrev(),
    data: {
      ctid, verdict, overturned,
      stage2_verdict: stage2Verdict,
      declared_origin, confirmed_origin,
      pre_dispute_status: preStatus,
      // Reversal data — commit-handler reads these to update content state.
      original_author_delta: stage2AuthorDelta,
      overturn_author_delta: overturnAuthorDelta,
      match_count: matchCount, mismatch_count: mismatchCount, abstain_count: abstainCount,
      expert_votes: filteredReveals.map(r => ({ juror_tip_id: r.data.juror_tip_id, vote: r.data.vote })),
    },
  }, config);
  txs.push(resultTx);

  // ── Appellant outcome ─────────────────────────────────────────────────────
  if (overturned && appellantTipId) {
    txs.push(scoring.buildScoreUpdateTx({
      tipId: appellantTipId, delta: APPEAL.OVERTURN_BONUS,
      reason: `Appeal overturned on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
      timestamp, getRecentPrev, config,
    }));

    // Reverse Stage-2 disputer effect.
    if (stage2Verdict === VERDICT.UPHELD && disputerTipId) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: disputerTipId, delta: -DISPUTE.UPHELD_BONUS,
        reason: `Appeal overturned: Stage 2 bonus reversed on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    } else if (stage2Verdict === VERDICT.DISMISSED && disputerTipId) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: disputerTipId, delta: DISPUTE.DISPUTER_STAKE,
        reason: `Appeal overturned: Stage 2 penalty reversed on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    }

    // Reverse Stage-2 author penalty (overturn UPHELD → DISMISSED) OR
    // apply fresh author penalty (overturn DISMISSED → UPHELD).
    if (stage2Verdict === VERDICT.UPHELD && authorTipId && stage2AuthorDelta < 0) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: authorTipId, delta: -stage2AuthorDelta,
        reason: `Appeal overturned: Stage 2 penalty reversed on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    } else if (stage2Verdict === VERDICT.DISMISSED && authorTipId && overturnAuthorDelta < 0) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: authorTipId, delta: overturnAuthorDelta,
        reason: `Appeal overturned: mismatch confirmed on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    }
  } else if (!overturned && appellantTipId) {
    txs.push(scoring.buildScoreUpdateTx({
      tipId: appellantTipId, delta: -APPEAL.APPELLANT_STAKE,
      reason: `Appeal failed on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
      timestamp, getRecentPrev, config,
    }));
  }

  // ── Expert score effects ──────────────────────────────────────────────────
  const isTie = matchCount === mismatchCount;
  if (!isTie) {
    const majorityVote = mismatchCount > matchCount ? VOTE.MISMATCH : VOTE.MATCH;
    for (const reveal of filteredReveals) {
      if (reveal.data.vote === VOTE.ABSTAIN) continue;
      const isMajority = reveal.data.vote === majorityVote;
      txs.push(scoring.buildScoreUpdateTx({
        tipId: reveal.data.juror_tip_id,
        delta: isMajority ? JURY.MAJORITY_BONUS : -JURY.MINORITY_PENALTY,
        reason: `Expert ${isMajority ? "majority" : "minority"} vote on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    }
  }

  // No-show experts
  for (const s of summons) {
    if (!revealedIds.has(s.data.juror_tip_id)) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: s.data.juror_tip_id, delta: -JURY.NO_SHOW_PENALTY,
        reason: `Expert no-show on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    }
  }

  log.info(`Appeal ${verdict} on ${ctid} — overturned=${overturned} (${txs.length} txs in batch)`);
  return { txs, verdict, overturned, confirmed_origin, matchCount, mismatchCount, abstainCount, tx_id: resultTx.tx_id };
}

module.exports = { selectJury, selectExperts, buildAdjudicationBatch, buildAppealBatch };
