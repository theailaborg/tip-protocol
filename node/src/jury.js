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
const { nowMs, nowPlusMs } = require("../../shared/time");
const { TX_TYPES, ORIGIN, VOTE, VERDICT, CONTENT_STATUS, TIP_ID_TYPES, PRESCAN_REVIEW_STATES } = require("../../shared/constants");
const { JURY, APPEAL, DISPUTE, REVIEWER } = require("../../shared/protocol-constants");
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
  const deadlineMs = revealDeadline;
  if (!Number.isFinite(deadlineMs)) return reveals;
  return reveals.filter(r => {
    if (!r?.timestamp) return false;
    const t = r.timestamp;
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
 * Pick `count` jurors from a deterministically-shuffled candidate list.
 *
 * Hard exclusions (the author, disputer, and revoked identities) are
 * filtered out by the caller BEFORE this function runs — every entry
 * here is jury-eligible in principle. This function decides how to
 * order them under the soft preferences:
 *
 *   Pass 1 — preferred:    score ≥ minScore  AND  ≤ maxPerRegion same-region
 *   Pass 2 — geo overflow: score ≥ minScore  (geo cap relaxed)
 *   Pass 3+ — score cascade: each fallbackFloor in turn (geo still off)
 *
 * The `fallbackFloors` rest-arg lets callers chain progressively lower
 * floors. Example for expert selection (3 cascade levels):
 *
 *   _pickWithGeoCap(shuffled, 3, 2, 850, 700, 500)
 *   //                              ^Pass 1/2  ^Pass 3  ^Pass 4
 *   // Pass 1: ≥ 850 + geo cap     ; Pass 2: ≥ 850 only ;
 *   // Pass 3: ≥ 700 (jury-tier)   ; Pass 4: ≥ 500 (VERIFIED-tier ultimate floor).
 *
 * Each subsequent floor must be strictly lower than the previous active
 * floor — non-decreasing entries are skipped (defensive — a redundant
 * pass would do nothing useful).
 *
 * Why floored relaxations: an unrestricted final pass would admit
 * arbitrarily-low-score jurors (including NOT_TRUSTED-tier) when the pool
 * is thin. The floors keep cascade-admitted jurors within VERIFIED tier.
 * If even the lowest floor can't fill `count`, the dispute proceeds with
 * `insufficient: true` rather than picking near-zero-score jurors.
 *
 * Why relaxations at all: rigid caps stalled the dispute pipeline whenever
 * the eligible pool was lopsided on either axis. Diversity + skill stay a
 * *preference* (Pass 1 wins when both can be satisfied) but no longer
 * prevent reaching `count`.
 *
 * Determinism: every node runs the same passes against the same seeded
 * shuffle of the same candidate set. Same input → same output.
 *
 * @param {Array} shuffled        candidates, each with { tip_id, region, score }
 * @param {number} count          target jury size
 * @param {number} maxPerRegion   Pass-1 geographic cap (still respected when achievable)
 * @param {number} minScore       Pass-1/2 score threshold
 * @param  {...number} fallbackFloors  optional cascade floors applied in order, geo cap off
 * @returns {string[]}            selected tip_ids; length === count when pool allows
 */
function _pickWithGeoCap(shuffled, count, maxPerRegion, minScore = 0, ...fallbackFloors) {
  const selected = [];
  const selectedSet = new Set();
  const regionCount = {};

  // Pass 1: preferred — score ≥ minScore AND geo cap respected
  for (const id of shuffled) {
    if ((id.score ?? Infinity) < minScore) continue;
    const region = id.region || "XX";
    if ((regionCount[region] || 0) >= maxPerRegion) continue;
    regionCount[region] = (regionCount[region] || 0) + 1;
    selected.push(id.tip_id);
    selectedSet.add(id.tip_id);
    if (selected.length === count) return selected;
  }

  // Pass 2: relax geo cap, keep main score floor
  for (const id of shuffled) {
    if (selectedSet.has(id.tip_id)) continue;
    if ((id.score ?? Infinity) < minScore) continue;
    selected.push(id.tip_id);
    selectedSet.add(id.tip_id);
    if (selected.length === count) return selected;
  }

  // Pass 3+: cascade through fallback floors. Each floor must be strictly
  // lower than the previous active floor — non-decreasing entries are
  // skipped to prevent redundant passes.
  let currentFloor = minScore;
  for (const floor of fallbackFloors) {
    if (typeof floor !== "number" || floor >= currentFloor) continue;
    for (const id of shuffled) {
      if (selectedSet.has(id.tip_id)) continue;
      if ((id.score ?? Infinity) < floor) continue;
      selected.push(id.tip_id);
      selectedSet.add(id.tip_id);
      if (selected.length === count) return selected;
    }
    currentFloor = floor;
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

  // HARD-EXCLUDE filter: never include the author, the disputer, any
  // revoked identity, or any organization. Orgs are entities (companies,
  // AI tools, services) — adjudication seats (juror / expert / reviewer)
  // are reserved for personal identities making a human judgment call.
  // Score and geographic-diversity are SOFT preferences applied inside
  // _pickWithGeoCap (Pass 1 strict, Passes 2-3 progressively relaxed).
  // Sort by tip_id for determinism across nodes before shuffling.
  const candidates = allIdentities
    .filter(id => {
      if (id.tip_id === authorTipId || id.tip_id === disputerTipId) return false;
      if (dag.isRevoked(id.tip_id)) return false;
      const tipIdType = id.tip_id_type || TIP_ID_TYPES.PERSONAL;
      if (tipIdType !== TIP_ID_TYPES.PERSONAL) return false;
      // Juror opt-in (issue #107): seated only when the identity explicitly
      // set juror_consent. Reviewer/expert consent do NOT imply juror consent
      // — each adjudication role is opted into independently.
      const consent = id.juror_consent;
      if (consent !== true && consent !== 1) return false;
      return true;
    })
    .map(id => ({ ...id, score: scoring.getScore(id.tip_id).score }))
    .sort((a, b) => (a.tip_id < b.tip_id ? -1 : a.tip_id > b.tip_id ? 1 : 0)); // binary, not locale: selection must be identical on every node

  if (candidates.length < JURY.SIZE) {
    return { jurors: candidates.map(c => c.tip_id), insufficient: true, seed, identityCount };
  }

  const shuffled = _seededShuffle(candidates, seed);
  const jurors = _pickWithGeoCap(
    shuffled, JURY.SIZE, JURY.MAX_SAME_COUNTRY,
    JURY.MIN_SCORE, JURY.MIN_SCORE_FALLBACK,
  );

  return { jurors, insufficient: jurors.length < JURY.SIZE, seed, identityCount };
}

/**
 * Deterministic expert selection for Stage 3 appeal.
 * Same algorithm as jury but higher score threshold and 3 experts.
 */
function selectExperts(dag, scoring, appealTxId, authorTipId, disputerTipId, ctid = null) {
  const allIdentities = dag.getAllIdentities();
  const identityCount = allIdentities.length;

  const seed = shake256(`${appealTxId}:${identityCount}`);

  // Stage-2 jurors are excluded from the Stage-3 panel: same dispute, a
  // fresh judicial body — re-using a juror is a conflict of interest and
  // also leaks information across stages (a Stage-2 minority voter judging
  // their own loss). When `ctid` is wired through, look up summoned jurors
  // for that ctid (is_appeal=false) and exclude them.
  const priorJurors = ctid && typeof dag.getTxsByTypeAndCtid === "function"
    ? new Set(
      dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid)
        .filter(s => !s.data?.is_appeal)
        .map(s => s.data?.juror_tip_id)
        .filter(Boolean)
    )
    : new Set();

  // Hard excludes — author, disputer, revoked, prior-stage jurors,
  // organizations. Adjudication seats are reserved for personal
  // identities (see selectJury for the same rationale).
  // Score + geo-diversity are soft preferences relaxed by _pickWithGeoCap.
  const candidates = allIdentities
    .filter(id => {
      if (id.tip_id === authorTipId || id.tip_id === disputerTipId) return false;
      if (priorJurors.has(id.tip_id)) return false;
      if (dag.isRevoked(id.tip_id)) return false;
      const tipIdType = id.tip_id_type || TIP_ID_TYPES.PERSONAL;
      if (tipIdType !== TIP_ID_TYPES.PERSONAL) return false;
      // Expert opt-in (issue #107): seated only when the identity explicitly
      // set expert_consent. Independent of reviewer/juror consent.
      const consent = id.expert_consent;
      if (consent !== true && consent !== 1) return false;
      return true;
    })
    .map(id => ({ ...id, score: scoring.getScore(id.tip_id).score }))
    .sort((a, b) => (a.tip_id < b.tip_id ? -1 : a.tip_id > b.tip_id ? 1 : 0)); // binary, not locale: selection must be identical on every node

  if (candidates.length < APPEAL.EXPERT_COUNT) {
    return { experts: candidates.map(c => c.tip_id), insufficient: true, seed, identityCount };
  }

  const shuffled = _seededShuffle(candidates, seed);
  // Cascade: 850 → 700 (jury-tier) → 500 (VERIFIED-tier ultimate floor).
  // The ultimate floor is borrowed from JURY.MIN_SCORE_FALLBACK rather than
  // duplicated as a 4th genesis constant — semantically it represents
  // "VERIFIED tier is the absolute minimum for any judicial role," shared
  // across jury and expert selection. If governance later wants
  // independent expert/jury floors, split into expert_min_score_floor.
  const experts = _pickWithGeoCap(
    shuffled, APPEAL.EXPERT_COUNT, APPEAL.MAX_SAME_COUNTRY,
    APPEAL.MIN_EXPERT_SCORE, APPEAL.MIN_EXPERT_SCORE_FALLBACK, JURY.MIN_SCORE_FALLBACK,
  );

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
  // A deadlocked but quorate jury (equal match/mismatch) produced NO decisive
  // result, so it is treated exactly like NO_QUORUM: escalate to Stage 3, or
  // refund if no expert panel can form. It is NOT a merits dismissal, so the
  // disputer is never forfeited and the author earns no vindication on a tie.
  const quorumMet = totalVotes >= JURY.QUORUM && nonAbstain >= JURY.MAJORITY_VOTE;
  const isTie = matchCount === mismatchCount;

  const timestamp = nowMs();
  const txs = [];
  const getRecentPrev = () => dag.getRecentPrev();

  const rec = dag.getContent(ctid);
  const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
  const disputeData = disputeTxs[0]?.data || {};
  const disputerTipId = disputeData.disputer_tip_id;
  const authorTipId = rec?.author_tip_id;
  const revealedIds = new Set(filteredReveals.map(r => r.data.juror_tip_id));
  // Pre-fetch Stage-2 commit txs once — determines no-commit vs no-reveal penalty split
  const jurorCommitTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid)
    .filter(c => !c.data?.is_appeal);

  // ── NO_QUORUM / deadlock (no decisive result) ─────────────────────────────
  if (!quorumMet || isTie) {
    // A Stage-2 NO_QUORUM normally auto-escalates to a Stage-3 expert panel.
    // But that escalation must only happen if a panel that could actually
    // reach quorum can be formed. If the eligible expert pool (after the
    // score floors + conflict-of-interest filter) is too small, escalating
    // would summon too few experts to ever reach APPEAL.MIN_VOTES, and in
    // the zero-expert case the appeal would HANG forever: the appeal-
    // resolution trigger is driven by expert-summons reveal deadlines, so
    // with no summons no deadline ever fires and APPEAL_RESULT is never
    // emitted. We therefore decide escalate-vs-terminate up front.
    //
    // The decision uses the expert COUNT, not the selected identities. The
    // count equals min(eligiblePoolSize, EXPERT_COUNT), which is identical
    // on every node at the same chain height (the pool is pure DAG state);
    // only WHICH experts a node picks depends on the per-node seed. So the
    // escalate-vs-terminate decision is deterministic.
    const appealTx = nodeSignedAuto({
      tx_type: TX_TYPES.APPEAL_FILED,
      timestamp,
      prev: getRecentPrev(),
      data: { ctid, appellant_tip_id: "SYSTEM_AUTO_ESCALATION", stage2_verdict: VERDICT.NO_QUORUM, stake: 0 },
    }, config);
    const experts = selectExperts(dag, scoring, appealTx.tx_id, authorTipId, disputerTipId, ctid);
    const canEscalate = experts.experts.length >= APPEAL.MIN_VOTES;

    // Emit ADJUDICATION_RESULT (verdict=NO_QUORUM) FIRST so every Stage-2
    // dispute ends with a verdict tx. `terminal` marks the case undecidable
    // (no Stage-3 panel possible) so the commit-handler restores content
    // status instead of leaving it parked awaiting an appeal that will
    // never come.
    const noQuorumResultTx = nodeSignedAuto({
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp,
      prev: getRecentPrev(),
      data: {
        ctid,
        verdict: VERDICT.NO_QUORUM,
        terminal: !canEscalate,
        tie: quorumMet && isTie,   // audit: deadlock (quorate, no majority) vs low-participation no-quorum
        declared_origin: disputeData.declared_origin || rec?.origin_code,
        confirmed_origin: null,
        reason: disputeData.reason,
        author_tip_id: authorTipId,
        author_score_delta: 0,
        pre_dispute_status: disputeData.pre_dispute_status || CONTENT_STATUS.REGISTERED,
        match_count: matchCount,
        mismatch_count: mismatchCount,
        abstain_count: abstainCount,
        juror_votes: filteredReveals.map(r => ({ juror_tip_id: r.data.juror_tip_id, vote: r.data.vote })),
      },
    }, config);
    txs.push(noQuorumResultTx);

    // No-show penalties always apply: the absent jurors are the ones who
    // broke quorum, regardless of whether the case escalates or terminates.
    // relatedTxId is the appeal (escalating) or the result (terminal).
    const noShowRelatedTxId = canEscalate ? appealTx.tx_id : noQuorumResultTx.tx_id;
    for (const s of summons) {
      if (!revealedIds.has(s.data.juror_tip_id)) {
        const hasCommit = jurorCommitTxs.some(c => c.data?.juror_tip_id === s.data.juror_tip_id);
        const delta = hasCommit ? -JURY.JUROR_NO_REVEAL_PENALTY : -JURY.JUROR_NO_COMMIT_PENALTY;
        const reason = hasCommit ? `Jury no-reveal on ${ctid}` : `Jury no-commit on ${ctid}`;
        txs.push(scoring.buildScoreUpdateTx({
          tipId: s.data.juror_tip_id, delta,
          reason, ctid, relatedTxId: noShowRelatedTxId,
          timestamp, getRecentPrev, config,
        }));
      }
    }

    if (!canEscalate) {
      // Terminal NO_QUORUM: no Stage-3 panel possible, the case is
      // undecidable. Content stands (its ADJUDICATION_RESULT restores
      // pre-dispute status in the commit-handler). Refund the disputer:
      // they forfeit only when a panel actually rules their dispute
      // groundless, never when the system fails to decide it.
      if (disputerTipId) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: disputerTipId, delta: DISPUTE.DISPUTER_STAKE,
          reason: `Dispute refunded (terminal no-quorum) on ${ctid}`,
          ctid, relatedTxId: noQuorumResultTx.tx_id,
          timestamp, getRecentPrev, config,
        }));
      }
      log.info(`Jury NO_QUORUM on ${ctid} — terminal (no expert panel formable, ${experts.experts.length} eligible < ${APPEAL.MIN_VOTES}); disputer refunded`);
      return { txs, verdict: VERDICT.NO_QUORUM, terminal: true, auto_appeal: false, matchCount, mismatchCount, abstainCount };
    }

    // Escalate to Stage 3.
    txs.push(appealTx);
    const commitDeadline = nowPlusMs(APPEAL.COMMIT_WINDOW_HOURS * 3600000);
    const revealDeadline = nowPlusMs((APPEAL.COMMIT_WINDOW_HOURS + APPEAL.REVEAL_WINDOW_HOURS) * 3600000);
    for (const expertTipId of experts.experts) {
      txs.push(_buildSummonsTx({
        ctid, disputeTxId: appealTx.tx_id, jurorTipId: expertTipId,
        seed: experts.seed, identityCount: experts.identityCount,
        commitDeadline, revealDeadline, isAppeal: true,
        timestamp, dag, config,
      }));
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

  // Author penalty value precomputed here so it lives on the
  // ADJUDICATION_RESULT tx as informational metadata (audit trail +
  // exact-reversal lookup by buildAppealBatch on overturn). The actual
  // score change is applied by a paired SCORE_UPDATE pushed below — the
  // RESULT tx itself only carries the offense increment (handled by
  // commit-handler via score-effects.applyScoreEffect's RESULT case).
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

  // Author penalty as a paired SCORE_UPDATE — single channel for every
  // score delta in the system. The offense increment lives on the
  // ADJUDICATION_RESULT tx above (RESULT-owns-offense rule); this tx
  // owns the score delta. APPEAL_RESULT can still reverse the exact
  // value because `author_score_delta` remains on the ADJUDICATION_RESULT
  // tx as the canonical source of truth.
  if (verdict === VERDICT.UPHELD && authorTipId && authorScoreDelta < 0) {
    txs.push(scoring.buildScoreUpdateTx({
      tipId: authorTipId, delta: authorScoreDelta,
      reason: `Author penalty: UPHELD on ${ctid}`,
      ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
    }));
  }

  // ── Juror score effects ───────────────────────────────────────────────────
  // Ties returned via the no-result branch above, so a decisive majority
  // exists here. (isTie is computed once near the vote tallies.)
  if (!isTie) {
    const majorityVote = mismatchCount > matchCount ? VOTE.MISMATCH : VOTE.MATCH;
    for (const reveal of filteredReveals) {
      const jurorTipId = reveal.data.juror_tip_id;
      if (reveal.data.vote === VOTE.ABSTAIN) continue;
      const isMajority = reveal.data.vote === majorityVote;
      txs.push(scoring.buildScoreUpdateTx({
        tipId: jurorTipId,
        delta: isMajority ? JURY.JUROR_MAJORITY_BONUS : -JURY.JUROR_MINORITY_PENALTY,
        reason: `Jury ${isMajority ? "majority" : "minority"} vote on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    }
  }

  // No-show penalties — no-commit vs no-reveal distinction
  for (const s of summons) {
    if (!revealedIds.has(s.data.juror_tip_id)) {
      const hasCommit = jurorCommitTxs.some(c => c.data?.juror_tip_id === s.data.juror_tip_id);
      const delta = hasCommit ? -JURY.JUROR_NO_REVEAL_PENALTY : -JURY.JUROR_NO_COMMIT_PENALTY;
      const reason = hasCommit ? `Jury no-reveal on ${ctid}` : `Jury no-commit on ${ctid}`;
      txs.push(scoring.buildScoreUpdateTx({
        tipId: s.data.juror_tip_id, delta,
        reason, ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    }
  }

  // Disputer outcome — stake-on-file model. The DISPUTER_STAKE is
  // deducted upfront in dispute-service.fileDispute (the SCORE_UPDATE
  // ride alongside CONTENT_DISPUTED). Here we only handle the verdict-
  // driven settlement:
  //   UPHELD              — refund stake + apply bonus (net +30)
  //   DISMISSED           — stake stays forfeited (no event needed; the
  //                         filing-time deduction is the penalty itself)
  //   CONSERVATIVE_LABEL  — refund stake, no bonus (disputer wasn't right
  //                         about the claimed origin, but author's
  //                         declaration was also wrong → neutral outcome)
  if (disputerTipId) {
    if (verdict === VERDICT.UPHELD) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: disputerTipId, delta: DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS,
        reason: `Dispute upheld on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    } else if (verdict === VERDICT.CONSERVATIVE_LABEL) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: disputerTipId, delta: DISPUTE.DISPUTER_STAKE,
        reason: `Dispute conservative-label on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    }
    // DISMISSED: no disputer event — filing-time stake deduction is the forfeit.
  }

  // ── Pre-scan reviewer CORRECT_BONUS overlay (Stage-2) ───────────────────
  // When this dispute came out of a CONFIRMED prescan-review, the
  // reviewer (= disputer_tip_id on the escalation tx) already gets the
  // standard disputer settlement above:
  //
  //   UPHELD             +stake (15) + UPHELD_BONUS (5) = +20
  //   CONSERVATIVE_LABEL +stake (15)                    = +15
  //   DISMISSED          0  (filing-time -15 stays forfeited)
  //
  // On top of that we add CORRECT_BONUS for the review work itself —
  // the reviewer did extra labour (the prescan-review decision) before
  // the dispute path even fired, so they earn an additional small
  // bonus when the verdict validates their CONFIRM. No overlay on
  // DISMISSED — the disputer settlement's stake forfeiture already
  // captures the "wrong call" penalty.
  //
  // Lifetime net per outcome (filing-time stake + Stage-2 batch + bonus):
  //   UPHELD             -15 + 20 + 5 = +10
  //   CONSERVATIVE_LABEL -15 + 15 + 5 = +5
  //   DISMISSED          -15 +  0 + 0 = -15
  const escalatedReview = typeof dag.getPrescanReviewsByCtid === "function"
    ? (dag.getPrescanReviewsByCtid(ctid) || []).find(r => r.state === "escalated_to_dispute")
    : null;
  if (escalatedReview && escalatedReview.assigned_reviewer
    && (verdict === VERDICT.UPHELD || verdict === VERDICT.CONSERVATIVE_LABEL)
    && REVIEWER.CORRECT_BONUS > 0) {
    txs.push(scoring.buildScoreUpdateTx({
      tipId: escalatedReview.assigned_reviewer,
      delta: REVIEWER.CORRECT_BONUS,
      reason: `review_correct_bonus:${escalatedReview.review_id}`,
      ctid, relatedTxId: resultTx.tx_id,
      timestamp, getRecentPrev, config,
    }));
  }

  // ── Wrong-DISMISS clawback (Stage-2) ──────────────────────────────────────
  // If there was a CLOSED_DISMISSED prescan review for this ctid and Stage-2
  // rules UPHELD, the reviewer who dismissed the flag was wrong. Reclaim the
  // CORRECT_BONUS paid at dismiss time (REVIEWER.WRONG_DISMISS_CLAWBACK, stored
  // as a negative delta). Net for wrong-dismiss reviewer = +5 (dismiss bonus)
  // + clawback = 0. Guard: only fires when no escalated_to_dispute review
  // exists (those ride the CONFIRM-bonus path above — a ctid cannot have both).
  if (verdict === VERDICT.UPHELD && !escalatedReview && REVIEWER.WRONG_DISMISS_CLAWBACK !== 0) {
    const dismissedReview = typeof dag.getPrescanReviewsByCtid === "function"
      ? (dag.getPrescanReviewsByCtid(ctid) || []).find(
        r => r.state === PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
      )
      : null;
    if (dismissedReview && dismissedReview.assigned_reviewer) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: dismissedReview.assigned_reviewer,
        delta: REVIEWER.WRONG_DISMISS_CLAWBACK,
        reason: `review_wrong_dismiss_clawback:${dismissedReview.review_id}`,
        ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    }
  }

  // Author vindication on DISMISSED. Spec (TIP_Scoring_v2 Reputation §):
  // a creator whose content the jury exonerates earns
  // DISPUTE.VINDICATION_BONUS — the only path that credits the author
  // through the dispute machinery. CONSERVATIVE_LABEL is neutral
  // (under-disclosure was honest but the claimed origin was off);
  // UPHELD/NO_QUORUM never trigger this.
  //
  // Reversal: if the disputer appeals and Stage-3 overturns to UPHELD,
  // the vindication is retracted (-VINDICATION_BONUS) by buildAppealBatch
  // — the author wasn't actually right after all.
  if (verdict === VERDICT.DISMISSED && authorTipId && DISPUTE.VINDICATION_BONUS > 0) {
    txs.push(scoring.buildScoreUpdateTx({
      tipId: authorTipId, delta: DISPUTE.VINDICATION_BONUS,
      reason: `Dispute vindication on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
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

  const timestamp = nowMs();
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
  // Pre-fetch Stage-3 commit txs once — determines no-commit vs no-reveal penalty split
  const expertCommitTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid)
    .filter(c => !!c.data?.is_appeal);

  // ── No decisive result at the final layer → terminal, refund, no penalty ──
  // Experts are the last stage, so a sub-quorum panel OR a tie (equal
  // match/mismatch) cannot escalate further. Neither is a merits ruling, so
  // we do NOT forfeit anyone: the original dispute's filing stake and the
  // appellant's appeal stake are both returned. Stage-2's settlement stands
  // (a tie does not overturn it), and no vindication is paid.
  const appealIsTie = matchCount === mismatchCount;
  // Precise audit flag: a deadlock is a QUORATE tie; a 0-reveal panel is
  // sub-quorum (0===0), not a deadlock, and is marked by `defaulted` instead.
  const appealDeadlock = nonAbstain >= APPEAL.MIN_VOTES && appealIsTie;
  if (nonAbstain < APPEAL.MIN_VOTES || appealIsTie) {
    const resultTx = nodeSignedAuto({
      tx_type: TX_TYPES.APPEAL_RESULT,
      timestamp,
      prev: getRecentPrev(),
      data: {
        ctid, verdict: VERDICT.DISMISSED, overturned: false, defaulted: true,
        tie: appealDeadlock,
        stage2_verdict: stage2Verdict || null,
        pre_dispute_status: preStatus,
        match_count: matchCount, mismatch_count: mismatchCount, abstain_count: abstainCount,
      },
    }, config);
    txs.push(resultTx);

    for (const s of summons) {
      if (!revealedIds.has(s.data.juror_tip_id)) {
        const hasCommit = expertCommitTxs.some(c => c.data?.juror_tip_id === s.data.juror_tip_id);
        const delta = hasCommit ? -JURY.EXPERT_NO_REVEAL_PENALTY : -JURY.EXPERT_NO_COMMIT_PENALTY;
        const reason = hasCommit ? `Expert no-reveal on ${ctid}` : `Expert no-commit on ${ctid}`;
        txs.push(scoring.buildScoreUpdateTx({
          tipId: s.data.juror_tip_id, delta,
          reason, ctid, relatedTxId: resultTx.tx_id,
          timestamp, getRecentPrev, config,
        }));
      }
    }

    // Refund the original filing stake when the dispute never got a merits
    // ruling at either stage (Stage-2 NO_QUORUM/tie auto-escalated here, then
    // Stage-3 also produced no result). Gated on stage2_verdict === NO_QUORUM:
    // a substantive Stage-2 verdict already settled the disputer, so refunding
    // here would double-pay. (The Stage-2-cannot-form-panel terminal path
    // refunds in buildAdjudicationBatch; mutually exclusive, shared reason
    // string, so SCORE_UPDATE dedup is a belt-and-braces guard.)
    if (stage2Verdict === VERDICT.NO_QUORUM && disputerTipId) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: disputerTipId, delta: DISPUTE.DISPUTER_STAKE,
        reason: `Dispute refunded (terminal no-quorum) on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    }

    // Refund the appellant's appeal stake: the appeal reached no verdict, so
    // the deposit is returned (forfeit only happens on a decisive loss, in
    // the not-overturned settlement path below). SYSTEM_AUTO_ESCALATION posts
    // no stake, so there is nothing to refund for it.
    if (appellantTipId && appellantTipId !== "SYSTEM_AUTO_ESCALATION") {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: appellantTipId, delta: APPEAL.APPELLANT_STAKE,
        reason: `Appeal stake refunded (no result) on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    }

    log.info(`Appeal no-result (${appealDeadlock ? "tie" : "sub-quorum"}) on ${ctid} — terminal DISMISSED, stakes refunded (${txs.length} txs in batch)`);
    return { txs, verdict: VERDICT.DISMISSED, defaulted: true, tie: appealDeadlock, tx_id: resultTx.tx_id, matchCount, mismatchCount, abstainCount };
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

  // Author-penalty delta for cases where Stage-3 produces the FIRST
  // applicable penalty: (a) overturn-of-DISMISSED (Stage-2 said no
  // offense; experts say UPHELD), or (b) NO_QUORUM→UPHELD (Stage-2
  // didn't reach a decision; Stage-3 is the first verdict). Both apply
  // a fresh Stage-2-style penalty here. Computed once so the value
  // lands in the APPEAL_RESULT tx for downstream consumers.
  const stage3AppliesFreshPenalty = (
    (stage2Verdict === VERDICT.DISMISSED && verdict === VERDICT.UPHELD)
    || (stage2Verdict === VERDICT.NO_QUORUM && verdict === VERDICT.UPHELD)
  );
  const overturnAuthorDelta = (stage3AppliesFreshPenalty && authorTipId)
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
      // Self-containment — both party tip_ids embedded so FE / analytics
      // / audits don't need to walk back to CONTENT_DISPUTED. Not load-
      // bearing for score effects (those flow through SCORE_UPDATE).
      author_tip_id: authorTipId,
      disputer_tip_id: disputerTipId,
      // Reversal data — commit-handler reads these to update content state.
      original_author_delta: stage2AuthorDelta,
      overturn_author_delta: overturnAuthorDelta,
      match_count: matchCount, mismatch_count: mismatchCount, abstain_count: abstainCount,
      expert_votes: filteredReveals.map(r => ({ juror_tip_id: r.data.juror_tip_id, vote: r.data.vote })),
    },
  }, config);
  txs.push(resultTx);

  // ── Appellant outcome ─────────────────────────────────────────────────────
  // Stake-on-file model: APPELLANT_STAKE was deducted at fileAppeal time
  // (the SCORE_UPDATE rides alongside APPEAL_FILED). Here we settle:
  //   overturned    → refund stake + apply OVERTURN_BONUS = +(stake + bonus)
  //   not overturned → no event (filing-time deduction stays forfeited)
  if (overturned && appellantTipId) {
    txs.push(scoring.buildScoreUpdateTx({
      tipId: appellantTipId, delta: APPEAL.APPELLANT_STAKE + APPEAL.OVERTURN_BONUS,
      reason: `Appeal overturned on ${ctid}`, ctid, relatedTxId: resultTx.tx_id,
      timestamp, getRecentPrev, config,
    }));

    // Reverse Stage-2 disputer effect under the stake-on-file model.
    // Stage-2 settlement deltas were:
    //   UPHELD     →  +stake +bonus  (refund + bonus = +30)
    //   DISMISSED  →  no event       (filing-time stake stayed forfeited)
    // Overturn flips that — for both directions, the new state is the
    // OPPOSITE Stage-2 outcome:
    //   UPHELD → DISMISSED    un-refund + un-bonus = -(stake + bonus) = -30
    //   DISMISSED → UPHELD    apply settlement now: stake refund + bonus = +30
    if (stage2Verdict === VERDICT.UPHELD && disputerTipId) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: disputerTipId, delta: -(DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS),
        reason: `Appeal overturned: Stage 2 settlement reversed on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    } else if (stage2Verdict === VERDICT.DISMISSED && disputerTipId) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: disputerTipId, delta: DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS,
        reason: `Appeal overturned: stake refunded + bonus on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    }

    // Reverse Stage-2 author penalty (overturn UPHELD → DISMISSED) OR
    // apply fresh author penalty (overturn DISMISSED → UPHELD). Score
    // delta only — offense_count adjustment is handled by APPEAL_RESULT
    // itself (RESULT-owns-offense rule).
    if (stage2Verdict === VERDICT.UPHELD && authorTipId && stage2AuthorDelta < 0) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: authorTipId, delta: -stage2AuthorDelta,
        reason: `Appeal overturned: Stage 2 penalty reversed on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
      // Stage-3 cleared the author — credit the vindication bonus that
      // Stage-2 didn't emit (because Stage-2 incorrectly UPHELD). Mirrors
      // what buildAdjudicationBatch would have emitted if Stage-2 had
      // ruled DISMISSED in the first place.
      if (DISPUTE.VINDICATION_BONUS > 0) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: authorTipId, delta: DISPUTE.VINDICATION_BONUS,
          reason: `Appeal overturned: vindication on ${ctid}`,
          ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
        }));
      }
    } else if (stage2Verdict === VERDICT.DISMISSED && authorTipId && overturnAuthorDelta < 0) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: authorTipId, delta: overturnAuthorDelta,
        reason: `Appeal overturned: mismatch confirmed on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
      // Retract the Stage-2 vindication — the author wasn't actually
      // right after all. Symmetric with the disputer-stake reversal a
      // few lines above: when an overturn flips the verdict, every
      // settlement that rode on the prior verdict gets reversed.
      if (DISPUTE.VINDICATION_BONUS > 0) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: authorTipId, delta: -DISPUTE.VINDICATION_BONUS,
          reason: `Appeal overturned: vindication retracted on ${ctid}`,
          ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
        }));
      }
    }

    // ── Pre-scan reviewer CORRECT_BONUS reversal/re-application (Stage-3) ─
    // The reviewer is the disputer (disputer_tip_id on the escalation
    // tx) — their stake refund / bonus / forfeit is already reversed
    // and re-applied by the disputer-overturn block above. The only
    // thing left for us is the CORRECT_BONUS overlay: reverse what
    // Stage-2 paid (if anything) and apply what Stage-3 says.
    //
    // Stage-2 paid CORRECT_BONUS on UPHELD or CONSERVATIVE_LABEL.
    // DISMISSED paid nothing extra.
    const escalatedReview = typeof dag.getPrescanReviewsByCtid === "function"
      ? (dag.getPrescanReviewsByCtid(ctid) || []).find(r => r.state === "escalated_to_dispute")
      : null;
    if (escalatedReview && escalatedReview.assigned_reviewer && REVIEWER.CORRECT_BONUS > 0) {
      const reviewerTipId = escalatedReview.assigned_reviewer;
      const stage2PaidBonus = stage2Verdict === VERDICT.UPHELD || stage2Verdict === VERDICT.CONSERVATIVE_LABEL;
      const stage3PaysBonus = verdict === VERDICT.UPHELD || verdict === VERDICT.CONSERVATIVE_LABEL;
      if (stage2PaidBonus) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: reviewerTipId, delta: -REVIEWER.CORRECT_BONUS,
          reason: `Appeal overturned: Stage 2 review_correct_bonus reversed on ${ctid}`,
          ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
        }));
      }
      if (stage3PaysBonus) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: reviewerTipId, delta: REVIEWER.CORRECT_BONUS,
          reason: `review_correct_bonus_on_appeal:${escalatedReview.review_id}`,
          ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
        }));
      }
    }

    // ── Wrong-DISMISS clawback reversal (Stage-3 overturn UPHELD→DISMISSED) ─
    // Stage-2 UPHELD applied a clawback to the reviewer who had DISMISSED.
    // Stage-3 overturns to DISMISSED → the dismiss was right after all →
    // give the reviewer their CORRECT_BONUS back (reverse the clawback).
    // Guard: only when Stage-2 was UPHELD (that's when the clawback fired) AND
    // Stage-3 fully clears the content (DISMISSED). The explicit
    // `verdict === DISMISSED` check makes this self-contained — it does not lean
    // on the enclosing `if (overturned)` to exclude UPHELD→UPHELD/CONSERVATIVE_LABEL,
    // so the clawback correctly STANDS whenever Stage-3 still finds a problem.
    // Also requires no escalated_to_dispute review (the two paths are mutually exclusive).
    if (stage2Verdict === VERDICT.UPHELD && verdict === VERDICT.DISMISSED
      && !escalatedReview && REVIEWER.WRONG_DISMISS_CLAWBACK !== 0) {
      const dismissedReview = typeof dag.getPrescanReviewsByCtid === "function"
        ? (dag.getPrescanReviewsByCtid(ctid) || []).find(
          r => r.state === PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
        )
        : null;
      if (dismissedReview && dismissedReview.assigned_reviewer) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: dismissedReview.assigned_reviewer,
          delta: -REVIEWER.WRONG_DISMISS_CLAWBACK,
          reason: `Appeal overturned: wrong_dismiss_clawback reversed on ${ctid}`,
          ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
        }));
      }
    }
  }
  // Not overturned: no settlement event for the appellant. The
  // filing-time stake deduction (in dispute-service.fileAppeal) is the
  // forfeit itself — appeal failed, stake stays consumed.

  // ── NO_QUORUM Stage-3 settlement ──────────────────────────────────────────
  // Stage-2 NO_QUORUM produced no settlement (no UPHELD bonus, no penalty,
  // disputer's stake stayed locked). Stage-3 is now the FIRST authoritative
  // verdict — apply settlement as if Stage-3 were the Stage-2 verdict:
  //   UPHELD             → disputer refund+bonus, fresh author penalty
  //   CONSERVATIVE_LABEL → disputer refund only, no author penalty
  //   DISMISSED          → no event (disputer's stake stays forfeited)
  // Appellant on NO_QUORUM auto-escalation is "SYSTEM_AUTO_ESCALATION"
  // (no real tip_id), so no appellant settlement event is emitted.
  if (stage2Verdict === VERDICT.NO_QUORUM) {
    if (verdict === VERDICT.UPHELD) {
      if (disputerTipId) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: disputerTipId, delta: DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS,
          reason: `Stage 3 verdict UPHELD: stake refunded + bonus on ${ctid}`,
          ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
        }));
      }
      if (authorTipId && overturnAuthorDelta < 0) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: authorTipId, delta: overturnAuthorDelta,
          reason: `Stage 3 verdict UPHELD: author penalty on ${ctid}`,
          ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
        }));
      }
    } else if (verdict === VERDICT.CONSERVATIVE_LABEL && disputerTipId) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: disputerTipId, delta: DISPUTE.DISPUTER_STAKE,
        reason: `Stage 3 verdict CONSERVATIVE_LABEL: stake refunded on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    }
    // DISMISSED on NO_QUORUM: stake stays forfeited (no event), matches
    // standard DISMISSED handling.

    // ── Pre-scan reviewer CORRECT_BONUS (NO_QUORUM → Stage-3 first
    // authoritative verdict) ──────────────────────────────────────────────
    // Stage-2 NO_QUORUM paid the disputer nothing (stake stayed locked).
    // The Stage-3 settlement above handles the disputer (= reviewer)
    // stake refund / bonus. We only add the CORRECT_BONUS overlay for
    // the review work when Stage-3 lands on UPHELD or CONSERVATIVE_LABEL.
    const noQuorumEscalatedReview = typeof dag.getPrescanReviewsByCtid === "function"
      ? (dag.getPrescanReviewsByCtid(ctid) || []).find(r => r.state === "escalated_to_dispute")
      : null;
    if (noQuorumEscalatedReview && noQuorumEscalatedReview.assigned_reviewer
      && (verdict === VERDICT.UPHELD || verdict === VERDICT.CONSERVATIVE_LABEL)
      && REVIEWER.CORRECT_BONUS > 0) {
      txs.push(scoring.buildScoreUpdateTx({
        tipId: noQuorumEscalatedReview.assigned_reviewer,
        delta: REVIEWER.CORRECT_BONUS,
        reason: `review_correct_bonus_no_quorum:${noQuorumEscalatedReview.review_id}`,
        ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    }

    // ── Wrong-DISMISS clawback (NO_QUORUM → Stage-3 first authoritative) ────
    // Stage-3 is the first authoritative verdict after Stage-2 NO_QUORUM.
    // If Stage-3 UPHELD, the reviewer who DISMISSED the content was wrong →
    // apply the clawback now (same semantics as Stage-2 UPHELD path above).
    // Mutually exclusive with the escalated_to_dispute path above.
    if (verdict === VERDICT.UPHELD && !noQuorumEscalatedReview && REVIEWER.WRONG_DISMISS_CLAWBACK !== 0) {
      const noQuorumDismissedReview = typeof dag.getPrescanReviewsByCtid === "function"
        ? (dag.getPrescanReviewsByCtid(ctid) || []).find(
          r => r.state === PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
        )
        : null;
      if (noQuorumDismissedReview && noQuorumDismissedReview.assigned_reviewer) {
        txs.push(scoring.buildScoreUpdateTx({
          tipId: noQuorumDismissedReview.assigned_reviewer,
          delta: REVIEWER.WRONG_DISMISS_CLAWBACK,
          reason: `review_wrong_dismiss_clawback_no_quorum:${noQuorumDismissedReview.review_id}`,
          ctid, relatedTxId: resultTx.tx_id,
          timestamp, getRecentPrev, config,
        }));
      }
    }
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
        delta: isMajority ? JURY.EXPERT_MAJORITY_BONUS : -JURY.EXPERT_MINORITY_PENALTY,
        reason: `Expert ${isMajority ? "majority" : "minority"} vote on ${ctid}`,
        ctid, relatedTxId: resultTx.tx_id, timestamp, getRecentPrev, config,
      }));
    }
  }

  // No-show experts — no-commit vs no-reveal distinction
  for (const s of summons) {
    if (!revealedIds.has(s.data.juror_tip_id)) {
      const hasCommit = expertCommitTxs.some(c => c.data?.juror_tip_id === s.data.juror_tip_id);
      const delta = hasCommit ? -JURY.EXPERT_NO_REVEAL_PENALTY : -JURY.EXPERT_NO_COMMIT_PENALTY;
      const reason = hasCommit ? `Expert no-reveal on ${ctid}` : `Expert no-commit on ${ctid}`;
      txs.push(scoring.buildScoreUpdateTx({
        tipId: s.data.juror_tip_id, delta,
        reason, ctid, relatedTxId: resultTx.tx_id,
        timestamp, getRecentPrev, config,
      }));
    }
  }

  log.info(`Appeal ${verdict} on ${ctid} — overturned=${overturned} (${txs.length} txs in batch)`);
  return { txs, verdict, overturned, confirmed_origin, matchCount, mismatchCount, abstainCount, tx_id: resultTx.tx_id };
}

module.exports = { selectJury, selectExperts, buildAdjudicationBatch, buildAppealBatch };
