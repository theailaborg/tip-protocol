/**
 * @file @tip-protocol/node/src/scheduler.js
 * @description Scheduled background tasks for the TIP node.
 *
 * Tasks:
 *   1. Merkle root publication (every 6 hours) — v2 FIX-02
 *   2. Score recomputation sweep (every 12 hours)
 *   3. Clean-record bonus application (daily)
 *   4. Peer sync ping (every 30 seconds)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { TX_TYPES }          = require("../../shared/constants");
const { shake256Multi }     = require("../../shared/crypto");
const { tallyVerdictAndApply, applyAppealVerdict } = require("./jury");
const { log }               = require("./logger");

function scheduledTasks(dag, scoring, gossip, config) {

  // 1. Merkle root publication (v2 FIX-02 audit mechanism)
  setInterval(() => {
    try {
      const count    = dag.dedupCount();
      const idCount  = dag.getTxsByType(TX_TYPES.REGISTER_IDENTITY).length;
      const root     = shake256Multi(count.toString(), idCount.toString(), new Date().toISOString().slice(0, 13));

      dag.addTx({
        tx_type:   TX_TYPES.MERKLE_ROOT_PUBLISHED,
        timestamp: new Date().toISOString(),
        data: {
          merkle_root:    root,
          dedup_count:    count,
          identity_count: idCount,
          node_id:        config.nodeId,
        },
      });

      log.info(`Merkle root published: ${root.slice(0, 16)}... (dedup: ${count}, identities: ${idCount})`);
    } catch (err) {
      log.warn("Merkle root publication failed:", err.message);
    }
  }, config.merklePublishInterval);

  // 2. Score recomputation sweep (every 12 hours)
  setInterval(() => {
    log.info("Starting scheduled score recomputation sweep...");
    scoring.recomputeAll().catch(err => log.warn("Score recomputation failed:", err.message));
  }, 12 * 60 * 60 * 1000);

  // 3. Peer health ping (every 30 seconds)
  setInterval(() => {
    const pc = gossip.peerCount();
    if (pc === 0 && config.peers.length > 0) {
      log.warn(`No active peers (${config.peers.length} configured). DAG sync paused.`);
    }
  }, 30_000);

  // 4. 90-day clean record bonus (every 24 hours)
  // Single DAG query returns only eligible identities — no full scan.
  setInterval(() => {
    try {
      const cutoff = new Date(Date.now() - 90 * 24 * 3600000).toISOString();
      const eligible = dag.getCleanRecordEligible(cutoff);
      for (const tipId of eligible) {
        scoring.applyScoreEvent(tipId, 10, "clean_record_bonus");
      }
      if (eligible.length > 0) log.info(`Clean record bonus: ${eligible.length} identities awarded +10`);
    } catch (err) {
      log.warn("Clean record bonus failed:", err.message);
    }
  }, 24 * 60 * 60 * 1000); // every 24 hours

  // 5. Verdict auto-trigger — jury + appeal in single pass (every 5 minutes)
  // Only processes disputed content with expired deadlines and no result yet.
  setInterval(() => {
    try {
      const disputedContent = dag.getContentByStatus("disputed");
      if (!disputedContent.length) return;

      const now = Date.now();
      for (const rec of disputedContent) {
        const ctid = rec.ctid;
        const allSummons = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid);
        if (!allSummons.length) continue;

        // Split into jury and appeal summons
        const jurySummons   = allSummons.filter(t => !t.data?.is_appeal);
        const appealSummons = allSummons.filter(t => t.data?.is_appeal === true);

        // Check appeal first (if exists, it's the active stage)
        if (appealSummons.length) {
          const deadline = new Date(appealSummons[0].data?.reveal_deadline).getTime();
          if (!isNaN(deadline) && now >= deadline) {
            const hasResult = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_RESULT, ctid).length > 0;
            if (!hasResult) {
              const reveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
                .filter(t => t.data?.is_appeal === true);
              log.info(`Auto-appeal verdict: ${ctid} (${reveals.length}/${appealSummons.length} reveals)`);
              const r = applyAppealVerdict(ctid, reveals, appealSummons, dag, scoring, config);
              log.info(`Appeal result: ${ctid} → ${r.verdict} (overturned: ${r.overturned})`);
            }
          }
          continue; // appeal is active, skip jury check
        }

        // Check jury (no appeal exists)
        if (jurySummons.length) {
          const deadline = new Date(jurySummons[0].data?.reveal_deadline).getTime();
          if (!isNaN(deadline) && now >= deadline) {
            const hasVerdict = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid).length > 0;
            if (!hasVerdict) {
              const reveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
                .filter(t => !t.data?.is_appeal);
              log.info(`Auto-jury verdict: ${ctid} (${reveals.length}/${jurySummons.length} reveals)`);
              const r = tallyVerdictAndApply(ctid, reveals, jurySummons, dag, scoring, config);
              log.info(`Jury result: ${ctid} → ${r.verdict}`);
            }
          }
        }
      }
    } catch (err) {
      log.warn("Verdict auto-trigger failed:", err.message);
    }
  }, 5 * 60 * 1000);

  log.info("Scheduled tasks initialised (Merkle root, score recomputation, peer health, jury verdict, appeal verdict)");
}

module.exports = { scheduledTasks };
