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
const { tallyVerdictAndApply } = require("./jury");
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

  // 4. Jury verdict auto-trigger (every 5 minutes)
  // Only checks content with status "disputed" — no full tx scan.
  setInterval(() => {
    try {
      // Get only disputed content (small set)
      const disputedContent = dag.getContentByStatus("disputed");
      if (!disputedContent.length) return;

      const now = Date.now();
      for (const rec of disputedContent) {
        const ctid = rec.ctid;

        // Direct query per CTID — no full tx scan
        const summons = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid);
        if (!summons.length) continue;

        // Check reveal deadline passed
        const revealDeadline = new Date(summons[0].data?.reveal_deadline).getTime();
        if (isNaN(revealDeadline) || now < revealDeadline) continue;

        // Check no verdict yet
        const hasVerdict = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid).length > 0;
        if (hasVerdict) continue;

        // Gather reveals and trigger verdict
        const reveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid);

        log.info(`Auto-triggering verdict for ${ctid}: ${reveals.length}/${summons.length} reveals, deadline passed`);
        const result = tallyVerdictAndApply(ctid, reveals, summons, dag, scoring, config);
        log.info(`Auto-verdict for ${ctid}: ${result.verdict} (${result.matchCount}-${result.mismatchCount}-${result.abstainCount})`);
      }
    } catch (err) {
      log.warn("Jury verdict auto-trigger failed:", err.message);
    }
  }, 5 * 60 * 1000); // every 5 minutes

  log.info("Scheduled tasks initialised (Merkle root, score recomputation, peer health, jury verdict)");
}

module.exports = { scheduledTasks };
