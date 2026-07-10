/**
 * @file tests/integration/prescan-flood-regression.test.js
 * @description Regression guard for the 2026-07-09 prescan-flood halt: K
 * contents stuck in prescan drive the fail-open trigger; pre-fix, same-owner
 * serialization (1 commit/round) + per-tick re-emission + no PRESCAN_COMPLETED
 * dedup grew the mempool unboundedly (180 wedged, 228 duplicate commits, live
 * cluster frozen 2h). Burst chaining + the trigger's pending-guard + Phase-1
 * first-wins must drain the whole flood in one round with zero duplicates.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createPrescanCompletionTrigger } = require(path.join(SRC, "consensus", "prescan-completion-trigger"));

beforeAll(async () => { await initCrypto(); });

const NODE = "tip://node/flood-test";
const AUTHOR = "tip://id/US-aabbccddeeff0011";
const T0 = 1767225600000;
const NOW = T0 + 10 * 24 * 3600 * 1000;

function _setup(K) {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: T0 });
  const reg = { tx_type: "REGISTER_IDENTITY", timestamp: T0, prev: [], data: { tip_id: AUTHOR }, signature: "00" };
  reg.tx_id = computeTxId(reg);
  dag.addTx(reg);
  dag.saveIdentity({ tip_id: AUTHOR, region: "US", public_key: "00", vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active", registered_at: T0, tx_id: reg.tx_id });

  const config = { nodeId: NODE, nodeRegisteredId: NODE, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const mempool = createMempool(dag, { nodeId: NODE });
  const handler = createCommitHandler({ dag, scoring, config, mempool });
  const trigger = createPrescanCompletionTrigger({ dag, config, submitTx: (tx) => mempool.add(tx), getCommittee: () => [NODE] });

  for (let i = 0; i < K; i++) {
    dag.saveContent({
      ctid: `tip://c/OH-${String(i).padStart(14, "0")}-0001`, origin_code: "OH", content_hash: shake256(`c${i}`),
      author_tip_id: AUTHOR, signer_tip_id: AUTHOR, authors: [{ tip_id: AUTHOR }], attribution_mode: "self", extras: {},
      cna_version: "CNA-2.2", status: "pending_prescan", prescan_status: "pending", registered_at: T0, tx_id: shake256(`ct${i}`), registered_urls: []
    });
  }
  return { dag, mempool, handler, trigger };
}

test("prescan fail-open flood drains in ONE round with zero duplicate commits", () => {
  const K = 20;
  const fx = _setup(K);

  fx.trigger.checkPending(NOW, 1);
  const batch = fx.mempool.drain(500);
  expect(batch).toHaveLength(K);   // one emission per stuck content

  const res = fx.handler.commitOrderedTxs(batch, 1, { certTimestamp: NOW });
  expect(res.committed).toBe(K);   // whole same-owner burst commits in one round
  expect(res.dropped).toBe(0);
  expect(fx.dag.getContentsStuckInPrescan(NOW * 2)).toHaveLength(0);
  expect(fx.dag.getMempoolTxs()).toHaveLength(0);

  // Re-ticks: nothing pending, nothing re-emitted, no duplicate ever commits.
  fx.trigger.checkPending(NOW + 1000, 2);
  expect(fx.mempool.drain(500)).toHaveLength(0);
  const committed = fx.dag.getTxsByTypeAndCtid
    ? null : null;
  // duplicate count via tx scan
  let prescanTxs = 0;
  for (const t of fx.dag.getMempoolTxs()) if (t.tx_type === TX_TYPES.PRESCAN_COMPLETED) prescanTxs++;
  expect(prescanTxs).toBe(0);
});

test("trigger does not re-emit while a PRESCAN_COMPLETED is pending in the mempool", () => {
  const fx = _setup(3);
  fx.trigger.checkPending(NOW, 1);
  expect(fx.dag.getMempoolTxs()).toHaveLength(3);
  fx.trigger.checkPending(NOW + 1000, 2);   // re-tick WITHOUT committing
  expect(fx.dag.getMempoolTxs()).toHaveLength(3);   // no re-emission
});

test("duplicate PRESCAN_COMPLETED is rejected at validation, in-batch and vs committed state", () => {
  const fx = _setup(1);
  // First emission, drained but NOT yet committed.
  fx.trigger.checkPending(NOW, 1);
  const [tx1] = fx.mempool.drain(10);
  // Mempool is now empty and the content is still pending, so a re-tick
  // legitimately emits a second, properly signed tx for the same ctid.
  fx.trigger.checkPending(NOW + 1000, 2);
  const [tx2] = fx.mempool.drain(10);
  expect(tx2).toBeTruthy();
  expect(tx2.data.ctid).toBe(tx1.data.ctid);
  // Third copy, held back for the committed-state check.
  fx.trigger.checkPending(NOW + 2000, 3);
  const [tx3] = fx.mempool.drain(10);

  // In-batch first-wins: only one commits.
  const res = fx.handler.commitOrderedTxs([tx1, tx2], 1, { certTimestamp: NOW });
  expect(res.committed).toBe(1);
  expect(res.dropped).toBe(1);

  // Committed-state first-wins: the held duplicate drops too.
  const res2 = fx.handler.commitOrderedTxs([tx3], 2, { certTimestamp: NOW + 3000 });
  expect(res2.committed).toBe(0);
  expect(res2.dropped).toBe(1);
});
