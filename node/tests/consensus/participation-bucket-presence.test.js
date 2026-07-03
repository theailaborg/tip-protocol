/**
 * @file tests/consensus/participation-bucket-presence.test.js
 * @description EPOCH_BUCKET_PRESENCE_PCT: a presence bucket ticks only when
 * the node appeared in >= pct of the bucket's best-observed anchor count, so
 * a per-slice drive-by can never buy a presence day while any genuinely
 * online node always qualifies.
 *
 * Own file: PC.init is once-per-process and this suite pins the default pct.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

const _pc = JSON.parse(JSON.stringify(getGenesisPayload().protocol_constants));
PC.init(_pc);  // no override: pins the code default of 70

// Requires AFTER the re-init so dag binds to the pinned pct.
const { initDAG } = require(path.join(SRC, "dag"));

function _appearances(dag, node, bucket, n) {
  for (let i = 0; i < n; i++) dag.incrementRotationParticipation(node, 1, bucket);
}

describe("EPOCH_BUCKET_PRESENCE_PCT default 70 (relative per-bucket presence)", () => {
  test("drive-by never ticks; online-all-hour always ticks; 70% boundary is inclusive", () => {
    const dag = initDAG({ inMemory: true });

    // 4 buckets, each with 10 anchors observed by the always-on node.
    for (let b = 0; b < 4; b++) {
      _appearances(dag, "tip://node/steady", b, 10);   // 100% of bucket max
      _appearances(dag, "tip://node/driveby", b, 1);   // 10% (one anchor per slice)
      _appearances(dag, "tip://node/boundary", b, 7);  // exactly 70%
    }
    _appearances(dag, "tip://node/partial", 0, 10);    // full hour 0 only
    _appearances(dag, "tip://node/partial", 1, 5);     // half of hour 1

    const by = Object.fromEntries(dag.getRotationParticipation(1).map(t => [t.node_id, t]));
    expect(by["tip://node/steady"].buckets).toBe(4);
    expect(by["tip://node/driveby"].buckets).toBe(0);
    expect(by["tip://node/boundary"].buckets).toBe(4);
    expect(by["tip://node/partial"].buckets).toBe(1);
  });

  test("bucket bar scales per bucket: a slow network hour lowers the bar for everyone in it", () => {
    const dag = initDAG({ inMemory: true });
    // Hour 0 saw only 3 anchors network-wide; a node in all 3 has full presence.
    _appearances(dag, "tip://node/a", 0, 3);
    _appearances(dag, "tip://node/b", 0, 3);
    const by = Object.fromEntries(dag.getRotationParticipation(1).map(t => [t.node_id, t]));
    expect(by["tip://node/a"].buckets).toBe(1);
    expect(by["tip://node/b"].buckets).toBe(1);
  });
});
