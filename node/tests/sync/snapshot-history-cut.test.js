/**
 * @file tests/sync/snapshot-history-cut.test.js
 * @description A snapshot's tx and commit history is cut at its header round, and the install leaves
 * the joiner with exactly the attested history: nothing from past the cut, none of its own stale rows.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));

const { buildCommittedDag } = require("../helpers/commit-builder");
const { attemptInstall } = require("../helpers/snapshot-install");

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

function lateTx(i) {
  const body = {
    tx_type: "REGISTER_CONTENT",
    timestamp: 1767225900000 + i * 1000,
    prev: [],
    data: { ctid: `tip://content/late-${i}`, origin_code: "OH", content_hash: shake256(`late-${i}`), author_tip_id: "tip://id/seed-author" },
  };
  body.tx_id = computeTxId(body);
  body.signature = "00";
  return body;
}

// A commit row `ahead` rounds past `base`, with its own index, timestamp and root.
function commitAt(base, round, overrides = {}) {
  const ahead = round - base.round;
  return {
    ...base, round,
    consensus_index: base.consensus_index + ahead,
    cert_timestamp: Number(base.cert_timestamp) + ahead * 1000,
    state_merkle_root: shake256(`root-${round}`),
    ...overrides,
  };
}

describe("snapshot history is cut at the header round", () => {
  test("txs and commits added while the stream is in flight stay out of the install", async () => {
    const fx = buildCommittedDag({ committeeSize: 2, seedTxs: 3 });
    const head = fx.sourceDag.getLatestCommit();
    const late = lateTx(1);
    const destDag = initDAG({ dbPath: ":memory:" });
    await attemptInstall(fx.sourceDag, destDag, {
      chunkSize: 64,
      onFirstServerFrame: () => {
        fx.sourceDag.addTx(late);
        fx.sourceDag.saveCommit(commitAt(head, head.round + 4));
      },
    });
    expect(destDag.getTx(late.tx_id)).toBeFalsy();
    expect(destDag.getCommit(head.round + 4)).toBeFalsy();
    expect(destDag.getLatestCommit().round).toBe(head.round);
    for (const t of fx.seededTxs) expect(destDag.getTx(t.tx_id)).toBeTruthy();
  });

  test("a stream carrying a commit row at or past its header round is refused", async () => {
    const fx = buildCommittedDag({ committeeSize: 2, seedTxs: 1 });
    const head = fx.sourceDag.getLatestCommit();
    const realIterate = fx.sourceDag.iterateAllCommitsExcept;
    // A serving peer that does not cut its history at the header.
    fx.sourceDag.iterateAllCommitsExcept = function* (round) { yield* realIterate(round); yield head; };
    const destDag = initDAG({ dbPath: ":memory:" });
    await expect(attemptInstall(fx.sourceDag, destDag, { chunkSize: 64 })).rejects.toThrow(/not cut at the header/);
  });
});
