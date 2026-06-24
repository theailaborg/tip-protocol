/**
 * @file tests/local-config-guard.test.js
 * @description Tier-boundary guard for issue #39 / A21. The 23 Tier-3 local
 * tunables (shared/local-config.js) must stay strictly disjoint from the
 * state-determining params that remain in the genesis consensus block. A key
 * appearing in BOTH would mean a per-node-tunable value is also baked into
 * genesis_hash (a leak); a state-determining key drifting INTO local-config
 * would let nodes silently fork. This test fails loudly on either mistake.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../shared");
const SRC = path.resolve(__dirname, "../src");
const LC = require(path.join(SHARED, "local-config"));
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

// The state-determining keys that MUST remain agreed (in genesis_hash).
// Tier-2 (governable later) + Tier-1 (bft_time_genesis_ms, the BFT-time anchor).
const AGREED_CONSENSUS_KEYS = [
  "votes_retention_rounds",
  "max_txs_per_certificate",
  "certificate_max_bytes",
  "gc_depth",
  "bft_time_genesis_ms",
  "committee_rotation_interval_commits",
  "committee_rotation_participation_pct_of_interval",
];

const localKeysLower = Object.keys(LC).map((k) => k.toLowerCase());
const consensusKeys = Object.keys(getGenesisPayload().protocol_constants.consensus);

describe("Tier-3 local-config / agreed-genesis disjointness (#39/A21)", () => {
  test("no local-config key also lives in the genesis consensus block", () => {
    const leaked = localKeysLower.filter((k) => consensusKeys.includes(k));
    expect(leaked).toEqual([]);
  });

  test("every agreed (state-determining) key is still present in genesis", () => {
    for (const k of AGREED_CONSENSUS_KEYS) {
      expect(consensusKeys).toContain(k);
    }
  });

  test("genesis consensus block holds ONLY the agreed keys (no Tier-3 re-added)", () => {
    expect([...consensusKeys].sort()).toEqual([...AGREED_CONSENSUS_KEYS].sort());
  });

  test("no agreed key has been moved into local-config", () => {
    for (const k of AGREED_CONSENSUS_KEYS) {
      expect(localKeysLower).not.toContain(k);
    }
  });

  test("each local-config knob is the value the CONSENSUS getter returns (repoint intact)", () => {
    // If a getter still read _c() instead of LC, this would diverge.
    for (const upper of Object.keys(LC)) {
      expect(CONSENSUS[upper]).toBe(LC[upper]);
    }
  });

  test("the local tunable set is exactly the 23 documented in issue #39", () => {
    expect(Object.keys(LC).length).toBe(23);
  });
});
