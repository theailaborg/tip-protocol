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

  test("the local tunable set size is pinned (bump this + document the knob in .env.example when adding one)", () => {
    expect(Object.keys(LC).length).toBe(32);
  });
});

// .env.example documents each Tier-3 knob with its RECOMMENDED default value so
// an operator can revert a local override. Those values must never drift from
// the real defaults in shared/local-config.js.
describe(".env.example Tier-3 recommended defaults match local-config (#39)", () => {
  const fs = require("fs");
  const ROOT = path.resolve(__dirname, "../..");

  // Source-of-truth defaults parsed straight from `_num("TIP_X", N)` literals —
  // independent of process.env, so an ambient override can't skew the check.
  const lcSource = fs.readFileSync(path.join(SHARED, "local-config.js"), "utf8");
  const defaults = {};
  for (const m of lcSource.matchAll(/_num\(\s*"(TIP_[A-Z0-9_]+)"\s*,\s*(\d+)\s*\)/g)) {
    defaults[m[1]] = Number(m[2]);
  }

  // Recommended values documented in the .env.example Tier-3 section.
  const lines = fs.readFileSync(path.join(ROOT, ".env.example"), "utf8").split("\n");
  const start = lines.findIndex((l) => /Tier-3 Local Tunables/.test(l));
  const documented = {};
  if (start >= 0) {
    for (let i = start + 1; i < lines.length; i++) {
      if (/^#\s*─{3,}/.test(lines[i])) break;   // next section banner
      const m = lines[i].match(/^#\s*(TIP_[A-Z0-9_]+)\s*=\s*(\S+)\s*$/);
      if (m) documented[m[1]] = Number(m[2]);
    }
  }

  test("parsed all 23 defaults from local-config.js, one per knob", () => {
    expect(Object.keys(defaults).length).toBe(Object.keys(LC).length);
    for (const key of Object.keys(LC)) expect(defaults).toHaveProperty("TIP_" + key);
  });

  test(".env.example has a Tier-3 section listing every knob", () => {
    expect(start).toBeGreaterThanOrEqual(0);
    const missing = Object.keys(defaults).filter((e) => !(e in documented));
    expect(missing).toEqual([]);
  });

  test(".env.example Tier-3 section has no entry that is not a real knob", () => {
    const stale = Object.keys(documented).filter((e) => !(e in defaults));
    expect(stale).toEqual([]);
  });

  test("each recommended value equals the local-config default (no drift)", () => {
    const mismatches = [];
    for (const env of Object.keys(defaults)) {
      if (documented[env] !== defaults[env]) {
        mismatches.push(`${env}: .env.example=${documented[env]} default=${defaults[env]}`);
      }
    }
    expect(mismatches).toEqual([]);
  });
});
