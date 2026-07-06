/**
 * @file tests/consensus/content-float-determinism.test.js
 * @description Regression for the 2026-07-06 byzantine-fork incident: a
 * content row's prescan_probability is a float4 DB column (32-bit) but a
 * float64 in live memory. A restarted node hydrates 0.1 as 0.10000000149
 * (the float32 round-trip); a live node holds exact 0.1. Hashing the raw
 * float forked the state root between them.
 *
 * The canonicalizer must produce the SAME content leaf , hence the same
 * state root , whether prescan_probability arrived as the exact float64 or
 * the float32-rounded value. This test builds both and asserts equal roots.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { initCrypto, shake256 } = require(path.resolve(__dirname, "../../../shared/crypto"));
const PC = require(path.resolve(__dirname, "../../../shared/protocol-constants"));
const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const { initDAG } = require(path.resolve(__dirname, "../../src/dag"));

beforeAll(async () => {
  PC.init(getGenesisPayload().protocol_constants);
  await initCrypto();
});

// The float32 round-trip a float4 column applies on read-back.
function asFloat32(n) {
  const b = Buffer.alloc(4);
  b.writeFloatBE(n);
  return b.readFloatBE(0);
}

function contentRow(ctid, probability) {
  return {
    ctid,
    origin_code: "OH",
    content_hash: shake256(ctid),
    author_tip_id: "tip://id/US-abcdef0123456789",
    signer_tip_id: "tip://id/US-abcdef0123456789",
    authors: [{ tip_id: "tip://id/US-abcdef0123456789", role: "byline", signed: true }],
    attribution_mode: "self",
    extras: {},
    cna_version: "CNA-2.2",
    status: "registered",
    prescan_flagged: 0,
    prescan_probability: probability,
    prescan_tier: "low",
    prescan_status: "completed",
    prescan_completed_at: 1783036800000,
    prescan_assigned_node_id: "tip://node/1122334455667788",
    prescan_content_type: "text",
    prescan_overall_degraded: 0,
    content_type_hint: null,
    override: 0,
    registered_at: 1783036800000,
    registered_urls: ["https://example.org/x"],
    media: [],
    media_canonical_hash: null,
    tx_id: shake256("tx-" + ctid),
  };
}

describe("prescan_probability float determinism", () => {
  const probs = [0.1, 0.9, 0.12345, 0.37, 0.5, 0.0, 1.0];

  test("live float64 and hydrated float32 yield the same state root", () => {
    for (const p of probs) {
      const live = initDAG({ inMemory: true });
      const hydrated = initDAG({ inMemory: true });
      live.saveContent(contentRow("tip://c/OH-test-0001", p));
      hydrated.saveContent(contentRow("tip://c/OH-test-0001", asFloat32(p)));
      expect(hydrated.stateRoot()).toBe(live.stateRoot());
    }
  });

  test("different probabilities beyond quantization resolution still differ", () => {
    const a = initDAG({ inMemory: true });
    const b = initDAG({ inMemory: true });
    a.saveContent(contentRow("tip://c/OH-test-0002", 0.1000));
    b.saveContent(contentRow("tip://c/OH-test-0002", 0.2000));
    expect(a.stateRoot()).not.toBe(b.stateRoot());
  });

  test("non-finite / missing probability is stable (defaults, no throw)", () => {
    const a = initDAG({ inMemory: true });
    const b = initDAG({ inMemory: true });
    a.saveContent(contentRow("tip://c/OH-test-0003", 0));
    const row = contentRow("tip://c/OH-test-0003");
    delete row.prescan_probability;
    b.saveContent(row);
    expect(b.stateRoot()).toBe(a.stateRoot());
  });
});
