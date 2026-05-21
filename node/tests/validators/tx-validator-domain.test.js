/**
 * @file tests/validators/tx-validator-domain.test.js
 * @description Direct unit tests for the L3 (validateBusinessRules) checks
 * on BIND_DOMAIN and UNBIND_DOMAIN.
 *
 * The whole point of L3: gossipped txs on a remote node hit exactly these
 * checks before any signature work runs, so format / enum / ordering
 * violations get caught with a fast diagnostic instead of failing late at
 * canonical-payload reconstruction.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");

const { validateBusinessRules } = require(path.join(SRC, "validators", "tx-validator"));

function _bindTx(overrides = {}) {
  return {
    tx_type: "BIND_DOMAIN",
    data: {
      tip_id:            "tip://id/US-aaaaaaaaaaaaaaaa",
      node_id:           "tip://node/n1",
      domain:            "acmenews.com",
      method:            "http",
      binding_state:     "verified",
      claim_signature:   "00".repeat(8),
      binding_signature: "00".repeat(8),
      claimed_at:        1778580000000,
      verified_at:       1778580030000,
      ...overrides,
    },
  };
}

function _unbindTx(overrides = {}) {
  return {
    tx_type: "UNBIND_DOMAIN",
    data: {
      domain:           "acmenews.com",
      node_id:          "tip://node/n1",
      reason:           "verification_lost",
      revoked_at:       1778580000000,
      unbind_signature: "00".repeat(8),
      ...overrides,
    },
  };
}

describe("validateBusinessRules — BIND_DOMAIN", () => {
  test("happy path passes", () => {
    const r = validateBusinessRules(_bindTx());
    expect(r.valid).toBe(true);
  });

  test("tip_id without tip://id/ prefix rejected", () => {
    const r = validateBusinessRules(_bindTx({ tip_id: "US-aaaa" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/tip_id must be a tip:\/\/id\/\.\.\. string/);
  });

  test("node_id without tip://node/ prefix rejected", () => {
    const r = validateBusinessRules(_bindTx({ node_id: "n1" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/node_id must be a tip:\/\/node\/\.\.\. string/);
  });

  test("malformed domain rejected", () => {
    const r = validateBusinessRules(_bindTx({ domain: "no-dot" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/domain must be a valid hostname/);
  });

  test("invalid method rejected", () => {
    const r = validateBusinessRules(_bindTx({ method: "ftp" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/method must be one of/);
  });

  test("binding_state other than 'verified' rejected on a committed tx", () => {
    const r = validateBusinessRules(_bindTx({ binding_state: "pending_verification" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/binding_state must be "verified"/);
  });

  test("non-ISO claimed_at rejected", () => {
    const r = validateBusinessRules(_bindTx({ claimed_at: "yesterday" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/claimed_at must be a valid epoch ms timestamp/);
  });

  test("non-ISO verified_at rejected", () => {
    const r = validateBusinessRules(_bindTx({ verified_at: "tomorrow" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/verified_at must be a valid epoch ms timestamp/);
  });

  test("verified_at before claimed_at rejected (logical-ordering guard)", () => {
    const r = validateBusinessRules(_bindTx({
      claimed_at:  1778580000000,
      verified_at: 1778579999000,
    }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/verified_at must not precede claimed_at/);
  });

  test("verified_at exactly equal to claimed_at accepted", () => {
    const r = validateBusinessRules(_bindTx({
      claimed_at:  1778580000000,
      verified_at: 1778580000000,
    }));
    expect(r.valid).toBe(true);
  });
});

describe("validateBusinessRules — UNBIND_DOMAIN", () => {
  test("happy path passes", () => {
    const r = validateBusinessRules(_unbindTx());
    expect(r.valid).toBe(true);
  });

  test("node_id without tip://node/ prefix rejected", () => {
    const r = validateBusinessRules(_unbindTx({ node_id: "n1" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/node_id must be a tip:\/\/node\/\.\.\. string/);
  });

  test("malformed domain rejected", () => {
    const r = validateBusinessRules(_unbindTx({ domain: "...." }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/domain must be a valid hostname/);
  });

  test("reason outside the canonical enum rejected", () => {
    const r = validateBusinessRules(_unbindTx({ reason: "made_up_reason" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/reason must be one of/);
  });

  test("non-ISO revoked_at rejected", () => {
    const r = validateBusinessRules(_unbindTx({ revoked_at: "right-now" }));
    expect(r.valid).toBe(false);
    expect(r.errors.join("\n")).toMatch(/revoked_at must be a valid epoch ms timestamp/);
  });

  test("each canonical reason accepted", () => {
    for (const reason of ["owner_revoked", "tip_id_revoked", "verification_lost", "admin_action"]) {
      const r = validateBusinessRules(_unbindTx({ reason }));
      expect(r.valid).toBe(true);
    }
  });
});
