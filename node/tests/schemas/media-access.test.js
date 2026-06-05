/**
 * @file tests/schemas/media-access.test.js
 * @description Shape + replay-window tests for media-access schema.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { nowMs } = require(path.join(SHARED, "time"));
const schema = require(path.join(SRC, "schemas/media-access"));

const TIP_ID = "tip://id/US-aaaaaaaaaaaaaaaa";

function _base(ts = nowMs()) {
  return {
    ctid: "tip://c/OH-aabbccddeeff11-1234",
    idx: 0,
    requester_tip_id: TIP_ID,
    signature: "deadbeef",
    timestamp: ts,
  };
}

// Default fake DAG: requester is active, not revoked. Tests override
// individual flags to drive the failure branches.
function _fakeDag({ identity = { tip_id: TIP_ID, public_key: "ff".repeat(32), status: "active" },
  isRevoked = false } = {}) {
  return {
    getIdentity: (tipId) => (identity && identity.tip_id === tipId ? identity : null),
    isRevoked: () => isRevoked,
  };
}

describe("media-access.validateRequest — shape", () => {
  test("happy path passes", () => {
    expect(() => schema.validateRequest(_base(), { dag: _fakeDag() })).not.toThrow();
  });

  test("non-object input → input_invalid", () => {
    expect(() => schema.validateRequest(null, { dag: _fakeDag() }))
      .toThrow(expect.objectContaining({ code: "input_invalid" }));
  });

  test("malformed ctid → ctid_invalid", () => {
    expect(() => schema.validateRequest({ ..._base(), ctid: "not-a-ctid" }, { dag: _fakeDag() }))
      .toThrow(expect.objectContaining({ code: "ctid_invalid" }));
  });

  test("negative idx → idx_invalid", () => {
    expect(() => schema.validateRequest({ ..._base(), idx: -1 }, { dag: _fakeDag() }))
      .toThrow(expect.objectContaining({ code: "idx_invalid" }));
  });

  test("non-integer idx → idx_invalid", () => {
    expect(() => schema.validateRequest({ ..._base(), idx: 1.5 }, { dag: _fakeDag() }))
      .toThrow(expect.objectContaining({ code: "idx_invalid" }));
  });

  test("malformed requester_tip_id → requester_tip_id_required", () => {
    expect(() => schema.validateRequest({ ..._base(), requester_tip_id: "not-a-tipid" }, { dag: _fakeDag() }))
      .toThrow(expect.objectContaining({ code: "requester_tip_id_required" }));
  });

  test("non-hex signature → signature_required", () => {
    expect(() => schema.validateRequest({ ..._base(), signature: "NOT-HEX!" }, { dag: _fakeDag() }))
      .toThrow(expect.objectContaining({ code: "signature_required" }));
  });

  test("non-integer timestamp → timestamp_required", () => {
    expect(() => schema.validateRequest({ ..._base(), timestamp: "now" }, { dag: _fakeDag() }))
      .toThrow(expect.objectContaining({ code: "timestamp_required" }));
  });

  test("stale timestamp → timestamp_drift", () => {
    expect(() => schema.validateRequest(_base(nowMs() - 10 * 60 * 1000), { dag: _fakeDag() }))
      .toThrow(expect.objectContaining({ code: "timestamp_drift" }));
  });
});

describe("media-access.validateRequest — DAG presence", () => {
  test("requester not on DAG → 404 requester_not_found", () => {
    const dag = _fakeDag({ identity: null });
    expect(() => schema.validateRequest(_base(), { dag }))
      .toThrow(expect.objectContaining({ status: 404, code: "requester_not_found" }));
  });

  test("requester inactive → 403 requester_inactive", () => {
    const dag = _fakeDag({ identity: { tip_id: TIP_ID, public_key: "ff", status: "suspended" } });
    expect(() => schema.validateRequest(_base(), { dag }))
      .toThrow(expect.objectContaining({ status: 403, code: "requester_inactive" }));
  });

  test("requester revoked → 403 requester_revoked", () => {
    const dag = _fakeDag({ isRevoked: true });
    expect(() => schema.validateRequest(_base(), { dag }))
      .toThrow(expect.objectContaining({ status: 403, code: "requester_revoked" }));
  });

  test("missing deps.dag → throws (programmer error, not schemaError)", () => {
    expect(() => schema.validateRequest(_base(), {}))
      .toThrow(/deps\.dag required/);
  });
});

describe("media-access.buildChallenge — determinism", () => {
  test("output is the canonical colon-joined string", () => {
    const out = schema.buildChallenge({
      ctid: "tip://c/OH-aabbccddeeff11-1234",
      idx: 2,
      timestamp: 1780500000000,
      requester_tip_id: "tip://id/US-bbbbbbbbbbbbbbbb",
    });
    expect(out).toBe("MEDIA_ACCESS:tip://c/OH-aabbccddeeff11-1234:2:1780500000000:tip://id/US-bbbbbbbbbbbbbbbb");
  });

  test("any input flip changes the challenge (catches replay-across-fields)", () => {
    const base = {
      ctid: "tip://c/OH-aabbccddeeff11-1234",
      idx: 0,
      timestamp: 1780500000000,
      requester_tip_id: "tip://id/US-cccccccccccccccc",
    };
    const variants = [
      { ...base, ctid: "tip://c/OH-aabbccddeeff11-9999" },
      { ...base, idx: 1 },
      { ...base, timestamp: 1780500000001 },
      { ...base, requester_tip_id: "tip://id/US-dddddddddddddddd" },
    ];
    const baseHash = schema.buildChallenge(base);
    for (const v of variants) {
      expect(schema.buildChallenge(v)).not.toBe(baseHash);
    }
  });
});
