/**
 * @file tests/schemas/interest-registered.test.js
 * @description Unit tests for the INTEREST_REGISTERED schema (VP-attested
 * registry entry that extends the interest taxonomy at runtime).
 *
 * Covers:
 *   - Canonical 4-field signed payload (alphabetical)
 *   - Slug regex enforcement (3–40 chars, lowercase + digits + hyphens)
 *   - Label length cap (≤ 80 chars)
 *   - Category enum (closed set)
 *   - validateRequest: missing/invalid fields, VP not registered, VP
 *     inactive, slug already registered
 *   - verifyTx happy path + every state-level rejection code
 *   - sign / verify round-trip
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const schema = require(path.join(SRC, "schemas", "interest-registered"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/US-vp-aaaaaaaaaaaa";

function makeFakeDag({ vps = {}, interests = {} } = {}) {
  return {
    getVP: (id) => vps[id] || null,
    getInterest: (slug) => interests[slug] || null,
    getActiveKey: (et, id) => {
      const map = et === "vp" ? vps : null;
      const rec = map && map[id];
      return rec ? { public_key: rec.public_key, algorithm: "ml-dsa-65" } : null;
    },
    getKeyValidAt: function (et, id, _ts) { return this.getActiveKey(et, id); },
  };
}

const _baseInput = (overrides = {}) => ({
  slug: "new-interest",
  label: "New Interest",
  category: "tech",
  approving_vp_id: VP_ID,
  ...overrides,
});

// ─── buildSigningPayload ───────────────────────────────────────────────────

describe("buildSigningPayload — 4-field canonical shape", () => {
  test("emits the 4 spec fields, alphabetical", () => {
    expect(Object.keys(schema.buildSigningPayload(_baseInput())).sort())
      .toEqual(["approving_vp_id", "category", "label", "slug"]);
  });

  test("reject-on-extra — junk fields stripped", () => {
    const p = schema.buildSigningPayload({ ..._baseInput(), malicious: "stripped" });
    expect(p.malicious).toBeUndefined();
  });

  test("slug outside the regex rejected", () => {
    for (const bad of ["AI-ML", " ai", "ai!", "a", "1ai", "ai-", "-ai", "ai_ml"]) {
      expect(() => schema.buildSigningPayload(_baseInput({ slug: bad })))
        .toThrow(expect.objectContaining({ status: 400, code: "slug_invalid" }));
    }
  });

  test("label > 80 chars rejected", () => {
    expect(() => schema.buildSigningPayload(_baseInput({ label: "A".repeat(81) })))
      .toThrow(expect.objectContaining({ status: 400, code: "label_too_long" }));
  });

  test("empty label rejected", () => {
    expect(() => schema.buildSigningPayload(_baseInput({ label: "" })))
      .toThrow(expect.objectContaining({ status: 400, code: "label_required" }));
  });

  test("category outside the enum rejected", () => {
    expect(() => schema.buildSigningPayload(_baseInput({ category: "made-up" })))
      .toThrow(expect.objectContaining({ status: 400, code: "category_invalid" }));
  });
});

// ─── sign / verify round-trip ──────────────────────────────────────────────

describe("sign / verify round-trip", () => {
  test("correctly-signed payload verifies", () => {
    const kp = generateMLDSAKeypair();
    const payload = schema.buildSigningPayload(_baseInput());
    const sig = schema.sign(payload, kp.privateKey);
    expect(schema.verifySignature(payload, sig, kp.publicKey)).toBe(true);
  });

  test("any field flipped breaks the signature", () => {
    const kp = generateMLDSAKeypair();
    const payload = schema.buildSigningPayload(_baseInput());
    const sig = schema.sign(payload, kp.privateKey);
    for (const field of Object.keys(payload)) {
      const tampered = { ...payload, [field]: `x${payload[field]}` };
      expect(schema.verifySignature(tampered, sig, kp.publicKey)).toBe(false);
    }
  });
});

// ─── verifyTx ──────────────────────────────────────────────────────────────

describe("verifyTx", () => {
  function _setup({ vpStatus = "active", existingSlug = false } = {}) {
    const kp = generateMLDSAKeypair();
    const vps = { [VP_ID]: { vp_id: VP_ID, public_key: kp.publicKey, status: vpStatus } };
    const interests = existingSlug ? { "new-interest": { slug: "new-interest" } } : {};
    return { kp, dag: makeFakeDag({ vps, interests }) };
  }

  test("happy path returns { ok: true }", () => {
    const { dag } = _setup();
    expect(schema.verifyTx({ data: _baseInput() }, dag)).toEqual({ ok: true });
  });

  test("slug invalid → 400 slug_invalid", () => {
    const { dag } = _setup();
    expect(schema.verifyTx({ data: _baseInput({ slug: "BAD" }) }, dag))
      .toMatchObject({ ok: false, status: 400, code: "slug_invalid" });
  });

  test("label invalid → 400 label_invalid", () => {
    const { dag } = _setup();
    expect(schema.verifyTx({ data: _baseInput({ label: "" }) }, dag))
      .toMatchObject({ ok: false, status: 400, code: "label_invalid" });
  });

  test("category invalid → 400 category_invalid", () => {
    const { dag } = _setup();
    expect(schema.verifyTx({ data: _baseInput({ category: "unknown" }) }, dag))
      .toMatchObject({ ok: false, status: 400, code: "category_invalid" });
  });

  test("VP not registered → 412 vp_not_registered", () => {
    const dag = makeFakeDag({ vps: {} });
    expect(schema.verifyTx({ data: _baseInput() }, dag))
      .toMatchObject({ ok: false, status: 412, code: "vp_not_registered" });
  });

  test("VP not active → 403 vp_inactive", () => {
    const { dag } = _setup({ vpStatus: "suspended" });
    expect(schema.verifyTx({ data: _baseInput() }, dag))
      .toMatchObject({ ok: false, status: 403, code: "vp_inactive" });
  });

  test("slug already registered → 409 slug_already_registered", () => {
    const { dag } = _setup({ existingSlug: true });
    expect(schema.verifyTx({ data: _baseInput() }, dag))
      .toMatchObject({ ok: false, status: 409, code: "slug_already_registered" });
  });
});

// ─── validateRequest (API ingress) ─────────────────────────────────────────

describe("validateRequest", () => {
  function _setup({ vpStatus = "active" } = {}) {
    const kp = generateMLDSAKeypair();
    const vps = { [VP_ID]: { vp_id: VP_ID, public_key: kp.publicKey, status: vpStatus } };
    return { kp, dag: makeFakeDag({ vps }) };
  }

  test("happy path — no throw", () => {
    const { dag } = _setup();
    const body = { ..._baseInput(), signature: "abcdef" };
    expect(() => schema.validateRequest(body, { dag })).not.toThrow();
  });

  test("missing signature → signature_required", () => {
    const { dag } = _setup();
    const body = { ..._baseInput() };  // no signature
    expect(() => schema.validateRequest(body, { dag }))
      .toThrow(expect.objectContaining({ status: 400, code: "signature_required" }));
  });

  test("malformed approving_vp_id → approving_vp_id_required", () => {
    const { dag } = _setup();
    const body = { ..._baseInput({ approving_vp_id: "not-a-vp" }), signature: "ab" };
    expect(() => schema.validateRequest(body, { dag }))
      .toThrow(expect.objectContaining({ status: 400, code: "approving_vp_id_required" }));
  });
});
