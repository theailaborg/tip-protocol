/**
 * @file tests/schemas/register-domain.test.js
 * @description Pure-function tests for the user-signed domain claim schema.
 *
 *   - exact 4-field canonical shape, reject-on-extra
 *   - domain normalisation (lowercase, trailing-dot strip, invalid hostname reject)
 *   - method enum gate
 *   - sign/verify round-trip with our own keypair
 *   - resolveClaimant: org-only gate + DAG presence + revocation
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { TIP_ID_TYPES, DOMAIN_VERIFICATION_METHODS } = require(path.join(SHARED, "constants"));
const schema = require(path.join(SRC, "schemas", "register-domain"));

beforeAll(async () => { await initCrypto(); });

// ─── In-memory DAG stub ─────────────────────────────────────────────────────
// Only the methods the schema actually calls. Keeps tests isolated from the
// real DAG bootstrap (which writes genesis state).
function makeFakeDag(identities = {}, revoked = new Set()) {
  return {
    getIdentity: (id) => identities[id] || null,
    isRevoked: (id) => revoked.has(id),
  };
}

const ORG_TIP = "tip://id/US-aaaaaaaaaaaaaaaa";
const PERSONAL_TIP = "tip://id/US-bbbbbbbbbbbbbbbb";

// ─── Module surface ─────────────────────────────────────────────────────────

describe("module surface", () => {
  test("exports the expected helpers", () => {
    expect(typeof schema.buildSigningPayload).toBe("function");
    expect(typeof schema.sign).toBe("function");
    expect(typeof schema.verifySignature).toBe("function");
    expect(typeof schema.validateRequest).toBe("function");
    expect(typeof schema.resolveClaimant).toBe("function");
    expect(typeof schema.normalizeDomain).toBe("function");
  });
});

// ─── normalizeDomain ────────────────────────────────────────────────────────

describe("normalizeDomain", () => {
  test("lowercases", () => {
    expect(schema.normalizeDomain("Example.COM")).toBe("example.com");
  });

  test("strips trailing dot (DNS-style FQDN)", () => {
    expect(schema.normalizeDomain("example.com.")).toBe("example.com");
  });

  test("rejects empty", () => {
    expect(() => schema.normalizeDomain(""))
      .toThrow(expect.objectContaining({ status: 400, code: "domain_required" }));
  });

  test("rejects non-string", () => {
    expect(() => schema.normalizeDomain(null))
      .toThrow(expect.objectContaining({ status: 400, code: "domain_required" }));
  });

  test("rejects malformed hostnames", () => {
    for (const bad of ["no-dot", "..double", "-leading-hyphen.com", "trailing-.com", "a..b.com"]) {
      expect(() => schema.normalizeDomain(bad))
        .toThrow(expect.objectContaining({ status: 400, code: "domain_invalid" }));
    }
  });

  test("accepts multi-label, hyphenated, IDN xn-- prefixes", () => {
    expect(schema.normalizeDomain("sub.acmenews.com")).toBe("sub.acmenews.com");
    expect(schema.normalizeDomain("xn--80aaxitdbjk.xn--p1ai")).toBe("xn--80aaxitdbjk.xn--p1ai");
  });
});

// ─── Dev-mode localhost gating ──────────────────────────────────────────────
// Production safety: localhost / 127.0.0.1 are accepted ONLY when BOTH
// NODE_ENV != "production" AND TIP_DEV_ALLOW_LOCALHOST_DOMAINS=1.

describe("normalizeDomain — dev-mode localhost", () => {
  const ORIGINAL_ENV = process.env.NODE_ENV;
  const ORIGINAL_FLAG = process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS;

  afterEach(() => {
    if (ORIGINAL_ENV === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = ORIGINAL_ENV;
    if (ORIGINAL_FLAG === undefined) delete process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS;
    else process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = ORIGINAL_FLAG;
  });

  test("localhost rejected by default (no flag)", () => {
    delete process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS;
    process.env.NODE_ENV = "development";
    expect(() => schema.normalizeDomain("localhost"))
      .toThrow(expect.objectContaining({ status: 400, code: "domain_invalid" }));
  });

  test("flag set + NODE_ENV != production accepts localhost", () => {
    process.env.NODE_ENV = "development";
    process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = "1";
    expect(schema.normalizeDomain("localhost")).toBe("localhost");
    expect(schema.normalizeDomain("localhost:4000")).toBe("localhost:4000");
    expect(schema.normalizeDomain("127.0.0.1")).toBe("127.0.0.1");
    expect(schema.normalizeDomain("127.0.0.1:8080")).toBe("127.0.0.1:8080");
  });

  test("flag set in production is IGNORED (defense-in-depth)", () => {
    process.env.NODE_ENV = "production";
    process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = "1";
    expect(() => schema.normalizeDomain("localhost"))
      .toThrow(expect.objectContaining({ status: 400, code: "domain_invalid" }));
  });

  test("normal domains still pass when flag is set", () => {
    process.env.NODE_ENV = "development";
    process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = "1";
    expect(schema.normalizeDomain("acmenews.com")).toBe("acmenews.com");
  });
});

// ─── buildSigningPayload — exact 4-field shape ──────────────────────────────

describe("buildSigningPayload — exact 4-field canonical shape", () => {
  const minimal = (overrides = {}) => schema.buildSigningPayload({
    claimed_at: 1778580000000,
    domain: "example.com",
    method: DOMAIN_VERIFICATION_METHODS.AUTO,
    tip_id: ORG_TIP,
    ...overrides,
  });

  test("emits exactly the 4 spec fields, alphabetical", () => {
    const p = minimal();
    expect(Object.keys(p)).toEqual(["claimed_at", "domain", "method", "tip_id"]);
  });

  test("reject-on-extra — junk fields don't end up in canonical payload", () => {
    const p = minimal({ malicious_field: "stripped" });
    expect(p.malicious_field).toBeUndefined();
    expect(Object.keys(p).sort()).toEqual(["claimed_at", "domain", "method", "tip_id"]);
  });

  test("method defaults to 'auto' when null", () => {
    const p = schema.buildSigningPayload({
      claimed_at: 1778580000000,
      domain: "example.com",
      method: null,
      tip_id: ORG_TIP,
    });
    expect(p.method).toBe("auto");
  });

  test("method outside enum rejected", () => {
    expect(() => minimal({ method: "ftp" }))
      .toThrow(expect.objectContaining({ status: 400, code: "method_invalid" }));
  });

  test("missing tip_id rejected", () => {
    expect(() => schema.buildSigningPayload({
      claimed_at: 1778580000000,
      domain: "example.com",
      method: "auto",
    })).toThrow(expect.objectContaining({ status: 400, code: "tip_id_required" }));
  });

  test("non-tip://id/ tip_id rejected", () => {
    expect(() => minimal({ tip_id: "tip://vp/US-aaaa" }))
      .toThrow(expect.objectContaining({ status: 400, code: "tip_id_required" }));
  });

  test("invalid claimed_at rejected", () => {
    expect(() => minimal({ claimed_at: "not-a-date" }))
      .toThrow(expect.objectContaining({ status: 400, code: "claimed_at_invalid" }));
  });

  test("domain normalised inside builder (mixed-case input)", () => {
    const p = minimal({ domain: "Example.COM" });
    expect(p.domain).toBe("example.com");
  });
});

// ─── sign / verify round-trip ───────────────────────────────────────────────

describe("sign / verify round-trip", () => {
  test("a correctly-signed payload verifies", () => {
    const kp = generateMLDSAKeypair();
    const payload = schema.buildSigningPayload({
      claimed_at: 1778580000000,
      domain: "example.com",
      method: "auto",
      tip_id: ORG_TIP,
    });
    const sig = schema.sign(payload, kp.privateKey);
    expect(schema.verifySignature(payload, sig, kp.publicKey)).toBe(true);
  });

  test("tampered field breaks verification", () => {
    const kp = generateMLDSAKeypair();
    const payload = schema.buildSigningPayload({
      claimed_at: 1778580000000,
      domain: "example.com",
      method: "auto",
      tip_id: ORG_TIP,
    });
    const sig = schema.sign(payload, kp.privateKey);
    const tampered = { ...payload, domain: "evil.com" };
    expect(schema.verifySignature(tampered, sig.hex, kp.publicKey)).toBe(false);
  });

  test("foreign key cannot validate", () => {
    const a = generateMLDSAKeypair();
    const b = generateMLDSAKeypair();
    const payload = schema.buildSigningPayload({
      claimed_at: 1778580000000,
      domain: "example.com",
      method: "auto",
      tip_id: ORG_TIP,
    });
    const sig = schema.sign(payload, a.privateKey);
    expect(schema.verifySignature(payload, sig, b.publicKey)).toBe(false);
  });
});

// ─── resolveClaimant — org-only gate + DAG presence ─────────────────────────

describe("resolveClaimant", () => {
  test("missing on DAG → 412 signer_not_registered", () => {
    const dag = makeFakeDag({});
    expect(() => schema.resolveClaimant(ORG_TIP, dag))
      .toThrow(expect.objectContaining({ status: 412, code: "signer_not_registered" }));
  });

  test("revoked → 403 signer_revoked", () => {
    const dag = makeFakeDag(
      { [ORG_TIP]: { public_key: "ff", tip_id_type: TIP_ID_TYPES.ORGANIZATION } },
      new Set([ORG_TIP]),
    );
    expect(() => schema.resolveClaimant(ORG_TIP, dag))
      .toThrow(expect.objectContaining({ status: 403, code: "signer_revoked" }));
  });

  test("personal → 403 tip_id_not_authorised", () => {
    const dag = makeFakeDag({
      [PERSONAL_TIP]: { public_key: "ff", tip_id_type: TIP_ID_TYPES.PERSONAL },
    });
    expect(() => schema.resolveClaimant(PERSONAL_TIP, dag))
      .toThrow(expect.objectContaining({ status: 403, code: "tip_id_not_authorised" }));
  });

  test("organization → returns identity", () => {
    const dag = makeFakeDag({
      [ORG_TIP]: { public_key: "ff", tip_id_type: TIP_ID_TYPES.ORGANIZATION },
    });
    const identity = schema.resolveClaimant(ORG_TIP, dag);
    expect(identity.public_key).toBe("ff");
  });

  test("identity row without tip_id_type defaults to personal → rejected", () => {
    const dag = makeFakeDag({
      [ORG_TIP]: { public_key: "ff" }, // missing tip_id_type
    });
    expect(() => schema.resolveClaimant(ORG_TIP, dag))
      .toThrow(expect.objectContaining({ status: 403, code: "tip_id_not_authorised" }));
  });
});

// ─── validateRequest — envelope gate ────────────────────────────────────────

describe("validateRequest", () => {
  const orgDag = makeFakeDag({
    [ORG_TIP]: { public_key: "ff", tip_id_type: TIP_ID_TYPES.ORGANIZATION },
  });

  const goodBody = () => ({
    tip_id: ORG_TIP,
    domain: "Example.COM",
    method: "auto",
    claimed_at: 1778580000000,
    signature: "00".repeat(8),
  });

  test("happy path returns normalised pieces", () => {
    const out = schema.validateRequest(goodBody(), { dag: orgDag });
    expect(out.identity.public_key).toBe("ff");
    expect(out.domain).toBe("example.com");
    expect(out.method).toBe("auto");
  });

  test("missing body → body_invalid", () => {
    expect(() => schema.validateRequest(null, { dag: orgDag }))
      .toThrow(expect.objectContaining({ status: 400, code: "body_invalid" }));
  });

  test("missing signature → signature_required", () => {
    const body = goodBody();
    delete body.signature;
    expect(() => schema.validateRequest(body, { dag: orgDag }))
      .toThrow(expect.objectContaining({ status: 400, code: "signature_required" }));
  });

  test("personal tip_id is rejected by the org gate inside resolveClaimant", () => {
    const dag = makeFakeDag({
      [PERSONAL_TIP]: { public_key: "ff", tip_id_type: TIP_ID_TYPES.PERSONAL },
    });
    expect(() => schema.validateRequest({ ...goodBody(), tip_id: PERSONAL_TIP }, { dag }))
      .toThrow(expect.objectContaining({ status: 403, code: "tip_id_not_authorised" }));
  });
});
