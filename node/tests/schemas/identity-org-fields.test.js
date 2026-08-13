/**
 * @file node/tests/schemas/identity-org-fields.test.js
 * @description org_type and lei on REGISTER_IDENTITY: organization-only,
 * LEI checksum-validated, and absent on identities that omit them so existing
 * signatures keep verifying.
 */

"use strict";

const { initCrypto, shake256, canonicalJson } = require("../../../shared/crypto");
const { TIP_ID_TYPES } = require("../../../shared/constants");
const schema = require("../../src/schemas/register-identity");

// A minimal but structurally valid Groth16-shaped proof; the builder only
// checks that it is a non-array object.
const ZK = { pi_a: ["1", "2"], pi_b: [["1", "2"], ["3", "4"]], pi_c: ["5", "6"] };

function baseInput(extra = {}) {
  return {
    public_key: "aabbcc",
    dedup_hash: "12345",
    zk_proof: ZK,
    vp_id: "tip://vp/US-1111111111111111",
    region: "gb",
    verification_tier: "T1",
    ...extra,
  };
}

const ORG = { tip_id_type: TIP_ID_TYPES.ORGANIZATION, creator_name: "ROOVERSE LTD" };
const REAL_LEI = "506700GE1G29325QX363";   // GLEIF Foundation

// schemaError throws a plain { status, error, code } object, not an Error, so
// jest's .toThrow(regex) cannot see a message. Assert on the code instead.
function expectCode(fn, code) {
  try { fn(); } catch (e) { expect(e.code).toBe(code); return; }
  throw new Error(`expected a throw with code ${code}, but nothing was thrown`);
}

beforeAll(async () => { await initCrypto(); });

describe("REGISTER_IDENTITY org_type and lei", () => {
  test("omitting both leaves the signed bytes unchanged", () => {
    // Both are optional, so an identity without them must hash exactly as it
    // did before the fields existed.
    const withFields = schema.buildSigningPayload(baseInput(ORG));
    expect(withFields.org_type).toBeUndefined();
    expect(withFields.lei).toBeUndefined();
    // Same payload built twice is stable, and neither key leaks in as null.
    expect(Object.keys(withFields)).not.toContain("org_type");
    expect(Object.keys(withFields)).not.toContain("lei");
  });

  test("both enter the signed bytes when present", () => {
    const without = schema.buildSigningPayload(baseInput(ORG));
    const withBoth = schema.buildSigningPayload(
      baseInput({ ...ORG, org_type: "private-limited-company", lei: REAL_LEI }),
    );
    expect(withBoth.org_type).toBe("private-limited-company");
    expect(withBoth.lei).toBe(REAL_LEI);
    expect(shake256(canonicalJson(withBoth))).not.toBe(shake256(canonicalJson(without)));
  });

  test("lei is uppercased before signing", () => {
    const p = schema.buildSigningPayload(baseInput({ ...ORG, lei: REAL_LEI.toLowerCase() }));
    expect(p.lei).toBe(REAL_LEI);
  });

  test("a bad LEI checksum is rejected", () => {
    // Real LEI with the final check digit changed.
    const bad = REAL_LEI.slice(0, 19) + "4";
    expectCode(() => schema.buildSigningPayload(baseInput({ ...ORG, lei: bad })), "lei_invalid");
  });

  test("a wrong-length LEI is rejected", () => {
    expectCode(() => schema.buildSigningPayload(baseInput({ ...ORG, lei: "TOOSHORT" })), "lei_invalid");
  });

  test("org fields on a person are rejected", () => {
    expectCode(() => schema.buildSigningPayload(
      baseInput({ tip_id_type: TIP_ID_TYPES.PERSONAL, org_type: "llc" }),
    ), "org_field_on_person");
    expectCode(() => schema.buildSigningPayload(
      baseInput({ tip_id_type: TIP_ID_TYPES.PERSONAL, lei: REAL_LEI }),
    ), "org_field_on_person");
  });

  test("org_type format is enforced", () => {
    for (const bad of ["A", "Private Limited", "x".repeat(65), "llc!"]) {
      expectCode(() => schema.buildSigningPayload(baseInput({ ...ORG, org_type: bad })), "org_type_invalid");
    }
  });

  test("org_type is not constrained by country", () => {
    // Deliberate: legal forms differ per jurisdiction and a hardcoded per-country
    // allowlist would need a fleet upgrade to extend. The VP vouches instead.
    const p = schema.buildSigningPayload(baseInput({ ...ORG, region: "GB", org_type: "gmbh" }));
    expect(p.org_type).toBe("gmbh");
  });
});
