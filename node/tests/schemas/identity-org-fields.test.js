/**
 * @file node/tests/schemas/identity-org-fields.test.js
 * @description org_type on REGISTER_IDENTITY: organization-only, and absent
 * on identities that omit it so existing signatures keep verifying.
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
// schemaError throws a plain { status, error, code } object, not an Error, so
// jest's .toThrow(regex) cannot see a message. Assert on the code instead.
function expectCode(fn, code) {
  try { fn(); } catch (e) { expect(e.code).toBe(code); return; }
  throw new Error(`expected a throw with code ${code}, but nothing was thrown`);
}

beforeAll(async () => { await initCrypto(); });

describe("REGISTER_IDENTITY org_type", () => {
  test("omitting org_type leaves the signed bytes unchanged", () => {
    // Optional, so an identity without it must hash exactly as it did before
    // the field existed: the key must be absent, not emitted as null.
    const payload = schema.buildSigningPayload(baseInput(ORG));
    expect(payload.org_type).toBeUndefined();
    expect(Object.keys(payload)).not.toContain("org_type");
  });

  test("org_type enters the signed bytes when present", () => {
    const without = schema.buildSigningPayload(baseInput(ORG));
    const withType = schema.buildSigningPayload(baseInput({ ...ORG, org_type: "private-limited-company" }));
    expect(withType.org_type).toBe("private-limited-company");
    expect(shake256(canonicalJson(withType))).not.toBe(shake256(canonicalJson(without)));
  });




  test("org fields on a person are rejected", () => {
    expectCode(() => schema.buildSigningPayload(
      baseInput({ tip_id_type: TIP_ID_TYPES.PERSONAL, org_type: "llc" }),
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
