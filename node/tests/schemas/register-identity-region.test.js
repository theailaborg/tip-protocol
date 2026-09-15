/**
 * @file tests/schemas/register-identity-region.test.js
 * @description New registrations must carry an ISO 3166-1 alpha-2 region; the
 * signing path still accepts any 2-8 char value so committed history verifies.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */
"use strict";

const path = require("path");
const registerIdentity = require(path.resolve(__dirname, "../../src/schemas/register-identity"));
const { ISO_3166_ALPHA2 } = require(path.resolve(__dirname, "../../../shared/constants"));

const DEPS = { dag: { getVP: () => null } };
const BASE = { public_key: "00", dedup_hash: "00", zk_proof: {}, vp_id: "tip://vp/US-1", vp_signature: "x" };

function _codeFor(region) {
  try {
    registerIdentity.validateRequest({ ...BASE, region }, DEPS);
    return null;
  } catch (err) {
    return err.code;
  }
}

describe("REGISTER_IDENTITY region", () => {
  test("the country set is the 249 assigned alpha-2 codes plus XK", () => {
    expect(ISO_3166_ALPHA2.size).toBe(250);
    for (const code of ISO_3166_ALPHA2) expect(code).toMatch(/^[A-Z]{2}$/);
  });

  // Drift guard against CLDR (the region data shipped with Node's ICU). Every
  // code we accept must be a real region, and any region CLDR knows that we do
  // not accept must be a known non-country; a new country fails here for review.
  test("the country set agrees with CLDR region data", () => {
    const NON_COUNTRIES = new Set(("AC AN BU CP CQ CS DD DG DY EA EU EZ FX HV IC NH QO RH SU " +
      "TA TP UK UN VD XA XB YD YU ZR ZZ").split(" "));
    const names = new Intl.DisplayNames(["en"], { type: "region", fallback: "none" });
    const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const known = [];
    for (const a of letters) for (const b of letters) {
      const code = a + b;
      const name = names.of(code);
      if (name && name !== code) known.push(code);
    }
    expect([...ISO_3166_ALPHA2].filter(c => !known.includes(c))).toEqual([]);
    expect(known.filter(c => !ISO_3166_ALPHA2.has(c) && !NON_COUNTRIES.has(c))).toEqual([]);
  });

  test.each(["IN", "GB", "US", "XK", "in", "gb"])("accepts %s at the API gate", (region) => {
    expect(_codeFor(region)).not.toBe("region_invalid");
  });

  test.each(["IND", "USA", "GBR", "ZZ", "UK", "EU"])("rejects %s at the API gate", (region) => {
    expect(_codeFor(region)).toBe("region_invalid");
  });

  test("absent region is left to the service default", () => {
    expect(_codeFor(undefined)).not.toBe("region_invalid");
  });

  test("the signing path still accepts a committed 3-letter region", () => {
    const payload = registerIdentity.buildSigningPayload({
      ...BASE, region: "IND", tip_id_type: "personal", verification_tier: "T3",
      algorithm: "ml-dsa-65",
    });
    expect(payload.region).toBe("IND");
  });
});
