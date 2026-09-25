/**
 * @file tests/org-id-schemes.test.js
 * @description Company registration identifiers are canonicalised one way only.
 *
 * The validator and the ZK encoder used to keep separate normalisers that
 * disagreed on hyphens, so a US EIN written the way the IRS prints it was
 * refused while hashing identically to its bare form. These tests pin the
 * shared rule and the length bound that stops two companies truncating into
 * one identity.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../shared");
const { resolveIdScheme } = require(path.join(SHARED, "org-id-schemes"));
const { canonicalizeGovId, GOV_ID_MAX_CHARS } = require(path.join(SHARED, "gov-id"));

// ═══════════════════════════════════════════════════════════════════════════
describe("resolveIdScheme , punctuation is presentation, not identity", () => {
  // The IRS prints an EIN as XX-XXXXXXX. Partners paste it that way.
  test.each([
    ["32-0727201", "IRS printed form"],
    ["320727201", "bare digits"],
    ["32 0727201", "space separated"],
    ["32.0727201", "dot separated"],
    ["  32-0727201  ", "surrounding whitespace"],
  ])("US EIN accepted as %s (%s)", (input) => {
    const r = resolveIdScheme("US", input);
    expect(r.name).toBe("EIN (federal)");
    expect(r.normalized).toBe("320727201");
  });

  test("every printed EIN form collapses to one canonical value", () => {
    const forms = ["32-0727201", "320727201", "32 0727201", "32.0727201"];
    const canon = new Set(forms.map(f => resolveIdScheme("US", f).normalized));
    expect(canon.size).toBe(1);
  });

  // These two schemes use hyphens structurally, so they must survive the strip.
  test("US state fallback accepted with and without its hyphens", () => {
    for (const v of ["US-VA-1234567", "USVA1234567"]) {
      const r = resolveIdScheme("US", v);
      expect(r.name).toBe("namespaced state number");
      expect(r.normalized).toBe("USVA1234567");
    }
  });

  test("German court-qualified number accepted with and without its hyphens", () => {
    for (const v of ["DE-HRB-12345-MUC", "DEHRB12345MUC"]) {
      const r = resolveIdScheme("DE", v);
      expect(r.name).toBe("court-qualified HRB/HRA");
      expect(r.normalized).toBe("DEHRB12345MUC");
    }
  });

  test("a state number never matches the EIN rule, and vice versa", () => {
    expect(resolveIdScheme("US", "US-VA-1234567").key).toBe("state");
    expect(resolveIdScheme("US", "320727201").key).toBe("company");
  });

  test("Indian CIN accepted, spacing ignored", () => {
    const spaced = resolveIdScheme("IN", "U72900 MH2021 PTC362851");
    const bare = resolveIdScheme("IN", "U72900MH2021PTC362851");
    expect(spaced.name).toBe("CIN");
    expect(spaced.normalized).toBe(bare.normalized);
  });

  test("LLPIN resolves to its own scheme, not CIN", () => {
    expect(resolveIdScheme("IN", "AAB-1234").name).toBe("LLPIN");
  });

  // A dropped leading zero is a different company, so the strip must not touch
  // digits , only separators.
  test("UK leading zeros survive canonicalisation", () => {
    expect(resolveIdScheme("GB", "01234567").normalized).toBe("01234567");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe("resolveIdScheme , refusals", () => {
  test("a country with no scheme stops the run", () => {
    expect(() => resolveIdScheme("BR", "123456789")).toThrow(/no registration-number scheme/);
  });

  test("a wrong shape is refused with what the jurisdiction expects", () => {
    expect(() => resolveIdScheme("GB", "123")).toThrow(/not a valid registration number for GB/);
  });

  test("an EIN of the wrong length is refused, not silently padded", () => {
    expect(() => resolveIdScheme("US", "3207272")).toThrow(/not a valid registration number/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// encodeGovId truncates at GOV_ID_MAX_CHARS. Left unguarded, two companies
// agreeing on that many characters mint ONE permanent identity between them.
describe("resolveIdScheme , truncation guard", () => {
  const overLong = "US-CA-" + "1".repeat(26) + "-AAAA";   // 34 chars canonical

  test("an over-length identifier is refused rather than truncated", () => {
    expect(canonicalizeGovId(overLong).length).toBeGreaterThan(GOV_ID_MAX_CHARS);
    expect(() => resolveIdScheme("US", overLong)).toThrow(/maximum 30/);
  });

  test("the refusal names the collision, so the operator knows why", () => {
    expect(() => resolveIdScheme("US", overLong)).toThrow(/single permanent identity/);
  });

  test("two identifiers that would have collided are both refused", () => {
    const a = "US-CA-" + "1".repeat(26) + "-AAAA";
    const b = "US-CA-" + "1".repeat(26) + "-BBBB";
    // Same first 30 characters: this is the collision the guard exists to stop.
    expect(canonicalizeGovId(a).slice(0, GOV_ID_MAX_CHARS))
      .toBe(canonicalizeGovId(b).slice(0, GOV_ID_MAX_CHARS));
    expect(() => resolveIdScheme("US", a)).toThrow();
    expect(() => resolveIdScheme("US", b)).toThrow();
  });

  test("a value exactly at the bound is still accepted", () => {
    const atBound = "US" + "CA" + "1".repeat(GOV_ID_MAX_CHARS - 4);
    expect(canonicalizeGovId(atBound).length).toBe(GOV_ID_MAX_CHARS);
    expect(resolveIdScheme("US", atBound).key).toBe("state");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// The original defect was two normalisers drifting apart. This is the test
// that fails if anyone reintroduces a second one.
describe("the validator and the ZK encoder agree", () => {
  const { encodeGovId } = require(path.join(SHARED, "zk"));

  test.each([
    ["US", "32-0727201"],
    ["US", "320727201"],
    ["US", "US-VA-1234567"],
    ["DE", "DE-HRB-12345-MUC"],
    ["IN", "U72900MH2021PTC362851"],
    ["GB", "01234567"],
  ])("%s %s hashes the canonical value the validator returned", (country, input) => {
    const { normalized } = resolveIdScheme(country, input);
    expect(encodeGovId(input)).toBe(encodeGovId(normalized));
  });

  test("hyphenated and bare EIN encode identically", () => {
    expect(encodeGovId("32-0727201")).toBe(encodeGovId("320727201"));
  });

  test("resolveIdScheme returns exactly canonicalizeGovId's output", () => {
    for (const [c, v] of [["US", "32-0727201"], ["IN", "U72900MH2021PTC362851"]]) {
      expect(resolveIdScheme(c, v).normalized).toBe(canonicalizeGovId(v));
    }
  });
});
