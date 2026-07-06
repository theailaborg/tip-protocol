/**
 * @file tests/shared/canonical-json.test.js
 * @description The canonicalJson contract, made explicit and enforced:
 * (1) deterministic , same value, same bytes, key order irrelevant;
 * (2) PORTABLE , the output is always valid JSON, parseable and
 * reproducible in any language. Property (2) was implicit for months and
 * violated by the String(undefined) branch; these tests make the class
 * unwritable.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { canonicalJson } = require(path.resolve(__dirname, "../../../shared/crypto"));

// deterministic PRNG for reproducible fuzz
function lcg(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}

function randomValue(rnd, depth = 0, allowUndefined = false) {
  const r = rnd();
  if (allowUndefined && (depth > 3 || r < 0.15)) return undefined;
  if (depth > 3) return null;
  if (r < 0.3) return null;
  if (r < 0.45) return Math.floor(rnd() * 1e6);
  if (r < 0.6) return `s-${Math.floor(rnd() * 1e4)}`;
  if (r < 0.7) return rnd() < 0.5;
  if (r < 0.85) return Array.from({ length: Math.floor(rnd() * 4) }, () => randomValue(rnd, depth + 1, false));
  const o = {};
  // undefined may appear ONLY as an object value (the omit case)
  for (let i = Math.floor(rnd() * 4); i > 0; i--) o[`k${Math.floor(rnd() * 10)}`] = randomValue(rnd, depth + 1, true);
  return o;
}

describe("canonicalJson , determinism (the old contract, unchanged)", () => {
  test("key insertion order never changes the bytes", () => {
    expect(canonicalJson({ b: 2, a: 1, c: [3, { z: 1, y: 2 }] }))
      .toBe(canonicalJson({ c: [3, { y: 2, z: 1 }], a: 1, b: 2 }));
  });

  test("real-payload shapes are byte-identical to v1 (no undefined = no change)", () => {
    // v1 output for this shape, computed before the change , pins that the
    // fix alters ZERO bytes for payloads following the x||null convention.
    expect(canonicalJson({ a: 1, b: null, c: "x", d: [1, null, "y"] }))
      .toBe('{"a":1,"b":null,"c":"x","d":[1,null,"y"]}');
  });
});

describe("canonicalJson , portability (the contract that was implicit)", () => {
  test("undefined object values are omitted", () => {
    expect(canonicalJson({ a: 1, gone: undefined })).toBe('{"a":1}');
  });

  test("undefined in an array is a caller bug: throws, never coerces", () => {
    expect(() => canonicalJson([1, undefined, 2])).toThrow(/undefined/);
  });

  test("bare undefined is a caller bug: throws; null is data", () => {
    expect(() => canonicalJson(undefined)).toThrow(/undefined/);
    expect(canonicalJson(null)).toBe("null");
  });

  test("omission vs null stay distinguishable", () => {
    expect(canonicalJson({ a: null })).not.toBe(canonicalJson({}));
    expect(canonicalJson({ a: undefined })).toBe(canonicalJson({}));
  });

  test("PROPERTY: output always parses as JSON and matches JSON.stringify semantics (500 fuzz cases)", () => {
    const rnd = lcg(2026);
    for (let i = 0; i < 500; i++) {
      const v = randomValue(rnd, 0, false);
      const out = canonicalJson(v);
      expect(() => JSON.parse(out)).not.toThrow();
      expect(JSON.parse(out)).toEqual(JSON.parse(JSON.stringify(v)));
    }
  });
});
