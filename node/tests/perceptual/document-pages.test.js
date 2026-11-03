/**
 * @file tests/perceptual/document-pages.test.js
 * @description Pages a cf-doc-1 item counts as for the plan page limits. The
 * vectors file is a byte-identical copy of the VP's
 * (tests/fixtures/doc-pages-vectors.json there), so the node and the VP's
 * browser copy of the rule cannot drift apart.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { documentPages, maxDocumentPages } = require(path.resolve(__dirname, "../../src/perceptual/document-pages"));
const { DOCUMENT_PAGES } = require(path.resolve(__dirname, "../../../shared/constants"));

const VECTORS = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../fixtures/doc-pages-vectors.json"), "utf8"));

describe("documentPages (shared vectors)", () => {
  test("the vectors use the node's characters per page", () => {
    expect(VECTORS.chars_per_page).toBe(DOCUMENT_PAGES.CHARS_PER_PAGE);
    expect(VECTORS.cases.length).toBeGreaterThan(0);
  });

  test.each(VECTORS.cases.map((c) => [c.name, c]))("%s", (_name, c) => {
    expect(documentPages(c.item, VECTORS.chars_per_page)).toBe(c.pages);
    expect(documentPages(c.item)).toBe(c.pages);
  });
});

describe("maxDocumentPages", () => {
  const doc = (perceptual) => ({ kind: "document", role: "document", perceptual: { kind: "document", ...perceptual } });

  test("takes the largest document item and ignores every other kind", () => {
    const items = [
      { kind: "text", perceptual: { kind: "text", unit: "page", unit_count: 9000 } },
      doc({ unit: "page", unit_count: 40, chars_covered: 0 }),
      doc({ unit: null, unit_count: 1, chars_covered: 1801 * 100 }),
      { kind: "image", perceptual: { kind: "image" } },
    ];
    expect(maxDocumentPages(items)).toBe(101);
  });

  test("a reject item is not fingerprinted and does not count", () => {
    expect(maxDocumentPages([doc({ tier: "reject" })])).toBe(0);
  });

  test("no document items, no items, or no array is 0", () => {
    expect(maxDocumentPages([{ perceptual: { kind: "image" } }])).toBe(0);
    expect(maxDocumentPages([])).toBe(0);
    expect(maxDocumentPages(null)).toBe(0);
    expect(maxDocumentPages([null, {}])).toBe(0);
  });
});
