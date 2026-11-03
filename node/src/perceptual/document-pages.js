"use strict";

// Pages a cf-doc-1 document item counts as for the plan page limits. Page and
// slide units count themselves; every other document counts standard pages of
// CHARS_PER_PAGE characters, rounded up, at least 1. The VP keeps a browser copy
// of this rule (public/shared/doc-pages.js); both are tested against the same
// vectors (tests/fixtures/doc-pages-vectors.json), so change them together.

const { DOCUMENT_PAGES } = require("../../../shared/constants");

function documentPages(item, charsPerPage = DOCUMENT_PAGES.CHARS_PER_PAGE) {
  if (item.unit === "page" || item.unit === "slide") return item.unit_count;
  return Math.max(1, Math.ceil(item.chars_covered / charsPerPage));
}

// The largest page count among a registration's fingerprinted document items,
// or 0 when it carries none. Reject items (not fingerprinted) do not count.
function maxDocumentPages(items) {
  let max = 0;
  for (const it of Array.isArray(items) ? items : []) {
    const p = it && it.perceptual;
    if (!p || p.kind !== "document" || p.tier === "reject") continue;
    max = Math.max(max, documentPages(p));
  }
  return max;
}

module.exports = { documentPages, maxDocumentPages };
