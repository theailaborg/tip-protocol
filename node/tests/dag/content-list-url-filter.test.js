/**
 * @file tests/dag/content-list-url-filter.test.js
 * @description Regression for the read-only registered-URL lookup added for
 * the VP portal's advisory duplicate-URL check. Verifies listContent({url})
 * returns EXACT registered_urls element matches and that the LIKE escaping
 * is injection-safe (no wildcard/prefix matches).
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initDAG } = require(path.join(SRC, "dag"));
// No initCrypto: saveContent/listContent are pure DB operations and do not
// sign anything, so this regression needs no crypto backend.

let _n = 0;
function _ctid() {
  // tip://c/OH-<16hex>-<4hex>
  const h = (_n++).toString(16).padStart(16, "0");
  return `tip://c/OH-${h}-aaaa`;
}

function _seed(dag, urls, at) {
  dag.saveContent({
    ctid: _ctid(), origin_code: "OH",
    content_hash: "00".repeat(32), perceptual_hash: null,
    author_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa",
    signer_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa",
    authors: [], attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: "registered", override: false, registered_at: at,
    registered_urls: urls, tx_id: "tx_" + _ctid(),
  });
}

describe("listContent url filter (advisory duplicate-URL lookup)", () => {
  test("exact registered-URL match returns the record; non-matches return nothing", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const FB = "https://www.facebook.com/share/p/18oEc59WeT/";
    _seed(dag, [FB], 1000);
    _seed(dag, ["https://x.com/u/status/1790000000000000000"], 1001);

    expect(dag.listContent({ url: FB }).length).toBe(1);
    // Trailing-slash sensitivity: stored value has it, query without it must NOT match.
    expect(dag.listContent({ url: "https://www.facebook.com/share/p/18oEc59WeT" }).length).toBe(0);
    // Completely different URL.
    expect(dag.listContent({ url: "https://www.facebook.com/share/p/ZZZZZZZZZZ/" }).length).toBe(0);
  });

  test("no prefix/superstring false matches (closing quote delimits the element)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    _seed(dag, ["https://x.com/p/12"], 2000);
    // Querying a prefix of a stored URL must not match.
    expect(dag.listContent({ url: "https://x.com/p/1" }).length).toBe(0);
    // Querying a superstring must not match.
    expect(dag.listContent({ url: "https://x.com/p/123" }).length).toBe(0);
    // The exact value matches.
    expect(dag.listContent({ url: "https://x.com/p/12" }).length).toBe(1);
  });

  test("LIKE wildcards in the query are escaped (no injection)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    _seed(dag, ["https://x.com/abc"], 3000);
    // "%" and "_" must be treated literally, not as SQL LIKE wildcards.
    expect(dag.listContent({ url: "https://x.com/%" }).length).toBe(0);
    expect(dag.listContent({ url: "https://x.com/ab_" }).length).toBe(0);
  });

  test("multiple registrations of the same URL are all returned", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const U = "https://example.com/post/abcdef";
    _seed(dag, [U], 4000);
    _seed(dag, [U, "https://example.com/mirror"], 4001);
    expect(dag.listContent({ url: U }).length).toBe(2);
  });
});
