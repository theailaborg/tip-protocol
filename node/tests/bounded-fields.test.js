/**
 * @file tests/bounded-fields.test.js
 * @description Every size-constrained column that a client can fill must have
 * a validator that rejects an over-length value BEFORE it reaches the DB.
 *
 * Why this exists:
 *   On 2026-08-19 a registration carried a media_canonical_hash longer than its
 *   varchar(64) column. It was accepted into the in-memory mirror, refused by
 *   Postgres, and the resulting memory-vs-DB mismatch fail-stopped all three
 *   mainnet nodes at once. One malformed field, whole fleet down.
 *
 *   Worse than an outage: the backends disagree. Postgres rejects, SQLite
 *   stores the overlong value, MySQL non-strict silently truncates. So an
 *   unvalidated bounded field is a cross-backend fork, not just downtime.
 *
 *   The root cause is drift: varchar(N) lives in a migration, the validator
 *   lives in a schema module, and nothing checked they agreed. This suite is
 *   that check. A new constrained column with no validator fails here.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");

const { assertBounded } = require(path.resolve(__dirname, "../src/schemas/_common"));
const contentRegister = require(path.resolve(__dirname, "../src/schemas/content-register"));
const registerIdentity = require(path.resolve(__dirname, "../src/schemas/register-identity"));
const bindDomain = require(path.resolve(__dirname, "../src/schemas/bind-domain"));

const SCHEMA_SQL = fs.readFileSync(path.resolve(__dirname, "../src/db/schema.sql"), "utf8");

/** Pull `column varchar(N)` out of one CREATE TABLE block. */
function columnsOf(table) {
  const m = SCHEMA_SQL.match(new RegExp("CREATE TABLE IF NOT EXISTS `" + table + "` \\((.*?)\\);", "s"));
  if (!m) throw new Error(`table ${table} not found in schema.sql`);
  const out = {};
  for (const c of m[1].matchAll(/`(\w+)` varchar\((\d+)\)/g)) out[c[1]] = Number(c[2]);
  return out;
}

describe("assertBounded", () => {
  const spec = { field: "thing", max: 8, pattern: /^[A-Z]+$/, describe: "uppercase" };

  test("accepts a value at exactly the limit", () => {
    expect(() => assertBounded("ABCDEFGH", spec)).not.toThrow();
  });

  test("rejects one character over the limit, and says so", () => {
    expect(() => assertBounded("ABCDEFGHI", spec)).toThrow(
      expect.objectContaining({ status: 400, code: "thing_too_long" }),
    );
  });

  test("rejects a wrong-format value that is within the limit", () => {
    expect(() => assertBounded("abcd", spec)).toThrow(
      expect.objectContaining({ code: "thing_invalid" }),
    );
  });

  test("absent is allowed unless required", () => {
    expect(() => assertBounded(undefined, spec)).not.toThrow();
    expect(() => assertBounded(undefined, { ...spec, required: true })).toThrow(
      expect.objectContaining({ code: "thing_required" }),
    );
  });

  test("rejects non-strings rather than coercing them", () => {
    expect(() => assertBounded(12345678, spec)).toThrow(
      expect.objectContaining({ code: "thing_invalid" }),
    );
  });
});

// The regression that took the fleet down. Each case feeds a value one char
// over its real column width and asserts the validator refuses it.
describe("client-fillable bounded columns reject over-length values", () => {
  test("content.media_canonical_hash , the 2026-08-19 outage", () => {
    const max = columnsOf("content").media_canonical_hash;
    expect(max).toBe(64);
    const overlong = "a".repeat(max + 1);

    // The legacy no-media[] path, which stored the client value verbatim.
    expect(() => contentRegister.validateRequest(
      {
        signer_tip_id: "tip://id/US-1", origin_code: "OH", signature: "x",
        media_canonical_hash: overlong, authors: [{ tip_id: "tip://id/US-1" }]
      },
      { mediaLimits: {}, dag: { getIdentity: () => null, isRevoked: () => false } },
    )).toThrow(expect.objectContaining({ code: "media_canonical_hash_too_long" }));
  });

  test("content.media_canonical_hash is rejected on the gossip path too", () => {
    const overlong = "a".repeat(65);
    const res = contentRegister.verifyTx(
      {
        tx_type: "REGISTER_CONTENT", data: {
          signature: "x", signer_tip_id: "tip://id/US-1",
          media_canonical_hash: overlong, cna_version: contentRegister.CURRENT_CNA_VERSION,
        }
      },
      {
        getIdentity: () => ({ tip_id: "tip://id/US-1", public_key: "00", tip_id_type: "personal" }),
        isRevoked: () => false
      },
    );
    expect(res.ok).toBe(false);
    expect(res.code).toBe("media_canonical_hash_too_long");
  });

  test("identities.region", () => {
    const max = columnsOf("identities").region;
    expect(max).toBe(8);
    // buildSigningPayload runs on both the API and verifyTx paths.
    // validateRequest is the API gate; buildSigningPayload covers verifyTx.
    expect(() => registerIdentity.validateRequest(
      {
        public_key: "00", dedup_hash: "00", vp_id: "tip://vp/1", vp_signature: "x",
        region: "A".repeat(max + 1)
      },
      { dag: { getVP: () => null } },
    )).toThrow(expect.objectContaining({ code: "region_too_long" }));
  });

  test("domain_bindings.domain", () => {
    const max = columnsOf("domain_bindings").domain;
    expect(max).toBe(253);
    const overlong = "a".repeat(max + 1) + ".com";
    expect(() => bindDomain.buildSigningPayload(
      { tip_id: "tip://id/US-1", domain: overlong, node_id: "tip://node/1" },
    )).toThrow(expect.objectContaining({ code: "domain_too_long" }));
    expect(max).toBe(253);
  });
});

// Drift guard: if someone adds a small varchar column to a consensus-written
// table, it must appear here with a decision recorded. Failing this test means
// "go check whether a client can fill that column", not "add it to the list".
describe("no unreviewed bounded columns", () => {
  const REVIEWED = {
    content: {
      tip_ctid: "server-derived from content_hash", origin_code: "enum",
      content_hash: "64-hex regex", author_tip_id: "tip:// form, DAG-resolved",
      signer_tip_id: "tip:// form, DAG-resolved", attribution_mode: "enum",
      cna_version: "version whitelist", status: "server-set",
      prescan_tier: "server-set", prescan_status: "server-set",
      prescan_assigned_node_id: "server-set", prescan_content_type: "server-set",
      content_type_hint: "server-set", media_canonical_hash: "assertBounded, both paths",
      tx_id: "server-derived", parent_url: "validateCanonicalUrl, 2048 cap",
    },
    identities: {
      tip_id: "server-derived from public_key", region: "assertBounded, both paths",
      vp_id: "DAG-resolved", verification_tier: "enum", score_display_mode: "enum",
      tip_id_type: "enum", status: "server-set", tx_id: "server-derived",
      org_type: "regex 2-64",
    },
    domain_bindings: {
      domain: "assertBounded, both paths", tip_id: "DAG-resolved",
      binding_state: "server-set", method: "enum", node_id: "DAG-resolved",
      tx_id: "server-derived",
    },
    nodes: { node_id: "server-derived", status: "server-set", operated_by: "DAG-resolved" },
    transactions: { tx_id: "server-derived", tx_type: "enum", subject_tip_id: "DAG-resolved" },
  };

  test.each(Object.keys(REVIEWED))("%s has no unreviewed varchar column", (table) => {
    const unreviewed = Object.keys(columnsOf(table)).filter(c => !(c in REVIEWED[table]));
    expect(unreviewed).toEqual([]);
  });
});
