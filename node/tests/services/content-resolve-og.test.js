/**
 * @file tests/services/content-resolve-og.test.js
 * @description content-service.resolveForOg — slim, read-only projection
 * for the Open Graph card. Must NOT alter resolve()/the extension contract.
 */
"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { ORIGIN_LABELS, CONTENT_STATUS } = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const AUTHOR = "tip://id/US-aaaaaaaaaaaaaaaa";
const CTID = "tip://c/OH-11111111111111-0001";
const REG_URL = "https://x.com/jane/status/123";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  dag.saveIdentity({
    tip_id: AUTHOR, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: shake256("author"),
  });
  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  dag.setScore(AUTHOR, 700, 0, nowMs());
  dag.saveContent({
    ctid: CTID, origin_code: "OH",
    content_hash: "ab".repeat(32),
    author_tip_id: AUTHOR, signer_tip_id: AUTHOR,
    authors: [{ tip_id: AUTHOR, tip_id_type: "personal" }],
    attribution_mode: "self", extras: { title: "My Article" }, cna_version: "CNA-2.2",
    status: CONTENT_STATUS.VERIFIED,
    prescan_flagged: false, prescan_probability: 0.1, prescan_tier: "low", override: false,
    registered_at: 1775001600000,
    registered_urls: [REG_URL], tx_id: shake256(`c:${CTID}`),
  });
  const service = createContentService({
    dag, scoring, config: { mediaLimits: {} }, submitTx: () => {},
  });
  return { dag, scoring, service };
}

describe("content-service.resolveForOg", () => {
  test("returns the slim card projection", () => {
    const { scoring, service } = _setup();
    const sc = scoring.getScore(AUTHOR);
    const out = service.resolveForOg(CTID);
    expect(out).toEqual({
      ctid: CTID,
      origin_code: "OH",
      origin_label: ORIGIN_LABELS["OH"],
      status: CONTENT_STATUS.VERIFIED,
      title: "My Article",
      author_name: null,
      author_tip_id: AUTHOR,
      author_score: sc.score,
      author_tier: "Trusted", // sc.tier.label — title-case, matches the inline badge / og-tokens tierForScore (NOT the uppercase .name enum)
      registered_url: REG_URL,
      created_at: 1775001600000,
    });
  });

  test("falls back to registered_urls[0] for registered_url", () => {
    const { service } = _setup();
    expect(service.resolveForOg(CTID).registered_url).toBe(REG_URL);
  });

  test("404 on unknown ctid (schemaError shape)", () => {
    const { service } = _setup();
    let thrown;
    try {
      service.resolveForOg("tip://c/OH-99999999999999-9999");
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeDefined();
    expect(thrown.status).toBe(404);
    expect(thrown.code).toBe("content_not_found");
    expect(thrown.error).toMatch(/not found/i);
  });
});
