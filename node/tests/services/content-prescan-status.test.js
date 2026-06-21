"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");

const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const PC = require(path.join(SHARED, "protocol-constants"));
try { PC._resetForTesting(); } catch { /* already initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const { initDAG } = require(path.resolve(__dirname, "../../src/dag"));
const { createContentService } = require(path.resolve(__dirname, "../../src/services/content-service"));

const CTID = "tip://c/OH-7f2a91bc3d5e4a-a3f8";

function setup() {
  const dag = initDAG({ dbPath: ":memory-test:" });
  const service = createContentService({
    dag,
    scoring: { getScore: () => ({ score: 500 }) },
    config: {},
    submitTx: () => ({}),
    prescanJobs: null,
  });
  return { dag, service };
}

function saveContent(dag, overrides = {}) {
  dag.saveContent({
    ctid: CTID,
    origin_code: "OH",
    content_hash: "abcd1234",
    author_tip_id: "tip://id/US-1234567890abcdef",
    signer_tip_id: "tip://id/US-1234567890abcdef",
    authors: [],
    attribution_mode: "self",
    extras: {},
    cna_version: "2.2",
    status: "registered",
    prescan_flagged: 0,
    prescan_probability: 0,
    prescan_tier: "low",
    prescan_status: "completed",
    prescan_completed_at: null,
    prescan_assigned_node_id: null,
    prescan_content_type: null,
    prescan_overall_degraded: 0,
    content_type_hint: null,
    override: 0,
    registered_at: 1779800000000,
    registered_urls: [],
    tx_id: "tx_abc",
    ...overrides,
  });
}

describe("getPrescanStatus", () => {
  test("404 when content row not found", () => {
    const { service } = setup();
    expect(() => service.getPrescanStatus(CTID)).toThrow(
      expect.objectContaining({ status: 404, code: "content_not_found" })
    );
  });

  test("pending row returns { ctid, prescan_status: 'pending' } only", () => {
    const { dag, service } = setup();
    saveContent(dag, { prescan_status: "pending", status: "pending_prescan" });
    const r = service.getPrescanStatus(CTID);
    expect(r).toEqual({ ctid: CTID, prescan_status: "pending" });
  });

  test("completed row returns the full verdict shape", () => {
    const { dag, service } = setup();
    saveContent(dag, {
      prescan_status: "completed",
      prescan_flagged: 1,
      prescan_probability: 0.92,
      prescan_tier: "high",
      prescan_completed_at: 1779800005230,
      prescan_content_type: "text",
      prescan_overall_degraded: 0,
    });
    const r = service.getPrescanStatus(CTID);
    expect(r).toEqual({
      ctid: CTID,
      prescan_status: "completed",
      prescan_flagged: true,
      prescan_probability: 0.92,
      prescan_tier: "high",
      prescan_completed_at: 1779800005230,
      prescan_content_type: "text",
      prescan_overall_degraded: false,
    });
  });

  test("legacy row (prescan_status missing on the record) defaults to completed", () => {
    const { dag, service } = setup();
    saveContent(dag, { prescan_status: undefined, prescan_tier: "low" });
    const r = service.getPrescanStatus(CTID);
    expect(r.prescan_status).toBe("completed");
    expect(r.prescan_tier).toBe("low");
  });

  test("degraded flag surfaces in the verdict", () => {
    const { dag, service } = setup();
    saveContent(dag, {
      prescan_status: "completed",
      prescan_probability: 0.5,
      prescan_overall_degraded: 1,
    });
    expect(service.getPrescanStatus(CTID).prescan_overall_degraded).toBe(true);
  });
});
