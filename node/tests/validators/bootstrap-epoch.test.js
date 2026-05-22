"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC    = path.resolve(__dirname, "../../src");

const { initCrypto }   = require(SHARED + "/crypto");
const { TX_TYPES }     = require(SHARED + "/constants");
const { validateBusinessRules, validateTransaction } = require(path.join(SRC, "validators", "tx-validator"));
const { getFoundingVP, getGenesisCommittee, getGenesisRing } = require(path.join(SRC, "genesis"));

beforeAll(async () => { await initCrypto(); });

// ── Stubs ──────────────────────────────────────────────────────────────────────
const dagAt = (latestRound) => ({ getLatestRound: () => latestRound });

// Minimal tx for validateBusinessRules (bypasses structure/schema layers)
const rulesTx = (tx_type, data = {}) => ({ tx_type, data });

// Full tx for validateTransaction (must pass structure + schema layers)
const fullGenesisTx = () => ({
  tx_type:   "GENESIS",
  tx_id:     "genesis-test-bootstrap-gate",
  timestamp: nowMs(),
  data:      {},
  prev:      [],
});

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("bootstrap epoch guard — validateBusinessRules", () => {

  describe("GENESIS tx type", () => {
    it("rejects at latestRound = 2", () => {
      const r = validateBusinessRules(rulesTx("GENESIS"), dagAt(2));
      expect(r.valid).toBe(false);
      expect(r.errors[0]).toMatch(/bootstrap-only/);
    });

    it("rejects at latestRound = 100", () => {
      const r = validateBusinessRules(rulesTx("GENESIS"), dagAt(100));
      expect(r.valid).toBe(false);
      expect(r.errors[0]).toMatch(/bootstrap-only/);
    });

    it("passes at latestRound = 0 (bootstrapping)", () => {
      const r = validateBusinessRules(rulesTx("GENESIS"), dagAt(0));
      expect(r.valid).toBe(true);
    });

    it("passes at latestRound = 1 (still bootstrapping)", () => {
      const r = validateBusinessRules(rulesTx("GENESIS"), dagAt(1));
      expect(r.valid).toBe(true);
    });

    it("passes when dag is null (legacy callers)", () => {
      const r = validateBusinessRules(rulesTx("GENESIS"), null);
      expect(r.valid).toBe(true);
    });
  });

  describe("VP_REGISTERED — founding VP", () => {
    it("rejects founding vp_id at latestRound = 2", () => {
      const { vp_id } = getFoundingVP();
      const r = validateBusinessRules(
        rulesTx(TX_TYPES.VP_REGISTERED, { vp_id, name: "Founding VP", jurisdiction_tier: "green", public_key: "aa" }),
        dagAt(2)
      );
      expect(r.valid).toBe(false);
      expect(r.errors[0]).toMatch(/founding VP/);
    });

    it("passes non-founding vp_id at latestRound = 2", () => {
      const r = validateBusinessRules(
        rulesTx(TX_TYPES.VP_REGISTERED, { vp_id: "tip://vp/US-aabbccddeeff0011", name: "New VP", jurisdiction_tier: "green", public_key: "bb" }),
        dagAt(2)
      );
      expect(r.valid).toBe(true);
    });
  });

  describe("NODE_REGISTERED — founding node", () => {
    it("rejects founding node_id at latestRound = 2", () => {
      const [foundingNodeId] = [...getGenesisCommittee()];
      const r = validateBusinessRules(
        rulesTx(TX_TYPES.NODE_REGISTERED, { node_id: foundingNodeId, name: "Founding Node", public_key: "cc" }),
        dagAt(2)
      );
      expect(r.valid).toBe(false);
      expect(r.errors[0]).toMatch(/founding node/);
    });

    it("passes non-founding node_id at latestRound = 2", () => {
      const r = validateBusinessRules(
        rulesTx(TX_TYPES.NODE_REGISTERED, { node_id: "tip://node/aaaa1111bbbb2222", name: "New Node", public_key: "dd" }),
        dagAt(2)
      );
      expect(r.valid).toBe(true);
    });
  });

  describe("REGISTER_IDENTITY — founding identity", () => {
    it("rejects founding tip_id at latestRound = 2", () => {
      const [foundingTipId] = [...getGenesisRing()];
      const r = validateBusinessRules(
        rulesTx(TX_TYPES.REGISTER_IDENTITY, { tip_id: foundingTipId, vp_id: "tip://vp/x", dedup_hash: "1" }),
        dagAt(2)
      );
      expect(r.valid).toBe(false);
      expect(r.errors[0]).toMatch(/founding identity/);
    });

    it("rejects founding tip_id at latestRound = 100", () => {
      const [foundingTipId] = [...getGenesisRing()];
      const r = validateBusinessRules(
        rulesTx(TX_TYPES.REGISTER_IDENTITY, { tip_id: foundingTipId, vp_id: "tip://vp/x", dedup_hash: "1" }),
        dagAt(100)
      );
      expect(r.valid).toBe(false);
      expect(r.errors[0]).toMatch(/founding identity/);
    });

    it("passes non-founding tip_id at latestRound = 2", () => {
      const r = validateBusinessRules(
        rulesTx(TX_TYPES.REGISTER_IDENTITY, { tip_id: "tip://id/US-deadbeefcafef00d", vp_id: "tip://vp/x", dedup_hash: "1" }),
        dagAt(2)
      );
      expect(r.valid).toBe(true);
    });

    it("passes founding tip_id at latestRound = 0 (bootstrapping)", () => {
      const [foundingTipId] = [...getGenesisRing()];
      const r = validateBusinessRules(
        rulesTx(TX_TYPES.REGISTER_IDENTITY, { tip_id: foundingTipId, vp_id: "tip://vp/x", dedup_hash: "1" }),
        dagAt(0)
      );
      expect(r.valid).toBe(true);
    });
  });

  describe("integration — validateTransaction propagates the layer", () => {
    it("GENESIS at round 2 fails with layer = business_rules", () => {
      const r = validateTransaction(fullGenesisTx(), dagAt(2));
      expect(r.valid).toBe(false);
      expect(r.layer).toBe("business_rules");
      expect(r.errors[0]).toMatch(/bootstrap-only/);
    });
  });
});
