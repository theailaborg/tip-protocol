/**
 * @file tests/services/content-resolve-author-revocation.test.js
 * @description GET /v1/content/:ctid surfaces author_revocation as the
 * read-time signal that a piece of content's author has been revoked.
 *
 * Replaces the prior REVOKE_VP → CONTENT_DISPUTED cascade: the chain
 * stores only the revocation row, and downstream consumers render
 * per-reason_code UI from the resolve payload. content.status stays
 * untouched — that field continues to describe the content's own
 * adjudication state.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { TX_TYPES, CONTENT_STATUS } = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const AUTHOR = "tip://id/US-aaaaaaaaaaaaaaaa";
const CTID = "tip://c/OH-11111111111111-0001";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  dag.saveIdentity({
    tip_id: AUTHOR, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("author"),
  });
  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  dag.setScore(AUTHOR, 700, 0, new Date().toISOString());

  dag.saveContent({
    ctid: CTID, origin_code: "OH",
    content_hash: "ab".repeat(32), perceptual_hash: null,
    author_tip_id: AUTHOR, signer_tip_id: AUTHOR,
    authors: [{ tip_id: AUTHOR, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: CONTENT_STATUS.VERIFIED,
    prescan_flagged: false, prescan_probability: 0.1, prescan_tier: "low", override: false,
    registered_at: "2026-04-01T00:00:00.000Z",
    registered_urls: [], tx_id: shake256(`c:${CTID}`),
  });

  const service = createContentService({
    dag, scoring, config: { mediaLimits: {} }, submitTx: () => {},
  });
  return { dag, service };
}

function _seedRevocation(dag, { tx_type, reason_code, evidence_hash, timestamp }) {
  const txBody = {
    tx_type, timestamp, prev: [],
    data: {
      tx_type, tip_id: AUTHOR, reason_code,
      evidence_hash: evidence_hash || null,
      issuing_vp_id: VP_ID, signature: "deadbeef",
    },
  };
  const revokeTxId = computeTxId(txBody);
  dag.addTx({ ...txBody, tx_id: revokeTxId });
  dag.addRevocation(AUTHOR, tx_type, timestamp, revokeTxId);
  return revokeTxId;
}

describe("content-service.resolve — author_revocation", () => {

  test("no revocation → author_revocation is null, author_valid true", () => {
    const { service } = _setup();
    const out = service.resolve(CTID);
    expect(out.verification.author_revocation).toBeNull();
    expect(out.verification.author_valid).toBe(true);
  });

  test("REVOKE_VP → surfaces tx_type, reason_code, evidence_hash, issuing_vp_id, revoked_at", () => {
    const { dag, service } = _setup();
    const ts = "2026-05-10T12:00:00.000Z";
    const txId = _seedRevocation(dag, {
      tx_type: TX_TYPES.REVOKE_VP, reason_code: "fraudulent_identity",
      evidence_hash: "ff".repeat(32), timestamp: ts,
    });
    const out = service.resolve(CTID);
    expect(out.verification.author_valid).toBe(false);
    expect(out.verification.author_revocation).toEqual({
      tx_type: TX_TYPES.REVOKE_VP,
      reason_code: "fraudulent_identity",
      evidence_hash: "ff".repeat(32),
      issuing_vp_id: VP_ID,
      revoked_at: ts,
      tx_id: txId,
    });
  });

  test("REVOKE_VOLUNTARY → content.status stays VERIFIED (no cascade)", () => {
    const { dag, service } = _setup();
    _seedRevocation(dag, {
      tx_type: TX_TYPES.REVOKE_VOLUNTARY, reason_code: "user_request",
      evidence_hash: null, timestamp: "2026-05-10T12:00:00.000Z",
    });
    const out = service.resolve(CTID);
    expect(out.status).toBe(CONTENT_STATUS.VERIFIED);
    expect(out.verification.author_revocation.tx_type).toBe(TX_TYPES.REVOKE_VOLUNTARY);
    expect(out.verification.author_revocation.reason_code).toBe("user_request");
    expect(out.verification.author_revocation.evidence_hash).toBeNull();
  });

  test("REVOKE_DECEASED → content.status stays VERIFIED", () => {
    const { dag, service } = _setup();
    _seedRevocation(dag, {
      tx_type: TX_TYPES.REVOKE_DECEASED, reason_code: "death_certificate",
      evidence_hash: "aa".repeat(32), timestamp: "2026-05-10T12:00:00.000Z",
    });
    const out = service.resolve(CTID);
    expect(out.status).toBe(CONTENT_STATUS.VERIFIED);
    expect(out.verification.author_revocation.tx_type).toBe(TX_TYPES.REVOKE_DECEASED);
  });

  test("REVOKE_DEVICE → content.status stays VERIFIED", () => {
    const { dag, service } = _setup();
    _seedRevocation(dag, {
      tx_type: TX_TYPES.REVOKE_DEVICE, reason_code: "device_compromise",
      evidence_hash: "bb".repeat(32), timestamp: "2026-05-10T12:00:00.000Z",
    });
    const out = service.resolve(CTID);
    expect(out.status).toBe(CONTENT_STATUS.VERIFIED);
    expect(out.verification.author_revocation.tx_type).toBe(TX_TYPES.REVOKE_DEVICE);
  });
});

describe("dag.getRevocation", () => {

  test("returns null when no revocation exists", () => {
    const { dag } = _setup();
    expect(dag.getRevocation(AUTHOR)).toBeNull();
  });

  test("returns the canonical row when present", () => {
    const { dag } = _setup();
    const ts = "2026-05-10T12:00:00.000Z";
    const txId = _seedRevocation(dag, {
      tx_type: TX_TYPES.REVOKE_VP, reason_code: "x",
      evidence_hash: null, timestamp: ts,
    });
    const rec = dag.getRevocation(AUTHOR);
    expect(rec).toEqual({
      tip_id: AUTHOR, tx_type: TX_TYPES.REVOKE_VP, timestamp: ts, tx_id: txId,
    });
  });
});
