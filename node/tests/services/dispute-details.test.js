/**
 * @file tests/services/dispute-details.test.js
 * @description Tests for the off-chain dispute body store under the
 * combined-endpoint design (dispute body lands atomically with the
 * dispute filing — no standalone upload endpoint).
 *
 * Coverage:
 *   - dispute-details-service: persistEvidence (validation, signature,
 *     idempotency, cross-identity collision), discardEvidence, getDetails,
 *     hasDetails.
 *   - dispute-service.fileDispute: combined flow end-to-end — body lands
 *     when the dispute is accepted, body is rolled back when the dispute
 *     fails downstream (so no orphan rows on aborted submissions).
 *   - canDispute uniqueness rule: a second dispute reusing the same
 *     evidence_hash is rejected.
 *
 * Drives services directly. HTTP wiring is intentionally not exercised.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, canonicalJson, signBody,
} = require(path.join(SHARED, "crypto"));
const { TX_TYPES, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createDisputeService } = require(path.join(SRC, "services", "dispute-service"));
const { createDisputeDetailsService } = require(path.join(SRC, "services", "dispute-details-service"));

beforeAll(async () => {
  await initCrypto();
});

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/test";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  dag.saveVP({
    vp_id: VP_ID, name: "vp1", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });

  const disputerKp = generateMLDSAKeypair();
  const disputerTipId = "tip://id/disputer";
  const authorTipId = "tip://id/author";

  for (const [tipId, kp] of [[disputerTipId, disputerKp], [authorTipId, null]]) {
    dag.saveIdentity({
      tip_id: tipId, region: "US",
      public_key: kp ? kp.publicKey : "00",
      root_public_key: kp ? kp.publicKey : "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: 1767225600000, tx_id: shake256(`id:${tipId}`),
    });
    dag.setScore(tipId, 750, 0, 1767225600000);
  }

  // Seed jury candidates so jury selection has someone to draw from.
  for (let i = 0; i < 8; i++) {
    const t = `tip://id/juror-${i}`;
    dag.saveIdentity({
      tip_id: t, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: 1767225600000, tx_id: shake256(`id:${t}`),
    });
    dag.setScore(t, 750, 0, 1767225600000);
  }

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const submitted = [];
  const submitBatch = (txs) => { submitted.push(...txs); };
  const submitTx = (tx) => { submitted.push(tx); };

  const detailsService = createDisputeDetailsService({ dag });
  const disputeService = createDisputeService({
    dag, scoring, config, submitTx, submitBatch,
    disputeDetailsService: detailsService,
  });

  return { dag, scoring, config, disputerKp, disputerTipId, authorTipId,
    detailsService, disputeService, submitted };
}

function _seedContent(dag, ctid, authorTipId) {
  dag.saveContent({
    ctid, origin_code: "OH", content_hash: shake256(`c:${ctid}`),
    author_tip_id: authorTipId, status: CONTENT_STATUS.REGISTERED,
    registered_at: 1775001600000, tx_id: shake256(`reg:${ctid}`),
  });
}

function _validPayload(seed = "default") {
  return {
    description: `The declared origin OH appears incorrect (${seed}); multiple AI fingerprints detected.`,
    evidence: [
      { type: "url", content: "https://example.com/analysis", description: "GPTZero report" },
      { type: "ctid", content: "tip://c/AG-cccccccccccccc-1111", description: "Similar AG content" },
      { type: "statement", content: "Author admitted using ChatGPT in a public tweet on 2026-04-01." },
    ],
  };
}

function _signEvidencePayload(payload, privateKey) {
  return signBody(payload, privateKey);
}

function _signDisputeFields(fields, privateKey) {
  return signBody(fields, privateKey);
}

function _buildDisputeBody({ disputerTipId, disputerKp, payload, reason = "origin_mismatch", claimed_origin = "AG" }) {
  const evidenceSig = _signEvidencePayload(payload, disputerKp.privateKey);
  const evidence_hash = shake256(canonicalJson(payload));
  const sigFields = { disputer_tip_id: disputerTipId, reason };
  if (claimed_origin) sigFields.claimed_origin = claimed_origin;
  sigFields.evidence_hash = evidence_hash;
  const disputeSig = _signDisputeFields(sigFields, disputerKp.privateKey);
  return {
    disputer_tip_id: disputerTipId,
    reason,
    claimed_origin,
    signature: disputeSig,
    evidence: { payload, signature: evidenceSig },
  };
}

// ════════════════════════════════════════════════════════════════════════════
// 1. dispute-details-service unit tests (persist / discard / read)
// ════════════════════════════════════════════════════════════════════════════

describe("persistEvidence — validation", () => {
  test("rejects malformed disputer_tip_id", () => {
    const { detailsService } = _setup();
    expect(() => detailsService.persistEvidence({
      disputer_tip_id: "not-a-tip-id",
      payload: _validPayload(),
      signature: "00",
    })).toThrow(expect.objectContaining({ status: 400 }));
  });

  test("rejects empty description", () => {
    const { detailsService, disputerTipId, disputerKp } = _setup();
    const payload = { ..._validPayload(), description: "" };
    expect(() => detailsService.persistEvidence({
      disputer_tip_id: disputerTipId,
      payload,
      signature: _signEvidencePayload(payload, disputerKp.privateKey),
    })).toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/description/i) }));
  });

  test("rejects 11-item evidence array", () => {
    const { detailsService, disputerTipId, disputerKp } = _setup();
    const payload = {
      description: "ok",
      evidence: Array.from({ length: 11 }, (_, i) => ({ type: "statement", content: `s${i}` })),
    };
    expect(() => detailsService.persistEvidence({
      disputer_tip_id: disputerTipId,
      payload,
      signature: _signEvidencePayload(payload, disputerKp.privateKey),
    })).toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/exceeds 10 items/i) }));
  });

  test("rejects unknown evidence type", () => {
    const { detailsService, disputerTipId, disputerKp } = _setup();
    const payload = { description: "x", evidence: [{ type: "video", content: "https://example.com" }] };
    expect(() => detailsService.persistEvidence({
      disputer_tip_id: disputerTipId,
      payload,
      signature: _signEvidencePayload(payload, disputerKp.privateKey),
    })).toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/type must be one of/i) }));
  });
});

describe("persistEvidence — signature & identity", () => {
  test("rejects unknown disputer_tip_id", () => {
    const { detailsService } = _setup();
    expect(() => detailsService.persistEvidence({
      disputer_tip_id: "tip://id/ghost",
      payload: _validPayload(),
      signature: "ab",
    })).toThrow(expect.objectContaining({ status: 404 }));
  });

  test("rejects signature by a different key", () => {
    const { detailsService, disputerTipId } = _setup();
    const otherKp = generateMLDSAKeypair();
    const payload = _validPayload();
    expect(() => detailsService.persistEvidence({
      disputer_tip_id: disputerTipId,
      payload,
      signature: _signEvidencePayload(payload, otherKp.privateKey),
    })).toThrow(expect.objectContaining({ status: 403 }));
  });
});

describe("persistEvidence — happy path & idempotency", () => {
  test("persists and returns hash", () => {
    const { detailsService, dag, disputerTipId, disputerKp } = _setup();
    const payload = _validPayload();
    const sig = _signEvidencePayload(payload, disputerKp.privateKey);
    const out = detailsService.persistEvidence({ disputer_tip_id: disputerTipId, payload, signature: sig });

    expect(out.evidence_hash).toBe(shake256(canonicalJson(payload)));
    expect(out.idempotent).toBe(false);
    const row = dag.getDisputeDetails(out.evidence_hash);
    expect(row).not.toBeNull();
    expect(row.disputer_tip_id).toBe(disputerTipId);
  });

  test("idempotent on same body + same identity", () => {
    const { detailsService, disputerTipId, disputerKp } = _setup();
    const payload = _validPayload();
    const sig = _signEvidencePayload(payload, disputerKp.privateKey);
    const first = detailsService.persistEvidence({ disputer_tip_id: disputerTipId, payload, signature: sig });
    const second = detailsService.persistEvidence({ disputer_tip_id: disputerTipId, payload, signature: sig });
    expect(second.evidence_hash).toBe(first.evidence_hash);
    expect(second.idempotent).toBe(true);
  });

  test("conflict on same hash claimed by a different identity", () => {
    const { detailsService, dag, disputerTipId, disputerKp } = _setup();
    const otherTipId = "tip://id/other-disputer";
    const otherKp = generateMLDSAKeypair();
    dag.saveIdentity({
      tip_id: otherTipId, region: "US",
      public_key: otherKp.publicKey, root_public_key: otherKp.publicKey,
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: 1767225600000, tx_id: shake256(`id:${otherTipId}`),
    });

    const payload = _validPayload();
    detailsService.persistEvidence({
      disputer_tip_id: disputerTipId,
      payload,
      signature: _signEvidencePayload(payload, disputerKp.privateKey),
    });

    expect(() => detailsService.persistEvidence({
      disputer_tip_id: otherTipId,
      payload,
      signature: _signEvidencePayload(payload, otherKp.privateKey),
    })).toThrow(expect.objectContaining({ status: 409 }));
  });
});

describe("discardEvidence + getDetails + hasDetails", () => {
  test("discardEvidence removes the row; getDetails then 404s", () => {
    const { detailsService, disputerTipId, disputerKp } = _setup();
    const payload = _validPayload();
    const sig = _signEvidencePayload(payload, disputerKp.privateKey);
    const { evidence_hash } = detailsService.persistEvidence({ disputer_tip_id: disputerTipId, payload, signature: sig });

    expect(detailsService.hasDetails(evidence_hash)).toBe(true);
    expect(detailsService.discardEvidence(evidence_hash)).toBe(true);
    expect(detailsService.hasDetails(evidence_hash)).toBe(false);
    expect(() => detailsService.getDetails(evidence_hash))
      .toThrow(expect.objectContaining({ status: 404 }));
  });

  test("getDetails rejects malformed hash", () => {
    const { detailsService } = _setup();
    expect(() => detailsService.getDetails("not-hex"))
      .toThrow(expect.objectContaining({ status: 400 }));
  });

  test("hasDetails returns false for malformed input without throwing", () => {
    const { detailsService } = _setup();
    expect(detailsService.hasDetails(undefined)).toBe(false);
    expect(detailsService.hasDetails("zzz")).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 2. fileDispute end-to-end with inline evidence (combined endpoint)
// ════════════════════════════════════════════════════════════════════════════

describe("fileDispute + evidence — happy path", () => {
  test("dispute lands and body is persisted in one call", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid, fx.authorTipId);

    const payload = _validPayload();
    const body = _buildDisputeBody({
      disputerTipId: fx.disputerTipId,
      disputerKp: fx.disputerKp,
      payload,
    });
    const out = fx.disputeService.fileDispute(ctid, body);

    expect(out.success).toBe(true);
    expect(out.evidence_hash).toBe(shake256(canonicalJson(payload)));
    expect(out.dispute_tx_id).toMatch(/^[0-9a-f]{64}$/);

    const row = fx.dag.getDisputeDetails(out.evidence_hash);
    expect(row).not.toBeNull();
    expect(row.disputer_tip_id).toBe(fx.disputerTipId);

    expect(fx.submitted.some(t => t.tx_type === TX_TYPES.CONTENT_DISPUTED)).toBe(true);
  });

  test("dispute without evidence is rejected (evidence is required)", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid, fx.authorTipId);

    const sigFields = { disputer_tip_id: fx.disputerTipId, reason: "origin_mismatch", claimed_origin: "AG" };
    const sig = _signDisputeFields(sigFields, fx.disputerKp.privateKey);

    expect(() => fx.disputeService.fileDispute(ctid, {
      ...sigFields,
      signature: sig,
    })).toThrow(expect.objectContaining({ status: 400, error: expect.stringMatching(/evidence is required/i) }));
  });
});

describe("fileDispute + evidence — rollback on downstream failure", () => {
  test("body row is discarded if canDispute fails after persist", () => {
    const fx = _setup();
    const ctid = "tip://c/missing";  // intentionally NOT seeded — content not found

    const payload = _validPayload();
    const body = _buildDisputeBody({
      disputerTipId: fx.disputerTipId,
      disputerKp: fx.disputerKp,
      payload,
    });
    const expected_hash = shake256(canonicalJson(payload));

    expect(() => fx.disputeService.fileDispute(ctid, body))
      .toThrow(expect.objectContaining({ status: 404, error: expect.stringMatching(/Content record not found/) }));

    // No orphan body left behind.
    expect(fx.dag.getDisputeDetails(expected_hash)).toBeNull();
  });

  test("body row is discarded if disputer signature is wrong", () => {
    const fx = _setup();
    const ctid = "tip://c/x";
    _seedContent(fx.dag, ctid, fx.authorTipId);

    const payload = _validPayload();
    // Build a body where the dispute-fields signature is bogus, but the evidence sig is fine.
    const evidenceSig = _signEvidencePayload(payload, fx.disputerKp.privateKey);
    const evidence_hash = shake256(canonicalJson(payload));

    const body = {
      disputer_tip_id: fx.disputerTipId,
      reason: "origin_mismatch",
      claimed_origin: "AG",
      signature: "ab".repeat(40),  // wrong dispute signature
      evidence: { payload, signature: evidenceSig },
    };

    expect(() => fx.disputeService.fileDispute(ctid, body))
      .toThrow(expect.objectContaining({ status: 403 }));

    expect(fx.dag.getDisputeDetails(evidence_hash)).toBeNull();
  });
});

describe("fileDispute — origin_mismatch eligibility matrix", () => {
  // Eligible: OH→AG, OH→AA, AA→AG (penalty paths) and AG→OH
  // (CONSERVATIVE_LABEL). Anything else is rejected up-front so frivolous
  // disputes never reach jury selection.

  function _seedContentWithOrigin(dag, ctid, authorTipId, originCode) {
    dag.saveContent({
      ctid, origin_code: originCode, content_hash: shake256(`c:${ctid}:${originCode}`),
      author_tip_id: authorTipId, status: CONTENT_STATUS.REGISTERED,
      registered_at: 1775001600000, tx_id: shake256(`reg:${ctid}:${originCode}`),
    });
  }

  // Builds a valid dispute body with an attached evidence block. The
  // payload's `description` is unique per claimed_origin so the
  // evidence_hash uniqueness rule doesn't trip across the eligibility
  // matrix tests.
  function _disputeBodyOnly({ disputerTipId, disputerKp, claimed_origin }) {
    const payload = _validPayload(`origin-matrix-${claimed_origin}-${nowMs()}-${Math.random()}`);
    return _buildDisputeBody({ disputerTipId, disputerKp, payload, claimed_origin });
  }

  test.each([
    ["OH", "AG"],
    ["OH", "AA"],
    ["AA", "AG"],
    ["AG", "OH"],
  ])("accepts %s → %s", (declared, claimed) => {
    const fx = _setup();
    const ctid = `tip://c/${declared}-${claimed}`;
    _seedContentWithOrigin(fx.dag, ctid, fx.authorTipId, declared);

    const body = _disputeBodyOnly({
      disputerTipId: fx.disputerTipId,
      disputerKp: fx.disputerKp,
      claimed_origin: claimed,
    });
    const out = fx.disputeService.fileDispute(ctid, body);
    expect(out.success).toBe(true);
  });

  test.each([
    ["OH", "OH"], // same-origin
    ["OH", "MX"], // MX has no penalty path
    ["AA", "OH"], // downgrade — no verdict effect
    ["AG", "AA"], // not in matrix
    ["MX", "OH"], // MX as declared origin — never eligible
  ])("rejects %s → %s as ineligible", (declared, claimed) => {
    const fx = _setup();
    const ctid = `tip://c/${declared}-${claimed}`;
    _seedContentWithOrigin(fx.dag, ctid, fx.authorTipId, declared);

    const body = _disputeBodyOnly({
      disputerTipId: fx.disputerTipId,
      disputerKp: fx.disputerKp,
      claimed_origin: claimed,
    });
    expect(() => fx.disputeService.fileDispute(ctid, body))
      .toThrow(expect.objectContaining({
        status: 400,
        error: declared === claimed
          ? expect.stringMatching(/must differ from declared origin/i)
          : expect.stringMatching(/not a disputable mismatch/i),
      }));
  });
});

describe("fileDispute + evidence — uniqueness rule", () => {
  test("second dispute reusing the same evidence_hash is rejected; first is preserved", () => {
    const fx = _setup();
    const ctid1 = "tip://c/one";
    const ctid2 = "tip://c/two";
    _seedContent(fx.dag, ctid1, fx.authorTipId);
    _seedContent(fx.dag, ctid2, fx.authorTipId);

    const payload = _validPayload("shared");
    const body1 = _buildDisputeBody({
      disputerTipId: fx.disputerTipId,
      disputerKp: fx.disputerKp,
      payload,
    });
    const out1 = fx.disputeService.fileDispute(ctid1, body1);

    // Mirror the dispute tx into the DAG so canDispute on the second call
    // sees the prior CONTENT_DISPUTED with the same evidence_hash.
    const disputeTx = fx.submitted.find(t => t.tx_type === TX_TYPES.CONTENT_DISPUTED);
    fx.dag.addTx(disputeTx);

    const body2 = _buildDisputeBody({
      disputerTipId: fx.disputerTipId,
      disputerKp: fx.disputerKp,
      payload,  // identical payload → same hash
    });

    // Either layer (persistEvidence binding check OR canDispute uniqueness rule)
    // is allowed to surface the conflict — both produce 409 with a clear message.
    expect(() => fx.disputeService.fileDispute(ctid2, body2))
      .toThrow(expect.objectContaining({ status: 409, error: expect.stringMatching(/already (used|attached)/i) }));

    // The first dispute's body is still there.
    expect(fx.dag.getDisputeDetails(out1.evidence_hash)).not.toBeNull();
  });
});
