/**
 * @file tests/services/profile-service-reviewer.test.js
 * @description Phase 5 — become-reviewer / stop-reviewing convenience
 * wrappers over UPDATE_PROFILE.
 *
 * Verifies that:
 *   - becomeReviewer pins reviewer_consent=true on the tx data
 *   - stopReviewing pins reviewer_consent=false on the tx data
 *   - Both still go through updateProfileSchema.validateRequest — the
 *     wrappers don't bypass any check. Signature mismatch / missing
 *     signature / wrong subject all reject identically to a generic
 *     POST /identity/:tipId/profile call.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256,
} = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createProfileService } = require(path.join(SRC, "services", "profile-service"));
const updateProfileSchema = require(path.join(SRC, "schemas", "update-profile"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const SUBJECT = "tip://id/US-1111aaaa1111aaaa";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const subjectKp = generateMLDSAKeypair();
  const otherKp = generateMLDSAKeypair();

  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  dag.saveIdentity({
    tip_id: SUBJECT, region: "US",
    public_key: subjectKp.publicKey, root_public_key: subjectKp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: false,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("subject"),
  });

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  const service = createProfileService({ dag, submitTx, config: {} });

  return { dag, service, submitted, subjectKp, otherKp };
}

function _signCanonical(input, privateKey) {
  const payload = updateProfileSchema.buildSigningPayload(input);
  return updateProfileSchema.sign(payload, privateKey);
}

function _throws(fn) {
  try { fn(); return null; } catch (err) { return err; }
}

describe("profile-service.becomeReviewer", () => {

  test("submits UPDATE_PROFILE with reviewer_consent=true", () => {
    const fx = _setup();
    const signature = _signCanonical(
      { tip_id: SUBJECT, reviewer_consent: true },
      fx.subjectKp.privateKey,
    );
    const out = fx.service.becomeReviewer(SUBJECT, { signature });
    expect(fx.submitted.length).toBe(1);
    const tx = fx.submitted[0];
    expect(tx.tx_type).toBe(TX_TYPES.UPDATE_PROFILE);
    expect(tx.data.reviewer_consent).toBe(true);
    expect(tx.data.tip_id).toBe(SUBJECT);
    expect(out.updated.reviewer_consent).toBe(true);
  });

  test("rejects signature signed for reviewer_consent=false", () => {
    const fx = _setup();
    // Client signed the wrong canonical payload — wrapper sets true, so
    // the signature verify against {tip_id, reviewer_consent: true} fails.
    const wrongSig = _signCanonical(
      { tip_id: SUBJECT, reviewer_consent: false },
      fx.subjectKp.privateKey,
    );
    const err = _throws(() => fx.service.becomeReviewer(SUBJECT, { signature: wrongSig }));
    expect(err.code).toBe("signature_invalid");
    expect(err.status).toBe(403);
    expect(fx.submitted.length).toBe(0);
  });

  test("rejects signature from a different keypair", () => {
    const fx = _setup();
    const sig = _signCanonical(
      { tip_id: SUBJECT, reviewer_consent: true },
      fx.otherKp.privateKey,
    );
    const err = _throws(() => fx.service.becomeReviewer(SUBJECT, { signature: sig }));
    expect(err.code).toBe("signature_invalid");
    expect(err.status).toBe(403);
  });

  test("rejects missing signature", () => {
    const fx = _setup();
    const err = _throws(() => fx.service.becomeReviewer(SUBJECT, {}));
    expect(err.code).toBe("signature_required");
    expect(err.status).toBe(400);
  });

  test("rejects URL tip_id mismatch with body.tip_id", () => {
    const fx = _setup();
    const signature = _signCanonical(
      { tip_id: SUBJECT, reviewer_consent: true },
      fx.subjectKp.privateKey,
    );
    const err = _throws(() => fx.service.becomeReviewer(SUBJECT, {
      tip_id: "tip://id/US-2222bbbb2222bbbb", signature,
    }));
    expect(err.code).toBe("tip_id_mismatch");
    expect(err.status).toBe(400);
  });
});

describe("profile-service.stopReviewing", () => {

  test("submits UPDATE_PROFILE with reviewer_consent=false", () => {
    const fx = _setup();
    const signature = _signCanonical(
      { tip_id: SUBJECT, reviewer_consent: false },
      fx.subjectKp.privateKey,
    );
    fx.service.stopReviewing(SUBJECT, { signature });
    expect(fx.submitted.length).toBe(1);
    expect(fx.submitted[0].data.reviewer_consent).toBe(false);
  });

  test("rejects signature signed for reviewer_consent=true", () => {
    const fx = _setup();
    const wrongSig = _signCanonical(
      { tip_id: SUBJECT, reviewer_consent: true },
      fx.subjectKp.privateKey,
    );
    const err = _throws(() => fx.service.stopReviewing(SUBJECT, { signature: wrongSig }));
    expect(err.code).toBe("signature_invalid");
    expect(err.status).toBe(403);
  });
});
