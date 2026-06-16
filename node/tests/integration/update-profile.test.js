/**
 * @file tests/integration/update-profile.test.js
 * @description Sparse-update profile preferences via UPDATE_PROFILE tx.
 *
 *   - Happy paths: reviewer_consent on/off (single v1 field; sparse-update
 *     semantics scaffolded for future field additions)
 *   - Sparse: present-only fields mutate the row; unrelated identity
 *     fields (region, public_key, etc.) preserved
 *   - Strict schema: unknown fields rejected
 *   - At-least-one rule: empty body rejected
 *   - Signature: tampered payload rejected; non-author key rejected
 *   - URL ↔ body tip_id mismatch rejected
 *   - Unknown TIP-ID rejected
 *   - getProfile reflects committed state
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
  initCrypto, generateMLDSAKeypair, shake256,
} = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createProfileService } = require(path.join(SRC, "services", "profile-service"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const updateProfileSchema = require(path.join(SRC, "schemas", "update-profile"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
  };
  const scoring = initScoring(dag, config);
  const submitted = [];
  // Just queue — commit-handler adds the tx to the DAG itself during
  // commitOrderedTxs. Calling dag.addTx here would make commit-handler
  // skip the tx (it's already in the DAG) and the state-application
  // case never runs.
  const submitTx = (tx) => { submitted.push(tx); };
  const profileService = createProfileService({ dag, config, submitTx });
  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId: NODE_ID });
  let round = 0;
  const commitSubmitted = () => {
    round++;
    commitHandler.commitOrderedTxs(submitted.splice(0, submitted.length), round, { certTimestamp: nowMs() });
  };
  return { dag, scoring, profileService, commitSubmitted, submitted };
}

function _seedIdentity(dag, tipId, kp, score = 750) {
  dag.saveIdentity({
    tip_id: tipId, region: "US",
    public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    // Explicit default — MemoryStore doesn't apply schema defaults the
    // way SQLite does. Production identities always have this set via
    // CREATE TABLE DEFAULT 0.
    reviewer_consent: false,
    registered_at: 1767225600000, tx_id: shake256(`id:${tipId}`),
  });
  dag.setScore(tipId, score, 0, 1767225600000);
}

function _seedUser(fx, label) {
  const kp = generateMLDSAKeypair();
  const tipId = `tip://id/US-${shake256(label).slice(0, 16)}`;
  _seedIdentity(fx.dag, tipId, kp);
  return { tipId, kp };
}

function _buildSignedBody(tipId, privateKey, preferences) {
  const payload = updateProfileSchema.buildSigningPayload({ tip_id: tipId, ...preferences });
  const signature = updateProfileSchema.sign(payload, privateKey);
  return { ...preferences, signature };
}

function _commit(fx) {
  // Drive committed-state through commit-handler so the identity row
  // reflects the sparse merge. Mirrors what consensus does on replay.
  fx.commitSubmitted();
}

describe("profile-service.updateProfile — sparse updates", () => {

  test("happy path: set reviewer_consent=true, identity row updates", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-1");

    const body = _buildSignedBody(tipId, kp.privateKey, { reviewer_consent: true });
    const result = fx.profileService.updateProfile(tipId, body);

    expect(result.confirmation).toBe("proposed");
    expect(result.tip_id).toBe(tipId);
    expect(result.updated).toEqual({ reviewer_consent: true });

    // tx.data carries the sparse field set + signature
    const tx = fx.submitted.find(t => t.tx_type === "UPDATE_PROFILE");
    expect(tx).toBeDefined();
    expect(tx.data.tip_id).toBe(tipId);
    expect(tx.data.reviewer_consent).toBe(true);

    _commit(fx);
    const updated = fx.dag.getIdentity(tipId);
    expect(updated.reviewer_consent).toBe(true);
  });

  test("can toggle off: explicit false update mutates field", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-2");

    fx.profileService.updateProfile(tipId,
      _buildSignedBody(tipId, kp.privateKey, { reviewer_consent: true }));
    _commit(fx);
    expect(fx.dag.getIdentity(tipId).reviewer_consent).toBe(true);

    fx.profileService.updateProfile(tipId,
      _buildSignedBody(tipId, kp.privateKey, { reviewer_consent: false }));
    _commit(fx);
    expect(fx.dag.getIdentity(tipId).reviewer_consent).toBe(false);
  });

  test("sparse: update doesn't mutate unrelated identity fields", () => {
    // Sparse-update semantics: only KNOWN_FIELDS are merged. Other
    // identity columns (region, public_key, vp_id, verification_tier,
    // etc.) must be preserved verbatim.
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-3");

    const before = fx.dag.getIdentity(tipId);
    const beforePublicKey = before.public_key;
    const beforeRegion = before.region;
    const beforeVpId = before.vp_id;

    fx.profileService.updateProfile(tipId,
      _buildSignedBody(tipId, kp.privateKey, { reviewer_consent: true }));
    _commit(fx);

    const after = fx.dag.getIdentity(tipId);
    expect(after.reviewer_consent).toBe(true);
    expect(after.public_key).toBe(beforePublicKey);
    expect(after.region).toBe(beforeRegion);
    expect(after.vp_id).toBe(beforeVpId);
  });
});

describe("profile-service.updateProfile — validation", () => {

  test("rejects empty body (no fields to update)", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-empty");
    const body = _buildSignedBody(tipId, kp.privateKey, {});
    expect(() => fx.profileService.updateProfile(tipId, body)).toThrow(
      expect.objectContaining({ status: 400, code: "no_fields_to_update" }),
    );
  });

  test("rejects unknown fields (strict schema)", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-unknown");
    // Sign payload that includes the unknown field — server rejects.
    const payload = { tip_id: tipId, reviewer_consent: true };
    const signature = updateProfileSchema.sign(payload, kp.privateKey);
    const body = { reviewer_consent: true, malicious_field: "yes", signature };
    expect(() => fx.profileService.updateProfile(tipId, body)).toThrow(
      expect.objectContaining({ status: 400, code: "field_unknown" }),
    );
  });

  test("rejects wrong field type (boolean field with string value)", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-type");
    const body = { reviewer_consent: "yes", signature: "dummy" };
    expect(() => fx.profileService.updateProfile(tipId, body)).toThrow(
      expect.objectContaining({ status: 400, code: "field_type_invalid" }),
    );
  });

  test("rejects URL/body tip_id mismatch", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-mismatch");
    const otherTipId = `tip://id/US-${shake256("attacker").slice(0, 16)}`;
    const body = _buildSignedBody(otherTipId, kp.privateKey, { reviewer_consent: true });
    // body.tip_id was set by buildSigningPayload — but our service signature
    // doesn't actually need it; we manually include it for the test.
    body.tip_id = otherTipId;
    expect(() => fx.profileService.updateProfile(tipId, body)).toThrow(
      expect.objectContaining({ status: 400, code: "tip_id_mismatch" }),
    );
  });

  test("rejects unknown TIP-ID", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const unknownTipId = `tip://id/US-${shake256("ghost").slice(0, 16)}`;
    const body = _buildSignedBody(unknownTipId, kp.privateKey, { reviewer_consent: true });
    expect(() => fx.profileService.updateProfile(unknownTipId, body)).toThrow(
      expect.objectContaining({ status: 412, code: "tip_id_not_registered" }),
    );
  });

  test("rejects tampered signature (sign with wrong key)", () => {
    const fx = _setup();
    const { tipId } = _seedUser(fx, "user-tampered");
    const wrongKp = generateMLDSAKeypair();
    const body = _buildSignedBody(tipId, wrongKp.privateKey, { reviewer_consent: true });
    expect(() => fx.profileService.updateProfile(tipId, body)).toThrow(
      expect.objectContaining({ status: 403, code: "signature_invalid" }),
    );
  });

  test("rejects missing signature", () => {
    const fx = _setup();
    const { tipId } = _seedUser(fx, "user-nosig");
    const body = { reviewer_consent: true };  // no signature
    expect(() => fx.profileService.updateProfile(tipId, body)).toThrow(
      expect.objectContaining({ status: 400, code: "signature_required" }),
    );
  });
});

describe("profile-service.getProfile", () => {

  test("returns default flags for un-set identity", () => {
    const fx = _setup();
    const { tipId } = _seedUser(fx, "user-default");
    const profile = fx.profileService.getProfile(tipId);
    expect(profile).toEqual({
      tip_id: tipId,
      reviewer_consent: false,
      juror_consent: false,
      expert_consent: false,
      interests: [],
    });
  });

  test("reflects committed state after update", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-getafter");
    fx.profileService.updateProfile(tipId,
      _buildSignedBody(tipId, kp.privateKey, { reviewer_consent: true }));
    _commit(fx);

    const profile = fx.profileService.getProfile(tipId);
    expect(profile.reviewer_consent).toBe(true);
  });

  test("rejects unknown TIP-ID", () => {
    const fx = _setup();
    const unknownTipId = `tip://id/US-${shake256("ghost2").slice(0, 16)}`;
    expect(() => fx.profileService.getProfile(unknownTipId)).toThrow(
      expect.objectContaining({ status: 404, code: "tip_id_not_registered" }),
    );
  });
});

// ── Issue #107 — independent role consent fields ───────────────────────────

describe("profile-service.updateProfile — juror_consent and expert_consent (issue #107)", () => {

  test("juror_consent can be set independently of reviewer_consent", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-juror");
    fx.profileService.updateProfile(tipId,
      _buildSignedBody(tipId, kp.privateKey, { juror_consent: true }));
    _commit(fx);
    // Use getProfile (not getIdentity) — back-compat normalization (undefined→false)
    // lives in _parseIdentityRow/knex _hydrate, not in the in-memory MemoryStore.
    const profile = fx.profileService.getProfile(tipId);
    expect(profile.juror_consent).toBe(true);
    expect(profile.reviewer_consent).toBe(false);  // unchanged
    expect(profile.expert_consent).toBe(false);    // never set → normalized to false
  });

  test("expert_consent can be set independently of reviewer_consent", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-expert");
    fx.profileService.updateProfile(tipId,
      _buildSignedBody(tipId, kp.privateKey, { expert_consent: true }));
    _commit(fx);
    const profile = fx.profileService.getProfile(tipId);
    expect(profile.expert_consent).toBe(true);
    expect(profile.reviewer_consent).toBe(false);
    expect(profile.juror_consent).toBe(false);     // never set → normalized to false
  });

  test("all three consent fields can be set in a single tx", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-allroles");
    fx.profileService.updateProfile(tipId,
      _buildSignedBody(tipId, kp.privateKey, {
        reviewer_consent: true, juror_consent: true, expert_consent: true,
      }));
    _commit(fx);
    const id = fx.dag.getIdentity(tipId);
    expect(id.reviewer_consent).toBe(true);
    expect(id.juror_consent).toBe(true);
    expect(id.expert_consent).toBe(true);
  });

  test("getProfile reflects all three consent fields", () => {
    const fx = _setup();
    const { tipId, kp } = _seedUser(fx, "user-profile3");
    fx.profileService.updateProfile(tipId,
      _buildSignedBody(tipId, kp.privateKey, { reviewer_consent: true, juror_consent: false, expert_consent: true }));
    _commit(fx);
    const profile = fx.profileService.getProfile(tipId);
    expect(profile.reviewer_consent).toBe(true);
    expect(profile.juror_consent).toBe(false);
    expect(profile.expert_consent).toBe(true);
  });
});
