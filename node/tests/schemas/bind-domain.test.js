/**
 * @file tests/schemas/bind-domain.test.js
 * @description Pure-function tests for the node-attested BIND_DOMAIN schema.
 *
 *   - 8-field canonical shape + reject-on-extra
 *   - sign / verify round-trip (node key)
 *   - verifyTx end-to-end:
 *       missing sigs → coded error
 *       node not registered / inactive → coded error
 *       claimant revoked / personal → coded error
 *       embedded user claim signature must validate against DAG pubkey
 *       happy path returns { ok: true }
 *   - UNBIND_DOMAIN buildUnbindSigningPayload + verifyUnbindTx
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const {
  TIP_ID_TYPES, DOMAIN_VERIFICATION_METHODS, DOMAIN_BINDING_STATUS,
  DOMAIN_UNBIND_REASONS,
} = require(path.join(SHARED, "constants"));
const registerDomainSchema = require(path.join(SRC, "schemas", "register-domain"));
const bindSchema = require(path.join(SRC, "schemas", "bind-domain"));

beforeAll(async () => { await initCrypto(); });

const ORG_TIP = "tip://id/US-aaaaaaaaaaaaaaaa";
const PERSONAL_TIP = "tip://id/US-bbbbbbbbbbbbbbbb";
const NODE_ID = "node-test-1";

function makeFakeDag({ identities = {}, nodes = {}, bindings = {}, revoked = new Set() } = {}) {
  return {
    getIdentity: (id) => identities[id] || null,
    getNode: (id) => nodes[id] || null,
    getDomainBinding: (d) => bindings[d] || null,
    isRevoked: (id) => revoked.has(id),
  };
}

// Helper: produce a fully-signed BIND_DOMAIN tx.data shape for verifyTx tests.
function buildBindTxData(userKp, nodeKp, overrides = {}) {
  const claimedAt = "2026-05-12T10:00:00.000Z";
  const verifiedAt = "2026-05-12T10:01:00.000Z";
  const claim = registerDomainSchema.buildSigningPayload({
    claimed_at: claimedAt, domain: "example.com", method: "auto", tip_id: ORG_TIP,
  });
  const claimSig = registerDomainSchema.sign(claim, userKp.privateKey);

  const binding = bindSchema.buildSigningPayload({
    binding_state:   DOMAIN_BINDING_STATUS.VERIFIED,
    claim_signature: claimSig,
    claimed_at:      claimedAt,
    domain:          "example.com",
    method:          "auto",
    node_id:         NODE_ID,
    tip_id:          ORG_TIP,
    verified_at:     verifiedAt,
  });
  const bindingSig = bindSchema.sign(binding, nodeKp.privateKey);

  return {
    binding_state:     binding.binding_state,
    claim_signature:   binding.claim_signature,
    claimed_at:        binding.claimed_at,
    domain:            binding.domain,
    method:            binding.method,
    node_id:           binding.node_id,
    tip_id:            binding.tip_id,
    verified_at:       binding.verified_at,
    binding_signature: bindingSig,
    ...overrides,
  };
}

// ─── Module surface ─────────────────────────────────────────────────────────

describe("module surface", () => {
  test("exports the expected helpers", () => {
    expect(bindSchema.TX_TYPE).toBe("BIND_DOMAIN");
    expect(bindSchema.TX_TYPE_UNBIND).toBe("UNBIND_DOMAIN");
    expect(typeof bindSchema.buildSigningPayload).toBe("function");
    expect(typeof bindSchema.buildUnbindSigningPayload).toBe("function");
    expect(typeof bindSchema.verifyTx).toBe("function");
    expect(typeof bindSchema.verifyUnbindTx).toBe("function");
  });
});

// ─── buildSigningPayload — exact 8-field shape ──────────────────────────────

describe("buildSigningPayload — exact 8-field canonical shape", () => {
  const minimal = (overrides = {}) => bindSchema.buildSigningPayload({
    binding_state: "verified",
    claim_signature: "00".repeat(8),
    claimed_at: "2026-05-12T10:00:00.000Z",
    domain: "example.com",
    method: "auto",
    node_id: NODE_ID,
    tip_id: ORG_TIP,
    verified_at: "2026-05-12T10:01:00.000Z",
    ...overrides,
  });

  test("emits exactly the 8 spec fields, alphabetical", () => {
    expect(Object.keys(minimal()).sort()).toEqual([
      "binding_state", "claim_signature", "claimed_at", "domain", "method",
      "node_id", "tip_id", "verified_at",
    ]);
  });

  test("reject-on-extra — junk fields stripped", () => {
    const p = minimal({ malicious: "stripped" });
    expect(p.malicious).toBeUndefined();
  });

  test("binding_state outside the on-chain set rejected", () => {
    expect(() => minimal({ binding_state: "pending_verification" }))
      .toThrow(expect.objectContaining({ status: 400, code: "binding_state_invalid" }));
  });

  test("method outside the enum rejected", () => {
    expect(() => minimal({ method: "ftp" }))
      .toThrow(expect.objectContaining({ status: 400, code: "method_invalid" }));
  });

  test("missing node_id rejected", () => {
    expect(() => minimal({ node_id: "" }))
      .toThrow(expect.objectContaining({ status: 400, code: "node_id_required" }));
  });

  test("invalid verified_at rejected", () => {
    expect(() => minimal({ verified_at: "not-a-date" }))
      .toThrow(expect.objectContaining({ status: 400, code: "verified_at_invalid" }));
  });

  test("missing claim_signature rejected", () => {
    expect(() => minimal({ claim_signature: "" }))
      .toThrow(expect.objectContaining({ status: 400, code: "claim_signature_required" }));
  });
});

// ─── sign / verify round-trip ───────────────────────────────────────────────

describe("sign / verify round-trip (node key)", () => {
  test("correctly-signed payload verifies", () => {
    const kp = generateMLDSAKeypair();
    const payload = bindSchema.buildSigningPayload({
      binding_state: "verified",
      claim_signature: "ab".repeat(8),
      claimed_at: "2026-05-12T10:00:00.000Z",
      domain: "example.com",
      method: "auto",
      node_id: NODE_ID,
      tip_id: ORG_TIP,
      verified_at: "2026-05-12T10:01:00.000Z",
    });
    const sig = bindSchema.sign(payload, kp.privateKey);
    expect(bindSchema.verifySignature(payload, sig, kp.publicKey)).toBe(true);
  });

  test("any field flipped breaks the signature", () => {
    const kp = generateMLDSAKeypair();
    const payload = bindSchema.buildSigningPayload({
      binding_state: "verified",
      claim_signature: "ab".repeat(8),
      claimed_at: "2026-05-12T10:00:00.000Z",
      domain: "example.com",
      method: "auto",
      node_id: NODE_ID,
      tip_id: ORG_TIP,
      verified_at: "2026-05-12T10:01:00.000Z",
    });
    const sig = bindSchema.sign(payload, kp.privateKey);
    for (const field of Object.keys(payload)) {
      const tampered = { ...payload, [field]: typeof payload[field] === "string" ? "xx" + payload[field] : payload[field] };
      expect(bindSchema.verifySignature(tampered, sig.hex, kp.publicKey)).toBe(false);
    }
  });
});

// ─── verifyTx — full server-side entry ──────────────────────────────────────

describe("verifyTx", () => {
  function setup() {
    const userKp = generateMLDSAKeypair();
    const nodeKp = generateMLDSAKeypair();
    const dag = makeFakeDag({
      identities: {
        [ORG_TIP]: { public_key: userKp.publicKey, tip_id_type: TIP_ID_TYPES.ORGANIZATION },
      },
      nodes: {
        [NODE_ID]: { public_key: nodeKp.publicKey, status: "active" },
      },
    });
    const data = buildBindTxData(userKp, nodeKp);
    return { userKp, nodeKp, dag, data };
  }

  test("happy path returns { ok: true }", () => {
    const { dag, data } = setup();
    expect(bindSchema.verifyTx({ data }, dag)).toEqual({ ok: true });
  });

  test("missing binding_signature → 400 binding_signature_missing", () => {
    const { dag, data } = setup();
    delete data.binding_signature;
    expect(bindSchema.verifyTx({ data }, dag)).toMatchObject({ ok: false, status: 400, code: "binding_signature_missing" });
  });

  test("missing node_id → 400 node_id_missing", () => {
    const { dag, data } = setup();
    data.node_id = "";
    expect(bindSchema.verifyTx({ data }, dag)).toMatchObject({ ok: false, status: 400, code: "node_id_missing" });
  });

  test("node not registered → 412 node_not_registered", () => {
    const { dag, data } = setup();
    data.node_id = "ghost-node";
    expect(bindSchema.verifyTx({ data }, dag)).toMatchObject({ ok: false, status: 412, code: "node_not_registered" });
  });

  test("node inactive → 403 node_inactive", () => {
    const userKp = generateMLDSAKeypair();
    const nodeKp = generateMLDSAKeypair();
    const dag = makeFakeDag({
      identities: { [ORG_TIP]: { public_key: userKp.publicKey, tip_id_type: TIP_ID_TYPES.ORGANIZATION } },
      nodes:      { [NODE_ID]: { public_key: nodeKp.publicKey, status: "suspended" } },
    });
    const data = buildBindTxData(userKp, nodeKp);
    expect(bindSchema.verifyTx({ data }, dag)).toMatchObject({ ok: false, status: 403, code: "node_inactive" });
  });

  test("wrong node sig → 403 binding_signature_invalid", () => {
    const { dag, data } = setup();
    const foreign = generateMLDSAKeypair();
    // Re-sign with a different key — node lookup still succeeds (right pubkey
    // on DAG), but the signature doesn't validate against it.
    const payload = bindSchema.buildSigningPayload(data);
    data.binding_signature = bindSchema.sign(payload, foreign.privateKey);
    expect(bindSchema.verifyTx({ data }, dag)).toMatchObject({ ok: false, status: 403, code: "binding_signature_invalid" });
  });

  test("claimant not registered → 412 signer_not_registered", () => {
    const userKp = generateMLDSAKeypair();
    const nodeKp = generateMLDSAKeypair();
    const dag = makeFakeDag({
      identities: {},
      nodes:      { [NODE_ID]: { public_key: nodeKp.publicKey, status: "active" } },
    });
    const data = buildBindTxData(userKp, nodeKp);
    expect(bindSchema.verifyTx({ data }, dag)).toMatchObject({ ok: false, status: 412, code: "signer_not_registered" });
  });

  test("claimant revoked → 403 signer_revoked", () => {
    const userKp = generateMLDSAKeypair();
    const nodeKp = generateMLDSAKeypair();
    const dag = makeFakeDag({
      identities: { [ORG_TIP]: { public_key: userKp.publicKey, tip_id_type: TIP_ID_TYPES.ORGANIZATION } },
      nodes:      { [NODE_ID]: { public_key: nodeKp.publicKey, status: "active" } },
      revoked:    new Set([ORG_TIP]),
    });
    const data = buildBindTxData(userKp, nodeKp);
    expect(bindSchema.verifyTx({ data }, dag)).toMatchObject({ ok: false, status: 403, code: "signer_revoked" });
  });

  test("claimant is personal → 403 tip_id_not_authorised", () => {
    const userKp = generateMLDSAKeypair();
    const nodeKp = generateMLDSAKeypair();
    const dag = makeFakeDag({
      identities: { [ORG_TIP]: { public_key: userKp.publicKey, tip_id_type: TIP_ID_TYPES.PERSONAL } },
      nodes:      { [NODE_ID]: { public_key: nodeKp.publicKey, status: "active" } },
    });
    const data = buildBindTxData(userKp, nodeKp);
    expect(bindSchema.verifyTx({ data }, dag)).toMatchObject({ ok: false, status: 403, code: "tip_id_not_authorised" });
  });

  test("user claim signature invalid → 403 claim_signature_invalid", () => {
    const { dag, data } = setup();
    // Swap claim_signature out for garbage. Node sig has to be rebuilt over
    // the new bytes for the verifyTx to even reach the claim-sig check.
    data.claim_signature = "00".repeat(8);
    const payload = bindSchema.buildSigningPayload(data);
    // re-sign with the actual node key that's on the DAG
    const realNodeKp = generateMLDSAKeypair();
    dag.getNode = () => ({ public_key: realNodeKp.publicKey, status: "active" });
    data.binding_signature = bindSchema.sign(payload, realNodeKp.privateKey);
    expect(bindSchema.verifyTx({ data }, dag)).toMatchObject({ ok: false, status: 403, code: "claim_signature_invalid" });
  });
});

// ─── UNBIND_DOMAIN ──────────────────────────────────────────────────────────

describe("buildUnbindSigningPayload", () => {
  const minimal = (overrides = {}) => bindSchema.buildUnbindSigningPayload({
    domain: "example.com",
    node_id: NODE_ID,
    reason: DOMAIN_UNBIND_REASONS.VERIFICATION_LOST,
    revoked_at: "2026-05-12T10:00:00.000Z",
    ...overrides,
  });

  test("emits exactly 4 fields", () => {
    expect(Object.keys(minimal()).sort()).toEqual(["domain", "node_id", "reason", "revoked_at"]);
  });

  test("reason outside enum rejected", () => {
    expect(() => minimal({ reason: "whoops" }))
      .toThrow(expect.objectContaining({ status: 400, code: "reason_invalid" }));
  });

  test("missing node_id rejected", () => {
    expect(() => minimal({ node_id: "" }))
      .toThrow(expect.objectContaining({ status: 400, code: "node_id_required" }));
  });
});

describe("verifyUnbindTx", () => {
  function setup() {
    const nodeKp = generateMLDSAKeypair();
    const dag = makeFakeDag({
      nodes:    { [NODE_ID]: { public_key: nodeKp.publicKey, status: "active" } },
      bindings: { "example.com": { domain: "example.com", binding_state: "verified" } },
    });
    const payload = bindSchema.buildUnbindSigningPayload({
      domain: "example.com",
      node_id: NODE_ID,
      reason: DOMAIN_UNBIND_REASONS.VERIFICATION_LOST,
      revoked_at: "2026-05-12T10:00:00.000Z",
    });
    const sig = bindSchema.signUnbind(payload, nodeKp.privateKey);
    return { dag, data: { ...payload, unbind_signature: sig } };
  }

  test("happy path", () => {
    const { dag, data } = setup();
    expect(bindSchema.verifyUnbindTx({ data }, dag)).toEqual({ ok: true });
  });

  test("missing unbind_signature → unbind_signature_missing", () => {
    const { dag, data } = setup();
    delete data.unbind_signature;
    expect(bindSchema.verifyUnbindTx({ data }, dag)).toMatchObject({ status: 400, code: "unbind_signature_missing" });
  });

  test("no existing binding → 404 domain_not_found", () => {
    const { dag, data } = setup();
    dag.getDomainBinding = () => null;
    expect(bindSchema.verifyUnbindTx({ data }, dag)).toMatchObject({ status: 404, code: "domain_not_found" });
  });
});

// Silence unused-import lint on the personal-tip constant — referenced via
// in-line literals in some assertions, kept available for future expansion.
void PERSONAL_TIP;
void DOMAIN_VERIFICATION_METHODS;
