/**
 * @file tests/integration/domain-binding.test.js
 * @description End-to-end domain binding through API → tx submission →
 * commit-handler replay. Exercises the full pipeline:
 *
 *   1. Happy path: org identity → POST /register (claim stored locally)
 *      → POST /verify (mock DNS) → BIND_DOMAIN tx → commit-handler
 *      applies binding to domain_bindings table.
 *   2. Personal TIP-IDs are rejected at register time.
 *   3. Pre-existing verified binding for a DIFFERENT tip_id → 409.
 *   4. Tampered claim signature → 403.
 *   5. Node verification failure (no TXT record) → 422.
 *   6. GET /v1/domain/:domain returns the committed binding.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256 } = require(path.join(SHARED, "crypto"));
const {
  TIP_ID_TYPES, DOMAIN_BINDING_STATUS, DOMAIN_HEALTHY_EXPIRY_MS,
} = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createDomainService } = require(path.join(SRC, "services", "domain-service"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const registerDomainSchema = require(path.join(SRC, "schemas", "register-domain"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";

// Stub verifier: simulates DNS / HTTP probe. Tests inject what the node
// "would have observed" so the integration stays hermetic (no real DNS).
function stubVerifier(outcome = "ok") {
  return {
    verify: jest.fn(async (method, domain, tipId) => {
      if (outcome === "ok") {
        return {
          verified: true, method, verified_at: Date.now(),
          evidence: { url: null, body: null, txt: [`tip-id=${tipId}`] },
          error: null,
        };
      }
      return {
        verified: false, method, verified_at: null,
        evidence: { url: null, body: null, txt: [] },
        error: { code: "dns_no_record", message: `no TXT records at _tip-protocol.${domain}` },
      };
    }),
  };
}

function setup({ verifier } = {}) {
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

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };

  const domainService = createDomainService({
    dag, config, submitTx,
    verifier: verifier || stubVerifier("ok"),
  });

  const commitHandler = createCommitHandler({ dag, nodeId: NODE_ID });

  // Commit submitted txs through the real commit-handler so derived state
  // (domain_bindings row) lands the same way it would in production.
  const commitSubmitted = (round = 1) =>
    commitHandler.commitOrderedTxs(submitted.splice(0, submitted.length), round, { certTimestamp: Date.now() });

  return { dag, domainService, submitted, commitSubmitted, nodeKp };
}

function seedOrgIdentity(dag, tipId, kp) {
  dag.saveIdentity({
    tip_id: tipId, region: "US",
    public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1",
    tip_id_type: TIP_ID_TYPES.ORGANIZATION,
    founding: false, status: "active",
    registered_at: 1767225600000,
    tx_id: shake256(`id:${tipId}`),
    creator_name: "Acme News",
  });
}

function seedPersonalIdentity(dag, tipId, kp) {
  dag.saveIdentity({
    tip_id: tipId, region: "US",
    public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1",
    tip_id_type: TIP_ID_TYPES.PERSONAL,
    founding: false, status: "active",
    registered_at: 1767225600000,
    tx_id: shake256(`id:${tipId}`),
    creator_name: "Some Person",
  });
}

function buildSignedClaim({ tipId, privKey, domain, method = "auto" }) {
  // Anchor `claimed_at` 60s in the past so it stays before the verifier
  // mock's `verified_at: Date.now()`. Real clients use the
  // current wall clock; a fixed future date here would trip tx-validator's
  // `verified_at must not precede claimed_at` check on slow CI hosts.
  const claimed_at = new Date(Date.now() - 60_000).toISOString();
  const payload = registerDomainSchema.buildSigningPayload({
    claimed_at, domain, method, tip_id: tipId,
  });
  const signature = registerDomainSchema.sign(payload, privKey);
  return { tip_id: tipId, domain, method, claimed_at, signature };
}

// ─── 1. Happy path ──────────────────────────────────────────────────────────

describe("domain binding happy path (register → verify → commit → get)", () => {
  test("BIND_DOMAIN tx commits and binding row is applied", async () => {
    const fx = setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("acme-org").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tipId, kp);

    const claim = buildSignedClaim({ tipId, privKey: kp.privateKey, domain: "acmenews.com" });
    const regOut = fx.domainService.register(claim);
    expect(regOut.status).toBe(DOMAIN_BINDING_STATUS.PENDING);
    expect(regOut.tip_id).toBe(tipId);

    const verifyOut = await fx.domainService.verify({ domain: "acmenews.com" });
    expect(verifyOut.verified).toBe(true);
    expect(verifyOut.confirmation).toBe("proposed");
    expect(verifyOut.tx_id).toBeDefined();

    // commit-handler applies the binding row
    const { committed } = fx.commitSubmitted();
    expect(committed).toBe(1);

    const binding = fx.dag.getDomainBinding("acmenews.com");
    expect(binding).toBeDefined();
    expect(binding.tip_id).toBe(tipId);
    expect(binding.binding_state).toBe(DOMAIN_BINDING_STATUS.VERIFIED);
    expect(binding.node_id).toBe(NODE_ID);
    expect(binding.claim_signature).toBe(claim.signature);
    expect(binding.binding_signature).toBeDefined();
    expect(binding.tx_id).toBe(verifyOut.tx_id);

    // Pending row deleted on commit.
    expect(fx.dag.getPendingDomainClaim("acmenews.com")).toBeNull();

    // GET surface returns the committed binding.
    const got = fx.domainService.get("AcmeNews.com");   // case-insensitive
    expect(got.status).toBe(DOMAIN_BINDING_STATUS.VERIFIED);
    expect(got.tip_id).toBe(tipId);
    expect(got.binding_signature).toBe(binding.binding_signature);
  });
});

// ─── 2. Org-only gate ───────────────────────────────────────────────────────

describe("personal TIP-IDs cannot bind domains", () => {
  test("register rejects with 403 tip_id_not_authorised", () => {
    const fx = setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("personal").slice(0, 16)}`;
    seedPersonalIdentity(fx.dag, tipId, kp);

    const claim = buildSignedClaim({ tipId, privKey: kp.privateKey, domain: "personal.example" });
    expect(() => fx.domainService.register(claim))
      .toThrow(expect.objectContaining({ status: 403, code: "tip_id_not_authorised" }));
  });
});

// ─── 3. domain_already_claimed (409) ────────────────────────────────────────

describe("domain already bound to a different TIP-ID", () => {
  test("second registration for a different tip_id is rejected with 409", async () => {
    const fx = setup();

    // First org owns the binding
    const kp1 = generateMLDSAKeypair();
    const tip1 = `tip://id/US-${shake256("acme1").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tip1, kp1);
    fx.domainService.register(buildSignedClaim({ tipId: tip1, privKey: kp1.privateKey, domain: "acmenews.com" }));
    await fx.domainService.verify({ domain: "acmenews.com" });
    fx.commitSubmitted();

    // Second org tries to claim the same domain
    const kp2 = generateMLDSAKeypair();
    const tip2 = `tip://id/US-${shake256("acme2").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tip2, kp2);
    expect(() => fx.domainService.register(buildSignedClaim({ tipId: tip2, privKey: kp2.privateKey, domain: "acmenews.com" })))
      .toThrow(expect.objectContaining({ status: 409, code: "domain_already_claimed" }));
  });

  test("verify() also enforces canBindDomain (race: domain taken between register and verify)", async () => {
    const fx = setup();

    // Second org registers a pending claim first.
    const kp2 = generateMLDSAKeypair();
    const tip2 = `tip://id/US-${shake256("race-b").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tip2, kp2);
    fx.domainService.register(buildSignedClaim({ tipId: tip2, privKey: kp2.privateKey, domain: "acmenews.com" }));

    // Simulate the race: BIND_DOMAIN for a DIFFERENT tip_id lands on the
    // DAG between register and verify. Use saveDomainBinding directly to
    // mimic a tx that committed via another path.
    fx.dag.saveDomainBinding({
      domain: "acmenews.com",
      tip_id: `tip://id/US-${shake256("race-a").slice(0, 16)}`,
      binding_state: "verified",
      method: "http",
      claimed_at: 1778576400000,
      verified_at: 1778576401000,
      node_id: NODE_ID,
      claim_signature: "00".repeat(8),
      binding_signature: "00".repeat(8),
      tx_id: shake256("race-tx"),
    });

    // verify() must now fail fast with 409, NOT silently sign a tx
    // commit-handler would drop.
    await expect(fx.domainService.verify({ domain: "acmenews.com" }))
      .rejects.toMatchObject({ status: 409, code: "domain_already_claimed" });
    expect(fx.submitted.length).toBe(0);
  });
});

// ─── 4. Tampered claim signature ────────────────────────────────────────────

describe("tampered claim signature", () => {
  test("register rejects with 403 signature_invalid when signature doesn't match payload", () => {
    const fx = setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("acme-tamper").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tipId, kp);

    const claim = buildSignedClaim({ tipId, privKey: kp.privateKey, domain: "acmenews.com" });
    // Mutate the domain — signature now mismatches the canonical payload
    claim.domain = "evil.com";
    expect(() => fx.domainService.register(claim))
      .toThrow(expect.objectContaining({ status: 403, code: "signature_invalid" }));
  });

  test("register rejects when signed by a different key", () => {
    const fx = setup();
    const kp = generateMLDSAKeypair();
    const foreign = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("acme-foreign").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tipId, kp);

    // Sign with foreign key — the DAG identity carries kp.publicKey, so verify fails
    const claim = buildSignedClaim({ tipId, privKey: foreign.privateKey, domain: "acmenews.com" });
    expect(() => fx.domainService.register(claim))
      .toThrow(expect.objectContaining({ status: 403, code: "signature_invalid" }));
  });
});

// ─── 5. Node verification failure ───────────────────────────────────────────

describe("node verification fails", () => {
  test("verify returns 422 with the verifier's error code", async () => {
    const fx = setup({ verifier: stubVerifier("fail") });
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("acme-fail").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tipId, kp);

    fx.domainService.register(buildSignedClaim({ tipId, privKey: kp.privateKey, domain: "acmenews.com" }));
    await expect(fx.domainService.verify({ domain: "acmenews.com" }))
      .rejects.toMatchObject({ status: 422, code: "dns_no_record" });

    // No BIND_DOMAIN tx submitted
    expect(fx.submitted.length).toBe(0);
  });
});

// ─── 6. verify without a pending claim ──────────────────────────────────────

describe("verify without a registered claim", () => {
  test("returns 400 not_registered", async () => {
    const fx = setup();
    await expect(fx.domainService.verify({ domain: "acmenews.com" }))
      .rejects.toMatchObject({ status: 400, code: "not_registered" });
  });
});

// ─── 7. GET for unknown domain ──────────────────────────────────────────────

describe("GET for unknown domain", () => {
  test("returns 404 domain_not_found", () => {
    const fx = setup();
    expect(() => fx.domainService.get("nothing.example"))
      .toThrow(expect.objectContaining({ status: 404, code: "domain_not_found" }));
  });

  test("returns pending row when /register fired but /verify hasn't", () => {
    const fx = setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("acme-pending").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tipId, kp);

    fx.domainService.register(buildSignedClaim({ tipId, privKey: kp.privateKey, domain: "acmenews.com" }));
    const got = fx.domainService.get("acmenews.com");
    expect(got.status).toBe(DOMAIN_BINDING_STATUS.PENDING);
    expect(got.tip_id).toBe(tipId);
  });
});

// ─── 8. Renewal prep (v2 canonical-state slots + read-time expiry) ──────────
//
// The renewal scheduler / RENEW_DOMAIN tx are deferred to a follow-up, but
// the canonical-state slots and the read-time "expired" derivation land
// now so consumers and the future scheduler share a single API surface.
// These tests pin the contract so v2 doesn't have to renegotiate it.

describe("v2 prep — expires_at, consecutive_failures, read-time expiry", () => {
  test("BIND_DOMAIN commit sets expires_at = verified_at + DOMAIN_HEALTHY_EXPIRY_MS and consecutive_failures = 0", async () => {
    const fx = setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("acme-expiry").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tipId, kp);

    fx.domainService.register(buildSignedClaim({ tipId, privKey: kp.privateKey, domain: "acmenews.com" }));
    const verifyOut = await fx.domainService.verify({ domain: "acmenews.com" });
    fx.commitSubmitted();

    const binding = fx.dag.getDomainBinding("acmenews.com");
    expect(binding.expires_at).toBeDefined();
    expect(binding.consecutive_failures).toBe(0);

    const expectedExpiryMs = Date.parse(verifyOut.verified_at) + DOMAIN_HEALTHY_EXPIRY_MS;
    expect(Date.parse(binding.expires_at)).toBe(expectedExpiryMs);
  });

  test("GET /v1/domain/:domain surfaces expires_at, days_until_expiry, consecutive_failures", async () => {
    const fx = setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("acme-get-expiry").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tipId, kp);

    fx.domainService.register(buildSignedClaim({ tipId, privKey: kp.privateKey, domain: "acmenews.com" }));
    await fx.domainService.verify({ domain: "acmenews.com" });
    fx.commitSubmitted();

    const got = fx.domainService.get("acmenews.com");
    expect(got.expires_at).toBeDefined();
    expect(got.consecutive_failures).toBe(0);
    expect(got.days_until_expiry).toBeGreaterThan(28);
    expect(got.days_until_expiry).toBeLessThanOrEqual(30);
    expect(got.status).toBe(DOMAIN_BINDING_STATUS.VERIFIED);
  });

  test("status derives to 'unverified' once now > expires_at (cert-expiry safety net)", async () => {
    const fx = setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("acme-expired").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tipId, kp);

    fx.domainService.register(buildSignedClaim({ tipId, privKey: kp.privateKey, domain: "acmenews.com" }));
    await fx.domainService.verify({ domain: "acmenews.com" });
    fx.commitSubmitted();

    // Backdate the binding so expires_at is in the past — same effect as if
    // the v2 scheduler had not renewed for 31+ days.
    const current = fx.dag.getDomainBinding("acmenews.com");
    fx.dag.saveDomainBinding({
      ...current,
      expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    });

    const got = fx.domainService.get("acmenews.com");
    expect(got.status).toBe(DOMAIN_BINDING_STATUS.UNVERIFIED);
    expect(got.days_until_expiry).toBeLessThanOrEqual(0);
    // Canonical row stays — historical signatures remain verifiable;
    // only the derived status flips.
    expect(fx.dag.getDomainBinding("acmenews.com")).not.toBeNull();
  });

  test("canonical state includes expires_at + consecutive_failures (state_merkle_root determinism)", async () => {
    const fx = setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("acme-canon").slice(0, 16)}`;
    seedOrgIdentity(fx.dag, tipId, kp);

    fx.domainService.register(buildSignedClaim({ tipId, privKey: kp.privateKey, domain: "acmenews.com" }));
    await fx.domainService.verify({ domain: "acmenews.com" });
    fx.commitSubmitted();

    let domainRow = null;
    for (const entry of fx.dag.iterateCanonicalState()) {
      if (entry.table === "domain_bindings" && entry.row.domain === "acmenews.com") {
        domainRow = entry.row;
        break;
      }
    }
    expect(domainRow).not.toBeNull();
    expect(domainRow).toHaveProperty("expires_at");
    expect(domainRow).toHaveProperty("consecutive_failures", 0);
  });
});
