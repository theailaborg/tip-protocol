/**
 * @file tests/integration/domain-release.test.js
 * @description An owner gives a protected site up (POST /v1/domain/release),
 * and from the release activation UNBIND_DOMAIN commits only as the owner's
 * signed release (owner_revoked) or after the owner's TIP-ID is revoked
 * (tip_id_revoked); before it the original node-only rule replays.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// Gates are read once at module load. Restored afterwards: --runInBand shares
// process.env with every later test file.
const RELEASE_GATE = 1790000000000; // 2026-09-21: before every real now in these tests
const _envBefore = {
  TIP_WEBSITE_PROTECTION_ACTIVATION_MS: process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS,
  TIP_DOMAIN_RELEASE_ACTIVATION_MS: process.env.TIP_DOMAIN_RELEASE_ACTIVATION_MS,
};
process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = "1";
process.env.TIP_DOMAIN_RELEASE_ACTIVATION_MS = String(RELEASE_GATE);

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const {
  TIP_ID_TYPES, DOMAIN_HEALTHY_EXPIRY_MS, TX_TYPES, DOMAIN_UNBIND_REASONS, SIGNED_BY_KIND,
} = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const rules = require(path.join(SRC, "validators", "business-rules"));
const { createDomainService } = require(path.join(SRC, "services", "domain-service"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { withTxId } = require(path.join(SRC, "services", "helpers"));
const bindDomainSchema = require(path.join(SRC, "schemas", "bind-domain"));
const registerDomainSchema = require(path.join(SRC, "schemas", "register-domain"));
const { TX_SIGNATURE_REGISTRY } = require(path.join(SRC, "schemas", "_registry"));

beforeAll(async () => { await initCrypto(); });
afterAll(() => {
  for (const [k, v] of Object.entries(_envBefore)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";
const OWNER = "tip://id/US-aaaaaaaaaaaaaaaa";
const OTHER = "tip://id/US-bbbbbbbbbbbbbbbb";
const SITE = "myblog.example";

function seedIdentity(dag, tipId, kp) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", tip_id_type: TIP_ID_TYPES.PERSONAL, founding: false, status: "active",
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, 750, 0, 1767225600000);
}

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const submitted = [];
  const domainService = createDomainService({ dag, config, submitTx: (tx) => submitted.push(tx) });
  const handler = createCommitHandler({ dag, nodeId: NODE_ID });
  const keys = { owner: generateMLDSAKeypair(), other: generateMLDSAKeypair() };
  seedIdentity(dag, OWNER, keys.owner);
  seedIdentity(dag, OTHER, keys.other);
  bind(dag, SITE, OWNER);
  return { dag, nodeKp, domainService, handler, submitted, keys };
}

function bind(dag, domain, tipId, verifiedAt = nowMs()) {
  dag.saveDomainBinding({
    domain, tip_id: tipId, binding_state: "verified", method: "dns",
    claimed_at: verifiedAt - 1000, verified_at: verifiedAt,
    expires_at: verifiedAt + DOMAIN_HEALTHY_EXPIRY_MS, consecutive_failures: 0,
    node_id: NODE_ID, claim_signature: "00", binding_signature: "00", tx_id: `tx-${domain}`,
  });
}

function releaseBody({ tipId = OWNER, kp, domain = SITE, releasedAt = nowMs() }) {
  const payload = bindDomainSchema.buildReleaseSigningPayload({ domain, released_at: releasedAt, tip_id: tipId });
  return { domain, tip_id: tipId, released_at: releasedAt, signature: bindDomainSchema.signRelease(payload, kp.privateKey) };
}

// A node-emitted unbind as any active node could build it.
function nodeUnbind(fx, { reason, ts, extra = {} }) {
  const data = { domain: SITE, node_id: NODE_ID, reason, revoked_at: ts, ...extra };
  const signature = bindDomainSchema.signUnbind(bindDomainSchema.buildUnbindSigningPayload(data), fx.nodeKp.privateKey);
  return withTxId({ tx_type: TX_TYPES.UNBIND_DOMAIN, timestamp: ts, data, signature }, fx.dag);
}

const stateOf = (dag) => dag.getDomainBinding(SITE).binding_state;

describe("the owner releases a protected site", () => {
  test("release is proposed, commits, and the site is no longer protected", () => {
    const fx = setup();
    const out = fx.domainService.release(releaseBody({ kp: fx.keys.owner }));
    expect(out).toMatchObject({ domain: SITE, tip_id: OWNER, released: true, confirmation: "proposed" });
    const tx = fx.submitted[0];
    expect(tx.data).toMatchObject({ reason: DOMAIN_UNBIND_REASONS.OWNER_REVOKED, tip_id: OWNER });
    expect(tx.data.cosignatures).toEqual([expect.objectContaining({ signer_kind: SIGNED_BY_KIND.SUBJECT, signer_ref: OWNER })]);

    expect(fx.handler.commitOrderedTxs([tx], 10, { certTimestamp: nowMs() }).committed).toBe(1);
    expect(stateOf(fx.dag)).toBe("revoked");
    expect(rules.siteOwnerOf(fx.dag, `https://${SITE}/post`, nowMs())).toBeNull();
    expect(rules.canBindDomain(fx.dag, { tip_id: OTHER, domain: SITE, at_ms: nowMs() }).valid).toBe(true);
  });

  test("someone else cannot release it (403), even with their own valid signature", () => {
    const fx = setup();
    expect(() => fx.domainService.release(releaseBody({ tipId: OTHER, kp: fx.keys.other })))
      .toThrow(expect.objectContaining({ status: 403, code: "not_domain_owner" }));
  });

  test("the owner's TIP-ID with someone else's signature is refused (403)", () => {
    const fx = setup();
    expect(() => fx.domainService.release(releaseBody({ tipId: OWNER, kp: fx.keys.other })))
      .toThrow(expect.objectContaining({ status: 403 }));
    expect(fx.submitted).toHaveLength(0);
  });

  test("a release signed more than 15 minutes ago, or ahead of now, is refused (400)", () => {
    const fx = setup();
    for (const releasedAt of [nowMs() - 16 * 60_000, nowMs() + 5 * 60_000]) {
      expect(() => fx.domainService.release(releaseBody({ kp: fx.keys.owner, releasedAt })))
        .toThrow(expect.objectContaining({ status: 400, code: "release_stale" }));
    }
  });

  test("an unbound or already released site is 404", () => {
    const fx = setup();
    expect(() => fx.domainService.release(releaseBody({ kp: fx.keys.owner, domain: "unknown.example" })))
      .toThrow(expect.objectContaining({ status: 404 }));
    fx.domainService.release(releaseBody({ kp: fx.keys.owner }));
    fx.handler.commitOrderedTxs(fx.submitted.splice(0), 10, { certTimestamp: nowMs() });
    expect(() => fx.domainService.release(releaseBody({ kp: fx.keys.owner })))
      .toThrow(expect.objectContaining({ status: 404 }));
  });
});

describe("from the activation, only the owner or a revocation unbinds", () => {
  test("a node-only owner_revoked unbind (no owner signature) does not commit", () => {
    const fx = setup();
    const tx = nodeUnbind(fx, { reason: DOMAIN_UNBIND_REASONS.OWNER_REVOKED, ts: nowMs() });
    expect(fx.handler.commitOrderedTxs([tx], 10, { certTimestamp: nowMs() }).committed).toBe(0);
    expect(stateOf(fx.dag)).toBe("verified");
  });

  test("verification_lost and admin_action from a node do not commit", () => {
    for (const reason of [DOMAIN_UNBIND_REASONS.VERIFICATION_LOST, DOMAIN_UNBIND_REASONS.ADMIN_ACTION]) {
      const fx = setup();
      const tx = nodeUnbind(fx, { reason, ts: nowMs() });
      expect(fx.handler.commitOrderedTxs([tx], 10, { certTimestamp: nowMs() }).committed).toBe(0);
      expect(stateOf(fx.dag)).toBe("verified");
    }
  });

  test("tip_id_revoked commits only once the owner's TIP-ID is revoked", () => {
    const fx = setup();
    const early = nodeUnbind(fx, { reason: DOMAIN_UNBIND_REASONS.TIP_ID_REVOKED, ts: nowMs() });
    expect(fx.handler.commitOrderedTxs([early], 10, { certTimestamp: nowMs() }).committed).toBe(0);
    fx.dag.addRevocation(OWNER, "REVOKE_IDENTITY", nowMs(), "tx-revoke-owner");
    const after = nodeUnbind(fx, { reason: DOMAIN_UNBIND_REASONS.TIP_ID_REVOKED, ts: nowMs() + 1 });
    expect(fx.handler.commitOrderedTxs([after], 11, { certTimestamp: nowMs() }).committed).toBe(1);
    expect(stateOf(fx.dag)).toBe("revoked");
  });

  test("a tx backdated before the activation is still judged at the certificate's time", () => {
    const fx = setup();
    const tx = nodeUnbind(fx, { reason: DOMAIN_UNBIND_REASONS.OWNER_REVOKED, ts: RELEASE_GATE - 60_000 });
    expect(fx.handler.commitOrderedTxs([tx], 10, { certTimestamp: nowMs() }).committed).toBe(0);
    expect(stateOf(fx.dag)).toBe("verified");
  });

  test("control: the same backdated construction commits when the rule allows it (owner revoked)", () => {
    const fx = setup();
    fx.dag.addRevocation(OWNER, "REVOKE_IDENTITY", nowMs(), "tx-revoke-owner");
    const tx = nodeUnbind(fx, { reason: DOMAIN_UNBIND_REASONS.TIP_ID_REVOKED, ts: RELEASE_GATE - 60_000 });
    expect(fx.handler.commitOrderedTxs([tx], 10, { certTimestamp: nowMs() }).committed).toBe(1);
  });

  test("control: a hand-built fresh owner release commits", () => {
    const fx = setup();
    const releasedAt = nowMs();
    const body = releaseBody({ kp: fx.keys.owner, releasedAt });
    const tx = nodeUnbind(fx, {
      reason: DOMAIN_UNBIND_REASONS.OWNER_REVOKED, ts: releasedAt + 1000,
      extra: { tip_id: OWNER, released_at: releasedAt, cosignatures: [{ signer_kind: SIGNED_BY_KIND.SUBJECT, signer_ref: OWNER, signature: body.signature }] },
    });
    expect(fx.handler.commitOrderedTxs([tx], 10, { certTimestamp: nowMs() }).committed).toBe(1);
  });

  test("an old release replayed later does not commit", () => {
    const fx = setup();
    const releasedAt = nowMs() - 20 * 60_000;
    const body = releaseBody({ kp: fx.keys.owner, releasedAt });
    const tx = nodeUnbind(fx, {
      reason: DOMAIN_UNBIND_REASONS.OWNER_REVOKED, ts: releasedAt + 1000,
      extra: { tip_id: OWNER, released_at: releasedAt, cosignatures: [{ signer_kind: SIGNED_BY_KIND.SUBJECT, signer_ref: OWNER, signature: body.signature }] },
    });
    expect(fx.handler.commitOrderedTxs([tx], 10, { certTimestamp: nowMs() }).committed).toBe(0);
    expect(stateOf(fx.dag)).toBe("verified");
  });
});

describe("before the activation the original rule replays", () => {
  test("a node-only unbind stamped and certified before the activation commits", () => {
    const fx = setup();
    const ts = RELEASE_GATE - 120_000;
    const tx = nodeUnbind(fx, { reason: DOMAIN_UNBIND_REASONS.VERIFICATION_LOST, ts });
    expect(fx.handler.commitOrderedTxs([tx], 10, { certTimestamp: ts }).committed).toBe(1);
    expect(stateOf(fx.dag)).toBe("revoked");
  });
});

describe("signed bytes", () => {
  test("an unbind without the owner fields signs exactly the original four fields", () => {
    const data = { domain: SITE, node_id: NODE_ID, reason: "verification_lost", revoked_at: 1790000000000 };
    const expected = { domain: SITE, node_id: NODE_ID, reason: "verification_lost", revoked_at: 1790000000000 };
    expect(bindDomainSchema.buildUnbindSigningPayload(data)).toEqual(expected);
    expect(TX_SIGNATURE_REGISTRY[TX_TYPES.UNBIND_DOMAIN].buildSigningPayload(data)).toEqual(expected);
  });

  test("the owner fields are signed by the node when present, in the schema and the registry alike", () => {
    const data = { domain: SITE, node_id: NODE_ID, reason: "owner_revoked", revoked_at: 1790000000000, released_at: 1789999990000, tip_id: OWNER };
    expect(bindDomainSchema.buildUnbindSigningPayload(data)).toEqual(TX_SIGNATURE_REGISTRY[TX_TYPES.UNBIND_DOMAIN].buildSigningPayload(data));
    expect(bindDomainSchema.buildUnbindSigningPayload(data)).toMatchObject({ released_at: 1789999990000, tip_id: OWNER });
  });

  test("a release signature never verifies as a domain claim", () => {
    const kp = generateMLDSAKeypair();
    const release = bindDomainSchema.buildReleaseSigningPayload({ domain: SITE, released_at: 1790000000000, tip_id: OWNER });
    const sig = bindDomainSchema.signRelease(release, kp.privateKey);
    const claim = registerDomainSchema.buildSigningPayload({ claimed_at: 1790000000000, domain: SITE, method: "dns", tip_id: OWNER });
    expect(registerDomainSchema.verifySignature(claim, sig, kp.publicKey)).toBe(false);
    expect(release.action).toBe("domain_release");
  });
});
