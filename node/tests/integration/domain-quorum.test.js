/**
 * @file tests/integration/domain-quorum.test.js
 * @description From the quorum activation a BIND_DOMAIN is one node's attestation:
 * a binding or its renewal applies only once ceil(2n/3) of the committee have each
 * checked the owner's proof within an hour. Before it, one node's BIND_DOMAIN binds
 * as it always did.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// Gates are read once at module load; restored afterwards (--runInBand shares process.env).
const QGATE = 1790000000000; // 2026-09-21, before every real now in these tests
const _envBefore = {
  TIP_WEBSITE_PROTECTION_ACTIVATION_MS: process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS,
  TIP_DOMAIN_QUORUM_ACTIVATION_MS: process.env.TIP_DOMAIN_QUORUM_ACTIVATION_MS,
};
process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = "1";
process.env.TIP_DOMAIN_QUORUM_ACTIVATION_MS = String(QGATE);

const path = require("path");
const fs = require("fs");
const os = require("os");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TIP_ID_TYPES, DOMAIN_HEALTHY_EXPIRY_MS, TX_TYPES, SIGNED_BY_KIND, DOMAIN_QUORUM } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createDomainService } = require(path.join(SRC, "services", "domain-service"));
const { createCoAttest } = require(path.join(SRC, "domain", "co-attest"));
const { withTxId } = require(path.join(SRC, "services", "helpers"));
const bindDomainSchema = require(path.join(SRC, "schemas", "bind-domain"));
const registerDomainSchema = require(path.join(SRC, "schemas", "register-domain"));
const { verifyStateRootConsistency, computeStateMerkleRootPerTable } = require(path.join(SRC, "consensus", "state-root"));

let tmpDir;
beforeAll(async () => {
  await initCrypto();
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-domain-quorum-"));
});
afterAll(() => {
  for (const [k, v] of Object.entries(_envBefore)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
});

const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;
const VP_ID = "tip://vp/v1";
const NODES = ["tip://node/q1", "tip://node/q2", "tip://node/q3", "tip://node/q4", "tip://node/q5"];
const OUTSIDER = "tip://node/q6";
const OWNER = "tip://id/US-aaaaaaaaaaaaaaaa";
const OTHER = "tip://id/US-bbbbbbbbbbbbbbbb";
const SITE = "quorum-site.example";
let dbSeq = 0;

function seedIdentity(dag, tipId, kp) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", tip_id_type: TIP_ID_TYPES.PERSONAL, founding: false, status: "active",
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, 750, 0, 1767225600000);
}

function setup({ committee = 5, store = "memory", keys: shared } = {}) {
  const dag = store === "memory" ? initDAG({ dbPath: ":memory:" }) : initDAG({ dbPath: path.join(tmpDir, `q-${dbSeq++}.db`) });
  const keys = shared || Object.fromEntries([...NODES, OUTSIDER, OWNER, OTHER].map(id => [id, generateMLDSAKeypair()]));
  for (const id of [...NODES, OUTSIDER]) {
    dag.saveNode({ node_id: id, name: id.slice(-2), public_key: keys[id].publicKey, status: "active", registered_at: 1767225600000 });
  }
  dag.saveCommitteeRotation({ rotation_number: 0, effective_round: 0, committee: NODES.slice(0, committee).map(node_id => ({ node_id })) });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  seedIdentity(dag, OWNER, keys[OWNER]);
  seedIdentity(dag, OTHER, keys[OTHER]);
  const handler = createCommitHandler({ dag, nodeId: NODES[0] });
  let round = 10;
  const commit = (txs, cert) => handler.commitOrderedTxs(txs.map(t => ({ ...t })), round++, { certTimestamp: cert });
  return { dag, keys, handler, commit };
}

function claimOf(fx, { tipId = OWNER, claimedAt }) {
  const payload = registerDomainSchema.buildSigningPayload({ claimed_at: claimedAt, domain: SITE, method: "dns", tip_id: tipId });
  return { tip_id: tipId, claimed_at: claimedAt, signature: registerDomainSchema.sign(payload, fx.keys[tipId].privateKey) };
}

// One node's BIND_DOMAIN (its attestation) around a claim.
function attest(fx, nodeId, claim, verifiedAt) {
  const canon = bindDomainSchema.buildSigningPayload({
    binding_state: "verified", claimed_at: claim.claimed_at, claimed_method: "dns", domain: SITE,
    method: "dns", node_id: nodeId, tip_id: claim.tip_id, verified_at: verifiedAt,
  });
  const data = {
    ...canon,
    cosignatures: [{ signer_kind: SIGNED_BY_KIND.SUBJECT, signer_ref: claim.tip_id, signature: claim.signature }],
    evidence: { url: null, body: null, txt: [`tip-id=${claim.tip_id}`] },
  };
  return withTxId({ tx_type: TX_TYPES.BIND_DOMAIN, timestamp: verifiedAt, data, signature: bindDomainSchema.sign(canon, fx.keys[nodeId].privateKey) }, fx.dag);
}

const binding = (fx) => fx.dag.getDomainBinding(SITE);

describe("before the quorum activation", () => {
  test("one node's BIND_DOMAIN binds at once and records no attestation (unchanged rule)", () => {
    const fx = setup();
    const t = QGATE - 5 * DAY;
    const claim = claimOf(fx, { claimedAt: t - MIN });
    expect(fx.commit([attest(fx, NODES[0], claim, t)], t + 1000).committed).toBe(1);
    expect(binding(fx)).toEqual(expect.objectContaining({ tip_id: OWNER, binding_state: "verified", verified_at: t, node_id: NODES[0] }));
    expect(fx.dag.listDomainAttestations(SITE)).toEqual([]);
  });
});

describe("after the quorum activation (committee of 5, quorum 4)", () => {
  test("three committee checks leave the site unbound; the fourth binds it from the earliest check", () => {
    const fx = setup();
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    for (const [i, id] of NODES.slice(0, 3).entries()) {
      expect(fx.commit([attest(fx, id, claim, now - 60000 + i * 1000)], now).committed).toBe(1);
      expect(binding(fx)).toBeNull();
    }
    expect(bindDomainSchema.attestationQuorum(fx.dag, { domain: SITE, ...claim }, now, 20)).toEqual(expect.objectContaining({ have: 3, need: 4 }));
    expect(fx.commit([attest(fx, NODES[3], claim, now - 30000)], now).committed).toBe(1);
    expect(binding(fx)).toEqual(expect.objectContaining({
      tip_id: OWNER, binding_state: "verified", verified_at: now - 60000, expires_at: now - 60000 + DOMAIN_HEALTHY_EXPIRY_MS, node_id: NODES[3],
    }));
  });

  test("a fifth check after the quorum changes nothing", () => {
    const fx = setup();
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    expect(fx.commit(NODES.slice(0, 4).map((id, i) => attest(fx, id, claim, now - 50000 + i)), now).committed).toBe(4);
    const before = binding(fx);
    expect(fx.commit([attest(fx, NODES[4], claim, now - 1000)], now).committed).toBe(1);
    expect(binding(fx)).toEqual(before);
  });

  test("a node outside the committee may attest but is not counted", () => {
    const fx = setup();
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    expect(fx.commit([...NODES.slice(0, 3), OUTSIDER].map((id, i) => attest(fx, id, claim, now - 50000 + i)), now).committed).toBe(4);
    expect(binding(fx)).toBeNull();
    expect(fx.commit([attest(fx, NODES[3], claim, now - 1000)], now).committed).toBe(1);
    expect(binding(fx).tip_id).toBe(OWNER);
  });

  test("checks for different claims do not add up", () => {
    const fx = setup();
    const now = nowMs();
    const a = claimOf(fx, { claimedAt: now - 3 * MIN });
    const b = claimOf(fx, { claimedAt: now - 2 * MIN });
    expect(fx.commit([attest(fx, NODES[0], a, now - 9000), attest(fx, NODES[1], a, now - 8000), attest(fx, NODES[2], b, now - 7000), attest(fx, NODES[3], b, now - 6000)], now).committed).toBe(4);
    expect(binding(fx)).toBeNull();
  });

  test("a node attests a claim once per window; a stale or future check is refused", () => {
    const fx = setup();
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    expect(fx.commit([attest(fx, NODES[0], claim, now - 50000)], now).committed).toBe(1);
    const again = attest(fx, NODES[0], claim, now - 1000);
    expect(bindDomainSchema.verifyTx(again, fx.dag, { atMs: now, certMs: now })).toEqual(expect.objectContaining({ ok: false, code: "attestation_duplicate" }));
    expect(fx.commit([again], now).committed).toBe(0);

    const stale = attest(fx, NODES[1], claim, now - DOMAIN_QUORUM.WINDOW_MS - 1000);
    expect(bindDomainSchema.verifyTx(stale, fx.dag, { atMs: now, certMs: now })).toEqual(expect.objectContaining({ ok: false, code: "attestation_stale" }));
    expect(fx.commit([stale], now).committed).toBe(0);

    // A node's own clock cannot stretch the window: it is measured from the certificate time.
    const ahead = attest(fx, NODES[2], claim, now + 2 * MIN);
    expect(bindDomainSchema.verifyTx(ahead, fx.dag, { atMs: now + 2 * MIN, certMs: now })).toEqual(expect.objectContaining({ ok: false, code: "attestation_ahead" }));
    expect(fx.commit([ahead], now).committed).toBe(0);
    expect(fx.dag.listDomainAttestations(SITE).map(r => r.node_id)).toEqual([NODES[0]]);
  });

  test("several nodes attest in one batch, each once", () => {
    const fx = setup();
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    expect(fx.commit([attest(fx, NODES[0], claim, now - 9000), attest(fx, NODES[0], claim, now - 8000), attest(fx, NODES[1], claim, now - 7000)], now).committed).toBe(2);
    expect(fx.dag.listDomainAttestations(SITE).map(r => r.node_id).sort()).toEqual([NODES[0], NODES[1]]);
  });

  test("checks older than an hour no longer count toward a new quorum", () => {
    const fx = setup();
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 3 * DOMAIN_QUORUM.WINDOW_MS });
    const early = now - 2 * DOMAIN_QUORUM.WINDOW_MS;
    expect(fx.commit(NODES.slice(0, 3).map((id, i) => attest(fx, id, claim, early + i)), early + 1000).committed).toBe(3);
    expect(fx.commit([attest(fx, NODES[3], claim, now - 1000)], now).committed).toBe(1);
    expect(binding(fx)).toBeNull();
  });

  test("a renewal needs the quorum too: one check does not extend the expiry", () => {
    const fx = setup();
    const now = nowMs();
    const t0 = now - 25 * DAY;
    const claim = claimOf(fx, { claimedAt: t0 - MIN });
    expect(fx.commit(NODES.slice(0, 4).map((id, i) => attest(fx, id, claim, t0 + i)), t0 + 1000).committed).toBe(4);
    expect(binding(fx).verified_at).toBe(t0);

    expect(fx.commit([attest(fx, NODES[0], claim, now - 5000)], now).committed).toBe(1);
    expect(binding(fx).expires_at).toBe(t0 + DOMAIN_HEALTHY_EXPIRY_MS);

    expect(fx.commit(NODES.slice(1, 4).map((id, i) => attest(fx, id, claim, now - 4000 + i)), now).committed).toBe(3);
    expect(binding(fx)).toEqual(expect.objectContaining({ verified_at: now - 5000, expires_at: now - 5000 + DOMAIN_HEALTHY_EXPIRY_MS }));
  });

  test("a live binding to someone else still refuses another claimant's checks", () => {
    const fx = setup();
    const now = nowMs();
    const mine = claimOf(fx, { claimedAt: now - 3 * MIN });
    expect(fx.commit(NODES.slice(0, 4).map((id, i) => attest(fx, id, mine, now - 9000 + i)), now).committed).toBe(4);
    const theirs = claimOf(fx, { tipId: OTHER, claimedAt: now - 2 * MIN });
    expect(fx.commit([attest(fx, NODES[4], theirs, now - 1000)], now).committed).toBe(0);
    expect(binding(fx).tip_id).toBe(OWNER);
  });

  test("a committee of 3 needs 2", () => {
    const fx = setup({ committee: 3 });
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    expect(fx.commit([attest(fx, NODES[0], claim, now - 9000)], now).committed).toBe(1);
    expect(binding(fx)).toBeNull();
    expect(fx.commit([attest(fx, NODES[1], claim, now - 8000)], now).committed).toBe(1);
    expect(binding(fx).tip_id).toBe(OWNER);
  });
});

describe("state", () => {
  test("memory and SQLite stores commit the same attestations to the same binding and sub-root", () => {
    const keys = Object.fromEntries([...NODES, OUTSIDER, OWNER, OTHER].map(id => [id, generateMLDSAKeypair()]));
    const now = nowMs();
    const fxs = { memory: setup({ store: "memory", keys }), sqlite: setup({ store: "sqlite", keys }) };
    const claim = claimOf(fxs.memory, { claimedAt: now - 2 * MIN });
    const txs = NODES.slice(0, 4).map((id, i) => attest(fxs.memory, id, claim, now - 9000 + i));
    const out = {};
    for (const [name, fx] of Object.entries(fxs)) {
      expect(fx.commit(txs.slice(0, 2), now).committed).toBe(2);
      expect(fx.commit(txs.slice(2), now).committed).toBe(2);
      expect(verifyStateRootConsistency(fx.dag).consistent).toBe(true);
      const sub = computeStateMerkleRootPerTable(fx.dag);
      out[name] = { att: sub.find(t => t.table === "domain_attestations"), bind: sub.find(t => t.table === "domain_bindings"), b: binding(fx) };
    }
    expect(out.memory.att.count).toBe(4);
    expect(out.sqlite).toEqual(out.memory);
  });
});

describe("API", () => {
  test("the lookup shows a pending claim's checks, the same on every node", () => {
    const fx = setup();
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    expect(fx.commit(NODES.slice(0, 2).map((id, i) => attest(fx, id, claim, now - 9000 + i)), now).committed).toBe(2);
    const svc = createDomainService({ dag: fx.dag, config: {}, submitTx: () => {} });
    expect(svc.get(SITE)).toEqual(expect.objectContaining({
      status: "pending_verification", tip_id: OWNER, attestations: expect.objectContaining({ have: 2, need: 4, nodes: [NODES[0], NODES[1]] }),
    }));
  });
});

describe("co-attest", () => {
  function coFx({ verified = true, self = NODES[1] } = {}) {
    const fx = setup();
    const submitted = [];
    const calls = [];
    const verifier = { verify: async (method, domain, tipId) => { calls.push(method); return verified
      ? { verified: true, method: "dns", verified_at: nowMs(), evidence: { url: null, body: null, txt: [`tip-id=${tipId}`] }, error: null }
      : { verified: false, method: null, verified_at: nowMs(), evidence: null, error: { code: "dns_no_match", message: "no record" } }; } };
    const timers = [];
    const co = createCoAttest({
      dag: fx.dag, config: { nodeId: self, nodeRegisteredId: self, nodePrivateKey: fx.keys[self].privateKey },
      submitTx: (tx) => submitted.push(tx), verifier, log: { info() {}, warn() {} },
      setTimer: (fn, ms) => { const t = { fn, ms, unref() {} }; timers.push(t); return t; }, clearTimer: () => {},
    });
    return { ...fx, co, submitted, calls, timers };
  }

  test("after another node's attestation, this node checks the proof and attests the same claim", async () => {
    const fx = coFx();
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    const first = attest(fx, NODES[0], claim, now - 5000);
    expect(fx.commit([first], now).committed).toBe(1);
    fx.co.enqueue(first.tx_id);
    await fx.co.idle();
    expect(fx.calls).toEqual(["auto"]);
    expect(fx.submitted).toHaveLength(1);
    expect(fx.submitted[0].data).toEqual(expect.objectContaining({ node_id: NODES[1], tip_id: OWNER, claimed_at: claim.claimed_at, claimed_method: "dns", domain: SITE }));
    expect(fx.commit(fx.submitted, nowMs()).committed).toBe(1);
    expect(fx.dag.listDomainAttestations(SITE)).toHaveLength(2);
  });

  test("it does nothing once this node attested, the site is bound, or this node is outside the committee", async () => {
    const now = nowMs();
    const a = coFx();
    const claim = claimOf(a, { claimedAt: now - 2 * MIN });
    const mine = attest(a, NODES[1], claim, now - 5000);
    expect(a.commit([mine], now).committed).toBe(1);
    expect(await a.co.check({ domain: SITE, tip_id: OWNER, claimed_at: claim.claimed_at, method: "dns", signature: claim.signature, first_at: now - 5000 })).toBe("attested");

    const b = coFx({ self: OUTSIDER });
    const claimB = claimOf(b, { claimedAt: now - 2 * MIN });
    const first = attest(b, NODES[0], claimB, now - 5000);
    expect(b.commit([first], now).committed).toBe(1);
    b.co.enqueue(first.tx_id);
    await b.co.idle();
    expect(b.submitted).toEqual([]);
    expect(b.calls).toEqual([]);
  });

  test("when this node cannot see the proof it retries within the hour, then gives up", async () => {
    const fx = coFx({ verified: false });
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    const c = { domain: SITE, tip_id: OWNER, claimed_at: claim.claimed_at, method: "dns", signature: claim.signature, first_at: now - 5000 };
    expect(fx.commit([attest(fx, NODES[0], claim, now - 5000)], now).committed).toBe(1);
    expect(await fx.co.check(c, 0)).toBe("retry");
    expect(fx.timers.map(t => t.ms)).toEqual([DOMAIN_QUORUM.RETRY_DELAYS_MS[0]]);
    expect(await fx.co.check(c, DOMAIN_QUORUM.RETRY_DELAYS_MS.length)).toBe("not_seen");
    expect(fx.submitted).toEqual([]);
  });

  test("reconcile picks up a claim still open in the window", async () => {
    const fx = coFx();
    const now = nowMs();
    const claim = claimOf(fx, { claimedAt: now - 2 * MIN });
    expect(fx.commit([attest(fx, NODES[0], claim, now - 5000)], now).committed).toBe(1);
    expect(fx.co.reconcile()).toBe(1);
    await fx.co.idle();
    expect(fx.submitted).toHaveLength(1);
  });
});
