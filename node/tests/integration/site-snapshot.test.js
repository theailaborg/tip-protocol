/**
 * @file tests/integration/site-snapshot.test.js
 * @description SITE_SNAPSHOT end to end: the frozen signed payload, the API
 * (POST /v1/site/snapshot and the reads), and the commit rules (owner or org
 * member, chain, rate, activation, witness), on the memory and SQLite stores.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// Gates are read once at module load. Restored afterwards: --runInBand shares
// process.env with every later test file.
const GATE = 1790000000000; // 2026-09-21: before every real now in these tests
const _envBefore = {
  TIP_WEBSITE_PROTECTION_ACTIVATION_MS: process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS,
  TIP_SITE_SNAPSHOT_ACTIVATION_MS: process.env.TIP_SITE_SNAPSHOT_ACTIVATION_MS,
};
process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = "1";
process.env.TIP_SITE_SNAPSHOT_ACTIVATION_MS = String(GATE);

const fs = require("fs");
const os = require("os");
const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const {
  TIP_ID_TYPES, DOMAIN_HEALTHY_EXPIRY_MS, TX_TYPES, SIGNED_BY_KIND, SITE_SNAPSHOT, TX_REJECTION_REASON,
} = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { verifyStateRootConsistency, computeStateMerkleRootPerTable } = require(path.join(SRC, "consensus", "state-root"));
const { withTxId } = require(path.join(SRC, "services", "helpers"));
const { createSiteService } = require(path.join(SRC, "services", "site-service"));
const { payloadHashHex } = require(path.join(SRC, "schemas", "_common"));
const schema = require(path.join(SRC, "schemas", "site-snapshot"));
const siteRoutes = require(path.join(SRC, "routes", "site"));
const { errorHandler } = require(path.join(SRC, "middleware", "error-handler"));
const express = require("express");
const request = require("supertest");

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "site-snapshot-"));
const opened = [];

beforeAll(async () => { await initCrypto(); });
afterAll(() => {
  for (const d of opened) { try { d.close?.(); } catch { /* already closed */ } }
  fs.rmSync(tmpDir, { recursive: true, force: true });
  for (const [k, v] of Object.entries(_envBefore)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

const VP_ID = "tip://vp/US-0e7db4040667073a";
const NODE_ID = "tip://node/n1";
const OWNER = "tip://id/US-aaaaaaaaaaaaaaaa";
const OTHER = "tip://id/US-bbbbbbbbbbbbbbbb";
const ORG = "tip://id/GB-cccccccccccccccc";
const MEMBER = "tip://id/IN-dddddddddddddddd";
const SITE = "myblog.example";
const ORG_SITE = "press.example";
const MIN = 60 * 1000;
const hex = (c) => c.repeat(64);

let dbSeq = 0;
const STORES = [
  ["memory", () => initDAG({ dbPath: ":memory:" })],
  ["sqlite", () => initDAG({ dbPath: path.join(tmpDir, `s-${dbSeq++}.db`) })],
];

function seedIdentity(dag, tipId, kp, type = TIP_ID_TYPES.PERSONAL) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", tip_id_type: type, founding: false, status: "active",
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, 750, 0, 1767225600000);
}

function bind(dag, domain, tipId, { verifiedAt = nowMs(), expiresAt } = {}) {
  dag.saveDomainBinding({
    domain, tip_id: tipId, binding_state: "verified", method: "dns",
    claimed_at: verifiedAt - 1000, verified_at: verifiedAt,
    expires_at: expiresAt ?? verifiedAt + DOMAIN_HEALTHY_EXPIRY_MS, consecutive_failures: 0,
    node_id: NODE_ID, claim_signature: "00", binding_signature: "00", tx_id: `tx-${domain}`,
  });
}

function makeKeys() {
  return {
    owner: generateMLDSAKeypair(), other: generateMLDSAKeypair(),
    org: generateMLDSAKeypair(), member: generateMLDSAKeypair(), vp: generateMLDSAKeypair(),
  };
}

function setup(makeDag = STORES[0][1], keys = makeKeys()) {
  const dag = makeDag();
  opened.push(dag);
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: generateMLDSAKeypair().publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: keys.vp.publicKey, status: "active", registered_at: 1767225600000 });
  seedIdentity(dag, OWNER, keys.owner);
  seedIdentity(dag, OTHER, keys.other);
  seedIdentity(dag, ORG, keys.org, TIP_ID_TYPES.ORGANIZATION);
  seedIdentity(dag, MEMBER, keys.member);
  dag.saveOrgMember({
    invite_tx_id: hex("7"), org_tip_id: ORG, member_tip_id: MEMBER, role: "author", status: "active",
    invited_at: 1767225600000, accepted_at: 1767225600001, add_tx_id: hex("8"),
    removed_at: null, remove_tx_id: null, removed_by: null,
  });
  bind(dag, SITE, OWNER);
  bind(dag, ORG_SITE, ORG);
  const submitted = [];
  const siteService = createSiteService({ dag, submitTx: (tx) => submitted.push(tx), websitePages: null });
  const handler = createCommitHandler({ dag, nodeId: NODE_ID });
  return { dag, keys, submitted, siteService, handler };
}

function payload(over = {}) {
  return schema.buildSigningPayload({
    domain: SITE, seq: 1, prev_snapshot_tx: null, root: hex("a"), page_count: 30,
    template_hash: hex("b"), profile: "cf-web-1", wacz_hash: hex("c"), pack_hash: hex("d"),
    ai_signals_hash: hex("e"), captured_at: nowMs() - 60 * MIN, signer_tip_id: OWNER, ...over,
  });
}

const witnessFor = (kp, p, vpId = VP_ID) => ({ vp_id: vpId, signature: schema.sign(p, kp.privateKey) });
const bodyFor = (kp, p, witness) => ({ ...p, signature: schema.sign(p, kp.privateKey), ...(witness ? { witness } : {}) });

// A SITE_SNAPSHOT as any node could relay it; `data` overrides the tx data.
function snapshotTx(fx, p, kp, { ts = nowMs(), witness = null, data = null } = {}) {
  return withTxId({
    tx_type: TX_TYPES.SITE_SNAPSHOT, timestamp: ts,
    data: data || schema.buildTxData(p, witness), signature: schema.sign(p, kp.privateKey),
  }, fx.dag);
}

let round = 10;
function commit(fx, txs, cert = nowMs()) {
  return fx.handler.commitOrderedTxs(txs, round++, { certTimestamp: cert });
}

const reasonOf = (fx, tx) => fx.dag.getTxRejection(tx.tx_id)?.reason;
const detailOf = (fx, tx) => fx.dag.getTxRejection(tx.tx_id)?.reason_detail || "";

function expectRefused(fn, status, code) {
  let err;
  try { fn(); } catch (e) { err = e; }
  expect(err).toEqual(expect.objectContaining({ status, code }));
}

async function expectRefusedAsync(promise, status, code) {
  await expect(promise).rejects.toEqual(expect.objectContaining({ status, code }));
}

// ════════════════════════════════════════════════════════════════════════════

describe("signed payload", () => {
  const FIXED = {
    domain: "theailab.org", seq: 2, prev_snapshot_tx: hex("1"), root: "15bb6f0d2d36256e0250b92e318c00f6098538002974be2ee62abafe68d01f8c",
    page_count: 30, template_hash: "b833d6114baaedd115ae77ea80b81032a3d67e2d34ece8549a720aa174ade8d4", profile: "cf-web-1",
    wacz_hash: "d43aae7ab28d9f1ad671c35e807bc918acd99e2c82fa2bb999337e1cc43c0f8d", pack_hash: hex("d"),
    ai_signals_hash: hex("e"), captured_at: 1794672650000, signer_tip_id: OWNER,
  };

  test("is exactly the 12 fields, and its hash is frozen", () => {
    const p = schema.buildSigningPayload({ ...FIXED, witness_vp_id: VP_ID, cosignatures: [], extra: 1 });
    expect(Object.keys(p).sort()).toEqual([
      "ai_signals_hash", "captured_at", "domain", "pack_hash", "page_count", "prev_snapshot_tx",
      "profile", "root", "seq", "signer_tip_id", "template_hash", "wacz_hash",
    ]);
    expect(payloadHashHex(p)).toBe("c58a8ae4111af8065b5932831b5d4b2521c3f7a52402b6532e3938b191d170e6");
    expect(schema.buildSigningPayload({ ...FIXED, seq: 1, prev_snapshot_tx: null }).prev_snapshot_tx).toBeNull();
  });

  test.each([
    ["www domain", { domain: "www.theailab.org" }, "domain_not_canonical"],
    ["upper-case domain", { domain: "TheAILab.org" }, "domain_invalid"],
    ["seq 0", { seq: 0 }, "seq_invalid"],
    ["seq 1 with a prev", { seq: 1 }, "prev_snapshot_tx_invalid"],
    ["seq 2 without a prev", { prev_snapshot_tx: null }, "prev_snapshot_tx_invalid"],
    ["upper-case root", { root: hex("A") }, "root_invalid"],
    ["short wacz_hash", { wacz_hash: "ab" }, "wacz_hash_invalid"],
    ["page_count 0", { page_count: 0 }, "page_count_invalid"],
    ["page_count over the cap", { page_count: SITE_SNAPSHOT.MAX_PAGES + 1 }, "page_count_invalid"],
    ["unknown profile", { profile: "cf-web-0" }, "profile_invalid"],
    ["captured_at in seconds", { captured_at: 1794672650 }, "captured_at_invalid"],
    ["signer not a TIP-ID", { signer_tip_id: "alice" }, "signer_tip_id_invalid"],
    ["visibility other than private", { visibility: "public" }, "visibility_invalid"],
  ])("refuses %s", (_name, over, code) => {
    expectRefused(() => schema.buildSigningPayload({ ...FIXED, ...over }), 400, code);
  });

  test("visibility is signed only when private: absent or null keeps the 12-field bytes", () => {
    const base = schema.buildSigningPayload(FIXED);
    expect(schema.buildSigningPayload({ ...FIXED, visibility: null })).toEqual(base);
    expect(payloadHashHex(schema.buildSigningPayload({ ...FIXED, visibility: undefined }))).toBe(payloadHashHex(base));
    const priv = schema.buildSigningPayload({ ...FIXED, visibility: "private" });
    expect(priv).toEqual({ ...base, visibility: "private" });

    const kp = generateMLDSAKeypair();
    const sig = schema.sign(priv, kp.privateKey);
    expect(schema.verifySignature(priv, sig, kp.publicKey)).toBe(true);
    expect(schema.verifySignature(base, sig, kp.publicKey)).toBe(false);
  });

  test("refuses a payload without prev_snapshot_tx", () => {
    const { prev_snapshot_tx, ...rest } = FIXED;   // eslint-disable-line no-unused-vars
    expectRefused(() => schema.buildSigningPayload(rest), 400, "prev_snapshot_tx_required");
  });

  test("changing any signed field breaks the owner's signature", () => {
    const kp = generateMLDSAKeypair();
    const p = schema.buildSigningPayload(FIXED);
    const sig = schema.sign(p, kp.privateKey);
    expect(schema.verifySignature(p, sig, kp.publicKey)).toBe(true);
    const changed = {
      domain: "other.example", seq: 3, prev_snapshot_tx: hex("2"), root: hex("0"), page_count: 31,
      template_hash: hex("0"), profile: "cf-web-1x", wacz_hash: hex("0"), pack_hash: hex("0"),
      ai_signals_hash: hex("0"), captured_at: FIXED.captured_at + 1, signer_tip_id: OTHER,
    };
    for (const [f, v] of Object.entries(changed)) {
      expect(schema.verifySignature({ ...p, [f]: v }, sig, kp.publicKey)).toBe(false);
    }
  });
});

describe("API and commit", () => {
  test("the owner's first snapshot goes through the API, commits and reads back", async () => {
    const fx = setup();
    const p = payload();
    const out = await fx.siteService.submitSnapshot(bodyFor(fx.keys.owner, p));
    expect(out).toEqual(expect.objectContaining({ domain: SITE, seq: 1, confirmation: "proposed", witness_vp_id: null }));
    const tx = fx.submitted[0];
    expect(commit(fx, [tx]).committed).toBe(1);

    const row = fx.dag.getSiteSnapshot(tx.tx_id);
    expect(row).toEqual({ ...p, tx_id: tx.tx_id, witness_vp_id: null, registered_at: tx.timestamp });
    expect(await fx.siteService.getSnapshot(tx.tx_id)).toEqual(expect.objectContaining({ seq: 1, signature: tx.signature, witness: null }));
    expect(fx.siteService.listSnapshots("WWW.MyBlog.example")).toEqual({
      domain: SITE, next_before: null,
      snapshots: [expect.objectContaining({ seq: 1, tx_id: tx.tx_id, root: hex("a"), wacz_hash: hex("c") })],
    });
    expect(verifyStateRootConsistency(fx.dag).consistent).toBe(true);
  });

  test("a private snapshot commits with visibility on its row; relayed without it, the owner's signature fails", async () => {
    const fx = setup();
    const p = payload({ visibility: "private" });
    await fx.siteService.submitSnapshot(bodyFor(fx.keys.owner, p));
    const tx = fx.submitted[0];
    expect(tx.data.visibility).toBe("private");
    expect(commit(fx, [tx]).committed).toBe(1);
    expect(fx.dag.getSiteSnapshot(tx.tx_id)).toEqual({ ...p, tx_id: tx.tx_id, witness_vp_id: null, registered_at: tx.timestamp });
    expect((await fx.siteService.getSnapshot(tx.tx_id)).visibility).toBe("private");
    expect(verifyStateRootConsistency(fx.dag).consistent).toBe(true);

    const other = setup();
    const { visibility, ...publicData } = schema.buildTxData(p, null);   // eslint-disable-line no-unused-vars
    const stripped = snapshotTx(other, p, other.keys.owner, { data: publicData });
    expect(commit(other, [stripped]).committed).toBe(0);
    expect(other.dag.getSiteSnapshot(stripped.tx_id)).toBeNull();
  });

  test("the next snapshot links to the previous one; a wrong prev or seq is stale", async () => {
    const fx = setup();
    const t0 = nowMs() - 40 * MIN;
    const p1 = payload({ captured_at: t0 - MIN });
    const tx1 = snapshotTx(fx, p1, fx.keys.owner, { ts: t0 });
    expect(commit(fx, [tx1], t0).committed).toBe(1);

    const p2 = payload({ seq: 2, prev_snapshot_tx: tx1.tx_id, captured_at: t0 + 10 * MIN, root: hex("f") });
    const tx2 = snapshotTx(fx, p2, fx.keys.owner, { ts: t0 + 20 * MIN });
    expect(commit(fx, [tx2], t0 + 20 * MIN).committed).toBe(1);
    expect(fx.dag.getLatestSiteSnapshot(SITE).tx_id).toBe(tx2.tx_id);

    const p3 = payload({ seq: 3, prev_snapshot_tx: tx1.tx_id, captured_at: nowMs() - MIN });
    expectRefused(() => schema.validateRequest(bodyFor(fx.keys.owner, p3), { dag: fx.dag }), 409, "site_snapshot_stale");
    const tx3 = snapshotTx(fx, p3, fx.keys.owner);
    expect(commit(fx, [tx3]).committed).toBe(0);
    expect(reasonOf(fx, tx3)).toBe(TX_REJECTION_REASON.SITE_SNAPSHOT_STALE);

    const replay = snapshotTx(fx, p1, fx.keys.owner, { ts: nowMs() - 1000 });
    expect(commit(fx, [replay]).committed).toBe(0);
    expect(reasonOf(fx, replay)).toBe(TX_REJECTION_REASON.SITE_SNAPSHOT_STALE);
    expect(fx.siteService.listSnapshots(SITE).snapshots.map(s => s.seq)).toEqual([2, 1]);
  });

  test("two snapshots of one site in a batch: the first commits, the second is stale", () => {
    const fx = setup();
    const a = snapshotTx(fx, payload({ domain: ORG_SITE, signer_tip_id: ORG }), fx.keys.org);
    const b = snapshotTx(fx, payload({ domain: ORG_SITE, signer_tip_id: MEMBER, root: hex("9") }), fx.keys.member);
    expect(commit(fx, [a, b]).committed).toBe(1);
    expect(fx.dag.getLatestSiteSnapshot(ORG_SITE).tx_id).toBe(a.tx_id);
    expect(reasonOf(fx, b)).toBe(TX_REJECTION_REASON.SITE_SNAPSHOT_STALE);
  });

  test("only the owner or an active member of the owning org signs; others are refused at the API and at commit", async () => {
    const fx = setup();
    const p = payload({ signer_tip_id: OTHER });
    await expectRefusedAsync(fx.siteService.submitSnapshot(bodyFor(fx.keys.other, p)), 403, "not_site_owner");
    const tx = snapshotTx(fx, p, fx.keys.other);
    expect(commit(fx, [tx]).committed).toBe(0);
    expect(detailOf(fx, tx)).toContain("Only the owner of myblog.example");
    expect(fx.dag.getLatestSiteSnapshot(SITE)).toBeNull();

    // A member of the org cannot sign for a personal owner's site, nor once removed.
    const asMember = snapshotTx(fx, payload({ signer_tip_id: MEMBER }), fx.keys.member);
    expect(commit(fx, [asMember]).committed).toBe(0);
    expect(detailOf(fx, asMember)).toContain("Only the owner of myblog.example");
    fx.dag.saveOrgMember({ ...fx.dag.getOrgMember(hex("7")), status: "removed", removed_at: nowMs(), remove_tx_id: hex("6"), removed_by: ORG });
    const removed = snapshotTx(fx, payload({ domain: ORG_SITE, signer_tip_id: MEMBER }), fx.keys.member);
    expect(commit(fx, [removed]).committed).toBe(0);
    expect(detailOf(fx, removed)).toContain("Only the owner of press.example");
    expect(fx.dag.getLatestSiteSnapshot(ORG_SITE)).toBeNull();
  });

  test("an unprotected or lapsed site is refused", () => {
    const fx = setup();
    expectRefused(() => schema.validateRequest(bodyFor(fx.keys.owner, payload({ domain: "unbound.example" })), { dag: fx.dag }),
      403, "site_not_protected");
    bind(fx.dag, SITE, OWNER, { verifiedAt: nowMs() - 100 * MIN, expiresAt: nowMs() - MIN });
    const tx = snapshotTx(fx, payload(), fx.keys.owner);
    expect(commit(fx, [tx]).committed).toBe(0);
    expect(detailOf(fx, tx)).toContain("myblog.example is not a protected website");
    expect(fx.dag.getLatestSiteSnapshot(SITE)).toBeNull();
  });

  test("a snapshot within 10 minutes of the previous is refused, and captured_at must move forward", () => {
    const fx = setup();
    const t0 = nowMs() - 40 * MIN;
    const tx1 = snapshotTx(fx, payload({ captured_at: t0 - MIN }), fx.keys.owner, { ts: t0 });
    expect(commit(fx, [tx1], t0).committed).toBe(1);

    const next = (over) => payload({ seq: 2, prev_snapshot_tx: tx1.tx_id, ...over });
    const soon = snapshotTx(fx, next({ captured_at: t0 + 2 * MIN }), fx.keys.owner, { ts: t0 + 5 * MIN });
    expect(commit(fx, [soon], t0 + 5 * MIN).committed).toBe(0);
    expect(detailOf(fx, soon)).toContain("less than 10 minutes ago");
    const backwards = snapshotTx(fx, next({ captured_at: t0 - MIN }), fx.keys.owner, { ts: t0 + 20 * MIN });
    expect(commit(fx, [backwards], t0 + 20 * MIN).committed).toBe(0);
    expect(detailOf(fx, backwards)).toContain("captured_at must be after the previous snapshot's");
    const future = snapshotTx(fx, next({ captured_at: t0 + 30 * MIN }), fx.keys.owner, { ts: t0 + 20 * MIN });
    expect(commit(fx, [future], t0 + 20 * MIN).committed).toBe(0);
    expect(detailOf(fx, future)).toContain("captured_at is in the future");
    const ok = snapshotTx(fx, next({ captured_at: t0 + 19 * MIN }), fx.keys.owner, { ts: t0 + 20 * MIN });
    expect(commit(fx, [ok], t0 + 20 * MIN).committed).toBe(1);
  });

  test("before activation it is refused at the API and at commit, judged at max(tx time, certificate time)", () => {
    const fx = setup();
    expectRefused(() => schema.validateRequest(bodyFor(fx.keys.owner, payload()), { dag: fx.dag, now: GATE - 1 }),
      409, "site_snapshot_not_open");
    const p = payload({ captured_at: GATE - 2 * MIN });
    const early = snapshotTx(fx, p, fx.keys.owner, { ts: GATE - MIN });
    expect(commit(fx, [early], GATE - MIN).committed).toBe(0);
    expect(detailOf(fx, early)).toContain("Site snapshots open on");
    const late = snapshotTx(fx, p, fx.keys.owner, { ts: GATE - MIN + 1 });
    expect(commit(fx, [late], nowMs()).committed).toBe(1);
  });

  test("a revoked signer is refused", () => {
    const fx = setup();
    fx.dag.addRevocation(OWNER, "REVOKE_VOLUNTARY", nowMs() - MIN, hex("5"));
    const tx = snapshotTx(fx, payload(), fx.keys.owner);
    expect(commit(fx, [tx]).committed).toBe(0);
    expect(detailOf(fx, tx)).toContain(`TIP-ID is revoked: ${OWNER}`);
    expect(fx.dag.getLatestSiteSnapshot(SITE)).toBeNull();
  });
});

describe("witness", () => {
  test("the capturing VP's witness is verified, stored and returned", async () => {
    const fx = setup();
    const p = payload();
    const out = await fx.siteService.submitSnapshot(bodyFor(fx.keys.owner, p, witnessFor(fx.keys.vp, p)));
    expect(out.witness_vp_id).toBe(VP_ID);
    const tx = fx.submitted[0];
    expect(tx.data.cosignatures).toEqual([{ signer_kind: SIGNED_BY_KIND.VP, signer_ref: VP_ID, signature: expect.any(String) }]);
    expect(commit(fx, [tx]).committed).toBe(1);
    expect(fx.dag.getSiteSnapshot(tx.tx_id).witness_vp_id).toBe(VP_ID);
    expect((await fx.siteService.getSnapshot(tx.tx_id)).witness).toEqual({ vp_id: VP_ID, signature: tx.data.cosignatures[0].signature });
  });

  test("a witness signed by another key is refused at the API and at commit", async () => {
    const fx = setup();
    const p = payload();
    const forged = witnessFor(fx.keys.other, p);
    await expectRefusedAsync(fx.siteService.submitSnapshot(bodyFor(fx.keys.owner, p, forged)), 403, "witness_invalid");
    const tx = snapshotTx(fx, p, fx.keys.owner, { witness: forged });
    expect(commit(fx, [tx]).committed).toBe(0);
    expect(detailOf(fx, tx)).toBe("signature failed");
    expect(fx.dag.getLatestSiteSnapshot(SITE)).toBeNull();
  });

  test("a witness from an inactive or unregistered VP, or a stray cosignature, is refused", async () => {
    const fx = setup();
    const p = payload();
    await expectRefusedAsync(
      fx.siteService.submitSnapshot(bodyFor(fx.keys.owner, p, witnessFor(fx.keys.vp, p, "tip://vp/US-ffffffffffffffff"))),
      412, "site_snapshot_witness_invalid");

    const stray = snapshotTx(fx, p, fx.keys.owner, {
      data: { ...p, cosignatures: [{ signer_kind: SIGNED_BY_KIND.VP, signer_ref: VP_ID, signature: witnessFor(fx.keys.vp, p).signature }] },
    });
    expect(commit(fx, [stray]).committed).toBe(0);
    expect(reasonOf(fx, stray)).toBe(TX_REJECTION_REASON.SITE_SNAPSHOT_WITNESS_INVALID);

    fx.dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", status: "suspended", registered_at: 1767225600000 });
    await expectRefusedAsync(fx.siteService.submitSnapshot(bodyFor(fx.keys.owner, p, witnessFor(fx.keys.vp, p))), 403, "site_snapshot_witness_invalid");
    const tx = snapshotTx(fx, p, fx.keys.owner, { witness: witnessFor(fx.keys.vp, p) });
    expect(commit(fx, [tx]).committed).toBe(0);
    expect(reasonOf(fx, tx)).toBe(TX_REJECTION_REASON.SITE_SNAPSHOT_WITNESS_INVALID);
  });
});

describe("HTTP routes", () => {
  function app(fx) {
    const a = express();
    a.use(express.json({ limit: "1mb" }));
    a.use("/v1", siteRoutes.createRouter({ siteService: fx.siteService }));
    a.use(errorHandler);
    return a;
  }

  test("POST, then GET by tx and by domain; a dotted domain and the tx route do not collide; errors carry their codes", async () => {
    const fx = setup();
    const http = app(fx);
    const posted = await request(http).post("/v1/site/snapshot").send(bodyFor(fx.keys.owner, payload()));
    expect(posted.status).toBe(202);
    expect(commit(fx, fx.submitted.splice(0)).committed).toBe(1);

    const one = await request(http).get(`/v1/site/snapshot/${posted.body.tx_id}`);
    expect(one.status).toBe(200);
    expect(one.body).toEqual(expect.objectContaining({ domain: SITE, seq: 1, tx_id: posted.body.tx_id, witness: null }));
    const list = await request(http).get(`/v1/site/${SITE}/snapshots?limit=5`);
    expect(list.status).toBe(200);
    expect(list.body.snapshots.map(r => r.tx_id)).toEqual([posted.body.tx_id]);

    const bad = await request(http).get(`/v1/site/${SITE}/snapshots?limit=500`);
    expect([bad.status, bad.body.error.code]).toEqual([400, "limit_invalid"]);
    const missing = await request(http).get(`/v1/site/snapshot/${hex("0")}`);
    expect([missing.status, missing.body.error.code]).toEqual([404, "site_snapshot_not_found"]);
    const stranger = await request(http).post("/v1/site/snapshot").send(bodyFor(fx.keys.other, payload({ signer_tip_id: OTHER })));
    expect([stranger.status, stranger.body.error.code]).toEqual([403, "not_site_owner"]);
  });
});

describe("determinism", () => {
  test("memory and SQLite stores commit the same txs (one public, one private) to the same site_snapshots state", () => {
    const keys = makeKeys();
    const fxs = STORES.map(([, makeDag]) => setup(makeDag, keys));
    const t0 = nowMs() - 60 * MIN;
    const tx1 = snapshotTx(fxs[0], payload({ captured_at: t0 - MIN }), keys.owner, { ts: t0 });
    const p2 = payload({ seq: 2, prev_snapshot_tx: tx1.tx_id, captured_at: t0 + 15 * MIN, root: hex("f"), visibility: "private" });
    const tx2 = snapshotTx(fxs[0], p2, keys.owner, { ts: t0 + 20 * MIN });
    const tables = fxs.map((fx) => {
      expect(fx.handler.commitOrderedTxs([{ ...tx1 }], 900, { certTimestamp: t0 }).committed).toBe(1);
      expect(fx.handler.commitOrderedTxs([{ ...tx2 }], 901, { certTimestamp: t0 + 20 * MIN }).committed).toBe(1);
      expect(verifyStateRootConsistency(fx.dag).consistent).toBe(true);
      return computeStateMerkleRootPerTable(fx.dag).find(t => t.table === "site_snapshots");
    });
    expect(tables[0]).toEqual(expect.objectContaining({ count: 2 }));
    expect(tables[1]).toEqual(tables[0]);
    expect(fxs[1].dag.getSiteSnapshot(tx2.tx_id).visibility).toBe("private");
    expect(fxs[1].dag.getSiteSnapshot(tx1.tx_id)).not.toHaveProperty("visibility");
  });
});
