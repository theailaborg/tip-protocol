/**
 * @file tests/consensus/commit-handler-key-retirement.test.js
 * @description A rotated-away or recovered-from key must not sign new
 * transactions. Keys resolve at tx.timestamp (history keeps verifying), so
 * the commit handler checks the resolved key's retirement against the
 * round's certificate time; a backdated tx signed with the old key is
 * rejected, while honest in-flight and long-queued transactions still land.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, computeTxId, shake256 } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TX_TYPES, TX_REJECTION_REASON, KEY_RETIREMENT_GRACE_MS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const invitedSchema = require(path.join(SRC, "schemas", "org-member-invited"));
const keyRecoverySchema = require(path.join(SRC, "schemas", "key-recovery"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-key-retirement";
const ORG = "tip://id/GB-400d3636845c06f2";
const ALICE = "tip://id/IND-1aeb5ec0aa16cb20";
const BOB = "tip://id/US-ed1c6dbddac62443";
const BASE_TS = 1767225600000;
const HOUR = 3600_000;
const VP_ID = "tip://vp/v1";

function setup({ keyRetirementActivationMs = 0, rotatedAgoMs = HOUR, isLocallyVerified, dbPath = ":memory:" } = {}) {
  const dag = initDAG({ dbPath });
  const nodeKp = generateMLDSAKeypair();
  const oldKey = generateMLDSAKeypair(), newKey = generateMLDSAKeypair();
  const people = { [ALICE]: generateMLDSAKeypair(), [BOB]: generateMLDSAKeypair() };
  dag.saveNode({ node_id: NODE_ID, name: "t", public_key: nodeKp.publicKey, status: "active", registered_at: BASE_TS });
  const vpKp = generateMLDSAKeypair();
  dag.saveVP({ vp_id: VP_ID, name: "test-vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: BASE_TS });
  const saveId = (id, kp, type) => dag.saveIdentity({
    tip_id: id, region: id.slice(9, 11), public_key: kp.publicKey, root_public_key: "00", vp_id: "tip://vp/v1",
    verification_tier: "T1", founding: false, status: "active", tip_id_type: type, registered_at: BASE_TS,
    tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: id }),
  });
  saveId(ORG, oldKey, "organization"); saveId(ALICE, people[ALICE], "personal"); saveId(BOB, people[BOB], "personal");
  for (const id of [ORG, ALICE, BOB]) dag.setScore(id, 500, 0, BASE_TS);
  // The org rotated its key rotatedAgoMs ago: old window closes, new one opens.
  const T_ROT = nowMs() - rotatedAgoMs;
  dag.saveEntityKey({ entity_type: "identity", entity_id: ORG, public_key: oldKey.publicKey, valid_from_ts: BASE_TS, valid_to_ts: T_ROT, source_tx_id: "k0" });
  dag.saveEntityKey({ entity_type: "identity", entity_id: ORG, public_key: newKey.publicKey, valid_from_ts: T_ROT, valid_to_ts: null, source_tx_id: "k1" });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, orgMembersActivationMs: 0, keyRetirementActivationMs };
  const handler = createCommitHandler({ dag, scoring: initScoring(dag, config), config, isLocallyVerified });
  return { dag, handler, oldKey, newKey, T_ROT, vpKp };
}

function recoveryTx(ctx, replacesPubkey, ts) {
  const newKp = generateMLDSAKeypair();
  const core = {
    algorithm: "ml-dsa-65", new_public_key: newKp.publicKey, recovery_evidence_hash: shake256("evidence"),
    replaces_pubkey: replacesPubkey, tip_id: ORG, vp_id: VP_ID, zk_proof: { pi_a: ["1"], pi_b: [["1"]], pi_c: ["1"] },
  };
  const payload = keyRecoverySchema.buildSigningPayload(core);
  const tx = {
    tx_type: TX_TYPES.KEY_RECOVERY, timestamp: ts, prev: [],
    data: { ...core, effective_at: ts, new_key_signature: keyRecoverySchema.sign(payload, newKp.privateKey) },
    signature: keyRecoverySchema.sign(payload, ctx.vpKp.privateKey),
  };
  tx.prev = ctx.dag.prevFor(tx.tx_type, tx.data);
  tx.tx_id = computeTxId(tx);
  return { tx, newKp };
}

// A thief holding the old key parks a rotation far ahead: the old window now
// closes in the future, and the "active" row is the not-yet-valid parked key.
function parkRotation(ctx, parkedUntil) {
  const parkedKey = generateMLDSAKeypair();
  ctx.dag.saveEntityKey({ entity_type: "identity", entity_id: ORG, public_key: ctx.newKey.publicKey, valid_from_ts: ctx.T_ROT, valid_to_ts: parkedUntil, source_tx_id: "k1" });
  ctx.dag.saveEntityKey({ entity_type: "identity", entity_id: ORG, public_key: parkedKey.publicKey, valid_from_ts: parkedUntil, valid_to_ts: null, source_tx_id: "k-parked" });
  return parkedKey;
}

function inviteTx(ctx, kp, ts, member) {
  const data = { org_tip_id: ORG, member_tip_id: member, role: "author", invited_at: ts };
  const tx = { tx_type: TX_TYPES.ORG_MEMBER_INVITED, timestamp: ts, signature: invitedSchema.sign(invitedSchema.buildSigningPayload(data), kp.privateKey), prev: [], data };
  tx.prev = ctx.dag.prevFor(tx.tx_type, tx.data);
  tx.tx_id = computeTxId(tx);
  return tx;
}

let round = 0;

describe("retired signing keys at commit", () => {
  test("the attack: an old-key tx backdated into the key's window is rejected as signer_key_retired", () => {
    const ctx = setup();
    const backdated = inviteTx(ctx, ctx.oldKey, ctx.T_ROT - 60_000, ALICE);
    // The signature itself verifies at that timestamp; only the retirement rule stops it.
    expect(ctx.dag.getKeyValidAt("identity", ORG, backdated.timestamp).public_key).toBe(ctx.oldKey.publicKey);
    const r = ctx.handler.commitOrderedTxs([backdated], ++round, { certTimestamp: nowMs() });
    expect(r).toMatchObject({ committed: 0, dropped: 1 });
    expect(ctx.dag.getOrgMember(backdated.tx_id)).toBeNull();
    expect(ctx.dag.getTxRejection(backdated.tx_id)).toMatchObject({ reason: TX_REJECTION_REASON.SIGNER_KEY_RETIRED });
  });

  test("the rule runs even when this node pre-verified the bytes at its API (same decision on every node)", () => {
    const ctx = setup({ isLocallyVerified: () => true });
    const backdated = inviteTx(ctx, ctx.oldKey, ctx.T_ROT - 60_000, ALICE);
    expect(ctx.handler.commitOrderedTxs([backdated], ++round, { certTimestamp: nowMs() })).toMatchObject({ committed: 0, dropped: 1 });
  });

  test("an old-key tx with a current timestamp fails the signature regardless", () => {
    const ctx = setup();
    const forged = inviteTx(ctx, ctx.oldKey, nowMs() - 1000, ALICE);
    expect(ctx.handler.commitOrderedTxs([forged], ++round, { certTimestamp: nowMs() })).toMatchObject({ committed: 0, dropped: 1 });
    expect(ctx.dag.getTxRejection(forged.tx_id).reason).toBe(TX_REJECTION_REASON.REVALIDATION_FAILED);
  });

  test("in flight: signed with the old key just before the rotation, certified inside the grace, commits", () => {
    const ctx = setup();
    const inFlight = inviteTx(ctx, ctx.oldKey, ctx.T_ROT - 30_000, ALICE);
    const r = ctx.handler.commitOrderedTxs([inFlight], ++round, { certTimestamp: ctx.T_ROT + KEY_RETIREMENT_GRACE_MS - 1000 });
    expect(r).toMatchObject({ committed: 1, dropped: 0 });
  });

  test("the same in-flight tx certified past the grace is rejected", () => {
    const ctx = setup();
    const late = inviteTx(ctx, ctx.oldKey, ctx.T_ROT - 30_000, ALICE);
    const r = ctx.handler.commitOrderedTxs([late], ++round, { certTimestamp: ctx.T_ROT + KEY_RETIREMENT_GRACE_MS + 1000 });
    expect(r).toMatchObject({ committed: 0, dropped: 1 });
    expect(ctx.dag.getTxRejection(late.tx_id).reason).toBe(TX_REJECTION_REASON.SIGNER_KEY_RETIRED);
  });

  test("outage survivor: a tx that waited two hours commits when its key was never rotated (no age bound)", () => {
    const ctx = setup({ rotatedAgoMs: 3 * HOUR });
    const waited = inviteTx(ctx, ctx.newKey, nowMs() - 2 * HOUR, ALICE);
    expect(ctx.handler.commitOrderedTxs([waited], ++round, { certTimestamp: nowMs() })).toMatchObject({ committed: 1, dropped: 0 });
    expect(ctx.dag.getOrgMember(waited.tx_id)).toMatchObject({ status: "invited" });
  });

  test("a tx signed with a key rotated during a long outage is rejected when the chain resumes", () => {
    const ctx = setup({ rotatedAgoMs: 30 * 60_000 });
    const signedBeforeOutage = inviteTx(ctx, ctx.oldKey, ctx.T_ROT - 10 * 60_000, ALICE);
    const r = ctx.handler.commitOrderedTxs([signedBeforeOutage], ++round, { certTimestamp: nowMs() });
    expect(r).toMatchObject({ committed: 0, dropped: 1 });
    expect(ctx.dag.getTxRejection(signedBeforeOutage.tx_id).reason).toBe(TX_REJECTION_REASON.SIGNER_KEY_RETIRED);
  });

  test("a current new-key tx commits", () => {
    const ctx = setup();
    expect(ctx.handler.commitOrderedTxs([inviteTx(ctx, ctx.newKey, nowMs() - 500, ALICE)], ++round, { certTimestamp: nowMs() })).toMatchObject({ committed: 1, dropped: 0 });
  });

  test("before the activation epoch the rule is not applied (mixed fleet safety)", () => {
    const ctx = setup({ keyRetirementActivationMs: Number.MAX_SAFE_INTEGER });
    const backdated = inviteTx(ctx, ctx.oldKey, ctx.T_ROT - 60_000, ALICE);
    expect(ctx.handler.commitOrderedTxs([backdated], ++round, { certTimestamp: nowMs() })).toMatchObject({ committed: 1 });
  });

  test("without a certificate time (legacy caller) the rule is skipped rather than judged by the wall clock", () => {
    const ctx = setup();
    const backdated = inviteTx(ctx, ctx.oldKey, ctx.T_ROT - 60_000, ALICE);
    expect(ctx.handler.commitOrderedTxs([backdated], ++round)).toMatchObject({ committed: 1 });
  });

  test("replay of a historical round keeps verifying: old-key tx certified while that key was current", () => {
    const ctx = setup();
    const historical = inviteTx(ctx, ctx.oldKey, ctx.T_ROT - 20 * 60_000, ALICE);
    // Certified back then, before the rotation; replayed now with the cert's own time.
    const r = ctx.handler.commitOrderedTxs([historical], ++round, { certTimestamp: ctx.T_ROT - 19 * 60_000 });
    expect(r).toMatchObject({ committed: 1, dropped: 0 });
  });

  // MemoryStore and SQLiteStore: the key-window rewrite must work on both (a
  // SQLite write through a live cursor used to throw mid-transaction).
  test.each([["memory", () => ":memory:"], ["sqlite", () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "tip-keyret-")), "dag.db")]])(
    "a recovery clamps a window parked in the future on the %s store, so the stolen key stops resolving for old timestamps", (_name, dbPathFn) => {
    const ctx = setup({ dbPath: dbPathFn() });
    const parkedUntil = nowMs() + 365 * 24 * HOUR;
    const parkedKey = parkRotation(ctx, parkedUntil);
    expect(ctx.dag.getActiveKey("identity", ORG).public_key).toBe(parkedKey.publicKey);

    const recoveredAt = nowMs() - 2 * KEY_RETIREMENT_GRACE_MS;
    const { tx: recovery, newKp } = recoveryTx(ctx, parkedKey.publicKey, recoveredAt);
    expect(ctx.handler.commitOrderedTxs([recovery], ++round, { certTimestamp: recoveredAt + 1000 })).toMatchObject({ committed: 1, dropped: 0 });

    // Every earlier window now ends at the recovery; the parked row never opens.
    expect(Number(ctx.dag.getKeyValidAt("identity", ORG, recoveredAt - 60_000).valid_to_ts)).toBe(recoveredAt);
    expect(ctx.dag.getKeyValidAt("identity", ORG, parkedUntil + 1000).public_key).toBe(newKp.publicKey);
    expect(ctx.dag.getActiveKey("identity", ORG).public_key).toBe(newKp.publicKey);

    // The thief's backdated tx (signed with the stolen key, dated before the recovery) is rejected.
    const backdated = inviteTx(ctx, ctx.newKey, recoveredAt - 60_000, ALICE);
    const r = ctx.handler.commitOrderedTxs([backdated], ++round, { certTimestamp: nowMs() });
    expect(r).toMatchObject({ committed: 0, dropped: 1 });
    expect(ctx.dag.getTxRejection(backdated.tx_id).reason).toBe(TX_REJECTION_REASON.SIGNER_KEY_RETIRED);
  });

  test("before the activation epoch a recovery closes only the open row, as before", () => {
    const ctx = setup({ keyRetirementActivationMs: Number.MAX_SAFE_INTEGER });
    const parkedUntil = nowMs() + 365 * 24 * HOUR;
    const parkedKey = parkRotation(ctx, parkedUntil);
    const recoveredAt = nowMs() - 1000;
    const { tx: recovery } = recoveryTx(ctx, parkedKey.publicKey, recoveredAt);
    expect(ctx.handler.commitOrderedTxs([recovery], ++round, { certTimestamp: nowMs() })).toMatchObject({ committed: 1 });
    expect(Number(ctx.dag.getKeyValidAt("identity", ORG, recoveredAt - 60_000).valid_to_ts)).toBe(parkedUntil);
  });

  test("a rotation parked beyond the lead bound is rejected at commit once the rule is active", () => {
    const ctx = setup();
    const ts = nowMs() - 1000;
    const fields = {
      algorithm: "ml-dsa-65", effective_at: ts + 365 * 24 * HOUR, new_public_key: generateMLDSAKeypair().publicKey,
      old_key_fingerprint: shake256(ctx.newKey.publicKey).slice(0, 32), tip_id: ORG,
    };
    const keyRotatedSchema = require(path.join(SRC, "schemas", "key-rotated"));
    const parked = { tx_type: TX_TYPES.KEY_ROTATED, timestamp: ts, prev: [], data: { ...fields }, signature: keyRotatedSchema.sign(keyRotatedSchema.buildSigningPayload(fields), ctx.newKey.privateKey) };
    parked.prev = ctx.dag.prevFor(parked.tx_type, parked.data);
    parked.tx_id = computeTxId(parked);
    expect(ctx.handler.commitOrderedTxs([parked], ++round, { certTimestamp: nowMs() })).toMatchObject({ committed: 0, dropped: 1 });
    expect(ctx.dag.getActiveKey("identity", ORG).public_key).toBe(ctx.newKey.publicKey);
  });
});
