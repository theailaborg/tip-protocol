/**
 * @file tests/store-conformance.test.js
 * @description Store conformance suite — the executable contract every DAG
 * store implementation must satisfy. One spec, run via describe.each against
 * each store factory, so any behavioral divergence between implementations
 * fails CI here instead of forking the network at runtime.
 *
 * Contract groups:
 *   1.  Transactions — addTx auto-fill, tamper rejection, ordered iteration
 *   2.  Identity + entity_keys — round-trip, key routing, rotation history
 *   3.  Scores / dedup — determinism guards (caller must pass tx-derived
 *       timestamps), clamping, first-write-wins on duplicate dedup hashes
 *   4.  Revocations — registry row + identity status flip
 *   5.  Content — round-trip + status transitions
 *   6.  Mempool — round-trip, bulk delete, counts
 *   7.  Prescan jobs — lifecycle transitions, oldest-first claim, stuck-claim
 *       recovery, single-winner claim (pins the contract any future async
 *       store implementation must preserve)
 *   8.  Upload sessions — node-local ephemeral chunked-upload state
 *   9.  Certificates / commits / votes_seen — idempotency, GC cutoffs,
 *       first-wins equivocation defense
 *   10. Committee history — replace-by-rotation_number, effective_round
 *       boundary semantics
 *   11. Domain bindings + platform links — round-trip, partial update merge
 *   12. Canonical state — clearCanonicalState completeness (incl. the dedup
 *       tip_id registry), reconcile primitives (deleteCanonicalRow /
 *       pruneCanonicalStateExcept exactness + root sync), cross-store
 *       deterministic iteration
 *   13. runInTransaction — rollback-on-throw. Implementations that are
 *       known no-ops are pinned with test.failing so the gap stays visible
 *       in CI output and flips to a hard failure the moment a fix lands
 *       (the failing-marker must then be removed).
 *
 * Adding a store: append a factory row to STORES. Adding a store method:
 * add its contract cases here once — every implementation is then held to
 * them automatically.
 *
 * The Knex/Postgres adapter runs this same spec when TIP_CONFORMANCE_PG=1
 * (CI postgres profile provides a scratch database); it is skipped locally.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

const SRC = path.resolve(__dirname, "../src");
const SHARED = path.resolve(__dirname, "../../shared");
const { initDAG, initDAGAsync, canonicalPk } = require(path.join(SRC, "dag"));
const { computeStateMerkleRoot } = require(path.join(SRC, "consensus", "state-root"));
const { canonicalJson } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));

// ── Store factories ────────────────────────────────────────────────────────

let tmpDir;
let fileSeq = 0;
const openDags = [];

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-store-conformance-"));
});

afterAll(async () => {
  for (const dag of openDags) {
    try { await dag.flush(); dag.close(); } catch { /* already closed */ }
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function track(dag) {
  openDags.push(dag);
  return dag;
}

// caps.atomicRollback: whether runInTransaction provides real rollback-on-throw.
// memory=false is the documented no-op (`dag.js` MemoryStore.runInTransaction);
// pinned below with test.failing until the storage rework lands.
const STORES = [
  ["memory", async () => track(initDAG({ dbPath: ":memory:" })), { atomicRollback: false }],
  ["sqlite", async () => track(initDAG({ dbPath: path.join(tmpDir, `conformance-${fileSeq++}.db`) })), { atomicRollback: true }],
];

if (process.env.TIP_CONFORMANCE_PG === "1") {
  STORES.push([
    "knex-pg",
    async () => track(await initDAGAsync({ dbDriver: process.env.DB_DRIVER || "postgres" })),
    { atomicRollback: false },
  ]);
}

// ── Fixtures ───────────────────────────────────────────────────────────────

let seq = 0;
const uniq = (prefix) => `${prefix}-${nowMs().toString(36)}-${seq++}`;

const T0 = 1773532800000; // fixed base timestamp (genesis epoch) for deterministic rows

function identityRec(tipId, overrides = {}) {
  return {
    tip_id: tipId,
    status: "active",
    registered_at: T0,
    verification_tier: "VERIFIED",
    region: "US",
    public_key: `pk-${tipId}`,
    algorithm: "ml-dsa-65",
    biometric_commit: "a".repeat(64),
    ...overrides,
  };
}

function contentRec(ctid, authorTipId, overrides = {}) {
  return {
    ctid,
    author_tip_id: authorTipId,
    signer_tip_id: authorTipId,
    content_hash: `hash-${ctid}`,
    origin_code: "OH",
    cna_version: "2.2",
    status: "active",
    registered_at: T0,
    ...overrides,
  };
}

function prescanJob(jobId, createdAt) {
  return { job_id: jobId, ctid: uniq("ct"), payload: JSON.stringify({ kind: "text" }), created_at: createdAt };
}

function uploadSession(sessionId, overrides = {}) {
  const createdAt = nowMs();
  return {
    session_id: sessionId,
    upload_id: `up-${sessionId}`,
    s3_key: `media/${sessionId.slice(0, 2)}/${sessionId.slice(2)}.bin`,
    content_hash: "a".repeat(64),
    mime: "video/mp4",
    size: 12345,
    signer_tip_id: uniq("id"),
    timestamp: T0,
    signature: "ab",
    parts: [],
    completed_size: 0,
    created_at: createdAt,
    expires_at: createdAt + 86400000,
    ...overrides,
  };
}

function certRec(round, author, overrides = {}) {
  const batchHash = uniq("bh");
  return {
    hash: uniq("cert"),
    round,
    author_node_id: author,
    batch: { hash: batchHash, round, author_node_id: author, txs: [] },
    acknowledgments: [],
    parent_hashes: [],
    signature: `sig-${batchHash}`,
    timestamp: T0 + round,
    ...overrides,
  };
}

function commitRec(round, overrides = {}) {
  return {
    round,
    anchor_cert_hash: `anchor-${round}`,
    leader_node_id: "n1",
    committee: ["n1", "n2"],
    support_count: 2,
    consensus_index: round,
    committed_at: T0 + round,
    state_merkle_root: `sr-${round}`,
    txs_merkle_root: `tr-${round}`,
    ack_signer_ids: ["n1", "n2"],
    ack_signatures: ["s1", "s2"],
    ack_signed_ats: [T0, T0],
    anchor_batch_hash: `ab-${round}`,
    cert_timestamp: T0 + round,
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════════

describe.each(STORES)("store contract: %s", (storeName, makeDag, caps) => {
  const atomic = caps.atomicRollback ? test : test.failing;

  // ── 1. Transactions ──────────────────────────────────────────────────────

  test("addTx auto-fills timestamp/tx_id and getTx round-trips", async () => {
    const dag = await makeDag();
    const before = dag.count();
    const tx = dag.addTx({ tx_type: "TEST_EVENT", data: { n: 1 } });

    expect(tx.tx_id).toBeTruthy();
    expect(tx.timestamp).toBeGreaterThan(0);
    expect(dag.count()).toBe(before + 1);

    const got = dag.getTx(tx.tx_id);
    expect(got.tx_type).toBe("TEST_EVENT");
    expect(got.data).toEqual({ n: 1 });
    expect(got.timestamp).toBe(tx.timestamp);
  });

  test("addTx rejects a tampered tx whose tx_id no longer matches canonical form", async () => {
    const dag = await makeDag();
    const tx = dag.addTx({ tx_type: "TEST_EVENT", data: { n: 2 } });
    expect(() => dag.addTx({ ...tx, data: { n: 999 } })).toThrow(/tx_id mismatch/);
  });

  test("iterateAllTransactions yields every tx ordered by tx_id", async () => {
    const dag = await makeDag();
    for (let i = 0; i < 5; i++) dag.addTx({ tx_type: "TEST_EVENT", data: { i } });

    const ids = [...dag.iterateAllTransactions()].map(t => t.tx_id);
    expect(ids).toEqual([...ids].sort());
    expect(ids).toHaveLength(dag.count());
    expect(new Set(ids).size).toBe(ids.length);
  });

  // ── 2. Identity + entity_keys ────────────────────────────────────────────

  test("saveIdentity/getIdentity round-trips fields and routes public_key into entity_keys", async () => {
    const dag = await makeDag();
    const tipId = uniq("US-id");
    dag.saveIdentity(identityRec(tipId));

    const got = dag.getIdentity(tipId);
    expect(got.tip_id).toBe(tipId);
    expect(got.status).toBe("active");
    expect(got.registered_at).toBe(T0);
    expect(got.verification_tier).toBe("VERIFIED");
    expect(got.public_key).toBe(`pk-${tipId}`);
    expect(got.algorithm).toBe("ml-dsa-65");
    expect(got.biometric_commit).toBe("a".repeat(64));

    const active = dag.getActiveKey("identity", tipId);
    expect(active).toEqual(expect.objectContaining({ public_key: `pk-${tipId}`, algorithm: "ml-dsa-65" }));
  });

  test("key rotation closes the prior key and getKeyValidAt selects by timestamp", async () => {
    const dag = await makeDag();
    const tipId = uniq("US-rot");
    dag.saveIdentity(identityRec(tipId, { registered_at: T0 }));
    dag.saveIdentity(identityRec(tipId, { registered_at: T0 + 1000, public_key: `pk2-${tipId}` }));

    expect(dag.getActiveKey("identity", tipId).public_key).toBe(`pk2-${tipId}`);
    expect(dag.getKeyValidAt("identity", tipId, T0 + 500).public_key).toBe(`pk-${tipId}`);
    expect(dag.getKeyValidAt("identity", tipId, T0 + 1500).public_key).toBe(`pk2-${tipId}`);

    // Re-saving the same active key must not append a duplicate history row
    const rowsBefore = [...dag.iterateEntityKeys()].filter(r => r.entity_id === tipId).length;
    dag.saveIdentity(identityRec(tipId, { registered_at: T0 + 1000, public_key: `pk2-${tipId}` }));
    const rowsAfter = [...dag.iterateEntityKeys()].filter(r => r.entity_id === tipId).length;
    expect(rowsAfter).toBe(rowsBefore);
  });

  test("identityCount reflects saved identities (metrics accessor)", async () => {
    const dag = await makeDag();
    const before = dag.identityCount();
    dag.saveIdentity(identityRec(uniq("US-cnt")));
    dag.saveIdentity(identityRec(uniq("US-cnt")));
    expect(dag.identityCount()).toBe(before + 2);
    // Re-saving an existing tip_id is an upsert, not a new row.
    const tipId = uniq("US-cnt");
    dag.saveIdentity(identityRec(tipId));
    dag.saveIdentity(identityRec(tipId, { registered_at: T0 + 1 }));
    expect(dag.identityCount()).toBe(before + 3);
  });

  // ── 3. Scores / dedup determinism guards ─────────────────────────────────

  test("setScore requires a caller-supplied timestamp and clamps to [0, 1000]", async () => {
    const dag = await makeDag();
    const tipId = uniq("US-score");

    expect(() => dag.setScore(tipId, 500, 0)).toThrow(/lastUpdated/);

    dag.setScore(tipId, 1500, 2, T0);
    expect(dag.getScore(tipId)).toEqual(expect.objectContaining({ score: 1000, offense_count: 2, last_updated: T0 }));

    dag.setScore(tipId, -50, 0, T0 + 1);
    expect(dag.getScore(tipId).score).toBe(0);
  });

  test("addDedupHash requires createdAt, round-trips, and first write wins on duplicates", async () => {
    const dag = await makeDag();
    const hash = uniq("dedup");
    const tipId = uniq("US-dd");

    expect(() => dag.addDedupHash(hash)).toThrow(/createdAt/);

    dag.addDedupHash(hash, 1111, tipId);
    expect(dag.hasDedupHash(hash)).toBe(true);
    expect(dag.getDedupRegistration(hash)).toEqual({ dedup_hash: hash, created_at: 1111, tip_id: tipId });

    dag.addDedupHash(hash, 2222, uniq("US-other"));
    expect(dag.getDedupRegistration(hash)).toEqual({ dedup_hash: hash, created_at: 1111, tip_id: tipId });
  });

  // ── 4. Revocations ───────────────────────────────────────────────────────

  test("addRevocation records the revocation and flips the identity status", async () => {
    const dag = await makeDag();
    const tipId = uniq("US-rev");
    dag.saveIdentity(identityRec(tipId));

    expect(dag.isRevoked(tipId)).toBe(false);
    dag.addRevocation(tipId, "IDENTITY_REVOKED", T0 + 10, uniq("tx"));

    expect(dag.isRevoked(tipId)).toBe(true);
    expect(dag.getRevocation(tipId)).toEqual(expect.objectContaining({ tip_id: tipId, tx_type: "IDENTITY_REVOKED", timestamp: T0 + 10 }));
    expect(dag.getIdentity(tipId).status).toBe("revoked");
  });

  // ── 5. Content ───────────────────────────────────────────────────────────

  test("content round-trips and status transitions are visible via getContentByStatus", async () => {
    const dag = await makeDag();
    const author = uniq("US-auth");
    const ctid = uniq("ct");
    dag.saveContent(contentRec(ctid, author));

    expect(dag.getContent(ctid)).toEqual(expect.objectContaining({ ctid, author_tip_id: author, status: "active" }));
    expect(dag.getContentByAuthor(author).map(c => c.ctid)).toContain(ctid);

    dag.updateContentStatus(ctid, "disputed");
    expect(dag.getContent(ctid).status).toBe("disputed");
    expect(dag.getContentByStatus("disputed").map(c => c.ctid)).toContain(ctid);
  });

  test("contentCount reflects saved content rows (metrics accessor)", async () => {
    const dag = await makeDag();
    const before = dag.contentCount();
    const author = uniq("US-auth");
    dag.saveContent(contentRec(uniq("ct-cnt"), author));
    dag.saveContent(contentRec(uniq("ct-cnt"), author));
    expect(dag.contentCount()).toBe(before + 2);
    // Re-saving an existing ctid is an upsert, not a new row.
    const ctid = uniq("ct-cnt");
    dag.saveContent(contentRec(ctid, author));
    dag.saveContent(contentRec(ctid, author, { status: "disputed" }));
    expect(dag.contentCount()).toBe(before + 3);
  });

  // ── 6. Mempool ───────────────────────────────────────────────────────────

  test("mempool round-trips, counts, and bulk-deletes", async () => {
    const dag = await makeDag();
    const before = dag.mempoolCount();
    const txs = [1, 2, 3].map(n => ({ tx_id: uniq("mtx"), tx_type: "TEST_EVENT", data: { n }, timestamp: T0 + n }));
    for (const tx of txs) dag.saveMempoolTx(tx);

    expect(dag.mempoolCount()).toBe(before + 3);
    expect(dag.getMempoolTx(txs[0].tx_id)).toEqual(expect.objectContaining({ tx_id: txs[0].tx_id }));

    dag.deleteMempoolTxs([txs[0].tx_id, txs[1].tx_id]);
    expect(dag.mempoolCount()).toBe(before + 1);
    expect(dag.getMempoolTx(txs[0].tx_id)).toBeNull();
    expect(dag.getMempoolTx(txs[2].tx_id)).not.toBeNull();
  });

  // ── 7. Prescan jobs ──────────────────────────────────────────────────────

  test("prescan job lifecycle: enqueue dedup, oldest-first claim, stuck recovery, transitions", async () => {
    const dag = await makeDag();
    const older = prescanJob(uniq("job"), T0);
    const newer = prescanJob(uniq("job"), T0 + 100);
    // Claims are gated on the content row existing (REGISTER_CONTENT committed)
    dag.saveContent(contentRec(older.ctid, uniq("a")));
    dag.saveContent(contentRec(newer.ctid, uniq("a")));

    expect(dag.enqueuePrescanJob(older)).toBe(true);
    expect(dag.enqueuePrescanJob(older)).toBe(false);
    expect(dag.enqueuePrescanJob(newer)).toBe(true);

    const claimed = dag.claimPrescanJob({ workerId: "w1", now: T0 + 1000, claimTimeoutMs: 5000 });
    expect(claimed.job_id).toBe(older.job_id);
    expect(claimed.status).toBe("claimed");
    expect(claimed.claimed_by).toBe("w1");

    // A claimed job within its timeout window is not reclaimable
    const second = dag.claimPrescanJob({ workerId: "w2", now: T0 + 2000, claimTimeoutMs: 5000 });
    expect(second.job_id).toBe(newer.job_id);
    expect(dag.claimPrescanJob({ workerId: "w3", now: T0 + 2000, claimTimeoutMs: 5000 })).toBeNull();

    // Stuck-claim recovery after the timeout elapses
    const stuck = dag.claimPrescanJob({ workerId: "w4", now: T0 + 20000, claimTimeoutMs: 5000 });
    expect([older.job_id, newer.job_id]).toContain(stuck.job_id);

    expect(dag.markPrescanJobDone(older.job_id, { completedAt: T0 + 30000 })).toBe(true);
    expect(dag.getPrescanJob(older.job_id)).toBeNull();   // success deletes the row (retention fix)

    expect(dag.releasePrescanJobForRetry(newer.job_id, { lastError: "boom" })).toBe(true);
    expect(dag.getPrescanJob(newer.job_id)).toEqual(expect.objectContaining({ status: "queued", retries: 1, last_error: "boom", claimed_by: null }));
  });

  test("claim is single-winner: one queued job is never handed to two claimants", async () => {
    const dag = await makeDag();
    const job = prescanJob(uniq("job"), T0);
    dag.saveContent(contentRec(job.ctid, uniq("a")));
    dag.enqueuePrescanJob(job);

    const claims = await Promise.all(
      ["w1", "w2", "w3", "w4", "w5"].map(async (workerId) =>
        dag.claimPrescanJob({ workerId, now: T0 + 1000, claimTimeoutMs: 60000 })
      )
    );

    const winners = claims.filter(Boolean);
    expect(winners).toHaveLength(1);
    expect(winners[0].job_id).toBe(job.job_id);
  });

  // ── 8. Upload sessions (node-local ephemeral chunked-upload state) ───────

  test("createUploadSession / getUploadSession round-trip", async () => {
    const dag = await makeDag();
    const s = uploadSession(uniq("session"));
    dag.createUploadSession(s);

    const got = dag.getUploadSession(s.session_id);
    expect(got.session_id).toBe(s.session_id);
    expect(got.upload_id).toBe(s.upload_id);
    expect(got.content_hash).toBe(s.content_hash);
    expect(got.parts).toEqual([]);
    expect(got.completed_size).toBe(0);
  });

  test("updateUploadSession merges parts and completed_size", async () => {
    const dag = await makeDag();
    const s = uploadSession(uniq("session"));
    dag.createUploadSession(s);

    const updated = dag.updateUploadSession(s.session_id, {
      parts: [{ part_number: 1, etag: "e1" }],
      completed_size: 1024,
    });
    expect(updated.parts).toEqual([{ part_number: 1, etag: "e1" }]);
    expect(updated.completed_size).toBe(1024);

    const got = dag.getUploadSession(s.session_id);
    expect(got.completed_size).toBe(1024);
  });

  test("deleteUploadSession removes the session", async () => {
    const dag = await makeDag();
    const s = uploadSession(uniq("session"));
    dag.createUploadSession(s);
    expect(dag.getUploadSession(s.session_id)).not.toBeNull();

    dag.deleteUploadSession(s.session_id);
    expect(dag.getUploadSession(s.session_id)).toBeNull();
  });

  test("getUploadSession returns null and deletes an expired session", async () => {
    const dag = await makeDag();
    const s = uploadSession(uniq("session"), { expires_at: nowMs() - 1000 });
    dag.createUploadSession(s);
    expect(dag.getUploadSession(s.session_id)).toBeNull();
  });

  test("cleanupExpiredUploadSessions removes only expired rows", async () => {
    const dag = await makeDag();
    const expired = uploadSession(uniq("session"), { expires_at: nowMs() - 1000 });
    const live = uploadSession(uniq("session"), { expires_at: nowMs() + 3600000 });
    dag.createUploadSession(expired);
    dag.createUploadSession(live);

    expect(dag.cleanupExpiredUploadSessions(nowMs())).toBe(1);
    expect(dag.getUploadSession(expired.session_id)).toBeNull();
    expect(dag.getUploadSession(live.session_id)).not.toBeNull();
  });

  test("listExpiredUploadSessions returns expired rows (with upload_id/s3_key) without deleting", async () => {
    const dag = await makeDag();
    const expired = uploadSession(uniq("session"), { expires_at: nowMs() - 1000 });
    const live = uploadSession(uniq("session"), { expires_at: nowMs() + 3600000 });
    dag.createUploadSession(expired);
    dag.createUploadSession(live);

    const rows = dag.listExpiredUploadSessions(nowMs());
    const ids = rows.map(r => r.session_id);
    expect(ids).toContain(expired.session_id);
    expect(ids).not.toContain(live.session_id);
    const row = rows.find(r => r.session_id === expired.session_id);
    expect(row.upload_id).toBe(expired.upload_id); // fields cleanup needs to abort S3
    expect(row.s3_key).toBe(expired.s3_key);
    // read-only: a second call still returns it (unlike cleanup, which deletes)
    expect(dag.listExpiredUploadSessions(nowMs()).map(r => r.session_id)).toContain(expired.session_id);
  });

  test("generateUploadSessionId returns 32-char lowercase hex", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    track(dag);
    const id = dag.generateUploadSessionId();
    expect(id).toMatch(/^[0-9a-f]{32}$/);
  });

  // ── 9. Certificates / commits / votes_seen ──────────────────────────────

  test("certificates round-trip and pruneCertificatesBefore removes only rounds below the cutoff", async () => {
    const dag = await makeDag();
    const c1 = certRec(10, "node-a");
    const c2 = certRec(11, "node-a");
    const c3 = certRec(12, "node-b");
    for (const c of [c1, c2, c3]) dag.saveCertificate(c);

    expect(dag.getCertificate(c1.hash)).toEqual(expect.objectContaining({ hash: c1.hash, round: 10 }));
    expect(dag.getCertificatesByRound(11).map(c => c.hash)).toContain(c2.hash);
    expect(dag.getCertificateByAuthorRound("node-b", 12).hash).toBe(c3.hash);

    const pruned = dag.pruneCertificatesBefore(12);
    expect(pruned).toBe(2);
    expect(dag.getCertificate(c1.hash)).toBeNull();
    expect(dag.getCertificate(c3.hash)).not.toBeNull();
  });

  test("saveCommit is idempotent per round and consensus_meta replaces per key", async () => {
    const dag = await makeDag();
    dag.saveCommit(commitRec(50, { anchor_cert_hash: "a1" }));
    dag.saveCommit(commitRec(50, { anchor_cert_hash: "OVERWRITE", committee: ["nX"], consensus_index: 99 }));

    const commit = dag.getCommit(50);
    expect(commit.anchor_cert_hash).toBe("a1");
    expect(commit.committee).toEqual(["n1", "n2"]);
    expect(dag.getLatestCommit().round).toBeGreaterThanOrEqual(50);

    expect(dag.getConsensusMeta(`k-${storeName}`)).toBeNull();
    dag.setConsensusMeta(`k-${storeName}`, "v1");
    dag.setConsensusMeta(`k-${storeName}`, "v2");
    expect(dag.getConsensusMeta(`k-${storeName}`)).toBe("v2");
  });

  test("votes_seen is first-wins per (round, author) — equivocation defense", async () => {
    const dag = await makeDag();
    expect(dag.recordSeenVote(7, "node-a", "batch-1")).toBe(true);
    expect(dag.recordSeenVote(7, "node-a", "batch-EQUIVOCATION")).toBe(false);
    expect(dag.getSeenVote(7, "node-a")).toEqual(expect.objectContaining({ batch_hash: "batch-1" }));

    dag.recordSeenVote(8, "node-a", "batch-2");
    expect(dag.pruneVotesSeenBefore(8)).toBe(1);
    expect(dag.getSeenVote(7, "node-a")).toBeNull();
    expect(dag.getSeenVote(8, "node-a")).not.toBeNull();
  });

  // ── 10. Committee history ─────────────────────────────────────────────────

  test("committee rotations replace by rotation_number and resolve by effective_round boundary", async () => {
    const dag = await makeDag();
    const mkRotation = (rn, effectiveRound, committee) => ({
      rotation_number: rn, effective_round: effectiveRound, committee,
      prev_rotation: rn - 1, signer_node_ids: committee, signatures: [], payload_hash: `ph-${rn}`, committed_at: T0,
    });
    dag.saveCommitteeRotation(mkRotation(7, 100, ["n1", "n2", "n3"]));
    dag.saveCommitteeRotation(mkRotation(8, 200, ["n2", "n3", "n4"]));

    expect(dag.getCommitteeAtRound(150).rotation_number).toBe(7);
    expect(dag.getCommitteeAtRound(200).rotation_number).toBe(8);
    expect(dag.getCommitteeRotation(8).committee).toEqual(["n2", "n3", "n4"]);

    dag.saveCommitteeRotation(mkRotation(8, 200, ["nA", "nB", "nC"]));
    expect(dag.getCommitteeRotation(8).committee).toEqual(["nA", "nB", "nC"]);

    const rotations = [...dag.getRotationsFromGenesis()].map(r => r.rotation_number);
    expect(rotations).toEqual([...rotations].sort((a, b) => a - b));
  });

  // ── 11. Domain bindings + platform links ────────────────────────────────

  test("domain bindings and platform links round-trip; link status update merges", async () => {
    const dag = await makeDag();
    const tipId = uniq("US-link");
    const domain = `${uniq("example")}.org`;

    dag.saveDomainBinding({
      domain, tip_id: tipId, binding_state: "bound", method: "dns-txt",
      claimed_at: T0, verified_at: T0 + 1, expires_at: T0 + 1000, consecutive_failures: 0,
      node_id: "n1", claim_signature: "cs", binding_signature: "bs", tx_id: uniq("tx"),
    });
    expect(dag.getDomainBinding(domain)).toEqual(expect.objectContaining({ domain, tip_id: tipId, binding_state: "bound" }));
    expect(dag.getDomainBindingsByTipId(tipId).map(b => b.domain)).toContain(domain);

    dag.savePlatformLink({
      id: `${tipId}::youtube`, tip_id: tipId, platform: "youtube", handle: "@x",
      profile_url: "https://youtube.com/@x", status: "active", linked_at: T0, verified_at: T0,
      unlinked_at: null, unlink_tx_id: null, node_id: "n1", tx_id: uniq("tx"),
    });
    expect(dag.getPlatformLink(tipId, "youtube")).toEqual(expect.objectContaining({ platform: "youtube", status: "active" }));

    dag.updatePlatformLinkStatus(tipId, "youtube", { status: "unlinked", unlinked_at: T0 + 5, unlink_tx_id: uniq("tx") });
    const updated = dag.getPlatformLink(tipId, "youtube");
    expect(updated.status).toBe("unlinked");
    expect(updated.handle).toBe("@x");
  });

  // ── 12. Canonical state ──────────────────────────────────────────────────

  test("clearCanonicalState leaves zero canonical rows", async () => {
    const dag = await makeDag();
    const tipId = uniq("US-clear");
    dag.saveIdentity(identityRec(tipId));
    dag.saveContent(contentRec(uniq("ct"), tipId));
    dag.setScore(tipId, 500, 0, T0);
    dag.addDedupHash(uniq("dedup"), T0, tipId);

    expect([...dag.iterateCanonicalState()].length).toBeGreaterThan(0);
    dag.clearCanonicalState();

    expect([...dag.iterateCanonicalState()]).toHaveLength(0);
    expect(dag.getIdentity(tipId)).toBeNull();
    expect(dag.dedupCount()).toBe(0);
  });

  test("clearCanonicalState wipes the dedup tip_id registry — stale mappings must not survive reinstall", async () => {
    const dag = await makeDag();
    const hash = uniq("dedup");

    dag.addDedupHash(hash, 1111, uniq("US-old"));
    dag.clearCanonicalState();

    // Reinstall the same hash with no tip_id (pre-§dedup-tipId snapshots);
    // a leaked mapping here diverges state_merkle_root across peers.
    dag.addDedupHash(hash, 1111, null);
    expect(dag.getDedupRegistration(hash).tip_id).toBeNull();
  });

  test("getDedupEntry / getProtocolParamAt return exact canonical rows or null", async () => {
    const dag = await makeDag();
    const hash = uniq("dedup");
    dag.addDedupHash(hash, 1234, "tip://id/US-x");
    expect(dag.getDedupEntry(hash)).toEqual({ dedup_hash: hash, created_at: "1234", tip_id: "tip://id/US-x" });
    expect(dag.getDedupEntry(uniq("missing"))).toBeNull();

    const key = uniq("pp");
    dag.saveProtocolParam({ param_key: key, value: 7, effective_from_height: 3, update_tx_id: "aa" });
    expect(dag.getProtocolParamAt(key, 3)).toEqual({ param_key: key, value: "7", effective_from_height: 3, update_tx_id: "aa" });
    expect(dag.getProtocolParamAt(key, 4)).toBeNull();
  });

  test("pruneCanonicalStateExcept deletes exactly the rows absent from the keep-set", async () => {
    const dag = await makeDag();
    const keepId = uniq("US-keep");
    const dropId = uniq("US-drop");
    dag.saveIdentity(identityRec(keepId));

    // Baseline = genesis bootstrap + keepId. Everything added after this
    // point simulates diverged-fork rows the reconcile must remove.
    const baseline = [...dag.iterateCanonicalState()];
    const baselineRoot = computeStateMerkleRoot(dag);

    dag.saveIdentity(identityRec(dropId));
    dag.saveContent(contentRec(uniq("ct"), dropId));
    dag.addDedupHash(uniq("dedup"), T0, dropId);
    dag.saveProtocolParam({ param_key: uniq("pp"), value: 7, effective_from_height: 3, update_tx_id: "aa" });

    // Surgical single-row delete round-trips.
    expect(dag.deleteCanonicalRow("identities", { tip_id: dropId })).toBe(true);
    expect(dag.getIdentity(dropId)).toBeNull();
    dag.saveIdentity(identityRec(dropId));

    const keep = new Map();
    for (const { table, row } of baseline) {
      if (!keep.has(table)) keep.set(table, new Set());
      keep.get(table).add(canonicalPk(table, row));
    }
    const pruned = dag.pruneCanonicalStateExcept(keep);
    expect(pruned.length).toBeGreaterThan(0);
    expect(dag.getIdentity(dropId)).toBeNull();
    expect(dag.getIdentity(keepId)).toBeTruthy();

    // Post-prune state is byte-identical to the baseline, proving every
    // delete kept the SMT/root in sync.
    expect([...dag.iterateCanonicalState()]).toEqual(baseline);
    expect(computeStateMerkleRoot(dag)).toBe(baselineRoot);
  });

  // ── 13. runInTransaction ─────────────────────────────────────────────────

  atomic("runInTransaction rolls back every write when the callback throws", async () => {
    const dag = await makeDag();
    const tipId = uniq("US-txn");

    expect(() =>
      dag.runInTransaction(() => {
        dag.saveIdentity(identityRec(tipId));
        dag.setScore(tipId, 700, 0, T0);
        throw new Error("mid-commit crash");
      })
    ).toThrow("mid-commit crash");

    expect(dag.getIdentity(tipId)).toBeNull();
    expect(dag.getScore(tipId)).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Cross-store determinism: identical logical state must canonicalize to an
// identical row sequence on every implementation — this is the property
// state_merkle_root stands on. Insertion order is deliberately shuffled.
// ═══════════════════════════════════════════════════════════════════════════

test("cross-store: identical state yields identical canonical sequences regardless of insert order", () => {
  const a = track(initDAG({ dbPath: ":memory:" }));
  const b = track(initDAG({ dbPath: path.join(tmpDir, `conformance-cross-${fileSeq++}.db`) }));

  const tip1 = "US-cross-1";
  const tip2 = "US-cross-2";

  // Same rows, different insertion order
  a.saveIdentity(identityRec(tip1));
  a.saveIdentity(identityRec(tip2));
  a.saveContent(contentRec("ct-cross-1", tip1));
  a.setScore(tip1, 500, 0, T0);
  a.addDedupHash("dedup-cross-1", T0, tip1);

  b.addDedupHash("dedup-cross-1", T0, tip1);
  b.setScore(tip1, 500, 0, T0);
  b.saveContent(contentRec("ct-cross-1", tip1));
  b.saveIdentity(identityRec(tip2));
  b.saveIdentity(identityRec(tip1));

  const canon = (dag) => [...dag.iterateCanonicalState()].map(({ table, row }) => `${table}:${canonicalJson(row)}`);
  expect(canon(a)).toEqual(canon(b));
});
