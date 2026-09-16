/**
 * @file tests/workers/prescan-worker-jobs.test.js
 * @description Prescan worker against a classifier that runs media scans as
 * jobs: submit by client_ref, defer on 202 without spending a retry, poll on
 * the backoff schedule, and finish, resubmit or fail open on each job state.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */
"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");

const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const PC = require(path.join(SHARED, "protocol-constants"));
try { PC._resetForTesting(); } catch { /* already initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.resolve(__dirname, "../../src/dag"));
const { createPrescanJobs } = require(path.resolve(__dirname, "../../src/services/prescan-jobs"));
const { createPrescanWorker } = require(path.resolve(__dirname, "../../src/workers/prescan-worker"));
const { TX_TYPES, PRESCAN_JOB, PRESCAN_FAIL_OPEN_AFTER_MS } = require(path.join(SHARED, "constants"));

const MEDIA_ID = "cd".repeat(32);
const CTID = "tip://c/OH-7f2a91bc3d5e4a-b1c2";
const T0 = 1779800000000;

function verdict(probability = 0.9) {
  return {
    probability,
    modalities_analyzed: ["image"],
    modality_results: [{
      media_id: MEDIA_ID, modality: "image", probability, weight: 0.5,
      provider: "ensemble", error: null, processing_ms: 900,
    }],
    provider_used: "ensemble",
    classifier_version: "2.0.0",
    processing_ms: 1000,
  };
}

async function setup({ prescan, prescanStatus, maxBacklog = 0 }) {
  await initCrypto();
  const kp = generateMLDSAKeypair();
  let t = T0;
  const clock = { now: () => t, advance: (ms) => { t += ms; } };
  const dag = initDAG({ dbPath: ":memory-test:" });
  dag.saveNode?.({ node_id: "tip://node/efbe3707224fb785", public_key: kp.publicKey, status: "active" });
  const config = { nodeRegisteredId: "tip://node/efbe3707224fb785", nodePrivateKey: kp.privateKey, prescanMaxBacklog: maxBacklog };
  const jobs = createPrescanJobs({ dag, now: clock.now });
  const txs = [];
  const calls = { prescan: [], status: [] };
  const classifierClient = {
    prescan: async (args) => { calls.prescan.push(args); return prescan(args, calls.prescan.length); },
    prescanStatus: async (id) => { calls.status.push(id); return prescanStatus(id, calls.status.length); },
    stage1: async () => ({}), providers: async () => ({}), health: async () => ({}),
  };
  const mediaService = {
    async presignForClassifier(media, opts = {}) {
      return media.map(m => ({
        media_id: m.media_id, mime: m.mime, url: `https://bucket/${m.media_id}?ttl=${opts.ttlSec}`,
      }));
    },
  };
  const worker = createPrescanWorker({
    dag, jobs, classifierClient, config, mediaService,
    submitTx: (tx) => { txs.push(tx); return { tx_id: tx.tx_id }; },
    log: { info: () => {}, warn: () => {}, error: () => {} },
    now: clock.now,
    random: () => 0.5,
  });
  dag.saveContent({ ctid: CTID, origin_code: "OH", content_hash: "h", author_tip_id: "a", signer_tip_id: "a", cna_version: "v1", registered_at: T0 });
  const { job_id: jobId } = jobs.enqueue({
    ctid: CTID,
    payload: { origin_code: "OH", text: "", content_type: "image", media: [{ media_id: MEDIA_ID, mime: "image/png" }], creator_cleared_count: 0 },
  });
  return { dag, jobs, worker, clock, txs, calls, jobId };
}

const QUEUED = { pending: true, job_id: "cj_1", state: "queued", poll_after_ms: 30000 };
// The classifier's own poll_after_ms: the worker obeys it. Jitter neutralised by random() = 0.5.
const FIRST_DELAY = QUEUED.poll_after_ms;
// Content registered at T0, so the network commits the neutral verdict here.
const DEADLINE_AT = PRESCAN_FAIL_OPEN_AFTER_MS - PRESCAN_JOB.BUDGET_MARGIN_MS;

describe("media pre-scan as a classifier job", () => {
  test("a 202 stores the classifier job and defers without spending a retry", async () => {
    const s = await setup({ prescan: () => QUEUED, prescanStatus: () => ({ state: "running" }) });
    await s.worker.tick();
    expect(s.calls.prescan[0].clientRef).toBe(s.jobId);
    expect(s.calls.prescan[0].files[0].url).toContain(`ttl=${PRESCAN_JOB.MEDIA_URL_TTL_SEC}`);
    const row = s.dag.getPrescanJob(s.jobId);
    expect(row).toEqual(expect.objectContaining({ status: "queued", retries: 0, classifier_job_id: "cj_1", classifier_polls: 0 }));
    expect(row.retry_after).toBe(T0 + FIRST_DELAY);
    expect(s.txs).toHaveLength(0);
  });

  test("the job is not polled before its first delay, then polls on the backoff schedule", async () => {
    const s = await setup({ prescan: () => QUEUED, prescanStatus: () => ({ state: "running" }) });
    await s.worker.tick();
    s.clock.advance(FIRST_DELAY - 1);
    await s.worker.tick();
    expect(s.calls.status).toHaveLength(0);
    s.clock.advance(1);
    await s.worker.tick();
    expect(s.calls.status).toEqual(["cj_1"]);
    const row = s.dag.getPrescanJob(s.jobId);
    expect(row).toEqual(expect.objectContaining({ classifier_polls: 1, retries: 0 }));
    expect(row.retry_after).toBe(T0 + FIRST_DELAY + PRESCAN_JOB.POLL_STEPS_MS[0]);
  });

  test("a done job emits the verdict through the normal path", async () => {
    const s = await setup({ prescan: () => QUEUED, prescanStatus: () => ({ state: "done", result: verdict(0.9) }) });
    await s.worker.tick();
    s.clock.advance(FIRST_DELAY);
    await s.worker.tick();
    expect(s.txs).toHaveLength(1);
    expect(s.txs[0].tx_type).toBe(TX_TYPES.PRESCAN_COMPLETED);
    expect(s.txs[0].data.failed).toBe(false);
    expect(s.txs[0].data.media_results[0]).toEqual(expect.objectContaining({ media_id: MEDIA_ID, probability: 0.9 }));
    expect(s.dag.getPrescanJob(s.jobId)).toBeNull();
  });

  test("a lost job is resubmitted by the same client_ref", async () => {
    const s = await setup({
      prescan: (args, n) => (n === 1 ? QUEUED : { ...QUEUED, job_id: "cj_2" }),
      prescanStatus: () => ({ state: "lost" }),
    });
    await s.worker.tick();
    s.clock.advance(FIRST_DELAY);
    await s.worker.tick();
    expect(s.dag.getPrescanJob(s.jobId).classifier_job_id).toBeNull();
    await s.worker.tick();
    expect(s.calls.prescan).toHaveLength(2);
    expect(s.calls.prescan[1].clientRef).toBe(s.jobId);
    expect(s.dag.getPrescanJob(s.jobId)).toEqual(expect.objectContaining({ classifier_job_id: "cj_2", retries: 0 }));
  });

  test("a failed job clears the classifier job and goes through the retry budget", async () => {
    const s = await setup({ prescan: () => QUEUED, prescanStatus: () => ({ state: "failed", error: "server_restart" }) });
    await s.worker.tick();
    s.clock.advance(FIRST_DELAY);
    await s.worker.tick();
    const row = s.dag.getPrescanJob(s.jobId);
    expect(row).toEqual(expect.objectContaining({ status: "queued", retries: 1, classifier_job_id: null }));
    expect(row.last_error).toContain("server_restart");
    expect(s.txs).toHaveLength(0);
  });

  test("a job that failed on unscannable media fails open at once", async () => {
    const s = await setup({ prescan: () => QUEUED, prescanStatus: () => ({ state: "failed", error: "file_too_large" }) });
    await s.worker.tick();
    s.clock.advance(FIRST_DELAY);
    await s.worker.tick();
    expect(s.txs).toHaveLength(1);
    expect(s.txs[0].data).toEqual(expect.objectContaining({ failed: true, failure_reason: "classifier_rejected_media: file_too_large" }));
  });

  test("a failed status poll keeps waiting and never spends a retry", async () => {
    const s = await setup({ prescan: () => QUEUED, prescanStatus: () => { throw { code: "classifier_timeout", message: "slow" }; } });
    await s.worker.tick();
    s.clock.advance(FIRST_DELAY);
    await s.worker.tick();
    expect(s.dag.getPrescanJob(s.jobId)).toEqual(expect.objectContaining({ status: "queued", retries: 0, classifier_job_id: "cj_1", classifier_polls: 1 }));
    expect(s.txs).toHaveLength(0);
  });

  test("a job still running at the network's fail-open deadline fails open", async () => {
    const s = await setup({ prescan: () => QUEUED, prescanStatus: () => ({ state: "running" }) });
    await s.worker.tick();
    s.clock.advance(DEADLINE_AT - 1);
    await s.worker.tick();
    expect(s.txs).toHaveLength(0);
    s.clock.advance(PRESCAN_JOB.POLL_STEPS_MS[0] + 1);
    await s.worker.tick();
    expect(s.txs).toHaveLength(1);
    expect(s.txs[0].data).toEqual(expect.objectContaining({ failed: true, failure_reason: "classifier_job_timeout" }));
  });

  // The deadline is measured from the content's registration, the same clock the
  // cross-node trigger uses, not from when the classifier accepted the job.
  test("content registered earlier reaches the deadline earlier", async () => {
    const s = await setup({ prescan: () => QUEUED, prescanStatus: () => ({ state: "running" }) });
    const content = s.dag.getContent(CTID);
    s.dag.saveContent({ ...content, ctid: CTID, registered_at: content.registered_at - 600_000 });
    await s.worker.tick();
    s.clock.advance(DEADLINE_AT - 600_000 + 1);
    await s.worker.tick();
    expect(s.txs).toHaveLength(1);
    expect(s.txs[0].data.failure_reason).toBe("classifier_job_timeout");
  });

  test("a later poll waits as long as the classifier asks", async () => {
    const s = await setup({
      prescan: () => QUEUED,
      prescanStatus: () => ({ state: "running", poll_after_ms: 200_000 }),
    });
    await s.worker.tick();
    s.clock.advance(FIRST_DELAY);
    await s.worker.tick();
    expect(s.dag.getPrescanJob(s.jobId).retry_after).toBe(T0 + FIRST_DELAY + 200_000);
  });

  test("a submit cut off by a timeout is resent once by client_ref", async () => {
    const s = await setup({
      prescan: (args, n) => { if (n === 1) throw { code: "classifier_timeout", message: "cut" }; return QUEUED; },
      prescanStatus: () => ({ state: "running" }),
    });
    await s.worker.tick();
    expect(s.calls.prescan).toHaveLength(2);
    expect(s.calls.prescan[1].clientRef).toBe(s.jobId);
    expect(s.dag.getPrescanJob(s.jobId)).toEqual(expect.objectContaining({ classifier_job_id: "cj_1", retries: 0 }));
  });

  test("a classifier that answers 200 keeps the synchronous path", async () => {
    const s = await setup({ prescan: () => verdict(0.2), prescanStatus: () => { throw new Error("must not poll"); } });
    await s.worker.tick();
    expect(s.calls.status).toHaveLength(0);
    expect(s.txs).toHaveLength(1);
    expect(s.txs[0].data.failed).toBe(false);
    expect(s.dag.getPrescanJob(s.jobId)).toBeNull();
  });
});
