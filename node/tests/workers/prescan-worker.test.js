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
const { TX_TYPES } = require(path.join(SHARED, "constants"));

// ── Mocks + helpers ───────────────────────────────────────────────────────
function makeClock(start = 1779800000000) {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; }, set: (ms) => { t = ms; } };
}

function makeSubmitter() {
  const txs = [];
  return { submitTx: (tx) => { txs.push(tx); return { tx_id: tx.tx_id }; }, txs };
}

// Build a classifier-client mock from a single response generator. The
// generator receives ({ originCode, text, file }) and returns a partial
// /v1/prescan response shape that we use to populate modality_results.
function makeClassifier(handler) {
  return {
    prescan: async (args) => handler(args),
    stage1:  async () => ({}),
    providers: async () => ({}),
    health:    async () => ({}),
  };
}

// Helper: deterministic response shape matching real /v1/prescan.
function R({ modalities = [], provider = "ensemble(ollama,statistical,heuristic)", version = "2.0.0", skipped = false }) {
  if (skipped) {
    return {
      flagged: false, probability: 0, modalities_analyzed: [], modality_results: [],
      provider_used: "skipped_locally", processing_ms: 0, locally_skipped: true,
    };
  }
  const top = modalities.length ? modalities.map(m => m.probability).reduce((a, b) => Math.max(a, b)) : 0;
  return {
    flagged: false,
    probability: top,
    modalities_analyzed: modalities.map(m => m.modality),
    modality_results: modalities.map(m => ({
      modality: m.modality,
      probability: m.probability,
      weight: m.weight ?? 0.5,
      provider: m.provider || provider,
      features_used: m.features_used || [],
      reasoning: null,
      processing_ms: 1000,
      error: m.error || null,
    })),
    provider_used: provider,
    classifier_version: version,
    processing_ms: 1500,
    recommended_status: "verified",
    grace_window_hours: 24,
    note: null,
  };
}

async function setup({ now, classifierHandler }) {
  await initCrypto();
  const kp = generateMLDSAKeypair();
  const dag = initDAG({ dbPath: ":memory-test:" });
  // Register the worker's signing node so verifyTx-style checks downstream
  // (commit-handler) won't reject. Worker tests don't run commit-handler;
  // we only validate tx shape + queue state here.
  dag.saveNode?.({
    node_id: "tip://node/efbe3707224fb785",
    public_key: kp.publicKey,
    status: "active",
  });
  const config = {
    nodeRegisteredId: "tip://node/efbe3707224fb785",
    nodePrivateKey: kp.privateKey,
  };
  const jobs = createPrescanJobs({ dag, now });
  const submitter = makeSubmitter();
  const classifier = makeClassifier(classifierHandler);
  const worker = createPrescanWorker({
    dag, jobs, classifierClient: classifier,
    submitTx: submitter.submitTx, config,
    log: { info: () => {}, warn: () => {}, error: () => {} },
    now,
  });
  return { dag, jobs, classifier, submitter, worker };
}

const CTID = "tip://c/OH-7f2a91bc3d5e4a-a3f8";

// ── tick — happy path ─────────────────────────────────────────────────────
describe("tick — happy path", () => {
  test("text-only OH content → emits PRESCAN_COMPLETED with clean verdict", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => R({ modalities: [{ modality: "text", probability: 0.21 }] }),
    });
    jobs.enqueue({
      ctid: CTID,
      payload: { text: "human-ish writing", origin_code: "OH", content_type: "text" },
    });
    const r = await worker.tick();
    expect(r.outcome).toBe("completed");
    expect(submitter.txs).toHaveLength(1);
    const tx = submitter.txs[0];
    expect(tx.tx_type).toBe(TX_TYPES.PRESCAN_COMPLETED);
    expect(tx.data.ctid).toBe(CTID);
    expect(tx.data.probability).toBe(0.21);
    expect(tx.data.tier).toBe("low");
    expect(tx.data.flagged).toBe(false);
    expect(tx.data.overall_degraded).toBe(false);
    expect(tx.data.failed).toBe(false);
    expect(tx.data.content_type).toBe("text");
    expect(jobs.get(jobs.getByCtid(CTID).job_id).status).toBe("done");
  });

  test("CRITICAL probability → tier + flagged set", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => R({ modalities: [{ modality: "text", probability: 0.985 }] }),
    });
    jobs.enqueue({
      ctid: CTID,
      payload: { text: "ai-style", origin_code: "OH", content_type: "text" },
    });
    await worker.tick();
    expect(submitter.txs[0].data.tier).toBe("critical");
    expect(submitter.txs[0].data.flagged).toBe(true);
  });

  test("non-OH origin → locally skipped, no modality results, fail-open-style verdict", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      // Mirror the real classifier-client's behaviour: short-circuit on
      // non-OH origins by returning the skipped shape.
      classifierHandler: (args) => args.originCode === "OH"
        ? R({ modalities: [{ modality: "text", probability: 0.1 }] })
        : R({ skipped: true }),
    });
    jobs.enqueue({
      ctid: CTID,
      payload: { text: "x", origin_code: "AG", content_type: "text" },
    });
    await worker.tick();
    expect(submitter.txs[0].data.probability).toBe(0);
    expect(submitter.txs[0].data.tier).toBe("low");
    expect(submitter.txs[0].data.flagged).toBe(false);
    expect(submitter.txs[0].data.failed).toBe(false);
    expect(submitter.txs[0].data.modality_results).toEqual([]);
  });

  test("multimodal text + image → single classifier call, both modalities in tx", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker, classifier } = await setup({
      now: clock.now,
      classifierHandler: () => R({ modalities: [
        { modality: "text",  probability: 0.30 },
        { modality: "image", probability: 0.80 },
      ] }),
    });
    jobs.enqueue({
      ctid: CTID,
      payload: {
        text: "caption",
        origin_code: "OH",
        content_type: "image",
        media: [{ base64: "<b64>", mime: "image/png" }],
      },
    });
    await worker.tick();
    expect(submitter.txs[0].data.modality_results).toHaveLength(2);
    const m = submitter.txs[0].data.modality_results.map(x => x.modality).sort();
    expect(m).toEqual(["image", "text"]);
  });

  test("N images → N classifier calls + union of modality_results", async () => {
    const clock = makeClock();
    let callCount = 0;
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: (args) => {
        callCount += 1;
        // First call: text + image
        if (callCount === 1) {
          return R({ modalities: [
            { modality: "text", probability: 0.10 },
            { modality: "image", probability: 0.40 },
          ] });
        }
        return R({ modalities: [{ modality: "image", probability: 0.95 }] });
      },
    });
    jobs.enqueue({
      ctid: CTID,
      payload: {
        text: "x", origin_code: "OH", content_type: "image",
        media: [
          { base64: "b64a", mime: "image/png" },
          { base64: "b64b", mime: "image/jpeg" },
        ],
      },
    });
    await worker.tick();
    expect(callCount).toBe(2);
    // After collapseSameModality, the image entry should be the max (0.95).
    const tx = submitter.txs[0];
    const img = tx.data.modality_results.find(m => m.modality === "image");
    expect(img.probability).toBe(0.95);
  });
});

// ── tick — degraded path ──────────────────────────────────────────────────
describe("tick — degraded signal handling", () => {
  test("hard-degraded response (forced 0.5) → release for retry (under retry budget)", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => R({ modalities: [{ modality: "text", probability: 0.5 }] }),
    });
    jobs.enqueue({
      ctid: CTID,
      payload: { text: "x", origin_code: "OH", content_type: "text" },
    });
    await worker.tick();
    expect(submitter.txs).toHaveLength(0);
    const job = jobs.getByCtid(CTID);
    expect(job.status).toBe("queued");
    expect(job.retries).toBe(1);
    expect(job.last_error).toBe("hard_degraded_signal");
  });

  test("hard-degraded + retries exhausted → fail-open with overall_degraded=true", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => R({ modalities: [{ modality: "text", probability: 0.5 }] }),
    });
    jobs.enqueue({
      ctid: CTID,
      payload: { text: "x", origin_code: "OH", content_type: "text" },
    });
    for (let i = 0; i <= PC.PRESCAN_WORKER.MAX_RETRIES_ON_DEGRADED; i++) {
      clock.advance(PC.PRESCAN_WORKER.CLAIM_TIMEOUT_MS + 1);
      await worker.tick();
    }
    expect(submitter.txs).toHaveLength(1);
    const tx = submitter.txs[0];
    expect(tx.data.failed).toBe(true);
    // probability=0.5 is the canonical "no signal" neutral; 0 would have
    // implied "definitely human." overall_degraded=true surfaces the
    // placeholder so downstream doesn't treat it as a real verdict.
    expect(tx.data.probability).toBe(0.5);
    expect(tx.data.overall_degraded).toBe(true);
    // Tier + flagged are derived via tierFromProbability(0.5) so the
    // schema's tier-vs-probability consistency check passes regardless
    // of threshold tuning. We don't pin the exact tier here.
    expect(["low", "elevated"]).toContain(tx.data.tier);
    expect(tx.data.flagged).toBe(false);
    expect(tx.data.failure_reason).toMatch(/hard_degraded_after_retries/);
    expect(jobs.getByCtid(CTID).status).toBe("failed");
  });

  test("hard-degraded fail-open preserves classifier's probability when a non-hard modality contributed", async () => {
    // Mixed result: clean text (0.42) + hard-degraded image (error). The
    // aggregator's overall_hard_degraded=true (image is hard) triggers the
    // retry path, but the aggregator's probability comes from the working
    // text modality. After retries exhaust, fail-open must NOT overwrite
    // that real number with 0.5 — the classifier did give us something
    // usable. 0.5 is reserved for the case where the classifier produced
    // no usable signal at all.
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => R({
        modalities: [
          { modality: "text", probability: 0.42 },
          { modality: "image", probability: 0.5, error: "no_signals_produced_a_result" },
        ],
      }),
    });
    jobs.enqueue({
      ctid: CTID,
      payload: { text: "hi", origin_code: "OH", content_type: "multi" },
    });
    for (let i = 0; i <= PC.PRESCAN_WORKER.MAX_RETRIES_ON_DEGRADED; i++) {
      clock.advance(PC.PRESCAN_WORKER.CLAIM_TIMEOUT_MS + 1);
      await worker.tick();
    }
    expect(submitter.txs).toHaveLength(1);
    const tx = submitter.txs[0];
    expect(tx.data.failed).toBe(true);
    expect(tx.data.overall_degraded).toBe(true);
    // The clean text modality's contribution survives the fail-open; we
    // do not assert the exact number (it depends on weights) but it must
    // not be the no-signal neutral 0.5 — that would be the failure value.
    expect(tx.data.probability).not.toBe(0.5);
    expect(Number.isFinite(tx.data.probability)).toBe(true);
  });

  test("soft-degraded (disagreement_override) → ships real probability through with overall_degraded=true, no retry", async () => {
    // Live reproducer: classifier returned prob=0.2113 with
    // disagreement_override flagged (statistical provider skipped because
    // text was too short to score). Same input → same response on every
    // retry, so the worker must record the classifier's honest
    // low-confidence answer instead of burning the retry budget.
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => R({
        modalities: [{
          modality: "text",
          probability: 0.2113,
          features_used: ["provider_ensemble", "disagreement_override"],
        }],
      }),
    });
    jobs.enqueue({
      ctid: CTID,
      payload: { text: "short", origin_code: "OH", content_type: "text" },
    });
    await worker.tick();
    expect(submitter.txs).toHaveLength(1);
    const tx = submitter.txs[0];
    expect(tx.data.failed).toBe(false);
    expect(tx.data.flagged).toBe(false);
    expect(tx.data.probability).toBeCloseTo(0.2113, 6);
    expect(tx.data.tier).toBe("low");
    expect(tx.data.overall_degraded).toBe(true);
    expect(jobs.getByCtid(CTID).status).toBe("done");
  });
});

// ── tick — hard error path ────────────────────────────────────────────────
describe("tick — hard error handling", () => {
  test("classifier throws → release for retry", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => { throw new Error("ECONNREFUSED"); },
    });
    jobs.enqueue({
      ctid: CTID,
      payload: { text: "x", origin_code: "OH", content_type: "text" },
    });
    await worker.tick();
    expect(submitter.txs).toHaveLength(0);
    const job = jobs.getByCtid(CTID);
    expect(job.status).toBe("queued");
    expect(job.retries).toBe(1);
    expect(job.last_error).toBe("ECONNREFUSED");
  });

  test("hard error + retries exhausted → fail-open", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => { throw new Error("ECONNREFUSED"); },
    });
    jobs.enqueue({
      ctid: CTID,
      payload: { text: "x", origin_code: "OH", content_type: "text" },
    });
    for (let i = 0; i <= PC.PRESCAN_WORKER.MAX_RETRIES_ON_ERROR; i++) {
      clock.advance(PC.PRESCAN_WORKER.CLAIM_TIMEOUT_MS + 1);
      await worker.tick();
    }
    expect(submitter.txs).toHaveLength(1);
    expect(submitter.txs[0].data.failed).toBe(true);
    expect(submitter.txs[0].data.failure_reason).toMatch(/error_after_retries/);
  });
});

// ── tick — unhandled-exception path emits fail-open ───────────────────────
describe("tick — unexpected errors → fail-open (not just markFailed)", () => {
  // The worker's catch handlers previously called jobs.markFailed without
  // submitting any tx, leaving the chain in PENDING_PRESCAN until the
  // cross-node trigger fired at FAIL_OPEN_AFTER_MS. They now emit a
  // fail-open immediately so the local queue and chain agree.

  test("payload-not-parseable → fail-open emitted", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => R({ modalities: [] }),
    });
    // Stub claim() to hand back a job with a non-object payload — simulates
    // corrupted queue data that survived the decode step in prescan-jobs.
    jobs.claim = () => ({
      job_id: "pj_corrupt_test",
      ctid: CTID,
      payload: "not-an-object-payload",
      retries: 0,
    });
    await worker.tick();
    expect(submitter.txs).toHaveLength(1);
    expect(submitter.txs[0].tx_type).toBe(TX_TYPES.PRESCAN_COMPLETED);
    expect(submitter.txs[0].data.failed).toBe(true);
    expect(submitter.txs[0].data.failure_reason).toBe("payload_not_parseable");
  });

  test("unhandled error in processing → fail-open emitted (tick path)", async () => {
    const clock = makeClock();
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      // Throw a non-Error to bypass _handleHardFailure's normal retry path —
      // simulates a programmer bug that escapes _processJob.
      classifierHandler: () => R({ modalities: [{ modality: "text", probability: 0.7 }] }),
    });
    jobs.enqueue({ ctid: CTID, payload: { text: "x", origin_code: "OH", content_type: "text" } });

    // Patch jobs.markDone to throw — this simulates an unexpected error
    // that escapes _processJob's normal retry/fail-open accounting.
    const originalMarkDone = jobs.markDone;
    jobs.markDone = () => { throw new Error("simulated post-classification crash"); };
    try {
      const result = await worker.tick();
      expect(result.outcome).toBe("crashed");
    } finally {
      jobs.markDone = originalMarkDone;
    }

    // First tx is the success verdict submitted before markDone threw;
    // second is the fail-open emitted by the catch handler.
    const failOpens = submitter.txs.filter(tx => tx?.data?.failed === true);
    expect(failOpens).toHaveLength(1);
    expect(failOpens[0].data.failure_reason).toMatch(/worker_crash/);
  });
});

// ── tick — empty queue ────────────────────────────────────────────────────
describe("tick — idle", () => {
  test("returns worked:false when no jobs available", async () => {
    const clock = makeClock();
    const { worker } = await setup({
      now: clock.now,
      classifierHandler: () => R({ modalities: [{ modality: "text", probability: 0.1 }] }),
    });
    const r = await worker.tick();
    expect(r).toEqual({ worked: false });
  });
});

describe("run — concurrency", () => {
  test("processes jobs in parallel up to opts.concurrency", async () => {
    const clock = makeClock();
    // Each classifier call resolves only when we let it. Tracks in-flight
    // count at the moment the classifier was entered — high water mark
    // proves we ran more than one at the same time.
    let inFlight = 0;
    let peakInFlight = 0;
    const pending = [];
    const { jobs, submitter, worker } = await setup({
      now: clock.now,
      classifierHandler: () => new Promise(resolve => {
        inFlight += 1;
        peakInFlight = Math.max(peakInFlight, inFlight);
        pending.push(() => {
          inFlight -= 1;
          resolve(R({ modalities: [{ modality: "text", probability: 0.1 }] }));
        });
      }),
    });

    // Enqueue 5 jobs
    for (let i = 0; i < 5; i++) {
      jobs.enqueue({
        ctid: `tip://c/OH-${String(i).padStart(14, "0")}-0001`,
        payload: { text: `job ${i}`, origin_code: "OH", content_type: "text" },
      });
    }

    // Start the loop in the background with concurrency=3
    const runPromise = worker.run({ concurrency: 3 });

    // Wait briefly for the loop to claim and dispatch the first batch
    await new Promise(r => setTimeout(r, 50));
    expect(inFlight).toBe(3);
    expect(peakInFlight).toBe(3);

    // Resolve all 5 classifier calls so the loop can drain
    while (pending.length > 0 || inFlight > 0) {
      const r = pending.shift();
      if (r) r();
      await new Promise(r => setTimeout(r, 10));
    }

    worker.stop();
    await runPromise;

    expect(submitter.txs).toHaveLength(5);
    expect(peakInFlight).toBe(3);
  });

  test("reads concurrency from TIP_PRESCAN_CONCURRENCY env when opts.concurrency unset", async () => {
    const saved = process.env.TIP_PRESCAN_CONCURRENCY;
    process.env.TIP_PRESCAN_CONCURRENCY = "2";
    try {
      const clock = makeClock();
      let inFlight = 0;
      let peakInFlight = 0;
      const pending = [];
      const { jobs, worker, submitter } = await setup({
        now: clock.now,
        classifierHandler: () => new Promise(resolve => {
          inFlight += 1;
          peakInFlight = Math.max(peakInFlight, inFlight);
          pending.push(() => { inFlight -= 1; resolve(R({ modalities: [{ modality: "text", probability: 0.1 }] })); });
        }),
      });
      for (let i = 0; i < 4; i++) {
        jobs.enqueue({
          ctid: `tip://c/OH-${String(i).padStart(14, "e")}-0002`,
          payload: { text: `j${i}`, origin_code: "OH", content_type: "text" },
        });
      }
      const runPromise = worker.run();
      await new Promise(r => setTimeout(r, 50));
      expect(peakInFlight).toBe(2);    // env says 2
      while (pending.length > 0 || inFlight > 0) {
        pending.shift()?.();
        await new Promise(r => setTimeout(r, 10));
      }
      worker.stop();
      await runPromise;
      expect(submitter.txs).toHaveLength(4);
    } finally {
      if (saved === undefined) delete process.env.TIP_PRESCAN_CONCURRENCY;
      else process.env.TIP_PRESCAN_CONCURRENCY = saved;
    }
  });

  test("default concurrency = 1 (sequential — back-compat)", async () => {
    const clock = makeClock();
    let inFlight = 0;
    let peakInFlight = 0;
    const pending = [];
    const { jobs, worker, submitter } = await setup({
      now: clock.now,
      classifierHandler: () => new Promise(resolve => {
        inFlight += 1;
        peakInFlight = Math.max(peakInFlight, inFlight);
        pending.push(() => { inFlight -= 1; resolve(R({ modalities: [{ modality: "text", probability: 0.1 }] })); });
      }),
    });
    for (let i = 0; i < 3; i++) {
      jobs.enqueue({
        ctid: `tip://c/OH-${String(i).padStart(14, "d")}-0003`,
        payload: { text: `s${i}`, origin_code: "OH", content_type: "text" },
      });
    }
    const runPromise = worker.run();   // no opts, no env → defaults to 1
    await new Promise(r => setTimeout(r, 50));
    expect(peakInFlight).toBe(1);
    while (pending.length > 0 || inFlight > 0) {
      pending.shift()?.();
      await new Promise(r => setTimeout(r, 10));
    }
    worker.stop();
    await runPromise;
    expect(submitter.txs).toHaveLength(3);
  });

  test("stop() drains in-flight jobs before returning", async () => {
    const clock = makeClock();
    let resolveFn;
    const classifierPromise = new Promise(resolve => { resolveFn = resolve; });
    const { jobs, worker, submitter } = await setup({
      now: clock.now,
      classifierHandler: () => classifierPromise.then(() =>
        R({ modalities: [{ modality: "text", probability: 0.1 }] })),
    });
    jobs.enqueue({
      ctid: "tip://c/OH-drain000000000-0004",
      payload: { text: "drain", origin_code: "OH", content_type: "text" },
    });
    const runPromise = worker.run({ concurrency: 2 });
    await new Promise(r => setTimeout(r, 50));
    worker.stop();
    // Submission hasn't happened yet — classifier still hanging
    expect(submitter.txs).toHaveLength(0);
    resolveFn();
    await runPromise;
    // After run() resolves, the in-flight job has settled and emitted
    expect(submitter.txs).toHaveLength(1);
  });
});
