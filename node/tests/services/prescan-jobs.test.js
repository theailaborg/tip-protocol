"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");

const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const PC = require(path.join(SHARED, "protocol-constants"));
try { PC._resetForTesting(); } catch { /* not yet initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const { initDAG } = require(path.resolve(__dirname, "../../src/dag"));
const { createPrescanJobs } = require(path.resolve(__dirname, "../../src/services/prescan-jobs"));

// ── Helpers ────────────────────────────────────────────────────────────────
function makeClock(start = 1779800000000) {
  let t = start;
  return {
    now: () => t,
    advance: (ms) => { t += ms; },
    set: (ms) => { t = ms; },
  };
}

function setup({ now }) {
  const dag = initDAG({ dbPath: ":memory-test:" });
  const jobs = createPrescanJobs({ dag, now });
  return { dag, jobs };
}

const CTID_A = "tip://c/OH-7f2a91bc3d5e4a-a3f8";
const CTID_B = "tip://c/OH-1234567890abcd-ef01";

// ── enqueue ────────────────────────────────────────────────────────────────
describe("enqueue", () => {
  test("returns job_id with enqueued=true on first call", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const r = jobs.enqueue({ ctid: CTID_A, payload: { text: "hi" } });
    expect(r.job_id).toMatch(/^pj_/);
    expect(r.enqueued).toBe(true);
  });

  test("idempotent on same ctid (enqueued=false, same job_id)", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const first = jobs.enqueue({ ctid: CTID_A, payload: { text: "hi" } });
    const second = jobs.enqueue({ ctid: CTID_A, payload: { text: "different" } });
    expect(second.job_id).toBe(first.job_id);
    expect(second.enqueued).toBe(false);
  });

  test("missing ctid throws", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    expect(() => jobs.enqueue({ payload: { x: 1 } })).toThrow(/ctid required/);
  });

  test("missing payload throws", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    expect(() => jobs.enqueue({ ctid: CTID_A })).toThrow(/payload required/);
  });
});

// ── claim ─────────────────────────────────────────────────────────────────
describe("claim", () => {
  test("returns null when queue is empty", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    expect(jobs.claim("worker-1")).toBeNull();
  });

  test("claims the only queued job", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const { job_id } = jobs.enqueue({ ctid: CTID_A, payload: { text: "hi" } });
    const claimed = jobs.claim("worker-1");
    expect(claimed.job_id).toBe(job_id);
    expect(claimed.status).toBe("claimed");
    expect(claimed.claimed_by).toBe("worker-1");
    expect(claimed.claimed_at).toBe(clock.now());
  });

  test("claims oldest queued job first (FIFO by created_at)", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const first = jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    clock.advance(100);
    jobs.enqueue({ ctid: CTID_B, payload: { x: 2 } });
    const claimed = jobs.claim("worker-1");
    expect(claimed.job_id).toBe(first.job_id);
  });

  test("returns null when only claimed (non-stuck) jobs exist", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    jobs.claim("worker-1");                          // claims it
    expect(jobs.claim("worker-2")).toBeNull();       // nothing else available
  });

  test("re-claims a stuck job after worker_claim_timeout_ms", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const { job_id } = jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    jobs.claim("worker-1");
    // Advance past CLAIM_TIMEOUT_MS (60s by default)
    clock.advance(PC.PRESCAN_WORKER.CLAIM_TIMEOUT_MS + 1);
    const reclaimed = jobs.claim("worker-2");
    expect(reclaimed.job_id).toBe(job_id);
    expect(reclaimed.claimed_by).toBe("worker-2");
  });

  test("payload is parsed back from canonical JSON", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    jobs.enqueue({ ctid: CTID_A, payload: { text: "hello", media: [{ mime: "image/png" }] } });
    const claimed = jobs.claim("worker-1");
    expect(claimed.payload).toEqual({ text: "hello", media: [{ mime: "image/png" }] });
  });

  test("missing workerId throws", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    expect(() => jobs.claim()).toThrow(/workerId required/);
  });
});

// ── markDone ───────────────────────────────────────────────────────────────
describe("markDone", () => {
  test("flips status to done + clears last_error", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const { job_id } = jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    jobs.claim("worker-1");
    expect(jobs.markDone(job_id)).toBe(true);
    const after = jobs.get(job_id);
    expect(after.status).toBe("done");
    expect(after.completed_at).toBe(clock.now());
    expect(after.last_error).toBeNull();
  });

  test("returns false on unknown job_id", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    expect(jobs.markDone("pj_doesnotexist")).toBe(false);
  });
});

// ── markFailed ─────────────────────────────────────────────────────────────
describe("markFailed", () => {
  test("flips status to failed + records error message (string)", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const { job_id } = jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    jobs.claim("worker-1");
    jobs.markFailed(job_id, "classifier timeout");
    const after = jobs.get(job_id);
    expect(after.status).toBe("failed");
    expect(after.last_error).toBe("classifier timeout");
  });

  test("Error object → records .message", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const { job_id } = jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    jobs.claim("worker-1");
    jobs.markFailed(job_id, new Error("ECONNREFUSED"));
    expect(jobs.get(job_id).last_error).toBe("ECONNREFUSED");
  });
});

// ── releaseForRetry ────────────────────────────────────────────────────────
describe("releaseForRetry", () => {
  test("flips status back to queued + increments retries", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const { job_id } = jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    jobs.claim("worker-1");
    jobs.releaseForRetry(job_id, "degraded_signal");
    const after = jobs.get(job_id);
    expect(after.status).toBe("queued");
    expect(after.retries).toBe(1);
    expect(after.last_error).toBe("degraded_signal");
    expect(after.claimed_at).toBeNull();
    expect(after.claimed_by).toBeNull();
  });

  test("released job is claimable again immediately", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const { job_id } = jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    jobs.claim("worker-1");
    jobs.releaseForRetry(job_id, "transient_error");
    const reclaimed = jobs.claim("worker-2");
    expect(reclaimed.job_id).toBe(job_id);
    expect(reclaimed.retries).toBe(1);
  });

  test("retries accumulate across multiple release cycles", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const { job_id } = jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    for (let i = 0; i < 3; i++) {
      jobs.claim("worker-1");
      jobs.releaseForRetry(job_id, `attempt-${i}`);
    }
    expect(jobs.get(job_id).retries).toBe(3);
  });
});

// ── getByCtid ──────────────────────────────────────────────────────────────
describe("getByCtid", () => {
  test("returns the row if it exists", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    const { job_id } = jobs.enqueue({ ctid: CTID_A, payload: { x: 1 } });
    expect(jobs.getByCtid(CTID_A).job_id).toBe(job_id);
  });
  test("returns null for unknown ctid", () => {
    const clock = makeClock();
    const { jobs } = setup(clock);
    expect(jobs.getByCtid("tip://c/missing")).toBeNull();
  });
});
