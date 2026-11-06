/**
 * @file tests/integration/email-registration.test.js
 * @description Email registrations stay private on the node.
 *
 *   register (extras.email) → prescan job with no text + email flag
 *   → worker completes it with the skipped verdict, no classifier call
 *   → PRESCAN_COMPLETED commits, content leaves PENDING_PRESCAN
 *
 * Also covers: a non-email registration still hands its text to the job,
 * text fingerprint items on an email are never ingested, the email text
 * shows up in no log line, queue row or tx, and an out-of-shape marker is
 * refused with 400 extras_email_invalid.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// Every log level reaches the console, so the log check below sees debug lines
// too. jest-setup already loaded the logger, so reload modules after setting it.
process.env.TIP_CONSOLE_LEVEL = "debug";
jest.resetModules();

const path = require("path");
const zlib = require("zlib");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { PROFILE: TEXT_PROFILE } = require("tip-content-fingerprint/src/text/constants");
const { initCrypto, generateMLDSAKeypair, shake256, tipNormalize } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, ORIGIN, CONTENT_STATUS, MEDIA_LIMITS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

try { PC._resetForTesting(); } catch { /* already initialized */ }
PC.init(getGenesisPayload().protocol_constants);

const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createPrescanJobs } = require(path.join(SRC, "services", "prescan-jobs"));
const { createPrescanWorker } = require(path.join(SRC, "workers", "prescan-worker"));
const schema = require(path.join(SRC, "schemas", "content-register"));

const NODE_ID = "tip://node/n_email_test";
const VP_ID = "tip://vp/v1";
const AUTHOR = "tip://id/US-e1e1e1e1e1e1e1e1";
const RECIPIENTS = "5a".repeat(32);
const EMAIL_TEXT = "Quarterly numbers\nHi team, the private figures are 4,812 and 77.";

beforeAll(async () => { await initCrypto(); });

function _packFingerprints(items) {
  const data = zlib.gzipSync(Buffer.from(JSON.stringify(items), "utf8")).toString("base64");
  return { profile: "cf-fingerprints-1", count: items.length, encoding: "gzip+base64", data };
}
const MINHASH = Array.from({ length: 128 }, (_, i) => (i * 7 + 13) % 100000);
const TEXT_ITEM = { kind: "text", role: "body", perceptual: { profile: TEXT_PROFILE, kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash: MINHASH } };
const IMAGE_ITEM = { kind: "image", role: "media", perceptual: { profile: "cf-image-1", kind: "image", pdq: "ab".repeat(32), quality: 95 } };

function setup({ classifier }) {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const authorKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  dag.saveIdentity({
    tip_id: AUTHOR, region: "US",
    public_key: authorKp.publicKey, root_public_key: authorKp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: false,
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: AUTHOR }),
  });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, mediaLimits: MEDIA_LIMITS };
  const scoring = initScoring(dag, config);
  dag.setScore(AUTHOR, 700, 0, 1769904000000);

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  let t = 1779800000000;
  const now = () => t;
  const prescanJobs = createPrescanJobs({ dag, now });
  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId: NODE_ID });
  const contentService = createContentService({ dag, scoring, config, submitTx, prescanJobs });
  const worker = createPrescanWorker({
    dag, jobs: prescanJobs, classifierClient: classifier, submitTx, config,
    log: { info: () => {}, warn: () => {}, error: () => {} }, now,
  });

  let round = 0;
  const commitDrain = () => {
    round += 1;
    t += 100;
    commitHandler.commitOrderedTxs(submitted.splice(0), round, { certTimestamp: t });
  };

  function body({ content = EMAIL_TEXT, extras = { email: { v: 1, recipients: RECIPIENTS } }, fingerprints = null } = {}) {
    const fields = {
      origin_code: ORIGIN.OH,
      registered_urls: [],
      extras,
      authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR, tip_id_type: "personal" }],
      signer_tip_id: AUTHOR,
      attribution_mode: "self",
    };
    if (fingerprints) fields.fingerprint_commit = schema.fingerprintsCommit(fingerprints);
    const payload = schema.buildSigningPayload(fields, shake256(tipNormalize(content)));
    return {
      ...fields,
      cna_version: schema.CURRENT_CNA_VERSION,
      content,
      content_type: "text",
      signature: schema.sign(payload, authorKp.privateKey),
      ...(fingerprints ? { fingerprints } : {}),
    };
  }

  return { dag, contentService, prescanJobs, worker, submitted, commitDrain, body };
}

function classifierSpy(probability = 0.97) {
  return {
    prescan: jest.fn(async () => ({
      flagged: false, probability, modalities_analyzed: ["text"],
      modality_results: [{ modality: "text", probability, weight: 1, provider: "ensemble", features_used: [], reasoning: null, processing_ms: 1, error: null }],
      provider_used: "ensemble", classifier_version: "2.0.0", processing_ms: 1, note: null,
    })),
    stage1: async () => ({}), providers: async () => ({}), health: async () => ({}),
  };
}

const _flush = () => new Promise((r) => setImmediate(r));

describe("email registration: prescan", () => {
  test("enqueues no text with the email flag; worker completes with the skipped verdict and never calls the classifier", async () => {
    const classifier = classifierSpy();
    const fx = setup({ classifier });

    const r = await fx.contentService.register(fx.body());
    expect(r.prescan_status).toBe("pending");

    const job = fx.prescanJobs.getByCtid(r.ctid);
    expect(job.payload.text).toBe("");
    expect(job.payload.email).toBe(true);
    expect(job.payload.origin_code).toBe("OH");
    // The stored queue row holds no trace of the email.
    const raw = fx.dag.getPrescanJobByCtid(r.ctid).payload;
    expect(Buffer.from(raw).toString("utf8")).not.toContain("private figures");

    // REGISTER_CONTENT carries the signed marker, never the text or its length.
    const regTx = fx.submitted.find(t => t.tx_type === TX_TYPES.REGISTER_CONTENT);
    expect(regTx.data.extras).toEqual({ email: { v: 1, recipients: RECIPIENTS } });
    expect(regTx.data).not.toHaveProperty("text_chars");
    expect(JSON.stringify(regTx)).not.toContain("private figures");
    fx.commitDrain();

    const tick = await fx.worker.tick();
    expect(tick.outcome).toBe("completed");
    expect(classifier.prescan).not.toHaveBeenCalled();

    const done = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_COMPLETED);
    expect(done.data).toMatchObject({
      ctid: r.ctid, probability: 0.5, tier: "low", flagged: false,
      overall_degraded: false, failed: false, modality_results: [],
      classifier_providers_used: "skipped_locally",
    });
    fx.commitDrain();

    expect(fx.prescanJobs.getByCtid(r.ctid)).toBeNull();
    const status = fx.contentService.getPrescanStatus(r.ctid);
    expect(status).toMatchObject({ prescan_status: "completed", prescan_tier: "low", prescan_flagged: false, prescan_overall_degraded: false });
    expect(fx.dag.getContent(r.ctid).status).toBe(CONTENT_STATUS.REGISTERED);
  });

  test("2.9.3: the from and all seals are signed, committed and stored as sent, and the email stays out of the classifier", async () => {
    const classifier = classifierSpy();
    const fx = setup({ classifier });
    const seals = { v: 1, recipients: RECIPIENTS, from: "f0".repeat(32), all: "a1".repeat(32) };
    const r = await fx.contentService.register(fx.body({ extras: { email: seals } }));
    expect(r.prescan_status).toBe("pending");
    expect(fx.prescanJobs.getByCtid(r.ctid).payload.email).toBe(true);
    const regTx = fx.submitted.find(t => t.tx_type === TX_TYPES.REGISTER_CONTENT);
    expect(regTx.data.extras).toEqual({ email: seals });
    expect(JSON.stringify(regTx)).not.toContain("private figures");
    fx.commitDrain();
    await fx.worker.tick();
    expect(classifier.prescan).not.toHaveBeenCalled();
    fx.commitDrain();
    expect(fx.dag.getContent(r.ctid).extras).toEqual({ email: seals });
  });

  test("a registration without extras.email still passes its text to the classifier", async () => {
    const classifier = classifierSpy(0.2);
    const fx = setup({ classifier });
    const text = "An ordinary public post about gardening";

    const r = await fx.contentService.register(fx.body({ content: text, extras: { title: "Gardening" } }));
    const job = fx.prescanJobs.getByCtid(r.ctid);
    expect(job.payload.text).toBe(text);
    expect(job.payload.email).toBeUndefined();
    fx.commitDrain();

    await fx.worker.tick();
    expect(classifier.prescan).toHaveBeenCalledTimes(1);
    expect(classifier.prescan.mock.calls[0][0].text).toBe(text);
  });

  test("the email text appears in no log line, at any level", async () => {
    const lines = [];
    const spies = ["log", "info", "warn", "error", "debug"].map((m) =>
      jest.spyOn(console, m).mockImplementation((...a) => { lines.push(a.join(" ")); }));
    try {
      require(path.join(SRC, "logger")).log.debug("email-test probe");
      const fx = setup({ classifier: classifierSpy() });
      const r = await fx.contentService.register(fx.body({ fingerprints: _packFingerprints([TEXT_ITEM]) }));
      fx.commitDrain();
      await fx.worker.tick();
      fx.commitDrain();
      await _flush();
      expect(fx.contentService.getPrescanStatus(r.ctid).prescan_status).toBe("completed");
    } finally {
      spies.forEach((s) => s.mockRestore());
    }
    expect(lines.some((l) => l.includes("email-test probe"))).toBe(true); // debug lines are captured
    expect(lines.some((l) => l.includes("Content proposed"))).toBe(true);
    for (const line of lines) {
      expect(line).not.toContain("private figures");
      expect(line).not.toContain("Quarterly numbers");
    }
  });
});

describe("email registration: fingerprints", () => {
  test("text fingerprint items on an email are not ingested; media items keep their index", async () => {
    const fx = setup({ classifier: classifierSpy() });
    const saveBands = jest.spyOn(fx.dag, "saveMinhashBands");

    const r = await fx.contentService.register(fx.body({ fingerprints: _packFingerprints([TEXT_ITEM, IMAGE_ITEM]) }));
    await _flush();
    await _flush();

    expect(fx.dag.getPerceptualFingerprint(r.ctid, 0)).toBeNull();
    expect(saveBands).not.toHaveBeenCalled();
    const img = fx.dag.getPerceptualFingerprint(r.ctid, 1);
    expect(img).not.toBeNull();
    expect(img.modality).toBe("image");
  });

  test("the same text fingerprint on a non-email registration is ingested", async () => {
    const fx = setup({ classifier: classifierSpy() });
    const r = await fx.contentService.register(fx.body({
      content: "Public post", extras: {}, fingerprints: _packFingerprints([TEXT_ITEM]),
    }));
    await _flush();
    await _flush();
    const fp = fx.dag.getPerceptualFingerprint(r.ctid, 0);
    expect(fp).not.toBeNull();
    expect(fp.modality).toBe("text");
  });
});

describe("email registration: marker shape", () => {
  test("an out-of-shape marker is refused with 400 extras_email_invalid before anything is queued", async () => {
    const fx = setup({ classifier: classifierSpy() });
    await expect(fx.contentService.register(fx.body({ extras: { email: { v: 1, to: "a@example.com" } } })))
      .rejects.toMatchObject({ status: 400, code: "extras_email_invalid" });
    await expect(fx.contentService.register(fx.body({ extras: { email: { v: 1, recipients: "ABC" } } })))
      .rejects.toMatchObject({ status: 400, code: "extras_email_invalid" });
    expect(fx.submitted).toHaveLength(0);
  });
});
