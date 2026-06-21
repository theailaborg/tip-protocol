/**
 * @file tests/integration/content-register.test.js
 * @description End-to-end content registration through API → tx
 * submission → eventual commit-handler replay. Drives the
 * single canonical CNA-2.2 path described in docs/CONTENT_SIGNING.md.
 *
 * Coverage:
 *   1. Happy path — DAG-registered signer submits, CNA-2.2 fields
 *      land in tx.data, no public_key field
 *   2. Off-DAG signer is rejected with 412 (no fallback)
 *   3. Tampered signature → 403
 *   4. registered_urls array passes through verbatim
 *   5. Reject-on-extra: junk top-level fields don't end up in tx.data
 *      and the signature still verifies (proves they weren't bound)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";
const { PROFILE: TEXT_PROFILE } = require("tip-content-fingerprint/src/text/constants"); // dynamic: text profile follows the lib

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, tipNormalize,
} = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const schema = require(path.join(SRC, "schemas", "content-register"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";

function _setup() {
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
    mediaLimits: { max_text_bytes: 1_000_000, max_image_bytes: 0, max_video_bytes: 0, max_audio_bytes: 0 },
  };
  const scoring = initScoring(dag, config);
  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); dag.addTx(tx); };
  const contentService = createContentService({ dag, scoring, config, submitTx });
  return { dag, scoring, contentService, submitted };
}

function _seedIdentity(dag, tipId, kp, score = 750) {
  dag.saveIdentity({
    tip_id: tipId, region: "US",
    public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: shake256(`id:${tipId}`),
  });
  dag.setScore(tipId, score, 0, 1767225600000);
}

/**
 * Build a CNA-2.2 register body the way every spec-compliant client
 * does: build the 9-field canonical payload, sign it, attach the
 * auxiliary request fields (content, signature). No public_key in the
 * body — verifier looks up signer's key from the DAG.
 *
 * Per docs/CONTENT_SIGNING.md.
 */
function _buildRegisterBody({ tipId, privKey, content, registered_urls = ["https://example.com/post/"], extras = {}, fingerprints = null }) {
  const contentHashFull = shake256(tipNormalize(content));
  const fields = {
    origin_code: "OH",
    registered_urls,
    extras,
    authors: [{ key_mode: "attribution", role: "byline", signed: false,
                 tip_id: tipId, tip_id_type: "personal" }],
    signer_tip_id: tipId,
    attribution_mode: "self",
  };
  // When the client attaches a perceptual fingerprints envelope, bind it by
  // signing its commit (strip-rule: present → in the 9-field payload).
  if (fingerprints) fields.fingerprint_commit = schema.fingerprintsCommit(fingerprints);
  const payload = schema.buildSigningPayload(fields, contentHashFull);
  const signature = schema.sign(payload, privKey);
  return {
    ...fields,
    cna_version: schema.CURRENT_CNA_VERSION,
    content,
    content_type: "text",
    signature,
    ...(fingerprints ? { fingerprints } : {}),
  };
}

// Pack an items[] array into the wire envelope the client sends (gzip+base64).
function _packFingerprints(items) {
  const json = JSON.stringify(items);
  const data = require("zlib").gzipSync(Buffer.from(json, "utf8")).toString("base64");
  return { profile: "cf-fingerprints-1", count: items.length, encoding: "gzip+base64", data };
}
const _flush = () => new Promise((r) => setImmediate(r));

// ─── 1. Happy path with DAG-registered signer ─────────────────────────────

describe("content register — DAG-registered signer (canonical happy path)", () => {
  test("registers cleanly; CNA-2.2 fields persisted on tx.data; no public_key", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("dag-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "Hello from a DAG-registered publisher",
    });
    const out = await fx.contentService.register(body);
    expect(out.confirmation).toBe("proposed");

    const tx = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT");
    expect(tx).toBeDefined();
    expect(tx.data.cna_version).toBe(schema.CURRENT_CNA_VERSION);
    expect(tx.data.attribution_mode).toBe("self");
    expect(tx.data.authors).toHaveLength(1);
    expect(tx.data.registered_urls).toEqual(["https://example.com/post/"]);
    // No public_key on tx.data — DAG identity is the source of truth.
    expect(tx.data.public_key).toBeUndefined();
    // signer_type was dropped — type resolved from DAG identity, not signed per-message.
    expect(tx.data.signer_type).toBeUndefined();
  });
});

// ─── 1b. Perceptual fingerprints — local off-DAG ingest, commit-only on tx ──

describe("content register — perceptual fingerprints (local off-DAG ingest)", () => {
  const minhash128 = Array.from({ length: 128 }, (_, i) => (i * 2654435761) % 100000);
  const ITEMS = [
    { kind: "image", role: "primary", exact: "a".repeat(64),
      perceptual: { profile: "cf-image-1", kind: "image", pdq: "ab".repeat(32), quality: 95 } },
    { kind: "text", role: "caption",
      perceptual: { profile: TEXT_PROFILE, kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash: minhash128 } },
  ];

  test("tx carries ONLY the commit; items ingested into the off-DAG index in order", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("fp-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const fingerprints = _packFingerprints(ITEMS);
    const body = _buildRegisterBody({ tipId, privKey: kp.privateKey, content: "post with media", fingerprints });
    await fx.contentService.register(body);
    await _flush(); // ingest is fire-and-forget

    const tx = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT");
    const ctid = tx.data.ctid;
    // The bulky envelope never rides the tx — only the signed 32-byte commit.
    expect(tx.data.fingerprint_commit).toBe(schema.fingerprintsCommit(fingerprints));
    expect(tx.data.fingerprints).toBeUndefined();
    // Components ingested locally, keyed by position, into the off-DAG tables.
    expect(fx.dag.getPerceptualFingerprint(ctid, 0)).toMatchObject({ ctid, modality: "image" });
    expect(fx.dag.getPerceptualFingerprint(ctid, 1)).toMatchObject({ ctid, modality: "text" });
  });

  test("no fingerprints → no commit on tx, nothing ingested", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("nofp-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);
    const body = _buildRegisterBody({ tipId, privKey: kp.privateKey, content: "plain post" });
    await fx.contentService.register(body);
    await _flush();
    const tx = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT");
    expect(tx.data.fingerprint_commit).toBeUndefined();
    expect(fx.dag.getPerceptualFingerprint(tx.data.ctid, 0)).toBeNull();
  });
});

// ─── 1c. Similar content — matcher wired into the content API ───────────────

describe("content register — similar content (findSimilar + resolve.similar)", () => {
  const A = Array.from({ length: 128 }, (_, i) => (i * 7 + 13) % 100000);
  const NEAR = A.map((v, i) => (i < 10 ? v + 1 : v)); // ~8% changed → shares LSH bands
  const textEnv = (minhash) => _packFingerprints([
    { kind: "text", role: "caption", perceptual: { profile: TEXT_PROFILE, kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash } },
  ]);

  // The harness's submitTx only records the tx; emulate the commit-handler's
  // content-row create so resolve()/findSimilar have rows to enrich.
  function _commit(fx, tx) {
    const d = tx.data;
    fx.dag.saveContent({
      ctid: d.ctid, origin_code: d.origin_code, content_hash: d.content_hash,
      author_tip_id: (d.authors && d.authors[0] && d.authors[0].tip_id) || d.signer_tip_id,
      signer_tip_id: d.signer_tip_id, authors: d.authors || [],
      attribution_mode: d.attribution_mode || "self", extras: d.extras || {},
      cna_version: d.cna_version, status: "registered",
      registered_at: tx.timestamp, tx_id: tx.tx_id, registered_urls: d.registered_urls || [],
      media: d.media || [], media_canonical_hash: d.media_canonical_hash || null,
    });
  }

  async function _registerPair(fx, kp, tipId) {
    await fx.contentService.register(_buildRegisterBody({ tipId, privKey: kp.privateKey, content: "alpha original", extras: { title: "Alpha" }, fingerprints: textEnv(A) }));
    await fx.contentService.register(_buildRegisterBody({ tipId, privKey: kp.privateKey, content: "beta near-dup", fingerprints: textEnv(NEAR) }));
    await _flush(); // local fingerprint ingest is fire-and-forget
    const reg = fx.submitted.filter(t => t.tx_type === "REGISTER_CONTENT");
    reg.forEach(tx => _commit(fx, tx));
    return { ctidA: reg[0].data.ctid, ctidB: reg[1].data.ctid };
  }

  test("findSimilar returns the near-duplicate as a card (score + modality + origin/byline/title)", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("sim-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);
    const { ctidA, ctidB } = await _registerPair(fx, kp, tipId);

    const res = await fx.contentService.findSimilar(ctidB);
    expect(res.ctid).toBe(ctidB);
    const card = res.similar.find(s => s.ctid === ctidA);
    expect(card).toBeDefined();
    expect(card.similarity.modality).toBe("text");
    expect(card.similarity.score).toBeGreaterThan(0.8);
    expect(card.origin_label).toBe("Original Human");
    expect(card.title).toBe("Alpha");
    expect(card.author_tip_id).toBe(tipId);
  });

  test("audio card score is normalised 0-1; raw landmark count goes to landmark_matches (not score)", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("sim-audio").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    // Two distinct posts (different text → different ctids) that carry the SAME
    // audio landmark set → a perfect audio match (every landmark aligns at
    // offset 0, so bestCount = 50). The raw count (50) must NOT leak into the
    // normalised `score` field — it belongs under `landmark_matches`.
    const landmarks = Array.from({ length: 50 }, (_, i) => ({ hash: 100000 + i, t: i }));
    const audioEnv = () => _packFingerprints([
      { kind: "audio", role: "audio", perceptual: { profile: "cf-audio-landmark-1", kind: "audio", landmarkCount: landmarks.length, landmarks } },
    ]);
    await fx.contentService.register(_buildRegisterBody({ tipId, privKey: kp.privateKey, content: "audio original", fingerprints: audioEnv() }));
    await fx.contentService.register(_buildRegisterBody({ tipId, privKey: kp.privateKey, content: "audio re-upload", fingerprints: audioEnv() }));
    await _flush();
    const reg = fx.submitted.filter(t => t.tx_type === "REGISTER_CONTENT");
    reg.forEach(tx => _commit(fx, tx));
    const [ctidA, ctidB] = [reg[0].data.ctid, reg[1].data.ctid];

    const res = await fx.contentService.findSimilar(ctidB);
    const card = res.similar.find(s => s.ctid === ctidA);
    expect(card).toBeDefined();
    expect(card.similarity.modality).toBe("audio");
    // The regression guard: `score` is the normalised 0-1 value, never the raw count.
    expect(card.similarity.score).toBeGreaterThan(0);
    expect(card.similarity.score).toBeLessThanOrEqual(1);
    // The raw landmark count is preserved under its own key.
    expect(card.similarity.landmark_matches).toBe(50);
    expect(card.similarity.score_ratio).toBeGreaterThan(0);
  });

  test("resolve() embeds the similar[] cards on the content detail", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("sim-signer2").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);
    const { ctidA, ctidB } = await _registerPair(fx, kp, tipId);

    const detail = await fx.contentService.resolve(ctidB);
    expect(Array.isArray(detail.similar)).toBe(true);
    expect(detail.similar.map(s => s.ctid)).toContain(ctidA);
  });

  test("findSimilar on unknown ctid → 404", async () => {
    const fx = _setup();
    await expect(fx.contentService.findSimilar("tip://c/OH-deadbeefdeadbe-0000"))
      .rejects.toMatchObject({ status: 404, code: "content_not_found" });
  });
});

// ─── 2. Off-DAG signer — must be rejected per spec §1 ─────────────────────

describe("content register — off-DAG signer is rejected (no fallback)", () => {
  test("signer with no DAG identity → 412 signer_not_registered", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("offdag-signer").slice(0, 16)}`;
    // No _seedIdentity — the whole point.
    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "Hello from an off-DAG signer",
    });
    await expect(fx.contentService.register(body))
      .rejects.toMatchObject({ status: 412, code: "signer_not_registered" });
  });
});

// ─── 3. Tamper detection ──────────────────────────────────────────────────

describe("content register — tamper rejection", () => {
  test("flipping origin_code after signing → 403 signature_invalid", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("tamper-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "tamper test",
    });
    body.origin_code = "AG";  // tampered after signing

    await expect(fx.contentService.register(body))
      .rejects.toMatchObject({ status: 403, code: "signature_invalid" });
  });

  test("appending an extra DAG-resident author after signing → 403 signature_invalid", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("tamper-author").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    // The injected author is also seeded on DAG, so the DAG-presence gate
    // passes — proving the signature-verification step is what catches
    // post-signing tampering, not the DAG check.
    const injectedKp = generateMLDSAKeypair();
    const injectedTipId = `tip://id/US-${shake256("tamper-author-injected").slice(0, 16)}`;
    _seedIdentity(fx.dag, injectedTipId, injectedKp);

    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "tamper authors test",
    });
    body.authors.push({ key_mode: "attribution", role: "byline", signed: false,
                       tip_id: injectedTipId, tip_id_type: "personal" });

    await expect(fx.contentService.register(body))
      .rejects.toMatchObject({ status: 403, code: "signature_invalid" });
  });

  test("appending an off-DAG author after signing → 412 author_not_registered (caught by validateRequest)", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("tamper-offdag").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "tamper offdag authors test",
    });
    body.authors.push({ key_mode: "attribution", role: "byline", signed: false,
                       tip_id: "tip://id/US-not-on-dag", tip_id_type: "personal" });

    await expect(fx.contentService.register(body))
      .rejects.toMatchObject({ status: 412, code: "author_not_registered" });
  });
});

// ─── 4. registered_urls — array passthrough ──────────────────────────────

describe("content register — registered_urls handling", () => {
  test("array registered_urls passes through verbatim — supports syndication", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("syndicated-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const urls = ["https://example.com/post/", "https://medium.com/@x/post"];
    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "syndicated content test",
      registered_urls: urls,
    });
    const out = await fx.contentService.register(body);
    expect(out.confirmation).toBe("proposed");

    const tx = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT");
    expect(tx.data.registered_urls).toEqual(urls);
  });

  test("empty registered_urls array → 400 (at least one published URL required)", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("unpublished-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({ tipId, privKey: kp.privateKey, content: "unpublished content test", registered_urls: [] });
    await expect(fx.contentService.register(body))
      .rejects.toMatchObject({ status: 400, code: "registered_urls_required" });
  });

  test("non-http(s) registered_url → 400", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("badurl-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({ tipId, privKey: kp.privateKey, content: "bad url test", registered_urls: ["ftp://nope"] });
    await expect(fx.contentService.register(body))
      .rejects.toMatchObject({ status: 400, code: "registered_urls_invalid" });
  });
});

// ─── 4b. Duplicate-content rejection + idempotent ingest ────────────────────

describe("content register — duplicate-ctid guards", () => {
  test("re-registering identical content while the first is PENDING → 409", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("dup-pending-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);
    const mk = () => _buildRegisterBody({ tipId, privKey: kp.privateKey, content: "duplicate me" });

    await fx.contentService.register(mk());                 // first accepted
    const firstTx = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT");
    fx.dag.saveMempoolTx(firstTx);                          // it's now pending in the mempool

    await expect(fx.contentService.register(mk()))          // identical content (same ctid) again
      .rejects.toMatchObject({ status: 409, code: "content_registration_pending" });
  });

  test("re-ingesting the same ctid skips — no duplicate perceptual/derived rows", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("idempotent-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);
    const fingerprints = _packFingerprints([
      { kind: "image", role: "primary", perceptual: { profile: "cf-image-1", kind: "image", pdq: "ab".repeat(32), quality: 95 } },
    ]);
    const mk = () => _buildRegisterBody({ tipId, privKey: kp.privateKey, content: "idempotent content", fingerprints });

    // The harness submitTx doesn't populate the mempool, so both registrations
    // reach ingest — exercising the ingest skip-guard directly (the belt-and-
    // suspenders for the true-simultaneous race the 409 above doesn't cover).
    await fx.contentService.register(mk()); await _flush();
    await fx.contentService.register(mk()); await _flush();

    const ctid = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT").data.ctid;
    expect(fx.dag.getPerceptualFingerprint(ctid, 0)).toMatchObject({ ctid, modality: "image" });
    expect(fx.dag.getPhashCodesByCtid(ctid)).toHaveLength(1); // NOT 2 — second ingest was skipped
  });
});

// ─── 5. Reject-on-extra ────────────────────────────────────────────────────

describe("content register — reject-on-extra (junk fields don't get bound to signature)", () => {
  test("a top-level garbage field is stripped before hashing; signature still verifies", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("extra-junk-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "extras test",
    });
    body.malicious_field = "this should be stripped";

    const out = await fx.contentService.register(body);
    expect(out.confirmation).toBe("proposed");

    const tx = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT");
    expect(tx.data.malicious_field).toBeUndefined();
  });
});
