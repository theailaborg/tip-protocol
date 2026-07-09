/**
 * @file tests/integration/content-register-neardup.test.js
 * @description Register-time near-duplicate warning (advisory) — the
 * `near_duplicates` array on the register response. Exercises both layers
 * of content-service._findNearDuplicates:
 *
 *   step 0 — exact_normalized: identical content_hash after tipNormalize
 *     ("I am Vishal" vs "i am VISHAL."), found on committed content rows
 *     AND on mempool-pending REGISTER_CONTENT txs ("pending_commit").
 *   step 1 — perceptual: the request's fingerprint envelope queried against
 *     the off-DAG index, self-excluded — all four modalities (text MinHash,
 *     image PDQ/MIH, video frame sets, audio landmarks).
 *
 * Invariants under test:
 *   1. The warning NEVER blocks — confirmation stays "proposed".
 *   2. The existing content keeps its ctid; the new registration gets its own.
 *   3. A registration never reports itself (own mempool tx / own envelope).
 *   4. Exact beats perceptual — one card per ctid, exact_normalized wins.
 *   5. Clean registrations return near_duplicates: [].
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
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";

// ─── harness (mirrors tests/integration/content-register.test.js) ──────────

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
  // Production parity: consensus stages a submitted tx in the persistent
  // mempool until it commits — that's what the near-dup mempool layer
  // (step 0b) and _pendingUrlConflict read. addTx alone bypasses it.
  const submitTx = (tx) => { submitted.push(tx); dag.addTx(tx); dag.saveMempoolTx(tx); };
  const contentService = createContentService({ dag, scoring, config, submitTx });
  return { dag, scoring, contentService, submitted };
}

function _seedIdentity(dag, tipId, kp, score = 750) {
  dag.saveIdentity({
    tip_id: tipId, region: "US",
    public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, score, 0, 1767225600000);
}

function _buildRegisterBody({ tipId, privKey, content, registered_urls, extras = {}, fingerprints = null }) {
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

function _packFingerprints(items) {
  const json = JSON.stringify(items);
  const data = require("zlib").gzipSync(Buffer.from(json, "utf8")).toString("base64");
  return { profile: "cf-fingerprints-1", count: items.length, encoding: "gzip+base64", data };
}

// Emulate the commit-handler's content-row create so the committed-row exact
// path (step 0a) and _nearDupCard's dag.getContent enrichment have rows.
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

const _flush = () => new Promise((r) => setImmediate(r));

// One register call end-to-end; unique URL per call so URL checks never trip.
let _n = 0;
async function _register(fx, { tipId, kp, content, fingerprints = null }) {
  const before = fx.submitted.length;
  const out = await fx.contentService.register(_buildRegisterBody({
    tipId, privKey: kp.privateKey, content, fingerprints,
    registered_urls: [`https://example.com/post/${++_n}/`],
  }));
  const tx = fx.submitted.slice(before).find(t => t.tx_type === "REGISTER_CONTENT");
  return { out, tx };
}

// Two identities per test — near-dups only arise across authors (same author +
// same content ⇒ same ctid ⇒ the rapid-resubmit guard rejects it instead).
function _twoAuthors(fx, seed) {
  const kpA = generateMLDSAKeypair(); const kpB = generateMLDSAKeypair();
  const tipA = `tip://id/US-${shake256(`${seed}-a`).slice(0, 16)}`;
  const tipB = `tip://id/US-${shake256(`${seed}-b`).slice(0, 16)}`;
  _seedIdentity(fx.dag, tipA, kpA);
  _seedIdentity(fx.dag, tipB, kpB);
  return { a: { tipId: tipA, kp: kpA }, b: { tipId: tipB, kp: kpB } };
}

// ─── perceptual text vectors (mirrors tests/perceptual/match.test.js) ──────

const A = Array.from({ length: 128 }, (_, i) => (i * 7 + 13) % 100000);
const NEAR = A.map((v, i) => (i < 10 ? v + 1 : v)); // ~8% changed → shares LSH bands
const FAR = A.map((v) => v + 500000);                // shares no band → no hit
const textEnv = (minhash) => _packFingerprints([
  { kind: "text", role: "caption", perceptual: { profile: TEXT_PROFILE, kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash } },
]);

// ─── step 0a — exact_normalized against committed rows ─────────────────────

describe("near_duplicates — exact_normalized (committed row)", () => {
  test("'I am Vishal' vs 'i am VISHAL.' → score-1 card; registration still proposed with its own ctid", async () => {
    const fx = _setup();
    const { a, b } = _twoAuthors(fx, "nd-exact");

    // The premise of the whole check: both spellings normalize identically.
    expect(shake256(tipNormalize("i am VISHAL."))).toBe(shake256(tipNormalize("I am Vishal")));

    const first = await _register(fx, { ...a, content: "I am Vishal" });
    expect(first.out.near_duplicates).toEqual([]); // nothing to match yet
    _commit(fx, first.tx);

    const second = await _register(fx, { ...b, content: "i am VISHAL." });
    // Advisory — NEVER blocks, and both registrations keep their own ctid.
    expect(second.out.confirmation).toBe("proposed");
    expect(second.out.ctid).not.toBe(first.out.ctid);
    expect(second.out.near_duplicates).toHaveLength(1);
    expect(second.out.near_duplicates[0]).toMatchObject({
      ctid: first.out.ctid,
      match_type: "exact_normalized",
      status: "registered",
      author_tip_id: a.tipId,
      origin_code: "OH",
      similarity: { score: 1 },
    });
  });
});

// ─── step 0b — exact_normalized against mempool-pending txs ────────────────

describe("near_duplicates — exact_normalized (mempool race)", () => {
  test("second author registering within the same round sees a pending_commit card, never itself", async () => {
    const fx = _setup();
    const { a, b } = _twoAuthors(fx, "nd-mempool");

    const first = await _register(fx, { ...a, content: "Raced content, one round" });
    // Deliberately NOT committed — the tx only lives in the mempool.

    const second = await _register(fx, { ...b, content: "raced CONTENT one round!" });
    expect(second.out.confirmation).toBe("proposed");
    // Exactly one card: author A's pending tx. B's own mempool tx (submitted
    // just before the check runs) must never be self-reported.
    expect(second.out.near_duplicates).toHaveLength(1);
    expect(second.out.near_duplicates[0]).toMatchObject({
      ctid: first.out.ctid,
      match_type: "exact_normalized",
      status: "pending_commit",
      author_tip_id: a.tipId,
      similarity: { score: 1 },
    });
  });
});

// ─── step 1 — perceptual via the request's own envelope ────────────────────

describe("near_duplicates — perceptual (fingerprint envelope)", () => {
  test("near-identical text MinHash from another author → perceptual card with normalised score", async () => {
    const fx = _setup();
    const { a, b } = _twoAuthors(fx, "nd-percep");

    const first = await _register(fx, { ...a, content: "alpha original prose", fingerprints: textEnv(A) });
    _commit(fx, first.tx);
    await _flush(); // off-DAG ingest is fire-and-forget

    // Different words (different content_hash — exact layer stays silent),
    // near-identical fingerprint → only the perceptual layer can catch it.
    const second = await _register(fx, { ...b, content: "totally different words here", fingerprints: textEnv(NEAR) });
    expect(second.out.confirmation).toBe("proposed");
    const card = second.out.near_duplicates.find((c) => c.ctid === first.out.ctid);
    expect(card).toBeDefined();
    expect(card.match_type).toBe("perceptual");
    expect(card.similarity.modality).toBe("text");
    expect(card.similarity.component_idx).toBe(0);
    expect(card.similarity.score).toBeGreaterThan(0.8);
    expect(card.similarity.score).toBeLessThanOrEqual(1);
  });

  test("exact hit suppresses the duplicate perceptual card — one card per ctid, exact wins", async () => {
    const fx = _setup();
    const { a, b } = _twoAuthors(fx, "nd-both");

    // Same normalized text AND same envelope: both layers would hit ctid A.
    const first = await _register(fx, { ...a, content: "same story twice", fingerprints: textEnv(A) });
    _commit(fx, first.tx);
    await _flush();

    const second = await _register(fx, { ...b, content: "SAME story, twice!", fingerprints: textEnv(A) });
    const cards = second.out.near_duplicates.filter((c) => c.ctid === first.out.ctid);
    expect(cards).toHaveLength(1); // never double-reported
    expect(cards[0].match_type).toBe("exact_normalized"); // the stronger signal
    expect(cards[0].similarity.score).toBe(1);
  });
});

// ─── clean path ─────────────────────────────────────────────────────────────

describe("near_duplicates — clean registrations", () => {
  test("unrelated content + unrelated fingerprints → empty array (present, not undefined)", async () => {
    const fx = _setup();
    const { a, b } = _twoAuthors(fx, "nd-clean");

    const first = await _register(fx, { ...a, content: "alpha original prose", fingerprints: textEnv(A) });
    _commit(fx, first.tx);
    await _flush();

    const second = await _register(fx, { ...b, content: "completely unrelated writing", fingerprints: textEnv(FAR) });
    expect(second.out.confirmation).toBe("proposed");
    expect(second.out.near_duplicates).toEqual([]);
  });
});

// ─── step 1 — perceptual, non-text modalities ───────────────────────────────
// Vectors mirror tests/perceptual/match.test.js so the register-time path and
// the matcher unit tests exercise identical index geometry.

const mkImg = (pdq, quality = 95) => ({ profile: "cf-image-1", kind: "image", pdq, quality });
const PDQ = "ab".repeat(32);            // 64-hex (256-bit)
const PDQ_NEAR = "cd" + PDQ.slice(2);   // chunk 0 changed (4 bits) -> shares chunks 1..15
const PDQ_FAR = "54".repeat(32);        // every byte differs -> shares no chunk
const imageEnv = (pdq) => _packFingerprints([{ kind: "image", role: "media", perceptual: mkImg(pdq) }]);

const vframe = (pdq, i, q = 80) => ({ frame: i, timestamp: i + 0.5, pdq, quality: q });
const A_PDQS = ["11", "22", "33", "44"].map((b) => b.repeat(32)); // 4 frames, 64-hex each
const flip1 = (hex) => (parseInt(hex.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0") + hex.slice(2);
const videoEnv = (pdqs) => _packFingerprints([
  { kind: "video", role: "media", perceptual: { profile: "cf-video-1", kind: "video", features: pdqs.map((p, i) => vframe(p, i)) } },
]);

const mkAudio = (landmarks) => ({ profile: "cf-audio-landmark-1", kind: "audio", landmarkCount: landmarks.length, landmarks });
const audioBase = Array.from({ length: 50 }, (_, i) => ({ hash: 1000 + i, t: i })); // 50 distinct landmarks
// a later sub-clip of the same source, clock reset to 0: 40 shared landmarks at a constant +10 offset
const audioNear = audioBase.slice(10).map((lm, j) => ({ hash: lm.hash, t: j }));
const audioEnv = (landmarks) => _packFingerprints([{ kind: "audio", role: "media", perceptual: mkAudio(landmarks) }]);

describe("near_duplicates — perceptual (image / video / audio)", () => {
  test("re-encoded image PDQ from another author → perceptual card with distance metric", async () => {
    const fx = _setup();
    const { a, b } = _twoAuthors(fx, "nd-img");

    const first = await _register(fx, { ...a, content: "image post one", fingerprints: imageEnv(PDQ) });
    _commit(fx, first.tx);
    await _flush();

    const second = await _register(fx, { ...b, content: "image post two", fingerprints: imageEnv(PDQ_NEAR) });
    expect(second.out.confirmation).toBe("proposed");
    const card = second.out.near_duplicates.find((c) => c.ctid === first.out.ctid);
    expect(card).toBeDefined();
    expect(card.match_type).toBe("perceptual");
    expect(card.similarity.modality).toBe("image");
    expect(card.similarity.component_idx).toBe(0);
    expect(card.similarity.distance).toBeLessThanOrEqual(31); // raw Hamming metric
    expect(card.similarity.score).toBeGreaterThan(0.8);       // 1 - d/32
    expect(card.similarity.score).toBeLessThanOrEqual(1);

    // Unrelated image → no card (candidate-gen shares no MIH chunk).
    const clean = await _register(fx, { ...b, content: "image post three", fingerprints: imageEnv(PDQ_FAR) });
    expect(clean.out.near_duplicates).toEqual([]);
  });

  test("re-encoded video frame set from another author → perceptual card with coverage metric", async () => {
    const fx = _setup();
    const { a, b } = _twoAuthors(fx, "nd-vid");

    const first = await _register(fx, { ...a, content: "video post one", fingerprints: videoEnv(A_PDQS) });
    _commit(fx, first.tx);
    await _flush();

    // Per-frame Hamming 1 (re-encode) → full bidirectional coverage.
    const second = await _register(fx, { ...b, content: "video post two", fingerprints: videoEnv(A_PDQS.map(flip1)) });
    expect(second.out.confirmation).toBe("proposed");
    const card = second.out.near_duplicates.find((c) => c.ctid === first.out.ctid);
    expect(card).toBeDefined();
    expect(card.match_type).toBe("perceptual");
    expect(card.similarity.modality).toBe("video");
    expect(card.similarity.target_match_pct).toBeGreaterThanOrEqual(80); // VIDEO_PC floor
    expect(card.similarity.score).toBeGreaterThanOrEqual(0.8);           // pct / 100
  });

  test("audio sub-clip from another author → perceptual card with landmark metric", async () => {
    const fx = _setup();
    const { a, b } = _twoAuthors(fx, "nd-aud");

    const first = await _register(fx, { ...a, content: "audio post one", fingerprints: audioEnv(audioBase) });
    _commit(fx, first.tx);
    await _flush();

    const second = await _register(fx, { ...b, content: "audio post two", fingerprints: audioEnv(audioNear) });
    expect(second.out.confirmation).toBe("proposed");
    const card = second.out.near_duplicates.find((c) => c.ctid === first.out.ctid);
    expect(card).toBeDefined();
    expect(card.match_type).toBe("perceptual");
    expect(card.similarity.modality).toBe("audio");
    expect(card.similarity.landmark_matches).toBe(40);        // shared landmarks, one offset bin
    expect(card.similarity.score_ratio).toBeGreaterThan(0.9); // 40 / min(40, 50)
    expect(card.similarity.score).toBeGreaterThan(0.9);
  });

  test("mixed envelope: far text + near image → the image component wins with its index", async () => {
    const fx = _setup();
    const { a, b } = _twoAuthors(fx, "nd-mixed");

    const first = await _register(fx, { ...a, content: "mixed media post", fingerprints: _packFingerprints([
      { kind: "text", role: "caption", perceptual: { profile: TEXT_PROFILE, kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash: A } },
      { kind: "image", role: "media", perceptual: mkImg(PDQ) },
    ]) });
    _commit(fx, first.tx);
    await _flush();

    const second = await _register(fx, { ...b, content: "another mixed post", fingerprints: _packFingerprints([
      { kind: "text", role: "caption", perceptual: { profile: TEXT_PROFILE, kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash: FAR } },
      { kind: "image", role: "media", perceptual: mkImg(PDQ_NEAR) },
    ]) });
    const card = second.out.near_duplicates.find((c) => c.ctid === first.out.ctid);
    expect(card).toBeDefined();
    expect(card.similarity.modality).toBe("image");
    expect(card.similarity.component_idx).toBe(1); // envelope position, not 0
  });
});
