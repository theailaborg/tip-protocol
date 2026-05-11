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
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
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
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${tipId}`),
  });
  dag.setScore(tipId, score, 0, "2026-01-01T00:00:00.000Z");
}

/**
 * Build a CNA-2.2 register body the way every spec-compliant client
 * does: build the 9-field canonical payload, sign it, attach the
 * auxiliary request fields (content, signature). No public_key in the
 * body — verifier looks up signer's key from the DAG.
 *
 * Per docs/CONTENT_SIGNING.md.
 */
function _buildRegisterBody({ tipId, privKey, content, registered_urls = ["https://example.com/post/"], extras = {} }) {
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
  const payload = schema.buildSigningPayload(fields, contentHashFull);
  const signature = schema.sign(payload, privKey);
  return {
    ...fields,
    cna_version: schema.CURRENT_CNA_VERSION,
    content,
    content_type: "text",
    signature,
  };
}

// ─── 1. Happy path with DAG-registered signer ─────────────────────────────

describe("content register — DAG-registered signer (canonical happy path)", () => {
  test("registers cleanly; CNA-2.2 fields persisted on tx.data; no public_key", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("dag-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "Hello from a DAG-registered publisher",
    });
    const out = fx.contentService.register(body);
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

// ─── 2. Off-DAG signer — must be rejected per spec §1 ─────────────────────

describe("content register — off-DAG signer is rejected (no fallback)", () => {
  test("signer with no DAG identity → 412 signer_not_registered", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("offdag-signer").slice(0, 16)}`;
    // No _seedIdentity — the whole point.
    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "Hello from an off-DAG signer",
    });
    expect(() => fx.contentService.register(body))
      .toThrow(expect.objectContaining({ status: 412, code: "signer_not_registered" }));
  });
});

// ─── 3. Tamper detection ──────────────────────────────────────────────────

describe("content register — tamper rejection", () => {
  test("flipping origin_code after signing → 403 signature_invalid", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("tamper-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "tamper test",
    });
    body.origin_code = "AG";  // tampered after signing

    expect(() => fx.contentService.register(body))
      .toThrow(expect.objectContaining({ status: 403, code: "signature_invalid" }));
  });

  test("appending an extra DAG-resident author after signing → 403 signature_invalid", () => {
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

    expect(() => fx.contentService.register(body))
      .toThrow(expect.objectContaining({ status: 403, code: "signature_invalid" }));
  });

  test("appending an off-DAG author after signing → 412 author_not_registered (caught by validateRequest)", () => {
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

    expect(() => fx.contentService.register(body))
      .toThrow(expect.objectContaining({ status: 412, code: "author_not_registered" }));
  });
});

// ─── 4. registered_urls — array passthrough ──────────────────────────────

describe("content register — registered_urls handling", () => {
  test("array registered_urls passes through verbatim — supports syndication", () => {
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
    const out = fx.contentService.register(body);
    expect(out.confirmation).toBe("proposed");

    const tx = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT");
    expect(tx.data.registered_urls).toEqual(urls);
  });

  test("empty registered_urls array — content not yet published", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("unpublished-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "unpublished content test",
      registered_urls: [],
    });
    const out = fx.contentService.register(body);
    expect(out.confirmation).toBe("proposed");

    const tx = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT");
    expect(tx.data.registered_urls).toEqual([]);
  });
});

// ─── 5. Reject-on-extra ────────────────────────────────────────────────────

describe("content register — reject-on-extra (junk fields don't get bound to signature)", () => {
  test("a top-level garbage field is stripped before hashing; signature still verifies", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("extra-junk-signer").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const body = _buildRegisterBody({
      tipId, privKey: kp.privateKey,
      content: "extras test",
    });
    body.malicious_field = "this should be stripped";

    const out = fx.contentService.register(body);
    expect(out.confirmation).toBe("proposed");

    const tx = fx.submitted.find(t => t.tx_type === "REGISTER_CONTENT");
    expect(tx.data.malicious_field).toBeUndefined();
  });
});
