/**
 * @file tests/schemas/content-register.test.js
 * @description Pure-function tests for the REGISTER_CONTENT canonical
 * signing schema (CNA-2.2 — see docs/CONTENT_SIGNING.md).
 *
 * The canonical builder must match every TIP client's implementation
 * byte-for-byte (browser extension, WordPress plugin, mobile app, CLI,
 * etc.). Until we have a cross-language fixture from each client, we
 * self-test:
 *   - exact 9-field shape, default-fills, reject-on-extra
 *   - canonicalJson rules (sorted keys, slashes unescaped, UTF-8)
 *   - sign/verify round-trip with our own keypair
 *   - registered_urls coercion (string → [string], array passthrough)
 *   - tamper-detection (every field flip breaks the signature)
 *   - verifyTx end-to-end (DAG lookup, no fallback, revoked rejected)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";
const { PROFILE: TEXT_PROFILE } = require("tip-content-fingerprint/src/text/constants"); // dynamic: text profile follows the lib

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, canonicalJson, shake256 } = require(path.join(SHARED, "crypto"));
const schema = require(path.join(SRC, "schemas", "content-register"));

beforeAll(async () => { await initCrypto(); });

const CONTENT_HASH = "ab".repeat(32);  // 64-char lowercase hex

// ─── Module surface (what other code imports) ──────────────────────────────

describe("module surface", () => {
  test("exports the expected schema constants and helpers", () => {
    expect(schema.TX_TYPE).toBe("REGISTER_CONTENT");
    expect(schema.CURRENT_CNA_VERSION).toBe("CNA-2.2");
    expect(typeof schema.buildSigningPayload).toBe("function");
    expect(typeof schema.sign).toBe("function");
    expect(typeof schema.verifySignature).toBe("function");
    expect(typeof schema.verifyTx).toBe("function");
  });
});

// ─── buildSigningPayload — exact 9-field canonical shape ──────────────────────────

describe("buildSigningPayload — exact 9-field shape", () => {
  test("emits exactly the 9 spec fields", () => {
    const input = {
      signer_tip_id: "tip://id/US-aaaa",
      origin_code: "OH",
      registered_urls: ["https://example.com/post/"],
      authors: [{ key_mode: "attribution", role: "byline", signed: true,
                   tip_id: "tip://id/US-aaaa", tip_id_type: "personal" }],
    };
    const payload = schema.buildSigningPayload(input, CONTENT_HASH);
    expect(Object.keys(payload).sort()).toEqual([
      "attribution_mode",
      "authors",
      "cna_version",
      "content_hash",
      "extras",
      "origin_code",
      "registered_urls",
      "signer_tip_id",
    ]);
  });

  test("authors entries normalised to exactly 5 keys; extras stripped", () => {
    const input = {
      signer_tip_id: "tip://id/US-aaaa",
      origin_code: "OH",
      authors: [
        { tip_id: "tip://id/US-aaaa", role: "byline" },                                         // missing key_mode/signed/tip_id_type
        { tip_id: "tip://id/US-bbbb", role: "byline", signed: true,
          tip_id_type: "personal", key_mode: "co_signed", garbage: "ignored" },
      ],
    };
    const payload = schema.buildSigningPayload(input, CONTENT_HASH);
    for (const a of payload.authors) {
      expect(Object.keys(a).sort()).toEqual(["key_mode", "role", "signed", "tip_id", "tip_id_type"]);
    }
    expect(payload.authors[0].key_mode).toBe("attribution");          // default
    expect(payload.authors[0].signed).toBe(false);                    // default
    expect(payload.authors[0].tip_id_type).toBe("personal");          // default
    expect(payload.authors[1].garbage).toBeUndefined();               // reject-on-extra
  });

  test("reject-on-extra at top level — junk fields don't end up in canonical payload", () => {
    const input = {
      signer_tip_id: "tip://id/US-x", origin_code: "OH",
      authors: [{ tip_id: "tip://id/US-x" }],
      malicious_field: "should be stripped",
    };
    const payload = schema.buildSigningPayload(input, CONTENT_HASH);
    expect(payload.malicious_field).toBeUndefined();
  });
});

// ─── Default-fill rules ─────────────────────────────────────────────────────

describe("buildSigningPayload — default-fill rules per docs/CONTENT_SIGNING.md", () => {
  const minimal = (overrides = {}) => schema.buildSigningPayload({
    signer_tip_id: "tip://id/US-x", origin_code: "OH",
    authors: [{ tip_id: "tip://id/US-x" }],
    ...overrides,
  }, CONTENT_HASH);

  test("attribution_mode defaults to 'self'", () => {
    expect(minimal().attribution_mode).toBe("self");
  });

  test("attribution_mode accepts every enum value (self / employed / hosted)", () => {
    expect(minimal({ attribution_mode: "self"     }).attribution_mode).toBe("self");
    expect(minimal({ attribution_mode: "employed" }).attribution_mode).toBe("employed");
    expect(minimal({ attribution_mode: "hosted"   }).attribution_mode).toBe("hosted");
  });

  test("attribution_mode outside the canonical enum is rejected", () => {
    expect(() => minimal({ attribution_mode: "anonymous" }))
      .toThrow(expect.objectContaining({ status: 400, code: "attribution_mode_invalid" }));
  });

  test("signer_type is NOT in the canonical signed payload (dropped — type is DAG-resident on identity row)", () => {
    expect("signer_type" in minimal()).toBe(false);
    // Even when explicitly passed, signer_type is stripped from the
    // canonical payload — the signer's role is resolved from the DAG
    // identity record, not asserted per-message.
    expect("signer_type" in minimal({ signer_type: "publisher" })).toBe(false);
  });

  test("extras defaults to {} when absent / null", () => {
    expect(minimal().extras).toEqual({});
    expect(minimal({ extras: null }).extras).toEqual({});
  });

  test("extras null/array/missing all coerce to {}; non-empty objects pass through", () => {
    expect(minimal().extras).toEqual({});
    expect(minimal({ extras: { language: "en" } }).extras).toEqual({ language: "en" });
  });

  test("extras = [] is rejected (must be object per spec)", () => {
    expect(() => schema.buildSigningPayload({
      signer_tip_id: "tip://id/US-x", origin_code: "OH",
      authors: [{ tip_id: "tip://id/US-x" }],
      extras: [],
    }, CONTENT_HASH)).toThrow(expect.objectContaining({ status: 400, code: "extras_invalid" }));
  });

  test("origin_code lowercase coerces to uppercase", () => {
    expect(minimal({ origin_code: "oh" }).origin_code).toBe("OH");
  });

  test("origin_code outside the canonical set rejected", () => {
    expect(() => minimal({ origin_code: "ZZ" }))
      .toThrow(expect.objectContaining({ status: 400, code: "origin_code_invalid" }));
  });

  test("cna_version is the literal CURRENT_CNA_VERSION regardless of input", () => {
    // attempted overrides via either old `cna` or `cna_version` keys are ignored —
    // the builder forces the current version into the canonical payload.
    const p1 = minimal({ cna: "CNA-3.0" });
    const p2 = minimal({ cna_version: "CNA-3.0" });
    expect(p1.cna_version).toBe("CNA-2.2");
    expect(p2.cna_version).toBe("CNA-2.2");
    expect(p1.cna).toBeUndefined();   // legacy field name not emitted
  });

});

// ─── registered_urls coercion ───────────────────────────────────────────────

describe("buildSigningPayload — registered_urls coercion", () => {
  const inputWith = (urls) => ({
    signer_tip_id: "tip://id/US-x", origin_code: "OH",
    authors: [{ tip_id: "tip://id/US-x" }],
    registered_urls: urls,
  });

  test("array passes through", () => {
    const p = schema.buildSigningPayload(inputWith(["https://a.example/", "https://b.example/"]), CONTENT_HASH);
    expect(p.registered_urls).toEqual(["https://a.example/", "https://b.example/"]);
  });

  test("empty array passes through", () => {
    expect(schema.buildSigningPayload(inputWith([]), CONTENT_HASH).registered_urls).toEqual([]);
  });

  test("undefined/null defaults to []", () => {
    expect(schema.buildSigningPayload(inputWith(undefined), CONTENT_HASH).registered_urls).toEqual([]);
    expect(schema.buildSigningPayload(inputWith(null), CONTENT_HASH).registered_urls).toEqual([]);
  });

  test("string input → reject (must be an array, no single-string back-compat)", () => {
    expect(() => schema.buildSigningPayload(inputWith("https://example.com/legacy/"), CONTENT_HASH))
      .toThrow(expect.objectContaining({ status: 400, code: "registered_urls_invalid" }));
  });

  test("non-string entry in array → reject", () => {
    expect(() => schema.buildSigningPayload(inputWith(["https://ok.example/", 42]), CONTENT_HASH))
      .toThrow(expect.objectContaining({ status: 400, code: "registered_urls_invalid" }));
  });

  test("scalar non-string input → reject", () => {
    expect(() => schema.buildSigningPayload(inputWith({ url: "x" }), CONTENT_HASH))
      .toThrow(expect.objectContaining({ status: 400, code: "registered_urls_invalid" }));
  });

  test("array order is preserved (index 0 = canonical convention is cryptographically enforceable)", () => {
    // Per docs/CONTENT_SIGNING.md §9: registered_urls[0] is the canonical
    // / primary URL. The signature commits to the order, so a verifier
    // who reorders the array breaks the signature.
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-canonical";
    const canonical = "https://example.com/post/";
    const mirror1   = "https://medium.com/@x/post";
    const mirror2   = "https://substack.com/p/post";

    const payload = schema.buildSigningPayload({
      signer_tip_id: tipId, origin_code: "OH",
      registered_urls: [canonical, mirror1, mirror2],
      authors: [{ tip_id: tipId }],
    }, CONTENT_HASH);

    expect(payload.registered_urls[0]).toBe(canonical);   // canonical preserved at index 0
    expect(payload.registered_urls[1]).toBe(mirror1);
    expect(payload.registered_urls[2]).toBe(mirror2);

    const sig = schema.sign(payload, kp.privateKey);
    expect(schema.verifySignature(payload, sig, kp.publicKey)).toBe(true);

    // Reordering — even keeping the same set of URLs — breaks the signature.
    const reordered = { ...payload, registered_urls: [mirror1, canonical, mirror2] };
    expect(schema.verifySignature(reordered, sig, kp.publicKey)).toBe(false);
  });
});

// ─── Required-field enforcement ─────────────────────────────────────────────

describe("buildSigningPayload — required-field enforcement", () => {
  test("missing signer_tip_id → reject", () => {
    expect(() => schema.buildSigningPayload({
      origin_code: "OH",
      authors: [{ tip_id: "tip://id/US-x" }],
    }, CONTENT_HASH)).toThrow(expect.objectContaining({ status: 400, code: "signer_tip_id_required" }));
  });

  test("authors[] empty → reject", () => {
    expect(() => schema.buildSigningPayload({
      signer_tip_id: "tip://id/US-x", origin_code: "OH",
      authors: [],
    }, CONTENT_HASH)).toThrow(expect.objectContaining({ status: 400, code: "authors_required" }));
  });

  test("authors[] missing → reject", () => {
    expect(() => schema.buildSigningPayload({
      signer_tip_id: "tip://id/US-x", origin_code: "OH",
    }, CONTENT_HASH)).toThrow(expect.objectContaining({ status: 400, code: "authors_required" }));
  });

  test("author entry missing tip_id → reject", () => {
    expect(() => schema.buildSigningPayload({
      signer_tip_id: "tip://id/US-x", origin_code: "OH",
      authors: [{ role: "byline" }],
    }, CONTENT_HASH)).toThrow(expect.objectContaining({ status: 400, code: "authors_tip_id_invalid" }));
  });

  test("content_hash not 64-hex → reject", () => {
    expect(() => schema.buildSigningPayload({
      signer_tip_id: "tip://id/US-x", origin_code: "OH",
      authors: [{ tip_id: "tip://id/US-x" }],
    }, "not-a-hash")).toThrow(expect.objectContaining({ status: 400, code: "content_hash_invalid" }));
  });
});

// ─── canonicalJson rules per docs/CONTENT_SIGNING.md §3 ─────────────────────

describe("canonicalJson — rules per spec", () => {
  test("forward slashes NOT escaped", () => {
    const out = canonicalJson({ url: "https://example.com/post/" });
    expect(out).toContain("https://example.com/post/");
    expect(out).not.toContain("\\/");
  });

  test("empty object emits as {} and empty array emits as []", () => {
    expect(canonicalJson({})).toBe("{}");
    expect(canonicalJson([])).toBe("[]");
  });

  test("keys sorted ASCII-ascending recursively", () => {
    expect(canonicalJson({ z: 1, a: 2, m: { y: 3, b: 4 } }))
      .toBe('{"a":2,"m":{"b":4,"y":3},"z":1}');
  });

  test("non-ASCII characters pass through as UTF-8 (not \\u-escaped)", () => {
    expect(canonicalJson({ name: "Renée" })).toBe('{"name":"Renée"}');
  });
});

// ─── Sign + verify round-trip ───────────────────────────────────────────────

describe("sign + verify — round-trip", () => {
  test("happy path: signed payload verifies under matching pub-key", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-aaaa";
    const payload = schema.buildSigningPayload({
      signer_tip_id: tipId,
      origin_code: "OH",
      registered_urls: ["https://example.com/post/"],
      authors: [{ tip_id: tipId }],
    }, CONTENT_HASH);
    const signature = schema.sign(payload, kp.privateKey);
    expect(schema.verifySignature(payload, signature, kp.publicKey)).toBe(true);
  });

  test("tampering with any field breaks the signature", () => {
    const kp = generateMLDSAKeypair();
    const payload = schema.buildSigningPayload({
      signer_tip_id: "tip://id/US-x", origin_code: "OH",
      authors: [{ tip_id: "tip://id/US-x" }],
    }, CONTENT_HASH);
    const signature = schema.sign(payload, kp.privateKey);
    expect(schema.verifySignature(payload, signature, kp.publicKey)).toBe(true);

    // Flip one field → reject.
    expect(schema.verifySignature({ ...payload, origin_code: "AG" }, signature, kp.publicKey)).toBe(false);
    // Append to authors → reject.
    expect(schema.verifySignature({ ...payload, authors: [...payload.authors, { tip_id: "tip://id/US-y" }] },
      signature, kp.publicKey)).toBe(false);
    // Change registered_urls → reject.
    expect(schema.verifySignature({ ...payload, registered_urls: ["https://other.example/"] },
      signature, kp.publicKey)).toBe(false);
  });

  test("wrong public key → reject", () => {
    const kp = generateMLDSAKeypair();
    const otherKp = generateMLDSAKeypair();
    const payload = schema.buildSigningPayload({
      signer_tip_id: "tip://id/US-x", origin_code: "OH",
      authors: [{ tip_id: "tip://id/US-x" }],
    }, CONTENT_HASH);
    const sig = schema.sign(payload, kp.privateKey);
    expect(schema.verifySignature(payload, sig, otherKp.publicKey)).toBe(false);
  });

  test("missing signature or public key → reject without throwing", () => {
    const payload = schema.buildSigningPayload({
      signer_tip_id: "tip://id/US-x", origin_code: "OH",
      authors: [{ tip_id: "tip://id/US-x" }],
    }, CONTENT_HASH);
    expect(schema.verifySignature(payload, null, "ab")).toBe(false);
    expect(schema.verifySignature(payload, "ab", null)).toBe(false);
  });
});

// ─── Hash determinism — two clients must produce the same bytes ─────────────

describe("payload_hash determinism — every client produces the same hash for equivalent input", () => {
  test("equivalent logical inputs (different insertion order, defaulted fields, garbage stripped) hash identically", () => {
    const a = schema.buildSigningPayload({
      signer_tip_id: "tip://id/US-1234",
      origin_code: "OH",
      registered_urls: ["https://example.com/post/"],
      authors: [{ key_mode: "attribution", role: "byline", signed: false,
                   tip_id: "tip://id/US-1234", tip_id_type: "personal" }],
    }, CONTENT_HASH);

    const b = schema.buildSigningPayload({
      // different insertion order, lowercase origin, garbage on author
      origin_code: "oh",
      signer_tip_id: "tip://id/US-1234",
      authors: [{
        tip_id: "tip://id/US-1234", role: "byline", signed: false,
        tip_id_type: "personal", key_mode: "attribution", garbage: "x",
      }],
      registered_urls: ["https://example.com/post/"],
    }, CONTENT_HASH);

    expect(shake256(canonicalJson(a))).toBe(shake256(canonicalJson(b)));
  });
});

// ─── verifyTx — high-level entry used by commit-handler ────────────────────

describe("verifyTx — DAG-lookup, no fallback", () => {
  function _fakeDag(identityRecord, revoked = false) {
    return {
      getIdentity: (tid) => (identityRecord && identityRecord.tip_id === tid ? identityRecord : null),
      isRevoked:   (tid) => revoked && identityRecord && identityRecord.tip_id === tid,
    };
  }

  function _validTx(kp, tipId) {
    const payload = schema.buildSigningPayload({
      signer_tip_id: tipId, origin_code: "OH",
      authors: [{ tip_id: tipId }],
    }, CONTENT_HASH);
    const signature = schema.sign(payload, kp.privateKey);
    return {
      tx_type: "REGISTER_CONTENT",
      data: {
        signer_tip_id: tipId,
        cna_version: "CNA-2.2",
        attribution_mode: "self",
        authors: payload.authors,
        extras: {},
        origin_code: "OH",
        registered_urls: [],
        content_hash: CONTENT_HASH,
        signature,
      },
    };
  }

  test("happy path: signer on DAG, signature verifies → ok", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-vt-ok";
    const dag = _fakeDag({ tip_id: tipId, public_key: kp.publicKey });
    const tx = _validTx(kp, tipId);
    expect(schema.verifyTx(tx, dag)).toEqual({ ok: true });
  });

  test("media[] consistent with media_canonical_hash → ok", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-vt-media-ok";
    const dag = _fakeDag({ tip_id: tipId, public_key: kp.publicKey });
    const tx = _validTx(kp, tipId);
    const media = [{ media_id: "a".repeat(64), mime: "image/png" }];
    tx.data.media = media;
    tx.data.media_canonical_hash = schema.mediaCanonicalHash(media);
    expect(schema.verifyTx(tx, dag)).toEqual({ ok: true });
  });

  test("media[] tampered after signing → 400 media_canonical_hash_mismatch", () => {
    // Proposing node swaps a media ref on the committed tx. The client
    // signature still verifies (it covers content_hash, not media[]),
    // so the mch re-derivation is the only thing that catches it.
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-vt-media-bad";
    const dag = _fakeDag({ tip_id: tipId, public_key: kp.publicKey });
    const tx = _validTx(kp, tipId);
    const media = [{ media_id: "a".repeat(64), mime: "image/png" }];
    tx.data.media_canonical_hash = schema.mediaCanonicalHash(media);
    tx.data.media = [{ media_id: "b".repeat(64), mime: "image/png" }];  // swapped
    const r = schema.verifyTx(tx, dag);
    expect(r.ok).toBe(false);
    expect(r.code).toBe("media_canonical_hash_mismatch");
  });

  test("signer NOT on DAG → 412 signer_not_registered (no fallback)", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-vt-missing";
    const dag = _fakeDag(null);
    const tx = _validTx(kp, tipId);
    const r = schema.verifyTx(tx, dag);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(412);
    expect(r.code).toBe("signer_not_registered");
  });

  test("signer revoked → 403 signer_revoked", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-vt-revoked";
    const dag = _fakeDag({ tip_id: tipId, public_key: kp.publicKey }, /* revoked */ true);
    const tx = _validTx(kp, tipId);
    const r = schema.verifyTx(tx, dag);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(403);
    expect(r.code).toBe("signer_revoked");
  });

  test("signed by wrong key → 403 signature_invalid", () => {
    const kp = generateMLDSAKeypair();
    const otherKp = generateMLDSAKeypair();
    const tipId = "tip://id/US-vt-wrongkey";
    const dag = _fakeDag({ tip_id: tipId, public_key: otherKp.publicKey });   // DAG has OTHER pubkey
    const tx = _validTx(kp, tipId);                                            // signed with our key
    const r = schema.verifyTx(tx, dag);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(403);
    expect(r.code).toBe("signature_invalid");
  });

  test("unsupported cna_version → 422 cna_unsupported", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-vt-future";
    const dag = _fakeDag({ tip_id: tipId, public_key: kp.publicKey });
    const tx = _validTx(kp, tipId);
    tx.data.cna_version = "CNA-3.0";
    const r = schema.verifyTx(tx, dag);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(422);
    expect(r.code).toBe("cna_unsupported");
  });

  test("missing signature → 400 signature_missing", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-vt-nosig";
    const dag = _fakeDag({ tip_id: tipId, public_key: kp.publicKey });
    const tx = _validTx(kp, tipId);
    delete tx.data.signature;
    const r = schema.verifyTx(tx, dag);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(400);
    expect(r.code).toBe("signature_missing");
  });
});

// ─── M3: media[] validateRequest + mediaCanonicalHash ─────────────────────

describe("validateRequest — media[] shape checks", () => {
  function _baseBody(tipId) {
    return {
      signer_tip_id: tipId,
      origin_code: "OH",
      signature: "deadbeef",
      content: "some content",
      registered_urls: ["https://example.com/post/"], // required as of registered_urls gate
      authors: [{ tip_id: tipId, role: "byline", key_mode: "attribution", signed: false, tip_id_type: "personal" }],
    };
  }
  function _depsFor(tipId, kp, opts = {}) {
    return {
      mediaLimits: { media_items_max: opts.itemsMax ?? 8 },
      dag: {
        getIdentity: (t) => (t === tipId ? { tip_id: tipId, public_key: kp.publicKey, status: "active" } : null),
        isRevoked: () => false,
      },
    };
  }

  test("media[] missing — accepted (text-only path)", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-m3-noimg";
    expect(() => schema.validateRequest(_baseBody(tipId), _depsFor(tipId, kp))).not.toThrow();
  });

  test("media not an array → media_invalid", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-m3-bad";
    const body = { ..._baseBody(tipId), media: "not-an-array" };
    expect(() => schema.validateRequest(body, _depsFor(tipId, kp)))
      .toThrow(expect.objectContaining({ code: "media_invalid" }));
  });

  test("media[] exceeds limit → media_items_max", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-m3-toomany";
    const body = {
      ..._baseBody(tipId),
      media: Array.from({ length: 3 }, (_, i) => ({
        media_id: String(i).padStart(64, "a"),
        mime: "image/png",
      })),
    };
    expect(() => schema.validateRequest(body, _depsFor(tipId, kp, { itemsMax: 2 })))
      .toThrow(expect.objectContaining({ code: "media_items_max" }));
  });

  test("media_id wrong length → media_id_invalid", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-m3-shortid";
    const body = { ..._baseBody(tipId), media: [{ media_id: "abc", mime: "image/png" }] };
    expect(() => schema.validateRequest(body, _depsFor(tipId, kp)))
      .toThrow(expect.objectContaining({ code: "media_id_invalid" }));
  });

  test("media_id uppercase hex rejected — strictly lowercase per content-addressed convention", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-m3-uppercase";
    const body = { ..._baseBody(tipId), media: [{ media_id: "A".repeat(64), mime: "image/png" }] };
    expect(() => schema.validateRequest(body, _depsFor(tipId, kp)))
      .toThrow(expect.objectContaining({ code: "media_id_invalid" }));
  });

  test("mime not image/audio/video → media_mime_invalid", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-m3-badmime";
    const body = { ..._baseBody(tipId), media: [{ media_id: "a".repeat(64), mime: "application/pdf" }] };
    expect(() => schema.validateRequest(body, _depsFor(tipId, kp)))
      .toThrow(expect.objectContaining({ code: "media_mime_invalid" }));
  });

  test("happy path: media[] with one image accepted", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-m3-happy";
    const body = { ..._baseBody(tipId), media: [{ media_id: "a".repeat(64), mime: "image/png" }] };
    expect(() => schema.validateRequest(body, _depsFor(tipId, kp))).not.toThrow();
  });
});

describe("mediaCanonicalHash — derivation", () => {
  test("empty or missing media → null (caller treats as no media)", () => {
    expect(schema.mediaCanonicalHash([])).toBeNull();
    expect(schema.mediaCanonicalHash(null)).toBeNull();
    expect(schema.mediaCanonicalHash(undefined)).toBeNull();
  });

  test("single media → shake256(media_id)", () => {
    const mid = "a".repeat(64);
    expect(schema.mediaCanonicalHash([{ media_id: mid, mime: "image/png" }]))
      .toBe(shake256(mid));
  });

  test("ordered concat — swapping order changes the hash (catches reorder tampering)", () => {
    const a = "a".repeat(64), b = "b".repeat(64);
    const h1 = schema.mediaCanonicalHash([{ media_id: a }, { media_id: b }]);
    const h2 = schema.mediaCanonicalHash([{ media_id: b }, { media_id: a }]);
    expect(h1).not.toBe(h2);
  });
});

// ─── Perceptual fingerprint binding (advisory, off-DAG) ─────────────────────

describe("perceptual fingerprint — commit + signed-payload strip-rule", () => {
  const zlib = require("zlib");
  const ITEMS = [
    { kind: "image", role: "primary", perceptual: { profile: "cf-image-1", kind: "image", pdq: "ab".repeat(32), quality: 95 } },
    { kind: "text", role: "caption", perceptual: { profile: TEXT_PROFILE, kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash: [1, 2, 3] } },
  ];
  const pack = (items, encoding = "gzip+base64") => {
    const json = JSON.stringify(items);
    const data = encoding === "identity" ? json : zlib.gzipSync(Buffer.from(json, "utf8")).toString("base64");
    return { profile: "cf-fingerprints-1", count: items.length, encoding, data };
  };
  const ENVELOPE = pack(ITEMS);

  function expectThrowCode(fn, code) {
    let err;
    try { fn(); } catch (e) { err = e; }
    expect(err).toBeDefined();
    expect(err.code).toBe(code);
  }

  const baseInput = {
    signer_tip_id: "tip://id/US-fp",
    origin_code: "OH",
    authors: [{ tip_id: "tip://id/US-fp" }],
  };

  test("fingerprintsCommit hashes the recovered bytes verbatim; identity and gzip agree", () => {
    const expected = shake256(JSON.stringify(ITEMS)); // shake256 of the exact decoded bytes
    expect(schema.fingerprintsCommit(ENVELOPE)).toBe(expected);
    expect(schema.fingerprintsCommit(pack(ITEMS, "identity"))).toBe(expected);
  });

  test("parseFingerprintItems recovers the ordered items[] (both encodings)", () => {
    expect(schema.parseFingerprintItems(ENVELOPE)).toEqual(ITEMS);
    expect(schema.parseFingerprintItems(pack(ITEMS, "identity"))).toEqual(ITEMS);
  });

  test("strip-rule: no fingerprint_commit → field absent from canonical payload", () => {
    const payload = schema.buildSigningPayload(baseInput, CONTENT_HASH);
    expect(payload).not.toHaveProperty("fingerprint_commit");
    expect(Object.keys(payload)).toHaveLength(8);
  });

  test("present fingerprint_commit → bound into the signed payload as the 9th field", () => {
    const commit = schema.fingerprintsCommit(ENVELOPE);
    const payload = schema.buildSigningPayload({ ...baseInput, fingerprint_commit: commit }, CONTENT_HASH);
    expect(payload.fingerprint_commit).toBe(commit);
    expect(Object.keys(payload)).toHaveLength(9);
  });

  test("malformed fingerprint_commit (not 64-hex) → reject at build", () => {
    expectThrowCode(
      () => schema.buildSigningPayload({ ...baseInput, fingerprint_commit: "nope" }, CONTENT_HASH),
      "fingerprint_commit_invalid",
    );
  });
});

describe("perceptual fingerprint — validateRequest envelope gate (throws before DAG lookups)", () => {
  const zlib = require("zlib");
  const pack = (items, encoding = "gzip+base64") => {
    const json = JSON.stringify(items);
    const data = encoding === "identity" ? json : zlib.gzipSync(Buffer.from(json, "utf8")).toString("base64");
    return { profile: "cf-fingerprints-1", count: items.length, encoding, data };
  };
  function expectThrowCode(fn, code) {
    let err;
    try { fn(); } catch (e) { err = e; }
    expect(err).toBeDefined();
    expect(err.code).toBe(code);
  }
  const ITEMS = [{ kind: "audio", role: "audio", perceptual: { profile: "cf-audio-landmark-1", kind: "audio", landmarks: [{ hash: 1, t: 0 }] } }];
  const ENV = pack(ITEMS);
  // media:[] satisfies the content/media-required gate without inline content;
  // the fingerprint branch runs before the authors[]/DAG checks, so a bad
  // envelope throws without needing a populated DAG.
  const base = (extra) => ({
    signer_tip_id: "tip://id/US-fp", origin_code: "OH", signature: "x", media: [], ...extra,
  });
  const deps = { mediaLimits: {}, dag: {} };

  test("fingerprints without commit → reject (can't bind)", () => {
    expectThrowCode(() => schema.validateRequest(base({ fingerprints: ENV }), deps), "fingerprint_commit_required");
  });

  test("commit without fingerprints → reject (nothing to ingest)", () => {
    expectThrowCode(
      () => schema.validateRequest(base({ fingerprint_commit: "a".repeat(64) }), deps),
      "fingerprint_commit_required",
    );
  });

  test("unknown envelope profile → reject", () => {
    const bad = { ...ENV, profile: "cf-fingerprints-99" };
    expectThrowCode(
      () => schema.validateRequest(base({ fingerprints: bad, fingerprint_commit: schema.fingerprintsCommit(bad) }), deps),
      "fingerprints_profile_invalid",
    );
  });

  test("unknown encoding → reject", () => {
    const bad = { ...ENV, encoding: "brotli" };
    expectThrowCode(
      () => schema.validateRequest(base({ fingerprints: bad, fingerprint_commit: "a".repeat(64) }), deps),
      "fingerprints_encoding_invalid",
    );
  });

  test("item with unknown modality kind → reject", () => {
    const badItems = [{ kind: "hologram", perceptual: { profile: "x", kind: "hologram" } }];
    const env = pack(badItems);
    expectThrowCode(
      () => schema.validateRequest(base({ fingerprints: env, fingerprint_commit: schema.fingerprintsCommit(env) }), deps),
      "fingerprint_kind_invalid",
    );
  });

  test("commit that doesn't match the envelope → reject", () => {
    expectThrowCode(
      () => schema.validateRequest(base({ fingerprints: ENV, fingerprint_commit: "b".repeat(64) }), deps),
      "fingerprint_commit_mismatch",
    );
  });

  test("reject-tier item is accepted (no profile required) — passes the fingerprint gate", () => {
    const items = [{ kind: "image", role: "primary", perceptual: { kind: "image", tier: "reject", reason: "decode_failed" } }];
    const env = pack(items);
    let err;
    try {
      schema.validateRequest(base({ fingerprints: env, fingerprint_commit: schema.fingerprintsCommit(env) }), deps);
    } catch (e) { err = e; }
    // It must NOT fail with a fingerprint_* code (it gets past the gate and
    // trips a later, unrelated check — authors/DAG — which is fine here).
    expect(String(err && err.code)).not.toMatch(/^fingerprint/);
  });
});

describe("perceptual fingerprint — verifyTx (commit is a signed field; no blob on tx)", () => {
  function _fakeDag(rec) {
    return { getIdentity: (tid) => (rec && rec.tip_id === tid ? rec : null), isRevoked: () => false };
  }
  const COMMIT = "ab".repeat(32); // a 64-hex commit; the blob it commits to never rides the tx

  // Build a REGISTER_CONTENT tx whose signature covers `fingerprint_commit`.
  function _signedTx(kp, tipId, { commit } = {}) {
    const input = { signer_tip_id: tipId, origin_code: "OH", authors: [{ tip_id: tipId }] };
    if (commit) input.fingerprint_commit = commit;
    const payload = schema.buildSigningPayload(input, CONTENT_HASH);
    const signature = schema.sign(payload, kp.privateKey);
    return {
      tx_type: "REGISTER_CONTENT",
      data: {
        signer_tip_id: tipId, cna_version: "CNA-2.2", attribution_mode: "self",
        authors: payload.authors, extras: {}, origin_code: "OH", registered_urls: [],
        content_hash: CONTENT_HASH, signature,
        ...(commit ? { fingerprint_commit: commit } : {}),
      },
    };
  }

  test("signed fingerprint_commit → verifies ok (covered by the signature)", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-fp-ok";
    const dag = _fakeDag({ tip_id: tipId, public_key: kp.publicKey });
    expect(schema.verifyTx(_signedTx(kp, tipId, { commit: COMMIT }), dag)).toEqual({ ok: true });
  });

  test("injected fingerprint_commit not covered by signature → signature_invalid", () => {
    const kp = generateMLDSAKeypair();
    const tipId = "tip://id/US-fp-inject";
    const dag = _fakeDag({ tip_id: tipId, public_key: kp.publicKey });
    const tx = _signedTx(kp, tipId); // signed WITHOUT a commit
    tx.data.fingerprint_commit = COMMIT; // attacker adds it post-signing
    const r = schema.verifyTx(tx, dag);
    expect(r.ok).toBe(false);
    expect(r.code).toBe("signature_invalid");
  });
});
