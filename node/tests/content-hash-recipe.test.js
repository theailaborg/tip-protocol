/**
 * @file tests/content-hash-recipe.test.js
 * @description Golden freeze for the CNA-MIX-1 content_hash recipe.
 *
 * Why this exists separately from signing-canonical-vectors.test.js:
 *   That suite freezes `canonicalJson(buildSigningPayload(data))`, and the
 *   signed payload carries `content_hash` but NOT `media[]` or
 *   `media_canonical_hash`. It therefore pins the content_hash VALUE it is
 *   handed, never the recipe that derived it. Adding a `.sort()` to
 *   mediaCanonicalHash would leave that suite green while silently breaking
 *   verification of every multi-media registration on the chain.
 *
 *   The recipe is frozen for the same reason the payloads are: a signature
 *   commits to specific bytes. Changing how the server derives content_hash
 *   makes it derive a different value than the author signed. Per
 *   docs/SIGNING_VERSIONING.md that is a breaking change requiring a new
 *   tx_type, never an in-place edit — so these values must not move.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const {
  shake256, tipNormalize, generateMLDSAKeypair, initCrypto,
} = require(path.resolve(__dirname, "../../shared/crypto"));
const contentRegister = require(path.resolve(__dirname, "../src/schemas/content-register"));
const { mediaCanonicalHash } = contentRegister;

beforeAll(async () => { await initCrypto(); });

const A = "a".repeat(64);
const B = "b".repeat(64);

// Frozen. Regenerating these means the chain's existing content no longer
// verifies; mint a new tx_type instead.
const FROZEN = {
  mch_AB: "9922955978a62d295a10fea400566dc803e53e3d3009790c5eaf688ee803f031",
  mch_BA: "aa4bb55fe45652b0a0974c16285c207ea6cda74621653e8cc05e8ffd48c5c540",
  empty_text: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
  media_only: "6053ed60fe8e5379f60114f3c3608b02ad4f814112d1ffbdf59c5db2588d9b68",
  text_only: "706ced3ac5b9f8445c2d81c57209e97340df83a18d6b4126e187c5051dbfffbd",
  mixed: "fec697fdc418a73744b5d1e182b1ac2a2fd942f10f9501108b29d6703383c79e",
};

// The production composition, mirrored from content-service.register().
const contentHash = (media, text) => {
  const mch = mediaCanonicalHash(media);
  const th = text ? shake256(tipNormalize(text)) : shake256("");
  return mch ? shake256(mch + th) : th;
};

const ref = (id) => ({ media_id: id, mime: "image/jpeg" });

describe("media_canonical_hash", () => {
  test("is shake256 of media_ids concatenated with no separator", () => {
    expect(mediaCanonicalHash([ref(A), ref(B)])).toBe(FROZEN.mch_AB);
    expect(mediaCanonicalHash([ref(A), ref(B)])).toBe(shake256(A + B));
  });

  test("is order-significant: reordering yields a different artifact", () => {
    expect(mediaCanonicalHash([ref(B), ref(A)])).toBe(FROZEN.mch_BA);
    expect(FROZEN.mch_AB).not.toBe(FROZEN.mch_BA);
  });

  test("is null for absent or empty media, so text-only keeps the plain text hash", () => {
    expect(mediaCanonicalHash([])).toBeNull();
    expect(mediaCanonicalHash(undefined)).toBeNull();
  });

  // The separatorless join is injective ONLY because every media_id is exactly
  // 64 hex (enforced by validateRequest and, on the gossip path, verifyTx).
  // Drop that and ["ab","c"] collides with ["a","bc"].
  test("fixed-width ids are what make the concatenation unambiguous", () => {
    const split = shake256("ab" + "c");
    const other = shake256("a" + "bc");
    expect(split).toBe(other);
  });
});

describe("content_hash composition (CNA-MIX-1)", () => {
  test("media only: shake256(mch + shake256(''))", () => {
    expect(shake256("")).toBe(FROZEN.empty_text);
    expect(contentHash([ref(A), ref(B)], null)).toBe(FROZEN.media_only);
  });

  test("text only: the normalised text hash, unwrapped", () => {
    expect(contentHash([], "Hello TIP")).toBe(FROZEN.text_only);
  });

  test("mixed: shake256(mch + textHash)", () => {
    expect(contentHash([ref(A), ref(B)], "Hello TIP")).toBe(FROZEN.mixed);
  });

  test("same text with different media does not collide", () => {
    expect(contentHash([ref(A)], "Hello TIP")).not.toBe(contentHash([ref(B)], "Hello TIP"));
  });

  test("same media with different text does not collide", () => {
    expect(contentHash([ref(A), ref(B)], "one")).not.toBe(contentHash([ref(A), ref(B)], "two"));
  });
});

// validateRequest pins media_id to 64 hex on the API path. A gossiped tx never
// passes through it, so verifyTx must re-check: without it a proposing node can
// re-split the signed concatenation (64+64 -> 32+96) into refs the author never
// signed, and the mch still matches.
describe("verifyTx: media_id shape on the gossip path", () => {
  const SIGNER = `tip://id/US-${"1".repeat(16)}`;

  function _buildTx(media, privateKey) {
    const mch = mediaCanonicalHash(media);
    const ch = shake256(mch + shake256(""));
    const data = {
      ctid: ch.slice(0, 14),
      signer_tip_id: SIGNER,
      origin_code: "OH",
      authors: [{ tip_id: SIGNER }],
      content_hash: ch,
      media,
      media_canonical_hash: mch,
      cna_version: contentRegister.CURRENT_CNA_VERSION,
    };
    data.signature = contentRegister.sign(
      contentRegister.buildSigningPayload(data, ch), privateKey,
    );
    return { tx_type: "REGISTER_CONTENT", data };
  }

  function _dag(publicKey) {
    return {
      getIdentity: () => ({ tip_id: SIGNER, public_key: publicKey, tip_id_type: "personal" }),
      isRevoked: () => false,
    };
  }

  test("accepts well-formed 64-hex refs", () => {
    const kp = generateMLDSAKeypair();
    const res = contentRegister.verifyTx(_buildTx([ref(A), ref(B)], kp.privateKey), _dag(kp.publicKey));
    expect(res.ok).toBe(true);
  });

  test("rejects a re-split that preserves the concatenation but not the refs", () => {
    const kp = generateMLDSAKeypair();
    // 32 + 96 hex chars: same 128-char concatenation, so the mch still matches.
    const split = [ref(A.slice(0, 32)), ref(A.slice(32) + B)];
    expect(mediaCanonicalHash(split)).toBe(mediaCanonicalHash([ref(A), ref(B)]));

    const res = contentRegister.verifyTx(_buildTx(split, kp.privateKey), _dag(kp.publicKey));
    expect(res.ok).toBe(false);
    expect(res.code).toBe("media_id_invalid");
  });
});
