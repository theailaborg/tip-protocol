"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");

// Initialise protocol constants from genesis once for all tests.
const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const PC = require(path.join(SHARED, "protocol-constants"));
try { PC._resetForTesting(); } catch { /* not yet initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const {
  deriveContentType,
  validateAgainstShape,
  resolve,
  primaryModality,
} = require(path.resolve(__dirname, "../../src/services/content-type"));

describe("deriveContentType", () => {
  test("text only → text", () => {
    expect(deriveContentType({ text: "hello world" })).toBe("text");
  });

  test("empty body returns null (caller rejects 400)", () => {
    expect(deriveContentType({})).toBeNull();
    expect(deriveContentType({ text: "" })).toBeNull();
    expect(deriveContentType({ text: "", media: [] })).toBeNull();
  });

  test("short text + image → image (photo-with-caption)", () => {
    const r = { text: "great shot", media: [{ mime: "image/jpeg" }] };
    expect(deriveContentType(r)).toBe("image");
  });

  test("long text + image → text (article-with-hero)", () => {
    const r = { text: "x".repeat(1500), media: [{ mime: "image/jpeg" }] };
    expect(deriveContentType(r)).toBe("text");
  });

  test("text + audio file → audio (audio dominates)", () => {
    const r = { text: "description", media: [{ mime: "audio/mpeg" }] };
    expect(deriveContentType(r)).toBe("audio");
  });

  test("text + video file → video", () => {
    const r = { text: "watch this", media: [{ mime: "video/mp4" }] };
    expect(deriveContentType(r)).toBe("video");
  });

  test("multiple media kinds → multi", () => {
    const r = { text: "", media: [{ mime: "image/png" }, { mime: "audio/mpeg" }] };
    expect(deriveContentType(r)).toBe("multi");
  });

  test("video + image → multi (two kinds)", () => {
    const r = { media: [{ mime: "video/mp4" }, { mime: "image/jpeg" }] };
    expect(deriveContentType(r)).toBe("multi");
  });

  test("multiple images of same kind → still image (not multi)", () => {
    const r = { text: "caption", media: [{ mime: "image/png" }, { mime: "image/jpeg" }] };
    expect(deriveContentType(r)).toBe("image");
  });

  test("MIME case-insensitive", () => {
    expect(deriveContentType({ media: [{ mime: "VIDEO/MP4" }] })).toBe("video");
    expect(deriveContentType({ media: [{ mime: "Image/PNG" }] })).toBe("image");
  });

  test("article threshold boundary (1000 chars)", () => {
    const at = "x".repeat(1000);
    const below = "x".repeat(999);
    expect(deriveContentType({ text: at, media: [{ mime: "image/jpeg" }] })).toBe("text");
    expect(deriveContentType({ text: below, media: [{ mime: "image/jpeg" }] })).toBe("image");
  });
});

describe("validateAgainstShape", () => {
  test("hint=text + only text → ok", () => {
    expect(validateAgainstShape("text", { text: "hello" })).toEqual({ ok: true });
  });

  test("hint=image + image file present → ok", () => {
    expect(
      validateAgainstShape("image", { text: "caption", media: [{ mime: "image/png" }] })
    ).toEqual({ ok: true });
  });

  test("hint=video but no video file → reject", () => {
    expect(validateAgainstShape("video", { text: "watch" })).toEqual({
      ok: false,
      code: "missing_video",
      message: expect.stringMatching(/video file/i),
    });
  });

  test("hint=audio but no audio file → reject", () => {
    expect(validateAgainstShape("audio", { text: "listen" })).toMatchObject({
      ok: false,
      code: "missing_audio",
    });
  });

  test("hint=image but no image file → reject", () => {
    expect(validateAgainstShape("image", { text: "no pic" })).toMatchObject({
      ok: false,
      code: "missing_image",
    });
  });

  test("invalid content_type → reject", () => {
    expect(validateAgainstShape("podcast", { text: "x" })).toMatchObject({
      ok: false,
      code: "invalid_content_type",
    });
  });

  test("hint=text + 30MB video + 5 char text → auto-correct to video", () => {
    const r = { text: "lol", media: [{ mime: "video/mp4", size: 31457280 }] };
    expect(validateAgainstShape("text", r)).toMatchObject({
      ok: true,
      correctedTo: "video",
      reason: expect.stringMatching(/text but.*media/),
    });
  });

  test("hint=text with substantial text (≥100 chars) + image → trust hint (no correction)", () => {
    const r = { text: "x".repeat(150), media: [{ mime: "image/jpeg" }] };
    expect(validateAgainstShape("text", r)).toEqual({ ok: true });
  });

  test("hint=multi with single-kind media → trust hint (always valid)", () => {
    const r = { text: "caption", media: [{ mime: "image/png" }] };
    expect(validateAgainstShape("multi", r)).toEqual({ ok: true });
  });
});

describe("resolve", () => {
  test("no hint → derives from shape", () => {
    expect(resolve({ text: "hello" })).toEqual({
      contentType: "text",
      hintProvided: null,
      resolution: "derived",
      reason: null,
    });
  });

  test("matching hint → from_hint", () => {
    expect(
      resolve({ content_type_hint: "image", text: "cap", media: [{ mime: "image/png" }] })
    ).toEqual({
      contentType: "image",
      hintProvided: "image",
      resolution: "from_hint",
      reason: null,
    });
  });

  test("major mismatch hint (video declared, no video) → throws 400", () => {
    expect(() => resolve({ content_type_hint: "video", text: "x" })).toThrow(
      expect.objectContaining({ status: 400, code: "missing_video" })
    );
  });

  test("auto-correctable hint (text + huge video file) → auto_corrected", () => {
    const r = {
      content_type_hint: "text",
      text: "lol",
      media: [{ mime: "video/mp4", size: 31457280 }],
    };
    expect(resolve(r)).toMatchObject({
      contentType: "video",
      hintProvided: "text",
      resolution: "auto_corrected_from_hint",
      reason: expect.stringMatching(/text but.*media/),
    });
  });

  test("empty request → throws 400 no_content_to_classify", () => {
    expect(() => resolve({})).toThrow(
      expect.objectContaining({ status: 400, code: "no_content_to_classify" })
    );
  });

  test("invalid hint string → throws 400", () => {
    expect(() => resolve({ content_type_hint: "podcast", text: "x" })).toThrow(
      expect.objectContaining({ status: 400, code: "invalid_content_type" })
    );
  });

  test("hint=multi accepted even with single-modality content", () => {
    expect(
      resolve({ content_type_hint: "multi", text: "x", media: [{ mime: "image/png" }] })
    ).toMatchObject({
      contentType: "multi",
      resolution: "from_hint",
    });
  });
});

describe("primaryModality", () => {
  test("returns the modality name for each content type", () => {
    expect(primaryModality("text")).toBe("text");
    expect(primaryModality("image")).toBe("image");
    expect(primaryModality("audio")).toBe("audio");
    expect(primaryModality("video")).toBe("video");
  });

  test("multi returns null (no single primary)", () => {
    expect(primaryModality("multi")).toBeNull();
  });

  test("unknown content type returns null", () => {
    expect(primaryModality("unknown")).toBeNull();
  });
});
