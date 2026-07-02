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
  resolvePlatformStrategy,
  applyStrategy,
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

  test("hint=text with media + trivial text body → trust hint (publisher is authoritative)", () => {
    // Publisher's signed hint wins even when shape suggests otherwise.
    // The classifier still scans the video modality; aggregator weights
    // both modalities so AI signal isn't lost.
    const r = { text: "lol", media: [{ mime: "video/mp4", size: 31457280 }] };
    expect(validateAgainstShape("text", r)).toEqual({ ok: true });
  });

  test("hint=text with substantial text + image → trust hint", () => {
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
      platformStrategy: null,
    });
  });

  test("matching hint → from_hint", () => {
    expect(
      resolve({ content_type_hint: "image", text: "cap", media: [{ mime: "image/png" }] })
    ).toEqual({
      contentType: "image",
      hintProvided: "image",
      resolution: "from_hint",
      platformStrategy: null,
    });
  });

  test("major mismatch hint (video declared, no video) → throws 400", () => {
    expect(() => resolve({ content_type_hint: "video", text: "x" })).toThrow(
      expect.objectContaining({ status: 400, code: "missing_video" })
    );
  });

  test("hint=text with video media → trusts hint (no auto-correction)", () => {
    // Publisher's signed declaration wins; the aggregator's weighted-
    // average path still scans the video modality, so AI signal isn't
    // lost when the resolved type is "text".
    const r = {
      content_type_hint: "text",
      text: "lol",
      media: [{ mime: "video/mp4", size: 31457280 }],
    };
    expect(resolve(r)).toMatchObject({
      contentType: "text",
      hintProvided: "text",
      resolution: "from_hint",
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

// ─── Explicit per-platform expectations ──────────────────────────────────
// Hand-coded URL → expected end-to-end content_type. Each entry is an
// independent assertion of how that platform's URL should resolve; values
// are NOT derived from PLATFORM_CONTENT_TYPE so a registry change to a
// "wrong" strategy (e.g. youtube → "audio") fails these tests loudly.
//
// Add a new platform: add one line per representative shape here AND add
// the registry entry. Both must agree.

const IMG  = { mime: "image/jpeg" };
const VID  = { mime: "video/mp4" };
const AUD  = { mime: "audio/mpeg" };

const PLATFORM_EXPECTATIONS = [
  // ── FIXED:video — platform is video regardless of shape ──
  { url: "https://youtube.com/watch?v=abc",       shape: { text: "long description", media: [VID] }, expected: "video" },
  { url: "https://www.youtube.com/watch?v=abc",   shape: { text: "x", media: [VID] },                expected: "video" },
  { url: "https://youtu.be/abc",                  shape: { text: "", media: [VID] },                 expected: "video" },  // alias
  { url: "https://m.youtube.com/watch?v=abc",     shape: { text: "", media: [VID] },                 expected: "video" },  // alias
  { url: "https://music.youtube.com/watch?v=abc", shape: { text: "", media: [AUD] },                 expected: "video" },  // alias (intentional: music.yt routes to youtube)
  { url: "https://vimeo.com/12345",               shape: { text: "", media: [VID] },                 expected: "video" },

  // ── FIXED:audio ──
  { url: "https://spotify.com/episode/123",        shape: { text: "", media: [AUD] }, expected: "audio" },
  { url: "https://open.spotify.com/episode/123",   shape: { text: "", media: [AUD] }, expected: "audio" },  // alias
  { url: "https://podcasts.apple.com/show/x",      shape: { text: "show notes", media: [AUD] }, expected: "audio" },
  { url: "https://soundcloud.com/u/track-name",    shape: { text: "", media: [AUD] }, expected: "audio" },
  { url: "https://on.soundcloud.com/abc",          shape: { text: "", media: [AUD] }, expected: "audio" },  // alias

  // ── MEDIA_DOMINANT — visual-first; long caption stays media ──
  { url: "https://instagram.com/p/abc",        shape: { text: "tiny",                media: [IMG] }, expected: "image" },
  { url: "https://instagram.com/p/abc",        shape: { text: "x".repeat(2000),      media: [IMG] }, expected: "image" },   // long caption ≠ article
  { url: "https://instagram.com/reel/abc",     shape: { text: "caption",             media: [VID] }, expected: "video" },   // Reel
  { url: "https://instagram.com/p/abc",        shape: { text: "x", media: [IMG, VID] },              expected: "multi" },   // carousel mixed
  { url: "https://tiktok.com/@user/video/1",   shape: { text: "caption",             media: [VID] }, expected: "video" },
  { url: "https://tiktok.com/@user/photo/2",   shape: { text: "caption",             media: [IMG] }, expected: "image" },   // photo carousel

  // ── MIXED (X / FB / LinkedIn / Reddit / Threads / Mastodon / …) ──
  // text only → text
  { url: "https://x.com/u/status/1",            shape: { text: "thread post", media: [] }, expected: "text" },
  { url: "https://twitter.com/u/status/1",      shape: { text: "tweet only",  media: [] }, expected: "text" },   // alias
  { url: "https://facebook.com/u/posts/1",      shape: { text: "status",      media: [] }, expected: "text" },
  { url: "https://fb.com/u/posts/1",            shape: { text: "status",      media: [] }, expected: "text" },   // alias
  { url: "https://reddit.com/r/sub/comments/1", shape: { text: "essay",       media: [] }, expected: "text" },
  // image only → image
  { url: "https://x.com/u/status/2",            shape: { text: "", media: [IMG] }, expected: "image" },
  { url: "https://facebook.com/u/posts/2",      shape: { text: "", media: [IMG] }, expected: "image" },
  // image + caption → multi  (key X/FB case: text might be the work)
  { url: "https://x.com/u/status/3",            shape: { text: "short caption",   media: [IMG] }, expected: "multi" },
  { url: "https://x.com/u/status/4",            shape: { text: "x".repeat(2000),  media: [IMG] }, expected: "multi" },
  { url: "https://facebook.com/u/posts/3",      shape: { text: "x".repeat(1500),  media: [IMG] }, expected: "multi" },
  { url: "https://linkedin.com/posts/u_x",      shape: { text: "career update",   media: [IMG] }, expected: "multi" },
  { url: "https://reddit.com/r/sub/comments/2", shape: { text: "discussion",      media: [IMG] }, expected: "multi" },
  { url: "https://threads.net/@u/post/1",       shape: { text: "thread",          media: [IMG] }, expected: "multi" },
  { url: "https://mastodon.social/@u/1",        shape: { text: "toot",            media: [IMG] }, expected: "multi" },
  { url: "https://truthsocial.com/@u/posts/1",  shape: { text: "post",            media: [IMG] }, expected: "multi" },
  { url: "https://weibo.com/u/post/1",          shape: { text: "weibo",           media: [IMG] }, expected: "multi" },
  { url: "https://wechat.com/u/post/1",         shape: { text: "wechat",          media: [IMG] }, expected: "multi" },
  // video + text → video (attention-dominant)
  { url: "https://x.com/u/status/5",            shape: { text: "x".repeat(2000), media: [VID] }, expected: "video" },
  { url: "https://facebook.com/u/posts/4",      shape: { text: "watch this",     media: [VID] }, expected: "video" },
  // audio + text → audio (attention-dominant)
  { url: "https://x.com/u/status/6",            shape: { text: "listen",         media: [AUD] }, expected: "audio" },
  // mixed media kinds → multi
  { url: "https://x.com/u/status/7",            shape: { text: "", media: [IMG, VID] }, expected: "multi" },

  // ── TEXT_DOMINANT (article / blog / news) — text wins even with hero image ──
  { url: "https://medium.com/@u/post",                shape: { text: "essay", media: [IMG] }, expected: "text" },
  { url: "https://anyone.substack.com/p/post",        shape: { text: "essay", media: [IMG] }, expected: "text" },   // subdomain
  { url: "https://substack.com/inbox/post-1",         shape: { text: "essay", media: [IMG] }, expected: "text" },
  { url: "https://nytimes.com/2026/05/30/article",    shape: { text: "article", media: [IMG] }, expected: "text" },
  { url: "https://www.nytimes.com/article",           shape: { text: "article", media: [] },    expected: "text" },  // www
  { url: "https://wsj.com/articles/x",                shape: { text: "article", media: [] },    expected: "text" },
  { url: "https://reuters.com/world/x",               shape: { text: "article", media: [IMG] }, expected: "text" },
  { url: "https://apnews.com/article/x",              shape: { text: "article", media: [] },    expected: "text" },
  { url: "https://bbc.com/news/world-x",              shape: { text: "article", media: [IMG] }, expected: "text" },
  { url: "https://bbc.co.uk/news/world-x",            shape: { text: "article", media: [IMG] }, expected: "text" },  // alias
  { url: "https://boomlive.in/fact-check/x",          shape: { text: "factcheck", media: [IMG] }, expected: "text" },
  { url: "https://theguardian.com/world/x",           shape: { text: "article", media: [] },    expected: "text" },
  { url: "https://washingtonpost.com/world/x",        shape: { text: "article", media: [] },    expected: "text" },
  { url: "https://my-blog.wordpress.com/2026/05",     shape: { text: "blog",     media: [IMG] }, expected: "text" },  // subdomain
  { url: "https://my-blog.blogspot.com/post",         shape: { text: "blog",     media: [] },    expected: "text" },
  { url: "https://tumblr.com/u/post/123",             shape: { text: "post",     media: [IMG] }, expected: "text" },
  { url: "https://ghost.io/post-slug",                shape: { text: "post",     media: [] },    expected: "text" },
  { url: "https://scribd.com/document/123",           shape: { text: "doc",      media: [] },    expected: "text" },
  { url: "https://slideshare.net/u/deck",             shape: { text: "deck",     media: [IMG] }, expected: "text" },
  // TEXT_DOMINANT media-only edge case: image embed with no text → image
  { url: "https://medium.com/@u/image-post",          shape: { text: "", media: [IMG] }, expected: "image" },
];

describe("platform registry — explicit URL → content_type expectations", () => {
  test.each(PLATFORM_EXPECTATIONS)(
    "$url + shape → $expected",
    ({ url, shape, expected }) => {
      const result = resolve({ ...shape, registered_url: url });
      expect(result.contentType).toBe(expected);
    }
  );
});

describe("platform registry — referential integrity", () => {
  const { PLATFORM_ALIASES, PLATFORM_CONTENT_TYPE } = require(path.join(SHARED, "platforms"));

  // Every alias must point to a canonical entry that actually exists in
  // the strategy map. Catches typos like {"twitter.com": "X.com"} that
  // would otherwise silently fail resolution at runtime.
  test("every alias target resolves to a known canonical platform", () => {
    for (const [alias, canonical] of Object.entries(PLATFORM_ALIASES)) {
      expect({ alias, canonical, strategy: PLATFORM_CONTENT_TYPE[canonical] })
        .toEqual({ alias, canonical, strategy: expect.any(String) });
    }
  });

  // Every canonical entry's strategy must be a valid strategy keyword.
  // Catches casing typos (e.g., "Video" vs "video", "Mixed" vs "MIXED").
  test("every canonical strategy is a valid keyword", () => {
    const VALID = new Set(["video", "audio", "image", "text", "MEDIA_DOMINANT", "MIXED", "TEXT_DOMINANT"]);
    for (const [host, strategy] of Object.entries(PLATFORM_CONTENT_TYPE)) {
      expect({ host, strategy, valid: VALID.has(strategy) })
        .toEqual({ host, strategy, valid: true });
    }
  });
});

describe("resolvePlatformStrategy", () => {
  test("exact host match → strategy", () => {
    expect(resolvePlatformStrategy("https://youtube.com/watch?v=x")).toBe("video");
    expect(resolvePlatformStrategy("https://medium.com/@x/post")).toBe("TEXT_DOMINANT");
    expect(resolvePlatformStrategy("https://instagram.com/p/abc")).toBe("MEDIA_DOMINANT");
    expect(resolvePlatformStrategy("https://x.com/user/status/1")).toBe("MIXED");
  });

  test("alias resolves to canonical strategy", () => {
    expect(resolvePlatformStrategy("https://twitter.com/u/s/1")).toBe("MIXED");
    expect(resolvePlatformStrategy("https://fb.com/post/1")).toBe("MIXED");
    expect(resolvePlatformStrategy("https://youtu.be/abc")).toBe("video");
    expect(resolvePlatformStrategy("https://bbc.co.uk/news/x")).toBe("TEXT_DOMINANT");
  });

  test("subdomain falls back to parent (substack, blog hosts)", () => {
    expect(resolvePlatformStrategy("https://anyone.substack.com/p/x")).toBe("TEXT_DOMINANT");
    expect(resolvePlatformStrategy("https://my.wordpress.com/2026/05")).toBe("TEXT_DOMINANT");
    expect(resolvePlatformStrategy("https://foo.bar.blogspot.com/post")).toBe("TEXT_DOMINANT");
  });

  test("www. prefix is stripped before lookup", () => {
    expect(resolvePlatformStrategy("https://www.nytimes.com/article")).toBe("TEXT_DOMINANT");
    expect(resolvePlatformStrategy("https://www.x.com/u/s/1")).toBe("MIXED");
  });

  test("unknown host returns null (caller falls through to shape)", () => {
    expect(resolvePlatformStrategy("https://random-blog.example/post")).toBeNull();
    expect(resolvePlatformStrategy("https://obscure-mastodon-instance.org/@u/1")).toBeNull();
  });

  test("malformed url returns null", () => {
    expect(resolvePlatformStrategy("not a url")).toBeNull();
    expect(resolvePlatformStrategy("")).toBeNull();
    expect(resolvePlatformStrategy(null)).toBeNull();
    expect(resolvePlatformStrategy(undefined)).toBeNull();
  });
});

describe("applyStrategy — FIXED (video/audio)", () => {
  test("fixed:video ignores text length", () => {
    expect(applyStrategy("video", { text: "x".repeat(50_000), media: [{ mime: "video/mp4" }] })).toBe("video");
    expect(applyStrategy("video", { text: "", media: [{ mime: "video/mp4" }] })).toBe("video");
  });

  test("fixed:audio with empty body → null (caller 400s)", () => {
    expect(applyStrategy("audio", { text: "", media: [] })).toBeNull();
  });
});

describe("applyStrategy — MEDIA_DOMINANT", () => {
  test("image + long caption stays image (caption is caption)", () => {
    const r = { text: "x".repeat(3000), media: [{ mime: "image/jpeg" }] };
    expect(applyStrategy("MEDIA_DOMINANT", r)).toBe("image");
  });

  test("video file (Reel) → video even on image-first platform", () => {
    const r = { text: "caption", media: [{ mime: "video/mp4" }] };
    expect(applyStrategy("MEDIA_DOMINANT", r)).toBe("video");
  });

  test("mixed media kinds → multi", () => {
    const r = { text: "", media: [{ mime: "image/jpeg" }, { mime: "video/mp4" }] };
    expect(applyStrategy("MEDIA_DOMINANT", r)).toBe("multi");
  });

  test("text-only (no media) falls through to text", () => {
    expect(applyStrategy("MEDIA_DOMINANT", { text: "hi", media: [] })).toBe("text");
  });
});

describe("applyStrategy — MIXED (X / FB / LinkedIn / Reddit)", () => {
  test("text only → text", () => {
    expect(applyStrategy("MIXED", { text: "long status update", media: [] })).toBe("text");
  });

  test("image-only post (no caption) → image", () => {
    expect(applyStrategy("MIXED", { text: "", media: [{ mime: "image/jpeg" }] })).toBe("image");
  });

  test("image + any caption → multi (text might be the work)", () => {
    expect(applyStrategy("MIXED", { text: "look", media: [{ mime: "image/jpeg" }] })).toBe("multi");
    expect(applyStrategy("MIXED", { text: "x".repeat(2000), media: [{ mime: "image/jpeg" }] })).toBe("multi");
  });

  test("video + text → video (attention-dominant)", () => {
    expect(applyStrategy("MIXED", { text: "x".repeat(2000), media: [{ mime: "video/mp4" }] })).toBe("video");
  });

  test("audio + text → audio (attention-dominant)", () => {
    expect(applyStrategy("MIXED", { text: "long commentary", media: [{ mime: "audio/mpeg" }] })).toBe("audio");
  });

  test("multiple media kinds → multi regardless of text", () => {
    const r = { text: "x", media: [{ mime: "image/png" }, { mime: "video/mp4" }] };
    expect(applyStrategy("MIXED", r)).toBe("multi");
  });

  test("empty request → null (caller 400s)", () => {
    expect(applyStrategy("MIXED", { text: "", media: [] })).toBeNull();
  });
});

describe("applyStrategy — TEXT_DOMINANT (article platforms)", () => {
  test("text present → text, regardless of hero image", () => {
    expect(applyStrategy("TEXT_DOMINANT", { text: "article", media: [{ mime: "image/jpeg" }] })).toBe("text");
  });

  test("short text + image → text (article platform; doesn't fall to image)", () => {
    expect(applyStrategy("TEXT_DOMINANT", { text: "tl;dr", media: [{ mime: "image/png" }] })).toBe("text");
  });

  test("media-only article post (image embed, no text) → image", () => {
    expect(applyStrategy("TEXT_DOMINANT", { text: "", media: [{ mime: "image/jpeg" }] })).toBe("image");
  });

  test("media-only with mixed kinds → multi", () => {
    const r = { text: "", media: [{ mime: "image/png" }, { mime: "video/mp4" }] };
    expect(applyStrategy("TEXT_DOMINANT", r)).toBe("multi");
  });
});

describe("resolve — URL platform integration", () => {
  test("YouTube URL with long description → video", () => {
    expect(resolve({
      text: "x".repeat(5000),
      registered_url: "https://youtube.com/watch?v=abc",
    })).toMatchObject({
      contentType: "video",
      resolution: "from_url",
      platformStrategy: "video",
    });
  });

  test("X long-form post with one image → multi (image+text on MIXED)", () => {
    expect(resolve({
      text: "x".repeat(2000),
      media: [{ mime: "image/jpeg" }],
      registered_url: "https://x.com/u/status/1",
    })).toMatchObject({
      contentType: "multi",
      resolution: "from_url",
      platformStrategy: "MIXED",
    });
  });

  test("X video tweet with text → video (attention-dominant)", () => {
    expect(resolve({
      text: "see this",
      media: [{ mime: "video/mp4" }],
      registered_url: "https://twitter.com/u/status/2",
    })).toMatchObject({
      contentType: "video",
      resolution: "from_url",
      platformStrategy: "MIXED",
    });
  });

  test("Instagram post with long caption stays image (MEDIA_DOMINANT)", () => {
    expect(resolve({
      text: "x".repeat(2000),
      media: [{ mime: "image/jpeg" }],
      registered_url: "https://instagram.com/p/abc",
    })).toMatchObject({
      contentType: "image",
      resolution: "from_url",
      platformStrategy: "MEDIA_DOMINANT",
    });
  });

  test("Medium article with hero image → text (TEXT_DOMINANT)", () => {
    expect(resolve({
      text: "essay body",
      media: [{ mime: "image/jpeg" }],
      registered_url: "https://medium.com/@u/post",
    })).toMatchObject({
      contentType: "text",
      resolution: "from_url",
      platformStrategy: "TEXT_DOMINANT",
    });
  });

  test("unknown domain falls through to shape heuristic", () => {
    expect(resolve({
      text: "hello",
      registered_url: "https://unknown-platform.example/post",
    })).toMatchObject({
      contentType: "text",
      resolution: "derived",
      platformStrategy: null,
    });
  });

  test("publisher hint wins over URL lookup", () => {
    expect(resolve({
      content_type_hint: "text",
      text: "x".repeat(500),
      registered_url: "https://youtube.com/watch?v=abc",
    })).toMatchObject({
      contentType: "text",
      resolution: "from_hint",
      hintProvided: "text",
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
