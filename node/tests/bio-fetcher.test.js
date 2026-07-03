"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../src");

const bioFetcher = require(SRC + "/services/bio-fetcher");

describe("extractHandle", () => {
  const { extractHandle } = bioFetcher;

  test("twitter/x URL extracts handle", () => {
    expect(extractHandle("https://x.com/alice", "twitter")).toBe("alice");
    expect(extractHandle("https://twitter.com/alice", "twitter")).toBe("alice");
  });

  test("instagram URL extracts handle", () => {
    expect(extractHandle("https://www.instagram.com/myhandle/", "instagram")).toBe("myhandle");
  });

  test("youtube @-handle URL", () => {
    expect(extractHandle("https://www.youtube.com/@mychannel", "youtube")).toBe("mychannel");
  });

  test("github URL extracts handle", () => {
    expect(extractHandle("https://github.com/johndoe", "github")).toBe("johndoe");
  });

  test("tiktok URL extracts handle", () => {
    expect(extractHandle("https://www.tiktok.com/@user123", "tiktok")).toBe("user123");
  });

  test("bluesky URL extracts handle", () => {
    expect(extractHandle("https://bsky.app/profile/alice.bsky.social", "bluesky")).toBe("alice.bsky.social");
  });

  test("threads URL extracts handle", () => {
    expect(extractHandle("https://www.threads.net/@alice", "threads")).toBe("alice");
  });


  test("linkedin returns null (no username)", () => {
    expect(extractHandle("https://www.linkedin.com/in/john-doe-123", "linkedin")).toBeNull();
  });

  test("unknown platform returns null", () => {
    expect(extractHandle("https://example.com/user", "myspace")).toBeNull();
  });

  test("URL with trailing slash is trimmed", () => {
    expect(extractHandle("https://github.com/johndoe/", "github")).toBe("johndoe");
  });
});

describe("containsTipId", () => {
  const { containsTipId } = bioFetcher;

  test("finds TIP-ID in plain HTML text", () => {
    const html = `<html><body><p>My tip id is tip://id/US-aabbccdd11223344 check it!</p></body></html>`;
    expect(containsTipId(html, "tip://id/US-aabbccdd11223344")).toBe(true);
  });

  test("finds URL-encoded TIP-ID", () => {
    const html = `<html><body>tip%3A%2F%2Fid%2FUS-aabbccdd11223344</body></html>`;
    expect(containsTipId(html, "tip://id/US-aabbccdd11223344")).toBe(true);
  });

  test("returns false when TIP-ID not present", () => {
    const html = `<html><body>some content</body></html>`;
    expect(containsTipId(html, "tip://id/US-aabbccdd11223344")).toBe(false);
  });

  test("partial match is not a hit (different suffix)", () => {
    const html = `<html><body>tip://id/US-aabbccdd1122334</body></html>`;
    expect(containsTipId(html, "tip://id/US-aabbccdd11223344")).toBe(false);
  });
});

describe("fetchProfileHtml error mapping", () => {
  // A profile site blocking our scraper (Medium 403s repeated fetches) must NOT
  // surface as a 502: a 5xx makes Cloudflare serve its own gateway page WITHOUT
  // the node's CORS header, so the browser can't even read the error. Map these
  // to a client-readable 4xx with a clear code/message instead.
  const https = require("https");
  const { fetchProfileHtml } = bioFetcher;

  afterEach(() => jest.restoreAllMocks());

  function mockStatus(statusCode) {
    jest.spyOn(https, "request").mockImplementation((options, cb) => {
      const res = { statusCode, destroy() {}, on() { return res; } };
      process.nextTick(() => cb(res));
      return { on() { return this; }, end() {}, destroy() {} };
    });
  }

  test("403 (bot-blocked) -> 4xx profile_fetch_blocked, not 502", async () => {
    mockStatus(403);
    await expect(fetchProfileHtml("https://medium.com/@x"))
      .rejects.toMatchObject({ status: 422, code: "profile_fetch_blocked" });
  });

  test("429 (rate-limited) -> 4xx profile_fetch_blocked, not 502", async () => {
    mockStatus(429);
    await expect(fetchProfileHtml("https://medium.com/@x"))
      .rejects.toMatchObject({ status: 422, code: "profile_fetch_blocked" });
  });

  test("404 (not found) -> readable 4xx, not 502", async () => {
    mockStatus(404);
    await expect(fetchProfileHtml("https://medium.com/@x"))
      .rejects.toMatchObject({ status: 422, code: "profile_fetch_failed" });
  });

  test("no bio-fetch failure maps to a 5xx (would drop CORS at the gateway)", async () => {
    for (const sc of [403, 429, 404, 500, 503]) {
      mockStatus(sc);
      const err = await fetchProfileHtml("https://medium.com/@x").catch((e) => e);
      expect(err.status).toBeLessThan(500);
    }
  });
});
