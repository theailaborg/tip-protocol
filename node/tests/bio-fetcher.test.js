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
