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

const https = require("https");
const dns = require("dns");

function mockDns(addresses) {
  return jest.spyOn(dns, "lookup").mockImplementation((host, opts, cb) =>
    process.nextTick(() => cb(null, addresses)));
}

describe("fetchProfileHtml error mapping", () => {
  // A profile site blocking our scraper (Medium 403s repeated fetches) must NOT
  // surface as a 502: a 5xx makes Cloudflare serve its own gateway page WITHOUT
  // the node's CORS header, so the browser can't even read the error. Map these
  // to a client-readable 4xx with a clear code/message instead.
  const { fetchProfileHtml } = bioFetcher;

  beforeEach(() => mockDns([{ address: "93.184.216.34", family: 4 }]));
  afterEach(() => jest.restoreAllMocks());

  function mockStatus(statusCode) {
    jest.spyOn(https, "request").mockImplementation((options, cb) => {
      const res = { statusCode, destroy() {}, on() { return res; } };
      process.nextTick(() => cb(res));
      return { on() { return this; }, end() {}, destroy() {} };
    });
  }

  // Request-level failures: no response ever arrives; the req object itself
  // fires 'timeout' or 'error'. These rewrites (previously 504/502) must map
  // to the same client-readable 4xx as the status-code branch.
  function mockReqEvent(event, arg) {
    jest.spyOn(https, "request").mockImplementation(() => {
      const handlers = {};
      const req = {
        on(name, fn) { handlers[name] = fn; return req; },
        end() { process.nextTick(() => handlers[event] && handlers[event](arg)); },
        destroy() {},
      };
      return req;
    });
  }

  test("timeout -> 4xx profile_fetch_timeout, not 504", async () => {
    mockReqEvent("timeout");
    await expect(fetchProfileHtml("https://medium.com/@x"))
      .rejects.toMatchObject({ status: 422, code: "profile_fetch_timeout" });
  });

  test("socket error -> 4xx profile_fetch_failed, not 502", async () => {
    mockReqEvent("error", new Error("ECONNRESET"));
    await expect(fetchProfileHtml("https://medium.com/@x"))
      .rejects.toMatchObject({ status: 422, code: "profile_fetch_failed" });
  });

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

describe("fetchProfileHtml SSRF guard", () => {
  // The mastodon platform pattern accepts any host, so the fetcher itself must
  // refuse to connect to non-public address space, and must connect only to
  // the address it validated (DNS-rebinding pin).
  const { fetchProfileHtml } = bioFetcher;

  let requestSpy;
  beforeEach(() => {
    requestSpy = jest.spyOn(https, "request").mockImplementation(() => {
      throw new Error("https.request must not be reached");
    });
  });
  afterEach(() => jest.restoreAllMocks());

  test.each([
    "https://10.0.0.5/@x",
    "https://127.0.0.1/@x",
    "https://[::1]/@x",
    "https://169.254.169.254/@x",
  ])("IP-literal host %s rejected before DNS or connect", async (url) => {
    const lookupSpy = jest.spyOn(dns, "lookup");
    await expect(fetchProfileHtml(url))
      .rejects.toMatchObject({ status: 400, code: "profile_url_not_allowed" });
    expect(lookupSpy).not.toHaveBeenCalled();
    expect(requestSpy).not.toHaveBeenCalled();
  });

  test.each([
    [{ address: "10.0.0.5", family: 4 }],
    [{ address: "127.0.0.1", family: 4 }],
    [{ address: "192.168.1.10", family: 4 }],
    [{ address: "169.254.169.254", family: 4 }],
    [{ address: "::1", family: 6 }],
    [{ address: "fd00::1", family: 6 }],
    [{ address: "fe80::1", family: 6 }],
    [{ address: "::ffff:10.0.0.5", family: 6 }],
  ])("host resolving to %o rejected before connect", async (addr) => {
    mockDns([addr]);
    await expect(fetchProfileHtml("https://evil.example/@x"))
      .rejects.toMatchObject({ status: 400, code: "profile_url_not_allowed" });
    expect(requestSpy).not.toHaveBeenCalled();
  });

  test("rebinding host (public + private A records) rejected before connect", async () => {
    mockDns([
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.5", family: 4 },
    ]);
    await expect(fetchProfileHtml("https://rebind.example/@x"))
      .rejects.toMatchObject({ status: 400, code: "profile_url_not_allowed" });
    expect(requestSpy).not.toHaveBeenCalled();
  });

  test("unresolvable host maps to opaque profile_fetch_failed", async () => {
    jest.spyOn(dns, "lookup").mockImplementation((host, opts, cb) =>
      process.nextTick(() => cb(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }))));
    await expect(fetchProfileHtml("https://nxdomain.example/@x"))
      .rejects.toMatchObject({ status: 422, code: "profile_fetch_failed" });
    expect(requestSpy).not.toHaveBeenCalled();
  });

  test("public host connects with the socket pinned to the validated address", async () => {
    mockDns([{ address: "93.184.216.34", family: 4 }]);
    let seenOptions;
    requestSpy.mockImplementation((options, cb) => {
      seenOptions = options;
      const handlers = {};
      const res = {
        statusCode: 200,
        destroy() {},
        on(name, fn) { handlers[name] = fn; return res; },
      };
      process.nextTick(() => {
        cb(res);
        handlers.data(Buffer.from("<html>tip://id/US-aabb</html>"));
        handlers.end();
      });
      return { on() { return this; }, end() {}, destroy() {} };
    });

    const html = await fetchProfileHtml("https://mastodon.social/@alice");
    expect(html).toContain("tip://id/US-aabb");
    expect(typeof seenOptions.lookup).toBe("function");
    const pinned = await new Promise((res, rej) =>
      seenOptions.lookup("mastodon.social", {}, (err, address, family) =>
        (err ? rej(err) : res({ address, family }))));
    expect(pinned).toEqual({ address: "93.184.216.34", family: 4 });
  });
});
