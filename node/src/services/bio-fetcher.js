"use strict";

const https = require("https");
const zlib  = require("zlib");
const { log } = require("../logger");

const FETCH_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2MB cap

const EXTRACTORS = {
  twitter:   u => (u.match(/(?:twitter|x)\.com\/([^/?#]+)/)?.[1] || null),
  x:         u => (u.match(/(?:twitter|x)\.com\/([^/?#]+)/)?.[1] || null),
  instagram: u => (u.match(/instagram\.com\/([^/?#]+)/)?.[1]?.replace(/\/$/, "") || null),
  tiktok:    u => (u.match(/tiktok\.com\/@([^/?#]+)/)?.[1] || null),
  youtube:   u => (u.match(/youtube\.com\/@([^/?#]+)/)?.[1] || u.match(/youtube\.com\/c\/([^/?#]+)/)?.[1] || null),
  github:    u => (u.match(/github\.com\/([^/?#]+)/)?.[1]?.replace(/\/$/, "") || null),
  reddit:    u => (u.match(/reddit\.com\/u(?:ser)?\/([^/?#]+)/)?.[1] || null),
  bluesky:   u => (u.match(/bsky\.app\/profile\/([^/?#]+)/)?.[1] || null),
  threads:   u => (u.match(/threads\.net\/@([^/?#]+)/)?.[1]?.replace(/\/$/, "") || null),
  rooverse:   u => (u.match(/rooverse\.app\/([^/?#]+)/)?.[1]?.replace(/\/$/, "") || null),
  soundcloud: u => (u.match(/soundcloud\.com\/([^/?#]+)/)?.[1] || null),
  mastodon:  u => (u.match(/^https:\/\/([^/]+)\/@([^/?#]+)/)?.[2] || null),
  linkedin:  () => null,
  facebook:  () => null,
  medium:    u => (u.match(/medium\.com\/@([^/?#]+)/)?.[1] || u.match(/^https?:\/\/([^.]+)\.medium\.com/)?.[1] || null),
  substack:  u => (u.match(/^https?:\/\/([^.]+)\.substack\.com/)?.[1] || null),
  devto:     u => (u.match(/dev\.to\/([^/?#]+)/)?.[1] || null),
};

function extractHandle(profileUrl, platform) {
  const extractor = EXTRACTORS[platform.toLowerCase()];
  if (!extractor) return null;
  try {
    return extractor(profileUrl) || null;
  } catch {
    return null;
  }
}

function containsTipId(html, tipId) {
  if (!html || !tipId) return false;
  if (html.includes(tipId)) return true;
  const encoded = encodeURIComponent(tipId);
  return html.includes(encoded);
}

function fetchProfileHtml(profileUrl) {
  return new Promise((resolve, reject) => {
    if (!profileUrl || !profileUrl.startsWith("https://")) {
      return reject({ status: 400, error: "profile_url must start with https://", code: "profile_url_invalid" });
    }
    let url;
    try {
      url = new URL(profileUrl);
    } catch {
      return reject({ status: 400, error: "profile_url is not a valid URL", code: "profile_url_invalid" });
    }

    const options = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: "GET",
      headers: {
        "User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
      },
      timeout: FETCH_TIMEOUT_MS,
    };

    const req = https.request(options, (res) => {
      if (res.statusCode >= 400) {
        res.destroy();
        return reject({ status: 502, error: `Profile URL returned HTTP ${res.statusCode}`, code: "profile_fetch_failed" });
      }
      const encoding = (res.headers["content-encoding"] || "").toLowerCase();
      const stream = encoding === "gzip"    ? res.pipe(zlib.createGunzip())
                   : encoding === "deflate" ? res.pipe(zlib.createInflate())
                   : res;
      const chunks = [];
      let totalBytes = 0;
      stream.on("data", (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          res.destroy();
          return reject({ status: 502, error: "Profile response too large", code: "profile_too_large" });
        }
        chunks.push(chunk);
      });
      stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      stream.on("error", (err) => reject({ status: 502, error: `Profile fetch error: ${err.message}`, code: "profile_fetch_failed" }));
    });

    req.on("timeout", () => {
      req.destroy();
      reject({ status: 504, error: "Profile URL fetch timed out", code: "profile_fetch_timeout" });
    });
    req.on("error", (err) => {
      reject({ status: 502, error: `Profile fetch error: ${err.message}`, code: "profile_fetch_failed" });
    });
    req.end();
  });
}

async function verifyBio({ tipId, profileUrl, platform }) {
  // Dev/test bypass: set TIP_SKIP_BIO_CHECK=true to skip real fetch.
  // NEVER enable in production.
  if (process.env.TIP_SKIP_BIO_CHECK === "true") {
    log.warn("bio-fetcher: TIP_SKIP_BIO_CHECK=true — skipping bio verification for %s (dev only)", profileUrl);
    const handle = extractHandle(profileUrl, platform);
    return { handle };
  }

  let html;
  try {
    html = await fetchProfileHtml(profileUrl);
  } catch (err) {
    log.warn("bio-fetcher: fetch failed for %s: %o", profileUrl, err);
    throw err;
  }

  if (!containsTipId(html, tipId)) {
    throw {
      status: 422,
      error: `TIP-ID not found in bio at ${profileUrl}. Add your TIP-ID to your profile bio and try again.`,
      code: "tip_id_not_in_bio",
    };
  }

  const handle = extractHandle(profileUrl, platform);
  return { handle };
}

module.exports = { extractHandle, containsTipId, fetchProfileHtml, verifyBio };
