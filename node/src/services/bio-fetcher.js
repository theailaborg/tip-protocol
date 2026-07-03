"use strict";

const https = require("https");
const { log } = require("../logger");

const FETCH_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2MB cap

const EXTRACTORS = {
  twitter: u => (u.match(/(?:twitter|x)\.com\/([^/?#]+)/)?.[1] || null),
  x: u => (u.match(/(?:twitter|x)\.com\/([^/?#]+)/)?.[1] || null),
  instagram: u => (u.match(/instagram\.com\/([^/?#]+)/)?.[1]?.replace(/\/$/, "") || null),
  tiktok: u => (u.match(/tiktok\.com\/@([^/?#]+)/)?.[1] || null),
  youtube: u => (u.match(/youtube\.com\/@([^/?#]+)/)?.[1] || u.match(/youtube\.com\/c\/([^/?#]+)/)?.[1] || null),
  github: u => (u.match(/github\.com\/([^/?#]+)/)?.[1]?.replace(/\/$/, "") || null),
  reddit: u => (u.match(/reddit\.com\/u(?:ser)?\/([^/?#]+)/)?.[1] || null),
  bluesky: u => (u.match(/bsky\.app\/profile\/([^/?#]+)/)?.[1] || null),
  threads: u => (u.match(/threads\.net\/@([^/?#]+)/)?.[1]?.replace(/\/$/, "") || null),
  soundcloud: u => (u.match(/soundcloud\.com\/([^/?#]+)/)?.[1] || null),
  mastodon: u => (u.match(/^https:\/\/([^/]+)\/@([^/?#]+)/)?.[2] || null),
  linkedin: () => null,
  facebook: () => null,
  medium: u => (u.match(/medium\.com\/@([^/?#]+)/)?.[1] || u.match(/^https?:\/\/([^.]+)\.medium\.com/)?.[1] || null),
  substack: u => (u.match(/^https?:\/\/([^.]+)\.substack\.com/)?.[1] || null),
  devto: u => (u.match(/dev\.to\/([^/?#]+)/)?.[1] || null),
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
        "User-Agent": "Mozilla/5.0 TIPProtocolBot/1.0 (+https://tip.protocol)",
        "Accept": "text/html,application/xhtml+xml",
      },
      timeout: FETCH_TIMEOUT_MS,
    };

    const req = https.request(options, (res) => {
      if (res.statusCode >= 400) {
        res.destroy();
        // Do NOT surface upstream failures as a 5xx. Cloudflare replaces an
        // origin 5xx with its own gateway page that carries NO CORS header, so
        // the browser can't even read the error (it shows a CORS wall + 502).
        // A blocked/failed profile fetch is a client-actionable verification
        // problem, so return a readable 4xx with a clear code/message. Medium in
        // particular 403s repeated scrapes (rate-limit), which is retryable.
        const blocked = res.statusCode === 403 || res.statusCode === 429;
        return reject(blocked
          ? { status: 422, error: "The platform blocked our automated verification (it may rate-limit repeated checks). Please wait a few minutes and try again.", code: "profile_fetch_blocked" }
          : { status: 422, error: `Profile URL returned HTTP ${res.statusCode}. Make sure the profile is public and the URL is correct.`, code: "profile_fetch_failed" });
      }
      const chunks = [];
      let totalBytes = 0;
      res.on("data", (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          res.destroy();
          return reject({ status: 422, error: "Profile response too large", code: "profile_too_large" });
        }
        chunks.push(chunk);
      });
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      res.on("error", (err) => reject({ status: 422, error: `Profile fetch error: ${err.message}`, code: "profile_fetch_failed" }));
    });

    req.on("timeout", () => {
      req.destroy();
      reject({ status: 422, error: "Verifying your profile timed out. Please try again.", code: "profile_fetch_timeout" });
    });
    req.on("error", (err) => {
      reject({ status: 422, error: `Could not reach the profile URL: ${err.message}`, code: "profile_fetch_failed" });
    });
    req.end();
  });
}

async function verifyBio({ tipId, profileUrl, platform }) {
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
