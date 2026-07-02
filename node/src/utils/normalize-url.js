"use strict";

// Tracking/session query params that don't change what post a URL points to.
// Stripped before comparison so a shared link with ?utm_source=... still
// matches the bare registered URL.
const TRACKING_PARAMS = new Set([
  "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
  "fbclid", "gclid", "igshid", "igsh", "img_index", "hl", "ref", "ref_src",
  "s", "t", "si", "spm",
]);

// Domain aliases: different hostnames that address the same post
// (platform rebrands, mobile subdomains, alternate front-ends).
const HOST_ALIASES = new Map([
  ["twitter.com", "x.com"],
  ["mobile.twitter.com", "x.com"],
  ["m.twitter.com", "x.com"],
  ["m.facebook.com", "facebook.com"],
  ["web.facebook.com", "facebook.com"],
  ["old.reddit.com", "reddit.com"],
  ["np.reddit.com", "reddit.com"],
]);

// Instagram serves the same post at both "/p/<code>/" and
// "/<username>/p/<code>/" (the username segment is optional and purely
// cosmetic — the shortcode alone identifies the post). Without stripping
// it, a URL copied with the username prefix would never match one copied
// without it, even though they're the exact same post.
const PATH_CANONICALIZERS = new Map([
  ["instagram.com", (path) => path.replace(/^\/[^/]+\/(p|reel|tv)\//, "/$1/")],
]);

// Normalizes a URL for comparison: lowercases the host, strips "www.",
// applies known domain aliases, strips default ports and trailing slash,
// drops tracking query params (and the "?" entirely if none remain),
// and ignores the hash fragment. Returns null for unparseable input so
// callers can fail closed instead of throwing.
function normalizeUrl(url) {
  if (typeof url !== "string" || !url) return null;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  let host = parsed.hostname.toLowerCase();
  if (host.startsWith("www.")) host = host.slice(4);
  host = HOST_ALIASES.get(host) || host;

  let path = PATH_CANONICALIZERS.get(host)?.(parsed.pathname) ?? parsed.pathname;
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);

  const params = new URLSearchParams(parsed.search);
  for (const key of Array.from(params.keys())) {
    if (TRACKING_PARAMS.has(key.toLowerCase())) params.delete(key);
  }
  const query = params.toString();

  return `${host}${path}${query ? `?${query}` : ""}`;
}

module.exports = { normalizeUrl };
