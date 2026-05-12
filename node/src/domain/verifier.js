/**
 * @file @tip-protocol/node/src/domain/verifier.js
 * @description DNS / HTTP proof-of-control primitives used by the node to
 * independently verify that a domain claim is legitimate.
 *
 * Two verification methods (mirrors the WP plugin's local self-verifier so
 * the same TXT record / well-known JSON satisfies both sides):
 *
 *   HTTP — GET https://<domain>/.well-known/tip-protocol.json
 *          Body must be JSON with at least { domain, tip_id }. Both must
 *          match the claim. Public-key cross-check (against the DAG
 *          identity record) is an extra defense — the plugin emits it,
 *          and a mismatch indicates the well-known is stale or forged.
 *
 *   DNS  — TXT _tip-protocol.<domain>
 *          Substring match for `tip-id=<tip_id>` (case-insensitive) across
 *          every TXT record at that hostname. Combined keys allowed
 *          (`v=tip1; tip-id=...; verified=true`).
 *
 *   AUTO — try HTTP first; on any failure fall back to DNS. Reports the
 *          method that actually succeeded.
 *
 * Output shape (always returned, never thrown — caller switches on
 * `verified`):
 *
 *   {
 *     verified:    boolean,
 *     method:      "http" | "dns" | "auto",
 *     verified_at: string (ISO8601) | null,
 *     evidence:    { url, body, txt } — populated fields depend on method
 *     error:       { code, message } | null
 *   }
 *
 * Error codes match the spec table in my-notes/DOMAIN_VERIFICATION.md §4.2
 * so the route layer can surface targeted remediation messages.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const dns = require("dns").promises;
const https = require("https");
const http = require("http");
const {
  DOMAIN_DNS_TXT_PREFIX, DOMAIN_WELL_KNOWN_PATH, DOMAIN_VERIFICATION_METHODS,
} = require("../../../shared/constants");
const { getLogger } = require("../logger");

const log = getLogger("tip.domain-verifier");

// Bounded fetch — HTTPS only by default (publisher must serve TLS).
// HTTP fallback is provided behind a config flag for local dev / testing
// against unencrypted endpoints; production deployments should leave it off.
const DEFAULT_FETCH_TIMEOUT_MS = 5000;
const DEFAULT_MAX_BYTES = 16 * 1024;   // well-known JSON is tiny

// Dev-mode opt-in: same gating as register-domain._devAllowLocalhost. When
// set, the HTTP fetch upgrades to http:// for localhost / 127.0.0.1 hosts,
// and verifyDns short-circuits since loopback doesn't have a public DNS
// record. NEVER takes effect in production.
function _devAllowLocalhost() {
  return process.env.NODE_ENV !== "production"
    && process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS === "1";
}
function _isLocalHostname(domain) {
  return /^(localhost|127\.0\.0\.1)(:\d{1,5})?$/.test(domain);
}

// If TIP_DEV_LOCALHOST_FETCH_HOST is set, rewrite the host portion of a
// loopback `domain` so a containerised node can reach the host's
// well-known server. Two forms supported:
//
//   "host.docker.internal"        — hostname only. The claimed domain's
//                                   port (if any) is preserved.
//                                   Example: claim "localhost:4000" →
//                                   fetch "host.docker.internal:4000".
//
//   "host.docker.internal:8088"   — host AND port. The override port
//                                   replaces the claim's. Useful when the
//                                   well-known server runs on a port the
//                                   claim doesn't include (e.g. claim
//                                   "localhost", real server on :8088).
//
// No-op when the env var is unset.
function _rewriteLocalhostForDocker(domain) {
  const override = process.env.TIP_DEV_LOCALHOST_FETCH_HOST;
  if (!override) return domain;
  const m = /^(localhost|127\.0\.0\.1)(:\d{1,5})?$/.exec(domain);
  if (!m) return domain;
  // Override includes a port → use it verbatim. Otherwise keep the
  // claim's port (or default to no port).
  return /:\d{1,5}$/.test(override) ? override : override + (m[2] || "");
}

function _evidence({ url = null, body = null, txt = null } = {}) {
  return { url, body, txt };
}

function _ok(method, evidence) {
  return {
    verified: true,
    method,
    verified_at: new Date().toISOString(),
    evidence,
    error: null,
  };
}

function _fail(method, code, message, evidence = _evidence()) {
  return {
    verified: false,
    method,
    verified_at: null,
    evidence,
    error: { code, message },
  };
}

/**
 * Fetch a small JSON document over HTTPS (or HTTP, if `allowInsecure`).
 * Returns { status, headers, body } on success. Throws structured Error
 * objects with `code` set so the caller can map to verification error
 * codes. Bounded by timeout + max-bytes so a hostile or hung server
 * can't tie up the verifier.
 */
function _fetchJson(urlString, { timeoutMs = DEFAULT_FETCH_TIMEOUT_MS, maxBytes = DEFAULT_MAX_BYTES, allowInsecure = false } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(urlString); }
    catch (err) {
      const e = new Error(`invalid url: ${urlString}`);
      e.code = "url_invalid";
      return reject(e);
    }

    const client = url.protocol === "https:" ? https : (allowInsecure ? http : null);
    if (!client) {
      const e = new Error(`refusing non-https well-known fetch: ${urlString}`);
      e.code = "scheme_invalid";
      return reject(e);
    }

    const req = client.get(url, { timeout: timeoutMs, headers: { "user-agent": "tip-node-domain-verifier/1.0" } }, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        const e = new Error(`HTTP ${res.statusCode}`);
        e.code = "well_known_unreachable";
        e.status = res.statusCode;
        return reject(e);
      }
      let received = 0;
      const chunks = [];
      res.on("data", (c) => {
        received += c.length;
        if (received > maxBytes) {
          res.destroy();
          const e = new Error(`well-known body exceeds ${maxBytes} bytes`);
          e.code = "well_known_too_large";
          return reject(e);
        }
        chunks.push(c);
      });
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        let body;
        try { body = JSON.parse(raw); }
        catch {
          const e = new Error("well-known body is not valid JSON");
          e.code = "well_known_invalid_json";
          return reject(e);
        }
        resolve({ status: res.statusCode, body });
      });
    });
    req.on("timeout", () => {
      req.destroy();
      const e = new Error(`well-known fetch timed out after ${timeoutMs}ms`);
      e.code = "well_known_unreachable";
      reject(e);
    });
    req.on("error", (err) => {
      // Surface err.code (ECONNREFUSED, ENOTFOUND, etc.) — they're the most
      // diagnostic signal when err.message is empty or generic.
      const detail = err.message || err.code || String(err);
      const e = new Error(`well-known fetch failed (${err.code || "unknown"}): ${detail}`);
      e.code = "well_known_unreachable";
      reject(e);
    });
  });
}

/**
 * HTTP verification — fetch the well-known JSON and verify it carries
 * the expected domain + tip_id. Optional `expectedPublicKey` (from the
 * DAG identity record) adds a third cross-check that catches stale or
 * forged well-known documents.
 */
async function verifyHttp(domain, tipId, deps = {}) {
  // Dev-mode: loopback domains fetch over plain HTTP because the local
  // well-known server is unlikely to terminate TLS. Production always uses
  // HTTPS — see _devAllowLocalhost for the gating contract.
  //
  // When the node runs inside Docker, `localhost` inside the container
  // resolves to the container itself, not the host. TIP_DEV_LOCALHOST_FETCH_HOST
  // (typically `host.docker.internal` on Docker Desktop, or `172.17.0.1` on
  // Linux) overrides the fetch hostname while preserving the claimed
  // `domain` for canonical/body comparison — the signed bytes carry
  // "localhost", and the well-known JSON still echoes "localhost".
  const devLocal = _devAllowLocalhost() && _isLocalHostname(domain);
  const scheme = devLocal ? "http" : "https";
  const fetchHost = devLocal ? _rewriteLocalhostForDocker(domain) : domain;
  const url = `${scheme}://${fetchHost}${DOMAIN_WELL_KNOWN_PATH}`;
  const fetcher = deps.fetchJson || _fetchJson;
  const fetchOpts = devLocal
    ? { ...(deps.fetchOpts || {}), allowInsecure: true }
    : (deps.fetchOpts || {});

  let body;
  try {
    const res = await fetcher(url, fetchOpts);
    body = res.body;
  } catch (err) {
    return _fail(
      DOMAIN_VERIFICATION_METHODS.HTTP,
      err.code || "well_known_unreachable",
      err.message,
      _evidence({ url }),
    );
  }

  const evidence = _evidence({ url, body });

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return _fail(DOMAIN_VERIFICATION_METHODS.HTTP, "well_known_mismatch", "well-known body is not a JSON object", evidence);
  }
  if (typeof body.domain !== "string" || body.domain.toLowerCase() !== domain) {
    return _fail(
      DOMAIN_VERIFICATION_METHODS.HTTP,
      "well_known_mismatch",
      `well-known domain "${body.domain}" does not match requested "${domain}"`,
      evidence,
    );
  }
  if (typeof body.tip_id !== "string" || body.tip_id !== tipId) {
    return _fail(
      DOMAIN_VERIFICATION_METHODS.HTTP,
      "well_known_mismatch",
      `well-known tip_id "${body.tip_id}" does not match requested "${tipId}"`,
      evidence,
    );
  }
  if (deps.expectedPublicKey && typeof body.public_key === "string" && body.public_key !== deps.expectedPublicKey) {
    return _fail(
      DOMAIN_VERIFICATION_METHODS.HTTP,
      "well_known_mismatch",
      "well-known public_key does not match the DAG identity record",
      evidence,
    );
  }

  return _ok(DOMAIN_VERIFICATION_METHODS.HTTP, evidence);
}

/**
 * DNS verification — resolve TXT _tip-protocol.<domain> and look for
 * `tip-id=<tip_id>` (case-insensitive) in any record's joined value.
 * Multi-string records are joined per RFC 7208 §3.3.
 */
async function verifyDns(domain, tipId, deps = {}) {
  // Dev-mode: skip DNS for loopback — `_tip-protocol.localhost` doesn't
  // resolve to anything useful. Return the dns_no_record shape so
  // verifyAuto falls through to the HTTP path on the same call.
  if (_devAllowLocalhost() && _isLocalHostname(domain)) {
    return _fail(
      DOMAIN_VERIFICATION_METHODS.DNS,
      "dns_no_record",
      "DNS skipped for loopback in dev mode — use method=http",
      _evidence({ url: null, txt: [] }),
    );
  }
  const host = `${DOMAIN_DNS_TXT_PREFIX}.${domain}`;
  const resolver = deps.resolveTxt || dns.resolveTxt.bind(dns);

  let records;
  try {
    records = await resolver(host);
  } catch (err) {
    return _fail(
      DOMAIN_VERIFICATION_METHODS.DNS,
      err.code === "ENODATA" || err.code === "ENOTFOUND" ? "dns_no_record" : "dns_no_record",
      `DNS TXT lookup failed for ${host}: ${err.message || err.code}`,
      _evidence({ url: null, txt: [] }),
    );
  }

  // Node's resolveTxt returns string[][] — each outer array is one TXT
  // record, the inner strings are its segments (RFC 7208 joins them).
  const flatRecords = (records || []).map(r => Array.isArray(r) ? r.join("") : String(r));
  const needle = `tip-id=${tipId}`.toLowerCase();
  const matched = flatRecords.find(rec => rec.toLowerCase().includes(needle));

  if (!matched) {
    return _fail(
      DOMAIN_VERIFICATION_METHODS.DNS,
      flatRecords.length === 0 ? "dns_no_record" : "dns_no_match",
      flatRecords.length === 0
        ? `no TXT records found at ${host}`
        : `no TXT record at ${host} contains "${needle}"`,
      _evidence({ url: null, txt: flatRecords }),
    );
  }

  return _ok(DOMAIN_VERIFICATION_METHODS.DNS, _evidence({ url: null, txt: [matched] }));
}

/**
 * Auto — try HTTP first, fall back to DNS. Reports the method that
 * actually succeeded so the caller can persist + audit.
 */
async function verifyAuto(domain, tipId, deps = {}) {
  const httpResult = await verifyHttp(domain, tipId, deps);
  if (httpResult.verified) return { ...httpResult, method: DOMAIN_VERIFICATION_METHODS.HTTP };

  const dnsResult = await verifyDns(domain, tipId, deps);
  if (dnsResult.verified) return { ...dnsResult, method: DOMAIN_VERIFICATION_METHODS.DNS };

  // Both failed — return the more-actionable HTTP failure unless the
  // DNS lookup actually found records (in which case it's the more
  // specific diagnostic).
  const preferDns = dnsResult.evidence && Array.isArray(dnsResult.evidence.txt) && dnsResult.evidence.txt.length > 0;
  return preferDns ? dnsResult : httpResult;
}

/**
 * Dispatch by method. Used by the service layer.
 */
async function verify(method, domain, tipId, deps = {}) {
  switch (method) {
    case DOMAIN_VERIFICATION_METHODS.HTTP: return verifyHttp(domain, tipId, deps);
    case DOMAIN_VERIFICATION_METHODS.DNS: return verifyDns(domain, tipId, deps);
    case DOMAIN_VERIFICATION_METHODS.AUTO: return verifyAuto(domain, tipId, deps);
    default:
      log.warn(`unknown verification method: ${method}`);
      return _fail(method, "method_invalid", `unknown verification method: ${method}`);
  }
}

module.exports = {
  verify,
  verifyHttp,
  verifyDns,
  verifyAuto,
};
