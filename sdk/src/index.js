/**
 * @file @tip-protocol/sdk/src/index.js
 * @description TIP Protocol SDK — Main Entry
 *
 * Usage:
 *   const { TIPClient } = require('@tip-protocol/sdk');
 *
 *   const tip = new TIPClient({ nodeUrl: 'http://localhost:4000' });
 *
 *   // Register an identity
 *   const identity = await tip.identity.register({ region: 'US', vpId: '...' });
 *
 *   // Register content
 *   const content = await tip.content.register({
 *     authorTipId: identity.tip_id,
 *     privateKey: identity.private_key,
 *     originCode: 'OH',
 *     content: 'My article text...',
 *   });
 *
 *   // Query trust score
 *   const score = await tip.trust.getScore(identity.tip_id);
 *
 *   // Render a badge
 *   const svg = tip.badges.renderSeal({ score: score.score, variant: 'gold-dark' });
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { TIPIdentityClient } = require("./identity");
const { TIPContentClient }  = require("./content");
const { TIPTrustClient }    = require("./trust");
const { TIPBadgesClient }   = require("./badges");
const { PROTOCOL }          = require("../../shared/constants");

class TIPClient {
  /**
   * @param {Object} options
   * @param {string} options.nodeUrl      Base URL of the TIP node e.g. 'http://localhost:4000'
   * @param {string} [options.apiKey]     Optional API key for authenticated endpoints
   * @param {number} [options.timeout]    Request timeout in ms (default: 10000)
   * @param {boolean} [options.debug]     Enable debug logging
   */
  constructor(options = {}) {
    if (!options.nodeUrl) throw new Error("nodeUrl is required");

    this.config = {
      nodeUrl:  options.nodeUrl.replace(/\/$/, ""),
      apiKey:   options.apiKey   || null,
      timeout:  options.timeout  || 10_000,
      debug:    options.debug    || false,
    };

    // Sub-clients
    this.identity = new TIPIdentityClient(this.config);
    this.content  = new TIPContentClient(this.config);
    this.trust    = new TIPTrustClient(this.config);
    this.badges   = new TIPBadgesClient(this.config);

    if (this.config.debug) {
      console.log(`[TIPClient] Initialised. Node: ${this.config.nodeUrl} | Protocol: ${PROTOCOL.version}`);
    }
  }

  /** Verify the node is reachable and responding. */
  async ping() {
    return this._fetch("/health");
  }

  /** Get full node info. */
  async nodeInfo() {
    return this._fetch("/v1/node/info");
  }

  /** Get list of connected peers. */
  async peers() {
    return this._fetch("/v1/node/peers");
  }

  /** Low-level fetch with auth, timeout, and error handling. */
  async _fetch(path, options = {}) {
    const url = this.config.nodeUrl + path;
    const headers = {
      "Content-Type": "application/json",
      "Accept":       "application/json",
      ...(this.config.apiKey ? { "X-TIP-API-Key": this.config.apiKey } : {}),
      ...(options.headers || {}),
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const res = await fetch(url, {
        method:  options.method || "GET",
        headers,
        body:    options.body ? JSON.stringify(options.body) : undefined,
        signal:  controller.signal,
      });

      clearTimeout(timer);

      const data = await res.json();
      if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { status: res.status, data });
      return data;

    } catch (err) {
      clearTimeout(timer);
      if (err.name === "AbortError") throw new Error(`TIP node request timed out (${this.config.timeout}ms): ${url}`);
      throw err;
    }
  }
}

// ── Named exports for tree-shaking ────────────────────────────────────────────
module.exports = {
  TIPClient,
  TIPIdentityClient,
  TIPContentClient,
  TIPTrustClient,
  TIPBadgesClient,
};
