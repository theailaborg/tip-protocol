/**
 * @file @tip-protocol/sdk/src/content.js
 * @description TIP Content Client — register content with origin declaration,
 *              resolve CTIDs, verify and dispute content origin.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const {
  hashContent,
  perceptualHashText,
  generateCTID,
  mldsaSign,
  shake256,
} = require("../../shared/crypto");

const { ORIGIN, ORIGIN_LABELS } = require("../../shared/constants");

class TIPContentClient {
  constructor(config) {
    this._config = config;
  }

  async _fetch(path, options) {
    const { TIPClient } = require("./index");
    return new TIPClient(this._config)._fetch(path, options);
  }

  /**
   * Hash content locally before registering (no network call).
   * Useful for checking whether content is already registered.
   *
   * @param {string} content
   * @returns {{ contentHash, perceptualHash, ctidPreview }}
   */
  hashLocally(content, originCode = ORIGIN.OH) {
    const contentHash   = hashContent(content);
    const perceptualHash = perceptualHashText(content);
    return {
      contentHash,
      perceptualHash,
      ctidPreview: `tip://c/${originCode}-${contentHash}-????`,
    };
  }

  /**
   * Build the signature payload for content registration.
   * Must be signed by the author's ML-DSA-65 private key.
   *
   * @param {string} contentHash  14-char hash from hashContent()
   * @param {string} originCode   OH|AA|AG|MX
   * @returns {string} payload to sign
   */
  buildSignaturePayload(contentHash, originCode) {
    return contentHash + originCode;
  }

  /**
   * Sign content registration locally.
   * The signature covers (contentHash + originCode) — making the origin
   * declaration cryptographically inseparable from the content.
   *
   * @param {string} content      Raw content text
   * @param {string} originCode   OH|AA|AG|MX
   * @param {string} privateKey   Author's ML-DSA-65 private key (hex)
   * @returns {{ contentHash, signature, ctidPreview }}
   */
  signContent(content, originCode, privateKey) {
    if (!ORIGIN[originCode]) {
      throw new Error(`Invalid originCode "${originCode}". Must be one of: ${Object.keys(ORIGIN).join(", ")}`);
    }
    if (!privateKey) throw new Error("privateKey is required to sign content");

    const contentHash = hashContent(content);
    const payload     = this.buildSignaturePayload(contentHash, originCode);
    const signature   = mldsaSign(payload, privateKey);

    return {
      contentHash,
      signature,
      originCode,
      ctidPreview: `tip://c/${originCode}-${contentHash}-????`,
    };
  }

  /**
   * Register content on the TIP node with a mandatory origin declaration.
   *
   * Flow:
   *   1. Hash the content locally
   *   2. Sign (contentHash + originCode) with your ML-DSA-65 private key
   *   3. Send to node — node runs calibrated AI pre-scan (v2 FIX-03)
   *   4. Node returns CTID, HTTP headers ready to deploy, and meta tags
   *
   * @param {Object} options
   * @param {string} options.authorTipId    Your TIP-ID
   * @param {string} options.privateKey     Your ML-DSA-65 private key (hex)
   * @param {string} options.originCode     OH | AA | AG | MX
   * @param {string} [options.content]      Content text (required unless contentHash provided)
   * @param {string} [options.contentHash]  Pre-computed hash (use if content is binary)
   * @returns {Promise<Object>}  CTID record with HTTP headers and meta tags
   */
  async register({ authorTipId, privateKey, originCode, content, contentHash: precomputedHash }) {
    if (!authorTipId)  throw new Error("authorTipId is required");
    if (!originCode)   throw new Error("originCode is required (OH | AA | AG | MX)");
    if (!ORIGIN[originCode]) throw new Error(`Invalid originCode. Must be one of: ${Object.keys(ORIGIN).join(", ")}`);
    if (!content && !precomputedHash) throw new Error("content or contentHash is required");

    const contentHash = precomputedHash || hashContent(content);
    const signature   = privateKey
      ? mldsaSign(this.buildSignaturePayload(contentHash, originCode), privateKey)
      : "unsigned";

    const res = await this._fetch("/v1/content/register", {
      method: "POST",
      body: {
        author_tip_id: authorTipId,
        origin_code:   originCode,
        content:       content || null,
        content_hash:  contentHash,
        signature,
      },
    });

    return {
      ctid:           res.ctid,
      originCode:     res.origin_code,
      originLabel:    res.origin_label,
      contentHash:    res.content_hash,
      txId:           res.tx_id,
      status:         res.status,
      preScanFlagged: res.prescan_flagged,
      preScanNote:    res.prescan_note,
      httpHeaders:    res.http_headers,
      metaTags:       res.meta_tags,
      registeredAt:   res.registered_at,
      // Helper: Nginx config snippet
      nginxSnippet:   this._buildNginxSnippet(res.http_headers),
      // Helper: HTML meta tags snippet
      htmlSnippet:    this._buildHtmlSnippet(res.meta_tags),
    };
  }

  /**
   * Resolve a CTID to its full provenance record.
   * @param {string} ctid  e.g. "tip://c/OH-7f2a91bc3d5e-a3f8"
   * @returns {Promise<Object>}
   */
  async resolve(ctid) {
    return this._fetch(`/v1/content/${encodeURIComponent(ctid)}`);
  }

  /**
   * Submit a community verification of a content record.
   * Verifier must have trust score >= 700.
   *
   * @param {string} ctid
   * @param {string} verifierTipId
   * @param {string} [verdict]  Default: "ORIGIN_CONFIRMED"
   * @returns {Promise<Object>}
   */
  async verify(ctid, verifierTipId, verdict = "ORIGIN_CONFIRMED") {
    return this._fetch(`/v1/content/${encodeURIComponent(ctid)}/verify`, {
      method: "POST",
      body: { verifier_tip_id: verifierTipId, verdict },
    });
  }

  /**
   * File an origin dispute against a content record.
   * @param {string} ctid
   * @param {string} disputerTipId
   * @param {string} reason
   * @param {string} [evidenceHash]
   * @returns {Promise<Object>}
   */
  async dispute(ctid, disputerTipId, reason, evidenceHash) {
    return this._fetch(`/v1/content/${encodeURIComponent(ctid)}/dispute`, {
      method: "POST",
      body: { disputer_tip_id: disputerTipId, reason, evidence_hash: evidenceHash },
    });
  }

  /**
   * Generate Nginx HTTP header config snippet from header map.
   * @param {Object} headers
   * @returns {string}
   */
  _buildNginxSnippet(headers) {
    if (!headers) return "";
    return Object.entries(headers)
      .map(([k, v]) => `add_header ${k} "${v}";`)
      .join("\n");
  }

  /**
   * Generate HTML meta tag snippet.
   * @param {Object} metaTags
   * @returns {string}
   */
  _buildHtmlSnippet(metaTags) {
    if (!metaTags) return "";
    return Object.entries(metaTags)
      .map(([k, v]) => `<meta property="${k}" content="${v}" />`)
      .join("\n");
  }
}

module.exports = { TIPContentClient };
