/**
 * @file @tip-protocol/sdk/src/badges.js
 * @description TIP Badge Renderer — generates SVG badges server-side or in-browser.
 *
 * Two distinct badge objects (per spec):
 *   1. TIP™ Powered Mark     — open, free, any implementer
 *   2. AI Trust ID™ Seal     — registry-issued, personal credential
 *
 * Plus:
 *   - Inline ShieldBadge     — compact for feeds, bylines, cards
 *   - HTTP header generator  — ready-to-paste server config
 *   - HTML meta tag generator
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { ORIGIN, ORIGIN_LABELS, HTTP_HEADERS } = require("../../shared/constants");
const { getTier } = require("../../shared/protocol-constants");

// ── Color constants ────────────────────────────────────────────────────────────
const COLORS = {
  green: "#1A8A5C",
  blue: "#2563A8",
  yellow: "#A88B15",
  orange: "#C07318",
  red: "#C53030",
  gold: "#B8942E",
  navy: "#0C1A3A",
  SEAL_GOLD: "#C9A84C",
  SEAL_NAVY: "#0B1629",
};

const SERIF = "Cormorant Garamond, Georgia, serif";

function tierColor(score) {
  if (score >= 800) return COLORS.green;
  if (score >= 600) return COLORS.blue;
  if (score >= 400) return COLORS.yellow;
  if (score >= 200) return COLORS.orange;
  return COLORS.red;
}

class TIPBadgesClient {
  constructor(config) {
    this._config = config;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // AI TRUST ID™ SEAL  (personal credential, registry-issued)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Render the AI Trust ID™ Seal as an SVG string.
   *
   * @param {Object} options
   * @param {number} options.score          0–1000
   * @param {number} [options.size]         px, default 200
   * @param {string} [options.variant]      "gold-dark" | "light" | "dark"
   * @param {boolean} [options.founding]    Show founding star
   * @returns {string} SVG markup
   */
  renderSeal({ score, size = 200, variant = "gold-dark", founding = false }) {
    const S = size;
    const cx = S / 2, cy = S / 2;
    const R = S / 2 - S * 0.028;
    const tR = R - S * 0.062;
    const iR = R - S * 0.135;
    const tc = tierColor(score);

    const isGold = variant === "gold-dark";
    const isLight = variant === "light";
    const uid = `s${score}${size}${variant.slice(0, 2)}`;

    const bgFill = isGold ? `url(#bg${uid})` : isLight ? "#FFFFFF" : "#0A0A0A";
    const ringColor = isGold ? `url(#rg${uid})` : isLight ? "#111111" : "#FFFFFF";
    const arcFill = isGold ? `url(#rg${uid})` : isLight ? "#111111" : "#FFFFFF";
    const dimFill = isGold ? "#4A6080" : isLight ? "#666666" : "#888888";

    // Shield path
    const sW = S * 0.19, sH = S * 0.24;
    const sX = cx - sW / 2, sY = cy - S * 0.30;
    const shield = `M${cx} ${sY} L${sX} ${sY + sH * .28} V${sY + sH * .62} C${sX} ${sY + sH * .9} ${cx - sW * .02} ${sY + sH * .99} ${cx} ${sY + sH} C${cx + sW * .02} ${sY + sH * .99} ${sX + sW} ${sY + sH * .9} ${sX + sW} ${sY + sH * .62} V${sY + sH * .28}Z`;
    const sCY = sY + sH * 0.52;
    const ck = { x1: cx - sW * .26, y1: sCY + sH * .06, x2: cx - sW * .02, y2: sCY + sH * .22, x3: cx + sW * .28, y3: sCY - sH * .10 };
    const xo = sW * 0.22, yo = sH * 0.24;

    const arcText = (text, radius, startDeg, endDeg, fSize, fill, flip = false) => {
      const chars = text.split("");
      const span = endDeg - startDeg;
      const step = span / (chars.length - 1 || 1);
      return chars.map((ch, i) => {
        const deg = flip ? endDeg - i * step : startDeg + i * step;
        const rad = (deg - 90) * Math.PI / 180;
        const x = cx + radius * Math.cos(rad);
        const y = cy + radius * Math.sin(rad);
        return `<text x="${x.toFixed(2)}" y="${y.toFixed(2)}" text-anchor="middle" dominant-baseline="middle" font-size="${fSize}" fill="${fill}" font-family="${SERIF}" font-weight="700" transform="rotate(${flip ? deg + 180 : deg},${x.toFixed(2)},${y.toFixed(2)})">${ch}</text>`;
      }).join("");
    };

    const shieldIcon = score >= 600
      ? `<polyline points="${ck.x1},${ck.y1} ${ck.x2},${ck.y2} ${ck.x3},${ck.y3}" stroke="${tc}" stroke-width="${S * .024}" stroke-linecap="round" stroke-linejoin="round" fill="none"/>`
      : score >= 400
        ? `<text x="${cx}" y="${(sCY + sH * .08).toFixed(2)}" text-anchor="middle" dominant-baseline="middle" fill="${tc}" font-size="${S * .13}" font-family="Georgia" font-weight="bold">!</text>`
        : `<line x1="${cx - xo}" y1="${sCY - yo}" x2="${cx + xo}" y2="${sCY + yo}" stroke="${tc}" stroke-width="${S * .022}" stroke-linecap="round"/>
           <line x1="${cx + xo}" y1="${sCY - yo}" x2="${cx - xo}" y2="${sCY + yo}" stroke="${tc}" stroke-width="${S * .022}" stroke-linecap="round"/>`;

    const foundingStar = founding
      ? `<circle cx="${(cx + iR * .62).toFixed(2)}" cy="${(cy - iR * .62).toFixed(2)}" r="${S * .072}" fill="${bgFill}" stroke="${ringColor}" stroke-width="${S * .009}"/>
         <text x="${(cx + iR * .62).toFixed(2)}" y="${(cy - iR * .62).toFixed(2)}" text-anchor="middle" dominant-baseline="middle" fill="${arcFill}" font-size="${S * .068}" font-family="Georgia">★</text>`
      : "";

    const dots = [-148, 148].map(deg => {
      const rad = (deg - 90) * Math.PI / 180;
      return `<circle cx="${(cx + tR * Math.cos(rad)).toFixed(2)}" cy="${(cy + tR * Math.sin(rad)).toFixed(2)}" r="${S * .007}" fill="${ringColor}" opacity="0.35"/>`;
    }).join("");

    return `<svg width="${S}" height="${S}" viewBox="0 0 ${S} ${S}" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    ${isGold ? `<radialGradient id="rg${uid}" cx="50%" cy="22%" r="78%">
      <stop offset="0%" stop-color="#EDD67A"/>
      <stop offset="52%" stop-color="${COLORS.SEAL_GOLD}"/>
      <stop offset="100%" stop-color="#7A5510"/>
    </radialGradient>
    <radialGradient id="bg${uid}" cx="50%" cy="36%" r="64%">
      <stop offset="0%" stop-color="#16243E"/>
      <stop offset="100%" stop-color="${COLORS.SEAL_NAVY}"/>
    </radialGradient>` : ""}
    <filter id="sh${uid}" x="-18%" y="-18%" width="136%" height="136%">
      <feDropShadow dx="0" dy="${S * .016}" stdDeviation="${S * .022}" flood-color="${isLight ? "rgba(0,0,0,0.10)" : "rgba(0,0,0,0.5)"}"/>
    </filter>
  </defs>
  <circle cx="${cx}" cy="${cy}" r="${R}" fill="${bgFill}" filter="url(#sh${uid})"/>
  <circle cx="${cx}" cy="${cy}" r="${R}" stroke="${ringColor}" stroke-width="${S * .015}" fill="none"/>
  <circle cx="${cx}" cy="${cy}" r="${iR}" stroke="${ringColor}" stroke-width="${S * .004}" fill="none" opacity="0.16"/>
  ${dots}
  ${arcText("AI  TRUST  ID™", tR, -124, -56, S * .067, arcFill, false)}
  ${arcText("AI  TRUST  REGISTRY™", tR, 56, 124, S * .040, arcFill, true)}
  <path d="${shield}" fill="${tc}1C" stroke="${tc}" stroke-width="${S * .014}" stroke-linejoin="round"/>
  ${shieldIcon}
  <text x="${cx}" y="${cy + S * .155}" text-anchor="middle" fill="${tc}" font-size="${S * .118}" font-family="${SERIF}" font-weight="700">${score}</text>
  <text x="${cx}" y="${cy + S * .22}" text-anchor="middle" fill="${dimFill}" font-size="${S * .046}" font-family="${SERIF}" letter-spacing="1">/ 1000</text>
  ${foundingStar}
</svg>`;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // TIP™ POWERED MARK  (open compatibility mark)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Render the TIP™ Powered Mark SVG.
   * Free for any TIP™ implementer — no permission needed.
   *
   * @param {Object} [options]
   * @param {number} [options.size]     default 140
   * @param {string} [options.variant] "light" | "dark"
   * @returns {string} SVG markup
   */
  renderTIPMark({ size = 140, variant = "light" } = {}) {
    const S = size, cx = S / 2, cy = S / 2;
    const R = S / 2 - S * .04, tR = R - S * .064, iR = R - S * .13;
    const isDark = variant === "dark";
    const bg = isDark ? "#0A0A0A" : "#FFFFFF";
    const ring = isDark ? "#FFFFFF" : "#111111";
    const sub = isDark ? "#888888" : "#555555";
    const uid = `tm${size}${variant.slice(0, 1)}`;

    const arcText = (text, radius, startDeg, endDeg, fSize, fill, weight, flip = false) => {
      const chars = text.split("");
      const span = endDeg - startDeg;
      const step = span / (chars.length - 1 || 1);
      return chars.map((ch, i) => {
        const deg = flip ? endDeg - i * step : startDeg + i * step;
        const rad = (deg - 90) * Math.PI / 180;
        const x = cx + radius * Math.cos(rad);
        const y = cy + radius * Math.sin(rad);
        return `<text x="${x.toFixed(2)}" y="${y.toFixed(2)}" text-anchor="middle" dominant-baseline="middle" font-size="${fSize}" fill="${fill}" font-family="${SERIF}" font-weight="${weight}" transform="rotate(${flip ? deg + 180 : deg},${x.toFixed(2)},${y.toFixed(2)})">${ch}</text>`;
      }).join("");
    };

    const dots = [-152, 152].map(deg => {
      const rad = (deg - 90) * Math.PI / 180;
      return `<circle cx="${(cx + tR * Math.cos(rad)).toFixed(2)}" cy="${(cy + tR * Math.sin(rad)).toFixed(2)}" r="${S * .006}" fill="${ring}" opacity="0.3"/>`;
    }).join("");

    return `<svg width="${S}" height="${S}" viewBox="0 0 ${S} ${S}" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <filter id="tsh${uid}" x="-15%" y="-15%" width="130%" height="130%">
      <feDropShadow dx="0" dy="${S * .012}" stdDeviation="${S * .018}" flood-color="${isDark ? "rgba(0,0,0,0.5)" : "rgba(0,0,0,0.08)"}"/>
    </filter>
  </defs>
  <circle cx="${cx}" cy="${cy}" r="${R}" fill="${bg}" filter="url(#tsh${uid})"/>
  <circle cx="${cx}" cy="${cy}" r="${R}" stroke="${ring}" stroke-width="${S * .016}" fill="none"/>
  <circle cx="${cx}" cy="${cy}" r="${iR}" stroke="${ring}" stroke-width="${S * .005}" fill="none" opacity="0.13"/>
  ${dots}
  ${arcText("TRUST  IDENTITY  PROTOCOL", tR, -140, -40, S * .043, ring, "600", false)}
  ${arcText("OPEN  SPEC  ·  APACHE  2.0", tR, 40, 140, S * .038, sub, "500", true)}
  <text x="${cx}" y="${cy - S * .048}" text-anchor="middle" dominant-baseline="middle" fill="${ring}" font-size="${S * .22}" font-family="${SERIF}" font-weight="700" letter-spacing="-1">TIP</text>
  <line x1="${cx - S * .10}" y1="${cy + S * .048}" x2="${cx + S * .10}" y2="${cy + S * .048}" stroke="${ring}" stroke-width="${S * .003}" opacity="0.2"/>
  <text x="${cx}" y="${cy + S * .125}" text-anchor="middle" dominant-baseline="middle" fill="${sub}" font-size="${S * .054}" font-family="${SERIF}" font-weight="600" letter-spacing="3">POWERED</text>
</svg>`;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // INLINE SHIELD BADGE  (feeds, bylines, compact contexts)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Render a compact inline shield badge SVG.
   * @param {Object} options
   * @param {number} options.score
   * @param {number} [options.size]     default 48
   * @param {boolean} [options.founding]
   * @returns {string} SVG markup
   */
  renderShield({ score, size = 48, founding = false }) {
    const color = tierColor(score);
    const borderColor = founding ? COLORS.gold : color;

    const checkmark = score >= 600
      ? `<path d="M16 24L22 30L34 18" stroke="${color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>`
      : score >= 400
        ? `<text x="24" y="29" text-anchor="middle" fill="${color}" font-size="16" font-weight="bold">!</text>`
        : `<line x1="17" y1="19" x2="31" y2="33" stroke="${color}" stroke-width="3" stroke-linecap="round"/>
           <line x1="31" y1="19" x2="17" y2="33" stroke="${color}" stroke-width="3" stroke-linecap="round"/>`;

    return `<svg width="${size}" height="${size}" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z" fill="${color}12" stroke="${borderColor}" stroke-width="${founding ? 2.5 : 2}"/>
  ${checkmark}
</svg>`;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // CONTENT ORIGIN BADGE  (per CTID, shows OH/AA/AG/MX)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Render a content origin badge pill SVG.
   * @param {string} originCode  OH | AA | AG | MX
   * @param {string} [status]    "VERIFIED" | "DISPUTED" | "PENDING"
   * @returns {string} SVG markup
   */
  renderOriginBadge(originCode, status = "VERIFIED") {
    const colors = { OH: "#2563A8", AA: "#7C3AED", AG: "#C07318", MX: "#8895A7" };
    const color = colors[originCode] || "#8895A7";
    const label = ORIGIN_LABELS[originCode] || originCode;
    const w = 160, h = 28;
    const statusColor = status === "DISPUTED" ? "#C53030" : status === "PENDING" ? "#C07318" : color;

    return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect width="${w}" height="${h}" rx="4" fill="${color}12" stroke="${color}" stroke-width="1"/>
  <text x="10" y="14" dominant-baseline="middle" fill="${color}" font-size="11" font-family="JetBrains Mono, monospace" font-weight="700">${originCode}</text>
  <line x1="32" y1="6" x2="32" y2="22" stroke="${color}" stroke-width="1" opacity="0.4"/>
  <text x="40" y="14" dominant-baseline="middle" fill="${color}" font-size="10" font-family="Libre Franklin, sans-serif" font-weight="600">${label}</text>
  <text x="${w - 8}" y="14" text-anchor="end" dominant-baseline="middle" fill="${statusColor}" font-size="9" font-family="Libre Franklin, sans-serif" font-weight="600" letter-spacing="0.5">${status}</text>
</svg>`;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // HTTP HEADER AND META TAG GENERATORS
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Generate ready-to-use HTTP header config for major web servers.
   *
   * @param {Object} options
   * @param {string} options.tipId
   * @param {string} options.ctid
   * @param {string} options.originCode
   * @param {number} options.score
   * @param {string} options.signature
   * @returns {{ nginx, apache, caddy, cloudflare, netlify, headers }}
   */
  generateHTTPConfig({ tipId, ctid, originCode, score, signature }) {
    const originLabel = (ORIGIN_LABELS[originCode] || originCode).toLowerCase().replace(/ /g, "-");
    const tier = getTier(score);

    const headers = {
      [HTTP_HEADERS.AUTHOR]: tipId,
      [HTTP_HEADERS.CONTENT]: ctid,
      [HTTP_HEADERS.ORIGIN]: originLabel,
      [HTTP_HEADERS.TRUST_SCORE]: String(score),
      [HTTP_HEADERS.TIER]: tier.name,
      [HTTP_HEADERS.SIGNATURE]: signature || "[ML-DSA-65 signature]",
    };

    return {
      headers,

      nginx: Object.entries(headers)
        .map(([k, v]) => `    add_header ${k} "${v}";`)
        .join("\n"),

      apache: Object.entries(headers)
        .map(([k, v]) => `Header set ${k} "${v}"`)
        .join("\n"),

      caddy: `header {\n${Object.entries(headers).map(([k, v]) => `    ${k} "${v}"`).join("\n")}\n}`,

      cloudflare: `// Cloudflare Worker\nresponse.headers.set("${HTTP_HEADERS.AUTHOR}", "${tipId}");\nresponse.headers.set("${HTTP_HEADERS.CONTENT}", "${ctid}");\nresponse.headers.set("${HTTP_HEADERS.ORIGIN}", "${originLabel}");\nresponse.headers.set("${HTTP_HEADERS.TRUST_SCORE}", "${score}");`,

      netlify: `# netlify.toml\n[[headers]]\n  for = "/*"\n  [headers.values]\n${Object.entries(headers).map(([k, v]) => `    ${k} = "${v}"`).join("\n")}`,
    };
  }

  /**
   * Generate HTML meta tags for a page.
   * @param {Object} options
   * @returns {string} HTML snippet
   */
  generateMetaTags({ tipId, ctid, originCode, score, status = "VERIFIED" }) {
    const originLabel = (ORIGIN_LABELS[originCode] || originCode).toLowerCase().replace(/ /g, "-");
    return [
      `<meta property="tip:author"  content="${tipId}" />`,
      `<meta property="tip:content" content="${ctid}" />`,
      `<meta property="tip:origin"  content="${originLabel}" />`,
      `<meta property="tip:score"   content="${score}" />`,
      `<meta property="tip:status"  content="${status}" />`,
    ].join("\n");
  }

  /**
   * Generate a full embeddable badge widget (self-contained HTML).
   * Drop this into any webpage to show a live trust badge.
   *
   * @param {Object} options
   * @param {string} options.tipId
   * @param {number} options.score
   * @param {string} [options.variant]  "gold-dark" | "light" | "dark"
   * @param {boolean} [options.founding]
   * @param {number} [options.size]     default 80
   * @returns {string} HTML with embedded SVG
   */
  generateEmbedWidget({ tipId, score, variant = "gold-dark", founding = false, size = 80 }) {
    const svg = this.renderSeal({ score, size, variant, founding });
    const tier = getTier(score);
    return `<!-- TIP™ AI Trust ID Badge — theailab.org/trust-identity-protocol -->
<div class="tip-badge" data-tip-id="${tipId}" style="display:inline-block;text-align:center;font-family:sans-serif;">
  <a href="https://theailab.org/verify/${encodeURIComponent(tipId)}" target="_blank" rel="noopener noreferrer" title="Verify this AI Trust ID™" style="display:block;text-decoration:none;">
    ${svg}
    <div style="margin-top:6px;font-size:11px;color:#4A5568;">${tier.label}</div>
  </a>
</div>
<!-- End TIP™ Badge -->`;
  }
}

module.exports = { TIPBadgesClient };
