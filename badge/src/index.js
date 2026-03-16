/**
 * @file @tip-protocol/badge-widget/src/index.js
 * @description TIP™ Badge Widget — drop-in browser script.
 *
 * Usage:
 *   <script src="https://cdn.theailab.org/tip-widget/v2/tip-widget.js"></script>
 *   <tip-badge tip-id="tip://id/US-a3f8c91b2d4e7021"></tip-badge>
 *   <tip-badge ctid="tip://c/OH-7f2a91bc3d5e-a3f8"></tip-badge>
 *
 * Or auto-scan mode (reads TIP-* HTTP headers and meta tags):
 *   <script src="..." data-auto-scan="true" data-node="https://node.theailab.org"></script>
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 * Apache 2.0 — Free for any TIP™ implementer
 */

(function (global) {
  "use strict";

  const DEFAULT_NODE = "http://localhost:4000";
  const SERIF        = "'Cormorant Garamond', Georgia, serif";

  // ── Tier colors ─────────────────────────────────────────────────────────────
  const tierColor = (score) => {
    if (score >= 800) return "#1A8A5C";
    if (score >= 600) return "#2563A8";
    if (score >= 400) return "#A88B15";
    if (score >= 200) return "#C07318";
    return "#C53030";
  };

  const tierLabel = (score) => {
    if (score >= 800) return "Highly Trusted";
    if (score >= 600) return "Trusted";
    if (score >= 400) return "Review Advised";
    if (score >= 200) return "Low Trust";
    return "Not Trusted";
  };

  // ── Inline shield SVG ───────────────────────────────────────────────────────
  function shieldSVG(score, size = 32, founding = false) {
    const color       = tierColor(score);
    const borderColor = founding ? "#B8942E" : color;
    const icon = score >= 600
      ? `<path d="M16 24L22 30L34 18" stroke="${color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>`
      : score >= 400
        ? `<text x="24" y="29" text-anchor="middle" fill="${color}" font-size="16" font-weight="bold">!</text>`
        : `<line x1="17" y1="19" x2="31" y2="33" stroke="${color}" stroke-width="3" stroke-linecap="round"/>
           <line x1="31" y1="19" x2="17" y2="33" stroke="${color}" stroke-width="3" stroke-linecap="round"/>`;
    return `<svg width="${size}" height="${size}" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z" fill="${color}12" stroke="${borderColor}" stroke-width="${founding?2.5:2}"/>
      ${icon}
    </svg>`;
  }

  // ── Origin badge pill ────────────────────────────────────────────────────────
  function originPill(originCode) {
    const originColors = { OH: "#2563A8", AA: "#7C3AED", AG: "#C07318", MX: "#8895A7" };
    const originLabels = { OH: "Original Human", AA: "AI-Assisted", AG: "AI-Generated", MX: "Mixed" };
    const color  = originColors[originCode] || "#8895A7";
    const label  = originLabels[originCode] || originCode;
    return `<span style="display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:3px;background:${color}12;border:1px solid ${color}30;font-size:10px;font-family:monospace;font-weight:600;color:${color};letter-spacing:0.5px;">${originCode} <span style="font-family:sans-serif;font-weight:400;color:${color}99;">${label}</span></span>`;
  }

  // ── Fetch identity data from node ────────────────────────────────────────────
  async function fetchIdentity(tipId, nodeUrl) {
    const url = `${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/score`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Node returned ${res.status}`);
    return res.json();
  }

  async function fetchContent(ctid, nodeUrl) {
    const url = `${nodeUrl}/v1/content/${encodeURIComponent(ctid)}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Node returned ${res.status}`);
    return res.json();
  }

  // ── Custom element: <tip-badge> ─────────────────────────────────────────────
  class TIPBadgeElement extends HTMLElement {
    static get observedAttributes() {
      return ["tip-id", "ctid", "score", "size", "variant", "node", "compact", "show-score"];
    }

    connectedCallback() { this._render(); }
    attributeChangedCallback() { this._render(); }

    async _render() {
      const tipId    = this.getAttribute("tip-id");
      const ctid     = this.getAttribute("ctid");
      const nodeUrl  = this.getAttribute("node") || TIPBadgeWidget.config.nodeUrl;
      const compact  = this.hasAttribute("compact");
      const showScore = this.hasAttribute("show-score") || !compact;
      const size     = parseInt(this.getAttribute("size") || (compact ? "28" : "48"), 10);

      // Show loading state
      this.innerHTML = `<span style="display:inline-flex;align-items:center;gap:6px;opacity:0.5;font-size:12px;font-family:sans-serif;color:#8895A7;">
        <svg width="${size}" height="${size}" viewBox="0 0 48 48" fill="none">
          <circle cx="24" cy="24" r="18" stroke="#E2E6EE" stroke-width="2"/>
        </svg>
        ${!compact ? "Verifying..." : ""}
      </span>`;

      try {
        if (tipId) {
          const data = await fetchIdentity(tipId, nodeUrl);
          const score = data.score || 0;
          const color = tierColor(score);
          const label = tierLabel(score);
          const founding = this.hasAttribute("founding");

          if (compact) {
            this.innerHTML = shieldSVG(score, size, founding);
            this.title = `${label} (${score}/1000) — TIP™ Verified`;
          } else {
            this.innerHTML = `<span style="display:inline-flex;align-items:center;gap:8px;font-family:sans-serif;">
              ${shieldSVG(score, size, founding)}
              ${showScore ? `<span style="display:flex;flex-direction:column;">
                <span style="font-size:13px;font-weight:600;color:#0C1A3A;">${label}</span>
                <span style="font-size:11px;color:${color};font-weight:600;">${score} / 1000</span>
              </span>` : ""}
            </span>`;
          }
          this.style.cursor = "pointer";
          this.title = `TIP™ Verified | ${label} | Score: ${score}/1000`;
          this.addEventListener("click", () => {
            window.open(`https://theailab.org/verify/${encodeURIComponent(tipId)}`, "_blank", "noopener,noreferrer");
          }, { once: true });

        } else if (ctid) {
          const data = await fetchContent(ctid, nodeUrl);
          const originCode = data.origin_code;
          const status     = data.status || "verified";
          this.innerHTML = originPill(originCode);
          this.title = `TIP™ Content Provenance | ${data.origin_label || originCode} | Status: ${status}`;
        }
      } catch (e) {
        const msg = compact ? "" : `<span style="font-size:10px;color:#C53030;">Unverified</span>`;
        this.innerHTML = `<span style="display:inline-flex;align-items:center;gap:4px;">${shieldSVG(0, size)} ${msg}</span>`;
        this.title = `TIP™: Could not verify — ${e.message}`;
      }
    }
  }

  // ── Auto-scan mode: read meta tags and inject badges on matching elements ────
  function autoScan(nodeUrl) {
    // Read TIP meta tags
    const tipAuthor = document.querySelector('meta[property="tip:author"]')?.content;
    const tipScore  = parseInt(document.querySelector('meta[property="tip:score"]')?.content || "0", 10);
    const tipOrigin = document.querySelector('meta[property="tip:origin"]')?.content;
    const tipStatus = document.querySelector('meta[property="tip:status"]')?.content;

    if (tipAuthor && tipScore) {
      // Inject a floating badge in the top-right corner
      const badge = document.createElement("div");
      badge.id    = "tip-auto-badge";
      badge.style.cssText = "position:fixed;top:12px;right:12px;z-index:9999;background:white;border:1px solid #E2E6EE;border-radius:8px;padding:8px 12px;display:flex;align-items:center;gap:8px;box-shadow:0 2px 12px rgba(0,0,0,0.1);font-family:sans-serif;cursor:pointer;";
      badge.title = `TIP™ Verified Author`;

      const score = tipScore;
      const color = tierColor(score);
      badge.innerHTML = `
        ${shieldSVG(score, 28)}
        <div>
          <div style="font-size:11px;font-weight:600;color:#0C1A3A;">${tierLabel(score)}</div>
          <div style="font-size:10px;color:${color};">${score} / 1000</div>
        </div>
      `;
      badge.addEventListener("click", () => {
        window.open(`https://theailab.org/verify/${encodeURIComponent(tipAuthor)}`, "_blank", "noopener,noreferrer");
      });

      document.body.appendChild(badge);
    }

    // Inject origin pills next to byline elements
    if (tipOrigin) {
      const bylineSelectors = [".byline", ".author", "[data-author]", "article header", ".post-meta"];
      bylineSelectors.forEach(sel => {
        document.querySelectorAll(sel).forEach(el => {
          if (!el.querySelector(".tip-origin-pill")) {
            const pill = document.createElement("span");
            pill.className = "tip-origin-pill";
            const originMap = { "original-human": "OH", "ai-assisted": "AA", "ai-generated": "AG", "mixed": "MX" };
            const code = originMap[tipOrigin] || "MX";
            pill.innerHTML = originPill(code);
            el.appendChild(pill);
          }
        });
      });
    }
  }

  // ── Widget public API ────────────────────────────────────────────────────────
  const TIPBadgeWidget = {
    config: {
      nodeUrl: DEFAULT_NODE,
    },

    init({ nodeUrl } = {}) {
      if (nodeUrl) this.config.nodeUrl = nodeUrl;

      // Register custom element if not already registered
      if (!customElements.get("tip-badge")) {
        customElements.define("tip-badge", TIPBadgeElement);
      }

      // Auto-scan if data-auto-scan attribute set on script tag
      const scriptTag = document.currentScript || document.querySelector("script[data-auto-scan]");
      if (scriptTag && scriptTag.getAttribute("data-auto-scan") === "true") {
        const nodeFromAttr = scriptTag.getAttribute("data-node");
        if (nodeFromAttr) this.config.nodeUrl = nodeFromAttr;
        if (document.readyState === "loading") {
          document.addEventListener("DOMContentLoaded", () => autoScan(this.config.nodeUrl));
        } else {
          autoScan(this.config.nodeUrl);
        }
      }

      return this;
    },

    // Programmatic badge rendering (for framework integrations)
    renderShield:  (score, size, founding) => shieldSVG(score, size, founding),
    renderOrigin:  (code) => originPill(code),
    tierColor,
    tierLabel,
  };

  // Auto-init on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => TIPBadgeWidget.init());
  } else {
    TIPBadgeWidget.init();
  }

  // Expose globally
  global.TIPBadgeWidget = TIPBadgeWidget;

})(typeof window !== "undefined" ? window : global);
