/**
 * @file browser-extension/src/content.js
 * @description TIP™ Extension — Content Script
 *
 * Runs on every page. Reads TIP™ meta tags and injects visual trust indicators.
 * For platforms without TIP headers (Twitter/X, Facebook, YouTube), uses
 * profile URL mapping via background service to resolve TIP-IDs.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

(function () {
  if (window.__tipInjected) return;
  window.__tipInjected = true;

  const SERIF = "'Cormorant Garamond', Georgia, serif";

  // ── Color helpers ───────────────────────────────────────────────────────────
  const tierColor = (s) => s>=800?"#1A8A5C":s>=600?"#2563A8":s>=400?"#A88B15":s>=200?"#C07318":"#C53030";
  const tierLabel = (s) => s>=800?"Highly Trusted":s>=600?"Trusted":s>=400?"Review Advised":s>=200?"Low Trust":"Not Trusted";

  // ── Shield SVG (inline, compact) ────────────────────────────────────────────
  function shieldHTML(score, size=20, founding=false) {
    const c  = tierColor(score);
    const bc = founding ? "#B8942E" : c;
    const icon = score>=600
      ? `<path d="M16 24L22 30L34 18" stroke="${c}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>`
      : score>=400
        ? `<text x="24" y="29" text-anchor="middle" fill="${c}" font-size="16" font-weight="bold">!</text>`
        : `<line x1="17" y1="19" x2="31" y2="33" stroke="${c}" stroke-width="3"/><line x1="31" y1="19" x2="17" y2="33" stroke="${c}" stroke-width="3"/>`;
    return `<svg width="${size}" height="${size}" viewBox="0 0 48 48" fill="none" style="display:inline;vertical-align:middle;" xmlns="http://www.w3.org/2000/svg">
      <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z" fill="${c}12" stroke="${bc}" stroke-width="${founding?2.5:2}"/>
      ${icon}
    </svg>`;
  }

  // ── Origin pill ──────────────────────────────────────────────────────────────
  function originPillHTML(code) {
    const colors = {OH:"#2563A8",AA:"#7C3AED",AG:"#C07318",MX:"#8895A7"};
    const labels = {OH:"Original Human",AA:"AI-Assisted",AG:"AI-Generated",MX:"Mixed"};
    const c = colors[code]||"#8895A7";
    const l = labels[code]||code;
    return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border-radius:3px;background:${c}12;border:1px solid ${c}30;font-size:10px;font-family:monospace;font-weight:600;color:${c};letter-spacing:0.5px;vertical-align:middle;">${code} <span style="font-family:sans-serif;font-weight:400;opacity:0.7;">${l}</span></span>`;
  }

  // ── Badge tooltip ─────────────────────────────────────────────────────────────
  function createTooltip(score, tipId, origin) {
    const c     = tierColor(score);
    const label = tierLabel(score);
    const div   = document.createElement("span");
    div.className = "tip-tooltip";
    div.innerHTML = `
      <span style="display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:4px;background:white;border:1px solid #E2E6EE;box-shadow:0 1px 6px rgba(0,0,0,0.10);font-family:sans-serif;cursor:pointer;"
        title="TIP™ Verified | ${label} | ${tipId}">
        ${shieldHTML(score, 18)}
        <span style="font-size:11px;font-weight:600;color:${c};">${score}</span>
        ${origin ? originPillHTML(origin) : ""}
      </span>`;
    return div;
  }

  // ── Read TIP meta tags ────────────────────────────────────────────────────────
  function readMetaTags() {
    return {
      author:    document.querySelector('meta[property="tip:author"]')?.content || null,
      content:   document.querySelector('meta[property="tip:content"]')?.content || null,
      origin:    document.querySelector('meta[property="tip:origin"]')?.content || null,
      score:     parseInt(document.querySelector('meta[property="tip:score"]')?.content || "0", 10),
      status:    document.querySelector('meta[property="tip:status"]')?.content || null,
    };
  }

  // ── Platform-specific injection: Twitter/X ───────────────────────────────────
  function injectTwitter() {
    const observer = new MutationObserver(() => {
      document.querySelectorAll('[data-testid="User-Name"]:not(.tip-processed)').forEach(el => {
        el.classList.add("tip-processed");
        const wrapper = document.createElement("span");
        wrapper.style.cssText = "display:inline-flex;align-items:center;margin-left:4px;";
        wrapper.innerHTML = shieldHTML(0, 16); // placeholder — score unknown without mapping
        wrapper.title = "TIP™: Identity not yet verified on this platform";
        el.appendChild(wrapper);
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── Platform-specific injection: YouTube ────────────────────────────────────
  function injectYouTube() {
    const observer = new MutationObserver(() => {
      document.querySelectorAll("ytd-channel-name:not(.tip-processed), #channel-name:not(.tip-processed)").forEach(el => {
        el.classList.add("tip-processed");
        const wrapper = document.createElement("span");
        wrapper.style.cssText = "display:inline-flex;align-items:center;margin-left:6px;vertical-align:middle;";
        wrapper.innerHTML = shieldHTML(0, 14);
        wrapper.title = "TIP™: Creator verification status unknown";
        el.appendChild(wrapper);
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── Main injection based on current page ─────────────────────────────────────
  function main() {
    const meta = readMetaTags();

    // If page has TIP meta tags — inject author badge and origin pill
    if (meta.author && meta.score > 0) {
      // Find byline elements to annotate
      const selectors = [".byline", ".author-name", "[rel=author]", ".post-author", "article header .name"];
      selectors.forEach(sel => {
        document.querySelectorAll(sel).forEach(el => {
          if (el.querySelector(".tip-badge-injected")) return;
          const badge = createTooltip(meta.score, meta.author, null);
          badge.className += " tip-badge-injected";
          el.appendChild(badge);
        });
      });

      // Show floating page-level badge
      if (!document.getElementById("tip-page-badge")) {
        const badge = document.createElement("div");
        badge.id = "tip-page-badge";
        badge.style.cssText = "position:fixed;bottom:16px;right:16px;z-index:2147483647;background:white;border:1px solid #E2E6EE;border-radius:8px;padding:8px 12px;display:flex;align-items:center;gap:8px;box-shadow:0 2px 16px rgba(0,0,0,0.12);font-family:sans-serif;cursor:pointer;transition:opacity 0.2s;opacity:0.9;";
        badge.innerHTML = `
          ${shieldHTML(meta.score, 24)}
          <div style="display:flex;flex-direction:column;">
            <span style="font-size:11px;font-weight:600;color:#0C1A3A;">${tierLabel(meta.score)}</span>
            <span style="font-size:10px;color:${tierColor(meta.score)};">${meta.score}/1000</span>
          </div>
          ${meta.origin ? originPillHTML(meta.origin.toUpperCase().replace(/-/g,"_").slice(0,2)) : ""}
        `;
        badge.title = `TIP™ Verified Page | ${tierLabel(meta.score)} | ${meta.author}`;
        badge.addEventListener("click", () => {
          window.open(`https://theailab.org/verify/${encodeURIComponent(meta.author)}`, "_blank", "noopener,noreferrer");
        });
        badge.addEventListener("mouseenter", () => badge.style.opacity = "1");
        badge.addEventListener("mouseleave", () => badge.style.opacity = "0.9");
        document.body.appendChild(badge);
      }
    }

    // Platform-specific injections
    const hostname = window.location.hostname;
    if (hostname.includes("twitter.com") || hostname.includes("x.com")) injectTwitter();
    if (hostname.includes("youtube.com")) injectYouTube();
  }

  // Run after DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", main);
  } else {
    main();
  }

  // Re-run on navigation (for SPAs)
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      setTimeout(main, 800);
    }
  }).observe(document, { subtree: true, childList: true });

})();
