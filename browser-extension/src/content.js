/**
 * @file src/content.js
 * @description TIP Extension - Content Script
 *
 * Runs on every page. Two responsibilities:
 *
 * VIEWER mode: Reads TIP meta tags and HTTP headers (via background cache).
 *   Injects trust badges into YouTube channel names, Twitter/X author names,
 *   article bylines, and any page with TIP meta tags.
 *   Scans page text for CTID URIs and makes them clickable.
 *
 * CREATOR mode: Detects upload pages (YouTube Studio, Instagram, TikTok, etc.)
 *   Injects a "Register with TIP" button into the upload form.
 *   Auto-reads title and description from the form.
 *   Sends content to the popup for registration.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * Author: Dinesh Mendhe <tip@theailab.org>
 * License: TIPCL-1.0
 */

"use strict";

import { TIP_PLATFORMS, TIP_TYPES, buildContentString, ORIGIN_COLORS, ORIGIN_LABELS, ORIGIN_HINTS } from "./tip-types.js";

(function () {
  if (window.__tipContentInjected) return;
  window.__tipContentInjected = true;

  // ── Announce extension presence (for VP app detection) ────────────────────
  document.documentElement.dataset.tipExtension = "ready";

  // ── VP app connection via window.postMessage (cross-browser) ──────────────
  window.addEventListener("message", (e) => {
    if (e.data?.type === "TIP_CONNECT" && e.data?.source === "tip-vp-portal") {
      chrome.runtime.sendMessage({
        type:    "TIP_CONNECT",
        tip_id:  e.data.tip_id,
        tip_key: e.data.tip_key,
      }, (res) => {
        window.postMessage({
          type: "TIP_CONNECT_ACK",
          ok:   res?.ok,
          error: res?.error,
        }, "*");
      });
    }
  });

  // ── Design tokens ───────────────────────────────────────────────────────────
  const C = {
    navy: "#0C1A3A", gold: "#B8942E", goldBg: "#B8942E15",
    green: "#1A8A5C", blue: "#2563A8", yellow: "#A88B15",
    orange: "#C07318", red: "#C53030", gray: "#8895A7",
    border: "#E2E6EE", bg: "#FFFFFF",
  };

  function tierColor(s) {
    return s>=800?C.green:s>=600?C.blue:s>=400?C.yellow:s>=200?C.orange:C.red;
  }
  function tierLabel(s) {
    return s>=800?"Highly Trusted":s>=600?"Trusted":s>=400?"Review Advised":s>=200?"Low Trust":"Not Trusted";
  }

  const ORIGIN_COLORS = { OH: C.blue, AA: "#7C3AED", AG: C.orange, MX: C.gray };
  const ORIGIN_LABELS = {
    OH: "Original Human", AA: "AI-Assisted",
    AG: "AI-Generated",   MX: "Mixed",
  };

  // ── Platform detection ──────────────────────────────────────────────────────
  const HOST = location.hostname;
  const PLATFORM =
    HOST.includes("youtube.com")    ? "youtube" :
    HOST.includes("instagram.com")  ? "instagram" :
    HOST.includes("tiktok.com")     ? "tiktok" :
    HOST.includes("twitter.com") ||
    HOST.includes("x.com")          ? "twitter" :
    HOST.includes("facebook.com")   ? "facebook" :
    HOST.includes("linkedin.com")   ? "linkedin" :
    HOST.includes("substack.com")   ? "substack" :
    HOST.includes("medium.com")     ? "medium" : null;

  const IS_UPLOAD =
    /studio\.youtube\.com|youtube\.com\/upload/.test(location.href) ||
    /instagram\.com\/(create|p\/|reels\/|stories\/)/.test(location.href) ||
    /tiktok\.com\/upload/.test(location.href) ||
    /twitter\.com\/compose|x\.com\/compose|x\.com\/home|x\.com\/intent\/post/.test(location.href) ||
    /facebook\.com\/(video\/upload|photo|stories\/)/.test(location.href) ||
    /linkedin\.com\/post\/new|linkedin\.com\/feed\//.test(location.href) ||
    /pinterest\.com\/(pin-creation|collage-creation)/.test(location.href) ||
    /substack\.com\/publish|substack\.com\/.*\/write/.test(location.href) ||
    /medium\.com\/new-story|medium\.com\/@.*\/new/.test(location.href);

  // ── Shield badge HTML ────────────────────────────────────────────────────────
  function shieldSVG(score, size = 20, founding = false) {
    const c  = tierColor(score);
    const bc = founding ? C.gold : c;
    const icon = score >= 600
      ? `<path d="M16 24L22 30L34 18" stroke="${c}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>`
      : score >= 400
        ? `<text x="24" y="29" text-anchor="middle" fill="${c}" font-size="16" font-weight="bold">!</text>`
        : `<line x1="17" y1="19" x2="31" y2="33" stroke="${c}" stroke-width="3" stroke-linecap="round"/>
           <line x1="31" y1="19" x2="17" y2="33" stroke="${c}" stroke-width="3" stroke-linecap="round"/>`;
    return `<svg width="${size}" height="${size}" viewBox="0 0 48 48" fill="none"
      style="display:inline;vertical-align:middle;flex-shrink:0;" xmlns="http://www.w3.org/2000/svg">
      <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z"
        fill="${c}12" stroke="${bc}" stroke-width="${founding ? 2.5 : 2}"/>
      ${icon}
    </svg>`;
  }

  function originPill(code) {
    const c = ORIGIN_COLORS[code] || C.gray;
    const l = ORIGIN_LABELS[code] || code;
    return `<span style="display:inline-flex;align-items:center;gap:3px;padding:2px 6px;
      border-radius:3px;background:${c}15;border:1px solid ${c}30;
      font-size:10px;font-family:monospace;font-weight:700;color:${c};">${code}
      <span style="font-family:sans-serif;font-weight:400;opacity:0.75;">${l}</span></span>`;
  }

  // ── Meta tag reader ──────────────────────────────────────────────────────────
  function readMetaTags() {
    return {
      author: document.querySelector('meta[property="tip:author"]')?.content || null,
      content: document.querySelector('meta[property="tip:content"]')?.content || null,
      origin: document.querySelector('meta[property="tip:origin"]')?.content || null,
      score:  parseInt(document.querySelector('meta[property="tip:score"]')?.content || "0", 10),
      status: document.querySelector('meta[property="tip:status"]')?.content || null,
    };
  }

  // ── Inline badge tooltip ─────────────────────────────────────────────────────
  function inlineBadge(score, tipId, origin, founding = false) {
    const c     = tierColor(score);
    const label = tierLabel(score);
    const el    = document.createElement("span");
    el.className = "tip-inline-badge";
    el.style.cssText = "display:inline-flex;align-items:center;gap:4px;margin:0 4px;cursor:pointer;vertical-align:middle;";
    el.innerHTML = `
      ${shieldSVG(score, 18, founding)}
      <span style="font-size:11px;font-weight:600;color:${c};font-family:sans-serif;">${score}</span>
      ${origin ? originPill(origin.toUpperCase().slice(0, 2)) : ""}
    `;
    el.title = `TIP Verified | ${label} (${score}/1000) | ${tipId}`;
    el.addEventListener("click", (e) => {
      e.preventDefault(); e.stopPropagation();
      window.open(`https://vp.theailab.org/verify-record/${encodeURIComponent(tipId)}`, "_blank", "noopener");
    });
    return el;
  }

  // ── Floating page badge ──────────────────────────────────────────────────────
  function showPageBadge(score, tipId, origin, founding = false) {
    if (document.getElementById("tip-page-badge")) return;
    const c     = tierColor(score);
    const label = tierLabel(score);
    const el    = document.createElement("div");
    el.id = "tip-page-badge";
    el.style.cssText = `
      position:fixed;bottom:20px;right:20px;z-index:2147483647;
      background:${C.bg};border:1px solid ${C.border};
      border-radius:10px;padding:10px 14px;
      display:flex;align-items:center;gap:10px;
      box-shadow:0 4px 20px rgba(0,0,0,0.12);
      font-family:'Libre Franklin','Helvetica Neue',sans-serif;
      cursor:pointer;transition:all 0.2s;opacity:0.95;
      border-left:3px solid ${c};
    `;
    el.innerHTML = `
      ${shieldSVG(score, 28, founding)}
      <div style="display:flex;flex-direction:column;gap:2px;">
        <span style="font-size:12px;font-weight:700;color:${C.navy};">${label}</span>
        <span style="font-size:10px;color:${c};">Score: ${score}/1000</span>
        ${origin ? `<span style="font-size:9px;margin-top:2px;">${originPill(origin.toUpperCase().slice(0,2))}</span>` : ""}
      </div>
      <button style="background:none;border:none;cursor:pointer;color:${C.gray};font-size:14px;padding:2px;margin-left:4px;"
        id="tip-badge-close" title="Dismiss">×</button>
    `;
    el.addEventListener("click", (e) => {
      if (e.target.id === "tip-badge-close") { el.remove(); return; }
      window.open(`https://vp.theailab.org/verify-record/${encodeURIComponent(tipId)}`, "_blank", "noopener");
    });
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = "0.7"; }, 5000);
  }

  // ── CTID link scanner ────────────────────────────────────────────────────────
  function scanForCTIDs() {
    const pattern = /tip:\/\/c\/[A-Z]{2}-[0-9a-f]{14}-[0-9a-f]{4}/g;
    const walker  = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const toWrap  = [];
    let node;
    while ((node = walker.nextNode())) {
      if (node.parentElement?.closest(".tip-inline-badge, #tip-page-badge, #tip-creator-panel")) continue;
      if (pattern.test(node.textContent)) {
        toWrap.push(node);
        pattern.lastIndex = 0;
      }
    }
    toWrap.forEach(node => {
      const frag = document.createDocumentFragment();
      const parts = node.textContent.split(/(tip:\/\/c\/[A-Z]{2}-[0-9a-f]{14}-[0-9a-f]{4})/g);
      parts.forEach(part => {
        if (/^tip:\/\/c\//.test(part)) {
          const a = document.createElement("a");
          a.href = `https://vp.theailab.org/verify-record/${encodeURIComponent(part)}`;
          a.target = "_blank"; a.rel = "noopener";
          a.style.cssText = `color:${C.blue};font-family:monospace;font-size:0.9em;text-decoration:underline dotted;`;
          a.title = `Verify on TIP Protocol DAG: ${part}`;
          a.textContent = part;
          frag.appendChild(a);
        } else {
          frag.appendChild(document.createTextNode(part));
        }
      });
      node.parentNode.replaceChild(frag, node);
    });
  }

  // ── YouTube: inject badge next to channel names ──────────────────────────────
  function injectYouTube() {
    const observer = new MutationObserver(() => {
      document.querySelectorAll(
        "ytd-channel-name:not(.tip-done), #channel-name:not(.tip-done), .ytd-author-text:not(.tip-done)"
      ).forEach(el => {
        el.classList.add("tip-done");
        const wrap = document.createElement("span");
        wrap.style.cssText = "display:inline-flex;align-items:center;margin-left:5px;";
        wrap.innerHTML = shieldSVG(0, 14);
        wrap.title = "TIP: Verification status unknown for this creator";
        wrap.style.opacity = "0.4";
        el.appendChild(wrap);
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── Twitter/X: inject badge next to usernames ────────────────────────────────
  function injectTwitter() {
    const observer = new MutationObserver(() => {
      document.querySelectorAll('[data-testid="User-Name"]:not(.tip-done)').forEach(el => {
        el.classList.add("tip-done");
        const wrap = document.createElement("span");
        wrap.style.cssText = "display:inline-flex;align-items:center;margin-left:4px;";
        wrap.innerHTML = shieldSVG(0, 15);
        wrap.title = "TIP: Creator verification status unknown";
        wrap.style.opacity = "0.35";
        el.appendChild(wrap);
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── Creator panel: injected on upload pages ──────────────────────────────────
  function injectCreatorPanel(platformName) {
    if (document.getElementById("tip-creator-panel")) return;

    const PLATFORM_SELECTORS = {
      YouTube:   { title: "#title-textarea, #title input", desc: "#description-textarea, #description" },
      Instagram: { title: null, desc: "textarea[aria-label], .caption-input textarea" },
      TikTok:    { title: null, desc: "[data-e2e='caption-input'] textarea, .caption-input" },
      X:         { title: null, desc: ".public-DraftEditor-content, [data-testid='tweetTextarea_0']" },
      Facebook:  { title: null, desc: "[data-testid='status-attachment-mentions-input']" },
      LinkedIn:  { title: null, desc: ".ql-editor, [data-placeholder]" },
      Substack:  { title: "h1[data-placeholder]", desc: ".tiptap, .ProseMirror" },
      Medium:    { title: "h1.graf--title", desc: ".graf--p:last-of-type" },
    };

    const selectors = PLATFORM_SELECTORS[platformName] || {};

    const panel = document.createElement("div");
    panel.id = "tip-creator-panel";
    panel.style.cssText = `
      position:fixed;bottom:24px;right:24px;z-index:2147483647;
      width:300px;background:${C.bg};border:1px solid ${C.border};
      border-radius:12px;box-shadow:0 8px 32px rgba(12,26,58,0.15);
      font-family:'Libre Franklin','Helvetica Neue',sans-serif;
      overflow:hidden;transition:all 0.3s;
    `;
    panel.innerHTML = `
      <div id="tip-panel-header" style="
        background:${C.navy};padding:10px 14px;
        display:flex;align-items:center;justify-content:space-between;
        cursor:move;user-select:none;
      ">
        <div style="display:flex;align-items:center;gap:8px;">
          <svg width="20" height="20" viewBox="0 0 48 48" fill="none">
            <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z"
              fill="#B8942E20" stroke="#B8942E" stroke-width="2"/>
            <path d="M16 24L22 30L34 18" stroke="#B8942E" stroke-width="3" stroke-linecap="round"/>
          </svg>
          <div>
            <div style="font-size:11px;font-weight:700;color:#FFFFFF;letter-spacing:1px;">TIP PROTOCOL</div>
            <div style="font-size:9px;color:#B8942E;letter-spacing:1.5px;">REGISTER CONTENT</div>
          </div>
        </div>
        <div style="display:flex;gap:6px;align-items:center;">
          <span style="font-size:9px;color:#94A3B8;background:#FFFFFF10;padding:2px 7px;border-radius:10px;">${platformName}</span>
          <button id="tip-panel-minimize" style="background:none;border:none;color:#94A3B8;font-size:16px;cursor:pointer;padding:2px;line-height:1;">−</button>
          <button id="tip-panel-close" style="background:none;border:none;color:#94A3B8;font-size:16px;cursor:pointer;padding:2px;line-height:1;">×</button>
        </div>
      </div>

      <div id="tip-panel-body" style="padding:14px;">

        <!-- Help tip -->
        <div id="tip-help-banner" style="
          background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;
          padding:9px 11px;margin-bottom:12px;font-size:11px;
          color:#1E40AF;line-height:1.5;
        ">
          <strong>💡 What is this?</strong><br>
          Declare how your content was created - human, AI-assisted, AI-generated, or mixed. Your declaration is signed with your verified identity and recorded permanently.
          <a href="https://theailab.org/trust-identity-protocol" target="_blank"
            style="color:#B8942E;display:block;margin-top:4px;">Learn more →</a>
        </div>

        <!-- Status bar -->
        <div id="tip-status-bar" style="display:none;padding:8px 10px;border-radius:6px;
          margin-bottom:10px;font-size:11px;font-weight:500;"></div>

        <!-- Setup prompt (shown if no TIP-ID) -->
        <div id="tip-setup-prompt" style="display:none;text-align:center;padding:10px 0;">
          <div style="font-size:13px;font-weight:600;color:${C.navy};margin-bottom:6px;">Set up your TIP-ID first</div>
          <div style="font-size:11px;color:${C.gray};margin-bottom:12px;line-height:1.5;">
            You need a verified TIP-ID to register content.<br>
            Click below to set up your identity.
          </div>
          <button id="tip-goto-settings" style="
            padding:8px 16px;background:${C.navy};color:#B8942E;
            border:none;border-radius:6px;font-size:12px;font-weight:600;
            cursor:pointer;font-family:inherit;
          ">Open Settings →</button>
        </div>

        <!-- Main registration form -->
        <div id="tip-reg-form">

          <!-- TIP-ID display -->
          <div id="tip-id-display" style="
            display:flex;align-items:center;gap:8px;
            padding:8px 10px;background:#F8F9FB;border-radius:6px;
            border:1px solid ${C.border};margin-bottom:12px;
          ">
            <svg width="14" height="14" viewBox="0 0 48 48" fill="none">
              <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z"
                fill="#1A8A5C15" stroke="#1A8A5C" stroke-width="2"/>
              <path d="M16 24L22 30L34 18" stroke="#1A8A5C" stroke-width="3" stroke-linecap="round"/>
            </svg>
            <div>
              <div style="font-size:9px;color:${C.gray};letter-spacing:1px;font-weight:600;">YOUR TIP-ID</div>
              <div id="tip-id-value" style="font-size:10px;font-family:monospace;color:${C.navy};
                white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px;"></div>
            </div>
          </div>

          <!-- Origin code selector -->
          <div style="margin-bottom:12px;">
            <div style="font-size:10px;font-weight:600;color:${C.gray};letter-spacing:1px;
              text-transform:uppercase;margin-bottom:8px;
              display:flex;align-items:center;gap:6px;">
              Content Origin
              <span title="How was this content created? Over-declaring AI is always safe."
                style="font-size:10px;background:${C.navy}10;color:${C.navy};
                border-radius:50%;width:14px;height:14px;display:inline-flex;
                align-items:center;justify-content:center;cursor:help;font-weight:700;">?</span>
            </div>
            <div id="tip-origin-btns" style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">
              ${[
                { code:"OH", label:"Original Human",   hint:"You wrote or filmed this entirely." },
                { code:"AA", label:"AI-Assisted",       hint:"You led the creative work; AI helped edit or improve." },
                { code:"AG", label:"AI-Generated",      hint:"AI generated this; you prompted and curated." },
                { code:"MX", label:"Mixed / Composite", hint:"Multiple sources - some human, somee AI." },
              ].map(o => `
                <button class="tip-origin-btn" data-code="${o.code}"
                  title="${o.hint}"
                  style="padding:7px 8px;border-radius:6px;border:1.5px solid ${C.border};
                    background:${C.bg};font-family:inherit;cursor:pointer;
                    text-align:left;transition:all 0.15s;">
                  <div style="font-size:11px;font-weight:700;color:${ORIGIN_COLORS[o.code]};
                    font-family:monospace;">${o.code}</div>
                  <div style="font-size:10px;color:${C.gray};font-weight:400;margin-top:1px;">${o.label}</div>
                </button>
              `).join("")}
            </div>
            <div id="tip-origin-hint" style="font-size:10px;color:${C.blue};margin-top:6px;
              padding:5px 8px;background:#EFF6FF;border-radius:4px;display:none;"></div>
          </div>

          <!-- Auto-detected content preview -->
          <div style="margin-bottom:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px;">
              <div style="font-size:10px;font-weight:600;color:${C.gray};letter-spacing:1px;
                text-transform:uppercase;">Content Preview</div>
              <button id="tip-refresh-content" style="font-size:10px;color:${C.blue};
                background:none;border:none;cursor:pointer;padding:0;font-family:inherit;">
                ↻ Re-scan
              </button>
            </div>
            <div id="tip-content-preview" style="
              font-size:11px;color:${C.navy};background:#F8F9FB;
              border:1px solid ${C.border};border-radius:6px;
              padding:8px 10px;line-height:1.5;
              max-height:60px;overflow:hidden;position:relative;
            ">
              <span style="color:${C.gray};">Scanning page for content...</span>
            </div>
          </div>

          <!-- Auth: WebAuthn (default) -->
          <div id="tip-auth-webauthn" style="margin-bottom:12px;display:none;">
            <div style="padding:8px 10px;background:#1A8A5C10;border:1px solid #1A8A5C30;border-radius:6px;font-size:11px;color:#1A8A5C;">
              🔐 <strong>Face ID / Fingerprint</strong> will be required to sign.
            </div>
          </div>
          <!-- Auth: Password (fallback) -->
          <div id="tip-auth-password" style="margin-bottom:12px;display:none;">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:5px;">
              <div style="font-size:10px;font-weight:600;color:${C.gray};letter-spacing:1px;
                text-transform:uppercase;">Signing Password</div>
            </div>
            <input id="tip-password" type="password" placeholder="Enter your TIP signing password"
              style="width:100%;padding:8px 10px;border:1px solid ${C.border};
                border-radius:6px;font-family:monospace;font-size:12px;
                color:${C.navy};outline:none;box-sizing:border-box;"
              autocomplete="current-password"
            />
          </div>

          <!-- Register button -->
          <button id="tip-register-btn" style="
            width:100%;padding:10px;border-radius:8px;
            background:${C.navy};color:#B8942E;
            border:none;font-family:inherit;font-size:12px;font-weight:600;
            cursor:pointer;letter-spacing:0.5px;transition:all 0.2s;
            display:flex;align-items:center;justify-content:center;gap:8px;
          " disabled>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Select origin code to continue
          </button>
        </div>

        <!-- Success state -->
        <div id="tip-success" style="display:none;text-align:center;padding:8px 0;">
          <div style="font-size:24px;margin-bottom:6px;">✅</div>
          <div style="font-size:13px;font-weight:700;color:${C.green};margin-bottom:4px;">Registered on TIP DAG!</div>
          <div id="tip-ctid-display" style="font-size:10px;font-family:monospace;
            color:${C.navy};background:#F8F9FB;padding:6px 8px;border-radius:5px;
            border:1px solid ${C.border};word-break:break-all;margin:8px 0;text-align:left;"></div>
          <button id="tip-copy-ctid" style="
            width:100%;padding:8px;background:${C.green}15;color:${C.green};
            border:1px solid ${C.green}40;border-radius:6px;
            font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;
            margin-bottom:6px;
          ">📋 Copy CTID to clipboard</button>
          <div style="font-size:10px;color:${C.gray};line-height:1.5;text-align:left;">
            Paste this CTID in your description or comments so viewers can verify your content.
          </div>
          <button id="tip-register-another" style="
            margin-top:8px;padding:6px 12px;background:none;color:${C.blue};
            border:1px solid ${C.blue}40;border-radius:5px;font-size:11px;
            cursor:pointer;font-family:inherit;
          ">Register another</button>
        </div>

      </div>

      <!-- Footer -->
      <div style="padding:8px 14px;background:#F8F9FB;border-top:1px solid ${C.border};
        display:flex;justify-content:space-between;align-items:center;">
        <a href="https://theailab.org" target="_blank" style="font-size:9px;color:${C.gray};text-decoration:none;">
          theailab.org
        </a>
        <span style="font-size:9px;color:${C.gray};">TIP v2.2</span>
      </div>
    `;

    document.body.appendChild(panel);

    // ── Panel state ────────────────────────────────────────────────────────────
    let selectedOrigin = null;
    let detectedContent = { title: "", description: "", url: "" };
    let detectedPlatformType = platformName?.toLowerCase() || "text";
    let currentCTID = "";

    // Draggable panel
    makeDraggable(panel, document.getElementById("tip-panel-header"));

    // Minimize / close
    document.getElementById("tip-panel-minimize").addEventListener("click", () => {
      const body = document.getElementById("tip-panel-body");
      body.style.display = body.style.display === "none" ? "block" : "none";
    });
    document.getElementById("tip-panel-close").addEventListener("click", () => panel.remove());
    document.getElementById("tip-goto-settings").addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "OPEN_OPTIONS" });
    });
    document.getElementById("tip-register-another").addEventListener("click", resetForm);

    // Load TIP-ID
    chrome.runtime.sendMessage({ type: "GET_IDENTITY" }, (res) => {
      if (res?.ok && res.data?.setupComplete && res.data?.tipId) {
        const idEl = document.getElementById("tip-id-value");
        if (idEl) idEl.textContent = res.data.tipId;
        document.getElementById("tip-setup-prompt").style.display = "none";
        document.getElementById("tip-reg-form").style.display = "block";
        // Show correct auth method
        const sm = (res.data.securityMethod || "").toLowerCase();
        const isWA = sm.includes("webauthn");
        document.getElementById("tip-auth-webauthn").style.display = isWA ? "block" : "none";
        document.getElementById("tip-auth-password").style.display = isWA ? "none" : "block";
      } else {
        document.getElementById("tip-setup-prompt").style.display = "block";
        document.getElementById("tip-reg-form").style.display = "none";
      }
    });

    // Scan for content
    function scanContent() {
      const sel = selectors;
      const titleEl = sel.title ? document.querySelector(sel.title) : null;
      const descEl  = sel.desc  ? document.querySelector(sel.desc)  : null;
      detectedContent.title       = titleEl?.value || titleEl?.textContent?.trim() || "";
      detectedContent.description = descEl?.value  || descEl?.textContent?.trim()  || "";
      detectedContent.url         = window.location.href || "";
      const preview = document.getElementById("tip-content-preview");
      if (preview) {
        const text = detectedContent.title
          ? `<strong>${detectedContent.title.slice(0,60)}</strong>${detectedContent.description ? `<br><span style="opacity:0.6;">${detectedContent.description.slice(0,80)}...</span>` : ""}`
          : detectedContent.description
            ? detectedContent.description.slice(0, 120) + "..."
            : `<span style="color:${C.gray};">No content detected yet. Type your title and description, then re-scan.</span>`;
        preview.innerHTML = text;
      }
    }
    scanContent();
    document.getElementById("tip-refresh-content").addEventListener("click", scanContent);

    // Origin button selection
    document.querySelectorAll(".tip-origin-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tip-origin-btn").forEach(b => {
          b.style.background = C.bg;
          b.style.borderColor = C.border;
        });
        selectedOrigin = btn.dataset.code;
        btn.style.background = `${ORIGIN_COLORS[selectedOrigin]}15`;
        btn.style.borderColor = `${ORIGIN_COLORS[selectedOrigin]}60`;

        const hints = {
          OH: "✅ Great choice. Declaring Original Human registers your work as fully human-created. If an AI classifier later disputes this, your trust score may be affected.",
          AA: "✅ AI-Assisted is honest and safe. No penalty for over-declaring AI involvement.",
          AG: "✅ AI-Generated is always accepted. Full transparency builds trust.",
          MX: "✅ Mixed reflects complex creative work. A good honest default when unsure.",
        };
        const hintEl = document.getElementById("tip-origin-hint");
        if (hintEl) {
          hintEl.textContent = hints[selectedOrigin];
          hintEl.style.display = "block";
        }

        // Enable register button
        const btn2 = document.getElementById("tip-register-btn");
        if (btn2) {
          btn2.disabled = false;
          btn2.innerHTML = `
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="2.5" stroke-linecap="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Register as ${selectedOrigin} - ${ORIGIN_LABELS[selectedOrigin]}
          `;
          btn2.style.opacity = "1";
        }
      });
    });

    // Detect auth method
    let widgetUseWebAuthn = false;
    chrome.runtime.sendMessage({ type: "GET_IDENTITY" }, (idRes) => {
      if (idRes?.ok && idRes.data?.securityMethod) {
        widgetUseWebAuthn = idRes.data.securityMethod.toLowerCase().includes("webauthn");
      }
    });

    // Register button click
    document.getElementById("tip-register-btn").addEventListener("click", async () => {
      if (!selectedOrigin) return;

      if (!widgetUseWebAuthn) {
        const password = document.getElementById("tip-password").value;
        if (!password) {
          showStatus("error", "Enter your signing password first.");
          document.getElementById("tip-password").focus();
          return;
        }
      }

      const content = `${detectedContent.title}\n${detectedContent.description}`.trim();
      if (!content) {
        showStatus("error", "No content detected. Try typing your title/description first, then re-scan.");
        return;
      }

      const btn = document.getElementById("tip-register-btn");
      btn.disabled = true;
      btn.innerHTML = "⏳ Registering on TIP DAG...";
      showStatus("info", widgetUseWebAuthn ? "Authenticate with biometric to sign..." : "Hashing content and signing with your key...");

      // Build proper content string using platform-aware formula
      const values = {
        title:       detectedContent.title,
        content:     detectedContent.description,
        video_url:   detectedContent.url || "",
      };

      function handleRegResult(res) {
        if (res?.ok && res.data?.ctid) {
          currentCTID = res.data.ctid;
          document.getElementById("tip-ctid-display").textContent = currentCTID;
          document.getElementById("tip-reg-form").style.display = "none";
          document.getElementById("tip-success").style.display = "block";
          showStatus("", "");
          navigator.clipboard?.writeText(currentCTID).catch(() => {});
        } else {
          showStatus("error", res?.error || "Registration failed. Check your node connection in Settings.");
          btn.disabled = false;
          btn.innerHTML = `Register as ${selectedOrigin} - ${ORIGIN_LABELS[selectedOrigin]}`;
        }
      }

      if (widgetUseWebAuthn) {
        // WebAuthn needs extension origin — use hidden iframe with publickey-credentials permission
        await chrome.storage.local.set({
          pendingReg: { originCode: selectedOrigin, content: detectedContent.description, title: detectedContent.title },
        });
        // Listen for result via storage
        chrome.storage.onChanged.addListener(function sigListener(changes) {
          if (changes.signResult) {
            chrome.storage.onChanged.removeListener(sigListener);
            const res = changes.signResult.newValue;
            chrome.storage.local.remove("signResult");
            const frame = document.getElementById("tip-sign-frame");
            if (frame) frame.remove();
            handleRegResult(res);
          }
        });
        // Create iframe on extension origin with WebAuthn permission
        const frame = document.createElement("iframe");
        frame.id = "tip-sign-frame";
        frame.src = chrome.runtime.getURL("sign.html");
        frame.allow = "publickey-credentials-get *; publickey-credentials-create *";
        frame.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;border:none;opacity:0;";
        document.body.appendChild(frame);
      } else {
        const password = document.getElementById("tip-password").value;
        chrome.runtime.sendMessage({
          type: "REGISTER_CONTENT",
          payload: { originCode: selectedOrigin, typeId: detectedPlatformType || "text", values, title: detectedContent.title, password },
        }, handleRegResult);
      }
    });

    document.getElementById("tip-copy-ctid").addEventListener("click", () => {
      navigator.clipboard.writeText(currentCTID).then(() => {
        const btn = document.getElementById("tip-copy-ctid");
        btn.textContent = "✓ Copied!";
        btn.style.background = `${C.green}25`;
        setTimeout(() => {
          btn.textContent = "📋 Copy CTID to clipboard";
          btn.style.background = `${C.green}15`;
        }, 2000);
      });
    });

    function showStatus(type, message) {
      const el = document.getElementById("tip-status-bar");
      if (!el) return;
      if (!message) { el.style.display = "none"; return; }
      const styles = {
        error: `background:#FFF5F5;border:1px solid #C5303030;color:#C53030;`,
        info:  `background:#EFF6FF;border:1px solid #2563A830;color:#1E40AF;`,
        ok:    `background:#F0FDF4;border:1px solid #1A8A5C30;color:#1A8A5C;`,
      };
      el.style.cssText = `display:block;padding:8px 10px;border-radius:6px;margin-bottom:10px;font-size:11px;${styles[type] || styles.info}`;
      el.textContent = message;
    }

    function resetForm() {
      document.getElementById("tip-reg-form").style.display = "block";
      document.getElementById("tip-success").style.display = "none";
      document.getElementById("tip-password").value = "";
      selectedOrigin = null;
      document.querySelectorAll(".tip-origin-btn").forEach(b => {
        b.style.background = C.bg;
        b.style.borderColor = C.border;
      });
      document.getElementById("tip-origin-hint").style.display = "none";
      const btn = document.getElementById("tip-register-btn");
      btn.disabled = true;
      btn.innerHTML = `
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        Select origin code to continue
      `;
      scanContent();
    }
  }

  // ── Drag helper ──────────────────────────────────────────────────────────────
  function makeDraggable(el, handle) {
    let ox = 0, oy = 0, x = 0, y = 0;
    let dragging = false, startX, startY, startLeft, startTop;
    handle.addEventListener("mousedown", (e) => {
      if (e.target.closest("button")) return;
      e.preventDefault();
      dragging = true;
      const rect = el.getBoundingClientRect();
      el.style.top = rect.top + "px";
      el.style.left = rect.left + "px";
      el.style.right = "auto";
      el.style.bottom = "auto";
      startX = e.clientX;
      startY = e.clientY;
      startLeft = rect.left;
      startTop = rect.top;
    });
    document.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      el.style.left = (startLeft + e.clientX - startX) + "px";
      el.style.top = (startTop + e.clientY - startY) + "px";
    });
    document.addEventListener("mouseup", () => { dragging = false; });
    function drag() {  // unused — kept for compat
    }
  }

  // ── Main ─────────────────────────────────────────────────────────────────────
  function main() {
    // Viewer: meta tags
    const meta = readMetaTags();
    if (meta.author && meta.score > 0) {
      const selectors = [".byline", ".author-name", "[rel=author]", ".post-author", "article header .name"];
      selectors.forEach(s => {
        document.querySelectorAll(`${s}:not(.tip-done)`).forEach(el => {
          el.classList.add("tip-done");
          el.appendChild(inlineBadge(meta.score, meta.author, meta.origin?.toUpperCase().slice(0,2)));
        });
      });
      showPageBadge(meta.score, meta.author, meta.origin?.toUpperCase().slice(0,2));
    }

    // Viewer: CTID scanning
    scanForCTIDs();

    // Viewer: platform-specific injections
    if (PLATFORM === "youtube")   injectYouTube();
    if (PLATFORM === "twitter")   injectTwitter();

    // Creator: upload page detection
    if (IS_UPLOAD) {
      const platformName =
        /youtube/i.test(location.href)   ? "YouTube"   :
        /instagram/i.test(location.href) ? "Instagram" :
        /tiktok/i.test(location.href)    ? "TikTok"    :
        /twitter|x\.com/i.test(location.href) ? "X"   :
        /facebook/i.test(location.href)  ? "Facebook"  :
        /linkedin/i.test(location.href)  ? "LinkedIn"  :
        /substack/i.test(location.href)  ? "Substack"  :
        /medium/i.test(location.href)    ? "Medium"    : "Platform";
      setTimeout(() => injectCreatorPanel(platformName), 1500); // wait for SPA to render
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", main);
  } else {
    main();
  }

  // SPA navigation re-trigger
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      window.__tipContentInjected = false;
      setTimeout(() => {
        window.__tipContentInjected = true;
        main();
      }, 1000);
    }
  }).observe(document, { subtree: true, childList: true });

  // ── Icon theme switching (dark / light mode) ─────────────────────────────
  // The service worker has no window.matchMedia - the content script detects
  // the system color scheme and tells the background to swap the icon set.
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  function reportTheme(isDark) {
    chrome.runtime.sendMessage({ type: "UPDATE_ICON_THEME", isDark }).catch(() => {});
  }
  reportTheme(mq.matches);
  mq.addEventListener("change", e => reportTheme(e.matches));

})();
