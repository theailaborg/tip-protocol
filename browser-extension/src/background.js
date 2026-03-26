/**
 * @file src/background.js
 * @description TIP™ Extension - Background Service Worker (Manifest V3)
 *
 * Dual-mode responsibilities:
 *
 * VIEWER MODE (existing platforms that publish TIP headers):
 *   - Read TIP-* HTTP response headers per tab
 *   - Cache identity and content records from TIP node
 *   - Poll revocation list every 5 minutes
 *   - Update toolbar badge color by trust tier
 *
 * CREATOR MODE (before platforms implement TIP natively):
 *   - Detect upload pages (YouTube, Instagram, TikTok, X, Facebook, LinkedIn)
 *   - Hash content and sign with creator's private key (via crypto.js)
 *   - Call POST /v1/content/register on TIP node
 *   - Return CTID and copy to clipboard
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * Author: Dinesh Mendhe <chairman@theailab.org>
 * License: TIPCL-1.0
 */

"use strict";

import { shake256, signData, generateKeypair, encryptPrivateKey, decryptPrivateKey, computeTIPID } from "./crypto.js";

const DEFAULT_NODE = "https://node.theailab.org";
const CACHE_TTL    = 5 * 60 * 1000;   // 5 min
const REVOC_POLL   = 5 * 60 * 1000;   // 5 min

// ── In-memory caches ──────────────────────────────────────────────────────────
const tabData      = new Map();  // tabId → parsed TIP header data
const identCache   = new Map();  // tipId → { data, ts }
const contentCache = new Map();  // ctid  → { data, ts }
let   revocList    = [];
let   revocLastTs  = 0;

// ── Upload page patterns ──────────────────────────────────────────────────────
const UPLOAD_PATTERNS = [
  { pattern: /studio\.youtube\.com|youtube\.com\/upload/,    platform: "YouTube"    },
  { pattern: /instagram\.com\/(create|p\/|reels\/|stories\/)/,  platform: "Instagram" },
  { pattern: /tiktok\.com\/upload/,                          platform: "TikTok"     },
  { pattern: /facebook\.com\/(video\/upload|photo|stories\/)/,  platform: "Facebook"  },
  { pattern: /twitter\.com\/compose|x\.com\/compose/,        platform: "X"          },
  { pattern: /linkedin\.com\/post\/new|linkedin\.com\/feed\//,  platform: "LinkedIn"  },
  { pattern: /substack\.com\/publish|substack\.com\/.*\/write/, platform: "Substack"  },
  { pattern: /medium\.com\/new-story|medium\.com\/@.*\/new/,    platform: "Medium"    },
  { pattern: /threads\.net\/intent|threads\.net\/compose/,      platform: "Threads"   },
  { pattern: /anchor\.fm|podcasters\.spotify\.com|buzzsprout/,   platform: "Podcast"   },
  { pattern: /wordpress\.com\/post|ghost\.io.*\/editor/,         platform: "Blog"      },
];

// ── Node URL ─────────────────────────────────────────────────────────────────
async function getNodeUrl() {
  const s = await chrome.storage.sync.get(["nodeUrl"]);
  return (s.nodeUrl || DEFAULT_NODE).replace(/\/$/, "");
}

// ── Fetch helper ──────────────────────────────────────────────────────────────
async function tipFetch(path, options = {}) {
  const nodeUrl    = await getNodeUrl();
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(nodeUrl + path, {
      signal: controller.signal,
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      ...options,
    });
    clearTimeout(timer);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

// ── Parse TIP-* HTTP headers ──────────────────────────────────────────────────
function parseTIPHeaders(headers) {
  const r = {};
  for (const h of headers) {
    const n = h.name.toLowerCase();
    if (n === "tip-author")       r.tipAuthor  = h.value;
    if (n === "tip-content")      r.tipContent = h.value;
    if (n === "tip-origin")       r.tipOrigin  = h.value;
    if (n === "tip-trust-score")  r.tipScore   = parseInt(h.value, 10);
    if (n === "tip-trust-tier")   r.tipTier    = h.value;
    if (n === "tip-signature")    r.tipSig     = h.value;
  }
  return r;
}

// ── HTTP header listener ──────────────────────────────────────────────────────
chrome.webRequest?.onHeadersReceived?.addListener(
  (details) => {
    const parsed = parseTIPHeaders(details.responseHeaders || []);
    if (parsed.tipAuthor || parsed.tipContent) {
      tabData.set(details.tabId, { ...parsed, url: details.url, ts: Date.now(), fromHeaders: true });
      updateBadge(details.tabId, parsed.tipScore || 0, true);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ── Toolbar badge ─────────────────────────────────────────────────────────────
function updateBadge(tabId, score, verified = false) {
  const color = score >= 800 ? "#1A8A5C"
    : score >= 600 ? "#2563A8"
    : score >= 400 ? "#A88B15"
    : score >= 200 ? "#C07318"
    : score > 0    ? "#C53030"
    : "#8895A7";
  const text = verified ? "✓" : score > 0 ? String(Math.round(score / 100)) : "";
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
}

// ── Detect upload page for a URL ─────────────────────────────────────────────
function detectUploadPlatform(url) {
  for (const { pattern, platform } of UPLOAD_PATTERNS) {
    if (pattern.test(url)) return platform;
  }
  return null;
}

// ── Revocation polling ────────────────────────────────────────────────────────
async function pollRevocations() {
  try {
    const since = revocLastTs > 0 ? `?since=${new Date(revocLastTs).toISOString()}` : "";
    const data  = await tipFetch(`/v1/revocations${since}`);
    if (data?.revocations) {
      const existing = new Set(revocList.map(r => r.tip_id));
      data.revocations.forEach(r => { if (!existing.has(r.tip_id)) revocList.push(r); });
      revocLastTs = Date.now();
    }
  } catch { /* silent - node may be offline */ }
}
setInterval(pollRevocations, REVOC_POLL);
pollRevocations();

// ── Creator: register content on TIP node ────────────────────────────────────
async function registerContent({ tipId, originCode, typeId, values, content, title, password }) {
  // 1. Get encrypted private key from storage
  const stored = await chrome.storage.local.get(["encryptedKey", "tipId"]);
  if (!stored.encryptedKey) throw new Error("No TIP-ID configured. Please set up your identity in Settings.");
  if (!password)            throw new Error("Password required to sign content.");

  // 2. Decrypt private key
  let privateKey;
  try {
    privateKey = await decryptPrivateKey(stored.encryptedKey, password);
  } catch {
    throw new Error("Wrong password. Cannot decrypt your signing key.");
  }

  // 3. Build canonical content string using platform-aware formula.
  //    If typeId + values are provided (new platform-aware flow), use buildContentString.
  //    Fall back to naive title+content for legacy callers.
  let contentToHash;
  if (typeId && values) {
    contentToHash = buildContentString(typeId, values);
  } else {
    contentToHash = title ? `${title}\n${content}` : (content || "");
  }
  if (!contentToHash.trim()) {
    throw new Error("No content to register. Fill in the required fields first.");
  }

  // 4. Hash using SHAKE-256 (TIP Protocol CTID formula)
  const contentHash = await shake256(contentToHash);

  // 5. Sign: payload = contentHash + originCode
  const payload   = contentHash + originCode;
  const signature = await signData(payload, privateKey);

  // 6. POST to TIP node
  const result = await tipFetch("/v1/content/register", {
    method: "POST",
    body: JSON.stringify({
      author_tip_id:    tipId || stored.tipId,
      origin_code:      originCode,
      content_type:     typeId || "other",
      content:          contentToHash.slice(0, 10000),
      content_hash:     contentHash,
      author_signature: signature,
      title:            (values?.title || title || ""),
    }),
  });

  return result; // { ctid, status, pre_scan_flagged, ... }
}

// ── Creator: generate and store a new keypair ────────────────────────────────
async function setupIdentity({ tipId, password, existingPrivateKey }) {
  if (!password) throw new Error("Password is required to secure your key.");

  let privateKey;
  let publicKey;

  if (existingPrivateKey) {
    // User is importing an existing key
    privateKey = existingPrivateKey;
    publicKey  = "imported"; // public key derivation from stored hex not needed for signing
  } else {
    // Generate fresh keypair
    const kp   = await generateKeypair();
    privateKey = kp.privateKey;
    publicKey  = kp.publicKey;
  }

  const encryptedKey = await encryptPrivateKey(privateKey, password);

  await chrome.storage.local.set({
    tipId,
    publicKey,
    encryptedKey,
    setupComplete: true,
    setupDate:     new Date().toISOString(),
  });

  return { tipId, publicKey };
}

// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const respond = (promise) => {
    promise.then(data => sendResponse({ ok: true, data }))
           .catch(err  => sendResponse({ ok: false, error: err.message }));
    return true; // async
  };

  switch (msg.type) {

    // ── Viewer: get TIP data for current tab ──────────────────────────────────
    case "GET_TAB_DATA": {
      const tabId = msg.tabId || sender.tab?.id;
      sendResponse({ data: tabData.get(tabId) || null });
      return false;
    }

    // ── Viewer: fetch identity record ─────────────────────────────────────────
    case "FETCH_IDENTITY": {
      return respond((async () => {
        const cached = identCache.get(msg.tipId);
        if (cached && Date.now() - cached.ts < CACHE_TTL) return cached.data;
        const data = await tipFetch(`/v1/identity/${encodeURIComponent(msg.tipId)}/score`);
        identCache.set(msg.tipId, { data, ts: Date.now() });
        return data;
      })());
    }

    // ── Viewer: fetch content record ──────────────────────────────────────────
    case "FETCH_CONTENT": {
      return respond((async () => {
        const cached = contentCache.get(msg.ctid);
        if (cached && Date.now() - cached.ts < CACHE_TTL) return cached.data;
        const data = await tipFetch(`/v1/content/${encodeURIComponent(msg.ctid)}`);
        contentCache.set(msg.ctid, { data, ts: Date.now() });
        return data;
      })());
    }

    // ── Viewer: check revocation ──────────────────────────────────────────────
    case "IS_REVOKED":
      sendResponse({ revoked: revocList.some(r => r.tip_id === msg.tipId) });
      return false;

    // ── Creator: register content on DAG ─────────────────────────────────────
    case "REGISTER_CONTENT":
      return respond(registerContent(msg.payload));

    // ── Creator: setup / import identity ─────────────────────────────────────
    case "SETUP_IDENTITY":
      return respond(setupIdentity(msg.payload));

    // ── Creator: get stored identity ──────────────────────────────────────────
    case "GET_IDENTITY":
      return respond(chrome.storage.local.get(["tipId", "publicKey", "setupComplete", "setupDate"]));

    // ── Creator: clear identity (logout) ─────────────────────────────────────
    case "CLEAR_IDENTITY":
      return respond(chrome.storage.local.remove(["tipId", "publicKey", "encryptedKey", "setupComplete", "setupDate"]));

    // ── Detect upload platform for a URL ─────────────────────────────────────
    case "DETECT_PLATFORM": {
      const platform = detectUploadPlatform(msg.url);
      sendResponse({ platform });
      return false;
    }

    // ── Node health check ─────────────────────────────────────────────────────
    case "NODE_HEALTH":
      return respond(tipFetch("/health"));

    // ── Open options page ─────────────────────────────────────────────────────
    case "OPEN_OPTIONS":
      chrome.runtime.openOptionsPage();
      sendResponse({ ok: true });
      return false;

    // ── Node URL management ───────────────────────────────────────────────────
    case "GET_NODE_URL":
      return respond(getNodeUrl());

    case "SET_NODE_URL":
      return respond(chrome.storage.sync.set({ nodeUrl: msg.url }));
  }

  return false;
});

// ── Tab lifecycle cleanup ─────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  tabData.delete(tabId);
  chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading") {
    tabData.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  }
  // Set creator badge on upload pages
  if (changeInfo.status === "complete" && tab.url) {
    const platform = detectUploadPlatform(tab.url);
    if (platform) {
      chrome.action.setBadgeText({ tabId, text: "+" }).catch(() => {});
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#B8942E" }).catch(() => {});
    }
  }
});

// Service worker v2.2.0 ready
