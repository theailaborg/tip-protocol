/**
 * @file browser-extension/src/background.js
 * @description TIP™ Extension — Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 *   - Intercept HTTP responses and read TIP-* headers
 *   - Cache TIP data per tab for popup display
 *   - Fetch identity/content records from the configured TIP node
 *   - Maintain local revocation list cache (polled every 5 minutes)
 *   - Handle messages from content script and popup
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const DEFAULT_NODE = "http://localhost:4000";

// ── In-memory tab data cache ──────────────────────────────────────────────────
const tabData    = new Map();   // tabId -> { tipAuthor, tipContent, tipScore, tipOrigin, identityRecord }
const identCache = new Map();   // tipId -> { data, fetchedAt }
const contentCache = new Map(); // ctid -> { data, fetchedAt }
let   revocationCache = [];     // [{tip_id, tx_type, timestamp}]
let   revocationLastFetch = 0;

const CACHE_TTL       = 5 * 60 * 1000;  // 5 min
const REVOC_INTERVAL  = 5 * 60 * 1000;  // 5 min

// ── Get configured node URL ──────────────────────────────────────────────────
async function getNodeUrl() {
  const s = await chrome.storage.sync.get(["nodeUrl"]);
  return s.nodeUrl || DEFAULT_NODE;
}

// ── Fetch with timeout ────────────────────────────────────────────────────────
async function tipFetch(path) {
  const nodeUrl = await getNodeUrl();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res  = await fetch(nodeUrl + path, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    return res.json();
  } catch {
    clearTimeout(timer);
    return null;
  }
}

// ── Read TIP-* headers from a web request ────────────────────────────────────
function parseTIPHeaders(headers) {
  const result = {};
  for (const h of headers) {
    const name = h.name.toLowerCase();
    if (name === "tip-author")       result.tipAuthor     = h.value;
    if (name === "tip-content")      result.tipContent    = h.value;
    if (name === "tip-origin")       result.tipOrigin     = h.value;
    if (name === "tip-trust-score")  result.tipScore      = parseInt(h.value, 10);
    if (name === "tip-tier")         result.tipTier       = h.value;
    if (name === "tip-signature")    result.tipSignature  = h.value;
  }
  return result;
}

// ── Intercept responses for TIP-* headers ────────────────────────────────────
chrome.webRequest?.onHeadersReceived?.addListener(
  (details) => {
    const parsed = parseTIPHeaders(details.responseHeaders || []);
    if (parsed.tipAuthor || parsed.tipContent) {
      tabData.set(details.tabId, { ...parsed, url: details.url, ts: Date.now() });
      // Update badge icon
      updateBadgeIcon(details.tabId, parsed.tipScore);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ── Update toolbar badge ─────────────────────────────────────────────────────
function updateBadgeIcon(tabId, score) {
  const color = score >= 800 ? "#1A8A5C"
    : score >= 600 ? "#2563A8"
    : score >= 400 ? "#A88B15"
    : score >= 200 ? "#C07318"
    : score > 0    ? "#C53030"
    : "#8895A7";

  chrome.action.setBadgeText({ tabId, text: score > 0 ? "✓" : "?" });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// ── Revocation list refresh ──────────────────────────────────────────────────
async function refreshRevocations() {
  const since = revocationLastFetch > 0 ? new Date(revocationLastFetch).toISOString() : null;
  const qs    = since ? `?since=${encodeURIComponent(since)}` : "";
  const data  = await tipFetch(`/v1/revocations${qs}`);
  if (data && data.revocations) {
    const newRevoc = data.revocations;
    // Merge with existing cache
    const existing = new Set(revocationCache.map(r => r.tip_id));
    newRevoc.forEach(r => { if (!existing.has(r.tip_id)) revocationCache.push(r); });
    revocationLastFetch = Date.now();
  }
}

// Poll revocations
setInterval(refreshRevocations, REVOC_INTERVAL);
refreshRevocations();

// ── Message handler (from content script and popup) ──────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  switch (msg.type) {

    case "GET_TAB_DATA": {
      const tabId = msg.tabId || sender.tab?.id;
      const data  = tabData.get(tabId) || null;
      sendResponse({ data });
      return true;
    }

    case "FETCH_IDENTITY": {
      const tipId = msg.tipId;
      const cached = identCache.get(tipId);
      if (cached && (Date.now() - cached.fetchedAt) < CACHE_TTL) {
        sendResponse({ data: cached.data });
        return true;
      }
      tipFetch(`/v1/identity/${encodeURIComponent(tipId)}/score`).then(data => {
        if (data) identCache.set(tipId, { data, fetchedAt: Date.now() });
        sendResponse({ data });
      });
      return true;
    }

    case "FETCH_CONTENT": {
      const ctid = msg.ctid;
      const cached = contentCache.get(ctid);
      if (cached && (Date.now() - cached.fetchedAt) < CACHE_TTL) {
        sendResponse({ data: cached.data });
        return true;
      }
      tipFetch(`/v1/content/${encodeURIComponent(ctid)}`).then(data => {
        if (data) contentCache.set(ctid, { data, fetchedAt: Date.now() });
        sendResponse({ data });
      });
      return true;
    }

    case "IS_REVOKED": {
      const revoked = revocationCache.some(r => r.tip_id === msg.tipId);
      sendResponse({ revoked });
      return true;
    }

    case "GET_NODE_URL": {
      getNodeUrl().then(url => sendResponse({ url }));
      return true;
    }

    case "SET_NODE_URL": {
      chrome.storage.sync.set({ nodeUrl: msg.url }).then(() => sendResponse({ ok: true }));
      return true;
    }

    case "NODE_INFO": {
      tipFetch("/v1/node/info").then(data => sendResponse({ data }));
      return true;
    }
  }

  return false;
});

// ── Tab cleanup ───────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  tabData.delete(tabId);
  chrome.action.setBadgeText({ tabId, text: "" });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    tabData.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: "" });
  }
});

console.log("[TIP™] Background service worker started.");
