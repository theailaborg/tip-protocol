"use strict";

// ── Constants ─────────────────────────────────────────────────────────────
const COLORS = {
  green:"#1A8A5C", blue:"#2563A8", yellow:"#A88B15",
  orange:"#C07318", red:"#C53030", gray:"#8895A7",
  navy:"#0C1A3A", gold:"#B8942E",
};
const ORIGIN_COLORS = { OH:"#2563A8", AA:"#7C3AED", AG:"#C07318", MX:"#8895A7" };
const ORIGIN_LABELS = {
  OH:"Original Human", AA:"AI-Assisted", AG:"AI-Generated", MX:"Mixed"
};
const ORIGIN_HINTS = {
  OH:"✅ Declaring Original Human means you created this without AI. If an AI classifier later challenges this, your trust score may be affected.",
  AA:"✅ AI-Assisted is honest and safe. No penalty for over-declaring AI involvement. Use this when AI helped but you led the work.",
  AG:"✅ AI-Generated is always accepted. Full transparency builds long-term trust with your audience.",
  MX:"✅ Mixed is a safe default when you're unsure. It covers anything combining human and AI contributions.",
};

function tierColor(s) {
  return s>=800?COLORS.green:s>=600?COLORS.blue:s>=400?COLORS.yellow:s>=200?COLORS.orange:COLORS.red;
}
function tierLabel(s) {
  return s>=800?"Highly Trusted":s>=600?"Trusted":s>=400?"Review Advised":s>=200?"Low Trust":"Not Trusted";
}

function shieldSVG(score, size=36) {
  const c = tierColor(score);
  const icon = score>=600
    ? `<path d="M16 24L22 30L34 18" stroke="${c}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>`
    : score>=400
      ? `<text x="24" y="29" text-anchor="middle" fill="${c}" font-size="16" font-weight="bold">!</text>`
      : `<line x1="17" y1="19" x2="31" y2="33" stroke="${c}" stroke-width="3" stroke-linecap="round"/>
         <line x1="31" y1="19" x2="17" y2="33" stroke="${c}" stroke-width="3" stroke-linecap="round"/>`;
  return `<svg width="${size}" height="${size}" viewBox="0 0 48 48" fill="none">
    <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z"
      fill="${c}15" stroke="${c}" stroke-width="2.2"/>
    ${icon}
  </svg>`;
}

function originPillHTML(code) {
  const c = ORIGIN_COLORS[code]||COLORS.gray;
  const l = ORIGIN_LABELS[code]||code;
  return `<span style="display:inline-flex;align-items:center;gap:3px;padding:3px 8px;
    border-radius:3px;background:${c}15;border:1px solid ${c}30;
    font-size:10px;font-family:'JetBrains Mono',monospace;font-weight:700;color:${c};">
    ${code}<span style="font-family:inherit;font-weight:400;opacity:0.75;font-size:10px;"> ${l}</span></span>`;
}

function msg(type, payload) {
  return new Promise(r => chrome.runtime.sendMessage({ type, ...payload }, r));
}

// ── State ─────────────────────────────────────────────────────────────────
let activeTab = "creator";
let selectedOrigin = null;
let currentCTID = "";

function show(id)  { const el = document.getElementById(id); if(el) el.style.display = "block"; }
function hide(id)  { const el = document.getElementById(id); if(el) el.style.display = "none"; }
function setHTML(id, html) { const el = document.getElementById(id); if(el) el.innerHTML = html; }
function setText(id, t)    { const el = document.getElementById(id); if(el) el.textContent = t; }

function showStatus(id, type, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!msg) { el.style.display = "none"; return; }
  const classes = { error:"status-error", info:"status-info", ok:"status-ok" };
  el.className = "status-msg " + (classes[type]||classes.info);
  el.textContent = msg;
  el.style.display = "block";
}

// ── Tab switching ─────────────────────────────────────────────────────────
document.getElementById("tab-creator").addEventListener("click", () => switchTab("creator"));
document.getElementById("tab-viewer").addEventListener("click",  () => switchTab("viewer"));

function switchTab(tab) {
  activeTab = tab;
  document.getElementById("tab-creator").classList.toggle("active", tab === "creator");
  document.getElementById("tab-viewer").classList.toggle("active", tab === "viewer");
  document.getElementById("creator-pane").style.display = tab === "creator" ? "block" : "none";
  document.getElementById("viewer-pane").style.display  = tab === "viewer"  ? "block" : "none";
}

// ── Settings button ───────────────────────────────────────────────────────
document.getElementById("settings-btn").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});
document.getElementById("creator-goto-settings")?.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

// ── Origin button selection ───────────────────────────────────────────────
document.querySelectorAll("#popup-origin-btns .origin-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#popup-origin-btns .origin-btn").forEach(b => {
      b.className = "origin-btn";
    });
    selectedOrigin = btn.dataset.code;
    btn.classList.add(`selected-${selectedOrigin}`);
    const hint = document.getElementById("popup-origin-hint");
    if (hint) { hint.textContent = ORIGIN_HINTS[selectedOrigin]; hint.style.display="block"; }
    const regBtn = document.getElementById("popup-register-btn");
    if (regBtn) {
      regBtn.disabled = false;
      regBtn.innerHTML = `
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
          stroke-width="2.5" stroke-linecap="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        Register as ${selectedOrigin} - ${ORIGIN_LABELS[selectedOrigin]}
      `;
    }
  });
});

// ── Register button ───────────────────────────────────────────────────────
document.getElementById("popup-register-btn")?.addEventListener("click", async () => {
  if (!selectedOrigin) return;
  const password = document.getElementById("popup-password").value;
  const title    = document.getElementById("manual-title").value.trim();
  const content  = document.getElementById("manual-content").value.trim();
  if (!password) { showStatus("creator-status","error","Enter your signing password."); return; }
  if (!content && !title) { showStatus("creator-status","error","Add some content to register."); return; }

  const btn = document.getElementById("popup-register-btn");
  btn.disabled = true;
  btn.innerHTML = "⏳ Registering...";
  showStatus("creator-status","info","Hashing and signing your content...");

  const res = await msg("REGISTER_CONTENT", { payload: { originCode: selectedOrigin, content: content||title, title, password } });

  if (res?.ok && res.data?.ctid) {
    currentCTID = res.data.ctid;
    setText("popup-ctid-display", currentCTID);
    hide("creator-manual-form");
    show("creator-success");
    showStatus("creator-status","","");
    navigator.clipboard?.writeText(currentCTID).catch(()=>{});
  } else {
    showStatus("creator-status","error", res?.error || "Registration failed. Check Settings → TIP Node connection.");
    btn.disabled = false;
    btn.innerHTML = `Register as ${selectedOrigin} - ${ORIGIN_LABELS[selectedOrigin]}`;
  }
});

// ── Copy CTID ─────────────────────────────────────────────────────────────
document.getElementById("popup-copy-ctid")?.addEventListener("click", () => {
  navigator.clipboard.writeText(currentCTID).then(() => {
    const btn = document.getElementById("popup-copy-ctid");
    btn.textContent = "✓ Copied!";
    setTimeout(() => { btn.textContent = "📋 Copy CTID to clipboard"; }, 2000);
  });
});

// ── Register another ──────────────────────────────────────────────────────
document.getElementById("popup-register-another")?.addEventListener("click", () => {
  hide("creator-success");
  show("creator-manual-form");
  selectedOrigin = null;
  document.getElementById("popup-password").value = "";
  document.getElementById("manual-title").value = "";
  document.getElementById("manual-content").value = "";
  document.querySelectorAll("#popup-origin-btns .origin-btn").forEach(b => b.className = "origin-btn");
  document.getElementById("popup-origin-hint").style.display = "none";
  const btn = document.getElementById("popup-register-btn");
  btn.disabled = true;
  btn.innerHTML = `
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    Select an origin code to continue
  `;
});

// ── Load viewer data ──────────────────────────────────────────────────────
async function loadViewerData(tab) {
  const r = await msg("GET_TAB_DATA", { tabId: tab.id });
  const data = r?.data;
  if (!data?.tipAuthor) { show("viewer-no-tip"); return; }
  show("viewer-tip-data");

  // Fetch full identity
  const identity = await msg("FETCH_IDENTITY", { tipId: data.tipAuthor });
  const idata = identity?.data;
  const score = idata?.score || data.tipScore || 0;
  const tier  = idata?.tier?.label || tierLabel(score);
  const c     = tierColor(score);

  setHTML("viewer-shield", shieldSVG(score, 44));
  setHTML("viewer-tier-badge", tier);
  const tierEl = document.getElementById("viewer-tier-badge");
  if (tierEl) { tierEl.style.background = `${c}15`; tierEl.style.color = c; }
  setText("viewer-score-text", `Score: ${score} / 1000`);
  setText("viewer-tip-id", data.tipAuthor);
  const fillEl = document.getElementById("viewer-score-fill");
  if (fillEl) { fillEl.style.width = `${score/10}%`; fillEl.style.background = c; }

  // Revocation check
  const revRes = await msg("IS_REVOKED", { tipId: data.tipAuthor });
  if (revRes?.revoked) show("viewer-revoked-warning");

  // Content record
  if (data.tipContent) {
    show("viewer-content-section");
    const originCode = data.tipOrigin
      ? data.tipOrigin.toUpperCase().replace("ORIGINAL-HUMAN","OH")
          .replace("AI-ASSISTED","AA").replace("AI-GENERATED","AG").replace("MIXED","MX").slice(0,2)
      : null;
    if (originCode) setHTML("viewer-origin-pill", originPillHTML(originCode));
    setText("viewer-ctid", data.tipContent);
    const statusEl = document.getElementById("viewer-content-status");
    if (statusEl) {
      statusEl.textContent = "Verified";
      statusEl.style.background = "#1A8A5C15";
      statusEl.style.color = "#1A8A5C";
    }
    const link = document.getElementById("viewer-verify-link");
    if (link) link.href = `https://vp.theailab.org/verify-record/${encodeURIComponent(data.tipContent)}`;
  }
}

// ── Node health indicator ─────────────────────────────────────────────────
async function checkNode() {
  const res = await msg("NODE_HEALTH");
  const dot = document.getElementById("node-status");
  if (dot) dot.style.background = res?.ok ? "#1A8A5C" : "#C53030";
  if (dot) dot.title = res?.ok ? `TIP Node online - ${res.data?.dag_count || 0} transactions` : "TIP Node offline";
}

// ── Main init ─────────────────────────────────────────────────────────────
async function init() {
  console.log("init calledd.....")
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  console.log(tab, "I am here")
  if (!tab) { hide("loading-state"); return; }

  hide("loading-state");

  // Check identity
  const idRes = await msg("GET_IDENTITY");
  const hasId = idRes?.ok && idRes.data?.setupComplete;

  // Creator tab setup
  if (!hasId) {
    show("creator-no-id");
  } else {
    // Check if on an upload page
    const platform = await msg("DETECT_PLATFORM", { url: tab.url });
    if (platform?.platform) {
      show("creator-upload-detected");
      setText("creator-tipid-upload", idRes.data.tipId || "");
    } else {
      show("creator-manual-form");
      setText("creator-tipid-manual", idRes.data.tipId || "");
    }
  }

  // Viewer tab setup
  await loadViewerData(tab);
  checkNode();

  // Show the active tab pane
  switchTab(activeTab);
}

// Show creator by default for upload pages, viewer otherwise
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (!tab) return;
  const isUpload = /studio\.youtube\.com|youtube\.com\/upload|instagram\.com\/(create|reels)|tiktok\.com\/upload|twitter\.com\/compose|x\.com\/compose|substack\.com\/publish|medium\.com\/new-story/.test(tab.url || "");
  if (isUpload) switchTab("creator");
});

init();
