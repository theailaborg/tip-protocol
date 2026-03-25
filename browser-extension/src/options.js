"use strict";

// ── FAQ data ──────────────────────────────────────────────────────────────────
const FAQS = [
  { q: "Is my private key sent to any server?", a: "No. Your private key is encrypted with AES-256-GCM using a key derived from your password via PBKDF2. Only the encrypted ciphertext is stored on this device. The TIP node receives only a cryptographic signature — it cannot reverse-engineer your private key from it." },
  { q: "What is a CTID and where do I put it?", a: "A CTID (Content Transaction ID) is a permanent URI like tip://c/OH-7f2a91bc3d5e4a-a3f8. It identifies your content on the TIP DAG. Paste it anywhere in your content: video description, article footer, post caption. Viewers with the TIP extension see it as a clickable verification link. Viewers without the extension can go to theailab.org/verify/[ctid] to verify manually." },
  { q: "What if I pick OH but my content is actually AI-generated?", a: "The TIP node runs an AI pre-scan calibrated to your creator history. If you declare OH but the AI classifier detects probable AI generation, your trust score decreases: -100 for a first offense, up to -350 for repeated offenses. Over-declaring AI involvement (e.g. declaring AA when it's actually OH) carries zero penalty. When in doubt, declare conservatively." },
  { q: "What happens if the platform already supports TIP natively?", a: "The extension automatically detects TIP-* HTTP headers in the platform's responses. Once those headers are present, the extension reads them instead of using the creator panel. The registration panel hides itself. You don't need to do anything — it transitions seamlessly." },
  { q: "Does the extension work on mobile browsers?", a: "Chrome and Firefox browser extensions are desktop-only. Mobile browser extensions are not currently supported by Chrome for Android or Safari for iOS. Platforms implementing TIP natively will provide the mobile experience." },
  { q: "What is the difference between TIP-ID and a CTID?", a: "Your TIP-ID (tip://id/US-...) is your identity — it represents you as a verified person. It stays the same forever. A CTID (tip://c/OH-...) is a content record — it represents one specific piece of content you registered. You have one TIP-ID and as many CTIDs as pieces of content you register." },
  { q: "What does the '+' badge on the extension icon mean?", a: "The gold '+' badge appears when you are on an upload page (YouTube Studio, TikTok, Instagram, etc.). It indicates the TIP creator panel has been injected and is ready for you to register your content." },
  { q: "Can I use the extension without a TIP-ID?", a: "Yes, for viewer mode. You can see trust badges on any page that has TIP headers or meta tags, verify CTIDs, and scan pages for TIP data — all without a TIP-ID. You only need a TIP-ID to register your own content." },
  { q: "How do I get a TIP-ID?", a: "Apply at theailab.org/get-verified. A Verification Provider (VP) runs you through biometric verification: government ID scan, 3D liveness check, and device biometric binding. Takes about 5 minutes. You receive your TIP-ID and private key at the end." },
  { q: "Is this free?", a: "Yes. The TIP extension is free. Getting a TIP-ID through an accredited VP is free for individuals. Commercial platforms building TIP into their products may require a commercial license above $500K annual revenue, but end users and creators are always free." },
];

// ── Build FAQ list ─────────────────────────────────────────────────────────────
const faqContainer = document.getElementById("faq-list");
FAQS.forEach(({ q, a }) => {
  const el = document.createElement("details");
  el.style.cssText = "margin-bottom:8px;background:#FFF;border:1px solid #E2E6EE;border-radius:10px;overflow:hidden;";
  el.innerHTML = `
    <summary style="padding:14px 18px;cursor:pointer;font-size:13px;font-weight:600;
      color:#0C1A3A;list-style:none;display:flex;justify-content:space-between;
      align-items:center;user-select:none;">
      ${q}
      <span style="color:#B8942E;font-size:16px;flex-shrink:0;margin-left:10px;">+</span>
    </summary>
    <div style="padding:0 18px 14px;font-size:12px;color:#4A5568;line-height:1.7;border-top:1px solid #F1F3F7;">${a}</div>
  `;
  el.addEventListener("toggle", () => {
    el.querySelector("summary span").textContent = el.open ? "−" : "+";
  });
  faqContainer.appendChild(el);
});

// ── Toast helper ───────────────────────────────────────────────────────────────
function toast(msg, duration = 2500) {
  const el = document.getElementById("toast");
  el.textContent = msg; el.style.display = "block";
  setTimeout(() => { el.style.display = "none"; }, duration);
}

// ── Navigation ─────────────────────────────────────────────────────────────────
document.querySelectorAll(".nav-item").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("pane-" + btn.dataset.pane).classList.add("active");
  });
});

// ── Password strength indicator ────────────────────────────────────────────────
window.updateStrength = function(val) {
  let score = 0;
  if (val.length >= 8)  score++;
  if (val.length >= 12) score++;
  if (/[A-Z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;
  const fills = ["#C53030","#C07318","#A88B15","#2563A8","#1A8A5C"];
  const labels = ["Very weak","Weak","Moderate","Strong","Very strong"];
  const fill = document.getElementById("strength-fill");
  const label = document.getElementById("strength-label");
  fill.style.width = `${score * 20}%`;
  fill.style.background = fills[score - 1] || "#E2E6EE";
  if (label) label.textContent = score > 0 ? labels[score - 1] : "Choose a password to encrypt your signing key.";
};

// ── Message helper ─────────────────────────────────────────────────────────────
function msg(type, payload = {}) {
  return new Promise(r => chrome.runtime.sendMessage({ type, ...payload }, r));
}

// ── Load identity state ────────────────────────────────────────────────────────
async function loadIdentity() {
  const res = await msg("GET_IDENTITY");
  if (res?.ok && res.data?.setupComplete) {
    document.getElementById("no-identity").style.display = "none";
    document.getElementById("has-identity").style.display = "block";
    document.getElementById("display-tipid").textContent = res.data.tipId || "";
    const date = res.data.setupDate ? new Date(res.data.setupDate).toLocaleDateString() : "";
    document.getElementById("display-setup-date").textContent = `Connected ${date}`;
    document.getElementById("pubkey-display").textContent = res.data.publicKey || "(key is stored encrypted)";

    // Fetch live score
    if (res.data.tipId) {
      const scoreRes = await msg("FETCH_IDENTITY", { tipId: res.data.tipId });
      if (scoreRes?.ok && scoreRes.data) {
        const score = scoreRes.data.score || 500;
        const tier  = scoreRes.data.tier?.label || "TRUSTED";
        const c     = score>=800?"#1A8A5C":score>=600?"#2563A8":score>=400?"#A88B15":score>=200?"#C07318":"#C53030";
        document.getElementById("score-card").style.display = "block";
        document.getElementById("score-shield").innerHTML = `
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
            <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z"
              fill="${c}15" stroke="${c}" stroke-width="2"/>
            ${score>=600
              ? `<path d="M16 24L22 30L34 18" stroke="${c}" stroke-width="3" stroke-linecap="round"/>`
              : `<text x="24" y="29" text-anchor="middle" fill="${c}" font-size="16" font-weight="bold">!</text>`}
          </svg>`;
        document.getElementById("score-tier").style.color = c;
        document.getElementById("score-tier").textContent = tier.replace(/_/g," ");
        document.getElementById("score-num").textContent = `Score: ${score} / 1000`;
      }
    }
  } else {
    document.getElementById("no-identity").style.display = "block";
    document.getElementById("has-identity").style.display = "none";
  }
}

// ── Connect TIP-ID ─────────────────────────────────────────────────────────────
document.getElementById("setup-save-btn").addEventListener("click", async () => {
  const tipId    = document.getElementById("setup-tipid").value.trim();
  const privKey  = document.getElementById("setup-privkey").value.trim();
  const password = document.getElementById("setup-password").value;
  const confirm  = document.getElementById("setup-password-confirm").value;
  const errEl    = document.getElementById("setup-error");

  errEl.style.display = "none";
  if (!tipId)    { errEl.textContent = "TIP-ID is required."; errEl.style.display = "block"; return; }
  if (!tipId.startsWith("tip://id/")) { errEl.textContent = 'TIP-ID must start with "tip://id/".'; errEl.style.display="block"; return; }
  if (!privKey)  { errEl.textContent = "Private key is required."; errEl.style.display = "block"; return; }
  if (!password) { errEl.textContent = "Password is required."; errEl.style.display = "block"; return; }
  if (password !== confirm) { errEl.textContent = "Passwords do not match."; errEl.style.display = "block"; return; }
  if (password.length < 8)  { errEl.textContent = "Password must be at least 8 characters."; errEl.style.display = "block"; return; }

  document.getElementById("setup-save-btn").textContent = "Saving...";
  document.getElementById("setup-save-btn").disabled = true;

  const res = await msg("SETUP_IDENTITY", { payload: { tipId, existingPrivateKey: privKey, password } });
  if (res?.ok) {
    toast("✓ TIP-ID connected successfully!");
    loadIdentity();
  } else {
    errEl.textContent = res?.error || "Failed to save. Try again.";
    errEl.style.display = "block";
    document.getElementById("setup-save-btn").textContent = "Connect TIP-ID";
    document.getElementById("setup-save-btn").disabled = false;
  }
});

// ── Generate keypair ───────────────────────────────────────────────────────────
document.getElementById("generate-keypair-btn").addEventListener("click", async () => {
  const password = document.getElementById("setup-password").value;
  const confirm  = document.getElementById("setup-password-confirm").value;
  const errEl    = document.getElementById("setup-error");

  if (!password || password !== confirm || password.length < 8) {
    errEl.textContent = "Set a valid password (min 8 chars, must match) before generating a keypair.";
    errEl.style.display = "block";
    return;
  }
  errEl.style.display = "none";
  document.getElementById("generate-keypair-btn").textContent = "Generating...";

  const res = await msg("SETUP_IDENTITY", { payload: { tipId: "", password } });
  if (res?.ok) {
    document.getElementById("setup-tipid").value = res.data?.tipId || "(pending VP registration)";
    toast("✓ Keypair generated. Complete VP registration to get your TIP-ID.");
    loadIdentity();
  }
  document.getElementById("generate-keypair-btn").textContent = "Generate new keypair";
});

// ── Disconnect ─────────────────────────────────────────────────────────────────
document.getElementById("disconnect-btn").addEventListener("click", async () => {
  if (!confirm("Disconnect your TIP-ID? You will need to re-enter your private key to reconnect.")) return;
  await msg("CLEAR_IDENTITY");
  toast("✓ TIP-ID disconnected.");
  loadIdentity();
});

// ── Refresh score ──────────────────────────────────────────────────────────────
document.getElementById("refresh-score-btn").addEventListener("click", () => loadIdentity());

// ── Change password ────────────────────────────────────────────────────────────
document.getElementById("change-password-btn").addEventListener("click", () => {
  document.getElementById("change-password-card").style.display = "block";
});
document.getElementById("cp-cancel-btn").addEventListener("click", () => {
  document.getElementById("change-password-card").style.display = "none";
});
document.getElementById("cp-save-btn").addEventListener("click", async () => {
  const current = document.getElementById("cp-current").value;
  const next    = document.getElementById("cp-new").value;
  const confirm = document.getElementById("cp-confirm").value;
  const errEl   = document.getElementById("cp-error");

  if (!current || !next || !confirm) { errEl.textContent = "All fields required."; errEl.style.display="block"; return; }
  if (next !== confirm) { errEl.textContent = "New passwords do not match."; errEl.style.display="block"; return; }
  if (next.length < 8)  { errEl.textContent = "Password must be at least 8 characters."; errEl.style.display="block"; return; }

  // Re-encrypt: decrypt with old password, encrypt with new
  const stored = await chrome.storage.local.get(["encryptedKey", "tipId", "publicKey"]);
  if (!stored.encryptedKey) { errEl.textContent = "No key found."; errEl.style.display="block"; return; }

  const res = await msg("SETUP_IDENTITY", { payload: {
    tipId:               stored.tipId,
    password:            next,
    existingPrivateKey:  "__RE_ENCRYPT__" + current + "__" + stored.encryptedKey,
  }});
  if (res?.ok) {
    document.getElementById("change-password-card").style.display = "none";
    toast("✓ Password updated successfully.");
  } else {
    errEl.textContent = res?.error || "Failed. Check your current password.";
    errEl.style.display = "block";
  }
});

// ── Copy public key ────────────────────────────────────────────────────────────
document.getElementById("copy-pubkey-btn").addEventListener("click", () => {
  const text = document.getElementById("pubkey-display").textContent;
  navigator.clipboard?.writeText(text).then(() => toast("✓ Public key copied!"));
});

// ── Node settings ──────────────────────────────────────────────────────────────
chrome.storage.sync.get(["nodeUrl"]).then(s => {
  document.getElementById("node-url").value = s.nodeUrl || "https://node.theailab.org";
});

document.getElementById("save-node-btn").addEventListener("click", async () => {
  const url = document.getElementById("node-url").value.trim().replace(/\/$/, "");
  await chrome.storage.sync.set({ nodeUrl: url });
  toast("✓ Node URL saved.");
});

document.getElementById("test-node-btn").addEventListener("click", async () => {
  const resultEl = document.getElementById("node-test-result");
  resultEl.style.display = "block";
  resultEl.innerHTML = `<div class="alert alert-info">Testing connection...</div>`;
  const res = await msg("NODE_HEALTH");
  if (res?.ok && res.data) {
    resultEl.innerHTML = `<div class="alert alert-success">
      <strong>✓ Connected</strong><br>
      Version: ${res.data.version || "—"} &nbsp;·&nbsp;
      Chain: ${res.data.chain_id || "—"} &nbsp;·&nbsp;
      DAG: ${res.data.dag_count || 0} transactions
    </div>`;
  } else {
    resultEl.innerHTML = `<div class="alert alert-danger">
      <strong>✗ Could not connect</strong><br>
      ${res?.error || "Node is offline or URL is incorrect."}
    </div>`;
  }
});

// ── Node status ────────────────────────────────────────────────────────────────
async function loadNodeStatus() {
  const res = await msg("NODE_HEALTH");
  const el  = document.getElementById("node-status-detail");
  if (res?.ok && res.data) {
    el.innerHTML = `
      <div class="status-row" style="margin-bottom:8px;">
        <span class="status-dot" style="background:#1A8A5C;"></span>
        <span style="color:#1A8A5C;font-weight:600;">Online</span>
      </div>
      <div style="font-size:11px;color:#8895A7;line-height:1.7;">
        Version: <strong>${res.data.version||"—"}</strong><br>
        Chain ID: <strong>${res.data.chain_id||"—"}</strong><br>
        DAG transactions: <strong>${res.data.dag_count||0}</strong><br>
        Identity count: <strong>${res.data.identity_count||0}</strong>
      </div>`;
  } else {
    el.innerHTML = `
      <div class="status-row">
        <span class="status-dot" style="background:#C53030;"></span>
        <span style="color:#C53030;font-weight:600;">Offline</span>
      </div>
      <div style="font-size:11px;color:#8895A7;margin-top:6px;">
        The TIP node is not responding. Content registration will not work.
        Check the node URL or ensure the node is running.
      </div>`;
  }
}

// ── Init ───────────────────────────────────────────────────────────────────────
loadIdentity();
loadNodeStatus();
