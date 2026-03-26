"use strict";

// ── WebAuthn helpers ──────────────────────────────────────────────────────────
// RP ID: window.location.hostname resolves to the extension ID in Chrome
// extension pages (chrome-extension://[id]/options.html), which is a valid
// WebAuthn RP ID for credentials scoped to this extension.
const WA_RP_ID = window.location.hostname || "theailab.org";

function _waRandomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}
function _waBufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function _waB64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

function isWebAuthnSupported() {
  return !!(window.PublicKeyCredential && navigator.credentials?.create);
}
async function isPlatformAuthenticatorAvailable() {
  if (!isWebAuthnSupported()) return false;
  try { return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); }
  catch { return false; }
}

/**
 * Create a new passkey.
 * No authenticatorAttachment restriction — the OS shows ALL options:
 * Face ID / Touch ID, Windows Hello, AND "Use a phone / security key" (QR code).
 */
async function webAuthnRegister(userId, displayName) {
  const cred = await navigator.credentials.create({ publicKey: {
    challenge:   _waRandomBytes(32),
    rp:          { id: WA_RP_ID, name: "TIP Protocol — The AI Lab" },
    user:        { id: new TextEncoder().encode(userId), name: userId, displayName: displayName || "TIP Creator" },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
    authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
    timeout:     120000,
    attestation: "none",
  }});
  return { credentialId: _waBufToB64(cred.rawId) };
}

async function webAuthnAuthenticate(credentialId) {
  const allowCreds = credentialId ? [{ id: _waB64ToBuf(credentialId), type: "public-key" }] : [];
  const assertion  = await navigator.credentials.get({ publicKey: {
    challenge:        _waRandomBytes(32),
    rpId:             WA_RP_ID,
    userVerification: "required",
    allowCredentials: allowCreds,
    timeout:          120000,
  }});
  return {
    authenticatorData: new Uint8Array(assertion.response.authenticatorData),
    signature:         new Uint8Array(assertion.response.signature),
  };
}

async function _waKey(auth, salt, usage) {
  const bytes = new Uint8Array([...auth.authenticatorData, ...auth.signature]);
  const km    = await crypto.subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, [usage]
  );
}

async function encryptKeyWithWebAuthn(privKeyHex, credentialId) {
  const auth = await webAuthnAuthenticate(credentialId);
  const salt = _waRandomBytes(16), iv = _waRandomBytes(12);
  const key  = await _waKey(auth, salt, "encrypt");
  const ct   = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(privKeyHex));
  const out  = new Uint8Array(16 + 12 + ct.byteLength);
  out.set(salt, 0); out.set(iv, 16); out.set(new Uint8Array(ct), 28);
  return btoa(String.fromCharCode(...out));
}

async function decryptKeyWithWebAuthn(encB64, credentialId) {
  const auth = await webAuthnAuthenticate(credentialId);
  const d    = Uint8Array.from(atob(encB64), c => c.charCodeAt(0));
  const key  = await _waKey(auth, d.slice(0, 16), "decrypt");
  const pt   = await crypto.subtle.decrypt({ name: "AES-GCM", iv: d.slice(16, 28) }, key, d.slice(28));
  return new TextDecoder().decode(pt);
}

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
    const secEl = document.getElementById("display-security-method");
    if (secEl) {
      const isWA = res.data.securityMethod === "webauthn";
      secEl.textContent = isWA ? "✓ Key secured with passkey" : "✓ Key secured with AES-256-GCM";
    }

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

// ── Setup step helpers ────────────────────────────────────────────────────────

// Temp store: private key passes from step 1 → step 2 in memory only (never stored raw)
let _tmpPrivKey = null;
let _tmpPubKey  = null;

function goSetupStep(step) {
  document.getElementById("ss1").style.display = step === 1 ? "block" : "none";
  document.getElementById("ss2").style.display = step === 2 ? "block" : "none";
  // Update step indicators
  document.getElementById("sp1").style.background = step >= 1 ? "#B8942E" : "#E2E6EE";
  document.getElementById("sp1").style.color      = step >= 1 ? "#fff"    : "#8895A7";
  document.getElementById("sp2").style.background = step >= 2 ? "#B8942E" : "#E2E6EE";
  document.getElementById("sp2").style.color      = step >= 2 ? "#fff"    : "#8895A7";
  document.getElementById("sl1").style.background = step >= 2 ? "#B8942E" : "#E2E6EE";
}

function showSetupErr(text) {
  const el = document.getElementById("setup-error");
  el.textContent = text; el.style.display = text ? "block" : "none";
}
function showStep2Err(text) {
  const el = document.getElementById("s2-err");
  el.textContent = text; el.style.display = text ? "block" : "none";
}

// Check passkey availability on load
(async () => {
  if (!isWebAuthnSupported()) {
    document.getElementById("ss2-wa").style.opacity = "0.5";
    document.getElementById("s2-wa-btn").disabled = true;
    document.getElementById("wa-unavailable").style.display = "block";
  }
})();

// ── Step 1 → "Continue" ───────────────────────────────────────────────────────
document.getElementById("s1-next").addEventListener("click", () => {
  const tipId   = document.getElementById("setup-tipid").value.trim();
  const privKey = document.getElementById("setup-privkey").value.trim();
  showSetupErr("");
  if (!tipId)   { showSetupErr("TIP-ID is required."); return; }
  if (!tipId.startsWith("tip://id/")) { showSetupErr('TIP-ID must start with "tip://id/".'); return; }
  if (!privKey) { showSetupErr("Private key is required."); return; }
  _tmpPrivKey = privKey;
  _tmpPubKey  = null;  // public key not needed for password path; set for generated keys
  goSetupStep(2);
});

// ── Step 1 → "Generate a test keypair" (s1-gen equivalent) ───────────────────
document.getElementById("generate-keypair-btn").addEventListener("click", async () => {
  const btn = document.getElementById("generate-keypair-btn");
  btn.textContent = "Generating…"; btn.disabled = true;
  showSetupErr("");
  try {
    // Generate keypair via background (crypto.js)
    const kpRes = await msg("GENERATE_KEYPAIR");
    if (!kpRes?.ok) throw new Error(kpRes?.error || "Keypair generation failed.");
    const { privateKey, publicKey } = kpRes.data;

    // Compute TIP-ID from public key
    const tidRes = await msg("COMPUTE_TIP_ID", { region: "US", publicKey });
    const tipId  = tidRes?.ok ? tidRes.data : null;

    // Fill both fields — exactly like s1-gen in standalone.html
    document.getElementById("setup-tipid").value   = tipId  || "(pending VP registration)";
    document.getElementById("setup-privkey").value = privateKey;

    // Keep in memory for step 2
    _tmpPrivKey = privateKey;
    _tmpPubKey  = publicKey;

    toast("✓ Test keypair generated. Devnet use only.");
    btn.textContent = "✓ Generated";
  } catch (e) {
    showSetupErr("Failed: " + e.message);
    btn.textContent = "Generate a test keypair (devnet only) →";
  } finally {
    btn.disabled = false;
  }
});

// ── Step 2 → Back ─────────────────────────────────────────────────────────────
document.getElementById("s2-back-btn").addEventListener("click", () => {
  _tmpPrivKey = null; _tmpPubKey = null;
  showStep2Err("");
  goSetupStep(1);
});

// ── Step 2 → WebAuthn ("Use Face ID / Fingerprint") ──────────────────────────
document.getElementById("s2-wa-btn").addEventListener("click", async () => {
  const btn   = document.getElementById("s2-wa-btn");
  const tipId = document.getElementById("setup-tipid").value.trim();
  btn.textContent = "Waiting for passkey…"; btn.disabled = true;
  showStep2Err("");
  try {
    const privKey = _tmpPrivKey;
    if (!privKey) throw new Error("No private key in memory. Go back to step 1.");

    // Register WebAuthn credential — browser shows native OS dialog here
    // (Face ID / Touch ID / "Use a phone, tablet or security key" QR code)
    const { credentialId } = await webAuthnRegister(tipId, "TIP Creator");

    btn.textContent = "Encrypting key…";
    const encryptedKey = await encryptKeyWithWebAuthn(privKey, credentialId);
    _tmpPrivKey = null;  // clear from memory immediately after encryption

    const publicKey = _tmpPubKey || "imported";
    const res = await msg("SETUP_IDENTITY_WEBAUTHN", {
      payload: { tipId, publicKey, encryptedKey, credentialId },
    });
    if (!res?.ok) throw new Error(res?.error || "Failed to save.");
    toast("✓ Passkey registered! Your TIP-ID is connected.");
    loadIdentity();
  } catch (e) {
    _tmpPrivKey = null;
    const m = e.name === "NotAllowedError" ? "Passkey cancelled. Try again." : e.message;
    showStep2Err(m);
  } finally {
    btn.textContent = "Use Face ID / Fingerprint"; btn.disabled = false;
  }
});

// ── Step 2 → Password ("Use Password") ───────────────────────────────────────
document.getElementById("setup-save-btn").addEventListener("click", async () => {
  const tipId    = document.getElementById("setup-tipid").value.trim();
  const password = document.getElementById("setup-password").value;
  const confirm  = document.getElementById("setup-password-confirm").value;
  const btn      = document.getElementById("setup-save-btn");
  showStep2Err("");

  if (!password)            { showStep2Err("Password is required."); return; }
  if (password.length < 8)  { showStep2Err("Password must be at least 8 characters."); return; }
  if (password !== confirm)  { showStep2Err("Passwords do not match."); return; }

  btn.textContent = "Saving…"; btn.disabled = true;
  try {
    const privKey   = _tmpPrivKey;
    if (!privKey) throw new Error("No private key in memory. Go back to step 1.");
    const publicKey = _tmpPubKey || "imported";
    _tmpPrivKey = null;  // clear before async call

    const res = await msg("SETUP_IDENTITY", {
      payload: { tipId, existingPrivateKey: privKey, password, publicKey },
    });
    if (!res?.ok) throw new Error(res?.error || "Failed to save. Try again.");
    toast("✓ TIP-ID connected successfully!");
    loadIdentity();
  } catch (e) {
    _tmpPrivKey = null;
    showStep2Err(e.message);
    btn.textContent = "Use Password"; btn.disabled = false;
  }
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
