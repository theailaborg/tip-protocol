"use strict";

// ── WebAuthn helpers ──────────────────────────────────────────────────────────
// RP ID: window.location.hostname resolves to the extension ID in Chrome
// extension pages (chrome-extension://[id]/options.html), which is a valid
// WebAuthn RP ID for credentials scoped to this extension.
import { TIP_WEBAUTHN_RP_ID } from "./config.js";
const WA_RP_ID = TIP_WEBAUTHN_RP_ID;

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
 * No authenticatorAttachment restriction - the OS shows ALL options:
 * Face ID / Touch ID, Windows Hello, AND "Use a phone / security key" (QR code).
 */
async function webAuthnRegister(userId, displayName) {
  const cred = await navigator.credentials.create({ publicKey: {
    challenge:   _waRandomBytes(32),
    rp:          { id: WA_RP_ID, name: "TIP Protocol - The AI Lab" },
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

// Key derivation: 3-layer architecture for ML-DSA-65 private key protection.
//
// Path A (Chrome/Edge 116+): WebAuthn PRF extension.
//   SHAKE-256(PRF_output || "tip-pqc-key-wrap")[:32] -> AES-256-GCM key.
//   Hardware-bound: PRF secret only released after biometric.
//
// Path B (Safari, Firefox, older Chrome): Fallback.
//   SHAKE-256(credentialId || "tip-pqc-key-wrap")[:32] -> PBKDF2 200k -> AES-256-GCM key.
//   Software-gated: biometric credentials.get() required before derivation.
//
// Both paths use AAD = tipId to bind ciphertext to the identity.
// v2 format: magic("TIP2",4) + salt(16) + iv(12) + aadLen(2 LE) + aad + methodByte(1) + ciphertext

// 4-byte magic header for v2 format (same as crypto.js). Collision probability: 1/2^32.
const _WA_V2_MAGIC = new Uint8Array([0x54, 0x49, 0x50, 0x32]); // ASCII "TIP2"
function _waIsV2(d) { return d.length >= 4 && d[0]===0x54 && d[1]===0x49 && d[2]===0x50 && d[3]===0x32; }
const _WA_KDF_DOMAIN = "tip-pqc-key-wrap";
const _WA_METHOD_PRF = 0x01;
const _WA_METHOD_FALLBACK = 0x02;

// Legacy v1 key derivation (kept for backward compat with pre-v2 stored keys)
async function _waKey(credBytes, salt, usage) {
  const km = await crypto.subtle.importKey("raw", credBytes, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, [usage]
  );
}

/**
 * Compute SHAKE-256(input || "tip-pqc-key-wrap")[:32] via background worker.
 * Retries once if messaging fails (extension startup race). Throws on failure
 * instead of silently falling back to SHA-256 (which produces different output).
 */
async function _waKdfHash(inputBytes) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(
          { type: "KDF_HASH", input: Array.from(inputBytes) },
          (response) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(response);
            }
          }
        );
      });
      if (res?.ok && res.data) return new Uint8Array(res.data);
    } catch {
      // First attempt failed (service worker starting up), wait and retry
      if (attempt === 0) await new Promise(r => setTimeout(r, 500));
    }
  }
  throw new Error("Cannot compute SHAKE-256 hash. Extension background worker is not responding. Please reload the extension.");
}

/**
 * Path A: Derive AES key from Secure Enclave via WebAuthn PRF extension.
 * Returns { aesKey, method: _WA_METHOD_PRF } or null if PRF is not supported.
 * Throws if PRF succeeds but downstream hash computation fails (do not silently downgrade).
 */
async function _deriveKeyViaPRF(credentialIdBuf, usage) {
  // Step 1: Attempt PRF assertion. If the browser doesn't support PRF,
  // the assertion succeeds but getClientExtensionResults().prf is absent.
  let assertion;
  try {
    const prfSalt = new TextEncoder().encode(_WA_KDF_DOMAIN);
    assertion = await navigator.credentials.get({ publicKey: {
      challenge:        _waRandomBytes(32),
      rpId:             WA_RP_ID,
      allowCredentials: [{ id: credentialIdBuf, type: "public-key" }],
      userVerification: "required",
      timeout:          60000,
      extensions:       { prf: { eval: { first: prfSalt } } }
    }});
  } catch (e) {
    if (e.name === "NotAllowedError") throw e; // user cancelled, do not swallow
    return null; // credential not found, authenticator error, etc.
  }

  const prfResults = assertion.getClientExtensionResults()?.prf?.results;
  if (!prfResults?.first) return null; // PRF extension not supported by this browser/authenticator

  // Step 2: PRF succeeded. From here, errors must propagate (not silently downgrade).
  // If SHAKE-256 fails, the user should see a clear error, not lose hardware protection.
  const prfOutput = new Uint8Array(prfResults.first);
  const keyBytes  = await _waKdfHash(prfOutput); // throws if background worker is dead
  const aesKey    = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "AES-GCM" }, false, [usage]
  );
  return { aesKey, method: _WA_METHOD_PRF };
}

/**
 * Path B: Derive AES key from credentialId (fallback).
 * Requires biometric gate before derivation.
 * @param {ArrayBuffer} credentialIdBuf
 * @param {string} credentialIdB64
 * @param {boolean} requireBiometric
 * @param {string} usage - "encrypt" or "decrypt"
 * @param {Uint8Array} salt - 16-byte random salt for PBKDF2
 */
async function _deriveKeyFallback(credentialIdBuf, credentialIdB64, requireBiometric, usage, salt) {
  if (requireBiometric) {
    await webAuthnAuthenticate(credentialIdB64); // biometric gate
  }
  const shakeInput = await _waKdfHash(new TextEncoder().encode(credentialIdB64));
  const km = await crypto.subtle.importKey("raw", shakeInput, "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, [usage]
  );
  return { aesKey, method: _WA_METHOD_FALLBACK };
}

/**
 * Encrypt private key with WebAuthn-derived AES-256-GCM.
 * Tries PRF (hardware-bound) first, falls back to credentialId + biometric gate.
 * v2 format with AAD = tipId.
 *
 * Note: PRF path triggers a second biometric prompt after passkey registration.
 * This is architecturally required (PRF needs credentials.get(), which cannot
 * reuse the registration response). The user sees:
 *   1. Passkey registration dialog (from webAuthnRegister)
 *   2. PRF authentication dialog (from _deriveKeyViaPRF)
 * On browsers without PRF, only the registration dialog appears.
 */
async function encryptKeyWithWebAuthn(privKeyHex, credentialId, skipAuth = false) {
  const credBuf = _waB64ToBuf(credentialId);
  const tipId   = document.getElementById("setup-tipid")?.value?.trim() || "";
  const aad     = new TextEncoder().encode(tipId);

  // Generate salt and IV upfront so they can be used in derivation
  const salt = _waRandomBytes(16);
  const iv   = _waRandomBytes(12);

  // Always try PRF first (hardware-bound, Chrome/Edge 116+).
  // _deriveKeyViaPRF returns null if PRF is unsupported by this browser/authenticator.
  // It throws NotAllowedError if user cancels biometric, or throws Error if PRF
  // succeeded but SHAKE-256 computation failed (prevents silent security downgrade).
  let derived = await _deriveKeyViaPRF(credBuf, "encrypt");
  if (!derived) {
    // Fallback: use random salt in PBKDF2 (salt stored in blob for decrypt to read)
    derived = await _deriveKeyFallback(credBuf, credentialId, !skipAuth, "encrypt", salt);
  }

  const { aesKey, method } = derived;
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    aesKey,
    new TextEncoder().encode(privKeyHex)
  );

  // v2 format: magic("TIP2",4) + salt(16) + iv(12) + aadLen(2 LE) + aad + methodByte(1) + ciphertext
  const aadLen = new Uint8Array(2);
  aadLen[0] = aad.length & 0xFF;
  aadLen[1] = (aad.length >> 8) & 0xFF;

  const out = new Uint8Array(4 + 16 + 12 + 2 + aad.length + 1 + ct.byteLength);
  let off = 0;
  out.set(_WA_V2_MAGIC, off); off += 4;
  out.set(salt, off); off += 16;
  out.set(iv, off); off += 12;
  out.set(aadLen, off); off += 2;
  out.set(aad, off); off += aad.length;
  out[off++] = method;
  out.set(new Uint8Array(ct), off);

  return btoa(String.fromCharCode(...out));
}

/**
 * Decrypt private key with WebAuthn. Requires biometric authentication.
 * Auto-detects v2 (PRF/fallback + AAD) vs v1 (legacy credId + PBKDF2 200k).
 */
async function decryptKeyWithWebAuthn(encB64, credentialId) {
  const d = Uint8Array.from(atob(encB64), c => c.charCodeAt(0));
  const credBuf = _waB64ToBuf(credentialId);

  if (_waIsV2(d)) {
    // ── v2 format ──
    let off = 4; // skip magic
    const salt   = d.slice(off, off + 16); off += 16;
    const iv     = d.slice(off, off + 12); off += 12;
    const aadLen = d[off] | (d[off + 1] << 8); off += 2;
    const aad    = d.slice(off, off + aadLen); off += aadLen;
    const method = d[off++];
    const ct     = d.slice(off);

    let derived;
    if (method === _WA_METHOD_PRF) {
      // PRF derives key from hardware secret (salt not needed)
      derived = await _deriveKeyViaPRF(credBuf, "decrypt");
      if (!derived) {
        throw new Error("This key was encrypted with Secure Enclave PRF. Use the original device and Chrome/Edge 116+.");
      }
    } else {
      // Fallback: biometric gate required, pass stored salt for PBKDF2
      derived = await _deriveKeyFallback(credBuf, credentialId, true, "decrypt", salt);
    }

    const { aesKey } = derived;
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      aesKey, ct
    );
    return new TextDecoder().decode(pt);

  } else {
    // ── v1 legacy format: salt(16) + iv(12) + ciphertext ──
    await webAuthnAuthenticate(credentialId); // biometric gate
    const credBytes = new Uint8Array(credBuf);
    const key = await _waKey(credBytes, d.slice(0, 16), "decrypt");
    const pt  = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: d.slice(16, 28) }, key, d.slice(28)
    );
    return new TextDecoder().decode(pt);
  }
}

// ── FAQ data ──────────────────────────────────────────────────────────────────
const FAQS = [
  { q: "Is my private key sent to any server?", a: "No. Your private key is encrypted on this device using AES-256-GCM. On Chrome/Edge 116+, the encryption key is derived from a Secure Enclave hardware secret via WebAuthn PRF, gated by your biometrics. On other browsers, the key is derived via SHAKE-256 and PBKDF2 (200,000 rounds) from your passkey credential or password. Only the encrypted ciphertext is stored. The TIP node receives only cryptographic signatures, never key material." },
  { q: "What is a CTID and where do I put it?", a: "A CTID (Content Transaction ID) is a permanent URI like tip://c/OH-7f2a91bc3d5e4a-a3f8. It identifies your content on the TIP DAG. Paste it anywhere in your content: video description, article footer, post caption. Viewers with the TIP extension see it as a clickable verification link. Viewers without the extension can go to vp.theailab.org/verify-record/[ctid] to verify manually." },
  { q: "What do the origin codes mean (OH, AA, AG, MX)?", a: "OH (Original Human): created entirely by you without AI generation tools. Traditional tools like Photoshop, spell-check, and color grading are fine. AA (AI-Assisted): you are the primary author but used AI tools for drafting, editing, or enhancement. AG (AI-Generated): AI is the primary creator; your role was prompting, curating, or minor editing. MX (Mixed/Composite): combines human and AI elements that cannot be clearly separated." },
  { q: "What if I pick OH but my content is actually AI-generated?", a: "The TIP node runs an AI pre-scan calibrated to your creator history. If you declare OH but the AI classifier detects probable AI generation, your trust score decreases: -100 for a first offense, up to -350 for repeated offenses. Over-declaring AI involvement (e.g. declaring AA when it is actually OH) carries zero penalty. When in doubt, declare conservatively. Conservative labeling is always safe." },
  { q: "What happens if the platform already supports TIP natively?", a: "The extension automatically detects TIP-* HTTP headers in the platform's responses. Once those headers are present, the extension reads them instead of using the creator panel. The registration panel hides itself. You do not need to do anything; it transitions seamlessly." },
  { q: "Does the extension work on mobile browsers?", a: "Browser extensions are desktop-only (Chrome, Edge, Firefox). For mobile, use the TIP Mobile App (iOS and Android), which provides the same content registration and verification features with native biometric support through the Secure Enclave. You can connect your existing TIP-ID to the mobile app by scanning the QR code on the VP portal's 'Identity Verified' page." },
  { q: "What is the difference between a TIP-ID and a CTID?", a: "Your TIP-ID (tip://id/US-...) is your identity. It represents you as a verified person and stays the same forever. A CTID (tip://c/OH-...) is a content record. It represents one specific piece of content you registered. You have one TIP-ID and as many CTIDs as pieces of content you register." },
  { q: "What does the '+' badge on the extension icon mean?", a: "The gold '+' badge appears when you are on an upload page (YouTube Studio, TikTok, Instagram, etc.). It indicates the TIP creator panel has been injected and is ready for you to register your content." },
  { q: "Can I use the extension without a TIP-ID?", a: "Yes, for viewer mode. You can see trust badges on any page that has TIP headers or meta tags, verify CTIDs, and scan pages for TIP data, all without a TIP-ID. You only need a TIP-ID to register your own content." },
  { q: "How do I get a TIP-ID?", a: "Visit vp.theailab.org/get-verified. A Verification Provider (VP) runs you through biometric verification: government ID scan, 3D liveness check, and device biometric binding. Takes about 10 minutes and is free. After verification, click 'Connect Browser Plugin' on the VP page to transfer your encrypted signing key to the extension." },
  { q: "Is this free?", a: "Yes. The TIP extension is free. Getting a TIP-ID through an accredited VP is free for individuals. The TIP Protocol specification is CC-BY 4.0 (free forever). Commercial platforms building TIP into their products may require a commercial license above $500K annual revenue, but end users and creators are always free." },
  { q: "What are the trust score tiers?", a: "Highly Trusted (850-1000): strong track record, high credibility. Trusted (650-849): consistent honest labeling. Verified (400-649): new or limited history, proceed with caution. Caution (200-399): past offenses, verify independently. Not Trusted (0-199): multiple misrepresentation offenses." },
  { q: "What cryptography does TIP use?", a: "All signatures use ML-DSA-65 (Dilithium), a NIST-standardized post-quantum algorithm (FIPS 204). Hashing uses SHAKE-256 (FIPS 202). Key encryption uses AES-256-GCM. These algorithms are secure against both classical and quantum computer attacks. Your content signatures will remain valid even after large-scale quantum computers exist." },
  { q: "Which platforms are supported?", a: "The extension injects a creator panel on YouTube Studio, TikTok, Instagram, X/Twitter, Facebook, LinkedIn, Threads, Substack, Medium, WordPress, podcast platforms, and news media upload pages. Viewer mode (badge display and verification) works on any website that serves TIP headers or meta tags." },
  { q: "Can I revoke my TIP-ID?", a: "Yes. Voluntary revocation is permanent. Your TIP-ID is marked as revoked on the DAG, and no new content can be registered under it. Existing content records remain for provenance integrity. To revoke, contact your Verification Provider or use the extension settings." },
  { q: "Can I connect my TIP-ID to multiple devices?", a: "Yes. After verifying on one device (browser or mobile), you can connect the same TIP-ID to other devices. From the VP portal's 'Identity Verified' page, use the QR code (for the TIP mobile app) or the 'Connect Browser Plugin' button (for additional browser extensions). Each device creates its own Secure Enclave keypair and encrypts your signing key independently." },
  { q: "What if I lose access to my device?", a: "During verification, you receive a .tip.json backup file containing your encrypted private key. Store it securely (password manager, encrypted USB drive). If you lose your device, import the backup on a new device via the TIP mobile app or browser extension. If you did not save a backup, you will need to complete the verification process again with your VP." },
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
    if (btn.dataset.pane === "platforms") initLabelContent();
  });
});

// ── Hash routing (e.g. options.html#platforms) ────────────────────────────────
if (window.location.hash) {
  const pane = window.location.hash.slice(1);
  const btn = document.querySelector(`.nav-item[data-pane="${pane}"]`);
  if (btn) btn.click();
}

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
    const cpBtn = document.getElementById("change-password-btn");
    const sm = res.data.securityMethod || "";
    const isWAMethod = sm === "webauthn-prf" || sm === "webauthn-fallback" || sm === "webauthn";
    if (secEl) {
      if (sm === "webauthn-prf") {
        secEl.textContent = "\u2713 Key secured with Secure Enclave (PRF)";
      } else if (isWAMethod) {
        secEl.textContent = "\u2713 Key secured with passkey (biometric-gated)";
      } else {
        secEl.textContent = "\u2713 Key secured with AES-256-GCM";
      }
    }
    // Hide change-password for WebAuthn users (key is passkey-encrypted, not password-encrypted)
    if (cpBtn) cpBtn.style.display = isWAMethod ? "none" : "";

    // Fetch live score
    if (res.data.tipId) {
      const scoreRes = await msg("FETCH_IDENTITY", { tipId: res.data.tipId });
      if (scoreRes?.ok && scoreRes.data) {
        const score = scoreRes.data.score || 500;
        const tier  = scoreRes.data.tier?.label || "TRUSTED";
        const c     = score>=850?"#1A8A5C":score>=650?"#2563A8":score>=400?"#A88B15":score>=200?"#C07318":"#C53030";
        document.getElementById("score-card").style.display = "block";
        document.getElementById("score-shield").innerHTML = `
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
            <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z"
              fill="${c}15" stroke="${c}" stroke-width="2"/>
            ${score>=650
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

    // Fill both fields - exactly like s1-gen in standalone.html
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

    // Register WebAuthn credential - browser shows native OS dialog here
    // (Face ID / Touch ID / "Use a phone, tablet or security key" QR code)
    const { credentialId } = await webAuthnRegister(tipId, "TIP Creator");

    btn.textContent = "Encrypting key…";
    const encryptedKey = await encryptKeyWithWebAuthn(privKey, credentialId, true); // skip re-auth - just registered
    _tmpPrivKey = null;  // clear from memory immediately after encryption

    // Detect method from encrypted blob (v2 format has method byte)
    const encBlob = Uint8Array.from(atob(encryptedKey), c => c.charCodeAt(0));
    let securityMethod = "webauthn";
    if (_waIsV2(encBlob)) {
      // magic(4) + salt(16) + iv(12) = offset 32, aadLen at [32,33]
      const aadLen = encBlob[32] | (encBlob[33] << 8);
      const methodByte = encBlob[34 + aadLen]; // aad starts at 34, method after aad
      securityMethod = methodByte === _WA_METHOD_PRF ? "webauthn-prf" : "webauthn-fallback";
    }

    const publicKey = _tmpPubKey || "imported";

    // Build tipKey object (VP-compatible format) so widget iframe can decrypt
    const encBlob2 = Uint8Array.from(atob(encryptedKey), c => c.charCodeAt(0));
    let tipKey = { credentialId, tipId, method: securityMethod, version: 2 };
    if (_waIsV2(encBlob2)) {
      let off = 4;
      tipKey.salt = Array.from(encBlob2.slice(off, off + 16)); off += 16;
      tipKey.nonce = Array.from(encBlob2.slice(off, off + 12));
      tipKey.iv = tipKey.nonce; off += 12;
      const aadLen = encBlob2[off] | (encBlob2[off + 1] << 8); off += 2;
      off += aadLen; // skip aad
      off += 1; // skip method byte
      tipKey.data = Array.from(encBlob2.slice(off));
    }

    const res = await msg("SETUP_IDENTITY_WEBAUTHN", {
      payload: { tipId, publicKey, encryptedKey, credentialId, securityMethod, tipKey },
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
  // Save first so test uses the current field value
  const url = document.getElementById("node-url").value.trim().replace(/\/$/, "");
  await chrome.storage.sync.set({ nodeUrl: url });
  const res = await msg("NODE_HEALTH");
  if (res?.ok && res.data) {
    resultEl.innerHTML = `<div class="alert alert-success">
      <strong>✓ Connected</strong><br>
      Version: ${res.data.version || " - "} &nbsp;·&nbsp;
      Chain: ${res.data.chain_id || " - "} &nbsp;·&nbsp;
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
        Version: <strong>${res.data.version||" - "}</strong><br>
        Chain ID: <strong>${res.data.chain_id||" - "}</strong><br>
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

// ══════════════════════════════════════════════════════════════════════════════
// LABEL THE CONTENT - Platform → Type → Fields → Origin → Register
// ══════════════════════════════════════════════════════════════════════════════

const LC_PLATFORMS = [
  {id:'instagram', name:'Instagram',  bg:'#E1306C', icon:'IG', types:['photo','carousel','reel','story']},
  {id:'facebook',  name:'Facebook',   bg:'#1877F2', icon:'FB', types:['text','photo','video','audio','link']},
  {id:'twitter',   name:'X/Twitter',  bg:'#111111', icon:'X',  types:['tweet','tweet_img','tweet_vid','thread']},
  {id:'youtube',   name:'YouTube',    bg:'#FF0000', icon:'YT', types:['video']},
  {id:'tiktok',    name:'TikTok',     bg:'#010101', icon:'TT', types:['video']},
  {id:'linkedin',  name:'LinkedIn',   bg:'#0A66C2', icon:'in', types:['post','article','video','document']},
  {id:'threads',   name:'Threads',    bg:'#000000', icon:'@',  types:['text','photo','video']},
  {id:'podcast',   name:'Podcast',    bg:'#8940E8', icon:'PC', types:['audio']},
  {id:'news',      name:'News Media', bg:'#0C1A3A', icon:'NM',
   types:['news_article','photo_journalism','breaking_news','investigation','live_blog','opinion','wire_adapted','correction']},
  {id:'blog',      name:'Blog',       bg:'#0D7490', icon:'BL', types:['article']},
  {id:'other',     name:'Other',      bg:'#8895A7', icon:'…',  types:['text','photo','video','audio','article','document']},
];

const LC_TYPES = {
  photo:           {label:'Photo',          sub:'Image + caption',           fields:['url','content'],                  contentLabel:'Caption',           urlLabel:'Image URL'},
  carousel:        {label:'Carousel',       sub:'Multiple images + caption', fields:['content'],                        contentLabel:'Caption'},
  reel:            {label:'Reel / Short',   sub:'Video URL + caption',       fields:['url','content'],                  contentLabel:'Caption',           urlLabel:'Video URL'},
  story:           {label:'Story',          sub:'Image + text overlay',      fields:['content'],                        contentLabel:'Story text'},
  text:            {label:'Text post',      sub:'Written post',              fields:['content'],                        contentLabel:'Post text',         placeholder:'Write your post...'},
  video:           {label:'Video',          sub:'URL + title + description', fields:['url','title','content'],           contentLabel:'Description',       urlLabel:'Video URL'},
  audio:           {label:'Audio',          sub:'Title + show notes',        fields:['title','content'],                 contentLabel:'Show notes',        titleRequired:true},
  link:            {label:'Link + comment', sub:'URL + comment',             fields:['url','content'],                  contentLabel:'Your comment',      urlLabel:'Link URL'},
  tweet:           {label:'Tweet',          sub:'Up to 280 chars',           fields:['content'],                        contentLabel:'Tweet',             placeholder:"What's on your mind?",   limit:280},
  tweet_img:       {label:'Tweet + image',  sub:'Text + image',              fields:['url','content'],                  contentLabel:'Tweet',             urlLabel:'Image URL',   limit:280},
  tweet_vid:       {label:'Tweet + video',  sub:'Text + video URL',          fields:['url','content'],                  contentLabel:'Tweet',             urlLabel:'Video URL',   limit:280},
  thread:          {label:'Thread',         sub:'Connected posts',           fields:['thread']},
  post:            {label:'Post',           sub:'Short-form update',         fields:['content'],                        contentLabel:'Post',              placeholder:'Write your post...'},
  article:         {label:'Article',        sub:'URL + title + body',        fields:['url','title','content'],           contentLabel:'Article text',      urlLabel:'Article URL', urlHint:'Use the canonical permalink.'},
  document:        {label:'Document',       sub:'Title + description',       fields:['title','content'],                 contentLabel:'Description',       titleRequired:true},
  news_article:    {label:'News article',   sub:'Headline + URL + byline',   fields:['url','title','byline','content'],  contentLabel:'Summary / lead',    urlLabel:'Published URL',  titleLabel:'Headline'},
  photo_journalism:{label:'Photo journalism',sub:'Image + cutline',          fields:['url','title','content'],           titleLabel:'Caption / cutline',   contentLabel:'Context',    urlLabel:'Image URL'},
  breaking_news:   {label:'Breaking news',  sub:'Developing story',          fields:['url','title','byline','content'],  contentLabel:'What is confirmed', urlLabel:'Story URL',      titleLabel:'Headline'},
  investigation:   {label:'Investigation',  sub:'Long-form / series',        fields:['url','title','byline','content'],  contentLabel:'Summary of findings',urlLabel:'Published URL', titleLabel:'Headline'},
  live_blog:       {label:'Live blog',      sub:'Real-time coverage',        fields:['url','title','byline','thread'],   urlLabel:'Live blog URL',         titleLabel:'Event title'},
  opinion:         {label:'Opinion',        sub:'Analysis / column',         fields:['url','title','byline','content'],  contentLabel:'Opening argument',  urlLabel:'Published URL',  titleLabel:'Headline'},
  wire_adapted:    {label:'Wire adaptation',sub:'Wire source + your work',   fields:['url','title','byline','wire','content'], contentLabel:'What you added', urlLabel:'Your published URL', titleLabel:'Headline', forcedOrigins:['AA','MX']},
  correction:      {label:'Correction',     sub:'Corrects previous CTID',    fields:['url','title','ctid_orig','content'], contentLabel:'What was corrected', urlLabel:'Corrected URL', titleLabel:'Corrected headline'},
};

const LC_ORIGIN_HINTS = {
  OH:"✅ No AI tools used. If an AI classifier later challenges this, your trust score may be affected.",
  AA:"✅ AI-Assisted: safe and honest. No penalty for over-declaring AI involvement.",
  AG:"✅ AI-Generated: full transparency builds long-term trust with your audience.",
  MX:"✅ Mixed: safe default when human and AI both contributed.",
};

// ── State ─────────────────────────────────────────────────────────────────────
let lcPlatform   = null;
let lcType       = null;
let lcOrigin     = null;
let lcThreadPosts = ['', ''];
let lcSecMethod  = 'password';
let lcCredId     = null;
let lcCurrentCTID = '';

function lcShow(id, v = true) {
  const el = document.getElementById(id);
  if (el) el.style.display = v ? 'block' : 'none';
}
function lcErr(text) {
  const el = document.getElementById('lc-err');
  if (el) { el.textContent = text; el.style.display = text ? 'block' : 'none'; }
}

// ── Render platforms ──────────────────────────────────────────────────────────
function lcRenderPlatforms() {
  const grid = document.getElementById('lc-plat-grid');
  if (!grid) return;
  grid.innerHTML = LC_PLATFORMS.map(p => `
    <button class="lc-plat-btn ${lcPlatform === p.id ? 'sel' : ''}" data-lcpid="${p.id}" aria-label="${p.name}">
      <div class="lc-plat-icon" style="background:${p.bg};">${p.icon}</div>
      <div class="lc-plat-name">${p.name}</div>
    </button>
  `).join('');
  grid.querySelectorAll('.lc-plat-btn').forEach(btn => {
    btn.addEventListener('click', () => lcSelectPlatform(btn.dataset.lcpid));
  });
}

function lcSelectPlatform(pid) {
  lcPlatform = pid; lcType = null; lcOrigin = null;
  lcShow('lc-step1', false);
  lcShow('lc-step2', true);
  lcShow('lc-step3', false);
  lcRenderTypes();
}

// ── Render types ──────────────────────────────────────────────────────────────
function lcRenderTypes() {
  const list = document.getElementById('lc-type-list');
  const plat = LC_PLATFORMS.find(p => p.id === lcPlatform);
  if (!list || !plat) return;
  list.innerHTML = plat.types.map(tid => {
    const t = LC_TYPES[tid]; if (!t) return '';
    const bg = t.bg || '#8895A7';
    return `<button class="lc-type-chip ${lcType === tid ? 'sel' : ''}" data-lctid="${tid}">
      <div class="lc-type-icon" style="background:${bg}15;color:${bg};">${tid[0].toUpperCase()}</div>
      <div>
        <div class="lc-type-label">${t.label}</div>
        <div class="lc-type-sub">${t.sub || ''}</div>
      </div>
    </button>`;
  }).join('');
  list.querySelectorAll('.lc-type-chip').forEach(btn => {
    btn.addEventListener('click', () => lcSelectType(btn.dataset.lctid));
  });
}

function lcSelectType(tid) {
  lcType = tid; lcOrigin = null;
  lcShow('lc-step2', false);
  lcShow('lc-step3', true);
  const type = LC_TYPES[tid]; if (!type) return;
  lcUpdateBreadcrumb();
  lcShowFields(type);
  lcApplyWireRestriction(type);
  lcUpdateAuthUI();
  lcValidate();
}

// ── Breadcrumb ────────────────────────────────────────────────────────────────
function lcUpdateBreadcrumb() {
  const bc   = document.getElementById('lc-breadcrumb');
  const plat = LC_PLATFORMS.find(p => p.id === lcPlatform);
  const type = LC_TYPES[lcType];
  if (!bc || !plat || !type) return;
  bc.innerHTML = `
    <div class="lc-bc-pill">
      <span class="lc-bc-mini" style="background:${plat.bg};">${plat.icon}</span>
      ${plat.name}
    </div>
    <span style="font-size:14px;color:#8895A7;">›</span>
    <div class="lc-bc-pill">${type.label}</div>
    <button class="lc-bc-change" id="lc-bc-change-type">Change</button>
  `;
  document.getElementById('lc-bc-change-type')?.addEventListener('click', () => {
    lcShow('lc-step3', false);
    lcShow('lc-step2', true);
    lcRenderTypes();
  });
}

// ── Field visibility ──────────────────────────────────────────────────────────
const LC_ALL_FIELDS = ['url','title','byline','wire','ctid-orig','content','thread'];
function lcShowFields(type) {
  LC_ALL_FIELDS.forEach(f => lcShow(`lc-field-${f}`, false));
  lcShow('lc-wire-origin-notice', false);
  lcShow('lc-origin-section', false);

  (type.fields || []).forEach(f => {
    lcShow(`lc-field-${f === 'ctid_orig' ? 'ctid-orig' : f}`, true);
  });
  lcShow('lc-origin-section', true);

  // Update labels
  const urlLbl = document.getElementById('lc-url-label');
  if (urlLbl) urlLbl.textContent = type.urlLabel || 'URL';
  const urlHint = document.getElementById('lc-url-hint');
  if (urlHint) urlHint.textContent = type.urlHint || 'Canonical URL is hashed, not the file.';
  const titleLbl = document.getElementById('lc-title-label');
  if (titleLbl) titleLbl.textContent = type.titleLabel || 'Title';
  const titleReq = document.getElementById('lc-title-req');
  if (titleReq) {
    titleReq.textContent = type.titleRequired ? '*' : '(optional)';
    titleReq.style.color = type.titleRequired ? '#C53030' : '#8895A7';
  }
  const contentLbl = document.getElementById('lc-content-label');
  if (contentLbl) contentLbl.textContent = type.contentLabel || 'Description or Caption';
  const contentTA = document.getElementById('lc-content-input');
  if (contentTA) {
    contentTA.placeholder = type.placeholder || 'Write here...';
    contentTA.maxLength = type.limit || 5000;
  }

  // Reset origin buttons
  document.querySelectorAll('#lc-origin-btns .lc-origin-btn').forEach(b => {
    b.className = 'lc-origin-btn';
  });
  lcOrigin = null;
  const hint = document.getElementById('lc-origin-hint');
  if (hint) hint.style.display = 'none';

  if (type.fields.includes('thread')) lcRenderThreadPosts();
}

// ── Thread posts ──────────────────────────────────────────────────────────────
function lcRenderThreadPosts() {
  const c = document.getElementById('lc-thread-posts');
  if (!c) return;
  c.innerHTML = lcThreadPosts.map((t, i) => `
    <div class="lc-thread-row">
      <div class="lc-thread-num">${i + 1}</div>
      <textarea style="flex:1;padding:8px 10px;border:1px solid #E2E6EE;border-radius:7px;
        font-family:'JetBrains Mono',monospace;font-size:12px;resize:vertical;min-height:60px;"
        placeholder="Post ${i + 1}..." maxlength="280" data-lct="${i}">${t}</textarea>
    </div>
  `).join('');
  c.querySelectorAll('textarea[data-lct]').forEach(ta => {
    ta.addEventListener('input', () => {
      lcThreadPosts[+ta.dataset.lct] = ta.value;
      lcValidate();
    });
  });
}

document.getElementById('lc-add-thread-post')?.addEventListener('click', () => {
  lcThreadPosts.push('');
  lcRenderThreadPosts();
});

// ── Wire restriction ──────────────────────────────────────────────────────────
function lcApplyWireRestriction(type) {
  const forced = type.forcedOrigins;
  lcShow('lc-wire-origin-notice', !!forced);
  document.querySelectorAll('#lc-origin-btns .lc-origin-btn').forEach(btn => {
    btn.classList.toggle('blocked', !!(forced && !forced.includes(btn.dataset.code)));
  });
  if (lcOrigin && forced && !forced.includes(lcOrigin)) lcOrigin = null;
}

// ── Change platform button ────────────────────────────────────────────────────
document.getElementById('lc-change-plat')?.addEventListener('click', () => {
  lcPlatform = null; lcType = null;
  lcShow('lc-step2', false);
  lcShow('lc-step1', true);
  lcRenderPlatforms();
});

// ── Origin buttons ────────────────────────────────────────────────────────────
document.querySelectorAll('#lc-origin-btns .lc-origin-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    if (btn.classList.contains('blocked')) return;
    document.querySelectorAll('#lc-origin-btns .lc-origin-btn').forEach(b => {
      b.className = 'lc-origin-btn' + (b.classList.contains('blocked') ? ' blocked' : '');
    });
    lcOrigin = btn.dataset.code;
    btn.classList.add(`sel-${lcOrigin}`);
    const hint = document.getElementById('lc-origin-hint');
    if (hint) { hint.textContent = LC_ORIGIN_HINTS[lcOrigin] || ''; hint.style.display = 'block'; }
    lcValidate();
  });
});

// ── Auth UI ───────────────────────────────────────────────────────────────────
function lcUpdateAuthUI() {
  const isWA = (lcSecMethod === 'webauthn' || lcSecMethod === 'webauthn-prf' || lcSecMethod === 'webauthn-fallback') && !!lcCredId;
  lcShow('lc-pw-field', !isWA);
  lcShow('lc-wa-note', isWA);
}

// ── Build content string ──────────────────────────────────────────────────────
function lcBuildContent() {
  if (!lcType) return '';
  const type = LC_TYPES[lcType]; if (!type) return '';
  const parts = [];
  const f = type.fields || [];
  if (f.includes('url'))       { const v = document.getElementById('lc-url-input')?.value.trim();       if (v) parts.push(v); }
  if (f.includes('title'))     { const v = document.getElementById('lc-title-input')?.value.trim();     if (v) parts.push(v); }
  if (f.includes('byline'))    { const v = document.getElementById('lc-byline-input')?.value.trim();    if (v) parts.push(v); }
  if (f.includes('wire'))      { const v = document.getElementById('lc-wire-input')?.value.trim();      if (v) parts.push(v); }
  if (f.includes('ctid_orig')) { const v = document.getElementById('lc-ctid-orig-input')?.value.trim(); if (v) parts.push(v); }
  if (f.includes('content'))   { const v = document.getElementById('lc-content-input')?.value.trim();   if (v) parts.push(v); }
  if (f.includes('thread'))    { const j = lcThreadPosts.filter(Boolean).join('\n---\n'); if (j) parts.push(j); }
  return parts.join('\n');
}

// ── Validate ──────────────────────────────────────────────────────────────────
function lcValidate() {
  const btn = document.getElementById('lc-register-btn');
  if (!btn) return;
  if (!lcType)             { btn.disabled = true; btn.textContent = 'Select content type to continue'; return; }
  if (!lcBuildContent())   { btn.disabled = true; btn.textContent = 'Add content to continue'; return; }
  if (!lcOrigin)           { btn.disabled = true; btn.textContent = 'Select an origin code to continue'; return; }
  btn.disabled = false;
  btn.textContent = `Register as ${lcOrigin}`;
}

// Bind field inputs to validate
['lc-url-input','lc-title-input','lc-byline-input','lc-content-input','lc-ctid-orig-input'].forEach(id => {
  document.getElementById(id)?.addEventListener('input', lcValidate);
});
document.getElementById('lc-wire-input')?.addEventListener('change', lcValidate);

// ── Register ──────────────────────────────────────────────────────────────────
document.getElementById('lc-register-btn')?.addEventListener('click', async () => {
  if (!lcOrigin) return;
  const content = lcBuildContent();
  const title   = document.getElementById('lc-title-input')?.value.trim() || '';
  if (!content) { lcErr('Add content to register.'); return; }

  const btn = document.getElementById('lc-register-btn');
  btn.disabled = true; btn.textContent = '⏳ Registering...';
  lcErr('');

  let res;
  try {
    if ((lcSecMethod === 'webauthn' || lcSecMethod === 'webauthn-prf' || lcSecMethod === 'webauthn-fallback') && lcCredId) {
      const stored = await chrome.storage.local.get(['encryptedKey', 'tipId', 'tipKey']);
      // Use VP key format if available, otherwise fall back to extension's own format
      let privateKeyHex;
      if (stored.tipKey && stored.tipKey.data) {
        const { decryptVPKey } = await import("./crypto.js");
        privateKeyHex = await decryptVPKey(stored.tipKey);
      } else {
        privateKeyHex = await decryptKeyWithWebAuthn(stored.encryptedKey, lcCredId);
      }
      res = await msg('REGISTER_CONTENT_WITH_KEY', {
        payload: { originCode: lcOrigin, content, title, privateKeyHex },
      });
    } else {
      const password = document.getElementById('lc-password')?.value || '';
      if (!password) { lcErr('Enter your signing password.'); btn.disabled = false; btn.textContent = `Register as ${lcOrigin}`; return; }
      res = await msg('REGISTER_CONTENT', { payload: { originCode: lcOrigin, content, title, password } });
    }
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      lcErr('Authentication cancelled. Try again.');
    } else if (e.name === 'OperationError') {
      lcErr('Key decryption failed. Please re-register your TIP ID in Settings → Setup tab.');
    } else {
      lcErr(e.message || 'Authentication failed.');
    }
    btn.disabled = false; btn.textContent = `Register as ${lcOrigin}`;
    return;
  }

  if (res?.ok && res.data?.ctid) {
    lcCurrentCTID = res.data.ctid;
    document.getElementById('lc-ctid-display').textContent = lcCurrentCTID;
    lcShow('lc-step3', false);
    lcShow('lc-success', true);
    navigator.clipboard?.writeText(lcCurrentCTID).catch(() => {});
    toast('✓ Registered! CTID copied to clipboard.');
  } else {
    lcErr(res?.error || 'Registration failed. Check Settings → TIP Node.');
    btn.disabled = false; btn.textContent = `Register as ${lcOrigin}`;
  }
});

// ── Copy CTID ─────────────────────────────────────────────────────────────────
document.getElementById('lc-copy-ctid')?.addEventListener('click', () => {
  navigator.clipboard?.writeText(lcCurrentCTID).then(() => {
    const btn = document.getElementById('lc-copy-ctid');
    btn.textContent = '✓ Copied!';
    setTimeout(() => { btn.textContent = '📋 Copy CTID to clipboard'; }, 2000);
  });
});

// ── Register another ──────────────────────────────────────────────────────────
document.getElementById('lc-register-another')?.addEventListener('click', () => {
  lcPlatform = null; lcType = null; lcOrigin = null;
  lcThreadPosts = ['', ''];
  lcCurrentCTID = '';
  ['lc-url-input','lc-title-input','lc-byline-input','lc-content-input','lc-ctid-orig-input'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  lcShow('lc-success', false);
  lcShow('lc-step3', false);
  lcShow('lc-step2', false);
  lcShow('lc-step1', true);
  lcRenderPlatforms();
});

// ── Init Label Content ────────────────────────────────────────────────────────
async function initLabelContent() {
  const idRes = await msg('GET_IDENTITY');
  if (!idRes?.ok || !idRes.data?.setupComplete) {
    lcShow('lc-no-id', true);
    lcShow('lc-form', false);
    return;
  }
  lcSecMethod = idRes.data.securityMethod || 'password';
  lcCredId    = idRes.data.credentialId   || null;
  const tipId = idRes.data.tipId || '';
  const el = document.getElementById('lc-tipid');
  if (el) el.textContent = tipId;
  lcShow('lc-no-id', false);
  lcShow('lc-form', true);
  lcUpdateAuthUI();
  lcRenderPlatforms();
  lcValidate();
}

// ── Init ───────────────────────────────────────────────────────────────────────
loadIdentity();
loadNodeStatus();
initLabelContent();
