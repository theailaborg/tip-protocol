# TIP - AI Trust ID Browser Extension v2.2.0

**Dual-mode creator registration and viewer badge overlay for the TIP Protocol.**
Works on YouTube, Instagram, TikTok, X/Twitter, Facebook, LinkedIn, Threads, Substack, Medium, podcast platforms, news media, and blogs.

**Author:** Dinesh Mendhe | **Owner:** The AI Lab Intelligence Unobscured, Inc.
**License:** TIPCL-1.0 | theailab.org

---

## What it does

**Creator mode** (before platforms implement TIP natively):
- Detects upload pages on YouTube Studio, Instagram, TikTok, X, Facebook, LinkedIn, Substack, Medium
- Injects a registration panel into the upload form
- Hashes content with SHAKE-256, signs with your ML-DSA-65 private key, registers on the TIP DAG
- Returns a CTID (Content Trust Identifier) to paste in your description

**Viewer mode** (works right now on any page):
- Reads TIP-* HTTP headers and meta tags
- Injects trust badges next to YouTube channel names and Twitter/X usernames
- Shows a floating badge on any TIP-verified page
- Makes CTIDs in page text clickable verification links

**Dual-use design**: Once a platform adds native TIP headers, the creator panel hides itself automatically and the viewer badge reads the platform's headers instead. No extension update needed.

---

## Install

### Chrome / Edge / Brave / Arc

```
1. Download or clone this repository
2. Open chrome://extensions (or edge://extensions, brave://extensions)
3. Enable "Developer mode" (top right toggle)
4. Click "Load unpacked"
5. Select the browser-extension/ folder
6. The TIP icon appears in your toolbar
```

### Firefox

```
1. Open about:debugging#/runtime/this-firefox
2. Click "Load Temporary Add-on"
3. Select manifest.json from the browser-extension/ folder
```

---

## First-time setup (creators)

1. Click the TIP icon in your toolbar
2. Click the **Settings** gear icon
3. Go to **My TIP-ID**
4. Enter your TIP-ID and private key from your VP registration
5. Set a strong signing password (or use biometric passkey if available)
6. Click **Connect TIP-ID**

Your private key is encrypted with AES-256-GCM and stored only on this device. It is never transmitted anywhere. See the Security Architecture section below for full details.

---

## Security Architecture

### Key hierarchy

The extension uses a layered cryptographic architecture. Two separate key systems serve different purposes: the Secure Enclave ECDSA key protects key storage, while the ML-DSA-65 key signs content. They never cross.

#### Key storage protection (at rest)

When biometric authentication is available, the extension uses the device's Secure Enclave (Apple), TrustZone (Android), or TPM (Windows) via WebAuthn to protect the ML-DSA-65 private key on disk.

The Secure Enclave creates an ECDSA P-256 keypair during WebAuthn registration. The private key is locked inside the hardware forever. It cannot be exported. ECDSA is a signing algorithm, not an encryption algorithm. You cannot encrypt data with ECDSA directly.

What the Secure Enclave provides instead is a PRF (Pseudorandom Function) via the WebAuthn `prf` extension. When the extension requests a PRF evaluation, the Secure Enclave uses its internal private key to compute a deterministic HMAC against a salt you provide. The output is a 32-byte pseudorandom value. This value is not a signature. It is not encryption. It is raw key material.

The actual chain is:

```
Secure Enclave ECDSA P-256 private key
        |
        | (PRF evaluation, requires biometric)
        v
32-byte PRF output (pseudorandom, deterministic)
        |
        | SHAKE-256(PRF_output || "tip-pqc-key-wrap")
        v
32-byte AES key
        |
        | AES-256-GCM encrypt (TIP-ID as authenticated data)
        v
ML-DSA-65 private key (encrypted at rest)
```

The ECDSA key's only job is to produce the PRF output. The PRF output's only job is to derive the AES key. The AES key's only job is to encrypt the ML-DSA-65 private key when it is sitting on disk. The ECDSA key never touches your content.

**Fallback path (PATH B):** If the device does not support the WebAuthn PRF extension (Safari, older Chrome), the extension falls back to SHAKE-256(credentialId || domain) into PBKDF2 with 200,000 iterations. A biometric prompt is still required before key derivation begins.

**Password fallback (legacy):** If no WebAuthn/passkey is available at all, the extension encrypts the private key using a user-chosen password processed through SHAKE-256(password || domain) into PBKDF2 (200,000 iterations, SHA-256) to derive the AES-256 key.

#### Content signing (in use)

Only ML-DSA-65 (FIPS 204, post-quantum) signs content. The ECDSA key in the Secure Enclave never touches content. When you click "Register" on a piece of content, the flow is:

```
1. Biometric prompt (Face ID / fingerprint / Windows Hello)
2. Secure Enclave releases PRF output
3. SHAKE-256 derives AES key from PRF output
4. AES-256-GCM decrypts the ML-DSA-65 private key into memory
5. ML-DSA-65 signs the content hash (in software, in memory)
6. ML-DSA-65 private key is released from memory
7. The signature is sent to the TIP node
```

The signed fields are: `{ author_tip_id, origin_code, content_hash }`. The content hash is SHAKE-256 of the raw content text. The TIP node verifies the signature against the author's registered ML-DSA-65 public key.

### What each key does

| Key | Location | Purpose | Touches content? |
|-----|----------|---------|------------------|
| ECDSA P-256 | Secure Enclave hardware | Produce PRF output for AES key derivation | No |
| AES-256-GCM | Derived in memory, never stored | Encrypt/decrypt ML-DSA-65 private key at rest | No |
| ML-DSA-65 | Encrypted on disk, decrypted in memory only for signing | Sign content hashes on the TIP DAG | Yes |

### Algorithms

| Function | Algorithm | Standard |
|----------|-----------|----------|
| Content hashing | SHAKE-256, 32 bytes | FIPS 202 |
| Content signing | ML-DSA-65 (pure, no hybrid) | FIPS 204 (post-quantum) |
| Key encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation (PRF path) | WebAuthn PRF + SHAKE-256 | W3C WebAuthn Level 3 |
| Key derivation (fallback) | SHAKE-256 + PBKDF2-SHA256, 200k iterations | NIST SP 800-132 |
| Passkey authentication | ECDSA P-256 via platform authenticator | FIPS 186-5 |
| Canonical serialization | Deterministic sorted-key JSON | TIP Protocol v2.0 Sec 4.2 |

### Data stored locally

All data is stored in `chrome.storage.local` (encrypted by Chrome's profile encryption on disk). No data is synced to the cloud.

| Key | Contents | Sensitive? |
|-----|----------|------------|
| `tipKey` | Encrypted ML-DSA-65 private key + credential ID + method + salt + nonce | Encrypted blob only |
| `tipId` | Your TIP-ID string | Public identifier |
| `tipPublicKey` | ML-DSA-65 public key hex | Public, registered on DAG |
| `tip_node_url` | TIP node URL | Configuration |

No private keys, passwords, or biometric data are ever transmitted to any server.

---

## File structure

```
browser-extension/
|-- manifest.json              Chrome Manifest V3
|-- popup.html                 Toolbar popup (creator + viewer tabs)
|-- sign.html                  Biometric signing prompt window
|-- options.html               Full settings page
|-- NOTICE.txt                 Required attribution (survives license conversion)
|-- PRIVACY_POLICY.md          Privacy policy (Chrome Web Store requirement)
|-- package.json               npm metadata
|-- README.md                  This file
|-- icons/
|   |-- icon16.png             Toolbar icon (16px, light theme)
|   |-- icon32.png             Toolbar icon (32px)
|   |-- icon48.png             Extension management page (48px)
|   |-- icon128.png            Chrome Web Store listing (128px)
|   |-- icon16-dark.png        Dark theme variants
|   |-- icon32-dark.png
|   |-- icon48-dark.png
|   +-- icon128-dark.png
|-- src/
|   |-- background.js          Service worker (MV3): message routing, registration API
|   |-- content.js             Content script: badge injection + creator panel
|   |-- crypto.js              Cryptography: ML-DSA-65, AES-GCM, WebAuthn PRF, SHAKE-256
|   |-- config.js              Environment config (node URL, WebAuthn RP ID)
|   |-- popup.js               Popup UI controller
|   |-- options.js             Settings page controller
|   |-- sign.js                Biometric signing flow (opens in popup window)
|   |-- tip-sign.js            Content registration signature (ML-DSA-65 pure)
|   +-- tip-types.js           Content type definitions for supported platforms
|-- scripts/
|   |-- build.js               Build script (esbuild, Chrome + Firefox targets)
|   +-- watch.js               Dev file watcher
+-- tests/
    +-- crypto.test.js         Unit tests for crypto module
```

---

## Supported platforms

| Platform | Upload detection | Badge injection |
|----------|-----------------|-----------------|
| YouTube Studio | Yes | Channel names |
| Instagram | Yes | Partial |
| TikTok | Yes | Partial |
| X / Twitter | Yes | Usernames |
| Facebook | Yes | Partial |
| LinkedIn | Yes | Partial |
| Threads | Yes | Partial |
| Substack | Yes | Via meta tags |
| Medium | Yes | Via meta tags |
| Podcasts | Via popup | Via meta tags |
| News sites | Via popup | TIP headers/meta |
| Any website | Via popup | TIP headers/meta |

---

## TIP Node

The extension connects to a TIP node for:
- Content registration (`POST /v1/content/register`)
- Trust score lookups (`GET /v1/identity/:tipId/score`)
- Revocation list polling (`GET /v1/revocations`)

**Default node:** `https://node.theailab.org` (mainnet)
**Local dev node:** `http://localhost:4000`

To run a local node:
```bash
git clone https://github.com/theailaborg/tip-node.git
cd tip-node && cp .env.example .env
docker compose up -d
docker compose exec tip-node node scripts/seed.js
```

Change the node URL in Settings, TIP Node section.

---

## Origin codes

| Code | Meaning | Penalty for mislabelling |
|------|---------|--------------------------|
| OH | Original Human | -100 to -350 score |
| AA | AI-Assisted | -25 if confirmed fully AI |
| AG | AI-Generated | None |
| MX | Mixed / Composite | None |

Over-declaring AI involvement is always safe. Declaring OH when AI generated the content risks trust score penalties.

---

## Permissions explained

| Permission | Why it is needed |
|------------|------------------|
| `activeTab` | Read the current page to detect upload forms and TIP headers |
| `storage` | Store your encrypted private key and settings locally |
| `scripting` | Inject trust badges and creator panels into web pages |
| `clipboardWrite` | Copy CTIDs to your clipboard after registration |
| `notifications` | Show registration success/failure notifications |
| `windows` | Open the biometric signing prompt in a secure popup window |
| Host permissions (all URLs) | Detect upload forms and read TIP headers on any website |

---

## Build from source

```bash
npm install
npm run build:chrome    # Build for Chrome/Edge/Brave
npm run build:firefox   # Build for Firefox
npm run build:all       # Build both
npm test                # Run unit tests
npm run lint            # Lint source files
```

---

## Contact

tip@theailab.org | theailab.org | accreditation@theailab.org

Copyright 2025-2026 The AI Lab Intelligence Unobscured, Inc. | Authored by Dinesh Mendhe
