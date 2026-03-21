# TIP™ Browser Extension v2.1.0

**Dual-mode creator registration and viewer badge overlay.**
Works on YouTube, Instagram, TikTok, X, Facebook, LinkedIn, Substack, and Medium.

**Author:** Dinesh Mendhe | **Owner:** The AI Lab Intelligence Unobscured, Inc.
**License:** TIPCL-1.0 | theailab.org

---

## What it does

**Creator mode** (before platforms implement TIP natively):
- Detects upload pages on YouTube Studio, Instagram, TikTok, X, Facebook, LinkedIn, Substack, Medium
- Injects a registration panel into the upload form
- Hashes content, signs with your ML-DSA-65 private key, registers on TIP DAG
- Returns a CTID to paste in your description

**Viewer mode** (works right now on any page):
- Reads TIP-* HTTP headers and meta tags
- Injects trust badges next to YouTube channel names and Twitter/X usernames
- Shows a floating badge on any TIP-verified page
- Makes CTIDs in page text clickable verification links

**Dual-use design**: Once a platform adds native TIP headers, the creator panel
hides itself automatically and the viewer badge reads the platform's headers instead.
No extension update needed.

---

## Install in Chrome / Edge / Brave

```
1. Download or clone this repository
2. Open chrome://extensions
3. Enable "Developer mode" (top right toggle)
4. Click "Load unpacked"
5. Select the browser-extension/ folder
6. The TIP™ icon appears in your toolbar
```

## Install in Firefox

```
1. Open about:debugging#/runtime/this-firefox
2. Click "Load Temporary Add-on"
3. Select manifest.json from the browser-extension/ folder
```

---

## First-time setup (creators)

1. Click the TIP™ icon in your toolbar
2. Click the **Settings** gear icon
3. Go to **My TIP-ID**
4. Enter your TIP-ID and private key from your VP registration
5. Set a strong signing password
6. Click **Connect TIP-ID**

Your private key is encrypted with AES-256-GCM and stored only on this device.
It is never transmitted anywhere.

---

## File structure

```
browser-extension/
├── manifest.json              Chrome Manifest V3
├── popup.html                 Toolbar popup (creator + viewer tabs)
├── options.html               Full settings page
├── NOTICE.txt                 Required attribution
├── package.json               npm metadata
├── README.md                  This file
├── icons/
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
└── src/
    ├── background.js          Service worker (MV3)
    ├── content.js             Content script (badge injection + creator panel)
    └── crypto.js              Browser crypto (AES-GCM, ECDSA stub, SHAKE-256)
```

---

## Supported platforms

| Platform | Upload detection | Badge injection |
|----------|-----------------|----------------|
| YouTube Studio | ✓ | Channel names |
| Instagram | ✓ | Partial |
| TikTok | ✓ | Partial |
| X / Twitter | ✓ | Usernames |
| Facebook | ✓ | Partial |
| LinkedIn | ✓ | Partial |
| Substack | ✓ | Via meta tags |
| Medium | ✓ | Via meta tags |
| Any website | Via popup | TIP headers/meta |

---

## Production crypto swap (BLOCKING-B1)

The current implementation uses **ECDSA P-256** as a development stand-in for ML-DSA-65.
For production, replace `src/crypto.js` signing calls with `@noble/post-quantum`:

```bash
npm install @noble/post-quantum
```

```javascript
// In crypto.js — replace generateKeypair() and signData()
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";

async function generateKeypair() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  return {
    algorithm:  "ML-DSA-65",
    publicKey:  bufToHex(publicKey),
    privateKey: bufToHex(secretKey),
  };
}
```

The `@noble/post-quantum` library is pure JavaScript, audited by Cure53, and
requires no native compilation or WebAssembly build steps — it works directly
in browser extensions.

---

## TIP Node

The extension connects to a TIP node for:
- Content registration (POST /v1/content/register)
- Trust score lookups (GET /v1/identity/:tipId/score)
- Revocation list polling (GET /v1/revocations)

**Default node:** `https://node.theailab.org` (mainnet)
**Local dev node:** `http://localhost:4000`

To run a local node:
```bash
git clone https://github.com/theailab-org/tip-node.git
cd tip-node && cp .env.example .env
docker compose up -d
docker compose exec tip-node node scripts/seed.js
```

Change the node URL in Settings → TIP Node.

---

## Origin codes

| Code | Meaning | Penalty for mislabelling |
|------|---------|--------------------------|
| OH | Original Human | -100 to -350 score |
| AA | AI-Assisted | -25 if confirmed fully AI |
| AG | AI-Generated | None |
| MX | Mixed / Composite | None |

Over-declaring AI involvement is always safe. Declaring OH when AI generated the
content risks trust score penalties.

---

## Contact

chairman@theailab.org | theailab.org | accreditation@theailab.org

Copyright 2026 The AI Lab Intelligence Unobscured, Inc. | Authored by Dinesh Mendhe
