# Chrome Web Store Submission Checklist

Guide for publishing the TIP - AI Trust ID extension to the Chrome Web Store.

---

## Required assets (must prepare before submission)

### 1. Screenshots (minimum 1, recommended 5)
- Format: 1280x800 or 640x400 PNG/JPEG
- Must show actual extension functionality, not mockups
- Suggested screenshots:
  1. **Popup open** on a YouTube page showing creator registration panel
  2. **Trust badge** injected next to a verified YouTube channel name
  3. **Settings page** showing the TIP-ID connection form
  4. **Registration success** with CTID displayed and copy button
  5. **Viewer mode** showing the floating TIP badge on a verified page

### 2. Promotional images
- **Small tile** (required): 440x280 PNG
- **Large tile** (optional but recommended): 920x680 PNG
- **Marquee** (optional): 1400x560 PNG
- Must not contain excessive text or misleading claims

### 3. Extension icon
- 128x128 PNG (already present in `icons/icon128.png`)

---

## Chrome Web Store developer account

1. Register at https://chrome.google.com/webstore/devconsole
2. Pay the one-time $5 registration fee
3. Verify your identity (required for extensions requesting host permissions)

---

## Store listing fields

### Name
```
TIP - AI Trust ID
```

### Short description (132 chars max)
```
Register your content on the TIP Protocol. Declare human or AI origin, get a verified CTID. Trust badges on YouTube, X, and more.
```

### Detailed description (recommended 500+ chars)
```
TIP - AI Trust ID lets creators register their content on the TIP Protocol DAG with a cryptographic proof of origin. Declare whether your content is human-made (OH), AI-assisted (AA), AI-generated (AG), or mixed (MX), and receive a permanent Content Trust Identifier (CTID).

For creators:
- Detects upload pages on YouTube Studio, Instagram, TikTok, X/Twitter, Facebook, LinkedIn, Substack, and Medium
- Hashes your content with SHAKE-256 and signs it with your ML-DSA-65 post-quantum private key
- Registers the hash and signature on the TIP Protocol DAG
- Returns a CTID to include in your content description

For viewers:
- Injects verified trust badges next to YouTube channel names and X/Twitter usernames
- Reads TIP-* HTTP headers and meta tags on any website
- Shows a floating trust badge on verified pages
- Makes CTIDs in page text clickable for instant verification

Security:
- Post-quantum cryptography (ML-DSA-65, FIPS 204)
- Private key encrypted with AES-256-GCM, protected by biometric authentication (WebAuthn)
- No browsing data collected, no analytics, no tracking
- All data stored locally on your device

Part of the Trust Identity Protocol (TIP) by The AI Lab Intelligence Unobscured, Inc.
```

### Category
```
Productivity
```

### Language
```
English
```

---

## Permission justifications (required during submission)

Chrome Web Store review requires a justification for each permission. Copy these into the submission form.

| Permission | Justification text |
|------------|-------------------|
| `activeTab` | "The extension reads TIP Protocol HTTP headers and meta tags on the active tab to display trust verification badges. It also detects content upload forms on supported platforms (YouTube, Instagram, TikTok, X, Facebook, LinkedIn, Substack, Medium) to offer content registration." |
| `storage` | "The extension stores the user's encrypted private key, TIP-ID, public key, and configuration settings (such as the TIP node URL) in local browser storage. No data is synced to the cloud." |
| `scripting` | "The extension injects trust verification badges into web pages next to verified creator names, and injects content registration panels into upload forms on supported platforms." |
| `clipboardWrite` | "After successful content registration, the extension copies the Content Trust Identifier (CTID) to the user's clipboard so they can paste it into their content description." |
| `notifications` | "The extension displays browser notifications to confirm successful content registration or report errors during the signing process." |
| `windows` | "The extension opens a small popup window for the biometric authentication prompt (WebAuthn/FIDO2) during the content signing flow. This is required because the WebAuthn API needs a focused browser context." |
| Host permissions (all URLs) | "The extension needs to run on all URLs to: (1) detect content upload forms on any supported platform, (2) read TIP Protocol HTTP response headers and HTML meta tags for trust badge display, and (3) scan page text for CTIDs to make them clickable verification links. The extension does not collect or transmit browsing data." |

---

## Single purpose description

Chrome requires a "single purpose" statement. Use:

```
This extension registers content on the TIP Protocol with cryptographic origin declarations and displays trust verification badges for TIP-verified creators and content.
```

---

## Privacy policy URL

Host the PRIVACY_POLICY.md at a public URL and enter it during submission. Options:

- GitHub Pages: `https://theailaborg.github.io/tip-sdk/browser-extension/PRIVACY_POLICY`
- Main website: `https://theailab.org/tip-extension-privacy`
- Raw GitHub: `https://github.com/theailaborg/tip-sdk/blob/main/browser-extension/PRIVACY_POLICY.md`

The Chrome Web Store requires a direct URL, not a file upload.

---

## Data use disclosures

During submission, Chrome asks what data the extension collects. Answer:

- **Personally identifiable information:** No
- **Health information:** No
- **Financial and payment information:** No
- **Authentication information:** No (biometric data never leaves the device)
- **Personal communications:** No
- **Location:** No
- **Web history:** No
- **User activity:** No
- **Website content:** No (only hashes are transmitted, never raw content)

---

## Pre-submission checklist

- [ ] manifest.json `version` matches package.json `version` (currently 2.2.0)
- [ ] All icons present: 16, 32, 48, 128 (light + dark variants)
- [ ] PRIVACY_POLICY.md created and hosted at a public URL
- [ ] NOTICE.txt present with license and trademark information
- [ ] Screenshots prepared (1280x800 or 640x400)
- [ ] Small promotional tile prepared (440x280)
- [ ] Permission justifications written (see table above)
- [ ] Single purpose statement written
- [ ] Developer account registered and identity verified
- [ ] Extension tested on Chrome 116+ (WebAuthn PRF support)
- [ ] Extension tested on Edge (Chromium-based)
- [ ] No console errors in background service worker
- [ ] No unused permissions in manifest.json
- [ ] config.js set to production values (node URL, RP ID)
- [ ] Build output is clean: `npm run build:chrome`

---

## Config changes for production

Before publishing, update `src/config.js`:

```javascript
export const TIP_NODE_URL       = "https://node.theailab.org";
export const TIP_WEBAUTHN_RP_ID = "theailab.org";  // MUST be production domain
```

The RP ID must match the domain where the passkeys were originally created during VP registration. If set incorrectly, biometric authentication will fail.

---

## Review timeline

Chrome Web Store reviews typically take 1-3 business days. Extensions requesting broad host permissions (`<all_urls>`) or `scripting` may receive additional scrutiny. The permission justifications above are designed to address common review concerns.

If the review is rejected, the most common reasons for this type of extension are:
- Insufficient justification for `<all_urls>` host permission
- Missing or inadequate privacy policy
- "Single purpose" violation (extension does too many unrelated things)

The TIP extension has a clear single purpose (content provenance and trust verification), so the last point should not apply.
