# Privacy Policy

**TIP - AI Trust ID Browser Extension**
**Effective date:** April 4, 2026
**Last updated:** April 4, 2026

This privacy policy describes how the TIP - AI Trust ID browser extension ("the Extension") handles your data. The Extension is published by The AI Lab Intelligence Unobscured, Inc. ("we", "us").

---

## Summary

The Extension stores all sensitive data locally on your device. It does not collect personal information, does not track browsing activity, and does not share data with third parties. The only network requests are to the TIP Protocol node for content registration and trust score lookups, initiated exclusively by your explicit action.

---

## Data the Extension stores locally

All data is stored in your browser's local extension storage (`chrome.storage.local`). This storage is encrypted by your browser's profile encryption and is never synced to the cloud.

| Data | Purpose | Sensitive? |
|------|---------|------------|
| Encrypted ML-DSA-65 private key | Sign content registrations when you explicitly choose to | Yes (encrypted with AES-256-GCM, requires biometric or password to decrypt) |
| TIP-ID | Your public identifier on the TIP Protocol | No (public by design) |
| ML-DSA-65 public key | Verify your identity on the TIP DAG | No (public by design) |
| TIP node URL | Connect to the correct TIP Protocol node | No |
| WebAuthn credential ID | Identify your passkey for biometric authentication | Non-sensitive metadata |

---

## Data the Extension does NOT collect

- Browsing history or URLs visited
- Page content, text, images, or media (except when you explicitly register content)
- Cookies, form data, or autofill information
- Personal information (name, email, address, phone number)
- Location data
- Device identifiers or fingerprints
- Analytics, telemetry, or usage statistics

---

## Network requests

The Extension makes network requests only in these situations, all initiated by your explicit action:

**Content registration** (when you click "Register"):
- Sends to the TIP node: content hash (SHAKE-256 of the content text), origin code (OH/AA/AG/MX), your TIP-ID, and an ML-DSA-65 signature.
- Does NOT send the actual content text. Only the hash is transmitted.

**Trust score lookup** (when viewing a TIP-verified page):
- Queries the TIP node for the trust score of a TIP-ID found in page headers or meta tags.
- Sends only the TIP-ID string. No browsing data is included.

**Revocation polling** (periodic, if enabled):
- Checks the TIP node's public revocation list.
- No user-specific data is sent.

All requests go to the configured TIP node (default: `https://node.theailab.org`). No data is sent to any other server, advertising network, analytics service, or third party.

---

## Biometric data

The Extension uses WebAuthn (FIDO2) for biometric authentication. Biometric data (fingerprints, face scans) is processed entirely by your device's operating system and hardware (Secure Enclave, TrustZone, or TPM). The Extension never receives, stores, or transmits biometric data. It receives only a cryptographic assertion proving that authentication succeeded.

---

## Permissions and why they are needed

| Permission | Justification |
|------------|---------------|
| `activeTab` | Read TIP headers and meta tags on the current page; detect upload forms on supported platforms |
| `storage` | Store your encrypted private key and extension settings locally |
| `scripting` | Inject trust badges into web pages and creator registration panels into upload forms |
| `clipboardWrite` | Copy your CTID to the clipboard after successful registration |
| `notifications` | Show success or error notifications after content registration |
| `windows` | Open a secure popup window for the biometric signing prompt |
| Host permissions (all URLs) | Detect upload forms on any supported platform and read TIP headers from any website |

---

## Third-party services

The Extension does not integrate with any third-party analytics, advertising, crash reporting, or data collection services. The only external service contacted is the TIP Protocol node, which is operated by The AI Lab Intelligence Unobscured, Inc. or a self-hosted instance configured by the user.

---

## Data retention

All data is stored locally and persists until you:
- Remove the Extension from your browser
- Clear the Extension's storage via Settings
- Revoke your TIP-ID via the VP portal

The TIP node retains content registrations (hashes and signatures, not content) as part of the public TIP DAG. This is by design: content provenance records are permanent and public.

---

## Children's privacy

The Extension is not directed at children under 13. We do not knowingly collect data from children.

---

## Changes to this policy

We may update this privacy policy from time to time. Changes will be reflected in the "Last updated" date at the top of this document and in the Extension's changelog.

---

## Contact

For privacy questions or data deletion requests:

- Email: tip@theailab.org
- Security: security@theailab.org
- Address: The AI Lab Intelligence Unobscured, Inc., 131 Continental Dr, Suite 305, Newark, DE 19713, United States
- Website: https://theailab.org
