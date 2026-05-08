# TIP Protocol Specification v4.0

**Trust Identity Protocol: Public Specification**  
Version 4.0 | March 2026  
The AI Lab Intelligence Unobscured, Inc.  
Authored by Dinesh Mendhe

**License:** CC-BY 4.0: Free to implement, share, and adapt with attribution.  
**Attribution:** "TIP Protocol Specification by Dinesh Mendhe, The AI Lab Intelligence Unobscured, Inc. (theailab.org)"

---

## Table of Contents

1. [Overview and Design Philosophy](#1-overview)
2. [Protocol Primitives](#2-primitives)
3. [Layer 1: TIP-ID (Identity)](#3-tip-id)
4. [Layer 2: TIP-CONTENT (Provenance)](#4-tip-content)
5. [Layer 3: TIP-TRUST (Reputation)](#5-tip-trust)
6. [Post-Quantum Cryptography](#6-cryptography)
7. [Federated DAG Network](#7-dag)
8. [Verification Provider (VP) System](#8-vp)
9. [Privacy Architecture (v2)](#9-privacy)
10. [GDPR Compliance (v2)](#10-gdpr)
11. [Jurisdiction Tiers (v2)](#11-jurisdictions)
12. [Identity Revocation (v2)](#12-revocation)
13. [Web Integration](#13-web)
14. [Visual Badge System](#14-badges)
15. [Protocol Constants](#15-constants)
16. [Changelog](#16-changelog)

---

## 1. Overview and Design Philosophy

TIP Protocol (Trust Identity Protocol) is a federated, post-quantum cryptographic protocol that establishes a verifiable trust layer for the internet. It is designed to solve three problems that no existing system addresses together:

1. **Who created this content?**: verifiably binding content to a specific real human
2. **How was this content made?**: mandatory origin declaration (human, AI-assisted, AI-generated)
3. **Should I trust this person?**: a public, tamper-proof reputation score

### Design Principles

**Protocol-level, not product-level.** TIP Protocol is to internet trust what HTTPS is to encryption: an open standard that any implementation can adopt, not a proprietary service.

**Reframe the question.** Instead of asking the impossible question "is this content fake?", the protocol asks the tractable question "does this content match its declared origin?" This eliminates the largest source of false positives in content authenticity systems.

**Conservative labeling is always safe.** Declaring content as more AI-involved than it actually is carries zero penalty. Only under-disclosure is penalized. The system is asymmetrically designed to incentivize honest disclosure.

**Federated, not decentralized.** The network is intentionally federated rather than fully decentralized during the founding phase. Any entity can run a node. Verification Providers are accredited but not centralized. The genesis block provides a single trust anchor without requiring energy-intensive consensus.

**Post-quantum by default.** All cryptographic primitives are NIST-standardized post-quantum algorithms (FIPS 203, 204, 205). Classical signatures are permitted only during a defined transition period.

---

## 2. Protocol Primitives

The protocol defines four primitive data types. Every interaction in the system is composed of these primitives.

### 2.1 TIP-ID

```
tip://id/[REGION]-[ML_DSA_PUBKEY_HASH_FIRST_16_CHARS]

Example: tip://id/US-a3f8c91b2d4e7021
```

A TIP-ID is a globally unique, portable digital identity bound to a specific verified human via the four-layer biometric verification stack (Section 3). The URI format encodes:

- `REGION`: ISO 3166-1 alpha-2 country code of the issuing VP
- `ML_DSA_PUBKEY_HASH_FIRST_16_CHARS`: First 16 hex characters of SHAKE-256(ML-DSA-65 public key)

### 2.2 TIP-CONTENT (CTID)

```
tip://c/[ORIGIN]-[HASH14]-[ID_SHORT]

Example: tip://c/OH-7f2a91bc3d5e4a-a3f8
```

A CTID is a content provenance record binding a piece of content to its creator's TIP-ID and a mandatory origin declaration. The URI format embeds the origin code directly, making the origin classification visible in every reference, link, or citation.

- `ORIGIN`: OH | AA | AG | MX (see Section 4.1)
- `HASH14`: First 14 hex characters of SHAKE-256(content)
- `ID_SHORT`: First 4 hex characters of the author's TIP-ID hash portion (the segment after the region prefix and dash in `tip://id/XX-[hash]`)

### 2.3 TIP-TRUST Score

An integer from 0 to 1000 representing the entity's public trust score, computed deterministically from the complete DAG transaction history (see Section 5). The score is not stored centrally: any protocol-compliant node computes the same score from the same DAG history.

### 2.4 TIP-TX (DAG Transaction)

Every state change in the system is a DAG transaction. Transaction types are defined in Section 7.3. Each transaction:

- References exactly 2 prior transactions (`prev[0]`, `prev[1]`)
- Has a unique `tx_id` = SHAKE-256 of the canonical transaction content
- Includes a post-quantum signature from the issuing party
- Is immutable once written to the DAG

---

## 3. Layer 1: TIP-ID (Identity)

### 3.1 TIP-ID Data Structure

| Field | Type | Description |
|-------|------|-------------|
| `tip_id` | String | Canonical URI: `tip://id/[REGION]-[HASH16]` |
| `region` | String | ISO 3166-1 alpha-2 |
| `public_key` | String (hex) | ML-DSA-65 public key (1,952 bytes) |
| `root_public_key` | String (hex) | SLH-DSA-128s long-term root key (32 bytes) |
| `biometric_hash` | String (hex) | SHAKE-256(512-dim facial embedding): never stored raw |
| `dedup_hash` | String (hex) | Peppered SHAKE-256 dedup hash (v2: device-held pepper) |
| `device_credential` | String (hex) | FIDO2/WebAuthn device public key |
| `vp_id` | String | TIP-ID of the issuing Verification Provider |
| `status` | String | `active` | `revoked_voluntary` | `revoked_vp` | `deceased` | `revoked_device` |
| `verified_at` | ISO 8601 | Verification timestamp |
| `attested` | Boolean | Whether social graph attestation was completed |

### 3.2 Four-Layer Biometric Verification Stack

Every TIP-ID is produced by a specific verification sequence. Each layer is mandatory unless specified otherwise.

**Layer 1: Government ID Verification**

The verification provider performs:
- OCR extraction of name, date of birth, ID number, and expiration date
- AI tamper detection (micro-printing, hologram, font consistency, edge artifacts)
- NFC chip verification for e-passports: ICAO digital signature verification against the issuing government's public key
- Cross-reference against issuing authority databases where available

**Layer 2: 3D Facial Liveness Detection**

A real-time challenge-response liveness check:
- Randomized facial movements required (head turns, blinks, smiles)
- Depth mapping (structured light or time-of-flight)
- Involuntary micro-expression analysis
- Skin texture frequency analysis
- Sub-dermal blood flow detection

The check produces a 512-dimensional facial embedding vector. This vector is immediately hashed via SHAKE-256 inside a secure hardware enclave. Only the hash leaves the device. The raw biometric data is destroyed and never transmitted.

Defeats: printed photo attacks, screen replay attacks, 2D deepfake attacks, silicone mask attacks, 3D-printed face model attacks.

**Layer 3: Device Biometric Binding (FIDO2/WebAuthn)**

The user's device secure enclave generates a cryptographic keypair:
- Apple: Touch ID / Face ID via Secure Enclave
- Android: Fingerprint / Face via Trusted Execution Environment (TEE)
- Windows: Windows Hello via TPM 2.0, or hardware security key (YubiKey, Google Titan)

The private key never leaves the hardware. The public key is bound to the TIP-ID. Re-authentication requires physical possession of the enrolled device.

**Layer 4: Social Graph Attestation (Optional)**

Three existing TIP-ID holders with trust scores ≥ 700 vouch for the new registrant. Each voucher stakes 25 trust points from their own score. If the new user commits origin misrepresentation within 90 days, each voucher loses the staked points.

Benefits of social attestation:
- Starting score: 550 (vs. 500 default)
- Trust accrual multiplier: 1.5× for the first 90 days
- Immediate jury participation eligibility

### 3.3 Deduplication Method (v2: Peppered)

**v1 (deprecated):** `dedup_hash = SHAKE-256(gov_id || dob || country || facial_hash)`

**v2 (current):** The device secure enclave generates a random 256-bit pepper at registration. The dedup hash becomes:

```
dedup_hash = SHAKE-256(gov_id || dob || country || facial_hash || pepper)
```

The pepper is generated by and held only in the user's device secure enclave. The pepper is never transmitted to the VP server or the DAG. Without the pepper, the hash cannot be recomputed even with full government database access, preventing nation-state reidentification attacks.

A zero-knowledge proof of uniqueness (ZK-SNARK) is published to the DAG instead of the hash. Any node can verify that the registrant is unique without accessing the hash.

---

## 4. Layer 2: TIP-CONTENT (Provenance)

### 4.1 Origin Declaration Categories

Every content registration requires a mandatory origin declaration. The system defines four mutually exclusive categories:

| Code | Label | Definition | Visual |
|------|-------|------------|--------|
| `OH` | Original Human | Created entirely by the uploader without AI generation tools. Traditional tools (Photoshop filters, color grading, spell-check) are permitted. | Blue shield |
| `AA` | AI-Assisted | Human primary author; AI tools used for enhancement or partial generation. The human is the primary creative agent. | Purple shield |
| `AG` | AI-Generated | AI primary creator; human role was prompting, curating, or minor editing. The AI is the primary creative agent. | Amber shield |
| `MX` | Mixed/Composite | Multiple sources, some human and some AI. Components must be individually annotated. | Gray shield |

**Edge Case Rulings:**

- Spell-check and grammar tools → OH
- AI autocomplete (>20% of content AI-suggested) → AA
- AI translation of human text → AA (ideas human, language AI)
- Heavily edited AI first draft (substance changed) → AA
- Lightly edited AI first draft (minor changes) → AG
- Computational photography (HDR, noise reduction) → OH

### 4.2 Content Registration Flow

**Step 1: Origin Declaration**  
User selects OH, AA, AG, or MX and cryptographically signs the declaration with their ML-DSA-65 private key. The signed declaration is a binding commitment.

**Step 2: AI Pre-Scan (v2: Calibrated Thresholds)**  
For OH-declared content, the system runs an AI content detection analysis. The detection threshold is calibrated per creator and per content type:

| Content Type | Default Threshold |
|-------------|------------------|
| Conversational | 0.82 |
| News/Journalistic | 0.85 |
| Creative Fiction | 0.87 |
| Academic/Technical | 0.92 |
| Legal/Formal | 0.93 |

Creator calibration:
- `T = T_baseline + min(H/200, 1.0) × (T_ceiling - T_baseline)`
- Where H = count of verified OH registrations
- Floor: 0.80 | Ceiling: 0.94

If content exceeds the calibrated threshold:
- Content is minted with status `PENDING` (flag-but-mint mechanism)
- Content enters Stage 1 adjudication automatically within 48 hours
- There is zero penalty for changing the declaration before minting

**Step 3: Dual Hash Computation**
- SHAKE-256 hash for exact content matching
- Perceptual hash (pHash for images, Chromaprint for audio) for fuzzy matching across reposts, transcoded versions, and minor modifications

**Step 4: CTID Generation**  
`tip://c/[ORIGIN]-[HASH14]-[ID_SHORT]`

- `ORIGIN`: The declared origin code (OH, AA, AG, or MX), embedded directly in the URI so that origin classification is visible in every reference, link, or citation.
- `HASH14`: First 14 hex characters of the SHAKE-256 hash of the raw content. This uniquely identifies the content.
- `ID_SHORT`: First 4 hex characters of the author's TIP-ID hash portion. For a TIP-ID of `tip://id/US-a3f8c91b2d4e7021`, the hash portion is `a3f8c91b2d4e7021` and ID_SHORT is `a3f8`. This links the CTID back to its author at a glance.

Example: For author `tip://id/US-a3f8c91b2d4e7021` registering original human content whose SHAKE-256 hash begins with `7f2a91bc3d5e4a...`, the CTID is `tip://c/OH-7f2a91bc3d5e4a-a3f8`.

**Step 4.5: Registered URL (MANDATORY)**

Every registration MUST include a `registered_url` — the canonical
permalink where the work is (or will be) published. This is a
**protocol-level requirement, not a UX convenience**. The registered
URL is stored on the DAG alongside the CTID, content hash, and
signature, and is what allows a viewer who encounters a CTID
elsewhere (a copy, a quote, an embedded reference) to locate the
original published version.

```
registered_url: string  // required
```

**Why mandatory:**

- Without `registered_url`, the trust badge can confirm "this CTID is
  registered" but offers the viewer no path back to the canonical
  source. That defeats one of the protocol's primary value props.
- The URL is included in the signed payload (see Step 5 below), so
  it cannot be retroactively spoofed without invalidating the
  signature.
- Implementations that ship a "register-CTID-before-publishing"
  workflow (where the CTID is signed before the URL exists, then
  embedded into the article body before publishing) MUST be retired.
  The correct workflow is: publish first → get permalink → register
  CTID → optionally edit the published copy to embed the CTID
  inline. The DAG accepts post-publish edits.

**Reference implementations:**

- `tip-browser-extension`: every TIP_TYPES and LC_TYPES entry sets
  `urlRequired: true`. Regression test
  `tests/news-required-fields.test.js → "TIP Protocol — URL is
  MANDATORY for every type"` asserts no type sets
  `urlRequired: false` anywhere.
- TIP node: `POST /v1/content/register` rejects requests where
  `registered_url` is missing or fails URL parse validation.

**Step 5: DAG Transaction**  
An ML-DSA-65 signature is computed over the SHAKE-256 hash of a canonical JSON object containing the author's identity, the content hash, the origin code, and the registered URL:

```
signature = ML-DSA-65.sign(
  privateKey,
  SHAKE-256(canonicalJson({
    "author_tip_id":   "tip://id/US-a3f8c91b2d4e7021",
    "content_hash":    "<SHAKE-256 hex hash of content>",
    "origin_code":     "OH",
    "registered_url":  "https://example.com/articles/the-original"
  }))
)
```

The `canonicalJson` function produces deterministic JSON with keys sorted alphabetically at all levels. This ensures that any conforming implementation (browser extension, mobile app, server) produces an identical byte sequence for the same inputs. The signature binds the author's identity, the content hash, and the origin declaration into a single cryptographic commitment. It is impossible to modify the origin code, substitute a different author, or alter the content hash without invalidating the signature.

**Step 6: Integration Artifact Generation**  
HTTP response headers and HTML meta tags are generated. Origin-aware visual badges are produced.

### 4.3 Adjudication Pipeline (Three Stages)

**Stage 1: AI Classifier Analysis (< 60 seconds)**  
Automated mismatch confidence score. Auto-escalate if > 90%. Auto-dismiss if < 30%. Cases 30-90% proceed to Stage 2.

**Stage 2: Human Jury Review (24-72 hours)**  
Seven TIP-ID holders with scores ≥ 700 independently review the case. The question posed: *"Does the declared origin materially match the content?"* This eliminates subjective editorial judgments.

**Stage 3: Expert Appeal Court (3-7 days)**  
Three domain experts conduct final review. Decision is recorded as an immutable DAG transaction.

### 4.4 Asymmetric Penalty Structure

| Offense | Score Impact | Escalation |
|---------|-------------|------------|
| Declared OH, confirmed AG (1st offense) | −100 | Warning; pre-scan recommended |
| Declared OH, confirmed AA (1st) | −40 | Warning |
| Declared AA, confirmed fully AG (1st) | −25 | Warning |
| Declared AG, actually human | 0 | No penalty. Conservative labeling is always safe. |
| 2nd offense | −200 | Account flagged; mandatory pre-scan |
| 3rd offense | −350 | Account suspended |

---

## 5. Layer 3: TIP-TRUST (Reputation)

### 5.1 Scoring Algorithm

The trust score is a deterministic integer (0-1000) computed from the complete DAG transaction history for a TIP-ID. Any protocol-compliant node, given the same DAG history, MUST compute the same score.

**Core invariant:** `score = f(sorted_dag_transactions_for_tip_id)`

| Event | Score Impact |
|-------|-------------|
| Initial registration (no attestation) | Start at 500 |
| Initial registration (with attestation) | Start at 550 |
| Content verified by community | +2 to +5 (weighted by verifier scores; daily cap) |
| Origin mismatch (1st offense) | −100 |
| Origin understated (1st) | −40 |
| Origin mismatch (2nd) | −200 |
| Origin mismatch (3rd) | −350 |
| Factual falsehood (separate from origin) | −75 to −300 |
| Successful appeal | +50% of lost points restored |
| 90-day clean record | +10 |

Bounds: Score is clamped to [0, 1000] at all times.

### 5.2 Trust Tier Visualization

| Score Range | Tier | Shield | Color |
|------------|------|--------|-------|
| 800-1000 | HIGHLY TRUSTED | ✓ | #1A8A5C (Green) |
| 600-799 | TRUSTED | ✓ | #2563A8 (Blue) |
| 400-599 | REVIEW ADVISED | ! | #A88B15 (Amber) |
| 200-399 | LOW TRUST | ✗ | #C07318 (Orange) |
| 0-199 | NOT TRUSTED | ✗ | #C53030 (Red) |

### 5.3 GDPR Score Visibility Modes (v2)

Users control their score visibility through three modes:

| Mode | What Is Shown | Default? |
|------|--------------|---------|
| `FULL_PUBLIC` | Numeric score (0-1000) and tier | No: explicit opt-in required |
| `TIER_ONLY` | Tier label only (e.g., "Trusted") | **Yes: default at registration** |
| `VERIFIED_ONLY` | Binary verified/unverified indicator only | No: maximum privacy |

Implementing parties MUST respect the user's chosen mode. Displaying a numeric score in TIER_ONLY mode is a GDPR violation.

---

## 6. Post-Quantum Cryptography

All cryptographic primitives are NIST-standardized post-quantum algorithms. Every conforming implementation MUST use these algorithms.

| Function | Algorithm | Standard | Key/Sig Size |
|----------|-----------|----------|-------------|
| Primary signatures | ML-DSA-65 (Dilithium) | FIPS 204 | PK: 1,952B, Sig: 3,309B |
| Root signatures | SLH-DSA-128s (SPHINCS+) | FIPS 205 | PK: 32B, Sig: 7,856B |
| Key encapsulation | ML-KEM-768 (Kyber) | FIPS 203 | PK: 1,088B |
| Hashing | SHAKE-256 / SHA-3 | FIPS 202 | 256-bit |

**Transition Period (Years 1-3):** Hybrid signatures using Ed25519 + ML-DSA-65 are permitted for backward compatibility. After Year 3, classical signatures are deprecated.

**Version Negotiation:** Nodes advertise their supported algorithm sets in the gossip handshake, analogous to TLS cipher suite negotiation.

---

## 7. Federated DAG Network

### 7.1 DAG Properties

- Each transaction references exactly 2 prior transactions (`prev[0]`, `prev[1]`)
- The genesis transaction has `prev = []` (the only exception)
- `tx_id = SHAKE-256(canonical_transaction_json)`
- Parallel transaction processing enables > 5,000 TPS
- Nodes gossip transactions to peers (no proof-of-work required)

### 7.2 Node Types

| Type | Role | Who Operates |
|------|------|-------------|
| Full Node | Complete DAG; independent verification | Enterprises, universities, NGOs |
| Light Node | Recent transactions + Merkle proofs | Browser extensions, mobile apps |
| VP Node | Full node + biometric hardware; issues TIP-IDs | Accredited Verification Providers |
| Archive Node | Complete DAG + historical snapshots | Academic institutions |

### 7.3 Transaction Types

| Type | Description |
|------|-------------|
| `REGISTER_IDENTITY` | New TIP-ID minted by an accredited VP |
| `CONTENT_REGISTERED` | New content provenance record |
| `CONTENT_VERIFIED` | Content confirmed by community verification |
| `CONTENT_DISPUTED` | Dispute filed against content origin declaration |
| `ADJUDICATION_RESULT` | Result of Stage 2 or Stage 3 adjudication |
| `SCORE_UPDATE` | Trust score delta applied |
| `REVOKE_VOLUNTARY` | User-initiated revocation |
| `REVOKE_VP` | VP-initiated revocation (fraud) with 90-day cascade |
| `REVOKE_DECEASED` | Death notification; identity archived permanently |
| `REVOKE_DEVICE` | Device credential compromised; identity preserved |
| `VP_REGISTERED` | New Verification Provider accredited |
| `MERKLE_ROOT` | Dedup registry Merkle root (published every 6 hours) |

### 7.4 Decentralization Roadmap

- **Phase 1 (Months 1-4):** Centralized coordinator operated by The AI Lab
- **Phase 2 (Months 4-8):** 21 elected validator nodes; The AI Lab holds 1 vote
- **Phase 3 (Month 8+):** Full decentralization when DAG density exceeds 100 TPS sustained

---

## 8. Verification Provider (VP) System

### 8.1 Accreditation Requirements

Any organization can become a VP by:
1. Implementing all four biometric verification layers with certified hardware
2. Passing an independent security audit (Trail of Bits, Bishop Fox, or equivalent)
3. Signing the TIP-VP Code of Conduct
4. Receiving accreditation from The AI Lab (accreditation@theailab.org)

### 8.2 VP Code of Conduct Requirements

| Obligation | Frequency | Absolute? |
|-----------|-----------|----------|
| Quarterly warrant canary | Quarterly | No (best-efforts) |
| Government request disclosure | Annual | No (to extent legally permitted) |
| No voluntary data sharing | Always | YES: absolute prohibition |
| Annual independent security audit | Annual | No |
| ZK dedup architecture | Always | No |
| Transparency register publication | Quarterly | No |
| Jurisdiction tier badge display (AMBER) | Per credential | No |

### 8.3 VP Categories

**Category A**: Identity-native organizations (iProov, Jumio, Yoti, Onfido, banks with existing KYC, national ID programmes)

**Category B**: Content platforms and journalism organizations (major publishers, CPJ, RSF, SPJ, journalism nonprofits)

**Category C**: Government digital identity programmes (EU eIDAS, UK DSIT, Estonia e-Residency)

**Category D**: Educational institutions (universities, colleges, research institutes)

---

## 9. Privacy Architecture (v2)

### 9.1 Peppered Deduplication Hash

```
pepper    = device_enclave.generate_random_256()
dedup_hash = SHAKE-256(gov_id || dob || country || facial_hash || pepper)

dag.publish(zk_proof_of_uniqueness(dedup_hash, dedup_registry))
```

The pepper is generated by the user's device secure enclave and never leaves the device. Without the pepper, the hash cannot be recomputed even with full government database access.

### 9.2 Dedup Registry Architecture

The peppered hashes are held in a dedicated deduplication registry service, separate from the public DAG. The registry performs exactly one function: answering "does this hash already exist?" with a ZK yes/no response.

### 9.3 Merkle Audit Root

The dedup registry publishes a Merkle root of its hash store to the public DAG every 6 hours. Any operator can verify that the number of stored hashes matches the number of registered TIP-IDs, confirming deduplication enforcement without accessing individual hash values.

---

## 10. GDPR Compliance (v2)

### 10.1 Legal Basis

A numeric trust score linked to a verified identity is personal data under GDPR Article 4(1). The original design made this score a permanent public record, directly conflicting with:
- Article 17 (right to erasure)
- Article 25 (data protection by design and by default)
- Article 35 (DPIA requirement for biometric processing)

### 10.2 DPIA Requirement

A Data Protection Impact Assessment (DPIA) is mandatory under GDPR Article 35(3)(b) before processing biometric data at scale. The DPIA must be published publicly before any European deployment.

### 10.3 Article 17 Erasure

Upon receiving an erasure request, the system:
1. Resets the user's trust score history
2. Removes event-level score data from queryable records
3. Preserves the TIP-ID and content provenance records on the DAG (required to maintain content integrity)
4. Records the erasure event as an immutable DAG transaction

The content provenance record (the binding of content to its creator) is preserved. The numeric reputation record is reset.

---

## 11. Jurisdiction Tiers (v2)

### 11.1 Three-Tier Classification

| Tier | Criteria | Badge Indicator |
|------|----------|----------------|
| GREEN | Strong rule of law, independent judiciary, no mandatory backdoor legislation | None: absence of AMBER means GREEN |
| AMBER | Moderate rule-of-law concerns, ambiguous/evolving data access laws, VP meets technical standard | Amber dot indicator on credential |
| RED | Mandatory government backdoor laws, mass surveillance infrastructure incompatible with TIP-VP Code | Cannot be accredited |

### 11.2 AMBER Indicator

When a VP operating in an AMBER-tier jurisdiction issues a TIP-ID, an amber indicator is displayed on the AI Trust ID Seal. Position: upper-left quadrant of the inner ring (mirroring the Founding Star at upper-right).

Color: #A88B15 (same amber used for REVIEW ADVISED tier: all signal caution).

Hover/tap disclosure: "Issued by a VP operating in an Amber-tier jurisdiction. More information: theailab.org/jurisdictions"

### 11.3 Warrant Canary

Every accredited VP must publish a quarterly signed statement confirming no compelled undisclosed government data access has occurred. Failure to publish within 90 days of the last canary is treated by the protocol as a triggered canary.

---

## 12. Identity Revocation (v2)

### 12.1 Revocation Transaction Types

| Type | Trigger | Cascade |
|------|---------|---------|
| `REVOKE_VOLUNTARY` | User request | None. Historical record preserved. |
| `REVOKE_VP` | VP found registration fraudulent | Content registered within 90 days auto-enters adjudication |
| `REVOKE_DECEASED` | Death certificate presented to VP | Permanent. Identity archived. No new registrations. |
| `REVOKE_DEVICE` | Device credential compromised | Score −15 pending re-verification. Identity preserved. |

### 12.2 REVOKE_VP Transaction Format

```json
{
  "tx_type":        "REVOKE_VP",
  "tip_id":         "tip://id/US-a3f8c91b",
  "reason_code":    "FRAUDULENT_REGISTRATION",
  "evidence_hash":  "SHAKE-256(evidence_document)",
  "issuing_vp_id":  "tip://id/VP-US-example",
  "signature":      "ML-DSA-65 signature by issuing VP"
}
```

---

## 13. Web Integration

### 13.1 HTTP Response Headers

```
TIP-Author:        tip://id/US-a3f8c91b2d4e7021
TIP-Content:       tip://c/OH-7f2a91bc3d5e4a-a3f8
TIP-Origin:        original-human
TIP-Trust-Score:   892
TIP-Tier:          HIGHLY_TRUSTED
TIP-Signature:     [ML-DSA-65 signature hex]
X-Powered-By:      TIP-Protocol/theailab.org
```

### 13.2 HTML Meta Tags

```html
<meta property="tip:author"    content="tip://id/US-a3f8c91b2d4e7021" />
<meta property="tip:content"   content="tip://c/OH-7f2a91bc3d5e4a-a3f8" />
<meta property="tip:origin"    content="original-human" />
<meta property="tip:score"     content="892" />
<meta property="tip:tier"      content="HIGHLY_TRUSTED" />
<meta property="tip:status"    content="VERIFIED" />
```

### 13.3 Badge Widget

```html
<script src="https://badge.theailab.org/tip-badge.min.js" defer></script>
<tip-badge tip-id="tip://id/US-a3f8c91b" size="120" variant="gold-dark"></tip-badge>
```

---

## 14. Visual Badge System

### 14.1 Dual Badge Architecture

The protocol uses two visually and legally distinct badge objects:

**Object 1: TIP Powered Mark (Open)**  
Displayed by any platform implementing TIP Protocol. Licensed under TIPCL-1.0 (converts to Apache 2.0 on January 1, 2031). No registration required. Arc text: "TRUST IDENTITY PROTOCOL" (top) and "OPEN SPEC · TIPCL-1.0" (bottom).

**Object 2: AI Trust ID Seal (Proprietary)**  
Issued by The AI Lab's registry to verified individuals. Cannot be self-applied. Features: gold metallic ring on navy background, tier-colored shield with status icon, numeric score, arc text "AI TRUST ID" and "AI TRUST REGISTRY". Colorways: Gold Dark (default), Light, Dark.

This separation mirrors the Bluetooth SIG model: open specification for broad adoption, controlled trademark for quality assurance.

---

## 15. Protocol Constants

```
PROTOCOL_VERSION:       "2.0"
CHAIN_ID:               "tip-mainnet-v2"
STARTING_SCORE:         500
ATTESTED_STARTING_SCORE: 550
MAX_SCORE:              1000
MIN_SCORE:              0
SOCIAL_ATTESTATION_BONUS: 50
VOUCHER_STAKE:          25
CLEAN_RECORD_DAYS:      90
CLEAN_RECORD_BONUS:     10
MERKLE_INTERVAL_HOURS:  6
DAG_MIN_REFS:           2
DISPUTE_AUTO_ESCALATE:  0.90
DISPUTE_AUTO_DISMISS:   0.30
PRESCAN_FLOOR:          0.80
PRESCAN_CEILING:        0.94
PRESCAN_DEFAULT:        0.85
```

---

## 16. Changelog

| Version | Date | Changes |
|---------|------|---------|
| v4.0 | March 2026 | v2 additions: peppered ZK dedup, adaptive pre-scan, multi-type revocation, GDPR score modes, jurisdiction tiers |
| v3.0 | March 2026 | Initial published specification (v1 design) |

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*  
*Licensed under Creative Commons Attribution 4.0 International (CC-BY 4.0)*  
*Attribution required: "TIP Protocol Specification by Dinesh Mendhe, The AI Lab Intelligence Unobscured, Inc. (theailab.org)"*
