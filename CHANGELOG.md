# Changelog

All notable changes to TIP Protocol are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

**Third Provisional Patent Filed (April 7, 2026)**
- Application Number: 64/031,648 (Confirmation: 7072, Docket: AILAB-2026-PROV-03)
- Six new claim groups (K-P) covering content normalization, dual-mode
  verification, content versioning, content scope extraction, multi-layer
  verification delivery, and extensible normalization framework

**Claim Group K: Canonical Content Normalization (CNA-1)**
- Six-step deterministic text normalization algorithm producing identical
  cryptographic hashes regardless of HTML formatting, Unicode encoding,
  whitespace handling, or typographic conventions
- Three-hash architecture: canonical hash (primary verification), exact hash
  (forensic audit), perceptual hash (near-copy detection at 90% threshold)
- CTID derivation from canonical hash ensures identical content always
  produces the same CTID across platforms

**Claim Group L: Dual-Mode Content Verification**
- Publisher Mode: domain-bound ML-DSA-65 signature with 5 HTTP headers
- Creator Mode: hash-based DAG lookup for creators on platforms they do not
  control (X.com, Facebook, YouTube). No HTTP headers needed.
- Timestamps excluded from signature payload in both modes (eliminates
  timezone and registration-to-publication gap fragility)
- New API endpoint: GET /v1/content/by-hash/:canonicalHash (19th endpoint)

**Claim Group M: Content Version Tracking**
- CONTENT_UPDATED DAG transaction type with three mutation semantics:
  CORRECTION (preserves CTID and origin code), UPDATE (permits origin code
  change), RETRACTION (marks withdrawn, -50 trust score)
- Version-chain verification: checks all versions before perceptual fallback
- CONTENT_SYNDICATED transaction type for authorized republication

**Claim Group N: Content Scope Extraction**
- Four-priority content boundary detection: (1) data-tip-content HTML
  attribute, (2) JSON-LD articleBody, (3) HTML5 semantic elements,
  (4) Readability algorithm fallback
- New HTML meta tags: tip-content-selector, tip-content-title
- New data attribute: data-tip-content="true"

**Claim Group O: Multi-Layer Verification Delivery**
- Five-layer progressive architecture: (1) publisher-rendered <tip-badge>
  web component, (2) platform-native meta tags (tip:author, tip:ctid,
  tip:origin), (3) browser extension, (4) mobile share-to verification app,
  (5) URL-based zero-install verification service

**Claim Group P: Extensible Normalization Framework**
- normalization_version field in content registration transaction
- Defined identifiers: CNA-1 (text), CNA-IMG-1 (images), CNA-VID-1 (video),
  CNA-AUD-1 (audio), CNA-MIX-1 (mixed media)
- New algorithms deployable without protocol upgrade

**Security Architecture: Key Protection Chain**
- Documented PRF-to-AES key protection chain for ML-DSA-65 private key:
  Secure Enclave ECDSA P-256 -> PRF (biometric-gated) -> SHAKE-256 ->
  AES-256 key -> AES-256-GCM encrypts ML-DSA-65 private key at rest
- ECDSA never signs content; it only gates the PRF
- Browser extension uses dual signature (Ed25519 + ML-DSA-65), both in
  software, Secure Enclave protects master seed at rest

**Trust Tier Overhaul**
- Updated trust tier ranges and names:
  850-1000 Highly Trusted (#1A8A5C), 650-849 Trusted (#2563A8),
  400-649 Verified (#C9A84C), 200-399 Caution (#C07318),
  0-199 Not Trusted (#C53030)
- New user at score 500 now lands in Verified tier (gold badge, checkmark)
  instead of the previous Review Advised tier (warning icon)
- 100-point buffer before dropping to Caution tier
- Shield icons: checkmark for >= 400, warning triangle for 200-399, X for 0-199

**Verification Result Cards**
- New rectangular verification card system for browser extension and web
  component detail panels
- Nine status types: verified (Publisher Mode), verified-syndicated,
  verified-creator, verified-corrected, verified-updated, republished (amber),
  mismatch (red), retracted (red), none (gray)
- Data-driven SVG renderer with dynamic height, score pills, origin pills,
  domain indicators, and accent-colored TIP PROTOCOL watermark

**Badge Library v8 (tip-badges repository)**
- 11 badge categories, 393+ pre-generated SVGs
- New no-score seal and registry badge variants
- React component (TipBadge) with 12 variants and live API fetch
- Web component (<tip-badge>) with Shadow DOM
- React VerificationCard component
- npm package: @theailab/tip-badges

**REST API**
- Added 19th endpoint: GET /v1/content/by-hash/:canonicalHash for Creator
  Mode hash-based content lookup

**DAG Transaction Types**
- Added: CONTENT_UPDATED (content versioning with typed mutations)
- Added: CONTENT_SYNDICATED (authorized republication across domains)

### Changed

- Browser extension moved to separate repository (tip-extension) for
  independent release cycles and Chrome Web Store compliance

---

## [2.0.0]: 2026-03-15

### Initial public release: TIP Protocol v2.0

This is the first public release of the TIP Protocol Reference Implementation.
It includes all five v2 architectural improvements over the original design.

### Added

**FIX-02: Privacy Architecture (Claim Group F)**
- Peppered SHAKE-256 deduplication hash: device-held 256-bit pepper prevents
  nation-state reidentification attacks against the public DAG
- Zero-knowledge proof of uniqueness published to DAG instead of raw hash
- Separate dedup registry service with ZK yes/no interface
- Merkle root published to DAG every 6 hours for public audit without
  exposing individual hashes

**FIX-03: Adaptive Pre-Scan Calibration (Claim Group G)**
- Creator-calibrated AI detection thresholds derived from DAG history
  (floor 0.80, ceiling 0.94: no account bypasses the scan)
- Content-type thresholds: conversational 0.82, news 0.85, creative 0.87,
  academic 0.92, legal/formal 0.93
- Flag-but-mint mechanism: content exceeding threshold is minted with PENDING
  status and enters Stage 1 adjudication automatically
- Replaces the fixed 0.85 threshold from v1 design

**FIX-05: Multi-Type Identity Revocation (Claim Group H)**
- Four distinct revocation transaction types: REVOKE_VOLUNTARY, REVOKE_VP,
  REVOKE_DECEASED, REVOKE_DEVICE
- REVOKE_VP: 90-day cascade: content registered within 90 days auto-enters
  Stage 1 adjudication
- REVOKE_DECEASED: permanent ARCHIVED status, all active jury commitments
  dissolved with no score impact
- REVOKE_DEVICE: identity preserved, score reduced -15 pending re-verification

**FIX-06: GDPR Score Visibility (Claim Group I)**
- Three score display modes: FULL_PUBLIC, TIER_ONLY (default), VERIFIED_ONLY
- TIER_ONLY is the default at registration per GDPR Article 25 data
  minimisation by design
- Zero-knowledge score threshold proof (proves score is above/below a
  threshold without revealing the number)
- GDPR Article 17 erasure: score history reset while preserving content
  provenance records on the DAG
- Four TierChip display modes: full, score, tier, dot, verified-only

**FIX-08: VP Jurisdiction Tier Classification (Claim Group J)**
- Three-tier jurisdiction classification: GREEN, AMBER, RED
- AMBER badge indicator on AI Trust ID Seal for AMBER-tier VP credentials
- RED-tier jurisdictions cannot receive VP accreditation
- Quarterly warrant canary requirement for all VPs
- VP Transparency Register (quarterly disclosure)

**Reference implementations:**
- Python node: 23 files, 6,170+ lines, 201/201 tests passing
- Node.js node: 24 files, 6,951 lines, 43/43 tests passing
- Browser extension: Manifest V3, Chrome and Firefox
- `<tip-badge>` web component
- SDK (JavaScript)
- CLI tools

**Interface v4:**
- 37 components, 3,212 lines
- 6-tab badge gallery
- 4 leadership admin pages (Command Center, Responsibility Matrix,
  VP Strategy, Genesis Ring)
- Public and admin split with auth gate

### Known Limitations (Blocking Before Production Deployment)

The following items are known stubs that MUST be replaced before deploying
with real user data. They are documented here for full transparency:

- **[BLOCKING-B1]** ML-DSA-65 implementation uses Ed25519 as a same-API
  development stand-in. Replace with @noble/post-quantum or liboqs before
  processing any real biometric data.

- **[BLOCKING-B2]** ZK proof uses a Pedersen-style commitment stub. Replace
  with snarkjs/Groth16 or arkworks before the dedup privacy guarantee is
  real.

- **[BLOCKING-B3]** Genesis root keypair (SLH-DSA-128s) must be moved to
  cold storage HSM with two-of-three custodian policy before network launch.
  The development genesis.json must be deleted and regenerated with the
  production key.

- **[BLOCKING-B4]** Default secrets (TIP_JWT_SECRET, TIP_ADMIN_API_KEY) in
  .env.example must never be used in production. Generate cryptographically
  random 256-bit values.

- **[BLOCKING-B5]** GDPR DPIA must be completed and published before any
  European deployment.

- **[BLOCKING-B6]** Data Protection Officer must be appointed before any
  European deployment.

These are not security vulnerabilities: they are documented development
stubs with clear replacement instructions. See Command Center in the admin
interface for the complete pre-launch checklist.

---

*For the full commit history, see the Git log.*
*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*
