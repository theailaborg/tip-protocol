# Changelog

All notable changes to TIP Protocol are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [Unreleased]

Changes that are merged to `main` but not yet in a tagged release will
appear here.

---

*For the full commit history, see the Git log.*  
*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*
