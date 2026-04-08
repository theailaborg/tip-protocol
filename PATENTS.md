# Patent Disclosure

## Overview

This software implements inventions that are the subject of pending U.S. patent applications filed by Dinesh Mendhe and assigned to The AI Lab Intelligence Unobscured, Inc. ("The AI Lab"). This document discloses the patent applications and the inventions they cover.

## Pending Patent Applications

### First Provisional Application

**Title:** System and Method for Federated Identity Verification, Content
Provenance Declaration, and Deterministic Trust Scoring Using Post-Quantum
Cryptography on a Directed Acyclic Graph Network

**Filing Date:** March 12, 2026
**Inventor:** Dinesh Mendhe (Sole Inventor)
**Assignee:** The AI Lab Intelligence Unobscured, Inc.
**Status:** Provisional filed under 35 U.S.C. 111(b)

**Inventions covered (Claim Groups A-E):**

| Group | Invention |
|-------|-----------|
| A | Four-layer biometric verification stack for generating a globally unique federated digital identity, including the SHAKE-256 deduplication hash method |
| B | Mandatory origin declaration system with AI pre-scan safety mechanism, inseparable cryptographic origin binding, and asymmetric penalty structure |
| C | Deterministic trust scoring engine computed from DAG transaction history without a central authority |
| D | Dual-badge visual trust communication architecture: open protocol mark vs. registry-issued personal credential seal |
| E | Web integration via standard HTTP response headers and HTML meta tags requiring zero new software |

### Second Provisional Application

**Title:** System and Method for Federated Identity Verification, Content
Provenance Declaration, and Deterministic Trust Scoring Using Post-Quantum
Cryptography on a Directed Acyclic Graph Network, with Enhanced Privacy
Architecture, Adaptive Pre-Scan Calibration, Multi-Type Identity Revocation,
GDPR-Compliant Score Display, and Federated VP Jurisdiction Tier Classification

**Filing Date:** March 2026
**Inventor:** Dinesh Mendhe (Sole Inventor)
**Assignee:** The AI Lab Intelligence Unobscured, Inc.
**Status:** Provisional filed under 35 U.S.C. 111(b)

**Inventions covered (Claim Groups F-J):**

| Group | Invention |
|-------|-----------|
| F | Peppered ZK deduplication: device-held 256-bit pepper, zero-knowledge proof of uniqueness on DAG, Merkle root auditability every 6 hours |
| G | Adaptive creator-calibrated AI pre-scan with content-type thresholds (0.82-0.93), creator history calibration (floor 0.80, ceiling 0.94), and flag-but-mint mechanism |
| H | Multi-type identity revocation system with four distinct transaction types (VOLUNTARY, VP-INITIATED, DECEASED, DEVICE) and cascading content effects |
| I | GDPR-compliant score visibility system with three display modes, zero-knowledge score threshold proofs, and Article 17 erasure preserving provenance integrity |
| J | VP jurisdiction tier classification (GREEN/AMBER/RED) with mandatory AMBER badge indicator, RED accreditation refusal, and quarterly warrant canary system |

### Third Provisional Application

**Title:** System and Method for Canonical Content Normalization, Dual-Mode
Content Verification, Content Version Tracking, Standardized Content Scope
Extraction, Multi-Layer Verification Delivery, and Content-Type Extensible
Normalization Framework for a Federated Post-Quantum Content Provenance Protocol

**Application Number:** 64/031,648
**Confirmation Number:** 7072
**Filing Date:** April 7, 2026
**Inventor:** Dinesh Mendhe (Sole Inventor)
**Assignee:** The AI Lab Intelligence Unobscured, Inc.
**Status:** Provisional filed under 35 U.S.C. 111(b)
**Docket:** AILAB-2026-PROV-03

**Inventions covered (Claim Groups K-P):**

| Group | Invention |
|-------|-----------|
| K | Canonical Content Normalization Algorithm (CNA-1): six-step deterministic text normalization producing identical cryptographic hashes regardless of HTML formatting, Unicode encoding, or platform rendering. Three-hash architecture (canonical, exact, perceptual) with defined verification fallback flow. |
| L | Dual-Mode Content Verification: Publisher Mode (domain-bound, HTTP headers) vs. Creator Mode (hash-based DAG lookup, no headers). Timestamp excluded from signature payload. Mode-specific ML-DSA-65 signature construction. New hash-based content lookup API endpoint (GET /v1/content/by-hash/:hash). |
| M | Content Version Tracking: CONTENT_UPDATED transaction type with CORRECTION/UPDATE/RETRACTION semantics. Version-chain verification. Origin code mutability rules per change type. Retraction scoring (-50 per retraction). |
| N | Standardized Content Scope Extraction: four-priority content boundary detection (publisher-declared data-tip-content attribute, JSON-LD articleBody, HTML5 semantic elements, algorithmic fallback). New tip-content-selector meta tag. |
| O | Multi-Layer Verification Delivery: five-layer architecture (publisher-rendered web component, platform-native meta tags, browser extension, mobile share-to app, URL-based zero-install verification service). |
| P | Content-Type Extensible Normalization Framework: normalization_version field enabling future content types (CNA-IMG-1, CNA-VID-1, CNA-AUD-1, CNA-MIX-1) without protocol upgrade. Perceptual hashing for recompressed media. |

## Non-Provisional Filing

A non-provisional patent application claiming priority to all three
provisional applications is planned for filing before March 12, 2027.
The non-provisional will include formal claims for all sixteen claim
groups (A-P).

## Patent License

See [LICENSE.txt](./LICENSE.txt) Section 8 for the patent license terms
included with TIPCL-1.0:

- **Free Use:** Royalty-free patent license for Compliant Implementations
  qualifying for Free Use under TIPCL-1.0 Section 2.1.
- **Commercial Use:** Patent license included in the Commercial License.
  Contact licensing@theailab.org.

## Defensive Termination

If you institute patent litigation against The AI Lab or any contributor
alleging that this software infringes a patent, your patent license under
TIPCL-1.0 terminates immediately.

## Contact

Patent licensing inquiries: legal@theailab.org
The AI Lab Intelligence Unobscured, Inc.
131 Continental Dr, Suite 305, Newark, DE 19713
theailab.org

---

*This patent disclosure is provided for informational purposes and does not
constitute legal advice. The scope of patent rights is determined solely by
the claims of any patent that may issue from these applications.*
