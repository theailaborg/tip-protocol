# Verification Provider (VP) Accreditation Guide

A Verification Provider (VP) is an organisation accredited by The AI Lab Intelligence Unobscured, Inc. ("The AI Lab") to issue TIP-IDs on the TIP Protocol network. This guide explains who can become
a VP, what is required, and how to apply.

---

## Who Should Become a VP

**Category A: Identity-native organisations**  
Banks with existing KYC infrastructure, biometric identity companies (iProov,
Jumio, Yoti, Onfido, Incode), telecom operators with SIM-based identity
services, national ID programmes.

**Category B: Content platforms and journalism organisations**  
Major news publishers, journalism nonprofits (CPJ, RSF, SPJ), fact-checking
organisations, content authentication platforms.

**Category C: Government digital identity programmes**  
EU eIDAS nodes, UK DSIT, Estonia e-Residency, national digital ID schemes.

**Category D: Educational institutions**  
Universities, colleges, and research institutes.

---

## What a VP Can Do

Once accredited, a VP can:

- Issue TIP-IDs to verified individuals through the four-layer biometric stack
- Run a VP Node (a full node with biometric hardware integration)
- View the ZK dedup registry for deduplication checks (yes/no only: not the hashes)
- Sign REGISTER_IDENTITY transactions with the VP's ML-DSA-65 keypair
- Display the "Accredited VP" mark on their products

A VP node participates in the full network: it gossips, validates, and stores
the complete DAG. Issuing TIP-IDs is the additional capability that requires
accreditation.

---

## Accreditation Requirements

### 1. Technical Requirements

- Implement all four biometric verification layers per the TIP Protocol Specification v4.0
- Deploy on hardware that includes: a FIDO2/WebAuthn authenticator, an HSM for the
  VP signing key (never software-stored), and a secure enclave for pepper generation
- Run a full TIP node (Node.js or Python reference implementation)
- Implement the ZK dedup architecture (v2 FIX-02): peppered hashes, ZK proofs on DAG
- Response time: complete identity verification within 3 minutes for 95% of users
- Uptime SLA: 99.5% availability for the VP node endpoint

### 2. Security Audit

Engage one of the following firms for an independent security audit covering:

- Biometric data handling pipeline
- Pepper generation and storage architecture
- ZK proof implementation
- Network security of the VP node
- Key management and HSM configuration

Approved audit firms: Trail of Bits, Bishop Fox, Cure53, NCC Group, or equivalent
with demonstrated experience in cryptographic systems. The full audit report
must be shared with The AI Lab and published publicly.

### 3. Code of Conduct

Sign the TIP-VP Code of Conduct. Key commitments:

| Obligation | Frequency |
|-----------|-----------|
| Publish quarterly warrant canary | Every 90 days |
| Disclose government data requests (aggregate) | Annually |
| Commission and publish independent security audit | Annually |
| Maintain transparency register | Quarterly |
| Zero voluntary data sharing | Absolute, permanent |
| ZK dedup architecture | Ongoing |

Full Code of Conduct: theailab.org/vp-code-of-conduct

### 4. Jurisdiction Assessment

The AI Lab will assess the jurisdiction tier (GREEN/AMBER/RED) based on:

- Strength of rule of law and judicial independence
- Existence of mandatory backdoor or data retention legislation
- Mass surveillance infrastructure
- Alignment with the VP Code of Conduct obligations

GREEN-tier VPs: no badge indicator added to issued credentials  
AMBER-tier VPs: amber indicator displayed on every issued AI Trust ID Seal  
RED-tier jurisdictions: cannot be accredited (VP accreditation refused)

---

## Application Process

### Step 1: Express Interest

Email accreditation@theailab.org with:
- Organisation name and category (A/B/C)
- Country of incorporation and countries of operation
- Brief description of your existing identity infrastructure
- Estimated volume of verifications per month

### Step 2: Technical Review (4-6 weeks)

The AI Lab technical team reviews your biometric stack implementation.
You will receive a detailed technical assessment and a list of any required
changes.

### Step 3: Security Audit (4-8 weeks)

Commission an independent security audit using an approved firm. Share the
full report with The AI Lab.

### Step 4: Legal Review and Code of Conduct Signing (2-3 weeks)

Review and sign the TIP-VP Code of Conduct and the VP Service Agreement.
The agreement covers: audit rights, revocation conditions, liability, and
SLA commitments.

### Step 5: Accreditation and Integration (1-2 weeks)

The AI Lab:
- Registers your VP keypair on the DAG
- Provides your VP ID (e.g., `tip://id/VP-US-yourorg`)
- Adds your VP to the network's known-good list
- Provides integration support for your first 100 identity registrations

**Total timeline: approximately 8-16 weeks from application to launch.**

---

## VP Accreditation Fees

| Category | Annual Accreditation Fee | Notes |
|---------- |-------------------------|-------|
| Category D (Education) | None | Free for universities, colleges, and research institutes |
| Category C (Government) | None | Free for government programmes |
| Category B (Journalism/NGO) | None | Free for journalism and press freedom organisations |
| Category A (< 10,000 verifications/month) | $5,000/year | Starter tier |
| Category A (10,000-100,000/month) | $15,000/year | Growth tier |
| Category A (100,000+/month) | $40,000/year | Enterprise tier |

Fees fund the VP audit programme, warrant canary infrastructure, and DAG
operations. The AI Lab does not profit from VP fees: they are cost-recovery only.

---

## Revocation Conditions

VP accreditation is revoked immediately if:

- The VP is found to have voluntarily shared user data with any third party
- A triggered warrant canary is not remedied within 30 days
- The annual security audit reveals a critical unmitigated vulnerability
- The VP issues TIP-IDs without completing all four biometric layers
- The VP operates in a jurisdiction reclassified to RED tier

---

## Apply

accreditation@theailab.org  
theailab.org/accreditation  
The AI Lab Intelligence Unobscured, Inc.

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc. | TIPCL-1.0*
