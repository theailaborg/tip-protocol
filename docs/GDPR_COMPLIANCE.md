# GDPR Compliance Architecture

TIP Protocol v2.0 was redesigned from the ground up to comply with GDPR
requirements for biometric data processing and personal trust score management.
This document describes the privacy architecture for implementors and DPOs.

---

## Data Classification

| Data Type | Classification | Processing Basis | Retention |
|-----------|---------------|-----------------|-----------|
| Facial scan (raw) | Biometric (GDPR Art. 9 special category) | Explicit consent | Destroyed immediately in device enclave: never stored |
| Biometric hash | Special category | Explicit consent | Device-held pepper prevents reidentification |
| Government ID number | Personal | Explicit consent | Used for dedup only; not stored on DAG |
| TIP-ID (tip://id/…) | Pseudonymous personal | Consent | DAG: permanent but pseudonymous |
| Trust score | Personal | Legitimate interest / Consent | Erasable per Art. 17 |
| Score event history | Personal | Consent | Erasable per Art. 17 |
| Content provenance record | Personal | Consent | Permanent: content authenticity depends on it |
| Dedup hash (peppered) | Special category | Consent | Dedup registry only; ZK proof on DAG |

---

## Legal Basis for Processing

### Identity Registration

**Processing basis:** Explicit consent (GDPR Art. 6(1)(a) + Art. 9(2)(a))

Required consent statements at registration:
- Consent to biometric verification (explicit, separate from general terms)
- Consent to publication of pseudonymous TIP-ID on public DAG
- Consent to trust score computation from public DAG history
- Consent to score visibility mode (default: TIER_ONLY)

### Content Provenance

**Processing basis:** Contract performance (GDPR Art. 6(1)(b))

When a user registers content, they are signing a provenance record. The
binding of their TIP-ID to the content hash is essential to the contract
they are entering with the protocol. This cannot be erased without destroying
the content record's authenticity guarantee.

---

## Article 25: Data Protection by Design

TIP Protocol v2 implements GDPR Art. 25 data minimisation at the technical level:

**Default score visibility: TIER_ONLY**
At registration, every TIP-ID is assigned `TIER_ONLY` score visibility.
This means external parties can only see "Trusted" or "Review Advised":
not the numeric score. Users must actively opt into `FULL_PUBLIC` visibility.

**No raw biometrics transmitted**
The facial scan is processed entirely inside the device's secure enclave.
The raw biometric data is destroyed before any network transmission occurs.
Only a SHAKE-256 hash of the 512-dimensional facial embedding leaves the device.

**Peppered dedup hash (v2)**
The dedup hash includes a device-held 256-bit pepper. Without the pepper,
the hash cannot be recomputed even with access to the underlying biometric
data. This prevents nation-state reidentification attacks on the public DAG.

---

## Article 17: Right to Erasure

TIP Protocol distinguishes between two types of personal data with different
erasure approaches:

### Erasable: Trust Score History

Upon a valid Art. 17 erasure request:
1. The user's numeric trust score history is reset
2. Event-level score records are removed from queryable APIs
3. An erasure transaction is written to the DAG (immutable record of the erasure)
4. The score is reset to 500 (unattested starting score)

The TIP-ID URI itself is not erased: it remains on the DAG as a pseudonymous
identifier. Only the score history attached to it is reset.

### Non-erasable: Content Provenance Records

Content provenance records (CTIDs) bind specific content to a declared origin.
Erasing these records would destroy the authenticity guarantee for published
content that may be cited, verified, or relied upon by third parties.

Users are clearly informed at registration that content provenance records
are permanent. This is analogous to how a published article's byline cannot
be retroactively removed from the historical record without destroying the
integrity of citations to that article.

If a user objects to a content record, the protocol provides:
- A declaration of inaccuracy flag (without deletion)
- Dispute and adjudication process for incorrect origin classifications

---

## Article 35: Data Protection Impact Assessment (DPIA)

Processing biometric data at scale requires a DPIA under GDPR Art. 35(3)(b).

**DPIA must be completed and published before:**
- Any deployment that processes biometric data from EU/EEA residents
- Any deployment that processes trust score data visible to third parties in the EU

**The DPIA must cover:**
- Biometric verification pipeline (all four layers)
- Peppered dedup hash architecture
- ZK proof publication on DAG
- Score visibility controls
- Cross-border data transfer (if VP nodes are located outside the EU)
- Data subject rights implementation (Art. 15-22)

The AI Lab Intelligence Unobscured, Inc. will publish its own DPIA at theailab.org/dpia before European launch.
Accredited VPs operating in the EU must complete and publish their own DPIAs.

---

## Article 37: Data Protection Officer

The AI Lab is required to appoint a DPO under GDPR Art. 37(1)(b) (large-scale
processing of special category data).

DPO contact: dpo@theailab.org

Accredited VPs processing biometric data from EU residents should assess whether
they also require a DPO under Art. 37.

---

## Data Transfers Outside the EU

The DAG is a public federated network. DAG transactions (including TIP-IDs and
CTIDs) are replicated to all nodes globally. Since TIP-IDs are pseudonymous and
do not contain personal data in the traditional sense (no name, address, or
identifiable information), their publication on a global DAG is consistent with
the pseudonymisation provisions of GDPR Art. 25.

However: if a TIP-ID is linked to an identifiable person through a separate
mechanism (e.g., a news organisation publishing "Journalist X's TIP-ID is..."),
it becomes personal data in context. Implementors should advise users accordingly.

---

## Data Subject Rights Implementation

Implementors must provide UI flows for:

| Right | Implementation |
|-------|---------------|
| Art. 15: Access | API endpoint to export all data associated with a TIP-ID |
| Art. 16: Rectification | Process to update incorrectly recorded biometric data |
| Art. 17: Erasure | Score history reset flow (see above) |
| Art. 18: Restriction | Ability to temporarily restrict score visibility to VERIFIED_ONLY |
| Art. 20: Portability | Export TIP-ID keypair, score history, and content records as JSON |
| Art. 21: Objection | Process to object to specific score events via adjudication |

---

## Incident Response

Any breach involving biometric data must be reported to the supervisory
authority within 72 hours (GDPR Art. 33).

The AI Lab's incident response contact: security@theailab.org

Accredited VPs must notify The AI Lab of any security incident affecting
biometric data within 24 hours of discovery.

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc. | TIPCL-1.0*  
*This document is informational and does not constitute legal advice.*  
*Consult a qualified GDPR practitioner before European deployment.*
