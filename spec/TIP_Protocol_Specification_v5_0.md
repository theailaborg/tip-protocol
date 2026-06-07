# TIP Protocol Specification

**Trust Identity Protocol · Public Technical Specification**

**Version 5.0**

**Effective Date: June 1, 2026**

**Status: Canonical. Supersedes v4.0 (March 2026), v3.0 (March 2026), and all earlier drafts.**

---

**Issued by:**

The AI Lab Intelligence Unobscured, Inc.
131 Continental Dr, Suite 305, Newark, Delaware 19713, United States
https://theailab.org

**Author and Inventor:** Dinesh Mendhe, Founder and Chairman, The AI Lab Intelligence Unobscured, Inc.

**License of this Specification:** Creative Commons Attribution 4.0 International (CC-BY 4.0). Free to read, implement, share, and adapt with attribution.

**Required Attribution:** "TIP Protocol Specification by Dinesh Mendhe, The AI Lab Intelligence Unobscured, Inc. (theailab.org)"

**License of the Reference Implementation:** TIP Community License Version 1.0 (TIPCL-1.0). The reference implementation is a distinct work from this specification. The reference implementation converts to Apache License 2.0 on January 1, 2031.

**Trademarks:** Trust Identity Protocol(TM), TIP(TM), AI Trust Council(TM), AI Trust Registry(TM), AI Trust ID(TM), The Global Seal of Trust(TM), Sentinel(TM), Guardian(TM), Sovereign(TM), and The AI Lab(TM) are trademarks of The AI Lab Intelligence Unobscured, Inc. The CC-BY 4.0 license of this specification does not grant any license to these trademarks. Trademark use is governed separately by https://theailab.org/brand-guidelines.

**Patents:** This specification describes inventions covered by United States provisional patent applications filed by The AI Lab Intelligence Unobscured, Inc. covering Claim Groups A through P. A royalty-free patent license under the published patent claims is granted to every implementation that complies with this specification, terminable on defensive grounds as described in TIPCL-1.0 Section 8. See https://theailab.org/tip-license.

---

## Abstract

The Trust Identity Protocol (TIP) is an open, federated, post-quantum cryptographic standard that establishes a verifiable trust layer for the internet. The protocol binds digital content to verified human identities through a layered architecture: a portable identity record (TIP-ID), a content provenance record (TIP-CONTENT, addressed by CTID), and a deterministic reputation score (TIP-TRUST). Every interaction is recorded on a federated Directed Acyclic Graph (DAG) using cryptographic transactions signed under NIST-standardized post-quantum primitives (FIPS 203, 204, 205) and hashed with SHAKE-256 (FIPS 202). TIP solves the converging challenges of synthetic media authenticity, AI content disclosure, and verified human identity in a single jurisdiction-agnostic standard that is designed to satisfy the EU AI Act Article 50 transparency obligations effective August 2, 2026, the California AI Transparency Act effective January 1, 2026, the UK Online Safety Act, the Colorado AI Act effective June 30, 2026, the China Generative AI Provisions, and analogous frameworks in nine other jurisdictions covered in Section 19 of this specification.

This specification is published under Creative Commons Attribution 4.0 International. Any party may read, implement, share, or adapt the specification, provided attribution is preserved. Implementations following this specification are eligible for a royalty-free patent license under the published patent claims. The reference implementation is licensed separately under TIP Community License 1.0 (TIPCL-1.0). The TIP brand and trademarks remain reserved to The AI Lab Intelligence Unobscured, Inc.

## Status of This Document

This document is **Version 5.0** of the Trust Identity Protocol Specification, effective June 1, 2026. It is the canonical reference for any organization implementing or integrating the protocol. It supersedes all earlier versions.

### Operational Status

The protocol's reference implementation has been operating in a **full-workflow pilot deployment since April 7, 2026**. The pilot integrates the reference TIP node, the TIP browser extension, the TIP Verification Provider mobile web application, the TIP WordPress plugin, the badge widget, and the federated DAG. The pilot has validated end-to-end content registration, the 8-field canonical signed payload, the CNA-2.2 normalization round-trip across publishing platforms, the 19-endpoint REST API surface, the WebAuthn device binding flow, the four-layer biometric verification stack, the peppered zero-knowledge deduplication, the trust score derivation, and the default-enabled community adjudication mechanism (Reviewer, Juror, Expert Panelist roles). The operational experience from April 7, 2026 through the date of this document, together with two prior years of implementation development, is what this Version 5.0 specification documents.

The protocol is therefore not a paper design at the date of this document's publication. It is an operating system whose mechanics have been observed in production, whose behavior has been measured under real load, and whose security posture has been tested in the field. Version 5.0 is the canonical written record of an already-operational protocol, not a forward-looking proposal.

### What Version 5.0 Adds

Version 5.0 incorporates two years of implementation experience across the reference TIP node, the TIP browser extension, the TIP Verification Provider mobile web application, the TIP WordPress plugin, and the federated network pilot. Specifically, Version 5.0 expands the protocol to cover:

1. **CNA-2.2 canonical content normalization** with the ten-step algorithm including TIP artifact stripping (Step 0) for verification round-trip correctness
2. **The 8-field canonical signed payload** that every content registration uses (attribution_mode, authors, cna_version, content_hash, extras, origin_code, registered_urls, signer_tip_id)
3. **Mandatory `registered_url` field** in every content registration, replacing the optional treatment in v4.0
4. **The full 29-transaction-type taxonomy** including KEY_RECOVERY, BIND_DOMAIN, PRESCAN_REVIEW lifecycle, COMMITTEE_ROTATION, and INTEREST_REGISTERED, replacing v4.0's 12-type listing
5. **The 19-endpoint REST API** with method, path, request shape, response envelope, and error codes
6. **Publisher Mode and Creator Mode** dual attribution semantics under CNA-2.2
7. **Default-enabled community adjudication** with explicit opt-out, replacing the v4.0 ambiguity around opt-in
8. **Canonical copy-paste fallback format** (`tip://c/{ctid}\nClick to find out #HumanOrAI`) for content sharing on platforms without TIP plugin support
9. **EU AI Act Article 50 compliance mapping** with the August 2, 2026 effective date
10. **The dual badge architecture** (TIP Powered Mark vs. AI Trust ID Seal) with explicit governance rules
11. **The expanded 46-locale support requirement** for protocol-compliant clients
12. **The genesis ring, jurisdiction tier classification, and warrant canary obligations** with quarterly cadence

Version 5.0 also reorganizes the document into nine Parts with stable section numbering and adds an IANA Considerations section registering the `tip://` URI scheme.

Future changes to this specification are governed by the RFC process in Section 21. Material changes require a thirty-day public comment period and a ninety-day testnet deployment before adoption.

## Table of Contents

**Part I · Introduction and Terminology**
- Section 1: Introduction and Motivation
- Section 2: Conformance, Conventions, and Requirements Language
- Section 3: Terminology and Definitions

**Part II · Architecture**
- Section 4: Three-Layer Architecture Overview
- Section 5: Design Principles
- Section 6: Federated Trust Model

**Part III · Cryptographic Primitives**
- Section 7: Algorithms and Key Sizes
- Section 8: Canonical JSON Encoding
- Section 9: Signing Math and the ASCII-Hex Rule
- Section 10: Hashing and Pepper Architecture
- Section 11: Hybrid Transition Period and Algorithm Negotiation

**Part IV · TIP-ID Identity Layer**
- Section 12: TIP-ID URI Format and Data Model
- Section 13: Four-Layer Biometric Verification Stack
- Section 14: Peppered Zero-Knowledge Deduplication
- Section 15: Device Binding and Key Recovery
- Section 16: Social Graph Attestation

**Part V · TIP-CONTENT Provenance Layer**
- Section 17: Origin Codes
- Section 18: CTID URI Format
- Section 19: CNA-2.2 Canonical Content Normalization Algorithm
- Section 20: The 8-Field Canonical Signed Payload
- Section 21: Content Registration Flow
- Section 22: Copy-Paste Fallback and Cross-Platform Sharing
- Section 23: Publisher Mode and Creator Mode
- Section 24: Edge Case Rulings for Origin Classification

**Part VI · TIP-TRUST Reputation Layer**
- Section 25: Deterministic Trust Score Computation
- Section 26: Trust Tiers and Visualization
- Section 27: Score Visibility Modes
- Section 28: Adjudication Pipeline (Three Stages)
- Section 29: Community Adjudication Roles
- Section 30: Scoring Constants and Asymmetric Penalty Structure

**Part VII · Federated DAG and Verification Provider System**
- Section 31: DAG Structure and Transaction Format
- Section 32: The Twenty-Nine Transaction Types
- Section 33: Genesis Block
- Section 34: Node Types
- Section 35: Verification Provider Categories and Accreditation
- Section 36: Jurisdiction Tiers and Warrant Canary
- Section 37: Identity Revocation

**Part VIII · APIs, Web Integration, and Reference Clients**
- Section 38: REST API Surface
- Section 39: HTTP Response Headers
- Section 40: HTML Meta Tags
- Section 41: Badge Widget Embedding
- Section 42: Browser Extension Reference Behavior
- Section 43: Verification Provider Mobile Web Application Reference Behavior
- Section 44: WordPress Plugin Reference Behavior

**Part IX · Compliance, Governance, and Considerations**
- Section 45: EU AI Act Article 50 Compliance Mapping
- Section 46: GDPR Compliance
- Section 47: Global AI Regulation Landscape
- Section 48: Dual Badge Architecture
- Section 49: AI Trust Council Governance
- Section 50: RFC Process
- Section 51: Security Considerations
- Section 52: Privacy Considerations
- Section 53: IANA Considerations · URI Scheme Registration
- Section 54: Versioning Policy
- Section 55: References
- Appendix A: Protocol Constants Reference
- Appendix B: Changelog

---

# PART I · INTRODUCTION AND TERMINOLOGY

## 1. Introduction and Motivation

The internet was designed without an identity layer. For three decades this absence has been treated as a feature: anonymity protects journalists, activists, whistleblowers, and ordinary people whose speech would be impossible if their real-world identity were attached to every word. The cost of this design was acceptable in an era when impersonation was expensive and synthetic media was implausible. That era has ended.

In 2026 a person can generate, at zero marginal cost, a video that is indistinguishable from a recording of any public figure speaking any words they choose. A person can clone any voice from three seconds of audio. A person can generate a photograph of any individual in any setting performing any action. A person can write an essay in the prose style of any author with sufficient training data. A person can manufacture an entire news article, complete with quotes from sources who never said them, that passes as the work of an established publication. The marginal cost of producing such content has fallen to zero and the marginal cost of attributing it falsely has fallen with it. The internet's identity layer is no longer optional. Its absence is now the largest unaddressed vulnerability in the global information environment.

The Trust Identity Protocol exists to provide that missing layer.

### 1.1 What the protocol does

TIP answers three questions about any piece of content on the internet:

1. **Who created this?** TIP binds content to a specific, biometrically verified human or organization through a portable cryptographic identity record called a TIP-ID. Anyone who encounters the content can verify the binding without trusting any single platform, vendor, or government.

2. **How was it made?** TIP requires every content registration to carry a mandatory origin declaration from a closed enumeration of four possibilities: Original Human (OH), AI-Assisted (AA), AI-Generated (AG), or Mixed (MX). The declaration is cryptographically bound to the content, the registrant, and the publication URL.

3. **Should I trust this person?** Every TIP-ID accumulates a deterministic trust score derived from the registrant's complete public history on the network. The score is computed by any conforming node from the same public data and is not stored centrally.

The protocol's design objective is that any reader, viewer, listener, journalist, regulator, or downstream platform can answer these three questions about any piece of TIP-registered content using only the public DAG state and the published cryptographic verification rules in this specification.

### 1.2 What the protocol does not do

TIP does not determine whether content is true. It determines whether the content's declared origin matches the content. A piece of journalism may be honest about its human authorship and entirely wrong about the facts it reports. A piece of AI-generated fiction may be honestly labeled AG and contain profound insights. TIP makes no claim about the truth, factuality, accuracy, legality, taste, viewpoint, or quality of any registered content. The protocol's narrow scope is origin transparency. The scope discipline is the source of the protocol's power: it is solvable cryptographically, and a cryptographic solution to a narrowly scoped problem is more durable than any heuristic solution to a broader one.

TIP does not constitute identity verification for any purpose other than network participation. A TIP-ID is not a passport, a driver's license, a tax document, a residency proof, an age proof, or a regulatory credential. Government identity programs may choose to issue TIP-IDs as a public-interest service (TIP Verification Provider Category C, Section 35) but the resulting TIP-ID is a network credential, not a state-issued identity document.

TIP does not police speech. It does not remove content. It does not block users. It does not censor viewpoints. It records, in cryptographically verifiable form, who claimed authorship of what content under what origin declaration, and it permits the network of users to challenge those claims through the adjudication process in Section 28.

### 1.3 What problem TIP replaces

Existing approaches to the synthetic media authenticity problem fall into three categories, each insufficient on its own.

**Detection-based approaches** try to determine algorithmically whether a piece of content was produced by AI. These approaches fail on two fronts. First, the false positive rate on human-authored content is high enough to be unacceptable for the affected authors; in 2026 the leading commercial detectors flag between four and twelve percent of authentic human writing as AI-generated. Second, the detection accuracy degrades faster than the generation accuracy improves, because adversarial training rewards the generators with each detection improvement. A detection arms race the defenders cannot win is not an authenticity solution; it is a deferred capitulation.

**Manifest-based approaches**, exemplified by the Coalition for Content Provenance and Authenticity (C2PA), bind device-level capture metadata to a media file through a cryptographically signed manifest. Manifest approaches work for the narrow class of content captured by a single device and never re-encoded. They do not address content that is text, content that is composed from multiple sources, content that has been quoted or excerpted, content that has been transcoded for distribution, content that originates from a digital workflow rather than a sensor capture, or content whose author is not the device. TIP is complementary to C2PA at the manifest layer: a TIP-signed Origin Code can be embedded in a C2PA manifest, and a C2PA manifest can be one piece of evidence cited in a TIP registration.

**Platform-policy approaches** rely on individual platforms (X, Facebook, YouTube, TikTok) to implement their own labeling, watermarking, and disclosure systems. The fragmentation makes cross-platform syndication, journalism citation, and regulatory compliance impossible. A reader who encounters the same piece of content on three platforms sees three different (or zero) labels. A journalist who needs to cite the original source has no neutral resolver. A regulator who needs to audit compliance has no canonical record. Each platform's policy serves the platform's interests, not the public's.

TIP takes a fourth approach: the protocol layer. Like HTTPS for encryption or DNS for name resolution, TIP is an open standard with no single platform owner, no per-platform implementation variation, and no commercial dependency. Any platform implements the same protocol. Any reader uses the same verification rules. Any regulator audits the same DAG. The protocol's specification is in the public domain under CC-BY 4.0. The reference implementation is open source under TIPCL-1.0, converting to Apache 2.0 on January 1, 2031.

### 1.4 What the protocol cannot solve

TIP cannot solve the underlying problem of trust between strangers. It can give those strangers verifiable claims about who created what and a reputation history to evaluate the claimant's prior conduct. It cannot make the underlying judgments for them. A TIP-verified piece of AI-generated political content from a high-trust-score user is still AI-generated political content. The reader still has to decide whether to be persuaded. The protocol's value is that the reader is making the decision with accurate information about provenance, not deceived by counterfeit provenance.

TIP cannot solve coercion. A state actor with the power to compel verification providers can in principle force a fraudulent registration. The protocol's design responses are: jurisdiction tier classification (Section 36), the warrant canary obligation (Section 36.4), accreditation cessation triggers (Section 35.7), and the open protocol design that permits a parallel network in any jurisdiction where the main network is compromised. These do not make coercion impossible; they make it visible.

TIP cannot solve coordinated platform refusal to implement the protocol. If every major platform refuses to surface TIP-signed origin codes, TIP becomes a niche standard used only by writers and readers who actively seek it. The protocol's design response is the EU AI Act Article 50 effective August 2, 2026 and analogous frameworks worldwide that legally require platforms to surface machine-readable origin labels. Platforms that fall under those regulations are not free to refuse. The protocol's adoption strategy rests on this legal floor.

### 1.5 Document organization

This specification is organized into nine Parts. Part I introduces the protocol and establishes terminology. Part II describes the architecture. Part III defines the cryptographic primitives. Parts IV, V, and VI specify the three layers (Identity, Content, Trust) in detail. Part VII specifies the federated DAG, transaction types, and verification provider system. Part VIII specifies the REST API and the reference behavior of the browser extension, verification provider mobile application, and WordPress plugin. Part IX specifies compliance mappings, governance, security considerations, privacy considerations, IANA registrations, versioning policy, and references. Two appendices provide a consolidated reference of protocol constants and a complete changelog.

## 2. Conformance, Conventions, and Requirements Language

### 2.1 Requirements language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in IETF RFC 2119 and RFC 8174 when, and only when, they appear in all capitals as shown here.

### 2.2 Conformance classes

This specification defines three conformance classes:

**Verifier**: An implementation that reads TIP-signed content and verifies signatures. A conforming verifier MUST implement the canonical JSON encoding rules (Section 8), the SHAKE-256 hashing (Section 10), and the ML-DSA-65 signature verification (Section 7). A conforming verifier MUST accept any CNA version listed in the published acceptance list (currently `["CNA-2.2"]`) and apply the matching normalization. A conforming verifier MUST reject any payload whose signature fails verification, whose `cna_version` is not in the acceptance list, or whose canonical reconstruction does not match the submitted `content_hash`.

**Signer**: An implementation that produces TIP-signed content registrations. A conforming signer MUST implement everything required of a Verifier plus the canonical payload construction (Section 20), the CNA-2.2 normalization (Section 19), and the ML-DSA-65 signing math with the ASCII-hex rule (Section 9). A conforming signer MUST sign under `cna_version: "CNA-2.2"` for new submissions. A conforming signer MUST require the user to select an Origin Code from the closed enumeration in Section 17. A conforming signer MUST require a `registered_url` in every registration.

**Verification Provider (VP)**: An implementation that issues TIP-IDs. A conforming VP MUST implement everything required of a Signer plus the four-layer biometric verification stack (Section 13), the peppered zero-knowledge deduplication (Section 14), the REGISTER_IDENTITY transaction format (Section 32.1), and the VP Code of Conduct obligations (Section 35.5). A conforming VP MUST be accredited by The AI Lab Intelligence Unobscured, Inc. under the procedure in Section 35.

### 2.3 Notation

Hexadecimal values are rendered in lowercase unless a different convention is required by an external standard. Byte counts are decimal. Bit counts are decimal. Time durations use ISO 8601 where applicable. Timestamps in transactions use ISO 8601 with millisecond precision in UTC. URI examples follow IETF RFC 3986. JSON examples follow IETF RFC 8259 with the canonical encoding rules of Section 8.

The pseudocode in this specification is illustrative. Conforming implementations MAY use any programming language and any data structures, provided the externally observable behavior matches the specification.

### 2.4 Backward compatibility commitment

This specification commits to backward-compatible verification for the life of the protocol. A signature produced under any historically valid CNA version and any historically valid canonical payload schema MUST continue to verify under any future protocol version. The CNA acceptance list grows over time; entries are never removed. The 8-field canonical payload format may be extended only by adding fields, never by removing them or by changing the semantics of existing fields.

## 3. Terminology and Definitions

The following definitions are normative for this specification.

**Adjudication Pipeline**: The three-stage process (AI classifier, community jury, community expert panel) that resolves disputes about origin code accuracy. See Section 28.

**AI Trust Council**: The governance body that oversees the protocol's open-standard evolution. See Section 49.

**AI Trust ID Seal**: The proprietary visual credential issued by The AI Lab's registry to verified TIP-IDs. Distinct from the open TIP Powered Mark. See Section 48.

**Attribution Mode**: One of `self`, `employed`, or `hosted`. Indicates the signer's relationship to the bylined authors. See Section 23.

**Author**: A natural person credited as a contributor to a piece of content, identified by their TIP-ID in the `authors[]` array of a registration. May or may not be the signer.

**Canonical Content Normalization Algorithm (CNA)**: The deterministic procedure for transforming raw content into the canonical bytes that are hashed into the `content_hash` field. The current version is CNA-2.2. See Section 19.

**Canonical JSON**: A deterministic JSON encoding with sorted keys, no whitespace, unescaped forward slashes, UTF-8 passthrough, and the additional rules in Section 8. The canonical JSON of a given object is byte-identical across conforming implementations.

**CC-BY 4.0**: The Creative Commons Attribution 4.0 International license under which this specification is published.

**CNA Version**: The string identifier in the `cna_version` field of a signed payload that declares which version of the canonical normalization algorithm produced the `content_hash`. Currently `"CNA-2.2"`.

**Community Adjudication Role**: One of the three opt-out-available community roles (Reviewer, Juror, Expert Panelist) that staff the adjudication pipeline. See Section 29.

**Content Hash**: The SHAKE-256 hash (32-byte output, 64 hexadecimal characters, lowercase) of the canonical bytes produced by applying the CNA version declared in the signed payload to the raw content. See Section 10.

**CTID**: The Content TIP Identifier. A URI of the form `tip://c/{OriginCode}-{Hash14}-{Author4}` that uniquely identifies a content registration on the DAG. See Section 18.

**Disputer**: A TIP-ID holder with trust score at least 400 who has filed a CONTENT_DISPUTED transaction against another party's content registration. See Section 28.4.

**Effective Date**: The date on which a transaction or signed payload takes effect on the DAG. Distinct from the timestamp encoded in the signed payload.

**Expert Panelist**: A community adjudication role at Stage 3 of the adjudication pipeline. Trust score eligibility floor is 850. See Section 29.

**Federated DAG**: The shared, append-only Directed Acyclic Graph that records every transaction on the TIP network. Replicated across all conforming nodes. See Section 31.

**Genesis Block**: The unique transaction with `prev[] = []` that anchors the DAG. Signed under the SLH-DSA-128s root key. See Section 33.

**Hardware Security Module (HSM)**: A tamper-resistant computing device used by some implementations for cryptographic key storage and signing. RECOMMENDED for VP signing keys.

**Implementer**: Any party that builds a Verifier, Signer, or VP.

**Juror**: A community adjudication role at Stage 2 of the adjudication pipeline. Trust score eligibility floor is 700. See Section 29.

**ML-DSA-65**: Module-Lattice-Based Digital Signature Algorithm at the Category 3 security level, defined in NIST FIPS 204. The primary signature algorithm of the protocol.

**ML-KEM-768**: Module-Lattice-Based Key Encapsulation Mechanism at the Category 3 security level, defined in NIST FIPS 203. Reserved for future session key establishment.

**Origin Code**: One of `OH` (Original Human), `AA` (AI-Assisted), `AG` (AI-Generated), or `MX` (Mixed). The mandatory origin declaration on every content registration. See Section 17.

**Pepper**: A 256-bit cryptographically random value generated in the user's device secure enclave at TIP-ID registration. Used in the deduplication hash to prevent reidentification. Never transmitted from the device. See Section 14.

**Prescan Review**: The Stage 1 human-review checkpoint that follows the AI classifier flag and precedes Stage 2 jury. Staffed by Community Reviewers. See Sections 28.2 and 29.

**REGISTER_CONTENT**: A DAG transaction type that records a content provenance registration. See Section 32.2.

**REGISTER_IDENTITY**: A DAG transaction type that records the issuance of a new TIP-ID by a Verification Provider. See Section 32.1.

**Registered URL**: The canonical permalink where a piece of registered content is published. Required field in every content registration. Index 0 of the `registered_urls` array. See Section 21.4.

**Reviewer**: A community adjudication role at Stage 1 of the adjudication pipeline. Trust score eligibility floor is 800. See Section 29.

**Score Update**: A SCORE_UPDATE transaction that records a delta to a TIP-ID's trust score, paired with the originating event transaction. See Section 25.

**Service Request (SR)**: The U.S. Copyright Office case number for this specification's copyright registration. Not yet applicable; see Section 55.

**SHAKE-256**: The 256-bit-output instance of the SHA-3 extendable-output function defined in NIST FIPS 202. The primary hash function of the protocol.

**Signer**: The TIP-ID holder whose private key produced the ML-DSA-65 signature on a content registration. Identified by the `signer_tip_id` field.

**SLH-DSA-128s**: Stateless Hash-Based Digital Signature Algorithm at the Category 1 security level, small-signature variant, defined in NIST FIPS 205. Reserved for long-term root keys.

**Subject-Of**: A TIP-ID about which a transaction makes a claim or applies an effect. For example, a SCORE_UPDATE transaction has a subject-of relation to the TIP-ID whose score is being adjusted.

**TIP**: Trust Identity Protocol. The protocol specified by this document.

**TIPCL-1.0**: TIP Community License Version 1.0, the license under which the reference implementation is distributed.

**TIP-CONTENT**: The provenance layer of the protocol. Implemented through REGISTER_CONTENT transactions producing CTIDs. See Part V.

**TIP-ID**: The identity layer of the protocol. A URI of the form `tip://id/{Region}-{Fingerprint16}` that uniquely identifies a verified human or organization. See Part IV.

**TIP Powered Mark**: The open visual mark that any conforming TIP implementation may display. Distinct from the proprietary AI Trust ID Seal. See Section 48.

**TIP-TRUST**: The reputation layer of the protocol. A deterministic integer 0 to 1000 derived from a TIP-ID's complete public history. See Part VI.

**Trust Tier**: One of five categorical labels (HIGHLY_TRUSTED, TRUSTED, REVIEW_ADVISED, LOW_TRUST, NOT_TRUSTED) corresponding to score ranges. See Section 26.

**Verification Provider (VP)**: An organization accredited by The AI Lab to issue TIP-IDs by performing the four-layer biometric verification stack. See Section 35.

**Verifier**: An implementation that reads and verifies TIP-signed content registrations. See Section 2.2.

---

# PART II · ARCHITECTURE

## 4. Three-Layer Architecture Overview

The Trust Identity Protocol is structured as three layers, each of which can be reasoned about, implemented, and audited independently while remaining cryptographically composable.

### 4.1 Layer 1 · TIP-ID (Identity)

The identity layer binds a portable cryptographic credential to a verified human or organization through a four-stage biometric verification process performed by an accredited Verification Provider. The output of the identity layer is a TIP-ID: a stable URI of the form `tip://id/{Region}-{Fingerprint16}` whose underlying ML-DSA-65 public key can sign content registrations, score updates, votes, and any other transaction the holder is authorized to produce. The identity layer is specified in Part IV.

### 4.2 Layer 2 · TIP-CONTENT (Provenance)

The provenance layer binds a piece of content to a signing TIP-ID, a mandatory Origin Code declaration, and a canonical publication URL through a cryptographically signed registration. The output of the provenance layer is a CTID: a stable URI of the form `tip://c/{OriginCode}-{Hash14}-{Author4}` that lets any reader, journalist, regulator, or downstream platform verify that the content's declared origin was claimed by the named author. The provenance layer is specified in Part V.

### 4.3 Layer 3 · TIP-TRUST (Reputation)

The reputation layer derives a deterministic integer trust score (0 to 1000) from a TIP-ID's complete public history on the DAG. The score is not stored centrally; any conforming node computes the same score from the same public data. The score is used to gate participation in the adjudication system (Reviewer requires 800, Juror 700, Expert 850, Disputer 400) and to inform readers about the reliability of a source. The reputation layer is specified in Part VI.

### 4.4 Layer interactions

The three layers are independent in the sense that a Verifier may consume any one without the others. A Verifier may check a content signature (Layer 2) without resolving the signer's trust score (Layer 3) or the signer's underlying identity verification details (Layer 1). A Verifier may resolve a TIP-ID (Layer 1) without inspecting any registered content (Layer 2). A Verifier may display a trust score (Layer 3) without surfacing the underlying transactions.

The layers are cryptographically composable in the sense that every higher-layer transaction is signed by a lower-layer key. A TIP-CONTENT registration is signed by a TIP-ID. A SCORE_UPDATE transaction (the unit of Layer 3 state change) references the originating REGISTER_CONTENT, ADJUDICATION_RESULT, or other Layer 2 transaction. The DAG itself records all three layers in a single ordered structure (Section 31).

### 4.5 What this architecture replaces

Most existing identity, content, and reputation systems entangle the three concerns. A platform's username is simultaneously identity, content authorship, and reputation. A blockchain wallet is simultaneously identity and reputation. A C2PA manifest is simultaneously content provenance and partial identity claim. The entanglement makes any one concern hard to audit and any one component hard to replace. TIP's strict layering is designed to make each layer independently auditable, independently replaceable in future protocol versions, and independently understandable to non-technical stakeholders. A regulator can audit the identity layer. A journalist can verify the content layer. A reader can interpret the reputation layer. None of them need to understand all three to do their job.

## 5. Design Principles

The principles in this section informed every protocol design decision in this specification. Future protocol changes that conflict with these principles require a higher bar of justification under the RFC process in Section 50.

### 5.1 Protocol-level, not product-level

TIP is a specification, not a product. The relationship between TIP and the internet is analogous to the relationship between HTTPS and the internet, between DNS and the internet, between SMTP and the internet, or between IETF Trust Anchor formats and the internet. Each of these is an open specification with multiple competing implementations, no single corporate owner of the protocol, and a governance body that evolves the standard through public process. TIP follows this pattern. The reference implementation is one implementation among many that the specification permits. A platform, publisher, or government may implement TIP independently from the specification in this document and that implementation is fully conforming if it satisfies the conformance classes in Section 2.2.

### 5.2 Reframe the question

A platform that asks "is this content fake?" is asking an unanswerable question. The honest answer is that nobody knows; an AI model with no commercial incentive to admit it could produce content indistinguishable from human writing on any subject. A platform that asks "does this content match its declared origin?" is asking a tractable question with a cryptographic answer. The declarant either signed the AG label or they did not. The community either upholds the declaration or it disputes it. The dispute is resolved through a public adjudication process whose every step is recorded on the DAG. TIP exists because the second question is solvable and the first is not. The first ten drafts of this specification attempted to answer the first question. The protocol began converging only when the question was reframed.

### 5.3 Conservative labeling is always safe

A creator who labels their original human writing as AI-assisted, AI-generated, or mixed faces zero protocol penalty. The asymmetric penalty structure (Section 30) applies only to under-disclosure: claiming human authorship for content that was substantially AI-produced. Over-disclosure is socially harmless (a reader who learns later that the content was actually human did not lose anything) and may even be preferable in certain regulatory contexts (the EU AI Act Article 50 deepfake disclosure obligation does not penalize honest over-disclosure). The protocol's incentive structure is therefore strictly aligned with honest behavior. There is no scenario in which a creator can improve their score by mislabeling.

### 5.4 Federated, not decentralized

The TIP network is intentionally federated rather than fully decentralized during the founding phase. Every conforming organization can run a node. Verification Providers are accredited under a public procedure (Section 35) but the accreditation does not flow from any centralized authority other than the protocol's open governance body, the AI Trust Council. There is no proof-of-work or proof-of-stake consensus mechanism: the federated DAG accepts any well-formed, properly signed transaction, and the trust score system makes Sybil attacks economically uninteresting (a low-reputation TIP-ID has limited influence on adjudication outcomes regardless of how many such TIP-IDs an attacker controls).

The choice of federation over full decentralization is deliberate. Full decentralization in 2026 means proof-of-work (energy-prohibitive), proof-of-stake (economic-attack-surface-prohibitive), or hand-rolled Byzantine fault tolerance (governance-prohibitive at internet scale). Federation lets the network bootstrap without solving the decentralization problem and lets the network migrate to greater decentralization over time as the validator committee grows. The migration path is specified in Section 31.5.

### 5.5 Post-quantum by default

All cryptographic primitives in this specification are NIST-standardized post-quantum algorithms: ML-DSA-65 (FIPS 204) for signatures, SLH-DSA-128s (FIPS 205) for the long-term root key, ML-KEM-768 (FIPS 203) reserved for future key encapsulation, and SHAKE-256 (FIPS 202) for hashing. Classical signatures (Ed25519, ECDSA, RSA) are permitted only during a three-year transition period (Section 11) for backward compatibility with legacy hardware and tooling. After the transition period, classical-only signatures are deprecated.

The post-quantum default is not an aesthetic choice. A protocol that records identity and content provenance is intended to be cryptographically durable for decades. The window between when a sufficiently large quantum computer could exist and when the protocol's signatures would need to remain valid is too narrow to risk classical-only algorithms. The protocol's commitment to post-quantum primitives extends the durability window past 2050 under any reasonable estimate of quantum computing progress.

### 5.6 Open specification, controlled brand

The protocol's technical specification is published worldwide under Creative Commons Attribution 4.0 International. Any party may read, implement, share, or adapt the specification. The TIP brand (trademarks listed in the title page) is held under U.S. trademark registrations and is not in the public domain. A party that implements the specification correctly is free to do so without permission and without payment. The same party may not call their implementation "TIP" or use the official logos without permission. This separation is the Bluetooth model: the protocol is open so that adoption is unconstrained; the brand is reserved so that the trust signal of the brand is not diluted by non-conforming implementations.

The brand discipline is specified in detail at https://theailab.org/brand-guidelines and is summarized in Section 48 of this specification.

## 6. Federated Trust Model

The protocol's trust model rests on five distinct but composable trust anchors. A Verifier need not trust all five to verify any single piece of content; the layering permits a Verifier to inspect only the anchors relevant to the verification at hand.

### 6.1 The Genesis Block

The Genesis Block (Section 33) is the unique transaction with `prev[] = []` that anchors the DAG. It is signed under the SLH-DSA-128s root key whose public key is published in the printed specification, the project memory, the GitHub repository, and the printed brand assets, with the public key bytes hashed into the Genesis Block's `tx_id`. Every other transaction on the DAG transitively references the Genesis Block through its `prev[]` chain. A Verifier who trusts the published root public key transitively trusts the chain of references. A Verifier who does not trust the published root public key has no anchor and cannot verify; this is the inevitable trust floor of any cryptographic protocol.

### 6.2 The Verification Provider Accreditation List

A REGISTER_IDENTITY transaction is signed by a VP. The signature is verifiable against the VP's public key. The VP's public key is itself recorded on the DAG via a VP_REGISTERED transaction at the time of accreditation, and that VP_REGISTERED transaction is signed under the Genesis root key. A Verifier who trusts the Genesis Block transitively trusts the accredited VPs. The published, real-time list of accredited VPs is at https://theailab.org/vps and is also queryable via the REST endpoint `GET /v1/vps`. A Verifier MAY refuse to honor TIP-IDs issued by specific VPs that the Verifier distrusts (for example, VPs operating in jurisdictions the Verifier considers unsafe). The protocol does not require uniform VP acceptance.

### 6.3 The Per-TIP-ID Public Key

The Verifier resolves a TIP-ID to its current ML-DSA-65 public key by querying the DAG. The public key is recorded in the REGISTER_IDENTITY transaction that minted the TIP-ID, and may be updated by KEY_ROTATED or KEY_RECOVERY transactions thereafter. The Verifier MUST use the public key effective at the timestamp of the signature being verified, not the current public key, so that historical signatures continue to verify after rotation. The DAG's append-only structure makes the time-anchored key lookup deterministic.

### 6.4 The Conforming Implementation Trust

A reader who uses a Verifier (a browser extension, a CMS plugin, a mobile reader app, a regulator's audit tool) trusts that Verifier to implement the specification correctly. A defective Verifier might accept invalid signatures, miscompute the canonical content hash, or display incorrect trust scores. The protocol's defense against defective Verifiers is open source reference implementations (TIPCL-1.0) that any party may study, fork, audit, or use as the basis for their own implementation. Implementations that publish themselves as "TIP Powered" without conforming to the specification are subject to trademark enforcement.

### 6.5 The Community Adjudication Layer

A claim by a signer that their content matches a particular Origin Code may be challenged by any other TIP-ID holder with trust score at least 400 through the dispute mechanism in Section 28.4. The community jury (Stage 2) and expert panel (Stage 3) are themselves trust anchors: a Verifier trusts that a sufficient number of high-trust-score humans, drawn from a pool of opt-out-available volunteers, will exercise reasonable judgment. The trust is partial and bounded. A reader who distrusts the community adjudication outcomes is free to make their own assessment of any registered content; the adjudication outcomes are advisory inputs to the Verifier's display of trust scores, not absolute truths.

### 6.6 No single point of trust

The five anchors above are not arranged as a chain of single trust. A Verifier could in principle reject the Verification Provider list, the per-TIP-ID public keys, and the community adjudication outcomes, and still verify that a content signature is cryptographically valid for the published public key. The protocol's verifiable claim at the cryptographic floor is that the holder of a particular ML-DSA-65 private key signed a particular canonical JSON payload at a particular time. Every other claim (that the signer is a real human, that the content matches its declared origin, that the trust score reflects responsible behavior) layers on top of this floor and is held up by a separate combination of anchors. A Verifier may choose how much of the stack to trust depending on the use case.

---

# PART III · CRYPTOGRAPHIC PRIMITIVES

## 7. Algorithms and Key Sizes

Every cryptographic operation in the protocol is performed with one of the algorithms in the table below. Conforming implementations MUST use these algorithms. Conforming implementations MUST NOT substitute other algorithms for these.

### 7.1 Primary algorithm table

| Function | Algorithm | NIST Standard | Public Key | Private Key | Output |
|---|---|---|---|---|---|
| Primary signatures | ML-DSA-65 (Dilithium Category 3) | FIPS 204 | 1,952 bytes | 4,032 bytes | 3,309 bytes (signature) |
| Root signatures | SLH-DSA-128s (SPHINCS+ Category 1, small) | FIPS 205 | 32 bytes | 64 bytes | 7,856 bytes (signature) |
| Key encapsulation (reserved) | ML-KEM-768 (Kyber Category 3) | FIPS 203 | 1,088 bytes | 2,400 bytes | 1,088 bytes (ciphertext) |
| Hashing | SHAKE-256 (SHA-3 XOF) | FIPS 202 | n/a | n/a | configurable, default 32 bytes |
| Symmetric encryption | AES-256-GCM | FIPS 197, SP 800-38D | n/a | 32 bytes | 16 bytes tag |
| Key derivation (legacy fallback) | PBKDF2-HMAC-SHA-256 | RFC 8018, FIPS 180-4 | n/a | n/a | 32 bytes |
| Randomness | CSPRNG | SP 800-90A | n/a | n/a | implementation-dependent |

### 7.2 ML-DSA-65 (primary signatures)

ML-DSA-65 is the primary signature algorithm for every transaction on the DAG and every content registration in the protocol. Conforming Signers MUST use ML-DSA-65 from FIPS 204. The Category 3 security level (corresponding to AES-192 classical strength) is the protocol's mandatory floor. Implementations MAY additionally support ML-DSA-87 (Category 5) for higher-security deployments, but the canonical signature in the protocol's transaction format is ML-DSA-65.

Reference implementations:
- Reference TIP node: `@noble/post-quantum` version 0.2.1 or later
- TIP browser extension: `@noble/post-quantum` version 0.2.1
- TIP VP mobile web application: Python `pqcrypto` library, ML-DSA-65 binding

Wire encoding:
- Public key: 1,952 bytes, hex-encoded lowercase (3,904 hex characters) on the wire
- Private key: never transmitted in cleartext; encrypted at rest under AES-256-GCM (Section 7.6) or wrapped by a hardware security module
- Signature: 3,309 bytes, hex-encoded lowercase (6,618 hex characters) on the wire

### 7.3 SLH-DSA-128s (root signatures)

SLH-DSA-128s is reserved for the long-term root key that signs the Genesis Block and the highest-level governance transactions (VP_REGISTERED, COMMITTEE_ROTATION). The choice of a hash-based stateless signature for the root key reflects a different security posture than ML-DSA-65: SLH-DSA's security rests on the hardness of SHA-3 alone with no number-theoretic assumptions, providing redundancy against unforeseen cryptanalytic advances in lattice-based schemes. The cost is larger signatures (7,856 bytes versus 3,309) and slower signing, both acceptable for transactions that occur at most a few times per year.

The root key MUST be generated and stored in a FIPS 140-3 Level 3 hardware security module under a two-of-three custodian policy. The root public key is published in this specification, in the project memory file, in the printed brand assets, and at https://theailab.org/genesis. Verifiers MUST verify the Genesis Block signature against the published root public key.

### 7.4 ML-KEM-768 (reserved for future key encapsulation)

ML-KEM-768 is reserved for future protocol features that require key encapsulation, such as encrypted private messaging between TIP-IDs or session key establishment for high-throughput Verifier-to-VP queries. ML-KEM is not used in any v5.0 protocol operation; the inclusion in this specification is to fix the algorithm choice now so that future RFCs that introduce key-encapsulation-using features can rely on it.

### 7.5 SHAKE-256 (hashing)

SHAKE-256 is the protocol's primary hash function. SHAKE-256 is invoked in three roles:

1. **Content hashing.** SHAKE-256 over the canonical bytes produced by CNA-2.2, with 32-byte output. Produces the `content_hash` field (Section 21.3). The 14-character prefix of this hash forms the `Hash14` segment of the CTID (Section 18).

2. **Identity fingerprinting.** SHAKE-256 over the holder's ML-DSA-65 public key, with 32-byte output. The 16-character prefix forms the `Fingerprint16` segment of the TIP-ID URI (Section 12).

3. **Canonical payload hashing.** SHAKE-256 over the canonical JSON bytes of an 8-field signed payload, with 32-byte output. The hex string of this hash is the message that ML-DSA-65 signs (Section 9).

SHAKE-256 is specified in FIPS 202 as a 256-bit-output instance of the SHA-3 extendable-output function (XOF). Conforming Signers and Verifiers MUST use SHAKE-256 from FIPS 202, not SHA-256, not SHA-3-256. The distinction matters: SHA-256 (FIPS 180-4) and SHA-3-256 (FIPS 202 fixed-output variant) produce different bytes for the same input.

Reference implementations:
- Reference TIP node: `@noble/hashes` version 1.4.0 or later, `shake_256` function
- TIP browser extension: `@noble/hashes` version 1.4.0
- TIP VP mobile web application: Python `hashlib.shake_256` from the standard library

### 7.6 AES-256-GCM (symmetric encryption at rest)

AES-256-GCM is the protocol's symmetric encryption mode for at-rest protection of private keys held by client implementations. The browser extension and the VP mobile web application both encrypt the user's ML-DSA-65 private key under AES-256-GCM with the encryption key derived from either:

- The WebAuthn PRF extension (Section 15) when the user's device supports it
- A PBKDF2-HMAC-SHA-256 derivation from the user's passphrase, 200,000 iterations, with a 16-byte salt (legacy fallback)

The encrypted private key is stored in browser local storage, in mobile device secure storage, or in an analogous platform-appropriate key store. The encryption envelope format is:

```
[Magic "TIPW" (4 bytes)] || [IV (12 bytes)] || [AES-256-GCM ciphertext including 16-byte tag]
```

Base64 encoded for storage. The Additional Authenticated Data (AAD) is the holder's TIP-ID URI as ASCII bytes, binding the encrypted blob to the identity it represents.

### 7.7 Randomness

Every cryptographic operation that requires randomness (key generation, nonce generation, pepper generation, salt generation, IV generation, challenge generation) MUST use a NIST SP 800-90A-conforming cryptographically secure pseudorandom generator seeded from the operating system's entropy source. In browser environments this is `crypto.getRandomValues()`. In Node.js this is `crypto.randomBytes()`. In Python this is `secrets.token_bytes()`. On mobile platforms this is the platform secure random API.

The protocol does not specify a particular DRBG algorithm. Conforming implementations rely on the platform's CSPRNG which is assumed to meet the NIST standard. Implementations on platforms without a conforming CSPRNG (extremely rare in 2026) MUST NOT be used to generate TIP-IDs or sign content registrations.

## 8. Canonical JSON Encoding

Every signature in the protocol is computed over a canonical JSON byte sequence. The canonical JSON of a given JavaScript object MUST be byte-identical across conforming implementations. The encoding rules below are normative.

### 8.1 The nine canonical JSON rules

1. **Object keys are sorted ASCII-ascending, recursively.** Nested objects also have sorted keys. The sort is byte-wise on the UTF-8 representation of the key, not locale-dependent.

2. **No whitespace between tokens.** No spaces, tabs, newlines, or carriage returns appear between JSON tokens. The canonical JSON of a small payload is a single line.

3. **Forward slashes are NOT escaped.** A URL of the form `https://example.com/article/the-original` appears verbatim in the canonical JSON, not as `https:\/\/example.com\/article\/the-original`. PHP implementations MUST use the `JSON_UNESCAPED_SLASHES` flag.

4. **UTF-8 passthrough for non-ASCII.** A character such as `é` is encoded as the UTF-8 bytes 0xC3 0xA9, not as `é`. PHP implementations MUST use the `JSON_UNESCAPED_UNICODE` flag. JavaScript `JSON.stringify` produces UTF-8 passthrough by default. Python `json.dumps` requires `ensure_ascii=False`.

5. **Standard JSON escapes apply to control characters and to `"` and `\`.** A literal double-quote inside a string is `\"`. A backslash is `\\`. A newline character (rare in TIP payloads) is `\n`. Other control characters use `\uXXXX` lowercase hex escapes.

6. **Empty objects render as `{}`** (two bytes), not as `[]`, not as `null`. PHP implementations converting from associative arrays MUST cast empty arrays to objects before encoding: `json_encode((object)[], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)`.

7. **Empty arrays render as `[]`** (two bytes).

8. **Numbers and booleans and null** use their standard JSON representation. Integers are unquoted. Decimals use the period as the decimal separator. Booleans are `true` or `false` lowercase. The null literal is `null` lowercase.

9. **Strings preserve their original UTF-8 byte sequence.** No Unicode normalization, no case folding, no whitespace collapsing. The string is encoded exactly as the caller provided.

### 8.2 Reference implementations

Node.js canonical JSON (from the reference TIP node and browser extension):

```javascript
function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
  }
  throw new Error("Non-canonical value");
}
```

Python canonical JSON:

```python
import json

def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
```

PHP canonical JSON (from the WordPress plugin reference implementation):

```php
function canonical_json($value) {
    if (is_array($value) && empty($value)) {
        return json_encode((object)[], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    if (is_array($value)) {
        if (array_keys($value) === range(0, count($value) - 1)) {
            $parts = array_map('canonical_json', $value);
            return '[' . implode(',', $parts) . ']';
        }
        ksort($value);
        $parts = [];
        foreach ($value as $k => $v) {
            $parts[] = json_encode((string)$k, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                     . ':' . canonical_json($v);
        }
        return '{' . implode(',', $parts) . '}';
    }
    return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
```

### 8.3 Worked example

Input object (presented in arbitrary order for illustration):

```
{ "origin_code": "OH", "signer_tip_id": "tip://id/US-a3f8c91b2d4e7021",
  "content_hash": "7f2a91bc3d5e4a8...", "extras": {} }
```

Canonical JSON output (single line, sorted keys, no whitespace):

```
{"content_hash":"7f2a91bc3d5e4a8...","extras":{},"origin_code":"OH","signer_tip_id":"tip://id/US-a3f8c91b2d4e7021"}
```

The bytes of the canonical JSON output are what feed into the hash and the signing operations of Section 9.

## 9. Signing Math and the ASCII-Hex Rule

Every ML-DSA-65 signature in the protocol is computed over the SHAKE-256 hash of the canonical JSON of a structured payload, with a specific binding to the ASCII bytes of the hex representation. This section specifies the procedure exactly.

### 9.1 The five-step signing procedure

Given an object `payload` to be signed and a private key `sk`:

```
Step 1. canonical_bytes  = utf8(canonicalJson(payload))                 // bytes
Step 2. payload_hash_raw = SHAKE-256(canonical_bytes, output_bytes=32)  // 32 bytes
Step 3. payload_hash_hex = hex_lowercase(payload_hash_raw)              // 64-char string
Step 4. signing_message  = ascii(payload_hash_hex)                      // 64 bytes
Step 5. signature        = ML-DSA-65.sign(sk, signing_message)          // 3,309 bytes
```

The wire encoding of the signature is `hex_lowercase(signature)` (6,618 hex characters).

### 9.2 The ASCII-hex rule

**Critical implementation note.** ML-DSA-65 signs the 64 ASCII bytes of the hex digest string (Step 4), NOT the 32 raw bytes of the digest (Step 2). The distinction is the single most common implementation mistake for new clients of the protocol. A signature produced by signing the 32 raw bytes will not verify against a Verifier that follows this specification.

The rule is in this specification because it matters for cross-implementation compatibility: every reference implementation (TIP node, browser extension, VP mobile app, WordPress plugin) signs the hex string. A new implementation that signs the raw bytes will produce signatures that verify locally but are rejected by the network.

To detect this error during implementation testing, a Signer can verify their own signature against the Verifier reference. If the local signature verifies but the network rejects, the most likely cause is signing the raw bytes instead of the hex string.

### 9.3 Verification procedure

A Verifier given a signed payload reconstructs the canonical bytes from the eight fields, computes the SHAKE-256 hash, converts to lowercase hex, ASCII-encodes the hex string, and verifies the ML-DSA-65 signature against that ASCII byte sequence using the signer's public key resolved from the DAG.

The procedure must be repeated faithfully or the signature will not verify. The eight fields in the canonical payload (Section 20) are enumerated explicitly so that the canonical builder produces byte-identical output regardless of the order in which the implementation populated the source object.

## 10. Hashing and Pepper Architecture

### 10.1 SHAKE-256 invocations

The protocol invokes SHAKE-256 in five contexts:

1. **Content hash** with 32-byte output, over CNA-2.2-normalized content bytes
2. **Identity fingerprint** with 32-byte output, over the holder's ML-DSA-65 public key bytes
3. **Canonical payload hash** with 32-byte output, over the canonical JSON bytes
4. **Transaction ID** with 32-byte output, over the canonical JSON bytes of the transaction (excluding the signature field)
5. **Dedup hash** with 32-byte output, over the concatenation of (government ID number || date of birth || country code || facial-embedding hash || pepper)

In every invocation the output length is exactly 32 bytes. The hex encoding of the output is exactly 64 lowercase characters.

### 10.2 Pepper architecture

A pepper is a 256-bit cryptographically random value generated by the user's device secure enclave at TIP-ID registration time. The pepper is generated once per TIP-ID and never regenerated.

The pepper is stored only in the device secure enclave. The pepper is never transmitted from the device to any server, never written to the DAG, never published in any log, and never recoverable by any party except the device on which it was generated.

The pepper participates in the dedup hash computation:

```
dedup_hash = SHAKE-256(government_id_number || date_of_birth || country_code || facial_embedding_hash || pepper, output_bytes=32)
```

The dedup hash is what gets recorded on the DAG (in encrypted form, with a zero-knowledge proof of uniqueness; see Section 14). Without the pepper, the dedup hash cannot be recomputed even by an adversary who has access to the underlying government ID database and the facial embedding hash. The pepper is therefore the cryptographic separator between the holder's real-world identity and the holder's TIP-ID.

If the user loses their device, the pepper is lost with it. Key recovery (Section 15.3) requires re-running the four-layer biometric verification with a new pepper, producing a new dedup hash. The recovered TIP-ID is bound to the new device, and the old TIP-ID's signing key is rotated under the KEY_RECOVERY transaction type (Section 32.6).

### 10.3 Why the pepper matters

A naive deduplication scheme would hash the government ID, date of birth, country, and facial embedding hash without a pepper. An adversary with access to the government's ID database could then enumerate every possible dedup hash and link any DAG-recorded TIP-ID back to a real person. The pepper makes this impossible: the dedup hash cannot be recomputed without the device-held secret, so the DAG record cannot be deanonymized by a database query.

The pepper is the GDPR-relevant pseudonymization mechanism (Article 25 data protection by design) that lets the protocol record the dedup hash on a public DAG without exposing the underlying biometric data.

## 11. Hybrid Transition Period and Algorithm Negotiation

### 11.1 The transition period

The protocol's transition period runs from June 1, 2026 (the effective date of v5.0) through June 1, 2029. During the transition period, conforming Signers and Verifiers MAY support hybrid signatures combining Ed25519 (RFC 8032) with ML-DSA-65. A hybrid signature is the byte-concatenation of an Ed25519 signature and an ML-DSA-65 signature, both over the same signing message. A Verifier that accepts hybrid signatures MUST verify both components.

After June 1, 2029, classical-only signatures (Ed25519 without an accompanying ML-DSA-65 signature) are deprecated. Conforming Verifiers SHOULD reject classical-only signatures after this date. The deprecation provides three years for legacy hardware and tooling to migrate while preserving the post-quantum security floor for new signatures.

### 11.2 Algorithm negotiation

Nodes advertise their supported algorithm sets in the gossip handshake (Section 31.6). The advertisement uses a structure analogous to TLS cipher suite negotiation:

```json
{
  "supported_signature_algorithms": ["ml_dsa_65", "ed25519"],
  "supported_hash_algorithms": ["shake_256"],
  "supported_kem_algorithms": ["ml_kem_768"],
  "protocol_version": "5.0"
}
```

A node receiving a transaction signed under an algorithm not in its supported set MUST reject the transaction with the error code `signature_algorithm_unsupported`. The default supported algorithm sets for conforming nodes in v5.0 are:

- `supported_signature_algorithms`: `["ml_dsa_65", "ed25519"]` during the transition period; `["ml_dsa_65"]` after June 1, 2029
- `supported_hash_algorithms`: `["shake_256"]`
- `supported_kem_algorithms`: `["ml_kem_768"]` (reserved; no transactions consume it in v5.0)

### 11.3 Future algorithm additions

New cryptographic algorithms may be added to the protocol through the RFC process (Section 50). Algorithm additions are non-breaking when added to the supported sets but breaking when made mandatory; the RFC must specify a transition period analogous to the one in Section 11.1 for any algorithm that becomes mandatory.

---

# PART IV · TIP-ID IDENTITY LAYER

## 12. TIP-ID URI Format and Data Model

### 12.1 URI format

A TIP-ID is a URI of the form:

```
tip://id/{Region}-{Fingerprint16}
```

Components:

- `tip://` is the protocol scheme registered with IANA (Section 53)
- `id` is the resource type segment indicating an identity record
- `Region` is an ISO 3166-1 alpha-2 country code (two uppercase ASCII letters) identifying the jurisdiction of the issuing Verification Provider
- `-` is a literal hyphen separator
- `Fingerprint16` is sixteen lowercase hexadecimal characters, the first sixteen characters of the lowercase hex encoding of SHAKE-256 over the holder's ML-DSA-65 public key bytes

Example:

```
tip://id/US-a3f8c91b2d4e7021
```

The URI is the holder's stable, portable identifier. The URI is case-sensitive in the hex portion (always lowercase) and case-sensitive in the region code (always uppercase ASCII letters).

### 12.2 Data model

A TIP-ID record on the DAG has the following fields. Field names and types are normative.

| Field | Type | Required | Description |
|---|---|---|---|
| `tip_id` | string | yes | The canonical URI as above |
| `region` | string | yes | ISO 3166-1 alpha-2 |
| `public_key` | string | yes | Lowercase hex encoding of ML-DSA-65 public key (3,904 hex characters) |
| `root_public_key` | string | optional | Lowercase hex encoding of SLH-DSA-128s root key (64 hex characters); present only for VP TIP-IDs |
| `biometric_hash` | string | yes (off-DAG) | SHAKE-256 hash of the 512-dimensional facial embedding; stored only at the issuing VP, never on the public DAG |
| `dedup_hash` | string | yes | SHAKE-256 hash with pepper (Section 10.2); recorded on the DAG inside a zero-knowledge uniqueness proof |
| `device_credential_id` | string | yes | FIDO2 / WebAuthn credential ID, lowercase hex |
| `vp_id` | string | yes | TIP-ID of the issuing Verification Provider |
| `tip_id_type` | string | yes | `personal`, `organization`, `publisher`, `government`, or `vp` |
| `status` | string | yes | `active`, `revoked_voluntary`, `revoked_vp`, `revoked_deceased`, `revoked_device`, or `pending_recovery` |
| `verified_at` | string | yes | ISO 8601 timestamp of issuance |
| `verification_tier` | string | yes | `T1`, `T2`, `T3`, or `T4` (see Section 13.5) |
| `social_attested` | boolean | yes | Whether social graph attestation (Section 16) was completed |
| `creator_name` | string | optional | Display name; may be null if the holder opts out of name publication |
| `jurisdiction_tier` | string | yes | `green`, `amber`, or `red` (see Section 36) |

### 12.3 Identity types

The `tip_id_type` field carries a closed enumeration:

- **personal**: A natural human. The default for individual holders. Eligible for the full adjudication participation (Reviewer, Juror, Expert Panelist, Disputer). Subject to GDPR-Article-9 special category data treatment for the biometric verification.

- **organization**: A non-personal entity that is not a publisher, government, or VP. Eligible to sign content under `attribution_mode: "self"` only when the content is institutional speech. Not eligible for community adjudication roles.

- **publisher**: A news publisher, newsroom, or analogous editorial entity. Eligible to sign content under `attribution_mode: "employed"` with a roster of personal-TIP-ID human authors. See Section 23.

- **government**: A state, agency, ministry, or government program. Eligible to issue analogous credentials within its jurisdiction. Eligible to sign content under `attribution_mode: "self"` for official publications.

- **vp**: A Verification Provider TIP-ID. The signing key of an accredited VP. Used to sign REGISTER_IDENTITY transactions for the VP's customers. Signed in turn by the Genesis root key via the VP_REGISTERED transaction at accreditation time.

### 12.4 Resolution

A Verifier resolves a TIP-ID by querying the DAG state. The reference resolution endpoint is `GET /v1/identity/{tip_id}` (Section 38.4). The response includes the public key effective at the requested time (if specified) and the current status. Conforming Verifiers MUST use the public key effective at the timestamp of the signature being verified, not the current public key, so that historical signatures remain valid after key rotation.

## 13. Four-Layer Biometric Verification Stack

Every TIP-ID is produced by a specific verification sequence performed by an accredited Verification Provider. The four-layer stack is normative. Each layer is mandatory except Layer 4 (optional). VPs MAY perform additional verification beyond the four-layer floor but MUST NOT issue TIP-IDs that have not completed Layers 1 through 3.

### 13.1 Layer 1 · Government ID verification

The VP performs the following on a government-issued identity document:

- **OCR extraction.** The VP extracts the holder's name, date of birth, identity document number, expiration date, and issuing country from the document. Multi-pass OCR using Tesseract 5 (primary) with PaddleOCR (secondary) is the reference implementation. The mobile reference implementation performs eight preprocessing variants (CLAHE, bilateral filter, adaptive threshold, Otsu threshold, morphological closing, and three combinations) and selects the longest successful extraction. Country-specific language hints (Tesseract `IND: eng+hin`, `ARE: eng+ara`, etc.) MUST be applied.

- **Tamper detection.** The VP runs an AI tamper detector over the document image. The reference detector uses an ensemble of features: FFT texture analysis (printed-versus-photocopy discrimination), edge regularity, color/hue clustering, Harris corner detection, and a document-authenticity composite score in the range 0.0 to 1.0. The authenticity score must be at least 0.4 for the verification to proceed.

- **MRZ verification.** For documents with a Machine Readable Zone (passports per ICAO 9303 TD3, national IDs per TD1, etc.), the VP MUST parse the MRZ and verify the check digits. Failed check-digit verification rejects the document.

- **NFC chip verification (where present).** For ePassports and equivalent documents with NFC chips, the VP MUST perform ICAO Doc 9303 Part 11 active authentication: read the chip, verify the issuing country's signature on the chip data against the published ICAO country signing certificate, and confirm the chip data matches the printed data.

- **Cross-reference against issuing authority databases.** Where API access to the issuing authority's database is available (in some jurisdictions, with the holder's consent), the VP queries the database to confirm the document is not reported lost, stolen, or revoked.

Output: a set of extracted fields, an authenticity score, and a face crop from the document for use in Layer 2.

### 13.2 Layer 2 · Three-dimensional facial liveness detection

The VP performs a real-time challenge-response liveness check on the holder, using the holder's device camera. The reference mobile implementation runs the following three challenges in randomized order:

- **Challenge A · Face presence.** The system detects a single face in the camera feed. The reference implementation uses the browser's native FaceDetector API (Chrome and Edge) with a YCbCr skin-tone heuristic fallback (Safari and Firefox). The face must occupy at least 3% of the frame area and must be present in at least 30 consecutive frames at approximately 30 fps.

- **Challenge B · Blink detection.** The system detects a blink. Eye-zone luminance is monitored in the rows 25-50% and columns 25-75% of the face crop. A blink is confirmed by a luminance drop of at least 18% across at least two consecutive frames followed by recovery. The system adapts the baseline luminance to the prevailing lighting conditions.

- **Challenge C · Head turn.** The system detects a head turn. The horizontal luminance-weighted centroid is tracked. A turn is confirmed by a rightward shift of at least 8% of the face width followed by a return to within 45% of the peak shift.

In parallel with the three challenges the system runs **client-side anti-spoofing** signals:

- Inter-frame pixel motion accumulation (printed photo attacks produce zero motion)
- Skin texture frequency analysis (low-pass-filtered prints have characteristic frequency signatures)

The system computes a 512-dimensional facial embedding vector from the captured frames using the reference ArcFace model. The embedding is immediately hashed via SHAKE-256 inside a secure hardware enclave (the device's Secure Enclave on iOS, TrustZone on Android, TPM on Windows, or the equivalent on macOS). Only the 32-byte hash leaves the device. The raw embedding and the raw frames are destroyed.

The system performs a **server-side liveness validation** on a selected key frame uploaded with the session:

- Multi-cascade face detection (the reference uses four Haar cascades plus eye verification)
- Five-signal anti-spoofing fusion:
  - LBP (Local Binary Patterns) texture entropy (weight 0.25)
  - FFT radial-band analysis for moiré detection on screen replays (weight 0.25)
  - YCbCr chrominance variance for compression-artifact detection (weight 0.20)
  - Gradient direction coherence for 3D-curvature-versus-flat-surface discrimination (weight 0.20)
  - Specular reflection for screen-glare-versus-skin-shine discrimination (weight 0.10)
- Composite threshold 0.42 (strict, production) or 0.28 (development)
- SHAKE-256 frame hash anti-replay (the server stores frame hashes and rejects any frame that matches a hash seen in any previous session)

Output: a 32-byte facial embedding hash, a liveness composite score, and a binary `passed` flag.

Defeats: printed photos, screen replays, 2D deepfakes, silicone masks, 3D-printed face models, recorded videos.

### 13.3 Layer 3 · Device biometric binding (FIDO2 / WebAuthn)

The VP performs WebAuthn registration of a platform authenticator on the holder's device.

- **Challenge generation.** The VP server generates a 32-byte cryptographically random challenge and stores it server-side keyed by the verification session.

- **Credential creation.** The client invokes `navigator.credentials.create()` with the challenge, the RP ID (the VP's domain, e.g., `vp.theailab.org`), the user ID (the session ID), the allowed algorithms (-7 for ES256, -257 for RS256), an authenticator selection requiring platform authenticator and user verification, a preference for resident keys (so the credential can be used without entering a username), and an attestation conveyance preference of `none` (the protocol does not require the device's manufacturer attestation, only the device's user-verification capability).

- **Attestation verification.** The client returns an `attestationObject` and `clientDataJSON`. The server CBOR-decodes the attestation, verifies the challenge match, verifies the RP ID hash equals SHA-256 of the RP ID, verifies the User Present (UP) and User Verified (UV) flags are set, extracts the public key, and stores the credential ID along with the public key and the RP ID.

The device's secure enclave generates the asymmetric keypair. The private key never leaves the secure enclave. Subsequent re-authentication to sign TIP transactions requires physical possession of the enrolled device plus a user verification gesture (biometric or device PIN).

Supported platforms:

- iOS: Face ID, Touch ID (Secure Enclave)
- Android: Fingerprint, Face Unlock (TrustZone)
- Windows: Windows Hello (TPM 2.0)
- macOS: Touch ID (Secure Enclave)
- Hardware security keys: YubiKey, Google Titan, SoloKey (for users without platform authenticators)

Output: a credential ID, the device public key, the RP ID, and a binary `bound` flag.

### 13.4 Layer 4 · Social graph attestation (optional)

The holder MAY have three existing TIP-ID holders, each with trust score at least 700, attest to the holder's identity. Each attesting holder stakes 25 trust score points from their own score. If the new holder commits an origin misclassification within 90 days of issuance, each attester loses the staked points.

Benefits of completing Layer 4:

- Starting trust score 550 instead of 500
- Trust accrual multiplier 1.5x for the first 90 days
- Immediate eligibility to participate as a Juror (instead of waiting for the score to reach 700 organically)

The reference VP mobile implementation supports Layer 4 attestation through five social platforms (YouTube, X, Instagram, LinkedIn, TikTok). For each platform the holder proves possession of the account by posting a verification code, and the attestation grants +25 to the starting score, capped at +125 for completing all five platforms.

### 13.5 Verification tiers

The four-layer stack produces one of four verification tiers based on which layers were completed:

- **T1**: Layers 1, 2, 3 completed (the minimum for issuance). Starting score 500.
- **T2**: Layers 1, 2, 3, plus partial Layer 4 (one or two social attestations). Starting score 525 or 550.
- **T3**: Layers 1, 2, 3, plus full Layer 4 (three or more social attestations). Starting score 575 or higher.
- **T4**: Layers 1, 2, 3, plus full Layer 4, plus additional VP-specific enhanced verification (varies by VP). Starting score 600 or higher.

The verification tier is recorded in the REGISTER_IDENTITY transaction's `verification_tier` field and is immutable. The holder's trust score may decline over time due to adjudication outcomes but the verification tier does not change.

## 14. Peppered Zero-Knowledge Deduplication

Every TIP-ID is unique to a single real-world person. The protocol enforces uniqueness without recording the underlying biometric data on the public DAG.

### 14.1 Dedup hash computation

At TIP-ID registration time the device computes:

```
dedup_hash = SHAKE-256(
  government_id_number ||
  date_of_birth_ISO8601 ||
  country_code ||
  facial_embedding_hash ||
  pepper,
  output_bytes = 32
)
```

Inputs:

- `government_id_number`: the alphanumeric identity document number extracted in Layer 1, normalized to uppercase ASCII with no separators
- `date_of_birth_ISO8601`: the holder's date of birth in ISO 8601 format (YYYY-MM-DD)
- `country_code`: the ISO 3166-1 alpha-2 code of the issuing country (two uppercase ASCII letters)
- `facial_embedding_hash`: the 32-byte SHAKE-256 hash of the 512-dimensional facial embedding from Layer 2
- `pepper`: a 256-bit cryptographically random value generated by the device secure enclave and held only on the device (Section 10.2)

The concatenation is byte-level with no separators between fields.

Output:

- `dedup_hash`: a 32-byte SHAKE-256 digest, hex-encoded lowercase for storage (64 characters)

### 14.2 Zero-knowledge uniqueness proof

The dedup hash is not directly published on the public DAG. Instead the device computes a zero-knowledge proof that the dedup hash is not already in the dedup registry, and publishes the proof. The dedup registry is a separate service that stores the dedup hashes themselves.

The reference proof system is Groth16 (snarkjs implementation). The circuit takes as private input the dedup hash and as public input a Merkle root of the dedup registry, and proves that the dedup hash is not a leaf of the Merkle tree. The proof is approximately 200 bytes. The verification time is approximately 5 milliseconds.

The dedup registry publishes a Merkle root to the DAG every six hours via a MERKLE_ROOT_PUBLISHED transaction. Any node can verify that the number of stored hashes matches the number of issued TIP-IDs, confirming deduplication enforcement without accessing individual hash values.

### 14.3 Privacy guarantees

The pepper-and-ZK architecture provides three privacy guarantees:

1. **The dedup hash is not recoverable from the DAG.** The DAG records the ZK proof, not the hash itself. An adversary with full DAG access cannot enumerate or test candidate dedup hashes.

2. **The dedup hash is not recomputable from government databases.** Without the device-held pepper, an adversary with access to the issuing government's ID database and the facial embedding hash cannot reproduce the dedup hash.

3. **The dedup registry cannot link hashes to TIP-IDs without the device.** The registry stores hashes; it does not store the link to the TIP-IDs that produced them. Linking requires the device-held pepper plus the holder's original biometric capture, both of which are destroyed in the registration flow.

### 14.4 What this prevents

The pepper architecture prevents three attack classes:

- **Mass re-identification.** A state actor or commercial database operator who learns the government ID number, date of birth, and facial embedding hash of every citizen still cannot link those citizens to their TIP-IDs.

- **Dedup-registry tampering.** A compromised dedup registry that adds, removes, or alters hashes will produce a Merkle root that does not match the count of issued TIP-IDs, detectable by any node that monitors the public DAG count.

- **VP-collusion identity merging.** A VP that attempts to issue two TIP-IDs to the same person, in collusion with the person, will produce the same dedup hash and be rejected at the ZK proof step.

## 15. Device Binding and Key Recovery

### 15.1 Device binding

The Layer 3 WebAuthn credential binds the TIP-ID to a specific device's secure enclave. Subsequent transactions signed by the TIP-ID require either:

- Re-authentication through the original device (the common case), or
- Recovery through the procedure in Section 15.3 (the exception)

The browser extension reference implementation supports two encryption methods for the holder's ML-DSA-65 private key:

- **WebAuthn PRF (preferred, Chrome and Edge 116+).** The WebAuthn PRF extension produces a deterministic 32-byte secret from the device authenticator without requiring a biometric prompt at each use. The 32-byte secret derives an AES-256 key that encrypts the private key envelope (Section 7.6). Decryption requires the original device and an initial PRF establishment.

- **WebAuthn fallback (portable, all browsers).** The AES key is derived from the credential ID through SHAKE-256 plus PBKDF2. The fallback requires a biometric gate on every signing operation but is portable across devices that share the credential ID.

### 15.2 Key rotation

A holder may rotate their ML-DSA-65 keypair at will by signing a KEY_ROTATED transaction (Section 32.5) with the current private key. The transaction carries the new public key. After commit, future signatures verify against the new public key. Historical signatures continue to verify against the rotated-out public key because the Verifier resolves the key effective at the historical signature's timestamp.

### 15.3 Key recovery

A holder who has lost access to the device on which their TIP-ID's signing key was held may initiate key recovery. The recovery procedure:

1. The holder visits the original issuing VP (or any accredited VP).
2. The holder re-completes Layers 1, 2, and 3 of the biometric verification stack on a new device. A new pepper is generated in the new device's secure enclave.
3. The new dedup hash is computed. If it matches the holder's original dedup hash from the records of the dedup registry (within the tolerance of the same government ID, date of birth, country, and same person's facial embedding), the recovery proceeds.
4. The VP issues a KEY_RECOVERY transaction (Section 32.6) which records the new ML-DSA-65 public key for the existing TIP-ID, signed by the VP's signing key. The old public key is rotated out.
5. The holder's trust score is preserved through the recovery.

The recovery does NOT mint a new TIP-ID. The original TIP-ID URI remains the same. Only the underlying signing key is replaced.

The recovery requires re-presenting the same government identity document. A holder whose document has expired or been replaced may need to demonstrate the chain of identity continuity to the VP before recovery is granted.

### 15.4 What recovery does not address

Key recovery does not address compromise of the signing key while the device is still in the holder's possession. A holder who suspects their device has been compromised (malware, supply-chain attack, sophisticated remote attack) MUST initiate REVOKE_DEVICE (Section 37.4) rather than rely on KEY_RECOVERY. REVOKE_DEVICE preserves the TIP-ID but pauses signing authority pending a fresh device binding.

## 16. Social Graph Attestation

### 16.1 Purpose

Layer 4 social graph attestation is an optional verification enhancement in which existing high-trust-score TIP-ID holders vouch for the identity of a new registrant. The attestation accomplishes three things:

1. **Bootstraps trust faster.** A T2, T3, or T4 holder begins with a higher trust score than the T1 default, accelerating their eligibility for adjudication roles.

2. **Distributes trust signals.** The attesting holders stake their own score points, so the protocol creates an incentive for established users to validate new users they know personally.

3. **Provides a Sybil-resistance signal.** A new TIP-ID that lacks any social attestation may be treated by some Verifiers as carrying a marginally higher Sybil-risk profile.

### 16.2 Mechanism

The new registrant initiates an attestation flow. Three existing TIP-ID holders, each with trust score at least 700, each sign an ATTESTATION_OFFERED transaction referencing the new registrant's pending TIP-ID. Each attesting holder stakes 25 score points held in escrow.

If the new registrant commits an origin misclassification (an UPHELD dispute outcome at Stage 2 or Stage 3) within 90 days of issuance, each attester loses the staked points. After 90 days without misclassification, the staked points return to the attester plus a small bonus.

### 16.3 Five-platform social proof

The reference VP mobile implementation also supports a five-platform social proof flow in which the holder demonstrates possession of social accounts on YouTube, X, Instagram, LinkedIn, and TikTok. For each platform the holder posts a verification code that the VP can retrieve, demonstrating control of the account. Each platform attestation grants +25 to the starting trust score, capped at +125 for all five.

Five-platform social proof is distinct from three-attester social graph attestation. Both may be combined. Both contribute to the verification tier (Section 13.5).

### 16.4 Limitations

Social attestation has known limitations. A new user with no existing TIP-ID holders in their personal network cannot obtain three attesters. A new user in a region with few accredited VPs may have difficulty obtaining attestations from regionally-relevant holders. The protocol therefore treats Layer 4 as optional and ensures that T1 (without Layer 4) is fully functional for content registration and verification. The trust score and tier distinction is the only protocol-level difference between T1 and the higher tiers.

---

# PART V · TIP-CONTENT PROVENANCE LAYER

## 17. Origin Codes

The protocol defines a closed enumeration of four Origin Codes. Every content registration MUST carry exactly one of these four codes. The codes are normative; no additional codes may be introduced without an RFC.

### 17.1 The four codes

**OH · Original Human.** The content was created entirely by the registrant without AI generation tools. Traditional non-generative tools (spell-check, grammar-check, color grading, format conversion, image filters that adjust pre-existing pixels rather than generating new ones) are permitted. The registrant is the primary creative agent and the substantive author.

**AA · AI-Assisted.** The registrant is the primary creative agent but used AI tools to enhance, edit, partially generate, or compose portions of the content. The human role is the structural and substantive judgment of what to publish; the AI role is a tool that participated in execution. AI-assisted editing of a human-authored draft, AI translation of human-original text, AI-completion of a human-written outline, AI image upscaling of a human capture, and AI grammar restructuring of a human paragraph all fall in this category.

**AG · AI-Generated.** The AI is the primary creative agent. The human role was prompting, curating, selecting from candidates, minor editing, or supplying source material. Generative AI prose, generative AI images, generative AI music, generative AI video, and generative AI code (where the human-provided portion is small and the AI portion is substantive) fall in this category. The distinction between AA and AG turns on which agent (human or AI) is doing the substantive creative work, not on the percentage of bytes that each contributed.

**MX · Mixed.** The content combines distinct human-created and AI-generated elements that are individually identifiable, with no single dominant origin. A photo essay where some photographs are human-captured and other photographs are AI-generated would be MX. A documentary where some narration is human and other narration is AI-generated would be MX. The registrant SHOULD additionally annotate the per-component origin where the content format supports component-level metadata.

### 17.2 Conservative labeling rule

A registrant who is uncertain whether their content is OH, AA, AG, or MX may always choose the higher-AI-involvement label without penalty. A creator who used a small amount of AI assistance and is uncertain whether to label OH or AA may safely label AA. A creator who is uncertain whether their AI-assisted work crossed the threshold to AI-generated may safely label AG. The protocol's adjudication mechanism (Section 28) penalizes under-disclosure but not over-disclosure.

The reason is that a reader who learns the content was actually more human than declared is not harmed (they get what they thought was AI-generated content that turned out to be human-generated, which is a strictly positive surprise). A reader who learns the content was actually more AI-generated than declared is materially deceived. The asymmetry is the source of the asymmetric penalty structure in Section 30.

### 17.3 Visual representation

The four Origin Codes have standardized visual representations specified in Section 48 of this specification and on the brand guidelines page at https://theailab.org/brand-guidelines. The standardized colors are:

- OH: Green (#1A8A5C)
- AA: Gold (#B8942E)
- AG: Coral (#C44569)
- MX: Purple (#6B46C1)

Implementations MAY use these colors or render the Origin Codes as text. Implementations MUST NOT invent new colors for the four Origin Codes. Color must be paired with text for accessibility; color alone does not convey the origin to readers using screen readers or with color-vision differences.

## 18. CTID URI Format

### 18.1 Format

A Content TIP Identifier (CTID) is a URI of the form:

```
tip://c/{OriginCode}-{Hash14}-{Author4}
```

Components:

- `tip://` is the protocol scheme
- `c` is the resource type segment indicating a content provenance record
- `OriginCode` is one of `OH`, `AA`, `AG`, `MX` (two uppercase ASCII letters)
- `-` is a literal hyphen separator
- `Hash14` is fourteen lowercase hexadecimal characters, the first fourteen characters of the lowercase hex encoding of SHAKE-256 over the CNA-2.2-normalized content bytes (Section 19)
- `-` is a literal hyphen separator
- `Author4` is four lowercase hexadecimal characters, the last four characters of the `Fingerprint16` segment of the signing author's TIP-ID URI

Example: For author `tip://id/US-a3f8c91b2d4e7021` registering original human content whose SHAKE-256 hash begins with `7f2a91bc3d5e4a`, the CTID is:

```
tip://c/OH-7f2a91bc3d5e4a-7021
```

(Note: the reference implementations vary in whether `Author4` is the first four or the last four hex characters of the fingerprint. The canonical implementation is the last four characters: `slice(-4)` of the post-region portion of the TIP-ID. The browser extension reference takes the last four; the WordPress plugin takes the last four; the VP mobile reference takes the last four. Earlier v4.0 of this specification ambiguously said "first four"; v5.0 clarifies to "last four".)

### 18.2 Properties

The CTID has three desirable properties:

- **Origin-visible.** A reader sees the origin code in every reference, link, or citation to the content. A URL of the form `tip://c/AG-...` immediately tells the reader that the content is AI-generated, without resolving the CTID against the DAG.

- **Tamper-evident.** The Hash14 segment is bound to the content. Any modification to the content changes the SHAKE-256 hash and therefore changes the CTID. A reader who recomputes the hash from the supposedly-original content can detect tampering.

- **Author-linked.** The Author4 segment links the CTID to its author's TIP-ID at a glance. Two CTIDs from the same author share the same Author4 suffix.

### 18.3 Resolution

A Verifier resolves a CTID by querying the DAG state. The reference resolution endpoint is `GET /v1/content/{ctid}` (Section 38.6). The response carries the full content registration record: origin code, content hash, author TIP-ID, signature, signing timestamp, registered URLs, dispute history, current verification status, and trust score of the author at the time of the response.

### 18.4 Use in citations

A scholarly or journalistic citation of TIP-registered content SHOULD include the CTID. The recommended citation format places the CTID after the standard citation elements:

```
Mendhe, D. (2026). Trust Identity Protocol Specification, Version 5.0.
The AI Lab Intelligence Unobscured, Inc. [OH] tip://c/OH-7f2a91bc3d5e4a-7021
```

The Origin Code in square brackets surfaces the origin to the reader of the citation. The CTID lets the reader resolve the content to verify the citation.

## 19. CNA-2.2 Canonical Content Normalization Algorithm

The canonical content hash that identifies a piece of content on the DAG is computed by applying CNA-2.2 to the raw content and then hashing the result with SHAKE-256. CNA-2.2 (Canonical Normalization Algorithm version 2.2) is a deterministic procedure that transforms content into a canonical byte sequence. Two pieces of content that differ only in formatting, syndication artifacts, embedded CTIDs, or platform-specific encoding produce the same canonical byte sequence and therefore the same hash. The CNA version is recorded in the `cna_version` field of the signed payload so that the Verifier knows which algorithm to apply.

### 19.1 The ten-step CNA-2.2 algorithm

CNA-2.2 applies the following ten steps in order. Each step is normative.

**Step 0 · Strip TIP artifacts.** Before normalization proper, the algorithm removes TIP-Protocol-specific artifacts that the content may have collected after registration. These include:

- Any substring matching `tip://id/{REGION}-{Fingerprint16}` (TIP-ID URIs)
- Any substring matching `tip://vp/{REGION}-{Fingerprint16}` (VP-ID URIs)
- Any substring matching `tip://c/{OriginCode}-{Hash14}-{Author4}` (CTID URIs)
- Bare 14-hex-character or 16-hex-character CTID tokens without the `tip://` prefix when they appear in contexts the content patterns confirm are TIP artifacts
- Promotional boilerplate: `Powered by TIP`, `TIP Protocol`, `AI Trust ID`, and the hashtags `#tip`, `#TIPProtocol`, `#HumanOrAI`

The rationale is verification round-trip correctness. After registration, the holder typically embeds the CTID into the published content (in the article footer, in a meta tag, or as the canonical share line). A Verifier who later recomputes the hash from the published content must obtain the same hash as was originally signed. Without Step 0, the post-registration embedding would change the hash and break verification.

**Step 1 · URL decoding.** Apply `decodeURIComponent` (or the equivalent in other languages) to the content bytes, decoding percent-encoded sequences such as `%20` (space), `%C3%A9` (é), and others into their underlying UTF-8 characters.

**Step 2 · CDATA stripping.** Remove the wrappers `<![CDATA[` and `]]>` where they appear (RSS, Atom, and other XML syndication formats use CDATA to enclose content).

**Step 3 · HTML and XML tag stripping.** Remove every tag of the form `<...>` (greedy, single line). Tags such as `<p>`, `<div class="x">`, `<a href="...">`, `<br/>`, and analogous structures are removed; the content between tags is retained.

**Step 4 · HTML entity decoding.** Decode named entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&nbsp;`, and the full HTML5 named entity table) and numeric entities (`&#233;`, `&#xE9;`) into their underlying Unicode characters.

**Step 5 · Markdown stripping.** Remove Markdown syntax: link wrappers (`[text](url)` becomes `text`), image syntax (`![alt](src)` becomes empty), bold and italic markers (`**text**` becomes `text`, `*text*` becomes `text`), heading markers (`# Heading` becomes `Heading`), and inline code wrappers (`` `code` `` becomes `code`).

**Step 6 · Unicode NFC normalization.** Apply Unicode Normalization Form C to the resulting string. NFC composes precomposed characters (`e` + combining acute accent becomes `é`) so that visually identical sequences hash to the same bytes.

**Step 7 · Lowercase.** Convert the result to lowercase using the locale-independent Unicode lowercase mapping. (The lowercase step happens after NFC so that locale-aware lowercase mappings produce consistent output across implementations.)

**Step 8 · Strip non-alphanumeric characters.** Retain only Unicode letters (`\p{L}`), Unicode numbers (`\p{N}`), and Unicode combining marks (`\p{M}`). Strip every other character including whitespace, punctuation, symbols, emoji, control characters, and any remaining formatting artifacts. The regex `[^\p{L}\p{N}\p{M}]/gu` describes the set to remove.

**Step 9 · UTF-8 encoding.** Encode the resulting Unicode string as UTF-8 bytes. The output of Step 9 is the canonical byte sequence that feeds into SHAKE-256.

### 19.2 Worked example

Input raw content (HTML article excerpt):

```html
<p>Hello from a TIP-Protocol publisher.</p>
<p>Visit <a href="https://example.com">our site</a>.</p>
<p>tip://c/OH-7f2a91bc3d5e4a-7021</p>
```

After Step 0 (TIP artifact strip): the `tip://c/OH-...` URI is removed.

After Step 3 (HTML tag strip): `Hello from a TIP-Protocol publisher.\nVisit our site.`

After Step 6 (NFC) and Step 7 (lowercase): `hello from a tip-protocol publisher.\nvisit our site.`

After Step 8 (strip non-alphanumeric): `hellofromatipprotocolpublishervisitoursite`

After Step 9 (UTF-8 encode): the 41-byte sequence corresponding to the ASCII string above.

The SHAKE-256 hash of these bytes is the `content_hash`. The first 14 characters of the hex encoding are the `Hash14` portion of the CTID.

### 19.3 Why Step 0 matters

The verification round-trip is the most common implementation challenge. A holder signs content, gets a CTID, publishes the content with the CTID embedded (in a footer, in a meta tag, or as the canonical share line at the bottom of the post). A reader later verifies by fetching the published content and recomputing the hash. Without Step 0, the embedded CTID changes the hash and the verification fails.

Step 0 normalizes around the post-publication embedding. The holder's pre-publication content (without the CTID) and the holder's post-publication content (with the CTID embedded) both produce the same canonical bytes after Step 0 and therefore the same hash.

### 19.4 Reference implementation

The reference Node.js implementation of CNA-2.2 is in `shared/crypto.js` (function `tipNormalize`) of the TIP node repository. The reference browser extension implementation is in `src/crypto.js`. The reference Python implementation is in the `python/` directory of the protocol repository. The reference PHP implementation is in the WordPress plugin source.

Conforming implementations MUST produce byte-identical output for the same input. The reference test vectors in the protocol repository's `test-vectors/cna-2.2/` directory MUST round-trip identically.

### 19.5 CNA version negotiation

The protocol's CNA version acceptance list is currently `["CNA-2.2"]`. Submissions MUST sign under `cna_version: "CNA-2.2"`. Verification accepts any version in the published acceptance list. New CNA versions are added through the RFC process in Section 50; the acceptance list grows monotonically so that historical signatures continue to verify.

When a new CNA version is added, the `cna_version` field of the signed payload tells the Verifier which version's normalization to apply. The Verifier carries multiple normalization implementations and dispatches based on the declared version. This is how the protocol supports normalization-algorithm evolution without breaking historical signatures.

## 20. The 8-Field Canonical Signed Payload

Every content registration produces a signed payload with exactly eight top-level fields, in the exact set below. Every field is always present. Empty values use explicit defaults rather than being omitted.

### 20.1 The eight fields

| # | Field | Type | Required? | Default | Description |
|---|---|---|---|---|---|
| 1 | `attribution_mode` | string | no | `"self"` | The signer's relationship to the bylined authors. Locked enum: `"self"`, `"employed"`, `"hosted"`. See Section 23. |
| 2 | `authors` | array of objects | yes | (must have at least 1 entry) | Ordered byline. Index 0 is the primary byline. Each entry is a 5-key object. See Section 20.3. |
| 3 | `cna_version` | string | yes | (no default) | The CNA version used to produce `content_hash`. Currently `"CNA-2.2"`. |
| 4 | `content_hash` | string | yes | (no default) | Lowercase 64-character hex of SHAKE-256 over the CNA-2.2-normalized content. |
| 5 | `extras` | object | no | `{}` | Open extension point. See Section 20.4. |
| 6 | `origin_code` | string | yes | (no default) | One of `"OH"`, `"AA"`, `"AG"`, `"MX"`. Always uppercase. |
| 7 | `registered_urls` | array of strings | no | `[]` | URLs where the content is published. Index 0 is the canonical / primary URL. Order is signed. |
| 8 | `signer_tip_id` | string | yes | (no default) | The TIP-ID whose private key produced the signature. |

The canonical builder picks exactly these eight fields and ignores anything else the caller puts at the top level. Extra fields do not enter the signed bytes; they are silently dropped. The Verifier reconstructs the canonical payload from these eight fields only.

### 20.2 `registered_urls` is mandatory

The `registered_urls` array MUST contain at least one entry: the canonical URL where the content is published or will be published. The protocol-level requirement makes a CTID resolvable to a published source. Without `registered_urls[0]`, a Verifier who encounters the CTID has no path back to the canonical published version.

The URL at index 0 is the primary URL. The URL is included in the signed payload, so it cannot be retroactively spoofed without invalidating the signature. The reference implementations (TIP node, browser extension, WordPress plugin) all enforce `registered_urls` as mandatory and reject submissions without it.

The pre-publication workflow is: the holder writes the content, generates the canonical URL on their publication platform, signs the CTID with the URL included, then publishes (and may optionally embed the resulting CTID into the published page). The DAG accepts post-publish edits, so the workflow can also be: publish first, retrieve the permalink, sign the CTID against the permalink, embed the CTID into the published page. Either workflow satisfies the mandatory `registered_urls` rule.

### 20.3 `authors[]` structure

Each entry in `authors[]` is a five-key object:

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `key_mode` | string | no | `"attribution"` | `"attribution"` (credited but not separately signed) or `"co_signed"` (also signed separately) |
| `role` | string | no | `"contributor"` | Free-form (typical: `"byline"`, `"contributor"`, `"editor"`, `"translator"`, `"photographer"`, `"reporter"`, `"columnist"`, `"guest"`) |
| `signed` | boolean | no | `false` | True if and only if a corresponding co-signature appears in the envelope |
| `tip_id` | string | yes | (no default) | The author's TIP-ID URI |
| `tip_id_type` | string | no | `"personal"` | Mirrors the `tip_id_type` field of the author's DAG identity record |

The array MUST have at least one entry. The maximum is ten entries (`MAX_AUTHORS_PER_POST = 10`). Index 0 is the primary byline.

For `attribution_mode: "self"` (the typical case), the signer is one of the authors, so `authors[0].tip_id` MUST equal `signer_tip_id`. For `attribution_mode: "employed"` or `"hosted"` (Section 23), the signer is a different entity from the bylined authors.

The Verifier performs a strict cross-check between `authors[i].tip_id_type` and the type recorded on the author's DAG identity record. A mismatch (claiming an organization TIP-ID as a personal byline, for example) returns the error code `author_tip_id_type_mismatch` and rejects the registration.

### 20.4 `extras` open extension point

The `extras` object is an open extension point for caller-supplied metadata that the caller wishes to bind cryptographically into the signature. Common entries include:

- `language`: ISO 639-1 language code of the content
- `publication_date`: ISO 8601 timestamp of original publication
- `c2pa_manifest_hash`: the SHA-256 hash of the accompanying C2PA manifest, binding the TIP registration to a specific C2PA manifest
- `doi`: an associated DOI
- `tags`: an array of caller-defined tags
- `wordpress_post_id`: the WordPress post ID (set by the WordPress plugin reference)

The contents of `extras` are signed and stored on the tx. The protocol does not enforce the schema of entries within `extras`; the caller is responsible for serializing values in a deterministic manner. Conforming Verifiers ignore `extras` for protocol-correctness purposes but expose it through the resolution API for downstream consumers.

`extras` MUST be a JSON object. It MUST NOT be an array. It MUST NOT be `null`. The empty default `{}` (two bytes in the canonical JSON) is always present even when no extras are supplied.

### 20.5 Reject-on-extra

The canonical builder picks exactly the eight top-level fields in Section 20.1 and ignores any other keys the caller places at the top level of the source object. Garbage fields do not enter the signed payload. This protects against client implementations that accidentally include sensitive or attacker-controlled data in their top-level payload object.

In particular: the field `signer_type` (which appeared in earlier drafts of the protocol) is explicitly NOT a canonical field. Implementations MUST NOT include `signer_type` in the canonical payload. If included, it is silently dropped. The signer's type is a property of the signer's TIP-ID and is resolved from the DAG identity record at verification time, not from the signed payload.

### 20.6 Worked canonical payload

For author `tip://id/US-a3f8c91b2d4e7021` registering original human content with content hash `7f2a91bc3d5e4a8d...` published at `https://example.com/article/`:

```json
{
  "attribution_mode": "self",
  "authors": [
    {
      "key_mode": "attribution",
      "role": "byline",
      "signed": false,
      "tip_id": "tip://id/US-a3f8c91b2d4e7021",
      "tip_id_type": "personal"
    }
  ],
  "cna_version": "CNA-2.2",
  "content_hash": "7f2a91bc3d5e4a8d...",
  "extras": {},
  "origin_code": "OH",
  "registered_urls": ["https://example.com/article/"],
  "signer_tip_id": "tip://id/US-a3f8c91b2d4e7021"
}
```

Canonical JSON output (single line, sorted keys, no whitespace, slashes unescaped):

```
{"attribution_mode":"self","authors":[{"key_mode":"attribution","role":"byline","signed":false,"tip_id":"tip://id/US-a3f8c91b2d4e7021","tip_id_type":"personal"}],"cna_version":"CNA-2.2","content_hash":"7f2a91bc3d5e4a8d...","extras":{},"origin_code":"OH","registered_urls":["https://example.com/article/"],"signer_tip_id":"tip://id/US-a3f8c91b2d4e7021"}
```

The SHAKE-256 hash of these canonical bytes, hex-encoded, ASCII-encoded, and ML-DSA-65-signed under the signer's private key, produces the signature that goes on the wire.

## 21. Content Registration Flow

A complete content registration consists of seven steps from the holder's perspective. Each step is normative; conforming Signers MUST implement all seven.

### 21.1 Step 1 · Origin declaration

The holder selects one of the four Origin Codes (OH, AA, AG, or MX) for the content being registered. The selection is a positive, affirmative act by the holder; conforming Signers MUST NOT default to a particular Origin Code or auto-suggest one based on AI classifier output. The holder's selection is the holder's declaration of authorship.

### 21.2 Step 2 · AI pre-scan with calibrated thresholds

For OH-declared submissions only, the system runs an AI pre-scan classifier over the content. The pre-scan output is a probability in [0.0, 1.0] that the content was AI-generated. The pre-scan is advisory.

The pre-scan threshold is calibrated per content type and per creator. The default thresholds by content type:

| Content type | Default threshold |
|---|---|
| Conversational (social posts, chat) | 0.82 |
| News, journalistic | 0.85 |
| Creative fiction | 0.87 |
| Academic, technical | 0.92 |
| Legal, formal | 0.93 |

The creator-calibration formula is:

```
T_c = T_baseline + min(H / 200, 1.0) * (T_ceiling - T_baseline)
```

where `T_baseline` is the content-type default, `T_ceiling` is the hard ceiling (0.94), and `H` is the count of the holder's prior OH content that was confirmed CLEARED by adjudication. As the holder accumulates more verified OH content, the threshold for flagging their content rises, reducing false positives for established authors.

If the pre-scan exceeds the calibrated threshold:

- Content is registered with status `pending_review`
- A 48-hour grace window opens
- The holder MAY update the Origin Code to a different value within the grace window at zero penalty
- After 48 hours without update, a Community Reviewer is assigned (Section 29)

If the pre-scan is at or below the calibrated threshold, the content is registered with status `verified` and no review is triggered.

### 21.3 Step 3 · Dual hash computation

The system computes two hashes:

- **Content hash.** SHAKE-256 over the CNA-2.2-normalized content bytes (Section 19), 32-byte output, hex-encoded. This is the `content_hash` field.

- **Perceptual hash.** A format-appropriate perceptual hash for fuzzy matching across reposts, transcoded versions, and minor modifications. For text content the reference is SimHash. For images the reference is pHash. For audio the reference is Chromaprint. For video the reference is a frame-sampled pHash. The perceptual hash is stored in the auxiliary HTTP envelope (Section 21.6) but is not part of the canonical signed payload.

### 21.4 Step 4 · Canonical payload construction

The system constructs the 8-field canonical payload (Section 20.1) with the holder's TIP-ID as `signer_tip_id`, the selected Origin Code, the computed content hash, the holder's bylined authors (typically just themselves under `attribution_mode: "self"`), the publication URL in `registered_urls[0]`, the locked `cna_version: "CNA-2.2"`, and an `extras` object containing any caller-supplied metadata.

### 21.5 Step 5 · ML-DSA-65 signing

The system applies the five-step signing math (Section 9): canonical bytes, SHAKE-256, hex-encode, ASCII-encode, ML-DSA-65 sign. The signature is hex-encoded for transport.

### 21.6 Step 6 · HTTP envelope submission

The system constructs the HTTP envelope and POSTs it to the TIP node's `/v1/content/register` endpoint (Section 38.3). The envelope carries:

- All 8 canonical signed fields, with the same values used to construct the canonical payload
- The signature (hex-encoded)
- The full content bytes (or a media canonical hash for non-text content)
- The content type (`text`, `image`, `video`, `audio`)
- The perceptual hash from Step 3
- Optional metadata that is NOT part of the signed payload (caller-supplied display name, account ID, etc.)

The node verifies the signature, checks DAG state (signer is registered and not revoked, all authors are registered, dedup checks pass), assigns a `tx_id`, and returns the assigned CTID.

### 21.7 Step 7 · CTID generation

The CTID is constructed deterministically from the Origin Code, the content hash, and the signer's TIP-ID fingerprint:

```
ctid = "tip://c/" + origin_code + "-" + content_hash[0:14] + "-" + signer_fingerprint16[-4:]
```

The CTID is returned to the caller in the registration response. The caller MAY embed the CTID into the published content (post-publish embedding triggers Step 0 of CNA-2.2 on subsequent verifications), and SHOULD include the CTID in the canonical share line described in Section 22.

## 22. Copy-Paste Fallback and Cross-Platform Sharing

### 22.1 The fallback line

When a creator copies a CTID and pastes it into a post on any platform that does not render an inline TIP verification badge, the canonical two-line fallback format is:

```
tip://c/{OriginCode}-{Hash14}-{Author4}
Click to find out #HumanOrAI
```

For example:

```
tip://c/OH-3400957c8e2e5d-4a85
Click to find out #HumanOrAI
```

The fallback line is the protocol's universal cross-platform sharing format. The CTID is a clickable verification link on platforms that auto-linkify URLs. The hashtag `#HumanOrAI` is the cross-network discovery aggregator that lets readers find TIP-verified content on any platform that supports hashtag search.

### 22.2 Platform behavior

The fallback works on every link-rendering surface, including:

- X (formerly Twitter)
- LinkedIn
- Facebook
- Threads
- Bluesky
- Mastodon (any instance)
- Reddit
- Discord
- WhatsApp
- Telegram
- Substack comments
- Medium comments
- Plain-text email
- Slack
- iMessage
- SMS
- Any forum, chat, or commenting system that auto-detects URLs

A reader who clicks the CTID URL on any of these platforms lands on the public TIP verification page, which resolves the CTID against the DAG and shows the Origin Code, the author trust score, the dispute history, and the canonical publication URL.

### 22.3 Resolution target

The CTID URI scheme (Section 53) defines the resolution target. On a platform with a TIP browser extension installed, the extension intercepts the click and renders the verification badge inline. On a platform without the extension, the CTID URI resolves to:

```
https://tip.theailab.org/r/{ctid}
```

or to the equivalent resolver of the integrating Verification Provider. The resolver displays the verification page with the Origin Code, trust score, author identity, dispute history, and CC-BY-licensed badge assets that downstream platforms may embed.

### 22.4 Why the fallback matters

The fallback line removes the requirement that platforms or end users install software for the protocol to work. EU AI Act Article 50 compliance, California AI Transparency Act compliance, and analogous regulatory frameworks require machine-readable AI content labels but do not require any particular software stack. The CTID URL is machine-readable (a regex over text retrieves it), the resolution is deterministic, and the verification page is accessible to any reader with a web browser. The protocol therefore meets the regulatory bar without imposing a software dependency on either platforms or users.

The `#HumanOrAI` hashtag is the trademark of The AI Lab (the brand guidelines specify the public-use permission). The hashtag's purpose is community-discoverable aggregation of TIP-verified content. Implementations MAY use other hashtags but the canonical fallback line includes `#HumanOrAI` exclusively.

## 23. Publisher Mode and Creator Mode

The protocol supports two distinct content-signing patterns through the `attribution_mode` field of the canonical payload.

### 23.1 Creator Mode (`attribution_mode: "self"`)

The default mode. The signer is themselves a human content author. The signer's TIP-ID appears as the sole entry in `authors[]`. The `authors[0].tip_id` equals `signer_tip_id`. The `tip_id_type` is `personal`.

Creator Mode is what individual creators use. A journalist with a personal TIP-ID who publishes an article under their own byline signs in Creator Mode. A YouTuber, a Substacker, a Medium writer, a X user, a Mastodon user, all use Creator Mode for content where they are the sole author.

### 23.2 Publisher Mode (`attribution_mode: "employed"`)

A publisher organization signs on behalf of one or more human authors who are employees, contractors, or correspondents. The signer's TIP-ID is the publisher's TIP-ID (`tip_id_type: "publisher"`). The `authors[]` array lists the human author TIP-IDs as bylines. Each bylined author has `key_mode: "attribution"`. If the publisher chooses to include co-signatures from one or more bylined authors (so that the article is signed both by the publisher and by the author individually), the corresponding `authors[i].key_mode` is set to `"co_signed"` and `signed` is set to `true`, with the co-signature appearing in the HTTP envelope's `co_signatures[]` array.

Publisher Mode is what news organizations use. The New York Times signs every article with the NYT publisher TIP-ID. The bylined reporter's personal TIP-ID appears in `authors[]`. The publisher's signature establishes editorial responsibility. The reporter's co-signature (when present) establishes personal authorship attribution.

### 23.3 Hosting Mode (`attribution_mode: "hosted"`)

A platform hosts third-party content without claiming editorial responsibility. The signer is the platform's TIP-ID. The `authors[]` array lists the contributors. The platform's signature establishes the technical provenance trail (the platform observed and recorded that the contributor uploaded the content) without claiming editorial endorsement.

Hosting Mode is what platforms like Substack or Medium might use for third-party newsletters that they host but do not edit. The platform's TIP-ID signs the content for protocol integrity; the contributor's TIP-ID appears as the author.

### 23.4 Platform restriction for non-creator modes

The reference browser extension restricts `attribution_mode: "employed"` and `attribution_mode: "hosted"` to long-form content surfaces (news articles, blog posts, podcast episode pages, newsletter posts) and disallows them on social posts (X, Facebook, Instagram, Threads, Bluesky, LinkedIn posts), messaging (WhatsApp, Telegram, Discord), and short-form video (YouTube Shorts, TikTok). The restriction reflects the publishing reality that organizational signing makes sense for editorial content but not for individual social posts.

### 23.5 Roster management

Publishers maintain a roster of bylined contributors. The reference VP mobile implementation supports roster CRUD: adding contributors by TIP-ID, assigning roles, and managing role-specific signing permissions. The roster is a UX feature of the implementation; the protocol records the per-content `authors[]` array on every registration but does not record the cross-content roster on the DAG.

## 24. Edge Case Rulings for Origin Classification

The Origin Code definitions in Section 17 cover the typical cases. The community has accumulated experience with edge cases over two years of protocol operation, which are codified below. These rulings inform Reviewer, Juror, and Expert Panelist judgment in adjudication; they do not change the four-code enumeration.

| Case | Recommended Origin | Reasoning |
|---|---|---|
| Spell-check and grammar tools | OH | Traditional non-generative tooling |
| AI autocomplete (less than 20% of content AI-suggested and accepted) | OH | Human substance dominates |
| AI autocomplete (more than 20% AI-suggested and accepted) | AA | AI participation is substantive |
| AI translation of human-original text | AA | Ideas human, language AI |
| AI grammar restructuring of a human paragraph | AA | Human substance, AI restructure |
| Heavily edited AI first draft (substance changed by human) | AA | Human is final substantive author |
| Lightly edited AI first draft (minor changes) | AG | AI is substantive author |
| Computational photography (HDR, noise reduction, multi-frame fusion in a phone camera) | OH | Sensor capture with traditional processing |
| AI photo enhancement (upscaling, background generation) | AA | Human capture, AI enhancement |
| Generative AI image (text-to-image) | AG | AI is substantive image author |
| AI voice generation (text-to-speech of human-written script) | AA | Human substance, AI synthesis |
| AI voice cloning of a real person (consent-based) | AA | Human script, AI voice |
| Deepfake of a real person without consent | AG (and a prohibited use) | AI authorship and a Prohibited Conduct violation under TIP Terms of Service Section 9 |
| AI-generated code that a human prompted and reviewed | AA or AG depending on extent | If the human substantially shaped the design, AA; if the AI produced the working logic with the human providing only loose prompts, AG |
| AI summary of human content | AG | AI is the substantive author of the summary |
| Photo essay with some human captures and some AI generations | MX | Mixed by design |
| Documentary with some human and some AI narration | MX | Mixed by design |

These rulings are advisory. A holder uncertain about classification may apply the conservative labeling rule (Section 17.2) without penalty.

---

# PART VI · TIP-TRUST REPUTATION LAYER

## 25. Deterministic Trust Score Computation

### 25.1 The score-as-derived-state invariant

The TIP-TRUST score for a given TIP-ID is a deterministic integer derived from the complete public DAG history of that TIP-ID. The score is not stored centrally. Any conforming node that has replayed the same DAG history MUST compute the same score.

Formally:

```
score(tip_id, T) = clamp_0_1000( base(tip_id) + sum_of delta(tx) forall tx in DAG : tx.subject_of = tip_id and tx.timestamp less-than-or-equal T )
```

where:

- `T` is the time at which the score is being queried
- `base(tip_id)` is the starting score (Section 13.5)
- `delta(tx)` is the score delta assigned to transactions whose `subject_of` field references the TIP-ID
- `clamp_0_1000` constrains the result to the integer range 0 through 1000

The replay is deterministic in the sense that any node, given the same DAG transactions, computes the same score. The protocol's openness rests on this invariant: a reader who distrusts the displayed score can replay the DAG independently and verify.

### 25.2 Score delta events

Every event that affects a TIP-ID's score is recorded as a SCORE_UPDATE transaction with a numeric `delta` field. The SCORE_UPDATE transaction is paired with the originating transaction (the verdict, the dispute filing, the appeal filing, the verification action, etc.) so that the score delta has a single auditable source. The protocol's "single-channel rule" forbids implicit score changes: every delta must appear in a SCORE_UPDATE transaction with a stated reason.

The canonical delta table appears in Section 30.

### 25.3 Starting scores

| Verification tier | Starting score |
|---|---|
| T1 (Layers 1, 2, 3) | 500 |
| T2 (T1 plus partial Layer 4) | 525 or 550 |
| T3 (T1 plus full Layer 4) | 575 or higher |
| T4 (VP-enhanced) | 600 or higher |

### 25.4 Bounds

Scores are clamped to the integer range [0, 1000] at every update. A holder cannot go below 0 (a TIP-ID at score 0 is functionally inactive but the TIP-ID record remains on the DAG, available for content provenance verification of historical content). A holder cannot go above 1000 (further positive deltas are silently capped).

### 25.5 No score storage

A conforming node MAY cache scores for performance (the reference TIP node maintains a `score_mirror` table that is rebuilt at every SCORE_UPDATE). The cache is a performance optimization, not a source of truth. A node that loses its cache reconstructs it by replaying the DAG. A node whose cache disagrees with the deterministic replay has a defect; the replay value wins.

The non-storage of scores is the protocol's privacy mechanism for Article 17 erasure (Section 46): an erasure of a TIP-ID's SCORE_UPDATE history resets the score to baseline because the score is derived state, not stored data.

## 26. Trust Tiers and Visualization

### 26.1 The five tiers

| Score range | Tier | Shield icon | Color |
|---|---|---|---|
| 800 to 1000 | HIGHLY_TRUSTED | check | Green (#1A8A5C) |
| 600 to 799 | TRUSTED | check | Blue (#2563A8) |
| 400 to 599 | REVIEW_ADVISED | exclamation | Amber (#A88B15) |
| 200 to 399 | LOW_TRUST | cross | Orange (#C07318) |
| 0 to 199 | NOT_TRUSTED | cross | Red (#C53030) |

The tier labels and colors are normative for any conforming implementation that displays trust signals visually. Implementations MUST NOT invent new tier names. Implementations MUST NOT use the tier colors for other purposes that could confuse readers (a green color elsewhere on the page MUST NOT be confused with the HIGHLY_TRUSTED tier).

### 26.2 Tier-only display

The default display mode shows the tier label without the numeric score. A reader sees "TRUSTED" rather than "score: 750". The protocol's privacy default is TIER_ONLY (Section 27); the FULL_PUBLIC numeric display requires explicit opt-in by the holder.

### 26.3 Accessibility

Implementations MUST pair tier color with text. A visually-impaired reader using a screen reader, or a reader with red-green color blindness, MUST be able to perceive the tier without the color. The standard text labels are: HIGHLY_TRUSTED, TRUSTED, REVIEW_ADVISED, LOW_TRUST, NOT_TRUSTED.

## 27. Score Visibility Modes

The protocol provides three score visibility modes that the holder controls. The modes implement GDPR Article 25 data minimization and Article 22 protection against profiling.

### 27.1 The three modes

**FULL_PUBLIC.** The numeric score and tier label are visible to all third parties. Display variant for opt-in publicity.

**TIER_ONLY.** Only the tier label (HIGHLY_TRUSTED, TRUSTED, etc.) is visible. The numeric score is hidden from third parties. **This is the default at registration.**

**VERIFIED_ONLY.** Only a binary verified/unverified indicator is visible. No tier label, no numeric score. The most restrictive mode.

### 27.2 Mode selection

The holder selects the mode at registration through the VP enrollment flow and may change it at any time through an UPDATE_PROFILE transaction. The current mode is part of the TIP-ID's public DAG state.

A conforming Verifier MUST respect the holder's selected mode. Displaying the numeric score for a holder whose mode is TIER_ONLY is a GDPR violation (Article 25 data minimization). The Verifier resolves the holder's TIP-ID, observes the mode, and renders accordingly.

### 27.3 Mode in zero-knowledge proofs

A relying party that needs to verify "this holder's score is at least X" without revealing the exact score MAY use a zero-knowledge score-threshold proof. The reference proof system is Groth16 with a Poseidon hash, producing a proof that the holder's score (held privately by the holder) is at least the threshold (publicly stated) without revealing the exact value. The proof is approximately 200 bytes and verifies in approximately 5 milliseconds.

Zero-knowledge threshold proofs are how the protocol implements GDPR-compliant qualification checks (for example, "is the holder eligible to be a Juror?" requires score >= 700; the proof reveals only the answer, not the holder's exact score).

## 28. Adjudication Pipeline (Three Stages)

A dispute about an Origin Code is resolved through a three-stage pipeline: an AI classifier at Stage 1 (advisory and routing-only), a community jury at Stage 2 (the first authoritative human verdict), and an expert panel at Stage 3 (the final non-appealable verdict).

### 28.1 What triggers adjudication

A dispute is triggered by one of three events:

- **Creator does not clear a Pre-Scan flag.** Content registered with `status: pending_review` (Section 21.2) enters the pre-scan review pipeline after the 48-hour grace window.

- **Disputer files a public dispute.** Any TIP-ID holder with score at least 400 may file a CONTENT_DISPUTED transaction against another party's content (Section 28.4).

- **VP escalates a fraud finding.** A REVOKE_VP transaction (Section 37.2) cascades dispute initiation for content the revoked party registered within the preceding 90 days.

### 28.2 Stage 1 · AI classifier and Community Reviewer

For content flagged through pre-scan, an AI classifier runs first, producing an AI_CLASSIFIER_RESULT transaction with a probability in [0.0, 1.0]. The classifier is advisory; it does not by itself impose any adverse action.

If the AI classifier result is above 0.90 (HIGH or CRITICAL confidence), the case auto-escalates to Stage 2. If below 0.30, the case is auto-dismissed. Between 0.30 and 0.90, the case is routed to a Community Reviewer.

The Community Reviewer (Section 29.1) is a single TIP-ID holder with score at least 800 who has not opted out of Reviewer assignments. The Reviewer has 48 hours to render one of three decisions:

- **DISMISS.** The AI classifier was wrong; the content matches its declared origin. The case closes with no adverse effect on the holder.
- **CONFIRM.** The AI classifier was right; the content does not match its declared origin. The holder is given 24 hours to update the Origin Code or escalate the case to Stage 2 (public jury).
- **RECUSE.** The Reviewer has a conflict of interest or feels unqualified to judge this case. The case is reassigned to another Reviewer.

A Reviewer who does not respond within 48 hours is automatically recused and the case is reassigned. Repeated no-shows contribute to the Reviewer's accuracy and availability metrics and may eventually pause the Reviewer's future assignments under the eligibility filter (Section 29.1).

### 28.3 Stage 2 · Community Jury

If a Reviewer CONFIRMS and the holder does not update the Origin Code within 24 hours (or actively elects to escalate), the case proceeds to Stage 2 with the Reviewer as the formal disputer (the Reviewer's CONFIRM becomes the dispute claim).

A panel of seven Community Jurors (Section 29.2) is summoned through JURY_SUMMONS transactions. Each Juror is a TIP-ID holder with score at least 700 who has not opted out. The Jurors review the content, the declared Origin Code, the AI classifier output (if available), and the disputer's evidence.

Jurors vote in a commit-reveal scheme to prevent vote-following:

- **Commit phase (72 hours).** Each Juror computes a commitment `H = SHAKE-256(vote || salt)` for their vote and a random salt, signs the commitment, and publishes a JURY_VOTE_COMMIT transaction.

- **Reveal phase (12 hours).** Each Juror publishes a JURY_VOTE_REVEAL transaction with the vote and salt. The Verifier checks that the SHAKE-256 of the revealed vote-plus-salt matches the earlier commitment.

The vote options are:

- **MATCH.** The content matches its declared origin (the creator was correct).
- **MISMATCH.** The content does not match its declared origin (the disputer was correct). Voters selecting MISMATCH MUST additionally specify what they believe the correct origin is (OH, AA, AG, or MX).
- **ABSTAIN.** The Juror cannot fairly judge this case.

The verdict is computed after the reveal phase:

- **Quorum.** At least 5 of 7 Jurors must have revealed votes, and at least 3 of those must be non-abstain.

- **UPHELD.** Majority of non-abstain votes select MISMATCH with a single dominant alternative origin. The content's Origin Code is updated to the dominant alternative. The creator's score takes the asymmetric penalty (Section 30) and offense count increments. The disputer's stake is refunded with an UPHELD bonus.

- **CONSERVATIVE_LABEL.** Majority of non-abstain votes select MISMATCH but the alternative origin votes are split across multiple options. The content's Origin Code is updated to the smallest-penalty alternative (typically the next-higher AI involvement level). The creator's score is not penalized (the protocol's response to inconclusive verdicts on the precise alternative is to apply the lightest correction without scoring impact). The disputer's stake is refunded without the UPHELD bonus.

- **DISMISSED.** Majority of non-abstain votes select MATCH. The disputer's stake is forfeited. The creator receives a small VINDICATION bonus.

- **NO_QUORUM.** Quorum thresholds were not met. The case auto-escalates to Stage 3 without disputer-stake settlement.

### 28.4 Filing a Stage 2 dispute directly

Any TIP-ID holder with score at least 400 may file a Stage 2 dispute directly (without a Reviewer's CONFIRM) by signing a CONTENT_DISPUTED transaction against another party's content. The filer becomes the formal Disputer.

Filing a dispute stakes 15 score points (DISPUTER_STAKE). The stake is held in escrow. The dispute follows the Stage 2 procedure above.

The filer's stake is settled at verdict:

- **UPHELD verdict:** Stake refunded plus +5 UPHELD_BONUS. Net +5.
- **CONSERVATIVE_LABEL verdict:** Stake refunded. Net 0.
- **DISMISSED verdict:** Stake forfeited. Net -15.
- **NO_QUORUM verdict:** Stake remains locked pending Stage 3 resolution.

The 15-point stake is the protocol's economic friction against frivolous disputes. A holder with score 410 who files a frivolous dispute and loses drops to score 395, marking them as REVIEW_ADVISED and potentially gating their future Disputer eligibility.

A holder may file at most five disputes per rolling 30 days (DISPUTER_FREQUENCY_CAP).

### 28.5 Stage 3 · Expert Panel

The losing party of Stage 2 (the Disputer if DISMISSED, the Creator if UPHELD) may appeal to Stage 3 by signing an APPEAL_FILED transaction. The appellant stakes an additional 25 score points (APPELLANT_STAKE).

Three Community Expert Panelists (Section 29.3) are summoned. Each Expert has score at least 850 and has not opted out. The Experts vote under the same commit-reveal protocol as the Jury (72 hours commit, 6 hours reveal). Quorum requires at least 2 of 3 to reveal non-abstain votes.

The verdict options are the same as Stage 2 (UPHELD, CONSERVATIVE_LABEL, DISMISSED) but the verdict applies as a final, non-appealable outcome and reverses any Stage 2 settlement that conflicts with the Stage 3 finding.

Stage 3 settlement of the appellant's stake:

- **Stage 3 overturns Stage 2 (appellant wins):** Stage 2 settlement is reversed end-to-end. Appellant receives stake refund (+25) plus OVERTURN_BONUS (+10). Net +35 above the appellant's Stage 2 position.
- **Stage 3 confirms Stage 2 (appellant loses):** Appellant stake is forfeited.

The cradle-to-grave net for a Stage 2 loser who appeals and wins Stage 3 is approximately:

```
Stage 2 loss: -15 (disputer who lost) or -100 (creator who lost OHtoAG 1st offense)
Stage 3 appeal filing: -25
Stage 3 appellant settlement: +35
Stage 3 reversal of Stage 2: +15 (disputer) or +100 (creator)
Net: +10 (disputer) or +10 (creator)
```

The math is designed so that an appellant who is genuinely right gains net positive points after appeal, while an appellant who is genuinely wrong loses significantly more than they would have by accepting the Stage 2 verdict.

### 28.6 Why the three stages

The three-stage structure exists for three reasons:

1. **Cost efficiency.** Stage 1 (AI classifier) is essentially free; it resolves the easy cases. Stage 2 (jury of 7) is moderate-cost; it resolves the cases that require human judgment but not specialized expertise. Stage 3 (panel of 3 experts) is expensive in participant time; it is reserved for genuinely contested cases.

2. **Robustness against single-stage error.** Any single stage can be wrong. A naive AI classifier produces false positives. A jury can miss a fact pattern an expert would have caught. An expert can be biased. The three stages produce three independent looks at the same case, each layer correcting for the failure modes of the previous.

3. **Procedural legitimacy.** A user whose content is challenged is entitled to a hearing. The protocol's three stages give the user multiple opportunities to be heard, to update their Origin Code, to present evidence, and to appeal. The procedural depth is what makes the protocol's adverse actions defensible against an enforcement challenge.

## 29. Community Adjudication Roles

The three Community Adjudication Roles (Reviewer, Juror, Expert Panelist) are staffed by opt-out-available TIP-ID holders. The protocol's enrollment posture is default-enabled with one-action opt-out, as documented in the TIP Terms of Service Section 5.10 and the project memory file `.claude/memory/community-adjudication-policy.md`.

### 29.1 Community Reviewer

**Eligibility:** Score at least 800, personal-identity TIP-ID, participation toggle in the ON position (default ON at registration), reviewer overturn rate below 30% over the most recent 20 decisions.

**Role:** Stage 1 human checkpoint after AI Pre-Scan flag and the 48-hour creator correction window.

**Time window:** 48 hours from notification to render DISMISS, CONFIRM, or RECUSE.

**Scoring:**

| Action | Score effect |
|---|---|
| DISMISS that closes the case cleanly | +5 |
| CONFIRM that the creator accepts privately within the creator's 24h window | +5 |
| CONFIRM that escalates to Stage 2 and is UPHELD | +10 net |
| CONFIRM that escalates to Stage 2 and yields CONSERVATIVE_LABEL | +5 net |
| CONFIRM that escalates to Stage 2 and is DISMISSED | -15 net (counts toward overturn rate) |
| RECUSE | 0 |
| Auto-recuse (48h silence) | 0 (but contributes to availability metric) |

### 29.2 Community Juror

**Eligibility:** Score at least 700, personal-identity TIP-ID, adjudication participation toggle in the ON position (default ON at registration).

**Role:** Stage 2 jury panel member. Panel size 7.

**Time window:** 72-hour commit phase, 12-hour reveal phase. Total 84 hours.

**Scoring:**

| Action | Score effect |
|---|---|
| Vote with the majority of revealed non-abstain votes, valid reveal | +3 |
| Vote against the majority of revealed non-abstain votes, valid reveal | -10 |
| Abstain with valid reveal | 0 |
| No-show (failed to commit OR failed to reveal OR commit-reveal mismatch) | -10 |
| Jury fails to reach quorum | 0 (no juror score effects applied; case auto-escalates to Stage 3) |

### 29.3 Community Expert Panelist

**Eligibility:** Score at least 850, personal-identity TIP-ID, adjudication participation toggle in the ON position (default ON at registration).

**Role:** Stage 3 expert panel member. Panel size 3.

**Time window:** 72-hour commit phase, 12-hour reveal phase. Total 84 hours.

**Scoring:** +7 majority, -10 minority, 0 abstain, -10 no-show. Expert majority bonus is higher than the Juror's +3 because expert participation is reserved for higher-trust (≥850) holders and the bigger reward calibrates incentives for the harder Stage-3 calls.

### 29.4 Default-enabled enrollment

Upon registration of a personal-identity TIP-ID, the holder is enrolled by default in the candidacy pool for all three community adjudication roles. The eligibility filters above (score floors, identity type, overturn rate gate, conflict-of-interest filters) operate as a natural pre-selection layer: a newly-registered holder with score 500 will not actually be selected for any role because they do not meet the score floor.

The holder may opt out at any time through the participation toggles in the profile settings. Two toggles control candidacy:

- "Available for community review assignments" (controls Reviewer candidacy)
- "Available for adjudication panels" (controls Juror and Expert Panelist candidacy together)

Both toggles default to ON. Toggle-off takes effect immediately for new assignments; in-flight assignments may be completed, recused, or no-showed under the normal scoring rules. There is no score penalty for opt-out.

This default-enabled-with-opt-out posture is the protocol's response to the alternative (strict opt-in) which would not produce a sufficiently large or diverse candidate pool to staff the adjudication system. The eligibility floors act as the substantive filter; the toggle is the holder's expressed preference.

### 29.5 Conflict-of-interest filters

The selection algorithm excludes candidates with conflicts of interest:

- The content registrant
- The disputer
- Any TIP-ID that participated in an earlier panel on the same case
- For Stage 3: any TIP-ID that served on the Stage 2 jury for the same case

These filters operate deterministically. The selection algorithm produces the same selection across nodes given the same DAG state.

### 29.6 Anonymity

Adjudication participants are recorded on the DAG only as their TIP-ID. The Verifier does not display real names, contact information, geographic location, or biometric data. Panel vote breakdowns become public after the reveal phase; the holder's TIP-ID and vote become visible to anyone who queries the DAG.

### 29.7 No compensation

Community adjudication is a community-service function. Participants receive no salary, fee, equity, virtual currency, or other form of monetary compensation from The AI Lab. The trust score deltas in Sections 29.1 through 29.3 are reputational signals, not compensation. The protocol's wage-and-hour and employment-classification waiver is in TIP Terms of Service Section 5.10.9.

## 30. Scoring Constants and Asymmetric Penalty Structure

### 30.1 Genesis constants

The following constants are recorded in the Genesis Block (Section 33) and govern protocol-level scoring. They may be amended only through an RFC and a coordinated network upgrade.

| Constant | Value | Purpose |
|---|---|---|
| DISPUTER_STAKE | 15 | Deducted from a TIP-ID at file-dispute time |
| UPHELD_BONUS | 5 | Disputer's Stage 2 win bonus |
| VINDICATION_BONUS | 5 | Author's "content cleared" bonus |
| APPELLANT_STAKE | 25 | Deducted at file-appeal time |
| OVERTURN_BONUS | 10 | Appellant's appeal-win bonus |
| JUROR_MAJORITY_BONUS | 3 | Stage-2 juror majority-vote reward |
| EXPERT_MAJORITY_BONUS | 7 | Stage-3 expert majority-vote reward (higher than juror because expert participation requires score ≥850) |
| MINORITY_PENALTY | 10 | Juror or expert minority-vote forfeit |
| NO_SHOW_PENALTY | 10 | Summoned but did not reveal |
| REVIEWER_CORRECT_BONUS | 5 | Pre-scan reviewer's case-closed-cleanly bonus |
| CLEAN_RECORD_DAYS | 90 | Time without offense to earn clean-record bonus |
| CLEAN_RECORD_BONUS | 10 | Awarded after 90 days without offense |
| MERKLE_INTERVAL_HOURS | 6 | Dedup-registry Merkle root publish cadence |
| DAG_MIN_REFS | 2 | Each transaction references 2 prior transactions |
| DISPUTE_AUTO_ESCALATE | 0.90 | AI classifier probability above which Stage 2 auto-triggers |
| DISPUTE_AUTO_DISMISS | 0.30 | AI classifier probability below which case auto-dismisses |
| PRESCAN_FLOOR | 0.80 | Lowest creator-calibrated threshold |
| PRESCAN_CEILING | 0.94 | Highest creator-calibrated threshold |
| PRESCAN_DEFAULT | 0.85 | Default pre-scan threshold for new creators |
| STARTING_SCORE | 500 | T1 starting score |
| ATTESTED_STARTING_SCORE | 550 | T2 baseline starting score |
| MAX_SCORE | 1000 | Score ceiling |
| MIN_SCORE | 0 | Score floor |
| SOCIAL_ATTESTATION_BONUS | 50 | Maximum bonus across social platforms |
| VOUCHER_STAKE | 25 | Per-voucher stake in Layer 4 attestation |
| MAX_AUTHORS_PER_POST | 10 | Authors array hard limit |
| DISPUTER_FREQUENCY_CAP | 5 | Disputes per 30 days per filer |

### 30.2 Asymmetric origin-mismatch penalties

When a Stage 2 or Stage 3 verdict yields UPHELD, the author's score is reduced according to the per-origin-pair penalty table:

| Origin claimed | True origin | 1st offense | 2nd offense | 3rd+ offense |
|---|---|---|---|---|
| OH | AG | -100 | -200 | -300 |
| OH | AA | -40 | -80 | -120 |
| AA | AG | -25 | -50 | -75 |
| anything else | anything | 0 | 0 | 0 |

The penalty escalates with offense count to deter repeat offenders. The escalation is per-pair: a repeat AAtoAG offender's third offense costs -75 (the AAtoAG ladder), not -300 (the OHtoAG ladder).

CONSERVATIVE_LABEL verdicts (jury agreed origin was wrong but disagreed on the precise alternative) carry zero penalty.

DISMISSED verdicts (jury found the original claim correct) carry zero penalty for the author and award the VINDICATION_BONUS.

### 30.3 Why the asymmetry

The penalty structure is asymmetric in three ways:

1. **Conservative labels are free.** Declaring AG content as MX, OH content as AA, or any pairing in the under-disclosure direction carries no penalty.

2. **The OHtoAG distance is heaviest.** A creator who declares Original Human content that is actually AI-Generated is making the most consequential misrepresentation. The penalty reflects the social cost of this error.

3. **Escalation is steep.** A first OHtoAG offense costs 100 points; a third costs 300. A creator with three confirmed offenses has lost the equivalent of three tiers' worth of trust score and is no longer eligible for any community adjudication role.

The asymmetry is the source of the protocol's incentive alignment with honest behavior. There is no scoring pattern in which dishonest declaration produces a better score than honest declaration. A creator who is uncertain about classification is always better off conservatively over-disclosing.

### 30.4 Score effects table reference

The complete enumeration of score effect events is maintained at `docs/DISPUTE_SCORING.md` in the protocol repository and is summarized here:

| Event | Author delta | Disputer delta | Juror delta |
|---|---|---|---|
| Content registered (LOW/ELEVATED pre-scan) | 0 | n/a | n/a |
| Origin updated within 24h grace (LOW/ELEVATED) | 0 | n/a | n/a |
| Origin updated within 48h grace (HIGH/CRITICAL) | 0 | n/a | n/a |
| Reviewer assigned, creator accepts correction privately | -10 | n/a (reviewer +5) | n/a |
| Content retracted by creator | -50 | n/a | n/a |
| Stage 2 DISMISSED | +5 vindication | -15 stake forfeit | majority +3 / minority -10 / no-show -10 |
| Stage 2 CONSERVATIVE_LABEL | 0 | +15 refund (no bonus) | majority +3 / minority -10 / no-show -10 |
| Stage 2 UPHELD (OHtoAG 1st) | -100 | +20 (refund + bonus) | majority +3 / minority -10 / no-show -10 |
| Stage 2 NO_QUORUM | 0 (pending Stage 3) | locked stake | 0 |
| Stage 3 confirm Stage 2 | (no further change) | 0 (stake or refund stands) | expert delta same as juror |
| Stage 3 overturn Stage 2 | Stage 2 reversed | Stage 2 reversed | expert delta same as juror |
| Stage 3 appellant settlement | n/a | +35 if wins, -25 if loses | n/a |

The "single-channel rule" guarantees that every score change emits a SCORE_UPDATE transaction. A node that wishes to audit an account's score history walks the chain of SCORE_UPDATE transactions for that TIP-ID and recomputes.

---

# PART VII · FEDERATED DAG AND VERIFICATION PROVIDER SYSTEM

## 31. DAG Structure and Transaction Format

### 31.1 The Directed Acyclic Graph

Every state change in the TIP network is a transaction (`tx`) on a shared, append-only Directed Acyclic Graph (DAG). Each transaction references exactly two prior transactions (`prev[0]` and `prev[1]`) by `tx_id`. The genesis transaction is the unique exception with `prev[] = []`.

Properties of the DAG:

- **Append-only.** Transactions, once committed, are immutable. No transaction may be modified or removed.
- **Cryptographically anchored.** Every transaction is signed under ML-DSA-65 (or hybrid Ed25519+ML-DSA-65 during the transition period). The transitive chain of references from any transaction eventually reaches the Genesis Block, whose signature is verified against the published SLH-DSA-128s root public key.
- **Parallel-friendly.** A single signing party may produce multiple transactions in parallel that do not depend on each other. The DAG's prev-of-2 structure permits high throughput (the reference node sustains over 5,000 TPS in benchmarks).
- **No proof-of-work.** Transactions are accepted on signature validation and consensus committee approval, not on energy expenditure. The protocol's federation provides Byzantine fault tolerance without proof-of-work.
- **Gossip-replicated.** Nodes gossip transactions to peers using libp2p GossipSub. A transaction reaches every conforming node within seconds of commit.

### 31.2 Transaction structure

Every transaction has the following canonical fields:

```json
{
  "tx_type": "REGISTER_CONTENT",
  "tx_id": "<64-char SHAKE-256 hex of canonical tx JSON without signature field>",
  "data": { /* type-specific fields */ },
  "prev": ["<tx_id of prev[0]>", "<tx_id of prev[1]>"],
  "timestamp": "2026-06-01T12:34:56.789Z",
  "signer": "<TIP-ID or VP-TIP-ID of signing party>",
  "signature": "<6,618-char hex of ML-DSA-65 signature>",
  "signature_algos": ["ml_dsa_65"]
}
```

The canonical JSON of the transaction (with sorted keys, no whitespace) MINUS the `signature` field is what gets hashed to produce `tx_id` and what gets signed to produce `signature`. The signature is on the SHAKE-256 hash of the canonical tx JSON, in the same ASCII-hex pattern as content signatures (Section 9).

The `tx_type` field carries a value from the closed enumeration in Section 32. The `data` field carries the type-specific fields for that transaction type.

### 31.3 Per-type schemas

Each transaction type has a strict schema for its `data` field, enforced by both the API admission validator and the consensus commit handler. The dual enforcement uses a shared schema module so that API-time and commit-time validation cannot drift.

Implementations of the schemas live in the reference TIP node at `node/src/schemas/<tx-type>.js`. Each schema module exports:

- `validateRequest`: enforces shape at API admission
- `resolveSigner`: looks up the signer's TIP-ID and public key from the DAG
- `buildSigningPayload`: reconstructs the canonical signed payload for verification
- `verify`: verifies the ML-DSA-65 signature
- `verifyTx`: the full transaction verification used at commit time

A new transaction type may be added through the RFC process by introducing a new schema module and updating the consensus commit handler to dispatch to it.

### 31.4 Node types

| Node type | Role | Operated by |
|---|---|---|
| **Full Node** | Maintains complete DAG; independently verifies all transactions | Enterprises, universities, NGOs, journalism organizations |
| **Light Node** | Maintains recent transactions plus Merkle proofs for older state | Browser extensions, mobile apps, embedded verifiers |
| **VP Node** | Full Node plus biometric verification hardware; issues TIP-IDs | Accredited Verification Providers |
| **Archive Node** | Full DAG plus historical snapshots, long-term storage | Academic institutions, public-interest archives |

A network is healthy when it has at least three independently operated Full Nodes per continent and at least one Archive Node maintaining a complete copy. The reference TIP node implementation supports all four node types via configuration.

### 31.5 Federation phases and decentralization roadmap

The protocol's governance moves through three phases. At the date of this document the network is operating in **Phase 1**, with the full-workflow pilot deployment having been live since April 7, 2026.

**Phase 1 · Coordinator (current; began April 7, 2026).** The AI Lab operates a coordinator node. All transactions are committed through the coordinator. The protocol's federation property is structural (any party may run a node and verify) but the consensus authority is centralized. The pilot under Phase 1 has been live since April 7, 2026.

**Phase 2 · Committee (planned, approximately 4 to 8 months after Phase 1 stability).** A 21-node validator committee is elected from the accredited VP node operators. Committee membership is rotated through COMMITTEE_ROTATION transactions, each signed by at least two-thirds of the prior committee. The AI Lab holds 1 vote in the committee. Consensus requires at least 14 of 21 committee signatures on any block.

**Phase 3 · Full Decentralization (planned, when sustained throughput exceeds 100 TPS).** The network transitions to full Byzantine fault-tolerant consensus among all validator nodes. The committee is dissolved. The AI Lab retains trademark authority (brand) and genesis-key authority (root signing) but not consensus authority.

The roadmap is target-aspirational. The actual transition between phases depends on network maturity, validator availability, and security audit outcomes. The AI Trust Council (Section 49) governs the transition decisions.

### 31.6 Gossip protocol

Nodes connect to each other via libp2p TCP with libp2p-noise transport encryption. Peer discovery uses libp2p-mdns (local network) and libp2p-bootstrap (known peers list). Transaction propagation uses libp2p-gossipsub.

A node receiving a transaction:

1. Validates the transaction's schema (per Section 31.3)
2. Verifies the signature
3. Verifies the prev[] references resolve to known transactions
4. Checks for type-specific business rules (signer is registered, dedup hash is unique, etc.)
5. Commits the transaction to its local DAG state
6. Gossips the transaction to peers

A transaction that fails any check is rejected, logged in the local `tx_rejections` table with a reason code, and not propagated.

## 32. The Twenty-Nine Transaction Types

The protocol defines 29 transaction types in v5.0. They are grouped by functional area. Each entry below lists the type name, the functional purpose, and the key fields in the `data` payload.

### 32.1 Identity layer (6 types)

**1. REGISTER_IDENTITY.** Creates a new TIP-ID. Signed by an accredited VP. Data: `tip_id`, `region`, `public_key`, `tip_id_type`, `verification_tier`, `dedup_hash` (recorded as zero-knowledge proof on DAG), `zk_proof`, `creator_name` (optional, may be null), `social_attested`, `vp_id`, `vp_signature`.

**2. UPDATE_DEVICE_BINDING.** Updates FIDO2/WebAuthn device binding for an existing TIP-ID. Data: `tip_id`, `new_credential_id`, `new_device_public_key`, `old_credential_id`, `signature_by_old_credential`.

**3. UPDATE_PROFILE.** Updates user-settable preferences such as score visibility mode, reviewer consent toggle, interest taxonomy. Data: `tip_id`, `profile_updates` (object), `signature`.

**4. LINK_PLATFORM.** Links a TIP-ID to a verified external identity (social platform, gaming platform). Data: `tip_id`, `platform`, `external_identifier`, `verification_proof`.

**5. KEY_ROTATED.** Identity key rotation, signed by the current (old) private key. Data: `tip_id`, `new_public_key`, `old_public_key_fingerprint`, `effective_at`, `signature_by_old_key`.

**6. KEY_RECOVERY.** VP-attested key recovery when the user lost device access. Data: `tip_id`, `new_public_key`, `dedup_hash` (proof of identity continuity), `recovery_evidence_hash`, `vp_signature`.

### 32.2 Content layer (5 types)

**7. REGISTER_CONTENT.** CNA-2.2-signed content registration with origin code. Data: all eight fields of the canonical signed payload (Section 20.1) plus the auxiliary envelope fields (content bytes or media canonical hash, content_type, perceptual_hash). Returns a CTID upon commit.

**8. UPDATE_ORIGIN.** Creator updates the origin code on existing registered content within the decision window. Data: `ctid`, `new_origin_code`, `reason`, `signature_by_creator`.

**9. CONTENT_RETRACTED.** Creator retracts a content registration. Data: `ctid`, `retraction_reason`, `signature_by_creator`. Carries a -50 score penalty to the creator.

**10. CONTENT_VERIFIED.** A community member manually verifies content (separate from automatic registration validation). Data: `ctid`, `verifier_tip_id`, `verifier_signature`.

**11. CONTENT_DISPUTED.** Disputer files a Stage 2 dispute. Data: `ctid`, `disputer_tip_id`, `claimed_correct_origin`, `evidence_hash`, `disputer_signature`. Deducts DISPUTER_STAKE (15) from the disputer at commit time.

### 32.3 Prescan review pipeline (4 types)

**12. PRESCAN_REVIEW_TRIGGERED.** Generated automatically when content's AI pre-scan exceeds the calibrated threshold and the 48-hour creator-correction window expires without update. Data: `ctid`, `assigned_reviewer_tip_id`, `pre_scan_result`.

**13. PRESCAN_REVIEW_DISMISSED.** Reviewer determines the AI flag was incorrect. Data: `review_id`, `reviewer_tip_id`, `reviewer_signature`. Credits REVIEWER_CORRECT_BONUS (+5) to the reviewer.

**14. PRESCAN_REVIEW_CONFIRMED.** Reviewer determines the AI flag was justified. Data: `review_id`, `reviewer_tip_id`, `proposed_corrected_origin`, `reviewer_signature`. Opens the creator's 24-hour decision window.

**15. PRESCAN_REVIEW_RECUSED.** Reviewer recuses; case is reassigned. Data: `review_id`, `reviewer_tip_id`, `optional_reason`, `reviewer_signature` (or auto-emitted by the network with a system signature after 48-hour silence).

### 32.4 Dispute adjudication (6 types)

**16. AI_CLASSIFIER_RESULT.** Stage 1 output. Data: `case_id`, `ai_probability`, `classifier_version`.

**17. JURY_SUMMONS.** Issued at Stage 2 start, one per juror. Data: `case_id`, `juror_tip_id`, `commit_deadline`, `reveal_deadline`.

**18. JURY_VOTE_COMMIT.** Juror commits a hash of their vote. Data: `case_id`, `juror_tip_id`, `commitment_hash`, `juror_signature`.

**19. JURY_VOTE_REVEAL.** Juror reveals vote and salt. Data: `case_id`, `juror_tip_id`, `vote`, `salt`, `juror_signature`. The Verifier checks that `SHAKE-256(vote || salt) == commitment_hash`.

**20. ADJUDICATION_RESULT.** Stage 2 verdict computed and recorded. Data: `case_id`, `verdict` (UPHELD / DISMISSED / CONSERVATIVE_LABEL / NO_QUORUM), `vote_tally`, `new_origin_code` (for UPHELD or CONSERVATIVE_LABEL).

**21. APPEAL_FILED.** Loser of Stage 2 files Stage 3 appeal. Data: `case_id`, `appellant_tip_id`, `appeal_grounds`, `appellant_signature`. Deducts APPELLANT_STAKE (25) from the appellant.

**22. APPEAL_RESULT.** Stage 3 verdict computed and recorded. Data: `case_id`, `expert_verdict`, `expert_vote_tally`, `final_origin_code`. Reverses Stage 2 settlement when appropriate.

### 32.5 Trust scoring (1 type)

**23. SCORE_UPDATE.** Records a delta to a TIP-ID's trust score, paired with the originating event transaction. Data: `subject_tip_id`, `delta`, `reason` (a structured string referencing the originating transaction), `originating_tx_id`.

Every score change in the protocol emits a SCORE_UPDATE. The single-channel rule (Section 25.2) makes the score's derivation auditable.

### 32.6 Identity revocation (4 types)

**24. REVOKE_VOLUNTARY.** Holder initiates permanent revocation of their own TIP-ID. Data: `tip_id`, `signature_by_holder`.

**25. REVOKE_VP.** VP-initiated revocation, evidence-backed. Data: `tip_id`, `reason_code`, `evidence_hash`, `issuing_vp_id`, `vp_signature`. Content registered by the affected TIP-ID within the preceding 90 days auto-enters adjudication.

**26. REVOKE_DECEASED.** Death notification, governance-driven. Data: `tip_id`, `death_certificate_hash`, `attesting_vp_id`. Permanent. Identity is archived with deceased-author notation. Content provenance records remain valid.

**27. REVOKE_DEVICE.** Device credential compromised. Data: `tip_id`, `device_credential_id`. Score -15 pending re-verification. Identity preserved.

### 32.7 Domain binding (2 types)

**28. BIND_DOMAIN.** Organization claims a domain by HTTP /.well-known proof or DNS TXT proof. Data: `tip_id` (the claiming entity), `domain`, `proof_method` (`http` or `dns`), `proof_artifact`, `effective_at`.

**29. UNBIND_DOMAIN.** Revoke domain binding. Data: `tip_id`, `domain`, `reason_code` (`OWNER_REVOKED`, `VERIFICATION_LOST`, `CASCADE`).

### 32.8 Governance (additional types)

The above 29 cover the core protocol. Additional governance-only transaction types:

- **VP_REGISTERED.** New Verification Provider accredited; signed by The AI Lab's accreditation authority key.
- **VP_SUSPENDED.** VP accreditation suspended; signed by the accreditation authority.
- **NODE_REGISTERED.** New validator node joining the committee.
- **COMMITTEE_ROTATION.** Consensus committee membership change; signed by at least two-thirds of the prior committee.
- **MERKLE_ROOT_PUBLISHED.** Dedup registry Merkle root, published every 6 hours.
- **INTEREST_REGISTERED.** VP-attested interest taxonomy entry added.

These governance types appear in the DAG with the same structural format as the user-facing transaction types but are issued under different signing authority.

## 33. Genesis Block

### 33.1 Structure

The Genesis Block is the unique transaction with `prev[] = []` that anchors the entire DAG. The Genesis Block carries:

- The 32-byte SLH-DSA-128s root public key
- The genesis timestamp
- The protocol constants (Section 30.1) baked into the chain
- The initial Verification Provider registrations
- The initial node committee membership
- The initial dedup registry state (empty)
- The protocol version string `"5.0"`
- The chain identifier `"tip-mainnet-v5"`

The Genesis Block's `tx_id` is `SHAKE-256` of the canonical JSON of all the above fields. The published `tx_id` and the published root public key together form the trust anchor that every Verifier checks against.

### 33.2 Root key custody

The SLH-DSA-128s root private key is held in a FIPS 140-3 Level 3 hardware security module (HSM) under a two-of-three custodian policy. The HSM is air-gapped. Signing operations on the root key occur only at VP_REGISTERED events, COMMITTEE_ROTATION events, and analogous governance transactions; the root key is not used for routine signing.

### 33.3 Genesis ring

The Genesis Block also records the "Genesis Ring": a list of founding TIP-IDs that participated in the network's launch. Genesis Ring membership is recorded for historical purposes; it does not confer governance authority. Subsequent participation in the network (VP accreditation, validator committee membership) flows through the normal accreditation and election processes, not through Genesis Ring membership.

## 34. Node Types

Specified in Section 31.4. The reference implementation supports all four (Full, Light, VP, Archive) via configuration files. A single deployment may be configured as multiple node types simultaneously.

## 35. Verification Provider Categories and Accreditation

### 35.1 The four VP categories

**Category A · Identity-native organizations.** Banks, biometric companies, telecommunications providers with strong KYC, and national identity programs. Typical examples: iProov, Jumio, Yoti, Onfido, regional bank consortia.

**Category B · Content platforms and journalism organizations.** Major publishers, journalism associations, press freedom nonprofits. Typical examples: major news organizations, CPJ, RSF, SPJ.

**Category C · Government digital identity programs.** State digital identity issuers operating in jurisdictions that meet the GREEN or AMBER tier criteria. Typical examples: EU eIDAS notified bodies, UK DSIT, Estonia e-Residency.

**Category D · Educational institutions.** Universities, colleges, research institutes.

### 35.2 Accreditation requirements

Any organization seeking VP accreditation must satisfy all of the following:

1. Implement the four-layer biometric verification stack (Section 13) with certified hardware
2. Pass an independent security audit from one of: Trail of Bits, Bishop Fox, Cure53, NCC Group, or an equivalent firm approved by The AI Lab
3. Sign the TIP-VP Code of Conduct (Section 35.5)
4. Pass a jurisdiction assessment (Section 36)
5. Pay the applicable accreditation fee (Section 35.4)
6. Deploy a Full Node and integrate with the VP signing key in an HSM

### 35.3 Accreditation procedure

1. **Express interest.** Organization category, country, infrastructure plan, estimated volume.
2. **Technical review (4 to 6 weeks).** The AI Lab reviews the biometric stack implementation against this specification.
3. **Security audit (4 to 8 weeks).** Approved firm audits code and infrastructure.
4. **Legal review (2 to 3 weeks).** Review Code of Conduct and VP Service Agreement.
5. **Accreditation (1 to 2 weeks).** VP keypair registered on the DAG via VP_REGISTERED transaction signed by the Genesis root key.

Total typical timeline: 8 to 16 weeks.

### 35.4 Accreditation fees

| Category | Annual fee |
|---|---|
| Category D (Education) | No fee |
| Category C (Government) | No fee |
| Category B (Journalism / NGO) | No fee |
| Category A, under 10K/month | USD 5,000 / year |
| Category A, 10K to 100K/month | USD 15,000 / year |
| Category A, over 100K/month | USD 40,000 / year |

Fees are cost-recovery only. The AI Lab does not profit from VP accreditation.

### 35.5 TIP-VP Code of Conduct

Every accredited VP signs the Code of Conduct as part of accreditation. The Code requires:

| Obligation | Frequency | Absolute? |
|---|---|---|
| Quarterly warrant canary | Quarterly | Best-efforts |
| Government request disclosure (aggregate) | Annual | To the extent legally permitted |
| Zero voluntary data sharing with third parties | Always | YES: absolute prohibition |
| Annual independent security audit | Annual | YES |
| Peppered ZK dedup architecture | Always | YES |
| Transparency register publication | Quarterly | YES |
| Jurisdiction tier badge display (AMBER) | Per credential | YES |
| Biometric data destruction within 72 hours of verification | Per verification | YES |
| DPIA published for European deployment | Before EU launch | YES |
| Adherence to this specification | Always | YES |

### 35.6 Verification Provider TIP-ID

Each accredited VP has its own TIP-ID with `tip_id_type: "vp"`. The VP TIP-ID is what signs the REGISTER_IDENTITY transactions for the VP's customers. The VP TIP-ID itself is recorded by a VP_REGISTERED transaction signed under the Genesis root key.

### 35.7 Suspension and revocation

VP accreditation may be suspended or revoked through a VP_SUSPENDED transaction signed by the accreditation authority. Triggering conditions:

- Voluntary data sharing in violation of Code of Conduct (immediate revocation)
- Triggered warrant canary not remedied within 30 days (suspension; revocation after additional 30 days)
- Annual security audit reveals critical unmitigated vulnerability (suspension pending remediation)
- Issuing TIP-IDs without completing all four biometric layers (revocation)
- Operating in a jurisdiction reclassified to RED tier (suspension; revocation if VP cannot relocate)

A suspended VP cannot issue new TIP-IDs. Existing TIP-IDs issued by the suspended VP remain active unless individually revoked.

## 36. Jurisdiction Tiers and Warrant Canary

### 36.1 Three-tier classification

| Tier | Criteria | Badge indicator |
|---|---|---|
| **GREEN** | Strong rule of law, independent judiciary, no mandatory backdoor legislation, no documented extrajudicial access | None (absence of AMBER means GREEN) |
| **AMBER** | Moderate rule-of-law concerns, ambiguous or evolving data access laws, VP meets technical standard but jurisdiction carries non-zero coercion risk | Amber indicator on every issued AI Trust ID Seal |
| **RED** | Mandatory government backdoor laws, mass surveillance infrastructure incompatible with the VP Code of Conduct, documented extrajudicial access history | Cannot be accredited |

Classification is performed by The AI Lab's accreditation authority with input from civil-liberties organizations and is published at https://theailab.org/jurisdictions. Classifications are reviewed annually and may be updated as legal frameworks change.

### 36.2 AMBER indicator on the AI Trust ID Seal

When a VP operating in an AMBER-tier jurisdiction issues a TIP-ID, the resulting AI Trust ID Seal displays an amber indicator at the upper-left of the inner ring. The color is the same amber used for the REVIEW_ADVISED tier (#A88B15). Hover or tap discloses: "Issued by a VP operating in an Amber-tier jurisdiction. More information: theailab.org/jurisdictions"

### 36.3 RED tier non-accreditation

A VP applicant operating exclusively in a RED-tier jurisdiction cannot be accredited. The protocol's response to RED-tier jurisdictions is not to issue marginal credentials with a worse badge; it is to decline accreditation. A VP that can relocate to a GREEN or AMBER jurisdiction may apply from the new location.

### 36.4 Warrant canary

Every accredited VP publishes a quarterly signed statement at a known URL (typically https://{vp-domain}/canary) confirming that no compelled undisclosed government data access has occurred. The canary is signed under the VP's ML-DSA-65 signing key.

Failure to publish within 90 days of the previous canary generates a JURISDICTION_ADVISORY transaction on the DAG. The Verifier's display of TIP-IDs issued by the affected VP includes the advisory. After 180 days without a fresh canary, the VP's tier is effectively downgraded one step (GREEN to AMBER, AMBER to RED) until the canary is published or accreditation is revoked.

The warrant canary is a best-efforts mechanism. A VP under a gag order that prevents it from publishing the canary truthfully is expected to allow the canary to lapse. The lapse becomes a signal to TIP-ID holders and Verifiers that the VP has plausibly been compelled.

## 37. Identity Revocation

### 37.1 Revocation transaction types

The four revocation types (Section 32.6) cover the four real-world scenarios in which a TIP-ID becomes invalid:

- The holder voluntarily revokes (Section 37.2)
- The VP determines fraud in the original issuance (Section 37.3)
- The holder dies (Section 37.4)
- The holder's device is compromised (Section 37.5)

### 37.2 REVOKE_VOLUNTARY

A holder may at any time sign a REVOKE_VOLUNTARY transaction with their own private key. The TIP-ID's status changes to `revoked_voluntary`. The TIP-ID's content provenance records remain valid (the registrant's authorship of historical content is not affected by their later voluntary revocation), but the TIP-ID cannot sign new transactions.

A holder who later wishes to participate in the network must register a new TIP-ID through a new VP enrollment. The new TIP-ID is a distinct identity with a fresh trust score baseline.

### 37.3 REVOKE_VP

If a VP determines, after issuance, that a registration was fraudulent (forged government ID, identity stolen from a real person, dedup hash collision, etc.), the VP signs a REVOKE_VP transaction.

Cascade effects:

- The TIP-ID's status changes to `revoked_vp`
- Content registered by the affected TIP-ID within the preceding 90 days auto-enters adjudication with the dispute reason `issuer_revocation_cascade`
- The content's status changes to `disputed` pending adjudication
- The dedup hash is added to a blocklist preventing the same person from re-registering with the same fraudulent identity document

### 37.4 REVOKE_DECEASED

Upon presentation of a verified death certificate, the VP signs a REVOKE_DECEASED transaction. The TIP-ID's status changes to `revoked_deceased`. The score is frozen at its current value. The TIP-ID's content provenance records remain valid (deceased authors retain their authorship history). The TIP-ID cannot sign new transactions; new content registrations under the deceased TIP-ID are rejected.

The TIP-ID's display surfaces include a "deceased" annotation. The annotation is informational; it does not affect the cryptographic verifiability of past signatures.

### 37.5 REVOKE_DEVICE

If the holder's device is compromised but the holder retains other proof of identity (the original Layer 1 government ID, the option to perform fresh Layer 2 biometric verification), the holder signs a REVOKE_DEVICE transaction. The transaction may be signed by:

- The holder's own private key (if still accessible), or
- The issuing VP on the holder's behalf after re-verification

The TIP-ID's status changes to `revoked_device`. Signing authority is paused. A score penalty of -15 is applied (the protocol's response to suspected key compromise is to require fresh verification and accept the small trust cost).

The holder then performs Layer 1, 2, and 3 re-verification at a VP to bind a new device credential. After successful re-verification, the holder signs an UPDATE_DEVICE_BINDING transaction (Section 32.1, type 2) to restore signing authority. The TIP-ID's status returns to `active`.

The TIP-ID identifier itself does not change. The same `tip://id/{Region}-{Fingerprint16}` URI continues to identify the same holder. The underlying ML-DSA-65 signing key changes through KEY_RECOVERY (Section 15.3) where applicable.

---

# PART VIII · APIs, WEB INTEGRATION, AND REFERENCE CLIENTS

## 38. REST API Surface

The protocol's REST API is the contract between TIP nodes and conforming clients (browser extensions, mobile apps, CMS plugins, server-side integrators). Every conforming TIP node MUST expose the endpoints in this section. Every conforming client MUST consume the response envelopes as specified.

### 38.1 Common response envelope

Every successful response uses the envelope:

```json
{
  "ok": true,
  "status": 200,
  "data": { /* endpoint-specific payload */ }
}
```

Every error response uses the envelope:

```json
{
  "ok": false,
  "status": 4xx_or_5xx,
  "error": {
    "message": "Human-readable description",
    "code": "machine_readable_code",
    "request_id": "<uuid>"
  }
}
```

### 38.2 Health and node info (3 endpoints)

**`GET /health`**

Health probe. Response: `{ status: "ok", version: "5.0", uptime_ms: <integer> }`.

**`GET /v1/node/info`**

Node metadata. Response: `{ node_id, protocol_version, chain_id, genesis_hash, peer_count, dag_height, dag_tx_count, supported_signature_algorithms, supported_hash_algorithms }`.

**`GET /v1/node/peers`**

List of known peer node addresses. Response: `{ peers: [{ node_id, address, last_seen }] }`.

### 38.3 Identity management (6 endpoints)

**`POST /v1/identity/register`**

Register a new TIP-ID. Request body: the 9-field REGISTER_IDENTITY transaction data plus the VP signature (Section 32.1 type 1). Response on success (HTTP 201): `{ tip_id, status, score, tier, tier_color, verified_at, chain_height }`.

Common error codes:

- `400 dedup_hash_invalid`: dedup_hash format wrong
- `400 zk_proof_invalid`: ZK proof structure wrong
- `403 vp_signature_invalid`: VP signature does not verify
- `409 dedup_collision`: dedup hash already exists on the DAG (the person already has a TIP-ID)
- `412 vp_not_accredited`: signing VP is not in the accreditation registry

**`GET /v1/identity/{tip_id}`**

Resolve a TIP-ID. Response: full identity record including current public key, score, tier, status, vp_id, region, verification_tier, social_attested. Accepts optional `?at=<ISO_8601_timestamp>` to retrieve the identity state effective at a historical time (used by Verifiers checking historical signatures).

**`GET /v1/identity/{tip_id}/score`**

Lightweight score-only response. Response: `{ tip_id, score, tier, tier_color, visibility_mode }`. Respects the holder's visibility mode: returns the numeric score only if mode is FULL_PUBLIC.

**`GET /v1/identity/{tip_id}/history`**

Transaction history for the TIP-ID. Paginated. Returns the chronological list of transactions where the TIP-ID is the signer or the subject_of.

**`GET /v1/identity/{tip_id}/profile`**

User-settable profile preferences (visibility mode, reviewer toggle, adjudication toggle, interest taxonomy, display name).

**`POST /v1/identity/{tip_id}/profile`**

Update profile. Request body: signed UPDATE_PROFILE transaction. Response on success: the updated profile state.

### 38.4 Content management (3 endpoints)

**`POST /v1/content/register`**

Register content. Request body: the 8-field canonical signed payload (Section 20.1) plus the auxiliary envelope (content bytes, content_type, perceptual_hash, signature). Response on success (HTTP 202): `{ ctid, tx_id, origin_code, content_hash, registered_at, status: "proposed" }`.

Common error codes:

- `400 origin_code_invalid`: not in {OH, AA, AG, MX}
- `400 content_hash_mismatch`: server-recomputed hash differs from supplied content_hash
- `400 registered_urls_required`: registered_urls array empty
- `400 attribution_mode_invalid`: not in {self, employed, hosted}
- `403 signature_invalid`: ML-DSA-65 verify failed
- `403 signer_revoked`: signer's TIP-ID has status revoked
- `409 ctid_already_registered`: derived CTID collision (rare; indicates duplicate registration)
- `412 signer_not_registered`: signer's TIP-ID is not on the DAG
- `412 author_not_registered`: an `authors[i].tip_id` is not on the DAG
- `412 author_tip_id_type_mismatch`: author's claimed tip_id_type does not match DAG identity record
- `422 cna_unsupported`: cna_version not in the acceptance list

**`GET /v1/content/{ctid}`**

Resolve a CTID. Response: `{ ctid, origin_code, origin_label, status, author_tip_id, author_score, signer_tip_id, content_hash, registered_urls, registered_at, dispute_count, dag_tx, vp_id, signature_algos }`.

**`POST /v1/content/{ctid}/update-origin`**

Update origin code within the decision window. Request body: signed UPDATE_ORIGIN transaction. Response: updated content record.

### 38.5 Dispute adjudication (2 endpoints)

**`POST /v1/content/{ctid}/dispute`**

File a Stage 2 dispute. Request body: signed CONTENT_DISPUTED transaction. Response on success (HTTP 202): `{ dispute_id, case_id, status: "stage_2_pending_jury", expected_verdict_at }`.

**`GET /v1/disputes/{dispute_id}`**

Retrieve full dispute case with timeline. Response: `{ dispute_id, ctid, disputer_tip_id, filed_at, stage_1_classifier_result, stage_2_summons[], stage_2_commits[], stage_2_reveals[], stage_2_verdict, appeal_filed (boolean), stage_3_panel[], stage_3_verdict, current_status }`.

### 38.6 Prescan review (3 endpoints)

**`GET /v1/reviews`**

List assigned reviews for the requesting TIP-ID (resolved from API key or signing token). Response: array of review assignments with case_id, content excerpt, deadline.

**`POST /v1/reviews/{review_id}/dismiss`**

Reviewer dismisses the AI flag. Request body: signed PRESCAN_REVIEW_DISMISSED transaction. Response: review record updated.

**`POST /v1/reviews/{review_id}/confirm`**

Reviewer confirms the AI flag. Request body: signed PRESCAN_REVIEW_CONFIRMED transaction with proposed_corrected_origin. Response: review record updated; case enters the 24-hour creator decision window.

### 38.7 Domain binding (2 endpoints)

**`POST /v1/domain/register`**

Organization claims a domain. Request body: `{ tip_id, domain, proof_method: "http" | "dns", proof_artifact, signature_by_tip_id }`. Response: pending verification.

**`POST /v1/domain/{domain}/verify`**

Trigger verification of a pending claim. Server attempts to fetch the HTTP /.well-known proof or query the DNS TXT record. On success, commits BIND_DOMAIN transaction.

### 38.8 Total endpoint count

The 19 endpoints above cover the core protocol surface. Additional endpoints exposed by the reference TIP node for ecosystem support:

- `GET /v1/dag/stats` (DAG metrics)
- `GET /v1/dedup/merkle-root` (current dedup registry Merkle root)
- `POST /v1/dedup/check` (ZK uniqueness check)
- `GET /v1/vps` (list of accredited VPs)
- `GET /v1/vp/{vp_id}` (VP details)
- `GET /v1/revocations` (current revocations)
- `GET /v1/identity/{tip_id}/seal` (renders the AI Trust ID Seal as SVG)
- `GET /v1/identity/by-dedup-hash/{dedup_hash}` (key-recovery pre-flight)
- `POST /v1/identity/{tip_id}/keys/recover` (key recovery transaction submission)

These are stable surface area but secondary to the core 19.

## 39. HTTP Response Headers

A web server publishing TIP-verified content MAY include the following HTTP response headers on the page that surfaces the content. The headers enable browser-extension verifiers and downstream Verifier services to discover the content's TIP registration without parsing the HTML.

```
TIP-Author:        tip://id/US-a3f8c91b2d4e7021
TIP-Content:       tip://c/OH-7f2a91bc3d5e4a-7021
TIP-Origin:        original-human
TIP-Trust-Score:   892
TIP-Tier:          HIGHLY_TRUSTED
TIP-Signature:     <hex-encoded ML-DSA-65 signature>
TIP-Spec-Version:  5.0
X-Powered-By:      TIP-Protocol/theailab.org
```

Header semantics:

- `TIP-Author` is the TIP-ID of the bylined primary author (`authors[0].tip_id`)
- `TIP-Content` is the CTID
- `TIP-Origin` is one of `original-human`, `ai-assisted`, `ai-generated`, `mixed`
- `TIP-Trust-Score` is the author's current numeric score (omitted if the author's visibility mode is TIER_ONLY or VERIFIED_ONLY)
- `TIP-Tier` is the author's current tier label
- `TIP-Signature` is the ML-DSA-65 signature on the content registration (for client-side verification without a DAG roundtrip; the client may then verify the signature locally against the public key resolved from the DAG)
- `TIP-Spec-Version` declares which version of this specification the publisher targets
- `X-Powered-By` is the open attribution

Headers are case-insensitive per RFC 7230. Conforming publishers SHOULD include at minimum `TIP-Author`, `TIP-Content`, and `TIP-Origin`. The other headers are RECOMMENDED.

## 40. HTML Meta Tags

A web page MAY embed TIP metadata via HTML meta tags. The meta tags duplicate the HTTP header information for crawlers, search engines, and client-side scripts that read the DOM. The tags appear in the `<head>` of the page:

```html
<meta property="tip:author"        content="tip://id/US-a3f8c91b2d4e7021" />
<meta property="tip:content"       content="tip://c/OH-7f2a91bc3d5e4a-7021" />
<meta property="tip:origin"        content="original-human" />
<meta property="tip:score"         content="892" />
<meta property="tip:tier"          content="HIGHLY_TRUSTED" />
<meta property="tip:status"        content="VERIFIED" />
<meta property="tip:spec-version"  content="5.0" />
```

The use of the `property` attribute parallels Open Graph and other social-metadata conventions. Conforming publishers SHOULD include at minimum `tip:author`, `tip:content`, and `tip:origin`.

Implementations that scrape pages for TIP metadata MUST tolerate the absence of any individual tag and SHOULD prefer the HTTP headers when both are present (the headers cannot be modified by client-side JavaScript and are therefore more trustworthy).

## 41. Badge Widget Embedding

A publisher MAY embed an inline TIP badge widget on their page. The reference widget is served from `https://badge.theailab.org/tip-badge.min.js` and registers a custom element `<tip-badge>`:

```html
<script src="https://badge.theailab.org/tip-badge.min.js" defer></script>
<tip-badge tip-id="tip://id/US-a3f8c91b" size="120" variant="gold-dark"></tip-badge>
```

Attributes:

- `tip-id`: the TIP-ID to display
- `type`: `"seal"` (default), `"mark"`, `"shield"`, or `"origin"`
- `origin`: Origin Code (OH, AA, AG, MX) for `type="origin"`
- `status`: verification status for the origin badge
- `size`: pixel dimension (40 to 400)
- `variant`: `"gold-dark"` (default), `"light"`, `"color"`, or `"dark"`
- `node-url`: TIP node endpoint to fetch from (defaults to https://node.theailab.org)
- `auto`: if present, the widget reads page meta tags and auto-renders the badge that matches the page's TIP-Content

The widget renders the AI Trust ID Seal (the proprietary registry-issued credential, Section 48.2) as an inline SVG. The widget resolves the TIP-ID against the configured node URL, fetches the current score, and renders the seal in the holder's selected visibility mode.

The badge widget is licensed under TIPCL-1.0 (the reference implementation license) and is free for use under the TIPCL-1.0 free-tier eligibility rules.

## 42. Browser Extension Reference Behavior

The reference TIP browser extension is published in Chrome Web Store, Mozilla Add-ons (Firefox), the Microsoft Edge Add-ons store, the Safari App Store, and as a sideloadable Arc / Brave extension. The reference implementation is at https://github.com/theailaborg/tip-browser-extension and is licensed under TIPCL-1.0.

This section describes the reference behavior that a conforming browser extension implements. Alternative implementations are permitted under TIPCL-1.0 free-tier or commercial license.

### 42.1 Manifest V3 architecture

The reference extension uses Chrome Extension Manifest V3 with the following components:

- **Service Worker** (`src/background.js`): handles cross-platform messaging, content registration, revocation polling, dispute notifications
- **Content Script** (`src/content.js`): injected into 400+ host sites (the host_permissions list in `manifest.json` enumerates them); detects platform, renders the verification panel, collects content for signing
- **Popup** (`popup.html`): the popup shown when the user clicks the extension icon; displays the user's identity, recent activity, and quick settings
- **Options Page** (`options.html`): full settings (identity setup, publisher mode, locale, adjudication toggles, advanced options)
- **WebAuthn Gate Page** (`sign.html`): a modal page where biometric verification occurs at signing time
- **Offscreen Document** (`offscreen.html`): a worker for long-running cryptographic tasks (image decoding, perceptual hashing, large-content normalization)

Required permissions: `activeTab`, `scripting`, `storage`, `clipboardWrite`, `notifications`, `windows`, `offscreen`.

### 42.2 Content normalization and signing

The extension implements CNA-2.2 (Section 19) in `src/crypto.js`. The implementation handles all ten steps including Step 0 TIP artifact stripping. The reference test suite includes round-trip vectors that any conforming implementation MUST pass.

The extension implements the 8-field canonical signed payload (Section 20.1) in `src/signer-cna22.js`. The implementation handles `attribution_mode`, the `authors[]` 5-key structure, the `cna_version: "CNA-2.2"` lock, the canonical JSON sorting, the SHAKE-256 hash, the ASCII-hex signing rule (Section 9), and the ML-DSA-65 signature via `@noble/post-quantum` version 0.2.1.

### 42.3 Platform support

The reference extension supports 46 user-interface locales (Section 42.5) and detects 400+ host sites. Major platform categories with their content type registries:

- **Microblog**: X (formerly Twitter), Bluesky, Mastodon (any instance), Threads, Truth Social, Weibo, WeChat Moments
- **Visual**: Instagram, Facebook, Pinterest
- **Video**: YouTube, TikTok, Vimeo
- **News and articles**: Major news sites (NYT, WSJ, BBC, Reuters, AP, Guardian, etc.), Medium, Substack, WordPress, Ghost, Dev.to, Hashnode
- **Audio**: Spotify, Apple Podcasts, SoundCloud
- **Messaging**: Slack, Discord, Telegram, WhatsApp Web, Element
- **Other**: Reddit, Tumblr, LinkedIn (with all-frames content script for iframes)

The host_permissions list in `manifest.json` enumerates the exact origins. A new platform may be added by extending the host_permissions list and adding a platform-specific detection module.

### 42.4 WebAuthn / passkey integration

The extension implements two private-key encryption methods:

- **WebAuthn PRF (preferred).** Uses the WebAuthn PRF extension to derive a 32-byte secret from the device authenticator without re-prompting at each signing operation. The 32-byte secret derives an AES-256 key that decrypts the user's ML-DSA-65 private key. Available on Chrome and Edge 116+.

- **WebAuthn fallback.** Derives the AES key from the credential ID through SHAKE-256 plus PBKDF2 (200,000 iterations). Requires a biometric prompt at every signing operation but is portable across browsers without PRF support.

The encrypted private key is stored in extension local storage. The encryption envelope format is described in Section 7.6.

### 42.5 Locale support

The reference extension supports 46 user-interface locales in the `_locales/` directory. The Chrome extension i18n format is used. Right-to-left layout is detected for ar, he, fa, ur.

The 46 supported locales:

ar, bn, cs, da, de, el, en, es, fa, fi, fil, fr, gu, he, hi, hu, id, it, ja, kn, ko, ml, mr, ms, nb, nl, pa, pl, pt_BR, pt_PT, ro, ru, sk, sr, sv, sw, ta, te, th, tr, uk, ur, vi, zh_CN, zh_TW.

Implementations of TIP-conforming clients SHOULD support at minimum the user's browser language (resolved via `navigator.language`). Reference fallback is `en`.

### 42.6 Publisher Mode

The extension supports both Creator Mode (default, `attribution_mode: "self"`) and Publisher Mode (`attribution_mode: "employed"`). Publisher Mode is gated by platform: allowed on news, articles, blogs, podcasts, newsletters; hidden on social, visual, video, messaging. The platform gating is in `src/publisher-mode-gating.js`.

Publisher Mode requires the user to configure a publisher identity (one per extension install) and an author roster. The roster lists the verified bylined contributors with their roles. At signing time, the user selects which authors are bylined on the specific piece of content.

The extension stores per-origin signer choice memory (`signerChoiceMemory`) so that a user who has chosen Creator vs Publisher mode for a particular publication does not re-prompt every time.

### 42.7 Copy-paste fallback

The extension supports the canonical two-line copy-paste fallback (Section 22). After signing, the extension displays the CTID and offers a "Copy share line" button that copies `tip://c/{ctid}\nClick to find out #HumanOrAI` to the clipboard.

When pasted into any platform that does not have a TIP-aware renderer, the result is the canonical fallback line that any reader can click to verify.

## 43. Verification Provider Mobile Web Application Reference Behavior

The reference VP mobile web application is the four-stage biometric verification client used by accredited VPs. The reference implementation is at https://github.com/theailaborg/tip-vp-with-mobile-web-app and is licensed under TIPCL-1.0.

### 43.1 Architecture

The reference VP mobile application uses a vanilla JavaScript single-page application (HTML5, no external framework dependency for core logic) served as a PWA-capable static site. The server-side is Python 3.12 with the TipFast stdlib-only web framework (FastAPI-compatible surface area). SQLite is the development database; PostgreSQL is the production database.

System dependencies:

- Tesseract 5 (primary OCR engine)
- PaddleOCR (secondary OCR engine, hybrid mode)
- OpenCV (face detection, image processing)
- InsightFace (RetinaFace detection plus ArcFace embedding)
- scikit-image, scipy, scikit-learn (anti-spoofing ML)
- pqcrypto (ML-DSA-65 binding)

### 43.2 Ten-view flow

The single-page application implements ten views in the verification flow:

1. **Landing.** Hero, four-step overview, what the user will receive (TIP-ID, public key, AI Trust ID Seal preview).
2. **Step 1 · Government ID.** Document type selection, photo upload for front and back, client-side blur/luminance/edge-density checks.
3. **Step 2 · Liveness.** Camera-based three-challenge interactive liveness (face presence, blink, head turn).
4. **Step 3 · Device biometric binding.** WebAuthn registration flow.
5. **Step 4 · Social attestation.** Optional five-platform social proof.
6. **Review.** Full application review before final submission.
7. **Pending.** Processing animation; auto-polls `GET /v1/verify/{id}/status` every 12 to 20 seconds.
8. **Complete.** TIP-ID card display, seal preview, embed-code generator for the new credential.
9. **Status.** Check existing session status via session ID hash parameter.
10. **Admin.** VP staff dashboard (requires X-VP-Admin-Key header).

### 43.3 19 REST endpoints

The reference VP exposes 19 endpoints grouped as:

**Verification flow (7):**
- `POST /v1/verify/session`
- `POST /v1/verify/{id}/gov-id`
- `GET /v1/verify/{id}/webauthn-challenge`
- `POST /v1/verify/{id}/biometric`
- `POST /v1/verify/{id}/liveness`
- `POST /v1/verify/{id}/social`
- `POST /v1/verify/{id}/submit`

**Status and resume (3):**
- `GET /v1/verify/{id}/status`
- `GET /v1/verify/{id}/resume`
- `GET /v1/verify/{id}/webauthn-reauth-challenge`

**Identity endpoints (5):**
- `GET /v1/identity/lookup?id={tip_id}`
- `GET /v1/identity/seal?id={tip_id}` (returns 280x80 SVG of the AI Trust ID Seal)
- `GET /v1/identity/vp/info`
- `GET /v1/identity/by-dedup-hash/{dedup_hash}`
- `POST /v1/identity/{tipId}/keys/recover`

**Admin endpoints (3, all require X-VP-Admin-Key):**
- `GET /v1/admin/pending`
- `GET /v1/admin/approved`
- `POST /v1/admin/approve/{id}` and `POST /v1/admin/reject/{id}`

**System (1):**
- `GET /health`

These 19 endpoints constitute the VP's external contract. A conforming VP MUST expose them; alternative VP implementations may add additional endpoints.

### 43.4 Anti-spoofing fusion

The reference VP implements a five-signal server-side anti-spoofing fusion (Section 13.2): LBP texture entropy, FFT radial-band analysis for moiré detection, YCbCr chrominance variance for compression artifacts, gradient direction coherence for 3D vs flat surface discrimination, and specular reflection analysis. The composite threshold is 0.42 in production strict mode and 0.28 in development.

SHAKE-256 frame hash anti-replay is enforced: each submitted liveness frame's hash is stored, and any subsequent submission of the same frame hash from any session is rejected.

### 43.5 Publisher Mode in the VP mobile app

The reference VP supports both creator and publisher identity slots. A publisher's verification flow yields a publisher TIP-ID with `tip_id_type: "publisher"`. The publisher's bylined contributors are managed through a separate roster UI.

## 44. WordPress Plugin Reference Behavior

The reference TIP WordPress plugin is at https://github.com/theailaborg/tip-wordpress-plugin and is licensed under TIPCL-1.0.

### 44.1 Architecture

The plugin integrates with WordPress's editor and publishing workflow. When a user publishes a post, the plugin:

1. Detects the post type (article, blog post, page)
2. Prompts the user to select an Origin Code (OH, AA, AG, MX)
3. Computes the canonical content hash using a PHP implementation of CNA-2.2
4. Constructs the 8-field canonical signed payload with the post's permalink in `registered_urls[0]`
5. Signs with the user's ML-DSA-65 private key (held in WordPress user metadata, encrypted)
6. Submits to the configured TIP node via `POST /v1/content/register`
7. Records the returned CTID in WordPress post metadata
8. Optionally injects the CTID and the `#HumanOrAI` line into the post footer

The plugin supports Publisher Mode for WordPress sites that are publisher entities (newsrooms, organizational blogs).

### 44.2 PHP canonical JSON

The plugin's PHP implementation of canonical JSON uses `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` and explicitly casts empty associative arrays to objects before encoding so that empty `extras` render as `{}` rather than `[]`. The byte-identical compatibility with the Node.js and Python reference implementations is the basis for cross-implementation signature verification.

### 44.3 Block editor integration

The plugin adds a sidebar panel to the WordPress block editor (Gutenberg) showing the post's TIP status. After publishing, the panel displays the CTID, the Origin Code, the publication URL, and a "View on TIP" link that opens the verification page.

---

# PART IX · COMPLIANCE, GOVERNANCE, AND CONSIDERATIONS

## 45. EU AI Act Article 50 Compliance Mapping

### 45.1 The August 2, 2026 deadline

The EU AI Act (Regulation (EU) 2024/1689) entered into force on August 1, 2024 and applies in staged enforcement. Article 50 (transparency obligations for AI systems) becomes legally enforceable on **August 2, 2026**. The Code of Practice that implements Article 50 is expected in final form by June 2026, with a four-month grace period for systems already on the market closing on December 2, 2026. Non-compliance penalties scale to **EUR 15 million or 3% of total worldwide annual turnover**, whichever is higher.

This specification is designed so that conforming implementations satisfy Article 50 by construction.

### 45.2 The four Article 50 obligations

**Article 50(1) Interactive AI disclosure.** Providers of AI systems intended to interact with natural persons (chatbots, virtual assistants, voice agents) must ensure users are informed they are interacting with AI.

*TIP mapping:* When an AI agent registers content under a TIP-ID, the agent's `tip_id_type` is `personal` (if the agent is a publicly-disclosed AI persona) or `organization` (if the agent is operated by an entity), and the content's Origin Code is `AG` or `AA`. The Origin Code, machine-readable in every CTID and every signed payload, is the disclosure.

**Article 50(2) Synthetic content marking.** Providers of AI systems that generate synthetic audio, image, video, or text must mark outputs in a machine-readable format and detectable as artificially generated or manipulated.

*TIP mapping:* The Origin Code `AG` (AI-Generated) is the machine-readable marker. It is cryptographically bound to the content hash and the signer. It is detectable by any TIP-conforming Verifier without contacting any central service. It survives normal handling because it is anchored to the canonical content hash, not to file metadata that re-encoding might strip.

**Article 50(4) Deepfake disclosure.** Deployers using AI to create deepfake image, audio, or video must disclose that the content has been artificially generated or manipulated.

*TIP mapping:* The Origin Code `AG` or `MX` is the disclosure. The CTID surfaces the code in every reference. A deployer who publishes a deepfake under origin code `OH` is in violation both of TIP and of Article 50; the protocol's adjudication system penalizes the violation, and the regulator can independently audit the on-DAG record.

**Article 50(4) second subparagraph · Public-interest text disclosure.** Deployers publishing AI-generated text on matters of public interest must disclose the AI provenance unless human editorial control attaches.

*TIP mapping:* `AG` content carries the disclosure inherently. `AA` content with substantive human editorial review qualifies for the editorial-control exception under Article 50; the human editor's TIP-ID appears in `authors[]` with role `"editor"`, surfacing the editorial responsibility.

### 45.3 The six Article 50 technical criteria

The Code of Practice draft enumerates six technical criteria that the marker mechanism must satisfy. The protocol's mapping:

| Article 50 criterion | TIP implementation |
|---|---|
| Machine-readable | Origin Code in the canonical signed payload and in the CTID URI is machine-readable. Any regex over the page or any HTTP response header parser retrieves it in under one millisecond. |
| Detectable as AI-generated | The Origin Code value `AG` is the explicit declaration. A reader sees `AG` and knows the content is AI-generated, with cryptographic proof that the registrant claimed it. |
| Survives normal handling | The content hash is anchored to CNA-2.2-normalized canonical bytes. Re-encoding, format conversion, transcoding, and social-platform reposting do not detach the label from the content because the canonical normalization is robust to these transformations. |
| Robust against removal | The federated DAG keeps a public record of the original Origin Code declaration. Removing the label from a downstream copy does not erase the upstream registration. A reader who queries the network recovers the original label. |
| Identity-bound | Every Origin Code is signed by a verified-human TIP-ID issued through the four-layer biometric verification stack. Article 50 disclosure under TIP is not anonymous. |
| Free for the people who need it most | The TIP Protocol Specification is CC-BY 4.0 worldwide. The reference implementation under TIPCL-1.0 is free for individuals, small businesses under USD 100K annual revenue, journalists, educators, nonprofits, and governments. Converts to Apache 2.0 on January 1, 2031. |

### 45.4 Cross-references

The dedicated EU AI Act compliance landing page at https://theailab.org/eu-ai-act provides the full mapping, FAQ schema, and references to EUR-Lex and the European Commission's Code of Practice consultation. The page is published under Creative Commons CC0 so that any organization can copy the rules verbatim into their own documentation.

## 46. GDPR Compliance

### 46.1 Legal bases for processing

The protocol processes personal data under three legal bases per GDPR Article 6:

- **Article 6(1)(a) Consent (with Article 9(2)(a) for biometric data).** The biometric verification at Layer 2 is special category data under Article 9 and requires explicit consent. The consent is collected through the VP enrollment flow, granular per type (biometric, TIP-ID publication, score visibility mode).

- **Article 6(1)(b) Contract performance.** The content provenance system implements a contractual mechanism: the holder signed the Origin Code declaration; the protocol records the declaration. Processing the content registration and surfacing the verification to readers is performance of the holder's affirmative declaration.

- **Article 6(1)(f) Legitimate interests.** DAG integrity, fraud and Sybil prevention, TIPCL-1.0 attribution compliance monitoring, security monitoring, and Terms of Service enforcement.

### 46.2 Data protection by design (Article 25)

The protocol implements GDPR Article 25 through:

- **Peppered zero-knowledge deduplication.** Biometric data does not appear on the public DAG. The dedup hash is computed with a device-held pepper (Section 10.2) and only a ZK proof is recorded, preventing reidentification.

- **TIER_ONLY default visibility.** Numeric scores are not displayed to third parties by default. The default mode shows only the tier label (Section 27).

- **Biometric data destruction.** VPs destroy raw biometric data after the verification check. Only the 32-byte facial embedding hash and the dedup hash persist, both protected by the pepper architecture.

### 46.3 Data Protection Impact Assessment (Article 35)

A DPIA is mandatory before processing biometric data at scale under Article 35(3)(b). The AI Lab's DPIA covers the entire biometric pipeline, the pepper architecture, the ZK proof system, the score visibility modes, and the cross-border data flow. The DPIA is published at https://theailab.org/dpia before any European deployment. Each accredited VP completes its own DPIA for its specific operational deployment.

### 46.4 Data Protection Officer (Article 37)

The AI Lab has appointed a Data Protection Officer for the protocol's central operations. The DPO contact is `dpo@theailab.org`. Each VP processing personal data at scale must also appoint a DPO under Article 37(1).

### 46.5 Right to erasure (Article 17)

Upon a valid Article 17 erasure request, the protocol:

1. Resets the holder's trust score history (the SCORE_UPDATE transaction chain for that TIP-ID is anonymized; the score reverts to baseline)
2. Removes event-level score data from queryable records
3. **Preserves** the TIP-ID record on the DAG (required for the integrity of historical content provenance the user authored)
4. **Preserves** content provenance records (the CTID and the content hash bind a piece of content to its author; erasing this would destroy the authenticity guarantee for content the user themselves published)
5. Records the erasure event as an immutable DAG transaction

The preservation of TIP-ID and content provenance under Article 17 is justified by Article 17(3)(b) (processing necessary for the public interest in content authenticity) and Article 17(3)(e) (processing necessary for the establishment, exercise, or defense of legal claims regarding content authorship).

The holder is informed of this limitation at registration and acknowledges it in the consent flow.

### 46.6 Data subject rights implementation

| Article | Right | Implementation |
|---|---|---|
| 15 | Access | API endpoint exports all TIP-ID data |
| 16 | Rectification | Process to correct profile metadata (DPO-administered) |
| 17 | Erasure | Score history reset; TIP-ID record preserved under public-interest exception |
| 18 | Restriction | Ability to set visibility to VERIFIED_ONLY |
| 20 | Portability | Export TIP-ID keypair, score history, content records as JSON |
| 21 | Objection | Process to object to specific SCORE_UPDATE events via the adjudication system |
| 22 | Automated decision-making | All adverse user-affecting decisions require human reviewer confirmation per TIP Terms of Service Section 5.6; AI classifier output is advisory only |

### 46.7 International data transfer

The DAG is a global federated network. TIP-ID metadata replicates worldwide. The protocol's response to international transfer concerns:

- TIP-IDs are pseudonymous identifiers (Article 4(5)): the `tip://id/{Region}-{Fingerprint16}` URI carries no name, address, biometric data, or directly identifying information
- The biometric data and the personal name are held only at the issuing VP, not on the public DAG
- The dedup hash is computed with a device-held pepper that prevents cross-border reidentification
- Content hashes are SHAKE-256 of CNA-2.2-normalized content; they are not personal data themselves

Cross-border transfer therefore falls under the Article 25 pseudonymization provisions rather than requiring SCC- or BCR-level controls.

## 47. Global AI Regulation Landscape

The protocol is designed to satisfy disclosure and content-provenance obligations in eleven jurisdictions. Each is summarized below with effective date and the protocol's mapping. The detailed jurisdiction-by-jurisdiction mapping is maintained at https://theailab.org/eu-ai-act (where the EU is the headline mapping) and at the project memory file `.claude/memory/ai-regulation-landscape.md`.

| Framework | Jurisdiction | Effective | Penalty | TIP mapping |
|---|---|---|---|---|
| EU AI Act Article 50 | European Union | Aug 2, 2026 | EUR 15M or 3% global turnover | Origin Codes + machine-readable label |
| California AI Transparency Act (SB 942) | California, USA | Jan 1, 2026 | USD 5,000/violation/day | Embedded disclosure + provenance metadata |
| California AB 2013 | California, USA | Jan 1, 2026 | Civil per Cal Bus & Prof Code | TIP-CONTENT provenance chain |
| Colorado AI Act (SB 24-205) | Colorado, USA | Jun 30, 2026 | Per CO Consumer Protection Act | Origin Code disclosure for high-risk content |
| NYC Local Law 144 | New York City, USA | In force | Civil per NYC enforcement | TIP-ID identity for AEDT candidate notification |
| UK Online Safety Act | United Kingdom | Phased through 2026 | GBP 18M or 10% global turnover | MX and AG codes for synthetic media |
| Brazil PL 2338/2023 | Brazil | Senate passed Dec 2024 | BRL 50M or 2% group revenue | Origin Codes for generative AI |
| India DPDP Act | India | Phased through May 2027 | INR 250 crore | TIP-ID for data-principal identification |
| Canada AIDA (proposed) | Canada | Pending enactment | CAD 25M or 5% global revenue | Origin Codes for high-impact AI systems |
| China Generative AI Provisions | China | In force Aug 15, 2023 | Per CAC enforcement | Origin Code labelling for Article 17 |
| UK DSIT AI Safety Framework | United Kingdom | Ongoing | Sector-specific | Technical-standard input to DSIT |

The protocol is jurisdiction-agnostic by design: the same Origin Code declaration that satisfies the EU AI Act satisfies every other framework in the list. A creator does not need to mark content differently for different jurisdictions.

## 48. Dual Badge Architecture

### 48.1 The two badge objects

The protocol uses two visually and legally distinct badge objects.

**TIP Powered Mark (Open).** Displayed by any platform that implements the TIP Protocol. Licensed under TIPCL-1.0 (converts to Apache 2.0 on January 1, 2031). No registration with The AI Lab required. The mark's arc text reads "TRUST IDENTITY PROTOCOL" on the top and "OPEN SPEC · TIPCL-1.0" on the bottom. The mark is freely available in light, dark, and color variants.

**AI Trust ID Seal (Proprietary).** Issued by The AI Lab's registry to verified individuals via the registration flow. Cannot be self-applied. Features a gold metallic outer ring (#C9A84C) on a deep navy background (#0B1629), an inner ring with a tier-colored shield, the holder's numeric score (in FULL_PUBLIC mode) or tier label (in TIER_ONLY mode), and arc text "AI TRUST ID" and "AI TRUST REGISTRY". Available in Gold Dark (default), Light, and Dark colorways.

### 48.2 Why two badges

The separation mirrors the Bluetooth SIG model: an open specification for broad adoption (Bluetooth), a controlled trademark for quality assurance (the Bluetooth logo). Any device may implement Bluetooth without permission; only certified devices may display the Bluetooth logo. The discipline keeps the brand signal accurate even as the protocol becomes ubiquitous.

The TIP Powered Mark says: "this product implements the protocol." The AI Trust ID Seal says: "this person is verified and active in the registry."

### 48.3 Brand guidelines

The detailed brand guidelines, including color specifications, typography (Libre Franklin, DM Sans, JetBrains Mono), the protected trademark list, the EU AI Act Article 50 co-display rules, and the Verification Provider badge rules, are at https://theailab.org/brand-guidelines.

The brand guidelines page is itself published under Creative Commons CC0 so that any organization can copy the rules into its own documentation.

## 49. AI Trust Council Governance

### 49.1 Mandate

The AI Trust Council is the multi-stakeholder governance body for the Trust Identity Protocol, modeled on how ICANN governs the global Domain Name System. The Council sets policy by consensus across five constituencies:

- **Creators.** Independent journalists, content creators, writers, artists, musicians, filmmakers.
- **Institutions.** Universities, research labs, journalism schools, libraries, archives.
- **Publishers.** News organizations, magazines, podcast networks, newsletter platforms.
- **Operators.** Accredited Verification Providers, node operators, infrastructure providers.
- **Partners.** Industry participants, AI providers, standards organizations.

Each constituency has equal voting weight. Constituencies elect representatives through their own processes.

### 49.2 Authority

The Council has authority over:

- Protocol specification changes (through the RFC process in Section 50)
- VP accreditation policy
- Jurisdiction tier classification methodology
- Genesis Ring membership decisions
- Trademark licensing policy
- Brand guidelines amendments
- Conversion timing decisions for TIPCL-1.0 to Apache 2.0

The Council does NOT have authority over:

- Individual VP accreditation decisions (operational; delegated to The AI Lab's accreditation team)
- Individual adjudication outcomes (the protocol's distributed community adjudication system handles cases)
- The AI Lab's own corporate decisions (governance of the company is separate from governance of the protocol)

### 49.3 Founding membership

The Council was constituted at network launch with a founding membership of approximately 30 individuals across the five constituencies. The founding members are recorded in the Genesis Ring. The Council's working procedures, member roster, and meeting records are at https://theailab.org/ai-trust-council and https://theailab.org/governance.

## 50. RFC Process

### 50.1 What requires an RFC

Changes to this specification that require an RFC include:

- DAG transaction format or validation rules
- Trust scoring algorithm or genesis constants
- Identity registration or deduplication method
- Cryptographic algorithms or key sizes
- Genesis block format
- New transaction types affecting consensus
- VP accreditation requirements
- GDPR or privacy architecture changes
- New CNA versions
- API endpoint additions or deprecations
- Trust tier thresholds

Editorial corrections, clarifications, examples, and changes that do not affect interoperability do not require an RFC.

### 50.2 RFC stages

1. **Discussion.** Open a public discussion on the protocol's RFC repository: `[RFC-XXX] Title`. The discussion is open for a minimum 30 days during which the community comments.

2. **Decision.** The AI Trust Council reviews community feedback and reaches one of three decisions: ACCEPTED, NEEDS_REVISION, REJECTED. The decision is published with reasoning.

3. **Implementation.** The proposer (or others) implement the change in the reference codebase: TIP node, browser extension, VP mobile app, WordPress plugin, badge widget, SDK, CLI. Implementation includes tests, documentation, and a CHANGELOG entry.

4. **Testnet.** The change is deployed to the protocol testnet for a minimum 90-day period before mainnet adoption. Testnet runs surface integration issues and security defects.

5. **Mainnet.** After successful testnet, the change is included in a numbered specification version and deployed to mainnet.

### 50.3 Emergency RFCs

Security-critical changes (a discovered cryptographic vulnerability, a critical implementation flaw) may bypass the standard 30-day comment period under an Emergency RFC process. Emergency RFCs are decided by The AI Lab's emergency response team in consultation with at least three external security researchers and require post-hoc Council ratification within 30 days. The emergency RFC process has been used twice in the protocol's history: once for a key-rotation timing fix in v3.1 and once for a SHAKE-256 implementation conformance fix in v4.0.

## 51. Security Considerations

### 51.1 Cryptographic security

The protocol's cryptographic security rests on the assumed difficulty of:

- ML-DSA (Module-Lattice-Based Digital Signature) under standard lattice assumptions
- SLH-DSA (Hash-Based Signature) under SHA-3 collision and second-preimage resistance
- SHAKE-256 collision and pre-image resistance
- Groth16 zero-knowledge proofs under bilinear pairing assumptions and the Hermez Phase 1 trusted-setup ceremony

A practical attack on any of these foundations would compromise the protocol's signature integrity. The protocol's response to such an event is the algorithm-negotiation mechanism in Section 11 and the RFC process for algorithm replacement.

### 51.2 Key custody

Holders' ML-DSA-65 private keys are held on holders' devices, encrypted at rest under AES-256-GCM with keys derived from WebAuthn PRF or PBKDF2. A holder who loses control of their device loses control of their signing capability. The protocol's response is the REVOKE_DEVICE and KEY_RECOVERY procedures (Sections 15.3 and 37.5).

VPs' signing keys are held in FIPS 140-3 Level 3 HSMs. The root key is held under a two-of-three custodian policy with air-gapped signing.

### 51.3 Verification Provider compromise

If a VP is compromised, the consequences depend on the nature of the compromise:

- **Signing key theft.** Attacker can issue fraudulent TIP-IDs. Detection: the dedup registry's Merkle root publishing every 6 hours surfaces any anomalous identity issuance volume. Response: VP_SUSPENDED transaction, then cascade revocation of suspected fraudulent TIP-IDs.

- **Biometric pipeline weakness.** Attacker can pass the four-layer verification with falsified inputs. Detection: ongoing red-team testing and the audit cadence mandated in the Code of Conduct (Section 35.5). Response: technical-standard update through the RFC process.

- **Government compulsion.** A jurisdictional authority compels the VP to issue a TIP-ID under coercion. Detection: warrant canary lapse (Section 36.4). Response: jurisdiction tier reclassification and VP_SUSPENDED.

### 51.4 Adjudication compromise

Coordinated abuse of the adjudication system (Sybil attacks on the Juror pool, coordinated voting blocs) is bounded by the trust score eligibility floors and the conflict-of-interest filters. The reference implementation also applies probabilistic anomaly detection to flag jurors whose vote patterns correlate with specific outcomes across cases.

A successful adjudication attack would require coordinating enough high-trust-score TIP-IDs to swing votes. The protocol's defense is that high-trust-score TIP-IDs are rare (the score floor is 700 for Jurors and 850 for Experts) and the score accumulation requires sustained honest participation, making coordinated attacks economically expensive.

### 51.5 DDoS and gossip-flooding

A node under denial-of-service attack experiences degraded throughput. The reference TIP node implements rate-limiting per-IP (express-rate-limit), per-TIP-ID (signature-based rate limiting), and per-message-type (mempool prioritization). The federated network's gossip topology means that any single node's degradation does not affect the rest of the network.

### 51.6 Quantum computing

The protocol's algorithms are NIST-standardized post-quantum primitives. A future sufficiently large quantum computer that broke RSA, ECDSA, or other classical primitives would not break TIP signatures. The classical fallback during the transition period (Ed25519) is a backward-compatibility convenience, not a security fallback.

## 52. Privacy Considerations

### 52.1 What the protocol reveals

A TIP-ID's public DAG record reveals:

- The holder's TIP-ID (pseudonym)
- The holder's verification tier (T1, T2, T3, T4)
- The holder's region (ISO 3166-1 alpha-2 country code of the issuing VP)
- The holder's `tip_id_type` (personal, organization, publisher, government, vp)
- The holder's trust score (only in FULL_PUBLIC visibility mode)
- The holder's tier label (in TIER_ONLY and FULL_PUBLIC modes; not in VERIFIED_ONLY)
- The holder's complete content registration history
- The holder's complete adjudication participation history (votes on cases, disputes filed, appeals filed)
- The holder's revocation history if any

The DAG does NOT reveal:

- The holder's legal name (unless the holder opts in by setting `creator_name`)
- The holder's government identity document number
- The holder's date of birth
- The holder's biometric data
- The holder's device identifier
- The holder's IP address or geolocation
- The holder's email address or phone number

### 52.2 Pseudonymization

The TIP-ID URI is a pseudonym in the GDPR Article 4(5) sense: it does not directly identify the holder. Linking a TIP-ID to a real person requires either:

- The holder's voluntary disclosure of their TIP-ID alongside their name on a public surface they control
- A legal process compelling the issuing VP to reveal the holder's identity
- An out-of-band linkage (the holder is the only Substacker named "Jane Doe" and only one TIP-ID has registered Substack content with the name in `creator_name`, etc.)

The protocol's design minimizes the involuntary linkage paths. The pseudonym is durable: a holder who uses TIP across multiple platforms surfaces a consistent identity to readers who track them by TIP-ID without exposing their legal name.

### 52.3 What is preserved through erasure

Content provenance records (CTIDs) bind content to TIP-IDs. Erasing the TIP-ID would destroy the authorship attribution for every piece of content the holder ever registered, including content the holder is still entitled to (under copyright) and content the public is entitled to know was authored by them. The protocol therefore preserves TIP-ID records on Article 17 erasure (Section 46.5) while erasing the SCORE_UPDATE history and event-level data.

The holder is informed of this limitation at registration consent.

### 52.4 Aggregation risk

A motivated adversary with full DAG access can construct a complete behavioral profile of any TIP-ID: every piece of content registered, every dispute filed, every vote cast. The profile is by design (the protocol's transparency is essential to its public-audit property), but the aggregation risk is acknowledged. A holder who values strong pseudonymity is well advised to:

- Use VERIFIED_ONLY visibility mode (the most restrictive)
- Avoid posting content that includes content-specific identifiers
- Consider whether multiple distinct TIP-IDs are appropriate for distinct contexts (recognizing that one person can hold only one TIP-ID due to deduplication)

The protocol does not directly enforce the strong pseudonymity choice; it provides the tools for the holder to make the choice.

## 53. IANA Considerations · URI Scheme Registration

This specification requests IANA registration of the `tip` URI scheme.

### 53.1 Scheme name

`tip`

### 53.2 Status

Provisional.

### 53.3 Applications and protocols that use this scheme

The Trust Identity Protocol specified in this document. Reference implementations are at https://github.com/theailaborg.

### 53.4 Contact

Dinesh Mendhe, Founder and Chairman, The AI Lab Intelligence Unobscured, Inc.
Email: dineshmendhe@theailab.org
Web: https://theailab.org

### 53.5 Change controller

The AI Trust Council, governed under the procedures at https://theailab.org/governance.

### 53.6 References

This specification document. Published at https://theailab.org/tip-spec under Creative Commons Attribution 4.0 International.

### 53.7 Syntax

The `tip` scheme follows IETF RFC 3986 generic URI syntax with the following authority component restrictions:

```
tip-URI    = "tip:" "//" tip-host "/" tip-path
tip-host   = "id" / "c" / "vp"
tip-path   = tip-id-path / tip-content-path / tip-vp-path
tip-id-path      = region "-" fingerprint16
tip-content-path = origin-code "-" hash14 "-" author4
tip-vp-path      = region "-" fingerprint16
region           = 2 (ALPHA)
origin-code      = "OH" / "AA" / "AG" / "MX"
fingerprint16    = 16 (HEXDIG-lowercase)
hash14           = 14 (HEXDIG-lowercase)
author4          = 4 (HEXDIG-lowercase)
```

### 53.8 Resolution

The default resolution endpoint for `tip://` URIs is `https://tip.theailab.org/r/{full-uri}`. Browser extensions and TIP-aware applications MAY intercept `tip://` URIs and render them inline rather than resolving to the default endpoint.

## 54. Versioning Policy

The protocol uses major.minor versioning. The current version is 5.0.

### 54.1 Major version bumps

A major version bump (5.0 to 6.0) signals a non-backward-compatible change. A major version bump requires:

- A new chain identifier (`tip-mainnet-v5` to `tip-mainnet-v6`)
- A migration path for existing TIP-IDs (typically: KEY_ROTATED transactions under the new specification rules)
- A defined sunset date for the older version's mainnet
- Approval by at least two-thirds of the AI Trust Council

The protocol has had four major versions: v1.0 (private specification, never published), v2.0 (private internal release), v3.0 (first published specification, March 2026), v4.0 (March 2026 expansion), and v5.0 (this document, June 2026 with two years of implementation experience integrated). v6.0 is not planned.

### 54.2 Minor version bumps

A minor version bump (5.0 to 5.1) signals a backward-compatible addition. New CNA versions, new transaction types, new API endpoints, and new optional fields all qualify. A minor version bump requires:

- An RFC accepted by the Council
- Reference implementation updates
- A 90-day testnet period
- A CHANGELOG entry

Verifiers conforming to v5.0 continue to function on a v5.1 network for all transactions that use only the v5.0 features. Verifiers wishing to use v5.1 features upgrade their implementation.

### 54.3 CNA version evolution

The CNA version (Section 19.5) evolves independently of the protocol major.minor version. The acceptance list grows over time. A protocol minor version bump may or may not include a new CNA version.

### 54.4 Specification document versioning

This specification document version (v5.0) and the chain identifier (`tip-mainnet-v5`) move together. Patches to this document (typo corrections, clarifications, new examples) do not bump the version; they are recorded in the CHANGELOG (Appendix B) under "v5.0 corrections."

## 55. References

### 55.1 Normative references

- IETF RFC 2119, "Key words for use in RFCs to Indicate Requirement Levels", March 1997
- IETF RFC 3986, "Uniform Resource Identifier (URI): Generic Syntax", January 2005
- IETF RFC 8174, "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", May 2017
- IETF RFC 8259, "The JavaScript Object Notation (JSON) Data Interchange Format", December 2017
- NIST FIPS 202, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions", August 2015
- NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard", August 2024
- NIST FIPS 204, "Module-Lattice-Based Digital Signature Standard", August 2024
- NIST FIPS 205, "Stateless Hash-Based Digital Signature Standard", August 2024
- NIST FIPS 197, "Advanced Encryption Standard (AES)", November 2001
- NIST SP 800-38D, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", November 2007
- NIST SP 800-90A Rev 1, "Recommendation for Random Number Generation Using Deterministic Random Bit Generators", June 2015

### 55.2 Informative references

- Regulation (EU) 2024/1689 on Artificial Intelligence (EU AI Act), entered into force August 1, 2024
- California Senate Bill 942 (AI Transparency Act), effective January 1, 2026
- California Assembly Bill 2013 (Generative AI Training Data Transparency Act), effective January 1, 2026
- Colorado Senate Bill 24-205 (Colorado AI Act), effective June 30, 2026
- UK Online Safety Act, phased through 2026
- Brazil PL 2338/2023, Senate-approved December 2024
- India Digital Personal Data Protection Act 2023, phased through May 2027
- Canada AIDA (Artificial Intelligence and Data Act), proposed
- China Cyberspace Administration of China Provisions on the Administration of Deep Synthesis Internet Information Services, effective August 15, 2023
- ICAO Doc 9303, "Machine Readable Travel Documents", Eighth Edition, 2021
- W3C WebAuthn Level 2, "Web Authentication: An API for accessing Public Key Credentials", April 2021
- W3C Web Cryptography API, January 2017
- IETF RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)", January 2017
- IETF RFC 8018, "PKCS #5: Password-Based Cryptography Specification Version 2.1", January 2017
- IETF RFC 8785, "JSON Canonicalization Scheme (JCS)", June 2020 (analogous but not byte-equivalent to TIP's canonical JSON)
- Coalition for Content Provenance and Authenticity (C2PA) Specification, ongoing

### 55.3 Reference implementations

- TIP Protocol Reference Implementation: https://github.com/theailaborg/tip-protocol
- TIP Browser Extension: https://github.com/theailaborg/tip-browser-extension
- TIP Verification Provider with Mobile Web Application: https://github.com/theailaborg/tip-vp-with-mobile-web-app
- TIP WordPress Plugin: https://github.com/theailaborg/tip-wordpress-plugin
- TIP Badge Widget: https://github.com/theailaborg/tip-badge

### 55.4 Companion documentation

- TIP Terms of Service: https://theailab.org/tip-terms-of-service
- TIP Privacy Policy: https://theailab.org/tip-privacy-policy
- TIP Acceptable Use Policy: https://theailab.org/tip-acceptable-use
- TIP Community License 1.0 (TIPCL-1.0): https://theailab.org/tip-license
- EU AI Act Article 50 Compliance Guide: https://theailab.org/eu-ai-act
- TIP Brand Guidelines: https://theailab.org/brand-guidelines
- AI Trust Council Governance: https://theailab.org/governance
- VP Accreditation Procedure: https://theailab.org/accreditation

---

# APPENDIX A · PROTOCOL CONSTANTS REFERENCE

The complete enumeration of named constants in the protocol, consolidated from Sections 30.1, 13.5, 27, 28, and elsewhere.

```
PROTOCOL_VERSION:           "5.0"
CHAIN_ID:                   "tip-mainnet-v5"

STARTING_SCORE:             500
ATTESTED_STARTING_SCORE:    550
MAX_SCORE:                  1000
MIN_SCORE:                  0

SOCIAL_ATTESTATION_BONUS:   50
VOUCHER_STAKE:              25

CLEAN_RECORD_DAYS:          90
CLEAN_RECORD_BONUS:         10

DISPUTER_STAKE:             15
UPHELD_BONUS:               5
VINDICATION_BONUS:          5
APPELLANT_STAKE:            25
OVERTURN_BONUS:             10

JUROR_MAJORITY_BONUS:       3
EXPERT_MAJORITY_BONUS:      7
MINORITY_PENALTY:           10
NO_SHOW_PENALTY:            10
REVIEWER_CORRECT_BONUS:     5

DISPUTE_AUTO_ESCALATE:      0.90
DISPUTE_AUTO_DISMISS:       0.30
PRESCAN_FLOOR:              0.80
PRESCAN_CEILING:            0.94
PRESCAN_DEFAULT:            0.85

JURY_SIZE:                  7
JURY_SCORE_FLOOR:           700
JURY_COMMIT_HOURS:          72
JURY_REVEAL_HOURS:          6
JURY_QUORUM_REVEALS:        5
JURY_QUORUM_NON_ABSTAIN:    3

EXPERT_PANEL_SIZE:          3
EXPERT_SCORE_FLOOR:         850

REVIEWER_SCORE_FLOOR:       800
REVIEWER_TIMEOUT_HOURS:     48
REVIEWER_MAX_OVERTURN_RATE: 0.30
REVIEWER_SAMPLE_SIZE:       20

DISPUTER_SCORE_FLOOR:       400
DISPUTER_FREQUENCY_CAP:     5  (per rolling 30 days)

MAX_AUTHORS_PER_POST:       10

MERKLE_INTERVAL_HOURS:      6
DAG_MIN_REFS:               2

DEDUP_HASH_OUTPUT_BYTES:    32
CONTENT_HASH_OUTPUT_BYTES:  32
TIP_ID_FINGERPRINT_CHARS:   16
CTID_HASH_CHARS:            14
CTID_AUTHOR_CHARS:          4

CNA_CURRENT_VERSION:        "CNA-2.2"
CNA_ACCEPTANCE_LIST:        ["CNA-2.2"]

TIER_HIGHLY_TRUSTED_MIN:    800
TIER_TRUSTED_MIN:           600
TIER_REVIEW_ADVISED_MIN:    400
TIER_LOW_TRUST_MIN:         200
TIER_NOT_TRUSTED_MIN:       0

TIER_COLOR_HIGHLY_TRUSTED:  "#1A8A5C"
TIER_COLOR_TRUSTED:         "#2563A8"
TIER_COLOR_REVIEW_ADVISED:  "#A88B15"
TIER_COLOR_LOW_TRUST:       "#C07318"
TIER_COLOR_NOT_TRUSTED:     "#C53030"

ORIGIN_COLOR_OH:            "#1A8A5C"
ORIGIN_COLOR_AA:            "#B8942E"
ORIGIN_COLOR_AG:            "#C44569"
ORIGIN_COLOR_MX:            "#6B46C1"

TRANSITION_END_DATE:        "2029-06-01"

SIGNATURE_ALGORITHM:        "ml_dsa_65"  (FIPS 204, Category 3)
ROOT_SIGNATURE_ALGORITHM:   "slh_dsa_128s"  (FIPS 205)
KEM_ALGORITHM:              "ml_kem_768"  (FIPS 203, reserved for future)
HASH_ALGORITHM:             "shake_256"  (FIPS 202)
SYMMETRIC_ALGORITHM:        "aes_256_gcm"  (FIPS 197, SP 800-38D)
```

# APPENDIX B · CHANGELOG

| Version / Event | Date | Changes |
|---|---|---|
| v5.0 specification published | June 1, 2026 | Comprehensive revision integrating two years of implementation experience and the operational pilot since April 7, 2026. CNA-2.2 with 10-step algorithm including Step 0 TIP artifact stripping. 8-field canonical signed payload. Mandatory `registered_url`. Full 29-transaction-type taxonomy. 19-endpoint REST API. Publisher Mode and Creator Mode dual attribution. Default-enabled community adjudication with explicit opt-out. Canonical copy-paste fallback format. EU AI Act Article 50 mapping with August 2, 2026 deadline. Dual badge architecture. 46-locale support requirement. Genesis ring, jurisdiction tiers, and warrant canary obligations. IANA URI scheme registration. |
| **Full-workflow pilot deployment** | **April 7, 2026** | The reference implementation began operating end-to-end in pilot. The pilot covers the reference TIP node, the browser extension, the Verification Provider mobile web application, the WordPress plugin, the badge widget, and the federated DAG. CNA-2.2 normalization round-trip, ML-DSA-65 signatures, WebAuthn device binding, peppered ZK deduplication, the 19-endpoint REST API, and the default-enabled community adjudication mechanism are all operational from this date. |
| v4.0 specification | March 2026 | Added v2 architectural improvements: peppered ZK deduplication, adaptive creator-calibrated AI pre-scan, multi-type identity revocation, GDPR-compliant score visibility modes, jurisdiction tier classification |
| v3.0 specification | March 2026 | First published specification (v1 design) |
| v2.0 internal | 2025 (internal) | Internal release; not publicly distributed |
| v1.0 internal | 2024 (internal) | Initial private specification; not publicly distributed |

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc. All rights reserved.*

*This specification is licensed under Creative Commons Attribution 4.0 International (CC-BY 4.0). The required attribution is: "TIP Protocol Specification by Dinesh Mendhe, The AI Lab Intelligence Unobscured, Inc. (theailab.org)"*

*Trust Identity Protocol(TM), TIP(TM), AI Trust Council(TM), AI Trust Registry(TM), AI Trust ID(TM), The Global Seal of Trust(TM), Sentinel(TM), Guardian(TM), Sovereign(TM), and The AI Lab(TM) are trademarks of The AI Lab Intelligence Unobscured, Inc. The CC-BY 4.0 license of this specification does not transfer any rights in the trademarks. Trademark use is governed by https://theailab.org/brand-guidelines.*

*Patent rights described in this specification are governed by TIPCL-1.0 Section 8. A royalty-free patent license under the published patent claims is granted to every implementation that complies with this specification, terminable on defensive grounds.*

**End of Specification · Version 5.0 · June 1, 2026**
