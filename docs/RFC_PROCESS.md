# TIP Protocol RFC Process

Protocol core changes require the Request for Comments (RFC) process.
This document describes what qualifies as a core change and how to propose one.

---

## What Requires an RFC

The following changes ALWAYS require an RFC before a pull request is accepted:

- Changes to the DAG transaction format or validation rules
- Changes to the trust scoring algorithm or penalty schedule
- Changes to the identity registration or deduplication method
- Changes to the cryptographic algorithms or key sizes
- Changes to the genesis block format
- New transaction types that affect network consensus
- Changes to the VP accreditation requirements
- Changes to the GDPR or privacy architecture

The following do NOT require an RFC:
- Bug fixes in non-core modules (SDK, CLI, badge, browser extension)
- New API endpoints that do not affect core protocol behavior
- Documentation improvements
- Performance improvements that do not change observable behavior

---

## RFC Process

### Step 1: Open a GitHub Discussion

Create a GitHub Discussion with the title: `[RFC-XXX] Your Title Here`
(The RFC number is assigned by a maintainer after triage.)

Include:
- **Problem statement**: What problem does this solve?
- **Proposed change**: Detailed technical description
- **Alternatives considered**: Why is this the best approach?
- **Backward compatibility**: Does this break existing implementations?
- **Migration path**: How do existing deployments upgrade?

### Step 2: 30-Day Comment Period

All RFCs remain open for community comment for a minimum of 30 days.
Maintainers may extend this period for complex or controversial proposals.

### Step 3: Decision

After the comment period, The AI Lab Intelligence Unobscured, Inc. (Phase 1) or the governance council
(Phase 2+) makes one of three decisions:
- **Accepted**: RFC proceeds to implementation
- **Needs revision**: RFC is returned to author with specific feedback
- **Rejected**: RFC is closed with explanation

### Step 4: Implementation

Accepted RFCs are assigned to a protocol release milestone. Implementation
must include:
- Reference implementation in both Node.js and Python
- Test coverage for the new behavior
- Updated protocol specification (spec/TIP_Protocol_Specification_v4.0.md)
- Updated CHANGELOG.md

### Step 5: Testnet Period

All accepted RFCs require a minimum 90-day testnet period before mainnet
deployment. This allows node operators to test upgrades without risk.

---

## RFC Archive

Accepted and rejected RFCs are archived in `docs/rfcs/` as Markdown files.

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*
