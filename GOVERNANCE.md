# Protocol Governance

## Overview

TIP Protocol is governed by The AI Lab Intelligence Unobscured, Inc. during
the founding phase (2026-2028). A community governance council is planned for
Year 2 onward. This document describes the current governance structure and
the roadmap to community governance.

## Current Governance (2026)

The AI Lab holds full governance authority over:
- Protocol specification changes
- VP accreditation and revocation
- Jurisdiction tier classification (GREEN/AMBER/RED)
- Genesis ring membership
- Trademark licensing
- Commercial license issuance

**Protocol steward:** Dinesh Mendhe, Founder  
**Contact:** chairman@theailab.org

## Decentralisation Roadmap

### Phase 1: Centralised Coordinator (Months 1-4)
The AI Lab operates the coordinator node. Simple, fast to deploy. This phase
is honest about the temporary centralisation.

### Phase 2: Committee of Validators (Months 4-8)
A committee of 21 elected validator nodes. The AI Lab holds one vote among 21,
preventing unilateral control. Validators are elected by VP-accredited nodes.

### Phase 3: Full Decentralisation (Month 8+)
Coordinator removed. Network self-validates when DAG density exceeds 100 TPS
sustained. The AI Lab retains trademark and genesis key authority but loses
operational control of the network.

## Protocol Changes

### Application Layer Changes

Changes to the SDK, CLI, browser extension, badge component, or API surface
(that do not affect the core protocol) follow the standard pull request
process described in [CONTRIBUTING.md](./CONTRIBUTING.md).

### Protocol Core Changes

Changes to the DAG engine, trust scoring algorithm, identity registration,
cryptographic requirements, or the genesis block format require the RFC
(Request for Comments) process:

1. **Open a GitHub Discussion** with the tag `[RFC]`
2. **30-day community comment period**
3. **The AI Lab review and decision** (during Phase 1)
4. **Implementation and testing** (minimum 90-day testnet period)
5. **Mainnet deployment** with coordinated node upgrade

RFCs that are accepted are assigned an RFC number and archived in
`docs/rfcs/`.

## Warrant Canary

The AI Lab publishes a quarterly warrant canary confirming that no government
has made a compelled, undisclosed request for user data. The canary is
published at theailab.org/transparency.

Failure to publish within 90 days of the last canary is treated by the
protocol as a triggered canary, and other nodes will flag affected
identities accordingly.

## Transparency Register

The AI Lab publishes annually:
- Number and category of government data requests received
- Status of all active VP accreditations
- Current jurisdiction tier classifications
- Security audit results for The AI Lab's founding VP node

Published at: theailab.org/transparency

## Genesis Ring

The genesis ring consists of:
- The AI Lab Founder (Dinesh Mendhe): required
- The AI Lab executive leadership members: required
- Named external validators (journalists, researchers, civil liberties advocates)

The genesis ring is **closed at network launch**. No new founding members
can be added after the genesis block is minted. Subsequent participants
join through normal network processes (VP accreditation or trust score
accumulation).

---

*The AI Lab Intelligence Unobscured, Inc.*  
*chairman@theailab.org | theailab.org*
