# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes: active security patches |
| 1.x     | Critical patches only |
| < 1.0   | No |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Security vulnerabilities in TIP Protocol can affect identity verification,
content provenance integrity, trust score manipulation, and cryptographic
protection of biometric data. We treat all security reports with the highest
priority.

### How to Report

**Email:** security@theailab.org

**PGP key:** Available at theailab.org/security/pgp-key.asc

**What to include:**
- A description of the vulnerability and its potential impact
- Steps to reproduce or proof-of-concept code
- Affected versions
- Any suggested mitigations (optional)

### What to Expect

| Timeline | Action |
|----------|--------|
| Within 48 hours | Acknowledgment of your report |
| Within 7 days | Initial severity assessment and triage |
| Within 30 days | Patch development for Critical/High findings |
| Within 90 days | Full public disclosure (coordinated) |

We will keep you informed throughout the process and credit you in the
security advisory unless you prefer anonymity.

### Severity Levels

**Critical**: Exploitable to forge TIP-IDs, manipulate trust scores at
scale, compromise biometric data, break cryptographic guarantees, or
subvert the genesis chain. Response: 24-hour acknowledgment, 7-day patch
target.

**High**: Enables impersonation, unauthorized content registration,
adjudication manipulation, or VP accreditation bypass. Response: 48-hour
acknowledgment, 30-day patch target.

**Medium**: Information disclosure, denial of service, or partial integrity
violations. Response: 7-day acknowledgment, 90-day patch target.

**Low**: Minor issues with limited security impact. Response: 30-day
acknowledgment, next minor version.

## Safe Harbour

We will not pursue legal action against researchers who:
- Report vulnerabilities through this responsible disclosure process
- Do not access, modify, or delete data belonging to other users
- Do not perform denial-of-service attacks
- Do not publicly disclose findings before the coordinated disclosure date
- Act in good faith

## Scope

**In scope:**
- TIP Protocol Reference Implementation (Node.js and Python)
- SDK, CLI tools, browser extension, badge web component
- REST API endpoints
- Cryptographic implementation
- DAG transaction validation
- Identity registration and deduplication
- Trust score computation
- VP accreditation process

**Out of scope:**
- The AI Lab Intelligence Unobscured, Inc. internal infrastructure not part of this repository
- Third-party biometric vendor software (iProov, Jumio, Onfido)
- Social engineering attacks against The AI Lab employees
- Physical attacks

## Security Architecture

TIP Protocol's security rests on several layers. Vulnerabilities are most
severe when they affect multiple layers simultaneously:

1. **Cryptographic layer**: ML-DSA-65, SLH-DSA-128s, ML-KEM-768, SHAKE-256
2. **Biometric binding**: Four-layer verification stack, device FIDO2 binding
3. **Deduplication**: Peppered SHAKE-256 hash + ZK proof on DAG
4. **DAG integrity**: Genesis block signature chain, gossip validation
5. **Trust scoring**: Deterministic computation, penalty structure
6. **Network layer**: Gossip protocol, node authentication

## Known Limitations (v2.0)

The following are known limitations documented in the protocol. They are not
vulnerabilities but known architectural trade-offs:

- The ZK proof library uses a stub implementation in v2.0.0. Production
  deployment requires replacing the stub with snarkjs/Groth16 or equivalent
  before processing real biometric data. See [CHANGELOG.md](./CHANGELOG.md).

- The ML-DSA-65 implementation uses Ed25519 as a same-API development
  stand-in. Production deployment requires the @noble/post-quantum or liboqs
  library. See [CHANGELOG.md](./CHANGELOG.md).

- The genesis root keypair (SLH-DSA-128s) must be moved to cold storage
  (HSM with two-of-three custodian policy) before network launch.

These are documented blocking items in the Command Center, not undisclosed
vulnerabilities.

## Security Hall of Fame

We thank the following researchers for responsible disclosure:

*(None yet: be the first)*

---

*The AI Lab Intelligence Unobscured, Inc.*  
*security@theailab.org*  
*theailab.org/security*
