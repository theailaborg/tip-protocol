# Agentic provenance on TIP primitives

A small, runnable reference for one question TIP's content provenance does not
answer on its own: when an AI agent acts on someone else's system, **which agent
acted, on whose authority, and what exactly did it do?**

The demo answers all three with signed records that anyone can check using
public keys. It reuses TIP's existing primitives and conventions. It does not
change the DAG, the transaction format, trust scoring or consensus, so it sits
outside the RFC process. A protocol-level version would go through an RFC.

## The flow

```
 Principal (TIP-ID)                    Agent                         Site (TIP-ID)
 ──────────────────                    ─────                         ─────────────
 signs a delegation  ───────────────▶  may sub-delegate a
 (agent key, scope,                    narrower scope
  validity window)                          │
                                            ▼
                                       signs a request:            checks, in order:
                                       action, resource,   ─────▶  signature, freshness,
                                       exact content hash,         replay, chain to the
                                       base hash, nonce            principal's registered
                                                                   key, scope, revocation,
                                                                   delivered bytes, base
                                                                            │
                                                                            ▼
                                                                   signs a receipt for every
                                                                   decision (commit or refusal),
                                                                   appends it to a Merkle log,
                                                                   signs a log checkpoint
                                                                            │
 Anyone ◀───────────────── evidence bundle (request, chain, receipt, proof, checkpoint)
 re-derives authority from the signed chain and checks the receipt is in the log.
```

| Question | Answered by |
|---|---|
| Which agent acted? | The request is signed by the agent's ML-DSA-65 key, and the chain's last link names that exact key. |
| On whose authority? | Each delegation is signed by the key above it, ending at a TIP-ID whose registered key must match. Sub-delegations can only narrow scope and time. |
| What did it do? | The agent signs the exact content hash before acting. The site signs a receipt with before and after hashes, logged under a signed Merkle checkpoint. |

## What it reuses from TIP

| TIP convention | Where in this repo | Used here for |
|---|---|---|
| ML-DSA-65 (FIPS 204), 1952-byte keys, 3309-byte signatures | `shared/crypto.js` | every signature |
| SHAKE-256 | `shared/crypto.js` | ids, content hashes, log |
| `canonicalJson` (sorted keys, compact) and `signBody` (sign the SHAKE-256 of the canonical JSON) | `shared/crypto.js` | record ids and signatures |
| TIP-ID derivation `tip://id/<REGION>-<hash16>` | `generateTIPID` | principals and the site |
| Merkle construction (`L`/`N` prefixes, odd node promoted) | `shared/merkle.js` | the receipt log |

`verify_with_tip.js` checks the Python-produced records with TIP's own Node
functions, so the two implementations can be compared directly.

## Run it

Python 3.11+ and a `cryptography` release with ML-DSA support (tested with 50.0.1).

```bash
cd examples/agentic-provenance
python -m pip install "cryptography>=50" pytest
python -m pytest -q                 # 32 tests
python demo.py --export out/        # narrated run, writes evidence bundles
```

Cross-check with TIP's Node implementation (from the repository root, after `npm install`):

```bash
node examples/agentic-provenance/verify_with_tip.js examples/agentic-provenance/out/valid_edit.json
node examples/agentic-provenance/verify_with_tip.js examples/agentic-provenance/out/tampered_receipt.json   # expected to fail
```

## What the tests cover

| Area | Cases |
|---|---|
| Identity | another organisation signing authority in a principal's name; a stolen chain used with a different key; a forged request signature; a principal with no TIP identity record |
| Authority | action outside scope; resource stretched by string prefix; sub-agent widening its own scope; sub-delegation from a key never delegated to; sub-delegation outliving its parent; repeated link (cycle); expiry; revocation by the principal; revocation by an unrelated party (ignored); revocation after the action (history stands) |
| Activity | one-character content substitution; replay; stale or future-dated request; edit based on an outdated read |
| Record | edited receipt; receipt paired with another request; receipt missing from the log; checkpoint signed by another key; a site committing an action the chain does not authorise; missing delegation (indeterminate, not valid); content that differs from the commit; inclusion proofs across a longer log |
| Conformance | canonical JSON rules including UTF-16 key order; Merkle construction and the duplicated-leaf case; key and signature sizes; TIP-ID format |

Each safety check was also removed one at a time to confirm that at least one test fails without it.

## Design notes

**Exact bytes, not the CNA-2 fingerprint.** CNA-2 normalises text so a published
post still matches its registered draft. It lower-cases and keeps only letters,
numbers and marks, so `balance=+100` and `balance=-100` share a CNA-2 hash.
That is correct for content matching and wrong for authorising an action, so
requests commit to the SHAKE-256 of the exact bytes. The CNA-2 hash can still
link the result to a TIP content record. See also #327 (CNA-3).

**The verifier does not take the site's word.** Authority is re-derived from
the signed chain. A receipt that says "committed" for an action the chain does
not allow is reported as invalid, which makes the receiving side accountable too.

**Refusals are evidence.** Every decision, including refusals, is signed and
logged, so attempted impersonation leaves a record.

**Invalid is not the same as indeterminate.** Missing evidence (an absent
delegation, an unknown identity) gives `indeterminate`, never `valid`.

**Revocation is judged at the time of the action.** A revocation counts when it
is signed by the issuer of the revoked link or of any link above it. Revoking
later stops new actions and leaves earlier receipts valid.

## Limits

- The identity directory is in memory. In production it is the TIP identity record for each TIP-ID.
- `decided_at` comes from the site's clock. Anchoring checkpoint roots in TIP would give the log an external timestamp. This demo does not write to a TIP node.
- A site could withhold a receipt. Agents keeping their own receipts and anchored checkpoints narrow that gap; they do not close it.
- A stolen agent key works until it is revoked or the delegation expires. Short validity windows limit the damage.
- `tip-agent:` identifiers are illustrative. An agent namespace in TIP URIs would be an RFC decision.
- Timing printed by `demo.py` is one machine, one thread, and re-signs the checkpoint on every receipt. It is indicative only.

## Possible next steps

1. Anchor each site's checkpoint roots under its TIP-ID, so log history is publicly timestamped.
2. Run the same evidence contract against one real workflow with a TIP sandbox.
3. If useful to the maintainers, an RFC for delegation and revocation records as TIP transaction types, with Node and Python reference implementations.

License: TIPCL-1.0, see [LICENSE.txt](../../LICENSE.txt).
