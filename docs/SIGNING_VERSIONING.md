# Transaction Signing Evolution Policy

How the canonical *signed* bytes of a transaction may change over time, and the
discipline that keeps every historical signature verifiable forever.

See also: [CRYPTOGRAPHY.md](./CRYPTOGRAPHY.md) (algorithms, `tx_id` derivation),
[CONTENT_SIGNING.md](./CONTENT_SIGNING.md) (the CNA content-register payload).

## TL;DR

- A signature commits to *specific bytes*. To verify an old tx, every node must
  reproduce the exact bytes that were signed. The chain replays from genesis, so
  a recipe change that alters those bytes breaks the whole history, not just new
  txs.
- **Iron rule:** never mutate or delete a tx type's signed-payload recipe. Only
  ADD.
- **Add a field:** append it to the recipe's `optional` set. The strip rule omits
  absent fields, so old txs keep their original bytes.
- **Breaking change** (remove / rename / re-encode / reorder a field): mint a NEW
  `tx_type`. The old type keeps its old recipe.
- We deliberately do **not** use a per-tx `sig_version` field or a signer-supplied
  `signed_fields` column. Rationale below.
- A golden-vector test freezes the canonical bytes so CI fails the instant a live
  recipe changes.

## The recipe

Each tx type's signed payload is built by one `buildSigningPayload(data)` function,
in `node/src/schemas/_registry.js` (registry-resolved types) or the type's
`node/src/schemas/<type>.js` module. There is exactly ONE builder per type, used
at both sign-time and verify-time, so the API service and the consensus verifier
cannot drift apart. This closed a confirmed production bug class (signed-field
lists that were hand-maintained in two places and silently diverged).

The canonical signed bytes are:

```
canonicalJson(buildSigningPayload(data))   then   SHAKE-256
```

`canonicalJson` sorts object keys, so field *order* in the builder is irrelevant
to the bytes; the field *set* and their *values* are what matter.

## The strip rule

`buildSignedPayload(data, { required, optional })` in `shared/crypto.js` is the
shared helper every recipe should route through:

- `required` fields: throw if missing/`null` (you cannot accidentally sign a short
  payload).
- `optional` fields: included only when not `undefined` and not `null`.
- `""`, `0`, `false` are kept (intentional values, not absence).

The omit-absent behavior is the entire forward-compatibility mechanism: an absent
optional field contributes zero bytes, so adding one never changes the bytes of a
tx that does not carry it. This is the same model Protocol Buffers uses for
additive evolution.

## How a recipe may evolve

| Change | Mechanism | Effect on old txs |
|---|---|---|
| Add a field | append to `optional` | none, bytes unchanged (absent field is stripped) |
| Make an optional field required | new `tx_type` | breaking, old txs lacked it |
| Remove / rename / re-encode / reorder | new `tx_type` | breaking, old recipe stays for the old type |

Minting a new `tx_type` for breaking changes mirrors how Bitcoin and Ethereum
evolve transaction formats: the version rides on the transaction's identity, and
every old version's verifier is retained indefinitely.

## Why not a `sig_version` field

A per-tx `sig_version` would only enable in-place breaking changes within a single
`tx_type`, which is strictly worse than a clean new type: the old and new payloads
would share one name and one code path, exactly the condition that produces silent
drift. Additive changes are already handled by the strip rule. So `sig_version`
buys nothing we want and reintroduces the risk we are avoiding. We do not add it.

Cosignatures are versioned implicitly by their transaction: every cosigned tx in
this protocol is assembled and submitted in one shot (LINK_PLATFORM collects
cosigs off-chain then submits; COMMITTEE_ROTATION aggregates 2f+1 node sigs then
submits), so all cosigs in a tx are always the same vintage. No per-cosig version
is needed.

## Why not a `signed_fields` column

Storing the field list on the transaction would let the *signer* choose which
fields the signature covers. An attacker holding a valid key could shrink it (for
example `signed_fields: ["tx_type"]`), sign a near-empty payload, and let the
commit handler apply the full `data`, a privilege-escalation hole (the
revoke-a-victim scenario). Plugging it would require a per-type
`MIN_REQUIRED_SIGNED_FIELDS` gate checked before the crypto step.

Our recipe lives in CODE, keyed by `tx_type`, so the signer cannot pick it and
there is nothing to gate. The one capability a `signed_fields` column would add,
letting an external auditor rebuild canonical bytes without our code, is better
served by publishing the recipe list as a versioned static spec artifact than by a
signer-controlled per-tx field.

## Cosignatures stay in `tx.data`

Conceptually cosignatures are signatures, not application data, so they do not
"belong" in `data`. But they are already covered by `tx_id` (which hashes the full
canonical tx including `data`) and their recipe already lives in code, so moving
them to a dedicated envelope column is pure cleanliness with zero correctness or
security gain, while touching the consensus hashing path (`canonicalTx` / `tx_id`),
the commit handler, snapshot install, and the SQL mirror. It is not worth the risk
before production. If ever done, it is a fork-window-only change: it alters the
`tx_id` bytes of every cosigned tx.

## Enforcement: the golden-vector freeze test

`node/tests/signing-canonical-vectors.test.js` pins
`canonicalJson(buildSigningPayload(sample))` for every body-scope registry tx type
against frozen bytes in `node/tests/fixtures/signing-canonical-vectors.json`. Any
edit that changes a live recipe's field set, key order, or strip behavior fails
CI, the exact change class that would break verification of already-signed
transactions. The suite also asserts that every body-scope registry type HAS a
vector, so a newly added recipe cannot ship unprotected.

To intentionally (re)freeze after an APPROVED change:

1. Edit `CASES` in `node/scripts/gen-signing-canonical-vectors.js`.
2. Run `node node/scripts/gen-signing-canonical-vectors.js`.
3. Review the JSON diff. A changed `canonical` string on an EXISTING case means a
   break in historical verification, and it must be deliberate (an additive field,
   or a new `tx_type`), never an accident.

## Coverage status

- Freeze test, fixture, and regen script: in place. Vectors cover all body-scope
  registry tx types, including with/without-optional variants that lock the strip
  rule.
- Six registry recipes are normalized to `buildSignedPayload` (CONTENT_VERIFIED,
  UPDATE_ORIGIN, CONTENT_RETRACTED, JURY_VOTE_COMMIT, APPEAL_FILED user-mode,
  UNBIND_DOMAIN), proven byte-identical by the freeze test staying green.
- Pending (already frozen, so safe to defer): VP_REGISTERED and NODE_REGISTERED
  carry an `algorithm ?? "ml-dsa-65"` default the strip helper cannot express
  inline; and the schema-module recipes need per-type input fixtures before the
  freeze test can extend to them.
