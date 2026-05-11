# `node/src/schemas/`

Per-tx_type schema modules. Each file is the **single source of truth**
for everything about one tx_type's lifecycle: request envelope, signed
canonical payload, sign/verify primitives, and consensus-replay
verification. One module per (tx_type, signer-role) combination.

Each module owns:

- the request envelope validator (`validateRequest`) — shape gate +
  DAG presence checks (signer + every author) that run before any
  crypto work
- the signer resolver (`resolveSigner`) — looks up the signer's DAG
  identity, rejects on missing / revoked, returns the identity record
  for downstream signature verification
- the canonical field list — no inline arrays scattered across services
  and the commit-handler (that's the drift class behind every
  signature-mismatch bug we've shipped)
- the canonical-payload builder (`buildSigningPayload`) — default-fills,
  reject-on-extra, enum-validates, returns the exact bytes to be signed
- a `sign` helper for clients
- a `verify` helper for verifiers (pure — no DAG access)
- a `verifyTx(tx, dag)` high-level entry the commit-handler calls
  (dispatches on `cna_version`, looks up signer, rebuilds payload,
  re-runs `verify`, checks authors are DAG-resident)

Both the API service and the commit-handler import the same module —
the field list, defaults, and verifier are shared, so they cannot
drift.

## Module convention

Every schema module exports:

```js
module.exports = {
  TX_TYPE:   "REGISTER_CONTENT",                      // the tx_type this schema applies to
  CURRENT_CNA_VERSION: CNA_VERSIONS.REGISTER_CONTENT.current,    // CNA version used at SIGN time
  SUPPORTED_CNA_VERSIONS:                              // whitelist accepted at VERIFY time
    CNA_VERSIONS.REGISTER_CONTENT.versions,            // (see shared/constants.js)

  validateRequest(body, deps): void     // request-envelope shape gate + DAG presence
                                        // checks (signer + every author). Throws
                                        // a structured error on failure. `deps` is
                                        // `{ mediaLimits, dag }` — mediaLimits for
                                        // content-size validation, dag for identity
                                        // lookups.

  resolveSigner(tipId, dag):            // looks up the signer's DAG identity, rejects
    Identity                            // 412 if missing / 403 if revoked. Returns
                                        // the identity record (carries .public_key).
                                        // Caller uses the returned identity to verify
                                        // the signature.

  buildSigningPayload(input, contentHash):     // builds the canonical payload (default-fills,
    Object                              // strips extras, normalises, enforces enums).
                                        // Throws on shape failures.

  sign(payload, privKey): string        // client helper — returns hex signature

  verifySignature(payload, sig, pubKey): bool    // pure signature verifier — given canonical payload, sig, key

  verifyTx(tx, dag):                    // server-side entry: dispatches on tx.data.cna_version
    { ok: true } |                      // (must be in SUPPORTED_CNA_VERSIONS), looks up
    { ok: false, status, error, code }  // signer identity from DAG, rebuilds payload from
                                        // tx.data via buildSigningPayload, checks authors are
                                        // DAG-resident, runs verify(). Used by commit-handler.

  // Additional re-exports — handy for tests and clients that want to
  // reference the spec constants without parsing them out of the canonical
  // payload:
  //   AUTHOR_KEYS      — the 5 keys per `authors[]` entry
  //   ORIGIN_CODES     — the canonical origin enum (OH / AA / AG / MX)
  //   canonicalJson    — re-export of shared/crypto.js#canonicalJson
  //   payloadHashHex   — debug helper that returns the hex digest a
  //                       canonical payload would produce
};
```

The commit-handler's per-tx dispatch becomes:

```js
const schema = require(`../schemas/${SCHEMA_FOR_TX_TYPE[tx.tx_type]}`);
const r = schema.verifyTx(tx, dag);
if (!r.ok) reject(r);
```

The service's per-endpoint flow becomes:

```js
schema.validateRequest(body, { mediaLimits, dag });          // shape + DAG presence
const identity = schema.resolveSigner(body.signer_tip_id, dag);
// recompute server-side hashes…
const payload = schema.buildSigningPayload(body, contentHashFull);   // canonicalise
if (!schema.verifySignature(payload, body.signature, identity.public_key)) {
  throw schemaError(403, "...", "signature_invalid");
}
```

No more inline field arrays per tx type, no more drift between API-time
verification and commit-time re-verification.

## Catalog

| TX_TYPE | Schema | Status | Module | Spec |
|---|---|---|---|---|
| `REGISTER_CONTENT` | CNA-2.2 | ✅ | `schemas/content-register.js` | `docs/CONTENT_SIGNING.md` |
| `REGISTER_IDENTITY` | 9-field canonical (VP sig) | ✅ | `schemas/register-identity.js` | inline header doc + `docs/IDENTITY_SIGNING.md` (TBD) |
| `CONTENT_VERIFIED` | (verifier sig) | ⏳ inline today | — | TBD |
| `UPDATE_ORIGIN` | (author sig) | ⏳ inline today | — | TBD |
| `CONTENT_RETRACTED` | (author sig) | ⏳ inline today | — | TBD |
| `CONTENT_DISPUTED` | (disputer sig) | ⏳ inline today | — | TBD |
| `JURY_VOTE_COMMIT` | (juror sig) | ⏳ inline today | — | TBD |
| `JURY_VOTE_REVEAL` | (juror sig) | ⏳ inline today | — | TBD |
| `APPEAL_FILED` | (appellant sig) | ⏳ inline today | — | TBD |
| `VP_REGISTERED` | (governance VP sig) | ⏳ inline today | — | TBD |
| `NODE_REGISTERED` | (governance VP sig) | ⏳ inline today | — | TBD |
| `REVOKED` | (VP sig) | ⏳ inline today | — | TBD |

The "inline today" sites are catalogued so the migration order is
obvious. Each one's a separate PR — the same shape (validate envelope,
canonicalise, sign-or-verify, dispatch from commit-handler) — but
standalone units of work.

## Why the convention

Every signature-failure bug we've fixed in the past ~6 weeks (the
`registered_url`, `creator_name`, `evidence_hash`, `claimed_origin`
mismatches) had the same root cause: a field-list array hand-mirrored
in two places, edited in one, forgotten in the other. Centralising the
schema in one module — service and commit-handler both reading from it
— makes that class of bug structurally impossible.

Adding a field to a schema = edit one module = both verifiers pick it
up automatically.

## Versioning

The CNA-version whitelist + current is the **single source of truth**,
declared in `shared/constants.js#CNA_VERSIONS`:

```js
CNA_VERSIONS.REGISTER_CONTENT = {
  versions: ["CNA-2.2"],     // accepted at verification time (whitelist)
  current:  "CNA-2.2",       // signed under for new submissions
};
```

**Two rules, two roles:**

- **Submissions** sign under `current`. The canonical builder forces this
  string into the signed payload's `cna` field; clients cannot pick a
  different one.
- **Verification** accepts any value in `versions`. Historical txs (signed
  under earlier CNA versions) keep verifying after a bump — that's
  what makes consensus replay deterministic across releases.

The schema module re-exports both as `CURRENT_CNA_VERSION` (= `current`) and
`SUPPORTED_CNA_VERSIONS` (= `versions`), so callers don't reach into
`shared/constants` directly.

CNA is the **Canonical Content Normalization Algorithm** — the function
that turns raw content bytes into the canonical bytes hashed into
`content_hash`. The `cna` field declares which CNA version was used.
Reference implementation of the current CNA version lives in
`shared/crypto.js#tipNormalize`. See `docs/CONTENT_SIGNING.md` §1 for
the full description.

**Adding a new CNA version (e.g. `CNA-2.3`):**

1. Append `"CNA-2.3"` to `versions`, set `current: "CNA-2.3"` in
   `shared/constants.js`. The whole codebase picks up the new whitelist
   immediately (no edits to `tx-validator.js`, `verifyTx`, or service code).
2. Implement the new CNA normalization function in `shared/crypto.js`
   (alongside or replacing `tipNormalize`).
3. If the new CNA version also changes the signed-payload shape (adds /
   removes fields), write a per-version `buildSigningPayloadV23` in the schema
   module and a dispatch table mapping `cna_version` → builder.
   `verifyTx` reads `tx.data.cna_version` and replays under the matching
   builder so existing txs keep verifying. If the shape doesn't change,
   this step isn't needed.
4. Add a frozen test-vector for the new version (raw content +
   canonical-JSON string + signature + pub-key + expected hash). Keep
   the old version's test vector in the repo forever — it's the
   regression guard that proves we didn't break replay of historical
   content.

Steps 2-4 are concrete work for the day the bump happens; today, with
only one CNA version, the codebase is intentionally minimal.

**Committed-tx invariant:** the bytes in `tx.data` for a committed tx are
permanent. Re-verification picks the right CNA implementation (and, if
shape changed, the right builder) by reading `data.cna_version`, so a
node running the latest binary still verifies content signed under
earlier CNA versions.

The version tag must be inside the signed payload (so it's bound to the
signature) and replicated at the top of `tx.data` (so the commit-handler
can dispatch without recomputing). See `schemas/content-register.js` for
the canonical example.
