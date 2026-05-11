# TIP Protocol — Content Signing Specification

**CNA version (current):** `CNA-2.2` — applied to content before hashing into `content_hash`. See §1.
**Status:** Canonical. Every client that registers content on a TIP node MUST follow this spec.
**Audience:** Integrators building any client that submits content to a TIP node — browser extensions, WordPress / Ghost / Substack plugins, mobile apps, CLI tools.

## TL;DR

To register content, a client (a) runs the content bytes through the current CNA (Canonical Content Normalization Algorithm) version to produce `content_hash`, (b) wraps that hash and a few related fields into a fixed 8-field canonical payload, (c) signs the payload with their ML-DSA-65 private key, and (d) submits the payload + signature + the raw content to `POST /v1/content/register`. The server reproduces step (a) with the same CNA version, rebuilds (b), looks up the signer's public key from the DAG identity record, and verifies the signature. Same canonical-JSON rules everywhere; no per-client variations; no fallback.

---

## 1. CNA — Canonical Content Normalization Algorithm

**CNA is the algorithm that turns raw content bytes into the canonical bytes hashed into `content_hash`.** It evolves over time; today the current version is **CNA-2.2**. Earlier versions (CNA-1 was the original six-step normalization described in TIP patent §2) have been refined into the current implementation.

What CNA-2.2 does, end-to-end:

1. Unicode NFC normalization
2. Strip all HTML / XML tags
3. Remove all HTML entities
4. Remove all Markdown syntax
5. Remove all whitespace and punctuation
6. Strip platform-specific encoding artifacts
7. Strip syndication reformatting
8. Encode the result as UTF-8 bytes

Hash those bytes with SHAKE-256 (32-byte output, lowercase hex) → that's `content_hash`. Reference implementation: `shared/crypto.js#tipNormalize()`.

The signed canonical payload (§2) carries a `cna_version` field that declares which CNA version was used to produce `content_hash`. The verifier reads `cna_version`, applies the matching CNA implementation to the raw content the client sent in the HTTP envelope, and compares the recomputed hash to `content_hash`. Mismatch → signature rejected.

Supported CNA versions are tracked in `shared/constants.js#CNA_VERSIONS.REGISTER_CONTENT`:

- `versions: ["CNA-2.2"]` — every CNA version ever released. Verification accepts any of these so historical content keeps verifying after a CNA bump (replay correctness).
- `current: "CNA-2.2"` — the CNA version new submissions are signed under. The canonical-payload builder forces this string into the signed payload's `cna_version` field; clients can't pick a different one.

When CNA-2.3 ships, both halves of the algorithm and the signed-payload shape (if it changes) move together under the new version tag — see §13.

## 1A. Identity prerequisite

Every signer's TIP-ID MUST be registered on the DAG before they can submit content. The protocol does **not** accept content from signers whose identities are not on the DAG. If your client is hitting a 412 on `POST /v1/content/register`, the upstream identity-issuance flow (your VP) hasn't propagated the identity to the DAG yet.

The signer's TIP-ID is referenced by the canonical payload's `signer_tip_id` field; the verifier looks up that TIP-ID's public key on the DAG and verifies the submitted signature against it.

---

## 2. The signed canonical payload

Exactly 8 top-level fields, in this exact set, every field always present (defaults filled when absent). Object keys are sorted ASCII-ascending (recursively) at canonicalisation time — clients can build the object in any insertion order; the canonical-JSON encoder normalises.

| # | Field | Type | Required? | Default when absent | Notes |
|---|---|---|---|---|---|
| 1 | `attribution_mode` | string | no | `"self"` | What relationship the signer has to the bylined authors. Locked enum: `"self"` / `"employed"` / `"hosted"`. See §6. |
| 2 | `authors` | array | yes | — must have ≥1 entry | Ordered byline. Index 0 = primary byline. Each entry is a 5-key object — see §5. |
| 3 | `cna_version` | string | yes | — | The **CNA version used to produce `content_hash`**. Currently submissions sign under `"CNA-2.2"`; verification accepts any value in `CNA_VERSIONS.REGISTER_CONTENT.versions`. See §1. |
| 4 | `content_hash` | string | yes (no default) | — | Lowercase 64-char hex of `SHAKE-256(CNA-applied content, 32)`, where CNA-applied means: run the content through the CNA version named in field `cna_version` above, encode UTF-8, hash. See §7. |
| 5 | `extras` | object | no | `{}` | Open extension point — see §8. |
| 6 | `origin_code` | string | yes (no default) | — | One of `"OH"` / `"AA"` / `"AG"` / `"MX"`. Always uppercase in the signed payload — clients sending lowercase get rejected. |
| 7 | `registered_urls` | array | no | `[]` | URLs where the content is published. **Index 0 is the canonical / primary URL**; later entries are mirrors / syndications. Order is signed. See §9. |
| 8 | `signer_tip_id` | string | yes (no default) | — | The TIP-ID whose private key produced the signature. The verifier uses this to look up the public key on the DAG. |

**Field shape, always present, deterministic.** Empty values use explicit defaults (`{}`, `[]`, `"self"`). Fields are NEVER dropped from the canonical payload — that's what makes the same logical content produce byte-identical signed bytes regardless of which client built the payload.

**Reject-on-extra.** The canonical builder picks exactly these 8 fields and ignores anything else the client puts at the top level. Garbage fields don't get signed; clients can't bloat the canonical JSON with attacker-controlled junk.

**Removed: `signer_type`.** Earlier drafts of CNA-2.2 included a 9th field, `signer_type` (`"personal"` / `"publisher"`). It was dropped because the signer's type is a property of their TIP-ID, persisted on the DAG identity record (see Protocol/Shared issue tracking `tip_id_type` on identities). Asserting the type per-message duplicated that field, and a single TIP-ID never legitimately signs in two roles — the verifier resolves role from the DAG identity at verify time, not from the signed payload. Clients MUST NOT send `signer_type` in the canonical payload; if they do, it will be dropped at canonicalisation (reject-on-extra applies). The auxiliary HTTP body may still carry it as informational metadata, but it is not signed and not verified.

---

## 3. Canonical-JSON encoding

Signing requires byte-identical canonical encoding across every client implementation. The rules:

1. **Object keys sorted ASCII-ascending, recursively.** Build order doesn't matter; the encoder sorts.
2. **No whitespace** between tokens.
3. **Forward slashes NOT escaped** (i.e. `https://example.com/` stays as-is, NOT `https:\/\/example.com\/`). PHP clients must use `JSON_UNESCAPED_SLASHES`.
4. **UTF-8 passthrough for non-ASCII.** Characters like `é` emit as the UTF-8 bytes, NOT as `é`. PHP clients must use `JSON_UNESCAPED_UNICODE`.
5. **Standard JSON escapes for control chars and `"`/`\`** only.
6. **Empty objects emit as `{}`** (not `[]`, not `null`). PHP clients converting from associative arrays must cast to object before encoding when the array is empty (`json_encode((object)[], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)`).
7. **Empty arrays emit as `[]`.**
8. **Numbers, booleans, null** use their natural JSON representation.
9. **Strings** preserve their original UTF-8 byte sequence — no normalisation, no case folding.

Reference implementations:
- **Node.js**: `shared/crypto.js#canonicalJson()` (TIP node).
- **PHP**: see WordPress plugin's `canonical_json()` helper. Must use `json_encode($obj, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)` after recursive ksort, and convert empty arrays to `(object)[]` before encoding.
- **Python**: `json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False)` plus pre-pass to convert empty dicts to `{}` (Python defaults are mostly correct).

---

## 4. Signing math

Given the canonical payload above:

```
canonical_bytes  = canonical_json(payload).encode("utf-8")              // bytes
payload_hash_hex = SHAKE-256(canonical_bytes, output_bytes=32).hex()    // 64 lowercase hex chars
signing_message  = payload_hash_hex.encode("ascii")                     // 64 BYTES — the hex STRING, not the 32 raw digest bytes
signature        = ML_DSA_65.sign(private_key, signing_message)         // 3309 bytes
signature_hex    = signature.hex()                                      // 6618 hex chars
```

**Critical:** the message ML-DSA signs is the **64 ASCII bytes of the hex string**, not the 32 raw hash bytes. This is the most common implementation mistake for new clients — if your test fixture verifies locally but the node rejects, this is the first thing to check.

**Algorithm:** ML-DSA-65 (FIPS 204). Not ML-DSA-44 or 87.
**Hash:** SHAKE-256 with 32-byte output (FIPS 202). Not SHA-256, not SHA-3-256.
**Public key wire format:** raw ML-DSA-65 public key, hex-encoded lowercase. 1952 bytes → 3904 hex chars. NOT PEM, NOT DER, NOT base64.

---

## 5. The `authors[]` array

Ordered byline. Index 0 is the primary byline. Each entry is exactly 5 keys, no extras (the canonical builder strips anything else):

| Key | Type | Required? | Default when absent |
|---|---|---|---|
| `key_mode` | string | no | `"attribution"` |
| `role` | string | no | `"contributor"` |
| `signed` | boolean | no | `false` |
| `tip_id` | string | yes | — |
| `tip_id_type` | string | no | `"personal"` |

Constraints:
- The array MUST have at least one entry. If the signer is also the only author (typical self-published case), put a single entry whose `tip_id` matches `signer_tip_id`.
- `key_mode` values: `"attribution"` (default — the author is credited but didn't sign separately) and `"co_signed"` (the author also produced their own signature, carried in the request envelope's `co_signatures[]` — see §10).
- `role` values: `"byline"` (visible byline), `"contributor"` (named contributor not in the byline), `"editor"`, `"translator"`. Free-form for now; UIs render whatever's there.
- `signed` MUST be `true` if and only if a corresponding co-signature is present in the envelope.
- `tip_id_type`: `"personal"` or `"publisher"`. Mirrors the (forthcoming) `tip_id_type` column on the identity row — this is the per-author assertion of role, signed at byline granularity.

---

## 6. `attribution_mode`

The signer's relationship to the bylined authors. **Locked enum** — `buildSigningPayload` rejects any value not in this set with `attribution_mode_invalid`:

| Value | Use case |
|---|---|
| `"self"` (default) | Signer IS one of the authors. Typical personal-creator submission. `signer_tip_id` MUST match `authors[i].tip_id` for some `i`. |
| `"employed"` | Signer is publishing on behalf of one or more authors under an employer / agency relationship (e.g. a newsroom publishing reporter byline). `signer_tip_id` is the publisher / org; `authors[]` lists the human bylines. |
| `"hosted"` | Signer is a platform / host publishing third-party content the platform itself doesn't claim authorship of. `signer_tip_id` is the platform; `authors[]` lists the contributors. |

Enum values come from `shared/constants.js#ATTRIBUTION_MODES` (`ATTRIBUTION_MODE_VALUES` for the frozen array used at validation time). Adding a new mode is a coordinated change — schema bump + client coordination.

Today `"self"` is the value all production clients send. `"employed"` and `"hosted"` unblock publisher / platform flows when the corresponding TIP-ID types (publisher) and signing relationships ship.

---

## 7. `content_hash`

Lowercase 64-char hex of `SHAKE-256(CNA_VERSION(content), 32)`, where `CNA_VERSION` is the CNA version declared in the signed payload's `cna_version` field (§1). Apply the steps for that CNA version, encode UTF-8, hash with SHAKE-256 to 32 bytes.

- **Text content** (today's only path in production): `shared/crypto.js#tipNormalize()` implements CNA-2.2. Run the 8 normalization steps, UTF-8 encode, SHAKE-256 → 32 bytes → 64 lowercase hex.
- **Mixed media (text + image / video / audio):** `content_hash = SHAKE-256(media_canonical_hash || text_hash, 32).hex()` — the media hash is concatenated with the text hash before the final SHAKE round. The client sends `media_canonical_hash` in the auxiliary HTTP envelope; the server combines and re-verifies.

The server recomputes the content hash from the content bytes the client sends in the request envelope using the CNA version named in `cna_version`, then matches against the `content_hash` in the signed payload. Mismatch is a signature failure (the canonical payload didn't bind to the content the client claimed to sign).

---

## 8. `extras`

Open extension point. Clients put data they want bound to the signature but the protocol doesn't enforce. Examples:

```json
"extras": {
  "wordpress_post_id": 1234,
  "doi": "10.1000/foo.bar",
  "language": "en",
  "tags": ["politics", "news"]
}
```

Or `{}` when empty (always present, never omitted, never `null`).

Anything in `extras` is signed — the canonical-JSON encoder includes it byte-for-byte. Clients that put data here commit to it cryptographically; the server ignores it for protocol logic but stores it on the tx for downstream consumers (e.g. the WordPress plugin can later read back its own `wordpress_post_id` and confirm the binding).

`extras` keys MUST be JSON-safe (no nested undefined, no functions, no circular references).

---

## 9. `registered_urls`

Array of URLs where the content is published. Always present.

**Order is significant. Index 0 is the canonical / primary URL** — the publisher's primary domain or the original place of publication. Subsequent entries are mirrors / syndications, in no particular order.

```json
"registered_urls": []                                          // not yet published
"registered_urls": ["https://example.com/post/"]               // single URL — canonical only
"registered_urls": ["https://example.com/post/",               // canonical (publisher's primary)
                    "https://medium.com/@x/post"]              // syndication / mirror
"registered_urls": ["https://example.com/post/",               // canonical
                    "https://medium.com/@x/post",              // mirror
                    "https://substack.com/p/post"]             // mirror
```

Each URL MUST:
- be HTTP or HTTPS (no `ftp://`, `file://`, etc.)
- be a single full URL string (the canonical encoder doesn't escape slashes, so the URL appears verbatim in the signed payload)

**Order is signed.** The canonical-JSON encoder preserves array order (it sorts object keys, not array elements). Reordering the array after signing breaks the signature. This is what makes the "index 0 = canonical" rule cryptographically enforceable rather than a convention readers have to trust.

**Why we don't have a separate `canonical_url` field:**
- The signature already binds the order, so a separate field would be redundant data committing to the same fact.
- One field = one source of truth = no consistency risk between two related fields drifting.
- API consumers that want only the canonical can read `registered_urls[0]`; consumers that want all URLs read the whole array. No spec branching.

**Domain binding** (the future `/v1/domain/{domain}` endpoint) operates against `registered_urls[0]`'s host: the content is "publisher-attested" only if the canonical URL's domain has a verified binding to the signer's TIP-ID. Mirror URLs at index ≥ 1 are not subject to publisher attestation — they're syndication metadata, not original-publishing claims.

**Adding a mirror after registration** is a future feature (a separate `CONTENT_URL_ADDED` tx type). The original signed registration commits only to the URLs known at sign time. Mirrors that didn't exist when the content was registered can be appended later under a separate signature without invalidating the original.

---

## 10. The request envelope

The signed payload is the cryptographic core. The HTTP request body that the client POSTs to `/v1/content/register` MUST carry:

1. **All 8 canonical signed fields** — exact same values that went into the signed canonical JSON. The server picks these 8 fields from the body and rebuilds the canonical payload byte-for-byte to verify the signature.
2. **A small set of auxiliary fields** the server needs but that aren't part of the signed payload (content bytes, content type, the signature itself, co-signatures).

**Rule:** the HTTP body MUST mirror the canonical signed payload — do not rely on the server's default-fill for optional fields. The server's defaults happen to match canonical defaults today (`attribution_mode: "self"`, `extras: {}`, `registered_urls: []`), but that coincidence is a fragile coupling: the day a client signs a *non-default* value but omits it from the HTTP body, signatures break silently because the server re-fills with its default and the canonical JSON diverges. Send everything you signed.

Request body shape:

```json
{
  "comment": "All 8 fields below mirror the signed canonical payload. Same bytes, same values.",
  "attribution_mode": "self",
  "authors": [{ "key_mode": "attribution", "role": "byline", "signed": false,
                 "tip_id": "tip://id/US-...", "tip_id_type": "personal" }],
  "cna_version": "CNA-2.2",
  "content_hash": "<64-hex>",
  "extras": {},
  "origin_code": "OH",
  "registered_urls": ["https://example.com/post/"],
  "signer_tip_id": "tip://id/US-...",

  "comment2": "Auxiliary fields — NOT in the signed payload.",
  "content":         "<full content text or media manifest>",
  "content_type":    "text",
  "perceptual_hash": "<dHash hex, optional>",
  "signature":       "<6618-hex ML-DSA-65 sig>",
  "co_signatures":   []
}
```

Auxiliary fields:

| Field | Required? | Notes |
|---|---|---|
| `content` | yes (or `media_canonical_hash`) | Full content bytes the server hashes to produce the canonical content hash and verify against `content_hash`. |
| `content_type` | yes | One of `"text"` / `"image"` / `"video"` / `"audio"`. |
| `perceptual_hash` | no | dHash for similarity search. Informational; not bound to authorship. |
| `signature` | yes | The ML-DSA-65 signature from §4. |
| `co_signatures` | no | Array of `{ tip_id, signature }` per author entry that has `signed: true`. Each co-signature signs the SAME canonical payload as the primary signature, with the contributor's private key. |

**Do NOT send these on the wire:**

- `public_key` — server resolves the signer's public key from the DAG identity record (§1C). Clients that ship a `public_key` field have it ignored. If your TIP-ID isn't on the DAG, the registration returns `412 signer_not_registered`; talk to your VP.
- `signer_type` — removed from the spec (§2 "Removed" paragraph). Even if sent, it gets stripped at canonicalisation and is not signed / not stored.
- `author_tip_id` — legacy field from earlier drafts. The canonical signed field is `signer_tip_id`. Sending `author_tip_id` does not satisfy the schema; the server requires `signer_tip_id`.
- `registered_url` (singular string) — replaced by `registered_urls` (plural array). Singular form is rejected.

**Authors must all be DAG-resident.** Every `authors[i].tip_id` MUST exist on the DAG at submission time, just like `signer_tip_id`. An off-DAG author entry returns `412 author_not_registered` with the offending TIP-ID in the error message. This applies at both API admission and consensus replay — same predicate, same failure mode in both places.

---

## 11. Server-side verification

The TIP node performs the following on every incoming `POST /v1/content/register`:

1. **Envelope validation** (`schemas/content-register#validateRequest`) — body shape: `signer_tip_id` format, `origin_code` in enum, `signature` non-empty, content / media XOR, content-size limits, `authors[]` non-empty + each entry has a `tip://id/...` `tip_id`. Bad shape → `400`.
2. **Signer DAG presence** (`schemas/content-register#resolveSigner`) — `dag.getIdentity(signer_tip_id)`. Missing → `412 signer_not_registered`. Revoked → `403 signer_revoked`.
3. **Authors DAG presence** (`schemas/content-register#_checkAuthorsRegistered`) — every `authors[i].tip_id` must be on the DAG. Missing → `412 author_not_registered` with the offending TIP-ID in the error.
4. **Content hash verification** — recompute `SHAKE-256(CNA-1(content), 32)` over the canonical content bytes; compare to `body.content_hash`. Mismatch → `400 content_hash_mismatch`.
5. **Canonical payload reconstruction** (`schemas/content-register#buildSigningPayload`) — pick the 8 signed fields from the body, normalise (uppercase `origin_code`, default-fill optional fields, normalise each author entry to exactly 5 keys, validate `attribution_mode` against the enum), build the canonical JSON.
6. **Signature verification** — `ML_DSA_65.verify(dag_identity.public_key, ASCII(SHAKE256(canonical).hex()), signature)`. Mismatch → `403 signature_invalid`.
7. **Co-signature verification** — for each `authors[i]` with `signed: true`, find the matching entry in `co_signatures[]`, look up that author's public key on the DAG, verify the co-signature against the SAME canonical payload. Any failure → `403`.
8. **CTID uniqueness** — the derived CTID (origin + content_hash prefix + signer suffix) must not already exist. Conflict → `409 ctid_already_registered`.
9. **Submit to consensus** — assemble the `REGISTER_CONTENT` tx, push to mempool. Response: `202 proposed` with the `tx_id` and CTID.

**Consensus-replay symmetry.** Steps 2, 3, 5, 6 run a SECOND time inside the consensus commit-handler when the tx commits, via `schemas/content-register#verifyTx`. Same predicates, same canonical-payload builder, same DAG lookups. Any tx that fails replay at commit time is recorded in `tx_rejections` with the matching error code. The shared schema module means API-time and commit-time can NEVER drift.

---

## 12. Worked example

**Step 1 — content + canonical content hash.**
Content: `Hello from a TIP-Protocol publisher.`
Canonical content bytes (after `tipNormalize`): same string.
`content_hash = SHAKE-256("Hello from a TIP-Protocol publisher.", 32).hex()` → (some 64-hex value, deterministic for those bytes).

**Step 2 — build the 8-field signed payload.**

```json
{
  "attribution_mode": "self",
  "authors": [
    {
      "key_mode": "attribution",
      "role": "byline",
      "signed": false,
      "tip_id": "tip://id/US-a1b2c3d4e5f6a7b8",
      "tip_id_type": "personal"
    }
  ],
  "cna_version": "CNA-2.2",
  "content_hash": "<64-hex from step 1>",
  "extras": {},
  "origin_code": "OH",
  "registered_urls": ["https://example.com/hello/"],
  "signer_tip_id": "tip://id/US-a1b2c3d4e5f6a7b8"
}
```

**Step 3 — canonical JSON.**

```
{"attribution_mode":"self","authors":[{"key_mode":"attribution","role":"byline","signed":false,"tip_id":"tip://id/US-a1b2c3d4e5f6a7b8","tip_id_type":"personal"}],"cna_version":"CNA-2.2","content_hash":"<64-hex>","extras":{},"origin_code":"OH","registered_urls":["https://example.com/hello/"],"signer_tip_id":"tip://id/US-a1b2c3d4e5f6a7b8"}
```

(All on one line, no whitespace, slashes unescaped, UTF-8 passthrough. Note `"extras":{}` and `"registered_urls":["..."]` — empty defaults visible.)

**Step 4 — payload hash.**
`payload_hash_hex = SHAKE-256(canonical_bytes, 32).hex()` → 64 lowercase hex chars.

**Step 5 — sign.**
`signing_message = ASCII(payload_hash_hex)` → 64 bytes.
`signature = ML_DSA_65.sign(privKey, signing_message)` → 3309 bytes.
`signature_hex = signature.hex()` → 6618 hex chars.

**Step 6 — submit.**

```http
POST /v1/content/register
Content-Type: application/json

{
  "attribution_mode": "self",
  "authors": [{ "key_mode": "attribution", "role": "byline", "signed": false,
                 "tip_id": "tip://id/US-a1b2c3d4e5f6a7b8", "tip_id_type": "personal" }],
  "cna_version": "CNA-2.2",
  "content_hash": "<64-hex>",
  "extras": {},
  "origin_code": "OH",
  "registered_urls": ["https://example.com/hello/"],
  "signer_tip_id": "tip://id/US-a1b2c3d4e5f6a7b8",

  "content":      "Hello from a TIP-Protocol publisher.",
  "content_type": "text",
  "signature":    "<6618-hex>"
}
```

**Step 7 — server response on success.**

```json
{
  "ok": true,
  "status": 202,
  "data": {
    "ctid": "tip://c/OH-<14hex>-<4hex>",
    "tx_id": "<64-hex>",
    "origin_code": "OH",
    "content_hash": "<64-hex>",
    "registered_at": "2026-05-10T14:32:00.000Z",
    "confirmation": "proposed"
  }
}
```

The response is `202 Accepted` because the tx is in the mempool but not yet committed. Clients can poll `GET /v1/content/{ctid}` until `status` flips from `pending` to `registered` to confirm consensus commit.

---

## 13. Versioning

The on-wire `cna_version` field declares the CNA version used to produce `content_hash` (§1). Versioning policy:

- **Submissions** sign under the current CNA version. The canonical-payload builder forces `cna = CNA_VERSIONS.REGISTER_CONTENT.current` into the signed payload; clients cannot pick a different one.
- **Verification** accepts any version in `CNA_VERSIONS.REGISTER_CONTENT.versions` — every CNA version that's ever shipped. Historical txs (signed under earlier CNA versions) keep verifying after a bump, which is what makes consensus replay deterministic across releases.
- **Unrecognised version** → `422 cna_unsupported` with `{ "error": "Unsupported cna_version: <value>...", "code": "cna_unsupported" }`.

The whitelist + current is the **single source of truth** in `shared/constants.js#CNA_VERSIONS`:

```js
CNA_VERSIONS.REGISTER_CONTENT = {
  versions: ["CNA-2.2"],     // accepted at verification time
  current:  "CNA-2.2",       // signed under for new submissions
};
```

**Adding a new CNA version (e.g. `CNA-2.3`):**

1. Append `"CNA-2.3"` to `versions`, set `current: "CNA-2.3"` in `shared/constants.js`. The whole codebase picks up the new whitelist immediately (no edits to `tx-validator.js`, `verifyTx`, or service code).
2. Implement the CNA-2.3 normalization function alongside (or in place of) `tipNormalize` in `shared/crypto.js`. If the algorithm changes, the same content produces a different `content_hash` under each version — the `cna_version` field is what tells the verifier which one to apply.
3. If the new CNA version also changes the **signed-payload shape** (adds / removes / reorders fields), write a per-version `buildSigningPayloadV23` in `node/src/schemas/content-register.js` and a dispatch table mapping `cna_version` → builder. `verifyTx` reads `tx.data.cna_version` and replays under the matching builder so existing txs keep verifying. If the shape doesn't change, step 3 isn't needed — only the CNA function differs.
4. Add a frozen test-vector for the new version (raw content + canonical-JSON string + signature + pub-key + expected hash). Keep the old version's test-vector in the repo forever — it's the regression guard that proves we didn't break replay of historical content.

Steps 2-4 are concrete work for the day the bump happens; today, with only one CNA version, the codebase is intentionally minimal.

**Committed-tx invariant:** the bytes in `tx.data` for a committed REGISTER_CONTENT tx are permanent. Re-verification picks the right CNA implementation (and, if shape changed, the right builder) by reading `data.cna_version`, so a node running the latest binary still verifies content signed years prior under earlier CNA versions.

---

## 14. Error responses

All error responses follow this shape:

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

Common codes for `POST /v1/content/register`:

| HTTP | Code | When |
|---|---|---|
| 400 | `body_invalid` | Request body is not a JSON object. |
| 400 | `signer_tip_id_required` | Missing or malformed `signer_tip_id` (must start with `tip://id/`). |
| 400 | `origin_code_invalid` | Not one of `OH` / `AA` / `AG` / `MX`. |
| 400 | `signature_required` | Missing or empty `signature`. |
| 400 | `content_required` | Neither `content` nor `media_canonical_hash` provided. |
| 400 | `authors_required` | `authors[]` missing or empty. |
| 400 | `authors_tip_id_invalid` | An `authors[].tip_id` is missing or not in `tip://id/...` format. |
| 400 | `attribution_mode_invalid` | `attribution_mode` not in the enum (`self` / `employed` / `hosted`). |
| 400 | `extras_invalid` | `extras` is not a plain object (e.g. array or null). |
| 400 | `registered_urls_invalid` | `registered_urls` is not an array of strings. |
| 400 | `content_hash_mismatch` | Server-recomputed content hash != `content_hash` in signed payload. |
| 403 | `signature_invalid` | ML-DSA verify failed against the DAG-resident public key. |
| 403 | `signer_revoked` | Signer's identity has been revoked. |
| 409 | `ctid_already_registered` | The derived CTID already exists. |
| 412 | `signer_not_registered` | Signer's TIP-ID is not on the DAG. Get the upstream VP to publish it first. |
| 412 | `author_not_registered` | One of the `authors[].tip_id` values is not on the DAG. The error message names the offending TIP-ID. |
| 422 | `cna_unsupported` | `cna_version` is not in `PAYLOAD_SCHEMAS.REGISTER_CONTENT.versions`. |

---

## 15. Implementation references

**Canonical schema module — single source of truth:**
- `node/src/schemas/content-register.js` — exports `validateRequest`, `resolveSigner`, `buildSigningPayload`, `sign`, `verify`, `verifyTx`. Both the API service and consensus commit-handler import this module so they cannot drift.
- `node/src/schemas/_common.js` — shared canonical-JSON / sign / verify primitives.
- `node/src/schemas/README.md` — module convention and the catalog of pending tx-type schema migrations.

**Constants:**
- `shared/constants.js#PAYLOAD_SCHEMAS.REGISTER_CONTENT` — `{ versions: ["CNA-2.2"], current: "CNA-2.2" }`.
- `shared/constants.js#ATTRIBUTION_MODES` + `ATTRIBUTION_MODE_VALUES` — locked enum for `attribution_mode`.
- `shared/constants.js#CNA22_AUTHOR_KEYS` — the 5 keys per `authors[]` entry.

**Service / consensus wiring:**
- `node/src/services/content-service.js#register` — API path: `validateRequest` → `resolveSigner` → recompute content hash → `buildSigningPayload` → `verify` → submit tx.
- `node/src/consensus/commit-handler.js` — `REGISTER_CONTENT` case: dispatches to `contentRegisterSchema.verifyTx(tx, dag)` for the re-verification, then `dag.saveContent(...)` for the derived-state row.
- `node/src/validators/tx-validator.js` — wire-contract validator: checks `cna_version ∈ PAYLOAD_SCHEMAS.REGISTER_CONTENT.versions`, required fields, basic types, `attribution_mode` enum, authors-array shape.

**Tests:**
- `node/tests/schemas/content-register.test.js` — unit tests for `buildSigningPayload`, `sign`/`verify`, `verifyTx`, default-fills, reject-on-extra, attribution-mode enum.
- `node/tests/integration/content-register.test.js` — end-to-end through the API: happy path, off-DAG signer (412), off-DAG author (412), tamper detection (403), `registered_urls` passthrough.
- `node/tests/consensus/commit-handler-rejections.test.js` — exercises consensus-replay rejection paths.

When a client submits content and gets a 403 with `signature_invalid`, ask:

1. Did you build the canonical JSON with sorted keys, no whitespace, slashes unescaped, UTF-8 passthrough?
2. Did you sign the **ASCII bytes of the hex digest** (64 bytes), not the **raw 32 hash bytes**?
3. Did you use ML-DSA-65 (FIPS 204), not ML-DSA-44 or 87?
4. Did you use SHAKE-256 with 32-byte output, not SHA-256?
5. Is `extras` `{}` and not `[]` when empty?
6. Are all 8 fields present (with defaults for the optional ones)? Did you accidentally include `signer_type` (removed — would shift the canonical JSON)?
7. Are author entries exactly 5 keys, no extras?

If all of these check out and you still get `signature_invalid`, run a debug fixture: dump the canonical JSON byte-by-byte and the resulting hex hash to your logs, then ask the node operator to compare against what their verifier reconstructs. Field-by-field diff usually surfaces the drift in one minute.

---

## 16. Change log (within `CNA-2.2`)

Pre-launch edits to the CNA-2.2 spec. No on-chain artifacts under stale shapes, so versions in `CNA_VERSIONS.REGISTER_CONTENT.versions` stay at `["CNA-2.2"]`. Clients shipping against an earlier draft must align before submitting.

- **Dropped `signer_type`** — was the 9th field of the signed payload, default `"personal"`. Removed because the signer's role is a property of their TIP-ID (resolved from DAG identity at verify time), not a per-message assertion. Canonical payload is now 8 fields. (§2 "Removed: `signer_type`".)
- **`attribution_mode` is a locked enum** — `"self"` / `"employed"` / `"hosted"`. Non-listed values reject with `attribution_mode_invalid`. (§6.)
- **`registered_urls` is a plural array** of strings, ordered, index 0 = canonical / primary URL. Old singular `registered_url` is rejected. (§9.)
- **No `public_key` on the wire** — DAG identity is the only public-key source. Off-DAG signers get 412. (§1A.)
- **No `author_tip_id` on the wire** — canonical field is `signer_tip_id`. Old `author_tip_id` is not accepted as an alias. (§2 field 8.)
- **Authors must all be DAG-resident** — every `authors[i].tip_id` must exist on the DAG, same predicate as the signer. (§10, §11.)
- **Multi-version CNA support infrastructure** — `CNA_VERSIONS` (in `shared/constants.js`) exposes `versions[]` (whitelist for verification) and `current` (used at submission). Lays the groundwork for `CNA-2.3` without breaking historical replay. (§13.)

---

*© 2026 The AI Lab Intelligence Unobscured, Inc.
Licensed under TIPCL-1.0.*
