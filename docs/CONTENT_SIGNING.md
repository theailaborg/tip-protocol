# TIP Protocol — Content Signing Specification

**Version:** CNA-2.2
**Status:** Canonical. Every client that registers content on a TIP node MUST follow this spec.
**Audience:** Integrators building any client that submits content to a TIP node — browser extensions, WordPress / Ghost / Substack plugins, mobile apps, CLI tools.

## TL;DR

To register content, a client signs a fixed 9-field canonical payload with their ML-DSA-65 private key and submits the payload + signature + auxiliary metadata to `POST /v1/content/register`. The server recomputes the same canonical payload, looks up the signer's public key from the DAG identity record, and verifies the signature. Same canonical-JSON rules everywhere; no per-client variations; no fallback.

---

## 1. Identity prerequisite

Every signer's TIP-ID MUST be registered on the DAG before they can submit content. The protocol does **not** accept content from signers whose identities are not on the DAG. If your client is hitting a 412 on `POST /v1/content/register`, the upstream identity-issuance flow (your VP) hasn't propagated the identity to the DAG yet.

The signer's TIP-ID is referenced by the canonical payload's `signer_tip_id` field; the verifier looks up that TIP-ID's public key on the DAG and verifies the submitted signature against it.

---

## 2. The signed canonical payload

Exactly 9 top-level fields, in this exact set, every field always present (defaults filled when absent). Object keys are sorted ASCII-ascending (recursively) at canonicalisation time — clients can build the object in any insertion order; the canonical-JSON encoder normalises.

| # | Field | Type | Required? | Default when absent | Notes |
|---|---|---|---|---|---|
| 1 | `attribution_mode` | string | no | `"self"` | What relationship the signer has to the bylined authors. Locks the assertion at signing time. See §6. |
| 2 | `authors` | array | yes | — must have ≥1 entry | Ordered byline. Index 0 = primary byline. Each entry is a 5-key object — see §5. |
| 3 | `cna` | string | yes | — | Always the literal `"CNA-2.2"`. Pins the signature to this spec version. |
| 4 | `content_hash` | string | yes (no default) | — | Lowercase 64-char hex of `SHAKE-256(canonical content bytes, 32)`. See §7 for canonical content rules. |
| 5 | `extras` | object | no | `{}` | Open extension point — see §8. |
| 6 | `origin_code` | string | yes (no default) | — | One of `"OH"` / `"AA"` / `"AG"` / `"MX"`. Always uppercase in the signed payload — clients sending lowercase get rejected. |
| 7 | `registered_urls` | array | no | `[]` | URLs where the content is published. Always present, can be empty when not yet published. See §9. |
| 8 | `signer_tip_id` | string | yes (no default) | — | The TIP-ID whose private key produced the signature. The verifier uses this to look up the public key on the DAG. |
| 9 | `signer_type` | string | no | `"personal"` | Categorical role of the signer — `"personal"` or `"publisher"`. Locked at signing time so it can't be flipped post-hoc. Authorisation gates (e.g. domain binding) require `"publisher"`. |

**Field shape, always present, deterministic.** Empty values use explicit defaults (`{}`, `[]`, `"self"`, `"personal"`). Fields are NEVER dropped from the canonical payload — that's what makes the same logical content produce byte-identical signed bytes regardless of which client built the payload.

**Reject-on-extra.** The canonical builder picks exactly these 9 fields and ignores anything else the client puts at the top level. Garbage fields don't get signed; clients can't bloat the canonical JSON with attacker-controlled junk.

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
- `tip_id_type` matches the `signer_type` semantics — `"personal"` or `"publisher"`.

---

## 6. `attribution_mode`

The signer's relationship to the bylined authors:

| Value | Use case |
|---|---|
| `"self"` (default) | Signer is one of the authors. `signer_tip_id` MUST match `authors[i].tip_id` for some `i`. |
| `"editorial"` | Publisher signing on behalf of one or more humans. `signer_tip_id` is the publisher (org TIP-ID); none of the `authors[].tip_id` match the signer. |
| `"ghostwritten"` | Signer is a real ghostwriter; `authors[0]` is the public byline (a different TIP-ID, with consent). |
| `"reposted"` | Signer is republishing content originally created by `authors[*]`. |

Today `"self"` is the only value all clients send. Other modes will be defined as publisher and multi-author flows ship.

---

## 7. `content_hash`

Lowercase 64-char hex of `SHAKE-256(canonical content bytes, 32)`. The canonicalisation rules for the **content** (separate from the canonical JSON used for the signed payload) are:

- For text content: see `tipNormalize` — Unicode NFC + canonical normalisation per CNA-2 (specifics in `shared/crypto.js`).
- For mixed media (text + image/video/audio): `content_hash` is the SHAKE-256 of `media_canonical_hash` concatenated with `text_hash`. See CNA-MIX-1 spec.

The server recomputes the content hash from the content bytes the client sends in the request envelope and matches it against the `content_hash` in the signed payload. Mismatch is a signature failure (the canonical payload didn't bind to the content the client claimed to sign).

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

Array of URLs where the content is published. Always present:

```json
"registered_urls": []                                          // not yet published
"registered_urls": ["https://example.com/post/"]               // single URL
"registered_urls": ["https://example.com/post/",
                    "https://medium.com/@x/post"]              // syndicated
```

Each URL MUST:
- be HTTP or HTTPS (no `ftp://`, `file://`, etc.)
- be a single full URL string (the canonical encoder doesn't escape slashes, so the URL appears verbatim in the signed payload)

Domain-binding (the future `/v1/domain/{domain}` endpoint) operates on these URLs: a content registration whose publisher TIP-ID has a verified binding to any of the URL hosts is considered "publisher-attested at that URL." Mismatched URLs are accepted but not domain-attested.

---

## 10. The request envelope

The signed payload is the cryptographic core. The client sends additional fields in the HTTP request body that are NOT in the signed payload — they're either auxiliary, server-derived, or per-author co-signatures.

Request body shape (JSON to `POST /v1/content/register`):

```json
{
  "comment": "Fields 1-9 below mirror the signed canonical payload. Same bytes, same values.",
  "attribution_mode": "self",
  "authors": [{ "key_mode": "attribution", "role": "byline", "signed": false,
                 "tip_id": "tip://id/US-...", "tip_id_type": "personal" }],
  "cna": "CNA-2.2",
  "content_hash": "<64-hex>",
  "extras": {},
  "origin_code": "OH",
  "registered_urls": ["https://example.com/post/"],
  "signer_tip_id": "tip://id/US-...",
  "signer_type": "personal",

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

Note: do NOT send `public_key` in the request body. The verifier looks up the signer's public key from the DAG identity record. If your TIP-ID isn't on the DAG yet, the registration will be rejected — talk to your VP.

---

## 11. Server-side verification

The TIP node performs the following on every incoming `POST /v1/content/register`:

1. **Schema validation** — body must have all required fields per §10.
2. **Identity lookup** — `dag.getIdentity(signer_tip_id)`. If the TIP-ID isn't on the DAG, return `412 Precondition Required` with `{ "error": "Signer TIP-ID not registered on DAG", "code": "signer_not_registered" }`.
3. **Revocation check** — if the signer's identity is revoked, return `403 Forbidden`.
4. **Content hash verification** — recompute SHAKE-256 over the canonical content bytes; compare to `body.content_hash`. Mismatch → `400 Bad Request` with `{ "error": "content_hash mismatch", "code": "content_hash_mismatch" }`.
5. **Canonical payload reconstruction** — pick the 9 signed fields from the body, normalise (uppercase `origin_code`, default-fill any optional fields the client omitted, normalise each author entry to exactly 5 keys), build the canonical JSON.
6. **Signature verification** — `ML_DSA_65.verify(dag_identity.public_key, ASCII(SHAKE256(canonical).hex()), signature)`. Mismatch → `403 Forbidden` with `{ "error": "Content signature verification failed", "code": "signature_invalid" }`.
7. **Co-signature verification** — for each `authors[i]` with `signed: true`, find the matching entry in `co_signatures[]`, look up that author's public key on the DAG, verify the co-signature against the SAME canonical payload. Any failure → `403`.
8. **CTID uniqueness** — the derived CTID (origin + content_hash prefix + signer suffix) must not already exist. Conflict → `409 Conflict`.
9. **Submit to consensus** — assemble the `REGISTER_CONTENT` tx, sign with the node's key, push to mempool. Response: `202 Accepted` with the tx_id and CTID.

Steps 5–7 run a second time inside the consensus commit-handler when the tx commits, using the EXACT same canonical-payload builder. The code path is shared (`node/src/validators/cna22.js`); API and consensus can never drift.

---

## 12. Worked example

**Step 1 — content + canonical content hash.**
Content: `Hello from a TIP-Protocol publisher.`
Canonical content bytes (after `tipNormalize`): same string.
`content_hash = SHAKE-256("Hello from a TIP-Protocol publisher.", 32).hex()` → (some 64-hex value, deterministic for those bytes).

**Step 2 — build the 9-field signed payload.**

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
  "cna": "CNA-2.2",
  "content_hash": "<64-hex from step 1>",
  "extras": {},
  "origin_code": "OH",
  "registered_urls": ["https://example.com/hello/"],
  "signer_tip_id": "tip://id/US-a1b2c3d4e5f6a7b8",
  "signer_type": "personal"
}
```

**Step 3 — canonical JSON.**

```
{"attribution_mode":"self","authors":[{"key_mode":"attribution","role":"byline","signed":false,"tip_id":"tip://id/US-a1b2c3d4e5f6a7b8","tip_id_type":"personal"}],"cna":"CNA-2.2","content_hash":"<64-hex>","extras":{},"origin_code":"OH","registered_urls":["https://example.com/hello/"],"signer_tip_id":"tip://id/US-a1b2c3d4e5f6a7b8","signer_type":"personal"}
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
  "cna": "CNA-2.2",
  "content_hash": "<64-hex>",
  "extras": {},
  "origin_code": "OH",
  "registered_urls": ["https://example.com/hello/"],
  "signer_tip_id": "tip://id/US-a1b2c3d4e5f6a7b8",
  "signer_type": "personal",

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

The `cna` field is the protocol version. A future `CNA-3.0` would add or remove signed fields and clients must bump their `cna` value to match. Verifiers dispatch on `cna`:

- Recognised version → run the matching verifier
- Unrecognised version → `422 Unprocessable Entity` with `{ "error": "Unsupported CNA version: <value>", "code": "cna_unsupported" }`

This means clients and nodes can roll out new CNA versions independently — old clients keep working with old verifiers; new clients use the new one. The shape of `tx.data` for committed txs is permanent; the verifier dispatch resolves which spec a given tx was signed under by reading `data.cna`.

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
| 400 | `bad_request` | Schema invalid (missing required field, wrong type) |
| 400 | `content_hash_mismatch` | Server-recomputed content hash != `content_hash` in signed payload |
| 403 | `signature_invalid` | ML-DSA verify failed against the DAG-resident public key |
| 403 | `signer_revoked` | Signer's identity has been revoked |
| 409 | `ctid_already_registered` | The derived CTID already exists |
| 412 | `signer_not_registered` | Signer's TIP-ID is not on the DAG. Get the upstream VP to publish it first. |
| 422 | `cna_unsupported` | Unrecognised `cna` value |

---

## 15. Implementation references

- **TIP node verifier (canonical):** `node/src/validators/cna22.js` — payload builder, signature verifier.
- **TIP node API path:** `node/src/services/content-service.js#register`.
- **TIP node consensus path:** `node/src/consensus/commit-handler.js` — `REGISTER_CONTENT` case.
- **TIP node tests:** `node/tests/validators/cna22.test.js`, `node/tests/integration/cna22-content-register.test.js`.

When a client submits content and gets a 403 with `signature_invalid`, ask:

1. Did you build the canonical JSON with sorted keys, no whitespace, slashes unescaped, UTF-8 passthrough?
2. Did you sign the **ASCII bytes of the hex digest** (64 bytes), not the **raw 32 hash bytes**?
3. Did you use ML-DSA-65 (FIPS 204), not ML-DSA-44 or 87?
4. Did you use SHAKE-256 with 32-byte output, not SHA-256?
5. Is `extras` `{}` and not `[]` when empty?
6. Are all 9 fields present (with defaults for the optional ones)?
7. Are author entries exactly 5 keys, no extras?

If all of these check out and you still get `signature_invalid`, run a debug fixture: dump the canonical JSON byte-by-byte and the resulting hex hash to your logs, then ask the node operator to compare against what their verifier reconstructs. Field-by-field diff usually surfaces the drift in one minute.

---

*© 2026 The AI Lab Intelligence Unobscured, Inc.
Licensed under TIPCL-1.0.*
