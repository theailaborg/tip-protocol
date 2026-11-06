# TIP Protocol REST API Reference

**Base URL:** `https://node.theailab.org`  
**Version:** v1  
**Format:** All requests and responses use `application/json`  
**Auth:** Admin endpoints require `Authorization: Bearer <TIP_ADMIN_API_KEY>`

---

## Endpoints

### Health and Node Info

#### `GET /health`
Returns node health status.

**Response 200:**
```json
{
  "status": "ok",
  "version": "2.0.0",
  "chain_id": "tip-mainnet-v2",
  "dag_count": 1842,
  "uptime_seconds": 86400
}
```

#### `GET /v1/node/info`
Returns full node metadata.

**Response 200:**
```json
{
  "node_id": "tip://id/US-nodehash12345678",
  "protocol_version": "2.0",
  "chain_id": "tip-mainnet-v2",
  "genesis_hash": "52f08c352f8866b4...",
  "vp_mode": false,
  "peer_count": 12
}
```

#### `GET /v1/node/peers`
Returns known peer nodes.

**Response 200:**
```json
{ "peers": ["node1.example.com:4001", "node2.example.com:4001"] }
```

#### `GET /v1/dag/stats`
Returns DAG statistics.

**Response 200:**
```json
{
  "tx_count": 1842,
  "identity_count": 423,
  "content_count": 891,
  "vp_count": 7
}
```

---

### Identity

#### `POST /v1/identity/register`
Register a new TIP-ID. Requires VP signature.

**Request body:**
```json
{
  "tip_id":        "tip://id/US-a3f8c91b2d4e7021",
  "region":        "US",
  "public_key":    "[ML-DSA-65 public key hex]",
  "vp_id":         "tip://id/VP-US-example",
  "dedup_hash":    "[peppered SHAKE-256 dedup hash]",
  "zk_proof":      "[ZK proof of uniqueness]",
  "vp_signature":  "[ML-DSA-65 signature by VP over tip_id+dedup_hash]",
  "attested":      false
}
```

**Response 201:**
```json
{
  "tip_id":       "tip://id/US-a3f8c91b2d4e7021",
  "status":       "active",
  "score":        500,
  "tier":         { "label": "REVIEW_ADVISED", "color": "#A88B15" },
  "verified_at":  "2026-03-15T00:00:00Z"
}
```

**Errors:**
- `400`: Missing required fields
- `400` `region_invalid`: `region` is not an ISO 3166-1 alpha-2 country code (send `IN`, not `IND`)
- `409`: TIP-ID already registered
- `422`: Duplicate identity (dedup_hash exists)
- `403`: Invalid VP signature or VP not accredited

#### `GET /v1/identity/:tipId`
Resolve a TIP-ID. URL-encode the TIP-ID.

**Response 200:**
```json
{
  "tip_id":      "tip://id/US-a3f8c91b2d4e7021",
  "region":      "US",
  "status":      "active",
  "vp_id":       "tip://id/VP-US-example",
  "verified_at": "2026-03-15T00:00:00Z",
  "score":       892,
  "tier":        { "label": "HIGHLY_TRUSTED", "color": "#1A8A5C" },
  "founding":    false
}
```

**Errors:** `404`: TIP-ID not found

#### `GET /v1/identity/:tipId/score`
Get trust score only (lightweight endpoint for embedding).

**Response 200:**
```json
{
  "tip_id":        "tip://id/US-a3f8c91b2d4e7021",
  "score":         892,
  "tier":          { "label": "HIGHLY_TRUSTED", "color": "#1A8A5C" },
  "offense_count": 0,
  "status":        "active",
  "display_mode":  "TIER_ONLY"
}
```

#### `GET /v1/identity/:tipId/history`
Get transaction history for a TIP-ID.

**Response 200:**
```json
{
  "tip_id":  "tip://id/US-a3f8c91b2d4e7021",
  "events": [
    { "tx_type": "REGISTER_IDENTITY", "timestamp": "2026-03-15T00:00:00Z", "delta": 0 },
    { "tx_type": "CONTENT_VERIFIED",  "timestamp": "2026-03-16T00:00:00Z", "delta": 3 }
  ]
}
```

---

### Content

#### `POST /v1/content/register`
Register content with origin declaration.

**Request body:**
```json
{
  "author_tip_id":    "tip://id/US-a3f8c91b2d4e7021",
  "origin_code":      "OH",
  "content":          "Article text or base64-encoded media...",
  "title":            "Article Title",
  "author_signature": "[ML-DSA-65 signature over content+origin_code]"
}
```

**Response 201:**
```json
{
  "ctid":          "tip://c/OH-7f2a91bc3d5e4a-a3f8",
  "status":        "verified",
  "origin_code":   "OH",
  "content_hash":  "[SHAKE-256 hex]",
  "registered_at": "2026-03-15T00:00:00Z",
  "pre_scan":      { "flagged": false, "probability": 0.12 }
}
```

If pre-scan flags the content, `status` will be `pending` and `pre_scan.flagged` will be `true`. The content is still registered.

**Errors:**
- `400`: Missing required fields or invalid origin code
- `400` extras_email_invalid, when `extras.email` is present but is not `{ v: 1 }` with optional `recipients`, `from`, `all` and `attachments` (see below)
- `400` email_hash_only_invalid, when an email sent by its hash alone has a malformed `content_hash`, or carries media, fingerprints or a non-text `content_type_hint` (node 2.9.4)
- `400` email_seals_required, when an email lacks `from`, `recipients` or `all`, or `attachments` (`details.missing` names them), and `400` email_empty, when its subject and body normalize to nothing (node 2.9.5, from `EMAIL_SEALS_REQUIRED_ACTIVATION_MS`)
- `400` email_no_links, when an email carries `registered_urls` or `parent_url` (node 2.9.4: a hash-only email always, any email from `EMAIL_PRIVATE_ACTIVATION_MS`)
- `403`: Author TIP-ID not active
- `413` document_pages_exceed_plan, when a document fingerprint item covers more pages than the signer's plan fingerprints (see below)
- `422`: Invalid author signature

##### Document page limits
Plans limit how many pages of a document the node fingerprints. A `cf-doc-1` item counts its `unit_count` when `unit` is `page` or `slide`, and otherwise `ceil(chars_covered / 1800)` standard pages, at least 1. On a node with a billing service configured, a registration whose largest document item is over the signer's plan limit is refused before anything is written, with `413` `{ code: "document_pages_exceed_plan", details: { pages, max_pages } }`; `POST /v1/media/upload-init` gives the same refusal for its `doc_pages`. The same file can still be registered without its document item, by exact hash only. A billing service that cannot be reached never blocks a registration or an upload.

##### Email registrations
An email is registered like any text: `content` is the subject, a newline, then the body, and `content_hash` covers that text. The signed `extras` carries `"email": { "v": 1 }` plus up to three optional seals, each 64 lowercase hex computed by the client (the node never sees an address): `recipients`, a salted commitment to the To and Cc addresses; `from`, a salted commitment to the sender's address (node 2.9.3); and `all`, a commitment to the To, Cc and Bcc addresses under a secret only the sender holds, so Bcc stays private (node 2.9.3). `v` must be the integer `1`, each seal is optional, and no other keys are allowed; anything else is refused with `400` `{ code: "extras_email_invalid" }`. The node uses the text only to recompute `content_hash`. It never sends an email's text to the AI origin classifier, keeps no copy of it, and indexes no text fingerprint for it (clients send none; a text or document fingerprint item that arrives with an email is dropped). The prescan completes at once with the same verdict a locally skipped origin gets, which is `probability` 0.5, tier `low`, not flagged, and `classifier_providers_used` `skipped_locally`.

Node 2.9.4: an email can register by its hash alone, so its text never reaches any node. Send `content_hash` (64 lowercase hex, the hash of the normalized subject-newline-body text, exactly what the signature covers) and no `content`; no `media`, `media_canonical_hash`, fingerprints or `content_type_hint` other than `text`, and no `registered_urls` or `parent_url` (refused with `email_no_links` even before the activation below). The node cannot and does not check that the hash is an email: the signature binds the signer to that hash at that time, and whoever holds the email proves a copy by hashing it and comparing (`GET /v1/content-matches?hash=`). The CTID is the one the text would give. Sending `content` with an email still works for older clients. Either way the email's length is not put on the tx (`text_chars` is absent) and the email earns no registration credit, since nobody can dispute it. From `EMAIL_PRIVATE_ACTIVATION_MS` (2026-11-06 11:15 UTC), checked at API time and at commit (at the later of the tx time and the certificate time, so a backdated tx cannot dodge it): an email cannot carry `registered_urls` or `parent_url` and links cannot be added to it later (`email_no_links`); nobody can verify it (`email_not_verifiable`); nobody can dispute it, and no node files a dispute on it either, from a review escalation or a creator fast-forward (`email_not_disputable`); and it is never reviewed: a flagged verdict on it is dropped (`email_not_scanned`), and no review is triggered, claimed from the desk or confirmed (`email_not_reviewable`). A review already running on one can still be dismissed or time out, which returns it to registered. The sender can still change the declared origin or retract the record as for any post. Its origin is the sender's own statement, so records say `origin_basis: "self_declared"`. The marker also takes an optional `attachments` seal (64 lowercase hex, node 2.9.4): a commitment to the attachments' bytes, hashed on the sender's device and salted by the email's text, so a swapped attachment is caught while no file reaches a node. The node checks its shape only. Node 2.9.5: from `EMAIL_SEALS_REQUIRED_ACTIVATION_MS` (2026-11-06 11:55 UTC, API time and commit) every new email must carry `from`, `recipients` or `all` (`all` alone is a Bcc-only email), and `attachments` (made over an empty list when there are no files), and must not be empty text; without them a receiver cannot tell a copy replayed from another address or re-sent to someone else from the original. Older email records are unaffected.

#### `GET /v1/content/:ctid`
Resolve a content provenance record.

**Response 200:**
```json
{
  "ctid":           "tip://c/OH-7f2a91bc3d5e4a-a3f8",
  "origin_code":    "OH",
  "origin_label":   "Original Human",
  "status":         "verified",
  "author_tip_id":  "tip://id/US-a3f8c91b2d4e7021",
  "author_score":   892,
  "dispute_count":  0,
  "registered_at":  "2026-03-15T00:00:00Z",
  "media": [
    {
      "media_id":       "[SHAKE-256 hex of the bytes]",
      "mime":           "image/png",
      "stored":         true,
      "size":           2361613,
      "ai_probability": 0.51,
      "ai_provider":    "image_detector"
    }
  ],
  "media_canonical_hash": "[SHAKE-256 hex]"
}
```

`is_email` is true for an email registration. `origin_basis` (node 2.9.4) says what backs `origin_code`: `open_to_review` (the AI prescan where it applies, and disputes) or `self_declared` (an email: the sender's own statement, never scanned and not disputable).

`media[]` carries public storage facts (type, size, whether the bytes are still stored) and the per-file AI score from the verdict. The bytes themselves are not here, fetch them via the role-gated media endpoint below. `ai_probability` is `null` until prescan completes.

Optional `include`:
- `include=similar` adds `similar[]`, the same cards as `GET /v1/content/:ctid/similar` (top 5). Without it no lookup runs.
- `include=fingerprints` adds `fingerprints[]`, the stored perceptual fingerprints `{ component_idx, modality, profile, quality, fingerprint }`; `include=fingerprints.document` (or `.text`, `.image`, `.video`, `.audio`, comma-separated) keeps only those kinds. A document's `fingerprint` is the whole `cf-doc-1` item, every page signature included. `video_every=N` keeps every Nth video frame.

#### `GET /v1/content/:ctid/similar`
Near-duplicates of this record among the content this node has indexed, as cards sorted by `similarity.score` (0 to 1, comparable across kinds; a rank, not a verdict). `?limit` (default 5, max 20).

```json
{
  "ctid": "tip://c/OH-7f2a91bc3d5e4a-a3f8",
  "count": 1,
  "similar": [{
    "ctid": "tip://c/OH-5c19e0aa7b2d33-91c0",
    "origin_code": "OH", "author_tip_id": "tip://id/US-...", "author_name": "...", "title": "...",
    "status": "registered", "registered_at": 1793448000000, "media": [],
    "similarity": {
      "modality": "document", "score": 0.94, "component_idx": 0,
      "shared_text": { "a_in_b": 0.27, "b_in_a": 0.45, "chars": 5043, "score": 5043, "at_a": [[2, 3]], "at_b": [[1, 2]], "worth_listing": true },
      "same_wording": false, "cross_format": false, "text_similarity": 0.31,
      "images": { "a": 0, "b": 0, "shared": 0 }, "textless_pages": { "a": 0, "b": 0, "shared": 0 },
      "units": { "a": 5, "b": 3, "shared": 0, "reordered": false }
    }
  }]
}
```

`similarity` carries the kind's own figures: `similarity` (text, MinHash), `distance` (image, PDQ bits of 256), `target_match_pct` and `query_match_pct` (video), `landmark_matches` and `score_ratio` (audio). For documents it is the library's `compareDocument` result: `shared_text` says how much of each document's text is in the other (`a_in_b`, `b_in_a`), about how many characters, and on which pages (`at_a`, `at_b`); `shared_text.score` is those characters with each passage weighted by 1 / (1 + the number of other owners whose records hold it), so text many people hold (a licence, a disclaimer) ranks last. A document is listed when `shared_text.worth_listing` holds (at least 300 characters shared, or the same wording) or it shares a scanned page image (the same scan or the same form). Its `score` is the larger of `shared_text.score / (shared_text.score + 300)` and the share of scanned pages that match. The text MinHash never lists or ranks one document against another: two large unrelated texts in one language can pass 0.30. A document also lists posts with the same text and images posted alone that match one of its pictures or pages.

#### `GET /v1/content`
List content, newest first. Cursor-paginated, public.

Query params (all optional): `author`, `origin`, `status`, `has_media`, `limit` (1-100, default 20), `cursor` (opaque token from a prior response's `next_cursor`).

Node 2.9.6 adds, for a person's own list (My Content):
- `kind`: `email` (records whose `extras.email` is an object) or `post` (every other record). `400` kind_invalid.
- `from`, `to`: `registered_at` range in epoch milliseconds, `from` inclusive, `to` exclusive. Send local midnights to get calendar days in the reader's time zone. `400` from_invalid / to_invalid / range_invalid.
- `q`: 2 to 100 characters, matched as a case-insensitive substring of the `ctid`, the registered URLs and the public `extras.title`. Case folding is ASCII only (`É` matches only `É`) so every store agrees. It needs `author` or `bylined`, so a search stays inside one person's list (`400` q_needs_author, q_invalid). An email has no public title or link, so a search finds an email only by its CTID.
- `include=summary` (needs `author`, `400` summary_needs_author) adds `summary` to the response, counted over all of the author's records whatever the other filters: `{ total, posts, emails, latest_at, months: [{ month: "2026-11", posts, emails }] }`, newest month first. `tz` (an IANA time zone such as `America/New_York`, default `UTC`; `400` tz_invalid) sets the month boundaries, daylight saving included. It rides on the page the client is already fetching, so counts cost no extra request.

All of them combine with each other, with the older filters and with `cursor`. A node older than 2.9.6 ignores them and returns an unfiltered page; a client can tell from `applied`.

**Response 200:** `{ "items": [ ...slim rows... ], "next_cursor": "..." | null, "applied": { "kind", "from", "to", "q" }, "summary"?: {...} }`. `applied` (node 2.9.6) echoes the normalized values, `null` when unset. Each row carries `ctid`, `author_tip_id`, `origin_code`, `status`, `prescan_status`, `prescan_tier`, `media_count`, `registered_urls`, `registered_at`, and (node 2.9.3) `is_email`, true for an email registration, which has no link by design, and (node 2.9.4) `origin_basis`, as on the record, and (node 2.9.6) `title`, the public `extras.title` up to 300 characters or `null`.

#### `POST /v1/content/:ctid/dispute`
File a dispute against a content origin declaration.

**Request body:**
```json
{
  "disputer_tip_id": "tip://id/VP-US-example",
  "reason":          "AI classifier detected probable AI generation in OH-declared content",
  "evidence_hash":   "[SHAKE-256 of classifier output]"
}
```

**Response 201:**
```json
{
  "success": true,
  "message": "Dispute filed. Stage 1 AI classifier will run within 60 seconds.",
  "dispute_id": "tx_id_of_dispute_transaction"
}
```

An email record cannot be disputed: `403` `{ code: "email_not_disputable" }` (node 2.9.4, from `EMAIL_PRIVATE_ACTIVATION_MS`). Jurors could never see the email.

#### `POST /v1/content/:ctid/verify`
Manually verify a content record (jury-level participants only). An email record cannot be verified: `403` `{ code: "email_not_verifiable" }` (node 2.9.4, from `EMAIL_PRIVATE_ACTIVATION_MS`).

---

### Media

Media bytes are content-addressed (`media_id = SHAKE-256(bytes)`), stored off-chain per node, and access-controlled by adjudication role. Only the content-hash references live on chain. See [`docs/user-journeys`](user-journeys/) for the role-access model.

**Accepted types**, detected from the bytes (never the claimed label): images (png, jpeg, gif, webp, heic, heif, avif), audio (mp3, wav, ogg, flac, m4a), video (mp4, webm, mkv) and documents: PDF (`application/pdf`), RTF (`application/rtf`), DOCX, PPTX, XLSX, ODT, ODP, ODS and EPUB under their standard mimes. ZIP-based documents are recognised by their member names, so a plain archive, a macro-enabled Office file (`.docm`, `.pptm`, `.xlsm`) or a legacy `.doc`/`.ppt`/`.xls` is `415 format_unsupported`. Documents are not scanned by the AI classifier yet: their `media[]` entry gets `ai_probability: null` with `ai_provider: "document_not_scanned"`, and a post whose only content is a document gets a skipped verdict. Fetching a document over the `fs` transport always returns `Content-Disposition: attachment`.

#### `POST /v1/media/upload`
Single-request upload for `fs`-backed nodes (dev/test). Body is the raw bytes (`Content-Type: application/octet-stream`), one file per call, streamed. Every federation node stores media in S3 and answers `410 use_multipart` here; use the presigned multipart flow below.

**Headers:** `X-Media-Mime`, `X-Signer-TipId`, `X-Timestamp` (epoch ms, 5-min window), `X-Signer-Signature` (ML-DSA over `MEDIA_UPLOAD:{shake256(bytes)}:{mime}:{timestamp}:{signer_tip_id}`).

**Response 201:** `{ media_id, content_hash, mime, size, uploaded_at, signer_tip_id }`. The `mime` is SERVER-DETECTED from the file's magic bytes and is authoritative, use it (not your own label) when registering. Identical bytes always return the same `media_id` (dedup).

**Errors:** `400` timestamp_drift / bytes_required; `403` signature_invalid; `410` use_multipart (S3-backed node); `413` file_too_large (aborts mid-stream, sends `Connection: close`); `415` mime_disabled / format_unsupported.

#### Presigned multipart upload (S3-backed nodes)
The client PUTs parts straight to S3 with presigned URLs; the node never proxies the bytes and nothing touches node disk. Per-mime size caps are node-local (defaults: video 15 GiB, audio 1 GiB, image 1 GiB, document 1 GiB; `GET /v1/constants` reports them as `media_limits`).

1. `POST /v1/media/upload-init` body `{ mime, size, content_hash, signer_tip_id, timestamp, signature }`, signature over the same `MEDIA_UPLOAD:{content_hash}:{mime}:{timestamp}:{signer_tip_id}` challenge; `part_size` is optional, the node sizes parts adaptively (32 MiB for large files; 5 MiB to 5 GiB, at most 9,999 parts). **201** `{ session_id, part_size, part_count, part_etag_is_md5, parts: [{ part_number, url, url_expires_at }], expires_at }`. `part_etag_is_md5` reports whether this node's bucket returns each part's MD5 as its `ETag` (`false` under SSE-KMS); `null` means the node could not determine it for this session, so do not rely on ETags for integrity. Optional `checksum: "crc32"` opts the session into per-part integrity (below); the response then echoes `checksum` and returns `parts: []`. Optional `doc_pages` (integer, 1 to 1,000,000) is the number of pages the client will fingerprint for a document (PDF, EPUB, DOCX, slides and the other document formats), counted as in [Document page limits](#document-page-limits); send it only when the registration will carry a document fingerprint item. Errors: `400` checksum_unsupported / doc_pages_invalid, `413` file_too_large / too_many_parts / document_pages_exceed_plan, `415` mime_invalid / mime_disabled.
2. `PUT` each part's bytes to its `url` and keep the returned `ETag`. Part URLs are valid until `url_expires_at` (2 h by default, node-configurable); refresh before that, or after a `403`, from `GET /v1/media/upload-status/:session_id`, which returns `{ state: "uploading", part_count, checksum, uploaded_parts, missing_parts, parts: [{ part_number, url, url_expires_at }], expires_at }`. Do not add `Content-MD5`, or any other header the URL was not signed with, to the part PUT: S3 answers `403 SignatureDoesNotMatch`. When `part_etag_is_md5` is `true`, comparing the returned `ETag` with the part's MD5 is a free per-part check; otherwise integrity is enforced at complete, where the node re-hashes the whole object against the signed `content_hash`.
   **Per-part checksums (`checksum: "crc32"` sessions):** URLs are minted in batches of up to 64 with `POST /v1/media/upload-status/:session_id` body `{ parts: [{ part_number, checksum_crc32 }] }`, where `checksum_crc32` is S3's encoding, base64 of the 4-byte big-endian CRC32 of that part's bytes. Each returned URL is signed with its checksum, and the PUT must carry the header `x-amz-checksum-crc32: <same value>`: S3 rejects a part whose bytes do not match with `400 BadDigest` (re-send that part), and a missing or altered header with `403`. Every part of such a session needs a checksum-bound URL; plain URLs are refused by S3. Errors: `400` parts_required / parts_too_many / part_number_invalid / checksum_required / checksum_not_enabled (checksum given on a session that did not opt in), `409` session_not_uploading.
3. `POST /v1/media/upload-complete/:session_id` body `{ signer_tip_id, timestamp, signature, parts: [{ part_number, etag, checksum_crc32? }] }`, signature over `MEDIA_UPLOAD_COMPLETE:{session_id}:{timestamp}:{signer_tip_id}`; on a `checksum: "crc32"` session every part entry must carry its `checksum_crc32` (S3 verifies them again while assembling; missing ones answer `400` checksum_required). The node assembles the object, re-reads it from S3 to verify `content_hash` and the detected mime, then promotes it. **201** with the same descriptor as the single-request upload when that finishes within 8 s; otherwise **202** `{ state: "finalizing", session_id, poll_after_ms }` and the client polls `upload-status` until `state` is `complete` (`result` holds the descriptor) or `failed` (`error: { code, status, message }`). The outcome stays readable for one hour; repeating `upload-complete` on a finished session returns the stored outcome. The descriptor's `computed_hash` is the SHAKE-256 the node computed from the assembled object (equal to `media_id` by construction); `hash_mismatch` and `size_mismatch` carry `details: { expected, computed, size }` with what the node measured, since the assembled object is dropped on failure. Errors: `400` size_mismatch / hash_mismatch / assemble_failed, `403` signer_mismatch / signature_invalid, `404` session_not_found, `415` mime_disabled / format_unsupported.
4. `POST /v1/media/upload-abort/:session_id`, signature over `MEDIA_UPLOAD_ABORT:{session_id}:{timestamp}:{signer_tip_id}`, cancels an upload that is still `uploading`; `409` while finalizing.

#### `GET /v1/content/:ctid/media/:idx`
Fetch media bytes. Role-gated, signed. The public cannot fetch bytes (only the metadata on the content record).

**Headers:** `X-Requester-TipId`, `X-Timestamp`, `X-Signature` (ML-DSA over `MEDIA_ACCESS:{ctid}:{idx}:{timestamp}:{requester_tip_id}`).

Allowed callers: author (always), assigned reviewer (until the review closes), disputer (while the dispute lives), juror (until ADJUDICATION_RESULT), expert (until APPEAL_RESULT). Everyone else gets `403 forbidden`.

**Responses:** `200` raw bytes (local-fs node) or `200` JSON `{ presigned_url, expires_at }` (S3 node, fetch the URL within ~5 min); `307` redirect to the origin node (bytes live elsewhere, repeat the same signed request to `Location`); `410 media_unavailable` (retention-deleted, the hash on chain remains the proof).

---

### Identity keys

#### `GET /v1/identity/:tipId/keys`
Public key-rotation chain for an identity, oldest first: `{ tip_id, rotations, keys: [{ public_key, algorithm, valid_from_ts, valid_to_ts, source_tx_id }] }`. Used for client-side verification: `tip_id` anchors `shake256(keys[0].public_key)`, and each later key is introduced by the signed rotation tx in `source_tx_id`.

---

### Revocations

#### `GET /v1/revocations`
Get all current revocations.

**Response 200:**
```json
{
  "revocations": [
    {
      "tip_id":    "tip://id/US-revokeduser1",
      "tx_type":   "REVOKE_VOLUNTARY",
      "timestamp": "2026-03-15T00:00:00Z"
    }
  ]
}
```

#### `POST /v1/revocations`
Create a revocation. Requires admin auth.

**Request body:**
```json
{
  "tip_id":        "tip://id/US-a3f8c91b2d4e7021",
  "tx_type":       "REVOKE_VOLUNTARY",
  "reason":        "User requested permanent revocation",
  "requester_id":  "tip://id/US-a3f8c91b2d4e7021",
  "signature":     "[ML-DSA-65 signature over tip_id+tx_type]"
}
```

For `REVOKE_VP`, additionally include:
```json
{
  "evidence_hash":  "[SHAKE-256 of evidence document]",
  "issuing_vp_id":  "tip://id/VP-US-example"
}
```

---

### Deduplication (Privacy-Preserving)

#### `POST /v1/dedup/check`
Check if an identity is unique. Returns boolean only: never reveals the hash.

**Request body:**
```json
{
  "dedup_hash": "[peppered SHAKE-256 hash]",
  "zk_proof":   "[ZK proof of uniqueness]"
}
```

**Response 200:**
```json
{ "is_unique": true }
```

#### `GET /v1/dedup/merkle-root`
Get the current Merkle root of the dedup registry (published every 6 hours).

**Response 200:**
```json
{
  "merkle_root":  "[SHAKE-256 Merkle root hex]",
  "count":        423,
  "published_at": "2026-03-15T06:00:00Z"
}
```

---

### Verification Providers

#### `POST /v1/vp/register`
Register a new VP. Requires admin auth.

**Request body:**
```json
{
  "vp_id":              "tip://id/VP-US-example",
  "public_key":         "[ML-DSA-65 public key hex]",
  "jurisdiction_tier":  "GREEN",
  "country":            "US",
  "operator_name":      "Example Identity Services LLC"
}
```

#### `GET /v1/vp/:vpId`
Get VP details.

**Response 200:**
```json
{
  "vp_id":              "tip://id/VP-US-example",
  "status":             "active",
  "jurisdiction_tier":  "GREEN",
  "country":            "US",
  "operator_name":      "Example Identity Services LLC",
  "registered_at":      "2026-03-15T00:00:00Z"
}
```

---

## Rate Limits

| Endpoint Group | Limit (unauthenticated) | Limit (admin auth) |
|---------------|------------------------|-------------------|
| Read endpoints | 100 req/min per IP | 1000 req/min |
| Write endpoints | 20 req/min per IP | 200 req/min |
| Admin endpoints | N/A | 50 req/min |

---

## Error Format

All errors return JSON:

```json
{
  "error":   "description of the error",
  "code":    "machine-readable error code",
  "details": { "field": "additional context" }
}
```

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc. | TIPCL-1.0*
