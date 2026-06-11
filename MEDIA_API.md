# Media API: client implementation guide

How a client (web UI, WordPress plugin, browser extension, SDK) uploads
media, registers content that references it, and fetches it back. Written
against the live node API; every value here matches the schemas in
`node/src/schemas/`.

The flow has three calls:

```
1. POST /v1/media/upload                 -> media_id (per file)
2. POST /v1/content/register             -> ctid (text + media refs)
3. GET  /v1/content/:ctid/media/:idx     -> bytes / presigned URL (role-gated)
```

## Prerequisites

- The user has a registered TIP identity (`tip://id/...`) and its ML-DSA-65
  private key on the client.
- Hashing is SHAKE-256 with 32-byte output, hex-encoded (64 chars). Use
  `shared/crypto.js` (`shake256`, `mldsaSign`) or any compliant library.
- All signed timestamps are **integer epoch milliseconds** (never ISO
  strings). Responses convert ms to ISO 8601 for display fields.
- Every response is wrapped in the standard envelope:
  `{ ok, status, data }` on success, `{ ok: false, status, error: { message, code, request_id } }` on failure.

## 1. Upload: `POST /v1/media/upload`

Upload the raw bytes of ONE file. Repeat per file (max 4 per content).

### Request

Body: the raw file bytes, streamed (`Content-Type: application/octet-stream`).
Do NOT base64 or wrap in JSON.

Headers:

| Header | Value |
|---|---|
| `Content-Type` | `application/octet-stream` |
| `X-Media-Mime` | real mime of the file, e.g. `image/png` |
| `X-Signer-TipId` | uploader's `tip://id/...` |
| `X-Timestamp` | integer epoch ms, must be within 5 minutes of server time |
| `X-Signer-Signature` | ML-DSA signature over the challenge below |

### The signed challenge

The client must hash the file BEFORE uploading and sign this exact string:

```
MEDIA_UPLOAD:{content_hash}:{mime}:{timestamp}:{signer_tip_id}
```

where `content_hash = shake256(file_bytes)` (64-char lowercase hex).
The server recomputes the hash from the bytes it actually receives and
verifies the signature against THAT, so you cannot claim bytes you did
not send.

```js
const bytes = await file.arrayBuffer();
const contentHash = shake256(Buffer.from(bytes));            // 64-hex
const timestamp = Date.now();                                 // integer ms
const challenge = `MEDIA_UPLOAD:${contentHash}:${file.type}:${timestamp}:${tipId}`;
const signature = mldsaSign(challenge, privateKey);           // hex

const res = await fetch(`${NODE}/v1/media/upload`, {
  method: "POST",
  headers: {
    "Content-Type": "application/octet-stream",
    "X-Media-Mime": file.type,
    "X-Signer-TipId": tipId,
    "X-Timestamp": String(timestamp),
    "X-Signer-Signature": signature,
  },
  body: bytes,
});
```

For upload progress bars use `XMLHttpRequest` (its `upload.onprogress`
fires per chunk); `fetch` cannot report upload progress.

### Response `201`

```json
{ "ok": true, "status": 201, "data": {
    "media_id": "3a867c...e7a14090",
    "content_hash": "3a867c...e7a14090",
    "mime": "image/png",
    "size": 2361613,
    "uploaded_at": "2026-06-11T08:24:01.000Z",
    "signer_tip_id": "tip://id/AU-..."
} }
```

`media_id` always equals `shake256(bytes)`. Uploading identical bytes
again (any user) returns `201` with the same `media_id`; deduplication is
free and safe to rely on.

**The `mime` in the response is authoritative and may differ from your
header.** The server derives the type from the file's magic bytes (png,
jpeg, gif, webp, mp3, wav, ogg, flac, mp4, webm) and stores THAT - the
client's declaration is never trusted for storage, size caps, or
classification. Always use the response `mime` in `media[]` when
registering. Bytes in an unrecognized container are rejected with
`415 format_unsupported`.

### Limits (genesis constants)

| Type | Limit |
|---|---|
| `image/*` | 5 MB |
| `audio/*` | 10 MB |
| `video/*` | disabled in v1 (always `415 mime_disabled`) |
| anything else (`application/pdf`, ...) | `415 mime_invalid` |
| files per content | 4 (`media_items_max`) |

### Errors

| Status | code | Meaning / client action |
|---|---|---|
| 400 | `timestamp_drift` | clock skew > 5 min; resync and retry |
| 400 | `bytes_required` | empty body |
| 403 | `signature_invalid` | challenge mismatch: wrong hash, mime, ts, or key |
| 403 | `signer_inactive` / `signer_revoked` | identity not active |
| 404 | `signer_not_found` | identity not registered on this node |
| 413 | `file_too_large` | over the per-mime cap. The server aborts mid-stream and replies with `Connection: close`; open a NEW connection for the next request |
| 415 | `mime_invalid` / `mime_disabled` | claimed type malformed or family disabled |
| 415 | `format_unsupported` | the BYTES are not a recognized media container |

## 2. Register content with media: `POST /v1/content/register`

Same endpoint and signing flow as text-only registration (see
`docs/CONTENT_SIGNING.md` for the base contract); media adds two fields.

### Added fields

```json
{
  "...all normal register fields...",
  "media": [
    { "media_id": "3a867c...90", "mime": "image/png" }
  ],
  "media_canonical_hash": "9f2bf4...d7"
}
```

- `media[]` order matters and is part of what you sign.
- Every `media_id` must have been uploaded already (else `404 media_not_found`).
- `mime` must match what was uploaded (else `400 media_mime_mismatch`).
- Media-only posts (no text) are allowed: omit `content`.

### Hash derivation (CNA-MIX-1)

The signed `content_hash` commits to text AND media together:

```
mch          = shake256( media_id_0 + media_id_1 + ... )      // plain string concat, in media[] order
text_hash    = shake256( tipNormalize(text) )                  // shake256("") when media-only
content_hash = shake256( mch + text_hash )                     // string concat of the two hex strings
```

Set `media_canonical_hash = mch` in the body. The server re-derives both
and rejects any mismatch, so the same text with different media always
produces a different `ctid` and nobody can swap media references after
signing.

### Response `202`

Normal register response: `{ ctid, prescan_status: "pending", ... }`.
Poll `GET /v1/content/:ctid/prescan_status` as usual; image/audio
modalities are scanned by the classifier alongside the text.

## 3. Fetch media: `GET /v1/content/:ctid/media/:idx`

Role-gated: only callers with standing on the content can read media.

| Allowed | While |
|---|---|
| author | always |
| assigned reviewer | review open (TRIGGERED/CONFIRMED), until dismissed/resolved |
| disputer | their dispute exists |
| juror | summoned, until ADJUDICATION_RESULT |
| expert reviewer | appeal summoned, until APPEAL_RESULT |

Everyone else gets `403 forbidden`. There are no public media URLs.

### Request

`idx` is the position in the content's `media[]` (0-based).

| Header | Value |
|---|---|
| `X-Requester-TipId` | caller's `tip://id/...` |
| `X-Timestamp` | integer epoch ms (5-minute window) |
| `X-Signature` | ML-DSA over `MEDIA_ACCESS:{ctid}:{idx}:{timestamp}:{requester_tip_id}` |

The challenge binds the ctid, so a signature for one content cannot be
replayed against another.

### Responses: a client MUST handle all four shapes

| Status | Shape | Client action |
|---|---|---|
| 200, `Content-Type: image/*` etc. | raw bytes | render directly (node on local-fs storage) |
| 200, JSON `{ media_id, mime, presigned_url, expires_at }` | presigned link | fetch `presigned_url` (plain GET, no headers) within ~5 min; render result (node on S3 storage) |
| 307, `Location: https://other-node/...` | redirect | re-issue the SAME request (same signed headers) to `Location`; the bytes live on the content's origin node |
| 303, JSON `{ code: "media_remote", available_at_node_id }` | origin known but unreachable | resolve that node's endpoint out of band, or surface "media on another node" |
| 410, `code: media_unavailable` | gone | retention-expired or deleted; show placeholder. The on-chain `media_id` still proves what the bytes were |

Integrity check (recommended): after downloading, verify
`shake256(downloaded_bytes) === media_id`. The filename IS the proof.

### Retention: when 410 starts appearing

| Case | Bytes deleted after |
|---|---|
| never disputed | 21 days from registration |
| adjudicated (no appeal) | 7 days after ADJUDICATION_RESULT |
| appealed | 7 days after APPEAL_RESULT |

Uploaded-but-never-registered media is swept after ~24h; register
promptly after upload.

## Reference implementation

The integration tests exercise every call and error in this document and
are the canonical examples until the SDK ships media helpers:

- `node/tests/services/media-service.test.js` (upload, streaming, dedup, fetch)
- `node/tests/routes/media-access-route.test.js` (all four access response shapes)
- `node/tests/schemas/content-register.test.js` (CNA-MIX-1 derivation)

Challenge builders live in `node/src/schemas/media-upload.js`
(`buildChallenge`) and `node/src/schemas/media-access.js`; clients can
copy them verbatim.
