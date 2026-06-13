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
- `403`: Author TIP-ID not active
- `422`: Invalid author signature

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

`media[]` carries public storage facts (type, size, whether the bytes are still stored) and the per-file AI score from the verdict. The bytes themselves are not here, fetch them via the role-gated media endpoint below. `ai_probability` is `null` until prescan completes.

#### `GET /v1/content`
List content, newest first. Cursor-paginated, public.

Query params (all optional): `author`, `origin`, `status`, `has_media`, `limit` (1-100, default 20), `cursor` (opaque token from a prior response's `next_cursor`).

**Response 200:** `{ "items": [ ...slim rows... ], "next_cursor": "..." | null }`. Each row carries `ctid`, `author_tip_id`, `origin_code`, `status`, `prescan_status`, `prescan_tier`, `media_count`, `registered_urls`, `registered_at`.

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

#### `POST /v1/content/:ctid/verify`
Manually verify a content record (jury-level participants only).

---

### Media

Media bytes are content-addressed (`media_id = SHAKE-256(bytes)`), stored off-chain per node, and access-controlled by adjudication role. Only the content-hash references live on chain. See [`docs/user-journeys`](user-journeys/) for the role-access model.

#### `POST /v1/media/upload`
Upload one file. Body is the raw bytes (`Content-Type: application/octet-stream`), one file per call, streamed.

**Headers:** `X-Media-Mime`, `X-Signer-TipId`, `X-Timestamp` (epoch ms, 5-min window), `X-Signer-Signature` (ML-DSA over `MEDIA_UPLOAD:{shake256(bytes)}:{mime}:{timestamp}:{signer_tip_id}`).

**Response 201:** `{ media_id, content_hash, mime, size, uploaded_at, signer_tip_id }`. The `mime` is SERVER-DETECTED from the file's magic bytes and is authoritative, use it (not your own label) when registering. Identical bytes always return the same `media_id` (dedup).

**Errors:** `400` timestamp_drift / bytes_required; `403` signature_invalid; `413` file_too_large (aborts mid-stream, sends `Connection: close`); `415` mime_disabled / format_unsupported.

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
