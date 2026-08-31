# TIP Protocol , Classifier API Interface

The contract between the TIP node backend and the AI classifier service: what
the node **sends**, what the classifier **returns**, and what the classifier
**does with the media URLs**.

Media is delivered **by reference** , the node sends presigned URLs, the
classifier downloads the bytes directly from storage. Text is sent inline.

## Transport

- Base URL: `TIP_CLASSIFIER_URL` (node env).
- Auth header: `X-TIP-Classifier-Key: <key>`.
- Content type: `application/json` both directions.
- Request/response (no webhook). The node calls from a background worker.

## Endpoint

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/prescan` | Pre-registration AI scan of OH content |

---

## POST /v1/prescan

### What the node sends

```json
{
  "text": "<title>\n\n<body>",
  "origin_code": "OH",
  "creator_cleared_count": 0,
  "author_tip_id": "tip://id/US-a3f8c91b2d4e7021",
  "provider_preference": "ensemble",
  "files": [
    {
      "media_id": "m_7f2a91bc",
      "mime": "image/png",
      "url": "https://<bucket>.s3.<region>.amazonaws.com/media/7f/2a91bc.bin?X-Amz-Algorithm=...&X-Amz-Signature=...&X-Amz-Expires=300"
    },
    {
      "media_id": "m_3d5e4a10",
      "mime": "video/mp4",
      "url": "https://<bucket>.s3.<region>.amazonaws.com/media/3d/5e4a10.bin?X-Amz-Algorithm=...&X-Amz-Signature=..."
    }
  ]
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `text` | string ≤ 100,000 chars | yes (may be `""`) | Text body. |
| `origin_code` | `OH \| AA \| AG \| MX` | yes | Only `OH` is scanned. |
| `creator_cleared_count` | int ≥ 0 | yes | Calibration input; `0` for new creators. |
| `author_tip_id` | `tip://id/XX-<16 hex>` | no | For logging. |
| `provider_preference` | string | no | Always `"ensemble"`. |
| `files` | array | no | One entry per media item; omit for text-only. |
| `files[].media_id` | string | yes (per file) | Echo this back in the result for attribution. |
| `files[].mime` | string | yes (per file) | `image/*`, `audio/*`, `video/*`. |
| `files[].url` | string | yes (per file) | Presigned GET URL. Plain HTTPS GET, no auth needed. |

A registration with N media items sends **one request** with N entries in
`files[]`. There is no fan-out and no base64.

### What the classifier does with the URLs

1. **Download each `files[].url`** with a plain HTTPS `GET`. No credentials, no
   headers , the signature is in the query string; S3 returns the bytes.
   Download the bytes **immediately on receiving the request** (before queuing
   heavy inference), so the URL is still valid (see TTL below).
2. **Run the modality** on each downloaded file (image / audio / video) and the
   text.
3. **Return one response** with a `modality_results[]` entry per file + text.
4. **Isolate per-file failures:** if a URL is unreachable, expired, or the file
   is unreadable, return that file's entry with a non-null `error` , do not fail
   the whole request. The other files still return results.

### What the node expects back

```json
{
  "probability": 0.6922,
  "modalities_analyzed": ["text", "image", "video"],
  "modality_results": [
    { "media_id": null,         "modality": "text",  "probability": 0.69, "weight": 0.5, "provider": "ensemble(...)", "error": null, "processing_ms": 1240 },
    { "media_id": "m_7f2a91bc", "modality": "image", "probability": 0.11, "weight": 0.3, "provider": "onnx-vision",    "error": null, "processing_ms": 830  },
    { "media_id": "m_3d5e4a10", "modality": "video", "probability": null, "weight": 0.0, "provider": "none",           "error": "download_timeout", "processing_ms": 0 }
  ],
  "provider_used": "ensemble(...)",
  "processing_ms": 2100
}
```

| Field | Node uses it? | Notes |
|---|---|---|
| `probability` | yes | 0..1, the blended verdict. |
| `modality_results[]` | yes | One per text + file. Always return the array. |
| `modality_results[].media_id` | yes | Echoes the `files[].media_id` (null for the text entry). Required for per-file attribution. |
| `modality_results[].probability` | yes | 0..1 for that modality; `null` when `error` is set. |
| `modality_results[].error` | yes | `null` = analyzed. Non-null (e.g. `download_timeout`, `unreadable`, `unsupported_mime`) = degraded; the node weights it down, never a pass. |
| `modality_results[].modality` / `weight` / `provider` | yes | Modality label, suggested weight, provenance. |
| `provider_used`, `processing_ms` | advisory | Telemetry / quality gate. |

The node computes the final tier/decision from `probability` using its own
protocol constants. The classifier does **not** decide flag/status/grace , it
returns evidence (probability + provenance + per-file error). This keeps the
classifier freely swappable without affecting consensus.

---

## Presigned URL TTL

The `files[].url` is a signed S3 link that expires after a fixed window (TTL).
After TTL seconds from when the node generated it, S3 returns `403`. Current
default: **300 s** (`TIP_MEDIA_PRESIGN_TTL_SEC`).

The URL only needs to live long enough for the classifier to **download** the
bytes , not to finish analyzing them. Once downloaded, the URL can expire.

### Download time (rough, at ~50-100 MB/s from S3)

| Media | Max size | Approx download |
|---|---|---|
| Image | 1 GiB | 10-20 s |
| Audio | 1 GiB | 10-20 s |
| Video | 15 GiB | 2.5-5 min |

---

## Errors

| Status | Meaning |
|---|---|
| 400 | No content supplied |
| 401 | Bad/missing `X-TIP-Classifier-Key` |
| 422 | Schema validation (bad origin, malformed id, oversize text) |
| 503 | All providers failed |

A per-file download/analysis failure is **not** a request error , it is
reported as a non-null `error` on that file's `modality_results[]` entry, with
the rest of the response intact.

## Media types

| Type | Delivery | Max size |
|---|---|---|
| Text | inline `text` | 100,000 chars |
| Image | `files[].url` | 1 GiB |
| Audio | `files[].url` | 1 GiB |
| Video | `files[].url` | 15 GiB |

These are the node's default per-mime caps (node-local, `TIP_MAX_*_BYTES`). The classifier's own `max_file_sizes` must be at least as large, or bigger files fail its download with `file_too_large` and the modality degrades.
