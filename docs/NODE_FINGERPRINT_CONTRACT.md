# Node contract: content fingerprints on `POST /v1/content/register`

What the VP web app now sends to the TIP node, and what the node must implement.
Only the **new** parts (`fingerprint_commit`, `fingerprints`) need work; everything
else is the existing CNA-2.2 register flow, unchanged.

Source of truth: `public/register-content.html`
(`buildCna22Payload`, `registerContent`, `buildFingerprintItems`, `packFingerprints`).

---

## 1. Request body (`application/json`)

```jsonc
{
  // ---- CNA-2.2 SIGNED payload (mirrored verbatim; the node reconstructs
  //      this exact object, canonicalises it, and verifies `signature`) ----
  "attribution_mode": "self",
  "authors": [
    { "key_mode": "attribution", "role": "byline", "signed": false,
      "tip_id": "tip://id/IN-xxxxxxxxxxxxxxxx", "tip_id_type": "personal" }
  ],
  "cna_version": "CNA-2.2",
  "content_hash": "<64-hex>",
  "extras": { "title": "<optional title>" },           // {} if no title
  "fingerprint_commit": "<64-hex>",                     // NEW. present only when fingerprints are sent
  "origin_code": "IN",
  "registered_urls": ["https://..."],                   // [] if none
  "signer_tip_id": "tip://id/IN-xxxxxxxxxxxxxxxx",

  // ---- auxiliary (NOT signed) ----
  "content": "<caption text, max 10000 chars>",
  "content_type": "text",
  "signature": "<ML-DSA-65 signature>",
  "media": [ { "media_id": "...", "mime": "image/png" } ],     // existing CNA-MIX-1 (optional)
  "media_canonical_hash": "<64-hex>",                          // existing (optional, with media)

  "fingerprints": { /* see §3 */ }                     // NEW. present only when there is something to fingerprint
}
```

`fingerprint_commit` and `fingerprints` are **both present or both absent**. They are
absent when nothing fingerprintable remains: no media, and the body text is empty or
not prose (e.g. an emoji-only or link-only caption that the library rejects). Such a
post still registers normally, just without dedup metadata, so the node MUST accept
their absence as valid (§6 step 5). They are also absent on any pre-fingerprint client.

---

## 2. The signature (what changes)

Unchanged mechanism: `signature = ML-DSA-65( shake256( canonical_json(signed_payload) ) )`,
verified against the signer's DAG-resident public key. `canonical_json` =
recursively sorted keys, no whitespace.

**The one change:** when `fingerprint_commit` is present in the body, the node MUST
include it (top-level) in the `signed_payload` it reconstructs before hashing. Sorted-key
order places it between `extras` and `origin_code`. If the node omits it, every
registration that carries fingerprints fails with `signature_invalid`.

Signed field set when fingerprints are present (9 fields):
`attribution_mode, authors, cna_version, content_hash, extras, fingerprint_commit, origin_code, registered_urls, signer_tip_id`

When absent, it's the existing 8 fields (do not inject the key).

---

## 3. The `fingerprints` envelope

```jsonc
{
  "profile": "cf-fingerprints-1",
  "count": 3,
  "commit": "<64-hex>",                  // == top-level fingerprint_commit (convenience copy; verify against the SIGNED one)
  "encoding": "gzip+base64",             // or "identity"
  "data": "<see below>"
}
```

Recover the fingerprints JSON string from `data`:

- `encoding == "gzip+base64"`: `json = gunzip( base64_decode(data) )`  (UTF-8)
- `encoding == "identity"`:   `json = data`  (already the JSON string; gzip-unavailable fallback)

`data` is gzipped because audio landmark arrays are large (~1.2 MB raw JSON for a
5-min song, ~220 KB gzipped). Video adds ~one 64-hex PDQ per second.

---

## 4. Commit verification (do this exactly)

```
recovered_json = recover(data, encoding)          # bytes as received, do NOT re-serialize
assert shake256(recovered_json) == fingerprint_commit   # the SIGNED top-level value
items = json_parse(recovered_json)
```

Hash the **decoded bytes directly**. Do NOT `json.dumps()` the parsed object and hash
that: the client commits over its exact serialized string, and Python/JS differ on float
formatting (e.g. `durationSec: 44.860952380952384`) and key order. Hashing received bytes
is byte-exact and order-exact (the item list is a JSON array, so sequence is preserved).

`shake256` = FIPS-202 SHAKE-256, 32-byte output, lowercase hex (same primitive as
`content_hash`). Python: `hashlib.shake_256(recovered_json_bytes).hexdigest(32)`.

---

## 5. Decoded `items` array

Ordered: `primary image → carousel[i] → extra[i] → audio → video → text unit(s)`.
Each item:

```jsonc
{
  "kind": "image" | "audio" | "video" | "text",
  "role": "primary" | "carousel" | "extra" | "audio" | "video"   // media
        | "caption" | "thread" | "thread_post",                  // text
  "index": 0,                  // present for role "carousel" / "extra" / "thread_post"
  "exact": "<64-hex>",         // the item's SHAKE-256 (file bytes); absent for text roles
  "perceptual": { /* verbatim library object, dispatch on .profile */ }
}
```

**The `exact` field** on a media item is the client-computed SHAKE-256 of the file bytes
(the same value bound at `/v1/media/upload`, and via `media_id` -> `media_canonical_hash`
-> `content_hash`). Treat the hash the node computed from the uploaded bytes as
authoritative; use `exact` only as the dedup-index key. They must be identical, since the
whole `fingerprints` blob is covered by the signed `fingerprint_commit`.

**Text roles (body prose only).** The text fingerprint covers only the BODY field
(caption / article body / post), never metadata (title, byline, section, wire, URLs).
Single-body posts emit one `caption`. Thread / multi-post content emits **two levels**:
- `thread`: all posts merged in order (catches whole/partial-thread copies; MinHash is
  set-based, so it tolerates small edits and reordered posts).
- `thread_post` (with `index`): one per post, so a single post lifted out still matches.

Tie `thread`/`thread_post` items to the registration via the ctid (threadId = ctid).

`perceptual` is the verbatim output of tip-content-fingerprint. Shapes (confirmed live):

```jsonc
// kind "text" (micro tier for short text, char tier otherwise):
{ "profile":"cf-text-3", "kind":"text", "tier":"micro", "exact":"<64-hex>" }
{ "profile":"cf-text-3", "kind":"text", "tier":"char", "shingle":"char-5", "shingles":96, "minhash":[ /* 128 ints */ ] }

// kind "image":
{ "profile":"cf-image-1", "kind":"image", "pdq":"<64-hex>", "quality":100 }

// kind "audio":
{ "profile":"cf-audio-landmark-1", "kind":"audio", "sampleRate":11025, "hop":512,
  "frames":966, "durationSec":44.86, "peakCount":669, "landmarkCount":5312,
  "landmarks":[ {"hash":6363204,"t":0}, /* ... */ ] }

// kind "video":
{ "profile":"cf-video-1", "kind":"video",
  "features":[ {"frame":0,"timestamp":0,"pdq":"<64-hex>","quality":83}, /* one per sampled second */ ] }
```

**Reject tier (library v2).** The client already drops these, so a well-formed request
won't contain them, but for robustness the node should ignore any item whose
`perceptual.tier === "reject"` (it carries `{ profile, kind, tier:"reject", reason }` and
no minhash/pdq/landmarks/features). `compare*` treats a reject as no-match regardless.

Note: `perceptual.kind` duplicates the item's top-level `kind`; both are present. For
matching/dedup use the library's own comparators (`compareText/Image/Video/Audio`,
profiles `cf-text-3 / cf-image-1 / cf-video-1 / cf-audio-landmark-1`) and thresholds.

---

## 5b. Full worked example (real values)

A single post with a primary image + one carousel image + audio + video + caption.
This is the **decoded** `fingerprints.data` (i.e. what you get after gunzip + parse).
Real `pdq` / `landmark` / `minhash` values from the library; big arrays truncated with
`...` for readability (they are sent in full).

```jsonc
[
  {
    "kind": "image", "role": "primary", "exact": "<64-hex of file bytes>",
    "perceptual": { "profile": "cf-image-1", "kind": "image",
      "pdq": "992f5b31de1330bb66a97e64e2450bc95bcd0d350fb48739f01172962af1f843", "quality": 100 }
  },
  {
    "kind": "image", "role": "carousel", "index": 0, "exact": "<64-hex of file bytes>",
    "perceptual": { "profile": "cf-image-1", "kind": "image",
      "pdq": "dd626c3731d93323c63764da19e6ce1e33d8d8cd471d93686c65313448eca653", "quality": 100 }
  },
  {
    "kind": "audio", "role": "audio", "exact": "<64-hex of file bytes>",
    "perceptual": {
      "profile": "cf-audio-landmark-1", "kind": "audio",
      "sampleRate": 11025, "hop": 512, "frames": 966,
      "durationSec": 44.860952380952384, "peakCount": 669, "landmarkCount": 5312,
      "landmarks": [
        { "hash": 6363204, "t": 0 },
        { "hash": 6375690, "t": 0 }
        // ... 5312 total
      ]
    }
  },
  {
    "kind": "video", "role": "video", "exact": "<64-hex of file bytes>",
    "perceptual": {
      "profile": "cf-video-1", "kind": "video",
      "features": [
        { "frame": 0, "timestamp": 0, "pdq": "c036bff938c1c00ecf303dd7018dc220ffd639c9c224f1123dc98ef4f513fd0b", "quality": 83 },
        { "frame": 1, "timestamp": 1, "pdq": "c836bfdb32c1c024cf303bdf40adcc203fd639cdc620f4923dcd9a74e412fd0b", "quality": 98 }
        // ... 22 total (one feature per sampled second at fps=1)
      ]
    }
  },
  {
    "kind": "text", "role": "caption",
    "perceptual": {
      "profile": "cf-text-3", "kind": "text", "tier": "char", "shingle": "char-5", "shingles": 56,
      "minhash": [ 6769377, 61990844, 38673283, 117418368, 8616698, 112901371 /* ... 128 total */ ]
    }
  }
]
```

A **thread** post (instead of `caption`) yields a merged unit plus one per post:
```jsonc
{ "kind":"text", "role":"thread",            "perceptual": { "profile":"cf-text-3", /* merged */ } },
{ "kind":"text", "role":"thread_post", "index":0, "perceptual": { "profile":"cf-text-3", /* post 0 */ } },
{ "kind":"text", "role":"thread_post", "index":1, "perceptual": { "profile":"cf-text-3", /* post 1 */ } }
```

Notes on variability:
- **Counts scale with the media.** `landmarks` ~150/sec for music (fewer for speech);
  `features` = ~one per second of video at fps=1; `minhash` is always 128 ints (char tier)
  or replaced by a single `exact` hex (micro tier, for very short captions).
- **Which items appear** depends on the post: a text-only post is just the `caption`
  item; a single-photo post is `primary` (+ `extra` items if more photos were added);
  a carousel is `carousel` items in slot order; audio/video posts add their item.
- **`index`** appears only on `carousel` / `extra` items.

---

## 6. Node checklist

1. Parse body as today.
2. If `fingerprint_commit` present, add it to the reconstructed CNA-2.2 signed payload,
   then verify `signature` as today (sorted-key canonical JSON, shake256, ML-DSA-65).
3. If `fingerprints` present: recover JSON per `encoding`, assert
   `shake256(recovered) == fingerprint_commit`, else reject (e.g. `fingerprint_commit_mismatch`).
4. `json_parse` and persist the `items` array, keyed to the new ctid, for dedup search.
5. Backward compatible: requests without `fingerprint_commit` / `fingerprints` behave
   exactly as before.

Reject `encoding` values other than `gzip+base64` / `identity`.

---

## 7. Payload sizing & limits

Fingerprint size is **independent of file resolution / byte size**. A 4K video and a
240p video of the same length produce the same fingerprint; a 50-megapixel photo and a
thumbnail both produce one 64-hex PDQ (~90 bytes). Only **duration** (audio/video) and
**item count** (photos) drive size, and the register UI allows at most **one audio + one
video** per registration (carousel/extra are images/documents only).

Measured on-wire sizes (gzip + base64, what lands in the JSON body):

| Case | on-wire |
|---|---|
| Video 10-min @1fps (4K or SD, identical) | ~5 KB |
| Video 30-min @1fps | ~13 KB |
| 50 photos (any megapixels) | <1 KB |
| Audio 5-min (dense music) | ~516 KB |
| Audio 30-min | ~3.1 MB |
| Audio 60-min | ~6.2 MB |
| Audio 120-min (cap) | ~12 MB worst case (~7 MB typical) |
| Worst realistic post (5-min audio + 10-min video + 20 photos) | ~522 KB |

**Limits in effect:**
- **Node:** register-body limit is **25 MB**.
- **Client:** audio is capped at **2 hours** at selection (`TipReg.AUDIO_MAX_SEC`);
  longer audio is rejected up front with a message. 2 h of dense music is ~7 MB on the
  wire (worst case ~12 MB), comfortably under 25 MB with room for the rest of the body.
  Video and images are not capped (their fingerprints are tiny at any size/length). If
  the audio cap or node body limit changes, change them in tandem.
