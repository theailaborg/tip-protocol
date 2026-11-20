# Site snapshots on the node: `SITE_SNAPSHOT` spec

Status: the record, its rules, state and API, pack ingest, the page lookup and similar search for site pages ("built") are implemented, not yet released, on tip-content-fingerprint 2.8.0 (vendored release tarball). Paragraph keys for ordinary posts ("next") wait for the library's `cf-text-4`. Consensus change, gated by an activation date. Part of the **Website Archive** project.

**Shared hosts cannot be protected.** `theailab.org` and `findtip.org` are in `SHARED_HOST_DOMAINS` (as are x.com, medium.com and the like), so no binding of them counts and a `SITE_SNAPSHOT` for them is refused (`site_not_protected`). A live test of the whole flow needs a site that can be bound: another domain, or a subdomain such as `archive-test.theailab.org`.

Tracking issue: #389.

Other repos involved:
- tip-content-fingerprint (library, profile `cf-web-1`)
- tip-site-archiver (capture service)
- tip-vp-with-mobile-web-app (VP)
- tip-site-archiver/viewer (viewer, its own deploy)

This document is self-contained for the node work.

---

## 1. Context

### What exists today
Website protection (node 2.8.0+):
- a site owner binds a domain (`REGISTER_DOMAIN` → `BIND_DOMAIN`, DNS TXT or well-known file);
- `siteOwnerOf()` in `validators/business-rules.js` makes the owner, or active members of the owning organization, the only parties allowed to register URLs of that site;
- owner takeover (from 2026-11-15) lets the owner win back a page URL registered by someone else;
- each protected page is a normal `REGISTER_CONTENT` record carrying the text hash plus client-supplied fingerprints (`cf-fingerprints-1`, bound by `fingerprint_commit`);
- similar search (`GET /v1/content/:ctid/similar`) uses the off-DAG perceptual index (`perceptual/*`).

### Problems
1. No whole-site, dated history; no versions.
   - URL exclusivity means the owner's own old record blocks re-registering a changed page (`url_already_registered`).
   - Takeover applies only to records by others.
2. One transaction, signature and billing call per page, so whole-site coverage does not scale.
3. Partial copies are missed. On the test cluster:
   - a whole-page repost was found at score 1.0 (and the copier was warned at registration);
   - a post that copied 3 paragraphs of a long page was not found: whole-text similarity 5%, containment 88%.

### What we are building (network side)
- **`SITE_SNAPSHOT` transaction.** It holds one Merkle root over the exact text of every page of a site at a point in time, plus the hash of the full archive (WACZ) and of the fingerprint pack. It is signed by the site owner and chained per domain (version history).
- **Off-DAG ingestion of each snapshot's fingerprint pack**, so similar search can return "page P of site D, snapshot S".
- **Paragraph keys plus key containment** (the share of a post's paragraph keys found on a page) for partial copies, for site pages and for ordinary text registrations.

**The node never crawls, renders or stores archives.** It stores records and indexes only. Capture happens in tip-site-archiver.

### Test evidence
On the test cluster (2026-11-14), these records were registered as stand-ins:
- snapshot root: `tip://c/OH-55f10785636a70-acbd`
- original page: `tip://c/OH-afc5f8dbf50aba-acbd`
- copies: `tip://c/OH-20571ea1b3c363-500b` (found) and `tip://c/OH-74352134d7d121-500b` (missed)

Hashing rules were validated on two captures of a 30-page site: same root, stable proofs.

---

### Where archives live
- **Nodes store no archive files.** The `SITE_SNAPSHOT` record holds the archive's hash (`wacz_hash`); the file is stored once per snapshot by the archive operator (the party running the capture service).
- **Node media buckets are unrelated.** They hold files uploaded through that node.
- **Independent captures by several nodes would never be byte-identical** (pages change on every request), so they could not share one record.
- **Packs are fetched by digest.** Nodes fetch fingerprint packs from the configured archive sources (`TIP_SITE_ARCHIVE_URLS`, comma-separated, tried in order) and check `pack_hash` before ingesting. Any byte-identical copy (the operator's bucket or a mirror) is acceptable.

## 2. Shared rules (from tip-content-fingerprint `cf-web-1`)

The node does not recompute roots; it stores and indexes them. Verifiers (viewer, VP) recompute with the library. For reference:

- **text hash** = `shake256(pageLines.join("\n"))`: every line of the page, trimmed, exactly as captured. This is what the proof binds;
- **page hash** = `shake256(tipNormalize(mainText))`, where main text = page lines minus the site template (lines on ≥60% of pages, only if ≥5 pages). For matching and "changed / unchanged" only, never evidence;
- **leaf** = `shake256("tip-web-leaf-v1\n" + canonicalUrl + "\n" + textHash)`;
- **parent** = `shake256("tip-web-node-v1\n" + left + right)`; leaves sorted by URL; an odd node is promoted;
- **pack** (`cf-site-pack-1`): gzip JSON lines with a header and per-page `{url, text_hash, page_hash, text, paragraph_keys, images[{media_id, pdq, quality}], screenshot_pdq}`; `pack_hash` = SHAKE-256 of the gzip bytes. A picture's `media_id` is SHAKE-256 of its bytes, the same as `POST /v1/media/upload`, so an archived picture matches the same picture registered on TIP.

**Every hash in the record and the pack is SHAKE-256, 32 bytes, hex**, the TIP rule (`shared/crypto.js`, `docs/CONTENT_SIGNING.md`). SHA-256 appears only inside the WACZ format, which the crawler writes (the file digests listed in `datapackage.json`, WARC record digests). A verifier goes from the record, to SHAKE-256 of `datapackage.json` (`wacz_hash`), to the SHA-256 of each file listed in it.

Golden vectors: `tip-content-fingerprint/test/web-vectors.json` (Test 1, theailab.org, 30 pages: root `15bb6f0d2d36256e0250b92e318c00f6098538002974be2ee62abafe68d01f8c`). The 2.8.0 package ships them and the Test 1 capture they name, so node tests replay Test 1 from `node_modules` (`require.resolve("tip-content-fingerprint/test/fixtures/web/theailab-test-1.json.gz")`).

Library version: the node bundles the v2.8.0 release tarball (`node/vendor/tip-content-fingerprint-2.8.0.tgz`, SHA-256 `8a630bc4ee5a3b3a35e96bf23386864298d17f54406f646645eb0c1a88aecf91`, the release asset's checksum). It keeps `cf-text-3` and the default LSH bands, and its exports map keeps the node's deep imports working; the full suite gives the same result on 2.7.1 and 2.8.0.

Library functions the node uses (2.8.0):
- **`web.readPack(bytes)`**, only after `shake256(bytes) === pack_hash`. It reads every gzip member (a pack written in several members loses no pages) and throws on a header whose `web_profile` is not `cf-web-1` or that lacks `domain` or `seq >= 1`.
- **`web.verifyPage(url, textHash, proof, root)`** whenever the node checks a page against a root (evidence, page reads). It recomputes the leaf from the URL and the text hash. `web.verifyProof(leaf, proof, root)` takes the leaf as given, so it proves nothing about the URL or the text unless the caller computed the leaf.

---

## 3. Transaction `SITE_SNAPSHOT`

### Fields
All timestamps are integer epoch ms. Every hash is SHAKE-256, 64 lowercase hex characters.

| Field | Type | Signed | Notes |
|---|---|---|---|
| `domain` | string | yes | the site's name, lowercase, without `www.` (both spellings are one site) |
| `seq` | int ≥ 1 | yes | previous + 1 |
| `prev_snapshot_tx` | tx_id or null | yes | null only for seq 1 (signed as null) |
| `root` | 64 hex | yes | Merkle root |
| `page_count` | int | yes | 1 to `SITE_SNAPSHOT.MAX_PAGES` (1,000,000) |
| `template_hash` | 64 hex | yes | |
| `profile` | string | yes | in `SITE_SNAPSHOT.PROFILES` (`cf-web-1`) |
| `wacz_hash` | 64 hex | yes | SHAKE-256 of the WACZ `datapackage.json` bytes |
| `pack_hash` | 64 hex | yes | SHAKE-256 of the pack's gzip bytes |
| `ai_signals_hash` | 64 hex | yes | SHAKE-256 of the robots.txt / AI-use capture |
| `captured_at` | int ms | yes | capture end time |
| `signer_tip_id` | tip id | yes | |
| `signature` (tx) | hex | n/a | the signer's ML-DSA-65 over the canonical payload |
| `witness_vp_id` + `cosignatures` | tip://vp id + `[{ signer_kind: "vp", signer_ref, signature }]` | no | optional witness: the capturing VP's ML-DSA-65 signature over the same canonical payload, as a VP cosignature (rule 7). The API takes it as `witness: { vp_id, signature }` |

**No storage URLs in signed bytes.** Locations can move; hashes do not.

### Signing (built)
- Same contract as other schema modules: `buildSigningPayload` → `canonicalJson` (sorted keys) → `sign` / `verifySignature`, with `SIGNATURE_SCOPE = body`, `SIGNED_BY = subject` and `SUBJECT_TIP_ID_FIELD = signer_tip_id`. The snapshot joins the signer's owner chain.
- Golden vectors: `node/tests/fixtures/signing-canonical-vectors.json` (`SITE_SNAPSHOT:base`, `SITE_SNAPSHOT:first`) and a frozen payload hash in `node/tests/integration/site-snapshot.test.js`. Per the signing-versioning policy, signed bytes are frozen once released.

### Rules (built; commit time, identical on every node)
Every rule is judged at max(tx.timestamp, certificate time), so a backdated tx can neither enter before activation nor skip the owner, chain and rate checks. The API applies the same rules at its own now.
1. **Activation:** before `SITE_SNAPSHOT.ACTIVATION_MS` the tx is refused at the API (`409 site_snapshot_not_open`) and rejected at commit.
2. **Signature** valid for the signer's key at the tx time (retired-key rules apply).
3. **Authority:**
   - the signer's TIP-ID is not revoked;
   - the domain has a live binding (`liveBindingFor`), and the signer is its owner or an active member of the owning organization (`mayPublishOn`);
   - phase 2 adds an authorised site key (see section 7).
4. **Chain:**
   - `prev_snapshot_tx` equals the domain's latest committed snapshot (null if none), and `seq = latest.seq + 1`;
   - the first valid snapshot in commit order wins, also within one batch; the other is rejected with the `tx_rejections` reason `site_snapshot_stale`.
5. **Rate:** at least `SITE_SNAPSHOT.MIN_INTERVAL_MS` (10 minutes) after the previous snapshot's tx time, and `captured_at` later than the previous snapshot's.
6. **Sanity:** the payload shape above; `captured_at` at most `SITE_SNAPSHOT.CAPTURE_SKEW_MS` (60 s) ahead of the commit time.
7. **Witness** (when `witness_vp_id` is present):
   - exactly one cosignature, `signer_kind: "vp"`, by that VP; cosignatures without `witness_vp_id` are refused;
   - the VP is registered and `active` in committed state;
   - its signature is verified by the unified dispatcher against the VP's key at the tx time (`getCosignatureContract`), like every cosignature;
   - a malformed witness or an inactive VP rejects the whole tx (`site_snapshot_witness_invalid`); a witness whose signature fails, or whose VP has no key, is rejected like any bad signature (`revalidation_failed`). It is never stored with the witness dropped, so a fake "captured by" claim cannot reach state.

### Activation gate (built)
- `shared/constants.js`: `SITE_SNAPSHOT.ACTIVATION_MS`, the mainnet date (provisional 2026-12-15 00:00 UTC, fixed at release).
- `validators/website-gate.js`: `siteSnapshotOn(atMs)`, beside the domain release gate. The env override `TIP_SITE_SNAPSHOT_ACTIVATION_MS` is honoured only when `NODE_ENV !== "production"` and warns at boot.

---

## 4. Code changes (by file)

| File | Change | State |
|---|---|---|
| `shared/constants.js` | `TX_TYPES.SITE_SNAPSHOT`; `SITE_SNAPSHOT` (activation, interval, capture skew, page cap, profiles, patterns, list cap); rejection reasons `SITE_SNAPSHOT_STALE`, `SITE_SNAPSHOT_WITNESS_INVALID` | built |
| `node/src/validators/website-gate.js` | `siteSnapshotOn`, `SITE_SNAPSHOT_MS` | built |
| `node/src/schemas/site-snapshot.js` (new) | `validateRequest`, `buildSigningPayload`, `buildTxData`, `checkSnapshot`, `checkWitness`, `getCosignatureContract`, `sign`, `verifySignature`, `verifyTx`. **All verification lives here**; the commit handler does not inline checks | built |
| `node/src/validators/business-rules.js` | exports `liveBindingFor` and `mayPublishOn` for the schema | built |
| `node/src/validators/tx-validator.js`, `node/src/tx-attribution.js`, `node/src/schemas/_schema-map.js` | wire shape, revoked signer at the API, signer as subject, schema registration | built |
| `node/src/consensus/commit-handler.js` | signer as actor; one snapshot per domain per batch; `verifyTx` at max(tx time, certificate time); write the `site_snapshots` row; map rejection text to the two reasons | built |
| `node/src/dag.js`, `node/src/db/knex-adapter.js` | `saveSiteSnapshot` (first write wins), `getSiteSnapshot(tx_id)`, `getLatestSiteSnapshot(domain)`, `listSiteSnapshots(domain, {before, limit})` on the memory, SQLite and Knex stores; a per-domain seq index in the memory map; state root, snapshot install, canonical delete and clear, parity probe | built |
| `node/src/db/migrations/017_site_snapshots.js` | table `site_snapshots(tx_id PK, domain, seq, prev_snapshot_tx, root, page_count, template_hash, profile, wacz_hash, pack_hash, ai_signals_hash, captured_at, signer_tip_id, witness_vp_id, registered_at)`, unique `(domain, seq)`; `registered_at` is the tx time, so every node writes the same row. `schema.sql` regenerated | built |
| `node/src/services/site-service.js`, `node/src/routes/site.js` (new) | `POST /v1/site/snapshot` (validate, plan check, submit), `GET /v1/site/:domain/snapshots`, `GET /v1/site/snapshot/:tx` | built |
| `node/src/services/website-pages-client.js` | `snapshotAllowed({owner_tip_id, signer_tip_id, domain, page_count})` → `POST /api/websites/snapshot` (same key, fails open, a refusal kept until `next_allowed_at`, epoch seconds) | built |
| `node/src/perceptual/site-ingest.js` (new) | after commit: fetch the pack by hash from each source in `TIP_SITE_ARCHIVE_URLS` (comma-separated, tried in order: `<source>/api/archive/pack/<pack_hash>`), check `shake256(bytes) === pack_hash`, read it with `web.readPack`, and require `header.domain === record.domain` and `header.seq === record.seq` (a pack is never ingested under another snapshot), the record's `page_count` leaf pages, and `web.packRoot(pages) === record.root` over every leaf line, off-site ones included (the owner signed all of them; packRoot also refuses a URL that appears twice, which would let the owner prove either of two texts). `web.readPack` stops at 256 MiB unpacked (a signed pack can be a gzip bomb, which the hash check cannot catch) and checks each gzip member's CRC-32 and length; the node also stops downloads at 64 MiB. A pack that fails these checks is recorded as `mismatch` (never retried, shown as not verified); an unreachable pack as `failed` (retried). **Off-site pages:** skip every page line whose URL host is not the record's domain or its `www.` host, and count and log them (a page that redirected to a login provider or a shop platform keeps its final URL; the archiver skips these, but the node does not trust every archiver; the pack arrives after commit, so this is an ingest rule, not a commit rule). Then ingest text bands, paragraph keys, picture `media_id` and PDQ under key `site:<tx_id>:<16 hex of SHAKE-256(url)>` (paragraph keys in `document_passage` under profile `cf-web-1`), and per page, against the previous snapshot's pack: `changed` (page_hash differs) and `kept` (share of the previous page's paragraph keys still present). Tables `site_page`, `site_ingest` (migration `018_site_pages`, node-local). Node-local, advisory, rebuildable; retries with backoff (wrong content is refused for good); a reconcile at start and every 10 minutes picks up snapshots installed by state sync; never blocks consensus | built |
| `node/src/routes/site.js`, `site-service.js` | `GET /v1/site/:domain/page?url=&at=` from the ingested pack, only for URLs on that domain (or its `www.` host); proofs checked with `web.verifyPage`; `GET /v1/site/snapshot/:tx` shows the ingest state | built |
| `node/src/perceptual/similar.js`, `matcher.js` | include site pages in candidates; score text by **key containment** when paragraph keys hit (shared keys divided by the post's keys; the node has no page text, so never the library's MinHash `containmentEstimate`), with **owner weighting**: a key held by many owners counts for little, from owner counts at run time (no list), as `compareDocument`'s `shared_text.score` does for documents. In a 13-site test (31,344 keys) the only keys shared between sites were 2 from the same embedded video player's help text on apnews.com and npr.org; ad copy that passes the block list behaves the same way. Site results come back apart from content (`sites` on `GET /v1/content/:ctid/similar`, `near_duplicate_sites` on register), one card per page at the latest snapshot that matched. Today documents query paragraph keys; posts match pages by text and pictures until `cf-text-4` | built |
| `node/src/services/content-service.js` | index paragraph keys for `REGISTER_CONTENT` text fingerprints too (partial copies for posts). The keys come inside the client's fingerprint envelope (new text profile `cf-text-4` from the library, bound by `fingerprint_commit`; theailaborg/tip-content-fingerprint#21, not started), so every node ingests the same keys; old profiles keep working without them | next |
| `docs/API.md` | site snapshot endpoints | built |

### Read API shapes
- `GET /v1/site/:domain/snapshots?before=&limit=` → `{ domain, snapshots: [{ seq, tx_id, root, page_count, captured_at, registered_at, wacz_hash, pack_hash, witness_vp_id }], next_before }` (built).
- `GET /v1/site/snapshot/:tx` → the full record with the owner's `signature` and `witness: { vp_id, signature } | null`, so a viewer can check both (built).
- `GET /v1/site/:domain/page?url=&at=` → `{ domain, url, seq, tx_id, captured_at, registered_at, root, text_hash, page_hash, leaf, proof, changed, kept }` from the ingested pack, or 404; only for that domain's URLs (built). `changed` alone is too coarse for news sites: between captures a few hours apart, npr.org and bbc.com/hindi kept almost no page hash (side lists and "2 hours ago" lines change, and they shift the template), while the share of paragraph keys kept on changed pages had a median of 88% and 92% (99-100% on Wix and Squarespace). `kept` (or MinHash similarity from the pack's text fingerprints) gives the VP history list a degree of change.

---

## 5. Tests
Built (`node/tests/integration/site-snapshot.test.js`, `tests/store-conformance.test.js`, `tests/db/migration-017-site-snapshots.test.js`, `tests/db/knex-adapter-site-snapshots.test.js`, signing vectors):
1. **Schema:** the exact 12 fields and a frozen payload hash; each malformed field refused with its code; changing any signed field breaks the signature.
2. **Rules:** owner and org member accepted; a stranger, a personal owner's site signed by an org member, and a removed member refused; unprotected and lapsed sites refused; wrong `prev` / `seq` and a replayed first snapshot are `site_snapshot_stale`; rate and `captured_at` rules; before activation refused, a backdated tx judged at the certificate time; revoked signer refused; each refusal checked for its reason.
3. **Witness:** a valid witness is stored and returned; a forged one refused at the API and at commit; an inactive or unregistered VP and a stray cosignature refused (`site_snapshot_witness_invalid`).
4. **Determinism:** two snapshots of one site in a batch keep the first; the memory and SQLite stores commit the same txs to the same `site_snapshots` sub-root; the incremental state root matches a full recompute.
5. **Store parity:** every primitive on the memory and SQLite stores, the Knex adapter (writes, parity probe, restart hydration with the same state root); migration up, down, up, and a schema.sql-first database.

Built for ingest, page reads and similar (`node/tests/integration/site-ingest.test.js` with the pack tip-site-archiver builds from Test 1, `tests/db/migration-018-site-pages.test.js`, store and Knex tests):
6. **Ingest:** the archiver's Test 1 pack matches its record (hash, header, 30 pages, golden root); a committed snapshot is fetched, indexed and served; a source that is down or serves other bytes is skipped for the next one; a pack that does not give the signed root, names another domain or seq, or lists a URL twice is `mismatch` and never retried; with no source holding the pack, ingest retries with backoff; a snapshot installed by state sync is found by reconcile; an off-site page stays in the root but is never indexed or served.
7. **Page reads and versions:** a URL on another domain answers 404; the served proof passes `web.verifyPage`; the next snapshot reports `changed` and `kept` per page; `at=` returns the snapshot covering that time, and a time before the first snapshot answers 404.
8. **Similar:** paragraph keys find the page, and a key a second site also holds counts half; a post carrying a page's text is warned at registration with the archived page (`near_duplicate_sites`).

## 6. Rollout
1. Test cluster with `TIP_SITE_SNAPSHOT_ACTIVATION_MS` 15-20 minutes ahead. Cross it, then commit snapshots from the archiver. Check identical roots and state on all nodes.
2. Release: tag, image, release notes naming the activation date. Every node operator upgrades before the date.
3. Watch the crossing (versions, one state root, no halt).

## 7. Phase 2 (separate activation): site keys
`SITE_KEY_GRANT` / `SITE_KEY_REVOKE`: the owner authorises a public key that may sign `SITE_SNAPSHOT` for one domain only, so automatic daily snapshots work without the owner present. The rule check accepts a live grant at tx time.

## 8. Related: owner release of a domain (needed by the VP "Remove" button)

**Status: done.** Shipped in node 2.9.9 (PR #388), active on mainnet since 2026-11-17 18:00 UTC (`DOMAIN_RELEASE_ACTIVATION_MS`). Test-cluster override: `TIP_DOMAIN_RELEASE_ACTIVATION_MS`. A release must be signed after the current binding (`409 release_before_binding`), and a released site accepts only a claim signed after its last binding (`409 claim_before_release`).
- The owner signs `{ action: "domain_release", domain, released_at, tip_id }` (canonical JSON, ML-DSA-65, the same helper as a domain claim).
- Request: `POST /v1/domain/release` with `{ domain, tip_id, released_at, signature }`.
- Responses:
  - `202` `{ released: true, confirmation: "proposed", tx_id }`;
  - `403 not_domain_owner` or a cosignature error;
  - `400 release_stale` (older than 15 minutes or ahead of now);
  - `404` no live binding;
  - `409 domain_release_not_open` before the activation.
- The commit rule is judged at max(tx.timestamp, certificate time), so a backdated tx cannot skip it. Tests: `node/tests/integration/domain-release.test.js` (16, including positive controls).

The design as planned:
- **What exists:** `UNBIND_DOMAIN` exists and applies (binding becomes `revoked`), with the reason `owner_revoked` defined, but there is no owner-facing route.
- **Add `POST /v1/domain/release`:** the owner (or an active member of the owning org) signs `{domain, released_at}`. The node checks the signature and emits `UNBIND_DOMAIN` with `reason: owner_revoked`, carrying the owner's signature.
- **Commit rule:** an `owner_revoked` unbind is valid only with a valid signature from the binding's owner at tx time. This is a rule change, so it ships behind an activation date (it can share one with `SITE_SNAPSHOT`).
- **Tests:**
  - an owner release revokes;
  - a release signed by anyone else is rejected;
  - a released domain can be bound again by whoever proves control.
