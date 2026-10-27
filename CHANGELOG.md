# Changelog

All notable changes to TIP Protocol are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed

**Node 2.8.1: a flagged post is no longer reassigned to reviewers forever**
- A HIGH/CRITICAL post whose assigned reviewers kept missing the 48 h SLA was
  reassigned every window with no end: one mainnet post went through 48
  assignments in three months, nobody acted, and nothing downstream could
  fire because escalation only follows a reviewer's decision. Once a post
  carries `PRESCAN_REVIEW_CAP.MAX_NO_SHOWS` (3) `sla_expired` recusals, the
  trigger stops assigning and emits a node-signed `PRESCAN_REVIEW_CONFIRMED`
  (`auto: true`, no reviewer, suggested origin AG). That opens the creator's
  existing 24 h window: accept the correction (-10) or let the existing
  auto-escalation file the dispute. History counts, so a post already past
  the cap closes on the first round after activation.
- A no-show auto-confirm pays no reviewer bonus on accept-correction, and the
  jury's reviewer bonus/clawback already skip a review without a reviewer.
- Commit rule change, gated on the round's cert timestamp:
  `PRESCAN_REVIEW_CAP.ACTIVATION_MS` (2026-11-08 00:00 UTC), every node on
  2.8.1 before then. `TIP_PRESCAN_REVIEW_CAP_ACTIVATION_MS` overrides it on an
  isolated cluster (warning-logged).

### Added

**Node 2.8.1: review desk, a named reviewer can take over an open review**
- Roster members of the genesis organization (the AI Lab on mainnet) holding
  the `reviewer` role form the review desk. A desk member takes over any open
  review at once with a reviewer-signed `PRESCAN_REVIEW_CLAIMED`
  (`POST /v1/reviews/:id/claim`): the open slot closes as `claimed_over`, which
  is not a no-show for the replaced reviewer, and a new slot opens assigned to
  the claimer with its SLA starting at the certificate time.
- Nobody claims a post they signed or are listed on as an author. Another
  org's `reviewer` role grants nothing, and nobody assigns a reviewer to
  someone else. Desk membership is managed with the existing roster invite,
  accept and remove flow.
- `GET /v1/reviews/open` lists open assignments with their idle time; with
  `?reviewer_tip_id=` each row says whether that person may claim it.
- Commit rule change, shipped with the no-show cap under the same
  `PRESCAN_REVIEW_CAP.ACTIVATION_MS` (2026-11-08 00:00 UTC).

**Node 2.8.0: website protection and owner takeover (consensus, two activation dates)**
- Website protection, active from **2026-11-01 00:00 UTC**
  (`WEBSITE_PROTECTION_ACTIVATION_MS`): a personal TIP-ID may bind a domain as
  well as an organization; a live binding stops any other signer registering
  that site's pages; `www.x` and `x` count as one site; a binding past its
  `expires_at` no longer blocks a new owner. Domains where many people publish
  under one name (`SHARED_HOST_DOMAINS`: x.com, github.io, medium.com, ...) never
  protect pages.
- Owner takeover, active from **2026-11-15 00:00 UTC**
  (`URL_TAKEOVER_ACTIVATION_MS`): the owner of a protected site (or an active
  member of the owning organization) registering one of its pages takes the
  address over from a record by anyone else; that record keeps its CTID but
  loses the address. Content transactions carry the new `url_takeovers` field
  only from this date.
- Both rules are judged on the later of `tx.timestamp` and the certificate
  time, so every node decides the same way; before the dates the node behaves
  exactly as 2.7.9 (no new field, same validity, same state root), which is
  what makes a rolling upgrade safe. **Every node, partners included, must run
  2.8.0 before 2026-11-01 00:00 UTC.**
- Optional website page allowance at registration, asked of the operator's
  billing service (`TIP_WEBSITE_PAGES_URL` / `_KEY` / `_TIMEOUT_MS`, falling
  back to the media quota URL and key). Unreachable billing lets the page
  through.

**`scripts/upgrade-node.sh`**: the gated one-node upgrade we run on every
release (checkout tag, rebuild, stop, root gate against an untouched peer,
start only on MATCH, wait for `/ready`), committed instead of living in `/tmp`
on each box.

### Changed

**Operator runbooks leave the public repo.** Node registration, key
distribution, S3 setup, log shipping and partner emails are now delivered by
The AI Lab team as part of a guided join; `docs/DEPLOYMENT.md` describes the
process and the requirements. `make-secure-bundle.sh` also accepts Ubuntu's
`7z`, `register-org.js` prints the org type, and the unmaintained
`seed:python` script is gone.

### Fixed

**Node 2.8.0: the reg-credit cap epoch default is the mainnet epoch**

`REGISTER_CREDIT.CAP_ENFORCE_ACTIVATION_MS` now equals the epoch mainnet
activated the cap with (2026-07-23 20:00 UTC), which the fleet had been pinning
through `TIP_REG_CREDIT_CAP_ACTIVATION_MS`. A new node no longer needs that env
line (or `register-node.js --reg-credit-activation-ms`) to agree with the
fleet; the override stays for networks that activated at another time. No
behaviour change on nodes that already carry the env value. `.env.example` and
the registration and deployment docs drop the "read it off a node" step.

### Added

**Node 2.7.9: built-in status page and public node registry**
- `GET /status` on every node: one page, no key, refreshed every 3 s, showing
  this node (id, version, uptime, join state, endpoint, memory, chain id),
  the chain (round, committed round, state root, committee, mempool), a
  checklist that turns green only when the node is reachable, the database
  reads, consensus runs, it is caught up, there is no fork halt, it has peers,
  at least one of them is a genesis node, every peer shares its state root,
  rounds advance and its endpoint is announced, and a peer table with the
  registry name, rounds, root and whether it agrees with this node.
- `GET /v1/nodes`: the on-chain node registry (id, name, status, endpoint,
  operator, founding flag, registered_at), never keys. Feeds the page and
  replaces the hand-kept node sheet.

### Changed

**Node 2.7.8: posts self-disclosed as AA/AG/MX are scanned too**
- The prescan skipped every non-OH registration and wrote the neutral 0.5
  verdict (`classifier_providers_used: skipped_locally`), which the public
  record shows as a plain 0.5 nobody can tell from "uncertain". The
  classifier now scores every origin; the result is information only, non-OH
  posts are never sent to a reviewer. `TIP_CLASSIFIER_SCAN_NON_OH` defaults to
  `true` in the template and the client; `false` restores the skip.

### Added

**Node 2.7.7: fewer fingerprint prompts during media upload.**

**Node 2.7.6: optional biometric commitment on identity registration**
- `REGISTER_IDENTITY` accepts an optional VP-signed `biometric_commit` (64-char
  lowercase hex, a SHAKE-256 commitment the VP computes over its off-DAG face
  template). The node treats it as opaque: validated for shape, bound into the
  signed payload with the strip-when-absent rule, mirrored onto `tx.data`,
  persisted on `identities` in every store and projected into
  `state_merkle_root`. Identities without a commitment sign and canonicalize
  byte-identically to before, so existing records and roots are unchanged.
- Migration `014_identity_biometric_commit` adds the nullable column.
- Rollout: every node must run 2.7.6 before the VP enables biometrics
  (`VP_BIOMETRIC_ENABLED`). A node on an older build drops the field when it
  rebuilds the signed payload, rejects the VP signature and forks on that
  registration; there is no activation epoch, the fleet upgrades first.

### Fixed

**Node 2.7.5: team seats hold under simultaneous accepts**
- Plan seats are enforced at the API, and the check counted only committed
  members, so several people accepting at once could each find a free seat and
  all commit (a free org could reach 6 members, Team 5 could reach 15).
  Admission now runs one at a time per org and counts this node's relayed but
  uncommitted acceptances and invites, released when the row lands or after
  120 s.
- The seat client shares one request among concurrent callers, answers from
  memory for 30 s after a failed call instead of waiting out the timeout
  again, evicts least recently used, and `peek` refreshes in the background.
- A `TIP_ORG_SEATS_ACTIVATION_MS` override logs a warning on start: it is a
  consensus gate and forks a node whose value differs from the fleet.

### Added

**Node 2.7.4: 2 free team seats, paid seats from the operator's billing service**
- Consensus seat ceiling: 1 member before `ORG_MEMBERS.SEATS_ACTIVATION_MS`
  (2026-10-19 16:00 UTC), `MAX_MEMBER_LIMIT` (250) from then on, decided by the
  tx timestamp. A commit-rule change: every node must run 2.7.4 before the
  activation, or it rejects a second member and forks.
  `TIP_ORG_SEATS_ACTIVATION_MS` overrides it on an isolated cluster only.
- Inside the ceiling, seats are operator policy at the API. With a billing
  service configured (`TIP_SEATS_URL`/`TIP_SEATS_KEY`, defaulting to the media
  quota url and key) the node asks `POST /api/team-seats/check` and admits
  invites and acceptances only within the org's allowance; without one every
  org gets `FREE_MEMBER_LIMIT` (2). Past it: `409 member_limit_reached` with
  `details: {limit, plan, upgrade_url}`. `GET /identity/:org/members` adds
  `plan` and `upgrade_url`.
- An outage never takes seats away (last known answer, else free), and a
  lapsed plan removes nobody.

**Node 2.7.3: optional monthly media allowance at upload-init**
- With `TIP_MEDIA_QUOTA_URL` and `TIP_MEDIA_QUOTA_KEY` set, a chunked upload
  asks the operator's billing service (`POST /api/media-quota/check`) before
  any bytes move and refuses with `402 media_quota_exceeded` (month's bytes
  used up), `413 file_too_large_for_plan` (single file over the plan) or
  `429 monthly_file_limit_exceeded` (new files this month, counted per TIP-ID
  type). Verified uploads are reported afterwards (`/record`), in the
  background with retries; the same `content_hash` counts once a month. The
  node's own per-type size caps still apply first. Unset, nothing changes:
  other operators are unaffected.
- The service is called fail-open: unreachable, an upload goes through unless
  a fresh answer for that TIP-ID was remembered. A remembered answer is dropped
  once its month reset or it aged past `MEDIA_QUOTA_CLIENT.LAST_KNOWN_TTL_MS`,
  so last month's zero can never refuse this month's uploads during an outage.
- Env is read in `config.mediaQuota`; timing constants live in
  `MEDIA_QUOTA_CLIENT`.

### Fixed

**Node 2.7.2: actionable error for the released extension's passkey path**
- Browser extensions up to v2.9.41 mark authors `signed: true` on the passkey
  path without attaching a co-signature, which the roster release refuses
  (`author_cosignature_missing`). The refusal stays, since the flag is a
  false claim inside the signed bytes; the message now tells the user to
  update the extension instead of quoting the raw check.

**Node 2.7.2: a retired signing key can no longer sign through a backdated transaction**
- Signing keys resolve at `tx.timestamp` so that history keeps verifying after
  a rotation or recovery. Nothing checked whether that key was still current
  when the round certified, so a node bypassing the API could commit a
  transaction signed with a rotated-away or recovered-from key by dating it
  inside the old key's window (the API path was never affected: it stamps the
  time itself and checks the active key). At commit, the key resolved for the
  signer and every cosigner must not have been retired more than
  `KEY_RETIREMENT_GRACE_MS` (6 min, mempool TTL plus a round) before the
  round's certificate time; otherwise the transaction is rejected as
  `signer_key_retired`. A key closed by `KEY_RECOVERY` gets no grace at all
  (it was lost or stolen), the grace applies only to a planned `KEY_ROTATED`.
  Honest transactions are not age-bounded: one that waited out an outage
  still commits unless its key was retired meanwhile.
  New reject rule, so gated on `KEY_RETIREMENT_ACTIVATION_MS`, pinned to the
  mainnet activation 2026-10-09 00:00:00 UTC (`TIP_KEY_RETIREMENT_ACTIVATION_MS`
  overrides it on an isolated cluster). Every node, partner nodes included,
  must run 2.7.2 before that epoch.
- Closing the loophole around that rule: a `KEY_ROTATED` could park
  `effective_at` years ahead, and a later recovery closed only the one open
  row, leaving the old key's window intact. From the same activation,
  `KEY_ROTATED` / `KEY_RECOVERY` clamp every window of the identity that is
  still open past `effective_at`, and a rotation may schedule itself at most
  `KEY_ROTATION_MAX_LEAD_MS` (24 h) ahead (`effective_at_too_far`; enforced at
  the API immediately, at commit from the activation). From the same
  activation a `KEY_ROTATED` must be signed by the active key itself
  (`signer_not_active`), closing the backdated take-over inside the grace.
- Catch-up replay (`replaySyncedTxs`) now judges each round by the BFT time of
  the anchor that committed it, the same clock the live path used, and leaves
  rounds no anchor has committed to bullshark instead of deciding them early
  without one.
- `KEY_ROTATED` / `KEY_RECOVERY` close prior key rows via the identity's key
  history instead of writing through a live full-table cursor, which failed
  on SQLite-backed nodes.

### Changed

**Node 2.7.1: organization roster activation pinned to 2026-10-07 16:50:00 UTC**
- `ORG_MEMBERS.ACTIVATION_MS` now carries the mainnet activation epoch, so a node
  needs no `TIP_ORG_MEMBERS_ACTIVATION_MS` override to agree with the fleet.

### Added

**Node 2.7.0: organization roster (`ORG_MEMBER_INVITED` / `ORG_MEMBER_ADDED` / `ORG_MEMBER_REMOVED`)**
- An organization can invite a registered personal TIP-ID onto its roster;
  the person accepts by signing their own tx that references the invite, so
  both consents are on chain and any node can list a person's open invites,
  whichever VP issued either identity. Either party ends a membership alone.
- Rows live in the new canonical `org_members` table (migration 012, in the
  state root). An invite is usable for 7 days after its tx and never takes a
  seat; the seat limit (`ORG_MEMBERS.FREE_MEMBER_LIMIT`, 1) is enforced when
  the acceptance commits, so an invite sent while a seat was free fails with
  `member_limit_reached` if the seat is gone by then. Open invites per org are
  capped at three times the seat limit. Roster changes are score-neutral.
- `GET /v1/identity/search?q=&limit=&type=`: type-ahead for the invite box, TIP-ID prefix or name substring, active personal identities by default.
- Byline read model: `GET /v1/content/:ctid` adds `publisher` (the signer) and
  `authors_resolved` (every author with name, type, tier, `member_role` from
  the signer org's roster, and `relationship`: `signer` | `member` | `listed`); `GET /v1/content?bylined=<tip_id>` lists
  posts that credit an identity without being its `author_tip_id`, and list
  rows carry `signer_tip_id`, `attribution_mode`, `publisher_name`;
  `GET /v1/identity/:id` adds `bylined_count`. The `author`/`bylined` filters
  now accept three-letter region codes.
- A member author's signed `authors[].role` is what they did for that post,
  chosen at publish time from the roster vocabulary (`412 author_role_invalid`
  otherwise); it need not match their team title, which `authors_resolved`
  reports as `member_role`. The signer's own entry and co-authors on personal
  posts keep a free `role`.
- Roster roles are a locked set (`author`, `editor`, `contributor`, `reviewer`,
  `correspondent`; labels only, no permission attached); any other value is
  `role_invalid`. `GET /v1/identity/:org/members` returns the allowed `roles`.
- API: `POST /v1/identity/:org/members/invite`, `POST /v1/identity/:member/members/accept`,
  `POST /v1/identity/:signer/members/remove`, `GET /v1/identity/:org/members`
  (`?include=removed`), `GET /v1/identity/:member/invites`,
  `GET /v1/identity/:member/memberships`; `GET /v1/identity/:id` adds
  `members {active, limit}` for organizations and `member_of` for people.
- `ORG_MEMBER_INVITE_CANCELLED`: the organization cancels an open invite or
  the invitee declines it (`POST /v1/identity/:signer/members/cancel-invite`);
  the row becomes `cancelled`, can no longer be accepted and no longer counts
  as an open invite.
- Invite replay guard: a committed invite's body signature is public, so the
  signed `invited_at` must lie within the claim window of the tx at commit
  and is stored on the row (`invited_claim`, migration 013); the same signed
  invite is refused a second time (`invite_replayed`). Invites per
  organization are capped per rolling 24 h, any status (`invite_rate_limited`),
  so invite/cancel loops cannot grow the table. An `authors[]` entry that
  claims a co-signature (`signed: true` or `key_mode: "co_signed"`) without one
  in the envelope is refused (`author_cosignature_missing`); co-signatures are
  not implemented, so the chain no longer records the false claim. The signed `accepted_at` /
  `claimed_at` of acceptances, removals and cancellations are held to the same
  window at commit, so a relayer cannot re-wrap a rejected acceptance later or
  backdate `tx.timestamp` past an invite's TTL. Open and daily invite caps
  are also counted inside a single batch, a cancel ordered before an accept of
  the same invite wins, and a revoked identity can no longer be listed as an
  author. A malformed `TIP_ORG_MEMBERS_ACTIVATION_MS` refuses to boot instead
  of silently using the default.
- Content registration: an organization may list as `authors[]` only itself
  or its active members, and an organization can appear as an author only on
  content it signs itself (nobody attributes content to another org); any
  other author is refused with `412 invalid_author`
  at the API and dropped at commit. `authors[]` is capped at
  `MAX_AUTHORS_PER_POST` (10, the spec value). The author checks (on-DAG,
  type match, roster) now also run at commit, where previously no author
  check ran at all. Nothing in the signed CNA-2.2 payload changes.
- Rollout: the three tx types and the author rules are new commit rules, so
  every node applies them only from `ORG_MEMBERS.ACTIVATION_MS`
  (`TIP_ORG_MEMBERS_ACTIVATION_MS` overrides it on an isolated cluster).
  Upgrade the whole fleet before that epoch.

### Fixed

**Node 2.6.6: gossip queued for one peer is bounded; a stalled reader is redialed**
- gossipsub keeps one outbound queue per peer and its default cap is
  unlimited. A peer that stays connected but stops reading its gossip stream
  (alive enough to answer pings and send requests) made every other node queue
  each batch, certificate and ack for it without bound, outside the V8 heap.
  On mainnet (2026-10-03) a halted partner node in that state grew every peer
  by ~90 MB/min; node 2 was killed by the kernel at 6.7 GB. The queue is now
  capped (`TIP_GOSSIP_MAX_OUTBOUND_BUFFER_BYTES`, 8 MiB), messages beyond it
  are dropped for that peer (it catches up through anti-entropy), and a peer
  over the cap for two peer-health ticks is redialed, which frees the queue.
- `/health` and `/metrics` expose off-heap memory (`external`,
  `array_buffers`), the per-peer queued bytes and the redial count, so this
  class is visible instead of hiding behind a flat `heap_used`.
- snarkjs left one worker thread per CPU, each with a WASM memory, resident
  after every dedup-proof verification; the curve is released once no proof
  call is in flight.

### Added

**Node 2.6.5: `GET /v1/identity/:tipId` returns `tip_id_type`**
- The response now carries `tip_id_type` (`personal` or `organization`), the
  value the node already enforces on every content registration's `authors[]`.
  Clients building multi-author bylines can fill each author's type from the
  lookup instead of guessing; `org_type` is null for genesis organizations, so
  it was not a usable substitute.

### Fixed

**Node 2.6.4: a node that follows the committee by fast-forwarding no longer reports itself halted**
- Fast-forwarding to a peer's round now refreshes the round-advance timestamp.
  A node whose own batches always arrive late never completed a round itself,
  so the halt detector flagged `sub_quorum` and `/ready` went 503 while its
  rounds and commits were fully in step (AZ Logics, 2026-09-30).

**Node 2.6.3: a dead joiner can no longer hold the snapshot slot; the last drifted row is corrected**
- A snapshot serve races its transfer and its final close against the stall
  timer and a one-hour deadline. Aborting a stream whose connection had already
  died did not settle the pending close, and on mainnet both peers held their
  single serve slot for two days, so a halted node had nowhere to recover from.
- Migration 011 sets the one mainnet content row whose attested value (4249)
  differs from its transaction to that value; migration 010 had rebuilt it from
  the transaction and the restarted node halted. No-op on every other network.
- The score write persists the clamped value the mirror holds.
- `scripts/check-boot-root.js` is the pre-restart gate: it rebuilds the root
  from a node's database exactly as boot does and compares it with a live peer.
  The rolling-upgrade runbook requires a MATCH before a node restarts.

**Node 2.6.2: a restarted node no longer halts and snapshot-recovers on boot**
- The pre-scan verdict is rounded to basis points where the blend is produced,
  so the transaction, memory, store, snapshot and state hash all carry one
  value. content.prescan_probability was float4 in Postgres; a blend such as
  0.37174999999999997 hashed as 3717 live and 3718 after the round-trip, and
  every restarted mainnet node diverged from the fleet. Migration 010 widens
  the column and restores each row from its verdict transaction at basis
  points, so the state root does not change and nodes roll one at a time.

**Node 2.6.1: a reconnect never snapshots state it already holds**
- The attested state root decides a reconnect sync: same root, no sync mode and
  no snapshot; a different root pulls certificates and snapshots only when the
  peers no longer hold the rounds to replay. An install aborted before any row
  landed clears its own marker; a wedged install flag times out.
- Disconnects are counted by the peer that dropped
  (tip_network_peer_disconnects_by_peer_total) next to the per-observer total.

**Node 2.6.0: a joiner behind a thin link installs, catches up and stays ready**
- Liveness belongs to the heartbeat; libp2p no longer aborts a connection on its
  own ping failures, and verdicts stand down during any bulk sync (snapshot or
  cert tail) on both ends. A peer whose pings still reach us is congested, not dead.
- The snapshot source pins the cert tail its joiner will need; the join flow
  pulls certs before snapshotting and promotes within the sync tolerance.
- Node-local cert retention floor (TIP_CERT_RETENTION_MIN_ROUNDS, 4500 rounds)
  on top of genesis gc_depth; stream negotiation and status probes sized for
  real links (TIP_STREAM_NEGOTIATION_TIMEOUT_MS, TIP_ANTI_ENTROPY_PEER_TIMEOUT_MS).
- Partner link requirement documented: 25 Mbit/s symmetric sustained minimum,
  50 recommended.

### Added

**VP Category D: Educational Institutions**
- New VP accreditation category for universities, colleges, and research
  institutes. Category D accreditation is free, consistent with the protocol's
  commitment to keeping academic and public-interest participation accessible.
- Updated across VP_ACCREDITATION.md, README.md, TIP Protocol Specification,
  and interface.

**Third Provisional Patent Filed (April 7, 2026)**
- Application Number: 64/031,648 (Confirmation: 7072, Docket: AILAB-2026-PROV-03)
- Six new claim groups (K-P) covering content normalization, dual-mode
  verification, content versioning, content scope extraction, multi-layer
  verification delivery, and extensible normalization framework

**Claim Group K: Canonical Content Normalization (CNA-1)**
- Six-step deterministic text normalization algorithm producing identical
  cryptographic hashes regardless of HTML formatting, Unicode encoding,
  whitespace handling, or typographic conventions
- Three-hash architecture: canonical hash (primary verification), exact hash
  (forensic audit), perceptual hash (near-copy detection at 90% threshold)
- CTID derivation from canonical hash ensures identical content always
  produces the same CTID across platforms

**Claim Group L: Dual-Mode Content Verification**
- Publisher Mode: domain-bound ML-DSA-65 signature with 5 HTTP headers
- Creator Mode: hash-based DAG lookup for creators on platforms they do not
  control (X.com, Facebook, YouTube). No HTTP headers needed.
- Timestamps excluded from signature payload in both modes (eliminates
  timezone and registration-to-publication gap fragility)
- New API endpoint: GET /v1/content/by-hash/:canonicalHash (19th endpoint)

**Claim Group M: Content Version Tracking**
- CONTENT_UPDATED DAG transaction type with three mutation semantics:
  CORRECTION (preserves CTID and origin code), UPDATE (permits origin code
  change), RETRACTION (marks withdrawn, -50 trust score)
- Version-chain verification: checks all versions before perceptual fallback
- CONTENT_SYNDICATED transaction type for authorized republication

**Claim Group N: Content Scope Extraction**
- Four-priority content boundary detection: (1) data-tip-content HTML
  attribute, (2) JSON-LD articleBody, (3) HTML5 semantic elements,
  (4) Readability algorithm fallback
- New HTML meta tags: tip-content-selector, tip-content-title
- New data attribute: data-tip-content="true"

**Claim Group O: Multi-Layer Verification Delivery**
- Five-layer progressive architecture: (1) publisher-rendered <tip-badge>
  web component, (2) platform-native meta tags (tip:author, tip:ctid,
  tip:origin), (3) browser extension, (4) mobile share-to verification app,
  (5) URL-based zero-install verification service

**Claim Group P: Extensible Normalization Framework**
- normalization_version field in content registration transaction
- Defined identifiers: CNA-1 (text), CNA-IMG-1 (images), CNA-VID-1 (video),
  CNA-AUD-1 (audio), CNA-MIX-1 (mixed media)
- New algorithms deployable without protocol upgrade

**Security Architecture: Key Protection Chain**
- Documented PRF-to-AES key protection chain for ML-DSA-65 private key:
  Secure Enclave ECDSA P-256 -> PRF (biometric-gated) -> SHAKE-256 ->
  AES-256 key -> AES-256-GCM encrypts ML-DSA-65 private key at rest
- ECDSA never signs content; it only gates the PRF
- Browser extension uses dual signature (Ed25519 + ML-DSA-65), both in
  software, Secure Enclave protects master seed at rest

**Trust Tier Overhaul**
- Updated trust tier ranges and names:
  850-1000 Highly Trusted (#1A8A5C), 650-849 Trusted (#2563A8),
  400-649 Verified (#C9A84C), 200-399 Caution (#C07318),
  0-199 Not Trusted (#C53030)
- New user at score 500 now lands in Verified tier (gold badge, checkmark)
  instead of the previous Review Advised tier (warning icon)
- 100-point buffer before dropping to Caution tier
- Shield icons: checkmark for >= 400, warning triangle for 200-399, X for 0-199

**Verification Result Cards**
- New rectangular verification card system for browser extension and web
  component detail panels
- Nine status types: verified (Publisher Mode), verified-syndicated,
  verified-creator, verified-corrected, verified-updated, republished (amber),
  mismatch (red), retracted (red), none (gray)
- Data-driven SVG renderer with dynamic height, score pills, origin pills,
  domain indicators, and accent-colored TIP PROTOCOL watermark

**Badge Library v8 (tip-badges repository)**
- 11 badge categories, 393+ pre-generated SVGs
- New no-score seal and registry badge variants
- React component (TipBadge) with 12 variants and live API fetch
- Web component (<tip-badge>) with Shadow DOM
- React VerificationCard component
- npm package: @theailab/tip-badges

**REST API**
- Added 19th endpoint: GET /v1/content/by-hash/:canonicalHash for Creator
  Mode hash-based content lookup

**DAG Transaction Types**
- Added: CONTENT_UPDATED (content versioning with typed mutations)
- Added: CONTENT_SYNDICATED (authorized republication across domains)

### Changed

- Browser extension moved to separate repository (tip-extension) for
  independent release cycles and Chrome Web Store compliance

---

## [2.0.0]: 2026-03-15

### Initial public release: TIP Protocol v2.0

This is the first public release of the TIP Protocol Reference Implementation.
It includes all five v2 architectural improvements over the original design.

### Added

**FIX-02: Privacy Architecture (Claim Group F)**
- Peppered SHAKE-256 deduplication hash: device-held 256-bit pepper prevents
  nation-state reidentification attacks against the public DAG
- Zero-knowledge proof of uniqueness published to DAG instead of raw hash
- Separate dedup registry service with ZK yes/no interface
- Merkle root published to DAG every 6 hours for public audit without
  exposing individual hashes

**FIX-03: Adaptive Pre-Scan Calibration (Claim Group G)**
- Creator-calibrated AI detection thresholds derived from DAG history
  (floor 0.80, ceiling 0.94: no account bypasses the scan)
- Content-type thresholds: conversational 0.82, news 0.85, creative 0.87,
  academic 0.92, legal/formal 0.93
- Flag-but-mint mechanism: content exceeding threshold is minted with PENDING
  status and enters Stage 1 adjudication automatically
- Replaces the fixed 0.85 threshold from v1 design

**FIX-05: Multi-Type Identity Revocation (Claim Group H)**
- Four distinct revocation transaction types: REVOKE_VOLUNTARY, REVOKE_VP,
  REVOKE_DECEASED, REVOKE_DEVICE
- REVOKE_VP: 90-day cascade: content registered within 90 days auto-enters
  Stage 1 adjudication
- REVOKE_DECEASED: permanent ARCHIVED status, all active jury commitments
  dissolved with no score impact
- REVOKE_DEVICE: identity preserved, score reduced -15 pending re-verification

**FIX-06: GDPR Score Visibility (Claim Group I)**
- Three score display modes: FULL_PUBLIC, TIER_ONLY (default), VERIFIED_ONLY
- TIER_ONLY is the default at registration per GDPR Article 25 data
  minimisation by design
- Zero-knowledge score threshold proof (proves score is above/below a
  threshold without revealing the number)
- GDPR Article 17 erasure: score history reset while preserving content
  provenance records on the DAG
- Four TierChip display modes: full, score, tier, dot, verified-only

**FIX-08: VP Jurisdiction Tier Classification (Claim Group J)**
- Three-tier jurisdiction classification: GREEN, AMBER, RED
- AMBER badge indicator on AI Trust ID Seal for AMBER-tier VP credentials
- RED-tier jurisdictions cannot receive VP accreditation
- Quarterly warrant canary requirement for all VPs
- VP Transparency Register (quarterly disclosure)

**Reference implementations:**
- Python node: 23 files, 6,170+ lines, 201/201 tests passing
- Node.js node: 24 files, 6,951 lines, 43/43 tests passing
- Browser extension: Manifest V3, Chrome and Firefox
- `<tip-badge>` web component
- SDK (JavaScript)
- CLI tools

**Interface v4:**
- 37 components, 3,212 lines
- 6-tab badge gallery
- 4 leadership admin pages (Command Center, Responsibility Matrix,
  VP Strategy, Genesis Ring)
- Public and admin split with auth gate

### Known Limitations (Blocking Before Production Deployment)

The following items are known stubs that MUST be replaced before deploying
with real user data. They are documented here for full transparency:

- **[BLOCKING-B1]** ML-DSA-65 implementation uses Ed25519 as a same-API
  development stand-in. Replace with @noble/post-quantum or liboqs before
  processing any real biometric data.

- **[BLOCKING-B2]** ZK proof uses a Pedersen-style commitment stub. Replace
  with snarkjs/Groth16 or arkworks before the dedup privacy guarantee is
  real.

- **[BLOCKING-B3]** Genesis root keypair (SLH-DSA-128s) must be moved to
  cold storage HSM with two-of-three custodian policy before network launch.
  The development genesis.json must be deleted and regenerated with the
  production key.

- **[BLOCKING-B4]** Default secrets (TIP_JWT_SECRET, TIP_ADMIN_API_KEY) in
  .env.example must never be used in production. Generate cryptographically
  random 256-bit values.

- **[BLOCKING-B5]** GDPR DPIA must be completed and published before any
  European deployment.

- **[BLOCKING-B6]** Data Protection Officer must be appointed before any
  European deployment.

These are not security vulnerabilities: they are documented development
stubs with clear replacement instructions. See Command Center in the admin
interface for the complete pre-launch checklist.

---

*For the full commit history, see the Git log.*
*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*
