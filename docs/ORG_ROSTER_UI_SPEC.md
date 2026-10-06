# Organization roster: UI integration spec

Node 2.7.0 (PR #323). Audience: VP app / web client developers. Everything below is served by any TIP node; the client never needs the org's node in particular.

## 1. What the feature does

An organization TIP-ID keeps a roster of personal TIP-IDs (its members). Only roster members can be listed as authors on content the organization signs.

Three flows, each a signed call from the party acting:

| flow | who signs | tx on chain | result |
|---|---|---|---|
| org invites a person | the org key | `ORG_MEMBER_INVITED` | open invite, visible to the person from any node |
| person accepts | the person's key | `ORG_MEMBER_ADDED` | active membership, takes a seat |
| org cancels / person declines | org key or person's key | `ORG_MEMBER_INVITE_CANCELLED` | invite closed |
| org removes / person leaves | org key or person's key | `ORG_MEMBER_REMOVED` | membership ended, seat freed |
| org publishes with member authors | the org key | `REGISTER_CONTENT` | content attributed to the members |

Limits (free plan, the only plan today):

| limit | value | error when hit |
|---|---|---|
| active members per org | 1 | `member_limit_reached` |
| open (pending, unexpired) invites per org | 3 | `invite_limit_reached` |
| invites per org per rolling 24 h, any status | 10 | `invite_rate_limited` |
| invite lifetime | 7 days from the invite tx | `invite_expired` on accept |
| authors per content | 10 | `authors_too_many` |
| signed claim freshness | 15 min (60 s clock skew ahead) | `claim_expired` |

## 2. Identities and keys

- The org is a TIP-ID with `tip_id_type: "organization"`; people are `"personal"`. `GET /v1/identity/:tipId` returns `tip_id_type`, so the app knows which screens to show.
- Every write below is signed with the ML-DSA-65 private key the app already holds for that identity (the `.tip.json` key file). The org key signs org actions; the person's key signs their own. No cosignatures anywhere.
- TIP-IDs in URL paths must be percent-encoded: `tip://id/GB-400d3636845c06f2` becomes `tip%3A%2F%2Fid%2FGB-400d3636845c06f2`.
- Response envelope on success: `{ "ok": true, "status": 200, "data": { ... } }`. On error: `{ "ok": false, "status": 409, "error": { "message", "code", "request_id" } }`. Branch on `error.code`, never on the message text.
- All timestamps the client signs are integer epoch milliseconds (`Date.now()`). Responses render stored times as ISO strings.

## 3. Search (new): `GET /v1/identity/search`

For the invite box: the user types a name or a TIP-ID, the app queries on every change (debounce 250 ms, cancel the previous request), shows the results, and "Invite" posts section 4.1 with the picked `tip_id`.

```
GET /v1/identity/search?q=<text>&limit=10&type=personal
```

| param | required | notes |
|---|---|---|
| `q` | yes | at least 2 characters. Matches a TIP-ID prefix (with or without `tip://id/`, case-insensitive) or a substring of the registered name |
| `limit` | no | 1 to 20, default 10 |
| `type` | no | `personal` (default), `organization`, or `any`. The invite box keeps the default: only people can be invited |

Response:

```json
{ "query": "alic", "results": [
  { "tip_id": "tip://id/IN-cbcd2ea94f1f1d49", "creator_name": "Alice Example",
    "tip_id_type": "personal", "region": "IN", "score": 535, "tier": "Verified" }
] }
```

Ordering: exact TIP-ID, then TIP-ID prefix, then name starts-with, then name contains. Revoked and non-active identities never appear. Errors: `query_too_short` (400), `limit_invalid` (400), `type_invalid` (400).

Show `creator_name` with the short TIP-ID under it (the last 16 hex characters are what people recognise). Names are not unique; the TIP-ID is the key the invite is sent to.

## 4. Roster endpoints

All writes return `202` with `confirmation: "proposed"`: the transaction is accepted into the mempool, not yet committed. See section 7 for what to poll.

### 4.1 Invite (org signs)

```
POST /v1/identity/<org>/members/invite
{
  "org_tip_id":    "tip://id/GB-400d3636845c06f2",
  "member_tip_id": "tip://id/IN-cbcd2ea94f1f1d49",
  "role":          "author",
  "invited_at":    1791266254000,
  "signature":     "<hex>"
}
```
Signed payload (section 5): `{ invited_at, member_tip_id, org_tip_id, role }`.
`role` is a lowercase token, 1 to 64 chars, `a-z 0-9 _ -`, starting with a letter (`author`, `editor`, `senior-editor`). Free text for display; the node does not interpret it.

Response `202`: `{ org_tip_id, member_tip_id, role, invite_tx_id, invited_at, proposed_at, confirmation: "proposed" }`. Keep `invite_tx_id`: it is the handle for cancel and accept.

Errors: `tip_id_mismatch` (URL is not `org_tip_id`), `org_tip_id_type_invalid` (signer is not an organization), `member_tip_id_type_invalid` (target is an organization), `member_tip_id_not_found`, `member_tip_id_revoked`, `already_member`, `invite_pending` (an open invite to this person already exists, including one still in the mempool), `member_limit_reached`, `invite_limit_reached`, `invite_rate_limited`, `invite_replayed` (the same signed body was sent before; sign a fresh `invited_at`), `claim_expired`, `signature_invalid`, `org_members_not_active` (network has not reached the activation date).

### 4.2 Cancel or decline (org or invitee signs)

```
POST /v1/identity/<signer>/members/cancel-invite
{
  "org_tip_id":    "tip://id/GB-400d3636845c06f2",
  "member_tip_id": "tip://id/IN-cbcd2ea94f1f1d49",
  "invite_tx_id":  "<from 4.1 or from GET /invites>",
  "claimed_at":    1791266300000,
  "signer_tip_id": "<org_tip_id to cancel, member_tip_id to decline>",
  "signature":     "<hex>"
}
```
Signed payload: `{ claimed_at, invite_tx_id, member_tip_id, org_tip_id, signer_tip_id }`. The URL `<signer>` must equal `signer_tip_id`.

Response `202`: `{ org_tip_id, member_tip_id, invite_tx_id, cancel_tx_id, claimed_at, proposed_at, confirmation }`.
Errors: `not_party` (signer is neither the org nor the invitee), `invite_not_found`, `invite_mismatch`, `invite_not_open` (already accepted, cancelled or removed), `signer_tip_id_revoked`, `claim_expired`, `signature_invalid`.

### 4.3 Accept (person signs)

```
POST /v1/identity/<member>/members/accept
{
  "org_tip_id":    "tip://id/GB-400d3636845c06f2",
  "member_tip_id": "tip://id/IN-cbcd2ea94f1f1d49",
  "invite_tx_id":  "<from GET /invites>",
  "accepted_at":   1791266400000,
  "signature":     "<hex>"
}
```
Signed payload: `{ accepted_at, invite_tx_id, member_tip_id, org_tip_id }`.

Response `202`: `{ org_tip_id, member_tip_id, invite_tx_id, add_tx_id, accepted_at, proposed_at, confirmation }`. Keep `add_tx_id`: it is the handle for leaving / removal.
Errors: `invite_not_found`, `invite_mismatch` (invite is for someone else), `invite_not_open`, `invite_expired` (older than 7 days; ask the org to invite again), `member_limit_reached` (the seat was taken by someone else after the invite went out; the invite stays open and can be retried once a seat frees), `already_member`, `org_tip_id_revoked`, `acceptance_pending` (already submitted, wait), `claim_expired`, `signature_invalid`.

### 4.4 Remove or leave (org or member signs)

```
POST /v1/identity/<signer>/members/remove
{
  "org_tip_id":    "tip://id/GB-400d3636845c06f2",
  "member_tip_id": "tip://id/IN-cbcd2ea94f1f1d49",
  "add_tx_id":     "<from 4.3 or from GET /members>",
  "claimed_at":    1791270000000,
  "signer_tip_id": "<org_tip_id to remove, member_tip_id to leave>",
  "signature":     "<hex>"
}
```
Signed payload: `{ add_tx_id, claimed_at, member_tip_id, org_tip_id, signer_tip_id }`.

Response `202`: `{ org_tip_id, member_tip_id, add_tx_id, remove_tx_id, claimed_at, proposed_at, confirmation }`.
Errors: `not_party`, `membership_not_found`, `membership_mismatch`, `membership_not_active`, `signer_tip_id_revoked`, `claim_expired`, `signature_invalid`.

Already-published content keeps its authors; removal only affects future posts.

### 4.5 Reads (no signature)

| call | returns |
|---|---|
| `GET /v1/identity/<org>/members` | `{ org_tip_id, limit, members: [row], pending_invites: [row] }`; add `?include=removed` for `removed: [row]` and `cancelled: [row]` |
| `GET /v1/identity/<person>/invites` | `{ member_tip_id, invites: [row] }`, open and unexpired only |
| `GET /v1/identity/<person>/memberships` | `{ member_tip_id, memberships: [row] }`, active only |
| `GET /v1/identity/<id>` | adds `members: { active, limit }` for an org, `member_of: [org_tip_id]` for a person |

A roster `row`:

```json
{ "invite_tx_id": "...", "org_tip_id": "...", "member_tip_id": "...", "role": "author",
  "status": "invited | active | removed | cancelled",
  "invited_at": "2026-10-06T05:58:08.427Z", "accepted_at": null, "add_tx_id": null,
  "removed_at": null, "remove_tx_id": null, "removed_by": null }
```
`removed_*` are filled for both removal and cancellation (`removed_by` says who signed). An invite expires 7 days after `invited_at`; `pending_invites` and `/invites` already exclude expired ones.

## 5. Signing recipe

Identical for every call; it is the recipe the app already uses for content and profile updates.

1. Build the payload object with exactly the listed fields, nothing else.
2. `canonical = canonicalJson(payload)`: JSON with keys sorted alphabetically at every level, no whitespace.
3. `digest = SHAKE-256(canonical)` as a 64-character lowercase hex string.
4. `signature = ML-DSA-65.sign(ASCII bytes of digest, privateKey)`, hex-encoded.
5. Send the original field values in the request body plus `signature`. The node rebuilds the same payload from the body and verifies.

Reference implementation: `node/src/schemas/_common.js` (`payloadHashHex`, `signPayload`). The field order in the body does not matter; the field set does.

Sign at the moment of the user's tap and send immediately: every signed time (`invited_at`, `accepted_at`, `claimed_at`) must be within 15 minutes of when the node receives it, and at most 60 s ahead of the node's clock. A signature is single-use: a resent invite body is refused (`invite_replayed`); build a new payload with a fresh time instead.

## 6. Publishing with member authors

Unchanged `POST /v1/content/register`; only the rules around `authors[]` are new.

```json
{
  "signer_tip_id": "tip://id/GB-400d3636845c06f2",
  "attribution_mode": "employed",
  "authors": [
    { "tip_id": "tip://id/IN-cbcd2ea94f1f1d49", "tip_id_type": "personal", "role": "byline" }
  ],
  "content": "...", "origin_code": "OH", "registered_urls": ["https://..."], "extras": {}, "cna_version": "2.2",
  "signature": "<hex>"
}
```

Rules, enforced at the API and again at commit:

| rule | error |
|---|---|
| org signer: every author is the org itself or an active member | `412 invalid_author` |
| an organization may appear in `authors[]` only when it is the signer (a person cannot list an org, an org cannot list another org) | `412 invalid_author` |
| revoked identities cannot be authors | `412 invalid_author` |
| at most 10 authors | `400 authors_too_many` |
| every author exists and `tip_id_type` matches the chain | `author_not_registered`, `author_tip_id_type_mismatch` |

`attribution_mode`: `"self"` when the signer is the (only) author; `"employed"` when an org publishes for its members. `"hosted"` is being retired; do not send it.

Author picker for an org account: populate it from `GET /members` (active rows) plus the org itself; the picker never needs search. Membership becomes usable one round after the acceptance commits (section 7).

## 7. Pending state and polling

A `202` means "proposed": committed a few seconds later (typically 3 to 10 s) once the round that carries it is certified. Until then the GET endpoints do not show the change and dependent actions fail (`invalid_author`, `invite_not_found`).

- After invite: poll `GET /<org>/members` until the row appears in `pending_invites` (match on `invite_tx_id`).
- After accept: poll `GET /<org>/members` until the row is in `members` with `status: "active"`.
- After cancel / remove: poll until the row leaves `pending_invites` / `members`.
- Poll every 3 s, give up after 60 s and show "still pending, pull to refresh". Do not resubmit on timeout: the signed body is single-use and a duplicate is refused.

Invites are discovered by polling `GET /<person>/invites` (on app open and every 30 s while the screen is visible). No push exists yet.

## 8. Error codes to handle

| code | HTTP | show |
|---|---|---|
| `org_members_not_active` | 403 | "Team roster is not available on this network yet" |
| `member_limit_reached` | 409 | "No free seat. Remove a member first" (org) / "The seat is taken; try again when it frees" (person) |
| `invite_limit_reached` | 409 | "Too many open invites. Cancel one or wait for expiry" |
| `invite_rate_limited` | 409 | "Invite limit for today reached" |
| `invite_pending` | 409 | "An invite to this person is already open" |
| `already_member` | 409 | "Already a member" |
| `invite_not_open` | 409 | "This invite is no longer open" (refresh the list) |
| `invite_expired` | 410 | "This invite expired; ask for a new one" |
| `invite_not_found`, `membership_not_found` | 412 | refresh the list |
| `not_party` | 403 | should not happen if the URL signer is the acting user |
| `member_tip_id_type_invalid`, `org_tip_id_type_invalid` | 403 | "Only people can be invited" / "Only an organization can invite" |
| `invite_replayed` | 409 | retry with a freshly signed request |
| `claim_expired` | 400 | device clock is off or the request was delayed; sign again |
| `signature_invalid` | 403 | wrong key for this identity |
| `invalid_author` | 412 | "This author is not a member of your organization" |
| `authors_too_many` | 400 | "At most 10 authors" |
| `query_too_short` | 400 | type at least 2 characters |

## 9. UI checklist

Organization account
- [ ] Members screen: seats used `active/limit` (from `GET /identity/<org>.members`), active members with role and joined date, pending invites with sent date and "expires in", a Cancel action per invite (4.2 with `signer_tip_id` = org), a Remove action per member (4.4).
- [ ] Invite box: search as you type (section 3), result rows show name + short TIP-ID, Invite button disabled when seats are full (`active >= limit`) with the reason shown.
- [ ] Publish screen: author picker lists the org itself and active members only; `attribution_mode` is `employed` when any member is selected, `self` when only the org.

Personal account
- [ ] Invites screen from `GET /<person>/invites`: org name (resolve `org_tip_id` via `GET /identity`), role, expiry; Accept (4.3) and Decline (4.2 with `signer_tip_id` = person).
- [ ] Memberships: list from `GET /<person>/memberships` with a Leave action (4.4 with `signer_tip_id` = person).

Edge cases
- [ ] Accept returns `member_limit_reached`: keep the invite visible with "seat currently full".
- [ ] Accept returns `invite_expired` or `invite_not_open`: remove it from the list.
- [ ] Any `202` followed by a timeout in polling: show pending, never auto-resend.
- [ ] A revoked member still shows as active in the roster; the publish screen must not offer them (check `status` via `GET /identity/<id>` when building the picker).
