# LINK_PLATFORM API — Developer Guide

Link a user's social media account to their TIP-ID, earning +5 trust score per platform (max +30 across 6 platforms).

---

## Overview

Two verification paths exist depending on the platform:

**OAuth path** (GitHub, LinkedIn, Twitter/X, YouTube, Reddit, Spotify, Facebook)
```
User signs claim → VP OAuth initiate → Platform OAuth popup → VP verifies → Node attests → Score +5
```

**Bio-check path** (Medium, Substack, Dev.to — and any platform without OAuth support)
```
User adds TIP-ID to bio → User signs claim → POST to node → Node scrapes bio → Score +5
```

The node accepts both paths on the same endpoint (`POST /v1/identity/:tipId/link-platform`). The presence of `vp_oauth_signature` in the request body selects the OAuth path; its absence selects the bio-check path.

---

## Supported Platforms

| Platform | Key | Verification | Handle source | Notes |
|---|---|---|---|---|
| GitHub | `github` | OAuth | `login` field | Standard OAuth 2.0 |
| LinkedIn | `linkedin` | OAuth (OIDC) | Display name | Vanity URL unavailable via OIDC; `skip_url_match` |
| Twitter / X | `twitter` | OAuth + PKCE | `username` | PKCE S256 + HTTP Basic auth |
| YouTube | `youtube` | OAuth (Google) | `customUrl` | Google OAuth 2.0; `skip_url_match` |
| Reddit | `reddit` | OAuth | `name` | HTTP Basic auth + `User-Agent` header |
| Spotify | `spotify` | OAuth | `display_name` or `id` | HTTP Basic auth; `skip_url_match` |
| Facebook | `facebook` | OAuth | `username` or `name` | `skip_url_match`; numeric-ID profile URL |
| Medium | `medium` | Bio-check | URL-extracted | Supports `@handle` and subdomain forms |
| Substack | `substack` | Bio-check | Subdomain | `username.substack.com` form |
| Dev.to | `devto` | Bio-check | First path segment | `dev.to/username` |
| Instagram | `instagram` | Bio-check | URL-extracted | No public OAuth for third parties |
| Bluesky | `bluesky` | Bio-check | URL-extracted | |
| Threads | `threads` | Bio-check | URL-extracted | |
| Mastodon | `mastodon` | Bio-check | URL-extracted | |
| TikTok | `tiktok` | OAuth | `display_name` | Adapter present; credentials optional |
| Rooverse | `rooverse` | Bio-check | URL-extracted | |

Any non-empty string ≤50 chars is accepted as `platform` by the node (open schema). The platform key is case-sensitive and used for deduplication.

---

## OAuth App Setup

Rebuild and restart the VP container after adding credentials:
```bash
cd tip-vp-with-mobile-web-app
docker compose build tip-vp && docker compose up -d tip-vp
```

### GitHub

1. **[GitHub Developer Settings → OAuth Apps](https://github.com/settings/developers)** → New OAuth App

   | Field | Value |
   |---|---|
   | Application name | `TIP Protocol (local)` |
   | Homepage URL | `http://localhost:5050` |
   | Authorization callback URL | `http://localhost:5050/v1/social/oauth/callback/github` |

2. Copy **Client ID** and generate a **Client secret**.

3. Add to `.env`:
   ```env
   OAUTH_GITHUB_CLIENT_ID=<client-id>
   OAUTH_GITHUB_CLIENT_SECRET=<client-secret>
   ```

**Scopes:** `read:user` — public profile name and URL only.

---

### LinkedIn

1. **[LinkedIn Developer Portal](https://www.linkedin.com/developers/apps)** → Create app

2. Under the **Auth** tab, add redirect URL:
   ```
   http://localhost:5050/v1/social/oauth/callback/linkedin
   ```

3. Under the **Products** tab, request **Sign In with LinkedIn using OpenID Connect** (auto-approved).

4. Copy **Client ID** and **Client Secret** from the Auth tab.

5. Add to `.env`:
   ```env
   OAUTH_LINKEDIN_CLIENT_ID=<client-id>
   OAUTH_LINKEDIN_CLIENT_SECRET=<client-secret>
   ```

**Scopes:** `openid profile` — name and unique account ID only.

> **Note:** LinkedIn's OIDC `/v2/userinfo` endpoint does not expose the user's vanity URL. Profile URL matching is skipped (`skip_url_match`); the OAuth handshake proves ownership. The handle stored is the user's display name.

---

### Twitter / X

1. **[Twitter Developer Portal](https://developer.twitter.com)** → Projects & Apps → New App

   - App type: **Web App** (confidential client — requires a client secret)
   - Under **User authentication settings**:
     - OAuth 2.0: **On**
     - App permissions: **Read**
     - Redirect URI / Callback URL: `http://localhost:5050/v1/social/oauth/callback/twitter`

2. Copy **Client ID** and **Client Secret**.

3. Add to `.env`:
   ```env
   OAUTH_TWITTER_CLIENT_ID=<client-id>
   OAUTH_TWITTER_CLIENT_SECRET=<client-secret>
   ```

**Scopes:** `tweet.read users.read`

**Auth variant:** PKCE (S256) + HTTP Basic auth for token exchange. The VP generates a fresh `code_verifier`/`code_challenge` on each initiate call; `code_verifier` is stored server-side and submitted during token exchange. The app must be a **confidential client** (has a client secret) to satisfy Twitter's Basic auth requirement.

---

### YouTube (Google)

1. **[Google Cloud Console](https://console.cloud.google.com)** → APIs & Services → Credentials → Create Credentials → **OAuth 2.0 Client ID**

   - Application type: **Web application**
   - Authorized redirect URIs: `http://localhost:5050/v1/social/oauth/callback/youtube`

2. Enable **YouTube Data API v3** in the project (APIs & Services → Library).

3. Copy **Client ID** and **Client Secret**.

4. Add to `.env`:
   ```env
   OAUTH_YOUTUBE_CLIENT_ID=<client-id>
   OAUTH_YOUTUBE_CLIENT_SECRET=<client-secret>
   ```

**Scopes:** `https://www.googleapis.com/auth/youtube.readonly`

> **Note:** The API returns `customUrl` (e.g. `@username`) and the profile URL is constructed as `https://youtube.com/@username`. This may differ from the `www.youtube.com` URL the user pastes. Profile URL matching is skipped (`skip_url_match`); the OAuth handshake proves ownership.

---

### Reddit

1. **[Reddit App Preferences](https://www.reddit.com/prefs/apps)** → Create App

   - Type: **web app**
   - Redirect URI: `http://localhost:5050/v1/social/oauth/callback/reddit`

2. Copy **app ID** (Client ID, shown under the app name) and **secret**.

3. Add to `.env`:
   ```env
   OAUTH_REDDIT_CLIENT_ID=<client-id>
   OAUTH_REDDIT_CLIENT_SECRET=<client-secret>
   ```

**Scopes:** `identity`

**Auth variant:** HTTP Basic auth for token exchange. The profile API at `oauth.reddit.com` requires a `User-Agent` header — the VP sends `TIP-VP/1.0 by TIPProtocol` automatically.

---

### Spotify

1. **[Spotify Developer Dashboard](https://developer.spotify.com/dashboard)** → Create app

   - Redirect URI: `http://localhost:5050/v1/social/oauth/callback/spotify`

2. Copy **Client ID** and **Client Secret**.

3. Add to `.env`:
   ```env
   OAUTH_SPOTIFY_CLIENT_ID=<client-id>
   OAUTH_SPOTIFY_CLIENT_SECRET=<client-secret>
   ```

**Scopes:** `user-read-private`

**Auth variant:** HTTP Basic auth for token exchange (Spotify requirement).

> **Note:** Profile URL matching is skipped (`skip_url_match`) because Spotify canonical URLs use a numeric user ID that may differ from what the user pastes.

---

### Facebook

1. **[Facebook Developer Portal](https://developers.facebook.com)** → Create App → **Consumer**

2. Add the **Facebook Login** product. Under Facebook Login → Settings, add Valid OAuth Redirect URI:
   ```
   http://localhost:5050/v1/social/oauth/callback/facebook
   ```

3. Copy **App ID** (Client ID) and **App Secret**.

4. Add to `.env`:
   ```env
   OAUTH_FACEBOOK_CLIENT_ID=<app-id>
   OAUTH_FACEBOOK_CLIENT_SECRET=<app-secret>
   ```

**Scopes:** `public_profile`

**Handle stored:** `username` (Facebook vanity name) if set, falling back to display `name`. The profile URL is constructed as `https://facebook.com/<numeric_id>`. Profile URL matching is skipped (`skip_url_match`) because the numeric-ID URL is not a user-facing vanity URL.

---

## Prerequisites

1. The user must have a registered TIP-ID (via `REGISTER_IDENTITY`)
2. The user's `.tip.json` file (downloaded at registration time)
3. Node running at `http://localhost:4000`

---

## Bio-Check Path (Medium, Substack, Dev.to)

### Step 1 — Add TIP-ID to your profile bio

Place your TIP-ID string anywhere in your profile bio or about section on the platform:

```
tip://id/IN-3f709ff96ddebfe7
```

The node fetches the public profile page HTML and does a plain-text search for the TIP-ID string.

> **Dev/testing only:** Set `TIP_SKIP_BIO_CHECK=true` in the node's `.env` to bypass this check. Never use in production.

### Step 2 — Generate the claim signature

```bash
node scripts/generate-link-claim.js \
  --tip-json ~/Downloads/tip-id-IN-3f709ff96ddebfe7.tip.json \
  --dob 10031991 \
  --platform medium \
  --profile-url https://medium.com/@vishalkothekar \
  --node-url http://localhost:4000
```

### Step 3 — Submit (no VP OAuth fields)

```bash
POST http://localhost:4000/v1/identity/tip%3A%2F%2Fid%2FIN-3f709ff96ddebfe7/link-platform

{
  "platform": "medium",
  "profile_url": "https://medium.com/@vishalkothekar",
  "claim_signature": "<hex>",
  "claimed_at": 1779874848270
}
```

The absence of `vp_oauth_signature` tells the node to verify via bio scrape.

**Profile URL formats per platform:**

| Platform | Example URL |
|---|---|
| `medium` | `https://medium.com/@username` or `https://username.medium.com` |
| `substack` | `https://username.substack.com` |
| `devto` | `https://dev.to/username` |

---

## OAuth Path (GitHub, LinkedIn, Twitter, YouTube, Reddit, Spotify, Facebook)

The OAuth flow is handled by the VP frontend (`settings.html` → Connections section). The VP initiates the OAuth popup, exchanges the token, fetches the user profile, signs a VP OAuth proof, and redirects back to the frontend with the proof in query params. The frontend then submits the signed proof to the node.

### Initiate endpoint (VP)

```
GET http://localhost:5050/v1/social/oauth/initiate
  ?platform=github
  &tip_id=tip%3A%2F%2Fid%2FIN-3f709ff96ddebfe7
  &claim_signature=<hex>
  &claimed_at=1779874848270
  &profile_url=https%3A%2F%2Fgithub.com%2Fvishalkothekar
```

Returns:
```json
{ "redirect_url": "https://github.com/login/oauth/authorize?..." }
```

Returns `503` if `client_id` is empty in `.env`.

### Node submit (with VP proof)

```bash
POST http://localhost:4000/v1/identity/tip%3A%2F%2Fid%2FIN-3f709ff96ddebfe7/link-platform

{
  "platform": "github",
  "profile_url": "https://github.com/vishalkothekar",
  "claim_signature": "<hex>",
  "claimed_at": 1779874848270,
  "vp_oauth_signature": "<vp-hex>",
  "vp_oauth_handle": "vishalkothekar",
  "vp_oauth_verified_at": 1779874848500
}
```

When `vp_oauth_signature` is present, the node verifies it against the founding VP public key and skips bio scraping.

---

## Generate claim signature (CLI)

```bash
node scripts/generate-link-claim.js \
  --tip-json ~/Downloads/tip-id-IN-3f709ff96ddebfe7.tip.json \
  --dob 10031991 \
  --platform github \
  --profile-url https://github.com/vishalkothekar \
  --node-url http://localhost:4000
```

| Argument | Description |
|---|---|
| `--tip-json` | Path to the user's `.tip.json` file |
| `--dob` | Date of birth used to decrypt the file (`DDMMYYYY`) |
| `--platform` | Platform key (see table above) |
| `--profile-url` | Full `https://` URL of the user's profile |
| `--node-url` | TIP node base URL |

> **CRITICAL:** `claim_signature` is cryptographically bound to `claimed_at` (millisecond timestamp). Never edit `claimed_at` — the signature will fail verification.

---

## Success Response (202)

```json
{
  "ok": true,
  "status": 202,
  "data": {
    "tip_id": "tip://id/IN-3f709ff96ddebfe7",
    "platform": "github",
    "handle": "vishalkothekar",
    "tx_id": "298d010cc36bfe3e330e6108ed7881705b00bada3e43c314e82ac26a9c9e86f4",
    "score_tx_id": "ed5c2d15fe88ad768367bd8bf12e635a2fa5becf104af8816da008dc94590556",
    "score_delta": 5,
    "profile_url": "https://github.com/vishalkothekar",
    "verified_at": "2026-05-27T09:43:15.837Z",
    "confirmation": "proposed"
  }
}
```

| Field | Description |
|---|---|
| `handle` | Extracted username from profile URL or API response |
| `score_delta` | `5` if under the 6-platform cap, `0` if already at cap |
| `confirmation` | `"proposed"` — tx in mempool, becomes `"committed"` after consensus (~4–10s) |

---

## Error Responses

| HTTP | Code | Cause |
|---|---|---|
| 400 | `platform_not_supported` | Platform key not recognized |
| 403 | `claim_signature_invalid` | Wrong `claimed_at` or wrong key — regenerate |
| 409 | `platform_already_linked` | That platform is already linked for this TIP-ID |
| 412 | `tip_id_not_found` | TIP-ID not registered on this node |
| 422 | `tip_id_not_in_bio` | Node fetched the profile but TIP-ID not found in HTML |
| 422 | `profile_url_mismatch` | OAuth-verified account URL differs from the URL submitted |
| 502 | `profile_fetch_failed` | Node could not fetch profile URL (HTTP error or blocked) |
| 503 | `oauth_not_configured` | Client ID/secret not set in VP `.env` |
| 504 | `profile_fetch_timeout` | Profile URL fetch timed out (10s limit) |

---

## Scoring Rules

- **+5** per linked platform
- **Max 6 platforms** — 7th and beyond link successfully but `score_delta: 0`
- Each `platform` string is unique (case-sensitive) — duplicate = 409
- Score bonus is a separate `SCORE_UPDATE` transaction paired with `LINK_PLATFORM`

```
Registration              → 500
+ github                  → 505
+ linkedin                → 510
+ twitter                 → 515
+ youtube                 → 520
+ medium                  → 525
+ reddit  (6th, cap hit)  → 530
+ spotify (7th, no bonus) → 530
```

---

## UNLINK_PLATFORM

Unlink a previously linked platform:

```bash
POST http://localhost:4000/v1/identity/tip%3A%2F%2Fid%2FIN-3f709ff96ddebfe7/unlink-platform

{
  "platform": "github",
  "claim_signature": "<hex>",
  "claimed_at": 1779874848270
}
```

The unlink is recorded as an `UNLINK_PLATFORM` transaction. The +5 score awarded at link time is not reversed. Re-linking the same platform later is allowed but does not earn a second +5.

---

## Read linked platforms

```
GET http://localhost:4000/v1/identity/tip%3A%2F%2Fid%2FIN-3f709ff96ddebfe7/platform-links
```

Returns the current list of active platform links with `handle`, `profile_url`, and `verified_at`.

```
GET http://localhost:4000/v1/identity/tip%3A%2F%2Fid%2FIN-3f709ff96ddebfe7/history
```

Full transaction history including all `LINK_PLATFORM`, `UNLINK_PLATFORM`, and `SCORE_UPDATE` events.

---

## How claim_signature works

The user signs a canonical 4-field JSON payload with ML-DSA-65 (post-quantum):

```json
{
  "claimed_at": 1779874848270,
  "platform": "github",
  "profile_url": "https://github.com/vishalkothekar",
  "tip_id": "tip://id/IN-3f709ff96ddebfe7"
}
```

Fields serialized in **alphabetical order**, no whitespace. The node verifies against the user's stored `public_key` from registration. This proves the user controls the TIP-ID and intends to claim the social account.

For OAuth platforms, the VP additionally:
1. Fetches the user's profile from the platform API using the OAuth access token
2. Verifies the authenticated profile URL matches the claimed URL (skipped for LinkedIn, YouTube, Spotify, Facebook — those use `skip_url_match`)
3. Signs a VP OAuth proof with the founding VP private key
4. Includes `vp_oauth_signature`, `vp_oauth_handle`, and `vp_oauth_verified_at` in the node request so any node can independently verify VP attestation

---

## Frontend Integration

### Connections section (`settings.html`)

The `#connections` section renders platform cards from `_CONN_PLATFORMS`. Two card variants:

**OAuth platforms** (`useOAuth` absent or `true`): "Connect" button opens an OAuth popup via `_connStartOAuth()`.

**Bio-check platforms** (`useOAuth: false`): "Connect" expands a form with:
1. Profile URL input
2. Copyable TIP-ID claim block (auto-populated via `_connToggleForm` on open)
3. "Verify [Platform] Bio" button that calls `_connVerifyBio()`

`_connVerifyBio()` signs the claim, POSTs directly to the node without `vp_oauth_signature`, and refreshes the platform-links list on success.

### Key storage architecture

The user's ML-DSA-65 private key is stored **encrypted in IndexedDB** (`tip-keys` database, `keys` store, `"tip-key"` record). Decryption requires WebAuthn biometric or recovery password. The key exists in memory only for the duration of the signing operation.

### Signing pattern (browser)

```javascript
const claimedAt = Date.now();  // generate once — used in both signing and POST body

const record = await getRecord();
const privKey = await unlockSourceKey(record, password);

const claimSig = await signCanonicalPayload({
  claimed_at:  claimedAt,
  platform:    "medium",
  profile_url: "https://medium.com/@vishalkothekar",
  tip_id:      record.tipId,
}, privKey);

await fetch(`${nodeUrl}/v1/identity/${encodeURIComponent(record.tipId)}/link-platform`, {
  method:  "POST",
  headers: { "Content-Type": "application/json" },
  body:    JSON.stringify({
    platform:        "medium",
    profile_url:     "https://medium.com/@vishalkothekar",
    claim_signature: claimSig,
    claimed_at:      claimedAt,  // same value — never recalculate
  }),
});
```

> **CRITICAL:** `claimedAt` must be the same `Date.now()` in both signing and POST. Even 1ms difference produces a different signature → 403.

### Reference implementations

| Page | Pattern |
|---|---|
| `public/settings.html` `#connections` | Full OAuth + bio-check platform grid |
| `public/disputes.html` | `signCanonicalPayload()` usage |
| `public/register-content.html` | Sign + POST pattern |










~~~

cd C:\Users\AZ LP Gayatri\Desktop\AZLOGICS\6. Tip Protocol\Tip Protocol\tip-protocol
docker build -t tip-protocol/node:2.0.0 .
docker compose -f docker-compose.local.yml up -d --force-recreate node1 node2 node3 node4 node5
cd C:\Users\AZ LP Gayatri\Desktop\AZLOGICS\6. Tip Protocol\Tip Protocol\tip-vp-with-mobile-web-app
docker compose build tip-vp
timeout /t 10 /nobreak
docker compose up -d --force-recreate tip-vp
timeout /t 2 /nobreak


cd C:\Users\AZ LP Gayatri\Desktop\AZLOGICS\6. Tip Protocol\Tip Protocol\tip-protocol
docker compose -f docker-compose.local.yml --profile observability down -v
docker compose -f docker-compose.local.yml down -v
timeout /t 2 /nobreak
rmdir /s /q data 2>nul
rmdir /s /q node2-env 2>nul
rmdir /s /q node3-env 2>nul
rmdir /s /q node4-env 2>nul
rmdir /s /q node5-env 2>nul
node --experimental-vm-modules scripts/seed.js
timeout /t 2 /nobreak

copy "genesis-data\founding-vp-keys.json" "C:\Users\AZ LP Gayatri\Desktop\AZLOGICS\6. Tip Protocol\Tip Protocol\tip-vp-with-mobile-web-app\server\data\founding-vp-keys.json" && copy "genesis-data\founding-vp-keys.json" "C:\Users\AZ LP Gayatri\Desktop\AZLOGICS\6. Tip Protocol\Tip Protocol\tip-vp-with-mobile-web-app\server\founding-vp-keys.json" && echo VP keys copied

timeout /t 2 /nobreak
docker build -t tip-protocol/node:2.0.0 .
timeout /t 10 /nobreak
docker compose -f docker-compose.local.yml up postgres node1 -d
timeout /t 10 /nobreak
:waitloop
curl -s http://localhost:4000/health | findstr /c:"\"ok\":true" >nul
if errorlevel 1 (
    timeout /t 10 /nobreak >nul
    goto waitloop
)
timeout /t 2 /nobreak
done
node scripts/register-node.js --name "Node 2" --port 4100 --p2p-port 4101 --public-ip 172.30.0.11 --out-dir ./node2-env --db-name tip_node2 --force
node scripts/register-node.js --name "Node 3" --port 4200 --p2p-port 4201 --public-ip 172.30.0.12 --out-dir ./node3-env --db-name tip_node3 --force
node scripts/register-node.js --name "Node 4" --port 4300 --p2p-port 4301 --public-ip 172.30.0.13 --out-dir ./node4-env --db-name tip_node4 --force
node scripts/register-node.js --name "Node 5" --port 4400 --p2p-port 4401 --public-ip 172.30.0.14 --out-dir ./node5-env --db-name tip_node5 --force
timeout /t 2 /nobreak
docker compose -f docker-compose.local.yml up node2 node3 node4 node5 -d
cd C:\Users\AZ LP Gayatri\Desktop\AZLOGICS\6. Tip Protocol\Tip Protocol\tip-vp-with-mobile-web-app
docker compose build tip-vp
timeout /t 10 /nobreak
docker compose up -d tip-vp
timeout /t 2 /nobreak
for %%p in (4000 4100 4200 4300 4400) do (
    curl -s http://localhost:%%p/health | findstr /o /c:"\"ok\":true"
    echo  ^> node :%%p
)
cd C:\Users\AZ LP Gayatri\Desktop\AZLOGICS\6. Tip Protocol\Tip Protocol\tip-protocol
docker compose -f docker-compose.local.yml --profile observability up -d 2>&1 | tail -10


TIP_ID='tip://id/IN-c848b2630746fff0'
docker compose -f docker-compose.local.yml stop node1 node2 node3 node4 node5

for db in tip_node1 tip_node2 tip_node3 tip_node4 tip_node5; do
  docker exec tip-postgres psql -U tipuser -d $db -c "
BEGIN;
DELETE FROM platform_links WHERE tip_id = '$TIP_ID';
DELETE FROM transactions   WHERE subject_tip_id = '$TIP_ID' AND tx_type IN ('LINK_PLATFORM', 'SCORE_UPDATE', 'KEY_RECOVERY');
DELETE FROM mempool        WHERE subject_tip_id = '$TIP_ID';
DELETE FROM tx_rejections  WHERE subject_tip_id = '$TIP_ID';
COMMIT;"
done

docker compose -f docker-compose.local.yml start node1 node2 node3 node4 node5

for db in tip_node1 tip_node2 tip_node3 tip_node4 tip_node5; do
  echo -n "$db: "
  docker exec tip-postgres psql -U tipuser -d $db -t -c \
    "SELECT COUNT(*) FROM platform_links WHERE tip_id = '$TIP_ID';"
done

curl -s "http://localhost:4000/v1/identity/tip%3A%2F%2Fid%2FIN-c848b2630746fff0/platform-links"


<!-- "SELECT column_name  FROM information_schema.columns  WHERE table_schema = 'public' AND table_name = 'transactions' ORDER BY ordinal_position;" -->

GitHub
✓ Connected · vrkothekar · +5 pts
Unlink
Byzantine-fork halt at round 2458 (2/2 peers disagree at committed_round=2458; self.state_root=8090e2a7da3a5148). Operator must investigate state divergence and clearByzantineForkHalt() after resolving.

Stuck in sync mode for 10s — sync attempts likely failing in a loop. Operator action: check peer connectivity / restart this node.

~~~


TIP_ID='tip://id/IN-bf47d365db1c48cf'

for db in tip_node1; do
  echo -n "$db: "
  docker exec tip-postgres psql -U tipuser -d $db -t -c \
    "SELECT * FROM platform_links WHERE tip_id = '$TIP_ID';"
    "SELECT * FROM transactions WHERE subject_tip_id = '$TIP_ID';"
    "SELECT * FROM mempool WHERE subject_tip_id = '$TIP_ID';"
done



~~~
Consumer Key
ftX3FHxrAVCbz6yrva4I2xQfz


Secret Key
amg0CbvZYAL2SS4uj225ipmqgsLP333bNBMJiNKHJPCDJbx0eW

Bearer Token
AAAAAAAAAAAAAAAAAAAAAMd%2B9wEAAAAAZLuVetY3DgEGzBB%2BJsU9vIRzy7k%3DderyhksRWUnenUwSggLpP6iYt2zSsYjvxasZOSdZzoGLggLqcV

Client ID
U2RuVkhSRjlMSlp5MC01aGQzWG06MTpjaQ

Client Secret
Yf6To7rwWZxl3U74TAuIBAKV08KLcuufqAqUboV6KltvCtzwaE



LvBpySz1drW0u3IZdeykiyB2N

bgzqoee0ZL3LMVASynqF613tiKJ6P0ONkCz6BLBTQXFK0YUNuw

AAAAAAAAAAAAAAAAAAAAAFmK9wEAAAAAvFbQwky9pBZAnD%2BRll6%2BUyWyAVg%3Dcc33Tsx1vWLLVeGrxn8M2LjN1vmYgBfMZKJpNcZ2wy2iNX2HbG


Slk0cTZpLXRlMTZuVElHZ1FPSE86MTpjaQ

kOhBsOeubWmzXtV55BmALzfBVvYBix6HWn7tqKuq1ECNuA8A0k
~~~

