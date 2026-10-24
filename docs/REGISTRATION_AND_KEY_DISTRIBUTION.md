# Registration of Organization and Key Distribution

Step-by-step runbook for onboarding a partner organization and their node onto
the TIP **production** network: collect details, register the org, register the
node, build the credentials bundle, deliver keys, verify.

**Read this first.** Mainnet records are permanent and uncorrectable. A wrong
character in a registration mints a second, permanent identity that can never be
reconciled with the real company. Nothing in section 4 onward is reversible, so
every gate in section 2 must be green before you run anything.

Run everything from the designated registration machine, never from a shared or
day-to-day development box: the commands below handle the founding VP key and
mint partner private keys.

---

## 1. Prerequisites on the registration machine

- [ ] Repo cloned at latest `main`, `npm install` run at the **repo root** (Node 24+;
      workspaces hoist every dependency there, installing inside `node/` is wrong)
- [ ] The **mainnet founding VP key file** `tip-vp-US-0e7db4040667073a.tip.json`
      (VP id `tip://vp/US-0e7db4040667073a`, the only VP mainnet accepts) present
      locally, readable only by you (`chmod 600`). Its path on your machine is
      `<VP_KEY_FILE>` below
- [ ] Network access to `https://node.theailab.org`
- [ ] `7zz` installed for the bundle step (`brew install sevenzip` / `apt install 7zip`)
- [ ] The live mainnet `TIP_CLASSIFIER_KEY` and `TIP_METRICS_TOKEN` values available
      (from the production node configuration, not from any test environment)

## 2. Gates: all must be true before anything is registered

- [ ] Partner's company details received **in writing, from their official
      documents** (certificate of incorporation), not from memory or a web search
- [ ] Details cross-checked for internal consistency (for an Indian CIN: the
      embedded year matches the incorporation date, PTC/PLC matches the legal form)
- [ ] Partner's production host provisioned per `NODE_REQUIREMENTS.md`, with a
      **static** public IP
- [ ] Inbound TCP **4000 and 4001** verified open from the public internet
- [ ] Partner's node link confirmed: **25 Mbit/s download and upload, sustained**
      minimum, 50 recommended (`NODE_REQUIREMENTS.md`); a shared office line is
      usually not it, and a slower link installs but never keeps up
- [ ] Partner's node domain resolves to their stated IP (`dig +short <domain>`), needed **by their first boot**, not for registration: the node probes
      its own domain before announcing it on-chain. Booting without DNS only
      fails the announce with a warning, recoverable later via
      `POST /v1/node/endpoint/announce`, so registration may proceed while DNS
      is pending
- [ ] Ops contact (name + email) received and recorded somewhere durable
- [ ] Any open security decisions recorded on their tracking issues
- [ ] This is the partner's **production** onboarding, every value below must be
      a mainnet value; no test-network tokens, genesis, or URLs anywhere

Flow: collect details → register org → register node → build bundle → deliver
keys → partner boots → verify → monitor.

## 3. Collect partner details

Company details and the per-country registration identifier rules (which number
to ask for, formats, what never to accept) live in
[`ORG_REGISTRATION.md`](./ORG_REGISTRATION.md) sections 1-2. Use them as
written; do not improvise identifiers for countries not in the table.

Infrastructure details to collect alongside:

| ask | why |
|---|---|
| static public IP of the node host | the node's advertised address in its env; how peers dial it |
| domain the node will serve on | published **on-chain** as their API endpoint; must be permanent |
| confirmation TCP 4000 + 4001 are open | 4000 API, 4001 p2p; without 4001 they never fully join |
| internet link of the node host | 25 Mbit/s symmetric sustained minimum, 50 recommended (`NODE_REQUIREMENTS.md`); ask for the plan's sustained rate, not the advertised peak |
| ops contact name + email | who we call when their node misbehaves |

The mainnet node needs its **own host**: a partner already running a testnet
node cannot reuse that box (same ports, different genesis).

Ready-made request wording: `partner-onboarding-emails.html` in this directory.

**Date format:** the script takes `--incorporated YYYY-MM-DD`. Partners often
send `DD-MM-YYYY`; convert carefully and confirm the conversion back to the
partner if the day is 12 or lower (ambiguous either way).

## 4. Register the organization

Commands, verification, and gotchas live in
[`ORG_REGISTRATION.md`](./ORG_REGISTRATION.md) sections 3-5. Summary of the
non-negotiables:

1. **Dry-run first**, always: it validates the identifier against the country
   scheme, builds the real proof, and prints the derived values without touching
   any chain. Use the full mainnet command with `--dry-run` appended, so the
   output you check is exactly what the real run will produce (`--node-url` and
   `--vp-file` are printed, not used); the real run in step 2 is this command
   minus the last line:

   ```bash
   node scripts/register-org.js \
     --name "<EXACT LEGAL NAME>" \
     --reg-number <IDENTIFIER> \
     --incorporated YYYY-MM-DD \
     --region <ISO-2> \
     --org-type <legal-form, e.g. private-limited-company> \
     --partner <partner-slug> \
     --node-url https://node.theailab.org \
     --vp-file <VP_KEY_FILE> \
     --dry-run
   ```

   A good dry run looks like this (THE PRESCIENT PACHYDERM LTD, public
   Companies House data):

   ```text
   Register organization identity

     ✓ GB identifier: company number (Companies House) (16846775)
     ✓ Approving VP: tip://vp/US-0e7db4040667073a
     ✓ Keypair generated: tip://id/GB-e9b2794d13d6c080
     ℹ Generating ZK dedup proof (Groth16)...
     ✓ Dedup hash: 158935866912253872021836...
     ✓ VP attestation signed

       Organization          THE PRESCIENT PACHYDERM LTD
       TIP-ID                tip://id/GB-e9b2794d13d6c080
       Region                GB
       Reg number            16846775 (company number (Companies House))
       Incorporated          2025-11-11
       Org type              private-limited-company
       Target                https://node.theailab.org

     ! --dry-run: nothing was registered and no files were written
   ```

   Check, line by line, against the partner's registration certificate:

   | line | must be | why it matters |
   |---|---|---|
   | `identifier:` | the scheme that matches the document the partner sent (Companies House number, EIN, CIN, ...) and the number exactly as printed with separators stripped (`32-0727201` shows as `320727201`), leading zeros kept | the number is hashed into the identity; a dropped zero or the wrong scheme is a different, permanent org |
   | `Approving VP:` | `tip://vp/US-0e7db4040667073a` (the mainnet founding VP) | any other VP means the test key was picked up; mainnet rejects it and a local target would mint a throwaway |
   | `Organization` | the legal name character for character, including suffix and case (`LTD`, `LLC`, `PRIVATE LIMITED`) | stored as `creator_name`, shown on every post; there is no rename |
   | `Region` | the country of incorporation, not the office or the founder | part of the TIP-ID prefix and of the dedup hash |
   | `Incorporated` | the date on the certificate, `YYYY-MM-DD` | hashed, and it is the password of the key file the partner receives |
   | `Org type` | the legal form in lowercase-hyphen spelling (`llc`, `private-limited-company`, `llp`, `gmbh`, `nonprofit`); never `(none)` for a real run | immutable today and shown to users; see #343 |
   | `Target` | `https://node.theailab.org` | a local target silently registers on the laptop cluster |

   Two things in the dry run are **not** the final values: the `TIP-ID` and
   the keypair are regenerated on the real run, so do not record them anywhere.
   The `Dedup hash` on the other hand is derived only from reg number, date
   and region, so it is already the real one: if the org was registered before
   with the same inputs, the prefix matches the `dedup_hash` in its key file
   (the example above reproduces Pachyderm's), and the real run would answer
   `409 Identity already registered`. A country not in the scheme table stops
   the run; that is a feature; see `ORG_REGISTRATION.md` before adding a
   country.

2. **The real run must name the mainnet VP and the mainnet node.** Without
   `--vp-file` the script picks up whatever VP key sits in
   `genesis-data/backups`, which on most machines is a test VP, and mainnet
   rejects it with `Only the founding VP can approve`:

   ```bash
   node scripts/register-org.js \
     --name "<EXACT LEGAL NAME>" \
     --reg-number <IDENTIFIER> \
     --incorporated YYYY-MM-DD \
     --region <ISO-2> \
     --org-type <legal-form> \
     --partner <partner-slug> \
     --node-url https://node.theailab.org \
     --vp-file <VP_KEY_FILE>   # .../tip-vp-US-0e7db4040667073a.tip.json
   ```

3. **Verify from two different nodes**: they must agree. Set the ID on its own
   line first (no trailing backslash: pasting the assignment and the loop as
   one line is a shell parse error):

   ```bash
   ORG_ID='tip://id/<REGION>-<id>'
   ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$ORG_ID")
   curl -s "https://node.theailab.org/v1/identity/$ENC"  | python3 -m json.tool | grep -E '"tip_id"|"creator_name"|"region"|"status"|"org_type"|"vp_id"|"registered_at"'
   curl -s "https://node2.theailab.org/v1/identity/$ENC" | python3 -m json.tool | grep -E '"tip_id"|"creator_name"|"region"|"status"|"org_type"|"vp_id"|"registered_at"'
   ```

   A verified, correct registration prints the same block from both nodes
   (SS SOFTWARE SOLUTIONS LLC, live on mainnet):

   ```text
       "status": 200,
           "tip_id": "tip://id/US-b4f0805cf87ce2f0",
           "region": "US",
           "vp_id": "tip://vp/US-0e7db4040667073a",
           "status": "active",
           "registered_at": "2026-09-23T09:50:57.212Z",
           "creator_name": "SS SOFTWARE SOLUTIONS LLC",
           "org_type": "llc",
   ```

   What each line proves:

   | line | must be | if not |
   |---|---|---|
   | first `"status": 200` | `200` | `404` within the first seconds is normal (tx still committing, retry); `404` after a minute means the tx was rejected, read the register-org output |
   | `tip_id` | the ID the real run printed | a different ID means you are looking at the wrong row |
   | `region` | the country passed as `--region` | wrong input; the identity is permanent, register again with the right values and never hand out this one |
   | `vp_id` | `tip://vp/US-0e7db4040667073a` | another VP id cannot happen on mainnet (the node refuses non-founding VPs); seeing one means the target was not mainnet |
   | `"status": "active"` | `active` | anything else: stop, the org cannot sign |
   | `registered_at` | the time of the real run, UTC | an older time means the org already existed (the run returned 409) |
   | `creator_name` | the legal name exactly as on the certificate | typo: permanent, see `region` |
   | `org_type` | the legal form passed as `--org-type` | missing means the flag was omitted; there is no update tx yet (#343) |

   The two nodes must print identical values; a difference is a sync problem,
   not a registration problem (check `/status` on the lagging node). The API
   does not return `tip_id_type`; the `org_type` line is what tells an
   organization row from a person's (`creator_name` exists on both).

4. The org key file lands in `generated/<partner-slug>/org/` at mode 0600.
   Leave it there for now; it is needed in section 5 (cosign) and section 6 (bundle).

## 5. Register the node

The node is registered *by us* but *operated by them*, and that claim is signed
twice: the founding VP approves the node, and the **organization cosigns**,
because naming an operator is a claim about a third party: the org's own key
must agree to it.

**Before the run:** `genesis-data/genesis.json` on the registration machine
must be the mainnet genesis. The script reads the founding VP from that file
and refuses the mainnet VP key if it is not (`loaded VP key is tip://vp/US-0e7db4040667073a
but the chain's founding VP is tip://vp/US-e2bc656109331767` means the checkout
carries the test genesis: `git checkout -- genesis-data/genesis.json`, then
confirm `d4666ce1`):

```bash
python3 -c "import json;print(json.load(open('genesis-data/genesis.json'))['genesis_hash'][:8])"   # d4666ce1
```

**1. Dry run.** Same command as the real run plus `--dry-run`; it signs
everything, writes the env and README, registers nothing and keeps no key:

```bash
node scripts/register-node.js \
  --name "<Partner> Node" \
  --partner <partner-slug> \
  --node-url https://node.theailab.org \
  --operated-by "tip://id/<REGION>-<org-id>" \
  --operator-key-file generated/<partner-slug>/org/<org-tip-id>.tip.json \
  --operator-key-date <incorporation date, YYYY-MM-DD> \
  --vp-file <VP_KEY_FILE>   # .../tip-vp-US-0e7db4040667073a.tip.json \
  --production \
  --port 4000 \
  --api-endpoint "https://<their-node-domain>" \
  --public-url "https://<their-node-domain>" \
  --public-ip <their-static-ip> \
  --dry-run
```

A good dry run (Rooverse, operated by THE PRESCIENT PACHYDERM LTD):

```text
  ✓ Founding VP keys loaded: tip://vp/US-0e7db4040667073a
  ℹ Target node: https://node.theailab.org
  ✓ Node healthy, DAG: 2070 txs
  ✓ Founding VP: tip://vp/US-0e7db4040667073a
  ✓ Keypair generated: tip://node/f7977ede8905c869
  ✓ Council signature created
  ✓ Operator cosignature created: tip://id/GB-400d3636845c06f2
  ! --dry-run: skipping registration, rendering the env only
  ✓ Backup (skipped, dry-run): generated/rooverse/node/tip-node-f7977ede8905c869.tip.json
  ✓ Bootstrap multiaddr: /ip4/54.86.250.48/tcp/4001/p2p/12D3KooWFFwHuj68SBoL6DaCnZWaa4QxjY4dnKKfMgQpBNqAz2jn
  ✓ Env file: generated/rooverse/node/rooverse-node.env
```

Check:

| line | must be |
|---|---|
| `Founding VP keys loaded:` **and** `Founding VP:` | both `tip://vp/US-0e7db4040667073a`; the first is the file you passed, the second comes from the local genesis |
| `Target node:` / `Node healthy` | `https://node.theailab.org`, healthy |
| `Operator cosignature created:` | the partner's org id from section 4; the script already proved the key file opens with the date and belongs to that org |
| `Bootstrap multiaddr:` | `/ip4/54.86.250.48/tcp/4001/p2p/12D3KooWFFwHuj68SBoL6DaCnZWaa4QxjY4dnKKfMgQpBNqAz2jn` (node 1); a `Could not read bootstrap_addr` failure means `TIP_BOOTSTRAP_PEERS` must be filled by hand |
| `Keypair generated:` | throwaway; the real run makes a new one, do not record it |

The dry run really writes `generated/<partner-slug>/README.md` and
`generated/<partner-slug>/node/<name-slug>.env` (only the key file is skipped);
a rerun with the same `--partner` and `--name` overwrites both in place, and the
real run overwrites the env once more with the real node id, so keep those two
flags identical across the dry run and the real run and never bundle a dry-run
env. Open the rendered env and check these lines, which carry the partner's
values:

```text
NODE_ENV=production
TIP_PUBLIC_URL=https://<their-node-domain>
TIP_API_ENDPOINT=https://<their-node-domain>
TIP_PUBLIC_IP=<their-static-ip>
PORT=4000
TIP_P2P_PORT=4001
TIP_BOOTSTRAP_PEERS=/ip4/54.86.250.48/tcp/4001/p2p/12D3KooW...
TIP_CLASSIFIER_URL=https://tipclassifier.theailab.org
TIP_CLASSIFIER_FALLBACK=0
TIP_CLASSIFIER_SCAN_NON_OH=true
```

The only `CHANGE_ME` left is `DB_PASSWORD`; `TIP_CLASSIFIER_KEY`,
`TIP_CLASSIFIER_CALLBACK_SECRET` and `TIP_METRICS_TOKEN` are empty on purpose
(section 6.2). There must be no `TIP_*_ACTIVATION_MS` line. Ignore the printed
"Setup for the new node" block: it describes a local node; the partner's steps
are `DEPLOYMENT.md` (section 7).

**2. Real run:** the same command without `--dry-run`. It prints, in addition:

```text
  ✓ Node registered: tip://node/<id>
    Name                    <Partner> Node
    Confirmation            proposed
  ✓ Backup: generated/<slug>/node/tip-node-<id>.tip.json
```

`proposed` is normal (the tx commits a few seconds later). Record the
`tip://node/<id>`; that is the partner's node identity, and the backup file is
their node key (mode 0600, bundled in section 6).

Flag by flag:

| flag | meaning |
|---|---|
| `--operated-by` | the org identity accountable for this node |
| `--operator-key-file` / `--operator-key-date` | the org's key from section 4, locked with the incorporation date; produces the cosignature |
| `--vp-file` | the mainnet founding VP key `tip-vp-US-0e7db4040667073a.tip.json`; without it the script uses the test VP in `genesis-data/backups` and mainnet rejects the signature |
| `--production` | `NODE_ENV=production` plus the federation's live defaults in the env |
| `--port` | 4000 (p2p follows on 4001); the script default 4100 is for extra local nodes |
| `--api-endpoint` | their domain; the node announces it **on-chain** at first boot after probing that the URL answers `/health` as itself |
| `--public-url` / `--public-ip` | what the API surfaces / what peers dial back; omitted under `--production` they become `CHANGE_ME` |

The env is generated **only** from `.env.example` plus these flags; nothing from
the registration machine's shell can leak into it. Pass the same `--partner
<slug>` to the org and node runs so both land in `generated/<slug>/` (org key
under `org/`, node key and env under `node/`, plus the auto-written README).

**3. Verify from two different nodes.** The registry is public, no token:

```bash
curl -s https://node.theailab.org/v1/nodes  | python3 -m json.tool | grep -B2 -A6 '"<Partner> Node"'
curl -s https://node2.theailab.org/v1/nodes | python3 -m json.tool | grep -B2 -A6 '"<Partner> Node"'
```

`"<Partner> Node"` is the exact `--name` value, quotes included; any other
spelling and grep prints nothing. Example for the SS node, live on mainnet:

```bash
curl -s https://node.theailab.org/v1/nodes | python3 -m json.tool | grep -B2 -A6 '"SS Software Node"'
```

prints this (and node2 prints the same):

```text
            {
                "node_id": "tip://node/e2bc616656de7c31",
                "name": "SS Software Node",
                "status": "active",
                "api_endpoint": "https://sssoftware-node.theailab.org",
                "operated_by": "tip://id/US-b4f0805cf87ce2f0",
                "founding": false,
                "registered_at": "2026-09-23T09:54:42.329Z"
            }
```

| line | must be |
|---|---|
| `node_id` | the id the real run printed |
| `name` | the `--name` value; this is what `/status` pages and the registry show |
| `status` | `active` |
| `api_endpoint` | **`null` right after registration**; it becomes their URL on their first boot (section 7) |
| `operated_by` | the partner's org id |
| `founding` | `false` (only the three Lab nodes are `true`) |
| `registered_at` | the time of the real run, UTC |

Both nodes must show identical values. Nothing on the partner's machine needs
to be live yet; this step involves only our nodes.

## 6. Build and deliver the credentials bundle

### 6.1 The bundle contents: assembled automatically

Point the bundler (6.3) at `generated/<partner>/` and it stages the deliverable
itself from whatever the registrations produced:

```
<Partner>/                                     inside the zip
├── node.env                                   <- generated/<partner>/node/<slug>.env
├── NODE-KEY__tip-node-<id>.tip.json           <- generated/<partner>/node/
├── ORG-IDENTITY__id-<REGION>-<id>.tip.json    <- generated/<partner>/org/
└── README.md                                  <- the partner-root README
```

What to expect from the bundler: a credential that is not there is reported as
`WARNING: not in this bundle: ...` and skipped, so an org-only or node-only
delivery is normal; a folder with no credentials at all refuses to build. No
genesis ships in the bundle: the repo the partner clones carries the mainnet
genesis, and the hash check is theirs (`DEPLOYMENT.md`).

The `NODE-KEY__` / `ORG-IDENTITY__` prefixes are ours, so the partner cannot
confuse the two files: the node key goes on the node host, the org identity
stays **off** the node host entirely. Where each file ends up on their host
(key renamed into `genesis-data/backups/`, owned by uid 1001, `node.env` copied
to `.env`) is the partner's step in `DEPLOYMENT.md`, section *Joining an
Existing Federation*, and the bundle README repeats it; nothing in it is done
from our side.

### 6.2 Hand-fill the secrets in `node.env`

`--production` already writes the federation-wide values: classifier URL, CORS
origins, strict classifier fallback, the mainnet rate limit and prescan
concurrency, and container-relative data/log paths. `node-env-template.js`
refuses to write credentials at all, so those stay hand work. Edit
`generated/<partner>/node/<slug>.env` **before** building the zip (the bundler
warns on empty values but does not fail):

- `TIP_CLASSIFIER_KEY`: the live production classifier key. Prefer one minted
  for this node rather than the shared key: a shared key cannot be revoked
  without rotating every node at once
- `TIP_METRICS_TOKEN`: the production metrics token (a 64-char random value; a
  token starting `certtest` is a test-network token and must never appear here)
- `TIP_CLASSIFIER_CALLBACK_SECRET`: the callback secret the classifier team
  issued with the key. Optional: empty means the node polls for verdicts instead
  of receiving callbacks (slower, still correct)
- `TIP_BOOTSTRAP_PEERS`: the generator writes node 1 only. Replace it with all
  three founding peers, comma-separated, so a restart does not depend on one box:

  ```text
  /ip4/54.86.250.48/tcp/4001/p2p/12D3KooWFFwHuj68SBoL6DaCnZWaa4QxjY4dnKKfMgQpBNqAz2jn,/ip4/3.228.92.23/tcp/4001/p2p/12D3KooWEbJH8E1J7Zpsghu48DXiowTeFsREDpk8SQKkjJeFUie9,/ip4/44.205.65.32/tcp/4001/p2p/12D3KooWES4aitBSBGFBBQ8mDFkpDq7tJ6Zy6V5h7jYSqdihbZHh
  ```

  (each is `data.p2p.bootstrap_addr` from that node's `/health`; re-read them if
  a founding node is ever re-keyed)
- No `TIP_*_ACTIVATION_MS` line: the code defaults are the mainnet epochs. A
  value here is only right on a network that activated a rule at another time

Then two checks on the finished file. First, the values that must not carry
anything unexpected:

```bash
grep -E '^(TIP_NODE_CREDENTIALS_FILE|TIP_PUBLIC_IP|TIP_PUBLIC_URL|DB_PASSWORD|TIP_CORS_ORIGINS|TIP_CLASSIFIER_FALLBACK)=' generated/<partner>/node/<slug>.env
```

prints six lines; for the Rooverse env generated in section 5:

```text
TIP_NODE_CREDENTIALS_FILE=genesis-data/backups/tip-node-<id>.tip.json
TIP_PUBLIC_URL=https://node.rooverse.example
TIP_PUBLIC_IP=203.0.113.10
DB_PASSWORD=CHANGE_ME_STRONG_DB_PASSWORD
TIP_CLASSIFIER_FALLBACK=0
TIP_CORS_ORIGINS=https://theailab.org,https://www.theailab.org,https://vp.theailab.org
```

| line | good |
|---|---|
| `TIP_NODE_CREDENTIALS_FILE` | `tip-node-<id>` is the id the real run printed, the same as the key file in `generated/<partner>/node/`; a different id means the env is from a dry run |
| `TIP_PUBLIC_URL` / `TIP_PUBLIC_IP` | the partner's domain and static IP you passed; `CHANGE_ME_*` only if you did not pass them (then the partner fills them before first boot) |
| `DB_PASSWORD` | **stays** `CHANGE_ME_STRONG_DB_PASSWORD`; the partner sets it, we never know it |
| `TIP_CLASSIFIER_FALLBACK` | `0` |
| `TIP_CORS_ORIGINS` | the three Lab origins, never `*` |

Second, the two secrets are filled, checked without printing them:

```bash
grep -cE '^(TIP_CLASSIFIER_KEY|TIP_METRICS_TOKEN)=.+' generated/<partner>/node/<slug>.env   # 2 (0 before you filled them)
grep -c certtest generated/<partner>/node/<slug>.env                                      # 0
```

**Media storage is not in the env.** Every mainnet node writes media to its own
S3 bucket with SSE-KMS; the generated env ships `TIP_MEDIA_BACKEND=fs`, which
writes media bytes to the node disk instead. Provision the bucket, KMS key and
instance role per [`PROD_S3_SETUP.md`](./PROD_S3_SETUP.md), then set
`TIP_MEDIA_BACKEND=s3` and the three values `TIP_MEDIA_S3_BUCKET`,
`TIP_MEDIA_S3_REGION`, `TIP_MEDIA_S3_KMS_KEY_ID` (plus `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` only when the host has no instance role) before the
node serves real traffic. This is usually done by the partner on their host, not
in the bundle.

### 6.3 Build the encrypted zip

```bash
scripts/make-secure-bundle.sh generated/<partner> "<Org Name>"
```

`<Org Name>` becomes the folder the partner sees after extracting and the zip's
file name. For Rooverse:

```bash
scripts/make-secure-bundle.sh generated/rooverse "The Prescient Pachyderm"
```

prints:

```text
  zip      : generated/deliveries/The Prescient Pachyderm-credentials.zip
  password : XXXX-XXXX-XXXX-XXXX-XXXX

  Extracts to The Prescient Pachyderm/ :
    NODE-KEY__tip-node-<id>.tip.json
    ORG-IDENTITY__id-GB-400d3636845c06f2.tip.json
    README.md
    node.env

  Attach the zip. Send the password by phone or Signal, never in the same thread.
```

| line | good |
|---|---|
| any `WARNING: TIP_CLASSIFIER_KEY is empty` / `TIP_METRICS_TOKEN is empty` **above** the zip line | section 6.2 was skipped; the zip was still built, so fix the env and build again (a second zip with a new password replaces the first) |
| `WARNING: not in this bundle: ...` | expected only for an org-only or node-only delivery |
| `Extracts to` | all four files for a full delivery; the node id in `NODE-KEY__` is the one the real run printed in section 5 |
| `password` | 20 characters, shown once here and appended to `generated/ZIP-PASSWORDS.md` |

The zip is AES-256 (never ZipCrypto). Outputs land **next to the partner
directory**, so for `generated/<partner>` they are `generated/deliveries/<Org
Name>-credentials.zip` and `generated/ZIP-PASSWORDS.md`; every partner's zips
collect in that one `deliveries/` folder (gitignored). Each log line carries
the first 16 hex of the zip's sha256, which is how you pick the right password
when several zips exist for the same partner:

```bash
shasum -a 256 "generated/deliveries/The Prescient Pachyderm-credentials.zip" | cut -c1-16   # must appear on the log line
7zz l -p"<password>" "generated/deliveries/The Prescient Pachyderm-credentials.zip" | grep -c '\.tip\.json\|node.env\|README'   # 4
```

### 6.4 Deliver

- **The zip goes by email. The password goes by phone or WhatsApp. Never both
  in the same channel**: if the password rides with the archive, the
  encryption bought nothing.
- Attach **one partner's zip only**. Bundles are named per partner and sit in
  one output directory; check the attachment name against the To: field before
  sending.
- The partner needs an AES-capable extractor (7-Zip on Windows, Keka or The
  Unarchiver on macOS); the built-in extractors on both platforms fail on AES
  zips. The email template says this.

Email wording: `partner-onboarding-emails.html`, mainnet card.

### 6.5 Issue the log-shipping label and password

The bundle does not carry log-shipping settings; the partner creates
`promtail.env` from `PARTNER_LOG_SHIPPING.md`, and we issue the two values it
needs. Do this with the bundle delivery, not after the first incident.

- **Node label** (`NODE_LABEL`): the organisation slug, lowercase, hyphens,
  unique across the federation (`ss-software`, `az-logics`, `rooverse`). Our
  own nodes are `node1`, `node2`, `node3`. It becomes `node="<label>"` on every
  log line, so the dashboards only show what is sent under exactly that label.
  Put the label in the onboarding email next to the zip name.
- **Username**: `promtail`, fixed in the agent config; nothing to issue.
- **Password** (`LOKI_PASSWORD`): the current Loki push password. It is one
  shared credential for every node today (the plaintext of the Caddy
  `basic_auth` hash on the observability host; the same value is in each Lab
  node's `promtail.env`). Send it on the same separate channel as the zip
  password, never in the email. A leak means rotating it on every node, ours
  and partners', so treat it like a node key.
- **Record** the label, the date and who received it in the partner's entry in
  the private notes; the password itself is only ever in `promtail.env` files
  and the Caddy hash.

Verification after their agent starts: the node appears under its label in
the federation dashboard within a minute; a `401` in `docker logs tip-promtail`
means the password does not match the hash.

## 7. Partner boots, we verify

Partner side: `DEPLOYMENT.md`, section *[Joining an Existing Federation (partner
node)](./DEPLOYMENT.md#joining-an-existing-federation-partner-node)*. Not
*Production Federation Deploy*, which is a cold start for a new chain and tells
them to seed. The three classic stumbles: the container runs as uid 1001,
`logs/` must be chown'd before first boot, and the node key has to be moved into
`genesis-data/backups/` where `TIP_NODE_CREDENTIALS_FILE` points.

**They must never run `scripts/seed.js`.** It mints a fresh genesis, and a node
whose `genesis_hash` differs cannot handshake with anyone. It presents as zero
peers and a permanent `syncing`, not as an error.

Our side: four checks, in this order. Each proves something different:

1. **Connected.** `curl -s https://<their-domain>/ready` shows `ready:true`,
   `halted:false`, `join_state:"ready"`. `syncing` / `catching_up` means still
   downloading state, normal for a while on first boot.
2. **Right network.** `/health` shows `peers.connected >= 1`. The p2p handshake
   authorises peers against the genesis-scoped on-chain registry, so a node on
   the wrong genesis cannot peer at all: non-zero peers **is** proof of the
   correct chain.
3. **All data correct, the definitive check.** Their
   `/v1/state-root` matches ours at the same round:

   ```bash
   curl -s https://<their-domain>/v1/state-root
   curl -s https://node.theailab.org/v1/state-root
   ```

   Equal `state_merkle_root` at equal `round` means their entire state is
   byte-identical to ours. Rounds advance every ~2s, so compare matching round
   numbers.
4. **Staying in sync.** `consensus.narwhal.round` increases between two calls
   and `consensus.halt.lastAdvanceAt` is within the last few seconds.

Then confirm their `api_endpoint` appears on-chain: their entry in
`https://node.theailab.org/v1/nodes` flips from `null` to their URL after the
first boot (the announce probes the domain, so DNS must resolve by then), and
`https://<their-domain>/status` shows "All good". Finally have them register
one test content and check it reaches `prescan: completed`.

## 8. After onboarding

- [ ] Add their node to the production Prometheus scrape targets: on the
      observability host, `~/tip-protocol/infra/observability/prod/prometheus.yml`,
      add `"<their-domain>:443"` under the `tip-federation` job next to the
      other partner nodes, then `docker compose up -d --force-recreate prometheus`.
      Grafana picks the node up by its id; bookmark `https://<their-domain>/status`
- [ ] If they serve media from their own bucket, have the classifier team add
      that bucket host to the classifier's `allowed_download_domains`; nothing
      on our side is IP-based (metrics are token-based, Loki uses the shared login)
- [ ] Record the ops contact in the operations inventory, not only in the email
      thread
- [ ] Walk the partner through key custody one more time: offline backup of both
      key files, org identity never on the node host

**Key loss or leak:** the classifier key and metrics token are shared,
fleet-rotatable credentials: a leak means rotating every node at once, so
report immediately. The **node key cannot be rotated at all** (issue #257): a
leaked or lost node key means deregistering and re-registering the node under a
new identity. The org identity key is rotatable via `KEY_ROTATED`.

## Troubleshooting

| symptom | cause |
|---|---|
| `Only the founding VP can approve` | wrong or missing `--vp-file`: you signed with a non-mainnet VP |
| `409 Identity already registered` | dedup hit: this company (same number + date + country) is already on-chain. If that is a surprise, stop and investigate before anything else |
| partner node: 0 peers and stuck at `join_state: syncing` despite open ports | almost always the wrong `genesis.json`. There is no clean "wrong network" error; this is what it looks like. Check the genesis before debugging firewalls |
| endpoint announce failed at boot | their DNS does not resolve, or 4000 is not reachable from the internet. Fix, then `POST /v1/node/endpoint/announce` on their node re-announces without a restart |
| partner cannot open the zip | OS built-in extractor; they need 7-Zip / Keka / The Unarchiver |

---

## Appendix A: worked example, full local rehearsal

Rehearse the entire flow on the local cluster before any mainnet run. Fictional
company throughout; local cluster must be up (`curl -s localhost:4000/ready`).
The local VP key in `genesis-data/backups` is picked up automatically, no
`--vp-file` locally, which is exactly why mainnet **must** pass it.

```bash
# R1: dry-run. Validates the identifier, builds the proof, registers nothing
node scripts/register-org.js \
  --name "THE PRESCIENT PACHYDERM LTD" \
  --reg-number 16846775 \
  --incorporated 2025-11-11 \
  --region GB \
  --org-type private-limited-company \
  --dry-run

# R2: register the org locally (note the printed tip://id/GB-... for R3/R4)
node scripts/register-org.js \
  --name "THE PRESCIENT PACHYDERM LTD" \
  --reg-number 16846775 \
  --incorporated 2025-11-11 \
  --region GB \
  --org-type private-limited-company \
  --partner pachyderm \
  --node-url http://localhost:4000
```

```bash
# R3: verify from two local nodes (both must agree)
ORG_ID='tip://id/GB-xxxxxxxxxxxxxxxx'
ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$ORG_ID")
curl -s "http://localhost:4000/v1/identity/$ENC" | python3 -m json.tool | grep -E '"creator_name"|"status"|"org_type"'
curl -s "http://localhost:4100/v1/identity/$ENC" | python3 -m json.tool | grep -E '"creator_name"|"status"|"org_type"'
```

```bash
# R4: register the node, org cosigning (use the exact key path R2 printed)
node scripts/register-node.js \
  --name "Pachyderm Node" \
  --node-url http://localhost:4000 \
  --operated-by "$ORG_ID" \
  --partner pachyderm \
  --operator-key-file generated/pachyderm/org/<org-tip-id>.tip.json \
  --operator-key-date 2025-11-11 \
  --production \
  --port 4000 \
  --api-endpoint "https://tipnode.pachyderm.example" \
  --public-url "https://tipnode.pachyderm.example" \
  --public-ip 203.0.113.10

# R5: verify the roster on two local nodes (public endpoint, no token)
curl -s http://localhost:4000/v1/nodes | python3 -m json.tool | grep -B2 -A6 '"Pachyderm Node"'
curl -s http://localhost:4100/v1/nodes | python3 -m json.tool | grep -B2 -A6 '"Pachyderm Node"'
```

```bash
# R6: rehearse the bundle. One command, staged straight from the partner dir
scripts/make-secure-bundle.sh generated/pachyderm Pachyderm
ls -la generated/deliveries/             # the zip; password was printed + logged
rm -rf generated/pachyderm generated/deliveries generated/ZIP-PASSWORDS.md   # rehearsal cleanup
```

The same flow on mainnet, with the real target, the real VP key file and the
real verification hosts; everything else is identical:

```bash
VP=/path/to/tip-vp-US-0e7db4040667073a.tip.json

# M1: org, dry run then real (drop --dry-run)
node scripts/register-org.js \
  --name "THE PRESCIENT PACHYDERM LTD" \
  --reg-number 16846775 \
  --incorporated 2025-11-11 \
  --region GB \
  --org-type private-limited-company \
  --partner pachyderm \
  --node-url https://node.theailab.org \
  --vp-file "$VP" \
  --dry-run

# M2: node, org cosigning, dry run then real (drop --dry-run)
node scripts/register-node.js \
  --name "Pachyderm Node" \
  --partner pachyderm \
  --node-url https://node.theailab.org \
  --operated-by "$ORG_ID" \
  --operator-key-file generated/pachyderm/org/<org-tip-id>.tip.json \
  --operator-key-date 2025-11-11 \
  --vp-file "$VP" \
  --production \
  --port 4000 \
  --api-endpoint "https://tipnode.pachyderm.example" \
  --public-url "https://tipnode.pachyderm.example" \
  --public-ip 203.0.113.10 \
  --dry-run

# M3: verify on two mainnet nodes
curl -s "https://node.theailab.org/v1/identity/$ENC"  | python3 -m json.tool | grep -E '"creator_name"|"status"|"org_type"'
curl -s "https://node2.theailab.org/v1/identity/$ENC" | python3 -m json.tool | grep -E '"creator_name"|"status"|"org_type"'
curl -s https://node.theailab.org/v1/nodes  | python3 -m json.tool | grep -B2 -A6 '"Pachyderm Node"'
curl -s https://node2.theailab.org/v1/nodes | python3 -m json.tool | grep -B2 -A6 '"Pachyderm Node"'
```

Then the env is hand-filled with production secrets before bundling (section 6.2).
