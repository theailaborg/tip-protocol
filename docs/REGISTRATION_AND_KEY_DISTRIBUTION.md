# Registration of Organization and Key Distribution

Step-by-step runbook for onboarding a partner organization and their node onto
the TIP **production** network: collect details, register the org, register the
node, build the credentials bundle, deliver keys, verify.

**Read this first.** Mainnet records are permanent and uncorrectable. A wrong
character in a registration mints a second, permanent identity that can never be
reconciled with the real company. Nothing in section 3 onward is reversible, so
every gate in section 1 must be green before you run anything.

Run everything from the designated registration machine, never from a shared or
day-to-day development box: the commands below handle the founding VP key and
mint partner private keys.

---

## 0. Prerequisites on the registration machine

- [ ] Repo cloned at latest `main`, `npm install` completed (Node 22+)
- [ ] The **mainnet founding VP key file** (`tip-vp-....tip.json`) present locally,
      readable only by you (`chmod 600`). Referred to below as `<VP_KEY_FILE>`
- [ ] Network access to `https://node.theailab.org`
- [ ] `7zz` installed for the bundle step (`brew install sevenzip` / `apt install 7zip`)
- [ ] The live mainnet `TIP_CLASSIFIER_KEY` and `TIP_METRICS_TOKEN` values available
      (from the production node configuration, not from any test environment)

## 1. Gates , all must be true before anything is registered

- [ ] Partner's company details received **in writing, from their official
      documents** (certificate of incorporation), not from memory or a web search
- [ ] Details cross-checked for internal consistency (for an Indian CIN: the
      embedded year matches the incorporation date, PTC/PLC matches the legal form)
- [ ] Partner's production host provisioned per `NODE_REQUIREMENTS.md`, with a
      **static** public IP
- [ ] Inbound TCP **4000 and 4001** verified open from the public internet
- [ ] Partner's node domain **already resolves** to their stated IP
      (`dig +short <domain>`). The node verifies its own domain at first boot;
      missing DNS means the on-chain endpoint announce fails
- [ ] Ops contact (name + email) received and recorded somewhere durable
- [ ] Any open security decisions recorded on their tracking issues
- [ ] This is the partner's **production** onboarding , every value below must be
      a mainnet value; no test-network tokens, genesis, or URLs anywhere

Flow: collect details → register org → register node → build bundle → deliver
keys → partner boots → verify → monitor.

## 2. Collect partner details

Company details and the per-country registration identifier rules (which number
to ask for, formats, what never to accept) live in
[`ORG_REGISTRATION.md`](./ORG_REGISTRATION.md) sections 1-2. Use them as
written; do not improvise identifiers for countries not in the table.

Infrastructure details to collect alongside:

| ask | why |
|---|---|
| static public IP of the node host | we allow-list it; peers store it |
| domain the node will serve on | published **on-chain** as their API endpoint; must be permanent |
| confirmation TCP 4000 + 4001 are open | 4000 API, 4001 p2p; without 4001 they never fully join |
| ops contact name + email | who we call when their node misbehaves |

Ready-made request wording: `partner-onboarding-emails.html` in this directory.

**Date format:** the script takes `--incorporated YYYY-MM-DD`. Partners often
send `DD-MM-YYYY`; convert carefully and confirm the conversion back to the
partner if the day is 12 or lower (ambiguous either way).

## 3. Register the organization

Commands, verification, and gotchas live in
[`ORG_REGISTRATION.md`](./ORG_REGISTRATION.md) sections 3-5. Summary of the
non-negotiables:

1. **Dry-run first**, always , it validates the identifier against the country
   scheme, builds the real proof, and prints the derived values without touching
   any chain:

   ```bash
   node scripts/register-org.js \
     --name "<EXACT LEGAL NAME>" \
     --reg-number <IDENTIFIER> \
     --incorporated YYYY-MM-DD \
     --region <ISO-2> \
     --org-type <legal-form, e.g. private-limited-company> \
     --dry-run
   ```

   Check the output: identifier accepted under the right scheme, name exact,
   date right. A country not in the scheme table stops the run , that is a
   feature; see `ORG_REGISTRATION.md` before adding a country.

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
     --node-url https://node.theailab.org \
     --vp-file <VP_KEY_FILE>
   ```

3. **Verify from two different nodes** , they must agree. Set the ID on its own
   line first (no trailing backslash , pasting the assignment and the loop as
   one line is a shell parse error):

   ```bash
   ORG_ID='tip://id/<REGION>-<id>'
   ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$ORG_ID")
   curl -s "https://node.theailab.org/v1/identity/$ENC"  | python3 -m json.tool | grep -E '"creator_name"|"region"|"status"|"org_type"'
   curl -s "https://node2.theailab.org/v1/identity/$ENC" | python3 -m json.tool | grep -E '"creator_name"|"region"|"status"|"org_type"'
   ```

   `status` must be `active`, `tip_id_type` `organization`, `creator_name`
   exact.

4. The org key file lands in `generated_orgs/<slug>-<short-id>/` at mode 0600.
   Leave it there for now; it is needed in step 4 (cosign) and step 5 (bundle).

## 4. Register the node

The node is registered *by us* but *operated by them*, and that claim is signed
twice: the founding VP approves the node, and the **organization cosigns**,
because naming an operator is a claim about a third party , the org's own key
must agree to it.

```bash
node scripts/register-node.js \
  --name "<Partner> Node" \
  --partner <partner-slug> \
  --node-url https://node.theailab.org \
  --operated-by "tip://id/<REGION>-<org-id>" \
  --operator-key-file generated/<partner-slug>/org/<org-tip-id>.tip.json \
  --production \
  --api-endpoint "https://<their-node-domain>" \
  --public-url "https://<their-node-domain>" \
  --public-ip <their-static-ip>
```

Flag by flag:

| flag | meaning |
|---|---|
| `--operated-by` | the org identity accountable for this node |
| `--operator-key-file` | the org's key from step 3 , produces the cosignature |
| `--production` | `NODE_ENV=production` in the generated env; CORS must be filled by the partner, never `*` |
| `--api-endpoint` | their domain; the node announces it **on-chain** at first boot after probing that the URL answers `/health` as itself |
| `--public-url` / `--public-ip` | what the API surfaces / what peers dial back |

The script generates the env **only** from `.env.example` plus these flags , it
reads nothing from your shell, so nothing from the registration machine can leak
into the partner's file. Secrets are added by hand in step 5.

Pass the same `--partner <slug>` to both the org and node runs and everything
lands in one folder:

```
generated/<partner>/
├── README.md          <- auto-written handling rules for every credential type
├── org/<org-id>.tip.json
└── node/
    ├── <node-id>.tip.json
    └── <slug>.env
```

**Verify** the registration. There is no `/v1/nodes` HTTP endpoint; the node
roster is exposed by the `tip_node_registry_info` metric (needs the metrics
token) , check it on two nodes:

```bash
TOK=<production TIP_METRICS_TOKEN>
curl -s -H "Authorization: Bearer $TOK" https://node.theailab.org/metrics  | grep tip_node_registry_info
curl -s -H "Authorization: Bearer $TOK" https://node2.theailab.org/metrics | grep tip_node_registry_info
```

The new node must appear with the partner's name and `status="active"` on both.
Nothing on the partner's machine needs to be live yet , this step involves only
our nodes.

## 5. Build and deliver the credentials bundle

### 5.1 The bundle contents , assembled automatically

Point the bundler (5.3) at `generated/<partner>/` and it stages the deliverable
itself from whatever the registrations produced:

```
<Partner>/                                     inside the zip
├── node.env                                   <- generated/<partner>/node/<slug>.env
├── NODE-KEY__tip-node-<id>.tip.json           <- generated/<partner>/node/
├── ORG-IDENTITY__id-<REGION>-<id>.tip.json    <- generated/<partner>/org/
└── README.md                                  <- the partner-root README
```

No genesis ships in the bundle: the repo the partner clones already carries the
mainnet genesis. Their verification (and ours) is the hash, not a file copy:

```bash
python3 -c "import json;print(json.load(open('genesis-data/genesis.json'))['genesis_hash'][:16])"
# must print the production genesis prefix , and they must never run npm run seed
```

Anything absent is reported with a WARNING and skipped, so an org-only or
node-only delivery also works; a directory with no credentials at all refuses to
build. The `NODE-KEY__` / `ORG-IDENTITY__` prefixes exist so the partner cannot
confuse the two: the node key lives on the node host; the org identity stays
**off** the node host entirely.

### 5.2 Hand-fill the secrets in `node.env`

The generator leaves these empty on purpose , edit
`generated/<partner>/node/<slug>.env` **before** building the zip (the bundler
warns on empty values but does not fail). Fill in:

- `TIP_CLASSIFIER_KEY` , the live production classifier key
- `TIP_METRICS_TOKEN` , the production metrics token (a 64-char random value; a
  token starting `certtest` is a test-network token and must never appear here)
- `TIP_BOOTSTRAP_PEERS` , a current multiaddr from a non-seed production node
  (`curl -s https://node2.theailab.org/health` → `data.p2p.bootstrap_addr`)

Confirm `TIP_API_ENDPOINT` and `TIP_PUBLIC_URL` carry their domain,
`DB_PASSWORD` and `TIP_CORS_ORIGINS` are `CHANGE_ME` placeholders, and nothing
else carries a live value.

### 5.3 Build the encrypted zip

```bash
scripts/make-secure-bundle.sh generated/<partner> <OrgName>
```

One AES-256 zip containing all five files, a fresh 20-character password per
run, printed once and appended to a `ZIP-PASSWORDS.md` build log. Both land
next to the partner directory: every zip collects in a single **`deliveries/`**
folder there, with the password log beside it , one place to look, outside any
repo checkout, and `deliveries/` is gitignored as a backstop.

### 5.4 Deliver

- **The zip goes by email. The password goes by phone or WhatsApp. Never both
  in the same channel** , if the password rides with the archive, the
  encryption bought nothing.
- Attach **one partner's zip only**. Bundles are named per partner and sit in
  one output directory; check the attachment name against the To: field before
  sending.
- The partner needs an AES-capable extractor (7-Zip on Windows, Keka or The
  Unarchiver on macOS); the built-in extractors on both platforms fail on AES
  zips. The email template says this.

Email wording: `partner-onboarding-emails.html`, mainnet card.

## 6. Partner boots, we verify

Partner side: `DEPLOYMENT.md`, section *Production Federation Deploy (0 to
live)*. The two classic stumbles are in the email template: the container runs
as uid 1001, and `logs/` must be chown'd before first boot.

Our side , four checks, in this order. Each proves something different:

1. **Connected.** `curl -s https://<their-domain>/ready` shows `ready:true`,
   `halted:false`, `join_state:"ready"`. `syncing` / `catching_up` means still
   downloading state , normal for a while on first boot.
2. **Right network.** `/health` shows `peers.connected >= 1`. The p2p handshake
   authorises peers against the genesis-scoped on-chain registry, so a node on
   the wrong genesis cannot peer at all: non-zero peers **is** proof of the
   correct chain.
3. **All data correct , the definitive check.** Their
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

Then confirm their `api_endpoint` appears on-chain (their first boot announces
it), and have them register one test content and check it reaches
`prescan: completed`.

## 7. After onboarding

- [ ] Add `<their-domain>` to external monitoring and the status page
- [ ] Add their node to the production Prometheus scrape targets
- [ ] Allow-list their IP where applicable
- [ ] Record the ops contact in the operations inventory, not only in the email
      thread
- [ ] Walk the partner through key custody one more time: offline backup of both
      key files, org identity never on the node host

**Key loss or leak:** the classifier key and metrics token are shared,
fleet-rotatable credentials , a leak means rotating every node at once, so
report immediately. The **node key cannot be rotated at all** (issue #257): a
leaked or lost node key means deregistering and re-registering the node under a
new identity. The org identity key is rotatable via `KEY_ROTATED`.

## Troubleshooting

| symptom | cause |
|---|---|
| `Only the founding VP can approve` | wrong or missing `--vp-file` , you signed with a non-mainnet VP |
| `409 Identity already registered` | dedup hit: this company (same number + date + country) is already on-chain. If that is a surprise, stop and investigate before anything else |
| partner node: 0 peers and stuck at `join_state: syncing` despite open ports | almost always the wrong `genesis.json`. There is no clean "wrong network" error; this is what it looks like. Check the genesis before debugging firewalls |
| endpoint announce failed at boot | their DNS does not resolve, or 4000 is not reachable from the internet. Fix, then `POST /v1/node/endpoint/announce` on their node re-announces without a restart |
| partner cannot open the zip | OS built-in extractor; they need 7-Zip / Keka / The Unarchiver |

---

## Appendix A , worked example: full local rehearsal

Rehearse the entire flow on the local cluster before any mainnet run. Fictional
company throughout; local cluster must be up (`curl -s localhost:4000/ready`).
The local VP key in `genesis-data/backups` is picked up automatically , no
`--vp-file` locally, which is exactly why mainnet **must** pass it.

```bash
# R1 , dry-run: validates the identifier, builds the proof, registers nothing
node scripts/register-org.js \
  --name "THE PRESCIENT PACHYDERM LTD" \
  --reg-number 16846775 \
  --incorporated 2025-11-11 \
  --region GB \
  --org-type private-limited-company \
  --dry-run

# R2 , register the org locally (note the printed tip://id/GB-... for R3/R4)
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
# R3 , verify from two local nodes (both must agree)
ORG_ID='tip://id/GB-xxxxxxxxxxxxxxxx'
ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$ORG_ID")
curl -s "http://localhost:4000/v1/identity/$ENC" | python3 -m json.tool | grep -E '"creator_name"|"status"|"org_type"'
curl -s "http://localhost:4100/v1/identity/$ENC" | python3 -m json.tool | grep -E '"creator_name"|"status"|"org_type"'
```

```bash
# R4 , register the node, org cosigning (use the exact key path R2 printed)
node scripts/register-node.js \
  --name "Pachyderm Node" \
  --node-url http://localhost:4000 \
  --operated-by "$ORG_ID" \
  --partner pachyderm \
  --operator-key-file generated/pachyderm/org/<org-tip-id>.tip.json \
  --production \
  --api-endpoint "https://tipnode.pachyderm.example" \
  --public-url "https://tipnode.pachyderm.example" \
  --public-ip 203.0.113.10

# R5 , verify the roster (there is no /v1/nodes endpoint; use the metric)
TOK=$(grep '^TIP_METRICS_TOKEN=' .env | cut -d= -f2-)
curl -s -H "Authorization: Bearer $TOK" http://localhost:4000/metrics | grep tip_node_registry_info
```

```bash
# R6 , rehearse the bundle: one command, staged straight from the partner dir
scripts/make-secure-bundle.sh generated/pachyderm Pachyderm
ls -la generated/deliveries/             # the zip; password was printed + logged
rm -rf generated/pachyderm generated/deliveries generated/ZIP-PASSWORDS.md   # rehearsal cleanup
```

What changes on mainnet, and nothing else: `--node-url https://node.theailab.org`,
`--vp-file <mainnet VP key>`, verification against `node`/`node2.theailab.org`,
and the env is hand-filled with production secrets before bundling (section 5.2).
