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

3. **Verify from two different nodes** , they must agree:

   ```bash
   for h in node node2; do
     curl -s "https://$h.theailab.org/v1/identity/$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" 'tip://id/<REGION>-<id>')" \
       | python3 -m json.tool | grep -E '"creator_name"|"region"|"status"|"tip_id_type"'
   done
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
  --node-url https://node.theailab.org \
  --operated-by "tip://id/<REGION>-<org-id>" \
  --operator-key-file generated_orgs/<slug>-<short-id>/<org-tip-id>.tip.json \
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

Output lands in `generated_nodes/<slug>-<short-id>/`:

- `<node-id>.tip.json` , the node keypair (mode 0600)
- `<slug>.env` , the drop-in env file
- `data/` , empty per-node data dir (not shipped)

**Verify** the node row from two nodes: it must appear with `status: active` and
the correct `operated_by`. Nothing else needs to be live yet , the partner's
machine is not involved in this step.

## 5. Build and deliver the credentials bundle

### 5.1 Assemble the partner directory

Create a directory (outside the repo checkout) containing exactly five files:

```
<partner>/
├── node.env                                   <- the generated <slug>.env, renamed
├── NODE-KEY__tip-node-<id>.tip.json           <- from generated_nodes/, renamed with prefix
├── ORG-IDENTITY__id-<REGION>-<id>.tip.json    <- from generated_orgs/, renamed with prefix
├── genesis.json                               <- the MAINNET genesis
└── README.md                                  <- partner setup steps
```

The `NODE-KEY__` / `ORG-IDENTITY__` prefixes exist so the partner cannot confuse
the two: the node key lives on the node host; the org identity must stay **off**
the node host entirely.

### 5.2 Hand-fill the secrets in `node.env`

The generator leaves these empty on purpose. Fill in:

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
scripts/make-secure-bundle.sh <path-to-partner-dir> <OrgName>
```

One AES-256 zip containing all five files, a fresh 20-character password per
run, printed once and appended to a `ZIP-PASSWORDS.md` build log next to the
partner directory. The zip and the log are created outside any repo checkout.

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
