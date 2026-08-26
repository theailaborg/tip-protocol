# Registering an organization

How to put an organization identity on chain with `scripts/register-org.js`.

An organization is a normal TIP identity with `tip_id_type=organization`. It differs
from a person in two ways: a display name is mandatory, and the uniqueness proof is
built from the company's registry details rather than a person's government ID.

## 1. What to ask the organization

Four fields, all on the certificate of incorporation. Asking for a copy of that
certificate is usually the fastest route.

| field | maps to | notes |
|---|---|---|
| Full legal name, exactly as registered | `creator_name` | mandatory for organizations |
| Country of incorporation | `country` | ISO-3166-1 alpha-2 |
| Registration number | `gov_id` | country-specific, see the table below |
| Date of incorporation | `dob` | `YYYY-MM-DD` |

Worth telling them, since it pre-empts the obvious objection:

> These details are used only to derive a privacy-preserving uniqueness proof. The raw
> values are never published: only a hash goes on chain, so nobody can read your
> registration details from the ledger.

### Node details , when the organization will also run a node

Ask in the same message, so registration is not blocked on a second round-trip:

| ask | why |
|---|---|
| static public IP of the node host | the node's advertised address in its env; how peers dial it |
| domain the node will serve on | published **on-chain** as their API endpoint; must be the address they intend to keep |
| confirmation TCP 4000 and 4001 are open to the internet | 4000 API, 4001 p2p; without 4001 they never fully join |
| ops contact name + email | who we call when their node misbehaves |

The mainnet node needs its **own host**: a partner already running a testnet node
cannot reuse that box (same ports, different genesis). Ask for the number and the
identifier type together (a CIN reply to an LLPIN question is the classic mix-up).

## 2. Which registration number, per country

The dedup hash is `Poseidon(reg_no, incorporation_date, country)`. The circuit cannot
tell a company number from a tax number, so **"one company = one identity" only holds
if every registration for a country derives `reg_no` the same way**. One Indian company
legitimately holds a CIN, a PAN and several GSTINs; each would mint a separate,
permanent, un-reconcilable identity.

So each jurisdiction has exactly one accepted identifier, enforced by `ORG_ID_SCHEMES`
in the script.

| country | ask for | format |
|---|---|---|
| **GB** | company number (issued by Companies House) | 8 chars. `16846775`, `SC123456`, `OC123456` (LLP). Keep leading zeros |
| **IN** company | CIN | 21 chars, e.g. `U74999MH2020PTC123456` |
| **IN** LLP | LLPIN | 7 chars. LLPs are **never** issued a CIN |
| **US** | federal **EIN** | 9 digits. NOT a state entity number |
| **AU** | ACN | 9 digits |
| **FR** | SIREN | 9 digits |
| **JP** | Corporate Number | 13 digits |
| **DE** | court-qualified HRB/HRA | `DE-HRB-12345-MUC` |

Do **not** accept, even if offered: India PAN (a tax ID, also held by individuals) or
GSTIN (state-scoped, one company holds several); UK VAT number.

### Why the country in the hash is not enough on its own
`country` separates identical numbers **across** countries: `16846775` in GB, US and IN
produce three different hashes. It does nothing **within** a country, which is what the
table above handles.

### Countries with no single national registry
- **US** has no federal company registry. State numbers repeat across states while
  `country` stays `US`, so the federal EIN is used instead. Where an entity genuinely
  has no EIN, namespace the state in: `US-DE-1234567`.
- **Germany** issues HRB/HRA per local court, so the court must be part of the value.
- **Canada** has federal and provincial registries; confirm which one issued the number
  before adding a row.

A country absent from the table stops the run rather than guessing. Adding one is a
deliberate act: confirm the country has a single national registry, then add the row.

### Continuity events: conversions and re-registrations

The dedup hash guarantees *the same government registration* never enters twice. It
cannot recognise the same **business** returning under a new registration, because
some jurisdictions make legal-form changes a new entity with a new identifier:

| country | behaviour on form change | exposed? |
|---|---|---|
| **IN** | LLP → company conversion issues a **new CIN and a new incorporation date** | **yes , worst case** |
| **DE** | moving the company seat changes the court, so a **new HRB** (the court is part of our value) | **yes, same class** |
| GB | company number persists through LTD→PLC and renames | robust |
| FR / JP / AU | SIREN / Corporate Number / ACN persist through form changes | robust |
| US | EIN survives most conversions; a few (e.g. sole-prop → corp) mint a new one | mostly robust |

The risk is a **reputation reset**: an organization with a damaged score converts its
legal form and registers again with a clean slate. The hash cannot stop it, so the
approval step does:

1. **Always ask, in writing:** *"Has this business ever operated under a prior
   registration number (as an LLP, before a conversion, or under a previous
   incorporation)?"* A false answer to the approving VP is misrepresentation.
2. **Read the certificate.** In India a converted company's incorporation certificate
   states the conversion and cites the former LLPIN, and the MCA record shows it. An
   incorporation date far newer than the business's visible history is the tell.
3. **Register a successor only alongside retirement of its predecessor.** If the old
   form holds a TIP identity, it is revoked (`REVOKE_VOLUNTARY`) as part of the new
   registration, so the chain records succession, not two live identities.

## 3. Register

### Flag reference

| flag | required | accepts | example |
|---|---|---|---|
| `--name` | yes | the full legal name, exactly as registered, quoted | `--name "AZLOGICS PRIVATE LIMITED"` |
| `--reg-number` | yes | the country's accepted identifier from the table in §2, exact format, leading zeros kept | `--reg-number U72900MH2021PTC362851` |
| `--incorporated` | yes | date of incorporation, `YYYY-MM-DD` only | `--incorporated 2021-06-28` |
| `--region` | yes in practice | ISO-3166-1 alpha-2 country of incorporation; must be in the §2 scheme table or the run stops. Default `GB` , always pass it explicitly | `--region IN` |
| `--org-type` | no | the legal form as the jurisdiction names it, freeform by design (forms differ per country), but must be 2-64 chars of lowercase letters, digits and hyphens. Common values: `private-limited-company`, `public-limited-company`, `llp`, `llc`, `gmbh`, `nonprofit` | `--org-type private-limited-company` |
| `--node-url` | for mainnet | the node to register through. Default `http://localhost:4000` (local rehearsal) | `--node-url https://node.theailab.org` |
| `--vp-file` | **for mainnet** | path to the mainnet founding VP `.tip.json`. When omitted the script picks up whatever VP sits in `genesis-data/backups`, which on a dev machine is the test VP , mainnet rejects it | `--vp-file <VP_KEY_FILE>` |
| `--partner` | recommended | partner folder name under `generated/`; use the same value for the node registration so both land together | `--partner azlogics` |
| `--out-dir` | no | full override of the output dir. Default `generated/<partner|slug-short-id>/org/` | `--out-dir /secure/azlogics` |
| `--dry-run` | no | boolean, no value. Validates the identifier, builds the real proof, prints everything, registers nothing , always run this first | `--dry-run` |

`--org-type` note: use lowercase-hyphen spelling of the form on the certificate
(`Private Limited` → `private-limited-company`). Anything outside
`a-z 0-9 -` or longer than 64 chars is rejected by the node with
`org_type_invalid`.

Rehearse on the local cluster first. Nothing about the flow differs except the target
and the VP key, so a local run catches every input mistake for free.

```bash
node scripts/register-org.js \
  --name "THE PRESCIENT PACHYDERM LTD" \
  --reg-number 16846775 \
  --incorporated 2025-11-11 \
  --region GB \
  --org-type private-limited-company \
  --node-url http://localhost:4000
```

Then mainnet. **`--vp-file` is required**: the default picks up the VP in
`genesis-data/backups`, which on a dev machine is the test VP, and mainnet will reject
it with `Only the founding VP can approve nodes`.

```bash
node scripts/register-org.js \
  --name "THE PRESCIENT PACHYDERM LTD" \
  --reg-number 16846775 \
  --incorporated 2025-11-11 \
  --region GB \
  --org-type private-limited-company \
  --node-url https://node.theailab.org \
  --vp-file path-to-vp-keys
```

`--dry-run` builds and prints everything without registering, which is the safe way to
confirm the identifier is accepted and the derived TIP-ID looks right.

## 4. Verify it committed

Registration returns `confirmation: "proposed"`; the identity lands a few seconds later
when the transaction commits.

```bash
curl -s "$NODE/v1/identity/$(python3 -c "import urllib.parse;print(urllib.parse.quote('tip://id/GB-...',safe=''))")"
```

Check `creator_name`, `region`, and `status: active`. On a multi-node network, check more
than one node: they must agree.

## 5. Deliver the credential

The script writes `generated/<partner>/org/<tip-id>.tip.json` at mode `0600`
(pass `--partner <slug>` so the later node registration lands in the same folder),
containing both keys plus the registry inputs.

Whoever holds that file can sign as the organization, so it is treated like an SSH
host key: stored at mode `0600`, never committed. Delivery is part of the partner
credentials bundle , an AES-256 zip with the password sent over a separate channel;
the full procedure is `REGISTRATION_AND_KEY_DISTRIBUTION.md` section 6.

The private key is generated locally and never transmitted: registration sends only the
public key. The planned VP-side page, where an organization generates its own keypair in
the browser and sends us only the public key, removes the delivery step entirely.

## Gotchas

- **Leading zeros are part of the number.** `01234567` and `1234567` are different
  identities. Ask for the value "exactly as printed", and beware spreadsheets stripping
  zeros.
- **Ask India entities whether they are a company or an LLP** before asking for a number.
- **The inputs are permanent.** A one-character error yields a different hash, the proof
  still verifies, and the chain accepts it. The mistake is undetectable (the hash is
  one-way) and uncorrectable (the entry is committed). It surfaces only when the real
  company later registers and fails to collide. Confirm the values with the organization
  rather than relying on a public-register lookup alone.
- **Duplicates are refused with 409** (`Identity already registered`) once a hash is in
  `dedup_registry`.
- The script exits explicitly after proving: snarkjs leaves worker handles open, so
  without that it would hang after finishing successfully.
