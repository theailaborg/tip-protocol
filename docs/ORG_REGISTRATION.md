# Registering an organization

Reference for registering an organization: what to ask for and which registration
number to use per country. The commands to run (`scripts/register-org.js`, dry run,
verify, delivery) are in [`REGISTRATION_AND_KEY_DISTRIBUTION.md`](./REGISTRATION_AND_KEY_DISTRIBUTION.md)
section 4.

An organization is a normal TIP identity with `tip_id_type=organization`. It differs
from a person in two ways: a display name is mandatory, and the uniqueness proof is
built from the company's registry details rather than a person's government ID.

## 1. What to ask the organization

### Ready-to-send requests

Two emails, both also in `docs/partner-onboarding-emails.html` (email 0 and
email 0b, where a country selector fills email 0's item 2 and the partner name
fills itself):

- **Email 0, organization registration:** every organization. Send it alone
  when the organization will only publish content as itself.
- **Email 0b, running a node:** only when the organization will also run a
  node. Send it together with email 0, so neither waits on a second round trip.

Email 0's item 2 depends on the country: take the identifier from the table in
section 2 and use the matching wording, e.g.

- India: `CIN (21-char) or LLPIN (7-char), and which one it is`
- UK: `Companies House company number (8 chars, exactly as printed, keep leading zeros)`
- US: `federal EIN (9 digits, not a state entity number)`

**Email 0: organization registration**

> Hi [partner] team, we're ready to register [ORGANIZATION NAME] on TIP mainnet.
> Since mainnet records are permanent and cannot be corrected, please confirm the
> following from your official documents (not from memory):
>
> 1. Full legal name, exactly as registered
> 2. [registration number wording for their country, from the section 2 table]
> 3. Legal form, as printed on the certificate (Private Limited, LLP, LLC, Ltd,
>    GmbH, ...)
> 4. Date of incorporation
> 5. Country of registration
> 6. Whether the business has ever operated under a previous registration
>    number (before a conversion or re-incorporation); if so, that number and
>    the date of the change
> 7. A contact for your organization's account: name, email, and a phone or
>    Signal number (your organization's key file comes by email, its password
>    by phone or Signal)
>
> Once these arrive we'll register your organization and send its key file.

Item 3 feeds `--org-type`, item 6 is the continuity question section 2 requires
in writing, and item 7 is what makes the password deliverable over a second
channel.

**Email 0b: running a node**

> Hi [partner] team, to register the node [ORGANIZATION NAME] will run on TIP
> mainnet, we also need the following about the machine it will run on:
>
> 1. Where the node will run: AWS EC2 (and which region), another cloud
>    provider, or your own hardware. This decides how media storage is set up
> 2. The host: a machine dedicated to this node (not a test network box), with
>    at least 2 CPU cores, 4 GB RAM and 20 GB free disk; 4 dedicated cores,
>    8 GB and 50 GB recommended
> 3. The host's static public IP. If it sits behind a router or NAT without one,
>    tell us: it can still run, with a different setup
> 4. The domain the node will serve on (for example node.your-domain.com),
>    confirmation that you control its DNS, and that you can serve HTTPS on it in
>    front of port 4000 (a reverse proxy or a tunnel). It is published on chain,
>    so it must be the address you intend to keep
> 5. Confirmation that inbound TCP 4000 and 4001 are open to the internet (or
>    that they cannot be, see item 3)
> 6. The host's internet link: 25 Mbit/s download and upload sustained minimum,
>    50 recommended, ideally a dedicated line rather than a shared office
>    connection
> 7. Media storage: on AWS EC2, confirm you have an AWS account where you can
>    create a bucket with our setup steps; anywhere else, we provide the storage
>    access and send it with your credentials
> 8. An ops contact for node issues: name, email, and a phone or Signal number,
>    reachable if the node misbehaves
>
> Once these arrive we'll register the node and send the credentials bundle.

What the answers decide: item 1 picks the S3 path (`PROD_S3_SETUP.md`: path A
`ec2` on EC2, otherwise path A `keys` or path C); items 3 and 5 decide between a
normal node and the outbound-only setup (`DEPLOYMENT.md`, "No static IP or
inbound 4001?"); item 4 becomes `--api-endpoint` / `--public-url`; item 8 goes
into the operations inventory. The rest of this document explains what each
answer must look like before you act on it.

### The fields, and where they go

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

### Node details: when the organization will also run a node

Send email 0b alongside email 0 (above). The mainnet node needs its **own
host**: a partner already running a test network node cannot reuse that box
(same ports, different genesis).

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
| **IN** | LLP → company conversion issues a **new CIN and a new incorporation date** | **yes, worst case** |
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

## 3. Register, verify, deliver

The commands, the dry-run and verify checklists, and the key delivery are in
[`REGISTRATION_AND_KEY_DISTRIBUTION.md`](./REGISTRATION_AND_KEY_DISTRIBUTION.md)
section 4 (organization) and section 6 (bundle). This document stays the
reference for what to ask and which number to use; the gotchas below apply to
every run.

## Gotchas

- **Leading zeros are part of the number.** `01234567` and `1234567` are different
  identities. Ask for the value "exactly as printed", and beware spreadsheets stripping
  zeros.
- **Separators are ignored, characters are not.** Hyphens, spaces and dots are stripped
  before the number is hashed, so a US EIN pasted the way the IRS prints it
  (`32-0727201`) registers the same company as `320727201`. Paste the value as printed
  and let the script normalise it. This is why a dropped leading zero still matters: the
  script removes punctuation, never digits or letters.
- **Nothing longer than 30 characters.** After separators are stripped the identifier
  must fit in 30 characters, which is what the hash encodes. Longer values are refused
  rather than truncated: two companies agreeing on the first 30 characters would
  otherwise merge into a single permanent identity. Every listed scheme fits (an Indian
  CIN is 21, an EIN 9); only the US state fallback can run over.
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
