#!/usr/bin/env node
/**
 * @file scripts/register-org.js
 * @description Register an ORGANIZATION identity on a TIP network.
 *
 * Generates a fresh ML-DSA-65 keypair, builds the ZK dedup proof from the
 * organization's public registry identifiers, has the founding VP attest the
 * canonical payload, calls the identity endpoint, and writes the credential
 * file the organization needs to sign content.
 *
 * The dedup hash is Poseidon(gov_id, dob, country). For a company those map to
 * its state-issued registration number, its incorporation date and its country
 * of incorporation, which is the same role a government ID plays for a person:
 * unique, permanent, externally verifiable. Get them from the public register
 * (UK: Companies House) and use the number EXACTLY as printed, since a dropped
 * leading zero produces a different identity that can never be reconciled.
 *
 * Usage:
 *   node --experimental-vm-modules scripts/register-org.js \
 *     --name "THE PRESCIENT PACHYDERM LTD" \
 *     --reg-number 16846775 \
 *     --incorporated 2025-11-11 \
 *     --region GB \
 *     --node-url https://node.theailab.org \
 *     --vp-file my-notes/mainnet-prod/tip-vp-US-0e7db4040667073a.tip.json
 *
 * Options:
 *   --name "Legal Name"       Registered legal name (required; orgs must attest one)
 *   --reg-number 16846775     Company registration number (required)
 *   --incorporated YYYY-MM-DD Date of incorporation (required)
 *   --region GB               ISO-3166-1 alpha-2 country of incorporation (default GB)
 *   --node-url URL            API to register against (default http://localhost:4000)
 *   --vp-file PATH            Founding VP .tip.json. Defaults to the VP found in
 *                             genesis-data/backups, which is the LOCAL/TEST VP.
 *                             Pass the mainnet VP explicitly for mainnet.
 *   --partner SLUG            Partner folder name; org and node runs sharing it land together
 *   --out-dir PATH            Override output dir (default generated/<partner|slug-short-id>/org/)
 *   --dry-run                 Build and print everything, but do not POST
 *
 * Output:
 *   generated/<partner>/org/
 *     └── <tip-id>.tip.json   Keypair + org metadata (mode 0600)
 *
 * The private key is written locally and never transmitted: registration sends
 * only the public key. Deliver the file to the organization over a secure
 * channel and have them store it at mode 0600.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

try { require("dotenv").config(); } catch { /* dotenv optional */ }

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");

const { nowIso, nowMs } = require("../shared/time");
const {
  initCrypto,
  generateMLDSAKeypair,
  generateTIPID,
} = require("../shared/crypto");
const { generateDedupProof } = require("../shared/zk");
const { resolveIdScheme } = require("../shared/org-id-schemes");
const registerIdentitySchema = require("../node/src/schemas/register-identity");
const { loadVpBackup } = require("./genesis-backups");

// ─── Terminal colors ──────────────────────────────────────────────────────────
const T = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", yellow: "\x1b[33m",
};
const ok = (m) => console.log(`${T.green}  ✓${T.reset} ${m}`);
const fail = (m) => console.log(`${T.red}  ✗${T.reset} ${m}`);
const info = (m) => console.log(`${T.cyan}  ℹ${T.reset} ${m}`);
const warn = (m) => console.log(`${T.yellow}  !${T.reset} ${m}`);
const label = (k, v) => console.log(`    ${T.dim}${k.padEnd(22)}${T.reset}${v}`);

// ─── CLI args ─────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
function getArg(name, fallback) {
  const eqHit = args.find(a => a.startsWith(`${name}=`));
  if (eqHit) return eqHit.slice(name.length + 1);
  const idx = args.indexOf(name);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
}

const orgName = getArg("--name", null);
const regNumber = getArg("--reg-number", null);
const incorporated = getArg("--incorporated", null);
const region = (getArg("--region", "GB") || "GB").toUpperCase();
// Legal form as the jurisdiction names it (private-limited-company, llc, gmbh).
// Deliberately not a fixed enum: forms differ per country and new ones appear.
const orgType = getArg("--org-type", null);
const nodeUrl = getArg("--node-url", "http://localhost:4000");
const vpFile = getArg("--vp-file", null);
const outDirOverride = getArg("--out-dir", null);
// Group outputs by PARTNER, not by artifact type: org and node keys for the
// same partner belong together (they ship in one bundle). --partner names the
// folder; without it the org name slug is used.
const partnerSlug = getArg("--partner", null);
const dryRun = args.includes("--dry-run");

function slugify(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "org";
}

// One README at the partner root explaining every credential type it may hold.
// Overwritten on each run so it always reflects the current layout.
function writePartnerReadme(partnerRoot) {
  const text = `# Partner credentials , handling rules

Everything for one partner lives under this directory.

## org/  (organization identity)
The .tip.json here IS the organization on the network: it signs content as them.
It is NOT needed to run a node. Keep it OFF the node host, with company signing
material. Mode 0600, never committed, never emailed in the clear.

## node/  (node identity + env)
The .tip.json here runs the node: it lives on the node host, read at boot
(mode 0600, owned by the container user). The .env is the node configuration ,
secrets (classifier key, metrics token) are filled by hand at bundle time, never
generated here.

## vp/  (verification provider , rarely present)
A VP key approves registrations. If one exists here, it is the most sensitive
file in this tree; it never leaves the registration machine.

Delivery: docs/REGISTRATION_AND_KEY_DISTRIBUTION.md section 5 , one AES-256 zip
via scripts/make-secure-bundle.sh, password over a separate channel.
`;
  fs.writeFileSync(path.join(partnerRoot, "README.md"), text);
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────
function post(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;
    const payload = JSON.stringify(body);
    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
    }, (res) => {
      let data = "";
      res.on("data", c => { data += c; });
      res.on("end", () => {
        let parsedBody = null;
        try { parsedBody = JSON.parse(data); } catch { /* non-JSON error body */ }
        if (res.statusCode >= 200 && res.statusCode < 300) return resolve(parsedBody);
        const err = new Error(`HTTP ${res.statusCode}`);
        err.data = parsedBody || data;
        reject(err);
      });
    });
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

async function main() {
  console.log(`\n${T.bold}Register organization identity${T.reset}\n`);

  // 1. Validate inputs up front: the dedup inputs are permanent, so a typo
  //    here mints an identity that can never be reconciled with the real one.
  const missing = [];
  if (!orgName) missing.push("--name");
  if (!regNumber) missing.push("--reg-number");
  if (!incorporated) missing.push("--incorporated");
  if (missing.length) {
    fail(`missing required: ${missing.join(", ")}`);
    console.log("\n  see the header of this file for usage\n");
    process.exit(1);
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(incorporated)) {
    fail(`--incorporated must be YYYY-MM-DD, got: ${incorporated}`);
    process.exit(1);
  }
  if (!/^[A-Z]{2}$/.test(region)) {
    fail(`--region must be a 2-letter ISO country code, got: ${region}`);
    process.exit(1);
  }

  // Jurisdiction gate. Runs before any keypair or proof work so a wrong
  // identifier costs nothing; past this point the inputs are permanent.
  let scheme;
  try {
    scheme = resolveIdScheme(region, regNumber);
  } catch (err) {
    fail(err.message);
    process.exit(1);
  }
  ok(`${region} identifier: ${scheme.name} (${scheme.normalized})`);

  await initCrypto();

  // 2. VP key. Defaults to the backups dir, which on a dev machine is the
  //    TEST VP: registering against mainnet with it fails the founding-VP
  //    check, so mainnet runs must pass --vp-file explicitly.
  let vp;
  if (vpFile) {
    vp = JSON.parse(fs.readFileSync(path.resolve(vpFile), "utf8"));
    if (!vp.private_key || !vp.public_key) throw new Error(`${vpFile} is not a VP keypair file`);
  } else {
    vp = loadVpBackup();
    warn("no --vp-file given, using the VP in genesis-data/backups (local/test VP)");
  }
  ok(`Approving VP: ${vp.vp_id}`);

  // 3. Keypair + derived TIP-ID.
  const keypair = generateMLDSAKeypair();
  const tipId = generateTIPID(region, keypair.publicKey);
  ok(`Keypair generated: ${tipId}`);

  // 4. Dedup proof over the public registry identifiers.
  info("Generating ZK dedup proof (Groth16)...");
  const { dedup_hash: dedupHash, proof: zkProof } =
    await generateDedupProof(scheme.normalized, incorporated, region);
  ok(`Dedup hash: ${String(dedupHash).slice(0, 24)}...`);

  // 5. Canonical payload, attested by the VP.
  const idFields = {
    region,
    public_key: keypair.publicKey,
    dedup_hash: dedupHash,
    zk_proof: zkProof,
    verification_tier: "T1",
    vp_id: vp.vp_id,
    tip_id_type: "organization",
    creator_name: orgName,
    ...(orgType ? { org_type: orgType } : {}),
  };
  const canonicalPayload = registerIdentitySchema.buildSigningPayload(idFields);
  const vpSignature = registerIdentitySchema.sign(canonicalPayload, vp.private_key);
  ok("VP attestation signed");

  console.log("");
  label("Organization", orgName);
  label("TIP-ID", tipId);
  label("Region", region);
  label("Reg number", `${scheme.normalized} (${scheme.name})`);
  label("Incorporated", incorporated);
  label("Target", nodeUrl);
  console.log("");

  if (dryRun) {
    warn("--dry-run: nothing was registered and no files were written");
    return;
  }

  // 6. Register.
  info("Registering...");
  let result;
  try {
    const response = await post(`${nodeUrl}/v1/identity/register`, {
      ...idFields,
      vp_signature: vpSignature,
    });
    result = response.data || response;
    ok(`Registered: ${result.tip_id}`);
    label("Confirmation", result.confirmation || "registered");
  } catch (err) {
    fail(`Registration failed: ${err.message}`);
    if (err.data) console.error("  ", JSON.stringify(err.data, null, 2));
    process.exit(1);
  }

  // 7. Credential file for delivery.
  const shortId = String(result.tip_id || tipId)
    .replace(/^tip:\/\/id\//, "").replace(/[^a-zA-Z0-9]/g, "").slice(0, 12) || "unknown";
  const partnerRoot = path.resolve(`./generated/${partnerSlug || `${slugify(orgName)}-${shortId}`}`);
  const outDir = path.resolve(outDirOverride || path.join(partnerRoot, "org"));
  fs.mkdirSync(outDir, { recursive: true });
  if (!outDirOverride) writePartnerReadme(partnerRoot);

  const fileName = String(result.tip_id || tipId)
    .replace(/^tip:\/\//, "").replace(/[^a-zA-Z0-9-]/g, "-").replace(/-+/g, "-") + ".tip.json";
  const tipJson = JSON.stringify({
    v: 1,
    type: "identity",
    tip_id_type: "organization",
    name: orgName,
    tip_id: result.tip_id || tipId,
    region,
    public_key: keypair.publicKey,
    private_key: keypair.privateKey,
    // Recorded so the dedup inputs stay auditable: they cannot be recovered
    // from the hash, and re-deriving them wrongly would mint a second identity.
    // The canonical value is what was hashed; the as-provided form is kept so a
    // later audit can read it back against the certificate it was copied from.
    registration_number: scheme.normalized,
    registration_number_as_provided: regNumber,
    registration_scheme: scheme.name,
    incorporated,
    dedup_hash: dedupHash,
    approving_vp_id: vp.vp_id,
    registered_at: result.registered_at || nowMs(),
    registered_on: nodeUrl,
    generated_at: nowIso(),
  }, null, 2);
  fs.writeFileSync(path.join(outDir, fileName), tipJson, { mode: 0o600 });

  console.log("");
  ok(`Credential: ${path.join(outDir, fileName)}`);
  warn("Contains the PRIVATE key. Deliver over a secure channel, never chat or email.");
  warn("Recipient should store it at mode 0600; anyone holding it can sign as this organization.");
  console.log("");
}

// snarkjs leaves worker handles open after proving, so the event loop never
// drains on its own: exit explicitly or the script hangs after finishing.
main().then(() => process.exit(0)).catch((err) => {
  fail(err.message);
  if (err.stack) console.error(err.stack.split("\n").slice(1, 4).join("\n"));
  process.exit(1);
});
