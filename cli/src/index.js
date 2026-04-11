#!/usr/bin/env node
/**
 * @file @tip-protocol/cli/src/index.js
 * @description TIP Protocol CLI
 *
 * Usage:
 *   tip --help
 *   tip config set-node http://localhost:4000
 *   tip identity register --region US --vp-id <vp>
 *   tip identity resolve tip://id/US-a3f8c91b2d4e7021
 *   tip identity score tip://id/US-a3f8c91b2d4e7021
 *   tip content register --file ./article.txt --origin OH
 *   tip content resolve tip://c/OH-7f2a91bc3d5e-a3f8
 *   tip content verify tip://c/... --as tip://id/...
 *   tip trust score tip://id/...
 *   tip trust revocations
 *   tip vp register --name "My VP" --tier green
 *   tip node info
 *   tip node peers
 *   tip badge seal --score 892 --size 200 --out seal.svg
 *   tip badge mark --size 140 --out tip-mark.svg
 *   tip badge headers --tip-id ... --ctid ... --origin OH --score 892
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { program, Command } = require("commander");
const fs = require("fs");
const path = require("path");
const { TIPClient } = require("../../sdk/src/index");
const {
  generateMLDSAKeypair,
  mldsaSign,
  shake256,
  shake256Multi,
} = require("../../shared/crypto");
const { ORIGIN, ORIGIN_LABELS } = require("../../shared/constants");
const { getTier } = require("../../shared/protocol-constants");

// ── Simple config store (file-based) ─────────────────────────────────────────
const CONFIG_PATH = path.join(require("os").homedir(), ".tip-cli.json");

function loadCLIConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")); } catch { return {}; }
}

function saveCLIConfig(cfg) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}

function getClient() {
  const cfg = loadCLIConfig();
  const nodeUrl = cfg.nodeUrl || process.env.TIP_NODE_URL || "http://localhost:4000";
  return new TIPClient({ nodeUrl });
}

// ── Output helpers ────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", blue: "\x1b[34m", yellow: "\x1b[33m",
  red: "\x1b[31m", cyan: "\x1b[36m", gold: "\x1b[33m", grey: "\x1b[90m",
};

function ok(msg) { console.log(`${C.green}✓${C.reset} ${msg}`); }
function err(msg) { console.error(`${C.red}✗${C.reset} ${msg}`); }
function info(msg) { console.log(`${C.cyan}ℹ${C.reset} ${msg}`); }
function label(k, v) { console.log(`  ${C.dim}${k.padEnd(22)}${C.reset} ${v}`); }

function printScore(data) {
  const tier = getTier(data.score || 0);
  const tClr = data.score >= 800 ? C.green : data.score >= 600 ? C.blue : data.score >= 400 ? C.yellow : C.red;
  console.log(`\n${C.bold}Trust Score${C.reset}`);
  if (data.score !== undefined) label("Score", `${tClr}${C.bold}${data.score}${C.reset} / 1000`);
  label("Tier", `${tClr}${data.tier || tier.name}${C.reset}`);
  if (data.verified_since) label("Verified since", data.verified_since);
  if (data.content_count !== undefined) label("Content count", data.content_count);
  if (data.status) label("Status", data.status);
}

// ─────────────────────────────────────────────────────────────────────────────
// ROOT PROGRAM
// ─────────────────────────────────────────────────────────────────────────────

program
  .name("tip")
  .description(`${C.bold}TIP™ Protocol CLI${C.reset} — Trust Identity Protocol v2.0\n  The AI Lab Intelligence Unobscured, Inc. | theailab.org`)
  .version(require("../../package.json").version);

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────────────────────

const configCmd = program.command("config").description("Manage CLI configuration");

configCmd
  .command("set-node <url>")
  .description("Set the TIP node URL")
  .action(url => {
    const cfg = loadCLIConfig();
    cfg.nodeUrl = url;
    saveCLIConfig(cfg);
    ok(`Node URL set to: ${url}`);
  });

configCmd
  .command("set-identity <tipId>")
  .description("Set your default TIP-ID for commands")
  .action(tipId => {
    const cfg = loadCLIConfig();
    cfg.defaultTipId = tipId;
    saveCLIConfig(cfg);
    ok(`Default TIP-ID set to: ${tipId}`);
  });

configCmd
  .command("set-key <hexKey>")
  .description("Store your ML-DSA-65 private key (stored locally, never sent to node)")
  .action(key => {
    const cfg = loadCLIConfig();
    cfg.privateKey = key;
    saveCLIConfig(cfg);
    ok("Private key stored in local config.");
    info("WARNING: Keep ~/.tip-cli.json secure. Do not commit it to version control.");
  });

configCmd
  .command("show")
  .description("Show current configuration")
  .action(() => {
    const cfg = loadCLIConfig();
    console.log(`\n${C.bold}TIP CLI Configuration${C.reset}`);
    label("Node URL", cfg.nodeUrl || "(not set — default: http://localhost:4000)");
    label("Default TIP-ID", cfg.defaultTipId || "(not set)");
    label("Private key", cfg.privateKey ? "[stored]" : "(not set)");
    label("Config file", CONFIG_PATH);
    console.log();
  });

// ─────────────────────────────────────────────────────────────────────────────
// IDENTITY
// ─────────────────────────────────────────────────────────────────────────────

const identityCmd = program.command("identity").alias("id").description("Identity management");

identityCmd
  .command("generate-keypair")
  .description("Generate a new ML-DSA-65 keypair (local only, not registered)")
  .action(() => {
    const kp = generateMLDSAKeypair();
    console.log(`\n${C.bold}New ML-DSA-65 Keypair${C.reset}`);
    label("Algorithm", kp.algorithm);
    label("Public key", kp.publicKey.slice(0, 32) + "...");
    label("Private key", kp.privateKey.slice(0, 32) + "...");
    info("Store your private key securely. Run: tip config set-key <privateKey>");
    console.log(`\n${C.dim}Full public key:${C.reset}\n${kp.publicKey}`);
    console.log(`\n${C.dim}Full private key:${C.reset}\n${kp.privateKey}`);
  });

identityCmd
  .command("register")
  .description("[DEV ONLY] Register a TIP-ID with mock ZK proof (production: use VP SDK)")
  .requiredOption("--vp-id <vpId>", "Verification Provider ID")
  .option("--region <region>", "Region code (default: US)", "US")
  .option("--tier <tier>", "Verification tier T1|T2|T3|T4 (default: T1)", "T1")
  .option("--attested", "Has social attestation (3 vouchers)")
  .option("--founding", "Founding member (Genesis Block)")
  .requiredOption("--vp-key <vpPrivateKey>", "VP private key (hex) for signing the registration")
  .action(async (opts) => {
    const client = getClient();
    // Mock dedup hash and ZK proof — production: VP SDK calls generateDedupProof() on-device
    const mockDedupHash = shake256Multi("cli-registration", opts.region, opts.vpId);
    const mockZkProof = { pi_a: ["1", "2", "3"], pi_b: [["1", "2"], ["3", "4"], ["5", "6"]], pi_c: ["1", "2", "3"], protocol: "groth16", curve: "bn128" };

    // VP signs canonical payload: dedup_hash + verification_tier + vp_id
    const vpPayload = mockDedupHash + opts.tier + opts.vpId;
    const vpSignature = mldsaSign(vpPayload, opts.vpKey);

    console.log(`\n${C.bold}Registering TIP-ID...${C.reset}`);
    info(`Node:   ${loadCLIConfig().nodeUrl || "http://localhost:4000"}`);
    info(`Region: ${opts.region}`);
    info(`VP ID:  ${opts.vpId}`);
    info(`Tier:   ${opts.tier}`);

    try {
      const res = await client.identity.register({
        region: opts.region,
        vpId: opts.vpId,
        vpSignature,
        dedupHash: mockDedupHash,
        zkProof: mockZkProof,
        verificationTier: opts.tier,
        socialAttested: !!opts.attested,
        founding: !!opts.founding,
      });

      console.log(`\n${C.green}${C.bold}Identity registered successfully!${C.reset}\n`);
      label("TIP-ID", res.tip_id);
      label("Score", res.score);
      label("TX ID", res.tx_id);
      label("Registered at", res.registered_at);
      console.log(`\n${C.yellow}${C.bold}IMPORTANT: Save your private key now. It will not be shown again.${C.reset}`);
      console.log(`${C.dim}Private key:${C.reset}\n${res.private_key}`);
      info("Run: tip config set-key <privateKey>  to store it locally");
      info(`Run: tip config set-identity ${res.tip_id}  to set as default`);

    } catch (e) {
      err(`Registration failed: ${e.message}`);
      if (e.data) console.error(e.data);
      process.exit(1);
    }
  });

identityCmd
  .command("resolve <tipId>")
  .description("Resolve a TIP-ID to its public record")
  .action(async (tipId) => {
    const client = getClient();
    try {
      const res = await client.identity.resolve(tipId);
      console.log(`\n${C.bold}Identity Record${C.reset}`);
      label("TIP-ID", res.tip_id);
      label("Region", res.region);
      label("VP", res.vp_id || "(none)");
      label("Tier", res.verification_tier);
      label("Status", res.status);
      label("Founding", res.founding ? "Yes ★" : "No");
      label("Content count", res.content_count);
      label("Registered at", res.registered_at);
      printScore(res);
      console.log();
    } catch (e) {
      err(`Could not resolve TIP-ID: ${e.message}`);
      process.exit(1);
    }
  });

identityCmd
  .command("score <tipId>")
  .description("Get trust score for a TIP-ID")
  .action(async (tipId) => {
    const client = getClient();
    try {
      const res = await client.trust.getScore(tipId);
      console.log(`\n${C.bold}Trust Score: ${tipId}${C.reset}`);
      printScore(res);
      console.log();
    } catch (e) {
      err(e.message);
      process.exit(1);
    }
  });

identityCmd
  .command("history <tipId>")
  .description("Show full score history for a TIP-ID")
  .action(async (tipId) => {
    const client = getClient();
    try {
      const res = await client.identity.getHistory(tipId);
      console.log(`\n${C.bold}Score History: ${tipId}${C.reset}\n`);
      if (!res.history || res.history.length === 0) {
        info("No score events found.");
      } else {
        res.history.forEach(ev => {
          const sign = ev.delta >= 0 ? `${C.green}+${ev.delta}${C.reset}` : `${C.red}${ev.delta}${C.reset}`;
          console.log(`  ${C.dim}${ev.timestamp}${C.reset}  ${sign.padEnd(12)}  ${ev.score_after.toString().padStart(4)} pts  ${C.dim}${ev.reason}${C.reset}`);
        });
      }
      console.log();
    } catch (e) {
      err(e.message);
      process.exit(1);
    }
  });

// ─────────────────────────────────────────────────────────────────────────────
// CONTENT
// ─────────────────────────────────────────────────────────────────────────────

const contentCmd = program.command("content").alias("c").description("Content provenance management");

contentCmd
  .command("register")
  .description("Register content with a mandatory origin declaration")
  .option("--file <path>", "Path to content file")
  .option("--text <text>", "Inline content text")
  .option("--hash <hash>", "Pre-computed content hash (for binary content)")
  .requiredOption("--origin <code>", "Origin code: OH | AA | AG | MX")
  .option("--tip-id <tipId>", "Author TIP-ID (uses default if set)")
  .option("--key <privateKey>", "ML-DSA-65 private key (uses config if set)")
  .action(async (opts) => {
    const cfg = loadCLIConfig();
    const tipId = opts.tipId || cfg.defaultTipId;
    const privKey = opts.key || cfg.privateKey;

    if (!tipId) { err("--tip-id required (or set default: tip config set-identity <tipId>)"); process.exit(1); }
    if (!ORIGIN[opts.origin]) { err(`Invalid --origin. Must be one of: ${Object.keys(ORIGIN).join(", ")}`); process.exit(1); }

    let content = opts.text || null;
    if (opts.file) {
      try { content = fs.readFileSync(path.resolve(opts.file), "utf8"); }
      catch (e) { err(`Cannot read file: ${opts.file}`); process.exit(1); }
    }
    if (!content && !opts.hash) { err("--file, --text, or --hash is required"); process.exit(1); }

    const client = getClient();
    console.log(`\n${C.bold}Registering content...${C.reset}`);
    info(`Author: ${tipId}`);
    info(`Origin: ${opts.origin} (${ORIGIN_LABELS[opts.origin]})`);
    if (opts.file) info(`File:   ${opts.file} (${(content || "").length} chars)`);

    try {
      const res = await client.content.register({
        authorTipId: tipId,
        privateKey: privKey,
        originCode: opts.origin,
        content: content,
        contentHash: opts.hash,
      });

      console.log(`\n${C.green}${C.bold}Content registered!${C.reset}\n`);
      label("CTID", res.ctid);
      label("Origin", `${res.originCode} — ${res.originLabel}`);
      label("Content hash", res.contentHash);
      label("Status", res.status);
      label("TX ID", res.txId);
      if (res.preScanFlagged) {
        console.log(`\n${C.yellow}⚠ Pre-scan flagged${C.reset}: ${res.preScanNote}`);
      }
      console.log(`\n${C.dim}Nginx config:${C.reset}`);
      console.log(res.nginxSnippet);
      console.log(`\n${C.dim}HTML meta tags:${C.reset}`);
      console.log(res.htmlSnippet);
      console.log();

    } catch (e) {
      err(`Content registration failed: ${e.message}`);
      if (e.data) console.error(e.data);
      process.exit(1);
    }
  });

contentCmd
  .command("resolve <ctid>")
  .description("Resolve a CTID to its provenance record")
  .action(async (ctid) => {
    const client = getClient();
    try {
      const res = await client.content.resolve(ctid);
      console.log(`\n${C.bold}Content Record${C.reset}`);
      label("CTID", res.ctid);
      label("Origin", `${res.origin_code} — ${res.origin_label || ORIGIN_LABELS[res.origin_code]}`);
      label("Author", res.author_tip_id);
      label("Status", res.status);
      label("Disputes", res.dispute_count);
      label("Verifications", res.verification_count);
      label("Registered at", res.registered_at);
      console.log();
    } catch (e) {
      err(e.message);
      process.exit(1);
    }
  });

contentCmd
  .command("verify <ctid>")
  .description("Submit a community verification of content origin")
  .option("--as <tipId>", "Verifier TIP-ID (uses default if set)")
  .option("--key <privateKey>", "ML-DSA-65 private key (uses config if set)")
  .action(async (ctid, opts) => {
    const cfg = loadCLIConfig();
    const tipId = opts.as || cfg.defaultTipId;
    if (!tipId) { err("--as <tipId> required"); process.exit(1); }
    const privKey = opts.key || cfg.privateKey;
    if (!privKey) { err("--key <privateKey> required (or set via: tip config set-key)"); process.exit(1); }

    const client = getClient();
    try {
      const res = await client.content.verify(ctid, tipId, privKey);
      ok(`Verification submitted. Score delta: +${res.delta_applied}`);
    } catch (e) {
      err(e.message);
      process.exit(1);
    }
  });

contentCmd
  .command("dispute <ctid>")
  .description("File an origin dispute against a content record")
  .requiredOption("--as <tipId>", "Disputer TIP-ID")
  .requiredOption("--reason <reason>", "Reason for dispute")
  .option("--key <privateKey>", "ML-DSA-65 private key (uses config if set)")
  .option("--evidence <hash>", "SHAKE-256 hash of supporting evidence")
  .action(async (ctid, opts) => {
    const cfg = loadCLIConfig();
    const privKey = opts.key || cfg.privateKey;
    if (!privKey) { err("--key <privateKey> required (or set via: tip config set-key)"); process.exit(1); }

    const client = getClient();
    try {
      const res = await client.content.dispute(ctid, opts.as, privKey, opts.reason, opts.evidence);
      ok(res.message || "Dispute filed successfully.");
    } catch (e) {
      err(e.message);
      process.exit(1);
    }
  });

// ─────────────────────────────────────────────────────────────────────────────
// TRUST
// ─────────────────────────────────────────────────────────────────────────────

const trustCmd = program.command("trust").alias("t").description("Trust scoring and revocations");

trustCmd
  .command("score <tipId>")
  .description("Get trust score for a TIP-ID")
  .action(async (tipId) => {
    const client = getClient();
    try {
      const res = await client.trust.getScore(tipId);
      printScore(res);
      console.log();
    } catch (e) {
      err(e.message); process.exit(1);
    }
  });

trustCmd
  .command("revocations")
  .description("List recent revocations")
  .option("--since <iso>", "Only show revocations after this timestamp")
  .action(async (opts) => {
    const client = getClient();
    try {
      const res = await client.trust.getRevocations(opts.since);
      console.log(`\n${C.bold}Revocations (${res.count})${C.reset}\n`);
      if (!res.revocations || res.revocations.length === 0) {
        info("No revocations found.");
      } else {
        res.revocations.forEach(r => {
          console.log(`  ${C.red}${r.tip_id}${C.reset}  ${C.dim}${r.tx_type} · ${r.timestamp}${C.reset}`);
        });
      }
      console.log();
    } catch (e) {
      err(e.message); process.exit(1);
    }
  });

trustCmd
  .command("merkle-root")
  .description("Get the dedup Merkle root for audit")
  .action(async () => {
    const client = getClient();
    try {
      const res = await client.trust.getMerkleRoot();
      console.log(`\n${C.bold}Dedup Merkle Root${C.reset}`);
      label("Merkle root", res.merkle_root);
      label("Dedup count", res.dedup_count);
      label("Identity count", res.identity_count);
      label("Generated", res.generated);
      console.log();
    } catch (e) {
      err(e.message); process.exit(1);
    }
  });

// ─────────────────────────────────────────────────────────────────────────────
// VP
// ─────────────────────────────────────────────────────────────────────────────

const vpCmd = program.command("vp").description("Verification Provider management");

vpCmd
  .command("register")
  .description("Register a new Verification Provider")
  .requiredOption("--name <name>", "VP display name")
  .option("--tier <tier>", "Jurisdiction tier: green|amber (default: green)", "green")
  .option("--key <publicKey>", "VP ML-DSA-65 public key (generates if omitted)")
  .action(async (opts) => {
    const client = getClient();
    let pubKey = opts.key;
    if (!pubKey) {
      const kp = generateMLDSAKeypair();
      pubKey = kp.publicKey;
      info("Generated new VP keypair. Private key:");
      console.log(kp.privateKey);
    }
    try {
      const res = await client._fetch("/v1/vp/register", {
        method: "POST",
        body: { name: opts.name, jurisdiction_tier: opts.tier, public_key: pubKey },
      });
      ok(`VP registered: ${res.vp_id}`);
      label("Name", res.name);
      label("Tier", res.jurisdiction_tier);
      label("VP ID", res.vp_id);
    } catch (e) {
      err(e.message); process.exit(1);
    }
  });

vpCmd
  .command("resolve <vpId>")
  .description("Resolve a VP record")
  .action(async (vpId) => {
    const client = getClient();
    try {
      const res = await client._fetch(`/v1/vp/${encodeURIComponent(vpId)}`);
      console.log(`\n${C.bold}Verification Provider${C.reset}`);
      Object.entries(res).forEach(([k, v]) => label(k, String(v)));
      console.log();
    } catch (e) {
      err(e.message); process.exit(1);
    }
  });

// ─────────────────────────────────────────────────────────────────────────────
// NODE
// ─────────────────────────────────────────────────────────────────────────────

const nodeCmd = program.command("node").alias("n").description("Node diagnostics");

nodeCmd
  .command("info")
  .description("Show node information")
  .action(async () => {
    const client = getClient();
    try {
      const res = await client.nodeInfo();
      console.log(`\n${C.bold}TIP Node Info${C.reset}`);
      Object.entries(res).forEach(([k, v]) => label(k, String(v)));
      console.log();
    } catch (e) {
      err(`Could not reach node: ${e.message}`);
      info("Check your node URL: tip config show");
      process.exit(1);
    }
  });

nodeCmd
  .command("peers")
  .description("Show connected peers")
  .action(async () => {
    const client = getClient();
    try {
      const res = await client.peers();
      console.log(`\n${C.bold}Peers (${res.count})${C.reset}\n`);
      (res.peers || []).forEach(p => info(p));
      if (!res.count) info("No peers connected.");
      console.log();
    } catch (e) {
      err(e.message); process.exit(1);
    }
  });

nodeCmd
  .command("ping")
  .description("Check node health")
  .action(async () => {
    const cfg = loadCLIConfig();
    const nodeUrl = cfg.nodeUrl || "http://localhost:4000";
    const client = new TIPClient({ nodeUrl });
    info(`Pinging ${nodeUrl}...`);
    try {
      const res = await client.ping();
      ok(`Node is healthy. DAG transactions: ${res.dag_count}`);
    } catch (e) {
      err(`Node unreachable: ${e.message}`);
      process.exit(1);
    }
  });

// ─────────────────────────────────────────────────────────────────────────────
// BADGE
// ─────────────────────────────────────────────────────────────────────────────

const badgeCmd = program.command("badge").alias("b").description("Badge generation");

badgeCmd
  .command("seal")
  .description("Generate an AI Trust ID™ Seal SVG")
  .requiredOption("--score <n>", "Trust score (0–1000)", parseInt)
  .option("--size <n>", "Size in pixels (default: 200)", parseInt)
  .option("--variant <v>", "gold-dark | light | dark (default: gold-dark)", "gold-dark")
  .option("--founding", "Show founding star")
  .option("--out <path>", "Output file (prints to stdout if omitted)")
  .action((opts) => {
    const { TIPBadgesClient } = require("../../sdk/src/badges");
    const badges = new TIPBadgesClient({});
    const svg = badges.renderSeal({
      score: opts.score,
      size: opts.size || 200,
      variant: opts.variant,
      founding: !!opts.founding,
    });
    if (opts.out) {
      fs.writeFileSync(path.resolve(opts.out), svg);
      ok(`Seal written to: ${opts.out}`);
    } else {
      process.stdout.write(svg + "\n");
    }
  });

badgeCmd
  .command("mark")
  .description("Generate a TIP™ Powered Mark SVG (open — no permission needed)")
  .option("--size <n>", "Size in pixels (default: 140)", parseInt)
  .option("--variant <v>", "light | dark (default: light)", "light")
  .option("--out <path>", "Output file")
  .action((opts) => {
    const { TIPBadgesClient } = require("../../sdk/src/badges");
    const badges = new TIPBadgesClient({});
    const svg = badges.renderTIPMark({ size: opts.size || 140, variant: opts.variant });
    if (opts.out) {
      fs.writeFileSync(path.resolve(opts.out), svg);
      ok(`TIP mark written to: ${opts.out}`);
    } else {
      process.stdout.write(svg + "\n");
    }
  });

badgeCmd
  .command("shield")
  .description("Generate an inline shield badge SVG")
  .requiredOption("--score <n>", "Trust score (0–1000)", parseInt)
  .option("--size <n>", "Size (default: 48)", parseInt)
  .option("--founding", "Founding border")
  .option("--out <path>", "Output file")
  .action((opts) => {
    const { TIPBadgesClient } = require("../../sdk/src/badges");
    const badges = new TIPBadgesClient({});
    const svg = badges.renderShield({ score: opts.score, size: opts.size || 48, founding: !!opts.founding });
    if (opts.out) { fs.writeFileSync(path.resolve(opts.out), svg); ok(`Shield written to: ${opts.out}`); }
    else process.stdout.write(svg + "\n");
  });

badgeCmd
  .command("headers")
  .description("Generate HTTP header config for your web server")
  .requiredOption("--tip-id <id>", "Author TIP-ID")
  .requiredOption("--ctid <ctid>", "Content CTID")
  .requiredOption("--origin <code>", "Origin code: OH|AA|AG|MX")
  .requiredOption("--score <n>", "Author trust score", parseInt)
  .option("--sig <sig>", "ML-DSA-65 signature")
  .option("--format <f>", "nginx|apache|caddy|cloudflare|netlify (default: nginx)", "nginx")
  .action((opts) => {
    const { TIPBadgesClient } = require("../../sdk/src/badges");
    const badges = new TIPBadgesClient({});
    const cfg = badges.generateHTTPConfig({
      tipId: opts.tipId,
      ctid: opts.ctid,
      originCode: opts.origin,
      score: opts.score,
      signature: opts.sig,
    });
    console.log(`\n${C.bold}${opts.format.toUpperCase()} Configuration${C.reset}\n`);
    console.log(cfg[opts.format] || cfg.nginx);
    console.log(`\n${C.dim}HTML meta tags:${C.reset}`);
    console.log(badges.generateMetaTags({ tipId: opts.tipId, ctid: opts.ctid, originCode: opts.origin, score: opts.score }));
    console.log();
  });

// ─────────────────────────────────────────────────────────────────────────────
// PARSE
// ─────────────────────────────────────────────────────────────────────────────

program.parse(process.argv);

if (process.argv.length < 3) {
  console.log(`\n${C.bold}TIP™ Protocol CLI v2.0${C.reset}`);
  console.log(`${C.dim}The AI Lab Intelligence Unobscured, Inc. | theailab.org${C.reset}\n`);
  program.help();
}
