/**
 * scripts/zk-setup.js
 * TIP Protocol — One-time ZK trusted setup
 *
 * Compiles the dedup circuit, generates proving key and verification key.
 * Run once before starting the node:
 *
 *   node scripts/zk-setup.js
 *
 * Prerequisites:
 *   - circom binary installed: https://docs.circom.io/getting-started/installation/
 *   - npm packages: snarkjs, circomlib  (npm install snarkjs circomlib)
 *
 * Outputs (in circuits/):
 *   dedup_js/dedup.wasm   — used by client to generate proofs
 *   dedup.r1cs            — constraint system (intermediate)
 *   dedup_final.zkey      — proving key (distribute to clients via SDK)
 *   vkey.json             — verification key (loaded by node at runtime)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const { execSync } = require("child_process");
const path         = require("path");
const fs           = require("fs");
const snarkjs      = require("snarkjs");

const ROOT     = path.join(__dirname, "..");
const CIRCUITS = path.join(ROOT, "circuits");
const CIRCUIT  = path.join(CIRCUITS, "dedup.circom");

async function main() {
  console.log("TIP Protocol — ZK trusted setup\n");

  // ── 0. Parse --ptau flag ─────────────────────────────────────────────────────
  // Pass the path to a publicly-audited Powers of Tau file for production:
  //   node scripts/zk-setup.js --ptau circuits/powersOfTau28_hez_final_18.ptau
  //
  // The repo ships without the ptau file (288MB — too large for git).
  // Download from iden3/snarkjs GitHub README → "Downloading a ptau file".
  const ptauFlagIdx = process.argv.indexOf("--ptau");
  const externalPtau = ptauFlagIdx !== -1 ? process.argv[ptauFlagIdx + 1] : null;

  if (externalPtau) {
    if (!fs.existsSync(externalPtau)) {
      console.error(`ERROR: ptau file not found at ${externalPtau}`);
      process.exit(1);
    }
    console.log(`Using external ptau: ${externalPtau}\n`);
  }

  // ── 1. Check circom is installed ────────────────────────────────────────────
  // circom is a Rust binary — may live in ~/.cargo/bin if not on PATH
  try {
    execSync("circom --version", { stdio: "pipe" });
  } catch {
    const cargoBin = `${process.env.HOME}/.cargo/bin/circom`;
    try {
      execSync(`${cargoBin} --version`, { stdio: "pipe" });
      process.env.PATH = `${process.env.PATH}:${process.env.HOME}/.cargo/bin`;
    } catch {
      console.error("ERROR: circom not found. Run: cargo install circom");
      process.exit(1);
    }
  }

  // ── 2. Compile circuit ───────────────────────────────────────────────────────
  console.log("Step 1/4: Compiling circuit...");
  execSync(
    `circom ${CIRCUIT} --r1cs --wasm --sym -o ${CIRCUITS} -l ${path.join(ROOT, "node_modules")}`,
    { stdio: "inherit" }
  );
  console.log("  Circuit compiled.\n");

  // ── 3. Powers of tau ─────────────────────────────────────────────────────────
  // Poseidon(3) has ~240 constraints, well within pot12 (supports up to 4096).
  const ptauPath = externalPtau || path.join(CIRCUITS, "pot12_final.ptau");
  if (externalPtau) {
    console.log("Step 2/4: Using provided ptau file — skipping local generation.\n");
  } else if (!fs.existsSync(ptauPath)) {
    // No --ptau provided — falling back to local single-contributor generation.
    // For production, use --ptau with the Hermez ceremony file instead.
    console.log("Step 2/4: Generating powers of tau (pot12, single-contributor)...");
    console.log("  WARNING: Single-contributor setup. Use --ptau with the Hermez");
    console.log("  ceremony file for production security.\n");

    const curve = await snarkjs.curves.getCurveFromName("bn128");
    await snarkjs.powersOfTau.newAccumulator(curve, 12, path.join(CIRCUITS, "pot12_0000.ptau"), console);
    await snarkjs.powersOfTau.contribute(
      path.join(CIRCUITS, "pot12_0000.ptau"),
      path.join(CIRCUITS, "pot12_0001.ptau"),
      "First contribution",
      "TIP Protocol Setup Entropy " + Date.now(),
      console
    );
    await snarkjs.powersOfTau.preparePhase2(
      path.join(CIRCUITS, "pot12_0001.ptau"),
      ptauPath,
      console
    );
    await curve.terminate();
    fs.unlinkSync(path.join(CIRCUITS, "pot12_0000.ptau"));
    fs.unlinkSync(path.join(CIRCUITS, "pot12_0001.ptau"));
    console.log("  Powers of tau ready.\n");
  } else {
    console.log("Step 2/4: Powers of tau already exists — skipping.\n");
  }

  // ── 4. Groth16 setup (phase 2) ───────────────────────────────────────────────
  console.log("Step 3/4: Running Groth16 trusted setup...");
  const r1csPath   = path.join(CIRCUITS, "dedup.r1cs");
  const zkey0Path  = path.join(CIRCUITS, "dedup_0000.zkey");
  const zkeyFinal  = path.join(CIRCUITS, "dedup_final.zkey");

  await snarkjs.zKey.newZKey(r1csPath, ptauPath, zkey0Path, console);
  await snarkjs.zKey.contribute(
    zkey0Path,
    zkeyFinal,
    "TIP Protocol",
    "TIP Protocol ZKey Contribution " + Date.now(),
    console
  );
  fs.unlinkSync(zkey0Path);
  console.log("  Proving key ready.\n");

  // ── 5. Export verification key ───────────────────────────────────────────────
  console.log("Step 4/4: Exporting verification key...");
  const vKeyPath = path.join(CIRCUITS, "vkey.json");
  const vKey = await snarkjs.zKey.exportVerificationKey(zkeyFinal);
  fs.writeFileSync(vKeyPath, JSON.stringify(vKey, null, 2));
  console.log("  Verification key written to circuits/vkey.json\n");

  console.log("Setup complete.");
  console.log("  Proving key:      circuits/dedup_final.zkey  (distribute via SDK)");
  console.log("  Verification key: circuits/vkey.json         (loaded by node)");
  console.log("  WASM:             circuits/dedup_js/dedup.wasm (distribute via SDK)\n");

  process.exit(0);
}

main().catch(err => {
  console.error("Setup failed:", err);
  process.exit(1);
});
