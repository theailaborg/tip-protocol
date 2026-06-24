#!/usr/bin/env node
/**
 * Resign genesis bootstrap signatures after GENESIS_PAYLOAD changes.
 *
 * Run with: node --experimental-vm-modules scripts/resign-genesis.js
 *
 * Precondition: genesis-data/founding-vp-keys.json must contain the active
 * founding VP keypair. If that file's public key differs from genesis.js, this
 * script updates genesis.js to be consistent with the file (which is correct
 * for development re-seeds where the key file is the source of truth).
 *
 * What it does:
 *   1. Reads founding VP private + public key from founding-vp-keys.json
 *   2. Patches genesis.js founding_vp.public_key and founding_vp.vp_id
 *   3. Clears require cache, re-requires genesis.js (picks up new VP key)
 *   4. Recomputes GENESIS_TX_SIGNATURE and GENESIS_VP_TX_SIGNATURE
 *   5. Patches genesis.js with new signatures in-place
 *   6. Deletes genesis.json so buildGenesisBlock re-mints on next node boot
 *   7. Verifies both signatures
 *
 * Run this any time genesis.js protocol_constants are modified or after a
 * full cluster reset where the VP keypair was regenerated.
 */
"use strict";

const fs   = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");

async function main() {
  // 1. Init PQ crypto
  const { initCrypto, mldsaSign, mldsaVerify, canonicalTx, shake256, generateVPId } = require(path.join(ROOT, "shared/crypto"));
  await initCrypto();

  // 2. Read founding VP keypair from founding-vp-keys.json
  const vpKeysFile = path.join(ROOT, "genesis-data/founding-vp-keys.json");
  const vpKeysData = JSON.parse(fs.readFileSync(vpKeysFile, "utf8"));
  const vpEntry = vpKeysData.entries[0];
  if (!vpEntry?.private_key || !vpEntry?.public_key) {
    throw new Error(`No VP private key found in ${vpKeysFile}`);
  }
  const vpPrivateKey = vpEntry.private_key;
  const vpPublicKey  = vpEntry.public_key;
  const vpId         = generateVPId("US", vpPublicKey);

  console.log(`VP public key: ${vpPublicKey.slice(0, 32)}...`);
  console.log(`VP ID: ${vpId}`);

  // 3. Patch genesis.js so founding_vp.public_key and vp_id match the key file
  const genesisJsFile = path.join(ROOT, "node/src/genesis.js");
  let gSrc = fs.readFileSync(genesisJsFile, "utf8");

  // Check current VP public key
  const curPubMatch = gSrc.match(/public_key:\s*"([a-f0-9]{32})/);
  const curPubPrefix = curPubMatch ? curPubMatch[1] : "(not found)";

  if (curPubPrefix === vpPublicKey.slice(0, 32)) {
    console.log("✓ genesis.js VP public_key already matches founding-vp-keys.json");
  } else {
    console.log(`Updating VP public_key: ${curPubPrefix}... → ${vpPublicKey.slice(0, 32)}...`);

    // Replace founding_vp.public_key (hex string of 4096+ chars in the founding_vp block)
    // The founding_vp block starts at line "founding_vp: {" and public_key is the only
    // 4000+ char hex string there. We replace the first occurrence of a long hex key
    // that appears right after "public_key:" in the founding_vp section.
    const OLD_PUB_KEY_PATTERN = /(founding_vp:\s*\{[\s\S]*?public_key:\s*")([a-f0-9]{1000,})(")/;
    if (!OLD_PUB_KEY_PATTERN.test(gSrc)) {
      throw new Error("Could not locate founding_vp.public_key pattern in genesis.js");
    }
    gSrc = gSrc.replace(OLD_PUB_KEY_PATTERN, `$1${vpPublicKey}$3`);
    console.log("✓ founding_vp.public_key replaced");

    // Replace founding_vp.vp_id (format: tip://vp/US-...)
    const OLD_VP_ID_PATTERN = /(vp_id:\s*")tip:\/\/vp\/US-[a-f0-9]{16}(")/;
    if (!OLD_VP_ID_PATTERN.test(gSrc)) {
      throw new Error("Could not locate founding_vp.vp_id pattern in genesis.js");
    }
    gSrc = gSrc.replace(OLD_VP_ID_PATTERN, `$1${vpId}$2`);
    console.log("✓ founding_vp.vp_id replaced →", vpId);

    fs.writeFileSync(genesisJsFile, gSrc);
    console.log("✓ genesis.js VP fields updated");
  }

  // 4. Clear require cache and load genesis.js with updated VP key
  Object.keys(require.cache).forEach(k => { if (k.includes("genesis") || k.includes("protocol-constants")) delete require.cache[k]; });
  const genesis = require(path.join(ROOT, "node/src/genesis"));
  const { GENESIS_TX, GENESIS_TX_ID, GENESIS_TIMESTAMP, GENESIS_PAYLOAD } = genesis;

  // Confirm the loaded VP key matches what we embedded
  const loadedVpKey = GENESIS_PAYLOAD?.founding_vp?.public_key;
  if (loadedVpKey !== vpPublicKey) {
    throw new Error(`VP public key mismatch after embedding: got ${(loadedVpKey||"").slice(0, 32)}... expected ${vpPublicKey.slice(0, 32)}...`);
  }
  console.log("✓ genesis.js loaded with correct VP public key");

  // 5. Recompute GENESIS_TX_SIGNATURE
  const SIG_DET = { deterministic: true };
  const genesisTxSig = mldsaSign(canonicalTx(GENESIS_TX), vpPrivateKey, SIG_DET);

  // 6. Recompute GENESIS_VP_TX_SIGNATURE (prev uses new GENESIS_TX_ID)
  const vpTxBody = {
    tx_type: "VP_REGISTERED",
    timestamp: GENESIS_TIMESTAMP,
    prev: [GENESIS_TX_ID, GENESIS_TX_ID],
    data: {
      vp_id:             GENESIS_PAYLOAD.founding_vp.vp_id,
      name:              GENESIS_PAYLOAD.founding_vp.name,
      jurisdiction:      GENESIS_PAYLOAD.founding_vp.jurisdiction,
      jurisdiction_tier: GENESIS_PAYLOAD.founding_vp.jurisdiction_tier,
      public_key:        vpPublicKey,
    },
  };
  const vpTxSig = mldsaSign(canonicalTx(vpTxBody), vpPrivateKey, SIG_DET);

  // 7. Patch genesis.js signatures
  gSrc = fs.readFileSync(genesisJsFile, "utf8");
  gSrc = gSrc.replace(
    /GENESIS_TX_SIGNATURE\s*=\s*"[^"]*"/,
    `GENESIS_TX_SIGNATURE = "${genesisTxSig}"`,
  );
  gSrc = gSrc.replace(
    /GENESIS_VP_TX_SIGNATURE\s*=\s*"[^"]*"/,
    `GENESIS_VP_TX_SIGNATURE = "${vpTxSig}"`,
  );
  fs.writeFileSync(genesisJsFile, gSrc);
  console.log("✓ GENESIS_TX_SIGNATURE updated in genesis.js");
  console.log("✓ GENESIS_VP_TX_SIGNATURE updated in genesis.js");

  // 8. Regenerate genesis.json with updated GENESIS_PAYLOAD
  //    Tests load genesis.json directly for protocol_constants, so the file
  //    must exist and must contain the new constants. buildGenesisBlock() auto-
  //    generates a dev-signed block when the file is absent.
  const genesisJsonFile = path.join(ROOT, "genesis-data/genesis.json");
  if (fs.existsSync(genesisJsonFile)) {
    fs.unlinkSync(genesisJsonFile);
  }
  // Clear cache so buildGenesisBlock sees the updated genesis.js
  Object.keys(require.cache).forEach(k => { if (k.includes("genesis") || k.includes("protocol-constants")) delete require.cache[k]; });
  const genesisForBuild = require(path.join(ROOT, "node/src/genesis"));
  // Pass a dev signing key so buildGenesisBlock can write the file
  const { generateMLDSAKeypair, mldsaSign: sign2, shake256: sha2, canonicalJson } = require(path.join(ROOT, "shared/crypto"));
  const devKey = generateMLDSAKeypair();
  const freshPayload = genesisForBuild.GENESIS_PAYLOAD;
  const freshHash = genesisForBuild.computeGenesisHash(freshPayload);
  const genesisBlock = {
    ...freshPayload,
    genesis_hash: freshHash,
    canonical_hash: sha2(canonicalJson(freshPayload)),
    signed_at: 1750000000000, // deterministic so tests don't flap on timestamp
    signer_public_key: devKey.publicKey,
    signature: sign2(freshHash, devKey.privateKey, { deterministic: true }),
    environment: "development",
  };
  fs.writeFileSync(genesisJsonFile, JSON.stringify(genesisBlock, null, 2));
  console.log("✓ genesis.json regenerated with updated protocol_constants");

  // 9. Verify
  Object.keys(require.cache).forEach(k => { if (k.includes("genesis") || k.includes("protocol-constants")) delete require.cache[k]; });
  const fresh = require(path.join(ROOT, "node/src/genesis"));

  const ok1 = mldsaVerify(canonicalTx(fresh.GENESIS_TX), fresh.GENESIS_TX_SIGNATURE, fresh.getFoundingVP().public_key);
  if (!ok1) throw new Error("GENESIS_TX_SIGNATURE verification FAILED after resign!");
  console.log("✓ GENESIS_TX_SIGNATURE verifies correctly");

  const freshVpTxBody = {
    tx_type: "VP_REGISTERED",
    timestamp: fresh.GENESIS_TIMESTAMP,
    prev: [fresh.GENESIS_TX_ID, fresh.GENESIS_TX_ID],
    data: {
      vp_id:             fresh.GENESIS_PAYLOAD.founding_vp.vp_id,
      name:              fresh.GENESIS_PAYLOAD.founding_vp.name,
      jurisdiction:      fresh.GENESIS_PAYLOAD.founding_vp.jurisdiction,
      jurisdiction_tier: fresh.GENESIS_PAYLOAD.founding_vp.jurisdiction_tier,
      public_key:        fresh.getFoundingVP().public_key,
    },
  };
  const ok2 = mldsaVerify(canonicalTx(freshVpTxBody), fresh.GENESIS_VP_TX_SIGNATURE, fresh.getFoundingVP().public_key);
  if (!ok2) throw new Error("GENESIS_VP_TX_SIGNATURE verification FAILED after resign!");
  console.log("✓ GENESIS_VP_TX_SIGNATURE verifies correctly");

  console.log("\n✓ Resign complete. Commit genesis.js.");
  console.log("  Note: genesis_ring_keys VP signatures are stale. Run full reseed to fix.");
}

main().catch(e => { console.error("ERROR:", e.message); process.exit(1); });
