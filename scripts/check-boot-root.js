#!/usr/bin/env node
/**
 * @file scripts/check-boot-root.js
 * @description Pre-restart gate: rebuild the state root from this node's database
 * exactly as boot does and compare it with the live attested root. Read-only.
 *
 * A node whose database does not rebuild to the live root halts on restart and
 * must snapshot-recover, so restart only on a match. Run inside the node image:
 *
 *   sudo docker compose run --rm --no-deps -T --entrypoint node tip-node \
 *     scripts/check-boot-root.js --peer https://node2.theailab.org
 *
 * Flags: --peer <url> (compare with that node's /v1/state-root) or --expect <root>;
 * --migrate applies pending migrations first (run with the node stopped).
 * Exit 0 on a match, 1 on a mismatch, 2 on an error.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const ROOT = path.resolve(__dirname, "..");

function _arg(name) {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : null;
}

async function _expectedRoot() {
  const expect = _arg("--expect");
  if (expect) return { root: expect, source: "--expect" };
  const peer = _arg("--peer") || "http://localhost:4000";
  const res = await fetch(`${peer.replace(/\/$/, "")}/v1/state-root`, { signal: AbortSignal.timeout(10_000) });
  const body = await res.json();
  const data = body.data || body;
  return { root: data.state_merkle_root, source: `${peer} at round ${data.round}` };
}

async function main() {
  const PC = require(path.join(ROOT, "shared/protocol-constants"));
  PC.init(require(path.join(ROOT, "node/src/genesis")).getGenesisPayload().protocol_constants);
  await require(path.join(ROOT, "shared/crypto")).initCrypto();
  const { KnexAdapter } = require(path.join(ROOT, "node/src/db/knex-adapter"));
  const { computeStateMerkleRootPerTable } = require(path.join(ROOT, "node/src/consensus/state-root"));
  const config = require(path.join(ROOT, "node/src/config"));
  const cfg = typeof config.load === "function" ? config.load() : (config.config || config);

  const expected = await _expectedRoot();
  const adapter = new KnexAdapter(process.env.DB_DRIVER || "postgres", cfg, null);
  // --migrate applies pending migrations first, exactly as the next boot would.
  if (process.argv.includes("--migrate")) await adapter.knex.migrate.latest();
  await adapter._hydrate();
  const rebuilt = adapter.mirror.stateRoot();

  console.log(`database : ${process.env.DB_NAME || cfg.dbName || "(DATABASE_URL)"}`);
  console.log(`rebuilt  : ${rebuilt}`);
  console.log(`expected : ${expected.root}  (${expected.source})`);
  for (const t of computeStateMerkleRootPerTable(adapter.mirror)) {
    console.log(`  ${t.table.padEnd(24)} ${t.root}  rows=${t.count}`);
  }
  const ok = rebuilt === expected.root;
  console.log(ok ? "MATCH: safe to restart" : "MISMATCH: do not restart, this node would halt at boot");
  return ok ? 0 : 1;
}

main().then((code) => process.exit(code)).catch((err) => {
  console.error(`check-boot-root failed: ${err.stack || err.message}`);
  process.exit(2);
});
