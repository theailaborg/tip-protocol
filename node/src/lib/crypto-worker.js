/**
 * @file @tip-protocol/node/src/lib/crypto-worker.js
 * @description worker_threads entry for the crypto pool. Runs the heavy ML-DSA
 * verification off the main event loop so a catch-up / rejoin burst of cert
 * verifies can't block consensus liveness. Verify is a pure deterministic check
 * (sig vs pubkey), so a worker result is identical to a main-thread result.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { parentPort } = require("worker_threads");
const { initCrypto } = require("../../../shared/crypto");
const { verifyCertificate } = require("../consensus/certificate");

let _ready = false;
const _queue = [];

function _run(msg) {
  try {
    if (msg.type === "verifyCert") {
      const map = msg.pubkeyMap || {};
      const getKey = (id) => map[id] || null;
      const result = verifyCertificate(msg.cert, getKey, msg.quorum);
      parentPort.postMessage({ id: msg.id, result });
      return;
    }
    parentPort.postMessage({ id: msg.id, result: { valid: false, error: `unknown task ${msg.type}` } });
  } catch (err) {
    parentPort.postMessage({ id: msg.id, result: { valid: false, error: `worker error: ${err.message}` } });
  }
}

parentPort.on("message", (msg) => {
  if (_ready) _run(msg);
  else _queue.push(msg);
});

(async () => {
  await initCrypto();
  _ready = true;
  parentPort.postMessage({ ready: true });
  for (const m of _queue.splice(0)) _run(m);
})();
