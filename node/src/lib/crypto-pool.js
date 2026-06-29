/**
 * @file @tip-protocol/node/src/lib/crypto-pool.js
 * @description worker_threads pool for off-thread ML-DSA verification.
 * Certificate verify is off the consensus critical path; a catch-up / rejoin
 * burst of synchronous verifies is what blocks the event loop. Offloading it to
 * workers keeps the main loop responsive during the burst.
 *
 * Pool size 0 => disabled: verifyCert runs synchronously on the caller's thread
 * (still returns a Promise), so the call sites are uniform and the feature can be
 * turned off without code changes. A worker death falls back to sync too, so a
 * pool failure can never stall consensus.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { Worker } = require("worker_threads");
const os = require("os");
const path = require("path");
const { verifyCertificate } = require("../consensus/certificate");
const { getLogger } = require("../logger");

const log = getLogger("tip.crypto-pool");

function _syncVerify(cert, pubkeyMap, quorum) {
  const getKey = (id) => pubkeyMap[id] || null;
  return verifyCertificate(cert, getKey, quorum);
}

/**
 * @param {Object} [opts]
 * @param {number} [opts.size]    worker count; default cpus-2; 0 disables (sync)
 * @param {boolean}[opts.enabled] master switch; false => size 0
 */
function createCryptoPool({ size, enabled = true } = {}) {
  // Capped at 3: verify shares the host with the main loop, DB driver, and other
  // pools. 1-core host gets 0 (sync). Override via TIP_CRYPTO_POOL_SIZE.
  const cpus = os.cpus().length || 1;
  const resolved = size != null ? size : (cpus >= 2 ? Math.min(3, Math.max(1, cpus - 2)) : 0);
  const N = enabled ? Math.max(0, resolved) : 0;

  const workers = [];
  const pending = new Map(); // id -> { resolve }
  let nextId = 1, rr = 0;

  function _onMessage(msg) {
    if (msg.ready) return;
    const p = pending.get(msg.id);
    if (p) { pending.delete(msg.id); p.resolve(msg.result); }
  }
  function _onError(err) {
    log.warn(`crypto worker error: ${err.message}`);
    for (const [id, p] of pending) { pending.delete(id); p.resolve(null); } // null => caller sync-fallbacks
  }

  for (let i = 0; i < N; i++) {
    const w = new Worker(path.join(__dirname, "crypto-worker.js"));
    w.on("message", _onMessage);
    w.on("error", _onError);
    w.unref(); // pool must not keep the process alive
    workers.push(w);
  }
  if (N > 0) log.info(`Crypto pool: ${N} verify worker(s) online`);
  else log.info("Crypto pool: disabled (verify runs on the main thread)");

  // Sync-verifies inline when disabled or when a worker dropped the task, so a
  // pool failure can never stall consensus.
  function verifyCert(cert, pubkeyMap, quorum) {
    if (N === 0) return Promise.resolve(_syncVerify(cert, pubkeyMap, quorum));
    const id = nextId++;
    const w = workers[rr++ % N];
    return new Promise((resolve) => {
      pending.set(id, { resolve });
      w.postMessage({ id, type: "verifyCert", cert, pubkeyMap, quorum });
    }).then((result) => result || _syncVerify(cert, pubkeyMap, quorum));
  }

  function shutdown() {
    for (const w of workers) { try { w.terminate(); } catch { /* ignore */ } }
  }

  return { verifyCert, shutdown, size: N };
}

module.exports = { createCryptoPool };
