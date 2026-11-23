"use strict";

// Pack worker thread: unzips, parses and checks one pack, builds every page's
// Merkle proof and content hash, then hands the leaf pages to the main thread
// one batch per request.

const { parentPort, workerData } = require("worker_threads");
const { checkPackBody, pageProofs, pageContentHash } = require("./site-pack");

const { record, bytes, batchPages } = workerData;

let leaves = null;
try {
  const checked = checkPackBody(record, bytes);
  const proofs = pageProofs(record, checked);
  checked.forEach((p, i) => { p.proof = proofs[i]; p.content_hash = pageContentHash(p); });
  leaves = checked;
} catch (err) {
  parentPort.postMessage({ type: "error", message: err.message, code: err.code || "pack_unreadable", permanent: !!err.permanent });
}

if (leaves) {
  let next = 0;
  parentPort.on("message", () => {
    const pages = leaves.slice(next, next + batchPages);
    next += pages.length;
    if (pages.length) {
      parentPort.postMessage({ type: "batch", pages });
    } else {
      parentPort.postMessage({ type: "done" });
      parentPort.close();
    }
  });
  parentPort.postMessage({ type: "ready", count: leaves.length });
}
