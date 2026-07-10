/**
 * @file tests/helpers/snapshot-install.js
 * @description Run one snapshot install attempt between two DAGs over a
 * re-fragmented (and optionally truncated) stream pair. Extracted from the
 * #132 streaming harness so crash / non-destructive-install suites share it.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");

const { createSnapshotHandler } = require(path.join(SRC, "sync", "snapshot-handler"));
const { createStreamPair } = require("./stream-pair");

// Re-fragments the server→client bytes into `chunkSize`-byte pieces and
// optionally truncates at `truncateAfterFraction` of the total (a fraction, so
// the cut lands past the header regardless of absolute size). A truncated
// stream ends mid-frame / before END, exactly a dropped connection.
async function attemptInstall(sourceDag, destDag, { chunkSize = 8, truncateAfterFraction = 1 } = {}) {
  const { client, server } = createStreamPair();

  const origServerSink = server.sink;
  server.sink = async (src) => {
    await origServerSink((async function* () {
      const parts = [];
      for await (const f of src) parts.push(Buffer.from(f));
      const whole = Buffer.concat(parts);
      const limit = Math.floor(whole.length * Math.min(1, truncateAfterFraction));
      for (let off = 0; off < limit; off += chunkSize) {
        yield whole.subarray(off, Math.min(off + chunkSize, limit));
      }
    })());
  };

  const sourceHandler = createSnapshotHandler({
    dag: sourceDag,
    network: { node: {}, handle: async () => { } },
    isAuthorizedPeer: () => true,
  });
  const destHandler = createSnapshotHandler({
    dag: destDag,
    network: { node: {}, openStream: async () => client },
    isAuthorizedPeer: () => true,
  });

  const results = await Promise.allSettled([
    sourceHandler._handleIncomingSnapshot(server, "test-client"),
    destHandler.requestSnapshotFromPeer("test-server", {}),
  ]);
  const clientResult = results[1];
  if (clientResult.status === "rejected") throw clientResult.reason;
  return clientResult.value;
}

module.exports = { attemptInstall };
