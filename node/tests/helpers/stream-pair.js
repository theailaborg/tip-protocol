/**
 * @file tests/helpers/stream-pair.js
 * @description In-memory bidirectional stream pair that mimics libp2p's
 * `{ sink, source, close }` contract. Lets any networking protocol test
 * (snapshot sync, cert sync, handshake, …) exercise the real framing +
 * decode + verify paths without standing up libp2p.
 *
 * Contract — each side exposes:
 *   async sink(asyncIterable<Uint8Array>)  → consumes chunks, signals EOF on return
 *   AsyncIterator<Uint8Array> source       → yields chunks the peer wrote, returns on peer EOF
 *   close()                                → no-op (present so caller can drop-in swap for libp2p streams)
 *
 * Client.sink → server.source; server.sink → client.source. Either side
 * completing its sink causes the opposite source loop to return normally.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

/**
 * Build one directional channel: a queue with an async iterator reader
 * and a sink that drains an async iterable into it. `waiters` is the
 * list of pending `source` reads parked on an empty-and-open queue —
 * each sink push and each close call wakes every waiter in order.
 */
function _makeDirection() {
  const queue = [];
  const waiters = [];
  let closed = false;

  const wake = () => { while (waiters.length) waiters.shift()(); };

  return {
    sink: async (src) => {
      for await (const chunk of src) {
        queue.push(chunk);
        wake();
      }
      closed = true;
      wake();
    },
    source: (async function* () {
      while (true) {
        while (queue.length > 0) yield queue.shift();
        if (closed) return;
        await new Promise(r => waiters.push(r));
      }
    })(),
  };
}

/**
 * Create a paired client/server stream. Usage:
 *   const { client, server } = createStreamPair();
 *   serverHandler._handleIncomingX(server);        // peer-side
 *   clientHandler.requestXFromPeer(server, { ... });
 */
function createStreamPair() {
  const c2s = _makeDirection();   // client → server
  const s2c = _makeDirection();   // server → client
  return {
    client: { sink: c2s.sink, source: s2c.source, close: () => { } },
    server: { sink: s2c.sink, source: c2s.source, close: () => { } },
  };
}

module.exports = { createStreamPair };
