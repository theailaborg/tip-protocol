/**
 * @file tests/network/gossip-backlog-integration.test.js
 * @description Two real libp2p + gossipsub nodes on localhost. The subscriber
 * stays connected but never reads its gossip stream, which is what a halted
 * partner node did on mainnet (2026-10-03). Without a cap the publisher's
 * per-peer outbound queue grows with every message; with the cap it stays
 * bounded and the backlog watch flags the peer for redial.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { createOutboundBacklog } = require(path.resolve(__dirname, "../../src/network/outbound-backlog"));

jest.setTimeout(90_000);

const TOPIC = "tip-backlog-test";
const MSG_BYTES = 64 * 1024;
const CAP = 1024 * 1024;   // small cap so the test finishes fast; semantics identical to the 8 MiB default

// Loaded once: jest's ESM loader does not tolerate the first dynamic import racing inside a test.
let mods;
beforeAll(async () => {
  const { createLibp2p } = await import("libp2p");
  const { tcp } = await import("@libp2p/tcp");
  const { noise } = await import("@chainsafe/libp2p-noise");
  const { yamux } = await import("@chainsafe/libp2p-yamux");
  const { gossipsub } = await import("@chainsafe/libp2p-gossipsub");
  const { identify } = await import("@libp2p/identify");
  mods = { createLibp2p, tcp, noise, yamux, gossipsub, identify };
});

async function makePair({ cap }) {
  const { createLibp2p, tcp, noise, yamux, gossipsub, identify } = mods;
  const mk = () => createLibp2p({
    addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: {
      identify: identify(),
      pubsub: gossipsub({
        emitSelf: false,
        allowPublishToZeroTopicPeers: true,
        floodPublish: true,
        ...(cap ? { maxOutboundBufferSize: cap } : {}),
      }),
    },
  });
  const publisher = await mk();
  const stalled = await mk();
  // The stall: the subscriber accepts every inbound gossip stream and never reads it.
  stalled.services.pubsub.pipePeerReadStream = () => new Promise(() => {});
  await publisher.start();
  await stalled.start();
  stalled.services.pubsub.subscribe(TOPIC);
  publisher.services.pubsub.subscribe(TOPIC);
  await publisher.dial(stalled.getMultiaddrs()[0]);
  // Wait until the publisher has an outbound gossip stream to the subscriber and knows it is subscribed.
  const id = stalled.peerId.toString();
  for (let i = 0; i < 100; i++) {
    const subs = publisher.services.pubsub.getSubscribers(TOPIC).map(String);
    if (publisher.services.pubsub.streamsOutbound.has(id) && subs.includes(id)) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  expect(publisher.services.pubsub.streamsOutbound.has(id)).toBe(true);
  return { publisher, stalled, id, stop: () => Promise.all([publisher.stop(), stalled.stop()]) };
}

function queuedBytes(pub, id) {
  const os = pub.services.pubsub.streamsOutbound.get(id);
  return os ? os.pushable.readableLength : 0;
}

async function publishMany(pub, n) {
  const payload = new Uint8Array(MSG_BYTES).fill(7);
  for (let i = 0; i < n; i++) {
    payload[0] = i & 0xff; payload[1] = (i >> 8) & 0xff;
    await pub.services.pubsub.publish(TOPIC, payload);
  }
}

function offHeapMB() {
  const m = process.memoryUsage();
  return Math.round((m.external + m.arrayBuffers) / 1048576);
}

describe("process memory towards a peer that stops reading", () => {
  const OFFERED = 128;   // messages of 64 KiB = 8 MiB per round

  test("library default: off-heap memory climbs with every megabyte offered to the stalled peer", async () => {
    const pair = await makePair({ cap: 0 });
    try {
      const before = offHeapMB();
      await publishMany(pair.publisher, OFFERED);
      await publishMany(pair.publisher, OFFERED);
      await publishMany(pair.publisher, OFFERED);   // 24 MiB offered
      const grown = offHeapMB() - before;
      expect(grown).toBeGreaterThanOrEqual(16);     // most of it is still held for the peer
    } finally { await pair.stop(); }
  });

  test("with the cap: the same 24 MiB offered leaves off-heap memory near flat", async () => {
    const pair = await makePair({ cap: CAP });
    try {
      const before = offHeapMB();
      await publishMany(pair.publisher, OFFERED);
      await publishMany(pair.publisher, OFFERED);
      await publishMany(pair.publisher, OFFERED);
      const grown = offHeapMB() - before;
      expect(grown).toBeLessThanOrEqual(4);          // at most the cap plus muxer window
    } finally { await pair.stop(); }
  });
});

describe("gossipsub outbound queue towards a peer that stops reading", () => {
  test("library default: the queue grows with every message, nothing bounds it", async () => {
    const pair = await makePair({ cap: 0 });
    try {
      await publishMany(pair.publisher, 64);   // 4 MiB offered
      const q = queuedBytes(pair.publisher, pair.id);
      // Everything past the muxer window is still held for the peer: well over what the cap would allow.
      expect(q).toBeGreaterThan(2 * CAP);
      await publishMany(pair.publisher, 64);   // 8 MiB offered: the queue keeps growing
      expect(queuedBytes(pair.publisher, pair.id)).toBeGreaterThan(q + CAP);
    } finally { await pair.stop(); }
  });

  test("with the cap: the queue never exceeds the cap plus one message and the watch flags the peer", async () => {
    const pair = await makePair({ cap: CAP });
    const watch = createOutboundBacklog({ limitBytes: CAP, strikes: 2 });
    try {
      await publishMany(pair.publisher, 64);
      const q = queuedBytes(pair.publisher, pair.id);
      expect(q).toBeGreaterThan(0);
      expect(q).toBeLessThanOrEqual(CAP + MSG_BYTES + 1024);
      // Two consecutive peer-health samples over the cap -> redial decision.
      expect(watch.observe(pair.id, q)).toBe(false);
      expect(watch.observe(pair.id, queuedBytes(pair.publisher, pair.id))).toBe(true);
      // Publishing keeps working for the publisher: messages beyond the cap are dropped for that peer, not queued.
      await publishMany(pair.publisher, 32);
      expect(queuedBytes(pair.publisher, pair.id)).toBeLessThanOrEqual(CAP + MSG_BYTES + 1024);
    } finally { await pair.stop(); }
  });
});
