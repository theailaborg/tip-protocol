/**
 * @file tests/sync/snapshot-download-bounds.test.js
 * @description #94: the joiner's snapshot download must be bounded.
 *
 * snapshot-handler `_readBoundedStream` reads a peer's snapshot off the stream
 * into one Buffer under a total-byte cap AND an overall deadline, so a hostile
 * or buggy peer can't OOM the joiner (flood) or hang it in `syncing` forever
 * (silence / slow-trickle). On breach it aborts the stream and throws, failing
 * the fetch so the joiner retries another peer.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { _readBoundedStream } = require("../../src/sync/snapshot-handler");

// A normal stream that yields the given chunks then completes.
function streamFrom(chunks) {
  return {
    source: (async function* () { for (const c of chunks) yield c; })(),
    abort() { },
    close() { },
  };
}

// A stream whose read never resolves until the consumer aborts it (a peer that
// opens the stream then goes silent). abort() rejects the pending read.
function silentStream() {
  let rejectNext = null;
  return {
    source: {
      [Symbol.asyncIterator]() {
        return { next() { return new Promise((_, reject) => { rejectNext = reject; }); } };
      },
    },
    abort(err) { if (rejectNext) rejectNext(err || new Error("aborted")); },
    close() { if (rejectNext) rejectNext(new Error("closed")); },
  };
}

describe("#94 snapshot download is bounded (byte cap + deadline)", () => {
  test("returns the concatenated body for a normal stream", async () => {
    const body = await _readBoundedStream(
      streamFrom([Buffer.from("ab"), Buffer.from("cd")]), 1024, 1000,
    );
    expect(body.toString()).toBe("abcd");
  });

  test("throws when total bytes exceed the cap (flood guard)", async () => {
    const flood = [Buffer.alloc(60), Buffer.alloc(60)]; // 120 bytes vs a 100 cap
    await expect(_readBoundedStream(streamFrom(flood), 100, 1000)).rejects.toThrow(/cap/);
  });

  test("rejects (does not hang) when the peer goes silent past the deadline", async () => {
    // 80 ms deadline: a never-yielding stream must reject ~80 ms later, not hang
    // until the jest timeout. That it rejects at all is the proof it didn't hang.
    await expect(_readBoundedStream(silentStream(), 1024, 80)).rejects.toThrow();
  });
});
