/**
 * @file tests/sync/snapshot-download-bounds.test.js
 * @description #94 + #132: the joiner's streaming snapshot download must be
 * bounded.
 *
 * `_boundedFrameStream` wraps the streaming frame parser with a total-byte cap
 * AND an overall deadline, so a hostile or buggy peer can't OOM the joiner
 * (flood) or hang it in `syncing` forever (silence / slow-trickle). On breach
 * it aborts the stream and the generator throws, failing the fetch so the
 * joiner retries another peer. Bounds are parameters here so the guard is
 * exercised directly; the receive path wires in SNAPSHOT_DOWNLOAD.MAX_*.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const PC = require(path.resolve(__dirname, "../../../shared/protocol-constants"));
const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
beforeAll(() => PC.init(getGenesisPayload().protocol_constants));

const { _boundedFrameStream } = require("../../src/sync/snapshot-handler");
const { frame } = require("../../src/network/framing");

async function collect(gen) {
  const out = [];
  for await (const f of gen) out.push(Buffer.from(f));
  return out;
}

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

// A slow-but-steady peer: yields each chunk after `gapMs`. Total transfer time
// can exceed the stall window while every individual gap stays under it.
function slowStream(chunks, gapMs) {
  return {
    source: (async function* () {
      for (const c of chunks) { await new Promise(r => setTimeout(r, gapMs)); yield c; }
    })(),
    abort() { },
    close() { },
  };
}

describe("#94/#132 streaming snapshot download is bounded (byte cap + stall timeout)", () => {
  test("yields each framed message for a normal stream, tallying bytes", async () => {
    const wire = Buffer.concat([frame(Buffer.from("ab")), frame(Buffer.from("cdef"))]);
    let lastTotal = 0;
    const frames = await collect(
      _boundedFrameStream(streamFrom([wire]), 1024, 1000, (t) => { lastTotal = t; }),
    );
    expect(frames.map(f => f.toString())).toEqual(["ab", "cdef"]);
    expect(lastTotal).toBe(wire.length);
  });

  test("throws when total bytes exceed the cap (flood guard)", async () => {
    // 120 bytes against a 100-byte cap — the cap trips before any frame parses.
    await expect(
      collect(_boundedFrameStream(streamFrom([Buffer.alloc(120)]), 100, 1000)),
    ).rejects.toThrow(/cap/);
  });

  test("rejects (does not hang) when the peer goes silent past the stall window", async () => {
    // 80 ms stall window: a never-yielding stream must reject ~80 ms later, not
    // hang until the jest timeout. That it rejects at all proves it didn't hang.
    await expect(
      collect(_boundedFrameStream(silentStream(), 1024, 80)),
    ).rejects.toThrow(/stall/);
  });

  test("does NOT trip on a slow-but-steady stream whose TOTAL time exceeds the window", async () => {
    // 5 frames, 20 ms apart = ~100 ms total, well past the 60 ms stall window,
    // but no single gap approaches it. A fixed total-deadline would wrongly abort
    // this; the stall timer must let it finish. This is the auto-scaling property:
    // any snapshot size is fine as long as data keeps flowing.
    const wire = frame(Buffer.from("x"));
    const frames = await collect(
      _boundedFrameStream(slowStream([wire, wire, wire, wire, wire], 20), 1024, 60),
    );
    expect(frames.length).toBe(5);
  });
});
