/**
 * @file tests/network/stream-frames.test.js
 * @description streamFrames (#132 streaming snapshot parser): yields each
 * complete length-prefixed frame as bytes arrive, reassembling frames split
 * across arbitrary network-chunk boundaries, holding only the remainder.
 * Must be byte-identical to parseLengthPrefixedFrames for any chunking.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const PC = require(path.resolve(__dirname, "../../../shared/protocol-constants"));
const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
beforeAll(() => PC.init(getGenesisPayload().protocol_constants));

const { frame, parseLengthPrefixedFrames, streamFrames } =
  require(path.resolve(__dirname, "../../src/network/framing"));

async function collect(gen) {
  const out = [];
  for await (const f of gen) out.push(Buffer.from(f));
  return out;
}

// async source that yields `chunks` one at a time
function source(chunks) {
  return (async function* () { for (const c of chunks) yield c; })();
}

// deterministic PRNG for reproducible chunk-boundary fuzz
function lcg(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }

function makeFrames(sizes) {
  return sizes.map((n, i) => frame(Buffer.from(String.fromCharCode(65 + (i % 26)).repeat(n))));
}

describe("streamFrames", () => {
  test("multiple frames delivered in one chunk", async () => {
    const frames = makeFrames([3, 7, 1, 20]);
    const wire = Buffer.concat(frames);
    const got = await collect(streamFrames(source([wire])));
    expect(got.map(b => b.toString())).toEqual(
      parseLengthPrefixedFrames(wire).map(b => b.toString()));
  });

  test("one frame split across many chunks (byte-by-byte)", async () => {
    const wire = Buffer.concat(makeFrames([50]));
    const chunks = [...wire].map(b => Buffer.from([b]));   // 1 byte per chunk
    const got = await collect(streamFrames(source(chunks)));
    expect(got.length).toBe(1);
    expect(got[0].length).toBe(50);
  });

  test("length prefix itself split across a chunk boundary", async () => {
    const wire = Buffer.concat(makeFrames([100]));
    // split mid-length-prefix (prefix is 4 bytes)
    const got = await collect(streamFrames(source([wire.subarray(0, 2), wire.subarray(2)])));
    expect(got.length).toBe(1);
    expect(got[0].length).toBe(100);
  });

  test("PROPERTY: identical to parseLengthPrefixedFrames for random chunkings", async () => {
    const rnd = lcg(2026);
    for (let iter = 0; iter < 40; iter++) {
      const sizes = Array.from({ length: 1 + Math.floor(rnd() * 8) }, () => Math.floor(rnd() * 300));
      const wire = Buffer.concat(makeFrames(sizes));
      // random chunk boundaries
      const chunks = [];
      let off = 0;
      while (off < wire.length) {
        const step = 1 + Math.floor(rnd() * 64);
        chunks.push(wire.subarray(off, off + step));
        off += step;
      }
      const streamed = (await collect(streamFrames(source(chunks)))).map(b => b.toString("hex"));
      const parsed = parseLengthPrefixedFrames(wire).map(b => b.toString("hex"));
      expect(streamed).toEqual(parsed);
    }
  });

  test("empty stream yields nothing", async () => {
    expect(await collect(streamFrames(source([])))).toEqual([]);
  });

  test("stream ending mid-frame throws", async () => {
    const wire = Buffer.concat(makeFrames([100]));
    const truncated = wire.subarray(0, 40); // header says 100, only 36 body bytes
    await expect(collect(streamFrames(source([truncated])))).rejects.toThrow(/mid-frame/);
  });

  test("frame length exceeding the max cap throws", async () => {
    const bad = Buffer.alloc(4);
    bad.writeUIntBE(999_999_999, 0, 4); // absurd length prefix
    await expect(collect(streamFrames(source([bad])))).rejects.toThrow(/exceeds max size/);
  });

  test("onBytes reports running total (for the download cap)", async () => {
    const wire = Buffer.concat(makeFrames([10, 10]));
    let last = 0;
    await collect(streamFrames(source([wire.subarray(0, 8), wire.subarray(8)]), (_add, total) => { last = total; }));
    expect(last).toBe(wire.length);
  });
});
