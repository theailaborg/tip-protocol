/**
 * @file tests/network/framing.test.js
 * @description Unit tests for the shared length-prefix framing helpers
 * (`network/framing.js`) used by `/tip/state-snapshot/1.0.0` and
 * `/tip/sync/1.0.0`.
 *
 * These tests don't need protobuf — they exercise the pure framing
 * machinery against raw byte sequences. Protocol-level tests live in
 * `tests/sync/sync-framing.test.js` and `tests/sync/snapshot-handler.test.js`.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const { frame, parseLengthPrefixedFrames, readAllFrames } = require(path.join(SRC, "network", "framing"));

describe("frame(payload)", () => {
  test("prepends a 4-byte big-endian length prefix", () => {
    const body = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    const framed = frame(body);
    expect(framed.length).toBe(4 + body.length);
    expect(framed.readUIntBE(0, 4)).toBe(body.length);
    expect(framed.subarray(4).toString("hex")).toBe("deadbeef");
  });

  test("empty payload produces a 4-byte prefix followed by nothing", () => {
    const framed = frame(Buffer.alloc(0));
    expect(framed.length).toBe(4);
    expect(framed.readUIntBE(0, 4)).toBe(0);
  });

  test("accepts Uint8Array as well as Buffer", () => {
    const u8 = new Uint8Array([1, 2, 3]);
    const framed = frame(u8);
    expect(framed.readUIntBE(0, 4)).toBe(3);
    expect(Buffer.from(framed.subarray(4)).toString("hex")).toBe("010203");
  });
});

describe("parseLengthPrefixedFrames(buf)", () => {
  test("splits a single-frame buffer into one frame", () => {
    const f = frame(Buffer.from([0xaa, 0xbb]));
    const frames = parseLengthPrefixedFrames(f);
    expect(frames).toHaveLength(1);
    expect(frames[0].toString("hex")).toBe("aabb");
  });

  test("splits multiple concatenated frames", () => {
    const a = frame(Buffer.from([0x01]));
    const b = frame(Buffer.from([0x02, 0x03]));
    const c = frame(Buffer.from([0x04, 0x05, 0x06]));
    const frames = parseLengthPrefixedFrames(Buffer.concat([a, b, c]));
    expect(frames).toHaveLength(3);
    expect(frames[0].toString("hex")).toBe("01");
    expect(frames[1].toString("hex")).toBe("0203");
    expect(frames[2].toString("hex")).toBe("040506");
  });

  test("empty buffer returns empty array (no frames)", () => {
    expect(parseLengthPrefixedFrames(Buffer.alloc(0))).toEqual([]);
  });

  test("rejects buffer with incomplete length prefix", () => {
    const bad = Buffer.from([0x00, 0x00, 0x00]);  // 3 bytes, need 4
    expect(() => parseLengthPrefixedFrames(bad)).toThrow(/truncated frame/);
  });

  test("rejects buffer with length-prefix claiming more bytes than present", () => {
    const len = Buffer.alloc(4);
    len.writeUIntBE(100, 0, 4);
    const truncated = Buffer.concat([len, Buffer.from([0xaa])]);  // claims 100 bytes, has 1
    expect(() => parseLengthPrefixedFrames(truncated)).toThrow(/truncated frame body/);
  });

  test("rejects frame larger than NETWORK.SNAPSHOT_MAX_FRAME_BYTES (hostile-peer guard)", () => {
    // Default max is 16 MB. Construct a prefix claiming 17 MB.
    const len = Buffer.alloc(4);
    len.writeUIntBE(17 * 1024 * 1024, 0, 4);
    const bad = Buffer.concat([len, Buffer.alloc(10)]);
    expect(() => parseLengthPrefixedFrames(bad)).toThrow(/frame exceeds max size/);
  });

  test("round-trip: frame() then parseLengthPrefixedFrames recovers exact bytes", () => {
    const payloads = [
      Buffer.from("hello world"),
      Buffer.from([0xff, 0x00, 0xff]),
      Buffer.alloc(1000).fill(0x42),
    ];
    const buf = Buffer.concat(payloads.map(frame));
    const recovered = parseLengthPrefixedFrames(buf);
    expect(recovered).toHaveLength(payloads.length);
    for (let i = 0; i < payloads.length; i++) {
      expect(Buffer.compare(recovered[i], payloads[i])).toBe(0);
    }
  });
});

describe("readAllFrames(stream)", () => {
  test("consumes a libp2p-style stream.source and returns parsed frames", async () => {
    const a = frame(Buffer.from("a"));
    const b = frame(Buffer.from("bb"));
    const c = frame(Buffer.from("ccc"));

    // Split chunks across frame boundaries to exercise Buffer.concat path.
    const fakeStream = {
      source: (async function* () {
        yield Buffer.concat([a, b.subarray(0, 2)]);
        yield b.subarray(2);
        yield c;
      })(),
    };

    const frames = await readAllFrames(fakeStream);
    expect(frames).toHaveLength(3);
    expect(frames[0].toString()).toBe("a");
    expect(frames[1].toString()).toBe("bb");
    expect(frames[2].toString()).toBe("ccc");
  });

  test("empty stream returns empty array", async () => {
    const fakeStream = { source: (async function* () { })() };
    expect(await readAllFrames(fakeStream)).toEqual([]);
  });

  test("propagates the parse error on truncated stream", async () => {
    const partial = Buffer.alloc(3);  // incomplete length prefix
    const fakeStream = {
      source: (async function* () { yield partial; })(),
    };
    await expect(readAllFrames(fakeStream)).rejects.toThrow(/truncated frame/);
  });
});
