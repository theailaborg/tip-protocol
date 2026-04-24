/**
 * @file @tip-protocol/node/src/network/framing.js
 * @description Length-prefixed framing helpers for TIP stream protocols.
 *
 * Used by:
 *   - /tip/state-snapshot/1.0.0   (§14 snapshot sync)
 *   - /tip/sync/1.0.0             (§19 cert sync — post-framing refactor)
 *
 * Wire format (per frame):
 *   [N bytes big-endian length][body bytes]
 *
 * Width of the length prefix comes from genesis
 * (`NETWORK.SNAPSHOT_LENGTH_PREFIX_BYTES`, default 4 → max 4 GB per
 * frame). Max individual frame size comes from genesis
 * (`NETWORK.SNAPSHOT_MAX_FRAME_BYTES`, default 16 MB) — a hard cap
 * against hostile peers trying to exhaust our memory with one massive
 * frame. Both senders and receivers honor the cap.
 *
 * Rationale vs alternatives:
 *   - Native protobuf "delimited" framing exists in some libraries but
 *     not in protobufjs. Hand-rolled length-prefix is portable.
 *   - varint framing would save a few bytes per frame but adds a state
 *     machine to the reader. 4-byte big-endian is simpler and 99.99%
 *     of our frames will be < 4 GB anyway.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { NETWORK } = require("../../../shared/protocol-constants");

/**
 * Wrap a payload in a big-endian length prefix. Returned buffer is a
 * single contiguous Buffer suitable for handing to `stream.sink`.
 *
 * @param {Buffer|Uint8Array} payload
 * @returns {Buffer}
 */
function frame(payload) {
  const widthBytes = NETWORK.SNAPSHOT_LENGTH_PREFIX_BYTES;
  const len = Buffer.allocUnsafe(widthBytes);
  len.writeUIntBE(payload.length, 0, widthBytes);
  return Buffer.concat([len, Buffer.from(payload)]);
}

/**
 * Parse a buffer containing zero or more length-prefixed frames.
 * Throws on truncated input or any frame exceeding
 * `NETWORK.SNAPSHOT_MAX_FRAME_BYTES` (hostile-peer guard).
 *
 * @param {Buffer} buf
 * @returns {Buffer[]}
 */
function parseLengthPrefixedFrames(buf) {
  const widthBytes = NETWORK.SNAPSHOT_LENGTH_PREFIX_BYTES;
  const maxFrameBytes = NETWORK.SNAPSHOT_MAX_FRAME_BYTES;
  const frames = [];
  let offset = 0;

  while (offset < buf.length) {
    if (offset + widthBytes > buf.length) {
      throw new Error(`truncated frame: ${buf.length - offset} bytes remain at offset ${offset}, need ${widthBytes}`);
    }
    const len = buf.readUIntBE(offset, widthBytes);
    if (len > maxFrameBytes) {
      throw new Error(`frame exceeds max size: ${len} > ${maxFrameBytes} at offset ${offset}`);
    }
    const start = offset + widthBytes;
    const end = start + len;
    if (end > buf.length) {
      throw new Error(`truncated frame body: need ${len} bytes at offset ${start}, have ${buf.length - start}`);
    }
    frames.push(buf.subarray(start, end));
    offset = end;
  }
  return frames;
}

/**
 * Read every chunk off a libp2p stream.source into a single Buffer,
 * then split into length-prefixed frames. Memory-bounded by the
 * caller's knowledge of max expected bytes (framing.js doesn't enforce
 * a total-stream cap; that's caller-specific).
 *
 * @param {{ source: AsyncIterable }} stream  libp2p stream
 * @returns {Promise<Buffer[]>}
 */
async function readAllFrames(stream) {
  const chunks = [];
  for await (const chunk of stream.source) {
    chunks.push(chunk.subarray ? chunk.subarray() : chunk);
  }
  if (chunks.length === 0) return [];
  return parseLengthPrefixedFrames(Buffer.concat(chunks));
}

module.exports = { frame, parseLengthPrefixedFrames, readAllFrames };
