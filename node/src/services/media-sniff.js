/**
 * @file @tip-protocol/node/src/services/media-sniff.js
 * @description Keeps an upload's first and last bytes for
 * media-upload.detectMime while the file streams through, without buffering
 * it. The tail is kept only for ZIP files (documents are told apart by the
 * central directory at the end), as a chunk ring bounded by
 * MEDIA_SNIFF_TAIL_BYTES plus one chunk.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { MEDIA_SNIFF_HEAD_BYTES, MEDIA_SNIFF_TAIL_BYTES } = require("../../../shared/constants");

const ZIP_LOCAL_SIG = 0x04034b50;

function createMediaSniffer({ headBytes = MEDIA_SNIFF_HEAD_BYTES, tailBytes = MEDIA_SNIFF_TAIL_BYTES } = {}) {
  const headChunks = [];
  let headLen = 0;
  let headCache = null;
  const tailChunks = [];
  let tailLen = 0;
  let zip = null;

  function push(chunk) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (headLen < headBytes) {
      const take = buf.subarray(0, headBytes - headLen);
      headChunks.push(take);
      headLen += take.length;
      headCache = null;
    }
    if (zip === null && headLen >= 4) zip = head().readUInt32LE(0) === ZIP_LOCAL_SIG;
    if (zip) {
      tailChunks.push(buf);
      tailLen += buf.length;
      while (tailChunks.length > 1 && tailLen - tailChunks[0].length >= tailBytes) {
        tailLen -= tailChunks.shift().length;
      }
    }
  }

  function head() {
    if (headCache === null) headCache = Buffer.concat(headChunks, headLen);
    return headCache;
  }

  // Last bytes of a ZIP (null for anything else, where the head decides).
  function tail() {
    if (!zip) return null;
    const all = Buffer.concat(tailChunks, tailLen);
    return all.length > tailBytes ? all.subarray(all.length - tailBytes) : all;
  }

  function headLength() {
    return headLen;
  }

  function isZip() {
    return zip === true;
  }

  return { push, head, tail, headLength, isZip };
}

module.exports = { createMediaSniffer };
