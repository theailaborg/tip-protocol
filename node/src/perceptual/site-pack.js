"use strict";

// Checks a fingerprint pack against its signed SITE_SNAPSHOT record. Pure and
// synchronous: the node runs it on the pack worker thread, tests call it directly.

const web = require("tip-content-fingerprint/src/web");
const { shake256 } = require("../../../shared/crypto");

function packError(message, code, permanent = false) {
  const e = new Error(message);
  e.code = code;
  e.permanent = permanent;
  return e;
}

/**
 * Header, page count and Merkle root of pack bytes whose hash is already
 * known to match. Returns the leaf pages. A pack with the right hash but the
 * wrong content can never be fixed by a retry, so those failures are permanent.
 */
function checkPackBody(record, bytes) {
  let pack;
  try {
    pack = web.readPack(bytes);
  } catch (err) {
    throw packError(`unreadable pack: ${err.message}`, "pack_unreadable", true);
  }
  const { header, pages } = pack;
  if (header.domain !== record.domain || header.seq !== record.seq) {
    throw packError(`pack is for ${header.domain} seq ${header.seq}, not ${record.domain} seq ${record.seq}`, "pack_header_mismatch", true);
  }
  const leaves = pages.filter((p) => !p.skipped);
  if (leaves.length !== record.page_count) {
    throw packError(`pack has ${leaves.length} pages, the record ${record.page_count}`, "pack_root_mismatch", true);
  }
  // Over every leaf line, off-site ones included: the owner signed all of them.
  // packRoot also refuses a URL that appears twice.
  let root;
  try {
    root = web.packRoot(pages);
  } catch (err) {
    throw packError(`pack pages do not form a tree: ${err.message}`, "pack_root_mismatch", true);
  }
  if (root !== record.root) throw packError("pack pages do not give the record's root", "pack_root_mismatch", true);
  return leaves;
}

// Proof steps stored as one string: "l" or "r" then the sibling hash, per level.
function encodeProof(proof) {
  return proof.map((s) => (s.side === "left" ? "l" : "r") + s.hash).join("");
}

function decodeProof(text) {
  if (typeof text !== "string" || text.length % 65 !== 0) return null;
  const out = [];
  for (let i = 0; i < text.length; i += 65) {
    const side = text[i] === "l" ? "left" : (text[i] === "r" ? "right" : null);
    if (!side) return null;
    out.push({ side, hash: text.slice(i + 1, i + 65) });
  }
  return out;
}

/**
 * Every leaf's Merkle proof from one pass over the tree, so a page read never
 * rebuilds it. levels and byCodePoint come from the pinned library copy, and
 * each proof is checked with the public verifyPage; one that fails is null.
 */
function pageProofs(record, leaves) {
  const { levels, byCodePoint } = web._internals;
  const sorted = leaves.map((p, i) => ({ i, url: p.url, leaf: web.leafHash(p.url, p.text_hash) }))
    .sort((a, b) => byCodePoint(a.url, b.url));
  const lv = levels(sorted.map((x) => x.leaf));
  const out = new Array(leaves.length).fill(null);
  sorted.forEach((x, pos) => {
    const proof = [];
    let idx = pos;
    for (let l = 0; l < lv.length - 1; l++) {
      const sib = idx ^ 1;
      if (sib < lv[l].length) proof.push({ side: sib < idx ? "left" : "right", hash: lv[l][sib] });
      idx >>= 1;
    }
    const page = leaves[x.i];
    if (web.verifyPage(page.url, page.text_hash, proof, record.root)) out[x.i] = encodeProof(proof);
  });
  return out;
}

function checkPack(record, bytes) {
  if (shake256(bytes) !== record.pack_hash) throw packError("pack bytes do not match pack_hash", "pack_hash_mismatch");
  return checkPackBody(record, bytes);
}

module.exports = { checkPack, checkPackBody, pageProofs, encodeProof, decodeProof, packError };
