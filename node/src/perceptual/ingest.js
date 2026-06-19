"use strict";

// Perceptual ingest, step (a): turn a tip-content-fingerprint output into the rows
// the off-DAG perceptual index stores. Index keys are derived with the PACKAGE
// (text.lshBands / image.indexChunks) so INGEST and QUERY stay in lockstep with
// the hash format (versioned by the modality PROFILE). Pure, no I/O: the caller
// writes the returned rows through the dag store methods (step b).
//
// Returns { fingerprint, bands, codes }:
//   fingerprint -> one perceptual_fingerprint row (source of truth)
//   bands       -> minhash_band rows   (text LSH; empty for image/video)
//   codes       -> phash_code rows     (image/video MIH; empty for text)
// (audio landmarks use a different index shape, added later.)
//
// See my-notes/PERCEPTUAL_INDEX_PLAN.md.

// Import ONLY the pure key-derivation helpers, not the package root: the root
// pulls in the fingerprint-COMPUTE deps (@noble/hashes ESM, wasm decoders) that
// the node never needs and that jest can't `require`. lsh.js / mih.js are
// dependency-free. (TODO: have the package expose a lightweight `keys` entry so
// this isn't a deep import.)
const { lshBands } = require("tip-content-fingerprint/src/text/lsh");
const { indexChunks } = require("tip-content-fingerprint/src/image/mih");
const PKG_VERSION = require("tip-content-fingerprint/package.json").version;

function buildIngestRows(fp, opts) {
  opts = opts || {};
  if (!fp || !fp.kind || !fp.profile) {
    throw new Error("perceptual ingest: fingerprint missing kind/profile");
  }
  const ctid = opts.ctid;
  if (!ctid) throw new Error("perceptual ingest: ctid is required");
  const componentIdx = opts.componentIdx != null ? opts.componentIdx : 0;
  const createdAt = opts.createdAt != null ? opts.createdAt : 0;

  const fingerprint = {
    ctid,
    component_idx: componentIdx,
    modality: fp.kind,
    profile: fp.profile,
    pipeline: JSON.stringify({ package: PKG_VERSION, profile: fp.profile }),
    quality: fp.quality != null ? fp.quality : null, // per-frame quality lives on codes for video
    fingerprint: JSON.stringify(fp),
    created_at: createdAt,
  };

  const bands = [];
  const codes = [];

  if (fp.kind === "text") {
    // Only char-tier (MinHash) texts get LSH bands; micro-tier is exact-match.
    if (fp.tier === "char" && Array.isArray(fp.minhash)) {
      const bandHashes = lshBands(fp.minhash);
      for (let band_idx = 0; band_idx < bandHashes.length; band_idx++) {
        bands.push({ profile: fp.profile, band_idx, band_hash: bandHashes[band_idx], ctid });
      }
    }
  } else if (fp.kind === "image") {
    codes.push(phashRow(ctid, fp.profile, "image", null, null, fp.quality, fp.pdq));
  } else if (fp.kind === "video") {
    for (const f of fp.features || []) {
      codes.push(phashRow(ctid, fp.profile, "video", f.frame, f.timestamp, f.quality, f.pdq));
    }
  }

  return { fingerprint, bands, codes };
}

// One phash_code row: the metadata + the 16 MIH chunk columns c0..c15.
function phashRow(ctid, profile, modality, frame, ts, quality, pdq) {
  const row = { ctid, profile, modality, frame, ts, quality, pdq };
  const chunks = indexChunks(pdq);
  for (let i = 0; i < chunks.length; i++) row["c" + i] = chunks[i];
  return row;
}

module.exports = { buildIngestRows };
