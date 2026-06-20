"use strict";

// Perceptual ingest, step (a): turn a tip-content-fingerprint output into the rows
// the off-DAG perceptual index stores. Index keys are derived with the PACKAGE
// (text.lshBands / image.indexChunks) so INGEST and QUERY stay in lockstep with
// the hash format (versioned by the modality PROFILE). Pure, no I/O: the caller
// writes the returned rows through the dag store methods (step b).
//
// Returns { fingerprint, bands, codes, landmarks, landmarkCount }:
//   fingerprint -> one perceptual_fingerprint row (source of truth)
//   bands       -> minhash_band rows   (text LSH)
//   codes       -> phash_code rows     (image/video MIH)
//   landmarks   -> [{ hash, t }]       (audio inverted index; clip_id assigned at write)
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
  if (!fp || !fp.kind) {
    throw new Error("perceptual ingest: fingerprint missing kind");
  }
  // Reject tier: the package couldn't fingerprint this component (corrupt /
  // empty / unsupported media). It carries no profile/minhash/pdq/features/
  // landmarks, so there are no keys to derive — skip it entirely (no row, no
  // index entry). Must precede the profile check below.
  if (fp.tier === "reject") return null;
  if (!fp.profile) {
    throw new Error("perceptual ingest: fingerprint missing profile");
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
  const landmarks = []; // audio: [{ hash, t }] (clip_id assigned at write time)

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
  } else if (fp.kind === "audio") {
    // Index the landmark set as-is. §8.1 lever 2 (cap N/sec, keep loudest peaks)
    // is a future subset-cap here; the full set always lives in `fingerprint`.
    for (const lm of fp.landmarks || []) landmarks.push({ hash: lm.hash, t: lm.t });
  }

  // The clip's FULL landmark count (for the matcher's scoreRatio denom), even if
  // only a subset is indexed.
  const landmarkCount = fp.kind === "audio"
    ? (fp.landmarkCount != null ? fp.landmarkCount : landmarks.length)
    : 0;

  return { fingerprint, bands, codes, landmarks, landmarkCount };
}

// One phash_code row: the metadata + the 16 MIH chunk columns c0..c15.
function phashRow(ctid, profile, modality, frame, ts, quality, pdq) {
  const row = { ctid, profile, modality, frame, ts, quality, pdq };
  const chunks = indexChunks(pdq);
  for (let i = 0; i < chunks.length; i++) row["c" + i] = chunks[i];
  return row;
}

// Step (b): derive the rows then write them through the dag store. async because
// audio needs the store-assigned surrogate clip_id before writing landmark rows
// (an await on the KnexAdapter path; a no-op await on the sync stores). The other
// writes stay fire-and-forget. Off-DAG / advisory: not mirrored, not in the root.
async function ingestFingerprint(dag, fp, opts) {
  const rows = buildIngestRows(fp, opts);
  if (!rows) return { skipped: true, bands: 0, codes: 0, landmarks: 0 }; // reject tier
  const { fingerprint, bands, codes, landmarks, landmarkCount } = rows;
  dag.savePerceptualFingerprint(fingerprint);
  if (bands.length) dag.saveMinhashBands(bands);
  if (codes.length) dag.savePhashCodes(codes);
  if (landmarks.length) {
    const clipId = await dag.getOrCreateAudioClip(fingerprint.ctid, fingerprint.component_idx, landmarkCount);
    dag.saveAudioLandmarks(
      landmarks.map((l) => ({ profile: fingerprint.profile, hash: l.hash, clip_id: clipId, t: l.t })),
    );
  }
  return { fingerprint, bands: bands.length, codes: codes.length, landmarks: landmarks.length };
}

module.exports = { buildIngestRows, ingestFingerprint };
