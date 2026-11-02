"use strict";

// One text LSH index per band scheme, each under its own minhash_band profile
// ("cf-text-3" for b32r4, "cf-text-3/<scheme>" otherwise), so a node can build,
// shadow or switch schemes without touching the index that answers.

const { performance } = require("perf_hooks");
const { LSH_SCHEMES, lshBands } = require("tip-content-fingerprint/src/text/lsh");
const { TEXT_LSH } = require("../../../shared/constants");
const { nowMs } = require("../../../shared/time");
const { log } = require("../logger");

const LEGACY_SCHEME = "b32r4";
const META_PREFIX = "text_lsh_index:";
const STATE = Object.freeze({ COMPLETE: "complete", BUILDING: "building", STALE: "stale" });
const MS_BUCKETS = [1, 2, 5, 10, 25, 50, 100, 150, 250, 500, 1000, 2500];
const CANDIDATE_BUCKETS = [0, 10, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
const NOT_READY_LOG_EVERY_MS = 60_000;

let _answer = TEXT_LSH.DEFAULT_SCHEME;
let _shadow = null;
const _byDag = new WeakMap();   // dag -> Map(scheme -> status)
const _stats = new Map();       // "scheme|role" -> lookup stats
const _warnedAt = new WeakMap(); // dag -> last "matching is off" warning

function _checkScheme(name, setting) {
  if (!Object.prototype.hasOwnProperty.call(LSH_SCHEMES, name)) {
    throw new Error(`${setting}: unknown text LSH scheme "${name}" (known: ${Object.keys(LSH_SCHEMES).join(", ")})`);
  }
}

function configure({ scheme, shadow } = {}) {
  const answer = scheme || TEXT_LSH.DEFAULT_SCHEME;
  _checkScheme(answer, "TIP_TEXT_LSH_SCHEME");
  if (shadow) _checkScheme(shadow, "TIP_TEXT_LSH_SHADOW");
  _answer = answer;
  _shadow = shadow && shadow !== answer ? shadow : null;
}

function answerScheme() { return _answer; }
function shadowScheme() { return _shadow; }
function ingestSchemes() { return _shadow ? [_answer, _shadow] : [_answer]; }

function bandProfile(profile, scheme) {
  return scheme === LEGACY_SCHEME ? profile : `${profile}/${scheme}`;
}

function bandRows(fp, ctid, schemes) {
  const rows = [];
  for (const scheme of schemes) {
    const profile = bandProfile(fp.profile, scheme);
    const hashes = lshBands(fp.minhash, { scheme });
    for (let band_idx = 0; band_idx < hashes.length; band_idx++) {
      rows.push({ profile, band_idx, band_hash: hashes[band_idx], ctid });
    }
  }
  return rows;
}

function _statuses(dag) {
  let m = _byDag.get(dag);
  if (!m) { m = new Map(); _byDag.set(dag, m); }
  return m;
}

function _load(dag, scheme) {
  const raw = dag.getConsensusMeta(META_PREFIX + scheme);
  if (raw == null) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function _save(dag, scheme, st) {
  _statuses(dag).set(scheme, st);
  dag.setConsensusMeta(META_PREFIX + scheme, JSON.stringify(st));
}

// b32r4 counts as complete until startup finds otherwise: ingest has always written it.
function isReady(dag, scheme) {
  const st = _statuses(dag).get(scheme);
  if (st) return st.state === STATE.COMPLETE;
  return scheme === LEGACY_SCHEME;
}

function status(dag, scheme) {
  const st = _statuses(dag).get(scheme);
  if (st) return st;
  return scheme === LEGACY_SCHEME ? { state: STATE.COMPLETE } : null;
}

function warnNotReady(dag, scheme) {
  const now = nowMs();
  if (now - (_warnedAt.get(dag) || 0) < NOT_READY_LOG_EVERY_MS) return;
  _warnedAt.set(dag, now);
  const st = status(dag, scheme);
  log.warn(`text near-duplicate matching is OFF: the ${scheme} index is ${st ? st.state : "missing"}`
    + (st && st.texts != null ? ` (${st.texts} texts indexed so far)` : ""));
}

const _yield = () => new Promise((resolve) => setImmediate(resolve));

// Band rows are deterministic per fingerprint and saved ignore-on-conflict, so
// texts ingested meanwhile, or a batch replayed after a restart, are harmless.
async function rebuild(dag, scheme, { resume = null, isStopped = () => false } = {}) {
  const st = resume ? { ...resume, state: STATE.BUILDING }
    : { state: STATE.BUILDING, started_at: nowMs(), after: ["", -1], texts: 0, bands: 0 };
  _save(dag, scheme, st);
  log.notice(`text LSH index ${scheme}: ${resume ? `resuming after ${st.texts} texts` : "building from stored fingerprints"}`);
  const t0 = performance.now();
  while (true) {
    if (isStopped()) return false;
    const rows = await dag.listTextFingerprintsAfter(st.after[0], st.after[1], TEXT_LSH.REBUILD_BATCH_ROWS);
    if (!rows.length) break;
    const bands = [];
    for (const r of rows) {
      let fp;
      try { fp = JSON.parse(r.fingerprint); } catch { continue; }
      if (fp.tier !== "char" || !Array.isArray(fp.minhash)) continue;
      for (const b of bandRows(fp, r.ctid, [scheme])) bands.push(b);
      st.texts++;
    }
    if (bands.length) dag.saveMinhashBands(bands);
    st.bands += bands.length;
    const last = rows[rows.length - 1];
    st.after = [last.ctid, last.component_idx];
    _save(dag, scheme, st);
    // Drain the write queue each batch: a backlog past the persistence guard fail-stops the node.
    await dag.flush();
    await _yield();
  }
  const done = { state: STATE.COMPLETE, started_at: st.started_at, built_at: nowMs(), texts: st.texts, bands: st.bands };
  _save(dag, scheme, done);
  log.notice(`text LSH index ${scheme}: complete, ${done.texts} texts, ${done.bands} bands in ${Math.round(performance.now() - t0)} ms`);
  return true;
}

// Startup check. Indexes the node will not write to are marked stale (they would
// fall behind); each index it will write to is loaded, resumed or rebuilt in the
// background, and answers only once complete.
function start(dag) {
  const idle = { stop() { }, done: Promise.resolve() };
  if (typeof dag.getConsensusMeta !== "function" || typeof dag.listTextFingerprintsAfter !== "function") return idle;
  const want = ingestSchemes();
  for (const scheme of Object.keys(LSH_SCHEMES)) {
    if (want.includes(scheme)) continue;
    const st = _load(dag, scheme);
    if (st ? st.state !== STATE.STALE : scheme === LEGACY_SCHEME) _save(dag, scheme, { state: STATE.STALE, at: nowMs() });
  }
  const todo = [];
  for (const scheme of want) {
    const st = _load(dag, scheme);
    if (!st && scheme === LEGACY_SCHEME) {
      _save(dag, scheme, { state: STATE.COMPLETE, built_at: nowMs(), legacy: true });
    } else if (st && st.state === STATE.COMPLETE) {
      _statuses(dag).set(scheme, st);
    } else {
      const resume = st && st.state === STATE.BUILDING && Array.isArray(st.after) ? st : null;
      _statuses(dag).set(scheme, resume || { state: STATE.BUILDING, texts: 0 });
      todo.push({ scheme, resume });
    }
  }
  if (!todo.length) return idle;
  let stopped = false;
  const done = (async () => {
    for (const t of todo) {
      if (stopped) return;
      await rebuild(dag, t.scheme, { resume: t.resume, isStopped: () => stopped });
    }
  })().catch((err) => log.error(`text LSH index rebuild failed: ${err?.stack || err}`));
  return { stop() { stopped = true; }, done };
}

function _bucketCounts(buckets, value, counts) {
  for (let i = 0; i < buckets.length; i++) if (value <= buckets[i]) counts[i]++;
}

function recordLookup(scheme, role, { ms, candidates, matches }) {
  const key = `${scheme}|${role}`;
  let s = _stats.get(key);
  if (!s) {
    s = { scheme, role, lookups: 0, matches: 0, ms: { counts: MS_BUCKETS.map(() => 0), sum: 0 },
      candidates: { counts: CANDIDATE_BUCKETS.map(() => 0), sum: 0 } };
    _stats.set(key, s);
  }
  s.lookups++;
  s.matches += matches.length;
  s.ms.sum += ms;
  _bucketCounts(MS_BUCKETS, ms, s.ms.counts);
  s.candidates.sum += candidates;
  _bucketCounts(CANDIDATE_BUCKETS, candidates, s.candidates.counts);
}

function statsSnapshot() {
  return { msBuckets: MS_BUCKETS, candidateBuckets: CANDIDATE_BUCKETS, series: [..._stats.values()] };
}

function logShadow(query, answerName, answer, shadowName, shadow) {
  const top = (r) => r.matches.slice(0, 10).map((m) => [m.ctid, Math.round(m.similarity * 1000) / 1000]);
  const one = (r) => ({ candidates: r.candidates, ms: Math.round(r.ms * 10) / 10, matches: top(r) });
  log.info(`text-lsh shadow ${JSON.stringify({ query: query || null, answer: answerName, [answerName]: one(answer), [shadowName]: one(shadow) })}`);
}

module.exports = {
  LEGACY_SCHEME, STATE, configure, answerScheme, shadowScheme, ingestSchemes, bandProfile, bandRows,
  isReady, status, warnNotReady, rebuild, start, recordLookup, statsSnapshot, logShadow,
};
