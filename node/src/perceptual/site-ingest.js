"use strict";

// Off-DAG index of committed site snapshots. For each SITE_SNAPSHOT this node
// fetches the fingerprint pack named by pack_hash, checks it against the signed
// record (hash, header, Merkle root, page count), and indexes its pages so
// similar search and page reads can name "page P of site D, snapshot S".
// Node-local, advisory and rebuildable: nothing here touches consensus state.

const path = require("path");
const { Worker } = require("worker_threads");
const { performance } = require("perf_hooks");
const { PROFILE: IMAGE_PROFILE } = require("tip-content-fingerprint/src/image");
const { shake256, shake256Incremental } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { SITE_INGEST, SITE_SNAPSHOT } = require("../../../shared/constants");
const { siteKey, liveBindingFor } = require("../validators/business-rules");
const { buildIngestRows } = require("./ingest");
const { checkPack, packError: _fail } = require("./site-pack");

const { PENDING, INDEXING, DONE, FAILED, MISMATCH, PRIVATE, PRUNED } = SITE_INGEST.STATES;
const WORKER_FILE = path.join(__dirname, "site-pack-worker.js");

function pageKeyFor(snapshotTx, url) {
  return `${SITE_INGEST.PAGE_KEY_PREFIX}${snapshotTx}:${shake256(url).slice(0, 16)}`;
}

function isSitePageKey(key) {
  return typeof key === "string" && key.startsWith(SITE_INGEST.PAGE_KEY_PREFIX);
}

// A page whose final URL left the site (login provider, shop platform) is kept
// for the root and proofs but never indexed or served.
function onSite(url, domain) {
  let host;
  try { host = new URL(url).hostname; } catch { return false; }
  return siteKey(host) === domain;
}

const _yield = () => new Promise((resolve) => setImmediate(resolve));

// Checks the pack on a worker thread and yields its leaf pages a batch at a
// time; the bytes move to the worker without a copy.
async function* _packBatches(record, bytes, onWorker) {
  const worker = new Worker(WORKER_FILE, {
    workerData: {
      record: { domain: record.domain, seq: Number(record.seq), page_count: Number(record.page_count), root: record.root },
      bytes,
      batchPages: SITE_INGEST.PACK_BATCH_PAGES,
    },
    transferList: [bytes.buffer],
    resourceLimits: { maxOldGenerationSizeMb: SITE_INGEST.WORKER_HEAP_MB },
  });
  onWorker(worker);
  const inbox = [];
  let waiter = null;
  const deliver = (item) => {
    if (waiter) { const w = waiter; waiter = null; w(item); } else inbox.push(item);
  };
  worker.on("message", (m) => deliver({ m }));
  worker.on("error", (err) => deliver({ err }));
  worker.on("exit", (code) => deliver({ exit: code }));
  const timer = setTimeout(() => {
    deliver({ err: Object.assign(new Error("pack check timed out"), { code: "pack_check_timeout" }) });
    worker.terminate();
  }, SITE_INGEST.CHECK_TIMEOUT_MS);
  const next = () => (inbox.length ? Promise.resolve(inbox.shift()) : new Promise((resolve) => { waiter = resolve; }));
  try {
    while (true) {
      const { m, err, exit } = await next();
      if (err) {
        const code = err.code === "ERR_WORKER_OUT_OF_MEMORY" ? "pack_too_large" : (err.code === "pack_check_timeout" ? err.code : "pack_check_failed");
        throw _fail(`pack check failed: ${err.message}`, code);
      }
      if (!m) throw _fail(`pack worker stopped (exit ${exit})`, "pack_check_failed");
      if (m.type === "error") throw _fail(m.message, m.code, m.permanent);
      // The timeout bounds the check; indexing then paces itself on the write queue.
      if (m.type === "ready") clearTimeout(timer);
      if (m.type === "done") return;
      if (m.type === "batch") yield m.pages;
      worker.postMessage("next");
    }
  } finally {
    clearTimeout(timer);
    onWorker(null);
    await worker.terminate();
  }
}

function _keysOf(row) {
  return row && row.paragraph_keys ? row.paragraph_keys.split(" ").filter(Boolean) : [];
}

function createSiteIngest({ dag, sources = [], fetchImpl = globalThis.fetch, log = console, now = nowMs, keepSnapshots = SITE_INGEST.KEEP_SNAPSHOTS } = {}) {
  const urls = sources.map((s) => String(s).replace(/\/+$/, "")).filter(Boolean);
  const queue = [];
  const queued = new Set();
  const known = new Set();   // snapshot tx ids already done or queued, so reconcile skips them
  let draining = null;
  let stopped = false;
  let timers = [];
  let warnedNoSource = false;
  let worker = null;
  let current = null;        // the snapshot being processed: never queued twice

  function enqueue(snapshotTx) {
    if (stopped || queued.has(snapshotTx) || snapshotTx === current) return;
    queued.add(snapshotTx);
    known.add(snapshotTx);
    queue.push(snapshotTx);
    if (!draining) draining = new Promise((resolve) => setImmediate(() => _drain().finally(resolve)));
  }

  async function _drain() {
    try {
      while (queue.length && !stopped) {
        const tx = queue.shift();
        queued.delete(tx);
        current = tx;
        try {
          await processSnapshot(tx);
        } catch (err) {
          log.warn?.(`site ingest: ${tx.slice(0, 16)} crashed: ${err.message}`);
        } finally {
          current = null;
        }
      }
    } finally {
      draining = null;
    }
  }

  // Resolves once the queue is empty (tests and orderly shutdown).
  async function idle() {
    while (draining) await draining;
  }

  // Hashed as it arrives, so the pack is never hashed in one pass.
  async function _download(res) {
    const declared = Number(res.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > SITE_INGEST.MAX_PACK_BYTES) throw _fail(`pack is ${declared} bytes`, "pack_too_large");
    const hash = shake256Incremental();
    const chunks = [];
    let size = 0;
    for await (const chunk of res.body) {
      size += chunk.length;
      if (size > SITE_INGEST.MAX_PACK_BYTES) throw _fail("pack exceeds the size cap", "pack_too_large");
      hash.update(chunk);
      chunks.push(chunk);
    }
    // A buffer of its own (never a pooled slice), so it can be transferred to the worker.
    const bytes = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) { bytes.set(c, at); at += c.length; }
    return { bytes, hash: hash.digest("hex") };
  }

  // Any byte-identical copy will do: each source is tried until one serves
  // bytes with the right hash.
  async function fetchPack(record) {
    const errors = [];
    for (const base of urls) {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), SITE_INGEST.FETCH_TIMEOUT_MS);
      try {
        const res = await fetchImpl(`${base}/api/archive/pack/${record.pack_hash}`, {
          headers: { "Accept": "application/gzip", "User-Agent": "TIP-Node/1.0" },
          signal: ac.signal,
          redirect: "follow",
        });
        if (!res.ok) throw _fail(`HTTP ${res.status}`, "pack_http_error");
        const { bytes, hash } = await _download(res);
        if (hash !== record.pack_hash) throw _fail("served bytes do not match pack_hash", "pack_hash_mismatch");
        return { bytes, source: base };
      } catch (err) {
        errors.push(`${base}: ${err.message}`);
      } finally {
        clearTimeout(timer);
      }
    }
    throw _fail(`no source served the pack (${errors.join("; ") || "none tried"})`, "pack_unavailable");
  }

  // Room in the write queue first; then the queued writes must land, and the job rests
  // as long as they took (the same pacing as indexing).
  async function _paced(write) {
    while (!stopped && _writesBehind()) await new Promise((resolve) => setTimeout(resolve, SITE_INGEST.WRITE_WAIT_MS));
    if (stopped) throw _fail("ingest stopped", "ingest_stopped");
    const started = performance.now();
    write();
    await dag.flush();
    const took = performance.now() - started;
    if (took >= 1) await new Promise((resolve) => setTimeout(resolve, took));
  }

  // Drops what an earlier part-way run left for this snapshot (its page rows and the
  // index rows they own), so a retry rebuilds every row with this run's reuse choices.
  async function _clearPartial(snapshotTx) {
    const rows = await dag.listSitePages(snapshotTx);
    for (let i = 0; i < rows.length; i += SITE_INGEST.PRUNE_BATCH) {
      const batch = rows.slice(i, i + SITE_INGEST.PRUNE_BATCH);
      const owned = batch.filter((r) => (r.index_key || r.page_key) === r.page_key).map((r) => r.page_key);
      await _paced(() => {
        dag.deleteSiteIndexRows(owned);
        dag.deleteSitePages(batch.map((r) => r.page_key));
      });
    }
  }

  // Keeps the index of a site's newest keepSnapshots indexed snapshots. An older one
  // loses its pages, and its index rows unless a kept page still points at them; a
  // pruned snapshot still holding such rows is revisited on later passes.
  async function pruneDomain(domain) {
    const kept = [];
    const older = [];
    let before = null;
    while (true) {
      const snaps = dag.listSiteSnapshots(domain, { before, limit: SITE_SNAPSHOT.LIST_MAX });
      if (!snaps.length) break;
      for (const snap of snaps) {
        const st = await dag.getSiteIngest(snap.tx_id);
        if (!st) continue;
        if (st.state === DONE && kept.length < keepSnapshots) kept.push(snap);
        else if (st.state === DONE || (st.state === PRUNED && Number(st.pages) > 0)) older.push({ snap, st });
      }
      before = Number(snaps[snaps.length - 1].seq);
      if (before <= 1) break;
    }
    if (!older.length) return 0;
    const inUse = new Set();
    for (const snap of kept) for (const r of await dag.listSitePages(snap.tx_id)) inUse.add(r.index_key || r.page_key);
    let dropped = 0;
    for (const { snap, st } of older) {
      const rows = await dag.listSitePages(snap.tx_id);
      const drop = rows.filter((r) => !inUse.has(r.page_key));
      for (let i = 0; i < drop.length; i += SITE_INGEST.PRUNE_BATCH) {
        const batch = drop.slice(i, i + SITE_INGEST.PRUNE_BATCH);
        const owned = batch.filter((r) => (r.index_key || r.page_key) === r.page_key).map((r) => r.page_key);
        await _paced(() => {
          dag.deleteSiteIndexRows(owned);
          dag.deleteSitePages(batch.map((r) => r.page_key));
        });
      }
      dropped += drop.length;
      dag.saveSiteIngest({ ...st, state: PRUNED, pages: rows.length - drop.length, next_attempt_at: Number.MAX_SAFE_INTEGER, updated_at: now() });
    }
    log.info?.(`site ingest: ${domain}: pruned ${older.length} snapshot(s) beyond the newest ${keepSnapshots}, ${dropped} page rows removed`);
    return older.length;
  }

  // Index rows are reused from the newest earlier snapshot this node fully indexed:
  // the previous one, unless it was private, failed or mismatched.
  async function _reuseSource(record, prevByUrl) {
    if (!record.prev_snapshot_tx) return prevByUrl;
    const prevState = await dag.getSiteIngest(record.prev_snapshot_tx);
    if (prevState && prevState.state === DONE) return prevByUrl;
    const earlier = dag.listSiteSnapshots(record.domain, { before: Number(record.seq), limit: SITE_INGEST.REUSE_LOOKBACK });
    for (const snap of earlier) {
      const st = await dag.getSiteIngest(snap.tx_id);
      if (!st || st.state !== DONE) continue;
      const out = new Map();
      for (const r of await dag.listSitePages(snap.tx_id)) out.set(r.url, r);
      return out;
    }
    return new Map();
  }

  function _writesBehind() {
    if (dag.isPersistenceOverloaded?.()) return true;
    const st = dag.persistenceStats?.();
    return !!st && (st.queue_depth > SITE_INGEST.MAX_QUEUED_WRITES || st.oldest_pending_ms > SITE_INGEST.MAX_OLDEST_WRITE_MS);
  }

  // Pages arrive in batches from the pack worker. Index rows are written once per
  // slice (SLICE_MS of work or MAX_SLICE_ROWS rows), one call per table; the ingest
  // then waits for those writes to land and rests as long as they took, so commits
  // never queue behind more than one small slice and a pack never piles up rows.
  async function indexSnapshot(record, batches, onProgress = () => {}) {
    const createdAt = now();
    const binding = liveBindingFor(dag, record.domain, Number(record.registered_at));
    const owner = binding ? binding.tip_id : record.signer_tip_id;
    const prevByUrl = new Map();
    if (record.prev_snapshot_tx) {
      for (const r of await dag.listSitePages(record.prev_snapshot_tx)) prevByUrl.set(r.url, r);
    }
    const reuseByUrl = await _reuseSource(record, prevByUrl);
    const pending = { fingerprints: [], bands: [], codes: [], passages: [], pages: [] };
    const pendingRows = () => pending.fingerprints.length + pending.bands.length + pending.codes.length + pending.passages.length + pending.pages.length;
    const writeSlice = async () => {
      if (!pendingRows()) return;
      const started = performance.now();
      if (pending.fingerprints.length) dag.savePerceptualFingerprints(pending.fingerprints);
      if (pending.bands.length) dag.saveMinhashBands(pending.bands);
      if (pending.codes.length) dag.savePhashCodes(pending.codes);
      if (pending.passages.length) dag.saveDocumentPassages(pending.passages);
      if (pending.pages.length) dag.saveSitePages(pending.pages);
      for (const k of Object.keys(pending)) pending[k] = [];
      await dag.flush();
      onProgress(pages);
      const took = performance.now() - started;
      if (took >= 1) await new Promise((resolve) => setTimeout(resolve, took));
    };
    const addFingerprint = (fp, key, componentIdx) => {
      const r = buildIngestRows(fp, { ctid: key, componentIdx, createdAt });
      if (!r) return;
      pending.fingerprints.push(r.fingerprint);
      for (const b of r.bands) pending.bands.push(b);
      for (const c of r.codes) pending.codes.push(c);
    };
    let pages = 0;
    let offsite = 0;
    let sliceStart = performance.now();
    for await (const batch of batches) {
      for (const p of batch) {
        while (!stopped && _writesBehind()) {
          await new Promise((resolve) => setTimeout(resolve, SITE_INGEST.WRITE_WAIT_MS));
          sliceStart = performance.now();
        }
        if (stopped) throw _fail("ingest stopped", "ingest_stopped");
        const key = pageKeyFor(record.tx_id, p.url);
        const keys = Array.isArray(p.paragraph_keys) ? [...new Set(p.paragraph_keys.filter((k) => typeof k === "string" && k.length <= 16))] : [];
        const away = !onSite(p.url, record.domain);
        const prev = prevByUrl.get(p.url);
        const prevKeys = _keysOf(prev);
        const have = new Set(keys);
        // A page whose indexed content and owner match the previous snapshot reuses
        // that version's index rows instead of writing them again.
        const indexHash = !away && typeof p.content_hash === "string" ? shake256(`${p.content_hash}\n${owner}`) : null;
        const earlier = reuseByUrl.get(p.url);
        const reuse = indexHash !== null && !!earlier && earlier.index_hash === indexHash;
        const indexKey = away ? null : (reuse ? (earlier.index_key || earlier.page_key) : key);
        pending.pages.push({
          page_key: key, snapshot_tx: record.tx_id, domain: record.domain, seq: record.seq, url: p.url,
          text_hash: p.text_hash, page_hash: p.page_hash, offsite: away,
          changed: prev ? prev.page_hash !== p.page_hash : null,
          kept: prev && prevKeys.length ? prevKeys.filter((k) => have.has(k)).length / prevKeys.length : null,
          paragraph_keys: keys.join(" "), proof: typeof p.proof === "string" ? p.proof : null,
          index_key: indexKey, index_hash: indexHash, created_at: createdAt,
        });
        pages++;
        if (away) {
          offsite++;
        } else if (!reuse) {
          if (p.text && p.text.kind === "text") addFingerprint(p.text, key, 0);
          let component = 1;
          for (const img of Array.isArray(p.images) ? p.images : []) {
            if (typeof img.pdq !== "string") continue;
            addFingerprint({ kind: "image", profile: IMAGE_PROFILE, pdq: img.pdq, quality: img.quality ?? null, media_id: img.media_id ?? null }, key, component++);
          }
          for (const k of keys) {
            pending.passages.push({ profile: SITE_INGEST.PASSAGE_PROFILE, passage_key: k, owner, ctid: key, component_idx: 0, unit: null });
          }
        }
        if (pendingRows() >= SITE_INGEST.MAX_SLICE_ROWS) {
          await writeSlice();
          sliceStart = performance.now();
        } else if (performance.now() - sliceStart >= SITE_INGEST.SLICE_MS) {
          await _yield();
          sliceStart = performance.now();
        }
      }
    }
    await writeSlice();
    await dag.flush();
    if (offsite) log.warn?.(`site ingest: ${record.domain} seq ${record.seq}: ${offsite} off-site page(s) kept out of the index`);
    return { pages, offsite };
  }

  async function processSnapshot(snapshotTx) {
    const record = dag.getSiteSnapshot(snapshotTx);
    if (!record) return null;
    const prior = await dag.getSiteIngest(snapshotTx);
    if (prior && (prior.state === DONE || prior.state === MISMATCH || prior.state === PRIVATE || prior.state === PRUNED)) return prior;
    if (prior && Number(prior.next_attempt_at) > now()) return prior;
    const base = {
      snapshot_tx: snapshotTx, domain: record.domain, seq: record.seq,
      attempts: (prior ? Number(prior.attempts) : 0) + 1, updated_at: now(),
    };
    if (record.visibility === SITE_SNAPSHOT.VISIBILITY.PRIVATE) {
      const row = { ...base, attempts: 0, state: PRIVATE, next_attempt_at: Number.MAX_SAFE_INTEGER, last_error: null };
      dag.saveSiteIngest(row);
      return row;
    }
    if (!urls.length) {
      if (!warnedNoSource) log.warn?.("site ingest: TIP_SITE_ARCHIVE_URLS is empty, snapshots are recorded but not indexed");
      warnedNoSource = true;
      const row = { ...base, attempts: base.attempts - 1, state: PENDING, next_attempt_at: now() + SITE_INGEST.RETRY_MAX_MS, last_error: "no archive source configured" };
      dag.saveSiteIngest(row);
      return row;
    }
    try {
      const { bytes, source } = await fetchPack(record);
      if (prior && (prior.state === INDEXING || prior.state === FAILED)) await _clearPartial(snapshotTx);
      const indexing = (pages) => dag.saveSiteIngest({ ...base, state: INDEXING, pages, next_attempt_at: 0, last_error: null, source });
      indexing(0);
      let saved = now();
      const progress = (pages) => {
        if (now() - saved < SITE_INGEST.PROGRESS_MS) return;
        saved = now();
        indexing(pages);
      };
      const out = await indexSnapshot(record, _packBatches(record, bytes, (w) => { worker = w; }), progress);
      const row = { ...base, state: DONE, next_attempt_at: 0, last_error: null, pages: out.pages, offsite: out.offsite, source };
      dag.saveSiteIngest(row);
      log.info?.(`site ingest: ${record.domain} seq ${record.seq} indexed, ${out.pages} pages (${out.offsite} off-site) from ${source}`);
      try {
        await pruneDomain(record.domain);
      } catch (err) {
        if (err.code !== "ingest_stopped") log.warn?.(`site ingest: pruning ${record.domain} failed: ${err.message}`);
      }
      return row;
    } catch (err) {
      if (err.code === "ingest_stopped" || stopped) return null;
      const delay = Math.min(SITE_INGEST.RETRY_BASE_MS * 2 ** (base.attempts - 1), SITE_INGEST.RETRY_MAX_MS);
      const row = {
        ...base, state: err.permanent ? MISMATCH : FAILED, last_error: `${err.code || "error"}: ${err.message}`.slice(0, 2000),
        next_attempt_at: err.permanent ? Number.MAX_SAFE_INTEGER : now() + delay,
      };
      dag.saveSiteIngest(row);
      log.warn?.(`site ingest: ${record.domain} seq ${record.seq} failed (${row.last_error})${err.permanent ? ", not retried" : ""}`);
      return row;
    }
  }

  // Every committed snapshot not yet indexed, including those that arrived by
  // state sync rather than through this node's commit path.
  async function reconcile() {
    let after = "";
    while (!stopped) {
      const batch = dag.listSiteSnapshotsAfter(after, 500);
      if (!batch.length) break;
      for (const r of batch) {
        if (known.has(r.tx_id)) continue;
        const st = await dag.getSiteIngest(r.tx_id);
        if (st && (st.state === DONE || st.state === MISMATCH || st.state === PRIVATE || st.state === PRUNED)) { known.add(r.tx_id); continue; }
        if (!st || Number(st.next_attempt_at) <= now()) enqueue(r.tx_id);
      }
      after = batch[batch.length - 1].tx_id;
      await _yield();
    }
  }

  async function retryDue() {
    for (const r of await dag.listSiteIngestsDue(now())) enqueue(r.snapshot_tx);
  }

  function start() {
    reconcile().catch((err) => log.warn?.(`site ingest: reconcile failed: ${err.message}`));
    const every = (fn, ms) => {
      const t = setInterval(() => { fn().catch((err) => log.warn?.(`site ingest: ${err.message}`)); }, ms);
      t.unref?.();
      timers.push(t);
    };
    every(retryDue, SITE_INGEST.RETRY_BASE_MS);
    every(reconcile, SITE_INGEST.RECONCILE_MS);
  }

  function stop() {
    stopped = true;
    for (const t of timers) clearInterval(t);
    timers = [];
    if (worker) worker.terminate();
  }

  return { enqueue, idle, processSnapshot, pruneDomain, reconcile, retryDue, start, stop };
}

module.exports = { createSiteIngest, checkPack, pageKeyFor, isSitePageKey, onSite };
