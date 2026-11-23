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

const { PENDING, DONE, FAILED, MISMATCH, PRIVATE } = SITE_INGEST.STATES;
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

function createSiteIngest({ dag, sources = [], fetchImpl = globalThis.fetch, log = console, now = nowMs } = {}) {
  const urls = sources.map((s) => String(s).replace(/\/+$/, "")).filter(Boolean);
  const queue = [];
  const queued = new Set();
  const known = new Set();   // snapshot tx ids already done or queued, so reconcile skips them
  let draining = null;
  let stopped = false;
  let timers = [];
  let warnedNoSource = false;
  let worker = null;

  function enqueue(snapshotTx) {
    if (stopped || queued.has(snapshotTx)) return;
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
        try {
          await processSnapshot(tx);
        } catch (err) {
          log.warn?.(`site ingest: ${tx.slice(0, 16)} crashed: ${err.message}`);
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

  function _writesBehind() {
    return dag.isPersistenceOverloaded?.() || (dag.persistenceStats?.().queue_depth ?? 0) > SITE_INGEST.MAX_QUEUED_WRITES;
  }

  // Pages arrive in batches from the pack worker. Index rows are written once
  // per slice (SLICE_MS of work, then the event loop is released), one call per
  // table, and each page first waits for room in the write queue, so a large
  // pack never piles up unwritten rows in memory.
  async function indexSnapshot(record, batches) {
    const createdAt = now();
    const binding = liveBindingFor(dag, record.domain, Number(record.registered_at));
    const owner = binding ? binding.tip_id : record.signer_tip_id;
    const prevByUrl = new Map();
    if (record.prev_snapshot_tx) {
      for (const r of await dag.listSitePages(record.prev_snapshot_tx)) prevByUrl.set(r.url, r);
    }
    const pending = { fingerprints: [], bands: [], codes: [], passages: [], pages: [] };
    const writeSlice = () => {
      if (pending.fingerprints.length) dag.savePerceptualFingerprints(pending.fingerprints);
      if (pending.bands.length) dag.saveMinhashBands(pending.bands);
      if (pending.codes.length) dag.savePhashCodes(pending.codes);
      if (pending.passages.length) dag.saveDocumentPassages(pending.passages);
      if (pending.pages.length) dag.saveSitePages(pending.pages);
      for (const k of Object.keys(pending)) pending[k] = [];
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
        pending.pages.push({
          page_key: key, snapshot_tx: record.tx_id, domain: record.domain, seq: record.seq, url: p.url,
          text_hash: p.text_hash, page_hash: p.page_hash, offsite: away,
          changed: prev ? prev.page_hash !== p.page_hash : null,
          kept: prev && prevKeys.length ? prevKeys.filter((k) => have.has(k)).length / prevKeys.length : null,
          paragraph_keys: keys.join(" "), proof: typeof p.proof === "string" ? p.proof : null, created_at: createdAt,
        });
        pages++;
        if (away) {
          offsite++;
        } else {
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
        if (performance.now() - sliceStart >= SITE_INGEST.SLICE_MS) {
          writeSlice();
          await _yield();
          sliceStart = performance.now();
        }
      }
    }
    writeSlice();
    await dag.flush();
    if (offsite) log.warn?.(`site ingest: ${record.domain} seq ${record.seq}: ${offsite} off-site page(s) kept out of the index`);
    return { pages, offsite };
  }

  async function processSnapshot(snapshotTx) {
    const record = dag.getSiteSnapshot(snapshotTx);
    if (!record) return null;
    const prior = await dag.getSiteIngest(snapshotTx);
    if (prior && (prior.state === DONE || prior.state === MISMATCH || prior.state === PRIVATE)) return prior;
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
      const out = await indexSnapshot(record, _packBatches(record, bytes, (w) => { worker = w; }));
      const row = { ...base, state: DONE, next_attempt_at: 0, last_error: null, pages: out.pages, offsite: out.offsite, source };
      dag.saveSiteIngest(row);
      log.info?.(`site ingest: ${record.domain} seq ${record.seq} indexed, ${out.pages} pages (${out.offsite} off-site) from ${source}`);
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
        if (st && (st.state === DONE || st.state === MISMATCH || st.state === PRIVATE)) { known.add(r.tx_id); continue; }
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

  return { enqueue, idle, processSnapshot, reconcile, retryDue, start, stop };
}

module.exports = { createSiteIngest, checkPack, pageKeyFor, isSitePageKey, onSite };
