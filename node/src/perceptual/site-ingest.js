"use strict";

// Off-DAG index of committed site snapshots. For each SITE_SNAPSHOT this node
// fetches the fingerprint pack named by pack_hash, checks it against the signed
// record (hash, header, Merkle root, page count), and indexes its pages so
// similar search and page reads can name "page P of site D, snapshot S".
// Node-local, advisory and rebuildable: nothing here touches consensus state.

const web = require("tip-content-fingerprint/src/web");
const { PROFILE: IMAGE_PROFILE } = require("tip-content-fingerprint/src/image");
const { shake256 } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { SITE_INGEST } = require("../../../shared/constants");
const { siteKey, liveBindingFor } = require("../validators/business-rules");
const { ingestFingerprint } = require("./ingest");

const { PENDING, DONE, FAILED, MISMATCH } = SITE_INGEST.STATES;

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

function _fail(message, code, permanent = false) {
  const e = new Error(message);
  e.code = code;
  e.permanent = permanent;
  return e;
}

const _yield = () => new Promise((resolve) => setImmediate(resolve));

/**
 * Check a pack's bytes against its signed record. Returns the leaf pages.
 * A pack with the right hash but the wrong content can never be fixed by a
 * retry, so those failures are permanent.
 */
function checkPack(record, bytes) {
  if (shake256(bytes) !== record.pack_hash) throw _fail("pack bytes do not match pack_hash", "pack_hash_mismatch");
  let pack;
  try {
    pack = web.readPack(bytes);
  } catch (err) {
    throw _fail(`unreadable pack: ${err.message}`, "pack_unreadable", true);
  }
  const { header, pages } = pack;
  if (header.domain !== record.domain || header.seq !== record.seq) {
    throw _fail(`pack is for ${header.domain} seq ${header.seq}, not ${record.domain} seq ${record.seq}`, "pack_header_mismatch", true);
  }
  const leaves = pages.filter((p) => !p.skipped);
  if (leaves.length !== record.page_count) {
    throw _fail(`pack has ${leaves.length} pages, the record ${record.page_count}`, "pack_root_mismatch", true);
  }
  // Over every leaf line, off-site ones included: the owner signed all of them.
  // packRoot also refuses a URL that appears twice.
  let root;
  try {
    root = web.packRoot(pages);
  } catch (err) {
    throw _fail(`pack pages do not form a tree: ${err.message}`, "pack_root_mismatch", true);
  }
  if (root !== record.root) throw _fail("pack pages do not give the record's root", "pack_root_mismatch", true);
  return leaves;
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

  async function _readCapped(res) {
    const declared = Number(res.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > SITE_INGEST.MAX_PACK_BYTES) throw _fail(`pack is ${declared} bytes`, "pack_too_large");
    const chunks = [];
    let size = 0;
    for await (const chunk of res.body) {
      size += chunk.length;
      if (size > SITE_INGEST.MAX_PACK_BYTES) throw _fail("pack exceeds the size cap", "pack_too_large");
      chunks.push(chunk);
    }
    return new Uint8Array(Buffer.concat(chunks.map((c) => Buffer.from(c))));
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
        const bytes = await _readCapped(res);
        if (shake256(bytes) !== record.pack_hash) throw _fail("served bytes do not match pack_hash", "pack_hash_mismatch");
        return { bytes, source: base };
      } catch (err) {
        errors.push(`${base}: ${err.message}`);
      } finally {
        clearTimeout(timer);
      }
    }
    throw _fail(`no source served the pack (${errors.join("; ") || "none tried"})`, "pack_unavailable");
  }

  async function indexSnapshot(record, leaves) {
    const createdAt = now();
    const binding = liveBindingFor(dag, record.domain, Number(record.registered_at));
    const owner = binding ? binding.tip_id : record.signer_tip_id;
    const prevByUrl = new Map();
    if (record.prev_snapshot_tx) {
      for (const r of await dag.listSitePages(record.prev_snapshot_tx)) prevByUrl.set(r.url, r);
    }
    const rows = [];
    let offsite = 0;
    for (let i = 0; i < leaves.length; i++) {
      const p = leaves[i];
      const key = pageKeyFor(record.tx_id, p.url);
      const keys = Array.isArray(p.paragraph_keys) ? [...new Set(p.paragraph_keys.filter((k) => typeof k === "string" && k.length <= 16))] : [];
      const away = !onSite(p.url, record.domain);
      const prev = prevByUrl.get(p.url);
      const prevKeys = _keysOf(prev);
      const have = new Set(keys);
      rows.push({
        page_key: key, snapshot_tx: record.tx_id, domain: record.domain, seq: record.seq, url: p.url,
        text_hash: p.text_hash, page_hash: p.page_hash, offsite: away,
        changed: prev ? prev.page_hash !== p.page_hash : null,
        kept: prev && prevKeys.length ? prevKeys.filter((k) => have.has(k)).length / prevKeys.length : null,
        paragraph_keys: keys.join(" "), created_at: createdAt,
      });
      if (away) { offsite++; continue; }
      if (p.text && p.text.kind === "text") {
        await ingestFingerprint(dag, p.text, { ctid: key, componentIdx: 0, createdAt });
      }
      let component = 1;
      for (const img of Array.isArray(p.images) ? p.images : []) {
        if (typeof img.pdq !== "string") continue;
        await ingestFingerprint(dag, { kind: "image", profile: IMAGE_PROFILE, pdq: img.pdq, quality: img.quality ?? null, media_id: img.media_id ?? null },
          { ctid: key, componentIdx: component++, createdAt });
      }
      if (keys.length) {
        dag.saveDocumentPassages(keys.map((k) => ({
          profile: SITE_INGEST.PASSAGE_PROFILE, passage_key: k, owner, ctid: key, component_idx: 0, unit: null,
        })));
      }
      if ((i + 1) % SITE_INGEST.YIELD_EVERY_PAGES === 0) await _yield();
    }
    dag.saveSitePages(rows);
    await dag.flush();
    if (offsite) log.warn?.(`site ingest: ${record.domain} seq ${record.seq}: ${offsite} off-site page(s) kept out of the index`);
    return { pages: rows.length, offsite };
  }

  async function processSnapshot(snapshotTx) {
    const record = dag.getSiteSnapshot(snapshotTx);
    if (!record) return null;
    const prior = await dag.getSiteIngest(snapshotTx);
    if (prior && (prior.state === DONE || prior.state === MISMATCH)) return prior;
    if (prior && Number(prior.next_attempt_at) > now()) return prior;
    const base = {
      snapshot_tx: snapshotTx, domain: record.domain, seq: record.seq,
      attempts: (prior ? Number(prior.attempts) : 0) + 1, updated_at: now(),
    };
    if (!urls.length) {
      if (!warnedNoSource) log.warn?.("site ingest: TIP_SITE_ARCHIVE_URLS is empty, snapshots are recorded but not indexed");
      warnedNoSource = true;
      const row = { ...base, attempts: base.attempts - 1, state: PENDING, next_attempt_at: now() + SITE_INGEST.RETRY_MAX_MS, last_error: "no archive source configured" };
      dag.saveSiteIngest(row);
      return row;
    }
    try {
      const { bytes, source } = await fetchPack(record);
      const leaves = checkPack(record, bytes);
      const out = await indexSnapshot(record, leaves);
      const row = { ...base, state: DONE, next_attempt_at: 0, last_error: null, pages: out.pages, offsite: out.offsite, source };
      dag.saveSiteIngest(row);
      log.info?.(`site ingest: ${record.domain} seq ${record.seq} indexed, ${out.pages} pages (${out.offsite} off-site) from ${source}`);
      return row;
    } catch (err) {
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
        if (st && (st.state === DONE || st.state === MISMATCH)) { known.add(r.tx_id); continue; }
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
  }

  return { enqueue, idle, processSnapshot, reconcile, retryDue, start, stop };
}

module.exports = { createSiteIngest, checkPack, pageKeyFor, isSitePageKey, onSite };
