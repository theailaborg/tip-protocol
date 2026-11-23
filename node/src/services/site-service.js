"use strict";

const { nowMs } = require("../../../shared/time");
const web = require("tip-content-fingerprint/src/web");
const { TX_TYPES, SITE_SNAPSHOT, SITE_INGEST, SIGNED_BY_KIND } = require("../../../shared/constants");
const siteSnapshotSchema = require("../schemas/site-snapshot");
const { isValidDomain } = require("../schemas/register-domain");
const { schemaError } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const { siteKey, liveBindingFor } = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const { pageKeyFor, onSite } = require("../perceptual/site-ingest");
const { decodeProof } = require("../perceptual/site-pack");
const { log } = require("../logger");

function _summary(row) {
  return {
    seq: row.seq,
    tx_id: row.tx_id,
    root: row.root,
    page_count: row.page_count,
    captured_at: row.captured_at,
    registered_at: row.registered_at,
    wacz_hash: row.wacz_hash,
    pack_hash: row.pack_hash,
    witness_vp_id: row.witness_vp_id,
    visibility: row.visibility || "public",
  };
}

// While indexing, `pages` is the count indexed so far and `total` the snapshot's page count.
function _ingestView(row, total) {
  if (!row) return { state: SITE_INGEST.STATES.PENDING, pages: null, offsite: null, attempts: 0, last_error: null };
  return {
    state: row.state, pages: row.pages == null ? null : Number(row.pages), offsite: row.offsite == null ? null : Number(row.offsite),
    attempts: Number(row.attempts), last_error: row.last_error || null,
    ...(row.state === SITE_INGEST.STATES.INDEXING ? { total: Number(total) } : {}),
  };
}

function _domainParam(raw) {
  const domain = siteKey(typeof raw === "string" ? raw.trim() : "");
  if (!isValidDomain(domain)) throw schemaError(400, "domain must be a DNS name", "domain_invalid");
  return domain;
}

function createSiteService({ dag, submitTx, websitePages }) {
  // ── POST /v1/site/snapshot ───────────────────────────────────────────
  // SUBJECT-signed relay: the signer's signature becomes tx.signature, the
  // witness rides as a VP cosignature, the node adds only the envelope.
  async function submitSnapshot(body) {
    const { payload, witness } = siteSnapshotSchema.validateRequest(body, { dag, now: nowMs() });

    if (websitePages && websitePages.enabled) {
      const owner = liveBindingFor(dag, payload.domain, nowMs());
      const answer = owner && await websitePages.snapshotAllowed({
        owner_tip_id: owner.tip_id, signer_tip_id: payload.signer_tip_id,
        domain: payload.domain, page_count: payload.page_count,
      });
      if (answer && answer.allowed === false) {
        throw schemaError(429, `${payload.domain} cannot take another snapshot on this plan yet`, "website_snapshot_limit", {
          domain: payload.domain, reason: answer.reason ?? null,
          next_allowed_at: answer.next_allowed_at ?? null, upgrade_url: answer.upgrade_url || "/plans#websites",
        });
      }
    }

    const tx = withTxId({
      tx_type: TX_TYPES.SITE_SNAPSHOT,
      timestamp: nowMs(),
      data: siteSnapshotSchema.buildTxData(payload, witness),
      signature: body.signature,
    }, dag);
    const validation = validateTransaction(tx, dag, { skipPrevCheck: true });
    if (!validation.valid) throw schemaError(400, validation.errors.join("; "), "tx_validation_failed");
    submitTx(tx);
    log.info(`Site snapshot proposed: ${payload.domain} seq ${payload.seq} by ${payload.signer_tip_id} (tx: ${tx.tx_id.slice(0, 16)})`);
    return {
      domain: payload.domain, seq: payload.seq, tx_id: tx.tx_id,
      witness_vp_id: witness ? witness.vp_id : null, proposed_at: tx.timestamp, confirmation: "proposed",
    };
  }

  // ── GET /v1/site/snapshot/:tx ────────────────────────────────────────
  // The full record with the owner's signature and the witness, so a viewer
  // can verify both itself.
  async function getSnapshot(txId) {
    if (typeof txId !== "string" || !SITE_SNAPSHOT.TX_ID_PATTERN.test(txId)) {
      throw schemaError(400, "tx must be a 64-character hex tx_id", "tx_id_invalid");
    }
    const row = dag.getSiteSnapshot(txId);
    if (!row) throw schemaError(404, `No site snapshot ${txId}`, "site_snapshot_not_found");
    const tx = dag.getTx(txId);
    const cosig = tx && Array.isArray(tx.data?.cosignatures)
      ? tx.data.cosignatures.find(c => c.signer_kind === SIGNED_BY_KIND.VP && c.signer_ref === row.witness_vp_id)
      : null;
    return {
      ...row,
      visibility: row.visibility || "public",
      signature: tx ? tx.signature : null,
      witness: row.witness_vp_id ? { vp_id: row.witness_vp_id, signature: cosig ? cosig.signature : null } : null,
      ingest: _ingestView(await dag.getSiteIngest(txId), row.page_count),
    };
  }

  // The snapshot that covered the site at `atMs`: the latest captured at or before it.
  function _snapshotAt(domain, atMs) {
    let before = null;
    while (true) {
      const rows = dag.listSiteSnapshots(domain, { before, limit: SITE_SNAPSHOT.LIST_MAX });
      if (!rows.length) return null;
      const hit = rows.find(r => r.captured_at <= atMs);
      if (hit) return hit;
      before = rows[rows.length - 1].seq;
      if (before <= 1) return null;
    }
  }

  // ── GET /v1/site/:domain/page?url=&at= ───────────────────────────────
  // One page of the snapshot covering `at`, from this node's ingested pack,
  // with a Merkle proof the node checks itself before answering.
  async function getPage(rawDomain, query = {}) {
    const domain = _domainParam(rawDomain);
    let url;
    try {
      url = web.canonicalUrl(String(query.url || ""));
    } catch {
      throw schemaError(400, "url must be an http or https URL", "url_invalid");
    }
    if (!onSite(url, domain)) throw schemaError(404, `${url} is not a page of ${domain}`, "site_page_not_found");
    const at = query.at === undefined ? nowMs() : Number(query.at);
    if (!Number.isSafeInteger(at) || at < 0) throw schemaError(400, "at must be an epoch ms timestamp", "at_invalid");

    const snap = _snapshotAt(domain, at);
    if (!snap) throw schemaError(404, `No snapshot of ${domain} at that time`, "site_snapshot_not_found");
    if (snap.visibility === SITE_SNAPSHOT.VISIBILITY.PRIVATE) {
      throw schemaError(404, `Snapshot ${snap.seq} of ${domain} is private: its pages are not shared with TIP nodes, so they cannot be shown or matched here. The site owner can share a page proof.`, "site_snapshot_private", { seq: snap.seq, tx_id: snap.tx_id });
    }
    const ingest = await dag.getSiteIngest(snap.tx_id);
    if (ingest && ingest.state === SITE_INGEST.STATES.MISMATCH) {
      throw schemaError(422, `The pack of snapshot ${snap.seq} of ${domain} does not match its signed record`, "site_snapshot_pack_mismatch", { ingest: _ingestView(ingest, snap.page_count) });
    }
    if (!ingest || ingest.state !== SITE_INGEST.STATES.DONE) {
      throw schemaError(409, `Snapshot ${snap.seq} of ${domain} is not indexed on this node yet`, "site_page_not_ready", { ingest: _ingestView(ingest, snap.page_count) });
    }
    const page = await dag.getSitePage(pageKeyFor(snap.tx_id, url));
    if (!page || Number(page.offsite)) throw schemaError(404, `${url} is not in snapshot ${snap.seq} of ${domain}`, "site_page_not_found");

    const proof = decodeProof(page.proof);
    if (!proof || !web.verifyPage(url, page.text_hash, proof, snap.root)) {
      log.error(`site page proof failed: ${domain} seq ${snap.seq} ${url}`);
      throw schemaError(500, "The indexed page does not match the snapshot root", "site_page_proof_failed");
    }
    return {
      domain, url, seq: snap.seq, tx_id: snap.tx_id, captured_at: snap.captured_at, registered_at: snap.registered_at,
      root: snap.root, text_hash: page.text_hash, page_hash: page.page_hash,
      leaf: web.leafHash(url, page.text_hash), proof,
      changed: page.changed == null ? null : Boolean(Number(page.changed)),
      kept: page.kept == null ? null : Number(page.kept),
    };
  }

  // ── GET /v1/site/:domain/snapshots?before=&limit= ────────────────────
  function listSnapshots(rawDomain, query = {}) {
    const domain = _domainParam(rawDomain);
    const limit = query.limit === undefined ? 20 : Number(query.limit);
    if (!Number.isInteger(limit) || limit < 1 || limit > SITE_SNAPSHOT.LIST_MAX) {
      throw schemaError(400, `limit must be an integer from 1 to ${SITE_SNAPSHOT.LIST_MAX}`, "limit_invalid");
    }
    const before = query.before === undefined ? null : Number(query.before);
    if (before !== null && (!Number.isSafeInteger(before) || before < 1)) {
      throw schemaError(400, "before must be a snapshot seq", "before_invalid");
    }
    const rows = dag.listSiteSnapshots(domain, { before, limit });
    const last = rows[rows.length - 1];
    return {
      domain,
      snapshots: rows.map(_summary),
      next_before: rows.length === limit && last && last.seq > 1 ? last.seq : null,
    };
  }

  return { submitSnapshot, getSnapshot, listSnapshots, getPage };
}

module.exports = { createSiteService };
