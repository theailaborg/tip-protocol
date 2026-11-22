"use strict";

// Off the commit path. When a BIND_DOMAIN attestation commits without a committee
// quorum, this node checks the owner's proof itself and, if it holds, attests too.
// Advisory and node-local: the commit rule counts whatever attestations arrive.

const { DOMAIN_QUORUM, DOMAIN_VERIFICATION_METHODS, SIGNED_BY_KIND } = require("../../../shared/constants");
const { nowMs } = require("../../../shared/time");
const registerDomainSchema = require("../schemas/register-domain");
const { domainQuorumOn } = require("../validators/website-gate");
const domainVerifier = require("./verifier");
const { buildAttestationTx } = require("./attest");

const claimKey = (c) => `${c.domain}\x00${c.tip_id}\x00${c.claimed_at}`;

function createCoAttest({
  dag, config, submitTx, verifier = domainVerifier, log = console, now = nowMs,
  committee = () => require("../consensus/participants").getActiveCommittee(dag),
  setTimer = setTimeout, clearTimer = clearTimeout,
}) {
  const scheduled = new Map();   // claim key -> { claim, attempt, timer }
  const ready = [];
  let running = 0;
  let stopped = false;
  let reconcileTimer = null;

  const selfId = () => config.nodeRegisteredId || config.nodeId;

  function claimFromTx(tx) {
    const d = tx && tx.data;
    if (!d || !d.domain || !d.tip_id) return null;
    const cosig = Array.isArray(d.cosignatures)
      ? d.cosignatures.find(c => c && c.signer_kind === SIGNED_BY_KIND.SUBJECT && c.signer_ref === d.tip_id)
      : null;
    if (!cosig) return null;
    return { domain: d.domain, tip_id: d.tip_id, claimed_at: Number(d.claimed_at), method: d.claimed_method, signature: cosig.signature, first_at: Number(d.verified_at) };
  }

  // Nothing to do once the claim is bound for this window, this node has attested
  // it, or this node is not in the committee (its attestation would not count).
  function _settled(claim, at) {
    const since = at - DOMAIN_QUORUM.WINDOW_MS;
    const b = dag.getDomainBinding(claim.domain);
    if (b && b.binding_state === "verified" && b.tip_id === claim.tip_id
      && Number(b.claimed_at) === claim.claimed_at && b.verified_at >= since) return "bound";
    const mine = dag.getDomainAttestation(claim.domain, selfId());
    if (mine && mine.tip_id === claim.tip_id && Number(mine.claimed_at) === claim.claimed_at && mine.verified_at >= since) return "attested";
    if (!committee().includes(selfId())) return "not_in_committee";
    return null;
  }

  function enqueue(txId) {
    if (stopped || !config.nodePrivateKey || !selfId()) return;
    const claim = claimFromTx(dag.getTx(txId));
    if (!claim) return;
    _schedule(claim, 0, 0);
  }

  function _schedule(claim, attempt, delay) {
    const key = claimKey(claim);
    const prev = scheduled.get(key);
    if (prev && prev.attempt >= attempt) return;
    if (!prev && scheduled.size >= DOMAIN_QUORUM.QUEUE_MAX) {
      log.warn?.(`co-attest: queue full, ${claim.domain} skipped (reconcile retries it)`);
      return;
    }
    if (prev && prev.timer) clearTimer(prev.timer);
    const entry = { claim, attempt, timer: null };
    scheduled.set(key, entry);
    if (delay <= 0) { ready.push(key); _drain(); return; }
    entry.timer = setTimer(() => { entry.timer = null; ready.push(key); _drain(); }, delay);
    entry.timer.unref?.();
  }

  function _drain() {
    while (!stopped && running < DOMAIN_QUORUM.CONCURRENCY && ready.length) {
      const key = ready.shift();
      const entry = scheduled.get(key);
      if (!entry) continue;
      running++;
      check(entry.claim, entry.attempt)
        .catch(err => log.warn?.(`co-attest ${entry.claim.domain}: ${err.message}`))
        .finally(() => { running--; _drain(); });
    }
  }

  // One check: verify the proof from this node and submit an attestation, or
  // retry later within the window.
  async function check(claim, attempt = 0) {
    const key = claimKey(claim);
    const at = now();
    if (!domainQuorumOn(at) || at > claim.first_at + DOMAIN_QUORUM.WINDOW_MS) { scheduled.delete(key); return "expired"; }
    const settled = _settled(claim, at);
    if (settled) { scheduled.delete(key); return settled; }

    let identity;
    try {
      identity = registerDomainSchema.resolveClaimant(claim.tip_id, dag, at);
    } catch (err) {
      scheduled.delete(key);
      return "claimant_invalid";
    }
    const result = await verifier.verify(DOMAIN_VERIFICATION_METHODS.AUTO, claim.domain, claim.tip_id, { expectedPublicKey: identity.public_key });
    if (result.verified) {
      submitTx(buildAttestationTx({ dag, config, claim, domain: claim.domain, result }));
      scheduled.delete(key);
      log.info?.(`co-attest: ${claim.domain} -> ${claim.tip_id} proof seen (${result.method}), attestation submitted`);
      return "attested_now";
    }
    const next = DOMAIN_QUORUM.RETRY_DELAYS_MS[attempt];
    if (next == null || now() + next > claim.first_at + DOMAIN_QUORUM.WINDOW_MS) {
      scheduled.delete(key);
      log.warn?.(`co-attest: ${claim.domain} proof not seen from this node (${result.error?.code || "verification_failed"}), giving up`);
      return "not_seen";
    }
    _schedule(claim, attempt + 1, next);
    return "retry";
  }

  // Claims still open in the window (after a restart or a snapshot install).
  function reconcile() {
    if (stopped || !config.nodePrivateKey || !selfId()) return 0;
    const at = now();
    if (!domainQuorumOn(at)) return 0;
    const seen = new Set();
    let n = 0;
    for (const row of dag.listDomainAttestationsSince(at - DOMAIN_QUORUM.WINDOW_MS)) {
      const key = claimKey(row);
      if (seen.has(key) || scheduled.has(key)) continue;
      seen.add(key);
      const claim = claimFromTx(dag.getTx(row.tx_id));
      if (!claim || _settled(claim, at)) continue;
      _schedule(claim, 0, 0);
      n++;
    }
    return n;
  }

  function start() {
    reconcile();
    reconcileTimer = setInterval(reconcile, DOMAIN_QUORUM.RECONCILE_MS);
    reconcileTimer.unref?.();
  }

  function stop() {
    stopped = true;
    if (reconcileTimer) clearInterval(reconcileTimer);
    for (const e of scheduled.values()) if (e.timer) clearTimer(e.timer);
    scheduled.clear();
    ready.length = 0;
  }

  async function idle() {
    while (running > 0 || ready.length > 0) await new Promise(r => setImmediate(r));
  }

  return { enqueue, check, reconcile, start, stop, idle };
}

module.exports = { createCoAttest };
