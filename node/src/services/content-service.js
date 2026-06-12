"use strict";

const {
  shake256, perceptualHashText, tipNormalize,
  generateCTID, verifyBodySignature, verifyTxId,
} = require("../../../shared/crypto");
const { nowMs, toIso } = require("../../../shared/time");
const { TX_TYPES, ORIGIN, ORIGIN_LABELS, HTTP_HEADERS, CONTENT_STATUS, PRESCAN_NOTES } = require("../../../shared/constants");
const { VERIFY_CAPS, SCORE_EVENTS, PRESCAN_WORKER } = require("../../../shared/protocol-constants");
const contentRegisterSchema = require("../schemas/content-register");
const contentListSchema = require("../schemas/content-list");
const { schemaError } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId, buildPrescanDescriptor } = require("./helpers");
const contentType = require("./content-type");
// Imported via the module reference (not destructured) so tests can
// jest.spyOn(helpers, "preScanContent") to drive specific tier scenarios.
const helpers = require("./helpers");
const { validate } = require("../middleware/validate");
const { log } = require("../logger");

function createContentService({ dag, scoring, config, submitTx, prescanJobs, mediaService }) {

  // Enqueue the prescan job for the worker. The job payload carries
  // everything the worker needs (text, origin_code, resolved content_type,
  // creator history calibration). Non-OH origins still enqueue — the
  // worker / classifier-client will short-circuit them with prob=0.
  // Enqueue failure is operational, not fatal — registration still
  // succeeds; the failover trigger will eventually pick the content up
  // if PRESCAN_COMPLETED never arrives. No-op when prescanJobs isn't
  // wired (legacy paths / certain test setups).
  function _enqueuePrescanJob({ ctid, content, origin_code, signer_tip_id, ctypeResolution, media }) {
    if (!prescanJobs) return;
    try {
      const verifiedOhCount = dag.getContentByAuthor(signer_tip_id)
        .filter(c => c.origin_code === ORIGIN.OH && c.status === CONTENT_STATUS.VERIFIED)
        .length;
      prescanJobs.enqueue({
        ctid,
        payload: {
          text: content || "",
          origin_code,
          content_type: ctypeResolution.contentType,
          content_type_meta: {
            hint_provided: ctypeResolution.hintProvided || null,
            resolution: ctypeResolution.resolution,
            platform_strategy: ctypeResolution.platformStrategy || null,
          },
          creator_cleared_count: verifiedOhCount,
          author_tip_id: signer_tip_id,
          // M3 — media references (media_id + mime). Worker fetches bytes
          // from mediaStorage at scan time; refs keep the queue row small.
          media: Array.isArray(media) ? media : [],
        },
      });
    } catch (err) {
      log.warn(`prescan-jobs enqueue failed for ${ctid}: ${err.message || err}`);
    }
  }

  async function register(body) {
    contentRegisterSchema.validateRequest(body, { mediaLimits: config.mediaLimits, dag });

    const {
      signer_tip_id, origin_code, content, signature,
    } = body;
    const identity = contentRegisterSchema.resolveSigner(signer_tip_id, dag);

    // M3 — validate each media[] reference exists in storage with matching
    // mime, dedup on media_id, return canonical list for downstream use.
    // Throws 404 / 400 before signature verify so clients see a clear error.
    const resolvedMedia = mediaService
      ? await mediaService.resolveRefs(body.media)
      : (Array.isArray(body.media) ? body.media.map(m => ({ media_id: m.media_id, mime: String(m.mime).toLowerCase() })) : []);

    // CNA-MIX-1: derive the media canonical hash from the resolved media[]
    // when present; fall back to client-supplied legacy field. The derived
    // value MUST match what the client signed — if both are sent and
    // differ, reject as a tampering signal.
    const derivedMch = contentRegisterSchema.mediaCanonicalHash(resolvedMedia);
    if (body.media_canonical_hash && derivedMch && body.media_canonical_hash !== derivedMch) {
      throw schemaError(
        400,
        "media_canonical_hash does not match shake256 of media[].media_id concatenation",
        "media_canonical_hash_mismatch",
      );
    }
    const media_canonical_hash = derivedMch || body.media_canonical_hash || null;

    // The client signs over content_hash, which combines media + text per
    // CNA-MIX-1. Server reproduces the same formula deterministically.
    const textHashFull = content ? shake256(tipNormalize(content)) : shake256("");
    const contentHashFull = media_canonical_hash
      ? shake256(media_canonical_hash + textHashFull)
      : textHashFull;
    // CTID short hash derives from the full canonical hash so it covers
    // every modality (text, media, mixed). Earlier branching on raw inputs
    // collided on same-text-different-media posts. shake256 output is
    // already uniformly distributed hex, so a 14-char prefix is fine.
    const contentHashShort = contentHashFull.slice(0, 14);

    // ── Signature verification ─────────────────────────────────────────────
    const canonicalPayload = contentRegisterSchema.buildSigningPayload(body, contentHashFull);
    if (!contentRegisterSchema.verifySignature(canonicalPayload, signature, identity.public_key)) {
      throw schemaError(403, "Content signature verification failed", "signature_invalid");
    }

    const perceptHash = content ? perceptualHashText(content) : null;

    // ── Async prescan ───────────────────────────────────────────────────
    // Resolve content_type (publisher's signed hint → server-derived from
    // request shape → server validation/auto-correct). Result is recorded
    // on the prescan job's payload and ends up on PRESCAN_COMPLETED later;
    // REGISTER_CONTENT only carries the hint (publisher's declaration).
    const ctypeResolution = contentType.resolve({
      text: content,
      media: resolvedMedia,
      content_type_hint: body.content_type_hint || null,
      // First registered URL drives platform-based resolution
      // (twitter.com → MIXED, youtube.com → video, etc.). See
      // shared/platforms.js for the strategy table.
      registered_url: Array.isArray(canonicalPayload.registered_urls) && canonicalPayload.registered_urls.length > 0
        ? canonicalPayload.registered_urls[0]
        : null,
    });
    const registeredAt = nowMs();
    const ctid = generateCTID(origin_code, contentHashShort, signer_tip_id);

    const { valid, error } = rules.canRegisterContent(dag, { signer_tip_id, ctid, origin_code });
    if (!valid) throw schemaError(error.status, error.message, error.code);

    const assignedNodeId = config.nodeRegisteredId || config.nodeId || null;

    const txBody = {
      tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: {
        // ── Server-derived / informational fields ─────────────────
        // origin_code + content_hash mirror the canonical signed values
        // (verifier needs them on tx.data to rebuild the payload).
        // origin_label is derived at response time from origin_code —
        // not stored on tx.data. author_tip_id is derived at persist
        // time from signer_tip_id — see commit-handler REGISTER_CONTENT.
        ctid, origin_code: canonicalPayload.origin_code,
        content_hash: contentHashFull, perceptual_hash: perceptHash,
        // Async-prescan slots — verdict lands later via PRESCAN_COMPLETED.
        // Defaults match the content row's schema defaults so legacy
        // commit-handler paths keep working.
        prescan_status: "pending",
        prescan_assigned_node_id: assignedNodeId,
        content_type_hint: ctypeResolution.hintProvided || null,
        // Passthrough — clients MAY send override=true as an explicit
        // ack-of-warning signal. Defaults to false when omitted; not
        // gated, so registration succeeds either way. The field is kept
        // on the tx row for now while the post-registration warning UX
        // is being validated end-to-end.
        override: !!body.override,

        // ── CNA-2.2 signed canonical fields (mirror canonicalPayload
        //    so commit-handler can replay buildSigningPayload(d, d.content_hash))
        cna_version: canonicalPayload.cna_version,
        attribution_mode: canonicalPayload.attribution_mode,
        authors: canonicalPayload.authors,
        extras: canonicalPayload.extras,
        registered_urls: canonicalPayload.registered_urls,
        signer_tip_id: canonicalPayload.signer_tip_id,
        // ── M3 media references. Not in the signed payload — content_hash
        //    already commits to media via CNA-MIX-1 (shake256(mch + textHash)).
        //    Persisted on tx.data so commit-handler can mirror onto the
        //    content row and the worker can resolve bytes from storage.
        media: resolvedMedia,
        media_canonical_hash,
      },
      // GH #51 — signer's ML-DSA-65 signature lives at tx.signature.
      signature,
    };
    const signedTx = withTxId(txBody);
    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(signedTx);

    _enqueuePrescanJob({
      ctid, content, origin_code, signer_tip_id, ctypeResolution,
      media: resolvedMedia,
    });

    const status = CONTENT_STATUS.PENDING_PRESCAN;
    log.info(`Content proposed: ${ctid} (origin: ${origin_code}, signer: ${signer_tip_id}, content_type: ${ctypeResolution.contentType})`);

    // Note: direct dag.saveContent happens in commit-handler when the tx
    // commits via consensus. API returns 202-style "proposed" so client
    // knows to expect async finalization.
    return {
      ctid, origin_code, origin_label: ORIGIN_LABELS[origin_code],
      // origin_code at registration is the original (ctid prefix
      // encodes it). origin_changed is always false here — present
      // for symmetry with the resolve() response shape so the FE
      // can branch on a single field on both paths.
      original_origin_code: origin_code,
      origin_changed: false,
      content_hash: contentHashFull, signer_tip_id, tx_id: signedTx.tx_id,
      registered_at: registeredAt, status,
      confirmation: "proposed",
      author_name: identity?.creator_name || null,
      registered_urls: canonicalPayload.registered_urls,
      // ── Async prescan ─────────────────────────────────────────────
      // No verdict yet — client polls the prescan_status endpoint until
      // PRESCAN_COMPLETED commits and the row's prescan_status flips
      // to "completed".
      prescan_status: "pending",
      prescan_poll_url: `/v1/content/${encodeURIComponent(ctid)}/prescan_status`,
      prescan_poll_after_ms: PRESCAN_WORKER.POLL_AFTER_MS,
      prescan_poll_max_attempts: PRESCAN_WORKER.POLL_MAX_ATTEMPTS,
      content_type_hint: ctypeResolution.hintProvided || null,
      http_headers: {
        [HTTP_HEADERS.AUTHOR]: signer_tip_id, [HTTP_HEADERS.CONTENT]: ctid,
        [HTTP_HEADERS.ORIGIN]: ORIGIN_LABELS[origin_code].toLowerCase().replace(/ /g, "-"),
        [HTTP_HEADERS.TRUST_SCORE]: scoring.getScore(signer_tip_id).score.toString(),
        [HTTP_HEADERS.SIGNATURE]: signature,
      },
      meta_tags: {
        "tip:author": signer_tip_id, "tip:content": ctid,
        "tip:origin": ORIGIN_LABELS[origin_code].toLowerCase().replace(/ /g, "-"),
        "tip:score": scoring.getScore(signer_tip_id).score.toString(),
        "tip:status": "PENDING_PRESCAN",
      },
    };
  }

  async function resolve(ctid) {
    const rec = dag.getContent(ctid);
    if (!rec) throw schemaError(404, "Content record not found", "content_not_found");

    // Public storage facts per media item (existence + size + the
    // server-detected mime). Metadata only — the bytes themselves stay
    // behind the role-gated media-access endpoint. Lets any viewer
    // confirm "the referenced object really is held by this node"
    // without revealing content.
    let enrichedMedia = rec.media;
    if (Array.isArray(rec.media) && rec.media.length > 0) {
      // Per-file AI scores from the verdict tx (media_results). The
      // collapsed headline probability lives on the content row; the
      // per-file evidence survives here even after the bytes are
      // retention-deleted or the classifier model moves on.
      const scoreById = new Map();
      const verdicts = dag.getTxsByTypeAndCtid(TX_TYPES.PRESCAN_COMPLETED, ctid);
      const latestVerdict = verdicts.length ? verdicts[verdicts.length - 1] : null;
      for (const mr of latestVerdict?.data?.media_results || []) {
        scoreById.set(mr.media_id, mr);
      }

      enrichedMedia = await Promise.all(rec.media.map(async (m) => {
        const score = scoreById.get(m.media_id);
        const base = {
          ...m,
          ai_probability: score ? score.probability : null,
          ai_provider: score ? score.provider : null,
        };
        if (!mediaService) return { ...base, stored: null, size: null };
        try {
          const head = await mediaService.head(m.media_id);
          return { ...base, stored: !!head?.exists, size: head?.exists ? head.size : null };
        } catch {
          return { ...base, stored: null, size: null };
        }
      }));
    }

    const tx = rec.tx_id ? dag.getTx(rec.tx_id) : null;
    const txValid = tx ? verifyTxId(tx) : false;
    const prevValid = tx && tx.prev ? tx.prev.every(p => !!dag.getTx(p)) : false;
    const author = dag.getIdentity(rec.author_tip_id);
    const revocation = dag.getRevocation(rec.author_tip_id);
    const authorValid = !!author && author.status === "active" && !revocation;
    const authorRevocation = _buildAuthorRevocation(revocation);

    const verifyCount = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_VERIFIED, ctid).length;
    const disputeCount = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid).length;

    // The ctid embeds the original origin_code at registration time
    // (see crypto.generateCTID). That's an immutable record of what
    // the creator first declared, even after UPDATE_ORIGIN rewrites
    // the row's origin_code. The FE uses `origin_changed` to suppress
    // the prescan warning banner and disable the change-origin CTA.
    const ctidOriginMatch = typeof rec.ctid === "string" ? rec.ctid.match(/^tip:\/\/c\/([A-Z]+)-/) : null;
    const originalOriginCode = ctidOriginMatch ? ctidOriginMatch[1] : null;
    const originChanged = !!originalOriginCode && originalOriginCode !== rec.origin_code;

    return {
      ...rec,
      media: enrichedMedia,
      origin_label: ORIGIN_LABELS[rec.origin_code] || rec.origin_code,
      original_origin_code: originalOriginCode,
      origin_changed: originChanged,
      author_name: (author && author.creator_name) || null,
      author_score: scoring.getScore(rec.author_tip_id).score,
      author_tier: scoring.getScore(rec.author_tip_id).tier.name,
      verify_count: verifyCount,
      dispute_count: disputeCount,
      verification: {
        tx_exists: !!tx, tx_id_valid: txValid, prev_valid: prevValid,
        author_valid: authorValid, author_revocation: authorRevocation, on_dag: true,
      },
      review_history: _projectReviewHistory(ctid),
      appeal_pending: _isAppealPending(ctid),
      prescan: buildPrescanDescriptor({
        preScan: {
          tier: rec.prescan_tier,
          probability: rec.prescan_probability,
          flagged: rec.prescan_flagged,
        },
        originCode: rec.origin_code,
        registeredAt: rec.registered_at,
        originChanged,
      }),
      prescan_note: PRESCAN_NOTES[rec.prescan_tier] || null,
      consensus: { available: false, status: "not_requested" },
    };
  }

  /**
   * Latest prescan-review row + counts for this ctid. content.status
   * already covers REGISTERED / PENDING_REVIEW / DISPUTED / VERIFIED /
   * RETRACTED — this surfaces the orthogonal "did a reviewer engage,
   * and what did they decide?" signal so clients can render
   * vindication ("cleared after review") vs. self-correct vs. accepted
   * privately without recomputing from raw txs.
   *
   * Returns { total, latest: { ... } | null } — `latest` is null when
   * no review has ever existed for the ctid.
   */
  // Lift the per-author revocation record into a read-time descriptor
  // for content consumers. Returns null when the author is not revoked.
  // reason_code / evidence_hash live on the source REVOKE_* tx (kept off
  // the canonical revocations row to avoid expanding state_merkle_root),
  // so we join through tx_id to surface them.
  function _buildAuthorRevocation(revocation) {
    if (!revocation) return null;
    const srcTx = revocation.tx_id ? dag.getTx(revocation.tx_id) : null;
    const d = srcTx && srcTx.data ? srcTx.data : {};
    return {
      tx_type: revocation.tx_type,
      reason_code: d.reason_code || null,
      evidence_hash: d.evidence_hash || null,
      issuing_vp_id: d.issuing_vp_id || null,
      revoked_at: revocation.timestamp,
      tx_id: revocation.tx_id,
    };
  }

  function _projectReviewHistory(ctid) {
    const reviews = typeof dag.getPrescanReviewsByCtid === "function"
      ? dag.getPrescanReviewsByCtid(ctid)
      : [];
    if (!reviews || reviews.length === 0) {
      return { total: 0, latest: null };
    }
    // getPrescanReviewsByCtid is sorted DESC by triggered_at_round.
    const r = reviews[0];
    return {
      total: reviews.length,
      latest: {
        review_id: r.review_id,
        state: r.state,
        assigned_reviewer: r.assigned_reviewer,
        triggered_at_round: r.triggered_at_round,
        decided_at_round: r.decided_at_round,
        confirmed_at_round: r.confirmed_at_round,
        confirmed_at_ms: r.confirmed_at_ms,
        decision_note: r.decision_note,
        suggested_origin: r.suggested_origin,
      },
    };
  }

  // Surface "appeal pending" as a separate signal from content.status so
  // the FE can render a Stage-3-in-progress badge without us mutating the
  // canonical status away from what Stage-2 already bound. True when an
  // APPEAL_FILED tx exists for this ctid without a matching APPEAL_RESULT.
  function _isAppealPending(ctid) {
    const filed = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid);
    if (!filed || filed.length === 0) return false;
    const resolved = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_RESULT, ctid);
    return filed.length > resolved.length;
  }

  function verify(ctid, body) {
    validate(body, { verifier_tip_id: { required: true }, signature: { required: true } });
    const { verifier_tip_id, verdict, signature } = body;

    // Stateful pre-conditions — same predicate as commit-handler.
    const { valid, error } = rules.canVerify(dag, { ctid, verifier_tip_id });
    if (!valid) throw schemaError(error.status, error.message, error.code);
    const rec = dag.getContent(ctid);
    const verifier = dag.getIdentity(verifier_tip_id);

    // Bind the signature to the specific ctid being acted on. The
    // ctid lives in the URL; we inject it into the body before
    // verification so a captured signature can't be replayed against
    // a different ctid owned by the same verifier.
    const VERIFY_FIELDS = ["verifier_tip_id", "ctid", "verdict"];
    const verifyPayload = { ...body, ctid };
    if (!verifyBodySignature(verifyPayload, signature, verifier.public_key, VERIFY_FIELDS)) {
      throw schemaError(403, "Verifier signature verification failed", "signature_invalid");
    }

    // Caps — UTC day/month boundaries (operational, not chain-canonical).
    // Direct ms arithmetic avoids the JS Date constructor (timestamp policy:
    // production code routes through shared/time.js helpers only). Month
    // start derives from `toIso(now).slice(8,10)` (day-of-month "DD") so
    // variable month lengths and leap years are correct without a Date()
    // constructor call.
    const allVerifyTxs = dag.getTxsByType(TX_TYPES.CONTENT_VERIFIED);
    const authorTipId = rec.author_tip_id;
    const MS_PER_DAY = 86_400_000;
    const now = nowMs();
    const dayStart = now - (now % MS_PER_DAY);
    const dayOfMonth = Number(toIso(now).slice(8, 10));
    const monthStart = dayStart - (dayOfMonth - 1) * MS_PER_DAY;

    const contentDeltaSum = allVerifyTxs.filter(t => t.data?.ctid === ctid).reduce((s, t) => s + (t.data?.weighted_delta || 0), 0);
    const dailyDeltaSum = allVerifyTxs.filter(t => t.data?.author_tip_id === authorTipId && t.timestamp >= dayStart).reduce((s, t) => s + (t.data?.weighted_delta || 0), 0);
    const monthlyDeltaSum = allVerifyTxs.filter(t => t.data?.author_tip_id === authorTipId && t.timestamp >= monthStart).reduce((s, t) => s + (t.data?.weighted_delta || 0), 0);

    const verifierScore = scoring.getScore(verifier_tip_id).score;
    let weightedDelta = verifierScore >= VERIFY_CAPS.HIGH_TRUST_MIN ? VERIFY_CAPS.HIGH_TRUST_DELTA : VERIFY_CAPS.BASE_DELTA;
    weightedDelta = Math.min(weightedDelta,
      Math.max(0, VERIFY_CAPS.PER_CONTENT - contentDeltaSum),
      Math.max(0, VERIFY_CAPS.PER_DAY - dailyDeltaSum),
      Math.max(0, VERIFY_CAPS.PER_MONTH - monthlyDeltaSum));

    const verifyTxTimestamp = nowMs();
    const verifyTxBody = {
      tx_type: TX_TYPES.CONTENT_VERIFIED, timestamp: verifyTxTimestamp, prev: dag.getRecentPrev(),
      data: { ctid, verifier_tip_id, verdict: verdict || "ORIGIN_CONFIRMED", weighted_delta: weightedDelta, author_tip_id: authorTipId },
      signature,
    };
    const signedTx = withTxId(verifyTxBody);
    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(signedTx);

    // Paired score-effect (single-channel rule): the CONTENT_VERIFIED tx
    // owns the verification record; this SCORE_UPDATE owns the score
    // delta. Submitted right after so they land in the same anchor commit.
    if (weightedDelta > 0 && authorTipId) {
      const scoreTx = scoring.buildScoreUpdateTx({
        tipId: authorTipId, delta: weightedDelta,
        reason: `Content verified (${ctid})`,
        ctid, relatedTxId: signedTx.tx_id,
        timestamp: verifyTxTimestamp,
        getRecentPrev: () => dag.getRecentPrev(),
        config,
      });
      submitTx(scoreTx);
    }

    return {
      success: true, delta_applied: weightedDelta,
      confirmation: "proposed",
      caps: {
        content: { used: contentDeltaSum + weightedDelta, max: VERIFY_CAPS.PER_CONTENT },
        daily: { used: dailyDeltaSum + weightedDelta, max: VERIFY_CAPS.PER_DAY },
        monthly: { used: monthlyDeltaSum + weightedDelta, max: VERIFY_CAPS.PER_MONTH },
      },
    };
  }

  function updateOrigin(ctid, body) {
    validate(body, { author_tip_id: { required: true }, new_origin_code: { required: true }, signature: { required: true } });
    const { author_tip_id, new_origin_code, signature } = body;

    // Stateful + time-window pre-conditions. Time-window uses nowMs()
    // at API call; commit-handler re-checks with cert.timestamp.
    const { valid, error } = rules.canUpdateOrigin(dag, { ctid, author_tip_id, new_origin_code }, { now: nowMs() });
    if (!valid) throw schemaError(error.status, error.message, error.code);
    const rec = dag.getContent(ctid);
    const author = dag.getIdentity(author_tip_id);

    // Bind the signature to the specific ctid being acted on (replay
    // protection — see verify() above for the same pattern).
    const UPDATE_FIELDS = ["author_tip_id", "ctid", "new_origin_code"];
    const updatePayload = { ...body, ctid };
    if (!verifyBodySignature(updatePayload, signature, author.public_key, UPDATE_FIELDS)) {
      throw schemaError(403, "Author signature verification failed", "signature_invalid");
    }

    const updateTx = withTxId({
      tx_type: TX_TYPES.UPDATE_ORIGIN, timestamp: nowMs(), prev: dag.getRecentPrev(),
      data: { ctid, old_origin_code: rec.origin_code, new_origin_code, author_tip_id },
      signature,
    });
    submitTx(updateTx);

    log.info(`Origin update proposed: ${ctid} ${rec.origin_code} → ${new_origin_code} (by ${author_tip_id})`);
    return { success: true, ctid, old_origin_code: rec.origin_code, new_origin_code, tx_id: updateTx.tx_id, confirmation: "proposed" };
  }

  function retract(ctid, body) {
    validate(body, { author_tip_id: { required: true }, signature: { required: true } });
    const { author_tip_id, signature } = body;

    const { valid, error } = rules.canRetract(dag, { ctid, author_tip_id });
    if (!valid) throw schemaError(error.status, error.message, error.code);
    const rec = dag.getContent(ctid);
    const author = dag.getIdentity(author_tip_id);

    // Bind the signature to the specific ctid being retracted (replay
    // protection — see verify() above for the same pattern).
    const retractPayload = { ...body, ctid };
    if (!verifyBodySignature(retractPayload, signature, author.public_key, ["author_tip_id", "ctid"])) {
      throw schemaError(403, "Author signature verification failed", "signature_invalid");
    }

    const retractTimestamp = nowMs();
    const retractTx = withTxId({
      tx_type: TX_TYPES.CONTENT_RETRACTED, timestamp: retractTimestamp, prev: dag.getRecentPrev(),
      data: { ctid, author_tip_id, origin_code: rec.origin_code, pre_retract_status: rec.status },
      signature,
    });
    submitTx(retractTx);

    // Paired score-effect (single-channel rule): retraction record on
    // CONTENT_RETRACTED, score delta on SCORE_UPDATE. Submitted together
    // so they land in the same anchor commit.
    const scoreTx = scoring.buildScoreUpdateTx({
      tipId: author_tip_id, delta: SCORE_EVENTS.CONTENT_RETRACTION.delta,
      reason: `Content retracted (${ctid})`,
      ctid, relatedTxId: retractTx.tx_id,
      timestamp: retractTimestamp,
      getRecentPrev: () => dag.getRecentPrev(),
      config,
    });
    submitTx(scoreTx);

    log.info(`Content retraction proposed: ${ctid} by ${author_tip_id}`);
    return { success: true, ctid, penalty: SCORE_EVENTS.CONTENT_RETRACTION.delta, tx_id: retractTx.tx_id, confirmation: "proposed" };
  }

  /**
   * Lightweight poll endpoint backing GET /v1/content/:ctid/prescan_status.
   * Returns just the prescan verdict fields the client needs to render the
   * pending → completed transition, without paying the cost of the full
   * resolve() projection.
   *
   * - 404 when the content row doesn't exist
   * - { prescan_status: "pending" } until PRESCAN_COMPLETED applies
   * - full verdict shape once the row's prescan_status === "completed"
   */
  function getPrescanStatus(ctid) {
    const rec = dag.getContent(ctid);
    if (!rec) throw schemaError(404, "Content record not found", "content_not_found");

    const status = rec.prescan_status || "completed";
    if (status !== "completed") {
      return { ctid, prescan_status: status };
    }
    return {
      ctid,
      prescan_status: "completed",
      prescan_flagged: !!rec.prescan_flagged,
      prescan_probability: typeof rec.prescan_probability === "number" ? rec.prescan_probability : 0,
      prescan_tier: rec.prescan_tier || "low",
      prescan_completed_at: rec.prescan_completed_at ?? null,
      prescan_content_type: rec.prescan_content_type || null,
      prescan_overall_degraded: !!rec.prescan_overall_degraded,
    };
  }

  // Explorer list — slim rows, cursor-paginated, newest first. Heavy
  // fields (authors[], extras, media[]) stay out of list rows; clients
  // follow the ctid to resolve() for the full record.
  function list(query) {
    const opts = contentListSchema.validateRequest(query);
    const rows = dag.listContent(opts);
    const hasMore = rows.length > opts.limit;
    const page = hasMore ? rows.slice(0, opts.limit) : rows;
    const items = page.map(c => ({
      ctid: c.ctid,
      author_tip_id: c.author_tip_id,
      origin_code: c.origin_code,
      status: c.status,
      prescan_status: c.prescan_status,
      prescan_tier: c.prescan_tier,
      media_count: Array.isArray(c.media) ? c.media.length : 0,
      registered_urls: Array.isArray(c.registered_urls) ? c.registered_urls : [],
      registered_at: c.registered_at,
    }));
    const next_cursor = hasMore ? contentListSchema.encodeCursor(page[page.length - 1]) : null;
    return { items, next_cursor };
  }

  return { register, resolve, list, verify, updateOrigin, retract, getPrescanStatus };
}

module.exports = { createContentService };
