"use strict";

const {
  shake256, generateTIPID, verifyTxId,
} = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { verifyDedupProof } = require("../../../shared/zk");
const { TX_TYPES, TX_TYPE_SET } = require("../../../shared/constants");
const { SCORE, SOCIAL_LINK } = require("../../../shared/protocol-constants");
const registerIdentitySchema = require("../schemas/register-identity");
const linkPlatformSchema = require("../schemas/link-platform");
const unlinkPlatformSchema = require("../schemas/unlink-platform");
const registerSocialSchema = require("../schemas/register-social");
const bioFetcher = require("./bio-fetcher");
const { schemaError, verifyPayload } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const { validate } = require("../middleware/validate");
const { log } = require("../logger");

const ACTIVITY_DEFAULT_LIMIT = 50;
const ACTIVITY_MAX_LIMIT = 200;

const CLAIM_MAX_AGE_MS = 15 * 60 * 1000; // 15 minutes — replay-attack window

// profile_url must match at least one pattern for the stated platform.
const ALLOWED_PLATFORMS = {
  twitter:    [/^https?:\/\/(www\.)?(twitter|x)\.com\/[^/?#]/i],
  x:          [/^https?:\/\/(www\.)?(twitter|x)\.com\/[^/?#]/i],
  linkedin:   [/^https?:\/\/(www\.)?linkedin\.com\/in\/[^/?#]/i],
  youtube:    [/^https?:\/\/(www\.)?youtube\.com\/@[^/?#]/i,
               /^https?:\/\/(www\.)?youtube\.com\/c\/[^/?#]/i,
               /^https?:\/\/(www\.)?youtube\.com\/channel\/[^/?#]/i],
  facebook:   [/^https?:\/\/(www\.)?facebook\.com\/[^/?#]/i],
  instagram:  [/^https?:\/\/(www\.)?instagram\.com\/[^/?#]/i],
  reddit:     [/^https?:\/\/(www\.)?reddit\.com\/u(?:ser)?\/[^/?#]/i],
  github:     [/^https?:\/\/(www\.)?github\.com\/[^/?#]/i],
  medium:     [/^https?:\/\/(www\.)?medium\.com\/@[^/?#]/i,
               /^https?:\/\/[^.]+\.medium\.com/i],
  soundcloud: [/^https?:\/\/(www\.)?soundcloud\.com\/[^/?#]/i],
  tiktok:     [/^https?:\/\/(www\.)?tiktok\.com\/@[^/?#]/i],
  spotify:    [/^https?:\/\/open\.spotify\.com\/[^/?#]/i],
  substack:   [/^https?:\/\/[^.]+\.substack\.com/i],
  devto:      [/^https?:\/\/(www\.)?dev\.to\/[^/?#]/i],
  bluesky:    [/^https?:\/\/bsky\.app\/profile\/[^/?#]/i],
  threads:    [/^https?:\/\/(www\.)?threads\.net\/@[^/?#]/i],
  mastodon:   [/^https?:\/\/[^/]+\/@[^/?#]/i],
};

// These platforms render bios with JavaScript or are login-gated — static
// HTML scraping cannot verify ownership. Must use VP OAuth proof.
const OAUTH_REQUIRED_PLATFORMS = new Set([
  "twitter", "x", "instagram", "tiktok", "threads", "facebook", "linkedin", "youtube",
]);

// Statuses the activity feed can include. Default is "committed" only —
// preserves back-compat for clients that pre-date the no-loss work.
const ACTIVITY_STATUSES = Object.freeze(["committed", "pending", "rejected"]);

function parseActivityQuery(query) {
  let limit = ACTIVITY_DEFAULT_LIMIT;
  if (query.limit !== undefined) {
    const n = Number(query.limit);
    if (!Number.isInteger(n) || n < 1 || n > ACTIVITY_MAX_LIMIT) {
      throw { status: 400, error: `limit must be an integer between 1 and ${ACTIVITY_MAX_LIMIT}` };
    }
    limit = n;
  }

  let before = null;
  if (query.before) {
    const t = query.before;
    if (Number.isNaN(t)) throw { status: 400, error: "before must be a valid ISO 8601 timestamp" };
    before = t;
  }

  let types = null;
  if (query.types) {
    const list = String(query.types).split(",").map(s => s.trim()).filter(Boolean);
    const invalid = list.filter(t => !TX_TYPE_SET.has(t));
    if (invalid.length) throw { status: 400, error: `Unknown tx_type(s): ${invalid.join(", ")}` };
    if (list.length) types = new Set(list);
  }

  // ?include=committed,pending,rejected — opt-in to merge pending +
  // rejected streams into the feed. Default = committed only so
  // existing clients see no behavior change.
  let include = new Set(["committed"]);
  if (query.include) {
    const list = String(query.include).split(",").map(s => s.trim()).filter(Boolean);
    const invalid = list.filter(s => !ACTIVITY_STATUSES.includes(s));
    if (invalid.length) throw { status: 400, error: `Unknown status(es): ${invalid.join(", ")}. Allowed: ${ACTIVITY_STATUSES.join(", ")}` };
    include = new Set(list);
  }

  return { limit, before, types, include };
}

// Project a raw tx into a UI-shaped activity item: trims tx-internal fields
// (signatures, prev refs, dedup_hash, zk_proof) that the timeline doesn't
// need, surfaces the role this tip_id played in the tx, and keeps ctid +
// origin_code / status / delta / reason where present so the UI can render
// "Registered content X", "Verified Y", "Score +5 for Z" without a second call.
//
// `status` here is the lifecycle status (committed | pending | rejected),
// distinct from the `data.status` field on some tx types — the UI needs
// both so it can render "Pending: Verify content X" or
// "Rejected: Identity already registered".
function projectActivityItem(tx, tipId, status, extra = {}) {
  const d = tx.data || {};
  // Broader role set now that activity includes verifier/juror/etc. We
  // surface the single most-specific role for display; the UI can
  // ignore it but the field name lets a feed renderer template differently.
  let role = "other";
  if (d.tip_id === tipId) role = "subject";
  // signer_tip_id is the CNA-2.2 canonical field on REGISTER_CONTENT;
  // author_tip_id remains the field name on UPDATE_ORIGIN /
  // CONTENT_RETRACTED / ADJUDICATION_RESULT. Both map to the "author"
  // role for activity-feed display purposes.
  else if (d.signer_tip_id === tipId || d.author_tip_id === tipId) role = "author";
  else if (d.verifier_tip_id === tipId) role = "verifier";
  else if (d.disputer_tip_id === tipId) role = "disputer";
  else if (d.juror_tip_id === tipId) role = "juror";
  else if (d.appellant_tip_id === tipId) role = "appellant";

  return {
    tx_id: tx.tx_id,
    tx_type: tx.tx_type,
    timestamp: tx.timestamp,
    status,                                            // committed | pending | rejected
    role,
    ctid: d.ctid || null,
    origin_code: d.origin_code || null,
    data_status: d.status || null,                     // tx.data.status (verified/disputed/etc.)
    delta: typeof d.delta === "number" ? d.delta : null,
    reason: d.reason || null,
    related_tx_id: d.related_tx_id || null,
    ...extra,                                          // rejection-only fields injected by caller
  };
}

function createIdentityService({ dag, scoring, config, submitTx }) {

  async function register(body) {
    // GH #51 — accept both legacy `vp_signature` (current WP plugin /
    // VP app shape) and the new top-level `signature` so new clients
    // can opt into the unified wire format without a server change.
    // Service-side path is uniform from here on.
    const normalisedBody = (body && typeof body === "object")
      ? { ...body, vp_signature: body.vp_signature || body.signature }
      : body;

    // Single envelope gate — schemas/register-identity owns shape + DAG
    // presence (VP must exist and be active). Spec: §1 of the
    // register-identity schema module.
    registerIdentitySchema.validateRequest(normalisedBody, { dag });

    const {
      public_key, dedup_hash, zk_proof, vp_id, vp_signature,
    } = normalisedBody;

    const region = typeof normalisedBody.region === "string" ? normalisedBody.region.toUpperCase() : "US";
    const tipId = generateTIPID(region, public_key);

    const { valid, error } = rules.canRegisterIdentity(dag, { tip_id: tipId, dedup_hash, vp_id });
    if (!valid) {
      const code = error.message.startsWith("Identity already") || error.message.startsWith("TIP-ID")
        ? "DUPLICATE_IDENTITY"
        : error.code;
      const e = schemaError(error.status, error.message, code);
      // Surface the existing tip_id on duplicate-registration so the FE can
      // pivot to the recovery flow (POST /v1/identity/:tipId/keys/recover)
      // without a separate by-dedup-hash lookup round-trip.
      if (code === "DUPLICATE_IDENTITY" && typeof dag.getDedupRegistration === "function") {
        const existing = dag.getDedupRegistration(dedup_hash);
        if (existing && existing.tip_id) {
          e.details = { tip_id: existing.tip_id };
        }
      }
      throw e;
    }

    // Build the canonical signed payload, verify the VP's signature
    // over it. canonicalPayload is also written verbatim onto tx.data
    // (mirroring CNA-2.2 content-register pattern) so commit-handler
    // can replay buildSigningPayload(d) deterministically.
    const canonicalPayload = registerIdentitySchema.buildSigningPayload(normalisedBody);
    const vp = registerIdentitySchema.resolveVP(vp_id, dag);
    if (!registerIdentitySchema.verifySignature(canonicalPayload, vp_signature, vp.public_key)) {
      throw schemaError(403, "VP signature verification failed", "signature_invalid");
    }

    const proofValid = await verifyDedupProof(dedup_hash, zk_proof);
    if (!proofValid) throw schemaError(400, "ZK proof verification failed", "zk_proof_invalid");

    const registeredAt = nowMs();
    const founding = false;

    const txBody = {
      tx_type: TX_TYPES.REGISTER_IDENTITY, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: {
        // ── Server-derived / tx-level fields ──────────────────────
        tip_id: tipId,
        founding,
        // ── Signed canonical fields (mirror canonicalPayload so
        //    commit-handler can replay buildSigningPayload(d))
        algorithm: canonicalPayload.algorithm,
        creator_name: canonicalPayload.creator_name,
        dedup_hash: canonicalPayload.dedup_hash,
        public_key: canonicalPayload.public_key,
        region: canonicalPayload.region,
        social_attested: canonicalPayload.social_attested,
        tip_id_type: canonicalPayload.tip_id_type,
        verification_tier: canonicalPayload.verification_tier,
        vp_id: canonicalPayload.vp_id,
        zk_proof: canonicalPayload.zk_proof,
      },
      // GH #51 — VP signature lives at tx.signature (unified storage).
      signature: vp_signature,
    };
    const signedTx = withTxId(txBody);

    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(signedTx);
    log.info(`Identity proposed: ${tipId} (type: ${canonicalPayload.tip_id_type}, tier: ${canonicalPayload.verification_tier}, vp: ${vp_id})`);

    // Note: direct dag.saveIdentity / addDedupHash / setScore happen in
    // commit-handler when the tx commits via consensus. API returns 202-style
    // "proposed" so client knows to expect async finalization.
    return {
      tip_id: tipId, public_key, tx_id: signedTx.tx_id,
      tip_id_type: canonicalPayload.tip_id_type,
      score: SCORE.INITIAL_IDENTITY, registered_at: registeredAt,
      confirmation: "proposed",
      ...(canonicalPayload.creator_name ? { creator_name: canonicalPayload.creator_name } : {}),
    };
  }

  function resolve(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const scoreData = scoring.getScore(tipId);
    const content = dag.getContentByAuthor(tipId);
    const revoked = dag.isRevoked(tipId);
    const tx = rec.tx_id ? dag.getTx(rec.tx_id) : null;
    const txValid = tx ? verifyTxId(tx) : false;
    const prevValid = tx && tx.prev ? tx.prev.every(p => !!dag.getTx(p)) : false;

    return {
      tip_id: rec.tip_id, region: rec.region, public_key: rec.public_key,
      vp_id: rec.vp_id, verification_tier: rec.verification_tier, founding: rec.founding,
      status: revoked ? "revoked" : rec.status, score: scoreData.score,
      tier: scoreData.tier.name, tier_color: scoreData.tier.color,
      content_count: content.length, registered_at: rec.registered_at,
      creator_name: rec.creator_name || null,
      verification: { tx_exists: !!tx, tx_id_valid: txValid, prev_valid: prevValid, on_dag: true },
    };
  }

  // Ownership-proof: client signs the canonical payload { challenge, tip_id }
  // (alphabetical key order, SHAKE-256 → ASCII-hex bytes → ML-DSA-65) —
  // same canonical-payload pattern the rest of the protocol uses.
  //
  // Binding `tip_id` into the signed bytes prevents a signature from being
  // replayed against a different TIP-ID (the old raw-challenge signing
  // had no such binding — a captured signature was valid for any TIP-ID
  // sharing the public key).
  function verifyOwnership(body) {
    validate(body, { tip_id: { required: true }, challenge: { required: true }, signature: { required: true } });
    const { tip_id, challenge, signature } = body;

    const identity = dag.getIdentity(tip_id);
    if (!identity) throw schemaError(404, "TIP-ID not found", "tip_id_not_found");
    if (dag.isRevoked(tip_id)) throw schemaError(403, "TIP-ID is revoked", "tip_id_revoked");

    const canonicalPayload = { challenge, tip_id };
    const valid = verifyPayload(canonicalPayload, signature, identity.public_key);
    if (!valid) throw schemaError(403, "Signature verification failed — you do not own this TIP-ID", "signature_invalid");

    const scoreData = scoring.getScore(tip_id);
    return {
      verified: true,
      tip_id,
      tip_id_type: identity.tip_id_type || "personal",
      verification_tier: identity.verification_tier || "T1",
      region: identity.region || "US",
      vp_id: identity.vp_id || null,
      founding: !!identity.founding,
      creator_name: identity.creator_name || null,
      score: scoreData.score,
      tier: scoreData.tier.name,
      status: identity.status,
    };
  }

  function getScore(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const { score, tier, offense_count } = scoring.getScore(tipId);
    const displayMode = rec.score_display_mode || "TIER_ONLY";

    return {
      tip_id: tipId, tier: tier.name, tier_label: tier.label, tier_color: tier.color,
      verified_since: rec.registered_at, content_count: dag.getContentByAuthor(tipId).length,
      status: dag.isRevoked(tipId) ? "revoked" : rec.status,
      creator_name: rec.creator_name || null,
      ...(displayMode === "FULL_PUBLIC" ? { score, offense_count } : {}),
    };
  }

  function getHistory(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const { score, tier, offense_count, history } = scoring.computeScore(tipId);
    return {
      tip_id: tipId, creator_name: rec.creator_name || null,
      score, tier: tier.name, offense_count, history,
    };
  }

  // Full per-identity activity feed: every tx where tipId played any
  // role (subject, author, verifier, disputer, juror, appellant) as
  // attributed by tx-attribution.subjectTipId. Distinct from getHistory()
  // which returns only score-affecting txs filtered through
  // `scoreTargetTipId` (narrower — only tip_id || author_tip_id).
  //
  // ?include=committed,pending,rejected merges in still-pending and
  // dropped txs from the mempool + tx_rejections tables so the UI can
  // show one consolidated "what happened to my submissions" view.
  // Default = committed only for back-compat.
  function getActivity(tipId, query = {}) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const { limit, before, types, include } = parseActivityQuery(query);
    const beforeMs = before ? before : null;
    const inWindow = (ts) => beforeMs == null || ts < beforeMs;
    const typeAllowed = (t) => !types || types.has(t);

    // Collect items from each requested stream. Each item carries its
    // lifecycle status so the UI can render appropriately.
    const items = [];

    if (include.has("committed")) {
      for (const tx of dag.getTxsBySubject(tipId)) {
        if (!typeAllowed(tx.tx_type)) continue;
        if (!inWindow(tx.timestamp)) continue;
        items.push(projectActivityItem(tx, tipId, "committed"));
      }
    }

    if (include.has("pending") && typeof dag.getMempoolTxsByTipId === "function") {
      for (const tx of dag.getMempoolTxsByTipId(tipId)) {
        if (!typeAllowed(tx.tx_type)) continue;
        if (!inWindow(tx.timestamp)) continue;
        items.push(projectActivityItem(tx, tipId, "pending"));
      }
    }

    if (include.has("rejected") && typeof dag.getTxRejectionsByTipId === "function") {
      for (const row of dag.getTxRejectionsByTipId(tipId)) {
        if (!typeAllowed(row.tx_type)) continue;
        // Rejected rows carry their own timestamp surrogate
        // (rejected_at_ms). Use the original tx timestamp when the
        // body is preserved (typical case); fall back to rejection
        // wall-clock so the entry still slots into the timeline.
        const tx = row.tx_data || { tx_id: row.tx_id, tx_type: row.tx_type, timestamp: row.rejected_at_ms, data: {} };
        if (!inWindow(tx.timestamp)) continue;
        items.push(projectActivityItem(tx, tipId, "rejected", {
          reason: row.reason,
          reason_detail: row.reason_detail,
          rejected_at: row.rejected_at_ms,
          rejected_at_round: row.rejected_at_round,
        }));
      }
    }

    // Canonical activity order — strict reverse-chronological:
    //   1. timestamp DESC                  — newer batch on top
    //   2. SCORE_UPDATE before anchor       — within a same-batch tie, the
    //                                         side-effect shows above its
    //                                         trigger because it's the
    //                                         logically-latest event in the
    //                                         causal chain ("latest on top"
    //                                         applies uniformly)
    //   3. tx_id DESC                       — final deterministic tie-break,
    //                                         stable across calls
    // Same rule mirrored in MemoryStore.getTxsBySubject and the SQL
    // ORDER BY — single source of truth.
    items.sort((a, b) => {
      // Coerce — see MemoryStore.getTxsBySubject. PG returns bigint as
      // string by default; mixed-type subtraction yields NaN which V8
      // treats as "don't swap" and the feed drifts out of order.
      const d = Number(b.timestamp) - Number(a.timestamp);
      if (d !== 0) return d;
      const ap = a.tx_type === "SCORE_UPDATE" ? 0 : 1;
      const bp = b.tx_type === "SCORE_UPDATE" ? 0 : 1;
      if (ap !== bp) return ap - bp;
      return a.tx_id < b.tx_id ? 1 : -1;
    });

    const total = items.length;
    const page = items.slice(0, limit);
    const nextCursor = page.length === limit && total > limit
      ? page[page.length - 1].timestamp
      : null;

    return {
      tip_id: tipId,
      creator_name: rec.creator_name || null,
      total,
      count: page.length,
      next_cursor: nextCursor,
      items: page,
    };
  }

  // GH #60 — public hash→tip_id lookup. Used by VP backends + FE clients
  // to decide between registration and recovery flows when the user
  // re-presents the same gov-id-derived dedup_hash. The dedup_hash is
  // already public on-chain (carried in REGISTER_IDENTITY tx.data), so
  // exposing it as an indexed lookup leaks no additional information.
  function findByDedupHash(dedupHash) {
    if (typeof dedupHash !== "string" || dedupHash.length === 0) {
      throw { status: 400, error: "dedup_hash is required" };
    }
    const rec = typeof dag.getDedupRegistration === "function" ? dag.getDedupRegistration(dedupHash) : null;
    if (!rec || !rec.tip_id) throw { status: 404, error: "no identity registered for this dedup_hash" };
    const identity = dag.getIdentity(rec.tip_id);
    if (!identity) throw { status: 404, error: "identity row missing for dedup_hash" };
    return {
      tip_id: identity.tip_id,
      vp_id: identity.vp_id,
      region: identity.region,
      verification_tier: identity.verification_tier,
      registered_at: identity.registered_at,
      status: dag.isRevoked(identity.tip_id) ? "revoked" : identity.status,
    };
  }

  async function linkPlatform({ tipId, platform, profileUrl, claimSignature, claimedAt, vpId, vpOauthSignature, vpOauthHandle, vpOauthVerifiedAt }) {
    if (!tipId || !platform || !profileUrl || !claimSignature || !claimedAt) {
      throw schemaError(400, "tipId, platform, profileUrl, claimSignature, claimedAt are required", "missing_fields");
    }

    const platformKey = platform.toLowerCase();
    const platformPatterns = ALLOWED_PLATFORMS[platformKey];
    if (!platformPatterns) {
      throw schemaError(400, `Unknown or unsupported platform: "${platform}"`, "unknown_platform");
    }
    if (!platformPatterns.some(re => re.test(profileUrl))) {
      throw schemaError(400, `profile_url does not match expected domain for platform "${platform}"`, "invalid_profile_url");
    }
    if (nowMs() - claimedAt > CLAIM_MAX_AGE_MS) {
      throw schemaError(400, "Claim has expired (max 15 minutes)", "claim_expired");
    }
    if (OAUTH_REQUIRED_PLATFORMS.has(platformKey) && !(vpOauthSignature && vpId)) {
      throw schemaError(403, `Platform "${platform}" requires VP OAuth verification`, "oauth_required");
    }

    const identity = dag.getIdentity(tipId);
    if (!identity) throw schemaError(412, `TIP-ID not found: ${tipId}`, "tip_id_not_found");

    const existingLink = dag.getPlatformLink(tipId, platform);
    if (existingLink && existingLink.status === "active") {
      throw schemaError(409, `Platform "${platform}" already linked for ${tipId}`, "platform_already_linked");
    }
    // Also block if there is a pending LINK_PLATFORM in mempool (not yet committed)
    const pending = typeof dag.getMempoolTxsByTipId === "function"
      ? dag.getMempoolTxsByTipId(tipId).filter(t => t.tx_type === TX_TYPES.LINK_PLATFORM && t.data?.platform === platform)
      : [];
    if (pending.length > 0) {
      throw schemaError(409, `Platform "${platform}" already linked for ${tipId}`, "platform_already_linked");
    }
    const existingLinkTxs = dag.getTxsByTipId(tipId).filter(t => t.tx_type === TX_TYPES.LINK_PLATFORM);
    // A re-link is when this specific platform already has a committed LINK_PLATFORM tx.
    // Re-links are allowed (after unlink) but never earn another +5.
    const isRelink = existingLinkTxs.some(t => t.data?.platform === platform);
    // Cap is per unique platform ever linked, not per tx (re-links don't consume a new slot).
    const uniqueLinkedPlatforms = new Set(existingLinkTxs.map(t => t.data?.platform));

    const claimPayload = registerSocialSchema.buildSigningPayload({
      tip_id: tipId, platform, profile_url: profileUrl, claimed_at: claimedAt,
    });
    if (!registerSocialSchema.verifySignature(claimPayload, claimSignature, identity.public_key)) {
      throw schemaError(403, "User claim signature verification failed", "claim_signature_invalid");
    }

    // VP OAuth proof path — VP verified social ownership via OAuth; skip bio check.
    // Falls back to bio check when no VP proof is provided.
    let handle;
    if (vpOauthSignature && vpId) {
      const vp = registerIdentitySchema.resolveVP(vpId, dag);
      const oauthProof = {
        claimed_at:  claimedAt,
        handle:      vpOauthHandle ?? null,
        platform,
        profile_url: profileUrl,
        tip_id:      tipId,
        verified_at: vpOauthVerifiedAt,
        vp_id:       vpId,
      };
      if (!verifyPayload(oauthProof, vpOauthSignature, vp.public_key)) {
        throw schemaError(403, "VP OAuth signature verification failed", "vp_oauth_signature_invalid");
      }
      handle = vpOauthHandle ?? null;
      log.info(`VP OAuth verified: ${tipId} -> ${platform} (handle: ${handle}) via VP ${vpId}`);
    } else {
      ({ handle } = await bioFetcher.verifyBio({ tipId, profileUrl, platform }));
    }

    const verifiedAt = nowMs();
    const canonicalPayload = linkPlatformSchema.buildSigningPayload({
      tip_id: tipId,
      platform,
      profile_url: profileUrl,
      handle,
      claimed_at: claimedAt,
      verified_at: verifiedAt,
      node_id: config.nodeRegisteredId || config.nodeId,
      claim_signature: claimSignature,
    });

    const nodePrivKey = config.nodePrivateKey;
    if (!nodePrivKey) throw schemaError(500, "Node private key not configured", "node_key_missing");
    const nodeSig = linkPlatformSchema.sign(canonicalPayload, nodePrivKey);

    const linkTx = withTxId({
      tx_type: TX_TYPES.LINK_PLATFORM,
      timestamp: verifiedAt,
      signature: nodeSig,
      prev: dag.getRecentPrev(),
      data: {
        tip_id: tipId,
        platform,
        profile_url: profileUrl,
        handle,
        claimed_at: claimedAt,
        verified_at: verifiedAt,
        node_id: config.nodeRegisteredId || config.nodeId,
        claim_signature: claimSignature,
      },
    });

    const validation = validateTransaction(linkTx, dag, { skipPrevCheck: true });
    if (!validation.valid) {
      throw schemaError(400, validation.errors.join("; "), "tx_validation_failed");
    }

    submitTx(linkTx);

    const scoreEligible = !isRelink && uniqueLinkedPlatforms.size < SOCIAL_LINK.MAX_SOCIAL_ACCOUNTS;
    let scoreTxId = null;
    const scoreDelta = scoreEligible ? SOCIAL_LINK.SOCIAL_LINK_BONUS : 0;

    if (scoreEligible) {
      const scoreTx = scoring.buildScoreUpdateTx({
        tipId,
        delta: SOCIAL_LINK.SOCIAL_LINK_BONUS,
        reason: `Social account linked: ${platform}`,
        relatedTxId: linkTx.tx_id,
        timestamp: verifiedAt,
        getRecentPrev: () => dag.getRecentPrev(),
        config,
        extraData: { link_tx_id: linkTx.tx_id },
      });
      submitTx(scoreTx);
      scoreTxId = scoreTx.tx_id;
    }

    log.info(`Social account linked: ${tipId} -> ${platform} (${handle || "no-handle"})${scoreEligible ? "" : " [no bonus - cap reached]"}`);
    return {
      tip_id: tipId, platform, handle,
      tx_id: linkTx.tx_id, score_tx_id: scoreTxId,
      score_delta: scoreDelta,
      profile_url: profileUrl,
      verified_at: verifiedAt,
      confirmation: "proposed",
    };
  }

  function getPlatformLinks(tipId) {
    const links = dag.getPlatformLinksByTipId(tipId) || [];
    return { tip_id: tipId, platform_links: links };
  }

  async function unlinkPlatform({ tipId, platform, claimSignature, claimedAt }) {
    if (!tipId || !platform || !claimSignature || !claimedAt) {
      throw schemaError(400, "tipId, platform, claimSignature, claimedAt are required", "missing_fields");
    }
    if (nowMs() - claimedAt > CLAIM_MAX_AGE_MS) {
      throw schemaError(400, "Claim has expired (max 15 minutes)", "claim_expired");
    }

    const identity = dag.getIdentity(tipId);
    if (!identity) throw schemaError(412, `TIP-ID not found: ${tipId}`, "tip_id_not_found");

    const existingLink = dag.getPlatformLink(tipId, platform);
    if (!existingLink || existingLink.status !== "active") {
      throw schemaError(409, `Platform "${platform}" is not actively linked for ${tipId}`, "platform_not_linked");
    }

    const claimPayload = unlinkPlatformSchema.buildUnlinkClaimPayload({ claimed_at: claimedAt, platform, tip_id: tipId });
    if (!unlinkPlatformSchema.verifySignature(claimPayload, claimSignature, identity.public_key)) {
      throw schemaError(403, "User claim signature verification failed", "claim_signature_invalid");
    }

    const unlinkedAt = nowMs();
    const nodeId = config.nodeRegisteredId || config.nodeId;
    const canonicalPayload = unlinkPlatformSchema.buildSigningPayload({
      claim_signature: claimSignature,
      claimed_at: claimedAt,
      node_id: nodeId,
      platform,
      tip_id: tipId,
      unlinked_at: unlinkedAt,
    });

    const nodePrivKey = config.nodePrivateKey;
    if (!nodePrivKey) throw schemaError(500, "Node private key not configured", "node_key_missing");
    const nodeSig = unlinkPlatformSchema.sign(canonicalPayload, nodePrivKey);

    const unlinkTx = withTxId({
      tx_type: TX_TYPES.UNLINK_PLATFORM,
      timestamp: unlinkedAt,
      signature: nodeSig,
      prev: dag.getRecentPrev(),
      data: {
        tip_id: tipId,
        platform,
        claimed_at: claimedAt,
        unlinked_at: unlinkedAt,
        node_id: nodeId,
        claim_signature: claimSignature,
      },
    });

    const validation = validateTransaction(unlinkTx, dag, { skipPrevCheck: true });
    if (!validation.valid) {
      throw schemaError(400, validation.errors.join("; "), "tx_validation_failed");
    }

    submitTx(unlinkTx);

    log.info(`Social account unlinked: ${tipId} -> ${platform}`);
    return {
      tip_id: tipId,
      platform,
      tx_id: unlinkTx.tx_id,
      unlinked_at: unlinkedAt,
      confirmation: "proposed",
    };
  }

  return { register, resolve, verifyOwnership, getScore, getHistory, getActivity, findByDedupHash, linkPlatform, unlinkPlatform, getPlatformLinks };
}

module.exports = { createIdentityService };
