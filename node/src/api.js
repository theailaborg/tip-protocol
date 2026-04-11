/**
 * @file @tip-protocol/node/src/api.js
 * @description TIP Protocol Node — Express REST API v1
 *
 * Endpoints:
 *   GET  /health
 *   POST /v1/identity/register
 *   GET  /v1/identity/:tipId
 *   GET  /v1/identity/:tipId/score
 *   GET  /v1/identity/:tipId/history
 *   POST /v1/content/register
 *   GET  /v1/content/:ctid
 *   POST /v1/content/:ctid/verify
 *   POST /v1/content/:ctid/dispute
 *   GET  /v1/dag/tx/:txId
 *   GET  /v1/revocations
 *   POST /v1/revocations
 *   GET  /v1/dedup/merkle-root
 *   POST /v1/vp/register
 *   GET  /v1/vp/:vpId
 *   GET  /v1/node/info
 *   GET  /v1/node/peers
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const path       = require("path");
const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");
const morgan     = require("morgan");

const {
  generateMLDSAKeypair, generateSLHDSAKeypair,
  signTransaction,
  shake256, shake256Multi,
  hashContent, perceptualHashText,
  generateTIPID, generateCTID,
  computeTxId,
  verifyTxId,
  verifyBodySignature,
} = require("../../shared/crypto");

// Assign content-addressed tx_id (no node signature — auth is at gossip layer)
function withTxId(txBody) {
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

// Sign a tx with the node's registered key (for auto/system txs only)
function nodeSignedAuto(txBody, config) {
  txBody.data.node_id = config.nodeRegisteredId || config.nodeId;
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, config.nodePrivateKey);
}


const { verifyDedupProof } = require("../../shared/zk");

const { validateTransaction } = require("./validators/tx-validator");
const { selectJury, selectExperts, tallyVerdictAndApply, applyAppealVerdict } = require("./jury");

const {
  TX_TYPES, ORIGIN, ORIGIN_LABELS, VERIFY_CAPS, DISPUTE, JURY, APPEAL, AI_CLASSIFIER, SCORE_EVENTS,
  getTier, PRESCAN_THRESHOLDS, HTTP_HEADERS, PROTOCOL,
} = require("../../shared/constants");

const { log }  = require("./logger");
const { getFoundingVP } = require("./genesis");

// ─── Simple AI pre-scan (v2 FIX-03 calibrated thresholds) ────────────────────
// Production: replace with a real ML-based AI content detector
function preScanContent(content, originCode, creatorHistory) {
  if (originCode !== ORIGIN.OH) return { flagged: false, probability: 0 };

  // Heuristic: high repetition, perfect grammar, round numbers = likely AI
  const words     = content.split(/\s+/);
  const wordCount = words.length;
  if (wordCount < 20) return { flagged: false, probability: 0.1 };

  const uniqueRatio    = new Set(words).size / wordCount;
  const avgWordLen     = words.reduce((s, w) => s + w.length, 0) / wordCount;
  const hasLongSentences = (content.match(/[.!?]/g) || []).length < wordCount / 25;

  let prob = 0;
  if (uniqueRatio < 0.55) prob += 0.2;
  if (avgWordLen > 5.5)   prob += 0.15;
  if (hasLongSentences)   prob += 0.1;

  // Creator calibration: established creators get higher threshold
  const verifiedCount = creatorHistory?.verified_oh_count || 0;
  const threshold = verifiedCount > 200
    ? PRESCAN_THRESHOLDS.ceiling
    : verifiedCount > 50
      ? 0.90
      : PRESCAN_THRESHOLDS.default;

  return { flagged: prob > threshold, probability: prob, threshold };
}

// ─── Merkle root over dedup hashes (published to public DAG) ─────────────────
function computeMerkleRoot(dag) {
  const count = dag.dedupCount();
  // In production: build a real Merkle tree over all dedup hashes
  // For now: SHAKE-256 of count + timestamp as a stub proof
  return shake256Multi(count.toString(), new Date().toISOString().slice(0, 10));
}

// ─── Build Express app ────────────────────────────────────────────────────────
function createApp({ dag, scoring, config, gossip: gossipRef = null }) {
  // gossipRef is { current: GossipServer } — resolved after init due to circular dep
  const _broadcast = (tx) => {
    if (!gossipRef || !gossipRef.current) return;
    try { gossipRef.current.broadcast(tx); }
    catch (err) { log.error(`Gossip broadcast failed for tx ${tx.tx_id}: ${err.message}`); }
  };
  const app = express();

  // ── CORS (before all routes including static) ───────────────────────────────
  app.use(cors({ origin: config.corsOrigins, methods: ["GET","POST","PUT","DELETE","OPTIONS"] }));

  // ── Static files (before auth/rate-limit) ───────────────────────────────────
  app.use("/v1/zk", express.static(path.resolve(__dirname, "../../circuits")));
  app.use("/download", express.static(path.resolve(__dirname, "../../browser-extension")));

  // ── Middleware ──────────────────────────────────────────────────────────────
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(express.json({ limit: "4mb" }));
  app.use(morgan("[:date[iso]] :method :url :status :response-time ms"));

  const limiter = rateLimit({
    windowMs:  config.rateLimitWindow,
    max:       config.rateLimitMax,
    standardHeaders: true,
    legacyHeaders:   false,
    message: { error: "Rate limit exceeded. Try again shortly." },
  });
  app.use("/v1/", limiter);

  // ── TIP HTTP headers on all responses ─────────────────────────────────────
  app.use((req, res, next) => {
    res.setHeader("X-TIP-Node-ID",      config.nodeId);
    res.setHeader("X-TIP-Node-Version", config.nodeVersion);
    res.setHeader("X-TIP-Protocol",     "TIP/2.0");
    next();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // HEALTH
  // ─────────────────────────────────────────────────────────────────────────

  app.get("/health", (req, res) => {
    res.json({
      status:      "ok",
      node_id:     config.nodeId,
      node_type:   config.nodeType,
      dag_count:   dag.count(),
      version:     config.nodeVersion,
      protocol:    PROTOCOL.version,
      timestamp:   new Date().toISOString(),
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // IDENTITY
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * POST /v1/identity/register
   * Register a new TIP-ID on the DAG.
   *
   * Body:
   *   region            string   e.g. "US"
   *   public_key        string   client-generated ML-DSA-65 public key
   *   dedup_hash        string   Poseidon(govId, dob, country) — decimal field element
   *   zk_proof          object   Groth16 proof { pi_a, pi_b, pi_c, protocol, curve }
   *   verification_tier string   "T1"|"T2"|"T3"|"T4"
   *   vp_id             string   ID of issuing VP
   *   vp_signature      string   VP's ML-DSA-65 signature
   *   social_attested   boolean  true if 3 vouchers provided
   */
  app.post("/v1/identity/register", async (req, res) => {
    try {
      const {
        region = "US",
        public_key,
        dedup_hash,
        zk_proof,
        verification_tier = "T1",
        vp_id,
        vp_signature,
        social_attested = false,
      } = req.body;

      if (!public_key)  return res.status(400).json({ error: "public_key is required (client-generated ML-DSA-65)" });
      if (!dedup_hash) return res.status(400).json({ error: "dedup_hash is required" });
      if (!zk_proof)   return res.status(400).json({ error: "zk_proof is required" });
      if (!vp_id)      return res.status(400).json({ error: "vp_id is required" });

      // Verify VP exists and is active
      const vp = dag.getVP(vp_id);
      if (!vp || vp.status !== "active") {
        return res.status(403).json({ error: "Verification provider not found or suspended" });
      }

      // Verify VP signature: VP must sign (dedup_hash + verification_tier + vp_id)
      // This proves the registration was submitted by a legitimate VP, not someone
      // who just knows a valid vp_id.
      if (!vp_signature) {
        return res.status(400).json({ error: "vp_signature is required" });
      }
      const VP_IDENTITY_FIELDS = ["region", "public_key", "dedup_hash", "zk_proof", "verification_tier", "vp_id", "social_attested"];
      if (!verifyBodySignature(req.body, vp_signature, vp.public_key, VP_IDENTITY_FIELDS)) {
        return res.status(403).json({ error: "VP signature verification failed — signature does not match VP public key" });
      }

      // Verify ZK proof: proves prover knows (govId, dob, country) that Poseidon-hash to dedup_hash
      const proofValid = await verifyDedupProof(dedup_hash, zk_proof);
      if (!proofValid) {
        return res.status(400).json({ error: "ZK proof verification failed — invalid or tampered proof" });
      }

      // Dedup check: reject if this identity has registered before
      if (dag.hasDedupHash(dedup_hash)) {
        return res.status(409).json({
          error:   "Identity already registered. Each human may hold exactly one TIP-ID.",
          code:    "DUPLICATE_IDENTITY",
        });
      }

      // TIP-ID derived from client-provided public key
      const tipId       = generateTIPID(region, public_key);

      const registeredAt = new Date().toISOString();

      // Founding status is determined by the genesis block, not the request.
      // Only identities in GENESIS_PAYLOAD.genesis_ring (populated by seed script
      // before launch) are founding members. The API always sets founding = false.
      const founding = false;

      const txBody = {
        tx_type:   TX_TYPES.REGISTER_IDENTITY,
        timestamp: registeredAt,
        prev:      dag.getRecentPrev(),
        data: {
          tip_id:            tipId,
          region:            region.toUpperCase(),
          public_key:        public_key,
          vp_id,
          verification_tier,
          social_attested,
          founding,
          dedup_hash,
          zk_proof,
        },
      };
      const signedTx = withTxId(txBody);

      const identityValidation = validateTransaction(signedTx, dag, {});
      if (!identityValidation.valid) {
        return res.status(400).json({ error: identityValidation.errors, layer: identityValidation.layer });
      }

      const tx = dag.addTx(signedTx);
      _broadcast(tx);

      dag.saveIdentity({
        tip_id:          tipId,
        region:          region.toUpperCase(),
        public_key:      public_key,
        vp_id,
        verification_tier,
        founding,
        status:          "active",
        registered_at:   registeredAt,
        tx_id:           tx.tx_id,
      });

      // Store dedup_hash — prevents this identity from registering again
      dag.addDedupHash(dedup_hash);

      // Initialise score
      dag.setScore(tipId, social_attested ? 550 : 500, 0);

      log.info(`Identity registered: ${tipId} (tier: ${verification_tier}, vp: ${vp_id})`);

      res.status(201).json({
        tip_id:           tipId,
        public_key:       public_key,
        tx_id:            tx.tx_id,
        score:            social_attested ? 550 : 500,
        registered_at:    registeredAt,
      });

    } catch (err) {
      log.error("Identity registration error:", err);
      res.status(500).json({ error: "Internal server error", detail: err.message });
    }
  });

  /**
   * GET /v1/identity/:tipId
   * Resolve a TIP-ID to its public record.
   */
  app.get("/v1/identity/:tipId", (req, res) => {
    const rec = dag.getIdentity(req.params.tipId);
    if (!rec) return res.status(404).json({ error: "TIP-ID not found" });

    const scoreData = scoring.getScore(req.params.tipId);
    const content   = dag.getContentByAuthor(req.params.tipId);
    const revoked   = dag.isRevoked(req.params.tipId);

    // Verify the underlying transaction
    const tx = rec.tx_id ? dag.getTx(rec.tx_id) : null;
    const txValid = tx ? verifyTxId(tx) : false;
    const prevValid = tx && tx.prev ? tx.prev.every(p => !!dag.getTx(p)) : false;

    res.json({
      tip_id:            rec.tip_id,
      region:            rec.region,
      public_key:        rec.public_key,
      vp_id:             rec.vp_id,
      verification_tier: rec.verification_tier,
      founding:          rec.founding,
      status:            revoked ? "revoked" : rec.status,
      score:             scoreData.score,
      tier:              scoreData.tier.name,
      tier_color:        scoreData.tier.color,
      content_count:     content.length,
      registered_at:     rec.registered_at,
      verification: {
        tx_exists:    !!tx,
        tx_id_valid:  txValid,
        prev_valid:   prevValid,
        on_dag:       true,
      },
    });
  });

  /**
   * POST /v1/identity/verify-ownership
   * Prove you own a TIP-ID by signing a challenge.
   *
   * Body:
   *   tip_id     string   the TIP-ID to prove ownership of
   *   challenge  string   any string (e.g. timestamp or nonce from client)
   *   signature  string   ML-DSA-65 sig over challenge using your private key
   */
  app.post("/v1/identity/verify-ownership", (req, res) => {
    const { tip_id, challenge, signature } = req.body;
    if (!tip_id)    return res.status(400).json({ error: "tip_id is required" });
    if (!challenge) return res.status(400).json({ error: "challenge is required" });
    if (!signature) return res.status(400).json({ error: "signature is required" });

    const identity = dag.getIdentity(tip_id);
    if (!identity) return res.status(404).json({ error: "TIP-ID not found" });
    if (dag.isRevoked(tip_id)) return res.status(403).json({ error: "TIP-ID is revoked" });

    const { mldsaVerify } = require("../../shared/crypto");
    const valid = mldsaVerify(challenge, signature, identity.public_key);
    if (!valid) return res.status(403).json({ error: "Signature verification failed — you do not own this TIP-ID" });

    const scoreData = scoring.getScore(tip_id);
    res.json({
      verified: true,
      tip_id,
      score:  scoreData.score,
      tier:   scoreData.tier.name,
      status: identity.status,
    });
  });

  /**
   * GET /v1/identity/:tipId/score
   * Return the trust score for a TIP-ID with full breakdown.
   */
  app.get("/v1/identity/:tipId/score", (req, res) => {
    const rec = dag.getIdentity(req.params.tipId);
    if (!rec) return res.status(404).json({ error: "TIP-ID not found" });

    const { score, tier, offense_count } = scoring.getScore(req.params.tipId);

    // Respect score display mode (v2 FIX-06)
    const displayMode = rec.score_display_mode || "TIER_ONLY";
    const response = {
      tip_id:        req.params.tipId,
      tier:          tier.name,
      tier_label:    tier.label,
      tier_color:    tier.color,
      verified_since: rec.registered_at,
      content_count: dag.getContentByAuthor(req.params.tipId).length,
      status:        dag.isRevoked(req.params.tipId) ? "revoked" : rec.status,
    };

    if (displayMode === "FULL_PUBLIC") {
      response.score         = score;
      response.offense_count = offense_count;
    } else if (displayMode === "TIER_ONLY") {
      // Score shown only to authorised parties; public sees tier only
    }
    // VERIFIED_ONLY: just return verified: true/false

    res.json(response);
  });

  /**
   * GET /v1/identity/:tipId/history
   * Full transaction history for a TIP-ID (score replay).
   */
  app.get("/v1/identity/:tipId/history", (req, res) => {
    const rec = dag.getIdentity(req.params.tipId);
    if (!rec) return res.status(404).json({ error: "TIP-ID not found" });

    const { history } = scoring.computeScore(req.params.tipId);
    res.json({ tip_id: req.params.tipId, history });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // CONTENT
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * POST /v1/content/register
   * Register content with a mandatory origin declaration.
   *
   * Body:
   *   author_tip_id  string  (required)
   *   origin_code    string  OH|AA|AG|MX (required)
   *   content        string  (required)
   *   signature      string  ML-DSA-65 sig over { author_tip_id, origin_code, content_hash }
   */
  app.post("/v1/content/register", (req, res) => {
    try {
      const { author_tip_id, origin_code, content, signature } = req.body;

      if (!author_tip_id)       return res.status(400).json({ error: "author_tip_id is required" });
      if (!origin_code)         return res.status(400).json({ error: "origin_code is required" });
      if (!ORIGIN[origin_code]) return res.status(400).json({ error: `Invalid origin_code. Must be one of: ${Object.keys(ORIGIN).join(", ")}` });
      if (!content)             return res.status(400).json({ error: "content is required" });
      if (!signature)           return res.status(400).json({ error: "signature is required" });

      const identity = dag.getIdentity(author_tip_id);
      if (!identity) return res.status(404).json({ error: "Author TIP-ID not found" });
      if (dag.isRevoked(author_tip_id)) return res.status(403).json({ error: "Author TIP-ID is revoked" });

      // Full SHAKE-256 for signature verification (64 hex chars — matches client signBody)
      const contentHashFull = shake256(content);
      // Truncated hash for CTID URI and storage (14 hex chars — readable)
      const contentHashShort = hashContent(content);

      // Verify body signature against full hash
      const CONTENT_FIELDS = ["author_tip_id", "origin_code", "content_hash"];
      const sigBody = { author_tip_id, origin_code, content_hash: contentHashFull };
      if (!verifyBodySignature(sigBody, signature, identity.public_key, CONTENT_FIELDS)) {
        return res.status(403).json({ error: "Content signature verification failed — signature does not match author public key" });
      }
      const perceptHash = content ? perceptualHashText(content) : null;

      // v2 FIX-03: Pre-scan (calibrated thresholds, flag-but-mint)
      const contentHistory = { verified_oh_count: dag.getContentByAuthor(author_tip_id).filter(c => c.origin_code === ORIGIN.OH && c.status === "verified").length };
      const preScan = preScanContent(content || "", origin_code, contentHistory);

      const registeredAt = new Date().toISOString();
      const ctid         = generateCTID(origin_code, contentHashShort, author_tip_id);

      // Reject if CTID already exists (same author + same content + same origin)
      const existing = dag.getContent(ctid);
      if (existing) {
        return res.status(409).json({ error: `Content already registered with this origin code (CTID: ${ctid})`, ctid, status: existing.status });
      }

      const contentTxBody = {
        tx_type:   TX_TYPES.REGISTER_CONTENT,
        timestamp: registeredAt,
        prev:      dag.getRecentPrev(),
        data: {
          ctid,
          origin_code,
          origin_label:   ORIGIN_LABELS[origin_code],
          content_hash:   contentHashFull,
          perceptual_hash: perceptHash,
          author_tip_id,
          signature,
          prescan_flagged:    preScan.flagged,
          prescan_probability: preScan.probability,
        },
      };
      const signedContentTx = withTxId(contentTxBody);

      const contentValidation = validateTransaction(signedContentTx, dag, {});
      if (!contentValidation.valid) {
        return res.status(400).json({ error: contentValidation.errors, layer: contentValidation.layer });
      }

      const tx = dag.addTx(signedContentTx);
      _broadcast(tx);

      dag.saveContent({
        ctid,
        origin_code,
        content_hash:    contentHashFull,
        perceptual_hash: perceptHash,
        author_tip_id,
        status:          preScan.flagged ? "pending_review" : "registered",
        registered_at:   registeredAt,
        tx_id:           tx.tx_id,
      });

      log.info(`Content registered: ${ctid} (origin: ${origin_code}, author: ${author_tip_id})`);

      const http_headers = {
        [HTTP_HEADERS.AUTHOR]:       author_tip_id,
        [HTTP_HEADERS.CONTENT]:      ctid,
        [HTTP_HEADERS.ORIGIN]:       ORIGIN_LABELS[origin_code].toLowerCase().replace(/ /g, "-"),
        [HTTP_HEADERS.TRUST_SCORE]:  scoring.getScore(author_tip_id).score.toString(),
        [HTTP_HEADERS.SIGNATURE]:    signature,
      };

      res.status(201).json({
        ctid,
        origin_code,
        origin_label:      ORIGIN_LABELS[origin_code],
        content_hash:      contentHashFull,
        author_tip_id,
        tx_id:             tx.tx_id,
        registered_at:     registeredAt,
        status:            preScan.flagged ? "pending_review" : "registered",
        prescan_flagged:   preScan.flagged,
        prescan_note:      preScan.flagged
          ? "Content flagged by AI pre-scan. You have 24 hours to change the origin code at zero penalty."
          : null,
        http_headers,
        meta_tags: {
          "tip:author":  author_tip_id,
          "tip:content": ctid,
          "tip:origin":  ORIGIN_LABELS[origin_code].toLowerCase().replace(/ /g, "-"),
          "tip:score":   scoring.getScore(author_tip_id).score.toString(),
          "tip:status":  preScan.flagged ? "PENDING" : "REGISTERED",
        },
      });

    } catch (err) {
      log.error("Content registration error:", err);
      res.status(500).json({ error: "Internal server error", detail: err.message });
    }
  });

  /**
   * GET /v1/content/:ctid
   * Resolve a CTID to its provenance record.
   */
  app.get("/v1/content/:ctid", (req, res) => {
    const rec = dag.getContent(req.params.ctid);
    if (!rec) return res.status(404).json({ error: "Content record not found" });

    // Verify the underlying transaction
    const tx = rec.tx_id ? dag.getTx(rec.tx_id) : null;
    const txValid = tx ? verifyTxId(tx) : false;
    const prevValid = tx && tx.prev ? tx.prev.every(p => !!dag.getTx(p)) : false;

    // Verify author identity exists and is active
    const author = dag.getIdentity(rec.author_tip_id);
    const authorValid = !!author && author.status === "active" && !dag.isRevoked(rec.author_tip_id);

    res.json({
      ...rec,
      origin_label: ORIGIN_LABELS[rec.origin_code] || rec.origin_code,
      author_score: scoring.getScore(rec.author_tip_id).score,
      author_tier:  scoring.getScore(rec.author_tip_id).tier.name,
      verification: {
        tx_exists:      !!tx,
        tx_id_valid:    txValid,
        prev_valid:     prevValid,
        author_valid:   authorValid,
        author_revoked: dag.isRevoked(rec.author_tip_id),
        on_dag:         true,
      },
    });
  });

  /**
   * POST /v1/content/:ctid/verify
   * Community verification of content origin.
   */
  app.post("/v1/content/:ctid/verify", (req, res) => {
    const rec = dag.getContent(req.params.ctid);
    if (!rec) return res.status(404).json({ error: "Content record not found" });

    const { verifier_tip_id, verdict, signature } = req.body;
    if (!verifier_tip_id) return res.status(400).json({ error: "verifier_tip_id required" });
    if (!signature)       return res.status(400).json({ error: "signature is required" });

    const verifier = dag.getIdentity(verifier_tip_id);
    if (!verifier) return res.status(404).json({ error: "Verifier TIP-ID not found" });
    if (dag.isRevoked(verifier_tip_id)) return res.status(403).json({ error: "Verifier TIP-ID is revoked" });
    if (verifier_tip_id === rec.author_tip_id) return res.status(403).json({ error: "Cannot verify your own content" });

    const VERIFY_FIELDS = ["verifier_tip_id", "verdict"];
    if (!verifyBodySignature(req.body, signature, verifier.public_key, VERIFY_FIELDS)) {
      return res.status(403).json({ error: "Verifier signature verification failed — signature does not match verifier public key" });
    }

    if (rec.status === "retracted") {
      return res.status(403).json({ error: "Content has been retracted by the author — verification not allowed" });
    }
    if (rec.status === "disputed") {
      return res.status(403).json({ error: "Content is under dispute — verification blocked until resolved" });
    }
    if (rec.status === "pending_review") {
      return res.status(403).json({ error: "Content is pending review — verification blocked until 24-hour grace period ends" });
    }

    if (dag.hasVerification(req.params.ctid, verifier_tip_id)) {
      return res.status(409).json({ error: "You have already verified this content" });
    }

    // ── Verification caps ──────────────────────────────────────────────────
    const allVerifyTxs = dag.getTxsByType(TX_TYPES.CONTENT_VERIFIED);
    const authorTipId  = rec.author_tip_id;
    const now          = new Date();
    const dayStart     = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const monthStart   = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

    const contentDeltaSum = allVerifyTxs
      .filter(t => t.data?.ctid === req.params.ctid)
      .reduce((sum, t) => sum + (t.data?.weighted_delta || 0), 0);
    const dailyDeltaSum = allVerifyTxs
      .filter(t => t.data?.author_tip_id === authorTipId && t.timestamp >= dayStart)
      .reduce((sum, t) => sum + (t.data?.weighted_delta || 0), 0);
    const monthlyDeltaSum = allVerifyTxs
      .filter(t => t.data?.author_tip_id === authorTipId && t.timestamp >= monthStart)
      .reduce((sum, t) => sum + (t.data?.weighted_delta || 0), 0);

    const verifierScore = scoring.getScore(verifier_tip_id).score;
    let weightedDelta = verifierScore >= VERIFY_CAPS.HIGH_TRUST_MIN ? VERIFY_CAPS.HIGH_TRUST_DELTA : VERIFY_CAPS.BASE_DELTA;

    // Apply caps — reduce delta to fit within limits
    weightedDelta = Math.min(
      weightedDelta,
      Math.max(0, VERIFY_CAPS.PER_CONTENT - contentDeltaSum),
      Math.max(0, VERIFY_CAPS.PER_DAY     - dailyDeltaSum),
      Math.max(0, VERIFY_CAPS.PER_MONTH   - monthlyDeltaSum),
    );

    const verifyTxBody = {
      tx_type:   TX_TYPES.CONTENT_VERIFIED,
      timestamp: new Date().toISOString(),
      prev:      dag.getRecentPrev(),
      data: {
        ctid:              req.params.ctid,
        verifier_tip_id,
        verdict:           verdict || "ORIGIN_CONFIRMED",
        weighted_delta:    weightedDelta,
        author_tip_id:     authorTipId,
      },
    };
    const signedVerifyTx = withTxId(verifyTxBody);

    const verifyValidation = validateTransaction(signedVerifyTx, dag, {});
    if (!verifyValidation.valid) {
      return res.status(400).json({ error: verifyValidation.errors, layer: verifyValidation.layer });
    }

    const verifyTx = dag.addTx(signedVerifyTx);
    _broadcast(verifyTx);

    if (weightedDelta > 0) {
      scoring.applyScoreEvent(authorTipId, weightedDelta, `Content verified by ${verifier_tip_id}`);
    }

    // Update content status to verified (community endorsed)
    if (rec.status === "registered") {
      dag.updateContentStatus(req.params.ctid, "verified");
    }

    res.json({
      success: true,
      delta_applied: weightedDelta,
      caps: {
        content: { used: contentDeltaSum + weightedDelta, max: VERIFY_CAPS.PER_CONTENT },
        daily:   { used: dailyDeltaSum + weightedDelta,   max: VERIFY_CAPS.PER_DAY },
        monthly: { used: monthlyDeltaSum + weightedDelta, max: VERIFY_CAPS.PER_MONTH },
      },
    });
  });

  /**
   * POST /v1/content/:ctid/dispute
   * File an origin dispute against a CTID.
   */
  app.post("/v1/content/:ctid/dispute", (req, res) => {
    const rec = dag.getContent(req.params.ctid);
    if (!rec) return res.status(404).json({ error: "Content record not found" });

    if (rec.status === "retracted") {
      return res.status(403).json({ error: "Content has been retracted by the author — dispute not allowed" });
    }
    if (rec.status === "pending_review") {
      return res.status(403).json({ error: "Content is pending review — wait for 24-hour grace period to end before disputing" });
    }

    const { disputer_tip_id, reason, claimed_origin, evidence_hash, signature } = req.body;
    if (!disputer_tip_id) return res.status(400).json({ error: "disputer_tip_id required" });
    if (!signature)       return res.status(400).json({ error: "signature is required" });
    if (!reason)          return res.status(400).json({ error: "reason required (origin_mismatch or factual_falsehood)" });
    if (reason === "origin_mismatch" && !claimed_origin) {
      return res.status(400).json({ error: "claimed_origin required for origin_mismatch disputes (what you think the actual origin is)" });
    }
    if (claimed_origin && !ORIGIN[claimed_origin]) {
      return res.status(400).json({ error: `Invalid claimed_origin. Must be one of: ${Object.keys(ORIGIN).join(", ")}` });
    }

    const disputer = dag.getIdentity(disputer_tip_id);
    if (!disputer) return res.status(404).json({ error: "Disputer TIP-ID not found" });
    if (dag.isRevoked(disputer_tip_id)) return res.status(403).json({ error: "Disputer TIP-ID is revoked" });

    // Minimum score to dispute (Verified tier or above)
    const disputerScore = scoring.getScore(disputer_tip_id).score;
    if (disputerScore < DISPUTE.MIN_SCORE_TO_DISPUTE) {
      return res.status(403).json({ error: `Score must be >= ${DISPUTE.MIN_SCORE_TO_DISPUTE} to file a dispute (current: ${disputerScore})` });
    }

    const DISPUTE_FIELDS = claimed_origin
      ? ["disputer_tip_id", "reason", "claimed_origin", "evidence_hash"]
      : ["disputer_tip_id", "reason", "evidence_hash"];
    if (!verifyBodySignature(req.body, signature, disputer.public_key, DISPUTE_FIELDS)) {
      return res.status(403).json({ error: "Disputer signature verification failed — signature does not match disputer public key" });
    }

    if (dag.hasDispute(req.params.ctid, disputer_tip_id)) {
      return res.status(409).json({ error: "You have already disputed this content" });
    }

    // No score change on dispute filing — penalty/bonus applied at verdict
    const disputeTxBody = {
      tx_type:   TX_TYPES.CONTENT_DISPUTED,
      timestamp: new Date().toISOString(),
      prev:      dag.getRecentPrev(),
      data: {
        ctid:            req.params.ctid,
        disputer_tip_id,
        reason,
        claimed_origin:  claimed_origin || null,
        declared_origin: rec.origin_code,
        evidence_hash,
        author_tip_id:   rec.author_tip_id,
        pre_dispute_status: rec.status,
        stake:           DISPUTE.DISPUTER_STAKE,
      },
    };
    const signedDisputeTx = withTxId(disputeTxBody);

    const disputeValidation = validateTransaction(signedDisputeTx, dag, {});
    if (!disputeValidation.valid) {
      return res.status(400).json({ error: disputeValidation.errors, layer: disputeValidation.layer });
    }

    const disputeTx = dag.addTx(signedDisputeTx);
    _broadcast(disputeTx);

    // Update content status to disputed
    dag.updateContentStatus(req.params.ctid, "disputed");

    // ── Stage 1: AI Classifier ───────────────────────────────────────────
    // AI classifier runs but always escalates to Stage 2 for now.
    // TODO (#47): AI needs actual content text — currently only hash is stored.
    // Disputer should submit content text, node verifies hash match, then runs ML.
    let stage1Result;
    try {
      const contentRecord = dag.getContent(req.params.ctid);
      const aiResult = preScanContent(contentRecord?.content_hash || "", rec.origin_code, {});
      const confidence = aiResult.probability || 0;

      // Always escalate — auto-dismiss disabled until AI has real content to analyze
      const routing = confidence >= AI_CLASSIFIER.HIGH_CONFIDENCE ? "escalate_high" : "escalate";

      // Write AI_CLASSIFIER_RESULT tx to DAG (metadata, not score-changing)
      const classifierTx = nodeSignedAuto({
        tx_type:   TX_TYPES.AI_CLASSIFIER_RESULT,
        timestamp: new Date().toISOString(),
        prev:      dag.getRecentPrev(),
        data: { ctid: req.params.ctid, dispute_tx_id: disputeTx.tx_id, confidence, routing },
      }, config);
      dag.addTx(classifierTx);
      _broadcast(classifierTx);

      stage1Result = { routing, confidence, message: routing === "escalate_high"
        ? "High-confidence mismatch. Escalated to Stage 2 jury with flag."
        : "Escalated to Stage 2 jury for human review." };

      log.info(`Stage 1 AI: ${req.params.ctid} confidence=${confidence} routing=${routing}`);
    } catch (e) {
      log.error(`Stage 1 AI failed for ${req.params.ctid}:`, e.message);
      stage1Result = { routing: "escalate", confidence: 0, message: "AI classifier unavailable — escalated to Stage 2." };
    }

    // ── Stage 2: Jury Selection ─────────────────────────────────────────
    let juryResult = null;
    try {
      const jury = selectJury(dag, scoring, disputeTx.tx_id, rec.author_tip_id, disputer_tip_id);
      if (jury.insufficient) {
        log.warn(`Jury selection: insufficient eligible jurors for ${req.params.ctid} (${jury.jurors.length}/${JURY.SIZE})`);
      }

      const commitDeadline = new Date(Date.now() + JURY.COMMIT_WINDOW_HOURS * 3600000).toISOString();
      const revealDeadline = new Date(Date.now() + (JURY.COMMIT_WINDOW_HOURS + JURY.REVEAL_WINDOW_HOURS) * 3600000).toISOString();
      const timestamp = new Date().toISOString();

      // Write JURY_SUMMONS tx for each selected juror + apply juror stake
      for (const jurorTipId of jury.jurors) {
        const summonsTx = nodeSignedAuto({
          tx_type:   TX_TYPES.JURY_SUMMONS,
          timestamp,
          prev:      dag.getRecentPrev(),
          data: {
            ctid:            req.params.ctid,
            dispute_tx_id:   disputeTx.tx_id,
            juror_tip_id:    jurorTipId,
            stake:           JURY.JUROR_STAKE,
            seed:            jury.seed,
            identity_count:  jury.identityCount,
            commit_deadline: commitDeadline,
            reveal_deadline: revealDeadline,
          },
        }, config);
        dag.addTx(summonsTx);
        _broadcast(summonsTx);

        // Deduct juror stake (applied at verdict, not now — same approach as disputer)
      }

      juryResult = {
        jurors:          jury.jurors,
        count:           jury.jurors.length,
        insufficient:    jury.insufficient,
        seed:            jury.seed,
        identity_count:  jury.identityCount,
        commit_deadline: commitDeadline,
        reveal_deadline: revealDeadline,
      };
      log.info(`Jury selected for ${req.params.ctid}: ${jury.jurors.length} jurors`);
    } catch (e) {
      log.error(`Jury selection failed for ${req.params.ctid}:`, e.message);
      juryResult = { error: "Jury selection failed", message: e.message };
    }

    res.json({
      success: true,
      message: "Dispute filed.",
      dispute_tx_id: disputeTx.tx_id,
      stake_at_risk: DISPUTE.DISPUTER_STAKE,
      stage1: stage1Result,
      stage2: juryResult,
    });
  });

  /**
   * POST /v1/content/:ctid/jury/commit
   * Juror submits a hidden vote commitment: SHAKE-256(vote + salt).
   * Vote is hidden until reveal phase.
   */
  app.post("/v1/content/:ctid/jury/commit", async (req, res) => {
    try {
      const { juror_tip_id, commitment, signature } = req.body;
      if (!juror_tip_id) return res.status(400).json({ error: "juror_tip_id required" });
      if (!commitment)   return res.status(400).json({ error: "commitment required (SHAKE-256 of vote + salt)" });
      if (!signature)    return res.status(400).json({ error: "signature required" });

      // Verify juror identity
      const juror = dag.getIdentity(juror_tip_id);
      if (!juror) return res.status(404).json({ error: "Juror TIP-ID not found" });
      if (dag.isRevoked(juror_tip_id)) return res.status(403).json({ error: "Juror TIP-ID is revoked" });

      // Verify signature
      const COMMIT_FIELDS = ["juror_tip_id", "commitment"];
      if (!verifyBodySignature(req.body, signature, juror.public_key, COMMIT_FIELDS)) {
        return res.status(403).json({ error: "Juror signature verification failed" });
      }

      // Check juror was summoned for this dispute
      const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, req.params.ctid)
        .filter(t => t.data?.juror_tip_id === juror_tip_id);
      if (!summonsTxs.length) {
        return res.status(403).json({ error: "You were not summoned as a juror for this dispute" });
      }

      // Check commit deadline
      const commitDeadline = new Date(summonsTxs[0].data.commit_deadline).getTime();
      if (Date.now() > commitDeadline) {
        return res.status(403).json({ error: "Commit window has closed" });
      }

      // Check not already committed
      const existingCommit = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, req.params.ctid)
        .find(t => t.data?.juror_tip_id === juror_tip_id);
      if (existingCommit) {
        return res.status(409).json({ error: "You have already submitted a vote commitment" });
      }

      // Write JURY_VOTE_COMMIT tx
      const commitTx = withTxId({
        tx_type:   TX_TYPES.JURY_VOTE_COMMIT,
        timestamp: new Date().toISOString(),
        prev:      dag.getRecentPrev(),
        data: {
          ctid:         req.params.ctid,
          juror_tip_id,
          commitment,
        },
      });
      dag.addTx(commitTx);
      _broadcast(commitTx);

      res.json({ success: true, tx_id: commitTx.tx_id });
    } catch (e) {
      log.error("Jury commit error:", e.message);
      res.status(500).json({ error: "Internal server error", detail: e.message });
    }
  });

  /**
   * POST /v1/content/:ctid/jury/reveal
   * Juror reveals their vote and salt. Node verifies SHAKE-256(vote + salt) matches commitment.
   */
  app.post("/v1/content/:ctid/jury/reveal", async (req, res) => {
    try {
      const { juror_tip_id, vote, salt, confirmed_origin, signature } = req.body;
      if (!juror_tip_id) return res.status(400).json({ error: "juror_tip_id required" });
      if (!vote)         return res.status(400).json({ error: "vote required (MATCH, MISMATCH, or ABSTAIN)" });
      if (!salt)         return res.status(400).json({ error: "salt required" });
      if (!signature)    return res.status(400).json({ error: "signature required" });

      const VALID_VOTES = ["MATCH", "MISMATCH", "ABSTAIN"];
      if (!VALID_VOTES.includes(vote)) {
        return res.status(400).json({ error: `Invalid vote. Must be one of: ${VALID_VOTES.join(", ")}` });
      }
      if (vote === "MISMATCH" && !confirmed_origin) {
        return res.status(400).json({ error: "confirmed_origin required when voting MISMATCH (what you think the actual origin is)" });
      }
      if (confirmed_origin && !ORIGIN[confirmed_origin]) {
        return res.status(400).json({ error: `Invalid confirmed_origin. Must be one of: ${Object.keys(ORIGIN).join(", ")}` });
      }

      // Verify juror identity
      const juror = dag.getIdentity(juror_tip_id);
      if (!juror) return res.status(404).json({ error: "Juror TIP-ID not found" });

      // Verify signature
      const REVEAL_FIELDS = confirmed_origin
        ? ["juror_tip_id", "vote", "salt", "confirmed_origin"]
        : ["juror_tip_id", "vote", "salt"];
      if (!verifyBodySignature(req.body, signature, juror.public_key, REVEAL_FIELDS)) {
        return res.status(403).json({ error: "Juror signature verification failed" });
      }

      // Check juror was summoned
      const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, req.params.ctid)
        .filter(t => t.data?.juror_tip_id === juror_tip_id);
      if (!summonsTxs.length) {
        return res.status(403).json({ error: "You were not summoned as a juror for this dispute" });
      }

      // Check reveal window (after commit deadline, before reveal deadline)
      const commitDeadline = new Date(summonsTxs[0].data.commit_deadline).getTime();
      const revealDeadline = new Date(summonsTxs[0].data.reveal_deadline).getTime();
      const now = Date.now();
      if (now < commitDeadline) {
        return res.status(403).json({ error: "Reveal window has not opened yet — commit phase still active" });
      }
      if (now > revealDeadline) {
        return res.status(403).json({ error: "Reveal window has closed" });
      }

      // Find the commitment
      const commitTx = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, req.params.ctid)
        .find(t => t.data?.juror_tip_id === juror_tip_id);
      if (!commitTx) {
        return res.status(404).json({ error: "No vote commitment found — you must commit before revealing" });
      }

      // Verify commitment matches: SHAKE-256(vote + salt) === stored commitment
      const computedCommitment = shake256(`${vote}:${salt}`);
      if (computedCommitment !== commitTx.data.commitment) {
        return res.status(403).json({ error: "Vote does not match commitment — vote discarded, stake forfeited" });
      }

      // Check not already revealed
      const existingReveal = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, req.params.ctid)
        .find(t => t.data?.juror_tip_id === juror_tip_id);
      if (existingReveal) {
        return res.status(409).json({ error: "You have already revealed your vote" });
      }

      // Write JURY_VOTE_REVEAL tx
      const revealTx = withTxId({
        tx_type:   TX_TYPES.JURY_VOTE_REVEAL,
        timestamp: new Date().toISOString(),
        prev:      dag.getRecentPrev(),
        data: {
          ctid:         req.params.ctid,
          juror_tip_id,
          vote,
          salt,
          confirmed_origin: vote === "MISMATCH" ? confirmed_origin : null,
        },
      });
      dag.addTx(revealTx);
      _broadcast(revealTx);

      // Check if all jurors have revealed — trigger verdict if so
      const allReveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, req.params.ctid);
      const allSummons = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, req.params.ctid);

      let verdict = null;
      if (allReveals.length >= allSummons.length) {
        verdict = tallyVerdictAndApply(req.params.ctid, allReveals, allSummons, dag, scoring, config);
      }

      res.json({ success: true, tx_id: revealTx.tx_id, verdict });
    } catch (e) {
      log.error("Jury reveal error:", e.message);
      res.status(500).json({ error: "Internal server error", detail: e.message });
    }
  });

  /**
   * GET /v1/content/:ctid/dispute-case
   * Returns full case details for juror review.
   */
  app.get("/v1/content/:ctid/dispute-case", (req, res) => {
    const rec = dag.getContent(req.params.ctid);
    if (!rec) return res.status(404).json({ error: "Content record not found" });

    // Content details
    const content = {
      ctid:         req.params.ctid,
      origin_code:  rec.origin_code,
      origin_label: ORIGIN_LABELS[rec.origin_code] || rec.origin_code,
      content_hash: rec.content_hash,
      author_tip_id: rec.author_tip_id,
      status:       rec.status,
      registered_at: rec.registered_at,
    };

    // Dispute details
    const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, req.params.ctid);
    const dispute = disputeTxs.length ? {
      disputer_tip_id: disputeTxs[0].data.disputer_tip_id,
      reason:          disputeTxs[0].data.reason,
      claimed_origin:  disputeTxs[0].data.claimed_origin,
      declared_origin: disputeTxs[0].data.declared_origin,
      evidence_hash:   disputeTxs[0].data.evidence_hash,
      filed_at:        disputeTxs[0].timestamp,
      dispute_tx_id:   disputeTxs[0].tx_id,
    } : null;

    // AI classifier result
    const classifierTxs = dag.getTxsByTypeAndCtid(TX_TYPES.AI_CLASSIFIER_RESULT, req.params.ctid);
    const ai_classifier = classifierTxs.length ? {
      confidence: classifierTxs[0].data.confidence,
      routing:    classifierTxs[0].data.routing,
    } : null;

    // Creator history
    const authorContent = dag.getContentByAuthor(rec.author_tip_id);
    const authorScore = scoring.getScore(rec.author_tip_id);
    const priorDisputes = dag.getTxsByType(TX_TYPES.CONTENT_DISPUTED)
      .filter(t => t.data?.author_tip_id === rec.author_tip_id);
    const priorAdjudications = dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT)
      .filter(t => t.data?.author_tip_id === rec.author_tip_id);

    const creator_history = {
      total_content:       authorContent.length,
      verified_count:      authorContent.filter(c => c.status === "verified").length,
      prior_disputes:      priorDisputes.length,
      prior_upheld:        priorAdjudications.filter(t => t.data?.verdict === "UPHELD").length,
      prior_dismissed:     priorAdjudications.filter(t => t.data?.verdict === "DISMISSED").length,
      current_score:       authorScore.score,
      current_tier:        authorScore.tier.name,
      offense_count:       authorScore.offense_count,
    };

    // Jury status
    const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, req.params.ctid);
    const commitTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, req.params.ctid);
    const revealTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, req.params.ctid);

    const committedIds = new Set(commitTxs.map(t => t.data.juror_tip_id));
    const revealedIds  = new Set(revealTxs.map(t => t.data.juror_tip_id));

    const jury = {
      jurors: summonsTxs.map(s => ({
        juror_tip_id: s.data.juror_tip_id,
        status:       revealedIds.has(s.data.juror_tip_id) ? "revealed"
                    : committedIds.has(s.data.juror_tip_id) ? "committed"
                    : "summoned",
      })),
      commit_deadline: summonsTxs[0]?.data?.commit_deadline,
      reveal_deadline: summonsTxs[0]?.data?.reveal_deadline,
      total_summoned:  summonsTxs.length,
      total_committed: commitTxs.length,
      total_revealed:  revealTxs.length,
    };

    // Existing verdict (if resolved)
    const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, req.params.ctid);
    const verdict = adjTxs.length ? {
      verdict:          adjTxs[0].data.verdict,
      declared_origin:  adjTxs[0].data.declared_origin,
      confirmed_origin: adjTxs[0].data.confirmed_origin,
      match_count:      adjTxs[0].data.match_count,
      mismatch_count:   adjTxs[0].data.mismatch_count,
      abstain_count:    adjTxs[0].data.abstain_count,
      resolved_at:      adjTxs[0].timestamp,
    } : null;

    res.json({ content, dispute, ai_classifier, creator_history, jury, verdict });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // STAGE 3: EXPERT APPEAL
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * POST /v1/content/:ctid/appeal
   * File an appeal against a Stage 2 verdict. Must be within 48 hours.
   */
  app.post("/v1/content/:ctid/appeal", (req, res) => {
    try {
      const { appellant_tip_id, signature } = req.body;
      if (!appellant_tip_id) return res.status(400).json({ error: "appellant_tip_id required" });
      if (!signature)        return res.status(400).json({ error: "signature required" });

      // Must have an existing verdict
      const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, req.params.ctid);
      if (!adjTxs.length) return res.status(404).json({ error: "No Stage 2 verdict found for this content" });

      // Check no existing appeal
      const existingAppeal = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, req.params.ctid);
      if (existingAppeal.length) return res.status(409).json({ error: "Appeal already filed for this content" });

      // Must be within 48-hour window
      const verdictTime = new Date(adjTxs[0].timestamp).getTime();
      if (Date.now() - verdictTime > APPEAL.FILING_WINDOW_HOURS * 3600000) {
        return res.status(403).json({ error: "48-hour appeal window has expired" });
      }

      // Only author or disputer can appeal
      const rec = dag.getContent(req.params.ctid);
      const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, req.params.ctid);
      const disputerTipId = disputeTxs[0]?.data?.disputer_tip_id;
      const authorTipId = rec?.author_tip_id;
      if (appellant_tip_id !== authorTipId && appellant_tip_id !== disputerTipId) {
        return res.status(403).json({ error: "Only the content author or the original disputer can file an appeal" });
      }

      // Verify identity + signature
      const appellant = dag.getIdentity(appellant_tip_id);
      if (!appellant) return res.status(404).json({ error: "Appellant TIP-ID not found" });
      if (dag.isRevoked(appellant_tip_id)) return res.status(403).json({ error: "Appellant TIP-ID is revoked" });

      const APPEAL_FIELDS = ["appellant_tip_id"];
      if (!verifyBodySignature(req.body, signature, appellant.public_key, APPEAL_FIELDS)) {
        return res.status(403).json({ error: "Appellant signature verification failed" });
      }

      // Write APPEAL_FILED tx
      const appealTx = withTxId({
        tx_type:   TX_TYPES.APPEAL_FILED,
        timestamp: new Date().toISOString(),
        prev:      dag.getRecentPrev(),
        data: {
          ctid:             req.params.ctid,
          appellant_tip_id,
          stage2_verdict:   adjTxs[0].data.verdict,
          stake:            APPEAL.APPELLANT_STAKE,
        },
      });
      dag.addTx(appealTx);
      _broadcast(appealTx);

      // Select 3 experts
      const experts = selectExperts(dag, scoring, appealTx.tx_id, authorTipId, disputerTipId);
      const commitDeadline = new Date(Date.now() + APPEAL.COMMIT_WINDOW_HOURS * 3600000).toISOString();
      const revealDeadline = new Date(Date.now() + (APPEAL.COMMIT_WINDOW_HOURS + APPEAL.REVEAL_WINDOW_HOURS) * 3600000).toISOString();

      // Write JURY_SUMMONS for each expert (reuse summons tx type with appeal flag)
      const timestamp = new Date().toISOString();
      for (const expertTipId of experts.experts) {
        const summonsTx = nodeSignedAuto({
          tx_type:   TX_TYPES.JURY_SUMMONS,
          timestamp,
          prev:      dag.getRecentPrev(),
          data: {
            ctid:            req.params.ctid,
            dispute_tx_id:   appealTx.tx_id,
            juror_tip_id:    expertTipId,
            stake:           JURY.JUROR_STAKE,
            seed:            experts.seed,
            identity_count:  experts.identityCount,
            commit_deadline: commitDeadline,
            reveal_deadline: revealDeadline,
            is_appeal:       true,
          },
        }, config);
        dag.addTx(summonsTx);
        _broadcast(summonsTx);
      }

      // Update content status back to disputed (under appeal review)
      dag.updateContentStatus(req.params.ctid, "disputed");

      log.info(`Appeal filed for ${req.params.ctid} by ${appellant_tip_id}`);
      res.json({
        success: true,
        appeal_tx_id: appealTx.tx_id,
        stake_at_risk: APPEAL.APPELLANT_STAKE,
        experts: {
          selected: experts.experts,
          count: experts.experts.length,
          insufficient: experts.insufficient,
          commit_deadline: commitDeadline,
          reveal_deadline: revealDeadline,
        },
      });
    } catch (e) {
      log.error("Appeal error:", e.message);
      res.status(500).json({ error: "Internal server error", detail: e.message });
    }
  });

  /**
   * POST /v1/content/:ctid/appeal/commit
   * Expert submits hidden vote commitment for appeal.
   */
  app.post("/v1/content/:ctid/appeal/commit", async (req, res) => {
    try {
      const { juror_tip_id, commitment, signature } = req.body;
      if (!juror_tip_id) return res.status(400).json({ error: "juror_tip_id required" });
      if (!commitment)   return res.status(400).json({ error: "commitment required" });
      if (!signature)    return res.status(400).json({ error: "signature required" });

      const juror = dag.getIdentity(juror_tip_id);
      if (!juror) return res.status(404).json({ error: "Expert TIP-ID not found" });
      if (dag.isRevoked(juror_tip_id)) return res.status(403).json({ error: "Expert TIP-ID is revoked" });

      const COMMIT_FIELDS = ["juror_tip_id", "commitment"];
      if (!verifyBodySignature(req.body, signature, juror.public_key, COMMIT_FIELDS)) {
        return res.status(403).json({ error: "Expert signature verification failed" });
      }

      // Must be summoned as appeal expert (is_appeal flag)
      const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, req.params.ctid)
        .filter(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
      if (!summonsTxs.length) return res.status(403).json({ error: "You were not summoned as an expert for this appeal" });

      const commitDeadline = new Date(summonsTxs[0].data.commit_deadline).getTime();
      if (Date.now() > commitDeadline) return res.status(403).json({ error: "Commit window has closed" });

      const existingCommit = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, req.params.ctid)
        .find(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
      if (existingCommit) return res.status(409).json({ error: "You have already submitted a vote commitment" });

      const commitTx = withTxId({
        tx_type:   TX_TYPES.JURY_VOTE_COMMIT,
        timestamp: new Date().toISOString(),
        prev:      dag.getRecentPrev(),
        data: { ctid: req.params.ctid, juror_tip_id, commitment, is_appeal: true },
      });
      dag.addTx(commitTx);
      _broadcast(commitTx);

      res.json({ success: true, tx_id: commitTx.tx_id });
    } catch (e) {
      log.error("Appeal commit error:", e.message);
      res.status(500).json({ error: "Internal server error", detail: e.message });
    }
  });

  /**
   * POST /v1/content/:ctid/appeal/reveal
   * Expert reveals their vote and salt for appeal.
   */
  app.post("/v1/content/:ctid/appeal/reveal", async (req, res) => {
    try {
      const { juror_tip_id, vote, salt, confirmed_origin, signature } = req.body;
      if (!juror_tip_id) return res.status(400).json({ error: "juror_tip_id required" });
      if (!vote)         return res.status(400).json({ error: "vote required (MATCH, MISMATCH, or ABSTAIN)" });
      if (!salt)         return res.status(400).json({ error: "salt required" });
      if (!signature)    return res.status(400).json({ error: "signature required" });

      const VALID_VOTES = ["MATCH", "MISMATCH", "ABSTAIN"];
      if (!VALID_VOTES.includes(vote)) return res.status(400).json({ error: `Invalid vote. Must be one of: ${VALID_VOTES.join(", ")}` });
      if (vote === "MISMATCH" && !confirmed_origin) return res.status(400).json({ error: "confirmed_origin required when voting MISMATCH" });
      if (confirmed_origin && !ORIGIN[confirmed_origin]) return res.status(400).json({ error: `Invalid confirmed_origin` });

      const juror = dag.getIdentity(juror_tip_id);
      if (!juror) return res.status(404).json({ error: "Expert TIP-ID not found" });

      const REVEAL_FIELDS = confirmed_origin
        ? ["juror_tip_id", "vote", "salt", "confirmed_origin"]
        : ["juror_tip_id", "vote", "salt"];
      if (!verifyBodySignature(req.body, signature, juror.public_key, REVEAL_FIELDS)) {
        return res.status(403).json({ error: "Expert signature verification failed" });
      }

      // Must be summoned as appeal expert
      const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, req.params.ctid)
        .filter(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
      if (!summonsTxs.length) return res.status(403).json({ error: "You were not summoned as an expert for this appeal" });

      // Check reveal window
      const commitDeadline = new Date(summonsTxs[0].data.commit_deadline).getTime();
      const revealDeadline = new Date(summonsTxs[0].data.reveal_deadline).getTime();
      const now = Date.now();
      if (now < commitDeadline) return res.status(403).json({ error: "Reveal window has not opened yet" });
      if (now > revealDeadline) return res.status(403).json({ error: "Reveal window has closed" });

      // Verify commitment
      const commitTx = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, req.params.ctid)
        .find(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
      if (!commitTx) return res.status(404).json({ error: "No vote commitment found" });

      const computedCommitment = shake256(`${vote}:${salt}`);
      if (computedCommitment !== commitTx.data.commitment) {
        return res.status(403).json({ error: "Vote does not match commitment — vote discarded" });
      }

      // Check not already revealed
      const existingReveal = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, req.params.ctid)
        .find(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
      if (existingReveal) return res.status(409).json({ error: "You have already revealed your vote" });

      // Write reveal tx
      const revealTx = withTxId({
        tx_type:   TX_TYPES.JURY_VOTE_REVEAL,
        timestamp: new Date().toISOString(),
        prev:      dag.getRecentPrev(),
        data: {
          ctid: req.params.ctid, juror_tip_id, vote, salt,
          confirmed_origin: vote === "MISMATCH" ? confirmed_origin : null,
          is_appeal: true,
        },
      });
      dag.addTx(revealTx);
      _broadcast(revealTx);

      // Check if all experts revealed → trigger final verdict
      const allReveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, req.params.ctid)
        .filter(t => t.data?.is_appeal === true);
      const allSummons = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, req.params.ctid)
        .filter(t => t.data?.is_appeal === true);

      let appealVerdict = null;
      if (allReveals.length >= allSummons.length) {
        appealVerdict = applyAppealVerdict(req.params.ctid, allReveals, allSummons, dag, scoring, config);
      }

      res.json({ success: true, tx_id: revealTx.tx_id, verdict: appealVerdict });
    } catch (e) {
      log.error("Appeal reveal error:", e.message);
      res.status(500).json({ error: "Internal server error", detail: e.message });
    }
  });

  /**
   * POST /v1/content/:ctid/update-origin
   * Author can change origin code within 24 hours of registration at zero penalty.
   */
  app.post("/v1/content/:ctid/update-origin", (req, res) => {
    const rec = dag.getContent(req.params.ctid);
    if (!rec) return res.status(404).json({ error: "Content record not found" });

    const { author_tip_id, new_origin_code, signature } = req.body;
    if (!author_tip_id)    return res.status(400).json({ error: "author_tip_id required" });
    if (!new_origin_code)  return res.status(400).json({ error: "new_origin_code required" });
    if (!signature)        return res.status(400).json({ error: "signature required" });

    // Only the author can update
    if (author_tip_id !== rec.author_tip_id) {
      return res.status(403).json({ error: "Only the content author can update the origin code" });
    }

    // Only registered or pending_review content can be updated
    if (rec.status !== "registered" && rec.status !== "pending_review") {
      return res.status(403).json({ error: `Cannot update origin — content status is '${rec.status}'` });
    }

    // 24-hour window check
    const registeredAt = new Date(rec.registered_at).getTime();
    const now = Date.now();
    const GRACE_PERIOD = 24 * 60 * 60 * 1000; // 24 hours
    if (now - registeredAt > GRACE_PERIOD) {
      return res.status(403).json({ error: "24-hour grace period has expired. Origin code can no longer be changed." });
    }

    // Validate new origin code
    if (!ORIGIN[new_origin_code]) {
      return res.status(400).json({ error: `Invalid origin_code. Must be one of: ${Object.keys(ORIGIN).join(", ")}` });
    }

    // Verify author signature
    const author = dag.getIdentity(author_tip_id);
    if (!author) return res.status(404).json({ error: "Author identity not found" });

    const UPDATE_FIELDS = ["author_tip_id", "new_origin_code"];
    if (!verifyBodySignature(req.body, signature, author.public_key, UPDATE_FIELDS)) {
      return res.status(403).json({ error: "Author signature verification failed" });
    }

    // Write UPDATE_ORIGIN tx to DAG
    const updateTxBody = {
      tx_type:   TX_TYPES.UPDATE_ORIGIN,
      timestamp: new Date().toISOString(),
      prev:      dag.getRecentPrev(),
      data: {
        ctid:              req.params.ctid,
        old_origin_code:   rec.origin_code,
        new_origin_code,
        author_tip_id,
      },
    };
    const signedUpdateTx = withTxId(updateTxBody);
    const updateTx = dag.addTx(signedUpdateTx);
    _broadcast(updateTx);

    // Re-run pre-scan with new origin
    const preScan = preScanContent(rec.content_hash || "", new_origin_code, {});
    const newStatus = preScan.flagged ? "pending_review" : "registered";

    // Update derived content record
    dag.updateContentOrigin(req.params.ctid, new_origin_code, newStatus);

    log.info(`Origin updated: ${req.params.ctid} ${rec.origin_code} → ${new_origin_code} (by ${author_tip_id})`);

    res.json({
      success:          true,
      ctid:             req.params.ctid,
      old_origin_code:  rec.origin_code,
      new_origin_code,
      status:           newStatus,
      tx_id:            updateTx.tx_id,
    });
  });

  /**
   * POST /v1/content/:ctid/retract
   * Creator voluntarily retracts their own content. Penalty: -50 score.
   */
  app.post("/v1/content/:ctid/retract", (req, res) => {
    const rec = dag.getContent(req.params.ctid);
    if (!rec) return res.status(404).json({ error: "Content record not found" });

    const { author_tip_id, signature } = req.body;
    if (!author_tip_id) return res.status(400).json({ error: "author_tip_id required" });
    if (!signature)     return res.status(400).json({ error: "signature required" });

    // Only author can retract
    if (author_tip_id !== rec.author_tip_id) {
      return res.status(403).json({ error: "Only the content author can retract" });
    }

    // Can't retract already retracted or disputed content
    if (rec.status === "retracted") {
      return res.status(409).json({ error: "Content is already retracted" });
    }
    if (rec.status === "disputed") {
      return res.status(403).json({ error: "Cannot retract content that is under dispute" });
    }

    // Verify author identity + signature
    const author = dag.getIdentity(author_tip_id);
    if (!author) return res.status(404).json({ error: "Author identity not found" });
    if (dag.isRevoked(author_tip_id)) return res.status(403).json({ error: "Author TIP-ID is revoked" });

    const RETRACT_FIELDS = ["author_tip_id"];
    if (!verifyBodySignature(req.body, signature, author.public_key, RETRACT_FIELDS)) {
      return res.status(403).json({ error: "Author signature verification failed" });
    }

    // Write CONTENT_RETRACTED tx
    const retractTx = withTxId({
      tx_type:   TX_TYPES.CONTENT_RETRACTED,
      timestamp: new Date().toISOString(),
      prev:      dag.getRecentPrev(),
      data: {
        ctid:         req.params.ctid,
        author_tip_id,
        origin_code:  rec.origin_code,
        pre_retract_status: rec.status,
      },
    });
    dag.addTx(retractTx);
    _broadcast(retractTx);

    // Apply -50 score penalty
    scoring.applyScoreEvent(author_tip_id, SCORE_EVENTS.CONTENT_RETRACTION.delta, `Content retracted: ${req.params.ctid}`);

    // Update content status
    dag.updateContentStatus(req.params.ctid, "retracted");

    log.info(`Content retracted: ${req.params.ctid} by ${author_tip_id} (penalty: ${SCORE_EVENTS.CONTENT_RETRACTION.delta})`);

    res.json({
      success: true,
      ctid:    req.params.ctid,
      penalty: SCORE_EVENTS.CONTENT_RETRACTION.delta,
      tx_id:   retractTx.tx_id,
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DAG
  // ─────────────────────────────────────────────────────────────────────────

  app.get("/v1/dag/tx/:txId", (req, res) => {
    const tx = dag.getTx(req.params.txId);
    if (!tx) return res.status(404).json({ error: "Transaction not found" });
    res.json(tx);
  });

  // ─────────────────────────────────────────────────────────────────────────
  // REVOCATIONS (v2 FIX-05)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * GET /v1/revocations?since=ISO_TIMESTAMP
   * Returns revocation list for light node polling.
   */
  app.get("/v1/revocations", (req, res) => {
    const since = req.query.since || null;
    const revocations = dag.getRevocations(since);
    res.json({
      revocations,
      count:      revocations.length,
      node_id:    config.nodeId,
      generated:  new Date().toISOString(),
      next_since: new Date().toISOString(),
    });
  });

  /**
   * POST /v1/revocations
   * Issue a revocation transaction (VP or Council-signed).
   */
  app.post("/v1/revocations", (req, res) => {
    try {
      const { tx_type, tip_id, reason_code, evidence_hash, issuing_vp_id, signature } = req.body;

      if (!tip_id)        return res.status(400).json({ error: "tip_id is required" });
      if (!tx_type)       return res.status(400).json({ error: "tx_type is required" });
      if (!issuing_vp_id) return res.status(400).json({ error: "issuing_vp_id is required" });
      if (!signature)     return res.status(400).json({ error: "signature is required" });

      const validRevocTypes = [TX_TYPES.REVOKE_VOLUNTARY, TX_TYPES.REVOKE_VP, TX_TYPES.REVOKE_DECEASED, TX_TYPES.REVOKE_DEVICE];
      if (!validRevocTypes.includes(tx_type)) {
        return res.status(400).json({ error: `Invalid tx_type. Must be one of: ${validRevocTypes.join(", ")}` });
      }

      // Verify the issuing VP exists and is active
      const issuingVp = dag.getVP(issuing_vp_id);
      if (!issuingVp) return res.status(403).json({ error: `Issuing VP not found: ${issuing_vp_id}` });
      if (issuingVp.status !== "active") return res.status(403).json({ error: `Issuing VP is not active: ${issuing_vp_id}` });

      // Verify VP signature over required fields
      const REVOCATION_FIELDS = ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"];
      if (!verifyBodySignature(req.body, signature, issuingVp.public_key, REVOCATION_FIELDS)) {
        return res.status(403).json({ error: "VP signature verification failed — signature does not match issuing VP public key" });
      }

      const identity = dag.getIdentity(tip_id);
      if (!identity) return res.status(404).json({ error: "TIP-ID not found" });

      const timestamp = new Date().toISOString();
      const revokeTxBody = {
        tx_type,
        timestamp,
        prev: dag.getRecentPrev(),
        data: { tip_id, reason_code, evidence_hash, issuing_vp_id, signature },
      };
      const signedRevokeTx = withTxId(revokeTxBody);

      const revokeValidation = validateTransaction(signedRevokeTx, dag, {});
      if (!revokeValidation.valid) {
        return res.status(400).json({ error: revokeValidation.errors, layer: revokeValidation.layer });
      }

      const tx = dag.addTx(signedRevokeTx);
      _broadcast(tx);

      dag.addRevocation(tip_id, tx_type, timestamp, tx.tx_id);

      // Cascade: flag recent content for adjudication (REVOKE_VP only)
      if (tx_type === TX_TYPES.REVOKE_VP) {
        const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
        const recentContent = dag.getContentByAuthor(tip_id).filter(c => c.registered_at > cutoff);
        recentContent.forEach(c => {
          const cascadeTx = nodeSignedAuto({
            tx_type:   TX_TYPES.CONTENT_DISPUTED,
            timestamp: new Date().toISOString(),
            prev:      dag.getRecentPrev(),
            data: { ctid: c.ctid, reason: "issuer_revocation_cascade", auto: true },
          }, config);
          const cTx = dag.addTx(cascadeTx);
          _broadcast(cTx);
        });
        log.info(`Revocation cascade: ${recentContent.length} recent content records flagged for ${tip_id}`);
      }

      log.info(`Revocation issued: ${tip_id} (type: ${tx_type}, by: ${issuing_vp_id})`);
      res.status(201).json({ tx_id: tx.tx_id, tip_id, tx_type, timestamp });

    } catch (err) {
      log.error("Revocation error:", err);
      res.status(500).json({ error: "Internal server error", detail: err.message });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DEDUP — ZK PROOF (v2 FIX-02)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * GET /v1/dedup/merkle-root
   * Returns Merkle root for public audit of dedup count consistency.
   */
  app.get("/v1/dedup/merkle-root", (req, res) => {
    res.json({
      merkle_root:    computeMerkleRoot(dag),
      dedup_count:    dag.dedupCount(),
      identity_count: dag.getTxsByType(TX_TYPES.REGISTER_IDENTITY).length,
      node_id:        config.nodeId,
      generated:      new Date().toISOString(),
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // VERIFICATION PROVIDERS
  // ─────────────────────────────────────────────────────────────────────────

  app.post("/v1/vp/register", (req, res) => {
    try {
      const { name, jurisdiction_tier = "green", public_key, council_signature, approving_vp_id } = req.body;
      if (!name)              return res.status(400).json({ error: "name is required" });
      if (!public_key)        return res.status(400).json({ error: "public_key is required" });
      if (!council_signature) return res.status(400).json({ error: "council_signature is required" });
      if (!approving_vp_id)   return res.status(400).json({ error: "approving_vp_id is required" });

      // Only the founding VP can approve new VPs
      const foundingVpId = getFoundingVP().vp_id;
      if (approving_vp_id !== foundingVpId) {
        return res.status(403).json({ error: `Only the founding VP (${foundingVpId}) can approve new VPs` });
      }

      // Verify the approving VP exists and is active
      const approvingVp = dag.getVP(approving_vp_id);
      if (!approvingVp) return res.status(403).json({ error: `Approving VP not found: ${approving_vp_id}` });
      if (approvingVp.status !== "active") return res.status(403).json({ error: `Approving VP is not active: ${approving_vp_id}` });

      // Verify council signature over required fields
      const VP_REGISTER_FIELDS = ["name", "jurisdiction_tier", "public_key", "approving_vp_id"];
      if (!verifyBodySignature(req.body, council_signature, approvingVp.public_key, VP_REGISTER_FIELDS)) {
        return res.status(403).json({ error: "Council signature verification failed — signature does not match approving VP public key" });
      }

      const vpId       = generateTIPID("VP", public_key);
      const registeredAt = new Date().toISOString();

      const vpTxBody = {
        tx_type:   TX_TYPES.VP_REGISTERED,
        timestamp: registeredAt,
        prev:      dag.getRecentPrev(),
        data:      { vp_id: vpId, name, jurisdiction_tier, public_key, council_signature, approving_vp_id },
      };
      const signedVpTx = withTxId(vpTxBody);

      const vpValidation = validateTransaction(signedVpTx, dag, {});
      if (!vpValidation.valid) {
        return res.status(400).json({ error: vpValidation.errors, layer: vpValidation.layer });
      }

      const vpTx = dag.addTx(signedVpTx);
      _broadcast(vpTx);

      dag.saveVP({ vp_id: vpId, name, jurisdiction_tier, public_key, status: "active", registered_at: registeredAt });

      res.status(201).json({ vp_id: vpId, name, jurisdiction_tier, registered_at: registeredAt });

    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/v1/vp/:vpId", (req, res) => {
    const vp = dag.getVP(req.params.vpId);
    if (!vp) return res.status(404).json({ error: "Verification Provider not found" });
    res.json(vp);
  });

  // ─────────────────────────────────────────────────────────────────────────
  // NODE REGISTRY
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * POST /v1/node/register
   * Register a node on the DAG (approved by founding VP).
   *
   * Body:
   *   name               string   optional label
   *   public_key         string   node's ML-DSA-65 public key
   *   council_signature  string   founding VP signs required fields
   *   approving_vp_id    string   must be the founding VP
   */
  app.post("/v1/node/register", (req, res) => {
    try {
      const { name, public_key, council_signature, approving_vp_id } = req.body;
      if (!public_key)        return res.status(400).json({ error: "public_key is required" });
      if (!council_signature) return res.status(400).json({ error: "council_signature is required" });
      if (!approving_vp_id)   return res.status(400).json({ error: "approving_vp_id is required" });

      // Only the founding VP can approve new nodes
      const foundingVpId = getFoundingVP().vp_id;
      if (approving_vp_id !== foundingVpId) {
        return res.status(403).json({ error: `Only the founding VP (${foundingVpId}) can approve new nodes` });
      }

      const approvingVp = dag.getVP(approving_vp_id);
      if (!approvingVp) return res.status(403).json({ error: `Approving VP not found: ${approving_vp_id}` });
      if (approvingVp.status !== "active") return res.status(403).json({ error: `Approving VP is not active: ${approving_vp_id}` });

      // Verify council signature over required fields
      const NODE_REGISTER_FIELDS = ["name", "public_key", "approving_vp_id"];
      if (!verifyBodySignature(req.body, council_signature, approvingVp.public_key, NODE_REGISTER_FIELDS)) {
        return res.status(403).json({ error: "Council signature verification failed — signature does not match approving VP public key" });
      }

      const nodeId       = generateTIPID("NODE", public_key);
      const registeredAt = new Date().toISOString();

      const nodeTxBody = {
        tx_type:   TX_TYPES.NODE_REGISTERED,
        timestamp: registeredAt,
        prev:      dag.getRecentPrev(),
        data:      { node_id: nodeId, name, public_key, council_signature, approving_vp_id },
      };
      const signedNodeTx = withTxId(nodeTxBody);

      const nodeValidation = validateTransaction(signedNodeTx, dag, {});
      if (!nodeValidation.valid) {
        return res.status(400).json({ error: nodeValidation.errors, layer: nodeValidation.layer });
      }

      const nodeTx = dag.addTx(signedNodeTx);
      _broadcast(nodeTx);

      dag.saveNode({ node_id: nodeId, name, public_key, status: "active", registered_at: registeredAt });

      res.status(201).json({ node_id: nodeId, name, public_key, registered_at: registeredAt });

    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  // NODE INFO
  // ─────────────────────────────────────────────────────────────────────────

  app.get("/v1/node/info", (req, res) => {
    res.json({
      node_id:           config.nodeId,
      node_type:         config.nodeType,
      region:            config.region,
      public_url:        config.publicUrl,
      protocol_version:  PROTOCOL.version,
      node_version:      config.nodeVersion,
      dag_tx_count:      dag.count(),
      identity_count:    dag.getTxsByType(TX_TYPES.REGISTER_IDENTITY).length,
      content_count:     dag.getTxsByType(TX_TYPES.REGISTER_CONTENT).length,
      dedup_count:       dag.dedupCount(),
      peer_count:        config.peers.length,
      uptime_seconds:    Math.floor(process.uptime()),
      spec_url:          PROTOCOL.specUrl,
      issuer:            PROTOCOL.issuer,
    });
  });

  app.get("/v1/node/peers", (req, res) => {
    res.json({ peers: config.peers, count: config.peers.length, node_id: config.nodeId });
  });

  app.get("/v1/node/registry", (req, res) => {
    const nodes = dag.getAllNodes();
    res.json({ nodes, count: nodes.length, node_id: config.nodeId });
  });

  // Node lookup (after /node/info, /node/peers, /node/registry to avoid route conflict)
  app.get("/v1/node/:nodeId", (req, res) => {
    const node = dag.getNode(req.params.nodeId);
    if (!node) return res.status(404).json({ error: "Node not found" });
    res.json(node);
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 404 fallback
  // ─────────────────────────────────────────────────────────────────────────
  app.use((req, res) => {
    res.status(404).json({ error: "Endpoint not found", protocol: "TIP/2.0" });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Error handler
  // ─────────────────────────────────────────────────────────────────────────
  app.use((err, req, res, next) => {
    log.error("Unhandled error:", err);
    res.status(500).json({ error: "Internal server error" });
  });

  return app;
}

module.exports = { createApp };
