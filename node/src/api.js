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
  txBody.tx_id = computeTxId(txBody);
  txBody.data.node_id = config.nodeRegisteredId || config.nodeId;
  return signTransaction(txBody, config.nodePrivateKey);
}


const { verifyDedupProof } = require("../../shared/zk");

const { validateTransaction } = require("./validators/tx-validator");

const {
  TX_TYPES, ORIGIN, ORIGIN_LABELS,
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
    if (verifier_tip_id === rec.author_tip_id) return res.status(403).json({ error: "Cannot verify your own content" });

    const VERIFY_FIELDS = ["verifier_tip_id", "verdict"];
    if (!verifyBodySignature(req.body, signature, verifier.public_key, VERIFY_FIELDS)) {
      return res.status(403).json({ error: "Verifier signature verification failed — signature does not match verifier public key" });
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

    const verifierScore = scoring.getScore(verifier_tip_id).score;
    const weightedDelta = Math.ceil((verifierScore / 1000) * 5); // 1-5 based on verifier trust

    const verifyTxBody = {
      tx_type:   TX_TYPES.CONTENT_VERIFIED,
      timestamp: new Date().toISOString(),
      prev:      dag.getRecentPrev(),
      data: {
        ctid:              req.params.ctid,
        verifier_tip_id,
        verdict:           verdict || "ORIGIN_CONFIRMED",
        weighted_delta:    weightedDelta,
        author_tip_id:     rec.author_tip_id,
      },
    };
    const signedVerifyTx = withTxId(verifyTxBody);

    const verifyValidation = validateTransaction(signedVerifyTx, dag, {});
    if (!verifyValidation.valid) {
      return res.status(400).json({ error: verifyValidation.errors, layer: verifyValidation.layer });
    }

    const verifyTx = dag.addTx(signedVerifyTx);
    _broadcast(verifyTx);

    scoring.applyScoreEvent(rec.author_tip_id, weightedDelta, `Content verified by ${verifier_tip_id}`);

    // Update content status to verified (community endorsed)
    if (rec.status === "registered") {
      dag.updateContentStatus(req.params.ctid, "verified");
    }

    res.json({ success: true, delta_applied: weightedDelta });
  });

  /**
   * POST /v1/content/:ctid/dispute
   * File an origin dispute against a CTID.
   */
  app.post("/v1/content/:ctid/dispute", (req, res) => {
    const rec = dag.getContent(req.params.ctid);
    if (!rec) return res.status(404).json({ error: "Content record not found" });

    if (rec.status === "pending_review") {
      return res.status(403).json({ error: "Content is pending review — wait for 24-hour grace period to end before disputing" });
    }

    const { disputer_tip_id, reason, evidence_hash, signature } = req.body;
    if (!disputer_tip_id) return res.status(400).json({ error: "disputer_tip_id required" });
    if (!signature)       return res.status(400).json({ error: "signature is required" });

    const disputer = dag.getIdentity(disputer_tip_id);
    if (!disputer) return res.status(404).json({ error: "Disputer TIP-ID not found" });
    if (dag.isRevoked(disputer_tip_id)) return res.status(403).json({ error: "Disputer TIP-ID is revoked" });

    const DISPUTE_FIELDS = ["disputer_tip_id", "reason", "evidence_hash"];
    if (!verifyBodySignature(req.body, signature, disputer.public_key, DISPUTE_FIELDS)) {
      return res.status(403).json({ error: "Disputer signature verification failed — signature does not match disputer public key" });
    }

    if (dag.hasDispute(req.params.ctid, disputer_tip_id)) {
      return res.status(409).json({ error: "You have already disputed this content" });
    }

    const disputeTxBody = {
      tx_type:   TX_TYPES.CONTENT_DISPUTED,
      timestamp: new Date().toISOString(),
      prev:      dag.getRecentPrev(),
      data: { ctid: req.params.ctid, disputer_tip_id, reason, evidence_hash, author_tip_id: rec.author_tip_id },
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

    res.json({ success: true, message: "Dispute filed. Content verification blocked until resolved." });
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
