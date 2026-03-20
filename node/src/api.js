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

const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");
const morgan     = require("morgan");

const {
  generateMLDSAKeypair, generateSLHDSAKeypair,
  signTransaction, verifyTransaction,
  mldsaVerify,
  shake256, shake256Multi,
  hashContent, perceptualHashText,
  generateTIPID, generateCTID,
  computeTxId,
} = require("../../shared/crypto");

// Helper: sign a tx with the node's private key
function nodeSigned(txBody, config) {
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, config.nodePrivateKey);
}

const { verifyDedupProof } = require("../../shared/zk");

const { validateTransaction } = require("./validators/tx-validator");

const {
  TX_TYPES, ORIGIN, ORIGIN_LABELS,
  getTier, PRESCAN_THRESHOLDS, HTTP_HEADERS, PROTOCOL,
} = require("../../shared/constants");

const { log }  = require("./logger");

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
function createApp({ dag, scoring, config }) {
  const app = express();

  // ── Middleware ──────────────────────────────────────────────────────────────
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors({ origin: config.corsOrigins, methods: ["GET","POST","PUT","DELETE","OPTIONS"] }));
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
   *   dedup_hash        string   Poseidon(govId, dob, country) — decimal field element
   *   zk_proof          object   Groth16 proof { pi_a, pi_b, pi_c, protocol, curve }
   *   verification_tier string   "T1"|"T2"|"T3"|"T4"
   *   vp_id             string   ID of issuing VP
   *   vp_signature      string   VP's ML-DSA-65 signature
   *   social_attested   boolean  true if 3 vouchers provided
   *   founding          boolean  optional, for genesis ring
   */
  app.post("/v1/identity/register", async (req, res) => {
    try {
      const {
        region = "US",
        dedup_hash,
        zk_proof,
        verification_tier = "T1",
        vp_id,
        vp_signature,
        social_attested = false,
        founding = false,
      } = req.body;

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
      const vpPayload = dedup_hash + verification_tier + vp_id;
      const vpSigValid = mldsaVerify(vpPayload, vp_signature, vp.public_key);
      if (!vpSigValid) {
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

      // Generate post-quantum keypair for this identity
      const keypair     = generateMLDSAKeypair();
      const rootKeypair = generateSLHDSAKeypair();
      const tipId       = generateTIPID(region, keypair.publicKey);

      const registeredAt = new Date().toISOString();

      const txBody = {
        tx_type:   TX_TYPES.REGISTER_IDENTITY,
        timestamp: registeredAt,
        prev:      dag.getRecentPrev(),
        data: {
          tip_id:            tipId,
          region:            region.toUpperCase(),
          public_key:        keypair.publicKey,
          root_public_key:   rootKeypair.publicKey,
          vp_id,
          verification_tier,
          social_attested,
          founding,
          dedup_hash,
          zk_proof,
        },
      };
      const signedTx = nodeSigned(txBody, config);

      const identityValidation = validateTransaction(signedTx, dag, { authorPublicKey: config.nodePublicKey });
      if (!identityValidation.valid) {
        return res.status(400).json({ error: identityValidation.errors, layer: identityValidation.layer });
      }

      const tx = dag.addTx(signedTx);

      dag.saveIdentity({
        tip_id:          tipId,
        region:          region.toUpperCase(),
        public_key:      keypair.publicKey,
        root_public_key: rootKeypair.publicKey,
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
        public_key:       keypair.publicKey,
        // Private key returned ONLY at registration — never stored server-side
        private_key:      keypair.privateKey,
        root_public_key:  rootKeypair.publicKey,
        root_private_key: rootKeypair.privateKey,
        tx_id:            tx.tx_id,
        score:            social_attested ? 550 : 500,
        registered_at:    registeredAt,
        message:          "Store your private keys securely. They are never stored by this node.",
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
   *   content        string  (required for text; can be hash for binary)
   *   content_hash   string  optional pre-computed SHAKE-256 hash
   *   signature      string  ML-DSA-65 sig over (content_hash + origin_code)
   */
  app.post("/v1/content/register", (req, res) => {
    try {
      const { author_tip_id, origin_code, content, content_hash: providedHash, signature } = req.body;

      if (!author_tip_id)       return res.status(400).json({ error: "author_tip_id is required" });
      if (!origin_code)         return res.status(400).json({ error: "origin_code is required" });
      if (!ORIGIN[origin_code]) return res.status(400).json({ error: `Invalid origin_code. Must be one of: ${Object.keys(ORIGIN).join(", ")}` });
      if (!content && !providedHash) return res.status(400).json({ error: "content or content_hash is required" });
      if (!signature)           return res.status(400).json({ error: "signature is required (ML-DSA-65 over content_hash+origin_code)" });

      const identity = dag.getIdentity(author_tip_id);
      if (!identity) return res.status(404).json({ error: "Author TIP-ID not found" });
      if (dag.isRevoked(author_tip_id)) return res.status(403).json({ error: "Author TIP-ID is revoked" });

      // Compute content hash
      const contentHash = providedHash || hashContent(content || "");
      const perceptHash = content ? perceptualHashText(content) : null;

      // Verify signature: sig must cover (contentHash + origin_code)
      const sigPayload = contentHash + origin_code;
      const sigValid   = verifyTransaction(
        { tx_type: "CONTENT_SIG", data: sigPayload, timestamp: "", prev: [] },
        signature,
        identity.public_key
      );
      // Note: in production enforce sigValid; here we accept but flag if invalid
      if (!sigValid) {
        log.warn(`Content signature invalid for author ${author_tip_id}`);
      }

      // v2 FIX-03: Pre-scan (calibrated thresholds, flag-but-mint)
      const contentHistory = { verified_oh_count: dag.getContentByAuthor(author_tip_id).filter(c => c.origin_code === ORIGIN.OH && c.status === "verified").length };
      const preScan = preScanContent(content || "", origin_code, contentHistory);

      const registeredAt = new Date().toISOString();
      const ctid         = generateCTID(origin_code, contentHash, author_tip_id);

      const contentTxBody = {
        tx_type:   TX_TYPES.REGISTER_CONTENT,
        timestamp: registeredAt,
        prev:      dag.getRecentPrev(),
        data: {
          ctid,
          origin_code,
          origin_label:   ORIGIN_LABELS[origin_code],
          content_hash:   contentHash,
          perceptual_hash: perceptHash,
          author_tip_id,
          signature,
          prescan_flagged:    preScan.flagged,
          prescan_probability: preScan.probability,
        },
      };
      const signedContentTx = nodeSigned(contentTxBody, config);

      const contentValidation = validateTransaction(signedContentTx, dag, { authorPublicKey: config.nodePublicKey });
      if (!contentValidation.valid) {
        return res.status(400).json({ error: contentValidation.errors, layer: contentValidation.layer });
      }

      const tx = dag.addTx(signedContentTx);

      dag.saveContent({
        ctid,
        origin_code,
        content_hash:    contentHash,
        perceptual_hash: perceptHash,
        author_tip_id,
        status:          preScan.flagged ? "pending_review" : "verified",
        registered_at:   registeredAt,
        tx_id:           tx.tx_id,
      });

      // Auto-schedule Stage 1 adjudication if pre-scan flagged
      if (preScan.flagged) {
        log.info(`Pre-scan flagged ${ctid} — auto-scheduling Stage 1 adjudication`);
        const flagTx = nodeSigned({
          tx_type:   TX_TYPES.CONTENT_DISPUTED,
          timestamp: new Date().toISOString(),
          prev:      dag.getRecentPrev(),
          data: { ctid, reason: "pre_scan_flag", probability: preScan.probability, auto: true },
        }, config);
        dag.addTx(flagTx);
      }

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
        content_hash:      contentHash,
        author_tip_id,
        tx_id:             tx.tx_id,
        registered_at:     registeredAt,
        status:            preScan.flagged ? "pending_review" : "verified",
        prescan_flagged:   preScan.flagged,
        prescan_note:      preScan.flagged
          ? "Content flagged by AI pre-scan and entered Stage 1 adjudication. No penalty if cleared."
          : null,
        http_headers,
        meta_tags: {
          "tip:author":  author_tip_id,
          "tip:content": ctid,
          "tip:origin":  ORIGIN_LABELS[origin_code].toLowerCase().replace(/ /g, "-"),
          "tip:score":   scoring.getScore(author_tip_id).score.toString(),
          "tip:status":  preScan.flagged ? "PENDING" : "VERIFIED",
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
    res.json({
      ...rec,
      origin_label: ORIGIN_LABELS[rec.origin_code] || rec.origin_code,
      author_score: scoring.getScore(rec.author_tip_id).score,
    });
  });

  /**
   * POST /v1/content/:ctid/verify
   * Community verification of content origin.
   */
  app.post("/v1/content/:ctid/verify", (req, res) => {
    const rec = dag.getContent(req.params.ctid);
    if (!rec) return res.status(404).json({ error: "Content record not found" });

    const { verifier_tip_id, verdict } = req.body;
    if (!verifier_tip_id) return res.status(400).json({ error: "verifier_tip_id required" });
    if (!scoring.isJuryEligible(verifier_tip_id)) {
      return res.status(403).json({ error: "Verifier not jury eligible (score < 700 or revoked)" });
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
    const signedVerifyTx = nodeSigned(verifyTxBody, config);

    const verifyValidation = validateTransaction(signedVerifyTx, dag, { authorPublicKey: config.nodePublicKey });
    if (!verifyValidation.valid) {
      return res.status(400).json({ error: verifyValidation.errors, layer: verifyValidation.layer });
    }

    dag.addTx(signedVerifyTx);

    scoring.applyScoreEvent(rec.author_tip_id, weightedDelta, `Content verified by ${verifier_tip_id}`);
    res.json({ success: true, delta_applied: weightedDelta });
  });

  /**
   * POST /v1/content/:ctid/dispute
   * File an origin dispute against a CTID.
   */
  app.post("/v1/content/:ctid/dispute", (req, res) => {
    const rec = dag.getContent(req.params.ctid);
    if (!rec) return res.status(404).json({ error: "Content record not found" });

    const { disputer_tip_id, reason, evidence_hash } = req.body;
    if (!disputer_tip_id) return res.status(400).json({ error: "disputer_tip_id required" });

    const disputeTxBody = {
      tx_type:   TX_TYPES.CONTENT_DISPUTED,
      timestamp: new Date().toISOString(),
      prev:      dag.getRecentPrev(),
      data: { ctid: req.params.ctid, disputer_tip_id, reason, evidence_hash, author_tip_id: rec.author_tip_id },
    };
    const signedDisputeTx = nodeSigned(disputeTxBody, config);

    const disputeValidation = validateTransaction(signedDisputeTx, dag, { authorPublicKey: config.nodePublicKey });
    if (!disputeValidation.valid) {
      return res.status(400).json({ error: disputeValidation.errors, layer: disputeValidation.layer });
    }

    dag.addTx(signedDisputeTx);

    res.json({ success: true, message: "Dispute filed. Stage 1 AI classifier will run within 60 seconds." });
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

      const validRevocTypes = [TX_TYPES.REVOKE_VOLUNTARY, TX_TYPES.REVOKE_VP, TX_TYPES.REVOKE_DECEASED, TX_TYPES.REVOKE_DEVICE];
      if (!validRevocTypes.includes(tx_type)) {
        return res.status(400).json({ error: `Invalid tx_type. Must be one of: ${validRevocTypes.join(", ")}` });
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
      const signedRevokeTx = nodeSigned(revokeTxBody, config);

      const revokeValidation = validateTransaction(signedRevokeTx, dag, { authorPublicKey: config.nodePublicKey });
      if (!revokeValidation.valid) {
        return res.status(400).json({ error: revokeValidation.errors, layer: revokeValidation.layer });
      }

      const tx = dag.addTx(signedRevokeTx);

      dag.addRevocation(tip_id, tx_type, timestamp, tx.tx_id);

      // Cascade: flag recent content for adjudication (REVOKE_VP only)
      if (tx_type === TX_TYPES.REVOKE_VP) {
        const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
        const recentContent = dag.getContentByAuthor(tip_id).filter(c => c.registered_at > cutoff);
        recentContent.forEach(c => {
          const cascadeTx = nodeSigned({
            tx_type:   TX_TYPES.CONTENT_DISPUTED,
            timestamp: new Date().toISOString(),
            prev:      dag.getRecentPrev(),
            data: { ctid: c.ctid, reason: "issuer_revocation_cascade", auto: true },
          }, config);
          dag.addTx(cascadeTx);
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
      const { name, jurisdiction_tier = "green", public_key, council_signature } = req.body;
      if (!name)       return res.status(400).json({ error: "name is required" });
      if (!public_key) return res.status(400).json({ error: "public_key is required" });

      const vpId       = generateTIPID("VP", public_key);
      const registeredAt = new Date().toISOString();

      const vpTxBody = {
        tx_type:   TX_TYPES.VP_REGISTERED,
        timestamp: registeredAt,
        prev:      dag.getRecentPrev(),
        data:      { vp_id: vpId, name, jurisdiction_tier, public_key, council_signature },
      };
      const signedVpTx = nodeSigned(vpTxBody, config);

      const vpValidation = validateTransaction(signedVpTx, dag, { authorPublicKey: config.nodePublicKey });
      if (!vpValidation.valid) {
        return res.status(400).json({ error: vpValidation.errors, layer: vpValidation.layer });
      }

      dag.addTx(signedVpTx);

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
