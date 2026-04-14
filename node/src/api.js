/**
 * @file @tip-protocol/node/src/api.js
 * @description TIP Protocol Node — Express REST API v1
 *
 * Thin orchestrator: creates services, mounts route modules, applies middleware.
 * Business logic lives in services/. HTTP handling lives in routes/.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const path = require("path");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");

const { errorHandler } = require("./middleware/error-handler");
const { requestId } = require("./middleware/request-id");
const { createTxSubmitter } = require("./services/helpers");

// Services
const { createIdentityService } = require("./services/identity-service");
const { createContentService } = require("./services/content-service");
const { createDisputeService } = require("./services/dispute-service");
const { createRevocationService } = require("./services/revocation-service");
const { createGovernanceService } = require("./services/governance-service");

// Routes
const healthRoutes = require("./routes/health");
const identityRoutes = require("./routes/identity");
const contentRoutes = require("./routes/content");
const disputeRoutes = require("./routes/dispute");
const revocationRoutes = require("./routes/revocation");
const governanceRoutes = require("./routes/governance");
const dagRoutes = require("./routes/dag");

function createApp({ dag, scoring, config, consensus: consensusRef = null, network: networkRef = null }) {
  const { submitTx, submitBatch } = createTxSubmitter(consensusRef);
  const ctx = { dag, scoring, config, submitTx, submitBatch, consensus: consensusRef, network: networkRef };

  // ── Create services ────────────────────────────────────────────────────────
  const identityService = createIdentityService(ctx);
  const contentService = createContentService(ctx);
  const disputeService = createDisputeService(ctx);
  const revocationService = createRevocationService(ctx);
  const governanceService = createGovernanceService(ctx);

  // ── Build Express app ──────────────────────────────────────────────────────
  const app = express();

  // CORS (before all routes including static)
  app.use(cors({ origin: config.corsOrigins, methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] }));

  // Static files (before auth/rate-limit)
  app.use("/v1/zk", express.static(path.resolve(__dirname, "../../circuits")));
  app.use("/download", express.static(path.resolve(__dirname, "../../browser-extension")));

  // Middleware
  app.use(requestId);
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(express.json({ limit: "4mb" }));
  morgan.token("req-id", (req) => req.id);
  app.use(morgan("[:date[iso]] :req-id :method :url :status :response-time ms"));

  const limiter = rateLimit({
    windowMs: config.rateLimitWindow, max: config.rateLimitMax,
    standardHeaders: true, legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        ok: false,
        status: 429,
        error: {
          message: "Rate limit exceeded. Try again shortly.",
          code: "RATE_LIMITED",
          request_id: req.id || null,
        },
      });
    },
  });
  app.use("/v1/", limiter);

  // TIP HTTP headers on all responses
  app.use((req, res, next) => {
    res.setHeader("X-TIP-Node-ID", config.nodeId);
    res.setHeader("X-TIP-Node-Version", config.nodeVersion);
    res.setHeader("X-TIP-Protocol", "TIP/2.0");

    // Wrap successful JSON responses in { ok: true, data: ... }
    // Error responses are wrapped by errorHandler middleware
    const _json = res.json.bind(res);
    res.json = (body) => {
      // Don't double-wrap if already wrapped (by errorHandler)
      if (body && body.ok !== undefined) return _json(body);
      return _json({ ok: true, status: res.statusCode, data: body });
    };

    next();
  });

  // ── Mount routes ───────────────────────────────────────────────────────────
  const API_VERSION = "/v1";

  // Health check at root (unversioned) + node info routes under /v1
  const healthRouter = healthRoutes.createRouter(ctx);
  app.use(healthRouter);
  app.use(API_VERSION, healthRouter);

  // All API routes under /v1
  app.use(API_VERSION, identityRoutes.createRouter({ identityService }));
  app.use(API_VERSION, contentRoutes.createRouter({ contentService }));
  app.use(API_VERSION, disputeRoutes.createRouter({ disputeService }));
  app.use(API_VERSION, revocationRoutes.createRouter({ revocationService }));
  app.use(API_VERSION, governanceRoutes.createRouter({ governanceService }));
  app.use(API_VERSION, dagRoutes.createRouter(ctx));

  // ── 404 catch-all (after all routes, before error handler) ─────────────────
  app.use((req, res) => {
    res.status(404).json({
      ok: false,
      status: 404,
      error: {
        message: `${req.method} ${req.path} not found`,
        code: "NOT_FOUND",
        request_id: req.id || null,
      },
    });
  });

  // ── Global error handler (must be last) ────────────────────────────────────
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
