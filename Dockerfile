# TIP Protocol Node -- Production Dockerfile (Node.js)
#
# Builds a minimal, production-ready image of the TIP Protocol full node.
# Uses multi-stage build: build stage installs dependencies, runtime stage
# copies only what is needed to run.
#
# Usage:
#   docker build -t tip-node .
#   docker run -p 4000:4000 -p 4001:4001 --env-file .env tip-node
#
# Or use docker-compose.yml for the full stack with PostgreSQL.
#
# Author: Dinesh Mendhe <chairman@theailab.org>
# Copyright 2026 The AI Lab Intelligence Unobscured, Inc.
# Licensed under TIPCL-1.0

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS build

WORKDIR /build

# Install native build tools required by better-sqlite3
RUN apk add --no-cache python3 make g++

# Copy package files and install production dependencies only
COPY node/package*.json ./node/
RUN cd node && npm ci --omit=dev

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime

# Metadata
LABEL org.opencontainers.image.title="TIP Protocol Node"
LABEL org.opencontainers.image.description="Trust Identity Protocol -- full node, REST API, DAG, trust scoring"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.authors="Dinesh Mendhe <chairman@theailab.org>"
LABEL org.opencontainers.image.vendor="The AI Lab Intelligence Unobscured, Inc."
LABEL org.opencontainers.image.url="https://theailab.org"
LABEL org.opencontainers.image.source="https://github.com/theailab-org/tip-protocol"
LABEL org.opencontainers.image.licenses="TIPCL-1.0"

# Create non-root user for security
RUN addgroup -g 1001 -S tipnode && \
    adduser  -u 1001 -S tipnode -G tipnode

WORKDIR /app

# Copy built node_modules from build stage
COPY --from=build /build/node/node_modules ./node/node_modules

# Copy application source
COPY node/src/        ./node/src/
COPY node/package.json ./node/package.json
COPY shared/          ./shared/
COPY scripts/seed.js  ./scripts/seed.js
COPY NOTICE.txt       ./NOTICE.txt
COPY LICENSE.txt      ./LICENSE.txt

# Create data directory with correct ownership
RUN mkdir -p /app/data && chown -R tipnode:tipnode /app

# Switch to non-root user
USER tipnode

# REST API port
EXPOSE 4000

# Gossip protocol port (P2P DAG propagation)
EXPOSE 4001

# Health check -- REST API must respond within 10 seconds
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:4000/health || exit 1

# Data directory as a volume so the DAG persists across container restarts
VOLUME ["/app/data"]

# Entry point
CMD ["node", "node/src/index.js"]
