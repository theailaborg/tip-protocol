# TIP Protocol Node -- Production Dockerfile (Node.js)
#
# Builds a minimal, production-ready image of the TIP Protocol full node.
# Uses multi-stage build: build stage installs dependencies, runtime stage
# copies only what is needed to run.
#
# Usage:
#   docker build -t tip-node .
#   docker run -p 4000:4000 --env-file .env tip-node
#
# Or use docker-compose.yml for the full stack.
#
# Author: Dinesh Mendhe <chairman@theailab.org>
# Copyright 2026 The AI Lab Intelligence Unobscured, Inc.
# Licensed under TIPCL-1.0

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:24-alpine AS build

WORKDIR /build

# Install native build tools required by better-sqlite3
RUN apk add --no-cache python3 make g++

# Copy package files and install production dependencies
# Install all production dependencies (root + node workspace)
COPY package*.json ./
COPY node/package*.json ./node/
# Vendored local dependency: node/package.json references tip-content-fingerprint
# as file:vendor/...tgz, so the tarball must be in the context before install.
# npm extracts it into node_modules (a real dir), so only the build stage needs it.
COPY node/vendor/ ./node/vendor/
RUN npm install --omit=dev && \
    rm -rf node_modules/wasmcurves/test node_modules/wasmcurves/benchmarks

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM node:24-alpine AS runtime

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

# COPY --chown, never a post-hoc `chown -R`: a recursive chown rewrites every
# file into a duplicate layer , it doubled the image (266MB content -> 919MB)
# and its extraction is what kept failing on small-disk hosts.
COPY --from=build --chown=tipnode:tipnode /build/node_modules ./node_modules

COPY --chown=tipnode:tipnode node/src/         ./node/src/
COPY --chown=tipnode:tipnode node/package.json ./node/package.json
COPY --chown=tipnode:tipnode shared/           ./shared/
COPY --chown=tipnode:tipnode circuits/         ./circuits/
# Copy browser extension zip if present (glob trick: bracket makes COPY no-op if missing)
COPY --chown=tipnode:tipnode browser-extensio[n]/*.zip ./browser-extension/
COPY --chown=tipnode:tipnode package.json      ./package.json

# Genesis state the node reads at boot. genesis.json is the minted, self-contained
# block (carries protocol_constants). genesis-config.json is a seed-time input and
# is intentionally NOT shipped: the runtime reads everything from genesis.json.
COPY --chown=tipnode:tipnode genesis-data/genesis.json ./genesis-data/genesis.json

# Copy license/notice if they exist
COPY --chown=tipnode:tipnode NOTICE.tx[t]      ./
COPY --chown=tipnode:tipnode LICENSE.tx[t]     ./

RUN mkdir -p /app/data && chown tipnode:tipnode /app /app/data

# Switch to non-root user
USER tipnode

# REST API
EXPOSE 4000
# libp2p P2P consensus
EXPOSE 4001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:${PORT:-4000}/health || exit 1

# Data directory as a volume
VOLUME ["/app/data"]

# Entry point
CMD ["node", "node/src/index.js"]
