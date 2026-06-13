#!/usr/bin/env node
/**
 * @file scripts/classifier-stub.js
 * @description DEV-ONLY: minimal AI-classifier stand-in so the async
 * prescan worker (init-prescan-worker.js) can complete locally without a
 * real classifier deployment. Returns a fixed low-probability text verdict
 * for every submission — content lands as tier=low, not flagged, and
 * `prescan_status` flips to "completed" so disputes can be filed.
 *
 * Usage:
 *   node scripts/classifier-stub.js [--port 9555] [--probability 0.12]
 *
 * Point the nodes at it (containers reach the host via host.docker.internal):
 *   TIP_CLASSIFIER_URL=http://host.docker.internal:9555
 * (see docker-compose.classifier-stub.yml overlay)
 */

"use strict";

const http = require("http");

function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : dflt;
}
const PORT = parseInt(arg("port", "9555"), 10);
const PROBABILITY = parseFloat(arg("probability", "0.12"));

function respond(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(body);
}

const server = http.createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => { raw += c; });
  req.on("end", () => {
    if (req.method === "GET" && req.url === "/health") {
      return respond(res, 200, { ok: true, service: "classifier-stub" });
    }
    if (req.method === "GET" && req.url === "/v1/providers") {
      return respond(res, 200, { providers: [{ name: "stub", status: "ok" }] });
    }
    if (req.method === "POST" && (req.url === "/v1/prescan" || req.url === "/v1/stage1")) {
      let parsed = {};
      try { parsed = raw ? JSON.parse(raw) : {}; } catch { /* keep {} */ }
      const hasFile = !!parsed.file_base64;
      const out = {
        provider_used: "stub-ensemble",
        classifier_version: "stub-1.0",
        modality_results: [{
          modality: hasFile ? "image" : "text",
          probability: PROBABILITY,
          weight: 1,
          provider: "stub",
          error: null,
        }],
      };
      console.log(`[stub] ${req.url} origin=${parsed.origin_code || "?"} text_len=${(parsed.text || "").length} → p=${PROBABILITY}`);
      return respond(res, 200, out);
    }
    respond(res, 404, { error: `no stub route for ${req.method} ${req.url}` });
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`classifier-stub listening on http://0.0.0.0:${PORT} (probability=${PROBABILITY})`);
});
