/**
 * @file tests/routes/nodes-route.test.js
 * @description GET /v1/nodes (public node registry) and the /status page it
 * feeds: public fields only, founding flag from genesis, no keys, and the
 * page is a self-contained document that reads only public endpoints.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const request = require("supertest");

const SRC = path.resolve(__dirname, "../../src");
const nodesRoutes = require(path.join(SRC, "routes", "nodes"));
const { GENESIS_PAYLOAD, getGenesisHash } = require(path.join(SRC, "genesis"));

const FOUNDING = GENESIS_PAYLOAD.founding_nodes[0].node_id;

function makeApp(rows) {
  const app = express();
  app.use("/v1", nodesRoutes.createRouter({
    dag: { getAllNodes: () => rows },
    config: { nodeId: "tip://node/self", nodeRegisteredId: "tip://node/self" },
  }));
  app.get("/status", (req, res) => res.sendFile(path.join(SRC, "public", "status.html")));
  return app;
}

const ROWS = [
  { node_id: "tip://node/partner1", name: "Partner One", status: "active", api_endpoint: "https://p1.example", operated_by: "tip://id/GB-1", registered_at: 1767225600000, public_key: "ab".repeat(16), algorithm: "ml-dsa-65" },
  { node_id: FOUNDING, name: "Founding", status: "active", api_endpoint: "https://node.example", operated_by: null, registered_at: 1767225600000, public_key: "cd".repeat(16) },
];

describe("GET /v1/nodes", () => {
  test("lists the registry with public fields only, founding nodes first", async () => {
    const res = await request(makeApp(ROWS)).get("/v1/nodes");
    expect(res.status).toBe(200);
    const d = res.body.data;
    expect(d.genesis_hash).toBe(getGenesisHash());
    expect(d.self).toBe("tip://node/self");
    expect(d.founding_node_ids).toContain(FOUNDING);
    expect(d.nodes.map(n => n.node_id)).toEqual([FOUNDING, "tip://node/partner1"]);
    expect(d.nodes[0]).toMatchObject({ founding: true, name: "Founding", api_endpoint: "https://node.example" });
    expect(d.nodes[1]).toMatchObject({ founding: false, operated_by: "tip://id/GB-1", status: "active" });
    for (const n of d.nodes) {
      expect(n).not.toHaveProperty("public_key");
      expect(n).not.toHaveProperty("algorithm");
    }
  });

  test("an empty or failing registry still answers", async () => {
    const res = await request(makeApp([])).get("/v1/nodes");
    expect(res.status).toBe(200);
    expect(res.body.data.nodes).toEqual([]);
    const app = express();
    app.use("/v1", nodesRoutes.createRouter({ dag: { getAllNodes: () => { throw new Error("db"); } }, config: {} }));
    const res2 = await request(app).get("/v1/nodes");
    expect(res2.status).toBe(200);
    expect(res2.body.data.nodes).toEqual([]);
  });
});

describe("GET /status", () => {
  test("serves the status page: self-contained, reads only public endpoints", async () => {
    const res = await request(makeApp(ROWS)).get("/status");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/html/);
    const html = res.text;
    for (const p of ["/ready", "/v1/health", "/v1/sync-status", "/v1/nodes"]) expect(html).toContain(`"${p}"`);
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/\/metrics|Authorization|Bearer/);
    expect(html).toContain("Connected to a genesis node");
    expect(html).toContain("Peers agree on state root");
  });

  test("the page file has no secrets and no external resources", () => {
    const html = fs.readFileSync(path.join(SRC, "public", "status.html"), "utf8");
    expect(html).not.toMatch(/https?:\/\/(?!schema|www\.w3)/);
    expect(html).not.toMatch(/key=|token=|secret/i);
  });
});
