/**
 * @file tests/routes/content-og-route.test.js
 * @description Wiring test for GET /v1/content/:ctid/og and a regression
 * guard that GET /v1/content/:ctid still dispatches to resolve() unchanged.
 */
"use strict";

const path = require("path");
const express = require("express");
const request = require("supertest");

const SRC = path.resolve(__dirname, "../../src");
const { createRouter } = require(path.join(SRC, "routes/content"));
const { errorHandler } = require(path.join(SRC, "middleware/error-handler"));

const CTID = "tip://c/OH-11111111111111-0001";
const SLIM = {
  ctid: CTID, origin_code: "OH", origin_label: "Original Human", status: "verified",
  title: "T", author_name: null, author_tip_id: "tip://id/US-a",
  author_score: 700, author_tier: "Trusted", registered_url: "https://x.com/p/1",
  created_at: 1775001600000,
};

function _app(contentService) {
  const app = express();
  app.use(express.json());
  app.use("/v1", createRouter({ contentService }));
  app.use(errorHandler);
  return app;
}

test("GET /v1/content/:ctid/og returns the slim projection + crawler cache header", async () => {
  const app = _app({ resolveForOg: (c) => ({ ...SLIM, ctid: c }) });
  const res = await request(app).get(`/v1/content/${encodeURIComponent(CTID)}/og`);
  expect(res.status).toBe(200);
  expect(res.body).toEqual({ ...SLIM, ctid: CTID });
  expect(res.headers["cache-control"]).toMatch(/max-age=300/);
});

test("GET /v1/content/:ctid still dispatches to resolve(), not resolveForOg()", async () => {
  let resolveCalled = false;
  const app = _app({
    resolve: async () => { resolveCalled = true; return { ok: true }; },
    resolveForOg: () => { throw new Error("resolveForOg must not be called by /:ctid"); },
  });
  const res = await request(app).get(`/v1/content/${encodeURIComponent(CTID)}`);
  expect(res.status).toBe(200);
  expect(resolveCalled).toBe(true);
});

test("GET /v1/content/:ctid asks resolve() for similar cards only with include=similar", async () => {
  const seen = [];
  const app = _app({ resolve: async (c, opts) => { seen.push(opts); return { ok: true }; } });
  const url = `/v1/content/${encodeURIComponent(CTID)}`;
  await request(app).get(url);
  await request(app).get(`${url}?include=similar`);
  await request(app).get(`${url}?include=fingerprints.text,image`);
  expect(seen[0]).toEqual({ includeSimilar: false });
  expect(seen[1]).toEqual({ includeSimilar: true });
  expect(seen[2]).toMatchObject({ includeSimilar: false, includeFingerprints: true, modalities: ["text", "image"] });
});

test("include lists similar and fingerprints in any order", async () => {
  const seen = [];
  const app = _app({ resolve: async (c, opts) => { seen.push(opts); return { ok: true }; } });
  const url = `/v1/content/${encodeURIComponent(CTID)}`;
  for (const q of ["similar,fingerprints", "fingerprints.text,similar", "fingerprints.text,image,similar", "similar,fingerprints.document", "fingerprints,fingerprints.text"]) {
    await request(app).get(`${url}?include=${q}`);
  }
  expect(seen[0]).toMatchObject({ includeSimilar: true, includeFingerprints: true, modalities: null });
  expect(seen[1]).toMatchObject({ includeSimilar: true, includeFingerprints: true, modalities: ["text"] });
  expect(seen[2]).toMatchObject({ includeSimilar: true, modalities: ["text", "image"] });
  expect(seen[3]).toMatchObject({ includeSimilar: true, modalities: ["document"] });
  expect(seen[4]).toMatchObject({ includeFingerprints: true, modalities: null });
});
