/**
 * @file tests/routes/content-list-route.test.js
 * @description GET /v1/content over HTTP, through the real router, service
 * and SQLite store (node 2.9.6).
 *
 * Two promises are pinned here:
 *   1. Every request today's clients send is answered as before: the VP's
 *      record rail, verify page, duplicate-URL check, site batch, post index
 *      and the browser plugin's My Content only ever send author, bylined,
 *      origin, status, url, limit and cursor. Their pages, rows and cursors
 *      are unchanged; the response only gains `applied` and a row `title`.
 *   2. The 2.9.6 filters work end to end and fail with a 400 code, never a
 *      500, and the summary can never cost a person their list.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const express = require("express");
const request = require("supertest");

const SRC = path.resolve(__dirname, "../../src");
const { initDAG } = require(path.join(SRC, "dag"));
const contentRoutes = require(path.join(SRC, "routes", "content"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { errorHandler } = require(path.join(SRC, "middleware", "error-handler"));

const ME = "tip://id/US-5ec7105f0b1a9e21";
const ORG = "tip://id/GB-0123456789abcdef";
const NOV1 = Date.UTC(2026, 10, 1);
const H = 3600 * 1000;
const hex = (n) => n.toString(16).padStart(14, "0");

function rec(i, { email = false, author = ME, at, title, urls, origin = "OH", authors } = {}) {
  return {
    ctid: `tip://c/${origin}-${hex(i)}-9e21`, origin_code: origin, content_hash: "00".repeat(32),
    author_tip_id: author, signer_tip_id: author, authors: authors || [], attribution_mode: "self",
    extras: email ? { email: { v: 1 } } : (title ? { title } : {}),
    cna_version: "CNA-2.2", status: i % 7 === 3 ? "disputed" : "registered",
    registered_at: at, registered_urls: email ? [] : (urls || [`https://www.linkedin.com/posts/p-${i}`]),
    media: i % 5 === 0 && !email ? [{ media_id: "a".repeat(64), mime: "image/png" }] : [],
  };
}

let app, dag;
beforeAll(() => {
  dag = initDAG({ dbPath: ":memory:" });
  for (let i = 0; i < 30; i++) dag.saveContent(rec(i, { at: NOV1 - i * 24 * H, title: i === 4 ? "Coffee truck story" : undefined }));
  for (let j = 0; j < 45; j++) dag.saveContent(rec(1000 + j, { email: true, at: NOV1 - j * 10 * H - 60000 }));
  dag.saveContent(rec(5000, { author: ORG, at: NOV1 + H, origin: "AA", authors: [
    { key_mode: "attribution", role: "byline", signed: false, tip_id: ORG, tip_id_type: "organization" },
    { key_mode: "attribution", role: "byline", signed: false, tip_id: ME, tip_id_type: "personal" },
  ] }));
  const contentService = createContentService({
    dag, scoring: { getScore: () => ({ score: 0, tier: { name: "x" } }) }, config: {}, submitTx: () => {},
  });
  app = express();
  app.use("/v1", contentRoutes.createRouter({ contentService }));
  app.use(errorHandler);
});

const get = (qs) => request(app).get("/v1/content?" + qs);
const ids = (res) => res.body.items.map((r) => r.ctid);

describe("requests today's clients send are answered as before", () => {
  test("record page rail: author + limit, then the cursor, newest first with no gaps", async () => {
    const all = dag.listContent({ author: ME, limit: 1000 }).map((c) => c.ctid);
    const seen = [];
    let cursor = null;
    do {
      const res = await get(`limit=7&author=${encodeURIComponent(ME)}` + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""));
      expect(res.status).toBe(200);
      expect(res.body.summary).toBeUndefined();
      expect(res.body.applied).toEqual({ kind: null, from: null, to: null, q: null });
      seen.push(...ids(res));
      cursor = res.body.next_cursor;
    } while (cursor);
    expect(seen).toEqual(all);                     // emails included, exactly as before
    expect(seen).toHaveLength(75);
  });

  test("duplicate-URL check and site batch: url + limit find the one claimant", async () => {
    const res = await get(`url=${encodeURIComponent("https://www.linkedin.com/posts/p-4")}&limit=100`);
    expect(ids(res)).toEqual([`tip://c/OH-${hex(4)}-9e21`]);
    expect(res.body.items[0].title).toBe("Coffee truck story");
  });

  test("verify page and post index: the global newest list pages as before", async () => {
    const res = await get("limit=20");
    expect(res.status).toBe(200);
    expect(res.body.items).toHaveLength(20);
    expect(res.body.items[0].ctid).toBe(`tip://c/AA-${hex(5000)}-9e21`);
  });

  test("plugin My Content: author with origin and status, and the byline view", async () => {
    const dis = await get(`author=${encodeURIComponent(ME)}&status=disputed&limit=50`);
    expect(dis.body.items.length).toBeGreaterThan(0);
    expect(dis.body.items.every((r) => r.status === "disputed")).toBe(true);
    const by = await get(`bylined=${encodeURIComponent(ME)}&limit=20`);
    expect(ids(by)).toEqual([`tip://c/AA-${hex(5000)}-9e21`]);
  });

  test("a parameter the node does not know is still ignored", async () => {
    const a = await get(`author=${encodeURIComponent(ME)}&limit=5`);
    const b = await get(`author=${encodeURIComponent(ME)}&limit=5&sort=old&foo=bar`);
    expect(ids(b)).toEqual(ids(a));
  });
});

describe("2.9.6 sections, dates, search and summary over HTTP", () => {
  test("Posts and media page one carries the counts; Emails pages emails only", async () => {
    const p = await get(`author=${encodeURIComponent(ME)}&kind=post&limit=20&include=summary&tz=America/New_York`);
    expect(p.status).toBe(200);
    expect(p.body.items.every((r) => !r.is_email)).toBe(true);
    expect(p.body.summary).toMatchObject({ total: 75, posts: 30, emails: 45, tz: "America/New_York" });
    expect(p.body.summary.months.reduce((n, m) => n + m.posts + m.emails, 0)).toBe(75);
    const e1 = await get(`author=${encodeURIComponent(ME)}&kind=email&limit=20`);
    const e2 = await get(`author=${encodeURIComponent(ME)}&kind=email&limit=20&cursor=${encodeURIComponent(e1.body.next_cursor)}`);
    const e3 = await get(`author=${encodeURIComponent(ME)}&kind=email&limit=20&cursor=${encodeURIComponent(e2.body.next_cursor)}`);
    const all = [...e1.body.items, ...e2.body.items, ...e3.body.items];
    expect(all).toHaveLength(45);
    expect(new Set(all.map((r) => r.ctid)).size).toBe(45);
    expect(all.every((r) => r.is_email)).toBe(true);
    expect(e3.body.next_cursor).toBeNull();
  });

  test("a date range and a search narrow the page; applied echoes them", async () => {
    const r = await get(`author=${encodeURIComponent(ME)}&kind=post&from=${NOV1 - 3 * 24 * H}&to=${NOV1 + 1}`);
    expect(r.body.items).toHaveLength(4);         // Nov 1, Oct 31, 30, 29
    expect(r.body.applied).toEqual({ kind: "post", from: NOV1 - 3 * 24 * H, to: NOV1 + 1, q: null });
    const s = await get(`author=${encodeURIComponent(ME)}&q=COFFEE`);
    expect(s.body.items.map((x) => x.title)).toEqual(["Coffee truck story"]);
    expect(s.body.applied.q).toBe("coffee");
  });

  test("a zone the node does not know (Chrome's Etc/Unknown) still returns the page", async () => {
    const r = await get(`author=${encodeURIComponent(ME)}&kind=post&limit=20&include=summary&tz=Etc/Unknown`);
    expect(r.status).toBe(200);
    expect(r.body.items).toHaveLength(20);
    expect(r.body.summary.tz).toBe("UTC");
  });

  test.each([
    ["kind=video", "kind_invalid"],
    ["from=yesterday", "from_invalid"],
    ["from=20&to=10", "range_invalid"],
    ["q=budget", "q_needs_author"],
    [`author=${encodeURIComponent(ME)}&q=a`, "q_invalid"],
    ["include=summary", "summary_needs_author"],
    [`author=${encodeURIComponent(ME)}&include=summary&tz=${encodeURIComponent("a b")}`, "tz_invalid"],
  ])("%s is a 400 %s, never a 500", async (qs, code) => {
    const r = await get(qs);
    expect(r.status).toBe(400);
    expect(JSON.stringify(r.body)).toContain(code);
  });
});
