/**
 * @file tests/services/explorer-api.test.js
 * @description Explorer APIs — content list (store conformance, filters,
 * cursor pagination), enriched media metadata on resolve, and the
 * identity key-history endpoint surface.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const contentListSchema = require(path.join(SRC, "schemas/content-list"));

const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

beforeAll(async () => {
  await initCrypto();
  try { PC._resetForTesting(); } catch { /* not yet initialised */ }
  PC.init(getGenesisPayload().protocol_constants);
});

// ── fixtures ───────────────────────────────────────────────────────────────

const AUTHOR_A = "tip://id/US-aaaaaaaaaaaaaaaa";
const AUTHOR_B = "tip://id/DE-bbbbbbbbbbbbbbbb";

function _row(i, { author = AUTHOR_A, origin = "OH", status = "registered", media = [] } = {}) {
  const hash14 = String(i).padStart(2, "0").repeat(7);
  return {
    ctid: `tip://c/${origin}-${hash14}-${author.slice(-4)}`,
    origin_code: origin,
    content_hash: shake256(`content-${i}`),
    author_tip_id: author,
    signer_tip_id: author,
    authors: [],
    attribution_mode: "self",
    extras: {},
    cna_version: "CNA-2.2",
    status,
    prescan_flagged: 0,
    prescan_probability: 0.1,
    prescan_tier: "low",
    prescan_status: "completed",
    registered_at: 1_780_000_000_000 + i * 1000,
    registered_urls: [`https://example.com/${i}`],
    media,
    media_canonical_hash: media.length ? shake256(media.map(m => m.media_id).join("")) : null,
  };
}

function _seedStore(store) {
  // 5 rows: 0..4 (ascending registered_at; list returns newest first)
  store.saveContent(_row(0));
  store.saveContent(_row(1, { author: AUTHOR_B, origin: "AA" }));
  store.saveContent(_row(2, { media: [{ media_id: "a".repeat(64), mime: "image/png" }] }));
  store.saveContent(_row(3, { status: "disputed" }));
  store.saveContent(_row(4, { author: AUTHOR_B, origin: "AA", media: [{ media_id: "b".repeat(64), mime: "video/mp4" }] }));
}

function _makeStores() {
  const os = require("os");
  const { MemoryStore, SQLiteStore } = require(path.join(SRC, "dag"));
  const sqlitePath = path.join(os.tmpdir(), `tip-explorer-test-${process.pid}-${Math.floor(performance.now() * 1000)}.db`);
  return [
    ["memory", new MemoryStore()],
    ["sqlite", new SQLiteStore(sqlitePath)],
  ];
}

// ── store conformance: listContent ─────────────────────────────────────────

describe.each(_makeStores())("listContent — %s store", (_name, store) => {
  beforeAll(() => _seedStore(store));

  test("no filters → newest first, all rows", () => {
    const rows = store.listContent({ limit: 20 });
    expect(rows.map(r => r.registered_urls[0])).toEqual([
      "https://example.com/4", "https://example.com/3", "https://example.com/2",
      "https://example.com/1", "https://example.com/0",
    ]);
  });

  test("author filter", () => {
    const rows = store.listContent({ author: AUTHOR_B, limit: 20 });
    expect(rows).toHaveLength(2);
    expect(rows.every(r => r.author_tip_id === AUTHOR_B)).toBe(true);
  });

  test("origin filter", () => {
    const rows = store.listContent({ origin: "AA", limit: 20 });
    expect(rows).toHaveLength(2);
  });

  test("status filter", () => {
    const rows = store.listContent({ status: "disputed", limit: 20 });
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("disputed");
  });

  test("hasMedia filter", () => {
    const rows = store.listContent({ hasMedia: true, limit: 20 });
    expect(rows).toHaveLength(2);
    expect(rows.every(r => r.media.length > 0)).toBe(true);
  });

  test("limit returns limit+1 rows for has-more detection", () => {
    const rows = store.listContent({ limit: 2 });
    expect(rows).toHaveLength(3); // 2 requested + 1 sentinel
  });

  test("cursor pages without overlap or gaps", () => {
    const page1 = store.listContent({ limit: 2 });
    const last = page1[1]; // page boundary (limit=2 → rows 0..1 are the page)
    const page2 = store.listContent({ limit: 2, cursor: { t: last.registered_at, c: last.ctid } });
    const seen = [...page1.slice(0, 2), ...page2.slice(0, 2)].map(r => r.ctid);
    expect(new Set(seen).size).toBe(4); // no duplicates across pages
  });
});

// ── key history conformance ────────────────────────────────────────────────

describe.each(_makeStores())("getEntityKeyHistory — %s store", (_name, store) => {
  test("returns chain oldest-first with open-ended current key", () => {
    const tipId = "tip://id/US-cccccccccccccccc";
    store.saveEntityKey({ entity_type: "identity", entity_id: tipId, public_key: "aa01", algorithm: "ml-dsa-65", valid_from_ts: 1000, valid_to_ts: 2000, source_tx_id: "tx1" });
    store.saveEntityKey({ entity_type: "identity", entity_id: tipId, public_key: "bb02", algorithm: "ml-dsa-65", valid_from_ts: 2000, valid_to_ts: null, source_tx_id: "tx2" });
    const history = store.getEntityKeyHistory("identity", tipId);
    expect(history).toHaveLength(2);
    expect(history[0]).toMatchObject({ public_key: "aa01", valid_to_ts: 2000 });
    expect(history[1]).toMatchObject({ public_key: "bb02", valid_to_ts: null });
  });
});

// ── service: list + cursor round-trip ──────────────────────────────────────

describe("contentService.list", () => {
  const { createContentService } = require(path.join(SRC, "services/content-service"));
  const { MemoryStore } = require(path.join(SRC, "dag"));

  let service;
  beforeAll(() => {
    const store = new MemoryStore();
    _seedStore(store);
    const dag = { listContent: (o) => store.listContent(o) };
    service = createContentService({ dag, scoring: { getScore: () => ({ score: 0, tier: { name: "x" } }) }, config: {}, submitTx: () => { } });
  });

  test("slim rows + media_count, no heavy fields", () => {
    const out = service.list({ limit: "3" });
    expect(out.items).toHaveLength(3);
    expect(out.items[0]).toMatchObject({ media_count: 1, origin_code: "AA" });
    expect(out.items[0].media).toBeUndefined();
    expect(out.items[0].extras).toBeUndefined();
    expect(typeof out.next_cursor).toBe("string");
  });

  test("cursor round-trips to the next page with no overlap", () => {
    const p1 = service.list({ limit: "3" });
    const p2 = service.list({ limit: "3", cursor: p1.next_cursor });
    expect(p2.items).toHaveLength(2);
    expect(p2.next_cursor).toBeNull();
    const all = [...p1.items, ...p2.items].map(i => i.ctid);
    expect(new Set(all).size).toBe(5);
  });

  test("invalid query values → 400 codes", () => {
    expect(() => service.list({ limit: "0" })).toThrow(expect.objectContaining({ code: "limit_invalid" }));
    expect(() => service.list({ limit: "101" })).toThrow(expect.objectContaining({ code: "limit_invalid" }));
    expect(() => service.list({ cursor: "garbage!" })).toThrow(expect.objectContaining({ code: "cursor_invalid" }));
    expect(() => service.list({ author: "not-a-tip-id" })).toThrow(expect.objectContaining({ code: "author_invalid" }));
    expect(() => service.list({ origin: "XX" })).toThrow(expect.objectContaining({ code: "origin_invalid" }));
    expect(() => service.list({ status: "bogus" })).toThrow(expect.objectContaining({ code: "status_invalid" }));
  });
});

// ── schema: cursor encode/decode symmetry ──────────────────────────────────

describe("content-list schema cursor", () => {
  test("encode/decode round-trip", () => {
    const row = { registered_at: 1_780_000_004_000, ctid: "tip://c/AA-08080808080808-bbbb" };
    const cur = contentListSchema.encodeCursor(row);
    expect(contentListSchema.decodeCursor(cur)).toEqual({ t: row.registered_at, c: row.ctid });
  });

  test("tampered cursor rejected", () => {
    expect(() => contentListSchema.decodeCursor("AAAA")).toThrow(expect.objectContaining({ code: "cursor_invalid" }));
  });
});

// ── resolve(): per-media AI scores from the verdict tx ─────────────────────

describe("contentService.resolve — media ai_probability projection", () => {
  const { createContentService } = require(path.join(SRC, "services/content-service"));
  const { TX_TYPES } = require(path.join(SHARED, "constants"));

  test("merges media_results scores into enriched media[]", async () => {
    const MID_A = "a".repeat(64);
    const MID_B = "b".repeat(64);
    const rec = _row(7, { media: [
      { media_id: MID_A, mime: "image/png" },
      { media_id: MID_B, mime: "image/jpeg" },
    ] });
    const verdictTx = {
      tx_id: "f".repeat(64),
      tx_type: TX_TYPES.PRESCAN_COMPLETED,
      data: {
        ctid: rec.ctid,
        media_results: [
          { media_id: MID_A, mime: "image/png", probability: 0.40, provider: "image_detector" },
          { media_id: MID_B, mime: "image/jpeg", probability: 0.95, provider: "image_detector" },
        ],
      },
    };
    const dag = {
      getContent: () => rec,
      getTx: () => null,
      getIdentity: () => ({ status: "active" }),
      getRevocation: () => null,
      getTxsByTypeAndCtid: (type) => type === TX_TYPES.PRESCAN_COMPLETED ? [verdictTx] : [],
      getOpenPrescanReviewByCtid: () => null,
    };
    const mediaService = { head: async () => ({ exists: true, size: 123 }) };
    const service = createContentService({
      dag, mediaService,
      scoring: { getScore: () => ({ score: 0, tier: { name: "x" } }) },
      config: {}, submitTx: () => {},
    });
    const out = await service.resolve(rec.ctid);
    expect(out.media[0]).toMatchObject({ media_id: MID_A, ai_probability: 0.40, ai_provider: "image_detector", stored: true });
    expect(out.media[1]).toMatchObject({ media_id: MID_B, ai_probability: 0.95 });
  });

  test("no verdict tx yet → ai_probability null", async () => {
    const MID = "c".repeat(64);
    const rec = _row(8, { media: [{ media_id: MID, mime: "image/png" }] });
    const dag = {
      getContent: () => rec, getTx: () => null,
      getIdentity: () => ({ status: "active" }), getRevocation: () => null,
      getTxsByTypeAndCtid: () => [],
      getOpenPrescanReviewByCtid: () => null,
    };
    const service = createContentService({
      dag, mediaService: { head: async () => ({ exists: true, size: 1 }) },
      scoring: { getScore: () => ({ score: 0, tier: { name: "x" } }) },
      config: {}, submitTx: () => {},
    });
    const out = await service.resolve(rec.ctid);
    expect(out.media[0].ai_probability).toBeNull();
  });
});
