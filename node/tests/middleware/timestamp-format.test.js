/**
 * @file tests/middleware/timestamp-format.test.js
 * @description Locks the API-boundary timestamp normalisation contract.
 *
 * Boundary semantics during the ms-unification migration:
 *   - Outgoing: ms → ISO, ISO unchanged
 *   - Incoming: ISO → ms, ms unchanged
 *   - Unknown fields untouched (allow-list discipline)
 *   - Nested objects + arrays walked
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

const { timestampFormat, createTimestampFormat, TIMESTAMP_FIELDS } = require(path.join(SRC, "middleware", "timestamp-format"));
const { MS_FLOOR_2025_01_01_UTC } = require(path.join(SHARED, "time"));

const GENESIS_MS = 1773532800000; // 2026-03-15T00:00:00.000Z
const GENESIS_ISO = "2026-03-15T00:00:00.000Z";

// During the migration the default middleware is outgoing-only.
// Incoming-only and bidirectional flavours come from the factory.
function _runMiddleware(req, res, mw = timestampFormat) {
  return new Promise((resolve) => mw(req, res, resolve));
}
const bothDirectionsMw = createTimestampFormat({ outgoing: true, incoming: true });

function _mockRes() {
  const captured = {};
  const res = {
    json(body) { captured.body = body; return res; },
  };
  return { res, captured };
}

describe("timestampFormat — outgoing (res.json)", () => {

  test("converts ms → ISO for allow-listed fields", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      registered_at: GENESIS_MS,
      verified_at: GENESIS_MS + 1000,
      timestamp: GENESIS_MS + 2000,
    });
    expect(captured.body.registered_at).toBe(GENESIS_ISO);
    expect(captured.body.verified_at).toBe("2026-03-15T00:00:01.000Z");
    expect(captured.body.timestamp).toBe("2026-03-15T00:00:02.000Z");
  });

  test("leaves already-ISO strings unchanged (transitional safety)", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({ registered_at: GENESIS_ISO });
    expect(captured.body.registered_at).toBe(GENESIS_ISO);
  });

  test("ignores non-allow-listed fields with timestamp-y names", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      referenced_at: GENESIS_MS,         // not in allow-list
      triggered_at_round: 42,             // round counter, not a timestamp
      timestamp: GENESIS_MS,              // allow-listed
    });
    expect(captured.body.referenced_at).toBe(GENESIS_MS);
    expect(captured.body.triggered_at_round).toBe(42);
    expect(captured.body.timestamp).toBe(GENESIS_ISO);
  });

  test("walks nested objects", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      data: {
        identity: { tip_id: "tip://id/x", registered_at: GENESIS_MS },
      },
    });
    expect(captured.body.data.identity.registered_at).toBe(GENESIS_ISO);
  });

  test("walks arrays", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      items: [
        { registered_at: GENESIS_MS },
        { registered_at: GENESIS_MS + 1 },
      ],
    });
    expect(captured.body.items[0].registered_at).toBe(GENESIS_ISO);
    expect(captured.body.items[1].registered_at).toBe("2026-03-15T00:00:00.001Z");
  });

  test("leaves null / undefined values alone", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({ registered_at: null, verified_at: undefined });
    expect(captured.body.registered_at).toBeNull();
    expect(captured.body.verified_at).toBeUndefined();
  });
});

describe("timestampFormat — default (outgoing-only) leaves incoming bodies alone", () => {

  test("does NOT convert incoming ISO → ms (default middleware)", async () => {
    const req = { body: { registered_at: GENESIS_ISO, timestamp: GENESIS_ISO } };
    const { res } = _mockRes();
    await _runMiddleware(req, res);
    expect(req.body.registered_at).toBe(GENESIS_ISO);
    expect(req.body.timestamp).toBe(GENESIS_ISO);
  });
});

describe("createTimestampFormat({ incoming: true }) — opt-in incoming conversion", () => {

  test("converts ISO → ms for allow-listed fields", async () => {
    const req = { body: { registered_at: GENESIS_ISO, timestamp: GENESIS_ISO } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.registered_at).toBe(GENESIS_MS);
    expect(req.body.timestamp).toBe(GENESIS_MS);
  });

  test("leaves already-ms numbers unchanged", async () => {
    const req = { body: { registered_at: GENESIS_MS } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.registered_at).toBe(GENESIS_MS);
  });

  test("ignores non-allow-listed fields", async () => {
    const req = { body: { description: "2026-03-15T00:00:00.000Z", timestamp: GENESIS_ISO } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.description).toBe("2026-03-15T00:00:00.000Z"); // untouched
    expect(req.body.timestamp).toBe(GENESIS_MS);                    // converted
  });

  test("walks nested incoming bodies", async () => {
    const req = { body: { data: { registered_at: GENESIS_ISO } } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.data.registered_at).toBe(GENESIS_MS);
  });

  test("leaves bad ISO strings alone for the downstream validator to reject", async () => {
    const req = { body: { timestamp: "not-an-iso-string" } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.timestamp).toBe("not-an-iso-string");
  });
});

describe("TIMESTAMP_FIELDS allow-list", () => {

  test("contains the canonical TIP timestamp field names", () => {
    // Smoke check — any new wire timestamp must be added explicitly.
    expect(TIMESTAMP_FIELDS.has("timestamp")).toBe(true);
    expect(TIMESTAMP_FIELDS.has("registered_at")).toBe(true);
    expect(TIMESTAMP_FIELDS.has("verified_at")).toBe(true);
    expect(TIMESTAMP_FIELDS.has("committed_at")).toBe(true);
    expect(TIMESTAMP_FIELDS.has("cert_timestamp")).toBe(true);
    expect(TIMESTAMP_FIELDS.has("signed_at")).toBe(true);
  });

  test("does not contain round counters or unrelated *_at names", () => {
    expect(TIMESTAMP_FIELDS.has("triggered_at_round")).toBe(false);
    expect(TIMESTAMP_FIELDS.has("referenced_at")).toBe(false);
    expect(TIMESTAMP_FIELDS.has("created_at_block")).toBe(false);
  });

  test("plausibility-floor smoke — TIMESTAMP_FIELDS only encodes 2025+ ms values in practice", () => {
    // Defensive — confirms the helpers' floor constant is sensible
    // relative to genesis. If MS_FLOOR_2025_01_01_UTC ever drifts past
    // genesis this catches it.
    expect(GENESIS_MS).toBeGreaterThanOrEqual(MS_FLOOR_2025_01_01_UTC);
  });
});
