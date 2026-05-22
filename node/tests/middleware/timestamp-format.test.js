/**
 * @file tests/middleware/timestamp-format.test.js
 * @description Locks the API-boundary timestamp normalisation contract.
 *
 * Boundary semantics during the ms-unification migration:
 *   - Outgoing: ms → ISO when key matches pattern AND value is valid ms.
 *   - Incoming: ISO → ms when key matches pattern AND value is strict
 *     ISO 8601 (the canonical form `toIso()` produces).
 *   - Pattern-matched keys with non-conforming values pass through
 *     (the value-shape gate is what makes pattern-based key detection
 *     safe). Unknown keys are walked into but not converted.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

const {
  timestampFormat,
  createTimestampFormat,
  TIMESTAMP_PATTERN,
  TIMESTAMP_EXCLUDE,
  STRICT_ISO_RE,
  isTimestampField,
} = require(path.join(SRC, "middleware", "timestamp-format"));
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

  test("converts ms → ISO for pattern-matched fields", async () => {
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

  test("converts camelCase *At fields (lastAdvanceAt, lastRoundAdvanceAt)", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      lastAdvanceAt: GENESIS_MS,
      lastRoundAdvanceAt: GENESIS_MS + 1,
      rotationAt: GENESIS_MS + 2,
    });
    expect(captured.body.lastAdvanceAt).toBe(GENESIS_ISO);
    expect(captured.body.lastRoundAdvanceAt).toBe("2026-03-15T00:00:00.001Z");
    expect(captured.body.rotationAt).toBe("2026-03-15T00:00:00.002Z");
  });

  test("converts *_deadline and *_since fields", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      filing_deadline: GENESIS_MS,
      commit_deadline: GENESIS_MS + 1,
      verified_since: GENESIS_MS + 2,
    });
    expect(captured.body.filing_deadline).toBe(GENESIS_ISO);
    expect(captured.body.commit_deadline).toBe("2026-03-15T00:00:00.001Z");
    expect(captured.body.verified_since).toBe("2026-03-15T00:00:00.002Z");
  });

  test("converts /outcome short-form `at` field", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({ tx_id: "tip://tx/abc", status: "committed", at: GENESIS_MS });
    expect(captured.body.at).toBe(GENESIS_ISO);
  });

  test("converts *_ms suffix timestamps (bft_time_genesis_ms)", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      bft_time_genesis_ms: GENESIS_MS,
      confirmed_at_ms: GENESIS_MS + 1,
      rejected_at_ms: GENESIS_MS + 2,
    });
    expect(captured.body.bft_time_genesis_ms).toBe(GENESIS_ISO);
    expect(captured.body.confirmed_at_ms).toBe("2026-03-15T00:00:00.001Z");
    expect(captured.body.rejected_at_ms).toBe("2026-03-15T00:00:00.002Z");
  });

  test("*_ms duration fields stay as integers (value gate rejects sub-floor values)", async () => {
    // Many `_ms` fields are durations not timestamps (timeout, window,
    // interval, grace). These are sub-MS_FLOOR small integers; the
    // value gate (`isValidMs`) keeps them as raw numbers even though
    // the key matches the pattern.
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      flagged_ms: 172_800_000,           // 48h grace duration
      unflagged_ms: 86_400_000,          // 24h grace duration
      round_timeout_ms: 5_000,           // 5s
      decision_window_ms: 600_000,       // 10min
      bft_time_genesis_ms: GENESIS_MS,   // real timestamp — does convert
    });
    expect(captured.body.flagged_ms).toBe(172_800_000);
    expect(captured.body.unflagged_ms).toBe(86_400_000);
    expect(captured.body.round_timeout_ms).toBe(5_000);
    expect(captured.body.decision_window_ms).toBe(600_000);
    expect(captured.body.bft_time_genesis_ms).toBe(GENESIS_ISO);
  });

  test("converts decision_window_ends_at, node_seen_at (UAT-regression names)", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      decision_window_ends_at: GENESIS_MS,
      node_seen_at: GENESIS_MS + 1,
    });
    expect(captured.body.decision_window_ends_at).toBe(GENESIS_ISO);
    expect(captured.body.node_seen_at).toBe("2026-03-15T00:00:00.001Z");
  });

  test("leaves already-ISO strings unchanged (transitional safety)", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({ registered_at: GENESIS_ISO });
    expect(captured.body.registered_at).toBe(GENESIS_ISO);
  });

  test("excludes round counters (*_at_round) and ack_signed_ats", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      triggered_at_round: 42,
      rejected_at_round: 7,
      ack_signed_ats: [GENESIS_MS, GENESIS_MS + 1],
      timestamp: GENESIS_MS,
    });
    expect(captured.body.triggered_at_round).toBe(42);
    expect(captured.body.rejected_at_round).toBe(7);
    expect(captured.body.ack_signed_ats).toEqual([GENESIS_MS, GENESIS_MS + 1]);
    expect(captured.body.timestamp).toBe(GENESIS_ISO);
  });

  test("value gate: pattern-matched key with non-ms value passes through", async () => {
    // A field that *looks* like a timestamp by name but doesn't hold
    // an epoch-ms integer must NOT be munged. This is what makes the
    // pattern-based detection safe.
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      referenced_at: "https://example.com/article#section1", // URL fragment, not a timestamp
      generated_at: 42,                                       // small int, not ms
      committed_at: null,                                     // explicit null
    });
    expect(captured.body.referenced_at).toBe("https://example.com/article#section1");
    expect(captured.body.generated_at).toBe(42);
    expect(captured.body.committed_at).toBeNull();
  });

  test("walks nested objects", async () => {
    const req = { body: {} };
    const { res, captured } = _mockRes();
    await _runMiddleware(req, res);
    res.json({
      data: {
        identity: { tip_id: "tip://id/x", registered_at: GENESIS_MS },
        consensus: { narwhal: { lastRoundAdvanceAt: GENESIS_MS + 1 } },
      },
    });
    expect(captured.body.data.identity.registered_at).toBe(GENESIS_ISO);
    expect(captured.body.data.consensus.narwhal.lastRoundAdvanceAt).toBe("2026-03-15T00:00:00.001Z");
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

  test("converts strict-ISO → ms for pattern-matched fields", async () => {
    const req = { body: { registered_at: GENESIS_ISO, timestamp: GENESIS_ISO } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.registered_at).toBe(GENESIS_MS);
    expect(req.body.timestamp).toBe(GENESIS_MS);
  });

  test("converts camelCase and *_deadline incoming too", async () => {
    const req = { body: { lastAdvanceAt: GENESIS_ISO, filing_deadline: GENESIS_ISO } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.lastAdvanceAt).toBe(GENESIS_MS);
    expect(req.body.filing_deadline).toBe(GENESIS_MS);
  });

  test("leaves already-ms numbers unchanged", async () => {
    const req = { body: { registered_at: GENESIS_MS } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.registered_at).toBe(GENESIS_MS);
  });

  test("rejects non-strict-ISO forms (date-only, locale, garbage)", async () => {
    // Loose Date-parseable strings used to silently round-trip via
    // fromIso. The strict regex now requires `toIso()`'s canonical
    // form, so these stay untouched for the downstream validator to
    // reject.
    const req = {
      body: {
        registered_at: "2026-03-15",
        verified_at: "03/15/2026",
        timestamp: "2026-03-15T00:00:00.000Z garbage",
      },
    };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.registered_at).toBe("2026-03-15");
    expect(req.body.verified_at).toBe("03/15/2026");
    expect(req.body.timestamp).toBe("2026-03-15T00:00:00.000Z garbage");
  });

  test("ignores non-pattern fields even when value is strict ISO", async () => {
    const req = { body: { description: GENESIS_ISO, timestamp: GENESIS_ISO } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.description).toBe(GENESIS_ISO);   // untouched (no pattern match)
    expect(req.body.timestamp).toBe(GENESIS_MS);      // converted
  });

  test("accepts ISO without milliseconds (still strict, .sss optional)", async () => {
    const req = { body: { timestamp: "2026-03-15T00:00:00Z" } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.timestamp).toBe(GENESIS_MS);
  });

  test("walks nested incoming bodies", async () => {
    const req = { body: { data: { registered_at: GENESIS_ISO } } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.data.registered_at).toBe(GENESIS_MS);
  });

  test("leaves bad strings alone for downstream validator", async () => {
    const req = { body: { timestamp: "not-an-iso-string" } };
    const { res } = _mockRes();
    await _runMiddleware(req, res, bothDirectionsMw);
    expect(req.body.timestamp).toBe("not-an-iso-string");
  });
});

describe("isTimestampField — name discipline", () => {

  test("recognises canonical TIP timestamp field names", () => {
    expect(isTimestampField("timestamp")).toBe(true);
    expect(isTimestampField("cert_timestamp")).toBe(true);
    expect(isTimestampField("registered_at")).toBe(true);
    expect(isTimestampField("verified_at")).toBe(true);
    expect(isTimestampField("committed_at")).toBe(true);
    expect(isTimestampField("signed_at")).toBe(true);
    expect(isTimestampField("decision_window_ends_at")).toBe(true);
    expect(isTimestampField("node_seen_at")).toBe(true);
    expect(isTimestampField("lastAdvanceAt")).toBe(true);
    expect(isTimestampField("lastRoundAdvanceAt")).toBe(true);
    expect(isTimestampField("filing_deadline")).toBe(true);
    expect(isTimestampField("verified_since")).toBe(true);
    expect(isTimestampField("at")).toBe(true);
    expect(isTimestampField("confirmed_at_ms")).toBe(true);
    expect(isTimestampField("bft_time_genesis_ms")).toBe(true);
    expect(isTimestampField("flagged_ms")).toBe(true);   // pattern match;
    // value gate filters non-ms-range values at runtime.
  });

  test("rejects round counters and known non-timestamp matches", () => {
    expect(isTimestampField("triggered_at_round")).toBe(false);
    expect(isTimestampField("rejected_at_round")).toBe(false);
    expect(isTimestampField("ack_signed_ats")).toBe(false);
  });

  test("rejects unrelated names (no false matches)", () => {
    expect(isTimestampField("description")).toBe(false);
    expect(isTimestampField("tip_id")).toBe(false);
    expect(isTimestampField("status")).toBe(false);
    expect(isTimestampField("AT")).toBe(false);       // uppercase-only — not camelCase
    expect(isTimestampField("_AT")).toBe(false);
  });

  test("plausibility-floor smoke — isValidMs floor is sensible vs genesis", () => {
    // Defensive — confirms the helpers' floor constant is sensible
    // relative to genesis. If MS_FLOOR_2025_01_01_UTC ever drifts past
    // genesis this catches it.
    expect(GENESIS_MS).toBeGreaterThanOrEqual(MS_FLOOR_2025_01_01_UTC);
  });

  test("STRICT_ISO_RE matches only toIso()'s canonical form", () => {
    expect(STRICT_ISO_RE.test("2026-03-15T00:00:00.000Z")).toBe(true);
    expect(STRICT_ISO_RE.test("2026-03-15T00:00:00Z")).toBe(true);   // .sss optional
    expect(STRICT_ISO_RE.test("2026-03-15")).toBe(false);            // date-only
    expect(STRICT_ISO_RE.test("2026-03-15T00:00:00")).toBe(false);   // missing Z
    expect(STRICT_ISO_RE.test("2026-03-15T00:00:00+00:00")).toBe(false); // offset form
    expect(STRICT_ISO_RE.test("03/15/2026")).toBe(false);
    expect(STRICT_ISO_RE.test("")).toBe(false);
  });

  test("TIMESTAMP_PATTERN and TIMESTAMP_EXCLUDE are exported for tooling", () => {
    expect(TIMESTAMP_PATTERN).toBeInstanceOf(RegExp);
    expect(TIMESTAMP_EXCLUDE).toBeInstanceOf(RegExp);
  });
});
