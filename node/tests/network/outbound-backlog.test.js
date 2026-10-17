/**
 * @file tests/network/outbound-backlog.test.js
 * @description A peer whose gossip queue stays over the cap across consecutive
 * peer-health samples is flagged for redial; a peer that drains is not.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { createOutboundBacklog } = require(path.resolve(__dirname, "../../src/network/outbound-backlog"));

const LIMIT = 8 * 1024 * 1024;

describe("outbound backlog watch", () => {
  test("a healthy peer under the cap is never flagged", () => {
    const w = createOutboundBacklog({ limitBytes: LIMIT, strikes: 2 });
    for (let i = 0; i < 10; i++) expect(w.observe("p1", 1024)).toBe(false);
    expect(w.snapshot()).toEqual([{ peerId: "p1", bytes: 1024, strikes: 0 }]);
  });

  test("a peer over the cap for `strikes` consecutive samples is flagged once, then re-counts", () => {
    const w = createOutboundBacklog({ limitBytes: LIMIT, strikes: 2 });
    expect(w.observe("stalled", LIMIT + 1)).toBe(false);
    expect(w.observe("stalled", LIMIT * 3)).toBe(true);
    expect(w.observe("stalled", LIMIT * 3)).toBe(false);
    expect(w.observe("stalled", LIMIT * 3)).toBe(true);
  });

  test("draining below the cap resets the strike count", () => {
    const w = createOutboundBacklog({ limitBytes: LIMIT, strikes: 2 });
    expect(w.observe("p", LIMIT + 1)).toBe(false);
    expect(w.observe("p", LIMIT)).toBe(false);
    expect(w.observe("p", LIMIT + 1)).toBe(false);
    expect(w.observe("p", LIMIT + 1)).toBe(true);
  });

  test("peers are tracked independently and forgotten on disconnect", () => {
    const w = createOutboundBacklog({ limitBytes: LIMIT, strikes: 1 });
    expect(w.observe("a", LIMIT + 1)).toBe(true);
    expect(w.observe("b", 10)).toBe(false);
    w.forget("a");
    expect(w.snapshot().map((p) => p.peerId)).toEqual(["b"]);
  });

  test("rejects a configuration that could never flag or never cap", () => {
    expect(() => createOutboundBacklog({ limitBytes: 0 })).toThrow(/limitBytes/);
    expect(() => createOutboundBacklog({ limitBytes: LIMIT, strikes: 0 })).toThrow(/strikes/);
  });
});
