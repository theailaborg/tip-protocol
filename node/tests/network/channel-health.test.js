/**
 * @file tests/network/channel-health.test.js
 * @description Per-peer outbound-delivery health + force-redial decision.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { createChannelHealth } = require(path.resolve(__dirname, "../../src/network/channel-health"));

function clock(start = 1_000) {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

describe("channel-health", () => {
  test("tracks ok/fail and resets consecutive failures on a success", () => {
    const ch = createChannelHealth({ healThreshold: 3, healCooldownMs: 1000, now: () => 5000 });
    expect(ch.recordSend("p", false)).toBe(false);
    expect(ch.recordSend("p", false)).toBe(false);
    let s = ch.snapshot()[0];
    expect(s.sendFail).toBe(2);
    expect(s.consecutiveFail).toBe(2);
    expect(s.sendOk).toBe(0);

    ch.recordSend("p", true);
    s = ch.snapshot()[0];
    expect(s.sendOk).toBe(1);
    expect(s.consecutiveFail).toBe(0);
  });

  test("signals a heal at the threshold and resets the consecutive count", () => {
    const ch = createChannelHealth({ healThreshold: 3, healCooldownMs: 1000, now: clock().now });
    expect(ch.recordSend("p", false)).toBe(false);   // 1
    expect(ch.recordSend("p", false)).toBe(false);   // 2
    expect(ch.recordSend("p", false)).toBe(true);    // 3 -> heal
    expect(ch.snapshot()[0].consecutiveFail).toBe(0);
  });

  test("cooldown blocks a second heal until the window elapses", () => {
    const clk = clock();
    const ch = createChannelHealth({ healThreshold: 2, healCooldownMs: 5000, now: clk.now });
    expect(ch.recordSend("p", false)).toBe(false);
    expect(ch.recordSend("p", false)).toBe(true);    // first heal (no prior cooldown)
    // Within the cooldown: cross the threshold again but no heal.
    expect(ch.recordSend("p", false)).toBe(false);
    expect(ch.recordSend("p", false)).toBe(false);
    // After the cooldown, the next threshold crossing heals again.
    clk.advance(5000);
    expect(ch.recordSend("p", false)).toBe(true);
  });

  test("a healthy peer (sends succeeding) never signals a heal", () => {
    const ch = createChannelHealth({ healThreshold: 2, healCooldownMs: 1000, now: clock().now });
    for (let i = 0; i < 10; i++) expect(ch.recordSend("p", true)).toBe(false);
    expect(ch.snapshot()[0].sendFail).toBe(0);
  });

  test("snapshot reports last-ok age, and forget removes a peer", () => {
    const clk = clock(10_000);
    const ch = createChannelHealth({ healThreshold: 5, healCooldownMs: 1000, now: clk.now });
    ch.recordSend("p", true);
    clk.advance(2_500);
    expect(ch.snapshot()[0].lastOkAgeMs).toBe(2_500);

    ch.forget("p");
    expect(ch.snapshot()).toHaveLength(0);
  });

  test("a peer with no successful send yet reports lastOkAgeMs = -1", () => {
    const ch = createChannelHealth({ healThreshold: 5, healCooldownMs: 1000, now: clock().now });
    ch.recordSend("p", false);
    expect(ch.snapshot()[0].lastOkAgeMs).toBe(-1);
  });
});
