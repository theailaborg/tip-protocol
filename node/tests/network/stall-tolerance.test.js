/**
 * @file tests/network/stall-tolerance.test.js
 * @description Network stall-tolerance contract.
 *
 * A brief single-thread event-loop freeze (GC pause, catch-up burst) must not
 * be mistaken for a dead peer and tear down a healthy committee connection.
 * Two layers cooperate, and their timeouts must stay ordered into a ladder:
 *   1. libp2p connection-monitor ping floor tolerates a multi-second stall.
 *   2. Heartbeat suspect window also rides through a brief stall.
 *   3. Ladder: connection abort never precedes heartbeat reconciliation, and
 *      the heartbeat path never fires on a sub-second blip.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { CONSENSUS } = require(path.resolve(__dirname, "../../../shared/protocol-constants"));

// Time a peer can be silent before the heartbeat path suspects it: the first
// miss lands one timeout after the last probe, then each further interval.
const suspectWindowMs = () =>
  CONSENSUS.HEARTBEAT_INTERVAL_MS * (CONSENSUS.HEARTBEAT_SUSPECT_MISSES - 1) +
  CONSENSUS.HEARTBEAT_TIMEOUT_MS;

describe("network stall-tolerance contract", () => {
  test("connection-monitor ping floor tolerates a multi-second stall", () => {
    expect(CONSENSUS.CONNECTION_MONITOR_PING_TIMEOUT_FLOOR_MS).toBeGreaterThanOrEqual(15000);
  });

  test("heartbeat suspect window rides through a brief stall", () => {
    expect(suspectWindowMs()).toBeGreaterThanOrEqual(10000);
  });

  test("ladder: connection abort never precedes heartbeat reconciliation", () => {
    expect(CONSENSUS.CONNECTION_MONITOR_PING_TIMEOUT_FLOOR_MS).toBeGreaterThan(suspectWindowMs());
  });
});
