/**
 * @file tests/network/stall-tolerance.test.js
 * @description Network stall-tolerance contract.
 *
 * A brief single-thread event-loop freeze (GC pause, catch-up burst) must not
 * be mistaken for a dead peer and tear down a healthy committee connection.
 * Liveness has ONE owner, the heartbeat; libp2p's connection monitor pings but
 * never aborts. A snapshot download saturates a joiner's link and its own
 * pings queue behind the bulk stream, so the monitor's abort killed every
 * install at the timeout, on schedule. The heartbeat knows to stand down
 * while an install is in flight; the monitor could not.
 *   1. libp2p connection-monitor ping floor tolerates a multi-second stall.
 *   2. Heartbeat suspect window also rides through a brief stall.
 *   3. Ladder: the (inert) monitor floor still sits above the heartbeat window.
 *   4. The monitor never aborts; the heartbeat evicts, except mid-install.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
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

// Init code that builds a live libp2p node cannot be instantiated here, so the
// contract is pinned against the source, the same way generated-env policy is.
describe("liveness has one owner", () => {
  const netSrc = fs.readFileSync(path.resolve(__dirname, "../../src/network/node.js"), "utf8");
  const consSrc = fs.readFileSync(path.resolve(__dirname, "../../src/consensus/index.js"), "utf8");

  test("libp2p connection monitor never aborts on ping failure", () => {
    const block = netSrc.match(/connectionMonitor:\s*\{[\s\S]*?\n\s*\},/);
    expect(block).not.toBeNull();
    expect(block[0]).toMatch(/abortConnectionOnPingFailure:\s*false/);
  });

  test("network exposes hangUp so consumers can evict", () => {
    expect(netSrc).toMatch(/function hangUp\(peerId\)/);
    expect(netSrc).toMatch(/^\s*hangUp,$/m);
  });

  test("suspect evicts via hangUp, and stands down while installing or serving that peer", () => {
    const handler = consSrc.match(/onPeerSuspect:\s*\([\s\S]*?\n\s{4}\},/);
    expect(handler).not.toBeNull();
    const body = handler[0];
    expect(body).toMatch(/isInstalling\(\)/);
    // the SENDER's pings queue behind the stream it is pushing; it must not evict
    // the joiner it is serving (found on the test cluster: sender hung up mid-serve)
    expect(body).toMatch(/isServingTo\(peerId\)/);
    expect(body).toMatch(/network\.hangUp\(peerId\)/);
    // both checks must gate the eviction, not follow it
    expect(body.indexOf("isInstalling()")).toBeLessThan(body.indexOf("network.hangUp(peerId)"));
    expect(body.indexOf("isServingTo(peerId)")).toBeLessThan(body.indexOf("network.hangUp(peerId)"));
    // standing down must also forgive: misses counted during the transfer would
    // otherwise evict on the very next tick after it ends (seen on the test cluster)
    expect(body).toMatch(/heartbeat\.forgive\(peerId\)/);
    expect(body.indexOf("heartbeat.forgive(peerId)")).toBeLessThan(body.indexOf("network.hangUp(peerId)"));
    // AE's cached join_state is written only on a successful poll and reported a
    // wiped-and-rejoined joiner as "ready" from before the wipe (test cluster,
    // 2026-09-25): it must not gate the verdict.
    expect(body).not.toMatch(/peerJoinState\(/);
    // channel-health rebuilt a joiner's transports on send failures caused by its own
    // saturated inbound; the guard must sit before the close
    const redial = netSrc.slice(netSrc.indexOf("async function _forceRedial"), netSrc.indexOf("async function broadcastToAuthorized"));
    expect(redial.indexOf("_transferGuard")).toBeGreaterThan(-1);
    expect(redial.indexOf("_transferGuard")).toBeLessThan(redial.indexOf("c.close()"));
    expect(consSrc).toMatch(/network\.setTransferGuard\(/);
  });
});
