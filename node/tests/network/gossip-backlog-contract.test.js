/**
 * @file tests/network/gossip-backlog-contract.test.js
 * @description Gossip queued for one peer is bounded and watched. A peer that
 * stays connected but stops reading must not grow this node's memory without
 * limit, and must be redialed so the queue is dropped (mainnet 2026-10-03:
 * one halted partner node drove node 2 to a kernel OOM kill).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const { CONSENSUS } = require(path.resolve(__dirname, "../../../shared/protocol-constants"));

const netSrc = fs.readFileSync(path.resolve(__dirname, "../../src/network/node.js"), "utf8");
const schedSrc = fs.readFileSync(path.resolve(__dirname, "../../src/scheduler.js"), "utf8");
const metricsSrc = fs.readFileSync(path.resolve(__dirname, "../../src/services/metrics-service.js"), "utf8");
const healthSrc = fs.readFileSync(path.resolve(__dirname, "../../src/routes/health.js"), "utf8");

describe("gossip outbound backlog contract", () => {
  test("the per-peer cap is a bounded number of megabytes, not Infinity", () => {
    expect(CONSENSUS.GOSSIP_MAX_OUTBOUND_BUFFER_BYTES).toBeGreaterThanOrEqual(1 << 20);
    expect(CONSENSUS.GOSSIP_MAX_OUTBOUND_BUFFER_BYTES).toBeLessThanOrEqual(64 << 20);
    expect(CONSENSUS.GOSSIP_BACKLOG_DISCONNECT_STRIKES).toBeGreaterThanOrEqual(1);
  });

  test("gossipsub is constructed with the cap (the library default is Infinity)", () => {
    expect(netSrc).toMatch(/gossipsub\(\{[\s\S]*?maxOutboundBufferSize:\s*CONSENSUS\.GOSSIP_MAX_OUTBOUND_BUFFER_BYTES[\s\S]*?\}\)/);
  });

  test("the backlog is sampled on the peer-health tick and a stuck peer is redialed", () => {
    expect(schedSrc).toMatch(/register\("peer-health"[\s\S]*?checkOutboundBacklog\(\)/);
    expect(netSrc).toMatch(/function checkOutboundBacklog\(\)[\s\S]*?_outboundBacklog\.observe\([\s\S]*?_forceRedial\(peerId\)/);
    expect(netSrc).toMatch(/_outboundBacklog\.forget\(remotePeerId\)/);
  });

  test("off-heap memory and the backlog are observable", () => {
    expect(metricsSrc).toMatch(/tip_process_memory_external_bytes/);
    expect(metricsSrc).toMatch(/tip_process_memory_array_buffers_bytes/);
    expect(metricsSrc).toMatch(/tip_network_backlog_disconnects_total/);
    expect(metricsSrc).toMatch(/tip_network_peer_outbound_backlog_bytes/);
    expect(healthSrc).toMatch(/external:/);
    expect(healthSrc).toMatch(/array_buffers:/);
  });
});
