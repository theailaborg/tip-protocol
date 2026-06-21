/**
 * @file tests/services/node-endpoint-update.test.js
 * @description NODE_ENDPOINT_UPDATED — schema shape, ownership probe,
 * tx emission, commit apply, and the media route's 307 consumption.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));
const { initCrypto, generateMLDSAKeypair, signTransaction, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createGovernanceService } = require(path.join(SRC, "services/governance-service"));
const schema = require(path.join(SRC, "schemas/node-endpoint-update"));

beforeAll(async () => {
  await initCrypto();
  try { PC._resetForTesting(); } catch { /* not yet initialised */ }
  PC.init(getGenesisPayload().protocol_constants);
});

const NODE_ID = "tip://node/aaaaaaaaaaaaaaaa";
const ENDPOINT = "https://node-a.example.com";

// ─── Schema shape ─────────────────────────────────────────────────────────

describe("node-endpoint-update schema", () => {
  test("valid endpoint passes", () => {
    expect(() => schema.validateRequest({ node_id: NODE_ID, api_endpoint: ENDPOINT })).not.toThrow();
  });

  test("null endpoint passes (clear)", () => {
    expect(() => schema.validateRequest({ node_id: NODE_ID, api_endpoint: null })).not.toThrow();
  });

  test("endpoint with path rejected", () => {
    expect(() => schema.validateRequest({ node_id: NODE_ID, api_endpoint: "https://x.com/v1" }))
      .toThrow(expect.objectContaining({ code: "api_endpoint_invalid" }));
  });

  test("non-http scheme rejected", () => {
    expect(() => schema.validateRequest({ node_id: NODE_ID, api_endpoint: "ftp://x.com" }))
      .toThrow(expect.objectContaining({ code: "api_endpoint_invalid" }));
  });

  test("malformed node_id rejected", () => {
    expect(() => schema.validateRequest({ node_id: "not-a-node", api_endpoint: ENDPOINT }))
      .toThrow(expect.objectContaining({ code: "node_id_required" }));
  });
});

// ─── Service: probe + tx emission ─────────────────────────────────────────

function _setup({ fetchImpl, apiEndpoint } = {}) {
  const kp = generateMLDSAKeypair();
  const dag = initDAG({ dbPath: ":memory-test:" });
  dag.saveNode({
    node_id: NODE_ID,
    public_key: kp.publicKey,
    status: "active",
    registered_at: 1_780_000_000_000,
  });
  const submitted = [];
  const config = {
    nodeRegisteredId: NODE_ID,
    nodePrivateKey: kp.privateKey,
    apiEndpoint: apiEndpoint === undefined ? ENDPOINT : apiEndpoint,
  };
  const service = createGovernanceService({
    dag, scoring: null, config,
    submitTx: (tx) => submitted.push(tx),
    fetchImpl,
  });
  return { dag, service, submitted, kp };
}

// Real /health goes through the API envelope: { ok, status, data: { node_id } }.
function _okProbe(nodeId = NODE_ID) {
  return async () => ({ json: async () => ({ ok: true, status: 200, data: { node_id: nodeId } }) });
}
// Some health endpoints might return a raw (non-enveloped) body.
function _okProbeRaw(nodeId = NODE_ID) {
  return async () => ({ json: async () => ({ status: "ok", node_id: nodeId }) });
}

describe("governance-service.updateNodeEndpoint", () => {
  test("probe answers as this node → tx submitted with endpoint", async () => {
    const { service, submitted } = _setup({ fetchImpl: _okProbe() });
    const out = await service.updateNodeEndpoint(ENDPOINT);
    expect(out.confirmation).toBe("proposed");
    const tx = submitted.find(t => t.tx_type === TX_TYPES.NODE_ENDPOINT_UPDATED);
    expect(tx).toBeDefined();
    expect(tx.data.node_id).toBe(NODE_ID);
    expect(tx.data.api_endpoint).toBe(ENDPOINT);
  });

  test("probe with raw (non-enveloped) health body also accepted", async () => {
    const { service, submitted } = _setup({ fetchImpl: _okProbeRaw() });
    const out = await service.updateNodeEndpoint(ENDPOINT);
    expect(out.confirmation).toBe("proposed");
    expect(submitted.find(t => t.tx_type === TX_TYPES.NODE_ENDPOINT_UPDATED)).toBeDefined();
  });

  test("trailing slash normalised before probe + tx", async () => {
    const { service, submitted } = _setup({ fetchImpl: _okProbe() });
    await service.updateNodeEndpoint(`${ENDPOINT}/`);
    expect(submitted[0].data.api_endpoint).toBe(ENDPOINT);
  });

  test("probe answers as a DIFFERENT node → 400, no tx", async () => {
    const { service, submitted } = _setup({ fetchImpl: _okProbe("tip://node/bbbbbbbbbbbbbbbb") });
    await expect(service.updateNodeEndpoint(ENDPOINT))
      .rejects.toMatchObject({ status: 400 });
    expect(submitted).toHaveLength(0);
  });

  test("probe unreachable → 400, no tx", async () => {
    const { service, submitted } = _setup({
      fetchImpl: async () => { throw new Error("ECONNREFUSED"); },
    });
    await expect(service.updateNodeEndpoint(ENDPOINT))
      .rejects.toMatchObject({ status: 400 });
    expect(submitted).toHaveLength(0);
  });

  test("clearing (null) skips the probe and emits the tx", async () => {
    // First set an endpoint on the row so the clear isn't a no-op.
    const { dag, service, submitted } = _setup({
      fetchImpl: async () => { throw new Error("probe must not run on clear"); },
    });
    dag.updateNodeEndpoint(NODE_ID, ENDPOINT);
    const out = await service.updateNodeEndpoint(null);
    expect(out.confirmation).toBe("proposed");
    expect(submitted[0].data.api_endpoint).toBeNull();
  });

  test("unchanged value → no tx, confirmation=unchanged", async () => {
    const { dag, service, submitted } = _setup({ fetchImpl: _okProbe() });
    dag.updateNodeEndpoint(NODE_ID, ENDPOINT);
    const out = await service.updateNodeEndpoint(ENDPOINT);
    expect(out.confirmation).toBe("unchanged");
    expect(submitted).toHaveLength(0);
  });

  test("announceConfiguredEndpoint refuses when TIP_API_ENDPOINT unset", async () => {
    const { service } = _setup({ fetchImpl: _okProbe(), apiEndpoint: null });
    await expect(service.announceConfiguredEndpoint())
      .rejects.toMatchObject({ status: 409 });
  });
});

// ─── DAG apply parity ─────────────────────────────────────────────────────

describe("dag.updateNodeEndpoint", () => {
  test("updates the row; getNode reflects it; clear sets null", () => {
    const dag = initDAG({ dbPath: ":memory-test:" });
    const kp = generateMLDSAKeypair();
    dag.saveNode({ node_id: NODE_ID, public_key: kp.publicKey, status: "active", registered_at: 1_780_000_000_000 });

    dag.updateNodeEndpoint(NODE_ID, ENDPOINT);
    expect(dag.getNode(NODE_ID).api_endpoint).toBe(ENDPOINT);

    dag.updateNodeEndpoint(NODE_ID, null);
    expect(dag.getNode(NODE_ID).api_endpoint).toBeNull();
  });
});

// ─── Commit-handler: monotonic timestamp guard (PR #120) ──────────────────

function _buildEndpointTx(dag, kp, nodeId, endpoint, timestamp) {
  const body = {
    tx_type: TX_TYPES.NODE_ENDPOINT_UPDATED,
    timestamp,
    prev: dag.getRecentPrev(),
    data: { node_id: nodeId, api_endpoint: endpoint },
  };
  body.tx_id = computeTxId(body);
  return signTransaction(body, kp.privateKey);
}

describe("commit-handler: NODE_ENDPOINT_UPDATED monotonic guard", () => {
  let dag, kp, handler;

  beforeEach(() => {
    kp = generateMLDSAKeypair();
    dag = initDAG({ dbPath: ":memory:" });
    dag.saveNode({ node_id: NODE_ID, public_key: kp.publicKey, status: "active", registered_at: 1_780_000_000_000 });
    handler = createCommitHandler({
      dag,
      scoring: null,
      verdictTrigger: null,
      cleanRecordTrigger: null,
      prescanReviewTrigger: null,
      prescanCompletionTrigger: null,
      config: { nodeRegisteredId: NODE_ID, nodePrivateKey: kp.privateKey },
      nodeId: NODE_ID,
    });
  });

  test("first update commits and advances updated_at", () => {
    const T1 = 1_780_000_001_000;
    const tx = _buildEndpointTx(dag, kp, NODE_ID, ENDPOINT, T1);
    const { committed, dropped } = handler.commitOrderedTxs([tx], 1);
    expect(committed).toBe(1);
    expect(dropped).toBe(0);
    expect(dag.getNode(NODE_ID).updated_at).toBe(T1);
  });

  test("update with strictly later timestamp is accepted (monotonic advance)", () => {
    const T1 = 1_780_000_001_000;
    const T2 = T1 + 5000;
    handler.commitOrderedTxs([_buildEndpointTx(dag, kp, NODE_ID, ENDPOINT, T1)], 1);
    const { committed, dropped } = handler.commitOrderedTxs([_buildEndpointTx(dag, kp, NODE_ID, "https://node-b.example.com", T2)], 2);
    expect(committed).toBe(1);
    expect(dropped).toBe(0);
    expect(dag.getNode(NODE_ID).api_endpoint).toBe("https://node-b.example.com");
  });

  test("update with equal timestamp is rejected (equal is stale)", () => {
    const T1 = 1_780_000_001_000;
    handler.commitOrderedTxs([_buildEndpointTx(dag, kp, NODE_ID, ENDPOINT, T1)], 1);
    const { committed, dropped } = handler.commitOrderedTxs([_buildEndpointTx(dag, kp, NODE_ID, "https://stale.example.com", T1)], 2);
    expect(committed).toBe(0);
    expect(dropped).toBe(1);
  });

  test("update with earlier timestamp is rejected (replay protection)", () => {
    const T1 = 1_780_000_001_000;
    const T0 = T1 - 5000;
    handler.commitOrderedTxs([_buildEndpointTx(dag, kp, NODE_ID, ENDPOINT, T1)], 1);
    const { committed, dropped } = handler.commitOrderedTxs([_buildEndpointTx(dag, kp, NODE_ID, "https://replay.example.com", T0)], 2);
    expect(committed).toBe(0);
    expect(dropped).toBe(1);
  });

  test("two updates for the SAME node in ONE batch: first-wins, stale-last cannot revert", () => {
    // Same-batch hazard: both pass the monotonic guard (it reads pre-batch
    // committed state), then Phase 2 applies last-wins. With the stale tx
    // ordered LAST and no in-batch dedup, it would revert api_endpoint AND move
    // updated_at backwards. The dedup drops the second so the first-in-order wins.
    const T1 = 1_780_000_001_000;
    const T2 = T1 + 5000;
    const newer = _buildEndpointTx(dag, kp, NODE_ID, "https://new.example.com", T2);
    const stale = _buildEndpointTx(dag, kp, NODE_ID, "https://old.example.com", T1);
    const { committed, dropped } = handler.commitOrderedTxs([newer, stale], 1);
    expect(committed).toBe(1);
    expect(dropped).toBe(1);
    // First-in-canonical-order won; the stale tx did NOT revert the endpoint.
    expect(dag.getNode(NODE_ID).api_endpoint).toBe("https://new.example.com");
    expect(dag.getNode(NODE_ID).updated_at).toBe(T2);
  });

  test("endpoint updates for DIFFERENT nodes in ONE batch: both commit (dedup is per-node)", () => {
    const kp2 = generateMLDSAKeypair();
    const NODE_2 = "tip://node/bbbbbbbbbbbbbbbb";
    dag.saveNode({ node_id: NODE_2, public_key: kp2.publicKey, status: "active", registered_at: 1_780_000_000_000 });
    const T1 = 1_780_000_001_000;
    const tx1 = _buildEndpointTx(dag, kp, NODE_ID, "https://a.example.com", T1);
    const tx2 = _buildEndpointTx(dag, kp2, NODE_2, "https://b.example.com", T1 + 1000);
    const { committed, dropped } = handler.commitOrderedTxs([tx1, tx2], 1);
    expect(committed).toBe(2);
    expect(dropped).toBe(0);
  });
});
