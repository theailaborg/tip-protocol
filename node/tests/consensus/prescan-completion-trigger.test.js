"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");

const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const PC = require(path.join(SHARED, "protocol-constants"));
try { PC._resetForTesting(); } catch { /* already initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const { initCrypto, generateMLDSAKeypair, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.resolve(__dirname, "../../src/dag"));
const { createPrescanCompletionTrigger } = require(path.resolve(__dirname, "../../src/consensus/prescan-completion-trigger"));
const { TX_TYPES, CONTENT_STATUS } = require(path.join(SHARED, "constants"));

const CTID_STUCK = "tip://c/OH-stuckpastfailopen-aaaa";
const CTID_FRESH = "tip://c/OH-freshpending00000-bbbb";
const CREATOR    = "tip://id/US-aaaaaaaaaaaaaaaa";
const NODE_ID    = "tip://node/efbe3707224fb785";

function makeFixture({ getCommittee } = {}) {
  const kp = generateMLDSAKeypair();
  const dag = initDAG({ dbPath: ":memory-test:" });
  dag.saveNode?.({ node_id: NODE_ID, public_key: kp.publicKey, status: "active" });
  const config = { nodeRegisteredId: NODE_ID, nodePrivateKey: kp.privateKey };
  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); return { tx_id: tx.tx_id }; };
  const trigger = createPrescanCompletionTrigger({ dag, config, submitTx, getCommittee });
  return { dag, submitted, trigger, config };
}

function seedPendingContent(dag, { ctid, registeredAtMs }) {
  dag.saveContent({
    ctid, origin_code: "OH",
    content_hash: "ab".repeat(32),
    author_tip_id: CREATOR, signer_tip_id: CREATOR,
    authors: [{ tip_id: CREATOR, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: CONTENT_STATUS.PENDING_PRESCAN,
    prescan_flagged: false, prescan_probability: 0, prescan_tier: "low",
    prescan_status: "pending",
    prescan_completed_at: null,
    prescan_assigned_node_id: NODE_ID,
    prescan_content_type: null,
    prescan_overall_degraded: 0,
    content_type_hint: null,
    override: false,
    registered_at: registeredAtMs,
    registered_urls: [], tx_id: shake256(`c:${ctid}:${registeredAtMs}`),
  });
}

describe("prescan-completion-trigger — fail-open", () => {
  beforeAll(async () => { await initCrypto(); });

  test("emits fail-open PRESCAN_COMPLETED for content past fail-open deadline", () => {
    const { dag, submitted, trigger } = makeFixture();
    const nowTs = 1779800000000;
    const stuckMs = nowTs - PC.PRESCAN_WORKER.FAIL_OPEN_AFTER_MS - 1000;
    seedPendingContent(dag, { ctid: CTID_STUCK, registeredAtMs: stuckMs });

    trigger.checkPending(nowTs, 1);

    expect(submitted).toHaveLength(1);
    const tx = submitted[0];
    expect(tx.tx_type).toBe(TX_TYPES.PRESCAN_COMPLETED);
    expect(tx.data.ctid).toBe(CTID_STUCK);
    expect(tx.data.failed).toBe(true);
    expect(tx.data.flagged).toBe(false);
    // Trigger's synthetic fail-open matches the worker's _emitFailOpen
    // convention: probability=0.5 (no-signal neutral) + overall_degraded=
    // true so downstream sees this as a placeholder, not a real verdict.
    expect(tx.data.probability).toBe(0.5);
    expect(tx.data.overall_degraded).toBe(true);
    // Tier is derived via tierFromProbability(0.5); we don't pin the
    // exact tier to keep tier-threshold tunable.
    expect(["low", "elevated"]).toContain(tx.data.tier);
    expect(tx.data.classifier_providers_used).toBe("fail_open_failover");
    expect(tx.data.failure_reason).toMatch(/fail_open_deadline/);
  });

  test("does NOT fire for content within the fail-open window", () => {
    const { dag, submitted, trigger } = makeFixture();
    const nowTs = 1779800000000;
    // 30 minutes in — well before the 1-hour deadline
    seedPendingContent(dag, { ctid: CTID_FRESH, registeredAtMs: nowTs - 30 * 60 * 1000 });

    trigger.checkPending(nowTs, 1);
    expect(submitted).toHaveLength(0);
  });

  test("only the round-modulo leader fires", () => {
    const otherNode = "tip://node/0000000000000001";
    const committee = [NODE_ID, otherNode];
    // Round 0 → idx 0 → leader is the FIRST after sort. After sort by
    // string comparison, "tip://node/0000…" < "tip://node/efbe…", so
    // round 0 leader is otherNode. Round 1 leader is NODE_ID.
    const { dag, submitted, trigger } = makeFixture({ getCommittee: () => committee });
    const nowTs = 1779800000000;
    const stuckMs = nowTs - PC.PRESCAN_WORKER.FAIL_OPEN_AFTER_MS - 1000;
    seedPendingContent(dag, { ctid: CTID_STUCK, registeredAtMs: stuckMs });

    trigger.checkPending(nowTs, 0);        // otherNode leads — we don't fire
    expect(submitted).toHaveLength(0);

    trigger.checkPending(nowTs, 1);        // NODE_ID leads — we fire
    expect(submitted).toHaveLength(1);
  });

  test("does nothing for content with prescan_status=completed", () => {
    const { dag, submitted, trigger } = makeFixture();
    const nowTs = 1779800000000;
    const stuckMs = nowTs - PC.PRESCAN_WORKER.FAIL_OPEN_AFTER_MS - 1000;
    // Seed as pending then flip to completed (simulating the worker
    // having emitted before failover fires).
    seedPendingContent(dag, { ctid: CTID_STUCK, registeredAtMs: stuckMs });
    const c = dag.getContent(CTID_STUCK);
    dag.saveContent({ ...c, prescan_status: "completed", prescan_completed_at: nowTs - 1000 });

    trigger.checkPending(nowTs, 1);
    expect(submitted).toHaveLength(0);
  });

  test("guards against missing config / submitTx / private key", () => {
    const dag = initDAG({ dbPath: ":memory-test:" });
    const trigger = createPrescanCompletionTrigger({
      dag, config: {}, submitTx: () => {}, getCommittee: undefined,
    });
    // Should not throw on missing private key (just no-op)
    expect(() => trigger.checkPending(1779800000000, 0)).not.toThrow();
  });
});
