/**
 * @file tests/consensus/commit-handler-owner-chain.test.js
 * @description Stage 3 (#199): commit-time owner-chain prev[0] validation +
 * OWNER_HEAD_STALE rejection + node-side rebuild/requeue. Enforcement is
 * unconditional: prev[0] must equal the owner's committed head on every chain.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, computeTxId, shake256 } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, TX_REJECTION_REASON } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const contentRegisterSchema = require(path.join(SRC, "schemas", "content-register"));
const { ownerKey } = require(path.join(SRC, "consensus", "tx-owner"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/oc-test";
const VP_ID = "tip://vp/v1";
const AUTHOR_TIP = "tip://id/US-owner-chain-01";
const OWNER = ownerKey({ entityType: "identity", entityId: AUTHOR_TIP });

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const vpKp = generateMLDSAKeypair();
  const authorKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
  dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });
  return { dag, authorKp, handler };
}

function _contentTx(dag, authorKp, text, opts = {}) {
  const content_hash = shake256(text);
  const data = {
    ctid: `tip://c/OH-${content_hash.slice(0, 14)}-0001`,
    origin_code: "OH",
    content_hash,
    signer_tip_id: AUTHOR_TIP,
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR_TIP, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, registered_urls: [],
    cna_version: contentRegisterSchema.CURRENT_CNA_VERSION,
  };
  const sig = contentRegisterSchema.sign(contentRegisterSchema.buildSigningPayload(data, content_hash), authorKp.privateKey);
  const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1777507200000, data, signature: sig, prev: opts.prev || dag.prevFor(TX_TYPES.REGISTER_CONTENT, data) };
  tx.tx_id = computeTxId(tx);
  return tx;
}

describe("commit-handler: owner-chain prev validation + stale-head retry", () => {
  test("valid owner-chain prev commits and advances the owner head", () => {
    const fx = _setup();
    const tx = _contentTx(fx.dag, fx.authorKp, "oc-solo");
    const res = fx.handler.commitOrderedTxs([tx], 1);
    expect(res.committed).toBe(1);
    expect(fx.dag.getOwnerHead(OWNER)).toBe(tx.tx_id);
    expect(fx.dag.getTxRejection(fx.dag.getOwnerHead(OWNER))).toBeNull();
  });

  test("an out-of-order same-owner chain commits FULLY in one round (multi-pass)", () => {
    const fx = _setup();
    const head0 = fx.dag.expectedOwnerHead(require(path.join(SRC, "consensus", "tx-owner")).ownerOf({ tx_type: TX_TYPES.REGISTER_CONTENT, data: { signer_tip_id: AUTHOR_TIP, authors: [{ tip_id: AUTHOR_TIP }] } }));
    const s1 = _contentTx(fx.dag, fx.authorKp, "oo-1", { prev: [head0, head0] });
    const s2 = _contentTx(fx.dag, fx.authorKp, "oo-2", { prev: [s1.tx_id, head0] });
    const s3 = _contentTx(fx.dag, fx.authorKp, "oo-3", { prev: [s2.tx_id, head0] });

    // Present the valid chain SCRAMBLED (s2, s3, s1) , the live bug: Bullshark
    // ordering delivered same-owner txs out of chain order and only the head
    // committed per round, the rest churned as OWNER_HEAD_STALE.
    const res = fx.handler.commitOrderedTxs([s2, s3, s1], 1);
    expect(res.committed).toBe(3);                 // all three, one round
    expect(fx.dag.getOwnerHead(OWNER)).toBe(s3.tx_id);
    expect(fx.dag.getContent(s1.data.ctid)).toBeTruthy();
    expect(fx.dag.getContent(s2.data.ctid)).toBeTruthy();
    expect(fx.dag.getContent(s3.data.ctid)).toBeTruthy();
  });

  test("a genuinely stale tx (no in-batch dependency) still stales, not committed", () => {
    const fx = _setup();
    const base = _contentTx(fx.dag, fx.authorKp, "gs-base");
    expect(fx.handler.commitOrderedTxs([base], 1).committed).toBe(1);
    // Points at a head that never commits in this batch , must NOT commit.
    const orphan = _contentTx(fx.dag, fx.authorKp, "gs-orphan", { prev: ["deadbeef".repeat(8), base.tx_id] });
    const res = fx.handler.commitOrderedTxs([orphan], 2);
    expect(res.committed).toBe(0);
  });

  test("two same-owner txs in one batch serialize: first commits, second is OWNER_HEAD_STALE + requeued", () => {
    const fx = _setup();
    const tx1 = _contentTx(fx.dag, fx.authorKp, "oc-first");
    const tx2 = _contentTx(fx.dag, fx.authorKp, "oc-second");
    expect(tx1.prev[0]).toBe(tx2.prev[0]);   // both raced against the same pre-batch head

    const res = fx.handler.commitOrderedTxs([tx1, tx2], 1);
    expect(res.committed).toBe(1);           // only the first
    expect(fx.dag.getOwnerHead(OWNER)).toBe(tx1.tx_id);

    const rej = fx.dag.getTxRejection(tx2.tx_id);
    expect(rej).not.toBeNull();
    expect(rej.reason).toBe(TX_REJECTION_REASON.OWNER_HEAD_STALE);

    // Requeued: a rebuilt tx2 (prev[0] now == tx1) is back in the mempool.
    const requeued = fx.dag.getMempoolTxs().find(t => t.tx_type === TX_TYPES.REGISTER_CONTENT && t.data.content_hash === tx2.data.content_hash);
    expect(requeued).toBeTruthy();
    expect(requeued.prev[0]).toBe(tx1.tx_id);        // rebuilt against the new head
    expect(requeued.tx_id).not.toBe(tx2.tx_id);      // new content-addressed id
    expect(requeued.signature).toBe(tx2.signature);  // content signature unchanged

    // The requeued tx now commits cleanly on the next round.
    const res2 = fx.handler.commitOrderedTxs([requeued], 2);
    expect(res2.committed).toBe(1);
    expect(fx.dag.getOwnerHead(OWNER)).toBe(requeued.tx_id);
  });

  test("burst chaining: three same-owner txs sealed in a burst commit in ONE round", () => {
    const fx = _setup();
    const txs = [];
    for (let i = 0; i < 3; i++) {
      const tx = _contentTx(fx.dag, fx.authorKp, `burst-${i}`);
      fx.dag.noteSealedTx(tx.tx_type, tx.data, tx.tx_id);   // what withTxId does at seal
      txs.push(tx);
    }
    // Each seal chained onto the previous pending tx, not the committed head.
    expect(txs[1].prev[0]).toBe(txs[0].tx_id);
    expect(txs[2].prev[0]).toBe(txs[1].tx_id);

    const res = fx.handler.commitOrderedTxs(txs, 1);
    expect(res.committed).toBe(3);
    expect(res.dropped).toBe(0);
    expect(fx.dag.getOwnerHead(OWNER)).toBe(txs[2].tx_id);
  });

  test("sterile rounds do not charge the stale retry budget; committing rounds do; absolute bounce cap backstops", () => {
    const fx = _setup();
    const AUTHOR2 = "tip://id/US-owner-chain-02";
    const author2Kp = generateMLDSAKeypair();
    fx.dag.saveIdentity({ tip_id: AUTHOR2, region: "US", public_key: author2Kp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(fx.dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR2 }) });
    fx.dag.setScore(AUTHOR2, 750, 0, 1767225600000);
    const _content2 = (text) => {
      const content_hash = shake256(text);
      const data = {
        ctid: `tip://c/OH-${content_hash.slice(0, 14)}-0002`,
        origin_code: "OH", content_hash, signer_tip_id: AUTHOR2,
        authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR2, tip_id_type: "personal" }],
        attribution_mode: "self", extras: {}, registered_urls: [],
        cna_version: contentRegisterSchema.CURRENT_CNA_VERSION,
      };
      const sig = contentRegisterSchema.sign(contentRegisterSchema.buildSigningPayload(data, content_hash), author2Kp.privateKey);
      const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1777507200000, data, signature: sig, prev: fx.dag.prevFor(TX_TYPES.REGISTER_CONTENT, data) };
      tx.tx_id = computeTxId(tx);
      return tx;
    };
    const _clearMempool = () => fx.dag.deleteMempoolTxs(fx.dag.getMempoolTxs().map(t => t.tx_id));
    const _requeued = (tx) => fx.dag.getMempoolTxs().some(t => t.data && t.data.content_hash === tx.data.content_hash);

    // Land a head, move past it.
    const base = _contentTx(fx.dag, fx.authorKp, "sr-base");
    expect(fx.handler.commitOrderedTxs([base], 1).committed).toBe(1);
    const mover = _contentTx(fx.dag, fx.authorKp, "sr-mover");
    expect(fx.handler.commitOrderedTxs([mover], 2).committed).toBe(1);

    // A tx whose predecessor is unknown-but-alive rides the WAIT path:
    // requeued UNCHANGED for up to MAX_RETRIES=8 bounces (sterile rounds
    // never charge the head-retry budget), then the predecessor is presumed
    // lost and the rebuild path recovers it against the committed head.
    const waiting = _contentTx(fx.dag, fx.authorKp, "sr-wait", { prev: ["77".repeat(32), base.prev[0]] });
    for (let r = 3; r < 11; r++) {
      _clearMempool();
      const res = fx.handler.commitOrderedTxs([waiting], r);
      expect(res.committed).toBe(0);
      expect(_requeued(waiting)).toBe(true);
      expect(fx.dag.getMempoolTxs()[0].tx_id).toBe(waiting.tx_id);   // unchanged, not rebuilt
    }
    _clearMempool();
    fx.handler.commitOrderedTxs([waiting], 11);   // 9th bounce: recovery rebuild
    expect(_requeued(waiting)).toBe(true);
    const recovered = fx.dag.getMempoolTxs()[0];
    expect(recovered.tx_id).not.toBe(waiting.tx_id);
    expect(recovered.prev[0]).toBe(mover.tx_id);   // rebased onto the committed head

    // A superseded-by-rebuild copy is silently dropped, so the old
    // permanently-stale re-feed can no longer churn: first pass rebuilds it,
    // the re-fed original is recognized as dead and NOT requeued again.
    const stale = _contentTx(fx.dag, fx.authorKp, "sr-stale", { prev: [base.tx_id, base.prev[0]] });
    _clearMempool();
    fx.handler.commitOrderedTxs([_content2("sr-sib-0"), stale], 20);
    expect(_requeued(stale)).toBe(true);    // rebuilt generation requeued
    _clearMempool();
    fx.handler.commitOrderedTxs([_content2("sr-sib-1"), stale], 21);
    expect(_requeued(stale)).toBe(false);   // copy superseded, no new generation

    // Absolute backstop: a permanently-waiting tx (predecessor never commits,
    // never dies) stops at 10x the cap , ghost-tx livelock bound.
    const ghost = _contentTx(fx.dag, fx.authorKp, "sr-ghost", { prev: ["88".repeat(32), base.prev[0]] });
    let dropBounce = null;
    for (let i = 0; i < 85; i++) {
      _clearMempool();
      fx.handler.commitOrderedTxs([ghost], 100 + i);
      if (!_requeued(ghost)) { dropBounce = i + 1; break; }
    }
    expect(dropBounce).not.toBeNull();
    expect(dropBounce).toBeLessThanOrEqual(81);
  });

  test("deep same-owner sibling burst drains to completion without rotation (lane-aware drain + front requeue)", () => {
    const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
    const dag = initDAG({ dbPath: ":memory:" });
    const nodeKp = generateMLDSAKeypair();
    const vpKp = generateMLDSAKeypair();
    const authorKp = generateMLDSAKeypair();
    dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
    dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);
    const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
    const scoring = initScoring(dag, config);
    const mempool = createMempool(dag, { nodeId: NODE_ID });
    const handler = createCommitHandler({ dag, scoring, mempool, config });

    // 15 siblings all built against the same pre-burst head (a client burst).
    const N = 15;
    const wanted = new Set();
    const head0 = dag.prevFor(TX_TYPES.REGISTER_CONTENT, {});
    for (let i = 0; i < N; i++) {
      const tx = _contentTx(dag, authorKp, `burst-${i}`, { prev: [...head0] });
      wanted.add(tx.data.ctid);
      mempool.add(tx);
    }

    // Drain->commit loop: lane-aware drain takes one committable tx/round,
    // front-requeue keeps the rebuilt tx ahead of siblings. Bounded rounds
    // prove there is no rotation.
    let round = 1, committedTotal = 0;
    for (; round < 200 && committedTotal < N; round++) {
      const batch = mempool.drain(25);
      if (batch.length === 0) break;
      committedTotal += handler.commitOrderedTxs(batch, round).committed;
    }

    expect(committedTotal).toBe(N);
    expect(round).toBeLessThan(60);
    for (const ctid of wanted) expect(dag.getContent(ctid)).toBeTruthy();
    expect(mempool.size()).toBe(0);
  });

  test("a rebuilt stale tx's OLD id is tombstoned: a gossiped copy cannot re-enter and churn", () => {
    const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
    const dag = initDAG({ dbPath: ":memory:" });
    const nodeKp = generateMLDSAKeypair();
    const vpKp = generateMLDSAKeypair();
    const authorKp = generateMLDSAKeypair();
    dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
    dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);
    const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
    const scoring = initScoring(dag, config);
    const mempool = createMempool(dag, { nodeId: NODE_ID });
    const handler = createCommitHandler({ dag, scoring, mempool, config });

    // Two siblings against the same committed head: first commits, second
    // stales and gets rebuilt under a fresh id.
    const a = _contentTx(dag, authorKp, "ts-a");
    const b = _contentTx(dag, authorKp, "ts-b");
    expect(a.prev[0]).toBe(b.prev[0]);
    expect(handler.commitOrderedTxs([a, b], 1).committed).toBe(1);

    // b was rebuilt (new id) and requeued; the OLD id must be tombstoned.
    expect(mempool.size()).toBe(1);
    expect(mempool.has(b.tx_id)).toBe(false);
    expect(mempool.add(b)).toEqual({ added: false, reason: "tombstoned" });

    // The rebuilt tx commits next round; the dead copy never re-entered.
    expect(handler.commitOrderedTxs(mempool.drain(25), 2).committed).toBe(1);
    expect(dag.getContent(b.data.ctid)).toBeTruthy();
    expect(mempool.size()).toBe(0);
  });

  test("an EARLY tx (predecessor in flight) waits unchanged instead of rebuilding into a sibling", () => {
    const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
    const dag = initDAG({ dbPath: ":memory:" });
    const nodeKp = generateMLDSAKeypair();
    const vpKp = generateMLDSAKeypair();
    const authorKp = generateMLDSAKeypair();
    dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
    dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);
    const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
    const scoring = initScoring(dag, config);
    const mempool = createMempool(dag, { nodeId: NODE_ID });
    const handler = createCommitHandler({ dag, scoring, mempool, config });

    // A sealed chain c1 -> c2; c2's cert arrives a round before c1's.
    const c1 = _contentTx(dag, authorKp, "early-1");
    dag.noteSealedTx(c1.tx_type, c1.data, c1.tx_id);
    const c2 = _contentTx(dag, authorKp, "early-2");
    expect(c2.prev[0]).toBe(c1.tx_id);

    // c2 alone: predecessor uncommitted and NOT dead , must wait UNCHANGED.
    expect(handler.commitOrderedTxs([c2], 1).committed).toBe(0);
    expect(mempool.has(c2.tx_id)).toBe(true);             // same id, no rebuild
    expect(dag.getTxRejection(c2.tx_id)).toBeNull();      // a wait is not a rejection

    // c1 lands; the waiting c2 drains and commits as-is.
    expect(handler.commitOrderedTxs([c1], 2).committed).toBe(1);
    expect(handler.commitOrderedTxs(mempool.drain(25), 3).committed).toBe(1);
    expect(dag.getOwnerHead(OWNER)).toBe(c2.tx_id);
    expect(dag.getContent(c2.data.ctid)).toBeTruthy();
  });

  test("a tx whose predecessor was rebuilt away (tombstoned) rebuilds immediately, no futile wait", () => {
    const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
    const dag = initDAG({ dbPath: ":memory:" });
    const nodeKp = generateMLDSAKeypair();
    const vpKp = generateMLDSAKeypair();
    const authorKp = generateMLDSAKeypair();
    dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
    dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);
    const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
    const scoring = initScoring(dag, config);
    const mempool = createMempool(dag, { nodeId: NODE_ID });
    const handler = createCommitHandler({ dag, scoring, mempool, config });

    const c1 = _contentTx(dag, authorKp, "dead-1");
    dag.noteSealedTx(c1.tx_type, c1.data, c1.tx_id);
    const c2 = _contentTx(dag, authorKp, "dead-2");
    expect(c2.prev[0]).toBe(c1.tx_id);

    // c1's id died (rebuilt away elsewhere). c2 must NOT wait for it.
    mempool.tombstone(c1.tx_id);
    dag.resetPendingOwnerHead(OWNER);
    expect(handler.commitOrderedTxs([c2], 1).committed).toBe(0);
    expect(mempool.has(c2.tx_id)).toBe(false);            // rebuilt under a new id
    expect(mempool.size()).toBe(1);
    expect(handler.commitOrderedTxs(mempool.drain(25), 2).committed).toBe(1);
    expect(dag.getContent(c2.data.ctid)).toBeTruthy();
  });

  test("a cross-cert COPY of an already-rebuilt stale tx is dropped, not rebuilt again", () => {
    const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
    const dag = initDAG({ dbPath: ":memory:" });
    const nodeKp = generateMLDSAKeypair();
    const vpKp = generateMLDSAKeypair();
    const authorKp = generateMLDSAKeypair();
    dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
    dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);
    const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
    const scoring = initScoring(dag, config);
    const mempool = createMempool(dag, { nodeId: NODE_ID });
    const handler = createCommitHandler({ dag, scoring, mempool, config });

    // Cert 1: sibling b stales and is rebuilt (b' now in mempool).
    const a = _contentTx(dag, authorKp, "cc-a");
    const b = _contentTx(dag, authorKp, "cc-b");
    expect(handler.commitOrderedTxs([a, b], 1).committed).toBe(1);
    expect(mempool.size()).toBe(1);
    const rebuiltId = mempool.getAll()[0].tx_id;

    // Cert 2 (same round wave): a COPY of the original b arrives. It must be
    // dropped as superseded , NOT rebuilt into a second in-flight duplicate.
    const res2 = handler.commitOrderedTxs([b], 1);
    expect(res2.committed).toBe(0);
    expect(mempool.size()).toBe(1);
    expect(mempool.getAll()[0].tx_id).toBe(rebuiltId);

    // The single rebuilt tx commits; no duplicate ever existed.
    expect(handler.commitOrderedTxs(mempool.drain(25), 2).committed).toBe(1);
    expect(dag.getContent(b.data.ctid)).toBeTruthy();
    expect(mempool.size()).toBe(0);
  });

  test("in-batch duplicate whose WINNER fails to commit is requeued, not orphaned", () => {
    const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
    const dag = initDAG({ dbPath: ":memory:" });
    const nodeKp = generateMLDSAKeypair();
    const vpKp = generateMLDSAKeypair();
    const authorKp = generateMLDSAKeypair();
    dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
    dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);
    const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
    const scoring = initScoring(dag, config);
    const mempool = createMempool(dag, { nodeId: NODE_ID });
    const handler = createCommitHandler({ dag, scoring, mempool, config });

    // Two copies of ONE content (same ctid, divergent rebuilt ids): the
    // "winner" passes Phase 1 but STALES in Phase 2 (superseded head); the
    // copy hits in-batch dedup. Old behavior dropped the copy forever , if
    // the winner then dies too, the content is lost with no trace.
    const base = _contentTx(dag, authorKp, "dup-base");
    expect(handler.commitOrderedTxs([base], 1).committed).toBe(1);
    const winner = _contentTx(dag, authorKp, "dup-orphan", { prev: [base.prev[0], base.prev[1]] });   // superseded head
    const copy = { ...winner, prev: [base.tx_id, winner.prev[1]] };   // current head
    copy.tx_id = computeTxId(copy);

    const res = handler.commitOrderedTxs([winner, copy], 2);
    expect(res.committed).toBe(0);
    // The copy must be requeued (winner did not commit), not rejected.
    expect(mempool.has(copy.tx_id)).toBe(true);
    expect(dag.getTxRejection(copy.tx_id)).toBeNull();

    // The content survives within bounded rounds (either surviving copy).
    let landed = false;
    for (let r = 3; r < 10 && !landed; r++) {
      handler.commitOrderedTxs(mempool.drain(25), r);
      landed = !!dag.getContent(winner.data.ctid);
    }
    expect(landed).toBe(true);
  });

  test("in-batch duplicate whose winner COMMITS is dropped as a true duplicate", () => {
    const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
    const dag = initDAG({ dbPath: ":memory:" });
    const nodeKp = generateMLDSAKeypair();
    const vpKp = generateMLDSAKeypair();
    const authorKp = generateMLDSAKeypair();
    dag.saveNode({ node_id: NODE_ID, name: "n", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveVP({ vp_id: VP_ID, name: "vp", jurisdiction: "US", jurisdiction_tier: "green", public_key: vpKp.publicKey, status: "active", registered_at: 1767225600000 });
    dag.saveIdentity({ tip_id: AUTHOR_TIP, region: "US", public_key: authorKp.publicKey, root_public_key: "00", vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", registered_at: 1767225600000, tx_id: seedAnchorTx(dag, TX_TYPES.REGISTER_IDENTITY, { tip_id: AUTHOR_TIP }) });
    dag.setScore(AUTHOR_TIP, 750, 0, 1767225600000);
    const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
    const scoring = initScoring(dag, config);
    const mempool = createMempool(dag, { nodeId: NODE_ID });
    const handler = createCommitHandler({ dag, scoring, mempool, config });

    const winner = _contentTx(dag, authorKp, "dup-true");
    const copy = { ...winner, prev: [...winner.prev] };
    copy.data = { ...winner.data };
    copy.timestamp = winner.timestamp + 1;   // distinct id, same ctid
    copy.tx_id = computeTxId(copy);

    const res = handler.commitOrderedTxs([winner, copy], 1);
    expect(res.committed).toBe(1);
    expect(mempool.has(copy.tx_id)).toBe(false);
    expect(dag.getTxRejection(copy.tx_id)).not.toBeNull();
    expect(dag.getContent(winner.data.ctid)).toBeTruthy();
  });

  test("broken chain: whole tail stales, requeues re-chained, commits next round", () => {
    const fx = _setup();
    // A foreign-view tx commits first and moves the head.
    const winner = _contentTx(fx.dag, fx.authorKp, "winner");
    fx.dag.noteSealedTx(winner.tx_type, winner.data, winner.tx_id);
    // A chained burst sealed against the SAME base (before winner committed
    // elsewhere) arrives after the winner in the ordered batch.
    const t1 = _contentTx(fx.dag, fx.authorKp, "chain-1");
    fx.dag.noteSealedTx(t1.tx_type, t1.data, t1.tx_id);
    const t2 = _contentTx(fx.dag, fx.authorKp, "chain-2");
    fx.dag.noteSealedTx(t2.tx_type, t2.data, t2.tx_id);
    expect(t1.prev[0]).toBe(winner.tx_id);   // chained onto pending winner

    // Round 1: winner commits; t1/t2 follow the chain and also commit
    // (chain intact since winner won). Now break a chain for real:
    const res1 = fx.handler.commitOrderedTxs([winner, t1, t2], 1);
    expect(res1.committed).toBe(3);

    // Seal two txs chained on a base that will lose the race.
    const loserBase = _contentTx(fx.dag, fx.authorKp, "loser-base");
    // do NOT note it (simulates a competing node's seal we never saw), then
    // seal a local chain against the stale committed head:
    const s1 = { ...loserBase };   // same prev base as head
    const s2 = _contentTx(fx.dag, fx.authorKp, "local-2", { prev: [s1.tx_id, s1.prev[1]] });
    // Competing tx from the same owner commits first (head moves):
    const competitor = _contentTx(fx.dag, fx.authorKp, "competitor");
    const resA = fx.handler.commitOrderedTxs([competitor], 2);
    expect(resA.committed).toBe(1);

    // Now the stale chain arrives: both stale, both requeue re-chained.
    const resB = fx.handler.commitOrderedTxs([s1, s2], 3);
    expect(resB.committed).toBe(0);
    const requeued = fx.dag.getMempoolTxs();
    expect(requeued.length).toBe(2);
    expect(requeued[0].prev[0]).toBe(competitor.tx_id);        // rebuilt from new head
    expect(requeued[1].prev[0]).toBe(requeued[0].tx_id);       // re-chained onto sibling

    // Next round: the re-chained pair commits together.
    const resC = fx.handler.commitOrderedTxs(requeued, 4);
    expect(resC.committed).toBe(2);
  });
});
