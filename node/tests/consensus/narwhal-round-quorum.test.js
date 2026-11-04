/**
 * @file tests/consensus/narwhal-round-quorum.test.js
 * @description Round advance, own-cert sealing and batch requeue under a peer whose certs land late.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs } = require("../../../shared/time");
const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, generateMLDSAKeypair, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { createBatch, createBatchAck, createCertificate } = require(path.join(SRC, "consensus", "certificate"));
const { serializeBatch, serializeBatchAck, serializeCertificate, deserializeBatch } = require(path.join(SRC, "consensus", "certificate-codec"));
const { loadTypes, encode, decode } = require(path.join(SRC, "network", "proto"));
const { getActiveCommittee } = require(path.join(SRC, "consensus", "participants"));

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

const SELF = "tip://node/self";
const B = "tip://node/peerB";
const C = "tip://node/peerC";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function build() {
  const kp = { [SELF]: generateMLDSAKeypair(), [B]: generateMLDSAKeypair(), [C]: generateMLDSAKeypair() };
  const dag = initDAG({ inMemory: true });
  const published = [];
  for (const id of [SELF, B, C]) {
    dag.saveNode({ node_id: id, name: id, public_key: kp[id].publicKey, status: "active", registered_at: 1767225600000 });
  }
  dag.saveCommitteeRotation({
    rotation_number: 1, effective_round: 1,
    committee: [SELF, B, C].map((id) => ({ node_id: id, public_key: kp[id].publicKey })),
    prev_rotation: 0, signer_node_ids: [], signatures: [], payload_hash: "test-stale-round-certs", committed_at: 1767225600000,
  });
  const network = {
    TOPICS: { MEMPOOL: "tip/mempool", CERTIFICATES: "tip/certificates", CONSENSUS: "tip/consensus" },
    publish: (topic, buf) => { published.push({ topic, buf }); },
    authorizedPeers: () => ({ [B]: { publicKey: kp[B].publicKey }, [C]: { publicKey: kp[C].publicKey } }),
  };
  const mempool = createMempool({ dag });
  const narwhal = createNarwhal({
    dag, mempool, network,
    config: { nodeId: SELF, nodeRegisteredId: SELF, nodePrivateKey: kp[SELF].privateKey, nodePublicKey: kp[SELF].publicKey },
    getNodeKey: (id) => dag.getNode(id)?.public_key || null,
    getNodeCount: () => 3,
    getCommittee: (round) => getActiveCommittee(dag, round != null ? round : narwhal.currentRound()),
    onCommit: () => {},
    onCertSaved: () => {},
  });
  return { narwhal, dag, kp, mempool, published };
}

function peerCert(fx, round, author, ackers, parentHashes) {
  const batch = createBatch(round, author, [], fx.kp[author].privateKey);
  const acks = ackers.map((id) => createBatchAck(batch.hash, id, nowMs(), fx.kp[id].privateKey));
  return encode("Certificate", serializeCertificate(createCertificate(round, author, batch, acks, parentHashes, fx.kp[author].privateKey)));
}

async function advanceToNextRound(fx) {
  fx.narwhal.start();
  fx.narwhal.exitSyncMode(999);
  await sleep(50);
  const r = fx.narwhal.currentRound();
  // The previous round's certs, as any node that reached round r holds them.
  await fx.narwhal.handleIncomingCertificate(peerCert(fx, r - 1, B, [B, C], []));
  await fx.narwhal.handleIncomingCertificate(peerCert(fx, r - 1, C, [C, B], []));
  const prev = fx.dag.getCertificatesByRound(r - 1).map((c) => c.hash);
  const own = createBatch(r, SELF, [], fx.kp[SELF].privateKey);
  fx.narwhal.handleIncomingAck(encode("BatchAck", serializeBatchAck(createBatchAck(own.hash, B, nowMs(), fx.kp[B].privateKey))));
  await sleep(20);
  expect(fx.dag.getCertificateByAuthorRound(SELF, r)).toBeTruthy();
  await fx.narwhal.handleIncomingCertificate(peerCert(fx, r, B, [B, SELF], prev));
  expect(fx.narwhal.currentRound()).toBe(r + 1);
  return r;
}

describe("narwhal: round quorum counts only certs of the current round", () => {
  test("one peer cert for the new round does not advance it on the previous round's certs", async () => {
    const fx = build();
    const r = await advanceToNextRound(fx);
    const parents = fx.dag.getCertificatesByRound(r).map((c) => c.hash);
    await fx.narwhal.handleIncomingCertificate(peerCert(fx, r + 1, C, [C, B], parents));
    expect(fx.dag.getCertificatesByRound(r + 1)).toHaveLength(1);
    expect(fx.narwhal.currentRound()).toBe(r + 1);
    fx.narwhal.stop();
  }, 10000);

  test("control: a quorum of new-round certs does advance it", async () => {
    const fx = build();
    const r = await advanceToNextRound(fx);
    const parents = fx.dag.getCertificatesByRound(r).map((c) => c.hash);
    await fx.narwhal.handleIncomingCertificate(peerCert(fx, r + 1, C, [C, B], parents));
    await fx.narwhal.handleIncomingCertificate(peerCert(fx, r + 1, B, [B, C], parents));
    expect(fx.narwhal.currentRound()).toBe(r + 2);
    fx.narwhal.stop();
  }, 10000);
});

describe("narwhal: own cert needs a quorum of previous-round parents", () => {
  test("a fast-forwarded node holds its seal until the previous round's certs arrive", async () => {
    const fx = build();
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(999);
    await sleep(50);
    const r = fx.narwhal.currentRound();
    const own = createBatch(r, SELF, [], fx.kp[SELF].privateKey);
    fx.narwhal.handleIncomingAck(encode("BatchAck", serializeBatchAck(createBatchAck(own.hash, B, nowMs(), fx.kp[B].privateKey))));
    await sleep(20);
    expect(fx.dag.getCertificateByAuthorRound(SELF, r)).toBeFalsy();

    await fx.narwhal.handleIncomingCertificate(peerCert(fx, r - 1, B, [B, C], []));
    await fx.narwhal.handleIncomingCertificate(peerCert(fx, r - 1, C, [C, B], []));
    await sleep(20);
    const cert = fx.dag.getCertificateByAuthorRound(SELF, r);
    expect(cert).toBeTruthy();
    expect(cert.parent_hashes).toHaveLength(2);
    fx.narwhal.stop();
  }, 10000);

  test("without parents it still seals once the round timer fires (no liveness loss)", async () => {
    const fx = build();
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(999);
    await sleep(50);
    const r = fx.narwhal.currentRound();
    const own = createBatch(r, SELF, [], fx.kp[SELF].privateKey);
    fx.narwhal.handleIncomingAck(encode("BatchAck", serializeBatchAck(createBatchAck(own.hash, B, nowMs(), fx.kp[B].privateKey))));
    await sleep(20);
    expect(fx.dag.getCertificateByAuthorRound(SELF, r)).toBeFalsy();
    await sleep(2300);
    expect(fx.dag.getCertificateByAuthorRound(SELF, r)).toBeTruthy();
    fx.narwhal.stop();
  }, 10000);
});

function testTx(i) {
  const body = { tx_type: "REGISTER_CONTENT", timestamp: 1767225600000 + i, prev: [], data: { ctid: `tip://content/requeue-${i}`, content_hash: shake256(`requeue-${i}`), seq: i } };
  body.tx_id = computeTxId(body);
  return body;
}

describe("narwhal: the parent wait is bounded across fast-forwards", () => {
  test("a node that keeps fast-forwarding without parents still seals one round timeout after it began waiting", async () => {
    const fx = build();
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(999);
    await sleep(50);
    const r = fx.narwhal.currentRound();
    const ownBatch = (round) => fx.published.filter((m) => m.topic === "tip/mempool")
      .map((m) => deserializeBatch(decode("Batch", m.buf))).find((b) => b.round === round && b.author_node_id === SELF);
    const ackOwn = (round, from) => fx.narwhal.handleIncomingAck(encode("BatchAck",
      serializeBatchAck(createBatchAck(ownBatch(round).hash, from, nowMs(), fx.kp[from].privateKey))));

    ackOwn(r, B);
    await sleep(1150);
    // A peer batch one round ahead fast-forwards the node and re-arms its round timer.
    fx.narwhal.handleIncomingBatch(encode("Batch", serializeBatch(createBatch(r + 1, B, [], fx.kp[B].privateKey))));
    await sleep(50);
    expect(fx.narwhal.currentRound()).toBe(r + 1);
    ackOwn(r + 1, B);
    await sleep(20);
    expect(fx.dag.getCertificateByAuthorRound(SELF, r + 1)).toBeFalsy();

    await sleep(1000);
    ackOwn(r + 1, C);
    await sleep(20);
    expect(fx.dag.getCertificateByAuthorRound(SELF, r + 1)).toBeTruthy();
    fx.narwhal.stop();
  }, 10000);
});

describe("narwhal: adopting an existing own cert never drops the new batch's txs", () => {
  test("txs of a batch superseded by an already-sealed own cert go back to the mempool", async () => {
    const fx = build();
    const tx = testTx(1);
    expect(fx.mempool.add(tx).added).toBe(true);
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(999);
    await sleep(50);
    const r = fx.narwhal.currentRound();
    const sent = fx.published.filter((m) => m.topic === "tip/mempool").map((m) => deserializeBatch(decode("Batch", m.buf)));
    const mine = sent.find((b) => b.round === r);
    expect(mine.txs.map((t) => t.tx_id)).toEqual([tx.tx_id]);
    expect(fx.mempool.has(tx.tx_id)).toBe(false);

    // A late seal already put an earlier batch under this round's label.
    const earlier = createBatch(r - 1, SELF, [], fx.kp[SELF].privateKey);
    const acks = [SELF, B].map((id) => createBatchAck(earlier.hash, id, nowMs(), fx.kp[id].privateKey));
    fx.dag.saveCertificate(createCertificate(r, SELF, earlier, acks, [], fx.kp[SELF].privateKey));

    fx.narwhal.handleIncomingAck(encode("BatchAck", serializeBatchAck(createBatchAck(mine.hash, B, nowMs(), fx.kp[B].privateKey))));
    await sleep(20);
    expect(fx.mempool.has(tx.tx_id)).toBe(true);
    fx.narwhal.stop();
  }, 10000);
});
