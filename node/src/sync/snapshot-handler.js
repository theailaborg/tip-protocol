/**
 * @file @tip-protocol/node/src/sync/snapshot-handler.js
 * @description §14 state-snapshot sync protocol — /tip/state-snapshot/1.0.0
 *
 * Lets new joiners catch up to a recent committed round in O(state size)
 * instead of O(full chain history). Builds on Part 1's commit-row
 * cryptography (state_merkle_root + txs_merkle_root + 2f+1 ack
 * signatures) — the joiner cryptographically verifies the snapshot it
 * received before installing any state.
 *
 * Stream framing:
 *   Each message is written as a 4-byte big-endian length prefix
 *   followed by its protobuf body. One libp2p stream carries:
 *     SnapshotHeader → SnapshotStateRow* → SnapshotEnd
 *
 * Verification (client side):
 *   1. Recompute state_merkle_root from received state rows → must
 *      match header's state_merkle_root. (Mirror of what the peer
 *      computed on their side via computeStateMerkleRoot.)
 *   2. Build node_id → public_key map from received `nodes` rows, then
 *      verify each ack_signature over `"ack:${anchor_batch_hash}:${signer}"`.
 *      Count valid signatures from committee members → must be ≥ quorum(2f+1).
 *   3. Sanity: row_count in SnapshotEnd matches rows received.
 *
 * Install (after successful verification): write all state rows via the
 * respective dag.save* methods + dag.saveCommit(header), all inside
 * dag.runInTransaction so the snapshot is atomic — either every row
 * lands or the whole commit rolls back.
 *
 * Trust model note:
 *   For MVP, signature verification uses public keys FROM THE INCOMING
 *   SNAPSHOT's nodes table. A malicious snapshot could invent nodes +
 *   matching private keys — we catch this later because the genesis
 *   founding_node + genesis_ring_keys MUST be present in the snapshot
 *   (joiner verifies against its own genesis). Full "walk committee
 *   from genesis through every commit's ack_signer_ids" chain-of-trust
 *   verification is deferred; see issues.md §14 hardening.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { mldsaVerify, canonicalJson } = require("../../../shared/crypto");
const { NETWORK } = require("../../../shared/protocol-constants");
const { computeQuorum } = require("../consensus/certificate");
const { createStateRootBuilder } = require("../consensus/state-root");
const { encode, decode, bytesToHex, hexToBytes, bytesToUtf8 } = require("../network/proto");
const { frame: _frame, parseLengthPrefixedFrames: _parseLengthPrefixedFrames } = require("../network/framing");
const { getLogger } = require("../logger");

const log = getLogger("tip.snapshot");

// Protocol constants live in genesis (shared/protocol-constants.js NETWORK).
// Lazy-accessed via getters so the values are consistent across nodes and
// a single genesis change rolls out everywhere. See also: HANDSHAKE_PROTOCOL.
const SNAPSHOT_PROTOCOL = NETWORK.SNAPSHOT_PROTOCOL;

/**
 * Create the snapshot handler.
 *
 * @param {Object} options
 * @param {Object}   options.dag               DAG facade
 * @param {Object}   options.network           libp2p network node
 * @param {Function} options.isAuthorizedPeer  (peerIdString) => boolean
 * @returns {Object}
 */
function createSnapshotHandler({ dag, network, isAuthorizedPeer = () => false }) {

  // ── Server: handle incoming snapshot request ────────────────────────────
  async function registerProtocol() {
    if (!network || !network.node) {
      log.warn("No network node — snapshot protocol not registered");
      return;
    }

    await network.handle(SNAPSHOT_PROTOCOL, async ({ stream, connection }) => {
      const remotePeer = connection?.remotePeer?.toString() || "unknown";
      try {
        if (!isAuthorizedPeer(remotePeer)) {
          log.warn(`Snapshot: rejected request from unauthorized peer ${remotePeer}`);
          try { stream.close(); } catch { /* ignore */ }
          return;
        }
        await _handleIncomingSnapshot(stream, remotePeer);
      } catch (err) {
        log.error(`Snapshot handler error from ${remotePeer}: ${err.message}`);
        try { stream.close(); } catch { /* ignore */ }
      }
    });

    log.info(`Snapshot protocol registered: ${SNAPSHOT_PROTOCOL}`);
  }

  async function _handleIncomingSnapshot(stream, remotePeer) {
    // Read one SnapshotRequest from the stream.
    const request = await _readOneMessage(stream, "SnapshotRequest");
    if (!request) {
      log.warn(`Snapshot: empty request from ${remotePeer}`);
      return;
    }

    const minRound = Number(request.minRound || 0);
    const latest = dag.getLatestCommit ? dag.getLatestCommit() : null;

    if (!latest || latest.round < minRound) {
      // Peer has no commit at or after the joiner's min_round — reply with
      // an error header so the joiner can pick a different peer instead of
      // hanging on a silent close.
      const errHeader = encode("SnapshotHeader", _emptyHeader(
        `no commit at or after round ${minRound} (latest=${latest?.round || 0})`
      ));
      await stream.sink([_frame(errHeader)]);
      log.info(`Snapshot: declined ${remotePeer} — latest=${latest?.round || 0}, requested=${minRound}`);
      return;
    }

    // Need the anchor cert's batch_hash so the joiner can reconstruct the
    // payload each ack signed. Fetch from DAG; falls back to zero-bytes if
    // the cert is missing (ack verification will fail on the joiner side,
    // which is the correct behaviour — no silent bypass).
    let anchorBatchHash = "";
    try {
      const anchorCert = dag.getCertificate(latest.anchor_cert_hash);
      anchorBatchHash = anchorCert?.batch?.hash || "";
    } catch (err) {
      log.warn(`Snapshot: failed to read anchor cert ${latest.anchor_cert_hash.slice(0, 16)}: ${err.message}`);
    }

    const headerBuf = encode("SnapshotHeader", {
      round: latest.round,
      anchorCertHash: hexToBytes(latest.anchor_cert_hash),
      leaderNodeId: latest.leader_node_id,
      committee: latest.committee || [],
      supportCount: latest.support_count,
      consensusIndex: latest.consensus_index,
      committedAt: latest.committed_at,
      stateMerkleRoot: hexToBytes(latest.state_merkle_root),
      txsMerkleRoot: hexToBytes(latest.txs_merkle_root),
      ackSignerIds: latest.ack_signer_ids || [],
      ackSignatures: (latest.ack_signatures || []).map(hexToBytes),
      anchorBatchHash: hexToBytes(anchorBatchHash),
      error: "",
    });

    // Stream header + state rows + end marker in a single sink call, using
    // an async generator so libp2p flushes frames as they're produced
    // (no full-state materialisation in memory on the sender).
    let rowsSent = 0;
    try {
      await stream.sink((async function* () {
        yield _frame(headerBuf);
        for (const { table, row } of dag.iterateCanonicalState()) {
          const rowBuf = encode("SnapshotStateRow", {
            table,
            canonicalJson: Buffer.from(canonicalJson(row), "utf8"),
          });
          yield _frame(rowBuf);
          rowsSent++;
        }
        const endBuf = encode("SnapshotEnd", { rowCount: rowsSent });
        yield _frame(endBuf);
      })());
    } catch (err) {
      log.warn(`Snapshot: stream write failed to ${remotePeer}: ${err.message}`);
      return;
    }

    log.info(`Snapshot: sent round ${latest.round} + ${rowsSent} state rows to ${remotePeer}`);
  }

  // ── Client: request a snapshot from a peer and install it ────────────────
  /**
   * Pull a state snapshot from a peer, verify it cryptographically, install
   * it atomically. Returns a descriptor of what was installed.
   *
   * @param {string} peerId                 libp2p peer ID string
   * @param {Object} [opts]
   * @param {number} [opts.minRound]        require a commit at or after this round
   * @param {string} [opts.requesterNodeId] optional — for server-side logging
   * @returns {Promise<{ round, consensus_index, rows_installed, state_merkle_root, txs_merkle_root }>}
   */
  async function requestSnapshotFromPeer(peerId, { minRound = 0, requesterNodeId = "" } = {}) {
    if (!network) throw new Error("snapshot: no network node");

    log.info(`Snapshot: requesting from ${peerId.slice(0, 12)}... (min_round=${minRound})`);

    const stream = await network.openStream(peerId, SNAPSHOT_PROTOCOL);
    try {
      // Write the request (one frame, length-prefixed for symmetry with the
      // server-side framing — server reads exactly one message).
      const reqBuf = encode("SnapshotRequest", { minRound, requesterNodeId });
      try { await stream.sink([reqBuf]); }
      catch (err) { throw new Error(`failed to send request: ${err.message}`); }

      // Read every frame off the stream into a single buffer, then split
      // into length-prefixed messages. For MVP this buffers the whole
      // snapshot on the client (small state, bounded memory). Scale fix is
      // same trigger as issues.md Consensus #32 — swap in a streaming
      // length-prefix parser when state grows.
      const chunks = [];
      for await (const chunk of stream.source) chunks.push(chunk.subarray ? chunk.subarray() : chunk);
      const body = Buffer.concat(chunks);

      const frames = _parseLengthPrefixedFrames(body);
      if (frames.length === 0) throw new Error("empty response from peer");

      // First frame is always SnapshotHeader.
      const header = decode("SnapshotHeader", frames[0]);
      if (header.error) throw new Error(`peer declined snapshot: ${header.error}`);

      // Middle frames are SnapshotStateRow; last frame is SnapshotEnd.
      if (frames.length < 2) throw new Error("response missing SnapshotEnd terminator");
      const endFrame = frames[frames.length - 1];
      const rowFrames = frames.slice(1, -1);

      const end = decode("SnapshotEnd", endFrame);
      const endCount = Number(end.rowCount || 0);
      if (endCount !== rowFrames.length) {
        throw new Error(`row count mismatch: header says ${endCount}, got ${rowFrames.length}`);
      }

      // Decode rows, rebuild state root incrementally, collect nodes so we
      // can verify ack signatures once the public keys are all known.
      const stateRoot = createStateRootBuilder();
      const nodePubKeys = new Map();           // node_id → public_key (hex)
      const installQueue = [];                 // { table, row } for the final write
      for (const frame of rowFrames) {
        const row = decode("SnapshotStateRow", frame);
        const table = row.table;
        const canonicalBytes = row.canonicalJson;
        if (!table || !canonicalBytes) throw new Error("malformed SnapshotStateRow");
        const canonical = bytesToUtf8(canonicalBytes);
        stateRoot.addRow(table, canonical);

        let parsed;
        try { parsed = JSON.parse(canonical); }
        catch (err) { throw new Error(`row canonical_json parse failed: ${err.message}`); }

        if (table === "nodes" && parsed.node_id && parsed.public_key) {
          nodePubKeys.set(parsed.node_id, parsed.public_key);
        }
        installQueue.push({ table, row: parsed });
      }

      // ── Root match ────────────────────────────────────────────────────
      const derived = stateRoot.finalize();
      const expected = bytesToHex(header.stateMerkleRoot);
      if (derived !== expected) {
        throw new Error(`state_merkle_root mismatch: expected ${expected?.slice(0, 16)}..., derived ${derived.slice(0, 16)}...`);
      }

      // ── Signature quorum ──────────────────────────────────────────────
      const anchorBatchHashHex = bytesToHex(header.anchorBatchHash);
      if (!anchorBatchHashHex) throw new Error("header missing anchor_batch_hash");
      const committee = header.committee || [];
      if (committee.length === 0) throw new Error("header missing committee");
      const quorum = computeQuorum(committee.length);
      const committeeSet = new Set(committee);

      const signerIds = header.ackSignerIds || [];
      const signatures = (header.ackSignatures || []).map(bytesToHex);
      if (signerIds.length !== signatures.length) {
        throw new Error(`ack length mismatch: ${signerIds.length} signers vs ${signatures.length} sigs`);
      }

      let validAcks = 0;
      const seen = new Set();
      for (let i = 0; i < signerIds.length; i++) {
        const signer = signerIds[i];
        if (seen.has(signer)) continue;          // no double-counting a signer
        if (!committeeSet.has(signer)) continue; // non-committee sig doesn't count toward quorum
        const pubKey = nodePubKeys.get(signer);
        if (!pubKey) continue;                   // no public key available — can't verify
        const payload = `ack:${anchorBatchHashHex}:${signer}`;
        if (mldsaVerify(payload, signatures[i], pubKey)) {
          seen.add(signer);
          validAcks++;
        }
      }

      if (validAcks < quorum) {
        throw new Error(`insufficient ack quorum: ${validAcks}/${quorum} (committee=${committee.length})`);
      }

      // ── Install atomically ────────────────────────────────────────────
      const installed = _installSnapshot(header, installQueue);

      log.notice(
        `Snapshot: installed round=${header.round} consensus_index=${Number(header.consensusIndex || 0)} ` +
        `rows=${installed} acks=${validAcks}/${committee.length} peer=${peerId.slice(0, 12)}`
      );

      return {
        round: Number(header.round),
        consensus_index: Number(header.consensusIndex || 0),
        rows_installed: installed,
        state_merkle_root: derived,
        txs_merkle_root: bytesToHex(header.txsMerkleRoot),
      };
    } finally {
      try { stream.close(); } catch { /* ignore */ }
    }
  }

  function _installSnapshot(header, queue) {
    // Atomic install — either every row + the commit row land, or nothing.
    // Uses DAG's existing save* methods so the write paths are the same as
    // normal consensus application (column defaults, integer coercion, etc.).
    return dag.runInTransaction(() => {
      let n = 0;
      for (const { table, row } of queue) {
        _installOneRow(table, row);
        n++;
      }
      // Commit row: convert header fields back to the native shape
      // dag.saveCommit expects.
      dag.saveCommit({
        round: Number(header.round),
        anchor_cert_hash: bytesToHex(header.anchorCertHash),
        leader_node_id: header.leaderNodeId,
        committee: header.committee || [],
        support_count: Number(header.supportCount || 0),
        consensus_index: Number(header.consensusIndex || 0),
        committed_at: header.committedAt,
        state_merkle_root: bytesToHex(header.stateMerkleRoot),
        txs_merkle_root: bytesToHex(header.txsMerkleRoot),
        ack_signer_ids: header.ackSignerIds || [],
        ack_signatures: (header.ackSignatures || []).map(bytesToHex),
      });
      return n;
    });
  }

  function _installOneRow(table, row) {
    switch (table) {
      case "identities":
        dag.saveIdentity(row);
        break;
      case "content":
        dag.saveContent(row);
        break;
      case "dedup_registry":
        dag.addDedupHash(row.dedup_hash, row.created_at);
        break;
      case "revocations":
        dag.addRevocation(row.tip_id, row.tx_type, row.timestamp, row.tx_id);
        break;
      case "verification_providers":
        dag.saveVP(row);
        break;
      case "nodes":
        dag.saveNode(row);
        break;
      default:
        // Unknown tables are tolerated so adding a new canonical table on
        // the server doesn't hard-fail older joiners — they'll just skip
        // installing it. (The state_merkle_root already validated content.)
        log.warn(`Snapshot: unknown table "${table}" — skipping row install`);
    }
  }

  return {
    registerProtocol,
    requestSnapshotFromPeer,
    SNAPSHOT_PROTOCOL,
    // Exposed for unit tests
    _handleIncomingSnapshot,
  };
}

// ─── Framing helpers ────────────────────────────────────────────────────────
// Length-prefix framing shared with /tip/sync/1.0.0; see network/framing.js.

/**
 * Read exactly one protobuf message off a libp2p stream (no length prefix —
 * single-message request path).
 */
async function _readOneMessage(stream, typeName) {
  const chunks = [];
  for await (const chunk of stream.source) {
    chunks.push(chunk.subarray ? chunk.subarray() : chunk);
    break;
  }
  if (chunks.length === 0) return null;
  return decode(typeName, Buffer.concat(chunks));
}

/**
 * Build an all-zero SnapshotHeader for the error-response path.
 */
function _emptyHeader(error) {
  return {
    round: 0,
    anchorCertHash: Buffer.alloc(0),
    leaderNodeId: "",
    committee: [],
    supportCount: 0,
    consensusIndex: 0,
    committedAt: "",
    stateMerkleRoot: Buffer.alloc(0),
    txsMerkleRoot: Buffer.alloc(0),
    ackSignerIds: [],
    ackSignatures: [],
    anchorBatchHash: Buffer.alloc(0),
    error,
  };
}

module.exports = { createSnapshotHandler };
