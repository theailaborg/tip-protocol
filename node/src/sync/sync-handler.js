/**
 * @file @tip-protocol/node/src/sync/sync-handler.js
 * @description Certificate sync protocol for TIP consensus.
 *
 * Handles new node catch-up and ongoing sync between peers.
 * Uses libp2p streams with Protobuf serialization.
 *
 * Protocol: /tip/sync/1.0.0
 *
 * Flow:
 *   1. New node opens stream to a peer
 *   2. Sends SyncRequest { from_round, merkle_root }
 *   3. Peer responds with batches of certificates (SyncResponse)
 *   4. Repeat until caught up (has_more = false)
 *   5. Close stream
 *
 * Also provides:
 *   - Merkle tree management (build, update, compare)
 *   - Auto-sync on peer connect (if roots differ)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");
const { createMerkleTree } = require("./merkle-tree");
const { encode, decode, bytesToHex, hexToBytes, bytesToUtf8 } = require("../network/proto");
const { getLogger } = require("../logger");

const log = getLogger("tip.sync");

const SYNC_PROTOCOL = "/tip/sync/1.0.0";

/**
 * Create the sync handler.
 *
 * @param {Object} options
 * @param {Object} options.dag         DAG store (certificates + txs)
 * @param {Object} options.network     libp2p network node
 * @param {Object} options.consensus   Consensus orchestrator (for commit handler)
 * @returns {Object} Sync handler
 */
/**
 * @param {Object} options
 * @param {Object} options.dag         DAG store
 * @param {Object} options.network     libp2p network node
 * @param {Function} options.isAuthorizedPeer  (peerId) => boolean
 */
function createSyncHandler({ dag, network, isAuthorizedPeer = () => false }) {
  // Build Merkle tree from existing certificates
  let _merkle = _buildMerkleFromDAG();

  /**
   * Build Merkle tree from all persisted certificates.
   * Iterates rounds in ascending order and uses getCertificatesByRound, which
   * returns certs sorted by author_node_id. This gives a canonical ordering
   * that's identical across nodes with identical DAG state, making the root
   * a deterministic summary of "what's in my DAG."
   */
  function _buildMerkleFromDAG() {
    const latestRound = dag.getLatestRound();
    const hashes = [];
    for (let r = 1; r <= latestRound; r++) {
      try {
        const certs = dag.getCertificatesByRound(r);
        for (const cert of certs) hashes.push(cert.hash);
      } catch (err) {
        log.warn(`Failed to load certs for round ${r}: ${err.message}`);
      }
    }
    const tree = createMerkleTree({ initialHashes: hashes });
    log.info(`Merkle tree built: ${hashes.length} certificates, root: ${tree.root().slice(0, 16)}...`);
    return tree;
  }

  /**
   * Rebuild the Merkle tree from DAG state so the root reflects every
   * saved cert in canonical (round, author_node_id) order. Called whenever
   * a new certificate is saved — either via anchor commit, live gossip, or
   * sync import. The rebuild cost is O(N) certs, which is trivial for the
   * permissioned-federation scale TIP targets.
   */
  function onCertificateCommitted(_certHash) {
    _merkle = _buildMerkleFromDAG();
  }

  /**
   * Get current Merkle root.
   * @returns {string}
   */
  function merkleRoot() {
    return _merkle.root();
  }

  /**
   * Register the sync protocol handler on the libp2p node.
   * This handles incoming sync requests from peers that need to catch up.
   */
  async function registerProtocol() {
    if (!network || !network.node) {
      log.warn("No network node — sync protocol not registered");
      return;
    }

    await network.handle(SYNC_PROTOCOL, async ({ stream, connection }) => {
      const remotePeer = connection?.remotePeer?.toString() || "unknown";
      try {
        if (!isAuthorizedPeer(remotePeer)) {
          log.warn(`Sync: rejected request from unauthorized peer ${remotePeer}`);
          try { stream.close(); } catch { /* ignore */ }
          return;
        }
        await _handleIncomingSync(stream, remotePeer);
      } catch (err) {
        log.error(`Sync handler error from ${remotePeer}: ${err.message}`);
        try { stream.close(); } catch { /* ignore */ }
      }
    });

    log.info(`Sync protocol registered: ${SYNC_PROTOCOL}`);
  }

  /**
   * Handle an incoming sync request — send certificates the peer is missing.
   */
  async function _handleIncomingSync(stream, remotePeer) {
    // Read SyncRequest from stream
    const chunks = [];
    for await (const chunk of stream.source) {
      chunks.push(chunk.subarray());
      break; // Only read one message (the request)
    }

    if (chunks.length === 0) {
      log.warn("Sync: received empty request");
      return;
    }

    let request;
    try {
      request = decode("SyncRequest", Buffer.concat(chunks));
    } catch (err) {
      log.warn(`Sync: failed to decode request: ${err.message}`);
      return;
    }

    const fromRound = request.fromRound || 1;
    const latestRound = dag.getLatestRound();

    log.info(`Sync: peer requested from round ${fromRound} (we have ${latestRound})`);

    // Collect all requested certs into one response. libp2p stream.sink is
    // single-use per stream, so the former multi-batch path silently dropped
    // anything past the first batch. For our federation scale this fits
    // comfortably in one message; if certs ever exceed CERTIFICATE_MAX_BYTES
    // * many, we'd need proper length-prefixed framing.
    const allCerts = [];
    for (let r = fromRound; r <= latestRound; r++) {
      try {
        const certs = dag.getCertificatesByRound(r);
        allCerts.push(...certs);
      } catch (err) {
        log.warn(`Sync: failed to read round ${r}: ${err.message}`);
      }
    }

    const response = encode("SyncResponse", {
      certificates: allCerts.map(c => _serializeCertForSync(c)),
      fromRound: allCerts.length > 0 ? allCerts[0].round : fromRound,
      toRound: allCerts.length > 0 ? allCerts[allCerts.length - 1].round : fromRound,
      latestRound,
      merkleRoot: hexToBytes(merkleRoot()),
      hasMore: false,
    });

    try {
      await stream.sink([response]);
    } catch (err) {
      log.warn(`Sync: stream write failed: ${err.message}`);
    }

    log.info(`Sync: sent ${allCerts.length} certificates (rounds ${fromRound}-${latestRound})`);
  }

  /**
   * Request sync from a peer — pull certificates we're missing.
   * @param {string} peerId  Remote peer ID
   * @returns {Promise<{ imported: number, fromRound: number, toRound: number }>}
   */
  async function syncFromPeer(peerId) {
    if (!network) throw new Error("No network node");

    const fromRound = dag.getLatestRound() + 1;
    log.info(`Sync: requesting from peer ${peerId.slice(0, 12)}... from round ${fromRound}`);

    let stream;
    try {
      stream = await network.openStream(peerId, SYNC_PROTOCOL);
    } catch (err) {
      throw new Error(`Sync: failed to open stream to ${peerId.slice(0, 12)}: ${err.message}`);
    }

    // Send SyncRequest
    const request = encode("SyncRequest", {
      fromRound,
      toRound: 0, // 0 = latest
      merkleRoot: hexToBytes(merkleRoot()),
      batchSize: CONSENSUS.SYNC_BATCH_SIZE,
    });

    try {
      // Write request
      try { await stream.sink([request]); } catch (err) { throw new Error(`Failed to send sync request: ${err.message}`); }

      // Read entire response — stream may split protobuf across multiple chunks
      const chunks = [];
      for await (const chunk of stream.source) {
        chunks.push(chunk.subarray());
      }

      let imported = 0;
      let maxRound = fromRound;
      let peerLatestRound = 0;

      if (chunks.length > 0) {
        let response;
        try {
          response = decode("SyncResponse", Buffer.concat(chunks));
        } catch (err) {
          log.warn(`Sync: failed to decode response (${Buffer.concat(chunks).length} bytes): ${err.message}`);
          return { imported: 0, fromRound, toRound: fromRound, peerLatestRound: 0 };
        }

        peerLatestRound = response.latestRound || 0;

        for (const certData of (response.certificates || [])) {
          try {
            const cert = _deserializeCertFromSync(certData);
            if (!dag.getCertificate(cert.hash)) {
              dag.saveCertificate(cert);
              imported++;
              if (cert.round > maxRound) maxRound = cert.round;
            }
          } catch (err) {
            log.warn(`Sync: failed to import certificate: ${err.message}`);
          }
        }

        // Rebuild merkle once for the whole batch — deterministic from DAG state.
        if (imported > 0) _merkle = _buildMerkleFromDAG();
      }

      log.info(`Sync: imported ${imported} certificates (up to round ${maxRound}, peer latest: ${peerLatestRound})`);
      return { imported, fromRound, toRound: maxRound, peerLatestRound };
    } catch (err) {
      throw new Error(`Sync stream error with ${peerId.slice(0, 12)}: ${err.message}`);
    } finally {
      try { stream.close(); } catch { /* ignore */ }
    }
  }

  // ── Serialization helpers ────────────────────────────────────────────────

  function _serializeCertForSync(cert) {
    return {
      round: cert.round,
      authorNodeId: cert.author_node_id,
      batch: {
        round: cert.batch?.round || cert.round,
        authorNodeId: cert.batch?.author_node_id || cert.author_node_id,
        txs: (cert.batch?.txs || []).map(tx => ({
          txId: tx.tx_id || "",
          txType: tx.tx_type || "",
          timestamp: tx.timestamp || "",
          prev: tx.prev || [],
          data: Buffer.from(JSON.stringify(tx.data || {})),
          signature: hexToBytes(tx.signature),
        })),
        signature: hexToBytes(cert.batch?.signature),
        hash: hexToBytes(cert.batch?.hash),
      },
      acknowledgments: (cert.acknowledgments || []).map(a => ({
        batchHash: hexToBytes(a.batch_hash),
        ackerNodeId: a.acker_node_id || "",
        signature: hexToBytes(a.signature),
      })),
      parentHashes: (cert.parent_hashes || []).map(h => hexToBytes(h)),
      signature: hexToBytes(cert.signature),
      hash: hexToBytes(cert.hash),
    };
  }

  function _deserializeCertFromSync(msg) {
    if (!msg) return null;
    return {
      round: msg.round || 0,
      author_node_id: msg.authorNodeId || "",
      batch: {
        round: msg.batch?.round || 0,
        author_node_id: msg.batch?.authorNodeId || "",
        txs: (msg.batch?.txs || []).map(tx => ({
          tx_id: tx.txId || "",
          tx_type: tx.txType || "",
          timestamp: tx.timestamp || "",
          prev: tx.prev || [],
          data: tx.data?.length ? (() => { try { return JSON.parse(bytesToUtf8(tx.data)); } catch { return {}; } })() : {},
          signature: bytesToHex(tx.signature),
        })),
        signature: bytesToHex(msg.batch?.signature),
        hash: bytesToHex(msg.batch?.hash),
      },
      acknowledgments: (msg.acknowledgments || []).map(a => ({
        batch_hash: bytesToHex(a.batchHash) || "",
        acker_node_id: a.ackerNodeId || "",
        signature: bytesToHex(a.signature) || "",
      })),
      parent_hashes: (msg.parentHashes || []).map(h => bytesToHex(h)).filter(Boolean),
      signature: bytesToHex(msg.signature),
      hash: bytesToHex(msg.hash),
    };
  }

  return {
    registerProtocol,
    syncFromPeer,
    onCertificateCommitted,
    merkleRoot,
    merkleTree: _merkle,
    SYNC_PROTOCOL,
  };
}

module.exports = { createSyncHandler };
