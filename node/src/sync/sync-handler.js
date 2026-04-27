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
const { frame, parseLengthPrefixedFrames } = require("../network/framing");
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
    // Debug: this rebuilds on every cert save and is chatty. Operators can
    // read the current root via /v1/stats or the merkleRoot() export.
    log.debug(`Merkle tree built: ${hashes.length} certificates, root: ${tree.root().slice(0, 16)}...`);
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
   * Handle an incoming sync request — stream certificates the peer is missing
   * as length-prefixed frames (§19).
   *
   * Wire format (response stream):
   *   [SyncResponseHeader][Certificate][Certificate]...[SyncResponseFooter]
   *
   * Streaming the body frame-by-frame (rather than encoding one giant
   * SyncResponse) eliminates the O(N) memory spike on the sender —
   * critical once the DAG gets large enough that the encoded aggregate
   * would approach or exceed 16 MB.
   */
  async function _handleIncomingSync(stream, remotePeer) {
    // Request is still a single unframed message — one-shot request path
    // matches snapshot-handler's convention.
    const reqChunks = [];
    for await (const chunk of stream.source) {
      reqChunks.push(chunk.subarray ? chunk.subarray() : chunk);
      break;
    }

    if (reqChunks.length === 0) {
      log.warn("Sync: received empty request");
      return;
    }

    let request;
    try {
      request = decode("SyncRequest", Buffer.concat(reqChunks));
    } catch (err) {
      log.warn(`Sync: failed to decode request: ${err.message}`);
      return;
    }

    const fromRound = request.fromRound || 1;
    const latestRound = dag.getLatestRound();

    log.info(`Sync: peer requested from round ${fromRound} (we have ${latestRound})`);

    // §2 cert GC interaction: if the joiner asks from a round we've already
    // pruned, cert replay would break on the first parent reference into the
    // pruned range. Respond with a header carrying snapshot_required and no
    // cert frames; joiner falls back to §14 snapshot sync.
    let earliestRound = 1;
    try {
      const e = dag.getEarliestCertRound();
      if (e > 0) earliestRound = e;
    } catch { /* earliestRound stays 1 */ }

    const currentMerkleRoot = merkleRoot();
    const snapshotRequired = fromRound < earliestRound;
    if (snapshotRequired) {
      log.info(`Sync: peer requested round ${fromRound} below GC horizon (earliest=${earliestRound}); signaling snapshot_required`);
      await _sendFramedResponse(stream, remotePeer, {
        header: {
          fromRound, toRound: fromRound, latestRound,
          merkleRoot: hexToBytes(currentMerkleRoot),
          snapshotRequired: true,
          earliestAvailableRound: earliestRound,
        },
        certsGenerator: null,
        footer: { certCount: 0, merkleRoot: hexToBytes(currentMerkleRoot) },
      });
      return;
    }

    // Happy path: stream header + one frame per cert + footer. Memory
    // consumption on the sender is bounded by a single Certificate's
    // protobuf encoding (few KB), not by total cert count.
    let certsSent = 0;
    await _sendFramedResponse(stream, remotePeer, {
      header: {
        fromRound, toRound: latestRound, latestRound,
        merkleRoot: hexToBytes(currentMerkleRoot),
        snapshotRequired: false,
        earliestAvailableRound: earliestRound,
      },
      certsGenerator: function* () {
        for (let r = fromRound; r <= latestRound; r++) {
          let certs;
          try { certs = dag.getCertificatesByRound(r); }
          catch (err) {
            log.warn(`Sync: failed to read round ${r}: ${err.message}`);
            continue;
          }
          for (const cert of certs) {
            yield cert;
            certsSent++;
          }
        }
      },
      // Footer is computed lazily so certsSent reflects actual emission.
      footer: () => ({ certCount: certsSent, merkleRoot: hexToBytes(currentMerkleRoot) }),
    });

    log.info(`Sync: sent ${certsSent} certificates (rounds ${fromRound}-${latestRound})`);
  }

  /**
   * Emit a framed sync response: header + optional cert-stream + footer.
   * Pulled out of _handleIncomingSync to keep the request-handling flow
   * readable and to make the frame sequence easy to test in isolation.
   *
   * @param stream                      libp2p stream
   * @param remotePeer                  peer ID for logging
   * @param opts.header                 SyncResponseHeader payload (camelCase field names)
   * @param opts.certsGenerator         optional generator<Certificate> — null if snapshot_required/error
   * @param opts.footer                 SyncResponseFooter payload, or () => payload for lazy construction
   */
  async function _sendFramedResponse(stream, remotePeer, { header, certsGenerator, footer }) {
    try {
      await stream.sink((async function* () {
        yield frame(encode("SyncResponseHeader", header));

        if (typeof certsGenerator === "function") {
          for (const cert of certsGenerator()) {
            yield frame(encode("Certificate", _serializeCertForSync(cert)));
          }
        }

        const footerPayload = typeof footer === "function" ? footer() : footer;
        yield frame(encode("SyncResponseFooter", footerPayload));
      })());
    } catch (err) {
      log.warn(`Sync: stream write failed to ${remotePeer}: ${err.message}`);
    }
  }

  /**
   * Request sync from a peer — pull certificates we're missing.
   *
   * @param {string} peerId               Remote peer ID
   * @param {Object} [opts]
   * @param {number} [opts.fromRound]     Override start round. Defaults to
   *   `dag.getLatestRound() + 1` (pull everything newer than our DAG). Callers
   *   who installed state via §14 snapshot sync pass `snapRound + 1` so we
   *   only fetch the catch-up gap instead of the whole chain from round 1.
   * @returns {Promise<{ imported: number, fromRound: number, toRound: number, peerLatestRound: number }>}
   */
  async function syncFromPeer(peerId, {
    fromRound: overrideFromRound,
    totalTimeoutMs: overrideTimeoutMs,
    maxResponseBytes: overrideMaxBytes,
  } = {}) {
    if (!network) throw new Error("No network node");

    const fromRound = overrideFromRound != null ? overrideFromRound : dag.getLatestRound() + 1;
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

      // Read framed response: [Header][Cert]*[Footer]
      //
      // Safety limits:
      //   - Per-frame cap enforced by parseLengthPrefixedFrames (16 MB,
      //     from NETWORK.SNAPSHOT_MAX_FRAME_BYTES) — hostile peer can't
      //     send one giant frame.
      //   - Total-bytes cap enforced inline (CONSENSUS.SYNC_MAX_RESPONSE_BYTES,
      //     default 1 GB) — hostile peer can't drip-feed infinite small
      //     frames until our heap dies.
      //   - Overall timeout wraps the whole read via Promise.race
      //     (CONSENSUS.SYNC_TOTAL_TIMEOUT_MS, default 30s) — hanging
      //     peer can't block the caller forever.
      // Constants default to genesis values but can be overridden per-call
      // for tests and ops-emergency shrinks (e.g. tightening the cap while
      // investigating a runaway sync from a misbehaving peer). Tests use
      // small values to exercise the cap/timeout paths in <1s.
      const maxResponseBytes = overrideMaxBytes != null ? overrideMaxBytes : CONSENSUS.SYNC_MAX_RESPONSE_BYTES;
      const totalTimeoutMs = overrideTimeoutMs != null ? overrideTimeoutMs : CONSENSUS.SYNC_TOTAL_TIMEOUT_MS;

      const readPromise = (async () => {
        const chunks = [];
        let total = 0;
        for await (const chunk of stream.source) {
          const c = chunk.subarray ? chunk.subarray() : chunk;
          total += c.length;
          if (total > maxResponseBytes) {
            throw new Error(`response exceeded max bytes: ${total} > ${maxResponseBytes}`);
          }
          chunks.push(c);
        }
        return chunks;
      })();

      let timeoutHandle;
      const timeoutPromise = new Promise((_resolve, reject) => {
        timeoutHandle = setTimeout(() => {
          try { stream.close(); } catch { /* ignore — forces the for-await above to end */ }
          reject(new Error(`sync timeout after ${totalTimeoutMs}ms`));
        }, totalTimeoutMs);
      });

      let chunks;
      try {
        chunks = await Promise.race([readPromise, timeoutPromise]);
      } catch (err) {
        clearTimeout(timeoutHandle);
        log.warn(`Sync: read failed from ${peerId.slice(0, 12)}: ${err.message}`);
        return { imported: 0, fromRound, toRound: fromRound, peerLatestRound: 0 };
      }
      clearTimeout(timeoutHandle);

      if (chunks.length === 0) {
        log.warn(`Sync: empty response from peer ${peerId.slice(0, 12)}`);
        return { imported: 0, fromRound, toRound: fromRound, peerLatestRound: 0 };
      }

      let frames;
      try {
        frames = parseLengthPrefixedFrames(Buffer.concat(chunks));
      } catch (err) {
        log.warn(`Sync: framing parse failed from ${peerId.slice(0, 12)}: ${err.message}`);
        return { imported: 0, fromRound, toRound: fromRound, peerLatestRound: 0 };
      }

      if (frames.length < 2) {
        log.warn(`Sync: response missing header+footer (got ${frames.length} frames)`);
        return { imported: 0, fromRound, toRound: fromRound, peerLatestRound: 0 };
      }

      // Decode header.
      let header;
      try { header = decode("SyncResponseHeader", frames[0]); }
      catch (err) {
        log.warn(`Sync: header decode failed: ${err.message}`);
        return { imported: 0, fromRound, toRound: fromRound, peerLatestRound: 0 };
      }

      if (header.error) {
        log.warn(`Sync: peer ${peerId.slice(0, 12)} returned error: ${header.error}`);
        return { imported: 0, fromRound, toRound: fromRound, peerLatestRound: Number(header.latestRound || 0), error: header.error };
      }

      const peerLatestRound = Number(header.latestRound || 0);

      // §2 cert GC: peer can't serve our requested range because it's
      // below their GC horizon. Joiner falls back to §14 snapshot sync.
      if (header.snapshotRequired) {
        log.info(`Sync: peer ${peerId.slice(0, 12)} signals snapshot_required (earliest available: ${Number(header.earliestAvailableRound || 0)}); falling back to snapshot sync`);
        return {
          imported: 0,
          fromRound,
          toRound: fromRound,
          peerLatestRound,
          snapshotRequired: true,
          earliestAvailableRound: Number(header.earliestAvailableRound || 0),
        };
      }

      // Decode footer (always the last frame). Everything between header
      // and footer should be Certificate frames.
      let footer;
      try { footer = decode("SyncResponseFooter", frames[frames.length - 1]); }
      catch (err) {
        log.warn(`Sync: footer decode failed: ${err.message}`);
        return { imported: 0, fromRound, toRound: fromRound, peerLatestRound };
      }

      const certFrames = frames.slice(1, -1);
      const declaredCount = Number(footer.certCount || 0);
      if (declaredCount !== certFrames.length) {
        // Silent-truncation guard: if the peer's footer disagrees with
        // what we received, something ate frames on the wire. Reject
        // the whole response rather than import a partial set.
        log.warn(`Sync: cert count mismatch from ${peerId.slice(0, 12)} — footer says ${declaredCount}, received ${certFrames.length}`);
        return { imported: 0, fromRound, toRound: fromRound, peerLatestRound };
      }

      let imported = 0;
      let maxRound = fromRound;
      for (const certFrame of certFrames) {
        try {
          const msg = decode("Certificate", certFrame);
          const cert = _deserializeCertFromSync(msg);
          if (!cert || !cert.hash) continue;
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

      log.info(`Sync: imported ${imported}/${certFrames.length} certificates (up to round ${maxRound}, peer latest: ${peerLatestRound})`);
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
    // Exposed for tests and for ops replay: run the server-side handler
    // against an arbitrary stream pair. Production paths always reach it
    // via libp2p's handle() callback installed in registerProtocol.
    handleIncomingSync: _handleIncomingSync,
  };
}

module.exports = { createSyncHandler };
