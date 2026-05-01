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

const { mldsaVerify, canonicalJson, shake256 } = require("../../../shared/crypto");
const { NETWORK } = require("../../../shared/protocol-constants");
const { computeQuorum } = require("../consensus/certificate");
const { createStateRootBuilder } = require("../consensus/state-root");
const {
  createTxsFullRootBuilder,
  createCommitsFullRootBuilder,
  createRotationsFullRootBuilder,
  canonTx,
  canonCommit,
  canonRotation,
} = require("./snapshot-roots");
const { getGenesisPayload } = require("../genesis");
const { encode, decode, bytesToHex, hexToBytes, bytesToUtf8 } = require("../network/proto");
const { frame: _frame, parseLengthPrefixedFrames: _parseLengthPrefixedFrames } = require("../network/framing");
const { getLogger } = require("../logger");

const log = getLogger("tip.snapshot");

// Genesis-defined protocol id for the state-snapshot protocol.
// Safe at module load: PC.init() runs before any application module
// is required (see node/src/index.js boot order).
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
function createSnapshotHandler({ dag, network, isAuthorizedPeer = () => false, bullshark = null }) {

  // ── #49 full-history frame helpers ───────────────────────────────────────
  // Shared by sender (tx + commit phases) and receiver (tx + commit phases).
  // The state phase has a different shape (each row carries `table`) and
  // doesn't share these — see Phase A in both directions for that.

  /**
   * Sender helper: hash one canonical-JSON row into the full-root builder
   * and return the wire-framed encoded body. Used inside the streaming
   * generator for SnapshotTxRow and SnapshotCommitRow.
   */
  function _frameFullHistoryRow(frameType, canonical, rootBuilder) {
    rootBuilder.addRow(canonical);
    return _frame(encode(frameType, {
      canonicalJson: Buffer.from(canonical, "utf8"),
    }));
  }

  /**
   * Receiver helper: decode each frame, verify the canonical bytes are
   * present, hash into the full-root builder, JSON-parse for the install
   * queue. Throws with a clear label if any frame is malformed.
   */
  function _decodeFullHistoryFrames(frames, frameType, rootBuilder, label) {
    const queue = [];
    for (const frame of frames) {
      const row = decode(frameType, frame);
      if (!row.canonicalJson) throw new Error(`malformed ${frameType}`);
      const canonical = bytesToUtf8(row.canonicalJson);
      rootBuilder.addRow(canonical);
      let parsed;
      try { parsed = JSON.parse(canonical); }
      catch (err) { throw new Error(`${label} canonical_json parse failed: ${err.message}`); }
      queue.push(parsed);
    }
    return queue;
  }

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
    // payload each ack signed: "ack:${batch_hash}:${signer}".
    //
    // #50: prefer the value stored directly on the commit row (every
    // commit written by post-#50 nodes has it). This makes serving
    // independent of cert GC — idle federations whose latest commit
    // drifts past gc_depth rounds can still serve snapshots because
    // the value is in the row, not behind a cert lookup.
    //
    // Fallback to cert lookup for rows written by pre-#50 nodes whose
    // anchor_batch_hash column is null. Those rows still work as long
    // as cert GC hasn't run yet (typical for fresh federations); once
    // GC runs, the lookup returns null and serving will fail with the
    // correct error rather than silently bypass the verification step.
    let anchorBatchHash = latest.anchor_batch_hash || "";
    if (!anchorBatchHash) {
      try {
        const anchorCert = dag.getCertificate(latest.anchor_cert_hash);
        anchorBatchHash = anchorCert?.batch?.hash || "";
      } catch (err) {
        log.warn(`Snapshot: failed to read anchor cert ${latest.anchor_cert_hash.slice(0, 16)}: ${err.message}`);
      }
    }

    // Peer's bullshark.lastCommittedRound at serve time. Falls back to
    // the latest commit's round when bullshark isn't wired (legacy
    // tests / out-of-process callers). Joiner uses this to advance its
    // OWN bullshark counter past the snapshot anchor when the network
    // has been idle since the last tx-bearing commit.
    const peerCommittedRound = (bullshark && typeof bullshark.lastCommittedRound === "function")
      ? Number(bullshark.lastCommittedRound() || 0)
      : Number(latest.round || 0);

    // Peer's bullshark consensusIndex at serve time. Joiner adopts this
    // so all in-sync nodes show the same network-wide anchor count
    // (Cosmos/Sui/Aptos pattern), instead of each node tracking its own
    // local-since-restart counter. Falls back to the latest commit
    // row's consensus_index for legacy tests without a wired bullshark.
    const peerConsensusIndex = (bullshark && typeof bullshark.stats === "function")
      ? Number((bullshark.stats() || {}).consensusIndex || 0)
      : Number(latest.consensus_index || 0);

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
      peerCommittedRound,
      peerConsensusIndex,
      // BFT-Time fields — joiner needs `ack_signed_ats` to reconstruct each
      // ack's signed payload (`ack:${batch_hash}:${signer}:${signed_at}`).
      // `cert_timestamp` is the canonical consensus wall-clock for this
      // anchor (median of acks.signed_at).
      ackSignedAts: latest.ack_signed_ats || [],
      certTimestamp: latest.cert_timestamp || 0,
    });

    // Stream header + state rows + tx rows + commit rows + end marker in a
    // single sink call. Async generator yields frames as they're produced so
    // libp2p flushes incrementally (no full-state materialisation on the
    // sender). The two #49 full-history roots are stream-computed while
    // emitting rows and shipped in SnapshotEnd — single pass over each table.
    let stateRowsSent = 0;
    let txRowsSent = 0;
    let commitRowsSent = 0;
    let rotationRowsSent = 0;
    let txsFullRoot = "";
    let commitsFullRoot = "";
    let rotationsFullRoot = "";
    try {
      await stream.sink((async function* () {
        yield _frame(headerBuf);

        // Phase A: derived state (existing — covered by state_merkle_root).
        for (const { table, row } of dag.iterateCanonicalState()) {
          const rowBuf = encode("SnapshotStateRow", {
            table,
            canonicalJson: Buffer.from(canonicalJson(row), "utf8"),
          });
          yield _frame(rowBuf);
          stateRowsSent++;
        }

        // Phase B: full transactions table (#49). Source has every tx ever
        // (no GC). canonicalJson(canonTx(tx)) is the byte form both sides
        // hash and store in SnapshotTxRow.canonical_json.
        const txRoot = createTxsFullRootBuilder();
        for (const tx of dag.iterateAllTransactions()) {
          yield _frameFullHistoryRow("SnapshotTxRow", canonicalJson(canonTx(tx)), txRoot);
          txRowsSent++;
        }
        txsFullRoot = txRoot.finalize();

        // Phase C: commits history except latest (#49). Latest already
        // rides in SnapshotHeader — including it twice would double-count
        // in the receiver's commits table and break the install.
        const commitRoot = createCommitsFullRootBuilder();
        for (const c of dag.iterateAllCommitsExcept(latest.round)) {
          yield _frameFullHistoryRow("SnapshotCommitRow", canonicalJson(canonCommit(c)), commitRoot);
          commitRowsSent++;
        }
        commitsFullRoot = commitRoot.finalize();

        // Phase D: committee_history rotations (§4 + #34). Every rotation
        // since genesis, in rotation_number order. The joiner walks this
        // chain forward, anchored at LOCAL genesis founding_node, and
        // verifies each transition's sigs against the previously-trusted
        // committee.
        const rotationRoot = createRotationsFullRootBuilder();
        if (typeof dag.getRotationsFromGenesis === "function") {
          for (const r of dag.getRotationsFromGenesis()) {
            yield _frameFullHistoryRow("SnapshotCommitteeRotationRow",
              canonicalJson(canonRotation(r)), rotationRoot);
            rotationRowsSent++;
          }
        }
        rotationsFullRoot = rotationRoot.finalize();

        const endBuf = encode("SnapshotEnd", {
          rowCount: stateRowsSent,
          txRowCount: txRowsSent,
          commitRowCount: commitRowsSent,
          txsFullRoot: hexToBytes(txsFullRoot),
          commitsFullRoot: hexToBytes(commitsFullRoot),
          rotationRowCount: rotationRowsSent,
          rotationsFullRoot: hexToBytes(rotationsFullRoot),
        });
        yield _frame(endBuf);
      })());
    } catch (err) {
      log.warn(`Snapshot: stream write failed to ${remotePeer}: ${err.message}`);
      return;
    }

    log.info(
      `Snapshot: sent round ${latest.round} → ${remotePeer} ` +
      `(state=${stateRowsSent} txs=${txRowsSent} commits=${commitRowsSent} rotations=${rotationRowsSent})`
    );
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

      // Last frame is SnapshotEnd; middle frames are state rows then tx
      // rows then commit rows in that order. SnapshotEnd carries per-
      // stream counts AND the #49 stream-tampering integrity roots
      // (txs_full_root, commits_full_root) computed by the sender.
      if (frames.length < 2) throw new Error("response missing SnapshotEnd terminator");
      const endFrame = frames[frames.length - 1];
      const rowFrames = frames.slice(1, -1);

      const end = decode("SnapshotEnd", endFrame);
      const stateRowCount = Number(end.rowCount || 0);
      const txRowCount = Number(end.txRowCount || 0);
      const commitRowCount = Number(end.commitRowCount || 0);
      const rotationRowCount = Number(end.rotationRowCount || 0);
      const expectedTotal = stateRowCount + txRowCount + commitRowCount + rotationRowCount;
      if (expectedTotal !== rowFrames.length) {
        throw new Error(
          `row count mismatch: end says state=${stateRowCount} txs=${txRowCount} ` +
          `commits=${commitRowCount} rotations=${rotationRowCount} (total=${expectedTotal}), ` +
          `got ${rowFrames.length} frames`
        );
      }

      const stateFrames = rowFrames.slice(0, stateRowCount);
      const txFrames = rowFrames.slice(stateRowCount, stateRowCount + txRowCount);
      const commitFrames = rowFrames.slice(stateRowCount + txRowCount,
        stateRowCount + txRowCount + commitRowCount);
      const rotationFrames = rowFrames.slice(stateRowCount + txRowCount + commitRowCount);

      // ── Phase A: derived state ───────────────────────────────────────
      // Different shape from B/C (carries a `table` field) so doesn't use
      // the shared helper. Collects node public keys for ack verification.
      const stateRoot = createStateRootBuilder();
      const nodePubKeys = new Map();           // node_id → public_key (hex)
      const stateInstallQueue = [];            // { table, row } for the install
      for (const frame of stateFrames) {
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
        stateInstallQueue.push({ table, row: parsed });
      }

      // ── Phase B / C: full tx + commit history (#49) ──────────────────
      const txsRoot = createTxsFullRootBuilder();
      const txInstallQueue = _decodeFullHistoryFrames(txFrames, "SnapshotTxRow", txsRoot, "tx");

      const commitsRoot = createCommitsFullRootBuilder();
      const commitInstallQueue = _decodeFullHistoryFrames(commitFrames, "SnapshotCommitRow", commitsRoot, "commit");

      // ── Root matches ──────────────────────────────────────────────────
      // state_merkle_root is consensus state — signed by 2f+1 acks below.
      // txs_full_root / commits_full_root are wire-format integrity
      // checks shipped in SnapshotEnd; mismatch means the stream was
      // tampered with or truncated mid-row.
      const derivedState = stateRoot.finalize();
      const expectedState = bytesToHex(header.stateMerkleRoot);
      if (derivedState !== expectedState) {
        throw new Error(`state_merkle_root mismatch: expected ${expectedState?.slice(0, 16)}..., derived ${derivedState.slice(0, 16)}...`);
      }

      const derivedTxs = txsRoot.finalize();
      const expectedTxs = bytesToHex(end.txsFullRoot);
      if (derivedTxs !== expectedTxs) {
        throw new Error(`txs_full_root mismatch: expected ${expectedTxs?.slice(0, 16) || "<empty>"}..., derived ${derivedTxs.slice(0, 16)}...`);
      }

      const derivedCommits = commitsRoot.finalize();
      const expectedCommits = bytesToHex(end.commitsFullRoot);
      if (derivedCommits !== expectedCommits) {
        throw new Error(`commits_full_root mismatch: expected ${expectedCommits?.slice(0, 16) || "<empty>"}..., derived ${derivedCommits.slice(0, 16)}...`);
      }

      // ── Phase D: committee_history rotations (§4 + #34) ─────────────
      // Two-step verification:
      //   1. Wire integrity — rotations_full_root match (same shape as
      //      txs/commits roots, catches truncation/tampering of the stream)
      //   2. Cryptographic chain-of-trust — walk rotations forward from
      //      genesis, verify each transition's sigs come from the
      //      previously-trusted committee. Anchored at LOCAL genesis
      //      founding_node (NOT the peer-provided nodes table) — that's
      //      what closes the synthetic-snapshot attack.
      const rotationsRoot = createRotationsFullRootBuilder();
      const rotationInstallQueue = _decodeFullHistoryFrames(
        rotationFrames, "SnapshotCommitteeRotationRow", rotationsRoot, "rotation"
      );
      const derivedRotations = rotationsRoot.finalize();
      const expectedRotations = bytesToHex(end.rotationsFullRoot);
      if (derivedRotations !== expectedRotations) {
        throw new Error(
          `rotations_full_root mismatch: expected ${expectedRotations?.slice(0, 16) || "<empty>"}..., ` +
          `derived ${derivedRotations.slice(0, 16)}...`
        );
      }

      // Chain-of-trust walk. Anchor at LOCAL genesis (hardcoded in this
      // node's binary, NOT from the peer's snapshot). Then walk forward,
      // adopting each rotation's pubkeys ONLY after verifying its sigs
      // against the previously-trusted committee. Any broken link rejects
      // the entire snapshot. See validators/business-rules.canCommitteeRotation
      // for the predicate this mirrors at commit-time.
      //
      // Returns the verified-and-ordered rotation list so the ack-quorum
      // check below can look up signer pubkeys from the chain-anchored
      // committee (NOT the peer-provided nodes table) — closes the last
      // chicken-and-egg corner of fresh-joiner verification.
      const verifiedRotations = _verifyRotationChain(rotationInstallQueue);
      const chainPubkeysAtRound = _buildPubkeyLookup(verifiedRotations, Number(header.round));

      // ── Signature quorum ──────────────────────────────────────────────
      const anchorBatchHashHex = bytesToHex(header.anchorBatchHash);
      if (!anchorBatchHashHex) throw new Error("header missing anchor_batch_hash");
      const committee = header.committee || [];
      if (committee.length === 0) throw new Error("header missing committee");
      const quorum = computeQuorum(committee.length);
      const committeeSet = new Set(committee);

      const signerIds = header.ackSignerIds || [];
      const signatures = (header.ackSignatures || []).map(bytesToHex);
      // BFT-Time: each ack's signed_at is bound into the signature scope.
      // Parallel array — `signedAts[i]` corresponds to `signerIds[i]` and
      // `signatures[i]`. Coerce protobuf int64 (Long) → plain Number for
      // payload reconstruction.
      const signedAtsRaw = header.ackSignedAts || [];
      const signedAts = signedAtsRaw.map(v =>
        (typeof v === "object" && v !== null) ? Number(v.toString()) : Number(v || 0)
      );
      if (signerIds.length !== signatures.length) {
        throw new Error(`ack length mismatch: ${signerIds.length} signers vs ${signatures.length} sigs`);
      }
      if (signedAts.length !== signerIds.length) {
        throw new Error(`ack length mismatch: ${signerIds.length} signers vs ${signedAts.length} signed_ats — peer may be running pre-BFT-Time code`);
      }

      let validAcks = 0;
      const seen = new Set();
      for (let i = 0; i < signerIds.length; i++) {
        const signer = signerIds[i];
        if (seen.has(signer)) continue;          // no double-counting a signer
        if (!committeeSet.has(signer)) continue; // non-committee sig doesn't count toward quorum
        // Pubkey lookup prefers the CHAIN-ANCHORED committee (cryptographically
        // verified via _verifyRotationChain back to LOCAL genesis founding_node)
        // over the peer-provided nodes table. Empty chain (pre-§4 peer or
        // legacy snapshot) falls through to nodePubKeys for backwards compat —
        // those snapshots predate chain-of-trust and rely on the older trust
        // model (operator-managed bootstrap addresses + state_merkle_root).
        const pubKey = chainPubkeysAtRound.get(signer) || nodePubKeys.get(signer);
        if (!pubKey) continue;                   // no public key available — can't verify
        // Reconstructed payload mirrors `_ackSignPayload` in certificate.js.
        // Without `signed_at` the signature wouldn't verify (signature scope
        // covers the timestamp).
        const payload = `ack:${anchorBatchHashHex}:${signer}:${signedAts[i]}`;
        if (mldsaVerify(payload, signatures[i], pubKey)) {
          seen.add(signer);
          validAcks++;
        }
      }

      if (validAcks < quorum) {
        throw new Error(`insufficient ack quorum: ${validAcks}/${quorum} (committee=${committee.length})`);
      }

      // ── peer_committed_round validation ──────────────────────────────
      // peer_committed_round is peer's bullshark.lastCommittedRound at
      // serve time. Joiner advances its own bullshark counter to this
      // value after install — necessary because on idle networks the
      // latest commit row drifts far behind the live round (sparse).
      //
      // Sanity check: peer_committed_round >= snapshot.round. Peer
      // can't claim it's at a round older than its own latest commit.
      // (No need to also check "no commit in bundle > peer_committed_round"
      // — `dag.getLatestCommit()` is by construction the max-round row,
      // so any commit > peer_committed_round would already make
      // snapshot.round > peer_committed_round, tripping this same check.)
      //
      // State at peer_committed_round equals state at snapshot.round
      // because no NEW commit rows exist between them — the bundle
      // shipped every commit row up to and including the latest, the
      // joiner's commits_full_root verifies the bundle's integrity, and
      // 2f+1 acks attest the latest commit's state_merkle_root. Trust
      // chain: 2f+1 → latest commit's state → no later commits → state
      // unchanged through peer_committed_round.
      const snapshotRound = Number(header.round);
      const peerCommittedRound = Number(header.peerCommittedRound || 0);
      if (peerCommittedRound > 0 && peerCommittedRound < snapshotRound) {
        throw new Error(`peer_committed_round (${peerCommittedRound}) < snapshot round (${snapshotRound}) — peer is lying about its current state`);
      }

      // peer_consensus_index sanity: peer can't claim a smaller anchor
      // count than the snapshot's commit row already proves.
      const snapshotConsensusIndex = Number(header.consensusIndex || 0);
      const peerConsensusIndex = Number(header.peerConsensusIndex || 0);
      if (peerConsensusIndex > 0 && peerConsensusIndex < snapshotConsensusIndex) {
        throw new Error(`peer_consensus_index (${peerConsensusIndex}) < snapshot consensus_index (${snapshotConsensusIndex}) — peer is lying about its anchor count`);
      }

      // ── Install atomically ────────────────────────────────────────────
      const installed = _installSnapshot(header, {
        stateRows: stateInstallQueue,
        txs: txInstallQueue,
        commits: commitInstallQueue,
        rotations: rotationInstallQueue,
      });

      log.notice(
        `Snapshot: installed round=${header.round} consensus_index=${Number(header.consensusIndex || 0)} ` +
        `rows=${installed.state}/state ${installed.txs}/txs ${installed.commits}/commits ${installed.rotations}/rotations ` +
        `acks=${validAcks}/${committee.length} peer=${peerId.slice(0, 12)}`
      );

      return {
        round: Number(header.round),
        consensus_index: Number(header.consensusIndex || 0),
        // Peer's bullshark.lastCommittedRound at serve time — joiner's
        // peer-sync layer reads this and calls bullshark.markOrderedUpTo
        // so the joiner's committed_round counter aligns with peer's.
        // Without this advance, anti-entropy would falsely detect a
        // "behind by N rounds" gap on idle networks (latest commit row
        // far behind live round) and loop trying to pull non-existent
        // certs.
        peer_committed_round: peerCommittedRound,
        // Peer's bullshark counter at serve time — joiner's peer-sync
        // layer adopts this so all in-sync nodes share the same
        // network-wide anchor count. Without this, each node's
        // consensus_index drifts based on local restart history.
        peer_consensus_index: peerConsensusIndex,
        rows_installed: installed.state + installed.txs + installed.commits + installed.rotations,
        state_rows_installed: installed.state,
        tx_rows_installed: installed.txs,
        commit_rows_installed: installed.commits,
        rotation_rows_installed: installed.rotations,
        state_merkle_root: derivedState,
        txs_merkle_root: bytesToHex(header.txsMerkleRoot),
        txs_full_root: derivedTxs,
        commits_full_root: derivedCommits,
        rotations_full_root: derivedRotations,
      };
    } finally {
      try { stream.close(); } catch { /* ignore */ }
    }
  }

  function _installSnapshot(header, queues) {
    // Atomic install — every row, every tx, every commit, plus the
    // header's commit row land together or nothing does. Uses DAG's
    // public save* / addTx methods so write paths match normal
    // consensus application (column defaults, integer coercion, etc.).
    //
    // Order:
    //   1. Derived state rows (identities, content, nodes, etc.)
    //   2. Pre-snapshot transactions (#49 — addTx preserves prev:[] for
    //      genesis-style txs because its auto-fill is gated on tx_id
    //      being absent. verifyTxId runs as defense-in-depth behind the
    //      snapshot-layer txs_full_root. _updatePrev fires per-row;
    //      installing in tx_id-ascending order leaves _prev pointing at
    //      [highest, second-highest] — exactly the state a fresh
    //      bootstrap would compute, so the joiner's next submission
    //      chains off the installed history.)
    //   3. Pre-snapshot commits (#49 — every commit row except the
    //      latest, which is written from the header at the end)
    //   4. Header's commit row — the freshly-attested checkpoint
    return dag.runInTransaction(() => {
      let stateN = 0;
      for (const { table, row } of queues.stateRows) {
        _installOneRow(table, row);
        stateN++;
      }

      let txN = 0;
      for (const tx of queues.txs) {
        dag.addTx(tx);
        txN++;
      }

      let commitN = 0;
      for (const c of queues.commits) {
        dag.saveCommit(c);
        commitN++;
      }

      // §4 + #34: install committee_history rotations. Already verified
      // up the call chain (rotations_full_root match + chain-of-trust
      // walk). saveCommitteeRotation is INSERT OR IGNORE so re-running
      // an install is idempotent — the bootstrap rotation 0 from initDAG
      // and the snapshot's rotation 0 should be byte-identical (same
      // genesis founding_node), so no conflict. Subsequent rotations
      // land cleanly because the local DB had none beyond rotation 0
      // before this install.
      let rotationN = 0;
      const rotations = queues.rotations || [];
      for (const r of rotations) {
        dag.saveCommitteeRotation({
          ...r,
          // canonRotation strips committed_at — restore a deterministic
          // value here so the row passes its NOT NULL constraint. We use
          // the rotation's effective_round-derived label (informational
          // only — not in the canonical hash, not in chain-of-trust).
          committed_at: r.committed_at || `installed-from-snapshot:rotation-${r.rotation_number}`,
        });
        rotationN++;
      }

      // Header's commit row — the round whose state_merkle_root we just
      // verified against 2f+1 acks. Convert header bytes-fields back to
      // the hex/string shape dag.saveCommit expects.
      // BFT-Time fields — coerce protobuf int64 (Long) → plain Number for
      // each ack's signed_at and the cert.timestamp. Already validated
      // upstream via the ack signature quorum check (we wouldn't be here
      // otherwise).
      const _toInt = (v) => (typeof v === "object" && v !== null) ? Number(v.toString()) : Number(v || 0);
      const headerAckSignedAts = (header.ackSignedAts || []).map(_toInt);
      const headerCertTimestamp = _toInt(header.certTimestamp);

      // #50: persist the header's anchor_batch_hash on the joiner so the
      // latest commit row stays self-contained for any future snapshot
      // serve. Without this, once the underlying anchor cert is GC'd the
      // serve-time fallback at `_buildHeader` returns null and snapshot
      // serving from this node fails. Phase C commits already carry the
      // field via canonCommit; this closes the gap for the header row.
      const headerAnchorBatchHash = header.anchorBatchHash && header.anchorBatchHash.length
        ? bytesToHex(header.anchorBatchHash)
        : null;

      dag.saveCommit({
        round: Number(header.round),
        anchor_cert_hash: bytesToHex(header.anchorCertHash),
        anchor_batch_hash: headerAnchorBatchHash,
        leader_node_id: header.leaderNodeId,
        committee: header.committee || [],
        support_count: Number(header.supportCount || 0),
        consensus_index: Number(header.consensusIndex || 0),
        committed_at: header.committedAt,
        state_merkle_root: bytesToHex(header.stateMerkleRoot),
        txs_merkle_root: bytesToHex(header.txsMerkleRoot),
        ack_signer_ids: header.ackSignerIds || [],
        ack_signatures: (header.ackSignatures || []).map(bytesToHex),
        ack_signed_ats: headerAckSignedAts,
        cert_timestamp: headerCertTimestamp,
      });

      return { state: stateN, txs: txN, commits: commitN, rotations: rotationN };
    });
  }

  /**
   * §4 + #34 — chain-of-trust walk for incoming snapshot rotations.
   *
   * Anchored at LOCAL genesis founding_node (hardcoded in this node's
   * binary, NOT from the peer-controlled snapshot). Walks rotations in
   * rotation_number order:
   *   - Rotation 0: must match local genesis (founding_node + its pubkey),
   *     no signers/sigs (genesis IS the trust anchor).
   *   - Rotation N (N>=1): must have ≥ 2f+1 sigs from the previously-
   *     trusted committee, signed over `rotation:${payload_hash}:${signer}`.
   *     payload_hash is recomputed from the canonical claim and must match.
   *
   * Throws on any failure; the snapshot install is rejected atomically
   * before any state lands. This is the core defense against the
   * synthetic-snapshot attack — a fabricated chain breaks at rotation 1
   * because the attacker can't produce founding_node's signature.
   */
  function _verifyRotationChain(rotations) {
    if (!Array.isArray(rotations) || rotations.length === 0) {
      // No rotation chain shipped (peer is pre-§4, or empty federation
      // somehow). Allow for now — the peer's nodes table + state acks
      // are the prior trust mechanism and remain in effect for fields
      // covered by state_merkle_root. New federations using §4 always
      // ship at least rotation 0.
      log.debug("Snapshot: no committee_history rows shipped — skipping chain-of-trust walk");
      return [];
    }

    // Local trust anchor — read genesis founding_node from THIS node's
    // binary, not the snapshot. This is the cryptographic root that
    // breaks the chicken-and-egg in fresh-joiner verification.
    const genesisFounding = getGenesisPayload().founding_node;
    if (!genesisFounding || !genesisFounding.node_id || !genesisFounding.public_key) {
      throw new Error("local genesis missing founding_node — can't anchor chain-of-trust");
    }

    // Sort defensively — sender ships in rotation_number order, but we
    // verify the contract here so a misordered stream can't slip past.
    const ordered = [...rotations].sort((a, b) => a.rotation_number - b.rotation_number);

    let trustedPubkeys = Object.create(null);

    for (let i = 0; i < ordered.length; i++) {
      const rot = ordered[i];

      // Rotation_number contiguity. ordered[0] must be 0; each later
      // rotation must be exactly previous + 1. Same invariant
      // commit-handler enforces at write time; verifying it again here
      // catches a peer that omitted a rotation.
      if (i === 0 && rot.rotation_number !== 0) {
        throw new Error(`first rotation must be 0 (genesis), got ${rot.rotation_number}`);
      }
      if (i > 0 && rot.rotation_number !== ordered[i - 1].rotation_number + 1) {
        throw new Error(
          `rotation chain not contiguous: ${ordered[i - 1].rotation_number} → ${rot.rotation_number}`
        );
      }

      if (rot.rotation_number === 0) {
        // Genesis rotation. Must match LOCAL genesis byte-for-byte on
        // the security-critical fields (founding_node id + pubkey),
        // and must have no signers/sigs. prev_rotation must be null.
        if (rot.prev_rotation !== null) {
          throw new Error(`genesis rotation: prev_rotation must be null, got ${rot.prev_rotation}`);
        }
        if ((rot.signer_node_ids || []).length !== 0
            || (rot.signatures || []).length !== 0) {
          throw new Error("genesis rotation: must have no signers or signatures");
        }
        if (!Array.isArray(rot.committee) || rot.committee.length !== 1) {
          throw new Error(`genesis rotation: committee must be exactly [founding_node], got ${rot.committee?.length} entries`);
        }
        const m = rot.committee[0];
        if (!m || m.node_id !== genesisFounding.node_id || m.public_key !== genesisFounding.public_key) {
          throw new Error(
            `genesis rotation does not match LOCAL genesis founding_node — ` +
            `peer claimed ${m?.node_id?.slice(0, 24)}, local has ${genesisFounding.node_id.slice(0, 24)}`
          );
        }
        // Adopt genesis as the trust root.
        trustedPubkeys[m.node_id] = m.public_key;
        continue;
      }

      // Non-genesis rotation. Verify ≥ 2f+1 sigs from currently-trusted
      // committee. Reuses the exact predicate commit-handler runs at
      // write time, just over the trustedPubkeys we've built up rather
      // than dag.getCommitteeRotation(rn-1). This keeps both call sites
      // in lock-step on the security check.
      const expectedHash = shake256(canonicalJson({
        rotation_number: rot.rotation_number,
        effective_round: rot.effective_round,
        committee: rot.committee,
      }));
      if (rot.payload_hash !== expectedHash) {
        throw new Error(
          `rotation ${rot.rotation_number} payload_hash mismatch — recompute=${expectedHash.slice(0, 16)} ` +
          `claimed=${(rot.payload_hash || "").slice(0, 16)}`
        );
      }

      const signers = rot.signer_node_ids || [];
      const sigs = rot.signatures || [];
      if (signers.length === 0 || signers.length !== sigs.length) {
        throw new Error(
          `rotation ${rot.rotation_number}: signer_node_ids/signatures must be parallel non-empty (got ${signers.length}/${sigs.length})`
        );
      }

      let validSigs = 0;
      const seen = new Set();
      for (let j = 0; j < signers.length; j++) {
        const signerId = signers[j];
        if (seen.has(signerId)) continue;             // duplicate signers count once
        seen.add(signerId);
        const pubkey = trustedPubkeys[signerId];
        if (!pubkey) continue;                        // signer outside currently-trusted committee
        const message = `rotation:${rot.payload_hash}:${signerId}`;
        if (mldsaVerify(message, sigs[j], pubkey)) {
          validSigs++;
        }
      }

      const trustedSize = Object.keys(trustedPubkeys).length;
      const f = Math.floor((trustedSize - 1) / 3);
      const quorum = 2 * f + 1;
      if (validSigs < quorum) {
        throw new Error(
          `rotation ${rot.rotation_number}: insufficient sigs from previous committee — ` +
          `${validSigs}/${trustedSize} valid, need ${quorum}`
        );
      }

      // Adopt the new committee's pubkeys. These come from the rotation
      // tx itself (canonRotation.committee carries [{node_id, public_key}]),
      // NOT from the peer-provided nodes table. Each pubkey is endorsed
      // by 2f+1 sigs from the previously-trusted committee — the
      // cryptographic root of the chain-of-trust guarantee.
      trustedPubkeys = Object.create(null);
      for (const m of rot.committee) {
        if (m && m.node_id && m.public_key) {
          trustedPubkeys[m.node_id] = m.public_key;
        }
      }
    }

    log.debug(`Snapshot: chain-of-trust verified across ${ordered.length} rotations`);
    return ordered;
  }

  /**
   * Build a {node_id → public_key} lookup for the committee in effect at
   * `round`, drawn from the verified rotation chain. Returns the
   * committee from the latest rotation whose effective_round <= round.
   * Empty chain (pre-§4 peer) → empty map; caller falls back to other
   * pubkey sources.
   *
   * Used by ack-quorum verification on the snapshot header so signer
   * pubkeys come from the cryptographically-anchored chain rather than
   * the peer-provided nodes table.
   */
  function _buildPubkeyLookup(verifiedRotations, round) {
    const map = new Map();
    if (!Array.isArray(verifiedRotations) || verifiedRotations.length === 0) return map;
    let best = null;
    for (const r of verifiedRotations) {
      if (r.effective_round > round) continue;
      if (!best || r.rotation_number > best.rotation_number) best = r;
    }
    if (best) {
      for (const m of best.committee) {
        if (m && m.node_id && m.public_key) map.set(m.node_id, m.public_key);
      }
    }
    return map;
  }

  function _installOneRow(table, row) {
    switch (table) {
      case "identities":
        dag.saveIdentity(row);
        break;
      case "content":
        dag.saveContent(row);
        break;
      case "scores":
        // Row shape mirrors `_canonScore`: { tip_id, score, offense_count,
        // last_updated }. last_updated is sourced from `tx.timestamp` on
        // the sender so it's deterministic across nodes (#31).
        dag.setScore(row.tip_id, row.score, row.offense_count, row.last_updated);
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
    _verifyRotationChain,
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
