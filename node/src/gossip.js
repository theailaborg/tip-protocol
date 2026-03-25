/**
 * @file @tip-protocol/node/src/gossip.js
 * @description WebSocket gossip layer for federated DAG propagation.
 *
 * Protocol:
 *   - Each node connects to its configured peers over WebSocket
 *   - New transactions are broadcast to all connected peers
 *   - Peers relay unknown transactions forward (2-hop TTL)
 *   - Sync requests pull missing transactions by timestamp range
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const crypto                 = require("crypto");
const WebSocket              = require("ws");
const { validateTransaction } = require("./validators/tx-validator");
const { TX_TYPES }           = require("../../shared/constants");
const { mldsaVerify, mldsaSign, verifyBodySignature, canonicalTx } = require("../../shared/crypto");
const { log }                = require("./logger");

// ─── Verify body signature on incoming tx ────────────────────────────────────
// Each tx type has a known signer and signed fields. Returns true if valid,
// false if verification fails. Skips txs where verification isn't possible.
function verifyIncomingTx(tx, dag) {
  const d = tx.data || {};
  const tt = tx.tx_type;

  try {
    if (tt === TX_TYPES.REGISTER_CONTENT) {
      const identity = dag.getIdentity(d.author_tip_id);
      if (!identity || !d.signature) return true; // can't verify — accept
      return verifyBodySignature(d, d.signature, identity.public_key,
        ["author_tip_id", "origin_code", "content", "content_hash"]);
    }

    if (tt === TX_TYPES.REGISTER_IDENTITY) {
      const vp = dag.getVP(d.vp_id);
      if (!vp || !d.vp_signature) return true;
      return verifyBodySignature(d, d.vp_signature, vp.public_key,
        ["region", "dedup_hash", "zk_proof", "verification_tier", "vp_id", "social_attested"]);
    }

    if (tt === TX_TYPES.CONTENT_VERIFIED) {
      const verifier = dag.getIdentity(d.verifier_tip_id);
      if (!verifier || !d.signature) return true;
      return verifyBodySignature(d, d.signature, verifier.public_key,
        ["verifier_tip_id", "verdict"]);
    }

    if (tt === TX_TYPES.CONTENT_DISPUTED) {
      if (d.auto) {
        // Auto dispute — verify node signature
        const node = dag.getNode(d.node_id);
        if (!node || !tx.signature) return true;
        return mldsaVerify(canonicalTx(tx), tx.signature, node.public_key);
      }
      const disputer = dag.getIdentity(d.disputer_tip_id);
      if (!disputer || !d.signature) return true;
      return verifyBodySignature(d, d.signature, disputer.public_key,
        ["disputer_tip_id", "reason", "evidence_hash"]);
    }

    if (tt === TX_TYPES.REVOKE_VOLUNTARY || tt === TX_TYPES.REVOKE_VP ||
        tt === TX_TYPES.REVOKE_DECEASED || tt === TX_TYPES.REVOKE_DEVICE) {
      const vp = dag.getVP(d.issuing_vp_id);
      if (!vp || !d.signature) return true;
      return verifyBodySignature(d, d.signature, vp.public_key,
        ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"]);
    }

    if (tt === TX_TYPES.VP_REGISTERED) {
      const vp = dag.getVP(d.approving_vp_id);
      if (!vp || !d.council_signature) return true;
      return verifyBodySignature(d, d.council_signature, vp.public_key,
        ["name", "jurisdiction_tier", "public_key", "approving_vp_id"]);
    }

    if (tt === TX_TYPES.NODE_REGISTERED) {
      const vp = dag.getVP(d.approving_vp_id);
      if (!vp || !d.council_signature) return true;
      return verifyBodySignature(d, d.council_signature, vp.public_key,
        ["name", "public_key", "approving_vp_id"]);
    }
  } catch (err) {
    log.warn(`Gossip: body sig verification error for ${tt}: ${err.message}`);
    return false;
  }

  return true; // unknown tx type — accept
}

const MSG_TYPES = {
  TX_BROADCAST:  "TX_BROADCAST",
  SYNC_REQUEST:  "SYNC_REQUEST",
  SYNC_RESPONSE: "SYNC_RESPONSE",
  HANDSHAKE:     "HANDSHAKE",
  CHALLENGE:     "CHALLENGE",
  CHALLENGE_RESPONSE: "CHALLENGE_RESPONSE",
  PING:          "PING",
  PONG:          "PONG",
};

// ─── Replay derived state from a synced tx ──────────────────────────────────
// When a tx arrives via gossip, only dag.addTx() is called. Derived tables
// (identities, content, dedup_registry, revocations) must be updated manually
// since the original API endpoint logic doesn't run during sync.
function replayDerivedState(dag, tx) {
  const d = tx.data || {};

  switch (tx.tx_type) {
    case TX_TYPES.REGISTER_IDENTITY:
      if (d.dedup_hash && !dag.hasDedupHash(d.dedup_hash)) {
        dag.addDedupHash(d.dedup_hash);
      }
      if (d.tip_id && !dag.getIdentity(d.tip_id)) {
        dag.saveIdentity({
          tip_id:          d.tip_id,
          region:          d.region || "US",
          public_key:      d.public_key || "",
          root_public_key: d.root_public_key || "",
          vp_id:           d.vp_id || "",
          verification_tier: d.verification_tier || "T1",
          founding:        d.founding || false,
          status:          "active",
          registered_at:   tx.timestamp,
          tx_id:           tx.tx_id,
        });
      }
      break;

    case TX_TYPES.REGISTER_CONTENT:
      if (d.ctid && !dag.getContent(d.ctid)) {
        dag.saveContent({
          ctid:            d.ctid,
          origin_code:     d.origin_code,
          content_hash:    d.content_hash,
          perceptual_hash: d.perceptual_hash || null,
          author_tip_id:   d.author_tip_id,
          status:          d.prescan_flagged ? "pending_review" : "verified",
          registered_at:   tx.timestamp,
          tx_id:           tx.tx_id,
        });
      }
      break;

    case TX_TYPES.REVOKE_VOLUNTARY:
    case TX_TYPES.REVOKE_VP:
    case TX_TYPES.REVOKE_DECEASED:
    case TX_TYPES.REVOKE_DEVICE:
      if (d.tip_id && !dag.isRevoked(d.tip_id)) {
        dag.addRevocation(d.tip_id, tx.tx_type, tx.timestamp, tx.tx_id);
      }
      break;

    case TX_TYPES.VP_REGISTERED:
      if (d.vp_id && !dag.getVP(d.vp_id)) {
        dag.saveVP({
          vp_id:             d.vp_id,
          name:              d.name || "",
          jurisdiction_tier: d.jurisdiction_tier || "green",
          public_key:        d.public_key || "",
          status:            "active",
          registered_at:     tx.timestamp,
        });
      }
      break;

    case TX_TYPES.NODE_REGISTERED:
      if (d.node_id && !dag.getNode(d.node_id)) {
        dag.saveNode({
          node_id:        d.node_id,
          name:           d.name || "",
          public_key:     d.public_key || "",
          status:         "active",
          registered_at:  tx.timestamp,
        });
      }
      break;
  }
}

function initGossip(server, dag, config) {
  const wss     = new WebSocket.Server({ server, path: "/gossip" });
  const peers   = new Map();    // nodeId -> { ws, authenticated }
  const seenTx  = new Set();    // dedup recently seen tx_ids
  const pendingChallenges = new Map(); // ws -> nonce

  // ── Incoming connections (from peers connecting to us) ──────────────────
  wss.on("connection", (ws, req) => {
    const remoteAddr = req.socket.remoteAddress;
    log.info(`Gossip: peer connected from ${remoteAddr}`);

    ws.on("message", data => {
      try {
        const msg = JSON.parse(data.toString());
        handleMessage(ws, msg);
      } catch (err) {
        log.warn(`Gossip: invalid message from ${remoteAddr}:`, err.message);
      }
    });

    ws.on("close", () => {
      log.info(`Gossip: peer disconnected (${remoteAddr})`);
      pendingChallenges.delete(ws);
      for (const [id, peer] of peers.entries()) {
        if (peer.ws === ws) peers.delete(id);
      }
    });

    ws.on("error", err => log.warn(`Gossip error (${remoteAddr}):`, err.message));

    // Send challenge nonce for authentication
    const nonce = crypto.randomBytes(32).toString("hex");
    pendingChallenges.set(ws, nonce);
    send(ws, { type: MSG_TYPES.CHALLENGE, nonce });
  });

  function handleMessage(ws, msg) {
    switch (msg.type) {
      case MSG_TYPES.CHALLENGE: {
        // We received a challenge from a peer we connected to — sign and respond
        if (msg.nonce && config.nodePrivateKey) {
          const nodeId = config.nodeRegisteredId || config.nodeId;
          send(ws, {
            type:      MSG_TYPES.CHALLENGE_RESPONSE,
            node_id:   nodeId,
            signature: mldsaSign(msg.nonce, config.nodePrivateKey),
          });
        }
        break;
      }

      case MSG_TYPES.CHALLENGE_RESPONSE: {
        // Peer responded to our challenge — verify against node registry
        const nonce = pendingChallenges.get(ws);
        if (!nonce || !msg.node_id || !msg.signature) {
          log.warn("Gossip: invalid challenge response — missing fields");
          break;
        }
        pendingChallenges.delete(ws);

        const registeredNode = dag.getNode(msg.node_id);
        if (registeredNode && mldsaVerify(nonce, msg.signature, registeredNode.public_key)) {
          peers.set(msg.node_id, { ws, authenticated: true });
          log.info(`Gossip: node ${msg.node_id} authenticated (registered)`);
          // Send sync request after auth
          const lastSeen = dag.getAllTxs().reduce((max, tx) => tx.timestamp > max ? tx.timestamp : max, "1970-01-01T00:00:00.000Z");
          send(ws, { type: MSG_TYPES.SYNC_REQUEST, since: lastSeen });
        } else {
          log.warn(`Gossip: node ${msg.node_id} rejected — not in registry or invalid signature`);
          ws.close(4001, "Node authentication failed");
        }
        break;
      }

      case MSG_TYPES.TX_BROADCAST:
        if (msg.tx && msg.tx.tx_id && !seenTx.has(msg.tx.tx_id)) {
          seenTx.add(msg.tx.tx_id);
          setTimeout(() => seenTx.delete(msg.tx.tx_id), 60_000); // TTL 60s
          const existing = dag.getTx(msg.tx.tx_id);
          if (!existing) {
            const result = validateTransaction(msg.tx, dag, { skipState: true });
            if (!result.valid) {
              log.warn(`Gossip: rejected tx ${msg.tx.tx_id} (${result.layer}): ${result.errors.join(", ")}`);
              break;
            }
            if (!verifyIncomingTx(msg.tx, dag)) {
              log.warn(`Gossip: rejected tx ${msg.tx.tx_id} — body signature verification failed`);
              break;
            }
            dag.addTx(msg.tx);
            replayDerivedState(dag, msg.tx);
            log.info(`Gossip: received tx ${msg.tx.tx_id} (${msg.tx.tx_type})`);
            if ((msg.ttl || 2) > 0) {
              broadcast(msg.tx, ws, (msg.ttl || 2) - 1);
            }
          }
        }
        break;

      case MSG_TYPES.SYNC_REQUEST:
        // Respond with all txs since requested timestamp
        const since = msg.since || "1970-01-01T00:00:00.000Z";
        const allTxs = dag.getAllTxs().filter(tx => tx.timestamp > since);
        send(ws, { type: MSG_TYPES.SYNC_RESPONSE, txs: allTxs, count: allTxs.length });
        break;

      case MSG_TYPES.SYNC_RESPONSE:
        if (Array.isArray(msg.txs)) {
          let imported = 0;
          for (const tx of msg.txs) {
            if (!dag.getTx(tx.tx_id)) {
              const result = validateTransaction(tx, dag, { skipState: true });
              if (!result.valid) {
                log.warn(`Gossip: rejected sync tx ${tx.tx_id} (${result.layer}): ${result.errors.join(", ")}`);
                continue;
              }
              if (!verifyIncomingTx(tx, dag)) {
                log.warn(`Gossip: rejected sync tx ${tx.tx_id} — body signature verification failed`);
                continue;
              }
              dag.addTx(tx);
              replayDerivedState(dag, tx);
              imported++;
            }
          }
          if (imported > 0) log.info(`Gossip: sync imported ${imported} transactions`);
        }
        break;

      case MSG_TYPES.PING:
        send(ws, { type: MSG_TYPES.PONG, timestamp: Date.now() });
        break;
    }
  }

  // ── Broadcast a new tx to all connected peers ─────────────────────────
  function broadcast(tx, excludeWs, ttl = 2) {
    const msg = JSON.stringify({ type: MSG_TYPES.TX_BROADCAST, tx, ttl });
    for (const [, peer] of peers.entries()) {
      if (peer.ws !== excludeWs && peer.ws.readyState === WebSocket.OPEN) {
        peer.ws.send(msg);
      }
    }
  }

  function send(ws, obj) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(obj));
    }
  }

  // ── Outbound connections to configured peer list ──────────────────────
  function connectToPeers() {
    for (const peerUrl of config.peers) {
      if (!peerUrl) continue;
      try {
        const ws = new WebSocket(`${peerUrl}/gossip`);
        ws.on("open", () => {
          log.info(`Gossip: connected to peer ${peerUrl}`);
          // Wait for challenge from peer (handled in handleMessage CHALLENGE case)
        });
        ws.on("message", data => {
          try { handleMessage(ws, JSON.parse(data.toString())); } catch {}
        });
        ws.on("error", err => log.warn(`Gossip peer ${peerUrl} error: ${err.message}`));
        ws.on("close", () => {
          log.info(`Gossip: peer ${peerUrl} disconnected, will retry`);
          setTimeout(() => connectToPeers(), 30_000);
        });
      } catch (err) {
        log.warn(`Gossip: could not connect to ${peerUrl}: ${err.message}`);
      }
    }
  }

  // Connect to peers after a short delay
  setTimeout(connectToPeers, 2000);

  return {
    broadcast,
    peerCount: () => peers.size,
  };
}

module.exports = { initGossip };
