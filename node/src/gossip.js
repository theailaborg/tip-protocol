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

const WebSocket     = require("ws");
const { TX_TYPES }  = require("../../shared/constants");
const { log }       = require("./logger");

const MSG_TYPES = {
  TX_BROADCAST:  "TX_BROADCAST",
  SYNC_REQUEST:  "SYNC_REQUEST",
  SYNC_RESPONSE: "SYNC_RESPONSE",
  HANDSHAKE:     "HANDSHAKE",
  PING:          "PING",
  PONG:          "PONG",
};

function initGossip(server, dag, config) {
  const wss     = new WebSocket.Server({ server, path: "/gossip" });
  const peers   = new Map();    // peerId -> WebSocket
  const seenTx  = new Set();    // dedup recently seen tx_ids

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
      for (const [id, peerWs] of peers.entries()) {
        if (peerWs === ws) peers.delete(id);
      }
    });

    ws.on("error", err => log.warn(`Gossip error (${remoteAddr}):`, err.message));

    // Send handshake
    send(ws, {
      type:       MSG_TYPES.HANDSHAKE,
      node_id:    config.nodeId,
      node_type:  config.nodeType,
      dag_count:  dag.count(),
      public_url: config.publicUrl,
      version:    "2.0.0",
    });
  });

  function handleMessage(ws, msg) {
    switch (msg.type) {
      case MSG_TYPES.HANDSHAKE:
        if (msg.node_id) {
          peers.set(msg.node_id, ws);
          log.info(`Gossip: handshake accepted from node ${msg.node_id}`);
        }
        break;

      case MSG_TYPES.TX_BROADCAST:
        if (msg.tx && msg.tx.tx_id && !seenTx.has(msg.tx.tx_id)) {
          seenTx.add(msg.tx.tx_id);
          setTimeout(() => seenTx.delete(msg.tx.tx_id), 60_000); // TTL 60s
          const existing = dag.getTx(msg.tx.tx_id);
          if (!existing) {
            dag.addTx(msg.tx);
            log.info(`Gossip: received tx ${msg.tx.tx_id} (${msg.tx.tx_type})`);
            // Relay to other peers (TTL = 1 more hop)
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
              dag.addTx(tx);
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
    for (const [, peerWs] of peers.entries()) {
      if (peerWs !== excludeWs && peerWs.readyState === WebSocket.OPEN) {
        peerWs.send(msg);
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
          // Handshake
          send(ws, { type: MSG_TYPES.HANDSHAKE, node_id: config.nodeId, node_type: config.nodeType, public_url: config.publicUrl });
          // Request sync
          const lastSeen = dag.getAllTxs().reduce((max, tx) => tx.timestamp > max ? tx.timestamp : max, "1970-01-01T00:00:00.000Z");
          send(ws, { type: MSG_TYPES.SYNC_REQUEST, since: lastSeen });
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
