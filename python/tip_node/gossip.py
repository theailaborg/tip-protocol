"""
node/gossip.py
TIP Protocol Python — WebSocket Peer Gossip Layer

# Author:    Dinesh Mendhe <chairman@theailab.org>
Handles DAG transaction propagation across the federated network.
Uses stdlib socket with a simple line-delimited JSON protocol.
Falls back gracefully when peers are unavailable.

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any

from tip_node.logger import get_logger
from tip_node.validators.tx_validator import validate_transaction

log = get_logger("gossip")

MSG_TX_BROADCAST  = "TX_BROADCAST"
MSG_HANDSHAKE     = "HANDSHAKE"
MSG_SYNC_REQUEST  = "SYNC_REQUEST"
MSG_SYNC_RESPONSE = "SYNC_RESPONSE"
MSG_PING          = "PING"
MSG_PONG          = "PONG"


class GossipServer:
    """
    Lightweight peer gossip over TCP with line-delimited JSON.
    Each message is a JSON object terminated by newline.
    """

    def __init__(self, dag, config: dict) -> None:
        self._dag      = dag
        self._config   = config
        self._peers:   dict[str, socket.socket] = {}  # node_id -> socket
        self._seen:    set  = set()
        self._lock     = threading.Lock()

        # Inbound server socket
        self._server_sock: socket.socket | None = None
        self._running = False

    def start(self, gossip_port: int | None = None) -> None:
        """Start gossip server (inbound) and connect to configured peers."""
        port = gossip_port or (self._config.get("port", 4000) + 1)

        self._running = True

        # Inbound listener
        threading.Thread(target=self._serve, args=(port,), daemon=True).start()
        log.info(f"Gossip server listening on port {port}")

        # Outbound connections (after a brief delay so the node is ready)
        threading.Thread(target=self._connect_all, daemon=True).start()

    def _serve(self, port: int) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(64)
            self._server_sock = srv
            while self._running:
                try:
                    srv.settimeout(1.0)
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=self._handle_peer, args=(conn, addr[0]),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception:
                    if self._running:
                        raise
        except Exception as exc:
            log.warning(f"Gossip server error: {exc}")

    def _handle_peer(self, conn: socket.socket, addr: str) -> None:
        log.info(f"Gossip: peer connected from {addr}")
        buf = b""
        try:
            while self._running:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        msg = json.loads(line.decode("utf-8"))
                        self._handle_msg(conn, msg)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            log.warning(f"Gossip peer error ({addr}): {exc}")
        finally:
            conn.close()
            with self._lock:
                for k, v in list(self._peers.items()):
                    if v is conn:
                        del self._peers[k]
                        break

    def _handle_msg(self, conn: socket.socket, msg: dict) -> None:
        mtype = msg.get("type")

        if mtype == MSG_HANDSHAKE:
            node_id = msg.get("node_id")
            if node_id:
                with self._lock:
                    self._peers[node_id] = conn
            # Send our handshake back
            self._send(conn, {
                "type":       MSG_HANDSHAKE,
                "node_id":    self._config["node_id"],
                "node_type":  self._config.get("node_type", "full"),
                "public_url": self._config.get("public_url", ""),
                "dag_count":  self._dag.count(),
            })

        elif mtype == MSG_TX_BROADCAST:
            tx  = msg.get("tx")
            ttl = msg.get("ttl", 2)
            if tx and tx.get("tx_id"):
                tx_id = tx["tx_id"]
                if tx_id not in self._seen:
                    with self._lock:
                        self._seen.add(tx_id)
                    if not self._dag.get_tx(tx_id):
                        result = validate_transaction(tx, self._dag, skip_crypto=True, skip_state=True)
                        if not result.valid:
                            log.warning(f"Gossip: rejected tx {tx_id[:16]}... ({result.layer}): {result.errors[0]}")
                        else:
                            self._dag.add_tx(tx)
                            log.debug(f"Gossip: imported tx {tx_id[:16]}... ({tx.get('tx_type')})")
                    if ttl > 0:
                        self._broadcast(tx, exclude=conn, ttl=ttl - 1)

        elif mtype == MSG_SYNC_REQUEST:
            since = msg.get("since", "1970-01-01")
            txs   = [t for t in self._dag.get_all_txs()
                     if t.get("timestamp", "") > since]
            self._send(conn, {
                "type":  MSG_SYNC_RESPONSE,
                "txs":   txs,
                "count": len(txs),
            })

        elif mtype == MSG_SYNC_RESPONSE:
            imported = 0
            for tx in msg.get("txs", []):
                if tx.get("tx_id") and not self._dag.get_tx(tx["tx_id"]):
                    result = validate_transaction(tx, self._dag, skip_crypto=True, skip_state=True)
                    if not result.valid:
                        log.warning(f"Gossip: rejected sync tx {tx['tx_id'][:16]}... ({result.layer}): {result.errors[0]}")
                        continue
                    self._dag.add_tx(tx)
                    imported += 1
            if imported:
                log.info(f"Gossip: sync imported {imported} transactions")

        elif mtype == MSG_PING:
            self._send(conn, {"type": MSG_PONG, "ts": time.time()})

    def _send(self, conn: socket.socket, obj: dict) -> None:
        try:
            conn.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        except (BrokenPipeError, OSError):
            pass

    def _broadcast(self, tx: dict, exclude: socket.socket | None = None, ttl: int = 2) -> None:
        msg = json.dumps({"type": MSG_TX_BROADCAST, "tx": tx, "ttl": ttl}) + "\n"
        data = msg.encode("utf-8")
        with self._lock:
            for sock in list(self._peers.values()):
                if sock is not exclude:
                    try:
                        sock.sendall(data)
                    except (BrokenPipeError, OSError):
                        pass

    def broadcast_tx(self, tx: dict) -> None:
        """Called by the node when a new tx is added locally."""
        self._broadcast(tx, ttl=2)

    def _connect_all(self) -> None:
        time.sleep(2)  # wait for node to start
        for peer_url in self._config.get("peers", []):
            self._connect_peer(peer_url)

    def _connect_peer(self, peer_url: str) -> None:
        """Connect to a peer and start sync."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(peer_url)
            host   = parsed.hostname or "127.0.0.1"
            port   = (parsed.port or 4000) + 1  # gossip port = API port + 1

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((host, port))
            sock.settimeout(None)

            log.info(f"Gossip: connected to peer {peer_url}")

            # Send handshake
            self._send(sock, {
                "type":       MSG_HANDSHAKE,
                "node_id":    self._config["node_id"],
                "node_type":  self._config.get("node_type", "full"),
                "public_url": self._config.get("public_url", ""),
            })

            # Request sync
            last_ts = max(
                (t.get("timestamp", "") for t in self._dag.get_all_txs()),
                default="1970-01-01",
            )
            self._send(sock, {"type": MSG_SYNC_REQUEST, "since": last_ts})

            # Start listening thread for this peer
            threading.Thread(
                target=self._handle_peer, args=(sock, peer_url),
                daemon=True
            ).start()

        except Exception as exc:
            log.warning(f"Gossip: could not connect to {peer_url}: {exc}")
            # Retry after 30s
            threading.Timer(30.0, self._connect_peer, args=(peer_url,)).start()

    def peer_count(self) -> int:
        with self._lock:
            return len(self._peers)

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
