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
from shared.constants import TxType

log = get_logger("gossip")

def _replay_derived_state(dag, tx: dict) -> None:
    """Update derived tables (identities, content, dedup, revocations, VPs)
    when a tx arrives via gossip. The original API endpoint logic does not run
    during sync, so derived state must be replayed manually."""
    d = tx.get("data") or {}
    tt = tx.get("tx_type", "")

    if tt == TxType.REGISTER_IDENTITY:
        dh = d.get("dedup_hash")
        if dh and not dag.has_dedup_hash(dh):
            dag.add_dedup_hash(dh)
        tid = d.get("tip_id")
        if tid and not dag.get_identity(tid):
            dag.save_identity({
                "tip_id":            tid,
                "region":            d.get("region", "US"),
                "public_key":        d.get("public_key", ""),
                "root_public_key":   d.get("root_public_key", ""),
                "vp_id":             d.get("vp_id", ""),
                "verification_tier": d.get("verification_tier", "T1"),
                "founding":          d.get("founding", False),
                "status":            "active",
                "registered_at":     tx.get("timestamp", ""),
                "creator_name":      d.get("creator_name"),
                "tx_id":             tx.get("tx_id", ""),
            })

    elif tt == TxType.REGISTER_CONTENT:
        ctid = d.get("ctid")
        if ctid and not dag.get_content(ctid):
            dag.save_content({
                "ctid":            ctid,
                "origin_code":     d.get("origin_code"),
                "content_hash":    d.get("content_hash"),
                "perceptual_hash": d.get("perceptual_hash"),
                "author_tip_id":   d.get("author_tip_id"),
                "status":          "pending_review" if d.get("prescan_flagged") else "verified",
                "registered_at":   tx.get("timestamp", ""),
                "registered_url":  d.get("registered_url"),
                "tx_id":           tx.get("tx_id", ""),
            })

    elif tt in (TxType.REVOKE_VOLUNTARY, TxType.REVOKE_VP,
                TxType.REVOKE_DECEASED, TxType.REVOKE_DEVICE):
        tid = d.get("tip_id")
        if tid and not dag.is_revoked(tid):
            dag.add_revocation(tid, tt, tx.get("timestamp", ""), tx.get("tx_id", ""))

    elif tt == TxType.VP_REGISTERED:
        vp_id = d.get("vp_id")
        if vp_id and not dag.get_vp(vp_id):
            dag.save_vp({
                "vp_id":             vp_id,
                "name":              d.get("name", ""),
                "jurisdiction_tier": d.get("jurisdiction_tier", "green"),
                "public_key":        d.get("public_key", ""),
                "status":            "active",
                "registered_at":     tx.get("timestamp", ""),
            })

    elif tt == TxType.NODE_REGISTERED:
        node_id = d.get("node_id")
        if node_id and not dag.get_node(node_id):
            dag.save_node({
                "node_id":        node_id,
                "name":           d.get("name", ""),
                "public_key":     d.get("public_key", ""),
                "status":         "active",
                "registered_at":  tx.get("timestamp", ""),
            })


def _verify_incoming_tx(tx: dict, dag) -> bool:
    """Verify body signature on incoming gossip tx. Returns True if valid or unverifiable."""
    from shared.crypto import verify_body_signature, mldsa_verify, canonical_tx
    d = tx.get("data") or {}
    tt = tx.get("tx_type", "")

    try:
        if tt == TxType.REGISTER_CONTENT:
            identity = dag.get_identity(d.get("author_tip_id", ""))
            if not identity or not d.get("signature"): return True
            # Field list must match what the author signed: registered_url is
            # included only when it was provided at registration time.
            fields = (["author_tip_id", "origin_code", "content_hash", "registered_url"]
                      if d.get("registered_url")
                      else ["author_tip_id", "origin_code", "content_hash"])
            return verify_body_signature(d, d["signature"], identity["public_key"], fields)

        if tt == TxType.REGISTER_IDENTITY:
            vp = dag.get_vp(d.get("vp_id", ""))
            if not vp or not d.get("vp_signature"): return True
            # Field list must match what the VP signed: creator_name is
            # included only when it was provided at registration time.
            base = ["region", "public_key", "dedup_hash", "zk_proof",
                    "verification_tier", "vp_id", "social_attested"]
            fields = base + ["creator_name"] if d.get("creator_name") else base
            return verify_body_signature(d, d["vp_signature"], vp["public_key"], fields)

        if tt == TxType.CONTENT_VERIFIED:
            verifier = dag.get_identity(d.get("verifier_tip_id", ""))
            if not verifier or not d.get("signature"): return True
            return verify_body_signature(d, d["signature"], verifier["public_key"],
                ["verifier_tip_id", "verdict"])

        if tt == TxType.CONTENT_DISPUTED:
            if d.get("auto"):
                node = dag.get_node(d.get("node_id", ""))
                if not node or not tx.get("signature"): return True
                return mldsa_verify(canonical_tx(tx), tx["signature"], node["public_key"])
            disputer = dag.get_identity(d.get("disputer_tip_id", ""))
            if not disputer or not d.get("signature"): return True
            return verify_body_signature(d, d["signature"], disputer["public_key"],
                ["disputer_tip_id", "reason", "evidence_hash"])

        if tt in (TxType.REVOKE_VOLUNTARY, TxType.REVOKE_VP,
                  TxType.REVOKE_DECEASED, TxType.REVOKE_DEVICE):
            vp = dag.get_vp(d.get("issuing_vp_id", ""))
            if not vp or not d.get("signature"): return True
            return verify_body_signature(d, d["signature"], vp["public_key"],
                ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"])

        if tt == TxType.VP_REGISTERED:
            vp = dag.get_vp(d.get("approving_vp_id", ""))
            if not vp or not d.get("council_signature"): return True
            return verify_body_signature(d, d["council_signature"], vp["public_key"],
                ["name", "jurisdiction_tier", "public_key", "approving_vp_id"])

        if tt == TxType.NODE_REGISTERED:
            vp = dag.get_vp(d.get("approving_vp_id", ""))
            if not vp or not d.get("council_signature"): return True
            return verify_body_signature(d, d["council_signature"], vp["public_key"],
                ["name", "public_key", "approving_vp_id"])

    except Exception as exc:
        log.warning(f"Gossip: body sig verification error for {tt}: {exc}")
        return False

    return True



MSG_TX_BROADCAST      = "TX_BROADCAST"
MSG_HANDSHAKE         = "HANDSHAKE"
MSG_CHALLENGE         = "CHALLENGE"
MSG_CHALLENGE_RESPONSE = "CHALLENGE_RESPONSE"
MSG_SYNC_REQUEST      = "SYNC_REQUEST"
MSG_SYNC_RESPONSE     = "SYNC_RESPONSE"
MSG_PING              = "PING"
MSG_PONG              = "PONG"


class GossipServer:
    """
    Lightweight peer gossip over TCP with line-delimited JSON.
    Each message is a JSON object terminated by newline.
    """

    def __init__(self, dag, config: dict) -> None:
        self._dag      = dag
        self._config   = config
        self._peers:   dict[str, dict] = {}  # node_id -> { "sock": socket, "authenticated": bool }
        self._seen:    set  = set()
        self._lock     = threading.Lock()
        self._pending_challenges: dict[int, str] = {}  # sock id -> nonce

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
        import secrets
        log.info(f"Gossip: peer connected from {addr}")

        # Send challenge nonce for authentication
        nonce = secrets.token_hex(32)
        self._pending_challenges[id(conn)] = nonce
        self._send(conn, {"type": MSG_CHALLENGE, "nonce": nonce})

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
            self._pending_challenges.pop(id(conn), None)
            with self._lock:
                for k, v in list(self._peers.items()):
                    if v.get("sock") is conn:
                        del self._peers[k]
                        break

    def _handle_msg(self, conn: socket.socket, msg: dict) -> None:
        from shared.crypto import mldsa_verify, mldsa_sign
        mtype = msg.get("type")

        if mtype == MSG_CHALLENGE:
            # We received a challenge from a peer we connected to — sign and respond
            nonce = msg.get("nonce")
            priv_key = self._config.get("node_private_key")
            if nonce and priv_key:
                node_id = self._config.get("node_registered_id") or self._config["node_id"]
                self._send(conn, {
                    "type":      MSG_CHALLENGE_RESPONSE,
                    "node_id":   node_id,
                    "signature": mldsa_sign(nonce, priv_key),
                })

        elif mtype == MSG_CHALLENGE_RESPONSE:
            # Peer responded to our challenge — verify against node registry
            nonce = self._pending_challenges.pop(id(conn), None)
            node_id = msg.get("node_id")
            signature = msg.get("signature")
            if not nonce or not node_id or not signature:
                log.warning("Gossip: invalid challenge response — missing fields")
                conn.close()
                return

            registered = self._dag.get_node(node_id)
            if registered and mldsa_verify(nonce, signature, registered["public_key"]):
                with self._lock:
                    self._peers[node_id] = {"sock": conn, "authenticated": True}
                log.info(f"Gossip: node {node_id} authenticated (registered)")
                # Send sync request after auth
                last_ts = max(
                    (t.get("timestamp", "") for t in self._dag.get_all_txs()),
                    default="1970-01-01",
                )
                self._send(conn, {"type": MSG_SYNC_REQUEST, "since": last_ts})
            else:
                log.warning(f"Gossip: node {node_id} rejected — not in registry or invalid signature")
                conn.close()
                return

        elif mtype == MSG_TX_BROADCAST:
            tx  = msg.get("tx")
            ttl = msg.get("ttl", 2)
            if tx and tx.get("tx_id"):
                tx_id = tx["tx_id"]
                if tx_id not in self._seen:
                    with self._lock:
                        self._seen.add(tx_id)
                    if not self._dag.get_tx(tx_id):
                        result = validate_transaction(tx, self._dag, skip_state=True)
                        if not result.valid:
                            log.warning(f"Gossip: rejected tx {tx_id[:16]}... ({result.layer}): {result.errors[0]}")
                        elif not _verify_incoming_tx(tx, self._dag):
                            log.warning(f"Gossip: rejected tx {tx_id[:16]}... — body signature verification failed")
                        else:
                            # prev links already checked by validate_transaction
                            self._dag.add_tx(tx)
                            _replay_derived_state(self._dag, tx)
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
                tx_id = tx.get("tx_id")
                if tx_id and not self._dag.get_tx(tx_id):
                    result = validate_transaction(tx, self._dag, skip_state=True)
                    if not result.valid:
                        log.warning(f"Gossip: rejected sync tx {tx_id[:16]}... ({result.layer}): {result.errors[0]}")
                        continue
                    if not _verify_incoming_tx(tx, self._dag):
                        log.warning(f"Gossip: rejected sync tx {tx_id[:16]}... — body signature verification failed")
                        continue
                    # prev links checked by validate_transaction
                    self._dag.add_tx(tx)
                    _replay_derived_state(self._dag, tx)
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
            for peer in list(self._peers.values()):
                sock = peer.get("sock") if isinstance(peer, dict) else peer
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
            # Wait for challenge from peer (handled in _handle_msg CHALLENGE case)

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
