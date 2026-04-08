"""
node/api.py
TIP Protocol Python — REST API

# Author:    Dinesh Mendhe <chairman@theailab.org>
Runs on stdlib http.server by default.
If fastapi + uvicorn are installed, uses them for async + OpenAPI docs.
All endpoints are identical regardless of backend.

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""

from __future__ import annotations

import json
import pathlib
import re
import time
import threading
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

from shared.crypto import (
    generate_mldsa_keypair, mldsa_sign, mldsa_verify, verify_tx_signature,
    sign_transaction,
    hash_content, perceptual_hash_text,
    generate_tip_id, generate_ctid,
    compute_tx_id, shake256, shake256_multi,
    compute_zk_proof,
    verify_body_signature,
)
from shared.zk import verify_dedup_proof
from shared.constants import (
    TxType, Origin, Protocol, HttpHeaders,
    JurisdictionTier, get_tier, ScoreEvent,
)
from tip_node.validators.tx_validator import validate_transaction
from tip_node.logger import get_logger

log = get_logger("api")


# ─── Pre-scan (v2 FIX-03 — calibrated thresholds) ────────────────────────────

def _prescan_content(content: Optional[str], origin_code: str, creator_history: dict) -> dict:
    """
    Heuristic AI content pre-scan.
    In production: replace with a real ML-based classifier.
    """
    if origin_code != Origin.OH or not content:
        return {"flagged": False, "probability": 0.0, "threshold": 0.85}

    words      = content.split()
    word_count = len(words)
    if word_count < 20:
        return {"flagged": False, "probability": 0.1, "threshold": 0.85}

    unique_ratio = len(set(words)) / word_count
    avg_len      = sum(len(w) for w in words) / word_count
    sent_count   = max(1, content.count(".") + content.count("!") + content.count("?"))
    long_sents   = (word_count / sent_count) > 25

    prob = 0.0
    if unique_ratio < 0.55: prob += 0.20
    if avg_len > 5.5:        prob += 0.15
    if long_sents:           prob += 0.10

    # Creator calibration
    verified_oh = creator_history.get("verified_oh_count", 0)
    from shared.constants import PreScan
    if verified_oh > 200:
        threshold = PreScan.CEILING
    elif verified_oh > 50:
        threshold = 0.90
    else:
        threshold = PreScan.DEFAULT

    return {
        "flagged":     prob > threshold,
        "probability": round(prob, 4),
        "threshold":   threshold,
    }


def _merkle_root(dag) -> str:
    count    = dag.dedup_count()
    id_count = len(dag.get_txs_by_type(TxType.REGISTER_IDENTITY))
    return shake256_multi(str(count), str(id_count),
                          datetime.now(timezone.utc).isoformat()[:13])


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()




# ─── Rate limiter ─────────────────────────────────────────────────────────────

class _RateLimiter:
    def __init__(self, window: int = 60, max_req: int = 200) -> None:
        self._window  = window
        self._max     = max_req
        self._buckets: dict[str, list[float]] = {}
        self._lock    = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = [t for t in self._buckets.get(key, []) if now - t < self._window]
            if len(bucket) >= self._max:
                self._buckets[key] = bucket
                return False
            bucket.append(now)
            self._buckets[key] = bucket
            return True


# ─── Request router ───────────────────────────────────────────────────────────

class TIPAPIHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for TIP Protocol REST API.
    Thread-safe: dag, scoring, config are shared across threads (they are each thread-safe).
    """
    dag              = None  # injected via create_server()
    scoring          = None
    config           = None
    limiter          = None
    gossip           = None
    node_private_key = None
    node_public_key  = None

    log_message = lambda self, fmt, *args: None  # silence stdlib access log

    # ── CORS + standard headers ───────────────────────────────────────────────
    def _send_json(self, status: int, body: Any) -> None:
        payload = json.dumps(body, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type",  "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-TIP-API-Key")
        self.send_header(HttpHeaders.NODE_ID,      self.config["node_id"])
        self.send_header(HttpHeaders.NODE_VERSION, self.config["node_version"])
        self.send_header(HttpHeaders.PROTOCOL,     Protocol.HEADER)
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> Optional[dict]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, Exception):
            return None

    def _with_tx_id(self, tx: dict) -> dict:
        """Assign content-addressed tx_id (no node signature)."""
        tx["tx_id"] = compute_tx_id(tx)
        return tx

    def _node_signed_auto(self, tx: dict) -> dict:
        """Sign auto/system tx with node's registered key + add node_id."""
        tx["tx_id"] = compute_tx_id(tx)
        tx.setdefault("data", {})["node_id"] = self.config.get("node_registered_id") or self.config["node_id"]
        return sign_transaction(tx, self.node_private_key)

    def _broadcast(self, tx: dict) -> None:
        """Broadcast transaction to gossip peers (no-op if gossip not connected)."""
        if not self.gossip:
            return
        try:
            self.gossip.broadcast_tx(tx)
        except Exception as exc:
            log.error(f"Gossip broadcast failed for tx {tx.get('tx_id', '?')}: {exc}")

    def _rate_check(self) -> bool:
        ip = self.client_address[0]
        return self.limiter.is_allowed(ip)

    # ── Method dispatch ───────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self._send_json(204, {})

    def do_GET(self):
        if not self._rate_check():
            self._send_json(429, {"error": "Rate limit exceeded"})
            return
        try:
            self._route("GET")
        except Exception:
            log.error(traceback.format_exc())
            self._send_json(500, {"error": "Internal server error"})

    def do_POST(self):
        if not self._rate_check():
            self._send_json(429, {"error": "Rate limit exceeded"})
            return
        try:
            self._route("POST")
        except Exception:
            log.error(traceback.format_exc())
            self._send_json(500, {"error": "Internal server error"})

    def _route(self, method: str) -> None:
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)

        # ── Static file routes ──────────────────────────────────────────────
        if method == "GET" and (path.startswith("/download/") or path.startswith("/v1/zk/")):
            return self._serve_static(path)

        # ── GET routes ──────────────────────────────────────────────────────
        if method == "GET":
            if path == "/health":
                return self._health()
            if path == "/v1/node/info":
                return self._node_info()
            if path == "/v1/node/peers":
                return self._node_peers()
            if path == "/v1/dedup/merkle-root":
                return self._merkle_root()
            if path == "/v1/revocations":
                since = qs.get("since", [None])[0]
                return self._revocations_list(since)

            m = re.match(r"^/v1/identity/([^/]+)$", path)
            if m:
                return self._identity_resolve(_decode(m.group(1)))
            m = re.match(r"^/v1/identity/([^/]+)/score$", path)
            if m:
                return self._identity_score(_decode(m.group(1)))
            m = re.match(r"^/v1/identity/([^/]+)/history$", path)
            if m:
                return self._identity_history(_decode(m.group(1)))
            m = re.match(r"^/v1/content/([^/]+)$", path)
            if m:
                return self._content_resolve(_decode(m.group(1)))
            m = re.match(r"^/v1/dag/tx/([^/]+)$", path)
            if m:
                return self._dag_tx(_decode(m.group(1)))
            m = re.match(r"^/v1/vp/([^/]+)$", path)
            if m:
                return self._vp_resolve(_decode(m.group(1)))
            if path == "/v1/node/registry":
                return self._node_registry()
            m = re.match(r"^/v1/node/([^/]+)$", path)
            if m and m.group(1) not in ("info", "peers", "registry"):
                return self._node_resolve(_decode(m.group(1)))

            self._send_json(404, {"error": "Endpoint not found"})
            return

        # ── POST routes ──────────────────────────────────────────────────────
        body = self._read_body()
        if body is None:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        if path == "/v1/identity/register":
            return self._identity_register(body)
        if path == "/v1/identity/verify-ownership":
            return self._identity_verify_ownership(body)
        if path == "/v1/content/register":
            return self._content_register(body)
        if path == "/v1/dedup/check":
            return self._dedup_check(body)
        if path == "/v1/revocations":
            return self._revocations_create(body)
        if path == "/v1/vp/register":
            return self._vp_register(body)
        if path == "/v1/node/register":
            return self._node_register(body)

        m = re.match(r"^/v1/content/([^/]+)/verify$", path)
        if m:
            return self._content_verify(_decode(m.group(1)), body)
        m = re.match(r"^/v1/content/([^/]+)/dispute$", path)
        if m:
            return self._content_dispute(_decode(m.group(1)), body)
        m = re.match(r"^/v1/content/([^/]+)/update-origin$", path)
        if m:
            return self._content_update_origin(_decode(m.group(1)), body)

        self._send_json(404, {"error": "Endpoint not found"})

    # ── Endpoint implementations ──────────────────────────────────────────────

    def _health(self):
        self._send_json(200, {
            "status":      "ok",
            "node_id":     self.config["node_id"],
            "node_type":   self.config["node_type"],
            "dag_count":   self.dag.count(),
            "version":     self.config["node_version"],
            "protocol":    Protocol.VERSION,
            "timestamp":   _utc_now(),
        })

    def _node_info(self):
        self._send_json(200, {
            "node_id":           self.config["node_id"],
            "node_type":         self.config["node_type"],
            "region":            self.config["region"],
            "public_url":        self.config["public_url"],
            "protocol_version":  Protocol.VERSION,
            "node_version":      self.config["node_version"],
            "dag_tx_count":      self.dag.count(),
            "identity_count":    len(self.dag.get_txs_by_type(TxType.REGISTER_IDENTITY)),
            "content_count":     len(self.dag.get_txs_by_type(TxType.REGISTER_CONTENT)),
            "dedup_count":       self.dag.dedup_count(),
            "peer_count":        len(self.config.get("peers", [])),
            "spec_url":          Protocol.SPEC_URL,
            "issuer":            Protocol.ISSUER,
        })

    def _node_peers(self):
        peers = self.config.get("peers", [])
        self._send_json(200, {"peers": peers, "count": len(peers),
                              "node_id": self.config["node_id"]})

    def _merkle_root(self):
        count    = self.dag.dedup_count()
        id_count = len(self.dag.get_txs_by_type(TxType.REGISTER_IDENTITY))
        self._send_json(200, {
            "merkle_root":    _merkle_root(self.dag),
            "dedup_count":    count,
            "identity_count": id_count,
            "node_id":        self.config["node_id"],
            "generated":      _utc_now(),
        })

    def _revocations_list(self, since: Optional[str]):
        revocs = self.dag.get_revocations(since)
        self._send_json(200, {
            "revocations": revocs,
            "count":       len(revocs),
            "node_id":     self.config["node_id"],
            "generated":   _utc_now(),
            "next_since":  _utc_now(),
        })

    def _identity_register(self, body: dict):
        region       = body.get("region", "US")
        public_key   = body.get("public_key")
        vp_id        = body.get("vp_id") or body.get("vpId")
        vp_signature = body.get("vp_signature") or body.get("vpSignature")
        dedup_hash   = body.get("dedup_hash") or body.get("dedupHash")
        zk_proof     = body.get("zk_proof") or body.get("zkProof")
        tier         = body.get("verification_tier", "T1")
        attested     = bool(body.get("social_attested") or body.get("socialAttested"))
        founding     = False

        if not public_key:
            self._send_json(400, {"error": "public_key is required (client-generated ML-DSA-65)"}); return
        if not vp_id:
            self._send_json(400, {"error": "vp_id is required"}); return
        if not vp_signature:
            self._send_json(400, {"error": "vp_signature is required"}); return
        if not dedup_hash:
            self._send_json(400, {"error": "dedup_hash is required"}); return
        if not zk_proof:
            self._send_json(400, {"error": "zk_proof is required"}); return

        vp = self.dag.get_vp(vp_id)
        if not vp:
            self._send_json(403, {"error": f"VP not found: {vp_id}"}); return
        if vp.get("status") != "active":
            self._send_json(403, {"error": f"VP is not active: {vp_id}"}); return

        # Verify VP signature over required fields
        _VP_IDENTITY_FIELDS = ["region", "public_key", "dedup_hash", "zk_proof", "verification_tier", "vp_id", "social_attested"]
        if not verify_body_signature(body, vp_signature, vp.get("public_key", ""), _VP_IDENTITY_FIELDS):
            self._send_json(403, {"error": "VP signature verification failed — signature does not match VP public key"}); return

        # Verify ZK proof: proves prover knows (govId, dob, country) that Poseidon-hash to dedup_hash
        if not verify_dedup_proof(dedup_hash, zk_proof):
            self._send_json(400, {"error": "ZK proof verification failed — invalid or tampered proof"}); return

        # Dedup check
        if self.dag.has_dedup_hash(dedup_hash):
            self._send_json(409, {
                "error": "Identity already registered. Each human may hold exactly one TIP-ID.",
                "code":  "DUPLICATE_IDENTITY",
            }); return

        tip_id        = generate_tip_id(region, public_key)
        registered_at = _utc_now()

        # Pre-validate
        tx = {
            "tx_type":   TxType.REGISTER_IDENTITY,
            "timestamp": registered_at,
            "prev":      self.dag.get_recent_prev(),
            "data": {
                "tip_id":            tip_id,
                "region":            region.upper(),
                "public_key":        public_key,
                "vp_id":             vp_id,
                "verification_tier": tier,
                "social_attested":   attested,
                "founding":          founding,
                "dedup_hash":        dedup_hash,
                "zk_proof":          zk_proof,
            },
        }
        tx = self._with_tx_id(tx)
        result = validate_transaction(tx, self.dag, )
        if not result.valid:
            self._send_json(400, {"error": result.errors[0],
                                  "errors": result.errors,
                                  "layer": result.layer}); return

        self.dag.add_tx(tx)
        self._broadcast(tx)
        self.dag.save_identity({
            "tip_id":            tip_id,
            "region":            region.upper(),
            "public_key":        public_key,
            "vp_id":             vp_id,
            "verification_tier": tier,
            "founding":          founding,
            "status":            "active",
            "registered_at":     registered_at,
            "tx_id":             tx["tx_id"],
        })
        self.dag.add_dedup_hash(dedup_hash)
        initial_score = ScoreEvent.INITIAL_WITH_ATTESTATION if attested else ScoreEvent.INITIAL_NO_ATTESTATION
        self.dag.set_score(tip_id, initial_score, 0)
        log.info(f"Identity registered: {tip_id} (tier={tier}, vp={vp_id})")

        self._send_json(201, {
            "tip_id":           tip_id,
            "public_key":       public_key,
            "tx_id":            tx["tx_id"],
            "score":            initial_score,
            "registered_at":    registered_at,
        })

    def _identity_resolve(self, tip_id: str):
        rec = self.dag.get_identity(tip_id)
        if not rec:
            self._send_json(404, {"error": f"TIP-ID not found: {tip_id}"}); return
        score_data = self.scoring.get_score(tip_id)
        content    = self.dag.get_content_by_author(tip_id)
        revoked    = self.dag.is_revoked(tip_id)
        self._send_json(200, {
            "tip_id":            rec["tip_id"],
            "region":            rec.get("region"),
            "public_key":        rec.get("public_key"),
            "vp_id":             rec.get("vp_id"),
            "verification_tier": rec.get("verification_tier"),
            "founding":          bool(rec.get("founding")),
            "status":            "revoked" if revoked else rec.get("status", "active"),
            "score":             score_data["score"],
            "tier":              score_data["tier"],
            "tier_color":        score_data["tier_color"],
            "content_count":     len(content),
            "registered_at":     rec.get("registered_at"),
        })

    def _identity_verify_ownership(self, body: dict):
        tip_id    = body.get("tip_id")
        challenge = body.get("challenge")
        signature = body.get("signature")
        if not tip_id:    self._send_json(400, {"error": "tip_id is required"}); return
        if not challenge: self._send_json(400, {"error": "challenge is required"}); return
        if not signature: self._send_json(400, {"error": "signature is required"}); return

        identity = self.dag.get_identity(tip_id)
        if not identity:
            self._send_json(404, {"error": "TIP-ID not found"}); return
        if self.dag.is_revoked(tip_id):
            self._send_json(403, {"error": "TIP-ID is revoked"}); return

        if not mldsa_verify(challenge, signature, identity.get("public_key", "")):
            self._send_json(403, {"error": "Signature verification failed — you do not own this TIP-ID"}); return

        score_data = self.scoring.get_score(tip_id)
        self._send_json(200, {
            "verified": True,
            "tip_id":   tip_id,
            "score":    score_data["score"],
            "tier":     score_data["tier"],
            "status":   identity.get("status", "active"),
        })

    def _identity_score(self, tip_id: str):
        rec = self.dag.get_identity(tip_id)
        if not rec:
            self._send_json(404, {"error": f"TIP-ID not found: {tip_id}"}); return
        score_data = self.scoring.get_score(tip_id)
        content    = self.dag.get_content_by_author(tip_id)
        self._send_json(200, {
            "tip_id":         tip_id,
            "tier":           score_data["tier"],
            "tier_label":     score_data["tier_label"],
            "tier_color":     score_data["tier_color"],
            "score":          score_data["score"],
            "offense_count":  score_data.get("offense_count", 0),
            "verified_since": rec.get("registered_at"),
            "content_count":  len(content),
            "status":         "revoked" if self.dag.is_revoked(tip_id) else rec.get("status", "active"),
        })

    def _identity_history(self, tip_id: str):
        rec = self.dag.get_identity(tip_id)
        if not rec:
            self._send_json(404, {"error": f"TIP-ID not found: {tip_id}"}); return
        result = self.scoring.compute_score(tip_id)
        self._send_json(200, {
            "tip_id":  tip_id,
            "score":   result["score"],
            "history": result.get("history", []),
        })

    def _content_register(self, body: dict):
        author_tip_id  = body.get("author_tip_id") or body.get("authorTipId")
        origin_code    = body.get("origin_code")   or body.get("originCode")
        content        = body.get("content")
        signature      = body.get("signature", "unsigned")

        if not author_tip_id:
            self._send_json(400, {"error": "author_tip_id is required"}); return
        if not origin_code:
            self._send_json(400, {"error": "origin_code is required (OH|AA|AG|MX)"}); return
        if not Origin.is_valid(origin_code):
            self._send_json(400, {"error": f"Invalid origin_code: {origin_code}"}); return
        if not content:
            self._send_json(400, {"error": "content is required"}); return

        identity = self.dag.get_identity(author_tip_id)
        if not identity:
            self._send_json(404, {"error": f"Author TIP-ID not found: {author_tip_id}"}); return
        if self.dag.is_revoked(author_tip_id):
            self._send_json(403, {"error": f"Author TIP-ID is revoked: {author_tip_id}"}); return

        if not signature or signature == "unsigned":
            self._send_json(400, {"error": "signature is required"}); return

        # Full SHAKE-256 for signature verification (64 hex chars — matches client signBody)
        content_hash_full = shake256(content)
        # Truncated hash for CTID URI and storage (14 hex chars — readable)
        content_hash_short = hash_content(content)

        _CONTENT_FIELDS = ["author_tip_id", "origin_code", "content_hash"]
        sig_body = {"author_tip_id": author_tip_id, "origin_code": origin_code, "content_hash": content_hash_full}
        if not verify_body_signature(sig_body, signature, identity.get("public_key", ""), _CONTENT_FIELDS):
            self._send_json(403, {"error": "Content signature verification failed — signature does not match author public key"}); return

        percept_hash = perceptual_hash_text(content)

        ctid          = generate_ctid(origin_code, content_hash_short, author_tip_id)
        registered_at = _utc_now()

        # Pre-scan (v2 FIX-03)
        author_content = self.dag.get_content_by_author(author_tip_id)
        verified_oh    = sum(1 for c in author_content
                             if c.get("origin_code") == Origin.OH
                             and c.get("status") == "verified")
        prescan = _prescan_content(content, origin_code,
                                   {"verified_oh_count": verified_oh})

        tx = {
            "tx_type":   TxType.REGISTER_CONTENT,
            "timestamp": registered_at,
            "prev":      self.dag.get_recent_prev(),
            "data": {
                "ctid":              ctid,
                "origin_code":       origin_code,
                "origin_label":      Origin.label(origin_code),
                "content_hash":      content_hash_full,
                "perceptual_hash":   percept_hash,
                "author_tip_id":     author_tip_id,
                "signature":         signature,
                "prescan_flagged":   prescan["flagged"],
                "prescan_probability": prescan["probability"],
            },
        }
        tx = self._with_tx_id(tx)
        result = validate_transaction(tx, self.dag, )
        if not result.valid:
            self._send_json(400, {"error": result.errors[0],
                                  "errors": result.errors,
                                  "layer": result.layer}); return

        status = "pending_review" if prescan["flagged"] else "registered"
        self.dag.add_tx(tx)
        self._broadcast(tx)
        self.dag.save_content({
            "ctid":             ctid,
            "origin_code":      origin_code,
            "content_hash":     content_hash_full,
            "perceptual_hash":  percept_hash,
            "author_tip_id":    author_tip_id,
            "status":           status,
            "prescan_flagged":  prescan["flagged"],
            "registered_at":    registered_at,
            "tx_id":            tx["tx_id"],
        })

        score_data = self.scoring.get_score(author_tip_id)
        http_headers = {
            HttpHeaders.AUTHOR:      author_tip_id,
            HttpHeaders.CONTENT:     ctid,
            HttpHeaders.ORIGIN:      Origin.label(origin_code).lower().replace(" ", "-"),
            HttpHeaders.TRUST_SCORE: str(score_data["score"]),
            HttpHeaders.SIGNATURE:   signature,
        }
        log.info(f"Content registered: {ctid} (origin={origin_code}, author={author_tip_id})")

        self._send_json(201, {
            "ctid":             ctid,
            "origin_code":      origin_code,
            "origin_label":     Origin.label(origin_code),
            "content_hash":     content_hash_full,
            "author_tip_id":    author_tip_id,
            "tx_id":            tx["tx_id"],
            "status":           status,
            "registered_at":    registered_at,
            "prescan_flagged":  prescan["flagged"],
            "prescan_note":     ("Flagged by AI pre-scan — Stage 1 adjudication queued. "
                                 "No penalty if cleared." if prescan["flagged"] else None),
            "http_headers":     http_headers,
            "meta_tags": {
                "tip:author":  author_tip_id,
                "tip:content": ctid,
                "tip:origin":  Origin.label(origin_code).lower().replace(" ", "-"),
                "tip:score":   str(score_data["score"]),
                "tip:status":  "PENDING" if prescan["flagged"] else "VERIFIED",
            },
        })

    def _content_resolve(self, ctid: str):
        rec = self.dag.get_content(ctid)
        if not rec:
            self._send_json(404, {"error": f"Content record not found: {ctid}"}); return
        score_data = self.scoring.get_score(rec.get("author_tip_id", ""))
        self._send_json(200, {
            **rec,
            "origin_label": Origin.label(rec.get("origin_code", "")),
            "author_score": score_data.get("score", 0),
        })

    def _content_verify(self, ctid: str, body: dict):
        rec = self.dag.get_content(ctid)
        if not rec:
            self._send_json(404, {"error": f"Content not found: {ctid}"}); return
        verifier_tip_id = body.get("verifier_tip_id")
        signature       = body.get("signature")
        if not verifier_tip_id:
            self._send_json(400, {"error": "verifier_tip_id required"}); return
        if not signature:
            self._send_json(400, {"error": "signature is required"}); return

        verifier = self.dag.get_identity(verifier_tip_id)
        if not verifier:
            self._send_json(404, {"error": f"Verifier TIP-ID not found: {verifier_tip_id}"}); return
        if verifier_tip_id == rec.get("author_tip_id"):
            self._send_json(403, {"error": "Cannot verify your own content"}); return
        if rec.get("status") == "disputed":
            self._send_json(403, {"error": "Content is under dispute — verification blocked until resolved"}); return
        if rec.get("status") == "pending_review":
            self._send_json(403, {"error": "Content is pending review — verification blocked until 24-hour grace period ends"}); return

        _VERIFY_FIELDS = ["verifier_tip_id", "verdict"]
        if not verify_body_signature(body, signature, verifier.get("public_key", ""), _VERIFY_FIELDS):
            self._send_json(403, {"error": "Verifier signature verification failed — signature does not match verifier public key"}); return

        if self.dag.has_verification(ctid, verifier_tip_id):
            self._send_json(409, {"error": "You have already verified this content"}); return

        if not self.scoring.is_jury_eligible(verifier_tip_id):
            self._send_json(403, {"error": "Verifier not jury eligible (score < 700 or revoked)"}); return

        verifier_score = self.scoring.get_score(verifier_tip_id)["score"]
        weighted_delta = max(1, min(5, int(verifier_score / 200)))
        verify_tx = {
            "tx_type":   TxType.CONTENT_VERIFIED,
            "timestamp": _utc_now(),
            "prev":      self.dag.get_recent_prev(),
            "data": {
                "ctid":             ctid,
                "verifier_tip_id":  verifier_tip_id,
                "verdict":          body.get("verdict", "ORIGIN_CONFIRMED"),
                "weighted_delta":   weighted_delta,
                "author_tip_id":    rec.get("author_tip_id"),
            },
        }
        verify_tx = self._with_tx_id(verify_tx)
        result = validate_transaction(verify_tx, self.dag, )
        if not result.valid:
            self._send_json(400, {"error": result.errors[0], "errors": result.errors, "layer": result.layer}); return
        self.dag.add_tx(verify_tx)
        self._broadcast(verify_tx)
        self.scoring.apply_score_event(
            rec.get("author_tip_id", ""), weighted_delta,
            f"Content verified by {verifier_tip_id}"
        )
        if rec.get("status") == "registered":
            self.dag.update_content_status(ctid, "verified")
        self._send_json(200, {"success": True, "delta_applied": weighted_delta})

    def _content_dispute(self, ctid: str, body: dict):
        rec = self.dag.get_content(ctid)
        if not rec:
            self._send_json(404, {"error": f"Content not found: {ctid}"}); return
        if rec.get("status") == "pending_review":
            self._send_json(403, {"error": "Content is pending review — wait for 24-hour grace period to end before disputing"}); return
        disputer  = body.get("disputer_tip_id")
        signature = body.get("signature")
        if not disputer:
            self._send_json(400, {"error": "disputer_tip_id required"}); return
        if not signature:
            self._send_json(400, {"error": "signature is required"}); return

        disputer_identity = self.dag.get_identity(disputer)
        if not disputer_identity:
            self._send_json(404, {"error": f"Disputer TIP-ID not found: {disputer}"}); return
        if self.dag.is_revoked(disputer):
            self._send_json(403, {"error": "Disputer TIP-ID is revoked"}); return

        _DISPUTE_FIELDS = ["disputer_tip_id", "reason", "evidence_hash"]
        if not verify_body_signature(body, signature, disputer_identity.get("public_key", ""), _DISPUTE_FIELDS):
            self._send_json(403, {"error": "Disputer signature verification failed — signature does not match disputer public key"}); return

        if self.dag.has_dispute(ctid, disputer):
            self._send_json(409, {"error": "You have already disputed this content"}); return

        dispute_tx = {
            "tx_type":   TxType.CONTENT_DISPUTED,
            "timestamp": _utc_now(),
            "prev":      self.dag.get_recent_prev(),
            "data": {
                "ctid":             ctid,
                "disputer_tip_id":  disputer,
                "reason":           body.get("reason"),
                "evidence_hash":    body.get("evidence_hash"),
                "author_tip_id":    rec.get("author_tip_id"),
            },
        }
        dispute_tx = self._with_tx_id(dispute_tx)
        result = validate_transaction(dispute_tx, self.dag, )
        if not result.valid:
            self._send_json(400, {"error": result.errors[0], "errors": result.errors, "layer": result.layer}); return
        self.dag.add_tx(dispute_tx)
        self._broadcast(dispute_tx)
        self.dag.update_content_status(ctid, "disputed")
        self._send_json(200, {
            "success": True,
            "message": "Dispute filed. Content verification blocked until resolved.",
        })

    def _content_update_origin(self, ctid: str, body: dict):
        rec = self.dag.get_content(ctid)
        if not rec:
            self._send_json(404, {"error": f"Content not found: {ctid}"}); return

        author_tip_id  = body.get("author_tip_id")
        new_origin_code = body.get("new_origin_code")
        signature       = body.get("signature")
        if not author_tip_id:   self._send_json(400, {"error": "author_tip_id required"}); return
        if not new_origin_code: self._send_json(400, {"error": "new_origin_code required"}); return
        if not signature:       self._send_json(400, {"error": "signature required"}); return

        if author_tip_id != rec.get("author_tip_id"):
            self._send_json(403, {"error": "Only the content author can update the origin code"}); return

        status = rec.get("status")
        if status not in ("registered", "pending_review"):
            self._send_json(403, {"error": f"Cannot update origin — content status is '{status}'"}); return

        from datetime import datetime, timezone
        registered_at = datetime.fromisoformat(rec.get("registered_at", "").replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if (now - registered_at).total_seconds() > 86400:
            self._send_json(403, {"error": "24-hour grace period has expired. Origin code can no longer be changed."}); return

        valid_origins = {"OH", "AA", "AG", "MX"}
        if new_origin_code not in valid_origins:
            self._send_json(400, {"error": f"Invalid origin_code. Must be one of: {', '.join(valid_origins)}"}); return

        author = self.dag.get_identity(author_tip_id)
        if not author:
            self._send_json(404, {"error": "Author identity not found"}); return

        _UPDATE_FIELDS = ["author_tip_id", "new_origin_code"]
        if not verify_body_signature(body, signature, author.get("public_key", ""), _UPDATE_FIELDS):
            self._send_json(403, {"error": "Author signature verification failed"}); return

        update_tx = {
            "tx_type":   TxType.UPDATE_ORIGIN,
            "timestamp": _utc_now(),
            "prev":      self.dag.get_recent_prev(),
            "data": {
                "ctid":            ctid,
                "old_origin_code": rec.get("origin_code"),
                "new_origin_code": new_origin_code,
                "author_tip_id":   author_tip_id,
            },
        }
        update_tx = self._with_tx_id(update_tx)
        self.dag.add_tx(update_tx)
        self._broadcast(update_tx)

        prescan = _prescan_content("", new_origin_code, {})
        new_status = "pending_review" if prescan["flagged"] else "registered"
        self.dag.update_content_origin(ctid, new_origin_code, new_status)

        log.info(f"Origin updated: {ctid} {rec.get('origin_code')} → {new_origin_code} (by {author_tip_id})")
        self._send_json(200, {
            "success":         True,
            "ctid":            ctid,
            "old_origin_code": rec.get("origin_code"),
            "new_origin_code": new_origin_code,
            "status":          new_status,
            "tx_id":           update_tx["tx_id"],
        })

    def _dag_tx(self, tx_id: str):
        tx = self.dag.get_tx(tx_id)
        if not tx:
            self._send_json(404, {"error": f"Transaction not found: {tx_id}"}); return
        self._send_json(200, tx)

    def _revocations_create(self, body: dict):
        tip_id       = body.get("tip_id")
        tx_type      = body.get("tx_type")
        reason_code  = body.get("reason_code")
        evidence_hash = body.get("evidence_hash")
        issuing_vp_id = body.get("issuing_vp_id")
        signature     = body.get("signature")

        if not tip_id:
            self._send_json(400, {"error": "tip_id is required"}); return
        if not tx_type:
            self._send_json(400, {"error": "tx_type is required"}); return
        if tx_type not in TxType.REVOCATION_TYPES:
            self._send_json(400, {"error": f"tx_type must be one of {sorted(TxType.REVOCATION_TYPES)}"}); return
        if not issuing_vp_id:
            self._send_json(400, {"error": "issuing_vp_id is required"}); return
        if not signature:
            self._send_json(400, {"error": "signature is required"}); return

        # Verify the issuing VP exists and is active
        issuing_vp = self.dag.get_vp(issuing_vp_id)
        if not issuing_vp:
            self._send_json(403, {"error": f"Issuing VP not found: {issuing_vp_id}"}); return
        if issuing_vp.get("status") != "active":
            self._send_json(403, {"error": f"Issuing VP is not active: {issuing_vp_id}"}); return

        # Verify VP signature over required fields
        _REVOCATION_FIELDS = ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"]
        if not verify_body_signature(body, signature, issuing_vp.get("public_key", ""), _REVOCATION_FIELDS):
            self._send_json(403, {"error": "VP signature verification failed — signature does not match issuing VP public key"}); return

        identity = self.dag.get_identity(tip_id)
        if not identity:
            self._send_json(404, {"error": f"TIP-ID not found: {tip_id}"}); return
        if self.dag.is_revoked(tip_id):
            self._send_json(409, {"error": f"TIP-ID already revoked: {tip_id}"}); return

        timestamp = _utc_now()
        revoke_tx = {
            "tx_type":   tx_type,
            "timestamp": timestamp,
            "prev":      self.dag.get_recent_prev(),
            "data": {
                "tip_id":        tip_id,
                "reason_code":   reason_code,
                "evidence_hash": evidence_hash,
                "issuing_vp_id": issuing_vp_id,
                "signature":     signature,
            },
        }
        revoke_tx = self._with_tx_id(revoke_tx)
        result = validate_transaction(revoke_tx, self.dag, )
        if not result.valid:
            self._send_json(400, {"error": result.errors[0], "errors": result.errors, "layer": result.layer}); return
        tx = self.dag.add_tx(revoke_tx)
        self._broadcast(tx)
        self.dag.add_revocation(tip_id, tx_type, timestamp, tx["tx_id"])

        # Cascade: flag recent content for REVOKE_VP
        if tx_type == TxType.REVOKE_VP:
            from datetime import timedelta
            cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
            recent = [c for c in self.dag.get_content_by_author(tip_id)
                      if (c.get("registered_at") or "") > cutoff]
            for c in recent:
                cascade_tx = self._node_signed_auto({
                    "tx_type":   TxType.CONTENT_DISPUTED,
                    "timestamp": _utc_now(),
                    "prev":      self.dag.get_recent_prev(),
                    "data":      {"ctid": c["ctid"], "reason": "issuer_revocation_cascade", "auto": True},
                })
                self.dag.add_tx(cascade_tx)
                self._broadcast(cascade_tx)
            log.info(f"Revocation cascade: {len(recent)} records flagged for {tip_id}")

        log.info(f"Revocation: {tip_id} (type={tx_type}, by={issuing_vp_id})")
        self._send_json(201, {
            "tx_id":     tx["tx_id"],
            "tip_id":    tip_id,
            "tx_type":   tx_type,
            "timestamp": timestamp,
        })

    def _dedup_check(self, _body: dict):
        # Removed: dedup is now checked inside _identity_register via dag.has_dedup_hash()
        self._send_json(410, {"error": "Endpoint removed. Dedup is checked during registration."})

    def _vp_register(self, body: dict):
        name              = body.get("name")
        tier              = body.get("jurisdiction_tier", "green")
        pubkey            = body.get("public_key")
        council_signature = body.get("council_signature")
        approving_vp_id   = body.get("approving_vp_id")

        if not name:
            self._send_json(400, {"error": "name is required"}); return
        if not pubkey:
            self._send_json(400, {"error": "public_key is required"}); return
        if not council_signature:
            self._send_json(400, {"error": "council_signature is required"}); return
        if not approving_vp_id:
            self._send_json(400, {"error": "approving_vp_id is required"}); return
        if not JurisdictionTier.can_accredit(tier):
            self._send_json(400, {"error": f"Cannot accredit VPs in '{tier}' jurisdiction"}); return

        # Only the founding VP can approve new VPs
        from tip_node.genesis import get_founding_vp
        founding_vp_id = get_founding_vp()["vp_id"]
        if approving_vp_id != founding_vp_id:
            self._send_json(403, {"error": f"Only the founding VP ({founding_vp_id}) can approve new VPs"}); return

        # Verify the approving VP exists and is active
        approving_vp = self.dag.get_vp(approving_vp_id)
        if not approving_vp:
            self._send_json(403, {"error": f"Approving VP not found: {approving_vp_id}"}); return
        if approving_vp.get("status") != "active":
            self._send_json(403, {"error": f"Approving VP is not active: {approving_vp_id}"}); return

        # Verify council signature over required fields
        _VP_REGISTER_FIELDS = ["name", "jurisdiction_tier", "public_key", "approving_vp_id"]
        if not verify_body_signature(body, council_signature, approving_vp.get("public_key", ""), _VP_REGISTER_FIELDS):
            self._send_json(403, {"error": "Council signature verification failed — signature does not match approving VP public key"}); return

        vp_id = generate_tip_id("VP", pubkey)
        registered_at = _utc_now()
        vp_tx = {
            "tx_type":   TxType.VP_REGISTERED,
            "timestamp": registered_at,
            "prev":      self.dag.get_recent_prev(),
            "data": {
                "vp_id":             vp_id,
                "name":              name,
                "jurisdiction_tier": tier,
                "public_key":        pubkey,
                "council_signature": council_signature,
                "approving_vp_id":   approving_vp_id,
            },
        }
        vp_tx = self._with_tx_id(vp_tx)
        result = validate_transaction(vp_tx, self.dag, )
        if not result.valid:
            self._send_json(400, {"error": result.errors[0], "errors": result.errors, "layer": result.layer}); return
        self.dag.add_tx(vp_tx)
        self._broadcast(vp_tx)
        self.dag.save_vp({
            "vp_id":             vp_id,
            "name":              name,
            "jurisdiction_tier": tier,
            "public_key":        pubkey,
            "status":            "active",
            "registered_at":     registered_at,
        })
        self._send_json(201, {
            "vp_id": vp_id, "name": name,
            "jurisdiction_tier": tier,
            "registered_at": registered_at,
        })

    def _vp_resolve(self, vp_id: str):
        vp = self.dag.get_vp(vp_id)
        if not vp:
            self._send_json(404, {"error": f"VP not found: {vp_id}"}); return
        self._send_json(200, dict(vp))

    def _node_register(self, body: dict):
        name              = body.get("name")
        pubkey            = body.get("public_key")
        council_signature = body.get("council_signature")
        approving_vp_id   = body.get("approving_vp_id")

        if not pubkey:
            self._send_json(400, {"error": "public_key is required"}); return
        if not council_signature:
            self._send_json(400, {"error": "council_signature is required"}); return
        if not approving_vp_id:
            self._send_json(400, {"error": "approving_vp_id is required"}); return

        from tip_node.genesis import get_founding_vp
        founding_vp_id = get_founding_vp()["vp_id"]
        if approving_vp_id != founding_vp_id:
            self._send_json(403, {"error": f"Only the founding VP ({founding_vp_id}) can approve new nodes"}); return

        approving_vp = self.dag.get_vp(approving_vp_id)
        if not approving_vp:
            self._send_json(403, {"error": f"Approving VP not found: {approving_vp_id}"}); return
        if approving_vp.get("status") != "active":
            self._send_json(403, {"error": f"Approving VP is not active: {approving_vp_id}"}); return

        _NODE_REGISTER_FIELDS = ["name", "public_key", "approving_vp_id"]
        if not verify_body_signature(body, council_signature, approving_vp.get("public_key", ""), _NODE_REGISTER_FIELDS):
            self._send_json(403, {"error": "Council signature verification failed — signature does not match approving VP public key"}); return

        node_id = generate_tip_id("NODE", pubkey)
        registered_at = _utc_now()
        node_tx = {
            "tx_type":   TxType.NODE_REGISTERED,
            "timestamp": registered_at,
            "prev":      self.dag.get_recent_prev(),
            "data": {
                "node_id":           node_id,
                "name":              name,
                "public_key":        pubkey,
                "council_signature": council_signature,
                "approving_vp_id":   approving_vp_id,
            },
        }
        node_tx = self._with_tx_id(node_tx)
        result = validate_transaction(node_tx, self.dag, )
        if not result.valid:
            self._send_json(400, {"error": result.errors[0], "errors": result.errors, "layer": result.layer}); return
        self.dag.add_tx(node_tx)
        self._broadcast(node_tx)
        self.dag.save_node({
            "node_id":        node_id,
            "name":           name,
            "public_key":     pubkey,
            "status":         "active",
            "registered_at":  registered_at,
        })
        self._send_json(201, {
            "node_id": node_id, "name": name,
            "public_key": pubkey, "registered_at": registered_at,
        })

    def _node_registry(self):
        nodes = self.dag.get_all_nodes()
        self._send_json(200, {"nodes": nodes, "count": len(nodes),
                              "node_id": self.config["node_id"]})

    def _node_resolve(self, node_id: str):
        node = self.dag.get_node(node_id)
        if not node:
            self._send_json(404, {"error": f"Node not found: {node_id}"}); return
        self._send_json(200, dict(node))


    def _serve_static(self, path: str):
        """Serve static files from /download (browser extension) and /v1/zk (circuits)."""
        import mimetypes
        root = pathlib.Path(__file__).parent.parent.parent  # repo root
        if path.startswith("/download/"):
            file_path = root / "browser-extension" / path[len("/download/"):]
        elif path.startswith("/v1/zk/"):
            file_path = root / "circuits" / path[len("/v1/zk/"):]
        else:
            self._send_json(404, {"error": "Not found"}); return

        # Prevent path traversal
        try:
            file_path = file_path.resolve()
            if ".." in str(file_path) or not file_path.is_file():
                self._send_json(404, {"error": "Not found"}); return
        except Exception:
            self._send_json(404, {"error": "Not found"}); return

        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)


def _decode(s: str) -> str:
    from urllib.parse import unquote
    return unquote(s)


# ─── Server factory ───────────────────────────────────────────────────────────

def create_server(dag, scoring, config: dict, gossip=None) -> HTTPServer:
    """Create a threaded HTTPServer with the TIP API handler."""
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    limiter = _RateLimiter(
        window=config.get("rate_limit_window", 60),
        max_req=config.get("rate_limit_max", 200),
    )

    class BoundHandler(TIPAPIHandler):
        pass

    BoundHandler.dag              = dag
    BoundHandler.scoring          = scoring
    BoundHandler.config           = config
    BoundHandler.limiter          = limiter
    BoundHandler.gossip           = gossip
    BoundHandler.node_private_key = config.get("node_private_key")
    BoundHandler.node_public_key  = config.get("node_public_key")

    host = config.get("host", "0.0.0.0")
    port = config.get("port", 4000)
    server = ThreadingHTTPServer((host, port), BoundHandler)
    return server
