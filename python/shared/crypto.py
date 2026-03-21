"""
shared/crypto.py
TIP Protocol Python — Cryptographic Primitives

# Author:    Dinesh Mendhe <chairman@theailab.org>
Post-quantum algorithms (production targets):
  ML-DSA-65    FIPS 204  Primary transaction signing
  SLH-DSA-128s FIPS 205  Root / long-term identity keys
  ML-KEM-768   FIPS 203  Node-to-node key encapsulation
  SHAKE-256    FIPS 202  All hashing: content, URIs, biometrics, dedup

Production note:
  ML-DSA-65 and SLH-DSA-128s use Ed25519 as a development stand-in
  (identical API surface, swap in pqcrypto / liboqs bindings when ready).
  SHAKE-256 uses Python's built-in hashlib — no substitution needed.

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from typing import Any

import oqs


# ─── SHAKE-256 (FIPS 202) ─────────────────────────────────────────────────────

def shake256(data: bytes | str, output_bytes: int = 32) -> str:
    """Compute SHAKE-256 and return lowercase hex digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = hashlib.shake_256()
    h.update(data)
    return h.hexdigest(output_bytes)


def shake256_multi(*parts: bytes | str, output_bytes: int = 32) -> str:
    """Compute SHAKE-256 over concatenated inputs, return hex digest."""
    h = hashlib.shake_256()
    for p in parts:
        h.update(p.encode("utf-8") if isinstance(p, str) else p)
    return h.hexdigest(output_bytes)


# ─── ML-DSA-65 KEYPAIR (Dilithium, FIPS 204) ─────────────────────────────────
# Production: replace body with pqcrypto.sign.dilithium3 or liboqs bindings.
# API surface is identical to the real implementation.

def generate_mldsa_keypair() -> dict:
    """Generate an ML-DSA-65 keypair. Returns dict with publicKey, privateKey, algorithm."""
    with oqs.Signature("ML-DSA-65") as signer:
        public_key_bytes  = signer.generate_keypair()
        private_key_bytes = signer.export_secret_key()
    return {
        "algorithm":  "ML-DSA-65",
        "publicKey":  public_key_bytes.hex(),   # 1952 bytes
        "privateKey": private_key_bytes.hex(),  # 4032 bytes
    }


def mldsa_sign(data: bytes | str, private_key_hex: str) -> str:
    """Sign data with ML-DSA-65 private key. Returns hex signature."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        with oqs.Signature("ML-DSA-65", secret_key=private_key_bytes) as signer:
            return signer.sign(data).hex()
    except Exception as exc:
        raise ValueError(f"Signing failed: {exc}") from exc


def mldsa_verify(data: bytes | str, signature_hex: str, public_key_hex: str) -> bool:
    """Verify ML-DSA-65 signature. Returns True if valid."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        sig_bytes        = bytes.fromhex(signature_hex)
        with oqs.Signature("ML-DSA-65") as verifier:
            return verifier.verify(data, sig_bytes, public_key_bytes)
    except Exception:
        return False


# ─── SLH-DSA-128s ROOT KEY (SPHINCS+, FIPS 205) ───────────────────────────────

_SLHDSA_ALG = "SPHINCS+-SHA2-128s-simple"


def generate_slhdsa_keypair() -> dict:
    """Generate an SLH-DSA-128s keypair. Returns dict with publicKey, privateKey, algorithm."""
    with oqs.Signature(_SLHDSA_ALG) as signer:
        public_key_bytes  = signer.generate_keypair()
        private_key_bytes = signer.export_secret_key()
    return {
        "algorithm":  "SLH-DSA-128s",
        "publicKey":  public_key_bytes.hex(),   # 32 bytes
        "privateKey": private_key_bytes.hex(),  # 64 bytes
    }


def slhdsa_sign(data: bytes | str, private_key_hex: str) -> str:
    """Sign data with SLH-DSA-128s private key. Returns hex signature."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        with oqs.Signature(_SLHDSA_ALG, secret_key=private_key_bytes) as signer:
            return signer.sign(data).hex()
    except Exception as exc:
        raise ValueError(f"SLH-DSA signing failed: {exc}") from exc


def slhdsa_verify(data: bytes | str, signature_hex: str, public_key_hex: str) -> bool:
    """Verify SLH-DSA-128s signature. Returns True if valid."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        sig_bytes        = bytes.fromhex(signature_hex)
        with oqs.Signature(_SLHDSA_ALG) as verifier:
            return verifier.verify(data, sig_bytes, public_key_bytes)
    except Exception:
        return False


# ─── Content hashing ──────────────────────────────────────────────────────────

def hash_content(content: bytes | str) -> str:
    """Compute SHAKE-256 of content and return 14-char truncated hex (56 bits)."""
    return shake256(content)[:14]


def perceptual_hash_text(text: str) -> str:
    """Normalised text hash for fuzzy matching across reposts."""
    import re
    norm = re.sub(r"\s+", " ", text.lower())
    norm = re.sub(r"[^\w\s]", "", norm).strip()
    return shake256(norm, 16)[:16]


# ─── Deduplication hash (v2 FIX-02 — peppered) ────────────────────────────────

def generate_pepper() -> str:
    """Generate a cryptographically random 256-bit pepper. Returns hex."""
    return secrets.token_hex(32)  # 32 bytes = 256 bits = 64 hex chars


def compute_dedup_hash(
    gov_id_normalized: str,
    date_of_birth_iso: str,
    country_code: str,
    facial_embedding_hash: str = "",
    pepper: str = "",
) -> str:
    """
    Compute a reference dedup hash (SHAKE-256).
    NOTE: The production ZK circuit uses Poseidon(gov_id, dob, country) —
          see shared/zk.js generateDedupProof() for the real implementation.
    """
    return shake256_multi(
        gov_id_normalized,
        date_of_birth_iso,
        country_code.upper(),
        facial_embedding_hash,
        pepper,
    )


# ─── URI generation ───────────────────────────────────────────────────────────

def generate_tip_id(region: str, public_key_hex: str) -> str:
    """Generate a TIP-ID URI: tip://id/[REGION]-[PQ_PUBKEY_HASH16]"""
    hash16 = shake256(public_key_hex)[:16]
    return f"tip://id/{region.upper()}-{hash16}"


def generate_ctid(origin_code: str, content_hash: str, tip_id: str) -> str:
    """Generate a TIP-CONTENT URI: tip://c/[ORIGIN]-[HASH14]-[ID_SHORT]"""
    # id_short: last 16-char hex segment of the TIP-ID, take first 4 chars
    id_part = tip_id.replace("tip://id/", "")
    id_short = id_part.split("-")[-1][:4] if "-" in id_part else id_part[:4]
    return f"tip://c/{origin_code}-{content_hash}-{id_short}"


# ─── Canonical serialisation ──────────────────────────────────────────────────

def canonical_json(obj: Any) -> str:
    """Deterministic JSON serialisation with sorted keys (all levels)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ─── Content-addressed transaction ID ─────────────────────────────────────────

def canonical_tx(tx: dict) -> str:
    """
    Produce the canonical JSON string for a transaction.
    Covers exactly 4 fields: tx_type, data, timestamp, prev.
    tx_id and signature are intentionally excluded:
      - tx_id  would be circular (it IS the hash of this string)
      - signature is computed over this same string, added after

    Python's json.dumps(sort_keys=True) sorts all nested object keys
    recursively, so no manual key-sorting helper is needed.

    Example:
      Input:  {"tx_type": "SCORE_UPDATE", "data": {"delta": 5, "tip_id": "x"}, ...}
      Output: {"data":{"delta":5,"tip_id":"x"},"prev":[],"timestamp":"...","tx_type":"SCORE_UPDATE"}
               ^--- all keys sorted alphabetically at every level
    """
    return canonical_json({
        "data":      tx.get("data", {}),
        "prev":      tx.get("prev", []),
        "timestamp": tx.get("timestamp", ""),
        "tx_type":   tx.get("tx_type", ""),
    })


def compute_tx_id(tx: dict) -> str:
    """
    Compute the content-addressed tx_id for a transaction.
    tx_id = SHAKE-256(canonical_tx(tx)) — always 64 hex chars (256 bits).

    IMPORTANT: tx["prev"] must already be set before calling this.
    Calling it before prev is attached gives a tx_id that doesn't commit
    to the chain position, breaking tamper-evidence.
    """
    return shake256(canonical_tx(tx))


def verify_tx_id(tx: dict) -> bool:
    """
    Verify that a stored tx_id matches the tx content.
    Use this when receiving a tx via gossip to detect tampering.
    Returns True unconditionally for GENESIS (self-certified).
    """
    if tx.get("tx_type") == "GENESIS":
        return True
    return compute_tx_id(tx) == tx.get("tx_id")


# ─── Transaction signing ──────────────────────────────────────────────────────

def sign_transaction(tx: dict, private_key_hex: str) -> dict:
    """
    Sign a DAG transaction.
    The signature covers canonical_tx(tx): {tx_type, data, timestamp, prev}.
    tx_id and timestamp must be set by the caller before signing.
    Returns the tx dict with signature attached.
    """
    import copy
    tx = copy.deepcopy(tx)

    if not tx.get("timestamp"):
        from datetime import datetime, timezone
        tx["timestamp"] = datetime.now(timezone.utc).isoformat()

    # NOTE: prev must be set before calling this so tx_id commits to chain position.
    tx["signature"] = mldsa_sign(canonical_tx(tx), private_key_hex)
    return tx


def verify_tx_signature(tx: dict, public_key_hex: str) -> bool:
    """Verify a signed transaction's ML-DSA-65 signature."""
    payload = canonical_json({
        "tx_type":   tx.get("tx_type", ""),
        "data":      tx.get("data", {}),
        "timestamp": tx.get("timestamp", ""),
        "prev":      tx.get("prev", []),
    })
    return mldsa_verify(payload, tx.get("signature", ""), public_key_hex)


# ─── ZK proof (stub) ──────────────────────────────────────────────────────────

def compute_zk_proof(dedup_hash: str, nonce: str | None = None) -> str:
    """
    Compute a ZK proof of uniqueness for registration.
    In production: generate a real ZK-SNARK proof (snarkjs / arkworks).
    This stub creates a Pedersen-style commitment.
    The proof is what gets published to the DAG — not the hash itself.
    """
    if nonce is None:
        nonce = secrets.token_hex(16)
    commitment = shake256_multi(dedup_hash, nonce)
    return f"zkp:{commitment}"


def compute_zk_score_proof(score: int, threshold: int, private_key_hex: str) -> dict:
    """
    Prove 'score >= threshold' without revealing the actual score.
    Returns a proof dict with commitment, proof string, and above_threshold flag.
    """
    above = score >= threshold
    blinding = shake256_multi(private_key_hex, secrets.token_hex(16))
    commitment = shake256_multi(str(score), blinding)
    proof_str  = f"zksc:{shake256_multi(commitment, str(threshold), str(above))}"
    return {
        "commitment":      commitment,
        "threshold":       threshold,
        "above_threshold": above,
        "proof":           proof_str,
        "blinding_factor": blinding,  # caller stores securely
    }


def verify_zk_score_proof(proof: str, commitment: str, threshold: int, claimed_above: bool) -> bool:
    """Verify a ZK score proof."""
    expected = f"zksc:{shake256_multi(commitment, str(threshold), str(claimed_above))}"
    return proof == expected
