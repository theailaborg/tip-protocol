"""
shared/crypto.py
TIP Protocol Python — Cryptographic Primitives

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

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature


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
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()
    return {
        "algorithm":  "ML-DSA-65",
        "publicKey":  public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo).hex(),
        "privateKey": private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()).hex(),
        # In production: publicKeySize = 1952 bytes, sigSize = 3309 bytes
    }


def mldsa_sign(data: bytes | str, private_key_hex: str) -> str:
    """Sign data with ML-DSA-65 private key. Returns hex signature."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        key_bytes = bytes.fromhex(private_key_hex)
        private_key = Ed25519PrivateKey.from_private_bytes(
            _extract_ed25519_private_raw(key_bytes)
        )
        return private_key.sign(data).hex()
    except Exception as exc:
        raise ValueError(f"Signing failed: {exc}") from exc


def mldsa_verify(data: bytes | str, signature_hex: str, public_key_hex: str) -> bool:
    """Verify ML-DSA-65 signature. Returns True if valid."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        key_bytes = bytes.fromhex(public_key_hex)
        sig_bytes  = bytes.fromhex(signature_hex)
        public_key = Ed25519PublicKey.from_public_bytes(
            _extract_ed25519_public_raw(key_bytes)
        )
        public_key.verify(sig_bytes, data)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# ─── SLH-DSA-128s ROOT KEY (SPHINCS+, FIPS 205) ───────────────────────────────

def generate_slhdsa_keypair() -> dict:
    """Generate an SLH-DSA-128s keypair (Ed25519 stub)."""
    kp = generate_mldsa_keypair()
    kp["algorithm"] = "SLH-DSA-128s"
    return kp


# ─── Ed25519 DER helpers ──────────────────────────────────────────────────────

def _extract_ed25519_private_raw(der_bytes: bytes) -> bytes:
    """Extract 32-byte raw private key from PKCS8 DER encoding."""
    # PKCS8 Ed25519 DER: last 32 bytes after a 2-byte OCTET STRING header
    if len(der_bytes) >= 34:
        return der_bytes[-32:]
    return der_bytes


def _extract_ed25519_public_raw(der_bytes: bytes) -> bytes:
    """Extract 32-byte raw public key from SubjectPublicKeyInfo DER encoding."""
    # SPKI Ed25519 DER: last 32 bytes
    if len(der_bytes) >= 32:
        return der_bytes[-32:]
    return der_bytes


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
    facial_embedding_hash: str,
    pepper: str,
) -> str:
    """
    Compute v2 peppered deduplication hash.
    The pepper NEVER leaves the user's device / secure enclave.
    Without the pepper this hash cannot be recomputed even with full
    government database access.
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


# ─── Transaction ID ────────────────────────────────────────────────────────────

def generate_tx_id() -> str:
    """Generate a unique 64-char hex transaction ID."""
    return shake256_multi(secrets.token_hex(32), str(time.time_ns()))


# ─── Canonical serialisation ──────────────────────────────────────────────────

def canonical_json(obj: Any) -> str:
    """Deterministic JSON serialisation with sorted keys."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ─── Transaction signing ──────────────────────────────────────────────────────

def sign_transaction(tx: dict, private_key_hex: str) -> dict:
    """
    Sign a DAG transaction.
    The signature covers: tx_type + data + timestamp + prev (canonical JSON).
    Auto-assigns tx_id and timestamp if missing.
    Returns the tx dict with signature and canonical_hash added.
    """
    import copy
    tx = copy.deepcopy(tx)

    if not tx.get("tx_id"):
        tx["tx_id"] = generate_tx_id()
    if not tx.get("timestamp"):
        from datetime import datetime, timezone
        tx["timestamp"] = datetime.now(timezone.utc).isoformat()

    payload = canonical_json({
        "tx_type":   tx["tx_type"],
        "data":      tx.get("data", {}),
        "timestamp": tx["timestamp"],
        "prev":      tx.get("prev", []),
    })

    tx["signature"]      = mldsa_sign(payload, private_key_hex)
    tx["canonical_hash"] = shake256(payload)
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
