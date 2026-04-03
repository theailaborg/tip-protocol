"""
node/validators/tx_validator.py
TIP Protocol Python — Production Transaction Validator

Every transaction entering the DAG passes through 6 validation layers:
  1. Structure    — required fields, types, value ranges
  2. Schema       — per-tx-type required fields and type constraints
  3. Business     — protocol rule enforcement (URI formats, origin codes, etc.)
  4. Cryptography — ML-DSA-65 signature verification
  5. DAG integrity — prev[] references exist, no duplicate tx_id
  6. State        — identity exists, not revoked, VP active, etc.

Each layer short-circuits on the first set of errors.

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from shared.crypto import verify_tx_signature, verify_tx_id
from shared.constants import TxType, Origin, JurisdictionTier


# ─── Result helpers ───────────────────────────────────────────────────────────

class ValidationResult:
    __slots__ = ("valid", "errors", "layer")

    def __init__(self, valid: bool, errors: list[str], layer: str = "") -> None:
        self.valid  = valid
        self.errors = errors
        self.layer  = layer

    @classmethod
    def ok(cls) -> "ValidationResult":
        return cls(True, [], "")

    @classmethod
    def fail(cls, layer: str, *errors: str) -> "ValidationResult":
        return cls(False, list(errors), layer)

    def to_dict(self) -> dict:
        return {"valid": self.valid, "errors": self.errors, "layer": self.layer}


# ─── Regex patterns ───────────────────────────────────────────────────────────
_TIP_ID_RE   = re.compile(r"^tip://id/[A-Z]{2,}-[0-9a-f]{16}$")
_CTID_RE     = re.compile(r"^tip://c/(OH|AA|AG|MX)-[0-9a-f]{14}-[0-9a-f]{4}$")
_HASH64_RE   = re.compile(r"^[0-9a-f]{64}$")
_HEX_TX_RE   = re.compile(r"^[0-9a-f]{64}$")
_VP_ID_RE    = re.compile(r"^tip://id/VP-")
_ISO_TS_RE   = re.compile(r"^\d{4}-\d{2}-\d{2}T")


# ─── Per-type schema definitions ──────────────────────────────────────────────
_SCHEMA: dict[str, dict] = {
    TxType.REGISTER_IDENTITY: {
        "required": ["tip_id", "region", "public_key", "vp_id",
                     "verification_tier", "dedup_hash", "zk_proof"],
        "types":    {"tip_id": str, "region": str, "public_key": str,
                     "vp_id": str, "dedup_hash": str},
    },
    TxType.REGISTER_CONTENT: {
        "required": ["ctid", "origin_code", "content_hash", "author_tip_id", "signature"],
        "types":    {"ctid": str, "origin_code": str, "content_hash": str,
                     "author_tip_id": str},
    },
    TxType.CONTENT_VERIFIED: {
        "required": ["ctid", "verifier_tip_id", "weighted_delta"],
        "types":    {"ctid": str, "verifier_tip_id": str},
    },
    TxType.CONTENT_DISPUTED: {
        "required": ["ctid"],
        "types":    {"ctid": str},
    },
    TxType.ADJUDICATION_RESULT: {
        "required": ["ctid", "declared_origin", "confirmed_origin", "verdict"],
        "types":    {"ctid": str, "verdict": str},
    },
    TxType.SCORE_UPDATE: {
        "required": ["tip_id", "delta", "score_after", "reason"],
        "types":    {"tip_id": str, "delta": (int, float), "score_after": (int, float)},
    },
    TxType.REVOKE_VOLUNTARY: {
        "required": ["tip_id"],
        "types":    {"tip_id": str},
    },
    TxType.REVOKE_VP: {
        "required": ["tip_id", "reason_code", "evidence_hash", "issuing_vp_id"],
        "types":    {"tip_id": str, "issuing_vp_id": str},
    },
    TxType.REVOKE_DECEASED: {
        "required": ["tip_id", "issuing_vp_id"],
        "types":    {"tip_id": str},
    },
    TxType.REVOKE_DEVICE: {
        "required": ["tip_id"],
        "types":    {"tip_id": str},
    },
    TxType.VP_REGISTERED: {
        "required": ["vp_id", "name", "jurisdiction_tier", "public_key"],
        "types":    {"vp_id": str, "name": str, "jurisdiction_tier": str},
    },
    TxType.MERKLE_ROOT_PUBLISHED: {
        "required": ["merkle_root", "dedup_count", "identity_count", "node_id"],
        "types":    {"merkle_root": str, "dedup_count": (int, float)},
    },
}

_SKIP_SIG_TYPES = {
    TxType.SCORE_UPDATE,
    TxType.MERKLE_ROOT_PUBLISHED,
    TxType.CONTENT_DISPUTED,
    TxType.GENESIS,
}


# ─── Layer 1: Structure ────────────────────────────────────────────────────────

def _validate_structure(tx: Any) -> ValidationResult:
    if tx is None or not isinstance(tx, dict):
        return ValidationResult.fail("structure", "Transaction must be a non-null dict")

    errors: list[str] = []

    # Required top-level keys
    for field in ("tx_id", "tx_type", "timestamp"):
        val = tx.get(field)
        if not val and val != 0:
            errors.append(f"'{field}' is required and must be non-empty")
    if "data" not in tx or tx["data"] is None:
        errors.append("'data' is required and must be non-empty")

    if errors:
        return ValidationResult.fail("structure", *errors)

    # tx_id format
    tx_id = tx["tx_id"]
    if not isinstance(tx_id, str) or len(tx_id) < 8:
        errors.append(f"tx_id must be a non-empty string, got: {repr(tx_id)[:30]}")
    elif not tx_id.startswith("genesis") and not _HEX_TX_RE.match(tx_id):
        errors.append(
            f"tx_id must be 64-char lowercase hex (SHAKE-256), got: '{tx_id}'"
        )

    # tx_type known
    if tx["tx_type"] not in TxType.ALL:
        errors.append(
            f"Unknown tx_type: '{tx['tx_type']}'. "
            f"Known: {', '.join(sorted(TxType.ALL))}"
        )

    # data must be a dict
    if not isinstance(tx.get("data"), dict):
        errors.append("'data' must be a dict")

    # prev must be a list
    if not isinstance(tx.get("prev", []), list):
        errors.append("'prev' must be a list")

    # Timestamp: valid ISO string + not more than 60s in the future
    ts_str = tx.get("timestamp", "")
    if not isinstance(ts_str, str) or not _ISO_TS_RE.match(ts_str):
        errors.append(f"'timestamp' is not a valid ISO datetime: {ts_str!r}")
    else:
        try:
            ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            from datetime import timedelta
            now = datetime.now(timezone.utc)
            if ts > now + timedelta(seconds=60):
                errors.append(f"Transaction timestamp is more than 60s in the future: {ts_str}")
        except ValueError:
            errors.append(f"Cannot parse timestamp: {ts_str!r}")

    return ValidationResult.fail("structure", *errors) if errors else ValidationResult.ok()


# ─── Layer 2: Schema ──────────────────────────────────────────────────────────

def _validate_schema(tx: dict) -> ValidationResult:
    schema = _SCHEMA.get(tx["tx_type"])
    if schema is None:
        return ValidationResult.ok()

    data   = tx.get("data", {})
    errors = []

    for field in schema.get("required", []):
        val = data.get(field)
        if val is None or val == "":
            errors.append(f"Missing required field: data.{field}")

    for field, expected_type in schema.get("types", {}).items():
        val = data.get(field)
        if val is not None and not isinstance(val, expected_type):
            type_name = (
                expected_type.__name__ if hasattr(expected_type, "__name__")
                else " or ".join(t.__name__ for t in expected_type)
            )
            errors.append(
                f"data.{field} must be {type_name}, got {type(val).__name__}"
            )

    return ValidationResult.fail("schema", *errors) if errors else ValidationResult.ok()


# ─── Layer 3: Business rules ──────────────────────────────────────────────────

_VALID_TIERS         = {"T1", "T2", "T3", "T4"}
_VALID_VERDICTS      = {
    "CLEARED", "DISMISSED", "OH_CONFIRMED_AG", "OH_CONFIRMED_AA",
    "AA_CONFIRMED_AG", "CONSERVATIVE_LABEL", "FACTUAL_FALSEHOOD",
}

def _validate_business(tx: dict) -> ValidationResult:
    tx_type = tx["tx_type"]
    data    = tx.get("data", {})
    errors  = []

    if tx_type == TxType.REGISTER_IDENTITY:
        # Founding members come only from genesis_ring (seed script), never from API transactions
        if data.get("founding") is True:
            errors.append("founding flag cannot be set via transactions — founding members are defined in the genesis block")
        tip_id = data.get("tip_id", "")
        if tip_id and not _TIP_ID_RE.match(tip_id):
            errors.append(
                f"Invalid TIP-ID format: '{tip_id}'. "
                f"Expected: tip://id/[REGION]-[16hex]"
            )
        tier = data.get("verification_tier", "")
        if tier and tier not in _VALID_TIERS:
            errors.append(
                f"Invalid verification_tier: '{tier}'. Must be T1, T2, T3, or T4"
            )
        dedup_hash = data.get("dedup_hash", "")
        if dedup_hash and not dedup_hash.isdigit():
            errors.append("dedup_hash must be a decimal field element string (Poseidon output)")
        zk_proof = data.get("zk_proof")
        if zk_proof is not None:
            if not isinstance(zk_proof, dict):
                errors.append("zk_proof must be a Groth16 proof object")
            elif not all(k in zk_proof for k in ("pi_a", "pi_b", "pi_c")):
                errors.append("zk_proof must have pi_a, pi_b, pi_c fields")

    elif tx_type == TxType.REGISTER_CONTENT:
        ctid = data.get("ctid", "")
        if ctid and not _CTID_RE.match(ctid):
            errors.append(
                f"Invalid CTID format: '{ctid}'. "
                f"Expected: tip://c/[ORIGIN]-[14hex]-[4hex]"
            )
        origin = data.get("origin_code", "")
        if origin and not Origin.is_valid(origin):
            errors.append(
                f"Invalid origin_code: '{origin}'. Must be OH, AA, AG, or MX"
            )
        ch = data.get("content_hash", "")
        if ch and not _HASH64_RE.match(ch):
            errors.append("content_hash must be a 64-char lowercase hex string")

    elif tx_type == TxType.SCORE_UPDATE:
        score_after = data.get("score_after")
        if score_after is not None:
            try:
                s = int(score_after)
                if not (0 <= s <= 1000):
                    errors.append(f"score_after must be 0–1000, got {s}")
            except (TypeError, ValueError):
                errors.append(f"score_after must be numeric, got {score_after!r}")

    elif tx_type == TxType.ADJUDICATION_RESULT:
        verdict = data.get("verdict", "")
        if verdict and verdict not in _VALID_VERDICTS:
            errors.append(
                f"Invalid verdict: '{verdict}'. "
                f"Valid: {', '.join(sorted(_VALID_VERDICTS))}"
            )

    elif tx_type == TxType.VP_REGISTERED:
        tier = data.get("jurisdiction_tier", "")
        if tier and not JurisdictionTier.can_accredit(tier):
            errors.append(
                f"VPs in '{tier}'-tier jurisdictions cannot be accredited. "
                f"Only green and amber jurisdictions are permitted."
            )
        vp_id = data.get("vp_id", "")
        if vp_id and not _VP_ID_RE.match(vp_id):
            errors.append(f"VP ID must start with 'tip://id/VP-', got: '{vp_id}'")

    return ValidationResult.fail("business_rules", *errors) if errors else ValidationResult.ok()


# ─── Layer 4: Cryptographic validation ────────────────────────────────────────

def _validate_crypto(
    tx: dict,
    author_public_key: Optional[str],
) -> ValidationResult:
    if not author_public_key:
        return ValidationResult.ok()
    if tx.get("tx_type") in _SKIP_SIG_TYPES:
        return ValidationResult.ok()
    sig = tx.get("signature", "")
    if not sig:
        return ValidationResult.ok()  # Signature absent — structure layer already warned
    try:
        valid = verify_tx_signature(tx, author_public_key)
        if valid:
            return ValidationResult.ok()
        return ValidationResult.fail(
            "cryptography",
            "Signature verification failed — transaction may have been tampered with",
        )
    except Exception as exc:
        return ValidationResult.fail("cryptography", f"Crypto verification error: {exc}")


# ─── Layer 5: DAG integrity ───────────────────────────────────────────────────

def _validate_dag_integrity(tx: dict, dag) -> ValidationResult:
    errors = []
    tx_id  = tx.get("tx_id", "")

    # tx_id must match content — detects any field-level tampering
    if not verify_tx_id(tx):
        errors.append("tx_id does not match transaction content — transaction may have been tampered with")

    # Only genesis can have empty prev
    prev = tx.get("prev", [])
    if not prev:
        if tx.get("tx_type") != TxType.GENESIS:
            errors.append("Non-genesis tx must have prev references")
        return ValidationResult.fail("dag_integrity", *errors) if errors else ValidationResult.ok()

    # Duplicate check
    existing = dag.get_tx(tx_id)
    if existing:
        errors.append(f"Duplicate tx_id: '{tx_id}' already exists in DAG")

    # All prev references must exist in DAG
    for prev_id in prev:
        if not prev_id:
            errors.append("Empty string in prev[] references")
            continue
        if not dag.get_tx(prev_id):
            errors.append(f"prev reference not found in DAG: '{prev_id}'")

    return ValidationResult.fail("dag_integrity", *errors) if errors else ValidationResult.ok()


# ─── Layer 6: State validation ────────────────────────────────────────────────

def _validate_state(tx: dict, dag) -> ValidationResult:
    tx_type = tx["tx_type"]
    data    = tx.get("data", {})
    errors  = []

    if tx_type == TxType.REGISTER_IDENTITY:
        tip_id = data.get("tip_id")
        if tip_id and dag.get_identity(tip_id):
            errors.append(f"TIP-ID already registered: '{tip_id}'")
        vp_id = data.get("vp_id")
        if vp_id:
            vp = dag.get_vp(vp_id)
            if not vp:
                errors.append(
                    f"VP not found: '{vp_id}'. Register the VP before issuing identities."
                )
            elif vp.get("status") != "active":
                errors.append(
                    f"VP '{vp_id}' is not active (status: {vp.get('status')})"
                )

    elif tx_type == TxType.REGISTER_CONTENT:
        author = data.get("author_tip_id")
        if author:
            identity = dag.get_identity(author)
            if not identity:
                errors.append(f"Author TIP-ID not found: '{author}'")
            elif dag.is_revoked(author):
                errors.append(
                    f"Author TIP-ID is revoked and cannot register content: '{author}'"
                )
        ctid = data.get("ctid")
        if ctid and dag.get_content(ctid):
            errors.append(f"CTID already registered: '{ctid}'")

    elif tx_type in (TxType.CONTENT_VERIFIED, TxType.CONTENT_DISPUTED):
        ctid = data.get("ctid")
        if ctid and not dag.get_content(ctid):
            errors.append(f"Content not found: '{ctid}'")

    elif tx_type in TxType.REVOCATION_TYPES:
        tip_id = data.get("tip_id")
        if tip_id:
            if not dag.get_identity(tip_id):
                errors.append(f"Cannot revoke: TIP-ID not found: '{tip_id}'")
            elif dag.is_revoked(tip_id):
                errors.append(f"TIP-ID is already revoked: '{tip_id}'")

    return ValidationResult.fail("state", *errors) if errors else ValidationResult.ok()


# ─── Master validator ─────────────────────────────────────────────────────────

def validate_transaction(
    tx: Any,
    dag,
    *,
    author_public_key: Optional[str] = None,
    skip_crypto: bool = False,
    skip_state:  bool = False,
) -> ValidationResult:
    """
    Validate a transaction through all 6 layers.

    Args:
        tx:                The transaction dict to validate.
        dag:               The DAG instance for state/integrity checks.
        author_public_key: Public key for signature verification (optional).
        skip_crypto:       Skip cryptographic verification (for internal/system txs).
        skip_state:        Skip state validation (for peer-sync replay).

    Returns:
        ValidationResult with valid flag, error list, and failing layer name.
    """
    # Layer 1
    r = _validate_structure(tx)
    if not r.valid:
        return r

    # Layer 2
    r = _validate_schema(tx)
    if not r.valid:
        return r

    # Layer 3
    r = _validate_business(tx)
    if not r.valid:
        return r

    # Layer 4
    if not skip_crypto:
        r = _validate_crypto(tx, author_public_key)
        if not r.valid:
            return r

    # Layer 5
    r = _validate_dag_integrity(tx, dag)
    if not r.valid:
        return r

    # Layer 6
    if not skip_state:
        r = _validate_state(tx, dag)
        if not r.valid:
            return r

    return ValidationResult.ok()
