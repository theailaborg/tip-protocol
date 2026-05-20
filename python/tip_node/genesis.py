"""
node/genesis.py
TIP Protocol Python — Production Genesis Block

# Author:    Dinesh Mendhe <chairman@theailab.org>
The Genesis Block is the immutable foundation of the TIP DAG.
Its canonical hash anchors every subsequent transaction.

Any node that receives a genesis block with a different hash is on a
different network and will be rejected during peer handshake.

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any

from shared.crypto import (
    shake256,
    canonical_json,
    mldsa_sign,
    mldsa_verify,
    generate_mldsa_keypair,
    generate_slhdsa_keypair,
    compute_tx_id,
)
from shared.constants import Protocol, ScoreEvent, Origin, PreScan, JurisdictionTier


# ─── Genesis constants ────────────────────────────────────────────────────────
# These are FIXED. Changing any value changes the genesis hash and forks the network.

GENESIS_TIMESTAMP = "2026-03-15T00:00:00.000Z"
GENESIS_CHAIN_ID  = Protocol.CHAIN_ID


# ─── Canonical Genesis Payload ────────────────────────────────────────────────
# Protocol definition data only. Tx-level fields (tx_type, timestamp, prev)
# are on the genesis tx wrapper, not here.

GENESIS_PAYLOAD: dict[str, Any] = {
    "version":    "2",

    "protocol": {
        "name":       Protocol.NAME,
        "short":      Protocol.SHORT,
        "version":    Protocol.VERSION,
        "chain_id":   GENESIS_CHAIN_ID,
        "spec_url":   Protocol.SPEC_URL,
        "license":    Protocol.LICENSE,
        "issuer":     Protocol.ISSUER,
        "issuer_url": Protocol.ISSUER_URL,
    },

    "initial_params": {
        "initial_score":             ScoreEvent.INITIAL_NO_ATTESTATION,
        "initial_score_attested":    ScoreEvent.INITIAL_WITH_ATTESTATION,
        "max_score":                 ScoreEvent.MAX_SCORE,
        "min_score":                 ScoreEvent.MIN_SCORE,
        "daily_verify_cap":          ScoreEvent.DAILY_VERIFY_CAP,
        "juror_monthly_max":         ScoreEvent.JUROR_MONTHLY_MAX,
        "voucher_stake_points":      ScoreEvent.VOUCHER_STAKE,
        "attestation_voucher_count": ScoreEvent.ATTESTATION_COUNT,
        "attestation_min_score":     ScoreEvent.ATTESTATION_MIN_SCORE,
        "clean_period_days":         90,
        "clean_period_bonus":        ScoreEvent.CLEAN_PERIOD_BONUS,
        "prescan_default_threshold": PreScan.DEFAULT,
        "prescan_floor":             PreScan.FLOOR,
        "prescan_ceiling":           PreScan.CEILING,
    },

    "origin_categories": {
        "OH": {"label": "Original Human",   "color_hint": "blue"},
        "AA": {"label": "AI-Assisted",       "color_hint": "purple"},
        "AG": {"label": "AI-Generated",      "color_hint": "amber"},
        "MX": {"label": "Mixed / Composite", "color_hint": "gray"},
    },

    "tier_thresholds": [
        {"name": "HIGHLY_TRUSTED", "min": 800, "max": 1000},
        {"name": "TRUSTED",        "min": 600, "max": 799},
        {"name": "REVIEW_ADVISED", "min": 400, "max": 599},
        {"name": "LOW_TRUST",      "min": 200, "max": 399},
        {"name": "NOT_TRUSTED",    "min": 0,   "max": 199},
    ],

    "penalty_schedule": {
        "oh_confirmed_ag_1st":     ScoreEvent.OH_CONFIRMED_AG_1ST,
        "oh_confirmed_aa":         ScoreEvent.OH_CONFIRMED_AA,
        "aa_confirmed_ag":         ScoreEvent.AA_CONFIRMED_AG,
        "ag_conservative":         ScoreEvent.AG_CONSERVATIVE,
        "mismatch_2nd_offense":    ScoreEvent.MISMATCH_2ND_OFFENSE,
        "mismatch_3rd_offense":    ScoreEvent.MISMATCH_3RD_OFFENSE,
        "factual_falsehood_minor": ScoreEvent.FACTUAL_FALSEHOOD_MINOR,
        "factual_falsehood_major": ScoreEvent.FACTUAL_FALSEHOOD_MAJOR,
        "device_compromise":       ScoreEvent.DEVICE_COMPROMISE,
    },

    "founding_vp": {
        "vp_id":             "tip://vp/US-6d0cbc4f960657bd",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "88cad5c44594bf4280a16e6d23b2eeac224a33e93d7635f143a86f7bd7ce0dcdcdb6967acc21f42548131642db2b7cefdf752d13c028aa0d1d07f3a8ef98581e73277e931b42f94f871a3203013199649324a9748649a8682b56e99a3f9f776bc940acc77cb9a7ce8725ae2170a956aeef2a1233e23a56771b243f378c68258926f4f147e36d40030c066edc6dafc7534954060af1852c8687444ffc0146c4b7f5817c20ce67e2e1aa38185013cb2182120828809c92ad1d76b54ae14625dc8c43ad3edb05e9a06d8c410f78b0b951e72dd5db73aac0c767bb890f866233f5eddd34870941608f1e784db3565530b323712b2239effe9d580c6f5cfd4c8000a669672bbece2d9a89a66ce74b3b8083a166ea14bdc3fd51fc8859d208ea765d8e3a247bb0187b7eb1f69e7d28a5be394e7ec72929dfbf9c14cf0484b982e1e98e0dfcf014aa65d58604058d7fb38220380bf52bc0f75048476e48a5d631f6870574e797e9318d52a93eb0187d5b9bb2c869dd9699df3d0859315efa3cec1b74655e35bf5d050dbc41dbe5d486c0c9405b4f95aa59d6b379b2d111135cc75789881ff139eae31bb0837db8d007f705c7800be79116255cb9f5d6f2c23d87a5d75b586ade93f1a6e13982c05fbb6aa6e52510e53a0866b16089fa6645e324261391caabec193fc74c412020488ee08a1865e2aada24a7ec1e9525813270857e92b396069a4c6c97a90ced3ade70804965a5c192418bab799a9fe235e44888cd9b2839acaa6692a2ae5d87990e08eb3ed7cd6b874c9ef7a08a9916a415df698b96db489ff2a27b5dbe02c630794c22cc3cbeea47937519305c3c09aec7920bb334bb9c2ce94e51be0607d13e639a503dba0e4649387e57339affcc8ad793bf9acf58190c825ff6df5c12d18a8e20cf22533c3eb3e8a877e556c9892f4bf66cc6de0120fc73309e788f8ffb08ef6d874c98b756cec4cb9bd1cc2a0bee7bbf57ba3ef725a042f2b448bfb06ea805e14d74f6b1ddb0d3a73d50ca77410a220841c646764804ab884ef37a47da52e46568a3d61419e4d621a22db1b4563930b6079dcc6eea9b389a92f85f993b9ec1737592140dc0810203a550c2d4d997e7bad82655182f98c5f7df08c6f5817ac5049aae4e984eb817daa30e820635e0fd759c8931f2893e2e08cfcad18061e114939fdce664aa35672b58d8785a0a33e94a6b329b2fb1d80d3d6e09c7bfcbb2834a6b39a2c91248789c6d999f4e84925d99466f0a6c4d9ab926c69a0d0a4f90db13ec41afaedd3f1755802f2153b53ec0137dfb3a56b2268e9bbf32330cccb1154b842eb7c4043a1612e97c0d09a055b330f9d4dc50e05f97c8c3c5c36f2b6265a22dfa90b9d005eedeaef7d5ebcfd15aff1ac221a974027054b024bdb4c18ac1e1e667f254d9d5d519ace3338766c5428986ec51ef93559cd85fd7d6579f7b7f3903db6fe91976e285eb15effd5d59fb97b1f99dcc4479d0c05bb6181934d6d74a5ad39803a3c83d034e37b8754f2d8a7c2b9a5722a6d7a4b51be753a7bd5e40897c6819e91b79cad8d8e08e7e03daa6ffe00fd4c21511a9a163607f5fc0d9bf0596301b67f8936eb3eed2f45ae1a9ef86c174eab07868555a8159f202f9c731262e21b59db80eb9ec9ff054e3b29a0a744b15cfb2d2d875ad24c581fd6ad0c30dfecca636e539333611e3485f63ab80ed5c2b89f1977cda90a082b7bbaf93dfbaf69c24cb304dc2f304c09e2558358ec42fbe3e889cd7556b3f05d342b68f3a6bc543a4a473ecafed3d89d90be2ccd883666354ea00f5e5da604d08d817ffb0aa799740b19d23d05337584d585ac387c168f9cd7a04ba7a1b85269a81c3ee8bbb38d05df4df4f416b1873daf496e37c3712e6e6042dafbbfbea3a476d5fe99aa794e26db6ec4c3979f10466878b5750af651f6daa054fe90f0e9689f5e498f28583aff8534fefbaf8475ed739aae47ae8346b45fefc44e14a13fb8c829b28d7bbb04b2c573fa21c390ef2152ba4778da4634135fbbc18afd991ecfbbca9ac9abd01c34494525605a15544c5e3b0cadedace0d0730c60b31e09617ccdf044f097e46ec2c4cb5d168d46e09ced6afdaef7273535a8c480f4fdb1f6992b07005fae832e83d9c380e83d8b563f625c0c01560c7f441f1ceac18062601e9a3a8d029537c4c61b06fade44c4c2e5101c1a397b078e10e4dab155f6fcc2736b797f6db2e2c2f5d5d38d057158d00efa7337aec391ac884290d014bd61bd62a05c6822bd89e9ce12cdab30f13d3ca95f0bcd9a71f140059f293b0edde541eb5815b445f2ddb926c290b61b23db72005dfc02337535650be428c60fae85098501f0055a646857c88e22389f3420b2aa7b923fc8d1886f5234008066a5a1cd426e148f0a1861e69c48bf462f7a47c2bec553b59cd5db025bea587049cc43591256571eb0f82eacb6833e9f388f1b76c01da5d449e4d85d0f7a38cf6268b8bbf526e0ac349babcb8fab2234d3a5a6a7bd53498baca8e483149f06a51be0dfb2c58a5e185be4250d5c71f527518a53d54605ff234b044118ead825bc2f8758770d75be05840cb105b5d0abd102763370cee587cf95c7bea1778a6d1686e3a93508674308855af6632d9d7c92ad2cff44ce7b09a0663d941156dd7eec020d7bcb76051ddb8bf047af2c6e1441d6f5326d94315e95212af275432489222c3b40f2d9b4b36169c10ed4cf25a0c5e47ebd636ce062e18169f0a62b8de",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-9e22c0063bb22881","tip://id/US-5bcffc254fee46ea","tip://id/US-acea845937cbab1d","tip://id/US-59ff599b8c138496"],

    "initial_dedup_merkle_root": shake256("empty-dedup-registry-v2"),

    "notes": (
        "TIP Protocol Genesis Block. This is the immutable foundation of the "
        "Trust Identity Protocol network. Once this block is committed to the DAG, "
        "its hash anchors every subsequent transaction."
    ),
}


def _compute_genesis_hash(payload: dict | None = None) -> str:
    """Compute the canonical SHAKE-256 hash of the genesis payload."""
    if payload is None:
        payload = GENESIS_PAYLOAD
    return shake256(canonical_json(payload))


# Pre-computed at import time — compiled into the constant.
GENESIS_HASH: str = _compute_genesis_hash()

# ─── Content-addressed genesis tx ID ────────────────────────────────────────
GENESIS_TX: dict = {
    "tx_type":    "GENESIS",
    "timestamp":  GENESIS_TIMESTAMP,
    "prev":       [],
    "data":       GENESIS_PAYLOAD,
}

GENESIS_TX_ID: str = compute_tx_id(GENESIS_TX)

# Pre-computed signatures from seed script (founding VP signs both bootstrap txs).
# Placeholder until seed runs — seed replaces these with real ML-DSA-65 signatures.
GENESIS_TX_SIGNATURE: str = "GENESIS_TX_SIGNATURE_PLACEHOLDER"
GENESIS_VP_TX_SIGNATURE: str = "GENESIS_VP_TX_SIGNATURE_PLACEHOLDER"


def get_founding_vp() -> dict:
    """Return the founding VP record from the genesis payload."""
    return dict(GENESIS_PAYLOAD["founding_vp"])


def get_initial_params() -> dict:
    """Return the initial protocol parameters from genesis."""
    return dict(GENESIS_PAYLOAD["initial_params"])


def validate_genesis_block(block: dict) -> bool:
    """
    Validate a genesis block received from a peer or loaded from disk.
    Returns True only if the genesis_hash matches the canonical payload.
    """
    if not block or "genesis_hash" not in block:
        return False
    return block["genesis_hash"] == GENESIS_HASH


def build_genesis_block(genesis_data_dir: str | pathlib.Path, signing_key: dict | None = None) -> dict:
    """
    Load genesis.json from disk (validating its hash), or create it on first boot.

    In production:
      1. Run seed.py --genesis-keys-only to generate the root SLH-DSA keypair.
      2. Run seed.py --mint-genesis to sign and write genesis.json.
      3. Commit genesis.json (NOT the private key) to version control.

    In development:
      A self-signed genesis is generated automatically on first boot.

    Raises:
      ValueError if genesis.json exists but its hash does not match GENESIS_HASH.
    """
    from tip_node.logger import get_logger
    log = get_logger("genesis")

    genesis_data_dir = pathlib.Path(genesis_data_dir)
    genesis_file     = genesis_data_dir / "genesis.json"

    if genesis_file.exists():
        try:
            block = json.loads(genesis_file.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(f"Failed to read genesis.json: {exc}") from exc

        if not validate_genesis_block(block):
            raise ValueError(
                f"FATAL: genesis.json hash mismatch!\n"
                f"Expected: {GENESIS_HASH}\n"
                f"Got:      {block.get('genesis_hash', 'MISSING')}\n"
                f"This node is on a different network or genesis.json has been tampered with."
            )
        log.info(f"Genesis block validated. Hash: {GENESIS_HASH[:16]}...")
        return block

    # First boot — generate a development genesis block.
    log.warning("genesis.json not found — generating development genesis block.")
    log.warning("For production: run scripts/seed.py --mint-genesis with the official root keypair.")

    dev_key = signing_key or generate_mldsa_keypair()
    block = dict(GENESIS_PAYLOAD)
    block.update({
        "genesis_hash":      GENESIS_HASH,
        "canonical_hash":    shake256(canonical_json(GENESIS_PAYLOAD)),
        "signed_at":         _utc_now(),
        "signer_public_key": dev_key["publicKey"],
        "signature":         mldsa_sign(GENESIS_HASH, dev_key["privateKey"]),
        "environment":       os.environ.get("TIP_ENV", "development"),
    })

    genesis_data_dir.mkdir(parents=True, exist_ok=True)
    genesis_file.write_text(json.dumps(block, indent=2, sort_keys=True))
    log.info(f"Development genesis block written to {genesis_file}")
    log.info(f"Genesis hash: {GENESIS_HASH}")
    return block


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
