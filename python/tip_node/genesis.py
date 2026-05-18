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
        "vp_id":             "tip://vp/US-dd6c5e085b0f8bc3",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "2bf781932149ce378151534c1002a20175b4af0ff6ae332c4d2c53e585837c6c9fd60ddd5817dca7c1d2f20479e53328cd12429c29711fa8f3357f28f0c6c9999d24a993fb28ec9283d15cb4eccc7feecc6f97525626e11d712de86992575fa0e7e18dff08a3ea6494a26aaefc5339513793e62221235a359518ff125b2f3b92f4778b0568310cf61df33dd84e60763d35fe6892af53b39655b9c4f944273f9469090e73d1c987da20ca66e68a8e488bf45eb5ce514aa9fb8b9f4322487faf92f2103142634ef3af7be20a4e2a0fd065c18548305cb06308280af2260578dece6e219617cecee4bef913c947c7d9e9549c6479337f2c6190fccc0976c2cbdc69d804b8f78a6ad3ef31aab20c950484ca084dcc95d3923ec37f61ccc8c9ea21fe86e2868bd82003b58f08de333ca6c1c30c1c3fd572af2d66190d5202f189e28ac804822d98451a54edc3c2a7dc755806094ea0e193119715c4e6fbd1d4f8f2197c170b722d653bea20721529a4aaeec5dd1886d9d2baa5de8916088c582d100aa5cdbd69eae20ebbfd004f96c608cf7cbdb0213243891862ea1849f501d0b7c279cad92eca1f34fcde9f2cce43e844d4d1e12dbab843bf0d4a68459f6182da380aa5d7526e48aab18da2443f7143ad53d081658373f7cd8fc788ff30b611e5106d326078bf4b3056e05bcc7427ca606393f77a258382796c13cf84155e7eb723bcee9a442453397fc085c8a56c1d24945874afdf44e82dc826007a19d396708380d734889599bd7b53116d27b9af051c5c9384f4f2bbdcc41a34010ae0553ff74b50780088e844a3bcda7b2e4c4194ffb798447c89a02d89ede5f7327bd5361adea2f2d933b85e6c0ee9b0470a8e47411a2fd3dad9dd5b8145ca38dbf9eb9e0b31c952641ff96e535811c11c374feebbc752313461a102ac460fbc55e45434a77c7f6b0b3bba38d7dd1b222c29ec5e966392c632320124fe7e89a7c08c06519e523b4e2e7acc492689999d898ab6e6ca4cfec49f85bf955e9c57d20d264be13b6556416707697e58f5608751fd830a32948045f306844e5f4ad07d6eb81eb45cd76fba7a16bdc43c8ab6bc6e2b1fbf21189d32dbba39f24976ec2852d96f61fcdbc8a0a513ceb85e69ceacb7483f372b2c63e3504fd4c8808b5803661fa37b7635250dcbd28baac18803f416a48aef697c8ace97a706c7f3d2f052cb19c09b32f934f5f45467d7b025e5e17acafb18b606973dcf901644a30695cb330829b9a32023c2dc4f7bfd56ae1335e25b6a574543f8e6f58111da1f92940e3ac4b0c851a11d586817d8d959629c9b6b7f380afcf4305122926b788826d6fef3882bd6a91761e6866123917e4d39617eb6f3b64523027aa21d52fb908d21cd02bab31bff599fe5bc98ed131a90a84287bd70928ec3cfde9468842e05181e338741ef4dccc06f42ba050a8556bf6896c85fed9a25e0afc1eff06f1019318277f28bc5c1b0deedbced417fae7698920816c839fc8f6c8d0c3928946af815e499af0703ba9efa2e96698898de02fab3ecf09a3b6dd39f8f1d75b7f7c730406db6f18601d7edcb71f572e42ab5a3c932b72d482814912465c247ba192b36c7b5b0546dd7ce64dbb7fd89652905f50aef5ab0ba4a630ee8a2d4eb5269d70569d53e280e37e53c7ece391874f0043946b40e69417a9de19db88be1a3531e7c0b5bcc6dd11998c9045a86da113b237d9ef32cdc969e10180d1604bfcc18dc0b01b9b4d853c633c669c80426cbf4f76643e4647aa032683ab5d6ec18a87695ecbc8ae49166c4a0193482a29fdffcd163bc702093e5e77d5c2bb6fde83de76f0da61e60007e1bc0b1238527422a24ce10c3ece4b820a8de3e6a8bb0372dadb05741d125240aa40384c98393647a6fa0631507d24c32eb6bb9334922260a04f32de3d69029d5c6cabef90d6ab05cc275fda60b26e57bc920a78ba3c6d4e78d97644778e5ddfa46630f5b56390781d5402cff9049e920b19418d2905abee6bfe1ae479c840d93e2d10ecaf35e77f0c49ae2985d316d72492b66598f2d35159d24e78712cc40dfa2fd40bb9f28b62716dcbab6fa629c9598626e2fc21e48e26db9bb52d4e4fd227c08c697f2c37d9a3e3a8826ffb255e0313e7ff02096eb46cfa31ac7570966b58ede97c6dcf09c6f2d32b0123a254b351eb68f2e0a9570a77da139315e8bac9ea26b7a92acc1b0f0b9aaba6484552b5c0b2cff4b8b71b24061a26e729d41d96e4fab7bdd9fed29a8d5fa83407c5db8908c7aa4b1d520aa685b37e9545099db342ad4b7086e3921558e9f4b932c94b60d4c810eca2e7a03348d61c38ac36f91d2ce3281767e06a3d9d918f742f9e4fb2321f14c5b8308fb7de8e5b4566be866f9399b299a1af49f9b0bbaf154a5d4db5ba92709f57055f0c3bee37a565b536588db0a4d3bc89a02d45f528171b4b46c18089baa10d4d672231956795e87ce0c2fff31378b38608d3fa023a26f9c2e410160a4cc8edc4f62e6ce1b84b9a05254b8fc5cd65d0f2d7e5246f383e0fcdaa5eb4a06bb7f1775552d3189d2c2409b436fe04f150c4f3becbe5f8e7e77d23d53f6e54d8c53a543b88ac9f67aa8513512ab6bcd0209069f525d7717e5f058f5f9d1e58fe08fd6685dcbddcb126c8358de8e2007075e50526799a1d989e4deaf5583516862f199b91e44bec8daf0d751cfce7f4b8dacfc4b17e356ccf4ee621ae05e3655a46f44c6d420f333598e0d52671f5f9d65",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-602145d4f714393f","tip://id/US-1d31ad6cb3ea1d1c","tip://id/US-92dc73984b1c8c8c","tip://id/US-c7a97b26711a37ae"],

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
