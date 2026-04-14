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
        "vp_id":             "tip://vp/US-21f83caad0c077c9",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "b6f2ff9c76d4d6e34c97b30d080b0ccba1749f9f9ed6cec15723e68c06e3f593585b53e6b0cdfbe50bded7746a93cfbd1523bab9a720549894383df39ecb53baca8359ef71b60028125f192b10fbfa5131193db13cdd911d767b06469e130f067fcae5a99920bb3ae09ca7bf9eb30e8d27d5015e38506106dee8fe903d2411f4c78c13ce147346c3f9f6183465d4856a12a2132f326daccb0718bff5c5580ef43e643b488747981080dfb0e17eb42c096283f7e2bc014b555e3a7c347800acfe50a5cecd664998d0edc2475858804eed63c809a562604b4ead392c26f9e8bd5fe25a1f6a138f4fa2b9255ea5682f23f5edc28841842818295d7296e7cd22953f72f3c049a977085fe016e211e7fc7729069e320fa87def04048f8b2ac0ab240be4b9cc84a7c7f8ee0dcd6ac75922b697ba9c8029d6f3028bba824f02debea79b70dbac9a4e88642d2b982c5fbd987c8f4a2ade4be7e5dea66c804d01c939cfb36e885936e70f04c84d4102a4f87257149b867349ed954ba9c52b9b24fe173ab72095f6e1c2de926c725741dc056554e3754e0342ebbec1245effe4c392971a615225a12431f3d465059db23012c7ac321ef71006f0ec3534605cd970dc89f0cbdc9795a88089a7796fb9c495535faea96dafa3a94fee6e3d2fdcfe3351ac538be332e4961bfbe2a12d9db7140439c359fc44222883b80dc6423c8e87e1993ae06cdd40401a84aa45a2eeb794dc0cc1157e457747321871359ab80baeb2e7f4ebec44f621bdc35039971ce83b891a066292caaee6c3c8ec94130f012b42ae2a04220c45fc28795030c9376b5a93f6728d3252abed5853b9acd53b55d03da5a25f164e126e7c856d351720361479b08020e86694aed1692f29d752dfb8b8e0a5fb7e3d1161a74de59f4bf1b47af5683eb5c93bbd224b9e9174133b715fb691d7a2022ec917e3545dc6ef5eec53aa5a8bf88dd5ce81d0b250de7c9f47601fcbd2f9d4d1b076c00506b9bca720cf0b4063904496209f6c0e7b056dc65ab3a2cedf04c6c9f3bc5a4a65a92d5f024b0c301eba19e3fa53c9ed621082e5278e45fb296f293133708ee775b14a1d2e425dcf59f6ce8eb2f8ac0f61db712c5d381a513d90915602a5ff24f53f023da7c02192d03bd84a93d6eea60f3361486f153d9d2524c02e653afd79b47b755637d920f3e2ab90ad952b3e4f9c9e358bc45174508dbd2a3ec744193d8560a40eda104b68ba71601b780516896a819b1067b20baf1dbe7867fb729fa47221516f3964a91d7abd2505289c4666823f75ad16983682c87e4a6403d368e835de2c9817fcb155ee85da28f539f5701c18618c8287c78371d4bd9a7ef39ef7a9b46e889eaeca8af66bc677f9c8142198e1ad7b4a66dca4f37562147a79b9adeb5f18c3b296a1a6ee452fa79da8d792fc7166c47c1c03369d0846e6a50328b4f63da523283be62720c69fc50a08117ba6152b5737ba2ee09551f938044299cf990dc96a8fadbfa3e411b8e75f0d00b82c983ec568c0754ba352a0926f8f37a3b9e1de06a6bb5006d2b2868feb55ea1eb4f56ab6a9b148caf2672938f4325cdc126571caa12672877424a9cb1fbf912b4502a27596ec910f79d59ddaf57a1bf27504220ce8a88c147fde6a6f5bde35888c8527cc0926fd9237100d09f9455fe9b7581d8ac8b0b2b94a3ed980631af6de5cac9fc18d78ee627df71c95eaca1c5ccf25c50f2307e60c3616a22ab5dad5f6f58fc01d02a29a04e2e67aea41c2ad5d6fdb55520d7c104346ae3bccc23dfe7c566b1fe99a22b4d924719d9d7b1a0966e484ab567934057332008e4bbe4a844a11e0fc68901a0d2cd117b3323bbfeb38fc88eec3cf19d647c39e83959a66b2cd8e155012ac3d61e94e8cef58b55fbc4133e68de6317c22785492edfa9f3f99a34e24b5a09f3ec621b1786b218e17ffd6be6d4367b3bd1fc3b6294f6291b5562556280b62f8d1483f9a92fd75d979d35df316c448a4e8dd9236df2718d1bf01f3a10da35c52343a16054bcefbe03cda1b1b7710a4f3b93334aa42d2a4cfff4eee60d7f02c5ada7c34a9e31d94573e87b1d86260a50c968532c0e13fe30afd9a68abcb418e7d02263430c65c8fe0a066e34f5af94dbd8967083632c4ffe9d8c67512b971601d2df89f890f59b49ffc52b3e29704a8a5c432cc2c3c1290fbacf025d208245dbcebed479eae48a04ab66feb9caa9a561dd8f318c416f5a089656b4fa0efc2f7846908c308dcb6a1946ac36c6f1067bcab412f7fbe285adb10debbf3a271b374bb01c728e1987f31ef94ff20346cdd5fa1757503a2e6cc40326f83dd2a0ff92243acb22feffee9bf41475d5b71db556694cc3add7cc1b5286563eb328906c6efae0dfc056678d12fa7863abdd1236fce9cd68815d6a331dccf18df0b06654dfd1754f97248c6cb4c1bd230ecb19d1bc9bfa0294959055d1c46f71f6a6c50009501ac8169c46adf2bb9decd7a7677cf0bc12158919bd2484dc621e64d3cf74ccb59fccdcddc0a5c48174655577ecad0699c351df6a8301e6e914481d7fb753093721d5df67b75ad33ff4af1fb36d9828fd527cad7c218e52feb6b890527b51df306acbca44c908bf442b4f90cb5419bd7c9e212512b3883c0e7fd2ff35c801a96f83109ce9fbd9e2a14cffff2c30375b0a153fa17257d72cb9cbaf6b4cd52096c40175477003c2f365c84e9f268e4e822e75476a3bcb24baa9f60cf4e02268d577ee4d99e8ac6",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-c0e4e450d940415d","tip://id/US-23feda24f9924319","tip://id/US-ffcb19ea211e78ca"],

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
