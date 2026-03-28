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
        "vp_id":             "tip://id/VP-US-theailab-genesis",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "660433c07225c5e2838f8a6fedc3074d5c8ab0db386810cdfb2c39cba6f69588949a593975bf6d3c2ae253d42ede861861ea0f9f0f0e64368d5b9a3bb43605fe8e4dda6953d505981d60706489dc418c5dfeb05ce6dd5974bf28dabbe52475575c87adb63b5980e00bcbd7ecf8d2640e142b6199b9074d1738eeb6cf27a3ab0d1029a045e917651fd84b5212dca9fd7fc34bc5b613a76e7807560a0557fa910ed92d6d73a4eb2fcc21045107fd5c90f29fb829a2ffc2d3d3991d61de1168d81eda70baa0c63fa289d4da967e52fe4c7361b2fdb6a7237a4bec2e577864671888c98d010eba961b4cf6f7c08279a8dae7b44d45a5021f0f7e47c95c2da0295ebfd901d704401257de6f42a6eaebef84a30e6061e25b6d670b14a86ca9aa8d36e1ea20668bf1e8cf820614b91d5f9a3939716b41d8f7f75b3e73ebc8988b58565f77580cee0baa9879e6b9f07e43387caf6d1408b9e67713dfab19b4bbf6fa0096bf2c3259d80294386a171433853c3086e8345b267ab492e7bf2790d1bab4aaff693dd4c9551054282bc15a6a64c3aebd20fcdec61a405c1c8389017accf194aa83be6b70a18b095f9fb09fb7386214bc2577c9be57a4940f5f371486631e73f4ca9fd29c2bc04452e66ce777c21a9c25efea0b70c6e138d44f7f02a15e7406d5dcd9d805e97c82b8323c9791be44556a5df3b2011c262f4234c9f499c0fd6176b75bd7748c6b944daa786a5d859acc72991a69b2a5479d4433f55ece15d39f545ab3440bc90ffdf8ee511bf54929d512808376b66d59a0bf3c07ac555dff20b032766a8e290da4a21243666351c850f0b8450ab1cbef81dd2fd6ae00a4075c11ff1bcdc36927007bc7ef9457705bc7e0e421e27693bcc50aac8f107894ada5523f2c307510bbd66138a138d1a8ee80071ce81af820cf07247bbfe9b42c4fb7d4aa6515d1d41eda7d2d3cab300f671cbfd9ec8d6dc03a998f09ddb4335503c94b5cb859807262a3c8dfe13a6830caa93c06601707932ed7daf23b7dada29027e9cfbb06ddb3b94afb4b1aec31cad8a8160cce29657b905eac9612abc41fcacf63918e8268db4ff3db69eac0bd062cd800d1c610a75f603b0439f1b582659a8bedb99063705c5d46be34c08966eb627bd2caf731b9f6f975ef1d7304515172ecfaad5a28c5a440c7c4b0f151ca6710b8d97949382cc56a27b0184f0660f370e1d5438ac231303bdb9bb7367663e09ccc3241625496c49d7136e2fe4355fa8b7cd7a041de511cf532272aeb192de5b7194e707e45319159e26abf6913b0eac783ab6d8a95b7413212e06da9d3982a9161d2b38dac2917717d8b2763f28716eaae98d312a4d12413f78b6749cc8a448a82f211ff64d0ee9fd055d709144ecf372dca6bfbdd00b5aff39a68742fe54d667ec177e1a6212c6aa09a238c53e3c62aa514499beafc9e7e7d64982a513d5b5850eaa0a049cd8ffe0b83731adb8de34019d4dc565a3c138310cd511dbaedc76fc9862c9d2851cf62961924aab4dac01881f6364f14522c49381fd9ee9eb697a5acdb9d86de754cdde485922576674b2521b97750326969dfdabc6299a4d91e1ca0587a642f07b68893dbf82aa2f19fa0031d562eee8d6f741b1ec53575ade435ace041140ccfe9db65b353670cd45f6b3f6e52107df77599fc6e8df7a10ac6cadd501d7218bffe19d3a00e6f379ce7458660239b1acea5597fbfbfc457b566c96f5ab1f1e3103614a575af961482f37647a26862765726047e77676a78d4f7a93c8073e3b33cbda865aee483603ad031784b30f073d9da12e0a42750b5133b42a59affea4273080be0b0051589c83f2fa9e25afd0f7e789f24755eed02ac2012e0cade0e0d36e642910bbb680ff69e9783e4d27c3c5ca9ddc7dfa1ca29dbf778248d7ab22587255079694daf1d6ed2e273c6cf1de93ff73ad56d1af0967f86986e1b04505f33fd69b35b2332605e0a22e9166966d1b487aedf178516f44ebc1c084ac96350a3ab1ae4688e240749d401b8104a7aeb884c26ee1575e03b0bca6db4fb35866094cbd9b5122a34387aa2b477d9b0749e2e8f5bbcf62ad51ac150e23c64d61841bc440a38e0727c65cbc0f488999c8fc241cf83d61f3065e8cea565e9799b588dc18ebda7ff29bbcc94be7d6780dabb4e7091643b785ad773dcdc2cde8510961347b79d9090683adab328713c179ea27c6d5a1e0fc68699677968673527561b82d464a102fd3879f590613061d40cce2046a95b6b7cf93ffde75e062e435ef378d2adae66cc01c242a1155828ed138295f4ef75983cc4336dfe29d9b49c0252c8c0130a0e52947958d2e36fe954157139c3c4d281f0243435324e3ce595f81b27770971f27bbb1ce913205ff467898de13c97ba786c6fd3cf55575b18c0de6f5e3c9680b4ddeb82d1b35243022875af55c5cff7f08f34b85029e203d4e48c9d3ce7594f7ccfbb50719d06ded4488adbd39fc7f9e211d206b987482c3e49c71274e02e9fbeb4aabe14794199b2c4c314bec22ad1b28dbee72a1bc0bbc595e506d5dd029c8f5df44b23b007794a51ded22814d101f6fb55c4df51addec39dd8082e7c0e2f9a54c7bbc91c3d50fbc5411565c0c873a7acaa3f48889f6ccb60256a79ce4c5545c6f84e95efc55f67e826d4aa61b001b42dc1e897c1148b6852f553acf3229f333a1aa6c368d447a8084cf15c359a21f6e58522d38bef1f913e30cccd40f1d9b6793fc7ba087f1f8d82",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-96bbb7639f6b5109","tip://id/US-bfd737f1516012b6","tip://id/US-86747549e257c60c"],

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
