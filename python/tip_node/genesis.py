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
        "public_key":        "4487cacb48f993662b6ec7319bd0468cb7ff3a5673e2575004358095dc966310165d068f759a4a9b006d900811d1f4422697cd6f126661236c5fcbb3311b752fd0483a1b9955b85b45b71be3e57e00428d49518cf6e189b94e75e9e48717fc534422694189c37c9eebbd5ca28d97149e1d9d06d45fe7795f9ff08552638acde0697272256d45bb1021609ed9c01a080e9071319a8f8ca515bf409a45260e4c48d7ce219a5c960ff73ac68f9d4d0f2d6c3376d563eebcf1422a24a01b5ba03dda874c153e7285946339db81125b17c6d761e6949575ed703ed776e7f49eca8b04f6184cd921f39e67375bf68c33537d6ab13fc185a78dfd14642549966e5a81ac51f93e30f6e4f3ae0a0ca8b29ed681c4022d6c6ef80e9b836d7e4765489d41cb3a1a7e22e82b6413a6814b893ece9df545b2ddc0df43b412124494a7a1cbd4c9e1694525abf2f55f2ed9d8d21155b55a03a9eeeb3a3e04bf60d67a6925ef5932b2b47a131eca61e34f413f9007440761aad0833c467dc4b2006310dfd23136244646153bdc000966dedcc55bae22b7c23a1fc4c336fdee026f60fe273473b39fac740bc6cfae809759cfccc3eb716364c378b79acef4bdf8419325277f8394e5599f41b90167d0b28f8f4d2b4cbab91fb4c631c56c4da3f4de02706291df128209b5f979c3cf2944f1754501254f0008aceecb5d3cce35a04a713da55582d44b0e7dfeca7ae09244e13cc588648d5ae70293caac9f1354b67698a57edc44396cf1f3d40a75d7f898953975df98dd9e26e67ff66e1a2717c7aea1fef439f383cf78f720a01cbea42bfa1e435f0e8e345ab67717ef60d145fb5b99daee997c103f2762d3b1e6b2d8a4eb8cdeed1136edfd24ccaa399875cfdc05e82b350b18e811545ffd1d36be921a97ab2672574b4f338ac290ca3e496e5ec5be4e810d873612b9474e5c3a2596056c8c4e6ab60607ab64cadf05b64a0edbceddbdf761d6e8e83c5e882d459d0226a54e1485ec28e3e3f625b089084705d6cec2339f2592e0fbf9cc16349003fc966e5eaead52f1fccf0c11a80273961854a1d4802e40990f0d720b37f6d80da2167351bdfe0991a21149ff35971fa8abb0451ad468c045b59aef6ad492eedb652b16cda16eb2c16fbca48ecaeefdf49cb3f113b9f6dac0a57b9c90917d7f9b5b611b327cd03abf47ce256167233beb1622d4f010277f6c3b93dfeb3c959162a9c79d63ddd4ad5c4aeba0479dbe265ca1b319a36182837b2c1b7c82875fc801084c3067fd56aa2e14b25e8fc6bd4b4c9d96fde3e25931150f307bf5297f44a7caa990825cfa06c6580002b48b0646e6d81e6911b7c0ac1d7ed41f5e13e96a2ef47bcfa63adc6ea72e3fd9f1d8c3721597611361b156b10a6fcf807f4beba71b2df75afbbb7adc1c0120ca43475e3a4caeca200ee87e9cf3f34ef27ba7d8d65a70b50ee0e92e075df3ad617e027027812e7b3c027d348da46a12f06f7470c0d766ade9693b62299951c111e177cc60b07e5dea62006b3f51580f53c6836687281135d84c3b5cccb6ffcbdaff42c4b478d297d286b31a37b511680408f9f10c0b2c89e333fe545fe3cab71b5defa3dee2cba4f214f92784994971b2977d12bb5dfee7decd2d06952710d18e54605fd60336f9551110e7eb541f93478f56ff46a33377d0254ff1bf0726fd79deb73e26e1487050335e617ad9b47ba87c125d7cf59ff7fb7e27c8bb1226b2723c3955cf77fbb6f3ce941456a7f5f3e2170097b12b619bcda06223650f331fd4de33587b8a9cf09f4682d9196f224347b2d69852be2688cf8ec02fdba0b25f8b01f948816243d0a7e8d67ab9be13449c777a777dabd91ecfa9c09f9e60641d8c45bafd3c3735e85fd4db97d01c6791ec82e4328764d05d05557adae4ec3fbfbf81c1455e16a3cb06be5832cb48d41c1c7637bf21a1917cf4d7398da410ce55055b875f127d3ea3b5f20df54b8d10546da768ce9498232129dbca87275d687d178e1de58b35b60db0514394bed5664c6a415689a5811025b0e1114b7e6791780e95eb8a5b4653f8387b58be6e0052666a3bd6d9603761dcd143b7bdb7f7462f44d45a08965e4a77a455e86ea4ba8f9c5eed4d3c726ede60572391e83329000d81aab1926f55ca0250eafb6fe96b3973ec567ceafa7b408e959b4f42c8f406071e91901431dd9e31f2fe64ddfb74ff1a3d9f2f323fa7ca15b237ebc041bb6017c65c66c55b9151d59b57214710127f6ab47a8ccec42f2f152080edd3cf6cedf62936221e4ce86b56a0f6e874382abb4b648284b3d2436a289471a7f09812bad19af86517412609a6341faf3c79aacd5c0c491cf43887789ad7b8e0c133b04c1a71880abcf04eb6d0574dc23a8b3c6ad20729a55c0cb6a28563eff89c25d41657eaa807e0ce7771f0ccce9e8e099177eeeaed1e54d3e06d28cdced324d813bd35007a1ace48fe49f809232856e8778941a83df7ce3c9db386d2ccfa9c64b65441581e18c266a3e6c9a49ee0b7a94dd24e55062fde2dd7441feeb381a5537bd158eabb93c5d8cb31a48b94e6508e9861434e0bee82a838d9faade3d56cf35fb411fce9fa5334a3793214f683d57d805fc643dac28a2b525bfad692480b5593d27e26fb93a6808bf70f2678e3d6fce750b05c9864ecf6e45ab505e4fc4b53977546d41bb447d778fd47451312d13ed3c6b18c52930009efee3ee56943272d02cbe61af5d3db110bfc9bb62de1c906b3978a",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-311fd92a53f52427","tip://id/US-a3d909b5b15dc9f3","tip://id/US-2a4ea7e3a3b14aea"],

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
