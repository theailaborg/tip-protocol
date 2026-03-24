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

GENESIS_TIMESTAMP = "2026-03-15T00:00:00.000000+00:00"
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
        "public_key":        "e948836546edde9bf8ad44548e0e322c2b773132739dd9a36b1665715947c04e589bdd6c4003692c748f8868e717a08f2ae3c0d67e49bc05bd973ef6c7dce0ff31152a715ad32f8362ca5d2a12acd2e75c848a2bac044eccb341927f5eb604c31ec09fb5abe1f4360d4cb2dc3d5b8c82fab941c5a880677efe7fa6e85d0ccc3643b7607f434e13268de7a73223d4dbd034ff370333ed80e0804bea519be81fb50dacd3dd0451086277d7ea09285d61b7d881703eb55b6f80c47fc3ce0f6d5e5d7b4e32101a8aaa18ee0545384278996cf0f8621d6911e06d7c67aef9ca5c63b8903795c2054dddbd69565693449e5fbc3567b7e95285073060b7b830a9f76b93ed72d6eb5cace72aee6d2acf8334485e962630056617f5dad912258587282204db6c3dfa2b744af069c874e70e52f876e8e2b820e7c63f6a3b532ff3bea498ad60a276fadf052c47a290f5093e724ab5f64bf7486a4edb0a7f0243e54994b1a835a963d2847515fa09b3df430b271ca8538d0ef4b108d078869dfcd89d17474d0d0346c8a62f2d3d1d09e4b1052047a5d1e60b36052dabf692d74be4666e06819091e03a28ae81fbaf00d1d29e84e64bcfeb4a74b2b35a5616afb9a1ce5a344222719a7ebdc6106e9e92f59419df70993e24e44ac1792199664e1e9d9a0ca5d712f095fcdd7ed784a460cd4ec1b79743d24756a0d93cbfd8a25cc219a1f9d1026250dd7a4e319b2038f918d6f805e36990dd818bd8029324b2055aadd760b20a701c5203cae5bfefb1856f354923a3da9cf11dc9dc1eac9ead221eef98659a69c9b6db36941671e7f87d6abb9878b6902dcf755c6a08e3a9b98704074f4716c89aebb7d410e812f657bddd2124052845c20fbc5840f085422b7dd66c092031c5e05befe3f0280cdff88f662ef6862105f51b795182d85b5a2c7844d4f8e353e425c8919c807159893e8b9c2d277f03badc06c28d16f622700a1ae71db963efbd2ffb1234403c079eff0291b762c58a80ee98cdfe561b072c1b4882b2763102f0be533b798eaeee9df35f276f0188a65489e3a4d06acd604e9c4f4247466386b7d4e95fd66b187232cf9f84c85ef384709539cf365742cea406dc7df52d14dc3a3d8fde8657378e98401074ff511a605da01a5e4622ec5ade2a08a9a799bd6b12408678fefd273090c0b278f3071de8cdcac6eaac7216643a785679619ddd3fd81557b8fc660918a899d05509efdbb2c3d43aab827b8c2abcd17d51db5b30540d069868b1a25a310ff01d30433870792c2e236827c55d243d39e39221a44f971bec3045d8c7fea064e01353654b81a600b4be58a56eb8407607dc30a35fd83d665079eb80a27fb1fe2c92e3ab2131a6b861f66955bc3f63430a98341de4f1df55ccf5385dd7faa448f15aff5fb87badfeb5b27ce86a576d8671b4bc4498a8d263de7747dfb2f13d2a99357e3c8675798e25910d3328bb7b692808a22ccabce1bce7075d44cd9c7cd86a0e3bb2270bb60f1a6c59a61a9fae68bca90a4739f4994caef4970c11291f6eeda5d9840a8ecc8596c3654ecdb62c2de982ab3f62071d8857ef6b85cb2960470fc83142b9c82bc31746196042405ffc05fa674b8e92141de10cacb272f5f3f49a49d20650d2b7c4bcea6e609df228d20c12b1e6a2ddf85459dbb7bd81aaba951d99b7b1c3e34bfa61f8471011c370bad663e8c20c6ea4dd106b1d7a1735f64f8c7ae02cd6ef0f47b2f5d934a50caae6d0e4e0833c2695fa441d62dcd9147a5c8c035c4bea083c58974b3eb84e86224c5008da3d506e5b9cd0fa7e33e33ff076d7ee0e439861c23b89b8deac0b51563fb89528b423966f7113029902eef73c58fbb88b0083875beb90fb0d03828e21ebd8050e83bf0a4a4b1376ef60b6fb88ca289087268541076ed652bfe220dae0b878b9fd667634105ded6ece215bcafa8ed5190c61b6ff405ea0009fd05d8396e011d0d29b50aeec77c200cf2eec69eb0a8062c8de5bfa62fce2d846ab433262497da7d8f22b99dfb6ed5cc5a729930f860a587e04590c053076ffa2bdae5ed147ecf6fc1ee767323ee9eca18225994c767f802bf13118b4b1acacfcc314ab89105b1dd8238c3b369ffe9f36a2d7620b8a4532e5cebc1c94ff32d1b09a2305f1c0a377742f44213d418ecf43374e9a0d35018a83377654941b47aaa16a00519a7923145708ecba9f9a69f0fbf33eb88e6a395041bcdabe2e57b9df8ed33f9e1e0ea2951d7b17bd74e4e4d1a4d90e83e696ce3eee1abba7fb191eaefcd683b7885259e480a0c72332db59aa2cccb3b08715ed15fe4a3943801bc055ddaffda93eea4aadad70fc7b061bab8e1ce37ff44a328982ae8fdfb4ab0ab1c96efddb212bd1e01445204d1beaac189b7a153ca771e18887e985fb9a22e22abd26ff1d1c1d897287bb3e477dd862be2277ade3c4d5ed6931eb069b0411cbf52d4a807b2f889459769e28f1ce120927025b127c282b5bd095539040845c54b2c35b2ee48685772edfe5cda701d5babdad740382739717e9b5313260a113de07484564a1ce9d5975124e0cb16ce03c169d575e431a68a53cc390185155d3af92237b1ee4d38d934aab98700d470ec9ab718d5f914a3064a2a266da0ca9db4c1d833ee702e7c3365a2c8c7ad18c2d43607d0fc6c5c224d9b2668dc7fa6a3a485be506b35d1dfe3ddbc377fa15294fe3bebc5851d0a750c29a8db9b06f2dca17fd170bc04f02602443ce07ff97c213e4",
    },

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
