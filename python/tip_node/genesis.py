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
)
from shared.constants import Protocol, ScoreEvent, Origin, PreScan, JurisdictionTier


# ─── Genesis constants ────────────────────────────────────────────────────────
# These are FIXED. Changing any value changes the genesis hash and forks the network.

GENESIS_TX_ID    = "0" * 64
GENESIS_TIMESTAMP = "2026-03-15T00:00:00.000000+00:00"
GENESIS_CHAIN_ID  = Protocol.CHAIN_ID


# ─── Canonical Genesis Payload ────────────────────────────────────────────────
# Serialised with sorted keys for deterministic output.

GENESIS_PAYLOAD: dict[str, Any] = {
    "tx_id":      GENESIS_TX_ID,
    "tx_type":    "GENESIS",
    "timestamp":  GENESIS_TIMESTAMP,
    "prev":       [],
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
        "public_key":        "06c3810582135d9723c5cb5d60cb78393360e283d1b4b80c293f300e43ae9f2b51b18f42dbd2e92dc3b961ae2eaa968b030126dff1e3dc9d68d7b5df094745d566803d1f77bc46bbfad631f6ba46c121da773b1b8c119763698a80361a05435baebe1263c986c9d78cd8a79d82efb30f784ac1240282a80df29926a6ff97822a86f81afd4bb32e55dc667e51960064294986c1a1a6eff408228979dd00ce961d0edcbec1307f3d654fcb36151a75d5907f3d0f7b403d89ed6bac113148fb0f30f6e8a6426420ac9f980514642f5a30659a81a3ea154df87d605cbb5b5d54ed91f096df55b9067ffaf793b7df3504ac9272bdfce6b34ec6e119a379aec3196a6e37c94f6f184cc2cb845a9f5f8cd38a9999b71e39aaa60572c2eda2b89da89ff537329287132bacfe7545734be67f63b6a70697b704ca4506537ab119d128f3c4a4efae5c364fd97b63a03e85dae0aeeea7ee69090f61ecebe15b64d170ccb5b3ae2fc9025f3c26fb3c479948e06bd2d363a332e2bd1cb7f8dc5d78911067e9e0757e8b5333350937ae2612c7ebf15570b014526aeb1a09d32d7b06875d3bc3f7b5a78f423ace93693bef9608e1854d5f1d6c8b0da57c5865b0bec78e82b11f0661e2fef50d14af3955eec1bc52688f84c4460422074a36839853739e164a12c612b720e7cc1fce9dd370ec4a8301a2ffd381b91239bdf449b88ce29399a14ca47416aae162c9e30619189e0ded79948e61956b8b136e24c192bff7dd8d20382af3cbb7898799e7c0b2c624db56666bbf5cf4fa6f990dceb6d404f639c98415c4d948da7fc36d3eb27828aa48b738e86f843980437e69bdd35cbe5626a464eeb67bfc5a335ae77908275c08706ace198de68af210340a16f0ff5f73c8cd611e8d38d6d00cd1f49165a13417f5f37d5301a9877f0be49528d8801402cc0384068bed897f1cd481ccc3c1a0139c73f7f19cb22bc21100dd2ebb84510597883076f402102eb610a8a8901b36d27a29fdb3c57f8e33e0346e9a929ab8045ac95a8eef344956fa20022cd1e30ea4b5d8bc5f81ae5d35e343f0c9ed3102293d65499955566851938415be3b888578ac611764e83c86aa6d08cea004cf4cf13bb6eb82e4310c30fc7704254c7a09e2e6654bac21263c07291fde5cc67a7e325d14ce919922df8fb9beb43a3567dda62e517f49ddc153694dec3531bdb044600f31d79e9fddf29789cde10bdfd113b839e66e98282bfcd9ff6505fc12c1ae0a31ed5a9692a0b7114a52f6b51de4c1f4dc520c2014256d302a8cf7a2d180d0f67f618c30202770e8b44a4880d4eb0009d07ff6357f7396c1233fc630560d632b72d4fb79aebf232a751da1ed8217290185109a24a821fb4d304ba149cc216770841ce5bd8e804bf4d153de0fe735eb1bc3aab8acc8db6cfa9b2b28a32a40a68d24eed651cc881cef9ee313fd69d52259f9915d67455ce5a06f7aa29e35df52e52bd388187da7ff41ed390820dc1d2125789fd5ffb9f27534da6a812c59255a10c36fb5953b4e74653173de901044b5976129b01bc1ecdbeb9dfd6b2775d4953bf6673bd05b4052f9b5b628e513868aaa7ca1bfc77ae54901373086cdd98ac7aea9f557cf5318e015fe692a74231ce1e190a12db9a971055e61e020444e398be68ff87fb4db47ddf13e8e52eed48f4fd89ef00946a432fc87871cb8b71382a9904b0c73a1ed91e1aa9bf41a32d4a73bb6380b222ec0dd1f55b749048ed45057e13c58bfe40929c293845e99335bc9ba3243e06e9ee5be6d3e08a4a84572a2d46d47abc3fd4df96f23a3d7ffafe89fe265984b8b748f48b53304eeaa074a6b520bc4022d29b78b322a102104c50e57ae5a2bf4574f7e2de03f53d9277bae13dd7e675ceaf169948cd7f5018ec5cc30e4d238e67d4504cd4c06b0b51a3ca20b99d19bcb12583576e1e8c7885859bdc75906814d151e9d777dc2112d262e63fb98c44cd49b1e6a1255d35322740bbbaedb1ab05d44ac5bb4b808c141ba4a59693af231fbc62fb08bfc55dcbeeb03ecabcd4412dffd0b1d5e36845f83e4988d4cc8f74658d47bba5a06d98cfa1a97045b5170f8437f807cae61826225743d4e41a334c756e6ca8069e613fe9093c8da7475974b1d29a4eab52add9cba680f364badf73a240c8151573e256acd14e8c36196452e70762d12e07b736a3c707f6955ff853b692e2a85873ae869d02b7c2bdd97591b3ddc9c2664a0f1a0b981b03e237c7d68a48849aa2e7f119fc8f939c1baafe6e66999b72e95f58fdbe6c95b13f0056c859b756001e55eb9445d0dcf5e467d6620ef1cbaf7dfd9da6830e5773d04f1774386b4c0bf401c7315b7c2afe39577c780b66c5a829368c113a4ddef58784738c1c3ac397bcc4b546542c4b868eb08723f78aabc5a7dd5d6a49042f317369e99261cbdb8925114158d6676a3cef298eff27c5c6253cd8afe6166fe3b9a36f70c1d294afbac3c9f51ad1d480bc6a6e1501d78966f03de6c9c5c41d119e8fbd754594a5c3a8547251642125aa04e6ac5d2b1cecabe929a5d7fcf0b2773b45320fce295714fe28c372ead3d873453a66599a1707c75f82dd1c8db4664031f5f27e210cf686e1ab220bc2d9ae818ad5845e6a1bc4848c5430b71d24a64b057d9f11c5ee165432da4ecc46a8d1e0ee0bca5c9add69a66a3735e9819c4ead75c04b768660cc71ba9db2d5704b5dbe1ae2f83344213e79eb578254e583ce93fde530a5554c6a766b4",
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
