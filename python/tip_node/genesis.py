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
        "vp_id":             "tip://vp/US-8c1675d596e68736",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "65d9067ace8d3bb21d53cc759f498f4dc40c8913b8fcf3c3399ead8c5889e5c1531aeac0c8c483700685c3862f0d63a64ff1a84080a7186720db02c6321dbbb17d614b7295d282352c5467da34e3d5de0ded3e96f880710e15500b4b21c60b5c755c4fd35c0f95225dc3a2027cb8e27bf6c886af9f54be19d2c3923da9c6a847d248c42be89795e29acf44f2de75412840e297f5f0f7be34002865be9907d24ce96f0c8e6c8db0b75df2bb8894a6cfd8b04a69d164fc46dc358a4aff760664b89ca2e9d7bfa20dcab119eef60c7bbf376b8cc5f12bc0724358c313a9394cf602648d27ad785ffcb2fd34ac6128b7b9a325238736f030ab79cedeef51c27750706835c3d4fee12d010bff97992cd860ae18e62c596c3489d7f3967b617c15fb3cabd04ef92af98b2dc006ed83b0fe7acab513dc68345fd4566d6e88fe3b220758d88942f276691b1d84f9f9ff3cec775d1c6acba1534caf1e4460885034c72db6c49ab5852ccd17359e84b29ffa3be9cb558320d29cd65af5bcbdb30baa4adbb61ca7be20a32a9ad4cc2714788998ad21ec0bbf88bd604e9538a94c368b56dbdcc8cf52f2f5bb0f075d3bcba2d528037b562d4307acfc0789dfc5444d4dbd3d5e6b83d75dbc69224f561f60d8435160abe076eb87739af016979c896fa7b558af7f088d6ba3bacb243856d5a60eb4f1aa8080d718286fd6f27557449c7c0c9800918a361ffa05ccf50be57e59dc811f8176ff94e8c0141da619e2ed8131260b725b50a22278c9a4da750668815471785ea311af019d3d1177bc1904ddda63e5db6ad391f0bc6178d7cf20206827bc1b4b6f7547d0c471776ea7295b801aeef558b75c850276d83dadf094d4a10e830af9c33496b1bcd89aec2477b42745e07440a1faf3435f67f79781307d5a0feaaf185e355ca25b46b9a84584c6af406c6d88cf14a134244ed8cccd74ee1b1b4e6db6a196623a9ff11d6431a47fd22cc613ca24d516e8c31a0c63969f550515a6daa70f77dd3314fe68a21728bcbdee570dec90b9445472edbeb23d1047b063a7fe265c70998df322deba25a7526ad9abea161c82ab14afdfe03199adefc9491d0f63f39c2250af7218bb63263849faab3e0003d52761d149e7523dc7e45f27240ffd33d4d2c03cfbe88a24c7ee8ff080df85113c42569a2d60b99b3d1f565e2fa05b4ce5589c2b2d2672011b69c4340d3688ffe749628cf1267b424e5c0fef12472ee48bd220556a0b813c80e742fdee17d2aca0264dc500e6a37f0ddc300d385e1b0e0551fd6f8d355b98f22e6ec559a9f06cf92c406546ce2b8c6998d81d2cd0f446ff714a35eaed09ad7677571b1796f7763968a2e50cd379338bf0e473a00ce4faf04d895125318ba066b86a9d31515493b25925ee80ce134314530a98312e98c82d78075884a2fc1a9b5917f4162dacff71e0a69dbcb124296a813b117e506d4fce0478168b0d55441c08b3c500bcfff372e7f84a15c70c2f88218b8df2d80185a1bb1ab42d0d6039f0b6ba72bd38e98fa5b6f6b64d8e371095e5d3604ea79a64d384c7c8aafeda06a6862052111ba18c3050043e7e35ec87e3c3773dc0d7d081520e451be1896b6e57b111f8d1fffa84661ab6c8893884a505d984d588c4163812a55db920de1a9e2c381e35a9b337c065f0a949dd755c98b96425a71e97729834e3dd7a914904b38d3c27b5d6fe7ceb117e45e2cfdbd705bbf66503e83f3772b864886d0d1bf3795598def884c35c50189568d3896066d82aa0fdce7ec51da7d29cfb3cd74c6ba25b7771c1219ed467cf4e96f8cb6e21e506b839ec23b65240d7e3c9cef33d288fbe024310984f3c8d080eedc4ecf4244b362cca495f75dfee8a672c245afdb52133dd4c5bbab352f8638a50cf84c272656e356e05c85044568617989f7c5d1e86157efc85c41d445a182ed571375406571225fdd5a54f3c1eab03b33c502e5bd806b8cca51891d77fff196d90873cdc09717409f07de1636a411aad1cef3bcacb781f998bd6e9c5099528e3db9d4ad6c1d94256cec12f7c9770d1eb8af88c662434fb761dfe26764eb5f527ed8868bcb0cbf5caa0a5ec2d0f78ab785289842695f793985ca07dd65edb25ae35daa23ee0789709b5f89754eae67d7b54b778ca4eaf227747a0ffaf3865634eeafab94ddeb96fdc705d7ad51c3d57eac69ee5f267b696e4d0e8211a9136197b8f2466c3840e78b27b9bcb167e81b79bb9016c02390363722b04b7f443513b18832166110713ed21e9a053821a981d86612cbadc925f4bf874dcf208487f0de6730e0ba7bd7f7e37d1ded70dd93e4a75c97b1216c42e6700f6e30f36ae106679992c9f929b6e91c9b05d482daef794acd64f93c581c41983824ffdb48eadd8ce4f059f9f85327006ec89de59792f3155cc4729205a0949212bc44509eb2f7fa5b76024c2b74b917a59ea74c4e1bd77c4fc45a36640f8a040cadc382c8644af10ec2d1b5873d9a2caa96300f804360e277e7fcd019f35ebb41f4d30941ee0bb2d58cdd4fd160dd57163e8bfea4381d73f4f102f2de76e3730c629f8d5ddeb53660dd5e09832aecb2438d31797460c441df0a033043825a4e33644ed5a6b27aa3d0225f83b07230b106a5cfe424bc32dceb544479a4aada87ff690491f1e2f1155fa9a986e06e9d30f3d81e454ceff8e28e8f1a0158703af1e2dde2b2ca36b2c2959afc91363e515cebdbf74a89b7bc9643fe8acb2c00e89b1480fcbd2",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-5433dd0aaf8d3391","tip://id/US-982eefd8aae14e3a","tip://id/US-aa49ebc66eaf00f5","tip://id/US-89065f4ca41389d0"],

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
