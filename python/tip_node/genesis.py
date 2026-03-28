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
        "public_key":        "9970c1232f47fe14117f3e62ebc0c4ec3556c15756a442bb67c4c8f7df384797c7b951a5f195bebe0f1423ab6300e66ec025f5f9b89a62228a8194a3ec00f6867c5a642f0a497ac760104804c0a0a13e9656ae08d5137abc7e0544cd678f9d410d328d8d440e1b2347f218d91eb5c9a525625af334728cfea8c4990232022222bd3712fe5b79f018cd59c376b81d0e75283570d8a79b3473c25a00376103429f24ad5667a370aae4fa3afe3947fe6b81d88570c2cd38cb2b2221300cab52d36a31d4da5c83f2a865bec5af28d76635d811859fba5fe61446893a281973dedcfbfd776bc1161f5cdb4313838fea8320f0c1842c45874c0ae8a437dc822a230cc94464ae07865d40a80552ad77e470429ff3cdd76ecae656f4caecce9a61915255454c8da761d8de8bb41931b94e140fd87ffd0897855c25fb1ce129bacbc1e0a8d87ff7f754bc00968335a92eb653c4920bd7fe8644e371c415bcbfc534a650c6854dffd68ba6d59e06c8b34b311da411e2ae53d9d84cdffaaa9d79859c1705432279716fde97d4fee6fb34f88f5d0968065cdbf5b3ab940c1ebdc69415969f65a655670529c6702dc31eeca96cdcba12fa2f8444913f81916bfd39ed17dd89ec43e00f6269b709064ea8f8bd31d2c3aa82ab5aa0ec40c2b5e95c7f10f9f30ee48a5133110150b4b3c2f0fafbd2558004c2d291b2cd7dd8012492ba7c862a397889caf3a12f3cd77bd5182c7ec8d0dfc83397794a514cbf559026a0c74a1b6079c6ce4c7c4b484a273a8fc5a82963851ee5cf5c46d21e22a699ce07485238c3f1b820b33ccdfebd3e55191a07c2eedef4ddc86403d958a54a1b13b66e42cf11657d1e00032cd4c21aa3763c60f8134e9e176583ef200dae19f821704fe80a74653119256938fee784c164ee18e67d22e631da2b75346415820492db053339e5ddf71b06f84d3bcecf0e7b95f329f7748fcc84923f616271c717e53ab0fa4d35ff2ff133d608c6b6c623bb86023882d5127bcc2948c939f2f1c4c29bfe91c2d2b00c9c92bbdb82f8a64f00e5dcfdc6878ed4367e999ccd05b788ac5a73709c8bf8700aed9814727538e17a5e6e4195223f464484284d8b433765634aad2f104490f7989e8ff2e103b1df2fc27264f2195498254337ea8356c058143dd7c65cf14f4049cfc6201e9317cf7bfc9fe3cff0cc6608dc841ef829be4d2b9859ce5ecea5c95bd88b0fbb444dfe07d0a873d3ce09fcc0d065ad5ff2e1f8efd4604da440a77db85fdb7b3e1e2787b6eaf167cef0b92bfdd2e6d47a156a528e4ad969c0698b88f39a7d5b317c121f5ab5152fc089f333657ce11a7b3c2f4284e1d0c0bd8f075bc2caa57002464a76ed2f412aa28a34cb741f606d13ea212cf18ef2d68f1f144306c55c4da831f05b8439f78d9092a7588d5ab18b0273af47b3b5394188a0ab9bc6f8cca735d63e8fcebdda44e27c4187d9aca504dbdc711e62e7787b2a6636aa02a985bda89d0969f6a91a641a12e5798a38a41dabe484bffdbffb26bbd48b335f785755f8869ff2bac0813f7ed535264609f10143aea6ef2440f47449a030226a948b8864ccf33a6d367021ae3322acc24ff7f34632dfc9fa1fd5f45662c27635912a76a3d0d580d18c6facbb95b90521e35c2bd5c27a798f9c0977991a63f1f969459adb7030311df0fb71f977ee2aba0d7cc348d61f340e5a76d7c45b8c3d52b10d1abcb977ebd73433464a6a554e65c654f72efd1956ed57fd4e456d299c24c8960e4c72b2d3d92b004bcf8d1d257dd3745a59a5f47dcd9f93f50ac9cdb2795d52f94a6d302e7e322fc2c11c08fcd7ce393797eb96665bc44744ce99d92088bdd97f3055e3d76cd4f2f29508e4d54824558f555c2d6cfc4e5c8b2832fbfea6f4212861972d11e03706bd4d676924eef91e93dc46839cdf38eefb6339143abdc79a659fc6e94161b8a4007ecd9e90fffbcb4a063ecd7e09f212f4955ddcd2bccc16f0c7309a8193d8c1a1b9c3c5d9e04c562dbc90215d6424afe6067c9a520f3340f3a3a887c91c583d56a4acf76cc53f8c96a76a47a525aeb7fce2f9f80a09d23c5de892f9d32b6e10e4a1a5f72785e9e23eec621366acf2adf3ec7505e40d93efcdcbaa9e3e28f79e19b722ec2d54d60458c94c6cae68e7b5dbc895da8ba3ee8a8e6cb7c6933b502631bfdf323c7070c3ff148c0bf9311561447ee704f6db1f98f155e203b890ff888e9d94fc993a2b6ad574ac6f9e3b40dc76c01565eb2ff8c4869d50229bc9831c54e1f54b30dcc9b042f39983fa76bf22ec76e2a103fc99b2d44643b32a4a436efa79f5f17a73af7c12b3f1ec3f116d206af50b124267b69a61a021d7b54797342a31db5ba6f62df1810f4a620e927edad065185a22e8d57b9b0618bf9fcabb7975116bfd25dbbcddbe77cfadaeb288a43965bdfb0a0754eec2f4a45ffcbbdcf42085d9cf59f4315ac4c082c5f57e42899bd49b23c00cd95e112b19c9e00fef4675a6535b688ad092f5ca416b95378b8c1645fc9a99a15837417eac91c232341ca62f141c57d92da1c1283dde3464b9efdd784c3cde8204676db2d37c659d5fcacab29261a8efa6a2697eeae5974cd2d0505ea72a9ae7210b77c5ca6c5b9b5521bfdd636b70613558f427bac48565ac1410ac63ba3e3e7de85e6b785696bb187f541157498ef8d3293ecc409082fbc8a88f52930615194d1df4608ff8972f48a0baceca47dc3785e41b9bb8717236e98f79c05ff1",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-7dd93c5d4a2d5deb","tip://id/US-da4abc8937977a20","tip://id/US-19733f308df74ffa"],

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
