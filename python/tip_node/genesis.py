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
        "vp_id":             "tip://vp/US-dbeab0d896b1b54e",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "68e781a72fb2719a6a43999f354d9756d8b1e97beca77d208d1a348283143d0ce904bc9b48d6fb7ebabe1e9a70f4fb3d46120b0d4de4aed0673c4464b86f482239e7c04c3952870d580f112413915633937153af5ddaef12269c6596f772a93c4b1b55790b5a03a6dfff665d817a375cc10cae7b0e5a934f77528f55ef3e4dd853ea00dd0a29fb627cdf02e2b47f866a33ca217ddeaa5c62e9248a7f7927a67c6be32196c5fe5b952cd5d113c00df29853a8f3f8fc70a7c3b186ab854ac2f97923573c4f7500e7e9da4ee1c1d15fc248d21d7897b93de1cca4c9c1568dd32cdea2392c521fda4e22f5a267790e06f39597df63d79781d2262d6a54bee8ef46f79e800071290bcbdd62aad00d0a866cdcf1745d05be16ae87657ed7a0cfbaca4efe6e8a089dd424bfa776d3882d0b655b44d7b4fd484d4a6b078548cbfe169d687e5c4dbc561be579b22e4c61b43aa81e583ab2c99413dcebcee81257fa52d01b105c0fc3fb343d59e9ae64dddb4aa8ef7b9c72008115b108553512ec9c945e1106439d28c5585b47c6a8b5ccbf858b9a24454598db39f827f24cbd17e575f46e05efa786b49631074e4e2d265abbd7edcbf1c8cb133d2093fba64c8f295529f06de193997454bae75cbf9a3892409db5474047c03acff360b7cbf32679fc347a47edf50ec66d1f63dee097b84357a98275e80940747c97eff54cb5d7b5fa87479ba542141bbcaa551d50b6d8b148705b11dd04db66456171bf4db93a27665585e59e79e9fb54bfc2b0177e11c80850e08812a2fb09ac6d10a55769af7e3f0b4f8db1092e1169eb26e2c375e85b602c8cd53426768e531699370f1150c57160382fc8d60333be8d5b84bb71949cfbae1e2e00e81655fb6e7c21dc1d0e1f21abec2b80e94bb16588f265e48f74b2f9c563eb6af191bcefd90303d1ad61c8a17a4b2d263e10d1371541b4e45aa021563e76c6b579329d67e1c9a8846235103ee3efc6af1cd771921666029d343e42bc328b6603ab782cbe3e6ab3635103564e9e0ec9b27f43edbf911b990ed80ef7bb242a25ed04e61af8166c662818d12249fcfb3b5dddadf60021ac748b4dd22b4268cc8728935c97e396a82ddf45fb5dfd857c7d6243e272a395bdd5817c0c5963a1efde4b62f5dea0a1cf4d711352d30739d777bc7a24cebb411536ab1dbbb8da60809fdb2faa9f108166443170ede8f48c99f1b1d2e178814e422b6c301a8a29be2c994d3d9726b239e7eaaff685d8586d49fb03d45bd0424e6c9ef611bf508588a7a08de4bb23a89ab1cf9fdb762fb61acaebd71e75a2506abcc0c641e87a2d863e20a2860f1d01e4780f468574b5b2cfc221d1a2c1bd7e2c0e065e2bbcc94a80d56c2ec77d589552ba85e4419fabe40ed9caac4e4968e02bb32b2197b6d22270742eb47a9d9367d435156f68c400ed7f5cfff73866a0a32af5d51bc5da7e7e6f24471c305f7ebece6608f36da303a722be0e4d69eb97a7361fac76ca2d71a625ece232975101629f063d6f9100b34d561ff000a87bb66cc0297d9b6b2d09ef69f20f360821397d0adec537da66d1455dacb05855277b4775cf3728dbd978a79a86890621ba5fbd2c62045d9decb5cb30228ef87871aba3856d028ffaa8aff112f4602138268af1d204431cc114a06e7a5bd1229e701353c2422d5e7f9e274bbc6461245afde3185e50dcc2bbefd5ca3b861cd238d16ddee19c6d3a7449979e9ad56d39af9b985137d99ac0eac92136e28465c3833c2c793863851078b1830248b60ed114a319a4ed1938b82244bb3b916fb8240487acc65c2bf5c59c95171e3ec1b4f54332d99ec3e9e411e189bd60092745ed5e152768fc8b1348955285f0f196d3d28847f18d75734719ef6a7493f38c2f63f81b326a6336198222d8abf3ed264f6c74f23fd125b71d338a98f94f5e4bf2027abe921e6534decab07f7b9d63314eb968fb90b2752c88dab4b699234d7ee7b4529db9747ad54e6391dcc8d55b15426898d57d6c327ea49ec7c0752f1b7fb29422a08c3d40eeb78b647a9c1ed88d10579614a2cc73d9f9a2e7aa9d31d96899759ef558d4be6c879ea6dd18008b8d0e303b04bc436d774ff98533573fda637a9fb4ed14f282075f42a5db859e40eb7a615df159a4fa87e0854ba4a3ac405531eea6e3d99570b4d042aa2250914095d9224975f8e67fb84642d232b68f5f6c03f380de4b8e234cdd6f10d42bc9fb84280fd4746653c2c74c94117a4e6ed90b832ee2843d4e53cc75f62893c7252ee299c3e0b3c44192f32d4658c81240bc925b3ac60e3fbaf8cee4227abb86ad015ddd3bb655c9adf95d8a53f3b7893b81f01a44ef9612191b061afeb8b091595663cc1bd94100d44b3fba13a0545d1008d67f667d9b04ed53d20622cc184364eba69bd539963dcc96ebf23ce5920c05bc0f1a4856731e6df0991db5eb55aa83ae64efc62b3802fc97e0841f9bf25b2901452930d07fc0e15c634b62feda8b0266ab20e97c291d7b349937c9948b6116be60ec246c94f0b62aa8e68a69e7a83bcfbffb6d11eccad3e384b8ea7b5c53565fa6322ccff4c497e464baec485b5967932f24c07bebc862fb1b17032acf3c2181b8483cf15fd4587eb6df948c012d6dd3a3e850a70d7f744029c9eb9d658fd6014842d09172012dcd530791c208a5a3aac59b71ad6b422a8067bb37b44e3b10915791573eb47a00b1892e2fbad3d016eb88d9ce9af2fe9b0e1e17b386411520ff6b",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-b08378fef9801527","tip://id/US-256a355696b37353","tip://id/US-4b3e107990ba9bd5","tip://id/US-482dbb2b235b58e3"],

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
