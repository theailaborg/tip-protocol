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
        "public_key":        "121cdede62beef724505dfc660bfa525b15de922a7e4c6511e084373c61127ca2d332bf2a06d6e3b7ac0694310561b710e132a689fe1df86fe9bbd3a10fa750e6e9f2ca22ab5fd68424acdb928db5547825611fad74001320407cbc237bd011bcd85f44b2d7667e67f3ba928d1a17437861cb1403e8d6bd55874f4203cf604aadfccb1e73205f91749309e64c546dd8106a285db7eb8e37bb401d4509228f5b676897eedfdc1df0edb42983ba5796ad71910926b9c8e3c6446c465c515e2db3e72c4ee6dcf0b78f589ff1348c5f74771ee157c893042a6667de2c2362acc5150873045b6f394aa4a3fea5a13fb97382902dfc661b157f8270a5c5f1602adb491866cd4bc5a9b910a2c469f6b2d42581a3d244c7718d334f14fc417dea231b3bfc77a9686255e84cad6884272298468bd84093224d532f42e82ddaeacd123013c3a723471ccd7cf630d3a711e836e362e36af937dacd18a2e6ce31bd1461f060d00af45995fc0d82ef456690a2dc4f4f54950af457563c153a278b430c857ffe009ee0b33e0a4f3b1e462a574ea80e5ee164bf8715631c946b4047223f602b44e692a15c06edd3162908acec2c386b9604297c8bb1e52083fc2f2841ba18d0f654b71b745066332433e2cadf1f1e0596a1747fc28f4ec0c7a49594e7dfbe4c468bf63261421b7ae035c22c14f576cd1058be1ee94c0c2aa80953586fa40b4002f008fd0701ad9d1d07ae40aa2586fa21fc01b16c75658b757ff8f06a40e86ecb23ad38ccfd054b49e6a46883d3605c50ca025433a64e0d6a3981cc623c810230eae51bbf3b5933cd592f0fe8c71bf83a80ee0a6273b8e3b9fad8f194b5ee02827c2e521065576f7f0be2f8f0c6f43500607b55370997a6cd59c1817ebdbdd27a58a2e040f9598a8162c8f1387d77d97a830a049f4d5b82220f373b8925243240afdcaccc91f0bdad0298e39adbbf1ddd7369a33e27cf4bb865bfa1bfd29d818a4a2e66d4e4ce3446acf8f2aaff26a31a73e6641afe3d45863fb639ec6d65305a9fd04a9a4afa790c22a9ff3c57ededc6505b4799d41e278475124a0b1e9ab4327d5b2b8b597743afcb6cbe4f4a321ac50b834a94fb6c7e67e28178504548477eb9026ea09466a2ac395159beddc5084d7c5a653cc7ea9433cc7b7199eb25f7f3d6106d96ab55ee5c04e435b9a68159ce1db743899524e5239f5d3b7fe19c28f0efce44737154376d2c3a0471c43a36e911d1c54ddc1e3a61e4185121656e63b0de14ac863dcf598472bdeec2e3b514fee362c87b1ce805079bc513e9affbef6328c12f36bc000925d0561535c9c93bfd5885756d7fe8c7af6a3abea90e7fa492f21cfd7ee468e2d54613549cb34b07999112aad8bf753dc9e4327f963f66d6560d383378ec150e53d159e463be51aa3a674041a9080d254015110582e878b4815549b187f4e16be985bcb528e7e073ad24753bb950bd960fbff868464a7264ff8dc1268bc1da21903689610a0a23e958bb11db2a5092377ba446e06729571935cd35538e805cb32f8e12bad6313daf23b7aa5bc93eac5c78b7a5b2bde485cc02d5fd28fb0c7d49ebb4d9c2911ec203c7ba56d50012dba93daf0ac6fc12c711dfef0af42da02bec608cc50c51cb205c3a1507e4c200ecb2db27f9f6ca552d41b8a49bb98490359e80868555d44e862756066f20f10af5dbe66b05d35e0de4fbe333e797c1349f45c81f69872fc0d4c7ebf783461fa8e3ed6e8d3a0153359f31c49662d09426c051c6d5462f461b1fd6fa0374ae7ae65c829957c500842663b19327972fef278dd25efeac39997ce412870cf3796fdeebd3216cf5ca0feda5bad2b7976908c9ff804a64d0bd3887a3294b0203fc92ce937441ac1d55e8e477974ece6d47a3021951d483d38ce08ca138435528b1932af5605b6077418d3770e9b8f15605739160c4cf477f6acfce9814917bc63ef5af910af6fd43183b5460406c698c547f160479921a5085d623b43f4fa2c89182edff219f414d762f02f697a1b7e9ed52226c26bb09e1c8e20850467f25d29ff3235aae1a5ac304394868f7aa7a001290a23db9cc3ef978e3c1f16963d79d73e8a1ad70cc9f3e867fd934272e9308f6386b9123f356b83857f1f12119ca10239e09695aac088a1a212093b332862bd866cadb937795163bc21723815f23d5aae9c604f3879bf186cd10a977cff2af3ae4e9a6b0d7acb0218e5b13c1dacb2a1adc55e9029852c49b18832d697de00e7afa42423095ec4a37e5cc3edaad54f97a8aaeda28a3eaf8166f287a8ec292722beeaef9b820ef923c85d484f80f1be84fa736864c5bcc62adb882bdc64df865a34402407fc1435349f212c389c2863d8f565772e86b8d78c130fa074acdab605dae47fa4393144968d23e95ed2567ddc5a1c330a0d0067380884355ecec5486a7848e663cf854e4850e900bca5ebdbf139a0888f6a843f864a26674410fdedde73c7d3768dcbb6bbf95b688c84e9b1c81abf5cc7c2434e4c4267e17702eb5ffe362b0b14be96022d7e3b64c30c208bbf98385201d9108e54bfac5032eacc8f691b000e21426c40532be72014fb91b5bea01d696f6a273adf995e3ac814453cded9e97d4f4fb8362f0983e97351af9895a453110e04d385af9983bca7806b7585443204cd6c7c3fdf9718ed16be6b6ce629cbd55f632fada731602db32635fb037f51710d991d57c2fc8ea626d27d6ea020d205b1a9d913b425d9eafd2369",
    },

    "founding_node_commitment": None,

    "genesis_ring": [],

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
