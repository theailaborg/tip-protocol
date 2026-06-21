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
        "vp_id":             "tip://vp/US-a47ca857e68d9b9f",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "afcb8f9db0a9afa04c706126b05d6a83d552350e64eb1db688ebc164104d0a6c2c753def4d808445c8c8754f834cc74b79a0892387f28a4879bd8d36e57b220ecb762dddf12945b74d64ed1f01a87a6021502f96640e5a45d733e632739a6f0a71e78d8b3efeb96fb4c088c0283966b0ca283ad5542251911f89a0059079e0a42eda519c16c15ce84d90fc85e9fa3254e0158a175f6a049466d5b12dac9ba6fe4103a4860132d43d5c5b34a1fd599c6a0d0241543363cb7253547f4026f72e5a940c61dd811b21f366a89e425ce474cbb8c37125304a576e3bf15c327e18d82ba420d326b4455e594b791fc398d10907486e271402a037841cc698b05e8b9cc529c52494f806ce6d97cd14b1e8229484e8dd391526986a5c82db4fa2c5b3bf1034013ea7cad73250ff4fb3bfe3cc7c3168e25037b411b14b0b82cfcb956c8a57e6fbf19c3b4a56aa9d698e66bd133583c9b92c5cf8584894022b1054ae757b7a32c8837b75dca480ab8af6997c3da2cc61b2e813a823de4699f9567cc2c8181f372ac3abe6b7e7995df466205bb72d37c5fc4342d06a79bb18931b189fbee970978fc1d794ef95dc20ec33879a95c4074f2987b9455fac598d6ab3e686068bc088150352c45f8601858bd98fd03334d5e8359e629ed40d46cb80a3d9fcf931a2bb30a926012daa0dac878cbda1a790250011268a7125c4f676db3b9f613b6735848155d5b5451a18d672fdacb9608e8d11e3728fdbb968606fc3b9ffc11e540b12d77a2722e3a7df4e1ce8ea8cee007e003429186af795e741e5c1f626113dc733f1130ae3b55bf8b3455bde90c170ff58da4ee99e49d8c489a95f4d76fcf2dd3ad19d47e990c09ec1fe2886e85e295f808d2840afb270306394cee97c729d06a8b14e0c8dd4d4b95b6f37126d8c5c9707d018b042546669fab369d26d8a08420a9e1f847813206bac3033adbfe6a4f0a5a8139dfa3148c4dbad6b693ce108982b0459584964adfa3936abbd927fd732b83cd13248688401d3f4c186ae220952b7399328a94e3115730b6e6ad75084ead2414cf62c57ab46b9481e2b8db5125bf67f4d30bc4d723cb563c5b866df9696cc4ace1f85d3194447dfb23cd76b396551bf3f031431a1935af66830d41adaa0838dc99e3feb071620cede5e2cefed4e6e42d99bc5efef437e387d4924cdba37fa12f2c8ac834ff1852d2cac2c894034cc82b77bd7de0500fc8fbe4cee4ba43a9ccb0a55faa6f3448e3ce1c6b916564a4b88b5be55653820f070257a465aee4a57c25eb89a7e026fbeba2c932e2c95f298c411f462916fdab2bd9698cf7dafb6d77d5a63f5da36eb9313e4468ee8ba9f4b4cecc780dc83c5a9b2cfa41aa9c2de55f56e3e0d2473a9f9d32d7f8ed9622949f1fe2263057fc559bdb3ad24f13582e1b1f147907f6a606ff0f8e5bcf624552c99d521304e667c0aa144c49d1e859769e524609d1a2d7de05576415d9c1192cad50b682aeb64744393105d0efc5110d848466f0127884f9ee0279b44ae40257c9857716ba692ebb00cd907289058aff58ab8ca4915dbd059a91267271796f8df55ad936b38cdf71da99424d4b869042966bb215b322fc440a8b323ecc82bb3573ec61594f43e52d97b105bc9e7741b3df627a6d420cbac5fd8a6a71953148b23fc9d197119e5aafec4cf9065b7cd6770487772e62aa34759e3e621ad8ed4cb2388586efe5518e52489f37a719a295470be0785d106763c1cee2726f0ae21f6d982a24020733837ec2ed3afd02879e04464cebe282a528b1e7d38081386993ca3cf953484a4980cce74d0d9b3135e731a0a53a72fedc3eb6a60e3d1b8fa4fd303e44ef83e7615f082e57db1461531491714d751b53a18f3194144634026156ad80240daedcc4d4bbcbdbf7e4e142dc9d1433eb1df05b41d18b41c1e9803f5afea19e4dbd0ea2f76fb151231a1895706659d5a7d502d0e584e746ecf7287328c27161158ff03460cd0c1b0987294d386ffe4998f54f13b22363e786028592ce07332f7c9d025a8072d57fcebaf7178b661a4e00e63ade244b0b463ffcabb193142f5782a4d8bca5b980ec0909079ebd83c3754420f24f346f87117708272ad591043c2c6892b459963b0aeb440b624b7991394346652e83f45351a8a6bbbc7aff3c0b3e05d1f5e2895f8abf44d7d8ab1b67182aa6c9d8c90f11c98e0aff583cba3dcd8fbea5a31b55cf7573e5030db5c6f11a1458288c985880eeb84aa0301295e59e69813b5607570786edc9bbc76159d0ad94288719e1e4e148cc8aeea691e9f308c56c260029017b259262aaab33bd484bde7e3fa3319737b14c5cdb8644528b74eadfdfec2bc993469251df44739b39a66b5be0a825499f8c9bd6f2aaf6e0486090e0ec17b238cbae9cbe6740dab74b1db7e55eff0e71c619d5495e436f17d5c9b77153222ba83eac3b86dfc72f24a7df8e9530bf0c40395c0729a2254632dde34b461f7af569a5b1bb61d1b4bc6b5a19b77c433cf20949112e531ccc31f0ceb70b864be776c536720ad2580f8c0b3b7852b01b24f81e7e0820acb03e873a3b9a7a1f561aae87e58d2e4c8bb65ceba3ecee508c8be816bb85fecf2088f043569974714f36c71a227d77caf23b5108c10fda1703b5f5664e1a8e659dd8acb20f39a444c2fb61264ca29d9f916ca362e5339c827deb93cbddd5db0519ac65f846a501fa0198c45ba8f82674b48a30f0d2c140ac272f5b3182f51503198a312",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-b952598ecc9e7dbc","tip://id/US-73ddf5359d03b14c","tip://id/US-02debc7b60b07301","tip://id/US-59a3dd1ddd4aa7a6"],

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
