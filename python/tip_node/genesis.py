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
        "vp_id":             "tip://vp/US-cc733607fa03646c",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "b3dd073cbce8d89cc746a0c747c205bb92b9ed459913b7e085476611d8db3d4635d4f5de6cebe0d72bd3416dd4108feae90f839e3dbd20a21a7d4f3f957cc991880679be868180af0b261739a06fcc38b87921c766fac20db71e5b78c47f85e1769b254d1562c702b99b2e38fcca20339ac117f5f44a51658d8d9682ebe3d220e3ff5be9e20ae405810e145adca31b8e9198154d7271766adbc41bd95656f1bafc8f933d014156b2af75936cf7e54cc857b63514db264f58a338f3e67c0324f67d19a599f48f25586cdd8f819c00e965dbe70a9eb91c04d928e5bdc25e80763607663dee9ff8ddc0fdf705a3d405807605ac7dca2af3ed9690238a0e800da1316702ceabe426eac3f62a3f556547493947dfe58467f65272d4b0fb034abe8b2034e4ad93d3d59a305b65e0ebefc553132598235458292b010fb0ded81d1c3f7636bc690ae23eb86c8bfae5a864bc4ef3f9892901a9c5ec9b9b05d35fe44d06cb229db3f4939fe936ab4ebcc297fa2e9dcf1f396b5e1f8c81b85e27859977a29f823508073295fe52a7db035873633ab2cbd01f6916593d21085a5d63c7bd84ed15d6912b3a8344bee88feed227ad9886f557a3fe5b3b82817f960c660a33c27a0dc27d8e70fb564079e6d705631c2bce2f67d29caae74d775cd8df69eca9f8f2cf297ba6c9232bef7e3b59b4975cfa0066cd752cb15d4555f3e99968dc421521b9a301ed147e1284e070224c6e07dffd59ba82ff7092eece083aa5fc9322d38b6d25a7bb53ac53a475ded8533a64dd38f3b30d4b2aa25afad6e0f3af79da27ce820b99c0ef299d9cc792230bc641989f454bc759f6ad45bdca69fdb6346f94cbec5573fd5705929cb435e03b1245c3100ea789b77ff76f123ded632a7fda9ce3150bb6757713f5379637961f75ee78946c4dea2f4ba154ffd23c206a0eed551d517423ad261f1cf5ade4dc7abcfe9e13af9f783e7dbd163c8f5d5a3a62140d81bbcf48a96b2263f6fe507ac784852d7999817029d794509facc07aa4d0775aa033fa7fe0d0d7805aecfc501d44e744929a840adb33e9a41aa203cfd8f46b6e14778334170b8f3c2fd36407b17a981c794b25a739b28826c7a04d7274525e6cfcbd181c48a5b34c37c4f5706dc8eb12eb3101ccf13b0cbd88bd6dc8b4eb7be71586dc3677b2edc90b263ce4f1e03a6ed8c9a1d7e3207786c75b47d996610fed4f56ef99398a4ecfe59adbc2cd6f8edc967d8ab73217fc5ff86553624d8953fb843d5deff88dbc962b2cbcd481cfed4c5d60d2369319a57bd2d6abc50b4f1e4b27c6f19962f7a844395b3af2e4139521544f660518e7b479005e38320f1b3e27e2237cad415d91837f7a155335ce3f225cc6cfe806b5b0533239c0f940a0c5eace869d85eb0d65625e5bf817a46cea86b04111d8454d19e198e7387acfb50034ca0471e1046973a7d70446838ea8fb672797f11066b5701fabd85a1d1bb938d3a593a93972114b425bc4bac8443a09c360dd8d514c2719d29b971a6fc1a5b98e8fc8455ff980d40c7b7f3616202bc42133e7b46b4d2f001403309720ca52d8787dc064e49fbdf3cbd7e9f1b932247377923fd89730906cfe0fea67826ca1500f5c87c7868c6be63f42ebde8d2df2089424dd43ba0330e4097f57ccd8045cfba697accd1cc67292f4240514540ff3d0db0792f8678e93d664f7c33d9e11a401424c6e4ebd2619b6b1c4ce759b02d380a65742e34db554cc02168877324f0a1370b85eba6cb38b168413d409da067c078e280944a75d10f5728b4c039453567a07db404568132200489c770689d699d94e54517a4e256179f1c5dffd02ca755d21497c659b0eba56f0a3aadc4188bda027183ef7fcbc6e8bf344875ee81498dbae6b629fed74198f0248fee02cb01af697862e2b2d4fb1d39e798676a869e510ee03b36ab789fe5e54dabf4e12d4d5231a0ed09ae3291ace2b5accc4d4900d374417551be07083202505dc87b9aa9c36a6156d195c52fcc4ace3c74fcf145281a1a3d6f850000dbdb9c575ab69e50fcc78ec4172af0807c510269e33bb25755601a166969a1199699770c8a170c7b40efe38c95e03b8326c32e3cc141f863dc4464b6736db857ea3ae930d159eb7c94ffc9c9bc4c0674fd10a6892101e51199f646180b792da7a8e6ff1902fabffd6b99cc4c553a0783ef85b07863f0772233bbe51c708d8a3ad0a712c728ccd1719e1deb90f87cea13f961b55491b65461572d504cee0132e775e4d9c2e3afcb6eec016eec96f29fa37cecdd13225d5921fc8d42a55b23529267127627f0fa08245a33c723bc2fa4662aeb1eb2c566355e804f28a8782a0306240853df0440229b2b593cfbc3567b59747b14ada291fbfaa7d63c477a72401e04b558c1c448eb0be24542a243300d054978130b2aebc16f8f6edadc89af97e7f56da9c455e93ea4ec6f2b60226a3d114e6f38e1e1ce803b18151c68a1076cb14828c57161e5ce2198e485a7fd2459c58631ed009778bf8fc41430bbaff820f6b70ab28630141aa2cbb535cd7969742f0ab88e1745649cdb6492f25f6b76930ff0c414aa694843bf6809f82a433912777fdbf3ec2cd1271e2e75eadf4cc13675a2ff9535dd70d45c1371744e53b135572338802c489d8ccf3bb0f8b19be8e10c1bdf4064ee65ab0896d2c6717b45d0427db034f36b1ebad50351898053f10a4a0798df09dabdf62ba19cec147e3f7b3caaacb0c674a1384b5eba8e7",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-4c0b7d1e8851a215","tip://id/US-5fb1990b4a3d859b","tip://id/US-b53bd091f66521db"],

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
