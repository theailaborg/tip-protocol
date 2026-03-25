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
        "public_key":        "aa55b860e21f63a42856e1c1ae5bda9fa7080a93c94751cdfa54a0cc503a0d4b4bb6befe489a2837b5cecabe2c8e044a36a339d643f76767a00af8a3deca50ee5c8ef82450d3eb13ef47672382f2702c7d96e1613cb4f719062b086bbe37de3930214182dd056fe082f8498a6accfb5925abd102d8a4eabd957a1fe20915dda6be834f026183b6ca3445e05cb18ce9a5a44aed8c8f3bf3086d19bcfb9aef2eb6e35e3e5d84a3b82d6fadf7e44848fba3dd0fb17d65fede4fd7cec6ed1ea20df4c4770b7e3f8783f52ce2b39fe873b68e6fdb0ddc92ae5a605302d82839bf9148761181db12f6f7ee38a6ab7277a234d3ecad2c782a63e0886b2a90e5b1927cdb6f8a679d34ced7f64f6c4ee6c9304c44cc5c378f2d1edebd36e8cf1a25c72247b1c86245371d5f89b16325deb11cef265066ab62b5fc0d2c38fbc6870653532f1258116877b353cd2b1740c7d470704838a67f6f58ad667f55463f5bdce94f96434b13d5ade40d01415b0939bcdabf05040e9cdc81f34b3904c8d3b1d197fe31331e6f0241a5766fa077e46a9bcab4b71e038cc413135f134f2ad1c73baf80efa0edea9cb4e612b04395c4f86ae69e540ea8651e1d344bc8f82ecd3a1c20cd2205869a674852010688b1e156eac8eff661e74f0e56e2494513431d7ec20f8c0aedd09c0d5bbfb2614ec10dc85ff673616d9f31173de0acee70c2e9bbdc82bd4079e71ee59387e2a4172d9e51870dd1f9f6e675978ff4faca31f63eaef2ac05f80d68755b377c98d8e05260d12c733ae5be26ca04ceeaa8570cd3c2fd9da5116bae2bf40ba637bf9361296c9d2449cc06a0229920855c4b9ed0c731e24c35a7bc05211ec059ff4e60d11bf29fbdc8411c3ca92ef0acbe8be2e0e4dbbcd926f5b709a3d403a772792fd835f2c09d662e7cacce287e89ed589e23427b82564263f299101528f38521d34c34934ee59d1f326901e050aa8d559d323d421a6b036497a2d9cc2b0dfdb0b65a5937a29f2f85cdbbbf7d70c69fa81dde47ef8e32c4f2d62d686c9f2346f3ca526495710cefd08d34bf444bb6303eeae911058af51a41ef602a9d30f91cad895fb4be06c1b58fd94a0f0d693537fed0666e9f175319ad49d6a2a282b3282a7fed7b931f3ecee6045cf8a5bb308b327aab9135ddb7e52a27ca782beceb9e58a0527ab8c3add67f0126dab622f9a61cb989cb94bf4b128fdac944942c61a4e253aae9a9eee9de74ab897ef75b5ba4ed13d41114692a7015c6e213db113df5295f15850ffc17629dd189d744f26a2621f0a490889b6828c2958e6b5e285ea133b61203e1bbdd1cca7733538e1046f9e3eb54f6cb13b886daa69dbe33cc747c6b37307e15e31c9b209d603c115123ab823c5c64fbba86c5d6009624f1f784ec11629d7ff1c8c450429081cc7b16a92ac7d1719d8f3c72a38d0dfbe5c26a58f54a84c4a41fcf02b3c1da1533be24bb0fcd98c5a4c6ae893b2cf9bc81d09d032054e2cab750bbcb406355cf5869ca1ceac13bc440c3b9a643900a9baaaefcd376b62764cac472c5fe1907627035972772e0af38ead5fe566b30e87f434bed7ce910a1796bc06c645a7d1b369d2332aea008bfee434840548e5b9848624094e8ed4c0ab17791d0db0cc59cfd2a623cbc59e1f72a2a655481f4736a6b40af9d9f152a4e87bbb0a9d7618b5153900309071475c3631a2ba67dd5a4ab79f50987146f90320cbaf07195e29dd4907370e40d729a98ffeae45e402a36068f2ebbcad14043a8b2642fb14bb64132b744c6d5e643b40f350fa43251d8f1b33048f471d4dfe1c78f090f59e4ba6b824917c40393f9cf269b97af9adbee1d2d523c63269fe112b8718a0473743ab98382a518670fc7ce144137737ddadd0b775133c0be1bc69ef9cb7383f16997b867b0da09bdb3fad19373cdfad3392d9e83817b7a6b1588bb5ca6bb0ab156bc74407f8d1d2b2d0ef7e7b11027a2ccc559521008774ad2cfbc9642779c24a5921057ace60ee37a92dd954775b3f7cab64c75ea293d5da3d401aaf169d0291bfcbd01ffa5a0a9ef3b9e84ec409f1a59b12f9d2b789fc98bee8e97ce9d23660115b9c54ba5f93603ab0b8b251a36e317c9058ff1cf3bc0685bd6ee6e5b6a9fc1b302dc44eeb03c6e19a1cc9ec09aa4bc1dfeeba005f4a4c8b4b4a68f4a0db171218a8fe90cc42db9f7cc4777686f6527c1a1592303846b9531b6e1408f3a6f5e4c41bf634da609b8f68b68330bf477220227824b33b0feee1e7f690ca97faffebd028d6dc02529304aba0b5d869c3b670c698f07acdb6a296e2aa7bf454f08251b36f9ec787d101fc1c1ec00911550089d6c918eb8e41928970574be642fb6787c8d1fdac9ce4513b5893718ecaff89e3cb08e70d9a8c82bed7a56ae464cdd729b87e000e74c432c2127a16302d5a21c644c0721de5776d0e0f209302357c331ddcb8992fb181aaf5635d5d7bb2ac5c1bf3882b7100798f219314cfb7bd6a6b42b56ea0b0521751eb216d34daff6ab53807a2d4b214962538cb452dee85235542f200a4f0f9e6dbff94dc93239b7bf0f0683ddc64bdcbba1693e8cb1fa15b4a26d97d8a5b0c27cb75405ec7a7c7703bed8e3778953c4c9fe854924136e2d2879e3c2fa36be2e9cccc1719a685a634caaf865f8723c391ff027e5bbf94126cb1004f7de8d95717c37c20d1818c1ca86ab927e63de57a10ef00c59d78cfb8fb409cdbe990487fb6e1e6376ef0d2ca6eb5ccb61c6",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-98130a42264acdb0","tip://id/US-2cb9f28901d3bced","tip://id/US-b75bbe6f51200a3b"],

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
