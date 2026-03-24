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
        "public_key":        "7b3eab9413ff025d69d215f52830a3dd9be9c42810080e91906c714ededc9da26014c8e3361fe41de71b4fdcaeafcc125bfb48469c9ba475aceaac552e919e5b9c75a9757be37cbfd95b605a7b82164e1c879ebc4686814320c7c1b8c7465df79b288b43ff3474ccb0dee1efc9e562e8885dbfeedf80945fe593ae6d72b73ef6854374a0d31178abf90d589619e23527ffcb03d25ed4bd1b8aef30127946503eaeea46e1566ee1d911744e63ba2445c9aea98fbb949230748aa2f2230b63e3a09387d1c8c88ce0e39b310d2b54a428954651c27e12a982037848b342f98c69787121717ccc4b2f7736cea436e750171f529a2bec291b93ebcdf6f72ace344421c9e949f16f3ccb8a52249320aa03a5f31c0851b6754ea83e8700bc0f524d2733da3d518de480dfd8d88981a72c48efd3b970b04e8341994b1cabe6d81c076017188fafb8b67b80ff959fac6fa49b43dda517b0bb1bbf8b2f1c6df2de58876fffa23091a2f290311ff95d900648deba1c4b1b568dbfe0704506d5773479bd7ea857459d1f0e3baad67a9511760167f78537629a3a859d3a5d21cebaa17175335091b033d2255f5193a82df2f3101f7417fff3c22641bb1ca86b6ed1929572e8b0e08fe30262ef5f553bf249fd95742a4fce4f7c7353b66824bb515bc8aa6326c511f6edd27de5b0eb870c5a45c59469bf0d46a8f91aa263e5d654651c956d3b5bd5b15679df9c8b0494d1e9c06ad9934254d764411835dc6b33c6b625469dfd2bcc2bb5594e7e1c1300016ea26f9b0266e08a7dffda79f5cd2ec59251d52146c848d469793b1451cbb9f36494157ed27a299279ff79c9ad819a811cbf15a89dbd9730b353f71f9708677d67694cb2a9ebb2dea5f2bd002053d0ea29e3059b391ae17807ff69d784564f61a79ade84bf8ba88446a799abde8c92a2411c14c05e01d26822292921eb25f55f8769c510d1bfe922a276dbe828e5814779586a910bb4ea2014bdee5317b498df2373b26bd7a72d9a91456f43316a2d6d7fed4bf7d96d24c17f2289b2b576cf01e93f8cc92a0c1284f60e8f858e68081d80bfeacc07202ebc68905961bfcdeb86e87bd9856512ce314eb0369ac2be224834a8a023474b288a297fab8fc7ea7594c06cc9b2afb4052233b631328adb9646563b6c3a60e33f0f39aeeb6bd564e9bb01a5b722c0dbcda209a2efd7ceabbb67124f8801356e0b85706a828f15c39056906fcf947b8c2d7e56c44070d1bcdc430962b5f8ecccf3d48811db0f728ffa12161cee5b9df1ee49e0b1a5ab2f03dbe2160c390660b508a6f68a1143ddb2c46398bad20088911a0ffcbc3b6fc9ae68161b383b9d766f89189dfb4ebcd66720c9feb586c3055ddfba2531102d1fa73411c5521c1a940ed74bbe9f09f7a3def62c3af4a81f7bc21c444879d5f158f97c3372118e684f72a7f0170344d7591bcc257a1252bc929d522a24f4eb0a8503fb83b35d72607b5f011b29632cc7c9829347fef097761fd01eee751fca5c35f17ce8b1fe7acf762e1b45eebc443fe3119432f13a06611fd1368a36c61f935d3514173789e7648bab17542410cceca22a781181b178e4cd66d0a005b1e2c808d9decf9666abc3022e8910338c8671d47739cce7cc563fbb115836d9aa9b7865a4126ef08bb6b0b50163b58905286b0feb14a5d3087b01041925e5b712278ba5afd1df206ab5f53c9a83904fdc1761b35793caab020d02dc12436d1a198ef20cc0931aeb0d821577a98d798461d767e54f0912cc2f05be523087c00c22676a02522c7e45cb0e36fd5445e99a4ee96a5eae893fdc980739f3c543cdf575bb551e4bf2adefda4082df5cd928fe9d8e6f68497684755f00fab0f5a102b22d28e337cdf2b887c8651bd1c27cadf68e5162a9861cd6c7cfb75baacab7c6c92a7b54c6c15ddd89ae3e26312c9d57c5a81222b45bf724a24dd8304b969e72157145dbb1431b4830e9462e16e31a5151a50cf2a23a8a4d782122fc115de901cc151a2d4f01ebf733a0d742be8b2cf4dbd8238f90bfd54c16d4560ccead0dc03a1fcfc0f7f862fbd8c04550166ae61fc38029de9eff376c9815131c148992ea4adb21f594dec95a23c3e7fa30f10d3bf58b574de98a57755c3b936ac35b7d578a033cfb303fc2e812101788dd35e764e9641e08e80f9b99a33ea9792c419e95d581e046bbb32134469e4e47097cdb9ec7ee6976a8e9ec67f014cc1a18d5c95e1687933a7d366eb02fcc5da2bf8d738b4f35151a1bc53a3eb0d6f5d2d309a062b988e4a5e0f03e0d9ce7158ca7aa4cfff53f5178f78d02ae925558846def093d58071170e29aa38ec0a8a3d7aec98aa65d3dca6b3b9e1e385abf803d093893591ef9d0c52f99fecd6ba55eb18b9a2566455c0d48b6eb80abbfec5c4841c662c00331dcd71e3d699acc5d45bc78974f866e0c281740d96a0e3412aec73c89af9d54a7cc0f039a163f85e25860648dd0d9b7e0245398ee4be32327adb981ce3e7d603d347dfb3e77bb760296e2932af35b74269898f4c65f5d47447ec26f4198593b54f5ac72c7945f34df69aef3ae3ae2ce471b55e27b00a76e0ccfa72a1677fff768798fa69b452148918cc093cdb9cf55eaa9a7fc038e1ca5113d311eaebb7f16a782ae44687a121d72a9e3873a459e04996cc32389395af7eba8e5cef67d40f84d872eb9acfd8de3cffc34c350e42914f322995a9054e4ff19fa116280cf73324e0ab3f032f8f3a04ff0fc6201",
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
