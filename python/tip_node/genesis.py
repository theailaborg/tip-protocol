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
        "public_key":        "3ce0afa09ee82142f27b435ee7a31831637a3bfc2099a53645837f5c88bba5926e4a466c0773603f381dbc49bfb680db7e19a872f2997c5922c1923302430b74c811413debf5f9d30ec3c5def828bf43cdafe3e09ccfb38d851d82ed28b11a9194fc77b51d58d9feaa73470fe9a2af24aa34ceaccb3c17e045956312f1b29b8fec542eff51cf051e244c8e88284567adbb3c62b7abc884a625bc46499e78addf54e756ea1c14af0ad797972560485188e4b3fe895d6e60987168f14d43d1bf5b1db2ae2bcf66afbb703a2ce9c0b76ced4e2194d884e59a32d4b50453d9464d9d2c3a7f6254b4ac6babcd45ac082ca24dcda08708acb9c5722e8fe8f810d34174e12da32555824d6a1cb75ebb383f513f4587dbd10317e63054718d25c8b003b5f0f8870588a790b2fcfc899a0912987fd6d68827ab3cfc0fbf8dbd9adabf49e8c7dea498e5123b42aad02edb9c482f0d1731ee2519b0c0c2f97dcb4c922114842603d65214689ae272c225f8dc7c9e0060e1504073e6783e96e40c25f2b9fb35bebe7d9b3b23f651ed52a373e4a2d4bc19ae74edb342620c8776694a5d3759161cedb172b46b473f81018b7ec63e573e90abe5af914b4e8a15f615ab731ce9d0b5709954c986a379f271eac7d3e0f29de084390cb49475cc2cf06d3b22c9e8a2f38af3952336b3d8e5bae9a978abf156bc3cccf62beab1a88bd4a419fc9f7310911434ed7b410c3f0d86e289e09cccf95ae8760dd13a07f80d0f267e99d235767c679292fcddc56cba1e06a2af527a74e4756259e877340b205a53740b06b8dcf7355378ddd19150585e4a3b3df9a0838ba42451446126de24027446b8e212f2e786e4ec60fb1b990e2db446ca1b8d5fbbf5577b299fbd3c529aed5a6110f7464e6f035de39ed4a40a02d41ac91024da9c0c57c628d1a7c481e3ecf574d885a2b5648c3ca7cb13d9c1580e47fbc847d732821c6998945d32fb916e02831d424a2ef32b192b6d4ddffcc5221c05ee1cba6c00288f4275c6a3e33d79986ebe8f59ee7cd5d247221a60c91f36ac08e431c40ce571ca98f895d07c67ec4cf2ac016ccac0739a52f66f5838a1d5c5164fd170f654241177ae503a8164d7e1a6233e4c227ed29afd37dbe77494ddb4c06d4e41ddc6636f3b58ac18f58f8260ea49745a14cbe284dd228930817f2589735621e4d329a4b695f90c42c6c8db5204940cb29363334b95c3eae13051135ab9f8d375155875baa3899b2b5b7d20ed8d0eae259f18f3b84bd5af517e531be066cfbd717aa3475882c183fd307f263cbacbbe275ad65275b497145aa2589f2f201544d34a6e69ff9122a43b69d201f1be6ba8a94efe478c3c1d743ab0937b19ecaf2ec269050eaacd65c5a158232de67d4268fd7cac012da16e93b9478bda43c1d067a6e3d62d9d2db7742ece15d089265b031bb3cd29d8d0a223736dde67ddd4382e3aabc492902161f4e6fa8970d8bb518edc8b8985866db2cb6e50d1bde0b1e924e72ffc97cf9fd7391484a0549e67055a9840f00fccf5db4545cdf5e696f5047a9ba55c6df864bebcd0fbf70f9e148af8b37382a9e91d7559952798a53656ffec260e13b3ef89c0676d1f5a02b3a59567d89ee68083fe18287653362eaebbd528ec1673c120bce5b9bf4878ad6d039e145efbf196c4cf1b598d4539c7a161d240f391ed2b9d6a679289a85ee8f7d93b6e4f42950fd961146e220d6fb2fd7d35102a150c6a9c0bdfda039f2f4b12d99e75d2deb920a1ecf27f2c0b0ee7913fd36b361267a4b2963ac84c9d5f61b482981e068c97c55ea1520501496b56e6efa5b0f0f17a12a83c63037e4c381f7fa84b9991f7ec7d3163b6eb217f4054e16ed6f20ca1cd235f1a2d37aa0a9149184b84f6da0c22e01864ed1b98c9ac5b4366bf97054c81b3d68e61fbf6e5b06e159ad01b324d9ddd08b1b05be6227c9055be25b004f6ed98daf10bd806fb8a52f9c2f9a184865a88aa20a361bf51bad65299bdb6c73d9b7345ae7474021fe32131c8269b37fc42dd260a2b744b267786ac06875f54fd07d1feeca1224037adc983d615a14f5ef2cc0bde137738ca536370bfbcf78b7e59d662387e50694b9f4e82e7b7f609b26c19773aef0debe1305ec08e76a514e63c800ca7d1a0a37824d56fb6a3c23bc6e0ab1c13698608b57a45b9408c3b3deeb0a7825ec6be7ccfa8c83874ffacf3b93c035dea2110fc253286f2c4dd0e2ff6b0b9d20668d15022142e0b5a3af4162f434f86bfeb776fd6038b1ff372ac5e881e44ebefe741e3fa83cc49bc5b45b4ed01c005c83f7e11548c9861d680fd9ccaab6c2e27def7e965c5d01d33558822d99c580e1f45aaf85a7bb7371ad776abb09ff88f0555305e6a43a751961e793869c249eb21958a2c5e96b74a16e5d3bc73938fc43f053826212d658c4882e8671e70ad3dfadb28843005b151e4f652f540207929f3189f23f9db1cab5c9b382411ad99a5b44743509a27feb916861b9515105efc6cec95e33fefa962694e5bb21c829d3ca707c1ac72a125e339102c820023e28be9f8394669c18de24d392ee08c62f302b671f3c5da64b449d9386c0e7444a8d8e37ac8493d95c0412f1fc6ac48229721863ac2ba19975884fd3bb3c0f6706f485b73dc3375f971d76ff4a4d494e24b39732a67401f99c8110772f9468d50989c5e54acf38e4a2f1a2af299267056e05aa4e8fbc4e9a6a83ecbee33a13877f56f63191a69f91c34c2bb3fc855",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-caf800bc12c8172a","tip://id/US-99f8cd4ad5e5f113","tip://id/US-ab4a37f0001cc58e"],

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
