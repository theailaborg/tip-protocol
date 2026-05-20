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
        "vp_id":             "tip://vp/US-ac6de96b3dd6a8ee",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "511e5ed17bdadf80101f5cf768676806d4db76f51dcc5febba5ae107f3324283daa55b902b9ef2ceddbe6922e7c23f137c89be5c6bda965f15a1f5bd2f4992e14723a757690817ab13f1b4a5418165c9d457d507b86f2faa3cf49d401c44dc7bf67b3eabfb98140e38e5409f29a23bf22cc0baa460b5f7d131a9345366900220c9c9dbb7c83a5ddb4967f1516fe305bf031dc8e633542db9f4e6a900f313d8b5c3dcc3e7c9077782584a2a42b66af158a071e253fc8bb3a6bca65cc1af4f3f3f77e13f2d8208b904754633a0fb6e0af610249e73146a8e32d6474a9771a0b1f30e1ef52d71750fd66949a431bc51741578c9bfb94164ad6d4b2812582a53d3f2709872b328e5cd17137a49dd7e939911fb9f86c5c0792e06d8946ef14ce1447e257995dbeb43c28f58dc4ef2bf40a59be8a7f2e1fe2b9ebf354797f707d0a3714aea901157e79fd59bab7ba2981323da3edc220df821ffb89886b3662b3839ad559ce80889dd6b84290d283e53e9935b5f40d086c753697c0202cbb8c099e24e4e581aeadc93ab4c9282fc6c6d35654b92b074a029588fb049a2e630daefad3a2abf65a10c9c5b94dafaa456fa5b901da5fc73c879298d797b0e27322b929071034c73e6a8c772b0083da9253453def4095bcf362e10e63ef1204e9328bfe21d8602ceebe66e71edef4d007a01ef85e9ad6623633af0f93e225ffd05a8b035f066a0fd2ca80bf61a75f3abda3863fa16b4d79c854683ccb25f28f056820a53c9d3c07e746b426a498604bf600bdb4aa1c30a2ec53d00a4f01d84e3a90f49c69efc6f83dd758fe7b7982f735adefdd64251dadb2c2621110d303be1f373b9c9cd993d1ec226ea7324a6ea030b6b8af36d4ba0fae361a52111a1bc0a71852b1d47ed54e5d77b8b5d1ef8a3ab492b8f50bd44985d7bb88ce1248281c22f56625c3d02b668d387d744668d508c2e76d0deca9167144b0e1e30cf4c22aa4755c9482c8c47925bff9aec7beff2e160bc9b744a3c20243fffa298439829f8bc9d5e52a1c78ce926eaaf3b464f0a75241f2c72fdec38a1f32d652ab941228f898df15fab891e0c079c4ac50c5af2fbed4e58d76259563d0c794ba3d2f8421570c46f5200ea8d95b5c8713a83a75fa054f1d741e5a51253baa7b9a976681823dacdbf6d7d3566e21a6eade8e2c47af583cb268d754e134fa21588493133f867cabda7ca2313668204be007d7710857639b3996ac9d8df5de0ee23973fbce72c25b00c47450809451a06f8c0cec70d33b19c68d97a434b36d6263addab21983143c129b1fd282741da9e1aeb7e0b19fdaf5010b9f6c52ee256e825283199b9c13df36fc9b87c056d8262b86ee7161345cd14c0defc5fd679f8ba906a0f90b658506c13ea938a06e7ad2ee968e210e35196babb2850c4afe85363858682dbd33183797ce55188742ec4caf0cda43675f5cfe03796382f491a51b33f70c7197f47ea4f75f9a802efc031c28f90036776518a643ca311f48d267a4f616989cb06b9c23c9e3be42b767d9790e1ed4a03964d5f947396608615f308feb0004c4a82f99c26856fec04eda87d7034b253f20d58be0a31fd89fece15e54fb74d74932f0aab42c504c95a98f1bc9af00a7a44390e47d8ec650c545f5eccf2b316bf34f96914a5607cb41926b5cac40c26ff8df2d8664a4edb3f8145df6b3beb601f3247e58206ccc4eefd37bf3e676924df955431df8aa3b4087297ae0df6272c06c4c288649bc21ed6bf0e261a80d2b0e2e08ffd13be15712d74895e039dce1d4bfe4104e41f0d4f7f0c4e04268bd2dc46e3d84145d134a0f9b02f880857e76d953f452da5811a50a1437970a85272d0e6fa13769652ce29831884fd7203f17b2378427f764cea2df8d2a87aca8f4466db38f3d56496e7e6c627811378b46da50ff7cbc2d7fd4e7dc9953fa0ea0477572e4c0324e299293359d43353e9e9179b01ecd8f2f27e4a14a1f29956d0ea653284e9729c752eee6854353f7d65927b0eecd7951e5214c5d42d0fa30ae3e422cc213ac03357333831bab1191eb696d9c020f58b2c6743aba31df373e8cc9fbab58a92db6a03354caf45db1268e268b15f08c058e8f5807f40e0192795be293354d4d441b0ee35f758ecc14b47741e3c46ed4b914c7dbe07c0ff2abe3ba7c28a78d25e7e2e2192a8f453f0d3a2b46bc42a6275516d01cee34c94de97f958563f3dd886467a915f908abf225e711da2389775fc0fb2b4234035f3aded68cbe15787e3b925e0cfc6af43b6307cd4461ad48ac6c767b5845d1aa4ebefb6f8c7898b226550964bc344d7f7315d38322400de49a459ca967937e8eb18f638ea1294f607525c63661ab32c25da6762bf0f68b434f06e5a3ced4ff9472c73de29a97d989d6348d0b5e7770925a26878bf595a5a29e0b5bb0df6b693de9f9ba4b29bb78bf3fa1947d94a5fa2edbde24248eda6a3aca5fb8b7774bcd4cb0e5d4df64bebced7715668cf90fbba443c1ffefcdd9a1e4cdf08ac59294a16183bef31d313ff1f6cf1da8353ee343a0c6547ec4892fa77243eb838cfb3d95cd4f18e7d2268dfddab60445b85a24b40edbd9ea00bc6aa5a81a436bae0e82afb15c6ecbc5c313d4d805dc0e2e537b3e4c07e86a0a23b07582ffd26e49e0d5fb4cc6f1054ad4e6d238a6b176d9eee5c987d8bab794f023ffad49bdf86b9066ff72994b0073e4ab80f38f25720dfd82ada7d555b428f6c21f4494195acc8a2228fe699",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-ed49a7c2fecb330c","tip://id/US-30a9e171d0fed5f2","tip://id/US-51c020baaaa6155e","tip://id/US-302fdb95ca8d2756"],

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
