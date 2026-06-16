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
        "vp_id":             "tip://vp/US-0794ae15e9db4b90",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "c57681e0e6b0935e0cb9fbc8f289dd2a56df150e8c51d44ca3e8798cdf1bc4d29f57c6907f8b8ca0555eea3cf430ca5962589d10166f942d2c9170bbae0cf036d01cb83c2e5eeca76ae567aadf3c7b046b98a4aa0047edcb3bbef40742b7137611ebe44a4da33628496c07244a63a1ece8f816843cbc68eab131be1148ef5e05f1fe57d283468b4887d06add68b3a04ccaf13d175f044361ef401e1382e3633a39aa2cb58b4de40b35b4dcb43bdc8a47afc55ad4881e72dbaeaf31b95ef928cdb042a49eed447a16d50af2c7fbd7b29c5266db639eda3e8a8d54247d3b18e37f0dd35b4cb53ea045f5084e8d114e2c925570f648d11a98dd6faee7f156d232fe65b47bb21d7e64882f3f4824d3aec937d3f7ee70eca863786f6922df5ac6770834aa632d05071e003482de2ded5e4cb9f096062df2acee9c92208525920b26229d98300cfa21947b0e749f04115f309491d315ecf5f09003f08fc78b2136b602a30e05819e09d64e8d12a9319f4780e079374cb11fb18f9a9958924f301ff13b78bdb7ba333e8d43e92711142a27f65bd9f77ad189e4a328581fea15e59e5fa17b053a3aa932668cef9915af2c5c99c98681863a160a96a3ce02e3b28c98cc8a34262c130eb341f7794d5745c8b642850d4e4ca7d09653b05206917d7759b5bf78bbaa9a911a5cbd97a3158525796d69611636109598c40074a64a015e8d9ec861ade8743c7d61599520719d3af3904d36d3df5fccd763ce784da0d4e01b0a2357d86f7c0a4f57edb34320ab4dd94d34082ad8925696cc7db923ea6cd0bd7228ef8bde9c6eccaee24961f3b979a20747f14762f6eb4287fad9a0d8d91622139a63ddb82922c3a910ac1d7f8ac93d92d80be4e9956dceeb5947d1b7220e68a3868a89517d8bb8e9a39a006e4d781795c6147ed8e63ff518f1706b57fed4de0bc030fe28adbe1a66536b074fed18d811ad9cd61e84b429ef059a9cfe29f0debbcd64e39b364d300a90d4d64e0808f33964e50609dffe2f04aae5f18588b34c247c0e8471a9e5d4552086ce9a13814cf1576a111126fd5822860aa9cba33484f026432c1cd8dbc824b72589d109873c845ad66d0fb2f13f1b280c16d97d481e5daad0d5c828ffbce6b1421accaabef37e54d343b50a8e7b0ba60c53773b9598eb7479549a399a40ffcc6b0f03346fade40a4237df9db00e4d13b5fe974c4b8eb5d37b3d6e65226ee874753c280a37013ed60307abc933b83a9764afbf0b4c6a448334d7a826c39c863ce25185e36d5f0a6c099b9c2488da1486402286a4e78faa737f6a85bc0778d54ff39a62cc41e3ae89c3a31fe87820e270faed552111cd606cab3375a1adcb2b4102c63e5b215741afa806fa45b8b8d209f2d8d1e32b6c96089de8fea0bbcf769f7fc2326875cc3667e3c67f56def6e7c6429c89280fbc5fdeb0f910dc52d8e932c31e39d1167a8e406024226df239a20e2ac08397568084b2f6e28d14cdf65695d08443603c10ec411cc36889a8b7c441ae0f29be3b42a327064185a33cea01b1fac2897a7053e081095306e5314b9fff821dab8d702b65d91397744183280498cedcfdb3c48aa5a8a5bb1f32d747660f8911329a9edaeefa7fb1e81a2379611f31eac77bfb198d3be9ce28dfcfad50ac420d48d1cdd52352f30face435f0dcd362b938f91971f0eff2498d390e6e757f7d3bfcaea130c6a25b2bbd1ebd4af79e4811cbf60e50b45264f2b3abea61828b7d0ea90efb18f31fb480bec689ea860fb5b094b52ea10486343ccce3b4c213d7d2f7a5acc2b053aa7cc87ed098f90c9bdd990c98b26369b2a47ea3f7a88541e1780496abce3a67c2c44f05a90414273f23865e7b7d90e7dc5061b062c80d9eded2927bffb9c1d2499118219ae184b7d4ae67b18dbaf3ee7f73784dc0572ffc9397eb67ce572e85e1a3e5c99efdd8070576fdfe714b0e3bec8c8328a62c1e85ff2e25f3848ac667f8faa301051aea0ed42259b46f17dda0a8bd397948cff0990daeae73a88de644b51a65b47fbd2fff5ca738ab561bb59395773604f2b47011cc6e64de7ff7064978fba9e3387e113b0dedc1ff194878e1bf12cecc5982ab8bb535f1e07dc2cbe8d37ed66df7d39c0b9c963d582a008c7f9aba8db3a8372aeb470ed728f67eff4400177e62bdfc70a9ed01ec7a3d89eb075969edb5d0fdc2f2ea0d69df02635dc8169a701cd7f8f278a7cf7530bcc2ff99d5a1d50c53da34c9afb795ff61e63d8154b0cee1e766dbec9b83e4a02ccff4f4c36d45dd0aa92fb7568b6522e2a2677c20aa2e9aa4382e48c3726ecc1532d05120be1716044ea30c6396e906f0a0138f7684d00eeb36f45bbd1588ec145ba449ee23327246f18415174f6a47f53c880cfa26a57f89f847eae9c8508f1edaaf8887aad6125c85e2e091ecc509e0b9149f490cf1be58609c5f17ef0d087c499d68b30164e415ea1c6c0aa36e1e210231e91ce276b7038b90e91d127dc2fbdc192c00d02f3234535c548d0cc348f14336c104679dbfe5fe0aed37657af8912f0c2052b145a641924430007cba89e00c7d62fd34c473990af7ad04c59694726eb5c91d33920cba00bc4f0ad0897841963517569ef0eb48e7b5b2f53bd7b19155752e4e15ce49118eaf2a759b686f4da00118d863c9583ac88473f54262bb7ba86a3fecdf4dbeba444a4d0451ac98ddaa44f5382ec37c91f8ebf1fa8332d19ec0d47e320bd55f45e0898e0d8510382574206e6a",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-21317046a96925ce","tip://id/US-07e28ab8db109f41","tip://id/US-e91cd1ef52ff6a44","tip://id/US-4f1e6145e0eba699"],

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
