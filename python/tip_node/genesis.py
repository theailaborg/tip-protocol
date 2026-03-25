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
        "public_key":        "f9f288884cdaaae2518d3dc07e3f354359ec318bdff3c8a8a336f0b2fdff804de5c776c08bcd71a0e8b8fe1c2e44a6fcd1aed5f12dab3f06ca3d1a147ae983319611ef11f8225cfb8cd7e64675d96db0c8f051b294d02d86599a16f8bb452b6417f766e6535f49ca677c78af5635a42c13a76a219be4955c9249f03ce21e46ee7dabac505821031fbb0f3cc5d0e2d0fb833bf45d0f0dd7ab6693a971e26204389ab5c06940a34cc0785de3ade9ab893349d8c3c711af076ecabc4a480c0a47816c1124093b46fa121effe9b7f89c4d0fad88419715b8a43ce69515be2e38e00b472995b12b91a0d2f23d1d0a91fb61457d7b2fffd55af3fb8362857f6c636ba50fd3d66c62c009c0cb3ac4e3f1f8a0343edf6191efd4429251dfae9ce9c482d8cd51b61bc5ff2950ebec6443ca62bfc3cd3c794ef9564ad2879f83e68102d7597a2c5dc2a235dc0ff5f50fcb171368985ddbc4d5a2fe27aefbfbc098a82c4f5794a01257b309588c0748fb6a21b5096c069ed0b5da1456029a2cbe03fa39c924d8b782ce242ee7118db1e92ceac5425144b5e7ec179b5d18ae725624720b98e8ca3a42569fccc3a7d3d8fc02f5915e4790a90f9ecff931cb99476e0e755ae2c3fb28b40745624a3df690d03983207a2118ecb62a76ecb0329b07dae49cb0560b934753c0d8e5ed80fb13c9db2276927f7c04c1ac3905a1c469c682f2d1488769723cd22999280a1491b9062ff4c10a9d3f0966de8d815e9d54d5f634ead72705fae801d90773800a40b335f6e0d0bacf6a8b189736424444923121e6e2cbe4132b826fc7d2cc05d98f9d9b8e4e1db4c9cb5c0eebb6e2f1997f9052be25994bcf7d517b02950c6613f7a2379bdb115c3f7973bfa673e6d65644eed8fccf0b4d0deab79b484ec225aefbb729c55a8e6d3ae2b96a54fb9ae4b9103cc2b74cd077d830e50e425c67b77a7236b2ea90c5ba8449227a7ada2c11590004d2a844e44c9ae31ca8866e12fc26053e0e6e986d360158bba11201c6a8a4ebe09fe2810c49eb35888b8e0be726cc56f46c3d2c10939afbb1a4bbb3848a5d1ee54640d55ab1a5b95f2271657c0614ca84def21274a36d8b6001fb46879026e6e20f78f12759b4a2bba9547a8c9ce10975b41ee132ef2ec8cc91ceba912e305d7e0c66b5e874d2da040b86dd83b35d3ea97d78217f0d6f81543afca486177446610df2eeb8a03b3e4dc139d1f72cbd72da24da46b00ea6a2f60b9d7d26de9276f53ed3b58c846100dd9b489fe772f7d76f49284d36719a32d955be7556bad50e0795f986519d8ce95fd1ae2d79b14f4264cfe6ccd8c1254a27d024cf0ba17c4f201ef9b0a16548dde75b5e245e8049fabb7f06ec2a8b83ab43feb93e21afdf3a831eb5653e1006c17a910fb2b92b4de780191de6ebe640437a7209110ad74df97688651e611cfe5a129ca0fb96c968e15eae79adf0abbdf995367ec026d936b6a0bafcabb53b7774872d390ad2abe773a98f128bdc1ab6d779a1caea5a29261fb78c31ed7d43f22d2f2f6b0a1dba50e3acee8681e8b0098c6a549f3192c0b13852d8de3610bd93f71f4009521cf83bea42dec6b9e95a33c50e92012422e21c289b55ee3feb32f9c4c0731f1f6dd10796ec40f29f83e0082cb5afc9907e409584696c77d67b02367840ae811bb116f361de100ed7ff6d65a4a9c513b39b59618effd5b851608f6837fbe93fd28f3050039e443facd5da8ab2402ea59f32afbd2c197238ef894b9f7aea9bb10e758a80142579d647d90ad3203cde8c2915ef0d8946e3fc50d666ace12d0d4af92b91fdf5e21fedb9b797563f2ea25e2d8a0f1f1065819ecf6c759ccb7aac8c49c6ea16633e3ede557ef5dc43788a79e1d36e3b0255c8864d58367407f46f980fc5c34787e0bc10b0cc67696e6cb61e1af8179f97d10cad43a27d3073a9646408a823a5937889b87e4844724fb3215c99a518adffccf9e6f658bf626e246e73e41abdfa095bd4ba465b4079c801ad6367d11704318aedb5fb6a73b804692fbd046bf76acece2c239c92bfa4798e67343bd0aef2f13a42e68c33edfcb98290e5cc8e37efbbdafdd7ac15a4f411618517de037b1f379d0cf7415fcd00fee0c0dc443c9de5bd40d9b837a0270fe9741d4adba8ffb7fb681f4f49bd1c45dfc3490832ef9b3a0479f68bd68833e8c7aafd0f00810a495a824e676af7f767b94df66f8e09c6876d1621ab30a28cf634bf1aa7c9a86a3693b02fcbeee39dffba94082f5f19a0cb7f7c34f5240bbdf1b87dfa3cc7fcdbb40b342a81efb41ab902c6d95a0f9cd0b3a82120e0909efe87477d5198f18f401cf1a2581e8e04455894bc5e5aab3058ad2ce805c659210a028ba49cc16919aef5c29339754f33f38e88a4e056ec8053af1da0dc37b8a6d2fff5701eff247a526610428428ea8fd3c1f90223bb9bd30ccaf588f6d462094b62430b13121e32509647b31665d0ceb2578d2d8422678e1f1596b46beaf39f14c5c08d2f6325989465a84e984c62628521eee01a9842a39be90fe0a2f1c5e7ff8521f909315d95fa16624c02e09f29b29e6300e839a88aa4e8e7ab6a616fc3e10558bf137828608a0a1cd3b42f1eda25ebd01339cadb19404efcdaa36e7bc3f51dafab9a445aeed50e087c495573dc4538f0304922c65d3f1c6bdeed63b1857a41a696f54daef35325a9c58af3031db10d974ffd4099f725e3bf8c1c544d5797144c0e30285a80faac508cc529f33a21f1",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-a054a68e809ba8f2","tip://id/US-ae3df677bc35553a","tip://id/US-1e38e6f1e7461475"],

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
