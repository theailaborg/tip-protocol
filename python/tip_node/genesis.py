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
        "vp_id":             "tip://vp/US-1d8e8ee431f715ec",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "d65c76cc3d9effa023a662d13017c80710cd6a5376dd73d6648de45a2fb4ff0e5cd3e9951f7a04ecdabd8a65faafdc3509a4e6e3acbcadb2b50121d3d621958b00184c71f535e28f220b96ce3d652801535083ab5de4f2f42622c226beaa6c121718cebc711cbe3c2345e117325616fbddba855254c85b612ebc39496be6b6eaa0e6afc309193b3f5ce50866bb49cc349c5192c328103236e50a9a08b2fb3c052e94b06995fb195c5fdd4a8c5170f7c0ec020b725631414ce3fdc931d907676efafffcc54c251dcd158eda0c8495b759daa5324c9559f79031dc0644bc3476d2a0db13ee1bcadd7d8b0540c7dc1fe952016f6429d6fb17bedcdc124a8b1905094957f7e680499b6f753a626d9819c47a8032347d3b54f44bded8851ca33235bd83c025a31565f4b5c4d50de566ac8fa38eb90ffca8260948fe4ea0e62b9b932bb18c5c6cb2caa3162c32cf7045c24df1d9e0b3e39408ea72762dd55d6b4007b126404cfb1bac43e6231458d5cca9ca2768821141bf0622cbf0469a968b82b9ccb7e13de6e4c52a5bf8307333777c1b44c6f1bcbcdd1ed5a966009fab069e1d9db7f28e976263ab9dd8a96bc8431ec42b9b2570738e5f81e21d055cb1db48620e5fd9dd155de3f357f9e311af29cf92dfab63cf39a5a3d9d4ca4d2e6f0cb9314022430e8d0d916c943b1b0712221e63e07d4ea83e82eb4160f67dc039afca377553474e33e8ad1e2d5669766a8adaa9a319cd8b1ada748db63ec93948f8ca38f97afea7f5e496c5eee6203a36611b93278ccc7de4ce4aba76ffbdb720dc49b1e053c166224fb3f6bcd5399a4806156d1270b6858602ea530bc4ce57fc2bf5456e66c439c6ee71aeb399b9652aa101b33c313f4715db15e2eb905fc72336d80b226d782de1c15539f18d85a2724dbf5ddedba10223d50d6327c69b1369865a855cb2e867f1e6ac1fa2fa90b802e91ccbc6a99b0e1067c16a583ba68e8997892ab2fccba676f88b4f0246cea1da7511e5cd544199d5b49d92883d35ceb194622865299c7da7286b616ea95c4db43d62c48e839aa42a92da0c6aecfc92549e7df998c5724519544020ede0c9f72fd4c9138979acd014be9b95db83de3c59766e8ee7431ebc492995c6f35176a9cc5f004290503d84d970d6073054e8424737c96da2a6b472d6393e8e24187f5e87bba25a7d694ad35659cb219345a13bc065017c30a72d0f67e77e4c9e62a2cba39bebda67a2ce4034cf8b8096c455c108d20dd1e3648b5d9c2bff5bcbf1154a61d11df80cd03ef20a81d65d11ece32eb7ad45b4e9d47e2447b5206ef28df442d788e9b5d902e6c21fd93f2ebac59a4b4009ff8bb10410907e5e440b43a9259f95cef71177ce03694a3b5fa75ec3a558ccdea80939c36e33e90009333893ce58a6a43ff7c2a5ab762fbfb36e406b2f2b036759b17c3c1ef2145549f665ca109c556dba95287bffdc1f1197ccc7e32eb628e11ea4d1f37224a7a5ff0ddd9f86ee7c55bce5ef8eab2f000cd95d922776ea65fe3e89b032bef68d296f0987c0fba787fadc946a2a59a6b9159e090ff766467d3278f0ce8c697a366a59aed6cad69321a68e2a38a711a3ace7a50f485e0346b20acf36a9abe1628ddb1c0fb16de7dadb252362e0b9c14f009d6f4e9dbe01acc45b20f9cf9a74b45c23f88df0f39e9335f902feac942a0eaae5f882702b5b287603a7f353da8a177b64f2f4152cfa896ef5b96093b7aae88ccaf2022ec4a3b48486ea8a7f7c2186ae1291a9b54943c7875382cc69b2200fdac0af24acfdd49d58d2e4f7fce4b707e2ea7b9f475b4917a4fd10d61c1fe38ad3e3d80d9d2ba40692505a34c1420a792a510dd2e8609f823ed3390a7868f44841a87a7fe3c9fd0d26640f36c79f9c9d1cde6e153c9333f6d024763fd98bdd2a5557dd3078b5af92fdb12b10b98dceb1651100e0db739e9a509a1a1f60e4a12da5bc25a1d3a949d3d525141dd33de7446c138141ac2a5eb34b1199d44aa153a561622b89bb9fb7ec300d764bc359eb472017e8a7101a8f7e8749e9d0aaf497a2d8dbb30c7a23cbd18e5d7d4a2f260e7d4971ac55436d1ebe7c93caa96877aa07cc6cfa817af0e34952d32d43e0f74a4daf08d77dfa5c02dbf1d47367ab60480250f300f65e6c8b04d1a2a9ee39d07d99e396992088742a0c8ca1352d0720a2cea838e262444abffc9ba6ff17d03e030f78700e34e2fdbee564401bf8eb8dbbc0339e4c2e9b3fce70f6e1867978fc5e47cb90845c0d2d4f05f9d663ff64c3515d11236a6fad1fbfc7736291cb8b742686e50768465c7ef9cf695161c6016945a72c78153cf686970314e6a6a59c59e6ddc6ded0c44b9fade133909974d21f4a30f613bfe488edd349353dfc3b0e9dc00b678ceaa46a7a1293daaa2e9d9a9eb138d8eb21c4b5d0ad9273cfdb7309e51f4a8c2cb2c83f40a929df701c661e24cb428e99fecae131459de632c973326fc814509cf9ee808af06a2c1b38d0dcd9b3cef9216c93c0e7e734d89da3a4e609e0dd022e4831b2a79272c75da8265e82119ca7fad1a62cd5509454648bf7fe92d1f69bbde56b8d105c0364c8ee205ec7bc245f71236e80bee376c1334f3af7ef7dd8cdf5fb3bb0369459c46871288707dd1b770c25046b8839ea67ec430a5c393244582f927c2bbdef3bd02fa2afc015a6592b575ad87841f47a3afcc82829ee3b55cac3b6bf8993d9f3182e0a5826183133e928d20cb6f08732b0d3f36abf",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-2ed64e139079d435","tip://id/US-9ef90f7c97271ad8","tip://id/US-1a2806569b35f03f","tip://id/US-a5b5308bd57f637b"],

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
