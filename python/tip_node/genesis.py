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
        "vp_id":             "tip://vp/US-0e8ec1f90f8588b2",
        "name":              "The AI Lab Intelligence Unobscured, Inc.",
        "short_name":        "The AI Lab",
        "jurisdiction_tier": JurisdictionTier.GREEN,
        "jurisdiction":      "US",
        "url":               "https://theailab.org",
        "email":             "trust@theailab.org",
        "registered_at":     GENESIS_TIMESTAMP,
        # Public key embedded by seed script. All nodes read this.
        # Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
        "public_key":        "5a95a8afe07dc9747ace611cbf61c9d07a0fe5088b3f0055881b5e6f0cfd36f208efcd9f2006acdc979d0aceb568f36a67be200397b13be1523c7e0cb8f2893f42a31394119855e8ab998790652e509cc47bdacb69f57c40dfa37e2e7593eb74fee8552394efa18c55024cc1e5defe1cfe79fc422f104f1bb906f304b4eb0f715dab8cac26ad010f97b17f39187ada6916ad4246d29fa1a5c33d122081104c992b9ec07ed6d11ab93ff5dd1c7f1af428ae9f865105d3dc01cb27b37cf2f8990a810d475e59735dba828bdd88fed7535725c82cae9786a155c62ee506adfafcdef84dd138a01e7afc0f362d96bf3fbd4dd4875fc25cbcc36a2bbcd6172e6da2d867b705223a80885834468f1df50c85e0e36cbe2c0bd2d08f48ef4a8df1a4bf30787f1320db9f59bf3af7ed689776ac4633c516a2daac12602ef4b4453479000b091cfaf04cf2cd458e1fa7ec9191eea6655b351b039ee250e9bc7a2612b5702dc7d8aa6fd458d69a60735a3e41c5fb758cf4a6eaff0a88e44180f4d583e9dced0dcd215e969c00fc5abbda2bc9849c3e424692cf6de47419fe2222524312f1ffa29e711c5c2234af077849eb2a51ca5f81e9cb693be11fb6498377610dfc60bab3dfff3da7f885bf1ba0aade67811bfc532f16cfad58c63b4674a0aa1e746bf78ac6df17c9473d30b3cb216cff14a399fe2a8b50dbdeb5a0bc8963b49a0d4c4ec9c202a188e9442508da34d9e48ffe818960280a31cfec52f51f7fda50ccddfcb4157ddb438960576a672f167c4ec618cdb81a86f3575e2551676342da48feceda3d316bd743f38eb8458e4bf31ad95cd5dc17c520881e90164a76d0f648018b0476c8438782482fe38c58d468bc972987f349e03d38271c9b921ba35bf3d780582272ed3f43f39cd69a995e8be20b3355976334daf025d63ab93a3be8337532ad64f8eeb7bbdd764be691a927816566a1c7f980028c03b403f786c1a891c8de913f7ea24effa38f00ba243ddea06f28a60d5d2d4429ca4cb1ad407de166333d7201efad97ce27e0108113eef9e76e8ea5e0d4449730114977bd452fd4452e53dd237b1258dc408d9010d3c99a0a17142b9fcebda6547d5b1d216adf99f1b7ad08e540c94a71ca6e30408f53b2f30d526e5b69204d43b9f61b97e4cd329cf6a065a389341a21989450fc3165cf2675268c2b413ef10656cfb612b113cc552f6c5aa2a8446e95db196ada6e4a091b2c0d97c5f4fdb4982010eac9a12ea39051f24c7ecdd0572e9bb034bec70115f374dc47e8380cf19afaab3829bfa5199e080d05a945395f1c4f3e16284af975faa4ed0c37b13f5e734cd8945949d2b76f2f3b3aa81e708dfe7a42dc5057866fd2fc345dcf977c8836c834507e4b130adb673e51e9a0eed8e72cb792ff62bca59122c440b5ddad24e43070d2f34dcc57495131347bb74993190d922d20358ada70589997e7eb966cd1d8732a23ab10d3e7a6e5ea0afe2b0fbb725fe6c8dc9e4eeb8540aba0bff18825cc5f7ae290f594fa59896098cbe8416f5ce5389e0f30a86f4cde30a02792982839b55ec0f81f3390dd1f677eb059c488bf8b975313083abb7bde635d4023de84746900e8eb89066ca273dcc48641e3498b8166b0db7643f6fc109739acbc8ffb395e971bb7c1b267adf99a8b202a2206c488e8b25a88cbc4ffa738b609baa49ce8ccf5aa92000612d6827cb60765d394155b4eb3ec4872cfbf86406629c51f05e633896808361fe4083742b5571190f30e52a624f55fbb173b214e72a543953b8375ec99f8cd8e04f2a064a8bcaaa76be93e5221ef2fa6dccf338df664c662359fea2178c9fa240ed0ecf6815b5c6cb1237793d79bb82e9df0989f940adcba88ddef85bcc6ad3ec6b4831ee67b3e67a06c4a7e20552139c2e64fc4cf03c00ab7e56abd74bd25a5134318bb03cd47f810477029029e5d5c20fc48b6b3587d3b014a9d7f021da1bbdcfd9873f0787bef85c33d82d53d463289f59b61435df1d4ef6267cd1aa7e92b593b2054ca400007d37d7b62bddae5415edd3a294771713ce4a681048ebabcb1ed5e20ea5ebc88a08b04b2abf8883d56f7766d73366d85980f9c0d7c3a65467bb792ca8eca47b4e6e1fa734651b2b3905478aacf78bf51b6524f9d6018d679ce1c611922380b5f681b4c20c0c9247102199ec3afac39876d64005190fd306b45af8e6e3a8932c80224cf4581d8137b524c196a926be2263445abc774efd434d1b5595936c03eee2df90a628e9e5f0322d9671241fb2562d33f6277f3faa3031a0f4c6a799138623a3a9e7e7aef979b0d14f3cf0182aed9da8544e165da33d1bdc6dde9ecd7e3979c88d4c953b5a8761653a2a1570f534736a780a7486b95446a5828be6ba7a51e257c700a9c96e3ffba457dc931905ce2cec68a44888e3668636aaaa42469596d61686d5503c0ba7be5aa23084e64911c7f630bafe484b05d52bc6987eb43a7d090cea777dde9666addf48cb9a5ca4a6ad4caa381469ac7798e5fcb0c64a925761bbc4fae342b4b58cf0182dd5756af5b7107915462ac7af204d2d5101020da7db5dc1a70e1bddcdffbfce50e539545923daf2ab615ca5a086e67e7e6cf3cd2f2846f0cd703bc8e9f9f74b1044377892eabc0f9655c21b76bcf2abe936ca60c9c19134abe754cb4a3c79a6af8f5dea1e04319d1f39dbea85b2df4e6baf0dde17a070a2f6311e1d2692152b2d50101f8fab9edbb1633fb19e640aa1697",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-74b4b890db2b11ef","tip://id/US-871d68f72fee1d5e","tip://id/US-104c12ca5dde8c24","tip://id/US-af4f66cf6b0f69e9"],

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
