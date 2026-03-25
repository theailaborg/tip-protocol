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
        "public_key":        "57ad9f2a9a92aca3e88deca83b0123a9d79636ca768329e9f7af1ae5594d8c8b5b53a6aff0055b44e9558179cc58960751999a67fc8de55d9591701535f0fc9d72ebb949a8f453bf3da06cdcaa3532ed19747661247147d69a9853e48d1f324f1b2acd0da043a1bd9c593b7b92ad50ba0261afe650e0cc6a033820cd37fa23ad228e643189027845f35b5210fc4d14ad0bd5a5c29f6f0557ab11c24f27211014ddbf0e6a5317ea724ddea0d2c99a9298e7de08cb05990f03f9e4a4a561e51fa9ba592cea2a5f8bc5c2f02cb67124392ac240b2a551ca0156a123521fb2199c18e093b1ad582646c3ccfb90aef54743a7da5831e86f2ca81e4dc2574469aa644c18f897ad089f78053be81c42888647338d07a6ebaf119044775f49c81093ba1862a349f69f271fc3b7ac4c7354f3b63bcb62efe6c07202c3ac712b86dd7d6255be3dfcea1dfc89ec4894ac5e050e19b3bdc37776311bbf08475932577965bf0ff391f24d046a3b7c599530c158601a1458ad4656798268ca8a633e9cad514a8eae4247d78a92083a4b2ca01532063b19d536bc1c48f1bfeaf554a480e505f35f875bb0c7350480670ef3e0e068f68cc481db14cba2b9ad5797f52d9a2a9d6ce4de579ecfc8dd6194c8438f93c94e50a180c5a427f3f6a3321cfa53b5700ac306d278a560215414ffb22a82c853265623f670e2bf1a43690a377ee2090e39b0d865a13ab012b0a87a5daf2063f3b3065a55d3dd84f1a7801de735ceba2566388dcc91ea5704292acc0ea08c787edbf51ccc811ec82482a0571308e25111607aa4c1914d18c38cc69933a2fe68bdfc56fa1120a8f258f6413fd64fd411a1c091bdf0a89f243e1c951c722fe43532f120fa069146dc1953dfeb5054c899f9cc4c2262fd4c7a2e3a4539d661a87a56b1a1a9bde24e392e5c6310ef042031c18a582df02fd8befee97f656fc295c322ac061f658fbf57c30b05047892511ab716ae6e4961f633b35f6bdb50bbe336a8c919c5e2e60409b4d700ca55f7900fea3403432bbeca55b32d649c5ff94f1de75fe51c55f04354d8f3192baf0c4fc92e22bdb0f6c682c959d822343461328677a620a4ce76472aab7a50b02d3c86d8630c29ecb5611ea5ea56c224cb722653b680334457799b6778b57b5b2d171f0b9a0eb4ab93be621c274e83c8baadf2353fc7798d6caa53c21677027a877d87ad8dd2cad29f3011936b74f43fd27bb5a241a9296e397c5bddc1b67f3435aaf96412ea6da86520c9f01e6d2ad203b96eb682907291dc9a2e32679d05702b60e86c2549e908a8a9dad45e8e39a5eec1387b1ccf1c9def48ec34490d9ababbd3846a70b4a5e4614885339d9a2284455454684607ea4fccfd1230c8d656141d6a0f93f019836683507085d03e46a9e277fbb8dc57117bcac0d5b4355378e9854dabac66fc544b2728c5bdf985fb9607eb2e528f2f2e8e8d5094427e7763db9b75dc0468c0eebb42df469b26a892cb572064c1c0690f64ab4997e0ea961193c8fde32deb5084400e92fdcbf4e99803f99b2dba820ca614a8d5fa89e4fdc1d0f0f590ae65e8965a43bcd7dfbdc9dd4b010176f70013e5a9ff0cf457ac74b5e2b144060e800225564fbb52e6b9dfae11d5b613b26d29c9c29b9d8edfaf7684b7478eac7360120d5a3db49708cbf09fdefbb9f00ce1d929304b8764fe4563eff752cc03b51db38967ea1fb24d2d2851f8892c53e0ef68137b385bb5abace9ce5a74a7486de6766b93ce5ee2852ba7b32db32dd6b793cfb29d923b349756526b7d26bbe61227731f82e2b277d14f85a6011f2778ab1101aa1fe740271c8caba4fc468546df7e0b28191553ba4d4969ee14f551cd9f2bedfa0cde4b475fe7ecb4f40705ac05be81d6014c1cf2940f4e452e8d5af42a9c010784f57a72da1049bdbc5ffe575dd0e27c410a3cf2f680107a0aefa0b656ffafe95d1d2740d1bb7f54fd79ab2c76a98ebaf5cf8b4729500adccc133434df53438ab5da9144946d4fbc0f879b269058444ef761caf53f69c1a763e2533af177e383c40f30c31abd6038d9298c28a8a6cced4b6565e13f7215add21af620622d3a244fc9b672ff9a632b66b4947bf0541b1b12cd4f208c3536fbb1d2fcfe740761c1001e06072b18b617e664016b78211ba993b8734e2abbb250a61b593565a7e146e3f9f00cf0d0fbcd41a4a9b33ca57b347dd14243a1f094b3080336816dc024f0fb66859ed8859f969c6a1cd90d5cddebf4f3a9933005730630132ed88743e741ddae96921610c9add51a29efe1051a3d244f1fb2d04089670a0cd4b9149d3951dd96f473cfe424410b532e0e9091d911e10beb477e59a32db59fb10db2a270a49ecb3a6b375baa44c051b871f567878205147ea24e587c2340afba79ab2ef3f268e05be821e7f48de7cc804cbdc35a8ba6190af3a3e190a9537328696068b83cadea24adf7a41a81bad651df0787a78a1f3936f710a5b5ab9acdb7e95263b0d55f84a92c35426d06ecc092635c5c40c50ee2d1c0684c0e4f9ba4021051863c808025ec09d620e32472cbb486ebf5f179ff96756bb6a08b52b15edffb8b5f3b3adef55e7e2e56e9d936d307f305e2231ddd7922c2b33ceb4cf51589024a819b4a6f17b1373180ac2f16ee51a422d68be23f7805fdce43318acfebb091769a1b478791e92748491d2742ea4630e0854030212ca0608eb0b637ca7ba367bd0e77c69c708c2ec7f4fd9b88f68fe3923e0d8db9",
    },

    "founding_node_commitment": None,

    "genesis_ring": ["tip://id/US-9bb82a1138aa1ba8","tip://id/US-cdfbe328f5f0036f","tip://id/US-0f029589184aa2f6"],

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
