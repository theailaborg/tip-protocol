"""
shared/constants.py
TIP Protocol Python — Protocol Constants

# Author:    Dinesh Mendhe <chairman@theailab.org>
Single source of truth for every protocol-level value.

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ─── Origin codes ─────────────────────────────────────────────────────────────

class Origin:
    OH = "OH"  # Original Human
    AA = "AA"  # AI-Assisted
    AG = "AG"  # AI-Generated
    MX = "MX"  # Mixed / Composite

    ALL    = {"OH", "AA", "AG", "MX"}
    LABELS = {
        "OH": "Original Human",
        "AA": "AI-Assisted",
        "AG": "AI-Generated",
        "MX": "Mixed / Composite",
    }

    @classmethod
    def is_valid(cls, code: str) -> bool:
        return code in cls.ALL

    @classmethod
    def label(cls, code: str) -> str:
        return cls.LABELS.get(code, code)


# ─── Trust tiers ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Tier:
    name:  str
    label: str
    min:   int
    max:   int
    color: str


TIERS: list[Tier] = [
    Tier("HIGHLY_TRUSTED", "Highly Trusted",  850, 1000, "#1A8A5C"),
    Tier("TRUSTED",        "Trusted",          650,  849, "#2563A8"),
    Tier("VERIFIED",       "Verified",         400,  649, "#A88B15"),
    Tier("CAUTION",        "Caution",          200,  399, "#C07318"),
    Tier("NOT_TRUSTED",    "Not Trusted",        0,  199, "#C53030"),
]


def get_tier(score: int) -> Tier:
    """Return the Tier for a given score."""
    for tier in TIERS:
        if tier.min <= score <= tier.max:
            return tier
    return TIERS[-1]  # fallback: NOT_TRUSTED


# ─── Verification caps ───────────────────────────────────────────────────────

class VerifyCaps:
    PER_CONTENT      = 5     # max +5 per CTID
    PER_DAY          = 5     # max +5 per creator per day
    PER_MONTH        = 30    # max +30 per creator per month
    BASE_DELTA       = 2     # base credit per verification
    HIGH_TRUST_DELTA = 3     # bonus for verifier score >= HIGH_TRUST_MIN (1.5x)
    HIGH_TRUST_MIN   = 800   # minimum score for high-trust bonus


# ─── Dispute & Jury constants ─────────────────────────────────────────────────

class Dispute:
    MIN_SCORE_TO_DISPUTE  = 400    # Verified tier or above
    DISPUTER_STAKE        = 15     # points held in escrow
    FRIVOLOUS_PENALTY     = 5      # deducted from stake if auto-dismissed (<30%)
    UPHELD_BONUS          = 5      # bonus to disputer if dispute upheld
    VINDICATION_BONUS     = 5      # bonus to creator if dispute auto-dismissed

class Jury:
    SIZE                  = 7      # jurors per dispute
    MIN_SCORE             = 700    # minimum score for jury eligibility
    JUROR_STAKE           = 10     # points staked per juror
    MAJORITY_VOTE         = 3      # votes needed if 2 abstain (otherwise 4)
    COMMIT_WINDOW_HOURS   = 72     # hours to submit vote commitment
    REVEAL_WINDOW_HOURS   = 6      # hours after commit window to reveal
    QUORUM                = 5      # minimum reveals needed (else escalate to Stage 3)
    MAJORITY_BONUS        = 3      # bonus for voting with majority
    MINORITY_PENALTY      = 10     # net loss for voting against majority
    NO_SHOW_PENALTY       = 10     # net loss for failing to reveal
    MAX_SAME_COUNTRY      = 3      # geographic diversity cap
    COOLDOWN_DAYS         = 7      # days before juror can serve same creator again

class Appeal:
    APPELLANT_STAKE       = 25     # higher bar than dispute stake
    MIN_EXPERT_SCORE      = 850    # experts must be highly trusted
    EXPERT_COUNT          = 3      # experts per appeal
    FILING_WINDOW_HOURS   = 48     # hours after ADJUDICATION_RESULT to file
    REVIEW_DAYS           = 7      # days for expert review
    OVERTURN_BONUS        = 10     # bonus to appellant if appeal succeeds

class AiClassifier:
    AUTO_DISMISS_THRESHOLD = 0.30  # <30% → auto-dismiss
    HIGH_CONFIDENCE        = 0.90  # >90% → escalate with flag
    TIMEOUT_SECONDS        = 60    # max time for AI inference


# ─── Transaction types ────────────────────────────────────────────────────────

class TxType:
    # Identity
    REGISTER_IDENTITY      = "REGISTER_IDENTITY"
    UPDATE_DEVICE_BINDING  = "UPDATE_DEVICE_BINDING"
    LINK_PLATFORM          = "LINK_PLATFORM"
    # Content
    REGISTER_CONTENT       = "REGISTER_CONTENT"
    UPDATE_ORIGIN          = "UPDATE_ORIGIN"
    # Trust
    CONTENT_VERIFIED       = "CONTENT_VERIFIED"
    CONTENT_DISPUTED       = "CONTENT_DISPUTED"
    # Adjudication
    AI_CLASSIFIER_RESULT   = "AI_CLASSIFIER_RESULT"
    JURY_SUMMONS           = "JURY_SUMMONS"
    JURY_VOTE_COMMIT       = "JURY_VOTE_COMMIT"
    JURY_VOTE_REVEAL       = "JURY_VOTE_REVEAL"
    ADJUDICATION_RESULT    = "ADJUDICATION_RESULT"
    APPEAL_FILED           = "APPEAL_FILED"
    APPEAL_RESULT          = "APPEAL_RESULT"
    SCORE_UPDATE           = "SCORE_UPDATE"
    # Revocation
    REVOKE_VOLUNTARY       = "REVOKE_VOLUNTARY"
    REVOKE_VP              = "REVOKE_VP"
    REVOKE_DECEASED        = "REVOKE_DECEASED"
    REVOKE_DEVICE          = "REVOKE_DEVICE"
    # Governance
    VP_REGISTERED          = "VP_REGISTERED"
    VP_SUSPENDED           = "VP_SUSPENDED"
    NODE_REGISTERED        = "NODE_REGISTERED"
    MERKLE_ROOT_PUBLISHED  = "MERKLE_ROOT_PUBLISHED"
    # Special
    GENESIS                = "GENESIS"

    REVOCATION_TYPES = {
        REVOKE_VOLUNTARY, REVOKE_VP, REVOKE_DECEASED, REVOKE_DEVICE
    }

    ALL = {
        REGISTER_IDENTITY, UPDATE_DEVICE_BINDING, LINK_PLATFORM,
        REGISTER_CONTENT,
        CONTENT_VERIFIED, CONTENT_DISPUTED, ADJUDICATION_RESULT,
        APPEAL_FILED, SCORE_UPDATE,
        REVOKE_VOLUNTARY, REVOKE_VP, REVOKE_DECEASED, REVOKE_DEVICE,
        VP_REGISTERED, VP_SUSPENDED, MERKLE_ROOT_PUBLISHED, GENESIS,
    }

    @classmethod
    def is_valid(cls, tx_type: str) -> bool:
        return tx_type in cls.ALL


# ─── Scoring events ───────────────────────────────────────────────────────────

class ScoreEvent:
    INITIAL_NO_ATTESTATION   = 500
    INITIAL_WITH_ATTESTATION = 550
    MAX_SCORE                = 1000
    MIN_SCORE                = 0
    DAILY_VERIFY_CAP         = 10
    JUROR_MONTHLY_MAX        = 20
    JUROR_MIN_SCORE          = 700

    # Penalty deltas
    OH_CONFIRMED_AG_1ST      = -100
    OH_CONFIRMED_AA          = -40
    AA_CONFIRMED_AG          = -25
    AG_CONSERVATIVE          = 0    # no penalty
    MISMATCH_2ND_OFFENSE     = -200
    MISMATCH_3RD_OFFENSE     = -350
    FACTUAL_FALSEHOOD_MINOR  = -75
    FACTUAL_FALSEHOOD_MAJOR  = -300
    DEVICE_COMPROMISE        = -15
    CLEAN_PERIOD_BONUS       = 10   # per 90-day clean period

    # Attestation
    VOUCHER_STAKE            = 25
    ATTESTATION_COUNT        = 3
    ATTESTATION_MIN_SCORE    = 700
    ATTESTATION_BONUS        = 50


# ─── Pre-scan thresholds (v2 FIX-03) ─────────────────────────────────────────

class PreScan:
    DEFAULT   = 0.85
    FLOOR     = 0.80
    CEILING   = 0.94

    BY_TYPE: dict[str, float] = {
        "conversational": 0.82,
        "news":           0.85,
        "creative":       0.87,
        "academic":       0.92,
        "legal":          0.93,
    }


# ─── Score display modes (v2 FIX-06) ─────────────────────────────────────────

class ScoreDisplay:
    FULL_PUBLIC   = "FULL_PUBLIC"
    TIER_ONLY     = "TIER_ONLY"     # default
    VERIFIED_ONLY = "VERIFIED_ONLY"
    DEFAULT       = TIER_ONLY

    ALL = {FULL_PUBLIC, TIER_ONLY, VERIFIED_ONLY}


# ─── Jurisdiction tiers (v2 FIX-08) ──────────────────────────────────────────

class JurisdictionTier:
    GREEN = "green"
    AMBER = "amber"
    RED   = "red"    # cannot be accredited

    ACCREDITABLE = {GREEN, AMBER}

    @classmethod
    def can_accredit(cls, tier: str) -> bool:
        return tier in cls.ACCREDITABLE


# ─── HTTP headers ─────────────────────────────────────────────────────────────

class HttpHeaders:
    AUTHOR       = "TIP-Author"
    CONTENT      = "TIP-Content"
    ORIGIN       = "TIP-Origin"
    TRUST_SCORE  = "TIP-Trust-Score"
    SIGNATURE    = "TIP-Signature"
    TIER         = "TIP-Tier"
    VP_ID        = "TIP-VP-ID"
    NODE_ID      = "X-TIP-Node-ID"
    NODE_VERSION = "X-TIP-Node-Version"
    PROTOCOL     = "X-TIP-Protocol"


# ─── API paths ────────────────────────────────────────────────────────────────

class ApiPath:
    HEALTH              = "/health"
    IDENTITY_REGISTER   = "/v1/identity/register"
    IDENTITY_RESOLVE    = "/v1/identity/{tip_id}"
    IDENTITY_SCORE      = "/v1/identity/{tip_id}/score"
    IDENTITY_HISTORY    = "/v1/identity/{tip_id}/history"
    CONTENT_REGISTER    = "/v1/content/register"
    CONTENT_RESOLVE     = "/v1/content/{ctid}"
    CONTENT_VERIFY      = "/v1/content/{ctid}/verify"
    CONTENT_DISPUTE     = "/v1/content/{ctid}/dispute"
    DAG_TX              = "/v1/dag/tx/{tx_id}"
    REVOCATIONS         = "/v1/revocations"
    DEDUP_CHECK         = "/v1/dedup/check"
    DEDUP_MERKLE        = "/v1/dedup/merkle-root"
    VP_REGISTER         = "/v1/vp/register"
    VP_RESOLVE          = "/v1/vp/{vp_id}"
    NODE_INFO           = "/v1/node/info"
    NODE_PEERS          = "/v1/node/peers"


# ─── Protocol metadata ────────────────────────────────────────────────────────

class Protocol:
    NAME       = "Trust Identity Protocol"
    SHORT      = "TIP"
    VERSION    = "2.0.0"
    CHAIN_ID   = "tip-mainnet-v2"
    SPEC_URL   = "https://theailab.org/trust-identity-protocol"
    LICENSE    = "CC-BY-4.0"
    ISSUER     = "The AI Lab Intelligence Unobscured, Inc."
    ISSUER_URL = "https://theailab.org"
    HEADER     = "TIP/2.0"
