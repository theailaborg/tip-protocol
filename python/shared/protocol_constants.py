"""
shared/protocol_constants.py
Immutable protocol constants loaded from the genesis block.

These are NOT configuration. They are protocol-level values that must be
identical across every node in the network.

Usage:
    from shared.protocol_constants import PC
    # At boot (once):
    PC.init(genesis_payload["protocol_constants"])
    # Everywhere else:
    jury_size = PC.get().jury.jury_size

Or use the backward-compatible accessors:
    from shared.protocol_constants import JURY, DISPUTE, APPEAL
    jury_size = JURY.SIZE

© 2026 The AI Lab Intelligence Unobscured, Inc.
License: TIPCL-1.0
"""

from __future__ import annotations
from typing import Any

# Default protocol constants — must match genesis block exactly.
# In production, these are overridden by genesis payload at boot.
_DEFAULT_PROTOCOL_CONSTANTS = {
    "score": {"max_total": 1000, "max_identity": 530, "max_content": 350, "max_reputation": 50, "max_longevity": 70, "initial_identity": 500},
    "identity": {"social_link_bonus": 5, "max_social_accounts": 6, "max_social_bonus": 30},
    "content": {"registration_credit": 2, "verification_credit": 1, "oh_cap": 200, "aa_cap": 100, "ag_cap": 100, "mx_cap": 100, "per_content_lifetime_cap": 5},
    "reputation": {"clean_period_days": 90, "clean_period_bonus": 10, "dispute_cleared_bonus": 5},
    "longevity": {"tiers": [{"months": 6, "points": 15}, {"months": 12, "points": 30}, {"months": 24, "points": 45}, {"months": 36, "points": 60}, {"months": 60, "points": 70}]},
    "penalties": {"oh_as_ag": [-100, -200, -300], "oh_as_aa": [-40, -80, -120], "aa_as_ag": [-25, -50, -75], "minor_falsehood": -75, "major_falsehood": -300, "retraction": -50, "device_compromise": -15, "lost_dispute_stake": -15, "lost_jury_stake": -10, "lost_appeal_stake": -25, "appeal_restore_percent": 50},
    "jury": {"dispute_stake": 15, "dispute_filing_min_score": 400, "jury_stake": 10, "jury_size": 7, "jury_min_score": 700, "jury_majority_bonus": 3, "jury_commit_hours": 72, "jury_reveal_hours": 6, "jury_min_reveals": 5, "jury_majority_vote": 3, "jury_minority_penalty": -10, "jury_no_show_penalty": -10, "jury_max_same_country": 3, "jury_cooldown_days": 7, "expert_panel_size": 3, "expert_min_score": 850, "expert_min_votes": 2, "appeal_stake": 25, "appeal_win_bonus": 10, "appeal_window_hours": 48, "appeal_commit_hours": 72, "appeal_reveal_hours": 6, "frivolous_dismiss_fee": 5, "ai_auto_dismiss_threshold": 0.30, "ai_auto_escalate_threshold": 0.90, "ai_timeout_seconds": 60, "vindication_bonus": 5, "upheld_bonus": 5},
    "tiers": {"highly_trusted": 850, "trusted": 650, "verified": 400, "caution": 200},
    "verify_caps": {"per_content": 5, "per_day": 5, "per_month": 30, "base_delta": 2, "high_trust_delta": 3, "high_trust_min": 800},
    "rate_limits": {"max_registrations_per_day": 50, "max_verifications_given_per_day": 5, "max_verifications_given_per_month": 30, "duplicate_perceptual_threshold": 0.90},
    "prescan": {"default": 0.85, "conversational": 0.82, "creative": 0.87, "academic": 0.92, "legal": 0.93, "floor": 0.80, "ceiling": 0.94},
    "network": {"chain_id": "tip-mainnet-v2", "merkle_publish_hours": 6, "score_cache_ttl_seconds": 21600, "revocation_cascade_days": 90, "warrant_canary_max_days": 90, "canary_advisory_window_days": 30, "origin_grace_period_hours": 24},
}


class _FrozenDict:
    """Immutable dict-like object with attribute access."""
    def __init__(self, data: dict):
        for k, v in data.items():
            if isinstance(v, dict):
                object.__setattr__(self, k, _FrozenDict(v))
            elif isinstance(v, list):
                object.__setattr__(self, k, tuple(
                    _FrozenDict(i) if isinstance(i, dict) else i for i in v
                ))
            else:
                object.__setattr__(self, k, v)

    def __setattr__(self, name: str, value: Any):
        raise AttributeError("Protocol constants are immutable")

    def __getitem__(self, key: str):
        return getattr(self, key)

    def get(self, key: str, default=None):
        return getattr(self, key, default)


class ProtocolConstants:
    _instance: _FrozenDict | None = None

    @classmethod
    def init(cls, protocol_constants: dict) -> _FrozenDict:
        if cls._instance is not None:
            raise RuntimeError("ProtocolConstants already initialized")
        if not protocol_constants or not isinstance(protocol_constants, dict):
            raise RuntimeError("Invalid genesis protocol_constants")
        cls._instance = _FrozenDict(protocol_constants)
        return cls._instance

    @classmethod
    def get(cls) -> _FrozenDict:
        if cls._instance is None:
            # Auto-initialize with default protocol constants
            cls.init(_DEFAULT_PROTOCOL_CONSTANTS)
        return cls._instance

    @classmethod
    def is_initialized(cls) -> bool:
        return cls._instance is not None

    @classmethod
    def _reset_for_testing(cls):
        cls._instance = None


PC = ProtocolConstants


# ── Backward-compatible accessors ─────────────────────────────────────────
# Match the old constant names from shared/constants.py.

def _j():
    return PC.get().jury

def _p():
    return PC.get().penalties

def _t():
    return PC.get().tiers

def _v():
    return PC.get().verify_caps

def _ps():
    return PC.get().prescan


class _VerifyCapsAccessor:
    @property
    def PER_CONTENT(self): return _v().per_content
    @property
    def PER_DAY(self): return _v().per_day
    @property
    def PER_MONTH(self): return _v().per_month
    @property
    def BASE_DELTA(self): return _v().base_delta
    @property
    def HIGH_TRUST_DELTA(self): return _v().high_trust_delta
    @property
    def HIGH_TRUST_MIN(self): return _v().high_trust_min

class _DisputeAccessor:
    @property
    def MIN_SCORE_TO_DISPUTE(self): return _j().dispute_filing_min_score
    @property
    def DISPUTER_STAKE(self): return _j().dispute_stake
    @property
    def FRIVOLOUS_PENALTY(self): return _j().frivolous_dismiss_fee
    @property
    def UPHELD_BONUS(self): return _j().upheld_bonus
    @property
    def VINDICATION_BONUS(self): return _j().vindication_bonus

class _JuryAccessor:
    @property
    def SIZE(self): return _j().jury_size
    @property
    def MIN_SCORE(self): return _j().jury_min_score
    @property
    def JUROR_STAKE(self): return _j().jury_stake
    @property
    def MAJORITY_VOTE(self): return _j().jury_majority_vote
    @property
    def COMMIT_WINDOW_HOURS(self): return _j().jury_commit_hours
    @property
    def REVEAL_WINDOW_HOURS(self): return _j().jury_reveal_hours
    @property
    def QUORUM(self): return _j().jury_min_reveals
    @property
    def MAJORITY_BONUS(self): return _j().jury_majority_bonus
    @property
    def MINORITY_PENALTY(self): return abs(_j().jury_minority_penalty)
    @property
    def NO_SHOW_PENALTY(self): return abs(_j().jury_no_show_penalty)
    @property
    def MAX_SAME_COUNTRY(self): return _j().jury_max_same_country

class _AppealAccessor:
    @property
    def APPELLANT_STAKE(self): return _j().appeal_stake
    @property
    def MIN_EXPERT_SCORE(self): return _j().expert_min_score
    @property
    def EXPERT_COUNT(self): return _j().expert_panel_size
    @property
    def MIN_VOTES(self): return _j().expert_min_votes
    @property
    def FILING_WINDOW_HOURS(self): return _j().appeal_window_hours
    @property
    def COMMIT_WINDOW_HOURS(self): return _j().appeal_commit_hours
    @property
    def REVEAL_WINDOW_HOURS(self): return _j().appeal_reveal_hours
    @property
    def OVERTURN_BONUS(self): return _j().appeal_win_bonus

class _AiClassifierAccessor:
    @property
    def AUTO_DISMISS_THRESHOLD(self): return _j().ai_auto_dismiss_threshold
    @property
    def HIGH_CONFIDENCE(self): return _j().ai_auto_escalate_threshold
    @property
    def TIMEOUT_SECONDS(self): return _j().ai_timeout_seconds

class _ScoreEventsAccessor:
    @property
    def CONTENT_RETRACTION(self): return _p().retraction
    @property
    def DEVICE_COMPROMISE_PENDING(self): return _p().device_compromise
    # Per-pair offense escalation [1st, 2nd, 3rd+] per spec
    # (TIP_Trust_Scoring §6 — base x [1, 2, 3]). Prior universal-ladder
    # aliases (MISMATCH_2ND/3RD_OFFENSE all reading oh_as_ag) over-penalised
    # repeat AA→AG / OH→AA offenders; replaced with per-pair lookups.
    @property
    def OH_CONFIRMED_AG_1ST(self): return _p().oh_as_ag[0]
    @property
    def OH_CONFIRMED_AG_2ND(self): return _p().oh_as_ag[1]
    @property
    def OH_CONFIRMED_AG_3RD(self): return _p().oh_as_ag[2]
    @property
    def OH_CONFIRMED_AA_1ST(self): return _p().oh_as_aa[0]
    @property
    def OH_CONFIRMED_AA_2ND(self): return _p().oh_as_aa[1]
    @property
    def OH_CONFIRMED_AA_3RD(self): return _p().oh_as_aa[2]
    @property
    def AA_CONFIRMED_AG_1ST(self): return _p().aa_as_ag[0]
    @property
    def AA_CONFIRMED_AG_2ND(self): return _p().aa_as_ag[1]
    @property
    def AA_CONFIRMED_AG_3RD(self): return _p().aa_as_ag[2]
    @property
    def FACTUAL_FALSEHOOD_MINOR(self): return _p().minor_falsehood
    @property
    def FACTUAL_FALSEHOOD_MAJOR(self): return _p().major_falsehood
    @property
    def CLEAN_PERIOD_BONUS(self): return PC.get().reputation.clean_period_bonus
    @property
    def INITIAL_NO_ATTESTATION(self): return PC.get().score.initial_identity
    @property
    def INITIAL_WITH_ATTESTATION(self): return PC.get().score.initial_identity + 50  # legacy: attestation bonus
    @property
    def MAX_SCORE(self): return PC.get().score.max_total
    @property
    def MIN_SCORE(self): return 0


# Singleton instances — import these
VerifyCaps = _VerifyCapsAccessor()
Dispute = _DisputeAccessor()
Jury = _JuryAccessor()
Appeal = _AppealAccessor()
AiClassifier = _AiClassifierAccessor()
ScoreEvent = _ScoreEventsAccessor()


class _TierResult:
    """Tier result with both attribute and dict access."""
    def __init__(self, name, label, color):
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "label", label)
        object.__setattr__(self, "color", color)
    def get(self, key, default=None):
        return getattr(self, key, default)
    def __getitem__(self, key):
        return getattr(self, key)


def get_tier(score: int):
    """Return tier info for a given score."""
    t = _t()
    if score >= t.highly_trusted:
        return _TierResult("HIGHLY_TRUSTED", "Highly Trusted", "#1A8A5C")
    if score >= t.trusted:
        return _TierResult("TRUSTED", "Trusted", "#2563A8")
    if score >= t.verified:
        return _TierResult("VERIFIED", "Verified", "#A88B15")
    if score >= t.caution:
        return _TierResult("CAUTION", "Caution", "#C07318")
    return _TierResult("NOT_TRUSTED", "Not Trusted", "#C53030")
