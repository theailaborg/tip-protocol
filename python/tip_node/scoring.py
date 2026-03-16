"""
node/scoring.py
TIP Protocol Python — Deterministic Trust Scoring Engine

# Author:    Dinesh Mendhe <chairman@theailab.org>
Core invariant:
  Given the same DAG transaction history, every protocol-compliant node
  MUST compute the same trust score for any TIP-ID.

Score range: 0 to 1000 (integer, clamped)
Starting score: 500 (no attestation) or 550 (with social attestation)

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Optional

from shared.constants import TxType, ScoreEvent, Origin, get_tier
from tip_node.logger import get_logger

log = get_logger("scoring")


def _parse_ts(ts: str) -> Optional[datetime]:
    """Parse an ISO timestamp string to a timezone-aware datetime."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _clamp(score: int) -> int:
    return max(ScoreEvent.MIN_SCORE, min(ScoreEvent.MAX_SCORE, score))


class ScoringEngine:
    """Deterministic trust scoring engine. Thread-safe for reads."""

    def __init__(self, dag, config: dict) -> None:
        self._dag    = dag
        self._config = config

    # ── Public API ────────────────────────────────────────────────────────────

    def get_score(self, tip_id: str) -> dict:
        """
        Return the trust score for a TIP-ID.
        Uses the cached score (fast path) and falls back to full recompute.
        """
        cached = self._dag.get_score(tip_id)
        if cached:
            tier = get_tier(cached["score"])
            return {
                "score":         cached["score"],
                "tier":          tier.name,
                "tier_label":    tier.label,
                "tier_color":    tier.color,
                "offense_count": cached.get("offense_count", 0),
                "last_updated":  cached.get("last_updated"),
            }
        return self.compute_score(tip_id)

    def compute_score(self, tip_id: str) -> dict:
        """
        Compute (or recompute) trust score from full DAG history.
        This is the authoritative deterministic computation.
        Side-effect: updates the score cache in the DAG store.
        """
        txs = self._dag.get_txs_by_tip_id(tip_id)
        txs.sort(key=lambda t: t.get("timestamp", ""))

        score         = ScoreEvent.INITIAL_NO_ATTESTATION
        offense_count = 0
        history       = []
        last_clean_ts = None

        for tx in txs:
            tx_type = tx.get("tx_type", "")
            data    = tx.get("data", {})
            ts      = tx.get("timestamp", "")
            delta   = 0
            reason  = ""

            if tx_type == TxType.REGISTER_IDENTITY:
                attested = data.get("attested") or data.get("social_attested")
                score    = ScoreEvent.INITIAL_WITH_ATTESTATION if attested else ScoreEvent.INITIAL_NO_ATTESTATION
                delta    = ScoreEvent.ATTESTATION_BONUS if attested else 0
                reason   = ("Registration with social attestation" if attested
                            else "Registration")
                last_clean_ts = _parse_ts(ts)

            elif tx_type == TxType.CONTENT_VERIFIED:
                weighted = int(data.get("weighted_delta", 2))
                delta    = max(1, min(5, weighted))   # cap: 1–5 per verification
                reason   = f"Content verified: {data.get('ctid', '')[:30]}"

            elif tx_type == TxType.ADJUDICATION_RESULT:
                delta, reason = self._adjudication_delta(data, offense_count)
                if delta < 0:
                    offense_count += 1
                    if delta <= -100:
                        last_clean_ts = None  # reset clean period on serious offense

            elif tx_type == TxType.SCORE_UPDATE:
                delta  = int(data.get("delta", 0))
                reason = data.get("reason", "Score update")
                if data.get("type") == "appeal_restore":
                    reason = "Successful appeal (+50% restored)"

            elif tx_type == TxType.REVOKE_DEVICE:
                delta  = ScoreEvent.DEVICE_COMPROMISE
                reason = "Device compromise pending re-verification"

            if delta != 0 or tx_type == TxType.REGISTER_IDENTITY:
                score = _clamp(score + delta)
                history.append({
                    "tx_id":       tx.get("tx_id", ""),
                    "tx_type":     tx_type,
                    "delta":       delta,
                    "score_after": score,
                    "reason":      reason,
                    "timestamp":   ts,
                })

        # ── 90-day clean record recovery (+10 per period) ─────────────────────
        if last_clean_ts:
            now = datetime.now(timezone.utc)
            if last_clean_ts.tzinfo is None:
                last_clean_ts = last_clean_ts.replace(tzinfo=timezone.utc)
            days_clean    = (now - last_clean_ts).days
            periods_earned = min(days_clean // 90, 5)  # cap at 5 periods
            if periods_earned > 0:
                bonus  = periods_earned * ScoreEvent.CLEAN_PERIOD_BONUS
                score  = _clamp(score + bonus)
                history.append({
                    "tx_id":       "synthetic:clean-record",
                    "tx_type":     "CLEAN_RECORD_BONUS",
                    "delta":       bonus,
                    "score_after": score,
                    "reason":      f"{periods_earned} × 90-day clean periods (+{bonus})",
                    "timestamp":   now.isoformat(),
                })

        tier = get_tier(score)
        self._dag.set_score(tip_id, score, offense_count)

        return {
            "score":         score,
            "tier":          tier.name,
            "tier_label":    tier.label,
            "tier_color":    tier.color,
            "offense_count": offense_count,
            "history":       history,
        }

    def apply_score_event(
        self,
        tip_id: str,
        delta: int,
        reason: str,
        related_tx_id: Optional[str] = None,
    ) -> int:
        """
        Apply a score event and persist a SCORE_UPDATE transaction.
        Returns the new score.
        Thread-safe: get_score + set_score + add_tx are each independently safe.
        """
        current = self._dag.get_score(tip_id) or {"score": 500, "offense_count": 0}
        new_score = _clamp(current["score"] + delta)
        self._dag.set_score(tip_id, new_score, current.get("offense_count", 0))
        self._dag.add_tx({
            "tx_type":   TxType.SCORE_UPDATE,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "tip_id":          tip_id,
                "delta":           delta,
                "score_after":     new_score,
                "reason":          reason,
                "related_tx_id":   related_tx_id,
            },
        })
        return new_score

    def recompute_all(self) -> int:
        """
        Recompute all scores from DAG history.
        Returns the number of identities recomputed.
        """
        txs = self._dag.get_txs_by_type(TxType.REGISTER_IDENTITY)
        count = 0
        for tx in txs:
            tip_id = tx.get("data", {}).get("tip_id")
            if tip_id:
                self.compute_score(tip_id)
                count += 1
        log.info(f"Score recomputation complete. {count} identities recomputed.")
        return count

    def is_jury_eligible(self, tip_id: str) -> bool:
        """
        Return True if this TIP-ID is eligible to serve as a juror:
          - Score >= 700
          - Not revoked
          - Status = active
        """
        if self._dag.is_revoked(tip_id):
            return False
        rec = self._dag.get_identity(tip_id)
        if rec and rec.get("status") != "active":
            return False
        score_data = self.get_score(tip_id)
        return score_data["score"] >= ScoreEvent.JUROR_MIN_SCORE

    # ── Private ───────────────────────────────────────────────────────────────

    def _adjudication_delta(self, data: dict, current_offense_count: int) -> tuple[int, str]:
        """Compute the score delta from an adjudication result."""
        declared = data.get("declared_origin", "")
        confirmed = data.get("confirmed_origin", "")
        verdict   = data.get("verdict", "")

        if verdict in ("CLEARED", "DISMISSED"):
            return 0, f"Adjudication cleared: {data.get('ctid', '')[:30]}"

        if verdict == "CONSERVATIVE_LABEL":
            return 0, "Conservative labelling — no penalty"

        # OH declared, AG confirmed — most serious
        if declared == Origin.OH and confirmed == Origin.AG:
            if current_offense_count >= 2:
                return ScoreEvent.MISMATCH_3RD_OFFENSE, "3rd+ OH→AG mismatch: account suspended"
            if current_offense_count >= 1:
                return ScoreEvent.MISMATCH_2ND_OFFENSE, "2nd OH→AG mismatch: account flagged"
            return ScoreEvent.OH_CONFIRMED_AG_1ST, "1st OH→AG mismatch: warning"

        # OH declared, AA confirmed
        if declared == Origin.OH and confirmed == Origin.AA:
            if current_offense_count >= 1:
                return ScoreEvent.MISMATCH_2ND_OFFENSE, "2nd mismatch: OH declared, AA confirmed"
            return ScoreEvent.OH_CONFIRMED_AA, "OH declared, AI-Assisted confirmed"

        # AA declared, AG confirmed
        if declared == Origin.AA and confirmed == Origin.AG:
            if current_offense_count >= 1:
                return ScoreEvent.MISMATCH_2ND_OFFENSE, "2nd mismatch: AA declared, AG confirmed"
            return ScoreEvent.AA_CONFIRMED_AG, "AA declared, AI-Generated confirmed"

        # Factual falsehood
        if data.get("type") == "FACTUAL_FALSEHOOD":
            severity = data.get("severity", "minor")
            if severity == "major":
                return ScoreEvent.FACTUAL_FALSEHOOD_MAJOR, "Major factual falsehood"
            return ScoreEvent.FACTUAL_FALSEHOOD_MINOR, "Minor factual falsehood"

        return 0, f"Adjudication: verdict={verdict}"
