"""
Jury selection and adjudication logic for TIP dispute resolution.

Stage 2: Deterministic jury selection — same identities + dispute tx = same 7 jurors on any node.
Stage 3: Expert appeal selection — same algorithm, higher threshold.

© 2026 The AI Lab Intelligence Unobscured, Inc.
License: TIPCL-1.0
"""

from shared.crypto import shake256
from shared.constants import Jury, Appeal


def _seeded_shuffle(arr: list, seed_hex: str) -> list:
    """Deterministic Fisher-Yates shuffle using seed bytes instead of random."""
    seed_bytes = bytes.fromhex(seed_hex)
    shuffled = list(arr)
    for i in range(len(shuffled) - 1, 0, -1):
        j = seed_bytes[i % len(seed_bytes)] % (i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
    return shuffled


def _pick_with_geo_cap(shuffled: list, count: int, max_per_region: int) -> list[str]:
    """Pick N from shuffled list with geographic diversity cap."""
    selected = []
    region_count: dict[str, int] = {}
    for identity in shuffled:
        region = identity.get("region", "XX")
        if region_count.get(region, 0) >= max_per_region:
            continue
        region_count[region] = region_count.get(region, 0) + 1
        selected.append(identity["tip_id"])
        if len(selected) == count:
            break
    return selected


def select_jury(dag, scoring, dispute_tx_id: str, author_tip_id: str, disputer_tip_id: str) -> dict:
    """
    Deterministic jury selection.
    seed = SHAKE-256(dispute_tx_id + identity_count)
    Eligible pool sorted by tip_id → seeded shuffle → geographic cap → pick 7.
    """
    all_identities = dag.get_all_identities()
    identity_count = len(all_identities)

    seed = shake256(f"{dispute_tx_id}:{identity_count}")

    eligible = sorted(
        [
            ident for ident in all_identities
            if ident.get("tip_id") != author_tip_id
            and ident.get("tip_id") != disputer_tip_id
            and not dag.is_revoked(ident.get("tip_id", ""))
            and scoring.get_score(ident.get("tip_id", "")).get("score", 0) >= Jury.MIN_SCORE
        ],
        key=lambda x: x.get("tip_id", ""),
    )

    if len(eligible) < Jury.SIZE:
        return {
            "jurors": [e["tip_id"] for e in eligible],
            "insufficient": True,
            "seed": seed,
            "identityCount": identity_count,
        }

    shuffled = _seeded_shuffle(eligible, seed)
    jurors = _pick_with_geo_cap(shuffled, Jury.SIZE, Jury.MAX_SAME_COUNTRY)

    return {
        "jurors": jurors,
        "insufficient": len(jurors) < Jury.SIZE,
        "seed": seed,
        "identityCount": identity_count,
    }


def select_experts(dag, scoring, appeal_tx_id: str, author_tip_id: str, disputer_tip_id: str) -> dict:
    """
    Deterministic expert selection for Stage 3 appeal.
    Same algorithm as jury but higher score threshold and 3 experts.
    """
    all_identities = dag.get_all_identities()
    identity_count = len(all_identities)

    seed = shake256(f"{appeal_tx_id}:{identity_count}")

    eligible = sorted(
        [
            ident for ident in all_identities
            if ident.get("tip_id") != author_tip_id
            and ident.get("tip_id") != disputer_tip_id
            and not dag.is_revoked(ident.get("tip_id", ""))
            and scoring.get_score(ident.get("tip_id", "")).get("score", 0) >= Appeal.MIN_EXPERT_SCORE
        ],
        key=lambda x: x.get("tip_id", ""),
    )

    if len(eligible) < Appeal.EXPERT_COUNT:
        return {
            "experts": [e["tip_id"] for e in eligible],
            "insufficient": True,
            "seed": seed,
            "identityCount": identity_count,
        }

    shuffled = _seeded_shuffle(eligible, seed)
    experts = _pick_with_geo_cap(shuffled, Appeal.EXPERT_COUNT, 2)

    return {
        "experts": experts,
        "insufficient": len(experts) < Appeal.EXPERT_COUNT,
        "seed": seed,
        "identityCount": identity_count,
    }
