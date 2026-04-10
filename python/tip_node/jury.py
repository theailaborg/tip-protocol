"""
Jury selection and adjudication logic for TIP dispute resolution.

Stage 2: Deterministic jury selection — same identities + dispute tx = same 7 jurors on any node.
Stage 3: Expert appeal selection — same algorithm, higher threshold.

© 2026 The AI Lab Intelligence Unobscured, Inc.
License: TIPCL-1.0
"""

from shared.crypto import shake256, compute_tx_id, sign_transaction
from shared.constants import Jury, Appeal, Dispute, TxType
from tip_node.logger import get_logger

log = get_logger("jury")


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


def _node_signed_auto(tx_body: dict, config: dict) -> dict:
    tx_body.setdefault("data", {})["node_id"] = config.get("node_registered_id") or config.get("node_id")
    tx_body["tx_id"] = compute_tx_id(tx_body)
    return sign_transaction(tx_body, config["node_private_key"])


def tally_verdict_and_apply(ctid: str, reveals: list, summons: list, dag, scoring, config: dict) -> dict:
    """Tally jury votes and apply verdict + score effects."""
    from datetime import datetime, timezone

    match_count    = sum(1 for r in reveals if (r.get("data") or {}).get("vote") == "MATCH")
    mismatch_count = sum(1 for r in reveals if (r.get("data") or {}).get("vote") == "MISMATCH")
    abstain_count  = sum(1 for r in reveals if (r.get("data") or {}).get("vote") == "ABSTAIN")
    total_votes    = match_count + mismatch_count + abstain_count
    non_abstain    = match_count + mismatch_count

    # Quorum check — penalize no-shows even on failure
    if total_votes < Jury.QUORUM or non_abstain < Jury.MAJORITY_VOTE:
        revealed_ids = {(r.get("data") or {}).get("juror_tip_id") for r in reveals}
        for s in summons:
            jid = (s.get("data") or {}).get("juror_tip_id")
            if jid not in revealed_ids:
                scoring.apply_score_event(jid, -Jury.NO_SHOW_PENALTY, f"Jury no-show on {ctid}")
        return {"verdict": "NO_QUORUM", "message": "Insufficient votes — escalate to Stage 3",
                "match_count": match_count, "mismatch_count": mismatch_count, "abstain_count": abstain_count}

    majority_needed = non_abstain // 2 + 1
    decision = "UPHELD" if mismatch_count >= majority_needed else "DISMISSED"

    rec = dag.get_content(ctid)
    dispute_txs = dag.get_txs_by_type_and_ctid(TxType.CONTENT_DISPUTED, ctid)
    dispute_data    = (dispute_txs[0].get("data") or {}) if dispute_txs else {}
    disputer_tip_id = dispute_data.get("disputer_tip_id")
    author_tip_id   = rec.get("author_tip_id") if rec else None

    declared_origin = dispute_data.get("declared_origin") or (rec.get("origin_code") if rec else None)
    confirmed_origin = None
    if decision == "UPHELD":
        origin_votes = [
            (r.get("data") or {}).get("confirmed_origin")
            for r in reveals
            if (r.get("data") or {}).get("vote") == "MISMATCH" and (r.get("data") or {}).get("confirmed_origin")
        ]
        origin_counts: dict[str, int] = {}
        for o in origin_votes:
            origin_counts[o] = origin_counts.get(o, 0) + 1
        confirmed_origin = max(origin_counts, key=origin_counts.get) if origin_counts else dispute_data.get("claimed_origin")

    verdict = "DISMISSED" if decision == "DISMISSED" \
        else "CONSERVATIVE_LABEL" if (declared_origin == "AG" and confirmed_origin == "OH") \
        else "UPHELD"

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    result_tx = _node_signed_auto({
        "tx_type":   TxType.ADJUDICATION_RESULT,
        "timestamp": now_str,
        "prev":      dag.get_recent_prev(),
        "data": {
            "ctid": ctid, "verdict": verdict,
            "declared_origin": declared_origin, "confirmed_origin": confirmed_origin,
            "reason": dispute_data.get("reason"), "author_tip_id": author_tip_id,
            "match_count": match_count, "mismatch_count": mismatch_count, "abstain_count": abstain_count,
            "juror_votes": [{"juror_tip_id": (r.get("data") or {}).get("juror_tip_id"),
                             "vote": (r.get("data") or {}).get("vote")} for r in reveals],
        },
    }, config)
    dag.add_tx(result_tx)

    # Juror score effects
    is_tie = match_count == mismatch_count
    if not is_tie:
        majority_vote = "MISMATCH" if mismatch_count > match_count else "MATCH"
        for r in reveals:
            juror_id = (r.get("data") or {}).get("juror_tip_id")
            v = (r.get("data") or {}).get("vote")
            if v == "ABSTAIN":
                continue
            if v == majority_vote:
                scoring.apply_score_event(juror_id, Jury.MAJORITY_BONUS, f"Jury majority vote on {ctid}")
            else:
                scoring.apply_score_event(juror_id, -Jury.MINORITY_PENALTY, f"Jury minority vote on {ctid}")

    # No-show penalty
    revealed_ids = {(r.get("data") or {}).get("juror_tip_id") for r in reveals}
    for s in summons:
        jid = (s.get("data") or {}).get("juror_tip_id")
        if jid not in revealed_ids:
            scoring.apply_score_event(jid, -Jury.NO_SHOW_PENALTY, f"Jury no-show on {ctid}")

    # Disputer effects
    if verdict == "UPHELD" and disputer_tip_id:
        scoring.apply_score_event(disputer_tip_id, Dispute.UPHELD_BONUS, f"Dispute upheld on {ctid}")
    elif verdict == "DISMISSED" and disputer_tip_id:
        scoring.apply_score_event(disputer_tip_id, -Dispute.DISPUTER_STAKE, f"Dispute dismissed on {ctid}")

    # Creator effects
    if verdict == "UPHELD" and author_tip_id:
        scoring.compute_score(author_tip_id)
        if confirmed_origin:
            dag.update_content_origin(ctid, confirmed_origin, "verified")
            log.info(f"Verdict UPHELD: {ctid} origin {declared_origin} → {confirmed_origin}")
    elif verdict in ("DISMISSED", "CONSERVATIVE_LABEL"):
        dag.update_content_status(ctid, "registered")

    return {"verdict": verdict, "confirmed_origin": confirmed_origin,
            "match_count": match_count, "mismatch_count": mismatch_count,
            "abstain_count": abstain_count, "tx_id": result_tx["tx_id"]}
