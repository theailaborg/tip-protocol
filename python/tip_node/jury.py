"""
Jury selection and adjudication logic for TIP dispute resolution.

Stage 2: Deterministic jury selection — same identities + dispute tx = same 7 jurors on any node.
Stage 3: Expert appeal selection — same algorithm, higher threshold.
Verdict tally: shared by API reveal endpoint + scheduler auto-trigger.

© 2026 The AI Lab Intelligence Unobscured, Inc.
License: TIPCL-1.0
"""

from datetime import datetime, timezone
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


def _node_signed_auto(tx_body: dict, config: dict) -> dict:
    tx_body.setdefault("data", {})["node_id"] = config.get("node_registered_id") or config.get("node_id")
    tx_body["tx_id"] = compute_tx_id(tx_body)
    return sign_transaction(tx_body, config["node_private_key"])


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ── Helpers (shared by jury + appeal) ────────────────────────────────────────

def write_summons_txs(dag, config, ctid, dispute_tx_id, members, commit_hours, reveal_hours, is_appeal=False):
    """Write JURY_SUMMONS txs for selected jurors/experts."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    commit_deadline = (now + timedelta(hours=commit_hours)).isoformat().replace("+00:00", "Z")
    reveal_deadline = (now + timedelta(hours=commit_hours + reveal_hours)).isoformat().replace("+00:00", "Z")
    timestamp = _now_str()
    tip_ids = members.get("jurors") or members.get("experts") or []

    for tip_id in tip_ids:
        tx = _node_signed_auto({
            "tx_type": TxType.JURY_SUMMONS, "timestamp": timestamp, "prev": dag.get_recent_prev(),
            "data": {
                "ctid": ctid, "dispute_tx_id": dispute_tx_id, "juror_tip_id": tip_id,
                "stake": Jury.JUROR_STAKE, "seed": members.get("seed"), "identity_count": members.get("identityCount"),
                "commit_deadline": commit_deadline, "reveal_deadline": reveal_deadline, "is_appeal": is_appeal,
            },
        }, config)
        dag.add_tx(tx)
    return {"commit_deadline": commit_deadline, "reveal_deadline": reveal_deadline}


def penalize_no_shows(reveals, summons, ctid, scoring):
    """Penalize jurors/experts who were summoned but didn't reveal."""
    revealed_ids = {(r.get("data") or {}).get("juror_tip_id") for r in reveals}
    for s in summons:
        jid = (s.get("data") or {}).get("juror_tip_id")
        if jid not in revealed_ids:
            scoring.apply_score_event(jid, -Jury.NO_SHOW_PENALTY, f"No-show on {ctid}")


def get_majority_origin(reveals, fallback_origin):
    """Get most common confirmed_origin from MISMATCH voters."""
    origin_votes = [
        (r.get("data") or {}).get("confirmed_origin")
        for r in reveals
        if (r.get("data") or {}).get("vote") == "MISMATCH" and (r.get("data") or {}).get("confirmed_origin")
    ]
    counts: dict[str, int] = {}
    for o in origin_votes:
        counts[o] = counts.get(o, 0) + 1
    return max(counts, key=counts.get) if counts else fallback_origin


# ── Jury Selection ───────────────────────────────────────────────────────────

def select_jury(dag, scoring, dispute_tx_id: str, author_tip_id: str, disputer_tip_id: str) -> dict:
    all_identities = dag.get_all_identities()
    identity_count = len(all_identities)
    seed = shake256(f"{dispute_tx_id}:{identity_count}")

    eligible = sorted(
        [i for i in all_identities
         if i.get("tip_id") != author_tip_id and i.get("tip_id") != disputer_tip_id
         and not dag.is_revoked(i.get("tip_id", ""))
         and scoring.get_score(i.get("tip_id", "")).get("score", 0) >= Jury.MIN_SCORE],
        key=lambda x: x.get("tip_id", ""),
    )
    if len(eligible) < Jury.SIZE:
        return {"jurors": [e["tip_id"] for e in eligible], "insufficient": True, "seed": seed, "identityCount": identity_count}

    shuffled = _seeded_shuffle(eligible, seed)
    jurors = _pick_with_geo_cap(shuffled, Jury.SIZE, Jury.MAX_SAME_COUNTRY)
    return {"jurors": jurors, "insufficient": len(jurors) < Jury.SIZE, "seed": seed, "identityCount": identity_count}


def select_experts(dag, scoring, appeal_tx_id: str, author_tip_id: str, disputer_tip_id: str) -> dict:
    all_identities = dag.get_all_identities()
    identity_count = len(all_identities)
    seed = shake256(f"{appeal_tx_id}:{identity_count}")

    eligible = sorted(
        [i for i in all_identities
         if i.get("tip_id") != author_tip_id and i.get("tip_id") != disputer_tip_id
         and not dag.is_revoked(i.get("tip_id", ""))
         and scoring.get_score(i.get("tip_id", "")).get("score", 0) >= Appeal.MIN_EXPERT_SCORE],
        key=lambda x: x.get("tip_id", ""),
    )
    if len(eligible) < Appeal.EXPERT_COUNT:
        return {"experts": [e["tip_id"] for e in eligible], "insufficient": True, "seed": seed, "identityCount": identity_count}

    shuffled = _seeded_shuffle(eligible, seed)
    experts = _pick_with_geo_cap(shuffled, Appeal.EXPERT_COUNT, 2)
    return {"experts": experts, "insufficient": len(experts) < Appeal.EXPERT_COUNT, "seed": seed, "identityCount": identity_count}


# ── Stage 2: Jury Verdict ────────────────────────────────────────────────────

def tally_verdict_and_apply(ctid: str, reveals: list, summons: list, dag, scoring, config: dict) -> dict:
    match_count    = sum(1 for r in reveals if (r.get("data") or {}).get("vote") == "MATCH")
    mismatch_count = sum(1 for r in reveals if (r.get("data") or {}).get("vote") == "MISMATCH")
    abstain_count  = sum(1 for r in reveals if (r.get("data") or {}).get("vote") == "ABSTAIN")
    total_votes    = match_count + mismatch_count + abstain_count
    non_abstain    = match_count + mismatch_count

    if total_votes < Jury.QUORUM or non_abstain < Jury.MAJORITY_VOTE:
        penalize_no_shows(reveals, summons, ctid, scoring)

        # Auto-escalate to Stage 3
        rec = dag.get_content(ctid)
        dispute_txs = dag.get_txs_by_type_and_ctid(TxType.CONTENT_DISPUTED, ctid)
        author_tip_id = rec.get("author_tip_id") if rec else None
        disputer_tip_id = (dispute_txs[0].get("data") or {}).get("disputer_tip_id") if dispute_txs else None

        appeal_tx = _node_signed_auto({
            "tx_type": TxType.APPEAL_FILED, "timestamp": _now_str(), "prev": dag.get_recent_prev(),
            "data": {"ctid": ctid, "appellant_tip_id": "SYSTEM_AUTO_ESCALATION", "stage2_verdict": "NO_QUORUM", "stake": 0},
        }, config)
        dag.add_tx(appeal_tx)

        experts = select_experts(dag, scoring, appeal_tx["tx_id"], author_tip_id, disputer_tip_id)
        write_summons_txs(dag, config, ctid, appeal_tx["tx_id"], experts, Appeal.COMMIT_WINDOW_HOURS, Appeal.REVEAL_WINDOW_HOURS, True)

        log.info(f"Jury NO_QUORUM on {ctid} — auto-escalated to Stage 3 with {len(experts.get('experts', []))} experts")
        return {"verdict": "NO_QUORUM", "auto_appeal": True, "experts": experts.get("experts", []),
                "match_count": match_count, "mismatch_count": mismatch_count, "abstain_count": abstain_count}

    majority_needed = non_abstain // 2 + 1
    decision = "UPHELD" if mismatch_count >= majority_needed else "DISMISSED"

    rec = dag.get_content(ctid)
    dispute_txs = dag.get_txs_by_type_and_ctid(TxType.CONTENT_DISPUTED, ctid)
    dispute_data    = (dispute_txs[0].get("data") or {}) if dispute_txs else {}
    disputer_tip_id = dispute_data.get("disputer_tip_id")
    author_tip_id   = rec.get("author_tip_id") if rec else None

    declared_origin = dispute_data.get("declared_origin") or (rec.get("origin_code") if rec else None)
    confirmed_origin = get_majority_origin(reveals, dispute_data.get("claimed_origin")) if decision == "UPHELD" else None

    verdict = "DISMISSED" if decision == "DISMISSED" \
        else "CONSERVATIVE_LABEL" if (declared_origin == "AG" and confirmed_origin == "OH") \
        else "UPHELD"

    result_tx = _node_signed_auto({
        "tx_type": TxType.ADJUDICATION_RESULT, "timestamp": _now_str(), "prev": dag.get_recent_prev(),
        "data": {
            "ctid": ctid, "verdict": verdict, "declared_origin": declared_origin, "confirmed_origin": confirmed_origin,
            "reason": dispute_data.get("reason"), "author_tip_id": author_tip_id,
            "match_count": match_count, "mismatch_count": mismatch_count, "abstain_count": abstain_count,
            "juror_votes": [{"juror_tip_id": (r.get("data") or {}).get("juror_tip_id"), "vote": (r.get("data") or {}).get("vote")} for r in reveals],
        },
    }, config)
    dag.add_tx(result_tx)

    # Juror score effects
    is_tie = match_count == mismatch_count
    if not is_tie:
        majority_vote = "MISMATCH" if mismatch_count > match_count else "MATCH"
        for r in reveals:
            jid = (r.get("data") or {}).get("juror_tip_id")
            v = (r.get("data") or {}).get("vote")
            if v == "ABSTAIN": continue
            if v == majority_vote:
                scoring.apply_score_event(jid, Jury.MAJORITY_BONUS, f"Jury majority vote on {ctid}")
            else:
                scoring.apply_score_event(jid, -Jury.MINORITY_PENALTY, f"Jury minority vote on {ctid}")

    penalize_no_shows(reveals, summons, ctid, scoring)

    # Disputer effects
    if verdict == "UPHELD" and disputer_tip_id:
        scoring.apply_score_event(disputer_tip_id, Dispute.UPHELD_BONUS, f"Dispute upheld on {ctid}")
    elif verdict == "DISMISSED" and disputer_tip_id:
        scoring.apply_score_event(disputer_tip_id, -Dispute.DISPUTER_STAKE, f"Dispute dismissed on {ctid}")

    # Creator effects
    pre_status = dispute_data.get("pre_dispute_status", "registered")
    if verdict == "UPHELD" and author_tip_id:
        scoring.compute_score(author_tip_id)
        if confirmed_origin:
            dag.update_content_origin(ctid, confirmed_origin, "verified")
            log.info(f"Verdict UPHELD: {ctid} origin {declared_origin} → {confirmed_origin}")
    elif verdict in ("DISMISSED", "CONSERVATIVE_LABEL"):
        dag.update_content_status(ctid, pre_status)

    return {"verdict": verdict, "confirmed_origin": confirmed_origin,
            "match_count": match_count, "mismatch_count": mismatch_count,
            "abstain_count": abstain_count, "tx_id": result_tx["tx_id"]}


# ── Stage 3: Appeal Verdict ──────────────────────────────────────────────────

def apply_appeal_verdict(ctid: str, reveals: list, summons: list, dag, scoring, config: dict) -> dict:
    match_count    = sum(1 for r in reveals if (r.get("data") or {}).get("vote") == "MATCH")
    mismatch_count = sum(1 for r in reveals if (r.get("data") or {}).get("vote") == "MISMATCH")
    abstain_count  = sum(1 for r in reveals if (r.get("data") or {}).get("vote") == "ABSTAIN")
    non_abstain    = match_count + mismatch_count

    # Need at least APPEAL.MIN_VOTES non-abstain
    if non_abstain < Appeal.MIN_VOTES:
        penalize_no_shows(reveals, summons, ctid, scoring)

        d_txs = dag.get_txs_by_type_and_ctid(TxType.CONTENT_DISPUTED, ctid)
        pre_status = (d_txs[0].get("data") or {}).get("pre_dispute_status", "registered") if d_txs else "registered"

        result_tx = _node_signed_auto({
            "tx_type": TxType.APPEAL_RESULT, "timestamp": _now_str(), "prev": dag.get_recent_prev(),
            "data": {"ctid": ctid, "verdict": "DISMISSED", "overturned": False, "defaulted": True,
                     "match_count": match_count, "mismatch_count": mismatch_count, "abstain_count": abstain_count},
        }, config)
        dag.add_tx(result_tx)

        dag.update_content_status(ctid, pre_status)
        log.info(f"Appeal NO_QUORUM on {ctid} — defaulted to DISMISSED, status restored to {pre_status}")
        return {"verdict": "DISMISSED", "defaulted": True, "tx_id": result_tx["tx_id"],
                "match_count": match_count, "mismatch_count": mismatch_count, "abstain_count": abstain_count}

    majority_needed = non_abstain // 2 + 1
    expert_decision = "UPHELD" if mismatch_count >= majority_needed else "DISMISSED"

    adj_txs = dag.get_txs_by_type_and_ctid(TxType.ADJUDICATION_RESULT, ctid)
    stage2_verdict = (adj_txs[0].get("data") or {}).get("verdict") if adj_txs else None
    appeal_txs = dag.get_txs_by_type_and_ctid(TxType.APPEAL_FILED, ctid)
    appellant_tip_id = (appeal_txs[0].get("data") or {}).get("appellant_tip_id") if appeal_txs else None

    rec = dag.get_content(ctid)
    dispute_txs = dag.get_txs_by_type_and_ctid(TxType.CONTENT_DISPUTED, ctid)
    dispute_data = (dispute_txs[0].get("data") or {}) if dispute_txs else {}
    author_tip_id = rec.get("author_tip_id") if rec else None

    confirmed_origin = get_majority_origin(reveals, dispute_data.get("claimed_origin")) if expert_decision == "UPHELD" else None
    declared_origin = dispute_data.get("declared_origin") or (rec.get("origin_code") if rec else None)

    verdict = "DISMISSED" if expert_decision == "DISMISSED" \
        else "CONSERVATIVE_LABEL" if (declared_origin == "AG" and confirmed_origin == "OH") \
        else "UPHELD"

    overturned = (stage2_verdict == "UPHELD" and verdict == "DISMISSED") \
              or (stage2_verdict == "DISMISSED" and verdict == "UPHELD")

    result_tx = _node_signed_auto({
        "tx_type": TxType.APPEAL_RESULT, "timestamp": _now_str(), "prev": dag.get_recent_prev(),
        "data": {
            "ctid": ctid, "verdict": verdict, "overturned": overturned, "stage2_verdict": stage2_verdict,
            "declared_origin": declared_origin, "confirmed_origin": confirmed_origin,
            "match_count": match_count, "mismatch_count": mismatch_count, "abstain_count": abstain_count,
            "expert_votes": [{"juror_tip_id": (r.get("data") or {}).get("juror_tip_id"), "vote": (r.get("data") or {}).get("vote")} for r in reveals],
        },
    }, config)
    dag.add_tx(result_tx)

    pre_status = dispute_data.get("pre_dispute_status", "registered")

    # Appellant effects
    if overturned and appellant_tip_id:
        scoring.apply_score_event(appellant_tip_id, Appeal.APPELLANT_STAKE + Appeal.OVERTURN_BONUS, f"Appeal overturned on {ctid}")
        if stage2_verdict == "UPHELD" and author_tip_id:
            scoring.compute_score(author_tip_id)
            dag.update_content_origin(ctid, declared_origin, pre_status)
            log.info(f"Appeal OVERTURNED: {ctid} — penalty reversed, origin restored to {declared_origin}")
        elif stage2_verdict == "DISMISSED":
            if confirmed_origin:
                dag.update_content_origin(ctid, confirmed_origin, "verified")
            log.info(f"Appeal OVERTURNED: {ctid} — Stage 2 dismissal reversed, experts confirm mismatch")
    elif not overturned and appellant_tip_id:
        scoring.apply_score_event(appellant_tip_id, -Appeal.APPELLANT_STAKE, f"Appeal failed on {ctid}")
        if verdict == "UPHELD" and confirmed_origin:
            dag.update_content_origin(ctid, confirmed_origin, "verified")
        else:
            dag.update_content_status(ctid, pre_status)
        log.info(f"Appeal CONFIRMED: {ctid} — Stage 2 stands, appellant loses {Appeal.APPELLANT_STAKE}")

    # Expert score effects
    is_tie = match_count == mismatch_count
    if not is_tie:
        majority_vote = "MISMATCH" if mismatch_count > match_count else "MATCH"
        for r in reveals:
            jid = (r.get("data") or {}).get("juror_tip_id")
            v = (r.get("data") or {}).get("vote")
            if v == "ABSTAIN": continue
            if v == majority_vote:
                scoring.apply_score_event(jid, Jury.MAJORITY_BONUS, f"Expert majority vote on {ctid}")
            else:
                scoring.apply_score_event(jid, -Jury.MINORITY_PENALTY, f"Expert minority vote on {ctid}")

    penalize_no_shows(reveals, summons, ctid, scoring)

    return {"verdict": verdict, "overturned": overturned, "confirmed_origin": confirmed_origin,
            "match_count": match_count, "mismatch_count": mismatch_count,
            "abstain_count": abstain_count, "tx_id": result_tx["tx_id"]}
