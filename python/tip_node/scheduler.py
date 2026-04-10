"""
node/scheduler.py
TIP Protocol Python — Scheduled Background Tasks

# Author:    Dinesh Mendhe <chairman@theailab.org>
Tasks (all run in daemon threads):
  1. Merkle root publication    every 6 hours  (v2 FIX-02 audit)
  2. Score recomputation sweep  every 12 hours
  3. Peer health ping           every 30 seconds

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from shared.crypto import shake256_multi
from shared.constants import TxType
from tip_node.logger import get_logger

log = get_logger("scheduler")


def start_scheduled_tasks(dag, scoring, gossip, config: dict) -> None:
    """Start all background task threads. All are daemon threads (no join needed)."""

    merkle_interval = config.get("merkle_publish_interval", 6 * 3600)
    recompute_interval = config.get("score_recompute_interval", 12 * 3600)
    peer_ping_interval = 30

    def publish_merkle() -> None:
        while True:
            threading.Event().wait(merkle_interval)
            try:
                count    = dag.dedup_count()
                id_count = len(dag.get_txs_by_type(TxType.REGISTER_IDENTITY))
                now_str  = datetime.now(timezone.utc).isoformat()[:13]
                root     = shake256_multi(str(count), str(id_count), now_str)
                dag.add_tx({
                    "tx_type": TxType.MERKLE_ROOT_PUBLISHED,
                    "data": {
                        "merkle_root":    root,
                        "dedup_count":    count,
                        "identity_count": id_count,
                        "node_id":        config["node_id"],
                    },
                })
                log.info(f"Merkle root published: {root[:16]}... (dedup:{count} ids:{id_count})")
            except Exception as exc:
                log.warning(f"Merkle root publication failed: {exc}")

    def recompute_scores() -> None:
        while True:
            threading.Event().wait(recompute_interval)
            try:
                log.info("Starting scheduled score recomputation sweep...")
                count = scoring.recompute_all()
                log.info(f"Score sweep complete: {count} identities recomputed")
            except Exception as exc:
                log.warning(f"Score recomputation failed: {exc}")

    def peer_ping() -> None:
        while True:
            threading.Event().wait(peer_ping_interval)
            try:
                pc = gossip.peer_count() if gossip else 0
                configured = len(config.get("peers", []))
                if configured > 0 and pc == 0:
                    log.warning(f"No active gossip peers (configured: {configured}). DAG sync paused.")
            except Exception:
                pass

    # 4. Verdict auto-trigger — jury + appeal in single pass (every 5 minutes)
    def verdict_check() -> None:
        from tip_node.jury import tally_verdict_and_apply, apply_appeal_verdict
        while True:
            threading.Event().wait(300)
            try:
                disputed = dag.get_content_by_status("disputed")
                if not disputed:
                    continue
                now_ts = datetime.now(timezone.utc).timestamp()
                for rec in disputed:
                    ctid = rec.get("ctid")
                    if not ctid:
                        continue
                    all_summons = dag.get_txs_by_type_and_ctid(TxType.JURY_SUMMONS, ctid)
                    if not all_summons:
                        continue

                    jury_summons   = [t for t in all_summons if not (t.get("data") or {}).get("is_appeal")]
                    appeal_summons = [t for t in all_summons if (t.get("data") or {}).get("is_appeal")]

                    # Check appeal first (if exists, it's the active stage)
                    if appeal_summons:
                        dl_str = (appeal_summons[0].get("data") or {}).get("reveal_deadline", "")
                        try:
                            dl = datetime.fromisoformat(dl_str.replace("Z", "+00:00")).timestamp()
                        except (ValueError, AttributeError):
                            continue
                        if now_ts >= dl:
                            has_result = len(dag.get_txs_by_type_and_ctid(TxType.APPEAL_RESULT, ctid)) > 0
                            if not has_result:
                                reveals = [t for t in dag.get_txs_by_type_and_ctid(TxType.JURY_VOTE_REVEAL, ctid)
                                           if (t.get("data") or {}).get("is_appeal")]
                                log.info(f"Auto-appeal verdict: {ctid} ({len(reveals)}/{len(appeal_summons)} reveals)")
                                r = apply_appeal_verdict(ctid, reveals, appeal_summons, dag, scoring, config)
                                log.info(f"Appeal result: {ctid} → {r.get('verdict')} (overturned: {r.get('overturned')})")
                        continue  # appeal active, skip jury

                    # Check jury (no appeal exists)
                    if jury_summons:
                        dl_str = (jury_summons[0].get("data") or {}).get("reveal_deadline", "")
                        try:
                            dl = datetime.fromisoformat(dl_str.replace("Z", "+00:00")).timestamp()
                        except (ValueError, AttributeError):
                            continue
                        if now_ts >= dl:
                            has_verdict = len(dag.get_txs_by_type_and_ctid(TxType.ADJUDICATION_RESULT, ctid)) > 0
                            if not has_verdict:
                                reveals = [t for t in dag.get_txs_by_type_and_ctid(TxType.JURY_VOTE_REVEAL, ctid)
                                           if not (t.get("data") or {}).get("is_appeal")]
                                log.info(f"Auto-jury verdict: {ctid} ({len(reveals)}/{len(jury_summons)} reveals)")
                                r = tally_verdict_and_apply(ctid, reveals, jury_summons, dag, scoring, config)
                                log.info(f"Jury result: {ctid} → {r.get('verdict')}")
            except Exception as exc:
                log.warning(f"Verdict auto-trigger failed: {exc}")

    for fn, name in [
        (publish_merkle,     "scheduler.merkle"),
        (recompute_scores,   "scheduler.scores"),
        (peer_ping,          "scheduler.ping"),
        (verdict_check,      "scheduler.verdict"),
    ]:
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()

    log.info("Scheduled tasks started (Merkle root, score recomputation, peer ping, jury verdict, appeal verdict)")
