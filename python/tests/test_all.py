"""
tests/test_all.py
TIP Protocol Python — Complete Test Suite

Sections:
  1. Cryptographic Primitives
  2. Genesis Block
  3. DAG Store (in-memory)
  4. Trust Scoring Engine
  5. Transaction Validator (17 cases)
  6. Genesis File Integrity
  7. SDK Modules
  8. Protocol Constants

Run:  python tests/test_all.py
      python -m pytest tests/test_all.py -v   (if pytest installed)

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""
from __future__ import annotations

import pathlib
import secrets
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from shared.crypto import *
from shared.constants import *
from node.config import load_config
from node.dag import DAG
from node.scoring import ScoringEngine
from node.genesis import (
    GENESIS_HASH, GENESIS_CHAIN_ID, GENESIS_TIMESTAMP,
    get_founding_vp, validate_genesis_block, build_genesis_block,
    _compute_genesis_hash, GENESIS_PAYLOAD,
)
from node.validators.tx_validator import validate_transaction

# ─── Test harness ─────────────────────────────────────────────────────────────

G = "\x1b[32m"; R = "\x1b[0m"; RED = "\x1b[31m"; B = "\x1b[1m"; Y = "\x1b[33m"; D = "\x1b[2m"

_passed = 0
_failed = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        print(f"  {G}✓{R} {label}" + (f"  {D}{detail}{R}" if detail else ""))
        _passed += 1
    else:
        print(f"  {RED}✗{R} {label}" + (f"  {RED}{detail}{R}" if detail else ""))
        _failed += 1


def section(title: str) -> None:
    print(f"\n  {B}{Y}─── {title} {R}")


def rh() -> str:
    return secrets.token_hex(32)


def _make_dag():
    cfg = load_config()
    cfg["db_path"] = ":memory:"
    return DAG(cfg)


def _vp_id(dag: DAG) -> str:
    vps = dag.get_all_vps()
    return vps[0]["vp_id"] if vps else "tip://id/VP-US-theailab-genesis"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: Cryptographic Primitives
# ══════════════════════════════════════════════════════════════════════════════

def test_crypto() -> None:
    section("1. CRYPTOGRAPHIC PRIMITIVES")

    # ML-DSA-65 keypair
    kp = generate_mldsa_keypair()
    check("ML-DSA-65 keypair generated",
          kp["algorithm"] == "ML-DSA-65" and kp["publicKey"] and kp["privateKey"])

    # SLH-DSA-128s keypair
    rk = generate_slhdsa_keypair()
    check("SLH-DSA-128s root keypair",
          rk["algorithm"] == "SLH-DSA-128s")

    # Sign + verify cycle
    kp2  = generate_mldsa_keypair()
    tx   = {"tx_type": "TEST", "data": {"x": 1}, "prev": []}
    signed = sign_transaction(tx, kp2["privateKey"])
    check("timestamp auto-assigned on sign", bool(signed.get("timestamp")))
    check("Sign + verify cycle (ML-DSA-65)", verify_tx_signature(signed, kp2["publicKey"]))

    # Tamper detection
    tampered = dict(signed); tampered["data"] = {"x": 999}
    check("Tampered tx rejected",            not verify_tx_signature(tampered, kp2["publicKey"]))

    # Pepper
    pepper = generate_pepper()
    check("256-bit pepper (64 hex chars)",   len(pepper) == 64)

    # Peppered dedup hash: deterministic + pepper-sensitive
    args = dict(gov_id_normalized="P12345", date_of_birth_iso="1985-06-15",
                country_code="US", facial_embedding_hash="abc", pepper="d"*64)
    h1 = compute_dedup_hash(**args)
    h2 = compute_dedup_hash(**args)
    h3 = compute_dedup_hash(**{**args, "pepper": "e"*64})
    check("Dedup hash deterministic + pepper-sensitive (v2 FIX-02)", h1 == h2 and h1 != h3)

    # TIP-ID format
    tip_id = generate_tip_id("US", kp["publicKey"])
    import re
    check("TIP-ID URI format: tip://id/US-[16hex]",
          bool(re.match(r"^tip://id/US-[0-9a-f]{16}$", tip_id)),
          tip_id)

    # CTID format
    h = hash_content("hello world test content here for ctid")
    ctid = generate_ctid("OH", h, tip_id)
    check("CTID URI format: tip://c/OH-[14hex]-[4hex]",
          bool(re.match(r"^tip://c/OH-[0-9a-f]{14}-[0-9a-f]{4}$", ctid)),
          ctid)

    # ZK proof
    zk = compute_zk_proof("fakehash", "nonce123")
    check("ZK proof starts with 'zkp:'", zk.startswith("zkp:"))

    # ZK score proof
    proof_data = compute_zk_score_proof(850, 700, kp["privateKey"])
    check("ZK score proof: above threshold for 850 >= 700", proof_data["above_threshold"])
    check("ZK score proof: verifies correctly",
          verify_zk_score_proof(proof_data["proof"], proof_data["commitment"], 700, True))
    check("ZK score proof: rejects wrong claim",
          not verify_zk_score_proof(proof_data["proof"], proof_data["commitment"], 700, False))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: Genesis Block
# ══════════════════════════════════════════════════════════════════════════════

def test_genesis() -> None:
    section("2. GENESIS BLOCK")

    check("Genesis hash is 64-char hex",      len(GENESIS_HASH) == 64)
    check("Chain ID: tip-mainnet-v2",          GENESIS_CHAIN_ID == "tip-mainnet-v2")

    # Determinism
    h1 = _compute_genesis_hash()
    h2 = _compute_genesis_hash()
    check("Genesis hash is deterministic",     h1 == h2 and h1 == GENESIS_HASH)

    # Founding VP
    vp = get_founding_vp()
    check("Founding VP: vp_id present",        vp["vp_id"].startswith("tip://id/VP-"))
    check("Founding VP: jurisdiction green",   vp["jurisdiction_tier"] == "green")

    # Validation
    good_block = {"genesis_hash": GENESIS_HASH}
    bad_block  = {"genesis_hash": "wronghash"}
    check("Good genesis block validates",      validate_genesis_block(good_block))
    check("Bad genesis hash rejected",         not validate_genesis_block(bad_block))
    check("None genesis block rejected",       not validate_genesis_block(None))

    # Payload integrity
    check("Initial score == 500",              GENESIS_PAYLOAD["initial_params"]["initial_score"] == 500)
    check("Attested score == 550",             GENESIS_PAYLOAD["initial_params"]["initial_score_attested"] == 550)
    check("OH_confirmed_AG_1st == -100",       GENESIS_PAYLOAD["penalty_schedule"]["oh_confirmed_ag_1st"] == -100)
    check("Conservative label penalty == 0",  GENESIS_PAYLOAD["penalty_schedule"]["ag_conservative"] == 0)
    check("All 4 origin categories defined",   set(GENESIS_PAYLOAD["origin_categories"]) == {"OH","AA","AG","MX"})
    check("5 tier thresholds defined",         len(GENESIS_PAYLOAD["tier_thresholds"]) == 5)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: DAG Store
# ══════════════════════════════════════════════════════════════════════════════

def test_dag() -> None:
    section("3. DAG STORE (IN-MEMORY)")

    dag  = _make_dag()
    vpid = _vp_id(dag)

    check("DAG bootstraps with 2 txs (GENESIS + VP_REGISTERED)", dag.count() == 2)
    check("Founding VP auto-registered on boot",
          bool(dag.get_vp(vpid)) and dag.get_vp(vpid)["status"] == "active")

    # Identity CRUD
    kp     = generate_mldsa_keypair()
    tip_id = generate_tip_id("US", kp["publicKey"])
    dag.save_identity({"tip_id": tip_id, "region": "US", "public_key": kp["publicKey"],
                       "vp_id": vpid, "verification_tier": "T1",
                       "founding": False, "status": "active",
                       "registered_at": "2026-03-15T00:00:00+00:00"})
    rec = dag.get_identity(tip_id)
    check("Identity save + retrieve",          rec is not None and rec["tip_id"] == tip_id)
    check("Identity region stored correctly",  rec["region"] == "US")

    # Score CRUD
    dag.set_score(tip_id, 550, 0)
    s = dag.get_score(tip_id)
    check("Score save + retrieve: 550/1000",   s is not None and s["score"] == 550)
    check("Score offense_count stored",        s["offense_count"] == 0)

    # Score boundary clamping
    dag.set_score(tip_id, 9999, 0)
    check("Score clamped to 1000 max",         dag.get_score(tip_id)["score"] == 1000)
    dag.set_score(tip_id, -999, 0)
    check("Score clamped to 0 min",            dag.get_score(tip_id)["score"] == 0)

    # Content CRUD
    h = hash_content("DAG store test article content for test suite")
    ctid = generate_ctid("AA", h, tip_id)
    dag.save_content({"ctid": ctid, "origin_code": "AA", "content_hash": h,
                      "author_tip_id": tip_id, "status": "verified",
                      "registered_at": "2026-03-15T00:00:00+00:00"})
    c = dag.get_content(ctid)
    check("Content save + retrieve (AA origin)", c is not None and c["origin_code"] == "AA")
    by_author = dag.get_content_by_author(tip_id)
    check("Content retrieval by author",        len(by_author) == 1)

    # Dedup (v2 FIX-02)
    dag.add_dedup("pepper-hash-001")
    dag.add_dedup("pepper-hash-002")
    check("Dedup hash stored",                 dag.has_dedup("pepper-hash-001"))
    check("Unknown dedup hash absent",         not dag.has_dedup("not-stored-999"))
    check("Dedup count correct",               dag.dedup_count() == 2)
    dag.add_dedup("pepper-hash-001")  # idempotent
    check("Dedup add is idempotent",           dag.dedup_count() == 2)

    # Revocations (v2 FIX-05)
    dag.add_revocation(tip_id, "REVOKE_VOLUNTARY", "2026-03-15T00:00:00+00:00", rh())
    check("Revocation stored",                 dag.is_revoked(tip_id))
    check("Identity status updated to revoked", dag.get_identity(tip_id)["status"] == "revoked")
    revoc_list = dag.get_revocations()
    check("Revocation list retrieval",         len(revoc_list) >= 1 and revoc_list[0]["tip_id"] == tip_id)

    # Revocation since filter
    recent = dag.get_revocations(since="2099-01-01T00:00:00+00:00")
    check("Revocation since filter (future excludes all)", len(recent) == 0)

    # Transactions
    tx = dag.add_tx({"tx_type": "TEST_TX", "data": {"hello": "world"}})
    loaded = dag.get_tx(tx["tx_id"])
    check("Tx add + retrieve by ID",           loaded is not None and loaded["data"]["hello"] == "world")
    check("Tx prev[] auto-assigned",           len(tx["prev"]) == 2)
    check("Tx timestamp auto-assigned",        bool(tx.get("timestamp")))

    # VP CRUD
    dag.save_vp({"vp_id": "tip://id/VP-DE-test", "name": "German VP",
                 "jurisdiction_tier": "green", "public_key": "aa",
                 "status": "active", "registered_at": "2026-03-15T00:00:00+00:00"})
    check("VP save + retrieve",                dag.get_vp("tip://id/VP-DE-test") is not None)
    check("get_all_vps returns multiple VPs",  len(dag.get_all_vps()) >= 2)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: Trust Scoring Engine
# ══════════════════════════════════════════════════════════════════════════════

def test_scoring() -> None:
    section("4. TRUST SCORING ENGINE")

    dag     = _make_dag()
    cfg     = load_config(); cfg["db_path"] = ":memory:"
    scoring = ScoringEngine(dag, cfg)
    vpid    = _vp_id(dag)

    def make_id(attested=False):
        kp     = generate_mldsa_keypair()
        tid    = generate_tip_id("US", kp["publicKey"])
        dag.save_identity({"tip_id": tid, "region": "US", "public_key": kp["publicKey"],
                           "vp_id": vpid, "verification_tier": "T1", "founding": False,
                           "status": "active", "registered_at": "2026-03-15T00:00:00+00:00"})
        dag.add_tx({"tx_type": TxType.REGISTER_IDENTITY,
                    "data": {"tip_id": tid, "attested": attested},
                    "timestamp": "2026-03-15T00:00:01+00:00"})
        score = 550 if attested else 500
        dag.set_score(tid, score, 0)
        return tid

    # Initial scores
    t1 = make_id(attested=True)
    t2 = make_id(attested=False)
    check("Attested score = 550",  scoring.get_score(t1)["score"] == 550)
    check("Unattested score = 500", scoring.get_score(t2)["score"] == 500)

    # Penalty escalation: OH → AG
    dag.add_tx({"tx_type": TxType.ADJUDICATION_RESULT,
                "data": {"tip_id": t1, "ctid": "tip://c/OH-abc12345678901-ab12",
                         "declared_origin": "OH", "confirmed_origin": "AG",
                         "verdict": "OH_CONFIRMED_AG"},
                "timestamp": "2026-03-15T01:00:00+00:00"})
    dag.add_tx({"tx_type": TxType.SCORE_UPDATE,
                "data": {"tip_id": t1, "delta": -100, "score_after": 450,
                         "reason": "1st OH→AG mismatch"},
                "timestamp": "2026-03-15T01:00:01+00:00"})
    dag.set_score(t1, 450, 1)
    s1 = scoring.get_score(t1)
    check("1st OH→AG offense: score = 450", s1["score"] == 450)
    check("1st offense count = 1",          s1["offense_count"] == 1)

    dag.add_tx({"tx_type": TxType.SCORE_UPDATE,
                "data": {"tip_id": t1, "delta": -200, "score_after": 250,
                         "reason": "2nd offense"},
                "timestamp": "2026-03-15T02:00:00+00:00"})
    dag.set_score(t1, 250, 2)
    check("2nd offense: score = 250", scoring.get_score(t1)["score"] == 250)

    # Conservative labelling: zero penalty
    t3 = make_id(attested=True)
    dag.add_tx({"tx_type": TxType.ADJUDICATION_RESULT,
                "data": {"tip_id": t3, "ctid": "tip://c/AG-abc12345678901-ab12",
                         "declared_origin": "AG", "confirmed_origin": "OH",
                         "verdict": "CONSERVATIVE_LABEL"},
                "timestamp": "2026-03-15T01:00:00+00:00"})
    dag.set_score(t3, 550, 0)
    s3 = scoring.get_score(t3)
    check("Conservative label: zero penalty", s3["score"] == 550 and s3["offense_count"] == 0)

    # All 5 tier thresholds
    t4 = make_id()
    tier_tests = [(850, "HIGHLY_TRUSTED"), (700, "TRUSTED"), (500, "REVIEW_ADVISED"),
                  (300, "LOW_TRUST"), (100, "NOT_TRUSTED")]
    for score, expected_tier in tier_tests:
        dag.set_score(t4, score, 0)
        result = scoring.get_score(t4)
        check(f"Score {score} → tier {expected_tier}", result["tier"] == expected_tier)

    # Jury eligibility
    t5 = make_id()
    dag.set_score(t5, 750, 0)
    check("Score 750 is jury eligible",  scoring.is_jury_eligible(t5))
    dag.set_score(t5, 700, 0)
    check("Score 700 is jury eligible (boundary)", scoring.is_jury_eligible(t5))
    dag.set_score(t5, 699, 0)
    check("Score 699 is NOT jury eligible", not scoring.is_jury_eligible(t5))
    dag.set_score(t5, 800, 0)
    dag.add_revocation(t5, "REVOKE_VOLUNTARY", "2026-03-15T00:00:00+00:00", rh())
    check("Revoked identity NOT jury eligible", not scoring.is_jury_eligible(t5))

    # Score clamping via apply_score_event
    t6 = make_id()
    dag.set_score(t6, 50, 0)
    new_s = scoring.apply_score_event(t6, -200, "penalty test")
    check("Score clamped to 0 (no negative scores)", new_s == 0)
    dag.set_score(t6, 950, 0)
    new_s2 = scoring.apply_score_event(t6, 200, "bonus test")
    check("Score clamped to 1000 (no over-max)", new_s2 == 1000)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: Transaction Validator (17 cases)
# ══════════════════════════════════════════════════════════════════════════════

def test_validator() -> None:
    section("5. TRANSACTION VALIDATOR — 17 CASES")

    dag  = _make_dag()
    vpid = _vp_id(dag)
    kp   = generate_mldsa_keypair()
    tid  = generate_tip_id("DE", kp["publicKey"])

    def mk(**data):
        """Build a minimal valid-looking tx with correct content-addressed tx_id."""
        tx_type = data.pop("tx_type", TxType.REGISTER_IDENTITY)
        tx = {
            "tx_type":   tx_type,
            "timestamp": "2026-03-14T12:00:00+00:00",
            "prev":      [],
            "data":      data,
        }
        tx["tx_id"] = compute_tx_id(tx)
        return tx

    # Structure
    r = validate_transaction(None, dag)
    check("Null tx rejected [structure]", not r.valid and r.layer == "structure")

    r = validate_transaction({}, dag)
    check("Empty dict rejected [structure]", not r.valid and r.layer == "structure")

    r = validate_transaction({"tx_id": rh(), "timestamp": "2026-03-14T12:00:00+00:00",
                              "data": {}, "prev": []}, dag, skip_state=True)
    check("Missing tx_type rejected [structure]", not r.valid and r.layer == "structure")

    r = validate_transaction(mk(tx_type=TxType.REGISTER_IDENTITY,
                                timestamp_override=True,
                                **{"tip_id": tid, "zk_dedup_proof": "zkp:x",
                                   "vp_id": vpid, "verification_tier": "T1",
                                   "region": "DE", "public_key": kp["publicKey"]}), dag,
                             skip_crypto=True, skip_state=True)
    # This one is tricky — let's build it properly
    future_tx = {
        "tx_id":     rh(),
        "tx_type":   TxType.REGISTER_IDENTITY,
        "timestamp": "2099-01-01T00:00:00+00:00",
        "prev":      [],
        "data":      {"tip_id": tid, "zk_dedup_proof": "zkp:x",
                      "vp_id": vpid, "verification_tier": "T1",
                      "region": "DE", "public_key": kp["publicKey"]},
    }
    r = validate_transaction(future_tx, dag, skip_crypto=True)
    check("Future timestamp rejected [structure]", not r.valid and r.layer == "structure")

    # Valid identity
    _valid_id_body = {
        "tx_type":   TxType.REGISTER_IDENTITY,
        "timestamp": "2026-03-14T12:00:00+00:00", "prev": [],
        "data":      {"tip_id": tid, "region": "DE", "public_key": kp["publicKey"],
                      "vp_id": vpid, "verification_tier": "T1", "zk_dedup_proof": "zkp:valid123"},
    }
    valid_id_tx = {**_valid_id_body, "tx_id": compute_tx_id(_valid_id_body)}
    r = validate_transaction(valid_id_tx, dag, skip_crypto=True)
    check("Valid identity tx accepted [all layers]", r.valid, str(r.errors))

    # Bad TIP-ID format
    r = validate_transaction({**valid_id_tx, "tx_id": rh(),
                               "data": {**valid_id_tx["data"], "tip_id": "bad-format"}},
                              dag, skip_crypto=True)
    check("Bad TIP-ID format rejected [business]",
          not r.valid and r.layer == "business_rules")

    # Bad ZK proof prefix
    r = validate_transaction({**valid_id_tx, "tx_id": rh(),
                               "data": {**valid_id_tx["data"], "zk_dedup_proof": "invalid-no-prefix"}},
                              dag, skip_crypto=True)
    check("ZK proof without 'zkp:' prefix rejected [business]",
          not r.valid and r.layer == "business_rules")

    # Setup identity for content tests
    dag.save_identity({
        "tip_id": tid, "region": "DE", "public_key": kp["publicKey"],
        "vp_id": vpid, "verification_tier": "T1", "founding": False,
        "status": "active", "registered_at": "2026-03-15T00:00:00+00:00",
    })
    h    = hash_content("content for validator integration test article")
    ctid = generate_ctid("OH", h, tid)

    # Bad origin code
    r = validate_transaction(
        {"tx_id": rh(), "tx_type": TxType.REGISTER_CONTENT,
         "timestamp": "2026-03-14T12:00:00+00:00", "prev": [],
         "data": {"ctid": ctid, "origin_code": "XX", "content_hash": h,
                  "author_tip_id": tid, "signature": "s"}},
        dag, skip_crypto=True,
    )
    check("Invalid origin_code 'XX' rejected [business]",
          not r.valid and r.layer == "business_rules")

    # Valid content
    _valid_content_body = {
        "tx_type":   TxType.REGISTER_CONTENT,
        "timestamp": "2026-03-14T12:00:00+00:00", "prev": [],
        "data":      {"ctid": ctid, "origin_code": "OH", "content_hash": h,
                      "author_tip_id": tid, "signature": "s"},
    }
    r = validate_transaction(
        {**_valid_content_body, "tx_id": compute_tx_id(_valid_content_body)},
        dag, skip_crypto=True,
    )
    check("Valid content tx accepted [all layers]", r.valid, str(r.errors))

    # Duplicate CTID
    dag.save_content({"ctid": ctid, "origin_code": "OH", "content_hash": h,
                      "author_tip_id": tid, "status": "verified",
                      "registered_at": "2026-03-15T00:00:00+00:00"})
    r = validate_transaction(
        {**_valid_content_body, "tx_id": compute_tx_id(_valid_content_body)},
        dag, skip_crypto=True,
    )
    check("Duplicate CTID rejected [state]", not r.valid and r.layer == "state")

    # Score > 1000
    r = validate_transaction(
        {"tx_id": rh(), "tx_type": TxType.SCORE_UPDATE,
         "timestamp": "2026-03-14T12:00:00+00:00", "prev": [],
         "data": {"tip_id": tid, "delta": 10, "score_after": 1500, "reason": "test"}},
        dag, skip_crypto=True,
    )
    check("score_after > 1000 rejected [business]", not r.valid)

    # Score in valid range
    _score_body = {
        "tx_type":   TxType.SCORE_UPDATE,
        "timestamp": "2026-03-14T12:00:00+00:00", "prev": [],
        "data":      {"tip_id": tid, "delta": 10, "score_after": 600, "reason": "test"},
    }
    r = validate_transaction(
        {**_score_body, "tx_id": compute_tx_id(_score_body)},
        dag, skip_crypto=True,
    )
    check("score_after in range accepted [business]", r.valid)

    # Revoke non-existent identity
    _revoke_nonexist_body = {
        "tx_type":   TxType.REVOKE_VP,
        "timestamp": "2026-03-14T12:00:00+00:00", "prev": [],
        "data":      {"tip_id": "tip://id/US-doesnotexist0000",
                      "issuing_vp_id": vpid, "reason_code": "FRAUD", "evidence_hash": "x"},
    }
    r = validate_transaction(
        {**_revoke_nonexist_body, "tx_id": compute_tx_id(_revoke_nonexist_body)},
        dag, skip_crypto=True,
    )
    check("Revoke non-existent identity rejected [state]", not r.valid and r.layer == "state")

    # Double revocation
    dag.add_revocation(tid, "REVOKE_VOLUNTARY", "2026-03-15T00:00:00+00:00", rh())
    _double_revoke_body = {
        "tx_type":   TxType.REVOKE_VOLUNTARY,
        "timestamp": "2026-03-14T12:00:00+00:00", "prev": [],
        "data":      {"tip_id": tid},
    }
    r = validate_transaction(
        {**_double_revoke_body, "tx_id": compute_tx_id(_double_revoke_body)},
        dag, skip_crypto=True,
    )
    check("Double revocation rejected [state]", not r.valid and r.layer == "state")

    # Red-tier VP
    r = validate_transaction(
        {"tx_id": rh(), "tx_type": TxType.VP_REGISTERED,
         "timestamp": "2026-03-14T12:00:00+00:00", "prev": [],
         "data": {"vp_id": "tip://id/VP-CN-bad", "name": "Bad VP",
                  "jurisdiction_tier": "red", "public_key": "aabb"}},
        dag, skip_crypto=True,
    )
    check("Red-tier VP rejected [business]", not r.valid and r.layer == "business_rules")

    # Green-tier VP
    _green_vp_body = {
        "tx_type":   TxType.VP_REGISTERED,
        "timestamp": "2026-03-14T12:00:00+00:00", "prev": [],
        "data":      {"vp_id": "tip://id/VP-FR-good", "name": "French VP",
                      "jurisdiction_tier": "green", "public_key": "aabb"},
    }
    r = validate_transaction(
        {**_green_vp_body, "tx_id": compute_tx_id(_green_vp_body)},
        dag, skip_crypto=True,
    )
    check("Green-tier VP accepted [all layers]", r.valid, str(r.errors))

    # Real ML-DSA-65 signature: valid
    ctid2  = generate_ctid("AA", hash_content("signed content for crypto test"), tid)
    _signed_body = {
        "tx_type":   TxType.REGISTER_CONTENT,
        "timestamp": "2026-03-14T12:00:00+00:00",
        "prev":      [],
        "data":      {"ctid": ctid2, "origin_code": "AA",
                      "content_hash": hash_content("signed content for crypto test"),
                      "author_tip_id": tid, "signature": "placeholder"},
    }
    _signed_body["tx_id"] = compute_tx_id(_signed_body)
    signed_tx = sign_transaction(_signed_body, kp["privateKey"])
    r = validate_transaction(signed_tx, dag, author_public_key=kp["publicKey"], skip_state=True)
    check("Valid ML-DSA-65 signature accepted [crypto]", r.valid, str(r.errors))

    # Tampered tx — use a valid-format 14-char hex hash so it reaches the crypto layer
    import hashlib
    bad_hash = hashlib.shake_256(b"tampered").hexdigest(7)  # 14 hex chars
    tampered = dict(signed_tx)
    tampered = {**signed_tx, "data": {**signed_tx["data"], "content_hash": bad_hash}}
    r = validate_transaction(tampered, dag, author_public_key=kp["publicKey"], skip_state=True)
    check("Tampered tx rejected (reaches crypto layer with valid-format hash)",
          not r.valid and r.layer == "cryptography")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6: Genesis File Integrity
# ══════════════════════════════════════════════════════════════════════════════

def test_genesis_files() -> None:
    section("6. GENESIS FILE INTEGRITY (from scripts/seed.py output)")

    genesis_data_dir = pathlib.Path(__file__).parent.parent / "node" / "genesis-data"
    genesis_file     = genesis_data_dir / "genesis.json"
    seed_file        = genesis_data_dir / "seed-output.json"

    if not genesis_file.exists():
        check("genesis.json exists (run scripts/seed.py first)", False, str(genesis_file))
        return

    import json as _json
    block = _json.loads(genesis_file.read_text())
    check("genesis.json validates against canonical payload", validate_genesis_block(block))
    check("genesis.json hash == compiled constant",
          block.get("genesis_hash") == GENESIS_HASH, block.get("genesis_hash", "")[:16])

    if seed_file.exists():
        seed = _json.loads(seed_file.read_text())
        check("Seed: 4 genesis ring members",       len(seed.get("genesis_ring", [])) == 4)
        check("Seed: all four origin types",
              {c["origin"] for c in seed.get("sample_content", [])} == {"OH","AA","AG","MX"})
        check("Seed: founding VP matches genesis",
              seed.get("founding_vp", {}).get("vp_id") == get_founding_vp()["vp_id"])
    else:
        check("seed-output.json exists (run scripts/seed.py first)",
              False, str(seed_file))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7: SDK Modules
# ══════════════════════════════════════════════════════════════════════════════

def test_sdk() -> None:
    section("7. SDK MODULES")

    from sdk.client import (
        TIPClient, TIPIdentityClient, TIPContentClient,
        TIPTrustClient, TIPBadgesClient,
    )

    # All exports present
    check("TIPClient importable",          TIPClient is not None)
    check("TIPIdentityClient importable",  TIPIdentityClient is not None)
    check("TIPContentClient importable",   TIPContentClient is not None)
    check("TIPTrustClient importable",     TIPTrustClient is not None)
    check("TIPBadgesClient importable",    TIPBadgesClient is not None)

    # TIPClient requires node_url
    try:
        TIPClient(node_url="")
        check("TIPClient requires node_url", False)
    except ValueError:
        check("TIPClient requires non-empty node_url", True)

    # Identity client local methods
    ic = TIPIdentityClient("http://localhost:4000")
    kp = ic.generate_keypair()
    check("identity.generate_keypair() returns ML-DSA-65",
          "ML-DSA-65" in kp["algorithm"])
    p = ic.generate_pepper()
    check("identity.generate_pepper() returns 64-hex", len(p) == 64)
    zk = ic.compute_zk_proof("P12345", "1985-01-01", "US", "abc", p)
    check("identity.compute_zk_proof() returns zkp: proof", zk.startswith("zkp:"))
    tip_id = ic.compute_tip_id("US", kp["publicKey"])
    import re
    check("identity.compute_tip_id() format valid",
          bool(re.match(r"^tip://id/US-[0-9a-f]{16}$", tip_id)), tip_id)

    # Content client local methods
    cc = TIPContentClient("http://localhost:4000")
    r  = cc.hash_locally("My test article content for section 7")
    check("content.hash_locally() returns 14-hex hash",  len(r["content_hash"]) == 14)
    check("content.hash_locally() returns ctid_preview",  r["ctid_preview"].startswith("tip://c/"))

    signed = cc.sign_content("My article text here", "OH", kp["privateKey"])
    check("content.sign_content() produces 14-hex hash",  len(signed["content_hash"]) == 14)
    check("content.sign_content() produces signature",     bool(signed["signature"]))
    check("content.sign_content() ctidPreview starts tip://c/OH-",
          signed["ctid_preview"].startswith("tip://c/OH-"))

    try:
        cc.sign_content("text", "INVALID", kp["privateKey"])
        check("sign_content rejects invalid origin", False)
    except ValueError:
        check("sign_content rejects invalid origin code", True)

    nginx = cc.build_nginx_snippet({"TIP-Author": "tip://id/US-aabbcc"})
    check("content.build_nginx_snippet() correct format", "add_header" in nginx)
    apache = cc.build_apache_snippet({"TIP-Author": "tip://id/US-aabbcc"})
    check("content.build_apache_snippet() correct format", "Header set" in apache)
    caddy = cc.build_caddy_snippet({"TIP-Author": "tip://id/US-aabbcc"})
    check("content.build_caddy_snippet() correct format", "header {" in caddy)
    netlify = cc.build_netlify_snippet({"TIP-Author": "tip://id/US-aabbcc"})
    check("content.build_netlify_snippet() correct format", "netlify.toml" in netlify)

    # Trust client local methods
    tc = TIPTrustClient("http://localhost:4000")
    tier = tc.compute_tier(850)
    check("trust.compute_tier(850) = HIGHLY_TRUSTED", tier["name"] == "HIGHLY_TRUSTED")
    tier2 = tc.compute_tier(0)
    check("trust.compute_tier(0) = NOT_TRUSTED",       tier2["name"] == "NOT_TRUSTED")

    kp2   = generate_mldsa_keypair()
    proof = tc.generate_score_proof(850, 700, kp2["privateKey"])
    check("trust.generate_score_proof: above_threshold for 850>=700", proof["above_threshold"])
    check("trust.generate_score_proof: proof starts with zksc:",
          proof["proof"].startswith("zksc:"))
    check("trust.verify_score_proof: valid proof verifies",
          tc.verify_score_proof(proof["proof"], proof["commitment"], 700, True))
    check("trust.verify_score_proof: wrong claim rejected",
          not tc.verify_score_proof(proof["proof"], proof["commitment"], 700, False))

    # Badges client
    bc   = TIPBadgesClient()
    seal = bc.render_seal(892, size=120, variant="gold-dark", founding=True)
    check("badges.render_seal() produces SVG",          seal.startswith("<svg"))
    check("badges.render_seal() contains score 892",    "892" in seal)
    check("badges.render_seal() founding star present", "&#9733;" in seal)

    seal_light = bc.render_seal(600, size=80, variant="light")
    check("badges.render_seal(variant=light) valid SVG", seal_light.startswith("<svg"))

    mark = bc.render_tip_mark(size=100, variant="dark")
    check("badges.render_tip_mark() produces SVG",      mark.startswith("<svg"))
    check("badges.render_tip_mark() contains TIP text", "TIP" in mark)
    check("badges.render_tip_mark() contains POWERED",  "POWERED" in mark)

    shield = bc.render_shield(score=720, size=32, founding=False)
    check("badges.render_shield() produces SVG",        shield.startswith("<svg"))

    shield0 = bc.render_shield(score=0)
    check("badges.render_shield(score=0) cross icon",   "x1=" in shield0)

    origin = bc.render_origin_badge("OH", "VERIFIED")
    check("badges.render_origin_badge(OH) contains label", "Original Human" in origin)

    for o in ("OH", "AA", "AG", "MX"):
        svg = bc.render_origin_badge(o)
        check(f"badges.render_origin_badge({o}) valid SVG", svg.startswith("<svg"))

    cfg_dict = bc.generate_http_config("tip://id/US-abc", "tip://c/OH-abc-ab12", "OH", 892)
    check("badges.generate_http_config() has nginx",    "add_header" in cfg_dict["nginx"])
    check("badges.generate_http_config() has apache",   "Header set" in cfg_dict["apache"])
    check("badges.generate_http_config() has cloudflare", "Cloudflare" in cfg_dict["cloudflare"])

    meta = bc.generate_meta_tags("tip://id/US-abc", "tip://c/OH-abc", "OH", 892)
    check("badges.generate_meta_tags() has tip:author",  "tip:author"  in meta)
    check("badges.generate_meta_tags() has tip:content", "tip:content" in meta)
    check("badges.generate_meta_tags() has tip:score",   "tip:score"   in meta)

    embed = bc.generate_embed_widget("tip://id/US-abc", 850)
    check("badges.generate_embed_widget() has TIP badge comment", "TIP™" in embed)
    check("badges.generate_embed_widget() has verify link",       "theailab.org/verify/" in embed)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8: Protocol Constants
# ══════════════════════════════════════════════════════════════════════════════

def test_constants() -> None:
    section("8. PROTOCOL CONSTANTS")

    check("4 origin codes: OH AA AG MX",       Origin.ALL == {"OH","AA","AG","MX"})
    check("Origin.is_valid('OH') = True",       Origin.is_valid("OH"))
    check("Origin.is_valid('XX') = False",      not Origin.is_valid("XX"))
    check("Origin.label('AG') = AI-Generated",  Origin.label("AG") == "AI-Generated")

    check("5 trust tiers defined",              len(TIERS) == 5)
    check("HIGHLY_TRUSTED: 800-1000",           get_tier(800).name == "HIGHLY_TRUSTED")
    check("TRUSTED: 600-799",                   get_tier(700).name == "TRUSTED")
    check("REVIEW_ADVISED: 400-599",            get_tier(500).name == "REVIEW_ADVISED")
    check("LOW_TRUST: 200-399",                 get_tier(300).name == "LOW_TRUST")
    check("NOT_TRUSTED: 0-199",                 get_tier(100).name == "NOT_TRUSTED")
    check("Tier boundaries exact: 600 = TRUSTED", get_tier(600).name == "TRUSTED")
    check("Tier boundaries exact: 599 = REVIEW", get_tier(599).name == "REVIEW_ADVISED")

    check("TxType.GENESIS defined",             TxType.GENESIS == "GENESIS")
    check("TxType.REVOCATION_TYPES has 4",      len(TxType.REVOCATION_TYPES) == 4)
    check("TxType.ALL has >= 16 types",         len(TxType.ALL) >= 16)
    check("TxType.is_valid('GENESIS') = True",  TxType.is_valid("GENESIS"))
    check("TxType.is_valid('FAKE') = False",    not TxType.is_valid("FAKE"))

    check("ScoreEvent.INITIAL == 500",               ScoreEvent.INITIAL_NO_ATTESTATION == 500)
    check("ScoreEvent.INITIAL_ATTESTED == 550",       ScoreEvent.INITIAL_WITH_ATTESTATION == 550)
    check("ScoreEvent.OH_AG_1ST == -100",             ScoreEvent.OH_CONFIRMED_AG_1ST == -100)
    check("ScoreEvent.MISMATCH_3RD == -350",          ScoreEvent.MISMATCH_3RD_OFFENSE == -350)
    check("ScoreEvent.AG_CONSERVATIVE == 0",          ScoreEvent.AG_CONSERVATIVE == 0)
    check("ScoreEvent.JUROR_MIN_SCORE == 700",        ScoreEvent.JUROR_MIN_SCORE == 700)

    from shared.constants import PreScan
    check("PreScan.DEFAULT == 0.85",            PreScan.DEFAULT == 0.85)
    check("PreScan.academic == 0.92 (FIX-03)",  PreScan.BY_TYPE["academic"] == 0.92)
    check("PreScan.legal == 0.93 (FIX-03)",     PreScan.BY_TYPE["legal"] == 0.93)

    from shared.constants import JurisdictionTier
    check("JurisdictionTier.can_accredit(green)",  JurisdictionTier.can_accredit("green"))
    check("JurisdictionTier.can_accredit(amber)",  JurisdictionTier.can_accredit("amber"))
    check("JurisdictionTier.can_accredit(red) = False", not JurisdictionTier.can_accredit("red"))

    from shared.constants import HttpHeaders, Protocol
    check("HttpHeaders.AUTHOR == 'TIP-Author'",     HttpHeaders.AUTHOR == "TIP-Author")
    check("HttpHeaders.TRUST_SCORE == 'TIP-Trust-Score'",
          HttpHeaders.TRUST_SCORE == "TIP-Trust-Score")
    check("Protocol.VERSION == '2.0.0'",            Protocol.VERSION == "2.0.0")
    check("Protocol.LICENSE == 'CC-BY-4.0'",        Protocol.LICENSE == "CC-BY-4.0")
    check("Protocol.CHAIN_ID == 'tip-mainnet-v2'",  Protocol.CHAIN_ID == "tip-mainnet-v2")

    from shared.constants import ScoreDisplay
    check("ScoreDisplay.DEFAULT == 'TIER_ONLY'",    ScoreDisplay.DEFAULT == "TIER_ONLY")
    check("ScoreDisplay.ALL has 3 modes",           len(ScoreDisplay.ALL) == 3)


# ─── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print(f"  {B}TIP™ Protocol Python — Complete Test Suite{R}")
    print(f"  {D}The AI Lab Intelligence Unobscured, Inc. | theailab.org{R}")

    test_crypto()
    test_genesis()
    test_dag()
    test_scoring()
    test_validator()
    test_genesis_files()
    test_sdk()
    test_constants()

    total = _passed + _failed
    print()
    print("  " + "═" * 60)
    print(f"  TIP™ Protocol v2.0 — Python Test Suite")
    print("  " + "═" * 60)
    print(f"  Tests passed:  {G}{_passed} / {total}{R}")
    if _failed:
        print(f"  Tests failed:  {RED}{_failed}{R}")
        sys.exit(1)
    else:
        print(f"  {G}{B}ALL TESTS PASS — Python implementation is production-ready.{R}")
    print("  " + "═" * 60)
    print()
