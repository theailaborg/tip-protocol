"""Synthetic run-integrity, evidence-outage and cryptographic deletion tests.

License: TIPCL-1.0 (see ../../LICENSE.txt).
"""
import copy

import pytest
from cryptography.exceptions import InvalidTag

import tip_agentic as ta
from test_tip_agentic import World, PLAN, T0, HOUR, DOCS


def run_three(w):
    outcomes = []
    for i in range(3):
        payload = f"synthetic-{i}".encode()
        req = w.edit(content=payload)
        outcomes.append(w.submit(req, content=payload))
    return [o["receipt"] for o in outcomes], outcomes[-1]["checkpoint"]


@pytest.mark.parametrize("position", [0, 1, 2], ids=["first", "middle", "last"])
def test_dropped_receipt_within_run_is_detected(position):
    from assurance import verify_run
    w = World()
    receipts, checkpoint = run_three(w)
    assert verify_run(receipts, checkpoint, w.directory).status == ta.VALID
    del receipts[position]
    assert verify_run(receipts, checkpoint, w.directory).status == ta.INVALID


def test_duplicated_receipt_within_run_is_detected():
    from assurance import verify_run
    w = World()
    receipts, checkpoint = run_three(w)
    receipts[1] = copy.deepcopy(receipts[0])  # preserve count, defeat size-only checking
    assert verify_run(receipts, checkpoint, w.directory).status == ta.INVALID


def test_reordered_receipts_within_run_are_detected():
    from assurance import verify_run
    w = World()
    receipts, checkpoint = run_three(w)
    receipts[0], receipts[1] = receipts[1], receipts[0]
    assert verify_run(receipts, checkpoint, w.directory).status == ta.INVALID


@pytest.mark.parametrize("fault", ["edited_receipt", "forged_checkpoint", "other_run"])
def test_run_verifier_rejects_tampering_and_wrong_run(fault):
    from assurance import verify_run
    w = World()
    receipts, checkpoint = run_three(w)
    if fault == "edited_receipt":
        receipts[0]["body"]["reason"] = "substituted"
    elif fault == "forged_checkpoint":
        checkpoint = w.rogue.sign_body(checkpoint["body"])
    else:
        # Same signing site, same indices and count, different signed run.
        w.gw.log = []
        _, checkpoint = run_three(w)
    assert verify_run(receipts, checkpoint, w.directory).status == ta.INVALID


class SyntheticEvidenceService:
    def __init__(self):
        self.available = True
        self.outcomes = []

    def __call__(self, outcome):
        if not self.available:
            raise ConnectionError("synthetic evidence service unavailable")
        self.outcomes.append(copy.deepcopy(outcome))
        return True


@pytest.mark.parametrize("action", ["create", "edit", "delete"])
def test_evidence_service_outage_mid_run_stops_state_change(action):
    w = World()
    service = SyntheticEvidenceService()
    w.gw.evidence_sink = service
    assert w.submit(w.edit())["receipt"]["body"]["decision"] == "committed"
    service.available = False
    # Explicitly grant delete as well, so authority is not what stops this action.
    grant = ta.issue_delegation(w.principal, w.principal_id, w.agent.public_key_hex,
        ta.make_scope(["create", "edit", "delete"], [DOCS]), T0 - HOUR, T0 + HOUR)
    resource = DOCS + "new.txt" if action == "create" else PLAN
    req = w.edit(signer=w.agent, chain=[ta.record_id(grant)], action=action, resource=resource)
    before_store, before_log = dict(w.gw.store), list(w.gw.log)
    with pytest.raises(ConnectionError, match="evidence service unavailable"):
        w.submit(req, delegations=[grant])
    assert dict(w.gw.store) == before_store
    assert w.gw.log == before_log
    assert len(service.outcomes) == 1
    service.available = True
    # The uncommitted attempt must not permanently consume its nonce.
    assert w.submit(req, delegations=[grant])["receipt"]["body"]["decision"] == "committed"
    assert len(service.outcomes) == 2


def test_missing_evidence_ack_stops_state_change():
    w = World()
    w.gw.evidence_sink = lambda outcome: None
    before = dict(w.gw.store)
    with pytest.raises(ConnectionError, match="acknowledge"):
        w.submit(w.edit())
    assert w.gw.store == before
    assert w.gw.log == []


def test_checkpoint_signing_failure_does_not_commit_or_append(monkeypatch):
    w = World()
    original = w.site_key.sign_body
    def fail_checkpoint(body):
        if body.get("type") == "checkpoint":
            raise RuntimeError("synthetic signing outage")
        return original(body)
    monkeypatch.setattr(w.site_key, "sign_body", fail_checkpoint)
    before = dict(w.gw.store)
    with pytest.raises(RuntimeError, match="signing outage"):
        w.submit(w.edit())
    assert w.gw.store == before
    assert w.gw.log == []


def test_key_destruction_deletes_content_while_log_still_verifies():
    from assurance import EncryptedRecordStore, verify_run
    w = World()
    store = EncryptedRecordStore()
    w.gw.store = store
    grant = ta.issue_delegation(w.principal, w.principal_id, w.agent.public_key_hex,
        ta.make_scope(["create", "delete"], [DOCS]), T0 - HOUR, T0 + HOUR)
    payload = b"synthetic clinical note; no real patient"
    req = ta.make_request(w.agent, [ta.record_id(grant)], "create", PLAN, T0, content=payload)
    created = w.gw.submit(req, [grant], content=payload)
    assert store[PLAN] == payload
    ciphertext = store.ciphertext_for(PLAN)
    assert payload not in ciphertext
    delete = ta.make_request(w.agent, [ta.record_id(grant)], "delete", PLAN, T0, base=payload)
    removed = w.gw.submit(delete, [grant])
    assert removed["receipt"]["body"]["decision"] == "committed"
    assert not store.has_key(PLAN)
    assert store.ciphertext_for(PLAN) == ciphertext  # bytes remain, key has gone
    with pytest.raises(KeyError):
        _ = store[PLAN]
    assert len(store) == 0
    assert verify_run([created["receipt"], removed["receipt"]], removed["checkpoint"], w.directory).status == ta.VALID
    assert ta.verify_evidence(ta.evidence_bundle(req, created, [grant]), w.directory).status == ta.VALID
    assert ta.verify_evidence(ta.evidence_bundle(delete, removed, [grant]), w.directory).status == ta.VALID


def test_encrypted_records_use_independent_keys_and_authenticated_ciphertext():
    from assurance import EncryptedRecordStore
    store = EncryptedRecordStore()
    store["a"] = store["b"] = b"synthetic"
    assert store.ciphertext_for("a") != store.ciphertext_for("b")
    del store["a"]
    assert store["b"] == b"synthetic"
    # Resource identity is authenticated: swapping ciphertexts cannot decrypt.
    store["c"] = b"synthetic"
    store._ciphertexts["b"] = store._ciphertexts["c"]
    with pytest.raises(InvalidTag):
        _ = store["b"]
