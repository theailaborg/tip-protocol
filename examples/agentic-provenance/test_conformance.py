"""Executable TIP Agent Conformance Checklist items; synthetic data only.

License: TIPCL-1.0 (see ../../LICENSE.txt).
"""
import json
import math
import subprocess
from pathlib import Path

import pytest
import tip_agentic as ta
from test_tip_agentic import World


def test_item7_incremental_roots_and_proofs_match_reference():
    log = ta.IncrementalMerkleLog()
    assert log.root == ta.merkle_root([])
    assert log.proof(0) is None
    for n in range(1, 130):
        log.append(str(n))
        items = list(log)
        assert log.root == ta.merkle_root(items)
        for i in range(n):
            assert log.proof(i) == ta.merkle_proof(items, i)
            assert ta.verify_merkle_proof(items[i], log.proof(i), log.root)
        assert log.proof(n) is None
        assert log.proof(-1) is None


@pytest.mark.parametrize("size", [1000, 10000, 100000])
def test_item7_append_hash_work_is_logarithmic(size, monkeypatch):
    log = ta.IncrementalMerkleLog(str(i) for i in range(size))
    original, calls = ta._node_hash, []
    def counted(left, right):
        calls.append(1)
        return original(left, right)
    monkeypatch.setattr(ta, "_node_hash", counted)
    log.append("next")
    assert 0 < len(calls) <= math.ceil(math.log2(size + 1))
    calls.clear()
    _ = log.root
    assert log.proof(size) is not None
    assert not calls  # current root/proof reuse hashes, not a disguised rebuild


def test_item7_prepared_append_does_not_change_live_log():
    log = ta.IncrementalMerkleLog(["one", "two", "three"])
    old = log.root
    proposed = log.prepare_append("four")
    assert log.root == old and len(log) == 3
    assert proposed.digest == ta.merkle_root(["one", "two", "three", "four"])


def test_item7_existing_node_verifies_incremental_proofs_and_bundle(tmp_path):
    root = Path(__file__).resolve().parents[2]
    vectors = []
    for n in [1, 2, 3, 5, 7, 8, 9, 31, 32, 33, 1000]:
        log = ta.IncrementalMerkleLog(str(i) for i in range(n))
        for i in {0, n // 2, n - 1}:
            vectors.append({"item": log[i], "proof": log.proof(i), "root": log.root})
    path = tmp_path / "proofs.json"
    path.write_text(json.dumps(vectors))
    check = """const fs=require('fs'),m=require('./shared/merkle');
    for(const v of JSON.parse(fs.readFileSync(process.argv[1]))) {
      if(!m.verifyProof(v.item,v.proof,v.root)) process.exit(1);
      if(m.verifyProof(v.item+'changed',v.proof,v.root)) process.exit(2);
    }"""
    subprocess.run(["node", "-e", check, str(path)], cwd=root, check=True, capture_output=True)
    w = World()
    for i in range(9):
        content = f"synthetic-{i}".encode()
        req = w.edit(content=content)
        outcome = w.submit(req, content=content)
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps(w.bundle(req, outcome)))
    proc = subprocess.run(["node", str(root / "examples/agentic-provenance/verify_with_tip.js"), str(bundle)],
                          cwd=root, check=True, capture_output=True, text=True)
    assert "9/9 checks passed" in proc.stdout


PAYMENTS = "https://site.example/payments/"
BUDGET = {"id": "synthetic-total", "unit": "test-credit", "total": 100, "per_action": 60}


def budget_world():
    w = World()
    root = ta.issue_delegation(w.principal, w.principal_id, w.agent.public_key_hex,
        ta.make_scope(["create"], [PAYMENTS]), w.now - 1, w.now + 1000, budget=BUDGET)
    workers = [ta.Signer.generate() for _ in range(3)]
    mandates = [ta.issue_delegation(w.agent, w.agent_id, agent.public_key_hex,
        ta.make_scope(["create"], [PAYMENTS]), w.now - 1, w.now + 1000,
        parent=ta.record_id(root), budget={**BUDGET, "per_action": 40}) for agent in workers]
    return w, root, workers, mandates


def payment(w, root, child, agent, index, amount=40):
    payload = ta.canonical_json({"amount": amount, "unit": BUDGET["unit"]}).encode()
    chain = [ta.record_id(root)] + ([ta.record_id(child)] if child else [])
    req = ta.make_request(agent, chain, "create", PAYMENTS + str(index), w.now,
        content=payload, spend={"amount": amount, "unit": BUDGET["unit"]})
    return req, payload, [root] + ([child] if child else [])


def test_item15_three_individually_permitted_agents_exceed_principal_total():
    w, root, agents, mandates = budget_world()
    for i, (agent, child) in enumerate(zip(agents, mandates)):
        req, payload, chain = payment(w, root, child, agent, i)
        auth = ta.check_authority(req["body"], {ta.record_id(m): m for m in chain}, [], w.directory, w.now)
        assert auth.status == ta.VALID and auth.budget["per_action"] == 40
        out = w.gw.submit(req, chain, content=payload)
        assert out["receipt"]["body"]["decision"] == ("committed" if i < 2 else "rejected")
        assert ta.verify_evidence(ta.evidence_bundle(req, out, chain), w.directory).status == ta.VALID
    receipt = out["receipt"]["body"]
    assert "combined spend" in receipt["reason"]
    assert receipt["budget"]["spent_before"] == receipt["budget"]["spent_after"] == 80
    assert PAYMENTS + "2" not in w.gw.store
    assert len(w.gw.log) == 3  # refusal is signed and included too


@pytest.mark.parametrize("field,value", [("total", 101), ("per_action", 61), ("id", "reset"), ("unit", "other")])
def test_item15_sub_mandate_cannot_raise_or_replace_budget(field, value):
    w, root, agents, _ = budget_world()
    child = ta.issue_delegation(w.agent, w.agent_id, agents[0].public_key_hex,
        root["body"]["scope"], w.now - 1, w.now + 1000, parent=ta.record_id(root),
        budget={**BUDGET, field: value})
    req, payload, chain = payment(w, root, child, agents[0], 0)
    out = w.gw.submit(req, chain, content=payload)
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert "budget" in out["receipt"]["body"]["reason"]
    assert not w.gw.store.get(PAYMENTS + "0")


def test_item15_omitted_child_budget_inherits_principal_limit():
    w, root, agents, _ = budget_world()
    child = ta.issue_delegation(w.agent, w.agent_id, agents[0].public_key_hex,
        root["body"]["scope"], w.now - 1, w.now + 1000, parent=ta.record_id(root))
    for i in range(2):
        req, payload, chain = payment(w, root, child, agents[0], i, 60)
        out = w.gw.submit(req, chain, content=payload)
        assert out["receipt"]["body"]["decision"] == ("committed" if i == 0 else "rejected")


def test_item15_separate_root_mandates_share_budget_and_cannot_reset_it():
    w, _, agents, _ = budget_world()
    for i, agent in enumerate(agents):
        root = ta.issue_delegation(w.principal, w.principal_id, agent.public_key_hex,
            ta.make_scope(["create"], [PAYMENTS]), w.now - 1, w.now + 1000, budget=BUDGET)
        req, payload, chain = payment(w, root, None, agent, i)
        out = w.gw.submit(req, chain, content=payload)
        assert out["receipt"]["body"]["decision"] == ("committed" if i < 2 else "rejected")
    replacement = ta.issue_delegation(w.principal, w.principal_id, agents[0].public_key_hex,
        root["body"]["scope"], w.now - 1, w.now + 1000, budget={**BUDGET, "total": 200})
    req, payload, chain = payment(w, replacement, None, agents[0], "replacement", 1)
    out = w.gw.submit(req, chain, content=payload)
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert "conflicts" in out["receipt"]["body"]["reason"]


@pytest.mark.parametrize("amount", [-1, 0, True, 41])
def test_item15_invalid_or_over_limit_spend_cannot_commit(amount):
    w, root, agents, mandates = budget_world()
    req, payload, chain = payment(w, root, mandates[0], agents[0], 0, amount)
    out = w.gw.submit(req, chain, content=payload)
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert w.gw._budget_spend == {}


def test_item15_missing_spend_cannot_bypass_budget():
    w, root, agents, mandates = budget_world()
    req, payload, chain = payment(w, root, mandates[0], agents[0], 0)
    req["body"].pop("spend")
    req = agents[0].sign_body(req["body"])
    assert w.gw.submit(req, chain, content=payload)["receipt"]["body"]["decision"] == "rejected"


def test_item15_evidence_outage_does_not_consume_budget():
    w, root, agents, mandates = budget_world()
    req, payload, chain = payment(w, root, mandates[0], agents[0], 0)
    w.gw.evidence_sink = lambda outcome: False
    with pytest.raises(ConnectionError):
        w.gw.submit(req, chain, content=payload)
    assert w.gw._budget_spend == {} and w.gw._budget_limits == {} and len(w.gw.log) == 0
    w.gw.evidence_sink = None
    out = w.gw.submit(req, chain, content=payload)
    assert out["receipt"]["body"]["budget"]["spent_after"] == 40


def test_item15_concurrent_agents_cannot_race_past_total():
    from concurrent.futures import ThreadPoolExecutor
    w, root, agents, mandates = budget_world()
    requests = [payment(w, root, mandates[i], agents[i], i) for i in range(3)]
    def submit(entry):
        req, payload, chain = entry
        return w.gw.submit(req, chain, content=payload)["receipt"]["body"]["decision"]
    with ThreadPoolExecutor(max_workers=3) as pool:
        decisions = list(pool.map(submit, requests))
    assert sorted(decisions) == ["committed", "committed", "rejected"]
    assert w.gw._budget_spend[(w.principal_id, BUDGET["id"])] == 80


def test_item15_spend_cannot_understate_payment_content():
    w, root, agents, mandates = budget_world()
    req, payload, chain = payment(w, root, mandates[0], agents[0], 0)
    req["body"]["spend"]["amount"] = 1
    req = agents[0].sign_body(req["body"])
    out = w.gw.submit(req, chain, content=payload)
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert "canonical synthetic payment" in out["receipt"]["body"]["reason"]
    assert not w.gw._budget_spend


def test_item16_repeated_mandate_link_is_refused():
    w = World()
    req = w.edit(chain=[w.root_id, w.child_id, w.root_id])
    out = w.submit(req)
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert "cycle" in out["receipt"]["body"]["reason"]
    assert ta.verify_evidence(w.bundle(req, out), w.directory).status == ta.VALID


@pytest.mark.parametrize("widen", [False, True], ids=["same-scope-cycle", "wider-authority-loop"])
def test_item16_signed_identity_loop_cannot_recover_authority(widen):
    w = World()
    scope = w.root["body"]["scope"] if widen else w.child["body"]["scope"]
    loop = ta.issue_delegation(w.sub, ta.agent_id(w.sub.public_key_hex), w.agent.public_key_hex,
        scope, w.child["body"]["not_before"], w.child["body"]["expires_at"], parent=w.child_id)
    chain = [w.root, w.child, loop]
    req = w.edit(signer=w.agent, chain=[ta.record_id(m) for m in chain])
    before = dict(w.gw.store)
    out = w.submit(req, delegations=chain)
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert ("wider" if widen else "cycle") in out["receipt"]["body"]["reason"]
    assert w.gw.store == before
    assert ta.verify_evidence(w.bundle(req, out, delegations=chain), w.directory).status == ta.VALID


OUTPUTS = "https://site.example/outputs/"


def output_mandate(w, agent, principal=None, principal_id=None):
    return ta.issue_delegation(principal or w.principal, principal_id or w.principal_id,
        agent.public_key_hex, ta.make_scope(["create"], [OUTPUTS]), w.now - 1, w.now + 1000)


def produce(w, agent, mandate, index, inputs=None, pool=None):
    content = f"synthetic output {index}".encode()
    req = ta.make_request(agent, [ta.record_id(mandate)], "create", OUTPUTS + str(index),
        w.now, content=content, inputs=inputs)
    outcome = w.gw.submit(req, [mandate], content=content, upstream_evidence=pool)
    return ta.evidence_bundle(req, outcome, [mandate], upstream_evidence=pool)


def input_ref(bundle):
    return {"receipt": ta.record_id(bundle["receipt"]), "content_hash": bundle["receipt"]["body"]["after_hash"]}


def output_chain():
    w = World()
    agents = [ta.Signer.generate() for _ in range(3)]
    mandates = [output_mandate(w, agent) for agent in agents]
    a = produce(w, agents[0], mandates[0], "a")
    pool = {ta.record_id(a["receipt"]): a}
    b = produce(w, agents[1], mandates[1], "b", [input_ref(a)], pool)
    pool[ta.record_id(b["receipt"])] = b
    c = produce(w, agents[2], mandates[2], "c", [input_ref(b)], pool)
    return w, agents, mandates, a, b, c


def test_item27_output_handoff_walks_back_through_agents_to_principal():
    w, _, _, a, b, c = output_chain()
    assert b["request"]["body"]["inputs"] == [input_ref(a)]
    verdict = ta.verify_evidence(c, w.directory)
    assert verdict.status == ta.VALID, verdict.reasons
    line = verdict.answers["lineage"][0]
    assert line["receipt"] == ta.record_id(b["receipt"])
    assert line["ancestors"][0]["receipt"] == ta.record_id(a["receipt"])
    assert line["principal"] == line["ancestors"][0]["principal"] == w.principal_id


@pytest.mark.parametrize("fault", ["missing", "receipt", "request", "mandate"])
def test_item27_missing_or_tampered_ancestor_cannot_verify(fault):
    w, _, _, a, _, c = output_chain()
    rid = ta.record_id(a["receipt"])
    if fault == "missing":
        del c["upstream_evidence"][rid]
    elif fault == "receipt":
        c["upstream_evidence"][rid]["receipt"]["sig"] = "00"
    elif fault == "request":
        c["upstream_evidence"][rid]["request"]["sig"] = "00"
    else:
        c["upstream_evidence"][rid]["delegations"][0]["sig"] = "00"
    verdict = ta.verify_evidence(c, w.directory)
    assert verdict.status == (ta.INDETERMINATE if fault == "missing" else ta.INVALID)


@pytest.mark.parametrize("fault", ["missing", "wrong-hash", "different-principal", "rejected-output", "duplicate", "malformed"])
def test_item27_gateway_refuses_unverifiable_handoff(fault):
    w = World()
    a, b = ta.Signer.generate(), ta.Signer.generate()
    ma = output_mandate(w, a, w.impostor, w.impostor_id) if fault == "different-principal" else output_mandate(w, a)
    first = produce(w, a, ma, "a")
    if fault == "rejected-output":
        first = produce(w, a, ma, "a")  # resource already exists
    ref = input_ref(first)
    if fault == "wrong-hash":
        ref["content_hash"] = ta.shake256("wrong")
    pool = {} if fault == "missing" else {ta.record_id(first["receipt"]): first}
    if fault == "malformed":
        first["receipt"]["body"]["log_index"] = 2**60  # cannot be canonicalised safely
    refs = [ref, ref] if fault == "duplicate" else [ref]
    second = produce(w, b, output_mandate(w, b), "b", refs, pool)
    assert second["receipt"]["body"]["decision"] == "rejected"
    assert "input provenance" in second["receipt"]["body"]["reason"]
    assert OUTPUTS + "b" not in w.gw.store
    assert ta.verify_evidence(second, w.directory).status == ta.VALID


def test_item27_input_reference_is_covered_by_action_signature():
    w, _, _, _, b, _ = output_chain()
    b["request"]["body"]["inputs"] = []
    assert ta.verify_evidence(b, w.directory).status == ta.INVALID


def enroll(w, code="code-v1", at=None):
    record = ta.issue_agent_record(w.principal, w.principal_id, w.sub.public_key_hex,
        ta.shake256(code), ta.shake256("model-version-manifest-v1"), ta.shake256("prompt-template-v1"),
        w.now - 1 if at is None else at)
    w.directory.register_agent(record)
    return record


def test_item2_registered_agent_hashes_are_bound_to_action():
    w = World()
    record = enroll(w)
    req = w.edit(agent_record=record)
    out = w.submit(req)
    assert out["receipt"]["body"]["decision"] == "committed"
    assert req["body"]["agent_record"] == ta.record_id(record)
    assert ta.verify_evidence(w.bundle(req, out), w.directory).status == ta.VALID


@pytest.mark.parametrize("field", ["code_hash", "model_hash", "prompt_hash"])
def test_item2_changed_runtime_hash_without_reregistration_is_refused(field):
    w = World()
    record = enroll(w)
    hashes = {k: record["body"][k] for k in ta.RUNTIME_HASH_FIELDS}
    hashes[field] = ta.shake256("changed")
    req = w.edit(agent_record=record, runtime_hashes=hashes)
    before = dict(w.gw.store)
    out = w.submit(req)
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert "runtime hashes differ" in out["receipt"]["body"]["reason"]
    assert w.gw.store == before
    assert ta.verify_evidence(w.bundle(req, out), w.directory).status == ta.VALID


def test_item2_enrolled_agent_cannot_omit_record_to_bypass_check():
    w = World()
    enroll(w)
    out = w.submit(w.edit())
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert "current Agent Record" in out["receipt"]["body"]["reason"]


def test_item2_reregistration_allows_new_code_preserves_old_evidence():
    w = World()
    old = enroll(w)
    req = w.edit(agent_record=old)
    prior = w.bundle(req, w.submit(req))
    w.now += 10
    new = enroll(w, "code-v2", w.now)
    stale = w.submit(w.edit(agent_record=old))
    assert stale["receipt"]["body"]["decision"] == "rejected"
    req = w.edit(agent_record=new)
    out = w.submit(req)
    assert out["receipt"]["body"]["decision"] == "committed"
    assert ta.verify_evidence(prior, w.directory).status == ta.VALID
    assert ta.verify_evidence(w.bundle(req, out), w.directory).status == ta.VALID


def test_item2_forged_registration_and_history_rewrite_are_refused():
    import copy
    w = World()
    original = enroll(w)
    forged = copy.deepcopy(original)
    forged["body"]["code_hash"] = ta.shake256("forged")
    with pytest.raises(ValueError, match="invalid"):
        w.directory.register_agent(forged)
    rewritten = ta.issue_agent_record(w.principal, w.principal_id, w.sub.public_key_hex,
        ta.shake256("new"), ta.shake256("model"), ta.shake256("prompt"), w.now - 2)
    with pytest.raises(ValueError, match="forward in time"):
        w.directory.register_agent(rewritten)


def test_item2_registration_is_not_a_substitute_for_mandate_scope():
    w = World()
    record = enroll(w)
    req = w.edit(agent_record=record, action="delete")
    out = w.submit(req)
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert "outside the delegated scope" in out["receipt"]["body"]["reason"]


def test_item15_verifier_rejects_site_signed_overspend():
    w, root, agents, mandates = budget_world()
    req, payload, chain = payment(w, root, mandates[0], agents[0], 0)
    state = {"principal": w.principal_id, "id": BUDGET["id"], "unit": BUDGET["unit"],
             "total": 100, "amount": 40, "spent_before": 80, "spent_after": 120}
    out = w.gw._record(req, req["body"], "committed", "", None, ta.content_hash(payload), w.now, state)
    verdict = ta.verify_evidence(ta.evidence_bundle(req, out, chain), w.directory)
    assert verdict.status == ta.INVALID and "budget" in verdict.reasons[0]


def test_item27_verification_depth_limit_fails_closed(monkeypatch):
    w, _, _, _, _, c = output_chain()
    monkeypatch.setattr(ta, "MAX_LINEAGE_DEPTH", 1)
    verdict = ta.verify_evidence(c, w.directory)
    assert verdict.status == ta.INDETERMINATE
    assert "limit" in verdict.reasons[0]


def test_item2_another_principals_record_cannot_authorise_action():
    w = World()
    record = ta.issue_agent_record(w.impostor, w.impostor_id, w.sub.public_key_hex,
        ta.shake256("code"), ta.shake256("model"), ta.shake256("prompt"), w.now - 1)
    w.directory.register_agent(record)
    out = w.submit(w.edit(agent_record=record))
    assert out["receipt"]["body"]["decision"] == "rejected"
    assert "principal does not match" in out["receipt"]["body"]["reason"]
