"""Independent accounting, replay and durable-run checks for synthetic scenarios.

These tests exercise completed, independent runs. They do not establish a shared
live budget between runs, external execution, or production TIP integration.
License: TIPCL-1.0 (see ../../LICENSE.txt).
"""
import copy
import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import simulation as sim
import tip_agentic as ta


def request(identifier, agent="a", amount=1, subject="person-1", **changes):
    return {"kind": "request", "id": identifier, "agent": agent,
            "site": "desk", "purpose": "approved", "amount": amount,
            "subject": subject, **changes}


def scenario(mode="sum", events=None, limit=10, agent_limit=10):
    return {"schema": "tip-simulation/v1", "id": "custom-boundaries",
            "title": "Synthetic accounting boundaries", "domain": "finance",
            "seed": None, "policy": {"mode": mode, "unit": "credits" if mode == "sum" else "people",
            "purpose": "approved", "shared_limit": limit,
            "agents": [{"id": "a", "limit": agent_limit}, {"id": "b", "limit": agent_limit}],
            "sites": ["desk", "branch"]},
            "events": events if events is not None else [request("one", amount=4), request("two", "b", 6), request("three")]}


def accounting_oracle(doc):
    """Reference by recomputing totals from accepted requests, not mutable counters.

Generated controls are interpreted in authoritative event order. The oracle
    retains the first payload for each agent/request ID, including refusals.
"""
    policy = doc["policy"]
    limits = {a["id"]: a["limit"] for a in policy["agents"]}
    accepted, seen, revoked, result = [], {}, set(), []
    stopped, counter = False, True

    def total(agent=None):
        selected = [e for e in accepted if agent is None or e["agent"] == agent]
        if policy["mode"] == "distinct":
            return len({e["subject"] for e in selected})
        return sum(e["amount"] for e in selected)

    for e in doc["events"]:
        before = total()
        if e["kind"] != "request":
            if e["kind"] == "revoke":
                revoked.add(e["agent"])
            elif e["kind"] == "stop_all":
                stopped = True
            elif e["kind"] == "resume":
                stopped = False
            elif e["kind"] == "counter":
                counter = e["available"]
            result.append(("control", before, total()))
            continue
        request_key = (e["agent"], e["id"])
        if request_key in seen:
            decision = "duplicate" if seen[request_key] == e else "refused"
        else:
            seen[request_key] = copy.deepcopy(e)
            valid = (e["agent"] in limits and e["site"] in policy["sites"]
                     and e["purpose"] == policy["purpose"]
                     and e["agent"] not in revoked and not stopped and counter)
            if valid:
                # Recompute candidates from the ledger; no production helper is used.
                accepted.append(e)
                valid = total() <= policy["shared_limit"] and total(e["agent"]) <= limits[e["agent"]]
                if not valid:
                    accepted.pop()
            decision = "allowed" if valid else "refused"
        result.append((decision, before, total()))
    return result


def projection(result):
    return [(row["decision"], row["total_before"], row["total_after"]) for row in result["trace"]]


def test_all_fifteen_presets_have_unique_ids_and_valid_accounting():
    cases = sim.presets()
    assert len(cases) == 15
    assert len({c["id"] for c in cases}) == 15
    assert {"healthcare", "finance", "government"} <= {c["domain"] for c in cases}
    for case in cases:
        assert sim.validate_scenario(case) == case
        result = sim.evaluate(case)
        assert projection(result) == accounting_oracle(case)
        assert result["summary"]["total"] <= case["policy"]["shared_limit"]


def test_preset_results_match_known_shared_totals():
    # These expectations come from the fifteen hand-reviewed explorer cases.
    expected = {"s-health": 4, "s-money": 45000, "s-gov": 3, "yakima": 25,
                "gulfcoast": 4200, "ctr": 990000, "hastert": 9500, "shopping": 930,
                "welfare": 3, "irs": 47000, "powerschool": 490, "baltimore": 4,
                "scholarship": 5, "fakedegree": 3, "sumleaks": 2}
    assert {c["id"]: sim.evaluate(c)["summary"]["total"] for c in sim.presets()} == expected


@pytest.mark.parametrize("domain", ["healthcare", "finance", "government", "education", "privacy"])
@pytest.mark.parametrize("seed", [0, 7, 173])
def test_seeded_workloads_are_repeatable_and_match_independent_oracle(domain, seed):
    first = sim.generate_scenario(domain, seed, 80)
    assert first == sim.generate_scenario(domain, seed, 80)
    assert first != sim.generate_scenario(domain, seed + 1, 80)
    assert first["seed"] == seed
    assert len(first["events"]) == 80
    assert projection(sim.evaluate(first)) == accounting_oracle(first)


def test_normalization_and_evaluation_do_not_mutate_caller_data():
    original = scenario()
    snapshot = copy.deepcopy(original)
    normalized = sim.validate_scenario(original)
    normalized["policy"]["agents"][0]["limit"] = 999
    assert original == snapshot
    sim.evaluate(original)
    assert original == snapshot


@pytest.mark.parametrize("amount", [0, -1, True, 1.5, "1", None, 2**53])
def test_invalid_quantities_rejected(amount):
    with pytest.raises(ValueError):
        sim.validate_scenario(scenario(events=[request("bad", amount=amount)]))


@pytest.mark.parametrize("field,value", [
    ("schema", "tip-simulation/v2"), ("seed", True), ("seed", 1.5),
    ("events", "not a list"), ("policy", []), ("id", ""),
])
def test_malformed_top_level_fields_rejected(field, value):
    doc = scenario()
    doc[field] = value
    with pytest.raises(ValueError):
        sim.validate_scenario(doc)


@pytest.mark.parametrize("mutation", [
    lambda s: s["policy"].update(mode="arbitrary"),
    lambda s: s["policy"].update(shared_limit=True),
    lambda s: s["policy"].update(shared_limit=-1),
    lambda s: s["policy"]["agents"].append({"id": "a", "limit": 3}),
    lambda s: s["policy"]["agents"][0].update(limit=True),
    lambda s: s["policy"]["sites"].append("desk"),
    lambda s: s["events"].append({"kind": "counter", "available": "false"}),
    lambda s: s["events"].append({"kind": "unknown_control"}),
])
def test_invalid_policy_and_controls_rejected(mutation):
    doc = scenario()
    mutation(doc)
    with pytest.raises(ValueError):
        sim.validate_scenario(doc)


def test_distinct_mode_cannot_hide_multiple_subjects_in_amount():
    with pytest.raises(ValueError):
        sim.validate_scenario(scenario("distinct", [request("bad", amount=2)]))


def test_exact_shared_boundary_and_refusal_does_not_consume_allowance():
    doc = scenario(events=[request("too-big", amount=11), request("fits", amount=10), request("over")])
    result = sim.evaluate(doc)
    assert projection(result) == [("refused", 0, 0), ("allowed", 0, 10), ("refused", 10, 10)]
    assert result["summary"]["allowed"] == 1
    assert result["summary"]["refused"] == 2


def test_agent_limit_is_separate_from_shared_limit():
    result = sim.evaluate(scenario(agent_limit=6, events=[
        request("one", amount=6), request("two"), request("three", "b", 4)]))
    assert [r["reason"] for r in result["trace"]] == ["accepted", "agent_limit", "accepted"]
    assert result["summary"]["total"] == 10


def test_distinct_people_count_once_globally_but_once_per_agent():
    doc = scenario("distinct", limit=2, agent_limit=1, events=[
        request("one", "a", subject="p1"), request("two", "a", subject="p1"),
        request("three", "b", subject="p1"), request("four", "b", subject="p2")])
    result = sim.evaluate(doc)
    assert projection(result) == [("allowed", 0, 1), ("allowed", 1, 1), ("allowed", 1, 1), ("refused", 1, 1)]
    assert result["trace"][-1]["reason"] == "agent_limit"


@pytest.mark.parametrize("changes,reason", [
    ({"agent": "unregistered"}, "unknown_agent"),
    ({"site": "unregistered"}, "unknown_site"),
    ({"purpose": "marketing"}, "purpose_mismatch"),
])
def test_unknown_authority_or_wrong_purpose_is_a_refusal_not_schema_failure(changes, reason):
    result = sim.evaluate(scenario(events=[request("bad", **changes), request("good")]))
    assert result["trace"][0]["reason"] == reason
    assert projection(result) == [("refused", 0, 0), ("allowed", 0, 1)]


def test_controls_and_retry_order_do_not_create_new_effects():
    first = request("one", amount=2)
    doc = scenario(events=[first, {"kind": "revoke", "agent": "a"}, copy.deepcopy(first),
        request("two"), {"kind": "stop_all"}, request("three", "b"),
        {"kind": "resume"}, request("four", "b"),
        {"kind": "counter", "available": False}, request("five", "b"),
        {"kind": "counter", "available": True}, request("six", "b")])
    result = sim.evaluate(doc)
    assert projection(result) == accounting_oracle(doc)
    assert [r["reason"] for r in result["trace"] if r["kind"] == "request"] == [
        "accepted", "idempotent_retry", "agent_revoked", "stop_all", "accepted", "counter_unavailable", "accepted"]
    assert result["summary"]["total"] == 4
    assert result["summary"]["duplicates"] == 1


def test_request_id_conflict_cannot_change_a_committed_request():
    original = request("one", amount=2)
    result = sim.evaluate(scenario(events=[original, {**original, "amount": 3}, copy.deepcopy(original)]))
    assert [r["reason"] for r in result["trace"]] == ["accepted", "request_id_conflict", "idempotent_retry"]
    assert result["summary"]["total"] == 2


def test_request_ids_are_scoped_to_each_agent():
    result = sim.evaluate(scenario(events=[request("same", "a"), request("same", "b")]))
    assert projection(result) == [("allowed", 0, 1), ("allowed", 1, 2)]


def test_refused_request_id_is_not_reinterpreted_after_resume():
    req = request("blocked")
    result = sim.evaluate(scenario(events=[{"kind": "stop_all"}, req,
        {"kind": "resume"}, copy.deepcopy(req), request("fresh")]))
    assert [r["reason"] for r in result["trace"] if r["kind"] == "request"] == [
        "stop_all", "idempotent_retry", "accepted"]
    assert result["summary"]["total"] == 1


def test_authoritative_event_order_changes_revocation_outcome():
    revoke = {"kind": "revoke", "agent": "a"}
    before = sim.evaluate(scenario(events=[request("one"), revoke]))
    after = sim.evaluate(scenario(events=[revoke, request("one")]))
    assert before["summary"]["total"] == 1
    assert after["summary"]["total"] == 0
    assert after["trace"][-1]["reason"] == "agent_revoked"


@pytest.mark.parametrize("count", [0, -1, True, 1.5])
def test_generator_rejects_invalid_workload_sizes(count):
    with pytest.raises(ValueError):
        sim.generate_scenario("finance", 1, count)


@pytest.fixture
def saved_run(tmp_path):
    path = tmp_path / "runs.sqlite3"
    return path, sim.run_scenario(scenario(), path)


def test_signed_run_verifies_replays_and_round_trips(saved_run):
    path, bundle = saved_run
    digest = sim.bundle_digest(bundle)
    verified = sim.verify_run(bundle, expected_digest=digest)
    replayed = sim.replay_run(bundle)
    assert verified["valid"] is True and verified["errors"] == []
    assert replayed["matches"] is True and replayed["errors"] == []
    assert sim.load_run(path, bundle["run_id"]) == bundle
    assert bundle["run_id"] in {r["run_id"] for r in sim.list_runs(path)}
    assert sim.bundle_digest(json.loads(json.dumps(bundle))) == digest
    assert not sim.verify_run(bundle, expected_digest="0" * len(digest))["valid"]


def test_completed_run_reopens_and_verifies_in_fresh_process(saved_run):
    path, bundle = saved_run
    script = """import json,sys
import simulation as s
b=s.load_run(sys.argv[1],sys.argv[2])
assert s.verify_run(b,expected_digest=sys.argv[3])['valid']
assert s.replay_run(b)['matches']
print(json.dumps({'scenario':b['scenario'],'trace':b['trace'],'summary':b['summary']}))
"""
    proc = subprocess.run([sys.executable, "-c", script, str(path), bundle["run_id"], sim.bundle_digest(bundle)],
                          cwd=Path(__file__).parent, text=True, capture_output=True, check=True, timeout=60)
    assert json.loads(proc.stdout) == {k: bundle[k] for k in ("scenario", "trace", "summary")}


@pytest.mark.parametrize("target", ["receipts", "signed_events"])
@pytest.mark.parametrize("attack", ["drop_first", "drop_last", "reorder", "duplicate"])
def test_missing_reordered_or_duplicated_signed_records_fail(saved_run, target, attack):
    _, bundle = saved_run
    altered = copy.deepcopy(bundle)
    records = altered[target]
    if attack == "drop_first":
        records.pop(0)
    elif attack == "drop_last":
        records.pop()
    elif attack == "reorder":
        records[0], records[1] = records[1], records[0]
    else:
        records[1] = copy.deepcopy(records[0])
    verdict = sim.verify_run(altered)
    assert verdict["valid"] is False
    assert verdict["errors"]


@pytest.mark.parametrize("field", ["scenario", "trace", "summary", "manifest", "checkpoint", "receipts", "signed_events"])
def test_each_evidence_surface_is_bound_to_the_run(saved_run, field):
    _, bundle = saved_run
    changed = copy.deepcopy(bundle)
    if field == "scenario":
        changed[field]["policy"]["shared_limit"] = 100
    elif field == "trace":
        changed[field][0]["total_after"] += 1
    elif field == "summary":
        changed[field]["total"] += 1
    elif field in ("manifest", "checkpoint"):
        changed[field]["body"]["run_id"] = "substituted-run"
    else:
        changed[field][0]["body"]["index"] = 999
    assert not sim.verify_run(changed)["valid"]


def test_concurrent_database_writes_preserve_independent_complete_runs(tmp_path):
    path = tmp_path / "concurrent.sqlite3"
    # Initialise schema before worker races: this test isolates write atomicity.
    sim.list_runs(path)
    def run(i):
        doc = scenario(events=[request("one", amount=i + 1)])
        doc["id"] = f"independent-{i}"
        return sim.run_scenario(doc, path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        bundles = list(pool.map(run, range(4)))
    assert len({b["run_id"] for b in bundles}) == 4
    assert len(sim.list_runs(path)) == 4
    assert sorted(b["summary"]["total"] for b in bundles) == [1, 2, 3, 4]
    for bundle in bundles:
        restored = sim.load_run(path, bundle["run_id"])
        assert restored == bundle
        assert sim.verify_run(restored)["valid"]


def test_signing_failure_does_not_publish_a_partial_completed_run(tmp_path, monkeypatch):
    path = tmp_path / "failure.sqlite3"
    baseline = sim.run_scenario(scenario(), path)
    original = ta.Signer.sign_body
    def fail_at_checkpoint(self, body):
        if body.get("type") == "simulation_checkpoint":
            raise RuntimeError("injected checkpoint signing failure")
        return original(self, body)
    monkeypatch.setattr(ta.Signer, "sign_body", fail_at_checkpoint)
    with pytest.raises(RuntimeError, match="injected checkpoint"):
        sim.run_scenario(scenario(), path)
    assert [r["run_id"] for r in sim.list_runs(path)] == [baseline["run_id"]]
    assert sim.load_run(path, baseline["run_id"]) == baseline


def test_valid_signatures_cannot_turn_a_policy_refusal_into_an_allow(tmp_path, monkeypatch):
    signers = {}
    original_sign = ta.Signer.sign_body
    def retain_test_signer(self, body):
        signers[self.public_key_hex] = self
        return original_sign(self, body)
    monkeypatch.setattr(ta.Signer, "sign_body", retain_test_signer)
    bundle = sim.run_scenario(scenario(), tmp_path / "dishonest-site.sqlite3")
    altered = copy.deepcopy(bundle)
    assert altered["trace"][-1]["reason"] == "shared_limit"
    forged_row = altered["trace"][-1]
    forged_row.update(decision="allowed", reason="accepted", total_after=11, agent_total=5)
    altered["summary"].update(allowed=3, refused=0, total=11)
    site_key = altered["manifest"]["body"]["site_key"]
    site = signers[site_key]
    rb = altered["receipts"][-1]["body"]
    rb["trace"] = copy.deepcopy(forged_row)
    altered["receipts"][-1] = site.sign_body(rb)
    cb = altered["checkpoint"]["body"]
    cb["root"] = ta.merkle_root([ta.record_id(r) for r in altered["receipts"]])
    cb["summary"] = copy.deepcopy(altered["summary"])
    altered["checkpoint"] = site.sign_body(cb)
    # All site signatures and the recomputed root are valid: replay must be the
    # check rejecting the dishonest decision, rather than simple tamper checks.
    for record in altered["receipts"] + [altered["checkpoint"]]:
        assert ta.verify_body(record["body"], record["sig"], site_key)
    verdict = sim.verify_run(altered)
    assert verdict["valid"] is False
    assert any("replay" in e for e in verdict["errors"])
    assert not sim.replay_run(altered)["matches"]


def test_whole_valid_run_substitution_needs_the_independent_digest(saved_run):
    path, original = saved_run
    replacement = sim.run_scenario(scenario(), path)
    assert replacement["run_id"] != original["run_id"]
    assert sim.verify_run(replacement)["valid"]
    assert not sim.verify_run(replacement, expected_digest=sim.bundle_digest(original))["valid"]


@pytest.mark.parametrize("field", ["receipt_index", "event_index", "event_amount",
                                   "trace_amount", "trace_total_before", "summary_total", "checkpoint_size"])
def test_validly_signed_boolean_cannot_replace_integer_evidence(tmp_path, monkeypatch, field):
    signers = {}
    original_sign = ta.Signer.sign_body
    def retain_test_signer(self, body):
        signers[self.public_key_hex] = self
        return original_sign(self, body)
    monkeypatch.setattr(ta.Signer, "sign_body", retain_test_signer)
    bundle = sim.run_scenario(scenario(events=[request("one")]), tmp_path / "strict-types.sqlite3")
    altered = copy.deepcopy(bundle)
    mb = altered["manifest"]["body"]
    site = signers[mb["site_key"]]
    event = altered["signed_events"][0]["body"]
    receipt = altered["receipts"][0]["body"]
    checkpoint = altered["checkpoint"]["body"]
    if field == "receipt_index":
        receipt["index"] = False
    elif field == "event_index":
        event["index"] = False
    elif field == "event_amount":
        event["event"]["amount"] = True
    elif field == "trace_amount":
        altered["trace"][0]["amount"] = True
    elif field == "trace_total_before":
        altered["trace"][0]["total_before"] = False
    elif field == "summary_total":
        altered["summary"]["total"] = True
    else:
        checkpoint["size"] = True
    altered["signed_events"][0] = signers[event["event_key"]].sign_body(event)
    receipt["event_hash"] = ta.record_id(altered["signed_events"][0])
    receipt["trace"] = copy.deepcopy(altered["trace"][0])
    altered["receipts"][0] = site.sign_body(receipt)
    checkpoint["root"] = ta.merkle_root([ta.record_id(altered["receipts"][0])])
    checkpoint["summary"] = copy.deepcopy(altered["summary"])
    altered["checkpoint"] = site.sign_body(checkpoint)
    for record, key in [(altered["signed_events"][0], event["event_key"]),
                        (altered["receipts"][0], mb["site_key"]),
                        (altered["checkpoint"], mb["site_key"])]:
        assert ta.verify_body(record["body"], record["sig"], key)
    assert not sim.verify_run(altered)["valid"]


def test_database_write_failure_rolls_back_completed_run(saved_run, monkeypatch):
    path, baseline = saved_run
    real_connect = sim._connect
    class FailAfterInsert:
        def __init__(self, connection):
            self.connection = connection
        def __enter__(self):
            self.connection.__enter__()
            return self
        def __exit__(self, *args):
            return self.connection.__exit__(*args)
        def execute(self, statement, *args):
            result = self.connection.execute(statement, *args)
            if statement.startswith("INSERT INTO simulation_runs"):
                raise sqlite3.OperationalError("injected failure before commit")
            return result
        def close(self):
            return self.connection.close()
    with monkeypatch.context() as patch:
        patch.setattr(sim, "_connect", lambda p: FailAfterInsert(real_connect(p)))
        with pytest.raises(sqlite3.OperationalError, match="before commit"):
            sim.run_scenario(scenario(), path)
    assert [r["run_id"] for r in sim.list_runs(path)] == [baseline["run_id"]]
    assert sim.load_run(path, baseline["run_id"]) == baseline


def test_changed_stored_bundle_is_detected_on_reopen(saved_run):
    path, bundle = saved_run
    changed = copy.deepcopy(bundle)
    changed["summary"]["total"] += 1
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE simulation_runs SET bundle=? WHERE run_id=?",
                     (json.dumps(changed), bundle["run_id"]))
    with pytest.raises(ValueError, match="digest"):
        sim.load_run(path, bundle["run_id"])
