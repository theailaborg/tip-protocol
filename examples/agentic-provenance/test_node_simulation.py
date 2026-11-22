"""Cross-language checks using actual TIP Node crypto, without network access."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import subprocess

import pytest

import simulation as sim

CHECKER = Path(__file__).with_name("verify_simulation.js")


@pytest.fixture(scope="module")
def signed_bundle(tmp_path_factory):
    return sim.run_scenario(sim.generate_scenario("finance", 23, 8), tmp_path_factory.mktemp("node-simulation") / "runs.sqlite3")


def check(tmp_path, bundle):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
    return subprocess.run(["node", str(CHECKER), str(path)], capture_output=True, text=True, timeout=30, check=False)


def test_node_accepts_python_mldsa_bundle_and_states_crypto_only_scope(tmp_path, signed_bundle):
    result = check(tmp_path, signed_bundle)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VALID: crypto-only cross-language consistency" in result.stdout
    assert "Use Python replay for policy evaluation" in result.stdout
    assert "not external identity proof" in result.stdout


@pytest.mark.parametrize("mutation", ["edited_receipt", "missing_receipt", "extra_receipt", "reordered_receipts", "missing_event", "reordered_events", "edited_trace", "edited_summary", "edited_scenario", "algorithm_downgrade", "wrong_signature", "wrong_checkpoint", "wrong_manifest"])
def test_node_rejects_tampered_or_incomplete_bundle(tmp_path, signed_bundle, mutation):
    bundle = copy.deepcopy(signed_bundle)
    if mutation == "edited_receipt":
        bundle["receipts"][0]["body"]["trace"]["total_after"] += 1
    elif mutation == "missing_receipt":
        bundle["receipts"].pop()
    elif mutation == "extra_receipt":
        bundle["receipts"].append(copy.deepcopy(bundle["receipts"][-1]))
    elif mutation == "reordered_receipts":
        bundle["receipts"][0], bundle["receipts"][1] = bundle["receipts"][1], bundle["receipts"][0]
    elif mutation == "missing_event":
        bundle["signed_events"].pop()
    elif mutation == "reordered_events":
        bundle["signed_events"][0], bundle["signed_events"][1] = bundle["signed_events"][1], bundle["signed_events"][0]
    elif mutation == "edited_trace":
        bundle["trace"][0]["total_after"] += 1
    elif mutation == "edited_summary":
        bundle["summary"]["total"] += 1
    elif mutation == "edited_scenario":
        bundle["scenario"]["policy"]["shared_limit"] += 1
    elif mutation == "algorithm_downgrade":
        bundle["receipts"][0]["body"]["sig_alg"] = "Ed25519"
    elif mutation == "wrong_signature":
        bundle["receipts"][0]["sig"] = "0" * len(bundle["receipts"][0]["sig"])
    elif mutation == "wrong_checkpoint":
        bundle["checkpoint"]["body"]["root"] = "0" * 64
    else:
        bundle["manifest"]["body"]["run_id"] = "another-run"
    result = check(tmp_path, bundle)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "INVALID: crypto-only" in result.stdout


def test_node_rejects_duplicate_fields_and_oversized_local_file(tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text('{"schema":"one","schema":"two"}')
    result = subprocess.run(["node", str(CHECKER), str(path)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 1 and "duplicate JSON field" in result.stderr
    with path.open("wb") as stream:
        stream.truncate(20 * 1024 * 1024 + 1)
    result = subprocess.run(["node", str(CHECKER), str(path)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 2 and "exceeds 20 MiB" in result.stderr
