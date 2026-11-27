"""Local synthetic benchmark of the existing demo; no network or real records.

Bulk sign/verify rates are receipt operations, NOT gateway transactions/sec.
Action latency samples use the real gateway at each prefilled log depth, with
request signing, submission and independent evidence verification included.
This avoids pretending that 100,000 full gateway actions were executed.
License: TIPCL-1.0 (see ../../LICENSE.txt).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
import tip_agentic as ta

NOW = 1_800_000_000_000
RESOURCE = "https://synthetic.example/records/0001"
PAYLOAD = b"synthetic-record:" + b"x" * 239  # 256 bytes, no personal data


def percentile(values, p):
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)]


def encoded_size(value):
    return len(ta.canonical_json(value).encode("utf-8"))


def world():
    principal, agent, site = (ta.Signer.generate() for _ in range(3))
    directory = ta.IdentityDirectory()
    pid, sid = (ta.tip_id("IN", s.public_key_hex) for s in (principal, site))
    directory.register(pid, principal.public_key_hex)
    directory.register(sid, site.public_key_hex)
    delegation = ta.issue_delegation(principal, pid, agent.public_key_hex,
                                   ta.make_scope(["edit"], [RESOURCE]), NOW - 1, NOW + 1)
    gateway = ta.SiteGateway(site, sid, directory, lambda: NOW)
    gateway.store[RESOURCE] = PAYLOAD
    return agent, site, delegation, gateway, directory


def measure(n, samples):
    agent, site, delegation, gateway, directory = world()
    chain = [ta.record_id(delegation)]
    req = ta.make_request(agent, chain, "edit", RESOURCE, NOW, PAYLOAD, PAYLOAD)
    template = gateway.submit(req, [delegation], content=PAYLOAD)["receipt"]["body"]
    ids, sign_ns, verify_ns, receipt_bytes = [], 0, 0, 0
    # Every receipt is uniquely signed and verified, with the same realistic
    # schema/field lengths as a gateway receipt. These are synthetic log entries.
    for i in range(n):
        body = {**template, "log_index": i, "request": ta.shake256(f"synthetic-request-{i}")}
        start = time.perf_counter_ns()
        receipt = site.sign_body(body)
        sign_ns += time.perf_counter_ns() - start
        start = time.perf_counter_ns()
        ok = ta.verify_body(receipt["body"], receipt["sig"], site.public_key_hex)
        verify_ns += time.perf_counter_ns() - start
        if not ok:
            raise RuntimeError("receipt verification failed")
        ids.append(ta.record_id(receipt))
        receipt_bytes += encoded_size(receipt) + 1  # canonical JSONL encoding
    root = ta.merkle_root(ids)
    checkpoint = site.sign_body({"schema": ta.SCHEMA, "type": "checkpoint",
        "site": gateway.site_identity, "site_key": site.public_key_hex,
        "size": n, "root": root, "at": NOW})
    start = time.perf_counter_ns()
    proof = ta.merkle_proof(ids, n // 2)
    proof_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns()
    ok = ta.verify_merkle_proof(ids[n // 2], proof, root)
    verify_proof_ns = time.perf_counter_ns() - start
    if not ok:
        raise RuntimeError("inclusion proof failed")
    gateway.log = ids.copy()
    baseline, latencies, action_bytes = [], [], []
    for _ in range(samples):
        start = time.perf_counter_ns()
        gateway.store[RESOURCE] = PAYLOAD
        baseline.append(time.perf_counter_ns() - start)
    baseline_ns = statistics.median(baseline)
    for _ in range(samples):
        start = time.perf_counter_ns()
        req = ta.make_request(agent, chain, "edit", RESOURCE, NOW, PAYLOAD, PAYLOAD)
        outcome = gateway.submit(req, [delegation], content=PAYLOAD)
        bundle = ta.evidence_bundle(req, outcome, [delegation])
        verdict = ta.verify_evidence(bundle, directory, content=PAYLOAD)
        elapsed = time.perf_counter_ns() - start
        if verdict.status != ta.VALID or outcome["receipt"]["body"]["decision"] != "committed":
            raise RuntimeError("action failed verification")
        latencies.append(max(0, elapsed - baseline_ns) / 1e6)
        action_bytes.append(encoded_size(bundle))
    return {"receipts": n, "signed": n, "verified": n,
        "signing_receipts_per_second": n / (sign_ns / 1e9),
        "verification_receipts_per_second": n / (verify_ns / 1e9),
        "signing_seconds": sign_ns / 1e9, "verification_seconds": verify_ns / 1e9,
        "action_samples": samples, "action_log_depth_min": n + 1,
        "action_log_depth_max": n + samples,
        "added_latency_p50_ms": percentile(latencies, .50),
        "added_latency_p95_ms": percentile(latencies, .95),
        "baseline_median_ns": baseline_ns,
        "evidence_bytes_per_action_mean": statistics.mean(action_bytes),
        "receipt_bytes_mean": receipt_bytes / n,
        "receipt_archive_jsonl_bytes": receipt_bytes,
        "hash_log_json_bytes": encoded_size(ids),
        "hash_log_plus_checkpoint_bytes": encoded_size(ids) + encoded_size(checkpoint),
        "proof_generation_ms": proof_ns / 1e6, "proof_verification_ms": verify_proof_ns / 1e6,
        "proof_siblings": len(proof), "proof_bytes": encoded_size(proof),
        "action_latency_samples_ms": latencies}


def machine():
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), platform.processor())
    def read_optional(path):
        p = Path(path)
        return p.read_text().strip() if p.exists() else None
    return {"platform": platform.platform(), "cpu": cpu, "logical_cpus": os.cpu_count(),
        "cpu_affinity_count": len(os.sched_getaffinity(0)),
        "cgroup_cpu_max": read_optional("/sys/fs/cgroup/cpu.max"),
        "cgroup_memory_max": read_optional("/sys/fs/cgroup/memory.max"),
        "mem_total": next(l for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemTotal")),
        "python": platform.python_version(), "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(), "workers": 1,
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "script_sha256": __import__("hashlib").sha256(Path(__file__).read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[1000, 10000, 100000])
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.sizes) < 1 or args.samples < 2:
        parser.error("positive sizes and at least two samples required")
    result = {"machine": machine(), "method": __doc__, "results": [], "skipped": []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for n in args.sizes:
        print(f"Measuring {n} receipts", flush=True)
        row = measure(n, args.samples)
        result["results"].append(row)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({k: v for k, v in row.items() if k != "action_latency_samples_ms"}), flush=True)


if __name__ == "__main__":
    main()
