"""Saved, reproducible synthetic policy experiments on TIP signing primitives.

This is an offline research harness, not a deployed TIP node or payment system.
Each completed run is one immutable SQLite row. A run has its own budget; site
labels model one shared coordinator, not independently deployed receivers.
License: TIPCL-1.0 (see ../../LICENSE.txt).
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import tip_agentic as ta

SCHEMA = "tip-simulation/v1"
RUN_SCHEMA = "tip-simulation-run/v1"
GENERATOR = "python-random-v1"
DOMAINS = ("healthcare", "finance", "government", "education", "privacy", "custom")
MAX_EVENTS = 200
MAX_VALUE = 10**12
HERE = Path(__file__).resolve().parent


def _fields(value, names, where):
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValueError(f"{where}: expected exactly these fields: {names}")


def _text(value, where, empty=False):
    if (not isinstance(value, str) or len(value) > 160
            or (not empty and not value.strip())
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ValueError(f"{where}: expected {'optional ' if empty else ''}text, at most 160 characters")


def _integer(value, where, minimum=0, maximum=MAX_VALUE):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{where}: expected integer {minimum}..{maximum}")


def validate_scenario(value):
    """Reject ambiguous inputs before any signing or storage; return a copy."""
    _fields(value, "schema id title domain seed policy events", "scenario")
    if value["schema"] != SCHEMA or value["domain"] not in DOMAINS:
        raise ValueError("unsupported scenario schema or domain")
    for key in ("id", "title"):
        _text(value[key], key)
    if value["seed"] is not None:
        _integer(value["seed"], "seed", maximum=2**32 - 1)
    p = value["policy"]
    _fields(p, "mode unit purpose shared_limit agents sites", "policy")
    if p["mode"] not in ("sum", "distinct"):
        raise ValueError("policy.mode must be sum or distinct")
    for key in ("unit", "purpose"):
        _text(p[key], f"policy.{key}")
    _integer(p["shared_limit"], "shared_limit")
    if not isinstance(p["agents"], list) or not 1 <= len(p["agents"]) <= 20:
        raise ValueError("policy.agents must contain 1..20 agents")
    ids = set()
    for agent in p["agents"]:
        _fields(agent, "id limit", "agent")
        _text(agent["id"], "agent.id")
        _integer(agent["limit"], "agent.limit")
        if agent["id"] in ids:
            raise ValueError("duplicate agent id")
        ids.add(agent["id"])
    sites = p["sites"]
    if not isinstance(sites, list) or not 1 <= len(sites) <= 20:
        raise ValueError("policy.sites must contain 1..20 sites")
    for site in sites:
        _text(site, "site")
    if len(set(sites)) != len(sites):
        raise ValueError("duplicate site id")
    events = value["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise ValueError(f"events must contain 1..{MAX_EVENTS} events")
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"event {i}: expected object")
        kind = event.get("kind")
        if kind == "request":
            _fields(event, "kind id agent site purpose amount subject", f"event {i}")
            for key in ("id", "agent", "site", "purpose"):
                _text(event[key], f"event {i}.{key}")
            _integer(event["amount"], f"event {i}.amount", minimum=1)
            _text(event["subject"], f"event {i}.subject", empty=p["mode"] == "sum")
            if p["mode"] == "distinct" and event["amount"] != 1:
                raise ValueError("distinct mode requires amount=1 and a synthetic subject label")
        elif kind == "revoke":
            _fields(event, "kind agent", f"event {i}")
            _text(event["agent"], "revoked agent")
            if event["agent"] not in ids:
                raise ValueError("revocation must name a registered simulation agent")
        elif kind in ("stop_all", "resume"):
            _fields(event, "kind", f"event {i}")
        elif kind == "counter":
            _fields(event, "kind available", f"event {i}")
            if type(event["available"]) is not bool:
                raise ValueError("counter.available must be a boolean")
        else:
            raise ValueError(f"event {i}: unsupported kind")
    return copy.deepcopy(value)


def presets():
    return [validate_scenario(s) for s in json.loads((HERE / "simulation_presets.json").read_text())]


def generate_scenario(domain, seed, count=25):
    if domain not in DOMAINS:
        raise ValueError("unsupported domain")
    _integer(seed, "seed", maximum=2**32 - 1)
    _integer(count, "count", minimum=1, maximum=MAX_EVENTS)
    rng = random.Random(seed)
    mode = "sum" if domain == "finance" else "distinct"
    purpose = f"synthetic-{domain}-review"
    policy = {"mode": mode, "unit": "minor currency units" if mode == "sum" else "subjects",
              "purpose": purpose, "shared_limit": 100 if mode == "sum" else 8,
              "agents": [{"id": f"agent-{i}", "limit": 70 if mode == "sum" else 5} for i in range(1, 4)],
              "sites": ["site-1", "site-2"]}
    events = []
    for i in range(count):
        choice = rng.randrange(20)
        if choice == 0:
            event = {"kind": "counter", "available": False}
        elif choice == 1:
            event = {"kind": "counter", "available": True}
        elif choice == 2:
            event = {"kind": "stop_all"}
        elif choice == 3:
            event = {"kind": "resume"}
        elif choice == 4:
            event = {"kind": "revoke", "agent": rng.choice(policy["agents"])["id"]}
        else:
            event = {"kind": "request", "id": f"request-{i+1}",
                     "agent": f"agent-{rng.randint(1, 4)}", "site": f"site-{rng.randint(1, 2)}",
                     "purpose": purpose if rng.randrange(5) else "unrelated-purpose",
                     "amount": rng.randint(1, 40) if mode == "sum" else 1,
                     "subject": "" if mode == "sum" else f"subject-{rng.randint(1, 12)}"}
        events.append(event)
    return validate_scenario({"schema": SCHEMA, "id": f"generated-{domain}-{seed}",
                              "title": f"Generated {domain} workload (seed {seed})",
                              "domain": domain, "seed": seed, "policy": policy, "events": events})


def evaluate(scenario):
    """Deterministic ordered policy model. No clocks, keys, I/O or real effects."""
    scenario = validate_scenario(scenario)
    p = scenario["policy"]
    limits = {a["id"]: a["limit"] for a in p["agents"]}
    totals = {a: 0 for a in limits}
    subjects = {a: set() for a in limits}
    shared_subjects, revoked, seen = set(), set(), {}
    stopped, counter, total = False, True, 0
    trace = []
    for index, event in enumerate(scenario["events"]):
        kind, agent = event["kind"], event.get("agent", "")
        row = {"index": index, "kind": kind, "decision": "control", "reason": kind,
               "agent": agent, "site": event.get("site", ""), "request_id": event.get("id", ""),
               "amount": event.get("amount", 0), "subject": event.get("subject", ""),
               "total_before": total, "total_after": total, "agent_total": totals.get(agent, 0)}
        if kind == "stop_all":
            stopped = True
        elif kind == "resume":
            stopped = False
        elif kind == "counter":
            counter = event["available"]
        elif kind == "revoke":
            revoked.add(agent)
        else:
            key = (agent, event["id"])
            content = ta.canonical_json(event)
            reason = None
            if key in seen:
                reason = "idempotent_retry" if seen[key] == content else "request_id_conflict"
            else:
                # Refusals also consume an id; a corrected request needs a new id.
                seen[key] = content
                if agent not in limits:
                    reason = "unknown_agent"
                elif event["site"] not in p["sites"]:
                    reason = "unknown_site"
                elif agent in revoked:
                    reason = "agent_revoked"
                elif stopped:
                    reason = "stop_all"
                elif not counter:
                    reason = "counter_unavailable"
                elif event["purpose"] != p["purpose"]:
                    reason = "purpose_mismatch"
                else:
                    own_delta = event["amount"] if p["mode"] == "sum" else int(event["subject"] not in subjects[agent])
                    shared_delta = event["amount"] if p["mode"] == "sum" else int(event["subject"] not in shared_subjects)
                    if totals[agent] + own_delta > limits[agent]:
                        reason = "agent_limit"
                    elif total + shared_delta > p["shared_limit"]:
                        reason = "shared_limit"
                    else:
                        totals[agent] += own_delta
                        total += shared_delta
                        subjects[agent].add(event["subject"])
                        shared_subjects.add(event["subject"])
            row.update(decision="allowed" if reason is None else ("duplicate" if reason == "idempotent_retry" else "refused"),
                       reason=reason or "accepted", total_after=total, agent_total=totals.get(agent, 0))
        trace.append(row)
    summary = {"allowed": sum(r["decision"] == "allowed" for r in trace),
               "refused": sum(r["decision"] == "refused" for r in trace),
               "duplicates": sum(r["decision"] == "duplicate" for r in trace), "total": total, "unit": p["unit"]}
    return {"trace": trace, "summary": summary}


def code_hashes():
    return {name: ta.content_hash((HERE / name).read_bytes()) for name in
            ("simulation.py", "tip_agentic.py", "simulation_presets.json")}


def bundle_digest(bundle):
    return ta.shake256(ta.canonical_json(bundle))


def _connect(db_path):
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("CREATE TABLE IF NOT EXISTS simulation_runs (run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, title TEXT NOT NULL, domain TEXT NOT NULL, digest TEXT NOT NULL, bundle TEXT NOT NULL)")
    conn.commit()
    return conn


def _save(bundle, db_path):
    raw, digest = ta.canonical_json(bundle), bundle_digest(bundle)
    conn = _connect(db_path)
    try:
        with conn:
            conn.execute("INSERT INTO simulation_runs VALUES (?, ?, ?, ?, ?, ?)",
                         (bundle["run_id"], bundle["created_at"], bundle["scenario"]["title"],
                          bundle["scenario"]["domain"], digest, raw))
    except sqlite3.IntegrityError as exc:
        raise ValueError("run id already exists; stored evidence is never overwritten") from exc
    finally:
        conn.close()


def run_scenario(scenario, db_path):
    scenario = validate_scenario(scenario)
    result = evaluate(scenario)
    run_id = uuid.uuid4().hex
    created = datetime.now(timezone.utc).isoformat()
    principal, site = ta.Signer.generate(), ta.Signer.generate()
    names = {a["id"] for a in scenario["policy"]["agents"]} | {
        e["agent"] for e in scenario["events"] if e["kind"] == "request"}
    agents = {name: ta.Signer.generate() for name in sorted(names)}
    manifest = principal.sign_body({"schema": RUN_SCHEMA, "type": "simulation_manifest",
        "run_id": run_id, "created_at": created, "scenario_hash": bundle_digest(scenario),
        "code_hashes": code_hashes(), "generator": GENERATOR,
        "principal_key": principal.public_key_hex, "site_key": site.public_key_hex,
        "agent_keys": {name: s.public_key_hex for name, s in agents.items()}})
    signed_events, receipts = [], []
    log = ta.IncrementalMerkleLog()
    for index, (event, row) in enumerate(zip(scenario["events"], result["trace"])):
        signer = agents[event["agent"]] if event["kind"] == "request" else principal
        signed = signer.sign_body({"schema": RUN_SCHEMA, "type": "simulation_event", "run_id": run_id,
                                  "index": index, "event": event, "event_key": signer.public_key_hex})
        receipt = site.sign_body({"schema": RUN_SCHEMA, "type": "simulation_receipt", "run_id": run_id,
                                 "index": index, "event_hash": ta.record_id(signed), "trace": row,
                                 "site_key": site.public_key_hex})
        signed_events.append(signed)
        receipts.append(receipt)
        log.append(ta.record_id(receipt))
    checkpoint = site.sign_body({"schema": RUN_SCHEMA, "type": "simulation_checkpoint", "run_id": run_id,
        "manifest_hash": ta.record_id(manifest), "site_key": site.public_key_hex,
        "size": len(log), "root": log.root, "summary": result["summary"]})
    bundle = {"schema": RUN_SCHEMA, "run_id": run_id, "created_at": created, "scenario": scenario,
              **result, "manifest": manifest, "signed_events": signed_events, "receipts": receipts,
              "checkpoint": checkpoint}
    checked = verify_run(bundle)
    if not checked["valid"]:
        raise ValueError("generated evidence failed verification: " + "; ".join(checked["errors"]))
    _save(bundle, db_path)
    return bundle


def verify_run(bundle, expected_digest=None):
    """Check signatures, completeness and policy decisions, not real effects.

    expected_digest is an optional externally retained trust anchor. Without it
    a fully replaced, consistently re-signed run cannot be distinguished from
    a new experiment. Keys in a bundle are simulation keys, not real identities.
    """
    errors = []
    try:
        _fields(bundle, "schema run_id created_at scenario trace summary manifest signed_events receipts checkpoint", "bundle")
        if bundle["schema"] != RUN_SCHEMA:
            raise ValueError("unsupported bundle schema")
        scenario = validate_scenario(bundle["scenario"])
        _text(bundle["run_id"], "run_id")
        _text(bundle["created_at"], "created_at")
        if expected_digest is not None and bundle_digest(bundle) != expected_digest:
            errors.append("bundle differs from independently retained digest")
        manifest = bundle["manifest"]
        mb = manifest["body"]
        if (mb.get("schema") != RUN_SCHEMA or mb.get("type") != "simulation_manifest"
                or mb.get("run_id") != bundle["run_id"] or mb.get("created_at") != bundle["created_at"]
                or mb.get("scenario_hash") != bundle_digest(scenario)
                or mb.get("generator") != GENERATOR
                or not ta.verify_body(mb, manifest["sig"], mb["principal_key"])):
            errors.append("manifest signature or scenario binding invalid")
        if mb.get("code_hashes") != code_hashes():
            errors.append("code version differs; use the recorded source revision to replay")
        n = len(scenario["events"])
        if any(not isinstance(bundle[k], list) or len(bundle[k]) != n for k in ("trace", "signed_events", "receipts")):
            raise ValueError("missing or extra events, receipts or trace rows")
        expected_names = {a["id"] for a in scenario["policy"]["agents"]} | {
            e["agent"] for e in scenario["events"] if e["kind"] == "request"}
        if set(mb["agent_keys"]) != expected_names:
            raise ValueError("agent key catalogue differs from scenario")
        ids = []
        for i, event in enumerate(scenario["events"]):
            signed, receipt = bundle["signed_events"][i], bundle["receipts"][i]
            eb, rb = signed["body"], receipt["body"]
            key = mb["agent_keys"][event["agent"]] if event["kind"] == "request" else mb["principal_key"]
            if (eb.get("schema") != RUN_SCHEMA or eb.get("type") != "simulation_event"
                    or eb.get("run_id") != bundle["run_id"] or type(eb.get("index")) is not int or eb.get("index") != i
                    or ta.canonical_json(eb.get("event")) != ta.canonical_json(event) or eb.get("event_key") != key
                    or not ta.verify_body(eb, signed["sig"], key)):
                errors.append(f"event {i}: signature, order or input binding invalid")
            if (rb.get("schema") != RUN_SCHEMA or rb.get("type") != "simulation_receipt"
                    or rb.get("run_id") != bundle["run_id"] or type(rb.get("index")) is not int or rb.get("index") != i
                    or rb.get("event_hash") != ta.record_id(signed)
                    or ta.canonical_json(rb.get("trace")) != ta.canonical_json(bundle["trace"][i]) or rb.get("site_key") != mb["site_key"]
                    or not ta.verify_body(rb, receipt["sig"], mb["site_key"])):
                errors.append(f"receipt {i}: signature, order or decision binding invalid")
            ids.append(ta.record_id(receipt))
        cp, cb = bundle["checkpoint"], bundle["checkpoint"]["body"]
        if (cb.get("schema") != RUN_SCHEMA or cb.get("type") != "simulation_checkpoint"
                or cb.get("run_id") != bundle["run_id"] or cb.get("manifest_hash") != ta.record_id(manifest)
                or cb.get("site_key") != mb["site_key"] or type(cb.get("size")) is not int or cb.get("size") != n
                or cb.get("root") != ta.merkle_root(ids) or ta.canonical_json(cb.get("summary")) != ta.canonical_json(bundle["summary"])
                or not ta.verify_body(cb, cp["sig"], mb["site_key"])):
            errors.append("final checkpoint signature, completeness or summary invalid")
        expected = evaluate(scenario)
        if ta.canonical_json(expected) != ta.canonical_json({"trace": bundle["trace"], "summary": bundle["summary"]}):
            errors.append("recorded decisions differ from deterministic policy replay")
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError) as exc:
        errors.append(f"invalid evidence: {exc}")
    return {"valid": not errors, "errors": errors,
            "trust": "externally pinned digest" if expected_digest is not None else "self-contained simulation keys; not external identity proof"}


def replay_run(bundle):
    verification = verify_run(bundle)
    return {"matches": verification["valid"], "errors": verification["errors"],
            "comparison": "ordered decisions, reasons and totals; keys, signatures and timestamps are not regenerated"}


def load_run(db_path, run_id):
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT digest, bundle FROM simulation_runs WHERE run_id=?", (run_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise KeyError("run not found")
    bundle = strict_json(row[1])
    if bundle_digest(bundle) != row[0]:
        raise ValueError("stored bundle digest mismatch")
    return bundle


def list_runs(db_path):
    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT run_id, created_at, title, domain, bundle FROM simulation_runs ORDER BY created_at DESC, run_id LIMIT 100").fetchall()
    finally:
        conn.close()
    return [{"run_id": r[0], "created_at": r[1], "title": r[2], "domain": r[3],
             "summary": strict_json(r[4])["summary"]} for r in rows]


def strict_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError(f"duplicate JSON field: {k}")
            result[k] = v
        return result
    def invalid(value):
        raise ValueError(f"non-finite JSON number: {value}")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid or excessively nested JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="simulation-runs.sqlite3", help="local completed-run store")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("presets")
    commands.add_parser("list")
    generate = commands.add_parser("generate")
    generate.add_argument("--domain", choices=DOMAINS, default="healthcare")
    generate.add_argument("--seed", type=int, required=True)
    generate.add_argument("--count", type=int, default=25)
    run = commands.add_parser("run")
    source = run.add_mutually_exclusive_group(required=True)
    source.add_argument("--preset")
    source.add_argument("--scenario", type=Path)
    for command in ("show", "verify", "replay"):
        item = commands.add_parser(command)
        item.add_argument("run_id")
        if command == "verify":
            item.add_argument("--expected-digest")
    imp = commands.add_parser("import")
    imp.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "presets":
            result = [{"id": s["id"], "title": s["title"], "domain": s["domain"]} for s in presets()]
        elif args.command == "generate":
            result = generate_scenario(args.domain, args.seed, args.count)
        elif args.command == "list":
            result = list_runs(args.db)
        elif args.command == "run":
            if args.preset:
                matches = [s for s in presets() if s["id"] == args.preset]
                if not matches:
                    raise ValueError("unknown preset; use 'presets' to list IDs")
                scenario = matches[0]
            else:
                if args.scenario.stat().st_size > 262144:
                    raise ValueError("scenario file exceeds 256 KiB")
                scenario = strict_json(args.scenario.read_text(encoding="utf-8"))
            result = run_scenario(scenario, args.db)
        elif args.command == "import":
            if args.bundle.stat().st_size > 20_000_000:
                raise ValueError("bundle exceeds 20 MB")
            result = strict_json(args.bundle.read_text(encoding="utf-8"))
            checked = verify_run(result)
            if not checked["valid"]:
                raise ValueError("; ".join(checked["errors"]))
            _save(result, args.db)
            result = {"run_id": result["run_id"], "imported": True}
        else:
            result = load_run(args.db, args.run_id)
            if args.command == "verify":
                result = verify_run(result, args.expected_digest)
            elif args.command == "replay":
                result = replay_run(result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if isinstance(result, dict) and (result.get("valid") is False or result.get("matches") is False) else 0
    except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
        parser.exit(2, f"simulation: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
