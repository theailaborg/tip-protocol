# Saved policy simulations for TIP research

Several agents can each stay within their own allowance while their combined
activity exceeds an approved scope. This example lets a reviewer change that
scope, run synthetic requests, inspect each decision, and reopen the signed
evidence later. It covers healthcare, finance and government, with education
and privacy examples for comparison.

The contribution is a reproducible way to examine the policy and its evidence.
A reviewer can challenge a result with custom inputs and repeat the experiment.
Shared budgets, delegation, signed receipts and erasure have prior work; this
example does not claim to have invented them or established a new TIP protocol.

## Two layers, with different evidence

| Layer | What it exercises | Boundary |
|---|---|---|
| Core example: `tip_agentic.py`, `test_tip_agentic.py`, `test_conformance.py`, `assurance.py` | Signed delegation, local agent registration, synthetic site actions, shared payment budgets, declared lineage, receipt verification and Merkle checkpoints. | Core gateway state remains in memory. See [CONFORMANCE.md](CONFORMANCE.md) for implemented checklist items and limits. |
| Policy harness: `simulation.py`, `simulation_server.py`, `test_simulation.py` | Fifteen prepared scenarios, seeded or custom workloads, ordered controls, signed simulation events and decisions, completed-run storage and replay. | A separate deterministic policy model using the core signing and hashing primitives. Its `simulation_*` records are local research formats, not TIP transaction types or delegation enforcement by a live node. |

Use the current test output and [validation report](VALIDATION.md) for this
revision. Distributed allowances, a retention service, durable encrypted
storage and independent human approvals are not implemented in this checkout.

## Review it locally

Use Python 3.11 or later and the dependencies described in [README.md](README.md).
From the repository root:

```bash
cd examples/agentic-provenance
python -m pip install -r requirements.txt
python simulation_server.py --db review-runs.sqlite3
```

Open `http://127.0.0.1:8766/`. The server listens on loopback and does not contact
external systems. Use synthetic labels, not personal records or credentials.
The local database and exported bundles contain the scenario inputs in plaintext.

1. Load **Three agents, four patients**, then select **Run and save locally**.
2. Use **Next event** to inspect each result. **Play slowly** uses a 3.5-second
   interval; **Extra time** gives six seconds. Playback reads saved decisions
   and does not execute another run. Complete-run totals stay visible separately.
3. Select **Verify saved evidence** and **Replay saved policy**. A policy refusal
   can be valid evidence: verification checks whether the recorded refusal is
   authentic, complete and consistent with the configured policy.
4. Generate a variation with a chosen domain, seed and event count. Inspect its
   JSON, change one allowance or purpose, and run it again. Each run is separate.
5. Stop the server, restart it with the same database path, and reopen the run
   from history. Verify and replay it again.
6. Review at least one finance and one government case, including a refused
   request. The hospital is an introductory example, not the entire scope.

## Command-line reproduction and export

For `simulation.py`, put the global `--db` option **before** the command.
Replace `RUN_ID` below with the `run_id` returned by a run or by `list`.

```bash
python simulation.py presets
python simulation.py --db review-runs.sqlite3 run --preset s-health
python simulation.py generate --domain finance --seed 42 --count 80 > scenario.json
python simulation.py --db review-runs.sqlite3 run --scenario scenario.json
python simulation.py --db review-runs.sqlite3 list
python simulation.py --db review-runs.sqlite3 show RUN_ID > run.json
python simulation.py --db review-runs.sqlite3 verify RUN_ID
python simulation.py --db review-runs.sqlite3 replay RUN_ID
python simulation.py --db imported-runs.sqlite3 import run.json
node verify_simulation.js run.json
```

The exported bundle contains the full scenario, ordered trace, summary, signed
manifest, signed events, receipts and final checkpoint. Preserve it with the
source revision and Python/dependency versions. The manifest records hashes of
`simulation.py`, `tip_agentic.py` and `simulation_presets.json`; verification
requires those files to match. Use the recorded checkout to review older runs.

A seed repeats generated inputs under the recorded generator/runtime. Replay
uses the saved inputs and compares ordered decisions, reasons and totals.
Fresh runs create new keys, identifiers, timestamps and signatures, so their
full bundles need not be byte-identical.

To detect replacement of an entire otherwise valid run, retain its digest
independently from the database and bundle:

```bash
python -c 'import json,simulation; print(simulation.bundle_digest(json.load(open("run.json"))))'
python simulation.py --db review-runs.sqlite3 verify RUN_ID --expected-digest RETAINED_DIGEST
```

Without that independent digest, verification establishes internal consistency
under the bundle's simulation keys. It does not identify a real organisation or
prove an external timestamp. Import verifies evidence and refuses an existing
run ID; it does not silently overwrite that run.

`verify_simulation.js` checks signatures, bindings and log completeness with
TIP's JavaScript primitives as a second implementation. It deliberately does
not repeat the policy model: use Python verification/replay for that check.
Install the repository's Node dependencies with `npm install` at its root.

## Policy and persistence contract

Custom scenarios use `tip-simulation/v1`. Start from an exported preset or a
generated scenario. Policies declare agents and their limits, site labels, one
approved purpose, a shared limit and either `sum` or `distinct` counting.
Amounts are positive integers; distinct counting requires amount `1` and a
subject label. Inputs have bounded sizes, with up to 200 events per run.

In sum mode, accepted amounts accumulate. In distinct mode, each subject counts
once globally and once for each agent accessing it. Unknown agents/sites,
wrong purposes, exhausted allowances and unavailable counters cause refusals.
Purpose is an exact declared string: there is no interpretation of a prompt,
assessment of medical necessity, or detection of inferred sensitive information.

Events are authoritative in their saved order. `revoke`, `stop_all`, `resume`
and `counter` are controls signed by the simulation principal. An exact retry
of an earlier `(agent, request ID)` is a duplicate with no new effect, including
after revocation. A different payload under that pair conflicts. Refused IDs
also remain used; a corrected request needs a new ID.

SQLite stores each completed bundle in one transaction. Reopening restores that
completed evidence, including its accounting trace. Interrupted writes must not
publish a partial run. **Every new run starts its own budget.** This is not a
durable live allowance shared across runs. Multiple site labels use one ordered
coordinator; they do not establish distributed operation or network revocation
latency. There is no external payment or disclosure to roll back.

## Expected results for the fifteen prepared cases

These are synthetic policy outcomes. Case names connect to the accompanying
research examples; the harness does not validate the original incidents or
establish legal thresholds. The cash cases model a review boundary, not an
automatic legal prohibition. Allowed/refused counts exclude control events.

| Preset ID | Example | Shared limit | Final total | Allowed / refused |
|---|---|---:|---:|---:|
| `s-health` | Claims batch | 4 people | 4 people | 5 / 2 |
| `s-money` | Payment agents | ₹50,000 | ₹45,000 | 3 / 2 |
| `s-gov` | Pension checks | 3 people | 3 people | 3 / 3 |
| `yakima` | Patient-record browsing | 25 people | 25 people | 25 / 5 |
| `gulfcoast` | Billing batches | 5,000 records | 4,200 records | 4 / 1 |
| `ctr` | Split cash deposits | ₹10,00,000 | ₹9,90,000 | 20 / 1 |
| `hastert` | Split withdrawals | $10,000 | $9,500 | 1 / 1 |
| `shopping` | Shared shopping budget | $1,000 | $930 | 3 / 2 |
| `welfare` | Departmental reuse | 3 people | 3 people | 4 / 2 |
| `irs` | Tax-record batches | 50,000 records | 47,000 records | 2 / 2 |
| `powerschool` | District support scope | 500 records | 490 records | 3 / 2 |
| `baltimore` | Grade-entry scope | 4 students | 4 students | 4 / 2 |
| `scholarship` | Scholarship checks | 5 students | 5 students | 6 / 1 |
| `fakedegree` | Degree issuer scope | 3 graduates | 3 graduates | 3 / 2 |
| `sumleaks` | Combining labelled pieces | 2 pieces | 2 pieces | 2 / 1 |

Repeated subjects explain why allowed requests can exceed the distinct total.
Education cases use purpose and registration checks; this harness does not
validate real grading deadlines, backdated certificates, second-person approvals,
or ABC/NAD records. The privacy case counts labelled pieces rather than detecting
whether their combination reveals a health condition.

## Requirements and remaining work

The following maps the work to Dinesh ji's requested areas. It identifies useful
evidence for review, not an endorsement or complete conformance assessment.

| Area | Evidence available here | Remaining work or boundary |
|---|---|---|
| Identity | Core signed registration/delegation; harness keys bound to named scenario agents | Real organisational enrolment, deployed TIP identities and independent code attestation |
| Observability | Saved requests, controls, reasons, totals, receipts and full-run verification | Independent observation of external effects; operational monitoring and external anchoring |
| Security and guardrails | Authority and exact-content checks in the core; bounded policy checks and tamper controls in the harness | General prompt-injection defence, semantic data-security guarantees and production threat assessment |
| Convergence | Shared sum/distinct accounting and reproducible variations | Distributed counters, partition-safe allowances and durable live budgets |
| Governance | Core delegation/revocation examples; ordered principal controls in the harness | Production Stop All protocol, independent human approval and network propagation measurement |
| Policies | Explicit purpose, individual/shared scope, counting rules and fail-closed counter simulation | Agreement on fail-open/fail-closed behaviour for each real receiver; policy lifecycle and legal interpretation |
| Provenance | Core declared input/output lineage and runtime commitments; harness source and scenario hashes | Proof of undeclared inputs or actual model execution; full prompt/script retention service |
| Scalability | Incremental Merkle work and benchmark entry points in the core; bounded repeatable harness workloads | Representative production load and distributed performance evidence |
| Post-quantum protection | ML-DSA-65 signatures and SHAKE-256 conventions on signed records | End-to-end deployed transactions, key management, hybrid encryption and recovery |
| Data assurance and retention | Integrity checks and a separate in-memory encrypted-record/key-deletion example | Deployment-specific retention, durable encrypted storage, backups, jurisdictional review and compliance evidence |

The next useful integration decision is a receiver workflow with an agreed
authority, purpose, counting rule and outage policy. Team concurrence is still
needed on its relevance and any overlap with unpublished work.

## Validation entry points

```bash
python -m pytest -q test_simulation.py test_simulation_server.py test_node_simulation.py
python -m pytest -q
```

The full example suite also includes Node interoperability checks requiring the
repository's Node dependencies. Report any excluded check explicitly.

The simulation tests include an independent accounting oracle, exact boundaries,
distinct-subject overlap, retries, revocation order, custom-input rejection,
fresh-process reopen and concurrent independent saves. Negative controls remove,
reorder or alter evidence, inject signing/database failures, and re-sign a false
decision with a rebuilt checkpoint. Verification must reject that decision even
though its signatures are valid. These checks support the stated simulation
contract; they do not establish HIPAA, GDPR or other legal compliance.
