# Validation of the saved simulation upgrade

Recorded 23 November 2026 (India time). Status: **example verified for local
research review; repository-wide and deployment acceptance remain incomplete**.

All changes are confined to `examples/agentic-provenance/`. The source and
checker files are bound by [SHA-256 hashes](validation/source-sha256.json).
The checkout base was `089fe7cf804dc8ae9da7d68854e9fad4965eaf5e`; the recovered
gateway additions match source from `7ee9556bf85b2e0ca1bd5ef442261a7aac67f20c`.
The hashes identify the revised files tested before committing this upgrade.

## Acceptance evidence

| Check | Result | Evidence and limit |
|---|---|---|
| Complete example suite | PASS: 223 tests | [Output](validation/example-tests.txt); includes the 97 gateway/assurance/conformance tests, 85 simulation tests, 26 HTTP tests and 15 Node simulation checks. No example tests skipped. |
| Fifteen prepared workloads | PASS | Every case ran, saved to SQLite, reopened, matched Python replay and passed the JavaScript evidence checker. Expected totals are listed in [SIMULATION.md](SIMULATION.md). |
| Reviewer-created workload | PASS | Finance seed 1729, 200 events: fresh-process generate, run, verify, replay, export and import succeeded. Saved bundle was approximately 4.5 MB; no real payment was made. |
| Persistence and failures | PASS | Server restart and fresh-process reopen, concurrent independent saves, interrupted SQLite transaction rollback and signing-failure controls are in the suite. A completed run is atomic; there is no resumable live budget shared between experiments. |
| Evidence challenge | PASS | Missing, extra, reordered and edited evidence rejected. A false allowance re-signed with a valid site key and rebuilt checkpoint still fails policy replay. Whole-run replacement is detectable only with an independently retained digest. |
| Input boundary | PASS | Invalid quantities, duplicate JSON fields, excessive nesting, invalid origins/hosts and changed retry payloads rejected. Raw editor text reaches the strict parser before interpretation. |
| Rendered desktop/mobile UI | NOT VERIFIED | Local browser access was unavailable. HTTP lifecycle and JavaScript syntax were checked; responsive CSS alone is not a rendered browser test. |
| Full Node core suite | INCOMPLETE | Attempt exited 134 with JavaScript heap exhaustion. Initial missing native SQLite bindings were repaired. No full-suite pass is claimed. |
| Baseline comparison of 25 failed Node suites | SAME RESULTS | Original and revised checkouts both returned 452 passed, 4 failed, 3 skipped after dependency repair. The four failures are unchanged baseline assertions in two core suites. [Comparison](validation/core-comparison.json). No Node core/shared code or tests changed. |
| Python core suite | BLOCKED | Collection stopped because the separate core implementation requires the unavailable `oqs` module. The example uses real ML-DSA-65 through `cryptography` and its tests ran. |
| Remote CI, deployed TIP receiver, real settlement, legal compliance | NOT ESTABLISHED | Local test results do not certify these boundaries. |

Example command, from the repository root:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q examples/agentic-provenance
```

Environment: Python 3.12.14, cryptography 50.0.0, Node 24.22.3, Linux x86-64.
Node interoperability uses the repository's installed `@noble/post-quantum`
dependency and its actual shared crypto/Merkle implementations. The standalone
Node simulation checker verifies cryptographic consistency; Python replay
checks the policy decisions.

## Scalability measurement

The recovered incremental Merkle implementation has executable tests comparing
roots/proofs against the reference tree and bounding append hash work. The
benchmark was rerun at three log sizes with 20 verified action samples each:

| Prefilled receipts | Signed and verified receipts | Action latency p50 | Action latency p95 |
|---:|---:|---:|---:|
| 1,000 | 1,000 | 8.22 ms | 12.62 ms |
| 10,000 | 10,000 | 6.87 ms | 10.92 ms |
| 100,000 | 100,000 | 7.56 ms | 11.32 ms |

```bash
cd examples/agentic-provenance
python benchmark.py --sizes 1000 10000 100000 --samples 20 --output benchmark.json
```

[Raw measurement](validation/benchmark.json) includes source hashes, machine
details and individual samples. These are synthetic receipt workloads followed
by a small number of gateway actions at each log depth, not 100,000 complete
business transactions. Other tests ran concurrently on the host. There is no
isolated production-capacity claim or new before/after speedup claim.

## Scope review

The useful contribution is an editable, persisted experiment with evidence that
a reviewer can challenge and reproduce across domains. Identity enrolment,
independent human approval, real receiver integration, partition-safe budgets,
durable encrypted retention and deployment-specific legal review remain pending.
The public Vercel explorer is separate and was not redeployed by this PR update.
