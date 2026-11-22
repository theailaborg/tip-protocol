# TIP Agent Conformance Checklist — executable example

This checklist covers the five requested items below. It uses the record names
supplied for this task, with a local compatibility mapping to the existing
example. It is not a claim of conformance to an independently reviewed whitepaper
schema, nor a complete 27-item implementation. All cases use synthetic data.

Run from the repository root, with the example's Python requirements and the
repository's Node dependencies installed:

```bash
python -m pytest -q examples/agentic-provenance
python -m pytest -q examples/agentic-provenance/test_conformance.py
```

Every checklist item below is backed by named runnable tests in
`test_conformance.py`. Parameterized variants exercise separate cases.

| Item | Contract | Runnable tests |
|---|---|---|
| 7 | Append and root update touch only O(log n) nodes; inclusion proofs preserve TIP's construction. | `test_item7_incremental_roots_and_proofs_match_reference`; `test_item7_append_hash_work_is_logarithmic`; `test_item7_prepared_append_does_not_change_live_log`; `test_item7_existing_node_verifies_incremental_proofs_and_bundle` |
| 15 | Agents share the principal's budget; the crossing action receives a signed refusal Receipt. | `test_item15_three_individually_permitted_agents_exceed_principal_total`; `test_item15_sub_mandate_cannot_raise_or_replace_budget`; `test_item15_omitted_child_budget_inherits_principal_limit`; `test_item15_separate_root_mandates_share_budget_and_cannot_reset_it`; `test_item15_invalid_or_over_limit_spend_cannot_commit`; `test_item15_missing_spend_cannot_bypass_budget`; `test_item15_evidence_outage_does_not_consume_budget`; `test_item15_concurrent_agents_cannot_race_past_total`; `test_item15_spend_cannot_understate_payment_content`; `test_item15_verifier_rejects_site_signed_overspend` |
| 16 | Neither a repeated Mandate nor a signed identity loop can restore authority. | `test_item16_repeated_mandate_link_is_refused`; `test_item16_signed_identity_loop_cannot_recover_authority` |
| 27 | An Action Request references the producer's Receipt and output hash; verification walks all declared ancestors to the same principal. | `test_item27_output_handoff_walks_back_through_agents_to_principal`; `test_item27_missing_or_tampered_ancestor_cannot_verify`; `test_item27_gateway_refuses_unverifiable_handoff`; `test_item27_input_reference_is_covered_by_action_signature`; `test_item27_verification_depth_limit_fails_closed` |
| 2 | Enrolled agents' signed code/model/prompt commitments must match the current Agent Record. | `test_item2_registered_agent_hashes_are_bound_to_action`; `test_item2_changed_runtime_hash_without_reregistration_is_refused`; `test_item2_enrolled_agent_cannot_omit_record_to_bypass_check`; `test_item2_reregistration_allows_new_code_preserves_old_evidence`; `test_item2_forged_registration_and_history_rewrite_are_refused`; `test_item2_registration_is_not_a_substitute_for_mandate_scope`; `test_item2_another_principals_record_cannot_authorise_action` |

## Record vocabulary

| Reviewer term | Local representation | Scope |
|---|---|---|
| Agent Record | `type: agent_record`, `issue_agent_record`, `IdentityDirectory.register_agent` | New signed registration with code, model/version-manifest and prompt-template digests; local trusted history. |
| Mandate | Existing `type: delegation`, `issue_delegation` | Existing API and wire type retained; optional signed `budget` added. |
| Action Request | Existing `type: action`, `make_request` | Optional signed `spend`, `inputs`, `agent_record`, `runtime_hashes`. |
| Receipt | Existing `type: receipt` | Decisions, including refusals; budget decisions include signed counter values. |
| Seal | Existing `type: checkpoint` | This example's site-signed Merkle root and size; no claim that it implements any separate whitepaper Seal format. |
| Approval | Not implemented | Independent human approval remains pending. |
| Stop All | Not implemented in the reference gateway | The separate [policy simulator](SIMULATION.md) has an ordered principal control; it is not a deployed Stop All protocol. Existing Mandate revocation is not presented as one. |

## Implementation boundaries

The Merkle log uses immutable cached subtrees. Appending shares the unchanged
left subtrees and rebuilds at most the right-hand path. Preparing a new root
leaves the live log unchanged until the evidence callback acknowledges it.
Root lookup is O(1), proof extraction O(log n), total live tree storage O(n).
Bulk restoration is O(n). Plain-list `merkle_root`/`merkle_proof` retain their
reference rebuild behavior; using a cached log selects the indexed path.

A root Mandate budget is `{id, unit, total, per_action}`. Integer values use the
JS safe range; amounts are positive integers. Omitted child budgets inherit;
explicit children may only narrow limits, preserving budget ID and unit.
Counters are keyed by `(principal, budget id)`, not by agent or individual
Mandate. Conflicting root definitions under an established ID are refused.
Use a new explicitly authorised budget ID for a distinct budget; this example
does not infer a single lifetime total across all IDs issued by a principal.
The gateway serializes submissions so threads cannot race the check/consume
step. There is no durable or distributed budget ledger.

Budgeted effects are deliberately bounded to creating synthetic payment
records whose exact canonical content is `{amount, unit}` and matches the
signed `spend`. Understating a spend while storing a larger payment is refused.
This does not implement a real payment provider. The independent verifier
checks the signed arithmetic and limits; completeness of all spending history
still requires a trusted final log and persistent accounting.

An `inputs` entry is `{receipt, content_hash}`. The flat `upstream_evidence` map
is keyed by Receipt body hash. Verification checks each ancestor's signatures,
Mandates, registered site key, Seal inclusion, committed output, matching hash
and common principal. Missing evidence is indeterminate and the gateway refuses
to act. Traversal is bounded to depth 16 and 128 Receipt visits. Signatures
prove declared dependencies, not that a model actually used the supplied input.

An Agent Record is signed by the principal and accepted into the local trusted
directory. Once enrolled, that key cannot bypass the check by omitting metadata.
Re-registration moves forward in time, with prior versions retained for
historical verification. Unenrolled agents retain the previous example behavior
for compatibility. Runtime hashes are declarations, not remote measurements;
a compromised agent can lie about its current code. There is no hardware or
process attestation, external enrolment service, or deployed TIP anchoring.

The existing in-memory storage, callback acknowledgement, crash recovery,
revocation completeness and key-deletion limitations still apply. In particular,
a remote acknowledgement and a content-store mutation are not an atomic
transaction. These tests establish no HIPAA or GDPR compliance conclusion.
