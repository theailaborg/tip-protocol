# Design: Issue #112 — Cross-Type Same-Batch State Conflict (AG-7 Follow-Up)

**Date:** 2026-06-17
**Issue:** [#112](https://github.com/theailaborg/tip-protocol/issues/112)
**Parent:** PR #101 / Issue #87 (same-type in-batch dedup)
**Scope:** Targeted A + Targeted B (Option 2 from issue)

---

## Problem

`commitOrderedTxs` validates all txs in Phase 1 before writing any in Phase 2. `_dedupCheck` only guards same-type/same-key duplicates; `_statefulCheck` reads only committed DAG state. Two **different** tx types that both gate on the same shared state each see the pre-batch value, both pass Phase 1, and both commit.

Two conflict families:

### Family A — Content-status conflicts (keyed on `ctid`)

Five tx types whose guards all read committed content status:

| Tx type | Effective state change | Blocked by |
|---|---|---|
| `CONTENT_DISPUTED` | status → DISPUTED | already DISPUTED |
| `CONTENT_VERIFIED` | status → VERIFIED | DISPUTED, RETRACTED, PENDING_REVIEW |
| `CONTENT_RETRACTED` | status → RETRACTED | DISPUTED |
| `UPDATE_ORIGIN` | (no status change, but gates on status) | not REGISTERED/PENDING_REVIEW/PENDING_PRESCAN |
| `PRESCAN_REVIEW_TRIGGERED` | status → PENDING_REVIEW | existing open review |

Any two of these for the same `ctid` in one batch both read the pre-batch status, both pass `canXxx`, and both commit. Proven: `CONTENT_DISPUTED + CONTENT_VERIFIED` → `committed=2`.

### Family B — Revocation freeze (keyed on `tip_id`)

`REVOKE_*` (VOLUNTARY/VP/DECEASED/DEVICE) flips an identity to revoked. ~16 identity-authored tx types guard on `isRevoked(dag)`. A `REVOKE_*` plus any such action for the same `tip_id` in one batch: the revoke commits but so does the action that should have been blocked.

---

## Approach

**Option 2 (chosen):** Shared `_actorTipId` helper for Family B + inline cross-type cases for Family A. All changes in `_dedupCheck` only. No changes to `_statefulCheck`, `_applyDerivedState`, business-rules.js, or schemas.

---

## Implementation

### 1. `_actorTipId(tx)` helper (new, module-level)

Extracts the acting identity's `tip_id` from a tx — the tip_id that `isRevoked` is checked against in that tx's business-rule or schema guard.

```
BIND_DOMAIN, KEY_ROTATED, KEY_RECOVERY, LINK_PLATFORM, UNLINK_PLATFORM,
MEDIA_UPLOAD, MEDIA_ACCESS, REGISTER_DOMAIN, UPDATE_PROFILE  → d.tip_id
REGISTER_CONTENT                                              → d.signer_tip_id
CONTENT_VERIFIED                                             → d.verifier_tip_id
CONTENT_RETRACTED, UPDATE_ORIGIN                             → d.author_tip_id
CONTENT_DISPUTED                                             → d.disputer_tip_id
JURY_VOTE_COMMIT, JURY_VOTE_REVEAL                           → d.juror_tip_id
APPEAL_FILED                                                 → d.appellant_tip_id
PRESCAN_REVIEW_DISMISSED/CONFIRMED/RECUSED                   → null (deferred — reviewer tip_id requires DAG lookup)
all others                                                   → null
```

**Known gap:** `PRESCAN_REVIEW_*` terminal types return `null` because the reviewer tip_id requires a DAG lookup to resolve from the review record. The cross-round guard in `_statefulCheck` still catches the revoke-then-review case across rounds; only the same-batch window remains open for these types. Marked in code as a deferred follow-up.

### 2. Family B pre-switch block in `_dedupCheck`

Added at the top of `_dedupCheck`, before the switch statement:

```js
// Reuses the existing REVOKE_TYPES constant already defined in the switch below.
const actor = _actorTipId(tx);
if (actor) {
  const inBatchRevoke = validated.find(
    t => REVOKE_TYPES.includes(t.tx_type) && t.data?.tip_id === actor
  );
  if (inBatchRevoke) {
    return {
      valid: false,
      error: `revocation freeze: ${tx.tx_type} dropped — ${actor} is being revoked this batch`,
    };
  }
}
```

This fires before the switch, covering all 16 enumerated tx types without touching their individual cases.

### 3. Family A cross-type check in `_dedupCheck`

The existing 5 standalone same-type cases (`CONTENT_DISPUTED`, `CONTENT_VERIFIED`, `CONTENT_RETRACTED`, `UPDATE_ORIGIN`, `PRESCAN_REVIEW_TRIGGERED`) are extended. Each case:

1. Keeps its existing same-type intra-batch check.
2. **Adds:** scan `validated` for any of the other 4 `CONTENT_STATUS_MUTATORS` types for the same `ctid` → drop if found.

```js
const CONTENT_STATUS_MUTATORS = [
  TX_TYPES.CONTENT_DISPUTED,
  TX_TYPES.CONTENT_VERIFIED,
  TX_TYPES.CONTENT_RETRACTED,
  TX_TYPES.UPDATE_ORIGIN,
  TX_TYPES.PRESCAN_REVIEW_TRIGGERED,
];
```

Each case checks:
```js
const siblingMutator = validated.find(t =>
  CONTENT_STATUS_MUTATORS.includes(t.tx_type)
  && t.tx_type !== tx.tx_type  // not same-type (same-type check already above)
  && t.data?.ctid === d.ctid
);
if (siblingMutator) return {
  valid: false,
  error: `content-status conflict in batch: ${siblingMutator.tx_type} already accepted for ${d.ctid}`,
};
```

Note: `CONTENT_VERIFIED`'s same-type dedup is keyed on `(verifier_tip_id, ctid)` — two different verifiers for the same content are both valid. The new cross-type check is keyed on `ctid` alone, which is the correct constraint for status conflicts.

`CONTENT_STATUS_MUTATORS` is defined once at the top of `createCommitHandler` (alongside other shared arrays like `REVOKE_TYPES`).

---

## Test Additions (`scripts/test-inbatch-dedup.js`)

### Family A cases (all via `duelViaRejectionTable`)

| Case name | Pair | Notes |
|---|---|---|
| `dispute-verify` | `CONTENT_DISPUTED` + `CONTENT_VERIFIED` | Proven repro from issue |
| `dispute-retract` | `CONTENT_DISPUTED` + `CONTENT_RETRACTED` | Different actors (disputer vs author) |
| `dispute-update-origin` | `CONTENT_DISPUTED` + `UPDATE_ORIGIN` | Content still in grace window |
| `verify-retract` | `CONTENT_VERIFIED` + `CONTENT_RETRACTED` | Third-party verifier + author retract simultaneously |

`PRESCAN_REVIEW_TRIGGERED` cross-type cases omitted — auto-emitted by node scheduler, not directly callable from the harness.

### Family B case

| Case name | Pair | Notes |
|---|---|---|
| `revoke-linkplatform` | `REVOKE_VP` + `LINK_PLATFORM` same `tip_id` | VP-issued revoke at node-A, LINK_PLATFORM for same identity at node-B simultaneously |

One Family B case proves the freeze path; the helper covers all 16 types uniformly.

### `--case` selector extension

```
dispute-verify | dispute-retract | dispute-update-origin | verify-retract | revoke-linkplatform | all
```

Existing cases (`dispute | verify | update-origin | retract | key-rotate`) unchanged.

### Acceptance signal

Same as existing cases: `IN_BATCH` verdict (rejection row contains "in batch") + state-root convergence across all 5 nodes. `FAILED` verdict (both committed) is the bug signal.

---

## Acceptance Criteria (from issue)

- `CONTENT_DISPUTED(X)` + `CONTENT_VERIFIED(X)` in one batch → exactly one commits, second dropped at `_dedupCheck`.
- Same for every cross-pair among the 5 content-status mutators on one ctid.
- `REVOKE_*(id)` + identity action by `id` in one batch → action dropped with "revocation freeze" error.
- No false positives: cross-type txs for **different** ctids / tip_ids in one batch both commit.
- Live repro: `node scripts/test-inbatch-dedup.js --case dispute-verify` reports `IN_BATCH`.
- State root converges across all 5 nodes after each test case.

---

## Out of Scope

- **General overlay approach** (provisional in-batch state view passed to `_statefulCheck`) — deferred. Closes the whole class definitively but is ~3-5 days. Issue recommends evaluating after A+B ship.
- **`PRESCAN_REVIEW_*` reviewer freeze** — deferred (requires DAG lookup in `_actorTipId`). Risk is lower: reviewer is VP-managed role.
- **Media upload/access revoke freeze** — `MEDIA_UPLOAD` and `MEDIA_ACCESS` are included in `_actorTipId` via `d.tip_id`, so they are covered. No separate test case needed beyond `revoke-linkplatform`.

---

## Files Changed

| File | Change |
|---|---|
| `node/src/consensus/commit-handler.js` | Add `_actorTipId` helper (module-level). Add Family B pre-switch block in `_dedupCheck`. Extend 5 Family A cases with cross-type ctid check. Add `CONTENT_STATUS_MUTATORS` constant. |
| `scripts/test-inbatch-dedup.js` | Add 5 new cases (4 Family A + 1 Family B). Extend `--case` selector. |
