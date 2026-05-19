# Dispute Flow — Scoring Reference

What every party gets at every step of the dispute lifecycle.
Concrete numbers throughout. All values come from genesis tunables; if
the tables here don't match what you observe on a node, either the
spec changed or the genesis is misconfigured.

---

## Constants (genesis values)

| Name | Value | Purpose |
|---|---:|---|
| `DISPUTER_STAKE` | **15** | Deducted at file-dispute time |
| `UPHELD_BONUS` | **5** | Disputer's Stage-2 win bonus |
| `VINDICATION_BONUS` | **5** | Author's "content cleared" bonus |
| `APPELLANT_STAKE` | **25** | Deducted at file-appeal time |
| `OVERTURN_BONUS` | **10** | Appellant's appeal-win bonus |
| `MAJORITY_BONUS` | **3** | Juror/expert majority-vote reward |
| `MINORITY_PENALTY` | **10** | Juror/expert minority-vote forfeit |
| `NO_SHOW_PENALTY` | **10** | Summoned but didn't reveal |
| `REVIEWER.CORRECT_BONUS` | **5** | Pre-scan reviewer's "case closed cleanly" bonus |

**Author penalty (UPHELD only)** — depends on the origin pair and the
author's prior offense_count:

| Origin pair | 1st offense | 2nd | 3rd+ |
|---|---:|---:|---:|
| OH → AG | -100 | -200 | -350 |
| OH → AA | -40 | -200 | -200 |
| AA → AG | -25 | -200 | -200 |
| anything else | 0 | 0 | 0 |

`CONSERVATIVE_LABEL` (e.g. AG → OH) and `DISMISSED` always = 0
penalty.

---

## File a dispute

| Party | Δ | Why |
|---|---:|---|
| Disputer | **-15** | filing stake (escrow) |
| Author | 0 | innocent until adjudicated |

## File an appeal

| Party | Δ | Why |
|---|---:|---|
| Appellant (whoever lost Stage-2) | **-25** | filing stake (escrow) |
| Other party | 0 | unchanged |

---

## Stage-2 verdict

Author column shows the penalty for **OH→AG, 1st offense**, which is
the default reference penalty (-100). Substitute the right row from
the penalty table above for other origin pairs.

| Stage-2 verdict | Disputer | Author | offense_count |
|---|---:|---:|---:|
| UPHELD | **+20** (refund 15 + bonus 5) | **-100** | 0 → 1 |
| DISMISSED | **0** (filing-time -15 IS the forfeit) | **+5** (vindication) | 0 |
| CONSERVATIVE_LABEL | **+15** (refund only, no bonus) | **0** | 0 |
| NO_QUORUM | **0** (stake locked, settles at Stage-3) | **0** | 0 |

### Jurors (any verdict)

| Reveal | Δ |
|---|---:|
| Voted with majority | **+3** |
| Voted against majority | **-10** |
| Abstained | **0** |
| Tie (3 MATCH = 3 MISMATCH): all revealers | **0** (short-circuit) |
| No-show (summoned, didn't reveal) | **-10** |

---

## Stage-3 verdict — every party, every direction

Stage-2 settlement deltas already landed before Stage-3 fires. The
Stage-3 batch reverses Stage-2's effects on overturn and adds the
appellant's settlement on top.

The numbers below show the **Stage-3 batch alone** (i.e. the deltas
emitted in the appeal-result batch — does not include the -25 the
appellant paid at file-appeal time, or any Stage-2 effects that
already landed). Author penalty assumes OH→AG 1st offense (-100).

### Overturn: Stage-2 UPHELD → Stage-3 DISMISSED
*Author was the appellant.*

| Party | Δ this batch | Why |
|---|---:|---|
| Author | **+35** | Appeal won: refund 25 + overturn bonus 10 |
| Author | **+100** | Stage-2 -100 penalty reversed |
| Author | **+5** | Vindication (Stage-2 wrongly UPHELD; now cleared) |
| Author offense_count | -1 | Stage-2 increment reversed |
| Disputer | **-20** | Stage-2 +20 settlement reversed (un-refund -15, un-bonus -5) |
| Stage-3 majority experts | +3 each | |

**Author from start of dispute:** -100 (Stage-2) -25 (appeal stake) +35 +100 +5 = **+15**
**Disputer from start of dispute:** -15 +20 -20 = **-15**

### Overturn: Stage-2 DISMISSED → Stage-3 UPHELD
*Disputer was the appellant.*

| Party | Δ this batch | Why |
|---|---:|---|
| Disputer | **+35** | Appeal won: refund 25 + overturn bonus 10 |
| Disputer | **+20** | Stage-2 settlement applied now (refund 15 + bonus 5) |
| Author | **-100** | Fresh UPHELD penalty (Stage-3 is the first verdict to penalise) |
| Author | **-5** | Vindication retracted (Stage-2's vindication was wrong) |
| Author offense_count | +1 | Fresh increment |
| Stage-3 majority experts | +3 each | |

**Disputer from start of dispute:** -15 -25 +35 +20 = **+15**
**Author from start of dispute:** +5 -100 -5 = **-100**

### Confirm: Stage-2 UPHELD → Stage-3 UPHELD
*Author was the appellant.*

| Party | Δ this batch |
|---|---:|
| Author | **0** (filing-time -25 stays forfeited) |
| Disputer | **0** (Stage-2 settlement stands) |
| Stage-3 majority experts | +3 each |

**Author from start:** -100 -25 = **-125**
**Disputer from start:** -15 +20 = **+5**

### Confirm: Stage-2 DISMISSED → Stage-3 DISMISSED
*Disputer was the appellant.*

| Party | Δ this batch |
|---|---:|
| Disputer | **0** (filing-time -25 stays forfeited) |
| Author | **0** (Stage-2 vindication +5 stands) |
| Stage-3 majority experts | +3 each |

**Disputer from start:** -15 -25 = **-40**
**Author from start:** **+5** (vindication unchanged)

### Defaulted DISMISSED (Stage-3 ran out of expert reveals)

| Party | Δ |
|---|---:|
| Appellant | 0 (filing-time -25 stays forfeited) |
| Other party | 0 |
| No-show experts | -10 each |

### Stage-3 on Stage-2 NO_QUORUM (auto-escalation)

Stage-2 paid out nothing because no quorum. Stage-3 is the first
authoritative verdict; settlement happens here as if it were Stage-2.
The "appellant" is `SYSTEM_AUTO_ESCALATION` (no real party), so no
appellant settlement event.

| Stage-3 verdict | Disputer | Author | offense_count |
|---|---:|---:|---:|
| UPHELD | **+20** (refund 15 + bonus 5) | **-100** (fresh penalty) | 0 → 1 |
| CONSERVATIVE_LABEL | **+15** (refund only) | **0** | 0 |
| DISMISSED | **0** (stake stays forfeited) | **+5** (vindication) | 0 |

### Experts (any Stage-3 verdict)

Same as Stage-2 jurors: majority +3, minority -10, abstain 0, tie 0
all-revealers, no-show -10.

---

## Pre-scan reviewer

The Phase-5 pre-scan reviewer is treated as the de-facto disputer of
any case that escalates from a CONFIRMED prescan-review. Their CONFIRM
is functionally a stake-on-the-line dispute filing on the system's
behalf, so they ride the disputer's settlement matrix at Stage-2 plus a
fixed `REVIEWER.CORRECT_BONUS` for the review work itself. They never
stake explicitly, so a win pays only the bonus (no refund line).

### Closed-path emissions (no public dispute fired)

| Reviewer action | Outcome | Δ this batch | Reason string |
|---|---|---:|---|
| DISMISS | reviewer says AI was wrong; case closes | **+5** | `review_dismissed:<review_id>` |
| CONFIRM → creator accepts privately | creator agreed with the call | **+5** | `review_accepted_private:<review_id>` |

Paired with the originating tx in the same batch (single-channel rule):
the DISMISS batch is `[PRESCAN_REVIEW_DISMISSED, SCORE_UPDATE]`; the
accept-private batch is `[UPDATE_ORIGIN, SCORE_UPDATE(creator −10),
SCORE_UPDATE(reviewer +5)]`.

### Verdict-driven emissions (Stage-2)

Applies when a dispute reaches Stage-2 verdict and the ctid had a
prior `prescan_reviews` row with state = `escalated_to_dispute`.

| Stage-2 verdict | Reviewer Δ | Composition | Reason string |
|---|---:|---|---|
| UPHELD | **+10** | `UPHELD_BONUS` (5) + `CORRECT_BONUS` (5) | `review_won:<review_id>` |
| CONSERVATIVE_LABEL | **+5** | `CORRECT_BONUS` only | `review_conservative:<review_id>` |
| DISMISSED | **−15** | `−DISPUTER_STAKE` (full overturn cost) | `review_overturned:<review_id>` |

### Verdict-driven emissions (Stage-3 overturn)

If Stage-3 flips the Stage-2 verdict, the appeal batch reverses the
Stage-2 reviewer settlement and applies a fresh Stage-3-based one.
Mirrors the disputer / author reversal pattern.

| Stage-2 → Stage-3 | Reversal Δ | Fresh Δ | Net |
|---|---:|---:|---:|
| UPHELD → DISMISSED | **−10** (reverse +10) | **−15** | **−25** from start |
| DISMISSED → UPHELD | **+15** (reverse −15) | **+10** | **+25** from start |
| UPHELD → UPHELD (confirm) | 0 | 0 | Stage-2 +10 stands |
| DISMISSED → DISMISSED (confirm) | 0 | 0 | Stage-2 −15 stands |

Reason strings for the Stage-3 batch:
`Appeal overturned: Stage 2 reviewer settlement reversed on <ctid>` (reversal)
`review_won_on_appeal:<review_id>` / `review_conservative_on_appeal:<review_id>` / `review_overturned_on_appeal:<review_id>` (fresh).

### Verdict-driven emissions (NO_QUORUM → Stage-3 first verdict)

Stage-2 NO_QUORUM emits no reviewer payment. Stage-3 is the first
authoritative verdict, so the full Stage-2 matrix is applied at
Stage-3 time:

| Stage-3 verdict on NO_QUORUM | Reviewer Δ | Reason string |
|---|---:|---|
| UPHELD | **+10** | `review_won_no_quorum:<review_id>` |
| CONSERVATIVE_LABEL | **+5** | `review_conservative_no_quorum:<review_id>` |
| DISMISSED | **−15** | `review_overturned_no_quorum:<review_id>` |

### Reviewer skin-in-the-game summary

| Reviewer journey | Cumulative Δ |
|---|---:|
| DISMISS, no later dispute | **+5** |
| CONFIRM → accept-private | **+5** |
| CONFIRM → dispute UPHELD (Stage-2 final) | **+10** |
| CONFIRM → dispute CONSERVATIVE_LABEL (Stage-2 final) | **+5** |
| CONFIRM → dispute DISMISSED (Stage-2 final) | **−15** |
| CONFIRM → Stage-2 UPHELD → Stage-3 overturn DISMISSED | **−15** (+10 then −25) |
| CONFIRM → Stage-2 DISMISSED → Stage-3 overturn UPHELD | **+10** (−15 then +25) |
| CONFIRM → Stage-2 NO_QUORUM → Stage-3 UPHELD | **+10** |
| CONFIRM → Stage-2 NO_QUORUM → Stage-3 DISMISSED | **−15** |

### Eligibility gate (separate from rewards)

Across all rewards, the reviewer's running accuracy ratio is tracked.
If overturn rate exceeds `REVIEWER.MAX_OVERTURN_RATE` (0.30) over the
last `ACCURACY_SAMPLE_SIZE` (20) decisions, the runtime selector
silently excludes them from future pools until accuracy recovers. No
revocation tx is needed — eligibility is a pure function of DAG state.

---

## Two bonuses at +5 — they are NOT the same thing

Three bonuses live in the same numeric ballpark but reward different
behaviours:

| Bonus | Triggered by | Goes to | When does it fire? |
|---|---|---|---|
| `UPHELD_BONUS` (+5) | Disputer wins Stage-2 | Disputer | Once, on Stage-2 UPHELD |
| `VINDICATION_BONUS` (+5) | Author's content cleared | Author | Once per resolution: Stage-2 DISMISSED, or Stage-3 overturn UPHELD→DISMISSED. Retracted on later overturn. |
| `OVERTURN_BONUS` (+10) | Appellant won the appeal (anyone) | Appellant | Once, on Stage-3 overturn |
| `REVIEWER.CORRECT_BONUS` (+5) | Pre-scan reviewer's call validated | Reviewer | DISMISS commit; accept-private commit; Stage-2 verdict (added on top of `UPHELD_BONUS` or alone for CONSERVATIVE_LABEL); reversed on Stage-3 overturn. |

`UPHELD_BONUS` and `VINDICATION_BONUS` never fire on the same party
in the same step (one rewards disputers, the other rewards authors).
`OVERTURN_BONUS` and `VINDICATION_BONUS` *can* fire on the same
party in the same step — specifically when the author appeals a
wrongful UPHELD and wins (overlap row 3 of "Overturn: UPHELD →
DISMISSED" above).

---

## Worked summary — five common flows

| Flow | Author net | Disputer net |
|---|---:|---:|
| Stage-2 UPHELD, no appeal (OH→AG, 1st) | **-100** | **+5** |
| Stage-2 DISMISSED, no appeal | **+5** | **-15** |
| Stage-2 UPHELD → author appeals → Stage-3 overturn DISMISSED | **+15** | **-15** |
| Stage-2 DISMISSED → disputer appeals → Stage-3 overturn UPHELD | **-100** | **+15** |
| Stage-2 UPHELD → author appeals → Stage-3 confirm UPHELD | **-125** | **+5** |
| Stage-2 NO_QUORUM → Stage-3 UPHELD | **-100** | **+5** |

---

## Single-channel rule

Every score change emits a `SCORE_UPDATE` tx. The verdict record txs
(`ADJUDICATION_RESULT`, `APPEAL_RESULT`) own only `offense_count` —
they never carry score deltas. Stake debits ride alongside
`CONTENT_DISPUTED` / `APPEAL_FILED` in the filing batch. Settlement
deltas ride alongside the verdict tx in the verdict batch. The score
engine replays deterministically by walking just the `SCORE_UPDATE`
txs filtered by subject, and the live-mirror cache always matches the
replay.
