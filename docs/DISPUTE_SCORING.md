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
| `JUROR_MAJORITY_BONUS` | **3** | Stage-2 juror majority-vote reward |
| `EXPERT_MAJORITY_BONUS` | **7** | Stage-3 expert majority-vote reward (higher than juror because experts require score ≥850) |
| `MINORITY_PENALTY` | **10** | Juror/expert minority-vote forfeit |
| `NO_SHOW_PENALTY` | **10** | Summoned but didn't reveal |
| `REVIEWER.CORRECT_BONUS` | **5** | Pre-scan reviewer's "case closed cleanly" bonus |

**Author penalty (UPHELD only)** — per-pair escalation `base × [1, 2, 3]`
per spec (TIP_Trust_Scoring §6 Asymmetric Penalty Structure):

| Origin pair | 1st offense | 2nd (2× base) | 3rd+ (3× base) |
|---|---:|---:|---:|
| OH → AG | -100 | -200 | -300 |
| OH → AA | -40 | -80 | -120 |
| AA → AG | -25 | -50 | -75 |
| anything else | 0 | 0 | 0 |

First-offense severity scaling is preserved at repeat offenses — a
repeat AA→AG offender gets the AA→AG ladder, not the (harsher)
OH→AG ladder. `CONSERVATIVE_LABEL` (e.g. AG → OH) and `DISMISSED`
always = 0 penalty.

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
| Stage-3 majority experts | +7 each | |

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
| Stage-3 majority experts | +7 each | |

**Disputer from start of dispute:** -15 -25 +35 +20 = **+15**
**Author from start of dispute:** +5 -100 -5 = **-100**

### Confirm: Stage-2 UPHELD → Stage-3 UPHELD
*Author was the appellant.*

| Party | Δ this batch |
|---|---:|
| Author | **0** (filing-time -25 stays forfeited) |
| Disputer | **0** (Stage-2 settlement stands) |
| Stage-3 majority experts | +7 each |

**Author from start:** -100 -25 = **-125**
**Disputer from start:** -15 +20 = **+5**

### Confirm: Stage-2 DISMISSED → Stage-3 DISMISSED
*Disputer was the appellant.*

| Party | Δ this batch |
|---|---:|
| Disputer | **0** (filing-time -25 stays forfeited) |
| Author | **0** (Stage-2 vindication +5 stands) |
| Stage-3 majority experts | +7 each |

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

When a CONFIRMED prescan-review escalates to a public dispute (either
the creator clicks "Dispute publicly" via `POST /v1/reviews/:id/dispute`
or the h=R+24 auto-escalation fires), the **assigned reviewer is set
as `disputer_tip_id`** on the CONTENT_DISPUTED tx. They are the formal
disputer of the case — their CONFIRM was the dispute claim, so they
own the disputer seat and ride the standard stake-on-file disputer
economics. Same rule as a normal user-filed dispute: `-DISPUTER_STAKE`
is deducted at filing time (paired SCORE_UPDATE alongside CONTENT_DISPUTED),
refunded on UPHELD / CONSERVATIVE_LABEL, forfeited on DISMISSED.

A small `REVIEWER.CORRECT_BONUS` (+5) overlay credits the review work
on top, when the verdict validates the reviewer's CONFIRM.

### Closed-path emissions (no public dispute fired)

| Reviewer action | Outcome | Δ this batch | Reason string |
|---|---|---:|---|
| DISMISS | reviewer says AI was wrong; case closes | **+5** | `review_dismissed:<review_id>` |
| CONFIRM → creator accepts privately | creator agreed with the call | **+5** | `review_accepted_private:<review_id>` |

Paired with the originating tx in the same batch (single-channel rule):
the DISMISS batch is `[PRESCAN_REVIEW_DISMISSED, SCORE_UPDATE]`; the
accept-private batch is `[UPDATE_ORIGIN, SCORE_UPDATE(creator −10),
SCORE_UPDATE(reviewer +5)]`.

### Escalation-time emission (paired with CONTENT_DISPUTED)

When the creator clicks "Dispute publicly" (or auto-escalation fires
at h=R+24), the reviewer's stake is deducted in the same batch as the
dispute tx:

| Stage | Reviewer Δ | Reason string |
|---|---:|---|
| Filing | **−15** | `Dispute filing stake on <ctid>` |

### Verdict-driven emissions (Stage-2)

Standard disputer settlement fires on `disputer_tip_id = reviewer`,
plus a CORRECT_BONUS overlay when the verdict goes the reviewer's way:

| Stage-2 verdict | Disputer settlement (already-existing path) | CORRECT_BONUS overlay | Lifetime net (incl. −15 filing) |
|---|---:|---:|---:|
| UPHELD | **+20** (refund 15 + bonus 5) | **+5** | **+10** |
| CONSERVATIVE_LABEL | **+15** (refund only) | **+5** | **+5** |
| DISMISSED | **0** (stake stays forfeited) | 0 | **−15** |

Reason strings: standard disputer reasons (`Dispute upheld on …`,
`Dispute conservative-label on …`) for the disputer settlement;
`review_correct_bonus:<review_id>` for the overlay.

### Verdict-driven emissions (Stage-3 overturn)

Stage-3 reuses the existing disputer-overturn machinery; my overlay
adds CORRECT_BONUS reversal + re-application:

| Stage-2 → Stage-3 | Disputer reversal | CORRECT_BONUS overlay (reverse + fresh) |
|---|---:|---|
| UPHELD → DISMISSED | **−20** (reverse +20) | reverse Stage-2 +5 = **−5**, no fresh |
| DISMISSED → UPHELD | **+20** (fresh, Stage-2 paid 0) | no reverse, fresh = **+5** |
| UPHELD → UPHELD (confirm) | 0 | 0 |
| DISMISSED → DISMISSED (confirm) | 0 | 0 |

Reason strings for the overlay: `Appeal overturned: Stage 2
review_correct_bonus reversed on <ctid>` (reversal),
`review_correct_bonus_on_appeal:<review_id>` (fresh).

The reviewer (= disputer) also happens to be the appellant when the
losing party of Stage-2 appeals. In that case the standard appellant
economics (filing-time `-APPELLANT_STAKE`, overturn `+25 + 10` bonus)
ride on top — already covered by the disputer / appellant scoring
tests, not duplicated in reviewer-payment tests.

### Verdict-driven emissions (NO_QUORUM → Stage-3 first verdict)

Stage-2 NO_QUORUM paid nothing (disputer stake stayed locked). Stage-3
is the first authoritative verdict, so the standard disputer settlement
fires then for the reviewer, plus CORRECT_BONUS overlay:

| Stage-3 verdict on NO_QUORUM | Disputer settlement | CORRECT_BONUS overlay |
|---|---:|---:|
| UPHELD | **+20** (refund + bonus) | **+5** |
| CONSERVATIVE_LABEL | **+15** (refund only) | **+5** |
| DISMISSED | **0** (stake stays forfeited) | 0 |

CORRECT_BONUS reason: `review_correct_bonus_no_quorum:<review_id>`.

### Reviewer skin-in-the-game summary (lifetime nets)

| Reviewer journey | Cumulative Δ |
|---|---:|
| DISMISS, no later dispute | **+5** |
| CONFIRM → accept-private | **+5** |
| CONFIRM → dispute UPHELD (Stage-2 final) | **+10** |
| CONFIRM → dispute CONSERVATIVE_LABEL (Stage-2 final) | **+5** |
| CONFIRM → dispute DISMISSED (Stage-2 final) | **−15** |
| CONFIRM → Stage-2 UPHELD → Stage-3 overturn DISMISSED | **−15** (filing −15 + Stage-2 +25 + Stage-3 −25) |
| CONFIRM → Stage-2 DISMISSED → Stage-3 overturn UPHELD | **+10** (filing −15 + Stage-3 +25 ; appellant economics separate) |
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

---

## Design decision — no stake from volunteer judgment roles

The TIP_Trust_Scoring spec (§10.3–10.5) describes a staking model for
the reviewer / juror / expert roles (10 / 10 / 15 points held at
acceptance, refunded on a good outcome). **We deliberately do NOT
implement this.** Volunteer judgment roles earn or lose at verdict
time only — no upfront stake, no escrow.

What this means in practice:

| Role | Spec (informational) | Implementation |
|---|---|---|
| Juror | stake 10 at summons | no debit; just `+3` majority / `-10` minority / `-10` no-show at verdict |
| Expert | stake 15 at summons | no debit; same `+3 / -10 / -10` pattern |
| Reviewer (review work) | stake 10 at accept | no debit; `+5 REVIEWER.CORRECT_BONUS` on closed paths only |

The `stake` field on `JURY_SUMMONS.data` and the genesis
`jury_stake: 10` value still exist as informational labels, but no
`SCORE_UPDATE` is emitted off them — they will not be wired up. New
contributors who see those fields should not assume they're enforced.

**Why we kept disputer / appellant stakes.** Filing roles
(disputer −15, appellant −25) DO get debited at filing time — those
stakes exist as anti-spam pressure on dispute submission, which is a
different problem than rewarding volunteer judgment work. When a
reviewer escalates a CONFIRMED review to a public dispute, they
become the formal disputer and the standard −15 disputer stake
applies (reviewer-as-disputer pattern). That is intentional and
remains in place.

The net economics for jurors / experts are equivalent to the spec
in both terminal states (`+3` on win matches "stake refunded + 3
bonus", `-10` on no-show matches "stake forfeited"). Only the
in-flight visibility differs — with our model, the participant's
score is unchanged while voting; with the spec, it would be locked
−10. The simpler model wins.

---

## Spec features we are NOT implementing

The TIP_Trust_Scoring docx describes additional features beyond
what's wired today. The following are explicitly on hold and may
never ship — listed here so future contributors don't try to add
them piecemeal:

| Spec feature | Why on hold |
|---|---|
| Reviewer / juror / expert staking | See "no stake from volunteer judgment roles" above. |
| Milestone bonuses (e.g. +15 / +30 / +50 at 10 / 50 / 200 accurate reviews; Silver / Gold / Diamond badges) | Reward inflation without clear protocol-level purpose. Reputation already accumulates via correct decisions. |
| Stage-3 Expert stake (15) | Same reasoning as juror stake — not enforced; remove from spec. |
| Retroactive DISMISS penalty (reviewer dismisses a case, a later user-filed dispute UPHOLDS mislabeling → −10 to the reviewer) | Requires tracking reviewer history across unrelated disputes. Complexity outweighs the marginal accuracy gain; eligibility gate (overturn rate ≤ 30%) already handles bad reviewers. |
| 90-day clean-record reset (offense_count → 0 after 90 days with no new offenses) | Genesis has `clean_period_bonus: 10` but the offense-reset semantics aren't wired. Considered but deferred until we have telemetry on real offense distributions. |
| Community Verifier scoring (5-point stake per hash-check verification, +1 reward) | **Possibly in scope.** Not built yet; if implemented, would land as a separate `COMMUNITY_VERIFY` flow with its own stake/reward channel. Tracking decision deferred. |

If a future contributor wants to revisit any of these, they should
open a dedicated issue with a concrete motivation (production data,
abuse pattern, or stakeholder ask) — not "the spec says so." The
spec was written before we observed actual usage; the scope we
shipped is the live target.
