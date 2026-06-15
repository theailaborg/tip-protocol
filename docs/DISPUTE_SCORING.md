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
| `JUROR_MINORITY_PENALTY` | **8** | Stage-2 juror minority-vote forfeit |
| `EXPERT_MINORITY_PENALTY` | **10** | Stage-3 expert minority-vote forfeit (heavier — expert tier carries the final word) |
| `JUROR_NO_COMMIT_PENALTY` | **1** | Juror summoned but never committed (small signal — didn't engage at all) |
| `JUROR_NO_REVEAL_PENALTY` | **8** | Juror committed but failed to reveal (heavier — engaged then bailed mid-process) |
| `EXPERT_NO_COMMIT_PENALTY` | **1** | Expert summoned but never committed |
| `EXPERT_NO_REVEAL_PENALTY` | **10** | Expert committed but failed to reveal |
| `REVIEWER.CORRECT_BONUS` | **5** | Pre-scan reviewer's "case closed cleanly" bonus |
| `REVIEWER.WRONG_DISMISS_CLAWBACK` | **-5** | Signed delta reclaimed from a reviewer whose DISMISS is later overturned by an UPHELD dispute. Default `-5` exactly cancels `CORRECT_BONUS` (pure clawback, net 0). Stored negative so the call site applies it directly (same convention as `accept_correction_score_delta`). Make it more negative than the bonus to turn it into a real penalty. |

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
| DISMISSED (clear MATCH majority) | **0** (filing-time -15 IS the forfeit) | **+5** (vindication) | 0 |
| CONSERVATIVE_LABEL | **+15** (refund only, no bonus) | **0** | 0 |
| NO_QUORUM | **0** (stake locked, settles at Stage-3) | **0** | 0 |
| Tie (MATCH = MISMATCH) | **0** (stake locked, escalates) | **0** (no vindication) | 0 |

A **tie is not a merits dismissal** — it is a deadlock, so it is treated
exactly like NO_QUORUM: the case auto-escalates to Stage 3 (no appeal stake
required), the disputer's stake stays locked (never forfeited on a tie), and
the author earns no vindication. Only a *clear* MATCH majority is a
substantive DISMISSED that forfeits the disputer and vindicates the author.

### Jurors (any verdict)

| Action | Δ |
|---|---:|
| Voted with majority | **+3** |
| Voted against majority | **-8** |
| Abstained (valid reveal) | **0** |
| Tie (MATCH = MISMATCH): all revealers | **0** (short-circuit) |
| Summoned, never committed | **-1** |
| Committed but missed reveal (or commit-reveal mismatch) | **-8** |

The split between `-1` and `-8` on the no-reveal side reflects intent.
A juror who never commits is just unresponsive — small signal. A juror
who commits and then bails actively hurt the panel: their commitment
was counted toward quorum expectations and other revealers may have
calibrated to it.

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

### No result at Stage 3 (expert tie, or ran out of expert reveals)

Experts are the final layer, so a tie (MATCH = MISMATCH) or a sub-quorum
panel cannot escalate further and is **not** a merits ruling. Nobody is
forfeited: the appellant's appeal stake is **refunded** (the appeal reached
no verdict), Stage-2's settlement stands (a tie does not overturn it), and no
vindication is paid. Forfeit of the appeal stake happens only on a *decisive*
not-overturned result (a clear confirm of Stage 2).

| Party | Δ |
|---|---:|
| Appellant | **+25** (appeal stake refunded — no result) |
| Other party | 0 |
| Experts who never committed | -1 each |
| Experts who committed but missed reveal | -10 each |

### Stage-3 on Stage-2 NO_QUORUM (auto-escalation)

Stage-2 paid out nothing because no quorum. Stage-3 is the first
authoritative verdict; settlement happens here as if it were Stage-2.
The "appellant" is `SYSTEM_AUTO_ESCALATION` (no real party), so no
appellant settlement event.

| Stage-3 verdict | Disputer | Author | offense_count |
|---|---:|---:|---:|
| UPHELD | **+20** (refund 15 + bonus 5) | **-100** (fresh penalty) | 0 → 1 |
| CONSERVATIVE_LABEL | **+15** (refund only) | **0** | 0 |
| DISMISSED (panel reached quorum, ruled on merits) | **0** (stake forfeited) | **+5** (vindication) | 0 |
| No result terminal (Stage-3 tie, Stage-3 sub-quorum, or no expert panel could be formed) | **+15** (refund, no bonus) | **0** (no vindication) | 0 |

**Refund on a terminal no-result.** A disputer forfeits their stake only
when a panel actually reaches quorum and rules the dispute groundless (a
real DISMISSED). When the case dies because the *system* could not
decide it — Stage-2 jury deadlocked/failed quorum AND Stage-3 experts
also deadlocked/failed quorum, or no eligible expert panel could be
formed at all — the disputer is refunded their 15: the failure was the
absent or split jurors'/experts', not theirs. The author gets no
vindication bonus in this terminal case, because nobody actually cleared
them. The content keeps its declared label (benefit of the doubt) but no party is
penalized except the no-show jurors/experts who broke quorum.

> Liveness dependency: the terminal-NO_QUORUM refund requires the appeal
> stage to always resolve. Today a Stage-2 NO_QUORUM that cannot form an
> expert panel escalates into a hang (no expert summons means no appeal
> deadline ever fires). That hang is fixed separately; the refund lands
> in both terminal paths once it does.

### Experts (any Stage-3 verdict)

Same shape as Stage-2 jurors but with heavier values across the board
(reflecting the final-word weight of Stage 3):

| Action | Δ |
|---|---:|
| Voted with majority | **+7** |
| Voted against majority | **-10** |
| Abstained (valid reveal) | **0** |
| Tie: all revealers | **0** (short-circuit) |
| Summoned, never committed | **-1** |
| Committed but missed reveal | **-10** |

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

### Wrong-DISMISS clawback (accountable dismiss)

The DISMISS `+5` is paid at dismiss time but is accountable. A DISMISS is
a non-action (the reviewer accuses no one), unlike CONFIRM which is an
accusation that carries the full disputer-stake risk, so a wrong DISMISS
is not punished like a wrong accusation. Instead the bonus is reclaimed.

When a public dispute is later filed on the same content by a separate
disputer and Stage-2 rules **UPHELD** (the AI flag the reviewer dismissed
was correct after all), the settlement reclaims the bonus via
`REVIEWER.WRONG_DISMISS_CLAWBACK` (signed `-5`): the dismissing reviewer
nets 0. The dismissing reviewer is a third settlement actor, distinct from
the disputer and the author; the clawback is found by looking up the
DISMISSED prescan_review for the ctid and emitting the delta for its
`assigned_reviewer`.

The clawback rides the full appeal chain exactly like the CONFIRM bonus:

| Stage | Event | Reviewer Δ | Reviewer net |
|---|---|---:|---:|
| 1 | DISMISS | +5 | +5 |
| 2 | dispute UPHELD (dismiss was wrong) | -5 (clawback) | 0 |
| 3 | expert OVERTURNS to DISMISSED (dismiss was right) | +5 (reverse) | +5 |
| 3 | expert CONFIRMS Stage-2 UPHELD | 0 | 0 |

Only one of {CONFIRM-bonus path, DISMISS-clawback path} applies per ctid:
a content cannot have both a CONFIRMED-escalated review and a DISMISSED
review driving the same dispute.

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
| DISMISSED (quorum reached, ruled on merits) | **0** (stake forfeited) | 0 |
| NO_QUORUM terminal (Stage-3 also failed quorum / no panel formable) | **+15** (refund, no bonus) | 0 |

CORRECT_BONUS reason: `review_correct_bonus_no_quorum:<review_id>`. The
terminal-NO_QUORUM refund applies to the reviewer-as-disputer exactly as
it does to any disputer: forfeit only on a real DISMISSED, refund when no
panel ever ruled.

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
| Juror | stake 10 at summons | no debit; `+3` majority / `-8` minority / `-1` no-commit / `-8` no-reveal at verdict |
| Expert | stake 15 at summons | no debit; `+7` majority / `-10` minority / `-1` no-commit / `-10` no-reveal at verdict |
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

The net economics retain the same shape as the spec at terminal
states (`+3` / `+7` on win matches "stake refunded + bonus"), but
penalties now split two ways: by role (juror `-8` vs expert `-10`
minority) and by engagement (`-1` for never committing, `-8` / `-10`
for committing-then-bailing). The asymmetry is deliberate — a juror
who never opened the case is just unresponsive (small signal); one
who committed and walked away mid-process took up a slot and
disrupted the panel's quorum math. Only the in-flight visibility
differs from the spec — with our model the participant's score is
unchanged while voting; with the spec, it would be locked.

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
