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

## Two bonuses at +5 — they are NOT the same thing

Three bonuses live in the same numeric ballpark but reward different
behaviours:

| Bonus | Triggered by | Goes to | When does it fire? |
|---|---|---|---|
| `UPHELD_BONUS` (+5) | Disputer wins Stage-2 | Disputer | Once, on Stage-2 UPHELD |
| `VINDICATION_BONUS` (+5) | Author's content cleared | Author | Once per resolution: Stage-2 DISMISSED, or Stage-3 overturn UPHELD→DISMISSED. Retracted on later overturn. |
| `OVERTURN_BONUS` (+10) | Appellant won the appeal (anyone) | Appellant | Once, on Stage-3 overturn |

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
