# Expert Journey

You're an **Expert**. A jury already ruled on a public dispute, and one side appealed. You're one of **3 experts** picked to settle it. Whatever your panel decides is **final** — no further appeal.

This is Stage 3, the highest-trust adjudication tier on TIP.

---

## Am I eligible?

You qualify if **all** are true:

| Requirement | Why |
|---|---|
| Your trust score is **850 or higher** | Experts hold the final word. Need the strongest track record. |
| You're a **personal identity** | Orgs never adjudicate |
| You turned ON **"I want to help adjudicate"** in your profile | Opt-in only |
| You weren't on the original Stage 2 jury | The same person can't judge the same case twice — system filters automatically |
| You're not the creator, the disputer, or the appellant | Conflict-of-interest filter |

You can turn the toggle off any time. You stop being picked, immediately.

---

## When does an appeal happen?

```
Stage 2 jury voted, verdict landed (e.g. UPHELD or DISMISSED)
                       ↓
   The losing party has 48 hours to file an appeal
                       ↓
              ┌────────┴────────┐
              ↓                 ↓
       No one appeals      Someone files
              ↓             APPEAL_FILED
       Verdict final            ↓
       Done                     ↓
                       3 Experts get picked
                                ↓
                       That's YOU — APPEAL_FILED notification lands
```

Appeals cost the appellant 25 points (filing stake). If they win the appeal, they get the 25 back + a +10 overturn bonus, AND the chain reverses the entire Stage-2 settlement that hit them. If they lose, the 25 stays forfeited and the Stage-2 outcome stands.

So appeals only get filed when someone genuinely believes the jury was wrong (the stake punishes frivolous appeals).

---

## What you see when you open the case

```
┌──────────────────────────────────────────────────────────┐
│  EXPERT PANEL — Appeal on Dispute #ds_7b3f…              │
│                                                          │
│  Content        →  [Title + body + media]                │
│  Creator        →  tip://id/IN-... (TIP ID only)         │
│  Disputer       →  tip://id/US-...                       │
│  Appellant      →  tip://id/IN-... (could be creator or  │
│                    disputer — whoever lost Stage 2)      │
│                                                          │
│  Stage 2 Verdict:  UPHELD (4 of 7 jurors said MISMATCH)  │
│  Stage 2 Origin:   relabeled to AG                       │
│                                                          │
│  Why appealed:                                           │
│  [Appellant's argument shown — text/evidence hash]       │
│                                                          │
│  Stage 2 Vote Breakdown:                                 │
│      MATCH      ×× 2 jurors                              │
│      MISMATCH   ×× 4 jurors (AG = 3, AA = 1)             │
│      ABSTAIN    ×× 1 juror                               │
│                                                          │
│  Your vote:                                              │
│     [ UPHOLD VERDICT ]   → "Stage 2 jury was right"      │
│     [ OVERTURN ]         → "Stage 2 jury was wrong"      │
│     [ ABSTAIN ]                                          │
│                                                          │
│  Phase: COMMIT — 71h 02m left                            │
└──────────────────────────────────────────────────────────┘
```

You see the full Stage-2 vote breakdown, the appellant's argument, and the original content. You're not redoing the jury's work from scratch — you're reviewing whether the jury made the right call given the evidence.

---

## Your three options

### UPHOLD VERDICT — "Stage 2 jury was right"

The jury looked at the same evidence and got it right. You agree with their verdict (whether it was UPHELD or DISMISSED).

In the app this shows as **MATCH** under the hood — same vote type the jurors used, applied at the expert tier. You're saying "the creator's original label matches what the content actually is" (or, mechanically, "the Stage-2 verdict on that question stands").

```
If majority of non-abstain experts vote UPHOLD VERDICT:
       ↓
   Stage 2 outcome stands — content origin + author penalty + disputer stake all stay
   Appellant's 25-point filing stake stays forfeited
   No further changes to anyone else's score
```

### OVERTURN — "Stage 2 jury was wrong"

You believe the jury got it wrong. In the app this is the **MISMATCH** vote — same machinery as Stage 2 — and if Stage 2 said UPHELD you're flipping to "creator was right after all", if Stage 2 said DISMISSED you're flipping to "actually creator was wrong". Pick the new origin label when prompted (same as a Stage-2 MISMATCH).

```
If majority of non-abstain experts vote OVERTURN:
       ↓
   Stage 2 outcome FULLY reverses (not partial).
   Appellant wins:
       - 25-point filing stake refunded
       - +10 overturn bonus
       - The Stage-2 settlement that hit them is reversed end-to-end:
           creator: full Stage-2 penalty reversed + vindication bonus
           disputer: full Stage-2 refund + upheld bonus reversed
           reviewer (if the case came from a CONFIRMED prescan-review):
              CORRECT_BONUS overlay reversed/re-applied to match the new verdict
   Original Stage-2 jurors:
       - The chain does NOT retroactively re-score Stage-2 jurors.
         Their majority-bonus or minority-penalty from Stage 2 stays put.
         (Only the case-level settlement reverses — juror scores are sticky.)
```

This is heavy. An overturn moves real points across the federation. **Don't overturn lightly.**

### ABSTAIN — "I genuinely can't tell"

You looked at everything and you don't have enough basis to overturn the jury OR uphold it confidently.

```
Effect on you:
       ↓
   Score delta: 0 — no bonus, no penalty
   Your vote doesn't count toward the panel majority.
   Expert panels need at least 2 non-abstain reveals to produce a verdict.
   If fewer than 2 experts make a valid (non-abstain) reveal → the appeal
   defaults to DISMISSED (Stage 2 stands). Rare at this tier — pool of 850+
   experts is small but reliable.
```

---

## What's at stake

Nothing is held in escrow at summons time — your score only moves once the appeal verdict batch lands. The deltas are similar to a regular juror, but the majority bonus is higher at Stage 3 because expert participation is reserved for higher-trust holders (≥850) making the harder calls:

- **Vote with the majority + reveal on time** → **+7** trust score
- **Vote against the majority + reveal on time** → **-10** trust score
- **ABSTAIN + reveal on time** → **0**
- **Miss the reveal phase** → **-10** (no-show)

The big stake on the table at Stage 3 is the **appellant's 25 + the original Stage-2 settlement** — that's what your three-person vote moves around. Your own personal delta is small; the impact of your vote on others is enormous. Treat the latter as the part that matters.

---

## Why two phases? (Commit + Reveal)

Same as Jury — but the stakes are higher.

**Phase 1 (commit, 72h):** Vote in private. App scrambles your vote with a salt and submits the hash. Nobody can see your vote yet, including you.

**Phase 2 (reveal, 12h):** Submit the actual vote + salt. Chain verifies the reveal matches the earlier commit. Everyone's vote is now public.

Prevents bandwagoning. Each expert votes blind.

---

## The full journey, hour by hour

```
HOUR 0:
   APPEAL_FILED tx commits on chain.
   System runs deterministic selection — 3 experts picked.
   You're one. Push notification lands.
   Your score doesn't move yet — settlement happens at hour 78.

HOURS 0 – 72:
   COMMIT PHASE.
        ↓
   Open the case. Re-read the content. Read the appellant's argument.
   Look at the Stage-2 vote split. Look at the AI prescan result.
        ↓
   Make your own honest call: UPHOLD or OVERTURN or ABSTAIN.
        ↓
   App computes commitment = hash(vote + secret salt).
   You sign + submit the commitment. Nobody knows your vote yet.

HOUR 72:
   COMMIT phase ends. REVEAL phase opens.

HOURS 72 – 78:
   REVEAL PHASE.
        ↓
   Open the case. Tap "Reveal my vote."
        ↓
   App sends your real vote + salt. Chain hashes it and verifies match
   with your earlier commit.
        ↓
   Your vote is now public on-chain.

HOUR 84:
   Reveal phase ends. Verdict computed automatically.
        ↓
   Need at least 2 non-abstain reveals (MIN_VOTES = 2). Otherwise
   the appeal defaults to DISMISSED — Stage 2 verdict stands.
        ↓
   - Majority of non-abstain says UPHOLD VERDICT → APPEAL_RESULT: Stage 2 stands.
                                                   Appellant's 25 stays forfeited.
   - Majority of non-abstain says OVERTURN      → APPEAL_RESULT: Stage 2 reversed.
                                                   Appellant gets +25 +10 bonus.
                                                   Full Stage-2 settlement reversed (creator + disputer + reviewer).
   - Fewer than 2 non-abstain reveals           → Defaults to DISMISSED. Stage 2 stands.

HOUR 84+:
   - You voted with majority + revealed → +7
   - You voted minority + revealed       → -10
   - You ABSTAINED + revealed            → 0
   - Missed reveal                       → -10 (no-show)
   - Verdict is FINAL. No further appeal.
```

---

## What if you miss a step

Same constants as Juror — there's no special expert escrow.

| What you missed | Consequence |
|---|---|
| Didn't commit at all (no submission in 72h) | Counted as a no-show. **-10 trust score** (unless the panel falls under MIN_VOTES = 2 non-abstain, in which case the appeal defaults to DISMISSED but no-shows still take the hit — same as Stage 2 quorum logic). |
| Committed but missed reveal | Treated the same as no-commit. **-10 trust score.** The chain can't see what's inside a sealed commit. |
| Committed + revealed but salts don't match | Same as miss: **-10**. App handles this correctly so it won't happen if you use the app. |

**If you can't reveal, don't commit.** The downside on a missed reveal is the same -10 as voting minority — and you didn't even get credit for trying.

---

## Stake math summary

(Your personal score delta. The case-level settlement — what your vote does to the appellant + creator + disputer — is on a different scale entirely.)

| Your action | Effect |
|---|---|
| Commit + reveal + vote with majority | **+3** |
| Commit + reveal + vote with minority | **-10** |
| Commit + reveal + ABSTAIN | **0 — neutral** |
| Commit + miss reveal | **-10 (no-show)** |
| Didn't commit at all | **-10 (no-show)** |

---

## Recognition: your Expert badge

Every appeal reveal you submit lands on chain as a `JURY_VOTE_REVEAL` tx with `is_appeal: true` attributed to you. The UI counts them off your activity feed and shows an **Expert badge** on your profile — e.g. *"Served 4 times as Expert"* — alongside your trust-tier badge. Because Stage 3 is rare (only triggers on appeal), the count grows slowly; that's by design — the badge signals depth of service, not volume.

Same data source as Juror, just filtered by `is_appeal === true`. Nothing extra stored on chain.

---

## Notifications you'll see

Your dashboard feed surfaces these expert-facing notification types — mirror of the juror set, with `expert_` prefix and 3-person panel context:

```
┌────────────────────────────────────────────────────────────────┐
│  PHASE 1 — Commit                                              │
│  type:     expert_commit_required                              │
│  priority: urgent (≤ 12h left) │ high otherwise                │
│  Title:    "Commit your expert vote ({remaining} left)"        │
│  Summary:  "Dispute on {ctid} is in commit phase."             │
│  Action:   [ Commit vote ] →                                   │
│            /disputes/{disputeId}/appeal/commit                 │
│  Deadline: summons.commit_deadline (72h after appeal summons)  │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  PHASE 1.5 — Committed, reveal window not yet open             │
│  type:     expert_awaiting_reveal_window                       │
│  priority: info                                                │
│  Title:    "Expert vote committed — reveal opens in {remaining}"│
│  Action:   [ View dispute ] → /disputes/{disputeId}            │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  PHASE 2 — Reveal                                              │
│  type:     expert_reveal_required                              │
│  priority: urgent (≤ 1h left) │ high otherwise                 │
│  Title:    "Reveal your expert vote ({remaining} left)"        │
│  Summary:  "Dispute on {ctid} is in reveal phase."             │
│  Action:   [ Reveal vote ] →                                   │
│            /disputes/{disputeId}/appeal/reveal                 │
│  Deadline: summons.reveal_deadline (78h after appeal summons)  │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  PHASE 3 — Revealed, awaiting appeal verdict                   │
│  type:     expert_awaiting_verdict                             │
│  priority: info                                                │
│  Title:    "Expert vote revealed — awaiting verdict"           │
│  Metadata: { my_vote, reveal_deadline }                        │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  PHASE 4 — Appeal verdict landed (24h info-recency window)     │
│  type:     verdict_on_my_jury  (role: expert)                  │
│  priority: info                                                │
│  Title:    "Appeal verdict on a dispute you served in:         │
│             {verdict}"                                         │
│  Summary:  "{ctid} {verdict}. You voted {my_vote}.             │
│             Score {±n}."                                       │
│  Metadata: { verdict, my_vote, outcome, score_impact }         │
└────────────────────────────────────────────────────────────────┘
```

The feed carries one item per appeal at a time — each card flips to the next phase as your commit / reveal lands, and the final VERDICT card stays visible for 24h before falling off the dashboard (your activity history keeps it forever). Appeals are final, so there's no follow-on `appeal_available` notification after this — the case is closed.

If you miss commit or reveal, no terminal notification fires; you just see `status: missed_*` in your jury-history endpoint and the -10 in your activity feed.

---

## How is Expert different from Juror?

You're at a higher tier, so:

| Dimension | Juror (Stage 2) | Expert (Stage 3) |
|---|---|---|
| Minimum trust score | 700 | **850** |
| Panel size | 7 | **3** |
| Personal majority bonus | +3 | +3 |
| Personal minority penalty | -10 | -10 |
| Quorum thresholds | ≥5 reveals AND ≥3 non-abstain | ≥2 non-abstain reveals |
| What you're judging | "Is the dispute right?" — looking at the content fresh | "Was the Stage-2 jury right?" — reviewing their verdict |
| Verdict can be appealed | Yes (to Expert panel) | **No. Final.** |
| Frequency of being summoned | Sometimes | **Rarely** (only when appeals fire) |

Three experts, three votes, two-out-of-three wins. You're the final word.

---

## Things people ask

**Why are there only 3 experts when juries have 7?**
Because the pool of 850+ trust score users is much smaller. Statistically, 3 high-trust experts at the appeal stage carry similar signal to 7 jurors at the dispute stage — and they're settling, not initiating.

**Is the stake higher at the expert tier?**
Your personal stake is actually the same as a juror (-10 / +3 / -10). What's higher at this tier is the *case-level* stake — the appellant's 25-point filing fee and the full Stage-2 settlement that flips on overturn. Your call is final, and reversing it isn't possible — so the impact on others is what makes this tier weighty, not your own score delta.

**Should I just rubber-stamp the Stage 2 verdict?**
No. You're not there to confirm — you're there to review. Read the appellant's argument. If they make a good case the jury missed something, OVERTURN. If they're just sore about losing, UPHOLD.

**Can I see who voted what in Stage 2?**
You see the vote breakdown (e.g. "4 MISMATCH / 2 MATCH / 1 ABSTAIN") and the chosen origin if MISMATCH won. You don't see individual juror TIP IDs in the UI, but the chain has the data publicly.

**What's "CONSERVATIVE_LABEL" if I see it on the case?**
Means the Stage 2 jury agreed something was wrong but disagreed on what label to apply. The chain picked the smallest-penalty option. If you overturn, you're saying the whole thing was wrong.

**Can I deliberate with the other 2 experts?**
No. All three of you vote independently and blind during COMMIT phase. After REVEAL, the votes are public — but by then it's settled.

**What if I think there's fraud / something seriously wrong with the case itself?**
Out of your scope as Expert. Your job is to vote on the appeal. Separate governance channels exist for fraud reports.

**How often does this come up?**
Rarely. Only when (a) a dispute makes it to Stage 2, AND (b) the loser stakes 25 points to appeal. In normal operation, maybe a handful per quarter on a federation with thousands of users.

---

## Right-now action list when you're summoned

1. **Open the case within 24 hours.** You'll need real time to consider — the higher stake demands it.
2. **Re-read the content** like it's the first time. Don't anchor on the jury's verdict.
3. **Read the appellant's argument carefully.** What did they say the jury got wrong?
4. **Look at the Stage-2 split.** Was it 5-2 (lopsided, jury was confident)? Or 4-3 (close call)? Closer split = more weight to the appellant's argument.
5. **Decide:** UPHOLD if the jury seems right. OVERTURN if you believe they missed something. ABSTAIN if you genuinely can't tell.
6. **Commit your vote.** Your score doesn't move yet — settlement waits for the verdict.
7. **Calendar a hard reminder for 72h later.** The 12h reveal window is unforgiving.
8. **Reveal on time.** Tap-and-sign.
9. **Watch the activity feed** for the panel verdict + your stake outcome.

Three days of focused attention. You hold the final word on whatever you're looking at.
