# Juror Journey

You're a **Juror**. Someone publicly disputed a piece of content. You're one of **7 jurors** picked at random to vote on it. The majority of those who actually vote decides the outcome.

This is Stage 2 — the public phase. Stage 1 (Reviewer) already happened or got skipped. Now it's the community's turn.

---

## Am I eligible?

You qualify if **all** are true:

| Requirement | Why |
|---|---|
| Your trust score is **700 or higher** | Jurors hold real consequences — you need a proven track record |
| You're a **personal identity** (not an organization) | Orgs can't be jurors |
| You turned ON **"I want to help adjudicate"** in your profile | Opt-in only |
| You're not the creator, the disputer, or anyone on the original review | Conflict-of-interest filter, applied automatically |

You can turn the toggle off any time. You stop getting picked, immediately.

---

## How a case lands on you

```
Someone publicly disputed a piece of content
       (could be the creator themselves after a reviewer's CONFIRM,
        or any user with score 400+ challenging a verified content)
                 ↓
       System runs a deterministic random selection
       (same algorithm on every node — everyone agrees)
                 ↓
       Picks 7 jurors from the eligible pool
                 ↓
       You're one of them — JURY_SUMMONS lands
```

Each chosen juror gets a push notification + an item in their queue. Same moment, same content, 6 others picked too. You don't see who the others are.

The clock starts. You have **72 hours to vote** and then **6 hours to reveal**. Total commitment: 3 days + 6 hours.

---

## Why two phases? (Commit + Reveal)

To prevent jurors from copying each other's votes.

**Phase 1 (commit, 72h):** You decide your vote in private and submit a SCRAMBLED version of it. The system stores the scrambled version. Nobody — including you — can verify what anyone voted yet.

**Phase 2 (reveal, 6h):** You submit your real vote + the unscrambling key. The system checks that your reveal matches your earlier commit. Everyone's reveal is now public.

This way, juror #5 can't watch juror #1's vote and copy it. Everyone votes blind.

---

## What you see when you open the case

```
┌──────────────────────────────────────────────────────────┐
│  JURY DUTY — Dispute #ds_7b3f…                           │
│                                                          │
│  Content        →  [Title + body + media shown here]     │
│  Creator        →  tip://id/IN-... (TIP ID, not name)    │
│  Disputer       →  tip://id/US-... (TIP ID, not name)    │
│  What's claimed →  Creator says OH (Original Human)      │
│  What's argued  →  Disputer says AG (AI-Generated)       │
│  Evidence       →  [Optional: link / hash / text the     │
│                     disputer attached]                   │
│                                                          │
│  Your vote:                                              │
│     [ MATCH ]      → "Creator's claim is correct"        │
│     [ MISMATCH ]   → "Disputer is right, creator wrong"  │
│     [ ABSTAIN ]    → "I can't decide — protected"        │
│                                                          │
│  Phase: COMMIT — 71h 14m left                            │
│                                                          │
│  [ Vote — then come back in 72h to reveal ]              │
└──────────────────────────────────────────────────────────┘
```

You take your time, study the content, read the evidence. Then you cast a vote.

---

## Your three vote options

### MATCH — "The creator was telling the truth"

You believe the creator's origin claim is correct. The dispute is groundless.

```
Effect on the case if MATCH wins majority of non-abstain reveals:
       ↓
   Verdict: DISMISSED
   Creator gets a +5 vindication bonus
   Disputer's filing stake (-15) stays forfeited
   No content change
```

### MISMATCH — "The disputer is right, creator's claim was wrong"

You side with the disputer. The content really isn't what the creator labeled it.

If you click MISMATCH, the app asks: **"What origin DO you think this is?"** Pick AA, AG, or MX. This is required — otherwise the verdict can't act on your vote. (The system needs to know what to relabel the content as.)

```
Effect on the case if MISMATCH wins majority:
       ↓
   Verdict: UPHELD (or CONSERVATIVE_LABEL if jurors disagreed on what label to apply)
   Content gets relabeled to the new origin
   Creator's score takes a penalty (size depends on the swap — OH→AG is the heaviest)
   Disputer gets their stake back + a +5 upheld bonus
```

### ABSTAIN — "I really can't decide"

Genuinely don't know. Don't want to vote wrong. Default-safe option.

```
Effect on you:
       ↓
   Score delta: 0 — no bonus, no penalty
   Your vote doesn't count toward majority
   (But it still counts toward "did this jury reach quorum?" — see below)
```

Use this when you genuinely lack info. **Don't use it just to dodge** — if you abstain too often, the system may stop picking you.

---

## What's at stake

Nothing is held in escrow at summons time — your score doesn't move until the verdict batch lands. But the verdict applies a flat reward or penalty based on what you did:

- **Vote with the majority + reveal on time** → **+3** trust score (majority bonus)
- **Vote against the majority + reveal on time** → **-10** trust score (minority penalty)
- **ABSTAIN + reveal on time** → **0** (neutral — neither bonus nor penalty)
- **Miss the reveal phase** (whether you committed or not) → **-10** (no-show penalty, only applies if the jury still reached quorum)

The asymmetric math (-10 to lose vs +3 to win) is deliberate: it makes "vote anyway, hope for the best" worse than "ABSTAIN if you're not sure." Voting carefully is the right strategy.

---

## The full journey, hour by hour

```
HOUR 0:
   JURY_SUMMONS lands. Push notification: "You're a juror on dispute #ds_7b3f"
   Your score doesn't move yet — settlement happens at verdict time (hour 78).

HOURS 0 – 72:
   COMMIT PHASE — vote in private.
        ↓
   Open the case. Read the content. Examine the evidence.
        ↓
   Pick: MATCH / MISMATCH (+ origin) / ABSTAIN
        ↓
   App generates a hidden "salt" + hashes (vote + salt) → commitment
        ↓
   You sign the commitment + submit it. Nobody knows your vote yet.

HOUR 72:
   COMMIT PHASE ENDS. Reveal phase opens.

HOURS 72 – 78:
   REVEAL PHASE — confirm your vote in public.
        ↓
   Open the case again. Click "Reveal my vote".
        ↓
   App sends your actual vote + the salt → chain hashes (vote+salt) and
   verifies it matches your earlier commit.
        ↓
   Your vote is now public on-chain.

HOUR 78:
   REVEAL PHASE ENDS. Verdict computed automatically.
        ↓
   System counts revealed votes. Verdict needs at LEAST 5 total reveals
   AND at LEAST 3 non-abstain reveals — otherwise NO_QUORUM.
        ↓
   With quorum:
        - MISMATCH > MATCH (majority of non-abstain)        → UPHELD
          ↳ If jurors disagreed on the new origin label and
            declared was AG with confirmed-majority OH       → CONSERVATIVE_LABEL
        - MATCH ≥ MISMATCH (majority of non-abstain)        → DISMISSED
        - Tie (MATCH == MISMATCH)                            → DISMISSED, no juror bonus/penalty
   Without quorum:
        - Fewer than 5 reveals OR fewer than 3 non-abstain   → NO_QUORUM
          ↳ Auto-escalates to Stage 3 (Expert panel)
          ↳ No juror score effects fire — neither bonuses nor no-show penalties

HOUR 78+:
   With quorum reached:
   - Voted with majority + revealed on time → +3
   - Voted minority + revealed on time       → -10
   - ABSTAINED + revealed on time            → 0
   - Missed the reveal (any reason)          → -10 (no-show)
   With NO_QUORUM:
   - Every juror's score impact is 0 — the case moves to Stage 3 unaffected.
   Outcome lands in your activity feed.
```

---

## What if you miss a step

| What you missed | Consequence |
|---|---|
| Missed the COMMIT phase (didn't submit anything in 72h) | Treated as a no-show. **-10 trust score** if the jury reaches quorum without you (5+ reveals, 3+ non-abstain). 0 if the jury fails quorum (NO_QUORUM auto-escalates without scoring anyone). |
| Submitted COMMIT but missed REVEAL phase (didn't reveal in the 6h window) | Same no-show rules apply. **-10** if quorum reached, 0 otherwise. The chain has no way to score what's still hidden inside the commit. |
| Submitted both — but the reveal didn't match the commit | Same as no-show. The system can't verify you voted in good faith. (App handles the salt automatically — this won't happen if you use the app correctly.) |

The bottom line: **come back and reveal.** The jury can't tell who committed and who didn't; both look the same to the verdict logic.

---

## What about NO_QUORUM?

Sometimes 7 jurors get summoned but too few actually reveal. The verdict logic needs **at least 5 reveals** total **and at least 3 non-abstain reveals** to compute a result. If either threshold is missed, the verdict is **NO_QUORUM**.

```
Fewer than 5 reveals OR fewer than 3 non-abstain
            ↓
   NO_QUORUM verdict — auto-escalates to Stage 3
            ↓
   3 Experts get summoned to settle it
            ↓
   No juror score effects fire — everyone walks away at 0
```

So if the jury collapses into NO_QUORUM, **nobody is penalised** — not even the people who never showed. The case just rolls into the Stage 3 expert panel and they make the call.

---

## Stake math summary

(Assuming the jury reaches quorum. NO_QUORUM zeroes everything out.)

| Your action | Effect |
|---|---|
| Commit + reveal + vote with majority | **+3 trust score** |
| Commit + reveal + vote with minority | **-10 trust score** |
| Commit + reveal + ABSTAIN | **0 — neutral** |
| Commit + miss reveal | **-10 trust score** (no-show) |
| Didn't commit at all | **-10 trust score** (still counts as no-show) |

---

## Things people ask

**Why a penalty? I don't want to risk anything.**
The -10 minority/no-show penalty is what makes jurors take it seriously. If voting were free, people would vote randomly or follow whoever votes first. The downside risk forces you to vote based on what you actually believe — or abstain if you genuinely can't tell.

**What's MATCH/MISMATCH again?**
MATCH = "the creator's label is right." MISMATCH = "the creator's label is wrong, and I think it should be [X]." Match the creator's claim, or mismatch it.

**Why does MISMATCH need me to pick an origin?**
Because the chain has to update the content to the new label. If 4 jurors say MISMATCH but each says a different replacement origin, the system applies the conservative one (CONSERVATIVE_LABEL verdict) — usually the smaller penalty.

**Can I see who else is on the jury?**
Only after reveal phase ends. During COMMIT, all 7 are anonymous to each other. After REVEAL, the chain has everyone's vote — so the data is public, but the system never shows you "your fellow jurors" in real-time.

**Can I see the AI's prescan result?**
Yes — the disputer can attach it as evidence. You'll see the AI confidence in the case panel. Use it as ONE input among many; don't just rubber-stamp the AI.

**What if the disputer is wrong / disputes are abusive?**
That's exactly why the disputer ALSO stakes 15 points. If the jury DISMISSES (creator wins), the disputer loses those 15. So abusive disputes self-discipline through the stake.

**What about emergencies — can someone bail me out?**
No. Once you commit, only YOU can reveal (because only you have the salt). If life happens and you can't reveal in the 6h window, you take the -10. Plan accordingly: don't commit on Monday if you'll be off-grid Thursday-Sunday.

**How often will I be picked?**
Depends on dispute volume + how many qualified jurors are active. Likely a few times a year initially. Higher score = larger pool = a bit more often.

---

## Right-now action list

When you get a JURY_SUMMONS:

1. **Open the case promptly.** Don't put it off for 60 hours.
2. **Read the content + creator's claim + disputer's argument.** Form an honest opinion.
3. **Decide your vote.** If genuinely unsure → ABSTAIN. Don't fake-vote.
4. **Submit the COMMIT.** App handles the hash + salt for you. Your score doesn't move yet — settlement waits for the verdict.
5. **Calendar a reminder for the reveal window** (~72h later). Don't miss this.
6. **Reveal on time.** A 30-second tap.
7. **Watch the activity feed** for the verdict and your stake outcome.

Three days of attention. That's the job.
