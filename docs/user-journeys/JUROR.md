# Juror Journey

You're a **Juror**. Someone publicly disputed a piece of content — they're claiming the creator's origin label is wrong. You're one of **7 jurors** picked at random to decide who's right: the creator or the disputer. The majority of those who actually vote sets the outcome.

This is Stage 2 — the public phase. Stage 1 (Reviewer) already happened or got skipped. Now it's the community's turn.

---

## Am I eligible?

You qualify if **all** are true:

| Requirement | Why |
|---|---|
| Your trust score is **700 or higher** | Jurors hold real consequences — you need a proven track record |
| You're a **personal identity** (not an organization) | Orgs can't be jurors |
| You turned ON **"I want to serve as a juror"** in your profile | Opt-in only. Each adjudication role (reviewer, juror, expert) has its OWN toggle, so you can sit on juries without being pulled into reviewer or expert duty. |
| You're not the creator, the disputer, or anyone on the original review | Conflict-of-interest filter, applied automatically |

**Where to find the toggle:** Profile → Settings → Adjudication participation → "Serve as a juror". Separate from the reviewer and expert toggles. You can turn it off any time, you stop getting picked immediately.

**How often you'll be picked:** A few times a year initially, depending on dispute volume and the active eligible-juror pool. Higher trust scores qualify for a bigger pool but the random selection is uniform — your trust score doesn't bias the picker, only the eligibility floor does.

---

## How a case lands on you

A dispute has been publicly filed — either by a user with trust score 550+ who challenged verified content directly, or auto-escalated from a reviewer's CONFIRM that the creator didn't accept. Either way, the disputer is that user or that reviewer (the creator is never the disputer on their own content). The protocol then picks 7 jurors:

```
       System runs a deterministic random selection
       (same algorithm on every node — everyone agrees)
                 ↓
       Picks 7 jurors from the eligible pool
                 ↓
       You're one of them — JURY_SUMMONS lands
```

Each chosen juror gets a push notification + an item in their queue. Same moment, same content, 6 others picked too. You don't see who the others are.

The clock starts. You have **72 hours to vote** and then **12 hours to reveal**. Total commitment: 3 days + 12 hours.

---

## Why two phases? (Commit + Reveal)

To prevent jurors from copying each other's votes.

**Phase 1 (commit, 72h):** You decide your vote in private and submit a SCRAMBLED version of it. The system stores the scrambled version. Nobody — including you — can verify what anyone voted yet.

**Phase 2 (reveal, 12h):** You submit your real vote + the unscrambling key. The system checks that your reveal matches your earlier commit. Everyone's reveal is now public.

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

**Viewing the content's media.** If the disputed content has media attached (images, audio, video), you can open the actual files while you sit on the jury. The bytes are access-controlled (the public sees only a file's type, size, hash, and AI score), but a summoned juror gets full view access so you can judge the work itself, not just its description. Your access opens when you're summoned and closes when the verdict lands (ADJUDICATION_RESULT). Each file also shows its own AI-likelihood score; the case's headline confidence is the most-AI-looking file among them. If the bytes were already retention-swept, you'll see the hash and score but not the file. The app handles the signed request and download link for you.

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
   Verdict: UPHELD (or CONSERVATIVE_LABEL if the creator declared AG and the jury confirmed it's actually OH — over-declaration, no creator penalty)
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
- **Vote against the majority + reveal on time** → **-8** trust score (minority penalty)
- **ABSTAIN + reveal on time** → **0** (neutral — neither bonus nor penalty)
- **Summoned but never committed** → **-1** (small signal — you didn't engage at all)
- **Committed but missed the reveal** → **-8** (heavier — you engaged with the case then walked away mid-process)

(On NO_QUORUM the majority/minority settlement does not apply, because there is no majority, so jurors who revealed get **0**, win or lose. But the no-show penalties above (**-1** / **-8**) still apply to the absentees who broke quorum. They are the only jurors who pay when a jury fails to reach quorum: the people who showed up are never punished for a quorum failure they didn't cause.)

The asymmetric math (-8 to lose vs +3 to win) is deliberate: it makes "vote anyway, hope for the best" worse than "ABSTAIN if you're not sure." Voting carefully is the right strategy. And the split between -1 (never committed) and -8 (committed-but-bailed) reflects intent — a juror who never opens the case is unresponsive; one who commits and walks away actively disrupted the panel's quorum math.

---

## The bigger picture: what your vote moves

Your own +3 / -8 is small. The case-level economics your vote drives are much bigger — your jury decides how points move between the creator and the disputer:

| Verdict | Creator | Disputer |
|---|---|---|
| DISMISSED (clear MATCH majority) | **+5** vindication bonus | **-15** (filing stake stays forfeited) |
| UPHELD (MISMATCH wins) | **-100** for OH→AG 1st offense (smaller for AA→AG or OH→AA; up to **-300** for repeat offenders — see the mislabeling table) | **+20** (filing stake refunded + upheld bonus) |
| CONSERVATIVE_LABEL (creator declared AG, jury confirmed it's actually OH — over-declaration) | **0** (no penalty — over-declaration is encouraged) | **+15** (refund only, no bonus) |
| NO_QUORUM (fewer than 5 reveals or fewer than 3 non-abstain) | 0 (pending Stage 3) | 0 (stake locked until Stage 3) |
| Tie (MATCH == MISMATCH) | 0 (no vindication) | 0 (stake locked, escalates) |

A **tie is a deadlock, not a dismissal** — there's no majority, so it auto-escalates to Stage 3 exactly like NO_QUORUM (the disputer's stake stays locked, the creator gets no vindication). Only a *clear* MATCH majority is a real DISMISSED that forfeits the disputer and vindicates the creator.

A jury that gets it wrong moves real points across the federation. **Your personal +3 / -8 delta is the smallest thing in the room** — the case-level impact is what the protocol is asking you to take seriously.

---

## The full journey, hour by hour

```
HOUR 0:
   JURY_SUMMONS lands. Push notification: "You're a juror on dispute #ds_7b3f"
   Your score doesn't move yet — settlement happens at verdict time (hour 84).

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

HOURS 72 – 84:
   REVEAL PHASE — confirm your vote in public.
        ↓
   Open the case again. Click "Reveal my vote".
        ↓
   App sends your actual vote + the salt → chain hashes (vote+salt) and
   verifies it matches your earlier commit.
        ↓
   Your vote is now public on-chain.

HOUR 84:
   REVEAL PHASE ENDS. Verdict computed automatically.
        ↓
   System counts revealed votes. Verdict needs at LEAST 5 total reveals
   AND at LEAST 3 non-abstain reveals — otherwise NO_QUORUM.
        ↓
   With quorum:
        - MISMATCH > MATCH (majority of non-abstain)        → UPHELD
          ↳ If creator declared AG and majority confirmed OH → CONSERVATIVE_LABEL
            (over-declaration: no creator penalty)
        - MATCH > MISMATCH (clear majority of non-abstain)  → DISMISSED
        - Tie (MATCH == MISMATCH)                            → no result → escalates (see below)
   No decisive result (deadlock or low participation):
        - Tie, OR fewer than 5 reveals, OR fewer than 3 non-abstain → NO_QUORUM
          ↳ Auto-escalates to Stage 3 (Expert panel); disputer stake stays locked
          ↳ Revealers get 0 (no majority to score); no-show jurors who broke
            quorum still take their -1 / -8

HOUR 84+:
   With quorum reached:
   - Voted with majority + revealed on time → +3
   - Voted minority + revealed on time       → -8
   - ABSTAINED + revealed on time            → 0
   - Never committed                         → -1
   - Committed but missed reveal             → -8
   With NO_QUORUM:
   - Every juror's score impact is 0 — the case moves to Stage 3 unaffected.
   Outcome lands in your activity feed.
```

---

## What if you miss a step

| What you missed | Consequence |
|---|---|
| Missed the COMMIT phase (didn't submit anything in 72h) | **-1 trust score** if the jury reaches quorum without you (5+ reveals, 3+ non-abstain). Small signal — you didn't engage at all. 0 if the jury fails quorum (NO_QUORUM auto-escalates without scoring anyone). |
| Submitted COMMIT but missed REVEAL phase (didn't reveal in the 12h window) | **-8** if quorum reached, 0 otherwise. Heavier than no-commit because you engaged with the case then walked away mid-process — the rest of the panel was counting on you. The chain has no way to score what's still hidden inside the commit. |
| Submitted both — but the reveal didn't match the commit | Same as missed-reveal: **-8**. The system can't verify you voted in good faith. (App handles the salt automatically — this won't happen if you use the app correctly.) |

The bottom line: **if you commit, come back and reveal.** Once you've committed, the panel's quorum math counts on you — bailing is a heavier penalty than never showing up.

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
| Commit + reveal + vote with minority | **-8 trust score** |
| Commit + reveal + ABSTAIN | **0 — neutral** |
| Commit + miss reveal | **-8 trust score** |
| Didn't commit at all | **-1 trust score** |

---

## Recognition: your Juror badge

Every jury reveal you submit lands on chain as a `JURY_VOTE_REVEAL` tx (with `is_appeal: false`) attributed to you. The UI counts them off your activity feed and shows a **Juror badge** on your profile — e.g. *"Served 17 times as Juror"* — next to your trust-tier badge. Nothing extra is stored: it's a pure read from `/v1/identity/:tipId/activity` filtered to `JURY_VOTE_REVEAL` rows where you're the `juror_tip_id` and `is_appeal` is false.

The count includes ABSTAIN reveals (you showed up and signalled) but not no-shows (no tx was emitted on your behalf). The badge appears the first time you reveal and ticks up every reveal after that.

---

## Notifications you'll see

Your dashboard feed surfaces these juror-facing types, each tied to a phase of the case. The same item ID updates priority as the deadline approaches:

```
┌────────────────────────────────────────────────────────────────┐
│  PHASE 1 — Commit                                              │
│  type:     juror_commit_required                               │
│  priority: urgent (≤ 12h left) │ high otherwise                │
│  Title:    "Commit your jury vote ({remaining} left)"          │
│  Summary:  "Dispute on {ctid} is in commit phase."             │
│  Action:   [ Commit vote ] → /disputes/{disputeId}/commit      │
│  Deadline: summons.commit_deadline (72h after summons)         │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  PHASE 1.5 — Committed, reveal window not yet open             │
│  type:     juror_awaiting_reveal_window                        │
│  priority: info                                                │
│  Title:    "Jury vote committed — reveal opens in {remaining}" │
│  Action:   [ View dispute ] → /disputes/{disputeId}            │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  PHASE 2 — Reveal                                              │
│  type:     juror_reveal_required                               │
│  priority: urgent (≤ 1h left) │ high otherwise                 │
│  Title:    "Reveal your jury vote ({remaining} left)"          │
│  Summary:  "Dispute on {ctid} is in reveal phase."             │
│  Action:   [ Reveal vote ] → /disputes/{disputeId}/reveal      │
│  Deadline: summons.reveal_deadline (84h after summons)         │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  PHASE 3 — Revealed, awaiting verdict                          │
│  type:     juror_awaiting_verdict                              │
│  priority: info                                                │
│  Title:    "Jury vote revealed — awaiting verdict"             │
│  Metadata: { my_vote, reveal_deadline }                        │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  PHASE 4 — Verdict landed (24h info-recency window)            │
│  type:     verdict_on_my_jury                                  │
│  priority: info                                                │
│  Title:    "Jury verdict on a dispute you served in: {verdict}"│
│  Summary:  "{ctid} {verdict}. You voted {my_vote}.             │
│             Score {±n}."                                       │
│  Metadata: { verdict, my_vote, outcome, score_impact }         │
└────────────────────────────────────────────────────────────────┘
```

The feed only carries one item per case at a time — as you commit, the COMMIT card flips to AWAITING_REVEAL_WINDOW; when the reveal phase opens, it flips to REVEAL_REQUIRED; after you reveal, it becomes AWAITING_VERDICT; and once the verdict batch settles, you see VERDICT_ON_MY_JURY for 24h before it drops off the dashboard (still visible in your history).

If you miss commit or reveal, no terminal notification fires — the chain doesn't replay your no-show to your dashboard. Your jury-history endpoint shows `status: missed_*` and the corresponding penalty (-1 if you never committed, -8 if you committed but missed reveal) in your activity feed.

---

## Things people ask

**Why a penalty? I don't want to risk anything.**
The -8 minority penalty is what makes jurors take voting seriously — if it were free, people would vote randomly or follow whoever revealed first. The split between -1 (never engaged) and -8 (committed then bailed) reflects intent: a juror who never opened the case is just unresponsive, while one who committed and walked away mid-process took up a slot and disrupted the panel's quorum math. The downside forces you to vote based on what you actually believe — or abstain if you genuinely can't tell.

**What's MATCH/MISMATCH again?**
MATCH = "the creator's label is right." MISMATCH = "the creator's label is wrong, and I think it should be [X]." Match the creator's claim, or mismatch it.

**Why does MISMATCH need me to pick an origin?**
Because the chain has to update the content to the new label. If MISMATCH voters split between different replacement origins (e.g. 3 say AA, 2 say AG), the chain takes the most common one as the new origin. (CONSERVATIVE_LABEL is a separate concept — it's the specific case where the creator declared AG but the jury confirmed it's actually OH, an over-declaration that carries no creator penalty.)

**Can I see who else is on the jury?**
Only after reveal phase ends. During COMMIT, all 7 are anonymous to each other. After REVEAL, the chain has everyone's vote — so the data is public, but the system never shows you "your fellow jurors" in real-time.

**Can I see the AI's prescan result?**
Yes — the disputer can attach it as evidence. You'll see the AI confidence in the case panel. Use it as ONE input among many; don't just rubber-stamp the AI.

**Can I view the attached images / video / audio?**
Yes, while you're on the jury. Your access opens when you're summoned and closes when the verdict lands. The public never sees the bytes, only each file's type, size, hash, and per-file AI score.

**What if the disputer is wrong / disputes are abusive?**
That's exactly why the disputer ALSO stakes 15 points. If the jury DISMISSES (creator wins), the disputer loses those 15. So abusive disputes self-discipline through the stake.

**What about emergencies — can someone bail me out?**
No. Once you commit, only YOU can reveal (because only you have the salt). If life happens and you can't reveal in the 12h window, you take the -8 (committed-but-no-reveal). Plan accordingly: don't commit on Monday if you'll be off-grid Thursday-Sunday. If you know up front you won't be around, *don't commit at all* — the no-commit penalty is only -1.

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
