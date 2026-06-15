# Reviewer Journey

You're a **Reviewer**. Your job is to look at content that AI flagged as suspicious and decide one thing: **was the AI right, or wrong?**

You're the first human in the loop. Most cases stop with you.

---

## Am I eligible?

You qualify if **all four** are true:

| Requirement | Why |
|---|---|
| Your trust score is **600 or higher** | Reviewers audit a single AI flag (lower stakes than jury/expert), so the bar is the lowest of the adjudication roles |
| You're a **personal identity** (not an organization / publisher) | Orgs can't be reviewers — only individual humans |
| You turned ON **"I want to be a reviewer"** in your profile | Opt-in only. Never auto-conscripted. |
| Your reviewer overturn rate is **under 30%** | If too many of your past calls got overturned, you're paused while you cool off |

You can flip the consent toggle off any time in profile settings. You stop getting assigned, immediately.

---

## How a case lands on your screen

```
Someone publishes content
          ↓
   AI scans it
          ↓
   AI says: "This looks HIGH or CRITICAL confidence AI-made"
          ↓
   Creator gets 48 hours to update their declaration without penalty
   (HIGH/CRITICAL flagged content; unflagged content gets 24h.)
          ↓
   48h passes, creator stayed silent (didn't change anything)
          ↓
   System picks a Reviewer (deterministic selection from the eligible 600+ pool)
          ↓
   That's YOU — notification appears
```

You get a push notification + an item in your "To Do" queue. The clock starts: **you have 48 hours.** (If you go silent past 48h, the system auto-recuses you and picks a fresh reviewer — no direct point loss, but your "no-show" count goes up and can pause your assignments.)

---

## What you see when you open the case

```
┌─────────────────────────────────────────────────────┐
│  REVIEW REQUEST #rv_4a8c…                           │
│                                                     │
│  Content        →  [Title + body text shown here]   │
│  Media          →  2 files · open while review live │
│  Creator        →  tip://id/IN-... (you see ID,    │
│                     not their real name)            │
│  AI's flag      →  CRITICAL — 98% confident AI-made │
│  Origin claimed →  OH (Original Human)              │
│  AI's guess     →  AG (AI-Generated)                │
│                                                     │
│  Your decision:                                     │
│     [ DISMISS ]   [ CONFIRM ]   [ RECUSE ]          │
│                                                     │
│  Time left: 47h 23m                                 │
└─────────────────────────────────────────────────────┘
```

You read the content. You compare what the creator claimed (e.g. "I wrote this — OH") vs what AI thinks (e.g. "AG — AI generated this"). You pick one of three buttons.

### Viewing the content's media

If the flagged content has media attached (images, audio, video), you can open and view those files **for as long as your review is open**. The bytes are access-controlled: the general public only ever sees a file's type, size, hash, and AI score, never the file itself. As the assigned reviewer you get full view access to the real bytes, because you can't fairly judge what you can't see.

- **Your access is scoped to your assignment.** It opens the moment you're assigned and closes the moment you submit DISMISS / CONFIRM / RECUSE (or the 48h auto-recuse fires). After the case leaves your hands you can no longer open the files.
- **The AI already looked at the media.** Each file carries its own AI-likelihood score, shown per file in the case panel. The headline confidence is the most-AI-looking file among them, so a single AI image inside an otherwise human post still drives the flag.
- **If the bytes were retention-swept**, you'll see the file's hash and score but the bytes are gone (deleted after the dispute-relevance window). Judge on the record that remains.

There is nothing to install and no key to fetch: the app handles the signed request and the temporary download link for you.

---

## Your three choices

### DISMISS — "The AI was wrong"

You read the content and you believe it's genuinely the creator's own work. The AI made a bad call.

```
You click DISMISS
       ↓
You sign the decision with your key
       ↓
Content goes back to "Verified" status
       ↓
Creator is unaffected — no penalty, badge restored
       ↓
You earn +5 trust score IMMEDIATELY (review_correct_bonus settles in the same batch).
The +5 is accountable: if someone later disputes the same content publicly and the
jury rules UPHELD (your DISMISS was wrong), the +5 is clawed back (net 0). If that
verdict is itself overturned on appeal back to DISMISSED (you were right after all),
the clawback reverses and you keep the +5.
```

A DISMISS accuses no one, so a wrong DISMISS is not punished like a wrong CONFIRM (which forfeits the full -15 disputer stake). You simply don't keep pay for a call later proven wrong. See "What you earn (or risk)" below for the full table.

### CONFIRM — "The AI was right"

The content really does look AI-made (or significantly AI-assisted) and the creator's "Original Human" claim doesn't hold up.

```
You click CONFIRM (you also pick what you think the true origin is — AA, AG, or MX)
       ↓
You sign your decision
       ↓
Creator gets a private notification: "A reviewer thinks this isn't quite OH.
                                       You have 24 hours to update the label privately."
       ↓
        ┌────────────────────────┬─────────────────────────┐
        ↓                        ↓                         ↓
  Creator agrees, updates    Creator stays           Creator pushes back
  label to AA/AG/MX           silent for 24h          publicly (manual escalate)
  privately                       ↓                         ↓
       ↓                   Auto-escalates to        Auto-escalates to
  Case closed:              public Jury              public Jury (Stage 2)
  creator pays -10          (Stage 2)                    ↓
  (accept-correction)            ↓                   You are listed as the
  You earn +5               You are listed as       formal disputer.
  (review_correct_bonus)    the formal disputer.    -15 dispute stake gets
  No dispute on record.     -15 dispute stake       deducted from your score.
                            gets deducted from
                            your score.
                            (Jury decides if you
                            get refunded + bonus.)
```

You don't decide the punishment. You just say "AI's flag was correct." Then the creator picks: admit privately (cheaper), or fight publicly (jury vote). If it goes public, you ride the dispute as the disputer — same stake-on-file rules as any other disputer.

### RECUSE — "I can't be fair on this one"

You know the creator. Or the content is in a domain where you have a financial / personal stake. Or you just don't feel qualified.

```
You click RECUSE (you can add an optional reason)
       ↓
Different reviewer gets assigned automatically
       ↓
No penalty for you. No bonus either. Just step aside.
```

**Always use this when you have a real conflict.** It's free, fast, and the right thing.

---

## What if I do nothing?

You have 48 hours (REVIEWER.AUTO_RECUSE_AGE_MS). After that:

```
48h passes with no decision (since the assignment's cert.timestamp)
          ↓
Network auto-emits a node-signed PRESCAN_REVIEW_RECUSED on your behalf.
          ↓
Review state flips to RECUSED, content status flips back to REGISTERED,
the next round's trigger picks a fresh reviewer.
          ↓
No direct point loss for the missed assignment, but the assignment counts
toward your accuracy / availability record. If your overturn rate or
no-show rate degrades, the eligibility check will pause you from future
picks until you cool off.
```

If life happens and you miss one, that's fine. Just don't make it a pattern.

---

## What you earn (or risk)

When the path closes without ever escalating to a public dispute, the math is simple. When it DOES escalate (because the creator went silent or fought publicly), you're staked as the formal disputer and the jury settlement rules apply.

| Outcome | Effect on you |
|---|---|
| You DISMISS | **+5 trust score** immediately. Accountable: if a later public dispute on the same content is UPHELD (your DISMISS was wrong), the +5 is **clawed back** (net 0). If that verdict is overturned on appeal to DISMISSED (you were right), the clawback **reverses** and you keep the +5. A wrong DISMISS only costs you the bonus, never a penalty. |
| You CONFIRM → creator privately accepts the correction | **+5 trust score** (review_correct_bonus). Creator separately takes -10 for the accepted correction. |
| You CONFIRM → escalates to Jury → Stage-2 UPHELD (jury agrees with you) | -15 stake (filing-time) + 15 (refund) + 5 (UPHELD bonus) + 5 (review_correct_bonus) = **+10 net**. |
| You CONFIRM → escalates to Jury → Stage-2 CONSERVATIVE_LABEL | -15 + 15 + 5 = **+5 net**. (Stake refunded + review_correct_bonus; no UPHELD bonus since the conservative path applies.) |
| You CONFIRM → escalates to Jury → Stage-2 DISMISSED (jury says you were wrong) | -15 stake stays forfeited. **-15 net.** Overturn rate ticks up. If it crosses 30%, you're paused from new assignments. |
| You CONFIRM → Stage-3 overturns the jury's verdict (in your favor or against) | Stage-2 settlement reverses end-to-end — including your stake/bonus overlay. Net outcome flips to match the Stage-3 verdict. |
| You RECUSE | **0 — neutral.** No change. |
| You auto-recuse (48h silent) | **0** for the score; the assignment counts toward eligibility metrics. |

The math is asymmetric in design: an honest DISMISS or a CONFIRM-with-accept pays +5 with no penalty risk (a wrong DISMISS only loses the bonus, never points). Going public on a CONFIRM is the path that puts real points (-15) at risk, and is also the path that pays the most when you're right (+10).

---

## Recognition: your Reviewer badge

Every assignment you close (DISMISS, CONFIRM, or RECUSE) shows up on your activity feed as a `PRESCAN_REVIEW_DISMISSED` / `PRESCAN_REVIEW_CONFIRMED` / `PRESCAN_REVIEW_RECUSED` tx attributed to you. The UI counts them and surfaces a **Reviewer badge** on your profile — e.g. *"Served 42 times as Reviewer"* — alongside your trust-tier badge. Nothing new gets minted on-chain: the count is a pure read off the same activity history that powers your `/v1/identity/:tipId/activity` feed.

No threshold to "unlock" the badge — it appears the first time you close a review and ticks up with every one after.

---

## Notifications you'll see

Your dashboard feed (the JSON behind your "To Do" list) emits exactly one notification type for reviewers:

```
┌──────────────────────────────────────────────────────────┐
│  type:     review_assignment_pending                     │
│  priority: urgent (≤ 6h left or overdue) │ high otherwise│
│                                                          │
│  Title:    "Review assignment open —                     │
│             {hoursRemaining}h to decide or recuse"       │
│            (overdue → "past SLA — auto-recuse imminent") │
│                                                          │
│  Summary:  "{ctid} is awaiting your decision.            │
│             Dismiss, confirm, or recuse before the       │
│             assignment auto-recuses and reassigns."      │
│                                                          │
│  Action:   [ Open review ]  →  /reviews/{review_id}      │
│  Deadline: triggered_at + 48h (REVIEWER.AUTO_RECUSE_AGE) │
└──────────────────────────────────────────────────────────┘
```

The item appears the moment a `PRESCAN_REVIEW_TRIGGERED` tx with you as `assigned_reviewer` commits, and disappears the moment you submit DISMISS / CONFIRM / RECUSE (or the 48h auto-recuse fires). No badge / no toast for closed reviews — they're visible only through your activity history and your Reviewer badge count.

---

## The complete journey at a glance

```
1.  Live your normal life. Reviewer-consent ON. Score 600+.
                       ↓
2.  Push notification: "You've been assigned to a review"
                       ↓
3.  Open the app. See content, AI's confidence, claimed vs guessed origin.
                       ↓
4.  Read the content. Use your judgment.
                       ↓
            ┌──────────┼──────────┐
            ↓          ↓          ↓
        DISMISS    CONFIRM     RECUSE
       (AI wrong)  (AI right)  (conflict)
            ↓          ↓          ↓
       Restored.  Creator      Someone
       Earn +5    decides:     else gets it
       (clawed    admit or
        back if   go public
        upheld)       ↓
                   ┌───┴───┐
                   ↓       ↓
               Admits   Public Jury
               quietly  takes over
               → done   (Stage 2)
                            ↓
                       7 jurors vote
                            ↓
                       You earn +5 if
                       they agree with
                       your CONFIRM
```

---

## Things people often ask

**Do I see the creator's real name?**
No. You see their TIP ID only. You're judging the content, not the person.

**Do I read the content for hate speech, copyright, politics?**
No. You ONLY decide one thing: does the content look AI-generated? Other moderation isn't in your job.

**What if the AI's confidence was high but I'm just unsure?**
If you genuinely can't tell, that's what RECUSE is for. Or — if you lean toward "it's borderline AI-assisted but not clearly AG," you can CONFIRM with origin = AA (AI-Assisted) or MX (Mixed). The creator then has 24h to either accept or push to Jury. The middle ground is honored.

**Can I review my own content?**
Never. The system filters you out of any review involving a TIP ID you control.

**How often will I get assigned?**
Depends on how many flagged cases come up and how many other reviewers are active. It's not constant — could be a few per week, or a few per month.

**Will the creator know it was me?**
No. The decision is on the chain (so anyone can audit it), but your TIP ID isn't broadcast as "the reviewer." Anonymity by design.

**Can I view the attached images / video / audio?**
Yes, while your review is open. Your access ends when you submit your decision (or auto-recuse). The public never sees the bytes, only the file's type, size, hash, and AI score.

**Can I change my mind after submitting?**
No. Once you sign and submit, it's on the chain. Take your time before clicking.

**Is there any money in this?**
No tokens. You earn trust score: +5 on DISMISS (clawed back if a later dispute proves the DISMISS wrong), +5 to +10 on a CONFIRM path that vindicates you, -15 when a public jury overturns your CONFIRM. Trust score is your protocol-wide reputation. Higher score = qualifies you for Juror, then Expert, roles, and those carry their own stakes.

---

## What to do RIGHT NOW if you just got assigned

1. Open the case within 12 hours if you can — leaves you cushion before the 48h limit.
2. Read the content carefully. AI's "high confidence" doesn't mean "correct" — it means "AI is more confident." You're the human check.
3. If you don't feel competent or impartial, RECUSE. No shame in it.
4. Otherwise pick DISMISS or CONFIRM with your honest read.
5. Sign + submit. Done.

That's the whole journey.
