# Creator Journey

You're a **Creator** — a normal user who publishes content on TIP. This is the most common role on the protocol.

Most of the time you just publish and people read it. Occasionally AI flags something or someone disputes you. This guide walks through everything that can happen to your content and what you do at each step.

---

## What you sign up for

When you publish content on TIP, you make **one specific claim**: an origin label. You're telling everyone "this is the type of content this is."

| Label | Means |
|---|---|
| **OH** — Original Human | I wrote/made this entirely myself, no AI involved |
| **AA** — AI-Assisted | I made this with AI help (e.g. AI helped me write some sentences, but the idea + structure are mine) |
| **AG** — AI-Generated | This is mostly or entirely AI-made |
| **MX** — Mixed | Combination — some parts mine, some parts AI, hard to separate |

You pick one when you publish. **Be honest about the label.** AI scans every piece of content and flags suspicious mismatches between what you claimed and what AI thinks it is.

---

## The happy path (most content)

```
1.  You write/make content
                 ↓
2.  You publish it (REGISTER_CONTENT)
                 ↓
3.  AI prescan runs in the background — gives a confidence score
                 ↓
4.  AI confidence is LOW or ELEVATED (not strongly flagged)
                 ↓
5.  Content shows as "Verified" with your chosen origin label
                 ↓
6.  You have a 24-hour grace window to change the origin label at
    zero penalty — useful if you realize on second thought you should
    have labeled it AA instead of OH (or any other tweak).
                 ↓
7.  After 24h the label is locked in. Content stays Verified. Done.
```

~90%+ of content goes through this path with zero friction. AI doesn't flag you strongly. No reviewer involvement. Nothing to deal with.

**The 24-hour grace window is your "I changed my mind" buffer.** Use it whenever you realize you mislabeled something — cheaper than a dispute later, and the change costs zero score.

---

## Attaching media to your content

Your content can carry media files: images, audio, and video. (Which types and size limits are enabled is network policy, set in genesis. Video is accepted for storage even though its automated AI score is not available yet.)

What you should know:

- **Upload first, then publish.** Each file is uploaded on its own (you get back a `media_id`), then you list those ids when you register the content. Uploading is content-addressed: the `media_id` IS the cryptographic hash of the bytes, so the same file always produces the same id, and re-uploading an identical file is free (it deduplicates).
- **The server decides the file type, not your label.** The node reads the file's actual bytes to determine the real type (png, jpeg, webp, gif, mp3, wav, mp4, ...). If your client mislabels a file, the node stores the truth and hands it back. Use the type it returns when you publish.
- **Your media is private to the people who judge it.** The bytes are NOT public. Anyone can see a file's type, size, hash, and AI score, but only people with a role on your content (you, an assigned reviewer, a disputer, jurors, appeal experts) can open the actual file. There is no public media URL.
- **Each file gets its own AI score.** The prescan classifier scores every file individually. Your content's headline confidence is the most-AI-looking file among them. You can see the per-file scores on your content page.
- **Media bytes do not live forever.** Once the dispute-relevance window closes (never-disputed content after a few weeks; disputed content about a week after the verdict), the node deletes the raw bytes. The content-hash stays on chain permanently as proof of what the file was, but the bytes themselves are swept to keep storage honest. Your registration and its verdict are unaffected.

---

## What happens if AI flags you

If you claimed **OH** but AI thinks **AG** with high confidence (HIGH or CRITICAL tier), things branch.

You'll see something like this on your content's detail page:

```
┌────────────────────────────────────────────────────────────┐
│  ⚠ AI flagged this content                                 │
│                                                            │
│  You claimed:  OH (Original Human)                         │
│  AI thinks:    AG (AI-Generated) — HIGH confidence (94%)   │
│                                                            │
│  You have 48 hours to update the origin label without      │
│  any penalty. Just pick a more accurate label and the      │
│  flag clears. After 48 hours, a human reviewer will be     │
│  assigned to look at your content.                         │
│                                                            │
│  Time left: 47h 23m                                        │
│                                                            │
│  [ Update origin to AA ]   [ Update to AG ]                │
│  [ Update to MX ]          [ Keep my claim ]   [ Retract ] │
└────────────────────────────────────────────────────────────┘
```

You have **48 hours** for HIGH or CRITICAL tier content. Time enough to think it over, talk to people, and make an honest call. You have **3 choices**:

### Choice 1: Update the origin (recommended if AI is right)

You acknowledge the AI was correct. You change the label to a more honest one.

```
You click "Update to AG" (or AA, MX)
       ↓
Origin label changes immediately. Flag clears.
       ↓
ZERO score penalty — updates inside the 48h grace window are free.
       ↓
Content shows as Verified with the new label. No public record of a dispute.
       ↓
Done. You walk away cleanly.
```

**Do this if AI is right.** Self-correcting inside the grace window is **completely free** — no penalty. The protocol's design is "honest labels are easy to fix." The penalty kicks in only if you DON'T self-correct, a reviewer agrees with AI, and you push it to public dispute and lose. So if AI is right, just update.

### Choice 2: Keep your claim, accept review

You believe the AI was wrong. You're going to fight it.

```
You don't update (or click "Keep my claim")
       ↓
48 hours pass — content stays as "Pending Review" status (amber badge)
       ↓
A human reviewer gets auto-assigned to look at your content
       ↓
        ┌──────────────┬──────────────┐
        ↓              ↓              ↓
   Reviewer        Reviewer       Reviewer
   DISMISSES       CONFIRMS       RECUSES
   (says AI       (says AI         (reassign)
    was wrong)     was right)
        ↓              ↓
   Flag clears.   You get a private 24h decision window
   Back to        (see "If reviewer confirms" below)
   normal.
   No penalty.
```

**Note:** During the 48-hour window before the reviewer is assigned, you can STILL self-correct at any time (penalty-free). The window isn't "fight or die" — it's "have time to think + still able to update."

### Choice 3: Retract the content

You realize the content shouldn't be public at all. Take it down.

```
You retract the content
       ↓
Content marked RETRACTED — hidden from public surfaces
       ↓
Small penalty (-50 score) — retractions are tracked
       ↓
But: no public dispute, no reviewer, no jury. You handled it yourself.
```

Use this for content that's truly not ready to be public, not as an escape from a flag (the -50 stings).

---

## If a reviewer confirms (you still want to fight)

Reviewer says "AI was right." You see:

```
┌────────────────────────────────────────────────────────────┐
│  A reviewer agreed with AI's flag.                         │
│                                                            │
│  Reviewer thinks:  AG (AI-Generated)                       │
│  You can either:                                           │
│    (a) Update the label privately → small penalty, no      │
│        public dispute on your record                       │
│    (b) Do nothing → in 24h this becomes a PUBLIC DISPUTE   │
│        where 7 jurors will vote on it                      │
│                                                            │
│  Time left: 23h 47m                                        │
│                                                            │
│  [ Accept correction — update to AG (private) ]            │
│  [ Take it to public dispute ]                             │
└────────────────────────────────────────────────────────────┘
```

You have **24 hours** to choose:

### "I'll accept the correction" (private resolution)

```
You click "Accept correction"
       ↓
Origin label updates privately to what the reviewer said
       ↓
Small penalty (-10 score for the relabel)
       ↓
No public dispute on your activity feed
       ↓
You move on
```

### "No, take it public"

```
You wait the 24h out, or actively click "Take to public dispute"
       ↓
Public CONTENT_DISPUTED tx fires automatically (with your authorization).
The reviewer becomes the formal disputer on chain — their CONFIRM is
the claim being adjudicated, so they hold the disputer seat and pay
the -15 disputer stake. You're the author being challenged, not the disputer.
       ↓
7 jurors get summoned (Stage 2 begins)
       ↓
You wait 72h-84h for verdict
       ↓
        ┌──────────────────┬──────────────────┬──────────────────┐
        ↓                  ↓                  ↓                  ↓
   Jury DISMISSES      Jury UPHELD       Jury NO_QUORUM    Jury CONSERVATIVE_LABEL
   (you were right)    (you were wrong)  (fewer than 5     (jurors agreed
        ↓                  ↓              reveals OR fewer  something was wrong
   Score restored.     Origin relabels.   than 3 non-       but disagreed on
   Your flag clears.   Heavy penalty      abstain reveals)  the new label —
   You earn +5         (size depends on        ↓            system applied the
   "vindication        the swap, see      Auto-escalates    smallest-penalty
   bonus."             score math below)  to Expert panel   label, no extra
                                          (Stage 3)         penalty for you)
                            ↓
                       Either side can
                       file appeal
                       within 48h
                       (Stage 3)
```

---

## What happens on Stage 3 appeal

If Stage 2 ruled against you and you believe the jury was wrong, you can appeal:

```
You file APPEAL_FILED within 48h
       ↓
-25 points deducted (appeal stake on file)
       ↓
3 Experts get summoned (Stage 3)
       ↓
       72h commit + 12h reveal (need ≥2 non-abstain reveals)
       ↓
        ┌──────────────────┬──────────────────┐
        ↓                                     ↓
   Experts UPHOLD jury                 Experts OVERTURN
   (you lose appeal)                   (you win appeal)
        ↓                                     ↓
   Stage 2 penalty stays.              Stage 2 penalty fully reversed
   Your -25 appeal stake               (delta restored to your score).
   stays forfeited.                    You also receive:
   Verdict FINAL.                         +25 stake refund
                                          +10 overturn bonus
                                          +5 vindication bonus
                                       Cradle-to-grave net: +15.
                                       Verdict FINAL.
```

Same flow if you WON Stage 2 and the disputer appealed — except now you're hoping experts UPHOLD (which keeps your win) and dreading OVERTURN (which loses you the case retroactively).

---

## Score math summary — what each outcome costs you

(Numbers below come from the protocol's genesis constants. Penalties are signed deltas applied as paired SCORE_UPDATE txs.)

| Outcome | Score effect |
|---|---|
| You publish content, AI doesn't flag (LOW/ELEVATED) | **0** — registration is free |
| You update origin within the 24h grace window (LOW/ELEVATED content) | **0** — free correction |
| You update origin within the 48h grace window (HIGH/CRITICAL content, before reviewer is assigned) | **0** — free correction |
| Reviewer is assigned, then confirms, you accept correction privately | **-10** (small relabel penalty — but you avoid a public dispute) |
| You retract your own content | **-50** |
| Stage 2 jury sides with you (DISMISSED) | **+5 vindication bonus** |
| Stage 2 CONSERVATIVE_LABEL (you declared AG and the jury confirmed OH — over-declaration) | **0** — content gets relabeled to OH and no score penalty applies (the protocol encourages conservative labeling) |
| Stage 2 jury sides against you (UPHELD) | **Varies — heavy.** Per-pair, per-offense escalation [1st, 2nd, 3rd+]: OH→AG is -100 / -200 / -300. OH→AA is -40 / -80 / -120. AA→AG is -25 / -50 / -75. |
| Stage 3 experts uphold the Stage 2 verdict against you | Same as Stage 2 — final. Your 25-point appeal stake also stays forfeited. |
| Stage 3 experts overturn in your favor | **Cradle-to-grave: +15.** At Stage 3 you receive +35 (stake + overturn bonus) + the full Stage-2 penalty reversed + +5 vindication bonus. Subtract the -25 you paid at appeal-filing and the original Stage-2 penalty already taken, and the net comes out to +15. |

**Key insight: the grace windows are zero-penalty.** Whether AI flags you or not, you have either 24h (LOW/ELEVATED) or 48h (HIGH/CRITICAL) to update the origin label for free. Once a reviewer is assigned (after the 48h flagged window), things start to have small penalties (-10 for accepting their correction privately). Going to public dispute and losing is where the real numbers hit.

**Self-correction is always cheaper than fighting it out and losing.** If you actually used AI, just label it AA or AG. The protocol doesn't punish honesty about AI use — it punishes lying about it.

---

## Notifications you'll see (dashboard feed)

Your dashboard feed (the JSON behind your "To Do" list) emits these author-facing notification types. Each is keyed on a chain event, so they appear / disappear automatically as state changes — no mark-as-read, no inbox.

```
┌────────────────────────────────────────────────────────────────┐
│  type:     content_flagged_for_review                          │
│  priority: high                                                │
│  When:     HIGH or CRITICAL prescan tier, OH origin, age < 48h │
│                                                                │
│  Title:    "{hours}h to reconsider —                           │
│             reviewer engages after that."                      │
│  Summary:  "{ctid} was flagged at {TIER} AI confidence         │
│             ({pct}%). Update the origin to AA / AG / MX        │
│             during this window for a clean exit, or do         │
│             nothing and an independent reviewer will           │
│             examine it at h=48."                               │
│  Action:   [ Update origin ] →                                 │
│            /content/{ctid}/update-origin                       │
│  Deadline: registered_at + CONTENT_GRACE.FLAGGED_MS (48h)      │
│  Dismiss:  self-correct OR clock passes 48h (then B takes over)│
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  type:     content_under_review                                │
│  priority: high                                                │
│  When:     prescan_review.state = TRIGGERED                    │
│                                                                │
│  Title:    "Independent reviewer is examining your content."   │
│  Summary:  "{ctid}: a reviewer was assigned at {ISO}.          │
│             You can still update the origin at zero penalty    │
│             until they decide."                                │
│  Action:   [ Update origin ] →                                 │
│            /content/{ctid}/update-origin                       │
│  Deadline: none (reviewer SLA bounds it server-side)           │
│  Dismiss:  reviewer DISMISS/CONFIRM/RECUSE  OR  self-correct   │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  type:     prescan_review_decision_required                    │
│  priority: high                                                │
│  When:     prescan_review.state = CONFIRMED (reviewer agreed)  │
│                                                                │
│  Title:    "Reviewer confirmed the AI flag —                   │
│             {hours}h to respond."                              │
│  Summary:  "{ctid}: an independent reviewer agreed with the    │
│             {TIER} AI assessment{ and suggested {origin} }.    │
│             Accept the correction privately (-10 reputation)   │
│             or escalate to a public dispute."                  │
│  Action:   [ Respond to reviewer ] → /reviews/{review_id}      │
│  Deadline: confirmed_at + REVIEWER.CREATOR_DECISION_WINDOW (24h)│
│  Dismiss:  you accept correction OR auto-escalates to dispute  │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  type:     dispute_filed_against_me                            │
│  priority: info                                                │
│  When:     CONTENT_DISPUTED tx commits with you as author      │
│                                                                │
│  Title:    "New dispute filed against your content"            │
│  Summary:  "{ctid} — {declared_origin}→{claimed_origin} claim."│
│  Action:   [ View dispute ] → /disputes/{dispute_id}           │
│  Deadline: none (informational; 24h recency on the feed)       │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  type:     verdict_landed  (role: author)                      │
│  priority: info                                                │
│  When:     ADJUDICATION_RESULT lands for a dispute you're in   │
│                                                                │
│  Title:    "Verdict landed on dispute you're party to"         │
│  Summary:  "{ctid} {verdict}."                                 │
│  Action:   [ View dispute ] → /disputes/{dispute_id}           │
│  Recency:  24h, then drops off the dashboard                   │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  type:     appeal_available  (role: author, you LOST Stage 2)  │
│  priority: urgent (≤ 12h left) │ high otherwise                │
│  When:     verdict = UPHELD (disputer won, you lost)           │
│            AND no APPEAL_FILED yet                             │
│            AND within the 48h filing window                    │
│                                                                │
│  Title:    "Your content's verdict was UPHELD —                │
│             appeal closes in {remaining}"                      │
│  Summary:  "Verdict on {ctid} (UPHELD). You can file an appeal.│
│  Action:   [ File appeal ] → /disputes/{dispute_id}/appeal     │
│  Deadline: verdict_at + APPEAL.FILING_WINDOW_HOURS (48h)       │
│  Metadata: { verdict, confirmed_origin,                        │
│              stake_at_risk_for_appeal: 25 }                    │
└────────────────────────────────────────────────────────────────┘
```

**Priority + ordering:** the dashboard sorts by priority descending (`urgent` → `high` → `info`), then by deadline ascending. The `attention_count` field in the feed response counts `urgent` + `high` items — that's the number on your dashboard tab indicator.

**Tier interplay:** none of these notifications gate on your trust tier — creators get them at any score. The actions you can take *in response* are tier-gated though (e.g. you can't dispute your own content; if you accept the reviewer's correction the -10 fires regardless of tier; appeal stake is a flat 25 regardless of tier). So the notifications surface uniformly, and the affordability of each response scales with your score.

---

## The complete journey at a glance

```
You publish content
        ↓
AI prescan runs
        ↓
   ┌────┴────────────────┐
   ↓                     ↓
LOW or ELEVATED      HIGH or CRITICAL
(not strongly        (strongly flagged)
 flagged)                 ↓
   ↓               48h grace window
24h grace                 ↓
(zero penalty           ┌─┴─┐
 to change)             ↓   ↓
   ↓                You      You
After 24h         update    keep
locked in.        (free)    claim
Done.               ↓         ↓
              Done.       After 48h,
                          Reviewer auto-
                          assigned (Stage 1)
                              ↓
                      ┌───────┼────────┐
                      ↓       ↓        ↓
                  Dismiss  Recuse   Confirm
                      ↓        ↓        ↓
                  Back to   Reassign  24h private window
                  normal              opens for you
                  No                       ↓
                  penalty            ┌─────┴─────┐
                                     ↓           ↓
                                 Accept       Don't accept
                                 privately     → public Jury
                                 (-10)         (Stage 2)
                                                ↓
                                        7 jurors vote
                                        (72h commit + 12h reveal)
                                                ↓
                                    ┌───────────┼────────┐
                                    ↓           ↓        ↓
                                Dismissed     Upheld   NoQuorum
                                (you win)   (you lose)  (5+ reveals
                                    ↓           ↓        AND 3+ non-
                                +5 bonus    Heavy        abstain not
                                            penalty      met)
                                                         ↓
                                                    Auto → Experts
                                                    (Stage 3)
                                    ↓           ↓
                          Either side can appeal in 48h
                                            ↓
                          Stage 3: 3 Experts (verdict FINAL,
                                              no further appeal)
```

---

## What you'll see on your screen — the journey moments

### Moment 1: Right after publishing

Content card shows: **"Verified — OH"** (whatever label you chose). Green badge. Done.

### Moment 2: AI flagged your content

Amber badge on the content card. Notification: "AI flagged your content as possibly AI-generated. You have 48 hours to update the label (zero penalty) before a reviewer is assigned."

### Moment 3: Pending review

If you didn't act within the 48h grace window, the badge stays amber. New notification: "A reviewer is examining your content."

### Moment 4: Reviewer's decision

- If DISMISSED: badge returns to green. Notification: "Reviewer cleared the flag."
- If CONFIRMED: notification: "Reviewer agreed with AI. You have 24h to accept correction privately or take it to public dispute."

### Moment 5: Public dispute (Stage 2)

Badge turns red. Public note: "Under dispute by tip://id/US-..."  Jury countdown shown. You can't edit the content during this phase.

### Moment 6: Stage 2 verdict

Notification: "Jury verdict: UPHELD" or "DISMISSED" or "NO_QUORUM"
Your score changes accordingly. Badge updates to match.

### Moment 7: Appeal window (if Stage 2 went against you)

48 hours notification: "You can appeal this verdict. Cost: 25 points staked."  Button to file appeal.

### Moment 8: Stage 3 verdict (if appealed)

Notification: "Expert panel verdict: UPHOLD verdict / OVERTURN. This is final."

Done. Whatever the final verdict is, that's your content's permanent state.

---

## Things people ask

**Why does the protocol care if I used AI?**
Because readers care. Some readers seek human-written content (essays, opinions, creative work). Others are fine with AI. The label lets readers decide. Lying about it breaks the contract with your audience.

**Is using AI bad?**
No. AA / AG / MX are not "bad" labels. They're descriptive. Many great works use AI assistance. **Mislabeling** is what gets penalized — not AI use itself.

**What if AI mis-flags me a lot?**
Self-correct quickly (zero or low penalty), or fight the flag (reviewer → jury can clear you). If you're consistently right and AI is wrong, the system reflects that — your score grows.

**What if I plagiarized — does that come up here?**
Plagiarism is a different concern. TIP's prescan/dispute is specifically about AI-generated origin labeling, not copyright. Plagiarism would be handled by separate (currently informal) channels.

**Can I delete my content?**
You can retract it (-50). The content's metadata stays on the chain — it's append-only — but the body is marked "retracted" and apps hide it.

**Can I appeal if I lose Stage 1 (reviewer)?**
Effectively yes — by not accepting the correction. That auto-escalates to Stage 2 (public Jury). And then if you lose Stage 2, you can appeal to Stage 3 (Experts).

**Can someone dispute my content even after AI didn't flag it?**
Yes — any user with score 550+ can file a public dispute on verified content. They stake 15 points; if they're wrong, they lose it. This is the "I read this and it really doesn't look human" community check on top of AI.

**Do I see who disputed me?**
You see their TIP ID. Not their legal name.

**How long does the whole process take in the worst case?**

```
~24h   grace window (LOW/ELEVATED) — or
~48h   grace window (HIGH/CRITICAL flagged content)
~48h   reviewer SLA
~24h   creator decision window after reviewer CONFIRM
~84h   Stage 2 jury (72h commit + 12h reveal)
~48h   appeal window
~84h   Stage 3 expert panel
─────
~13–14 days worst case
```

Most cases close inside the grace window (you self-correct or AI is wrong). Stage 3 is rare.

---

## Right-now action list at each branch

### You just published — AI flagged you

1. Read AI's reasoning + confidence level.
2. Be honest with yourself: did you use AI? If yes, **update the label to AA/AG/MX inside the 48h window — zero score penalty**.
3. If you really didn't, keep your claim. After 48h a reviewer will examine it. You can still update during those 48h if you change your mind.

### A reviewer confirmed against you

4. Honestly evaluate: was the reviewer right? If yes, **accept correction privately**. Cheap, no public dispute.
5. If you genuinely believe the reviewer was wrong AND you have evidence, take it to public Jury. Be ready for an 84h wait + potential heavy penalty if 4 jurors disagree.

### Jury voted against you

6. Did the jury actually have the relevant info? If you have NEW evidence or you think they missed something specific, **file the appeal within 48h** (costs 25 points on-file at appeal time). If you win at Stage 3, the Stage 2 penalty is fully reversed AND you get +35 from the appellant settlement (25 stake refund + 10 overturn bonus) plus +5 vindication. After offsetting the -25 you paid to file the appeal, the cradle-to-grave net comes out to +15 — the system pays for being right at appeal, not just for winning.
7. If the jury just disagreed with you reasonably, accept it. Appeals only win when there's a genuine error.

### Either way — long-term

8. Watch your overall trust score over time. One bad case doesn't destroy you. Repeated mislabeling does.
9. Use accurate labels. The protocol rewards honesty about AI use, not avoidance of AI use.
