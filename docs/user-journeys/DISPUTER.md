# Disputer Journey

You're a **Disputer** — a user who saw a piece of content and believes the creator labeled it wrong. You're going to challenge it publicly. Real points are at stake — yours, and the creator's.

---

## Why dispute?

The protocol shows every piece of content with an origin label (OH = human, AA = AI-assisted, AG = AI-generated, MX = mixed). If you see content labeled "OH" that you're confident is AI-generated, you can challenge it.

Reasons to dispute:

- AI prescan missed it (low confidence) but the content's clearly AI-made
- Creator's history shows a pattern of AI-mislabeled work
- You're an expert in a domain and recognize generative output
- Reviewer dismissed a flag you disagree with

**Reasons NOT to dispute:**

- You disagree with the creator's opinions / politics — disputes are about origin labels, not content quality
- You don't like the creator — disputes for personal reasons cost you 15 points if you lose
- "It just feels AI to me" — feelings aren't enough; have a basis

---

## Am I eligible?

You qualify if **all** are true:

| Requirement | Why |
|---|---|
| Your trust score is **550 or higher** | Filters out brand-new or untrusted users from spam-disputing |
| You're not disputing your own content | The system filters this automatically |
| You haven't disputed too many times in the last 30 days (5-per-30 days cap per user) | Anti-abuse — prevents serial disputers |

---

## What it costs

**You stake 15 trust score points when you file a dispute.** This is deducted from your score the moment you submit (stake-on-file model: a paired SCORE_UPDATE rides alongside CONTENT_DISPUTED, deducted upfront, refunded only if you win).

| Outcome | Net effect on your score (cradle-to-grave) |
|---|---|
| You win at Stage 2 (Jury UPHELD) | **+5 net** (-15 filing, +15 stake refund, +5 upheld bonus) |
| You partly win at Stage 2 (CONSERVATIVE_LABEL — creator declared AG and the jury confirmed OH; over-declaration with no creator penalty) | **0 net** (-15 filing, +15 stake refund, no bonus) |
| You lose at Stage 2 (DISMISSED) | **-15 net** (filing stake stays forfeited; no settlement event) |
| Jury fails quorum (NO_QUORUM, auto-escalates to Stage 3 Experts) | Settlement is deferred — net depends on the final Stage-3 verdict. Your 15 stays locked until then. |

If you lose at Stage 2 and want to file an appeal, you stake an additional **25 points** (APPELLANT_STAKE). The net math for the appeal path is in the full score table at the bottom.

The cost is real. The protocol uses stake to make sure you have skin in the game. **Don't dispute on a hunch.**

---

## The full journey

### Step 1: Find content worth disputing

You're browsing TIP. You see a piece of content labeled "OH" (Original Human). You read it and you're skeptical.

```
You open the content's detail page
       ↓
You see:
    - Origin label (e.g. "OH")
    - AI prescan tier (e.g. LOW, ELEVATED, HIGH, CRITICAL)
    - Verification count (other users who've verified it)
    - Creator's TIP ID
       ↓
Decide: do I have a real basis to dispute?
```

If yes, look for the **"Dispute this content"** button on the content page.

### Step 2: Build your case

```
┌──────────────────────────────────────────────────────────┐
│  FILE A DISPUTE                                          │
│                                                          │
│  Content:    [content title]                             │
│  Currently:  OH (Original Human)                         │
│                                                          │
│  Your claim — what do you think it actually is?          │
│                                                          │
│      [ AA ]   AI-Assisted                                │
│      [ AG ]   AI-Generated                               │
│      [ MX ]   Mixed                                      │
│                                                          │
│  Evidence (optional but strongly recommended):           │
│                                                          │
│  [_________________________________________________]     │
│  [_________________________________________________]     │
│  [_________________________________________________]     │
│                                                          │
│  Stake: 15 trust score points                            │
│  Refund if you win: 15 + bonus                           │
│  Forfeit if you lose: 15                                 │
│                                                          │
│  [ Cancel ]                  [ File Dispute (sign + 15) ]│
└──────────────────────────────────────────────────────────┘
```

**Evidence makes or breaks your case.** Specific things help jurors:

- Quotes from the content + side-by-side comparison with known AI tools' typical outputs
- Links to the creator's other content with admitted AI use
- Domain-specific reasoning ("as a professional translator, I recognize the pattern of GPT-style sentence cadence here")
- Statistical detectors' output (with disclaimer about their limits)

**Vague evidence loses cases.** "It just sounds AI" doesn't move jurors.

### Step 3: Submit + stake locks in

```
You click "File Dispute"
       ↓
App computes the canonical signed body
You sign with your private key
Submit to API
       ↓
15 points immediately deducted from your trust score (stake-on-file)
       ↓
CONTENT_DISPUTED tx commits to chain
```

You can't take it back from here. The creator + jury are now involved.

### Step 4: AI classifier pass (informational)

Before going to jury, an AI classifier records a confidence score on the chain. This is logged as audit metadata for jurors to consult — it does NOT auto-dismiss or auto-affirm your case.

```
       ↓
AI classifier records confidence on AI_CLASSIFIER_RESULT tx
       ↓
        ┌──────────────────────────┬──────────────────────────┐
        ↓                          ↓
   AI confidence HIGH (>=0.90)   AI confidence below 0.90
        ↓                          ↓
   routing = "escalate_high"    routing = "escalate"
   (jurors see a strong          (jurors see standard
   AI agreement signal)           AI signal)
        ↓                          ↓
   Either way: proceeds to Stage 2 Jury
```

The AI signal helps jurors but doesn't replace them. Every filed dispute reaches a human jury in the current implementation — no path is auto-dismissed.

### Step 5: Jury phase (Stage 2)

```
7 jurors get summoned (random selection from score 700+ users)
       ↓
You wait through their 72h commit phase
       ↓
Then their 12h reveal phase
       ↓
Verdict computed
```

You're not involved during these 84 hours. You watch your "Disputes" feed for the result.

### Step 6: Read the verdict

```
       ┌────────────────────┬────────────────────┬────────────────────┐
       ↓                    ↓                    ↓                    ↓
   DISMISSED            UPHELD                CONSERVATIVE_LABEL    NO_QUORUM
   (you lose)           (you win)             (you partly win)      (auto-escalates)
       ↓                    ↓                    ↓                    ↓
   Your 15 stake         You get +15 stake     Jurors agreed         Auto-escalates
   stays forfeited.      refunded + 5          you were right        to Stage 3
   No settlement         upheld bonus.         but disagreed on      Expert panel.
   event fires.          Content gets          what label.           You wait more —
                         relabeled to          Smallest-penalty      Stage 3 becomes
                         what jurors           label applied.        the first
                         agreed on.            You get +15 stake     authoritative
                                               refunded but          verdict.
                                               NO upheld bonus.
```

### Step 7: If you lost — can you appeal?

Yes. The losing side (you, in this case) has **48 hours** to file an appeal. Costs an additional 25 points staked.

```
You file APPEAL_FILED within 48h
       ↓
-25 points deducted (appeal stake on file)
       ↓
3 Experts get summoned (Stage 3)
       ↓
You wait 84h
       ↓
        ┌──────────────────┬──────────────────┐
        ↓                                     ↓
   Experts UPHOLD jury                 Experts OVERTURN
   (Stage 2 stands; you still lose)    (Stage 2 reversed; you win after all)
        ↓                                     ↓
   Both stakes stay forfeited:          You receive two batched settlements:
   -15 (Stage 2 filing)                  - Appellant settlement: +25 (stake refund)
   -25 (appeal filing)                                            +10 (overturn bonus)
   Net: -40. Verdict FINAL.              - Stage-2 reversal:      +15 (stake refund)
                                                                  +5 (upheld bonus)
                                        Total credited at Stage 3: +55
                                        Cradle-to-grave net: -15 -25 +55 = +15
                                        Content relabels. Verdict FINAL.
```

You appeal only when you genuinely believe the jury got it wrong. The math doesn't favor speculative appeals.

### Step 8: If you won — can the creator appeal?

Yes. The creator has 48h to challenge your win. Same Stage 3 expert path. You then wait through their appeal and either:

- Experts UPHOLD jury → you keep your win + your bonus
- Experts OVERTURN → you lose the case (and your 15 stake — but you only filed the dispute, you didn't appeal, so no 25 lost)

You're a passive participant during Stage 3 if you didn't appeal.

---

## The full timeline

```
HOUR 0:
   You file dispute. -15 stake deducted (stake-on-file).
   AI_CLASSIFIER_RESULT recorded same moment — audit signal, not gating.
   7 jurors picked + summoned in the same atomic batch.

HOURS 0 – 72:
   Stage 2 Jury COMMIT phase.

HOURS 72 – 84:
   Stage 2 Jury REVEAL phase.

HOUR ~84:
   Stage 2 verdict lands. Settlement applied:
       UPHELD             → you get +15 stake refund + 5 upheld bonus
       CONSERVATIVE_LABEL → you get +15 stake refund (no bonus)
       DISMISSED          → no event (your -15 stays forfeited)
       NO_QUORUM          → auto-escalates to Stage 3 immediately; your 15 stays on file

HOURS 84 – 132 (if you lost or want to challenge):
   Appeal window — 48h to file. Filing costs an additional -25.

HOURS 132 – 216 (if you appealed):
   Stage 3 Experts. 72h commit + 12h reveal.

HOUR 216:
   Final verdict. Whatever it is, that's the end. No further appeal.
```

Worst case: ~9 days from file to final. Most disputes settle at Stage 2.

---

## Score math summary

Net = cradle-to-grave change to your trust score across the full dispute lifecycle (filing, settlement, optional appeal). Filing stakes are deducted upfront and only return on a winning verdict.

| Scenario | Cradle-to-grave net |
|---|---|
| Stage 2 UPHELD (you win at the jury) | **+5**  (-15 +15 +5) |
| Stage 2 CONSERVATIVE_LABEL (jury says origin was wrong but disagrees on the new label) | **0**  (-15 +15 +0) |
| Stage 2 DISMISSED, you don't appeal | **-15**  (filing stake stays forfeited) |
| Stage 2 DISMISSED, you appeal, Stage 3 UPHELDS jury | **-40**  (-15 filing -25 appeal, both stay forfeited) |
| Stage 2 DISMISSED, you appeal, Stage 3 OVERTURNS | **+15**  (-15 -25 +35 appellant settlement +20 stage-2 reversal) |
| Stage 2 UPHELD, creator appeals, Stage 3 upholds jury | **+5**  (Stage 2 win stands) |
| Stage 2 UPHELD, creator appeals, Stage 3 OVERTURNS | **-15**  (Stage 2 win reverses: -15 -5 from your settlement) |

Headline: **only file when you genuinely believe you're right and have evidence.** A 50/50 hunch loses you points on average.

---

## Notifications you'll see (dashboard feed)

You sit on the disputer side of the same feed creators read. Two notification types are scoped specifically to you (everything else — jury phases, prescan flow — fires only for the author or jurors).

```
┌────────────────────────────────────────────────────────────────┐
│  type:     verdict_landed  (role: disputer)                    │
│  priority: info                                                │
│  When:     ADJUDICATION_RESULT lands on a dispute you filed    │
│                                                                │
│  Title:    "Verdict landed on dispute you're party to"         │
│  Summary:  "{ctid} {verdict}."                                 │
│            (verdict ∈ UPHELD, DISMISSED, CONSERVATIVE_LABEL,   │
│             NO_QUORUM)                                         │
│  Action:   [ View dispute ] → /disputes/{dispute_id}           │
│  Recency:  24h, then drops off the dashboard                   │
│  Metadata: { verdict, confirmed_origin, resolved_at }          │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  type:     appeal_available  (role: disputer, you LOST)        │
│  priority: urgent (≤ 12h left) │ high otherwise                │
│  When:     verdict = DISMISSED (author won, you lost)          │
│            AND no APPEAL_FILED yet                             │
│            AND within the 48h filing window                    │
│                                                                │
│  Title:    "Your dispute was DISMISSED —                       │
│             appeal closes in {remaining}"                      │
│  Summary:  "Verdict on {ctid} (DISMISSED).                     │
│             You can file an appeal."                           │
│  Action:   [ File appeal ] → /disputes/{dispute_id}/appeal     │
│  Deadline: verdict_at + APPEAL.FILING_WINDOW_HOURS (48h)       │
│  Metadata: { verdict, confirmed_origin,                        │
│              stake_at_risk_for_appeal: 25 }                    │
└────────────────────────────────────────────────────────────────┘
```

**What you DON'T see:** the in-flight jury phases (`juror_commit_required`, `juror_reveal_required`, etc.) are juror-scoped — they only fire for the seven people elected to your case. As the disputer you sit in passive-waiting mode through the 84h commit+reveal window. The dashboard doesn't surface progress because there's nothing you can do during that phase; only the final `verdict_landed` lands when the case settles.

The author's `dispute_filed_against_me` notification fires the moment you file — but that's their dashboard, not yours.

**CONSERVATIVE_LABEL and NO_QUORUM:** neither triggers `appeal_available` on either side. CONSERVATIVE_LABEL has no clear loser (label adjustment without penalty); NO_QUORUM auto-escalates to a Stage-3 expert panel without anyone filing.

**Tier interplay:** you only see these notifications if you've filed a dispute, which requires score 550+. If your score drops below 550 between filing and verdict, your existing disputes still settle — the eligibility check runs at filing time, not at verdict time. The notifications still surface to you regardless.

---

## What you see on your screen — the journey moments

### Moment 1: Filing

The dispute form (shown above). You pick the origin you think it should be, add evidence, sign + submit.

### Moment 2: Right after submission

In your "My Disputes" feed:

```
ds_7b3f… — Filed Just now
Content: [title]
Status:  AI screening...
Stake:   15 (on file)
```

### Moment 3: AI screening pass

```
Status: Going to Jury — 7 jurors summoned
Verdict expected in ~84 hours
```

### Moment 4: Stage 2 in progress

```
Status: 7/7 jurors committed — waiting for reveal phase
                                Reveal opens in ~12 hours
```

Then:

```
Status: 5/7 revealed — verdict computed (5 reveals minimum required; 3+ non-abstain)
Verdict: UPHELD — your dispute won
Your stake: refunded + 5 upheld bonus
Content relabeled: OH → AG
```

### Moment 5: If you lost + want to appeal

```
[Banner] You can appeal this verdict.
        Cost: 25 trust score points.
        Time left: 47h 14m
        [ File appeal ]
```

### Moment 6: After Stage 3 (if appealed)

```
Status: Expert verdict — FINAL
Stage 3 Outcome: UPHELD jury (your appeal failed)
Net for this dispute: -40 trust score
```

Or:

```
Status: Expert verdict — FINAL (OVERTURN)
Net for this dispute: +15 trust score (cradle-to-grave)
```

---

## Things people ask

**Can I dispute multiple things at once?**
Yes, but you're capped at 5 disputes per rolling 30 days per user. The cap prevents serial disputing as harassment.

**What if I'm sure I'm right but I don't want to lose 15 points?**
Then don't dispute. The protocol is designed so the stake reflects the seriousness of the action. If your conviction isn't worth 15 points to you, it's not strong enough to drag jurors in.

**Can I dispute anonymously?**
You're identified by your TIP ID (a pseudonym). Your legal name isn't shown. But the chain has the dispute permanently — and your activity feed shows it. Filing a dispute is a public act.

**What if the creator deletes the content during my dispute?**
They can retract it (-50 to them). The dispute proceeds — content history is on the chain. Retracting doesn't escape the dispute.

**What's "CONSERVATIVE_LABEL" verdict?**
Means jurors agreed something was wrong (you were right to dispute), but they couldn't agree on the new label. The system picks the smallest-penalty label as a fair fallback. You still win + get the refund.

**How much evidence is enough?**
For HIGH/CRITICAL-confidence content (AI prescan already flagged it), even minor evidence helps jurors decide. For LOW-confidence content (AI didn't flag), you need substantial evidence — specific quotes, comparisons, expertise — to convince a majority of the 7 jurors (5+ must reveal; 3+ of those must vote non-abstain) who haven't seen the content before.

**Can I withdraw a dispute?**
No. Once it's on the chain, it's permanent. The stake is locked. Plan accordingly.

**Do I have to provide evidence?**
Technically you can dispute without evidence, but you're almost certain to lose. The 15 points is on the line. Always include evidence.

**Who pays my reward if I win?**
The creator's penalty doesn't fund your reward directly. The system refunds your 15-point filing stake plus a fixed +5 UPHELD bonus, drawn from the protocol's incentive budget. The creator separately takes their own penalty (-25 to -300 depending on the origin swap and offense count). The two are independent.

**What if AI changed its mind after my dispute?**
AI runs once at registration. The AI classifier in dispute resolution is a separate pass. They can give different answers. Jurors weigh both.

---

## Right-now action list

Before clicking "Dispute":

1. **Re-read the content** completely. Don't react to a snippet.
2. **Write your evidence draft.** If you can't articulate WHY you think it's mislabeled, that's a signal to step back.
3. **Check the AI prescan tier** on the content. If AI also says HIGH/CRITICAL, your dispute has air support. If AI said LOW and you disagree, you need more evidence.
4. **Check your own score and budget.** You're risking 15 points (or up to 40 with appeal). If your score is 410 and you can't afford to drop to 395, don't dispute.
5. **Confirm you don't have a personal beef** with the creator. Disputes are about origin labels, not personalities.
6. **Click File. Stake. Wait 84 hours.** Don't doom-scroll the dispute feed — verdict will come.
7. **If you lose, accept it.** Appeals only make sense when you have NEW evidence or the jury clearly missed something. Don't appeal out of spite.

Two clean outcomes:
- **You were right → +5 net at Stage 2 (or +15 if you had to appeal and won), and content gets corrected for the community.**
- **You were wrong → -15 (no appeal) to -40 (lost the appeal too). Take the lesson, move on.**

The protocol rewards careful, well-supported disputes. Use the tool seriously.
