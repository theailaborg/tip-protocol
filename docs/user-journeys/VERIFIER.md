# Verifier Journey

You're a **Verifier** — a user who reads someone else's content and attests publicly that the origin label looks right. Your signature on the chain says: *"I read this, and yes, OH (or AA / AG / MX) is the correct label."*

You're the community's positive-signal layer. Disputers raise red flags; verifiers raise green ones. Both keep the label honest.

---

## Why verify?

The protocol shows every piece of content with an origin label. Most readers scroll past without acting. Verifiers are the small fraction who take a second to say: *"I looked, I agree."*

Reasons to verify:

- Content from a creator you follow and trust
- You're a domain expert and recognize the labeling as accurate
- The piece is clearly human-made and you want to push back against false AI-flag noise
- Quietly raising the author's reputation when they got the call right

**Reasons NOT to verify:**

- You skimmed it and don't really know — verification is a public attestation, treat it as such
- You like the creator personally — verify the *content*, not the person
- You want to game the author's score — caps + weighting make this not worth the cycles

---

## Am I eligible?

You qualify if **all** are true:

| Requirement | Why |
|---|---|
| Your trust score is **650 or higher** | Filters out brand-new accounts from rubber-stamping content for friends |
| You're not the author of the content | The system filters this automatically |
| You haven't already verified this specific piece | One verification per verifier per content |
| The content is in a verifiable state — not RETRACTED, DISPUTED, or PENDING_REVIEW | You can't attest to something that's mid-dispute or pulled |
| The author isn't revoked | Revoked authors can't accumulate further verification weight |

No opt-in toggle needed. Verification is on-demand: you see a piece, you decide to verify it, you sign + submit. No assignments, no summons, no clock.

---

## What it costs

**Verifying is free.** No stake, no score deducted, no risk to you personally.

The author gets a weighted score delta from your attestation; you contribute the weight, you don't pay it. The protocol's "cost" of verification is enforced through **caps** (so a single verifier can't move someone's score arbitrarily), not through stakes.

---

## What your verification is worth

The weight of your verification depends on YOUR trust score at the moment you sign:

| Your trust score | Contribution to author's score |
|---|---|
| **800 or higher** (high-trust) | **+3** per verification |
| 650–799 | **+2** per verification |
| Below 650 | (you can't verify — eligibility floor) |

This is `VERIFY_CAPS.HIGH_TRUST_DELTA` (= 3) and `VERIFY_CAPS.BASE_DELTA` (= 2) from the protocol constants.

So a high-trust verifier moves the needle 50% harder than a regular one. Which means: as your own score climbs, your verifications matter more.

---

## Caps — what limits the impact

Three rolling caps keep verification from being a brigading vector:

| Cap | Limit | What happens at saturation |
|---|---|---|
| **Per content** | +5 total weighted delta from all verifiers combined | Your verification still commits, but the delta applied is 0 (the chain caps it) |
| **Per day** | +5 weighted delta per author per UTC day | Same — your verification commits but the author's score isn't moved further today |
| **Per month** | +30 weighted delta per author per rolling 30 days | Same |

(These are `VERIFY_CAPS.PER_CONTENT = 5`, `PER_DAY = 5`, `PER_MONTH = 30` from the current genesis settings.)

The chain computes your effective delta as:

```
applied_delta = min(
    your_base_or_high_trust_delta,
    per_content_remaining,
    per_day_remaining,
    per_month_remaining
)
```

So if a piece has already received +5 worth of verifications, the next verifier adds **0** — but the verification still lands on chain as an attestation. Your name is still associated with the call.

---

## The full journey

### Step 1: Find content worth verifying

You're browsing TIP. You see a piece labeled "OH" that you've read carefully and you agree with the label.

```
You open the content's detail page
       ↓
You see:
    - Origin label (e.g. "OH")
    - Trust tier badge of the author
    - AI prescan tier (e.g. LOW, ELEVATED, HIGH, CRITICAL)
    - Verification count (how many others have already verified)
    - Verify button
       ↓
Decide: do I want to attest to this label?
```

### Step 2: Sign + submit

```
┌──────────────────────────────────────────────────────────┐
│  VERIFY THIS CONTENT                                     │
│                                                          │
│  Content:    [content title]                             │
│  Currently:  OH (Original Human)                         │
│  Author:     tip://id/IN-... (T2 — trust score 720)      │
│                                                          │
│  Your verdict:                                           │
│      [ ORIGIN_CONFIRMED ]   "Yes, the label is correct"  │
│                                                          │
│  Your contribution:                                      │
│      Your score: 712 → base delta (+2)                   │
│      (At score 800+ your verifications contribute +3.)   │
│                                                          │
│  Caps:                                                   │
│      Per content: 4 of 5 used → your delta caps at +1    │
│      Per day:     2 of 5 used (for this author)          │
│      Per month:  19 of 30 used (for this author)         │
│                                                          │
│  [ Cancel ]                  [ Verify (sign + submit) ]  │
└──────────────────────────────────────────────────────────┘
```

You click Verify. The app builds the canonical signed body (`verifier_tip_id`, `ctid`, `verdict`), signs it with your private key, and submits to `POST /v1/content/:ctid/verify`. The chain commits a `CONTENT_VERIFIED` tx attributed to you.

### Step 3: Done

No follow-up. No commit/reveal phase. No 84-hour wait. Verifications are one-shot: you sign, the chain commits, the author's score moves (subject to caps), and you walk away.

You can verify another piece immediately — subject to the per-day / per-month / per-author caps.

---

## What if content I verified later gets disputed?

Your verification is on the chain forever, regardless of the dispute outcome.

- **Dispute filed** → content moves to `DISPUTED` status. New verifications are blocked, but yours stays committed.
- **Jury UPHELD (creator was wrong)** → the content gets relabeled. Your `CONTENT_VERIFIED` tx is still on the chain attesting to the *original* label. No score penalty hits you — the weight you contributed simply doesn't reverse.
- **Jury DISMISSED (creator was right)** → your verification is implicitly vindicated. Still no direct score impact on you (verifiers don't get bonuses), but the public record shows you backed the right call.

There's no "verifier penalty" for being wrong. The system doesn't second-guess your attestation. The reasoning: if a single bad verification cost you score, careful verifiers would simply stop verifying — and the community attestation signal would dry up. So the protocol opts for *cap-the-weight* over *punish-the-verifier*.

That said, your verification history is public. A pattern of verifying content that later gets UPHELD against the creator is a reputation signal others can read, even if it doesn't move your numeric score.

---

## Score math summary

(Cradle-to-grave change to YOUR trust score from one verification.)

| Scenario | Effect on your score |
|---|---|
| You verify content, caps not hit | **0** — verifying is free |
| You verify content, caps already hit | **0** — verification commits, no score moves |
| Content you verified later gets DISMISSED in a dispute (creator wins) | **0** — verifiers don't get vindication bonuses |
| Content you verified later gets UPHELD against the creator (you were wrong) | **0** — no verifier penalty |

The author's side of the math is what your verification actually moves:

| Your score | Author's gain per verification (uncapped) |
|---|---|
| 800+ | **+3** |
| 650–799 | **+2** |

Subject to per-content cap of 5, per-day cap of 5, per-month cap of 30 per author.

---

## What you see on your screen — the journey moments

### Moment 1: Browsing content

Each content card shows the current verification count next to the origin label — e.g. *"OH · ✓ 7 verifications"*. If you're eligible (score 650+, not the author, haven't verified this one), a **Verify** button is enabled. If not eligible, it's disabled with the reason on hover.

### Moment 2: Filing your verification

The verify modal (shown above). One screen, three pieces of info: your current weight (+2 or +3), the caps remaining, and a sign-and-submit button. No second confirmation.

### Moment 3: Right after submission

In your "My Verifications" feed (or activity history):

```
[ctid_abc…] — Verified Just now
Content:   [title]
Verdict:   ORIGIN_CONFIRMED
Weight:    +2 (capped to +1 by per-content remaining)
```

### Moment 4: Long-term

Your verifications stay in your activity history forever. The author's score reflects your contribution (capped). If the content gets disputed later, you'll see a status note on the entry — but no action is required from you.

---

## Notifications you'll see (dashboard feed)

**None scoped to verifiers.** Verification is a fire-and-forget action, so the dashboard feed doesn't surface any verifier-specific notification types.

You'll still see your own verifications in your **activity feed** (`GET /v1/identity/:tipId/activity`) as `CONTENT_VERIFIED` tx entries — but that's a history view, not a notification.

If a dispute later lands on content you verified, you can see it through the content's own status page, but the chain doesn't push a "your verification was implicated" notification — you're not a party to the dispute, just an earlier attestor.

---

## Things people ask

**Why is there a score floor at all? Doesn't this shut out new users?**
The 650 floor (the threshold currently documented for verifiers, set above the disputer floor of 550) keeps fresh accounts from being recruited to rubber-stamp a friend's content the day they sign up. Score 650 is reachable by anyone who's been on the protocol a few weeks publishing honestly — it's not a high bar for genuine users.

**Why don't I earn anything for verifying?**
Verifiers are the easy-mode positive signal. If the protocol rewarded verifications, the rational play would be to verify everything you see and farm the bonus. Keeping it free-but-unrewarded means people who verify do it because they actually read and agreed — same logic as the upvote button on most platforms.

**Can I un-verify?**
No. Once on the chain, your `CONTENT_VERIFIED` tx is permanent. Think before you sign.

**Can I verify something I'm not 100% sure about?**
You can, but you probably shouldn't. The chain doesn't penalize you, but your verification history is public — and verifying something that later gets UPHELD against the creator is a record others can read.

**What about content with AI prescan flagged HIGH/CRITICAL — can I verify it?**
Only if the content is still in `REGISTERED` status. The moment a reviewer is assigned (status → `PENDING_REVIEW`) or a dispute is filed (`DISPUTED`), verifications are blocked. So in practice: HIGH/CRITICAL flagged content has a narrow window between registration and the reviewer assignment where verification is still possible. Most verifiers wait until the dust settles.

**What if a creator I follow gets disputed a lot — does verifying them hurt me?**
Not directly. Your score doesn't move based on the disputes their content faces. What it does affect is your *visible verification history* — if you consistently verify content that later loses disputes, careful readers will weight your verifications lower over time. Reputation, not score.

**How often can I verify?**
Per author you target, you're capped at 5 weighted delta per day and 30 per month. Across different authors, there's no overall daily cap on you personally — you can verify hundreds of pieces a day across many authors. The per-author caps prevent collusion / sock-puppet farming.

**Do I see who else verified the same content?**
Yes — the chain has every `CONTENT_VERIFIED` tx with the verifier's TIP ID. The UI typically shows recent verifier IDs on the content detail page.

**Can verifications be revoked or invalidated?**
Only when the author themselves gets revoked. Then the chain stops counting weight from past verifications going forward, but the tx history stays. Individual verifications can't be removed by the verifier or the author.

---

## Right-now action list

Before clicking **Verify**:

1. **Actually read the content** — the whole thing, not just the headline.
2. **Form a real opinion** about whether the origin label matches what you read.
3. **Check your own score** to see your contribution weight (+2 below 800, +3 at 800+).
4. **Glance at the cap status** — if the content is already at +5, your verification is free public attestation but doesn't move the author's score.
5. **Sign + submit.** No commit phase, no reveal phase. One click.
6. **Move on.** No follow-up needed.

The protocol rewards thoughtful verifications by giving them weight, not money. Use the tool when you've actually read the piece and you actually agree. That's it.
