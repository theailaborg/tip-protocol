# User Journeys

Plain-language guides for the six roles a person can play on TIP. Each guide walks you through the **complete journey** for that role — what you see, what you decide, and what you earn or risk.

Written for people who use the app, not for engineers.

## The six roles

### Everyday roles (most users will be these)

| Role | Who you are | Time commitment |
|---|---|---|
| **[Creator](CREATOR.md)** | A normal user who publishes content. Most people on TIP are creators. This guide covers what happens when AI flags your content, when someone disputes you, and how to handle each step. | A few seconds at publish time. Occasionally hours if something gets contested. |
| **[Verifier](VERIFIER.md)** | A user who reads someone else's content and publicly attests that the origin label looks right. The positive-signal counterpart to disputing. Score 650+. | Seconds per verification — one click after reading. |
| **[Disputer](DISPUTER.md)** | A user who saw a piece of content and believes it's mislabeled (e.g. claimed "OH — human" but looks AI-generated). You challenge it publicly. | Filing takes minutes. Waiting for verdict takes ~3 days. |

### Adjudication roles (opt-in; high trust score required)

| Role | When you're called | Time commitment |
|---|---|---|
| **[Reviewer](REVIEWER.md)** | When AI flags content as possibly AI-generated. You decide: was the AI right or wrong? Score 800+, opt-in. | Up to 48 hours per case |
| **[Juror](JUROR.md)** | When a community member publicly disputes a piece of content. You're one of 7 jurors who vote on it. Score 700+, opt-in. | 72 hours to vote + 6 hours to reveal |
| **[Expert](EXPERT.md)** | When someone challenges a jury's verdict (appeals). You're one of 3 experts who make the final call. Score 850+, opt-in. | 72 hours to vote + 6 hours to reveal |

## How they fit together

```
Someone publishes content
          ↓
   AI scans it
          ↓
   Did AI flag it?  ── No → published as-is, done
          ↓ Yes (HIGH or CRITICAL flag)
          ↓
   ┌─────────────────┐
   │  STAGE 1        │   ← Reviewer steps in
   │  Reviewer       │
   └────────┬────────┘
            ↓
   Did Reviewer dismiss it (AI was wrong)?
            ↓
       Yes → content restored, done
       No (CONFIRM) → creator gets 24h to admit/fix privately
                       ↓
       Creator stays silent or refuses
                       ↓
   ┌─────────────────┐
   │  STAGE 2        │   ← 7 Jurors take over
   │  Public dispute │
   └────────┬────────┘
            ↓
   Jury votes — majority wins
            ↓
   Did either side appeal within 48h?
            ↓
       No → verdict final, done
       Yes (someone files appeal) →
                       ↓
   ┌─────────────────┐
   │  STAGE 3        │   ← 3 Experts settle it
   │  Final appeal   │
   └────────┬────────┘
            ↓
   Expert panel votes — verdict final, no further appeal
```

## How the roles connect

You may play different roles at different times. A typical TIP user is **always** a Creator (when they publish), **sometimes** a Verifier or Disputer (when they react to other people's content), and **occasionally** a Reviewer / Juror / Expert (if they opt in and qualify by score).

```
You publish content                   →  CREATOR
You read & agree with a label         →  VERIFIER (score 650+, free attestation)
You see content that looks mislabeled →  DISPUTER (you stake 15 pts to file)
AI flags someone's content            →  REVIEWER (called automatically, score 800+)
A dispute escalates to public jury    →  JUROR (1 of 7, score 700+, stake 10 pts)
A jury verdict gets appealed          →  EXPERT (1 of 3, score 850+, stake 25 pts)
```

## Some things to know before you read

- **Anonymous** — you don't see who flagged the content, who's disputing it, or who else is on the jury/panel. The creator doesn't see who you are either. Only your decision is public on the chain (under your TIP ID pseudonym).
- **You can opt out anytime** — turn off "I want to help adjudicate" in your profile and you stop getting picked for adjudication roles.
- **No tokens** — you earn trust score (your reputation on the protocol), not money. Trust score makes you visible, trustworthy, and qualifies you for higher-tier roles.
- **You can decline a specific case** — if you know the creator personally or have a stake, recuse yourself. It's free and the right thing to do.
- **You have skin in the game where it matters** — Disputers stake 15, Jurors stake 10, Experts stake 25. Reviewers don't stake. Creators don't stake (but lose points if their content is mislabeled). Vote/decide with the majority → get it back + bonus. Vote/decide against → lose it.

Pick the role you're playing today and read its guide.
