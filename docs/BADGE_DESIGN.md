# Badge Visual Design Specifications

This document defines the visual specifications for all TIP Protocol badges.
Implementors must follow these specifications precisely. Deviation constitutes
trademark misuse under TIPCL-1.0 Section 7(2).

---

## Two Badge Objects

TIP Protocol uses two visually and legally distinct badge objects. These are
**not interchangeable** and must never be confused:

| Badge | Name | Issued by | License |
|-------|------|-----------|---------|
| ![Seal](seal-preview) | **AI Trust ID™ Seal** | The AI Lab Intelligence Unobscured, Inc. registry only | Trademark: registry-issued |
| ![Mark](mark-preview) | **TIP Powered Mark** | Any compliant implementation | TIPCL-1.0: free for compliant implementations |

---

## Object 1: AI Trust ID™ Seal

The Seal is a personal trust credential issued by The AI Lab registry to
verified individuals. It cannot be self-applied or generated independently.

### Visual Structure

```
┌──────────────────────────────────────┐
│  ╭─────────────────────────────────╮ │
│  │  ● FOUNDING STAR (if founding)  │ │  ← Upper right ring position
│  │         ╭─────╮                 │ │
│  │         │  ✓  │  [TIER COLOR]   │ │  ← Shield icon (score-colored)
│  │         │ 892 │                 │ │  ← Numeric score (if FULL_PUBLIC)
│  │         ╰─────╯                 │ │
│  │  AI TRUST ID   ← Arc text top   │ │
│  │  AI TRUST REGISTRY ← Arc bottom │ │
│  ╰─────────────────────────────────╯ │
└──────────────────────────────────────┘
```

### Dimensions

| Size | Outer diameter | Inner ring | Shield size |
|------|---------------|-----------|-------------|
| 40px | 40px | 32px | 18px |
| 80px (default) | 80px | 64px | 36px |
| 120px | 120px | 96px | 54px |
| 200px | 200px | 160px | 90px |
| 400px | 400px | 320px | 180px |

### Colors

**Colorway: Gold Dark (default)**
- Outer ring: `#C9A84C` (gold metallic)
- Background: `#0B1629` (deep navy)
- Shield color: tier-dependent (see Trust Tier Colors below)
- Text: `#C9A84C` (gold)
- Founding star: `#FFD700` (bright gold) at 12° upper right

**Colorway: Light**
- Outer ring: `#B8942E`
- Background: `#F8F9FB`
- Shield color: tier-dependent
- Text: `#0C1A3A`

**Colorway: Dark**
- Outer ring: `#C9A84C`
- Background: `#1B2A4A`
- Shield color: tier-dependent
- Text: `#E2E6EE`

### Trust Tier Colors (Shield)

| Tier | Score | Color | Hex |
|------|-------|-------|-----|
| HIGHLY_TRUSTED | 800-1000 | Green | `#1A8A5C` |
| TRUSTED | 600-799 | Blue | `#2563A8` |
| REVIEW_ADVISED | 400-599 | Amber | `#A88B15` |
| LOW_TRUST | 200-399 | Orange | `#C07318` |
| NOT_TRUSTED | 0-199 | Red | `#C53030` |

### Shield Icons

| Score | Icon | Meaning |
|-------|------|---------|
| ≥ 600 | ✓ (checkmark) | Trusted |
| 400-599 | ! (exclamation) | Review Advised |
| < 400 | ✗ (cross) | Low Trust / Not Trusted |

### AMBER Jurisdiction Indicator (v2)

When issued by an AMBER-tier VP:
- Amber dot (6px at 80px size) at upper-left of inner ring
- Color: `#A88B15`
- Hover/tap: "Issued in an amber-tier jurisdiction: tap for details"
- No indicator for GREEN-tier VPs

### Arc Text Typography

- Font: Cormorant Garamond, fallback Georgia, serif
- Top arc: "AI TRUST ID": letter spacing 3
- Bottom arc: "AI TRUST REGISTRY": letter spacing 2
- Size: 4.5% of outer diameter
- Rendering: SVG textPath on a circular arc path

### Score Display (respects GDPR visibility mode)

| Mode | Display |
|------|---------|
| FULL_PUBLIC | Numeric score (e.g., "892") |
| TIER_ONLY | Tier label only (e.g., "TRUSTED") |
| VERIFIED_ONLY | Checkmark only: no score, no tier label |

---

## Object 2: TIP Powered Mark

The Mark is an open compliance badge. Any platform implementing the TIP
Protocol specification may display it under TIPCL-1.0.

### Visual Structure

```
┌──────────────────────────┐
│  ╭────────────────────╮  │
│  │  ┌───┐             │  │
│  │  │TIP│             │  │  ← Protocol acronym
│  │  └───┘             │  │
│  │  TRUST IDENTITY     │  │  ← Arc text top
│  │  PROTOCOL           │  │
│  │  OPEN SPEC · TIPCL  │  │  ← Arc text bottom
│  ╰────────────────────╯  │
└──────────────────────────┘
```

### Mark Colors

**Light variant (for dark backgrounds)**
- Ring: `#CBD5E0`
- Background: transparent
- Text: `#CBD5E0`

**Dark variant (for light backgrounds)**
- Ring: `#4A5568`
- Background: transparent
- Text: `#4A5568`

**Color variant**
- Ring: `#2563A8` (blue)
- Background: `#EBF0F8`
- Text: `#0C1A3A`

### Mark Sizes

Minimum display size: 40px. Do not display the Mark below 40px.

---

## Shield Badge (Inline / Compact)

For use in article bylines, comment sections, and compact layouts where
the full Seal is too large.

```
[▣ TRUSTED]   or   [▣ 892]
```

- Width: 2× height (e.g., 16px tall × 32px wide)
- Left: tier-colored shield icon
- Right: tier label or numeric score (per visibility mode)
- Border radius: 3px
- Background: `tier_color + "15"` (15% opacity)

---

## Origin Badges

Origin badges display the content's declared origin type. Used in article
headers, content management systems, and browser extensions.

| Code | Label | Color | Icon |
|------|-------|-------|------|
| OH | Original Human | `#2563A8` (blue) | ✏ |
| AA | AI-Assisted | `#7C3AED` (purple) | ⚡ |
| AG | AI-Generated | `#C07318` (amber) | ⬡ |
| MX | Mixed | `#4A5568` (gray) | ◈ |

Status overlays (applied to top-right of origin badge):
- PENDING: amber dot
- DISPUTED: orange dot
- VERIFIED: no overlay (clean)
- REVOKED: red dot

---

## Usage Rules

### What you MUST do

- Display the badge at full fidelity (no cropping of the ring or text)
- Link the badge to theailab.org or theailab.org/verify
- Use the correct badge for your context (Mark for platforms, Seal for users)
- Respect the user's GDPR score visibility mode

### What you MUST NOT do

- Modify the badge colors, typography, or ring proportions
- Add third-party branding inside the badge ring
- Animate the badge in a way that distorts the logo
- Display the AI Trust ID™ Seal without registry issuance
- Display a Seal for a TIP-ID with `revoked` status

### Minimum clear space

Surround the badge with clear space equal to 25% of the badge's diameter.
Do not place text, other logos, or decorative elements inside this clear space.

---

## Web Component (`<tip-badge>`)

```html
<!-- Full seal -->
<tip-badge tip-id="tip://id/US-a3f8c91b" size="120" variant="gold-dark"></tip-badge>

<!-- TIP Powered Mark -->
<tip-badge type="mark" size="80" variant="light"></tip-badge>

<!-- Shield only (for bylines) -->
<tip-badge type="shield" tip-id="tip://id/US-a3f8c91b" size="32"></tip-badge>

<!-- Auto-scan mode (reads page meta tags) -->
<tip-badge auto size="80"></tip-badge>

<!-- Origin badge -->
<tip-badge type="origin" origin="OH" status="verified" size="48"></tip-badge>
```

The web component fetches trust score data from the TIP node specified in the
`TIP-Author` meta tag, the `tip-node` meta tag, or the component's
`node-url` attribute (in that order).

---

## SVG Export

All badge variants are available as standalone SVG files at:

```
https://badge.theailab.org/svg/seal-{size}-{variant}.svg
https://badge.theailab.org/svg/mark-{size}-{variant}.svg
https://badge.theailab.org/svg/shield-{tier}-{size}.svg
https://badge.theailab.org/svg/origin-{code}-{status}.svg
```

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*  
*AI Trust ID™, AI Trust Registry™, TIP™ are trademarks of The AI Lab.*  
*Badge designs are proprietary. TIP Powered Mark is licensed under TIPCL-1.0.*
