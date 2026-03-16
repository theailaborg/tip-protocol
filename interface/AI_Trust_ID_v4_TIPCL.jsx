/**
 * AI Trust ID™ Interface v4: Production Build
 * Protocol: TIP™ v2.0 | Build: 2026 Q1 | Distribution: Partners + Investors
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc. All rights reserved.
 * Authored by Dinesh Mendhe | theailab.org
 *
 * VIEW MODES:
 *   PUBLIC  Community-facing. Protocol overview, registration guide, content
 *           origin system, developer integration, full badge gallery, privacy.
 *
 *   ADMIN   Leadership + investor use. All public content plus: Licensing +
 *           Revenue, Launch Plan, Command Center [ACTION], Responsibility Matrix,
 *           VP Strategy, Genesis Ring governance, Privacy Arch., Revocation,
 *           GDPR, Jurisdiction Tiers.
 *           Credentials: admin@theailab.org / TIP2026!Launch
 *
 * BADGE GALLERY (Badges tab, 6 sub-tabs):
 *   Seals: 3 variants x 5 tiers x 6 sizes
 *   Shields: 5 tiers x 4 sizes + founding variant
 *   Origin: 4 origins x 5 status states x 3 sizes
 *   Score Chips: GDPR display modes (full/score/tier/dot/verified)
 *   Bylines: byline + feed card + YouTube integration
 *   Embed Code: HTTP headers, meta tags, web component, REST API reference
 *
 * v2 SECURITY FIXES:
 *   FIX-02 Privacy Architecture: peppered dedup hash, ZK proof, dedup registry
 *   FIX-03 Pre-Scan Calibration: creator-calibrated thresholds, content-type
 *   FIX-05 Identity Revocation: four tx types, cascading content effects
 *   FIX-06 GDPR Compliance: score display modes, Art.17 erasure, DPIA, DPO
 *   FIX-08 Jurisdiction Tiers: Green/Amber/Red VP classification
 *
 * TIP™, AI Trust ID™, AI Trust Registry™, The Global Seal of Trust™ are
 * trademarks of The AI Lab Intelligence Unobscured, Inc.
 *
 * LICENSING:
 *   Protocol Specification: CC-BY 4.0 (free for everyone, attribution required)
 *   Reference Implementation: TIP Community License v1.0 (TIPCL-1.0)
 *     - Free for individuals, nonprofits, journalists, governments, <$500K rev
 *     - Commercial license required for enterprises above $500K annual revenue
 *     - Mandatory attribution in UI: "Built on TIP Protocol by The AI Lab"
 *     - Converts to Apache 2.0 on January 1, 2031
 *     - NOTICE file attribution survives conversion permanently
 *     - Trademarks (TIP™, AI Trust ID™) reserved by The AI Lab permanently
 *   licensing@theailab.org | theailab.org/licensing
 */

import { useState, useEffect } from "react";

// ─── Design tokens ────────────────────────────────────────────────────────────
const C = {
  bg: "#FFFFFF", surface: "#F8F9FB", surfaceRaised: "#F1F3F7",
  border: "#E2E6EE", borderLight: "#D0D5E0",
  gold: "#B8942E", goldDim: "#B8942E12", goldGlow: "#B8942E22",
  navy: "#0C1A3A", navyLight: "#1B2A4A",
  textPrimary: "#0C1A3A", textSecondary: "#4A5568", textMuted: "#8895A7",
  green: "#1A8A5C", blue: "#2563A8", red: "#C53030",
  orange: "#C07318", yellow: "#A88B15",
  purple: "#7C3AED", teal: "#0D7490",
  adminAccent: "#1B2A4A",
};

const SERIF = "'Cormorant Garamond', Georgia, serif";
const SEAL_GOLD = "#C9A84C";
const SEAL_NAVY = "#0B1629";

// ─── Shared visual primitives ─────────────────────────────────────────────────

function ShieldBadge({ score, size = 48, founding = false }) {
  const color = score >= 800 ? C.green : score >= 600 ? C.blue : score >= 400 ? C.yellow : score >= 200 ? C.orange : C.red;
  const borderColor = founding ? C.gold : color;
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none">
      <path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z" fill={`${color}12`} stroke={borderColor} strokeWidth={founding ? 2.5 : 2} />
      {score >= 600 && <path d="M16 24L22 30L34 18" stroke={color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />}
      {score >= 400 && score < 600 && <text x="24" y="29" textAnchor="middle" fill={color} fontSize="16" fontWeight="bold">!</text>}
      {score < 400 && <><line x1="17" y1="19" x2="31" y2="33" stroke={color} strokeWidth="3" strokeLinecap="round" /><line x1="31" y1="19" x2="17" y2="33" stroke={color} strokeWidth="3" strokeLinecap="round" /></>}
    </svg>
  );
}

function ArcLetters({ cx, cy, text, radius, startDeg, endDeg, fontSize, fill, flip = false, weight = "600" }) {
  const chars = text.split("");
  const span = endDeg - startDeg;
  const step = span / (chars.length - 1 || 1);
  return (
    <g>
      {chars.map((ch, i) => {
        const deg = flip ? endDeg - i * step : startDeg + i * step;
        const rad = (deg - 90) * Math.PI / 180;
        const x = cx + radius * Math.cos(rad);
        const y = cy + radius * Math.sin(rad);
        return (
          <text key={i} x={x} y={y} textAnchor="middle" dominantBaseline="middle"
            fontSize={fontSize} fill={fill} fontFamily={SERIF} fontWeight={weight}
            transform={`rotate(${flip ? deg + 180 : deg},${x},${y})`}>{ch}</text>
        );
      })}
    </g>
  );
}

function TrustIDSeal({ score, size = 200, variant = "gold-dark", founding = false }) {
  const tiers = [
    { min: 800, color: C.green }, { min: 600, color: C.blue },
    { min: 400, color: C.yellow }, { min: 200, color: C.orange }, { min: 0, color: C.red },
  ];
  const tc = (tiers.find(t => score >= t.min) || tiers[4]).color;
  const S = size, cx = S / 2, cy = S / 2;
  const R = S / 2 - S * 0.028, tR = R - S * 0.062, iR = R - S * 0.135;
  const sW = S * 0.19, sH = S * 0.24, sX = cx - sW / 2, sY = cy - S * 0.30;
  const shield = `M${cx} ${sY} L${sX} ${sY+sH*.28} V${sY+sH*.62} C${sX} ${sY+sH*.9} ${cx-sW*.02} ${sY+sH*.99} ${cx} ${sY+sH} C${cx+sW*.02} ${sY+sH*.99} ${sX+sW} ${sY+sH*.9} ${sX+sW} ${sY+sH*.62} V${sY+sH*.28}Z`;
  const shieldCY = sY + sH * 0.52;
  const ck = { x1: cx-sW*.26, y1: shieldCY+sH*.06, x2: cx-sW*.02, y2: shieldCY+sH*.22, x3: cx+sW*.28, y3: shieldCY-sH*.10 };
  const xC = cx, yC = shieldCY, xo = sW * 0.22, yo = sH * 0.24;
  const isGold = variant === "gold-dark", isLight = variant === "light";
  const uid = `tis${Math.round(score)}${size}${variant.slice(0,2)}`;
  const bgFill = isGold ? `url(#bg${uid})` : isLight ? "#FFFFFF" : "#0A0A0A";
  const ringStroke = isGold ? `url(#rg${uid})` : isLight ? "#111" : "#FFF";
  const arcFill = isGold ? `url(#rg${uid})` : isLight ? "#111" : "#FFF";
  const dimFill = isGold ? "#4A6080" : isLight ? "#666" : "#888";
  return (
    <svg width={S} height={S} viewBox={`0 0 ${S} ${S}`} fill="none" xmlns="http://www.w3.org/2000/svg" style={{ display: "block" }}>
      <defs>
        {isGold && <>
          <radialGradient id={`rg${uid}`} cx="50%" cy="22%" r="78%">
            <stop offset="0%" stopColor="#EDD67A"/><stop offset="52%" stopColor={SEAL_GOLD}/><stop offset="100%" stopColor="#7A5510"/>
          </radialGradient>
          <radialGradient id={`bg${uid}`} cx="50%" cy="36%" r="64%">
            <stop offset="0%" stopColor="#16243E"/><stop offset="100%" stopColor={SEAL_NAVY}/>
          </radialGradient>
        </>}
        <filter id={`sh${uid}`} x="-18%" y="-18%" width="136%" height="136%">
          <feDropShadow dx="0" dy={S*.016} stdDeviation={S*.022} floodColor={isLight ? "rgba(0,0,0,0.10)" : "rgba(0,0,0,0.5)"}/>
        </filter>
      </defs>
      <circle cx={cx} cy={cy} r={R} fill={bgFill} filter={`url(#sh${uid})`}/>
      <circle cx={cx} cy={cy} r={R} stroke={ringStroke} strokeWidth={S*.015} fill="none"/>
      <circle cx={cx} cy={cy} r={iR} stroke={ringStroke} strokeWidth={S*.004} fill="none" opacity=".16"/>
      {[-148, 148].map((deg, i) => { const rad = (deg-90)*Math.PI/180; return <circle key={i} cx={cx+tR*Math.cos(rad)} cy={cy+tR*Math.sin(rad)} r={S*.007} fill={ringStroke} opacity=".35"/>; })}
      <ArcLetters cx={cx} cy={cy} text="AI  TRUST  ID™" radius={tR} startDeg={-124} endDeg={-56} fontSize={S*.067} fill={arcFill} weight="700"/>
      <ArcLetters cx={cx} cy={cy} text="AI  TRUST  REGISTRY™" radius={tR} startDeg={56} endDeg={124} fontSize={S*.040} fill={arcFill} weight="600" flip={true}/>
      <path d={shield} fill={`${tc}1C`} stroke={tc} strokeWidth={S*.014} strokeLinejoin="round"/>
      {score >= 600 && <polyline points={`${ck.x1},${ck.y1} ${ck.x2},${ck.y2} ${ck.x3},${ck.y3}`} stroke={tc} strokeWidth={S*.024} strokeLinecap="round" strokeLinejoin="round" fill="none"/>}
      {score >= 400 && score < 600 && <text x={cx} y={shieldCY+sH*.08} textAnchor="middle" dominantBaseline="middle" fill={tc} fontSize={S*.13} fontFamily="Georgia" fontWeight="bold">!</text>}
      {score < 400 && <><line x1={xC-xo} y1={yC-yo} x2={xC+xo} y2={yC+yo} stroke={tc} strokeWidth={S*.022} strokeLinecap="round"/><line x1={xC+xo} y1={yC-yo} x2={xC-xo} y2={yC+yo} stroke={tc} strokeWidth={S*.022} strokeLinecap="round"/></>}
      <text x={cx} y={cy+S*.155} textAnchor="middle" fill={tc} fontSize={S*.118} fontFamily={SERIF} fontWeight="700">{score}</text>
      <text x={cx} y={cy+S*.22} textAnchor="middle" fill={dimFill} fontSize={S*.046} fontFamily={SERIF} letterSpacing="1">/ 1000</text>
      {founding && <g>
        <circle cx={cx+iR*.62} cy={cy-iR*.62} r={S*.072} fill={bgFill} stroke={ringStroke} strokeWidth={S*.009}/>
        <text x={cx+iR*.62} y={cy-iR*.62} textAnchor="middle" dominantBaseline="middle" fill={arcFill} fontSize={S*.068} fontFamily="Georgia">★</text>
      </g>}
    </svg>
  );
}

function TIPMark({ size = 140, variant = "light" }) {
  const S = size, cx = S/2, cy = S/2, R = S/2-S*.04, tR = R-S*.064, iR = R-S*.13;
  const isDark = variant === "dark";
  const bg = isDark ? "#0A0A0A" : "#FFFFFF", ring = isDark ? "#FFFFFF" : "#111111", sub = isDark ? "#888888" : "#555555";
  const uid = `tm${size}${variant.slice(0,1)}`;
  return (
    <svg width={S} height={S} viewBox={`0 0 ${S} ${S}`} fill="none" xmlns="http://www.w3.org/2000/svg" style={{ display: "block" }}>
      <defs><filter id={`tsh${uid}`} x="-15%" y="-15%" width="130%" height="130%"><feDropShadow dx="0" dy={S*.012} stdDeviation={S*.018} floodColor={isDark ? "rgba(0,0,0,0.5)" : "rgba(0,0,0,0.08)"}/></filter></defs>
      <circle cx={cx} cy={cy} r={R} fill={bg} filter={`url(#tsh${uid})`}/>
      <circle cx={cx} cy={cy} r={R} stroke={ring} strokeWidth={S*.016} fill="none"/>
      <circle cx={cx} cy={cy} r={iR} stroke={ring} strokeWidth={S*.005} fill="none" opacity=".13"/>
      {[-152, 152].map((deg, i) => { const rad=(deg-90)*Math.PI/180; return <circle key={i} cx={cx+tR*Math.cos(rad)} cy={cy+tR*Math.sin(rad)} r={S*.006} fill={ring} opacity=".3"/>; })}
      <ArcLetters cx={cx} cy={cy} text="TRUST  IDENTITY  PROTOCOL" radius={tR} startDeg={-140} endDeg={-40} fontSize={S*.043} fill={ring} weight="600"/>
      <ArcLetters cx={cx} cy={cy} text="OPEN  SPEC  ·  TIPCL-1.0" radius={tR} startDeg={40} endDeg={140} fontSize={S*.038} fill={sub} weight="500" flip={true}/>
      <text x={cx} y={cy-S*.048} textAnchor="middle" dominantBaseline="middle" fill={ring} fontSize={S*.22} fontFamily={SERIF} fontWeight="700" letterSpacing="-1">TIP</text>
      <line x1={cx-S*.10} y1={cy+S*.048} x2={cx+S*.10} y2={cy+S*.048} stroke={ring} strokeWidth={S*.003} opacity=".2"/>
      <text x={cx} y={cy+S*.125} textAnchor="middle" dominantBaseline="middle" fill={sub} fontSize={S*.054} fontFamily={SERIF} fontWeight="600" letterSpacing="3">POWERED</text>
    </svg>
  );
}

function AnimatedScore({ target }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = 0; const inc = (target / 1200) * 16;
    const timer = setInterval(() => { start += inc; if (start >= target) { setVal(target); clearInterval(timer); } else setVal(Math.floor(start)); }, 16);
    return () => clearInterval(timer);
  }, [target]);
  return <span>{val}</span>;
}

function SN({ num }) {
  return <span style={{ fontSize: 13, fontWeight: 600, color: C.gold, letterSpacing: 3, fontFamily: SERIF }}>{String(num).padStart(2,"0")}</span>;
}

function TrackLabel({ letter, text }) {
  return (
    <div style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      <span style={{ width: 24, height: 24, borderRadius: 4, border: `1.5px solid ${C.gold}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, color: C.gold, fontFamily: SERIF }}>{letter}</span>
      <span style={{ fontSize: 11, letterSpacing: 2, color: C.textMuted, fontWeight: 500, textTransform: "uppercase" }}>{text}</span>
    </div>
  );
}

// ─── Static data ──────────────────────────────────────────────────────────────

const REG_STEPS = [
  { id: "gov_id", title: "Government ID Verification", desc: "Upload a valid government-issued photo ID. We support passports, driver's licenses, and national ID cards from 195 countries. OCR extraction, NFC chip verification, and AI tamper detection run automatically.", required: true },
  { id: "face_scan", title: "3D Facial Liveness Check", desc: "Complete a real-time liveness check. Turn your head left, right, blink, and smile. This prevents photo, deepfake, and mask spoofing while creating your unique biometric hash.", required: true },
  { id: "fingerprint", title: "Device Biometric Binding", desc: "Link your device biometric sensor (Touch ID, fingerprint, Windows Hello). This binds your TIP-ID to a physical device for re-authentication via WebAuthn/FIDO2.", required: true },
  { id: "social", title: "Social Graph Attestation", desc: "Optional but raises your starting trust score. Three existing AI Trust ID holders with score above 700 vouch for your identity. Each voucher stakes 25 points, creating accountability on both sides.", required: false },
];

const CELEBRITIES = [
  { phase: "01", name: "Technology Leaders", targets: "Founders, CEOs, CTOs", why: "Already in the AI discourse. Being first signals leadership and creates credibility foundation.", timing: "Launch Week", strategy: "Direct outreach via VC network. Offer Founding Verified badge (unique gold shield, non-reproducible, minted in Genesis Block)." },
  { phase: "01", name: "Investigative Journalists", targets: "Major outlet reporters, independents", why: "Credibility IS their product. They suffer most from AI impersonation and deepfake quotes.", timing: "Launch Week", strategy: "Partner with CPJ, RSF, SPJ. Free lifetime verification for credentialed journalists. CMS auto-publish plugins." },
  { phase: "02", name: "Scientists and Academics", targets: "AI researchers, Nobel laureates", why: "Institutional credibility plus massive social reach. Legitimizes the system for mainstream adoption.", timing: "Weeks 2 to 3", strategy: "University partnerships. ORCID integration. arXiv and bioRxiv plugin for automatic CTID seals on preprints." },
  { phase: "02", name: "Political Leaders", targets: "Heads of state, tech-forward legislators", why: "Deepfake political content is the number one public fear. They are highly motivated to adopt.", timing: "Weeks 2 to 3", strategy: "Government affairs outreach. Position as election integrity tool aligned with EU AI Act." },
  { phase: "03", name: "Content Creators", targets: "Top YouTubers, podcasters, TikTokers", why: "Massive audience bridge from institutional credibility to consumer adoption.", timing: "Weeks 3 to 8", strategy: "Creator Fund: $2K to $10K per creator for top 100. Affiliate referral program. Dedicated creator dashboard." },
  { phase: "03", name: "Athletes and Entertainers", targets: "Major sports figures, musicians, actors", why: "Pop culture reach makes Trust ID aspirational, not just functional.", timing: "Month 2 onward", strategy: "Talent agency partnerships (CAA, WME, UTA). Bundle with brand protection and impersonation monitoring." },
];

// ─── Shared page sections (used in both views) ───────────────────────────────

function OriginCategories() {
  return (
    <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 24 }}>
      {[
        { code: "OH", label: "Original Human", color: C.blue, bg: "#F0F7FF", desc: "Content created entirely by the uploader without AI generation tools. Traditional tools (Photoshop filters, colour grading, spell-check) are permitted.", examples: "Photographs, handwritten articles, hand-drawn art, live video recordings" },
        { code: "AA", label: "AI-Assisted", color: C.purple, bg: "#F5F3FF", desc: "Human did the primary creative work but used AI tools for enhancement, editing, or partial generation. The human is the primary author.", examples: "AI-enhanced photos, articles with AI-suggested edits, music with AI backing tracks" },
        { code: "AG", label: "AI-Generated", color: C.orange, bg: "#FFFBEB", desc: "AI did the primary generation. The human's role was prompting, curating, or minor editing. The AI is the primary creator.", examples: "DALL-E/Midjourney images, ChatGPT articles, AI-composed music, synthetic video" },
        { code: "MX", label: "Mixed / Composite", color: C.textMuted, bg: C.surface, desc: "Content combining multiple sources, some human and some AI, where no single origin dominates. Must disclose which components are AI-generated.", examples: "Articles with AI illustrations, podcasts with AI voice segments, websites mixing both" },
      ].map((cat, i) => (
        <div key={i} style={{ background: cat.bg, border: `1px solid ${cat.color}20`, borderRadius: 10, padding: 20, borderLeft: `4px solid ${cat.color}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
            <span className="mono" style={{ fontSize: 14, fontWeight: 700, color: cat.color }}>{cat.code}</span>
            <span style={{ fontSize: 14, fontWeight: 600, color: C.navy }}>{cat.label}</span>
          </div>
          <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, marginBottom: 8 }}>{cat.desc}</p>
          <div style={{ fontSize: 11, color: C.textMuted, fontWeight: 300 }}><span style={{ fontWeight: 600, color: C.textSecondary }}>Examples: </span>{cat.examples}</div>
        </div>
      ))}
    </div>
  );
}

function OriginPill({ origin, status = "VERIFIED", size = "md" }) {
  const map = {
    OH: { label: "Original Human", color: C.blue,    bg: "#EEF4FF" },
    AA: { label: "AI-Assisted",     color: C.purple,  bg: "#F5F3FF" },
    AG: { label: "AI-Generated",    color: C.orange,  bg: "#FFFBEB" },
    MX: { label: "Mixed",           color: "#6B7280", bg: C.surface },
  };
  const stColor = status === "DISPUTED" ? C.red : status === "PENDING" ? C.orange : status === "APPEALED" ? C.purple : map[origin]?.color;
  const o = map[origin] || map.MX;
  const sm = size === "sm", lg = size === "lg";
  const h = lg ? 32 : sm ? 20 : 26;
  const fCode = lg ? 12 : sm ? 9 : 10;
  const fLabel = lg ? 11 : sm ? 9 : 10;
  const fStatus = lg ? 10 : sm ? 8 : 9;
  return (
    <div style={{ display: "inline-flex", alignItems: "center", height: h, borderRadius: 4, border: `1px solid ${o.color}30`, background: o.bg, overflow: "hidden", gap: 0 }}>
      <div style={{ padding: lg ? "0 10px" : sm ? "0 6px" : "0 8px", borderRight: `1px solid ${o.color}20`, display: "flex", alignItems: "center" }}>
        <span className="mono" style={{ fontSize: fCode, fontWeight: 700, color: o.color, letterSpacing: 0 }}>{origin}</span>
      </div>
      <div style={{ padding: lg ? "0 10px" : sm ? "0 6px" : "0 8px", borderRight: `1px solid ${o.color}15`, display: "flex", alignItems: "center" }}>
        <span style={{ fontSize: fLabel, fontWeight: 500, color: o.color }}>{o.label}</span>
      </div>
      <div style={{ padding: lg ? "0 8px" : sm ? "0 5px" : "0 6px", display: "flex", alignItems: "center" }}>
        <span style={{ fontSize: fStatus, fontWeight: 700, color: stColor, letterSpacing: 0.3 }}>{status}</span>
      </div>
    </div>
  );
}

// ─── TRUST TIER CHIP ──────────────────────────────────────────────────────────
function TierChip({ score, mode = "full", size = "md" }) {
  const color = score >= 800 ? C.green : score >= 600 ? C.blue : score >= 400 ? C.yellow : score >= 200 ? C.orange : C.red;
  const label = score >= 800 ? "Highly Trusted" : score >= 600 ? "Trusted" : score >= 400 ? "Review Advised" : score >= 200 ? "Low Trust" : "Not Trusted";
  const sm = size === "sm"; const lg = size === "lg";
  const h = lg ? 30 : sm ? 18 : 22;
  const fScore = lg ? 14 : sm ? 10 : 12;
  const fLabel = lg ? 11 : sm ? 9 : 10;

  if (mode === "score") return (
    <div style={{ display: "inline-flex", alignItems: "center", gap: 5, height: h, padding: lg ? "0 10px" : "0 8px", borderRadius: 20, background: `${color}12`, border: `1px solid ${color}30` }}>
      <span style={{ fontSize: fScore, fontWeight: 700, color, fontFamily: "'Cormorant Garamond', serif" }}>{score}</span>
      <span style={{ fontSize: fLabel - 1, color: `${color}80`, fontWeight: 400 }}>/ 1000</span>
    </div>
  );
  if (mode === "tier") return (
    <div style={{ display: "inline-flex", alignItems: "center", height: h, padding: lg ? "0 10px" : "0 8px", borderRadius: 3, background: `${color}10`, border: `1px solid ${color}25` }}>
      <span style={{ fontSize: fLabel, fontWeight: 600, color, letterSpacing: 0.5, textTransform: "uppercase" }}>{label}</span>
    </div>
  );
  if (mode === "dot") return (
    <div style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span style={{ width: sm ? 6 : 8, height: sm ? 6 : 8, borderRadius: "50%", background: color, display: "inline-block", flexShrink: 0 }} />
      <span style={{ fontSize: fLabel, fontWeight: 500, color }}>{label}</span>
    </div>
  );
  // "full" mode: score + tier label
  return (
    <div style={{ display: "inline-flex", alignItems: "center", gap: 6, height: h, padding: lg ? "0 12px" : "0 10px", borderRadius: 20, background: `${color}10`, border: `1px solid ${color}30` }}>
      <span style={{ width: sm ? 5 : 7, height: sm ? 5 : 7, borderRadius: "50%", background: color, flexShrink: 0 }} />
      <span style={{ fontSize: fScore, fontWeight: 700, color, fontFamily: "'Cormorant Garamond', serif" }}>{score}</span>
      <span style={{ width: 1, height: "60%", background: `${color}30` }} />
      <span style={{ fontSize: fLabel, fontWeight: 500, color }}>{label}</span>
    </div>
  );
}

// ─── VERIFIED CHECKMARK BADGE ─────────────────────────────────────────────────
function VerifiedBadge({ size = 18, color = C.blue }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" fill="none" style={{ display: "inline-block", verticalAlign: "middle" }}>
      <path d="M10 1L12.4 7.26L19 8.18L14.5 12.56L15.78 19L10 15.77L4.22 19L5.5 12.56L1 8.18L7.6 7.26L10 1Z" fill={color} opacity="0.15" stroke={color} strokeWidth="1.2"/>
      <polyline points="7,10 9.3,12.3 13.5,7.5" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
    </svg>
  );
}

// ─── BYLINE COMPONENT (news/article use case) ─────────────────────────────────
function BylineExample({ name, tipId, score, origin, founding, platform, verified }) {
  const color = score >= 800 ? C.green : score >= 600 ? C.blue : score >= 400 ? C.yellow : score >= 200 ? C.orange : C.red;
  const label = score >= 800 ? "Highly Trusted" : score >= 600 ? "Trusted" : score >= 400 ? "Caution" : score >= 200 ? "Warning" : "Suspended";
  return (
    <div style={{ padding: "12px 16px", background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <div style={{ width: 32, height: 32, borderRadius: "50%", background: `${color}20`, border: `2px solid ${color}40`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color, fontFamily: "'Cormorant Garamond', serif" }}>{name[0]}</span>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: C.navy }}>{name}</span>
            {verified && <VerifiedBadge size={15} color={color} />}
            {founding && <span style={{ fontSize: 9, fontWeight: 700, color: C.gold, letterSpacing: 0.5 }}>★ FOUNDING</span>}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 2, flexWrap: "wrap" }}>
            <span className="mono" style={{ fontSize: 9, color: C.textMuted }}>{tipId}</span>
            {platform && <span style={{ fontSize: 9, color: C.textMuted }}>· {platform}</span>}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
          <ShieldBadge score={score} size={28} founding={founding} />
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 14, fontWeight: 700, color, fontFamily: "'Cormorant Garamond', serif", lineHeight: 1 }}>{score}</div>
            <div style={{ fontSize: 8, color, letterSpacing: 0.5, fontWeight: 600, marginTop: 1 }}>{label.toUpperCase()}</div>
          </div>
        </div>
        <OriginPill origin={origin} size="sm" />
      </div>
    </div>
  );
}

// ─── FEED CARD COMPONENT ──────────────────────────────────────────────────────
function FeedCardExample({ name, title, excerpt, tipId, score, origin, founding, timestamp }) {
  const color = score >= 800 ? C.green : score >= 600 ? C.blue : score >= 400 ? C.yellow : score >= 200 ? C.orange : C.red;
  return (
    <div style={{ border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden", background: C.bg }}>
      <div style={{ height: 6, background: `linear-gradient(90deg, ${color}, ${color}66)` }} />
      <div style={{ padding: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <div style={{ width: 26, height: 26, borderRadius: "50%", background: `${color}20`, border: `1.5px solid ${color}40`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color }}>{name[0]}</span>
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ fontSize: 11.5, fontWeight: 600, color: C.navy }}>{name}</span>
              <VerifiedBadge size={12} color={color} />
              {founding && <span style={{ fontSize: 8, color: C.gold }}>★</span>}
            </div>
            <span className="mono" style={{ fontSize: 8.5, color: C.textMuted }}>{tipId}</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 3 }}>
            <ShieldBadge score={score} size={22} founding={founding} />
            <span style={{ fontSize: 9, fontWeight: 700, color, letterSpacing: 0.3 }}>{score}</span>
          </div>
        </div>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.navy, marginBottom: 5, lineHeight: 1.4 }}>{title}</div>
        <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300, marginBottom: 10 }}>{excerpt}</div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <OriginPill origin={origin} size="sm" />
          <span style={{ fontSize: 9.5, color: C.textMuted, fontWeight: 300 }}>{timestamp}</span>
        </div>
      </div>
    </div>
  );
}

// ─── CODE SNIPPET COMPONENT ───────────────────────────────────────────────────
function CodeSnip({ code, label }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(code).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1400); });
    }
  };
  return (
    <div style={{ position: "relative" }}>
      {label && <div style={{ fontSize: 9, fontWeight: 600, color: C.textMuted, letterSpacing: 1.5, marginBottom: 5, textTransform: "uppercase" }}>{label}</div>}
      <div className="code-block" style={{ fontSize: 10.5, lineHeight: 1.8, position: "relative" }}>
        <button onClick={copy} style={{ position: "absolute", top: 8, right: 8, background: copied ? C.green : "#1e2d4a", border: `1px solid ${copied ? C.green : "#2d3f5a"}`, color: copied ? "#fff" : C.textMuted, borderRadius: 4, padding: "3px 8px", fontSize: 9, cursor: "pointer", fontFamily: "inherit", fontWeight: 600, transition: "all 0.2s" }}>
          {copied ? "✓ COPIED" : "COPY"}
        </button>
        <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "#CBD5E0" }}>{code}</pre>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// BADGE GALLERY: complete reference for open-source implementors
// ═══════════════════════════════════════════════════════════════════════════════

function BadgeGallery({ showScore }) {
  const [tab, setTab] = useState("seals");

  const tabs = [
    { id: "seals",    label: "AI Trust ID™ Seal" },
    { id: "shields",  label: "Inline Shield" },
    { id: "origin",   label: "Origin Labels" },
    { id: "chips",    label: "Score Chips" },
    { id: "bylines",  label: "Bylines & Cards" },
    { id: "embed",    label: "Embed Code" },
  ];

  return (
    <div>
      {/* Tab bar */}
      <div className="rg-tabs" style={{ display: "flex", gap: 4, marginBottom: 22, flexWrap: "wrap" }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: "7px 14px", borderRadius: 5, border: `1px solid ${tab === t.id ? C.gold : C.border}`, background: tab === t.id ? C.goldDim : "transparent", color: tab === t.id ? C.gold : C.textMuted, cursor: "pointer", fontFamily: "inherit", fontSize: 11.5, fontWeight: tab === t.id ? 600 : 400, transition: "all 0.15s" }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── TAB: AI Trust ID™ Seal ─────────────────────────────────────────────── */}
      {tab === "seals" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          {/* Three variants × five tiers */}
          {[
            { variant: "gold-dark", bg: C.bg,       label: "GOLD · DARK",  note: "Default. Issued by the AI Trust Registry™. Used on dark and light backgrounds." },
            { variant: "light",     bg: "#F5F0E8",   label: "LIGHT",        note: "For light UI environments, parchment backgrounds, or print." },
            { variant: "dark",      bg: "#111827",   label: "DARK",         note: "For dark-mode interfaces, video overlays, and deep backgrounds." },
          ].map(({ variant, bg, label, note }) => (
            <div key={variant} className="card" style={{ marginBottom: 16 }}>
              <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 6 }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2 }}>VARIANT: {label}</div>
              </div>
              <div style={{ fontSize: 11, color: C.textMuted, fontWeight: 300, marginBottom: 16 }}>{note}</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
                {[
                  { score: 924, label: "HIGHLY TRUSTED",  name: "Verified Journalist", founding: true  },
                  { score: 718, label: "TRUSTED",          name: "Science Writer",      founding: false },
                  { score: 462, label: "REVIEW ADVISED",   name: "Flagged Account",     founding: false },
                  { score: 231, label: "LOW TRUST",        name: "Low Trust User",      founding: false },
                  { score: 38,  label: "NOT TRUSTED",      name: "Suspended Actor",     founding: false },
                ].map((u, i) => {
                  const tierColor = u.score >= 800 ? C.green : u.score >= 600 ? C.blue : u.score >= 400 ? C.yellow : u.score >= 200 ? C.orange : C.red;
                  return (
                    <div key={i} style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "18px 6px", gap: 8, borderRight: i < 4 ? `1px solid ${C.border}` : "none", background: bg }}>
                      <TrustIDSeal score={u.score} size={96} variant={variant} founding={u.founding} />
                      <div style={{ textAlign: "center" }}>
                        <div style={{ fontSize: 8.5, fontWeight: 700, color: tierColor, letterSpacing: 0.8, marginBottom: 2 }}>{u.label}</div>
                        <div style={{ fontSize: 9.5, fontWeight: 500, color: variant === "dark" ? "#CBD5E0" : C.navy, marginBottom: 1 }}>{u.name}</div>
                        {u.founding && <div style={{ fontSize: 8, color: C.gold, letterSpacing: 0.5 }}>★ FOUNDING</div>}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}

          {/* Size scale */}
          <div className="card">
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>SIZE SCALE: ALL SIZES RENDER FROM THE SAME SVG COMPONENT</div>
            <div style={{ display: "flex", alignItems: "flex-end", gap: 20, flexWrap: "wrap" }}>
              {[
                { size: 200, label: "200px: Profile page / hero" },
                { size: 140, label: "140px: Sidebar widget" },
                { size: 96,  label: "96px: Article footer" },
                { size: 64,  label: "64px: Card header" },
                { size: 48,  label: "48px: Byline" },
                { size: 32,  label: "32px: Feed row" },
              ].map(({ size, label }) => (
                <div key={size} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
                  <TrustIDSeal score={892} size={size} variant="gold-dark" founding={size >= 96} />
                  <div style={{ fontSize: 9, color: C.textMuted, textAlign: "center", maxWidth: size + 20 }}>{label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: Inline Shield ─────────────────────────────────────────────────── */}
      {tab === "shields" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>ALL FIVE TIERS × ALL FOUR SIZES</div>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
                <thead>
                  <tr style={{ background: C.surface }}>
                    {["Tier / Score", "48px (default)", "36px (compact)", "24px (inline)", "16px (micro)"].map(h => (
                      <th key={h} style={{ padding: "8px 12px", textAlign: "left", color: C.textMuted, fontWeight: 500, borderBottom: `1px solid ${C.border}`, fontSize: 10, letterSpacing: 0.5 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[
                    { tier: "Highly Trusted", score: 924, founding: true },
                    { tier: "Trusted",         score: 718, founding: false },
                    { tier: "Review Advised",  score: 462, founding: false },
                    { tier: "Low Trust",       score: 231, founding: false },
                    { tier: "Not Trusted",     score: 38,  founding: false },
                  ].map((row, i) => {
                    const color = row.score >= 800 ? C.green : row.score >= 600 ? C.blue : row.score >= 400 ? C.yellow : row.score >= 200 ? C.orange : C.red;
                    return (
                      <tr key={i} style={{ borderBottom: `1px solid ${C.border}`, background: i % 2 === 0 ? C.surface : C.bg }}>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: C.navy }}>{row.tier}</div>
                          <div className="mono" style={{ fontSize: 10, color: color, marginTop: 2 }}>score: {row.score}{row.founding ? " · ★ founding" : ""}</div>
                        </td>
                        {[48, 36, 24, 16].map(sz => (
                          <td key={sz} style={{ padding: "10px 16px" }}>
                            <ShieldBadge score={row.score} size={sz} founding={row.founding && sz >= 36} />
                          </td>
                        ))}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>SHIELD IN CONTEXT: WHAT THE ICONS MEAN</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 14 }}>
              {[
                { score: 892, icon: "✓ checkmark", meaning: "Score 600–1000. Trusted or Highly Trusted. Content history is clean. Verified by a Green-tier VP.", color: C.green },
                { score: 462, icon: "! exclamation", meaning: "Score 400–599. Review Advised. Has some disputed content. Verified but use with caution.", color: C.yellow },
                { score: 38,  icon: "✗ cross", meaning: "Score 0–399. Low Trust or Not Trusted. Multiple adjudicated mismatches. Suspended accounts show at 0.", color: C.red },
              ].map(({ score, icon, meaning, color }, i) => (
                <div key={i} style={{ padding: 14, background: C.surface, borderRadius: 8, border: `1px solid ${color}20` }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                    <ShieldBadge score={score} size={36} />
                    <span className="mono" style={{ fontSize: 11, fontWeight: 600, color }}>{icon}</span>
                  </div>
                  <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{meaning}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>FOUNDING STAR INDICATOR: GOLD BORDER VARIANT</div>
            <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
              {[48, 36, 24].map(sz => (
                <div key={sz} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
                  <ShieldBadge score={924} size={sz} founding={true} />
                  <span style={{ fontSize: 9, color: C.gold }}>{sz}px</span>
                </div>
              ))}
              <div style={{ marginLeft: 12, fontSize: 12, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300 }}>
                <span style={{ fontWeight: 600, color: C.gold }}>Gold border</span> indicates a Genesis Ring founding member. Only applies to the small number of identities minted in the network's genesis block. Cannot be earned after launch.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: Origin Labels ─────────────────────────────────────────────────── */}
      {tab === "origin" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          {/* All origins × all statuses */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>ORIGIN PILLS: ALL ORIGINS × ALL STATUS STATES</div>
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", width: "100%" }}>
                <thead>
                  <tr style={{ background: C.surface }}>
                    {["Origin", "VERIFIED", "PENDING", "DISPUTED", "APPEALED", "CLEARED"].map(h => (
                      <th key={h} style={{ padding: "8px 14px", textAlign: "left", color: C.textMuted, fontWeight: 500, borderBottom: `1px solid ${C.border}`, fontSize: 10, letterSpacing: 0.5, whiteSpace: "nowrap" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {["OH", "AA", "AG", "MX"].map((origin, i) => (
                    <tr key={origin} style={{ borderBottom: `1px solid ${C.border}`, background: i % 2 === 0 ? C.surface : C.bg }}>
                      <td style={{ padding: "12px 14px" }}>
                        <div className="mono" style={{ fontSize: 13, fontWeight: 700, color: origin === "OH" ? C.blue : origin === "AA" ? C.purple : origin === "AG" ? C.orange : "#6B7280" }}>{origin}</div>
                        <div style={{ fontSize: 10, color: C.textMuted, marginTop: 2 }}>{{ OH:"Original Human", AA:"AI-Assisted", AG:"AI-Generated", MX:"Mixed" }[origin]}</div>
                      </td>
                      {["VERIFIED", "PENDING", "DISPUTED", "APPEALED", "CLEARED"].map(status => (
                        <td key={status} style={{ padding: "12px 14px" }}>
                          <OriginPill origin={origin} status={status} size="md" />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Three sizes */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>THREE SIZES: LG / MD / SM</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {["OH", "AA", "AG", "MX"].map(origin => (
                <div key={origin} style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 10, color: C.textMuted, width: 28, fontWeight: 500 }}>{origin}</span>
                  <OriginPill origin={origin} size="lg" />
                  <OriginPill origin={origin} size="md" />
                  <OriginPill origin={origin} size="sm" />
                </div>
              ))}
            </div>
          </div>

          {/* Where to use */}
          <div className="card">
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>WHERE EACH ORIGIN LABEL APPEARS</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              {[
                { placement: "Article byline (under author name)", size: "sm", usage: "Shows at a glance how the content was made. Pairs with the shield badge and the author's score." },
                { placement: "Content management system", size: "md", usage: "Author selects origin when publishing. The declaration is signed and immutable once submitted." },
                { placement: "Social media card / embed preview", size: "md", usage: "Appears in the link preview generated by TIP's Open Graph tags. Visible when the URL is shared." },
                { placement: "Browser extension overlay", size: "lg", usage: "The TIP browser extension shows the full-size origin label when a user inspects a piece of content." },
                { placement: "Search result snippet", size: "sm", usage: "Search engines that implement TIP™ can display the origin label in the snippet beneath the URL." },
                { placement: "Content dispute queue (admin)", size: "md", usage: "Displayed in the adjudication interface alongside the declared vs. confirmed origin comparison." },
              ].map((item, i) => (
                <div key={i} style={{ padding: 14, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                    <OriginPill origin="OH" size={item.size} />
                    <span style={{ fontSize: 9, color: C.textMuted, fontStyle: "italic" }}>size: {item.size}</span>
                  </div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: C.navy, marginBottom: 4 }}>{item.placement}</div>
                  <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{item.usage}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: Score Chips ───────────────────────────────────────────────────── */}
      {tab === "chips" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 6 }}>FOUR DISPLAY MODES: GDPR SCORE VISIBILITY SETTINGS</div>
            <p style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300, lineHeight: 1.7, marginBottom: 18 }}>Users control their score visibility via three GDPR-compliant modes: Full Public (numeric score), Tier Only (label without number), and Verified Only (checkmark without number or tier). Implementors must respect the user's chosen mode. The "dot" mode is a supplementary micro-indicator.</p>
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", width: "100%" }}>
                <thead>
                  <tr style={{ background: C.surface }}>
                    {["Score", "full (score + tier)", "score (number only)", "tier (label only)", "dot (micro)", "verified (boolean)"].map(h => (
                      <th key={h} style={{ padding: "8px 12px", textAlign: "left", color: C.textMuted, fontWeight: 500, borderBottom: `1px solid ${C.border}`, fontSize: 10, whiteSpace: "nowrap" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[924, 718, 462, 231, 38].map((score, i) => {
                    const color = score >= 800 ? C.green : score >= 600 ? C.blue : score >= 400 ? C.yellow : score >= 200 ? C.orange : C.red;
                    return (
                      <tr key={score} style={{ borderBottom: `1px solid ${C.border}`, background: i % 2 === 0 ? C.surface : C.bg }}>
                        <td style={{ padding: "12px 12px" }}><span className="mono" style={{ fontSize: 14, fontWeight: 700, color }}>{score}</span></td>
                        <td style={{ padding: "12px 12px" }}><TierChip score={score} mode="full" /></td>
                        <td style={{ padding: "12px 12px" }}><TierChip score={score} mode="score" /></td>
                        <td style={{ padding: "12px 12px" }}><TierChip score={score} mode="tier" /></td>
                        <td style={{ padding: "12px 12px" }}><TierChip score={score} mode="dot" /></td>
                        <td style={{ padding: "12px 12px" }}><VerifiedBadge size={18} color={color} /></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>THREE CHIP SIZES</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {[892, 520, 285].map(score => (
                <div key={score} style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 11, color: C.textMuted, width: 36 }}>{score}</span>
                  <TierChip score={score} mode="full" size="lg" />
                  <TierChip score={score} mode="full" size="md" />
                  <TierChip score={score} mode="full" size="sm" />
                  <span style={{ fontSize: 9, color: C.textMuted }}>lg / md / sm</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>SCORE DISPLAY MODE RULES FOR IMPLEMENTORS</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {[
                { mode: "FULL_PUBLIC", color: C.green, rule: "User has opted in to showing their numeric score. You may display TierChip mode='full' or mode='score'. Default for users who set this in their TIP™ profile settings." },
                { mode: "TIER_ONLY", color: C.blue, rule: "User shows only the tier label, not the number. Display TierChip mode='tier' or mode='dot'. Never display the numeric score for these users. This is the default setting at registration." },
                { mode: "VERIFIED_ONLY", color: C.purple, rule: "User only wants to show verified status, not tier or score. Display the VerifiedBadge checkmark only. Respect this setting strictly: showing more is a GDPR violation." },
                { mode: "Shield badge", color: C.textMuted, rule: "The ShieldBadge icon (checkmark/exclamation/cross) is always safe to show regardless of score display mode. It conveys risk level without revealing numeric score." },
              ].map((item, i) => (
                <div key={i} style={{ padding: 14, background: `${item.color}06`, border: `1px solid ${item.color}20`, borderRadius: 8, borderLeft: `3px solid ${item.color}` }}>
                  <div className="mono" style={{ fontSize: 10, fontWeight: 700, color: item.color, marginBottom: 6, letterSpacing: 1 }}>{item.mode}</div>
                  <div style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{item.rule}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: Bylines & Cards ───────────────────────────────────────────────── */}
      {tab === "bylines" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>BYLINE INTEGRATION: NEWS, BLOG, LONG-FORM CONTENT</div>
            <p style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300, lineHeight: 1.7, marginBottom: 16 }}>
              Drop into any byline element. Shows author name, verified indicator, TIP-ID, shield badge with score, and origin label. All in one row.
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <BylineExample name="Priya Mehta" tipId="tip://id/US-a3f8c91b" score={892} origin="OH" founding={true}  platform="The Guardian" verified={true} />
              <BylineExample name="Marco Bianchi" tipId="tip://id/IT-7c2d4e19" score={718} origin="AA" founding={false} platform="Reuters" verified={true} />
              <BylineExample name="Chen Wei" tipId="tip://id/DE-f7a29b01" score={462} origin="AG" founding={false} platform="Independent" verified={true} />
              <BylineExample name="Unverified User" tipId="tip://id/BR-d1a6c904" score={38}  origin="OH" founding={false} platform={null}   verified={false} />
            </div>
          </div>

          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>FEED CARD INTEGRATION: SOCIAL MEDIA, AGGREGATORS, SEARCH</div>
            <p style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300, lineHeight: 1.7, marginBottom: 16 }}>
              Full card variant. A colour bar at the top communicates trust tier at a glance. Origin pill in the footer. Score shown compactly.
            </p>
            <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <FeedCardExample name="Priya Mehta" title="AI Regulation: What the EU AI Act Really Means" excerpt="The Act's Article 50 mandates disclosure of AI-generated content. Here is what publishers need to know before the August deadline." tipId="tip://id/US-a3f8c91b" score={892} origin="OH" founding={true}  timestamp="2 hours ago" />
              <FeedCardExample name="SynthVoice Bot" title="Breaking: World Leaders Sign Climate Deal" excerpt="Explosive new agreement signed today will reshape global energy policy for the next fifty years..." tipId="tip://id/XX-unknown01" score={38}  origin="AG" founding={false} timestamp="just now" />
            </div>
          </div>

          <div className="card">
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>YOUTUBE / VIDEO PLATFORM INTEGRATION: DESCRIPTION BLOCK</div>
            <div style={{ padding: 20, background: "#0F0F0F", borderRadius: 10, fontFamily: "'Helvetica Neue', sans-serif" }}>
              <div style={{ display: "flex", gap: 14, marginBottom: 12, alignItems: "flex-start" }}>
                <div style={{ width: 40, height: 40, borderRadius: "50%", background: "#1A8A5C20", border: "2px solid #1A8A5C50", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <span style={{ fontSize: 18, fontWeight: 700, color: "#1A8A5C", fontFamily: "'Cormorant Garamond', serif" }}>P</span>
                </div>
                <div>
                  <div style={{ color: "#F1F1F1", fontSize: 14, fontWeight: 600 }}>Priya Mehta</div>
                  <div style={{ color: "#AAA", fontSize: 12 }}>1.2M subscribers</div>
                </div>
              </div>
              <div style={{ color: "#F1F1F1", fontSize: 14, fontWeight: 600, marginBottom: 8 }}>The Truth About Deepfakes: How Journalists Are Fighting Back</div>
              <div style={{ color: "#AAA", fontSize: 12, marginBottom: 12, lineHeight: 1.6 }}>47K views · 3 days ago</div>
              <div style={{ background: "#1A1A1A", borderRadius: 8, padding: "12px 14px", fontSize: 12 }}>
                <div style={{ color: "#AAA", marginBottom: 10, lineHeight: 1.7 }}>
                  This video was independently produced. All facts are sourced and linked below.
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", background: "#111", borderRadius: 6, marginBottom: 8 }}>
                  <TrustIDSeal score={892} size={40} variant="gold-dark" founding={true} />
                  <div>
                    <div style={{ color: "#E5E7EB", fontSize: 11, fontWeight: 600 }}>Verified with AI Trust ID™</div>
                    <div style={{ color: "#6B7280", fontSize: 10 }}>tip://id/US-a3f8c91b · Score: 892 · Highly Trusted</div>
                  </div>
                  <div style={{ marginLeft: "auto" }}>
                    <OriginPill origin="OH" size="sm" />
                  </div>
                </div>
                <div style={{ color: "#6B7280", fontSize: 10 }}>🔗 Verify: theailab.org/verify/tip%3A%2F%2Fid%2FUS-a3f8c91b</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: Embed Code ────────────────────────────────────────────────────── */}
      {tab === "embed" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>

          {/* HTTP Headers */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 6 }}>HTTP RESPONSE HEADERS: SERVER-SIDE (NGINX / APACHE / CADDY)</div>
            <p style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300, lineHeight: 1.7, marginBottom: 14 }}>Add to your web server config for every response. This is the minimum implementation: takes 5 minutes. No SDK, no dependency, no account required for the TIP Powered Mark.</p>
            <CodeSnip label="Nginx (nginx.conf)" code={`# Add inside your server {} or location {} block:
add_header TIP-Author        "tip://id/US-a3f8c91b2d4e7021";
add_header TIP-Content       "tip://c/OH-7f2a91bc3d5e4a-a3f8";
add_header TIP-Origin        "original-human";
add_header TIP-Trust-Score   "892";
add_header TIP-Tier          "HIGHLY_TRUSTED";
add_header TIP-Signature     "[ML-DSA-65 signature hex]";`} />
            <div style={{ marginTop: 14 }}>
              <CodeSnip label="Apache (.htaccess)" code={`Header set TIP-Author       "tip://id/US-a3f8c91b2d4e7021"
Header set TIP-Content      "tip://c/OH-7f2a91bc3d5e4a-a3f8"
Header set TIP-Origin       "original-human"
Header set TIP-Trust-Score  "892"
Header set TIP-Tier         "HIGHLY_TRUSTED"
Header set TIP-Signature    "[ML-DSA-65 signature hex]"`} />
            </div>
          </div>

          {/* HTML Meta Tags */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 6 }}>HTML META TAGS: IN YOUR &lt;HEAD&gt;</div>
            <p style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300, lineHeight: 1.7, marginBottom: 14 }}>Paste these in the &lt;head&gt; of every published page. These power the browser extension, search engine integration, and social media previews.</p>
            <CodeSnip code={`<!-- TIP™ Provenance Meta Tags -->
<meta property="tip:author"    content="tip://id/US-a3f8c91b2d4e7021" />
<meta property="tip:content"   content="tip://c/OH-7f2a91bc3d5e4a-a3f8" />
<meta property="tip:origin"    content="original-human" />
<meta property="tip:score"     content="892" />
<meta property="tip:tier"      content="HIGHLY_TRUSTED" />
<meta property="tip:status"    content="VERIFIED" />
<meta property="tip:signature" content="[ML-DSA-65 signature hex]" />
<meta property="tip:node"      content="https://your-node.example.com" />`} />
          </div>

          {/* Badge Widget */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 6 }}>&lt;TIP-BADGE&gt; WEB COMPONENT: ZERO DEPENDENCIES</div>
            <p style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300, lineHeight: 1.7, marginBottom: 14 }}>Drop-in custom element. Loads asynchronously. Renders the AI Trust ID™ Seal if the TIP-ID has a valid Seal, or the TIP Powered Mark if not. Auto-scans the page's meta tags if no tip-id attribute is set.</p>
            <CodeSnip code={`<!-- 1. Load the widget script once (auto-scans page, no config needed): -->
<script src="https://badge.theailab.org/tip-badge.min.js" defer></script>

<!-- 2. Drop the element wherever you want the badge to appear: -->
<!-- Full Seal (requires registry-issued TIP-ID): -->
<tip-badge tip-id="tip://id/US-a3f8c91b" size="120" variant="gold-dark"></tip-badge>

<!-- TIP Powered Mark (for platforms implementing the spec): -->
<tip-badge type="mark" size="80" variant="light"></tip-badge>

<!-- Auto-scan mode (reads tip:author meta tag from the page): -->
<tip-badge auto size="80"></tip-badge>

<!-- Inline shield only: -->
<tip-badge type="shield" tip-id="tip://id/US-a3f8c91b" size="32"></tip-badge>`} />
          </div>

          {/* REST API */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 6 }}>REST API CALLS: FOR PLATFORMS AND CMS PLUGINS</div>
            <p style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300, lineHeight: 1.7, marginBottom: 14 }}>Four endpoints cover the complete lifecycle for a platform integrating TIP™. All return JSON. No API key required for read operations.</p>
            <div style={{ display: "grid", gap: 12 }}>
              {[
                { label: "Resolve a TIP-ID (display author badge)", code: `GET https://node.theailab.org/v1/identity/tip%3A%2F%2Fid%2FUS-a3f8c91b

// Response:
{
  "tip_id": "tip://id/US-a3f8c91b",
  "score": 892,
  "tier": "HIGHLY_TRUSTED",
  "tier_color": "#1A8A5C",
  "status": "active",
  "founding": true,
  "vp_id": "tip://id/VP-US-theailab-genesis"
}` },
                { label: "Get author trust score only", code: `GET https://node.theailab.org/v1/identity/tip%3A%2F%2Fid%2FUS-a3f8c91b/score

// Response:
{
  "score": 892,
  "tier": "HIGHLY_TRUSTED",
  "tier_label": "Highly Trusted",
  "tier_color": "#1A8A5C",
  "offense_count": 0,
  "status": "active"
}` },
                { label: "Resolve a CTID (verify content provenance)", code: `GET https://node.theailab.org/v1/content/tip%3A%2F%2Fc%2FOH-7f2a91bc3d5e4a-a3f8

// Response:
{
  "ctid": "tip://c/OH-7f2a91bc3d5e4a-a3f8",
  "origin_code": "OH",
  "origin_label": "Original Human",
  "status": "verified",
  "author_tip_id": "tip://id/US-a3f8c91b",
  "author_score": 892,
  "dispute_count": 0
}` },
                { label: "File a dispute (when your AI detector flags a mismatch)", code: `POST https://node.theailab.org/v1/content/tip%3A%2F%2Fc%2FOH-7f2a91bc3d5e4a-a3f8/dispute
Content-Type: application/json

{
  "disputer_tip_id": "tip://id/VP-US-yourplatform-vp",
  "reason": "AI classifier detected probable AI generation in OH-declared content",
  "evidence_hash": "[SHAKE-256 of your classifier output]"
}

// Response:
{
  "success": true,
  "message": "Dispute filed. Stage 1 AI classifier will run within 60 seconds."
}` },
              ].map(({ label, code }, i) => (
                <CodeSnip key={i} label={label} code={code} />
              ))}
            </div>
          </div>

          {/* TIP Powered Mark usage */}
          <div className="card">
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 6 }}>TIP™ POWERED MARK: OPEN SOURCE DISPLAY RULES</div>
            <p style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300, lineHeight: 1.7, marginBottom: 14 }}>Any developer or platform that implements the TIP™ open specification can display the Powered Mark. Licensed under TIPCL-1.0 (converts to Apache 2.0 on January 1, 2031). No permission required. Never substitute this for the AI Trust ID™ Seal.</p>
            <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: C.green, letterSpacing: 1, marginBottom: 10 }}>✓ ALLOWED</div>
                {["Display on any platform implementing TIP™","Use in developer documentation and SDKs","Show on 'About' or 'Trust' pages","Animate the mark with CSS (scale, fade)","Use at any size from 40px to 400px"].map((rule, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, marginBottom: 7 }}>
                    <span style={{ color: C.green, fontWeight: 700, flexShrink: 0, fontSize: 12 }}>✓</span>
                    <span style={{ fontSize: 11.5, color: C.textSecondary, fontWeight: 300 }}>{rule}</span>
                  </div>
                ))}
              </div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: C.red, letterSpacing: 1, marginBottom: 10 }}>✗ NOT ALLOWED</div>
                {["Substitute it for the AI Trust ID™ Seal (they are different)","Modify the mark or add your branding inside the ring","Use it to imply your own content is human-verified","Display it unless you actually implement the TIP™ spec","Use it in advertising without TIP™ implementation"].map((rule, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, marginBottom: 7 }}>
                    <span style={{ color: C.red, fontWeight: 700, flexShrink: 0, fontSize: 12 }}>✗</span>
                    <span style={{ fontSize: 11.5, color: C.textSecondary, fontWeight: 300 }}>{rule}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC BADGES PAGE
// ═══════════════════════════════════════════════════════════════════════════════

function PublicBadges({ showScore }) {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={5} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Trust Badges</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 28, fontWeight: 300, lineHeight: 1.7 }}>Every visual element in the TIP™ system: from the full AI Trust ID™ Seal to a 16-pixel shield in a tweet: tells the same story. One shows a platform implements TIP™. The other is a personal credential tied to a verified identity. They are never combined or substituted for each other.</p>

      {/* Two badge types intro */}
      <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 28 }}>
        <div className="card" style={{ borderTop: `3px solid #444` }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 2, marginBottom: 16 }}>PLATFORM COMPATIBILITY MARK</div>
          <div style={{ display: "flex", justifyContent: "center", gap: 20, marginBottom: 20 }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}><TIPMark size={104} variant="light" /><span style={{ fontSize: 9, color: C.textMuted, letterSpacing: 1 }}>LIGHT</span></div>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}><TIPMark size={104} variant="dark" /><span style={{ fontSize: 9, color: C.textMuted, letterSpacing: 1 }}>DARK</span></div>
          </div>
          <div style={{ fontSize: 14, fontWeight: 700, color: C.navy, marginBottom: 6 }}>TIP™ Powered Mark</div>
          <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, marginBottom: 14 }}>Any platform implementing TIP™ may display this mark. Licensed under TIPCL-1.0 -- free forever for compliant implementations. No registration required. Attribution required.</p>
          {[["Who can display it","Any developer implementing the TIP™ open specification"],["License","TIPCL-1.0 · Free for compliant implementations · Converts to Apache 2.0 in 2031"],["Shows a trust score?","No. Compatibility mark only, not a personal credential"]].map(([k,v]) => (
            <div key={k} style={{ display: "grid", gridTemplateColumns: "130px 1fr", gap: 8, padding: "5px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11.5 }}>
              <span style={{ color: C.textMuted, fontWeight: 500 }}>{k}</span>
              <span style={{ color: C.textSecondary, fontWeight: 300 }}>{v}</span>
            </div>
          ))}
        </div>
        <div className="card" style={{ borderTop: `3px solid ${C.gold}` }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>PERSONAL TRUST CREDENTIAL</div>
          <div style={{ display: "flex", justifyContent: "center", gap: 20, marginBottom: 20 }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}><TrustIDSeal score={892} size={104} variant="gold-dark" founding /><span style={{ fontSize: 9, color: C.textMuted, letterSpacing: 1 }}>GOLD · DARK</span></div>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}><div style={{ background: "#F5F0E8", borderRadius: 8, padding: 4 }}><TrustIDSeal score={892} size={104} variant="light" /></div><span style={{ fontSize: 9, color: C.textMuted, letterSpacing: 1 }}>LIGHT</span></div>
          </div>
          <div style={{ fontSize: 14, fontWeight: 700, color: C.navy, marginBottom: 6 }}>AI Trust ID™ Seal</div>
          <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, marginBottom: 14 }}>Issued by the AI Trust Registry to verified individuals. Tied to your personal TIP-ID. Your trust score shown in the tier colour for instant readability.</p>
          {[["Issued by","The AI Lab · AI Trust Registry™"],["Who receives it","Verified individuals with a registry-issued TIP-ID"],["Score shown","Your public trust score (0–1000) in tier colour"]].map(([k,v]) => (
            <div key={k} style={{ display: "grid", gridTemplateColumns: "130px 1fr", gap: 8, padding: "5px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11.5 }}>
              <span style={{ color: C.textMuted, fontWeight: 500 }}>{k}</span>
              <span style={{ color: C.textSecondary, fontWeight: 300 }}>{v}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Full gallery */}
      <BadgeGallery showScore={showScore} />
    </div>
  );
}

function PublicHome() {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ textAlign: "center", marginBottom: 56 }}>
        <div style={{ fontSize: 11, color: C.gold, letterSpacing: 5, fontWeight: 600, marginBottom: 16 }}>THE AI LAB · TRUST IDENTITY PROTOCOL (TIP™)</div>
        <h1 className="serif hero-title" style={{ fontSize: 46, fontWeight: 700, lineHeight: 1.15, marginBottom: 20, color: C.navy }}>
          Know who created it.<br /><em style={{ color: C.gold, fontWeight: 400 }}>Trust what you read.</em>
        </h1>
        <p className="hero-desc" style={{ color: C.textSecondary, fontSize: 15, maxWidth: 640, margin: "0 auto", lineHeight: 1.75, fontWeight: 300 }}>
          TIP™ is a free, open protocol that lets real people prove their identity and label their content honestly. When you see an AI Trust ID badge, you know the person behind it is verified and that their content is labelled truthfully.
        </p>
      </div>

      <div className="rg3" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20, marginBottom: 32 }}>
        {[
          { icon: "🛡", title: "For Individuals", color: C.blue, desc: "Get a verified AI Trust ID that proves you are a real, unique person. Post content with a signed origin label. Build a public trust score based on your honest track record." },
          { icon: "✍", title: "For Creators", color: C.purple, desc: "Label your work as human-created, AI-assisted, or AI-generated. Protect your reputation. Let your audience know exactly what they are reading, watching, or hearing." },
          { icon: "⌨", title: "For Developers", color: C.teal, desc: "Add TIP™ to any website in five minutes using standard HTTP headers. No SDK required. Implement the open spec freely. Browser extensions render trust badges automatically." },
        ].map((item, i) => (
          <div key={i} style={{ padding: 24, background: C.surface, borderRadius: 12, border: `1px solid ${C.border}`, borderTop: `3px solid ${item.color}` }}>
            <div style={{ fontSize: 28, marginBottom: 12 }}>{item.icon}</div>
            <div style={{ fontSize: 15, fontWeight: 600, color: C.navy, marginBottom: 8 }}>{item.title}</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, margin: 0 }}>{item.desc}</p>
          </div>
        ))}
      </div>

      <div style={{ background: "#F0F7FF", border: `1px solid ${C.blue}20`, borderRadius: 12, padding: 32, marginBottom: 28, borderLeft: `4px solid ${C.blue}` }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.blue, letterSpacing: 2, marginBottom: 12 }}>WHY THIS EXISTS</div>
        <p style={{ fontSize: 14, color: C.textSecondary, lineHeight: 1.8, fontWeight: 300, margin: 0 }}>
          AI can now generate indistinguishable text, images, video, and audio at near-zero cost. Within a few years, no human will be able to tell AI-created content from human-created content by looking at it alone. TIP™ solves this not by trying to detect AI (which is an arms race no one wins), but by creating a system where people <strong style={{ color: C.navy, fontWeight: 600 }}>declare and sign</strong> the origin of their content before publishing. Honest labelling is rewarded. Dishonest labelling has consequences.
        </p>
      </div>

      <div className="card" style={{ padding: 32, background: C.surface }}>
        <div style={{ textAlign: "center", marginBottom: 20 }}>
          <div style={{ fontSize: 10, color: C.textMuted, letterSpacing: 3, marginBottom: 4 }}>HOW THE PROTOCOL WORKS</div>
          <div className="divider" style={{ maxWidth: 200, margin: "0 auto" }} />
        </div>
        <div className="rg3" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
          {[
            { num: 1, title: "Verify your identity", desc: "Complete a one-time verification using your government ID and a 3D liveness check. Your raw biometrics are never stored. You get a portable, quantum-safe TIP-ID.", color: C.blue },
            { num: 2, title: "Label your content", desc: "When you publish, declare how you made it: Original Human, AI-Assisted, AI-Generated, or Mixed. Sign that declaration with your TIP-ID. It becomes immutable.", color: C.purple },
            { num: 3, title: "Build your trust score", desc: "Every piece of verified content adds to your public trust score (0 to 1000). Honest behaviour earns trust over time. Misrepresentation has escalating consequences.", color: C.green },
          ].map((layer, i) => (
            <div key={i} style={{ textAlign: "center", padding: 20, background: C.bg, borderRadius: 8, border: `1px solid ${C.border}`, borderTop: `3px solid ${layer.color}` }}>
              <SN num={layer.num} />
              <div style={{ fontSize: 13, fontWeight: 600, marginTop: 8, color: C.navy }}>{layer.title}</div>
              <div style={{ fontSize: 11.5, color: C.textSecondary, marginTop: 8, lineHeight: 1.6, fontWeight: 300 }}>{layer.desc}</div>
            </div>
          ))}
        </div>
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <p style={{ fontSize: 12, color: C.textMuted, fontWeight: 300 }}>The protocol is open-source and free for individuals, journalists, nonprofits, governments, and small businesses. Anyone can run a node. Anyone can verify a badge.</p>
        </div>
      </div>
    </div>
  );
}

function PublicHowItWorks({ regStep, setRegStep }) {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={2} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Getting Verified</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 32, fontWeight: 300, lineHeight: 1.7 }}>Verification takes about ten minutes. It is a one-time process. Your raw biometric data is never stored anywhere. Three steps are required; a fourth optional step raises your starting trust score.</p>
      <div className="rg-sidebar" style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 20 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {REG_STEPS.map((s, i) => (
            <button key={s.id} className={`step-btn ${regStep === i ? "active" : ""}`} onClick={() => setRegStep(i)}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: regStep === i ? C.gold : C.textMuted, fontFamily: SERIF, letterSpacing: 2 }}>{String(i+1).padStart(2,"0")}</span>
                <div>
                  <div style={{ fontWeight: 500, fontSize: 12.5 }}>{s.title}</div>
                  <div style={{ fontSize: 10, color: s.required ? C.gold : C.textMuted, marginTop: 2, letterSpacing: 1 }}>{s.required ? "REQUIRED" : "OPTIONAL"}</div>
                </div>
              </div>
            </button>
          ))}
        </div>
        <div className="card" style={{ animation: "fadeIn 0.3s ease" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
            <SN num={regStep + 1} />
            <div>
              <h3 style={{ fontSize: 18, fontWeight: 600 }}>{REG_STEPS[regStep].title}</h3>
              <span className="tag" style={{ background: REG_STEPS[regStep].required ? `${C.gold}10` : `${C.blue}10`, color: REG_STEPS[regStep].required ? C.gold : C.blue, border: `1px solid ${REG_STEPS[regStep].required ? C.gold : C.blue}25`, marginTop: 4 }}>{REG_STEPS[regStep].required ? "REQUIRED" : "OPTIONAL · TRUST BOOST"}</span>
            </div>
          </div>
          <p style={{ color: C.textSecondary, fontSize: 13.5, lineHeight: 1.8, marginBottom: 24, fontWeight: 300 }}>{REG_STEPS[regStep].desc}</p>

          {regStep === 0 && (
            <div style={{ background: C.surface, borderRadius: 10, padding: 20, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, marginBottom: 12, color: C.textMuted, letterSpacing: 2 }}>WHAT HAPPENS TO YOUR ID</div>
              <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                {[
                  ["Your data stays private", "We verify your ID and immediately hash the result. We do not store your ID number, your date of birth, or a copy of your document."],
                  ["One person, one TIP-ID", "A deduplication check ensures no one can register twice. Your identity is unique to you and cannot be transferred."],
                  ["195 countries supported", "Passports, national ID cards, and driver's licences from every recognised nation are accepted."],
                  ["e-Passport NFC supported", "For passports with a chip, we cryptographically verify the government's digital signature for the strongest possible assurance."],
                ].map(([title, desc], i) => (
                  <div key={i} style={{ padding: 14, background: C.bg, borderRadius: 8, border: `1px solid ${C.border}` }}>
                    <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 6, color: C.navy }}>{title}</div>
                    <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {regStep === 1 && (
            <div style={{ background: C.surface, borderRadius: 10, padding: 20, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, marginBottom: 12, color: C.textMuted, letterSpacing: 2 }}>YOUR PRIVACY IS PROTECTED</div>
              <div style={{ padding: 16, background: "#F0FDF4", border: `1px solid ${C.green}20`, borderRadius: 8, marginBottom: 12 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: C.green, marginBottom: 6 }}>Zero raw biometrics stored</div>
                <div style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>The liveness check runs inside a secure enclave on your device. It produces a mathematical representation of your face, which is immediately converted into a one-way hash. Only the hash leaves your device. Your actual biometric data never does. We cannot reconstruct your face from what we store.</div>
              </div>
              <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300 }}>The liveness check requires you to turn your head and blink. This defeats printed photos, deepfake videos, and masks. It is a 60-second process that works on any modern smartphone camera.</div>
            </div>
          )}
          {regStep === 2 && (
            <div style={{ background: C.surface, borderRadius: 10, padding: 20, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, marginBottom: 12, color: C.textMuted, letterSpacing: 2 }}>USES THE SAME TECHNOLOGY AS APPLE AND GOOGLE PASSKEYS</div>
              <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, marginBottom: 16, fontWeight: 300 }}>Your device generates a keypair in its secure enclave. The private key never leaves your hardware. We store only the public key. This means that even if our servers were breached, an attacker could not impersonate you.</p>
              <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
                {[["Apple", "Touch ID or Face ID via Secure Enclave"], ["Android", "Fingerprint or Face via Trusted Execution Environment"], ["Windows", "Windows Hello via TPM 2.0 or a hardware security key"]].map(([t, d], i) => (
                  <div key={i} style={{ padding: 14, background: C.bg, borderRadius: 8, border: `1px solid ${C.border}` }}>
                    <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 6 }}>{t}</div>
                    <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{d}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {regStep === 3 && (
            <div style={{ background: C.surface, borderRadius: 10, padding: 20, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, marginBottom: 12, color: C.textMuted, letterSpacing: 2 }}>SOCIAL VOUCHING</div>
              <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, marginBottom: 16, fontWeight: 300 }}>Three existing AI Trust ID holders with trust scores above 700 can vouch for your identity. Each voucher stakes 25 of their own trust points. If you misrepresent your content within 90 days, they lose those points. This creates real accountability on both sides.</p>
              <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div style={{ padding: 14, background: "#F0FDF4", borderRadius: 8, border: `1px solid ${C.green}20` }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: C.green }}>What you gain</div>
                  <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, marginTop: 4, fontWeight: 300 }}>Starting score of 550 instead of 500. A 1.5x trust accrual multiplier for your first 90 days. Immediate eligibility to participate in community verification.</div>
                </div>
                <div style={{ padding: 14, background: "#F0F7FF", borderRadius: 8, border: `1px solid ${C.blue}20` }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: C.blue }}>Who can vouch</div>
                  <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, marginTop: 4, fontWeight: 300 }}>Any three verified AI Trust ID holders with a trust score above 700. You can find vouchers through your professional network or community groups that have adopted TIP™.</div>
                </div>
              </div>
            </div>
          )}
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 24 }}>
            <button onClick={() => setRegStep(Math.max(0, regStep-1))} disabled={regStep===0} style={{ padding: "9px 18px", borderRadius: 6, border: `1px solid ${C.border}`, background: "none", color: regStep===0 ? C.textMuted : C.textPrimary, cursor: regStep===0 ? "default" : "pointer", fontFamily: "inherit", fontSize: 12 }}>Previous</button>
            <button onClick={() => setRegStep(Math.min(3, regStep+1))} disabled={regStep===3} style={{ padding: "9px 18px", borderRadius: 6, border: "none", background: regStep===3 ? C.border : C.navy, color: regStep===3 ? C.textMuted : "#FFF", cursor: regStep===3 ? "default" : "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: 600 }}>Next Step</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function PublicOrigin() {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={3} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Content Origin Labels</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 12, fontWeight: 300, lineHeight: 1.7 }}>AI-created content that is honestly labelled is not a problem. The problem is AI content labelled as human-created. TIP™ shifts the question from "is this fake?" to "does this content match what the creator declared?" That is a question with a clear, enforceable answer.</p>
      <div className="divider" style={{ marginBottom: 28 }} />
      <div style={{ background: "#F0F7FF", border: `1px solid ${C.blue}20`, borderRadius: 12, padding: 24, marginBottom: 24, borderLeft: `4px solid ${C.blue}` }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.blue, letterSpacing: 2, marginBottom: 8 }}>THE CORE PRINCIPLE</div>
        <p style={{ fontSize: 13.5, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>When you publish through TIP™, you sign a declaration of how you made your content. That signature is cryptographically bound to your TIP-ID and recorded permanently. If an AI detection tool later finds a mismatch, that is a provable violation of your declaration, not an ambiguous editorial call. <strong style={{ color: C.navy, fontWeight: 600 }}>Honest labelling is always safe. Conservative labelling is always safe. Only dishonest labelling carries consequences.</strong></p>
      </div>
      <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>THE FOUR ORIGIN CATEGORIES</div>
      <OriginCategories />
      <div style={{ background: "#F0FDF4", border: `1px solid ${C.green}20`, borderRadius: 12, padding: 24, marginBottom: 24, borderLeft: `4px solid ${C.green}` }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.green, letterSpacing: 2, marginBottom: 8 }}>CONSERVATIVE LABELLING IS NEVER PENALISED</div>
        <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>If you label content as AI-Generated when you actually wrote it yourself, there is zero penalty. The system is designed to incentivise over-disclosure. You are always safe saying "AI made this." You are never penalised for being cautious.</p>
      </div>
      <div className="card">
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>COMMON QUESTIONS</div>
        <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          {[
            ["Does spell-check count as AI?", "No. Spell-check corrects errors but does not generate content. Content using only grammar and spell-check tools is Original Human."],
            ["What about AI autocomplete?", "AI-Assisted if more than 20% of the content came from AI suggestions. Original Human if under 20%."],
            ["What if I translated my writing with AI?", "AI-Assisted. The ideas are yours; the language is AI-generated. That is a genuine collaboration."],
            ["What about phone camera processing?", "Original Human. Computational photography (HDR, noise reduction) is standard photographic technology, not AI generation."],
            ["I used AI for a first draft then rewrote it heavily. Which category?", "AI-Assisted if you substantially changed the content. AI-Generated if you mainly cleaned up and lightly edited."],
            ["What about satire or fiction?", "Origin is about how the content was made, not whether it is literally true. A human-written satirical piece is Original Human."],
          ].map(([q, a], i) => (
            <div key={i} style={{ padding: 14, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 6, color: C.navy }}>{q}</div>
              <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{a}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function PublicIntegration({ embedTab, setEmbedTab }) {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={4} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Add TIP™ to Your Site</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 24, fontWeight: 300, lineHeight: 1.7 }}>TIP™ integrates into existing web infrastructure using standard HTTP response headers and HTML meta tags. The simplest integration takes five minutes and requires no code changes. Six tiers let you go as deep as you need.</p>
      <div className="rg-tabs" style={{ display: "flex", gap: 6, marginBottom: 24 }}>
        {[{ id: "widget", label: "HTTP Headers" }, { id: "extension", label: "Browser Extension" }, { id: "opengraph", label: "Meta Tags" }, { id: "api", label: "SDK / API" }].map(t => (
          <button key={t.id} onClick={() => setEmbedTab(t.id)} style={{ padding: "7px 14px", borderRadius: 5, border: `1px solid ${embedTab === t.id ? C.gold : C.border}`, background: embedTab === t.id ? C.goldDim : "transparent", color: embedTab === t.id ? C.gold : C.textMuted, cursor: "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: embedTab === t.id ? 600 : 400 }}>{t.label}</button>
        ))}
      </div>
      {embedTab === "widget" && (
        <div className="card">
          <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>TIER 0: HTTP HEADERS (5 MINUTES, NO CODE REQUIRED)</div>
          <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, marginBottom: 20, fontWeight: 300 }}>Add these to your web server config. Works with Apache, Nginx, Caddy, Cloudflare, Vercel, and Netlify. No SDK. No JavaScript. One configuration change and every page you serve declares its TIP™ provenance.</p>
          <div className="code-block" style={{ marginBottom: 20 }}>
            <div style={{ color: "#718096" }}># Nginx example</div>
            <div><span style={{ color: "#68D391" }}>add_header</span> TIP-Author <span style={{ color: "#ED8936" }}>"tip://id/US-a3f8c91b2d4e7021"</span>;</div>
            <div><span style={{ color: "#68D391" }}>add_header</span> TIP-Content <span style={{ color: "#ED8936" }}>"tip://c/OH-7f2a91bc3d5e-a3f8"</span>;</div>
            <div><span style={{ color: "#68D391" }}>add_header</span> TIP-Origin <span style={{ color: "#ED8936" }}>"original-human"</span>;</div>
            <div><span style={{ color: "#68D391" }}>add_header</span> TIP-Trust-Score <span style={{ color: "#ED8936" }}>"892"</span>;</div>
            <div><span style={{ color: "#68D391" }}>add_header</span> TIP-Signature <span style={{ color: "#ED8936" }}>"[ML-DSA-65 signature]"</span>;</div>
          </div>
          <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
            {[["Tier 0: HTTP Headers", "5 min. One config change."], ["Tier 1: HTML Meta Tags", "10 min. Per-article provenance."], ["Tier 2: Badge Widget", "30 min. One script tag."], ["Tier 3: CMS Plugin", "5 min. WordPress/Shopify."], ["Tier 4: SDK", "1 to 5 days. Full API access."], ["Tier 5: Run a Node", "1 to 2 weeks. Full independence."]].map(([title, desc], i) => (
              <div key={i} style={{ padding: 14, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, marginBottom: 6, letterSpacing: 1 }}>{title}</div>
                <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {embedTab === "extension" && (
        <div className="card">
          <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>BROWSER EXTENSION: TRUST BADGES EVERYWHERE</div>
          <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, marginBottom: 20, fontWeight: 300 }}>The TIP™ browser extension reads trust headers and injects badges directly into the pages you browse. For sites that have not yet added TIP™ headers, the extension can still display trust information for content creators who have a TIP-ID linked to their profile.</p>
          <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            {[["Facebook / Meta", "Badge appears next to profile names. Matches via profile URL to TIP-ID."], ["YouTube", "Badge overlaid on channel name and video title. Content hash from video metadata."], ["X / Twitter", "Badge next to display name. Content hash from tweet text and media URLs."]].map(([t, d], i) => (
              <div key={i} style={{ padding: 16, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>{t}</div>
                <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300 }}>{d}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {embedTab === "opengraph" && (
        <div className="card">
          <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>HTML META TAGS: PER-ARTICLE PROVENANCE</div>
          <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, marginBottom: 20, fontWeight: 300 }}>Add TIP™ meta tags to individual pages for per-article provenance. These appear in link previews on Slack, Discord, iMessage, and any platform that reads Open Graph metadata.</p>
          <div className="code-block">
            {[["tip:author","tip://id/US-a3f8..."],["tip:content","tip://c/OH-7f2a..."],["tip:origin","original-human"],["tip:score","892"],["tip:status","VERIFIED"]].map(([prop, content], i) => (
              <div key={i}><span style={{ color: "#ECC94B" }}>&lt;meta</span> <span style={{ color: "#68D391" }}>property</span>=<span style={{ color: "#ED8936" }}>"{prop}"</span> <span style={{ color: "#68D391" }}>content</span>=<span style={{ color: "#ED8936" }}>"{content}"</span> <span style={{ color: "#ECC94B" }}>/&gt;</span></div>
            ))}
          </div>
        </div>
      )}
      {embedTab === "api" && (
        <div className="card">
          <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>SDK AND REST API</div>
          <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, marginBottom: 16, fontWeight: 300 }}>The TIP™ SDK is available as open-source packages for JavaScript, Python, Rust, and Go. The REST API requires no SDK and works with any language.</p>
          <div className="code-block">
            <div style={{ color: "#ECC94B" }}>GET /v1/ptid/PTID-US-a3f8c91b2d4e7021/score</div>
            <div style={{ marginTop: 10, color: "#718096" }}>// Response:</div>
            <div>{"{"}</div>
            {[['"ptid"','"PTID-US-a3f8c91b2d4e7021"',"#ED8936"],['"score"','847',"#63B3ED"],['"tier"','"HIGHLY_TRUSTED"',"#ED8936"],['"verified_since"','"2026-03-15T00:00:00Z"',"#ED8936"],['"content_count"','142',"#63B3ED"],['"disputes"','0',"#63B3ED"]].map(([key,val,vc],i) => (
              <div key={i} style={{ paddingLeft: 16 }}><span style={{ color: "#68D391" }}>{key}</span>: <span style={{ color: vc }}>{val}</span>,</div>
            ))}
            <div>{"}"}</div>
          </div>
        </div>
      )}
    </div>
  );
}

function PublicPrivacy() {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={6} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Your Privacy and Your Data</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 12, fontWeight: 300, lineHeight: 1.7 }}>TIP™ is designed from the ground up to collect the minimum data necessary, store it in the most privacy-preserving way possible, and give you control over what others can see.</p>
      <div className="divider" style={{ marginBottom: 28 }} />

      <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 28 }}>
        {[
          { title: "Zero raw biometrics stored", color: C.green, bg: "#F0FDF4", desc: "Your facial scan produces a mathematical hash. Only the hash is stored. We cannot reconstruct your face, and neither can anyone who accesses our system. Your biometric data is processed in a secure enclave on your device and never transmitted in raw form." },
          { title: "Your dedup hash is private", color: C.teal, bg: "#F0FAFA", desc: "The deduplication check that ensures one person equals one TIP-ID uses a device-held secret called a pepper. Without your device, your hash cannot be recomputed, even by someone with access to a government ID database. Your dedup hash is never published to the public ledger." },
          { title: "You control your score visibility", color: C.blue, bg: "#F0F7FF", desc: "Choose from three display levels: your full numeric score visible to all, your tier label only (Trusted, Highly Trusted, etc.), or simply a verified/unverified indicator. You can change this at any time." },
          { title: "You can request erasure", color: C.purple, bg: "#F5F3FF", desc: "Under GDPR Article 17, you have the right to have your score history deleted. Your TIP-ID remains on the ledger (required to preserve the provenance of your published content), but your event history and score reset. Your content provenance records are unaffected." },
        ].map((item, i) => (
          <div key={i} style={{ background: item.bg, border: `1px solid ${item.color}20`, borderRadius: 10, padding: 22, borderLeft: `4px solid ${item.color}` }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: C.navy, marginBottom: 10 }}>{item.title}</div>
            <p style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, margin: 0 }}>{item.desc}</p>
          </div>
        ))}
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>VERIFICATION PROVIDER TRANSPARENCY</div>
        <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, marginBottom: 16 }}>Every organisation accredited to verify identities (called a Verification Provider, or VP) must disclose the following publicly, updated quarterly:</p>
        <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
          {[["Country of operation","Where the VP operates and which data localisation laws apply."],["Government data requests","Aggregate count and category of any government data access requests received, published to the maximum extent the law allows."],["Warrant canary","A quarterly statement confirming no undisclosed compelled access has occurred. Silence means it has."]].map(([title, desc], i) => (
            <div key={i} style={{ padding: 14, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.navy, marginBottom: 6 }}>{title}</div>
              <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ background: "#FFFBEB", border: `1px solid ${C.gold}20`, borderRadius: 12, padding: 24, borderLeft: `4px solid ${C.gold}` }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 8 }}>REGULATORY COMPLIANCE</div>
        <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>TIP™ is designed to comply with GDPR, BIPA, and equivalent biometric privacy regulations worldwide. A full Data Protection Impact Assessment is conducted and published before any European deployment. A Data Protection Officer is appointed as required by Article 37 of GDPR. Verification Providers operating in jurisdictions with mandatory government access laws are flagged with an Amber indicator so users are informed before they choose a provider.</p>
      </div>
    </div>
  );
}

// ─── ADMIN PAGES ──────────────────────────────────────────────────────────────

function AdminHome({ version }) {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 32 }}>
        <div style={{ padding: "4px 12px", background: `${C.adminAccent}10`, border: `1px solid ${C.adminAccent}20`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.adminAccent, letterSpacing: 2 }}>INTERNAL VIEW</div>
        <div style={{ fontSize: 11, color: C.textMuted }}>Full protocol documentation including business strategy, pricing, and launch plan</div>
      </div>
      <div style={{ textAlign: "center", marginBottom: 56 }}>
        <div style={{ fontSize: 11, color: C.gold, letterSpacing: 5, fontWeight: 600, marginBottom: 16 }}>THE AI LAB · TRUST IDENTITY PROTOCOL (TIP™)</div>
        <h1 className="serif hero-title" style={{ fontSize: 46, fontWeight: 700, lineHeight: 1.15, marginBottom: 20, color: C.navy }}>
          TIP™ Protocol Overview<br /><em style={{ color: C.gold, fontWeight: 400 }}>Internal Reference.</em>
        </h1>
        <p className="hero-desc" style={{ color: C.textSecondary, fontSize: 15, maxWidth: 640, margin: "0 auto", lineHeight: 1.75, fontWeight: 300 }}>
          TIP™ is a federated, post-quantum, open-source protocol that verifies identity and content provenance across the internet. Like HTTPS secured data in transit, TIP™ secures trust in origin. Anyone can implement it. Anyone can run a node.
        </p>
      </div>
      <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 28 }}>
        <div className="card">
          <TrackLabel letter="1" text="TIP-ID (Identity Layer)" />
          <div className="mono" style={{ fontSize: 11, color: C.gold, margin: "12px 0 8px" }}>tip://id/US-a3f8c91b2d4e7021</div>
          <p style={{ color: C.textSecondary, fontSize: 13, lineHeight: 1.7, marginBottom: 16, fontWeight: 300 }}>A verified human identity bound to a post-quantum keypair via 4-layer biometric verification. Federated: resolvable on any TIP node. Portable across providers. One human, one TIP-ID.</p>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <span className="tag" style={{ background: `${C.gold}10`, color: C.gold, border: `1px solid ${C.gold}25` }}>BIOMETRIC LOCKED</span>
            <span className="tag" style={{ background: `${C.blue}10`, color: C.blue, border: `1px solid ${C.blue}25` }}>QUANTUM-SAFE</span>
            <span className="tag" style={{ background: `${C.green}10`, color: C.green, border: `1px solid ${C.green}25` }}>SYBIL-RESISTANT</span>
          </div>
        </div>
        <div className="card">
          <TrackLabel letter="2" text="TIP-CONTENT (Provenance Layer)" />
          <div className="mono" style={{ fontSize: 11, color: C.gold, margin: "12px 0 8px" }}>tip://c/OH-7f2a91bc3d5e-a3f8</div>
          <p style={{ color: C.textSecondary, fontSize: 13, lineHeight: 1.7, marginBottom: 16, fontWeight: 300 }}>Content provenance with mandatory origin declaration. Cryptographic hash + origin (OH/AA/AG/MX) + creator's TIP-ID, signed and recorded on the federated DAG. Verifiable via HTTP headers or meta tags.</p>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <span className="tag" style={{ background: `${C.gold}10`, color: C.gold, border: `1px solid ${C.gold}25` }}>HASH-LOCKED</span>
            <span className="tag" style={{ background: `${C.orange}10`, color: C.orange, border: `1px solid ${C.orange}25` }}>TAMPER-EVIDENT</span>
            <span className="tag" style={{ background: `${C.blue}10`, color: C.blue, border: `1px solid ${C.blue}25` }}>DAG-RECORDED</span>
          </div>
        </div>
      </div>
      <div className="card" style={{ padding: 32, background: C.surface }}>
        <div style={{ textAlign: "center", marginBottom: 20 }}>
          <div style={{ fontSize: 10, color: C.textMuted, letterSpacing: 3, marginBottom: 4 }}>THREE COMPOSABLE PROTOCOL LAYERS</div>
          <div className="divider" style={{ maxWidth: 200, margin: "0 auto" }} />
        </div>
        <div className="rg3" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
          {[
            { num: 1, title: "TIP-ID (Identity)", desc: "Verified human bound to post-quantum keypair. Four-layer biometrics. Federated providers.", color: C.blue },
            { num: 2, title: "TIP-CONTENT (Provenance)", desc: "Content hash + mandatory origin declaration (OH/AA/AG/MX). Signed, immutable, on-DAG.", color: C.purple },
            { num: 3, title: "TIP-TRUST (Reputation)", desc: "Public score 0 to 1000. Deterministic from DAG history. Computed by any node. No central database.", color: C.green },
          ].map((layer, i) => (
            <div key={i} style={{ textAlign: "center", padding: 20, background: C.bg, borderRadius: 8, border: `1px solid ${C.border}`, borderTop: `3px solid ${layer.color}` }}>
              <SN num={layer.num} />
              <div style={{ fontSize: 13, fontWeight: 600, marginTop: 8, color: C.navy }}>{layer.title}</div>
              <div style={{ fontSize: 11.5, color: C.textSecondary, marginTop: 8, lineHeight: 1.6, fontWeight: 300 }}>{layer.desc}</div>
            </div>
          ))}
        </div>
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <p style={{ fontSize: 12, color: C.textMuted, fontWeight: 300 }}>Each layer is independently useful. A site can implement Layer 2 alone (add TIP™ headers in 5 minutes) without deploying the full stack.</p>
        </div>
      </div>

      {version === "v2" && (
        <div style={{ marginTop: 24, background: C.navy, borderRadius: 12, padding: "16px 24px", display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: C.gold, letterSpacing: 3 }}>v2 · CRITICAL FIXES APPLIED</span>
          <span style={{ fontSize: 11, color: "#94A3B8", fontWeight: 300 }}>FIX-02 Privacy Architecture · FIX-03 Pre-Scan Calibration · FIX-05 Revocation · FIX-06 GDPR · FIX-08 Jurisdiction Tiers</span>
        </div>
      )}
    </div>
  );
}

function AdminLicensing() {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={3} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>The Three-Layer Licensing Model</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 12, fontWeight: 300, lineHeight: 1.7 }}>Free where it drives adoption. Paid where enterprises profit. Free users build the network; enterprises pay for the value that network creates.</p>
      <div className="divider" style={{ marginBottom: 28 }} />
      <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16, marginBottom: 24 }}>
        {[
          { letter: "A", title: "Protocol Specification", license: "CC-BY 4.0", color: C.green, who: "Free for everyone. Forever.", desc: "The TIP™ spec is published under Creative Commons. Anyone can implement TIP™ from the spec alone, without paying, without asking permission. Like the HTTP RFC. Irrevocable." },
          { letter: "B", title: "Reference Implementation", license: "TIP™ Community License", color: C.blue, who: "Free under $500K revenue. Paid above.", desc: "The AI Lab's code (node, SDK, tools) is licensed under TIPCL-1.0. Free for individuals, nonprofits, education, governments, journalists, and businesses under $500K annual revenue. Enterprises above $500K pay a tiered fee. Mandatory UI attribution: 'Built on TIP Protocol by The AI Lab'. Auto-converts to Apache 2.0 on January 1, 2031. NOTICE file attribution and trademark restrictions survive the conversion permanently." },
          { letter: "C", title: "Badge & Trademark System", license: "Two-tier: Open + Proprietary", color: C.gold, who: "Primary revenue engine.", desc: "The TIP™ Powered Mark is free. The AI Trust ID™ Seal and TIP™ Certified badge are proprietary, registry-issued, and require annual certification. The trademark never converts to open source. This is the permanent moat." },
        ].map((layer, i) => (
          <div key={i} style={{ background: C.bg, border: `1px solid ${layer.color}25`, borderRadius: 12, padding: 22, borderTop: `4px solid ${layer.color}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
              <span style={{ width: 28, height: 28, borderRadius: 6, border: `2px solid ${layer.color}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 700, color: layer.color, fontFamily: SERIF }}>{layer.letter}</span>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: C.navy }}>{layer.title}</div>
                <div style={{ fontSize: 10, color: layer.color, fontWeight: 600, letterSpacing: 1 }}>{layer.license}</div>
              </div>
            </div>
            <div style={{ fontSize: 10, fontWeight: 600, color: layer.color, marginBottom: 6, letterSpacing: 1, textTransform: "uppercase" }}>{layer.who}</div>
            <div style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300 }}>{layer.desc}</div>
            {i === 1 && <LicenseViewer compact={true} />}
          </div>
        ))}
      </div>
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>ENTERPRISE LICENSE TIERS (LAYER B: REFERENCE CODE)</div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
            <thead><tr style={{ background: C.surface }}>
              {["Company Revenue", "Annual Fee", "Includes"].map(h => (<th key={h} style={{ padding: "10px 12px", textAlign: "left", color: C.gold, fontWeight: 600, borderBottom: `2px solid ${C.border}`, fontSize: 10, letterSpacing: 1 }}>{h}</th>))}
            </tr></thead>
            <tbody>
              {[["$500K to $10M","$2,750/yr","Unlimited deployment of reference node, SDK, and tools"],["$10M to $50M","$11,000/yr","All above + priority support + dedicated onboarding"],["$50M to $500M","$55,000/yr","All above + SLA-backed API + custom integration support"],["$500M to $5B","$165,000/yr","All above + white-label options + source code escrow"],["$5B+","$550,000/yr","All above + protocol co-development + Gold council membership"]].map((row, i) => (
                <tr key={i} style={{ background: i % 2 === 0 ? C.surface : C.bg, borderBottom: `1px solid ${C.border}` }}>
                  {row.map((cell, j) => (<td key={j} style={{ padding: "10px 12px", color: j===1 ? C.navy : C.textSecondary, fontWeight: j===1 ? 600 : 300, fontSize: 12 }}>{cell}</td>))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>ENTERPRISE CERTIFICATION TIERS (LAYER C: PRIMARY REVENUE ENGINE)</div>
        <div className="rg5" style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 8, marginBottom: 16 }}>
          {[{ tier: "Sentinel", price: "$2.5K/yr", for: "Startups / SMEs" },{ tier: "Guardian", price: "$10K/yr", for: "Mid-market" },{ tier: "Silver", price: "$15K/yr", for: "Growth orgs" },{ tier: "Gold", price: "$50K/yr", for: "Industry leaders" },{ tier: "Platinum", price: "$100K/yr", for: "Enterprise" }].map((t, i) => (
            <div key={i} style={{ padding: 14, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}`, textAlign: "center" }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: C.navy }}>{t.tier}</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: C.gold, margin: "6px 0" }}>{t.price}</div>
              <div style={{ fontSize: 10, color: C.textMuted, fontWeight: 300 }}>{t.for}</div>
            </div>
          ))}
        </div>
      </div>

      {/* WHY THIS STRUCTURE MATTERS -- admin context */}
      <div className="card" style={{ marginBottom: 24, border: `1px solid ${C.teal}30`, borderTop: `3px solid ${C.teal}` }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.teal, letterSpacing: 2, marginBottom: 16 }}>WHY THE PAID + FREE + TRADEMARK STRUCTURE IS THE STRATEGY</div>
        <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, marginBottom: 20 }}>
          The three layers are not separate decisions -- they are one interlocking system designed for a specific outcome: TIP Protocol becomes the internet trust standard, and The AI Lab is the permanent authority that maintains it. Here is why each layer is essential and what breaks if any one is removed.
        </p>
        <div style={{ display: "grid", gap: 12 }}>
          {[
            {
              title: "Free use drives network effects that make the trademark valuable",
              color: C.green,
              body: "If journalists, nonprofits, and governments had to pay to use TIP Protocol, they would not adopt it. Without those high-credibility users, the network has no trust signal worth buying. The AI Lab's revenue comes from enterprises paying for the premium credential -- but that credential is only worth paying for if verified journalists and scientists are on the same network. Free use for the credible majority is what makes the paid credential valuable for the commercial minority.",
            },
            {
              title: "TIPCL-1.0 commercial tier funds the infrastructure that keeps the free tier running",
              color: C.blue,
              body: "Running the AI pre-scan classifier, maintaining the VP accreditation programme, operating founding nodes, responding to revocation broadcasts, publishing quarterly warrant canaries, and completing the DPIA -- all of this costs money. The commercial license revenue from enterprises above $500K is what funds the infrastructure that the free-tier users depend on. Without the paid tier, the free tier degrades or disappears. The commercial tier does not contradict the free tier -- it subsidises it.",
            },
            {
              title: "Trademarks are the permanent quality control mechanism",
              color: C.gold,
              body: "The TIPCL-1.0 code license converts to Apache 2.0 in 2031. The patents expire around 2047. But The AI Lab's trademarks -- TIP™, AI Trust ID™, AI Trust Registry™ -- never expire as long as they are renewed and used. This means that permanently, forever, only The AI Lab can call something TIP™. An implementor who cuts corners on biometric verification, skips the warrant canary, or uses fake VP accreditation cannot call their non-compliant product TIP™ without trademark infringement. The trademark is the enforcement mechanism for quality standards after the other protections expire.",
            },
            {
              title: "The combination creates a moat that scales with the network",
              color: C.purple,
              body: "A single-layer strategy fails. Patents alone: someone designs around them. Open source alone: no revenue to sustain the infrastructure. Trademark alone: no adoption without open access. The three layers together create something no single competitor can replicate in one move: an open network (CC-BY 4.0 spec) with quality-controlled credentials (trademarks) and sustainable funding (commercial licenses), all anchored to an immutable genesis block that every node in the world traces back to The AI Lab. The moat grows with every verified identity added, because no fork can copy the history.",
            },
          ].map(({ title, color, body }, i) => (
            <div key={i} style={{ padding: 18, background: `${color}06`, borderRadius: 8, border: `1px solid ${color}20`, borderLeft: `3px solid ${color}` }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: C.navy, marginBottom: 8 }}>{title}</div>
              <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, margin: 0 }}>{body}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>REVENUE PROJECTIONS (CONSERVATIVE)</div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead><tr style={{ background: C.surface }}>
              {["Revenue Stream","Year 1","Year 2","Year 3"].map(h => (<th key={h} style={{ padding: "10px 12px", textAlign: "left", color: C.gold, fontWeight: 600, borderBottom: `2px solid ${C.border}`, fontSize: 10, letterSpacing: 1 }}>{h}</th>))}
            </tr></thead>
            <tbody>
              {[["TIP™ Certification fees (primary)","$150K","$2.5M","$12M"],["Enterprise TIPCL licenses","$150K","$1.2M","$5.5M"],["API premium tiers","$150K","$800K","$3.5M"],["Concierge + Brand Safety","$50K","$500K","$2.5M"],["TOTAL","$500K","$5M","$23.5M"]].map((row, i) => (
                <tr key={i} style={{ background: i===4 ? `${C.gold}08` : i%2===0 ? C.surface : C.bg, borderBottom: `1px solid ${C.border}` }}>
                  {row.map((cell, j) => (<td key={j} style={{ padding: "10px 12px", color: i===4 ? C.gold : j===0 ? C.textSecondary : C.navy, fontWeight: i===4||j>0 ? 600 : 300, fontSize: 12 }}>{cell}</td>))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function AdminLaunch() {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={10} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Celebrity Launch Plan</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 12, fontWeight: 300, lineHeight: 1.7 }}>A trust system is only as credible as its most visible members. The launch strategy creates a cascade: celebrities verify, their audiences notice, organic adoption follows.</p>
      <div className="divider" style={{ marginBottom: 28 }} />
      <div className="card" style={{ marginBottom: 24, padding: 28, background: C.surface }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>LAUNCH SEQUENCE</div>
        <div className="rg-bio" style={{ display: "flex", gap: 14, alignItems: "stretch" }}>
          {[{ num: "01", title: "Credibility First", desc: "Tech leaders and journalists establish institutional legitimacy.", color: C.gold },{ num: "02", title: "Utility Second", desc: "Scientists and politicians demonstrate real-world value and urgency.", color: C.blue },{ num: "03", title: "Culture Third", desc: "Creators and entertainers drive mass consumer adoption.", color: C.green }].map((phase, i) => (
            <div key={i} style={{ flex: 1, display: "flex", alignItems: "stretch" }}>
              <div style={{ flex: 1, padding: 18, background: C.bg, borderRadius: 8, border: `1px solid ${phase.color}20` }}>
                <div style={{ fontSize: 22, fontWeight: 600, color: phase.color, fontFamily: SERIF, marginBottom: 6 }}>{phase.num}</div>
                <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 6, color: C.navy }}>{phase.title}</div>
                <div style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{phase.desc}</div>
              </div>
              {i < 2 && <div style={{ display: "flex", alignItems: "center", padding: "0 4px", color: C.textMuted, fontSize: 16 }}>›</div>}
            </div>
          ))}
        </div>
      </div>
      <div style={{ display: "grid", gap: 12 }}>
        {CELEBRITIES.map((c, i) => (
          <div key={i} className="card" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, padding: 22 }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 18, fontWeight: 600, color: C.gold, fontFamily: SERIF }}>{c.phase}</span>
                <span className="tag" style={{ background: `${C.gold}10`, color: C.gold, border: `1px solid ${C.gold}20` }}>{c.timing}</span>
              </div>
              <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 2, color: C.navy }}>{c.name}</div>
              <div style={{ fontSize: 11, color: C.textMuted, marginBottom: 10 }}>{c.targets}</div>
              <div style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300 }}><span style={{ fontWeight: 600, color: C.textPrimary }}>Why them: </span>{c.why}</div>
            </div>
            <div style={{ background: C.surface, borderRadius: 8, padding: 16, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, marginBottom: 8, letterSpacing: 2 }}>OUTREACH STRATEGY</div>
              <div style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300 }}>{c.strategy}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AdminRegistration({ regStep, setRegStep, version }) {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={5} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Registration Flow</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 32, fontWeight: 300, lineHeight: 1.7 }}>Four-layer identity verification. Each layer adds Sybil resistance. The system is designed so creating a fake identity is more expensive than behaving honestly.</p>
      <div className="rg-sidebar" style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 20 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {REG_STEPS.map((s, i) => (
            <button key={s.id} className={`step-btn ${regStep===i ? "active":""}`} onClick={() => setRegStep(i)}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: regStep===i ? C.gold : C.textMuted, fontFamily: SERIF, letterSpacing: 2 }}>{String(i+1).padStart(2,"0")}</span>
                <div>
                  <div style={{ fontWeight: 500, fontSize: 12.5 }}>{s.title}</div>
                  <div style={{ fontSize: 10, color: s.required ? C.gold : C.textMuted, marginTop: 2, letterSpacing: 1 }}>{s.required ? "REQUIRED" : "OPTIONAL"}</div>
                </div>
              </div>
            </button>
          ))}
        </div>
        <div className="card" style={{ animation: "fadeIn 0.3s ease" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
            <SN num={regStep+1} />
            <div>
              <h3 style={{ fontSize: 18, fontWeight: 600 }}>{REG_STEPS[regStep].title}</h3>
              <span className="tag" style={{ background: REG_STEPS[regStep].required ? `${C.gold}10` : `${C.blue}10`, color: REG_STEPS[regStep].required ? C.gold : C.blue, border: `1px solid ${REG_STEPS[regStep].required ? C.gold : C.blue}25`, marginTop: 4 }}>{REG_STEPS[regStep].required ? "REQUIRED" : "OPTIONAL · TRUST BOOST"}</span>
            </div>
          </div>
          <p style={{ color: C.textSecondary, fontSize: 13.5, lineHeight: 1.8, marginBottom: 24, fontWeight: 300 }}>{REG_STEPS[regStep].desc}</p>
          {regStep === 0 && (
            <div style={{ background: C.surface, borderRadius: 10, padding: 20, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, marginBottom: 14, color: C.gold, letterSpacing: 2 }}>TECHNICAL IMPLEMENTATION</div>
              <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                {[["OCR Extraction","Real-time document parsing extracts name, DOB, ID number, expiry. Cross-referenced against issuing authority databases."],["NFC Chip Read","For e-Passports with NFC chips, cryptographic verification of the ICAO digital signature against the issuing government."],["Tamper Detection","AI model trained on 10K+ forged documents. Checks micro-printing, hologram patterns, font consistency, edge artifacts."],["Dedup Hash", version==="v2" ? "Peppered SHAKE-256 (v2 FIX-02): hash includes device-held pepper. Never stored on public DAG. ZK proof published instead. See Privacy Architecture section." : "SHAKE-256 of ID number + DOB + country. Same combo equals same person. Prevents multi-account registration."]].map(([title,desc],i) => (
                  <div key={i} style={{ padding: 14, background: C.bg, borderRadius: 8, border: `1px solid ${i===3&&version==="v2" ? C.teal : C.border}` }}>
                    <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 6, color: i===3&&version==="v2" ? C.teal : C.textPrimary }}>{title}{i===3&&version==="v2"?" ✦ v2":""}</div>
                    <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {regStep === 1 && (
            <div style={{ background: C.surface, borderRadius: 10, padding: 20, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, marginBottom: 14, color: C.gold, letterSpacing: 2 }}>WHY 3D LIVENESS, NOT JUST A PHOTO</div>
              <div style={{ display: "flex", gap: 16 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: C.red, marginBottom: 8, letterSpacing: 1 }}>ATTACKS DEFEATED</div>
                  {["Printed photo held to camera","Screen replay of victim's video","2D deepfake in real-time","Silicone mask or prosthetic","3D-printed face model"].map((a,i) => (<div key={i} style={{ fontSize: 11, color: C.textSecondary, padding: "5px 0", borderBottom: `1px solid ${C.border}`, fontWeight: 300 }}>{a}</div>))}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: C.green, marginBottom: 8, letterSpacing: 1 }}>DETECTION METHODS</div>
                  {["Depth mapping via structured light or ToF","Micro-expression analysis (involuntary)","Skin texture frequency analysis","Sub-dermal blood flow detection","Challenge-response: random head turns, blinks"].map((a,i) => (<div key={i} style={{ fontSize: 11, color: C.textSecondary, padding: "5px 0", borderBottom: `1px solid ${C.border}`, fontWeight: 300 }}>{a}</div>))}
                </div>
              </div>
              <div style={{ marginTop: 16, padding: 14, background: "#FFF5F5", border: `1px solid ${C.red}20`, borderRadius: 8 }}>
                <div style={{ fontSize: 10, color: C.red, fontWeight: 600, letterSpacing: 1.5 }}>CRITICAL: ZERO RAW BIOMETRICS STORED</div>
                <div style={{ fontSize: 11, color: C.textSecondary, marginTop: 6, lineHeight: 1.65, fontWeight: 300 }}>The liveness check produces a 512-dimensional embedding vector, immediately hashed via SHAKE-256. Only the hash is stored. Raw biometric data is processed in a secure enclave and never leaves the device.</div>
              </div>
            </div>
          )}
          {regStep === 2 && (
            <div style={{ background: C.surface, borderRadius: 10, padding: 20, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, marginBottom: 14, color: C.gold, letterSpacing: 2 }}>DEVICE BIOMETRIC BINDING VIA WEBAUTHN/FIDO2</div>
              <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, marginBottom: 16, fontWeight: 300 }}>Uses the same protocol behind Apple and Google Passkeys. The device secure enclave generates a keypair. The private key NEVER leaves the hardware. We store only the public key bound to the TIP-ID.</p>
              <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
                {[["Apple","Touch ID / Face ID via Secure Enclave. Keys are hardware-bound and non-exportable."],["Android","Fingerprint / Face via TEE. StrongBox Keymaster on Pixel and Samsung flagships."],["Windows","Windows Hello via TPM 2.0. Falls back to security key (YubiKey, Google Titan)."]].map(([t,d],i) => (
                  <div key={i} style={{ padding: 14, background: C.bg, borderRadius: 8, border: `1px solid ${C.border}` }}>
                    <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 6 }}>{t}</div>
                    <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{d}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {regStep === 3 && (
            <div style={{ background: C.surface, borderRadius: 10, padding: 20, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, marginBottom: 14, color: C.gold, letterSpacing: 2 }}>SOCIAL GRAPH ATTESTATION: SYBIL DEFENSE</div>
              <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, marginBottom: 16, fontWeight: 300 }}>Three existing Trust ID holders with scores above 700 must vouch for a new user. Each voucher stakes 25 trust points. If the new user is caught posting fake content within 90 days, vouchers lose those points.</p>
              <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div style={{ padding: 14, background: "#F0FDF4", borderRadius: 8, border: `1px solid ${C.green}20` }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: C.green }}>Benefits</div>
                  <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, marginTop: 4, fontWeight: 300 }}>+50 starting bonus (550 vs 500). Faster trust accrual (1.5x multiplier for first 90 days). Immediate jury participation eligibility.</div>
                </div>
                <div style={{ padding: 14, background: "#FFFBEB", borderRadius: 8, border: `1px solid ${C.orange}20` }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: C.orange }}>Cold Start</div>
                  <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, marginTop: 4, fontWeight: 300 }}>At launch, The AI Lab staff and celebrity launch partners form the Genesis Ring: manually verified founding members who can vouch for early adopters.</div>
                </div>
              </div>
            </div>
          )}
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 24 }}>
            <button onClick={() => setRegStep(Math.max(0,regStep-1))} disabled={regStep===0} style={{ padding: "9px 18px", borderRadius: 6, border: `1px solid ${C.border}`, background: "none", color: regStep===0 ? C.textMuted : C.textPrimary, cursor: regStep===0 ? "default" : "pointer", fontFamily: "inherit", fontSize: 12 }}>Previous</button>
            <button onClick={() => setRegStep(Math.min(3,regStep+1))} disabled={regStep===3} style={{ padding: "9px 18px", borderRadius: 6, border: "none", background: regStep===3 ? C.border : C.navy, color: regStep===3 ? C.textMuted : "#FFF", cursor: regStep===3 ? "default" : "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: 600 }}>Next Step</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AdminContent({ version, embedTab, setEmbedTab }) {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={7} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Content Origin Declaration</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 12, fontWeight: 300, lineHeight: 1.7 }}>AI content that is honestly labelled is not a problem. The offense is not using AI. The offense is lying about using AI. This reframing eliminates the largest source of false positives.</p>
      <div className="divider" style={{ marginBottom: 28 }} />
      <div style={{ background: "#F0F7FF", border: `1px solid ${C.blue}20`, borderRadius: 12, padding: 24, marginBottom: 24, borderLeft: `4px solid ${C.blue}` }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.blue, letterSpacing: 2, marginBottom: 8 }}>THE ACCOUNTABILITY SHIFT</div>
        <p style={{ fontSize: 13.5, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>Instead of asking the impossible question "is this content fake?", the system asks: <strong style={{ color: C.navy, fontWeight: 600 }}>"does this content match its declared origin?"</strong> By requiring users to declare origin at registration, the system creates a signed, immutable commitment. If AI detection later reveals the content was AI-generated but declared as Original Human, that is a provable, intentional misrepresentation, not an ambiguous editorial judgment.</p>
      </div>
      <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>THE FOUR ORIGIN CATEGORIES (MANDATORY AT UPLOAD)</div>
      <OriginCategories />
      {version === "v2" && (
        <div className="card" style={{ marginBottom: 24, border: `1px solid ${C.teal}30`, borderTop: `3px solid ${C.teal}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.teal, letterSpacing: 2 }}>AI PRE-SCAN: CALIBRATED THRESHOLDS (v2 · FIX-03)</div>
            <span className="tag" style={{ background: `${C.teal}15`, color: C.teal, border: `1px solid ${C.teal}30` }}>REPLACES FIXED 85%</span>
          </div>
          <p style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, marginBottom: 16 }}>The v1 fixed 85% threshold treated a first-time registrant identically to a journalist with 500 verified OH posts, and ignored that academic writing, legal prose, and non-native English writing systematically score 15 to 25% higher on AI detectors. v2 replaces it with a creator-calibrated, content-type-aware threshold system.</p>
          <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 16 }}>
            <div style={{ padding: 14, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.navy, marginBottom: 8 }}>Creator-calibrated threshold</div>
              <p style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300, margin: 0 }}>Each TIP-ID accumulates a content profile. A creator with 200+ verified OH registrations has their threshold adjusted upward. Floor: 80%. Ceiling: 94%. No account bypasses the scan entirely.</p>
            </div>
            <div style={{ padding: 14, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.navy, marginBottom: 8 }}>Content-type thresholds</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: "4px 12px", fontSize: 11 }}>
                {[["Conversational","82%"],["News / journalistic","85%"],["Creative fiction","87%"],["Academic / technical","92%"],["Legal / formal","93%"]].map(([type,threshold],i) => (
                  <><span key={`t${i}`} style={{ color: C.textSecondary, fontWeight: 300 }}>{type}</span><span key={`v${i}`} style={{ color: C.teal, fontWeight: 600, textAlign: "right" }}>{threshold}</span></>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>CONTENT REGISTRATION FLOW (6 STEPS)</div>
        <div className="rg3" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
          {[
            { num: "01", title: "Origin Declaration", desc: "User selects OH, AA, AG, or MX. Signs declaration with TIP-ID private key." },
            { num: "02", title: version==="v2" ? "Calibrated Pre-Scan" : "AI Pre-Scan", desc: version==="v2" ? "Creator-calibrated threshold applied. Flag-but-mint: user can proceed with OH declaration; enters Stage 1 adjudication within 48 hours." : "System runs AI detection. If declared OH but AI probability exceeds 85%, user is prompted to reconsider. No penalty for changing before minting.", highlight: version==="v2" },
            { num: "03", title: "Dual Hash", desc: "SHAKE-256 cryptographic hash for exact matching. Perceptual hash (pHash/Chromaprint) in parallel for fuzzy matching across reposts." },
            { num: "04", title: "CTID Generation", desc: "tip://c/[ORIGIN]-[HASH14]-[ID_SHORT]. Origin code embedded in the URI itself, propagating with every link, citation, or embed." },
            { num: "05", title: "DAG Transaction", desc: "ML-DSA signature over (content_hash + origin_type). Origin declaration is cryptographically inseparable from the content." },
            { num: "06", title: "Embed Code", desc: "Origin-aware badge generated. HTTP headers and HTML meta tags ready to deploy." },
          ].map((step, i) => (
            <div key={i} style={{ padding: 16, background: step.highlight ? `${C.teal}06` : C.surface, borderRadius: 8, border: `1px solid ${step.highlight ? C.teal+"30" : C.border}` }}>
              <span style={{ fontSize: 18, fontWeight: 600, color: step.highlight ? C.teal : C.gold, fontFamily: SERIF }}>{step.num}</span>
              <div style={{ fontSize: 12, fontWeight: 600, marginTop: 6, marginBottom: 6, color: C.navy }}>{step.title}</div>
              <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{step.desc}</div>
            </div>
          ))}
        </div>
      </div>
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>PENALTY STRUCTURE: ORIGIN MISREPRESENTATION</div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
            <thead><tr style={{ background: C.surface }}>
              {["Offense","Impact","Escalation"].map(h => (<th key={h} style={{ padding: "10px 12px", textAlign: "left", color: C.gold, fontWeight: 600, borderBottom: `2px solid ${C.border}`, fontSize: 10, letterSpacing: 1 }}>{h}</th>))}
            </tr></thead>
            <tbody>
              {[["Declared ORIGINAL HUMAN, content is clearly AI-Generated","-100","1st offense warning",C.red],["Declared ORIGINAL HUMAN, content is AI-Assisted","-40","Warning",C.orange],["Declared AI-ASSISTED, content is fully AI-Generated","-25","Warning",C.orange],["Declared AI-GENERATED, content is actually original","+0","No penalty",C.green],["Repeat misrepresentation (2nd offense)","-200","Account flagged, pre-pub AI review required",C.red],["Repeat misrepresentation (3rd offense)","-350","Account suspended",C.red]].map((row, i) => (
                <tr key={i} style={{ background: i===3 ? "#F0FDF4" : i%2===0 ? C.surface : C.bg, borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "10px 12px", color: C.textSecondary, fontWeight: 300, fontSize: 11.5 }}>{row[0]}</td>
                  <td style={{ padding: "10px 12px", color: row[3], fontWeight: 600, fontSize: 12 }}>{row[1]}</td>
                  <td style={{ padding: "10px 12px", color: C.textSecondary, fontWeight: 300, fontSize: 11.5 }}>{row[2]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div style={{ background: "#F0FDF4", border: `1px solid ${C.green}20`, borderRadius: 12, padding: 24, borderLeft: `4px solid ${C.green}` }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.green, letterSpacing: 2, marginBottom: 8 }}>CONSERVATIVE LABELLING IS NEVER PENALISED</div>
        <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>If a user declares content as AI-Generated when it was actually human-created, there is zero penalty. The system incentivises over-disclosure. Users are always safe erring on the side of more AI disclosure.</p>
      </div>
    </div>
  );
}

function AdminBiometrics({ version }) {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={5} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Biometric Strategy</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 32, fontWeight: 300, lineHeight: 1.7 }}>Why we use all three biometric layers and why each alone is insufficient.</p>
      <div className="card" style={{ marginBottom: 20, border: `1px solid ${C.red}20`, background: "#FFF5F5" }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.red, marginBottom: 14, letterSpacing: 2 }}>THE CORE PROBLEM: NO SINGLE BIOMETRIC IS ENOUGH</div>
        <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
          {[["Fingerprint Alone","Not available on most laptops. Can be spoofed with gelatin molds. Some people lack readable prints. Cannot work remotely via browser."],["Face Scan Alone","2D photos defeat basic checks. Even 3D liveness can be fooled by frontier deepfakes. Identical twins create ambiguity. Changes with age and surgery."],["Gov ID Alone","IDs can be forged or stolen. Does not prove the person presenting the ID is the person ON the ID. Cannot detect deceased persons' documents."]].map(([title,desc],i) => (
            <div key={i} style={{ padding: 16, background: C.bg, borderRadius: 8, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>{title}</div>
              <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300 }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, marginBottom: 14, letterSpacing: 2 }}>DEDUPLICATION ARCHITECTURE {version==="v2" ? "(v2 PEPPERED HASH)" : "(v1)"}</div>
        <div className="code-block">
          {version==="v2" ? <>
            <div style={{ color: "#718096" }}>// v2: Peppered hash, nation-state safe (FIX-02)</div>
            <div style={{ color: "#68D391" }}>pepper = device_enclave.generate_random_256()</div>
            <div style={{ color: "#ECC94B", marginTop: 8 }}>dedup_hash = SHAKE-256(</div>
            <div style={{ paddingLeft: 20 }}>gov_id_number_normalized +</div>
            <div style={{ paddingLeft: 20 }}>date_of_birth_ISO +</div>
            <div style={{ paddingLeft: 20 }}>issuing_country_code +</div>
            <div style={{ paddingLeft: 20 }}>facial_embedding_hash +</div>
            <div style={{ paddingLeft: 20, color: "#68D391" }}>pepper  // never leaves device</div>
            <div style={{ color: "#ECC94B" }}>)</div>
            <div style={{ marginTop: 12, color: "#718096" }}>// ZK proof published to public DAG (not the hash itself)</div>
            <div><span style={{ color: "#ED8936" }}>zk_proof</span> = prove_uniqueness(dedup_hash, dedup_registry)</div>
            <div style={{ color: "#68D391" }}>dag.publish_registration(tip_id, zk_proof)</div>
          </> : <>
            <div style={{ color: "#718096" }}>// v1: Hash stored on DAG (see FIX-02 in v2)</div>
            <div style={{ color: "#ECC94B" }}>dedup_hash = SHAKE-256(</div>
            <div style={{ paddingLeft: 20 }}>gov_id_number_normalized +</div>
            <div style={{ paddingLeft: 20 }}>date_of_birth_ISO +</div>
            <div style={{ paddingLeft: 20 }}>issuing_country_code +</div>
            <div style={{ paddingLeft: 20 }}>facial_embedding_hash</div>
            <div style={{ color: "#ECC94B" }}>)</div>
            <div style={{ marginTop: 12, color: "#718096" }}>// Stored on public DAG</div>
            <div><span style={{ color: "#ED8936" }}>if</span> dedup_hash <span style={{ color: "#ED8936" }}>exists in</span> registry:</div>
            <div style={{ paddingLeft: 20, color: "#FC8181" }}>REJECT: "Identity already registered"</div>
            <div><span style={{ color: "#ED8936" }}>else</span>:</div>
            <div style={{ paddingLeft: 20, color: "#68D391" }}>CREATE new PTID, store dedup_hash</div>
          </>}
        </div>
      </div>
    </div>
  );
}

// Import admin compliance pages from v2 architecture
function PrivacyPage() {
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "inline-flex", alignItems: "center", gap: 10, marginBottom: 8 }}><SN num={9} /><span className="tag" style={{ background: `${C.teal}15`, color: C.teal, border: `1px solid ${C.teal}30` }}>v2 · FIX-02</span></div>
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Privacy Architecture</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 12, fontWeight: 300, lineHeight: 1.7 }}>The original deduplication hash was a surveillance vector. SHAKE-256(gov_id + DOB + country + facial_hash) stored on the public DAG is reidentifiable by any nation-state with access to a government ID database. v2 closes this gap with four architectural changes.</p>
      <div className="divider" style={{ marginBottom: 28 }} />
      <div style={{ background: "#FFF5F5", border: `1px solid ${C.red}20`, borderRadius: 12, padding: 24, marginBottom: 24, borderLeft: `4px solid ${C.red}` }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.red, letterSpacing: 2, marginBottom: 8 }}>THE ORIGINAL VULNERABILITY (v1)</div>
        <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>Three of the four inputs to the deduplication hash (government ID number, date of birth, and country code) exist in government databases worldwide. A nation-state actor could precompute hashes for every citizen in their database and correlate them against the public DAG. The "zero raw biometrics stored" guarantee addressed GDPR/BIPA but did not address this structural reidentification risk.</p>
      </div>
      <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>FOUR ARCHITECTURAL CHANGES (v2)</div>
      <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        {[
          { num: "01", title: "User-held pepper", color: C.teal, bg: "#F0FAFA", desc: "At registration, the device secure enclave generates a cryptographically random 256-bit pepper. The full dedup hash becomes SHAKE-256(gov_id + DOB + country + facial_hash + pepper). Only the user's device holds this pepper; the registry never stores it. Without the pepper, the hash cannot be recomputed even with full government database access." },
          { num: "02", title: "ZK proof on the DAG", color: C.blue, bg: "#F0F7FF", desc: "The DAG no longer stores the deduplication hash. Instead, it stores a zero-knowledge proof that the hash does not already exist in the dedup registry. The proof is verifiable without revealing the hash. Any node can confirm deduplication enforcement without gaining the data needed to perform reidentification." },
          { num: "03", title: "Separate dedup registry", color: C.purple, bg: "#F5F3FF", desc: "The peppered hashes are held in a dedicated deduplication registry, a separate service from the public DAG. It performs exactly one function: answering 'does this hash already exist?' with a ZK yes/no response. Access is restricted to accredited TIP-VPs performing live registrations only." },
          { num: "04", title: "Merkle audit root", color: C.green, bg: "#F0FDF4", desc: "The dedup registry publishes a Merkle root of its hash store to the public DAG on a defined schedule. Any operator can verify that the number of stored hashes matches the number of registered TIP-IDs, confirming deduplication enforcement, without accessing any individual hash value." },
        ].map((fix, i) => (
          <div key={i} style={{ background: fix.bg, border: `1px solid ${fix.color}20`, borderRadius: 10, padding: 20, borderLeft: `4px solid ${fix.color}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span style={{ fontSize: 16, fontWeight: 600, color: fix.color, fontFamily: SERIF }}>{fix.num}</span>
              <span style={{ fontSize: 14, fontWeight: 600, color: C.navy }}>{fix.title}</span>
            </div>
            <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, margin: 0 }}>{fix.desc}</p>
          </div>
        ))}
      </div>
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>UPDATED DEDUPLICATION HASH SPECIFICATION (v2)</div>
        <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.red, letterSpacing: 1, marginBottom: 8 }}>v1 (VULNERABLE)</div>
            <div className="code-block" style={{ fontSize: 11 }}>
              <div style={{ color: "#718096" }}>// Stored on public DAG: reidentifiable</div>
              <div style={{ color: "#ECC94B" }}>dedup_hash = SHAKE-256(</div>
              <div style={{ paddingLeft: 20, color: "#FC8181" }}>gov_id_number + date_of_birth + country_code + facial_embedding_hash</div>
              <div style={{ color: "#ECC94B" }}>)</div>
            </div>
          </div>
          <div>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.green, letterSpacing: 1, marginBottom: 8 }}>v2 (PROTECTED)</div>
            <div className="code-block" style={{ fontSize: 11 }}>
              <div style={{ color: "#68D391" }}>pepper = enclave.generate_random_256()</div>
              <div style={{ color: "#ECC94B", marginTop: 4 }}>dedup_hash = SHAKE-256(</div>
              <div style={{ paddingLeft: 20 }}>gov_id + dob + country + facial +</div>
              <div style={{ paddingLeft: 20, color: "#68D391" }}>pepper  // never leaves device</div>
              <div style={{ color: "#ECC94B" }}>)</div>
              <div style={{ color: "#68D391", marginTop: 4 }}>dag.publish(zk_proof_of_uniqueness)</div>
            </div>
          </div>
        </div>
      </div>
      <div className="card">
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>THREAT MODEL: v1 vs v2</div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
            <thead><tr style={{ background: C.surface }}>
              {["Threat Actor","v1 Outcome","v2 Outcome"].map(h => (<th key={h} style={{ padding: "10px 12px", textAlign: "left", color: C.gold, fontWeight: 600, borderBottom: `2px solid ${C.border}`, fontSize: 10, letterSpacing: 1 }}>{h}</th>))}
            </tr></thead>
            <tbody>
              {[["Nation-state with full ID database","Can precompute all hashes and correlate to DAG identities","Blocked: pepper is device-held and not recoverable from databases",C.red,C.green],["DAG node operator","Can observe all dedup hashes and attempt reversal","Sees only a ZK proof of uniqueness, with no hash or inputs exposed",C.red,C.green],["Compromised TIP-VP","Has access to all hashes it issued","Hash is peppered by user device; VP never holds the pepper",C.orange,C.green],["External researcher","Can enumerate DAG hashes for analysis","Merkle root confirms count; no individual hashes accessible",C.orange,C.teal]].map(([threat,v1,v2,v1c,v2c],i) => (
                <tr key={i} style={{ background: i%2===0 ? C.surface : C.bg, borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "10px 12px", color: C.textSecondary, fontWeight: 500, fontSize: 11.5 }}>{threat}</td>
                  <td style={{ padding: "10px 12px", color: v1c, fontWeight: 300, fontSize: 11 }}>{v1}</td>
                  <td style={{ padding: "10px 12px", color: v2c, fontWeight: 500, fontSize: 11 }}>{v2}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function RevocationPage() {
  const [activeType, setActiveType] = useState(0);
  const types = [
    { code: "REVOKE_VOLUNTARY", color: C.blue, label: "User-initiated", desc: "Signed by the user's current ML-DSA-65 keypair. Used when a user permanently retires their identity. All existing content registrations remain intact and verifiable. The TIP-ID is marked inactive while its historical record is preserved.", requires: "User signature only", cascade: "No cascade. Content provenance records remain valid." },
    { code: "REVOKE_VP", color: C.red, label: "Fraudulent registration", desc: "Issued by the originating TIP-VP when registration is found to have been fraudulent. Requires the VP's institutional ML-DSA-65 signature plus an evidence hash linking to supporting documentation. Cannot be issued by a different VP than the one that registered the identity.", requires: "Originating VP signature + evidence hash", cascade: "All content registered within 90 days prior auto-enters Stage 1 adjudication. Content older than 90 days is flagged but not auto-disputed." },
    { code: "REVOKE_DECEASED", color: C.orange, label: "Death notification", desc: "Issued by a TIP-VP after presentation of a verified death certificate. Creates a DECEASED_CONFIRMED status rather than full erasure. The identity record persists for historical content verification and cannot be reused. The account is locked against new content registrations, new vouching, and jury participation.", requires: "VP signature + death certificate hash (SHAKE-256)", cascade: "No penalty cascade. Existing content remains verified. Active jury commitments are dissolved with no score impact." },
    { code: "REVOKE_DEVICE", color: C.yellow, label: "Device compromise", desc: "User-initiated when a device credential is known to be lost or compromised. Invalidates only the FIDO2 device binding, not the identity itself. The TIP-ID remains active. New device binding requires in-person VP re-verification to generate a new pepper and update the FIDO2 credential.", requires: "User signature on any remaining valid device (or in-person VP)", cascade: "Device-signed transactions after the known compromise timestamp are flagged for review. Identity score is reduced by -15 pending re-verification." },
  ];
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "inline-flex", alignItems: "center", gap: 10, marginBottom: 8 }}><SN num={10} /><span className="tag" style={{ background: `${C.red}12`, color: C.red, border: `1px solid ${C.red}25` }}>v2 · FIX-05</span></div>
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Identity Revocation</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 12, fontWeight: 300, lineHeight: 1.7 }}>An append-only DAG is excellent for provenance but creates an enforcement void when an identity must be invalidated. v2 defines four revocation transaction types that handle revocation without erasing history, preserving content provenance integrity while enabling enforcement.</p>
      <div className="divider" style={{ marginBottom: 28 }} />
      <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
        {types.map((t, i) => (
          <button key={i} onClick={() => setActiveType(i)} style={{ padding: "8px 14px", borderRadius: 6, border: `1px solid ${activeType===i ? t.color : C.border}`, background: activeType===i ? `${t.color}10` : "transparent", color: activeType===i ? t.color : C.textMuted, cursor: "pointer", fontSize: 11, fontWeight: activeType===i ? 600 : 400, fontFamily: "inherit" }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>{t.code}</span>
          </button>
        ))}
      </div>
      <div className="card" style={{ marginBottom: 24, borderLeft: `4px solid ${types[activeType].color}`, animation: "fadeIn 0.3s ease" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
          <span className="tag" style={{ background: `${types[activeType].color}12`, color: types[activeType].color, border: `1px solid ${types[activeType].color}25` }}>{types[activeType].label}</span>
          <span className="mono" style={{ fontSize: 12, color: types[activeType].color }}>{types[activeType].code}</span>
        </div>
        <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, marginBottom: 16 }}>{types[activeType].desc}</p>
        <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "8px 16px" }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: C.textMuted }}>Requires:</span>
          <span style={{ fontSize: 11, color: C.textSecondary, fontWeight: 300 }}>{types[activeType].requires}</span>
          <span style={{ fontSize: 11, fontWeight: 600, color: C.textMuted }}>Cascade effect:</span>
          <span style={{ fontSize: 11, color: C.textSecondary, fontWeight: 300 }}>{types[activeType].cascade}</span>
        </div>
      </div>
      <div className="card">
        <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>REVOCATION TRANSACTION FORMAT (DAG SPEC)</div>
        <div className="code-block">
          <div style={{ color: "#718096" }}>// Revocation transaction structure</div>
          <div style={{ color: "#ECC94B" }}>revocation_tx {"{"}</div>
          <div style={{ paddingLeft: 20 }}><span style={{ color: "#68D391" }}>"tx_type"</span>: <span style={{ color: "#ED8936" }}>"REVOKE_VP"</span>,</div>
          <div style={{ paddingLeft: 20 }}><span style={{ color: "#68D391" }}>"tip_id"</span>: <span style={{ color: "#ED8936" }}>"tip://id/US-a3f8c91b2d4e7021"</span>,</div>
          <div style={{ paddingLeft: 20 }}><span style={{ color: "#68D391" }}>"reason_code"</span>: <span style={{ color: "#ED8936" }}>"FRAUDULENT_REGISTRATION"</span>,</div>
          <div style={{ paddingLeft: 20 }}><span style={{ color: "#68D391" }}>"evidence_hash"</span>: <span style={{ color: "#63B3ED" }}>SHAKE256(evidence_document)</span>,</div>
          <div style={{ paddingLeft: 20 }}><span style={{ color: "#68D391" }}>"issuing_vp_id"</span>: <span style={{ color: "#ED8936" }}>"tip://id/VP-EU-digiid-2026"</span>,</div>
          <div style={{ paddingLeft: 20 }}><span style={{ color: "#68D391" }}>"signature"</span>: <span style={{ color: "#63B3ED" }}>ML_DSA_65_sign(issuing_vp_keypair, tx_body)</span></div>
          <div style={{ color: "#ECC94B" }}>{"}"}</div>
        </div>
      </div>
    </div>
  );
}

function GDPRPage() {
  const [scoreMode, setScoreMode] = useState(0);
  const modes = [
    { id: "FULL_PUBLIC", label: "Full public", color: C.blue, desc: "Numeric score (0 to 1000) and full event history visible to all. Opt-in only. The user must explicitly consent to this level of disclosure." },
    { id: "TIER_ONLY", label: "Tier only", color: C.green, desc: "The five-tier label (HIGHLY TRUSTED, TRUSTED, etc.) is public. Numeric score and event history are private. This is the default for all accounts." },
    { id: "VERIFIED_ONLY", label: "Verified only", color: C.gold, desc: "Only a binary verified/unverified indicator is public. Score and tier are visible only to entities the user explicitly authorises via a signed permission token." },
  ];
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "inline-flex", alignItems: "center", gap: 10, marginBottom: 8 }}><SN num={11} /><span className="tag" style={{ background: `${C.purple}12`, color: C.purple, border: `1px solid ${C.purple}25` }}>v2 · FIX-06</span></div>
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>GDPR and Data Rights</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 12, fontWeight: 300, lineHeight: 1.7 }}>A numeric trust score linked to a verified identity is personal data under GDPR Article 4(1). The original design made this score a permanent, public, immutable record, directly conflicting with GDPR Article 17 (right to erasure) and Article 35 (DPIA requirement). v2 addresses all three obligations.</p>
      <div className="divider" style={{ marginBottom: 28 }} />
      <div style={{ background: "#F5F3FF", border: `1px solid ${C.purple}20`, borderRadius: 12, padding: 24, marginBottom: 24, borderLeft: `4px solid ${C.purple}` }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.purple, letterSpacing: 2, marginBottom: 8 }}>LEGAL REQUIREMENTS ADDRESSED IN v2</div>
        <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginTop: 4 }}>
          {[["GDPR Art. 4(1)","Trust score + verified identity = personal data. This is not discretionary; it is black-letter law."],["GDPR Art. 17","Right to erasure. Users can demand deletion of their score history. The content provenance record must survive; the score link to identity need not."],["GDPR Art. 35","DPIA mandatory before processing biometric data at scale. Must be published. Cannot be deferred to after launch."]].map(([article,desc],i) => (
            <div key={i} style={{ padding: 14, background: C.bg, borderRadius: 8, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.purple, marginBottom: 6, fontFamily: "'JetBrains Mono', monospace" }}>{article}</div>
              <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>
      <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>SCORE DISPLAY TIER SYSTEM (v2 DEFAULT: TIER_ONLY)</div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {modes.map((m, i) => (<button key={i} onClick={() => setScoreMode(i)} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${scoreMode===i ? m.color : C.border}`, background: scoreMode===i ? `${m.color}10` : "transparent", color: scoreMode===i ? m.color : C.textMuted, cursor: "pointer", fontSize: 12, fontWeight: scoreMode===i ? 600 : 400, fontFamily: "inherit" }}>{m.id}</button>))}
      </div>
      <div className="card" style={{ marginBottom: 24, borderLeft: `4px solid ${modes[scoreMode].color}`, animation: "fadeIn 0.3s ease" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <span className="tag" style={{ background: `${modes[scoreMode].color}12`, color: modes[scoreMode].color, border: `1px solid ${modes[scoreMode].color}25` }}>{modes[scoreMode].label}</span>
          {scoreMode===1 && <span className="tag" style={{ background: `${C.green}10`, color: C.green, border: `1px solid ${C.green}25` }}>DEFAULT</span>}
        </div>
        <p style={{ fontSize: 13.5, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>{modes[scoreMode].desc}</p>
      </div>
      <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        <div style={{ padding: 24, background: "#FFFBEB", border: `1px solid ${C.orange}20`, borderRadius: 12, borderLeft: `4px solid ${C.orange}` }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.orange, letterSpacing: 2, marginBottom: 10 }}>DPIA REQUIREMENT (ART. 35)</div>
          <p style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, margin: 0 }}>A Data Protection Impact Assessment is mandatory before any European deployment. It must be published publicly. Biometric data processing at scale is explicitly listed in Article 35(3)(b). This cannot be deferred. The DPIA must be completed and published before any TIP-VP begins onboarding European users.</p>
        </div>
        <div style={{ padding: 24, background: "#FFF5F5", border: `1px solid ${C.red}20`, borderRadius: 12, borderLeft: `4px solid ${C.red}` }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.red, letterSpacing: 2, marginBottom: 10 }}>DPO REQUIREMENT (ART. 37)</div>
          <p style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, margin: 0 }}>The AI Lab Intelligence Unobscured, Inc. is required to appoint a Data Protection Officer under Article 37(1)(b), which covers processing of biometric data for the purpose of uniquely identifying natural persons. This is a legal requirement with direct personal liability for the named DPO. The DPO must be appointed before any European data processing begins.</p>
        </div>
      </div>
    </div>
  );
}

function JurisdictionsPage() {
  const [activeTab, setActiveTab] = useState("classification");
  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "inline-flex", alignItems: "center", gap: 10, marginBottom: 8 }}><SN num={12} /><span className="tag" style={{ background: `${C.teal}15`, color: C.teal, border: `1px solid ${C.teal}30` }}>v2 · FIX-08</span></div>
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Jurisdiction Tiers and VP Transparency</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 12, fontWeight: 300, lineHeight: 1.7 }}>The v1 "no government backdoors" provision in the TIP-VP Code of Conduct is unenforceable. A contractual prohibition cannot override a nation's laws. v2 replaces it with an honest, tiered transparency framework achievable in every jurisdiction.</p>
      <div className="divider" style={{ marginBottom: 28 }} />
      <div style={{ display: "flex", gap: 6, marginBottom: 24 }}>
        {[{ id: "classification", label: "Tier Classification" },{ id: "register", label: "Transparency Register" },{ id: "conduct", label: "Code of Conduct" }].map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{ padding: "7px 14px", borderRadius: 5, border: `1px solid ${activeTab===t.id ? C.gold : C.border}`, background: activeTab===t.id ? C.goldDim : "transparent", color: activeTab===t.id ? C.gold : C.textMuted, cursor: "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: activeTab===t.id ? 600 : 400 }}>{t.label}</button>
        ))}
      </div>
      {activeTab === "classification" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
            {[
              { tier: "GREEN", color: C.green, bg: "#F0FDF4", title: "Full compliance", items: ["Strong rule of law","Independent judiciary","No mandatory backdoor legislation","No additional badge indicator shown"] },
              { tier: "AMBER", color: C.orange, bg: "#FFFBEB", title: "Conditional compliance", items: ["Moderate rule-of-law concerns","Ambiguous or evolving data access laws","VP meets technical standard","Visible jurisdiction indicator on badge"] },
              { tier: "RED", color: C.red, bg: "#FFF5F5", title: "Cannot be accredited", items: ["Mandatory government backdoor laws","Mass surveillance infrastructure","Laws incompatible with TIP-VP Code of Conduct","No accreditation permitted"] },
            ].map((tier, i) => (
              <div key={i} style={{ background: tier.bg, border: `1px solid ${tier.color}20`, borderRadius: 10, padding: 20, borderTop: `4px solid ${tier.color}` }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: tier.color, fontFamily: SERIF, marginBottom: 4 }}>{tier.tier}</div>
                <div style={{ fontSize: 11, fontWeight: 600, color: C.navy, marginBottom: 12 }}>{tier.title}</div>
                {tier.items.map((item, j) => (<div key={j} style={{ fontSize: 11, color: C.textSecondary, padding: "4px 0", borderBottom: `1px solid ${tier.color}15`, fontWeight: 300 }}>{item}</div>))}
              </div>
            ))}
          </div>
        </div>
      )}
      {activeTab === "register" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, marginBottom: 20, fontWeight: 300 }}>Every accredited TIP-VP must disclose the following in a publicly maintained register, updated quarterly.</p>
          <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 24 }}>
            {[["Country of incorporation","Legal jurisdiction where the TIP-VP is registered as a corporate entity."],["All operating countries","Every country in which the VP operates verification infrastructure or processes personal data."],["Government data requests","Aggregate count of government data access requests received in prior 12 months, published to the extent legally permitted."],["Warrant canary status","A quarterly-updated canary statement. Absence of update signals the canary has been triggered."]].map(([title,desc],i) => (
              <div key={i} style={{ padding: 16, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: C.navy, marginBottom: 6 }}>{title}</div>
                <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {activeTab === "conduct" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, marginBottom: 20, fontWeight: 300 }}>The v2 Code of Conduct replaces the unenforceable absolute prohibition with a best-efforts transparency standard. Every provision is achievable in every Green-tier jurisdiction.</p>
          <div style={{ display: "grid", gap: 12 }}>
            {[
              { obligation: "Disclose government requests", detail: "Publish aggregate count and category of all government data access requests, to the extent legally permitted.", tier: "All VPs" },
              { obligation: "Warrant canary, quarterly", detail: "Publish a signed statement confirming no compelled undisclosed access has occurred. Failure to update within 90 days is treated as a triggered canary.", tier: "All VPs" },
              { obligation: "Zero-knowledge architecture", detail: "Implement technical architecture that minimises data accessible to any single employee or government request. The peppered dedup hash system (v2 FIX-02) is the minimum acceptable implementation.", tier: "All VPs" },
              { obligation: "No data sale or voluntary sharing", detail: "This provision remains absolute. Voluntary data sharing with any third party, whether commercial or government, without a legal compulsion is grounds for immediate accreditation revocation.", tier: "All VPs · Absolute" },
              { obligation: "Annual independent security audit", detail: "Commission and publish an annual third-party security audit of the biometric verification pipeline. The report must be published in full.", tier: "All VPs" },
            ].map((item, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 2fr auto", gap: 16, padding: 16, background: i%2===0 ? C.surface : C.bg, borderRadius: 8, border: `1px solid ${C.border}`, alignItems: "start" }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: C.navy }}>{item.obligation}</div>
                <div style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{item.detail}</div>
                <span className="tag" style={{ background: item.tier.includes("Absolute") ? `${C.red}10` : `${C.green}10`, color: item.tier.includes("Absolute") ? C.red : C.green, border: `1px solid ${item.tier.includes("Absolute") ? C.red : C.green}25`, whiteSpace: "nowrap" }}>{item.tier}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── ADMIN: COMMAND CENTER ─────────────────────────────────────────────────────
// Leadership dashboard: what The AI Lab must complete, in priority order.

function AdminCommandCenter() {
  const [activeSection, setActiveSection] = useState("blocking");

  const sections = [
    { id: "blocking", label: "Blocking (Must ship)", color: C.red },
    { id: "launch", label: "At Launch", color: C.orange },
    { id: "90days", label: "Within 90 Days", color: C.blue },
    { id: "12months", label: "Within 12 Months", color: C.green },
  ];

  const tasks = {
    blocking: [
      {
        id: "B1", title: "Replace ML-DSA-65 stub with production PQ library",
        owner: "Engineering", effort: "4-6 weeks",
        detail: "Current implementation uses Ed25519 as a same-API development stand-in. Must be replaced with @noble/post-quantum or liboqs native bindings before any real biometric data is processed. API surface is identical; swap is a one-file change in shared/crypto.",
        risk: "CRITICAL: All signatures are non-quantum-safe until this is done.",
      },
      {
        id: "B2", title: "Replace ZK proof stub with real ZK-SNARK library",
        owner: "Engineering", effort: "6-8 weeks",
        detail: "The compute_zk_proof() function currently produces a Pedersen-style commitment. Must be replaced with a certified ZK-SNARK proof (snarkjs/Groth16 or arkworks). This is the cornerstone of the v2 FIX-02 privacy guarantee. Without it, the dedup hash is not truly private.",
        risk: "CRITICAL: ZK proof is the privacy architecture. Stub is not safe for production.",
      },
      {
        id: "B3", title: "Cold-storage SLH-DSA-128s genesis root keypair",
        owner: "Dinesh Mendhe / Legal", effort: "1 week",
        detail: "The genesis root keypair generated by seed.py must be moved to cold storage (HSM or hardware security module) with a minimum two-of-three multi-signature policy. The development genesis.json must be deleted and re-generated with the production key before any network launch. This key is permanent and irrevocable.",
        risk: "CRITICAL: If the genesis key is compromised, the entire network can be forked.",
      },
      {
        id: "B4", title: "Remove placeholder genesis ring and register real founding members",
        owner: "Dinesh Mendhe", effort: "2-4 weeks",
        detail: "The current seed output contains 'Test Journalist' and 'Test Researcher' as genesis ring members. These must be replaced with real, biometrically verified people who have agreed to be founding members. The genesis ring legitimises the entire network. Anyone reading genesis.json will see these names.",
        risk: "HIGH: Placeholder names destroy credibility with sophisticated reviewers and investors.",
      },
      {
        id: "B5", title: "Change all default secrets (JWT, Admin API key)",
        owner: "DevOps", effort: "1 day",
        detail: "TIP_JWT_SECRET and TIP_ADMIN_API_KEY ship with literal placeholder values 'CHANGE_THIS_IN_PRODUCTION'. These must be replaced with cryptographically random 256-bit values before any network-facing deployment. Log a warning if the defaults are detected (already implemented).",
        risk: "CRITICAL: Default secrets expose every deployed node to trivial authentication bypass.",
      },
      {
        id: "B6", title: "Complete DPIA before European deployment",
        owner: "Legal / DPO", effort: "4-6 weeks",
        detail: "GDPR Article 35(3)(b) mandates a Data Protection Impact Assessment before processing biometric data at scale. This is not optional and cannot be deferred. The DPIA must be published publicly. Deploying TIP™ in Europe without a completed DPIA exposes The AI Lab to fines of up to 4% of global annual revenue.",
        risk: "CRITICAL: Legal non-compliance. Cannot launch in EU without this.",
      },
      {
        id: "B7", title: "Appoint a Data Protection Officer",
        owner: "Legal / HR", effort: "2-4 weeks",
        detail: "GDPR Article 37(1)(b) requires appointment of a DPO for any organisation that processes biometric data for the purpose of uniquely identifying natural persons. The DPO must be named, published, and contactable. The role carries direct personal liability and must be filled by a qualified person.",
        risk: "CRITICAL: Legal requirement. Individual liability for the named DPO.",
      },
    ],
    launch: [
      {
        id: "L1", title: "Build and publish VP accreditation process",
        owner: "Business Development + Legal", effort: "3-4 weeks",
        detail: "No organisation can become a VP without a published accreditation process. Required: VP Code of Conduct (one page), technical integration guide, annual security audit requirement, jurisdiction tier classification for the first 30 countries, VP application fee structure ($5K/year minimum to signal commitment).",
        risk: "HIGH: Without this, The AI Lab cannot onboard any VP at launch.",
      },
      {
        id: "L2", title: "Build production AI pre-scan engine (replace heuristic stub)",
        owner: "ML Engineering", effort: "8-12 weeks",
        detail: "The current Python/Node pre-scan uses word-frequency heuristics. Production requires a fine-tuned ML classifier per content type (academic, journalistic, conversational, legal), creator-calibrated thresholds derived from DAG history, and the flag-but-mint mechanism with a proper adjudication queue. This is a revenue driver: enterprises pay for pre-scan API access.",
        risk: "HIGH: Heuristic pre-scan will produce false positives that damage creator trust.",
      },
      {
        id: "L3", title: "Build 7-juror adjudication pipeline",
        owner: "Product + Engineering", effort: "6-8 weeks",
        detail: "Stage 1 is automated (pre-scan). Stage 2 requires 7 jurors drawn from high-trust TIP-IDs (score >= 700). The adjudication pipeline must: select jurors randomly, present evidence, collect votes, apply the verdict to the DAG (ADJUDICATION_RESULT transaction), apply score delta, and handle appeals. Cap: 20 jury cases per TIP-ID per 30 days.",
        risk: "HIGH: Without adjudication, disputed content has no resolution path.",
      },
      {
        id: "L4", title: "Recruit 3 anchor journalists / researchers for genesis ring",
        owner: "Dinesh Mendhe", effort: "4-8 weeks",
        detail: "Approach: major outlet investigative journalists, AI safety researchers, or a named technologist with credibility outside the AI Lab's immediate network. Pitch: 'Be one of the first three people in the world with a provably verified internet identity. Your name anchors the founding of TIP™.' Offer: Founding Verified badge, non-transferable genesis status, advisory relationship.",
        risk: "HIGH: A genesis ring of only internal staff looks self-serving and fragile.",
      },
      {
        id: "L5", title: "Deploy node infrastructure on production hosting",
        owner: "DevOps", effort: "2-3 weeks",
        detail: "The node runs on Python 3.11+ or Node.js 18+, requires SQLite with WAL mode, TLS termination via Nginx or Caddy, and a minimum of 3 geographically distributed nodes for the founding network. Each node runs: REST API (port 4000), TCP gossip (port 4001), scheduled Merkle root publication every 6 hours.",
        risk: "HIGH: A single-node network is not federated. It is just a database.",
      },
    ],
    "90days": [
      {
        id: "N1", title: "Publish first quarterly warrant canary",
        owner: "Legal", effort: "1 day (then quarterly)",
        detail: "Every accredited VP must publish a signed quarterly statement confirming no compelled undisclosed government data access has occurred. The AI Lab itself must publish this first, modeling the behaviour for VPs. Absence of an update within 90 days is treated by the protocol as a triggered canary.",
        risk: "MEDIUM: Sets the transparency standard. Delayed start undermines trust.",
      },
      {
        id: "N2", title: "Build biometric vendor integration (iProov, Jumio, or Onfido)",
        owner: "Engineering + BD", effort: "6-10 weeks",
        detail: "The current biometric stack is documented but not integrated. A VP needs: gov ID OCR + tamper detection, NFC chip read for e-passports, 3D liveness check. The fastest path is integrating iProov (liveness) + Jumio (document verification) SDKs. Both have Python and JS SDKs. The AI Lab runs this for the founding VP; other VPs source their own vendors.",
        risk: "HIGH: Without real biometrics, the TIP-ID has no actual verification value.",
      },
      {
        id: "N3", title: "Commission and publish first VP security audit",
        owner: "Security + Engineering", effort: "4-6 weeks",
        detail: "Every VP is required by the Code of Conduct to commission an annual third-party security audit of its biometric verification pipeline. The AI Lab's founding VP must do this first and publish the full report. Recommended firms: Trail of Bits, Bishop Fox, or Cure53.",
        risk: "MEDIUM: Required by CoC. Also directly improves the security of the biometric pipeline.",
      },
      {
        id: "N4", title: "Approach Category A VPs: iProov, Jumio, Yoti directly",
        owner: "Business Development", effort: "Ongoing",
        detail: "These companies already verify identities at scale. Pitch: TIP-VP accreditation lets them issue a new credential type (TIP-ID) at the end of their existing verification pipeline with minimal new code. Revenue share: they earn a portion of Layer C certification fees for every identity they verify. Priority targets: Yoti (UK, strong privacy positioning), iProov (liveness, government contracts), Jumio (enterprise document verification).",
        risk: "MEDIUM: Each VP partnership multiplies the addressable user base.",
      },
      {
        id: "N5", title: "Resolve founding aristocracy governance (Fix #7)",
        owner: "Legal + Dinesh Mendhe", effort: "2-4 weeks",
        detail: "Current protocol: genesis ring members have permanent non-revocable founding status. This creates an aristocracy. Before launch, the governance rules must clarify: Can a founding member be revoked for fraud? (Recommended: yes, founding status grants a score premium, not immunity.) Can new founding members be added? (Recommended: no, the ring closes at network launch.) What is the key recovery mechanism if Dinesh Mendhe's TIP-ID is compromised?",
        risk: "MEDIUM: Unresolved governance creates legal ambiguity and credibility risk.",
      },
    ],
    "12months": [
      {
        id: "Y1", title: "Approach Category B VPs: Major news publishers",
        owner: "Business Development", effort: "Ongoing",
        detail: "CPJ, RSF, SPJ as institutional anchors. Individual flagship publishers: The New York Times, The Guardian, Reuters, AP. Pitch: 'Your journalists are being impersonated by AI. We will verify your credentialed journalists for free in year one. In return, you run a VP node.' The publisher verifies people they already know; the quality of verification is excellent. This also gets TIP™ written into editorial policy at major outlets.",
        risk: "LOW: These organisations are motivated. The pitch is aligned with their interests.",
      },
      {
        id: "Y2", title: "Approach Category C VPs: Government digital ID programmes",
        owner: "Policy + BD", effort: "12-24 months lead time",
        detail: "EU eIDAS notified bodies, UK DSIT digital identity framework, Estonia e-Residency. Also: submit TIP™ as a technical standard input to EU AI Act implementing regulations. The ask is not 'become a VP' but 'issue TIP-IDs as an output of your existing digital ID programme.' A government-issued TIP-ID carries maximum credibility. Timeline: start conversations now, expect 12-24 months to first agreement.",
        risk: "LOW: Long timeline is expected. Starting now is the right call.",
      },
      {
        id: "Y3", title: "Build temporal trust decay and recovery curves",
        owner: "Product + Data Science", effort: "4-6 weeks",
        detail: "Currently the 90-day clean record bonus applies indefinitely. A more sophisticated model would: decay trust scores slowly during periods of inactivity, accelerate recovery for consistent honest behaviour, and model the long-term equilibrium of the score distribution across the network. This matters for jury selection fairness and for the network's reputation signal at scale.",
        risk: "LOW: Enhancement. Current model is functional for launch.",
      },
      {
        id: "Y4", title: "Build model-level provenance extension for AG content",
        owner: "Engineering + Product", effort: "4-6 weeks",
        detail: "Current AG origin label tells you the content is AI-generated but not which model generated it. A v2.1 extension could embed the specific model attestation (GPT-4o, Claude 3.7, Gemini 2.0) in the CTID metadata. This requires cooperation from AI model providers: or a self-attestation mechanism for creators who disclose their tools.",
        risk: "LOW: Enhancement. Not required for v2.0 launch.",
      },
    ],
  };

  const activeColor = sections.find(s => s.id === activeSection)?.color || C.navy;
  const activeTasks = tasks[activeSection] || [];

  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
        <div style={{ padding: "4px 12px", background: `${C.red}10`, border: `1px solid ${C.red}20`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.red, letterSpacing: 2 }}>LEADERSHIP VIEW</div>
        <div style={{ fontSize: 11, color: C.textMuted }}>Prioritised action register for The AI Lab executive team</div>
      </div>
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Command Center</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 28, fontWeight: 300, lineHeight: 1.7 }}>
        Every item below is a concrete decision or deliverable that only The AI Lab can own. Items are sorted by the order they block launch. Nothing in this list can be delegated to a VP or publisher.
      </p>

      {/* Priority summary cards */}
      <div className="rg4" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 28 }}>
        {sections.map(s => (
          <button key={s.id} onClick={() => setActiveSection(s.id)}
            style={{ padding: "16px 12px", borderRadius: 10, border: `2px solid ${activeSection===s.id ? s.color : C.border}`, background: activeSection===s.id ? `${s.color}08` : C.bg, cursor: "pointer", fontFamily: "inherit", textAlign: "left", transition: "all 0.2s" }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: s.color, marginBottom: 8 }} />
            <div style={{ fontSize: 12, fontWeight: 600, color: C.navy, marginBottom: 4 }}>{s.label}</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: s.color }}>{tasks[s.id]?.length}</div>
            <div style={{ fontSize: 10, color: C.textMuted, marginTop: 2 }}>action items</div>
          </button>
        ))}
      </div>

      <div className="card" style={{ marginBottom: 12, padding: "10px 20px", borderLeft: `4px solid ${activeColor}`, background: `${activeColor}05`, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: activeColor, flexShrink: 0 }} />
        <div style={{ fontSize: 11, fontWeight: 600, color: activeColor, letterSpacing: 2 }}>{sections.find(s=>s.id===activeSection)?.label?.toUpperCase()}</div>
        <div style={{ fontSize: 11, color: C.textMuted, fontWeight: 300 }}>Click any item to expand. Owner and effort estimate shown for each.</div>
      </div>

      <div style={{ display: "grid", gap: 10 }}>
        {activeTasks.map((task, i) => (
          <TaskCard key={task.id} task={task} color={activeColor} />
        ))}
      </div>
    </div>
  );
}

function TaskCard({ task, color }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ border: `1px solid ${open ? color+"40" : C.border}`, borderRadius: 10, overflow: "hidden", transition: "all 0.25s", background: open ? `${color}04` : C.bg }}>
      <button onClick={() => setOpen(!open)}
        style={{ width: "100%", padding: "16px 20px", background: "none", border: "none", cursor: "pointer", fontFamily: "inherit", display: "flex", alignItems: "center", gap: 14, textAlign: "left" }}>
        <span className="mono" style={{ fontSize: 10, fontWeight: 700, color, minWidth: 28, letterSpacing: 0 }}>{task.id}</span>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: C.navy }}>{task.title}</span>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
          <span style={{ fontSize: 10, color: C.textMuted, background: C.surface, border: `1px solid ${C.border}`, borderRadius: 3, padding: "2px 8px", letterSpacing: 0.5 }}>{task.owner}</span>
          <span style={{ fontSize: 10, color: color, background: `${color}10`, border: `1px solid ${color}25`, borderRadius: 3, padding: "2px 8px", fontWeight: 600 }}>{task.effort}</span>
          <span style={{ color: C.textMuted, fontSize: 14, transform: open ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>▾</span>
        </div>
      </button>
      {open && (
        <div style={{ padding: "0 20px 18px 62px", animation: "fadeIn 0.2s ease" }}>
          <p style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, marginBottom: 12 }}>{task.detail}</p>
          <div style={{ padding: "8px 14px", background: `${color}08`, border: `1px solid ${color}25`, borderRadius: 6, fontSize: 11.5, color: color, fontWeight: 600 }}>
            Risk: <span style={{ fontWeight: 400, color: C.textSecondary }}>{task.risk}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── ADMIN: RESPONSIBILITY MATRIX ─────────────────────────────────────────────

function AdminResponsibilities() {
  const [activeParty, setActiveParty] = useState("ailab");

  const parties = [
    { id: "ailab",      label: "The AI Lab",         color: C.gold,   icon: "🏛" },
    { id: "tipvp",      label: "TIP Verification Providers", color: C.blue,   icon: "🔐" },
    { id: "publishers", label: "Large Publishers (YouTube, Facebook, etc.)", color: C.purple, icon: "📡" },
  ];

  const responsibilities = {
    ailab: {
      intro: "The AI Lab is the protocol authority. It owns the genesis block, the trademark, the accreditation process, and the AI detection infrastructure. These responsibilities cannot be delegated. VPs implement what The AI Lab specifies. Publishers consume what VPs produce.",
      owns: [
        { category: "Protocol Governance", items: [
          "Owns and signs the genesis block (SLH-DSA-128s root key, cold storage)",
          "Defines and publishes the TIP™ protocol specification (CC-BY 4.0)",
          "Sets and enforces the VP accreditation standards and Code of Conduct",
          "Classifies jurisdiction tiers (Green/Amber/Red) quarterly",
          "Manages the AI Trust Registry™ trademark globally",
          "Controls the Founding Ring and Genesis DAG bootstrap",
        ]},
        { category: "AI Detection Infrastructure", items: [
          "Builds and operates the calibrated AI pre-scan engine (NOT YouTube or Facebook)",
          "Trains per-content-type ML classifiers (academic, journalistic, conversational, legal)",
          "Manages creator-calibrated threshold adjustment from DAG history",
          "Operates Stage 1 automated adjudication pipeline",
          "Provides pre-scan API access to enterprises (this is a primary revenue driver)",
          "Sets the flag-but-mint policy and adjudication queue priorities",
        ]},
        { category: "Node Infrastructure (Founding)", items: [
          "Runs the founding DAG node network (minimum 3 geographically distributed nodes)",
          "Publishes Merkle root every 6 hours for public dedup audit",
          "Maintains the founding VP node (issuing TIP-IDs during bootstrap)",
          "Manages peer gossip network during early network growth",
          "Publishes quarterly warrant canary for the founding nodes",
        ]},
        { category: "Revenue and Business", items: [
          "Collects Layer C certification fees (primary revenue: $2.5K-$100K/year per organisation)",
          "Collects Layer B enterprise TIPCL license fees ($2.75K-$550K/year per company)",
          "Manages VP accreditation revenue (application fees, annual renewal)",
          "Provides AI pre-scan API as a paid enterprise tier",
          "Manages the AI Trust ID™ Seal. The only party that can issue the seal.",
        ]},
        { category: "Legal and Compliance", items: [
          "Completes DPIA before European deployment (GDPR Art. 35)",
          "Appoints a Data Protection Officer (GDPR Art. 37)",
          "Publishes quarterly warrant canaries across all founding nodes",
          "Establishes and enforces VP Code of Conduct globally",
          "Manages trademark enforcement for TIP™, AI Trust ID™, AI Trust Registry™",
        ]},
      ],
      does_not_own: [
        "Running biometric verification infrastructure for individual users (that is what VPs do)",
        "Detecting AI in YouTube or Facebook content (those platforms use TIP™ to file disputes (they run their own detection))",
        "Storing user biometrics at any point (biometrics are hashed in the VP's secure enclave and never transmitted raw)",
        "Adjudicating every individual content dispute (the 7-juror Stage 2 process is community-run)",
        "Requiring specific VP technical stacks (VPs can use any compliant biometric vendor)",
      ],
    },
    tipvp: {
      intro: "A Verification Provider is an organisation accredited by The AI Lab to issue TIP-IDs. A VP performs the four-layer biometric verification stack and calls the TIP node API. The AI Lab sets the standards. VPs implement them. VPs can be governments, banks, publishers, or biometric companies.",
      owns: [
        { category: "Identity Verification", items: [
          "Runs the full four-layer biometric stack: gov ID + liveness + device binding + optional social attestation",
          "Integrates a certified biometric vendor (iProov, Jumio, Onfido, or equivalent)",
          "Performs OCR extraction, NFC chip verification, tamper detection on government documents",
          "Runs the 3D liveness check (defeats printed photos, deepfakes, masks, silicone prosthetics)",
          "Generates the device-side pepper for the v2 peppered dedup hash",
          "Computes the ZK proof of uniqueness without ever transmitting the raw dedup hash",
        ]},
        { category: "Node Operation", items: [
          "Runs a TIP node (Python or Node.js reference implementation, or custom compliant implementation)",
          "Calls /v1/identity/register with the ZK proof and VP signature after biometric completion",
          "Maintains uptime, backups, and disaster recovery for their node",
          "Participates in the gossip network to propagate DAG transactions",
          "Polls the revocation list endpoint every 5 minutes for fresh revocations",
        ]},
        { category: "Transparency and Compliance", items: [
          "Publishes quarterly warrant canary (aggregate government data requests, to extent legally permitted)",
          "Maintains the Transparency Register: country of incorporation, all operating countries",
          "Commissions and publishes an annual third-party security audit of the biometric pipeline",
          "Implements and enforces the VP Code of Conduct signed at accreditation",
          "Maintains GDPR/BIPA compliance for all biometric data processed in their pipeline",
          "Applies Zero-Knowledge architecture. The dedup hash never leaves the user's device unencrypted",
        ]},
        { category: "User Interactions", items: [
          "Provides the user-facing verification interface (web app, mobile app, or in-person kiosk)",
          "Explains the privacy policy to users before biometric data is processed",
          "Handles user requests for erasure (Art. 17) by notifying the TIP node",
          "Issues TIP-IDs to verified users and returns the TIP-ID URI and keypair",
          "Manages the secure enclave where the pepper is generated and held",
        ]},
      ],
      does_not_own: [
        "AI detection (VPs verify identity, not content. Content detection is The AI Lab's infrastructure)",
        "The trust score computation (every node computes scores deterministically from DAG history)",
        "The AI Trust ID™ Seal (only The AI Lab issues the Seal to verified individuals)",
        "The protocol specification (The AI Lab owns and publishes it under CC-BY 4.0)",
        "Adjudication of content disputes (that is the 7-juror community pipeline)",
        "Setting penalty thresholds or score parameters (defined in the genesis block, immutable)",
      ],
      categories: [
        { label: "Category A: Identity-native orgs", color: C.green,  examples: "iProov, Jumio, Yoti, Onfido, banks with existing KYC, national ID programmes", pitch: "You already verify identities. TIP-ID is a new credential type you can issue at the end of your existing pipeline with minimal new code." },
        { label: "Category B: Content platforms", color: C.blue,    examples: "Major news publishers, journalism associations (CPJ, RSF, SPJ), academic institutions", pitch: "Your journalists are being impersonated. We will verify your credentialed journalists for free in year one. In return, you run a VP node." },
        { label: "Category C: Governments", color: C.purple, examples: "EU eIDAS notified bodies, UK DSIT, Estonia e-Residency, German eID", pitch: "Integrate TIP-ID issuance into your existing national digital ID programme as a value-add to existing digital ID holders." },
      ],
    },
    publishers: {
      intro: "Large publishers like YouTube, Facebook, X, LinkedIn, and major news sites are TIP™ consumers, not operators. They do not run the AI detection. They do not run VP nodes. They implement TIP™ headers and call The AI Lab's API to file disputes. Their role is adoption, not infrastructure.",
      owns: [
        { category: "What they implement (5 minutes)", items: [
          "Add TIP-Author, TIP-Content, TIP-Origin, TIP-Trust-Score HTTP headers to their responses",
          "Add TIP™ meta tags to published content pages",
          "Optionally install the CMS plugin (WordPress, Shopify) for automatic header injection",
          "Optionally embed the TIP™ badge widget (<tip-badge> custom element) on content pages",
        ]},
        { category: "What they call (API integration)", items: [
          "GET /v1/identity/:tipId/score: displays the author's trust score next to a byline",
          "GET /v1/content/:ctid: verifies a CTID before displaying a badge",
          "POST /v1/content/:ctid/dispute: to file a dispute when their own AI detector flags a mismatch",
          "GET /v1/revocations: to poll the revocation list and hide content from revoked identities",
        ]},
        { category: "What they optionally pay for (revenue for The AI Lab)", items: [
          "Layer C certification: AI Trust ID™ Seal for their platform ($2.5K-$100K/year)",
          "Layer B enterprise license: Reference node SDK for custom deep integrations ($2.75K-$550K/year)",
          "Pre-scan API: submit upload content to The AI Lab's calibrated AI classifier ($0.001-$0.01/check)",
          "Brand Safety API: monitor for impersonation of their platform's verified accounts",
        ]},
        { category: "What they ALREADY have that complements TIP™", items: [
          "Their own AI detection systems (Google DeepMind, Meta AI, etc.): these feed disputes INTO TIP™",
          "Their own moderation pipelines: TIP™ disputes become one input signal among many",
          "Their own creator monetisation and verification programmes: TIP™ score can gate access to programmes",
          "Existing HTTP header infrastructure: zero new deployment dependencies",
        ]},
      ],
      does_not_own: [
        "Running the AI detection for TIP™ (they use THEIR detection to file TIP™ disputes: The AI Lab runs TIP™ detection)",
        "Running a VP node (large publishers can become VPs, but this is optional and adds responsibility)",
        "Storing TIP-IDs or managing biometric data (they only read public TIP™ data via API)",
        "Computing trust scores (every node does this deterministically: publishers just read the result)",
        "Enforcing TIP™ policy (they choose whether to act on TIP™ score: TIP™ does not mandate platform policy)",
      ],
      key_insight: {
        title: "The Critical Distinction: Who Runs AI Detection?",
        body: "YouTube and Facebook run their own AI detection (Google has SynthID, Meta has its own classifiers). These run on THEIR infrastructure, detect AI in THEIR content, and produce a signal INTERNAL to their platform. When that signal fires and the content has a TIP™ signature declaring it as OH (Original Human), THAT is when they call POST /v1/content/:ctid/dispute: filing a dispute with TIP™. TIP™ then runs its own independent adjudication. The two detection systems are complementary, not competing. YouTube does not replace The AI Lab's pre-scan. The AI Lab's pre-scan does not replace YouTube's detection. Both run independently and TIP™ is the arbitration layer between them.",
      },
    },
  };

  const data = responsibilities[activeParty];

  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
        <div style={{ padding: "4px 12px", background: `${C.adminAccent}10`, border: `1px solid ${C.adminAccent}20`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.adminAccent, letterSpacing: 2 }}>INTERNAL VIEW</div>
      </div>
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Responsibility Matrix</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 28, fontWeight: 300, lineHeight: 1.7 }}>
        The three parties in the TIP™ ecosystem each have distinct, non-overlapping responsibilities. Understanding these boundaries is critical for investor conversations, VP negotiations, and publisher partnerships.
      </p>

      {/* Party selector */}
      <div style={{ display: "flex", gap: 8, marginBottom: 24, flexWrap: "wrap" }}>
        {parties.map(p => (
          <button key={p.id} onClick={() => setActiveParty(p.id)}
            style={{ padding: "10px 18px", borderRadius: 8, border: `2px solid ${activeParty===p.id ? p.color : C.border}`, background: activeParty===p.id ? `${p.color}10` : C.bg, cursor: "pointer", fontFamily: "inherit", display: "flex", alignItems: "center", gap: 8, transition: "all 0.2s" }}>
            <span style={{ fontSize: 16 }}>{p.icon}</span>
            <span style={{ fontSize: 12, fontWeight: 600, color: activeParty===p.id ? p.color : C.textSecondary }}>{p.label}</span>
          </button>
        ))}
      </div>

      {/* Intro */}
      {data && (
        <>
          <div style={{ background: "#F0F7FF", border: `1px solid ${C.blue}20`, borderRadius: 12, padding: 22, marginBottom: 24, borderLeft: `4px solid ${parties.find(p=>p.id===activeParty)?.color||C.blue}` }}>
            <p style={{ fontSize: 13.5, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>{data.intro}</p>
          </div>

          {/* Key insight box for publishers */}
          {activeParty === "publishers" && data.key_insight && (
            <div style={{ background: `${C.navy}`, borderRadius: 12, padding: 24, marginBottom: 24 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.gold, letterSpacing: 3, marginBottom: 12 }}>{data.key_insight.title}</div>
              <p style={{ fontSize: 13, color: "#CBD5E0", lineHeight: 1.75, fontWeight: 300, margin: 0 }}>{data.key_insight.body}</p>
            </div>
          )}

          {/* VP categories */}
          {activeParty === "tipvp" && data.categories && (
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 12 }}>THREE VP CATEGORIES AND HOW TO APPROACH EACH</div>
              <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                {data.categories.map((cat, i) => (
                  <div key={i} style={{ padding: 18, background: C.bg, borderRadius: 10, border: `1px solid ${cat.color}25`, borderTop: `3px solid ${cat.color}` }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: cat.color, marginBottom: 8 }}>{cat.label}</div>
                    <div style={{ fontSize: 11, color: C.textMuted, fontWeight: 300, marginBottom: 10 }}><span style={{ fontWeight: 600, color: C.textSecondary }}>Examples: </span>{cat.examples}</div>
                    <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300, padding: 10, background: `${cat.color}06`, borderRadius: 6, border: `1px solid ${cat.color}15` }}><span style={{ fontWeight: 600, color: cat.color }}>Pitch: </span>{cat.pitch}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Responsibility sections */}
          <div style={{ display: "grid", gap: 14, marginBottom: 24 }}>
            {data.owns.map((section, si) => (
              <div key={si} className="card" style={{ padding: 22 }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>{section.category.toUpperCase()}</div>
                <div style={{ display: "grid", gap: 8 }}>
                  {section.items.map((item, ii) => (
                    <div key={ii} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                      <span style={{ color: C.green, fontWeight: 700, fontSize: 13, flexShrink: 0, marginTop: 1 }}>✓</span>
                      <span style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Does NOT own */}
          <div className="card" style={{ borderLeft: `4px solid ${C.red}`, background: "#FFF5F5", border: `1px solid ${C.red}15` }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.red, letterSpacing: 2, marginBottom: 14 }}>WHAT {parties.find(p=>p.id===activeParty)?.label?.toUpperCase()} DOES NOT OWN</div>
            <div style={{ display: "grid", gap: 8 }}>
              {data.does_not_own.map((item, i) => (
                <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <span style={{ color: C.red, fontWeight: 700, fontSize: 13, flexShrink: 0, marginTop: 1 }}>✗</span>
                  <span style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{item}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ─── ADMIN: VP STRATEGY ────────────────────────────────────────────────────────

function AdminVPStrategy() {
  const [tab, setTab] = useState("build");

  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
        <div style={{ padding: "4px 12px", background: `${C.adminAccent}10`, border: `1px solid ${C.adminAccent}20`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.adminAccent, letterSpacing: 2 }}>INTERNAL VIEW</div>
      </div>
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>VP Strategy</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 24, fontWeight: 300, lineHeight: 1.7 }}>How to build a Verification Provider. How to approach organisations. What the accreditation process must look like before any VP can be onboarded.</p>

      <div className="rg-tabs" style={{ display: "flex", gap: 6, marginBottom: 24 }}>
        {[{id:"build",label:"How to Build a VP"},{id:"approach",label:"How to Approach Orgs"},{id:"accreditation",label:"Accreditation Process"},{id:"codesign",label:"VP Code of Conduct"}].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: "7px 14px", borderRadius: 5, border: `1px solid ${tab===t.id ? C.gold : C.border}`, background: tab===t.id ? C.goldDim : "transparent", color: tab===t.id ? C.gold : C.textMuted, cursor: "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: tab===t.id ? 600 : 400 }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "build" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div className="card" style={{ marginBottom: 20, borderTop: `3px solid ${C.blue}` }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>WHAT A VP IS: MECHANICALLY</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, marginBottom: 16 }}>
              A Verification Provider is a server (running The AI Lab's reference implementation or a custom-compliant equivalent) that performs the four-layer biometric verification stack and then calls the TIP node REST API at <span className="mono" style={{ fontSize: 11, color: C.navy }}>POST /v1/identity/register</span> with a valid ZK dedup proof and VP signature. The VP sits between the user's device and the DAG.
            </p>
            <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              {[
                { title: "The VP Code (what they deploy)", color: C.blue, items: ["TIP node: Python or Node.js reference implementation", "VP registration endpoint: receives biometric pipeline output", "ZK proof computation: runs on the user's device via VP-provided SDK", "Gossip participation: propagates DAG transactions to peers", "Revocation polling: checks every 5 minutes for fresh revocations"] },
                { title: "The Biometric Stack (what they source)", color: C.purple, items: ["iProov or equivalent: 3D liveness check (defeats deepfakes, masks, printed photos)", "Jumio or Onfido: gov ID OCR, NFC chip read, tamper detection", "WebAuthn/FIDO2: device biometric binding (Touch ID, Windows Hello, Android TEE)", "Secure enclave SDK: for pepper generation (pepper never leaves user device)", "Optional: social graph attestation interface (3 vouchers with score >= 700)"] },
              ].map((col, i) => (
                <div key={i} style={{ padding: 18, background: C.surface, borderRadius: 10, border: `1px solid ${col.color}20`, borderTop: `3px solid ${col.color}` }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: col.color, marginBottom: 12 }}>{col.title}</div>
                  {col.items.map((item, j) => (
                    <div key={j} style={{ display: "flex", gap: 8, marginBottom: 7, alignItems: "flex-start" }}>
                      <span style={{ color: col.color, fontSize: 11, flexShrink: 0, marginTop: 2 }}>→</span>
                      <span style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{item}</span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>

          <div className="card" style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>REGISTRATION FLOW: STEP BY STEP</div>
            <div className="rg3" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
              {[
                { num: "01", title: "User uploads gov ID", detail: "VP calls Jumio/Onfido API. OCR extracts name, DOB, ID number, expiry. NFC chip cryptographically verified for e-passports. Tamper detection runs. Data stays on VP's server temporarily." },
                { num: "02", title: "3D Liveness check", detail: "VP calls iProov API. User turns head, blinks. Depth mapping, micro-expression analysis, sub-dermal blood flow detection. Produces 512-dim facial embedding. Only the SHAKE-256 hash is stored: raw biometric is destroyed in the enclave." },
                { num: "03", title: "Device biometric binding", detail: "VP's SDK initiates WebAuthn/FIDO2 on the user's device. The device secure enclave generates a keypair. Private key never leaves hardware. VP stores only the public key bound to the TIP-ID." },
                { num: "04", title: "Pepper generation", detail: "The user's device secure enclave generates a 256-bit random pepper. This pepper is included in the dedup hash but NEVER transmitted to the VP server. Only the user's device holds it. Without the pepper, the hash cannot be recomputed." },
                { num: "05", title: "ZK proof computation", detail: "The user's device computes: dedup_hash = SHAKE-256(gov_id + DOB + country + face_hash + pepper). Then computes ZK proof of uniqueness. Only the proof is sent to the VP, not the hash." },
                { num: "06", title: "VP calls TIP node", detail: "VP calls POST /v1/identity/register with the ZK proof, its own VP signature, verification tier, and region. The TIP node validates, writes to DAG, and returns a TIP-ID + keypair to the user. The private key is NEVER stored by the node." },
              ].map((step, i) => (
                <div key={i} style={{ padding: 16, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
                  <div style={{ fontSize: 18, fontWeight: 600, color: C.gold, fontFamily: SERIF, marginBottom: 6 }}>{step.num}</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: C.navy, marginBottom: 6 }}>{step.title}</div>
                  <div style={{ fontSize: 11, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{step.detail}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ background: "#FFF5F5", border: `1px solid ${C.red}20`, borderRadius: 12, padding: 22, borderLeft: `4px solid ${C.red}` }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.red, letterSpacing: 2, marginBottom: 10 }}>WHAT MUST NEVER HAPPEN AT ANY VP</div>
            <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              {["Raw biometric data transmitted to any server (only hashes leave the device)", "The pepper transmitted to the VP server (device-held only, always)", "The raw dedup hash stored on the public DAG (only ZK proof is published)", "Private keys stored by any server (returned to user at registration, never stored)", "Government data shared voluntarily without legal compulsion (absolute prohibition: grounds for VP revocation)"].map((item, i) => (
                <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                  <span style={{ color: C.red, fontWeight: 700, fontSize: 13, flexShrink: 0, marginTop: 1 }}>✗</span>
                  <span style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{item}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === "approach" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          {[
            {
              cat: "CATEGORY A: Identity-Native Organisations",
              color: C.green, timing: "Approach immediately",
              targets: "iProov (liveness, London), Jumio (doc verification, US), Yoti (digital ID, UK), Onfido (enterprise KYC), Banks with existing KYC, eIDAS notified bodies",
              pitch: "You already verify identities at scale. TIP-VP accreditation lets you issue a new credential type: the TIP-ID: at the end of your existing verification pipeline. The marginal cost to you is a REST API call after your existing verification completes. In return, you earn a revenue share on every TIP-ID you issue that later purchases an AI Trust ID™ Seal.",
              script: [
                "You've verified millions of people. Today that verification only works inside your ecosystem.",
                "TIP-ID is a portable credential that works across the internet. When you issue a TIP-ID, you are giving your verified users a credential they can use everywhere.",
                "You sign the TIP-ID with your VP key. Your name is permanently recorded in the DAG as the issuing authority.",
                "Every time one of your verified users earns money through TIP™ certification, you get a cut.",
                "We need 3 founding VPs at network launch. Would you be one of them?",
              ],
              considerations: "These organisations are technically sophisticated. Lead with the revenue share and the portable credential angle. Have the API documentation ready. They will want to see the protocol specification (CC-BY 4.0: freely available) and the security audit before committing.",
            },
            {
              cat: "CATEGORY B: Content Platforms and Journalism Organisations",
              color: C.blue, timing: "Approach in month 1-2",
              targets: "Committee to Protect Journalists (CPJ), Reporters Without Borders (RSF), Society of Professional Journalists (SPJ), The New York Times, The Guardian, Reuters, Associated Press, BBC",
              pitch: "Your journalists are being impersonated by AI at scale. Deepfake quotes attributed to your reporters damage your outlet's reputation and you have no way to definitively prove your journalists did not say what the AI put in their mouths. TIP™ gives your journalists a verified identity tied to their published work. When someone fabricates a quote from one of your reporters, you can prove: cryptographically, on an immutable public ledger: that the content did not originate from a verified TIP™ identity associated with your outlet.",
              script: [
                "In the last 12 months, how many times have your journalists had words put in their mouths by AI?",
                "What would it mean for your publication to be able to say: every article published by us carries a verified, quantum-safe signature from the journalist who wrote it?",
                "We are offering the 10 founding journalism organisations free verification for all credentialed journalists in year one.",
                "In return, you run a VP node. You verify people you already know: journalists on your payroll, with press credentials. Your verification quality is excellent.",
                "Your name on the founding network is a permanent statement that you stand for verified journalism in the age of AI.",
              ],
              considerations: "These organisations are motivated by credibility, not revenue. Lead with the impersonation problem, not the business model. Offer free verification for credentialed journalists explicitly. Have a simple one-page explainer ready: not the technical specification.",
            },
            {
              cat: "CATEGORY C: Governments",
              color: C.purple, timing: "Start conversations now, expect 12-24 months",
              targets: "EU eIDAS notified bodies, UK DSIT digital identity framework, Estonia e-Residency, German BSI, US NIST National Cybersecurity Center, India UIDAI (Aadhaar)",
              pitch: "Do not lead with 'become a VP'. Lead with 'integrate TIP-ID issuance into your existing national digital ID programme as a value-add to existing digital ID holders.' Citizens who have already completed government KYC would automatically receive a TIP-ID as part of their digital ID package. The government runs no new biometric verification: they already have it. They just issue an additional credential.",
              script: [
                "Your digital ID programme has verified millions of citizens. Those verifications are currently siloed inside your national system.",
                "TIP-ID would let your verified citizens carry that credential onto the open internet.",
                "We are submitting TIP™ to the EU AI Act implementing regulations working group as a technical standard for AI content labelling compliance.",
                "A government-issued TIP-ID carries the highest possible verification credibility. It would make your digital ID programme the gold standard internationally.",
                "We are not asking for a commitment today. We are asking for a conversation with your digital identity technical team.",
              ],
              considerations: "Governments move slowly. The value here is legitimacy, not speed. Start with technical staff in digital identity teams, not policy staff. Submit TIP™ as a standard to NIST, BSI, and ENISA working groups simultaneously: this creates pull demand.",
            },
          ].map((cat, i) => (
            <div key={i} className="card" style={{ marginBottom: 16, borderTop: `3px solid ${cat.color}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
                <div>
                  <div style={{ fontSize: 10, fontWeight: 600, color: cat.color, letterSpacing: 2, marginBottom: 4 }}>{cat.cat}</div>
                  <div style={{ fontSize: 11, color: C.textMuted, fontWeight: 300 }}><span style={{ fontWeight: 600 }}>Target orgs: </span>{cat.targets}</div>
                </div>
                <span className="tag" style={{ background: `${cat.color}10`, color: cat.color, border: `1px solid ${cat.color}25`, whiteSpace: "nowrap", marginLeft: 16 }}>{cat.timing}</span>
              </div>
              <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                <div>
                  <div style={{ fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 1.5, marginBottom: 10 }}>THE PITCH</div>
                  <p style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300 }}>{cat.pitch}</p>
                </div>
                <div>
                  <div style={{ fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 1.5, marginBottom: 10 }}>CONVERSATION SCRIPT</div>
                  {cat.script.map((line, j) => (
                    <div key={j} style={{ display: "flex", gap: 8, marginBottom: 7, alignItems: "flex-start" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: cat.color, flexShrink: 0, marginTop: 2 }}>{j+1}.</span>
                      <span style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{line}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ marginTop: 14, padding: 12, background: `${cat.color}06`, borderRadius: 8, border: `1px solid ${cat.color}15` }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: cat.color }}>Key considerations: </span>
                <span style={{ fontSize: 11.5, color: C.textSecondary, fontWeight: 300 }}>{cat.considerations}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === "accreditation" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div style={{ background: "#FFF5F5", border: `1px solid ${C.red}20`, borderRadius: 12, padding: 22, borderLeft: `4px solid ${C.red}`, marginBottom: 24 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.red, letterSpacing: 2, marginBottom: 8 }}>CURRENT STATUS: NOT YET BUILT</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>
              The AI Lab cannot onboard any VP without a published accreditation process. This must be built and published before any VP conversations move beyond initial interest. The five components below are all required.
            </p>
          </div>
          <div style={{ display: "grid", gap: 12 }}>
            {[
              { num: "01", title: "VP Code of Conduct", status: "Not built", color: C.red, desc: "A single signed document that every VP must agree to before accreditation. Must cover: warrant canary (quarterly), transparency register (quarterly), no voluntary data sharing (absolute), annual security audit, ZK architecture minimum standard, minimum biometric vendor certification requirements. See Code of Conduct tab for the full draft." },
              { num: "02", title: "Technical Integration Guide", status: "Partial (code exists)", color: C.orange, desc: "The Python and Node.js reference implementations exist and document the API. Missing: a biometric vendor selection guide, the device-side SDK for pepper generation, the ZK proof library integration guide, and a step-by-step VP onboarding checklist. Estimated effort: 3-4 weeks of technical writing." },
              { num: "03", title: "Jurisdiction Tier Classification", status: "Framework built, list needed", color: C.orange, desc: "The GREEN/AMBER/RED framework is defined in the protocol. Missing: the actual country list. The AI Lab must formally assess and publish which countries are GREEN (full rule of law, no backdoor laws), AMBER (moderate concerns), and RED (cannot accredit). This requires a legal review of data access laws in at minimum the top 40 countries by internet usage. Quarterly review cadence." },
              { num: "04", title: "VP Application and Fee Structure", status: "Not built", color: C.red, desc: "Currently any organisation can register as a VP via a single REST call. Production must require: a written application, proof of biometric vendor integration, completed Code of Conduct signature, jurisdiction declaration, and a VP accreditation fee ($5,000/year minimum). The fee is a commitment signal, not a revenue driver. Revenue from VPs comes from the identity issuance revenue share." },
              { num: "05", title: "VP Revocation Process", status: "Partial (REVOKE_VP tx type exists)", color: C.orange, desc: "The REVOKE_VP transaction type is defined and implemented. Missing: the governance process for revoking a VP. Who can file a revocation? What evidence is required? Who adjudicates? What happens to the TIP-IDs issued by a revoked VP (they remain valid: the VP's endorsement is noted as compromised but the identity itself was verified)? This needs a published policy before any VP is onboarded." },
            ].map((item, i) => (
              <div key={i} className="card" style={{ padding: 20, borderLeft: `4px solid ${item.color}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
                  <span style={{ fontSize: 16, fontWeight: 600, color: item.color, fontFamily: SERIF }}>{item.num}</span>
                  <span style={{ fontSize: 14, fontWeight: 600, color: C.navy, flex: 1 }}>{item.title}</span>
                  <span className="tag" style={{ background: `${item.color}10`, color: item.color, border: `1px solid ${item.color}25` }}>{item.status}</span>
                </div>
                <p style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, margin: 0 }}>{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "codesign" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div style={{ background: "#F0F7FF", border: `1px solid ${C.blue}20`, borderRadius: 12, padding: 22, marginBottom: 20, borderLeft: `4px solid ${C.blue}` }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.blue, letterSpacing: 2, marginBottom: 8 }}>DRAFT: NOT YET PUBLISHED</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>The VP Code of Conduct replaces the unenforceable v1 "no government backdoors" absolute prohibition with a best-efforts transparency standard. Every provision below is achievable in every Green-tier jurisdiction. VPs in Amber-tier jurisdictions must disclose their tier on every badge they issue.</p>
          </div>
          <div style={{ display: "grid", gap: 10 }}>
            {[
              { obligation: "Quarterly warrant canary", tier: "All VPs: REQUIRED", detail: "Publish a signed statement each quarter confirming no compelled undisclosed data access has occurred. Statement must be machine-verifiable. Failure to publish within 90 days is treated by the protocol as a triggered canary. Other nodes will flag affected TIP-IDs.", absolute: false },
              { obligation: "Government data request disclosure", tier: "All VPs: REQUIRED", detail: "Publish aggregate count and category of all government data access requests received in the prior 12 months, to the maximum extent the law allows. Minimum disclosure: the number of requests, even if the content must be withheld. Zero-count disclosure is required if no requests were received.", absolute: false },
              { obligation: "No voluntary data sharing (ABSOLUTE)", tier: "All VPs: ABSOLUTE PROHIBITION", detail: "Voluntary sharing of any TIP-ID data with any third party: whether commercial or government: without legal compulsion is grounds for immediate accreditation revocation. This is the only absolute prohibition in the Code. It cannot be overridden by any VP contract or service agreement.", absolute: true },
              { obligation: "Annual independent security audit", tier: "All VPs: REQUIRED", detail: "Commission and publish an annual third-party security audit of the biometric verification pipeline. The full report must be published. Firms: Trail of Bits, Bishop Fox, Cure53, or equivalent. Audit must cover: biometric data handling, pepper generation and storage, ZK proof implementation, and network security of the VP node.", absolute: false },
              { obligation: "Zero-knowledge dedup architecture", tier: "All VPs: REQUIRED", detail: "Implement the v2 peppered dedup hash architecture as the minimum standard. The pepper must be generated in the user's device secure enclave. The raw dedup hash must never be transmitted to the VP server or stored anywhere outside the user's device. Only the ZK proof of uniqueness is sent to the TIP node.", absolute: false },
              { obligation: "Transparency register (quarterly)", tier: "All VPs: REQUIRED", detail: "Maintain and publish a quarterly transparency register disclosing: country of incorporation, all countries where the VP operates verification infrastructure, all countries where user data is processed, the jurisdiction tier classification, and the biometric vendor(s) used.", absolute: false },
              { obligation: "Jurisdiction tier badge indicator", tier: "Amber-tier VPs: REQUIRED", detail: "VPs operating in Amber-tier jurisdictions must display a visible amber indicator on every AI Trust ID™ Seal they issue. This informs users that the issuing VP operates in a jurisdiction with moderate rule-of-law concerns. Green-tier VPs display no additional indicator.", absolute: false },
            ].map((item, i) => (
              <div key={i} style={{ padding: 18, background: item.absolute ? "#FFF5F5" : C.bg, border: `1px solid ${item.absolute ? C.red+"30" : C.border}`, borderRadius: 10, display: "grid", gridTemplateColumns: "1fr 2fr auto", gap: 16, alignItems: "start" }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: item.absolute ? C.red : C.navy, marginBottom: 4 }}>{item.obligation}</div>
                </div>
                <div style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{item.detail}</div>
                <span className="tag" style={{ background: item.absolute ? `${C.red}10` : `${C.green}10`, color: item.absolute ? C.red : C.green, border: `1px solid ${item.absolute ? C.red : C.green}25`, whiteSpace: "nowrap" }}>{item.tier}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── ADMIN: GENESIS RING ───────────────────────────────────────────────────────

function AdminGenesisRing() {
  const [tab, setTab] = useState("authority");

  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
        <div style={{ padding: "4px 12px", background: `${C.adminAccent}10`, border: `1px solid ${C.adminAccent}20`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.adminAccent, letterSpacing: 2 }}>INTERNAL VIEW</div>
      </div>
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Genesis Ring and DAG Bootstrap</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 24, fontWeight: 300, lineHeight: 1.7 }}>
        The genesis block is not a technical detail. It is the constitutional founding document of the TIP™ network. Every transaction on every node everywhere traces back to it. These are the decisions that must be made before any network launch.
      </p>

      <div className="rg-tabs" style={{ display: "flex", gap: 6, marginBottom: 24 }}>
        {[{id:"authority",label:"Who Signs the Genesis"},{id:"ring",label:"Genesis Ring Composition"},{id:"governance",label:"Governance Decisions"},{id:"bootstrap",label:"Bootstrap Sequence"}].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: "7px 14px", borderRadius: 5, border: `1px solid ${tab===t.id ? C.gold : C.border}`, background: tab===t.id ? C.goldDim : "transparent", color: tab===t.id ? C.gold : C.textMuted, cursor: "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: tab===t.id ? 600 : 400 }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "authority" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div style={{ background: C.navy, borderRadius: 12, padding: 28, marginBottom: 24 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: C.gold, letterSpacing: 3, marginBottom: 12 }}>THE SINGLE MOST IMPORTANT DECISION IN TIP™ LAUNCH</div>
            <p style={{ fontSize: 13.5, color: "#CBD5E0", lineHeight: 1.75, fontWeight: 300, margin: 0 }}>
              The genesis block is signed by a SLH-DSA-128s root keypair. This keypair is The AI Lab's permanent, irrevocable authority over the network's founding record. If this key is compromised, a malicious actor can bootstrap a parallel network that appears legitimate. The key must never touch an internet-connected machine after the genesis block is signed.
            </p>
          </div>

          <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
            <div className="card" style={{ borderTop: `3px solid ${C.green}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: C.green, letterSpacing: 2, marginBottom: 14 }}>REQUIRED: COLD STORAGE PROTOCOL</div>
              {["Generate the SLH-DSA-128s keypair on an air-gapped machine (never network-connected)","Write the genesis block with this key (one-time operation)","Store the private key on a hardware security module (HSM): minimum: YubiHSM 2 or Ledger","Apply a two-of-three multi-signature policy: Dinesh Mendhe + two designated key custodians","Store key shards in geographically separate secure locations","Document the key recovery procedure in a physical document, stored offline","The genesis.json (public key + hash only) is committed to version control: the private key is NOT"].map((item, i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "flex-start" }}>
                  <span style={{ color: C.green, fontWeight: 700, fontSize: 12, flexShrink: 0, marginTop: 2 }}>✓</span>
                  <span style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{item}</span>
                </div>
              ))}
            </div>

            <div className="card" style={{ borderTop: `3px solid ${C.red}` }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: C.red, letterSpacing: 2, marginBottom: 14 }}>WHAT MUST NEVER HAPPEN</div>
              {["The genesis private key on any internet-connected machine after signing","Generating the key on a cloud server, VPS, or CI/CD pipeline","Storing the private key in any version control system","Storing it in the same location as the genesis.json public record","Allowing a single person to hold the only copy","Using the development genesis block from scripts/seed.py in production","Launching the network before deleting the development genesis-data/ directory and regenerating with the production key"].map((item, i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "flex-start" }}>
                  <span style={{ color: C.red, fontWeight: 700, fontSize: 12, flexShrink: 0, marginTop: 2 }}>✗</span>
                  <span style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.6, fontWeight: 300 }}>{item}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>WHY THIS MATTERS MORE THAN ANY OTHER LAUNCH DECISION</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, marginBottom: 12 }}>
              The genesis hash <span className="mono" style={{ fontSize: 11, color: C.navy }}>52f08c352f8866b4...</span> is compiled into every node's source code. Every transaction on every node everywhere references this hash. Changing it means forking the network: creating a new, incompatible network. This is a one-time, irrevocable act.
            </p>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>
              Unlike blockchain systems, TIP™ does not achieve security through proof-of-work. It achieves it through the institutional authority of The AI Lab signing the genesis block and the social trust of the founding VP and Genesis Ring. This makes the genesis signing ceremony more analogous to a notarised founding document than a cryptographic puzzle: and it must be treated with the same gravity.
            </p>
          </div>
        </div>
      )}

      {tab === "ring" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div style={{ background: "#FFF5F5", border: `1px solid ${C.red}20`, borderRadius: 12, padding: 22, borderLeft: `4px solid ${C.red}`, marginBottom: 24 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.red, letterSpacing: 2, marginBottom: 8 }}>CURRENT STATUS: PLACEHOLDER MEMBERS MUST BE REPLACED BEFORE LAUNCH</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>
              The current seed output contains "Test Journalist" and "Test Researcher" as genesis ring members. These are development placeholders. Anyone reading the genesis block: journalists, investors, regulators, or adversarial researchers: will see these names and immediately question the legitimacy of the entire network. The genesis ring must contain real, verified, named people before any public network launch.
            </p>
          </div>

          <div className="card" style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>RECOMMENDED GENESIS RING STRUCTURE: THREE TIERS</div>

            {[
              {
                tier: "Tier 1: The AI Lab Leadership Team", color: C.gold, count: "Leadership + Anchors",
                desc: "The AI Lab's founding leadership team anchors the genesis ring as the core institutional voice. Their presence permanently records The AI Lab's founding team on the network's genesis block. Additionally, 2 to 3 credible external figures from outside The AI Lab should be added to demonstrate independent validation of the network's founding.",
                members: [
                  { role: "Dinesh Mendhe: The AI Lab Founder", status: "Required. Protocol inventor. The genesis block is signed by The AI Lab. Dinesh must be in the ring.", tier: "REQUIRED" },
                  { role: "The AI Lab executive leadership members", status: "Required. Named founding team members from The AI Lab, biometrically verified before launch. Permanently recorded on the genesis block.", tier: "REQUIRED" },
                  { role: "Named investigative journalist from a major outlet", status: "External validator. Must be a real, credentialed journalist who has agreed to participate. Not a placeholder.", tier: "REQUIRED" },
                  { role: "Named AI safety researcher or academic", status: "External validator. A well-known researcher in AI safety, fairness, or content provenance.", tier: "REQUIRED" },
                  { role: "Named technologist or civil liberties advocate", status: "External validator. Someone with credibility outside the AI/tech space: a digital rights lawyer, a freedom of the press advocate.", tier: "RECOMMENDED" },
                ],
              },
              {
                tier: "Tier 2: The AI Lab Operational", color: C.blue, count: "2 entries",
                desc: "The founding VP node and an automated system credential. These are operational necessities, not people.",
                members: [
                  { role: "The AI Lab Founding VP", status: "The AI Lab itself, accredited as the first VP. Issues TIP-IDs during bootstrap before other VPs are onboarded.", tier: "REQUIRED" },
                  { role: "TIP™ Protocol Bot", status: "System credential for automated operations (Merkle root publication, scheduled tasks). Clearly labelled as non-human.", tier: "REQUIRED" },
                ],
              },
              {
                tier: "Tier 3: Partner Organisations (Optional, at launch)", color: C.green, count: "2-5 entries",
                desc: "If Category A or B VP organisations are onboarded before launch, their institutional accounts can be included in the genesis ring as founding partners. This rewards early movers and strengthens the ring's credibility.",
                members: [
                  { role: "First Category A VP (e.g. iProov, Jumio, or Yoti institutional account)", status: "Only if fully accredited and biometrically verified before launch.", tier: "OPTIONAL" },
                  { role: "First Category B VP (e.g. a major news outlet's institutional account)", status: "Only if fully accredited and biometrically verified before launch.", tier: "OPTIONAL" },
                ],
              },
            ].map((tier, ti) => (
              <div key={ti} style={{ marginBottom: 20, padding: 20, background: C.surface, borderRadius: 10, border: `1px solid ${tier.color}20`, borderLeft: `4px solid ${tier.color}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: tier.color, marginBottom: 4 }}>{tier.tier}</div>
                    <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300, margin: 0 }}>{tier.desc}</p>
                  </div>
                  <span className="tag" style={{ background: `${tier.color}10`, color: tier.color, border: `1px solid ${tier.color}25`, marginLeft: 16, whiteSpace: "nowrap" }}>{tier.count}</span>
                </div>
                {tier.members.map((m, mi) => (
                  <div key={mi} style={{ display: "flex", gap: 12, marginBottom: 8, padding: "10px 14px", background: C.bg, borderRadius: 8, border: `1px solid ${C.border}`, alignItems: "center" }}>
                    <span className="tag" style={{ background: m.tier==="REQUIRED" ? `${C.red}10` : m.tier==="RECOMMENDED" ? `${C.orange}10` : `${C.green}10`, color: m.tier==="REQUIRED" ? C.red : m.tier==="RECOMMENDED" ? C.orange : C.green, border: `1px solid ${m.tier==="REQUIRED" ? C.red : m.tier==="RECOMMENDED" ? C.orange : C.green}25`, minWidth: 90, textAlign: "center" }}>{m.tier}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: C.navy, marginBottom: 3 }}>{m.role}</div>
                      <div style={{ fontSize: 11, color: C.textMuted, fontWeight: 300 }}>{m.status}</div>
                    </div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "governance" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div style={{ background: "#FFFBEB", border: `1px solid ${C.gold}20`, borderRadius: 12, padding: 22, borderLeft: `4px solid ${C.gold}`, marginBottom: 24 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 8 }}>DECISIONS THAT MUST BE MADE BEFORE LAUNCH</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>
              These governance questions are currently unresolved in the protocol specification. They must be decided, documented, and encoded in the genesis payload or a formal governance annex before any public network launch. Leaving them open creates legal ambiguity, investor risk, and operational uncertainty.
            </p>
          </div>

          <div style={{ display: "grid", gap: 14 }}>
            {[
              {
                q: "Can a founding ring member be revoked if they commit fraud?",
                status: "UNRESOLVED",
                color: C.red,
                recommendation: "YES: founding status grants a score premium, not immunity from revocation. A founding member who commits provable origin fraud gets the same penalty as anyone else: -100 (1st offense), up to suspension. Founding status should be recorded permanently on the DAG but should not override the penalty schedule. This must be encoded in the genesis payload before launch.",
                risk: "If this is not decided, The AI Lab will face a precedent-setting crisis when (not if) a founding member commits fraud.",
              },
              {
                q: "Can new founding members be added after network launch?",
                status: "UNRESOLVED",
                color: C.orange,
                recommendation: "NO: the genesis ring should be closed at network launch. The genesis ring is not the governance council: it is the founding witness list. After launch, the network grows through normal VP accreditation and trust score accumulation. Keeping the ring open creates ongoing political pressure to add 'founding' status to powerful partners. The clean answer is: the ring is closed at launch, and subsequent participants join through normal network processes.",
                risk: "Open ring creates ongoing political complexity and potential for abuse by well-resourced partners.",
              },
              {
                q: "What happens to TIP-IDs issued by a revoked VP?",
                status: "PARTIALLY RESOLVED",
                color: C.orange,
                recommendation: "The REVOKE_VP transaction is implemented and the revocation cascade is defined (content registered within 90 days enters adjudication). However, the policy for older content (over 90 days) and the status of the TIP-IDs themselves needs to be formally documented: TIP-IDs issued by a revoked VP remain valid: the VP's endorsement is noted as compromised but the biometric verification was real. The TIP-ID holder can request re-verification through another accredited VP.",
                risk: "When the first VP is revoked, this question will be asked publicly. Having no documented answer damages trust.",
              },
              {
                q: "Who holds the backup if Dinesh Mendhe's founding TIP-ID keypair is compromised?",
                status: "UNRESOLVED",
                color: C.red,
                recommendation: "Establish a formal key recovery procedure before launch: the SLH-DSA-128s root keypair (held in cold storage) can be used to sign a REVOKE_VOLUNTARY transaction for a compromised TIP-ID and issue a REGISTER_IDENTITY for the replacement. The two-of-three key custodian policy for the root key means two custodians can authorise the recovery without Dinesh Mendhe present. Document this procedure in writing and store it offline.",
                risk: "Founder key compromise with no recovery procedure could disable The AI Lab's participation in the network.",
              },
              {
                q: "What is the governance body for protocol upgrades (v3, v4)?",
                status: "NOT DESIGNED",
                color: C.orange,
                recommendation: "Design a protocol governance council before the first external VP is onboarded. Suggested model: The AI Lab holds 1 permanent seat (protocol authority). 2-4 seats are held by elected VP representatives (rotating, annual election). 1-2 seats are held by community representatives from high-trust TIP-ID holders (score >= 900). Protocol changes require two-thirds council vote plus a 90-day public comment period. Emergency security patches can be fast-tracked with unanimous council vote.",
                risk: "Without a governance structure, The AI Lab is a single point of control: which is a legitimate criticism from decentralisation advocates.",
              },
            ].map((item, i) => (
              <div key={i} className="card" style={{ borderLeft: `4px solid ${item.color}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 600, color: C.navy, flex: 1, paddingRight: 16 }}>{item.q}</h3>
                  <span className="tag" style={{ background: `${item.color}10`, color: item.color, border: `1px solid ${item.color}25`, whiteSpace: "nowrap", flexShrink: 0 }}>{item.status}</span>
                </div>
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 10, fontWeight: 600, color: C.green, letterSpacing: 1.5, marginBottom: 6 }}>RECOMMENDATION</div>
                  <p style={{ fontSize: 12.5, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>{item.recommendation}</p>
                </div>
                <div style={{ padding: "8px 14px", background: `${item.color}06`, borderRadius: 6, border: `1px solid ${item.color}20` }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: item.color }}>Risk if unresolved: </span>
                  <span style={{ fontSize: 11.5, color: C.textSecondary, fontWeight: 300 }}>{item.risk}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "bootstrap" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div className="card" style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>COMPLETE BOOTSTRAP SEQUENCE: DAY-BY-DAY LAUNCH TIMELINE</div>
            <div style={{ display: "grid", gap: 8 }}>
              {[
                { day: "D-90", phase: "PRE-LAUNCH", color: C.red, action: "Generate SLH-DSA-128s genesis root keypair on air-gapped machine. Store in HSM. Establish two-of-three custodian policy. Delete all development genesis-data/ files." },
                { day: "D-60", phase: "PRE-LAUNCH", color: C.red, action: "Make governance decisions (founding ring immunity, ring closure, VP revocation policy). Encode decisions in genesis payload. Recompute genesis hash. This hash is permanent." },
                { day: "D-45", phase: "PRE-LAUNCH", color: C.orange, action: "Confirm real founding ring members (Tier 1: named journalist, researcher, advocate). All Tier 1 members complete biometric verification through The AI Lab's founding VP. Their TIP-IDs are ready." },
                { day: "D-30", phase: "PRE-LAUNCH", color: C.orange, action: "Run scripts/seed.py --mint-genesis with the production root keypair. genesis.json with production hash is committed to version control. The founding VP and genesis ring members are registered in seed-output.json." },
                { day: "D-14", phase: "PRE-LAUNCH", color: C.orange, action: "Deploy minimum 3 production nodes (geographically distributed). Validate peer gossip between all 3 nodes. Deploy nginx/Caddy with TLS. Run full integration test suite against production nodes." },
                { day: "D-7", phase: "PRE-LAUNCH", color: C.blue, action: "Replace pre-scan ML stub with production classifier. Validate adjudication queue. Publish VP accreditation process publicly. Publish VP Code of Conduct." },
                { day: "D-0", phase: "LAUNCH DAY", color: C.gold, action: "Network goes live. Founding ring members' TIP-IDs are publicly visible. First external VP onboarding conversations begin. Press release: 'TIP™ Protocol launches with [X] founding verified members.'" },
                { day: "D+7", phase: "POST-LAUNCH", color: C.green, action: "Publish first warrant canary across all founding nodes. Begin Category A VP onboarding conversations (iProov, Jumio, Yoti). Monitor adjudication pipeline for first real disputes." },
                { day: "D+30", phase: "POST-LAUNCH", color: C.green, action: "First external VP accreditation completed (if Category A partner is ready). First enterprise content registration through a non-founder TIP-ID. First community verification dispute resolved through 7-juror pipeline." },
                { day: "D+90", phase: "POST-LAUNCH", color: C.green, action: "First Category B VP (major news publisher) onboarded. First warrant canary published by an external VP. Protocol governance council structure published for community comment." },
              ].map((step, i) => (
                <div key={i} style={{ display: "grid", gridTemplateColumns: "64px 96px 1fr", gap: 14, padding: "12px 16px", background: C.surface, borderRadius: 8, border: `1px solid ${C.border}`, alignItems: "start" }}>
                  <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: step.color }}>{step.day}</span>
                  <span className="tag" style={{ background: `${step.color}10`, color: step.color, border: `1px solid ${step.color}25`, textAlign: "center" }}>{step.phase}</span>
                  <span style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{step.action}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


// ─── ADMIN AUTH GATE PLACEHOLDER ──────────────────────────────────────────────
// TODO (Dinesh): Replace this component with real authentication before
// deploying the admin area publicly. Connect to your preferred auth provider
// (NextAuth, Clerk, Auth0, Supabase Auth, or custom JWT) and gate the
// adminUnlocked state on a verified session. The UI shell below is intentionally
// left as a placeholder and does NOT implement real authentication.

function AdminAuthGate({ onUnlock }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [shake, setShake] = useState(false);

  const handleSignIn = () => {
    // TEMPORARY CREDENTIALS (replace with real auth before production deployment)
    const TEMP_USER = "admin@theailab.org";
    const TEMP_PASS = "TIP2026!Launch";
    if (email === TEMP_USER && password === TEMP_PASS) {
      onUnlock();
    } else {
      setShake(true);
      setTimeout(() => setShake(false), 500);
    }
  };

  return (
    <div style={{ minHeight: "calc(100vh - 140px)", display: "flex", alignItems: "center", justifyContent: "center", padding: "40px 20px" }}>
      <div style={{ width: "100%", maxWidth: 420 }}>
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <TrustIDSeal score={900} size={72} variant="gold-dark" founding />
          <div style={{ marginTop: 20, fontSize: 22, fontWeight: 700, color: C.navy, fontFamily: SERIF }}>Admin Access</div>
          <div style={{ marginTop: 8, fontSize: 13, color: C.textMuted, fontWeight: 300 }}>Internal use only. Authorised personnel only.</div>
        </div>
        <div style={{
          background: C.bg, border: `1px solid ${C.border}`, borderRadius: 16, padding: 36,
          boxShadow: shake ? `0 0 0 3px ${C.red}30` : "none",
          transition: "box-shadow 0.15s ease",
        }}>
          <div style={{ marginBottom: 20 }}>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: C.textMuted, letterSpacing: 1, marginBottom: 8, textTransform: "uppercase" }}>Email address</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleSignIn()}
              placeholder="you@theailab.org"
              style={{ width: "100%", padding: "12px 14px", border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 13.5, fontFamily: "inherit", color: C.textPrimary, outline: "none", background: C.surface }}
            />
          </div>
          <div style={{ marginBottom: 28 }}>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: C.textMuted, letterSpacing: 1, marginBottom: 8, textTransform: "uppercase" }}>Password</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleSignIn()}
              placeholder="••••••••••••"
              style={{ width: "100%", padding: "12px 14px", border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 13.5, fontFamily: "inherit", color: C.textPrimary, outline: "none", background: C.surface }}
            />
          </div>
          <button
            onClick={handleSignIn}
            style={{ width: "100%", padding: "13px", borderRadius: 8, border: "none", background: C.navy, color: C.gold, fontSize: 13, fontWeight: 600, cursor: "pointer", fontFamily: "inherit", letterSpacing: 0.5, transition: "opacity 0.2s" }}
            onMouseEnter={e => e.target.style.opacity = "0.9"}
            onMouseLeave={e => e.target.style.opacity = "1"}
          >
            Sign in to Admin
          </button>
          <div style={{ marginTop: 20, padding: 14, background: C.surface, borderRadius: 8, textAlign: "center" }}>
            <div style={{ fontSize: 11, color: C.textMuted, lineHeight: 1.6, fontWeight: 300 }}>
              Contact <span style={{ color: C.navy, fontWeight: 500 }}>The AI Lab</span> for access credentials.<br />
              <span style={{ fontSize: 10, color: C.textMuted }}>This area contains confidential business and technical information.</span>
            </div>
          </div>
        </div>
        <div style={{ textAlign: "center", marginTop: 20, fontSize: 11, color: C.textMuted }}>
          © 2026 The AI Lab Intelligence Unobscured, Inc.
        </div>
      </div>
    </div>
  );
}

// ─── MAIN APPLICATION ──────────────────────────────────────────────────────────



// ═══════════════════════════════════════════════════════════════════════════════
// TIPCL LICENSE VIEWER -- inline readable + downloadable license text
// ═══════════════════════════════════════════════════════════════════════════════

const TIPCL_SUMMARY = `TIP COMMUNITY LICENSE v1.0 (TIPCL-1.0)
The AI Lab Intelligence Unobscured, Inc. | Effective: January 1, 2026
theailab.org | licensing@theailab.org

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PLAIN ENGLISH SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FREE FOR:  Individuals · Nonprofits · Journalism organizations ·
           Governments · Education · Businesses under $500K/yr revenue
           Research & development (any size)

PAID FOR:  Commercial use above $500K annual revenue
           Sentinel $2,750/yr · Guardian $11,000/yr · Silver $55,000/yr
           Gold $165,000/yr · Platinum $550,000/yr

ALWAYS:    Display attribution: "Built on TIP Protocol by The AI Lab"
           Preserve the NOTICE file in all distributions

CONVERTS:  To Apache License 2.0 on January 1, 2031
           (NOTICE file + trademark restrictions survive permanently)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
§1  PREAMBLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This License governs the TIP Protocol Reference Implementation
authored by Dinesh Mendhe and owned by The AI Lab Intelligence
Unobscured, Inc. ("The AI Lab"). The Protocol Specification is
separately licensed under CC-BY 4.0 and is unaffected by this
License.

The AI Lab believes open protocols create stronger ecosystems,
attribution is a structural truth (not a courtesy), commercial
enterprises building revenue on this technology should help sustain
it, and individuals/journalists/nonprofits/governments should never
face a paywall to participate in a public-interest trust protocol.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
§2  FREE USE — WHO QUALIFIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You qualify for FREE USE if you are:

(a) An individual person (any income level)
(b) A business with Annual Revenue under USD $500,000
(c) A nonprofit, NGO, or tax-exempt charity (any size)
(d) A university, college, or educational institution (any size)
(e) A government entity (any size)
(f) A journalism organization or individual journalist (any size,
    used solely for editorial identity/provenance purposes)
(g) Using the Software only for internal R&D/testing (any size)

Free Use grants you the right to: deploy TIP nodes, modify the
Software, distribute to other Free Use users, and apply for VP
accreditation — all at no charge.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
§3  COMMERCIAL LICENSE REQUIREMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Any use that does not qualify as Free Use requires a Commercial
License. Contact: licensing@theailab.org

Tiers:
  Sentinel  $500K–$10M rev    $2,750/yr
  Guardian  $10M–$50M rev    $11,000/yr
  Silver    $50M–$500M rev   $55,000/yr
  Gold      $500M–$5B rev   $165,000/yr
  Platinum  $5B+ rev        $550,000/yr

Commercial License includes a patent license for The AI Lab's
essential patent claims covering TIP Protocol inventions.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
§4  ATTRIBUTION — MANDATORY IN ALL CASES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Every implementation (Free or Commercial) must display:

  "Built on TIP Protocol by The AI Lab Intelligence
   Unobscured, Inc. (theailab.org) | Licensed under TIPCL-1.0"

Acceptable formats:
  Full:    Full text above in footer/About/Help page
  Short:   "Powered by TIP Protocol — theailab.org" + hyperlink
  Badge:   TIP Powered Mark + hyperlink to theailab.org/tip
  API:     X-Powered-By: TIP-Protocol/theailab.org in responses

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
§5  NOTICE FILE — REQUIRED IN ALL DISTRIBUTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Include this NOTICE file verbatim in all distributions:

  TIP Protocol | Copyright 2026 The AI Lab Intelligence
  Unobscured, Inc. | Authored by Dinesh Mendhe
  theailab.org | Licensed under TIPCL-1.0
  TIP™, AI Trust ID™, AI Trust Registry™ are trademarks of
  The AI Lab Intelligence Unobscured, Inc.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
§6  RESTRICTIONS — ABSOLUTE (FREE AND COMMERCIAL)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You may NOT:
  1. Remove or alter the NOTICE file
  2. Use TIP™, AI Trust ID™, AI Trust Registry™ or confusingly
     similar marks without a separate trademark license
  3. Issue AI Trust ID™ Seals yourself (registry-issued only)
  4. Claim The AI Lab endorses your product
  5. Run a private fork claiming to be the TIP™ network
  6. Sub-license commercial rights to third parties

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
§7  CONVERSION TO APACHE 2.0 (JANUARY 1, 2031)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

On January 1, 2031, this License converts to Apache License 2.0.
After conversion, commercial use requires no paid license.

SURVIVING PERMANENTLY after conversion:
  ✓ NOTICE file preservation in all distributions
  ✓ All trademark restrictions (TIP™ marks remain reserved)
  ✓ AI Trust ID™ Seal registry-issued only
  ✓ Genesis block (cryptographic fact, not a license term)

ENDING after conversion:
  - Mandatory UI attribution display in running applications
  - Commercial license fee requirement
  - Copyleft on protocol core modifications

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
§8  PATENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Free Use includes a royalty-free patent license for compliant
implementations. Commercial License includes a broader patent
license. If you sue The AI Lab for patent infringement, your
patent license terminates immediately.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GOVERNING LAW: Delaware, USA | Arbitration: JAMS, Wilmington, DE
FULL TEXT: theailab.org/license | licensing@theailab.org
COPYRIGHT 2026 THE AI LAB INTELLIGENCE UNOBSCURED, INC.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;

function LicenseViewer({ compact = false }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const download = () => {
    const blob = new Blob([TIPCL_SUMMARY], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'TIPCL-1.0-LICENSE.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  const copy = () => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(TIPCL_SUMMARY).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1600);
      });
    }
  };

  return (
    <div style={{ marginTop: compact ? 12 : 20 }}>
      {/* Action buttons row */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <button onClick={() => setOpen(!open)} style={{
          display: "flex", alignItems: "center", gap: 6,
          padding: "7px 14px", borderRadius: 6,
          border: `1px solid ${open ? C.blue : C.border}`,
          background: open ? `${C.blue}10` : C.surface,
          color: open ? C.blue : C.textSecondary,
          cursor: "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: open ? 600 : 400,
          transition: "all 0.2s"
        }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
            <line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>
          </svg>
          {open ? "Close License" : "Read TIPCL-1.0 License"}
        </button>

        <button onClick={download} style={{
          display: "flex", alignItems: "center", gap: 6,
          padding: "7px 14px", borderRadius: 6,
          border: `1px solid ${C.green}40`,
          background: `${C.green}08`,
          color: C.green,
          cursor: "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: 600,
          transition: "all 0.2s"
        }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Download TIPCL-1.0.txt
        </button>

        <button onClick={copy} style={{
          display: "flex", alignItems: "center", gap: 6,
          padding: "7px 14px", borderRadius: 6,
          border: `1px solid ${copied ? C.green : C.border}`,
          background: copied ? `${C.green}10` : "transparent",
          color: copied ? C.green : C.textMuted,
          cursor: "pointer", fontFamily: "inherit", fontSize: 12,
          transition: "all 0.2s"
        }}>
          {copied ? "✓ Copied!" : "Copy text"}
        </button>

        <a href="mailto:licensing@theailab.org" style={{
          display: "flex", alignItems: "center", gap: 6,
          padding: "7px 14px", borderRadius: 6,
          border: `1px solid ${C.gold}40`,
          background: `${C.gold}08`,
          color: C.gold,
          textDecoration: "none", fontFamily: "inherit", fontSize: 12, fontWeight: 500
        }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
            <polyline points="22,6 12,13 2,6"/>
          </svg>
          licensing@theailab.org
        </a>
      </div>

      {/* Inline license text */}
      {open && (
        <div style={{
          marginTop: 12, background: C.navy, borderRadius: 8, padding: 20,
          animation: "fadeIn 0.25s ease", position: "relative"
        }}>
          <div style={{ position: "absolute", top: 10, right: 12, fontSize: 9, color: "#4A6080", letterSpacing: 1 }}>
            TIPCL-1.0 · theailab.org/license
          </div>
          <pre style={{
            margin: 0, fontFamily: "'JetBrains Mono', Courier New, monospace",
            fontSize: 10.5, lineHeight: 1.9, color: "#CBD5E0",
            whiteSpace: "pre-wrap", wordBreak: "break-word",
            maxHeight: compact ? 320 : 520, overflowY: "auto"
          }}>{TIPCL_SUMMARY}</pre>
        </div>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════════
// PROTOCOL DIAGRAM -- SVG architecture + licensing visual
// Used on both public LicensePage and admin AdminLicenseDeep
// ═══════════════════════════════════════════════════════════════════════════════

function ProtocolDiagram({ mode = "public" }) {
  // mode: "public" = licensing focus, "admin" = full architecture
  const W = 900, H = mode === "admin" ? 760 : 680;
  const cx = W / 2;

  return (
    <div style={{ background: C.surface, borderRadius: 12, border: `1px solid ${C.border}`, padding: "20px 10px", overflowX: "auto" }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxWidth: W, display: "block", margin: "0 auto", fontFamily: "'Libre Franklin', Arial, sans-serif" }}>

        {/* ── Background ── */}
        <defs>
          <linearGradient id="bgGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#F8F9FB"/>
            <stop offset="100%" stopColor="#FFFFFF"/>
          </linearGradient>
          <marker id="arr" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#8895A7"/>
          </marker>
          <marker id="arrBlue" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#2563A8"/>
          </marker>
          <marker id="arrGreen" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#1A8A5C"/>
          </marker>
          <marker id="arrGold" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#B8942E"/>
          </marker>
          <filter id="cardShadow" x="-5%" y="-5%" width="110%" height="120%">
            <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="rgba(0,0,0,0.08)"/>
          </filter>
        </defs>

        {/* ── TITLE ── */}
        <text x={cx} y={28} textAnchor="middle" fontSize="15" fontWeight="700" fill="#0C1A3A">TIP Protocol Architecture and Licensing Model</text>
        <text x={cx} y={46} textAnchor="middle" fontSize="11" fill="#8895A7">The AI Lab Intelligence Unobscured, Inc.  |  theailab.org</text>

        {/* ─────────────────────────────────────────────────────── */}
        {/* ROW 1: THREE PROTOCOL LAYERS */}
        {/* ─────────────────────────────────────────────────────── */}
        <text x={cx} y={74} textAnchor="middle" fontSize="10" fontWeight="700" fill="#B8942E" letterSpacing="2">THREE COMPOSABLE PROTOCOL LAYERS</text>

        {/* Layer 1: TIP-ID */}
        <rect x={40} y={82} width={240} height={100} rx="8" fill="white" stroke="#2563A8" strokeWidth="2" filter="url(#cardShadow)"/>
        <rect x={40} y={82} width={240} height={8} rx="8" fill="#2563A8"/>
        <rect x={40} y={86} width={240} height={4} fill="#2563A8"/>
        <text x={160} y={104} textAnchor="middle" fontSize="13" fontWeight="700" fill="#2563A8">TIP-ID</text>
        <text x={160} y={119} textAnchor="middle" fontSize="10" fill="#4A5568">Identity Layer</text>
        <text x={160} y={133} textAnchor="middle" fontSize="9" fill="#8895A7">Gov ID + 3D Liveness + FIDO2</text>
        <text x={160} y={145} textAnchor="middle" fontSize="9" fill="#8895A7">Peppered ZK dedup + ML-DSA-65</text>
        <text x={160} y={163} textAnchor="middle" fontSize="8" fill="#2563A8" fontStyle="italic">tip://id/US-a3f8c91b</text>

        {/* Layer 2: TIP-CONTENT */}
        <rect x={330} y={82} width={240} height={100} rx="8" fill="white" stroke="#7C3AED" strokeWidth="2" filter="url(#cardShadow)"/>
        <rect x={330} y={82} width={240} height={8} rx="8" fill="#7C3AED"/>
        <rect x={330} y={86} width={240} height={4} fill="#7C3AED"/>
        <text x={450} y={104} textAnchor="middle" fontSize="13" fontWeight="700" fill="#7C3AED">TIP-CONTENT</text>
        <text x={450} y={119} textAnchor="middle" fontSize="10" fill="#4A5568">Content Provenance Layer</text>
        <text x={450} y={133} textAnchor="middle" fontSize="9" fill="#8895A7">Mandatory origin: OH / AA / AG / MX</text>
        <text x={450} y={145} textAnchor="middle" fontSize="9" fill="#8895A7">SHAKE-256 hash + AI pre-scan</text>
        <text x={450} y={163} textAnchor="middle" fontSize="8" fill="#7C3AED" fontStyle="italic">tip://c/OH-7f2a91bc3d5e-a3f8</text>

        {/* Layer 3: TIP-TRUST */}
        <rect x={620} y={82} width={240} height={100} rx="8" fill="white" stroke="#1A8A5C" strokeWidth="2" filter="url(#cardShadow)"/>
        <rect x={620} y={82} width={240} height={8} rx="8" fill="#1A8A5C"/>
        <rect x={620} y={86} width={240} height={4} fill="#1A8A5C"/>
        <text x={740} y={104} textAnchor="middle" fontSize="13" fontWeight="700" fill="#1A8A5C">TIP-TRUST</text>
        <text x={740} y={119} textAnchor="middle" fontSize="10" fill="#4A5568">Reputation Layer</text>
        <text x={740} y={133} textAnchor="middle" fontSize="9" fill="#8895A7">Score 0-1000, deterministic</text>
        <text x={740} y={145} textAnchor="middle" fontSize="9" fill="#8895A7">Any node computes from DAG history</text>
        <text x={740} y={163} textAnchor="middle" fontSize="8" fill="#1A8A5C" fontStyle="italic">No central database</text>

        {/* Arrows between layers */}
        <line x1={282} y1={132} x2={328} y2={132} stroke="#8895A7" strokeWidth="1.5" markerEnd="url(#arr)"/>
        <line x1={572} y1={132} x2={618} y2={132} stroke="#8895A7" strokeWidth="1.5" markerEnd="url(#arr)"/>
        <text x={305} y={128} textAnchor="middle" fontSize="8" fill="#8895A7">binds</text>
        <text x={595} y={128} textAnchor="middle" fontSize="8" fill="#8895A7">scores</text>

        {/* ─────────────────────────────────────────────────────── */}
        {/* ROW 2: FEDERATED DAG */}
        {/* ─────────────────────────────────────────────────────── */}
        <text x={cx} y={212} textAnchor="middle" fontSize="10" fontWeight="700" fill="#B8942E" letterSpacing="2">FEDERATED DAG NETWORK</text>

        <rect x={80} y={220} width={740} height={70} rx="8" fill="#0C1A3A" filter="url(#cardShadow)"/>
        {/* Genesis block */}
        <rect x={100} y={230} width={120} height={50} rx="5" fill="#1B2A4A" stroke="#B8942E" strokeWidth="1.5"/>
        <text x={160} y={250} textAnchor="middle" fontSize="9" fontWeight="700" fill="#C9A84C">GENESIS BLOCK</text>
        <text x={160} y={263} textAnchor="middle" fontSize="8" fill="#94A3B8">Signed: SLH-DSA-128s</text>
        <text x={160} y={275} textAnchor="middle" fontSize="8" fill="#B8942E">The AI Lab</text>

        {/* DAG nodes */}
        {[310, 430, 550, 670].map((x, i) => (
          <g key={i}>
            <rect x={x} y={234} width={80} height={42} rx="4" fill="#1B2A4A" stroke={i===0?"#2563A8":i===1?"#7C3AED":i===2?"#1A8A5C":"#C07318"} strokeWidth="1"/>
            <text x={x+40} y={250} textAnchor="middle" fontSize="8" fontWeight="600" fill={i===0?"#60A5FA":i===1?"#A78BFA":i===2?"#34D399":"#FDBA74"}>{i===0?"VP Node":i===1?"Full Node":i===2?"Archive":("Light Node")}</text>
            <text x={x+40} y={263} textAnchor="middle" fontSize="7" fill="#64748B">{i===0?"Issues TIP-IDs":i===1?"Full DAG copy":i===2?"Research":("Mobile/browser")}</text>
            <text x={x+40} y={274} textAnchor="middle" fontSize="7" fill="#475569">{i===0?"Accredited VP":i===1?"Open access":i===2?"Open access":("Open access")}</text>
          </g>
        ))}

        {/* Gossip arrows */}
        {[222, 392, 512, 632].map((x,i) => (
          <line key={i} x1={x} y1={255} x2={x+86} y2={255} stroke="#334155" strokeWidth="1" strokeDasharray="3,2" markerEnd="url(#arr)"/>
        ))}
        <text x={cx} y={305} textAnchor="middle" fontSize="9" fill="#64748B" fontStyle="italic">Anyone can run a Full Node or Light Node. Only accredited VPs can issue TIP-IDs.</text>

        {/* ─────────────────────────────────────────────────────── */}
        {/* ROW 3: LICENSING MODEL */}
        {/* ─────────────────────────────────────────────────────── */}
        <text x={cx} y={335} textAnchor="middle" fontSize="10" fontWeight="700" fill="#B8942E" letterSpacing="2">FOUR PROTECTION LAYERS</text>

        {/* Layer A: Spec - CC-BY 4.0 */}
        <rect x={40} y={343} width={190} height={110} rx="8" fill="white" stroke="#1A8A5C" strokeWidth="2" filter="url(#cardShadow)"/>
        <rect x={40} y={343} width={190} height={26} rx="8" fill="#1A8A5C"/>
        <rect x={40} y={357} width={190} height={12} fill="#1A8A5C"/>
        <text x={55} y={358} fontSize="9" fontWeight="700" fill="white">A</text>
        <text x={135} y={358} textAnchor="middle" fontSize="10" fontWeight="700" fill="white">Protocol Spec</text>
        <text x={135} y={373} textAnchor="middle" fontSize="9" fontWeight="600" fill="#1A8A5C">CC-BY 4.0</text>
        <text x={135} y={386} textAnchor="middle" fontSize="8" fill="#4A5568">Free for everyone</text>
        <text x={135} y={398} textAnchor="middle" fontSize="8" fill="#4A5568">Forever. Read it, implement</text>
        <text x={135} y={410} textAnchor="middle" fontSize="8" fill="#4A5568">it, teach from it.</text>
        <text x={135} y={428} textAnchor="middle" fontSize="8" fill="#1A8A5C" fontWeight="600">Attribution in citations</text>
        <text x={135} y={440} textAnchor="middle" fontSize="8" fill="#8895A7" fontStyle="italic">required permanently</text>

        {/* Layer B: Code - TIPCL-1.0 */}
        <rect x={250} y={343} width={190} height={110} rx="8" fill="white" stroke="#2563A8" strokeWidth="2" filter="url(#cardShadow)"/>
        <rect x={250} y={343} width={190} height={26} rx="8" fill="#2563A8"/>
        <rect x={250} y={357} width={190} height={12} fill="#2563A8"/>
        <text x={265} y={358} fontSize="9" fontWeight="700" fill="white">B</text>
        <text x={345} y={358} textAnchor="middle" fontSize="10" fontWeight="700" fill="white">Reference Code</text>
        <text x={345} y={373} textAnchor="middle" fontSize="9" fontWeight="600" fill="#2563A8">TIPCL-1.0</text>
        <text x={345} y={386} textAnchor="middle" fontSize="8" fill="#4A5568">Free under $500K rev</text>
        <text x={345} y={398} textAnchor="middle" fontSize="8" fill="#4A5568">Paid above. Converts to</text>
        <text x={345} y={410} textAnchor="middle" fontSize="8" fill="#4A5568">Apache 2.0 Jan 1, 2031.</text>
        <text x={345} y={428} textAnchor="middle" fontSize="8" fill="#2563A8" fontWeight="600">UI attribution required</text>
        <text x={345} y={440} textAnchor="middle" fontSize="8" fill="#8895A7" fontStyle="italic">until 2031, NOTICE forever</text>

        {/* Layer C: Trademark */}
        <rect x={460} y={343} width={190} height={110} rx="8" fill="white" stroke="#B8942E" strokeWidth="2" filter="url(#cardShadow)"/>
        <rect x={460} y={343} width={190} height={26} rx="8" fill="#B8942E"/>
        <rect x={460} y={357} width={190} height={12} fill="#B8942E"/>
        <text x={475} y={358} fontSize="9" fontWeight="700" fill="white">C</text>
        <text x={555} y={358} textAnchor="middle" fontSize="10" fontWeight="700" fill="white">Trademarks</text>
        <text x={555} y={373} textAnchor="middle" fontSize="9" fontWeight="600" fill="#B8942E">Trademark Law</text>
        <text x={555} y={386} textAnchor="middle" fontSize="8" fill="#4A5568">TIP™, AI Trust ID™,</text>
        <text x={555} y={398} textAnchor="middle" fontSize="8" fill="#4A5568">AI Trust Registry™ owned</text>
        <text x={555} y={410} textAnchor="middle" fontSize="8" fill="#4A5568">by The AI Lab. Forever.</text>
        <text x={555} y={428} textAnchor="middle" fontSize="8" fill="#B8942E" fontWeight="600">License required to use</text>
        <text x={555} y={440} textAnchor="middle" fontSize="8" fill="#8895A7" fontStyle="italic">any mark. Renew q10 yrs.</text>

        {/* Layer D: Patents */}
        <rect x={670} y={343} width={190} height={110} rx="8" fill="white" stroke="#C53030" strokeWidth="2" filter="url(#cardShadow)"/>
        <rect x={670} y={343} width={190} height={26} rx="8" fill="#C53030"/>
        <rect x={670} y={357} width={190} height={12} fill="#C53030"/>
        <text x={685} y={358} fontSize="9" fontWeight="700" fill="white">D</text>
        <text x={765} y={358} textAnchor="middle" fontSize="10" fontWeight="700" fill="white">Patents</text>
        <text x={765} y={373} textAnchor="middle" fontSize="9" fontWeight="600" fill="#C53030">Patent Law</text>
        <text x={765} y={386} textAnchor="middle" fontSize="8" fill="#4A5568">10 patented inventions</text>
        <text x={765} y={398} textAnchor="middle" fontSize="8" fill="#4A5568">Claims A-E (v1) +</text>
        <text x={765} y={410} textAnchor="middle" fontSize="8" fill="#4A5568">Claims F-J (v2)</text>
        <text x={765} y={428} textAnchor="middle" fontSize="8" fill="#C53030" fontWeight="600">Included in TIPCL</text>
        <text x={765} y={440} textAnchor="middle" fontSize="8" fill="#8895A7" fontStyle="italic">commercial license. ~2047.</text>

        {/* ─────────────────────────────────────────────────────── */}
        {/* ROW 4: WHO CAN DO WHAT */}
        {/* ─────────────────────────────────────────────────────── */}
        <text x={cx} y={480} textAnchor="middle" fontSize="10" fontWeight="700" fill="#B8942E" letterSpacing="2">WHO CAN DO WHAT</text>

        {/* Open actions */}
        <rect x={40} y={488} width={385} height={120} rx="8" fill="#F0FDF4" stroke="#1A8A5C" strokeWidth="1.5" filter="url(#cardShadow)"/>
        <text x={232} y={504} textAnchor="middle" fontSize="11" fontWeight="700" fill="#1A8A5C">ANYONE CAN (with attribution)</text>
        {[
          "Run a TIP node on the original network",
          "Implement the protocol from the CC-BY 4.0 spec",
          "Build apps using TIP Protocol APIs",
          "Become an accredited VP (after The AI Lab audit)",
          "Display the TIP Powered Mark (TIPCL-1.0)",
          "Earn and display TIP-ID trust scores",
        ].map((t, i) => (
          <g key={i}>
            <circle cx={58} cy={518 + i*16} r={4} fill="#1A8A5C"/>
            <text x={68} y={522 + i*16} fontSize="9" fill="#4A5568">{t}</text>
          </g>
        ))}

        {/* Proprietary actions */}
        <rect x={475} y={488} width={385} height={120} rx="8" fill="#FFF5F5" stroke="#C53030" strokeWidth="1.5" filter="url(#cardShadow)"/>
        <text x={667} y={504} textAnchor="middle" fontSize="11" fontWeight="700" fill="#C53030">ONLY THE AI LAB CAN</text>
        {[
          "Issue AI Trust ID™ Seals (trademark)",
          "Use TIP™, AI Trust ID™, AI Trust Registry™ marks",
          "Sign the genesis block (SLH-DSA root key)",
          "Accredit new Verification Providers",
          "Issue TIPCL commercial licenses",
          "Classify VP jurisdiction tiers (Green/Amber/Red)",
        ].map((t, i) => (
          <g key={i}>
            <rect x={491} cy={518 + i*16} width={8} height={8} rx="1" fill="#C53030" y={514 + i*16}/>
            <text x={506} y={522 + i*16} fontSize="9" fill="#4A5568">{t}</text>
          </g>
        ))}

        {/* ─────────────────────────────────────────────────────── */}
        {/* ROW 5: 2031 CONVERSION TIMELINE */}
        {/* ─────────────────────────────────────────────────────── */}
        <text x={cx} y={634} textAnchor="middle" fontSize="10" fontWeight="700" fill="#B8942E" letterSpacing="2">LICENSE TIMELINE</text>

        {/* Timeline bar */}
        <line x1={60} y1={655} x2={840} y2={655} stroke="#E2E6EE" strokeWidth="3"/>

        {[
          { x: 60,  y: 655, label: "2026", sub: "TIPCL-1.0\nLaunch", color: "#2563A8" },
          { x: 240, y: 655, label: "2027", sub: "Non-provisional\npatent filed", color: "#7C3AED" },
          { x: 420, y: 655, label: "2028-2030", sub: "TIPCL-1.0\nin effect", color: "#1A8A5C" },
          { x: 620, y: 655, label: "Jan 1, 2031", sub: "Converts to\nApache 2.0", color: "#B8942E" },
          { x: 800, y: 655, label: "2031+", sub: "Trademarks +\nNOTICE permanent", color: "#C53030" },
        ].map(({ x, y, label, sub, color }) => (
          <g key={x}>
            <circle cx={x} cy={y} r={6} fill={color} stroke="white" strokeWidth="2"/>
            <text x={x} y={y - 12} textAnchor="middle" fontSize="8" fontWeight="700" fill={color}>{label}</text>
            {sub.split("\n").map((line, li) => (
              <text key={li} x={x} y={y + 18 + li*11} textAnchor="middle" fontSize="8" fill="#4A5568">{line}</text>
            ))}
          </g>
        ))}

        {/* Permanent bar */}
        <rect x={620} y={648} width={220} height={14} rx="4" fill="#C5303015" stroke="#C53030" strokeWidth="1" strokeDasharray="4,2"/>
        <text x={730} y={658} textAnchor="middle" fontSize="7" fill="#C53030" fontWeight="600">Trademarks + Patents permanent</text>

      </svg>

      {/* Legend */}
      <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap", marginTop: 12 }}>
        {[
          { color: C.green,  label: "Protocol Spec (CC-BY 4.0) -- Free Forever" },
          { color: C.blue,   label: "Reference Code (TIPCL-1.0) -- Free / Paid" },
          { color: C.gold,   label: "Trademarks -- The AI Lab Only, Permanent" },
          { color: C.red,    label: "Patents -- 10 inventions, valid to ~2047" },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11 }}>
            <div style={{ width: 10, height: 10, borderRadius: 2, background: color, flexShrink: 0 }}/>
            <span style={{ color: C.textSecondary }}>{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC: LICENSE PAGE
// Friendly explanation of TIPCL-1.0 for developers and implementors
// ═══════════════════════════════════════════════════════════════════════════════

function PublicLicense() {
  const [tab, setTab] = useState("overview");
  const tabs = [
    { id: "overview", label: "How Licensing Works" },
    { id: "diagram",  label: "Visual Diagram" },
    { id: "freeuse",  label: "Free Use" },
    { id: "faq",      label: "FAQ" },
  ];

  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <SN num={7} />
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>Open Protocol. Clear Rules.</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 28, fontWeight: 300, lineHeight: 1.75 }}>
        TIP Protocol is open. The specification is free for everyone under CC-BY 4.0. The reference code is free for most users under TIPCL-1.0. The trademarks and patents protect the brand and specific inventions. Here is exactly what you can do and what you cannot.
      </p>

      {/* Tab bar */}
      <div className="rg-tabs" style={{ display: "flex", gap: 4, marginBottom: 24, flexWrap: "wrap" }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: "7px 14px", borderRadius: 5, border: `1px solid ${tab===t.id ? C.gold : C.border}`, background: tab===t.id ? C.goldDim : "transparent", color: tab===t.id ? C.gold : C.textMuted, cursor: "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: tab===t.id ? 600 : 400 }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          {/* Three license objects */}
          <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 24 }}>
            {[
              { letter: "A", title: "Protocol Specification", badge: "CC-BY 4.0", color: C.green, bg: "#F0FDF4",
                who: "Free for EVERYONE. Forever.",
                desc: "The TIP Protocol specification document is published under Creative Commons Attribution 4.0. You can read it, implement it from scratch, teach from it, translate it, or publish it. All you need to do is credit The AI Lab as the author.",
                can: ["Build a custom TIP node from scratch", "Implement in any language", "Join the original network", "Publish the spec in your docs"],
                cannot: ["Call your implementation TIP™", "Issue AI Trust ID™ Seals"] },
              { letter: "B", title: "Reference Implementation", badge: "TIPCL-1.0", color: C.blue, bg: "#F0F7FF",
                who: "Free under $500K revenue. Paid above.",
                desc: "The AI Lab's working code (Python node, Node.js node, SDK, CLI, browser extension) is licensed under TIPCL-1.0. Free for individuals, nonprofits, journalists, governments, education, and small businesses. Commercial use above $500K annual revenue requires a Commercial License.",
                can: ["Deploy the code as-is", "Modify it for your needs", "Distribute it to other free users", "Use the patent-protected inventions (free tier)"],
                cannot: ["Remove The AI Lab attribution from the UI", "Use TIP™ trademarks", "Sub-license to commercial users"] },
              { letter: "C", title: "Badges and Trademarks", badge: "Trademark Law", color: C.gold, bg: "#FFFBEB",
                who: "AI Trust ID Seal: Registry-issued only.",
                desc: "TIP™, AI Trust ID™, AI Trust Registry™, and The Global Seal of Trust™ are The AI Lab's trademarks. The TIP Powered Mark (open compliance badge) is free for any compliant implementation under TIPCL-1.0. The AI Trust ID™ Seal requires registry issuance.",
                can: ["Display the TIP Powered Mark if you implement TIP™", "Show user-provided AI Trust ID Seals that The AI Lab issued", "Describe your product as 'implementing TIP Protocol'"],
                cannot: ["Issue AI Trust ID™ Seals yourself", "Use TIP™ in your product name", "Display AI Trust Registry™ on any credential you create"] },
            ].map((layer, i) => (
              <div key={i} style={{ background: layer.bg, border: `1px solid ${layer.color}20`, borderRadius: 12, padding: 20, borderTop: `4px solid ${layer.color}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                  <span style={{ width: 28, height: 28, borderRadius: 6, border: `2px solid ${layer.color}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 700, color: layer.color, fontFamily: SERIF }}>{layer.letter}</span>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: C.navy }}>{layer.title}</div>
                    <div style={{ fontSize: 10, color: layer.color, fontWeight: 600, letterSpacing: 1 }}>{layer.badge}</div>
                  </div>
                </div>
                <div style={{ fontSize: 10, fontWeight: 700, color: layer.color, marginBottom: 6, letterSpacing: 1, textTransform: "uppercase" }}>{layer.who}</div>
                <p style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, marginBottom: 12 }}>{layer.desc}</p>
                <div style={{ fontSize: 10, fontWeight: 700, color: C.green, marginBottom: 6, letterSpacing: 1 }}>YOU CAN:</div>
                {layer.can.map((item, j) => (
                  <div key={j} style={{ display: "flex", gap: 6, marginBottom: 4, alignItems: "flex-start" }}>
                    <span style={{ color: C.green, fontWeight: 700, flexShrink: 0, fontSize: 11 }}>+</span>
                    <span style={{ fontSize: 11, color: C.textSecondary, fontWeight: 300 }}>{item}</span>
                  </div>
                ))}
                <div style={{ fontSize: 10, fontWeight: 700, color: C.red, marginTop: 10, marginBottom: 6, letterSpacing: 1 }}>YOU CANNOT:</div>
                {layer.cannot.map((item, j) => (
                  <div key={j} style={{ display: "flex", gap: 6, marginBottom: 4, alignItems: "flex-start" }}>
                    <span style={{ color: C.red, fontWeight: 700, flexShrink: 0, fontSize: 11 }}>-</span>
                    <span style={{ fontSize: 11, color: C.textSecondary, fontWeight: 300 }}>{item}</span>
                  </div>
                ))}
                {i === 1 && <LicenseViewer compact={true} />}
              </div>
            ))}
          </div>

          {/* WHY THIS STRUCTURE MATTERS -- public audience */}
          <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 12, padding: 24, marginBottom: 20 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: C.navy, letterSpacing: 2, marginBottom: 16 }}>WHY THESE RULES EXIST AND WHY THEY MATTER TO YOU</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, marginBottom: 20 }}>
              The licensing structure is not about making money from open source. It is about making sure TIP Protocol is still running, maintained, and trustworthy in five, ten, and twenty years. Here is how the three layers work together to protect you as a user.
            </p>
            <div className="rg3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
              {[
                {
                  icon: "🌐",
                  title: "Free use builds a network you can trust",
                  color: C.green,
                  body: "Journalists, nonprofits, and governments use TIP Protocol for free. This is intentional. A trust network is only meaningful if the most credible people are on it. Investigative journalists and scientists on the same network as you is what makes your AI Trust ID™ badge mean something. If only paying enterprises were on the network, it would just be a corporate product. Free use for credible institutions is what makes the whole system worth having.",
                },
                {
                  icon: "⚙️",
                  title: "Commercial licenses fund the infrastructure protecting everyone",
                  color: C.blue,
                  body: "The AI pre-scan that catches false origin declarations, the VP audit process that ensures your verifier meets security standards, the warrant canary that tells you if a government demanded your data, the revocation system that protects you from impersonation -- all of this costs money to build and maintain. The commercial license revenue from large enterprises funds it. Without it, the free tier degrades. The paid tier is what makes the free tier sustainable.",
                },
                {
                  icon: "🛡",
                  title: "Trademarks protect the meaning of your credential",
                  color: C.gold,
                  body: "When you see the AI Trust ID™ Seal on a journalist's article, you know it was issued by The AI Lab's registry against the full biometric standard -- not by a copycat site that skipped the liveness check. The trademark ensures that only registry-issued credentials can carry that name. If the trademark were not protected, anyone could create a fake 'AI Trust ID' with no real verification behind it, and the whole system's credibility collapses. The trademark is what your trust in the badge is ultimately based on.",
                },
              ].map(({ icon, title, color, body }, i) => (
                <div key={i} style={{ padding: 18, background: C.bg, borderRadius: 10, border: `1px solid ${color}20`, borderTop: `3px solid ${color}` }}>
                  <div style={{ fontSize: 22, marginBottom: 10 }}>{icon}</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: C.navy, marginBottom: 8, lineHeight: 1.4 }}>{title}</div>
                  <p style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, margin: 0 }}>{body}</p>
                </div>
              ))}
            </div>

            {/* Quality + longevity callout */}
            <div style={{ marginTop: 20, padding: "16px 20px", background: C.navy, borderRadius: 8, display: "flex", alignItems: "flex-start", gap: 16 }}>
              <div style={{ fontSize: 28, flexShrink: 0, lineHeight: 1 }}>♾</div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: C.gold, letterSpacing: 1, marginBottom: 6 }}>BUILT FOR THE LONG RUN</div>
                <p style={{ fontSize: 12, color: "#CBD5E0", lineHeight: 1.75, fontWeight: 300, margin: 0 }}>
                  The reference code converts to Apache 2.0 on January 1, 2031 -- meaning after that date, even large enterprises can use it without paying. But the trademarks never convert. The genesis block never changes. The network history never disappears. The AI Lab's role as the trusted anchor of this network is designed to outlast the commercial license period. The 2026-2031 window is when we build the foundation. Everything after that is the permanent structure.
                </p>
              </div>
            </div>
          </div>

          {/* 2031 conversion note */}
          <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 10, padding: 20, borderLeft: `4px solid ${C.gold}` }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: C.gold, letterSpacing: 2, marginBottom: 8 }}>JANUARY 1, 2031: LICENSE CONVERSION</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>
              On January 1, 2031, TIPCL-1.0 automatically converts to Apache License 2.0 for the reference implementation code. After that date, commercial use of the code requires no paid license. However, three things survive the conversion permanently: (1) the NOTICE file attribution requirement -- your code must always credit The AI Lab in its distribution package; (2) all TIP™ trademark restrictions -- you still cannot use The AI Lab's marks; and (3) the genesis block -- every node on the network will always trace back to The AI Lab's founding signature regardless of what the code license says.
            </p>
          </div>
        </div>
      )}

      {tab === "diagram" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, marginBottom: 20, fontWeight: 300 }}>
            This diagram shows how the three protocol layers, four protection mechanisms, network participation rules, and license timeline all fit together in one picture.
          </p>
          <ProtocolDiagram mode="public" />
        </div>
      )}

      {tab === "freeuse" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>COMPLETE FREE USE ELIGIBILITY TABLE</div>
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 12 }}>
                <thead>
                  <tr style={{ background: C.surface }}>
                    {["Who you are", "Revenue limit", "Free use?", "UI attribution required?", "VP accreditation possible?"].map(h => (
                      <th key={h} style={{ padding: "8px 12px", textAlign: "left", color: C.textMuted, fontWeight: 600, borderBottom: `1px solid ${C.border}`, fontSize: 10, letterSpacing: 0.5 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[
                    ["Individual developer",      "None",       "YES",    "YES", "YES"],
                    ["Startup (under $500K rev)",  "< $500K",    "YES",    "YES", "YES"],
                    ["Nonprofit organization",     "None",       "YES",    "YES", "YES"],
                    ["Journalism organization",    "None",       "YES",    "YES", "YES (priority)"],
                    ["University / college",        "None",       "YES",    "YES", "YES"],
                    ["Government body",            "None",       "YES",    "YES", "YES"],
                    ["Enterprise (over $500K rev)","Any",        "NO",     "YES", "YES"],
                    ["Enterprise with license",    "> $500K",    "PAID",   "YES", "YES"],
                  ].map((row, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${C.border}`, background: i%2===0 ? C.surface : C.bg }}>
                      {row.map((cell, ci) => (
                        <td key={ci} style={{ padding: "10px 12px", color: ci===2 ? (cell==="YES"||cell==="YES (priority)" ? C.green : cell==="NO" ? C.red : C.gold) : C.textSecondary, fontWeight: ci===2 ? 600 : 300, fontSize: 12 }}>{cell}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card">
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 14 }}>THE MANDATORY ATTRIBUTION -- EXACTLY WHAT YOU DISPLAY</div>
            <p style={{ fontSize: 12, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, marginBottom: 16 }}>
              Every implementation must display one of these formats somewhere visible to users -- in a footer, About page, Help section, or equivalent. You choose the format that fits your design.
            </p>
            {[
              { label: "Full form", code: 'Built on TIP Protocol by The AI Lab Intelligence Unobscured, Inc. (theailab.org) | Licensed under TIPCL-1.0' },
              { label: "Short form (with hyperlink)", code: 'Powered by TIP Protocol -- theailab.org' },
              { label: "Badge form", code: '<tip-badge type="mark" size="40" variant="light"></tip-badge>\n<!-- Links automatically to theailab.org/tip -->' },
              { label: "API response form", code: 'X-Powered-By: TIP-Protocol/theailab.org' },
            ].map(({ label, code }, i) => (
              <div key={i} style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 1, marginBottom: 6 }}>{label.toUpperCase()}</div>
                <div className="code-block" style={{ fontSize: 11, lineHeight: 1.8 }}>
                  <pre style={{ margin: 0, whiteSpace: "pre-wrap", color: "#CBD5E0" }}>{code}</pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "faq" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {[
              { q: "Can I build a competing trust protocol using TIP as a foundation?", a: "Yes, with two constraints. First, you must attribute The AI Lab as the origin in your NOTICE file and UI. Second, you cannot call it TIP™ or use any of The AI Lab's trademarks. Your product must have its own name and brand." },
              { q: "Can I fork the code and change the license to MIT or GPL?", a: "No. You can fork the code and distribute it under TIPCL-1.0. You cannot relicense it under a different license. The NOTICE file and attribution requirement survive any fork." },
              { q: "I have a startup that just crossed $500K revenue. What happens?", a: "You have a 90-day grace period to purchase a Commercial License. Email licensing@theailab.org. The Sentinel tier ($2,750/yr) is designed for companies in this range." },
              { q: "Does TIPCL-1.0 affect the open protocol specification?", a: "No. The protocol specification (the document describing how TIP works) is separately licensed under CC-BY 4.0 and is completely unaffected by TIPCL-1.0. You can always implement TIP Protocol from scratch using only the spec." },
              { q: "After January 1, 2031, does the commercial license requirement go away?", a: "Yes. On January 1, 2031, the code converts to Apache 2.0 and the commercial license requirement ends. However, trademark restrictions and the NOTICE file attribution requirement survive the conversion permanently." },
              { q: "Can a government make TIP Protocol mandatory without paying?", a: "Yes. Government entities qualify for free use under TIPCL-1.0 regardless of their size or budget. A national government implementing TIP Protocol for citizen identity pays nothing for the code. Attribution in documentation is still required." },
              { q: "I am a journalist. Do I need to pay anything?", a: "No. Journalism organizations of any size qualify for free use under TIPCL-1.0. This includes newspapers, magazines, broadcast organizations, independent journalists, and press freedom nonprofits." },
              { q: "Where is the full TIPCL-1.0 license document?", a: "The full legal text is available at theailab.org/license and in the LICENSE.txt file included with every distribution of the reference implementation." },
            ].map(({ q, a }, i) => (
              <div key={i} style={{ padding: 16, background: C.surface, borderRadius: 8, border: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: C.navy, marginBottom: 8 }}>{q}</div>
                <div style={{ fontSize: 11.5, color: C.textSecondary, lineHeight: 1.65, fontWeight: 300 }}>{a}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN: LICENSE STRATEGY DEEP DIVE
// ═══════════════════════════════════════════════════════════════════════════════

function AdminLicenseDeep() {
  const [tab, setTab] = useState("architecture");
  const tabs = [
    { id: "architecture", label: "License Architecture" },
    { id: "diagram",      label: "Full Diagram" },
    { id: "moat",         label: "Permanent Moat" },
    { id: "2031",         label: "Post-2031 Strategy" },
  ];

  return (
    <div style={{ animation: "slideUp 0.5s ease" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
        <div style={{ padding: "4px 12px", background: `${C.adminAccent}10`, border: `1px solid ${C.adminAccent}20`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.adminAccent, letterSpacing: 2 }}>INTERNAL VIEW</div>
        <div style={{ fontSize: 11, color: C.textMuted }}>License strategy and competitive protection analysis</div>
      </div>
      <h2 className="serif section-heading" style={{ fontSize: 32, fontWeight: 700, marginTop: 8, marginBottom: 6, color: C.navy }}>TIPCL-1.0 License Strategy</h2>
      <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 24, fontWeight: 300, lineHeight: 1.75 }}>
        TIP Community License v1.0 governs the reference implementation. Four independent protection layers work together: the TIPCL-1.0 code license, the CC-BY 4.0 spec, trademark law, and patent law. Each layer protects something different. Together they are designed to make TIP Protocol the standard while ensuring The AI Lab captures the value it creates.
      </p>

      <div className="rg-tabs" style={{ display: "flex", gap: 4, marginBottom: 24, flexWrap: "wrap" }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: "7px 14px", borderRadius: 5, border: `1px solid ${tab===t.id ? C.gold : C.border}`, background: tab===t.id ? C.goldDim : "transparent", color: tab===t.id ? C.gold : C.textMuted, cursor: "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: tab===t.id ? 600 : 400 }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "architecture" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div style={{ overflowX: "auto", marginBottom: 24 }}>
            <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 12 }}>
              <thead>
                <tr style={{ background: C.surface }}>
                  {["Layer", "What it covers", "License / Law", "Free for whom", "Expires", "Attribution survives"].map(h => (
                    <th key={h} style={{ padding: "10px 12px", textAlign: "left", color: C.gold, fontWeight: 600, borderBottom: `2px solid ${C.border}`, fontSize: 10, letterSpacing: 1 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[
                  ["A: Protocol Spec", "The rules document", "CC-BY 4.0", "Everyone, forever", "Never", "Citation required, permanent"],
                  ["B: Reference Code", "Python + Node.js + SDK", "TIPCL-1.0 -> Apache 2.0", "Individuals, nonprofits, <$500K", "Converts Jan 1, 2031", "UI until 2031, NOTICE forever"],
                  ["C: Trademarks", "TIP™, AI Trust ID™, etc.", "Trademark Law", "N/A -- license required", "Never (renew q10yr)", "Cannot use marks -- permanent"],
                  ["D: Patents", "10 specific inventions", "Patent Law", "Free in TIPCL compliant impl.", "~2047", "N/A -- license required"],
                  ["E: Genesis Block", "Network founding record", "Cryptographic (SLH-DSA)", "N/A -- structural fact", "Never", "Baked into DAG permanently"],
                ].map((row, i) => (
                  <tr key={i} style={{ background: i%2===0 ? C.surface : C.bg, borderBottom: `1px solid ${C.border}` }}>
                    {row.map((cell, ci) => (
                      <td key={ci} style={{ padding: "10px 12px", color: ci===0 ? C.navy : ci===4 ? (cell.includes("Never") ? C.green : cell.includes("2031") ? C.gold : C.red) : C.textSecondary, fontWeight: ci===0 ? 600 : 300, fontSize: 12 }}>{cell}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="card" style={{ marginBottom: 20, border: `1px solid ${C.teal}30`, borderTop: `3px solid ${C.teal}` }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.teal, letterSpacing: 2, marginBottom: 16 }}>WHY TIPCL-1.0 IS BETTER THAN PURE APACHE 2.0</div>
            <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <div style={{ padding: 16, background: `${C.red}06`, borderRadius: 8, border: `1px solid ${C.red}20` }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: C.red, marginBottom: 10 }}>PURE APACHE 2.0 (what we replaced)</div>
                {["No mandatory UI attribution -- The AI Lab disappears from products","No commercial license requirement -- enterprises pay nothing","No copyleft -- core improvements not shared back","Attribution only in NOTICE file -- hidden from end users","No network participation rules","Converts immediately: day one no commercial leverage"].map((item, i) => (
                  <div key={i} style={{ display: "flex", gap: 6, marginBottom: 6, alignItems: "flex-start" }}>
                    <span style={{ color: C.red, fontWeight: 700, fontSize: 11, flexShrink: 0 }}>-</span>
                    <span style={{ fontSize: 11, color: C.textSecondary, fontWeight: 300 }}>{item}</span>
                  </div>
                ))}
              </div>
              <div style={{ padding: 16, background: `${C.green}06`, borderRadius: 8, border: `1px solid ${C.green}20` }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: C.green, marginBottom: 10 }}>TIPCL-1.0 (current)</div>
                {["Mandatory UI attribution: The AI Lab name in every deployment","Commercial license required for $500K+ enterprises: revenue stream","Copyleft on protocol core: improvements flow back to network","5 years commercial leverage: 2026-2031 to build network effects","Trademark and NOTICE restrictions survive 2031 conversion","Free for journalists, nonprofits, governments: maximum adoption"].map((item, i) => (
                  <div key={i} style={{ display: "flex", gap: 6, marginBottom: 6, alignItems: "flex-start" }}>
                    <span style={{ color: C.green, fontWeight: 700, fontSize: 11, flexShrink: 0 }}>+</span>
                    <span style={{ fontSize: 11, color: C.textSecondary, fontWeight: 300 }}>{item}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === "diagram" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, marginBottom: 20, fontWeight: 300 }}>
            Complete architecture diagram showing all protocol layers, the DAG network, four protection mechanisms, network participation rules, and the license timeline in one view.
          </p>
          <ProtocolDiagram mode="admin" />
        </div>
      )}

      {tab === "moat" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div className="card" style={{ marginBottom: 16, background: C.navy, border: "none" }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: C.gold, letterSpacing: 3, marginBottom: 12 }}>THE PERMANENT COMPETITIVE MOAT</div>
            <p style={{ fontSize: 13, color: "#CBD5E0", lineHeight: 1.75, fontWeight: 300, marginBottom: 16 }}>
              Even if a well-resourced competitor (Google, Meta, a nation-state) forks the open spec and builds a competing identity network after 2031, they face six structural advantages that The AI Lab permanently owns and that no license change or fork can replicate.
            </p>
            <div style={{ display: "grid", gap: 10 }}>
              {[
                { num: "01", title: "The Genesis Block", color: C.gold, detail: "Every node on the TIP network traces its chain back to a genesis block signed by The AI Lab's SLH-DSA-128s root key. A fork starts a new DAG with zero history. A user with 500 verified articles and a trust score of 850 on the original network is not going to abandon that history to restart at 500 on a fork." },
                { num: "02", title: "The Trademark", color: C.gold, detail: "TIP™, AI Trust ID™, and AI Trust Registry™ are trademarks that survive any license conversion permanently. A competitor cannot call their product TIP™ or issue AI Trust ID™ Seals. They must invent their own brand and convince the world to trust it from zero." },
                { num: "03", title: "The Patent Portfolio", color: C.gold, detail: "10 patented inventions (5 from v1, 5 from v2) are valid until approximately 2047. Any implementation of the peppered ZK dedup, adaptive pre-scan calibration, multi-type revocation, GDPR score visibility, or jurisdiction tiers requires either a license from The AI Lab or a design-around. Design-arounds are possible but costly and weakening." },
                { num: "04", title: "The VP Network", color: C.gold, detail: "Every accredited Verification Provider -- iProov, Jumio, Yoti, major news publishers, government digital ID programmes -- is exclusively in The AI Lab's network. A fork must rebuild the entire VP ecosystem from scratch with no head start. The VP network is the bottleneck for new identity issuance." },
                { num: "05", title: "The DAG History", color: C.gold, detail: "The AI Lab's network will have years of accumulated trust score history, content provenance records, and adjudication outcomes before any competitor could launch. That history has real economic value to users and relying parties. A competitor with no history cannot replicate it." },
                { num: "06", title: "The Genesis Block Attribution", color: C.gold, detail: "NOTICE file requirements mean every fork, every competitor, every downstream implementation must acknowledge The AI Lab as the origin. Even the competition's documentation says 'based on TIP Protocol by The AI Lab.' This is the same position Linus Torvalds holds with Linux: not controlling every distribution, but acknowledged as the inventor of the technology that spawned an industry." },
              ].map((item, i) => (
                <div key={i} style={{ display: "grid", gridTemplateColumns: "60px 1fr", gap: 14, padding: "14px 0", borderBottom: i < 5 ? `1px solid #1B2A4A` : "none" }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: C.gold, fontFamily: SERIF }}>{item.num}</div>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: "#F1F5F9", marginBottom: 6 }}>{item.title}</div>
                    <div style={{ fontSize: 12, color: "#94A3B8", lineHeight: 1.65, fontWeight: 300 }}>{item.detail}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === "2031" && (
        <div style={{ animation: "fadeIn 0.3s ease" }}>
          <div style={{ background: "#FFFBEB", border: `1px solid ${C.gold}20`, borderRadius: 12, padding: 22, borderLeft: `4px solid ${C.gold}`, marginBottom: 24 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 8 }}>JANUARY 1, 2031: WHAT ACTUALLY CHANGES</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.75, fontWeight: 300, margin: 0 }}>
              On January 1, 2031, TIPCL-1.0 converts to Apache 2.0. The commercial license requirement disappears. Mandatory UI attribution in running applications disappears. But the business model should not depend on these post-2031. Here is why the 2026-2031 window is what matters, and what the business looks like after.
            </p>
          </div>

          <div className="rg2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
            <div className="card" style={{ borderTop: `3px solid ${C.red}` }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.red, letterSpacing: 2, marginBottom: 14 }}>WHAT DISAPPEARS AFTER 2031</div>
              {["Mandatory UI attribution display in running applications","Commercial license fee requirement for enterprises","Copyleft on protocol core modifications","Network participation obligations"].map((item, i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                  <span style={{ color: C.red, fontSize: 12, flexShrink: 0, marginTop: 1 }}>-</span>
                  <span style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300 }}>{item}</span>
                </div>
              ))}
            </div>
            <div className="card" style={{ borderTop: `3px solid ${C.green}` }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.green, letterSpacing: 2, marginBottom: 14 }}>WHAT STAYS AFTER 2031 (PERMANENT)</div>
              {["NOTICE file attribution in all code distributions","All TIP™ trademark restrictions: no one can use The AI Lab's marks","AI Trust ID Seal exclusively issued by The AI Lab's registry","Patent protection on 10 inventions (valid to ~2047)","Genesis block: all nodes trace to The AI Lab's founding signature","VP accreditation: The AI Lab controls who can issue TIP-IDs","DAG history: years of accumulated trust records"].map((item, i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                  <span style={{ color: C.green, fontSize: 12, flexShrink: 0, marginTop: 1 }}>+</span>
                  <span style={{ fontSize: 12, color: C.textSecondary, fontWeight: 300 }}>{item}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div style={{ fontSize: 10, fontWeight: 600, color: C.gold, letterSpacing: 2, marginBottom: 16 }}>REVENUE MODEL POST-2031: SHIFTS BUT DOES NOT DISAPPEAR</div>
            <p style={{ fontSize: 13, color: C.textSecondary, lineHeight: 1.7, fontWeight: 300, marginBottom: 16 }}>
              The Layer B code license revenue ($2.75K-$550K/year from enterprise code licenses) will decrease or disappear after 2031. This is intentional and expected. The model by 2031 should be primarily:
            </p>
            <div style={{ display: "grid", gap: 10 }}>
              {[
                { stream: "AI Trust ID™ Seal certification fees", amount: "$2.5K-$100K/year per org", basis: "Trademark -- unaffected by code license conversion. Only The AI Lab can issue the Seal." },
                { stream: "VP accreditation fees", amount: "$5K-$50K/year per VP", basis: "Governance -- VP accreditation is a contractual relationship, not a code license." },
                { stream: "AI pre-scan API (calibrated ML classifier)", amount: "$0.001-$0.01 per content check", basis: "Service -- The AI Lab's infrastructure, not the open-source code." },
                { stream: "Brand Safety API", amount: "$5K-$50K/year per enterprise", basis: "Service -- monitoring for impersonation of verified accounts." },
                { stream: "Enterprise support and integration (Red Hat model)", amount: "$10K-$200K/year", basis: "Service -- enterprises will pay for SLAs, dedicated support, and custom integration even if the code is Apache 2.0." },
              ].map((s, i) => (
                <div key={i} style={{ display: "grid", gridTemplateColumns: "3fr 1.5fr 3fr", gap: 12, padding: "12px 16px", background: i%2===0 ? C.surface : C.bg, borderRadius: 8, border: `1px solid ${C.border}` }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: C.navy }}>{s.stream}</span>
                  <span style={{ fontSize: 12, fontWeight: 600, color: C.gold }}>{s.amount}</span>
                  <span style={{ fontSize: 11.5, color: C.textSecondary, fontWeight: 300 }}>{s.basis}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


export default function AITrustIDApp() {
  // View mode: "public" shows community pages, "admin" shows internal pages
  const [viewMode, setViewMode] = useState("public");
  // Admin authentication state (placeholder, see AdminAuthGate above)
  const [adminUnlocked, setAdminUnlocked] = useState(false);
  // Protocol spec version (admin only)
  const [version, setVersion] = useState("v2");
  // Navigation and page state
  const [page, setPage] = useState("home");
  const [regStep, setRegStep] = useState(0);
  const [embedTab, setEmbedTab] = useState("widget");
  const [showScore, setShowScore] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setShowScore(true), 400);
    return () => clearTimeout(t);
  }, [page]);

  const publicNav = [
    { id: "home", label: "Overview" },
    { id: "howitworks", label: "How It Works" },
    { id: "origin", label: "Content Labels" },
    { id: "embed", label: "For Developers" },
    { id: "badge", label: "Badges" },
    { id: "yourprivacy", label: "Your Privacy" },
    { id: "license", label: "Open License" },
  ];

  const adminNavV1 = [
    { id: "home", label: "Overview" },
    { id: "licensing", label: "Licensing + Revenue" },
    { id: "launch", label: "Launch Plan" },
    { id: "register", label: "Registration" },
    { id: "content", label: "Content Origin" },
    { id: "biometric", label: "Biometrics" },
    { id: "embed", label: "Integration" },
    { id: "badge", label: "Live Badges" },
  ];

  const adminNavV2 = [
    ...adminNavV1,
    { id: "privacy", label: "Privacy Arch.", isNew: true },
    { id: "revocation", label: "Revocation", isNew: true },
    { id: "gdpr", label: "GDPR & Data Rights", isNew: true },
    { id: "jurisdictions", label: "Jurisdiction Tiers", isNew: true },
    { id: "command", label: "Command Center", isNew: true, isAlert: true },
    { id: "roles", label: "Responsibilities", isNew: true },
    { id: "vpstrategy", label: "VP Strategy", isNew: true },
    { id: "genesis", label: "Genesis Ring", isNew: true },
    { id: "licensedeep", label: "License Strategy", isNew: true },
  ];

  const navItems = viewMode === "public" ? publicNav : (version === "v2" ? adminNavV2 : adminNavV1);

  const switchToAdmin = () => {
    setViewMode("admin");
    setPage("home");
    setShowScore(false);
    setTimeout(() => setShowScore(true), 300);
  };

  const switchToPublic = () => {
    setViewMode("public");
    setAdminUnlocked(false);
    setPage("home");
    setShowScore(false);
    setTimeout(() => setShowScore(true), 300);
  };

  const navigate = (id) => {
    setPage(id);
    setRegStep(0);
    setShowScore(false);
    setTimeout(() => setShowScore(true), 300);
  };

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.textPrimary, fontFamily: "'Libre Franklin', 'Helvetica Neue', sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,400;0,600;0,700;1,400&family=Libre+Franklin:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        @keyframes slideUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes shake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-6px)} 75%{transform:translateX(6px)} }
        .nav-btn { background: none; border: none; color: ${C.textMuted}; padding: 10px 16px; cursor: pointer; font-size: 12.5px; font-family: 'Libre Franklin', sans-serif; font-weight: 500; border-radius: 6px; transition: all 0.25s; white-space: nowrap; letter-spacing: 0.3px; }
        .nav-btn:hover { color: ${C.textPrimary}; background: ${C.surfaceRaised}; }
        .nav-btn.active { color: ${C.gold}; background: ${C.goldDim}; font-weight: 600; }
        .nav-btn.new-item { color: ${C.teal}; }
        .nav-btn.new-item.active { color: ${C.teal}; background: ${C.teal}10; }
        .nav-btn.alert-item { color: ${C.red}; }
        .nav-btn.alert-item.active { color: ${C.red}; background: ${C.red}10; }
        .card { background: ${C.bg}; border: 1px solid ${C.border}; border-radius: 12px; padding: 28px; transition: all 0.3s; }
        .card:hover { border-color: ${C.goldGlow}; box-shadow: 0 2px 20px rgba(184,148,46,0.06); }
        .serif { font-family: 'Cormorant Garamond', Georgia, serif; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .tag { display: inline-block; padding: 3px 10px; border-radius: 3px; font-size: 10px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; }
        .divider { height: 1px; background: linear-gradient(90deg, transparent, ${C.border}, transparent); margin: 8px 0; }
        .step-btn { background: ${C.bg}; border: 1px solid ${C.border}; color: ${C.textPrimary}; padding: 14px 18px; border-radius: 8px; cursor: pointer; font-family: inherit; font-size: 13px; text-align: left; transition: all 0.3s; width: 100%; }
        .step-btn:hover { border-color: ${C.borderLight}; background: ${C.surface}; }
        .step-btn.active { border-color: ${C.gold}; background: ${C.goldDim}; }
        .code-block { background: ${C.navy}; border-radius: 8px; padding: 20px; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; line-height: 1.9; overflow-x: auto; color: #CBD5E0; }
        .mode-btn { padding: 5px 14px; border-radius: 20px; font-size: 11px; font-weight: 600; cursor: pointer; font-family: 'Libre Franklin', sans-serif; letter-spacing: 0.5px; transition: all 0.2s; border: 1px solid transparent; }
        .admin-bar { background: ${C.navy}; padding: 8px 32px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
        @media (max-width: 600px) {
          .app-header { padding: 10px 14px !important; }
          .app-header .brand-text { font-size: 12px !important; }
          .app-header .brand-sub { font-size: 8px !important; }
          .app-header .site-url { display: none !important; }
          .app-nav { padding: 8px 10px !important; }
          .nav-btn { padding: 8px 10px; font-size: 11px; }
          .app-main { padding: 20px 14px !important; }
          .app-footer { padding: 16px 14px !important; }
          .hero-title { font-size: 28px !important; }
          .hero-desc { font-size: 13px !important; }
          .card { padding: 16px !important; }
          .code-block { padding: 14px; font-size: 10px; }
          .rg2, .rg3, .rg4, .rg5 { grid-template-columns: 1fr !important; }
          .rg5-seal { grid-template-columns: repeat(3, 1fr) !important; overflow-x: auto; }
          .rg-sidebar { grid-template-columns: 1fr !important; }
          .rg-bio { flex-direction: column !important; }
          .rg-tabs { flex-wrap: wrap !important; }
          table { font-size: 10px !important; }
          table th, table td { padding: 6px 8px !important; }
          .section-heading { font-size: 24px !important; }
          .admin-bar { padding: 8px 14px !important; }
        }
        @media (min-width: 601px) and (max-width: 900px) {
          .app-header { padding: 12px 20px !important; }
          .app-nav { padding: 10px 16px !important; }
          .app-main { padding: 28px 20px !important; }
          .app-footer { padding: 20px 20px !important; }
          .hero-title { font-size: 36px !important; }
          .rg3, .rg4, .rg5 { grid-template-columns: repeat(2, 1fr) !important; }
          .rg5-seal { grid-template-columns: repeat(3, 1fr) !important; overflow-x: auto; }
          .rg-sidebar { grid-template-columns: 1fr !important; }
          .rg-bio { flex-wrap: wrap !important; }
          .rg-bio > div { min-width: 260px !important; }
        }
      `}</style>

      {/* ─── HEADER ─── */}
      <header className="app-header" style={{ borderBottom: `1px solid ${C.border}`, padding: "14px 32px", display: "flex", alignItems: "center", justifyContent: "space-between", background: `${C.bg}EE`, backdropFilter: "blur(12px)", position: "sticky", top: 0, zIndex: 100 }}>

        {/* Logo: light variant for readability on white header */}
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <TrustIDSeal score={900} size={34} variant="light" founding />
          <div>
            <div className="brand-text" style={{ fontSize: 14, fontWeight: 700, letterSpacing: 1.5, color: C.navy }}>THE AI LAB</div>
            <div className="brand-sub" style={{ fontSize: 9.5, color: C.gold, letterSpacing: 3.5, fontWeight: 500 }}>TRUST IDENTITY PROTOCOL (TIP™)</div>
          </div>
        </div>

        {/* Right side controls */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {/* Admin version switcher (admin mode only) */}
          {viewMode === "admin" && adminUnlocked && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginRight: 8 }}>
              <span style={{ fontSize: 10, color: C.textMuted, letterSpacing: 1 }}>SPEC</span>
              <button className="mode-btn" onClick={() => { setVersion("v1"); if (!adminNavV1.find(n => n.id === page)) setPage("home"); }} style={{ background: version==="v1" ? C.surfaceRaised : "transparent", color: version==="v1" ? C.textPrimary : C.textMuted, border: `1px solid ${version==="v1" ? C.border : "transparent"}` }}>v1</button>
              <button className="mode-btn" onClick={() => setVersion("v2")} style={{ background: version==="v2" ? C.navy : "transparent", color: version==="v2" ? C.gold : C.textMuted, border: `1px solid ${version==="v2" ? C.navy : "transparent"}` }}>v2</button>
            </div>
          )}

          {/* Public / Admin mode toggle */}
          {viewMode === "public" ? (
            <button className="mode-btn" onClick={switchToAdmin} style={{ background: C.surfaceRaised, color: C.textSecondary, border: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 6 }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              Admin
            </button>
          ) : (
            <button className="mode-btn" onClick={switchToPublic} style={{ background: `${C.adminAccent}10`, color: C.adminAccent, border: `1px solid ${C.adminAccent}20`, display: "flex", alignItems: "center", gap: 6 }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
              Exit Admin
            </button>
          )}

          <div className="site-url" style={{ fontSize: 11, color: C.textMuted, letterSpacing: 1, marginLeft: 4 }}>theailab.org</div>
        </div>
      </header>

      {/* ─── ADMIN BAR (when in admin mode) ─── */}
      {viewMode === "admin" && adminUnlocked && (
        <div className="admin-bar">
          <span style={{ fontSize: 10, fontWeight: 700, color: C.gold, letterSpacing: 3 }}>ADMIN · INTERNAL VIEW</span>
          <span style={{ fontSize: 11, color: "#94A3B8", fontWeight: 300 }}>Contains confidential business strategy, revenue projections, and launch plan. Do not share externally.</span>
          {version === "v2" && (
            <span style={{ fontSize: 10, color: "#64748B", marginLeft: "auto" }}>v2 · FIX-02 · FIX-03 · FIX-05 · FIX-06 · FIX-08</span>
          )}
        </div>
      )}

      {/* ─── NAV ─── */}
      {!(viewMode === "admin" && !adminUnlocked) && (
        <nav className="app-nav" style={{ padding: "10px 32px", borderBottom: `1px solid ${C.border}`, display: "flex", gap: 2, overflowX: "auto", background: C.bg }}>
          {navItems.map(n => (
            <button key={n.id} className={`nav-btn${n.isAlert ? " alert-item" : n.isNew ? " new-item" : ""}${page===n.id ? " active" : ""}`} onClick={() => navigate(n.id)}>
              {n.label}
              {n.isAlert && <span style={{ marginLeft: 5, fontSize: 8, fontWeight: 700, background: `${C.red}20`, color: C.red, borderRadius: 3, padding: "1px 4px" }}>ACTION</span>}
              {n.isNew && !n.isAlert && <span style={{ marginLeft: 5, fontSize: 8, fontWeight: 700, background: `${C.teal}20`, color: C.teal, borderRadius: 3, padding: "1px 4px" }}>NEW</span>}
            </button>
          ))}
        </nav>
      )}

      {/* ─── MAIN ─── */}
      <main className="app-main" style={{ padding: "36px 32px", maxWidth: 1100, margin: "0 auto", animation: "fadeIn 0.4s ease" }}>

        {/* ══ ADMIN AUTH GATE ══ */}
        {viewMode === "admin" && !adminUnlocked && (
          <AdminAuthGate onUnlock={() => setAdminUnlocked(true)} />
        )}

        {/* ══ PUBLIC PAGES ══ */}
        {viewMode === "public" && page === "home"        && <PublicHome />}
        {viewMode === "public" && page === "howitworks"  && <PublicHowItWorks regStep={regStep} setRegStep={setRegStep} />}
        {viewMode === "public" && page === "origin"      && <PublicOrigin />}
        {viewMode === "public" && page === "embed"       && <PublicIntegration embedTab={embedTab} setEmbedTab={setEmbedTab} />}
        {viewMode === "public" && page === "badge"       && <PublicBadges showScore={showScore} />}
        {viewMode === "public" && page === "yourprivacy" && <PublicPrivacy />}
        {viewMode === "public" && page === "license"      && <PublicLicense />}

        {/* ══ ADMIN PAGES ══ */}
        {viewMode === "admin" && adminUnlocked && page === "home"          && <AdminHome version={version} />}
        {viewMode === "admin" && adminUnlocked && page === "licensing"     && <AdminLicensing />}
        {viewMode === "admin" && adminUnlocked && page === "launch"        && <AdminLaunch />}
        {viewMode === "admin" && adminUnlocked && page === "register"      && <AdminRegistration regStep={regStep} setRegStep={setRegStep} version={version} />}
        {viewMode === "admin" && adminUnlocked && page === "content"       && <AdminContent version={version} embedTab={embedTab} setEmbedTab={setEmbedTab} />}
        {viewMode === "admin" && adminUnlocked && page === "biometric"     && <AdminBiometrics version={version} />}
        {viewMode === "admin" && adminUnlocked && page === "embed"         && <PublicIntegration embedTab={embedTab} setEmbedTab={setEmbedTab} />}
        {viewMode === "admin" && adminUnlocked && page === "badge"         && <BadgeGallery showScore={showScore} />}
        {viewMode === "admin" && adminUnlocked && page === "privacy"       && version === "v2" && <PrivacyPage />}
        {viewMode === "admin" && adminUnlocked && page === "revocation"    && version === "v2" && <RevocationPage />}
        {viewMode === "admin" && adminUnlocked && page === "gdpr"          && version === "v2" && <GDPRPage />}
        {viewMode === "admin" && adminUnlocked && page === "jurisdictions" && version === "v2" && <JurisdictionsPage />}
        {viewMode === "admin" && adminUnlocked && page === "command"       && <AdminCommandCenter />}
        {viewMode === "admin" && adminUnlocked && page === "roles"         && <AdminResponsibilities />}
        {viewMode === "admin" && adminUnlocked && page === "vpstrategy"    && <AdminVPStrategy />}
        {viewMode === "admin" && adminUnlocked && page === "genesis"       && <AdminGenesisRing />}
        {viewMode === "admin" && adminUnlocked && page === "licensedeep"   && <AdminLicenseDeep />}

      </main>

      {/* ─── FOOTER ─── */}
      <footer className="app-footer" style={{ borderTop: `1px solid ${C.border}`, padding: "24px 32px", marginTop: 48, textAlign: "center" }}>
        <div style={{ fontSize: 11, color: C.textMuted, letterSpacing: 1 }}>
          &copy; 2026 The AI Lab Intelligence Unobscured, Inc. · All rights reserved.
          {viewMode === "admin" && adminUnlocked && <span style={{ color: C.adminAccent }}> · Admin Interface v4 · {version === "v2" ? "Protocol v2.0" : "Protocol v1.0"}</span>}
        </div>
        <div style={{ fontSize: 10, color: C.textMuted, marginTop: 6, letterSpacing: 0.5 }}>
          AI Trust ID&trade; &middot; AI Trust Registry&trade; &middot; TIP&trade; &middot; Trust Identity Protocol (TIPCL-1.0) &middot; The Global Seal of Trust&trade; &middot; theailab.org
        </div>
        {viewMode === "admin" && adminUnlocked && version === "v2" && (
          <div style={{ fontSize: 10, color: C.teal, marginTop: 6, letterSpacing: 0.5 }}>
            v2 Critical Fixes: FIX-02 Privacy Architecture · FIX-03 Pre-Scan Calibration · FIX-05 Identity Revocation · FIX-06 GDPR Compliance · FIX-08 Jurisdiction Tiers
          </div>
        )}
      </footer>
    </div>
  );
}
