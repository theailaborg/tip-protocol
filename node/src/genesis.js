/**
 * @file @tip-protocol/node/src/genesis.js
 * @description TIP Protocol Genesis Block — Production Implementation
 *
 * The Genesis Block is the immutable foundation of the TIP DAG. It contains:
 *
 *   1. The protocol declaration (version, issuer, spec URL, license)
 *   2. The root Verification Provider record for The AI Lab
 *   3. The founding node keypair commitments
 *   4. The Genesis Ring: founding identities (placeholder — real identities
 *      added via the seed script before launch)
 *   5. The initial trust scoring parameters
 *   6. A cryptographic seal over the entire block using SLH-DSA-128s
 *      (the most conservative post-quantum signature scheme)
 *
 * IMMUTABILITY GUARANTEE:
 *   The Genesis Block hash is computed from a canonical serialisation of all
 *   its fields. Any node that receives a genesis block with a different hash
 *   is on a different network and cannot interoperate.
 *
 *   Every subsequent transaction references the genesis block hash, making
 *   the entire DAG history traceable back to this single anchoring event.
 *
 * PRODUCTION STEPS BEFORE LAUNCH:
 *   1. Run: node scripts/seed.js --generate-genesis-keys
 *      This produces the root SLH-DSA keypair stored in genesis-data/
 *   2. Run: node scripts/seed.js --mint-genesis
 *      This writes genesis.json with a valid signature
 *   3. Commit genesis.json (NOT the private key) to version control
 *   4. Every node validates the genesis hash on startup
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { shake256, shake256Multi, generateSLHDSAKeypair, mldsaSign, mldsaVerify, computeTxId, canonicalJson, canonicalTx } = require("../../shared/crypto");
const { nowMs, fromIso } = require("../../shared/time");
const { TX_TYPES, PROTOCOL, ORIGIN } = require("../../shared/constants");
const { log } = require("./logger");

// ─── Genesis Block Constants ──────────────────────────────────────────────────
// These are FIXED and must never change once the network is live.
// Integer epoch ms for 2026-03-15T00:00:00.000Z UTC — chain wall-clock
// anchor. Every node verifies this exact value at startup.
const GENESIS_TIMESTAMP = 1773532800000; // 2026-03-15T00:00:00.000Z UTC
const GENESIS_CHAIN_ID = "tip-mainnet-v2";
const GENESIS_VP_REGION = "US";

// ─── Canonical Genesis Payload ────────────────────────────────────────────────
// Protocol definition data only. Tx-level fields (tx_type, timestamp, prev)
// are on the genesis tx wrapper, not here.
// This is the EXACT data hashed for GENESIS_HASH. Must be byte-for-byte
// identical across every node in the network.
// Any edit here MUST be paired with re-running `npm run seed` to regenerate
// GENESIS_TX_SIGNATURE and GENESIS_VP_TX_SIGNATURE.

const GENESIS_PAYLOAD = Object.freeze({
  version: "2",

  protocol: {
    name: PROTOCOL.name,
    short: PROTOCOL.short,
    version: PROTOCOL.version,
    chain_id: GENESIS_CHAIN_ID,
    spec_url: PROTOCOL.specUrl,
    license: PROTOCOL.license,
    issuer: PROTOCOL.issuer,
    issuer_url: PROTOCOL.issuerUrl,
  },

  // ── Protocol Constants (75 values — immutable, read by all nodes) ──────────
  // These are loaded into ProtocolConstants singleton at boot.
  // See my-notes/global-constant.md for the full specification.
  protocol_constants: {
    score: {
      max_total: 1000,
      max_identity: 530,
      max_content: 350,
      max_reputation: 50,
      max_longevity: 70,
      initial_identity: 500,
    },
    identity: {
      social_link_bonus: 5,
      max_social_accounts: 6,
      max_social_bonus: 30,
    },
    content: {
      registration_credit: 2,
      verification_credit: 1,
      oh_cap: 200,
      aa_cap: 100,
      ag_cap: 100,
      mx_cap: 100,
      per_content_lifetime_cap: 5,
    },
    reputation: {
      clean_period_days: 90,
      clean_period_bonus: 10,
      dispute_cleared_bonus: 5,
    },
    longevity: {
      tiers: [
        { months: 6, points: 15 },
        { months: 12, points: 30 },
        { months: 24, points: 45 },
        { months: 36, points: 60 },
        { months: 60, points: 70 },
      ],
    },
    penalties: {
      // Per-pair escalation [1st, 2nd, 3rd+] = base × [1, 2, 3] per spec
      // (TIP_Trust_Scoring §6 Asymmetric Penalty Structure).
      oh_as_ag: [-100, -200, -300],   // 1st, 2nd, 3rd offense
      oh_as_aa: [-40, -80, -120],
      aa_as_ag: [-25, -50, -75],
      minor_falsehood: -75,
      major_falsehood: -300,
      retraction: -50,
      device_compromise: -15,
      lost_dispute_stake: -15,
      lost_jury_stake: -10,
      lost_appeal_stake: -25,
      appeal_restore_percent: 50,
    },
    jury: {
      // Stakes — positive (amounts at risk, code applies ± based on outcome)
      dispute_stake: 15,
      jury_stake: 10,
      appeal_stake: 25,
      frivolous_dismiss_fee: 5,
      // Thresholds — positive (score requirements)
      dispute_filing_min_score: 550,
      jury_min_score: 700,
      jury_min_score_fallback: 500,        // Pass-3 floor in jury.js _pickWithGeoCap. When the eligible-at-700 pool can't fill jury_size after geo relaxation, the selector falls back to score >= 500 (verified-tier) rather than admitting arbitrarily-low-score jurors. Never below dispute_filing_min_score.
      expert_min_score: 850,
      expert_min_score_fallback: 700,      // Pass-3 floor for selectExperts. Mirrors jury_min_score_fallback — when expert pool at 850 is insufficient, falls back to jury-tier (>=700) rather than open admission.
      // Sizes and counts
      jury_size: 7,
      jury_majority_vote: 3,
      jury_min_reveals: 5,
      jury_max_same_country: 3,
      appeal_max_same_country: 3,          // Geo-cap for selectExperts (Stage 3 appeal panel). Caps any single jurisdiction below the 3-of-5 majority and lets a 5-expert panel form from as few as two countries. Promoted to genesis for governance tunability + audit clarity.
      jury_cooldown_days: 7,
      expert_panel_size: 5,
      expert_min_votes: 3,
      // Bonuses — positive (always added)
      jury_majority_bonus: 3,
      expert_majority_bonus: 7,
      appeal_win_bonus: 10,
      vindication_bonus: 5,
      upheld_bonus: 5,
      // Penalties — negative (always subtracted). Juror/expert split + no-commit/no-reveal split.
      // no-commit: summoned but never submitted a commit tx (-1 — light penalty, could be a node outage)
      // no-reveal: committed but didn't reveal (-8/-10 — deliberate non-reveal is more culpable)
      jury_minority_penalty: -8,
      expert_minority_penalty: -10,
      jury_no_commit_penalty: -1,
      jury_no_reveal_penalty: -8,
      expert_no_commit_penalty: -1,
      expert_no_reveal_penalty: -10,
      // Timing
      jury_commit_hours: 72,
      jury_reveal_hours: 12,
      appeal_window_hours: 48,
      appeal_commit_hours: 72,
      appeal_reveal_hours: 12,
      // Phase 3 abuse prevention — rolling per-filer rate limit. A
      // disputer can file at most N disputes within the trailing
      // window. v1 picks 5 / 30 days (per spec §5.4). Window is in ms
      // to match the rest of the time constants; the predicate counts
      // CONTENT_DISPUTED txs by disputer_tip_id within now-window.
      max_disputes_per_filer_per_window: 5,
      dispute_filer_window_ms: 2592000000,
      // AI classifier
      ai_auto_dismiss_threshold: 0.30,
      ai_auto_escalate_threshold: 0.90,
      ai_timeout_seconds: 60,
    },
    tiers: {
      highly_trusted: 850,
      trusted: 650,
      verified: 400,
      caution: 200,
    },
    verify_caps: {
      per_content: 5,
      per_day: 5,
      per_month: 30,
      base_delta: 2,
      high_trust_delta: 3,
      high_trust_min: 800,
    },
    rate_limits: {
      max_registrations_per_day: 50,
      max_verifications_given_per_day: 5,
      max_verifications_given_per_month: 30,
      duplicate_perceptual_threshold: 0.90,
    },
    prescan: {
      default: 0.85,
      conversational: 0.82,
      creative: 0.87,
      academic: 0.92,
      legal: 0.93,
      floor: 0.80,
      ceiling: 0.94,
      // 4-tier categorical model — fixed cutoffs for v1; per-content-type
      // overrides come in v2 when categorization wires in.
      tier_thresholds: {
        elevated: 0.70,
        high: 0.90,
        critical: 0.98,
      },
      // Creator-history calibration (Claim Group G / FIX-03). Veterans with
      // clean track records get a one-tier-down adjustment. Never shifts 2
      // tiers — prevents "build clean history then post AI as OH" gaming.
      calibration: {
        moderate_min: 50,
        veteran_min: 200,
      },

      // ── Async-prescan worker config ──────────────────────────────────
      // The worker process polls prescan_jobs, calls the classifier, and
      // emits PRESCAN_COMPLETED. Retry policy: degraded (soft) failures
      // and hard errors get separate budgets but share the same backoff
      // schedule. After both budgets exhaust, fail-open silently —
      // content moves to REGISTERED without a flag.
      worker_max_retries_on_degraded: 4,
      worker_max_retries_on_error: 4,
      worker_retry_backoff_ms: [5000, 30000, 300000, 1800000],  // 5s, 30s, 5min, 30min
      worker_claim_timeout_ms: 60000,         // 60s before another worker reclaims a stuck job
      // Failover: when the original assigned node fails to emit
      // PRESCAN_COMPLETED within takeover_after_ms, a round-modulo
      // leader on another node takes over. fail_open_after_ms is the
      // backstop — past this point, any leader can emit a fail-open
      // completion so content can't get stuck in PENDING_PRESCAN forever.
      takeover_after_ms: 600000,              // 10 min
      fail_open_after_ms: 3600000,            // 1 hour
      // Client poll hints — surfaced on the 202 response from
      // /v1/content/register. Wait poll_after_ms before each poll;
      // give up after poll_max_attempts.
      poll_after_ms: 2000,
      poll_max_attempts: 30,
      // Content-type taxonomy + detection
      valid_content_types: ["text", "image", "audio", "video", "multi"],
      // Image + text post split: text length ≥ this → article-with-hero
      // (content_type="text"), below → photo-with-caption ("image").
      article_text_threshold_chars: 1000,
      // When a modality returns degraded signal (error / disagreement /
      // exact 0.5 neutral), its weight in the aggregation is multiplied
      // by this. 0.5 = half-weight; 0 would zero it out entirely.
      degraded_weight_multiplier: 0.5,
      // Per-content-type modality weight matrix.
      //
      // PRIMARY-FLOOR + ASYMMETRIC-LIFT aggregation: the primary modality
      // (matching content_type — diagonal of this matrix) is the FLOOR
      // — its probability is the minimum verdict. Off-diagonal entries
      // are LIFT COEFFICIENTS for secondary modalities, which can ONLY
      // RAISE the verdict when they vote AI more strongly than primary;
      // they NEVER dilute a clean primary.
      //
      //   final = primary_prob + Σ max(0, secondary_prob - primary_prob) × secondary_weight
      //   (clamped to [0, 1])
      //
      // Diagonal cells are set to 1.00 as a documentation convention
      // marking "this is the primary." The aggregator skips the primary
      // in the lift sum (it's the floor, added directly), so the value
      // is not arithmetic — it's read at a glance to identify each row's
      // primary modality.
      //
      // 'multi' has no single primary; the aggregator falls back to a
      // traditional weighted average over present modalities.
      //
      // Per-row reasoning (off-diagonal lift coefficients):
      // - text:  image=0.30 (visual companion content), video=0.20
      //          (embedded video), audio=0.10 (rare in articles)
      // - image: text=0.30 (caption claim), video=0.20 (carousel clip),
      //          audio=0.10 (rare)
      // - audio: text=0.20 (description/lyrics), image=0.15 (cover art),
      //          video=0.20 (music video case)
      // - video: audio=0.35 (voice-over AI is the strongest secondary
      //          signal for AI video), text=0.15 (description), image=0.10
      //          (thumbnail is just a frame, redundant with video itself)
      //
      // See ASYNC_PRESCAN_ARCHITECTURE.md § Modality weight matrix for
      // full design discussion.
      modality_weights: {
        text: { text: 1.00, image: 0.30, audio: 0.10, video: 0.20 },
        image: { text: 0.30, image: 1.00, audio: 0.10, video: 0.20 },
        audio: { text: 0.20, image: 0.15, audio: 1.00, video: 0.20 },
        video: { text: 0.15, image: 0.10, audio: 0.35, video: 1.00 },
        multi: { text: 0.30, image: 0.30, audio: 0.20, video: 0.30 },
      },
    },
    // ── Content size caps (v1: inline base64 only) ─────────────────────
    // Hard limits enforced at the API boundary BEFORE the body-parser.
    // video_max_bytes=0 means video uploads are rejected in v1; lifts
    // to GB-scale in v2 once the content-storage layer + file_url path
    // ships. request_body_max_bytes is the Express body-parser limit;
    // single media + reasonable text fits under 25 MB.
    // Dev-federation limits: generous caps while clients and the media
    // pipeline are built out. Revisit before mainnet — video in particular
    // is upload-supported but NOT classifier-supported yet (verdicts
    // fail-open as degraded 0.5 until the classifier ships video models).
    content_limits: {
      text_max_bytes: 102400,             // 100 KB
      image_max_bytes: 104857600,         // 100 MB
      audio_max_bytes: 209715200,         // 200 MB
      video_max_bytes: 4294967296,        // 4 GB
      media_items_max: 20,
      request_body_max_bytes: 26214400,   // 25 MB
    },
    reviewer: {
      // Runtime eligibility gates for reviewer pool. No REGISTER_REVIEWER tx —
      // selection is a pure function of identity state + DAG history,
      // mirroring jury selection.
      min_score: 600,
      max_overturn_rate: 0.30,
      accuracy_sample_size: 20,
      // Creator's accept-private window after PRESCAN_REVIEW_CONFIRMED. The
      // prescan-review trigger emits an auto-cascade CONTENT_DISPUTED once
      // this elapses against cert.ts.
      creator_decision_window_ms: 86400000,
      // Score delta applied to the creator when they accept the reviewer's
      // correction privately (Option 1). Negative — accepting the
      // CONFIRMED finding still carries a small penalty, smaller than the
      // dispute pipeline's OH→AA range (-10..-30). Stored as the signed
      // delta directly so the call site does not negate.
      accept_correction_score_delta: -10,
      // Age threshold for the dashboard self-correction warning. Once
      // flagged content is older than this (and still REGISTERED, not
      // self-corrected, not yet review-triggered), the
      // content_flagged_for_review notification surfaces on the
      // creator's /v1/users/:tip_id/dashboard.
      creator_warning_age_ms: 86400000,
      // Age (ms since PRESCAN_REVIEW_TRIGGERED's cert.ts) at which the
      // prescan-review-trigger emits a node-signed auto-recuse on
      // behalf of an inactive assigned reviewer. Same mechanism as
      // h=R+24 auto-escalation: deterministic clock (cert.ts), round-
      // modulo leader gate, content.status flip-back triggers
      // re-assignment.
      auto_recuse_age_ms: 172800000,
      // Reward for completing review work correctly. Paid as a bonus
      // ON TOP of the disputer-equivalent settlement when the reviewer's
      // CONFIRM aligns with the eventual dispute verdict, AND paid alone
      // when the case closes without a public dispute (DISMISS or
      // creator-accepted-private). On overturn the reviewer takes the
      // full DISPUTE.DISPUTER_STAKE forfeit — they're treated as the
      // de-facto disputer of the case they CONFIRMED. See
      // docs/DISPUTE_SCORING.md "Pre-scan reviewer" section.
      reviewer_correct_bonus: 5,
      // Signed delta applied to a reviewer whose DISMISS is later overturned
      // by an UPHELD dispute (the reviewer said the AI flag was wrong, but the
      // jury said it was right). Stored negative so the call site does not
      // negate — same convention as accept_correction_score_delta. Default -5
      // exactly cancels reviewer_correct_bonus (pure clawback, net 0). Make it
      // more negative for a real penalty if rubber-stamp dismissing surfaces.
      reviewer_wrong_dismiss_clawback: -5,
      // Availability gate (no-show pause). An assignment that dies by
      // node-signed auto-recuse (recusal_reason "sla_expired") is a
      // no-show. More than max_noshow_recusals of them within the
      // reviewer's last noshow_sample_size RESOLVED assignments pauses
      // selection until the rolling window clears. Manual recusals and
      // still-open assignments never count. Hard filter — never relaxed
      // by the selection cascade: relaxing would re-assign the case to
      // someone already ignoring assignments and burn another 48h SLA.
      max_noshow_recusals: 3,
      noshow_sample_size: 10,
    },
    content_grace: {
      // Self-correction windows. Unflagged content keeps the original 24h
      // window; HIGH/CRITICAL prescan-flagged content with override gets 48h,
      // matching the time before reviewer engagement at h=48.
      unflagged_ms: 86400000,    // 24h
      flagged_ms: 172800000,     // 48h
    },
    media_retention: {
      // Three-case retention — clock anchor depends on the ctid's
      // lifecycle so far:
      //
      //   never disputed              → registered_at + base_retention_ms
      //   only ADJUDICATION_RESULT    → adjudication.ts + post_adjudication_ms
      //   APPEAL_RESULT reached       → appeal.ts + post_appeal_ms
      //
      // post_adjudication_ms (7d) safely covers the 2d appeal-filing
      // window — by the time the clock hits, no further appeal can land.
      // Orphan uploads (no content row ever referenced the media_id)
      // are deleted after orphan_upload_ms.
      base_retention_ms: 1814400000,     // 21d — never disputed
      post_adjudication_ms: 604800000,   //  7d — after ADJUDICATION_RESULT, no appeal
      post_appeal_ms: 604800000,         //  7d — after APPEAL_RESULT (terminal)
      orphan_upload_ms: 86400000,        // 24h
    },
    consensus: {
      // Tier-2 — state-determining; all nodes must agree (enforced via genesis_hash).
      // Tier-1 — bft_time_genesis_ms is the BFT-time chain anchor; any change is a new chain.
      // Tier-3 tunables (timing/capacity/retries) are in shared/local-config.js — read from
      // TIP_* env vars with defaults matching the original genesis values, excluded from hash.
      votes_retention_rounds: 5,          // §1 equivocation defense: keep votes_seen rows for this many recent rounds before auto-prune
      max_txs_per_certificate: 500,       // max txs drained from mempool per certificate
      certificate_max_bytes: 1048576,     // 1 MB max certificate size
      participant_inactive_rounds: 4,    // remove participant from active set if no cert in this many rounds
      gc_depth: 500,                     // cert GC: retain this many rounds of certs behind last committed round; older rows pruned from DAG + in-memory waiters. At 2s rounds = ~17 min of history, enough for consensus parent refs, cert waiter, and brief-offline recovery (anti-entropy covers longer gaps). Reference Narwhal uses 50-500 depending on committee size.
      bft_time_genesis_ms: GENESIS_TIMESTAMP, // BFT-time floor for round 1. Round 1 has no prev_cert.timestamp, so its cert.timestamp must be >= bft_time_genesis_ms. One source of truth for the network's launch anchor. Frozen at genesis (part of genesis hash); never change post-launch.
      // ─── #75 Rotation-period model ──────────────────────────────────────
      // Committee changes only at rotation boundaries — every node hits the
      // boundary at the same `consensus_index` (Bullshark anchor count),
      // which is bit-identical across all nodes. At each boundary, every
      // node deterministically computes the next rotation's committee from
      // the `rotation_participation` counter table (incremented on every
      // anchor commit). Within a rotation period, getActiveCommittee is a
      // pure lookup against committee_history — no per-round divergent
      // computation. Replaces the pre-#75 cert-history span check, which
      // could not stay deterministic under per-node cert GC timing (#74).
      committee_rotation_interval_commits: 100,        // rotation period length in anchor commits (consensus_index). Testnet: 100 anchors ≈ 200 rounds ≈ 3 min at 2s rounds. Production override: 43200 ≈ 24h. Deterministic boundary at consensus_index % this == 0. Smaller = faster admission, more rotation churn; larger = longer admission delay, less churn.
      committee_rotation_participation_pct_of_interval: 70,  // committee admission threshold for next rotation: a node qualifies when its rotation_participation count (raw anchor-walk credits — NOT a fraction of total participation) reaches `ceil(INTERVAL * pct/100)`. With INTERVAL=100 and pct=70 the threshold is `>= 70 credits`, easy to clear since each anchor walk yields several credits per active node. Genesis members are exempt — always in committee while registered+active. Old key `committee_rotation_min_participation_pct` is still read for backward compat.
    },
    network: {
      chain_id: "tip-mainnet-v2",
      handshake_protocol: "/tip/handshake/1.0.0",
      snapshot_protocol: "/tip/state-snapshot/1.0.0",
      sync_status_protocol: "/tip/sync-status/1.0.0",
      peer_announce_protocol: "/tip/peer-announce/1.0.0",
      snapshot_length_prefix_bytes: 4,
      snapshot_max_frame_bytes: 16777216,   // 16 MB per frame — hard cap against hostile peers
      score_cache_ttl_seconds: 21600,
      revocation_cascade_days: 90,
      warrant_canary_max_days: 90,
      canary_advisory_window_days: 30,
      origin_grace_period_hours: 24,
    },
  },

  origin_categories: {
    OH: { label: "Original Human", color_hint: "blue" },
    AA: { label: "AI-Assisted", color_hint: "purple" },
    AG: { label: "AI-Generated", color_hint: "amber" },
    MX: { label: "Mixed / Composite", color_hint: "gray" },
  },

  founding_vp: {
    vp_id: "tip://vp/US-0794ae15e9db4b90",
    name: "The AI Lab Intelligence Unobscured, Inc.",
    short_name: "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction: "US",
    url: "https://theailab.org",
    email: "trust@theailab.org",
    registered_at: GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key: "c57681e0e6b0935e0cb9fbc8f289dd2a56df150e8c51d44ca3e8798cdf1bc4d29f57c6907f8b8ca0555eea3cf430ca5962589d10166f942d2c9170bbae0cf036d01cb83c2e5eeca76ae567aadf3c7b046b98a4aa0047edcb3bbef40742b7137611ebe44a4da33628496c07244a63a1ece8f816843cbc68eab131be1148ef5e05f1fe57d283468b4887d06add68b3a04ccaf13d175f044361ef401e1382e3633a39aa2cb58b4de40b35b4dcb43bdc8a47afc55ad4881e72dbaeaf31b95ef928cdb042a49eed447a16d50af2c7fbd7b29c5266db639eda3e8a8d54247d3b18e37f0dd35b4cb53ea045f5084e8d114e2c925570f648d11a98dd6faee7f156d232fe65b47bb21d7e64882f3f4824d3aec937d3f7ee70eca863786f6922df5ac6770834aa632d05071e003482de2ded5e4cb9f096062df2acee9c92208525920b26229d98300cfa21947b0e749f04115f309491d315ecf5f09003f08fc78b2136b602a30e05819e09d64e8d12a9319f4780e079374cb11fb18f9a9958924f301ff13b78bdb7ba333e8d43e92711142a27f65bd9f77ad189e4a328581fea15e59e5fa17b053a3aa932668cef9915af2c5c99c98681863a160a96a3ce02e3b28c98cc8a34262c130eb341f7794d5745c8b642850d4e4ca7d09653b05206917d7759b5bf78bbaa9a911a5cbd97a3158525796d69611636109598c40074a64a015e8d9ec861ade8743c7d61599520719d3af3904d36d3df5fccd763ce784da0d4e01b0a2357d86f7c0a4f57edb34320ab4dd94d34082ad8925696cc7db923ea6cd0bd7228ef8bde9c6eccaee24961f3b979a20747f14762f6eb4287fad9a0d8d91622139a63ddb82922c3a910ac1d7f8ac93d92d80be4e9956dceeb5947d1b7220e68a3868a89517d8bb8e9a39a006e4d781795c6147ed8e63ff518f1706b57fed4de0bc030fe28adbe1a66536b074fed18d811ad9cd61e84b429ef059a9cfe29f0debbcd64e39b364d300a90d4d64e0808f33964e50609dffe2f04aae5f18588b34c247c0e8471a9e5d4552086ce9a13814cf1576a111126fd5822860aa9cba33484f026432c1cd8dbc824b72589d109873c845ad66d0fb2f13f1b280c16d97d481e5daad0d5c828ffbce6b1421accaabef37e54d343b50a8e7b0ba60c53773b9598eb7479549a399a40ffcc6b0f03346fade40a4237df9db00e4d13b5fe974c4b8eb5d37b3d6e65226ee874753c280a37013ed60307abc933b83a9764afbf0b4c6a448334d7a826c39c863ce25185e36d5f0a6c099b9c2488da1486402286a4e78faa737f6a85bc0778d54ff39a62cc41e3ae89c3a31fe87820e270faed552111cd606cab3375a1adcb2b4102c63e5b215741afa806fa45b8b8d209f2d8d1e32b6c96089de8fea0bbcf769f7fc2326875cc3667e3c67f56def6e7c6429c89280fbc5fdeb0f910dc52d8e932c31e39d1167a8e406024226df239a20e2ac08397568084b2f6e28d14cdf65695d08443603c10ec411cc36889a8b7c441ae0f29be3b42a327064185a33cea01b1fac2897a7053e081095306e5314b9fff821dab8d702b65d91397744183280498cedcfdb3c48aa5a8a5bb1f32d747660f8911329a9edaeefa7fb1e81a2379611f31eac77bfb198d3be9ce28dfcfad50ac420d48d1cdd52352f30face435f0dcd362b938f91971f0eff2498d390e6e757f7d3bfcaea130c6a25b2bbd1ebd4af79e4811cbf60e50b45264f2b3abea61828b7d0ea90efb18f31fb480bec689ea860fb5b094b52ea10486343ccce3b4c213d7d2f7a5acc2b053aa7cc87ed098f90c9bdd990c98b26369b2a47ea3f7a88541e1780496abce3a67c2c44f05a90414273f23865e7b7d90e7dc5061b062c80d9eded2927bffb9c1d2499118219ae184b7d4ae67b18dbaf3ee7f73784dc0572ffc9397eb67ce572e85e1a3e5c99efdd8070576fdfe714b0e3bec8c8328a62c1e85ff2e25f3848ac667f8faa301051aea0ed42259b46f17dda0a8bd397948cff0990daeae73a88de644b51a65b47fbd2fff5ca738ab561bb59395773604f2b47011cc6e64de7ff7064978fba9e3387e113b0dedc1ff194878e1bf12cecc5982ab8bb535f1e07dc2cbe8d37ed66df7d39c0b9c963d582a008c7f9aba8db3a8372aeb470ed728f67eff4400177e62bdfc70a9ed01ec7a3d89eb075969edb5d0fdc2f2ea0d69df02635dc8169a701cd7f8f278a7cf7530bcc2ff99d5a1d50c53da34c9afb795ff61e63d8154b0cee1e766dbec9b83e4a02ccff4f4c36d45dd0aa92fb7568b6522e2a2677c20aa2e9aa4382e48c3726ecc1532d05120be1716044ea30c6396e906f0a0138f7684d00eeb36f45bbd1588ec145ba449ee23327246f18415174f6a47f53c880cfa26a57f89f847eae9c8508f1edaaf8887aad6125c85e2e091ecc509e0b9149f490cf1be58609c5f17ef0d087c499d68b30164e415ea1c6c0aa36e1e210231e91ce276b7038b90e91d127dc2fbdc192c00d02f3234535c548d0cc348f14336c104679dbfe5fe0aed37657af8912f0c2052b145a641924430007cba89e00c7d62fd34c473990af7ad04c59694726eb5c91d33920cba00bc4f0ad0897841963517569ef0eb48e7b5b2f53bd7b19155752e4e15ce49118eaf2a759b686f4da00118d863c9583ac88473f54262bb7ba86a3fecdf4dbeba444a4d0451ac98ddaa44f5382ec37c91f8ebf1fa8332d19ec0d47e320bd55f45e0898e0d8510382574206e6a",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  // Founding node — registered by seed script, bootstrapped by initDAG.
  // { node_id, name, public_key, council_signature }
  founding_node: {"node_id":"tip://node/725edc5831b1c6d1","name":"The AI Lab TIP Node","public_key":"eb782fea3deb253f937edbe43c0f0df44e232be20d748aa06af87390cc5cf4ee144c4415b5e631c02c2da47138005537deb8ff7e561dc49f3abcd4188345acba3781d1fd7ae2e9fa5d749b0ad11bf11725cbbb1629f3031f740eb2173a60782e5166e998edcb16d70ca20501adfa309007eacdf22c49ec4135dd849230de39c16f0b4138048087ab2b7c0709f9c9c9be7a98b97adbf2b4de26300015c3e9d2811946a31a9a968865235f41001d8dda400565a20948628b8118f30849672c2602b1f94c0e623dfb5ca16776215326e7695a038cc8110ae5bda2a1c1e4b195f777b368131db525968e032fb9b03e2be879f341a4182f628293bd30022f1d8caae49ecf31eb4a4b1ca579093088ebcd682c98ebbfbe86c609ef61b38b4daf5fe68583a83291fa3a741810ec3bf8e0fe9e6761786e40f9055b511349c9f511a8800fc0d16d8ff197825b20569dbe00996f1aa4c099179fef4672a013847f3eaffb7b68c70c1bf0a7c34b0b04e0a9680c926e71a1c83217580b29db05c4d17db772677403c0b532e27983059114b3012c1d271419dd8f27dd71f3556b838e47bbc9f9b591b0e7fb46d0267197bd947b94bdb778f899bdf29e9caf72c511d8e5222b6f2593941614d6c6b43978a92d5ef65713903bbc14164f5518c763d7024d6f596449506523f6d7eb3254e3fac1c6f3169f58b524d8951b9ee76bea7753b84df89bc63fe7130521b8f3dd892591e26e303da93a1aa99af71ed6c20604a6dc01ff6a668806b96bd805d486aa986fa08a0387c8f438e099fa0daa38a75900e08b1dd844ee24ff0b1f756b835927a6ff0ebae65003338e97ba5228bd4eaf41a93882311018827ec5d76bf412c4644a434a340763fc7fb4f317244d667d29b3e438fcd84799b2aa291f82c044eb59ce0f9a7ed24a114e42665d5610b924173d48027278df88da49c76b5a0377f08567f0746cf96757aa684e553e28c87f307757d0be1d6638bc7132bb570d8f5f6cae6284e0ee9aad2f6633fd5b706bd96ef7238b7aeac000425fa7fc4cf812becfbeb99431ec17069c6448ebeaef9392d031d011e7492d8fb8969a9960bd346465c1d83d08ce53ca5dad55a2d981f4b1ad608c0892c922460d327954ab014ec61233264fdbc071a3b334269c7c9f95ddf0ee1750427b83b54ff02f5edcc205e74062ac08418dedaaff68748b6afa54f69ee3788ecf54e3fdd187b0854215a1915fa031336b919b48244ef3dccf592253b8ddf2f95d009de8a00ef3947de3ec3b33dda3410b91bf6183ba7732e4a62ca4168ef3d64a1da3e6803dcf1841ab43907dee9c8bba017a946bb931df159a6ebd869ff0b9ee44774079b9e4c8cad21ff4c054434cde8251f0895aa70e7328f2463a0028292b331718fdc7e34b70f7552f724a66dcc5fefe0d00c2ac3e606ff6ebe0b3223ba37cd4ffb9aeabe8b07fd4750c36bf7697e15a01c72f067efbb53ceda5be42dcef8ff5ac6a05ea2bb8a7a5899baa78eba2ead366da3b7c0a9c43aca72c846ebff3992420af516401733698fcdd096c5d929398f15bf0e3f9208c4dbfabe195feb181f7eccf3e4d443ee3c32efcc381e0e954799aff5c1851231cddd6e43e48f7cb1a82953412b64b3ed007cea611d864c063fff582fce4ad471bd30e6d523fca9fe90d5d122a992223eec41f77fce5c5b3e89261c7f4395e6602e4ee03ecb4ccc673223315bd91b7d42171457ee802c4702fb6af06ae8748a8dc6712f4ed7d9aa0cfe4c9aa63c5978cb9dc5f0414b3e66acce85c66739e6c5636a8192ed40aeb49a6f045a465b7a102386c6c6cbc482da7858d9e2364d9b6475877ede79a8829367b1acaf1319d344ec169c54fda21e2da58f6e1d70d1658a1a57d98910f57bb1795404038bf95bd36c02154a4d4b63d71e9ee7a056ead8ffecff7c35503a6ba156b5c539223566bb18309b05936f8264005fe0961a5f53b36eebb869bd8d6aec5688fc98eafd4eecbb9baca7a183b0ab620ac77f6ffbb42c1aa4c05fe11ed0aa2e88c863af2887f7b5ec111ee4a24614fbd900151575a009a7747ac0e5907571c291ded366ca9372ea9f8b7aa7dcbd476c99d4e7cbbd6fbe8c104fe56183df6c930e9ad8566d89f3ef08c90263842d323f7ae79bdea574ce1e86ad9699a2cfd71377a9ec0334a25277ff6d78c3c95b42017a95a328bdced252b764029599211cef3c4dd025ef4ab387b198497ff4a3c2d0f7a66fa8bf26b034e834fde0e5cf188c9d871323906f8602dd398aef4d958b405ddb0aceba445e4768b4c609678aef865e257d9ec3b7e168729d9d0c7031946444d4668c127e3c5f4bb951f13295274f42d9174cf32ed3014d61e8d0ea7c4a2c37f872965ac35c584131a5ec7a7c5fc922642e3dfc109119ef7466c96f91cfb792d7b9254fe5442e05f060bf47aeddaa455427911bc6e42c1562e39a844b5cea29fdd9fd8b2896778eb11cabfbb2741492b99d8c5c18c290e1d4cf5fa7f38f6b78c15f588dda55bbdc6f41f5b470fe0ba536a036144dfe12105837aab7197fa1afc64f205c89c5e51caf701434e800677ad1c505293756032298abd513cb101c7dfc876e5628077f9d5cb9330a8e2c362c1a6ee2e6f85411d387873dee224db5b70765c8bf7f60b300a28bb852ac3e3b585b288324a50803a0345f3c87d2ffd591df0c9e1977f7cda8f8e35b2e91fb4a2b13bb8ffbd7f334210fd089312fc13158911ab9288a7ab7f65b8478e6c8e348f","council_signature":"7bdd3d965f4b83b47dae72b5a911718b36c8543c1fde152117a77298347baf87d756602fe9f6b2507f2d95fd9bd4b1c8779a1726601f70b14794e0c569850456124acd4749061c840a47da62542d8cfbf78986bd125f32ebad4b1de7d93005a126a54820d43f7490cf11a3df05dfc52004b18a481b108916220f1bf6cc8057c469243d74e4de9eeb34ed2d1959b0ae426964cea4f007ade89cd268270efaed03b1f431713cca9202d7fe55841257c51c1fbf6ac1f5228baecdc4a5bbc055637d42e41e0275e5ff3a4bb3bff722cabc3920167438f1291091a2921db88c590b8273fddc70bd0331d2fc9ccd61f1654a04ffbf575cad0d1d57937f7670680c9f2d50c9594b67acf77454c09512727f0fa041b75111cdebaae33fbd0c4b4eaedf2bc70eae57816581f7bcb59d8d6d40bb2a32a3e44eeb29661d2e62c348fbf05d0cdf9b69a23d330ef0ac4e241c2260e3e46f0719a3782f2fe4ad14df00e65b9d7f5764401ebb48a64f75581178c36d9c6d6707453487de11fd32b7497c2ad84eb318f03e2338f40eef51941fc39a5fbb50cbe9b4cd63120211c0c1a40882ff93e7779c166d00831ffead6283f80b735524e70aa87539ca49c3f4a87aaff1f37f274dff53b110903d8c825bae645fa0550a9d95ce7d27cb8e8afc3e5c73c08807b1e8dea2e5d95b0587936e6daa26cb13fb3a4abca05116e26efabb8dedf1b2fbbf0289ac123de94a489d1aad2b81905c90c643f46daf69df443d95c5c3e57decc6365965facb245b1db7d6165ee6adc7001111c8b27e3c6c2ec9e234a2471f9d9985334c152fcf6c0e8c565823d1cb203c9c71c1415ea3dbdbdf0d1d27cc2b9b6a52afe23845748086b61514f82ac187ba1a8d89822bb419b98fbc9e05a8c2a42287d75b4f8ef3e17e0e3127ea250da3b5460c7c5f681b08bd9dc71b0c8104ddef53759d6e7983b8a801619a3827988590828ec8afa7b9b0afecd978312a72d0469b94515aca10f48c7414976b6047f36b29b955645cdd7c707c66d297e32bed67499f8bec1acc546a8da77b8eed8d6d9a6966cd0b65ac6516aff1a25c825646c2b141aa5cc65dcee1d838a120f64de223fb27c4ae48f6d8e95224da01ac579aa3dab9c16061cdd333e845d2b916e5a1fe2d4eb9951707fd1d611248045b20f35a0fe228f3b5497a08af18df384a0256ec6e4df9eddf993eee74ada358a3b754876a1c6108ce8d1e218a194a6cd994f29dcdf5623c2a344b1481eadf3f7e3f1814e2e372d4af9df2a6f97f0c8266b806ea4b81df299baa2015dc4f5ce42f3f70827018634e5bcc8b1f5ad18b6d82ead6f3458bf7e37492a7327f3b7582874fb3fd3a7f35eb4d033e675dabf0b8df008490964f5c0d6db7351deaf6c6ee914d11530abacfa6336f302e8bbf0a22c38d26bcde6c28f01ccbe29d8e304cf139034ea056d8fc4823446d5886960395c06b6d7fa942c42f5d084d9df60d03a87577ac429f00ed31caa2cf214ba9e3ce3bf73a509b68022ad812526b7a827c5a6f7b08bb36f3438155072a703ef8661a53bcdda70504255d4f2782c76022f9b42d2688ff80bf5a668ff737f864801e09ac867cc105ab2175c0f8e027c60d4c4991de0db54e77461048d1c7722b5fa3ac7f35a6eefc97df1b3855fe59166dee727d7b46f55a3a4539f20654528b4c15314e3c16a8d32deb5a158ff26d8d2e73f1198b9b42595866800632cbdf49cd746b00869e980b3cf2d50d3944faddb22702f552c5f1117d3d9027c92768e0297b66e7f0bac51ffc0b940bb76f0f8edb4581df99e934b97dcd5559cd5fc6254da36fc7b46d7895222ecd81d33a5d4f3b0ca1a85499ea1864d09b95bc13ad5564758028e37fc7f21e3c086e90d018d5bc9cc191b56726443be07e2755f59181f0bfa1fa99e8a616d0ce14869a62d87719aeb5174d6b486f53da1a7617a96eb021540440ee0607f7ff36f2a7f81e3cd5a9f7bb3e5f9af3fc7da19b27664861802b73c4ac268cd41d3a32c8749cd58e628495b3ce17cd4598acc21bb3c0e29ffcc49877e6e40375f8be43d032669d10be233d0ee2681632c31cb6aeb5a8c321dc5d8273d25ed2e2d86ca3c00672256b24fe9b573a8ffc0d83bdf4de5bb6ee547ee89736a8b897a1edd7cafc124b32379259621d7e078caf24938e058562f3e2db8188d890aee3f630df59ef1771e879c7d0064e1e3b77c92d9a4fec7c26a974c222e96ed454cefedc3aa5ba28992a767fcfb9c3b00c2764bc3ab15a45a695c8b94ee87eb844e100705e5b0c36811c8cc1cfce96ef8e2c4386d427d54c04d5a02a49c5f9e4bb04cde1d80b02914bdbf0f890110c431ce2ece00a28fc6c0916e3aac2d5db5dacf764e3f6097ce73b82fa4107463e29512d86982317b29fa31ee1181b6597d57b7d9285f46629273b378204df287dcc2695a5d075a6ed75b9fa84b1c4eead4895f707b7c3d2e175eddf9874ffefa72535107f630a79af81df75bd01d24088a82e4fdbaa0f66bab39c78691a5ab7f75e12e23361031b2ffaf147ce48f699fe6f947a561e26576a11f4fe467b64f5ed7a071c813b812ab94ec52422a0113fc8fb41547773f3b30baf7692d4ebd96885646e6f085e8aead3e64f5ec392fb1d1863d292646ce3b9044ce5ecc2731b5343aefc0df86039cce570dd26432362348e5ca59b9f69e9ebd186efa781629b6a5d08a5f78028beccb16854d29e578d2991a6c5a739946b2733348d3af4f1f9433d9360de67a443f4e9f7917ef8112cc2c3d76401da1c3851ab55b880b1c55032aa08d8951ed7359113018d668699b0ed10720be13d1944aacefa86bc64d85a51fb31bd01aaa77010834a71db2de59020d1d11f9476a5dd7c0fd43cd44d6408d23d010ef30b3c1c46904eaccbf180e3aae2589af2550bee8348d98fbdb3710f9211a1ee642bc73c19d31ebbe7fd96bfe96113e405bcc174c7ae45a180763bf8c198bd45d315ae2fb32c572c54ceeed476ef91d6bd31d8dd630f62d6c59e0ffbb499fe2aa281451304967e454cb1e89fb085b7861fb9ede1159a22f05afac138fb2054c2c2f9167a85ac4ee2698c9edd68902d6b9caf64d3379d09b3f3d9c5b7edb4f7caae2a7a2d9e08d8cc659cec74a2938d3389727e9e57dd144f820bf5e8f54984ebb38264fca46c6af9b1aceb7ec3fb868fccf4e0c2b373d03f21141707836c5950da875712d1628e4c6df6680287e7304d3d2b72953f170c07b8c766c66f5ff0a3a0cc60e41b0f4e90df3465b211b2a2e6b52cb4be54da951250fc34dd715ae56bce6cae75656f41c97cb176d60393438744225a6f5585bf3bb496e95254db89414d6ba56d47e95fc1997a2c427cfd18dd3f380f2974e6629c7e62802e58e7ed391978fb184921af2fc7dc5b730e9069e52dbdc10f3c383ed44b174c0fe011210d5d6f088d58f2a0cb72ff16e52f523eaabc903e7eb2bc01c7f47284401dea6121a132212f762d575cc6be1bcdab590d0fa646cfa44f95c5486e026ef075ca364a873f7610ecdc0deaf105252e9b04ba10fd44b4b1e2fab07bc779ec4adbc64b90645b88f15ea5a6cf84ef906b568854b37c55ddbd4928ba9666cfc6e9823e99ff50056930bfd17d278c2f13b921b5a45cc986cb1169595295cb67936a42a51d44d57bec0356bb7ff41f2ca5cda4b1e68426360beda283117d6dae92ab9993f59038a7649fbb419eb75dac05d59a383b9d4974c354f24ea673c0f7727b6a389da43268cceb23fb94bf2122396d3fa9f9448647aa7fd67cdf5f3329f4671cfc205ac4988875855e60af7166625df4af8a63a6a616717f81f545ef2b7a129666dd31e7575e4f574ed31e2b8d482520a07d32850070d44d856baed9b1bd82bef4089968c2a063af37f50f0a77e25fd42535bad235c71be4bf67b526a91daff2fd7329d90f8ce8a33c0d3ad01d2c08d4ebe277ff8c3926904c438ee2499d9234827cef3b05dbe359b2a55a40a38c3cec6499284bbe2d931ed99900e0c31e9b72b982ac7d1683a7b7ba7f4f9fd27f9206c10618eed6566b75b402a8df20865032c096d3355958d1d51e54c62b242a0754ddf8c55eb3220bd1e7dea448a22152a4790d7c69ea4277b41c82a62b6c8ffbdf00862973acf5966215f533125186a26aeea0f472daecc023fa57b92311c6e063975719b78616264943902e052ac35f717f43be9a6668e057b71876362d46e56192ea0a56e56c8591e69c7e9417f19c34e24d16ee97f2dfb5c154895e8c92c34e01a40774982026ba4709db1774f685f8abe89cdc87a75821b0adaeab8fe26a662fd9223ff3468c012fb579d0e2960144546d11a5fb4c4e92c35ce9e0f6b49db84c2beb5cced9527ce716bf739c3a18303ec6a375625770ca7db3db407ead877374d2520cc3585d115e230050707d534a1478f0b08f5338c7071fba04c1a17468966fa5c4baf90c239399159beba2c60c9351f804dd8015c5b5c665d60d5a168610bac99139ff993cc7aef557b2923e845517e1c0613a15096e8a7fda52a45234720d38b247f2e2e699044dee1afdb989e2e0b19d7247369a52f57110bb46a56d099fcfde19646b9bc2020a3e72a5b1e9ef64727587bbe9417096b0b2d8467fe6eef708134e526585ff00000000000000000000000000000000000000040c12181d24","approving_vp_id":"tip://vp/US-0794ae15e9db4b90"}, // embedded by seed script

  // Genesis Ring — founding verified members
  // TIP-IDs, public keys, and VP signatures are embedded by the seed script.
  // initDAG uses this data to reconstruct identical identity txs on every node.
  genesis_ring: ["tip://id/US-21317046a96925ce","tip://id/US-07e28ab8db109f41","tip://id/US-e91cd1ef52ff6a44","tip://id/US-4f1e6145e0eba699"],
  genesis_ring_keys: [{"tip_id":"tip://id/US-21317046a96925ce","region":"US","public_key":"3169236e335eba99b08a8467b3d2a8296a6d29cb33b88ca6b5f33193eec982255bb0d1964980ba252eef9036d491604338105cf94f3873d4e7844dcf1333ef696121e5f3ac1d49e80585b3c56d990bf89fe5beb709ac2e99187ffe5d2a2ca660fe7d4bf88e0bb5760d2158776ad4eebf9c21c3ea1f3aa8c5e4d199e8634698c702dab63202e235d9a53db95720b69868b5145978b2fd748671d914afc36ff19d8810eeee90e38c5921d1ea8e5f4b5abef3258e9e670087341c7be2608847876b56411f1a254e35b7377a3e6be6cb32f1c5beb3fc96aa058c357fa13f963f299979b308b2034e1ca9cc88b5915e37058cfd02f8d40c57c8db002bc045296fbb469084953944eaf45d4fe8dc621aa85ecdba5dce6e71533878495ca066ada3f92e363a70eea238050a2bd8b704335343695b7df7ca2fa3c62261cc568271a00e13236a9d08b7e38736d4f986452ea2606d97beb60e0bf1381729236a69cdc9070a1110486be7128f8855b5db9afebddef705e75b2bcf2c4eeb04bc714b08f0d09f988b22b457edc09b4df466164c49138f9eaa7cac204b47a46012a38bbabc4a70ac63558859030c86fee77ab53fb23740630a3531d88a521cac0ed5d6157d8158d0b523a593e26f0e42839490bce4c56b8b8dbf363f4e38c2d9f150d0f2d8fcead79d9065409a46cb832d7ac4e937087c4d3e7cf83726e7d4ef75f07d44560f8702da7cbc64b4f187d020d4938f7ce92ea529ba0a7e624fa7b0ac30b1e2ec90645d8e9164337af65148fd31f320108c5edbadd5912b210fe36c1fecf275065134648118773debb6337e7f3521de991262679f1688a8569b4ef46b4a839a3b0524db44d1b821d843f936cb4864e40f5d4056ac320692bb1ed4cf233bc67f78f391409727bafc5df1bc566961c35f6317fed0d4c5ca854acb8d710ceec2f40409c9ae4d438e11fdd749b612fec517cba9052f2e9c999d751e4bab7605c971ad338764e860483af1e8183ce8e301711ff11fb094334c480db0220d8c927e7a0288f4530b91643266bd7b899166b8b7939fd21c4eeb53bbd608dc5cb1e2dac052cbd542ee628ef1c6af5b95e45b38fc91ba53b87641b743e150a3ba82ac9394d91cd5a5f42ce723245a8b2ed0546c0dbc7e96b5146576ba3f96b9f9293f71bf3ea6dbfb2802f0728861cf6f6862aa6b1cf9ee5b48c3cdb5426fe17b5c6362baee83b56aac2f23721a9e5740d903326548bd8c6fd1d95214698401d5dbf3dfaf8ecaf7298f140b6c27be27b612888600c4f12ff06fb493f4819079350633e1120c73b9af915fdc23e67e419af66ac800b8f5aba52aa4f2ea068a89450a90133f1e596d2033fe0a43185a7acd06591c0c795012cffc689c9b89d88ea87e827507d7b6826d9ba77991b055a0f4685890237d0ad78edfed90aa76b1a618ee8d7b30074f374c9e746529366d55b4c758300103765d86c6dddd84db83bd41975acca95ec0a60562b6268e42a5b22034ba8436f327db77fc63f8880f4ca626c8fcaca3739743a9acd6a91d936eac1037f92233b27e41ae92c72875c204fec83fd7132f99ff5b3e974275e3eb1a928c0d156e829fd74859e951b3909aa6864fa0c96a52241f51efdd1b16e7dd976d8fc071e6385f7ff49dd22be0d1bc01accb603d63fe0e6286e272d3ac575147c403f68cec12b2280ee9800efbd4b02d6465989e734e90d1f0896bc6273e3c7b5fcb54b23ad0d27f4160690e923bba2d3e6a008ab1f66a645bbf6719b2bbb0a8ac37e86a924bbe37ffa7d116f810bc853ef829cb4bbdeeec45e9004c379cb5b54d490991029b39e57221e7140f2ad7e24930fe6553c1db38f6651ab44b594048a4af7efaa46de56324a883a5b08f1820d2bc73b346f7ae4d279bf52b01da23eeac38181b175b729dd5efb5d54e420b5e5bcb53903dcd2d7c502ecff70d5751a74cc7591d5dd53ea67137bb239fee7753a87fe77730de6200c6a940a06ec54870d04b8f35edf1e4b930e9d760e4a489de559eb76111d8a2638abe37dc818c2c301685167c6769820e2266d3bcceec3714568b4720d658a24252aa3d70fb94cb8dc3b373eb230e447d249bce80bf20210b5661d3b4a977d9262a7a0beebc83dee627bf45b4a8d7fb763b144cb65f73de8aa506d22575071ffdaeb373f9bd7e4cd91f7caacc2864a9d1b302973f227cf54d99785a8f24283279ccb37b374dce666fbcc70585699d30882f12f6692deed508ab22810b422a5648c9cb8ef78153fff3111eb67c9fb65290d2e13458883bbec22739fd141052d7185a3d9bf88e70f58ecdd3f8dfb9ed415ff6260bcdfea55280f29704fdd15878ba5af8133bfac3222593ebc08be6a4e1ecfac203c54b228c3ad6f87f5f7aeefd9f06a17801860ac6644e28ef7ea41175be07c73cb0fd15e84f8b15823d92b9bf444a77beed220363bdff35ec24714638503e1f60bfc56c675081a8a1ff9e1adc44afedbbbd60a8df8e40b72bee159e9a9d0d6be066a00ce03e88ad129d752abf4b948192c4041a48c2737a5b4afffd3713424d2769e65cb28de30e03e0f905adfcdf103566082fc57a48c83de5c41f2982050ac2304787db5e907a28e9ab5f1fb282e8d9d54e510252516a369f0636bb68e4ec5b54991ca0fa77f45d1d7542f6ee36474f2e7fe6c324da9ebbf046feb85c3d17f66e2afe939e9ade08d6cffdfcfad6b050d8b8b45ca8e60431be0ca5b8ba3d596e11eb6816da8fe6d9f82f3560dbf7","dedup_hash":"92661839774354454942","tip_id_type":"organization","creator_name":"The AI Lab Intelligence Unobscured, Inc.","vp_signature":"dd606724ec0b20fc5d23d9fa11d7af30201d33284d58240b74bf9e8bde485263264a9e08653052214d73c5ae8df1d68e594d8db010b8a05ee6eded4f5175edc9a1432c052bda61e58749135915427fb1414e78d688cbd109900e86b2f84de04b92d7d5adbd8a65e05f502ef83b908adf7f4127beb76c9e4cb165302b8e2b83d79c3815e78524a4e0289ac95ce199412b17191ec1415eef171f6452a24f5ab07b6e2750d3ff4d6110bf376f32aa16b27c4f6064b0e2769fee869b9967830ea80aabe4cc69cbd7221e847c78c136fb7e82b38fb56be3afb314c45093d8b32f14896b7b1cfeadc9d667f24cb946a5566761454442883f79f83bd4b039aee9d730cc9afab922e30b4c4559351c08b80c875e96f2d9adb7cfd83e6a543b278493a560d2fb69c5e4a492e0ff221dfa6aeb207588f3f0e077c628703008fcf1df727203f57cde7caaf67fdabc73f79102de03ff427edddad22ad65bb6ae72354039e5dd0ebc5e862ae0a5dc548308324a4a4a34a7810bcf50c1f63f91fd3dd2039b5a8dc60a05de342921a5e2ee41e0d61a43943ef0ae41c7a19fcd079c90a74d34a9652659d622a40ccd021b4e006f4ac6eddb9212bc4ee139af8874d7a0cdf8b5c7012435c21fbc8a9a08ed01d7203e47e266987a7bf0dfcaef22db658f05cac35f53836916c1b401297593ada7759021c378af110246c4c20a8f1065f743071a5af05397492940f2e8fe505a37af78d0f25bd153c8e7861a32dc439bace2f08f8aeaca5910a4a5128dc5b273e639b1f50f56d14b541c0450e00dc97da00798aecaca67158cf1d742ff4e321ad06fd7b0d98472db771a47be6186bfed32c9df1cc3c72d359b89ea8e9d5aaf47635c9351ed9f5434e28afd1eaa84dd026e7ce53816a8b4bfd54b7facdfe934139b7d6c4f716f199e7d1368cec61e1a48df1e76dcd437603047ae2a9551859a4bd675d18ed5f8b01ceaa96a83761ca156f653dba70abe52c8bf768539e4c038efc4119c10c0eceb912e2ca723ba2c7b68cff6fe1616ee6e0c9e60a152500d88474bc1607181fbf85b558ba1bc2a14bf9f2c4ca0fdf90c0806c7082031b142739999c5138c3fab1a797b4b2a007a5ad078bb5fb195ee22bf895ab418b83bd5baccc65e3c19a99f916db899d62adde62096eefa5894dbefa49edaea510d707c0c46d69e853c42fea149f4202ae1b1ceb3e81c27d434120a58b16654a678afaabf60bf0927d53dc11215c9f0c9c7e2a5e9593c4867b04d649fc8310be818ad984b7c67f8ab9773bd4e4ec463af23bb8c969efdd5508b0edb06f7a6e276cedeec7e8f17900eb176d98844d1c8697ba10676b4c3a4342f02dcfda0503cb12cddaa4fc78f73ffd86da1e4d25421e9b9ebc8c64fe336e9f67a83ec94a85a539ae85030a70eca06b4a263ae72b777515f13ed38e118774cf1ed710f9dc876e976534852f8eeb3a6cda0fc890fe9bb7a2c91d4b33c5feb47bfe6749a942f80ae53897ac90648e4349fa8b0e16bc85b094cd010c6e0f602c5927a54b7bd5a47d178257a18051c26d173edc3e3232271094778b26180e8ec3a6a4638f9856db0b42fe30f31128669dcc522aa6419d6821ef4f4a5dc6683505d336c5bba5009ad0e46d9f7f0ab2f0a4f72352c5c2952cbd9b55cb5e7eedb9f208e1e87c49e2f6667f056546517e7ccb8dbada9a34e49ff3f589dc27b3aa1dc6297df81c60e2c58d47722b71f56a5dd90b7d2e6a455fbd6aeda21df9ad2822a7f9a777198df1b7e20a69ab72d7a00dda6cd2eaa84c024dd312e9c72650357170dbc6bcf2eaa5407a267034f5be62b4a69cae19827791fb43565116ea0a6954eee394826f9a8c6532245f9fe743df9249480b39c628e6a8fc764d4948d7cc581e5eee65ef3b0a612b65fadc01ee79c0d5e73152344952b3b782e00118020a3ef5a0bcc415017f6d5c87a8a918685bc5cda9f02ff73c7e416aa58993046b73826ee95646ab18de6ad60bf924f0f384c3f4ffc7b1fa03be55820c7c90c2829c5d292e133d87f8f0b36e8084dd70ef6614df1282fb998c9aa87db6a249be78489ef48fbe839795315799246f8642096af2c0dc692a37ce8a84f15cf10ae04f830d684abaa4def56f2c18e89a78d523019e0b15927c5d79354223961abd1a67f8c0931eb01f5789b7c9f0d1ae3217102a59e77554d5b26cb82559fe4bbfc7d65d8f8b17ea4b91d04bd02e4decbfaac1ff6704ef5c3cb21f6930ab65887535f6ae091aa722f38e8425d4f8940dfdd0eb8cf00c8471c80637099385751fce4e9f952a3ee67473179d9be2ccdbfc9817ac5b949c03d91f8c9e77119d6ca17fedb6dbbcd58380c0f3edd57eb87a50021327ae9cdeb3e3c77d0d46afc0c5efedd1f0a7dd8542d9eaa050e2acf36b3d6c469dfc24c05a6d9f1e385fb278ff06799873acc08f6c243c4226190e73326ac921fd676bbfbe8f0ef568f7b204fffdc3c2f2befc5af347870b19486c343bffe0401c7fe47cee451e2dfb6aaf3052f3655d33992d2329f52d66207e0e1b36f9bb945c384b17b96dda8d611ab1e6e78835abbb6a7fba6a9ab4ffc646d5b15176af01d908f6f67578846e4ec41e63b24fb0778287935d69708df3de2418fd9de8703dd27bb0b1f9249301361070faf46bdf0dcecc20a75c6e0a4526ba05740fe5d127ee8e8d005700ff8f339ec541f28fe1e245f1f1f7dc77a4dc582346b693710fb96ff74bc9af12b06ea754c10ee0456ce6360aed687f09bdeea018f432412feec6f504b9aacd7a785cec1006507f6e5b634deb4db9f0a8c55b309886356622f6c71dcd96c25c5e5850e035f7ea247c35226c1b0ce90f2fec283da4b21063a4e3c072babe00704cd8e9265a827222c570353c1cb4f570fab903ab05088c74df0cedb9bafcdc1cf4ece7a27370446a408cdeac4659587a7b6614e891a5961685c0994c0325d5e7f6e7308f29b4f9f0a5bb307d637a7aa6c95a585cb342e2c7f1f5294089e8a5f00efa36312e5ccd0a52e8988591d5b20d32904333c3620b834677d40144941b2589481c109ea9d4fd40ac8d77dab865e6b64b87867d46997c6ef903ba4b262a99b767ecbd13d15d3b8ea38a769c10e3b8d5dc8506cc9aab59f3215c560f07a42b7b9eb57d86a11341ff0eb762f358359f9e92760f670ff4d273fa40db4d8e2446a340cf5736a474d25fdd65edb3ebd30693708d70615c9d08841c27590a28a0ca0380a1fc19d311719cee9e6fcf2fe95dc7fac799cc4a314c602dec4806df5fb80494a883c2e01e6b0da263a3b13fbd80ea7103afc87529a59315ce274503788dbdeb71d5ab7f1e695a1f4f5aab18b6215b41806fafd87fb928cec09675400eced37c9089aefb64230fbb863cb5d565914d7c2afb67cb96deb9c35214e45aa19389b610fd229ae930a9a3eca41a9134fb86779fb522ae32455a4182dbaccc5d30cfdc7985bcdb55d99b64649ab83237eac14b55452e2e1701c2fff3994212fd05b1ee9ff3b4cf466f1e9d4efdd3e83ff008d110aeada3970143df28dd997089ca9bef28960f90fe88c6cc34641019b5ce121ef9f0372438ef8bcae93bcd063880afa123efb4308818ff6cb9fc749dcee75c9f416ba3fcee95c6c4fa95fd78f348ea436dad081cdd6cfdbb17ae10e11e3addb438d374e15a89208d600452b643870216da79ab47753618d10e3931512f37ea8c3e765838d54bcff4a0ef073086b411717b933f487d6d5cbb1360f5b5efc7d2318e23129e68246d54a253adaa616618abb2a3eaa36d0a5013adb16871ad77132189edb8f72912ff8166862964c6438830f5a53c87841bfc52566506b21efeaadcd3d9ddea63f26227e6935ca02c3fe7bdab17ebd0538bcac11c9344bbf3350a4f9bf29b6694fcd7f62f50be78d07842f6798a409184f52d60510b831b9e37102075c39f92b020c6029297334f61b7a016ca60715db68e810d8ef2c54fd910f904dda0c912e610c922d9ebc363a33c6b0dcd869bd9800708c26dd902258d2e430139a5bea2d0e0925856beda1522f68f86e4ab861569e8c4be1257e18428ee4b012c59471d4c32aa7f42f0b56f5a85c6119524133185afbb60d8c41811ed5b04129e82af4bd916e521e3b935cabe20c34bb803795e3b3a6de0d4ae15736cc6f302827cf1c45d70f97c643fafab30313391b1cf4764f4876edb00f30b9e060c7b8784e560592b90a6256030fc5b203e842af669f14a9da78c7ca76be353fe07b74a33e889650038e42d26739e7160b4268df36e684e14a6c7a730be78d97405a71d2b80e5baaab2784b83de444756796ff70de2cadcb6a706fba16cabd135c23391b7d32058fa8ac0f39f3fa9a841cf3faae3d934cec7730454284d15f40f5a3a0a9ae210421d42dc608748553be93f626538f057dfe2b2da3879cf0d037be7708514aafaa4e7bb2ec6873c7b62f0ea80a1e185f99bfd80cfde3defdd3abf7d56538f506088ce27cfe6ab174048ff06f317f328af5ecae224afb2fd47b50015791399404707cbf7bc7ba646e49b1fcbc43702b2742c5cd78586b69f567fba61d3d78b1c528b2848caf99709df7e4bf83fe9a5593a4acfbfc16509096add9de193d47496891b3bfd7e8ebf8191d536e9babb2b7c6dded4c689eec2123373d76b4000000000000000000060d1924282e"},{"tip_id":"tip://id/US-07e28ab8db109f41","region":"US","public_key":"03e1efaea58b75a1d7cc3acdd3a96107f230d7b6e80f93fc53c9994ae6a77ad604457036f8057696719e76b0d8df51bb3b621a8f141fd6de94a2ae528a41a30b785503f03aa1018d8f8ac6240ea00b516e182f72397ae991e6cfb5fd0acf561458a6a7ad82ce6baa5eae0b4f2ee19cc4da05df96c322d136926ebc71c23d2233bdf3ae9b5587006c73ceeb79497001d6ce820924741165d3c3ec068f1023df0cf45a67924b568db380a27c99c7b6694be567b8279f42179a3970dc440b83205b427f28b509cb67958e87f9f5ceb7d34a117862389afbf48df60570a201c0cef8022552c51955089772a1ef3c7f55e9d264e7758c0bcd1c79eac9175e4c65dd128b132e7546de2820120854cf2b8f6862011d72c53c06d8bfc11de4f5e06e1b3a209ef5b13f5e2d25df75593b66b26ec8484b5998015df750cba0106bf40f434eb6a50b9289824e5842ed880cd49d83c4e64d2b963c831999b3b46b49d0163af3a37bcfc232655266df8df6d1f2084b266c91b0ec6692861062bc3c758b08c4100f358051c109808f516c50a845c21757d39326ad47391f391044e184288c6ec38a0e64758c4bd28e29e277dbef36a98dec410ffe4f8ad8db10d9e97fd98507070d5170b84e62e8529029dd568d1262d9fb9368cb6998ea837ccbf98d0357ee1dbb1c106da0e71ff94450a8f7721278393800e56696f6a29450e04a55941d0eae093d8176143ee4e1be1306b852cff63a4d8907c93c6306d5479c1e2eb52a6f5276dfee9f54eb0ad1feb19d4ab3a984726469cfec4903e4e6af377ef76c3353abfa20cb510ae401f80328a59284268bbbf02744a3b393c3c01e6ee79f9d66a4fb94105a213fdd1141a1364f7ea6fa71e39d97c2c491d480f2fe3134bd23902c27184655a7384486be193728b186856d9aff62b468d90a610acdfce04c5fe63a2763662429ebf2c51b84773b0a513bdee147d300861d3c152967a464baf90067b5caa6d57ec830cfcd1c2d3bacff0b53cd1d907b8aaa3d1e037a2d9f2a970664957073616029aadb2ebf2a67c42c7a983ec5d8601e303024f456802d7bb536dadaa2158ce6329b1dbe6fd62389fb9aaff525ecedab28e6d293159f45f09eb9d969c93266fe218a878876b90d2f248a0b22124926b929ceb8ba114281f58343a5761241c99a02c5b22a99993f1520356f609b8ff77e35104506a7aa2895f569d5de8820ed6d47fcf1e1553aae54505a3d8d35d857175dc7c33af28553264661a87cae3c69c5238b48c04776b2f4db494e33f82a34857de6ca09f05d64d3d0506e2f76f73ae9d572038adc062486acc7aec16ec6dfbe43f324ae8ef16d424fd20d64290839054c085ceaafa18761e62fd677e4f7a5c05bcd25a92868f0bb52291d8ca45a0da03fee69e5d18be47bab734ff7c920dc5af4c14c148aec3f7f9c205bbeaddd95230adc2fe97b2416312abc1787c2c49dfdf0aae0dcd6ee32504f6c1ba903def36fb7efdcd9ffc74b9f7dc825d5bbab0c2ae0346b522d264f02d515385cd266ddd40ce2ae89719741d827a34d40219efb8d4885522571d1d760fbe874ecc6a6713ddcea22683b96f0bc06313c5f4d30755ffd96b5c835bf655cff88524234bc95f11882a5abb96a9ab6911c804763fa6113da7294e3d5568a96ddfa5752853d4970dc1581042f2ab78ac9551e2dd3acc42aa253dab09358df0f83d055b11bbcdd1d0edd31acd2547246ec8ec15d627a517cf38100f8d61f975ba37723c52d8b648969208e6e3f628eceee5dfec290e08b1041477bf378997560c8d08516c834033e779bc7b99dd0f249aeef2ea5095574810f867762bead513ae829a41ed1338c300a866c01c619a017a0be5f28f8a98b9c2e6d8c7b151435e1b2dc7f349f1208cc05aeaf08907c1e65aa75089187220e8442a0948dcb98d51a6c7049962131e7dcb28a998915d45c01d008d089016af5d3921c7a5d4e52e36d78d96c19a7f994fa68acfffcc68ebf84a3f4f532c073053e9038341c9a9510ffafe11515ab09d805deeac797e4377e6e5d8bcebbef3c50d46f7cfcf3c19c45580a446677f76647e78fc975c3830b8362e0c4c9cd95c781a9a5bfb61e4cd2d794377dec9ea494afb979b94c24940f991bc08a32f6647e205d832e5316a7669217e2ce2b30866ece654a16a0557be815d344778b07a62548f81984b5184e1c14ed7b7c215221bbcdc7cbee8e1f4b9b33d97edeefafa0bce1817e3ae3c7e66f7452799d05c6938ce4c0be1861ee14f8bfd7525b80d52323a33dea007a875e1f4a89fa3add6f88ca0bc7cd58c979a8d7cc8e051fe8c8863d24cc112fa0153d2eca0cab9dc832028778f575a999685e77aaa976f8ac4e0a647ea5cdf0e8bd96c31a6a961b9f211e443226379787e48143c64042d14a87ff620f35d2ca987b4ff20318aa1eff2c4c864b763f98ecd880c2c0997928d47ff17808aa5a950ed30542cf93104e8c6bee4194813e719d3f2e833dd86a985d4e95dd6a10df34c1c5f5d68308380e062eaf8ab37317733d5f52cc230edcc26249f4eded703e0be2ab1a5e0005091335d90b15cd01ec53a0b7314b92ea501c40e520cb53145fe36fa947e59fbc2d071c9b7207deda834331deec63ed65f4097dbf3933e5b0997cef4ec7f4912499cf7ca676d0293d2eac351bcc3f6bd1f91d5130403aa7de8fefc2da80698c393926e7d163e86b736e967a3121d115b59d5f798e5e86a596575efbafe45cc602c54bb1bf","dedup_hash":"23702933538943712392","tip_id_type":"personal","vp_signature":"6e5dba6b754880370ac08b75dc2a5f1c9174e10a0672ebc7f3bc854b157ec6478745ce6d19b43c21e67ca0e969e0763f6a26497e60b90b43a1a8b3f8dbcd894412fbeaefb4feb8ee618ee7b7186116543ccd64a20d718554d4eaa815b1efe483183b88a6042ca57b58d3ad2a3d761e2d6e87fd2852da91beb5859e69678c53d2217081ee8e62fc05cfefa8f7fe6b15e7c0896a8516a5901f7226a4caafa270b8d2fb78a4f367cb4ad1aa85aaf6267891c3ba10aadfb5150cce6b1fccb206263654ab20dc999d4c6343591925d9b4c3ea713a2bcf5034586dc2b72120e02d347d68fa412dde31322a3e5dac301f55b99343ab41165a7fbb703b10ce3a9f92579d5bbd9e1441b5a449215fac0da6c94acd8e94dda11cc66b1b78cca8e80c695b142607508e2c7cf3079795dfd88f2a3652bc0be7fc3df641293e0085447a6f5ecf9058ebf436dd88538c15f201b8420491ed3386e3127ae46a9294db669c364417f1e8444f4401a0a35f119017cdc1db609dedf6b0ea4b42083cd9d7d27e8651ef59aa31d1b863758fecbbe03df3c4b1cc75bcc9f4e74fe7c4de2080d9ca1fbcdc3fd7d546a1a31912f177351b691550d192bb2ae2d0908678736447bcc4f70e3c35f8865da7b509fe2d66d49d265d4fcbed51a5e700975433f2cb3e32ccfcd9829b37766a06c96088e76372dbe7f2db417a05185e4200a18d5227ddefc90118b83e20f4561c38db79ad8e7845cd5f50b8d86f9606e7ab8fdf9c3ec6a9d2e143c519cf7905a96260be36c71c9f6f557924d49de9146c4dd6797a12fef1fd1744e77d4d098e0f4cdcb30c7cb6d924dd3f5de188030a9dd9b346b2b23fe5dd8815c57c351efc2d75af281be46493d8ad388ce7fc2c61e37dd1b87e30ea7dcc0310d6079006624817632eb44342c6fa373532ffb47297801b4ab9ee6190bfaa2eac71993a677e707ed2b1d01ddfa546b7f67c3411e00b568fd50012e82429176026cb24de14828bff092c082b00e25b4034ffe78ef991da6f7b97fae785e25678b3084806ac4bcfadd31da764c9bd687ca6b176c2b5ec6aca9ebfa03c29dfbd3094dccfba485c7875b343624799b842df35eb081cbbdd1a3b1e75c478267f5dca6ebd137a44897b8d9d578236cc1c084ebf46a6b4e662aee476d6b62ae89d51c308630f1f8a66e629a8bc197d4e627f321455df46f46354de0c26f8b2782db88c49d361af463032d4b2cff72c709a00de4a3e8e34adabce58b9969cedd350ba271a8083fd68878abd3e07bacf156e0d648c5f2c096f3d32c54e942b7cf4e8e582e42079eef7c1486654e6755ff89c5b155ab1462313a8a612c6a9e2f22c94b12b609e6e5f9b1ddf8fa89dd9b0201c215a783c1859c705ffc4deb748c91cab15ac747d5f7e2a78e93cbf433ab8e0c751cd379263db30bfb5dc508a9392b3918fb9efb1d93ecf7393c9903d3af08bae8290cebd80d4bf8f059c2036af81d97ee7af3b78385f1ed515e9fe49dfe29a991c83330a584a4d6888e83612a4f022e10aacd668ff4bef41670d157ee8f2cbec6fac5b4dd11822d17a297023c85f93533b168e0b87c4cd4f7aa49c51fdbdfc67de55a64f389b004b6d1fd6c9195fcf9d95328559709d2d89a6575b693629a06dfe2a84533068a780567574d94e70ef19526733e063dcfc722285258c02dd46c203bea4ddf66a07a90428b7a2b106d9379af9bcd09f5d530b01876a9966a252178fee8d07f3132eb04ae451b864574c43a9353cb072ecba7c5ff3b43a08b72cf6370528acfe285024af4ee3e31e57c5690d7078f92279402c4536753bc5075cbebebcc1d9d5b1a5d183677584f1baa58df7c3ac0c1feb055e7b172ed965d198adfe996928b95e75c3aa8a3dcc7a66b430c82b481a13b7a96d496ee5b73d79e6b3fa94e93042817a8931cfe2e110153b21d1f030fe4398f33e8153a12ec3f314a04ad85fbc13fac5c042825e045695ca69cd967bb45974951379cd2196269536e858a4ef1075f398741a766dac6b0dee35eec38912c0ca0509c7ec3a6b3c7c840c67181d13f49ed4d3b9908e5e9a97a2c5ae5bcc90ca7a156c5812ed2ecc8dc8910a583d03dc33164db9fb78a429b6703114ec4cba082a91a93d9aaf5253b3a8757ec25ce3d835a5a1508cfcc4014aac73676ff67bb84f99fa43095c0c948c2890fc256992d16629a561d3cd14122d2b2f1caef87c8a9f744dc81bc7602833902517046c8af8459a09e6c7e3410755ca3f9b2e39ef81f172b8b78afb96fbeac70009681fdef5ca976fa09b16c4e28736251fe5e58bdee6d5c40f5297a48e4c749caf18055b8771798f271f74277f892322aad00c41cd70c6364ec7fab826540bfc278da9cccb3d0f56fd1997848b556a0d87dc4e8bcdaf5858af4d36dce0967cd9ddf51dadc96c01c98725a2c2386e454cf353f30304dc9d299246a5ed5bbf17d8b9dbd696d8b10e6476288f665c5747043f756ceaf59691c259ab756f003584a1df7102062e48bd85f996706f4e670012d65fb74eb3135d0073f6f96f435177f3863b1bc8fcb0432b470336e4873527866cbf5f9b65193abf576621ccdc7769fbefdc582927adb2fe3e914e6d3a39218965cd24d496770a8f6311e2f7b6873e28dd4f1e455c44146dff929f6a8aec5a7e46b98beef5e7ee69361544d84b600e8d471bb14f09d51170b821caa7c90086dac8efc1442311497ad63d4aeb383f58bc77d72e271d81ce850905e99b9841fe890e06c18779a2be9164e7f1164a4d56c10acd7dd7f10d8a006b23c8a19699fd39a25d6b4467a283f043a4d0505aa456455acf42584b3908008debe209b7b2c8b99e03fe0f4ec3c78e142aa086820db544c7e268bd1b082677762940b1772b4dfab0ae2afcd5404b766c5324a024d406ac7f5ea4ca3d66b4b862abd1a13fe544afa8fd81505ad4626f2d6bf375eb011fb8ead088acdfccd469efd66178588b3a3e5d2231ffaaf9e981fa761693fe7573be1066c63d5ada561705d6d3cc314493978203d388e4b83a565fe00fc61d8f5488bff3a8e14717efec84570e828b045422b77c531085efb5f1b4edc32a752095cb5befde20ca729c8ce710d514166b15a34b3b24499d2b5e35cf755b619818a1a101916143af44fa604adee2360785044ed6e45c19e0a5cec46a82f47dc74bbd0c58861c3d283720c0aefb7979b8f325c19284bb643bf114da046fd77c6650301ebf241683048bd6999d0bdff2638ff7bc0e0b39e57c284508cb2c82d0b335aa1a088bf2a872f2ece09323d643615e874d23aa8b0895a6ecd5a9d744dd9653f41d194f5dbe98e0fc6cb45ddec4aae4c11f203bbad01cf6e019b48e535570192e3811be6a8b8db5e3c56fb3adf7de79369c7b97b78aa0b86e5723c16856f85468dedf6720782458ed5c03fecf388d714c72f52bd38cae3754c007035581706d145ef386ed49b3a591b158153a50d73aa35b74c293a4bbb24702aec27f2fd39ff826f18a5c7d725d8d88abc535ed635a0b66882f0f55f4d9fa8593f68019b3159a2e4231d2e078c36f89da67a586f67ef03d39bb35c67fbffbb5028ab58bbe7bb0e3a1f9ded4f7c4d01cf01b8f1c972f1bc95c7a0852fdc8c05cc472747e576d05066ec288148f53d2412b59e53b7a60111084615146d5dc65952a8dba8a74d17a916d0f5f611338450b116a99609da3728714e1cc7d80a9169830bddb4459d2a61f04415c58ca8a1d7575d28dff67b3683b5efa735d83e9aecade676d82ace27e61e5949e6e47d9134e4dcf33758041207c0a8ece1338544b30d828ad49bea136cbff51b1df0de8915fa4fd250aeb4c22e194ee98590838caeddf9057b5132373075aba0798844d5614a34725d1864a7a32d38d54409417efbf7fe374a9c24fc8e59e87f2a5fcfd57a2a4244ab703befb20d43630363706d1be4b9012e6863b47da1a7d1d537583e151d115f1017b77afdea80336154de7412977c2e509ec4c16009725bd6f31d639a7684b5e26f449bf9215a3334b3273706bdc828a983d60be3fa45f2e288dd74cbbd1484cc8decec0b00f7facbd6416b04deb074e9743289c0a550aea91fd48bb6e681503312e937072b6004b81b683dc3ab93a6da8cd257a0c778cebc8c253269b247b093109db5220e0c1427108d8339cb5f4bf80eaa2c83c09d3cc24ca89d7b6896d781ca7ad15a92b5783035a9bf26815d697d268b189d5cba3114662a55fc8c4791d1490c92a0349dc76e5ed925b392e40eff6bf5dbdc5b8da5f19dcbfa25e72fece652145307e09d500ab4b4b19b5fe91cd9a91ea463781abbafe8b0a85059718c2a0573dd4184dc6f58dc0fa9a453e5210a2a99249eac90c83d08ca97945389c039d188ec1fd1e479994348b30b1a49084f44226bfec803f876fdaf808df721c43e9e03f4633b6d8ee3f570f920facc426f3b7729a7034fd33b71ba8dbfe1cdec1dc05577f1cc491ce802f67ca84151f57d5ad14ca32a17dd4ccd14c617b9d550b670f30672b86dd1e054af9424b2ae7d4dddd8d11c37dea7e9e94e323ce0ff9735782485046695163b2f1a280292dbe0964fb90ecb48bcc3e130f184a99b3c0c2ef345879ec2857636a8ac8f980a2bad1f30c22292e39565887f0029c0000000000000000000000000000000000000000080c13182123"},{"tip_id":"tip://id/US-e91cd1ef52ff6a44","region":"US","public_key":"d2df051a7123dc740dba73151fb7bca238774213216224081c6eb7d905ae643a7c2c36eb7331061a5267c6cc5fa250634539c8b5df80cc4386e27c6fb5334b5001d0f8256a22246714b917ed69db0d921ccb3006ab948a82179fd5f36ffc35b06aff95f2fd9c9e3be1c5bc03be15a64a5fbab47f320d950ee462e835c163f0342f52e573e281b4ef8cddfd75f2e2f1df2bf9ec506529a8bb72af43d865a290afc2f5be9ea4ec621f77218331e5ced9bd28364f1d85f0f7a1ffac7c14dd974c3d1e0663d575539e7a67b9feea6b4636ef95bb88427efde67c52407f6985b0fff13cf509fc5156e587fad087310f29c86f4e702dcdfbbadd0a24505b0646951654fd6b5627eaa8ef49702a84f957511be8476ad36a8c26b14ca150207c8b036c7274632c06b306d6913b70c9c0e2fbe0b18b4bc8bec513fc013466e36e206083dd8635530b06fc0697ceac2a61f5290d4dd7230ae0268b1fcb3f238077b7ec2af6a5f838436e00d7d4ed6ed3ae440fa705b3c6506f4e46069b313bcb25b0d51d582a384b109a980ea80d31a701584c0f863ee35bca893777c2b0b135a1ccf5f644d85d697d0e975498e6ea7c9ef78e54fb118932d6b603c43167e4c6dadc063cbfac8c28c4122a51298d0924e3cc8052019bf9e7a81a2ce68c6da013cd1e5ffb0ae093f2d897854fcd2fc40a94b44aafbe8e52f90b99e0365af368bb0625be8889b64f2e222ac6670827eeeafd784b584ebd9c010c1a3433848fa46c3ed01c322bd90512eb16fb6ea345efa234dbeab144a109399616fc7e304e1237f985258cfef7ab49464e43a105266175fe4093502be38b83e23878e85104921b80da39b3fb4ebdc8fa0fbaa68d3e22e18d48f3d9966bd37bb3776059ea421615ca6a3a65ab617c6b419704df0c435567c4760efe02b8883687bf9a9b3a3771aa1008ffdff4057ee404b9bd33decaa8bda5fda7daf0b03334d626d1128e12eaa4ec73512352a95fa8337ab24071395e5e2353391163132bef87d518159096e0d7d70ed808fd3b859498641ca86d1c295aa08acbecc0d896f2ffaf8e52a8d125a89e6bbae0323748e60a709935bb51b63a3cc66f8a87efa82e5c60abb3579d967dbf92afa1a97ba9641b13e12553c11381225a7a125d91386c967076d4cc0802baaf762e10c74e53b91d48eb1c6578115dbd86bf532d09f8561b4d9e73c494da51b6ed0b8e06e1d99d1285158adc7135fc09a2ae4765e3716edeeb434e06bfdf89273b3a425e9939a67c7801f5251756a40b94b6a155c7ac075eebe915e2da361b7ee135231752e06d7c555d73bb0228902f4d0b0340b838510a1a8001915b532bcde9c42e9e01fff062c4457ab18e4bf0fd743c0adcdc3281477e9b28e5d70368b7933285ec0f4ee7c028e959786e1b13116736ffe9731274a074affba9711bbb266516ce113af56b0b9f10ecc34d2f377c462e75c2300d0e6950c5f780783dac1460aa82e5287683c322df88053935f03adce12b337ab06fe767243d802ebf63a73c2d82493c9facea5a04cbbcb031c0851ce0fa3d89e153ba3b4cbe7924732febb62e48d4729b13ca8699dac2196a2a7bdc3b5d5a6b554874d27f6fb70cfd4adc4985ab6a735defe62efd8c677e6e44098fa5aae44ac5fe69bb67fe819687cbd359757410a61535787ffbb12fc343ec96498d51d338e08f558350560a43a89c99960be9e89695729c21148a24f19a8eb75fd413b074a6bbdd53f2d4ef295b0f7349ab0a95bc649a87d6c196f8e4b539b27f6a2e5a209e9b70b2c09a6d1b272cf84c05da3f7db7050f5e870114b7366480889f5100a35b2553e0323f74e7393a7c4d2add007b68e6f76fe2288fbf5b75ffc88c2aa25e72df09a816f9d9ec2f149b3b5f8dc4b34a988c6a9308d25624620b82c3d19969673ae453937536a0bd55342cb3cae3a1ac02bab78fd3fa0ab5c2878babef69404c966b8d2cb4886f1e33b5906a64b5f929e697d919bc8fb8dc36feaf99e678a4041d5f8015bfe2191c626ddf658ed2ad8c96026ab199aaa9033eafc8a0da8979e8028dd13fb3f57e1dcbd0b0d3df218105f6caba6a5b373c6715595824b4e147f8ad811747df4e1f2e0f2863e50c20e662789ca599a9089f3a3972fd1269edff9e631a776bdee46facd11ed8b0316b244d2887de273b19949f75d13a49101314b6d71c1d4f12085b95773834ff36864f0fa4b817c3b6ddc8e3ccae5c03cba104bdaed8d862efa387585e5426ff880afbce262b2830648a0e3704768917b7f5a89372f4d61e6d3e154023d78525f9d12a426a5350f8976046eb113912997781f7a050aecd49f6ddb2d50f074bc47e36f4cfad61eb315d1ce9e264c7641a0becffca03759861e0aad35ec4a6b548c89b23a6bf9463f3b71d0f13172dcbb68cd0460aa4825a54c796cc0ea9a0163abe83020a542136131eac28c3b1ff32139101cbac57d3c0bf56997a1e246390ae6a9e549be6ebef6401d219871ae0ca58994ed6319485aeb4088c8f4377a08f53754c8b823ae0ab496da8cbfb9d406de1411d66639719f9bbfc3fb27c457211146e81afec9d55ce348b3928eea4b4ceb4c38c23644d3aefb225a5ab6c5966cdc8dffd1a67e4013b2e4238bf9851874b0043d7da2532cab6a14fba1415d6b748eeffe022d5743ac4f3b785ad369ea2ed34f5cb081e236417aea01140b760b6d386f0434b18fa490c4e7ff47e110a72b850b7994ef0bdd203cb633ee45fdcd3492ba94e","dedup_hash":"74146165765493969290","tip_id_type":"personal","vp_signature":"6d7a508c434ef61a7c8a3281754b29ecae754fad06ffa7f1e048232af5636d4c7279b7dd6cc9a775b2dd272b38d80ed99b0a8e0c9506bbc6b83c95b99c98700500a12717cd7ea27f7029228cb3ff08e00051411fb17cce7a51f48e367493286853621e5a191452c1d5dbbe5f1ad1d1d4c8dc8673254c32e6f8ac4d1520b0a66e75ec8820bf7e34d34ee159028692abe5c916efcc57ed9fb9d4493c74335f0f82a440972f7adaa90d75919f9d2282b61253cc11d654dfb88ad9a6db77bff59b3ed96371ab07e2cc4047c5bbf714e60e6f06916954352be5c2aeedbf4078889d8a12d53e1b531291105647fc6d9d806875a3b8849bbe65be1a2d270aaa3e86e8817f429f35b0cdb5604f8dffc424ee0f49216f52a1557ffae42b61e825bb6a305843b8bc0b460894c4ae275838286797613ed4c18eec584047ff2df6089b7f23a075d04be93f5e857668f2528a3bec6414473ca809a6328e91d6afb03ca17bdfe70e44bb5f74acba0c499f15c0bf6997ab0414b6003fbfb90948c7b16516b71ea773ba3942f50e30ac3c30799197198c61927f8c7b698bc2a910ae6232bb1561236ea58c5742fdd64a8c63d3c507ad51f237d7cf42016d462cadbba82a597d35adf780aa4850bc4cf3173ec5245333909fa5f22817e0d5641996866e84aecb08a17dd6889f88233cfa0f4e0b0a4863e09e359103354f6b1983dfb0f9d09438f5ed46ee14b84f526be6fb1fb415516c512aee656864c531ee6768faf2c8e11562af31eed89086c34d7a958993b4308c9f39ac018049428f3a11107deb0f289575a99d80ad310846129c28d0aead3c8ef7d962eda2b9d628fc345a298ac2ecff4cd73e33c0d582698b26878eb8c7731a6bb53d388e3914c91f4802fe919d2fb34ec7eb35d04109150af86988dd9632ad1853d2f1fd265cdd37188db523f3766799848d603533e3667b83f29b603d3835c322ad2a2b8b97d350b4984f4705c7933f5c7a3c5926075101e35b24021e40ec7ee4ee09cb90b8360c5e31626646cebcb8000c16861858cd352172c0da73d90de67651dd51139a7ac0e0caa2660e8ac5cd1c5c39c72f6609c74584f894b04ca15c39d19af164962dfdb446805e4a6d554c543384f27ef7356f5fb8afa2e648b0f47b2dc089b93e648ad7b983352a3b207e317ad6f61631d44c1a18b5922bb4d6be94850859fe2f59f1281d2873f0c7d704164d63c273d8d447f835561cadcecbb3692041dc4f97e7f181ca1276af4b9a74c4642d5239f8d916f685ecf0f370c3fdcb37e756e95f7620d12dcc08d4437ae7ce4cc07b3ad6eca4fd084d4e3d221107c9e7faac33137d8c2bd03e5d032365045a0e2c8e0ff99afb5424570fdaba0e8470e0a1fc4de7092cf6d58c786c3dcf252008478cde49d5eeedb1c9b12c2e45051e149af1ca36c46a85a648b265a936a42c74a214b19a81bfdc0f8c5a469cd4acf1bf0b0f2fcee499021c993b016ede62fb42920efcdfbf169f50acce0b7fc74366f7c2f4eaf2f2b0653775447f06e9c7f1845315b65c95464461d3e0f9e126658aecb322d09fa053c8fad6adbdcadbb78126535fdd9394743f95cbfd879cb638975048dfed67b972b805b5b87180f3efaa0b382e881ead75a9e05e3c11ff1b26c462e2eb98a041037c0f09f513d0053e1a5dbc52d32e9ef53e7b7b40ea8093d5ccb8b581213624932f7bf7447b1ce9b1bbe3cdf30a4a837106865212202577dfa32db523bc4ca6e5ea9c4a6d547347c7ba53aab1d2fca82d2d322a87c9cc1f8901c64a50c8981f083c33c6c2bf50136a8f8ab9546a939b02c4771857c3197bd0bb20bf211e5dcd915815e6efbeb37e458fd755feea98948efdc05bc46e8fc3bab65889c015a6400e9ab72c1ac758c5b08da1404b251f5903d0d2e02330329f59d3ccf23ba0474a19170a24e73aef25822cd8539d5eab3f12ae06e2b2858183de4f880fb6e02b8f134cc434bb89c0624dbdd6237063e0ff56cbeea4cc7092e8189e7ed136239bccd8a35c209ee32023591f984b5e44c4be12b7e47f9c2e8b50b9867db8362f3f8ebc5fa7a29683dd8e55d57caeb24e04c7d6ee90d62123648e64929db7e7ad7602d7cdf11b99257e6720fb0917753c3347fac5a1c3164bbefe10527bbba63ce18dd77e9253c8626d3eb9cab3e61ef368be13d371720fac714e6dc807871fc0e72b8a28cd1e493a2099e16f71fe0eab7c336333a9b19988f7474c923578e533c6f5c16df35e9173c805f6e2380d5edf45b3ef402687b0233dd5e746f8db228d1e72568785f5a9e55efbbd2ad7bbabd069214490ce1a1e795d48fe00c36eb570ed1ae5040687723d952e4fdf8fbdb20c2ed23191f41dd12adbc58a27e69df50d93fac12a5d8cd9e36927f6b737943f9601f30508c64369af3b536e6d53b1140c314e94b8d7b216a55778b8a300588293d590a395a4a4ab4f837e7aeb29039da5a21300c30a171f9fb26a47fab0c4c7369b3c7df3e5d402c0fd769275bbf60998c1bf00361f64767c5af7eb59475c74ede30600aa24f8e1ef7c1ae202040f32554a433a1f6bd81aa1cdb038e2a22e6f246cd9b235eabcab4e974d16efe7354ead3e891fdce4f990ceb0a6d158e8ae44170586556342160b72fc33b2b56e16953cdcbd712ed1b8cde3480dd915e03ece72c9fff8cf14f5b601c2e32f64f4b77be1f723ddccdd45f9d837a94bc81adb4a06299cec2c76d30f4d0cd0114860ca4a559c9dbc41082d97f4d58411404ed2c0f0bd39922388eb0cb56b976bba16a0fa5039887ba25714a6deb6a8b48579fa64209c9da2a46a4373ffa868486c08e423d2b43e97127dd2ee16fc17897c80e7486a0a73fb8ad83433e7f32bca39439933b0ccacc045e6cafba7b05691c74e02b094d6854f8934a4752bbf13b151cfcbbd64e027272047f5267ae88334b0b99188bf86c79976cc8899c4b15bb26bca5283461ed2a231e6e774dddc7f9603b1fafa7ee612b0831d409190ed1f5168b2ce8508a663487221877ad9baf8f7569ed3e1ca12ab50de8d75dc413fb3a2df8c91d330ee243895cec555c7bd5d6e8d3c823d1acf7e81a50461ef9155c8f3e3a9eb0277f290cc562b5fbab67fea1cbe6c290ee994d6e9e5cbad51e3d90cd43db867818732d0d72624211455cf6950eb7ae3b5ca7f845f4d93085aafd98b14751cb8a978e35403efae0291e65582ad9ff2e1e1e3e693a12d736c3d03b6caf67334742637f6ab04c0406715dd69539cfa5bb5b17306828941062eb0499576f1b543049f24e54b2e2a58d50aae21f01bf8b1b235df03fc509e1bb19f96a0c10e68126d8f855b0c13f2d42e62498101c33d775a4c481562ece821de7dbc85981d8a68e7f1945feb370d8c75c6272bfb6d2b86b4865f41e840476fabad4dfe717b372f111977bedd658d65e39691e83c0ba7a32eacfb5dc9f5478384ab3966cd130cd7acaa3a8f535149fd615eb460a184d214b7c6b6fc7ae186971ecbdf68ecb9f0d515d5c2daeed62e3a0150b2250761fdea176cd52b8d04d010080fab6d8d84ed332caf3b4ce0854ac5647127a4fd13ee87863c7efcfa005b166de326d8dc77399b7c945cbd3039d15e571cd05920a1590ba25cb2e5c255aefc39c3ea27d016e009fffe0ccea8322c44eaa040dbbfc2a354bc14090da86bf38d375a6c34a59348eea8307667f7b9f61b2e2e372ab4bb60feaaf8bddace7799448d629fb08bd36823cb8e6c217e67a14b5aafd9c79a13111bf33830fa7f5b765411b4861f57ba118fb60ea685481d28db4705799d0433807b330159764551e625c8754da28419d035ed5b8a5d244060e1a74cfa5b0c0becdb2dc0b6d0f824dbdd1e9bb7ee0a939dfae8f7291832f21dbe1966abb88eb7d92ff4d3583dd0cec1f13793e53feb3ee3af8232ae9a9f86108963d0cf514489a378ab38cde427887f672f3627595231101c3a36d19d4f3f9138593f17d85f4815815b7963083c6fe650932fdd71717d1cc71ffb52dec631924c5a6f6de001c1d9e8ca55472c8cb320fa7a08aac0520b6ef0047a6d614ee53fac37f41e277b55826cedd3dc2a93d24cedb4ebfb5cad2b4c33b233cbcc9205e801a3befd23f14f0375c8ba65814e0b4d9b31130c84538b95521e347652df1c02445905e2ecb17facaa53fb9796b9c5727566474eeff2cbb6d32f79342aa280cdc99b2fb8db698e9a245a3e74dc3929ef07fce2744aa4dc0f300472f59403808d29c2de1715f4c947eff639f8c38a2cc87c0f35e82c3c3078aee71b8af0d4cf4eaf7aa1ab6e0737d6a3324c77e30bba7e1248eda659dd58e59441c7ac4067d2c99dda042c38a9f6a0d1fcf538ba03a44dc3e617439f2e8748b091043339734698ae0b626d502d3cd82b02d2af1034acff9c859d3a16ea1c42bee6ae4928fcac09ab2ba9321d8a69aa9b2bd24dfa75f73e23c39678ed3b8caba517719c4cd48f15792d05ad2270dfdeed1df2099eee9f101ebc238a02fefd155c8ce2f9ee56ab6da72a139a09b0d03b136880db01754c3f62b165897b81671aaf439a10df70a79828fcfca1b762973556bde22d157a767483207edec46da715cbd1e5ee183e757d99babcf03b4765899ce8f7223336546391acaff3033152556a888995c1196e90a9bdf8000000000000000000000000040c131c252b"},{"tip_id":"tip://id/US-4f1e6145e0eba699","region":"US","public_key":"4e611e9a5edcbfc0155022602e4fcfe39c9484767a58e2d8eda54d0fec3a8f65f56a4f8001e9f9cf76d88912058b5e5d47ab009cbf269d54a7fa2beb075ab1eed29d8bc74e98879e149c1bd41c80d7eef504504a514455fe50b84fe5cf6d435e2342ccb4317c6cbf7009eea2e18a6203b46e1d5e68443bb4c2de367633c7547d8b001362a863d9914f2158214ef82996d1338d83f7bfbe91a12827596e1b25aed816e6db6c8a8cc1bc3f171635d086b649997110d631f0e88487bebf76e283020f51ce77b03560242c0695d9e3b380ddb6d344185378c87f8964ee6c9e22016f9397ea140b4d36764ec20ab847f049349613df286931730fd486484e34d44ceec7c50d9adda92d3bb1cf388ee006fe8fc07982cc470e93319321eb0b4d8146699324998caec0069c5b1229a316c7c15bda1298cb6dea0442e276aaf26cbc90f60f570b67f2996f1f645382dfd801ce1c1b27a139a5cccd019fc757e4a783eb1592c6eba9fc8d5e82b61673a5f6315fe3681e286602e904ef89dc528d763303d315595539d2ed2ef900159b107deb4af04f847727f40bf7220a7eda1bd92720c460834984ebe5fcf5871e07066ee89ed54fd9c5e9fef873c436edadef69b16466662de3297ca126f56a72c09bddb8803dc76fa5dfce946716a881cb6880502ee69506acc7670cd2c1abc6022ec5fac71124d55e47e2503e1db5ea6b7b5f56d0007028dd8223fe5ac4ffbfa7d8115747236dbcb1b9e84317bc2fe2600cf9a81d1e123ad4bf2528bf364d89ae0c2b7e71f3fec3bb0d6dc0019e2f93b1b624608243f5b303b696164ee7a44598dd5a2c38ba70deee9e094112667ab83ae0fc4a8556644723289a7b77e1b6007185364c588f7e0a10a7d2ee9650d25e031da2599a84c8f7a6826dad7777bf19444ffc56c625e072a94eb3d38cae2a28ac8784e3524015f2613362848590a31970c11711ccd846567aa883a04d5ccd56637aaaa21e6955849050058a349dd26f917a2808bde2b88cd87996142fcd75205c287337a70579399be7af9268909e1c9f4bd33040736061dbf712f6dba0c7f54ec24f28557dd6560f486f14a5d44e747a57e6f3366c0c86de296d5029a2b2e5a49b871ab63dfaf620b96f7a45651e7a3f49262d389be0010eada583a494cb3fd11ff0f4f67644cfb0af9b348256bb8cdda50b39dcb0fad7fd0c7c109991d13b03dc6a580d28661704e549d86a502fdd4a8fea3ad14de0815ba6fa3845c26341bbc64c85c4413b7b9bb2e8fc5372752234dfad19e1a177f86a08473678667a1fd4d9ea86181dce64819c431e9386e0de664e5856980a908bf9bbcbfad9ceb1a11d57ee9d6bdcd7c9fd3acae03c1dab2bff02d5f34e07eba523c381302b906b99a96baadb978567d1399adba67718680f14edc1228643a37d8dcaf4668b5a80f43f7da87ef505a62d297f6884f867c3a1326fdfb33a0a0ad71f2041441474f8fb8bb41919400a95dbb2d0133f632b3eadcc4945192bdae8cfa48a5607953412c55a84afa0e4ece614daa58be8d74cc3b333c46f8e43dfdbb95e315790210f6188f5ea6ba64f2438992d908bcc836b3e362b7e38c5eadfd7e8c2c59274418fa2092358153620970627ec793a9de4a5a3a0c55dd2606c4c792f049408c6e9c9267319b161ca5df04aff62f2a4750d710fb9bf5c0eb8518ee22b32373cf99521ddc5ba9a4beb7c66d840de84c7acdb499822bd7d81aac1f1194537e58e4393f7376c38e538516ca0633618ca0f29e9e4e21114aace2b5853fd0eca00cc741a6b94cc1259627bec3a648496a4954661c07af85ef9ac86019808027db5e7979416ce6ca2b9ce1cfa5c8cdea1c1777343c63c3659b2c7a57f9b3cf5259eb7862d32bdb1d90f1e447f0b479e1177cc92ff835d5643b734a0516af99e9a5af5a485a2a2c998f0d0d20d07413c872365c679b0c6ce75cbcb54ac56f1947c2b0416da4fe2b9faa033b1ad2d0e1dbc8dd0c7d755d6803c61bf898a46b4439aa48af1299eb22f6605602ba09f4c579063c826ba75847a8666c668e6738ed8ac421b0636e9ab3d710fb1e7e798b4e3e49a2493606f13d975c0a8aef030c3bd1b3f4b50132550c35491677aa4475dac54880dbb97f1c956ec891b12cabe516fae2d6193ce27a9b1369bcb6e31a89c91f7e783fed25240f76006db8ebbfff2582708740daf37246856eab65c3c7e7725f750359bc88edbdc8f137212c678c18af706a85246a83b12a835c2e121cd4d40af68065e422e567678df6db0d44c8303d33365a213e41a22ea4f012518de87bd9499c3f8e96b787b29ab85fef44706c4738ea13fc261e74d95754c5f66126d57e825d3b88fab159985573c3fad6d484b8dec836571a0f86c906c081c0e0cf75de2d817456640b2c0a6e312e17a6f9a26b4f7f74d3b9c53203910425a02658b818f0df809756dfcda70d13fdc45cbcbd1cbd277a4b0d6d3c413ac435e484c13670d5e071b7cd706c28decb0748ae435cc771de9dc76f2c5fafddcee81a57baaed5542f5f4aa5632d5c2cd02697ebe2facacb4e1fec75868a248d37378e1b5f699f4b6065f6cd04fa4aa3200da0a7422f886e23941f78ec2db6158bb1d84febd1489d65a97bb8117e320bbc941519e3e4d790d6c01c4d452bc5cad2e6d5b261b63be35b6e26af9220bd6218d49453ad75995b01f375f347a04ea520ffa3ba9a5b166c4953764a5a1a508f0f2dc50721355306526f6cea756b093b38e2089af","dedup_hash":"70044443154882484498","tip_id_type":"personal","vp_signature":"2913ba7fbbf5d3dc6fb5172700be41153022b4f267c72e2bbbc1ceb6d87b010ed63e3c35578a02a111e7f65edd9d107fda84f68d91cb2dc373ddb364e9987379f4dd05d8dfce8e66361a73601eac9b020e05acbf875192e1bb134035ada6f81054ce271eb529a511dc1f7ad9067a3737c4330f411c097d9310527fc5cad3ef190c6007da2913b80a7ef21aaa076fbd40e5a34d0b78d1193252e0885194f4aca3f9673a4e4d40fce690113cc8d55aea44a2bd42133690f4cde71656096a19656d54e4b02adffd76826f572643facc2bd2eae118d4a76b786398e529038819c3c6ae4c8be047bf0e7392d6f8745b2977eaf49efb276f8a14c366cd1d0524282770c6af950fa2b91707b16506847f79df96a6c273793efaf06cbeb157cbe2696d302e5b1ca34ea641e929600fe5da1e16648d4da7cbb4bdbce5f3e95ed61c34fe3b6f7b502f3943f83d209cfaceb236b5c7727535663c0c8287e5844de3385c119799fa89f5d9e1e0be0af77547e3e14beeeeda424cc682ac06448fab840df264f89c4b266af3589bcdddb431f3900db9876f97f82d3c95cb82f26deb77c7bd440bf549c160ddea76d52a0114b5d143ed944c19bdff1438c5766824891addbd08cec04dd01c052fa1eda6647cfe373785b25bbbd5ff8a9bbd28ebce215aa4e107457ccea6cb3ce525111e40710cc937697a455abc11f3dc8c7af3ae077044aecefebe6a535779dd02ccab00a36a87fc3059d197853c4e21d2af4dcc4a45420c99bbd5ea10fb8b6f2f2ad9b8ed6b0d230a19904c9389464fb2430e46bbb48067ca3c8788712367bae2baaba197a83a2a6f1d2e2bf13a76d62fff11ab8dfe5066c901c4743a4812df5332d6f9fefbca28a9ef52172f8d17054cbfadd999190c36462893a8090393b69503cb88f26ce88c99d69de59ad4111c088ba58fd9884e1fd45d709063a78bb51333ee40f5ea816d4180e17113d0a852a6ac5fcd332c965a97e50f5447586b913f2da0543cfd730c9188f660f9a3961df4fc169029da5c619fb4cdcfe1769743dd2c1a07b34d90ccf82b1bb6e91cb6236e330a7e55bc579def047b936f92d79087e9b3dd1cab84174e08aa12df41ff793e66a76a68c4a144156e75e58fa25445fb7ff7e794851dd505918d4412caa039be984d59365024b904b139d79e4450965b05671f4bad9099d64681fe48396d7f8c30580f048edb83411e1a3a55ded35647ede1056381a1c95c056c568be74be1f9da646e6b1a4ddc181c7b683fff069b930ba84d5664e72de71d250a8122760b2043d3f29a9699cec9339e19c2239d0c6b88b4aeabc8dde2f7b6c8ac0b50b8c5f73e42c2721c03a62b824134fc6c04a96ed5e0035440ae1114c38e69c4756561abc7d5d434861242af823b928b8f197a90fb4963d55f54278727638ff940940a96cecdd6deec64f7839c9095ac5713e7bf89f731ae13e7130bc5e809d5450df7b78d5724763aa815eb9582180970bf0c2636133f153880278e183b91dc26508dd618d76dabd6b8bf6bbc24fff8ee2d0e40cfd880ddb26c70576af7aa3489676326a9be25ef2d24da32f8e394220879adb35c79279999cc2a1258bd330cdd2e7055c30d4a43b51b373853185a191dfa1dc3f99d61ae44fe4d772d52fa2deb46650a6cbb3ee744d6d1763e3757d18e699d05207d682bcd5596a63736ef0283a657a1bdeefd6633c55a7f479fda529e09bb15096fe972aeeac551c897dc4a2234f8595f2eb38eadeba48956bac6d886bcbb83e2e4e5fd86e3717433686517df38c1d0110932578e15357faff67d93869e98272ce8a6ff2e3e7354a02251270374dd8739bc456ec957fc13f9a5899538e4ce222863ea10b8e4374e14c4e5df53ef982647748fdd6ea4b791c4a00c81f2da37b18e66f4c50ec23023e5703598248ba6fd9e23bc45a2dc720dc89fd910ae68c15ab06b35d8293cf1196971a1da445611977a8c769ba80b6973bd3fcd14ed18cc7dc5dc646bffb36cadbda4bc7677b33f054050c5cf32926525c3bbbbb92baa9e4a598833bb81580f519ebda6b57f7a00773cb8298aac22e0acf1d6d23d9d989d9ca5d20f31047e51cf51a5acb9d4577774bc60ecdafa9747ff35b104cfded9f97605ed11168ba32877fa0fb6e9012fcef156c1c096b7998466ddd273eb03923da36bfaae129ef3f38ca086fdf24193a8db61ff239d14c33570658a64d6c6de4f0671f728d63f663c13b19985ce1fac85775b97ca7c2974f7e67f9ccb3161321d61d62f976bb27f88d39d60162b750e284994ac91895a9ffaa6af3d5992660052c20652c33819621ac63ca9676ebc9b954edc6427c800736a617d6f35e7602a1a3db35677d7a960255865892cf2625fd1cb8aa178a51ff38c71d3b5641b1d386ff77c27706b34b7a389c7a767a719b40bdaad107ca1abd9dcf3830930ca5ef7ec43c0b174cc503f45123f65d0be5d2fce57755046f768ddc6c529506bcb95013e5f62da5cc1841068a6d43cfd1a3d486d77926499c035a06a961662b3f5bf4c40bec9031294fb5470bb35d4497f35db411415d96dce42b9819802691a5994b629562827d86e05eebe72392db565af62fa62b6959a553a49c8226532d5ad08d5925f0572f0fdec30cedd637acf29218c3d36dca2f87206bfa19947d50e5756060a746807c727b968b86e22662c1f555cee63489432d5d08931d313861004e00183755376e835b975999f5ddc4fe417edc494fb84656ce91dc8137c575e1432b311c16f40f73aa391d5f4155e175bc96ddb91722a86848369f413133a2716c85b70193517e51858a3784faf7c44a5ea6c0efec0ddff2a0abd997eabb74ee9abb9b6d83bfc2eaf25e2d2fc07d483ce8eb224c14ded21e88f1205b572fa5f99d825110b20fbf74ad6efc2a9e495f8e9412a1edeaae5186a041d1571afde636daf8d387ac1e7ba0a673721b94f207e3bfb1212bb774a2360e524be0ccd362ce4f3d80141f96dbee790cee4eb0b78df55979b1d24833d89313e653b43b761adf4f477f9f51fe9d418f050f3ce895c2ba86c545b5a2481d968c201f4c2c3e060e5b503e4f533cf0d3b8411cc6407c7fe667e0fbd29248b611577de03de4859b8ec8065f3906e3df7a3f1775083ab97fa9d7b6ddfd9d5c148c7d8b3e7616936fe642541243248cb315f0be503fe72ae2cdeebb68e9e9133d587f10127a0d0274f54aa4098b2fdec6cad31d0f87b694c3fe4b0b2ce6829cf046911b410ea504bd6bbd6e396d24b170c152886b1bf075a8c91d28319ee43ebb5dd78a88fd506d14ebfc415e082d7b45a07f0d1c13dc2130be406afd1388a89c8bc2bb77d05fd44a69e30e921f5dab3c33a5469f68cba025f6b9ebbba349515590fe0afb6c895e70e1d165fb9ae98eb809b10539d590865e4ba09e900ff6e6b8795a28f00fa3473f778a04fb3008e0ac0ea91034f86cd8f94c6b63d1ad19b37ea3e33c8f1d11506f146cba65000cb040189fe2f3c0c71e4169f261210cf16b65bad8c7c1b680b084f90ca69650318708034f23eed21b96a2205ac529e6b4337feb7be98e42daa7a77e980ec7f350bcf6119cd77eace25496285394626c484d595bafd547efc75359d3773a8f6caaa6ec7b6f4f6cc525a1cbdfb4cdd4e782859d29737bc6a14d70acd4f8e04c84f6a70c062cc8c7f189c6c31305f18153b605b032453c524152956506a6468dd84eb8386497305d1b2228000ccd16794b30feec8308aa2d5e7305cf1685b2e53a58cff55c8893c739b084aa49379f63259c8e56b4529a8e365d1b79c734e5398699f8ccf818ceb86d097de0de38b36497c5169fd98b67d50a197276c9e9737b4f7ede674c63e8ae4182f29f091b39dcc1f2524a2807ff785623b06de1101768776f5d13415c118b7656d40e3eacb288921d1c94b4f12a1e5e1483129b756868a03dff7aa9d770532cd9affcf112718637b0395f2784f4dc05a2ec3d8e0d4d5f6e78a5286194c52d094e290e1a655b4664ba4a894c9724fa37a291f2cabba7105991c8b867b2f81b06e1d5e80acf22e03e0800a90620e8ca5d9dec71e353a3224b8f209e6a4c4a72967d69f892fb2c9d10635aecf8e964ec0723a20f226c0c57d76b2f63ed37b438b56513dee901db9dd078576a1538ca34086c94769232f241b0deacc944df04d3a6ff836495d485655cc1eb7a807138e9155cc51775598f202750dfb1fec5352b1fa6a089cd6a235264f351f0ed0d55ad10439c1680475b2bad29115923fefbbd1846ccc8c4fbcf3beb33c90c6acc8747bef24bc86b5f2e7b57a2e5e2ad518da56ad85c70cd3f20b4b00129c724a5422b122acdb4a0ff0b04a6fa5f2c20840efc0967923e58c9f325ea1151b7cd3bf3e9e983963fb317e4405a7985563a4e0d3b4031f1a25e6c0de5a38bb261782564d2f85074eded500e7e19e3ab81be4548b9e55041079d07f244aeae6dd5370c8245bd90c125f46a35e45afc5bc427c740514ce79495cf01d2bc44b4d832e22002bf910258c9b8a0b44234109b4b621bb5fe6cbdc052dc01495b61f6765447472a2f48689c17fa9085958e2cd9e1dbf44617066ab1620acafb1bde94d595b6794a7bee5375e697c999caf619dafbdd11a5763676b7c9bbb283283a7abb4cfe8000000000000000000000000070f161b232b"}],     // [{ tip_id, region, public_key, dedup_hash, vp_signature }] — embedded by seed
  genesis_ring_signatures: [], // [signature_hex] — one per identity registration tx, same order as genesis_ring

  // Merkle root of the initial dedup registry (empty at genesis)
  initial_dedup_merkle_root: shake256("empty-dedup-registry-v2"),

  notes: "TIP Protocol Genesis Block. This is the immutable foundation of the Trust Identity Protocol network. Once this block is committed to the DAG, its hash anchors every subsequent transaction.",
});

// ─── Genesis hash (chain anchor) ─────────────────────────────────────────────
function computeGenesisHash(payload) {
  return shake256(canonicalJson(payload));
}

const GENESIS_HASH = computeGenesisHash(GENESIS_PAYLOAD);

// ─── Protocol params hash (forward-compat: Tier-2 governance anchor) ─────────
// SHAKE-256 over the protocol_constants sub-object only.  In Phase 1 this is
// redundant with genesis_hash (Tier-2 is still inside the genesis anchor), but
// it establishes the handshake field so Phase 2 can move Tier-2 params to a
// separate governance tx without changing the handshake wire format.
function getProtocolParamsHash() {
  return shake256(canonicalJson(GENESIS_PAYLOAD.protocol_constants));
}

// ─── Content-addressed genesis tx ID ────────────────────────────────────────
// Computed from the canonical form of the genesis tx, just like all other txs.
const GENESIS_TX = Object.freeze({
  tx_type: "GENESIS",
  timestamp: GENESIS_TIMESTAMP,
  prev: [],
  data: GENESIS_PAYLOAD,
});

const GENESIS_TX_ID = computeTxId(GENESIS_TX);

// Pre-computed signatures from seed script (founding VP signs both bootstrap txs).
// Placeholder until seed runs — seed replaces these with real ML-DSA-65 signatures.
let GENESIS_TX_SIGNATURE = "15343381865577f68feae7cbba17e1f1f169104c6749f32d2547242b20d7347f0aabb95fe4e807a73e53f337a9482e89034955e6592c927a6c9d243eef8cdc406edd4ad4c7e3921660190861ba1ac19542009bbe7e394110df244e9a52aaf260cdb0fff8a95c01c4e0f95fe94f9d0103fc7af15906cb36743f305a13224da0b0ed161c6b3788c18f24b594ee51cefb4bdb361adae58154f8e61c9523af3ee637c375399f71dc759b2cd89a37184a9403bfdc6bcac57acf93c1bfa555e7af9f7efd77fbc8fc18d70104a351c9c5e47a43c626fdf47df7a6b5fa4e370761ab90a1f98dc132a2ebde6fb010e3e79b4f654ebd7d57bdf450326f8c18235f1d8fd28c02751de0146ae56efa3384409c78efa5116ed1e10726f3ccc759eb299f9be292278c83b1ff6d7144b2d49115278c1b52331353cbbeaa326fc715bd529959ba0d39942525beacba6207f7ecb39b2c0522ce7b29e7471fa12636661f84c8e538960e16258689c0e0257f4769cae906773ce3776762bf2daf29bd1f1f8defc8962b67cac68d75b075d9a4d6ebf56dc14c28d9d8ff27ecc0156bc1c6417dc50cdc4ddcb1fc35e69140e54da09bf0264f35fe48e4de7fa32a86c56518151d78ac142be84b78d827ee09a908c0bb814f692ca431f8021f2fd68d2833e31dac2541e331be8b13d0a5abe357448bbbe91da96dc77fccdbe1be91e518e0a5ef82297314316caf0833e797cf5977d7f1b3891adfaa577b2f941f15b03eb6b11479f704c138e03a5a3057be00ef8ff099960b9f7dad8d58803ac28177cc54f283027f6ea7748bda56b7e9bd029a8fdda872cf961a9ca0e3aeeba8e6e9422a1611ad425096cbeca14507055d9483513bfecac5d8ea92b02d4417c21931601ad7458c80fe10dd910663913c5b1af8725d9ac4562432ce03b1b1af9e1ae1c3188ad530e2f6659d0c26674b935769c79bee4682ee834018a0699a3317c88dae1e0824545c096f2096275a22d90559cef8a3e2f1f15026c54b0afdecbd46b5e59ab7e60aaaf14269c3da86a3f0f7771fec6536b0a413f1148bf712a13a878187c59b8731fa33c0936bf5575a69065e05c3329bb4dd316e3ea35a67d95b457503be437d29c3ff148d54ce553e1df2d93764b2841c9f589c2e4e87a0a69cc55fbfaed3960833dbd4099f68b73e646e21cdc7ff26942b8a36b67d47a6e8bf2e7ccdb3cc7f32a4a99457f6845fdbda45dc7e36bff2729f86ff3cd28a8f501221660fed72645bd6b34b4c795786c2371ef0ca5c4e2424fbd18e978ffc79f879fdf53658e7cea8cef6017ee59f6338c7da259541f819d93477bdaa6a88f53356fd178eb9c4c3f7ce56e3e1b45adc624d4cc164d1cb4ba3263c34510be7199d9f46ab35868aacba7cc11cbebe1cf38a87bf48ace107c255611bfec00dcc68667f0b078d8a3c34782e19cabeae723120bcd50b7dabd25255db81ead093f469224cd6acea060a0fde00fdd28571fba6380e664153f535683852f951c558a961cc1628562926a3e6fc6ade0412529ff14853bae765033f30db2d71fb943ba838b8e7b48df6314026fc1e0f78326b7e3053c697d5063937bb607a17fd92d4d5259e77089e1e5dc393e41ed5680ef1bdc70d40890cfd875f5a2ba2e3e4cc901f72658be3ec9ce77941357a54f416bccae84c96a4b969841ceb9abe660c498071d28911c255be4ca7b2532f4b6160ea10c2421b4c08da16761b8e11730f4277488b95951847fedbcc026ee7bbc7a8d3062ddff54832d46434a8a8c103113f54830d4260e3a1aab49a6bcd188e6742d05d9c62a0893dae10b15c2cf777b14bf0c3177e372eae88b1b21ff381f53f96c3c5f77f97a1b3226e1c14a213cccf4223d5e8d2e65f4697d823542dfb75144b3d9146b8c16ff61ed31697558b173ebf3be0d556cc06566709d74a61c50ddfeeec590e9bf2ff3005a3fe221ef67fd54c9f185f78d3571adcdb23b960bf4f67bc6fd2f08a3880a180e604ab19c4771dd7eb010defddc34206110b3152025be09ca16558c26e1ac8d62d0673f25c67c2d37d2c564e7d452c9a2a552305d87dc594401ead728b7706b00f7866296fead38c758a01d26c717a8f69b85b45246e904e70fe721f88b38a46439e08b0ad5aaa90a0330cf450c1012619ac29cf8cfb31ce1975a3b3b3f23cc72dc8d1ac1bd35e5637b4b561a2abb2530c224bb613b89c6de8e948fb66e83c838f873d14d2ba051d94ccb1c0a0cd2c160b0776bf4de1950149fa39856aa2e1d9a9ae105d169ce82dc5fdabdae8a5847dcc66b3fbf6e67befb77e9cde7238f1940b8ffb23638b33e2e845eb402421eb6d13846f9c173646d790de2ffa4a444470cebb3625e6c13a0e44bf5d76d3848375ab76a8252c7d3aeed835c22c50bab76ed289513e38ffdae25981f8b59553a304a9dedef19539b5f237f7369a73b9c4c3d9ab282734692bd9d73d6ebb6cb8ec80374caa2fac6c60ceede4a86c7da81d9515862fbb33ce0fd0a428dd4f00323130d9d4140004e5064a2119e78742198897ceffc1074ecbefd34cc61511c7d3f0068bbaaf8507d0217e42df502c6f845bf22b466f201806ece5c67bcfe5387f540c1ab1b3752b456156b250f4d2584e6fc9adae5120b4be83dfa419a9d09fc368f5495ed1c63544a2066f7d8d5678a23d5fbaf4e832abd70f9b31a605b052b8ddeacebe538820bee6d745b41785304ac4adf58e45df61058cd7f5309f85352468515dbe04c0cd5f70474aaf48b6c38700bd10cd9c161c711764582420ba77dc555796e6812621a96b3fa401424f2373701e037e7443476aa4bc05397b21020a410b6860a0025068049cca1be80574b78579118b2b8084b5f4941fa96d5609284d1bd0fc8dd34f368e23a57a62dbefb7ed999bef922cabb63b43e13ee60ad1937f67f09cd1f6bb0b1e5b7136d27054f4d45ffacf9fe9ee112e9b22625171a7af5968099685822e8bae0b81a707e89e73d8608fa0b8f8979b300c6894b1035a92b08ea86740335e9f5532776a15e534868f82484febec0d2a01e761bfda696451b1aedc91ae4fa091cece9fa2f8c3e09203b1120fa97ce0700c2f1988462f6b25b91c426af74fc5c56caad4fcd951ac12258cf0e22db321241da4af661c456f07d6673c3b7ac52338b4164d68a786451e0e04be789783aef04b300371ce52fb92f858211c1fea66e96b289ede8904ecb2ff010ca8afe3e524738e4b4326ad3bcae023b67aea7193cbd0ca8bafa27cb786f9995b8e8c7a377e8964b8b3d3b39c237cd098be89a6e87c24132b373296e380e0c301c85aa2001cf9ac554aaa39b3184591f3e4324829b7b1a514df2224f1485b950367ad3536b66c92545b1b343a9f1dad0a3540dc9696166ab4d54967e00815d1277a89305a724450ddaf23981f33c80bf6bf3d2118d03d7707ea6c6679544a2fca75d49d365d70186b248f29f0bdfebbff9dbe69a53c4a102ec0c8b3f7f2cd8520b1726b81b2db7b7caf2684c145fefb04845987c3eb2a92ae048777f21a136507663212ce0c6fd31c8d75e452788a477d3152fbb112937e1475663071e7f4db7563a3bd019dabf20b17f1be602cfdfba091d01955da06713f78f236eac0701a6628b6b69954b95d1bda85dd2164cd5429d3d148241bafd2ccfc586b958fa3d4ac13fc2a36d845f9ea6d8d95834255087583d3b1ef36756c21d90a55192920a22d5138ab908f3a04f6d05f0463d1963e579259597688edd6c4ba6e18e1efeeda49b7434ee16e35809eeed4b7d07e659231a25dc29cc9b313f1fbde79205722a58d212d9d1a3154271300b86854fde41be0288569fb97d24c9ef58e3804adc215b2b5d1d2cdb6451007de4764e93fea436302fbecfab94423a8d030552c9a80f23415c23e231cbdb14347c7b471913496fdf0f6a8e85ee5d969d526e7d9e3f187d66c7f88dae82d1373a383ab1f55b27eec62958d566a872dc4b8bf8eba59d6871c4dec6b239eb73fff293d544ab4670fe591d930fe7966dca36c135c7734c18b85e124fc9298854a19a3d9745c90e6271ba2e30e16610759a64a8e2c81e8018820f876584edb9fc93d833c95ff41c06d11b3b0faa713442bf56f3cd37181ea7a00ab853973336a58488aa53a87d3c941feacdc73840135144f3e4dc004fe89814ecd9d82c5b37ef26a6a948af4b1eab00737608d509dee71bf40c8a8b1d473e2adc6569c19f713894dfa93773fd84655173585e4fed121f05818dc595fc604929d03c46b9bc34a31bedae010b7df446eb938dc676f2fd7fd0c9f74e766774429d25e539d0b6989cab978ae7304356827c37d5014f6e076c763a6386ec3aa4c51857d77595249a8cf6e6c37f1cc8a18c1af748f097cc902571337128596863a3499561237da04458100b7a9972b5d33443dfd684f16e956c1e3006797e1067bb03b8393d962837e42c5e35842a5d9fe79a03d2ee8f16b1aec6d0d4aa913331b77ada0d0b3d305d24568da60556aff0653b8085111b7295ba714aa5f96fba5f9839dcdee55023903cf51942d7334b323975e4ff190a1a331a53fc6cd3d158101c4b31052995b98f575730f3f486d849aa6a7c6363a4ab02260757f8589969ea2c6cffb4b54a0d3d90e206ca0b000000000000000000000000000000000000000010a0e1a1f24";
let GENESIS_VP_TX_SIGNATURE = "5c6cf88a273d04bcf22479e8f470247aaf5dd7276e60c2e6f70d2cf06e56116719756cfd0c74357ab75f21339c0f15c3de2993d472374614fee260b5691d6f618327fb696747778292d23323a0f2b949e1566c82abe4ea6de7fdd5f477df3acb27bfc912ab6bc05c00ed9747fa0c53afd03827a64283e80e1208fb126c1c49021054553ec57abcad50d9955972892712321053d10c156f7bc28a2da52df6fdda640b6547a8258cc87bcbded0db8a1033d84b19f07c6ffd01dbcafdb9d060cd3a05e75d563ce817430209d635188d6ab50578696fc9a7b613b9daf747393cf62d570914089043108054fda60fb5b258c3fb7df5feb34463105f5c7eaf7b0588d76bd005d25ec8e45354a180fc91a20f93c7ee3362d0a7694a3ad71ce624ef8e2fcd320092ae0684a1b9cb4a014c376488114b63a97e52df3a42c49dad2c27d3849f1a393905539427cc7de9ffde8af7b341e1617cf63940d019569a2b6fea8ff7787c4636b152ecc010efb62429c9071ae8f4416a8bf529fa66f155e576a7f4c15bd8a86e68a4b801a459487b41625bb1472bc8ec3e4707dde737855d12f6b471a22255a62ff7d1f0b9232c2f0e82782e5f3d12e0a4829bd3f612fc2010a4e9d7b77b2a349b601931f996f2d2a6b4933b2b8863544e390ffafa6676a29a3b01a0d692ea4afe259cfa1f00ba02d8a0e1fa7b1edda987b62307c689702a7f6edb1cc2d8eb0d31f38842566759bab6bfd6a139dc2c3de767821c7156c205c793d120e9d252ade007449dd0c5cefd52e1bd65bb8f1c835d18eaf755ef2fc445493b9fa77e1556f21eb694ecf6cdd94aea44327d522d44a73a9cd1c09e34f69d9cfd600bf8cc7954d059486b6263507068cbcf39ffaf2d00a0bac061a9b20382f0012405d33f72d31bd1160d770ae4f68a2211c8beae6bd266cf39c5fadddddf6b79ecfd185eee8dc9c20271735e0cc1d2186dc53968c5420fae3944a7efec3e5abffb97d1e512b8e0b7eb80bf53295f8fdff1bb1a2be05654feee6d614db6cf02eea452f8327029a4f97a283d812495adf741802cf6d02e14e89aee642a9da4166ba8573a5244ddeab9c8e9fa6ab0581fb1866d64f1f1b677d4a8fa94ec99058c6711e993b16f89658fe052e1210542a89990c1beff6463e12b93dd17d31c49dfbbf0a0c1542eaf7133389e36257a52ce1a40802da5db601949b0b92e2166fe2dafff5243c29709e020c85b95d489df15076ec950ff28514a8db51d70e9c62ad44f2c559e24f6d4a808efca697b82a1308d3d59f325aec50e9af172616b63063d73a1041c58701dab796cf07c9063b89c7534cdf3b756f47dac27cb63476551d9641ede5a2abda5fb946014bb1deda6f1e615d0a290d76cf87020870d1cceb2570364d993be67756b90304c627610d0e9b8f3e2cdae3e8c98e65b538a0088c39cfad556ecbabe31f02782887dc1d0421b9bec4e871714567cf99b9edd032f0f44da0ad7f79038d9dc6f916ae0b0b3e583a021cb3bc1cb36488a04ca1a0ac581bda2891705ef0b40c78f00614f197e8afc67211e99e6217c1b3a6953ecb8fbafd5ff9d4ca323293b88dbc0adfdc39067008f7074463bf8dc39aeaa5cbe045f13ab7361b4066b56d69e55428e9768361887392dcea7ac6a37a06987848f9c8156ba12d74f2cb25036c4a438991d948ebcef8e8bf648087861d87572e77ba9074da00f8d51ccaf819aacdf265d1637e4bd657f05170eb115103afd7ee6183ae1d35330aff67bde80b90100c850aa6fd64b01d6d1e5da4e97943860019fe4ea874585b5a2fc4d98049494b1862611ed11a51dd8c0b82893fca5cbdccde80284b5430ad07192ffe6a9734856856189e5d05073dd9abac90218051ff3e59e1c8417d182e91ab0daf1f22f8b460a82c65eac6e9aa501d6e272da1d0864f29c78d81e7c06bdd384dafdaf81c84e3dbb175e0443d6e8044232d0ca50f941f518a2716643e4e15b0f0142813af87b727642f7d50b92ab7c0e2b08d03aa4b26819efcd817a12b71109692f8d05dcba9397d1c06d488812a8c2552997b3292b9ff9b183958851b129a6804f486585fc8bb08adaff80c51c806ea2535afa4239573d7ed3967da0862495f0f311e5d0552e6252718f78a9b6ddc1acfbf0012114522748e7e892b9055e368666b80eaba27eee6297a939cd78ad5df3cf1a5f61625832c00e26ef0958ffea6579e2d504192cac8196bc2dd5d7aa5d477d585b3bec8b6896397f32e22076ad9ed163eb89e047180ed93d5ba9020935f4cb70dedc0d299f489a5f3e2220f26c4aa76d5476a618a6eaaf44f170ba3ed310edd1ae52c21a11f204f46dfa5bae3edffab65006d85f7b23581d6ecb774de290a4aceff94a0841ec8ce71a708ded0372e9890fd122b534c2aa6b4ec926ae23a69db941b0218b0990351ef767f3303ea64fc6541e151f0fa2b859015ce107455503908d59cf6b307aae8ad485198fc9de402f5d78f60e14b67194da6df1787284d336707dc976c94ebf0108b7a6735dcc9c1e17af9dba166c2670a25d47d7c0a87cd00e142fb127d9e9db6ea1e729cee41df6907a000a88d479d864193df3188265df0b0fd34363c16bfa42e4513375bd42c9fe915634eadf2c42b46e121db33c68d5740050f9e1201b4848f7b294783ca8e12cb78e1dcca22c3a6ada2be2db1498ddb7b49494737dd2a5077f6b7e6cd819487e39dc7cba71d15a78d4436cab2cf096ad2b36b820081d4f65db2d74890f803b6e02844232ef3ab9b02b248bedb4cdb05d03fcee90e5cd41caff10577c76567c6a74e033bf42df10f6ee45a91a9e21e43b2357422c00a1bf58c684bada8e1db6ba43a74e87cdedd9254a3d41dcc9cb633c908eccc80c32dafc9a10dbb67462bc4b070a21b82990b528fe49ddfff016ec66120fa04441dd720a42f81323a1ae48d1eeb2b5017ee39665cea5a205028fd0463899b79b6f68c876f2b36052e16a074c9482e967e3fb03d7b559a949126c8f8a6e83e10b4c525cbd3eec8ae1586aae1f723bd57d34a202838172d1da18fb1e750e80a71bc7013c25965edce3fb6fcd12517afd4f84a141fe85844ffe88abeda5aa9a9bb8cc2f40dd8aef1eb0b80083cfbe34836f6158b959f43810f0e41ae01452952eeecf9a0f7bfac6cc31de779310a50d363d507bdce9881d83ed366f91b3459cf90072bff859a3ae27d545df260de19560b3631da4f60cd50544125e2e57231b1424b298984869bd28d3315a01cf47cbcf8df97e6f5de8a8a1eb5894ef3f77bc6b24c7621fabe595b517c2f25a9373b740657b7b81dc8903743b7373b9cf7febf02ca4c2b060226d68da1951583f8940820cefc2bacea6584a4a33423467fac7ec0c58eca2bad7c7c77e66d6fc4d8385d43a5572b6c6fb05aba74abd2b1ec43b1f62f1bffcd8b6ac278e5c1d1212481614d5fccb90f0415d91d0564d697a355d8e6c267f81ac5b089f151429516cd0fc4a8263ba11fd79c83a734b459a19e205b65e2007e816d2dbb5887555652e5f494e91806276d3e04a56b93727fc473d8a2698aa4bcccfa37ec39c8535229c08e4093f9b3beb49d940a5396569641b6e289f29e883e74223f3625a6891ae62dd5d8b506b957a3a67372a25011a1124dfa8cfc97d44b0716b779bf93eb169c26be9c8506e82293535ba40b049337d0b6049e00603aa190aebcb37bf4d5cb9b9eb9928a212e4f0bae0c44dd3a008bb9ac51a9a41ff803f7b796412959dc39b614a52ee1b12ba9392de16dcf82dc89818c5f953e3e51342af57bddbdfe750a9994e9c1a0f179c81028e6c38f35af3549e13813bc9ce37feb16e65f5ed7135c85410ec92f6bacc5d1a42c51f75164985fa483087e1d89bfb3ba5c60cd9515dcc6d31b771813b0473925880811e34a540c3e1297d5ffc79459b026600ccd658db696654fa8d30f3576347dac644abea56ca73f980c2b67ef720e49008f81e2ee74874f1b6f5e9942b35caa3f0e5bb8ec680e433c484b105a7ba94ef0423ce574bd92cfc5899afb98e91aedcf4588923a7ef945984b62b57e8f1b562cfb42c7110fcffabab1df7a429de72a76764d3e65f2f0cbf18e61de7a0e7cf7acaa2f29aa5fc8b5bd818c7967c749469fb4a3fab2447a3c9fbfb2c6861e63bffc70d53fc810d298937b31b29852210e10ac686276b72576867c355d179b7cc4d195dcf4a99b62a7b3fcebf91a94f1187c1278ef0ad6ea0d07a0d120abde89c800125aeadbdc8fcc17eab55a3238b270b6a6c7af2af634fd3a08f8a60a48f231d004a5f307684110a90f9ce398b6cd4269655a95318fbadfe09f2b79c50e5ab9c2b03aa447b4a52b0ca3bad2ba29e7968f61f5360352398ffe4bfea3a038fc74503d922b5209c08b04a675fff1e83aa176e6df18270a8018201902234299f60cffc03b4313052cf5bdd3036556c49887121e08265c45c31ef49eff9e61b7ffde1da90ea2b246eda86bac3d63d5fc53c5a766e055e33540a5792d52e42f074fcbc0fd01a979b8ecfaaca72f2807fd33a7c16cd59d9be91e73c7750bc796c7738c921f54ef3cb9744038d7d8d71ad8b8e876c7c8fa3e0e8143949a3b5b8bfd4dcef3256c2cc1e49666a738dbebf4f6c7804102e353b5d637eaac9e7fb00000000000000000000000000050f131b1e2a";

// ─── Load or create genesis block ────────────────────────────────────────────

/**
 * Build the complete signed genesis block.
 * In production this is loaded from genesis.json (pre-signed at launch).
 * During development a self-signed genesis is generated automatically.
 *
 * @param {string} genesisDataDir  Path where genesis.json is stored
 * @param {Object} [signingKey]    { privateKey, publicKey } — required for first mint only
 * @returns {Object} The complete genesis block
 */
function buildGenesisBlock(genesisDataDir, signingKey) {
  const genesisFile = path.join(genesisDataDir, "genesis.json");

  // If genesis.json already exists, load and validate it
  if (fs.existsSync(genesisFile)) {
    const loaded = JSON.parse(fs.readFileSync(genesisFile, "utf8"));
    if (!validateGenesisBlock(loaded)) {
      throw new Error(
        `FATAL: genesis.json hash mismatch!\n` +
        `Expected: ${GENESIS_HASH}\n` +
        `Got:      ${loaded.genesis_hash}\n` +
        `This node is on a different network or genesis.json has been tampered with.`
      );
    }
    return loaded;
  }

  // Genesis does not exist yet — build it (development / first boot)
  log.warn("genesis.json not found — generating development genesis block");
  log.warn("For production: run scripts/seed.js --mint-genesis with the official root keypair");

  const { generateMLDSAKeypair: gkp } = require("../../shared/crypto");
  const devKey = signingKey || gkp();

  const block = {
    ...GENESIS_PAYLOAD,
    genesis_hash: GENESIS_HASH,
    canonical_hash: shake256(canonicalJson(GENESIS_PAYLOAD)),
    signed_at: nowMs(),
    signer_public_key: devKey.publicKey,
    // Deterministic so the auto-generated dev genesis is reproducible across
    // node restarts: same key + same hash → identical signature → identical
    // genesis.json on every boot from an empty data dir.
    signature: mldsaSign(GENESIS_HASH, devKey.privateKey, { deterministic: true }),
    environment: process.env.NODE_ENV || "development",
  };

  // Persist for subsequent node boots
  fs.mkdirSync(genesisDataDir, { recursive: true });
  fs.writeFileSync(genesisFile, JSON.stringify(block, null, 2));
  log.info(`Development genesis block written to ${genesisFile}`);
  log.info(`Genesis hash: ${GENESIS_HASH}`);

  return block;
}

/**
 * Validate a genesis block received from a peer or loaded from disk.
 * Returns true if the hash matches the canonical payload.
 */
function validateGenesisBlock(block) {
  if (!block || !block.genesis_hash) return false;
  const expected = computeGenesisHash(GENESIS_PAYLOAD);
  return block.genesis_hash === expected;
}

/**
 * Get the genesis hash constant (used to verify incoming peer genesis blocks).
 */
function getGenesisHash() {
  return GENESIS_HASH;
}

/**
 * Get the genesis chain ID (prevents accidental cross-network connections).
 */
function getChainId() {
  return GENESIS_CHAIN_ID;
}

/**
 * Get the genesis payload (read-only).
 */
function getGenesisPayload() {
  return Object.freeze({ ...GENESIS_PAYLOAD });
}

/**
 * Get the founding VP record from the genesis payload.
 */
function getFoundingVP() {
  return Object.freeze({ ...GENESIS_PAYLOAD.founding_vp });
}

/**
 * Get initial protocol parameters from genesis.
 */
function getInitialParams() {
  return Object.freeze({ ...GENESIS_PAYLOAD.initial_params });
}

/**
 * Genesis-anchored committee — the founding-node IDs that are admitted
 * into the runtime committee from round 1, with no K-round proven wait.
 * Late joiners (any node whose id is NOT in this set) must produce for
 * `K = COMMITTEE_ROTATION_HYSTERESIS_ROUNDS` rounds before being admitted.
 *
 * Source of truth: `GENESIS_PAYLOAD.founding_node`. If genesis later grows
 * a `founding_committee: [...]` array (multi-founder chain), surface that
 * here without changing call sites.
 *
 * @returns {Set<string>} node IDs that are genesis members
 */
function getGenesisCommittee() {
  const ids = new Set();
  if (GENESIS_PAYLOAD.founding_node && GENESIS_PAYLOAD.founding_node.node_id) {
    ids.add(GENESIS_PAYLOAD.founding_node.node_id);
  }
  if (Array.isArray(GENESIS_PAYLOAD.founding_committee)) {
    for (const m of GENESIS_PAYLOAD.founding_committee) {
      if (m && m.node_id) ids.add(m.node_id);
    }
  }
  return ids;
}

/**
 * Genesis-anchored founding identities — the TIP-IDs minted by the seed
 * script and embedded in `GENESIS_PAYLOAD.genesis_ring`. These identities
 * are materialised by `initDAG` at boot; any later `REGISTER_IDENTITY` tx
 * carrying one of these tip_ids is a replay attempt and must be rejected
 * by the bootstrap-epoch gate.
 *
 * @returns {Set<string>} TIP-IDs that are genesis-ring members
 */
function getGenesisRing() {
  const ids = new Set();
  if (Array.isArray(GENESIS_PAYLOAD.genesis_ring)) {
    for (const tip_id of GENESIS_PAYLOAD.genesis_ring) {
      if (typeof tip_id === "string" && tip_id) ids.add(tip_id);
    }
  }
  return ids;
}

function verifyGenesisSignature() {
  const valid = mldsaVerify(
    canonicalTx(GENESIS_TX),
    GENESIS_TX_SIGNATURE,
    getFoundingVP().public_key,
  );
  if (!valid) throw new Error(
    "Genesis signature does not verify against GENESIS_PAYLOAD. " +
    "GENESIS_PAYLOAD was likely edited without re-running scripts/seed.js " +
    "to regenerate GENESIS_TX_SIGNATURE. Run `npm run seed` and commit " +
    "the regenerated genesis.js before starting the node.",
  );
}

function verifyGenesisVPSignature() {
  const foundingVP = getFoundingVP();
  const vpTxBody = {
    tx_type: "VP_REGISTERED",
    timestamp: GENESIS_TIMESTAMP,
    prev: [GENESIS_TX_ID, GENESIS_TX_ID],
    data: {
      vp_id: foundingVP.vp_id,
      name: foundingVP.name,
      jurisdiction: foundingVP.jurisdiction,
      jurisdiction_tier: foundingVP.jurisdiction_tier,
      public_key: foundingVP.public_key,
    },
  };
  const valid = mldsaVerify(
    canonicalTx(vpTxBody),
    GENESIS_VP_TX_SIGNATURE,
    foundingVP.public_key,
  );
  if (!valid) throw new Error(
    "VP genesis signature does not verify against GENESIS_PAYLOAD.founding_vp. " +
    "GENESIS_PAYLOAD.founding_vp was likely edited without re-running scripts/seed.js " +
    "to regenerate GENESIS_VP_TX_SIGNATURE. Run `npm run seed` and commit " +
    "the regenerated genesis.js before starting the node.",
  );
}

// PQ crypto (ML-DSA) requires an async initCrypto() call before it can verify.
// genesis.js is loaded synchronously at module scope (before initCrypto runs),
// so these checks cannot auto-run here. They are called explicitly from
// node/src/index.js right after initCrypto(), ensuring they fire before any
// DAG writes. Tests call them in beforeAll after initCrypto().

module.exports = {
  GENESIS_TX_ID,
  GENESIS_TX,
  GENESIS_TIMESTAMP,
  GENESIS_CHAIN_ID,
  GENESIS_HASH,
  GENESIS_PAYLOAD,
  GENESIS_TX_SIGNATURE,
  GENESIS_VP_TX_SIGNATURE,
  buildGenesisBlock,
  validateGenesisBlock,
  getGenesisHash,
  getProtocolParamsHash,
  getChainId,
  getGenesisPayload,
  getFoundingVP,
  getInitialParams,
  getGenesisCommittee,
  getGenesisRing,
  computeGenesisHash,
  verifyGenesisSignature,
  verifyGenesisVPSignature,
};
