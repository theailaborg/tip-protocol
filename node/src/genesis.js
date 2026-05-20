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
const { TX_TYPES, PROTOCOL, ORIGIN } = require("../../shared/constants");
const { log } = require("./logger");

// ─── Genesis Block Constants ──────────────────────────────────────────────────
// These are FIXED and must never change once the network is live.
const GENESIS_TIMESTAMP = "2026-03-15T00:00:00.000Z"; // Network launch date
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
      dispute_filing_min_score: 400,
      jury_min_score: 700,
      jury_min_score_fallback: 500,        // Pass-3 floor in jury.js _pickWithGeoCap. When the eligible-at-700 pool can't fill jury_size after geo relaxation, the selector falls back to score >= 500 (verified-tier) rather than admitting arbitrarily-low-score jurors. Never below dispute_filing_min_score.
      expert_min_score: 850,
      expert_min_score_fallback: 700,      // Pass-3 floor for selectExperts. Mirrors jury_min_score_fallback — when expert pool at 850 is insufficient, falls back to jury-tier (>=700) rather than open admission.
      // Sizes and counts
      jury_size: 7,
      jury_majority_vote: 3,
      jury_min_reveals: 5,
      jury_max_same_country: 3,
      appeal_max_same_country: 2,          // Geo-cap for selectExperts (Stage 3 appeal panel). Tighter than jury cap so a single jurisdiction can never reach majority on the 3-expert panel. Was hardcoded as `2` in jury.js; promoted to genesis for governance tunability + audit clarity.
      jury_cooldown_days: 7,
      expert_panel_size: 3,
      expert_min_votes: 2,
      // Bonuses — positive (always added)
      jury_majority_bonus: 3,
      appeal_win_bonus: 10,
      vindication_bonus: 5,
      upheld_bonus: 5,
      // Penalties — negative (always subtracted)
      jury_minority_penalty: -10,
      jury_no_show_penalty: -10,
      // Timing
      jury_commit_hours: 72,
      jury_reveal_hours: 6,
      appeal_window_hours: 48,
      appeal_commit_hours: 72,
      appeal_reveal_hours: 6,
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
    },
    reviewer: {
      // Runtime eligibility gates for reviewer pool. No REGISTER_REVIEWER tx —
      // selection is a pure function of identity state + DAG history,
      // mirroring jury selection.
      min_score: 800,
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
    },
    content_grace: {
      // Self-correction windows. Unflagged content keeps the original 24h
      // window; HIGH/CRITICAL prescan-flagged content with override gets 48h,
      // matching the time before reviewer engagement at h=48.
      unflagged_ms: 86400000,    // 24h
      flagged_ms: 172800000,     // 48h
    },
    consensus: {
      round_timeout_ms: 2000,             // max time to wait for 2/3 certificates per round
      batch_wait_ms: 500,                 // inter-round delay (reference Narwhal max_header_delay)
      consensus_summary_interval_ms: 60000, // periodic consensus heartbeat summary (cadence of INFO roll-up log)
      votes_retention_rounds: 5,          // §1 equivocation defense: keep votes_seen rows for this many recent rounds before auto-prune
      max_txs_per_certificate: 500,       // max txs drained from mempool per certificate
      mempool_max_size: 10000,            // max pending txs in mempool
      mempool_tx_ttl_seconds: 300,        // evict txs older than 5 minutes
      certificate_max_bytes: 1048576,     // 1 MB max certificate size
      sync_batch_size: 100,               // certificates per sync response batch
      ordered_hash_cache_size: 10000,     // max cert hashes kept in Bullshark ordering dedup
      max_msgs_per_peer_per_sec: 100,    // rate limit: max GossipSub messages per peer per second
      sync_max_retries: 5,               // max retry attempts for certificate sync after peer connect
      sync_retry_base_ms: 1000,          // base delay between retries (multiplied by attempt number)
      participant_inactive_rounds: 4,    // remove participant from active set if no cert in this many rounds
      handshake_timeout_ms: 10000,      // max time to complete TIP handshake after connection
      handshake_max_retries: 3,         // max dial attempts for handshake before giving up
      gc_depth: 500,                     // cert GC: retain this many rounds of certs behind last committed round; older rows pruned from DAG + in-memory waiters. At 2s rounds = ~17 min of history, enough for consensus parent refs, cert waiter, and brief-offline recovery (anti-entropy covers longer gaps). Reference Narwhal uses 50-500 depending on committee size.
      gc_interval_commits: 10,          // cert GC: run prune every Nth commit (modulo-based throttle). At ~one commit every few seconds this runs ~20-60s apart, keeping SQLite churn bounded.
      anti_entropy_interval_ms: 4000,    // §28: how often the anti-entropy loop polls every authorized peer for its sync state. Default = 2 × batch_wait_ms. Shorter = faster divergence detection, more network chatter; longer = slower but cheaper. 4s is light chatter (~one RPC per peer per 4s).
      anti_entropy_peer_timeout_ms: 2000, // §28: per-peer RPC deadline. Slow peer must not block the loop — times out and marked stale, retried next cycle.
      sync_divergence_grace_ms: 30000,   // §28: time-bounded catch-up race guard for the divergence detector. A non-ready peer briefly showing divergent state at the same committed_round during snapshot install / cert replay is normal and must not trigger halt; divergence persisting at the same committed_round longer than this is malicious-or-corrupted (an honest replay reaching the same committed_round must produce the same state_root) and the joinState exemption is dropped to flag it as byzantine. 30s covers worst-case mid-install windows (large snapshots, slow disks) while keeping malicious-peer detection responsive.
      rotation_coord_rebroadcast_interval_ms: 1500, // multi-sig committee rotation: re-broadcast the open proposal + accumulated sigs at this cadence while inflight. Defends against transient delivery failures so partial sig sets accumulate across retries. 1.5s gives ~20 retries within a typical 30s aggregation deadline.
      sync_total_timeout_ms: 30000,      // §19 framed sync: total deadline for a single syncFromPeer call. Protects a joiner against a hanging/adversarial peer that accepts the stream then writes slowly. 30s covers normal catch-up on any realistic DAG size; caller (peer-sync retry) handles the failure.
      sync_max_response_bytes: 1073741824, // §19: cumulative byte cap on a single sync response (1 GB). Per-frame cap (snapshot_max_frame_bytes=16MB) bounds individual frames; this one bounds total stream size against a peer that drip-feeds infinite small frames. Aborts the read loop.
      max_round_duration_ms: 300000,     // BFT-time bound: cert.timestamp must lie in [prev_cert.timestamp + 1, prev_cert.timestamp + max_round_duration_ms]. Caps how far time can advance per round so a colluding majority can't jump the clock to expire pending deadlines. 5 min is generous (2-3 orders of magnitude above legitimate per-round drift) and tight enough to defend against meaningful skew. Reference: Tendermint Block.Time validation uses a similar deviation bound.
      bft_time_genesis_ms: new Date(GENESIS_TIMESTAMP).getTime(), // BFT-time floor for round 1. Round 1 has no prev_cert.timestamp, so its cert.timestamp must be >= bft_time_genesis_ms. Derived deterministically from GENESIS_TIMESTAMP so there is one source of truth for the network's launch anchor. Frozen at genesis (part of genesis hash); never change post-launch.
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
    vp_id: "tip://vp/US-ac6de96b3dd6a8ee",
    name: "The AI Lab Intelligence Unobscured, Inc.",
    short_name: "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction: "US",
    url: "https://theailab.org",
    email: "trust@theailab.org",
    registered_at: GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key: "511e5ed17bdadf80101f5cf768676806d4db76f51dcc5febba5ae107f3324283daa55b902b9ef2ceddbe6922e7c23f137c89be5c6bda965f15a1f5bd2f4992e14723a757690817ab13f1b4a5418165c9d457d507b86f2faa3cf49d401c44dc7bf67b3eabfb98140e38e5409f29a23bf22cc0baa460b5f7d131a9345366900220c9c9dbb7c83a5ddb4967f1516fe305bf031dc8e633542db9f4e6a900f313d8b5c3dcc3e7c9077782584a2a42b66af158a071e253fc8bb3a6bca65cc1af4f3f3f77e13f2d8208b904754633a0fb6e0af610249e73146a8e32d6474a9771a0b1f30e1ef52d71750fd66949a431bc51741578c9bfb94164ad6d4b2812582a53d3f2709872b328e5cd17137a49dd7e939911fb9f86c5c0792e06d8946ef14ce1447e257995dbeb43c28f58dc4ef2bf40a59be8a7f2e1fe2b9ebf354797f707d0a3714aea901157e79fd59bab7ba2981323da3edc220df821ffb89886b3662b3839ad559ce80889dd6b84290d283e53e9935b5f40d086c753697c0202cbb8c099e24e4e581aeadc93ab4c9282fc6c6d35654b92b074a029588fb049a2e630daefad3a2abf65a10c9c5b94dafaa456fa5b901da5fc73c879298d797b0e27322b929071034c73e6a8c772b0083da9253453def4095bcf362e10e63ef1204e9328bfe21d8602ceebe66e71edef4d007a01ef85e9ad6623633af0f93e225ffd05a8b035f066a0fd2ca80bf61a75f3abda3863fa16b4d79c854683ccb25f28f056820a53c9d3c07e746b426a498604bf600bdb4aa1c30a2ec53d00a4f01d84e3a90f49c69efc6f83dd758fe7b7982f735adefdd64251dadb2c2621110d303be1f373b9c9cd993d1ec226ea7324a6ea030b6b8af36d4ba0fae361a52111a1bc0a71852b1d47ed54e5d77b8b5d1ef8a3ab492b8f50bd44985d7bb88ce1248281c22f56625c3d02b668d387d744668d508c2e76d0deca9167144b0e1e30cf4c22aa4755c9482c8c47925bff9aec7beff2e160bc9b744a3c20243fffa298439829f8bc9d5e52a1c78ce926eaaf3b464f0a75241f2c72fdec38a1f32d652ab941228f898df15fab891e0c079c4ac50c5af2fbed4e58d76259563d0c794ba3d2f8421570c46f5200ea8d95b5c8713a83a75fa054f1d741e5a51253baa7b9a976681823dacdbf6d7d3566e21a6eade8e2c47af583cb268d754e134fa21588493133f867cabda7ca2313668204be007d7710857639b3996ac9d8df5de0ee23973fbce72c25b00c47450809451a06f8c0cec70d33b19c68d97a434b36d6263addab21983143c129b1fd282741da9e1aeb7e0b19fdaf5010b9f6c52ee256e825283199b9c13df36fc9b87c056d8262b86ee7161345cd14c0defc5fd679f8ba906a0f90b658506c13ea938a06e7ad2ee968e210e35196babb2850c4afe85363858682dbd33183797ce55188742ec4caf0cda43675f5cfe03796382f491a51b33f70c7197f47ea4f75f9a802efc031c28f90036776518a643ca311f48d267a4f616989cb06b9c23c9e3be42b767d9790e1ed4a03964d5f947396608615f308feb0004c4a82f99c26856fec04eda87d7034b253f20d58be0a31fd89fece15e54fb74d74932f0aab42c504c95a98f1bc9af00a7a44390e47d8ec650c545f5eccf2b316bf34f96914a5607cb41926b5cac40c26ff8df2d8664a4edb3f8145df6b3beb601f3247e58206ccc4eefd37bf3e676924df955431df8aa3b4087297ae0df6272c06c4c288649bc21ed6bf0e261a80d2b0e2e08ffd13be15712d74895e039dce1d4bfe4104e41f0d4f7f0c4e04268bd2dc46e3d84145d134a0f9b02f880857e76d953f452da5811a50a1437970a85272d0e6fa13769652ce29831884fd7203f17b2378427f764cea2df8d2a87aca8f4466db38f3d56496e7e6c627811378b46da50ff7cbc2d7fd4e7dc9953fa0ea0477572e4c0324e299293359d43353e9e9179b01ecd8f2f27e4a14a1f29956d0ea653284e9729c752eee6854353f7d65927b0eecd7951e5214c5d42d0fa30ae3e422cc213ac03357333831bab1191eb696d9c020f58b2c6743aba31df373e8cc9fbab58a92db6a03354caf45db1268e268b15f08c058e8f5807f40e0192795be293354d4d441b0ee35f758ecc14b47741e3c46ed4b914c7dbe07c0ff2abe3ba7c28a78d25e7e2e2192a8f453f0d3a2b46bc42a6275516d01cee34c94de97f958563f3dd886467a915f908abf225e711da2389775fc0fb2b4234035f3aded68cbe15787e3b925e0cfc6af43b6307cd4461ad48ac6c767b5845d1aa4ebefb6f8c7898b226550964bc344d7f7315d38322400de49a459ca967937e8eb18f638ea1294f607525c63661ab32c25da6762bf0f68b434f06e5a3ced4ff9472c73de29a97d989d6348d0b5e7770925a26878bf595a5a29e0b5bb0df6b693de9f9ba4b29bb78bf3fa1947d94a5fa2edbde24248eda6a3aca5fb8b7774bcd4cb0e5d4df64bebced7715668cf90fbba443c1ffefcdd9a1e4cdf08ac59294a16183bef31d313ff1f6cf1da8353ee343a0c6547ec4892fa77243eb838cfb3d95cd4f18e7d2268dfddab60445b85a24b40edbd9ea00bc6aa5a81a436bae0e82afb15c6ecbc5c313d4d805dc0e2e537b3e4c07e86a0a23b07582ffd26e49e0d5fb4cc6f1054ad4e6d238a6b176d9eee5c987d8bab794f023ffad49bdf86b9066ff72994b0073e4ab80f38f25720dfd82ada7d555b428f6c21f4494195acc8a2228fe699",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  // Founding node — registered by seed script, bootstrapped by initDAG.
  // { node_id, name, public_key, council_signature }
  founding_node: {"node_id":"tip://node/2a34e3fb8c717c57","name":"The AI Lab TIP Node","public_key":"bc515f7ea123f81e02c299e4d1ba6a77eaaaf05e22c131e3033f8e22f15916a3333f75d939010b20033761b68245ec8d2f5639abb43afec52d43d85e5da73a724c1e06a867632ac67291b10b2ccc4f28fafab7470d524b89959489ae9c98f45292911a553fa01aa98489a3af6aaa4e57cf9fa4316297eee82c2db56483fc1872724310ceb72d9ef22f7e554d719b6e78585236da384fd5cd4c7b503450847987e003d723540020dfa9e3be5ca8042cf08f32af6c78cd52015a29befbca85f158721306ef61ba50eb4ea0c7c86738adf1447b5a040fd749a57f8f447de453ea82ad0b3dac1adf212e7d43bde1f51034fb8917ba6d3632a58d4ce2e0f0f1b66f6602765482ec7fbb2ac10627031328c0094549a84bf8469d04b8b5943ccb836531024e52d7960a4e6fe6c786edb87cea1b4c5d5e02f6ddc04f9344df12db98ecd0235905deb6d70af670953a3367e4202917f3dba84228d437fe4a13ab46f33e56069c7a7563b6dd206dc4f18d6e2cd210d2c694df3b75907265033ae7003a6ab5ac96ba75b76a6069f9b87e2f85698248b33d6348306fee0e914b4cc9c168dfabd7b1b6d521ae9ea0e0bee31f5173cc23fddedf7c23c160240a25821c55d5ef2f415397158a3162d7b2dffb47b3603b342d5205e4ade8592d019cf0cc3c1a4c36d1de417c2f985563ef7904b644182391bee91748d9d0ec41f3aafabb5b513bf8171808b413628b0b78dde61d2b8bed2686ecde3ec4dadda3c620f3f0e60bcea49b394aadd73f1bc469c11d9c207a1cdb5ec5f78f62d1ae74def3db048014aa741817db75c42eecc46ecdb39342169b05e2f668bd1a045067bab3c2170beadfd03d8d4a66f19d2deb44a98a153322efa0f67ceb6a0631dceea4107e995a404a54fb5dd6a5f5e9d1b852497e76da6450a93a1329f4f6f9ed1ebb0318dbd5d0d40d2b75b271145f9ca9c6c9f9edd45046fa901c175aafd83c75eaebdb71ee317c32204e88d6a3927a62d7879ff71d1126aa2ca0c4a836fbd78e9531357476af9913394f407a3279adfa47f5ebfbd0d9a543c00034b2db43afde8cec80df9151783ae0bb89b629b38d12f461e4b5f5cd1989d8a762092fdfce9f27f0c4d2e5fc389ad13d369fb5b174b2729feccddb3e9c933dd9b63f1ea6a898f7308eb2f07fff36a3376e4b045353578e0f6f30a5c04b1143921c7cf990e1d50fa2a54e666ed0f05ca0449e0f87e3923b17748394eb7821b39e624a44921105b5c6b587c5995ab5ea9a9edfeb8819502dae163de7e097e081e98ebd86ebb0c977d7c4d575f00dadcfcbc41bb88a3eec9a0dd6d5ccb3e1247ad8b5329f52b930538ff0e60cd863bae0030feeed82dbad7c6ac9af56ee0f461fa7f1150698f93b4085214727463066861b36e89462fd7a62d3f17a178a1da3a0f57c186482d37c19963584c03b2ad376cdf00e05817a7c5ddd105fe35263a3a539689502164c7b8996368c3ff822ffba879733b7d39012eeb2698f1fcd31867005c0c2c4920612fadb66c27f170499f8afc4c9829274a19c48cec05e429eaff1aa7683cb2c30c3150e634ad3ab72951d5ea9d666c7638181969185cf312308bea1855792ca1039ec65bbab1e0a0b7a3003b6de37b96cd529e67f93cb37cdf93cb1ec3190839a498ef95a9852b6a3b03c2dc552b8dfd0705b4cafd03197db4a213d6b87ff58aa396eccf42c62596d6612cd920986b9d4a7fc2640aabc1fd6f6ac8f797dea9ebb713665f8e042a335ca0ed7d7ba17c027eb3beae8fe6ee3d6d7d0aecb106fd826ee15443a3d27656d5e6ab2d2288cd28456e166014e674587091c872f48ac3fcdfa99003efa436f134e3a7f2a089200b503c593fcc0842e0b58e8baf14e8ff682dd180a9b47ec80ca397d65c1776c2e284173114ab5eb07104858551c34ca63f7b11f0f53b93dc454b505f2bf4ee294e0a578343905c40cf5e76230c85871c9d7c75cf81f4c42e5ccac403f5bed0bb5a705f9f72c57334207064b3032b208d188a7d5a631a36796151ee869c22797d7e9ab8583b73c24c91ee125414e58d3b46305b856b9d311d68de5f8d066481e59d545b523b6ac63d0b163e587b4cf94375a31ec22a253cfb38b49b442fd91a1a6f957390a343d5f868696a47833bebe5abbd9fbf5932b3b43a20e655932cf3a6b8b2c2314b87a7fbd142527ddb40be0cf192c4db8942c998560de20dc56ad1db2305e68c70b9948474b9921a3967d60ba61470f95bfc0ae3b800af22f31fe86938229459fd099582ad322467b70e95c7a2e8eddb3f01b6616d8e0b729b2b9160cc8175cb026465281696f657a4d0163ec28a859ccdc1b3d3ff44cd90f63c2284314cbd9270ecacbf41ef4cb06098db3207714a353d59f5af06041990e96d77a19188257c6a84d1892ffd854d74e1ef603912e81dd5334f9e4326fb38e3e9401a8c6c07138b43342a102bb0d0b421745f3e17d0fbae20347421ef55c64ddd6b40cfeefb78c3986fe631b0b8562e4ef23839bc64ec9b026007c60c7602ed045b2b9e7b20399be0eaec533a9bde3943dcfaa257e0e803478df93eeab0e11525ca6850cc6a4e87b7a4264f2fa448fd0d0d2245276eb4c290b1683dffa6693c3645790bdfde5e713f7d7c1528d31a61ccd7dd81bbfe109d5d004d8776ceb3a5a89121df77fd4a044b8858f1d79ec88b0cfd51ed723214cc4a2b9b9822fd65735a44a06b722b380d4f3c0aa6cebdf0c91722ed8783c13c6118d8f84d5c0","council_signature":"c22994cced5aba5b746b85200720d083c6d9c781609c8d7a26905524fb0d5115ea454fa391fbc5a99bf0ad30dcf212b804014d3f4682aa2564d594de673c89e67794cee4c4f012b1668ba28f2f34aafbee08a73d0f2d09cd4f0a53f8ac750e21e0a03c8bd221ed675e76859aff5a6ff011d8323f31d1055c121559fe00beaa3fd2752ad7a13784279871f43b1f65c0d3b0f8ac93074e00ca75487b2bfee03ff0117ca3269f017443d1f8cdd38f69f28840f93a6e748dd899acae54036a995d76ad76b6a14c190f19f9af4aa7536152b9a5123ca6f7ed1a0aecdc434f4afc9d56d40fa25140d81513208cb056a41551c985c98dbd72d5b903371fad42a7f7800e50d0507d1d44d8c3eba14257b80a1ba1400acf7a05d578da993b82c020ed150aeb43ea597fe475c508bd319c4b9633ef1ab9421d952ecabe1e655fd02f373ca6aecec010dd883e8838dbb35819f1633bcae82ee45adfb3b587bc40766c2a068f1acb4652d8dabc554e2b2442383c525b69a67c015a433a75da011bc7aeeee6e58594b50e8dd72b90576be28a84921f04d1e09b73b23e33f34ad4b71539e01fb5ec294974302d8c5a65bb44842def046ebb0291930de3b6f382d94ffbe3a791a3b0bcb53b9ea77f74c84a4922bb5a31dcf03732ec5b0c2686ab2a7f9f048289347570f6bf7a0ded8afddb2b56e68fe262ca9dff85f19bd65ac9fa8fc4f6022aa8e3a5e862cd3e4f7d4a108ceb7775096ecd9a48e5718b9ef2049092da78c2fb86998dff4e4c80558c95c0a46bd6d3c98d09dfe7178ab52fc1b24a30597e973b6850af0a00d194716224198ab2c752f6ac3dd063535fc81498b4cbc3ecf40bd703a1ac1afd5932f4e42ae74a67a2a7d57d5edcbc665365699092307571bb80c2a65684341d958631eb9ed91a80b202519a181d6a090023202d8486b2f605e637b37fb4016fb7d4fd633f400763d94f38d17b595b1baa4d8d2e53bb1f22fe0047b3429078c4d9196adf25db4f20564cf36bb712568008c6778f52aee2ecde148325f9eeebf3d5504a082d9ff550a5ce3c65deacceadcf013b0efd21c37851ef89eef1f316cc85306fd0ef21be1dcd18f7cf07edc4edb5e8134b1678e24a3c18136a7022e8b2419edfac9fba8ff41a9f38098368b382969db66d0f2bfb700fc8ef4ae6e1d6d3af3c02cc590b6e090eabab7a952a0e40f78ca1661ccc04af9c9d6b0830950f80b71bb58dc47393407a59b1adff0606f0e50c4ad83fb0e801c23a9f7248aee9e6babf3798637bcd8ece20023337f79c5040df2b6986a8a43b619997a3ab9624d05b8d0765213e00722b541a2ea9bb296f912ac59d62a0b8e1f18e4c5437f34f5e40a61da9ed3f6c0ee8e1d8af8e71decfddf6443a37e8cc3c986805e0a8d67804c568bc815d4eab4d5f567d22df211691bea7be432718bb889899bf35b6078916b699ce4142b569dabd339673bb501d059c775cd0b76763b0d1233c565cce2258027a439a21ed0e1e3b3889c0db832c0d3155a2ca9c72f11fb1d9316c1c54bfa2f293bbcbb57db274c5388d7055b8a827bc5a9683f3f362c85b71d1563334c8a304df2f4dd0687d01522958e271505a89777ce82431a06a73d8dee01dcffaa5abdee2b26707237ea0451f2f34526856e58aab0f3d097fb9ba96a2d0756648a27f64de3937b24ff10c44835b775df0902896f28fd048e07cedee2d985b2321a5e93d93b321157fc960666177a8b96c9fbbe29c3c22935b0d00fdd5e315f8470ffdf71b639924298986447f84a7db67c8792d6249769e8b8af4c4ddc70740e878147f5d88912f3200655e541636297513a8c847afa7498ef89122912297dcd2d8cc7d81b4816ef45061bb2bf650564c6b7bf8b98e6b1452473222e894f5f047b12d3e3157028016b97f1ab5bbc778e45f4a8879f5210b91e8d915bd1137273a12838c17d0e563874595009d102a7e28e849010160ec21d1e4bdb7c5cf907bf9a0c34ac9b38c172b1b134ad623d23ff535d550da768243354f9ba9aa10fa55d74b83a2fecf3b3de98ab9d0045f8a1f617de238a3d761bf0ecdd36a80726cba623ac41d202d99daf3e5a619682762cc6da8c4485981f7ef2ea5f0ab739f214bc6c7ae47e34970dde3b97283cbe0bf16525d6a5c1bf614d7f7d35fce49e82451feb1740e8bd7f702db53c86df011cd3a455b8a1d7b9cef5e72a6e1bca3edd63325c299101eb6e275348ffa6c640ec37976d0a3ef31cfbf39e6a42a7db976da8ef75dc9c3f5894f47699112cce756747dd14c7e6f76ee5a0d017fe80689afd012a27487c320eb0346e6b5e01c4118685b152a8dc0c2f981a034cd33a49731e2a942eb3ffcab370a290bd868c6070a898c9237e101bc89e834005a1cc4674132a2f13c17c7767ded228f4c661b6f707355f6de3e263fb4b7d29d616595d4faf5eb6eca1bbfcaa14b79afbba082b20222abc3a07ed4c16ec592872b154145a330d10bb3d77f48fc61e613f47873d34d9549b6bb0cdfb4d9ea447817ae5ccb7df3690b22da30194f13ea96f18391924021b91c187f281ffac757a72c3981f9822e228000d987e98d9c5ab278642a2942fc2040fb4085ee1d348fa9f58887fd81331c4e9997a2200811341be771b425389db5eb80d7cadbcddc03b0e72281bff77e8cd3a077f953827f781461e4f8476a447b3c8ee8780a006957f9c0ab8ec346ff92370c44122ec3234965cd8c4cf3c40de52abb5da8bf96a2041af4dd3fe638453bbb36d9e33812728fa5489fa2e7217efe75952f83b212a2fb5ce1d142797a70b8301ac0fbbb9182fe8246a81f564e72b702b77a73dbc4738bd1e0adff9eb9be4206330e9573319a756bd8e0da5b7323cb8a640791714b425e38a43acbf199b322b40b8d442312c8da90f78127e073c6318cc632a07034286bf5821fa8bae2f82c7069573c8a3a50c758697e039fbe43a23ba7779fb52f823eb2e0820bb4e20c30317709713d4012c8c31446aa9b5dc59d6d86f2d2a9d2fd86b3d534b92893779e7f511ecab685f2a89e99f2f2dacc7336e381ca72b7ce3b15ee890299b732d796e3ae9ec701b293f70219e5804579b1f8ea2b0dbdeeb40f872191802862d5ef2dcaf7cea757dee810bce8df904f618632d1e17f47fa129822add09bcbe5d3ebdffe3408a261d29f7f2929bd454fcb756197fb1c78b3c207cdea0bdd85ef0d4b6e7c8452c64884531a5ba4407ecee75d010ea1eb729f941417501d22f1115f5049a43d68321efb25e5e5ed9d305cd80c7bc35d12e8c349dd15493544db2cb88f86da48b169dbcd32020c72125c373769f0c2cb577ff59a0ee58a11a9d69ab7819e6ab6a5cbcdf2d29712f1c94309afc9e9ce6dcdd0ebffd381166ac6e27b34b20b85e1716258a922ea4903c3f0e3007c47e0779122d38831d759f631bbc1410ad8be71aee717a5556ba91fd33a31c4a449c4ab6cb6d90ec940607a44a4965f268baf4724ef03ad6e04a8603c9dcb35876152a016252f5737afba818078ab9e8ba3edf674e97979cf915d1aed99e37b2ddd757cc5cd98c710528add50f9036fb6a83c180d07520ba96346a960824caad6ce5cf9f6346ab96f2cb0a6d6a5a557fea6e5f5d22eb001ba39ece6a2515fdc6fb1ac3c5c4c18c4d9298d1ccff4ca1354d1ab00582f22246b300d22c4278489c223c0d52f8ad0da59b75e0f2ca4ad3cb2a453fb9a6c8464c41bca9f3da0257e2934b0f3e1524900f1d9e3d1fde3a27315195e73aba61995b8d1be95e97e14eed275b5770228fc5d1702c6efdda2e8440a285bd0245e9ec3c9390858eeea069acfadadf1f9b8c2cf748c143e2744541d344f16edbc10ce2eb5f659c842ccf1b81795004536de6aa326cb8d9c533be4470c8de431111e1145d338af153edcd9411b663299740677a6740450ee47f911646f2690dd26cdc19b6e5ddf6aae807281cad48c33b9de9d242d92e1fe51e854be69b986a0865a97a685ecf6d6695c6a4e42cdada5ed8a770d8207416c79f083751bbb923b5e2a5e101b8868df02946af787bd2041a23265545ce6c3a1e8c674c4ee6b76ba948d09bb383a88419922f0e1d7160ecac80e1c75d68300f11422aa39cf057527f277a1049a88a3db5f8f18aaf0d6952999314f9189d9f60c6910d2141c89521451fa8b5c5ea7bc73b6abf664e4d371ad8ea2a8e4471dec688560ab3ea4a2e0bae7300849ee235f4db7d7064cca24154bf063a9656fb710d0c6d4b1d6affbb68d520d029c479e3dccc709328c88fd3aa77252a37f87e1bb6ee41512333d89c659292020de0272cbb539233a8ee96681c4b0189ece2bee83df4dc4156c8d759b1240eb9a89a9179121fbdcd64dfac78ac0bdcb671f183d6fe5674b7cdfd74966c8cae71fec300dfe786f2e73ca9eb483d593bc21e983712d4485aecc7ad01e864989946586c59148cad3484c3972582117cb32544b3f1ffba241d0482f1b7944caa7873cc79ef1055575a80be768e1a887e52805fbb47e9490267a1bed3513dd03fe956abceae54bfff33793a58b0069f1ac4c6ad43dffe393dbe5b469c3f2b07230d14741943130445ed973297d253e759bc9e80409cdf01011204e7bda101d5157587fbde8f25f7d23a1c3ccf50000000000000000000000000000000000000000000000060a10191b20","approving_vp_id":"tip://vp/US-ac6de96b3dd6a8ee"}, // embedded by seed script

  // Genesis Ring — founding verified members
  // TIP-IDs, public keys, and VP signatures are embedded by the seed script.
  // initDAG uses this data to reconstruct identical identity txs on every node.
  genesis_ring: ["tip://id/US-ed49a7c2fecb330c","tip://id/US-30a9e171d0fed5f2","tip://id/US-51c020baaaa6155e","tip://id/US-302fdb95ca8d2756"],
  genesis_ring_keys: [{"tip_id":"tip://id/US-ed49a7c2fecb330c","region":"US","public_key":"b0a45fbf9f81670b31a736ff8155555d6d9df43c504a07c2f6bc29549d941129001bf3617abe973747a44e80d1cfd1a5800495e89b196d49a0942bb0ea4eba89fb5b16edf2edf2110c69234194cd66b150b779f606206cbea078738bb38c66daafbe771c76f6a84f23dfd24a7a921adb11c8c5849550adc20d3625c165edda8ff51b760150ccbfab66d6f5b2e739a1c57c36446984c2f552dd64f4d9abb8383956abc401db36c3be1063d220b2d0c5f9dcce6ea345d93e3788ea06adefc780d404c9c33cea2952be59e2f10ad8f074536e75e8641b162d90a77f6c9458e9568bd63c837e39cdddcb0e313e12e5cd0dda3d0c047d59a80195897e1bb583d93f3d18237e3ca9201886cbbaba8e76e05a472b5c8ea9db701c6fa0a031b9b8dbf861ed6080d10dde6a6369ffdd2be3a93f66e8617b4ab74cc37de8ea2b2a4adf3cdb1d4246fec8b532493894cffa89b0ea035b49bf1b751d06f9eb821cad40fc85fb270ff8a120f2f94d478e587e49051d165afc12169620447960939ac9a93d3cc4f6c787dd43c356685177544909b1825b38d2009cf1c52b734c43827a06ed9fa6462c209c8cf4e9ce0fbddf763e64e0e9e3c33b084bba8b732796bab7cd91b07841ff28261da6dfecbf097aeea03e09fa4af63924565a307ff91b64360e5d65dec1cf6a707e54fed0266fc534b9b0f30293607c5cfc34b25b29f2c340e455ffc343a4d4b071f1c5f9fe3655a8a22c722b4bc7a54ad576f80bd88d084f3b4b45906717526daf4fdb8e413a1ea559be990fb02f883b8320c9fa0c63dfaa3af5b1c441f44d4a516c5b629d10eb4a9b8ab14a3a452ca62c6581e32e69ba3b3caf55729aed82fe2a6c6699586930be6a2930c9d9bb7e3f296edf547d81e44dcef48c33013a86f4d9580b9c559d54bfc541435f8d5fb25f6865360083eab3243dfce824d1ec0f7351668fa78ad817be68da73912cdf68a8b49c9c86efaa0442d794bf2e82725cf1db577c85b7eff827b8292d56704e3bd0da977fddbea35d3c872ede6ae9aaaa614adb11fbe642519abd0971465182099633c53f567320033f6210a0a7c8fd1c69ac231c3904c55004c3933e21c5c4d8deedc2e7cdcf295133ad41f1f88b4499f9e8b1233b712579055d99ee0169ff21c74949492838d3ecece4ff4895bd70d1c182a322fb4b9a07aedbd688653461b65f5e9b4a4d668ee37577f46cff35dc31842c9a66c253c0e1fdfcbc5aae6b986516e97f43bd73ab120c539d11f67f02cb59d3c4a815658b6a69dfcc07595eb7188a25b70d98df489444c2a09136f189ff215a7fb6b100d45df9398de9deb23944e3dcb98f4f80b818bfd0fef8f5cce37f791c88e4e0a6297d5f35a52c27d7a872e935c71a7c5c38e00bf100e2f298f50159dc092bc9fd44aa9c3f01b339e2e7df8d53553fae3e63535d8efe2632579623f55fe750acf3b1434895de4941946e4965cac80f1e060dcc8c54686a3a0161910e2b99271fc4f53210bca7ca3b1969c5589ca64178f4ce07a0951c4e73e09c8b9ce6a5c6260d552ca502a923efe02519f21e58f8cb2bb4d4a26a827424dfcdfc0263d336207f6c3924d818550138d6caebd960c2a72418c5a3ef2b432e9cea20615fd9425cf20b187a885588b1c26ca442be3dc246d680dc5957b93f0e6ef4c27c9f4b18719fe092a0a5b0d827dffd904ca7ec7fc90a90b6217886ef528d89b6fb879d8141389a0553f51501377be929ae187687e62ff1ae459b190333d983f7d490b9eb3b0def346b616db29a4850717622b84ccf93a442f370b2a44335893811b8ebe85556806b2a39b7f69af3c5a3849e1f93b371ee57f2bb6cdc22023a67f6f2568d6ec806f78affe7c28c2106c31b3cf412c82f79ae67f4cc94978d6610bf0075a56d60d2a89d52ad6df79d32f55a23f0487bf7e8b5ee5e54d1e55cb198c300aeb3a05aa3fe996c4cf1dcc954da12acb89d27a684725f3c855cccc4be8a30716be066ef05aff9db238fd52befcdf02d1ba3c7f1e819ded553af05fcf140ecefc6d4be4d6d8529d0ee367d85022b90f8b0c1132a398bf7c488173681f5b0d32c54029277f62027a3221b0974f9b15e5c8277fae6453f552c5896f1fae690de64839bd4f3eeb556d3d818447e815ddcafc9e5d171eff8df945d94407e5176534a96cfc2181dcdbffd15bed5a723b9ba38370c8823fe5dd0bdb6f0561d5a9a241abaf48560c3872ff68a635063c36eeb16bcd5003be6ae8156db19ab4d237e3bcda518478f0d94b0b495f314bbf0852ab40ba161d927cfff7dd36cd66144957101ee881fa86df59508d57b2c3d3181e826f0dd94646fbc07d446347578d24cba3913457f9aa33a0da1b78adfd2a9a84585609f988882c72a1342d415f6459b42818706bc2239abf0e91fd31b88996f99f6dc1c9901a344b3bc2719d67e71245f31ea0f193594382293ede01e77595a097268b6833da85ae478d9b4393c8d9c3132bf4485463a439fb242c3802629adbb28e8a15a9599374444101ff723fac8a375afff3311e70716c374d1aeae98549acf67be291fbb86bc0e08ced85942453bb38dd424852519f837ec4826ac5da115f4944c8da91adad7f26e04f2392853dafd8fb6dafb77b43e1f3b27b0c2ef03f26e8824100db3b5ae440a02ad3be18ccba78d5ccd2e1b343872dd6431223feff78a24007790074f7bff6491a32b6e0c6a1c613e09182bb7a9e643b37957133a772692c167474b47693607ac4f","dedup_hash":"92661839774354454942","tip_id_type":"organization","creator_name":"The AI Lab Intelligence Unobscured, Inc.","vp_signature":"a8fee82e35fc453a36d1e8b684bfc67459f0005db5a62b36d9be0b8ad0d6f0f175a1e9b731d1d7e902bf0e23758f69fad6af280e374e3510a6fcdba90befd0b25ae615f949a6c0277232d424177e41b94c020312e72cff86936a8f25cfba8a0dabd9e1c098eedbbb83cd620c11a0afe1ae523359fd2c5593b84189757337a080013f7f34a7d1dbc712fcf09127e1001abaf34751131fc6c17d3090158283f358f46bac52b627665579f8e7f731e5e4ede70a82a8e9a46356b4c874c4fc805f6623283d7e00cd8fb22bc9419ec58faee91f1c357e59974845891139be703b0055488f1c436802c0779c872a0f953d50a9edc8a950cbbf58b4ab6e4ad1b365bb211a2f9f4158a8c7cf0502d57240c48249766c2c176e78dd78f0714ea84e4c63fa10e57eb104fefd8bb23a6627d9e0d4fde0d4c2594ba2ca94316dca55f943f97a56af49a46f5a93022f6def48639e77973fb31118d1c254362628bce50fbee1de54fff26d701d355f71696fa26cf7411f62521d08360080b9c6aec5656681d9af51d4f7c69714f68fd7e3065600797eed6ce0819e0a955550afe6ee2160f42ca85b4163f2839a3397461c06d17deab3b2aea00d32b41d27b5d56219970d99da8263703daf8d04b481a48616321756cc9f4273b9c7c58f79e438fc4c69c0b752b9b3152a755bed308ff6b6f912d0c6db9eba56d67237c05ec9938614af06112dfca5125580acbf203dd4bc390b166e04c9a812b1aa5b8b93d4eb57d2b4a215277ae4e35a1237fa41eb7451742cdac0a1c294ba145c66a83179d85c8e7b34112678ef32551d61b9a1dbbb1e3d310e73f8cbfedc41e8300f4f16d131c8c4f0bb154cf759397dfcd7bcc90087cf4fe07fe87e1c98cf08b15f484f9f315b769075a6328988a8ba6212873acf00a6b43d83771151cb2a375334fb341807871fbb3bb052e187f1e08ae3ffe256b2be178bd84ed22272aa7d7278d1f6f6f080ce7e08d41d4783216604c67cac7ab34e6d1537a32a4b99857771ebfbf4c508db182d61fce289ab6b380851b6807d3111d16f4eb4d7ee767ac487f9062147f324a6fa65ad340de3e867b29e1a18d72df439b10fbc804ad7ba849f401eb6b64e7472d100d980b44fff59cef69d63865b4d453a9bee666c047066f3c1e58b0bb9e824c4c5c6f6c6cf6c6542ff73971c8b7e62378e531e83cd5582a2cf0eaf8839d60d3e935cfa55ed9d5fa1b0a28195f580f6c76021373305a425b70280c121a74e3efe60828cba6971c7eff05b725e3a08aaf36cab793907282fefab9023441c86e0d3e5d45a7c3eb3aa43bec8587ce4e2b3b9738d0c8e073999f132282f64c882e0949ba5af525d671e210330a6cebfab8a786b4085d49bf82d05027045fd57a9b61aec3dbfacc708731f8822aa47a038228ddd6f6a50db73dde545db185a6374b80c1de53ed9bdac9de861dd744962ddb1e1aed6f778225c04c1f096abb5dd8368a00b31346cc2731ef3a0a690cd1f8aa3934c0585a167b351e8e09572416f80bdd4fbcedd6b6537a6071e0ec205ec509fe52ae29a8ab554dec892aeb86f14dcf80df38e9acea48110813c522228073c5f5559916a5b41e866ae311f1327c7775ac571ced989cba304c3ce5aababc7e9583c6a65af479bc777cbe5141a76e25ab95d5849fbb591ebed6a62e3f9276bb016dd1db38090ae0b8b24bf8f599f0cb6d29143e7c3ec02ca8a6c80c391e065b0e956e014d7468ac78c83ea8b6d9fbe2cda3957bd13df5a3078b57188787846e86538bba3cb536786df491f1ef4ee113e12e96f070b263b2db7a2eaae3ff04836a77b036d4ff46b6128b015aa3902fb952a1385465f61b11c3f67f5f262ca62a758c4ddbb042b8d7d3e29dff4d77f51fb8d6aed9147867175c1f1e851e5433961be3db94698c08a0a1560ff3e526cb9d91f15335b1cbd11f897220e405b09d93f63e17dcf29b25a1ac7f81613f11eaa49c05c82ab5e07121a60c60f7f3fc5ec7e316b6acf3a2167b4a49d7034d49babcb8673c42b478076bda73ec80e48c7b5e3cafc8bbcfaa990ae1f3ce3aa965d651c44effd46a96c90076cc359fc419bfd1e6c76141aac66047a3f946807e1e13f731ddecf0bfbd2fededec3b0e65632a2b176f4371bcd5fee67f01647372eedce86b225c5feec3bcc638850589a61086002ca89bdc7c5024584ae2d3f9a0a1cb162caae51657f8498fbe3e71c7d949baf6f3032431c35f23e8cbdfbdfed8af341c70f2c45f8029e36b463713a6793610c4a4404dd0e9f7d77713754a3b828f97d3a3483765687d2afc350a1f149ef9fd418800111c06ca38b892448414d7cc36c3e35748afd6156e0651c62a18106b4be6197216e18baf6a8c75e1ba972f3097030aa69bdaad80d26c19660712c49364db87c781faa52b2af5d4873045070fa650eb748a0e21c0d55e0c8fa0fff4d91c8cf2f2adc76b5cccac401601e37396932b04ed6b43d9ea90f2c148eb110186aa68e67b223c5ab018a6bac19f50ea4de42de9647e77f228f9fe46f5e1fde3fc0b569bb5c11b0817e27a61fba26cf51e0228bc23a791245487d501412c34215896a2b8f252033809b70da18ad3a982f9ee107b31011c9aaaca9230be42424d6ceeec8f6bd86b71f98003e04d51744e6f937ba74e169a85141270359b0f9764fbe2d0cc9ade027c61d3101b67393c5da2d88970bd24b0d115344c8f780e286591814406908f32a52f4ededbd3f18eea54ed8cf4d7aa5b1dcb127e69598a1e5fcb9e10dc8193cd35ca104b42c1c54697779070d4b9178bbbf6a705ded74e62fdd9f2708bee861a3caab5b3d1ed1741d2b05fa03322b04ca67c1f2f757b66e3ec47c8c0caba982b02f83c42300d13ca0beaec8d94537bc81a6478e4106cfad099a251b4ddf8238b7d7fba0d73497766cb010078f378a07ac162e03588fc5349df7ab63ec6b26cd66149a70ac6f96ac59adce70e03225b1970e136480c3103b3c6fab40ced2764870f52a4a9161f0b961181b8010433678196301049f4e9a3b2f2edeb06a00ac4747f56e309762c937c66a1d7bdef48fb2102b53e07807b88fdd5840ea2bd7a575251b77d90f8b2d2a3486e68b74a9c68abba84a06254734ad2134b965c214fd1acdf884924c722580c23384526498c520bed8e85545d6c70b23fac74d0758580458b3a9eb3757291b95b8a59e02e016d2fb75b49a1cf336a1b1f84db29e27d810974953eac29c5ce12f97e8921c3ff8ffeecf36a9aee6fb33fadcf6ab14e47bb24dce1701fa6e47942dcb0f778e13f4a0917fe27fe7c39e99039a7d02caffac3cea04899f2d030d9a12e5408b02e9b6d111b68a4a9e2fb5086cdcc317fe1a6b58f54331d8bc800effa28f187feac5c8b1c47c72c7e5e24643ea6ade94d6f362e7429a40d9bfd4d426fad24c1ddb2f8b43616fcd5fb7bac9aff2a071eea04b199d1f600be328f7582a2e6b325153395ed184169b5bc1f5bae4c43513d569344ab23441b7adb02a81e18ee058c13bbedc41c198ebf13481f8c41bfdcfd40b9fe201766f17b7d3b7b2577ea53e409a91f6217c5f743d63f756f63dd4164c8afb1e897ac484286532c3826a0348d3adf128b66b6f4b845876546e92366aa8fc6b384accfcd8aa5a1b7dc858179d205b8b05130b448c1f78b5b1ce2db1f9b24057d5219357a90ab4f525a5ba1d9252a30707892c933046399e4e898ef9efa4507a249fc2de985935ab09a7c995ffc954e10ee1f41dedbece1f3962459a2f40367db370b52bcd87f065ce24d7f3c537405d3ee641a4bc055899b7f8ae92bf516c9d06e5797861736776aff278b5104ee9d31a3e01f28b30ffa37b0a0fbb20df4184d72c6a87d3550bdd9caa1a6407dfd52f63e406fc5e91e4cd3952fc0c9d5af8b51e2e45cade16a445793b507d66e1cd403ea7e9ecebb3cbd151c8625a8a5af5cd92c288a4ea6644b52843cd4471c70c3161cd6394e102c59537aa7b6d6f4e0a7e6c82593b5636c3bfa7a7470b487ae35c85e3962f8742e974c0e75227483667a0798d8a3eed101e93230e5ea18d22b4535912abdee0f0801987b08d3b270b3eaef741638b53f637432db36b7025b3c286e722b93debaf5a65bfa01ab7d4c6ab745381731e58d8a9355b411490e7ce2227eb4bacb1d1e9504a04e852d6c9258a7d69451f30a820c1ef5cc0bf53fef74c8d7064bb85a1bf5905f59e6527133666cb6b29adbe9e1e56ed3f0b5848a5d4832f8eb8779b3f620e52a24ded23329ea86676251f1b452b186de33e54a51f5eaa23f933309417b8ca780c7351690dcab79e09973ec676d1f879551c1471dc4af6baa18e100b591f61a775cf42a4ca1f5fc115a510cd2018ee90a0c5f68af46d13e0fb198c46a155b9265beb01c7a84f82f4ab333844eab01eb4f1e71b873b5d85d220e9b04dd0f435dd0eee16dd4f1227e94c379d9ad27407ce374faee052e48605bcdaa65784d02d45d939732658857a59866aaefe1093fe09c3733b3e31641eb7fbf61315bd34bd2f75c2bb096de0bab22629fc12cd84c64ba7f8c9e932081654eff7421e31608a448734e30f095a50a08e35c56d23333b4560b7c4cdd20102346f790914869fb2b6c69dbcc0a9afb8d1000000000000000000000000000000000000000000000000000000090e1518191c"},{"tip_id":"tip://id/US-30a9e171d0fed5f2","region":"US","public_key":"af99c3baa23b8afe67fd6f271d5c57721acc6334bbc1ebd602ea6932ef585a0d2cd71af2306592138a074f0ee947ebd70ad0b4263a02b475f8748d2e66ed6f18b3c12893e937230792a7bb03b0609ae5a1a99c12c146da79aaa1f1472ca8ea2f2e21aa82df9c6ab1e5bd49c094b819e0dc3a68e48538cad502f98ef95cb57f76860ac593bd659104a109724c23174161d7bf6d4fe43d9762acc03dd92fa4aad8f3b569abd3c5fa2be34d0b42712cd83714a5cc218aef8a2ea059510e0a022a4d0887494275b2900528c9e371ca75a6ce98d508ca01826423427690512da841375b94c1bd723b7a6fae66ad0fac9393d0e671e414728a01650f8d3efaab1b7578ea729216927f8f649da972b34a295f71c49df8e8c2da2742763ac875dd0fa1e8400c6e1613feb15147650d3357af8f6958e25893c9bb29bf944dbb642bad67d7a4d10aaa8155467b72d013ac5e8278a1e0d1deaa98c84de9dc1b60e607b97385896bcf7c8f777dc75766dcaddb00cc3643b341ed164d9ac77486d10f2724202ea1993840d599faf941101eb22757ba3af90755b48a6c141e6aefd50d7db1cfe33406a12793658ed9c289523e5592daae2e9c663b2b109d6f5c9c59f2eb8fc5e70b9724235cc8e94e6f17d9732cc6e4ffa6f96f99619f9095d7949b7f5074d031fce87ebeb694b7172f0f190495fc72683ff3686cb59ea1407ebcc1ce58d29ae2863906df4aea8a239514a518a21b6336b975f55d602ed529c9488b9e8dd70d5ad34f2b4c13771e273f6be3ae8aba67a55912678ceca92766af7f7287ca53c7254d203402780eccdc72ae3ed691926836978519b4c1bbaed1a0ac1481ec50ea3436ce13e3aebf3f35046c5cc5afd0524bbf1ad8f0fd606f7256bfb5a738a27d3388c49dfb9e381f1d4a0ccdf712c747d9a8d27910b5b19775aac7ebc157f8d402f3fbac87ef162f76dbd67d7c34f88950e4b14901fb790bc70e1c3bcc2fe39fd9044816a1c397576ccfa9078f717e226f57da26b881923d2e1d72b14889171823fa34b68d65e65e1c24420777c32aeabdfd720adf17ba701db666eee0fb76575d487844e93551619e87dbb4b50f1293d48246bb8bb968f75cbcf1b094736f71c750e1ee0d9ed22bbf619f9e81ec1cb60eb3f599e0fc62df72c1bebe615c17b128eb68c0472d1fa9a2e940e1f749c05864ea55d36b819bb045896f88305efebb2ef9367b2b5c56670525b44f3e1fb0b60befcc7a0594285b2c550236ea903dc3698c44c685d2525366d041ab33eabc96194a6b9b9f96e572b8f02d2597e6fa725d1a4a4d999a61ff518a6d2c24bea431564b3db6728167323a20d379b2a29339d5b05976977079ff8588fb87679f3a430f401440d33e6b7d46bbdd7dcd31ba124d93131e308a02effbc4e9cabb0b5b6f962a52f1faca28578f00f3114ddcf7a8308e03d773ce77bb5b36475d366cd3cea83d0c4b46497d58b8935fe594b04ec5fa9c036eb50ba8b5fd4c8470e5a1d58c05fba82c514b641f46432d5194ffdb21d5ab0e96ed0252b958af24c75e5eb119b59be46ae49da0e4b81e4c238b2d567b3217fa44f1273b3fff8518f270851c2da5ddd74b84a9e6c6b2769744a2c9094a775a804372c7acc294deb8e69ac0b187025ca178e17d48e861b49c38e5b5f5988c5766e19a35b04caddde8d79e0f157c79547dac8308f25e17302bd3f4ab77671ac410b26d78c3c2fac2151fe47c43aabc288b448f508b6ad231e6fd38b0eb97ca213e10ba9836e7419ba1ff5865529ec820588ec0004b5528c35994f4b7121dbeb76a20564a0e7996d1e5158f39e7626a8cfdcc54907e4a6d5341ac36ef9cd2914a4a9da4de3a97e355ca4033dd7293b69b335f6db8990e6229a79b3be9aaa4acc0c34d357e05078495c197802bf0a45b70fdc676cd51cdce3044635145800a9b901f8c7a24ecf8233655e75a399ee709522571a1ff3f615ca3fd19573e5801d856f9d80cdc83ae48581450200074945e767ee0900305eeca61915e6297d12a88baf15b2d2b762fa4bc7c6dcb7b6872bd7a3d20c117d95881b33cbb0f5052621ff8b79c1271eb531e28dd04541741375885b5b74bcfc024001b548de5540301403e3fa03a14800130a72620b65165656cb9956f0646f5c719c2b575ed467d8014920f699f85699e496bbf9d5f4643f1c32fad0fed26aa009dfeb606141c987aff3e07bf088983dd04c73ae5f73287dfee157d5d7fea2e3f0b077377fbaff3f8795a234c63e82b4d5c47e3af335194a536c2a9f85075d1574816a56e99226020445d1f96092f17d1392362df9f24be99c9708da4b08406366e609c7658a6c032f0ff4d31f9e2cf00230559ce1c3c1b7d67b479d351db9ef493824e40e5c98f1411bd0fffe5b1e1e9f0316c4fc4c3c347f0f984c7d272f7d2a65afa4362a6c9cd2251bef842b2b625fa7e914e6d5af522f31785812714db34db728c77a8881c576414cc1bc857a096f544e3d0242c6defe15e621a98afa8d0274fad41c7c464dec5d8295f53585680b6a38c0599fae0d0cbe174c02c80a51bf530a0464716c5aed4796fdb45ce87478de1cc898e9da53538f34a7a60ecbdc68a21e3d7656e121752b1bc061474daeeaf3b55266128f473d5a4de75b7e9b6087e6b5d04d7e0a3c0a1fbcb6b17674e54a24162f74b23fe3e5296d46f4ad3daa9c8e8b5fe8d4964fbbe4c583e5fc1d2dd9bfcc55951aae66a924da6f7b9ce8e845f98808d3625e98495","dedup_hash":"23702933538943712392","tip_id_type":"personal","vp_signature":"7e2169ee1b0249f5fe10a98b87ea13f41d7cfb408ee1a4fd0e6034312e8981e2c57496a3befc7a76f40e7f866e8973063ce54342af2c10cee9dbb2eac86c7e81e74a189207eb837d6384397c9f580e128badc3c59b8c33a18e4fc596a7d866faaacd9453c051c0e9376be6d8a247442db699457f1367f1057e849e95dc9231f57c074bbb7a804157668f73d015af20ddc9e37a936fa47b98b23bdbd2c2af8d9a7ad6b98328e8735863c83638a65e8599a6a115c37db73445d0f58b212ae13f47aef4f9615523610660ff38d2cb8a74dfce7861ac05ca9ce2aa5d1e8f121adf4b1a44c770dfc8c8744779e5bcf153f1bcc83224a91c3d1e9750b86795ab88b899db9290f052ddfa2c0035ef593b84829d34052379c16beb4934badf868b194e7e2ebcb403ae826e90d0aa692d0bbf0f7f06e7b4bc3f0c3fc61ea6a11a48782797e9d99752ec73c9034cb3e768fe83e144b25a03220e7aff70106b1c3f0c306b8a79bfac5193a6c4ee1de828858da35c4591c100be992c333564b3450f7b06f12770ccfc11be54955c5a1b6302fb7bc3e70d3dcd374ffa413a471866df347a355f23122067f079aaf1e96790caea2c5dc055978b35eb4db2d7cc805a43e2097810765ba11ef80b5cc054b01b4f54138f23bacf753f9ea29b099279f03fb86f18ecc4967d8b0422bde6f2ab0816473c2f88768262de7635c3100bd38f217f981cf22d7885b9e04af18cf3b40c597d6f48b00e240674288821e0b7edc3bc80955870976055e2bfd8abf95e5e9f621509d9ba80de54c9f638ad2dec71028e52697bfb90f845cb621598421762fcdb2c4a9b3216c168cb07f45f623369ee01e52274e6012fe215996533708d690c6b15f8d10ea7c04829725daa089b959f221ad70abc799356f359b73d8336ef39c8d9911dc32b9ff8a2eb870cdeae0e93a1c6f1a3a24e47bb44f1b28a919e5d65a5fecb115feaaa3aba79d0692699b8d386168c6c9394ec4435eb46e4eb6b390220ab4bc9b02ba729d4f50d69948c9afa1948114263ce09723a0e318f9906c1ad1654128db1a3f0dcd8a7aefa7744499e3a9d6791c45b805e524c553160f89ad2c3205758e456c38137ae1d66a94f7210d4cad9e38f83ccd92a37d79eaabec159e65cd1e444c0a060eae13853262ed1fda5397841f9cea4c06dfa44271ba8c713eed2ec82055e8cdf864bb1aaf8585b4cfc7addc793a02ccf5a616b5d07340763cd794c583eb6e6e926b2958d5cd41566706bc66f5bc5bd091eb0bce356035686d436eaa6e49d20225a05acf5ce883ba1fe616c120d0aa78d39ec19ac20766d5fe2678e5555b31f2c416b878115c7a2273748a56f93c6bf42ed2790218a5aae36101903c64463f7aa619939abfb24853d1c1e781d31e92dbdaed09c61d56cea2bdb237138a68e40d5c6f9730bbdfccb65e6e90656ff5f3cd8ba442d1ca348833da5101299dc33daa06e9c1a81209813b2eeb73751c390a467891d7067c8ced5db72bf2f0ebe8605717ce1fa0dad0f3deb54fe064cee4e2119021a4fb4cba35e47bc882df06e42013e22320b0f1e4a85ac8c1654b8c8ae06d188be8fabea1703b61fb0f2d618c6cf522fc7a37c34b0862f390f80e99a45f6b0b666caac70f88dacc17e27c911d56d46672cf696e0620c8026f7c92879f8a3a627ca70247d0feaa16475c4d100bee79b67cb2049d5d119d92e0ab4c7575ddbdd343edc22f3958ed8401882b7ed75d51fbe19e436334a6c022b78d885701bbec2ba705b3faee1f38d3cee3deb90dd0436f057811dab7caabd822ef23824ec2a348ed1ab30f39a5bcc3da1e29b2fc3da3328ce7177c066dd2584854f484f307ee621d66ce630225eb697508bef996a779608f9cbcbb3862e5411b46243b8a5316dc952fd43d68c7bad44197582ae4c101608eaf6b1773f1a178850d521429885ee46f74e04e175366809f9acaf283364560c517a2073b789c9c62a328964c298845981952875ebc207eb678656a00b469178891c033e67d9b9d9d8143a66bfac5bb280f7d975b5b5d4f7462cc566f19845190aeaa4f9d29f57a655327499e339cfdef3b3ab8d540d5db90c78b0f7bab96925fa0a51324e1525a7dda08614c40c381c549473e9534e285a7426fa9dce9fd60e41cbe9fa07672730043ff2b370520062ab2a4061b982216fbc169f730ddb4b2285634b0c79ecdb21223073c767474f64e904e3d99581fd6009e094cf12c2ec38835112a795c2e42289250c23eab6cb4906006dba488f4159ed051ef50b88cb38a24c66c7f1b7d7fbe67216169f82f28f1a2ed7e09fe88ba667f58e1cf942627a72c005dcb6cd998acffe2aefc6bd3f9125087617b159083f9f0a1b07bb3415d8f7dfa92bd4a16c3c3e610a1a2768b1ca27bbbb4c7d88adc4a923e92ad14c6c75cc51e2a910254f9d338575ff3d37cb2a530f70db52c7c6ee5ace2eb09e0cffb090c888b1d893ec672654e141b80950781411a5d461be98d05283ab8d3fb23afb4eefced84f7fca44a4a9804f6b7452c698aaf067dee2d03b022c38679872e8450c1e9d1e37d588a3d06ba9491bd72524e747b3a50e2632b9721452f223827e36f9dfd47a6ddbb0ccda56d555853a4782be46ae5dd78131a4871d9e07b37d6401c818fed0af475c36bec43541b35ddbb5a4c4947d49a1f69dddab724b9fb97feb3c53a0a3c8b77370ac326a194cf0400371a0dd49011dedf17aff2865df664793883b32fc169301161f2bd1a9a260bb6c71df2be48078c9c2f8c577dac02191cad1e381e782a54384aac3cdc3bb240dfd7781aeeb22b08a8daffed15dbb698e306110d501bf277f5e6d01fde009b89c00086778f73412f572d6aef9ec7bad0e4105028067aae33c970dfeaa6d41f22bb28e4237fb348bbc5b10211841a5629831954bc00b84118f46f95a9115fea8b9f9e0948689a4511e1c8289a5d22fac27ab13773b1d32803ce6bd3df6dd0c0cfb7db7f889ef2f04d8ab1a559b50d2bc86e6f6b2bb4c71049d45f9cafc0e915e38f1311f1f6ccfaa51c32eada0b83c0cf3c099fe0bb94693cb946bbdf0b21539a6c364e9d2f558c3878f5372035b2c0f4e8e56cab844a49055e06694396dcdf0fc46d948cc9fd70020ba62984ccea7ed43c0252992da959927efe1d8fa6a7d5047be1da152c0ee8b908e72e6d42605d4e7b826419648cc14bd56f5c011de45dae150625cd3c9a79761b71546e57aa0b791da5201899681898a92217b4b0e63d3137445f508b7d09996b9c26def8da578efa2e21aa199634abbfd9780277c4e340d0580c4f7ed15796514462e8d67d7a786d7eba571cea12b076de0bf8c4f4377e41993bee033d3dbb279dc108c87e4948c090120f0c6504a5bbc7ad867e118b6f5109d7129452fd12a419e15a213a67000ad8bf337bead3946a5485e000cbe7f07bc090a0bc35caa61eb39f6dcd7b18e6a0c07a0d2f3cab754ad0f2b7c63d7938cd5da93e0c420197b8bfeeda40949e91dc8f2b9048b44eece4c9e3b858e3e969d271064bd301c7f4fecd293a4e6600024130193068e38afb5d902137a5f313153f28d2aa71ea873e4ce5f79a0dd9548d0549aa7ee609e11eb6bfb3c26d28cbfc3ab91950ae316689c643bcb6b501730a15951f07c52b7d7ba7c90dfdb062e618780f33363fe16c3deba210703715827272d6533bac6e29f956e7c53f2f5a36f72ffd7245d04c9f7f8406ff9417a62e4527fb9c185c6ef5331de3cd95ed9da9cb79753a0f6bb67b1ae6a4a2e05cdfd0141c6b6e3ce3e7a4ec8ddeb4d0cff6e5226416c356a30ec66f0a936cea5ed2d0109a0087c8bb98e8031700777ee5f5deeae8d3684e74d97e0097b216a417cc3071c5b51fab1d23db54d9dff4a687de705d212f2d94affcb8b25c1851e5d9e750b1b2cf1294cc659e080162c9903ee3f30aa679d02095ede7097769319d25c8ccba5969bbe0e61042b21402e0687a7114c7e7fd872d85ecc11486a4695b224a7d73e1b00f0cbe9ff37de63ab3b530de2fcc1761c97657d6e2fccb5abcbdf2820b54fdbd63221b03d890f9c6ba46835906234eb0aa7e3c08578a875a38d52eebc1d3955da1ab18b8aa53deb980e008a6bf61ebaa2110d35e317aa2dd4aa4ad057ffe52ccc192036301c57edd463d6ec0051b674888aaf4987099407dea505dcbc8b6622840a2799b6aa50ebdbc872b7806239f4226522e314422a0d44844c3fc96a81a770af67b7fd37cbbe69bf1dc4b768d01fe88559ce9f8a9fa64ba2bfc63d588eb46ee3ded9de1b0d3deed7b7010fe800416221298c410a8cc00844669f0e82610ae5e6afcd3a583007b44a4eb9f008b5d10e6297a7a5cc9f97d705b9ab4d8c9b51f5b53cbf32fc4d2e46dddf80cb591a8b01faee73b21da8764ef64e8e59f7fcfbb78e6a24cad4b45c26a64b0d5cedf7d7c7058374906a0ff03880ca84ad28b461ec1b5dd94ce279ef22e1505f61459b86915a01f1cd9ce4390c1f12627be38821aa78667e485e9d78a25f6e3be864c637890f6a95c85215865f78d0ab741b27c514aa19701cbfc27d2567f9e535c6a0bc3b1ee799a2f4591f602d88f6588ea3cddcdf0d213141fcfeff6770b53467eb03234d5389a1a5bb445157cb000000000000000000000000000000000000000000000000060d10131b1f"},{"tip_id":"tip://id/US-51c020baaaa6155e","region":"US","public_key":"1fb89618ae0373fb6b6e8b36a7c2c8bfca29c8030e7373d614a7d13aad7262405429a1d8fd74f6a1bf60aafc48a3dc9d1e55436388a8bb25aaf279f7e2d24b2c9c466a47b758ce852b0e5c8b91fabe33eef8454072de3c6a84160d6b07e0276f14737ac54496bbf5092117a76c40ba2ef885d72c55927528a60df69af18edc0b07517e504cffae8b679a5ad795983ab91db4af06f8b5d13093ba55ff911529d684caf4b10e4be0c3adbeed727c792e36ab7fb0be541bf174b92d3b8fd8c62ed4480f0a617df9ee84654302a38fc08adeeba949bf8070b736c64d57f4ca39360beba720ebe5c3a660c81c04c46bddede8ea149b9d2ef157c705286fefa9e901b1d6f3d870b57447131bf0c98e21f90a331b1b2d4d164283405d3ccad0045048010d57dc131ce6b1cff191539b45de80abb0ca4f6709695dda13fbc27f128976ce1cee5af4b9507b3f5305da52cffb9f5bd252b0ff522c9451a264d0120c3ff1193330e54e439785aa69f7e06c6d92ab1f5166f2181f0582f9839fe10839a11444d7deea70acc047935f8f1eb7b3deabc2636f879955681d563cee4dff8b9495bef9fc694cfb3be431cbb03b733423ac203331e115da21c92e8fc3e0cba7e8473b3e595dfb68ea1f6d8fddd2141490b331172ead7e17370665661718b3a853e8c10366ceb86eb8d52a76d26038a28930a9d3a4084278732100789546d94c925bde99c0001671a932e626a1b6aeff81c302a7fef07334ae2dc214b56a7883e54c09bde4e92dbe8eedde177771bc78d83ec16f36cda1b90056318d4e9660064a3b0928c8fdc389122f0e25dc1305f16b281822c763a6691348d7f2363c23ab8fc2d7b4aee67748a1dba80412f6e110fa6b9484fcf7ab8daeb6755089ebd33c2be6e6c43a310874b07414625789b4cd43cf08ecae717f40e2ae08a932e7c9e69fe82ea6e38418fad590d2c240a4a0240eceb01daec6b0316e583745b70b33bd1a0131b8ca7ebce680a98cfd69d643ba1c643ce9aaeed8548bb44f8fd28f9cff4cb8ffea89be16df39a2235e6ebe41f13dad9a01cf170401f9dc390fbff7f26c414ff04a2491082d26dca3bea87ed247f7c280517f5edacc44851b7fbb508c7e062a6118f0850e36d8b7b1c0da811adb91f8dd82447771848fc67de977b2373287b88b67f81d8fa483c3f593c2b06a1bb4a46a537d55d009efba1544ede2b88d351e1418b8abb2c193c3c20c572de6b505aeeb12c2beaefe3c9a7c36ee8e9a25f1e78cafab1228881e341ffd10c4d4e22865dd58155003c6f778728d26afd038fde1f62b0a2e0f1e538bcc939628bed973aa521a4c7884a1283265e1ca80eeb377ba4913a84581ac8cb62498d63cca4e518ce677f063aab576b24f5ddb1035240ed4e053bd80056a0274bb032c945aca62bcae7995cb2cfae2fa03ed5bc295d35fd1b3f29d15fe56d9dfcb9b43006eca00e5f094282fee6b26e3cfd3cf514af40a66b43e8d42aa8b8ae4a0924dec591ec48d37e1a8e2826e89dbb360a07befe2ca016f5338e120d96c0e135dccc85bdd9696c7b7cee135188fc8c17978d6ed3280c09e11eec8eb5bd0c7b31f71b1067d5b7ffbb4985151393a7f93f347e075d8d06183a11e5ab6ae0549cdd9f17db433140b048bfdd18bf9a1ecc64ba634c1189fa8f55f24e93fd1ee096ba615f8544d90e5f2b8cf5ea5d941e17c808fa8bcadab5740f765e1f9e8cd51b1c98dafad700b5fd511ad7ba9dcb7b7fcc5b235f94d05022384007b57050eb38291f12e5e1907bf43a1e22123750f9cf4e5793fe1a81f58c376841c54e635cf4a8de64896a67380340661266f377461ad641d5bea82969ebbe570d445ba6efad8ba2113bc8ac8440915d02202b0264a7e7665dfa1f5d71ee912e8460acb90d5ebc292b0cd549dff303f9ba4a33b218cccdfb7096f602752647183409f7c882ca364b0abfab77f800d180a7151aee4899fa5a65eb721a06c4ba01d0f6f4adcaca514689c3adaa82ffb90ebe5c8b87e927766ec21cf6fbb4501c89095ea7331e907494fc85ed9a193d20c3d51f6f9f16948751f24119fb6d4ae02dba32885630bbec4a40e3e82fa3315003646bf3cfc13449aeb58b2c235206c1c8d51ad947134178e773891726f2e21f1c3663d7384938df7981f9f57817633c17ca420dfa71a71fa027d090ce217b5530763c3b7498f336a32acd1c57a3de5ae100be7418f18df330ed8e6ffacf9b12dee56ca8055d1867d8c1cc43b810fc7128958c1e31cfffcc9db4628ebcf43548a56e75e4b311f6b8cc5a388634aaedc7d34b4fd8c71dbb1ce6f8d996f73e38e2a76da163e67f0659229e0285143d5bf4133bd3669b4a252a8cced2127e4a0fc40ce89465cb3b9af7ae6f9c5c66ed8e7980464923035e5634146437ece15b255f6626cb77dcde7120978c08488baacd2ed2487a44cc0ae5504e37dc1d8fad379109c5311ec6e2911d86270964583ef0d2a6fec7de85925245b4083d3c6c354417e8a1eedf733893b0de48d0e32726921e4174569220cee6b2a1d0597236e76be085e40aebbba0843341953b111a0c0b88e2d3287639bb909738b016ecbf78ea572548b8521725b3a2f226e139d360bae7c1895e7943f8ee3d86357fcae12f87e9feaed70201ca955b931f35fe318f6d61ce230585d8313d31bcedc66e188a087ca6a4e74f19af17773aab10bc15247a5b72ec20cc3602a68d11a571c216b747ab648569b51b90e57e53621fd119d99f5","dedup_hash":"74146165765493969290","tip_id_type":"personal","vp_signature":"42b45f608d50ef74fb6f831357caccba9d87de8c0f56a5dbb96ef431bb6a2ce83ada9384116e1f7f285bcf1ee52a74f003317328c5924f42024ac6364bccd96a801254dbd000b3da393a5b57b4c9ba799079585eed37e303a07e596752310728c5453d5e3a8966b029ef63cf0f930cb1bae9d4888223d98f546875aebe42121dd4f165190dbb4c908fa7f7439e85cfc6379b696bc1388de44f8ceffd46c7d99fbfe61742831bd26fb17c2c40170f3963e217e5715654f07ed3a3090149d343862b0feb4539cead26f49f49f3bc8be8a8385bb68275d24e41113d5cdad8224f8b2e06fabe97dc5083b68509a9f3bb4201a1c3efe49ef34592879c1e51e9f490bd877f1787c74a84c2e569fc8ed9e8b4a41b9c731de5779df75895ac8857de802e6ecefdd6192f51e30c4259990da66da3ca6d9fc9aedec81a1dbd85487e2b9a297520b6a8a8ce0663966698db679d6b9c8d82eb393219a409ca4e03b69f1e20782b29dd9244dfe73de40858fd425b2f10593afcf90348eb7e07710c7a9f1a2cda8c929d04e094fb769660316555c2c78bd765e812e0399795e63271796bed586360cf66466c793c1663282d732c9251eaf3bf17fd31e33035d0a51da45af56d2061f0a04c4fb6894f9ba7f6bcddb95d179aaa7bc8ce652891b424899951d94c84ba4d7905240a3fdbc7eea6e5bc36241d57e128c608c3e5c309e093897788f58382a14267ab3de28a132aad7460912cfaf2f3f6489501944ff073cd0f96098dabdfafadd3308908bf90bad7fbcd16aa7e13d7160dada86fc45c0254091741dfcf743d7b08ddb5ad9095ee51fd563bb2ce0612efe65066b35f44ce495ea14098766daac4c7a8b52fb4131fd0868de4cc6bac5f6aead7e8e3627d8648b19c45f2f5e3b3fb57f7cb56fb684e568c4d136fa69d31556b8d2bec674243ea4fabefbd2e4affe2c54b6452e0f1d5e6ad72a8a17dcc6027c16ffd62a0b53082fa1493ece0aa3f890858f7cf59ef6c5fbcafc7f4d85f77cae8bcfd13ebacc34bb43ff91720a0e17c6f1a0f3e0075c4ea35ea1fbb6802777a6a28b3dbc0449bc35e22f024e339e0ec60d4dcd7bfabead8ae78914d37c2dca0369e652efd130d8ac7b9ba2b3daa93b620650e105338180c2840104e86d20142967d9ae5e20eb3d9f5810f98b85d45bf787e1cc6782b64a61ecd6cfbee55d1596689e07f67ea126d7717c2e84dc520c0f2ffda4add7cb5566a910ca7c17b43ddfa2ba74c849a046e6d039cfd2bcf0ceeb4d0621dbcd2312a23da1006b1b74f545fd58aa8f83eb7795b0d334155e025c7c257c4b56efb7d127631e523c1a64dde947f97cad085397740fda53ecf244ccff8a0c2f12376f4e7d9dceb9999665b3103a7a71f199ad0cb2bc6eae0a9bad1abe1bd827482ab63435cd2bf3b0b1ca0a257ef47cca441e6713770e85059fe2573f56e1092cc04766c35277b73c015c1ebb398a937bdff6000c9e4fec40c13baf9de87095b50cfa6f76cdddb947fa6880875b7d162756d40bdda62da847f0c926e60b56b3521a85592db731091d801a0c7486a1695a96aa78f01ad25377941abd236fc3ef7b8657a728dcbff5775739054279b71c3566af46928276ce1ee244463c422e780509d3bf4dca31f9a916ff38b6bbe71904fd48064a1779760592e17b23d38ac0585e5dd0fe7419df8eaaf86255040e3278c9c04b29faa4329bd18e0a963b3083f6ad6eb56b58fc757225586331f48a86aeb39eab8f91694a8bf3fbbde44735e1499fbccb858d7060bb1f0ad896f214fbd8af44633f4f189f164bb04b66e42ea97ba4681e069986b3cf1e2882d1fe06f106b49c65a9bf7727c16d4540453e1ce11afb9463ff67aae00a74724f11a4e595a5c2e7682f7c591973f48609844c0f4b9b875051293e50b3601703a354c04992dff2d5b3d8973bba800ff1c588f3c0ffbd3a350c536f052fafcbe42ccf8e3d5e941fde0c910bbe54304625134aa5efa640b9997e93f23fe0c1265540d38334f1f97cd7853dc6534ba8b244df8a8023dcc5bc0283eb9e4f7aeb840f459184aa6486009d15ba162452467103374f88a86d0cab70beda4352e32106cebd20ab4b73780b02415ee39805b5dc7b1a20377183466c74f21ba820d1740ab201ba42af3d21e00b07b2dda8e3a66a26c4568defe53ac92538ede1d722e41f19e0bc8419586adc54b4c0dfe8a437f8057bfb55448d4b13da13ac7b0be97065f6cc0cb83ebb5004eda18a78098fdd596571a135ca8eeef1b60d28b76d45d348509fe20373504aa61fc86af465edbd9eb0bccc29af9b7d0cbc02810fabd77f85cebd69f379f9decb39710e769c5afbe5f9ec7171146704a847212766fdb5740aff309c7be29a07276818bcbc96d4df3b52cf7ed364f876508ba92e34605415812c54875a980c078a1433bf54d3e3807961a27a540a371b01736d98df9c73d03c9fa7280a374de9c51e7d876b002bdd6bc85ab8f61fb4479f93be60b8bdfe6cb53ed7db67f35a363826314065e9e4fa638d5b164be43c540c4ad35f55c8198f22210ec67180c5045d7ae035607edc0e0fb1ada37a63e059c1eed7c57b9687bea38c59570a00167c9cbd661cb31a45c8302cc531017ef465eea634c7ace45e0cde2bf5c47d2b378cbba8c3b657966bba24f11ec86344643b27614b28bfc6a94783ba205f94934c218079f746060492591312b887d82aa64a074679c8ed6297cd2dbfe32c69af018b3f1bf76cf89f29df7ab9403c3c06d8eef7b6d89c75e0d378e25165d0d4a7a615964144d7fbcb7bfcc31a0920589d8720fc34382bc2a45427a63ec55d9cc2585a8dafa3d18a6d9ac7d67057f5dbc1b49bfccb2c01afb159696664240c6a438d2533c3f32efc40935dfba4d77a318584614bc84677f3ace2db9387612826a62842191cb6610c04c8b37534bb9f92b99e52cb924a8f707a00a104630ad71971e54e3f0f79723c1c96f24b2dd5158786f5ce57349e91490678a2f9e30bd911f6ba198f20770dcac72664af456ab24523ab4f7237f562ee92241d4fd9803eff72b5b90a8b06627e4d10b1c12567dfaeeaebf273673afde17c079241da43ac6fda01029156d5ca5b3440a8d265950cc95f46759c6127c5506a6671718f796d583546933c3bd4cd91e4e9f720a843b0a29145a7222e65ec47ce617a7381773d173bff2f76b1dae076497a1fa2ec3c9c4376e8e60c43f66573e34c6e01e3b523012a59cf934e888a0a8b1d2a4826c3529ee400b562c60409289a2fe3c005211c57db960d52816b027b07d6f83aff18b9b3b3c05e0e4decc095429e725399e152bed166620f3f7ec449b328d75b5410d667f932000eb4ea80816d0235bf52c68a7c7c750cae68c5734c9fed5502eec40906729e74e68437f435ee22fa825b17fac013f47a35c6455aa765f8eba1b7f080264cb46201737fe7f018590ce6be1e44a89fe58255f97481e4558439b24c099e0f10efc65e28b6d6d171303bedaa4320e594fb3ec8c5af2f7155d529a3654198ebf124851e537c48e1e3b8574dcd5fafcc2fc0696ef1442f388c0d89fa86cc0b7d93ea3d226abde7ab66af0284f4c15fb7855c8a00aab3f172a2de658f48774746210eb68ca9a6be8c13f27d3c5ab9dedfb6615ee2c1e6dc446fa9532a538d059d266e8700dc48c76a27836db0f3942fcb0694741daa7bc4139c951d71975f266fcf861a44d3838fd419340250a84019d8f8a8ada9946a15ef09e9282976fddd4cf2921b110af8d01afb75ac20db22be275a0e8b2fb885c053cbb904023079414cb08fdc8d63842084bb0f761d7cdbb115dfb5110358957b25b55ce2cbd00e05bdce201bcd34755744b75c228e629faeb3c4a4fbb383020a95fc349304d4aef9f2902b1d347f2207d144a554a09cd74e9d6fa365cd28f9e7d9d43db211e684ad6039aa990de499f01ffa721c7a7770bf76c6e84589891933cb6419cd9a12478f4c95d83421033a1c130fe44332562346e9a39067d4fa2cec3ce936d919d432b5fa482f56510277a1bd64559964090280f77bccdc2789340513fc0c0ce77bd097f55b0104c8d180b72f1cbfa938aaa492b4bf41fbdeb5c3fb7e7b01acd73c46693da297b758af6328a240f1d9a5b18d2946e160bcd9327ed2769152d2add85694fe5a3e69226ffad31bae74184eb9d229e19c83c9588867d90a4e2caa2a52dc5a0f7a86ecc9c66de015a53deca75412da9eab7404440a72ef4900f1f9fb25f91ccd58177660d362dc9181d206dd495cea942cde3100c184b1016062acd1085263316767711c51da6f5583533d79f2e8e46baed8023f38534309fe98b0005b65979dd9011fb23f0834ecf6b84d768851c781d02a96a15ac86950bd589a6f0b03de2cd13cdb94605cc6e4c8ec20e1955ccd8146e6c44ed1ab4d837e2c0ad1616f98b160a2a3aa2487aabb8055be7d8f819eeecc7d330bee0de6898c699de3d4293a42ea90041598a6250c80e885c7c4862771129e33a12a6a5193fbf19d267b1a38d24b805798a20cade2f9d4b6353d98a01bb21d5871a23d3315d33a3c5a65aaf6bc3957bb77b55a375ee50428b3638424e5b5f8c939e0c155e639eeb497887a7accdd31d1f61e44e4f8598cbeffa061858699e0000000000000000000000000000000000090f161a2126"},{"tip_id":"tip://id/US-302fdb95ca8d2756","region":"US","public_key":"a030e279e1f2b96ed690a1b85b71028ae6a52f79f40e2e8e4a637ebfbf8fab7e10433437b51f7b13ab0e9c3f798a14984c8648cc3b94228fa9ec306fb5b6a82e26e01a1cca95c854e1c92d717e8f0c22606396c3f52796377c3ed6d20343eecc98b242418cef5351aae1e68fdf6b5396d47fedb7d16c281621186ea1d1e6c1ebf0ba4dcb51352a52dfef0275b199e525b75fd089e7d192550ef77019bf5bd9ffc6c319c53981badba644b927f0e633519e205dc553fdafa6f9b12db158a250290cdf717c502cf9134ab0938470fab32d2a74cb9aed2fd291e3771b777cac115828f77bda5f294dd82a42eac2f1d74fbd26cf70752a9d82837bf650c695371b335ba7fcd10cdef0b06fb1f6cbca0d68c21103319a6b4075ead0103b07f080b6517d49b59b16a414711ae674143739ac45fe957d93168b1500dafaaca02a9ad35059a6cbae063bd5f87a733fd120e6ac712519bed3aa2e38009d55e4f6ce010af7b6598e40d282a64198203afc8653a0cd850ff570977d93207407a505a6eedf2d067ff28f04ca5714a2466929afe2cfef6f2f0c3533420cfb24a78d64e80784bbd1c0c99e8ddc49a66fb11005c125925f4feade1533a2cd444f18b703af561952db018ca79528aa67b945672723aee7d1c9fdf5fdb457a6cf533ed38e381d679842c026a9db2aeba4a494a69024760f0324988e64e1df6e47e835733f804c1af9c1c02a7cb07a2282d89c7e47ff1d3afbe3298b189cfa55e5983ee633a18bb5a27948ab07f4809222c7cde4f597526058b7a25760b15ee13f0e81d7069d2c2efdfa150be5957a24e3d36791edfc294dd21a2ccab7ff8f351899f475a116e29eb7c759bd45105540c750d83ac9f0197cc0bc4a140b6d36229201e3501f80671196c57cc595375df47aa52b4aa2db4b79042a057a2132fcbfc4868c17841947295c6c981307e5fad5a20efc4c1bf9455564f1ba0dbedb9dc51e5d07873d36f77b20cff16a603381c7fc17f0fb56a955e9a6e2a8b470f7e1bb01d9fdafb7206ead1b52ba9e8adc78295c2747e389130ccbe601c57f93ae4a19a53d51d7b695412e09675565b142aa124a61bbf886fd2e94d03d3dc74e49ebd74936591cadf95c024859923224674e118088e98461f9a62b7de2b5511d37c31f199d43a4623dc0b6c6a1f818bfbecffd3bfcdab1b33c47cc68a8f54bd79583e2fc7f39ec310a01f0a347bb20c5c22d4c64d9f0d22246e13fde46400c6f1627ef7159e51195f55db9dabcdcfcf046f050092267692906aa2bf0c39d4cdd1af500ffe9dbf739f3c76cbad115801e121a06e99f3ca33e3ddbc5a0046eb308243be92d2069596a80805f53a4df2c98b56ea0e1715996afe6536faf2d51d390eac2f03eede1836be0b50e38d25ed2412b726c31933fdcf3970b7bee851a4a71b8a8c071d61e1934f93edc43eee02e2dc9584369bf4bcd3436669445bfd54890fcc5caabdd2eac7393b5044f2d78c9e686b47b5a6dbf7ac8a2abcf504dc4fcd50028b2d73626348085a66447cd2c450fbe7585a4079b97a56cfc7d822e96281e94c3c669a923131eac9cdca7b50edcb0ccbb9b42ff7ca0bdee3727226a02ab88d19fbf0de39361e2211b4bcbd682edfd0bffebaa836745d9cc7b1f8e7fd10c026b2986cbefa72e9fb1cba8f914275b99d241be0235d6f219eb1cc17c0c5ae54b9da25c790e73d4c9f09cedca1f4107119b5ee0cc92e460ea18863ecc26f990d2f3f46fa4f3ec9b2db14d99b3510ddadd055eb1bef6513dabcfc9f85d07facbff4a74f3817be0f0c8126cb4e6fd1730b8fdf0bfe8f5f6520cc42960f6b6916c8ca90bd758005906dfbcd804d68fcf6e5c44983bd44e982fcba15130a7f002dbc4bc1aafa4ce14ca86218dc0cd6232da3d1e754a201f46a5813dd4962445432b200288b383c691374ce6dabf27e4d9062278bc7dbb69b8c3ddee19a553d55ccf53c492d523f8eb44ecd8fd647308a98199c9fe90af3f4c1b32b95bdaccb5dc7a83d98b4ffbe6591c367cc8762b5aabd2df39f684ade0b2a2b58539b0be7d517ffacb37828d07f0b874ce9c0a5ecf0b2216bd61c866b15bd948ad4831edb1351b1e7793ad90ff896ba316513ee245a8fcb117459a4ef66f940c4e7ad34c094319a39c33aaf9ed738ad391b3e6400fb7ac3322f23d37331360d364a511044dad9966e448416bf3ddf7e0c0f22b0b062fb716a245d42a23ec3333c3bfe9a34c025833eb43a6ddd5449f688bab1098cd482b46138391af058a0c350d704790e7e427373730bc37ba8085cdb33c00ce619ac8634769ee32ad54cd7e7330e02a9f238481c228536e3a03a8a15f87a2c06a261fcd6a89ab447c4d9c2204d1885fabd0e6bf1a39ce0d171bb4d34399592a1573ba91d235daa58cf5159a10412b6d3d0be114831e61f10587d31067b7a0a81ca8a28d0e0b09cfd1ed111df9d3877475b8efb639d315320ec4f4347909200865d51c442a39e8be35a2d737abb7a034a4957f866952b51ef005a809d0226e5f26ece67ff11974c12ac93c8848158c7199050dc028b0462c202d81f0c4c5547a8ccc09ae8630f4e670ff9347474481ebd6f10d9a6bba6786854f1d5eeb4e7a9c592bfe95882b0924a95181dbd88ce8179ca70445e23ab5c2a5a028883444922fe63744d0da5a5f3955253740c471ea2a70acbae8f05d60cbe1e3e3717e93ef46982414973ee3906d09ce94d585aa56d4bb8e37345c1f45d35608db4adaec6eb2","dedup_hash":"70044443154882484498","tip_id_type":"personal","vp_signature":"ec081e2247005803f2a8643fa14bb3068a29ea3feff3eac7afe9d4d6403de61ed943a2a1cdbcd95df1d25b151393e01ac2e5da7ba18a293c5f89763444b2f32c68f657166aca8d14a62de169e84132a80396b2040ea0af424ca28592cec987ce1b2048b51369cfd40d81621580b2aa4d50ba8c49ddbffdecde8ecbf1e8ca8a67682011b8a9c7314ed911f15ae68654f127e41da61aa85c827400c9b3b1948ddb46177c4b6c524289e39e6e3d988fd15e07cdae693e7c7fc9c53bbdb6ece87e45fd50fa5f6544c3d181b0443ef69380fb985a2758c703b2be223ed53a6a2f407ba835b85dd3605295d1a7aebe3fd350869a05d38bf6c52d7095bad394f280911ad51a7a0651ee8daedc31d771488b2f800c94d9e581c500433240a67b246c62864e6dc50a1e5a3e14b46306cb959acdc7c815b59b49f4113b8c17e8c70f2295608dafb76acfd970257a50d471254aa02048329bf489e4d65722f13e60bd5219b76624e6beeb71c97a5c25d417755bd88389ecb3388938ececc77b28ecbf2c07413ba2baebd42e1db55b158fa0f471d44400992bc0bc50bbf8f547ee8db23698155e5ac1ee97753840004dd043878d8ffd9a7fc594659b0dd138b997984034be27e6486b1e90c128ddca01949df697fce21188282da3729a8e47a0ac69efeb1aa8b147ee6069554b365062e09fc3c37c5a580735ef2436ffcaf540883004ad582263b94085be482bf0792357ad90b00a21b0e3bb3d03453d1dbc7d390b2a14afb860d9510e93ee6565dedb210293cd143d2d826f85e4b47bfbfad446adc3736571866812ee3d34f0e03f6cab7a59043fd2cef5803ada1d438eba31f66a451d612e9af191cbe7af0b4d0a0d9ab837491ec733839213330229d3f7f586f9f625cb6ea6fb5e2d94d7ebe01eb15671bd918524ef7879574ecfafd906d887f3229d563429961c838f0fe519eb4b18a853b55a23bf7605163fa0ba963c394d1ec9a69af249c2c1531dbfc3169555f9a5fef9bb483001dfa47af77c9440c8f2ee6bfa93624f342b4d0b29f4bcdf0c5c15b559a2aab2abf3b909aa48131342655125085987cd014be1429ff9e90bfdf81b2539a3001ed962c25988d03046f5a94f79cb806cbe969c6935ecb7232081cacd762b2fc7ed37ff38410c69d7cd95ea58cd5273cef8e682a96a993352cb98070455ed38626320b6bec8f1b90a2c533aa6d98a3114e4a1873a2f4523c45590e6c9d69114484fce9e069526798597bb250c1cf4f3600c43141a39262fc886ad84af91f9e2fca040789e6a48835993fc2c4f5a511fb6a0ad9c0c00abb439c220607e3dffc815f9d2362fd463ee6611ad081615c0b62ed67bc79958cb1b442178944cc4ef2a29844bf070bda0afb5e0563bd068f0ff3ff67b8e1abdd467fef427a6d7debd662ebe6d9ac707da2995ef588e019cb83f26a3700eae3262a9ea4a2a09469b98041cebdf2da7ed7e351e9a094cb4903abb49f6f222d0ecc2208eeb1ffc99d2e9408235e8fe1550ddc50bc5a5b07d0af7e9fbd8b5c27c3a41683de7fe6baadd4bb5d4a9fea111bc73b8cc441bef77faeeb11424083dc9ded9ba131cb9cfb72511ca999590f9bbe996d70604c36f834e756fa24269140d7d39fe038526a0ad71d14ef00ec1f8150b8f887a786dc60900b9ead6d89cece0b8a0f693d5f4248f855fe4ecc73d0a71f008e773e00318b37a572dc5cb383e639ad0be363743ee76152bbd7d731e8d9d5a280c17942b7f9e14f7f0ad530368afe0258ea9e4ace25e523a3d3e49baaf7205116e3da5504aadb6dbafa7f5cc927ad5146766022fa0cbec69dfafd8e98b8a1078213eba5859ea399d70ec3220f0a980be0876e9e8e2682911f7255bf85c9a20595e0b6e9d8a5828dd59e65c2ccb315bc0bac42462eafc3fe86c896554f8776e3481912bdd586ec02aaedffca1be24b5b756508b62787956e90a301f9d832b893aa3a0223285defec4ec8e7f1fdfcb68888dcc1ff73f4fdf61eac191e41ff1a5622f97de47ff6be640ce410e96a0faee48f896d6af2eb08b7ad6ea3db75191f5d922410c39e4d714361fd311683fdb9cea0a8f3c9113662633395f279bc2bb0654c39dff34f7478d5d20c4b113a99775bb45059fb1a560a1b3cbd33d33e832d57cfb7d0f74bf3caa6b0bda898e0d4b34a2522c1251b5e9069aafe59a4b9a30752f52094f7682f3b26e68e1523ac0963234271b52bdf5557ff1e0298f026de012a5c963592cb7f3a34296a1c4e56e377d186e8ac10a88576de53a8cf69a755f951abde1276fdb7ca623772184a36c769966e986dc8129f58498e0c7ac14ba46cfe646a66438e4330c746e03a0f88dd109547f3654eea49b6fde148d008a9cf345b58920854c31570fde231fd1b22d69e13375bf6fde5af0fd3e3a5ca1ed665cd026c8bd075c8c85108efc2dc67ca6a7ac90d687b3986abc29a32a7449ab97376255eb7060021f03381edc81989fef39eac1840169278f7e8c03bf7bf2747edf8215a2ae1e2cb71059ffc96c7394f9eda8be85e8327c1e426e904da4bb0d1a152af4f2542da6c09342d61951657d686ac05a79453917e1ff5de5f2f040285bb0f001a143c554fcbf296dfe7c9538235e8a6f1a71328a570d6f47094d9895f8312274ecf0754e2cef9c207b2b3a82088ef37dba1b04f0a8d10ba50ad5dfa479cde8bfceb203dbfefaeb9e7b728eb6c779f1b6167d786c5c2dc0c8246ca19f35d6c5757a0a5b5b8cc32997099b93f239003d299c6af5a58265ea3547c9059a8303f9f5dc97fa6de0153aaa03177cd408345e628a737067d9ac53567a033f15ef0b3271e627581fdab6f799100d1e38f700bd90a8c121a9befcbfcb1daab470c26e3b524a2f3c7a641467f96887b315831eed48ade6e781d770127829136969dae848c8edb4e88f1fb2b6644c0f948e27a307ff78a9b67242a4db555955dbd7b2d80e87a362c9a05fe7c6ff35c0585758011b7a8fc729a11ef208569120052f8d79ab1f7f9b44816906089f6432c5a678d50e84be419dc9192e1cb4f734c32edfbe06d5a778c3ba3befb148e0a9126f34e4f86327a361e36ef59e20e3f19f93b194fe3d4c1d25977a4df114fbaaa72f391839a19475a4081dcba52134922849f1331d45ec68622a38192141ccf18b7af3ee6ec15f94b6b0536df600bcb6d5e062800a5f346bfc80328c4d02c809e1e3b24b4da60c1a7bbafb94fb6e22637d6cd39bca18e8c6317c2c0a835c49dca2a29e343c11931fd2883ba858588d439caeb6e40ef8fd76b44d512734a17a017cd2126c08bc2d6aea7676b5d8d2f1f95aba9d35542fab52b2f82a7a8ebbae68fc0acdbfc717109bcd7e6cae6327014376629db18ce79a28543adbb0ee5daea15d27212d57fc0ace1496c51a6f2904b72a5d6b856b9fab9c7a22560ab4866a41be73b0e04ccd40c8fa73b47a0f663d016143eb4cd97c0d117868b9e2aa1aee8b39746c6c1438725278f737cee87e65f5dbc4d0116ed97041b550cd0e589a4bc48cc47fde082c0bbfebf597366eaedfb679c438bc08fe581afbd99d81a837e347a59eba018d1f7d47f19fa60a713c7c4410211e0c6006dff0da03d304cfbe2e998c7b0f8ddf01f1e7ccae5e4ec7cbeb98220bea0f0e6ed9f262b81856e379c09749896e151940f2671ccfa1484008c3810da91765b0cd37b477af4b576b2e8fa9be5bfcb58af1fe85476127bb8aeb0669fd285f3d0158a84fd69cfff4c49703158479d99fd92f537b4e8a94b091db85303eda4bcb1fa2a02d3b1ec87a591b855dc7e9c103c8bba4be6370e2cb41da773877fea94163e6e75bd8f1062eead8d534531f97dcb9ca46d8fd88b90a3671cc5c894b04b39bb01bc7592e3f52dd32583bdafbda1b959b279eb5f60f9df4917f5a2d51294dd8210a427f77161b93943a51fc76b72dfb5ad049795f5b36da39210c5fd33cff6be9c6b7f423eaf41f9755a9f16e3e981adce9c4309bb6858432d8cd1e4f1140050b01f26cc58b24d33345a71451b22015a489cb66aef1960f1d81bca7da950a4bd82812b2698b68b380971876543d55511125c8182fd59f1151b27ad1450b9e79fa6b84464b48fe163e7793fb18d0eda963c36db29c933379e42780cfb3be3611d5f458688445c1374c90db839c523cca4f2fc4014ead5986cedbf219cff30c7e15dc0edb391da28d3f1a769b7e39e2075f85ecb899e1180d8bec7a7072a44b4bf7e82edec80036cf07c109a5793c5f9f6494157716f42245e8c1a7d81e1ea4d4432367780b83cb66ccb515dd0e81c4fa228c7f916954fd5b83640661dc155db66051541d5c3fa0f0e7439e3928a6577a01f4d0b87345cd4b3603209f119d8639f85db997964d5f175a6bf747af2bfe462b63f7fa970cff8ef9c16cc5a38ce24951eb17ac73c634617b788f62fdc8cfd8ccf9eed33955e452566558c2a73a8aaa1764d0a722993f2a3c4c8307dfd527848dc98bd3216ff5da58e3d4214f520b74bcc9687642ea5cedc0c7a15bfa6e50328a94b5f3e39003306222d3aaf92de21c027b8ffce9315a13404dbc47c03eb83c368afa0d34b30abbceb7b7436dadced3ee01819db1c9d6e4041c3c44506577d4d6fe0c3543dfe1f7fc02467bb2353773c0d500000000000000000000000000000000060d171e2227"}],     // [{ tip_id, region, public_key, dedup_hash, vp_signature }] — embedded by seed
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
let GENESIS_TX_SIGNATURE = "ee606a5bb639ebcea44ae4fcd27eeb953ecdf85da7786d8a1446eefc5bea6433e6c43e92db02fc0226979d45ae5427b9c5d930561da63aa6733c209456e0366fc7df35932889b2c9bcbbc74c77e50bf8d36168a75c0d2b2e10e7bb79fb719ff01f9268d619799f441552591496a0bbb70fb0ce8c4af51b2c38676b11f68017f58f93d557ca744f8c7b7341db1d34f93bb9fcc9f36bba24c214ef017af92eae9fcc304c42071df1eb73ccb4a8716ee4c66f7b11297ee29086a34f6227d38e31b69f4c09060f6d8730a0f596088419528b459f9e0f778c9811f7b9c138f14a23d589a8f9f7c494b9d8c022c35624904fbc0e4acf97c52cfeeb08872b5522c35f2cc30b6b09ba9ddda8e6f2929e6d6cae13ea857e53916a243d9b6e1e2dd447113cb055f79f964a54882231b2259d17f4502e91260b1c51027ca4375f57daa18c6ee98b4ed45b3f420ca17b28cb1bb79b1aa5d48cda0425d2650a8f039a03f1217e8ebc67c82495882b3951f65f22584adfb570dc70cc95e264f61a66a61d1d041f1492727ffbce58d026399d6064fc94889c4e729bace01fb4271fc86c1988d5f7a29dec7234031730f9aa495bbcdfce486ba799bba20e87672264bf8f7822edfcf23fcc54af545cdacb3ffbb6eaa00647795ac7d874787d83625464383f89c994e53863fa22dbca9727a2b87137e151b6776838d72d9d0ae5c63b41a55bff4611c8f7c311ea77ac6295a7ac7bf86eaedc02d20652b22f021cb15eb59327d9395e61bccbd6e8b533f507e100828c95185febb6079100eb93b63efe86ec0ea4f0558340c12f166d7791f1261b5ddb045510e61191b40fcdbfb764d29ad0b42cc333c3ba8b929e3c656ad3c7d3524519138a123d8eb8f9d25bf63ba8f3569a06a0afa14f8175f5e42aceee9d428634dff924b0989b66a1449145a24f0cf61a4c894806d516645c6408619c3e5d0d97faf103df51306437adf03bee8c54d1f38ab3de5d2d1f9941d73ebbf5eff9f96c54bbe5758fc300b63cda7ee5e3919d663dcbcce26e91ef9ff4bde1b2893f0d5d961b8db5d3bcc6b61f5e8dfb6a090a54b50f409b6762bbc4354a97c4b558ef9afc1b2702c69995c83206a627fa58f4fcdf2b35f66e69b4d495f2ccaf206fa3b1489b02aa197153e1ced29fce219b9246fa2ff5fd5a11019e388dfe07fd834a902df4164775864914c8d8fd179e2489601f56121c8a47493c65a918ca5876ee1a999e7b74db96f60017a2ad499f0b27a40a5662326b9b72950fcf3a1f3e652984e1fdce6d62312cfdd30ce0e07270ab63ada2b36f05e96c058045eeb4ba68f84b133799c5651caa6696c7b69db3ff6c95b3833b24a0d94ab1e0c14d038230da977110bef86c22f0c33f2324b82805570b863ed3beb73b7a3b983db538da4d57400c4e5a783ebb76af6664b2fbfea64464b4d54fa065f5d2a529c1f68a75868bc23b5aaa132f2879f00825354b50473c8b9caf5eaf2e942d42f05a66587ecca9bbe26e46019fed1e46e4165ee26ed1f1f5b95ec494f63226b8578c7999f4e8f053f2f0218dcef3d40983500bdc2ae05aef17e8939110726c63a78890f2a0af10155c0e011da101473444754d9c3282e0f39819c29ba3d3c1bbe5883523fa05f0e69ee178eafb0e8d03bae7e1eaaa83a864c30d0e78872ff06f6dff9f67dca45f05aa56319f8d811b3b79a101801d1206bb0808f0916c6f2f02d9a4b44a5d3019c707f1252461d7f18d77206c1a8131a57eb7cca54e7b9982a8ac69ff2687adf8f3cac49103dccf770f80ed6cdd185268936e7bb450d21971316dd8277c18b490154bcd47010bf768dca8c2c09700f210181e4570d9ed1ffc4345f9d9173c3045172b5f01ca18ee19a3941ee81c3e3631660b0443e09b9ede5abbcb0f1f48ee121eae6482e6c1118acdb7c9c89d6c47bc0743aebbc7b3006615a9f717eeb50fe573bcecc021b7fdbad449bd6ca9a8b368f94598a27c011f89bd744626a949fb5ff010053f462b8f449db731e86c25ae6edff4e31fc45bcab9edb1872bd3fc0c2f4d029d65af865e49950d3147852bb83dea40da9a72a193df0ba15e3d722badfc72bbd66c60fc0298a89146fd68624e2bce0d2d0d5de0fbe0c69f3ca10140973908ae60e76a8f0dc9076757abbde9f38f733afc65d75f05656e3cdd2fed6061bad44486c5a18240abc0eaf7b14681b1ddcdac2279db51fd7855851f426a46f449699e9245d9f4fbd460f2bf5ff311ba006e2e01a80a5b5004de7b002beacefb2981e283801c689726f27157a9e67b1934b29aa850d40147e08c75226d95598f5da7330d5ff0789076a0fb5250cfe4128cf617c0ded4ab63b105e8147e36115cbf2dbf7f9c7a70b1d74ced712def58223369bb57b6882a744b50117885590cada05805d240eae95c9f547ed60678c3e3d22b7769f3292bcb6f8f8f3c44e8c199532de41a6fccec46040b906e59e2e4ccba591f7a496fb29d2d9f371fcbf333c611096944a03d7cd25453a3a893850570567dbf102b65ed8754c9df9ceeb7558f5c74ca87fe43935f722219b093007da39b8276c79fbbb64c801ead55218df4f2dc50c7fdee608ce2b2e32508745595d639c0107489d875882cd52f4595b75514fac68f631945db669eaefbdf7c82a2174fbacd6dcee38b32f0745c9b167ec173e0b22ea38589bdbb17f17805abe58a005b29083648c2e45bd2e9a560a322b54efef98bc25275f0d5eaa49f6ae197f4ad7087fc0569f248cb1b249acbb41e4587d7683f0ce38bb9743a73e6822ed72d5efcd470e9ccbff4f2c8433d7cf38ea3657e9be4383994c9efe6e669c4347371713966f78e624716167f67c0f301276624ff3bc9164e685b26906c71a34bf1e9c99bb4af798be6d19e1326b2f3de7ac6ffd08c784ace0c6ccf1b6ee10f78be88e25a5a7de4e3f5e9597ef175a90240951ca38e0671dd6465c5747198a2e389106c420c2c36bf7c3b634c9c742120e4d4987297d5bb644008fa75af8f07bb69cfe9e08c8ff75cabd443cdfe219986417be1d40a696f564a1b80c3f7abc91d3704dd4842413b463bd034e4ed90312d0d3cd5fae6a786673ab363a5f12c52d0fbb6b6e1c6f6770a0b2ca477bfef36ea5c516c5315e032896554abfe1b001f76f0006c05f7d4573ef2574d8a1d82fbd24840a7492dda22a9935477d35e4d7876234e06dfa53970afbb31fcbdb03caced8696b886f6c9fda0f8f490e40b3bf115d9769e92291605aaef21e13e3bdce2d1c937367785c25be3d24ef0cb978dadb332d7275eb1e44f28b11f0f2f1188d2e35f443589ef595becc411a88fc7ba6fb3932a754cb515b12aaecd5081b5b5cb25c911110719c3c07d74450617c524ebce7de36996c8242fcc24c1250ca54a5c9337693ea4270870a796ec68bd7f8b13702378cd76126ddba693f02b68071f0a206633353724239942ab9ec9614bbecbcd4ce5fab6b2240271f31ce72744afee0765da9880605ce3267f1ab8fb7c94ce36ff26cb30e7b88a0820afb074f483fcc9377a60b9866b85e36aa4b9ac9a0d98f4ff4f16356c0d82fbb891c8e2305127c94b3fdffd8aae39639fda1cbdfba097f32d6065d638e7ae9112c439fb350f61a9c000bcc5f188af46bc1348676abb59a803b115281e352593f09f53203d1ce87f6436dca652ad72df0299e108cb4fa265e96dd670fc2025fec6b0f82030fb785165cc20c9585b15a5c7b37a4386ba16222958dcc5e385e4c892115bcc8acd2dc9fa4fbe021a94265d444a4f9565f57775c9fe0c4eb0069bd9dfd3c049b390b674578e13ff3f06660c7ee8b39a31e1a97d0133372cd514b2e8d7bcb027bc1403665fc7a5e4d5bb3071ccaa168eaf73c62247e76bef41315d2bb2bd31a4b51df54b5763b4e4bdbca628bfc4654cf3dd4254be6abea447df357d26356316afe2ab3e2ad90fd6a85e00385f5d159a1431e95d35c6f9233401ce1ee8e637db599e87e99facf12f2ff8f758bae1ef05625f208aadfbf508c73ce42a029b7554d17fb192e60eb5bb4ba3bcee406fc36a43f6314fb4988473ff29f62d7cff27b7bce126f91582d6fa271d9ebc2d29f3ea6195ff7b791f1c39c7a559da9588ac7b19be3d45ad49c8da332da63330a72bb89fdc3f40b7a3ea7b0842d1b103d9385585fc653f671b144d928e85fb17f025682a4df04eeb23e59c551433b68032495fc579ebaca370292decb7f125ce57ad7809b1105e9d16c510ee2e001df85f1ad81da98a4cf10ec160b01320732469add2e3ca23a87d132a9f0a7117aded17923e8c5ac09086a3dd99b360e39159578a1a7e2b50b7e67bdec2186047a70fd66ca8e0bc4836667e87d85b6cc586e44e7aece7c14e68755495a1d60da2a4df5a672f9774dd44cebd8f6faabbfbeebfef5a96582c42bf64ebc889012727a2f65681bcc246d9e23d05bcb380faf62d5ea53e6a397ef5e8b1de5e2c3becd4bc610ffb1d83a47b46045c94ee68324399ba11731fa2d8f145ac923814c4b59a09e94b2ca2935da2cc9d785d5db374b7186602922bace7fb2b18092239034029b07df5d7fe8a3748af1aadc2c13afc927a184664686e8bafbfdb3b43586084b5c22a3e939ec91d323f5e83a2f7258db0058d990000000000000000000000000000000000000000000910151c1f22";
let GENESIS_VP_TX_SIGNATURE = "7e3a798ebf6767228676124bed04bde006888ca3d1772e7813effccaace3d2722f53583c37ef4313b57590b32e40387b5fe48ba88b1e2933ab552d4f3ab4811ccabf70601ae711b091096e4dc9d5833508e279b4bbe1f666f0c59b604b9d4c3d75691367c0efd4cc2d1a15dd91e7d2b8d395bdf288ba4993a8e7d8a0a1df1cae51e3b6a38e036cb56fa463e6b85188e82da8e265eb39f16bb08f72fde814c6a41f19ed302fd67a99f1451c8a576a0808216bab3d16fc8bb71379b410785c734dffd00cd01d5d031208f05b393b9c8e421a5235720795f668c7fe97ed3d2cb432d6a6b4bdd454e4da47a809733ba149e93288eeac73aab9e3e4e1f510b0577a84a1a51821fb33582cd66a56cca9a2aa366132853dfe5e6a8ccfcac655ab833e0ed88127fd1defeab70247607641e90b2b6e03127ce3d41f716ac0f3073b4644e9b4c41cabaa0a7d76d663558dcea966a004b674aea110b908147fae74cb76466a9ec80604481f0f7313f4c0dd9ca4112003d3ff3cbd56575cf37ee8631b5913a606a9b7bc2ab1b0ce2fd6fed43f0169fd95c277eefd18f2bdb7d7e362a93a988ae49f5639eb679b71a8866b59fe52f556c33ca4df8f3edcc9a343b623a5b7605c07605d3071c2be9284b5da1fc1841e4b3f45bb0cb3dd59bed616aa42e737cf1efa5d2d8d93f0058878e87b40b161bce05ec63b5619cc8ca816dcfd6f19978e4b882fbcdf29d32d87133eaa9ad76a1881876b0d3f25b72944bfcb8903b8a5ebf6580140885f4fc1dc85194dfdd857dc542bbf246ed9013a2df8e8366acc8c069d22c109618733262a53f1770efd0800e04e6af9432a3c26c038d625f52350306a2d70a95a9936cc743f5448bd21314291943fe88b6455680131859cfdfad1c358be5bc61228787d4b8f839a413e96e923abbc79bc50148138b07e082b443714a860f327e7ba45ec00a3889a4e6f23f4d70718b72a2247b45f96672b1ad5001442106050536b2a23361b93ec461a51f0f3d7f1c34be2344c1c1354f301a8ca9b17df1b40766e8dfcaac368a5876e8d1c28af3493441796e1e949470850b6ac9ea3e02bc9b822e5c916d43d857c049e9b23d4f741a5721326ab70159113b536bb331d6969ba4479217076d9452b2c0ff83fb2c69b05274c33c55fd37377a081a86ac0a3f695c097c00a196578448ec96d02c5dea04fad2b1276015f3528fa7d15da31f5a89ef85a6e9621caa06a9fc55df753e7caea0e0e425733851caa246e3bd69f4aa64a3b16e09522c64113389291ab1df4d859b638051139ca690087601b47721bb058f5bdb448c8c485287c55390e99e7db85144b2c6be2b366e1f8d07fe764e19d5f0a8b6241f9f6bec063d33bc484657f24803e1f14784f37badc6a34234e94c1dae8be9977d86057a53d4a780789a0efa0a2df705784fb171fe64b493c352f90fd0d5c19fb2738245a737c375a2075d0a79b7cf4c745f588e3fc126e879d3c71434500a709f6c70cf2115bb4e5cac9031d98b14ceb932c34132837ba38a78f9bef9e521b8b33d205bd1acdc9744285cec3754ebdaf3e1e5810c12ca484c2df50dc06ed7175af1a3c0fba440e1587c0bcec373f6dbbe9200e74f04ce4dab444dc8cc6d1c218d17363994ce0282d4fdb26ad47957c6e5305bc21d5b5b202e04e63e0c234a161b8b5c45b582a26a3f21a7913df7064d9223d7010ad664eae5df667759c0df3d2f9486e34fcbd3597128284b64c2da4c1022b8815f6b4894b46b68e4ba8278ea7241fa9af5526d40a474e6d495a9fb837f0500d9d1c56c320d7e3cea4b83a8c05aa9ddc2f6e41b158b030cfb3dc0abf42436681ef3caaaca04243c569f9916a01fa25d1075fb988d7ad4286910b2b0048b1ffab46969cc5f18acf3236477c807fcba8ccf5da9d6dc2ffee3f5666111555e3d1e0017dca6a501a2457f2866513e1c62ca73977e986f80f0abcefb1ee22cb4115be06ffb0966f6b4dafc480a237f294eca0beb6353c071a7afebbf5eaf61436532053135e2454ca1b6ea559f2363053eed0a62a04101b3ef1cc870931f7b24b8014e67a1526f59ba551f5ff222ab5873ffc8da5f573d4569a3fbc81d5737602d49c658d07dddd0ba7687bacba69d788992e1abc2e35294a9e70da1e8bdcae23ef36ac6cfa91426b35cca0915e3824f1bc5a7a35e98d7ff14693d96be73eea0db58c2ca9f49d6f2e4866b162999eea7166debf21ba0522ecfa805b54e74e2c70f1d162a26a3055dba745d6f09b6e2bb8c36a3f9f10872fd50569c6d93847b18bce555b1bf250b9980f64a053448578281ac61064515618383c5d71707191dfdd411bf918a97fd9385e1dde7d10b229a769d393f1434fafd1a81c40e79598697e05ab5790411b747c034461ad0d7698e676b8d92f9aa4518f1078ad6f4d41d5058ffe410284624292bcc79ac4a3f0085bd3c9fdf3d2f08df0c57ba28e8b80345db341265301ec715d5558e32f1adc9840ff2ac15075248ccabacb69a04fbabaaae668f6a53c3f1ced830bfdbbe062192b45083a11691e5afcec5fc5e4a68b8afe22f84f3da77cd09b132ef13b4adeb3a070e7d9eea31645f2ef2b0f4e4d3663f582b000111284e0e7159b997986af6f5c6a4e8bc147c52a7ba8b2506898486a0e744285fec008dc7dcc49fbeb34755767e14fa961d221dc0afb9a0fb43175b7436ae2178b11ade77655f40c52024b05da8b910f7f7283941be7714b23419dcc6b79911837e0392059d714c236170355c7e36b58613462df9eea2e7e402a0389106cc81e78e2ebb876d223e68ecfd42e1e4a0335897c63b77de7537d12692f446cc4ecd2538a2937772d6fe97bd4ddad5123785e84e4387299a52fa5502c42a9337ef2d8721a91499a92fede1ea637b9df3bad253ec924bc61c0f2f7936ac95e7385d147f17e9ca6d8cd672c39abc356a4b7ec254907a4dfaa8d9f658624268a6f924782de7888a6a060bf14bd6f175706b1b7906219f525b397b6cf6720acc5fd75463aa6f6cc7b393c10cfaeda19669b2900d9b6776236efed5f03204af8031740d071a9c261c60b0c157e9b904ed90439f5cbb598113f6058658f4efed6a191db2dac5e7d6c8babdbb1f7a5e5bdcd5dac49acf4696bf60f4e175f79e7f21ef875b4f8d2769ec3915adf8dc2855ddb8b002880d1f53d63b8c3e76f997bc6e0b4e7fab2754821c36a7f30051b4630f3df3367b6138f70d2440c3cd5076dcb7992a7f2a89cd8541c1fccc6fd571112be1ad6f2e544edd91db384dd312c57d8a2d89ecae3f2ca28efe1d76e362ad22e9139fe3f70710c8c6f13f6234d10df3b006aae07f761279e4c6b70a79dd9aa11a16c9498d54c57c9a06e2d94291954eb011c748d84ec8c367a11f926be6ce08d25420c1d3dd7cf56c28dd4298ab7835222986bba3a5040e991f974c4ebfb962e29ed8920887119c8790f77198c4e7286dc198688014590bace3ae348d0086cf96992fdaf5c88f9919b4ea28e6bd2adbcf8ef2e2c8f5ace27dd3029b8780cad2fed0c3abd608b2e119feaf41ffcd6be2120ec0a9e9b179d20641517c346ef7bf2ed390b74f7412176ca981373f37f21f79dcdf97de08f23a4e70830d632665726e453d0a1d9fa0bb769c8c90a36423d0b5b2a410d3dc7f1c73e603aa6e51271ea5c7c7a62b7de8cf0b09ace9a4d7c5f1e9c76cae449fee29e4f823b2b74c92de7a130e2476974ecb7abbcda7a653beb4a3b36bd708e7a6c92a48d0a2d0838bfee86b6782cc531fe79f600325f7351319dbe5b62ab6d9a9c7c0d9ec8eba88d23c4bd529d5e9dadc35833a1f0d978408c6c276ddbd5ae784a04c28fea37b8368f2fee132cea3b880e3eab31d3b7d2776fca15f72f7e41e4b963a4eb757ce693629fcb99b670b6c50df6374c7c925c69dbbc2285625fd5262722c07a749bfad7c64e607c8b263441d57bae22bd5bf10337345faebc59c4b4f8786296c98b7090b3c485a96279ed45db5489bb5d07ad87f194e8124627c11ede2cec0eb75027106949dbd6895db48c43712141ce71ed98907fa1cf32aa7ad5bcefc412c50fb17bdcc6c45a3a77fa59dfec44360247f35fc0c280e3940209a82b76a42d974bb52e645c3b9c61a5edf1f3376e81296963bd668571aab73467761df040b25b5acad3423addbcb5fc39101c819ad8af8af50a656338301021e640c7cffdf5adb995ae65ead9d4fc1a76ed36c0f89683870c89f80287ac5a3365f93d278f3cf97e6232fa46c73214322f1edb289edccf7ceac270246ce949ce10211ca4b4f81df79adf4ddeb4b5f62677635eb9c9f4670e519a2fddb416e25f3835a4b1da04ad2e29f31eccc2f627019725cb3e480fc5d1bf35743126b876d2c1e77d30f59471eefcb3d454278e782f8813b14251338dbd7756c7246b002777ac79ce058fb3c2f37539203c9574480e030c94325ec16e3faf4777617bc97f7741343b9ca272441e6413bccd6d83c1877160a5455414183af4ded958629b9ffc7b693b5795c5fa7ffe2f8ce6d766130a1aea362f434b3c4ad3dc345b0491d8b9dc98ee1fb941fe7510031a32124392871f4a115381081a3ed1aec5c6f71a5584d0d1e1265f6c72ad119ac0def11215759a9ba7bec8e90000000000000000000000000000000000000000000004080e131821";

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
    signed_at: new Date().toISOString(),
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
      vp_id:             foundingVP.vp_id,
      name:              foundingVP.name,
      jurisdiction:      foundingVP.jurisdiction,
      jurisdiction_tier: foundingVP.jurisdiction_tier,
      public_key:        foundingVP.public_key,
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
  getChainId,
  getGenesisPayload,
  getFoundingVP,
  getInitialParams,
  getGenesisCommittee,
  computeGenesisHash,
  verifyGenesisSignature,
  verifyGenesisVPSignature,
};
