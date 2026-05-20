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
      oh_as_ag: [-100, -200, -350],   // 1st, 2nd, 3rd offense
      oh_as_aa: [-40, -80, -160],
      aa_as_ag: [-25, -50, -100],
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
    vp_id: "tip://vp/US-dd6c5e085b0f8bc3",
    name: "The AI Lab Intelligence Unobscured, Inc.",
    short_name: "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction: "US",
    url: "https://theailab.org",
    email: "trust@theailab.org",
    registered_at: GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key: "2bf781932149ce378151534c1002a20175b4af0ff6ae332c4d2c53e585837c6c9fd60ddd5817dca7c1d2f20479e53328cd12429c29711fa8f3357f28f0c6c9999d24a993fb28ec9283d15cb4eccc7feecc6f97525626e11d712de86992575fa0e7e18dff08a3ea6494a26aaefc5339513793e62221235a359518ff125b2f3b92f4778b0568310cf61df33dd84e60763d35fe6892af53b39655b9c4f944273f9469090e73d1c987da20ca66e68a8e488bf45eb5ce514aa9fb8b9f4322487faf92f2103142634ef3af7be20a4e2a0fd065c18548305cb06308280af2260578dece6e219617cecee4bef913c947c7d9e9549c6479337f2c6190fccc0976c2cbdc69d804b8f78a6ad3ef31aab20c950484ca084dcc95d3923ec37f61ccc8c9ea21fe86e2868bd82003b58f08de333ca6c1c30c1c3fd572af2d66190d5202f189e28ac804822d98451a54edc3c2a7dc755806094ea0e193119715c4e6fbd1d4f8f2197c170b722d653bea20721529a4aaeec5dd1886d9d2baa5de8916088c582d100aa5cdbd69eae20ebbfd004f96c608cf7cbdb0213243891862ea1849f501d0b7c279cad92eca1f34fcde9f2cce43e844d4d1e12dbab843bf0d4a68459f6182da380aa5d7526e48aab18da2443f7143ad53d081658373f7cd8fc788ff30b611e5106d326078bf4b3056e05bcc7427ca606393f77a258382796c13cf84155e7eb723bcee9a442453397fc085c8a56c1d24945874afdf44e82dc826007a19d396708380d734889599bd7b53116d27b9af051c5c9384f4f2bbdcc41a34010ae0553ff74b50780088e844a3bcda7b2e4c4194ffb798447c89a02d89ede5f7327bd5361adea2f2d933b85e6c0ee9b0470a8e47411a2fd3dad9dd5b8145ca38dbf9eb9e0b31c952641ff96e535811c11c374feebbc752313461a102ac460fbc55e45434a77c7f6b0b3bba38d7dd1b222c29ec5e966392c632320124fe7e89a7c08c06519e523b4e2e7acc492689999d898ab6e6ca4cfec49f85bf955e9c57d20d264be13b6556416707697e58f5608751fd830a32948045f306844e5f4ad07d6eb81eb45cd76fba7a16bdc43c8ab6bc6e2b1fbf21189d32dbba39f24976ec2852d96f61fcdbc8a0a513ceb85e69ceacb7483f372b2c63e3504fd4c8808b5803661fa37b7635250dcbd28baac18803f416a48aef697c8ace97a706c7f3d2f052cb19c09b32f934f5f45467d7b025e5e17acafb18b606973dcf901644a30695cb330829b9a32023c2dc4f7bfd56ae1335e25b6a574543f8e6f58111da1f92940e3ac4b0c851a11d586817d8d959629c9b6b7f380afcf4305122926b788826d6fef3882bd6a91761e6866123917e4d39617eb6f3b64523027aa21d52fb908d21cd02bab31bff599fe5bc98ed131a90a84287bd70928ec3cfde9468842e05181e338741ef4dccc06f42ba050a8556bf6896c85fed9a25e0afc1eff06f1019318277f28bc5c1b0deedbced417fae7698920816c839fc8f6c8d0c3928946af815e499af0703ba9efa2e96698898de02fab3ecf09a3b6dd39f8f1d75b7f7c730406db6f18601d7edcb71f572e42ab5a3c932b72d482814912465c247ba192b36c7b5b0546dd7ce64dbb7fd89652905f50aef5ab0ba4a630ee8a2d4eb5269d70569d53e280e37e53c7ece391874f0043946b40e69417a9de19db88be1a3531e7c0b5bcc6dd11998c9045a86da113b237d9ef32cdc969e10180d1604bfcc18dc0b01b9b4d853c633c669c80426cbf4f76643e4647aa032683ab5d6ec18a87695ecbc8ae49166c4a0193482a29fdffcd163bc702093e5e77d5c2bb6fde83de76f0da61e60007e1bc0b1238527422a24ce10c3ece4b820a8de3e6a8bb0372dadb05741d125240aa40384c98393647a6fa0631507d24c32eb6bb9334922260a04f32de3d69029d5c6cabef90d6ab05cc275fda60b26e57bc920a78ba3c6d4e78d97644778e5ddfa46630f5b56390781d5402cff9049e920b19418d2905abee6bfe1ae479c840d93e2d10ecaf35e77f0c49ae2985d316d72492b66598f2d35159d24e78712cc40dfa2fd40bb9f28b62716dcbab6fa629c9598626e2fc21e48e26db9bb52d4e4fd227c08c697f2c37d9a3e3a8826ffb255e0313e7ff02096eb46cfa31ac7570966b58ede97c6dcf09c6f2d32b0123a254b351eb68f2e0a9570a77da139315e8bac9ea26b7a92acc1b0f0b9aaba6484552b5c0b2cff4b8b71b24061a26e729d41d96e4fab7bdd9fed29a8d5fa83407c5db8908c7aa4b1d520aa685b37e9545099db342ad4b7086e3921558e9f4b932c94b60d4c810eca2e7a03348d61c38ac36f91d2ce3281767e06a3d9d918f742f9e4fb2321f14c5b8308fb7de8e5b4566be866f9399b299a1af49f9b0bbaf154a5d4db5ba92709f57055f0c3bee37a565b536588db0a4d3bc89a02d45f528171b4b46c18089baa10d4d672231956795e87ce0c2fff31378b38608d3fa023a26f9c2e410160a4cc8edc4f62e6ce1b84b9a05254b8fc5cd65d0f2d7e5246f383e0fcdaa5eb4a06bb7f1775552d3189d2c2409b436fe04f150c4f3becbe5f8e7e77d23d53f6e54d8c53a543b88ac9f67aa8513512ab6bcd0209069f525d7717e5f058f5f9d1e58fe08fd6685dcbddcb126c8358de8e2007075e50526799a1d989e4deaf5583516862f199b91e44bec8daf0d751cfce7f4b8dacfc4b17e356ccf4ee621ae05e3655a46f44c6d420f333598e0d52671f5f9d65",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  // Founding node — registered by seed script, bootstrapped by initDAG.
  // { node_id, name, public_key, council_signature }
  founding_node: {"node_id":"tip://node/4404c815a812646a","name":"The AI Lab TIP Node","public_key":"f8635feba5bdc379d990c62c649b2faa78c21c966c37839578af7bbbc5c1833f342a0ffdc6dc21e4a1c9c0087acb1f489c2e522ef134fce5e271d7ef3a5e178b92a2de1f364fc8c107ad4256d430a2a1c83d3a719948a7ebf40dcffee92398cbf5bcc2f58fb5002a218ba722c4828f803a1d16c921fac7fc0092aee081dac0ca3ab0b88f3e0a39b675b60d5cf153dc23e670e9b00f89919b4e5ca4ff3929261ea2800a000ea00e520df180b97738d7324f8edb29fed61d772c168ffbeb8c75e6be6c658351629c38b152b068c63b5667e4f3983ecb85a709b580c56cb59dbf15728fc45d927baf1923236414ecbe209d974aa9f29d4e07b9ff43ab4a5b1cdcb3292b7bdf64b6da270bf975b348d9c14123466fd4debb59cd6a80c3583c5911dfbe58f251ed94f7caff3fafd91e072bb8d714caa314734a9b1a2d3a1e2027fe5c1afa0df928de68a432e92cbc4df9adc33361646788bffbed0c987e30251dec61aeb467fd66beef3f6da56f9337d91088fc9d381d09a434edbae5f86eb67dae89fa8208e6a4a990d367734f1ab65ccce241fe073f68823a8fcb9d7844592c40aed53dab85ca341025735b077f4ad2d449020a2347dd8ea7240f8600e3a0ed4d3ddaa706338f5506914887ce861ea7a2a580cd76b55a16f0dd1f0883057023b479c996addaff401d2cac13ed5fb46bb2d47dba0f1adaf6e49208f73b0b8291500b05a0efd7d8b181033e6979de7aedad399673cd51de85c689fe18d7fab6d57095830fb62f8396d9f2733c5dbc681f1534ef588184db16e6b9bbc29f2f6b426dcd1d7ecf15117385f1548c0acff71418a5c89c0d352a2c8a7f34bb730564e0d048eab9a4931a346cf799f36d7549a708fc3a3336008dc6bca52af20e5273ba407a11c643cac54cb58a8d02dbbfd77d0fe71f0407b6cf873bf0e3c24f15e5f9a2e383d35fef5ccef4f49f8f3dec4215c1374887216ba7a9fcd13ab981512b88e8a97f941a27229d6813ca583c2201e4c415950f1073df25a8857425e177b42a8070c3b6316b9bf749fca8b305f6f0b8e7b7545d5968f4d7279b3cb5bde5de1dbe97be7369572f8248f8732bda9c99e34543c0f63f122caeedf28a95e14f4f834579e61965a7ea6a53cc485bc44733ae03a447e846cc85d8e7283f2477143f2fe4a72092d29929a65d88282f4a0f7d9db66256600a49d88a0b0581bf92b6bb9958f04db163da0ca28f3c2f21245bc17a465df819dc0fcd9d78bc1889af2eb77a04dcecb4b40b958dc787b4597818c4c8e45792a10ce612139f60a87921ced79c8111087a252481de9e31e49194de4cce04a62cf925c3e2c03f6d36efab4ba27da609f97f51c7696e5473061de59ae18ef06b022b6835bde312d6973e3388567d8bca4ab3dc7061fdf5456b2c8bc6813a937c9108d17eef2e3efe064d751696a3f1fe514a6d714023c251d41ab69e0cbbe7733c68452bcc698089240b2c542b20a2b4a72f7bb94260bea43f2f59a8998e56b1b21688cee836f98830d54c0139c4f4ed91c778b1622a26ad0b4658dbff053378a15b6571f7986c729f02d5bdd6490488efbdeb300ca1a2f5eb0965ae2bd08eb245636f5301ff916d016c6a0d7df8d078ac3a7c900eedd5c3481033264c3dc3f873837389b9ca77a2b053338d3943f80e8c441bc2dbf6b0d9132e77e0094caac9c049e7ef52f0b285ff7da43634481d661c18561d58112cf5650f8d0d211a00688899634c0690fbca77507a79ce465c4ef0a79dde7885ed7904c11f1651822a52608a0ce18810f5be22e97d1a9a6eaaae296cded0b1afa87f7fce1c081a35bfc66c9b81115270a8227c09cdb18233572276f9704def3ccb5bd2db719b58adbe0483d3c7facf60a36318d7ff9189f13cef0525cfe59feca599a3e4fe455f7ae81f61cc7783f3e53045cd8c9a3bf146f5422caa52352f10df799ef438f25a554c24406eecb299c4168409fe73e2f47ec004ec45f9fd653702055cab1f6d481586fa3dfb8e306427b674e15ae64eca949fa6e856fb2637dfa36fabad6afa138a7c2e39928ad69bbfed1a55a908a163263cd547c111e34d996fba5ea1cc5173551f162f131118c17357432e7f77b9b87cf1dd1d08d9a1e489a1ac63df8dd2412863b7f85c0347d1e7e3fb21b1de99e625da6096c75c71d495000b3f840087de8960ae9f933f40ffc598125f9f2607f48574443e6cd1a5a4236246aff5fdcfa4100e18d8c0d32863ee32c3e900fe495de25672f6fce1c41dd7b73105c5b8f3033293dcfa5a6d561d7c2cf2755a5c4d588cd8d83c36d67ebcf569dbb6153b7721c5dbcf2b15235be989e30a2c15940fe5c8b2be8658cd561514b23cecb1c0a22e03efcb036422ffdc087aea1eaf9e6fae6fd5a69c807a5b9e8afc558b6fbda2bdc14b4845bd3ea7c00f456a448afccfe56fa8edeb8281eba79de8ce1cb83c7fe54e0136ed2e409d8285ae686eaade756de14a16256dde18dd5a2e1e5c09b6c98c193f319d1ccb91e9fdd0dce688fc7188352ff874f47119bbb53ae7b3f647f7638fc0e9ae10cbd34e07facf77e2210089ed98d6435df95c6c5bc2b7333fed3685cc25b50187d1929bca482c7426c9b3b2874561088e665980d39c18a59a1a917f2f538e78f02cf39c5f9b14f650755524b20f3fadab809bd15229fab143eb223bb38cb693f3ca26044908dd979810412ba04b91a9c526f727c37050909572752c5f55dffe2a8c19135ec467298665bb6ad90218","council_signature":"98c583273fd76569e50aaa42c810e94b538ea0be82905b84ee54111b181602e0b5c3edc59b4c0b3e5727ff7041af62f5171a7e4f8f381eeb70e175c5c9490f0fb720ae9f8e99112d728b9755529099bf2e6b3c107d9ced75d54869a9152fa6966b66ef4b561d1fd3e32392f110c169468f7072c1ce4165c9070909b298af468905444f897ddde8c0f18e0d7ee2ed324023a32230d046b1d6439da789dd9416a537ce8d1020009c8299bb28d5b919fc39dab76dd93252e7d18fc9087b669a81c7c3c179096be7e5cc0761d1a9ad201aa0bdf47ab4039f291bee59e9c1ebe61dc3e0e77fd31285c8b2beac2c25663b3541df10e3b06381792b698d6643d066be17c14932f3408433d389e14e7afb5638427767e0cdc388b7a08f38d8d5d2e599a9e6a32ea51bfc3aa01a98f9c6f47e628aa2fa741461213b35845d3582e36c3497b2fcbf9a14210c966ab48c618e6e3d92bd0b70771c0b0adb6fcb35ddbc97a412edac95b69602008b423c02fa93e3d0aa8f29793687dd0993280b7ff86763cd77a19ca9c25da5190ee2e57cf28670644ea17ee542bfe8e9c04c9e17163307d38113c20f03b75a273610dea98a1a7a1380299a22b64593b13e096ba3e3d332f9d24bdbe1d3c134211c19072a7d7e6f05b5cd2ba1f77d5896c70b500c575ac1ed4b32ddb237fa4b372841b96998a32a22ee264620d84a0dd53825afe9278c0b2a6cb7f602a7bd24d2dd430dfb5d6f0c18d1ea93bc31f0aa898e135dcf178f1c72a6cae3ad89bc47fd5f53454b8904f408a6eae8b7e8240eb4807ce4a7ce0006b2cb0069b2d7873141f972d53ce32127d6feb3c4ce337e9e907431f842073ab3eec1049bf92d519eb938ff74e44caf4dbb245371fb82fab853ef0cdbadd9cb742077a3ba57154d28bfe24effcd20a1ae9ad32e8649cbb5f082cde768fae07934fe4ab239c052085d28e88435319cfd4de665f984913ab7c9d11a7f7a0b668a75dd7af81a9ed235f3aa7ad306e7c5d8dba0499657a335b88f6d0a4ecb745ee97fe13f9169e971b072266f7cfce9bf92fbbbfe56309b468201c00cad4d808fba81d5ecb133143f8f0b3d579288ad93735b611c8d5d25f99fe856f2358cae27dcc1b34f77c9f4924c19187af305b4359828fdcb6592014e3a8c8a21ea9ae277aa6494857bb0c4bad6285f7d4e6917487e24bb62e15bfa2a74d40c2d9ad468b963bf24409ff28260ccf37aa49fc45c3e0ecb6a7d455628d222280739b7323903aa99834a3612b0f3dad6197a14ed5a2580c1dde96f49e80b8f4c7449e31eff13407db3447830663d4e16ea5a23f03bcc4c493c6bd629c7f6a1b01c66f66efa25bdecb17a88b358047ef6ad30bbd15f3e9333c0fa75e94182ccf35bc2939cdfd8e4a57bc80392407e89639b7543962ea63501bcd4d7f0548d78a2e7df9cd4e069b981cec68c15a2594dc1ff76f52bdc0b463223702e1ddf11af580e846a944818172ceaa6f2013811b25360d03f755a116e66c8ec2773c61ef59d1c521a93866eecf2dba418f335d310e414c556452f95275c1a9ef82a290ecf565a9eb8ef0f512c002b1a6f17e5309a9bc3f488aa5fc24c76dcea715ea64520f3a892aaa3ef2250da2619ac7cf4803bce2c8aa6d7a1974ee96f45b064410149cd09aa47afcadf1fb2f462e386a99de3199be907d0cf224977cc7d3000b431f1354c7ac4c791cab69ca85d2bba6e39fcd25166c5fc9a3e88f935b8c722a7b83a3866d742153a8547144446aaca9c79d8aeba43a9b64a048939b62ba4878396c28acc7e1265122f4aae42e1bb5bb840524f1d87cc1d009685789bb5fca915af250bfb35ddd3082558a6bc44b19596706fdf4279e85fab6f25ca808fb160464f0c6469ab0818563d09d33a561987ee61a2c698f8b9025519e98d8623b920e9270c5cac42099c999173a0db1b7a5d54ea77e547780c63d506199a0db509927cca8f3840e4985b06bce3350a73172df66d147877aafc9997efac04d970e1d9ddd11dd43ce7f8a72b718cc008e126504ae4aee62778aeda688b22db213354162c6aab60d74d0e6a88c8c562ded7f86902ec009397356650d3933f453ed80869477ab685eaf9b2aedf7fd1f18b028907d446ecc4789c63cff8907c39a7148c2f3fbac5e31179afa0c03a4f3efc82c627b40546ee3c47c4cdd03a7c987d07c50ecd715065b1fdbc88b08c8938e1305d343ff1a19d5032fbe1e7cf55ff9685d5afbb32dd780c286684e3ebdaaad29a7aa4a1c6f8f2e7b919a0d08ec24f2dd430f56b56045f09e45084aae2917b52f33b6d6d2599141e728cc1ac3437aee5fa8d1553cdc1fb757a0cdbc8cc5d30d303135171ba828ab513e54dc91f9ffc41bfdf2f954a8652e6749ec578461a6615fb6f5b1f5266d96cd0f236a0729a9a6efcd327481c47da1095cf5a5263939940ae70f0f2b32d14e71c13e28e8e8622b0e90ace1e3570b6a45475f494da2c2ba9c1face68d17dda8de804d441be122fee522e774cf0e9d0cb7c90325c9e42f67da90feded320f9bbe46e219ed78712616e306f06629d92a1d2cf8f4e120d6d688f7f971698bcbeac9642dbbde3f1a5a97d575e4f4f4a31b74c20f3f473c10b5ecf67c7e661523975880796c32f983250b7a5e4f7f5e70204d5ddecb7d519497f3824696785210dcff945cd5acaa808530c0527580ba2dde6d31ebe140c14c30e1c2dbdca50ed2282366b127c3f980cc7e68134d27624755aeeb16a02ec9ffb8f38ec66781539c30f61ff59ba99e1f04a830192ef267f64d143a7b7378bc4ccb6131344f95c6598394663104d390ede4243a8ecc6408cdeedb84aab008e91968d4c318fa8e2d9222330c52cafbf05b9b23f0834d35ce27d9a6f1ef2013a6ad51f9e64555735e97a781264463ed1e00beb9e44b5594a7348d92a43f4b39e880741eb474b4c1c61e7828699392eff0d538a3605193180a10e00236aafc052cae0ea629b07cd163e48b10eb95fde5dda60cd4598db75f438f1d5abeaa1992b18b0892ca04b31a178e8c8b36f956d052d9cc95a32fd6fa6e30ea1db069140b48591d3096d99869c6f8f897f7154170496a903a976ead8a44c79b8263819041d55d32ccf3d727cc18144ccb3bc407175addad2c24bfae6a3b9d94cb97dc24762fda4e6e6ff9f37bbdbb399113340c7d4a2e8a0ddc10f5e1fb1271081696334949590c61e8cc4c4e92baee310fac0b39e133b05e43764ad22201b95ce7d125d58d65b3a813b58d8904af92e0218294f9798d9470e917287e6cc5e457902bfb5e363100ae14772dbeb95368d6b51e6333db1f189745ab887d622ce275a966a3022879f47696fc7f538ce23fc3969b6a6b9b3e89141b418b99879350cca20821c2d407ac5aa1612382889eb5f781b102af0443a1a1e4e235b02d3a9a377b98ac885becbc887e5fcdab083f8041f2783bea39a54bf2db54a4fee7160b43d8f0e9cab35d3e3b6ea72f7895e63f2a2b7176bb9561a10ee6b5c28d6b7eadc70a0034d41fc0363e912814cc5ce2853b6d9921ba724a5067092e9e492087fdfdf6515f9cd11c6383546149e6cb04cf6ecf671c53228cfb7ee66e1d73600facb7a653802f7b85f55b39dd6dc8374e4f326d1c176edb6810b2b92c3294e6ac9ac69cffaabf57ff173028b544b8db5a6d9d1de3e029cf24885d77d5ea481aeb26972375b9e8dcd8333f40a77cc6e9f075109b1112ca71e2a11340a3d3e2d6a1b942478b410b728325542a950e319283871c3fa63a73d2dae59b58aa07bee669bb2c003d5558a466a4776b5a21ef150b7f3bc7f66a6aabfd393ff7d085cd121f8299456a22f14374275616ff0890aaeeb21d287cf563e757383a0845aaa4c604aac2d32c83b68fd456fb6342c74e5304e6ddaa2a7c1d3736702e7bbc6b1827301f8b860854b5f81f640a93976beb2ef26992c80a9ba83034f659528246bbd6c77dc9f8595ff4ac4d9c0b6fafe9716e01106cad2a893f64381109008d34e5a52534cbe56d14a88ac2c3860a4aa48f4e870c6a23bd723217972a8797a1f1985c2bfda8b609ad937cb1aaee16e88d04708ad6a363e653d7d910bd88000fc380e2d7ca2b85f0058e2c8bd91892065ec382efe558e382783827bc085c7bb593fd61698f4191d6e8eec45481cee36ffba727ee03b9bc6b553f4e495e426c1f4c7bb2fe4035fee95d73f1ce615dda39e592cb395bbbf3ed34bffea051e86d9bc578f4e0cc818cedfd98a002408f7de9fbbf885c19f5da90d0835dfaa7195922b20b42d2d781021682e2906f1e0ed36db007c674ec50b4a9d61ee78a8658d26fa03d8e35d477844b1e4b54852f2b3595250de04851d706cb74ffd06fcec42b78caaadecd2e0fdddc18b4d395fccabed2050baf436e1dd1ff4e0bd3a437bd10c90cbe562192bfd75dbff1aec58c3bdf955503a2e818d0daf6fe89c0a1acd1016f23639015abeb17ba8c05f1a3163a22c17873c02b409eee48966d938cc7e3835a8696fb0af866bc5ee9a9b920bc6ad219189763855dc2c79ec00429422dcb61ba72ac415b8dda59ddeb801911d459e1afd612b9585a763a19f5b2c20a02a27f02425daae701426ba3b3b4dee606276bb7f42a699db447525fb6edfe1021333d5db2d10000000000000000000000000000000000000000050d12161c23","approving_vp_id":"tip://vp/US-dd6c5e085b0f8bc3"}, // embedded by seed script

  // Genesis Ring — founding verified members
  // TIP-IDs, public keys, and VP signatures are embedded by the seed script.
  // initDAG uses this data to reconstruct identical identity txs on every node.
  genesis_ring: ["tip://id/US-602145d4f714393f","tip://id/US-1d31ad6cb3ea1d1c","tip://id/US-92dc73984b1c8c8c","tip://id/US-c7a97b26711a37ae"],
  genesis_ring_keys: [{"tip_id":"tip://id/US-602145d4f714393f","region":"US","public_key":"d87823be0aa3c3c60bd92728c77c9d01595eb54b83f4ee2864c7710ad51b070d315c9864ef044f34dd77510b5c230c6ea48df41bdf9a673bb5f0ea9deff99955f8fe4d72f461db3b47347423124eddab317ce80229ea879e4e299475d138ce1a98a3252551db9721ae8d3ebe42bf5c61866460d0a254989af31836131b1c2c952f7026ced34fb18bd5a17c82c0662daf3f53e78d56a96f3b1545077af794a45be3eef9c15a604fb5d27ba05aa0a654d3d2668616ec366bcb48e2ed14d9a1c28749a29650d5b542a4ab7f3502a8343ec62bca903210c674ffcd1f13f256afa33962d0b7b03be89b49ecb99e075961fa3d6f3e26509fbcd3d5be362e1b86ba7542770d263dc83fda20d632a12408d8439e3754f2755886107a82bb1bd2449ab25d13fd4917000c2b6e3a516b34ebbf65c09b7507fed1dbdd1a0f266b63e86bc29b4af72c43a17b6357fc60f1d7419ec576fffc073b7f2dd4a8f89bd3e2cea31528695bd1b172c61a58de8b669eeba293aa0008ff12a0858a0b0dbf3e9d0cbb8ba1a03153354a3ff9ba08d2b12ddeec3c9471dfd5d0b546960b443ad8afd00b142d7b0cbbb40253cf5903f8a57f4081d10469e31b9c003d393fa8500e32ab6b5c8f333b280b01bcd9acfc6a22d05ddcd734d051ab4384b5182af58505056bd926c0111884d5ce85231c270b67c103861d049704b8c94c618ebdbbeec4c2fee38e5087de8391f9caca5ecd0a7c3c66d0fc9ab038ff19a2419851c35cf638f08e3e27a27979e14c1d1a9726aced5cafb424d721d4547e66feaafefec32c902d429c80f05ab496d403d43cc69b35441102a9de374e2bb45089b9c3489e59fb93a4055e817dea3a2aa2cccc1f106cc71ce274c53c91278e3c2f359999cda5bda72a2366435a35226d62dfd4cf2503b671ed0b047ded4dffa65e61118ca20dad63debdc9c46ff9f9e8e4940a5c23443999cf4f12cffd1ee1720f7015a9e01e08b780ef79ed9b5ba021380f5fe6b4b837ceb7584cd1006b81cc078a15df2f6eccbf5924f4c7ca66014a77289a3a1bcca08bcfdb50c5a9ee969694d7c4480751ce051589ec5e7f5b090daf19c28c8b782f1af2f0bf0c2438b486b2fd4363babfc3840aa4d2cebdfdba34a4c4f77a36c57573cba751c9f70bbc44e53d558b81ab95a2575d02b3fd7dbac8f79f6607d61d7208fe00fdf8cb766776578ad10444b5998f2b4cc0c945454a2b2f1c76fd97dafecb8b8b910f942f85521df6b4bf50e5b3bd044697b42beb17969cac438b31f59d4ac2ac7ea687b6691660f20c61f9a7c6a71955f8d50b6ae4a8002cd66d1efa47f58c3158773e41bb44cce99a2af8a7073d4051e7994ff9d89b733e1f5b3778c90cf3e2205650f7e49d8e17d069b5e9a66469c17bb5803b49227304bd5099466bb9c636705667963272a6d2d33580611322cfafcfb55c58cb0710dcde4ea6ca8d9dbf81eafe31edcde6d0f2fc917783f913da6b50f6e9def4b835c807f894c0c35048d6eae3cf60f38927436abacbb12168081cc3419a4ed550466c7b1bf6d38980268f55628daba11d08ebd09ca82642ebe31c3c3340bfd65733d956926b787f1dd53a06c1cc62bd9f0f4a71340bf3bd05261178322c0ed7fd02f7ffe909ef43d00ffb8c8951b92a4c13581210653cf534eb1b1edec5bee092506199ef1085359fea6299ef05ba9f0fcebb7f7ae28b1b2406427a08daaff9b060e210aa605ea8faa7e296e4240ff59b5e7ca874c8d9896cf8198e59fe981d06b43f49d98c8aee4ba5aeddb5560473b63a6814410662c607bc9838a484d74bba39158002e714c7c6159f6db52971b8cc968aa8f3b1eca3e0178ae929e28010fcb4d48afcf55cdd0e45d903bb30c088ab83626ccbe26bff1bf34f0a56c8dbb51cbe8adac87d5fbefa6eec6ac20fba8c526cd1922f1cbb8546ddfb0adaaf6c7d843d908efcc0cc7b54d5586f2da33d30bd505129dc7faf31c3f42a5e7ad90056c2a00c17b46bf1556b441ec58b35c6c537e7460d50661333fa76152c950e18fb95743ec48aa1346830b4e89bd26ba3e8fb89b472dcfe9b1664f6f2e52796c22b4b1993164fec25a4d45f3ac67c3622659b2088b1856309740572d21ffe09dc94ae2d536800ae451fe5ad69d6300d7808d1b4810be6ff3a471c74efd5ae9ddf3c9622c6bda009545b50724170a8357e18ff747e08c79808d1b4d34279c1913ab54489eeb73271f8fc64df7ab614e715782cf4f1ee08de58bdeafa0eae95068bfbc1b8eda7ef2ae8c5e94b0850b78faddb89ca1d8d4dafcff31d30e3449e734f46b60679c621fc25c40075265eb33c1037c9a8004f8db89837c74c8ef9dd8a438d454aaf5b0c26eeed9d718aced2075d3913acdd507a1086f0ea684da7a4bb7bb70d1267d22e791e6cbe781f383094ddbebedc84218b7cbed30f3569c113f6c2ea576d3789c92136022d1e30d7162ffddefa03f526f543fac0ef485d97033b4f0412b5dc7561894cff33152b7f3b0dc7cacdc6d8da77c778ec8ba323f43418def9dcf226215d87c399865c6535c8b2b9edc1153f66f5f56beb9b0af29a3703e4fb2af74e978b6e73e88b21ae71dc023dc91beb4a7def90ac7d811ea739054cc7feac232cb4cc3c93c5ea714c14b2bac57854457bfa8aa8d0e5d8a134a8a61abf9a982d05c2131e57770d6cfb4c16e1476e06bfd3c2f20cb7e61be266e17c90df785742ec2e85c9d673da1b8b95f71894eec553a72f9e5c9fa1c0159380","dedup_hash":"92661839774354454942","tip_id_type":"organization","creator_name":"The AI Lab Intelligence Unobscured, Inc.","vp_signature":"24c3142bef97999cc282e1cd062ab17ae49570209eb40dbe1822de271eb07aaf8c3b5b8cd2cb333bcec887b6c86edacaa9b9b629126428a6bd16cb7050552673e73003b6a90f0157097eae39e3ddfb90325684bc26f3f4a5f6d63e0638e35f2947e7a4e5c0918940b25c8f0245106440b18a2626c2cd382ac8d98856993d8bef87e04c10170afc562401421a8a69a1d3824b5319e0cf2aa625adcc175e0ec5fcf26f54767fb68e8f3f64cb96a4d6a36ba74b414c9a8be4f6c3eec344d5be1e0c7a99e207a3c8465a16b3742e3deb82c1f063bb398f816b86656c616c819679bc4ddbd31ca5da45c7e2530b928a5a3be23f931f9ff17fc6f71e4531f69d15810c31b757780c464b09a5ea4b4514f3713fbb9408530a7312df8bff5cb0f573efbdb945ec19b46fb0d2f78a21f12872131adb51476f81a75dcbfee08d59fb0891704b0d5b44dc55dbca7569e2c770e39348223fef97f7bf4c768dc8795f6fda0f369a661e42bd9da1ad14f57385292d3afcbe0a2168e019e17832b87e04a35891ac9f6170afb476ef5c752807c376563e742c258f997b1d8c3496a9872d2d0c2862764f97638b009acde292633d98da67ab0a7e4ce558095f0d784a761b7d20b48192f91bca284edc51e50714dbd3243b468585c5fdb725278abe7f53154f897fb7076a97bf885945bbf1e1c68a184b4bdb88dafdfb60aafe2f6aa3d7caec6417b842e9d7c6bdccb250afa44a90cbfd305281c92a062402999b981f6feefeec1a7be8256fb1368a7318cd530e7386ca20c9db6123785d14873c484b9095a7c3633f2d3f80e77c11f4f55513eec8f2f570d8c42fbebb9c4a3e1ea0e856e8000f20dcdb0d234a9a0b2225e19cca146c8883d2099f34afb1e14b8d51c77acf7160d535a88619d811c18fde19e38d046b1371cbece3e5cdc88d38b83f92084f48de83e408b66d888e5d8d77fd44acdd20838bfb2182f2d13819ee2cca278855122341002acafefeeb7c15c84f3d630adf098425ab7e27ce0f3011bab349c9b74bdceea25c39575974f7701538415819db49159a8187c87f06d5c91c0f7aefd7479964a964888cb96a8bc0b92311115fd9d2eaa5ceb17c11eac52d79870964b1c6a6ef87020581520c7c327e9941d745b7191bca5c1a2c6eabce9df660c286f65ce6ed5b34ae96f4fede24ea1f8ad70f6b1a77bb1a005ffd625585f70b78a19e0b6c6464f95fe9e03c4527b60c0bd1b3cad02c002151f1ed824d38ed4e2c376f76e273b57d07ab6099c0f12c1fbca4d3230c5f4428c7c3dcbbd839495b9a5c8ad44511528f7cbbc8bea424cfb9176a4863b83364f4bad88fe346935fb8fbf0f86576bae46c7a32e008f0288476866b5a3f200d469810b839a4dfa695e9ac6786002dfe0743f690fabf8f619e2b0f1929ccaf51924bec55c7d488119f0e12b85a74468246bede4923cbc6c75edbf1eb1ed8247e976f18e3995ef2bced2286dd45fd829d71d063c4ba1ecdd30f2f38bae48a22ce2a99fb373f41e45201065837a408f0104a075f9b8f11ce042dfc3fb6ef100fbb286109d8cb5d9baec515716f69a19cd2c48035ae97609845a4daadd4f9798dd4f37746158756ea531133b56635f95c62a6b9d57423f1d0abbbb5b2bf9914d3c5f4c62d8f76994cba5f3cf7474dcac952acbca036968a6a9607557877177fab86df1954aed557a2ddb04a64b84f3db1ddfd07b17fbd081f66727a2425a0bd4e79751a0c88792d90591e5d945a9ff7c2037a1a878799178d4de6001c165d5965121bca2633862640895cef1e7314438bb87de46c862a96154d99fb8b65b4f1844df05273c4ff2e07df0e6c6823206752e487663ca8234189ec2bac56eebc5ab6e7cb378236f06da4999c9f1392f293f3e83f7e0740fed4dc6c94d519326f91235f4009b01a97820ee385bb08d74b97603c9f0aabe17ac209f68201bbed4ffb6eb51fa93f1bfda01d030d445e9799691cb4c735bed7d2f395042dd9b5fd2a19ef07e4b84ec2986abbe028f7540a13f71bea6dcbf4b5ef3d33209f0eb4ecab5d77a08782727d685f4ec49487740133b92e18b44920e6e165c1248b7c8d3538ee7b1c1a7a250b2206ac5e3b83df5f1ece4f22897211293863954353beebfdcba9e5024b98f5d278057b2134171767afa58bb279fd465791704dd506216af1e5d9922252b5d786b4bfd0a38b417cea1999d415634bb4d2e7ff919bbb0682992da2f16c9563130475896bd031e36511e0a25bacca086f272046f33a8c0478e40636f40a1b4716f91790edb1f73d394014e8b8d6fca7ad2445a6a6acf322d4b789fc97426196bd310fbe239c07871983a1f920d9e26732ca720a04456c6ed96a6958173880bc5e76b035b37de2fc29697f31ef6106f7580ed1b24389a01f85401497236b70a9488c7b63f96b72b93d170477a2f9de9bf53280fa5df710a78986c8e244c3a37a69a084a2e9bbe6114f12a2e7a0c80fa78d28324a314a51e77ab7221248f4f9888d2ef1546b2dd3a94353026faa22dae55b74dcee4228d09d6fdf2237aa9b178d79baa6739520bce695796593ef65781ac4f7acf5b089e75b76f386344b44fd025054b30b71fd6be47478f1385aca35d6b3b011927df890374ff95a27efb485a50e2e0606327b90072d6350754e58351f855869ed98021e8d7154e5bcb77e269e1fe08bdfdedc146a7774a732aefcb1e9d4561dd851450926a4d093cafa1c004585cc4dc9698456a6b7741d566088fdc2f24633383cbc4b6cac0437f9125faa5fd70d70d7c70a051f01a83cc266861b91521e686ccccdf5421a2db6ef4a3f8fbe62cebcb34ea8fd267bb74e24957d6aaaf9a3b30479fbbf0691bcc66abcf017a010596fbe678f81e4aac62b682c1ffbdb9798aaa5e7ea294e7cc36e7288cfba08289c6416ef74ef555a55523797e2ca949d1d85f05659820803b7da127aae5cdb2a08438d36292c09f825ca198ba4bcbc9908234ade742a92c05b9c75089f44d6a51df8cba076129a0a3edbac514867cec4a0119f9432904c78bda88a3636b7c3e2787dd7a06d6cdc31b775d7b8939a27d8b7bd6f81cdb04afc6334d782af45a82e25b78b7454fed0d4b70a6e15424f4ae378cc075dab9ae51ac808a71eef86bdcad24a1bbde918ecfff51d7afd0420459982db860c7a6dfc9cff7ac6b0a0983b0ea3e9369f3469acb1fc102c7f37e0bc548cc7d90f76ce67fa89bdcec26972d4363ff084d76c0553a75233e85dcbc8fafdc4518831c68bf9166c91802d4e6ded65be2d853eb1b96e63c29e3e01d640ed38f50ef189e54215fe228cb78ef8b635177fa853613ba467429eaed42d042c10a6ac2a33f5ad2041b7eddc5c7c9736045cb823786fe7db0ac924afaa0774b19925aa24e2f8613a93114349b15c09523e23beba541ee7a84842ab213d35cf904e85dbbe77a51a4f8858baed91c191cdd42ad98a9f7dae0569354411b4a1b8b02318e78bfb7fb9890321375ed0820a536b0a7c077aa8d9b6374ebc6bde165c80db87d2f61d652517a1f41edb597edd3f8bf7dc01c903b6bc9a16f96da7c40b996fa6945c6e2b243b759e4a6229aacaed1c83b928f0cabe1244898b3273fe9a607ef7091a57465ddb55970974cb71bfbcea7a07c88a1f507f31859d500f5dedec0661bf84e72ade69b5f7a089ce18f691417ce39c940c6c8c3fabf49b75adc9764d8e2215341dc2ea77e24019e542a52242ee8447a7a299831efbce8715841eafe9b0f526d80bd717db4509c10d680f9789286c05d38ebbf0b4fd10b2182debb164fc97f7a34f77d61b93953ef1b5208a3642191e42fe89a8df0458e00c5448f1917c566bf7616c552ff7daef8d40d0a7a523b711210fc60509290e6a2461603c798aef31e545e799fa00ba7cbf0379e0e17dc966660504c96fe08602e4489614c524146c14fba9e15e75ab898f89186267157f533cd4d0830d0f5155f2ef890ed58052de24c3337e19eefa73f509c585409e0e8ddbe2f5fb88241c0ca74bf5b23589fe42ca8a1e4eee61cbf2f4e21cc6fd40ea0a4422834e19225fdef1ec5115af0c713070988e497e73092e7d98e81c19090d2a27a8025e52ae68b0a722fe14152ceaf865a2a360d997a118fa71f6a973dcbbdc4459b48a7adcabc61dcac2b810dfec3a7d5828e211b7f68b4a511e1b09b489bb66826692507a8f07d4f141cbaa794f71fce51cccc497eef1e07abd29f6bd20cfd47b27a47e91fa93e84beeb88e3f8bb016236aaa50789f285f51381f824fa3d948c68b2e2cb74353baf18a4c513bace91d0052dffbe51ab4bb39be25b6ff978dedd39edcd03468c3ce32748235a303f1a47ad3536d662d4a772343baa21cccd14e7f9268f14403011f7aa4d99c8a048e4f158350a9a13705a25eb8b07780b21ee2a7d32ed6d708a09671431d7d67a1b9d4616bf2597284216e7f814e322dd70fb3ea3231e36cb55915953d600a7f660b6dcdd0e6e1a2d8cd7ab3bf8626f1f445e2be8dafea817d553e9290b9b06833db08f5d02b41f1bd57771ffe87f800b36056afee8f3416835e8d0c8e48e0d42b51de99772fec663f6e3173894b04434b61919bedfa2f9a0d0e1226496390a1d82f4df9112a4351717d7fa3e5ec1679868792000000000000000000000000000000000000080a13162025"},{"tip_id":"tip://id/US-1d31ad6cb3ea1d1c","region":"US","public_key":"4ac7603bbb41e8cada57ef7e3108303325eaa01defc352beaa90d356323140538e3acc8f2692f25f813155749c7f29a5470837eba4d7dbcfd1f69cd5994d79a3ac74fe00b1721c9fe69f40d52dbd710aed76c8eed050d1ae3a279ec8366132564fa22f93d41eba23ee1eed140b712420405ffc2ba3c86052738b60ee9c26dbb4e912f49567b27abb09eba01371fb8464343bb91bdc49c44822e0a49b58a159b7194da06a4358dc51d112e6335a96f65a4e74bb1414d0be8aec2639189e9fddb752a7f2a84a4b0108c923dfbd6e46ccc1c006a9988fcd87ecb1c467ae998b70878b7d47168295473f2ec3649c70f806d6f8750ec2db5413bd789d93d95241a4a639f7644f243b69f697a53417eb9a1ee77e6e0972dc3769e54c897d06e5cc75ef78c1cfed02545c379ee5168fd3c900646654f517a7ad9b0d37e59b6dd3759b1148f60cbbcd0958a9b66624e3f8bd4f56889821edb589f7b4e4eb7a7a979a200278135594bd77ec73be5336c4c57d742e349465798ce5e6342142c017a43b58b15b311329b83c94a8a01f322487849217287af042cbe0eecc1fea976735ac00a5e3989c3232abc41f2cbb93a15262aa2b5c4349153822472bd46726b7f38a50d0c717fab006c53b5c2b77d5d4b129c0a3b9fcd798a9b2bec9a7f945a610f6b32f87086341fa0a145ca31cfbd474ddc0e30047e39d56268b9e364d57b5f8d8dbcf77d0144422053e38960f197e8f7742f76781a108d5b6d20b66df1d49ccd10365e04e87313a7811c13f7c9bf6c1b712f5e9612d33cf0d228b38f256f82357e1ce86bfbfa6cedcb16eda8b4b61e838a1a49e93454b553663cd51e6ec1e0484aa41339a4f5fbe4f33e236c9db119e1cd188544397723a80034da8648f242e497d9f668bf8159484af2b7a6f01b19d29097137b34a8f18b5994d1baeeee7360aec5c79434304980774077c050c9c68a573c958545b0c91860f2f14a20a589c0ab0d014c278e9161a531b58c02308290ddec01d4112874a9f4091e3ad74754398bd2f39f5b38f57b9b11a5457e2abea43714e880009137eb9ad174deef9f126427a17dbd9814cfa4a75745d5204c19f9b410a77cd180e74aa94bed9b29e60a22c6ea1df8331c4c2e508a35c6146c2cdae3fa6d953e1d6c1ee24a266b4ac7d48035fbf9910aca945c23c5bb688ad51310d1a245343cf37fc6c2d394dae25dd10dfe22ee37286160572076260fb1f7e3f943e1e4050da8f456d95a73d2e5729100217047baf46d77d3728d4e5e99fd4b64be749702fbba147a2ceb452f741dc3bd4951fef3266bf894e3b53d66a85eddb728b39cea767d9f6922b80a4b6b1766ad45dd37234fba274698fdbca7b1c054b7eb1b661923a74e22057901a42bdc65209542367a31464ffe270c45482f80acfb1b2ee0523d320747c698307e3f4240cf57f3be0bf0425a6e596e622d145f3b674613fe9afbd3e02d61a9eeb7be92bd22e81cc624ae2e38e32db32cd27ce6ecc9a0f6a34ff143485446857522060f21d544b40ff34b0363908683bb55ddb24893a3a63340bf167224b9cc823df45ed841a99f6fc13b47948f2225d126663f001aae1099d67baaf58313990bde781e799342d0b88540889de9820fae52ca9ae7f2019d139ec0721fd030c6dc0ecd68923a96445f9fca4dfc2ab39635b09a0eea5bf5a1a629039a300943b82d73925faf0303ee43c96262fbc537e6f4faf1dae1eaa7f3ee4d0f63120e365fa202eb8ee72679a9890023235bc8c4659b59ed58053a0b4e0e5b8dde11d92e321fe23bfe917b99ce114f48d7a78444f0a9cc74e4dab9e6135081bf916675971b683353f2b439d6dc94beaf2403b67ee2ee40d1957d28400ce5840f7a52e728a9001970c4c9b4668381cd8cc5b834a1991f13284e71ce892ebee11a2ea25581ccfa77c818a65035ae443ac2dbe9c519138e817170b489f6af0ddce373190a036665c29606eea571c15f2d6c57cb9423389ce3e4771702aae5b9be81397bde15e398b23392072f140d8b778a47ca00db1f9f77ab253994a84acf8f00f767d6b3800f6fa7045eae3779b6a87db77ac1d7e6b12e643d0b3da2463d3661d66eb658f678e20ff6aa3d1e1eb6136ff012ed8f74298f9535c4cd13d9582bab24dbdc0ea80a4fada3dea63b4c2f60cb88aeb04af702eb2ed712ed6cdf2dc2a97aabdede4d3fb376b0bb7fb5e9953f34a30ff305e9637754a6ee190d6719602ed8f928e00cf1a2252a828de57c873379f3cc871ed44ffec8079f7ca3daf70be695f7640ce513bf8f0036e752fd6e3a3e9b291ed9c5eefca462e59ae84b4efcc955138da333b4901e442dc4735b48129f7920c1e1e762e9caab1d6126ca5b722ea83a3af15d43985a30ebb50361b2d91352b034740f95e660d75f6481f4a10f2b58df6e5c57004943db6e4ed41334a50f4366732a919c1c0c8929a237c9a1c1b1ca5cb57057e2932ce2a609a33c7dbf7d54f01c89ff3fc208418dc984ab4ddf5fa003e56a1e4b78ed278b275606e89bbd9d34163de9467d38ab34570935aafeaa59fa42194021caaa4c814c2528158dcc382efe03d4fc34d3d508bccb87476b6ae801a4f9598faaebb12027cce1ca405153bf1407ee683651a1588f008b0829c7b48e0afd9a7c0bceeedc2c68235971960476a63d7444d2bba68846d235c8ddbfc76e68308e446b7da1f38d5dc09d2609e1d8acb27f28e44045c3f46bc9075c0094f4ff430f5c0289f28aca9802b","dedup_hash":"23702933538943712392","tip_id_type":"personal","vp_signature":"106b8c91c19b2af2cf0d890d2de20c2364952f15f87e66b5ce84b36ab1f7dc434a16d38f93e47d8d50d6d841cfbf0930feb1ee2ccf7b12c16dff5ba1ac5673f6bc33fb45d86d416fd302aed058c0c61f32247d8bff649489b1395ebcb6cc304c46bf0b56d52b8786cd47516d9bee356dba2c65178f5a8f69970baed3601d4b1ea44e59fa8da14a9deaa1c02653b6878a274352db179641e5019cfa8598b3f757c6552ca671004d6f47893d9867ba3482cb866072c21f3c8048a0079919999e0a70a277b37b52a06f8365914e473c3e603837f3b76bded80f2b90fe7587b6dddc0d7cebfb4cf5381b479139c6be69a52cfc1869425fad9355487c6d3161d643fbdfde1f44dd20bcbeb95851c1937e358c708449a25ec6f8d2aaae0632d38c176c429ec47db8ddbf62ab8edea7ccb2ccab7cafc26cd2e9686c5364cff446959b4d29f53948e220908cd242a299778ece5fae4816bf09d1be86f05f505f11f0c51b0fce47f4468b1519676ecc10e54127aea1f09c0dab1f0e80dd2927779e776966fbdc608fe3fc5aa2bfba9994af5a33f7fe9d67f7210d796e0726123574b211121a49dc452c22261ed145a939e151589c1ec75f10a71f9178b8874d48137ff331b8e4171017c61e1bbf72a6814c2cc030f6aba50ab1f5951fdd5fcee0af2e5e18aa3d1f575232e07f731e8ba838c2aa4e0113f011a6839d280b6f8491e115611741815bef3defb4eca4815553979818fa55f52385a48fe671c4147c353a188ef29754dd02a023452979c1bfd735f423b1af00f9e584d52f13dca144d8f2ac656ea4124e4a0c7dc17f1ef7884d58c6af5a34341fdfc3e4501a97f723301bfd9f88d2228161c190741d9668e3007c1b831fcbf3a230ca49855cec37cc30fdac13b98f525f8d0685ab058f0a6e89a8f257f1d707fdda4e09b622ffd7d460cd37e1e029b8bf94056695684e283028c30b23092033d6448b70722cd38ea382db0a18b94c2bb9b9eaa226ba0688259716c59189d4cc84fcc443fbaafc47822ea06d4122ba119c10df84c7c4fca536bd89b3d71beaaafe9d8c5a6c7f1da52d30367b458953188cca86d22078edbf30f544750404c84a0b5787985505193bfaeed2003fd9505eeecd83902371bb70ccad9844af9b05df44657d4c77b8fce762e046a42e06ff4b3fa5392f99ddd34e99f9da81347f3ee33f96d66eeccb661f11370a4c2c5905a9e87da8bd57a519c3e5b0c24aef0e575b13a6d8990464580b85460644104aaf0cbad52538af8af327f9af8557efb0547f84081dbeb6cf21994822c6811ef461b7178d3f24ce1ae284744e1216df6b0f5bc02e8f91ab26c643db82df74603cb02ea053946adb6d3fee84f5331f618cc92b354c84427515150b5addcaf82bc83128fae0c296bc45cb35891998d44266bed25bb90135889c0fd0fca2eb420d6c606b67081a328a1768dbc55dbe6b1628298f3bf3691edc63113789553610f62384d3967ceed2a5103cba391983346c8a55dca1277514de27d40b1fedc2889f1e23a6868587a1602fa450826f3f12fc2957692551d103c87d016489ec657e73f5f0f2af5a7fd78ebe79c8551c47158311bddbd157a8bf48949bc7caae9e245299fdfbd9891fe667ec99456b027d0aaa27b9932d6575cba4ad98b51133eedf53b789280c649c3ae49c4bb02c6f051989bc66c337e4693e531f6ad5481bc9208c207c2271636ad0de53a1064b1a8abfc2fa3c16e1840f1a10f8906f2817a0905a222e9e9d27ed434cfd797b26a373d2918e12686f6853a64d3aaa8d42a4a8a20799832a2e542240489f310fce515001217ee535f0563667e99d0d28dc442fce71106d214dd9babd27d6717ba422fdd578f0ab3ee8270a8e1941ca1057200ed530671fae5c28152aa34be068c0b2a787948c4c7f675fb30f34df3b5294ba52bec1eca7fbebbf5ef1b92f9fb6757b9ce4f26d4806c9042747cd0f15b19946d8677f9c707b964bb8832712f724e3767b66c0ef3741a1c1a2a14a19c1810bbb3c5bb9a57f21fffa2caa4eadcdc45b48611c338a1fd987ee3ac4c6a092870feb32b90183b1e423184f2d4f0136f8483f5560bc217ae34f3ec66ed6562a5be020e07ac1971495ac04d230efa97e1cc621dcec0a186acd2dff6bf7df96e14b3f563c0f5ca8f2c1641aff65295f1c3773852b5a987f4dd781c9f1ef3874f0ebbcce5188f4f8737aa43c80fc0918da4cf9e4debed83556f887cdec3c7b8da2161b11f21539cb562ab389f7f6b6647633db0bf252027c3b96b9f6ccf8792b9516bfd40f6bf06ed391f0c1ba4f3b67bda34525ce341391402962bc8eb26fd4ebdaa1a08ddaa88429c1114028dd157a261c393be1377c42ecfc3b75e79ab6111706885ae6870b192860325f0611392294b0e4646c05543824aaa46feaefcf7cfc1bfddd97d2833afbe801c327be6452251aaf656fd829f95ccd4fd136b155a91a206977f6ae3deb5ded38bc89175c3ee91fe0b174c88fffda5fa90b0a06f5c706f28d4f26c6703385a71422482d6930c502fce9848ea67d24496360781c423ee2b5e5b7087a80361a25cd2e7ad219b43130417cd4fd54ea115f58c5516628af32b4e7c11b3fd84676a2125272f7ecfa4dc7728f454f89d0bb1e186926e2bdf6a932d3ea9eb79856ad74c36ab81fa3217ccc01e9fcdb9c8a2676d56904baad3c6feff04dc85b3deb431c2bfac57b46029ddee277bbddbd533cb4daf7af42b889694e4f1b80ffddf8635e9a1fe7e75718104866d04fe067ff98ae1db98afebc53261598e7fe2653806f1107cceae8059bbea706e35db8103e34527b3f7c3c8b7c6650fbc2a4370882e5daa54f565b2647d2823054299db4187521ab4ad9b15388d3df147ddc4bc5d34be0ab813e24c82a3fad6970cdb1802f5bf4ff10ef01da2de9963c1738beb0c7b6b27200ddf9652514979e9690ad68d78556bc351c1f67b3d115357611495c796f00714df851021c4df87d26a171bea27edc85f38ba3ba8c192379b8ca81b83222b212c5418ac8344696f2cc09e5857469e019dfa2de39605b373ae750b470f716feeec29dfc555a792381ced40c7fccd8dae9266cb6a5165031badf7885acb9b38adecd86d2a01a6b5f79be72335b31c5878aff26474b72ca257c74df52280b1d458b1b6f9bc5dbdc996cb3a0dae5801dcb2b7a556d9d2b5dc5ca20b2af1970297231b1b2918d43ddbca61641531bb4ee4b44e9f93d036795713e4d4b72e0e1cc31797addce3d4b99eb0372fff154eb7f07b966986b19cdbba76f6f449523d34759b214a3c1823ff7349f1487409de80fa0c2d3fb7db876e4d84ed1f579b3d74b0f9622b8770e3317aa3c4217c592697ff708ed41ea0b59a27c3fde3baacea44084160679e177268c8fee3cbcce01315c62582ba82e7480b81848cf1703b40c5c32058b70b2a27cf3b9e97b81912dc9df28455854283ffc5af6d8f3757cd66323feb0f40c27ccf69d5877df08e3066cbcbbcac60f0613ce5a424be7638c13a60239c36375ee3acb2f5e8e4e06ab7dba424b5c0a27f0bdc19cee37f8469e8719124b0f1563dd03d7e3551b95f074e25e1a7a96d2315b67c8fdd66222aea2e1eee8463466344abbced3eade41c3ad9ea49665a46dad3451b32177810188a37629172320d7b5443c44a3f52ea085a12a6c8ab8a76261cb0f4baf0af1b6e7afab26d8848ac7b80fa78611f3d1ade64189355a567c2a3f663826fe1d22ec0f156eb9932a3eab82abed46af9c04c6e148def03de2528dc3a1b5dc331d374d0c498db975f8abb83dd638d1cb61a9ca9ddcad9c91ea1569ce8101f48c73a67d4276f4bbb7ea28fb6bce81b5616c6d297021679b7868c79976786f8c71e70538dd747720a8c1d115bceb0d50b60f313128c8b0d2d8b60e692e85477d4a53019aefb85a22924aa0669a4c9ecd1151e1dbabd683f91e7128da299b7c12fe5eac3bd10efcbd60f7cae78e99983370d1cd2b51ed63d60725b938e29c145443a989f17888d16d25d18e1910ba6cce1ecb9bcf7208cad4caa08d8b3389e08c8afb0f250564803a22678e90a6e56ffe92bfa4a359323d4f0a8ca53ad61946272ba1f62e41675011463b7ebd9538a177a7c19bdc8d78596a4d4f1859ad788b9f9d8908bf36b31bdc541c8bf69c59e10db66097864fa45b52138b6c7662ec95befe4c6217a245d1bf41479effe92be4b4eb13ed9c21fd3c40bf842c7db838e078d77b621068f8aa1933eddd2a84038f6ec2270aa9f9b10d67e0a9a9538f71048f99be438f0fb36b3e68f91cf20213bb7d91eb036ac4cc063ae32e2354301954176139e4ecdba314c4be7179751b7fe67efe5b1e82af4d4c1393c33019535eb09fa0728ff820644647d85e898ee7d00dec4f3790ad655542ad6b840b6dae936ad5e315177995501e74deef5665e50e902d94f6bc6db94103985f7c2df8217a14afe69b649610c11061ccba29ab8fed57d92a5d8441383946c6e9ae1a33ba84896d8e93f0b0831cae7f3da2a7c6f0782263680712938b67884fa50e300eb3055d5aeb5c329bd467825c8e20a5c83bc521c70e9425a853fc6e1700205388b2c0d5f030a2a3051a20355d6a7fa50a1d2b3b599298c004515d627b011340546061648c9cd500000000000000000000000000080b131b202a"},{"tip_id":"tip://id/US-92dc73984b1c8c8c","region":"US","public_key":"30b3e53419b7b6b3dab7c37a50ca2eea4d29eb91e8ff0ecacfac995a47ec9b753a299a312de2c371a9b519bb8a7724fe82addec58a1155cff69bd29156f057361d258059c5c3aeb0dc51c4a61ed60333f1479b9b76aaafe282ad59eba7ca3afbd4af5c08d7aa358d3e8f7a3f48125d7f3f9fe68cc851313b4d198fff3d39df0d1fb08ee84954e37fb8b4486cdc5cd08a9029c808ec0cb5f87e9546931801d0ce692424fbe12d91ff0e67526aaf5726c4c71cfee3dac416a2b9d1a091d02653913084d2bfbb9507e6af1fadd4ddad5e620037082501cc14b23e68fb3b7a5d1f0f0d902bb72647ea390fd53a7c551ee9b05d5353ad212177b941278582c0678c5306baa91d1e6a91993eb6c93bbdaa625499cfeb19468dc0fa1bf8c93216240548cdff026b11d0f484a1d917d11b9062eb6e8785f9123df67015a48684893aaf7d6a271b5668b344ef08ee0f67cf57951a3bcb769031651f2bf0daedeb19ab2ae5f0eb7fbd8b9712c7eb3f38123a3773415c843bba3046fc0b7a04752f0873ff506e419b9a9dc1719e6183b76a462b19c27f7b964189b0b9229ad334271ac11885dce244d7a72a002adc9768e59993f632a81be766f67c5cf254594bf228f3bd19b85ed94f4e4463cb8ab760ca516ce7be7be5001e9d90d31dbd014bf884995aac059d51500c6ba764db72bbb70b8987341c85eebc501029788f7a08a77b717830695f87108619de8f1365e463e4c11ecf5b0912810222ec54b5f1a5a7b358fe50977474c27e6f1347377e53bf8468e6335b5947fdc5c25ee4921a096e2935971d7dda4ff7b352de61d73f7a03f49e524ba6f787a917f2085925feaf2bc49183f3a0dce39ceb5495261ff80f57ba9cf80efaaecd0bf9867260c4f37b6841bd07c7060590e8c8b1a50c960925cde7f50384ae3f7cd513c5276e3fa8accec258ba81c5c74a9f5c1c62e1a3bcfb519259b982e582e222ceb1ff1946bf095d303dbde9594f637fdb4770b55244609f7e357603f4c6d5d8c985088a1c6cd1a6edae88588be465d29f92d3ede7413e9cdf8593f02ffbc3b095b0656fa78efc5bbbfaafd8c5ef85b817ddc5ff63e499aad6996c391c77a175c90e0b49a77a59b2a5bc644eddf8fb834122f86f8f4ee26aede7cbbb23a8e028dc4e2002df89d6563d5dfc6158ce95b364b2d67e5568ab96c05b70380311d6d25ea1f9e615b0ec8e3344469ca71f5bc317485baec0558c5aeab4ef9d2327cf90054ca8b53b223f40c9c31071a2ee7ffc054d1451c49fbc5393460d30b80337d5c08e234fa099435dd638c160250cdce00961b7b54362e9496264cb15a84c4721eb870e0b3e4da42856dea9ba59a7e492d126f05d516973168190472cd59a36ce1df9f79d427e919875dc77b0415d1452a080992aba35509c1cf48c501f5650e8651ee8e532174491ff5eaed3ca1b8211eff2ecd6d4972a6218e0abe2bc82c20f2a7185ebbf3e87f8b05a98a10ab2859b00b7bc57472bbf5e3213a868b56412ce6f842a72a1ceb38881840235dbde3c3792e6f41d3881bbf30ed9d68522008f5a1764d1008afb8ca16b086d12f417145e8f06e63c6a04bdae8bd1e338f9e1a4399f6ef00339345a82aaf6d74448f433bd8f0f086229aa76c001ac093a5a0b729af058cb15c427dfc56dc268a95952dbf56d8e18279966d050d389308b8b614df909c459fcbf196cf8ad985fd4d705465a59b79e9c32e332a10a03a52baa880452cf3abcff1b1c21541ef9b0b0d870c0804bccec1fe0fe65bbe09cff6c827bdb71c13c5e1e3fa83ca1773f70a4cab0affd834214f09ea20209302173d14962806c298a920bef38d2b053ede1bc7a2eb06920172211c5f5dc28c73a064068b0840fd56cc81bd7d47a9d2206df7e9b781f61e8c8620538df7f8d6483e8b3d6db2882f4d942ecf4ea9aa101c97a29d937e4add5fc00e5dcadf54267c95303bc906d27d781979083c587d45b7597442093bc07bf5938574f53a2902d3f1b8ffa71c40ed3b75f4dfd684a3b90058dbc019ba633ff8967fcb2a4d7dd4d008c647724c5b4ab94a307876cdede14fc4b0d021866ca146518025ad66d48e8561216d5701f723c34d9cbe2bce6077446e2484040879840e222affd3928582cf4ca1ff4a58be4a89471a547c985ebd6f2479b84386bee24968f3ab3097a74af354a0cf8655531f0e7d4c0af15e0b83471be421989856107bdf5ee87e96923bdc09b3c82e8fb01dfd4378a57638f8456c3c4968b77d2c54a8792059f750c72aa468739f3360efe6c5f7a422608defccacc69df0d497124994231e891aa1746d957c64a5e8b34a6fecbf1299d3adb895ccdee9553b7d7b866038d6be4fe38fe9d5c31e1c5f32ce3142d6d0a5466b2b2159c1b863f7a036d69ff447d266dfaeb059c28fac2a9a8027bf1d42ac5951ac2d864b89549e47357e9a3f0613c3dab70f7d74add6508c48d0eb703e7000e8d1a3fb2d66639f98e6a4fd58f9eaf8a862ed44d9306ce1c1a3ecb7abe2aec20fd7af2432077f101102a8ad3fc199846b1093367033c2cd6f55063de2b87b52748b35fbbbe5382ce1162a45a67de2c33f4c147819655f76148135c341d8fb60bf40e56ff4ab3089c88ab5d54cb494f65e8aea6503742faf8a18af058e1ee37a552fdc84d77bf7bd8fc47f5c34f4fd50c078b002cbff1789d6847f42c7bb35711f9704eb5b376684898b6a016d3068ccca702e85a7df0a2e3e042af3a2e8bbf7f5864700f1269","dedup_hash":"74146165765493969290","tip_id_type":"personal","vp_signature":"f458a03ab0308090336cf85bcadb964a9f8bd67310004dc5ae48ae0e86baa488647385ace54184073f81036d8f84736b6003d4090f93761181c731904cbbbf7845281a3bd5462d650201b2b17bc0a5a31360e86c5d93ba1221e146e198972aed52bd74321faf9a317f086e2279f998c37903fa4b078c06bc86be5e8680faf2c10388035c416bd49f42926cb8d7769473a53ad77f40f7502aff5ba968c41729e0b67365693ff34451ee1b18ab70c6574275c4b070667c273576783600bdd30d8dd04ec73b468745f35f2a355c0b344ed087690abc00b68300c53362af2f335e506a693ca83518617d570721efaada09a981adae305cfb924705659512b8d0c8e316c332d668b54839f5ea2e96a0a3a6b8e5f6e3c03103a497ce6b07415b7344a3e6680a824b6a936315fa4cf25074bda85d10730590213d5a801e5af3790ec7ca13fbaacd7e2a8c7b1b28b4f7afbd8a4473c41c4b40859749b1312985647d0f19a17ea79a016462d3b4ada7bb3873a61618eff16cd4b16d558d15440af724e749c06c38cc9d6c93fccaa8283215b05d4871a54b41b5d558856596543ba5bf9289c53ffa9154aa9bf01f4d324eebce6529ee73c5ef01b67e8c802d65f5f62b3ab6c1ed69e5eb8f0fb6080de2dfb1a057e2ce8cde9a8521c8b51c0ee3e4d614691681537f414cb6446c949c9293dee9644def5ce00ab0c335c4acf6da660cd8c0716e63f8b35940672fe1dd67b5265b12423eaaa9f814e39546bf3b7a8697bd7f94c3892e2cb1eff94d05b370f83788070c82377b6684f59358f52302dd949bf9b6894b0ebd56f3233a6fe0974b11d51447fe2107e48dfe0cf0ef67c0aab3a419039630150049249de9213db386a0a1416382d42d7e29c52b1e1d5c8c11aff972a769cd988eebee53911d7bf2fec5c30acf1df29bb3a9d73bd4f6a4670574d2945783bbd08182d06799e722a4c139560317c3790fc0b46922a5bee07f85c54cf5c50f70ad6fbd2a402ae2c1e2905477a354bbf97412da74be783e9a8d39c93fc4b4967bcf649453a8c7c8503c8aa88a800115b092a41ed907c8864215bc68d7d272a0253b062197a640640418970a3224aee339285580864436027d2fcb814f14d671493df9d793a2487a26117fb3dec6b3873a4031e52e8911ec8a331ad369d1a121735b436fb61d933bf50c55d6f0a17208157235f5f7e572d01b210b2b1d0dca7a98260c07ed04925b5cea662ff3452f548a2e14357478ad90b4c210fdaaf66c815f84d280c57f9be7f160adda7bc443c95f55346afb667e01d67ad3b26348e986f6c40748a6373d35ba13ff049517f45e5851bd80b5c787e5190dc80abf47d1ee3d3c6ee2b24d2718d35bc049f7f348fb08a838812b63eb4ffef5529cda3b09af7e3db628a440a27aea3a1fe501c45c6a36af8b4342102296833ea892fd945f76be12bf72bb238ffd5155f7503cbff793479820adcca37ca1dd43b03a1c6487303bcf28f968bf503b809e9cbc61ee2530931a7c13ae96e19cf952d3a8338ecccc149973dbbf8a9a0b404f389aa6d1ab6b7d725d2eafccfb3da2933ad73bfb785262dad90d47fd4be1145463514202a792ff0812af4de628b45883255ee0c3dd330f43eb13d9f334ce1d56a49b1ffe7e9627001483e4ea9127198811c18dcf4542eb4b6ee434f7a478300e1c613f119028ac3d1b850cb191895ba4b41630ab597646ae0f875cfbcc42653a3ddd7dcaa684da9eb86aa28d38e986e467976c6e4a5bd2f32d7338a8e110623c94c30c78a21077e19d2fd13e7b9ea005d229ddda865ce374ea4c97a8462c9c7c13ef11c184d95b04dc5c4d0c939ed6428e0c493fe0fc167334ece6be51ea6c658b4cb1c70b1bdddcbb360418cfc4a1f33365598e03ad679d4503c664c8f81e35e60a46c3254bce91e7e079054468fb88e88cec6104f0afa5e6cace56c5b80124cc4fdc4bf6b8f3f8d35c7eec30e8172b7a9b475fe362c9cf04d3680e5c0ded33aa9c5371175a5200a660d8ec813052fd3e8a12539786396aade3c9e655f19394f1a19c682be80ecf6bf9fbfdaac04a3cbf872da4cf8bd1924308ecf4909421855c5e5fa611c48b20dcbf34723f7d954e4d2417af183afd836802b3476535e705c3d50840718a6d4ccb2449d113186c22e4648a2075cf4d9c4589bbadb79ca6df1974462a697bee7ba5a6031853445af5827c82d6597154045b7e48a27a249852a8cfcddd99e1f409bb587fb001dd0ca9422e191f452f74caed1455cb9286b34687ec89fb074202718dfedaf8ab5a046c16ca7759a242617816ebb11d68044d8c9099cf41136cd9ad6b42f63507c5ba3066cfd018a822c3c17447d0c546d43094b53d30fac00c2dbfdd0fca3bac01f717a6342a36a5410ba893cf3a5df5fc9b074c6dbd022ecc695dcb30efb795fa1cbeefb2740e342b3f041065905453bd71ad58f68ffd0043daea143e3ff7158d3e327b86b7a617b00bb7d7f0f48d87f6225cc88fceef4808a50c0cda49007f817950784a192ad0cd58cd21291ab8a22175a4586a412c8b0d532e90558a1dd170b38beb393d663f365973cf40a60405880aa31f980a9303d0379a2ca46246301bb799155c56be3f987a8611ac908c49ab8632aee12c8843d2fa4f1ae41a3b25d754edc7f7fdd137e20e2dc2d74e307c7740f659657178577d32f49d6d1d3ff9510dfc2504d74bfc57b1519a72c44fcc8cc5a8d96bb85719e283bf5fc07dde795945c916aedab83150a0b7bbc9eb2fb1d579318c9d79b0b7857d99625716daff233b144627e152a1dad4250656f6f9e208a5b3fc186dee3fed76a668e16adb01638e95506c48e47970ad6277b575f4643693152a36dbf026a3f1bf88c29780fb951891dab5e6ed62dc703b53875a638241a0391e790291e7b81f00d5e9c2b803398a1a2a1be612f581cc0dbf32243ca2070a49098a7fc1b4535e1152ce9da7308e1378e7e56ca727240adabbb970d3d152501b170ea9c09bc63bbb2fb8da0ece32d4b823eb59f1e5b01b12587c771da721635e71243777036058ed9c5257282204f2549043af7a10eba85c2ca8260a13b0c7976c7a8e5de2c9ba9f1c39088b6bd5b51866f9828bd85df209bc53c6c50744f2376fd78711f48cd5471d539584e15b8e344daf7f0294f24195e3cb0805c4039b2b4a68edb7ad161e8c54721a3def95287a2772c15092179aed372c888a5fc83fc0a7fc101edb6cfd0290dbfbc8917128c9fdb09b96fd979958f22710179b797c0597be4869a0de0c654de4c5509de0d1a36b1cbb078dfd01043b1063a6c59454284a6b30db3e7e70a35cf11cb62bc192d56607aa7ac81b3f66ed96f1ab2214502f485181332bc1ca08e57b7ca88795ca3c764a7dceac84114a9fe092c90e14e7d73e51e6604605841165da80ed9d8c49a6324fc94a3fa20d0b0594d44e637f08f5a500c6bf1cac9676e4a942cbd0518fb2e1de8380f8334f5855dbc9f2e7c4fd2b0749a251becc825a0d658fdd3dbd4df08748aaad40d9a53b9306a96c1a208a92a0c77b64a4bd5a576f28316a1e63c6cac80eadda3012638e30595ee1a495829168a06df953931bff541fe99c80e942daacbcdd1ee1b537d85aabf6f93e0f2a8adcef7fb6b10a5a5884834cd05f66877d32a2c999143209c3e390007d03797c364850297adcadad1f1f499d52b12df3fc5f53b58f05c4f0e2600d0e0bfac7574eebc7f99f1ff6585e3e4b08216c327bdc356162436109d02893ecd8384230fc44aebe4e4069a9ad226318ebb93f36d3c8d9b1fbd32b3a35f227e767848d3a511b28c57559427f05016d1d7c860bfd84676c7d5703c3be0722484c23f5770193ca183e34a3c5c91bc17d3046c4f9673285ca1c66d08577340211d0932166d2bcc1bbd6c3b09784cdba398b525fa9faa2b7b3e811839ba57fa0bdbed3d4ac958669206e047e40ba64c25f54c2f6d3559eab53ce3258f535ceaf517f06a13d1f3a75876efa067d6bd516de74b87292a1eb3c8d973cba16b1d1278d2c8f70a2281af922ccf66a5d60a225b9f2ef21b43c22f42988256728e09d87bd353fc4ac0fa2ab35d901f7bef89d142b8b9585f56a62278625223ac836611ab1386b2b188e85ac5d6770e2f9772bdf6157ad4bb4a0c4d0241e7f0baeaed14124d4063b1044cc23609bff242797f7c0fa4048dae736b11f4f90f8c6446a82e1f91f1b58b4cc8798bc806e2962f78e0ca348f342d719aac423db1fe0dcd171816ea6338ea3601ec65af3072e3a5485c20c1d31ed83ca3e330c467611ed34f53e4f209fed7a14fe7ca85a45fc6b367f78a1e726a945761be0c3cbee6abc2328cbf62df1ba18c462d173cb6999e20cef2366c1e05f19722ae9d8cb537ecfab9a747179c00880b1f2f35d53b64b016230b4e0b7cc9adb958c4ae80bd15948cdd939ad4b2e9da2a89b917cab840cc9a2e11184431aabf3ba57e2619f0bb621fcebd88e50575d3876f2f2eae3d1db7c60c93aeece4a56b7ee8673ad4b7569881d67efd6dbf40488767a234ff4aab971ada522fde894d55b60218bce6ec952263638acc82a789c92e0eb159842c485f12e3f90b2d1ed2f75b1d7fb1028395b5e6985fb101a548c9aa7c0e2e9050a264c8cc3c51c2a309396e3f900000000000000000000000000060b131c232a"},{"tip_id":"tip://id/US-c7a97b26711a37ae","region":"US","public_key":"d6b4dc033ad429dc2bcd53381f94672bc8a5efd2278cf0b6abbff0615f4692319f97b4224b1eef6f9ff960c7e3ee4307c77b6dac9fc27bc79e58ad5c52c49fea673eff43428be84c95ee6d506b99c327a0436960dd3052986389c0274b49cf2ff286c9b5129de361caf7f8a90dcf0e41dbc56843bd8c8b6edc2babfc068ddefb740aa4176bdac4167b445b797237985eca7897b08e696ab99a2d5716947326d7db410912b80e27117a06f64cc9cf384092a304209336e2ae0d2de04ef615212141a3273ed1dd6e6dc01d52a7997aa44eed085976609624a746c515333af09ea1e87dc6ce078a36e14f1da8c97962cbd0f7371377ed432f9856279350d98c8bec852c6dbffc2b047701803eba454399985667fe0b22ee9bc6dd899758a2cb4d0c8d508be2e7d3541ad1e842c95fb3be92da4734f2ff2b68589f02b6f9fbba43b03cfa9a9b6adb2732a1e896758583b929f9bd737dd711204f8eea746f434ca31b40e19912689921ff897d9374e4e3e0592e66dd9b5d94b8d18e8e4f3159f352a6dec2df5f106431af17d568258793658b7aa128a263ffca1207f691b64c23327d58ffed37c70d402f205b6292a9761b190b0b2e99284f8000d8a5303c69c2f0794d5887095a00d37f64b67f220c7b6530625b0acd53b010b0e6726b46c4733e339f5ee7213e9659425bd4a1a6d5e66c8d3d6f90c2ebbea45af71757d623b14b85c49174e61bac52850cd76082c042e00f8f29bae753025d32c50ac01090aa80a696c7f3b311c5b0e40a58b88b2d0a4d85340c81f0600b4bedb2f63c14c8dcbb1af2b041f7d87194e45a99289463f79a1c761cdfa53c96f3b78075891c42253d52bd08ebe401d755dc553bce2606c49c41fa03ab1bed12e62e2c5207d9b4cc1078b1fccd87bfe872a61d4ceccfc3b78319910fd8a9bb34029df6e4474a62f9c864dc2e41a399b7295fe221de656031a49900634420b77b42313589521a34e45367f7cb26ee57118a91b70a8a4bff037b6b05035ba234d67301ee184f15d4d5cd70e6cad4895672a99a39d3684f6693b31715bfc557e2774e2af39501708b2364c95988d4a51ed889b789a2e18619eba8397ab70d1cea9f15c9bf43bd0c39a5a8d20eec747b983e55b48d484107a68a1f0e304e95f9f4fc422caecb8afcae00eaef51665c1452ed1404573372cedfb30952341efa5189b77d94e49684a5c73569c32080d32206a7282c46f5988b2d057df2914cd1fc204a53f3ae42a01462a6cb736a0af112c3aca8cfd8dd88a24a26e89fc5aa78cdcf77dd0e4d2b51dede15235ac8e43e3a9f32ff155ea5f710ccde3c05a142c7cfbd31eaab5ea17703d9170342e30cd1ee40461932c372ae06d146581e3bc1bd866fd1713d8a3316c36f571d757eaf9ff3b7243c2166a50cb4e197bbbfd372fbd5d3300dcbea8211e4d4cb99408e2208aabf9679fb2cddfddc62aaa6e7e818140e1145852b3f2ad0fc4fe4c90a61f5dcb2b1fc6abbff5afc09e011b8f0066fc422ef80d1582e89967f7f3c9c9400437f6a53b9e9b58a4e4e6f4a56a8a04317c489a2a9fddc6795f80d2540a329f5800de2131ddd44cf6f33fe34f0977e54f2e74c310a70662b07e85e1a47629618e16f2152db04faa7b8b58e1f204271848d5952d6a2de8ab64f781a7136c5d61de8788ce459a83b8aeb21cfe19b7e7e55fdd340b27e25ce34edf17821c0762c861b9942eb444b59af4affc1dba69f5b8661438620266b714ff10e2ed22da7369b4110c788ba9dc722405e3e19cf8525cef545244d4a1fca2f9e82fb08084211d328d02a477924ae700b7f659ea7e3ab2dc951ad30f052f0324b96164f92755f44d9e0b1e657dfa91f7559617e6f1907d5233e53f00ccfa8922bf5cb47bfe04530d3079694d8c1117efa6d55d09b71f738d788e180b28434abb376f2927c5a26c198db6edf7d0cea76a255a5db2897673fb5f49ecb9d94757321d3b4b0fed97eed10305f1960944cb25396c78f47c90299bc1254ec5fb0b1159a62c4ab967fa6931ad4d39e1387af6a5920c68a3e85d721782c2008cb394716e19b745758ceeb78a46ecfe8cbb5e4a5d0797dd3989a6682c2c6f57da52b1803c7d196086f9b3ada4dca1b20045fa388e83b9fde6acab52280607180042c0bb7339d176f4f95c9c62d883cbe59fb5868f97e8408c84a3600c3e6823d44d8d83f490ccb9b2b424ef29fab256c2aa254ba70b939c8229a634a41c261c89afc2ce7cdb81d37e25bfeafa901c7565002d8e2986780a8507bcf894ee398d8372517ddc07fd803902d2f7e935e4a860a9c1912ec51ce42e01020eda22ace4bc92185605a5258cc3286954a1ba279f2b808a8e75ec20be94d37a71dee1e77db14754b489ded66eb39b2bc549e76c12b67f0e0ff4df3f379f058c6ae4929b2cc99125cfdeac3d453a2aebb05de9142aa4cbe562d037cb0aafd1b17f603c66112570f94723a31815eea80c7e6378894a405983247bf9ff1b274fc7128b578efb459aec1ef8b10b1857cc700c077739a44f23f31dfb2e33670c846955978376d9ef22ba8756509049bf200a3d1c7282ed5c1ebc3cd2183eea13bc78e7c15a6702e58e7b4beb6e5d5df681b30fb1a5345b9914a99941b4949b71112117130f7bdb741788b3ddf9abe320eec0e7fd792fa837d2c492e71ce2905674d925d49de2cd5ecccf17252f9a58a48ea489e3b903b5b0a5393fab19a9ac8f1fd1c17b9d7213e52bac47bbb0b586dd2522d","dedup_hash":"70044443154882484498","tip_id_type":"personal","vp_signature":"213853d2c56cc0a13652df5c0123777ed70b534c96f6bffb328ef704e0df182ce459cc31326607f047717c0c67f1c4f15ea9d9b6a825b0f143115c8bb78977d55a22d30282b300bdf329ed514b4f5d3c1bfaa657450170a2c4726c9cd4772891108c09c1ae2af0ddfcbdae2202bd3cbd24ac2966d7616806c161f6ac3767fa2c835033a929acc4f55b9b0b1b2950bca0695dc33bb63eaf4023d2103e24de89bc8c2bc00b1a8050cf15b8602a612b3d92d23a3dbb396fce99aefd854544981baf68267951d5c5708045d962ada337f6063d4894d5195c12ff326b0a92a5147036b94f79a0b2c3507aaa9057a1a0fb95d04dc57fa5a3650ac5915dddfc5c47475898ecee8054ba1491a2fbca090ef9284fae0f988b7b7e19b796047168f8e26c65ef53b9e19d8bd210195a4ad38366917af31e270bca5c05bebfa3f02b9e191b0a66423b0fba84f4ed757dfd293079412698e41f5ba68c281e6fc97ee7ddff3243868d132bcff476fb62060e864cd6cbb51ca27f9c6d1a62d650fbc31a02159906bd17c77883fc8e254ce4c6111b1f9e9e82673279bfc51aae79f24e7d60b6834f5b66b4985ea55b49aa8d2da07ef13dbe0d3240ae8ca7a6dbcb6930a1098ce00ac5b3a6fd9336f65e643795e4d5b3e4f1741d8583a5c926452de1146864a61610a48ac8ad072750793861e32a52d0fc5b51ae23036ebf714e946dcc339b65a220078547fe11f822ecae665a1f1d5988d8b59f5e32898932c79389905c4ace279c4611f011751df0af8393f64f201269545811affe038d29742822dd9b7c7b5e455df41150c4af7319d95cf8392e63f10f442c4020cefff2ea8293eaa1631e3090c0fe23846b7398ff98c209252d73138d5f6334586f2bc1423f64ae5844848c0d3c915a5adab4e5af43721ba02bb6436d18be670caed2a8e40df9e678dc5f2c0a427d556541374369eb1c7ea9cd0d6696c4365684663cbf4cede47b3429c61aebbec9d23fe4321f3a5fd678413bc06272194f06478352754398029b86ac3ffecf3f3ae80b93ad2992396c1695ef341df3f1c182d4f19d834d89da13ed760f086ad0e02523f83976e0e92b5877990fb93347be5b893802db6ec27877dc060aa4ddd3d5f3e692470706f6da302c7c866a1fae24b347f32683800897a66d23112caa37a3d2e3f69750638c074edee9729544b314b163e6f1145b609c1b52d609569418403d483f93a5b48243b0db469bfd3e059230a08291fc937166e17e29143bca9084aaa0544369fc35ca051adfd1d5916fd901343b01b8f346f3dcb335cbc3eb5a66c86b089e9591a66f24abaf0b28acc5e8a05d07b6989fd5b007a9725ab60e60ce743f3eb6819aa21bbbc2d9dbced3577cc2aff82bb798d4561a45ec919dfd515af0f885e4a3fbf8e104707b4252641c1e996d36d8a7381636825843d7fac452b95900d180ad64c1a333f84ec441ba936f90a37df42f87c9d821287d255eaf586f106fac95daeae3d2d17533e9b29a7ef994798cee6f7e1f5166e126636ab3207faefdeef8ac1b52c89330950ab0b2f568215df9bed5c26540c2d3bf88232e07fe4d17ca67c3b02edcd2ba64fea4f5f7b62a5c6627bafa2b46003329348ab8618904036ef1662030c29971f221198ebadee86e60d8f4b793ae049933f86f66c683f42e33e19146300261376852e0508f51889e4560d01bb6da02c124cf3e1e2b247a6a5e39901eef764db5b2c95aaa90166098e3c0e2f553f056774a5b24be697cef42470146c1cf00f56bc806baa088876880763f7d0b34e1313aca7125db8186ce6b7d086b99fa8db1f6e4ba9e45c8715bf3fa73d48a27a78a5392031163585547e5b49e7a451dc3d13bee889b78fb90343df2bc4804c1baf3425da93303d62d8b15ca48081ecf5f08a7288231ef38561b045f3327e31e4e4e6092d1dc34606c101b2397fcfb67b6c16f922315686dea484130aec000970fffa1c6acda38820a76de60993b8aa1d81f9f83817ec82f2a98e6a571d5332b8ef16dfcb6ece6f9218d7ac085beb4b5f5beea74c258fced2af5abb76fce87294fc25662cf8a0679f0671e82775baf68d474015b129e22ece1859d0e9685f97a2702a366e7174b9c2e058646a8feb7088bf6b8d1a9c94f94b51938b8f7c0fd1b0d8a6675c1799cff6773e90fe08f92c020e9767f6d3240d91778a9ec1f16874ec990098cac8d250b835b3341035efee7b75fec2fd6e7aa4ca64a66a000ff56b3af839bddf33cccef87753feb6ca1f137d97e725e937e7a4873b946ccde313d84f80f7e8d1cefc22fd8e32670bd738a4dbc67a21697c45bec40fe0e62f0df99cc680814a942bf66c75048951a662ac0011ee7895181a7465dca38967029942cdd38f1cd52bde61bb16fcf060b49dbe1d6a31690189f6616cc192733623b6bb010410d68a19653269c5c99836c0452ba08cd4dfd96e7502f48165fcee39227c6ae6cc15f9cce0495f6dda18e5408ed8e94b875dd7f6a265a4804105d00a4e6a963c75c4d1b05a2a081b74ac6f35795dc932bc4dc9d47d79846dc350856d15f7c70344c32cb5a4c4a447029a5a410e208804691b9711b47391063d87353cd3e6d797662aece3723a822ac7656e71dbc1bdcb574aaee1be50fe516aef557f76b296c8fdbf299a271e2f4ccf3c8cbf2ef24fd25c1c794ff75f6c854807ca24a243c44ef650d1e18d18f2e0f42c4068fc392734034e051403b25d922297b38fdf365f623a7fe30d60c9d7a6e9389455717d72f12b604bfa14a6b28bbc5f54f40b293e85058341bf79a5d7510010a10b9d47b5f77b4db02e69d83d2763ba59ec4e4848aa55196320da00bf0848cda5e4646728d3b52e76cc06caecaf519911e0e813450ac933b5d587690e7470513e9c1bb29612978850bcf3738bbafe3c04f02ea8036808dd5568dccf921659ef891fbd936b2a7df8eddfc22459bdae76dc54ccb71d08831d10ce617d6fd0fa0fb9357cccc8717c9836f5822db6d10eddc1029f036eb746c618e947fd6c2d49328cd7df95a1866f188f327e09b2bf297985a3b0c8b4cc6f72736714a324e5ccfbcdc837ed2505ca133fcdb72ba7da6f3c044d4f11ef7784bd008d7f63943d06728d7f2325d8a897741416d30628cc190fbadc4797a46c4a5d26bda59c598daf3a91479ca0cc10eddecd9f5f0cb21c3fb659942c82c8782f76c5b07d1658876bb939505fb5dbe82d24a2752952f3b86b9c1b60e4d02d474737770b94c8f6fc0dc6c703ef495c3af28bc4d2780e930484c7f92b4a797f4247665c0b9ec77295570e7e19c2098d51254af7dc2517921a674187bfc8af504778367d78f073382ec704aa6e4fa9aa386d3cbaa475d83eccb5b7b3ea2d4a7a5e214c1a1b698c28616abbe7ff51f15b5a76d2e01977834e4aba335472978534e11d1c6ea61504361cea47eaf9976120af480189bb3459460325cd68998ba3344352742fa7f62b5159e225ac3518c99fca91c466e13ccdb766698531c40fc11704401d61461f35a738546d7443cf25ebb4e3bc1f49e383affa28cf81c0c2730d3dece88991d15238459d00ca139fd98895f1963ecadf7ceff108a31a32972b5719f17fefe9b8222211137234280be1db00dfd9274a007e57fead997aa7640a011c0f5285bb7b50575cc137f3255f42968b6634d951ca9416a05b4c2f6a9a51519a529f0c4a9a345e0c57ea686bf1f6b0adce7441f1b81da569ac074b02c1248d21df5d76b7753a6b8e08a19f25a478c77fd753426e5057dd016cae5fa38192a5917b81972b13f7dcd4b63f2e93dab722f535135d59fdc12156360a83cac193d23e8c16453b272a35aa744d45b49b602e3d69fb1c8ae065488829b9caaf03e6ffa9a41a97933aa5c8cec037c57c356d4af4f9ea326b406f6a344454898fd1278915e9bee0626fd8b213e104608b4c5ea02f4d05bbd239b539d96774149066f291a0f1baca9201b739784c655f05f4d67ef3de7141c5ac56797dc355d7c245a8a73f6d48146825d9660fb6ec6c3797ee2075110d16e5ef9716fcca1c58a9031766fdecc34b72781916ba6793e2865e6af20e04886e9264a5e758d7524b469143f6c3ec97dc9bd51028600bccdc531ad92eef02f6a10b8b27b108956dcebe692800c2303ab180c7f7f1b6ee0f28f21bcff0bdf5d9fd957ec1bc3486b699258e167dfe2305aa36b7c06311f668e71722ae3a84d66e0a444b6c9f79962c93803d29bf6eedc5b802840510b37b0316b596f388ff082ab589aa50975ea2a8e720931b21b569cadab40e56521736bb32266f87beadf07952afd42af65a9b381c909397bb5b84ac75359298b81b2ce9de1645e083a0dea255e26835c2f47161d7eec870391b64da3e3c79bcf6a649452937279696948811adeaf59d9b1836181ffc3ac4ca55ba9c369d4b4a01b7557faaa2aedcdcb6b7039a0749c8dbbd1d2c3b52a7e0c1d6f4e7e07a0773fcfd8391e00042440f74ab56b8db72ab7c4cd08ce8d9be2ff48d6619976c07b5567a695ec09a810a0b92cbcc7a67d5721629764a58caa4d3c478d800d9f91164cb9fc126d497679c07104e4efcd31b94514202836525eabcef70a435180a7d4d8db03637cadb5dc2a66797c7f9be3031a57e816183e448b8ca0cdd6e7eced0000000000000000000911171e222e"}],     // [{ tip_id, region, public_key, dedup_hash, vp_signature }] — embedded by seed
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
let GENESIS_TX_SIGNATURE = "84d03ab4634ed0fb4ea1a1b5883ed116abd5682ec52a17f7066e0aa03d3db7c0cfa15bfae3b5efeb5bc46303cfd60072a67125b46bf5f5bc2d6faa3c18739eb81c2183bbf0ed5441a2ed26a289bf091deff53167817fea9bab9f987623c504710dd9ec45514e96c8b1fab638b8af9b4e324b5f6c393691d749eadce044540f152222a7b4503f0fff7a289305cf8a156449c172d5733ae9867dda18893f421a6348fb6787b24fb96226cdfd208b0af438c4550057ed5a4b1064a605c778aac8f5176b8d3c480f1dc372084794c633dda550673e20f8fe974ab1905b96195ffc714fd10b5d5e9b775c3e773321f9c0a056bd1c0e0b947aa941deb58f60005a0750ea91582a79af017eac420d631c0bdcb1c246dad49f170aea442e73574314e3b5cf7251e0931f99835d2fd44ecfda23962dd33fc986e53203b6c666e961caf017eda9e9482d20d3c913f9da74b04b77efc3612498e4a871d9aa043b7147ee816bf8083d7175e60eb0dc2c9be9d0ad8d7f857b0cfad865ac4f795be80c9f23cc577e709dff9bfea90a6b5059f93c924555d08cb56fb520aa43aa2058e70ad0d9fef25841757e55dd038c2f93c624e4ff872768b093db8261389bfe530c48bd768eee925b48217c0737b1e02755c8945e897a91748d646218a967edc813208f0b86c66a87e3ac713ef26a0a1a4079ee1e05ab0e8bc015088952c9dad88b667a020de39a73beb96f2422f374bcd7cf6798e59b5af2a6fc3a269566386531641f8c913f9b9a6e107a807198176a75ad08d289abdc477605317f38cc918ac3bbe8e8e3e2faf6906f7f300ee7cb107b50ce2dd8132639bc0d9e9cb3cd2729a204eaefe7d034cb932f2ccd062f0293dc4b59c51921beca32703d13978b61efeb7ea2d4cfe954c21a95cc12e70b230110b5966b98e1e7ea7e65efe7977fd48fd97577cc6bfc234ff4969d1fb614960f73db5d071855379f669c63b3a3670d010a2c13b09e31acf5da6fae36ac38cc40e33c07887dba9958143a06194bfb4a5cfac9b367d35252e302f9977e4f7c7cfc809b03129f570fc309399b0c0b649e874125436b0177235c25782ae39ad4f772755444115ac9a79d38926a125bf52aab6aaee5ad1f217cea2dfe01c0902da28ff6ea54f4772b81c9d70059872eab2005fcd42bee636630e967f813dfd2cff5f4167e4e89fb7cf031dcbec4a8686f42184ab7c18274f3af76934884bd3ec63b6c8db3bc9db7c40716f2aae45393811629bda7892adfcdd5fa01b457a6b66296da3e02126d06611c624e5edd927856bdf4d335ac98368aff3933f0ad5ad868172a716a1036fb0b739f2a56fb3e5c152e4081adee0379fc6d0ecb6e618cfaf55e917b96b209014debb27969556f949b62a4f063367474164737100b29be327bb792303943d238a0b5ceee8face28b773caadc68b7c279596e97a12afdd24292564141db6f0e1c3b05ae9853e73888ecda6b3f89b08f868027f337325751a74e8854e74fa55e93a7effc232079bed2bdd265045ad7c5dd42d233df3c4942cb894bff86443fb6bb2e663dbd166bc1e009e390c5bfc2ee07221cde7094ac43d4c30177b4ffe455e7a6c15d30c28b6e600c4f92715fc5cbdbb87df2a3d37272ef2bd366c209db5119c64e024ce32b22ac38007641004386d2032b73daeef67e54f8490e03b40ecf461793e4b622c5bf0aeda0112ccc3e783b8b8bd69dd98431d50a277c68708583c05370f2671a07fea184e423d44f978240bc22e9b45cf258ef57a210300f99bed11251eea4dec6d7b02d139285c451bcce1baae48f3ebfd49ee1c0bd2d82b1b7e9496c2d341b14bdd2083158d6807070d9025a27e36ca6675b2f12a75ef57b8eee4e82275cf6e8ec765b22dff418241313094d3339a98ab01dcca520c4226dd75e4b3b5754a63c68224971725a8bfdf1b06d3af2ada40787f4df78499026f7eaa7337091fcaac1c14cc9a2840329ec029a7e21e2cd0004a8197a394ff5085821cf71c22a37902a9128e96bad8fa363b4e651a0a2a6357304c317b2b337474acfd4cfc47fb75e80c98ecc796ad200f3fdd0e61aa33b087e34368e7f57efa87eac2d17b95ef2db211c9eb050380a1c0bd43a545055ed31eaec6ed6b6259ba96a8f6371be2234b41af3099f95f73dbd69b03e1eb882877012c7ed059f3973813720f69fb4c91e52bdc0a3656003ccb1fa3b5b4e9fd8a70e1925726336b6405a358256c9160fbf4ecf998ee4cf0bd8f9c2ee84b3fe0499e9163e04d8db40c4a91e5cbcd116c8b7e592395732418ffe39538425c2957832853f6729984ae19605423847355d1ea00a09a504b2e59f8b1c1c9568cab84f20680e44663a5fae799830ea185b0eb6eae737f15989b52ed53313d6e81ef6e1694eb566cc09ac6bedc53816549b1dac250a45df08def7df63683b54ec71c4e771d77d682c3f214c8455fdf8767f8746fc213b6f89dcee441c6a36b877da120ce58240dd62e1ce4f6c19798a6d9217fb9ba3f3b8ee348d8dea255ee25b1146caa16d1238173203573493c4b3ab60d8d6eb0e1e378448e20d37b7aee20fd041633fff625fd3e0279fdcd28effb9df6eb06cae85e6ca95e10424c4619c24669e0c15b581338cbc289aea7a1791970cb578709c824bec927d47315e8cc102a2e58b258c94d4ed27aa7008ede445e797758c32b6ac1a73dbecf3377ce41f17cfe6e6aa655b6c37c2d12b9fa09ceaac02f1099d1adf4e9ea8f4e15980580cc7bb6a8522046d72fac4cdb584ded6352e268176d9eeb5f31a40b3c4f865fb0122bef734e235f6c99327f90291597b13c23f12b858c572c1164bb4f80bdb4db39cd5688fd47c2a031ddd941b81ce3cf4a27ad60779cc5c79a87a7304c179ad1b0e59c3cb434de0423d069e56ea71a7b962d0caf079aaa9c80c718677c4a35ce751703188aad0a31a6ad39fc8b50160de3b5fc2a9406eadd89110cbf93fa2c68612d5139e9fea6006d13b35a4368e33de1f47127c617ec3e8a584476904e59b929ed66f9ee1648f6ee4fab4dbf350336f01a5ab1be083d18a1a93bba228dda3044fda695deaab0b6948ab695b03a458fdbc4b720433acb83a253b0cb673951e8c3f0f7a6226e60c3d47ba5d2c3aa7d2d3494e9ff98d69138c7cf046602725ebddeab0b0fda62551287868c1eb73520ca11c7968ed0b88b9e0eea08cec1b453965d75189cac062f35ce59aa295b790b48ed37c9eb7a181da51f7d7876c7e31d76517688c1265c532a869aefd9fac9ab5c8977433ffbdb217901b756b2d4c0645cafe8d9d94fb4fc00dce2aee925c6dc8986b54b77716a6699485099edbb5ea8475f1282f49d199deb58d1998ffa7e9eca61f668b70cacd323dabe622cb3af617d78b8e4cfbeabc3f3cd60e7e468c1cacce05529334feb36316adff0b10a842c7b8d88e3772b05102e4753d193a75dbcfadc1752d1a3c6f5d41a849063281e88577cfbefe92c89b443f2ee6e9dc4dd34dcf3e9225f8b035146c37a2e5fbd9870fc7338dcce01b72e0b15f65ebd0957e0d0e2169e6010774063698b5eb761b10aeb10f03016329691c95777a107b5540e548070ecdfd36d6f9fce2317c73f59039223012ac88fadb419ca698e1104f4e8ffb3f26e2f52479a020f014a4f5341d211ed21e12aeb779803766bcdfa69398405e3b3b8e25339a0f5af7ff8df69fe1adb54562c19d039902c8359384312112ba552135ec739da60fc50e5e9a71d2d5d1f9705cf07dee4139f8ee562bafc1c0a19158689ae8018a169311db25c575e1f995640f2b2a4b86d3e30ab6304607c199674a5603cff2a53f2be4b76a35d68d4c67e35fda58cbf7138e0af36243ed76957be185183480fb825e290a314c5e0eb641f3cb4cf0e7442e9df641b26d4e27c5ef0cb63749169b14b2e04e0425c697038a60facace9b039e0dec8b85777e14d8835f187059d4dde26aa4e1220f13e80adf1685cafe1f8158ea152e31ca91b90879f9ef454e8b8c826a5d00a7a014c92a0aba45e3377a229dd63f69f0e7a9c1d98fbf4f5823edf6ba34765f385ab05dccefdd513ec7950f32ed5657c590374089f5db44b7c955cf5fc6a482c1d4abf0e130a6405d738417f5bc67f42ed52dba1977a3d12d272d5a7f14f8e2141c1aaf03f5daf1106b7f663dc88115dbe5600699b7f95c4e66eeb853f4d906b6fbff296ff648d566b3c38c2b42c6fc090c521c9138529079caeee05e30ce796b509bf176d14b01af8bde063c2779e04bad395dccf940b1aba653db266ad1a8295f73483eb7cb77936c0168ea1fbab8ea78dc005ad7eabbea5580c9eec0c309cfe4b5947bf6f14a92488a42c69ddd33c37a8ceaac11ca3d6f5c219944b606d7e2bede8d8cde75eabd6fbffb2ce44d4de25914af4fb8db30f91c4151a3bd1e2ff3a0bc8809e246ea4f3bee0031ee9e87089852c6ef9b0b62085ca2ba8058deaf03fcd6f9677079680e0a3f24c07638ed1a9e879d04d541be48e85648f9a82cb795bc44c77907b67e3ed831c66f7342c47b21b2ad1a22753b035d4f22225daccab057ecb83b80a71d658fba50c29ff238e3b57ca423afdb0c3752797af0f31d8397f02751a3abbcf1f90214a6c3ec0034485f788cbac6fd356c8aa9adc6f2f3000000000000000000000000000000070b12172028";
let GENESIS_VP_TX_SIGNATURE = "4a9927999c3fce767e725b7f56565426efe0d472215a2430de718aaea7d3b3b74851209e4a6ce172ab24cf8b6826b6c00c2a53bedb468cc3404240798693ba575bea02c7308715215f157932347263c7c3dddd4cddc61966b5bf6675e4f96144bef4cd6688e368a0a8e2236667182a55ea5d1a28b7cd277cfb598442a4fc09859f29e35ab3f2fef5c3429f4202f921cbe461710051f37b1bbc87fdd6934521073fdfff4bc30a02633f72a2636d1d3021910a1202fc717d0d1c795216dd60e6736dab9e2746411d211e68b68a5b1d8372570045689df11fb43c2ee5e2a789616e987cdd55e91c630726492412df5b086dd5b12b659a28092a254d8e6d76785ca74131675c60fb623fcd14441d8cc248e30cf564b3e5544d8f0646387bc333f9b9a49155757d8f923bd30d6f15aff85e2587f6238341dbb0a49dbdaa9872ae59f5ed1b22f73ca946d2de0e554579f64b2ee3a30f44b8170cfd1691114249b77f198bcccbcc946014b658d066d2e6c555383bf0a74ed48a6a143b413340b08e96940ce39920f8c549ba5783e35b2d0ba526ce7fa3d1fc518c248d05620d57e7b4c785baaa251bbc3b57538d99bced2dba89f9dde0dd48fa759948b5a5ed90a7a3180e05f224025f2d81c2d14d7b4691608cf37e39d4a011ab3e9f6289f2b754139da14c49c779f2e3ad38f8110546dc6d79cfc6e0dd4baf9ee3309552a8812d2bf6bcf6bcc965f27af3196836a5725080530b9324b007c3765d1ddb0b33460ca576c0e149b5863b565d7e4399d86dbf71f236a9103a08a5a08fe8d68dae6ef89a1df9f5f41b9c513fea90886d3f5a4dcee0f196a915e7a931cc869c414dcb9bb8fde8263dd544c2be0dc20040ca66ab72bc4434376f599510e7b8bff0b828c1fb577c537a313f7a86ee5268f05bd7b3fcc5a8c539bc2ff3698c46b81ae5bfb6bcdfc20fa28a2f945ba6a7fb85291b6f5ad751f81559976e5efbdeae0e6762a1f067896d021804d274919fe1c99d8eedbbca673fa80d2ccf976bddf3b24e2c88ed9dfd5a3d03982bcdb74437e68d92832e02a8d966fe2d670e8d108097a7562f38b7a7b0600c731775685cd6b0087750f2cf53de7c346a59fb873753c6ff6de23a8c000dd99de80b54c826cce7165beb251ca6581286bce6df61a547a22676017e9cfce0f9619972ef40faab1762c2df8e35ce6504d153c413a354f73c75137425ff910dc281942fb6decf31244b898f0e523b893bd69887d473d549c2bdb88f4a295e59f9753f778c4f4b7f3c07be5326830f1cfbf76fd33257b292a3de6deff9b03447dd2c3decd7018df2005cc24401cbd73f688da321086350c212bd4b5e756bd68d5d40e562535ea7e9e7a77e8febd2b3509dd5e9c65788a95bae79b82cf2ee475d7ea7db712911d4d9e7e247ea78b8df08ecf2b6def4032bac468857a5add9fd6eb2b777e16e92cf9f657e42b8a65e92ffb13fddc72a8d66e49df7cd5fad11ec046ed1f29c21a2559506eb199369d2b255b7be740c8dfabbe7917ec45d194538692247dd04cd6339cdbd3ccaf8b9817ec7bac747d322e4aae6510f3656634941c55ed22fc17c2c1e147749961b2425276b5f753dda5699e8a0c55eec2bae7b934eb8769416a0babfcff395171b01dd373e1d12dc3d0787e514ff8036b7b7150976af12ef68471fc160acafa6dba71330dfa64539824c86fed66ec2842a887ac3dd5ad70b42d36c60d7afbe2d223f14b7fc9a298ac4eb9e276871cebb4a6cdac1dc21aa72fce0c8b3dead90f68670b343f73adfecff809dd2eef48990e7dddf8c1b005f6769fe160d834f97250a096f2255688dd2178072255ecdb28cba96f5bdcce2698f82af08adb490025a1c8551a85cc30f55ef0830112307f6dc158bc04397a418c62e927bbb760ee26c08353cc336f469338419b2612a5c422c94311908edf00a35842a7cf16e5ed17dacc9b298e17f6430a2daaf1adab2119334a2301d18cf2d457e3755aa157b8f70cebe43ddda2c6fc7901b81750e6def8437c6b1af7b55ad8a36690e19db77af1c7b9079db9f4d63e5763ecf2431859ba904208e8167120e3d3645ad7968084db373eec87889477c98c98a45da4e03d34c0442bbd834cb78fcdb2d47b076970991ce8574bdcac65d73834fc1ec83031c3f25cb93ab64bd740e1be876b6d20b142d18dcb1c9f077f693570fd108877537b2cf51563ce8ce864cbe78df909714dcb7035413bbdc26fe91864b0d22ae8dc15655d9504fe0acc87721d0d530eb1f4873689194d56a8fae7f09fed9c5f50c2d87d4963354334bb7196fe93d125a009d1e746c13ca4fd70b17800f235b0a03d5049893a3c7d234f27fb242feb329d5bed2570f73a1d72b64d8ff310de857c9896b4c52659032b6eb5ad07b3ed1d0576d86708944f970ce2e09dc1f8214461329b06389f4d6c745226be4ee83a9c979aa1253ee6d072648f565b2b6a59fc9251e1da1b09dac665b785be181391e2cb2a279e26b0b26e61143b5b47b0b3f5394c264697a86eefdd625ed17e00a0514c66524a42a61c07691a3796a7299f5382c9edfcf9f7aa2c529048be4703c36a23e4625e7a3d23ee2a2c8fcaf22cb81d7cc6469be74a795bbb4dacc277a3f8d717f94224b2d4284332773f275bdc5cea2c1b04f5d559c99c13c89d24710bb9534574f092032192166e2b7e9dbb8bcbec27cee6bba7541f49950a253bec08030c59ab3d55f686fc3168f73fdf95e4f0c733c025dd1fc81f1c6c2dd770807a5daf8f1a75a929a4d410d780873ac33be8ab9f7ff895c65602cc4b895555599b377b0696828fbc0a98fcf668e108b51e905fdedfb64e3f03a4ba4546053bb4e51dfc8dc91846f2707ac26ccaf285a67e73f4e212e3196aeaad3031ce81f69223f6c75a366ed7f1f0d4fa3a539c89b133524fe0760dad4a700f21d47010593b72ef921dde91f40adf5b1f220cbcb694161f1017c14b51efe048ce8020ab71eb8c5069f4b37d800590562226a5564127966a4f5bbf8e487839373055ec254227aee73f517045c2954b2f0f1759507039b1b54a1f9053b4c1e356f02d4cb9b88db992559e582fd91c360f74f7f5ababecd973e0327bccd99dcc86897a3afe7504b82e0cb00da21918bd0c52ff173af90b6808872455f3f5683ec4a6ac3ab7111ecfc347abd4fcdb384676404ed76a26a60e1b20d3b9eba2bf33a95903d6de6bc65fbdca62c56b44887cda9d52c1c717b5433335cb756e2242cd27f5d38376547dc09f167783e8b1edf8fb61cbb13bebe9273c268c9aea9ecd3e4df96116e76d642046f6a0ee525f19acae2c81b48073dc39089783ead7a4da7386a36d0b352656247ab34c3d6253345020559826520e32b70b6f9fb6410d34531495412778a1bd5405a47e7dfdcd41f296c95a8c5f162c2b4b2d057d9cd3763bcb7723303cec60744dfeb2fe6819b3ea0a557e529f8a2b44b8245691cc18f87b4e65e1228ce839eaced68bdc2d27ac9a19bf46e7a7e6932bc559d116f7b80779a5190d00f9c9bc1ae051fed004098e273a100f2ed2d680fed4cb039747705edb11bb12334dedd8438f123ddfb8d54a06a03b96f50da4d83679bbed36cefe99a46ffce00fdcc66880b5014afc33a79e3a909b384d2f9284881550f88acf8028ec9cc4cb708032f0d0c836721c1c95416b6a6757008e0e349f65e69d52ccc14eb6cd62f7aab4f973d6b96a2398d2fa392590655302babbec8865e2d91825b5425dce904e738de5edbe120c732339e1e4bb32e473cf1c8ff3ad98f85a38bd2cc4465a24c6671437153955bc5204c50c878fc6b1a58467271a37e81ccac9de8394267690d1b27fca9603611959e11074aec0ed71dd7ee8d33ebb5cf123c91bc9fbbc75d621bba2818df8fb49f8ff9b77e80eead9674ae1fc12b492b07937293cd6fe457427fa8dacd5a7a213df73ad45ee3c3c94174fd179953ef2507416dcec700e570c3f10f5ec7e9b8db5545e42cc901014000c2cd438d946f422b644b771cced8cf4964d2d7f15d634e4ea528efcac2efcbcfad0f2a67ad5b42e2fdd82447ab329df741d4e6971c8c99b74936de9a095dcc8b5f266d4ba926eb82ff7868fd4d6f30d2ec21acfc26d470e55ed632f54adbe7a4e8206faf14c64bf2d3050039692a29bc3c773d490f4254e52bfd5c308f5b34fe7337870243de50b6b323474b68ff3ccbd982ba3e812bcceb6778291985c69c9bd3bfc402b7adb3128137a650730017b13a889ceb704072fa53a07a2aeb8665608c0e590c3c0e25f26e8da908bd7385893b35e085277e34053c1a3c4ff89a0e62c45cb21fa31f9c8af5a5172fa2354b2ed73184420a6bc3134ca295f7cd9eb22c08a37140461a9f854d367cf69bf8273daf8f7fc4610b5be62db8e65d2731f2964f0f22f60591f21b78e48e505b2295998eeedb81e4280280300ba3c7ad62fe1cc1ceacf4bd0d1bc23d50295c70bd92bef411ceb2c056512e184f883c85536a6df10a399ec92326409bee2656330aabbaa9cf044700e1c881440b1a1cdfbade7c9330d65f689a8e8cb86a28e273098c09b01b0b1e2e3b7fadc572e1e70abc66c2191b214675e7f854b3e2084c56d0d8edf00b1f37577e8fb4d74a7981b5e7000000000000000000000000000000000000000000000002090c131b20";

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
