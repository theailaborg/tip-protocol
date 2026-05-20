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
      snapshot_busy_retry_ms: 5000,      // §47: when two minority nodes race into byzantine_fork recovery simultaneously, the second may hit the same majority peer mid-install. Retry the SAME peer this many ms apart before moving to the next candidate. Set close to typical snapshot-install duration so the busy peer is likely free on retry.
      snapshot_busy_retry_attempts: 1,   // §47: how many retries against the same busy peer before giving up and trying the next. 1 is enough for the 2-minority-node race; raise if snapshots take longer than snapshot_busy_retry_ms or if more concurrent races are expected.
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
    vp_id: "tip://vp/US-6d0cbc4f960657bd",
    name: "The AI Lab Intelligence Unobscured, Inc.",
    short_name: "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction: "US",
    url: "https://theailab.org",
    email: "trust@theailab.org",
    registered_at: GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key: "88cad5c44594bf4280a16e6d23b2eeac224a33e93d7635f143a86f7bd7ce0dcdcdb6967acc21f42548131642db2b7cefdf752d13c028aa0d1d07f3a8ef98581e73277e931b42f94f871a3203013199649324a9748649a8682b56e99a3f9f776bc940acc77cb9a7ce8725ae2170a956aeef2a1233e23a56771b243f378c68258926f4f147e36d40030c066edc6dafc7534954060af1852c8687444ffc0146c4b7f5817c20ce67e2e1aa38185013cb2182120828809c92ad1d76b54ae14625dc8c43ad3edb05e9a06d8c410f78b0b951e72dd5db73aac0c767bb890f866233f5eddd34870941608f1e784db3565530b323712b2239effe9d580c6f5cfd4c8000a669672bbece2d9a89a66ce74b3b8083a166ea14bdc3fd51fc8859d208ea765d8e3a247bb0187b7eb1f69e7d28a5be394e7ec72929dfbf9c14cf0484b982e1e98e0dfcf014aa65d58604058d7fb38220380bf52bc0f75048476e48a5d631f6870574e797e9318d52a93eb0187d5b9bb2c869dd9699df3d0859315efa3cec1b74655e35bf5d050dbc41dbe5d486c0c9405b4f95aa59d6b379b2d111135cc75789881ff139eae31bb0837db8d007f705c7800be79116255cb9f5d6f2c23d87a5d75b586ade93f1a6e13982c05fbb6aa6e52510e53a0866b16089fa6645e324261391caabec193fc74c412020488ee08a1865e2aada24a7ec1e9525813270857e92b396069a4c6c97a90ced3ade70804965a5c192418bab799a9fe235e44888cd9b2839acaa6692a2ae5d87990e08eb3ed7cd6b874c9ef7a08a9916a415df698b96db489ff2a27b5dbe02c630794c22cc3cbeea47937519305c3c09aec7920bb334bb9c2ce94e51be0607d13e639a503dba0e4649387e57339affcc8ad793bf9acf58190c825ff6df5c12d18a8e20cf22533c3eb3e8a877e556c9892f4bf66cc6de0120fc73309e788f8ffb08ef6d874c98b756cec4cb9bd1cc2a0bee7bbf57ba3ef725a042f2b448bfb06ea805e14d74f6b1ddb0d3a73d50ca77410a220841c646764804ab884ef37a47da52e46568a3d61419e4d621a22db1b4563930b6079dcc6eea9b389a92f85f993b9ec1737592140dc0810203a550c2d4d997e7bad82655182f98c5f7df08c6f5817ac5049aae4e984eb817daa30e820635e0fd759c8931f2893e2e08cfcad18061e114939fdce664aa35672b58d8785a0a33e94a6b329b2fb1d80d3d6e09c7bfcbb2834a6b39a2c91248789c6d999f4e84925d99466f0a6c4d9ab926c69a0d0a4f90db13ec41afaedd3f1755802f2153b53ec0137dfb3a56b2268e9bbf32330cccb1154b842eb7c4043a1612e97c0d09a055b330f9d4dc50e05f97c8c3c5c36f2b6265a22dfa90b9d005eedeaef7d5ebcfd15aff1ac221a974027054b024bdb4c18ac1e1e667f254d9d5d519ace3338766c5428986ec51ef93559cd85fd7d6579f7b7f3903db6fe91976e285eb15effd5d59fb97b1f99dcc4479d0c05bb6181934d6d74a5ad39803a3c83d034e37b8754f2d8a7c2b9a5722a6d7a4b51be753a7bd5e40897c6819e91b79cad8d8e08e7e03daa6ffe00fd4c21511a9a163607f5fc0d9bf0596301b67f8936eb3eed2f45ae1a9ef86c174eab07868555a8159f202f9c731262e21b59db80eb9ec9ff054e3b29a0a744b15cfb2d2d875ad24c581fd6ad0c30dfecca636e539333611e3485f63ab80ed5c2b89f1977cda90a082b7bbaf93dfbaf69c24cb304dc2f304c09e2558358ec42fbe3e889cd7556b3f05d342b68f3a6bc543a4a473ecafed3d89d90be2ccd883666354ea00f5e5da604d08d817ffb0aa799740b19d23d05337584d585ac387c168f9cd7a04ba7a1b85269a81c3ee8bbb38d05df4df4f416b1873daf496e37c3712e6e6042dafbbfbea3a476d5fe99aa794e26db6ec4c3979f10466878b5750af651f6daa054fe90f0e9689f5e498f28583aff8534fefbaf8475ed739aae47ae8346b45fefc44e14a13fb8c829b28d7bbb04b2c573fa21c390ef2152ba4778da4634135fbbc18afd991ecfbbca9ac9abd01c34494525605a15544c5e3b0cadedace0d0730c60b31e09617ccdf044f097e46ec2c4cb5d168d46e09ced6afdaef7273535a8c480f4fdb1f6992b07005fae832e83d9c380e83d8b563f625c0c01560c7f441f1ceac18062601e9a3a8d029537c4c61b06fade44c4c2e5101c1a397b078e10e4dab155f6fcc2736b797f6db2e2c2f5d5d38d057158d00efa7337aec391ac884290d014bd61bd62a05c6822bd89e9ce12cdab30f13d3ca95f0bcd9a71f140059f293b0edde541eb5815b445f2ddb926c290b61b23db72005dfc02337535650be428c60fae85098501f0055a646857c88e22389f3420b2aa7b923fc8d1886f5234008066a5a1cd426e148f0a1861e69c48bf462f7a47c2bec553b59cd5db025bea587049cc43591256571eb0f82eacb6833e9f388f1b76c01da5d449e4d85d0f7a38cf6268b8bbf526e0ac349babcb8fab2234d3a5a6a7bd53498baca8e483149f06a51be0dfb2c58a5e185be4250d5c71f527518a53d54605ff234b044118ead825bc2f8758770d75be05840cb105b5d0abd102763370cee587cf95c7bea1778a6d1686e3a93508674308855af6632d9d7c92ad2cff44ce7b09a0663d941156dd7eec020d7bcb76051ddb8bf047af2c6e1441d6f5326d94315e95212af275432489222c3b40f2d9b4b36169c10ed4cf25a0c5e47ebd636ce062e18169f0a62b8de",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  // Founding node — registered by seed script, bootstrapped by initDAG.
  // { node_id, name, public_key, council_signature }
  founding_node: {"node_id":"tip://node/182f5c30af222bb5","name":"The AI Lab TIP Node","public_key":"371378c3681d21a953dc3697f9e7f6bd45ab5f5b833c65d10405cc52101a8614631eecab66e5db4058232138efc47179bbdc533e7182077a063ac5171b888566ddec0efd9b5e5fd710ba0ebfba692271c1b8e290cad0e985b137cb66c9d0e55508f0ad5da893f2fc0f881bf43df67819e27d523d33c8768f2d4c9fb08592e8d57d6a05914bf49daec1a761d6a2e4f3a511c36cf2846245e35551e3f1f88e5b12bb48dce895ec3d6472c117a2bbbae5fbcb0bfce3cd818f2546f718da6b54af29f3c2a3ba5924631b31b33139fd613411d8db8ee58df7f89f3055ce10e7b98b05dc62bd978e971987204fb8b2451288d017ccb919c93dc83e5f9be0fb5e5c07b085a0aad17e53fd18aacaedf938ff492177d54ecb33797f3c20500eb40f8e6b4defd96e295c2068ec2b3d923a6558156c14eb732a7977c20393632bd4aef5d379b076f54bb8e8a73748571ebad21a6b832aae0ca228dd7b61fcd899f46305380385e222c750d62116e0c0ae694022172715033e2285f68536e43b557708515eb60f40d9a1c82f5ac26e1e69b0f6f28f8b1472e9888a83d763662a207bab2b061200080adb3746cb27db6d36ac3ac7ae777057103aa115262404898f0667fe40b358322f8e5e6ff5ec54a13e7c839932e875d9570978fab1079da960a9f780c8a103720b8fd94097ad5824595c1cc28e677552be56eb85866984bbff13bb25cf8fa96ff4b55852c57dba6490eb59a99f097b683b775592ef06949f986c21fbc470c7b80bd9356cb2d96eafdee9d41532582b78d8979f21e704c718977bb6fac961532fb6235f5f37194d7576011b9ecd70daf3cf5cea73964bd0d701eb17681d31fe683e9ced02d51118a123d105b43155deca3077cb692247a121e520ab06ac9705dffe17e60c8986825d884059dd151b586dfaf4fff063cba95cdfc220792bbee18c42eec2ac8a3577018ebf3836b54d423554736159cbab314bf1fd28422fcb94f27f642da29a707d27b79117c3fc40a267e2da727734da3813e516d9a9cfbfec0620ce6b994006db412529abacc495cc6f63fee1768ff2d2243346f05b09475f9b7354a09f9e046432cd5727cce07a790444eaa5797daf00ad4ff2d5c03758aba655cdae04ad1fc9f9d9b081df5c5ee22461dac55654c273a0535063172393e3b4f9ee2e880115af208c7074cce6d2955d136ef8a1590627e7201603a837e33b01200bc69650bdd93a01d3650caf7546787eca732760dec3d07369097433506adfedd8df23106efa751e52fc6b7d716db3522a8455312a925dcd84de9a58468360114f8b89813101aa6f4bcda0ec0e4a1dc84a6c3f58f2f59556169e4c92cfc9b8fbff1e4d19b95e994aed81ec60876d55f52f8ce8c33d3e939f5816ab3a31138a2e185a68e9033799ff685e6fc6ab540738a5ef10db539ae8513f6688aa8ea99bbe7236994ece6c05b0598ef8d6466f210d8ca5382518d4480286f25d016e47c9f4bc7dda63e8c3a0770065375b094bec3b664ab18b7ed7fa50d64aafe9c3790def2979e3b080867430d916cc5d3b3c51edb992a24d1a70079f11755fe212c3ac5730bc2a05b1e3c17cc9f1e9fb0e96e6944d7314823e8b4200268b588e37813c46c512bd3774abf79f8ce8ef482c5a889ab60fd0503c0b6f2c567ede18ce26bed60976f0ca98aec61e550693a53cc0abeeded276a7545bd3576e38dedb0db5c9af0b0d2de0d56877e2b3352eecd61b6de86d1af526acbd66c366ce0bc66347dfbe616b1ec42d02d3f6a4db6bd7236362c24cdc625649c7fbd455ae3394af2241857487a6250f8912410e7fdfeb5916668d5c5d6a915d90e84ad7c2da62cde42c2777b8fad84abea3535b644a3519af93074bedf96d5464b35a9125e42a5ecd0fe48335691eb08e2b70c0f64d0475fce724df7a416b8197e43989b24c23c8bc4d3f4edb8a03224824841a579104023787651c22d2e87c42681ea453abe87db7203e5873c08529ef01a358fc92569bea2c4f91b9925045b1a0e38802a39fe39fa0d71f5e4b170e35fe82eef36760d5d00d147c7ce6a3750ddf5090a1bbecfeb862acff1740b6eaf14b29160584f65c99ffc273ff927de4af4be66d8808b430a83c906c018e94f24b696836f331d1d913df1f1beae5711962298f476bbf5ec4047815746c9ce4e4795cd2d1ee3a51341e403badae4476880257122413203a577605217e2391c5eae6c74bf009cd5866c74f8eb6ed2eb8b2c7709eab4e9eb5aebce78ba89bec7919d6a40951199cf215f61de8c97ce9ccb0c379bf234dbdf3f6d2bd511aec0ce6ab5ba25646bfd6671db8fef943c193bcbfa182054a92e65aa9ba9f79c6da1b25282d80a61e42610009026e9cbe95f5f2f8328614b1c73cd3f3dd9670882e2358cfa1e62b1c781c25fbdddd54665130833e2686bd378c4751002223308cfc621bde7f0bc3e3985a882e8b4c2a0785b6be541afe09ec9834e2dfd4e2bf1d418297135501a8a6ccea141a88bb0218c9681f2187c7160d58b90b54b4866f1156f49b2aad2784a7e6ab04c054a3b94778c6789ac69b0c2edd1a568055c72a84d0b6e2929d711b5dbe902d46df8aaea729939a1eefbe2c67a95bb7775be98ae5605fef5ed6047b5889a96f4c5a9e6a1981da70c6d22cdb3558d286e689e377eeec00fb59ebc637a0b0cb39cae3b6eaf54a446df6db2df999c578930a23df635ef936a482580280cceeace5aebd73c8c406c0388e468d841a670c8d9c","council_signature":"9ecf3f570212487c9724b2225edb9b4f1a78e645090cc1f235f2d96e45b6b4516dc177096fb133b7d98453ac8b5f1b67eca4d7d34c69c61d563c5ffd79e39e1dce22e4e852213ffbbb44d6ec1b6b728bc5623c881b65ccdf8ad2c57dc40c2939ecce1d4a76c1ea94b19470992585aed19dcf975ba159346069a117f1c020f7c355d2099ba0501d022a1fccfca0757eaf00887c50bbfa21deff61c3678f33eb002f256844789548d1995072f5fcae6bc4e3f2409fb9a1c96eb203e1e0a90139810bfde216e1f79fae689b67b43fc9e660282915acee8a08fd6e623d97efe40e9c5068d18438b44a3172419a6d27c45eb1d0f013d38f088a375f23e6f2cf276086e6a943d14c3212ac39221d44e509f83342dbd2d4d41c79803b4c9242491ace47cb60364819a9866a2a381fe9c1d26d52600536bcd1abd94d592a101a5b93a42ff22834481bb17a464a2f6616f6e28aa06ad26649a0dcc2da69454e7e269dda261f97c7ab51587fc951e504b5bc35d14bfcbe732c96a1194d1c5a3cd82fda86e41318cd016c57177f3b22c16ba2e98348f89e4e2e6772199ad171af9b3f0ef53a923caf173a32cfd0bbf9207708b385ccded8337d6953b1cae32d6f45168f7c3e2b18e7eecd79e8be99f62721bde5b53dd25554638f9d8598bfe4208cb7e4ffffbe1423f810fec914e9b57d12c4233be7d2680953a197f41e6cea4b142cab8099e220c0d5f84779d32d4b3fd1d89cc2f07e5dd856e715ec279005b42908533c55ea3f27d9916dfede953e86c07e15c4055b33a501e987bed6f4c30f102525a3cfd1efea871fde3831cd32f8d098f0da10a12a4010a131bacf93f95cda2b420afc294f0b4cf4b1eb86b61db574d834bc6302352f794aa32737192f34614a57c40003a08a321b218e18bfcb653f938a00c8cad86d1eee92c8c67b81dc6b9eb531fe83cc1f13e1aee6bee8b1918cdb71ca9517bd5865dafd8b224abee0390b26f7db6b7966809a01313942373f801a7413bb68362e74e076d70441baed021b653784b8e640004ad6839e7d68dece2811226e1791e96d7ae9645e79ea9db05e2d454eb26636bfcbbb4cd06bbd0690fb12e31e308b1b30fddedab5eea14574f9d6feffeb0feeee5a5729337d500f8a53dea11eeea7927a1d7f907faa7fc5a54e97db55ee19270d4e2ce3c3c2ff2e088cea39d3ec5dac0c3197bd6256602fed11ca686b51e1424e548f807803605b770198c0e864180ebd667d01ca6a00e34926b756a2dec7452db05aeeef1e3828b4c061e141471f22240ae5182ca86ab4266798282f9239903f64a02288813dbb1ad7cc909dfae61422f75fdb8ff71f3f82e376710744f11f5ddb96a6eb2cb3507712f303dc34eeb0404af2d50e9df52500a24437676f25301504d207652c3ae47f3cbfe6cfeccc7612522d5a23e8142ec2a6387ef54b3f073a302d16f4b9f18fb78cfb7a903fd19d3b23553aaab881616a9c4365f572235334731cea00b04799cab81dd3eaa7df6c14fbe1812d50af3b73c9c3a73b2aa9470b4944d35a9e16d0f00551e181a1c3c79b0b3bb0104d80b98b82d6ad57e850bf849d40140226c0760b9684f078c9b862e486dc8e129fa44cd769c9ee11f49c63d36764090c7a92da0dc3889469f9e5aca8f4bc43337e266a404f0005fcebc509c36ec14a84188082e5510ce73b6dbee4ccf46a4d57836b39eba052ccc6f914ca2110efb19ee622c291761d8e4c2b51ff3a08b0f6afc5101b23765c3813e6a2a0894951f494d432a1fe118bacb2964735ceed2ae2865b3ebe2358fdbb52d1a6dcd1e6a536697e2d43f3a99143c6cadf9370db6e201f06e8e25f8eac9ff1f3cf66d6547f30075b9433f3c61bd1bd1ea8cc0a8017e0218794824e3acfa883d1b660858eceb6fe6496adeb2f109ded20a773273a475c0e6386db05f911277ec23ea8649363297d7f7e5a208d2102ee30c91866cce4de298d43099aeb0794eeedebecd675b701f17cafd09a952fdde166e788c309a423b41e582cb7ade7d6c42e75160c7eec5ced5efa5a6d64cfb12c9bc4515991836eddfeecb55114d81cd43b121f63db88e89c424a3cdd0a49ceb524522a7679486d08e6a26af264b4dd93bc7c0a432183c9dcd7dd1528fdb834a4dc929a8ad033c60c960e93d95a7fa12028897398ed105f259c83017df3eba28e26e1601688109228d6af55bc4ad50809862aee6f7b3f32c6139ead3c0166feda9a7993b3f6b1190360e9151313ca286ea66c5434879c9d9d386209276f6282b4773daebfe0920cdfc950cb6300c033d3c719ea7c07f81c8116de31860a16dedfe16a33c56e7aed2ba9885e662641e350d2f60b3ba357440e2c300ad5ed1044d2fc1d057da8a18066aa4ffda209fff82bbde47719cde9715d8b5fa65cb04ff4869494e43f316e4d29d154836fee3ac101187741f084215e41b14a51bac7b0e05b538f9c77bc758e62219410659f57193130bbb2972b496f9f5a89c25c1512508030f90e82ecb5aa2b8c0c378749fd50669823f98c951cc177ddecbb05f894d54d8487602734b63974483b1ccccdea21a45cdaaf7d45e83b4b566ceeecd884f18e2125121c41fa6ab19c13890eb4fb1ab8f3d1aceea4680412045f4c8b42dc9b6ae2f49b9c9187cf35675dee5459841c83041b6cf69e4cdb43b4a438be8b30d64e835382fa53c126e1269aac98aa3a8e16a05337be14483accdd07c7295a236b6814992e2512acab0d818fe9e92ed1ab312ec621b7242f6d72de1bf0fa5365054746c4828ab552fe175f1c30bfd350ec958468c4375b9d0816539b8253b68c56dc4c8e11f4f27494bde5f3d03fb111889499a94767085c21508c8325d34bf3d5e74717875aa54bb0d9bd4bd16356c48b95f1a2b344431304180ceec5520f7674098484ac7b77f295cf654a51a12fc9d9655d9b9a935dae50566e818fe3fb04a5641e31eed7f9de9d4da63d7299ca397f2a78b72e00d602bef9db318546ff3a302efe8f5bad11afe0173de15855dd15ebb9d5126cf57b23d9dba828d1ab278d4f61872fb4ce3cbc3a4eb8f020aa131315ba7171704d06b2d1bed05b7f1bc9194bf28d831795bfb498eaf04f0ab1f4c22431e1653cc222f2d4e11f672277070eedb7be13bcb65eff3922b835f8c6a6938b7903ae626fcf86ce8283bc69e46892ad3c40f0a735f28bcd88de98a37ce540d2857755a9ff282564da254466c71e571e900f8deb59528d7aee67300b2dab7ff11bfdfb6819ad93c627ee4223550dcd659846948095f20fda26784bc3c5d35bfcede053676f50639d6cb98f78f56f27e62691dc1f63ef12eec69ef08fccc4fa466bddb182b1b038983f33df24662ffdafbe02effc8b96aee34a03348e633d1ff04ce3a4248bd58d0ff7162718970278d4d9c7dcf6983be7905a67e61698ecc81a604de98879f4e508fe8ed89fe7b1aec967064ea04683ec29b856e16c40b3aeaa4dc05d3bb6f5c08498989e01443e147905db3241edc443f5ebf341ad0fab4516e2e4c07b07bd4b3dbc6eb15b198fc9cea05a752e3434d04db09d1546abc24c2d36cf52bd71c45f3cd1741c615c88b7955cf9c679fc484a3888552715233a77c92c2bbb1e93ea7dcd5cbb2c785927ebf8ce076b72e7cc54619a0600bfe9d69809855796a4b8dd4bf9ec097b884ea92ce4476551d582730da0355a8e19dd398c429f5b4211b0f4286feaf1983fc1bfb841432386d9047d6f15875898233550afe411ab62ffc9c798b3a40b4715c6e5a8395bdeda53b930b911fac6efae8718f53e15d72f3aa55fbaed352793fc7ca4e7eb1d302731b4c1bcb909cb1b620b5bff925889eb3e3ee95e57924e839c8a5fa41fdb7aaeb893123649847b3aac509e953f03f7b7531dfd424e0b2c255f08b0d52eb27d789df5478db75500530dcdc5889662866ee4527c75c94abcb1120512a39a10060902a0dd17ae02d06580cb2bd13c7b14b9b007ffb059a95caadcbaeed9eadfa69f44437be66467a90cb01f4b2f0ed3fbf93f5c48a66169e7512fc15f323c69bbe1b8f23a5addc2d47ee779036af6654aab52d572aebe149fcddd76bf3fa3c976a83ec45cf6910671190204a19a9a2b4171363acbd2cc031bcea2b4b76d98e43ed66f1bddebd3a8dfc8c2ce1d279faa10fb6ad30ba2442aa345fdbb780831a6748a085bfee8be981bbf27c653551fe9c90a3d388e39da4b443efc22af37cec2b74384a92c79355bc6ba5acd21f92800c139956d72ae3ef96a1437e6c5e163e621d2b843a846279f46a6fb398947bda8b8de0594d704e0bffc91c2a98548db0f47662202901c1208ec88b239036c7390fb70757d2078e4249d51c0a11374c99dc5c4bd92e52541a19284d2ec028e1de391fcbfe7509e897b228daecb0b9b68ab3fadf6199e0e2ff2efadaa1ff16e250d522ae844313100357eb63871ebe2f3d436707cd698c4941412caa714d19697b238f01b63aa48f1b6a3133d23bdb9da86e01ea8a86d2e98777fde956f3763934c3bd034ad4255596fd9501b6c630667181b4befbde2bf01e75bb20de73172da9155f5cea9472fd3b505a60d9951c36e240a3460b0c9e65a657e94426573a5b8e9ed0a10213481c2d0f21d25898fdf7277808fd8f8fe000000000000000000000000000000000000060a11191e25","approving_vp_id":"tip://vp/US-6d0cbc4f960657bd"}, // embedded by seed script

  // Genesis Ring — founding verified members
  // TIP-IDs, public keys, and VP signatures are embedded by the seed script.
  // initDAG uses this data to reconstruct identical identity txs on every node.
  genesis_ring: ["tip://id/US-9e22c0063bb22881","tip://id/US-5bcffc254fee46ea","tip://id/US-acea845937cbab1d","tip://id/US-59ff599b8c138496"],
  genesis_ring_keys: [{"tip_id":"tip://id/US-9e22c0063bb22881","region":"US","public_key":"add1c0f47d653f2afa30b73a772036c874180297fd755c0c889614a8f9581785a4873133baa16ddd06d23277e72fd2c0c27dd9c7fb8843786f4f0124baf68d6de4600f71f7ffd6e37d3d788d2aab0ac8ddf5852ccc91469c7ed5d98afcf3494d6535632e6ad937c1b7a79efea00f7eae58dec85a85c13821e9d62b4e3eb4768d3a8161bea9ba9836392625387ca3672512affd3166a09fee1e7c70e9c909057025324928c59ffbd14dab438b2181459e7944a08606afb6d58caca07f201d598ad32b0f55ac533f4536fbd66eae09c5c2a9c721b6f9eff39f9c9b27907af1c5a17d31e1b6c6400c30714d95c0f5393db456f4acbce33991468a3a4c6063a00be1b98449fc5d84f1878c79ba4ab3f83087838f193bd6fde78976718cbae4b2f02faec7aa4179c6d01c42626e3be206dd51dded0139a261613cad09bd67362ff987aab5db974ef4ef4a9020d3e74187b65db99579411bdef67b7006762300f4809d35830697f3371f8179faf1b0c930830d75371c1943c813cda276dc59da007dd161b472629d36e7acb77410524cdde495e3a0dcd3a2369cf17af2a54004c6e68bda6cfb4fc29f2ffae71adceec6abb0b0e6d5d577ca0f09a343c1e670e789c36d4da9ecad43912798c7751e0f9d86be78fe4912b316a8f711482a6d6cb93afbf47103ac423585a73962801a728dee7930d185217421cd940fd6c7e9e12f30354415bbb3a5ede06c30a590824166c21af0e74062a97eb0c557a72ae94d2ebe43328a13cf790309133c82e2a411b6ea9c21a70824b61101574f459d330ad98909d7caa35efc10fc4383b62013b5b8dd26cc40cf77afa7a8ce0ed0b6a80db8d575398626840a520ad8ebd90c788774c78facf9c90408eafd9ddadda229110d4f0954fdb21ea43e2d647e09402916b1ea422d1ea9e3947dd5ecd2f912cbf3d29594391948f91826d98284f4723d523fa7df94b49a71a4f187b0042144402485a2da6b057f6d6f801e34690811a46f1a0d2fc067a9888dd4fbf003e804f65b9cf2612a0605c650d20f7abedf7eaa8474674b1647f479314e07ea4cda9824bda667b874914f30987d5ac5bf43d79a2744e2e52310378a3491f49858a31c65456b000fac322c08b44c887c4dbf48b365088cc3a1965f87c4ad92ceacd5fd686dc09d8eeb3c455ed30959743f2731dc0b845b649f3a42d910fdd6c8ff70ecd8dff4c8d3ea5b832525e3ec11121fd417e21e63ffa1aeaea14d37796e7ed536589ef2d103c6d46b49e19f4492389a5da569039ef34008362ca800c8981aa9620f43445394c90ea80f7041a785f9f078823359a63b9185e95833f18a220663fb14c45aa365930fc5db7cbc6d6bc48f0dc58279471f27bae3b2cd3c66541116679f549229f783a07f6849a3c37149a341d256cfed70fe0ef064779cd9af7f861552eb4d12d00438e944f010c9116e37245dcbef565f36fe15c403e6c0c90d3dc50f1f1b856091710783f9c88ed3811b265a7eb5fba661268610997aca95f453a667ddc852b5d07762fdf0b85cede2f8d1a16b7ee14e088602950868d1e4e2003cc98d5514bc781d6e2c0fa842839cd93b2b733f04d4cc249ed7ef366fa12f0869ed2d8866637212a46d8ce4a13a392b649b6c82063504c44dc5583470b780dfb6008cb64679daca1bc2de35a5e30b61ef3ab7ea69ac431e259471d13af15bcfd132ad79c5c535ed5645f81a08b190a64d5169c7b971171c2ba76a974518ada319b95d0d36d7764a895901286c2fa4722436bb14f6048a0c303f071e7912984ed852db0e3394b8b521d301c54ce8696e317e97226d30224b96386c0123515971a972e2e3c9ef10385de6ce9c8e032cd6e4f01d541843eb173bcabc46a5454267449be1267aaf4cb71a924bb9645c6f1ce9d7d782707268cba1f22287e773ac75d85ed4bb3275dca9618fd274ad4b1727b268a68df1e5dc7d09ab327443d97b9cac2a714f3f5b37abcf0648bf20a7db6fc2215a38b11749edd061dcf1fff952f1585689300defa4828a6fd66b57dca538b990c48ae3d3ff0ea8a336550220e68153a1cad36c1a9504e609e2e410aaa09f6caf902199f2d11f8bed2f0a3098ab9cd8c57c54ef55aad6f7f2e24c3539ceadc3fc994c18b7e79c1fd4a92c4c0f418f819e6ad6336b82c61cc41c6c2bf99ac574e2e3e34640cd98938ba6ccac7b071354ac48dde4f5fdae738aa1aca603ae090eb397b02790f8e85497c61117c3172cc4fc4ca86a3bd68137fc828c28b608ba5e280705d2e59bf52cac9a7ce6d8549022a6803dc04003cc6a2d954103c1c0cbc742888350df3c77ccd832cb07dad556faa91f972ff495567aadb41a68343df5daa15b1f77423036346803a0e18f21431c4210def7c8aefdbe3d05dbc7ee949747e2791d06ee6ff34036c2082b4d919b85bf3e3264112b927a3b0129f2ca63b953f68d2a507cd9df251ecbf93a9dc4bec7505e6079a9a8056c0da086d518dcae8b9fd7440ab81d18b1cb8fa9cac0215beeb1d38a4aa0de3c331e124446525732ee3aee020ff1af2d939715d8e0f022569e3c52049cc2c3857859f7cc055d205fe046e7bb01e4469a7d6c6d29bfff5e5585e0eac1055d57084bd5c16b5be0b52d96fe096a5f98fa911f8e0e43f39a14ec1a962fe81edb7b3063359ceef437714657636a4f417f31e06c0432d626f6eb02fff0398a3a046caa9d0012616d52f6fcfae574ddbbfe83d9737afb39baf8dd4fb68f8253311468","dedup_hash":"92661839774354454942","tip_id_type":"organization","creator_name":"The AI Lab Intelligence Unobscured, Inc.","vp_signature":"5e356876afa6e74272b1197faa002dd6c2a9111a589f7efe583b4099048c5c5f1b3ea84e99e8ae2e5ac142b85cbf56feeb37c7f79816f25bed7ae37d09fe32a3ffd4dd1a6fe115416f8053ce3cd6b2240bb71f6bfc1f74db5a1dbaaad36b09d87ce56e36114909d2cd2a122dfca3de5f73ac3885817d5145d0ca99898a29460a9624106ef0e7f4c8c16252c201b23b96beaf9b940791cccbaf447ea4f3e241eaa7a352647ed968c96abb441773ea00ec3f124b0ebd6550dba01dc69f3f357710440388eb3298c6f1470aab0089c0d5e5a7d6310c0b03c2e88d2b8be4685d445d09f3aac6b6434282c956e9a1bda2e15bf2acb7a26e6ad41e0bae0c946d497c3aa9de8ada63a3ed3c823d58ade7b0954432a911405e24e794ea7ff2ca6310f4cdf4419d2a1a0a252980e91d16fddfe0f51e9f374fda97a0140a2b7927dfe68c31cb3cede1cf668c2f06208e18016276aa59b467784265271610732fa5da7beaedcd9b0bbcccebb89acc9f14252d68d31fc44ff23206bc3952b2e04d51ef2c704053d346ad7597ab68e5131cc7f6f4b9451065a5ac45e0ea0de3cb8dfaf4502b8851ac69456110bb1537f7b098e78caf588d175c4c0a9038de10370e07c7b9112bc5f442470c5565e665b846a26c08b414fbcd33f3129dc4705f2b0d81370acdeaa43c43464f068acd91c5aacf1036121a6cbd39a0a1bb71efe1131d8168a3f42684f75a813c8fb32c2d2c2b79c33e1decc022438c79cbdfcaf36768e6f7c86b74ee27d646d69a8e11b109538a456cd81e28b6fa42ce259b9742a424bc482da83d1ab5f3ce6d1e1e6cf69c81f30b49521f3452215535201c2a93699f7c65897545daff9bca6732c64b15ce7f608b8b4e64c6945d5358c71d6b1b9796eb38dbac90ba071b91e484a224756c07143ec0bd3484a46c5e7d5df1148884188b0fd284fd7523d70de85a27f0debb79c8c7a60cd00e8a8d4850e797fc78757b8328264b452e8acf73584ffe412f1d5c224f417e099ce0caf86633be15b0091af7ab994e4a0f31baaefceb7427771db0ee19199c796df5dc031c1ca2eae4c95297db1c716eed01eb6a9187ddd071b56bf14a4ff1eaddef1e479112eaa6a5f7a08a373946f9dd696027c34a64c68c0309432523a4026c3e79d8e8f4705ac96c5269ffb249832b37ab749421d71ed1ec5056055911ff85ddc28460c2188a7c88ffeabd61050d59bae24b69810b6b80537a6a1d37eb67cfb6d38d4b5418581b9dbc40b72c461041bd5264f4bb56aecd444eabf973f05778a3b5d50be9a7310875adcb794cf5db63db0b797ba6efb58735511b499b2cc1086680de9ab9444ce3ec5829b23de54cc17cad26f32f9195172e6416bc5958e923e6d27eab36f970cfef4b28e99c48f509826cbe522e559332bdd9b2dca3ecc822debabdf515289f090f6391f427d203eff88edcc8a303fa61557ebd130d7394a487043bb49817ac80d42fb8195337c55ac960f551dcca4460faafebd3f5b070933bba724d792cf2f428073f19445398b0475fadae414beb472972132e05e2f9844a1b089c07ffa2db962273710d5926aa8a3beeecbc0a2582b7066c122cde2d1293300f93e9ee4f44e90beba2ad0397ba4e7a0efc48c0515e54f5af18191f5c025ed255023ca7c052989d2c44406844abeb9f94e227a44c229f1e6f0c2b87949ac766db493152338804fec8f4f01e251e5a80a2d43c5ffca8943b2f850de0731d757057d91728b93c88f6c3da27bd7f01e2aab416f6c3380e270ce0f3ced596bf59e5bb6a6a51bdf95e51dce1c12404c4856e3eaeb499b636cf874c3226f610024d6f81165227772b6992134c249708f5bc18eebb6e7b2dbe31fcdf23657f4b1b216864fccdb12eb733192e0c50c84d1a6d8e892ce3ecc5a09e018fbfaef93ec23e3abef032262e43d77157f38ff05e7ab99922f3dfdd965314f40572a8f58543f82fe57facd5417f4cf24a74e24e100f687144bb4c293d4d91490b3bbf0f56c9665ac695b1a7dee055ecddd628092dcb70699ac59fc1cf9fc0573d227ef4e0fe1edc88265e877b892cd4c689b7e49538ca74d2b6d02ffb47da290cb6622061296c3b66fb3d0501a0a3801fb30284acf7c9c24148685322a5eb3c4d5889df591a513ac6a406252a7299e1416003fc7045f36f642e663c67ee2125d2419ab686458aa12b5d341c80a959d8e106939ceeb6c759f757a308ec4ba30db4a3191c1566ec99b1914e5866b47ec5d5743120221de8229a33b32e00973d2da0f7ce7e336c1a58697367ba46bb2b629599874cfcf963cb65b04f9cb401a5937843fb88eee9d11b7dfbe5b70d8c9de352045c69f716ecc4149a64dcc6c8fcdb7ab79de29e1b7ea7e44d6bc60176d7c1ce7f06e9674bbd8ad938bf2a9749c3b14bebe75b5950b89a1544a0cef758fe44627640a2efd91f897389a1ad286da5f5fde4b7a75b056e7aa9910ce8cffe6166052c83a308817c3f0fd36fc8bdaf4b29cbf596ae280c0794a30f5a195372ce0930ebeed456ea7af5517690460678cdcdddc5c35fd1b7fbb437cdeec0ae0a1ce951fbe241d80ad0d5b7bfca9bdd3be6391b3275aee8e4f81c1bdc52a709ede9bc34a88b4a431a81c0fd15a2ac5253d5a8cde57611b784cb70fe0905c8ace3600b8112d9f93f5378cbbcbc5cefeaf9a0bca612434f7493837bc463d85422179e99dfc875ced4d4f222ba0565672884030a3138480847efeed7d3f749c133c17502fb62f7cc03188b0bd032cbca72f564e69a1c66b2adc56bc52b56af7f6299871e4980d30a2fcd8340305bca92cfd5f7279f1d9d2bc36820f7253666c1cd7fb1292aa3fe18de6ccadd9bc550a9c7fb67d09c50c156515ea769f331b080d9f7968cf513005b70835dfb53d77f97d0890457dfb8bb37ebe133a13704ca25b139d3c090fdf85cd90e0ea0377100875e15b4fca5cac1055e1f8ce3cbf68fc10d880382bd16674b2656007540199c7a8657d8a878982ea9f9dfc09dbae2f2fdfc903af69ebe3e881faac7ec6475562e51bcb652bc8c783d731013605104fe031ad287879796f41edf5c13c01627c9896709323e2c1330ca78e16b4e3826c7cfea24c6d6dae3f8c88148c6c1ba4c371786e4803e54d0caf12410887912828272aad08a2da6f25338452b6557c12e448d035efd430fd2f0888314743b91f5de007803c68fbe6055f1ad64d42d49fe56ca5917c1146159c27eb303635fc2a810bdf501749fc4c73248e9be86f76f745f57be4aee14ec663ee13ddd5569edf7b111373ea9b88161d5790e15a858e7e1c6c813a92a02b21578cfe70cf76d06e250c8ec9a256ae2be762d55639521d479bb7b45b91501d9aea079fd1d879c8b603c8a98f948ac21d0a2649751039cdaaa2eebbdc88829923d9b1813d9d7a4b9ec5076c657741a07b42b71b225e2b4c1c187f4071fa70e9f65cf5c76974b2f6c84f050e51b463525e46e2be6409d52ba3bb58aa2b46ecb51f5578f271f418e73c2f897e823564438bd78e7af34d1b9c8016d851c62506281944c1440685041d61a572e4991b729ea3869ccc352ca943c52cca3deb0d12a0286b2295bd33121999630a6af1c0813174683bb7549bb8c998a6949a7c40762d62c3f5745b434cc6357f55a4d488ab7a999a50d5c02240f5143cc06600156b6ffca3488248e862770feb937ca7795b3a95ec4d823e91ccd719e1f12bece6d75025943aca195847439906a798675ce5c034bc8c137b2835a391c02addee645f14e14045dc03d952e928927b2086f6b28559dd1d4f283d6be91d9192f0637b7ec87060e5321864ccbd4adc9a38df3fc91d78918f435ccb17af2829ad136c82d0fdea389443db1796b7ad661fa6c12c7db7ae70c0a1c68335d20e5dd91b76410baa431c727caae22b9b8569d58f8afa228d7ffffe3b7760ca7eb460a9a017a46a65e30ffc0959b4fccb19833d5a77f23e8346f2485d2838b7a4f34315471321e65f07e8a11caf34644d8f29cca53c64ab8423107cf103aaa0c08df814c7d7c3edc9afbe4654716388d0814f7e3c706255e6cf6f10b0d828abfcb0cf36601b669d72efe7ade5c5ea5acc79422063cbe42d854661e184d38fd3c62e03724c90c07b3197f03ee2e18e54f59d7de80aa473e1be139162e40e82d8efd86079a44e35c7a58de4c461ee0714fcb20e9b51158e835df4079a7c4b02772326a5aeb5aa8e209b8ed0d84dbb952a14f5f6600dbae96c1ed17c5a3b93912592d5b7a0366f110240a832e09048888c62d4fc4528997f6a9cd4f72a568690acf9941cabb9ca1b60a197e0c4f707a9da0f470c77de17d03875a4e3245970fee5dd46beb6581c091d9100bebc35f8cf71b71a35214debefc3fa09c8f3aa0f894cc6d2e278f8035baae3deb6b71c1805e98bb48b5cde55c7a71f79a6ef849329a628a2d197d041333e809d3b7151fc491ed7a3d74a7372c67442ffd40b7987953024fc184505fa8256f18c6f013aa54d2558cc1660ff0e6729f2e73382b239eab00a51324ac7af830803ce79be095e99ed69f82303167786a69de7ed2fa10900c9baa5a5e77be87df4078867fa4341c39495364f5002b57718aa9b5e8065658707c7f879ea121364f89b4d83b4d5982bfc0296c000000000000000000000000000000000000060e171d2325"},{"tip_id":"tip://id/US-5bcffc254fee46ea","region":"US","public_key":"0c3aa47b935772152c637024b0c8f750ed32c907066372c10f8e0a1ec65f2e095a0f48af31d2838d3adb2385600eb701f41fe404ea40830c9b72c6f9560e86fdb40d252b765a2b993917ae6375dfc4c72a8f98c0a04be56cf60c324a7929255b4fbf6ea04b56e90d0af9c3c4a14edc0d1ce41e381c1582a66b7d7e0c1bc38d0845c637825b93e56b3d99a8075c66aee699b84f4d5ceb9f92c7841ec5ae593a9271556445155c7404654c490c0483592782b3faed7be08702b8d3c1603c329dfd64a456cdf6a31caa6bdc772c8e914f8cee67098a1cf977d2c24e6a01244ddf595d90bef6fa5ae369b820bd9e849c5af05468653b74f86591a542e57b4639fc50316949d313bf20e92f9462eed3f68817d09ff043e83d4eedaa5171760204b85ae719453d69c27ff5ccbe50ad92e51a7e8316b0c0b15a1f9c6d391bbb39b07f1290f5ab688e24b30c043a6693f3d01573c42801cc0e8efa497e9a057f6c6bff89e976366dbb7a58f01a4ee476d1a59c97eac84e110474243a465aa46054f3a6154cadc0f8d42963035b223b9f390630955fc3b9f6ed4a1cdb577937c96f00d44184e04335d4ceccc3c73449ee523aeaf4ee5dd71d08e99c8b341f944d417ffa009fe8af3d08d12afa46ae45303df22e6ba9138a9573a4fe5ad93f28ffa3bc439581ad955738b42d1dde0e84d4aeb1f4e34cf034637354cbfd0af13ed6a819628c651bfda7791cfa857c93d934669cc9eb41ea655bf57132f046f6c99dac96f5e62e08c230d4963d1c1e2260ef43f859671c28fdcd6d4350bd16dcec2945df2e3875b30f19566689b658b816b37623d15b2e620bb8ee687f73e23f45eaca03e06282525433663520ebeecb44543e2805758d5d8df53e3a5808b99929cf666222c88e8a59fdc849453acdb022c490cd1db117b181cc0bb3768803fbeccb3d8c7489d4bf5042642c60b55409c277891fde2f5435737651ff4ad91ce886a5d079d7f505899292dc1e586892f0973304aa1c30eb3d9369e59e852c6c50b86f09268d8ab5bd9dad4fb4580f292c780370bd7c7f7d15fd7ead063f7f0ef957e1396f27f212868279567ab381b95a676d1654ea76bb3a20c2d7b3d0fd1a00b113d26374e892fd248346f21f1e0b315e71dab2cfee070ad6cbafe390d277ef5d75e3c5c042bb3642db694b001635ff6fc7ccd50d3b8bebcdc6e85c1d97ee2ddf78694273191e8d81a1998bb92a00e91a303f71d7118d3c9cc0de78400acf74ff2cb130bb960a69b81d3858df367832466148562a6d4196f8ce04ca26eb6637d343edcc6b236f34b43260b27862f8c38da06cae6c786211f4d49186b3f718463040985a2d562ceb3a8e7504ca38d5dbec3bde29fe2ae923969bc7a9b7ea6de2374f2f75aed7ffa393638317184852a05026cf24800887434891c72ed6f1944393a28b503fb2e833bf40afd84083d8cb325c653f3d19d6ad580f2015491fc96912ccd754d4adb52aa963b0165d5ba600eda6ff62c425e1f8e043997413bf9e989f8019f41d5780fdd4ac66fb484b070fe399bf592ac9f939fc652ae1f70acc0516116831d895d1189c6f8c292358978b35c2142a32b2ee88310836c32a98c946f7ee9e57ca7e637f63a5b9f03d0c2d7f65388129486f40f1a8e1ad22b932b86bb0aaca48a77eceb345d53a6a40b4cf403048fda430016b5d2d7130298186f9dd8cfeb0ba03999b751b46e96cad075280e23d5fb01ad7aba5dc6e188b9b2d19cb54d908c55b0ebd0bb023cd692f6e543423f4d40e4303fd84fae11900a4fe48e30627ff4dc3d300ebaca6748a5390a9f9cf053176baadd4f819958b9fb709e72078e7d42e32c431da012eb8e685eabb1debb2747dd79c0cf50dcda2b8ecbe5698a8f1ad59213534694b808ab183fc6a1df70d39076aed58e9b8463815d49cc77e2e6bfc2d4ff9acf4b60df7e808e24c433954a6e459a699b7d03716dd9d2651d177e41fff45702754da1969412315e99144353a4e0e7ccb9d7aeeaec53e7559e86dc086d11fe58c6f43f6bdb057666e23f0964a7831edd5c0f9fd6a3ac3bc69c6875f4df72659ae54c92c5c696a04e2ada6e3bb32ffd1674aec77fc72cf10c833727d79c0a9e3a20d40c8e2b38ff2f780cfd99b341631042adb5ba5173cd17d34bda3c501f75694a591d72425b1acb499e7f76d1922908b12f77d7178a4daedc32391ec9111cb5d8720f1519437bbec1e42ae73aeef4a730f11fdc058423858244b3ac4d76fd0c180dee3215abf07bcf7bac17f0a8db8061fd1d4a21ce4fdbe7f0e171aa4328e4461ffdcd9b9fa2dc5923450c01f4610141bfcf5131601224f031e98c709892fc638f3ba4f058425ab670e8ad1c6faea96a6718e46b15824d63bb12a5a7c0aaadbde46fbc001b57e923f71eee8b6c2dd6516cf2f857b8aa8eceafecfde1f3a3ba7f10d5ab00335c062aa7be3ac09b11a3af0a128bb7b40afed098a73f048add2e8d287504f0d0bc921738c4ee4b28413f2176261f0349d56425febe32e77608c53e2ceaf471c8caf40f949fa3824d1a104de7072362d4b6e8a0d2d501da47eb0ae03d895698460b43d63a815cb7da54d72d44e27864e3be49db1d7a56c5bd4fffeafc8b7a5a211af106516c0cd33c4e3ae13868f662ca1ef19dbbf58255827899786601a2332c7e6ea7d0d8e3f107d1f679d669284736b9f54dce3b1c56534cc0d6b6e2cbf600e5c80f03a6fe9d601f0d30d5e0d9c0bc54996834ec00079f470","dedup_hash":"23702933538943712392","tip_id_type":"personal","vp_signature":"1f83d9640be765ae98f50332bcf50c1f052e1650d08aaf32a12b16a69d55822e9bea2f8a1ad474e311b14a9cd5891cf80b5ef88a350fcb808b6febd391cb0799c6348e74fe28d3437caa25987882f6395f4d3e464452724caf8649280fcca4dfca922ebc0fce53757d36ce503a5ee43eb4d02a20986c19ea0760abf14299c3ead05e2f8292da19377fc291737e634f64271ed2663b838f029fbcca181fe587b6b409b4eb428266822e37109c858fc345b1a42e0fc0471142ac0e113811da1acbcf785417fd0dd67ee749d830b402cfeccc5ab18c0031160ed771c37e0e90f8e6ae34ccca269059dc6e61c149298367dff9c42063d7b941fe1e71e882d748dad40637f787e80fe94d544cbc4998b55eb1e8c6878f5bfd9eb19955ca72e6308f987fa83f4e63dc23ff89636e35ce6d9a15afa19e2ddaea4fc1d472cf49c6e422c55930eeae7c0aaba7c17bd46c66ddf5c6fdfe0a144f40b6acb62d3d35d37d492c34b9995343edcd3f1d8e62642d66908d8868b970e1447334e5f39d85b0c29ed81179b1a41bab375189ef6f941fd3da2e5f998484d5cbcf769fbd262f579a4bf8b5f34392638bd576e84f6bb53a3bc8fd9a9c9d08479530696c04491c54458fe7aa1ae71553fe99cafbb145ab4823b6e9d8b3bcbbfa0a9541de23da164dd620304e71d3e4c77742b3b30f0cfa3e02f71632b21675db9e83850ac372287f6f87cd87880c37cf33245077adc9cb5d673b5189d11cb8006dd2d2b96abc258e889147e8703458623adf997d567d5d8800486a8caa7436c8ac86defc998162095e86c75f46a3376c2abcef19730d7ac2175d007242e24bc5da6852041c74690ef9f5216f2510f2e24638b235b042e1ebcd66f55dbc497378aebf1b958535c0637abb03499d0c0f4b252ff7b5a1e9980487c5bb3f2fd675512c602f842bf2a0e923581129359c5ec757e55cfac1ca1e21d8ee7bdfb2dd79ce6c01dd117530c06fc77f0201f6ce8ae36acf6707f37591f22dfffcf33ad0e312d76a6e481d025a6808a8c73287b9ed4068def89f3f26c4ef2daa028f7d6d1057fde8d6773f771c5d13f1948082929623d72588529511dc58694e90b03a2a10bcb48b33fac387d0e5ee190743ce16f173bed2c35b230bbe8eeb4167c29f5f654bbd78a55ff67dcf31a1ed98c5ea9ab435d949a2a851abb7100806ec8b3b04358879937a1868cfc7641fc1f26687591a18f5122ef71cfcbcedab6d75cebe982dbfaee5628beca891c7e36bf5705c0f46639038bfd7a1c0052cf08b0f9c10b2fa91071af10d5b8e36a63cb9a5582eb235fdbe08e3a7c8d87b84e47b68fbcb0fb4015618aecefcd2c167c2f9af890c832fc40fe3888e37c201a9634feb6d1a023065ac0a81f85d414b672e0aa711f39c033bc3765db7a16cf149a60eae344ed05584777566aca5ffd11cba5d3cf4179e2681755254edf6342a4facbc006bc5b48fd112e8c73292595b5ebf513bfd82ed408d0bfd659572b8b0e1bc38e3411648daa8060dc17284f9abf3e5a661d602732d276510f8933b6b767d9b676643325cf03e29b3771b8f52b30477c4419c912f700f7a946dbb8f71e140d5f6c5e94e3b1cfaa971fdbe5bbbe743c875dac2b2f404533ba4201cd32066087b33fd717b309ff6e8c6344ea3d4863524afce62e0f17e2c6b116d262d880060050e96738922290a6f8902e161ea49979ab887fd62d7eb4f9b70ec755aefe657b143996a068d992be2b07e66c6e45b229381858ed81be18bab3872101564e42fa461f487b0e8ebd6d36d43fffb0fbdd2be742492f63f09e0c222901dc263f1fe30c56c29b78932acbc6625a070b2db1364871374ff9bd1b9e89f56b6765bdad601d4ac8e5d1c6be888550644e795db3ff0e359aa08646aee89295df5fe27b4322aaca709963beec78747a9eae4fb70659a91c500a89a0215c0684624ac32ae80c1b2a0f7ad2e38f99b1080e8ff2581cdc285469bca49116e569811347572423bc898440994bc8c1836e74cf062a9853017553249569fa18b482c844e7af82d449292441dad1f2dbf79c87ce45853a5353f9c53398d48cf0bcc7f56683230a5e87d70489e12353be6e9b6d7ccd72d7c7664a0f40710072c2f365ebda40b3313f79fba630ef3ed3aece9b4ec6ee14306926619601649dce3522239cc3947ae015f3f2407789b4ee3085ac36c5eb28c947712284ef54f53e9cdec641a98c0f951505dbb5d1a32bfe67e0b49f23bca60a2d0e098e9a33f9968486f7e19aad0a47b7aad7963480ef55dededa088e408a990a1a0b569ac5e280607254d967690d9d177f9b06319f3f74922aa90644bb789acc4220b3bdb099f772d21e2cffb19fe2c44220603aae24bfe6e3d3129a91a7f3ff8ad1901a81eb20427c0165a934aa877e5443e68c9f7ef72bdd2a552ad3c7414b24f7e4c3eb72788985b8b7ce1057aadf133f627e3fe28b1b326ba228487b01b8ab709ef675a146bc3f4dc669cb3ccdce9640b39be854e7daed36f4c36bcfdaa7aa81c14300dde5478c668c16d457e3b8b97a3043977eeed357a26b1d9c86dde14493afc27367de97a93dcd89e06a2efcfb15d4f3a13ae3956dd702f95b017bc0f87b43eb78a07cfc858d051a270e5f531cae427a16801753755a806b85272cbdb6a0ca18c295a964ff1aaacb2f2ca305fe777bd6bc232037e45c72c087862a3bd7cd2dc6ce60bee753b0b0f66a7f4c81561173b3c916f748b0a97d579fbeec9fc9a70fdc51b58eefaa0a695bb2d5b86c3427bac97009404fc5ed9081bf290224921ea4e24dd2e69d177304cfe806f525d3a8662bdb0f84fba5e071b2fedaf6f3efa99b326713526e9d4d018d956b7b672a4b65aa03da7f5f87010331aa5ec7ea821a80f0684c0c50b22ffa1f446420564f686a9d38de83042e57c9055628d70b55ba5d1cf6a8e6b37a2ea901a78c7e01cb7ffa0e77b5668616f9eb211df8a6f50bffcce120135e382e57cf3f8f80e294e30982a779d065fe3bdf7921724d4bb5de56a148128577d3852f125d8eef2d6a11310153d51e7ffb7562516b8a7bef5bb5a8735854da2b3f216a708284fb199b7d4631d542dea7cf56ffc7f18e98e5d7258ce768f3bf1469f6ece422c44036719660b5d169b9e588c233a28b3c6dc608ac53f72d62bf628b4838f56b4973cb4447d676e547c9968e917938be902f0a17f8061c0795b5a5d53fef85707227bee7679e0a1b87b3dfe3f4f4eb2b67bff642ee02cc552b72705e70e3da6bc62e84437fffe608fcda2d4fe5cf48caee0c7deb30904b7ebac07535737000cb03f87d982cf0244762fccd5c7a2cc5cfd81f8526fb14070478d4c01a5a8fe6bcf7d5b3372a832b108f2e564ddc7a22fffe1ccb8fa08086fbe618ac6278e87a8d5ae8eb65a6832ebf2022401a9c453c50bdef557c1bd2a1c9aca171adcb5a8a12ff2f6764802d64b892fb145061b21357fa8b84501a6b86869f24d73c67d2c487caf14d6da31378a16ebb603514a5fb68464780d8f2585b5d38663786cc948f83b4bc88001e4fd36eddb1f1187cccb0c0c67bab87a3ddd2c6c56dd22b86f990cb592da2f4af9e9f0cb9793d7ae155ecb9a4d408604b476acf1fdd9a316ab561bb51eb038142699ce5414aecb227e207634a9e7dae4f2ed3d04fc3797e826ee58c05c62cadb802be0b9211d24861df5b79e10b8e29e00688c99a7fdfa3f26c064791387dc12a2d0318fa69719d9fa9e711be1caa4a044f542c42b6224a905d64c372e3c40b3619969330ed3d6a893eba93a5756e98c7e59ba1154e5cd3d42540c46c92a86ae6d66928eac44d428373f90295d66e441b44ff90d51b78ac867f53e05a1947938cad937e3b9b1c89f2d1e57042fd1040386593bba73d257f77cba0b61b3bc88f6950a6644897970667fb513bf82430a3472b91eb01716f706aac3c9e1d866069eb9b80b3c6f686b3c1aca2a0eb0a254f6f96e5647f802ac67cd70198cbcfa1c5db617ec5f713121b1f073857c716107b6ece2973319e2e43a375ee2f450fa28e80f37c477a831d54eadbfebb950ed51de7b8ac13415e3dcf9458409ca2a02eed547c8896fe96e6156aa18882044b6baf9967b18cdbe584939eba273eab55df59b5a78f94e5b977be1e868c1cc09b7dbd1496e6baa01622843b14c470763d48ea7bc680a4ff947cea368778831f38120ea70a594e9e047b43425895dc333260acd0baf528529f21a8cb0d214b27b63330b1893fe4a554f087921890274a72ae7f990e6deda798e1ebbef828820338d77511b6be44f54f654d6774af45afc5231f0468ead6d9c65634d7781af7d01f5634f9eba59f0c41ab53290d8ef6f9af3089553139f3cab6a553ae7db935083f1cf37ab1368762c4f0e4f4ac93ef7c838221fbed2186f6e0a6a42284869540efe008eef307e4266113ecbd586c9d31f6faf7021d14557e4f4656ef0c319ee0313f72bbd30888d41d4e31c957a024fffd7a53ef3bb645743aa90cb9a79ae9938a514255c76ff0419f529917f74162ee268c049a26413b41b84d61b49cda4b79d1cb2c4a97e57f11de5edf7c81e47567466588874ae26d45456c5c7defafe0530528694dce4e90d276094aabdc4cafe4a93ab232f475782b1ebf0f1000000000000000000000000000000000000010810191c25"},{"tip_id":"tip://id/US-acea845937cbab1d","region":"US","public_key":"14262b47b494940d9cd047c209eff32cbdf561f30a89e4de5389beee8dcd2ffcf178274e82f44f4dfc83ebc8d8e8fa976a970c2943dfd823943f1f5cde2b23ebdba64950ed0ca6f1580e8e626534933a15393d979fd583e878aa710d397f06d3ef4acfc42fdca89174e4e2e4a044c0f05033d9bbd9b910886b7b7f9202bf4d89587d7a520f30971d910e73d59491815a74e5067795d368b513439d9b94fe1d92f00d25c9520eafa2dd1239ad1c3a329f2eaf011c8f879f29357127cb691c86a603127a8fb7e213c4ae247f52ead536a94926bebaffbadef2ec586a80548488aefdc574dd1807f559a3fc90bc440e4b8016d56bfa8497e6cf15532bec2ec40936ace4fa131db87bf0b8260704c0e689e088197ca72d6860f041a144bef45f4133f9b8089b710faa9c22f1fde2fc38999dcf776fb5f862e6dda6695606a0bdb2e6b265c258e5ea3d52737c348a964df8cc5d29e2330800edfc4404f1b764f80aae5200610caf54b606333e80713d5a1ac647b60a1ead0c53af7b455b929606eac146dd6caedd5496b57fb066f4f735cba82e06d4ced95ad0af13aaae9e06d484393cd68ea6954c4839dd34c1e1165d9edc7bc23aa3f51d8fd7aed196db121760aef4b7208df3c9a0911a2575bb5a31f32ff0a352f14e014399f187f9073cdf58c8aeca8d08049b111f3e033935ba9f39fc5cf1f719cf8d274cb443928926251c0f6865c6575a6efbcc9972344fb4c9585778307016287f0bb7fd89ac6c633f1fb2cc084a47a50ac82838954d01a1841864420b9fcb2117bdcd1a988e7794fc148968bd391ac4b9cb15979e721d9bd85e6d04110de424a8d94cbf2dc480e6ef2cab20b205de3823195100db42c844a9121bd3fcd600ae75a0466281a3808548f2f2eaf3022d407e578c56d181df7b1f91659c089a5884b04828cbf2b26d1f393bac14505e81b447153b5e649c7568029a3b54228d82fa5daa5ab48d74cfefd0fec3966e7b1983b20d41b5e7dafa0f461f302d956c0ff7f5179247432d7ceecc109b02e13f5e59df7c0061448ab5bb3f83c83d93a979b34c22295b4ec1049852efca2fa6b136baac0d80aa0f833a01bae32952d8c48b19d3dd7829cd18e76278b72160e4adb057e7c318dda98926a61a6de4095197b9059aa65a583c2a52b5768484a370c0d834f09c66cd1896d7f8041de6741fe3a3adc4af8722d7fa70bf3bf00b6c7d24cadc54e34d7c3546979bca42cdb15d972debf3dff909c9df7296ad28d3d779112dacc2b2afe899de63184972669f5b90ea716168129679456fbff54f1f53a8625d3b103d34ccadc0457418a46e04d6702df6c22d23fab3bbe6f7ad21ca93ca668c401d0202a75f306581fc4a04d212c5be007ffe4811cd03ceae1ce057417e162c3e3be6fca2be31ec8150b953e16acc32c46bb97523de733f22992a008151593f495ab994079c1cfde93fad142d6488b317ac74a19f7b180f091bb57de3cc6f55903dbd931d41db0cff69052a92cbcb7d3aaf501616e2c003db34d0e2d361be01a288ca55b690eac0083bbad3a2aba9bc0c6f4d77d77c7789604192b347484badce8a657e1de8ea6b607a91ad5582e6f2aff52532d2cbce0b57a36066e57be3674e19cd6579ed03b02138ba0873d50421e8bf75ba6655b352ad86833d14cb0c4f9d1f68831faad01da13c517afaa0935b708d377ad279595f6f16a297a2a6af56642eb15b34253038edcfc994d9d688b4911cefc6335b57f330e949f38f7f1c1855c6110b677eea2d5517d85e7664f3fcd55fe51476488f4ad0f6e04d90e70422bda3d3a8c665435824ff0b3f3c233845cb9b9d4b78bcf5f3948c0ab49cdf3787bca6c6fce6187f0254783f1d02d26c8039359b66bfc820a517e8d2066ce986029f989f31118329811728d8cad1ec03cd64a2a1bbee6a7a0a8496f63348cf75064a96254fc3c56d4ff300347f3ed897620f1e00a255ae5038589aa9dc7734364815a041f5f4af67d6ffceaeb26b9fe3cdd377e522d856a9dccd2e1ab1fd12464615696553e7a3b36b1a2f99a7694a0495d9298129c726dc4d0c2cc6b763ac233dfbb0c205a4edc24666b135a1e6e00035b76865bf7eca34a53ba758090dc5e5502bd3dd19e7dc445f7e7a85c37181cfb220356e2695a50210cc7d362a7730ff60c8ae625837c9fec523bc451da65ea082324d7528c3d2a3e4998c584e3993f19bac29ca19f3d3a1f662212f34853dcc2d1949788edd8bc6a7654ec8dbc4de84a9954edc24c7920547762f9deabeb9565a5cd7ec8c2ac3abf5e130726cbee0460ec60165f1359361571cb7e959c1b7e35cda3151ae813a45d2cd37547fc1c4c536f559b7ac663020aa44ce0313df5a0864b74976e5e0900488af2af496f1ba5d48e0e87163b782b06981c09ce86090d14a6d79226cd1d68ee752f0efa65bccad1c91fd724f58acd777f265657c8a525c4cf78e4b62f42e7ba396e33bca26195205f864052caaaa9c868cbe2d966fc6a29ebbbae02d15bc8208dc340fafb98c6f20e99a2299b106e2062d92b8fdb1e65c2f354b9a8bd911e7bdebe59bf41e96062c89fab0c667daec69a1a39f6839f366049e19445824262e9704e69f9f053c3ec3bb289ba1f358333dbeee6cea8a6c66df9403d3c91628b36f5d8c142de44ea702b88379d6fa4ad28d0ad1a5619dc73bc2257b4aa60be35c44082299f950c4147e0a9d9041f7fcae9858f9ad25a6de73b8ae6b87cc4db08887f2734294","dedup_hash":"74146165765493969290","tip_id_type":"personal","vp_signature":"650fd75cd1ea298e343b6b70ac5de278ea2c7150dc47ab900195ed69b53bc88bd7bf04ac533c92898e2a51dd63aaf8edd1dff836b2d2a48e1910ebe928bbfa6169953f59b71ad01f22e6ff047e164596046b2d8e824bfa4b8f5b7bef3f217aa68a50ed7c187f01ce781888a92d28aa38ccedc0fef6782faa06619dac3b26cc7c570d1a6aea447e20505f86afa2fd723d9715a639af79698458ca2f63cdab4f066670e85522c408af53dd2eff661d58fd8b2d54b3712cbbd9e8324f3e7fd734b628d896c0e1d5e6aaefc1f24d35ef1a718ce6d7444f418a2bc951c330ac4a4684f8862165446d5408053ed99ec5e491af4d291af5a9203cc2dccc891d714a5a46ed90f8be288aeb105970e2111695fadbf6978d46b6bab4006e98a569e14af91769a1e71785721d9a33caec9fd4d3a96c1e5cdf980079c5221a7698bc4cedd7da95cf1b64b3c56debe6cd56d135fe6a8637107921daed6716370fd4fcab035ff0eb1dcc1afe53f634cc015d661e73eb804ccfc03bc829ba2ffb9b7f14ebb3a0c1e4e399daa589fe4ceb476f9a5e00556e3977d5f6e64f16dad6b5e38b2004cf4eb77b19f96489612432df3101a84030b87cf862ee36e922f65ecef76e54b9b147118a8431fdb73b5f2bbf54087d3d275d86a8b49b01663ac67261bc612abe7fdde82c844c2956a1319da489c891c4ec21761729f31ff2f64c116e8befd618fa921e42642213b13249d93f8eb640371df03e8ed2731f90df54def46d8fa36298fc163bdaf19d3cfc1c5652f04205dba454cab657535d12734fcb1706683151d28f575fef13d001ce3ac10bef6c4811b68d1f5be61f37ee94537740cbe8466bc24a1d4f8b8fa48a491e7a9c1d53ce398f169738d639a511990fc8b5aa63ebf00eb7c7a9a892f4aa4026eda3b2f885960b7b82d654a659849a53b4fd3d00e2ff0c1fedf838dcc6f08e0589ce19db121ddf4df62327e16008356d3c3cc4b7d0d3dfaddfc1046d0b756faaf768f19b3f2df5208e83d7e18c00ac8a03ea638cd9a9e9e235267fccf64830d51b005f07f2dd2254529a5fd3bc72b7b9f8735ab655ebdf7cd230ff82c30f5377354daa37167435f4b8992453bcbc622a835bbbf4c0fb58f0cc50d17f7b3a49a23c6440f162aeda3144cd3287beef6dfbc5a286e11b4a94d95968a6be4caed6b1a4c18ef1e1e93dbcfeca4a525cd45d710ae756e364e98227b65eed5ae62f6f384582822d6ab37bcb69aedb3238ea31ad966b5143163e2d7865aee6fcfc5cdbe70102beb0876d343f610a19203c88f8458068e118953fc2bd97bcc84a582c422c8d49be9d57a34fff5341fe6b06f5fb53065d388e0f215cb3b4ec9a231dacf1a11246d04c6d795b7b519a2dded07e571eab2bf964e6c34aa934736df329b8201f184b9797b166782ec8c85bca954e706b43f9abaf3e7eeb8eac42145dd217d435fac279a430d9af239e8c99d111b45c2038037a5bc61bba41fa69f42b57a4d16438293f110c3131df77bfc7d52ccfdd28148d71032ed880dae9ff4abef813b07dcaf0fbdbc45ef43a5c3623e9af7fd4fcd5262a36bdb5f276287c65c4a3cfaa234d17b1f4e55cd8e3e7f6a5372abb5ac64aea85ecb2e2172d9c208ffeb19f4468757c71432757f883be5514168c48c2585f05b06356bdb37bba081724a5ebf6d58e735a17a7f814b9401d7cb9846f2e1eda1b27d0839a8328885cd349522f8103ddb7e6fceb860649c07d4c53a3ee6b0a75fe9f48412b0952ece0db98981106b76ee3d9536ee2c22e2ea97aede4eb080fd900351b645cb5df9a722b0b03111185368ab054004843740fa07cda8b4a6cf5455b37bb3c7a0a055429d24bd04d652edfba3cb54f45c2acad7946fd8bd92ffe3b4575142f5f5590b116bdeeb923b300b9b52e748a3e3c55ab8cceb5f4871ede98a97bb86c20fd8cea0d4ef67400ad95579e754a64015131a55a033b3c07209dcd09cf095739809aed546847db67d0b9f10029f8e837cc8ba4bfaf7a0ecf10aaabe95315787aff0049e88349ecd970d77cc20a9f297e72cb5ba9950c808c5d04958155e08edf7b37734aa8a8df2d58cd2bad2c27d0280134d804e330bd5e523172e811d3b3a8c31899caf7b9248e814a21a89626c975231120e3db59d24d18374c479489661b50dbb96ea6c5a93c77c6b151f454bd33155d05282f9b2d7353e538311d782d23106c3c3ef6d642387ba1485fed90da585e5b3d45e945e38c6d020d8e8dadb68e328ac6ed3f82fcee6580c4f5ed59ab6097680204c16e8e31c7b6d92d793842b910d2bd3cafbea0ce2e557da49745fca8f8ada87d69cfd1a37ea51d81d75ab24cead6925023bfbeb877efe4b8ac2779142e6e2f67288a02700ced1654112612c2bb967360b3c9355f87f5f89c804df2a3009923d9dd21116764e1ac486793e08e1dc3f26c37074d38da3e788bca284fa36d10441613069ccbf398a17c85a207d10d6c4bbf1fe916d5db2833efa40e62e4f9ce026518f38ba64cfbf545fd13a4528e4f5fef7eea2211d043488e0c2e61232d6c7c19daaf754d93f6147493f6c41bcfbfbb4a27d0e3b4fa4ae32eec67fdaaad416e9a2f9999930610cf5c07acf20b3a4cd6af761800e24d51fb3d751f46b10d4d97f3da1cdab4232a52b80c2099bcadc049455595be566dde70c225a1b4d5a590dcb4bf3e91174a9bc7dc573e723732c4612d098b25cae9235a67b0f0a4ce625175e6e4dd9cd1a8f17675c047511650aeef687000d3185ed83b64add7fa3fea1a1a34a6651ca1af217d6c192573a16ebab300a1c0c3085a8daee94ac6717a684d6213b04eff57ec5e2385be31177bea3bafd46b36ddb6be027b48364ebf118210f2686fbffab0ec75a465011788955b30b662b566318349012c9e1be75c01edd1440801059e66e03608631c49a3fb2a145cd8d343611335605867ecc53e2f88033983a96436fc0ec041dd9333d8f041ea29f05a20a51828151a2358c553db8aa1fa992e050b689cfb9d448f75412f050f4db1e673e3b713d72f044d009f7e7d1e1e3efe84c44522ff732707a2e3c1be4800975d6dd70661e3f32860704f4f050ce83d855a185bb1d3cfa8c6bad5d9374b384818b3235df280a04935d04e873451402de753c626dcd051b3fe3915f6231bb196d37d601fa5eea7e78f82c42d1b1a7b71b48a54bd2f5fbdf44077e2c24f15947eee994f8c9d78efcdc522534fd9d5d2c43aed88a01cd4951b14e940517e8a718c75acfc383bbc74a6c270d6d5c1dfccf174f168b231bdf2256f2bf3d55672b878ff3d3a93ee2867ae573da8cc4c589034b165c8ab40e9e953f2cc5e6d78278365b720d4976b267fcda812f2a0fdd6bb09fe923c6b00b5619facd85edac8c615d15dcb900359c6b69f84ca256f85592ee9c2baff1981ca506f9bbdecf68bbd35a45809d040d6971d1e46fe7c5f6f62e8b4c77db6649caa1f09f579a5d2f55ad5fec1595ed2fafca54617c859d1ca3a6bb58c1939df6071d99f2f567e1cca8baf0a00ccc605710fc26a7dbf631017f1db5966217598f4b9b6f995c0f9b35b525a809aca08fe4e829746a2ebb77ec024b72c41755da7b4f9ecccf0b318fd499f9ca7bcf1b2da565f196df90a1e72f067e14d6331b6c97a08baf11f8076703d87723ce5b143b2785cdfbcbc83b60dcf825e931cd456da85b12c9bf8f99e5252109a026141ff0b992e928b2e171a4b1f8aea40d610916007c82682dff62a098d093a3dfcf265f5ab6bf45f7e4b9fb70312e6df86f0844232bfbc498187970df4d3d4192de53dcbb2ab2c8d1f9e5ed3065e356da565ddc7b438e8bcd6607a5887cb6c658f650eb9cdb4e4fed5c772c2809694012b2711a1859755b8dab259c76cd25d88a8979f2047cbc7e945fb3c44ef0e9d6dc0b2b90607c32966e5182dfd888df506a5897607480a7d27dd814c4f44958cbce5f05de6feab40f27ebc79086521d2bea28178b66b81e7bd5dbb7f56d502b0ff4ffb660f16928544b24373a6c0380851f013e6b54408dca2eea4e3babab7bf01a16d8af4cf88c0189833bfcfd981286707ddae28df6b711b983797062c3ae9003781839007322bcde7494b6c881117198f6d2e60f16d06ff5db6ec2fe68ff7df51188ed2e8ae513243301e9c4ee3b8e41bbf6a21db429016bf9866c8788d48f81745ad9a68b7175b8e72c0d36c25472b43a1651630c0b71e50ccc1aa64c2e1061f693208a1e63348fc423afd4056a21759f1f306c1a9bc6843b11d774ddd160da3a7410e52ff12cd47386c672390b97f6f9a5466432d28de8b2c6550506681ef029ce04875f9d9b9a3ac250a0449900ee8d9ede35b5c1c4f1868b6e1abda6dc1de0e0bc74e853c7f0d906d08fb68f1c694cec914d491e910275266a24eaa7f4d4ed5b6966190e58cab52ce40116dbf9442cfa811068ed587ec3a85d68d7437a4be17dcb7a405987cbb94654c15ad76024b799e03bdc25945c9cbb7427b0d1295129b7145746aa431f1351e919c0a54d4c422caf8edbce0a36f866cf7de986825fa5e5d0a2e629c443b8ebea8d91d7e00fdd9a8fad9e8cdaa1c2919f5b3155053566a89b4b7c32da7fc0b205361af294d7ed4f005070e1c3c46a2cee4e8e98dad000000000000000000000000000000000000000000080b10152022"},{"tip_id":"tip://id/US-59ff599b8c138496","region":"US","public_key":"cf28c5cf46b2f82a9c4551ed410dfeafd6f879200f713eac2ddcad6b5c4241a33ecc226e6324c0b21f2492a004d05799ca038b329060b966f3c035abb679350c76fa74788e97c329c81b00234163fab5e88999c569b8158a93a26d17c116ff024db425aa4539892a4cac108eb7077f0b7c57e0fab6043c9c2b8988792fde8cce4fe54d0a05d37e2c2e657afbc95bdfa8cff1eb234463aabe9c3fa0a1b048b989d4a2b1a92e93f013e4bb6009756cc8eacfed2d2666894b042a690b3d71ea15fb5d208dcda9ae6370accd1a75fe45186673adac9afb38bf3f79f09fa6a72987765779e68791c50084d9425974bb75f12f2a840460b342695358e70bef71cdad8eae5d94dfa6b21fe87b0127e969fa13154e9964db65ab8b8adb0423e5d522b04479545cc247ab5e6f2cde6791584b7c99b7a6ab9f8d868dc946e566f51c9de7967fff322f53ec59a92951b8bebd135bb0f9950bdfc04847d95d11c248dcaa1331b6200c1d4cd78365cd8b5a1c027a0a437264cd5bbce88f10c1d88cd20ce0acdf77668b188a98e58a9e1f26fdae18e0bb4b7d5935a0618590545f76fd30ae173330499f38365a85ecdb391ba4452e5022cbbf90186fbb8f7cc622acf5ba50648dfe813c5512aa6445ca22bc3fd91e20b53d49a1db73c4198c9e5c14e2c235792fad27d0763fb357b61fb2643f92dcd4024a199bd47dec7c99c92cb9da567083158a9ac1b845db1e0a2e17efd5fd8f6f640638c83ecbb6010bbd91f814e276c4d05c30e059fb1b51f59758105d4fa23e060c9fea7f670afbfa49f6f3381efc09543fe953a83f178130fd4f3f9ea9ecfc5748a00d10cdd61d5ae2c171c7c6caf36c28aeebfb8fbe9e5e31d4dc0c9deb6bc207547381053e40ea3ac55d687b6f0665b3b6a521aa8f0d054cccdf182b52c4672827d43a27452298719d2dbb674433ded4bd037a6ca591324e74fbba096214457f3cfab2426cacad808bc5ac7c839cdebc66ed8525e8367d5c50d9df475a60693db39d6aa5100f48f58228611e7ec953a1ed7d4438b48492e29a80972f26794d3ff966bf838507492402d61c4ec12712b73ddb495ae6bd8ae5139fa61ae3e5050460c67aa17475a2aa6834d1962530f83e09ee4d2daac9da255f45ce9a9cb7e49e2c60919b04f374924350b8bd1e67d360fde5981696645011778771cdbf4582b275943f1b615a795dec8ab4b9e932e79395d6bc631dbfa07ea758858ac22aba78494cc567f3d4ae0c5f68b83a47aacb7685a376bcf34c14ddcb0aacb712defdc6de0397518d542df0da9eaf37841447b453a5cb4647dcf08316377d42d8298fa25c55a3aab9c45d38b513db682759ba5738ba4204f32c90c7bc6afde238e4588790786b7c4be411ca522cb4377b32ffaaf9c3ec17eea15b252f51ca14981b041dc66de3f290273e3fbe5412b9352b283e36be47d473b0d00a317831221fd58afc03bd0ff72c5e3b5bc1d7a938ea0d5c3431e2f62bc97d63a2fda3688bf3f19c693e8c768d491e90e6ab7e5e518d9df5d0c6ec949e264632aa61e253f7090bb1d0098ecb739dfcf4e124bd598f10e46adea87833d9ca95c0edf44f4e8a3cd09216fd813ec3be8c152c79f83987f6d6a2720cca2ad0f4c5d21056ad7018b71ed1106ccff829cbe03a50a517f40ef1b751aead98b06a3c2151d3c6b1ff873725ab4914a3445cef0559bd2f3616a77a5f21dd4e53390684910e1292db016349538523cb024043d41f6a13282d9618ad54bb9488c43d357a78d7961356d134ccd3bd9b7ce349c326a80bb431038cefcd4fc48302de18dbb2820a28a89a432381b1cf948d3942f62e6ccd63e7d99436eb9482ed52fce5b11df9d6ee0645104c9a71f3c2f3ec257151af0f6eba2685fcc2199ae8cfef19ad3fbca55bceb861ddd6e456fce3c1b69728bfdda0b9fc7adfa6280eefd5a39ef6aa39f5495149c5fbe549556f29ef6d689be52004da4b5b8416e875158aebcd702e4646c60d56285c5e6d549ee89697cd6444f21bfa4a058292628916e1a6fbad4417f6a6a23dfd52256f51d1133d9caa93ace191d69667658301e01e03876163d737ab07751368332640bf327f0e1a34a93cb2f1db93d8a664923560bfa1bb989c00e9fa8e11458b5e1fbfb0c57c47a9e1797f32b277331bde1bce51835623d3466cd30771f4f4aada99ceec27a34b92b527689ba141d95d6776017de9cd0122802256ad81b487dd43c2606af4e2e995624252200194430bdd23f2a68cc93b7a67f41d5433377584d32b7de769abb9ea9b8b3600447368c89745d56ee97ea041cea902b5900a19d8681abcc9aeceac9da91309dadc121840bef6f292a874402b0d23835859d149260a80197f2bd8290ad9c6cf0f1ea9b622befb8decf63e9fd235d55febd493beac82adfb3e2f6eccc4adb3fbf419525acf36fd503a4ba46187b125c08413e303a11f7b59ea191eae43b4c791325b2ed991bcd7ab7c5c360098f6b5ca8a84938c174a85a451b7adf69fb55e65e69a7971ff9daa9c5b9fdd6c4086de8568dc28153406f11ba7478d1bc2b12e8995706982f3e841b9aa2740ca96a8872c53f02f4c8c5eaae5238166fe4bb8a4882d5af33b699baf9504c9f1bdab66a5254cb21b77404018c8ba55324f2c2268921ffd50796c7f353f5deb60e21763000181deed4ea982393be04cce74c2602d5c772603163485a5681d936ccb8cd79ec105387fbc1a0573c47ae7d358dfa651e0b206fdd1fe8cbe27","dedup_hash":"70044443154882484498","tip_id_type":"personal","vp_signature":"088c30cbe72087719d07b9a1f5a5145c51b40698e18e887caffd46096ce45073a14357d3a15c6971650411d71fcae7240970ce750369218f650f9ae0d44a550032580d360d216249108d504d31486674f812d89ce2008cc2d039f9d8c98c6703b749ae36303ea1283190da04c6926985f8ba0eaea2220ccecd470279dd242ee3c7c26918bb8c9978721a787b96d8108fc0a8e7b0eb9550332c9f5eb796f07a5bba59280e853a9bb67e5baa148059a0e2b6ad83d3c49f7cc469075e0c282d7910e685bddd7609aba0ba95a1ef788a35e53e2fbebefaee3c8ea9e1a485a3326dad85b6311a4175cde4a1e6045cf0b7b49eb8d15b25172ac6b7744447c440a0e22644248424071806c7d3e39f114c957f2984a44c68da8342f0fc644c6ae85cd657cbb49a3e017c0f4b290271f2ff295290096ca16ea3e16ff87013dc8f1aa9aacb51e9078d04ef6c3b5e387ac53acb98ba988f2eea2423e1c493242d78133096ef735eaf748a909d04b6232340fb2ca81d139fcc722b311ac20e0de2d9e7470384435e360fea3a2c4ed24c279b15b9a70297a9639d89cd5863a81ef9249898dcee309f974e47d4c265cc4e92638f8fb10ec253ef69ec58d059093696f9431c83318da8ce696f42243c86344bd5599e77c2df6bc8e390a6ecf8a827cbf06706d992468c03f39215b40ef07e5ec196f0f4c1ddb64bfad9b0f70592d1cd557a72d9cb9a87451afe1f76e5544a1abc9bccfa093f60688292116e6dc35cfff5f04b1c791d00a38405f143d05bac56f5081495dada5ab077ddce30bbf05b943e429e2654e6b415295345cf93e0817438b6d0d27021a7b37a47c83d057b4459ae4cae18610df2a8bff50bf85eeee6c388a8edc89c402c3e80a604936b21441ebabe3559d0cbb22d764d16a54ea93cca749ccc23280de565ce2f38bcdd77fda53def60916077f00c6fb4a645fd5f333fedc6d1a02febb36dbeba22c373cd6e9d940abfdebb4dff4d1b934cc1cf841c8a18cb2a22f0b9864fad6a731957326846eb2168691ebb572119c79f832fba644a4f442dd96799be5f39f77db22365d27ca9ed6e6607faa7914dff4b5316053c15447537fec79d86e72ad50e5834f45abc63cab9eaff1273ad189f47c132ad4da5118342b6770035d832b94fce04714f37df63485b437f0ed0eaa1d2ce3b5ace1de1f7b48a0f54710af176ada5e9409afe4388394ee014b7879825e972e8b7161a84767df4ac5ec0abe838801075a448a0778fde72a68f1fedf01fa52efafb952eb0c332762b55465a06715a6cbd01e0054d6e2b8af3aff0b11a5a190b377a6747fa232287a6014a3e0e40041bda73fd1ea5452ac07d4168db813769f4f3bc485d0a606508272d929303011aaaedf17241843c2b701449dc374055c54390055698302ee5a54bf112ae749add39061c4f33946c9a02305c54315f0231740d1016917ac667aaa6bbf7b4a94db0c350ea71f16f89b8a14ce4eb9755e6d8f3a5f67e4d476ee24369a03911b65bf8892c6d3f390a32867f638fde4de5fefcc72545e52cde036faa47182a1f28e5856b52b1c86ce6c5867acbfd7562d36274ac9e2987eee377bb4c76f90cbd83bfbc2a1ace2f9bb032fff7fc45bd6d803f2083c13dcc2e7c7bbb028610839fbac3fbfdd8d47e594a600d5122db440188a52f4b123dc4608f9adcbb2bdbb6eb2c469ae70c9ae738a53f34194f79ef1454eef72364f36ce08a483b661bc7c66037d75493f0f1fea4ac0ec2828aae757eb5bc61f1e10212657f95ffbfd33e1c2fa1c8fdae6a82caff2b65bea4844cacd020af11e5fb35669c1154ba9a80f0f9bbf49f43ff5934c9055bb018c348febcf8942c734da1ac29780fd0cb31f0e1f8093a2d0f68a85c3a30025b27be23ef0ccfa9d950e41fd37810d0e40237b50d9f28a89aeb53bd6c6705e691cd3b094a7a2b84f8b92ecb7630f22a2a4da3e8c581fc66297d9b0efb642f4f2a48fa112b9bacd61a1007fc1bc326eb18f79efda8815dcdf4656db3954c77c642ee0c18b39bb57d9abfebe6d780377cfee2096637201ad3fbdc678a28b8b0c8e5a57d12ac617d16ba24bebb96fa60609383b3ea0845d13ae52c3ec2f2931ddc0622f9fd9cce274c612667f2e6ddf6e8d020f0f99e18946e7e73e286ff38b45bfcae857071d003cdbe1754ff4fe3c7b67e4ebaa294d0c3acdb05a6e4b00ad485daf38ed5adad1c40d97187a49a0496108e9559a8ac148934e2971b3823fdf067df95020d38f16151e4765f0a65e50fe21b5a707d766bb730a97db72e0ff2a1b55d2bbec556226123f6ed8c388dfc55e6b96edb0638746164d4b30f0b249130b830f2d701936b4e7028119b753c68e5dc42eb34a52597382395fdc97c24311afe0731a179d6c569b1b86be63cb11e3d3d71664103e8a6c14a93667471fc3c7d1963a6b46656959e91d996ba30e54d35b49f04feef7b4aad522371d6a0b35052b7c0b1c5b1ecae1fa65c5d2e6d653324a2a9fcbe86c0156b220652b2bd0e741e49ea2faa64f26284050b2066317bab15ea07190b6702302994e65fa574339566b5c37fd1a2411cff9ea9ad55551cf38c2733f5a163da07e3339b6abc0983fea0f528a257bfdb233f9db67eaadc9a01bd873aa130dd9a1165ff84ee211af7fed50e9ea4124d16453ec47c487c9f02dfd1523434208c7ec34c97fd2e4731081e1beccd3e80e259e5ea7185a58485b02398e06ee24c57bf80b4b3f37cb83fa4e31795af78de160bd2399f3d82c8931da78c76e7bf5809303351057c4392e79a14a16211d2ae2444dd65a58b10e7775bea1c5aa25ba5cb0c02bbd37bec2fd71079d8319a568ab44bad8c334a361852652c00790869ef8c7b139f4571452032aed5a8d3ee59c67985c084275e4aa7c9357454d7c47cac57a06f5b96a0e05c79f904bf45e42ffded4319565ea1a24f74b1f55c02678f30c1a1a76398b3a9f6ee1b154ee0c9dd063660791b433484d2210fdba662babafca23137bc158fa37a14b23496fbfd594259057ed223c3de75b118bdd5d4abc544e8b9b822eb54229297655652152a31bb5c47292639a466763c72068bb325695288d437696656655aeabfecf73bfed5480763fa2ee0f987e5e7d1221b7c24b663bdbbfc2e40188d1b84c074cef140583a56c369546e1454b81f254e86f5d7d35cbc2a9a5a9a1eb9c647ac2ceaf0b6d8f3dfeaea557ecfb572c6f485306a1c445438ce956d365c5aa2b8b547dd31101e75b950c9e68ea90f24b7994189ca975a5b013e5e0a44f131e19e1c7405890c862a4d8e28a8511cf32075e535649ca53960686ca82dcee659196fb503a5f5cb9b614dca4a5d3d325c83dd6f547fe5ff1936e8e1397dd7df24603f7e2f3cfed761de9daa6fe4b5b26f85da2b3af29c742ce8820078a0e1e8e334f780b99faee5595edf7e835b0a39841cf46b7b6bb69fe87c5023d9e88ee7595aca0b5a572c3bacf79c49f229c7cc31e198ca1ce9de32a96a5934f4913b345304254cd89a6facb37346814131f6c2f716a93bae34c450c26dde1c6d8010de53b5d63068c28297b9e764aa531464dfa916ef36ccfa2d05ce3ddfc9833b474816afbfc7e09e362e9e088b870c1bdbd728fe475e3e79698f2dcd9875424a805f3ae8fc2ae5847618de954669aba54e39c16b4853863ab403f60953755fbbaa149ef5e17e35e8d02b875b27a5d5e67585b327cc7415c7263681f673eefcbd74be9c60186c8ee96e240685d679ecda852d3029c601369cb013f46f2fd563bdb865ebb4c02a49d221500a18fef757db66442523a2c88d8a23ca3a8f74f22c1fb93a542ed802f47c2e60425290e08945e2d5cf4dff6ff26566b190006d1a471e10ed01fe768043e08df98125b9329c1f598f032eafc67b8f6eb0aba32b1fa0e9a4d45847dca6e27c3043982166f9d05813da6e8a416c5278a1e98225690d5b41656940cbad504ef4ff242c582f1615962db8ca3c94599e1659e2e9d2ad47485849c6b651518a5a193161d54aa55ad0b69406774e00e284ed0bfbc3e042ec1dd38ff6dfa4d0c010f11fed22c38f7afb0b85cea02cd30c8b079652f06edf6921c3cafa277dce2d549838589cc95d75e98fbf1fad6194936bb3d3d2db782b0f3b92b7084929e1b0f650d1fc68862e0d480c97745a1edb3b53afcf0150946845b3733cffe385ae11c383de9f1f98d5e6acc0db6144c12ac5bb8277903059c4dfbf9eef8c62daba3e86fe3cf1f512aba2df809128af51f14615d641d3af2a4e9ba9ab1bd00ae3d8452b53d67bdebc19377d799347be1a7cc7778fa07627f3348fb76bb62d61a5a339bedfbc686ef60818e8f6c1ac83602ac8917097d5ad70d41d0c274d434a3e0dbe62d9dc38e82e1d442dd457751b7b49f431f411c7499ec434e225afe964b3b8e22ece07dcc76bf6fff7666f7a6e44351776ec7650570ab785687b9fcfd68e45a67a8a998b6fddcd5033df21a22c55789cc02cb170196f0a05ebb16f72f1e9a15d55b10dec2177d5ebd2801f3a0f5dac528f70706f3acdfc0724b7e6198185ac8fcf21d388285727e99aa295b476afb376aa89c7d0d8ae8905151a1e286571b31f61626dacfe131d454fcc9d9eade0f3fb6168b6bac3c9dadceef2ff4f535896000000000000000000000000000000080e13192428"}],     // [{ tip_id, region, public_key, dedup_hash, vp_signature }] — embedded by seed
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
let GENESIS_TX_SIGNATURE = "dd4b38387872a7b346f2214d57c741a9ca09a273c230fe4cec2684039bd153f66f30a6c6712fb9ba40c638199db133aa7559cfb48b7530e3b350cce61047f60ec17218d2ae13bee2ee75e305c76048af38205bb0009d76bd87f465834918111e8d3ad95f067ba18fbe4181a6d677b650cfea6f3546ac2e90e418b5e60f781a9957a9b96e43f5ee065ca27de94ad2d3cad8b22b6cc60e17a4abc41f685aaae39933cfe501b3655baf42585be9dd00c3b1ecf1da08c10c6def1f605a31d52d9ea28d10d619bd8096d05503a5883ebe7467bf3f7775043ebd0f2508b442d2ca7877cd19bde8b3d17867c82f1058adfe740c2c7b962d58ddfe39e3481884525b6aec3626209090d9cf031979eaf12a963862c2527ae505f9854b5ae96bc03eaf599c2b3209e59079bf995b6d211930a0c9476f0469b6b1c1913c0ee230db0cc3738420079968564073868981889b6cbbadc64fecc1e96cfabe97739b5248b78a111d0b5b4b8c3b8d4b923bcd7ad654add625538f0e567f0c4583826928853168076f7eb0f7b08cd393348e21fc9f699e318cef1d2b646565b14226a032fae9312de84cfddf059e94696ac94239f875c24d48c7f5fa69e1a2bb8fae57c5d19218ba409748b602964d093cb9ba7832585bf55d225b2db89c7130987875a2dde7629ba8601337ee02144269ec111639754c4ee963e3436ac2b97852b3fee497f5eba2e253e079cc92d7c13bc703344f1e4001e3e602171c8431af432d121e70348716e09ad77d031978a7825bb96cd6aef43fdc438a32f201d15bd0f9c48962abcc20266cf61512a1e6edca352b447a48bb6ad31171b5f311f3e84e8b8d1646ec5c49f91705f757c4916537666ae3ae1974fdd39dbead5a5332c83e988d8146f7e71c430895d37dd6afa13cc7f8061fbd041360c7773af98a0ffad06b2e60ac90644f110fa665b7826506a1f4c0cf30dcc02c1c06facac886b92f27cb3fa98715e416bd8f2198de0e484587f89cc77b405e3e3e5b854c6c4fcb9a6556472ecafdd2faf537e652b82850e9bfd597ed4efefbf60149544a0aa32f9cb8b845b855e69461288e86ddb4599d64823c10c8766fc433a6e8cf1e6560faffc19061d2319574c3acb0157938aaa7727261a7627c137594a51ae6309f0fb2139144a44a9294828d5d825689e847f67e2b0d60da9d8cdec28a62d91848a061df3ae33d6842b85450307a2e4445980d53a4ef3150c811aa993847f5906f88ca7603b4251790fe5b6eee4b9f4119177605b4036aa1ad75b83895983cc4ba6761aed6a303b6e6d4d2fc0efb8a69eb4b40fd0ed3f68fe994760c04a336d189c5965fccfa436f86806fea95187a39d171414f70ac8faf7bca24a89f69ffdc23c786e95615de1a4f3e7bff616527a3ddd0fe8296c0f248c074b376b2deecd6fee022d9921b1655b2929d27c2ebf5d35757c1bc15bd32fac80c056cab3a639b0c15313452af9b7aaedeebf9a8a23b994233d305cc4d4ee1e39b86a3fa04d63ce13f03b2846f863beeeeb21646607bc7f627516eb105f05260430d138856a57e4018a9b0e6f5ebd9da12f036df50ed12782cd0e138a0946f88ba0bae0bc19886c349ba79c142431b8a4be5b1212b452873d1e6698aa74dd1e74b140c1f1e93491e54410706e34098573c2f0db35325ac2290f93b1d57fde33334e87d2b3cf1836113b6014ab1c2f96ae7aafa1f07aa77c610c8ecb8b4d6aceec43782e35ab243ac72e840e127e5f67b0f5421d9903e0fc1ce813e0a24feabef5e95f02267d9ee9a07ce6b3a20e946155708a628c5f390186bda462373fd9fd0722674dd7fb96a5cefbb173d26ea535fee2b2a904c45bfacb4039b690114da59dae36eea32d34015768631cff809960157deb122b2a26a2b20c621107f09f2edbf50cf924406b3589511665a965da48fe97dec19e3fe04369023417a5f937c927d351e5ffaa852b87956b9b3565e19a32277868663212f12d9057b7ea51ebb7c2bb9eb926365f54efc88bc7f4f662494477463af7e10855810f4b1633edf105fb7bedd9d4334ccc2e717b8358468ad934b7c4c376a1091798dc55b23cdf2b1962e55d37bef7d4ef056f680ded0f767326f78897540261f7afa358de50b17e85471484bdecc5b82a3c1ac18726b77e0ff4008cf3820cff1c1e22a288fd16cb7821ebec334a075d3ee16d07af81e8e43fe6581c4a2a028e4e727853b9650651f387823f9eb003328a2bbab74de577aee29e7ea0251248a1bb2217254b068ed7b45501286a6ca4c8f9ccbf78e2a9d59d5a74f6da3e88e1a2a462c7c38db357b6ddbf76213636c23f9c60f75bf3e0c9d8b0f8ad8466d6a4ac492e4e5de64433dc43dd7276955e71a0aa6709df5b5229a84b1925d0779efdac39f2ac20dd28c182949b85aee5772aff314d8daed754cd463513e5af7e5a9ebf3974dea635c974cb2e5bf84530ae9d8d8208e8a663586c63d53c8ea1b5b467928d7142eceea6ee5e8d0080568aaadf37e38844e2856e89267368b59270064bc7b253f57de3ee8e541d4f81dd6d12c0b3d0d2f0ebc7f747ca2624bbc936f46fddd4c4c061c423000a8f4e535298313c8288791b3ebce714cbcf6ac3f7333b350084720a78498df8e82f639417d36a3d9c43d5f396bbf6ae53b0ded3d180d8e874024327e39643f108bbb1909b6e82cc82b3863131519ab1868893dcf27fdea8344175b530d9082e514a6cfbdaa8f16e17a73ca5d8029bc0709b3246d45e83d65df7e3227a7cf7a7f187c1992bccb4525f6e5ea4dc8682c9deccce0e670573d9181f32a481e42cb2a13947f9596dc9c33a11ec94328f60f78e3ddfe1bce6b04293ffaa4bcb20cc493fcc204ee213719b737f28d394dd6db1640fb1e84d9111ed5b98ed19ad6561fe820ce23dd537621acb8a30cb7a9e48b97639bac16a904d4cdecb18cb5a4556de81bb5ea3ad1e69cb480085b58eb7c15939ccebefd9b55a4a708349cc882f06d3d909d18244ef0470c51fb17abb431ec86320bbbce7160463e9b29feadd6dd1a4caf6cdb79aa7633bd9edc443ee0027ed274e721355a432dab0d3522f12505a01eacd9cd31135a1e2574a86071860595bd88fd0b16883a8fb9cdf666cb6fdbcf7542f2525cc266a5eb62eb0d341321fe49e34432904c735885a93761a71e20b50887b583bdf430896f495778fb841e258de8ed59c68c1afbbf56b6d12d53808fc1852ec17f7aee65d73ba29e76c72c95f9544b84b299fc0de4a04b5b682c51a11ddbf092d33fa418ba8f07f4a011ab0d5aa1d25c61da015dc643e06d9940032071431cb7fe1c7f5326440c54f813fdcfed2ef1d1be54bba7b0d14ed3e1254f6be2e9423f32c54fd22eeecfb5a8019411a3393381becd913adec11c03ab74190393c3f9ce4376ec0b9761d92155470783b6fa94640541129335ad56c229fcddecc8fdbbace49a3eb07a459a2dff9e6b6d434f1feb933cb29d20947ae5418889bb1f475e47934e09d8a2ef61476de7ecc8a4fddc6ba8af08b9a3a0e8528861764d35f933853d992e7184b43b01dd0fafc06b117d2f7c4fbd483f24e9751e4d5da714c63b2d33f03618682a6adb41a4e702746fa8d240679c31999865d982a8b63a6af1a17edb4d5d3f0cbacf11839bcd99642742cb879648d6902ea0b9bdb48257b1d8557849213d4f15c37826d284fb1de41a16a1b8e2ea2b21355313d9fde8b490d4c1c3503584e7b6ae258023e9e7a2abe9999962a2a1771d2dbe77724d9c25337f0b711ba58c6e00565db97c95efd7132a179b7db8a3aa85536ab40f9fba5724366a68a84c24fd8c096d425a0237df6bc1f8c6b24223f70d92ae539053b9e7a56bf0ea531989ffdc173a61779c57f7dc4e97f8706bc99fa247345fbd512366224e3c1249aadde36f79d668e026d6f2ba2f77555261e9394effde9c121e98bc0bdeb679f519131d6e4e9c80201453b048d28990c8296c1dbb29545570e31feaa79512b184350fe819bb36557fca515de3bfb221c9e4eec926518da89bdb23c8d51e109d0c4c888779bbf66e620148aa3ce3d77dffc0797810cf91a8247080414f6c173af97e70c8f89c06ec1049ccd9e31cbf859029ae3e8dcb94b2b72f8b27d3f6a7b1ed732551ff0537e9b5d8cf366137deab38fcb1ae6eb1a9e29846adb554fe4580c323bc27772fd388214098de0a7202208de4fec1275f12d806e1227214699c2c143f0b13387d8cb5086baf7abd0c708e7a56da50e99e7ec0ca7c828cbf670f7803456f5bb320e04a13dda094d358726a8a9faa1dc1a637f21c7ec9c8119788614b49e1c4824dabf404c5cbbc8c308e272a41946efc402be1c6b4b7c8500b5b90828c88cbe32e7e7a48065e33fb194a674532fb932de318aede9957a0e199aa9c57865af52036d21d5c3a177f3984b6d89d0dc2fd8e22ee5599df5ceba22b177554440c4d95ddd2ffede4ef278a5e12b7a569c3cf3fd534c4425e632c7367c445679d288038c975082e534942cb20f30585aa4f7efa86cc94f67a065ac7e1dfe5df60cde753828fcf554cda5310d7a6dc0a635bdf4e397c2a27cf3269e967dcaf9ad5b81d6f88c5fa0f41556672859099d0d128505d64a5a8b1c5e52b9ec6e0f433415cbfe4eb144454d9f9000000000000000000000000000000050f181d2328";
let GENESIS_VP_TX_SIGNATURE = "f9e0a714d461de63eb3caee732d37e6eeaa70d768ed288673d650b44c3cfab17bf90075f0797d6f034e19e0edd101de13d4889e6bb3dd5a05568673b45c93c94c9365e00895abee6ff90decc5fb405a43243260df3b8744de1285c7d9de4d69fd5e8f3cb62eadf21fd92d5bdd63658d5946ba933318570f40b84f7bcc18ce10ffc87f1c6e95ce96612c9fcf87660e33b08aed1439bf2d1eb83fb409172bde7ad240256f96e0d617ad7450f6a204b2064956a2e3ae058ff8147d5f7b2489ec36babe54eb894861e5a98f1c5cceb2dcffeb3d4d20bc1d60310dd761a45240e522e23227570299f1ec52a2607af9f8f57f2f1ee1ff15e1c89d4eefe32cb6028eea1c3045d810bf39f43699480f7466a5174825685f9befbff660285bc12a304e46a707e0894e3a509b40285889fb47d817b657599c91527fb8b7ecc052d774449d2725f3f35c9be6068202a4295c78c37d4bdb2b3e8465972c944b76918ba775ffb18a527ae504a0e8a01d932868f235f8b627d4d636a88ce318951c080e238a409ec1f8791c9c6370a28e62a91690f29fc41ec102b0439e581343b0f77dc57bdd7f8b120aa81e7e5d18fe41291b1e3b8211a4542e48bba6d2e5978e9bbb21997c526e0f478905dafdea3dd48c152574e22218aaea87100d60f8889253acef1fdabbe64b8cbe3018feb843624ed7ed08b75e35c05ccea96c5137865d713e811ed8be5eab4f20eac03d919f8c5fe1ad2c978ef6e4a5b6541f7c7df846635656ce710c768aae1066be58ecdf97ac76039c085061d146453d2baeb1121d9c07afed672bc1c47cd61388924ce2248f53bd5cd22051300c9917c08878f1da0f88749467b819868c5360bb99b8d063d0022ebc78bc502f8bdba44e44cf08a4f9811f1cd44d5e1945b82858492152a557abecb34a82932b21032d1343e5a96b1bfaae67e00192268ba307749b5c5d0c32854b15df66a951d1b403160ae7964aef21f695e81b591dfd096b9ad0df68f1356a82db7084a0cb294e5cda2667945da37910499942bdd15549a4740ad3c8806d3cd48ab325170e10d882fce268d0a644b7824ada744a50ea24889c40f9bcfa417624e60dcedb19e2ead987c3dd3d4f178949455b378f1fe088f42920991899f98e3bd1b2743d85d8a8f60b7fe3a719c22b4d5641f01e4c7b8dfd9d3b6d9e7697c60522f7c34d7c834c606a0df7bd24d2269c59787d5ccd54a96edbe6b683aa544b3b28b9ed3eb12a5267df337adc7b4dfb5793b2de514e1079c9ff1e333680e5cd4fa419499ac7e652a30d2d74a84dcdbfea8f5c90af0c6e3d825a1266f04b96ea4a8ab0f5ccb1287656a5e81d1fc3276fd4b5ed653952ee069d79d6f470f8228c7eb559124fd6468d680ce38f7c841f73446bab3a7687e810ce75101c35fce7fea4e818d56d38402e5c588fbdc94b56538670ddb90fc43369dd8afc58dee06b0205aa2ab1e2a336f1eb63b719591da917f7462dcb6369f0ce4c97bbb7590742109b028cfb18880792f40d7d2c2658f1d76bb3aea108b8bd1581ae2743adf0dc3ec382c30417ec90cf78d01c7054d998482c29681f25bd50cca3d663340018ca0e6e3c52c54ff9907a6fc76e17b80fe608bcee5aa88dc2e1aa4423a0c89bf926842424766e4a5bb1a1bde25ea829997e115430e3a9db99ef07a2b84bb0256dd3bbcae4339891f2d1efc21f30c7b8cbd531d24e5b4f7747f5d7cce399260cc2955c6fcd16236a48edf561b7889a32459c86f420ffd8df24a66e97bfb280d421b0debd2abb0733c36fa40ce1693696f06f63dcd020a9fb3248b2163f4c05b359445aca56ddc16317b8b66bca2f6d66f463e5624c519d71023a9922e0e591d45e268d8e2f2e4b21725f4b4df6f213d502843f08d7de555e786409a0aabfacc424197cd6ce73d5dba1f4a7d795c18ed19f3f20df651d6132e8f3d0c0f89501da5c3dabf50bbe9102194b8c69125329b1c4a51cf19b3a1b5985e8d57c4550285ceebf7c9ccaf7c383fc3df9ed98fdae30955ab4910927b5440f7f64d23a0a178c898c2b832985a6c3141bf04f45bd4d5acda63398f3fe81a1b926008bc11c12478742cffecb1d9412be875f1a0ee174652e86d1fa66585730c4f50bd59a6ac0af53feeb180f9cfe26adb4059f3789bc5bf3f4fb7d00a58dbba3e24ecf3f44de545fee7774b2e48312eb8d9a8d84fc312d3af3bde042e96878e410e6cd795a36804c85385b069ae7557d878e17796889c95ee71266cf68466e1b5d54b1ff47d822bf2e048a66a311de0f947466902dd0d46ab97845485c6fe965aa61b0a851ab04fea5ce855d426d3b3c7a6a3723319245bc43f724c46877e9ad42e7a5b82438527e0220d73e03fc063c4cbd445469a433b2c994cccf5298135f7d8b460297fd8cd2c350149dd251d603c70d06f5508d0bfde8e428cd67c8ebb491c76a1cb0fb8e6f281126f803a7605fbe136d6d6d4e55b6c7843b43cae46607221a00b7dba9d80e40b9b306e6c0b6f684b496174a555c75f6cd26adb72c6a9c713d5cc54d7820f8dc1188e3042d396f3137f9751c4826e0ae7661a739ee3e2f6c19c6db2ed97fd77b8e808193af996ba121271993b6508e4176938ff9f097c1961b0f3736cef83c0cf781af8663dba9e6ae2c9c78f4e98ec899538e52bf1f5515789f31f140052b249a74f51604a5a0d265011ee67e05aac94e279c3e57f2e0d1e7fe6414dacfc7620129f233c7270087fd89cfef146f738f705b851da4111960ec5b8a60b2f950fdbbc80bf9408634c82c8431f2151b65eeb8131cf7327d5632926e34b64ca34140fc2a5b01209af64df309bc5cbab985219c45620382efb09aa6d6f8717248f7187961a8fa9404026188b793ceb51bebfc4cff725774ad04e60c07c5f8dbc470a995948754224969410276f019645a9634b1e4cc3ef27cdaaa8aa367e26f662de8383b1eabc8c1487c92a97e272645947673ca39735e6bd8d3f8a3fafc056991cb5cef2a9360a752325fd329fc13b924d13c3befe660be44d855e5ef627ee0de916f6bce706fa77113167af0e1f10feed7cfe7ee8effcdf448b4bb1f2e0454c4c2c91ec88bf75f121c25b3b644b5615e709e4db201409cee503716ee0015414964f4bf93c7683cb3d9712864d1b8cf4ed3bb0db2793e83c7d82bd04b8604d6dab41c49dc35a160cb49c39f9f6e8475f39faec19b10930af8823d4240cc623776dd8cd4891fdf154a44f1f41f3f6b59fd7f50c72cf0df111ac4c1b964511383731e56ec9150a2af50ba87b4c16bd37bcfab5486c3d29e822b79112578dc90f630cd280437a9fa4951f207e4ab97870b2bb7bf9c34e9d6dc28129e01b992dd38955eab1fc8704c23817ccd777bb399c04945efe32ff566416c7ee184acf55db3bae82868c47f52be5a068c5edea1b6e3f6f9c6615b4fef05b1d4c808214e15a2a124fd48cc08ae6d5cac5ba1de362fb3ad65a2297d13c85f3cfaafec09ee8cc9f925171cf6bc6007fcb4d857b747da8426483ea6d8b123a8a9c0f9d68f5bba2492785e7672f3b7eb942b0d65ffdfef838560ca373d9bbb4d1ca00b6c8100df030ffaa0a42c1535428c84f24e1a2a1f276f4d6056c66b5bcb6a0b89ad26427328fbf11426b40967a3a643c0a1c7cc0c749f0d1aa27c276d6f7d1516a8068e2902635002815d83e6ae04a05d081c306b263152b730996d6f1f7f4dfaf8ce6fe9492dfb677b0172d6559617a28eb29999c4aec46751e95b1e55304e001442e132ce49c8a8e0321f918a495289b80a5e18b83335a032d260291a461e37b7f33dda53d8deb0edb6c6266fe71a580d82d25f450a765989f575c2ea70b9b14c2add5e2422da4a9dde7c0b7de36074ec8e66fa8ec7bccfb66f0e0eedf4569e1a8bcc6b2903fb26cd90608fb116b244597016567675fe9b08eb2d235ff17bdd95f755f907c13389aa183f5d8922e159aace3fe31fabb1fea81ca02d49e4b4d3cb32bd0e041a5c8372f4609c9ef8170bea5f521964791e98a07a06ffdda98e3532c8a1c3d3bae5996726ed59117dad353f1e3ad7e2703ffd2d4982db7b655d81c44c5e6b297d3725ae33d1e436fe1f45b7912556602b2ab589e2367e5e10365d0b8d403b1dca9d628daabaf8a5e3a426a2df8f1938ebb2b766ca3614b06e27709d8fa362910a2c64e038aa4a59f1accf9c2092cd5e21b124c52402b818dbb6879c0ef50b8a979824e09665d7fd59456a99dceeb81b846511b336f9ddcf61aa097c8bf530503aa05b9f904f561d2e504f71bfe4d623ae52bc9135071559091eba907a0fbfe57d2e3cd4a247d72b1b4a55e376c1803bbe80a1128865d238434603d7ae760e238f52729210aaa698b8d1893b5b190357d353ad13fc52cc8fe658f20c2c33fe5d04ed1a30be0dbd9e6346ec6340141d45b585b1573c2b2cf41c27fa998aa0feb81608aa723c6d759c55186479c94113f5c49fad633f360d2500fd8bbd82786c0a39ab58f7b4e7ad3789a20cf413598da4fb066a04c2ced14f158fb2a7592d326779dbe9875978b0341373df3ed159adc635e316c30d1ce2dae9f354f920253bd776dadbd06dbe959ecfe202a1920387896bef826345d6a6e85bfc4f71d405a7cb1e4ff060a0d2f40c3eb000000000000000000000000000000000000000003050c151c23";

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
