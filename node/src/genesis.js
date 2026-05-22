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
      ack_stream_timeout_ms: 3000,       // §46 / #48: per-call deadline for direct-stream ack send (sendAckDirect) and ack-request round-trip (sendAckRequest). Caps a slow / hung peer from blocking the local stuck-round retry path. 3s is generous against normal libp2p stream latency (~tens of ms) and tight enough that a single bad peer doesn't stall the retry loop.
      sync_divergence_grace_ms: 30000,   // §28: time-bounded catch-up race guard for the divergence detector. A non-ready peer briefly showing divergent state at the same committed_round during snapshot install / cert replay is normal and must not trigger halt; divergence persisting at the same committed_round longer than this is malicious-or-corrupted (an honest replay reaching the same committed_round must produce the same state_root) and the joinState exemption is dropped to flag it as byzantine. 30s covers worst-case mid-install windows (large snapshots, slow disks) while keeping malicious-peer detection responsive.
      rotation_coord_rebroadcast_interval_ms: 1500, // multi-sig committee rotation: re-broadcast the open proposal + accumulated sigs at this cadence while inflight. Defends against transient delivery failures so partial sig sets accumulate across retries. 1.5s gives ~20 retries within a typical 30s aggregation deadline.
      sync_total_timeout_ms: 30000,      // §19 framed sync: total deadline for a single syncFromPeer call. Protects a joiner against a hanging/adversarial peer that accepts the stream then writes slowly. 30s covers normal catch-up on any realistic DAG size; caller (peer-sync retry) handles the failure.
      sync_max_response_bytes: 1073741824, // §19: cumulative byte cap on a single sync response (1 GB). Per-frame cap (snapshot_max_frame_bytes=16MB) bounds individual frames; this one bounds total stream size against a peer that drip-feeds infinite small frames. Aborts the read loop.
      max_round_duration_ms: 300000,     // BFT-time bound: cert.timestamp must lie in [prev_cert.timestamp + 1, prev_cert.timestamp + max_round_duration_ms]. Caps how far time can advance per round so a colluding majority can't jump the clock to expire pending deadlines. 5 min is generous (2-3 orders of magnitude above legitimate per-round drift) and tight enough to defend against meaningful skew. Reference: Tendermint Block.Time validation uses a similar deviation bound.
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
    vp_id: "tip://vp/US-1d8e8ee431f715ec",
    name: "The AI Lab Intelligence Unobscured, Inc.",
    short_name: "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction: "US",
    url: "https://theailab.org",
    email: "trust@theailab.org",
    registered_at: GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key: "d65c76cc3d9effa023a662d13017c80710cd6a5376dd73d6648de45a2fb4ff0e5cd3e9951f7a04ecdabd8a65faafdc3509a4e6e3acbcadb2b50121d3d621958b00184c71f535e28f220b96ce3d652801535083ab5de4f2f42622c226beaa6c121718cebc711cbe3c2345e117325616fbddba855254c85b612ebc39496be6b6eaa0e6afc309193b3f5ce50866bb49cc349c5192c328103236e50a9a08b2fb3c052e94b06995fb195c5fdd4a8c5170f7c0ec020b725631414ce3fdc931d907676efafffcc54c251dcd158eda0c8495b759daa5324c9559f79031dc0644bc3476d2a0db13ee1bcadd7d8b0540c7dc1fe952016f6429d6fb17bedcdc124a8b1905094957f7e680499b6f753a626d9819c47a8032347d3b54f44bded8851ca33235bd83c025a31565f4b5c4d50de566ac8fa38eb90ffca8260948fe4ea0e62b9b932bb18c5c6cb2caa3162c32cf7045c24df1d9e0b3e39408ea72762dd55d6b4007b126404cfb1bac43e6231458d5cca9ca2768821141bf0622cbf0469a968b82b9ccb7e13de6e4c52a5bf8307333777c1b44c6f1bcbcdd1ed5a966009fab069e1d9db7f28e976263ab9dd8a96bc8431ec42b9b2570738e5f81e21d055cb1db48620e5fd9dd155de3f357f9e311af29cf92dfab63cf39a5a3d9d4ca4d2e6f0cb9314022430e8d0d916c943b1b0712221e63e07d4ea83e82eb4160f67dc039afca377553474e33e8ad1e2d5669766a8adaa9a319cd8b1ada748db63ec93948f8ca38f97afea7f5e496c5eee6203a36611b93278ccc7de4ce4aba76ffbdb720dc49b1e053c166224fb3f6bcd5399a4806156d1270b6858602ea530bc4ce57fc2bf5456e66c439c6ee71aeb399b9652aa101b33c313f4715db15e2eb905fc72336d80b226d782de1c15539f18d85a2724dbf5ddedba10223d50d6327c69b1369865a855cb2e867f1e6ac1fa2fa90b802e91ccbc6a99b0e1067c16a583ba68e8997892ab2fccba676f88b4f0246cea1da7511e5cd544199d5b49d92883d35ceb194622865299c7da7286b616ea95c4db43d62c48e839aa42a92da0c6aecfc92549e7df998c5724519544020ede0c9f72fd4c9138979acd014be9b95db83de3c59766e8ee7431ebc492995c6f35176a9cc5f004290503d84d970d6073054e8424737c96da2a6b472d6393e8e24187f5e87bba25a7d694ad35659cb219345a13bc065017c30a72d0f67e77e4c9e62a2cba39bebda67a2ce4034cf8b8096c455c108d20dd1e3648b5d9c2bff5bcbf1154a61d11df80cd03ef20a81d65d11ece32eb7ad45b4e9d47e2447b5206ef28df442d788e9b5d902e6c21fd93f2ebac59a4b4009ff8bb10410907e5e440b43a9259f95cef71177ce03694a3b5fa75ec3a558ccdea80939c36e33e90009333893ce58a6a43ff7c2a5ab762fbfb36e406b2f2b036759b17c3c1ef2145549f665ca109c556dba95287bffdc1f1197ccc7e32eb628e11ea4d1f37224a7a5ff0ddd9f86ee7c55bce5ef8eab2f000cd95d922776ea65fe3e89b032bef68d296f0987c0fba787fadc946a2a59a6b9159e090ff766467d3278f0ce8c697a366a59aed6cad69321a68e2a38a711a3ace7a50f485e0346b20acf36a9abe1628ddb1c0fb16de7dadb252362e0b9c14f009d6f4e9dbe01acc45b20f9cf9a74b45c23f88df0f39e9335f902feac942a0eaae5f882702b5b287603a7f353da8a177b64f2f4152cfa896ef5b96093b7aae88ccaf2022ec4a3b48486ea8a7f7c2186ae1291a9b54943c7875382cc69b2200fdac0af24acfdd49d58d2e4f7fce4b707e2ea7b9f475b4917a4fd10d61c1fe38ad3e3d80d9d2ba40692505a34c1420a792a510dd2e8609f823ed3390a7868f44841a87a7fe3c9fd0d26640f36c79f9c9d1cde6e153c9333f6d024763fd98bdd2a5557dd3078b5af92fdb12b10b98dceb1651100e0db739e9a509a1a1f60e4a12da5bc25a1d3a949d3d525141dd33de7446c138141ac2a5eb34b1199d44aa153a561622b89bb9fb7ec300d764bc359eb472017e8a7101a8f7e8749e9d0aaf497a2d8dbb30c7a23cbd18e5d7d4a2f260e7d4971ac55436d1ebe7c93caa96877aa07cc6cfa817af0e34952d32d43e0f74a4daf08d77dfa5c02dbf1d47367ab60480250f300f65e6c8b04d1a2a9ee39d07d99e396992088742a0c8ca1352d0720a2cea838e262444abffc9ba6ff17d03e030f78700e34e2fdbee564401bf8eb8dbbc0339e4c2e9b3fce70f6e1867978fc5e47cb90845c0d2d4f05f9d663ff64c3515d11236a6fad1fbfc7736291cb8b742686e50768465c7ef9cf695161c6016945a72c78153cf686970314e6a6a59c59e6ddc6ded0c44b9fade133909974d21f4a30f613bfe488edd349353dfc3b0e9dc00b678ceaa46a7a1293daaa2e9d9a9eb138d8eb21c4b5d0ad9273cfdb7309e51f4a8c2cb2c83f40a929df701c661e24cb428e99fecae131459de632c973326fc814509cf9ee808af06a2c1b38d0dcd9b3cef9216c93c0e7e734d89da3a4e609e0dd022e4831b2a79272c75da8265e82119ca7fad1a62cd5509454648bf7fe92d1f69bbde56b8d105c0364c8ee205ec7bc245f71236e80bee376c1334f3af7ef7dd8cdf5fb3bb0369459c46871288707dd1b770c25046b8839ea67ec430a5c393244582f927c2bbdef3bd02fa2afc015a6592b575ad87841f47a3afcc82829ee3b55cac3b6bf8993d9f3182e0a5826183133e928d20cb6f08732b0d3f36abf",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  // Founding node — registered by seed script, bootstrapped by initDAG.
  // { node_id, name, public_key, council_signature }
  founding_node: {"node_id":"tip://node/c34ed84e1f0cb97a","name":"The AI Lab TIP Node","public_key":"c0189e5b42e94877113d24c9d2ec82e7a8fd050e2e7857986ae34aef0e6f93fe7ac2503c59a79df24a7c7a7b8f982c532c98a7a84848e4a40c9c57d48d4530434b3e1c030e44df01ef8c371582eca3658848d0b8cf874016338f2c6a6e9cdf346268fb5efa79a4dfcbd96399960c9bd0cc4c2e6a0e92deb1d6d0e8b247fbd7381c5dcb0d18ca1b00fef6e3a0fed5c6ee9d67ddd3cef3a36957d2344dff8628d355a04820381e5e9a7e1769a1c55bad1e1d766a7c10c5df671b4b7c43e64ed07219bcdee7c3fa1dc2aff05c3d1ae7fbbb2697978d416eb2bc70414005a0abb6e4362810f2dd70c117cb9dee6d220dcbffe9aedcb5e1d144c92fccd79f342417e84f543fc2659f0d06bd401406d2ac9a457ec6df5c4b0df051d519a4f73901c4a4e0c1978fef0905d1f30ec9ff17bcd22e07a25dc99be4475502073edd8ba3adeec33d49fc4c29b60b5296466f9b7706b75a5d2f8aa37177218b8b517b931f950937f20ed81735b1c96c47032a884a0cc9d230f19fc5e0fce6ab14894d207b7a2eef2eb7268650d131aa27a575401e2ed07030d9f7282b87aba76e8257189befce26718142e7d24bd9757ecf688c7e013998aa422dc26ad2f22b7c603e2c306b215e4b8458e8fb7af037cac864f9e63bafb3f35ddf9a8ae32b90cf92dafa1c137ed07b66247d96b17be6861a61ae8ca0b153c252af400b256820b4b6c6c4e116171865836bb8e337cff42a61f450095c6593212ddef82c7edeb629c92f855b489893d7bb9bc37744384963b9434aa18f9d0937e6301abca28d5eabcbe13c6a50443c9f6e2d30c9afb24cd2acf5f1197b18c5005ee55a488a927bcd2540e8692b133702cc497f1250b47ed5b595dda797400a88845b2191a617b3291ffb45fc0518e13e036565398595ee98b3fc2c24f574ee77451a17f4987f3e1637d72dd6271df3d04e35e34f572e438c11473ee28ebb03a87b03de4121216edada55a85d6c5a822e7a8490cd5e33b88572870b1452fb40594b3c1b5230ab3230c8cb1c0bcb6930ef67f2cd82ed465a48e9dd5da25a526f620e12b7e097f49669b9bbf36c307f9a5c68f3795822a994eb8d1c5efbc2ef12ad8fd191c726ef2cd6bc800014518ae20694c4b7e50aa026efb59bedc880c0b8c6e6873ceab4731a8d564d8eafedbec06d80fc7f13201fa83b886b6ed16a198e6b0cea16bdfa4c15efbc70e11597e6c66ff5106223cc075dc9062f8d3cedcf5b1dde85085203bc866809faf62728c3975e1f3a0b09858bd1b16d5503b995b8c43197f20e602bafd7ad4317c1ded25b4ed019ea1c2271d6a5549d01889958084317b1b009f0542d9fdfaabf0dcc969b7a09224ac0e81644090051395cafca9a9d7cb4e17ee42f11a7ee7891aa91f28cd7486212fb0e54ba686ae4887bbeead9ce0e06b5bd10cea56069cce3cd552b4600d03791f9c0f15cd270c16096166bd9ef11d93ad12a07bc06b86df8d26376cadfc669e23a9a17da14f292f450cd59080bf72667d11c20867c0b75ef1c1492532272248502e7558df44466277809beef88df3bfb059eb4877317ffb4dc089af45d08d86b081ee894e04782db4bd1843f2fbba054fdef6d6f8e2390dfb93ad1095af65d7dc491481341432fecbdb334a572923b6cb90f8871581cf4e58faafc63c915333f63f2da384dbdb0eb10dee7ec77433461c605c187cba810368258e83a1a276b9409d8833c6e299662c8a69504632e0ccf0fce4366e332f806e5dfbfbc3247dcee43ff1ba49c1fe6b4573ae1642e7f506bf033151eef0b496e863d4d3ac0043466af18bf5bbd0be401eb28da802962c1b3cb5d2001d4720bda24e79c88b2594137af8aa61561d349dfe979c01303a4dbdba330ba82828a232c32f39443c4715d160b44ec8d2eca3a450c3572b01e026ed47aa1de461c59541e42f6b619165ad671a81bf5dc4dce5a48f95aca8091b5241f2329d6951a2895dde054834afef9845e2628a186840dca7ba6abbd5bf67d2e92512c861f7f616cf3351fc9f6ddaf147831ee11d63a083b922ac0527ae6ccd5f2a92b8dbe8328a1b491ae64111d3075ab7860a0889582a683dfdf28b8e3253cfe79bbe975eb7b660f41a89f0ccb36043442ffac4ac3981513b35b2f3579b64100064161aeda37486cb771fbdf052cc21a0aa446209ce275f1e41eb6e30f8e2340e2b4d291f323dcc2f1c408e6571021721f1bc14965009faaa8bfd3cca194c171e77a5ad0eea249230c8eb4d33367f89c3c44a9dcdc85c59462e0e9a38b2151a3fb20dfe1aef30bb3322d4fd0a75eb8dff8aab7724d00e4a04311d59b7d1514707dfd3a7528caba12cbde1817332ba38915a8013aa38082ad3528374b3f59e0dea52ab590299e5745af531a33db3f6e910e12bd150c1ecf149b1fb84a4691501bf82b03c38809af86d02441f58ce7d922a006952025abf02c73582bf3a713540effa7e91a3d33cefae5afd136c1337857c55592c1a075dd778d66571293e45cc5166b1736172dc0774bba42dc2f2fe9e86a1df0647d702ef809da38b9e564dd0126cc72471c512345c7fe5f577fb413f5352a52c92a1e8d7b1db3e48d270ecdd348c71ea6a42c9bfc206ef735e5828c6444f421cc3417b1b626955b72196cc36ded87f11a0526a2294d2a2401422d0deb78e8a660fcda0274c0d612c0925a734be8686bd338a65e437a403b29f79364dcc72a5fc533460f73af61dea78de2de1956b209db79616150c0a8ea46","council_signature":"6d22b9ece65cae92655bc483cffeb041bd67aaa1d1fa6eca26598dbc04a86ce07ccb414155cd6177fece6fdaf03fa15c06e047c967a61e941a9643432659b73147074286a8320da6dfefc875e4b197e6bed6da670810dfa1bf4301d6c4872cf3e878160bb461c456a36f19fa5e3eed44a0bbf2cd1dd22fcb4e2f70531554311d95bbb9fa3f9943ca8e4ddeeccbd735efe60f1510bfdcf42fee93dac601ba6172eb1db38fa9b930158fa9842b161a5c8551d5a891f4717daad46890f776830df0dd3103c08380b83350c4476c5fa59e8622c19e7db86f687c8de0f96ef25e79c3471c990719500a544d7bfcea7a7e6597820c60976a21d8ee910a016e2773e96d4ee664aa0eb676b0fc0afdaaaae9a04e30718aa28122e6ebe95ed76131ec3615ee25897ecd6eadd3603668e7995e3d1d391fe2e0c9305078629c8c28928c154640a1f3acf1bd7576bcd81145de3e207fcbd931c197c51002268d75db634eb677f24242ae48ff82de7703cc2fc4573836a77983ea74f664749a5003a75df889774be0f125137e86043a52947384f70e9dead6cf55abc45e2ae4139c67d14209e467bcedda11f4e3e7d46d1b93e1926ef85bdef6f2165c6acd55eefe10f5e66ecb839c0158cf66ed3d2a67ebb2175ae32026929cf0c187a0026ad2a988dde7039a5d7229e2d6aa7318e40732030271b617301fa6b5f35eee021fa0bd751d7d3cfe2cc93b4bed5abbb329bfb797cb3faffe18fc816e40d743fe3074335a6b8025bc02ab0c983191a52ef651ba146cfac45b0ae08d4683530e64c74a270dc80fb3a873e282abc8f42dc317655d92fc4e690c720faec0c8fc6b11cdeb0a8b6f2ace546eda7e7f104245529cdb0eab8b054148c47199738b839f5d4a01ed011acd750e8a75564d02aeb0e1568d44ad88e4288ffff7f52b2cfabe4d2c58549c58eee589496d3aadab2d985bd9f13af66c5b34e11a86c678dea50548740753348142ebc43f2ef2696ec0956923bf8e022d1bd3254aac109c9211689568efaa8d1a48364761e3bc457a7d72225d78ebeda5bdc3a23c2ed17c2e6b0f09768663499ff3ea2e0ccf16d2660a642a5700222d7ea0b3fbe7ab6ea85f9f072f4294bb2fa949ac3b6af99cde081f4aebdf72293edf7c23ed1243a53ce9b5b044fc9cd4bb5e5c626cdbd652acde01adf572e83db5172b9247c33f425a1ab7c8117bc7b3d9da7d6fc262d95b3ec8c8baf712b156a4029880db4b19650d611419a64697468c51632ff1759feeee85252f5dd542b0455673a845fd2140c38a8d8e9ae643cf1c240f92b43ea057e785dac7592ff4628005ad076bf2342d57c1d1225820c0baa8bfd3b01d0cc683a0cfc32ee742a254005c0d4b12a800bcdebbb60c8a05bf1f7e532ac22430dd53b0e08f462d71b413a7630c269e5766a6599df28eb1c5361dd5b28b6ce4adaf9d6f5419409eb2f2a1258031e06ffb7ead9852298bd81b9a813edca6676cb795a5651e00954ec2ee4145def1ec03c2c9380dae98a9a30d934a340827317ed4ea7f0deea0f0f0a96e2b47b98749ddc20da3d4ba8c35e2b3ed4d0955c93978caccf3f14e9248a5318a028983583f69a0de3566f95aafbab9b6d5b3248f9ece6391b00a09b011aced36aa853f66655c08f0cf55d43ba547586cf0d7d1f8ceb4c58db8d6dea300e8a6a7ea67551b6253294bdee2f8fbeab191b891abbe7aa3b7c0b579b49b771f582ab39ad3e0532247a82735aebfc7a017fe863261e880a896f028898246b783861787864dbcb18e8e82de6615687bac602ad1bde8931a11c06f296b92fd79015d31a6e1f811dcb8f98097995b7915706945043a3c0cacd395aa0d4f83c3d0508d19bde4397ad60097359e335ca27d0edc809aeff7d051104325741455514449204a471c68e369296e1a34f9ed04930792e11a9e07c2d563aa266458c0a0b46333d2262fe77343746a25533d81c8101e1bae62058f157a99938655f5a5675bf81c3e2158e1c00bb0bc58f99c0beefe67811281cb0097bb4f52eeb9a831eb8dac1845d2ab861318a98d0c9ad5b3b8bcef1dab5dd0829bf6307a18d8648834667d02a5306d9695d39c2cf4f678b49d0b83b78b78c12fbbb0d052c2631c8f837fe2c47da54d1db164c561a57ceb121cfaeea5ad851be87c8a4ec09d50f33e196b21818b02e37a4150a0ec1fd65741a0fe4eab9928e2b0a86f950cb4960a52bc045e0ce42a497be1e4d927bb35d6bdeacf7cf155d2873b0848b773faf48bca0e3a89e4513d5edfce72c99df1a208056fecbb2f863ab012153393b1b65d88ea96cf434a37731f6b5a277fabcf0717a0e8654f0ef111173940bd3c5825a1b45e33d797007ca5eb79a186ba02dc73a670319a22f74dba8a2a06d2f942d2597a85c99ab0bbe1c8afbd53e024736e897a1abdf5847a9b7dae662b682096bee0a0581f6a2870f7175a8d47c630eb752620df68578e39170f6d0422493fdcabe8e8d17fb8b37af7ef3ea616a5eabe655db2748ec4882b91ed17a36e7a5a87bdca1bd094f858169cdf4f547f5d3dbeeb0a92359b7d160dc6a70b8c5d35fbe9a223fb1d6e86a2994cda3ffc60f3f2043d1abea0351aa9d1f967b8e5f6351850eb4ca24a3c2c7006c948d19a0adc5231db4771f9431ac6f174c3ed98142707e77d35d30f6249f2c04e6a62c6ac986cc826c7c8111785393ff727c223a9e7e43294a2d90c10c4d8df7eae34d6189bce0161da15261c55a45e9a0e7683e49edae212147d125cb4f048f28f1f70c5de728e53b4dea5a73fbe0717aab6732d95457fcff7ae2fdb4d1dafbbdd14fa9e4135565412db1c9810f2491c78e0dc9202ee90152d10bb41964ebaa40066c7f1855f6edad3ed06f711e77215604034ad115ae4e30901d4d1c94a0cb9552b14f769bf1b14441df8fb4ba3aa481dbd75779cf38bcec6a67bf793fc132e0ac12dae1dd5eb4f8c0cb29f41dd082a808b55327e52f515695fec60b6cf0ea9c26e019b8aa936512b3d0fe2305fc5824108c7d462603eb40fb2743a53b3d30ab27f0172e1f53d309eecf877e252f671b4a133e42dfe7f05240b00192bee67c738188c11176034d71aa9bfe18be722fdd3a07e5a32e21c602c5ad13e7921afb95b295ae77a63aec2eebcb4ce46e7954069c3eb5ead7729542fcff58be3195f07734008262086d99aa01d9879fd0562a64089e37d67ad3fa057395306fa0ebdec483bf9778a8969ae053de13615c9ed367febce2831fadd6938aa3d92cad807e95887ad3348dba72a2c30637c8ba31174a0a8230f3ec3f15f1fad84c773f8811a0c4ed2e6a47293b0be4b550955d3fe50ee0706b7d741d37c7325877a5e5fbca9bef60bf38fc7f0a6b2d64d718a170ade41081b6a3f97cddf24c347b6fcddd84ef7a3bcec4a0fd4893a95d446132e4bece84c8554facd535e95666748669d16c7dcc095aee659de14da980946c388ffe901b29203de3dfc9c139b71662463017d1decef537ea7bf75b35166cf63fe2e000fe3c918f26fd35d00a6c94be4649751b4b8d458d49089fa7e38f8406139f3759ed057a783deac50ce6dd3560e5c5fba07c87ddfe19ea6a5d477f5bb1d3cec944e305766c138eb23c806d93df9c469797980eacb290de2820dc6d6dee37883a74c26f31f0cbd0abc5f2c894037741bce536b283dea287e48c1384e2c8605b6a848164fc78c68d05c00f64f85a9d13021cf4d2ac4fd27039028fe2f57de275c12749f86e9a92da1ba055045acebd5ce61783803eeaeb70afaa3d2edb702130514203c94634b2927cc1ae8d056bedb5348423dd23adf729ab14ac3c61b9f4bdf2353a926b54362216b7053a89c89dc98da9b1455bf90cb86fa763f2b06b0c4307522b4375476cf73ac9899f92f080dd6288b32a4a1890f0da8344d9724b1bf12a9d958817cfc82f3461b1587339056feabcbe5fb8421e945566adc58671263dec78119c786c9b6025890053bf49fa9718a07ced423de324e9ff2cfd424307005cc02d2797c692fa77b3834849ab51ec1ee9bbdd673d2770ea2746800c8f05e66c472ff12892f2714c3397f713786d9a4883e920b39c6db745fc5f4374668266d62775ab8a770a22c2d0491d5fbe4c1c2b84b8a3915b2823cc35672dcb51793658f2f51f11d2bfa963dc2b37c63e82266c8a42693ecf7f0a7e2d6fae8f7d30e460014b96f8cce88836c87510c3cc6615684332676fddeebc9a7529a78eb2df7e1f59a1d589298da3bcd749162747e3d290a5630f0f1cf37de20cae8e3c33a5ce713ec564df9c22c4e48a70d5c063673c1283c115b4f2d3d5cf9bb1b8fa83af05546f73d5a998b9972840173d4c14c475233c8232398789292bebcf70b6c56bf162a7a49e6cac2bbd07d110a703ad2d0849c60a65450ceb2181899cb283d7df57cc92708a6e0838db21ced7f37e62350843d9c3d39545a556e419d88f4f23a3be279b7eb6588d08d2a0077fca4eea4ccdb2964f9490ee8d54c1f1b3c6aa49596f44f99934ca6f26c6fb4ef3a7116631453c2746ddf9de85dea298a97db7d16b2351f6a863bd40ac51187665d630785004acf22af0520b6f342234460b9d7f126bfe2286a708389c8d5da2aea034d8891989dbd193f90919bc2d1ecf60000000000000000000000000000000000000000060911131a23","approving_vp_id":"tip://vp/US-1d8e8ee431f715ec"}, // embedded by seed script

  // Genesis Ring — founding verified members
  // TIP-IDs, public keys, and VP signatures are embedded by the seed script.
  // initDAG uses this data to reconstruct identical identity txs on every node.
  genesis_ring: ["tip://id/US-2ed64e139079d435","tip://id/US-9ef90f7c97271ad8","tip://id/US-1a2806569b35f03f","tip://id/US-a5b5308bd57f637b"],
  genesis_ring_keys: [{"tip_id":"tip://id/US-2ed64e139079d435","region":"US","public_key":"fc0c38d46dcfb191dfea7ad976a1b0daa66eb83b0b0be379a3286f323c34add2369a3df1282c2fb086746e756216f8882e2df603a680937e78e8205f438e58e115fdd6fc63d610ee857b1b4c64d94c275dc23d7d88ab1314d8cb8afdbb73cf73d399a2eb7d06f05067350e7380b090f8879228f13e15cc761904d6b9ac0b4eb78b48cfddd13d27a0f5258e64b330f4d7e34443250e6395714e497047f67ac353db4a7ec0ea6bff351b03fcfde76d13067c3d89f2619ee4cb54ab04f815d5019c65f73e057ce76fff39b856a856f554cba7932a661cbbc47ab2708b8eb83a04dc0512458f63005185c94a56bfdeec7e8d69ccf574c978c1a321760f2da160fbc5fbff0c2bd71aedbd16dab6f5c9bf80a97fccbe4240c2cfa7a79a17f82aaf795a867becbf0bd9b9eff728825c283bfcde0d92a5f052f91a15838791f1b128a917072272ccfd75f140d2289451c3a030316bd6368f0ca0c36ed373486b506393138689e6ac57566480c25c4bf0083c2ff2b262cf41f444520954126dbe251a9a58fc55b432817f9babd0d495ba6e1c4c764b415117623eadb4d80e4330c32be35d91b976850f7adcfce565bb455da425107e7c257ed0d291f5984e5f11f5bb3e6f7e0adeae11f93a7f4aea32788e1621656a271864d95488dee597c701f91b1738bd274366d29f5832072a7c8605b88df20353eac477f9c0a6bb07ef5ad9426fe9341565e6cb85196b785758c7456d29db965dfaf61d3318574af7143b2c535c42ed781201bac27946e480cc6fed16be71709688a82d42c85897c32b8148e477ffd760ec46810a3ed675cda90f0d90ea02fc723c82b6b71108a2837eb93a55226bcd29624acce86f26b54d0e15c3664a152a83057cd0abfde1ff2e479e12fd31c4a08a2041f3ed72b064cea240118f25356f9a447d4fde0475cc5ad3708baf856690156086566cd9e2104182f0e82d647d934b4e8d70ddeeee2782306b897272772ddf75da6f4f3bf87ecd3c6e37d2a4e391ced21121d57ccea4a74157d807bb79230ed31350aa6850dba6300457afcd55f6b1a4a020defb5e7484a8092e3358aeeecf3d5946eaacb62222151a5dd5c718c9df49087361538e47ae2bbbb294edbdd62cb8a13adaad4b7a250444cfcdde5b3ba71d22520f3348b3abeb005f17601de2a239911f2dd6a4cfbdd811b9cff3aaacf124ab41d9b81b56e242676efd5bfc40d9717a564f59b72bf384f9de8e1e6fb10389a2f83b8a0d76869531ea59dbc8db95b7ab74fd76ec301990046febed2e2025af7b4bb492cc925fd7879ec00407aa3e0303ca2030b8af42754339b6571b27431a878384b28f2c8b6e9a2c071e484225801fef2e173350f0861abda3ac6c2553cf6fc7e85c59a80f74fa5df865c7d973deb0e09c51e6c15cb22d5ae4b3ddacead8a3fc7d5b7bf872145ca0763951812ebb013c6e3e7522844a40f2356373e4cf4b80d80d5ad78f9f05454749cb31c343a8789f5d13c4f7106aa60fe1623b836e28af521d36d1497cb338f3b543fcba609c8a26997eabeb22840927f33758644aa167abe3662f859e12a74aac97079b5314413edd3d163c28ffe467637978f83cda9c82905a6eb95b0d0fd4a2621570438e64be5c34a3ee6751222367834130ae362ed096df2c73d7ccf6f046f6a393243a35d186a17cdb3ff45e34592e20d4ce8b8df604592b439897d7efdf6b49a32548e85958b332691152519dd750d7ef7ef1d3d0516ac480c6d3fa111b28438146cbcbc0ef741349f7b74b5656320088a376dfff67b27ead5c9f2787b9048919e9f33dffa0ab34c82d24da15713c8a95fe93fc80612042ff3a8d18e5572b8b7f6eb1d1b170b891c76519d96c8767f82b7151c66bc0bac74f9acaab586a675e489f299b8b779c14d56bed8ba80ddfcd8f0eb68da7b77ab52e466d86f6b2e403482b1c8fa7f6b2a0e9571fb64aabfc770baff8c25e7954740721de5c0d44f509b630ec39e6f60d0975ab11702f5bbb2a86f750c27d2eb2d3a29311a36c978dceb2c9b5bf3c7a53fb7e0bedc487bd7359bd65d85540201f6f6ef6a7ad7159bfb1ec8882a52d36626b4739bd2897aacbdf212b5ab48ab6aa6be866b29417e6a72ff8f71d078d971d59fb352067e73b875d872cbfd096da46832efa7a5f1ab9947c99140202f5da3419f6cd0783f36fc5d5eca3e5e81cd9b1672ec5d7355e465330cb7a66ddf2bf10271d9a44fd35a88d00d46f0782ccd9764d469d8b920f9423de5d9a9e0ab824ba1e6a574130ed69a0eff3d8c504041a609fa1ee54c28a7ecac645188e02291209447874796cc112200854f97ba1e2b41a32d7371e5d62285d421bf7e78e40677a67b849045eaa2a6f6719188bbfbd60859ac3ed8ddc4cdc5bc9f3379509eee6117754f70491cea2a674544e09c51dbe2321504e43709c937c2811dbff0ed269be1c3f98b7f80c4a64b5dcbf9163cba53c27ddb95dd2df0ccebfdf180c97cb22c199b26c61ea9aa950bc148e24406e5c1ca234bc976532aef112c05974a994f4ee7bbd12f54244bb42e269d0e2932df7cb601184e5bb6d9be02831a9f0ba596fc9b2b304fccc9561772b8feed52ba43c51ce5cfc2776191e5202c2f090b2b5dbf621f3a47e22163b8c476860020a841737ecc134c043cd381781ceb71cc9178265a1ad1957a4016f88d573f46ed5560e2780be06719cbc204cd9c758c64d6b215a96498299f15faa4aa9e64e066e59fe2b33f9b1dda3235241f5","dedup_hash":"92661839774354454942","tip_id_type":"organization","creator_name":"The AI Lab Intelligence Unobscured, Inc.","vp_signature":"fa342f8e5ccf2e979a5e71fe4a99988ac412650e4f2834da4d66b827eea494447b129d21e6b2250153b8617ede05a97e35a33c2c0427caa3f97663865ad4538ca35443e5c1e7874e0a6b0058d9f0d2625cf69d482ac487360c425af16b66015d73cca7619c6efd585fac308e25d0a71c672933d2a25c581a0251b8ae1ebca1d1afbb1de941adb828332267e04d5c65e4ba2c7110a7faeefedbaba35cbdb48eb4774d10cc504120ade4212d13764b4fd73bef8d03527fcef5cd535504fcde1e153fb20b86a42f033210a46dfb7b9551a7deb76ae4c46a38054c35847a064b4a33055de078bed86019d8e3f59c47b11aa8d13b9e08b73cfd534bef6ad005bf8424dccc723aa47e230a41ff326dc53e868c608e4db06ed5379c8971c4876c9aca5cd024803519526e2f8111d0498e6ed4bf47b433e3ef5939ca80ba0c4c3c79ae5352cdcfe45ce5f5317bd37e8beec993ab86147068bc33ef333710cf3d48a502a909855df20268a0de3b8b0ac640e1574e4f6aab4e4afc7d7b30b1f539021f7a0304f06bd32b06f7cd97bff0afe532aa205e2ec8eec2516454737ce7e9399ac69854dc4dfba7ab4763be0263aa3d66008f322fd7a36632ca7886ca88a6e146e52332968c6eadbdfebd02861bccaee7a832807efc0c76531ec2ba1c097544f61a16ed5e2d7d9d34e139d73662389aaf56fe2b99800299e349f4b139e0d8a702a25ec50f8a459e7f9c97618fa59ba4a44631986c1d36666e808a18af040bcd9c6261c8700d68d4f0daaa1a2d591a162ada03e24eec72cc5c6e8ae112172f94a592609b88270be3b417b4d33ddab1759b4272f2b1697d4c98f415886e7da222826c8c09fda7a3ccc22d246dc50f7cc17c687bd597d80d566f87ce51326e95b2f0e600a7d388f31803d68212b4efa0d658b12f310d0cb93db8ae6261a48b172cac710cfc64da5be6822b2068f0321a37525e50408a93d861ffd7441aba530f0d3a01b6f81a33867da2daaf283721a6c73946ee5101b72d71b6d17a7684c20dd8f3e0960390dd76f5eec23bf987c9750d6a6b914e6d697c64b4509e5d768f62c176619c758437dc53b48ddba121b996730514834ea2c3cde9c1322f1f9c87d5496af5cfd9f0943ff72d376ac4eb665f53891f0fa11da5a278754a6a582e21e57c4e3656ed617cd9edfb2bb860af1f23e021a3b4142a79db53023555dd30b31574b4324f1d6359a219060add3ab9134bd6b71b5a48b7a0e05ddee6e21865d12d9076e2a4aede23b32907fd75e44e99e7719a6e7df1a11ce063e5e0140bdad6d4bccba4d69338ae27c7886e40191790d0b40aa1a1012fe60f9dfb71346762628e1845ef3d8695943a849b96acdf5fe5a63086a3f700f7d27d5b6a8991e7834bfa76e6306d3ae989ce5e91aff36e832d0c30bc0a2d3e7f0da53f387562dab73fdaacb72469b0101eb6bb56af995631689e200789f9491f50b2ed34edef64790a62fee286b1ebf8dcbc5930d3f6acad34a0504a45e2fddffd7608195915c34ee7e13d52670204af4572b0646998a6c8133b12dc69c3602a1c437ac1e8908d7e81bea6dfd3a706c2c583f6cc72ea00a2a9292a9ba6957b9b5fc3ec5cc1b5cd38f475408db3138cee257696b8ce32113604a6a74639d9029976efed9824ed75c46bac4c9a2afcba2cf581da755556b3c61e55b2d43f9d2fd5f332d8a6daf49f72f532f203a568c229657235a6e9afee5ced4633cba8e9a1f3968e8d067c847b2bbafd785f931c5b3832cac31874b68f396e839c5d91c811606570ec2799234a30b91834bc3a3fa91ccdfd3bea7d0dbf571fb0404bdc1e234cf1a2b97178156ad174dd097ac627aacddc76291c5ec6b495132c9f74410b311e8e2fb81fedce1e0c08ffa886d3632ad5ff2f2d2cec94e88bbef02149d34db0f4e522d300e92504dad3f311a6b77ca01691b0e1f2d24aa2c4f32fef636795c6d3b28abe90c7c1c95a040fb4cde70939b714ecd7552ff0e1001c3ea5beaebc0ce7dbc49871cfe4d1527eb49a03c9e4d5139b42f9a07b8a360dd9d9f1f9d18907c6680ef35c54282fd3773397b78c111bfcf63431dc5fe03e4fb37ad1ce1d9aed909b62a9800dc211e76915e53154c1491a534c64034eaf15b7789e683fa5b8fbc80da6b51378add2b21013cf83420d07d319427efc6399a77db87918560570b29538b8f9383c6741b7b6e8acb655b8118960d33a6cd4377b62739cdabd2d360c067da1908d5693de30f227008389d6e4b6a5506a99335a9c7f78d2216b891527d965dfea915662e5b0f087b6ff858d944e86cd179b90575f95d6cde44c11779f4153714f897d5d155251b2929907d9275a9412c3f3049747b3701f62e133e661c40da27680e42a75380e9c43953a3a31198b46a7b79c2548d47c974b93f5a284acdba23adbf240c694af8a405d9137e2bc8fdd976056e44491cb8d7f300306676a3461d7551a447faa7ac3a2f23dabae7469b9177c388babe503a2f44733e566efacfcc1b66b1337bf53aaf1f1492f2397a5b5c15d121527fa4dafae93edd305ed31d9fa1d7ebef326388458c0cc420e17e15702ee8235b9ad665e6764e653e8affd6284e3f8c7eeedb35b2f756bdcc703fba5e5874974408c6eb1bc5d723643eb5d18fc9041ec800eae1e528030d32d68150965dab3d45703f2c857c86c743c17dd00f282ceae6baaea0fe4e2c85be306315fd300da4a44664c213b2f838e61f3e4dd23793517645415cace09b74ada2cf8b779af3f8e2ea715f8a87e01ae399328a17feee9be9055608a1ba926ac98cd04a8f1042a96285d7d179925ba955e09263db3b797b3491025d67edb9c65ffda5a1ec12e3075a468e49e3dc3db7eeb286d91e06045f54ff1820608111a98910a2be8e711bdcceb2f3af2936b6930434b47947efccc435383469a0fca7ff4075087422436c0605594a0578b0f7e89cb667a903e883a9a484c4d37af500e4394f29cf826521fb2067acbbce646ce73f87828f3facb24e8acacc971e17ff66577787700bb56e48578f0a93d1c2ddf90eb284581dbd7b107c08134737ab8e780540410f16c386b88926de4e7a4548cbf585097cefc82c7c84dc305d41c9d455810c57962bdc837c5d64edb1a2626d5ffbb45f789e773c539b3af7011f1c7fd99600da20c594824268de1ea22e6aed3555bcc1388f4d58d80b7dcece93e72e51773bc7dff15af274a01a8638ccc2540eb3b2981920204e30de5f36609b3c4dbd97b4e2186f42217430f18822fad523770b5aa00338cf828117590dc299b7e813ca2b08e691da375855986e81579c9c991c792222597e1ff48b2d2d9dd6483e1a6716da8128ed3188a011be2b0fe2e36bbe1653ea55c1ae75f9c0ad9c56c66bcd123b8784f57a5c7d77b455006ffaff30b3f68da78a92371e8c59d64ff280d3a7f9672bb45a8dacfa0b12132151c01dab099c6526739bc10e4d050e34d548ce02d2e683f8f53c79bb057dffff80d9291685b685dbaafa0cbeba7e010eabcd9d1335c523e2244b6ceeee9c7e2a491c2864eb26bf2eea0a1c2229600627a44bb979a5b9dff524654b4629bd078abdee5017bc496e184bf92d0a7b41b659241682f0bf38b063dbb67fe5849f6aee9676dfb3456ac0810a3a7827838090b8cfe932e1fcdf5454133404befdf15b6eb16a4fbcb5635399487d106d035c064913fa5824e995dc91a80f0533a724360470d6cd5a015bee316834c5d200f99df911c65d7dd419f1d14f5e50441217ca0733274e9354f1ab4cde1d410e7c375c5f043fb5b138ff3c93bf4eae895353eb211bcd94a538688bb027c2b66209a98586cca496bb7ab0d168131f30a84e885cb56edd6b0f0f1416e33ed631481ff6bf49f1ae0a0870281c952f254dc92146cbf2cd16390457abd81a32ce011ddff5b8bcc023796b073ece78a7229f27e1c27837be5dd6d2c3b21843621bab8bd45613a30d27642c4d66b8d840f182387b0f05cc0c9834059bdb9d290d4edb834df9115f7a34d87a6f7bf653ab9bfb6cd42aa7427b18368bd7fc5e1bf201f7c4c440d36fa03ae029514076cb8f8d4333c17a55b2e37feeaa31dab5b79b64b5471be257cb98e29c49d8ace12e63d7fc60f3484a2818b2eaebdc60f6d9b552636ad527813666c27d1c2c3a64eb75d56f205fb60de312d372aa86441f7b4eb9e1e7f15bc1c5acfa76d171b20bd637dc384cefae7c4b0f9ce596b1d51e94eb7187fb7b7357df87f5f8243905fce676f3e99f072932d0edc06657e90ad428f38072b0a4697ed02938c51ddd39bcf242209a5ee874bc7767fb1d3f4ce177bdb06958bbeee2d42d512d5d798935229b1f430577df55622920017a46c500f308c0e653270b4f4bfb46114a0d8a149abe4b931fb3d82302123ad17531a74d9a66cb5fdf9db166fd0e5d47f6d2202ba97e8bd5aa5ac0a6f1a6ebdb14c27c55c6cd812007a54a152659adc065de3b9ebce2d0237a4c637eb81a5306f3565ec548d3ca521fccc14fd4218d24f91ba3587d707a663c62b45b3096cec8abeb30d762a933d8ef1a58c059f2f41e65914525cd9434e36a70b5336c4c461396c570a14273264879394bfd4e60a1a729fef3749516a8485ccec205171a0d609252a3247626970878cb4e1e901498aa0a9b7000000000000000b10181d2a30"},{"tip_id":"tip://id/US-9ef90f7c97271ad8","region":"US","public_key":"6797daf6491fa650ef7d1d29528b47db6f348406d17bd099774b37b506201ee2e38c25cdc9af39659bdd08a2834f325fe9b7fc28389b773e28740e0708fe4ff2a74b4e23d2dc58b511ef7057092cafac072bca059f02215d17da076e8caeb318dc40848e9319abfeebd1ecce2e48141379d97b8dbb646ceea382d36549d7cd1feeb42014a34a6728f67c8d7cbfc08e32806e32f47c3441c532920820c1162b806b2918456b0248ae50129f8d1f25704725ee7fedc470a8107672f670a9b53ea0e9a0b785d5f664abf56277c6a4d02863daec8408a71de0a6b0e739889e4e84a46dd307ef4322b190d08a40b4f502e8a94bf64e5c6895118a709ac921b4f2f9694baa853deafd1270b275aaa258de25609b8bdd57c0881705949f921fa5180dd76a6542217abd64cb0d068e5e8941d90859fe733a8a29495e9faebab8f6adedd7a9475e389436fe016ab25690eae1fa8af922d2d5ba8c8e05db183047e4bd057e99beb4d980445ea47269006aa1364b80b2a6ab3c0b03d304f65265102021cc8cfc420fb6eaff810ab05505b0de68122e36a141190c35cab51e978a3cefc6a9b9103b10f4b923e937726dfc98db2a4fd237bfbf564741838e051614aadcf4e8fda45203ba47cd56d4bc6010719217d58e2cd00e86b4dc705c706a0f4ae7c7f696926bbaa2b6bb93bc1688844dc0fffc4fad9719800e12cd368adfa0b850f5350b3992c6a26d0dd330ff0a16474b13a8095ab55c6e54088d01e6989ad3292429789d493a91a2c85d489a26dfb004d915c3ee5e9492ce81162fe88346e6bc03cd79ef209e59be47b8cadce2cef2c8d1bd2369e47b6ce39f42fed7116a573b2d380470c5b68e041a3040753c6e39921ac803dc50a78e5f9f4161bc7483ee555e196e4a14fad7b68ea804d967fdf1c633dd342ea184e318f6aa4b3df578ae059ff71acff643a9233a93f309b50a1d38b885c93adaf7913924bab3ed0f1b224ccc3904d82a9c71092f529293ee83ddb6da962b4100ed137c186fd8efebfe3db9d0a50277db8d2ccd8c131bf7b395b63664d8d2582387d347802f65d57297f23910caec71b40a0e59e260e35c90eea242355160b8f222c18cdac2aaec8b54a99ddf8c17afcefc672bd56cbf32a3fed56ed6be892a98d478389c4ca2922d799e897ac581e38168d133d438114bb61d489278934051fefc6f2891345a561c27154675245c3f845b26ae27a5be7b8c62575ed989eb626c4f35d61f558071396386651d0aecf4a00e1576148c3cd9036f77fdc1cd4c5582509d2ef395ee6c8de9ce55c4076f9155f05e398ced4d514f47f645eded3ecbeb64beaef8af779f707da1c56baad701bac0bcd9966d63bd126946d2db6292fd407782990bd6206172f91950f2fd9a5268ad97a8dbf584404002da8093ad587029e66d3a6601ba6021aa9af6853a5e196bdab8e98fcbaf0afefecbb1055a5f146b944c8e781993df93b344f53ebbef4a04276e117a1e73c0d6ff1f9808aef8f07adf167e5745c9811f855f3809887f6299f3ba4953bdc494c9552fa1893b32a32481e8d47d6b68fc8ffb6357f0d9516bd927eb053a78c020734c7dedde4601c2fbeb33c1f2754dca4943422dd1954a9fd0c4a21264f3c0ea8674f94664f7d463c92437bbe7a2263036bdebcd6f3fd89b6c20ca7b05b59d81a7cb0ca27e842057765bea4d766f367664ccdc742feebdb8e995cf177775c78fb55f4c23e28cc8d80933e3a5f7a028cbac717be6c1d774ae3b7f7c1a2257ac93a2a7bcc37dd2652ddb6dd8851c20e1b88bf604b00a1feb5baa781c9d540315d7477e48acd0431a7493c26678f72ea7de81b3f20a366a7efaf7976c7690be6c0b2e17d2b4aed9e53509a165155970478c355f17fe54f7bdc11948945d69933a75bccbc5974a8fbb19e97b39963f91d9e2a30afc1d50457c7c093271b27bec6cfe69d9b526b6b85820d1e6fab5c901d3400961057e1017ffb5a630b43305bca10a17921eea37156cf97d1589ba6f40f87cf2218a99f2189d57b5921790af516d2cb268e7d0ff38ee4a22875005df470810c1be9cce8e877dbaa2d0cd98575eeca240d6dddbccda371f1ee06b1ed0f76ebd331513019dc954d27f1ed09c331ce642610ce7ec44496ac3b670660fcc82dbb40b0d8d4d5791286ffd52eb8088f10372d79a7a609407e13e0e01265e787cc2d6acd9036c9c9f487d48c2e482a2fdc33972efb201cbce62f77667f8b18673f501e1adee4b54363cc47faafc76490927ee0692e2da4b1e5370723c718cae6b5504928060e613d0a61617f1e7929eed06b9a09883388cc6d32083111b767df40ac1df675220d8c4bc8f004bc9eefadc331a2cad0a2ee3d952985ed5f7b11228b577c68bcbaafe9bb431bff8d35b92d8a6810e6a0db685f31ec8da3f55b43cf483ce4b59b9f5089750a5e9932166ee0523da9589abedf135433a99952446f2ea01375dbcdcbb846051522fbc7daba6d23a0925114e395289c6fc299633bb5e7eae7ef41e0b4274c01c12738c0d35f5261fd5be8a1ae737eb44621a4b28ac391a5a3d438c7403cd3366a83e56e3110d6b8c404b815a702769535f7198c8e10acf9bc578f85a78f1acb92904fa975bbbf81058979a6f0b6e559e4767c46e74e789352edf2e35144e80fa8932b15662ec2485f555a1bb179db171369c77683b5ed8eb9c73d84b6df8aded49c8f94c44fb5cc6e7430d41a6f55ac8b4a1d962af525808acba5505cd0a1083","dedup_hash":"23702933538943712392","tip_id_type":"personal","vp_signature":"4e87e043902bfdde9d05750aae13e8ece1358e2207e9bf551dc6b58b7a5242c41301b9914e9890972bb0ea9fc785170870a34b0f8f8ef82b264f6e55c1461395c79289f9113db7b1ab64d526f09f4491ed52abbda4745aac80ca850052f435f7eb10b4c04a65d2d5e05edede125fcf2bb6c1de9d975e7c038a3a8eb66e6c717a71b5d11f70d69a5209d3b5c513c94bed0080ac9dd1ca736a55f4aeb4f421a14a08cabbf815a682d6afdcd3e651758b966686f100ee5b48d6c4a0f7a3b9d864272806af825525310d643a0f881584c880da3ba3f144085035499e1ba51251a96765d10a42e3f1befb76d555ca6a3bfd4f48aa16d1f6731bba2098fb0f31e6209d9061a7e63384a5a492cb9ab6588e04f6c71b10c9f49174d0bb8faa81dca515fd9a7bc7861e526a26ef0fee6beea18cc829774c165c941bfd3bd98a4f40153f463cd299ffadb7b3f45047ea2f1e8529074d8e82d3f20cff6985bd40b50b5ccf4367af62f03696fc4733c5a7eaa479d3ba498e319fe15037fdadd7c5c3179ba2b4cf16cf337f8889014ab4d6b81ed2eaeda406645d95a808ff401074a1c7d09079aaa2121f7bdc55221f66daf93d50a35555a5207c0e7b457649fe0d3e1066e97bf8cad2cc8c9a8bda12c69a23ee5befcbb54c4ebea634fced8a5c2a3ab266c5031dddf3e00c4b5820a7725c15f11e81668b98cfd1e11e5cb2629fd616d3f6cc3cec889c6e943d469900fed05ce8ad9065059d65341adf364806468094b520e64a9f939af80420a259dd9df288fe1655922383ba1d221a64a40f3dc5b2862304a167966ee03d6f3e3de9813f33004791ed06900682821139e5be9dc9664a3b7c17c2c9c0a877a7d783690c6a16786bc9b8063cd0288175abfc60260cc482d97fb6f8b7428eb23baa5bcd31e87075f3875af1c64ac3a18b4478ac9ccc0471e59c2a22746549eeea3e8adbfbb71a2cfe0b02486472d3abae858e569bf1945ed44e80a9af2f67fe9980c4879a7f365726175ee43dad99112956a18ce1daf9fe6d78953580ba1fa5b478a5cdd16434e0af50d0980430fad7f2e4f3c89d07b32da5a37dddc391d387eff0879c02be732dc801b6cd2a8390f142a200185f033eb0bb1271fd77b223d5d624ab584852b30f26043fd61f6bb5ca43f4b2bf2d69f8000641ab057d43e1618a0edcd1843ac11a1086b60b59718897cf78bf474ac4a064e3274ea373b5e04b0e6d4ce2d5299821f1db3cf9abf385a194cda4a6391636e9c93eacb314d6e5d38e20fd0c7074a3c95e8aa5af1a1160d8d737bc4d75a1c7bd839558e9f4ed1bd12723bf64139e696abf7606d06419612b1ede869076870283b587eb41e17916f9e621ac3abcc5c976e8573ea4cc948205386dcf35dcb4c9d1dcfd07cacc08d9098b0447424da994744c5fe6567de8b6ec5e2d853a5c86f86e477c9fc3a1f14c994d7fca514d4f72d3fb4bd6b3be08a2d8edabb3b28546022acb0bca4a25e1d7430d0ed04be01f83e64d136b9217d3dab3a3e900e47f5340e40192f0f608cfe3df60b275780ea60ced493f2e831ac48371c76b03b2ffbcebd34636bc1852e2b28637ac4eb8ff526c8f7c1e1553b537061f747b0e2f2fd4b9daa872f21b37278a5f3b0dc814732444047cad116f1f2dd6d035cfa5eb7aa8360a9457462317392ceb43530f75fbccb57b9478a8633433f35c6540fbee8ee416594f4ce3e86ec8665410ca47a69ac50b3c908d1c4702fef3266b9f42e9e310119a28fc15b9a3d41dbc38703944fc4f5a2a61c0ec1397c5f7e26c400278743e1eab703a63c9203619ab0df281a1968aeaf38a11d4026ec971ad748bf28993f8a5d6df9b1f3bf0602321b169ce024e0f3222e91529a7579a3d5b0c78d1bc00a9486bc2458ecb86fdb100feedf2643f4bf9c991111d113d902a764b2112c38765ca330f39a7d0f540bb5fcc4632da75bdb2dd285db734fa7bb1bcf418efbd6416534be601250beb79109fd713496bdd11fab79bb04d1e436ede08d7b2d6b056678b0302c654bfeeaab24ff3048e486975d666649113de585f7da978f1bf30c3e82842d5f24826f17fdf76246cca55862579e1da723da056dbdd5b86982932cebf055cd11703cbcdd90e19348b04dd63c8bf70656a678c91b95f5869d7e3c54c5329cdc1a50915f9bdc3bc8f15cb6e49dcdb5f08f9dc2287e029a054736fc06b7bf71c04660051832caf196e9099333f7840e9e184fc3b34a016bd007f3cb16a98bb02662d0435d2a898dd29e88701a83d630019047f19b609ec1a99a41d5507d8f5b69439acea01bc7bf82c07e421aa162db9eaf7bab301014b7e75da503092742a42736ea51c39c8100c2950adafcc22c107e4b31dab2cebe308b3bba09e78a772c90ddb54661caeda92657d99895bce9af492f0d1df7547b0221e23ff956e1be730ea55f5c9f2ced9f220669c87abc675c3aed58eda19144f5d946e714d883f563c4a12ec3d23942cd6323eaee4e3ad2c3616c2b755276616c5f1577e3d7d593baf9790ba2e6f90782344fb423c46d12de1e1754263ad2e78185ab3ec37ced5c7c8e00c0f2de8a0405469bd77259b6d37bef2018bbd920a35fe3287ade59fea4ae3c9c5bc2fb7776a28e219a076c976920429af86d67506371b558acca19e6f5c26d4ae4ec30c4d7b2840ece6a9c7022db7a56bb4f99ce28d0a5e9101266f7d8390dfcd60abc9d97ceaf2f9e9d6214a8c2e84d9efe14dadf9434bbde77779ad0771f2a2115f3bc8cfbe54c80a8c5d0172741b3741f8b96d61a2b08c09112fbd7ad553e81e6889c6a7075d7415c150496608d3f6195e54d12a1ec7a1e253ffbae068d3f8a31e4b69409e7dbb14f98264e9a02c780637b8cd205503c22e7c8f37a59c03142443659cd85e4b589a2cf4e4c3a07a7d0fc32a718e60eabdfb45c1b1764d8f06b6c6b10d4c905e5d9472150fe9a25a942d8a7061355dff3045926c10b6ffd5774b3218d5512e80f9bdc888874979da904c6e58a131ebc4d1735637ca6ec29b56081655c0b79d94a6cfd8ece48850333b391a87c57b47b4aa78b3aaa4e15dd1ed3aa9d0f781e84a26742169429a27523f971bbadd94f83b5d2441783ebc0c64a0ddabe7854aa9a76b06005e9109b2a729f303798ba9adcecbec053bfef6a95ad993f43dd8063596f449d93c0d89748f478fbaaca11f0ab529e903cc355b050c0ca5a69902ab5bc540402300df7292f3c2c5b4aa05a902b83391f7d7fdcfd56e12909424cc1004c51128dbbcf191f591410c0603a57e145eb0383fa01b801c767aca6c1515947c1d923e163e7589c0f0b8fa0dd8296a4e70770ace3d673b7228a55990b9436af6337211c6956ff4db2d968ddf04449a64c4ede42289c10d388a2f720fa2ded91965a27c3aeaa86e3cb44b56b6ae43ef42dc479eef5e5ceebcdb6a0031a262ed54598d89c02de1fe6edbf0f4867e48577ccae24d31c8beb5919ff3de71b8737c1a031014537210fd8506300dad013b975a9a48b1c3d63e380a2759c5af17bbb049c5ee7efdfe27fa74df4d02b5f6829220e72c1db8ea704f96d66d544028bd0dce8aee55b2e8ba31f250d32c3de18e9a2af62e33e3fdb4ae162a1d6c7c4e8adbc61c633985f7e2d85428e79fe143ad421a4e1df2cf214ae20317bb24594a83e7c401421f45fafa0962a40187ad3086651f9db74b4063eb2a1f48cf44ca369849b20d66e293557571d6001200f5724b18fc6c8183ec3b6d7c33c072d95d9ca6535d94a965446e3997828bbbc41559b89dd60ce859ede268e484bf83209f4a9ccfdf699ae984ffd8e050da59fcaf74388ba66290d250790ca21178fe7a369d23d31d2dd5f2bab88f04791dc39f551ceb6fb04d1525992676141b7f9036e22b2d17adf45b7d40a0810468e98a086c5c477f0d1e8eea2f188435e4d0cfa144415265921c102c4df1509443f74288957e5f395052e0c43f586ed8bc841253b8247b7c2e2ee2c21e19fe77050b114687af776f2207b398121ed11a988aa09ace4345c77f950bdd06d4d98fee015f8601534afc2b5f71b3f706dcbc26924c179079e24776c093c1b50224f1cd7b5de012716e42bf75fa193cdde82e177256c0375d94d903865128186233662138531b088ae7d4de868e8a702cc60a773f641bc1b15852a3a8f8a9c797d242cc3e7eca3ac9f99b08508ca24c8746f306fae31b75cca6b66b94bffccedaa8a12eb3cbd72bc2ac3aba2dfee910c712d13943edc6cc8f236c45ba661687d83d26fcb41516ae85d7d170ec969bf38c8624984c24f43e1b8478e500a8c926c580da3d29fe1b783825b847a25da1234b840af60a60d9fb147d65c8c8327a11a588c0e47aa4743b4db54c23421e1e82f4eaabde318eda36b97a05fdb8183ebcd0561c1568c6ebd9321e0385bc624b8f66b46e40463d0f6c8f9697406ef931a7c90b5c0a7bcfd70f205332e54658a9021c15347e884f308ed62c6b7a3a3f8d3fd0c6cc23a63c14b57792222f3783e27e474342ca5c5ca0eb72586eade16aadc227acedfb93b1422512d76dfcc48f2b0d42c454e045ca8bcf3d8b5346691f74eb9a6f41e8909bc57786b4b7bccdd85f607ae2f3042337389aa7ca0f14191f6e92c211aecad7e1e83f72849ea7aeb0c5000000000000000000000000000000070c131a2028"},{"tip_id":"tip://id/US-1a2806569b35f03f","region":"US","public_key":"f03edfb9985bfe8cde6b7366c4a81d52e38315b4b5e02a2146140adc3d0a90938e1d8726bf3fddb3b5c0fc98d27cb086dced517b5483f93dc8f9d3c78c2698a65607e507f8463154ac04a9f2636c47b7d40688bf469af0e92e4c39e296efd8428357eedd594b998427cf46328f3dd65b23913f989e48e14c78c31b9b3e475bd136351ff1128df34a3f411848cedfa79fb4a559100ecb88c76a6870ef3c85e62732bd1fec280e2047f8679feb0d9b01fef1c89b6fff14e17f84f7827c57d433be2b019ce730f196d7b156ef69ebfb8cf97ef7507aab45ac532b33c033968c4f118e70067f96fd4c3af005af6930e53eacd055f7dbf45648585c5e822d2a03122627d84c644488ecf4951a80f0574e9897f6f8821b73a5dbe66a7fcec0f313f64efb406537f8f988528090db1d651db964be5a9d97b6730aa01fd75b58761e8beb0f8656a5c7b50b0979a1664b2b8e992c8ff396737bfba4eefa57e4393867db856d93d18d09579188899d7f2ab8c9195f412db3812ddecccd643f52184dfc32b3ac63d422566727e736c040c8f6dff4f360f1943768cc2d34e0049d0497ca947e994e70807ae51114f7ca96376b4eabda99fcdf7c0051b36b7199220f17fb65295a187ccc93f8d45f0ffbe4c704818e722e86a4248d27442b647411f6c6c097b31567763e78681636d06d49c3c638abbfe76c52cb7b0d86fdaba90218f0be253bc4b68d0e1ba078d442235fb3d8ff3d57be3aba7b31391b38dc75a6e2235c607106a0bb8937e248c20b5a754e61e081a776e6215cd7c5a9908105451492fd247ba05ed299413022aaad200f1899d1dce0a28fa6f2a01ca5a1d6e7efc25f514eefde659c59d30df57d1da11b696cce36e6ff5ad26ec4714e7f01c8b7bd7784b7d8fba4f0b517fab27004cd98b3252d32bc0b75f19802ef5143286f0523185266c0eee655547cfec315711221566ea0d5e4cb2b5b2f8b4983202635d6c690b21576be089e977fb29262706fab7badb4c9dc9ad041082e072ce7b15f33e906ed69b777bdbcae50c6932df254e9f26d0a74815efd34e71269c51240e08ff8ea46ca3cc314823ff713f7b0f80cb510ed2b795f8629f6fa564fe3771a232d400886b5246d8a08ab3caa14050c793eac37b51d4a5c5e7072f0b0da09120d0e1c5d790f01e12babcabe2f74802289519e1155e89f4b610cc69597053b52c7403a10afb8521640db61ab3547f84933c1c0cf17d07cbc9801cb73315852d5e993657a4e58f3ee270ff3eb70be7b7667f229d35703da4710758caf6b0dff6df43b9d81f6b3159fe3f643a665f79d3a56b5078e5a05abc149a68331d2898864430ffd95e0c0f485708e01a93395893704c9a52dffe534fcdae9ddcda5f62a2f51752c1a5a4bc9a25b5e2e2e78b7d87b2054444aa73089dbabcc09365c0e78e0b21e2b4e3d5362df132a011820b87b2c6c6ce6342e0ea272398c396f3fa5478e85b0d8ec62d7e11779e22d65d8a56f01a45023b968b00464ae92b84c32d3452b4bd363dafbb001329fb677888842d1f941b1c77618cddf19d395c99ccafc254d1e90f627677a924368b7103ae3ba73ffbb54f8b32954d111a9f31085ecee6bbde9533191c3bf3e4361b7231a951b9f9a227cc4d844e3bc4cc2118095bd200c603fc278a8bda6c9e46f18252e63b93fab6bb79bdd08989464839dfd24c2c50cb9db76d0bc7c7ac99928868d33ced6a77a7d95bc3c47d79087b28f728b0dc1f88cefcc8fee9f8deea179d22650c850b5177f3a766941fefb33c534ee9bcdb43a61169a0a893656a6616590d3046697b05f9b540858ffd682b9f6e028d7dd7d76df41cc8686f48c5dbcf8a044d67a41591c89a8349c967c52b3fdd236489a44b64e26bfa330484bc0091c287edfabd50654a88c5b9aad15343ddc7b409444ad6d6a361b96cf46bc41750e37459ad2428f08d1fc5c1f89f2c4b294e6173b19105da2c7f038988c742ea3e9b68a07d3b355bd5fcb22dde2a71402e12c3406c0ab00033ac3e7014d95a07eac22f92ffb390f136204670e5b36547198840c66fe8916b4d14511e3cb56ca28539f64870306011f9ecb3b962098a7487ba856f1ac39df32096bc0f7cb83365984bda9ae9c6c84bcd7575b66b7378be57a5aa1af19962eb8cacb4979ddb8e1eed5d90c4179385eb5ad5fe5364e464f8dac4e91eaf2362eb164a50a69a1857b5a6785468d1752a318fe850b0d5dbae90a31196140249828e24d7aa289a9488a5ecb3506e94d511c22c21474580888cc8f177745df90f6ae37581c9a304d8c021603d43a316b83ebcd0d14b02ff545aadc9375d6e92c0c1bd40510857e87b439003c292f13422f986ea33696695ac526b3dff465eb2196dc339fbc12ccfab63a3a7e177053b6109d82c16a89ae5c163ccb562a45bf15d48534c19ec1fa3c76ed6baca926c8c31be65f2b9a05b6b854e31def41daacd5f2eb418edf19ce66a750bb66c30930b71c020bcf06f914797cf80af0072aa0f3ad461542126fe6efadbf5cbc1977aafe629ce2a27c39113db8c0d8cc1a22738ef18f9d27de0d6a6a339ca07d2ca728a42a2e60fe06bdb0cab4ebe24b7b0e8b87791f7ccffd672abcb5b3d8f7fc1a3110d8330bcf5d9ecb4aabcd9a466b62c928d4965b6b48b073e421d6d1d2504b7047fc332355432f12b1a0b78325fb5552d4c6640062d898e7f4cafdbce4a354b809449465934b6ea887846d9e64baa0c4869878d33d391d7bf51af0","dedup_hash":"74146165765493969290","tip_id_type":"personal","vp_signature":"7a5decace1948b5fd405457176aa3da460e5f8cae5e3bb82d10dc76fc706fa3b555875e480e65fc803ed22e914a706781a334e5654c590a3ac776eebd88677b8f033880f6858f419742b5cae84216c701938baeaf94372ea0c7e41617dce0fc2ebbd882d2477d6d6cbb9707920747586b1d06d7fc133a8ce79ca92d4a21e6cd2e40bc7d6fb1977cb53403649dc0e00459ecc980293ce28929d697232c5547e96706d93d8ec91d8cf2d0bc27c1734dfece5091fc5447344e19e8713080906b1dae1879e7afde21159670f2511aeb4ecb7282d2ce837663e34f0dc53ae9f2fa5f10e5c9c1e255c0ef35715c7b7c2d4d099f2cf50eaf3012a5320aba00a496d78211cc25b2e74d56eaca32fefc0532e55da828b344fbd2a443136f4fbe31ca8b7234b0106fd88d6f3c9e7a0e24bf889ccbb6144eb4ca959812584da370ba136cf982a7f93ce4a83319bd87dfaaaa64f345bdb2dfc24595d2d57ede368c861a126596849ae053ec045d57426aeb0a695bc9c4cb9f43c3aac9059569917cab3822f32e36edc8029acb0ae92a436cce40d31e4fbc499be1c702c06a309caa1f8792b6d5ced2fde063a1aa011f3dc1d0c20ad9a60518937c9585f07ace697233c87982f205c225da4e5dbd37e848a64d8f16b440dfab8d47f7e1fa1e05b46aa1b25e6bdd4b15d1d8de776b95c679a89d5f8b9e4815ef1d69e9a26949275fbf9748cf435ba249bba6aa48990eed9da76d2774a0ee69217ffe9e78cf8ea07b689519b06d747bc4cf9f0b283fd95c5ce32af6fc0c7d86355a51d803cddfd83abdc1d35ef3c4a012b45d2e223f3e087b829b2baa5f4117258ae0af10677c9128298cf8c4d383fdb62f77fcefc0b166f1b7de0311eee92be2c132d1cbfc48c0db3f1c1fa5609293b59d6d6ee44a4caa18a588b3ff65a9c00f9ba765b005d7bc21f36d6406858d84869f7089e76bacff1f822319fd12e455cbb91f02894fd90ae31a7127a311621c351cacfe4780f1533f2dd64ae594177d0f7b1ef882c9ad7b2b7dd7a4cb99a083c679265e281dd02ed9835b7eec6407b855eed00f496879026130813285bdcbbb7b8130f20c6815440f2703b94cd8fb0ce0e7e6ca26200ccdefc2b444eefe41bf2ed40711c23114db4d3977fe846b662533f6c0f526d757a98d9812ebdbaa97aaa19f9003ff1eea3c9237c763216e3359a2654ae544597b84cf8a65c10542be51653540aadbc8713ff982dad90fd28dad36d599029d40a58e4a4d7b6d123c133deb55c7324f791e9882ceac2cc641f32a9e53a3eb9f56873fb4be1219a39718d98f73587be92bee078b00825403b3be1e7dad56b89ba4ae42fd91d939434dbf071867ad418d32509c50bd244272cc7b8509cd9d8c9a8925b3118e1c3c5f434d0774c1423a669388bcd7793ef0d5ac405b3f9a531961f39c7b819d3fdd934075790276ad852812afee3ee4e343f6b10a310397676d7bb7a2afe44fe5801686ec6eb7ede37b1562698def61b27c0bd19aee201a4e3f9c9191840b16dc296cd4023c46c70a1190b6c7d4d61d6aae9d6a27a13d53adcd1ed0e5f6aed9334095645c25ab5e07fe69bea000d8de62f9a42e607b700342f479a4006cf01acafc105b7e9b467142194f08e0f2c195b0aae52f8fda5c178222797f60a52b4ed45d734bc24f341337c9db03057ba14c6ef67bd6001d5fc0080a1c86b485aa137add6e3b083a1afef7849a6e4e0783fc6f86fa1929eb0d6334492e5df26cec12ecab30d7e024ebaca268b40c7ff4b80b43afb154cab7cbff3c2d2d0bc37e6eb95b0c29aaaef9766ed4a0dabef95031212a6c055b13883e88c4cabc0e025b049c9d281b93b5754e557cd2d193ea1b3faaf90e5caaba312097630cdd6c187f26086a8dde28df75fc8d7d782d2be71ac324a45f090ca971db4de2cc2a92445e5d1b8ab8a3a47f3f163b1f0a6ffddca892c4fcba841e1ba8d1bfeb49802021d9487b7d8c2f1279f6ab5d4152258ad1fbce9dc4363183b87bd2753c8088089f150bb29b4fe7893824ce279955261f05521420f843aca8f4d140fae0e50601a704803f4b43a582bf208a0bf566d04bf27bfaa76475f79777cd5e484b32ef37dccbd81c2e45be1176f8d37075f80334c67ca446f0cb6822426df223d88acbc0ea8f7baf806b65cd75764f03975ba61c0ca0e7270f2f13e30fe8ac2bdaad78d381134569fd9997133ed491ee83a33fabd7d1e72b42c519209e2d04e52dd203e13e28666b0d8904ef0234ce2ec63046716a715341cb04b4bad3f8c96d8556e2101271120e2a7d2e0a92145aad44022d419ad8773a2ce30fd51404a164d2acdf94c4cb70717ac47c102e21bb7f4ff789eaf509937a586b40ea5691222f377639d28b58d8e57f7f993abacd7c8b79dbaa9fddbdad90e7aea5f3ce1ba8fe0e5218337afd5b5d66b1b5cceaae73d0a9766212c73dc8f29940ffe1ce2be55d03f2544d6e7a68985be8a74e86f3e4c7b1d6ab13ee26f0cab439283035373b02530ce3098edf72ee87086bdeb25072bcb827ee70579a0fd0cd4f4d416ef5f4bc7da770f616a98de95d16bf219374c84e4bcbb2257f7d4ea46e0a9f9c1b7939cae62b16a67de9e43657c312603506e36f3e08bed7f47fe2522978df24446016121db705196e474f61042379f3b7059524a393edf8f9e1060601deccb1051a25e77d5cda728aa0dda5aaac760ca9f2ba952a127f8822214577fbbca59290c04b9d9840fd6756f06ff808716acbc249b0b64c097ee10831e91a58ef06495b6a15d1b847eef88a2020aa0916bd1d6e38e00128aeb129a1737b7b3af63c3ec0a4fb1719eefbfbedf2326f9b3ba919bac8cd5b4c6d50a989aca7bfb3a6458a5ac1337c711c72d2384b62f2794280968220e4925957094dd233df71d3180749c96756d0d4b690c251dd4e738a43f9e7cd7e2be279f8d61b5641cf80d03960ab8621e5cd4f922a55c96cd2004a2ea8d95d4f623b1f04b4ac171ffd2ab1e3168db59d5a08c92b5cc57f835e1bef54e8254673de3b0132c8036896d666fae81c0ee5a12743342dfe985a0a29a156404b568f0498fd59dbfcb48126f924f7e5638976ef93f3de32545af33377332f6774586f187a232e7f0994e3599d4aab120fc6964680e770c7fb81fc0d70923e7ba28a0c76a069dbd3be36f18eeb8edc9b66fb9a3b4e0f91892393db7d6792557be5ae1d28d944a8c4425f6e38d6fcaa45a82809ca16f66310a332eafb621ee5a242a33650f34ce19187dd355dbbe18069136d80462716075902b3394d6b8b02cbb01c2ab9b4b44a34eaccd564d06d5debd59ac60cbac3269a5d6fb5a2ee5043e6489e7d734e2935e6032203134670d975ab7e2ed533c3c49b48a2be9b152d4aefa5eef297507e42cc3c63322b25ece0947beb2c3d57d2612dede075c29b3eecc43cadc52e2466f75007f5dc04a1f2f868eda15f795c9b6e413398354ecc9260e300ff501f89abffb38fb1e0e6f7ce6d4fd4713de6cc15b308c552d0c3c326fc292e1b1e92fa6eb23142776984894182385713d30da16592627b3b5a8d8c9efbbef8381fb1152aa8ab2faa3d49442f1f6c789ec4e3c3340801f8235f8dd5176d681e33feb16bbddbc5548737216d65f05cea8c890f458363c22fd768c69c636c98d4e00fc5f5012e79d1fbe558984187aaa7f2e10cae4c5ef9a15119b4e6628218821c71bf8569c3292fdbd644924aa034d888b617b34b6d660ae3cb4811a23dc2863ce7edcc3fa7a331ede072db46c914a9c2ad2d44f686213da38f062317786cdaafb325ab605070279532bd51adf9b0002df13bac697250fce184397f6e5346724a945ab42092a550f5e42f0e20d169133022e3cd10e47ee004dcaf2bcff179fa14aaa8642daaff2f30323646d6070b708713e3450cdac8e3f7f6038b0a5fc7ca9608f99ce39274aab6cdc39bd90ce3ca468f6d1fb45453c6cb519420738298db76c5b47b7eebc3011da8cb5211e88c6daede63eb061cb00dd6ab9442fc6bba8cbc5e0ef8246b3d038a3c291497a9d70d65d6b0a6a18e372355a3c07b077efcb24d8c9a7edb63d0660cb614468a7cf10a3fd227ff69327bcd3c1bc8370d70c4d4bddc3a778cd39e743606c0191959eef886309d05465457ee65db258bc11412747676ed646219cc6464894e755cb44947733b72640c974587d3500dfa16cf0e964872bff20666bba8109185d7c4facf621df3dbba6429fc79ccac8e1b77725413a9b3fc588c501947f78d4cdfef801c2e655fb645b8b5563bb8fe7daf045b7f41255a563ceead98fdf25193b70e2d1731fb9ada368a94c467e6a3834e8e21830f43ad845e9889a008e4d1796dc8f5591e92a103397529acbff53a148f0b438de4608b287f61750f3e835fa8876d25dad48add8093c42c72af6bd663f59a773fa19d5bc9ead4ab5706347b920269ab6157658a38715df9043e04d1166bde1f28f77e1ffb4f4fd87985e15f013b2dc927127e51564a62804cc3aec225c4bfa14f49c30b84acb4aadb1ad68faa138cf6d2eb7f2ce088f62b415999ce760c7e75e5cdba6f4a2da830c9ddf1be631776c9eb1102f96a1ea40828ca7abe1405a608db1d9ee142f3f61758dbcd2065398e305e6e8000000000000000000000000000000000000000000000000030910181c1f"},{"tip_id":"tip://id/US-a5b5308bd57f637b","region":"US","public_key":"60739d7781124a2bd0b963bf3177e1c483e6e24943c95e326b6c8f174a1c39063247c1131040d248da952434a9a0f2e6e05cb4540247370881da0d55997e060a5e41c111772c15120c64bd24953e66c1057875d988c3287f956dfe41752b001bba44750a0f4495a9c19ffdde0a8102800a2276cb18056c019778a6c94a87b1dd237709774e82d3bffa89c735061d8f39c5073daaac849c5ed49c41bd237ff99590e7958b2af21417d3de77f506028f63cfc3882d9433e0615d8a6680390c8c3563b634961596e6583a454fde267f062f0a255e23b1af03f20cd234cf51ed83a8938ff078c5aa35d56ccc39a90866e60e72312174006a60bd1404454bd5eada8a3a3ea9b7f38f05d3f4d7e145e3236b9b61efe8b5681fcded94fe3398e61f2e085111f1fb26202e74ec4ca7b216725a16ae5923214be9ce398b750ba0197dc94b9578ae59ef236444c52d95ef510d49dfe13b93f5692fe6a8c80da290a2e0c02cfe812e975b58f8475c7c34087349eec0fc84eab952b2c3da756d71c44425a58ba5bb717170bec8e2e4bd40b08e1800dbddb0899ce56798663caf39cf68ecd0d9832b7e1837f9b302309d57c615c75440a2a5e788ea34f4753a537f9a1413227f3f576b29727914ab01934409296879dfd9efe56ca0486b62b96ee032f54f41409ca6ecf7a444dd650cfb8f9baf393502bf583beb3c4bc22085d52f621f41ffbd0cf87bb5fb86917b45713943cd6f1e54f1800efef026c127ead8293a345b7e7b810078a4e714bad93206b701915b59f2bd155bfe65c2b72497902151f3d82ff9daff445a489ecd3be0cd1252d872e2f13d716adaaa6e6833b8bdb3eb3e8ecccc0ad4b872d426afddd493269db3a63cc59cc0fcd20e69f3887a0e17557d2ee46280827b40020cf75b37e47324e4950e11788da6e359b80da390735fb6aed8b63f043313534cc83a55ca16be2cabd24771b8bad0a1cf745e11600d6cd96bb4f1cf17cf6b20a28288fc2aaf7c9d03f419d66d1b398a1bbb2fe9bda64f3bf9f93cacdbed8f7c1a298015ca7f40d519e3de438dbeb20f1298fd22ce410386844b7d26850ed78e9a86fde6f5dd93661df32a4ec805b732d1bb4c4407b12491ce29028f285dcde5348c986d38d61ddac45058bacedd085d91c00efd672a93e846023e22ad1704f2192ac3558a85637b00338406bffa59c0b2ce7d3955ce5c4d84a8e849bc04ac53e14b4b8daa29ceb147260bb0876bd1d7498db53c4646f35e1503ce9b9dddd4a64bca94571d22225ef5fd703ca4ed58c3241b37e3ae46d0a744d38add35d1eba938cb55c0f1845ef6ad987a80a42efacafc0cafe2e958fc85462d07846f1a954fd71fd22597c2aabfd5a89a7327153f7d86a32feb763a29b92f5a58b29da863929a44045f6850a11eb0c095d5dadf44e725f500f58bfe6026136480b1ad65064b0b23f7e1ac645657a9b7708a67212994b3ef768eb4e362c826c3674dab43e08032ccccc5cb60fe8dfcedc9e8c907751693b29a9c440e3d627679885be0ee17a630fd637d560cd06dc79a7f44f08aef689aaeb5525685d6d1104933d0c44c155964da87f17f0720ba5596fba87bf820f5c37c1a45ca5d37ceb92838c8b54094955de7e24b9b2cd9f28da16c6cd63df2efabedb8b194d61a316d64b0d56d488d95276d000b95aba735bbba678a0056e3cd9721653c18a3c2bcd8a05aa26b68fe0b22a7a937e5e98c442cf7f9f039082d9dea4d8af857a0bf9183e3c0e65f6a7c1473d45436353fd877d06991838f0569189b143ec4e8946f258c4d596464d53108ca380dbd9561c0d4fa5b96c1e5f31e8e10aa6811350aefc6780e55ff6577c31d6718c0bc6133c844e769ff3a450106bd90c3a87f4ab349743e5023198a3f36a72212e74b9c4af76c7dab2406d70a4bf4b719b56cabecad63d70e294a5e1156a82166d28c9ef6cee1831ac3fccf8c644ae50960b285f02cae15871d4cbac711e92020d80739f9c69e513b798215c0e1c9090d516b7d869e3010d7540db6faa036b54a6a676a010da476b6f8b3cbc3a474bc0d722f8613fbc9830a5ba0ebf8749e5cf42ae6ef0596d84112e98399ffb689aaf054a763c034556633299c5bc349c69d2dddd3ad9957a404efbd946c1bbfd72345023c1d0f789653d9967cdf8ef9e0af8480304768cb6bb6377f70e8701e7af9ac1649276a40da3f91b72cddb933cd4dd0f40e2ff379df8f67dc2f12a72cd4f95a5eb8d74518c80ae04fc692df6aee770a7ab1fbeb4d316c3ebbd789aff89d166864bb24f55c65d480335c6cc09039b3dfb72056139368e4869555c65859babf4953ae2eda1dbb363ecb8d5c5c551de7dd5a8b877a6d2fd6d8f07c7903aea5ffabec277b4ef4b5d0419c00a7988f9894ed130830ea23bd9b3dde30b4565420c48134cb4c79deddb3a322939759d9252bbc7c2113798a8c28067f9709aa765215341f432e16544d0e9dfcf1782f0ca606dd2dcf05a7accce481f45f5878899e78351050157afa37590841c9118480463ea2562ad163815a161b610f2b7fd9ad9499b97e3da960408b97a4b24d5abbb7e912d90f07b42860be0464f913962950df0a4455fc86447c0419884b466fed1e23cf691a7cd926a2b7b9696a24bbd1e83630fb9906a1181f118490c5f81c10fd98d0d845cc7049185ebed91c7214cb80d49a0a9035e2bfa43cdb238f92216fccf27ebdd353aaee561623cba9d9adb963696eed3c1e091e93d7e66881","dedup_hash":"70044443154882484498","tip_id_type":"personal","vp_signature":"f787a2020f02f70fd6dcecf434073744f22d8f7b904be6a9eaa28b1820216dd1b3500d3fd004794cc0f9f14028af9c49d38467140be0efee5de203498975777c9c192c350a554d8eebb86c995bda41d4d4e24b28b8a34a568f85821494a99a275aa317c713632d3bde5825b503404c45f81ef752b70c363727e865644e1fb95b82153a441ab2ba20d41a41912938dcaeb3d39268329652375d9318778142c16e057d168b5af81fefd8293f2b81a02479aa8e2977be9062f4a55acf5ab3268dae6bc776a1a5fd55e14bb88f1d211e6e3cdac4d2f3d95fd25588a0b70b5553378cd022d8b11095dabed2a77e34ec311fb9be5c0f00c486dbfaf5f2416ad456c4328617767af377f79631a28b5f135a9388f1b0c77c0ce079750cd23d99fbe1ba9aa804f6830b9e4ec0db98ca099d6a777ab9d87317595162dfe48c575370260d833cde4b25e6e0b901a8f34068f738d8bdba976eabbd6ed36676d68ca49ed8f6f8fdbecf638b1f73267404c834eb3afef4102421ac117c741240f3fd7a33be1e5b502213eefde4a8ff2e5f51a4ad18f3bdd24894aa86ca712ea59ac331a9ca8e613028339f5b6d9160b22235d5bf49ba32e4b6c42909f3893f603974c76b33fbb86ed4817935be4ae23a922fe39d2907824ceb4ab7c02ae3f07b13d0aa773403cb0257d88b46f916c8b3feabfea1db5873314c29f66c2206d2c7bc24e40d3499220606c16037d8b643d0e8497ef9c9c311366166504f118b10d971ecc9739b1fdc412d60efd2b68e5c28399c2140d34e57fc9285673fdb9f400631c227feb142b1025f4edc970edd6980b7364343ec128a51cc55a99c4f1fb617d7b731082f77b025656e452ee93178e42ff901cc9f9684f75571d04ae9f320180f985c65320d6bb5a723a7e96ae8ffc19160f52b5e116efef64bcb48f90378fda2e14d76feaf9616c1abd35b7f27a0298d29aae6d95c9c892455028dd6f856abb7dac8dcb0dbd1bc3bd709319c0d72de2a1afcf39e012df5c40685da88648f89ec190bab06e9d91f19d17000fbc1a760283a2a2e6ee8107653976bd012b4fd545802f9c85c6313476e9c700a2d6f6b5508168db9c8c01a5c60a85eeea1a71afc55f9edec3c0eb5776712828138fe4e5e8dcab55da660f47364c71537897b5b82bbc22a67dde32be9cbfd2bfbf3b79682ee8fd27b88a675b7c8008d26b834b64f5190e1cfc678c7d716f5832e317957f10a5a6a7d83c1916c9f1e6ef8a2f5a99e4897bde6e58c62161efa4609bae5da5798025f80ee62f41ae8ad521059b505c10bc1f96e3511d158a5824d96df043c72df02ba63c65dbbfc3a5015c04a0cdabd78f636b1ea168b91c87c6fe2c2ffc9b23ab9817c7c3fab6781d14706d4d8018f58c6503c1e555974ab6ab8765e965453ad24e6b0964c24ce47af3398f80bc998966ae1a6440e7b65b14254d8b2be307e25ee2f3fdf82e58c5a93fc8ede1d1ecd92664aabb396c62712964b126e59648d09fdca6a6eb2b28bf296d6093fec0e793649fc5c4e4f4f5e447494de1d92ee15bde33c1225410da65341422aff5094cff9f32c4e5f5835806eecc8c1c827923b8551953744889be8df69407b0b96b47f9ebadbd9aecbc71943456a5cd2c618e951d62a7feca4553273863b82ce2371088b6006840b97668449bb15d0faf7203f0a7de0c9332ae4b437b364434cc0b4a0c875f434bcbd42eb8331bfed08dd3e359c9ca779c039f7643dfe0f9512d09c1ce4bd081ce93b5c95f1731d5b5e2f7f5a9f76dd5a771bd1dfe94526b8f6d1d59e21f8b5fdfdf980db2646f8a178527057239adaba2714157abf22e617ac9079161d3dd514f60b6ce930cd8acf7220841ffe91a1470fc27b17f8a09684886b323c00c2d2440127504602f492f1a5ffe2af277e4dda1e0e6673c46e82084ec97edaf55be28e4d24845b6825b8b53428d241015430840d265ddc8dbd69e36788547083a08224a52cb9cc8dc9922c37025f660d3114e7496b2b8f1f90ff39d9a48781e5db2841237bc57af5e2c7957fb5b2511408102c969588ed0b433588e8efa112dc8eaa5962133c5f8e6e636c244eab052bb809c8a9cf954b2180d931ff209d8f91d9ef766af8c8208a3bdac5fb54519c6a5896d8c94a4e45cead0fdf2c2be09d4fceb851d03a98803cb22a5171f6ddaee898421d7b269302b48289835ca21462886f0b7363aaf7390263b74a7e57c14443de018ed0ca39b94d99bbbe1d3809d70db1a91b456ed6a0f12b0592aa143fcfcf6d4452704db1293ba7990be8fa0c1a612f0e1676ab1802664b5942b88de77a81119c8c28b17912a539d2547504e9852f63addc4a8d1fd55b6f683d449a6052942ef8ac286dc234a33fca0db70726c15393e87294047c5a91a30467c2d1834bb5c6386d4b8c73170d1f8f7b521f808f47e8fb8edd2e7e20e11bbfc4201867dc906cb0b8daebfebbc3507f36b52769e0818a0604f0c4c6c1889edef40da25c33fe9f75e3f4b4bedbef4817ed994f96ea8ed57d5d331e4fabe8d30951654173b236958a9827beef5842e950bf36e99cd8a1bb6175d0e82de5d951a7218283974f477bede1704896318fb5f33d06c3e3ce689c517cb685ef7d099904afe8b41095169b9248addee4bfecfdf6dca500d9c781729f639b3c4051e17dad76efd0fd006b0212d1712991493239a69950080d586a270f2fb5adc5bc7d1dea1b39e15f14d1a44fb831c9e6652d464102ff31e9bacac705ecbc107e7be9a80b2265ff593ba8c8118b74d9c318068ee1e725f0f79793b6670bdf29e0ee505b5accf52d6e2337656c41a9ce8965aeb2c9cf40d284572f66d47db6bb602b0c98be9840a20b847ff77d599dded0e8f807d2d661c7a193665651245b64e17ad3b2d659b19bbef168a6153daae17a1a8e4a503c0fee8759c8ae3ca308a16f25bd469f294ff17a3a6514c62a6c036f4c08d0b35725352f9fd96c5297979f974a6ec5514216c58cf6a9d558f15a02a8c62b67c4cd04917732f295e72a609d9f05881e6d8b5d0871fc9182c2480246e6ebcac227c9a61bf1ba81a435f45df2a2ca9cdbd54fe9318690262a1885ead6940a01ae82eb764e39ae994474050d42eef437aa1272e683d196ed76e68efd6701061a3122aa0ebb176ce53517d0105c8157ab80df04b4202af0e77e6d71f9571fd4aba1e448315d9ba24a22d3bb72ec3ca8bd91c601c4cad60bba447586026d9a339c13716aabbe0e7085bfa570ef8819c65d6b15de79ef7a39efe79e9e9c54b967e346d04bfbb7b04b004297ea0a837b4bbe666d524b6cf4fa8570be0799a2a010327e42eba2fb1d5db92ece3d030e964ab7f27585bc0dde205cfab50bdf6be87248b76b2bdd581a57e7d176adc6e9ec1612cae1fc0b019efe8d99dd36d95fb0fd9c94ea92a3b4285bb90e2db9a6889fd0a12add776e379d950ce0cb83bae68118b7300635be343e35abace950f368014389049514f09b8734344e47a020c92d7144968711036d703a7040b72cdfc3c5f7dd4985e9f4b431777ae496cb47b9165cad969bdf572edd7b4b7337854ded5152198f4408ad0e5d2a1b168e424bef2939f186cfef939778c68578c8e41c61c36c4bed59fb9a971c751a7b33c4237bb1c633c9b4007c45420d890c7fce7795a4ad554fa63c7ac1d847db3ae9ef08a6422e806e0dd893e3d2fc7e57172d080bceb9a5eb7664b3651d3176a1339c0d0d38c7fa41752f824a2afd3967e0ed6c40ea7b72372a7419201b0ec0b404a9661dea19ecb88aaf2a8292f86f0a11138a930891cad6ebc5660ba7cecdcd36c849a92b247f54417f1d9caf9640c601f231a333243695cfd7ab203d2603bf0527d5a6d9ad81d11afa49f41f1d7a3b536386319d957aec7594f87f07d40720c85d2de2ca4169e72e2309f110dffdabd9b24a6c531a9a154faa802f025162161eedfb5363a29dbfb9a3c281ba541e73b1e23f2451085fd856a8a71744d476879fefb1630dbcdeb503f8c10f206dba475c2d1eb88add4c1a5ffd8ece0f376f67f38f993d2124d1b9be8a78de6ad102f49b8f7c8f992bc267e1680899d18c9eb04eebb31fb74885396f0122d9c2f8f420cd8903b34f39de11977ee1809396fd8af37fec0e4d78b9e500034d2cae6bc930e5e9f4ae67d99d13f915f116739aff788576d5c5414fe3b5e6c482417d1cf2472ba2e3b46bfaed0aa59c44c70649d7c263f69a5d06bf93a721365afed27bf5487f8415f5a20e4b10a4cf706b318a1ea201820daaa73ce4e75d20a269aab4485fae5e8b1f3980bf441f41a8fb154ac5b3033ce5a367b07d7c2cc6d433c2ba5024ffa12b6c937d87702b9f2f16356ddd78dbfc12514580a9686f5b8db2c958f277d28e8e4534f2505a2a3b13a82f361dc0d0fb657e07a88058a0a30cce6022a940920a67279c6b5628ca4c904ff1818c0e18c2898fc69f606739515b7edf0e3672a952a9d2e4647b467bfcd276cc3e4a776043e5992eb3a2787a38a4d27dd884cb786c516abcfee89de74ca1ad288815478bae1d641ddba5180ce375bcaa43fc08fd3365654df5b07c0db007ddb2c7768efba118659c0105305d707382a9d5d7e25563878ccadbdf0b565d75919697b6c1265d8186c1c6e4f3699fad3033383e4c5e92ccd500000000000000000b121b23262f"}],     // [{ tip_id, region, public_key, dedup_hash, vp_signature }] — embedded by seed
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
let GENESIS_TX_SIGNATURE = "c7a08c58b589b309279d320e2b41e8c0ab4dde1cca3123b3c9fa1ed7e393611d123fc9dbf22b0b2c2f681ff6fa095c1b451b572a08c96826e4a14317094a1bab540ba80248287936c01a5e961cb9a7f98c2b2b2756e27a6783c023380080d3f71edf2df5c2faedbc5ce91670fe7d7d31f308b2e66752ca77f2a35bd582a69dc9474114a10c2796077785646d1d90fe5646d89a8809fc7e221772ea0698d30d71ee2be12082cd86a3a4e1aa6aed89cbdc4e5990f26c4a655e0b76a31d2af59286d451f5af9d86e555f82083b159d4ee05fcaa75c55e2ef3565b7dcf1cefab072497f876451503ed46651643a6484c5d7d077480b015388ffb815aad7afc48f68032597ab5f76b6f9c31b70d1802a5e2db7aa36915f04183c2801045650f1574cc126d4a8bd8323c644b008560f7c2aad4428949c5d5783bf3ff6006e450c2f206a633c42fe75bbf8a78709bc0eb49817d86b7dda1bc6c5d57810ff49eeecdee3747ab248e60fadcb70a9f518e0b5e5574cb6862b11670fad7291d5040463d87c01fffeb207b17927f5bafacc9cff70bece04b2972c73e47293e8ffa9eeb7cb2d1e8c2b66e2dd8c5b912b050f71fb7872fbfc702952692a775d25fe2230e41c1fd07c7259cb5a6d313a99bbe4e30620b3e700f83878aeb798505b2985df538980045f48386d93eea996bc7429b64de838535fe0a5afd53af877fec5c8ed2a72e166745c1e46f3426f21bdd6038e73ba442e95bbd49c5cce830e180accacfb32be382a6587614baf75bb7f3de593e18b65ef56630130c97c96ede3d79ec6219089bd6524ca8b3da49246b383238b08d07abbd92f68cc31c17c91f19c2f061837043f64d007d0a7ea469e08c5e5b69aabe945f801f0ca93e279fd7aa194fea9081a49742f5f2f3d0acc8cca39d780c3becc2d17e07cb80818a1eb744178baa6829c914225f5346f762fcd35d3ebfd3e8f9a9c9aaedd7b804473fc56ab23e6e184eaaf0a86a38f0005fdd095a681040043e0709aef469949e41d223b12fb9f012b9c9285c2a4c7f68e32d862c507925c992d43c7e01d930f170eb16962905103c7d9552a25d2b8eb01d6963a392263a622acc465084ee27e6803458616737802457359485e306ce574cdc03c9d8eb632158a59c955dc6f4d4fd2c33972e895a7921e2509fa06deb7ffc0a2fe4092b5b6e0694cd4479f5450688227023711012cd17aead351df06405f3ab21e004820688bfcdaa6c830a405d74c8b44702b27b1f050cd863b7023a3403757ebfb333718002de841f4a7b1a535ef3efb167d2a218e84f83d8cd3c4d4888aeaa5319bfc33a6074ed7db7ed705dcf464dc456baeb933b169c075757e1fe10d120f072f22a2b036095f783d56d238dee8db6f47d8728e41ed9dd74bd0e8d01c5e5756f96a8134fb4649d6f32b053e69eb7c5e8a409f66e72f14eee0d1dbb57da2277bdda3a2c91f94a822bcd4a7a308de8191416d91ec59781803e89a16ecb3025280d28bb8ffa22ee3950ee300aab8afe37b10241fe2a56b5a6a4a7afd28482e21db9d4b53e6f206f757d7069670572cf782dde7fa1029cdc0c9f329e5c05db2aeeb7106112d8be418fe4159133b80b90a899ea16a66561c8a15262142d7db26a0146c1264f334dd948e77ba38be98213dc74311129e66ab0a2dade71eb87011896c9dc116eeba24e17726d7e90649f395affb7bca7d2239b70452fd8b1c8313d16803f6eca35e7e03bc471f7e3a8024a22e7d2a97270cda3f2e3974573929f96dc11dc501c9a7b85010ac84bda85d1f9373f6950b0998d8ff138e470e726b2a435953007c6032cc309611639bce375711380c6dbb59727b14fc508d85379817505444344eaa006a5405c6c12750ee1d77c74fab46f2708f457077585f4223560453a5ac7fa02910897c7ad66f63b8da90cc965d3b1318b50af3245d8ff3a2338d2844c776118a32cc227b29ae5c94b9a222229980d6e2e5b691ce39de73604786b1f62e5c62d85b3fb8a645a81c86b7c455d3ab415f947e0251600bd516bd9b5a6a6fe37d696171091430404b6e94e77038674762f36ebd0b3229a0db04d5b04b030a713b52bced8b83d281bfc9fcb34461915a82b5e204b43f285e9ee23072677cccbfc6646810a149878b914fbd9d737c2dedf3df6c4debe2cc8ff6404a1a51886c0bdf2d19741a5955ee8fd279f378f4ea8f29ed35167085fad691c287068ffa1a318d543ad6505722c85b13f38941146f175baff24b84b49b0df46fb47eef80b1a7e24523b3f0b7d6825a3d89341290441ac9f01290068e6a81723a465f52dcf4cf8bb8c2c0aa972c920df300c4cb74f0db58ac6ed89946fc47e97be562afdc20ff15a9ef09ec9e2eea1fcb0caafb5d76378f691a937d6d5f682264298b21a62b062bb2c58a757365a932f6b61b8325e64a3d08531bb78b51ffa34c56e1d6ade7070516a415fceef8a4e6d824d16572e18f7e3268f0c3ba5da6266d2f257b258fa1ddfd4dd5ec74ec1c0c357fe619e54a8ec069e362aee73f5607a72dd55cd907d96529ca816c0b48605e8bc600a2d7110771706791c3845ced96598ba14c8f1deea8d494d5300d8a50e01f0dcab845f6f035977aa08757c123883bfb4113fead9eaed673063132207ca5094e4dad7e396939862a5ccaf70c0218cfdfb46c48e6094d857733a1acf081fb3e1d346ed79875c3d167cec6d64526b11908cd1d244fd2a99eb9c73840b46ea5deb35d68b026afb22ad34dca4b613eea8041e0e6513c018b33afa3046bd32069b62a74db28be3098fabbced746576f03bcc0779a4ef6793fb9f51197f989433653a6f41a9254dab5774fde2de817196704fe066e565a1fd0311675fe10c96268efa4800a00760d307611e836139e08aee04bf8c19bee3df6d71123d8d876c5b8050e00bada70b654f873ebf35faac1d6263825e5005d104cb8232d67693e335bbf2676a69d5d49e8778c9fb81987a006b575bb3a8c319f65f297a0adc2db1f99536c2289e7e81ea8369aa64ce2e33099ec591b6030a4f44ab5349d494a4c5484517e6382a351a74ef80c32307f7e786debfb36e65238b906583d0983939f299ffeba72d33ab2ded8ecaf233bb5031979314fbfaef13cd16c322e0a56919d0280a4ca2d47c0600afa67eb269f745e12f22c6cefb71cbbb127d6005d831ddb3d2d00da9cb656ce15058967e84ccc48974aab4a29c9d6ce7c4ae24e1abd134a285f44ea5b19d7fb701a34ef60135ba4c097e5235d793dfc52c89808bf737e5ae5e7f5b019f14b3a273ade6bd2582e644a61704599b9e95dfe25f1b84d9c0ed038a71713d2292c383b0fef82b081e474924682bf9c42b501c80afdb20548ee40cb86cef1205276011b41f361643966b634f839c94838fc7e4f3057d771ea9c81392f1ad145476a5d99d653431db53c672a869461c8ce49ffdf51a1d96ca47c1abde95e7aa30317f2af500f3b1f14ba581a8e4c03eaf92bbe74c1396353b7af1b4068254240fdb727e7a6d92ecb5807b3eaaffe9608a10e980375d349085580f55f3341d7c9c8b7458504aeb0c491e6df437cac0b947c52049d5aef380248e0cd18459ae3b29165e220694277eafaa7d3b47a08f048988e73fe84d119868a42dea1e252048b05cb2daf9cb0dd2da2dd80db0123069889b203c4c95b6f9f99f51629c816c4696ff3da51a615d849982d684306c371b13687b48b898e50a9443964f800304e3db205b688a294b9bd1c5f28aae7724ec9eae18f65d446c8390846c0b137f741fe00b65666df37ddae1e0df13112e99f63565b7c0b2da82175277301c85daf417cbb24b7858bb39df257d1204e9ed868ed512d2b86b7e0af35c2aefdc88ec920aaa7469ad683bf30c0a5d36c4093c0239ba73d91d551cc4c9010e50ea98df4aa87ecb8ae5f2686a9e3a7f53149d5fbc63dbcdbb0bd3c12d378f15ec4cd02bba1002b5e6229b9b3474ab6aa8f83e3d502af96bd41f827d826c4c5f0ecc405435adfacfe26d08536e96c1514bec9c9857d1c3f42306909fe26e4ae5f1af7d3a3a012aca7ad6c8e7fcfcebbb4a05e0f4fe9e663970a1c7b19de1d746f01b855b26e6a6fe77b6cd82306fd8c3c81f8bb576fd639883f67d07c3c81bbbe310c2f6031f2c0851468a26a686f88159ea01d2b613116d76c2a1a69c829a232166e221c922801f80855972013d64ece1b3166807fdcdc4ea77245ad09a07dcc93dcf4c9eb3069675a18c7c7536a49fb0ef51107abdd701b71aa043e852755cb39adc02f59d907a3dfd3f6f5a3e630b9569b11e2021676f59d2537ff0e07f83b4c228bbae787aa802fc0afd52eea5102cacb8d17f898a89a870c1fd2866a82b0e2b500b970a6594e4ecff6aaf429b232f6ac4d29260bbda423ade94da081e56008009910a05c7acd05de30fa61e2b812a6a8c28d5ed4511d6cab16ed1e08b4a2f84127711213b6dec3f088dd4fa6be0b6d1fad24bc520384a12b0711f2ff6d8d4e6b6ddf8097936dd1b9d39614b796f1d02ab94fec961d7d829b9bc2fbcb9d9fab223fd78c9b353ff28e273395f738605b475caf35321768b9c09b52d3f04898fa9c01c6998a9b2e8f3224b4e536adae7f33d62689294020b2024444c678ba8c82039558c9da2b3c8ced6dadff5f8000000000000050c14192331";
let GENESIS_VP_TX_SIGNATURE = "0e47a3c2132372b51e4a3607501765051a6bf4a9d27b99df582263abebdb98a62fca8763c2986292ffd38a6b48309bf99f143223ffc785f16277cdb20cb72051eb4ebfccb4f22dc6b3f5ec3968da355c50def0c829746c2472dae1b0157a7adc47c4d0684a6dab9cb2e7d672905c4c72dffa4e78d250e6e3b6d5de49240a786d6009353824ee960e23fc0046eb78747d506eea669fce2758016d0a4ca9f7278d77c6204ffcf54eef7924b7c315d594f0f8f292419377edadd035870dfb2145ae6904fb60761a3ad3cff435e1a0d2b598d6ff0c25edf17fcdcd21f02f09e1b8453d932b0ac61aaf9463f1fe3c134e5336969ef2abebcc923182c5ea82d13de52c3c3d89e0dff2f8fa07b849e1ad224981778fcde9e19724198745f5993caba0266c7496784fcd78bc3b0fc2dc96385c7f0fbfb5f4ba3d38ad704ba20e53840b722d797449ae72e175181ac182498f874162e0c89888cf65056f53429361579120d67d12b6017dcd470dee76cd3a6e1fd42926fa5f57c8c45da434f17cf9cabd6f4e6399459b7d99a122bd6721100e29b35f0edc765bb4ea99da22737a16356eb3f8570be0dbe69627676e7e87e34a4af17a9c7e3054113de4cfcb33223872e62e30b1a299c95712fde485035cac89fca83738ab4e90259bdf0bb34bdc198058c5cba9c89f14fa2de2a09c557123f107014c93b1c40358eb9b9176c0d16d9fdeb568d070e519a543d16d9393a748edb5e922c2b82d9f8f1f053e9101eff055c146fcd2c16c9b99c2081be8de9bc1bd8cb765b69c81be504d40b805a27db59511dc8386df659d138cdf83c0cff84edebeebb27e6af7a09eafb1f20fd34343ece6bf7a987ae2b9c8563d44ac7bbe725006ffe43318a1cf04b78498f5eb1360eb84f268c38467ab92e0d632d7b21b22fd40fddfb2c42c5e6c2098839af452364895a457ff8b9d85da6f99947de413af18380a6bb5999f994ac47b71057882b31745433bbc7e0fea61ed5186d5d1b976e565db701a1ba9303cb3747f99c2c7b989606395c5f7cc74e17bb851a5858276ba70f8cccb1cf1afcbc92b337859ee2d900101d4d192422245a1319534c4bbef71c33a994abf56e675b27c013f0a510c5ad9dd04a03ebf62075a72209bd551afa9c3faa878cba4e3436149a05ef54dce2a0d159a29b12e5f845d95cebcfa9475c3819467f2caf70936a693a05fc26ecdeb90ca94d383d44e40c1d1b3e0d314a587bd98b6d639e4d530f5a0ad84859dd87d9a0c0ad55dc4760535e07dbc6500aaf78e2531a3d0ee3ac1ca8ffeb674148b465501ce42a55a8bf1c6ca17b4d71c66b8fbb60008cc4c3e93a4b3d0d83181dad65fbfe0190263390d98500c64231a09ac6fdc20052424af23994122d40c97548e4c4bfae3e17d16890ee2c47baeae2811d5f71cc79eb410f74f2bbe9904290cb46c5b5ba14b57812bf37de0fa72664c464c39dda766157937492511cd56bd0600c38aca34f5bd56b49b2defc1394aca1bcb70c80b4235097923a39c038213d805e766ebad37c4c250705cd3ea34ba940af845928e571adcc924a9e3a00ed1fb06d5bd6e8175d5ab0703a26906147a3ff3354e1f0b2615090220db08015259cf96cf0d0078e8e16f4fb52ae271a7ffee80cb10d955b315cf642cbad7ced8f7127e3ee4d3b0a3cf14c9c4a3a280f6b2d4dcc8ff353d3e72c963f67c383dc877e107c28cabb72e226eb893bbb35fe9670d4c75abe606e930ab19d3b9895f3b445031f1f1dde066e003f8dedc88a627e4f23320f16afbeddd02838649041b95ecd8e4351f0846836b9acff73bd6a73a401b3f999a67a5bd92bb07b9c360007d10ef5b70b82526859d235571d74265892fc23794c0384c2ebdb7a8b1ae9187b1f1b8fe125efe778f1555163d78b549ccb9e2ffe6e5894009bd813db48257c3f9b7e17dbc00e6f374fccae7ce772952e039ce36bb6fa9b6278f79e886d9712568c7102662991db0e956e03fa39e9c315aab8c8cbe69024d30e1c79350484c2d31a3f36066179cc5e7da767c309c503fe2dfd00254e5b67350931ac5ab3dec2ac6311fb40506b4f9195be0d4eabfd1a164980b2a5aeec153ee5058728fdb6e1ef9e392e86c14ad81ad045578d2b093c0295d19abe15ed4ccc9b9a19aa8dfc159bfe3cb6d42e417fba252aedaab9157fa4af24721cb443118d0dc459054eae54e20ddd5ce4daa788c09418b13d61f6be777e79098d10b8c8c678a1791dc0604357e91ecb75cbd56bb676c3d55dd0792e9be4fca5713436af2032820fb18c6b1f797a55b0a1e53392e1e559c70122d91d435708f845f841fd91e756310be25f2572ec6dfd7065e85c7bfac48bf9ad7d75b40229fcb7f3c289ae924524570f5b9116a03743977d2b948c947082c6df0a352e7436f92d43800e452105d4180e353c7dae05916629273cb59906cb68202acfc6c5b7f401e5b654f56b3a0328d6ea44324a5e027e8c56db0507e2bbd4a1fdb539fb9ed90868bef9016590a6392e351534bd2b946819dde79f4b2a98f437a1a3f4002b51050dfd8810df71e715a9ef6b2df567fc0422a5e95cda0d3262fff7938a3b822e0f41f70a2867d06e9ff0242172654fe53e6dc997f31c429e5f04b6f397b33cb2bdfeae627202f199a29662523b582b74a2adb3dd0eb0c4e25732b07be32ee682195acc22dad99427e3ee26bbd4bd4efb77a8d58ded8938e028132af9f1e189926ce4cb23f160f43d757dfc4a5c7fd1ae8cbbff879d02078c58cb6245d4b4ec31ad71a7f2d7213d47605e8a43e389069aa79a1490098feb38a9903a17e154fc46a6bb35ca89c39340236639928f6b62c22ab996d7dfe079ab3856749c6ae8fdb33aacb0d4aecc777f5b7b52117a9ac9a4c2e210808102ad32523c1fdbd48274b1d979c30c6841244a6a1ee898a725570b3564345a0bf986461ddaee01acfd37644da97f3c00b46076e72b4734b80cde31d1d1ed5c3f4d4706645c57ff7c9e5cdb261ee2566f94aaf6c9d40a095f0dffd1620fd2575d432d6fe6ee26f884849c581732fe0704bf4f22ebe3465c7229793b593b7251289fd2bc15966c640f41e9dff2731a0e6cb90b3c676ff641c8fc6682b9bd3b832e3f7691f77a30b78a2516e894b1818de824adacfd23898fae5d05607c098c5ebb4881cca82c37b408ebcc2f94b6ea949b461772db35880bf614f9c50c0691f40f3917fdac52852a64a287b58e7f8a7a8f0e479fa378c601d613cbc91164987cdb96dd65ffa354fe13534fca09cd3fe98818cdead453cb09b95962a9b2e7d10609a2631fbf06135125f849decbad66458a5817a261daf3a8d75c7bab6face52d48ae52399391c013e0b4c20d6816efc5021df8815f0b73fd268c17e14a519941a7cb3a34486135900c1050157d78570cf94514e2baf32f333b307e4b2ce92d4e8a9cb2786a45821af3985eb62ce41fd25cba160a739bed7c3d6c45b6bebb0bd4926f59dadf00e128d1face0d443fd8cf89dbd9b0c8fd0c8986163729fdec6ed69dbac19d3d846b058dead9f27b1dfa87f14bbfd2b20e7ce3299a78418847b1ed15f515f7236bb3cfff390f02c4ab591e50abdb18e9aa3dc5437e4637004bf9f149d0c770d553677dbf98edec5e4854a90ce6e7a09ef90f11d05cd2794873a67b85124204b300d4c70ea99cc92eb8eb16c05d051c8bf3a3332f295a5f76c194f672be9e6946383ad86c78499429ea23b9e1516d0959230a6fb2901e0c17f8a9bfa1f2f655f830b9c7c13825a28ed040cdbb3ad69f86ad52182e33271e4d5cc2bfddaf5396e9609b5cbedcf02b007b56c19f2f50a0a420c06a7a91459050ea7fa365115da00b36b466c2bdb301e497023f71d1cfe5f1a534f296077be17955275263fff2c4c0664df0fb440b5d004b52892ace4ab8a1a35e3dfad524431ea933f7e2319efc746d75645997460a877c7772097d7263bb3c47ba2a07cb82a0550da00888e2308fb1241a744b3b33fadf77af99a6ec36b2de93184475aa59b79c25397406a9f9fb60072adbf79aa21b47fbc6125e1f62bef6cf5cbb8358ed1d64e12b0313a0658415916947552f8b9c85d64e0a05506e0c9ebe2ec36d811f5eff8f05d011febcae3c53363b2faab2b37157331b740e6493562bac1eac5db9775d77fea336b12ea7f6d290953806498051f8ff83f15411e12df88c65dcb6d05234f6ae4cc35572e651d372c51623d59a913daadb3f791a3a1618f55bfb9f3926de6e406003dc37418fa6f5c6119f997d411711aa418bee2a3b4723943e5814125999d75f9d18f40d1005d43efa30cd77db85e71964d5ce604b91b3f06c445aa6c0dece488b39e76a4b1334f07fa43247be724bcf2393017a3bf6773a3ae440d71ee1ec405a0f6e91a115734942c4129af6efe59be6a10ad2143143c6738a2e155c2904b82c3e0c60d2f4588efc288bdbad949a6d37844ff6feaf153fd1aa32132dfbe3034414de7049eec72bd3429fdfe8c3f756f431a5b9f612c6d4f2b6aa8c236398db880149dd8cacbcfa8b4085624c932c84b0300a0580ab3a912abaca8c5a100649c99c36d72cb6f9c82fdad5d7ee50117304296b0d2e11e203e7690a3626770aedf3c8da1af4089afd54fccde00000000000000000000000000000000000000000000000000080e13171b1e";

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
