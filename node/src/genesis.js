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
const { shake256, shake256Multi, generateSLHDSAKeypair, mldsaSign, mldsaVerify, computeTxId, canonicalJson } = require("../../shared/crypto");
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
    vp_id: "tip://vp/US-8c1675d596e68736",
    name: "The AI Lab Intelligence Unobscured, Inc.",
    short_name: "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction: "US",
    url: "https://theailab.org",
    email: "trust@theailab.org",
    registered_at: GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key: "65d9067ace8d3bb21d53cc759f498f4dc40c8913b8fcf3c3399ead8c5889e5c1531aeac0c8c483700685c3862f0d63a64ff1a84080a7186720db02c6321dbbb17d614b7295d282352c5467da34e3d5de0ded3e96f880710e15500b4b21c60b5c755c4fd35c0f95225dc3a2027cb8e27bf6c886af9f54be19d2c3923da9c6a847d248c42be89795e29acf44f2de75412840e297f5f0f7be34002865be9907d24ce96f0c8e6c8db0b75df2bb8894a6cfd8b04a69d164fc46dc358a4aff760664b89ca2e9d7bfa20dcab119eef60c7bbf376b8cc5f12bc0724358c313a9394cf602648d27ad785ffcb2fd34ac6128b7b9a325238736f030ab79cedeef51c27750706835c3d4fee12d010bff97992cd860ae18e62c596c3489d7f3967b617c15fb3cabd04ef92af98b2dc006ed83b0fe7acab513dc68345fd4566d6e88fe3b220758d88942f276691b1d84f9f9ff3cec775d1c6acba1534caf1e4460885034c72db6c49ab5852ccd17359e84b29ffa3be9cb558320d29cd65af5bcbdb30baa4adbb61ca7be20a32a9ad4cc2714788998ad21ec0bbf88bd604e9538a94c368b56dbdcc8cf52f2f5bb0f075d3bcba2d528037b562d4307acfc0789dfc5444d4dbd3d5e6b83d75dbc69224f561f60d8435160abe076eb87739af016979c896fa7b558af7f088d6ba3bacb243856d5a60eb4f1aa8080d718286fd6f27557449c7c0c9800918a361ffa05ccf50be57e59dc811f8176ff94e8c0141da619e2ed8131260b725b50a22278c9a4da750668815471785ea311af019d3d1177bc1904ddda63e5db6ad391f0bc6178d7cf20206827bc1b4b6f7547d0c471776ea7295b801aeef558b75c850276d83dadf094d4a10e830af9c33496b1bcd89aec2477b42745e07440a1faf3435f67f79781307d5a0feaaf185e355ca25b46b9a84584c6af406c6d88cf14a134244ed8cccd74ee1b1b4e6db6a196623a9ff11d6431a47fd22cc613ca24d516e8c31a0c63969f550515a6daa70f77dd3314fe68a21728bcbdee570dec90b9445472edbeb23d1047b063a7fe265c70998df322deba25a7526ad9abea161c82ab14afdfe03199adefc9491d0f63f39c2250af7218bb63263849faab3e0003d52761d149e7523dc7e45f27240ffd33d4d2c03cfbe88a24c7ee8ff080df85113c42569a2d60b99b3d1f565e2fa05b4ce5589c2b2d2672011b69c4340d3688ffe749628cf1267b424e5c0fef12472ee48bd220556a0b813c80e742fdee17d2aca0264dc500e6a37f0ddc300d385e1b0e0551fd6f8d355b98f22e6ec559a9f06cf92c406546ce2b8c6998d81d2cd0f446ff714a35eaed09ad7677571b1796f7763968a2e50cd379338bf0e473a00ce4faf04d895125318ba066b86a9d31515493b25925ee80ce134314530a98312e98c82d78075884a2fc1a9b5917f4162dacff71e0a69dbcb124296a813b117e506d4fce0478168b0d55441c08b3c500bcfff372e7f84a15c70c2f88218b8df2d80185a1bb1ab42d0d6039f0b6ba72bd38e98fa5b6f6b64d8e371095e5d3604ea79a64d384c7c8aafeda06a6862052111ba18c3050043e7e35ec87e3c3773dc0d7d081520e451be1896b6e57b111f8d1fffa84661ab6c8893884a505d984d588c4163812a55db920de1a9e2c381e35a9b337c065f0a949dd755c98b96425a71e97729834e3dd7a914904b38d3c27b5d6fe7ceb117e45e2cfdbd705bbf66503e83f3772b864886d0d1bf3795598def884c35c50189568d3896066d82aa0fdce7ec51da7d29cfb3cd74c6ba25b7771c1219ed467cf4e96f8cb6e21e506b839ec23b65240d7e3c9cef33d288fbe024310984f3c8d080eedc4ecf4244b362cca495f75dfee8a672c245afdb52133dd4c5bbab352f8638a50cf84c272656e356e05c85044568617989f7c5d1e86157efc85c41d445a182ed571375406571225fdd5a54f3c1eab03b33c502e5bd806b8cca51891d77fff196d90873cdc09717409f07de1636a411aad1cef3bcacb781f998bd6e9c5099528e3db9d4ad6c1d94256cec12f7c9770d1eb8af88c662434fb761dfe26764eb5f527ed8868bcb0cbf5caa0a5ec2d0f78ab785289842695f793985ca07dd65edb25ae35daa23ee0789709b5f89754eae67d7b54b778ca4eaf227747a0ffaf3865634eeafab94ddeb96fdc705d7ad51c3d57eac69ee5f267b696e4d0e8211a9136197b8f2466c3840e78b27b9bcb167e81b79bb9016c02390363722b04b7f443513b18832166110713ed21e9a053821a981d86612cbadc925f4bf874dcf208487f0de6730e0ba7bd7f7e37d1ded70dd93e4a75c97b1216c42e6700f6e30f36ae106679992c9f929b6e91c9b05d482daef794acd64f93c581c41983824ffdb48eadd8ce4f059f9f85327006ec89de59792f3155cc4729205a0949212bc44509eb2f7fa5b76024c2b74b917a59ea74c4e1bd77c4fc45a36640f8a040cadc382c8644af10ec2d1b5873d9a2caa96300f804360e277e7fcd019f35ebb41f4d30941ee0bb2d58cdd4fd160dd57163e8bfea4381d73f4f102f2de76e3730c629f8d5ddeb53660dd5e09832aecb2438d31797460c441df0a033043825a4e33644ed5a6b27aa3d0225f83b07230b106a5cfe424bc32dceb544479a4aada87ff690491f1e2f1155fa9a986e06e9d30f3d81e454ceff8e28e8f1a0158703af1e2dde2b2ca36b2c2959afc91363e515cebdbf74a89b7bc9643fe8acb2c00e89b1480fcbd2",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  // Founding node — registered by seed script, bootstrapped by initDAG.
  // { node_id, name, public_key, council_signature }
  founding_node: {"node_id":"tip://node/1184c980d1e032e4","name":"The AI Lab TIP Node","public_key":"91de56e803b41aafc382d60528d91b043127a4f90e51738b893e7a1222f63dffa8c7ef68a41d48467193d25a52be10943f67e4416b11d33776ac66fe4b8b3ac4ef83345d0dd7aba6853b779ab3d8552c2dd32e617a714f80b6bb77a1d5ef3055daa7e4e64f8b64c9f9c5afe15289f992bea0a5de29f2d08595a190521b5e3c4af745b99b7538275a8bd9f82d3b634e1db9f5da79d6b0635133daff5a9581dce6a60490eb729c805ac6509d17474d3f8531fd955dfe87fb6e41201c3cfee5dd7bb15491f2d49ede51f8421a3ba1e42918556474641c21b79c858a2bf68ffb3da6d9643f23c1cbf5206eb87d939e76d9b08e57dc9fa2cac352aecbd3b33753c9c49a399d5616e8e7b062069d436d18061441a225a16831cd4a590f9ab6efdfa916ceb0c731bf6f88101e6d742a20876148ec1764d00bb3bec79176e2d285327c750dab6980425067f8cada5d6d7cb1ab02b919a133d5a4cc6b68db79717c92a7c3c15881bfd4fdf078135b7ce9041c303a09e59743c6b6ff7100cca9df13ef062b340463264ecf635eca6dab9690a092006c6c6f75fef0ea7d86fe50253d323c021efd6be339c5f463045b95c58b467190829cd59ef55d30fd020b489f108286eea089665680b85f3fbf564ede3a8ba48b6d7943466bc4c4d2f8471770148dd16bf427cd7c53ab9b7004fabeedf0cb2d5bb1321a1d851bb3d54a20f504084036975206a4e8355b8f89e5907d2dd5950e5d938c4a5c9a87d0ad92558c9ebceaf258491c8c043569d377375d010788a6290971edb84525c7b67a42529366fa0173637b787ac8efd1f59ebbf879293991a748dfcb3127b5537728c9c49c6cb0be1957dccf1b94c46cf0896a8de1947e91dd333b7da748a453f19620b8cf12c5121397d59c7962dbb89bca28eb67f58ae170d4cc2fbafef494598e2106146e1ee9c52d4a3f4fc3b8c1ff9f5f9972af0a2cde235bb95a95b787c0396b080d7cf3eecc2175101a5b592d97080dabdefbb074171cb4f0d92e51ed2f5ea4b9b999573a0f0aea6bcd70437479316b8bd4e23ed6d2c865630c2fcb7eba7e1b7318e21e43157987ffb47e4b134a1675e9e2f5f64fc0c3f1e3602534c5b652a917fb1a62f7d3f67ddeca29c4e2b5e2d1ab7f94cc9cf0cf4137d21aefbf2eba8a2722cb4ad2588e6654e2645eeeaa0a549c2666f9a4944794389307bf9b4c8bb7ba0292c1aeea2a4e0fa2c42bfbc1486b01fee921f54081fc76bf4aaca6a9c030b346f72fe40bb83664e01fce1fd24bbab4e773fde4a52d5e13e14a474e9b14e5bdbefb6895fcbe1664ba7abc751e9b9a9fe77e5cf757836a7974d1962436d52665df1523c493c2d2be692225026be0fb75d8ca2aa0402e1ec4c008810c6f546ae65fe582a433be65ba6c97d243f81e8493b6107dc2872e9dcb416204214adea5117631be2d321930922215e0fe797ab53468352284841a78d27328d8fe823c961fced779dba84d2feec95cd9b04c781533575023f8c9686dff06bb73ce7d25399d78d9ca5b6faa5eda4e9151a304c890a206a99790b00809df337c9bd2a9dda5c63ea9f8fc73431722f78972b50b3f58b9eaf369c316793e25d8e2fefe62c43ca8d49152ba03a1b4aed7bf2baaaaeda6bca0c945b2c6d44039a177a37e47842f3b56f8304a3e9aa720af43810b28380e7dacda148805fd28811d4529fb04074b13bd88115b9a634cc8729475e11a69f4e68a4f2227079727c86bccc143933d3605eb220e8b4870f137f2078bb8661626a8a5af49a63ac0f690dd9de487149c0bf4aa329732dd69490c3d0c7bb3480b5ad0fd3cc5810798deda63338910b532a0fc041ddeac2edbe53b846fabf921569904488124a98edd7406bfefad308101be95905f6401e5194dd899dbd4019b2fbf72fa8a3b83749e7f21e7d44f61f94734daa0794904004b20d9526f2f4b10ad2071a37ae5561c3649ee28f24478bb31aca7155e03ccb96e72234e882362ddc7e41eef29e39b5f5d055d24010f93dd4b31ad75358e867591881b5f56e9d83670e5114c31fd9d0d8754e17024f19870e06d951d8763f7af22bc17e08ad0b5dfa5558579b7678529960f939174780877eb03c6fb22cca31abd048cb12258a3cd1dedf6431818657e9065f9a966b8234dc5b03b220b7bea239cf70ac486b60c85bfe23e92805d0a300b787bf11f528f42fb4d0e7280ff7900a11786bf2a02833729851ecd5fb23a0fb91a14e7554bb8c2a750b39c9e24145c448fae7143ca51ff34b10eeb897b151821a5e711f7d7a613fbe931834f43a43e2eda519979694251923bcfc8c2ba6f6e207380c8b571c7b594631a09ac91e25156be5b6680180e580d59674f566e4e7d6622735a8dbb792f212ddaf4509eb7ab8b9a28ed0bc9f58c82c703d2449b58a9e0dcce94b857ecb3f23ebb23b334943511486d40572e2d7dbf17b81f26dd9866375f1ee5ca41b7b1fbd11e7569a494251f3ee831a94f99698e743fbf1e356a4b2a68c9cb12776370af97b49a838bc9146c914213b26032595957d327762d8aa90f110d180383637073089e6b503e0435ef2a26c3be4b3d7f1917b59098cd00296345e47b7e88ed4d7e7827362ca198cd2bcd95f9f750489ec3e64b67b826271ffd80d09bcad023ebede5d618ba8ddce45cc63d99df6f4c8f542f3d3282947e352915fd3314955e270d7046f8504c0d8f1b3770f4b259254ab63eafdb67f6f4b8a491ff5e862480873daf2013ec8a630da3","council_signature":"974b4611f432234a02ca9cdfce465bed98bb6fdba2d185b98a7ec0be8b4a3ced2cb94ea7fd8089e5ac5a218c271ee890414205ab7f907f99d492b129c9c92ee9d9d8757d6aa4ede5f0292965195b78cd1fd158dc62ee5af0efd6f0f5619fd9ba0a854ed65f9705a186121e667f6a21e204455a30e64b1a7ba08d1d044bad264f69193af9f1b2994a89bbe570e65e44b0268c462f0361bd3c257079d6eec78cfa62b9bcc405755ded266133cabe38f01f8fcbd8a97a658b83e36b89ab13326fdde20d32a37ca3554278bebd52e756917535fe5eb676797537ff2cf783b67b0922ff65fe0a38e70fd88dfd6324b3ca058e3c6ada23620174db49d52fe5bc2ce852121e3127fd6471f129e6c6314c74546c48f3be0137dc89b6c67310e4af96be5a18de36129a21159ae0920993f318ce55367691df5b2ecd4fe06eaf8f23246343b28d3a12753601b530df1aa6cc4d2adac3d1bf5c2d89b2931f7e106b0a7e8b3fbcd64b2823b11468a50ba02a5ccc26cb178f695da94af93b15602457c799d87ae031f2b1a3611d19f78a475f7a161fea7f184bd9a773a0d6022a8321475020c25491e51f038f19475b45e7102e1019cb1536b94b7dee84600d5c324dd9c9f9601c8d33545fe7c7559740359fe520fe9ee286c90d04c9c9ece85055255191fcda803da5a6cafb20e57fe9417eef5a71be46b727e9e2c3f50b6a5646cf13795f7db2d186222cebac226128b238ce0126fd9b4b9c1b12bcb9d7c98b1b640533bc4b13fe1068f93082f768e32c89734a7fcb036f4f01185454e09fbd6fc20927d79b52911b3b37caf16991dc15d8865d5b8867395259ee58fafbc6c576d910017c5d464b0512ec8d6ee74c4a871060961eb10defb1fca1e98f228b5d3d6c388a19bccdfa62508bf52b3696f3a8b4f1785a2dfb98979af391c1972029afd96b4f75afd56355211a08b5af5f21aff47bf1ea105912016d4a18d75693f63e2f5e369c5c056ddac356b4e67a656c02dbae81075450ac459f795436e5a6ad249001d4b87eef7edd1ce5d39a8b27d54a3b6ce7835bc3ec3b86b9884992c6d0d102509a58e7f93d05c64c3c05c1b0e192aef1eb72ffe5f506210274b807c55ebdd72e1e187bee89fc6b892927b4c44e27571495ae743475a13a3cd45b549f9eb64c934d5dbf410cf899c6c45ed89683932ca7f334fac072cf36f0123d780f63601c5fa565edade72e2085668d9b1234521c37ef717609797aad4bd903208feb261842cb97097c029fba4e4236b56da413beb2c9c936260dc8ac740a88f5a5709c87df67d936008d858418e1eb344348f3a1fb2e9da82a3401059e466cbe4421213886f833355d3b0079344cb92b7ae16c9b2c3f6b21d09720e8244e11965938e4081eeaf3bea01808b4a2dbdcb3216723723598afd95bceaaa69d6156f2a7acd3d64667807901e01c547c50e6b760c962eb9d4f3b7f67e0621bb6c5df243ab5e4495f3a31e493e66b84b326cfe17e2133af7375eb5ec8ac36d56d6cbb82479d6d888b35cf89930f4c63252b462dbc1e74635ead5efd7e9d7704c5a58d3a743a3e54db00397bd824fbc6246c394981d52f5af8786cbf3e857c7fa3a65756f179cae43df422eeedf7fd149d208bd70348ce25314086198c8c435855b47f5cdcfb636d6ca3c2a28f70a2628c2ffc19071a8aae2a867207a1ae782bbabb5435bc83733894b0a7dde26e7a40f99a94bb09a155d5f80875e24467cfe825e361d36dc6b25eccdef7ee75456516c4a5cd3cc1b576a34d939ed421f6498538738aa225120606a4acc13b8d7df58a2469a96cf6a1815c3b682238c556af1401ebc1f3abec94ac051c358b6822ae518d45c9123c55f1ae38abe9fe7c0c6cb7546debb1caf442eba4ad5e1bb8fe409d0d7e54ae135ae932ebce7e8a7e99fe0e62e60dbef7298a713180318e27326bb72a11e07e1074d574493b628ad841ff357ed98345c8095a828d67d0e527fd07a2ba4793ed2122d53b6216d273e8f12c1016aa402cbdb1be1c245844a00563ccb122a8883c57ba3766951e33d93328f21340e9d821389ebc59ad7d7789bab60b0fdd3eb7f80fd10f9ce7a9e93dc3cee6eb786085aec3fca521d7fdab33bbda355823f0a47f9d12841273373aee478c5b642df98e6d3b2bc2112b90458809e4c06f245406693f4b35ceb66748fea372457d57f3c51531108b02b928c13bb3093362dd05ccdcec3a235f83e5da4db2b74dfbc3b885a160a490144619f323ab562ac42f58ab888bb56a7de90b45ce7c2319975753259fe41fced6df2999322ed8ab6665f76abef49cb79ff95f9ee6febee0d5878bdd07891ace3c3000f86f5ec81416659f41e7a5414d7b75a062c8494c686b7bd7208b9b960f25474ea30dd9461e6d5697be1b89b2c29ad77dc71b87cad26259c43041bab956f04d8e7b7ceb74bdaaeb7f6eaf665ac98e8f959fd134ec49eb1b2765629904587d29317f710aa8f970c1c1b96972f7ce36905bebec6c35895bc2a2b49bdfe3272fde1da8a2e103214ba602023c85bbd67ce9e5d2883606eab2a9e77166022d408d2bddd9bee8d749392719c73da46a4cc842f526580f75af9d2ce873a3c8d576e6687378f89792849c2f236aaa9b59ff05cd322c3ab830844a5d6f421accd3231373626b10a7a5860b1e49a92d93e290115353a4f3b9eb7c30b64210dd1a0e813e1fd6f899c516f43dc0dd9a2cfc8a9524aebfcf95148d07b175a1f495493c7b1695c08f43c8a70b58c10915eed72bcd29f1787d949d440bf5a44bad60a578c37ad5ca31de649334c171fe213052496a47173b42e3eeb83d622dd2f9bdeafe0bcb4cb010e4a0ff8eb1d4f3ac56a6a51a4fa67aec75bf7a879da2057e5746268d0f1158ed433734e5e9f66c13446d5bab1022a88e58e6a65761297c3eb6c670877cf9a7baae1e0bc5fd7b8193a7b4c77ebc85eb30207c9bd3908d29e96121525d6fd82b75a3279cd078f6f2e5bbbe60da09701d9d073a5a0c0d94e62657794a6851543fe0d99e8c5532a8ce71f1847772b41b5265b25a8cec7530240c3b727c2b5bdfd33e79b7f4c63160d8e6fd2485557ed99350cb0ef77bd431f56375adc353baffdb47b206b763a6c72939d2c46ec8ca849f47ccbdb2d410759bf7db6e66e092b335cfd76bfa5b664d72f971fd60429376322d08dbe370659c6c9d6e952e94254088a7feddc65c5e068495518abf9802bac93981beb6f24d8d51c46e37eeeae2c33aa87a981481b97a77c1a35ba0e4443bb89e4b27b88d976df339fd3337559459a1b8a2d347effff7889a2865ba5031c70c537a22d92d6fda1e37371aa68d71e936d2db19358eaace0a202c90b75b98b4affd58aeadea935a731d0669a6b50cb2d9997a7eb20267e7171175b6aaea36ce1ea5d8dc4795654cf6d6e4954021c360497335fe6cc269ae9321b5c5ef20871ec9145ec20d7d491d3ead3141e8261608299a5b94fa52150567ef88230debaa4a7b333e95d498c90db57c14fc037e7e4213330b8f1877a063cf1485f4c24f5a3d751593c62bd56eec6d44b78eab24d943689fa98692e012470886b92200f60c206117474538c41ecda53bdf7203cfc7eac12803a7fcbcf9b8e0882408572cc4bc81e42ae118b4f0f23bc2002a0741cb5d0ec219bb9c8da1a64425750cf7ab84532084ddf9bf08de170fbcf2ce1747a72d207c8c9c61b9461051d441cad359e1cef43c7d3ec27448ca52519f6222073dc910abe068a2b5e1633cb9a401b8ab79f2bffd80b7f5dba0379853c69c638395757ebe7e584208a927fd9deeec1b7942903168785434e6198f39b86410dd81bc9978027729a7da3d7bf6e32d7a39f4376735d2c7f1244b8204c86c5bcf4524dba3018cdc896107a32922b6625e5c38a786b04467d5a7e56b8787f0e847f306e16a2e3e6c6c9d332c4edd4fa6e665d5641be759626a521f7fe6d694c7c41503a20ea6e55e57f4dbabb18fbf58cea95931315811dd2e1b883c44252f89d2dcef38ef16df17795ad09b26a741973fa12a72592667a01c2fc9f4545a461842ad1dd295c09934bceef630ec8f1fc0029d59006eec2e44b44b504aa894352fe60cff76fddcfe2a37b088564465f0c722a9a95da46c1d008f3be434996db800a783268831802b175bdb1871582417758a0d94b72f48978f9c2258755b003ac3a461b277060c321837412447e108d36890c3ef90834a2b90780e2111540b0be725cb78e91a69a5afcb09bc1d57cf25effd081e56c408ae38d737f414d984dd14e380e1d5b69978addf381c69fe208354c44a42f9469b96b1cc0198e3695f23d6489718ec11a1f5d092e573b73cffdf23407fc4bff4eb905eb129a38330999a9bceb85d13113746096c946e1cc53d13b63674676a4cd6ea22fd852e6769e6d141ed4cd6366f335d981eb2ec9aabd578593240423a847852eed332526453d8481ffa22cf124ccf5781e777424ee6355ae386ff0a0a74c80d6c00a14de12e007e376745c1aac0f9d3c4c81061f058fca0a84bbb5118ee553eb92f9076bcf34c02c10c2310db902d28983ceb13c4de487f2eadee352124b492561a2e46943296a6e204063561647a7ca5b9e3f3066797a1dde0ed0f717e899fa2b8c6e7f2f8fb02366b9ba4c2e9000000000000000000000408131a262d","approving_vp_id":"tip://vp/US-8c1675d596e68736"}, // embedded by seed script

  // Genesis Ring — founding verified members
  // TIP-IDs, public keys, and VP signatures are embedded by the seed script.
  // initDAG uses this data to reconstruct identical identity txs on every node.
  genesis_ring: ["tip://id/US-5433dd0aaf8d3391","tip://id/US-982eefd8aae14e3a","tip://id/US-aa49ebc66eaf00f5","tip://id/US-89065f4ca41389d0"],
  genesis_ring_keys: [{"tip_id":"tip://id/US-5433dd0aaf8d3391","region":"US","public_key":"587dbfbf62ca9fb24da5ea4b1325908dddc1af63284dd0f16cadb2cdea955b2f4c446f3577c34413384e16ef0a27773e3854cc49afa31bd867b7db12c5641dfd786086fa610d08ec7e10480d8b85936e01673e2f7694c1283685a2afe2ca1c6005fe694870d95c45a895be909b50c6b14bdbb80e19642dd7fde4d45cf15dac294bbb423109c870a70e7527a591f3638a63f796cf7731abb9aa3c1d65e1e5c258984ab7482a31438c95ffa5899e4ccd468fa39d797a7001d4c6353d40d7a7a7a0e28ca5a7ab491fd48075da903e182961c54c3feaef6cf98321069a5a54b8222ab2c88a71e53e1555bb5fcb613d00f9b0481c6a8b9a5d7d924496f2bcb086a50073923c41862fc3dd37a79d4bb6e12c2aebbc8180950a577843542d43c3e6256746b6947a2a0c5294c5c75bc799791b1ebf238095579fab813989233554c2352c3fb70a03392e81fef526d787a462b634f28defa448f3c22184e9a8940b21521e23964e23b762cb6b4a3ecbedff0735714b2da4d5b8992d9c6ca93cf2d5dfc08bf24d9d0202644e604f0738aad3a24da877267ed1e73661a3684a9bdb470c60911e8ef39386c6a4107aa163e068bbfe4a8d9a8f6fcb211998dd09500e2392cff805d73369fd100d49b74af008e7f5742a72b7aaa9b22e32db5ea7dc9242c9b8c34bc7ccc216ba146851c5857a0c5cb5f348648043495f5bccd9495f9b01afb5b56a7f701880d5445e80d942e0f9928c868f1ef76b784823dbf63c5de73bf3f53f52c039461b7cbfda122aedce8a8a3084e293a259fc748f5ba618a9123bc1d06dee75afda92bd8e0ac8acf1a1a5bae4059ba62a099320a388f7cbe4f323b3dba24d5b111dc9dd5a559f4d7aaed8edb80d7cf3401ed1d91dd09013ebdfe063e7d5016275184ade4144598d3540981a4d7dcd4fea0c78e8f6d821ed4e7cd3706c3194a6b81ede87fd7154c8ba143b63add4a1c7286be1b31fe5b8bda18c3aa038f584052f96a493e0beddebf9f931ef6d70ec7f33ad0cf71a304e65cd80d40aca901575e6bd620d668dc74c24707a10f64f57ea323774974c00a6b751fa300fefc222ccae7cae1263d0b3d9bd8e138e4e714d0d66d6f132e293966468185fce155af10122b84b7ff46d60da638d4c2d454e74be6d70347d27646ba48f4d56e9281dbd4d66b9c84a48a10ff4f187655c9d05f270d6996e780e6224be149fbb98d2be5cad76eba1822408818fa275a04e9d58f7843a2968863a3ab0d56ada4860a73e6ad5d2c27e01cb4dcb5df65f21c3bad93c4f36646d2e4b1d05e03e9a3a0d30d1e8d0ac5f4a7f869f0ff7116ea3fffaab7f0cf2b69c5d3b256d18f435beb59161b784dc217fd41eedfaf5ba5fd3db4c6172426b2a5b4b51680cce8e8c3e62dbe393935069199431ee133fb00d168956fccf2dfe7accb963c3bafd94accc26682407758e39f5c0fed38310c160d3c87c96cddf2df327e1c346ed7805698a1bca4526624a1f2224dc62d2574e4a2547de7037e660b3e94784756bc900931686d15c5d4576f82ee3371ec5c40d2c159fe5046b6c07c2c5342e0b1fa2fa8cfcba05af193bbac72412f02ee4fe4cc9e5701b7b00aa4e1cb3e1c08952e010b31f2560685537f4df65c4d970b78bc728dc177f156baaa5a93b352c785c401a9dfb29810099b258a1c789436beaaf53acd2a553d5b7ee60e5c1cef49c2e46de6dec860f2f27db4fe44191772d056e33cdaea23af14f630617f1c65be2d258d89972836411651aa6e7dc66d3eb9b631f875d70cef564d843c9f2602e96bc120cf6f7ea009539d55e9692378611e903088089fd53139fa6c8517d47c1130280360b4921efc5b242e08c58f17fbe08121465f0b909f8fb4c3272f1390c45b9998838eed83693a48dc7e7fe0c5aa5358a0df30b951eb05924d5bf728c427c29bb699cfa0d5f390ded69b82a90c438a2d50a4057794971685e7c49d6cdf71c883fcbf84b034729af3a9f7e02d2e222547f4eacef77e7be2deb2ef44466e09f3cdb9efcf278f70dcaf458add1004aa9dd29100dec4226b22adbffb5f2cb3992550024e7049cb1b9db820ec663380e41f40533e124c31a300d1ce039463e741c081f987c1ce722983714410f9f2144c2a11feebc08cfbaad7360e838db0e75d98250bfb16bd644a0df08dcb11062a659fd4198f179abd4ce76d42fa0ee30ebd6be97001523b5f114007eae618b84e8f7a446734b1b67d9534ad1854c1f088843f09710efa43ac9739b646f3ac6c26bd16cbd972b7ba02ccf4591fad986686b3602cfde947786afcec223dd02ba080487ea016b8222e1bc28a99b593607ac99d2727c2ecdfae5f6379f5954685118341caf28aff0b9787ba996a45db0c8e1a80cf137a762bf0c9b2b9e3f446f1af109508760291f86988450f5589d20936302496392f80431384f77c44e1aa247c4033c5602980beb18922d7aa13a5a44d41fdbdd2555296eec9dcd61c005edd8db0818a7b35a4648adc50bbd92361ea0748ace02dcd7bf49fec223be961bf9c767ec9d78076ee6ea08f4aa937732f42d67b4775b3ee107832b24f66847d10859d812a2e050ce016f4a5eb3ab3d87fd7ee9cc8e6bb5648911a2fe20512f429ab19dd8ec23d28dbd7859826aa75710cb103a81e9d325cbff595307e580eeb2a74930cfaa62a8c4ce813734f6c1b0b87858f69e9687d17939516f68c83a8af8f1489f80eeb2169c623cbc7c680cccea9e06f914c0c8dace49f64f1dbf","dedup_hash":"92661839774354454942","tip_id_type":"organization","creator_name":"The AI Lab Intelligence Unobscured, Inc.","vp_signature":"b9d112b7bc6ad84b88e42c819e102d063ec2521de50674e9f6ade56d2d288e5988888a3434df29012a7d73993e359d97dd20629a21eab645059dd3f2892329cd6faaaeeabdd6b577302638027643ed90939dd70f93829d24841980162a012359900563d5ee8f1dec5f127b5b20860c96d7e46655473c6a08a89b504414ae8816c9ebb7a54d5f2ea57e6b3a2d555ff5589fc1713c3a537c5aa1cc0c5ad3c6432a024ffd97e26e63860baf8c7350d23edde86f186fad44613804ff5f0f70e254b73d8e243cf278bdc6396bc8d27dcf04f1028c277b18971a8c684961294551469570b11b395c72d6c39a565b651ff3cf127eab8b47262898776fe48bf80147f25980c4f6f7bc100b5fcea3655d35f3a3312173d46b03ad95cd074a43a726d386365eb1f9efc23237577c80309114b5f0ae3c00dac7b8704ed681b7a907c074fa913cee7e328aede7140663fb56164e2f76a5f39d6d33f921953c63d9d45a4ed63c2141ed0e5bdebb5cac03a2ea55b337749a0acd986673e43ee31bc26bc0f9c47e25bf9fdf0da6993fb1b57a27b65d1ea8706dd23dd6fdb41cd841754f1fdf2892242a80d3dfc64ba5fae05913b19ff3a441f7196633efbdadbf5ad171d06d7aa4dc5f3c7638e9b97bcd621f984b310e5607758e50b6eabd7363301d6be2920903c37e219a31bac2edd71ed3fd6273307d9fd555220234e21246ba39880e7d0a79ec5137ebfc1c9c2c70a8efc04747fcd27905c751a9d7ebf49cc3b6544d66ccf788963307b8df2053e6f6445a9d2d7c28720d94570ccf135b94615fb7f9e5c6fe9001f79a184ce2f2830212fe0c4263e069dec11cfc5699b65a8f72a2b06894342d60db9562848a6eeeeedce1931e3075811fcf70c06dc75a55cced03c87d3f0f299ad532de14b28ea73c5fee168c6a19599bc409d695c18fdf4a25d851b2d39f8179a1831219ca19d94ef9fb64183b01a00c5eff01912b5fdf7afb0368df525c2b4935b910b902cf520a9f77acb73d79f36bb8f1897322ce9d4451bc069d8fb88c3198033f7f3bd0252069a5a2c735833fbae942ee1226d3275f5488de0af846a251b5632f6a41fd9cd2e048fbe9432bf1f96cdce0c240f2741413b4c465838b76168039c58c533f8cb3c1238b1d9fcf80a4add42e330a7c0b381ee1b943db3acadf410c3d98d8a860a161770375b47a90d3d77c691577aef562dd831e6c821f708b6ac15c0369d9aee90e4cd338b7cf612c36cf1088c1085f715318140350e7534ad2eec407d723c89de3771571d8ead57a36f4e29230047d9f11f4a7d6092c800aa4661a08c722d27451402ef802cabfdb7e67516044c8837e838f0c1265c5a5831934007935922f79751271e1c2c39f167b5f327a1c1b32936db2fc12345aacf358687dba7a63c643bcf506b9e632d0993d85fc2cda312559b0e8a0e5fc08ef78dc150441a806095d52e35c490ec12a72bfca9c1203c438bbe57f9fbabd512c30968911535d0144d7ccad855b413e4111a71cbed1a307b918d6fe73f60a2dfe88b73e76760ea4b7ed4316dee762b0aef9b02d5e91a10157144da8cece17c6badbe8abf26b69c4fd655d4c99fa758509a5af9557bfcac0611f4fbbf86c6fa4db874c242dcf96c606beecd04590b4a10e0863c2a9baeab102f63468310e1fa2ce4cc0830075a883d9d18bb202ab25be7997b08cb974183bb02f12a61143776663dbc9c36449285986287ed555bd474bfc6b9535d152d90c625fb042f151988eaf904a3ca957b7c7c932f9af5044816ed00f942d05dfe6bc4240f15df9a5cc2f5853764226061cee108ee7a4309ee4797c9c3bb62dd979294dc2f3fe5867cde2b76e4e22015c1910003e282a379e052c3ca65b2bde33ce318c831058e0dedeb25d6deea47662f2f2480f81d15ae6333e689cf5e28f9ffc94fbf921dfbd1834a887f393a8d51b1e1483bf4523cd09b126eefe50c0c7dfd31ccfe5677caf692f9806ebcbdb1e76bb19e2f95315c7926d7a089eb54e5e9c8df3436d6ca3fb11e7bd2681d36af6ac8396a275447ad3d354a1b213a2b056d1b4864cc011bb5cd0cf2f029c9064f2fdb9b0d9f920d6a280b2981b4f43681e6b2dab8f038583d849b90d21b9342816fae4e6572797183a48b73993fd99a451fbc35e4aeb50846280bcd782ae55eab3f6ca79cef7acd159c05a56ee734ce7570204f52e3ad135a058da7681d2c9302a753aaeaf09717677fd343ed2483e77e98dce87bbd6161a8c315501707bc428361ec98e5032b3b3033ec8725483f2b56cfb6cff0f151a6db93983916835ac78fd7fbb3af635357f1d545edb766b2c1bbd0176568ccbe67d592e9cbb4d1c722ed11fa42f97bce72a466f61cacc5fbcb468481e67f818f5c6770e82f3d0cec01c13817ec4c65e24b590a7b07e0f18234203a43dcfabbd996023d7a8af80950b8ec6503ad8bad85414928800396a6253575f4ab31286db65c9a72dc076b1eaec9d8169e62651e9469b9196907226f04fae2ffa2bd075c7f53d813402a32954451423935f142b8bf39a488c9a6252b85258241015554166e643ac38744074c7cf161bcf71c3550563436d03b04202e578fbb5a35daa1e9c3be9a225b17b173a4e01930951e9d913fd6fffbb7f2d182a0bb866b836c62aa28d943923535a275b1c7ae6917478a71b04fec9b46866b945eff1659a8b4e4463dd020473b81fc18eac174201fe44e62a62fbd3e0e87b1ee2fc7b511a4188fc7df78317f1b0a103aba2f9f2845231828de865869bca81ad99a4eb7591d5c29eb987da0b4e5513b6370842bca443b6c5527cacad02bfb8b9e38f3f2ba05646c85e6ab441eb1ba85200e01fd702a44ed2f6a479c8a8ed554d258d7a47ea923ef4309c787c0c18601c203ce01143176e8d08bd75c25257c1206bb176a45ffbacce8e3231deae087502305c191369bee1560df51377d5912de0d8ebe338a474cb4e2371d96a8250980fc65390f319a3d7ac027bb3e4e9f6d80e0777504ef37a98860e037f7d3c7a6b33d11d746e5466ce9469c796107c90ce78b93045de55c9b525824af2781269b7e6d9d88b9474b5881bccb03f49b46164822d4df0152bd25c58d224d81166762b445220643d5b223fc4def8a51141b9a696f014a4a208ab4aee90e28d22d81e696ef5462be5bbf030bd75bedad25a45023dec5b8c21d0a46db6673bc3a846ff1124de1ceb9ac97447836e9c8ebf473ea07717ce3bb1318eb24dcd5b1364bcb397a0dc68b41f65225753de211f686a4be920231538657b342084bb9b3b891f1e4fe2a9f0d4f4141e3dcb390e31b716a469a88499b0025878f93ae09fe2f5dd4da3885acbe3592afb4a9e765dac28e82699e0186f1d54ed7d8216181f6a9d397f14ce360b7d5a91a9864217c0bd2df98603814b7dbb63a23a08574f61bf2bb7328dfeedcdfe6781fd1840dcd4ce46a1b17c93582125c49e728c66a07054034fe4fb1dfc4b6204894f4515027bfff11c253a04a1d748324cbfce876343f56086eb285c036b4002a718600d7bbdf257c7e33b9dfede00d845c5c950d615f3667177b4e3eacd3e3b697019d4ae33dc76c422f610630a07ea01f3f3e5fccd49509d4ff0126e5c72b7f98d598c77ea027cd00389ae23eeca5291876faba2ceab9b3c9bcf93a440e24d59e73b23ca176974778bea97d7099ac53fef5feffd8dbb41d0a4011976f56f399204522d4bb456ae969b2954883656e647a3fa78e252150c933c17c4bac6fdd0cd8ce393f34dd4e2a2949e11e5de622846e060b34c6bc8bd5d3c090fe2ee34e4c8a4c2aac83dde781e30926e1a14e2a008e6b4d45ad0aa1b94f2c115a1b33e9725183a37158cf6a91bd62c858b0f84880961da44cd410a776515317eba3413cb8ea7253148d7d4bc61581366927ecbe9cd497d63187f4440aeb130ddc7e28399098e0e5798bbef1a319d0fcd7c581a189bce8e74e307b74e4e9149ec0d3fe3f03da54661732f905d6ad961637b8a1290389edb8834e04f504600baa59e87e60d772e3203222f8feaa0a214cd20349b6fec378a0718194d5a6b6d89ff267ef974ab0c6ddcfd0e91761b4694ea2407d4e01a0b0606712938e843fce49139dd9d0f0af7be4aa0ed614e34146647980555bdfc8dd59e7da2539d7af4d5e3d14f781766cc88956eca29dbf6bea188d575d580550797e52a9813af983efd4fdd7c944725336a1db7417b61568d1f37d7712568544f4dae8759ca6a709fabf215b46c1197037b121a855c642409f5c39070a7a7fc829fb3a0adfc971cdd02d489d483e111a25f8770726f6532ae5c77c7bfee38c4f335e65c71a423bdca6c6dcda5e0718e3870d9a4d22e1470c2eb4faffe178cfca7f9022583447071fa2128af6e2f573e746c9f503addac061fdbf6e1ce94aa3410f91e9d1aa4a9cb572624381cbb8a7d3edcf4d047847a49ac4f689bd65c70da9b08b9c0938a0b8026391ccb822735bc16222320e6bcde789c7e347497e4a0d4f9894c0a5df425f1215b213554cab05af7ed28d402eaceebd9db72553c590868715ccf04f8f1c5301fab6303bcd5b50e60460e0e6100dc81654761e676849799f60e73aebac0de0121242563686c96b70213447789b8c2d2e6070b14496b85a8bcc3c6ec0000000000000000000000000002070d161f2a"},{"tip_id":"tip://id/US-982eefd8aae14e3a","region":"US","public_key":"f1e9f685f04ab524e83271978fc1e3c88be7a1a4fb5f2e3bdb92d91624aa93d4cb6d68c69dfad7b92fe59725691983b3e464658e3743ebd5a47b5603b1811d6f674c1446faa6f5ca83f821d18e17955490a800d714cca472a831c1a0d0db17587f76dbf045cdddd7ee1c51e8a8e3e1ab08c7ab3842d1efa074bd4dda7efb19f2d2d0d0ca7f07f9a10872ac0cb39c4d75f2c7a91c53700934b5b0087d5c0abab1b41036da51cb949272d99ec9cfbba42ae57f3f3018295e273786f4bf67e0a22b309759076461c34618c40f9561529b64dbd105317dad39738734dc00c23f1702f8459731f25a5e45beb3958c9690d6406915bf12865641a7110bb68bb0e30529d20b88ab3c64b9d724a5be083d17b4b916aa4ce57b6f346a088f83bce4074bc0316c8d9d384642376cb7e337c132a3e21efebdf3e3a0a3ef1042a386ab536701c4059eb29f8fc2b771baa8cc23703eb8e8e00aa73387e3bfca15b653a4835c940f1027d970518766353e410588e0848e9023d928373cb00f53017bcc9cc4a29583a735b4399e3bc35ab066c33ffa198f3b76efc4c24a46ec21e27f79e42354c12a5da587ee5e71f3b8e3231207c3af0e8152a732059fb28898827d7755d99b0a1c28f2ad5197bfe46fac47505ce3849d8b42756a96b987592a83dac503bc2e7f21d09f85d414dc720e84dacb0e4a746f4e0369386a63c0ff52f1f19665ecc0dc0525de0f7075cb3fbec64c9777f188c7e04d6589a4b495839874830c8f4231449f79eb8c0786c52ea412be8859724f5b883348da791af918cb763adeadb23e6847a450053fddc0f0e1133f57915f3743fec95b814da2a80ca22e395de4707d8c72df6c989e8f4b7b6bc4b0e1e2c0d3c7f8c413a5cb826647a24ecf3402777f49c3d83d5f3e6e4e3f7483eb23ca67530780657e44505ef9eecb40e9a62c09777064564ac30322038ca0f90bab36ae71e63cd098391a29d876be487cf440db2fb9536e354a0ffc6ad9dfb559544a9e4fc56f39ed6d702b99c5dc80b5f3173628f8965914ad4317ec3f6c0c756b9e871fb96ed5d2e2534a851fdcbab8e958abb597ebbe628b43dd1a27cb51c863e59808f40575eff995c5ee3a68031305bd60313ee4eabcb512eeaadf8e6497ff8f9e03f4654bd1e2f9b0048115960559ebcc7e682db887d61cf5d7b9e179ab38ba75c8ca953d99014844ad7c58c47621e36e5a93f33ea31e3bad4170db5348fb4fa8cc82a4d18f02847eb7c9896bb65de30e9f5e50288ad3615f823f79a6a07d8740eec60871f9c1d8688e43714012f801cd8662db2f780609ac247fbfd9972da0ada3f815661737e8ea5fb2ce93525aa730b181a3c3bec072a918976eb2d039f865636d437efd87613a5f6db714d36d934cff3b330bd01079903c86d1eadb287eb6ded7a22a5249d74c598fee0ee7346305599d03423182a21e1eb7604c68f87ef7cf6310788a941be52f7419f50931f47b1d0f29c55eb53565e253aa5302fe9b17532c79cee1f544cd6c76d1f034122115dac6fb21e2765f322abc5bc1eb4e0c2e649a7fb87f58db3b897734fd5560c961b19d9f2a068a9b89f7aacbb13ba31b1755a795c759694fefec0b6fd9d09924e2339230ced84ccb93e4b8071e15b5125a56432fa95e3993ae1cfb5a5895c6a3eac115cfe51dfb1ac09f44e6f3b2c42d5da58318bf93532e767b5f40dcd658c5e746fd5a7f8af1eae50c00ab65adfb541548253c44c2d740ca78d1d817fcd63a51de2fa123dfa7a79a54a1d7d3a77982e42c3d4519b3f4d6814b9a5fc7ef6193a4c3ecf75211dfad34738c35e98b1103e605b5ab8386903f7fd398a511182842d97e1727138a182081a4af6221491585c9135a561bb5abd8cbd41804eca5affdce0ada1d0a0ad75dc48bea26c63a337d76726c6b659bcda1b8064416fc2936b9292ead5c72e19edf72eff378ccd663f9bbe6426774a0fe15f2a40b385cdee04542c04f5e0f707afbe669220e8b33cd5698cc7fb2737133ea9a6351f4a62ef039a5ba0b8ca65e07772a9b04daf211dd376c3b927eeac6c307490db8ebe5a2319e8407b4bbbc4511d7aa46ac0423bf6231978c05134404c4ba0f1ba8f02b091288b9c46a34706b64cc6bd575610d3804d633acda21748f9a953dbcd9aac46c4b8719e96bd96ea744b4a6f74c771ec16dcecf331d948300f4e7cb45059826cea3caaf52298511de0ea8d46008ac22a1dd2e5c839201913709fa764aa32eca4bf7b61cc80af90d089e27892b0614d46ec0a3d9d7f85b36309a1af729fa3170687be91dc90339b59b24f1e550f81bfbb7d5d43edda94339bb3aec6372e68f1a1aa8b3abcc3a75d53afbc663e71a261f62294192a489578fa0049369bbd77baaa05f1749b18982aff4956bf088e4ef04e57677e0e93b19ab50829abf02065d69aff5c6daf2d93e6b5d544c3351d85adf4a677790b954f98a2bad78350ef22d309cf1486724c00daf244fb98415ed8a389d8592f126e331077e45f4c16c6c5a2579c57ec8ef2e83408ad04bd0a09c31615a4e5352cdd2678c9121b1f25164ae0cdb9e41bb22ff5c4ea936203a09e763485a21215f080b5670f2d05f44514b16a55f7f778ee79dfc8970afb162218402a0ca1aac5e3ce847e0647c2d19d45973ff94996e80799f9c82054a3e15d56544af058c6b890d562f2afe4142141797dc4a1a6de955af3467da4f8977d5ca79b235e349b18aa0558d3d9164302ea5cb78c3c1327f61992b","dedup_hash":"23702933538943712392","tip_id_type":"personal","vp_signature":"90f36e98c07749fc40be0881ec86344a9ecb2a59402b03646fa3d1315ddfef1ae91f325aca3413a989e6a6cfa11d8de4d19eac5456c0f927e9ccce14e7ffc2863284795efe950d1b4f11e191147038982d19434df7711932eb6b437be10abc7e32156de99390aaf7e5c0d11d8b616488bcd729fd96eab392a23aac8ed3d0900f951ba60be50f9eb1806963c2b3a300bb34bf8edaa3322e04715ec334dfa565d4b99b6c0531cdc30b968da53272c5cc0f44e1c430e0cee39febad7c6aef09240ac974d8b09420f192eee6561f0ea76c57e300ad7bbfd839504a92974c924c19061babfc51201968ac074d108d44e07bc8a9491fe2290660177e5a508db2129ceb200cfcf2d20468e11a5f4aa40484d4b4015004b72e9b9d1ee3ef021c93da09ebeb5ef14ea5cc79160e146b9409117c46e864dcbc71d217f62f97f57b3da261510edcc3cf43a4c52334db71e9f306e7fc19c97206b44c33701a46867451ee5374802c87a1be2f45373be6a8cba35c8ddf8db284cd6718cedbe8ecaa7d74da16ea4303b7a624f7fda8f395c6416bef66d8771ced34c425527de37700afb78528dc91356b93cc7759da64d9b71af285a4ca7ee7c8762bf7d0f8d61a32fee047cd5e25b294c711ebef4f64a5c7eed5f3e94a883379838a9f1b2b07345cf80c1e36a032b5b12dcc676927972bd1c0991b934cba37bfa6ec6270ca86ec4ba18ac02331b0689251e87a355e7396aee98ddd2f0885badd67addb050c6bcc4ffeee14b7a004a8e677f70a88549da6bf1326adacfc23b4662cd6764d42313d947bb7b58b3909bb0fcbb583a9ef8ef2c86efeab92627ba1c5add984bef5210543aa3ee54c44569c1071de19717f2ea01efd60db19e8411ce269f9ad72f071d9c4b10e70da2e56428f3edf91cea71f9c1a5eff155780a436170460ac6027fc7e73dd64cdf50350107b4094ccc2a16edc278f433235903e9a2c41517b03103738eaee6efdf0fd995195ccb17c1934bb2a95b4a83e926e6a2c1b04483d0458edf2da9adea1fc4fe788d3f1e28fbacdeb57dbcc449e7d0049f409efa080e6bd8922559d7cb50b88d7d9f8ad7d546640d04d44cb58df75a32539171081fef293f94f06a27cd7747e7054d4d169087c4de19154394a9226eddf2892f9a5a56bdc9261d8f4164b40cd635f0bee684e5c8004a7dd1f7fbf8efe239815f1997fed31f03ae669e1944e3ada634cfc15eedba16f74e62e5a71fa2c0aa0add713135873645fd690b1d773d8651574cbe52e7b4cca3940d407c501ed633cd2e7c44ce42dbf199e1c71ef7b04efb4a0d08858077fd392454a730823991bdd64ae5ed8beb2e0ad40b5400fc4e405dd3e6422c7586ef846123a08aa49d69e50b8e37c9081168552dd0e0c2d64b930eec74cca089bb16853807dc5eda4311e8b9121226b1f274754fc6152fab42aa4aae362ec373cf961620ffa1444669315e1284bcf555252677700769c5d3ec527a969f15650a15e982e5bb3e363400c3ef4a69418e1665384a0a8997cfc8b32838d81e93040398b12b240c4f83720a9b33510bdba453339eb972eb48b048ddbcb864c26827bb67218dfa9ee6c6543c38da2d52725e8aa1cf8a9a8bfa8e4963e4dd56e4039164e0be8550e88b19e070be160db792b254fa1ebe572288b100ce7b29ff6906a99bd8ee6834e75e1f9bd2b8abc063949e38307b3e8654baa397c9b0906e4431b05ae8524175326e8a2c14e4fba39089cd00552997ff1785fc7beed413edd54f680d3aed44eabb1bc9c57557d208d8e472909b6036b506fc450ddcac95a67abb939ba01df9738db31c752a48d5745c97dff461b7f243b5aae165964efec24ca8649801d26d890fa9ac8ac42a985531867881297e181ead50517aa931bb00a56f618c3b3bfc1820cb54f4ca798b9d81c3d5711ae66898ed87eb541dfbe82aa46c9a16931573f120ed5c38dc2baed0ab4934e0c4de9fec9d9ef2a61afd57e9ef0b5f76a63652f135a113eef92802c05a564d515b142439af538061c505506f900789128ab006ff3fde8f0ffd9093271abebc4ce8fc3814d32d9b0c8bfcb08f8b75b3554271ae711920333fac17fb7b2b0142053cba8b212a94bf6f24dbaa9214f54fcd6c43865e223d64dff0c3a1fa8eba2807f0ddde766589c6af67110471f71865efc39dac6a09072c50720774c85c372231fa2964029cfb820c89c3822bf10ae4ef588ff70ac878cedd355d1aacf8fd48376bf8c02644a413f5e6ef2d51c29aa06f6e9137ec6381ea3ca817b8b6710c28fe2307752e0d5e0d750c84075166d1a4d0a4caf8ac892c816aa324134f33fcf34ebf266c179d7c73207f6359fae24ff45c726deff60522ed85c63f5ce9c4af5f0a2cf90640caf493ad11a8848337e76ef9d3c162f19bb35b6c0d36a699a2290933251621bfa71f8f5c7488562c3dadd394a1e2023ca9a8844e14cc7eddbaaa7aa429e2e0ae991f7cc6ecc15e91892bd5fa5d0cdbb1f5fc80b6a0b182b02b2a780cb543d0ec82ec2ee887960a4718502ac0956040ca0c36a1f8e45c8d0786fd4833548691887ce55615ad8c0376565ca9ea07fc736d15c3ec407974a90a551e44b72c07962fecf3ed836a4772aa62ca7eb8230a85ab3f7459b52ba934b618c2e98ea3f90368605f936882384ac80aad592af81b77aa38120cdb2021681c4fb3bcbaf47cfd6d0423ea43efd736e8cd234471c208669bc2e83da4d3d0a60287cfcb24b7cdd1865372ca726a3f1108e44410e33f4f06b24d8a2747cfdfe8150b91e4c5e8f10c759692f7cd34a339632abaaea79f4e9cc0121b45ca0d2e15340a9853fb91f697a27d7898272c083b91498b475069599f2120e919b24dc3321507854bef673c98beed6fb33967266c7d3734d0c692ddc248eba3bca7fd9e0abca53b0a4a362af8107b15eb5685bf58115659146f32aba5351847a294db943f44e81e5b1075d82e4c686211917a6d66862c90983fb1bf80b0ee405c17ff5813258dd75fba6dc04706c400e7020073db68877d354f04ba6a76d8045daa9bfcf77906c0b49e2e312f488a5a5399f7989a660a257fa72d47a8921c8a3c11a8e4280dfd81ba09f08b1f94753adca6cad280ba8fb9a372009596393ece0a33bb7a96f02a0254e8616f5f6d46bb5d75363528d64e357b03bb635d8bc14fcc66035fcbb0760b1afeeac5dbe9a4e9e305931ad8d8b6754125d68ee713ff7e7c922f4c5529e6acc83435fed281575593447c1822c336f47ba734f408ed133fb28f4e66b100722d9bfdb1e7ac390f70afe69a56b8f83bb596bb35c19cf5dfbdf034571c8e73ab9f0903f6f88c6071aab25ab52434d44f1767bcd16104a6a52eaaa57cebcd9a9bb52b254e1e7d206e878db3aba6a3703356923d3d9872e516572705eb12da48a004e1507615d460a9fbf8ecc9480a1a613e8bbd84dff561f3708971dbefffd69e361d82a1beaaaf27ec3b2f8dd0309d7df4d4988b8693f0a7638164bc007b0c8aa4066d9307acf4b0754ff74eacb1998043572dcbb3ac9c5c43e2e524661a1270129190b86b1841281ef1e32980b9e58f46fea4e47e42ca9b03d6fb10711d396c36be37f14c46d2013b2e615119493ae9cdb72d25dfc0bda3a956fc248499329360be5fa0182a65fc6cf3b16f01a77d4047c876bf77d829b78e482b57094f7e9314ff6f95dc1951c5e230887bd8391a193ca1a5e34402669d987042af9c9ab741d40fcd615068dd2af707223dec106117bbb157bb8f3f6c5fae60dce3f617cf91f7c9a69b1b00701fc73f32336187277f7c538952c6c21122301c79f455fb52009a138b4bed7ac058e4326dc0c6590da299d44c8efe17735f4db9169d53534bb3228770629b32afa423ad7ae246dcd465a0df015983847a0d6e30e01c39b980ae6fa4b0b2aab8a4b28ca5cb49c3c2549b0d21bb0050e4efcf11a6b3e30b71aae9354095f0ecd192c6c3be7db06af449ad83fab81cb76f1d01dce57234d8abca4b5ce211ec032b0026101eb834a7018e4d8ae0bd6eba3bd8903b8630427928e5cdcb971b082c52757cde8c9fbc14650688646005a18a705d086ab224a65b8ea53f89534399bb2307ebd148d28145589f721b90203325cd8e484e9c2e2566ee67c53eba22cd33af231f92152b1b79bdb7ec64d76f815cb0bff4147959127e26e134083a517e9fe656b38ace80d9fb71548c1626ad97cc7d6e32f3503d383e3daf77bde6b47b09186e6ccacfd4d79bf9d96228044b91ff7f8b3677ae8bbb557ac15b30372657d25d808f404aa4620a0573a2791e68de2ec772707d5afdf8a7b4e113412cc8a172f456c3149568c85ffeb65bf9e9eabba2b252d56fa83438faa0f55f537867c0085004b9a439c4c16ff277c91a1236a8915fffe61ad0e79f1d89609282e5ec4109df7c44f6cc4680c45da89d726adb19f498dd4bdb1534d2a934f626fe56be555b1c09b57142a8c736d6f2425a7796d095b0f27fc4ad5a69f1c8da0eeb535e247720aafe63d2cac3defd0a1dbcf839ab0bab1d51bd9cc9858caa56163f3d01561526dfec29e694dbb10a2f04632c83f3537d3db60ec1e05eb62767c8a9facd5ea030f176b7eb3d84a7aaceaedff286393c1c20d7188c217254658747aa3bdec00000000000000000000000000000000080f151a1e27"},{"tip_id":"tip://id/US-aa49ebc66eaf00f5","region":"US","public_key":"8a8c6233ca57ccdb65bce48320525f63cfabf12e3e74061c6da8d71d22fe14ced9bf019276b106fabea0b8e37578cf3a5e0963a2c89372450bdf79b15ef247eea68845e8336b3abd1d8ccf2015a82c3d4a05627edd89bfe877ddce418d322d7378e13d29193c331d066217b4bc39d26882497a73f296e7c0e36d838fff29b8d85b15b6a0aa4236bb75331ecc7b2f3126808b9e4f9f1a3aad703f581130073ff0b05556b33f04874ab94abb22d893a04e5e40c5ac8190fcaa1e387df1c66e40fac3a432fb5e9207c6d36bb957860054dcf441c8abec5346e387ae5dc69987065aae3f4a6c5c681cf0fe821ba3dda312746a0760a1f9a9ca23ea4c3071d9f92d7d8735e98acb754761d099819a64641a4778aa5cc86f204e9fda6c2fc69be6bde195b1cfa8c6ef3dce1e442f2b26d760c8d9ebf7ce6a274a896ab91f1694bb28c6550df3b7c9ca3647b48b2310ccbfbfa14acf6de332a64dd890b894380d3c0c5ae167313d04931274d2a7d9c66eb3701a3f396d4ef6dc3ce3ac52f7d7aa0f1a86036b7f95762b7132ce6bae8b463c9bc9a6dbabb7629cd928bad5e626d5e92d09b4fcc0a237ec2f32dc2d263f30cf4f0009ced2ee5d921cec7d3e3bdaafa814e7f78ca6af5f85dd591b18731cd69149f1e33dc737f3512d6fd1782b1cb809242e3779e56794012596d63e4d363e22c01b8da79ce6b9328914a03f94a8aaeb1c5884c9f53c4c2a3e3eb176de4d18bf0da65ffd2afed70ec851731e9024842b41d7b91282865ea45e9d8d2609213382f3ac31c7ed44ccc1853d57f31e6ee6727d86f2c17ba406c852449deed58510957da31909cc8489165e3357c707cf469f49732bf79d00e51976425ac92442290e6f3af39790d841ada8d496783e29d8542d059e488b39b90cc3695568a1513927eb4790738c024c55b7e9751a7a7246b715f8819307a9c8df05744e1bece7045107539ef4ea874e7ed024964ffcb28349f564f07df495e9a24ed62cad61b521a47fb14e49742f50b54359eee76ee8b8a31a532f0049fd54064dedfadc069151af8fb996758433f5d5af42b4df39742b4f0997b9bda13abd205287438367fd5b788c8be3c8636595d9067be6eb5d30b583a88a0e9bade98470dc05f1d11a23b0dfb79e86126cba80291fcc6dce18df1911008052f1e3d5943b0dd003af326432531866e426240d5949793177d141b5666436fd490003a64c575326a9283fc4745952817cdbc0733cd22083184b5e6eec9aa9f3409a628e0635da83670904858f77ad9a1728bc2556889391412cdccd77446a2ad2594c580499c950ecb0904ac78ef68e42f908d4e937765ec9324b0ab9d177d583c4e1dddae421fadb7c5da0ef5907510e128238fb4249f4690809b18524ffde2d6c6f202125aaa3a4ca0b8af899a719c3a71a02227eacfd54ad21620010b04fa5c31f69f911d9b0337d4c35b8f529222c88cb263530393232ebf11d63f3b584159f08c85cc87343756e76b2b255eb5bad226832215c6c2d308e264ecba069ad2c85981cab03df915a4c2add967d16b2c56c6e1510abf4e04882ce040ae287a96427896e9339f89438fabca01b47345d1b0ebac036653b26dfeb7742621e63bffa666969ddd563fafcb1517fc06c49a15349d10c6adf0a6d01baf694841b20e6b0f55e21fa9e2486aad491b5dfaf734d2398be07f058236156ee69162e1f39ae4562f1e1a6f5459e8253db906c27499514d66957c7a3f35307784e74420e7b621601c88b3c3d7f8111d9ce4b3897577328c02ce517da80bd8ef2711e854c7d232662c4a528230eb6b405ae3cdbaa8032867cf224583aef220f95389a22c2fcdc5c2a16d3ff052c736cc78e0889b278b80fb13f87f338e52164f6f2899ef7892a2f60d52eb861836d33f59d31fea3cc5bb3700ca8f6cc1e0f1fcfcaa6d32ed815a17129e10eb62bab3a8166373a2be30c2255a51b939bdd9c9cdb0cf06291bb27f81bd45133532db0de2cd12c56524ee59c1ac6248cc10c50b81eddaefaf2c5de608a2412c24920bc022b1667717e06581c04ec3fe965e0bbf9ba830495884bce6711d2ef21623ccd84807acfe2ca6d7ecb317aff4fe6c9704493d63520068f82dca0b3447e94886dd698c0104b0dd5dca73e33edce8012c12a966be7a52ccf29ff61b7e63c7d1e722e4764af81b081a7de59bade7cca1983381ad5e70681475679ff534a70cb8ee1e547675eec928487fcb4370d9f094af20736280917f10f73b1dcb015872f1669513859d9d376647dadac846ff477f81c8854bfac4a01c8e8cbd86c1f5f97d80354f22ffd75d9eb81d2e9668f532e404df84e9dffc11b71e8b515e975162b256a309a11ed4476762a6626cf64cb86a498821db7be507c71d6d326bf7a3cf728e461816d551dff031ad56a424e844a571b149d017fb5f963f8146d61ec10bba7d4972b3eec20bb4949c1cd50cba8c7242801aaa1af49ce25012914466ad28451657120c3f415ae7354e4224f7f1df5efb7f6f163711c5719144c1a451cebdaafcb4ea0cc6a8b3943e8b09de9fb83576dc6a7487babbab985322fbb0da7c2963fa90b23666e37cebd0d082558edf1b9c734050f4515387ff87891c71c02af128f0fcc0b505445cdc1bfdc90c2cd252848cee33ea03ec1d01a8b5376662762de57dd168eb04b9210890d50579fd1773677ce2cf58cfbcf5836a2f70bbbad5757fe025c2f85718410655ec622474cc274dc140d3f6a279585bc25","dedup_hash":"74146165765493969290","tip_id_type":"personal","vp_signature":"61a41386a7c6f00e7b4d1cdd6b83e7677436a3a8a871b49c48a4cc05d7649f8c76d02c9319785e309ed966f1d1e216000597dbea278a968f2c443a8f1e3a4b328cf8a053cdd348ca4de18e0b84e345c3c77afa2d60ed8a7a36fcac81ccb0868c9f0eaf50763437257cde2e006374abae32e5c55a97b63c63647a729687641ad85fdb9645f20f1aebca8aa046d728cb1cc03b33c1b74b7432c9cc557fff83eb8debdea3840e3c506d92e129abda2e5c73866d25778fca3ebfd8c1f908ec45d484ce38919797b472a369a48cafac68fec23a060a5c723125e107d7aefbae3b5e990f5c197cfd8d37871554ec947735a3ad88e4a90a0cb81cb5bba3e41c40c544401972994177856ce14c3e97b26a5aa1cae60f920a065e2735306b7fe9bf2442fb3f95d63bf63db2cb8f2efc129a0da0b5f952090168a5478a066d8a980324b60a0893fcc66cc938d745ff91784a2221097922592c9114542455ab551d31d108c29cfeda949a87729b821176742cdd7581b0ed6bb2a1869ef8b43281a8218da5337f3da0b2d14500e23179d26eef82eb99cd9149040c3f65e3e7af84074adda52a250316ecfa555d2e6b4c2459e45860d901154fd765ee6f1469f4a6f97f9a89a632a700ddfb453c90f749cec971637fbbc2e5faea2e7ffc205bbb276ed47118e11e2f1733d3a06ab21a1be649050a4a2ecbc070fe25950287bb252736cbaeca6c5367272380cb42c84bf2e5aa9418446c9d0ee94f10616b4159e35e807db7f7178e1a1157ae319730ba0c80cb2aafbd7c36455945425d53f5255334aa20a91dea1ba21d761078dffc42d97c63223811cf624ad9480ffdab1f19732ada714828d2bcef94bf5c26caf0204f1f3ef220962fa73171b34376ec3515c8937d81f3ffc8b75e101e13c3b8c6a7fee1122eada67dd42e32cb66d548e1a8f8f1383d94c239545c8a9bf6b9e68b3622fb7103a79bf945269645f2c7e7638413dc8f427a59844b1b1129efe63d714579f9631c6de89666ef2851d6560e2a7fb5daf71f289b982af6d9969c0e5e6dabe8588d30c715a6d45515a5684483ba163404f0b86c359c28215f6013d3786c9a47bda7c932799689ae36f84e8eb97d83ed46c2d0cc540f11c6d958bf1fc8ee7b5a1f5e2458d68035ca9f9d0ef208e22ecd878bf735587770c92bade58fdb6ebb5194b52086ea536d03f4f989b53b25da1168f1e1dcc47d5d212a7418a0794db05ebde22da6f898e5f7c6beb5e7c758f8fcc8727a5388f341e54a77483b3e122076d66689b8328d04a08ffc70adc70fd15aff7dcb51ccfc52e48e9ee8c5575cd032b84950ba2fc0d75b79a4848542e63f7183da28ceb00374c1e9b1824eac8fd93a0be2303dd844b7f137826f44c26eb9b42bf294bf3f9e43e9c0985f9fe3c1ae20c9a7a771abe8aedf7337da9308c55e30a80e73d9491c35eb4b4ec65c2c0cb6cb22476f6244faae4d1fadff41f90319eb1197502d8e350241c77ed60145721414d1660ff48e30192e91b38c444c631f571ebd36c813c1c22dd1ea91af6f16640a735c77c1e1924af3ef7be425833c015d8f888db763c3dd16e1f7e4cf8611ba14ea96d80e603dca630f58f725dc36a0a47ea6573d488aede770c693bcfbd2a38532c57a7464d4aa6b180e8701f465f66a5dd564aefecb3f1cf09030ab84487b2f20c18fd22e53413fd6a52f2cea5e2fe46c6f0a1530d96ea0e318bf63a86e3dba14f9b41df4463031c2f9dac730956e585a6510f517101d07fbb4cdb2b1e7ce797e49e1808da959f25982b0ba48eccb7c240d37906311bced5825d743a9753eb93dafe5a0deb62f17c3a83be72610d977ed1a66312fbd79f0b13761c36b4fc33411e5f6241e5d983624805455c68c62655a62f15d47ae9e834edfec34e94ba46863b9877c377e325d7e1ce25319000fc0fab12df76aa15784a2654b2f1cf22a30ce49fa91163d95573db5a0958c7e366e250372712bffea4778c5f6ed72cc1779b8af8ae61c426cb714cf7e872e416ad80635a8b9624723d6535b967116299f66d808786b2c3311a424d7b633722575bb2be2c49e82f5a17fdd479f69f3278fda6cbb6283e451fe3e4c943ec84ea03e5739bb39111f88c4298a1e1b02208c2cb2f21d32b6aafe570ffb8703c3559889a8a39829577c897026bdd94b8ec1f3cfd046a0310b4cdd95f6557672b0cd8304b1150ce7a2ffca64d3e87aa3639546b45341ea192ebb13eb2c338474cc1d981e3256bef61070904c27cab9c5cb45908af31f675dce0c6eb0b45c646c2751c393735e43b5bb6c8a31cb31c40f931c9291d9a1365739149dc9e3873e3c3dad1b62d532669ea725e142ba1c271befac75c59204db993d077e3d7f9e36777daba55be9f8262b85edf1d690268b4438f0ccafe916659585792743e8c593d8cbc6286c4f10f455a86a66f255d825005bc15a157b7ccd0a845f363109caadc4a0c8ca93c63cd688017772103fa1945193557e4ac63a79650418a7f92200a99be3b379d7f74a5aa9471f13a26c6b3638a02a6f383984c5a24215858cc97b74394bf9491eadb461db44bc6f9d682e6f5acefd472837922b79ce7c87164e1a6497b7e8a7f25f4c0adba7ec73ea12586cce1411e18e6c616ac65ee6e88f11fac385a0508c02f16ecd9fe53ceed6b97a1e357182f5448f37d2e21dcf05e6097a75c5194af6a424ccdeaf4d70cf873d44906c776b044d0a101e32d7fce5c508004429ccd4feedfdee46211739bee866e40d32cfb3a691278544f078e2caac4092dcd1b2491986fd01bbe9366929844e451b7447f20c96e7b956d8d43e83946ba4fa207b175f0795d4b0ca201ab7623789a11f8eef81dd235dd70219aa5b72484abb12e1c7dc86ea3e5198d737a17b4a7eccfb5ca115b8703b25c8484edc9e679fe91ea23c08c8f7c6febc168122326f88988c76dc6b690eedab03c028b1d2b38f521316d38f5c9e846ed9af27c6804300e21912b366f642b5ba6766e085d7aa1887897f8f9b5bec65b3e51c36050405741df97ebb7d0e158674ca21aab2675126026a6bce2e6608a81ed08865fe86b6c904ab72aa59c8850017299d12391b5378f6bf9574f158909bdf3da95aea25f00395b8c3d421a2149eeb5d4466a46f44dbaa9d1e90916952cb863944be2cefe837fbcecc65ea2745d4f440381c69510a16250f1b59b3879549e48c8101bf595771d2144bd9702f1bd46f02aa3631f57141261f3854d9345e84eff4a4f3572b2823ff1cb162207f1b438f5136ab07df649e42d87e195b749f18d6b0e48e407d54e40dbbe2843c5c9abc232140e1bcbc67ddb7d4e337453a510aca2b50015ab133255c3d4357ab53af7a259f9ddecc9f5f61f7626b25718553aeb2cd8d54d204bc99b07cc9c65d95e285f1af38cf5b642cf92ed8f2c98df782652c427b0029c414042f32eb4799c97a419e1a646f91c217bf11de5aa5b05dfe0d11e4f9945d29251939a92d3f4e34c08e59ca47b4ef6c684d2acf9939224a3dbf5a664ae1c8e46473ea7470a254f76239a652ce9c7d753d226829352cb7963e8ff3bf5c187b003d0c7c5bdcb99feec5e8fc3fd39b794fb69c710ab0a591cb9c0ec4cdb59b527e8cb5acb31ca974dc43f96d5a4f30356bba55a6693c744b2fe5a82072c386bcae85bbcc5268f341b515e869149f57e16549f378a560872ad4ce117d711ed6d3456869c3cc1a922d3e3caef26c345f6e549eca2976d6b552c92f79fe48417fc78b4ff13f9b351e8243a51ac9df159875757fee288c84a562e9ff8be46145d948bd6913908e24b4817ae7732d14da3fb8cb106d9a9240caf362fe9491ee92597bb5df2ca4434b166503405781f278137bb96b78021c440404534547e199ccda36fab7d1fe0c61d2fa5867850023e1c8aee4f027fa6c9b0766b87daa8f104e9d8abdec000b8252653f8902d64a554ac1932153fa7c02a5a0ec5cc1686d69c9a13b71ec2584dc6762e4a201c1a652a36e42f4dc36f4aa5e7e96b21a7f212395e66f243607244a5379b9b637e25e540fcab29f9216a6f49dcf1f9ab90eb18663abb3146c0232ff9de191ed2562296f76a3b23b2d47bcf6246e867c58c9b5ed34e1de16f99a6114539c383096528f207b2c77b0a3d35680d7ca0720633c9dce95e718def935e9ced6b6c553af0596fe9d6b213d7db3ee51d6472784e0749d8b9bd0fdc36d5abf28c59d0727e509563155693c85d1736124f65879e18c38bd4867083aee25855b7dbe81058a9be7c2f0ef7eece9de972d8550b477df27481d8fad2c41c3e4d0b3fc3a9969802a70805a73602fde95214e74a6a2cd68e909467ce69a8d66632f21f20918c0497eda97e26aa981a22a7a087dced899069f9b3c49f97dddd1cecda6aba47773b3fafcf6381426fcf7c82736d94d847f00b2eb62bca83a26437d154b5bc0854c25a42e0269101a1be34980ac0f3b25bff2e66cf8eb9160ad1fdfd103afe65567482ee00a9f42b0d4da9f3658ea3464a191da01cfaa0e1319a202216cb8ec78a039d54529ec49207f8052359e1f048cf0af09702332a07219c3bbba37936f0f8d271b6fc8263387b4323a5998b8173b84a7c4d6f6fb4fb5cdd6d7dd012c336fb4c3d800335e85c9153966adf000000000000000000000000000000000000000050d131a1f24"},{"tip_id":"tip://id/US-89065f4ca41389d0","region":"US","public_key":"2638993d72056e0fe831be23d2728ef0aa623a1cb3719d110e6a860460e2b44285ea36b7ee3588c2c95e91ecd7f5678de4efa4c548b493d545ca93a95c3273fa22dc77d908a0822447f5bde2f79f27174b5b2e11d32df81444e7d28542904ed11fdf4ebc441132270ae7de983aab4e75a827d410848914eec7f0aaf6563352751e7d28c03112d0e82e5d6d38db8c3b4ffd2f625d47c91e114537ebde85b4972ac38bb7995f23c1ef2e77d815a98703793345bbe58f198be90f6f677f362cb63c887acd9845cb618b3f101878bfaf88927a5c884718b9bc7b14eb29e096e238967590f1e0cc854f50836da96fcf3ddb1fbbf3101ac35c8d579151d2d3bd1e523886c036829b8aa8c74a03badab2e7c084b922c89e278b0fa7ea78477272d503f99f80561aca15c5182a7ba9832593997a53940b9f1035127eeafd1df34630946a76858bd645eb0414ecac86d6d0f70a469e7a43b330c6de0ed485f0065152c50cf46151e82b898e00b5c3751f8eeefab54c9c93ef41dde348ba0a2cf9612ed138c6aec87fec4c72908dec08774f0091a82617f9a327e7e7840cc2a0f80d21a18fd2f1afe8573e558a3df7692317488bf639182f19b7a22aeb0d48a374adb2d5720e05bc03236a81b8f97e0bc64ab6261e498b6def21dc5fcdf88eb7c411e994ca35b6dcd2e04a885bcb6c133aa7b9b1c07b9759ec77c192773da10ea9e3f03721f9c8bfce6551a77ec0230cf03cf218bb28f4b7c3b3fdecd37db1f7e20f842b39beedcf370171cd480c923857c2d69f3968a7584f76c36afb660a6b765a1a60bb572d27046c735b1a7917f28a5edfb447e36c557a1bacfaaf7e2bdc0f975cd80a19f185965d6bb9f0bba722c6f3e4fa218a8da7984368422dce4c5e2cf8f573bf806eac5cfd316ab3284d7befdf18f3145d4305432699f457f32c9646918ccaeaf736388b0bda9fec4fab5d763faaaa9fc53f3cb546c1c161dc3ad576e053ece8b8177d8b7a56e57a43782f90cd0cdbd37ecac41cbf2e8ff6c11e06ccc4dfea3e69e4fa53e15350d11310cb20f9a22fca4a654942ca9d4c1cce473b7e40c6766d4234db89a2345e390a39f70172729f6384b010a1c0acb124025dcf97f4c87fafd8fcc93847065be657530323295c8c3a23958e4a8347ef0e3922fa034e328cc7f271ecc4e75dd7735637f2491df44be3f75a07d0f550bd72a88ef2e2696e67f013dc596df451418a8f9bbbef5ced040e4b2dc4a47b34aba97af72462200e2c3d64d7610755e7a021a997ca530de9df272af38ce93f9f5aabb188315ba62c495bc112d1ed38dc536efd6e1f8b04067f7c0682596b89a9501f31d0f6fbe45e6b4db7bffc17f2b98c7aa5594374df14f9be3e539dcd4aede2a2b35eaa0d77b50c349a6b2aa897113692fbafa7c79347eec19bf21944023b4363e893045a5ea5c6013bd8a4cba4d3d165a656a4581ccd982fdf67f74c8037aa5cc0b4fc7e67648203d4ddf27b8e6996b1266de30ceaf1fb9c3de459e3925a0c2094efc6f81873cdf5cf2a76976894b57c788d57d640136c5fd664d8b8f61a2f01e401f09612b7cad8604f3f4f34d620f8da15f3c7c99df73a95ab7853b6de16049baba079324122fe8efe9265223aecad91ef8870b4c47c83e31ce052718aa540337e59c3e7d69f69c3315f4111c2424d9e87ee361eb0e35043f23df8547bcd9a7a42882614c5f114d39aec4af8edf24e424eec5e5f0005567f95eb68b31a3d66fb672679517d3c46d50c44c6ade0d7752ea1014ed4e4c92d24fe4c227ac9e02d750f2a497b1916b5ef5dd5cade89929e3994187bb8fa36f29b167274f921284ac94e8f6d4ff10192e5c1858eeead2c782aec0045601b524f9f60ab2d9469a5d1680f8ff0077dcaf0f4bcdc04c8219d44b3cbbe9eb991336a5d66f379a7dc4fe186d464a960560737fff4f36ae96264486bcfcacc044534f45b86a0b721812ff5a989c9c27f83b4fb1c6afcaf26a6412159122379c50b2e872d157a28252e28584d31267c9e8efc6ab4c9fed5affb5fea42e3e7ab4427bd767fc017aa57bb7e321b6b0f94c62eeddb520b8d304adf0f1a49980ec5eb80aed37047c1c971b3efa6095bd4a9713c93504db47a2fb602c4630fe229cafc0c590313704bbe4a015c773967f3f1891cec1078444df1a64e6469184d6e762365bb11bfad873d79567dcd9a0a9dddd57a775c2c4624da6d768cb706814b9729f88c4c25ea69a310c1ba123493d1e4826d0bc5782111d953101de9f1eda4dc706bc3ae9e2bd5dea0cf211f5ed53b909eb2af4bc66a0e86f1f6181cde3c4740e4a89133c9365b5df15e69637fcce66009fb2c490f762d1415a0ce7c146f0755f8bc65e7cf42ba09aff643571281e9e84e20f6218e744de900bf62eff1509de89109f2b205fdc0d3724ac6289782372acc9f9aa66dce4989326f056ad5f23200e9671a99c1a96b60aa476e06a462c9c81ce98d54bf16cd2b768c07f33c73f1e4094c08b8d7d56f61287fe6fe7f45bd93d66de8d21aede176a3581039b2981285e684ae077e1c68d9f98a36057385dc4f05a83d13c9aa9ce5e28c7c642bed5b3198494bd30beb5cbfb8c2cae93317d94fe47a541a1edbc88734ae74707c96b26c05ac525b1e6bf0795f7132bf37a831581a0d17d3636168227b15579af56af0ff20f5bf8b4975120d03fdee71c105e7a2ae5c9014593d38b5b1b83ead16d462df979f3ff358eff8fa98cafd4915806bc921c946fa","dedup_hash":"70044443154882484498","tip_id_type":"personal","vp_signature":"641213daf67b534cddd1703da0718ed710ed37e979e0389b382721cd7a9db832dab2dec728a41e71670b3174fa23d02036644c3059f61ce64bf401adedaadb220aa1dac0fed08d35b168d2c163b965d1c8328a157ced8919579f4a6f2f2c89bf4881bfd9652bb1c45309dcacfa3e1fa523e41babf15263200f17eea87989e019e3bdcbd83e053f52066414fed9ba372bb90ef03e70b22b57b43683ee8b163192e50f7f40acc406802e8780cf27fe54f3e5b5f938949894bcf24cffbcb2f04dcd37d5409b58cd7002f9ac7fee0540a1dfbad317c3e7cc9eb8bfaa5cd4cfec3a886584cfa7eda6a4b09e01fc813906e1a8ba05863dd731c28aa98a3ca563c3acdd7ccc06e1951c116da080f18a304dfbd0acaaaf905625a4b21b5bff885526663ba2381629e1a2f91c08e85ce37dd63d267857bc5417437e340121b0e041d619a41bd49be418bbfe4b35c61f202a1290eee47a5779727298478759db2b7478830650adab7999de9026668c685c8374525cc817e9b0661dfdd44f06df0b49ba54efa3ac1313784a3d4623efaa5c6cdd062d31944673a4eb946aee34c69dd3088d904d4b36f3ed7b3e04fdaa837ac4b096391d3b9593d719d8e57d33c7796c555ec97e7a7252d9b840d7267404a0d701d83310733aadaa210ffd1c93912bcf9f073f16a93057535e72342ef95e995b8332f4f9df58c6879b395a3eb5d2662d189594400fd435d30b5e2e74e14b5bc52fa2ec34e80bb0a42cea0a9566c0b14f845cac3c95a4bdd2ac312ae364843e6a7aafeac309de2a49b39d91e722c163883440e07bcd882c1be296488ff9bc7461e599f0c6285ba28f10bc2df19a17a1b55cfea5c77c760e0f1b853b60fbf0b3caff6022f5372079ac06023897bf2456dd7e42ec6743f47fdd176a68c5ee007b481a271c7dff776b10e1b76daafa0826eeaf3c65ab265a768259b0aa09d7dc94c0ed22016380165bddedd4ac9efaa0fb1d3c8f2086db9457373e4af31c4715f9ff2bc685d9c047ae347b495f45cacc053b736114569262eace617076dd11419ad9b5e90020e2bf736abb3a45ba5ad77a9c63a876f69d1b171c793edc9846ae68f1ef6fc22b92fc901b9c44484b26ee0733f2711d8e68b3be4c63ceca15e6bfd1733e08719da94a13cbf042d09772a18054f6c7b03f8f1af25935bd39556638cf206070df544fcf9146cc07eb869a15cdca1d305577d709e90faaccd6ad5da5593891574267c7f8ed5bb7d7c5826393675661f9d23614111ec6d7175087f6be42de8da30d6de1d0942701c31811330c2cd618ecbc2f89e1e8f7966d2121294d45a131853b11333507a6d7a7671ebdaaecb72b9dbfa4184b1ab4a2fa795ef5e4c4d195e582b3277deffa7ab27eaeb7d2b87091da8a2b99d059ce8f9503c42590712819ff8524ae9e87b018ec8f1aced06208f6951080071eb3205d4e3db05b3c9838bc75549f540e5f2fcb4abf1c5f04e7fd04f54fe1f28b4c9a698f13759d44da1202432bd04943fc93957a1760e9f7b14a9249f841cb11360f35fc380608d438892930141d79b49bb3e0c2305d0e160d0ac712a5613d700f8a6ea67c1fa9b298dff7fed188db45bd8ade83fbd9b03560975e41758ccaf590dfbff75d2fec93c4191bfd6f1579604953cbb4a809823a2e2dfac029989f3bfaf1f540ce83b795811882df79a0b9b023726e56ec81c7a9f4b60d693cc426c4f30d3f9c42a085438dbc0063912461732f79b9809709eb1fb702cacfc00a48ec5c2831f1b2f7d6d9535a61c0aeb7c755bc0f8c037b06acd38733c1b152ba869f1dcadbb241b40e745c2b07e45bf2e1058a6e8f364cea23a77fd164295aed47d29e074431316949c91410f6e6a0122021724fc6c27f0a8f725a1c83d7bcb7243be771bdfbc4cb5863cd2d721859d60dea1baa2d4010edbaf667aae56c8e038fee580f25e9704dfe56cf5e4d23ded5fd8ee2d5f4fa0617305aea8fbda8737e466b89fbdf55a25177c0adee68222017c072b28a130b62fb4c230f20327961f1382660dc7633b373b8bef16fa2624ccfa78bed0da80a7f355c64cc09332f963c5b32c30a5b1f04ae45e2a0cf055d7d5b31c7780346ede84030d3e14a83b3e645be847ce11b3400588fce76bf956861be6233d700c373135741cfebfa804959842f5818fcfd5a45cfa2d82de9e231017d46da9b3cecd1f260768ed8663f6fb00da660411139d63d0dc6084f0e861400cb8fa0a29debaf0a49672c90c43d36684d078c5b3727a98d76158fe65a905e7e5d42e4f246d9d7620920a8f9b1865675c069a7b1ed9e67cb85789a9dc72ba17bbabeda64ffd03da6932cb3df4d96086e04b4723967b5fb5280ba8202c73ad38872f59bbc6b98b3c943daec010ad9e55062825cbd3e2bea9d78d97fb123a8354c692cc0cafc6f6bc62dda4db6634248a26eae9423ffcc10b18ed7a52015b2050a6fac9b2cf76749e9f11456f0ac4b2b54fdb45eca334fb570025932199bfada8f5ba174d1c10646a08f88bdade307fded28c9d9e485b158b5a07c608560c872200d51e4c326562e6824ab6a876ad77a6bf49b4786f1574702fe7eb7248094464e61994070f04a806b17e3b137261363e849edb02b89f3e0bc4f959a3d423a16e60e994c4c53e51296071ffd726d24edf5be13fc1418530c16ef76955e29efab27d7cd52bc76988f4be9566cb158aca0ee30608f50d490a95c82638b8fa6f33a1f53ffc14dced7ed953f32fd70983702c951279bcf9bb3bdb85ad08b2c232e3bf8e8609d4eb1e1569667e4f095bbc5957fbd106ddb98613ad687775f1799d4974e2c8b682d094f3803dabd7ac0a5ed0625c974ae8c66675b49fc960e9678c2e04752e6859b01e2b7c3f980f724115780a0d1d6f91e707ed69d792c4ef0dd30dbe6a4339a5cbe3a826f53691556f5405b10ae51964fdffa54dbf343e54876d6bdd8ca30b10124b347072bd68362b7d493cf6e6d552d2aacbf690cfe46884582f840f9747b4f87e8053692987928c4a5143f47dcfdbc97fce6cbce1be8cc27cbee3a38ffeab6eabab948988f1f0530b04afe627a4d3bb7af8d1661c3942f0b291d3079b066937c45a0e4af9dd6f52ce81e039948109b45d9dcccc83512f554072e32e0d33a6a8af1e64750f263608d9ac1e82df81155fc25f11ba46dbe920156455a8a92e3f90c83cd325e857b69a38a8e1d5214d6d5405994fcd21fa6b28771505dc8190751012b0056bff8f4dab093783d9cd1097f2ba9b5354e66666e76a79be92d281b4c2059880140b6509138d79450a483d27df1b07fc23f5127a0f99ed495fe0059ed0fca1b04243ba98d73c29b4671534fa829830f293ee4c2fd6e6513320ab669db313e5c01c7003d72f3709f071501ac6f5abc08d4358e5c2469614cb03ce26ed487e650c72886447dd3c91b6716bb4287deb7c809ba7ec1611fce96d15f53d80bd82abdd58dfc4b4502e9c5af7fe48c8b03eab93873d807835bfcf139af830b951df42fe0b480f15ce7af130eb0e59032f8ddd3fcb3ca77f3a2baf755890845b11116d4a4849f2d9c8a4cef99af0b6571e5a555692a0bd4014a3d8c1059fc55603e1129edddebe72ea30ca1676df1aabde884954e4a3faf3223c9907605724c2897eeb37c15d571589fd6d1c41162fe1fc3baa5506fc142bffa6d8ee27ae41613f79ae8874883525cf03e8128a635aca1034dbab9245efa32324aad23bdec06300ce817866ea6c886b9df996313526261e2d20ff01ac27be30bf0bd4756b34169f13b5f1e0f5a1c2def4953adffff1a15f3e5250124fdd06b05e9637effeb6eab2e34dd2c9c87838904bec1d3cde91e042a6222a2ec678a91d2c4ec433bd1d88b1563e98289a1723f92b5d5f1de9c5f88789872f610c69f2dade8e7eea2ade3c38cdf2415ceea7ea01efd3ef84d1e84eedd7029a968a00af2a2a54c69dcb4e86bf46227b7b980b42f473df6cdd91178f4fdfac316eda2635ce59b2cf82b33815982a06cbcc3ae023c6af5f1d922f70fee3914eaeb35c6fe3cb3e78e5bec17c66847991a25c933f9d3b163f2230e33879ffb623e9fdeaf26ba413980a1281ecb16a0f52cf9ff39a2437fe9ce335ab4d7082296495c598538151aca8a365c3f824b127bc2b4af9499b8826045f0e99048691a1c8c1e77a76b600a4d07299636403fcfb133c287768b00d61ca3b231ab1b3c9d3605e97a893f02490debdc74e329ec23cb95c465aaf1ea66e44ab4f5560126d6f54ee44a492ce7108f372a81905afb7c6b55c91ceb6c4fb57c8e3461c38f46badd19a3ac940860b62321f5f92e3932968f7b14c07e086c7157ed7282fbd546eaa31fa8492b2a6a4713f8e309cc01ee62632cad41d3093e22847b4891c9761f3d03fc2588afae9082d8d029e138d640bab64cc0d568091eb57371a7a84fa61722efcbf1cf925a3d99a20cc1bc624211635e93363520732b4e84d97b9b33b3c84396ac044b4aac3a4b93415e4251d4c7c47552dc3fd42615361aa67215e37c0bf443699c01f0f898668a18da67adbe82f8209fb992acb36eb7157cbc7c2e31a71eaf4030968df23cba471836080a263a4c5a8a9dfb0a101625586e87a9d3df45642a65071c2a8693253d5a6e7e80889299b4d700000000000000000000000000000000091315171c27"}],     // [{ tip_id, region, public_key, dedup_hash, vp_signature }] — embedded by seed
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
let GENESIS_TX_SIGNATURE = "a0e7adddb1a09b13b4c8ee854d95ab76f416d615af5200932c8c759f7947b5449498773ee460ed2b8a2d51777bdd80c86307ca05b6a100953940899d3d770d1f396e0fc4d022c851b9ec466ba8f475220acf885b42e50cb9e235855a5c9d78daec3db28f168e02515805c20e5a9f4e916e247637499c99683f322696e38c88fbda945cc26473abbce951db224bf0e71310f45d62661ed3d05e0374cbbd7a56d7b652024a3c4515b4cab19051284524a52c459ff2bce6b26154618c213e6e6e44f2809112b027b5e109bf7417e28c605c02e7b056f582fe0b8eaa1e225519add58758422c9adf8bf2f0d6f74bd592f66d9bc37641bacf81d320df02c757fbd7505a1648597f2e583cf023208180b4c396a0e13356c69b7ec671ec71ccfe43792dc227432c5456176acaced0a66e82f97da630efa720e11389e033c611ef36712e17b330499f54e06113531365e0ce8bdeb9cc1cc9ea371bdb5a62d972f35a413bb753b1515d5fcda96f7b40c42da8ec42be17186a57b41f05f365fcbf0fd7d44a2277a96e979420bc7e82c1d37c129b35bd328e77cac7c38aa8e87baf53788419a5941eb6e17b3293ab5c3dcbdf7369fca1c5a02bf5f690d76c93e61a0df14a936e844d7f45a3dc21bfc05f1bfe385da43839755aa5170e1e22fa8e1d13f8293e851df0f6b09afce9882299b9e3ae67f1741eff96e4ae291100a309d5fca46d99ab0118425c664b5dae738d8f7c463f1561331b0ef0d3523993c19223c0ae562681116b4e31d47b5fe644f74b429a32e0cddf8afd1b31c1e1bdf5b8bc06269b01771cb5a382acbb5e13fea7406acde3a23ec779f3ff435b975a3c767805e4aa8beae563047c424f20195ab9ecfb0791851f5f9aeb517a9d254684a58a895e8b1ba044ea0e04646e17c650cf77b78a43fbb7d4d999340f8432f7f1ee0bf1bfb7519c138356df0ca2f33afb36ece767496bacd0e4a6c50a1c77a9bf0dede9040a9b4b9010126fe3259979be6c0c505ea859022f806b4d823f3b06bd8e244218f53bc529441f5fc1bfa07c9d38a3dba6e40d03d762ea1524616af7958ab5a0392a70c4124702d3943e1d3f1fced8a398c9201372c213ad55bc3aaf8697304732432f6a99bbe3a6e54056726d3511d8f0530f67c83130c78d139171c93e19db79212c84cd06690184f1611c4899a7145e889a072b213a093e4cde56b780d232c58ef555df4bf0546450318398fb41b65762a78095edcd269abc9e35516811b61df9207c8f099ca2b165d0f2d171a98a2f353761502c81ebbb5cfbdc63a2d89fb8ff235237e4fe00249d2c602fa5c9bb2c0cfcaa1d58a50769deb0db5ed1acb120541e938eb887c0d46d00f0f7f811fface5fb1c228fe913333dd694d183a6b04ba4a0a3f88ef1657b129ad404aa311bc0090385238a7830d4f7573db329c780b61b42cd54061eac69203c34eb3728e33735d1a12fd4865541015fb9a2d77ce53de7c7172dbc6f29efaaac1fc4280adc43d14c62a65f681006311e66c03fbbce51a01ae6a2b3dcefe081271aeb9af3a183b3966ff09d362326cc8b1f4c9e1313111893aabbf99d29e9fd6d97e6d1ec57d4198de48c48b04a69aad9fc9ebde79aee2ed629fcd24309a5bb34bcb40e1a0d47cb9b5411e692310baad182b83e27ef324da273cd98e5d3785f57d353d1fe3296ec421a61c07bd37dc10d7eb5cf9816126759a1033886c9904503abd8c3cb133f1b81736a95d1ca70b8ba1291282498cd53784a0c43596aaa08be48df6d652b105678faf0ba33bc5e9942176f00f2e800168676ece8032d33946b2345c51cb467cf6ff188287ad7251b3be1368770c1bef32d7bf6cf4697d2aeeb7218a6732194cbaee8efef3a2fb503ef62cd644d992ad23828d1e303443bad2bd9161c59d7e35f1d37b9bcf961b899fe04a9f9ec99523dcacd4e1c34ebfc372d4798c0d57491c590e448db170ae493f027a82fd3ba66cc680281672635411f9f26c6aa9f20ecd8c0474799b325385a8a4ad4b4e1017f39db1ecd5bac421d1bbbe86214a6b08df833233f9564ec7cb31559b5b79aa997ca74092a4007437ced55f9ec638f2aa7f44cb8d7447962a60df69623f39a7f6af45907b8f68a0aa75034a3014612ac135fe2bc724d9793ef71d23d98d86923be25e8a0cf845a5af5d6b3e1f6f83c32681b9a511288b4a201916b680d530b7d357e8347dc1f0c7d783037491088cca410da1fd52225b99c5d97a0807c860d94a2b55b4abb70b23a2ad9006d3ccc758099373d061fae95a1e5af355920d7dcefc28f6b15bfba2616e33e8d485146785340517433e16538ac1951f8155111863b489fa70c262f22d58d3657ab228a15e95a3616b2e6b534750d6b6b989db699b2346590fc776346978254ba9e2d9d045ba14d008d13691bd0ae84d688bbcd9fcee3fce418057c33099f6a0c2ea674e952ee589b43cc4d9f5f46b0b174cfc47e88b440960486c1e87ebcd0c91b2509290f3bf612ea7234146b7fb7befe39667410a3195bc6bf8f8f78a26d7a21d02e1cf846fbe39e9b088b598914604fe59c441606dcf7ff589dfae21a2187a87bd64835ee3452762bb757dd3a334dcf160433850012882a35933a8348380c26105ada97d187b9585ff3a2ccf0d40064ac36ee93fb2625265f275763591dc087fd775c2a6d85aca945b07ad5301a9adf887944c44183e1c2162945ee31859bc4776391e613dbebddc4466a1d29d2442780bb33d0256ec3543556d145e78ba3d609496bed86d42fcb51fe7e0903edb27a188d2e13a2ec95be87eb5f20d11a076a59a0103f784912ddfe56b5400f432615f06e8b94d070591b6b70de13b1ccd778a7ff3798b8f6e7fc41d14623c903109c764ef9d162b2684006f11f715c91e162e1845f9400f7c034aa09f75c3ca5a71c6ace67bdce10fcd607b63010ff21c17e395c34c8e9fcc59405b01349780b10c852476e44f9ae2c6c6dbe93efd8f90936b12009c45f67965acd63d557c3899fdb2759669e0281861cb2210989309e9003f274a21dcf9e0b77f4eb7ca336122867abf9c7a5751d7192915485ebcb24a15f556d67bcad60a4429f9ca03a58831acaf8e697841ab9f92f4bdcb1fbbe05b1427f1e639aab0b0b0c6fca97afc4be7aeebe7b0306a29e5777f942002a9e2d57504653ff9dc2a4149f292376da49c85fcc9ba212fbc33bb59c1bfd62ea323f2838c70f4a7f5cf1be944d454075dcc8bbf6c6af2106069b2d3e39dc4e7fac16fbac0b74e11f7e0bac1ec11e970d5769b833c63170f28e886e0d4ef92a95ac7372a7a6aee58ebde235668fb0e53882b730b18fcd8b862650998b7f60e1d6c07c369d2ed53e1ffbce50e32f46a95a0e618a4533c0172cd1c84e61b6158ff9d15bfc4ab9a2f5927cf83bdbe1d081525697e6cec4efc94b521c6a46504989c0372e32bb7ac71bbe44190c90d2f51a59c6628296f6f101318af92121f12444356f507ea1ac6143c1dbf6e70a5d005c37ccfc81d5185643dc6dd6b0f62eb8d4773eac44236e7d46ebfe070df530967c027bec8e70f0546b899a1ead3b26f1e9f04f08a3819066327efeb4fac4ed929639653b2f9f12483d47fcaaa85e4b4945146f8ff54ddb33a2c2688e479ff673d3999f27575decfe1be2925e65483b056a02e5870fd854c56f0ffbfa1535840f0afe5ad448d3bc985f3abb96bb606475ca509017aa620160e9154b45e69bd469229689302cbe33c82955c46db4fad94c25a26534df2b9decd5c7fc74dc5308e47d06fbecdb3f29b3003dfdb9e91a315a7c41a9bad2eea0865b0955196f72270ddff98352dd4e2965be2f254a22908a8b5ed5326a611b07b30ba61813526ca2f28eb4a5ed756f97b13163b991e328906f2e1ce08137126921e2b927171cd9edb6d18edc09696c069f6f0d5364bcafc26b912734988015d6bbbdb26366358476f06d4c888348d069ea9b0ad00e68e22d5e976486c716d8d00858fdfac8ca7ef33e710cb63c514c550f108d706598fbb1098feb361c8b61829d275cb0686c3ee0209b290f76ef48cf93db10ea475683e013851f216e308c9d937bd48058c93b4f96ca7776ff21a3918717e3f7003b78dd231a4dce25d7e6b8447ad05a50e9c5f6a1a716180a960a2b6b4d73c70e4e334f149a5346531924881ef370ea5aa573ab2c5d00376679be26219e227fe3309aae32beb633d566e8dbefc70d321f073a140fcd929629baf84e4004348b17b3f24790d7f1cb0b48334af12af9fea463193d1a4ffae760e6d1da6abfaa388819d0d91f5be8645cac52e4914d060fffc22cdb56941cd565678e29eed88edee3769559157af3b9f7fd6ab1126be9598f17ed68fcc8e8f58c248774dd36ac1d5e6a5a51f9c9fa658e776e10c3655f1ed1a98e1e687f2276e089f45cb2aa0efa8511d8bbcc07d13f925fda30f608d9ed727cbb5a12ceb6c5a50dbcc8d9ea235285fa4b381407044c52c1a8bb4516ee397903d62331f9d39966049b638ddca450472acdc96739b28cd5937f481319dfdc4fc521ea3f9127c0deb9b4abab50bb209e5e947bce58b913e67905650f27a79939aa215860637797d294b7f4010940ab0609bad2f6fd162ea9d3d6dcef0590b500000000000000000000000000000000000000000000000000070a0e141b1e";
let GENESIS_VP_TX_SIGNATURE = "830464278b775e1bb9dd3be58b1e3fc4550170ae59fb539684253d241f4a01ea08c53e2accdcfdda382cc14f15c7720d904d2fcfa2f887765006c83253ebeb6d2a60d60dfcdd36f32cc704f738f3ce6328016812c245efcad14d7ded8f8923c815e9c1104e4f8ddcd641bfd353973da654de4e1609382ffbfede7b8c888cc4fa32f65ed9d67abb8716d5f656f3f6759c8385186323ba8d318d666f1a69509ea47a78a7497e7566b89d652e0750f5ae0a07f2f4b29362fdaf1044a2d96155d669584ca3ef20cb38fa67377e60fe517561f23cd20474bc8d132c7e4ce8c28305df0cd6543c1b3c17eacde2dc43c30e341f254664dd2ba58d6150530da237ea5a883adbbbd3bb6790775b81a4f07ce6a8a45a86e3b2d1a8e6d862c84c1dbcf7e727a6e755f0ad218dcb4b299199c435b12bff2d537d5a61e65e9743224a5267922e0ea1c6d1eb3ffe2739d266cc363b0b8d0e713644d16e70d5b4eb033ff97934e10a85194f2d1b746986b7fdd82bf630541efa0c3497dc0041d17f64bb2f94ab5f4600bbd16af068867e260cf95003d1b9463b1d00824d984b406eae7b635135f03aa4c516e0a18da7969fdce96a14aa33a716473f74d65c4ce110b1cf2b9888eddb32c031f9b74b7b2d1c5e2e12bd599cf605136cb0280206badb98181df3e396b7ef47f32803a9f2f2a02da0460640c57cdbe17ecfe871ed39ee702049ec4c78e5610defa806ebd25b85ceb2358732064fcfa9789132623d41b0fb426b9792c977bd718dcbb41db972ea5016144755dd7050087be4f21c8d7a234be709a9242dbdfb02b8bbbc4033562ef147af9e3f633a9be1a09fe08a9016a5a4c2d290cd525e50b7500547b7d6f64b849a2c9fc5f5f871060d0c809e34a121f52397b1a7b398d3e140f58d1142a17b7982569aa2cf318d92c489a2b8afee78deccdefe0a3099302493f08eef0a5871f6782cc9fd7e64901c052bcaa011a88f6e25de1cf29aebb229c1f6d1b20428f4bf2b21980844e5969773362c219ad3b39e2de13835e0472ac6cc995f0c371ae5354ee768e86c8086ec2fc5c65ad46fff30e0620e48a4197c4bdd601743936266adf86b6499a1798eafe9d399c7f21f4012fa9e731f1039702c4569d09fa15ca51fcb477daa69618723a8ee4edf5103e43db567a7b2461dac2b4c433b05c1bdb31abc8e9781125a9b7245c7777a16583e0f56880e04ea55ff27fdf0a4ff2fb839403ae44f68f2f7b6fd70a8fe2523bf21f40a51abb652c290ac8b67fd576104c8da61b29551c586b944c51644e33631f01d6c43248bd5552cae81fe7ae3dd295125d624a0031ae2b7c38b8a974e058813ee495bd99bbb3f37fb67c2a4a8ff9962951c4a545ea168858842b27b0ab921f90be9ae2d3ed02f9c23cd2eb06f1fe70fce20718f4dd678d78ee3f41f138a57aea8f159e71594aa282c2c9f7ec9276c02c34ddd2bdabd96a915b52d2131ff507a18abe9a3abfecdae358df70451c5d9508abdbdb4125d4dac3e1d61b17fddf1a3c4d35ed3bb88245c32862400164ce9281cd2ec56c9ba177d1c0e7d3957d4acfb9de38d86a35a7d8e3583eb57a1e1b4822d9d475fa88f1604a0f7bcf7f4cd107460651540c22704ea54c1e38c9cae1fdce51d4667bc8f9034eab73f7a8685fc7b8f4e0524d142cbfb285d8ae3c846bc1e68c6caaed1c22663cfe39cf29613a5fe935e8875ffdbb169de614d5bf5bac9316043a8cebb7b5970fed093d4ddfc95a089ca0f254b51ecfbc074f2eace6eeb8adbb9c9221b1994adabee2cad7ae14937c52cb95ab714c6b3e3fdb489042da696798b63a98f76719b6cd1e6d9a74e2351c2899e8a72e135b3383d50055f98dbc926d2b728ef2256b6d01fee70d43f980583fdfaccff8c083a2f4cf02161770064e9baa5aef06219653342a8f2cec63e1cf8cb8b3ac28ccffcf49963db41a583f8d22615d779979de49e11cd17f1dabc29c4954a5b1674b426f6eddb706c949b52018fa38af8fdac758ab28104cbdebb599da2d75d284d25b3f8f0dd4aa4d16ecfd6f08f12b01f42e70f57999feba8a10a739aea03d78ec1a7493a2a80ceabe41eca8925645a367f4c6bcb6078b3d8db98ed33e413b49846c7fb158aafb7da241d0cea03ce1b23b49e42b06551f3086a0aaf45c11778e035d7b82dc1c37a948d6622aa022a5fb0355662b10939c6a4a702b078a5959a01f23575678f5dfb84063c55729439ce7418fdac42a57d9c2b3d1bcee7575566675bcd9b96df73931313076b6326e93ed8cdae1d4cb70e06c0ba0dc04616a7ed95699f8b3af12df319974d0215239b7d56af12051c779ad9cdf511495b836ce50a4d7dc1f0671ce73c21deb6a6644ed7630b8c24492fee26216a2e7eeb0b3e6044fd090ac8736a6a6cee056ad240c83b660ef00d8cfcd044f5ec884b29793850ac6cc4ec073d96446f8a30bae7813df8f51c209d5a1cce1e2bc601305815833e69596fb2d7f7ae2b5f683b144a30530cb986acd1b2b4acde2dc9421c60a099702f980f5c7b76bea460f67a851681f71e02344205219fccce9f961d6df29443672e23546a7d782a676c067fa12983cb4c909e50cdaba9545ee0e9d53858aae803f2cb59813ff3672584694b3e59ebe2651aa64daf67b59e05eaf8822db87d453c7a17ea6092621a070ff12a3840e8aa03fd68b017a81ffab62aeb375dd752a31b54cf62b5fa6d9718b8a221ccad7a346c4a18682ab1db4be85c580e3afb65c25478d9ffe6638ba27971801fa5c784adc3b72b6003b2c3bd4f397435992283469d325794686024e5f846682f8c8a6df78e7aa4473642cf791a2241fec330c46135af4cd1de7dccc4e76baefd5b618411ddfcd2643f72215afdfd1504c1ee437f78f7385234633190e4ebe805bbb17273eaf34460259a35c1ead314a490697f6af160bc653316cd857372bbfe6dd5b277943c14eb4598989007163a3335fc2696247decb171a4a5921063cd7662685990ccc0336fdca911747d2fe08beb2be73ef421f65a726ecdb6e1d734dabc60050e9a123d5f67e2b3003ef6914a18be5d533805e53843a30eae2110a29b34bf5783560e73fdd7f88bdddd5bc3f37731ad2a8866c132d4bab214bb7a5a240cd93f443db83243575211d07a86bd0214c3326a1cc17d2aadb0df27cb3d3c7ca18f35a9b633e6ba1bd507e7b7b8684e79ee2b65a759c2aeeba73239abd5c0acc60f7f140afebf5ea94ef72376128fe77094ad5ff175adc933f580cd48c87020035f39507b5261165aff0b5c568d91777c15e9f7812158e3ef8dbd9362cc2044e2f9e65d4d9de44e925ea67dab52c974009394c5d740ae401bd32a3139aa361d4795b5921945539acf6b273c05f90ac6017517a24c48598daf3c754b8f883bd14042589ed62fb440804be2743553bb779ef765cc91f0a2410faa96714e5019341a50e2c45e8b954faf4b523ed7aa4754fc07dc86690751ea4ea9582515858c78fbebae575e79e6101b40b3ab7254c030e3b532e003c3630301a9b14f8e77678a6cf3529ca1f759414e67115b913e819c59a26dabc3e497ba104da20e4a6fddc4e55490dad1f8360353f91cc0f38d01c8cab00e4460105da45a6f2b7fe033bbcf3c2105910200c66d224664e482ad1c3f90b12678b45122982d29e3951bdadd3cdf9c9a254ccb0286a9c85a28cc7586e5720f68d700b3c43464ec7b0c0bec5a03303a8d1abb82f5d28ef6580c396a83b92ee37014da5b2acc0ef5402d795174b608d36346333c30e566201c229dbe0314bb68ce7ef27596565095f321cf002d5d318a4b969b30cd9d2697cb3f1ece2332aca453af554b44019dd0735b188c084478dee310a4dd4b7a97f019d69d18460a435b7bda4ff2522767cb691c7fb06f8b3cea5ad3d69f824cf219240dc95154bbe8107a4cbb02ab1db85f6a92cfe5ac60259e519e71bdd70e032ae9586a935b29a9d2722a6c47af9e4a99eba51a526f97ccc11fc40d2d00ffe0364e46a67c724b1354f42838f0dbaae39f6ac98551a4cc593af5db94442183878eee5d30e1acd835c2a3cb2032dba66692169177dc10660227e84b7ee5a97a83910b927142c1d6fd121961d3f926ccf8b600d7f26394f16a5c6c5551fe6a5b88804d8b0b1d6580f95f1bb1ffc6d182b13238d4050b67ea64ada50002d64aec29a7c107afa542eeb39b21063601ce3ceb2247f425c4bbf11edb093eee69160a3085811e76123aff8798d2e331ec328fd4c128f10f5520d612b4b9757a9ccfae17c12571e29e8234e2f540b9d92fa662748ccb2c873bef58d7d5a835fad8cbb3006b7a0ea8d382a4ce42d4d4af9d4ddebe6e050d0656d0cc8b491c33f8c3e6756f068b7d2141cca859d29f1b16c5e748ca2e69af01fa426f3c15bc3370196e453b3f8fed90b54561655f08ea3d176c0515995b83eef066cc36156d2d4fe69c5d49b7bf76ddc7f2c7d76046e556167b7f747dce11d06f3a833f2e0d04585398d5ee97d72532e7627ca27a014fda57ba94a354fd48de11ed5a1a00d88ffe0f70e942e4c70884e2cdc0e2aa6ccd341f101a54bf8145b55b2790677e63100ada104275c8d4edf31c222f7581a9adbacbeff2f7071d3475d1f56f727f83b2c8cbe736a0aad8fd0c438ac5e400000000000000000000000007131921262b";

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
};
