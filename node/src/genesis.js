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
      expert_min_score: 850,
      // Sizes and counts
      jury_size: 7,
      jury_majority_vote: 3,
      jury_min_reveals: 5,
      jury_max_same_country: 3,
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
      committee_rotation_min_participation_pct: 70,    // an author must have appeared (as leader OR ack-signer) in ≥ this% of the rotation period's anchors to qualify for the next rotation's committee. 70% balances flap protection (transient outages don't drop you) with peer-352 protection (sustained absence does). Genesis members are exempt — always in committee while registered+active.
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
    vp_id: "tip://vp/US-21f83caad0c077c9",
    name: "The AI Lab Intelligence Unobscured, Inc.",
    short_name: "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction: "US",
    url: "https://theailab.org",
    email: "trust@theailab.org",
    registered_at: GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key: "b6f2ff9c76d4d6e34c97b30d080b0ccba1749f9f9ed6cec15723e68c06e3f593585b53e6b0cdfbe50bded7746a93cfbd1523bab9a720549894383df39ecb53baca8359ef71b60028125f192b10fbfa5131193db13cdd911d767b06469e130f067fcae5a99920bb3ae09ca7bf9eb30e8d27d5015e38506106dee8fe903d2411f4c78c13ce147346c3f9f6183465d4856a12a2132f326daccb0718bff5c5580ef43e643b488747981080dfb0e17eb42c096283f7e2bc014b555e3a7c347800acfe50a5cecd664998d0edc2475858804eed63c809a562604b4ead392c26f9e8bd5fe25a1f6a138f4fa2b9255ea5682f23f5edc28841842818295d7296e7cd22953f72f3c049a977085fe016e211e7fc7729069e320fa87def04048f8b2ac0ab240be4b9cc84a7c7f8ee0dcd6ac75922b697ba9c8029d6f3028bba824f02debea79b70dbac9a4e88642d2b982c5fbd987c8f4a2ade4be7e5dea66c804d01c939cfb36e885936e70f04c84d4102a4f87257149b867349ed954ba9c52b9b24fe173ab72095f6e1c2de926c725741dc056554e3754e0342ebbec1245effe4c392971a615225a12431f3d465059db23012c7ac321ef71006f0ec3534605cd970dc89f0cbdc9795a88089a7796fb9c495535faea96dafa3a94fee6e3d2fdcfe3351ac538be332e4961bfbe2a12d9db7140439c359fc44222883b80dc6423c8e87e1993ae06cdd40401a84aa45a2eeb794dc0cc1157e457747321871359ab80baeb2e7f4ebec44f621bdc35039971ce83b891a066292caaee6c3c8ec94130f012b42ae2a04220c45fc28795030c9376b5a93f6728d3252abed5853b9acd53b55d03da5a25f164e126e7c856d351720361479b08020e86694aed1692f29d752dfb8b8e0a5fb7e3d1161a74de59f4bf1b47af5683eb5c93bbd224b9e9174133b715fb691d7a2022ec917e3545dc6ef5eec53aa5a8bf88dd5ce81d0b250de7c9f47601fcbd2f9d4d1b076c00506b9bca720cf0b4063904496209f6c0e7b056dc65ab3a2cedf04c6c9f3bc5a4a65a92d5f024b0c301eba19e3fa53c9ed621082e5278e45fb296f293133708ee775b14a1d2e425dcf59f6ce8eb2f8ac0f61db712c5d381a513d90915602a5ff24f53f023da7c02192d03bd84a93d6eea60f3361486f153d9d2524c02e653afd79b47b755637d920f3e2ab90ad952b3e4f9c9e358bc45174508dbd2a3ec744193d8560a40eda104b68ba71601b780516896a819b1067b20baf1dbe7867fb729fa47221516f3964a91d7abd2505289c4666823f75ad16983682c87e4a6403d368e835de2c9817fcb155ee85da28f539f5701c18618c8287c78371d4bd9a7ef39ef7a9b46e889eaeca8af66bc677f9c8142198e1ad7b4a66dca4f37562147a79b9adeb5f18c3b296a1a6ee452fa79da8d792fc7166c47c1c03369d0846e6a50328b4f63da523283be62720c69fc50a08117ba6152b5737ba2ee09551f938044299cf990dc96a8fadbfa3e411b8e75f0d00b82c983ec568c0754ba352a0926f8f37a3b9e1de06a6bb5006d2b2868feb55ea1eb4f56ab6a9b148caf2672938f4325cdc126571caa12672877424a9cb1fbf912b4502a27596ec910f79d59ddaf57a1bf27504220ce8a88c147fde6a6f5bde35888c8527cc0926fd9237100d09f9455fe9b7581d8ac8b0b2b94a3ed980631af6de5cac9fc18d78ee627df71c95eaca1c5ccf25c50f2307e60c3616a22ab5dad5f6f58fc01d02a29a04e2e67aea41c2ad5d6fdb55520d7c104346ae3bccc23dfe7c566b1fe99a22b4d924719d9d7b1a0966e484ab567934057332008e4bbe4a844a11e0fc68901a0d2cd117b3323bbfeb38fc88eec3cf19d647c39e83959a66b2cd8e155012ac3d61e94e8cef58b55fbc4133e68de6317c22785492edfa9f3f99a34e24b5a09f3ec621b1786b218e17ffd6be6d4367b3bd1fc3b6294f6291b5562556280b62f8d1483f9a92fd75d979d35df316c448a4e8dd9236df2718d1bf01f3a10da35c52343a16054bcefbe03cda1b1b7710a4f3b93334aa42d2a4cfff4eee60d7f02c5ada7c34a9e31d94573e87b1d86260a50c968532c0e13fe30afd9a68abcb418e7d02263430c65c8fe0a066e34f5af94dbd8967083632c4ffe9d8c67512b971601d2df89f890f59b49ffc52b3e29704a8a5c432cc2c3c1290fbacf025d208245dbcebed479eae48a04ab66feb9caa9a561dd8f318c416f5a089656b4fa0efc2f7846908c308dcb6a1946ac36c6f1067bcab412f7fbe285adb10debbf3a271b374bb01c728e1987f31ef94ff20346cdd5fa1757503a2e6cc40326f83dd2a0ff92243acb22feffee9bf41475d5b71db556694cc3add7cc1b5286563eb328906c6efae0dfc056678d12fa7863abdd1236fce9cd68815d6a331dccf18df0b06654dfd1754f97248c6cb4c1bd230ecb19d1bc9bfa0294959055d1c46f71f6a6c50009501ac8169c46adf2bb9decd7a7677cf0bc12158919bd2484dc621e64d3cf74ccb59fccdcddc0a5c48174655577ecad0699c351df6a8301e6e914481d7fb753093721d5df67b75ad33ff4af1fb36d9828fd527cad7c218e52feb6b890527b51df306acbca44c908bf442b4f90cb5419bd7c9e212512b3883c0e7fd2ff35c801a96f83109ce9fbd9e2a14cffff2c30375b0a153fa17257d72cb9cbaf6b4cd52096c40175477003c2f365c84e9f268e4e822e75476a3bcb24baa9f60cf4e02268d577ee4d99e8ac6",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  // Founding node — registered by seed script, bootstrapped by initDAG.
  // { node_id, name, public_key, council_signature }
  founding_node: { "node_id": "tip://node/f612a70cf8229d57", "name": "The AI Lab TIP Node", "public_key": "93dc463b33b0e3318d22d3f8b2b7bd2053fc4be802fd2b9902be9fdd7580a53e8e55c25c91078ff5b37a022832665f788a27181d0338fe5aafeb7f3582f10aae53209b78e7dc74299d1c7a0d90d4bcda3c4da872fc021ecd8e28d891864ea7d6cf0d44db448d19abf3b3816b8e41512c8101eb03c753facd1ebd2a66303b02d3e5abe697dc868b61c9f6e1d573a917a244f0bc3878c366ce6712f616e7cb95905b300b834f7c014815dbfd8e6dc91f97ffca59d3c03ab26b12cf54af8b967ffea985f45fda3d0677b59909d85fccf0b14d82407b8696944847b637389ba549e79c55cd364b313fc9d7973bc8394f664d776f1f1419670ea51280460e2463b7d5885e62de59478d94b1fa8a5a07e91cd37398052951ccc522125048ed95d91b81c3add41ad1611685cdeb777f35c29b1e7d7b0abda7bbf04079cfbb9448b5f24524cbd553d30e290d8b37617d5d852f0b148451a64199a153efc9ce0df02325dfd990de8d39e79a10533329772e6b089d7c68f2d47704dd091cbb8a14e98bb9183e9ba0c83eae2fbf6670d06c18b377f80c984ef5fd71567aa73ba6f2563242948521d7082f70caa1b4118d1fe459891af8ee4bdcc9df6f43af9fd4b977802adee3d004c64646100a65f4dcadea036fd7cbedfb7ac6c1eecc7ad6cad23e3734b4e8e966b73c336bdaf5dd311f63c414a3f53946f32d4a2afcd65eccea3b9857dfd8b5f44db292c958ad52f8b540d6dbe16f194b68891099203328eb85245834c891d76c2e68e209a17f75fa694c30efa7372c41ac9e348e9b129d4e21a7e9cd37c579dc3f8a2b5cdf8132a638e2cfb47c64fa74b41d88751eee45071ce0956fbeb216d09c45d5a6ba466ff005224f569a51dc8ef07d354d042841b7a0d7f3d40be8ae85be372217ee5c1c0f0e8f411d1714796a4fd405325504bfbbad97b64ec0b2a409b1011fef897a5e1c0b416c760a5a3ea8296cccfcc3b1869a406fed4d94a644bc8eda7f6549cebdf8088803d46c68d90cce8bd2c947e390361147c3074a8418fdfb1a32c5a193bbb1424eabfe0acf657d78d320ceb40665e0656f9f3df3ce0a5de2455f65f6144a0e3b2d9b090551f61d6be4959c3a235556be55096b8dd14e42a976b2557128b88a152dba5196c704da5c2422474f125708f594405b2466f963935e94289183d9cd12166a2d587cde166c2401897332cd870bffc6fbde1ef285a318817cc2455f241c4f381e72ebf8a4247128b7fb045332779a59c2a57084233eb93e689f26e52b4e46bcaaa4bd7ed6c52549dd7fb433de91f0fb5ecb65e2a5f0bf58024a75dcb468f8242c514dc788927e51ba02ee5599d52542b159bd5d9f23ec50865da479a00b12b187656a196b4f6319dc70278fc95663f0d2991bca06961604cd5c1bbedb016dcef40735291dc71d9f71885a06e62cfa55c035117be8edec2bf68ac6b395361b5439e02d232e76dc10f3055b55fe47d75fd739240c0c3f38277d8dfaccdf9e8f376df249fde706900facabd65253988ed87479627000692263ce7baa0d82f9c6eb94f5918c69fba74f981f19390cd4c11feef90903e3beb6dca3660a4d791048af7cc8388d32608667a6984917f75da0a12631051bfd69224e22192f2c7c162ee9742785f21de9f0c93ef1fde464092f5d921657b499ea2caaac8561cce94378b0e183c77dc34580111e3e20498a68b3417173e62db6067144c70162e525d965e5e5b1cacfe2199f989fb7b24ada2c2da6bc0ae4543b06b8449258baa41016a55cd984e14a4e4dd052efd73adf207f6d0d289e62dab7c32e13fab0cb94e1020ea584abf3eb09b1a9f1a310eb0a05e39f8464beb88a494047c8c75c1299bfda3edd2059838da279eff069d0aa08334a33213271d94a8021d229091296604e71ea932d30ae6ebe951adfb503378c8c9133148573894d035db0726cebf649b3ece4f1ea7367fa7e34e3cb65bdcd902c24b2e088dd816b68fbb88d353d0e76354d3cb8b6241fcd0bf0786233ba3e39ba40d04c6031b2c296e7173dc23efc63d33dac0f068c3229c4fd6137ba293adf7df1d4aa34650975c6e4b672960c508b3bb38f4df8c492e94293102f76e60c2f9e27ab79e5f0ec16b012d2da4f8d068adfda2f4350d50d739759d3276bd82d297071c231f0ab93b80c1029ca529159177fc60c999e41a484c9ac39af0f235f76843799f5b7062e2076df44f85ab013ed7451d9f01ff249809a0ca1b6ab2a7da5096cf145ff54d3f2d5ebfd4402ba0983f50dfcb3c02dedab8c0ffa8888eff040163b29d46cf73844344de4003bff3594d64d233d1bccc0654b29a146b1a2bd61670291a3506f19de8de42539c14e3811bf75463b0776710fcace90cffa3e24854adaa753ce1f7f7fcca91fb9181998ab47375717732c3517860b40716654838ebd8ff546f55e0a82a0847a425b9aaf4bf44b0c888fb67030d25d47fbb0c9a30f6412f6041fe67f591c6123b4e9e70e1c5b6dfb1d5e5d3ea20b2db9ce81f65bff3e2172d5c3772b24e574de51f9a77f20f70102464ca4dc48fcf7607a17a4a2929a9430c945513d89e612abd7550df75bb3ef314fd8291b30382ca3dd11ab26859c351f3c376efea31c365abbd721c601beea3060529d9a889cdeb73589ee8c80d2a0324773406d38e6824da6251eaebebb022c73790c38d7b8a6b40389bef38ff0214d8afc71c7be0b4bd00009472dbff4f4f7a01ab2aab2b8428bf452178ad7355c2018d82a", "council_signature": "0d061225b37f719560b09f8e2c9cc0365511cffbbe4da7179c1dc01dd62b838adfaf626fccab2c4fc2e74bc7a5493c97f72f854bf9b53b37cfb16fbb022546ae6f05a7d19c3ab7f3804b53aef71998fbbd145e6675054ecb015cfb316818a1ae036ec29ab2393760a3319597f8209deadecb2a0e84a705d91f538ed00dce3b8adcf115a8cf9d0403a1c2e852691661dc0074bd7e5278f50e1d7140a3757c801b2bcb8c0e9d110f08ada9685f6e2b31b9274bd78c2e65068bbf198fa3bd28574f64aa53b266dff1fb5b5b6c1f8270ff67da33e7ac0abd109d2f93f3d21fee10207c1b91e0976bf3153a1bc9852becbfe01cdf723a8a24fa2d4d65831c1a426c8b5d72a7485d37d1540edaae047f5570c73cda8e309022849d1165832da25829da53dddbb2cb8730c57160405566b5d0d9b180ae493839ecc65e80bcd628f913dbb5c0c3ddc197369840dec3d459cc4bfc90839f89d15f740b647f954beaf32515438dd4fc2451dfaff8f1324be30f6cf94891b9e482ceb97c235179d1ffda4e664454a256ad7310adb2f98b234f2452a2a8e4f92d460ce5d1d583fa5a0b386b453a3226504a05700d696a4fa93f3f1a8a9be54862deafce912aaa0393bbded982cb93843830d72e3ad9e80a47b875fb6df56d6a4759fb1ed859b2ac29b07e9cf4bdc1590100e4989a7d8a7c012806a258572df5dfc6b6e45f3289d410838b9d0aa1b0190447dff15425ccc6c565a5f1b2452e7649f046ee72a9d425b4ff58a81fb74cf118faa493c8aedb9efc5324b4918832fe406cf57dd727b72b0c0df501ece998dcef574d0c182041805afe157bf737c834f6991c75ceb700cf219527c6d9f2f10b56ca84bf9cdc649ac0c98cbfc2bb6211ce1f02b979913927400feccea6a6da93a52b63979599f8395d4874f54ddfd9266015a4835d6ac5f95ce1cb4b0f121e073fd170a5f296db9ed05403fc14b3b9c1739a8e43aa6fde34c948dcf69294b1608287fa831c7356361b2a9526b82dfee95c6fbfff394789f1bef9afdc1b7f3183476f2044ab79dc069a6e5a56af710cdb195a0cfaada348fc6c25f41e2fd5724ac129f5409724e8626f41d72aaa292fc7cb144804fd52cdc300ae2d6264452608350dd9b3b500748b438ec2843bda1c0b84641acd8ddce6c0d4d462aa318abe6f55f7cc95a7bf0d45ce6ca56481b8bc3dc20743e1dbed9555ef6e7ad03772a280137424029d981577cc854795581dc40902b8d60ac1297e6677694a644e3a1d0408a7d40f43562740dacf1787d1fac6329ee73e8598f663c5cf6e75d80d931f7f668a60766ef787bf04dfdb7762781aa2572e14d41beced2eeaad178bde6e5685a9881f16956c648e087f3c4448afdc63f26bbf2b45a34f0beac120f15765333df3950d68a180fa217e8d0e960aa78d06ee6839af8a8ffd20f82e5071a97ecc231fe7d0be7545f865b1219a68a18b284878f29b21e6c1fcef19ea46480e5376ef005c752a50fea65fcd07b2bb1c3c16ddbcddfef10a52f798ba66c69e19ae25b0a8c91ffb505cd6e02939e7c31ce0b6d6dd19c7255ed339d013f8307a0d24f234edfcdcd2a7e2bbad68f295a6e6998f7a3154b0a19c5abbe881e1ea3a5edd30d46fb17140e7deee358bfb7c10b486f6bc55eda1c8730172c857935d5207f732993269a3f314f7c1e8f442326ba739070d3e9d1ba405b564afc446f34dc9ce43c04f3235c002add25dee6fb831754327d230606742cb0a7c15e11f44d3901a445dcec43d8ad310003f01d87a405f12c1a2ff7d8474429d8a711e67cde2cc24d3160ae0b2200e4bcaa3c71dfbbf3dbb38554b10e964dd9864360ed3f16980c30264f7f82a69898f3846be85ffea5f9f2c6fe8906b66eaa00fc090931f6764e85cdcc97991643d937f8b5b17405da1360ced171d6f20b5a3f5da4f4488f12aea5facf77c3177f90d97db8dff08ebc584b7f5cc11a7033c49ab8c0e60bc3a624fab38e2722edaa498ec3623a9b134d38378648a0522d2d825dcb3535f9e4a37d5a3e2dfd5052b2fabe7f114aeb2de5ed4a8f12452bb26e15dcf698557bc38186b6bb65ed714ef435e43dfce56b22beeb97af30bcdd160ae3411235d861e7ed024a6ae833a44c9ca8c5298ca8cfffa24c3c9bdc0b8ac56fa47720d828a46b94381e69282f00903ead62878266d7cccb623bab8fbb3f0820cf2d28278e9987ac62f8ef2111619b396eed273e34d5e9060f5fac5b4c8403bcb38a07621c2fdf2d07ed3a497d622d355f6f10d9c57701aa48d4d44688973660fa831122b16801f5ca75547085b47cb034018cbdf79523df71aab38a40d18a56a384c71aed05a5e11b99c941a18398a6e8a1fdd31c4342f1015f3d4e6e4e50c5296f75d9de20a86121412b3bc5c2e7030f0f71b4b1127190994db4aab458145a21d4cc20ca0dc155b46b73bced02e4b7b8b408eb7afc0763eab22ad20f5c5700d3881564fa0d77175cf5f1934192b4fb681f8cb7f8d731a0f784547825bebc0115804860de3655b9b6ce6bf788a054e5ef29b0beae0034e588abc426ea302465e778b1c8619cac19bfab9dafe03563bd75f7cf5b7063e60a37b35a612a9091e0a8bf6be0b636c56febea056c383237d0c49bd821279a6c3ca9041aa145e9471e37e99cc125b24716e89853f9ab6ea28c69f7b85171ced120f1188927d4937b2e1646d1bfed41d1ab09e898042053db49bc26fa9b7f0cab79aa9c75001f09ace3631797cec2519ae1924d944f581eafa483f632357c66c206c06862761c7b4183dbd67ee9fb98000264d16090c4cc4b7d4204604871b105a8edd69f19fddb330368a99a09ee82ffa76989af79954bb898276cd772c161eb04c0435fdf09d0fb5949cc0d1c7ac91e08a383c20ead332c3a40e0216896ca800fd40e078a6cb6dd0a00aa0f5bc3bedd26867db1f34fa2e05647642e120f5aa944bebf4e0841ec74a58141fb4621dc9ff50fec80dca07d40b94c6c0c89dce537e5773bdb14d897eeaa1280e8af420a2e845f6f6e3bd44e2bdf88bebe3f535e9aad0fc261c4be3677bd510cecee8192ce0e68a59308eabc63ea38c4f3675dfc1f64947618a91e6f9b74d3ef08051c3bce3c51810c174429418cd2cd886c3388d27253e5af3bd34389d8f888a8c73a407f92ab6b09f427688c0e6973ebdba0c80166f520711a853ee8da46a8b1776c4976edc33a746255dfbf01a5ad053e58879adeab0df831612ac398bb962f2aa61a231ab8e291da111ae3093f9a4b0c517b603f1ce2e8fd2a219d1de27dead3a3205e6380bb5ed2e6e6878d5410ed9bfa3bfe245c24ff84416a4fd16b5c1df38cc565d170b4da413f5ba77b050c72381f62ef22e0c7080a245a7a3893fbd44f0e10cb5a3ed154acf4093ac10fae81af3f824542b88dc57bcbcfc55d9948f80d12bdaa95f51a1b87a5657646899357111ec98efbfc20f3ac375b551d6e7009378e736949ca8457f81645c0673fac59f40dafaed926e11d93179ae0034c3d1de259194d07b147e6cbf65ca730d403be5fcef3c504132369bd3bf7b536ac5ebe6f7fe358fc585d8ade235c9ac717523c34a0bca02eb6e82233aa2d9b202e8de85fb0fdeb661d2b74ce226b05608fafbd234cad66bad34723d785555504ba98acbd6d6c67d01c32016202951a12ace11988ac13a9252a14f8c0244a051f6212828dd4517c4da52a7660b0a001d27d53fa7b977b90cfb1215cc696a4007c69a46069f0a14138b15208dc85b337b375df01084e6501d66d4429c9465c311c7aeb41d0637843919f6a54dd55cbc34ed50aa38df9a9860d35191e21e0e423fcd0431d91c06c688396d39e6f2b6f9bddd43335d228eea31472c3b92a3455a6751e22b2518820b4651d83f60836a38433f38dbf7d2f57eba9c7a45759a7a90b8d11960321fda2b18b22ec9f4e8d1f13ef6361b0d98fc36dcf4aae46d0c2cead30d5de622956e4b21b612e0fd83d86269b1fecf6193d8f2b3fd8eb04d3c0fe2ee71e96de5bece3443fb1a8decdd9731ea6b3b0341edcabd0ec830d41f159527e7d72c73ec5f49af71446eb4e77faa8c0a80c28d6a251dd6407a49771d5ee87318edbede7d3398a94c2f98a929290027a84483bad91802fd33345113a6a3417b9085a54049f3a2b164fff1c133f7648e31788b94ee694fb4a8976ccd8272b7af7eb9fb752d32d55fd5e5880da73b02200c01ea55fc4ab46b8225e4cf02ab6b74d5553ec0a26c197b65b9d0937bf4dad260e1b137124ba53bff278088de23e1e3961f06851b880ab35fa517be45168b1caa21b6227e6aa347fa2cc3400b1a794d9f0e778bdb37bc900ad5bb9c65cf991665dc2348ee8b39c272ef6098bd42aa0a670ba39b70d947ff219dda3a9bdafa1e72362691f355e24c7ccf112dc317b9483b50fbb8c93f9fff54b58542e33cda551a8735410bc4b511fe4ba84da7d86d847ff7469bdf319e1694f93caab6d7ba305173993e55d0febb59ed91c16d22f6b6cd1de4ae8e9aab7641fffda71448da26aea0dfa154e6e9239c01bd01fc512c2e48ecb1431baa13517e59e743932af5bfad94e8381ad3fdb877391016224445566e9ac9ff070c155c7b83d7f778a7adb3b50d2d41c009107481bbdfe7ee03cbd0dc000000000000000000000000000000000a12171b2327", "approving_vp_id": "tip://vp/US-21f83caad0c077c9" }, // embedded by seed script

  // Genesis Ring — founding verified members
  // TIP-IDs, public keys, and VP signatures are embedded by the seed script.
  // initDAG uses this data to reconstruct identical identity txs on every node.
  genesis_ring: ["tip://id/US-cba871cd1878bc41", "tip://id/US-ef8c7b397bc79c17", "tip://id/US-db372e842a4c5abb"],
  genesis_ring_keys: [{ "tip_id": "tip://id/US-cba871cd1878bc41", "region": "US", "public_key": "31908d35a0ad2108945710be17e6ababfdd69f3ab364c59ab13580a794bd02359893a5c5b8349005a2806eb9a3341cbda0f90ddb900bb2ced76d45b2abb96302f20fd740df102a9f147072517446315481ff336839d59cb13b7f05ced429e15954cf02a8d1fd8a582d742fced9be01e251440c056f615a815b676090062bb518de6d9bfbae1b93dd539b58716e9533d36129d7dc8b61cddf1b7f1038fec928568dd6c26fec46dcf86104bb15d83a85803ef34a7ce5ce7bc43002caaa80d947a8cc81097c8ab27745011f13d137afce79071dfc982de7921dfef9b6359cc8f6757bb7ad4fb45a2bc737565b5cc347e7f21308858833acbc3c4667f7a662859ad5b70fe0666ace60f95d6bd870a460195dfb583e0143e818ffe2a75791dca99eb357d8b7057933dc3a4b75d253267ff525c634e2ebbdd0d81b3851c035bf9847a0527f155c1bb5327b183fd6a3b2d4af37a7ebe0afcac6b4a570a7a2f97b3e2468477a60e24cb775bab0975dc7664dc975e9cd55f14ae0534d00bdcbfbf23fd03d20bc3dd5d38ae66051b902b26e14b8b4e5968385b283c9e1fa160bedca486b41b7371835214271b1e92b106eb2ba36c3bacddeec07ef21c70dcda8e6c259d72a08adc5e01799a167e070af06cbef6bc1e47d55598e74c7ee03a343b539cdc352951d08dcff8f0f85124e11d58fc71e2eb0350b52a92ddd541bc22a527a72d3642cb77098337c0b7d4730aed1aca0d3042e5a9b6dd076c71770a7f1c0a98c9ae674d3e5509c4325a3cc2fd04750f660c640ef8f1c6d6412ffc99b5978fc85b9d71ec4b5f5d3633537872e5cfdb5cd2abd131f8f0783bdc556dfa77d15ac4e49ba3545730730193f3af71bc3b322dd993c365066ba8b4bc737cfb44d37238eb558229c0915d6bb77ee8546bb4c3bf695c2a34e714901dc9bea6f9e1f358d5965d38c092e2b2e58979f54709b67d09307588150fe8c506060ea35d39b1204a9d2326873a59d187144dd3900e8b7b68602998c3f5bd6c42029ba907a79ffd76a0a23aa02f9a21ffcad0ea808def190e61a294732690ba290c89204529f71f0660350a269b908e1b7e403586892116e57120df193d69edee98cf5f53fa0aed2d13d5129ca47215867fb57229ea48a7a6a6089954fb9f227bded738fd13dffc3e7d113b89a25d98400f5a5161973198516166c05170890c042269c5722ce9d0f7c54787c9ced66d1dbdba8eac67e4f23b4cbf2493834c03047f5646f74e480f74d73a8e99f702d53e0ed75f299ae72b15c58cfbedee557d8a603fd399e50646da8d6aa215f1fac3ac6acef8f6c6cc86bcdb8719cc5e71a00a366b095ef791eb0ef88c23fe2116d733c852da568f81f1a75bd2873fdf60ff2bf3460de634007e0a07c6832f8567e899e638bad29db0378b5ef73d86b8022e6cbef00309e9e659867eaa0439bed9bd48de72b11ea2eb17c9e8efc64dc0b3a0e3094492a0b95b6f8c1899047a1aa955d40510c302771a87f4d3ddd6c1913ef142c46243d2168aefe454fa5b16129bce8dd3ed3eacad3713f623dbbdb4e6e7bc4dd8d5242f5c20647a1a31eb8caac88a9c308b9e9f33fb91396bce46dc953d14f89118573d0acd09bd117745af16b0ea290d6d6f4191a9f79fc788740aedf3936ba5bc95a79293500ae12fbb01f8d306b3e0d7f8ef754c5acb7f88e53d0561fc81e6027233949a7f0186271b95403cb77e9d35dead7d52e12d566f6eb12483fe1e46dd2cb98b41368ddc9f4c9dba18b6feab5fa3d9521cc6367c76e963ecea126c4d673b639f0301a43486a90585bcf0ec359aa2c44afd949ed05beb00d2c8ebdbe71dacfe3de0fc0c6997b945d7db275b0d92573ba9c1f63d7b8ad581821587948915b5a4b1916052636cc5e3f9a3226161ed5a356126987751788bd3743cf1fbeabdd9f9e3792543d8e8cc45b0354d5ab670ed2345d1baecbb353005dd13fe744ccbffe79cde3d39c4ef3d89e2ca2375a9540b9a343629cd4a2d9f6407851f8e90752b638173e985096cd1bf7398f9bd2eb9dfaa0d5a082b500b893822741f69f348d37d088a063fe175de4cd00a1c2d8272c2651d13908dfd769c8bce0e97ac219b1ab07f45e4dad5a24d679b9e04b05f156dae3407784fa1849ab36e1d70917ce668a9b257ea59d58334e13dab913b7a442de1b8a71daf9b4cf75445f32b1984eb5c791d3b284336631e428531a4617223514b4c01ad55595084ff2b1913903832dd9e08fcd5ec1a9ee7cbb3031f28afaaf27344af14b1134db223f3ac1fe06c2a9666fca7f1031004c27a764fa38b5cbb671237311ba98d79f9a086cdbfd399ae6a07bd850db064f8332d18958f28fefb2b5c8d5e14d01c3b036a021c20d1bb8f1b2f75e3a12c53bcc392a287e92348dc9d8948bccda0bbb961a77570ff11f2def4e01a0364ce2810b033a19fd5693aa079c2c1f6d80c0a7269b8e0eddd7fa4722b4afe9e455b267ae567ebc3e780067e43fdbbe301bb5ea2c964f33bd954b8444478885157e1878ac3efdff2fc684ebb45ade5b37c5eabd06a2b3226782819658d73921598c297da49d3fa705c834c46b8cc3a7db8d090db0a185e3104040b1896c888764a2bce99abc321466c7069e7ad1bece1b73830aca7de0ce753d8258f3b81f8a346f1e020d1ad47779b3782bdd73b378b6faa875e40c5f4b734ec3975b6a5ae7f97c80cb8f492d3fa267ef9b19d268a5ecfd0f407655f8e40c9fa2bf8ce66b54212d8f4fec", "dedup_hash": "23702933538943712392", "vp_signature": "c224c64b885ef443fb9f11e08122c182a7fc43ee343cd3a44305cae41514c9d9d2d70f3e22d469d276f487d5a0304c2d7c60c5f68507cb7f067453eb2f0075afa4cc0104fa50c71aeac528af2d36650d80e31a37e8a8960c79a18eca51260feb595e92bb92224450eec87c1b102a806d51b685bf2a356e4ccf07ea2ea91d0ad2eb78b95d5948d9d32cb99d96d66eb33cb2534c635a847627db61bf0ac7391b03090987e79c0aa0670a883619ed3734c3b6d52083a1665855b292443fb7844ea4e614c5d6ac0bb9ad098e54c66366a83b7dc3c56f3ca72f787ee19aa6eb0e7cebb6fd95c73e9c29c704e99776db4c9fc14f156ffd6797520fde60ade384b3c8a3355a43d4fe86e75e9294eaa2e713a4cb2d05fbf466b40afd5daa4c568ece1c334517a1fbf6a26c7ddba0a08dd02d93c2c034691602b7db01ed8ad124205773d3d985db1ae612990e5ddd1755bd3d2d2eec8e80710845d1c2b3ce14033096693be82ba385004a8bdb875c5d7b6c78f1e16500efc48db88237386ef326ff454668e4ffc9bd93ad8e573904fda55b517d1fa5cbe37cc23fd5fd3af9cdcadbf152cd9ebfdab7dbd105a2f3cbb3df86de6bd93bb2009a2caddae6135ad4c232f5259bc146f7f58d8f3fd3a40100d3af8674e2864ffcd3e8040353070922266669fec613588998a9dfac4864f230534696a6c90c70389c05fb9bac9fa99dbf2e243ae29fc693c38a1e184298f2066e10566b9bbb4a0de79971e3cfa2878a5a4fd3d2e79425e33e8d4bce08a4d6d13afb566bb3b20918261ba8fc4c720ec03ae493674c38b476a4f2bc340732eccf3ce743e1581dfb4baf5ebd384d99cd6e0bfa02a7c448bf7dca9277bd56430d4ecb02db22429dc4a1275f62265ca5739215009af29a331b22f36855d17a3fbcdf866ebce4026603b57daf30dfba9381e34909ae706ca96994d79b0587c20a811029f3e9d7d548791d91169a0ef0c454e82bfcac9444f1cf80bee801a1804888f0a8557e191965ceca51f8b5bda9847bff51fd15a2000848dd9497194ec81b7fb2509c4c21aac66e6de91103689f21cdc9f0ec681a2a4d34247ffc592f254643c4e543d45ed8046b4833087dc2657c12c241ed0e9b5503db70790def73786afd59136c34b8916e0b30c2bfcca3d709ac11a465dd3fe6842dd58cf686fa9677ffac5c4a3e0c5c9cc67f8c54d1fd1b6efebcc007245fe3c0a1d0530313f83f0de4fa76888c6fb4ca3acb77bcd9581bc8835ae30e5490deb96546ada33969b602bc1c0173deb87e92015a14e6f413b0de48da9714d6a067f800a52ccadf95cbdb71be63a56b40d3cdb296b8d425acc2dd716d46cdbf3b6a9600c26efd44ae0c92157c94f951a2c42ee68fa915fea6c693edbec920999001d354fbe82a3a0887548b3515d1871675acce3508064fb940473190f401c970d70dc7d02879d6f1f23aae30fa8d18083b90f8a1d9a954aa8f85d80d9759a254280be4c90d2ed681e9a312c6623908eeb61d8b97558daf2c277c3e75301d85f6130be99e281f379f391c00883346d8762c74db5ffaac1353a5d535ecbbd6eb77c37efbe9b9951b7f5e046cb83fa27687f4e27a7254af0a6357d1651021c3272b6c439fd1866eb1cf67fbecc24afd9da198ef2d27019676e16a1bc3fe4228360a53f7ce791834424d9d4285b63cf9aea0a00a3fe1c73ec848297b3e93bf2f45fc3a2695c42bc1bc0c9249196b17782bc91aef42627835428959be60d0bc229d2e251ffb24d0f5a35a055a182f48228c2c5cc6e56a3692fa1097f1fdef762fd07cdf4fa82bf9991fc28bd96ff15630f726b4fa253f65345e7e863500d0d59eec8d29b66dcec6af609b69981d2c50d33717c1e1ccf07528f96302a18c9755cb85bd068b1cb446459203f955d9cb5b720d995252d71ec765346268f93ba73207eeea38e1167a46cb0f7a2beee4b574babf2b0378410ab5b2d88111e9c415c249f6384d2c80f003c1de7d6071f48801238de66cd2d6da09d194a8b0600a2effe9ef8beb7ce17f196a867b6bbacd628b73800947d4645c53d8fb74fed09e42bba7f65ee1999bae7636c0bc69a418995cc118bd921d58daeb310eb10934d813371e3444c0111c9492fb4a438ebdb30b28c13c8ae9da3d2f0e47c773bc357fd46f3f9fd3ca68f8b9cbea0ea76caf1b8bd683541518930d8301977d14d20ed3a70320a6e986a7451303519520468466d3a091d031b42eb6ca2df6949be710f769c0340ae3bf42ec43aa1c101ed1770bf0d333be20c5a34108e7caa6d87f9b46de998a74d94f0767765ce8393f49d0854b33e516ff1ac43cab5e3c8aae46456329941469866dfd8f0b14eaf4f507cc51a0706cdae0f3787773b1e0b5c5d1a5e5ce58a8a2a87a88659e0dcb7c3819107432f158da5f7760eca4c3c6f8b5342caacae9bac463149b1745aed18173c2f61b6d9e787409c77d8cd4dbb5a411f88924d6fed274a0957f08d3a211791f4716cee42c0eade0e42fab817b9f5518a7e434f88d8758fb08462a056bf0f86cc7dbf010544a7a4b4502235db909d432c09af0e383a8bd94f32c62ebb79e041396e6f2ac1d49ec1ed1af1775e20b1bc0296debd50a99da0710d98b59d57baf6e44d919d5a1b0b2e6ee602f84acdaca9c3a91c7b384cedb41e436e05cc057b3714d9f838e3c8875c1bf845c09deaa9cb6b23c9a67d5ae062ac28675e61f8d562bd9501c551c971214427c5406efa16de915aee60fb4ac4a62dd56a32fe4c56fdb5bc771ec2f677f33d1279d81ff001c18d7128a71f407eeda1dc2423e397a7cffb3f40b037bdfb9f6073920bc122454729357eb98199fa4075f7abfbb2976366e8bd0fce80a98df008d3e021bbd6f512fd052c541ad1ac3f91db410c2d82204ace67fa809c90f96b306d1b6e7e846dccf12f06f2b919c1154f4568f9988f255de70a8ed4c7b71380783b82e5b48a6ed8cfa8f39b31b5ca7dc46083be74ace83498879eb8011c9d5e20e777aeba93284963699ed79730ebd52c0fdf70a300223eeb5f696fe9ddfa42ce81932a44a666cfdef9bf35bec45fddad9d746d380ccb80b7b486c086a783b4563edfb7c76090cee1d083b73d859eb17dfe97754219dd53703566b565ff329c169dfa3052e0ea91594aeb1dbc92a2ea7ea9b4ca8ee7058d1f012750c53b104935664292234c26bf355cb243dfc780fb0c60ead2d5224d638e49ce29414c1fa14508a42c2941769d49407b0c7cc77d3617c94af1ab8de11fd746e7708fa1cc03b49a4e7b9587b7c5750aeb8485d9db968692df70fc12f1e3811e11ce72d2e82989c78e2bd7b730c9c0df4774f46d9eff07f62bbe247274cc0c8ab7adb8459ce9882db1155b1bf03f29359a97761c2461395f1ca0fcbfe8128de9e32f8fc84ee4e1d70515420bdda5653823e300659478c98e4767194e9e1c3142a846f9ec540f2c4f1e485ecd9fcfa6c4b2ec4a559d33bfac77db71a88ba5e3ffd92cc4f9631553108ffa2ecff48d5e4dc1c53653e6ce82a98e8b72279688e2bd14a0aaf0007899e205bf59182c0d6ae7ed7f9118976618136c3612129bda6b8592eebfbd66a0c6d68efe3a7782ba02b100e44cdf37c8a20f542dc0891b56f8acf8f03a9b649871d6fea6b5e47380afeb22fdc1e6f7ee7593ebaa92964ffbbb173d30bc3682cbaab9de7c7bebd25c0ac8414cb33cc9e9d76231578eebe836ee4a593a63038ae753d04c78a86d6d7223bd58c01be847cae67d022573213120639d18bad9e9054cf44d035b513b37e41916e7cc5754da3d896f5a770e4c43b3a6888acb601ea9c33af29cda6e0b27ec625713cd42cd62e4c6524a8aa1274ef7107fff1c9cb6770d3936b7d42c9042e5c19b72fb56f39b77c1b7d5688674c71d15da18b44a3a29affdc2c86249b400a028f3e3a6872c418269023ea110f9b13638e36c42d1180e872f6856b0c21cb950d9766cf84afde7e619f7ced13a9a553c49f618f7e98c71f0ef0df53b55ffe7a2d9a8aea8a4b3d038d0fc15376ed3858bb05d3436c6606025bc663c0b625e2f92c4072b74795957a10ad1b58fd241b004dffcd87c5997a243a49f054581e973704d7905c84fa444fcb3b05c1b49785c4628dd8180660c57beaaa11f55a0aa33e33b7893c01d3ee7d507b3d6eccd8c948ae7ff937ec55e919cb930b80f5769df1854cc65149f11ea2ea862e1177eab25470c3479e6c2821323af26d52736ca069474cff0193e19e88e31d51cf06f8b44707ecca2eb292c051a049b80eee2dbc8ab288898cef87196d318c16fd64465d4f5c0b1d3dcd97a49fa3b902020f9ec1eab2c7c192e2f4e3296f2922f7bc12e9b7f0d2d90b7daad2cbc53d3f59ea43963f5fa0271b5773f48af70d80a6f00c3867a2cba9974b97a6770bf7a04fa463df02257a30e7a356b60acae33bb8e3ef914ca1c204494c0abf79456588c0e2b117e3543d8274ebe7417385a15a3901d48043c1612c286783e1615b860fe61cae9c1e755f05d4ff6aa4f5052bef9e69478c32d8f073880e14b0f07e3a9b262e09773d046f57c31f4f091a23b16b385f072e20f45c39a463421d6d2f64153ccdd3dceb0145477c82a4fb191b410c1c323a7c9faeb2bed8fc3f91ce26377d00000000000000000000000000000000000000000000060d101b1e21" }, { "tip_id": "tip://id/US-ef8c7b397bc79c17", "region": "US", "public_key": "915382959d6cf58686aee6b0d518320fb8b34980f69d61e7a6fdf394d58e222e0dca3e170df9c2c013885b79dfe306706199210c7fb0bdb56dec1398cc956c9c823eece49d81da79390830aefdec77e9e9a3e7096ee8ab6715aeebc06b6578de4150f79e886984b7bb4581260613a97744cef5163c76a711aee809e0221a9c6372498d3a261a1bad581ae50f3a3ebfd8ad0e1fd4f16408bf63ab2701f675dab5d2ece5f66fb03b583bab0db8b0f63852138f180cdf87618040f826de18d20ae4fe1de02a4ec1436a9cc1b756e4baabd435587eaba51b3a695907b72d35207aed61e85fcba63d92cd6a80c0f8a00f237d24049e70f068b2629052e72fc11ebc0b7f0a8e9f9281a02f489aae5f2cb247e8a3606a28fb95ba4c85a47369735f23e11536dc43242f2c523284fce08aa439054c5e0034b905dc438bf5d2b33610e8df98dc6ea6cdd23768a7cb83792142b9458c507fe694251bff6664753e5bc81b69f802b09371a9c38356eaf188ece188614e4777e87d4e12c1a95b675ebea3199af54b6c262f8a70d7675a787a0f4f9c1b253e2d5a515109ea6037049a092a33a2d3669f4f25f682abad6ed79e69ee0e834dfd26a6fe9dca8023145736837b9d117a7caeed8415495eed3876f98956cb08710708f99c823fc804337442861396b325261107392f6185f3f5957bee08f76ffd32c2eab65af8b13888d86f2d19293cf603b1d289a44e4e11f4eee8369c06e8202ad276c2ea8583a995844ed12a27ba48448b6ab25f29a54d4d1f9d11cbb38055a21efb860380b02e242433ba300e5a8a91e04ebf740413a73215e4c2cd4a2b4088c7c689d3e2b4785a135d4293e93daf9ab81372d0174e555dd074dfb7a59d30c1a7196ba90016554f37fe4a579462f8c378b8ee351fe07d9fe09d6001f24faa8c8ebca0eb91000d377adda8b0097c346c422c90034249b27221bbf3850d9b86a08a59dba8d03d5098eb51fabe230db384c8cd9c64b9903c2cd0f812d3279a96ff7907ba99dcfdf8a09a66bfb1af29eabf5530965d11b749659dcb275a5f5391fc71be959bb5e116109e2d8ad4f2b3bc08fd62afc2d1fc38782f0b71ecb936c10bc3efe91a0d7569e8ad8dfa2c73c00520ca5c566e6a84757c90fedf589c7086b942eb46eb6697691069334ec9d21bc9742fb0d1ab566cdbd08c431f220f0bef193eeadb6e54bf2666de237aeeb514217c0e782421ad4979764b38a5651f31867826bae4cad4a12c18d83c4993a8d660027a4230fac62a94ede8f911a5ff5c44bd473c792c654ebf7fb7d0cc43c0a6a4fc9cabf61f08ec550b9b59b3a443dee652e8a457211554de5cd05b452a343e2dd77f9332d0b29af44d7854e7636358727e79186c4781ef1e3d274dd0df5b2e62020e29b690ac83e76a76f1ed6d85713969e9bd1057cb44713ba4c012d1578b8e335bc074fd48d708618e4eb905d6431d113ae594ba0e70295084ed8c7f783458e4aa27b34897fc3db43c3ef23829c9e3b291b65b734cd9cc701d45152861515c35af48becf366b704fab90c47b306db02f476e17fe0e001a7de0b202f61b5e12dc13c42e940aae49688b6f0ac34939b1b12b910e34d58ffbf2d1d0f39de6af252e7412a3718ed5c6979cc9f0c5515541f9df68197fca9444c30b9ce30aa2fdaadfbdae965c57b1f6b9edbff1a86e1533c8ef7cf61cc35ab80da2d8261ca11750f1b70c9a0f405aabef466801dba22382a931e83d2dfb9bf8ec362e411941a0c176562566180071a969cb0f009f3278478b2e2095b3d6261604e7430a24330cad1a45f8a0bf3485912d2996a89afb2b42b85328084fc7e9854ac56d1fccff3fcb1ffa9d3b17138de61f726ba6faf115e7a348f4033bda31a6cbd71c6e9eabd71bf3b48ade73acb1528db2bf61370547e94312f60ba93946dbb85741457af93a6bb57113f3b55e3276f9a57e4329e62bfc847c1b2a64365b694970ed5bebca1b45d55e25b0596ca844cfe43db9fa5c1c7d5f6adbd77f543cd12e50ba7d4ec62beaad7f36908f9bd55b170656e17e81b0cd43d41ff26a1125004456df28292e1fa7750cafe1d20c579aa2847155b67ea7059cbbd8dc08c4a1411fb788c6f0b0c31458050c4b46cd2f63097387b1e5165d17eda3e8557674d01e691adc996cf1e0d94e2041379a99bd42a2e56b935b84a2d1c57eaa3c9a3cbc1c381151db1054d890e3555060fa4423a3f8024a0bf3cbc5abed81c132374df95ecb459bbcf0a3fec130ec32778349777e76716ad79c2fca3e1472fbf2fe24d406e6b8f4fdf85571feed1ce187fc66f56386e7c28acccd790718752b21bbe837598397b86b1b09f50589bc777e87b7ae09c5bccefbdd34d7b1fee635b65a1b29f6894b1a6224efcd7e539ba47b9e92d526341513c7ce22469518390276018e28320e33d79c2fc72b58fe7d16e277d90858948c551439ce570caf8119894ab0d86a7e22079abd8235f6eb9031a83ce21e7e2988eb9e18d2950ca8e18e8228332732fc5c9088d9ee49197fc78850821d2bb834ea2fb4dde9920028049a2874c9d5e28be869e374fdb4f2031512fd637a6b1062de51eb061520325b76d509d265e133935058dc1e4653f63180da2c917ef11cd728e2ac25949cd06732cecaeaace62f469302c79e5b95a8e58c9b2b9e8a924e824c00c3bca0217578d2fd62c975f231d000754531d82b4f0210284c5172b21fbd6937e03e7cf8bcfe97fba9e1f28c20cc174cc1a22392", "dedup_hash": "74146165765493969290", "vp_signature": "6eb478c0b5e3bcccd87c216fd5fb911607553f8ad2c0667018cf494d121911ff99bf64214cec9bbc007bb9848d1cb4bd905513c3e75fd0fa6896dfae001d93dbf43b42b58fe32d92919c1a79f9eb535c73ad49c309cab1384c8e60b816aedda52bad4699fe97fea50c7f4ca8300c6aba4456129952fe776ffcd6feda08cfdc6bfed6226d805798cadfc69c933145f51f372d4cc533bc9c1a1d23255d8f775eb12fcc49c04db6150da088bcd90a24b071b2178f391076c30955b4ec72e73f35f5937c92e01bb942fdcc6a585ce451ec0520889f60e94c194b0ec527f75a0dc476436cbaf6848fd754b565e2783310b7e1bac1c9899c9dad089c587bce0c9b3a2edc308db61567e72562819042305b21bd0fa5c93dc7cb1629069e8f65ec00e907a2d749718c83b018b3ca2f721875c2e472a5464c066dc4e3b83c1e4ee93330439521c3fb17962f9b4ad7e369f885b6e77acb03f5412e854379f492c3aded77557637099d8876dd52a61d2a272383a85f1669a57b16aed0897e86043dce39a214044d2ed7b960eeacbce885f16015cbd606010885f40641aa4f593a66bc09e1e646b5434cee95157f2af2301782f98f6a0fb22e6466e360d52ebbbba503e2ff59108b2c3a5b8f929386df109007325998996b4d703a1a8e92d622def7a32ed508f97874fe15ce884863688a677f5b514934f70b61470408b161d4bc64c62515f27ae771d6c58a95017d406bd0ebb0ec51af65b6a2d2225245e8b7a5ce2bf812f1966d74cdbafb7582be597e7a2d2a79e04ca388961a4bba47ea99f9a3c9baec92b7279873eedc548ce1d908b64be0ae1ec5d69140dc20f127ec0631e97bf19d630d15213c6abff1691b8f8a76e3377ee9569eca410f519a9bd6bf9fae59591d269dff77dc344447ae0f25541353ec8be688437d8fe39c09a0260c92aed9a8614e991fbf36a72e9a06a32313d53957c363091e28eaeba581c12968873c8bb95d3f9642f4facc236e9dc35ed24ddb45a90312ca9099fc304e070b03635b11843af024000502e65a8caad77c01fcedc0e2d916375b8633e945e296dfaa2d076d2a54992e34168469037d327921c9ec2d3141f580b4e619e61747e814c1339dd72beb3a5be7c88ddffd5128152703140cf443abb9b6947a74f52a38f6bdc230485e1e0d3ec2588013f04e24a756781e840f64341839123ba1d9fa68230e2fc6a7ad6af9e9cad389ea9d2194e3f978b5863844f71f3ce9cb4292f4ddb6dcca44810e26f92ae4359e0e9977b660d05f1887927e0f761d643fb6ec285213a178b52c3251fa485d10eb65005a046b9e4f13bda0d0bb8e2d1494ab24891047088f75d236dedd53f512e0daefda94f8a06b9e16118865a9851b8c13f6be4ede8d1caf48c72b0100fc0cb47a2e07e18cf729f2a50ea5190f3235e1d0ae938a628823b4aef4a1c53136a935e94981e3ac5e03e02265bcb72183903df7123844f8c6a5b00dad23ea41d9a15ee4f3321c6d2e04c1a2c04b75bff2bd2329e81dbdc03c233c8051d7579e1ad086f5c251543b9dfc4f7206c41e257aa7968c850e6bdf821d2f644fb379e777623ce2b22e4443533afc52fa1463f1b959f415a92e825cff88481ce8f138359e6813cfccfe5ade421f891b017038d19cd138b060dd1c0d910c12acc2846ca7e3927a3538608dfcda9772e6b2a291cf452f9ad4f66f13a9516ea98cea48c6a3df2a3394aa9102c1a7a34fa5efec86e6c5016a3d0d97cab5f4a5737db6a1bc6af322087e7460f500225d4f82bbe3563654fb7f759f36fda958ce7ddba1924a627c71b162c2a85f5d979a0cca0305d6c6fed03681d191f6fbc976e47e4023da8f9df27afe9c67da3e2118091b18b5099196ff95316a2ad0137d021d92a891e8b41ff97c0f686bc410b1ed68defe314a6f24ad2f5a290af2afe62910b29a03c12a882ed9ed35a2b029cfc7276ccda28e91182a43e64a7231f144dd5c7898532706566367a8c577b470c10281231d11f3fcd32391d9d6498522a43d01c87b882226a68891793e24e13eb52a1a21cb9b26992709fa0a564ef08dcc81a228a0ae535cfc5d7f4f913beddc306692bf40184664023458b516f091e279bd086ee4c65518af8158f7e3fc081845895dfdd7338e5f22e3256918cf075437e7beb50bfe4416ce5a9c94d70075e5209f45c0a239c7550bdce1bd48ea2a3d521e78794bab0e3e78ff4ba1ca85ad579bd78878792fc9d5c5e1a8b52f62b091e5e2c06ed361af663fdc0b0db61b4f787749501b6c57088eccb4c4743a4ac3b75e8601a1eedf574b9db335000a9cecc68b2d3030485aecb73e74ca7b9dd577685a1b4f5497a6c72c74eebd8996ca796bebdd4268ac0e5e5831b04e4f996512707282669b26cd6e1d7fb78ee0f95cef36b64a2b9fb38e5561f48f7bc20e17e2948fb1889820d53053e10a279d0df78199d00a086df94643457ed329a135edd7b6984160b460875f091022a8f6233fb45dbf5ec363e4598838234ec25f2566745f73386b59461dfcb74a626d07e681493e8b599d3b3427e174e8164e0016152078ed4a4814d2f027b8dcba9679abcb9c50c16bed7bffe58cd181462fc833f5727b6ba0661956a0732d1c162bc4c9662b0725323c0ef32082fe87aab334d94d3975bc631b21e1ba04ffecd1a65e1875a2a98a628c7f09ee9fe85d00bd0b26d95bf813bd241be0e3eec5a6a15bacfb6ddf1f85610bdc25b15d7127b5dbaab9486e7c9e70d4ceef555aed4f3f005ad83d82e92ecdae4a8188032d2057d2e58465939ebe4cddb1809b17a5192320f04d9f99b63ce7a132a9c772a39d0dbbfca0eb8354ea147978d3a4117301e8941721c84c9c9283893c96d01f0581f12f14ec6a1bf7a773053ce8d0ea0440e02e878865fd412e4b32453a6987c25f1f9f665d02d4f0ef249194411ab621e8ebda4706ccada143c129f15382e2e1acabf33289cf38275668d581f7ffc5122d1a763a553ed35d0438be6a1309afd1848786d799a8a9d9ca83252998f3e0f4707baee1c73b1361f591844ff07c6dd52fa63aeb2ed943c224dacf2bcdda92edaa08302537be7935948868c3a0e6940982ae9b5700aa2f870a2f2b8a20b53ec07bb82c6f08d7dc5df95b431218956222a00584ec9871edd63d183a89a150101a598838fb6d0aa29a840b820af2be266e3633bd421d0046dfcffb79069688d7eaba9e53a5e292099c6f187643b7b26ce1973561041779dd2acc0f3cfb487cb939d5900fc9a90d7ffba9fac1c5d9178d4070f434de4ec3925b4a40c063c0900dd6c1e76d9d774f23b5108b76fa5f640b1fd2ab651491a2e6b1f487cadbaaa979d4ed72bf8ca3bf1dfd12159fde81927212b4c9ee73555ebf817eda26dee62ed51726d132115b7c489115223653fb5d20c08e1ae66e65e41776e703a3c0464453194d0ba6a5c8bb736768c2c804627665e51d9f8a901235b8c6ee0e278e1f2ade9be2c08cfe96838054a8b77239cb64b8bbb62001aa30db963cb313d3844b2d6b0b18b2789ab148f59e552162b2201432d6c7a73b0dc3b67a7525e4be9fa0021b6c5bbb8e0da998e8e95064fc46c433715617ff8b28979248e0df4a681a6ea46b49d3450f21f87b969aadca642d323eb3933b340b54d2242abd1ab38054f65f8c6948543006b2a8930dea7e79486ba117a8b135ff6bdb211406619a7e38820256f5170634ce1c0b1f81a89415fc7c72fff3f3493c349f013e9cab99e71d91c2e2af1563070611fd94c7d5c55428691ad6eb897cda607039d3b5d106511ac3687b79670134d763ceee92e9547e5885365021f4168fb52c449947490286b1232d278b58549490fe628074f94868c9f726de9b3e93d1c97334e2466b155f109b45ef718df009d70d453d6a9de0a518d10b3973e608ea791c13cd3128e4423f3b381f69332846ac0bd883c8e30213c1c562d6005918de66a4817ee3a3a840bf4793697a15325c7f30e1a7266de943203540eee7469a6e9462ce5e367dd37c0981db8e9f7ab06bd77b1e1052450c3760f28e9306be499773b35eed5ac7d00e53a48e4f6de1f18f83b34142a3793a48cc3c8ef86706058a0bfd3b521f8f0c2045f4de1c968ad03330d0dfa80f5ea716c8e5131cfbed88e39256eb2ff5c1ed4cec86fa1b47bbd6a2662687847616f116705189b7cfa86eb72cc8ae9e61272aff7eb76c9f07cadfc4390cb469c7494e3a89ba3883a588d0f18c1e4fa7e2c71e0eb59b40e4bcd9d9cfb5db89575419912d57f96d4450b70a441c91500e163400fb7979ac386f6e6e3ce1a285c65a97f9e02374831629604704a7eb9bc9c16f3be4889578c5ea79deb800d802bf641cf0b54a905508f16b27352f247bca393970e7131303d98f342bdb80d97c9c23203616ebbd85f5875e6fdf44c07e5b9e31c1aba60dd5a2ea6eb34f46168e31d0390e14c17c6c753e2d235f682ab0a7b913f054c765091b4290ad9a50a79989d64bc0e8585e46c104b648f4d6815377fab0e6394b8119a0d1c22f184b3e961a656257924b3ac4a5258a0497958cff33d4dfd5cc2b6823398c8a2bfe09dc3d29940205933f890f144d5f779dc2f93d6483b5d1506069346068daef30737f82abb2c7ecf70219496074f30000000000000000000000000000000000000000070c0f141d23" }, { "tip_id": "tip://id/US-db372e842a4c5abb", "region": "US", "public_key": "203427fea57b0464fbf8f3df49f8623b22c19eeabb53c6890cc6d719ab23fcd35a465660c0ca0b8aacdab1cd81a7c209dc695323aa0bcf018a8add9c179afd00854a79f0c5c3f914ac92d74cd50617b1cd4a4103867b0a14df9c5a3e2bb563c92530b92ca61f2daa8ec8f4e3d2ac465408888f395bc29206af31e834c9f1bde3811eb0e22c268fa3a573dc91251e9cccd5a2e89e9d7a08a326368ab6b2b84ae6be6be71f2a4759f9d37ed44af8fe1f02f59b4fde88557e0cda6db52a835d760c4b0b054e54c1b949fbdc3142abcd54eccc10349028ba661b85a21f394a714cb2633c7910f93d27888fc03548c9ef27c4c466b8a28771f945f8b3d1fa567e365c5a03e995aa83f400a144b3e439eaf327cbfd50deaec34866d84032f3f7a033f8743be215e8741175128bcdd6c0ed73744a06a7c0e47bf50c72e0a8d7b43a870f1295a68dfa942b6a26f94b896db177b7c6c1f9d090c1eaca2f1d03a651291b5e4e221fb1208db4cf8a3b3486508fcf373a47777fb994f384046fc99a35c37107ce223c5c4141ea63491a083d3f4b97167c26d8653d8ea7160687938ec013f3ed5979f80ca50240762c545af4f802be5662ea6c8fa2fae5607cd066648f5eb47d28d3aa54358f3634ceaf1cf204342094f9e78c384cce6654fb8bb49c7e859971c5da2d2dcb814db5f5b104e61f1646ee3d57a07a8af8fcd2629a8dd926a82f4d1777a3823bd4ae14a4a71e5a8cc8635bb1317762f1c206eef9926413f1fabdac23ee1de6827a0b9dfb1817c9fddf57ef06e430c28b183149db7e58e41e06273bfbd7c22d45c35fae0b87f66a1fa2b663fd1c74bec41a8d7bd1a47246e0416e1e23ce849daa76d423254a013f73195e4ca6079a0eaba71441d18abbf7cf1c2bf0e78da03963ee79f77a9d622d7083c01e515cde045d619432175e1b3a607d21915515c6647c5e9b834ac16a8b715c8fd8881627e14c9a6dcb6f9badc5e30416bba709c70c98463e87d518b15fa0abf2081f9ebbf939bbdeb7ea12fca96855590435d3e63cdfc96731c8bd856df4ce4be49b54d5784981e72307cf0bca54e1a71fe7689eda0f0dedef796aae5a0a1c6f6aa055b4de2ba2c32bd3fcf99b5fd74ec5f6f32ec802e97d0f4276acce192a4450c7d203c1b7185341dfb4c129a218058e34d4fb7c5d9a2665b2faf08191af2a2203247d044077f2b391c78695c67b775f7f8e3dc1ed156f6f65933413cb8261edca7cd1209283902a5c79241dc2621dadb2e8cf014d8ae950d1fee20ee8342e72b9fb2406218ee28ff7019464658f3dd3ae07f08722b60dffb51d8ef732e0dfee76dc5af298a21bcfbc0f976c359baf6265489cd879f44d194449f8cdf09dba5a5977ef8911d845ff7509f471b8afa58eff4d81b996ce0ad364c78e2801572048b2939665748b8f2c79d594a57b813e9049a4f065474bf505606ea7c1926297b98380bc86c30978aa6a3639585059a2f8d607bb2a7c01c5c7a1c211cc93785b6ee1e9b59a78bf797464e16986aa19a4913303f7e8b9bc1a3be5bd183fea311074ccec87e7d707344572ffa3fe7a03bff4c6b003655121915b2850daef1a1b83e6527efdd98a8950c67e958507236719f9f1e58e063c4152fd2ead8e8dd66e2e3caf5b01a95b57a99f51d6550a76afc6c30ac778cb132f53e1131d6e5d16ad1fa4447cee583bd89b48dcc47821991c41849c782c1d2b0f7e61a17559ea92cf71b08062a66e7e662635d70b754af3f742b5f4947bc34d3087d85688d4dcfd350ec3419f41eaa7d854420a6d906d36d5f3c5085758f6c68542633c638076faafdb064b7029f7e2f0c26378c2bcf3516923cc9bb4cce74e1dd5b69c6da19cf738166671a391aa8fefd6df9f87795175452b64980cb41b8df9308f9d4be33367f4bc51beb279a0f98828e65ff722e6d7c155fa0daee1999ce34cf7afa85ff5c3eae3ccdb6f87ca3b0a08ade684d3e11a642bb723153b501ddfb235d368600dc01ec167479538d70ad7441b86b5c06a827db769ff3584d8325a734ce9473b3e7a107fb9587d4f33fef05d8349f3c03981691b3ed14944aacbf4c3fd419c4856ab97f34ecffd97ea4c0a632af305a094172d278f49dec1c417954fc90dac420251c7995795d4e414020dc126880379871df97ad4a4e9e75ba6ee200a4c37935b683c54580236cabff806c5243faaaa9ce153f8a81ae2f8f5d6fd232d81194de57264d52fd8e678f80ad75b56f589c3cb9289face03ba8a6ca277a416095b297ecb6070e11c2294d13363aaec38984b5721041d19ba5516ec4de283c9256601cef75bd02f78d5d88c1febfeaed4424bc10f73acac22ede8b03db96e4793f991756bfea8a05bf767cd9e811310c5bed826fc0d364a502c90b2cca88d2e8ed6b77ced8baa0afaa35ab8a608ac7999c38656b67a5bb616fab801fd1c7940f1d17013c5fd4a37c4dbb5746e34da612281501e5370abdee5c1ed2202bda429bedd8a9e93a74b01f21d35fdb6e28056c613adee635aef9638f6a33b4b751f834fe9add8b73933ac01c78d941330f5c8e6bea012430adb9ad8cc709b24ae50d4860c086e4d678a8c9e542660329765cf0b6d22a73b232892fd55fda5076d1be62a78aa185f79124a6a4fdd6a9a9d15adcc51e85dd57fbd5dbd8441aa5818066177e3f5363709bcec006719053e12cdc9d06e1eab6f156a6cecaa99d89bbf633493f3cc543d16f780c0424a97771e7b987376076b96dbe088", "dedup_hash": "70044443154882484498", "vp_signature": "1430669217e947d6d2a508590ce581433f2a2abcf7456175f077eeab19882b988a1ede33489b142e7e1c36bc63ad7db2021dd992b260d7bac402cca7f1e04dc92bb8533fd4099be4f3eb9b5736e54e3c3ba7e8385e9bc6993b8fe384356aa64191dbc200ef0c605c8055a84a221abe43ef30c154f45321314bb3a3e6e159d1754b62e3e895c6bf910af6ddbee2cebeeacc5a91ef924ad282c99688a5603ffda4bf5d7a84b1263ddcc7c1df9c78eacdd15ecb00214e0ea24ba3a29f119486f7137226c460e611e134ef4c0b78288f4dd3c81d1fabedb11d4e5edd2de0882a6c6f53e8ec67a3fb2d6d9f14018b39c57ba4e25e470d6e27add5dd147311b92e64b1e205fc4d503fd90db953757ec0143133616b3a65d5906f9ccd83441a8e80e4534a489677d70fe157ca24bb812853b0325fa864481873341a6481afe93e9d013ca67b679b3fadea6c1649abb868451f43db452d13a972b0642157f697860ff12e6554d20299bcf493347bcefe7fa1cba52560c5a12283405be7300ae0cf6a70558e8cc8098e973a4ecd448608f61c48f4b9f009ac2126b54c635bff1fd71e080004fcc0e529b783303fc3daaee12dbc99134719a9d5e70910c6baa66c0d2407ae0cb0aeaa30f5f8f34c4261ccd853aee7249561ea144ec707efd1b342ed826a7460e3e6ae2acd9427dd80a38b15ad47411678c36b0f6af388c0298835817e2cca1fc8f8b31ffb179320e444d428a20911a09186d67fb5ae13f68faeceb62d2cb9a98f9b18c575b797a64e4e99e2ff555dfb8479bc92cd813e438c1dfa4c44ca30b849e73c9037734a51b0499f591be4076b15eb954ca2c63665937daae53fea23bdd475c43f0ab4e7504a237893bf38ac0ba4a908c523a85bac889c5b4bb6003f6dce68fb2dba78e9e0616ab773bf9ec1db6de1976adcf058f78a3da43f5544e5ce9c7b4b8a6ff85b414c7471a4c6b3625994f52a98cdea961572edb0273b8847a03f0d27d1d1e0d368cfb789a0baf7510b14864d1ea315be9f38b479985e1a6b4d0edb7393e4d8f8e8236a574af8aa885765dfacedb5ff4f58a85c88341ef739cf569c31cd3116defc14deee7f7d9e56b369ac4bab45dd572a5c6ca4921082db7769ee50750b64dd309c620e6ac9835b36e0263fa8d0bab3e95ff6505b577927bf49003afa4116371f41a793374d85c87fd3e9c1197119e9b97ff303311c408cc30a77174bca3b158083fa5d8908a0a63528501550e23742f8f7d59725b2b509caa1683f9fbf56366700dec40ad1cb55b684f6e758b0c9ce0022ae2861be2a2820d19bcdd4515a094ef5521c1112a5f67087183184c0257f2939317f1ac06ea1f31a83d3de25510887272c647f215167742902c7f7e933f353b0984917e85c1e02fa1da8b43f48d18b5eb9c9c8ea64ceca89777e1c192757335b257fbfb480424234946f9700845c485e93880a78735b91fb7da83376ec76f45288b9150df5faabfeec2d6e65f02dfe1739d21ec6eff7cb2ae672372e5e826f174ccce28c513b22cefba672aae8a8689e01a15e8287cb212dbfc2dad3267e3a7ed5b4217bdbb5dc9595eab66514a3648f69c3324c3b0d929e58a195b232480ce96fe7841315d7427ecb03d05a76b34a49f6badd430308fa31a590e50fe691afe62d3c019d015cfd060afe508cafc7b1717aec5574d16d756c7a90e1176c4002fe5e91e9dbf79d2d220242237a19a0c12faff57cf04b228eeef54b07f6abf15fd4ff60aba8963978595b237fee0efcef16cd493cc24dc6a6dc36a34471aae5b73708f15eeb7a482211de66ada51c7b28631a44237dc26fc4c6e0905250ddb6d53e2b69cfbaad5c2c8f5d781b3f5399a8100e0b455df3be308c96faa9dc7fa7fc9b6a140541c3d27030d5f405dd23e89b0816eb2703070d16a0e8a68923ded6eb8682035731af84f4fcd11ac10eb63616b609afbb5a09488c8fa5bfbf86278cf46cb46be9c78dd4af29f2cc22359871d6d6bc0b3175a31903409403006eb9757cb78e1139d4f8a6bafb7653c860d0cd419bee476a0e028c0550c5dc3d15170359762c36f898ad54fac1553ece86946ff16bd1f085ce201c7b888e245b977898e74df171cfa856ed157a927ef6bb29930a608bffbd807c826e8d8e0e8133c6cb2e79e8ff0a59b33f7cfdc73132eb67c05a621968789bd2d1b0eb07e57ebea9e8183ac3c6b2a2e4a51b0e856a9d33c63f64b675dcf94bbe654905aede1abf45591797c0656901063d7f70caeb00854d881544f399fb1696113ec58002dd9eb9119e2810ae115446b0ad502e7985a571ae227b4d9029bad833c2939cd8dbff9c1f326540febcb9445c8605b90f03cefb7f069e61a1efe13a8c932f7539dab2e9a33fabd262ab2507a6dce506bd64f00600aceb97fde2d902e25c6ea2d4079b974840c33fcbded9abf79f35e6cc36a56c39b1c685a2309815b9b8694d55a63b46a2d6c98594e61aa966d307190fb5a4911ada8e186861a2c8823772ed0af4ebbe0d5b5cef7b6ac763bfba3ff247660f4a94edd46d6ab82b41de46c4dd1fbdca3a99c1214de529f76645e6f9f08c9c81aacd509b8acba791c6def35ce812d462e610066b72eeffc58aff7753377e585a414dbf8cc06a36df30ffae47204e4ca36c978a490ee67130c9541607875655c7cc2ff3b185fe31ec5a267b6865fe6f175822ea60df7856a772b85670c4110f6ca7614f30224a7d47cc2da83d81bd1ffcedc3e257c8c41b958bb6cee66ff86de86bfe4dda58fedf02159a9eedfe6b45ed47998ff19ddcc37183d5c3fd6005175c95420b9dfc3f5ce7905b4e48f2344ef029bf1479cd78bba3c91be25f48b5638411060b5f159ef6e2fbdc0dde70346b7b087ced2d0c416e73fa2657b4c2e0d0deaef328263ccc6a9e0091a85e3908b0c15f6ca35d851dc61e88ccfaeeb56274c92688f5eca697bd172474c25363fa78a213e6ae233e43cd7d6945f4684452d4cc952b93aa64ce24d6548e36f011aeab9dbcea787e8fba6be0e97094b92fee2d0813b1022800745c72e92a5138627c13c856d5d8b37501b1bab5847f0ab2659fca8db31d78e0335730cc75abbbc67a66379b739faee2140ea00077b9ec9d95fe94a4b1d01c260466228119ecb029e3caa78b57c098dc0677e08429b0f7b76188464ba1a82d17cc3c0d3da4356a3b351df7f6b7e9e9d9b8f83e18e9af5a4c8718c7a2cb3ebfa7c171a6c9a96dae84026577d0699ddf3b3390ec241fc33ebe63b33deddde3794aed4e3c4a5642d0b217cf14ba3c31034089000044ff3038cd2d317ee3cfcdeefd1538b76e38ba1dbeb95e97c7df39a4d9ba75c19d698ef07f477fc494872b0944d8d3d347fc2a3a19ce75d4858bafd8aad67534bb96c1fa143ea911af07495f9b612e1c081b6d425411ecbb162174d2aca9cf6d2bdff39d3348a0c06ad029f38a0e6dbd2d1c80fab0302129a3183e1cb1ff9ba6ee77018565607aa8a59b61cdc8d8eb4672b59bab909ba3ac53132633893d1144bc01c7eb9f0e68bc59f01a072aadc2545d632d119562c5ebd1e43f870e3b060324031eca471922344fc5ff7a487b50431428addc9a7d56a8058dae17c488bb0d7cd31b9c159f86e265ab983703135390a2c0c466d9617af6786bb295b88e597457d297c4f576acdc40ff024c823bf73527628665ce047c92141df0becb6524570be2a3d1122dc21369726df764ed11e9b9414f5d22ed82a21135887fd670789562dd744a1f161c0a1918f5ebaa81dd531e77abaf2dc80e859a0cf71a7d3b63f1f7b39ff72f5866b4ebc6ccb89647cbce856227aa62fc21dd268ec66b0b0953ae4e11b5924b5aa6e6279220dcc450a176530ce8e284b1e1f9c6d93418597cf608a1001428a98e17a339d26ea8912eeaac5b4cc93921b350ce34c30196f58d63448d770a4e4ce11797fb563c92bbe70067449b7cdede3bd670b730b8b332606f7544cc763f6970daddbb1cc2397cbd2ea92d4f88ff70a0c4b64ccd686bbf9a450a28e60e637199fdae47d4718eb1520642c7f8a369981226c16d002a66185518a93649bb3db7bf1fbfd9c03ae6e05fe37921ccd444667e4f297d194651b6d7da9374cd8520c9dedec50b5cc3e0532036933a857b86e2835f74dc2dba29712171f8c30e457744859e4d5bb109e93eb81aab94e2486e2fd1786f3e9867c01a439c95ccb7a29f391fcf9ebfbf0f3ef1fddbfc4195162b42dc94dbc83b8ab9c4371410521089e1375581ff26849a07ca537f065165501e74d8e3d19c41b76599ca95a2f0171f80ba239fc5ee850df743b16d496b1e82cb5899748b15301160340a25f8a743d90d5e2b9f066b186c3c51c0922a8d85c386ff05b1e6f838d3699d504f997af771207d987777881af031633037aeb1ac1222999e718cf33c1574bace846f2d9e1e5afb0051b0d895c1123863af0cd4f784490d34866c9eb3f8ec32d7979829e6e73be98f0424865f93a7f6871266da993356caed4eae585aa58fe25ecf9011ac24afc8adc256437683ef62e1c79662cc2cbff1db4ee3846678682b9ab17d04ff4ce235df8398de28a7c3fc309fad55a51a466a8085920d5e742c373b488894a92e8392b4c9d9405b6e7593acbed5444da2b3bcbfe2fe0000000000000000000000000000000000060910161e26" }],     // [{ tip_id, region, public_key, dedup_hash, vp_signature }] — embedded by seed
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
let GENESIS_TX_SIGNATURE = "7fceb93a636f7b64a18f749a977e03fe4772a3fca276acc95f0c711bcf9b95b272a63a6220ec86645b0813d5177f74b9f8457fba2cb93531700ff341a08f40d4ea363f1344a191c2fd7a9a8f53edbe79ab6dd8f207d2464b827c59fe2bb7af0d4b6b05b65796bb40391f5cfa1d1511b6421a760cdd3126a0dee772ff9a5ceb84b716105495a9a549bd3a3ac87da67a83dda759f71eca74193427ae62328eb16d36eaaab18deef637388b68c25442e4ca4003a8cc4a4e266cad1b45224bb0eadcabb88ceb87d8c06a86439106203aafad84519fa5134ab854c021eebf5ac62ff78cdc8667331eb3a89411d5d962ec4ef7d34f85059d0242bc15c34949ddf240a448c7c3bf0b0188a58b14441ca14eed28a1b1633ecad435c6e134b65fa3b3ad135e755e8de9df51f22f59f391cbc901948fd0b48002b591348011735f432c852a788fe516581d12fd655677a6b74abc323ea14fcf667f019c2ce5bd6ae9af40533bec7d42f5c223ea6b0cf6992e53478f69388b49fd51890ddfaabfd06b8dd7ab17ae13e1763269aa10b0dfa70e6b0d70e10bb2df2a58e66a584a9916d6e6bc9e3fc4b244d2b39f768958fa6ca04a38af3859752fa175290c942007f403d6d9946badfdd86f2b70b719b09f1e9c8f2af461dfa6218d559ef91e3c22b03b8fedee3411d707748287e11caa8dd472eb97a10b08a865e7751bca25620615a25a8dfffa5b2cd91fa2172253a269b615f6ea66739f30c7632e0aeb4a82773c345b888556244221b615938d17d6cf1d8ed09a3851230b193d628daf862e0ef4cc55094d7e6ea84f68c372dcbe6afc4c63693246f915469f5758bbc50a865be43408fb54e740213be707588b2b1bac371ee951fd181999c60589947542f543723e0bdd6bc056d45a25c732ec2f5b6f7063c84ed839e83b396aa94443ae1dd2c51a5d74fa95fb8af9727fdf667813ffd0c08bf7b6e7da9a53bb5833e9a720eff58d245821b3020fed8ceca337e47d3784dc79cee35451213051fed5439518e689ab0f1f00ab1dbb6c55b94c2e278a715bd44cfef4bc35b89b1839cf152eda73081b1e44d4b6b2fe6f6f4c59df81c0cec937efed38485849f301f514d9e31e4b8db80bd1f3ffa95bfeacd9a22d11be7277f9dc88e694a5dfd3764c9b55cd1849e28f06a59f28f4b44213f2219accb50320dd32a1e71b437cbd388a011784f6056d9b3180dc223cfc3c8c118cd52d9c375fc36f666dea09e3a341252c0b2f0b428ff07199180eb8dbd474d8b8a806ef1abb8c2bfa2edb80d7764986f7f94558f5e738721518a6619fd7f794e254cd36ce90ba03d8883583f8b3229b682cdfad66af8db4b469d08d5357afcc6ff6bf4120fa5df25ec3a8adc736e69af0660c16487a5d6ab5dc1f36f7d4558c960f0bb104814c81ae51d6481d27a2a5ca175e9b3c4c203f35896dc1e6a21adb263c2500520f26a71b5dcb0332d8571df1f6a4e863e7092f6c57170243a18b20842860680b908e5cb316067834b1a9f0ddccf128d280ac1a353a862a41d10a33f64d580a9e66aa0917c1f5a523403af666942d1ee55d759d912caea33ddb6ddc460772df3614f5505c3097c55aae25165ec14f6cd80777622ac44a99667eb30cd5594446ee417048bf02774b71b463614517b834cbe54c94575580eaa14440bc6c5fefed62a761bfb0eab5e72a3596f9d7166e69f5c53dfc6f1c650aaef356a443a4d1c56aeb0023556f8c9b2a09110b71b1a80e4a78554d0d6fd2895bf1629a2437b6491b11b2bb57b41dc8af5a7c649902f33b9d8a1237a8b425513d11c5856736a61709e98775fe44ca57c5a3243a8eb82b2093c054e4a263828b8784193c6bbbe5761a1ce41e4c0e62e143fe6098d6a05b5b3fb95eb1c4ee501a5b4895f059683698a7ee882cb704fec084dec8dec35db3f04e6710f01637f07ab50582db967904b6398629bdfb1d37b3f4f91370598ee7c0698a0f27c56b0d3bbc18541337999f2f8ff46d1c848db3f93b030623e19b658d015a17fdeb39ba3cd7ec3eddeb96c9ad2aba147b3af20331337387710dc14ac570bed33965405eed5886382d79fe0b34dc07bbff5d5104fde33f194c4361893a7450dc76ab44b5e86f7df4de939e304f24cd80a032317a160df0005ca65897d922cc632955dc202f4006c029e507c9dd2f2d525a013d17eb6bdd65453d4f4a40559e1ae1fbca860744b70112f55be257a8b8961d958218b7edd414cfab1a63f0b46c811961f28ceace2ea1cf7749cc3898457e3783e7e56f0c2898ac4a9a2147a0b01133bf56d61ac3c0a0cb874826a6073e275cb9390ed47d962ce9376743777206a60be7fca186c3655851700c516001ebce72fa9dadd7de93225592b960ec2af530d4f34a8104588b759444679dea01c349ac997291342a6da7d0cb6e53e8febb14cacc5013a60099ceca55444708daf799851177afb547cc68fa143cfa47a7c8cbc82e7bad0b5bb7f9b93b8a90e2f7584cb29b7b06afece34e046d8ad6cfae29e33db1d57d350e4bcd4731e536d34683ecb7f0c754936e8183e720cd7da4f4b84657086e597efe128fc733c05f1c15681005ee33cd3ebe8de827503ef645b7c24af5d4db9f1eb03e76c4ceac1ace3c232b62894eb77245b81a7f7f72f2bcfd91c9e081afb6fd7b495a86b3a303f792d1a4bc01152e8e0e1e813881f6ade28555b19909c687ba393421873b9a2bf537f8fee73fb9ec261ba6f838bd9f25d84c40b12324a7c942993011ed8477e689ae0eb9412ece565e14ed023af1b277fe23575b8b3428929fa9316a6b539d28d4b1fcc5f3649fe0f30533d163195ed8952e5a9cabb2fb6874147f28404d645db4e6c7b1c7f8910c3aae74df40464b56fd36424d298f61b8a5a20a20eec5943ee233c668172781742524578429752fb72b63305ae737f45120ade2ded4f4c8d5cb738b39cb12022be4d1201d225e50f944ffe19f99b1007ff5aafca4d60146402165c5418edcf7b868e7285664ce09e3b1c496a9d5fd8e09bae81cabc2b67a0bea735da404140fd6856bc5a48332ea30f5ad7138966d9b5ffe9c84300fa9d8b1942fe6b38cc9da0668f4074d5806738083d44a8d070015ef7a3739cb498c88ece84fbdc2135915f7ff849239f0552c49c1973ddd47211cede54f6184be427edf487ef9d36c82244492a6d1413620f15cdf744cd1adfc73eccb3af2057edc57d6952bdca8432a6662703012c351ca11d41b9a3b2f31cd782b59c3c1b50757bdb2fccdf6ac6191748adfd99a99cbebc8110623178a22071ad56b15139db1c2ce384d7f694404e340cb3d837e94b8ee1ae79c3c34d4fdd077b004e50915010b3df2e70c24c4b4bdf601bc2a4de26c98187afb72fc872aa40343f7cf5d05867341b1ef5453e364c2466ed031fbcbadbf3ccba44dbdbc0cedae4b58f48dd75b215a26f71646c9348b92cd274a6e1db7873385b93179fcf2ac64c5e3d6e7e9d5ac125473fff315246289dcb8faa556eb9dcc640b1536982e9c0a92ad40d2ad4a38c30990bc22c7f0751b4b096d76966c545b79899577cfdbfecbb803527e4eba76a6fb8ce1feed7542e93b9fa6a19c72b07f5326ded25977012d2d7c47654af35e98e41215153206cfedf24ac1fc56fb04e352a2df89fa8af0cca37db052e2b78963deee922a3d782057360544786c9100a4420808a7c9f816ce3dc3c9d4569c250f6b6e0f993011a469f5d12a6d4412887ddeb22b0c4ccd48a5cab6d6139fa2d1977bbb9ee614b8a6261affe2e54cdf86e266c17a056f7009239ff5f9305d00f28f0b9d5e308cdebf577251cb4460281646a9dd675622e2be39f7469e53aa09f564ff80bfae5423567ac210e1c0a27e883c49aa832962e758d0bbf448a635cc1af33c8e3e667727498307d39c547938486728b18dbe98515fbcd820e0ce0611df0e3d1397e4353375996210307d99593ac1cf264c5f4e9e3926527614abf8042315478ca07f31cde8af2dd2010357dcb9bc52bd0149eab4327bc0406bd82e91350ed56142043fafe7f109eeddd03ec90196fbb79fb0a65cda7cbe2d9d49e64b5fedf911d4ab26d3455b8cdac73fde49785396b90bbb74931fc18873edc476745bd36736bf9a6bcdd2348330a22e66bd9b162fe5c295f71ede0d852d7dc1c70caf589c05d3d05a9ac2eb1ce2f87141074bdd0812ebfd1e6171ae44635f4f286bcc99097158f54cd9c15100fea8ed83caa7111f9d40d533fc251ba47f30971bc5757e06ac98cba4827eeaa830e9d7cf8e42e2d7303a2f79b7544a5e1132498ac8939de90e0a05c80c2d6acdaa64f8bdffbcc778f4865ee7ddd55c448147c9a749979a661f3897e31f9afe067e163020acc893b1739c9ec2382a4c18bb60c539643d5d80a6b1285d1ba3db2ef09d41c4e9318e9b6e0016c83d5fb3c56f34502917ed549c1f35a25dacf37c6d03e31c1a2d0ae1b945149d54f726a5e36a5173feba5a5dd2dabaa6b86dc86b14493508acebcbe30fd8d5f9b9eac596734c49274ecd3ede1f6a8e0e3a6f39551bd67ec6facb93305ef6bfa317ccc4a21a4105e2d2f4bf75bae87c2f32b1da002a535566909eb7c5c6d8e4eaf3070d155d68767bdaf90b98afb4bdc6e30013667597abf6b15b9eb3e000000000000000000000000000000d161d242529";
let GENESIS_VP_TX_SIGNATURE = "ff3f391f41c2d4670bf71801065475e22fa6b530ff221735160bf30b7b08cedb88451cee85e6405e3388c28b1b46868b5079c47781bf07d23cd3b025da3f56ba1af963cf9fc06a302d2962988c1a55800adaf81f029dc08fe3b7557fc4f9879aad0069e5d1f6211346ee1174e8f2142cf1e8a55a65875a7cc4279c89fdd7b8db5f2466d3f8aa9828cbb682af14435d0d99dd127bfa2c2e6c50ff3e2ec0059aab8df4d25c5c7a8ca85344ef3ed983a17a18a95220ca9f5dcad3858df0eeb5f1596346f59aee447c2e66c863cc578dd4e3c0253a3ecddd3a4184491ddd1613ab7d0e20deb522d25ce25cf2079fa6b7bb50faa17dabb13fa5e4f8e84bd43678075b27ce2ae5667a68d487e41fca0353650efe97d58428e746ca132fa4a6e7225dc400153bf0522f7ef40c88a439e00f84ec337a5d9b3372f4675f688cfe2a5e986daf824e9e806a00c89d9da09379fe6f208af723da3f8d14b50b8ae9503008bdc7599adb9e001a5ff09503770207fce3e50cbb823db745e22ee0c4055b00785a948360787aec6b13e49383413a97352de91f0a54bc901170c1897a3d7d6d866b0ab30a475173ae38dbbb6be47d9e67581469e6b68e5872b8f61c5f99741fa30d3fc52af11b1678ca58ec3c4e89a38fefb34f2971fdf66653110595515de489f28ad893e1edfe1573e009b83b39f87dd519a0e0762b96e56f2e372f6471afc97279f21557400e7397f5bddc45f369a410940af93471cec56992c38b16c72e9f8aa6e1dd5e742ccb5b63749d1275ba49dc183bc7f07adc43509163153d10b14d9ee631e51bda782b15fcaae4140494178f8870ff9a43d562e320cfe7acfe210bdff54ffbe731affffa395afccfb9fd0e984419bfa93f54943f82fff05dfca3a3218f26bc2bb9b1f3be4d6c03782dfb4db0e46379ef3fa86fb520178210926ecb43b131bb508895a37fe4d8d9567c8d089258606f3ac59bb3dcc04ad9f741dbcbe95b6549f89fb8ce34e771ca5003676d678f4c3da7cdc4bc52561691a428515a9727416f01837cd8e4abdf7924269b6c23c4202e5c57200e660e45a86cffb7471385fe10713f7bc1dc92cd015d4420eb8bfbd9037189a36a3b9968b3e4504eb4d76a2c962d2f81a7a0af617fc40be3df06674ef26c8e26d8ebb89ee932011570ac9b59ac923ff07e06ccb6846c390e610c0c69506a48a63a09860feb552e34aa07d70178a662af7a5b6e70a0fcbfc68c456b559d8eeae66b6510a8e7c8b3fb08e9dd04034b281964069692f91459210a4aa963cb93ac79daff55d4bcadb9c4b8e197b160eec26ddb78dddfe76e69f322811612646105a5a826cd7d8629924bed179f6b7847030995a087417294325e71411d768bb943663b99deb044acd2c4d9ad12b9c978fe185770ca7be89b43085ebd7f9606e42eb71758886d44f607ccd56e9eb17cc71ff55df155cbbe88a0b789797b03f20e45d2b05965c64c8c3daffa594f7d9d91eb1a810f2e2ca8d21ae93e9276fa605b1dcf3ef993016ba87c36d873421e2943e9ec2d712bc8f55127bccb009aa6738c1ba709733ff36f24621fa2155ccb1491b563a10112213d0c09ee44ace2beffae0d8d3f6ceb77b653b85baf7f28bfd3d1248768ddb0a032e1d7840822e2062eabc79ea913ea095ba0220ddd9243b5bf9d14b1f6bdd92935ba2fbfe9e0eb2880faaaab1b2d43c7e33bf9ae8c52616f05f509628a09ce7013bf1ec120daf72246650886fbcfdd6ae500bff64caabf77e4ec80f8b7754ecc0cbc1f73f7379eb3b5bd1be0b40d8b4305a7aba73afb39477892f97c74c9f29b4cf620ac1a64e87ccc2a834741e35a1f5d9632d239c22085d9f2c1bb1dfadef15c8e021b89ce29241b4f6889d2a5c62f219e07fc3730c4180bca1f6ed62573f2feaeb49e09ac8441ecd694b0403d30f0714194a1fa7140f828cfe32f02bee5ecc27cb085bd5a5fcbeef6d96a69ac5bd355672b65efb843320486023d3e51c44a6a75879394894562e18f0f99b5403f2782151e49593b901f8e0b48760b4743f64fd8e3c1f088bca0c8dff04f94ded2c2593552266e8664e395321da58cb46ae9c82b3b4c73cb5f84b91f2ca7f5ba2d2568c13f00c3ee9e51a8077093a6c00776db5e45fe311907c12008fe6ae6d78af675eb27d9a7a9d1b5923f47aa0720eba1eca47af939ed985516622c9586f0d15ee6919a6a28615676ece3df91af04808585ef6ec9b8b29751e75091be99e7bf5529c41f4ec4cdf196ed1e477fa3dc55365f1fdb0c0df16e0d758579977788af6653f7b37fa78f002de505b1d6143ed6946ebacfd1670b2d32a115748f5e6dec7aaccbd257a3c398074faefe46dffc112d78744ffea36e4d44b329dd31d647d03c81715022dc2cbf7ed210bd7c0e4bf587699750a0dcf70dbf183907787bee58a3a8b7f3988f5decea2755c47ae8ae420b8e80ba1dda9589937e35f5f8a16138275cdb361f5b88cbcb099a4627a7d2c8109927942faca8aa6f2b8e416155ea29f21497563f654327e132776169379fdd3bc716575b29c11448fdde15d195d81fe8cb977288c8c8990d88c7c1629ca156fb0b2310f6c8940300e75e46364890669cc4e72e32462d895def6807a27f2325af604ffddaf53d124605d263ff9540a257af3a19ac2926a07644d06378aa38d2bd9342dcd4c8749fd69d66eb07d731ada8a8e36dd0928aa81160318d1ea7deb85deb9dd6e1499fb81c9c44bbdfeec3f88cc797099891d3a9e850103d72e5e5b553de3c9b8a40798047966026c0654bb96d2c15499658e111973c6aa9ac147d74a97d527e5d2390f91dac54f21d137521957d46f2a2ebf5b50b55eb92e480c162dbb296010738641060e65793b6308608b011e408fa0ba76d852f5255bd7b95ddf3b5dfecce803d4b94d009cfed38a48bae2655b4760da215278f77773d8ae5f0fb8f7710146169331ebfc96a856e856f9df252fb8b2348bd7d538f59c6175cce6568b8185e0805f24559ade34554aa85e28b3527275221244ada1491baeae0f12b33d93937d88f85e827d84d015190a211ae06c53ce3e1f8e58eb33a4806e1e1b1e8a084009f0698103a23ee0f343f6d027379647041321be2541eb069a09d6a5548d398561552d46e4f69ca4c848e97580e6a2cfcd4a5581ab00ba38a66df2a9c8e275ce6436fed61b908befcb0962115fcaedced8b67a0aba256789c56a0f1195b97cb762c6a864ab7aa729da60b0c34275ff16e43ad1ba00f93d0275e19aa97b07ff36326f31e436616ff426ddc35ea10ec21d34a15e4fc66bb9969403f56717884b445c714ba8e437e3a5e84402ed840ab215c3dc941ffdb363a2a40512ca42a9e5fe370096ea2bb95d824a7c48241213508e5102db0b63094bbfed357f9ce3058ba792ce5fc9120e7b6af0b50a36ab484e3d7eb4d7e6558a034ab8772eef1725a7dbb7c1673de74b5d4c7ac5195ba8088852ca77a440e29c2c8304c5898607020355c74da36eab4f54737446b4c185a7196dbe57e7d3fef08c45bd5a3c27d55d30d695f18b9b3d96c298e4ad504953c896af7ddd385ce2b88e64ebad6d86d7a18f6785c5c4ef9e9fa23d92200871308415bdb7ae559bd2ade93d67a861cd4e6b44ea2ba20dc583c0d9ceecf846aae47c25c1db7cd320d5bb7a6710abd4081d28cad1c64599fa690d05b6a23a15774e45320a2092b87594dc8a197a44af435194bc44cc5b5acc19e8ef4be1e92a8d055556f82b3381eb3cc8fa848b047ac381c0aa10b3d067ecc1fa29273d61bb970dbaa56cc3bc38977d1b2860b526c0eaed23763772ad29678577b1c589b101e87e84dc7c2a32366633ee3070eca26c005384424ff643105b677e3badb980eab8a6277ccb5b17c6e37aad9ada289a354976153d4a2dbed84e9a91429ba05f370be3cc8dcdc6a13be573d7846322c4435119d5dadcf2263b069750085e6b6e7b009480bb8aa7d1e3a9b110e2cb225a3d04c16b9e8fe5e59fd1112dc5107b3cd82635923db3967bfb82f2e9adfd7b1295b0232d026569c84f6204dc87d728bb087a88bafb225685cbc0dc179f9fceade926e8f4cf00b5229053214b65829bf8fc044db5f37ceeaa35a291af052f62a05324fdf4ee8f78dec4a10fe2e2d62c35ffdf5102748036e6045eabca03d0522522b32647229cabfc3bca183508b18abd052549b8258a4fa3b6fdbc4318fca0acdab2db3c70f4648fc60ae455f9cb36815e86e3aa3c2dcffc0e9aa17cbb3daf22abde5f5551486f2afd80c5aa2b2c934cfd759964a31b02c5c0e9ea207f237ebea6705c0b52749b3c0e813a06f87d9ea68940859986139db7c8b4e878cea5799365b1d0bb80d8ee83dc0eb8a0d0f979c003d64977516f45736d8a436781ae17bd70d35a8cd28aa3ddacb37ad5fbec96ec495bd5a9eed8fdb30faad28d49bd87b146a449882cf0045451dc886d15e38b5966ec682fa30c00529af61d7baf596bf35345750feedd671bd06f83e59b5370718cc69814127ed63564b167d41b3b4a80e2a5379da7f809319367c8c6873d7e940d2dda6a5dd756d5b16a09756a2f4d3a0aff606b55b7ebe0e480011228a92a9bfd6e8f4103b48729fba0777b5cedfeffcff4b537296b03339a9abfd4a5d939dafb2fd00000000000000000000000000000a10181d2229";

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
    signature: mldsaSign(GENESIS_HASH, devKey.privateKey),
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
