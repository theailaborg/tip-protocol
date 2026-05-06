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
    vp_id: "tip://vp/US-cc733607fa03646c",
    name: "The AI Lab Intelligence Unobscured, Inc.",
    short_name: "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction: "US",
    url: "https://theailab.org",
    email: "trust@theailab.org",
    registered_at: GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key: "b3dd073cbce8d89cc746a0c747c205bb92b9ed459913b7e085476611d8db3d4635d4f5de6cebe0d72bd3416dd4108feae90f839e3dbd20a21a7d4f3f957cc991880679be868180af0b261739a06fcc38b87921c766fac20db71e5b78c47f85e1769b254d1562c702b99b2e38fcca20339ac117f5f44a51658d8d9682ebe3d220e3ff5be9e20ae405810e145adca31b8e9198154d7271766adbc41bd95656f1bafc8f933d014156b2af75936cf7e54cc857b63514db264f58a338f3e67c0324f67d19a599f48f25586cdd8f819c00e965dbe70a9eb91c04d928e5bdc25e80763607663dee9ff8ddc0fdf705a3d405807605ac7dca2af3ed9690238a0e800da1316702ceabe426eac3f62a3f556547493947dfe58467f65272d4b0fb034abe8b2034e4ad93d3d59a305b65e0ebefc553132598235458292b010fb0ded81d1c3f7636bc690ae23eb86c8bfae5a864bc4ef3f9892901a9c5ec9b9b05d35fe44d06cb229db3f4939fe936ab4ebcc297fa2e9dcf1f396b5e1f8c81b85e27859977a29f823508073295fe52a7db035873633ab2cbd01f6916593d21085a5d63c7bd84ed15d6912b3a8344bee88feed227ad9886f557a3fe5b3b82817f960c660a33c27a0dc27d8e70fb564079e6d705631c2bce2f67d29caae74d775cd8df69eca9f8f2cf297ba6c9232bef7e3b59b4975cfa0066cd752cb15d4555f3e99968dc421521b9a301ed147e1284e070224c6e07dffd59ba82ff7092eece083aa5fc9322d38b6d25a7bb53ac53a475ded8533a64dd38f3b30d4b2aa25afad6e0f3af79da27ce820b99c0ef299d9cc792230bc641989f454bc759f6ad45bdca69fdb6346f94cbec5573fd5705929cb435e03b1245c3100ea789b77ff76f123ded632a7fda9ce3150bb6757713f5379637961f75ee78946c4dea2f4ba154ffd23c206a0eed551d517423ad261f1cf5ade4dc7abcfe9e13af9f783e7dbd163c8f5d5a3a62140d81bbcf48a96b2263f6fe507ac784852d7999817029d794509facc07aa4d0775aa033fa7fe0d0d7805aecfc501d44e744929a840adb33e9a41aa203cfd8f46b6e14778334170b8f3c2fd36407b17a981c794b25a739b28826c7a04d7274525e6cfcbd181c48a5b34c37c4f5706dc8eb12eb3101ccf13b0cbd88bd6dc8b4eb7be71586dc3677b2edc90b263ce4f1e03a6ed8c9a1d7e3207786c75b47d996610fed4f56ef99398a4ecfe59adbc2cd6f8edc967d8ab73217fc5ff86553624d8953fb843d5deff88dbc962b2cbcd481cfed4c5d60d2369319a57bd2d6abc50b4f1e4b27c6f19962f7a844395b3af2e4139521544f660518e7b479005e38320f1b3e27e2237cad415d91837f7a155335ce3f225cc6cfe806b5b0533239c0f940a0c5eace869d85eb0d65625e5bf817a46cea86b04111d8454d19e198e7387acfb50034ca0471e1046973a7d70446838ea8fb672797f11066b5701fabd85a1d1bb938d3a593a93972114b425bc4bac8443a09c360dd8d514c2719d29b971a6fc1a5b98e8fc8455ff980d40c7b7f3616202bc42133e7b46b4d2f001403309720ca52d8787dc064e49fbdf3cbd7e9f1b932247377923fd89730906cfe0fea67826ca1500f5c87c7868c6be63f42ebde8d2df2089424dd43ba0330e4097f57ccd8045cfba697accd1cc67292f4240514540ff3d0db0792f8678e93d664f7c33d9e11a401424c6e4ebd2619b6b1c4ce759b02d380a65742e34db554cc02168877324f0a1370b85eba6cb38b168413d409da067c078e280944a75d10f5728b4c039453567a07db404568132200489c770689d699d94e54517a4e256179f1c5dffd02ca755d21497c659b0eba56f0a3aadc4188bda027183ef7fcbc6e8bf344875ee81498dbae6b629fed74198f0248fee02cb01af697862e2b2d4fb1d39e798676a869e510ee03b36ab789fe5e54dabf4e12d4d5231a0ed09ae3291ace2b5accc4d4900d374417551be07083202505dc87b9aa9c36a6156d195c52fcc4ace3c74fcf145281a1a3d6f850000dbdb9c575ab69e50fcc78ec4172af0807c510269e33bb25755601a166969a1199699770c8a170c7b40efe38c95e03b8326c32e3cc141f863dc4464b6736db857ea3ae930d159eb7c94ffc9c9bc4c0674fd10a6892101e51199f646180b792da7a8e6ff1902fabffd6b99cc4c553a0783ef85b07863f0772233bbe51c708d8a3ad0a712c728ccd1719e1deb90f87cea13f961b55491b65461572d504cee0132e775e4d9c2e3afcb6eec016eec96f29fa37cecdd13225d5921fc8d42a55b23529267127627f0fa08245a33c723bc2fa4662aeb1eb2c566355e804f28a8782a0306240853df0440229b2b593cfbc3567b59747b14ada291fbfaa7d63c477a72401e04b558c1c448eb0be24542a243300d054978130b2aebc16f8f6edadc89af97e7f56da9c455e93ea4ec6f2b60226a3d114e6f38e1e1ce803b18151c68a1076cb14828c57161e5ce2198e485a7fd2459c58631ed009778bf8fc41430bbaff820f6b70ab28630141aa2cbb535cd7969742f0ab88e1745649cdb6492f25f6b76930ff0c414aa694843bf6809f82a433912777fdbf3ec2cd1271e2e75eadf4cc13675a2ff9535dd70d45c1371744e53b135572338802c489d8ccf3bb0f8b19be8e10c1bdf4064ee65ab0896d2c6717b45d0427db034f36b1ebad50351898053f10a4a0798df09dabdf62ba19cec147e3f7b3caaacb0c674a1384b5eba8e7",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  // Founding node — registered by seed script, bootstrapped by initDAG.
  // { node_id, name, public_key, council_signature }
  founding_node: {"node_id":"tip://node/c8aefd90b6a81770","name":"The AI Lab TIP Node","public_key":"23018ff95bdc4b7e3f44d964ae94c37bc8599cd984cdc4975dd48c07b2dfb8fac45b8a9eb3bb07a27100aca2a5b5acb758dbbea8c1951b3ad37fd8516778c21cb09b6f437d0a4e770dece5aac5148dfce06d2b53eaa5594c968b0b1dbbb0e5e35a89122385c18fa8fed82517280e69a56c307dde56a2a3a63f87221e77b05f08f51aeec7ff48ccefaa8c559556c41a4e11782e328969f97cbcb1e2264a812006fb70a43b5c2c2b6e6496e7a7e338f7af706e4587dc92b19a4b011e4212152b4489b634c6f1bb46beec14c51c1660b341ffa2626873cc2811094ca5d2f2a84acfbe0e7f2acd70b8283c5304ff74b4a47db769f0a45903c00a338914243eaed2a67bf3862ec7d369e53b0e5c8d77065e6f17d8c3901084623b7cb6366a53484640f215a43ddee8a812cfbcb80324e7b254a35c6aa2f3feb886b39c6b746169b6665526cfac47d3feb036826a30e2c4b4b0eaa5c3e3fc5244b56715d120732c65c3ddd4b316ff618e5525fef07cd3558bb16c96c043d97571049bcb16ef5d6a3dcabd9ca4c9ecbf5f74af142b7948e06333ec6ba0d26a0ddcc71c87b6497313db8f4a4d8754ecd67e9e234c3b8ea9069a7a9d6ba162530eeaadc08ec80374f85eda864fe2010da006b8ad904e4e5cfe207ccfb6a7beca328251129951350cf0092bbd52fb2c335ec75e0b9ee346aeedf8a68cf41c727141a8b042c0e0f3c8a1ad2a837d7237399568e610a4f6a4364c9e6e855d76d66218844aca69dc0563c9534ae4f134cf376dc7a33d8b15e4a493c7d606d89a6970826d090bcd6c0d4e5094354f044d823f8e163f3f3686cadb68c92f77a48c45a913e6ace6e6e7a97817a933402c0358b60b6dd05f4c44d07fa874e44ed104b0755746248ccb0527913c6b3251b17006235c5c052ef55d24d30b04856f59a4733c5a917e88edbba1b31c2382ca599824581c52fb1d25286bc0665719a0c6367798c3245045e20ba68ec2f959730a375c5376ef57b784fadfdd4e15a923d7b92747dbe04fefe3f6662d3e5e7c02baa5fa1e44b6ef34bb12bec4ec3aa4012850dac02a60cc865101de6572ebda52b6ce32b2a8243c856ad5be1f29d6a1cbfcbcd305c6af3547db6b42773d4ef42ed371be4197b80a65983172d3a69ada9268c72291d6ff76ba47e446ab44356cdcadb2d28cdae31e480b0937ecaca2f4c930b9e282a7a06ee784ee7b2e67fa3c64457fc59e7b409a5ebabc7be73e8e461ba473b705714d2f527d5ba3e97f8c6a92d88f79919e3bc333d353c4d6973bc7b03956c7102d98f83810d72f2160b1b852f7db0b6ce32f729b40a78322d1cb99de1c5d4100137fbe37339e9a8668d95d66ba0ad1dd9e43bb7cedb00b66d5199f21201e2f5a60cc176225427e760869e9c5d44d7fda962e8b8cd0f388748e11a75468c393e65f4df38368f5887d81bbfbf44b04a76a76cc0ff2c527b23fb3e5aa40e02fb0f719f9c291975101f9f2399ee80a57e8940e51c48772b1dd8ac1873f3973ae9f52ba10d414144826628d2daf3da3c8325e4a0003f6abe53fb3aa91dab5e206a7f0bb0b62bab9cca5f550dfeaaed75d4274d02d5711769ec652a0c275ebe269a4b39a51ffa890997d739690c0be6eb5eacf2c3e5975e55cd89d0824c59eb21c07e3043f285c04f81046fbfaf3c9fa4df4ccffb5f9cfa892375d1c2ef9780351707093ca42f28f6e65d26e38e12cd6db35e830003ade0576372c0c8b198be9e0f0e497dd34db355a44c8779c62b1022c893705a5679004ce8c4ee58d9ef1ee755f256c7870decd50b8444638b563c8ed79ce2f9d65a65a5da0ea1c44db84a5f1db179498601afd382ecf6e5a132d36f5e990045d0f151ab881d1c86ef059ddc5ab67a49defba6e301e98519b08342cb9d0ae5abdf5bbb23e5ebb9569545bbfcd2b5011f3fafa83d17fbd18d216643ebfbb56011a1f99c59ad9d0b98b9906d65ef3eef3fc06b53e05e6841775c8a0c41f2665271564c4d25b8233c6609c72ebb91bd6237189dc9c9b588e899175ea075ef3c761c01a4cb2bf55763d0311c179d45a93090a45db3c05b2fe735843192a8f1fd8502c5eb62b35402839ee38b082cb7f0f533777256deca9fec6b66b934c8f2686390058bc2e68152e546acb7cf624370c8a798a33174729dce3678dc81eb2de8bddd10ab88d47ac64c20aa5fed96853faa1b27a7f35b82a6f4220f7860d520aa52020adf99530f6772341fb08bbadf41552965a185efd447e35aa964484b0b0cb80f8bb02998cd5c26b462b3b108f1ffd5a431b343f35f3cbc3b5900e3067c92fa1f89b77affbab678f5034e2aa05076c77e35c65bb1946d02156dc33822786caafa5188b0fb789e98863a31ea40471ec9be4d1ca0a48b496445e01cf1041e302572ac4ae1b920881676a1b36554320ed8163dc92b6963aa4de68192316d8f0f552ded371128d372c4e5be16bdc7960a57dc1e1f23e48a66b5db439f44d8e7083b7f8df911c3be572279de748957bf55174fbd2ba812f0393834b6e8fb1a2943d54b19b034adab3ebfbfd5f829231bdf8227aea48e2114ff73f0a0bf22f050773d1ee5802cd4c251225d7c97ab88a7de6f5e13db74bba87e4b36c1780cf4b733b15f4217abd2367044354e7c2167f44164b8e69f5a16685ad252cc4b93d4efc5e83129a7a4516b4516feb9df61f9402ebf2e820f970a858b18110f2524ce10798e8846b8704a0bc54d1ac43a5426b47d1a11393b2e7a5ee7f9168a6","council_signature":"d3342f989ba45fbab68847dd5797ba3a3a166ca886d471606c848bb7855434be2c3e025e6b1e863fe51534fbc20c0327d02ce4a85cba6e44f8cafbd1b3fb9475de76a85a7434c5747036884c1c7b6dde7495ce0faa9e87a7635cf4530e610472d56f726a854e98e0f418919bfec19bb501329d2f469c6401d2eecd6e54adb8700f1143a4dada3e1f5bc45f2dc46f418f8d6c56483cff2d7cac6d705cf40800a06ef83f34b0784d72c982f40ec8478b41a61539f944531c771f0f859afdb3b541b7c25e771bab399a54312fbfce786acbb68d9848c90e02c9827601aa37c18944b5e0b89ae3492590cd7fda95cdad6b0a2f71be13f3717ebb48a6356b5a96a4012b57c158503f8e6db1a890048cc00ee08272bc08fd6928aa256c40a60b2ff2ae2d24c29a51cbae3bec544d82ea7f251aeb89272c56b1d70541da443c4dd2533324687b5a691bc12d9240b034301373bda707abc4b037187e04839c9f0b9d665bb488b592231699c19e8ef529627f2320aaa006386f0c4218a3ece4994bc75328a713dce93c9e748845648c5f5cb09255fdecd57ae6ec597cd1b7db2e321d2332dffc2bf111a07824b8a092f089e09db728a994f5effa4e90650d07eca5c1e97f352d2e807c0fefda2d841fb59a81e6f25267b1f7145291aff17120a49709e0fbf955c704216251130f5f88c1ddf89394456733e3803daad45aab3adc4efb5681c48ea2858a850068972df70af6dcd64bce192e1ba6838d9602455d30d1f7b13af4e74657f9f817c4e64d59d977c773d8acb568673ae1343548a212a91589382822a2d1eb4e5554fcb5045c2b30d3a27a4f52b81ab29ec48f134247a9591af4a5872d94797e6cb11c0e8d19658ce3e540a6ed8875059bfaa4b1c3ba12d9d57f79a06582e6187dc49735a935ba92b35f90488a84d3d8e404476d052f6e4e7154e8a7d6c00f4efad7921fd28fc7ef61cf4ac20423989aab4315804e08ef11b17d30101c72fd60e61ad4d7a77fc561492cd5d3b6d547e76a1759f60c098998228e5fcc42294b88f7332fea374dd54c5f9a2864e3e7cc9b4f1b78d0ef2ab1bbf3b1453e2f89564c72faa0a32ee167a8adf033fc5beeddd7503d94b4790df2709551be1b433dcc375c2a4beb6d77b30dece2ee2b330aa3ba20afd8f971b81e881d74dbd6e97ad2ebbb2d32ca99e9ec21a0bd7d32a2cf972c4670e54a81ee287d0a3f1205d45769afd1955516d44fe231e519378aced874fe0154a2526532770dfe54a843576747e1b2512e297265b66b8213d183676ccd978a8b0f05985e16e13e734202ac74df3b9f3eb9fb2616a441d43952beeee8820530dd3cae89b28d7942d7f3faaf95b8b9d22b57515cb022939e79c9a1a8122481bd70350a4a5c5938513e4a7ee1a0dca8f320435e07f3f46863480be934c12f8bc23cee9b2801d3d0eb024411a7b36a6c4927a8c9d9d38ca67a2fbd5986089790d92ccf6180923bfa63ac433c78dfbb12b49b2b88fde190b0f47a4c3f56dcf0b4c71dee2224be63912c90b5be7ca48834362503595d19a243127721c0082657c1875d096749d9495649dbc7320109d940aef35c69589ca26080f87604119fd2134bc122586c4ef9946b56301c03599c593b6964fcb22ed77969bffe9a866df1a57ea44dc22aba476b6229a0fec8de4d0b139a45b09e019396f2025f078fbc6d02af36708e91372baa646827cf030382406f37fd3f5563f9be01da52d9b981fb2e6079be84b2371407a61b3847baf9e99ed4b8c54f0000a386f31c6b6de18b9c95c340b96ac0aec31fa5543d3525c5d8e0a5145d5293517ddc0f356c290229760352b48c175e451842fa4f5bf9a91b2ac744e59c082b4b818b2ec62d949a9bb8401a55ed95a332fed42142131fe38ed742337ff0f2b959b4d8a6e2ff0bfb07885aebd413ffc5312ba232bc0ca0f9fcbee55464d47175c8055430dbd690e171e024d0d020817a05faf12f4a3222fbfbb1b2e2ec7be08749db3e3785af81b2899af5d8e77af5ff68f5c3436d05b8964db5d54037ec49e3eb5a304d006cc38a74c6103abbd9765c988c0691cd5cd4e25efa5ee0e0d2ba34cc8a4e227ef9eed2fd5859af683f63d15f3eac0c87b28f06db073ae56d7980c7a16908d34fd1500b61f6bc477a7d422422c6da1e05d2661ecf9d87862e56609428bd6502d4857ef950c2a88daffbc9ebb8a80bf85f6ef1e8e1c96754da37822f6792abd83355b10684e0cbe1c908bcc3565b302b632986cafd2cffbc9891cbd29ad03b3372cbcf63897aa9624a1dc1dc87fc3d1ba2bafe902e8935dd5f3509a17e8b3328e1a578cf2c0ab05cc6c889a13bc458db545d88348e2c52e7a01301274c2fbea4787b68b214e38f0fae7cc7ccf1f8e586e86fed640f93927f42ef0013fb331732be1eac92c0dd475708df9e1c3e660052b6d7dd9e7124a4d59ae65be7999326358f73488f24ac1d143c0e9bdaa35593eb9361660753f2b2e03553d0cade183d6088e48f541a43af1e3fc3e360e37e39c47ea335f46cdfec9cd6b083d011d7d2ebea56f39c7a98c58ed85620a0841371b7cb07b9fa6e755a0d5be16634dc60ea42bef89c9635aa7a7d27f47bb0ad2f4a6ddf7d8f77e56ce937a18de615c5638388f679da88c38ecd0f2cc176078f20a32da03e73df6ab8d3820c79fbd7d4e3bd34bdb55b7b1213b0f55b65d5d1ab53c9884f95a42b4ad514aaa0c42ed38dae2fc0b0cededa5f8a99b4878fb06317f7e6c14e1e3f2c88d136da115720a18a552e2d956f0c5f9146b62c07c4bd3860c64cc9925d4def0c2fa79e902ebded155d8211ea3975a6668a8d63bae78fd8a8317d6f03544c178db00329e8903ce64b0ee459b0d718f1e8be69314ac9784f2d3b490cdf873b3c928dc91617ad4d0cc6d3a98e14286b0d985c78c38faf7bc18f2017a8c472f6a95ef27711ca51fa99276d01765c0af0eeb39e2f5b80b44a311b8ec937aca07041a3de1da094ad754e3681e6d9a8b1bb1dd3d4fd487a3a84264cca8ee9edbd0f8049b4e833acadd767ad6f98366792936a290948e505bc5aca29c40831ce17306017349150cd9d4a4402a76a887b899cfc27a2d7ad6c0878468c5d4c5b8483878b1ae7114e2fde1dfe605ac95a9079981326f4197f30e4f6928e0c60a09d4335fc703b79390d2f541452f8a35288604fac5ec2a31fd1dbf875f912dbbd75b12e312b93b73603d4bc86e1d8d7acaba70ec55d5b5c754bbd7886eec46a06fd8195c41b877bbd487cbfcf6d0fe7e057dbf37a440ebbdbde36843dac00db195163a14e0d432f647c84a525e1eeea78c38a8204881691ebe49467e0a361818d1b8c46905707dce475e97f881a9c9029d588815774669297b2ff1d8bdbb1c9ddd4e287114fef5a1c28be205bdabf0fce9f1685087394ddf0de4aaa78cc05153d0b97216e232339a92605880efde5bf07a72a3ee43f5d2f7b4ba9c2feb57f366864f5936cb3f71dcff74dcf78de269e09b6cda7dca3dcf80eb14b3226bb507642e0727b2ce3aa6b3879b6b6966967115b9a3eddcbf10da4255daf45fda852a0233e45ee7360ac86b64551f5ecb9d7f51b35506dce889bcd48a7913fb6af5265a6f68da39a5d50fee255c314d132ffaf86e64e6dccf224d8c139076d2e041856b44eb8d0bcea957c1d4486b201a2f05b46f566710dbc752553de74b304fa62086f56ca9bb1c0d33ec245a3ed6de42a0521619566d8a78afa8b7791c3a936ba8f96016bce8cbb5d4c65fb3f2dd0f78b0c214ef2e5804e150fe3eb489253c7bf6f5ad41b5224ef279506768ccea044d7187ef750be8d340607c07c6bd84a9b4dac70e5f8a7d411763162d584cdfce308690650a9186bd03074843f1ba21a5cb6b08b4f54319a03cce6e062c29214f1199947c89736f87691e3257d9d3da8d598036a80303cc32f9889af2a99d5abe3f27c32adbc24c75028c920c116578c935405b1610b66da334a7df6f7ffcf58f7e9e728acf546654e873ecd4e1b76696320768c9a0d83172b65c903e4f781c99ef246c3def56d3a9b745ed795e8c7379bc2ef526b65ce861b29a5778c3c9c87a46f3e8d9cf72a0086059e702af0e2b11268edc5746029ca1a4874190d5be64826852864d51b4cb09a72e6f47e8090f8f64d6ef782ceaa3e06171a83b49a984fc24d56021ab55ad471ecc38eed761d2f42a6f1c6d44be12c51281940e05d3ce8c992b537d1eefaab9bebecd76e380c5012c54c996cc3a47fb6a1b7cc3ca5efb5f490f78ec8a4d4bacc7c52ec1c63daadbe81fa485735dfa0212f5dc30fa50ee6ca844d69a96f724a1f5d77ca6a426570fccd3d910b953f4bee6d104c91aebda890eb3bebc813e509fb738176c2109d7d990f2d725d5f9902211c83229a0f27b525e70407b557f0fb8d1c565aa07aa3a660f342edda9b12e8537ab5c830b177b537fff599e201e2932223f5b3ee5b3cdd8983a51c0b3026bcfe0f3889364a21991afe268f4b590015a3576446dfda8e6309c954a6211d51bf232512de3601c5437676d39090b042192b2568d9b01b278d67f0f2eb3f0591ca77c1efee5c2098e62470c6455f3c0c63a0de396669a1a9043a3d737b080c2f333d9b31333f4058c6f2fda4fd0000000000000000000000000000000000000000000000000004090e141c1e","approving_vp_id":"tip://vp/US-cc733607fa03646c"}, // embedded by seed script

  // Genesis Ring — founding verified members
  // TIP-IDs, public keys, and VP signatures are embedded by the seed script.
  // initDAG uses this data to reconstruct identical identity txs on every node.
  genesis_ring: ["tip://id/US-4c0b7d1e8851a215","tip://id/US-5fb1990b4a3d859b","tip://id/US-b53bd091f66521db"],
  genesis_ring_keys: [{"tip_id":"tip://id/US-4c0b7d1e8851a215","region":"US","public_key":"148e11bdd8088b1c1eb791193d99968782d135e0d66f3a9f026a2d38bbef83e31bc3471457b01ce3e6e2c617d501458142858179da7e41297ab9fecedbda9f8ff488c9f42c99aacd2bcf25c2438ea0c8a96e74312c5adbccb7644878b94750c9e4b90d68eb9cabebc627a630b745418a30499260fb28f6ab88bc692d2273ba6917ac2ee3f1b4a083fea7ed69eb9364696c0828dec29d7b1a9cb0a44cf653a85948b87667fad849dc2b8e923bbf157874179834d37cd8d4d4fa5ada06abbd35cbb2bdeb79ef63621f1002b8dc40fe18da082f24d1894071b51671ccbd2927952facd011020b0b38329112c8780602c5b27bfab0da50d0ab7ddb1aade0ce3eca2a4d68fe473fb612094776d9ee3d24d36a23641851c7994d36e09421e446fbd0719524680be54fb31774dab492c03fcac8950b3d662f3bd4b90b2c49b76a01f1d9afb74811e378c0f95959fd73e94aff5ccfaada3dec7642ed0242ebd41a37ac0952985d3c3f45bf784ed961a5fe4a556a9f454d5c507656b6f003bf9ad04114401bf789668bf3da53c1370db2baf091f4a1f7268b18c927e1ae51c0fe8a496232340abb509a9b22651c22e78d673883f2c7d694dc74f792744b21743c0ec006321e0cc7509b7f2ee131628a339305a8d8ad4a2e80838ece15b0dc4b448b53a099a63ed72d60bdf50ad1f33cad097e99725cf0bb190f3f81f5d1178a8fd8280a081537cd98da4b05ee51364841c24799c9a44f223e01495a69ce4616c797a7b4106bffb5bf71269a3262732ec63b886ad0356324d30593f4a2d43e18ffb91e5835dbab4acce8dae49d09298f4d5eeff39b390437fc6d48c299033ad3f30f61da4e2fe1ee93fc0372f0bb3cb66f9fe07abdfc842413a581cd3977dfe8b905e7b09b40fb603d6d68f5d2ad5a85b1110b42a8e5c5ab3c34c0fc5c42cbba36b22c65f71be3112501937af978073b98b981af6773fe1d0dd0b940c5a7e45e2076a0de3cae9f703f10e7c383079fe5d10d331b846f2a7318c111cc00334d77213296294d4d21ab57b24560a9db246c7abdc17e029b5f7639b8db31dac18a6a32276a95197063072b3e39495cfb37f5e02659506bbea3a427c7c5a4a6c5f631075e6b5706617c09c883465e3c38c95a07295eea0e2d9e1a3e5059dad6a32a2e4125718a0fde19edc209bb40a7341845134b4ee841e94a2b0839229e64385f786b9342433025404a969a4fcfb159f03220ad75289ac8517119b0102dc25f88af4a82d3d76a5299a86e5311d6e1d10417291aa49f7958360724fec251db6923b7a98b14c67db563d1ef8e78a8c6b7de54dbdac108e2992bbed6f71c801e20b2ac11531e405235d2eb89398aa1b25124485eaeebb2f0d89ed81fdaa805bb8545802e6b6dcebb9015b898d5017705451f49af0052f07df1f08c5011570e5f43a2d7ea6f631e31043897787599be70f21109fddfba960a204891a06a7acd97c08466e68312e6538595a30fb7f08504f4f37e13c570c2f11c53aaf5fc03de2568f52135fe7d01fac036887fe35ba74136a76a40dd7398adc2f1965efd7c1f6876aa3d26b0355d136278c76372bb5ff31d46d70dfc453bd23a0a0eb522c992dc96ebbc4cb081002d6400d34379f67c2325962a056c7103459e3270e84249c868047ea22beff1b30aca1f0122a993901b84eac430552f659ab57b9f790d2c99dae74cf0cb5c62c08dfe5aa8fc7613a4e99f0d73f3919e6ee69c3ab11bd80e4099a41347bd7360e6ecedc8c9b2fba09ca1845a23a6e67d15c18999ff8a2f5461b8cca8942473c10918a4ff72176b73958a2cc8d0cd3c7a9d09fba82c8122bb473e04cf87f21689415b0476b434ee08072b4fb0c585f642cd5fd3e4e54f2a9c1d54fc0ac4ec9db3893fd9d16438f12c19cbc5d0a97b054eb8fe78bac60276dc7353784269d126baf14627aa8bcac49a16e53777b8b3e1c1a67939258349c4e8c1c344710a68410e50031c9e53ce8ce6705fe7605a8243fa53eb4490540f72cdde7c63b64a586cf6ba131cff09e3186584900af5d2308cf79a3403e7250eb4c04519a7237cc034e976d2a436b626437630ab831f0ae2c6444a5c8ac7085ffa64cf724b7cf21a94a1c5dfa27d09de98f770ce0c643888e744dbcd7524df45e0de37a4f9fd11a9ca6825dd9840aa4d75f032d5889eabd300f14bce6675c05e3c829ef9db311d1bf02171ca7365e8d443ab1eef780b32688fc643ecf4fa361d7fdc16a59c4959793e4b601d30ce411a9af9b69b5cec50341334b489238c950cc9eafd19f4dff16f2bd8a72e6800d9c166b57e70accd32eb68e7b4f0416202ef58721040178736af4234761e6ee0712313d3ea7a642563131962ab896a1004ff0c12010015718d9a364f8d46a1a4d4f85f74f131860baed416ca049986428332fd324cafc87ae354618525acbd57c41334f0c5e26d85dde0d9a88580e61d7a627982c34baee5a4304cab536cb999713763c7d249457584009eb10c1f4726f07ec216f41258f248255918c9dee2109a54d51a9796c1b81d149edf8be976e1c707459dd1b22e4256c8102c9fbfcc67ac2a4f285d57d830cd379a7f0f94de347df2ab4242755027e66635f8ce411ece92d0722d1000af0076ab4ff44c4e9e76c13ff3c5df1a0f969612ccc484b991d9052acd55929d3b1e177f0731b933b06beca0acccd82797e46485855250d42a173c82f207ad8275e6c46db44ab2d843646a4274bbf8a8cc3552a1349f78eb","dedup_hash":"23702933538943712392","vp_signature":"a522606f60ded4e2100176af97a9f9cd962c6458e06aaa761c4467d74ca35bdb155fee6f54fa589322c420ec051fab5eb4590bd9ae28a25d8530884059c9e416fc81a10c1871478485ea2b632191ad373f3f4dc425f441b0ebb61086b5bf9da063b8abfaf6397d44792da7540b9dec86c07a65ad613fc62a910ea82134994f990756b8b10c2efd45f1d2119f9ac8720a2a97c3f2728f70e7019a76f3fd495b487aa94296cbc39235b56a2ec19d5dbbe0a6c3db4924bef188def667532564d2d2acdc2a903fff0146b62cb2e358ae644443b5b481207c8e7dd22d490570fb61c03bcb933c66708fe722ce5899fc6b6e076bb15683b3913377f54998b05c98561a010a7f1ec7cca1d6ab6cf8dd055db8fa789afbd756f29bb59e50b9a9372253c83ca08fb59d177d1fa6684a0e90845e6d84204c9e2513331084785474e13f4c499eda2df5070c109436d7d7eccf28d1304daebe19a2cf1974cf9b5c870c1b58435050f67f4dd0ed299396268982b049e560e4ddb13051e4465ced046eba7194a4e6349c951b4bc9d26cb5952a01a5c4b2fc34e0ad6b42290c579c64f6ada81de0d5467fa5bcc8f6ebabf02d9140578008e8cab9be61865a2ac29ef1925519af808e414b0962cfc8e7ddb4418b67769fa80f264736700a26f97b3b3e09e442300192cd5abc79c432b7b89802d20ffe7c617c5adc198c681f9659367d21b30519fe4d63613f54df52a6610fbc53e0b8425d0e9b3c35dbe2d900b85df62b27871d120affd161be288fa3569ea8fa464db41e3c3c05352a0c744371d5bb68ed3597c44dbd64c863f1ea93f8f1459a5c2515fffa37818a734145705e59326956c4633e3b3f77e24774137ab8b176ce908b4ce9c415b8971b7c90b490785cb09a6e67f611f43c572bed76f8da8a925c20d7d046365121ddabdd4fef27ccdc40147c6818d177d741ae4bfa3ff1e37b11aae91eee7c94e3a332ed00e198d1168df0f5637202fb8d622e4d209c3b9baade796b42fd6b637a4591ef071ffa8ad5948f2dcceb11b8d5fc9affe7815dc82c651043fb35da21c617fe4360c4937bbd84403cd972793d6061343d76cc9dbed1b2106b5850bc9e8031e7e554ef4fed051290ebe7e5496eb0536e5c161f3103ae64e097049ca3b061075c2790d6794f480620548b00c8fef2df38e5dd1f572c5fae8a9b154434c65b0b82bd7b1c302686b410810e1402beb6be092aab95200e199aa7c19c5c0b83c2e3f807cdd352be001680b79a4ae2f763842b6530bb235fac945c77b76bb8194fad0c8cdc0a24434d7c393e87fb3600df06a90835fc4803441c63ea290135bdf25eccf01b6d08dfbde686da1e14edecef3578e26772cf126137203850e8d5d9cb76bffd9a4f25027f3c3eee7fce7f6cc2f150d8309c2427c176a2e8a1007d89e1e5a398a90efe359342e9d4a7ce0cc588dc16e23b6239ac49c4f220b3baae4b8c0ea45bf306a55b606f9bbb938a9799466c78c5f70de19b96520cf7494e2bfd77b77ac39e31d69b3f96039075d9a8beec842c7a33e19543ba227c0aecf40f96c004cec5ca9287ece939045e046e7f73d8311a5f11ae4a3ae64ceae4b3a7b5d4941f390bc49449fcb5209024c27fd684eac1b4641c8b9ad4423148e66dc5296b421ca036c7923c9fec884facc65342b6d3234c92bf72f52bde92eaf4757a6b279bee629cb5d8172f4bec0f43e671dc1a869b35292aba90544b070fb914fb9a0ac9f4de59dd8aa8bd41512d701c4857f791a457498c97c42501b30e99c79897db03f9154450de103254f3b015045af31f0efc5924c8201153a039d93cf331824fac81acccc44ef3ff56bd7761d4bc167aba9c379e250850ac76ba222eda2c895aad117f9d916c490452aeea1da9e9e41486253673cf82c09dc01dd584b59a5ff518cbe44cb474a6d7ee7ebbe3509f51d28c95a81cb57094d095595c9e7a0b610f51e17c585fc906e142d817f915a7ee81d6f2864c2d338717f4cb074507383993f309a84765ad51c2a4224dd96b662e594f1281ad588f3a81cbbc1b604594ed06d9c79834ee77a40cbca3956a8027c8ecc4a0876bec2e7d4953d5d248fae288ef23d8948f9702b8701bd1d1e97088d79e3f7e619742f8749ca43768a214959053a945b524b39f8bf33cdea460a62f454ff34db3c3f7f8116e6d2302f160990f68dbefb5ede5eef40733aa18992916d6dfe4a012adfd4aa9839f9aa8491b95dfcc0716d80679c2913c26f9ed84b4593daa371c405cb14db5cd487a6d094c2e298be6b1a1f40cfb54fdcb81e9662782e09ce0aca456c200f651086e36bb4d9562623ec8c940860555a18788c05711849b9d8c884b4ddce0d7a08db44a79cb798159a4c005da2dbc1f3e59811fed27d3774b4d2c22ef41c4b569bb0ed8a86c22e986a1e372f5bbfedc64b21fafafba45ae4e24bc9f5ceb110707b8952525fc8920a79da6dc1804a53fa1825deb8dfb5f2d2cadf45c25fca8cb72d47d47fd9aaf007a3b435bc196d44695915ebdd4442bb1d1c77b5974f596bd1ac0090a57cd1bcd7d9de3bfdcb7ec3bca5beed020f29d44c269f4ff9a8ef1628a8d98cdc1ac17a8cf1bb63f1ee974516feb46f0edb6c181e39ba6946e7d28a28d1b71c9c9b1b3449e511f4ad6c163fc706c02fcc4e144e60075bc787873f610f8cb31a94925809dd3dafb45ab53868b45651409353879571f59709fd86c95d075629d320bd748891eb5230f293fb8d1815fb9011c0e4e91055607c614d4595308fbb3d9db6d32d420237497f4f00fbc5fec63d2d83730edc36df9346ebdc8e4369ec44f07bdad2ef14a5fbc843d306f8de61f41d97c6f0c93e8b395ff71ebda5364282534d9d59b452df30a9ca71daae9055de9bec707bdb907f20c39ae0c307e1ba5edf3753cfbf47600ae8ef32c79cf44fd31571fa92b765834a176c7891249513065f141fec556d8da9e7890982e6ae9e6868c46383551b8abe5857e46b96815449e5c4b0e5a178db2e4ffc51c842122ee2a994908d011ea3a454c156a4dc98b9065cf4a9763603e05b88f29d88fb1f6edcbdd028a0cee2f6830b526edc0373c2bf8243995a2d98beb50814bdea07ab3580f6bfdec7c53bb7dd257fbd7641e5d2451ca1978adaf34c52e1157cf95e86c48e4c30e5afaf16ed519ce9f73fd8207d8c0bbcda939d1d10f1dd6fcf18b7f3162fc3f5bda333d847681167bc62f2706fe858c54b3c07227758c15122897fbcc4f54e3dbd06c1749b071154a4a794ede3498440934788fdf108603d7bc0e36714a720ac562712b2c76bf61e1497eadfec448bbc7d40633d541aea7f4b471917cdbc05c34ca7abd09521db3bed9147881976d9dba45818daef92c8972ee18027e5ec0c8e5f93993481d639a1d78f092b197699c77bd55096859748277fe219e6a20080bfdf546b0cb0228ddf8355d6facedc943321f61de9dd3e94257297baa2465da76a54fa42a34e8efae2060c319a2ffdf6d8b748b830f07e513c53a1a906b4fc3444633eb59c65c34d263abd4b9c3b9dacdf863806b76b71cdc6e1e1897d263a0c9feb4a97be114e64c416877a1e69410b8cfa595b8a7bf22ac88c7bb711f55c6cf336523dfaa47ee3ec46a8f0f4b1d44474f62918f51f8e29d008dfa9962afc4259296c27d194f928b5ac27baef9a234867c05b041b8632c2259b92130eaa8b05883b32088d6ea025968e33d2366a9220e1795754c87cb6725456a9c51cda960b6ae2525ca93c7fe41dd24941ee29727562e4b38040c49ed97bb44979c50616745ec54683b1cc9f5bbc4ebb0ad128acf58aa93e2ffba5457047a05b1156dfae74f7a5cd7afe2bec9da3b65ce6aa06954cad5a044af3f40324b894543849c1181a698fd5cb8beb9dad7de92b340e6d41cdfb60130f12b8f30edc9f6491df275d1207605afba0c338205008f53f563bfe050c7955a73af1d97c3d4eff07192ae9bf3ec3e0e5635694f4386f9c8168379ecbf0708a22663f4dbf375975779309f010f72e27c0946d615b0891670e09e309f645dd1c0ad37fb60e776fca1699ffbb0933cab08da030e47ff4523738b4ae86a4d585d214ef0d931830b1797076ced9112f1af9cbe5bf041cb8d04bd98a508cf1d58e5b290a5760baa08d1583c6a7e78a8b72e4358293848600512f971fb92e033bdfdf080cdc14d1c16575f34db322f404d5ffb74b43c1ffca73c823f72683be56638f2087322a2fa40efa2468c2396dab7b7518dfac6ceff5f89e84a4ed55bae650826791353fa8e3a4b2fdc781a1426804ff82bad0091837c7992d3811655adfc1396bded9e924ff61643f81b863eb311b6beef656d229b358e692873034fb5081370946e3cb273a444fdcecd5842cfe207a97d643df75c3d8d793ab703055909affb3e512ee2a2a7b5d03e7524159f037fac38d9db99dfd362969665a27d90961115eecbc05cc94f8dda8aa63affeaa9c8b38247fe797a395b658fc4ec46a92eb0710b54821577c426276bf5b19b52a5a5249a5b7e4bf0ca678d1cc73875c6dfdc259649f4d8cf16ba2b7040876e08fe3f1b04e9ed07e104454505ee63bab950495d7cabdcf62039626874b5e6e7f8061d62a7b1c6cb022e33687c8cadb0e2f7183e4976e21f2d3b4b5862b2c2caff000000000000000000050e151f242e"},{"tip_id":"tip://id/US-5fb1990b4a3d859b","region":"US","public_key":"88a527395aace3dd7443f2add214671fe5c155c65dc7b2ec090f2692f39eede5bb740c14e029c544494b1402d1391d0a1953aa4cb65de9b8b93cabdfbe813dde7fd72a93ab43f522f6d7073e38ad38134340c7deb5598f39d8eab7b71abc07f344375d34a25c452fde94b90ebcb30f7d1480532b32e813e6d9d3cd83208d1162563fb62a3d6e6ddc9a92d34bfe72affa2ddbb258da84b7c4cd1e46da7e81a11e2b06e59070e48e562b5558965f0172909890a83da039d904108cb723d46cfae8ead9fc88a6770e474b9bff823217d2145c608d291400ac9a63a5b1178b883f294d0072e75eeaf5acebda4244d5546ada502c78bb54d4bd9f82b49f8b388d1c34ac9f1d26ec1dda3dca46eba1f6c254c47b42f2274487342ac830d79a7a7e5310f0062f5ff13701f5681cf1a598e8cabcfc203d43ddb3d29378c61e84ba4af89d30056897e12258c8d1dbd3f745e36d652eebb7e6278e038123a3d71ef8fe8a2c78c86adf337d58c763767a83f99a3a24dc9135e58ecc6d5e7ab82d0e99850b93739a1220db025f865f4ecb2ca58c8accbbc2806c8315c7acca02353afc598cb98dbf43d0fe4b0a101b11b7fca585dfe8b843970f5d38646ff5889038ec8aa63ba799287067292a7f8f76d8d1c047f3fdab519122f64b4a36d58cc36d49814536401df1a8cf283035e4da191ff0bbbb6ba956f3eef36d30d58b3649aeefe97a144db98b2be1e1e410e4cef093d1b8c444c9742fd3de2e44f444bbc852e50687ee401d8d04c0d77c6be1c5fe158da00910f7ab89130e7cb6ccc72680410239a674fca56790ad23617ff903dc03d8e03675476b3d84687f5f28049492033deeb6f6518851ec83e61940d4abdbf72f531424cbf9d7ffcb9aeae1cefddc5307cbc26de1941cb2d45099825311274b3fb28eb8d536c0c78fdce13e2ac02ee461f3f512cebe75c0281fa2027f1be98ec6b47ed60e52c6cfdd48c36e787e881030f998f81346bb2d1943a499d3e5666b0710cc3dd0595af9e93365907ff774c6d373ce9c6dfae56cddc7e3ec16556118a1583c1b9053c2663adecbfa040294e9c966cb4f5a3e2a5062a9d60749c337cfd23bd4c0afed0f89d1ec765609148ee94a90aef3be3f7bc2bacee44d736bea12a67775a80678fe31bf497b98acea59aec679e91468351dd6fc9de625163adfc74a985593fc9343f957c8e5dc7753543846298e9ea884a95f42e3f0217fe99da60b9ea0ceff640e9cae51d2b69733482371f0ce20272b696cd2a5acaeef4d24ba0b756a54adad46b7b105332638731f6adf1601cda72b67d6fcdc056e4bfe0106232bdcc3cd3a45a1af85dcf3599a9b009c622f69a9a2acbc611b468a299d18102e69e29648aa35cecaa4d40c83b64b8defaccc9dab2279d9450cac3c19fc2eda192dfb8a70e2563e5f18d35c74b054914c16ec093f762958292ee8782105dcf5349337a61b3385d4273a2312fd230a1485c197a4eb4acb0e45acc8acfdc152dce6ab7da366342e856118311820c8ddfd4f83a07234c59cda9f2863d8dd1fa108d6500d595431e09cf9647633cb08052e910dbacd8c6b6e89b269896a307aaf6be641360a6cf82907a3e34bf65f2dfc80c567213f4e06e6090691a16d5c879108d1d1704ace389883db4fc448469c5bea4390a5e48a92446a3a7ede54c25c228aff79ccb85b767efb62535f2aa8e9e14d8661b7773a834624aad2dadd199eb6e1c81f0d4e0312ef0d32ed5cfde60522ee1e6b5cd5e71d3ab89ceb177c1c0b83578c575b6f35d6ae3a3b043ca427087b522b6c8546a5849312baddd39b1137ffcee75a73f316258898d855b3e596c55818c1a7328385e88db28df5b621e42b13a51980a054258825a4046a9aa10778c0d4aae38dc24037b29c6f4ff3b762daea5fa6e58595f1137015e37d36ac2da376801107fcee1fd89ae97c49e3ab9b32ecbd605f7a362fea44ba5daefd0992e6336074b8b61e13c8946bbe51710568f5ab259fe330ca07c7f12681fb6b21652f614bd20de13beb34b753fca46da4b7e07ae1deeabf3a78e3461617ec12d42624b60b6f0115de811572836653f4e37a36b6ab9e71a4959bb82af2f2755b5d982d2ca6065958a69d0ac7d1f9ab642627f08d14d27402550795e8d931cc432265c70cc7df1d30ccb68bb013f69e5b0fa33046e43f447214351449bf7b6e75edd4132cd158846034f6e72dc936baab5b1d019cbe97e3d6b866caf022b49cca91d96234be29e62c83e98684bdf337fc5050e90b9f3b9f9d8437369e6f4834414c41dde0bdae146f7f5f2b6cb6d87674ab82005befbc4354fa839661d943c7961183be90377d1a0e96f2d778e78eb38356ecd6f1c7359c7e30ac2e0f1932a61d0f1e06f45a531582c260400bbc7c142b9cf573e726aeeffd52c095bed282b813ec795aef32c5bf99acda7e5fad4b9dd035f92b0fbbe551393e01d5f9f7c5df5980d6bee6b0f3555134b93eab17d123ef5f98ece46a2a3eb4084826723419d8f803060d6c92b947eb019b1e5dccee2d49642f2e9c8f28789e017356bccf5ef7cf46907984f304df1c43a7d06c9591a2c2b42ba3c2cf6ff1e5a7bf430d71f276019725939ba960bb0988c577edbf3890df483782f7ecc0ff3021c01f46cde14bc57c3aa7cf43dcd021fdaf37f28f7999a2e58bb39d746f82aea98a5c43732a867aefa9eba46165e1b393c2edb71fb46b88d8d707971a666d1b1cf39fc15d9bf25f72b78f4649e8b8c023","dedup_hash":"74146165765493969290","vp_signature":"d9fd33eb641f35f131afb00b5dbd4ffdce5ba4a1cbafec7e5079f34741892d68d5108007ef201ed3067ba0db8d2797fa2b6763664454ef0350b1cc286078077171944357b23a697906957520d321e92fc82e0034830621aed67c788161bdf8268b7ab86332d24fc307208bbe9d099841dfce02a8045188a300eb831e13cabfefa420bbd9a38b818442231081a496a77cba4fbadfe65415c1930b7594aa2fe4abf56a1b4142547360ec46bcaa07a9d43a1ea86d5ce1e9597fe3629292e5cf9bae437293e065bf4786a10b241d05b83d6bc20d948bc68e4027ff75a41e6c7176c3d41bd7cb8dc899c1aa77cf3aa86e311b4e790721ae2534712c5a237d0628f0c2a94f9f9828cde304e570dad0c2e4cc72672608cdb8108a97055245f1c84c62b005490b1d7ec12975f0794528c71e946d44c7b43942f1f5fd45fc88af6d1bb930ec36006bacf1b49af4e145feed46d0dd6059d0c2733b38254b6f5d40d7b4a1a3cd8ec384b7555ed1ee2b08d3cdfbba076f68c10af07e05d385026b651cc0319f9eef38405afcfca8486c7b00381f9d7b4b148a175167e00d072de63397485e5840f319b7838a4a3954c312684c38afbddbf18d1e37856e29bf4b7953ad5f718e950532f3d4750c2b40d4c0df8b8e5e8d3fcc1e36bbd7b77fe640ba7593e826cc0f1e1951d7aa53c3a58dc290c3e9bfcc36d0d8abcc48b9fee78d4c2b42c1fa4c42a4275b873821f3a558018134074535f17f94c265f844128ab2b22e294c17073c4a9d492998b981423f7133de048130b18387b6b5c56a4b46fa8717938aae702a7259913382add042ef3f86b21ced59b565f6c562447bd0cf135318e0b637dbee80d85a918443258531943c65c22a8c368ba199065c94c96c0ccbc8f45826369d50e6dde7a1e2aedf397f66b597a5528cafeb4b6f1e74da78c47e204d3ec92a28056397055865c6caae9e6881fe9b981247e3b130bcc82106f265350184a5fb61310eb6d43eed953c34e667ab7b2c5f00d305c0cea35724f76fd22e332c739e3bcfec2e45b527670f64a37b7499c308e7acc4438d6bb0d452857780069c3656442bf770ae7e5c0e640b752918b213b28b5ac05b452496573009bbb4311c6a1c752dc0bc3d05461e7fd81587cab44b366b1728fb520cf29a75f0696d875aff1509235326a55632ce6dff58ccb7924365a8401630de942c29ceeb86bd18a956450a00425c447ada4f2948327c78988993a216e96775c1488f921425f2453dfda3a4e54afbecf3284fae2df88898e64591223e7680b8d6444ee531d9be401fabf8feefce1b42143ecf80842d2ae7875a5a8df94cd42785d1429c1fdceacbd841098563087dc7e136c9fd5b2a72cbbbff610ed55cdc913f64ff338a734dccdc927d3dcf142597abcaac87bf94c5ac772f7756b7c4aab7417c7c54a2b38b463def21e6d6fd8e9f751dcd1857c55c52ed6d8a71dad06a5ecb1850751a14354e07366c59c6f16cb28f40a9743bce7166f3457790f86bc5caa2f72d4586c535a95683df4013fcbf58ff4a4f878748870897da04fbc7faee6f520d15517a5acb6e840c229f16366879950ed030a09130740cb12aea27d27c8f7ce21b1ea3d49ec5a0d0920569d90566c361cda162d170b7fc6049d5eec7848e0a680368571ede1841d314acc1acf2d9a42448ef0fd2ae13c191546d9125550e4d27476035bcc30a99ae9c0a1d4c06555b654c0a683d354713c321b8455c4b0a40cc7d44f13e25350e484850b2c871790b01c92a33f7eed7d76214c7f5f434f5293f88196fa5f23ff1f222c2b50f1cc15b194f10f6776947a16ce8cf2e4e1c287ea072fd4a5df92f90577bbd3f8c07ddc488b495bf64e20161af8c49b2a98923040c29525605bd45aeca0880fe30e677a62016eff19b02bf726a0850acdda17d9e6e5e52611bfd7b8dcd00b936d95bece777de3c4ababced7bc02d91e76c49fbe47c5028b907acbf3be78cc80be78b5aebd53861445579137048eb6b95b10e00c7398df0f8d1f4545afa2170bbedb5a029498b62fb5825523db870887684a3e57572ad7109d59992399969ff3d4f66eae6ba634182b102e2757d4fb0c2bfad125a0531e94af07004e80ce303fd7bb97a5c0147b5c5d9cb8209acaad7e5b5051e237eebc14cfed93185a8cf036dbd7d7fee556dab5f85d1246c3c95517d98bd5c1bbb8030a55626e4af87b3bf231808b4928b22e1ec2a1adaf98f35def486b1c7b8a4aaf3843ee3ef1032ce18af71a01a7a0d8f36c52001a4b6ce0114078c0832de59c710c3d66cda4d5f07b991dbf9c1834ad692a3921b8bf7f7dc9ce5b23960f578f8dc9fd9c319eb869774110281b905ce951ebdab93e2469b88579feb1da4f29d581eca7fb1fb3f00810766093e5b60314ea70641c92a36059832413d2d3eb5d07b05da51f4ceca4fc30cf527411e979df7f5f2d4e052cfdf34bc3610da9367ab4d3a9b8046b229f09fc69682d1c2bfc2319360027bcbcf3734169a41458f0d1eca2812e3f878c01ce625b40f926d81c98c5d2298cf33ae317bff1a3fa9a2e60e8b5d4317d8b28a0029bd0b66ce35111a9986ab08730916fde2e188491d2689016570643853ba6c96cba92aea266a752094dc377f39994b2a59b5a3cd0405cfddea79fde044c263b61b1d2b97b20346896290e4c04194543a1d448cdf26c3443ee250f3cf0b015609cd9e81b1a55fe5c4474c636f9bea0234fb0a20ede975a08adeeaaa8350c4888a7621ced0aa8086e0ee5bfcf450cd9940cac69b0f490d53a8ece4f0db651b5460bfa92e0c7e13d8930e9dd105e006fe3559b86df408b6033bddaaab29315924ab25eee74e17f0cc0b0e419ff8e7478224ed4fa2f0726ebccbf43fbd5027ef1f262763477b6faabcc41593862e902003d5e336628921503393c5d40458dc3127eef47c9ed19321b2460705259cbae92d2fceb9ea944f04fb836e486b9453405f8704e3951bb0351038b87df6dabc77a876dddcf242d7a6fbacb3679a2e168318cda8e0e87071b3917fefd30bafb8e8d5ae648cf7cf0bc6f4fc89f713eaf60936654f6bc2b73a6671e997bd096c283705c40080add496f6a030f3e78699e044344bd7fb2ae087982c06a04ec945504a0b46c92e69bada25d02dd295904f1c5536fef9f79346ac620a873b1efbec4f2a808849d18ed66bbcd39d28c53d1e40c0f45f2fc5f29dda2003ca850ef93d14f4192e3d0b35644b8bc8d80f98f21894bcf36fc0e1ed4e9ce180d437f0cb710cdb60d82fbf9d0b9934c99b749f8bd06a65b821761d42ddc2e8b28d93147cc91ce940d3316f2e93ff2fefcdeb2e86f14ed7cfe66fd4da553aee1d77a0f89987f14f267f5189a7d83238839a291c48f1e5eade5838cf37ba6034c9dc7f9c69e970b6182f3928e3e5af8570d535e4308b36776404fc13685c10b06265ac480658c45f0098ab42443c97b91fa0b019e00b18a8942c044737895d634eab1c8609b5df1645195c7ee1f1a267bef1e2c52e0d09b6b7bf11a83392a2530a12e5d45a24482cda144fefad004929d6941b55b6d3eb5b1c96262f16b49cfd90239983373934d9bbac84393fcd03a4a8cb9fbc3863bb9601e13030a8cfbab6e89117398db129e5f76608accae55887de4de2828c40202c017c9832fb11b9661d9e220ec7362ed3a06ae7681397d0d382eb35ceca120ff3e59f8f5fd5b16d77cdfb9b11b8ce6c5aae1c6c9650b6c276d13ed81cd8156c47742c17ff4cf10875d199cc0c29ec9888221735ca22dbbd6562d61094a3fd5b4691285bbdd04cd52c2583dfb5f51fa62fc270351d3574b2d79a784b956066104db77ddbbee4be5ae81cb39eaf43b296f9666c1569c8e90e845c00a3003b968463877ef8ab9610477fe741b2b3fe770b90a414b006e759f05285c6b6da699ce1077c237649fae03122c9f4c6b7c0f6ca9fd5131d2907836b58eaa71319ff85f1a78cfab546ba0e4c6a8cdcb59862ebe2ab6d291ad9b368acab82ed4bbe2cde87b19c5b7d588a1451a4379b753ec1245cb36ad99095a20b11f925f89ed56ed5e718a0a05903b338bc772d8bf4fb803649a3c5bd0ec1cd81e5c74c5fe13d0387f20ef0f53cef37428fafb3fa0d0363d2043884998940cb5d501e55a303f8b2bbeee6cbba695e1bdad80cbaaaad268483decede839c86a4772d87fb9369bd32305680387be750edbeb702e612264704bff0df9c4e7c412a85f88ed25ba477e5d449366b64afd777767ab0d9c0aad49990e746b3efb9d8006d29c7038c77b9486d98d28c85b3b8402cf3e7378de25b1ee5b7f28290887790df5337c06a69aae03a88cf9c071c81ad54e0a6e8015e24a2136ad3d695fb17ab49631693f00d05e7a910b060ddbaacfd49cafe39c09646c1f83bdfc47e90c8cb5a23cd9a353d0cf0278c7d9a43365d0e0b3da446b10f2a7e58d76e4db3691af1553664836b852ac56d986d047091e2a8aff57c34447c24dc927656fb2966ee609c2f52cc933446033f3f19480656ac61e5968fc9230f68eac1bad8bc148cafd696c9ceb50ac989f9149bdcabb0472b590805d21d059947e0c0a91691d21d181d6483b0b2edf512314f82d9131e253a50d1d4fe0718203044090f4aa1a4e32d8ba1d1f5f60000000000000000000000000000000000080d151a2026"},{"tip_id":"tip://id/US-b53bd091f66521db","region":"US","public_key":"e5d7b5ce98b472a80c6684b32aa687087d930b9a7f57854b689bdb9cb572acd814d16fd10fca40b7f87ed909fefeb7e6b60e5fb48f22927ff16c99d7506ad4801c59173422b05ba812d8945a478d3ec133b639e8c5c549182f26b6cb01c8e4c7a6282d1e8bc9d2a57047d930df7cb97a0a2d8b3ce6ff160f6d4a0a6bc085b6db554f9d2155ade2bce7179e002806d01fc5575e29a85bfa88012bbbd5d5593b535e41aebe5bdd8bda05eec58fb14f02261403cf7f057ec2f0fb7864ab517c134ea0e1cc125badb59911c4fef8c322af6ba5b65cd9dfe5775c5d9130a6a7c6a9df8fc641a4cab6831553beb451b9f9397a8eef2249ed5310a052004555354514a4317e3552436056f39f4138df5966b4d36e0e19cb3b0e3696985cb35ef9a3d6363c9b3ba7a51e23ef744c1157f889ad364a5884a7578f49f4ac3adf700df93e0d3862dad29c674adeacb53e2dc4a66a26a178e248151f17938f153e8fc37e48413c03b8eedd629d9564a601d1bb0663d9b1739421f778b0352c113299655dafcf4d7ce6a3a492307f089b9df9e730b69573522771febc867109510e72257d1f0dae541a51d2ea1981ae56c38e322f47257a8ba5eabc489d22c8db72513f9a42c852f418bb68faa951c2e8569a9c048153b24a18078b04be164e91e9f43f46127ef2379712cf5c0629c417ef109f9e3c42d6156d5543db4db4b3d93f73dce31de4eb8aa8579d8e896b709e3d72784383194ba3fc4f1683cb7127e94dba50dd862a556118322b8e29b1698829f448f553ffcc56c838d9414ba49ec3bb999ce5e543a97d26e6f1479a73d863c333482bf0d3219c8acba0b3b441a245a027c8e2d6024602f5649c5201837d60945c59c1e52f87208939eaffdb34a9a5f544c0458874a106602c495e46961f91e34ad685c3f460ba01bb10f8450557741bf87409359a1d15e60f78d569b82a48d294c943f72d72ada628e6830d420f73c5dabb9ff7661f9197996b8bf65204fbefb4a5714ffc3c2ad036646b2fbbc98054a15ac208a683ead4102062da20c70cde07016963b1578671019e5e128d8b412b984b10a629b18e901884a13d88fc3c95f6bc504ecd6169672d25051e4cdbeff3fb886439b485556fac9cb309fcc23a84d0a42700147867282b0f8d7b80db0ce6b7ed5bd8a051ce942a0b97fc99e09a1d6ed60276f6a5081c85c2bb793edbbc61ab6199a2e9bb8fe9eec7e397e30e670ed4059dead550710eb6c11fedcf52a0c36c2a471e7ae1d4c71f95cdb4f64ebb44ff34de865633bde415334019fe4fae892a26fa1216b2951b81f17e87b8b9c53caaa1fd4e6998440d9207718fbd73a9938a688ea155af1344f72a4788571fd658f7c21571039eb1f177ef62e72792f3de887c71c4338b6cdc96264869e9f610f02083a15c00624701c14ea25caf4e642a4ec1bf3edaca9bf86270fed85415e440b6bd9ad2cbbb5275dd9f3519acf7918fa984e764385381173cc628018d4a6bd721f8730f5efdfd24119ebca73ffcd8fbaee7eea862187491cd5c826199da86f70c1ba4c60f2f9bf3033cdd1588572e83e05674aa430cc79fd5fb4da6ac471eab6162f7ef7acf19dd85287c1ff8d2a1cd83dd868d0127292ecee2f4932184556123b5f41eedccaf5d2efeddbc525a436ad45df1ad36d9ef1d0409039c140fcfd7ae429fb988f5a8156bf1e87f4c2dd0837fd99655894898f898cd8d1299e27c6bc3b757cfbf3f31b66cfc555a387d110926c11609b6c8c812f28031914408059f78130f9d8426680223c2b83ca4a86d85f8d0d3df168bc8465d2a890eebe1c3fd767616edd174c3d9408d1adb425b0ada6f51756a269a7a31335d5cf1a55bd32e3f153032e2cc24542545886e3cd99f6113640e05b274a5a80d5a12998910b16d45c17157f86c8be9c5e1778067c59cb8d953954ad20f6c7b16c53f6fe2930bda303a1ed9ed7ca65170bf98f061b7680953bf127aed058b229448fc14b23bdf7e6deb2f2f0ba6cab6210eb953d28e45327a8b8a33e673d0cab0b86f8c201f66591ccebcbbc5fcf075d052a7a509682ce9d42a77061730e5927e869d4e534192f6fd2bc09d5049e89c03df2e75dd9681d71bd76d62ba22e0156e88af52e2945995d163cb8bffc5c78672638b3c913394646556505839a528fee416dd0abc7d9bda43106d90650a236c05029d62d37361fbeb274e8beecf7fb886f6763ac50cccbb09df832a2bd98f117d538f43ba0e57d05257690013b598d8134139254959e819deb31b5d8050fb6f165915fbe12639f043082a0cc4a5560326899ac47bb99f55bf319bbfa3206d02a31d6c0eb9f6466ab9050daa65fa37a446687ab9ffa8cbacd5305126908e3798913d730ef885c6f23e067fbd3948a60171c69f40b211851123a31c5a07c716f3b07e684a9841a4ef6d533a9781e457aeedfcd1c582e44a7a02a4be22ba5a0b25cbf173d976b914f0863578e5639c857da2638b482fe6076b002c7b1e73acbad6ad0e84ae3885b33aaffb2a067efe1dcef174e1ab1d0c98c0485b3312f9df6195f29f5006b35c399b222ab086d07035655032e0bf4fada1121b2c2414393accd689f1a3cbcbfafa825a02e54e18430f188e9ba6f2b511a1cedffca6df8bedebc5a5cd0e5332125d11ce2f490d17cd3a801eaedb112be8f660eb5889a80b71a4c2b87042a0aec0cea1e721a305730c505e67e81be3de3dcbb19cd50ea6fd6744a2b2e8053b0894b6d158751b84ba","dedup_hash":"70044443154882484498","vp_signature":"ed5fcac7bb2a8df9eea3d1deb30f62c1c6cc96ed5f24b1318cfb6e17e9087f760d5620416333000a75a1e6ec5a2bbbab3f3522c38db49e506c7c027b1ffa20cbf5e63d7fcdf8186a53b7bd415c0f801ddd4bb0e98e8a981d973a748d34ce844c36b1fdd0741e0b7bd1aa91ef8831f16208dabf56b8a191f875d1f052e65840c9b0941a9bab3c15f916c27f4cbbbe0a513146d6030fa2922e4dd41136741ba962b362120fafbaf870408788765bb4a59b0efef8068a002c1e68e900b0b04201766c22304138f33215c7e27e20f753b9c77e7ead155079248e82bd4c016c20275897077254404f457e22b1db8f334b8aa8ec2ff5d31d3aa377d5c5bff269bda5e0c69ff4dc98bc6e3b8047db44a687fee930d064f8019ba15f638a60442ff81303afc6eab997a6934b672dd40380896572cb60ab501f9875870f7d7a731b6aebc2c5c3b3740f2cab57d20fdda1a11044ee94b6994a6b8fb69f0a56984279484cc976e7700e090f2828b0e6d7d54bf17f13cdd4fc5546519ea6e83acafed15caffc1f83c156d2c3f920552c14f5cc30aa314fd1d38f83efbf72e56a4790599745585a0b0e8a5289ccfc702bfa0696fe3f061058fe584ef3328105ae7b20532208c1e08c28bc1155625f49730f753d0a653e87afcdf74c503cefd0e436f908a7bebc31bd09da1627356ba5c202de96f1d87d1f22f8d4beb029d925e2544552ac2fa8a640ed24d67900442b5c5dc01abff1e02464d06dad411a9fd2d86ae10c20710e20df26a519f97cf40cf4b186c998c92aeccc9a43fdc17341859c53ce08c361d25317626ed57c90584be044faafc77d919d2b23be2be8e92fa62dcbad26225f9f4d8f805dd448f813220598886c4f0c38c057292e46669be8fe99e61e8ad8b10d14f352057fe3f6e3fcb14a9c857d72a10fed4cd24896c485c4e107c5f2630f6cc6c3318e583aa7522de8b9cca23f6d565d85ed7ae8da6dd3ff6b8a18b06ce76b966a2d0b727f67583a1ae97b9a464bac0a0080c9b5dbcce43d5d5bcb11696f8a8342da0115af12357e7203f054e62718560491ef0b7596f72171a5444a0016fcb0f15213d22bb57513985855a7c1e35d0629cdbdc432609e90408c7767eeedecb8bcd3b3845bedfdca66236fc5026744c17ffcfdadb7f6383f49acadbd4013ae13ad5703102b57c86350f3e5388bf20b32b8add7d47990beae5ce68258d2dc5d2cb20e5ecf9ae6f0883410abcc1edb71abe047619328afb62ed401cee7f6adcc06c571fc63e8eef95a4e7491d795e0e496dca1e08116eada10b453b13b5444ea6dd3ea4328649b4d4b1a7f5d279ac4ab8bb81ac49794346f9bdc84681f74d9591ff0c61e88da1ac4828ec1f1e6fb36e20294ffcdd23f25edf08cf428f158424cfb57296bdb0c4ef4ef9d0bdf539a78f2e20e9b90ad3871807ffdc09890e89b21e8cd717ed160826831da096ef1bd223b4e81a7f0e60bb6871a8ad4cba8dc93a157fbc497fd5e5a245f92380100c742ab7413073023cacae4b01d364be5dccadd056eba378ab96aebe0ea5d89c1c56a9062b206a2cdeb29c06e0d10651ac5e1263b3eb24d1f824ea02fe6c9c65998bd102e8e8a0340c1eccf8b774b1d0120b43b7cabb1fcfca18bbd193721b8545f194cc687db2d723777b518b14efb59bc2b02e36c10988840052f71a31f985df7be02ac6af199f7fd969b3b55b6027c1ed04b9a25f7685db064be491702b51ed784d3b11b936497bed56a1a239f6dbb032c93467a35f36052e3efb8c8718fa7368cdbe881c3b071e6c2c825a56d24b6e70be77712f138cf0e84ec5789eb4dafbbfa39466ab130ec5fbf51b5bff510b607bbb3267ba904020b9f4f41ab7071fd654ce6efda7a94a718d06e9d444e7b7eb243ee48324d11e4881c596df303718eca7b94dc00dc055f718639120f103d792b93c7bbc5072f3028c20879fc473354fb3673cce4d8d61f6ac66067a56b3ceed9357c2219973036cf9d77ef0ce3f438aab6e1747357a635f27e06ced9c563ea279e95db6f45e43a89d7425e4dbf127688b02a382d25dd6e8cf189c9a9654270e2b11f40299a9ab482e67c884ae2e46f3b5588dde43268ed04034be52d44d28169baf944bb6e178d7e98329ed3815e299aea05990a56e04fa17fa9f9e1ed52bd317d5c751245c08d73dd710fdd521fdefb8f382327d487ca33fa13a1a6c5df79bb40b5aaca3a3bed2b4fce3f69c0000e35883eef171215927787f1d713c4e50df413270aa890c2e6c8878b1ba757166666b446433c83f72b94a034b5cacd51d03752b82e0a9d470ac9d5fdcee2d71bca6d07a7fb6077399318daaa5f87e2b7f90bf8c011548eb527b398e012165d4c28017bc4e6c5c59af6c497864dd4ddcbefc1a4ad52e77f0afd7ee77cfb548afecb37f2765b78088f998b3ecab53ba7c2caf2e6d8f23761a0312c3ac3f8a4f03f423085a3e61624bf4974bcc2c70839714fb26cc54a21dae20bf5f5feef021495f1b893d0623ab0f4790b78908fe88b0f90b79ada6b9fa3eff316351623f557c482330c8357d1a25f524490eda43340775e573a674a071d2e88661707246168125f7ae76dac601c2de4097e18f8b9415cb4ccafdb25871662f9d8e25392b325dece661e83dae3ed3f4b3ebf2724b759bc3ca8f9c21116deb89b0e190caa64d3ccbc988a9f37423f1acb9c7ba32f10f576b0d5d338920661aa289e16ec56cb74a66498ff33d7aa9a3b129c4346122cf101f5374c0ae02b4974c0757ab7397001d3d3d9ef35ede52537bf588439351a9f6ded7ee0b28e881dac4f80336d6534818252ae81d114f0feb332a2397812025228382261e63e4a6545a85f9eb4b4368a838b496a82d61c9977535f739fc00f6cb7ae69b1d085955da40f371f638a89654032c854f0507c942a12656425b67b2061bff239087f131881fef63f7d47d0c4dc9a8cc93eaeb3693a962e7caa2db068f442cb13758400bd0d601a9299064bdaee93ce5b6a829fa65637b0aef32c7c4cefec6d399ce4dc257a23d78969f5724c4c0be530fbf1913883c3bce7d275bd7a408473e4fb06d5c062cdb634ffa2c96d8ac66aab42cdab290e99322e700cd3e82f3fec547f74d305b676531065319ac30475a229e464e4052a53cb9519ad33d8f8fc23f5a93e2c4257cadaffc4de905f3d08645667a1deed7a2de75f0eb63fb84330ee026aa869085e3108623df843d55cdbaa3615222956a4858fd461995bfbeda6670f22ca1bf13d12ea7fda373f467a868b32ca3038e866f5e0b6e90a718110e2bc9d9dfd3b2d8d35fe97871f000031eb672a35029cf1b3108d1c21a19c8252e0bc1c02b66521be24ccdba24fe9aa6e21b043beeb8ed63aa685270066622eea28440035a449b297874f33ea40c08d24a61e71faee59c213ad086d88bb274ee6927eff5dffa24936b0962f4302789d2b5af9c36fcf72b894a3344293737bb8c6d1e3d8af2af7c1f6440b7790cee27f73f12d7a76d06c99676309235d30267aa1d637383b5c0da9d199b862b3d9449a436ec5b2fe7e8576c6fe691eca777ea903f5fb736cff251e54bfbc69a8820044a09b49d02ca0f3cb4671679f805b45db244a5e0286096c9f8a2d327cb167b5e922aa8ee4538f253c3df42afaec4101c4baa7e4cb153db7d107f2ef4c81fdbef7ae2370b457333ea7a755545d307ffb70b0fd30803e498a2aba17151039cbc5ecb8035fbbc4f4bc39461ca65e8a1f225e317f664d1a5ab5b5ab69dccccbbe8926150de3852da3e54f10faf96913a46346f1024129d2dff5d482487fb276d040a1f8eee9f2eceeee2dd416bdf423e3418b48b5c0fbdca01f790776d5abdb699ac69c1f94dd6ec07d5371819047b019ccb19e765734b42a62ffb28bd88b5e8dfe6d4215c01d889a4cbbf080c3efea009617fa0044bc391ad7bfa078d543adf76731be786df09e6d414eb4acf9222f7e216a35cf69308a9240a4a8638f4f9f0d5b9aab4924ef55bccee5510165a6efdd7ab689a75fcdf9c46d9dd5d11fae8f18439d3047ad49d22e7c599e9636cd779530dc592263d3e23da7d472bfc9205aa93ac7d3b0b1591771f8d208ead77c1d23466791001b52348578067bcf29c04b62cdef5fdea8db917c7c3db35de559a44735a96390b7fc2daac33754dac38fce03857ed10bea739f9aadec8fb5494686b07582b2800ddb23f784a4257b7f2709c01cca2139e305efef34445c6a5168adc2b543e49e470bd2cc31f5a907e49c0b342b5731a7d3a524a0609bcd772019558151127d2b78aa2da57c1eaccdb189a7ac40342dada86a00c8ef5a00fcca38e230ff79691cd0aa849af4762c33d47a9827ce2089ec6e963d9482d1f2fa7be1fc7c337d50c34e0da987404835348d12588dc8f39745d5ecaa85499aef5ca5884fac372d1ef4bb20d31a701a941666750da1e1103ae764557e91fc229197a35c3f4769ff12f7d268921d96f979e4365a5fccbda6d2a6cb98fd98696c70f8a8f62171fa96e035533295cb01cda69f885e54b53bd3b973ccc238f3dc6a3ed6d543002389a64686df2fb019fc5c28591c440b24fc69aa732aeae81c2b7eabd0d20017294278c14d4e9ab2bbd0e1f61d7084abd9da030508525872a0c8dc1c6d8899b5c5c900000000000000000000000000060c141a232a"}],     // [{ tip_id, region, public_key, dedup_hash, vp_signature }] — embedded by seed
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
let GENESIS_TX_SIGNATURE = "3e447a396e5aec25ffe1dcc19d8a04a2be50b7143fc567d987306ee24497a6837aa8d947011054a006b7f20d6152ddc9ec38ce50ad0d76785994fe20b8c774a51eb3f4615b3adabe93bbb805d60e8f093c2cac890d5f50d58910d52fc2f8aec62a052ec2c95dfbe6fa33bdc3cd52efb0d292bfc9997918ca95f35b0ded6e506e14e5dfa51ce0bb27ec9711881d1727ec845f0eac219a76292b19316487f6b43c059b65625d04a55c0d542c3f2ea529ed6a434ddb1ae6b6dd4ec77ecff16f101556953cb350b052526756745883d0078b3230f25b8736e1fe3e85724e15cfab9a8fed905c355ffb471ae730057177d4ecec00986a9e1c9dd52206b0bcda910303e61bf6f0bca662cc8ecc91a3f975f674de36703282b1fa46dd0e52ea31bde399be5f59d183e6908b9d745a1b1530765581994931367f4ae982e7eb6c123e4a0006244eb213ab084754b66d4d0a3216524465e58d767053c411645a2dafae02eaf307c0be740e056e2e928cea83d8565a1de3f811e8376564e7b24e5df7adf9d8ab0c694da594f027f88d109c199eb7c0c46b9a5cf867bc654752b2da7288521b10af52641d9f131c5ec5c6916ba2eacac4ed23ad165558cc3405c4dd0a465114b32ee8eb6a958ddd29bf6294b74daca85dd2181ece77951d87163aa9ae707947459ef15bad869924be040008f0b76decfe8f0407d74f89b197bcb9bbe872d1f90d3576c6bac52fa7f40e1f4069b268d64850ffb5443b59095c9e56e1cbd18b9fa63a2354149c2d4a7860db053c34196b904189ddc5555f284eadb778f03e61eb22ed70a69b97cf6baa3687417d3fa2e101719b9453bea6e44955579ba80fa1834cb2308f91cd21acc9a535bd6dda9f2cf3c853969c4a6f9ebeab1bf804def13e33186b14c910dcba8140dce9ef7fa1711b54c6a94df75b9cc9dccbc20098e8b3dbdff6fd2b8825a3eef95187c3ee415eafe9a48cf4478f2824063e5a3a255db23dcb10de99c2499111a851707c18c100b227b4e9b528d457a5394fe6ef07be6709eca2dbfee15151d05c3d1b2f3c7db2f5820a6d0949b296008e309c5153d3a8ab2dc0fd628931026d1ffe6dbd3e611ab34383aa81d32170bd139b00ca57a704ed026b019e5d2fbbf4aa5e06f37040b5af16018bdacb4d557a0cbd52b953ecf7a48933ecc07fee06fc2e941d510891b585eb8293694f89ddd3e3245df444210934d9677e17125c296336b70f26bb27ac17c70b7e85a96b86322cdb2b99096b0ac5ed5ae2e32bb65fc7a92597b8d94a371ceb459defe380668c52284cab81da8ec936d042e5b5822416da0238470f15a2a8d9b3711b79a1d4a572f3cb34e977183c60ea7e44894d08e919280735c6de95d38413eaa2f9965c5ec7a983d6ac4da06faa33f405d38986437242ea7f84735e8642c8d2485cf1956cdf0678cc02dded8ace233a174e346303610a54b24972c77f3e60a9a200ba3c0fa8ef1760bd8cd37db4cef06e5cb86930f220006f0b0673aaa2c820ccb1524c940f1a47e026a45ede8ea4607066316fd1c781099761d08a86bab62442dd832e1d9919b0eb22b853ab357c4b8fd8f40124b046c6f9a2e594ce844e0d8dd634face64cd22d77ef6a649431c8139d9a5c0fae6ae78d912909293853a98bb5986b90fdc726fd6eb24f164de8cbbc04d0ba7c84012cdc6b7e64393e6eca619829c6dbf812a42ce0dcd2e1a99f3c772c8a5b643914a05ae1617c449e34fd17b34128c840c4831d33266c0e732c18f70e00ea5c288326cc5fb24fd0b1502ab0f96d435e4c362847bf1f2826aba386692e5ffe15ce59e6e1a1ed2b20047241727097db250b20d5a3158b76ed9104a3d087c24b83e5e69815c53bda4b9841f4eeb0ee4314b7ce3505ff26d2833f4960560935191d45252dde943aaf48409438acf4854ab6bb1dacd310cbf1445b2e244e4b6dc530af8e0a0c9578aec231c05a375c5b38dfcf439aa23fac18ef697b954750ea71ea753fd6a8b7a78fbbe283d64e46c6fadd6310ca316cdafbf004d97a6ba91129fa5044235284925d1a44aacefa97f632fbcc169106010f944d2e97a5b107b5fea5704ebf62c84dffa9308edd9d94717b2443a5325970cbdc6eea038f68068b21595ac59b3ef3b9dae003493b27bdb45215fb8494411abace21c0ddfbfcc2ac0e789b1a6b96eeee7350fe9674d82a729ebff51127d3897b84fe4199a438cc600451d3446e203874aaa76543f66db013caff3ede6827c4715e613a8db0f774be9ebfcb0d5f6c4dd10596094d9b6a5622de296fc6ab551abcf030cad703cfb5d275366b27b27fc74a104292e48cdbd85132e0f3aafcfd5bdd06bacb631f650ba421cbee8208687d9367e138f5ff4cd05768cc7aab136d14892778aeb93069f1eff07f0d9ef8df532d4df664951bab41e31a019731f7487306cb506318ad612e55d457c11ceb60c078e481b4fe2f372fb869e1077abef4cfb2f81437973e513fa406529d1164d3b1884bab1ff081918e477b3c506a6f73193046c5a9e2997b97c06db67ed8970b2d2f1a065969caac8469e507508925bb72883291e961de8349ec521fa6cd044f306b91607dfcc384c1ed15d0f78b52d2db8d474dc0e0093cf9ca526ea70843866bb103bb04f04502b8d32f798ebc9eb2a4a921d2685115643b5dd1f3aa079f45ea165bbe0e182fab199df2db7110b36dc3385fe4b39ec53a25eae01acf2eb3a5643f3867ef05a6ab34f819c397c94b67d9b2ea36554accb305d2365ad696ad2ac77cbcdbfe6f729d53bdf1dadd4477a6c843bd4514919371a0135e4d6bdd2c527c654a566ce3825d060a4a813874aeb5c2f60c2ff3fc3371c18584b1e40ac2a7a04b21a6885f9ced44af3ce46b163c4ac2454418c6354174dd7b6e8c3c77b143fe1796acaea35806a0d428e12429caef0557779ed34a6ebe992b53efd9fd3f6a3c9de9899fea7a6221be498a6a22c0a5d902a6ff10661676a17f3be9e9b00ec3df1f671785fde30132b9ef86f5f5328f56b773c4842a811e08a8c9c0887326186650b699ebc1343fc5f50cab04b84722d8a28c53c00569eb2b9033f9746637212f113f394f9525aae53a53292f5e0934bf5493970c92de96be5022163b2194483bb05020dcc478e2a22e220058b137a7950a7554301146a139cc8d5df999cd32c1c58575ef24dd501cc0ab208b6c03d58c3ef88fdb3b37ec1d8b01f74d5fa362c993b2e0ac58f16e90ec5d00b2375b3598bfd53dc76c48812f393060f530516a76b5de6e6e12e4cb237c5af81d147151d5e5dd79af95cdd3049e0abd8f96881090d754e22d9d2f4e89c911ba892327d7d5b1eaab2da78fa48ee1e7af0e5bca6e0f445e5e0cf6fc3501cc0c974c729e33479e7e1aca634c52d8ae775a0faa8b764d16079e631e923208db9274deab81a7be5002804c19d42a3b97cbcf86735788add2c9fc5350a455ec669cb1d772c9ce7cc437e44cbcde089e5bf80b45a3d185dc708163f8b6a8bbc79ba829a53551d8c807d780357feb237bc6474db4559845c9e5f3c66c523a81ee6ef6b3c0e1e622f6002de8a41e06b326743d18568ef51c79e418b7f48288e9a6824c20d38049ef3e5744fadfb9e6c446a320dec5e84484870f362d215d1786c2e69065164ea1647ffd2fbf9dc35583ce181d1d3dd0b89ca80a8a1a70ffd1cf90b90701ae1aa90c4735beb9b5d9b9376c55700f6dd1e6f5e32cbaeac6fb1108095df76854df2f3b5539500a3cbc291940136c245d45a76c9a1de80e0fb45c3462865ba609ec1e406948188344b83e1477c248969d32a66d4c2fd003f3b1041c486521490245d48960ec5af90d96e9ade0b62c6ef071911824a9961e59734a128183760667e96e4a399e4b3e672f03a3588acf0b27c912d98760430c146ed719026676e9d96b844eef9330c89ef5c4811cdf7917505162ee461200392c68fd5c499260cc04e243995015ef6cece001bf0f0b3c1ecf75e3e35a4d7c2aa9a1a05d068ef5f53a28972cf7e9300237230227b5cfa6049025bcc91f066f4894957e7661be52b8e3a74d5cedcbfbcbad46656029812c2addc3964e228e63d07cd6433407259aae292fbb447e0effa0b748e825d7d7c4a1f9b409756db1a3ac8fd0678fc7137fd9eb6c2dc3e712e1a3d33d509b6159f437914397e74c6503ee5b0a74b6705151fb691a46942787a7cd66a8d39225ea6c82439be9ab65a2a0c5f6880ebe7d812e38cb0e78609754897ad439b12fbd1286d05fa3ccd1312ec2d01e2edcdc39aac573922ae7bd474ddebffdb3e7d60d166299fc87fe34b1d31228051e1faf27084d38bf7d5a65fdbea57110b7e6e53852474cb0ac4c1e2107e09b6ce8cdc0c2472c36ce817a3afc2201c030b354137ccdbddd4f5440fe48b690f7b70e313fd1114be30f057d6cbafdc6775386d1d1582df10a223162b8937193dd705b0aed80cabe9c52ab85cc652378869a300258eaec6c2aefbb9feba3fd538a5f73a98426a46b58053391c374104e89b8b3311f58ed922d679e3cd1ae136a067a3b16e461694565e9c804950ac3b18897ab6f1ddfb460209dbd1bdfe7f1157276aa4dbdded161e9a6ca85157aa04414f699899bec1c5e7fd223a5d98e4ea00000000000000000000000000000000000000000000000006090b0e191f";
let GENESIS_VP_TX_SIGNATURE = "b5b915cb9c3673c1c97199db0b907d1e56d53c69098e64548840e0cc8c402527c9ecc28468d7790b8aaa03637e137bb44ff1e33ece729fa0554edec4f68a8d07c34cb4dd80ef3f47ba9f40c524ee09edecda73f2a4f71918bf0b3d10c7243b802dd43ed143ab45c80e64d8be979e82f30c6cca7163d208a63d3c792da789fc1f6bb24d4c7705f66c7be8561ef741e969b4626b4ff6c8ae718923264d5720af94b64f7b595a852bbcf209703d5a9319646c030c2c4c90aacfd1ff1ff7b53f4015ebd7eea6c1a1f53799986f663bf32d940f45a94e83bbbbaf3fce0ba22031d5d7a341b95f521caf20440ac7ae5ea0b441bc78c79bae1405099e7b71db9a72e26248de1a85ba145c55d04ce7fa439f117f2d8a5853a93f06b2df7e051d99b622888e80f67da92dabbc5fc43327b369e317ff898b758122d10942eb01d8571c7cef1fba38690a16b46f9b836ea7a52398022a8f182866b5485de9f4d5303144a60bf0ca4858d8de68b1b61c3981124a8ec481daaeec9eaec403808ce1a99ae982b502664b6ee2a62517b229af786ec49e860d039e8201c71661eef110f16f666b41645fefb61b973eeddf9851d143dc77b648bd1d9d5ed812448da2ea23b66af51efcc4972eb5efb7bedd3ed014dca19c10d592a784f56cbdefe143dcc316f1f12ecd806ea3a0ae686c3ab71acc8d392dd858eca1098b6a5efd5b94688cd59358395c68d10a6d1e12997e1efd3fcc87aa32a04651d806f414a43725fea51e0e9a6d9c5e8d1c18c6d19e16d48f570829e32fab21847acbd032e2df759d34c305b8541282ffd889cec2688cb60824ab143ff3058ed8e5b1671405ce87eda5c74974372687a1bdf5bec4e7198562b9e9fc4c836e9ffd61c662dc4a66a9c18497c2f02bf8ccbd7e1f4bac878139da20add0c5797f6374cbf5c56bf6a3c91789d175d20dd568d82e82783181cae14bab81b24b7fc629148c4d5ca0a4a9f3d2da3270bb641c87df2a1d382597e1ce5acb815bef60c09efa8e3569e7f644d3147ed635110aa364fa8530fb8721becbf6fc6dbb5d26c63a5d7320496326617548568f3cb23afa2074a7235c6e5d20c34cef6fe94f4ca658eb80bef2e03a89f22f961cdcb815ad695c5c8cf46da5d0d24fda750c85145321b0320a592b008c39323eadebae3733ade78a0cc331d7cee4f7416930b6a06d25c45667e020aacbb9d8ec7f60a64f7ca567f0f8efda1729d26363b6098d1cdc3df65bc85c11474091774c438a1841a17dc3a08aba5041924d66c3c7e0bc5bfca5828b0a1a6640f0f6464b4db8721a230085ad17e4c490b34b4ac4395abb94ed927113d251e7d54221bf93d520332c498b0453af2df613da8125df7a49840a97d93681e36e1bad6287a8bed4567dfb69e6cf0416bbdd89a3955c06d2e87e5d97c08f4ec5b5afc95de0d821189bf765dc900f706bd838810b7dd14bd79f67890d226aa421bbb6145bfd35cc34623c1192ad31fb91cd9de6aa020e936967a075eee41e2c42d6fe3a5936927c0cdd6e25a4711b67e136164a65a7211a427481301a237d8d1bad83e0a20e568a69aad07a092fc6bb40910ed7fcc587c5810679af6d2bc988d1be4576e0d4bfeb85dbef8d9cf37b2b021f19169168c9e11b7c90f3b3ce425f3991a75073ec2c9121ae07f632c32288aa32aa91b22b3c62418edeb88880babf6ec5a42b4d4554dc8e4cbefac7753a8c517ad65fa5a05ca342b715dec01e31e38ea873b89a1497139fcf8c1a041c61c6d368b93776ae9be93c142dda9404fa59cb6778441c9d86714ecf9f2f050461a33f276365dfb856833513dc2bac10c3854658c3c5b05053a9ff8bc9fb80aa5b9cb01afdec5c519ad99b07ed77a64191467b8298e4a5de3e62af90f4546e61e1ba94a9d21677f39a87d2876413b8961ec45aceebf6d4f87b695e64713b569457f5953917ebad70b1c6fc4888e2a535326dc9b6c7ba3884af4247e06789514daaf5e0c6a3e0073557c1986f27771978215a7065f89f033dc9e478ced3342916132b348f9a2fdab21a6eab0c1119c91734d7a66f0fb7f15a695385a9d076d3af98fcb07e6ad05449b874916fa9857d66913f49219b57f04508318651e8a89602644c5953ee7fee7299447ce17f0656d701f689cf79602ad3b404a3093a54d6579c85b0d6401db19033324c475ef2d5755ab7483068382190bce4625c9dc519101590e105cf1a791f5919ef5cc1d13a7d9cdb17ded3c576b86a467cef1f61adb792c18c5e50b7b56b74fb1a2c680157a9c4b289c3a6f99ac461f20437772909987825048132f352bb1e77e26efa8de0d8f981017a03c6833ff0e02aa5c8821c032d0e0057c87628fc52c37499c794960e5508249eb29e31961aa7ba324a9fbe23a58035a57600c31b1e3dc538316b190a63a55dc280070efa8a5bb75e940954fab93f13cf21efce322d4a8020cae035664f61fce3bff1f96cab5e6194fb3e36fe4889bd811329c773d8d8973d8a22d7be435a0fc0c909aa7098afa9beb39d2939e9917d87c7d4871b5a9f200810d27ae37ef0b15efd9cd1ab881aef86cfc603749de4ab4854eff30d997660a52e4881168cbc83579e04e8e209eefcfb919148a066eacbd9c59d6f0ee922d35c8be3f50bb417bdb673a3a1902b1f4699ed42715a075273c6a1517a9b141f149b9ce019721a039068cfee37ed9d9bf10a61c3f994271aca7a92907606e9430adc8afd49c11f92d83a3d0974842b476ea10e16bfa17d3dac8f4ca11ef730653ffaa3a6277fe078ba9ad7061904fbfe1adc236bc9894219d0f30d3ea2ed92164cfa0cb50af324f9be8199853a1c2e642ddf5f18f2bee1679da0c876cbd1c641eb952a618af60c43db58dafcd469a57e9c979b2fc2f22396cd84b8f8902a0619a0a7f28eafa635de83334199daea184afe8d3f77a099076bcb3e4f257654cf7e8db7d0b618121805d2f82a40034308b8cd8406fc9e8e0de1fdc32d53b2977aa5c6e92dae1c986454440d7a462fc27b67c02a83df30fdb15e3e1a601a9a178d8d39a25dabcc7a3163225d0a41fb0af4ca829ec356d243024f230ebd4fea2576eb0e6748ae56a3bce61706bcfbf7dabee450eb8b20f5f7c7ed6140dd62820e179e7ee9fd703441914b18d1ebfabbd49185fd95f98dbd71aea6a89c93d6452d5a03ce1528040311bbe414c6d01e49c655b09712818f5ee5d741a6a61ffb0c951bd43e12af76ca7d7c994a5985240b8b4c01b1eb499c85e35e796d22ed81fcdc4dc2c6334f1488a711e91229c333d404062fb3f187dfd30b032825a5fb149d43c760e5afab896129fc11c7e2980e6fda2cd38045469a8b95d0ecf916b36450c7c3476dc6780b7ca952cda310d10bfcc03349d689491922a5dec6dd4ae42c596c74eea369a6e5029a9f32fd9dbb5876ac29fe62382c278fe83a5b8b6d19e20c4e9c505203ed4b49e0815947f67fcf3b631c91b0a9150cd7b0eaf3da41371738def79f437705ea0aa06236fb1b273f6c47902fa45f255be07ec3f2441e3cadffe7ca01d692e5d2e6ed7cfaeccdacd2eadfe7019320cb531b033b820d0a101c3e8079177b4a9316878ba75e34ec4360d6d1070de9dd7b646a48ce77163eab7874e3d4228e641377e060c36eb5674b12e21ca20887e180ed226aa11d2cf3a4eb43837b051437063ed5735902bf658fd49238ad684a1b7fc4da901339144bc0db4a21d0ac1b3d3bfc81ad088f3627d619e66b1bb44dde5627c05d39f894e6682b5e89e2604b37b9d0dba0812ad1a76ec2ef237700f12831b2ade332491a838e01d2ff7990d2bdb9b1e51fea4492b7ef777fbc01a8aae4ff7bea5405571d253e824428dd186a5b37fc943cd74633d676860493708b8469b51929dd565484f8b19d56926bedc98ce92ce1bec94ea20864555c206c637ab5505d43c6d80fb78c3c21fb4257f7372056a0d9afa8836bbfd84d95f3cc37df7a59c9919916269cd94f1f09672708bcd7eb4ecaa0c2501c3c1c7b772953333b18816aeb364e3edb882d28f3a45cc47824bb1dbee7958ed23e4d02501c12aa65c7d4d58b3c1361c328530c0bbf9e5c2330a789ee9feb7a68fcfcd80e0a3cc34c513f1dfdfaee492f19e2b80ad15de248b67c448ae49781cdc30a3706335e2045a2cacba26e47a472fbc3a89c35ca11f26f6b6a9e293c8828bfde9db1803c20b104eb6a402d1fac098100cf6fa01d33b6bc703df20601fe0fdf00c6bff44537f50d1a859b8ab599abc3f7340289b60c16caa158225b52e03fefac984ebe7a82ef15b293d008b38748066e3522fddb5517c8a40796c106910be9e9f25ae5db3636413b81997e30f1cefb3fca6d9b408e3952ee777348f27fa8b6006f2562a05dfd7772a5bde1c348d45cfedb8747ef8a3d38f81118dca24317e8e1f61aeaea959af4d2feb8825ebe2f5c4a520c68d338cb014e95ccc155d05b280a68fe30fa097d5f30132e3556a584fcd866c719d862c1e83c961ce0354f66437f9c5a73801b65100d20efdc57909e766aae67bc984e4f9be92634530dc6989b42dccb3be5e2f94d1e8c5d8235b058a65ca6076960217d5601b8508183a508383aac2a83a9d4eef502070e1b29526a86c329cee2437c9ea5b700000000000000000000000000000000000000000000000004080e171a1f";

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
