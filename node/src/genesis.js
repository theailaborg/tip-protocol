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
  founding_node: {"node_id":"tip://node/c8aefd90b6a81770","name":"The AI Lab TIP Node","public_key":"23018ff95bdc4b7e3f44d964ae94c37bc8599cd984cdc4975dd48c07b2dfb8fac45b8a9eb3bb07a27100aca2a5b5acb758dbbea8c1951b3ad37fd8516778c21cb09b6f437d0a4e770dece5aac5148dfce06d2b53eaa5594c968b0b1dbbb0e5e35a89122385c18fa8fed82517280e69a56c307dde56a2a3a63f87221e77b05f08f51aeec7ff48ccefaa8c559556c41a4e11782e328969f97cbcb1e2264a812006fb70a43b5c2c2b6e6496e7a7e338f7af706e4587dc92b19a4b011e4212152b4489b634c6f1bb46beec14c51c1660b341ffa2626873cc2811094ca5d2f2a84acfbe0e7f2acd70b8283c5304ff74b4a47db769f0a45903c00a338914243eaed2a67bf3862ec7d369e53b0e5c8d77065e6f17d8c3901084623b7cb6366a53484640f215a43ddee8a812cfbcb80324e7b254a35c6aa2f3feb886b39c6b746169b6665526cfac47d3feb036826a30e2c4b4b0eaa5c3e3fc5244b56715d120732c65c3ddd4b316ff618e5525fef07cd3558bb16c96c043d97571049bcb16ef5d6a3dcabd9ca4c9ecbf5f74af142b7948e06333ec6ba0d26a0ddcc71c87b6497313db8f4a4d8754ecd67e9e234c3b8ea9069a7a9d6ba162530eeaadc08ec80374f85eda864fe2010da006b8ad904e4e5cfe207ccfb6a7beca328251129951350cf0092bbd52fb2c335ec75e0b9ee346aeedf8a68cf41c727141a8b042c0e0f3c8a1ad2a837d7237399568e610a4f6a4364c9e6e855d76d66218844aca69dc0563c9534ae4f134cf376dc7a33d8b15e4a493c7d606d89a6970826d090bcd6c0d4e5094354f044d823f8e163f3f3686cadb68c92f77a48c45a913e6ace6e6e7a97817a933402c0358b60b6dd05f4c44d07fa874e44ed104b0755746248ccb0527913c6b3251b17006235c5c052ef55d24d30b04856f59a4733c5a917e88edbba1b31c2382ca599824581c52fb1d25286bc0665719a0c6367798c3245045e20ba68ec2f959730a375c5376ef57b784fadfdd4e15a923d7b92747dbe04fefe3f6662d3e5e7c02baa5fa1e44b6ef34bb12bec4ec3aa4012850dac02a60cc865101de6572ebda52b6ce32b2a8243c856ad5be1f29d6a1cbfcbcd305c6af3547db6b42773d4ef42ed371be4197b80a65983172d3a69ada9268c72291d6ff76ba47e446ab44356cdcadb2d28cdae31e480b0937ecaca2f4c930b9e282a7a06ee784ee7b2e67fa3c64457fc59e7b409a5ebabc7be73e8e461ba473b705714d2f527d5ba3e97f8c6a92d88f79919e3bc333d353c4d6973bc7b03956c7102d98f83810d72f2160b1b852f7db0b6ce32f729b40a78322d1cb99de1c5d4100137fbe37339e9a8668d95d66ba0ad1dd9e43bb7cedb00b66d5199f21201e2f5a60cc176225427e760869e9c5d44d7fda962e8b8cd0f388748e11a75468c393e65f4df38368f5887d81bbfbf44b04a76a76cc0ff2c527b23fb3e5aa40e02fb0f719f9c291975101f9f2399ee80a57e8940e51c48772b1dd8ac1873f3973ae9f52ba10d414144826628d2daf3da3c8325e4a0003f6abe53fb3aa91dab5e206a7f0bb0b62bab9cca5f550dfeaaed75d4274d02d5711769ec652a0c275ebe269a4b39a51ffa890997d739690c0be6eb5eacf2c3e5975e55cd89d0824c59eb21c07e3043f285c04f81046fbfaf3c9fa4df4ccffb5f9cfa892375d1c2ef9780351707093ca42f28f6e65d26e38e12cd6db35e830003ade0576372c0c8b198be9e0f0e497dd34db355a44c8779c62b1022c893705a5679004ce8c4ee58d9ef1ee755f256c7870decd50b8444638b563c8ed79ce2f9d65a65a5da0ea1c44db84a5f1db179498601afd382ecf6e5a132d36f5e990045d0f151ab881d1c86ef059ddc5ab67a49defba6e301e98519b08342cb9d0ae5abdf5bbb23e5ebb9569545bbfcd2b5011f3fafa83d17fbd18d216643ebfbb56011a1f99c59ad9d0b98b9906d65ef3eef3fc06b53e05e6841775c8a0c41f2665271564c4d25b8233c6609c72ebb91bd6237189dc9c9b588e899175ea075ef3c761c01a4cb2bf55763d0311c179d45a93090a45db3c05b2fe735843192a8f1fd8502c5eb62b35402839ee38b082cb7f0f533777256deca9fec6b66b934c8f2686390058bc2e68152e546acb7cf624370c8a798a33174729dce3678dc81eb2de8bddd10ab88d47ac64c20aa5fed96853faa1b27a7f35b82a6f4220f7860d520aa52020adf99530f6772341fb08bbadf41552965a185efd447e35aa964484b0b0cb80f8bb02998cd5c26b462b3b108f1ffd5a431b343f35f3cbc3b5900e3067c92fa1f89b77affbab678f5034e2aa05076c77e35c65bb1946d02156dc33822786caafa5188b0fb789e98863a31ea40471ec9be4d1ca0a48b496445e01cf1041e302572ac4ae1b920881676a1b36554320ed8163dc92b6963aa4de68192316d8f0f552ded371128d372c4e5be16bdc7960a57dc1e1f23e48a66b5db439f44d8e7083b7f8df911c3be572279de748957bf55174fbd2ba812f0393834b6e8fb1a2943d54b19b034adab3ebfbfd5f829231bdf8227aea48e2114ff73f0a0bf22f050773d1ee5802cd4c251225d7c97ab88a7de6f5e13db74bba87e4b36c1780cf4b733b15f4217abd2367044354e7c2167f44164b8e69f5a16685ad252cc4b93d4efc5e83129a7a4516b4516feb9df61f9402ebf2e820f970a858b18110f2524ce10798e8846b8704a0bc54d1ac43a5426b47d1a11393b2e7a5ee7f9168a6","council_signature":"b96ef6e0b5398c8f240f35a91eaf891327e9f137e80ef5c0ecfdad4b4966c9ffe1871d215ed347289cb0cd8b6ff7def83769516d7a0a0e5da08c2c8104be62db467dc2e6cf831eed5de7b02214be559f3ea78823be8d27f384c9754caedfa81fae3b4f562a774173b47b2254d5d5ca2e743637e9604448e5318850ef604501214f8c599924716b28f127da996dd5135efead51ba69b582ed869c347909335511ba5eaacfa14d8b2cc74c366c0edfef8f8821e65ee0bae131a6197f177cd13062667aec3c587f345eaad37dd39f8e8e26d6535154f31c486a11787547f7f092cc66e9620c249940f236496abf2e1ccf0941d112dd239f2d694e8d308aa9cc1ed91795cba1deb8a515b6dd67b532636b2b838dee09001b48e8572c68f9aeb5e58340015b537f469cbbbda73b251e553d797d47493087c98f91c882088e8a52b84915c494b3486a2fbb2fff7176cd3590e1e22f030b2f0ce62e8e4fe4fa5a0be64fcf86039c9502b3e3d9eb33b95b02b08b71f0e068555dc2e70dc3c9b7a98c1c70b07f483685c840c4ce33db13e302ceebfd16565502ba3ea5961e5dd1109121a2f01c7321287af4e21a715d8236a1d7f5dba315ec387ebec1043165d26c42ad26dc75851d9d5e73f174eb682d37a9584329882b12a27c8eb26009dd32ca0e4f9422b5bda9ccdd60bbb873fe0e2534cf38d76dd2ba58e56820dec9380a232b85c7606d295ad0c5565c01863c44aa1520436fef841c3cd6e81ae640cb6b9328f80f1f060f35d41f17ad1474f121242739556622e59922cd30cd073138b76fbc0c149d9c059fd76234e05d1c2a0575ecab838d231ffa88b08e4d269ab124715d3fbcc8d28f95cc54eb2ed0c53577a1555f8e8db849036735f7aaa3c501cf12e1a55c1c2f3a63720af3b8a403573b4eabfc146f2a6e4b47379a5a37c622d1bbab8b97173ffc78c29f34657bb2afbe24122986b94682ca15a79e96ae4da8172329ab140df3a375f03733f6f44019ad935c13ea0ea12e7a1fa15bfa9be84dba342832ebdfb0079972eea1b07971f3fff2b9f42353967f6d65dec7cfaf06175b5f8b65271608b820da36af458485ef439682b963349a97c4baa6af075aa2d759fba36749043280cb916974afbb70a06c4263fcb3dac2fad91591aeeb90e11465c61f302afc31fade12d93b07f88212bdced5c24f7210f0e51ef9c5b03b48037c454cff08a83e52abca62f06d11a20674e56b9589ceadd9efb1d3fec11144137d2be2d2c1d570fd3fbabc7f71d805edb77e594b16e4759e511173ba10164131cfd6d57ba0009a68968b2ee9f8b03ed39ae6902db6050a47c7b58025bb6a24dbe271e3a6d1f0f77ca08da63bfaa209eba3d0c984f6c5aad8831a31d43f96851cb73d232d5e64c3ae806e60b7c8358b81d9a5957cdf98b436e052dade11eca107c25490e2e99bf99a599021def02c3928953d6d1db9f720383c19642e75f96b68b029c419126dcc8fbbf017053a52e2ae22f6c5755dcd6af37e2bd5454f387491400d8fc57881956984fd7527d70014f16eb03e319b726bbb6bc87cc140b476ce98bf3b500092b28dffa71469e86b26361e5aca14f168e6b2ba22be922ef483f7055f0e59651d52d25f6704456f1c7b81fa6ac3e94ba7a4dae26f8ed3fe9c3d0e2beae854d206cb600ea66bdf3735c91d547b573abc3c9ea0d1f407bacbeeffc510dbea8ba1b93294348d0cbb255fc21e6246ec81badbbbc3a7b36dc74367ee49f981b486da6777cbd80b038785181a69bad73bd6817b540afd45f8230f94c8d6bf9917754bffed3bf8f315fce7293764255c2b28617d45df0a2887f09e5e742e161d2749f028dcd23e797e1fc0c47dad84a1e629449bd694ef3089e3784e75d6bc257b85329053b8f544fe8d4a22fc8a4ae9ae34928b738c17ae5b0a88621f025d42b1621e520132e89fc33bb0e250afc1cb323b36c1d0df46132cb8aca1c60a35a03beb8c713e10049f44cbfb00d349dc704aa391e345b941e7c9887d9d2aa9afb4a1bf59f722bdde5a0ac02158ce55c8c3735ea726930b36eb1faf351f711686b3fa78275b45896e728bd70109d72304c97f4ba29c330e3b6ba0131ebc59021fb669adb0926a2855f088cb502494793a6dd7dacb6c7e7773aa0858d7902f0f7eccd570271a515477831957519bef0a91b52a2a4f853e1aead8ecff3ee28bff23ef433784b47922f1943d2fac5568886f7b671a8954cc5a506b16a81b3a0370cc68dba9e122217776c320707f0b4b0b297cbd9b1116b1705d2da4f4cbf0d88d5f7ff0f05f7a7fe541df76978edb0b79fcbe15656fc78a6dc6170b15138ac6c55d3b85d79a9aa476fcc5a5e275a58ba9aab629ebdc3c91d9217e7981b313754c6edd35eb72f31657006b77a89d9749ed5f3bd85fb072e296a5fd98ad731a85281e4d2e01fc03196af2fc302050cd2313df57649c744f281ccc117c471f0b8736b02eaaffee2b2f4e5fd2c9343250750ac1edc603b0feb303526bf586725c284aff226046d6e3b759ed0b18b354851a29edf0ad2a0bd971e5072de5d0fc4a9e23d25ab72cea6eb5f5d3922e912b00ced7bf30774051b071bbbc89d5c9b740552671feda81c353dbc97c6b337546ce588d4cd0874cc6dd49e805036be460d7f965e846fe62508da33b373005661e11e91cc5bfe4409e8242fa9cf5e55252aa8c6d95048b4365d15b314e45852fda871dc010311c15f70080e780344f36a7ff02d0bf45bf912ffdff6d583b42ff16d49a4c1a1cfedf48b51bf02100d6de4f2f75ba574472fa083934bda3c88da4ee99c3819d75de95aaca59c1ff96abb462fe1d7b4e17ca2e06004db11f86d8bbfda61827770f047ea3ecf0f34e02f86a2f15ee42b9be2b48adf75d4ae3aa29f427301ab2cb93726f0c421e5fe00061b61e603f74f90cb53538386315d68bd1cbdde55698215024a965a23458673fc8d13057eb3970c316bf808fb1ed533d1eb7848dccf468babd63b7c16f60a8f41d629ec97a9fb3e35742b5235e2948dfa03dca4840de5d299e85dc8b2bd0e09520e9050fa1c963d7b9b582990ae3afa3150c4b14daf399ea0928aeade7cdbdfa376daa0ce8a3ff6f7e290c1b75f919e54887f0cf499dcb7035536524759e359b55a29429dc7f743d17ec655f79bc60612a9319c57bf063334190a23cc70fd729683f9c55fb2d5e12b9bdc508243658c963aea3ec8534f0946cc9e704951e6ed16631c3b6d3110f517a00977aee8642b58409a7435d3fc748173c804fe9aa5788a1728172a3dbcf95174f8354269e5ed069310955843cf6a4b879cc492a4d67f5db2aae2296a28ff86b71d53685d85c4d1d824a0c8f77be19dbf8dac1c7206daac4bbd7210a53a4de01e71eae64b8426bd656cbb6399001497e8eec9fab7dd2061011e98808518741e6df8cf42bf8680344cce80986332517947181bb914c33ae8372f2c99cb65a030b41f927305b6ef765d69e13e4ab23f823b4446c4522e2d879463f0d39cbca1ce38e79141c6322235728bb79b13a34d6ccbd39d4281a8e9a497f6846aae266f6cf184aa99af6463ffd3110c9b5f6948605d5e2e0782f1f2ec216fe612ccdd19032a29a74a818339fd987577a48e375495ab7fdd4a7c47336f2a0700e939771b42044c617afecdd0a44e4ce78412c6039cd54b472229a7e5fea4ceaf32bb846db6b88e1e2e3c1b34f6e578c5d0017e222d7541cf40b0eafad7dd1188a622ac9fd177fb128773915192b867ede476663c847ce8e6eb20b4145b100b3c072cd1f57c595a86ea910d5e6efe8a256175d2ccf03bb11f249262cb3e1b77ad7442b14355f92b77cd0a07392987b80e3e342f4fa71c91ea1353bd063ffa703eaae382130e2b5ae176b3eb0ed70e0495a84ea67290295c4899f0728f5a3c726d0aa670fa628fb5b2355ecfcf75bbfd1fc2d3edc5b313fba1696148678d28e75e779814097a4ea2be1fa52f1be2e8fe021fd7fbe92de72f98c4d58841b293d6787269aedaff96f6509f74f3072dab7398d4c44c4f0c283df2ba38a94d1081ea9064884d0fadcbd75f43169ca20769cc9150f56e45d8a63ca51b9c4f4a59ad55aa0f0632282df199b6eed423f05c1ae610fdb06fe56a94b11a674c77479b3583e32362ed780321834dba1bead6493d816f33c51c0ad13b83af0c2eb754a4f589df541ec6739a779a34acde3210d3eeab195ee293fed788782099a92719ca1fc6bb459cd288a53e2df0b747e74b972fcd0c7f5a75c6640b4d9881f82b2bfde665b6a2b8a1d0e5b0586a5e59e2d7f3c65690876924a856ea68dabfd0324bd8acf38b586f74860f4c8b0207d32b688875d5db046f575de0f508ea2bafa46c482c4d808155e0db449d5c88d8f536bd747753ad15a21c0c87d61c795b13fb5ac224528ac550e5c1921640cae3ed7b6ad3362906347f2585220b4522a327c4bc54847a4414a32c1e5627b9fa5746b765302b3bbbee510e1f790792ea78ca58d1f4c1bcea05002e4895226c191134180826081d32cbe41bd30d2d9427f20cf70d62101a8fa05d2589ffb771ffea6514d3c4e7a3d2ca9528cff43cfcd0c6e82d0f0020b3fafb0f1fa08264c6ba0a6bbd1d4f71b4969798e969cabb22a495ba1a8b2cfdb031149638192ceedf000000000000000050c161f2730","approving_vp_id":"tip://vp/US-cc733607fa03646c"}, // embedded by seed script

  // Genesis Ring — founding verified members
  // TIP-IDs, public keys, and VP signatures are embedded by the seed script.
  // initDAG uses this data to reconstruct identical identity txs on every node.
  genesis_ring: ["tip://id/US-4c0b7d1e8851a215","tip://id/US-5fb1990b4a3d859b","tip://id/US-b53bd091f66521db"],
  genesis_ring_keys: [{"tip_id":"tip://id/US-4c0b7d1e8851a215","region":"US","public_key":"148e11bdd8088b1c1eb791193d99968782d135e0d66f3a9f026a2d38bbef83e31bc3471457b01ce3e6e2c617d501458142858179da7e41297ab9fecedbda9f8ff488c9f42c99aacd2bcf25c2438ea0c8a96e74312c5adbccb7644878b94750c9e4b90d68eb9cabebc627a630b745418a30499260fb28f6ab88bc692d2273ba6917ac2ee3f1b4a083fea7ed69eb9364696c0828dec29d7b1a9cb0a44cf653a85948b87667fad849dc2b8e923bbf157874179834d37cd8d4d4fa5ada06abbd35cbb2bdeb79ef63621f1002b8dc40fe18da082f24d1894071b51671ccbd2927952facd011020b0b38329112c8780602c5b27bfab0da50d0ab7ddb1aade0ce3eca2a4d68fe473fb612094776d9ee3d24d36a23641851c7994d36e09421e446fbd0719524680be54fb31774dab492c03fcac8950b3d662f3bd4b90b2c49b76a01f1d9afb74811e378c0f95959fd73e94aff5ccfaada3dec7642ed0242ebd41a37ac0952985d3c3f45bf784ed961a5fe4a556a9f454d5c507656b6f003bf9ad04114401bf789668bf3da53c1370db2baf091f4a1f7268b18c927e1ae51c0fe8a496232340abb509a9b22651c22e78d673883f2c7d694dc74f792744b21743c0ec006321e0cc7509b7f2ee131628a339305a8d8ad4a2e80838ece15b0dc4b448b53a099a63ed72d60bdf50ad1f33cad097e99725cf0bb190f3f81f5d1178a8fd8280a081537cd98da4b05ee51364841c24799c9a44f223e01495a69ce4616c797a7b4106bffb5bf71269a3262732ec63b886ad0356324d30593f4a2d43e18ffb91e5835dbab4acce8dae49d09298f4d5eeff39b390437fc6d48c299033ad3f30f61da4e2fe1ee93fc0372f0bb3cb66f9fe07abdfc842413a581cd3977dfe8b905e7b09b40fb603d6d68f5d2ad5a85b1110b42a8e5c5ab3c34c0fc5c42cbba36b22c65f71be3112501937af978073b98b981af6773fe1d0dd0b940c5a7e45e2076a0de3cae9f703f10e7c383079fe5d10d331b846f2a7318c111cc00334d77213296294d4d21ab57b24560a9db246c7abdc17e029b5f7639b8db31dac18a6a32276a95197063072b3e39495cfb37f5e02659506bbea3a427c7c5a4a6c5f631075e6b5706617c09c883465e3c38c95a07295eea0e2d9e1a3e5059dad6a32a2e4125718a0fde19edc209bb40a7341845134b4ee841e94a2b0839229e64385f786b9342433025404a969a4fcfb159f03220ad75289ac8517119b0102dc25f88af4a82d3d76a5299a86e5311d6e1d10417291aa49f7958360724fec251db6923b7a98b14c67db563d1ef8e78a8c6b7de54dbdac108e2992bbed6f71c801e20b2ac11531e405235d2eb89398aa1b25124485eaeebb2f0d89ed81fdaa805bb8545802e6b6dcebb9015b898d5017705451f49af0052f07df1f08c5011570e5f43a2d7ea6f631e31043897787599be70f21109fddfba960a204891a06a7acd97c08466e68312e6538595a30fb7f08504f4f37e13c570c2f11c53aaf5fc03de2568f52135fe7d01fac036887fe35ba74136a76a40dd7398adc2f1965efd7c1f6876aa3d26b0355d136278c76372bb5ff31d46d70dfc453bd23a0a0eb522c992dc96ebbc4cb081002d6400d34379f67c2325962a056c7103459e3270e84249c868047ea22beff1b30aca1f0122a993901b84eac430552f659ab57b9f790d2c99dae74cf0cb5c62c08dfe5aa8fc7613a4e99f0d73f3919e6ee69c3ab11bd80e4099a41347bd7360e6ecedc8c9b2fba09ca1845a23a6e67d15c18999ff8a2f5461b8cca8942473c10918a4ff72176b73958a2cc8d0cd3c7a9d09fba82c8122bb473e04cf87f21689415b0476b434ee08072b4fb0c585f642cd5fd3e4e54f2a9c1d54fc0ac4ec9db3893fd9d16438f12c19cbc5d0a97b054eb8fe78bac60276dc7353784269d126baf14627aa8bcac49a16e53777b8b3e1c1a67939258349c4e8c1c344710a68410e50031c9e53ce8ce6705fe7605a8243fa53eb4490540f72cdde7c63b64a586cf6ba131cff09e3186584900af5d2308cf79a3403e7250eb4c04519a7237cc034e976d2a436b626437630ab831f0ae2c6444a5c8ac7085ffa64cf724b7cf21a94a1c5dfa27d09de98f770ce0c643888e744dbcd7524df45e0de37a4f9fd11a9ca6825dd9840aa4d75f032d5889eabd300f14bce6675c05e3c829ef9db311d1bf02171ca7365e8d443ab1eef780b32688fc643ecf4fa361d7fdc16a59c4959793e4b601d30ce411a9af9b69b5cec50341334b489238c950cc9eafd19f4dff16f2bd8a72e6800d9c166b57e70accd32eb68e7b4f0416202ef58721040178736af4234761e6ee0712313d3ea7a642563131962ab896a1004ff0c12010015718d9a364f8d46a1a4d4f85f74f131860baed416ca049986428332fd324cafc87ae354618525acbd57c41334f0c5e26d85dde0d9a88580e61d7a627982c34baee5a4304cab536cb999713763c7d249457584009eb10c1f4726f07ec216f41258f248255918c9dee2109a54d51a9796c1b81d149edf8be976e1c707459dd1b22e4256c8102c9fbfcc67ac2a4f285d57d830cd379a7f0f94de347df2ab4242755027e66635f8ce411ece92d0722d1000af0076ab4ff44c4e9e76c13ff3c5df1a0f969612ccc484b991d9052acd55929d3b1e177f0731b933b06beca0acccd82797e46485855250d42a173c82f207ad8275e6c46db44ab2d843646a4274bbf8a8cc3552a1349f78eb","dedup_hash":"23702933538943712392","vp_signature":"02f8376bbeb6642f0b508581a2db3a771936972bf02be137a644e96a85dfd4e134959ab486584071aa7f25801884d382fd23deb03c8e1cb64334468515ab3175919bf71cef4d5bd046806958757c4d7190e879501a74cca7a7e1bee3fab549673e78b2807043b2fd0c0862325b12cdeae23dfebdf936e84bb0e73136080fa229faa03061f6244b95bad31f2b9dafb351b820c26ca559f62ded8efc44b0533ddb8ee4bc690db12d2fd243971cf46315314b29cad505fa3c7c472aa739c6534b9d6eeebec4f95d216db60320afd713dbbed3541e933ae3a1fa6e88b6838e3a0aba7579771393af7d93d31861f05fe7750eaa8a8ba330f792d3b9c339c8fec23c345935dee069bc4029b3be6ccc59d9d4d00b1f7994197dc968fbc1b93beeaa7df3faf7f0fd1634e7a1648bf5e64cfd5d98fa99658178e7bd185b04022c4b05db9b98dd9db7d2433d2626978c584c5235857440259445dfb7d9893388bb751fe7efbf1e60279d4b37ef2cf99bc43d9578c597125545b70feb1f4c5b297b937af8e511dfbdbfa2f4433283c3b99f03c1794bf988f5537fd05bdb5384aed6f581dc19be120925c3a64c286bb90745be38e83da1b0f6c0e2d7c130572301170e061f2a80b78e5a0105f4c735da227d7d3094eb51d98495971583874ff120c07ccd987d8d8cdd21b95248560454d22c6c71a54e9c9345164749a98eaf559c36abc5dbee51ff8c13bc62dfe5add635a5a56c1e397a5fe6177235c871350d930f76cc6483ccf0694a5446c5615624ca7345ed516cb5890b71ebbdbbff44b9f0d3174f6100bcff7b0dd14748a7e6a2a025190bb0645465216fbcb4e5c89361b807ee64943451b902ab80cf18146a0eda2a17a49aee04a2d909e65d9e4ede5b0f66eaac20fefc5f2c7cd46a460700b6f56cfec7153619c2e2599ecefb6df4b0add8b174436045a6a3e6956935e18aa791f668f542e2936384628908b713cf9baab29db32d74d0ff6efb853c15317a6b6b9aee59320492fafb40a70ec1f99e828bc12647010997c720180baa1f72e817b302942c74069606176ef6268afcb7ac2924df14c037d8ad4459351d9feb8bfa7be428878b46e37d450fe14f6ef4130166bb78e991fee8cb22462f4448e455b187b3faab667b5abc97b9f3d4c66ca280576bb63c26e1599f5e381fbe875c0ef17990355113e5c4694ba0983677e683c9f2f6cea52139a3a1d669fb945b9f11d0e161446405f43bd2ef8a070930cc2e19cd361b969aee895878a93d234d30a6ae0fe83820d181556b4cbf3ab2fc941f1c4c5a916225a16b3cc753a2906fd117d508af52f3a574d81fbce9dcf784f36891408946e3daca9dff97b46e6de7d5bf6c2ac7dc4a245c49979d2fc7f452c3601392b3d691b033da37088f6b712e3de5bacc8ff0aefa22f5e2a63b2aa64a649ab833370e6a2eacbbd9a20406e4fd59900ba56a9a9f49d7785c4b6bc5609be4570170805d1821c36887fec1792781913c7276d0c151a4956b9c6bdb23a8044d18785ae199348bfb892d10bf6366df33eaad044669dfe1d555bf863c860b7d3b6dcf090dfba5724a255ddae0549544a3fab78f63f2d387903fa3babfcc6eb5ac1619201ad017230bda922d8f2d08884d2e3e96739ac32eb01dbb00a3c4a6504057e5484c3bb32a4a7a38f36f39c1b0c99856b76d33c1f76e4d948ed131e1b76df234030ffee4cd50a054775ed64afb261f0dbddc5affb0c6f00a4940ec4389080f8a41198fdf7f7a3b222da02b2dd23831dba8440cd4e973b32a7a607744d9513083de7f2eb508502eccb3c721b19cb3d4dee9d91eca47c16b6262f74f639a7d27945a321b2113f2c8cb26e1df266898027d9cb20cf65080e3aba04056d6aefe1ff26f0c48123482f9cc27abea1187dc701658141afce3a65494b54d502e6fb3f20ec819940c26ae23198059bede35af52319e31e1d46839572dc92f6cbcb93bf78a295e3eb7cff8ad2537a9bf64e2586c877d85d6e07496d0201c86bf886329a51373bdcbb4a94228d6915f6db497122e9e5da58b7a56fbbf26e52ebed3f347f36b2b08b95b3664ebc17e139178982d50e27d4a8d6774b6193ce0408ed7984a6088c38bc223b71626777a6693d99bd0272073e596244891f0efeb34e4904d292f65aa80f1e8852c03863d32483acfc485699677f57929d2f765ce5576a92bcaabbc9a118f3b7e832767ac51126ad156408709b6caea18f6d726adfd33fa85285b1347cb35b481fb99daa71fc408ca8c6bb2cedb1f269b5ee1553b364afc1c537747d5239841408a8847bca2e3d410efba3e2bd6fd3cadfbc15587e983a048b43553f80fea118099a99af8d794ca4f4e5adc4799d72af4219ef6a03115b525dcd22ddd282c2f7eea1ad84f5d922d29ccd0656a9f10bee24f2e61632c2493c90a74b848defdac03c57afb1eae51725a5f3762f24b7d7e8da24345a2eb071df221b2a98cea440d6914419f92edbdea63347eb43b1955e85686e091dda1f70f2c8074897d96bd3ab5beef1634c8e844054af42946647e6ad95cb5608754a58b09b188239cf421d391bcedb38bf0351b64f2a2c11b221714bf49add0f87c5ba02a658321299641b36538f01e01148e1d1c01ec3755866262d7633de925e83e648a87af93c9634be28479f515d36468da61c2004add051f2f3509bc9f1bc4be21fc92f81429265856b56c68be242ed3b4242dd6f689bc520c4d8cee60219a34ef6f9d1544211b0b28a758ce10c9df4cacada5ab6f173f443b01a4f4e097e3c3f23149c25b874056cc0cc8c097eb9959b23f8d31568fa983bb8d15cf000ca795c21b35ecc4d909213080e05334ef0bff8024e65562d4947a903b1cfe27efc87d8e93692304207c829e2df5ac3102558441743cce138fbe8fc9dc32a7e1671928f921c47fc3cecd202afc51c70a74ea36283d5d3c0cf029e0281f28eb3813d2cf30f57253b23296fda5413d91f297114f545c4d5736d8800ef975713e71f7b0a3d6e6a3497a95389abd639660523e8fe7e814a3fd4ccf0a8beb6bd197d678424b92b664c26a23d630f81556b3c0044fac1f48338d8a11668de4ac944f6a7290f6eb33cbb54ed0cd0a6d99159a3ed0fb25f8d33b369a47782daacf354d58b5f993857b1285d7cc6577dd48dd489955b0e314b9b5f283b6842b134348c03d63e287be6430f825abdca8cf498fab39eb28f70ec3c335ade602b20a774d7d693cd5793932fec4b506ea0145ef2d68246f6078da64f557a58941334c1edb52c0be41d8d5a926804d2462d2054495d9e77f555c23e6fad30fcb9668213b7f7af5b9b9f8801eab08003bc09b92fedb773a37670898e03270c28288cdc3cc1556847600c47dad4ee22c2b079f9106cd2b72f214306dad268b9657b13e36328fa02fe049d84a539a8c5402de566189b3d9077b5cfec9f1f1f28c810713c8a9115ec35ac5afd51ce4f3c65200af9dd6609587dc856a33e6618befd69831df69dec7ddf1a523e34fce0d86f4b4f7264f45d56bda063026173237e0c4b28e88c9ca9a6cc7d43d28e97a7fed1af8dc449c2725ad9fe57a5ed7acacee9647827ab4020f91382c1420fd931124696a36cba900e55e5e415a39cc2a5c4533038de4620e088a1da96c1be6564cbf4cde7028222991f8f662dda325b17c25fc61eebab6e74d30fc78dc31776ec33707b13245ac59f490f2f760023c6a220a08717a3ff0c0a5fcd5f07801496e75c092cc8f1370a8efa8879773c1a1e80a186978a4c0a1c27a0e8c68e266d8a49c5e2e14f71ed608536f203766a813aa8d677b84af25d36c654cb05d3080854b8f34db5750412b8a0baff2424223a87d61e05f93b21b195605372c2a084af9258b55937547eea3162dfc36aeca40f60ff4450a7803eda2ebeecbcae4d3c747dbf61a52a05981bc610cfaa160a462936a6f7c1ba926f9c0152b66595d444e6ee6c96124290ed3a1429d28b2bf4f78aee135bdde425c283d25d7b1f7d9243416bcaa9640354a536da76244ddce107f45d45699c7b7860624dea6d47d65c08067a631b3ab66afe2fe6f94ac492a492a35fdbec1167e30f74cc244f70a3cc873a7ebfe89a1b602f41ae64b273ddbeedec319b927a0400808c20841b8a132df4e247456b7db7285b788e828ee629ff986a91b2c5c530aafc9937901b2e5235be594728031bec09b7c4d3ccd7fbb0c941e849c597fe5009f4c4292a580a14f12046e48ded0e754ee2e2aabd3f7247b7abdac32325015b2d5abfeb6aeba8751e52327a2cf8747301056b47f8ec651f1b26c9790ace9544b1c3ced665e513d7a927f3b3006c2438d6082144c6c3542bccf45541067a2f00e5d5e384ec4956f5b8d8755308f7400b75ca714e81d1e4eabc4d0712bea716079b0cc43f21919515d6c8be713dd3a1336e24c9d091694126ddcda5d98b85d70b1e169267a9f64dfde39e34253e3eff41f2851c3c028dc09b9334143b6a2d3a8ff1bb371cea6c77d182a7605aed95bcae16fe53b6008f504d763ea0d1cfd3a6ac8c09c3b52c1a4c4cbac4da6b6f28a43268944820d6dfa7fd7f63f121c5edf0b05c4917de50d125792c5f5305b607cb7383c82a6eaf75b86bdccf8545a80c4d3e604111819202150607fa3b0b9da0000000000000000000000000000060b11161c29"},{"tip_id":"tip://id/US-5fb1990b4a3d859b","region":"US","public_key":"88a527395aace3dd7443f2add214671fe5c155c65dc7b2ec090f2692f39eede5bb740c14e029c544494b1402d1391d0a1953aa4cb65de9b8b93cabdfbe813dde7fd72a93ab43f522f6d7073e38ad38134340c7deb5598f39d8eab7b71abc07f344375d34a25c452fde94b90ebcb30f7d1480532b32e813e6d9d3cd83208d1162563fb62a3d6e6ddc9a92d34bfe72affa2ddbb258da84b7c4cd1e46da7e81a11e2b06e59070e48e562b5558965f0172909890a83da039d904108cb723d46cfae8ead9fc88a6770e474b9bff823217d2145c608d291400ac9a63a5b1178b883f294d0072e75eeaf5acebda4244d5546ada502c78bb54d4bd9f82b49f8b388d1c34ac9f1d26ec1dda3dca46eba1f6c254c47b42f2274487342ac830d79a7a7e5310f0062f5ff13701f5681cf1a598e8cabcfc203d43ddb3d29378c61e84ba4af89d30056897e12258c8d1dbd3f745e36d652eebb7e6278e038123a3d71ef8fe8a2c78c86adf337d58c763767a83f99a3a24dc9135e58ecc6d5e7ab82d0e99850b93739a1220db025f865f4ecb2ca58c8accbbc2806c8315c7acca02353afc598cb98dbf43d0fe4b0a101b11b7fca585dfe8b843970f5d38646ff5889038ec8aa63ba799287067292a7f8f76d8d1c047f3fdab519122f64b4a36d58cc36d49814536401df1a8cf283035e4da191ff0bbbb6ba956f3eef36d30d58b3649aeefe97a144db98b2be1e1e410e4cef093d1b8c444c9742fd3de2e44f444bbc852e50687ee401d8d04c0d77c6be1c5fe158da00910f7ab89130e7cb6ccc72680410239a674fca56790ad23617ff903dc03d8e03675476b3d84687f5f28049492033deeb6f6518851ec83e61940d4abdbf72f531424cbf9d7ffcb9aeae1cefddc5307cbc26de1941cb2d45099825311274b3fb28eb8d536c0c78fdce13e2ac02ee461f3f512cebe75c0281fa2027f1be98ec6b47ed60e52c6cfdd48c36e787e881030f998f81346bb2d1943a499d3e5666b0710cc3dd0595af9e93365907ff774c6d373ce9c6dfae56cddc7e3ec16556118a1583c1b9053c2663adecbfa040294e9c966cb4f5a3e2a5062a9d60749c337cfd23bd4c0afed0f89d1ec765609148ee94a90aef3be3f7bc2bacee44d736bea12a67775a80678fe31bf497b98acea59aec679e91468351dd6fc9de625163adfc74a985593fc9343f957c8e5dc7753543846298e9ea884a95f42e3f0217fe99da60b9ea0ceff640e9cae51d2b69733482371f0ce20272b696cd2a5acaeef4d24ba0b756a54adad46b7b105332638731f6adf1601cda72b67d6fcdc056e4bfe0106232bdcc3cd3a45a1af85dcf3599a9b009c622f69a9a2acbc611b468a299d18102e69e29648aa35cecaa4d40c83b64b8defaccc9dab2279d9450cac3c19fc2eda192dfb8a70e2563e5f18d35c74b054914c16ec093f762958292ee8782105dcf5349337a61b3385d4273a2312fd230a1485c197a4eb4acb0e45acc8acfdc152dce6ab7da366342e856118311820c8ddfd4f83a07234c59cda9f2863d8dd1fa108d6500d595431e09cf9647633cb08052e910dbacd8c6b6e89b269896a307aaf6be641360a6cf82907a3e34bf65f2dfc80c567213f4e06e6090691a16d5c879108d1d1704ace389883db4fc448469c5bea4390a5e48a92446a3a7ede54c25c228aff79ccb85b767efb62535f2aa8e9e14d8661b7773a834624aad2dadd199eb6e1c81f0d4e0312ef0d32ed5cfde60522ee1e6b5cd5e71d3ab89ceb177c1c0b83578c575b6f35d6ae3a3b043ca427087b522b6c8546a5849312baddd39b1137ffcee75a73f316258898d855b3e596c55818c1a7328385e88db28df5b621e42b13a51980a054258825a4046a9aa10778c0d4aae38dc24037b29c6f4ff3b762daea5fa6e58595f1137015e37d36ac2da376801107fcee1fd89ae97c49e3ab9b32ecbd605f7a362fea44ba5daefd0992e6336074b8b61e13c8946bbe51710568f5ab259fe330ca07c7f12681fb6b21652f614bd20de13beb34b753fca46da4b7e07ae1deeabf3a78e3461617ec12d42624b60b6f0115de811572836653f4e37a36b6ab9e71a4959bb82af2f2755b5d982d2ca6065958a69d0ac7d1f9ab642627f08d14d27402550795e8d931cc432265c70cc7df1d30ccb68bb013f69e5b0fa33046e43f447214351449bf7b6e75edd4132cd158846034f6e72dc936baab5b1d019cbe97e3d6b866caf022b49cca91d96234be29e62c83e98684bdf337fc5050e90b9f3b9f9d8437369e6f4834414c41dde0bdae146f7f5f2b6cb6d87674ab82005befbc4354fa839661d943c7961183be90377d1a0e96f2d778e78eb38356ecd6f1c7359c7e30ac2e0f1932a61d0f1e06f45a531582c260400bbc7c142b9cf573e726aeeffd52c095bed282b813ec795aef32c5bf99acda7e5fad4b9dd035f92b0fbbe551393e01d5f9f7c5df5980d6bee6b0f3555134b93eab17d123ef5f98ece46a2a3eb4084826723419d8f803060d6c92b947eb019b1e5dccee2d49642f2e9c8f28789e017356bccf5ef7cf46907984f304df1c43a7d06c9591a2c2b42ba3c2cf6ff1e5a7bf430d71f276019725939ba960bb0988c577edbf3890df483782f7ecc0ff3021c01f46cde14bc57c3aa7cf43dcd021fdaf37f28f7999a2e58bb39d746f82aea98a5c43732a867aefa9eba46165e1b393c2edb71fb46b88d8d707971a666d1b1cf39fc15d9bf25f72b78f4649e8b8c023","dedup_hash":"74146165765493969290","vp_signature":"186b4e3cf924a9a0b854f066cb20c4c09bdd89983495ef2e1595caf7b9603469ba9e1ed3c7d403fd0411bedceedb16304288367cc373cce12f3af0285e76bfcfbef703138edcb1905dd816e0e513cce7caad294a8b1bd12fe1a67b423b56754340373d578cdc1f1afc8f4ac895ef449705fe9007760f9693443104e1d6489adb7759f396c70e92f1e2285f0c591e2a1b16f9666f80b0f11081bd2393ec4bd1a2249880f71da2a45bd722049ede3e38303d3fa1fe77149f474de3e5f1138ffc3cecbe6fd657693f164c0c3ff0a89bd027fa570a2c43b6bcaa7315ede4383b5b3a9c2984e794a57b067b17838e157f8ca6feae5fb29c0a1f6c55f88327239b537067c7dc0e20b6d4a78f90fd597b11b6fac2fa718ea5e09e33d3a38795e9f4574f581d092ca0e59146834fe41bf84f5cf4158762933e56f1a711d9b0f25aee532ead5a37dfd8ff5d17a5b2023ccff18fcf357e0f5ee7acc09dce6b85d02f34f97ecab005f48e4a9fb6970a117b96acff9bbcde485d9636ecd15d1660c3fa30a5f677ac198d299fe501776beb9fe9898c4d8a5cbc212d23e660c415706a44087a4f1893dc0aeffdd81c9006510ff29f63be963aaa0476c45660b04116235f8b05d555c3453fb225aa7db8e049ded45ccfa7cc743618464666272ddd031e991e05442a70dbcfcb116aa9ca29df284a97811ef7fa21ef5aefcc87d367e1d6ddb36ce778729976f6f74dedf0806440c6f436ad5db082cc1737f55e14e638bdb0c2e84116e15cafd3d3e4f7e4f843db28a2efdd6317050ec3a03e4d47a92aca242249abb1d8fe186b1389cffc1aa15303dfdf237f69ff905905d5655edff4e55eb9e31c3245d86fe6f697c4da9cbccb233d7ee4a759e189faed58e97c25a60b4c0be456d3ebf864f8db0e5d313c9387cdbf8dc5c4d9bce9a729f9591bc2bf5616d4be71df73d12957c034ebf1de15d0cc652ee945038bad752d383a37a47ab7a1489677fa79e6a2599a83d42d6ef4aec6afb07c454851dbdf5e517fa21148ed6ec7de9d51317f6bfb229b13ac719b40b4592b8192f2a8e02db410f8f85f108f1fef50a446819747563d8962a1a6290912607e223b2bf5eb0fec702a6a556cfda162b50253839ae9147ebb776709ab8f45e4ceea8a224e322c27e85a7a3bb37719ce13407154722cf49268b601212fee2dafae35b1b01db590571491f363c9f4c0c722781276ee0103fd41738744d7d0bc18192bf317a484a82c3396586683678c78ebc3b09f1cafddb2e55e75f84b130138c346b980696d659bec6c667710addf5089cd2b08ffd517ba5acd7e67e5b3632c68194cd2a42565ae95ecd4fe86757c3e44e290d707b73ae0422d7936fb411c823e675ec6d6f1f3afd06f67f866e3ca2a9bd4129feed7f9df6c2e151ff8a5b3e45133d005f4c5208c107b6779a294721231746b3a0cf19a318ed1f6b2e64cc7e1714ee2b20a370ceca381b8553e39f63f600bb036147b121215584297eab014e69f072e9e589218889912f2457f502315aba98e18e2fdd5ef7dd5e6972a3b2fabf58944521ef483ae9a16341105e5376cd74a43392356b2a2e2d4319afd9d7eb009803da7267b351b35de92b5dc0ac5b8b76c525081e1c823cc22faea1751d9573ed1c4fb5e489807fa838bb6dca620353966c4982eb17db3373e108ad81e53fffd5450b9982434ed5b604aff030f5c4dadfe1829b1f51164f8e05079a83fa8334e8cda879984cd3f1e0a05b03209e055b21f97b66e2a56e22baf10f5a95166476abb5c14c30b8edcf743d7dbfc42817e2e716a67bf98540e312ea329caa8da6777f72ba0aafa9fa6c3d2ef723189774139c15187241125b22b30aae2d9ee2e9a7e4f9aa3b6707d55dc0a012d223cb9939634361c900568cf34c3e89cc7817f45cebaf5d834450de5ff030dd627ce97219f93e7672a12e32e4e95596c15d82f588fc38df5eab9c6de097ce0344ac4e0609fb5be45797839341ce21a1db374f51323698c790bf1c6f54bcd74b4b1e3bc6768fd99a779fff4015649be84789b0d5d6b17aefad15e45f4826766f8bf015c8156368180cd53f746d97a3b4804ddea352dbc2b66aad5be33b8326cc20a66d48a152ed7af42cd7a4b7c25a13f52ac136ecf51b4f2f1e15a2da155f349d99e6db4d5fa01ae51bce88a2edb50202419359e3bb9585c0415ef15a80f7434737e5eb384e5bdaddf6c2f0afce3b68ff81d80b9ac18e0a08197ac2b2d7f9ae4a1831fd9df495729cad78875cdc1a2cd790a913c8d4d79a01f119d7b7d3d2052f6bd129b9e9f2d4bbc9c88abf05bc533d74c1c617ae96d7b52632d6194e69fd2b1ea0242cefe265149506088b242c9e8d95c81109e185466c90f323dd1702878acba34f0929b5977695fd3c9ab5aabee0d2660a6f5ba904975a966683ce96ab38f236a68b6173d18593a55e90572c1ce90c02ab0a02ce59989086d56ec84eccc4147d5ff0a5f82789734b7c0981cd179acd60873ba3ef3a4e6ee9cc91bb14c4444f7d271ff79a975b2fce9f4384e8c4ec7c15f0dfd84d6ca54d298dd4fdcb2a77018e96229518d5adf40a0ca82d934cfe569ac7c0afba21182f0d5ed14bda6c66a8d5a944cce1037dfeedcb76a258f3325de4595c0f693e24ea7b6e666e6d06af9e98c85621f4c4d66bc4da4362a66448ac5f37a80a2b4f4a17c0fe52c36f8efc29d834852e8844cc43918cbd7aeee124c745fde8287577ed2fca8d25b426ab3cf2407b7704ca24e3ad5f60598d3520cfa551f4908beccc647f84b0fb32fe9c624a66438e957a38623de89d73c33533695e9d50ef368b80aa2490291f81f630965c637f696919f22a7356123e8d94fd38e42f0dc5d422a1a1742b9526e03a9bfbc76da03a9949b5eb538de0330c2d019c4644106d1e685e95ca67075f4b14df5649cf7e2f8d24538cc645ffdd117c0a4a7c3f62d885a39bfe2e9cfa6f99d874ded554e3d24ea5f97534f78e505b3b8918ff7585f855d7070b7ce7b142fc5b04dba03fc12ddf234ca4cf9ff6f440bdf7b1adf6dbc2ca4ed10dc11f437706f5ac21d1fdd5fcc597bc80da3be783d253ff0df8c8876419862f5cb51927eaea46c0b31f7187c908cc06f2cef7b492ff15a4f0e111cab4115777afdf418ab35c565f59e7afd41bb5223ee728a86020295da586409ab679a4aa9b95c3c29ead93bd77587bfe123782de16e80a07284158f93ecbf99f30587db31fb230c940c929b6929c9663e1d453a0b4fe907dd2d8b62e2662ce7b49c16d11a87ede2274ebf137c1fb971d0e8582ab258052dd520a140d93be007db95aee1ecd860402d0460c6154574dc37554ba63136d174bdc286c0d5385326da87331bd9f43256ad77fcacd47329bc255cf7c1ba1dd17f445e6f8c1561246a6b588658fa9a44d703da4d75f7ac88d315e7450c5ac1eb19fc864470d8b638b5791c0103c96c89567253be133052826fab7979dc3c180067d34ea9b040e66d7d4cb09f9b1b33936ae5d1a1fd5ec8005142bc2788fee598275d73b05d8de6b1e2768f5d5be41e3e47765a95da111e39b3900137c4f7ef349f42c4191ddb1b328a772eb6bb7edb368b545a66ecbcb380eac26574613d2998386b151eebd8a633f979e204956eef9b59ef68a30382cb2595ccca119a53bf3d607c4c5f9353ca85c12d278db130f4f2c5a200ffadba4ab3f516becf0e4a1cebba7190bfcfe561b69d460547c346d9ac0993f0efe4aefb9db113a8865e2377af910c569c92bb64bda8f40c49fd7cc15b5aaf4dbabd86d19ebd899f3cb866a26b3c62b56424648a1320ccb01e9a46f0afc4c4702d3a4a3dc2f1c1f558e69437cea0b1b6f4ae521d874b306c85e1538da32cfbf2885092c34c872f28e4725a73fe5338b22b232e90dc463bd0893812d9b2a184fac51f50da9348977ccfc3b58337a0cc40355515fd35a584258dfacabced41aebd51893766356f625319273be11b971925a49f6195de550c99ae69026da9b13404e91122b160a336a94a86d0f6a64aeb3103e3b94a05e023dc1abdb6a95067226fafbf1b121bf748bd48a303941e50d76c1e86e9418ac4a939569b9de7c4822798669e430673243be1530edde8b5dda49dbd38a5b44016ada58ff61b1f7e4679ca66aa99de968ca01b546e382ca50b5d2ba849968db2966d3c9af939ad8ea9e2e850252b77358d99fb64dffde81a3cce914f1e38585eb32dcee127abf94a2c375680f3d6655d5af7ab255b2ffd812b9ef52d68b513348d293394a01e21b74b0311607d941c7b675459703c95d37ae40eadaa07253e8187039ebf5181677a17f6b96f8bddee3aa436414aae2be4fb6db174cfd38784f9ffc206606383841a04530d1999d5709aee1d291b1043dfb5deac666bb5cfa3f65872eb3722389ab955033f9a5bf80b2f5792bba4f2dda42cdac4381b1016ebdd368771f91377d6f03100668b192c5279f231123a9a9ad547e0aeb41e5933e3ff1768e9697766a3c769d6be061960efb415304837355d2787dfef79bf0bef2d6a12927cbb3d4d5537c938531995a18c26280348e3ecb6cfeb5444368cc84e45c6809ff89e04266265b8d2fe16abb5f1060f146d8796989aa1c9d4e0eb3c436184a6cbd8eefc5b93c3d3dcdef33d000000000000000000000000000000060a17202728"},{"tip_id":"tip://id/US-b53bd091f66521db","region":"US","public_key":"e5d7b5ce98b472a80c6684b32aa687087d930b9a7f57854b689bdb9cb572acd814d16fd10fca40b7f87ed909fefeb7e6b60e5fb48f22927ff16c99d7506ad4801c59173422b05ba812d8945a478d3ec133b639e8c5c549182f26b6cb01c8e4c7a6282d1e8bc9d2a57047d930df7cb97a0a2d8b3ce6ff160f6d4a0a6bc085b6db554f9d2155ade2bce7179e002806d01fc5575e29a85bfa88012bbbd5d5593b535e41aebe5bdd8bda05eec58fb14f02261403cf7f057ec2f0fb7864ab517c134ea0e1cc125badb59911c4fef8c322af6ba5b65cd9dfe5775c5d9130a6a7c6a9df8fc641a4cab6831553beb451b9f9397a8eef2249ed5310a052004555354514a4317e3552436056f39f4138df5966b4d36e0e19cb3b0e3696985cb35ef9a3d6363c9b3ba7a51e23ef744c1157f889ad364a5884a7578f49f4ac3adf700df93e0d3862dad29c674adeacb53e2dc4a66a26a178e248151f17938f153e8fc37e48413c03b8eedd629d9564a601d1bb0663d9b1739421f778b0352c113299655dafcf4d7ce6a3a492307f089b9df9e730b69573522771febc867109510e72257d1f0dae541a51d2ea1981ae56c38e322f47257a8ba5eabc489d22c8db72513f9a42c852f418bb68faa951c2e8569a9c048153b24a18078b04be164e91e9f43f46127ef2379712cf5c0629c417ef109f9e3c42d6156d5543db4db4b3d93f73dce31de4eb8aa8579d8e896b709e3d72784383194ba3fc4f1683cb7127e94dba50dd862a556118322b8e29b1698829f448f553ffcc56c838d9414ba49ec3bb999ce5e543a97d26e6f1479a73d863c333482bf0d3219c8acba0b3b441a245a027c8e2d6024602f5649c5201837d60945c59c1e52f87208939eaffdb34a9a5f544c0458874a106602c495e46961f91e34ad685c3f460ba01bb10f8450557741bf87409359a1d15e60f78d569b82a48d294c943f72d72ada628e6830d420f73c5dabb9ff7661f9197996b8bf65204fbefb4a5714ffc3c2ad036646b2fbbc98054a15ac208a683ead4102062da20c70cde07016963b1578671019e5e128d8b412b984b10a629b18e901884a13d88fc3c95f6bc504ecd6169672d25051e4cdbeff3fb886439b485556fac9cb309fcc23a84d0a42700147867282b0f8d7b80db0ce6b7ed5bd8a051ce942a0b97fc99e09a1d6ed60276f6a5081c85c2bb793edbbc61ab6199a2e9bb8fe9eec7e397e30e670ed4059dead550710eb6c11fedcf52a0c36c2a471e7ae1d4c71f95cdb4f64ebb44ff34de865633bde415334019fe4fae892a26fa1216b2951b81f17e87b8b9c53caaa1fd4e6998440d9207718fbd73a9938a688ea155af1344f72a4788571fd658f7c21571039eb1f177ef62e72792f3de887c71c4338b6cdc96264869e9f610f02083a15c00624701c14ea25caf4e642a4ec1bf3edaca9bf86270fed85415e440b6bd9ad2cbbb5275dd9f3519acf7918fa984e764385381173cc628018d4a6bd721f8730f5efdfd24119ebca73ffcd8fbaee7eea862187491cd5c826199da86f70c1ba4c60f2f9bf3033cdd1588572e83e05674aa430cc79fd5fb4da6ac471eab6162f7ef7acf19dd85287c1ff8d2a1cd83dd868d0127292ecee2f4932184556123b5f41eedccaf5d2efeddbc525a436ad45df1ad36d9ef1d0409039c140fcfd7ae429fb988f5a8156bf1e87f4c2dd0837fd99655894898f898cd8d1299e27c6bc3b757cfbf3f31b66cfc555a387d110926c11609b6c8c812f28031914408059f78130f9d8426680223c2b83ca4a86d85f8d0d3df168bc8465d2a890eebe1c3fd767616edd174c3d9408d1adb425b0ada6f51756a269a7a31335d5cf1a55bd32e3f153032e2cc24542545886e3cd99f6113640e05b274a5a80d5a12998910b16d45c17157f86c8be9c5e1778067c59cb8d953954ad20f6c7b16c53f6fe2930bda303a1ed9ed7ca65170bf98f061b7680953bf127aed058b229448fc14b23bdf7e6deb2f2f0ba6cab6210eb953d28e45327a8b8a33e673d0cab0b86f8c201f66591ccebcbbc5fcf075d052a7a509682ce9d42a77061730e5927e869d4e534192f6fd2bc09d5049e89c03df2e75dd9681d71bd76d62ba22e0156e88af52e2945995d163cb8bffc5c78672638b3c913394646556505839a528fee416dd0abc7d9bda43106d90650a236c05029d62d37361fbeb274e8beecf7fb886f6763ac50cccbb09df832a2bd98f117d538f43ba0e57d05257690013b598d8134139254959e819deb31b5d8050fb6f165915fbe12639f043082a0cc4a5560326899ac47bb99f55bf319bbfa3206d02a31d6c0eb9f6466ab9050daa65fa37a446687ab9ffa8cbacd5305126908e3798913d730ef885c6f23e067fbd3948a60171c69f40b211851123a31c5a07c716f3b07e684a9841a4ef6d533a9781e457aeedfcd1c582e44a7a02a4be22ba5a0b25cbf173d976b914f0863578e5639c857da2638b482fe6076b002c7b1e73acbad6ad0e84ae3885b33aaffb2a067efe1dcef174e1ab1d0c98c0485b3312f9df6195f29f5006b35c399b222ab086d07035655032e0bf4fada1121b2c2414393accd689f1a3cbcbfafa825a02e54e18430f188e9ba6f2b511a1cedffca6df8bedebc5a5cd0e5332125d11ce2f490d17cd3a801eaedb112be8f660eb5889a80b71a4c2b87042a0aec0cea1e721a305730c505e67e81be3de3dcbb19cd50ea6fd6744a2b2e8053b0894b6d158751b84ba","dedup_hash":"70044443154882484498","vp_signature":"c41112b5892d401b411138de8fcbb316648a78509583a76f8d222cf731842a25131e671dcd44764fc453cd11b0773c336591bd3adb92922c10df8afab5d54c8865846a0e8ce07a6da388e0c344f6fadee4ed500fc64244a434c7f226c9fd95adde826fc573961becb55bcb4ceb3adbea6557fe89986aa0fbf82a0ad0876d5d388d7d370bba575ddfff5d62a34bf1c2163551ad655469411d162d1363b74cc65ca6825ff47b29a76acb1c13043736ae7e829f8112ac872acfab201655fc8a9f459016028073e91c5ea617bdc275335a7feba93892970acbd484ffe660a8f78721a42056db5e7b2fcfbd91ef4e10e6c61a1506f7bdeb121654f986b8627c72cdb4181d9e39ad700da65e32fd023d1a6961d98e62a12bae79cf3216eebc664798f9d9e0941083315393ec4bde2c926b3774e619d30e471e5dc9021c394643781935cc27594ef6f6a8d4c18aee5f60dec05cb8357ec165692e3e07eca0c43ca09aad8a66b752b74e6f88e3764366fbbcb95702d37156bce0e5a2c26d6e630b48806e58928b4a977ad25eed8af98365376a1f463292471430b8c42f82e6401e321ee4851fd87a721b54164cb9512a03bb8b9933285474f8dc7f41456253bdb70a06678b3318dd20a19a109954024707e53cf6106f79c8d4d3dacb94f28ee34c0e49081e7fe670e07d5ceb94e41769836772319e6154124051d66b3a5e6d5bdc3576a1e50183ea63d1a0e84ae5f23ba0284a8e9f31df2141ca15546d7d1485cfafcc5f43bfdb61b4f227ba96dc4287f866c83c4bd34060d2ece0dcaca8173ae55674e482b4ee337c4553a1f1cae6efa80cfdd705074c3057e7703ab1b9fe0650a3f75195b285e8b1d8c7f9e57f0186e3d7f3ac9472f37c9cbfc5bc3e22634b748de2f98a1c505bb8efd48807646ca950ccb2b4663fcaf796e4d1fbf35d5312343a4216b3f2c1431ac5de6ec1f8c37cc4c616a5b6af4a392a2589d087e59802ebcdfc052319c546ce8be73cfe1896ed2327d15f2024af4fd748635b4a9bb52d6e927b9ed912db3bdd62c37647599614604a5a584d3b19cd10b05243fe3522209e7ac42bef6e81b4af1354a8803f0cbfd17a36304ec56a9ddac21ed49c3c452304f36ab1c1b6e63059ecb5cd60dd7992be5a8cb45b6cdf1e4af270bc25d24e50c6f8f08126bfadbe21380abdb1b33cf64c0efbcef6e7dde5175d0744476bf2b8c91a671c76c9a9c64a993b0f9e303f32cf9d64b0ba7f9a102143df5e9363410c4c93c7b246cdbc87d8f5dc6428e4103fe608d10f7c52fb1e8f851600f7e8e6a407a23b4e41d68e85d324995afa80e77c810125ca10b09bd2c85be2dbddaa3bd013cfc93ffb764cac4a7fc046e73903278ab59110ae79862308277c8ec78302a59ffd879130eb7b50c644e1d18a3036f0d6a88596c9f56245a1d9bba448f40c0b628a953526721df043ac7762161ffb27a63d3ec293e646eb3ed79c1234387ec2d51786f2d75c02c3bbfdc5baad3eae6a51d52ab43893f1787738de134b84e42154b1723ed392fdd76791ce0067e8db92741c25249ec15d4018f4df6803b5fc7dd50e929a13cc5eee7222c9c07bc1b1b927c467572bc837c2d611f201bcd8e37c5960fc7746a46996fed63cc34c723b3e6bc3f3db3e29594bc9e9496737a1775fb395125faef54a631c9beb650d0e0b0a84bfebcb8420ea9ffef7502d3500a92524ea6367294bfa21fe8649da2da7a857de3ba0356602f025d62522cf7e296d87cee16275cfd9517b3d7fbb4f97f4529d647f2b12f1b4909e3b5f49e234e83c5fa38e268bfda903301f2a6465fa198d771d732feb6a9f5c97c29a741f314c75594f15c502f06e5cd96f24d61209c79fbd77dc710027e2d977f10b3e58e1625348bb54b34d6ba4b02769a5fc3d0a77deee9f5487d794d978d25a7978e68db392c527dcce16519f68510fe730b720f10e3b705e94dd335628d7e4d49536f05e2886cdef37bf1e52f457c5651b327dbebbcef6487e99e7f3fff59c5cef4642f242193202271cc613bc805d67de2106bc1cf0daa90e8ac7f5f2cdead16476ff3567195ac18d8040120c927fe384dae09ca39a3e18c50286fc8c32c1e762a5d86bceaecf7677dbc1b3e8d094633fb185dbc465b3bda536ef3c9cfbfdf4b7b77b8c868864e4ab1a4fdfc926583ead0ac46cc207f7e8a7cf892013b55b7ab38d59c424079f65f20bdc97d8ca018948829525aee403751bfd9542cb7eb7a5dcac4e1eae6426e1198cc7f67943a79690ed37649c23ec991478c72511c15c42c2b4d8e0fdfdf7a9127b76717a07bfeea8068282b52940bada22c5c22a2638f948229dc22a9ddd1c199ebf47c8717603ec5866aeb443c0ca1eda7ee4304e773384d48b456cc48a38b66bfcc0324f5daf7652b516742a3e15486b245bd426ddd081255d7feeaf055655f5d27117555ed7dbd50a80f9fba9b2053038cf3488514413805d9688212d8960497af6b1a787b1615aac0ff9d90b99aa512167288fb34a78413714036cc7375ddaf973073549af0a685058d588e9c65023af515e088407d07cc7e480feb1d6f9a99afd800c478f47eb6daefbc2f2721a7c9349fbd539ce79b9091bc215f78d0fdad9be275743aadfc7db15515d9af87e5e4d13ed3f83a99728b1cfe665fb66cb61ebb6e882ae020d366cb16d10ba88810022be3b72fda8089569a508990ce40e1ee149c94379a9a81f0fed9aada7eaa04e5082e397e26284256ac2e5a56f5541d3ae6c21dfdde26e9334323cbd2444cfeb50c15c5f1777f1bb9d7070a9156c53fa5855dd0656134a7a18bbece94d9991b3e52178efeae5c75ebf8d5af2cb826b772319f4d935fe2a97df10186fdd7a678ef60c5e2be4fd9fc45251f9088e3972750c2b110f2ac904d3d866283b4b5290eeead56cf14b0c0dc635258617ca2748b43298ac647b1800f271bea43ba7340a64f9f6b7aecbaa736e1ad913b350599980da771bc422aeba410b3c8aab96237d0a7d0e9fffa3068777fa7a4a45221149710ce1e97ebb6bd70be3f86a70515730f51ae9a2715f57a87f337d22b21f62b7c09bc407640aaf6ab421b96d16c9f63858001c0082020e22c8586b8ed1356fdf4e0a77b97c6096aa090fc41553e96dac20de01520bbc3c64378a3cef62e06647175c366337e39c628ad21c701747ecb454b9f044d025f693496356bcf61c5614e0711d67cda9ab2cd7db89ec292507e30624198032bbe44a0c53ebcc5a6966322dba3b984bdf0132efb20ab77ccfafdd9b1b17899155cee501f387f7829ec5cda6b04b73cabd50f1c0cedca978a237fc86d310e668b3a3fbf260f1ee890c8f6a2c39b85c559f7fdcc229b4a5b28a74f7e5193d112307a483b58ab428f326ebf4a52b76baf4f675a62e71eba7ac45bb30508437f23edcb0a70af51e9bddc4b1db46d015c054f44bfdaf0c9d99287c4f60cca79cfcb87540ef684cdad24794848018bff298f3d0b8e1400e197edb7577128d09b2fde2738c7fe028841f61a1f259eb556539bb6015d2f7d942f823fef5ba1977da682d6e1db1c1f72bd1910b9f98ab2b7dbbbf257e87cb1d472d6562a86f0856537e8ae41e97aca08f093e5155e67269c3b55b6acb0f6911e4de2b3254d38fb3f940efdffedb227ffc721fd97e1b23b3188baa8611349183970abda03356de94648cd00f0c0b812a83538f61a50f4d3e30945ecfbca66c5dc60714f44c348a6d61e9f850f030a22fe21c20cba88d851a3a4e4b88e25aa50345f8a1b13582d3bc66c54e8ebaaafefc3fa41ccec53f360f14f399ad0833367f56d08ad2e5eaf26fa62e0155d781149b074c77ae38518e940317f08ab23925f734807acbf6deb03e47a2069924a4c67162df5c2354cae41be3fc047c2c4e0641c99f2b342d606488fad4a18f27619202e0ea42f6c78e69553a8ff19988c2b896ce43a722c509e942a03f4b155836744a2bda285144b24e4d0d815e90814bdea0e040863937fece61ee53fb9b2e40dea675782bf1995acf5963b588229590cfa5c8d43868144a9fc0fa27f600c8daccee2d3aa9f240e82991f92760558463252747c0d9ed15a2b5d5bdf3ab08ec6d80ce2e6fb11a8ec0e1332887af1d0466a701bf10d83374cc5bd2286b798f92ee5b7e1b919821238eb1c3d53ff3a07d06ef74595f676a9ab38f8bf49fb89fa7835488c58b1f35fa703d9258d4a8184c79a44fba7be0f0972cf5029df6268f6c381c66f34284d3a112a482499b29eb329f9f9eb075ac90d1a7750606734fb6203ffcae58a86c4a0efda81dd832e734d2b1bcb996f8fe664ae845ffa555ec5e6ee57dc9d84793865578a8536a2c9deb2109b845bfdc3db97659026f2ba59a388b3ee47bd71e209e7c06710be34ea17d1750bcafa54722e103594be1577db5ce934d3c0e0ffed53c7fed405b9f17005fc9d3fbfb5ef441bc7a53ea4a7947a3f223b4af145613e4f7aacdb993f5ead043f568e10b720a8c95a058e891b2241e4dca4b0d7f8e09b0866a5d1cd59b822f065febe063306319ad72e575fab6685b96cf36d6d2d5c46731aa36640aa5d152fd4738f771b154a72c475b190a12151c1ebcc9ef2f414859a8b4d3ecf7fdffa9042a667a9297cdd9e6f4fe23383e4697d4dae90d393a4b5471b1d2dce3e7fd000000000813141f2733"}],     // [{ tip_id, region, public_key, dedup_hash, vp_signature }] — embedded by seed
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
let GENESIS_TX_SIGNATURE = "e9344ec8766b309a9968ec28cd80c3261e45d9b95c83d5df2ea8a692aa3e646853bf8242cbf0cc3276c92db9abb6c8602bf0b129eb3baad497a8df141cbb2cd503eea78d64f24e99357bb5f0c86f706f43826a37a9474ecebd749c7534cc74c173796ffa563f36c78bfd58aa5734e052b629ffd61f8f198aad77f8d4fcea9b0681c754ede45477170021a74baf55b063d96abe22fa6dbb48afb12aeae432b51a7c001cfd8005eb279fc655800c4bb7968a72bc640e3396acadf6c07611f469e036b8b8111c2cee9fb531f99707b4e4f7021e5f3168c3e14c546f01019b235993592ec01b91c4e853154e7546f34f45ecc20dabad3834400736735ed344e94aebcc14d82f8928b07f09730cc37185c970f6bc8a03c3a3dd8f638c323424909a6d6596b7e98529a3651986f729daa5dbadb23b09d9eceb8ed0b1adb2bb80d2ddfc11df8170ca5ac02cda7041547f74c4fcf72f5e632f9378db5ef2be43688a4905162d80f399c856497e9f5c5864aa8c5d3f73600c72f47f72554cd27c56eefe28dde61c7db685f5904a2d300a3f6925b4b06e98524128fea3ebd1de8dfb3da4c3ff05c5177748f71623bf0c60d5a79e9b8a65d8effa1870694634ee291df571efc2ec02743d773c5ecf4675872d21892fcd7cadc6e1125231aa2287f9bdaf3b7fac19d0e722d1d1f757805b35c91bfbc2e5976e10604cbc55383d936d17e0362b4dd41bd2afada659a98cf8a41691bf4f3ab4d8dbbdd869d0667424248d89285b092eb1eef43a87ef664a73000c1a25ab4e50faa65887280ada99e2657451bd7cf3ffb60f9225bf2e7350264f5fe2616d823f022533371e4619a54cc35db522d0830c5cd682f5a6a44b79d9a50aff147386f5ea202b0ca34f5c9ed0ec90848aa4727e3c8629efc51f675a73b421e69eb5ef3019d2569d4e8ef902727493da553dfbff5d13965217df734c235f13154118700b6a66e0f63a4cd0804f8235ef7b5665618743c86ac279104fb8bc5428ad100638b64f85f4dc7ecac034548fc4fa0e59c2e4c345402da82f9feb03bb9500eeed59742bcda1f2a91ad762287de80dd10bd35fc7f257e7864b3b8030f5a9137e892ff60b6ca77989a3aebdf8933cb90daef10ed6b88cb33f6ce8fabb60be488837d3fc512348f03465a4cc4dfdadaa3cb995f9e4c496522094de465412929a87fa609c631791ace942594b9879465f92fd4c192920ce40109e485d944257c5deeced02d0c7e8a61c84bb183ff1fe0f1e324cf7175c5f9e371349d46c707baf26157fbf04fb190082761e4fc0ca6a890170488d34fb12216b5e7a64cea58fac750a3064cd8006a2d9be2fbffa2bf5d3d6d07cf5a932e2917e1fbcdfadd27e971971ac1894b5b223a3a733ce2fdbe736dac4b5fda4d9d57fa5ac2e4d8dd5325d4f40f438fb06d1a3f5d8e9bb4a9628837e49994ce440b86ad9f57ce430c8ebd45a263c6375c74cacdbd1afd79cd9b2cb154fa2fc3d213e4c22825508ac234836ba83c1c14df93e0d84d7429644594ba19391eec8f081458882e6853025226b02b86316ae24f723ff33f8b1ed5d411668d76ec3a2111af628f5eb2a62aa962718a03c04854b197f31afecdb75eb7fb86f297bcdc6eb3ae671410928438082f0bca88bfa86a0c404d68eacaa055a1a74eae5dd93c95994a6b1a42a6ff598ae4ca5e4280e3686315dd8ce9b15d5b9afa4de8c7e8ebb5225c787068de1b1496f61bb5dcc9cbe81b68026ce4d9d866dcec8271ae983e4d000742af01d19df0f4db8c3198de8df9639e45dc05f266d08a3d0089ec14bde7a9334d77b50ed170bb18f02ffea9620231600c16af5b12e954d2d080b980930ce47322f1cedee6374e7cefead460ac7acdebeba29c1c241dad46cfe218edd49640f4be908e1a6cbc85bc26a304defc379d0ce7c766490d23652e8850d21879744fd6e17dcdcf77e04934e3515feb42529723731ae2e2e081864e1d86cda71da363d8269e2f5267b9ab77813711beca7a08f399cbfe38a3d0419ff1a4da3e8fe82024a02f3817dec8a0c0be677a59a9d5224c88a763b7e924f4d1bd870153d3a360be97678748bccc67a7592de201f49d6a590076ac3fcf2e620774db4ccc67c9935d0eb4ee1ac2e2b621bf551f24fdf52bf2c133fbf33b5f82255ada94ce149b28ce653d1d61badf6099f7ff4d664f53eb92d74caf483372e43612f98d25f91a13be7a1f0a328de5ae4a075dd2a6da5fc4a4a432e6de4ef6f87c7fd81c3a18355578024d53aa18a6e19d42388e4aeec4c1c960c7be897bcd1f17f02fec5931b49252bdbf810f35b9f2814f37896d93020c853368910d7b6d6efaa91588b077df3ab59ffb9c46892619057c3af186feb3d1cde4fd156bf537db95c56cecf7d971b5836658d6f645a56dae2bae6910c60db6c3fb38f445ab3be3a7934595d460714d2431c3a93812eda68721b4b18a1e2fb851dcef47dd310dd86df7749e78387f3cd8d7e5df005352281932e165b1000b325dcb3eca55d168c78636b359fb235b551b0389664311cccd2ffe82c00c50085b1f176a96e434f8a030191c5c3025ce3479ff5010f7edae2a60ea69d619426092fcff69ada574cfae3c2263fd03ed20b040efa15849d1bce4b17673d78a164e0178229cbc09e5bc025dae821e14e20903fec8facfc6e37a0764d0843cadce71bb5c6226bca5ce4f72cd510efe3b7e333b2350ec513b9f777f1634ca4b84db7d1d948f9584691cb3582d97b44b13fb8634787deedb0cc3274eb6d035403791b74ecd6e4f97a9ac724d2308ace2fec2de4fc05f9c816075f83a3076069fb7b522b14e1a604d8b80c7d4690d3df005d8a848f94ee656a5005962dca70febbad0362935e1275827654e9aeb4c5f47ba3915b49dee1dfc8f69c2c73760c485979e5fe0b016f2091c89aec2be756e9887d9902da5cd05bc511577ec4cd78be187cef4efc20e2f60762a6ea76974a9342bd972f06e6891f3cf28cb23e70d8078e014855768d34ac05897dd715246bf289396df5b5b0ce3b81da47b3d194622abc42a70e22e3f9c1df8f4949c0a84250294c97863724263d5b6e7c3a826e2a8ecb25cb55ba9c0a5f637ea50858332f57e8f60687eba4023848cb34b67411bc69a614cee24f32d4b5893c73aba655525fe9b6eb35c08a37f77002bb0f89e19e3d99a72a5c391b63bf7e1a048a6fb54f67d1955958ed225bcb30a8040f9413cf6b86aac4531586795f0c19b44f57967520a9aa2235ac66193f1a2f4f104b33420b112b2b4bb194faa92b6b9d425683bcd1caea4f7351a5e7b5d176a7fbb2a4098bc66da281b2a5ae211a9386e2013971a25bdca6478c809fa60c69d605a709c9ddbef43c4f4d3932a76128276c77e69f789b7238c0ed50ef95093006bf1e53905a570b7a20af896c7ff930740716eebd4251f59c911fa90ef132a4fbb7d0959a2e417ecb43854e0e3c058859b3abe7c544cf099a0c2bd48f9aa7aa25b824e32bc304cc61900d42aef256b4384692edabaec492bbe5870ee7ae8af88f12ce6f1bc92b4e0840fcdb883ba9f0d4b71371468b3821714049e506774595a71e591eb0ab70c6e23772e97040749533318de399ba72e007404e11eb05bd275466ae45ebe5394892aff60c167d568e53681486899a7a4dd3b73c4a36725e8f28bcfa33c1655b3a0846669d8caf052907e05e931fc14faed89fe55297660f6d082a4d208215157af269401fdfc6fa9b50b4cdd354018ee72d896ce84a5552f9e5d0c86eb7f770f1e9a9f4f69fb5ba19e91c32765cb68964da78be6f0e35eb6cdafea17030f2dfa67ab97686cf8de48e128a17395e5bbdd9a127b67cc79b5e60046ed4f62593eb7113383ae028778ccd8272dbcb7531666e3398d09232f69cecd84fb974fa3465bbba6f257971602f8c9a3cea369612610c1fdf06697f8aabf78fb23ac2a3c2f9b3c1fdb12d696b4f763ce39446f7298e3af9050a59d28f23c136e2a8ea32d6b0357d1370e6ca365748c20f01db25b393a4b5873fd94d789597728923afa17234321262d0e6b1e0944f6d31d33b2f901bc405536822cf2c6ecb0a3218c8c7c64e005642717141ff6505021bfeec278459baaae8a0b5f04f59c6b01e4a0624abe5a62c715826966203734890d1dc7cd5df9364f4e29ea23e633b785a74b7e62be619f542ae37ad312750379163f8c77fcd2085a970c6acff89421cc02c79bec0d58a5a97de617dff0b11a6c9803669779dfe6004e0f3eb9a5890e2906cab60c98795dfe54eb00c02846875e67774dd96ca50499a48fa2ffc261aecd9bd8426c35151824bf677ab28fe5f9ec9b05f8f5cf49ff58f73b6ffbeb40665c88879fc930bce3b7e7f24cef3c64a9fb929b16bd7a316ff0a9022460db734f3783637bd5af3f08f4e34a36036200164862285a0413c0a1ccbe3e920f68d5ea11eb95ef2aa6a8d250270b3916841cd4acfa7d47a82d18d9580fb9fdfb0f4c7a90332446339ea4162c7c84e7f925509d14767c4c9585ee0f349b48310c53dd245837df34db05a79c7b897a0a071b4047dc3a878068ff1ba913b277cb9beb37f6828e53570a05fc2fc48687887c2022938748299d4e8f81f2a41506e747685969ad2e50191f6023138a1a3b8dbdc0000000000000000000000000000000308111d2028";
let GENESIS_VP_TX_SIGNATURE = "94acf984a238c828c545b83b76f324794ddbeeed296142b7fca289b5f3dc631ec4630bfaeb407400ba8f02a627f09763b53fd66d954aed0e735565635eaf40eee23c78bb1120e85e189cdedc5a7f3c404cce444dcd5f88001ff36265de399d7bddb6478eb127def90c5938e7d27260e4318c94c50f868ee897dae32b48cf4c31bfb157c624852215db6e75d726adce2daff6658ddf681c65283a36c775b34cec12384ded8fe9f3c6986bbb91fd3bf5ec3cab2e238a04153a6e364d8f207cbf9700e97c0e774dd5c4f9bbf44f57bb002cbbd54c2921fe557314fc8a79df28974dd468f428b04e0ff26e7bc22d492695e0e159e4d63840e94a2228920468d253327e088d748dca00aaa860c6ba82fd750f098e8fad2cf1c0e7c91d56ab8955334b9c129e121fc24cb2876ae262f3478bfd3c161567fb9000e63fb507d47806b778389440e7acb32ca9579b4be9983508b98bdf480d50924f1106dd0e9b585c86e7de9150b8d6136966c580e8f62d057e54a8a75a5b64749da4d748b3b2aa330513d17f5b1e185fb39383e844dae4056f2764556eae709b1e273e60a32a9219fa54f88cf75e5fa9a0bd191c01815311676d2784f6cc82beabccc0e74031b1d8ef11b41e5fbfc91eb57164d18055bdbd4b3471013d4c747e1ab824f30c9f33fb394155514c2bdda326e589faf4a1e721c9eed42a7c2f9fb8783004aa4db9d4dedc2ea89698980fa7d39633bdc460aa791d7f4b8eecccf9d854a5016938a46dcd6b235e9b2ef6a4a5a4ba2fc879fe2fb5453623d88e37cf9f1d967623fd001231d9b152b329a9dc5a8161a3d3afe8dcbdfc18eff91caf7ddaa03a1d666b01b1e7c919d4626ccafc7446bd3ba2670d63faf23130b1b0b00400acc1a1bd01dc703c805b47974fc5d855c07b5cdae498d56789aa206caed52eab95c577f8548c7f5d2b07c2775be2e77f18e55ee08a4e92b7772226392fd0a011f122b874c98336a1357a7f6750e9b58c0fcab4e3aa084b764c308763a86170f6cde92068cfad8fa68a873f9a15083f5b109a08f488b617b74902c5e423c2918c7e80b365fb02226cb3512fdcdcfad2997990c7fb5be3e0a4a6c2e1e656543e5765ce50b50041306b20e4e500578d0afd596bb929712209a184c0abf89c4b071503cc3e3e324683fbee179d80f75043f077c0e1cd04e979e2af2cdeeaea45ecc8505583efdab31ef0ec20f913d337e7fe18817b90019e7eb6f6402c2a9ab69062b9fe316d096db12fb35e10d93e5f52fef60129f21a38f955a80ff9725595f085c805352fbc13908537f72025f7d89f80ea33c9773d7b0b22a9813e99c8d1ac40e0c4a029e8072e58723d2f2d723ce6657dd036413196eff18fd849353fb9191582fab0899e0db5eed4793c2faa913aad4041e0f17af8170e5afa379df3b88c61a0bacb689bdeee49c2b5e0584782f9228adb59f094b8b9413d04e4a17df1d647a0852a444d2c4db9f53289da6fc33404f30a8ec37d0d10be28f67f6578030d64f798aea2fe67318ae5f98753aca77840998cd43e507ca789228797f0f271533c2cfb21ea2520eb89edd5db3712423e907388b3435a6e6aed78051d0e68ff412c526a4700c75e8d51945ab5261e439aeffcfa3fd18ed8ece76ad65cd9db5d84f9173ebb8a39f228d2e97b8e819cb7b4ab0256561b4c3087ca922e6362b42e56c398ae5e6154041db9f88395d9f4caaa4061d6ef30a4e582ffe540755be304b2cd0398cdb8399383c7e280c3d8e64c8a07300b40230a4b6abdd6b2843f77cdd8e42df0177d0442f05fc0fdd8ba52d71036589a2b3fa206abbc8faa86f71ed2c292a5f36c1577f67857a31cd6789d465ab2a57ee8dd99ee457bc2f2971596924ea817bf2447f980ee5b0d961be8c595571c1400b58301144fbb784c5b5e3cd03d8415bc59c4b51b673b9aa40c89f752aa50151bc356547ca5f93516e52f5f8471210a0ddcfc2781c23ea146d104042dfd9628bb86591acedba5909f5c5ea60284293e54aa15d9136f5e02687def912fcc94cf3af4d9002dae3b4eb284e56f81e7f09e1e1af9497105c918a7a901f63b4cb6bef0dc02b37176f30f60743f4febef5f69b62ea5a871cfc2d17edce45d99f93e0d308835555e1e6e63d9915a2982a7e801f1d5f1369cdc75f540b744af728caa231edbb7d6d2c90b6e0aa69bbbde75cda5c8c5fe962d6747ce8bf067ddf6b50c2a0b78e612fe0cc69adc7fbf0cf55b5909b66114f9356b0e5efe6b1750662b13bd7e48c7bba6502ad26b1f3c20a42e7b2f8a82cf63911cdee2e351e22d1eefd12e1f6e0525caacc999360d8f6b502e5bcb4f0a08deaf0444ac98feafff092b57bdc7e79ef359fa27214cf9ae15a1783f54eab9ca4f0ad253891378356adcf47b55cb9191439116cd6b8856f754645867e5afb7e830b0c6c8848e0efaae703c9569b337f9e58067d42ab098a45f05da41f02aefa57c16df57923762b551d2daafa08fbf68ec771750478e6b1a563fbb88cc171bdcc491b3cb8204e7b6e262ef9f81ed87e3e53cc77eebf5cb8eebf526b3e5c588cc58f353e0159f436b352c3dfce74b392f4d2984056ca2f795dbeabda515db4273028857a82c4ad89a510ba80caec60889298a5c3d69b2ff3a70a547cedd7cafb372d8438561a05cfaacd5e269030c5312f57b91adcfb60589107ab38a3eb4bfd4ef605351d7b45a4e4593c7f08d5792c606c9d09eb28b8557a331eddece324cb09eb205a4018d236006ee3d26cd88b9fc688c15d59d92a818902b55a575afda5750e855370ad3cc65a633f6ef92da5a105e0f7b11d137179288ac0c2cf66414f020fe3b1caa6555d6b723687bf9d04475d9ccbd6b9426c2a4e44786141784865ccac827937437d54915fc15e6c74a7615a598c06193eb69cefe430b22ce8ae8e79379a4df1ced3b549af3d786eed09cdcf999110265bf73252e6f60bb53d68d9fcb6af6193009b88037f2e6c18bef64621159cb1115f85e385ae33e39a01e83ffb48e6ee15f4fef60d4296a2d148eb2108f9aa4b02ac3a35f8db0fd83c69a07435660e70edb91c18c321b4a45bc65bf9f8c220e6eb8bc2d979d00600ef1e492a0967a0ed04e6b8330ba2085b2ce029e2716c5ce72ad88f58d5aecc21c7e2cbebc4f6dc7727f1cc92abb667bec0770bacafdcdfd208d2955f4ac9f00a55f0c3feffe65e56d9ab98b299719a7d8a36e93545e70baa0fd38793fca66b060e25a0103cd9d4d499221062332b5d3968e6fe9c93444657d84f37525e6a65b2a8fdcee675356912917ce5d7c4f0218e45047b9d600d26dad29fad6014dea9e5b360df77ef324d87d6cc6f49b6da645f5deb3f29685425402e46d2620776c509287f48a9d9fd3191a20e595088706b9af7983354e9e9b5424d99f7797440aa58278b5439632624d4a34d040e102f88d83a3018c6d0affb206de0979b98d94bdb205d79319214ef06d0e2b6e8c92dc9c4c37c7002812202968ca382330efc3056f868ae429f6c4a30b2ffc81672b73f8ce52bd9912d947cee5f425ad18112c94fb2058678bbb42a09babe463c22b8f8118242c80c2b05921484643b13d110117ff16dd5b0a202c6f1ba88d359fa8e522649dc581a2c079c57a691d55e731384823427f1a01f9a6e1cadc5f1ce6c22497880d25a7f1f447fe768e3d610c6f64acc7556b816b3e44cf4def5a14357f1397f2afe628759cdb10ef4b8e422ce4e5dd659a15525ba9070d494f79e2bf7efb856fe535bda797b714e558f16927b4840fc54f5abf062dc67bede75041942d222db6e692355fac2b13abbc84aecec0a6ff5430c062bdba1d4a2afddd4026fc97773bc3f5035773a84146c0b107a22711b57de43cfa66e9603012333f0fcbf20c842bb7c5d79d30787cbeed2e9643f4c8dfab58150d38910c7c8e7a11362255187c8c83ea3fa95de5d07769a8f29e07be5c1467de942800286020456be77d802c718fb18e9ff53170b4cf50cff393687df75d8b495c2f33de87e7c2ed5068784f44f16f571e1d56bad8a41176029374cc4d06472b694e9586e5cc632eaf1f55641278f2eb2d7d007d1ab01014d40941ea3f42f9112981e391815ede551e3751a14b01f9331b3b865e3220c98b0884f975c79e04c2b32671a43ce349b7f02f3c8ecb7a18b4c1492d6d71a06dde46ecea4acf0e1e9be4b553d4d1b388f8e3d3e3dcba815f07d3e8bf9329aead1361504d7f7fab89a66ba2090109ef7b27e7be54f4794bf703db0fa28e632ddb7f6db89dc7914eec3b884c5c43719d2febdd1658bc4977ee52ab6b6cee40f6dee2ce31c699c43a2c2d556c23c3386875b0213363ce29a62184d1129ce09c046acd803a2edff2e26325423ceadbd60d559761262147a6184e6293273f399dcd0bceb1434ae6d9f072536df6407c3d792e097cbe59bbc534dc34edc1bdbd9310d9dfa0dfb37d8621c10fa04e8c19110ca7f65fc469a0e86382bd3a7842a80974bb61fbb9608c21bf983d8546f81227bb8351d84b3062ae54b5541b2fc5347b5fd94f33d2565712f58433086205ea8186844ac9dfd97c38f9471a2c81aca6c3decfaf1c7b91a1cad2d9fc141e32696d72aa4e5a606c7790a3ef376f74788389a3ccf0131994cff136555a6d717dd2d600000000000000000000080f1720252d";

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
