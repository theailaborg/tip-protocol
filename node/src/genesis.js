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
      batch_wait_ms: 200,                 // after first tx, wait this long for more txs before starting round
      max_txs_per_certificate: 500,       // max txs drained from mempool per certificate
      mempool_max_size: 10000,            // max pending txs in mempool
      mempool_tx_ttl_seconds: 300,        // evict txs older than 5 minutes
      certificate_max_bytes: 1048576,     // 1 MB max certificate size
      sync_batch_size: 100,               // certificates per sync response batch
      ordered_hash_cache_size: 10000,     // max cert hashes kept in Bullshark ordering dedup
      max_msgs_per_peer_per_sec: 100,    // rate limit: max GossipSub messages per peer per second
    },
    network: {
      chain_id: "tip-mainnet-v2",
      merkle_publish_hours: 6,
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
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: ["tip://id/US-c0e4e450d940415d", "tip://id/US-23feda24f9924319", "tip://id/US-ffcb19ea211e78ca"],

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
let GENESIS_TX_SIGNATURE = "2a11d7aa47a6c078ab6544a6a4c795a8f855a1c03faff842cb574174353330d5b962cddf89678f37d10599f8a2ab2cbfe554f2ac9396018274e9ef0144b5cc578fc0573a61019ee4767c67b1eb60afa03fd1a6866ce00eca7977d3b26ae0264ba3b491b5716f717d939d1264d4e1e1d94e3283479c873ca8838db42968d8215cc46487e3d34a906dbe0079e794bf500fd46e7ca2352c90a225f1cd9deca39cb6c6301a1414ea51644192db2bf2dd41e857e6a3568703c0069fd4449b612987fc3359957d684f2554f3ebe71bffdcceb73a2f6c054f28cdc417c32263327a12b155790c1e3addc8e229b98fc0dfa7d3101d14a7448d0183e8b3bb9fcf306c43350cdf82507bf9ed967c821cc821dac2d92322e08647dfe4abbedc7881a1679647aa5ff743932703a4f402c7fe74bf3fcc9566436c479b36a63cd2690d78cb4265e4d0d82e071a9d2607f27f0aa4b02d8c22d5bfc3e819d7d588910f3f77a373c74c1cda622510fcea45ed616ee1a307e14a56f657552c21319e92d0de99818247e140693de217b9c0b1a1f845d75315d974b1ef35ba2a448eb25d091a3cd10cc43f88acf04587dc0c0e7f80c891cced6be17f90b7697920ab6cf665a553ad8acdc13740dad5306a3e6685664300187e5a9e8d32e22aef8cfde89cc2b79e29c73d8f1d90f355249c6a5fce55166523ea4dd54ec17d79d3d5185a61404d666b8a338b08fb8a6f3cc31929cd9932c9a984b71df53d5c0fa1554ad2a3e9965cdb416a864c77b593d09d6a7406f1388314623c063dfa593e58a58e6aa28a2f503d2f81322541d1c77e984fd072e2b87501963e05529476566b1b4842e0eca6a4cf9a016dd986828f9765de22c13de724c75fb9df2f7969d2f10af6421a42249c905c07664c2d1687c6412b43efeb667f6d44201b2f83cb35ff6ba50ec8df730459935b2811577fab5e01aa9d0e799392151d38d8073d0c603c7bb47d9fb97eb13d5cced79ac199638a13414e9bdfa0a1a9c8890be6caf50948def521ae5aa0c06d01c42ba1ca026d31ecbf68453dc889cda6901b78dd9b7f97e2f1cdd0116455f58a8fa7c658e20a395230300ebddbfa3d3d83cd9324af363bf81919f45a321ad487a7e89e0e4b7cb051a29a57c59ffb4d0a80ef1b9852c02621664dc5f33c5cf9b5c169c2bf13969686b6a886e0808f35c6c727fc0b7dcaf02147f878ac4f247931d552791a2b6a2b24fc916fb2d9a0a434b6b665e2f3ae1501faf2be0be57a2b45a773178e4d2df0b4090f1bb97d29e4dddbb0aa03b2db15a442a81a4cc70ad5891c6ef4ab3a16e1f9083a3645b1b42f427451e57180a6b4ae0c9aee752acd3cc602b416dc0591f6b5ad36c2a5f1ae945a78d372878667a47e156c3ba9936d6edf29b9d821bb1d2704275212cd6b2b4cc5c5bb2da24b2e7931de842d6d6b9b8537302a9b97d1095742ddefb29e4b880a98d869ced8c9009c3d1c57748b0dace1a0d3647ad4ed53e880685a5eca0eaf22c784ed197dbd00efb653c6a05971d3e57e40cf7e04a6d886d2cfb7e13cea9edcf615bc09c9c43289cf30867fe739a1d335e5e07b86fb07ccf05e7f55c3a270c972d8ffaff0b776c00891dad28cacdffbc9cd28053c9bceea36d8ae976e959f2e881eceebfa69ac225d19845126aaf6cda922cc22a06f45e96f96ea50bf1febc77aa9606af0ee0820454ab88606d37b2f9233240abc13a7edce0bbbbb3bc7618c2ba11ce079a4d1f073c924a5695fe0501af5b98625e185896b10144660fe8fdcd948e4c9d67fa744c874c7700de7719c7e69a14d229a3650fc7676dba30e237584a7c9fd8bc1b071793e778effcf9f26730b0fabc87340bbb3962398cdf4ee272d65b572a469e54c82cc670236af0f4262111230c1aa8603990d11dd0554a7b7002a0eb5f58ca513cd0d44a91182954261ce16f0534090f41cb952d4fb4dbde383a83997fa826f06bd7b4c7ea7ecddbe6f037e4aebb1efad8d6812d934a25a9ada81f754677ed952b8e14907671977c6f022458e68ff833a793bb9aa92d8257f38808d98b2ce0abca70a6a768b1c09d19524cc804998854a9b5b679bd01106ca915d8299ac11b48b6ba9437d501562fd5d379b23ffc88da147e3ed011691bf74993ce0d29a7434eda0e817bc02ef1e5d2d05901e6cf7db8b0a27c135b9b1613e440797ddaa32570760e949cfb23e886574dfae4601a9bd0268550b38aa6c6934d722551f26b2796b2e4a59b735c0c4f466df3c6d145b9cc964e1741472abe16d547c3d0dbac344bc98968e2119571a8cb2b71b86efc21b0b66351b88042953ea79a6eb3dc3145d8268bd1681f8cf305e8299803a8aaa251f4085808a8a1aa5da31af3a9868aa630a2d2d062b1e71a99bcc0d5f2e93b027628682208702f41df8a57e1e19391bf0725150c4f25ffc85389ccb858449bed3564e30597d966bde24d6699b8610255a1ddef5ad49a8c22d164a19ba235034121db89a8e94eaa320eb9aba4844bf57db0d54121d3db545a17d15b3ea4611123fff9e373ce984470ec5b3dbe59a8eb4899dc41a4862aec13dc25e4211a099e0642dc4fd5b498c58893de7176350d0b6d39d7caa170d546a1cf0faced567bd7c2e0d34494cdddb60d56ec1faadc77487f26c3c61a1d7084ba15ec7d19eccda9f803adc245a0409e617324ec948f606d1348f32ca264feced982fa31ff1c90c492c9019e211f579b8ba494f643ee639c7fbc899621b02871e02ec1b548f0900212505e5ed18302fc568e606f89339bfc3360570cf5a5306ef9b90e33a187a1108630ea69f1339d499f026de8c38736eb905bfd2066e9a641b155c1c5a70525f282357a5be2da2354a76de06153848f543cdf34467a6d3fff43c17f4e2f3f457374e68dea490a71450d92c9e369c44d684f08fec846b4824495a8dc0df0d449c4044cd49aa9b846e506013cd3151ddd01045f06a9c77d0ffb201ab17e921d412ca292bf861fba52830999240dfe7d9bd7fc9dea83290e87ed5d385340b3d48b6775b378c54be80503260015e9abb75c52d1e6a0ff8363fa7f115bae7cf211701f3b775ee89c22e3d5d6f962a582b159c7e22e34fb86e2777a0a0ca73f5ef6d32afc54240373212ffef1f0d2246920ecef5e5202ab52bb7917e0e333c33175d635ee9548f07e124d001a222a54629ba939bed91c11b69934422a318ed9dad8e4b4d30f1d74aac98ffc7be8ef62c9f556a647bf0566ad750674d74d96c52e1d2bd663779c78d128933484102afbf9aa195cbdc96d671bab02a74674a3ea296f32360b0d9748416c6bc492b9154c7ff7e14eeda6ccaf180a42c5f7cdf22f53206fa6cdf6d1c23119a0adcb0e63b323e9acad574d6952d6fd2617e22c813a9723e5d8a793e2664d79a09fd3136aed7a1d8205baac1d03dfc758d9be529034bdabb47bf14363eac80396323aabef06ea6be2738b88c573731c45c4982243c0384f9e4baf4d77f22874f80b73a7bfa9ce4f717fb22bb9c1c8270e5213036dd52c84f85c72e8ccabeaa6d0782bb9533fef696cc41b75b659a462924c445d5002eca59b4f6a1d87909a97faf1956535b93874ddbc80a2151fc44e984f1aab3e0d89ff366e023f2336518e0093ccfebe727b0c88df23ab9e9c072a26f1838a12fade5229de67563d607ff389fc64bb1a610f90f2339d87982bdcc84e12b5cbbbdd417b53bfe2a9199d6f9a379a1c44ceb50a991d67c5c700592e9cee7ada4f9ffe1388bc5417206ee89e6ec2c407b91b316bb6acc8592dde8875157afb9c80481c8ffa67500e2c3e9a1d9c402cb88aed7d63a4bacfa4e9b81ebfa8b9587bdd7720b622553fe6093cb66a8c738d3836c86e2586d05f8f55ce00d72804418a9dacb6fd1cdaab4c265cc36112a5af5453b09fa58f99b8aae0d4e21c0cf9b06768781ec28fc5960c49c661ca80d2e348ada1124214effd7d1f70a4f009666393c12b37709f934dede5c66e75e778b057c434a4921c862e305c61a73ad47ed9b51566ed7b7d28e30f353db4dd062b1f3cfe72c3ee5c78f9b202d8124c714d15a70022fe966ce304f1689186b5ab4eb2bc23cbc9fb7cb7dd95cf4612d4dcfd28b92f4f225dd6bb45b6bb4dad251d052e648ef7b807aac25f52cd6ab5ea69d990d57123637065840754f9b5af0906d9feb7fffb6465e6ab6a56d772d4bee2d59faa12a125d73202e3f9aa645801bef973b9a65d4b522e6222c7234d11042a6e5097e9a66a8d3f7870aeec2ee4553192e78af2a7027408450a74a21f8d9b0ce0747ca86e0629c1629f6eda44b3e968d9c45d48b6a29bf2aeaf0137dea3121277dfba559a921dc66588784e84b961f48286a755e34348d94185b0a2876db666d3e8a947c6225a562e733ce283570e5fd25ff73c5da75ccd03bb3c2804623e9afb13b6d1e0841427c3b93c6372efdd3f428eb6a96a5c4c0e08761c6805098bad920e1c8cf76aba2de498f5c59e488f17a0c061053a6c3505d4947b23099bbd0e071c273985e704927c1923586dbc2da6b2224e6be959e91f01cdd77350db41e27c9e7f3efd066566c49f84bd4669dc5ff330952bcca911c476e76b6cdd1f10b0c243554566b859ff4f839416177adb905718cb2bef84083e30c14171d1e3248555d689195f200000000000000000813191f222f";
let GENESIS_VP_TX_SIGNATURE = "4ebfd770d8ac697253d9a248ff4f7a0acd4a5038dac508291a4fc17096e6344030719fec8adc10c9dbb1c022fc502eae02e638ae44c77c9cf94f0f1ec172dfe4cc18c7c17860343185317f9ed06cb2d711516abe4420bc621d8844ff10a65a7db898cf7cbf0339e5ed5c9898bfcccd044a9277aee5ea576f62f2e64f91f2ae36100ef490877d063aeec77cce913069bdf180063bce5a768be4e84c21442b33bf8d4204d2ea6da7b99291886b336229a16458497e675584a25815262eb048483091cab10e600792b559f81382038b30e30ee9a71f8ca14fc82d6b8dfca9045ec99e5fa25609f1f014346b45a8db5a7749fc0d23d22a9b09190f04cb5e49e345cdb0770b78becf73875b71b44e985aa61f52cbab852eec3bb5e39957fb464d6d0bb22d1183d24a2a5ed743fdd0051bdac9378dcc3b388f6c7c0aa9252661fc1c8e72a8b2c98a5d0809f6833f11e3130350de902b6841beb75f2088d5c354083b7b7c48db9f4be01f92f3b1e9a8adc3b16bcbac5f39a89f511608b3050f46b0cd5242b2cf8e7bf0b4aa84f5b1f5d42e0d69d4578c9948bcd2dca584eeb7f922e4795491f9c898446eaa1a94add74a5caaa3e676507716f180fdc5746df5c3c976d34a2e49daff6a841f167334951a5430d91c60e432b73916ad51073a8d6270bcb8afebec446410098b339bd9506fbca100f682eccf86f3368e6fff7b7c3e943f9acfc28fb863151e5e4d4e2e64f417fb41c163c3d2736e76c0f938de348f3d8c373a5f0ae9f10bb3320db36d5509dffb7366addba77f5b913056ed7b37dbc0d37982024370cb9acc962454ccbb9dc490ca0064e47f8cbd6fc022e5265c754151b11cd3f9aee003e478c052cc4642a5061cdcdffaa0205c12d8ed2a9b6b9027ba12f7fa72b22d5f64c472e4ae77b3ba946437e89a7f4ab813b8224a63cbdc9fe47de5876afcfe4675efc1ba0c945c37f0adc25c3722ac136d6a69d17f6a7516fa0678720bdb2b28e25c0d470a0d3423cc93b129ee31d93558ce70d8f71800faee204881ac0eaf7e8748f8801894dc653852e92367edf3bed9f6822921a103c2fbe3c95a9e82f015caa5ffc281fc9a629b16eb2ff598a996c84f737daeb2a117bf8656809eab05d07b8c930184816192c579216b28e033dadf662ed6f11cba5376f97412c045f277fcceb53ba7b4f48f2c0f7d1b6987362b9b7b3b404d88dc53aae0806d77dc4d3691bae344e106cf74644eff6df8e37ef9ffd144d05c29ec855880c8e5a45df9d4f1d18487280b5f0911d3709edab9c6cfeec07934dbe7f7810d2e93e9dc2de96ad75d475a2dba01fea08369fdb150b1f826b3bc1fb569ee340c8b02327fde027cc88dbe853d447a41898a36ee4463e00d573920608e19101f8ac548197443659e4f84a9eb2be4c08e940e51a324eb200084f5145f9556088098309e306619e605fcf6642a76cd44e71c0aa49b128a6d101691b762c2e6a67b7a51336f67a47c49ede28e215d2ee95e322e3f1ff56ecb15fb66da70bb241c471dfeecfb15609ec8d96eebd7f7bcc15fdb4823dcd990cb2be5f8d5e2b5516599af9c1d040a13b77fef1367b70e2a773b90629d209d90f6a50fa5b74c89ae7c0a2086188c510de39a0c5c94e4075a33073e68eccb1d9b18892fa14cdebf18b3d8ce7cee6b6dbca703cf7d9c80de756bdfeff63e432510c3274b770dc6c1c5f164c936882ff12280fe3d1616b4680dcade97dc13672a89590115ec6730e25a52ad9764f881fb6f4ba5d818eeab49dfbcf165da00d8dae23eee6b303a950a520e9202c20d793fdc3ff4678eff7924d85d65fd1200acd354c7421ac54b41b77c1736e99a816a4fccec2c943fa81949621a1f82e51ab9ea438ebccf237787ea6d8e8695e8f8e3dfe1d8132b0ce4f49acf734e665e742bca59aba1ef1ebb07b3f0c33c2bc995f57cc43e8bf5fa47edb91fd51065fa34357b2e3b7345ed60bfad115a055d7230a596acd03287f7beab43ff5170c8e6c893e2d2fc5e7ee5439ad938dd807607776eace7ff839d146174f2a36179e54048aa8982a3d7ef3ea83a7245dafc6ac36bef07ed2a8c33f508cd37fd4b5aa640e3737b2149f519132321dbd13f55655fda659d011af2ac5de9366dde760e71368ce57c5bf58cd53f1b50a77d32010c5bfba977912d02cab96ba603b0f7ebab302ceb26d8a3d1a0b2dccffa166518d14b0f0588e154e0fc482097f7cb373264e22d0b59869d2f6324cc7344efb72eb245bde85861bd0b455ec2f027cb7130868ad5d06240aafd009a96aa0a6e752b46cab5d72dcafd51d5e49231a418385c508672586706a450e6e9ddfa6a9e4d8fc7a915ed70e287dc5b764db0ce5b084b060f4d8c30fe9da0f588648da173bf831b39e0e335291834ac1610e1a8468785c5929f0562031a19468e1aa93bd3e9a6a2310956bcc97597441b95e09ed84f8fda74516de955f9da0638f649ed9e8c9ede62d47bb8be1ced623d97c8d359c7caa04ebeaef3ba6326ea4709affc2addb74a8449b438eb4771c23470c4943244b1c1a4f521db6eb722e306071343a7e63736c7c45efb81b8bd4090684161698d664d8330cb93751b00f3920d8e294279f8b0210299ff3bc5a64f48b453d9453f48ddab35118120fdb235a87997876b8fce04991319aa3c47d2471cb80cd24a3cf11995f88155622a4fcab2075b03b73145b8f7fd52fe14c4ee1e5ce3bb29d0ecedec2ba2f6110597d87a8dc50b2a86139b85a1a4fd1a4cffcda31ab20db4c79fdddd4dcd4423b23aee304f3e74d54e016f6fe1d06182cefea1a3a20eed1b53e86e83a4128ccd89fbcb1733840ecc4ad36b8be45570efbc57c0e90b81c41facc11b97431f52a840cc21b6a650606498e6d38a16e8e721ba378f3644746fb6e3ef1722795e887b95b378807b7c98805e655a99f1451c3713071fe7de9e88d684b630c80ccc36df384b999a965e6ebe74be7aa85a610795b9474a0f9a0a0e5966aa0c304ebd244e3d12ca46ff6289a8a16c8a6b353f493860e2d92c5a147040bd870b1f6df60ff72bbe7ea9138546579ae02551970cd7ed4e9c1f7c6e136f91f445a37fe7ac358a7ee6b2657451167e9fb849da0fc5180c2ef4698ad527468dcf97ab7a8d04d98896283ea9be02b11c0a7c42c75fcf80eff2183a5076019579fa3d9150d6729f641ce4b6c7c3feb581cfd94ba6890a3cf4fe7050fd668c79bc8dce7a1fe801a2b5d3f50bd7774e4853d441efdc5590d3afcf45b67adee1cd46f7a8fc2cf8e6fa8214e47b55e4905ee4ab0d39e4097f45dc6f0592e03fb009d060813e5df2ce9090d52ef513fc3198d78aa61c6c1efdc2ab1497f96be01a989709c63d298fe6465d91c0c7be9c409b9c52eb0026e118a9423a4c01dea8e7fce998a8061effe6e334fcc089c77853b48ee13d8b860ea2f2d55d18d85b9f01ccbde49f68ed4652adabc887563f0fe4b1ec67983d864bb6436c123d722e99f2d43c22fb383e50f247a580539946cebf7174da58d69770015c331a81b5dabe77031ec2293decc64f71292014a4f7f5e9a87e67c5fdf3987999bc2556f8f4855de19a55aa1a31c6a59b9ee58c18ef2fc669b7b751ce261198e9b512cc89e1a4c8da7315b2c676addf3963fb49ad109e9323b819fd7111f687d2398236520d930aba7160430ad2362a60497eab0cf69d3fb1b0448f744e957b8e61d5f1fcfbbe2af21b68aef4b83bda90e8c8cf0cdcf7b061c6d156140058d182cd5556353535c64c287778d3f3cdeaa027e01e162020a2f46d74480dfec338e9e730ba183631763608ec7c555989c6814fea7652e4c4a461bcc012cd8deb02d5d5bb2c859883f00265c18d87a161b6a228a65ba412bd9557a3931d6c8e609b400f357b640d6ec999935ef8ab521fd4e0410ece5f520deb22ce74bd8896604a7ca6cc28e989867e820b50813ada2570e3c91bf55d15adadf5156bfd74ac6bdd956f662478332b5e3048f0a267f4dde02848de9f089a6a1500b7c50e7d2c0c8e9524198f76808a1fe4c5e74d966ba1dbbf17f32fca313f6a19bb467418eeefe4d35f846fabfde4ff29f31de3305e3db1c5bcdc1ee0b39e0ad74f182d560ed93f65ec6b56faa6488da10f25ef2f3f0615ea271e7135c42dfb1f547a4a6254de6e6513856fb07bd1030588869bf0074eb39f24cccd255cf9e4f251029f7599a835b170ea44bcaf39c4f40a9eef55b7684d5adad71883044f9d117b1b6137a7f5e8a33393c5ab0fbfc8a657bd35e82fb78de30dd00b696561c5cfd21cc027958ee6e248e883186e70b8dd91ea0946364a7d23d8acf0ffb423e360937c53c1a35a1601608b427ddee12542edcbc0ee0296b151ad023f86a827b56347dedd5f91116ebdb7d30461a53323161d112a12a1216e1c9b2d0598deb4391ccdecc7049e505b57cedf43c00b77ead00f936c98d340e64c6c064b9c3920568877eea6efee11086ae7cae9280ff81e773c46083c8ebe3e3ca7dacc14c7b62e7e37092f0c958f65f0cb43c9e403c8c65cf40fa13857e1857bb04fe1263a270b156015078842d941a262e5a560f2e977407cc3251864d10d283763d9273e7e8de65787888a9aaaccd6e803414f6b8fb5e7ec233099bcce01455dd3d9dde200000000000000000000000000000000050a131b2027";

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
  computeGenesisHash,
};
