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
const path   = require("path");
const fs     = require("fs");
const { shake256, shake256Multi, generateSLHDSAKeypair, mldsaSign, mldsaVerify, computeTxId, canonicalJson } = require("../../shared/crypto");
const { TX_TYPES, PROTOCOL, ORIGIN } = require("../../shared/constants");
const { log } = require("./logger");

// ─── Genesis Block Constants ──────────────────────────────────────────────────
// These are FIXED and must never change once the network is live.
const GENESIS_TIMESTAMP  = "2026-03-15T00:00:00.000Z"; // Network launch date
const GENESIS_CHAIN_ID   = "tip-mainnet-v2";
const GENESIS_VP_REGION  = "US";

// ─── Canonical Genesis Payload ────────────────────────────────────────────────
// Protocol definition data only. Tx-level fields (tx_type, timestamp, prev)
// are on the genesis tx wrapper, not here.
// This is the EXACT data hashed for GENESIS_HASH. Must be byte-for-byte
// identical across every node in the network.

const GENESIS_PAYLOAD = Object.freeze({
  version:    "2",

  protocol: {
    name:       PROTOCOL.name,
    short:      PROTOCOL.short,
    version:    PROTOCOL.version,
    chain_id:   GENESIS_CHAIN_ID,
    spec_url:   PROTOCOL.specUrl,
    license:    PROTOCOL.license,
    issuer:     PROTOCOL.issuer,
    issuer_url: PROTOCOL.issuerUrl,
  },

  initial_params: {
    initial_score:            500,
    initial_score_attested:   550,
    max_score:                1000,
    min_score:                0,
    daily_verify_cap:         10,
    juror_monthly_max:        20,
    voucher_stake_points:     25,
    attestation_voucher_count: 3,
    attestation_min_score:    700,
    clean_period_days:        90,
    clean_period_bonus:       10,
    prescan_default_threshold: 0.85,
    prescan_floor:            0.80,
    prescan_ceiling:          0.94,
  },

  origin_categories: {
    OH: { label: "Original Human",   color_hint: "blue"   },
    AA: { label: "AI-Assisted",       color_hint: "purple" },
    AG: { label: "AI-Generated",      color_hint: "amber"  },
    MX: { label: "Mixed / Composite", color_hint: "gray"   },
  },

  tier_thresholds: [
    { name: "HIGHLY_TRUSTED", min: 800, max: 1000 },
    { name: "TRUSTED",        min: 600, max: 799  },
    { name: "REVIEW_ADVISED", min: 400, max: 599  },
    { name: "LOW_TRUST",      min: 200, max: 399  },
    { name: "NOT_TRUSTED",    min: 0,   max: 199  },
  ],

  penalty_schedule: {
    oh_confirmed_ag_1st:     -100,
    oh_confirmed_aa:         -40,
    aa_confirmed_ag:         -25,
    ag_conservative:         0,
    mismatch_2nd_offense:    -200,
    mismatch_3rd_offense:    -350,
    factual_falsehood_minor: -75,
    factual_falsehood_major: -300,
    device_compromise:       -15,
  },

  founding_vp: {
    vp_id:             "tip://id/VP-US-theailab-genesis",
    name:              "The AI Lab Intelligence Unobscured, Inc.",
    short_name:        "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction:      "US",
    url:               "https://theailab.org",
    email:             "trust@theailab.org",
    registered_at:     GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key:        "660433c07225c5e2838f8a6fedc3074d5c8ab0db386810cdfb2c39cba6f69588949a593975bf6d3c2ae253d42ede861861ea0f9f0f0e64368d5b9a3bb43605fe8e4dda6953d505981d60706489dc418c5dfeb05ce6dd5974bf28dabbe52475575c87adb63b5980e00bcbd7ecf8d2640e142b6199b9074d1738eeb6cf27a3ab0d1029a045e917651fd84b5212dca9fd7fc34bc5b613a76e7807560a0557fa910ed92d6d73a4eb2fcc21045107fd5c90f29fb829a2ffc2d3d3991d61de1168d81eda70baa0c63fa289d4da967e52fe4c7361b2fdb6a7237a4bec2e577864671888c98d010eba961b4cf6f7c08279a8dae7b44d45a5021f0f7e47c95c2da0295ebfd901d704401257de6f42a6eaebef84a30e6061e25b6d670b14a86ca9aa8d36e1ea20668bf1e8cf820614b91d5f9a3939716b41d8f7f75b3e73ebc8988b58565f77580cee0baa9879e6b9f07e43387caf6d1408b9e67713dfab19b4bbf6fa0096bf2c3259d80294386a171433853c3086e8345b267ab492e7bf2790d1bab4aaff693dd4c9551054282bc15a6a64c3aebd20fcdec61a405c1c8389017accf194aa83be6b70a18b095f9fb09fb7386214bc2577c9be57a4940f5f371486631e73f4ca9fd29c2bc04452e66ce777c21a9c25efea0b70c6e138d44f7f02a15e7406d5dcd9d805e97c82b8323c9791be44556a5df3b2011c262f4234c9f499c0fd6176b75bd7748c6b944daa786a5d859acc72991a69b2a5479d4433f55ece15d39f545ab3440bc90ffdf8ee511bf54929d512808376b66d59a0bf3c07ac555dff20b032766a8e290da4a21243666351c850f0b8450ab1cbef81dd2fd6ae00a4075c11ff1bcdc36927007bc7ef9457705bc7e0e421e27693bcc50aac8f107894ada5523f2c307510bbd66138a138d1a8ee80071ce81af820cf07247bbfe9b42c4fb7d4aa6515d1d41eda7d2d3cab300f671cbfd9ec8d6dc03a998f09ddb4335503c94b5cb859807262a3c8dfe13a6830caa93c06601707932ed7daf23b7dada29027e9cfbb06ddb3b94afb4b1aec31cad8a8160cce29657b905eac9612abc41fcacf63918e8268db4ff3db69eac0bd062cd800d1c610a75f603b0439f1b582659a8bedb99063705c5d46be34c08966eb627bd2caf731b9f6f975ef1d7304515172ecfaad5a28c5a440c7c4b0f151ca6710b8d97949382cc56a27b0184f0660f370e1d5438ac231303bdb9bb7367663e09ccc3241625496c49d7136e2fe4355fa8b7cd7a041de511cf532272aeb192de5b7194e707e45319159e26abf6913b0eac783ab6d8a95b7413212e06da9d3982a9161d2b38dac2917717d8b2763f28716eaae98d312a4d12413f78b6749cc8a448a82f211ff64d0ee9fd055d709144ecf372dca6bfbdd00b5aff39a68742fe54d667ec177e1a6212c6aa09a238c53e3c62aa514499beafc9e7e7d64982a513d5b5850eaa0a049cd8ffe0b83731adb8de34019d4dc565a3c138310cd511dbaedc76fc9862c9d2851cf62961924aab4dac01881f6364f14522c49381fd9ee9eb697a5acdb9d86de754cdde485922576674b2521b97750326969dfdabc6299a4d91e1ca0587a642f07b68893dbf82aa2f19fa0031d562eee8d6f741b1ec53575ade435ace041140ccfe9db65b353670cd45f6b3f6e52107df77599fc6e8df7a10ac6cadd501d7218bffe19d3a00e6f379ce7458660239b1acea5597fbfbfc457b566c96f5ab1f1e3103614a575af961482f37647a26862765726047e77676a78d4f7a93c8073e3b33cbda865aee483603ad031784b30f073d9da12e0a42750b5133b42a59affea4273080be0b0051589c83f2fa9e25afd0f7e789f24755eed02ac2012e0cade0e0d36e642910bbb680ff69e9783e4d27c3c5ca9ddc7dfa1ca29dbf778248d7ab22587255079694daf1d6ed2e273c6cf1de93ff73ad56d1af0967f86986e1b04505f33fd69b35b2332605e0a22e9166966d1b487aedf178516f44ebc1c084ac96350a3ab1ae4688e240749d401b8104a7aeb884c26ee1575e03b0bca6db4fb35866094cbd9b5122a34387aa2b477d9b0749e2e8f5bbcf62ad51ac150e23c64d61841bc440a38e0727c65cbc0f488999c8fc241cf83d61f3065e8cea565e9799b588dc18ebda7ff29bbcc94be7d6780dabb4e7091643b785ad773dcdc2cde8510961347b79d9090683adab328713c179ea27c6d5a1e0fc68699677968673527561b82d464a102fd3879f590613061d40cce2046a95b6b7cf93ffde75e062e435ef378d2adae66cc01c242a1155828ed138295f4ef75983cc4336dfe29d9b49c0252c8c0130a0e52947958d2e36fe954157139c3c4d281f0243435324e3ce595f81b27770971f27bbb1ce913205ff467898de13c97ba786c6fd3cf55575b18c0de6f5e3c9680b4ddeb82d1b35243022875af55c5cff7f08f34b85029e203d4e48c9d3ce7594f7ccfbb50719d06ded4488adbd39fc7f9e211d206b987482c3e49c71274e02e9fbeb4aabe14794199b2c4c314bec22ad1b28dbee72a1bc0bbc595e506d5dd029c8f5df44b23b007794a51ded22814d101f6fb55c4df51addec39dd8082e7c0e2f9a54c7bbc91c3d50fbc5411565c0c873a7acaa3f48889f6ccb60256a79ce4c5545c6f84e95efc55f67e826d4aa61b001b42dc1e897c1148b6852f553acf3229f333a1aa6c368d447a8084cf15c359a21f6e58522d38bef1f913e30cccd40f1d9b6793fc7ba087f1f8d82",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: ["tip://id/US-96bbb7639f6b5109","tip://id/US-bfd737f1516012b6","tip://id/US-86747549e257c60c"],

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
  tx_type:    "GENESIS",
  timestamp:  GENESIS_TIMESTAMP,
  prev:       [],
  data:       GENESIS_PAYLOAD,
});

const GENESIS_TX_ID = computeTxId(GENESIS_TX);

// Pre-computed signatures from seed script (founding VP signs both bootstrap txs).
// Placeholder until seed runs — seed replaces these with real ML-DSA-65 signatures.
let GENESIS_TX_SIGNATURE = "1c8ee97475f18fa0ac55d45a55644b0487a95af08cb1bc9b26b08b2152562054600af2904a58d6f921ce808021c7e572a3d9f314d091304d8cb13250718fe3bee8f2ff023c2557d7ad3ead37d94ae545a739aee95b0422c0bcd3f50732d647146489ab2a7b4e99b2f92da06dcdbf7d8fb5ea8dc58122f173fe971075e02288791566a99ef86bb35654c50df17ec8afc7c07f49e8eccf3a0937b3a281fb45e909e0852c5bf04dbce569372a1099382192390ef955c88a57ffa14362aee5da51b6dd484fa8196abff8fedddbf993c38f38110688e1a9beef746545a04927e4085c748bffc9f51f67fc8f6169f4d64aa589aacde22b2ccc56dcf16daf5505005f0d5e85da5d70bd951a2168a3bdf124f18e332b01b9df650dfb688c4e7d06fcc56448113f0baac86da0dc9a18713f884e32fd793e11e8eee1345cb4208880d31facefa66b88b3711996f251ec19f3833e60bd6cd0226d4c6ab171d5163f793972eff21889d811e1f7efd22dba6be7a9e66d868d1e2eb54931f4485f3e13715606cadeaf25e3160a0581b1d259f3c195d221baceb2ecce6484d1f3a3aae0ff9e5665a8679afc1cc6d9f15e63dc21e22f6f75370f0e35be9a88cc8a137071d24fbfc4f859b0dacabdc6526957cd33f0f6b8b5711efc48b8c2c8d6d2a8c0fbcad3c328e9c239d6b9d1375abae26a6adc2125d753273b897a3a229d00952397552dabbec799cd79080ef01a9320d11d018f2a3556af353b77c04d34fe7a3590d76f1953530baee062ab3750716ae40f7533d3521f10ece2f9219afc1bb0f5a9cf92c0e07692ea95dd02983f52fbb93e8231949a36321f7cb70227eef3843c89ed8f820541d996b24f7fecb236511b09117baf24368cd254898ada6802dd2cb89cb6f99217714b7cb624bd9099aab77e379d4d5c5ff3f38687dcb32f9ca4b5f4394d31cccc931649b920e13a8770356d79eb587e13cf0900a588ce39b100d7153edaac96fc7fc4458852d31deb264e894fb46e986e1cf1e565e5b0a61602297c9f6a14df1839a73412ae2dd28bf9c07a277b0f1e8df53ba61fe5711ec3411a13d4a67fee77bcb76245abfcdb336386220aa16ca2195a2d457525d7056b851070d91cb2c1b70a8ac3d9a44931da4671d638a1e96b54fa265e539588248403a09f30427c29727055d7131236465ca99c377dc9dd7536fb017e760c9ecdaea665a609f1899757a5071cb82f1327af40e3642de35430cbea72df6944c3a924fef30cb43b3bf87f14848fd12b962b5360a1b52766e521c0089deaad6d692f6c9cee6cbadbb3dad293cc263b82fb8b488527f76be8bdee4954bc7fa929d5eb8ddb56c0315730ae017f24bf5a62d816a06e81e0fcd69f22da158b178d7c3143d0ede4849abee8a732af48726fda47d5a250ffeb6e95c165704c039474d4c174adcb40485df23de904ed780ce91804593856602dd8c35744b78aa081df6829f70fee3f8e002554d241332d2b4218019dfd05dcc5b610d8d3dc3b5dacc5d4c7b7c9aa6d5ceee6936987a7cd78cf77dda4247412dbbb99f3885405922c27d5029057548262f24e9bb4fd433c8db96acac702f4c1920c8840f765474ed3eebc12e092fe9a9ce4b7b10d8580f07c9d192d5f3f63e206758c8bbcdae183443ec68358083b9a889e6790abe2641a1dad33709f1f001daaac1bef0310494999c0be08db22272ff007d7a1a1b0a751b42817bbce40a2ddfd71e4c65eec92c0d35ac8be83fe7f47d12d41dc10d783c85fcaf5bdde7626d2148fdd63fd3c54c7b5a4816b796cbaf87907145ac846b8753b5084c3ae2906b6ae2176ecec5f3807015d6d6cb54d5cd5853c9e304910a89b8a3c5e627295a53873211dd78095005603d641c5fc2409263fec39542c3e7a830ede4d9508addf383f0596161f9479874c621159f9ed13acd107b596d5065b13b083d8d7b59d465f535119e6415cffc909c848ada03756bec0063a17e38698321d9849f46fb52514764242c51b82fbb296d37ad9189256f4ef069fe03dec31483aadafab1090219df5ac9ffc7c5a3ebb5bb3210df8fc94575fd00a972a093519b82d8acd72bc0dcb7619c2bdb0e4e25017a4e74b15809ab45923537541d205972025adf573cac94c7229d3088b3e9247f6501028522a1376a7e938d1dc0c92b740fa6b2a58a2e0e739cba1b23df75a8535d69b427f641285390d5e79d0609bf75a42bca479a9c2b9b98f755f66c9a5bd79ebd13fe5a650d3d887dcd3375d15897bd4a80d1c64ed18b0eee7c0c27b22a5e6995221a15879c4ef5a83f51b47143f81de8157a1ca9ed47bd2407d4331178369299e2e9c0eda1415a9b1184aa0f3659e46c2352c3383779b7ee493e9af4f58019c8481fcd4caa6212d56395a89321fc346ca378279d13bbb6b6804f7035c0426474e15e35a59f1a5f666bb7a5f7a8ce46e488e897d64a1918edcafbc04b47244ec027c6317e589acdb3897da572fafc135d563e21be759cc1e9f0517b724a0f37d59232c5ff51db343140611b2ccedc4b7f43f15077eca808d6102757c33a0f85294047e3815ae3b5f2881219cc6cc858b16765fc4e3a594a9ad21380ad8e03b381d825194c0266933e2380ac10938edc1fd346cfdc6f90bdbf80f480cf98caa5922b0de940b351d649e43a97ae19f8d37dedbd64b9750dfb53d82cf85046024072fb3c04e4601836b92e7f15cb4ec9627f4d30fd0bb6dc0c6c4f8f6fed8950905f2b27de576456eef4ba93c625858976c41df927118a37275971b8c69d8bed4f0358dd8c4f30ac98ec29142b1e04374feb9d9c71e0bce731edc1057cd41c68be19074d19f0c45dedd2c3ab819ccd4022ae20959ecf36e9fb67356aea64509243edef5c853fd62ef854c2adda286a86ede1a302eab05421574efb14ba4bcb18bf666bd1cb46a6bb56f329b18d78657c7e9034c713598f89a58103731961b415bdb9218bc6a739ee412b7d6aa705a11014641042f3569d4d31b11d0dd23e0c6b67aaf9ebbbc244fece2f1b958da30b750221961c273053ccdfb690d735c83758668246007ef7181a5e89ad9f8fe56295a34912dbe5a28bf67d6132171935220f349e00a3271bcce8bbdc6bc5f4f634e3832e82e06da56d93629c41cf945cf8c002553405a1d6d1ffc5986142b8dc9be1b90a769cfb5bb028b34c8dd61129308c6b4748727d17727f3f1cfd32ff07cea495a3a45d3251b8e6a87e91de48e4f782c25b489c68ae0175b672820abbd2f4e92cfe0aa664cb39297fc907669d6b23a626e45b3b9c68f577aec0c462d273e6fdc3eba02e2127366f5f0d59929898f0cc1871c4c4969b1c6a1ad02ff527e2666bfe739ec203655c4109021fbfb10c9cf27dc38fc1a01e98cb1f6959c7121237106708f5b01654498ca1bc96070755ba4477f69a2b9e356dc858345d1d399e2856b9737de7087a0da9c60f9c8f273930b943e5977106014fa0e12dac6fc9f0917c59f61c5d966d77be2a379a5b0420aad7ead0f4c52d0aa020c272fc1d8c2c071c4ddbc59cf72b21c5580132c51f8827d9629d5a73819f755a4d95065bfe4efbb5f9d75b1d8518407580a46e263af38a34e2c73e518b78aedbd7015c0eba070c04c404ff4389ce5bde8319a0992aa17b57c4eaf4acc5fefb1efc6b33476e1c8f73a1a7c21a4d9a91a48c082e02d7387d39634d162a0a5d2047dcf5ec38220cc9151dd24587300d49bd7309e4aa7ba143271b5ce1e21cf0b620d4a04087f893f4cc47f401904d114a0e9f125f4b03879e394fe1e618aa047f17ba1433d5fa2eb749ceee4b622a0047c764ce6f19eead2f94efc62322db899acf8d375e998e4da90ac8206c13fcc0773fcb691fb02a0c62999d9b85250faeb0a06087ac823868943cfd83213a04c52b540e3de8edb771c7599ae03b39bbde4156d292f9ff6ab828397a7bb88ffeab8bb389baab34df952fdde4db3d2230295f0f645bcdc911484b1fb0c06f5d6cefe06e967a86118010107d408d900683ad6d59534333552b5bde37540f1cfaeb81cc40e22676366d9b9cb3607af58b4d09efdb2a589eae003f7aebd741b086840aede52dbf41ac7c33eff997c747fcb7314f45144dec4ab94d32fc10e2a3b0f38171713c8c7c4c3827264884173f8808a26240815e2b9e2d3344ce957b9cb638d9c83e1b665575e0a6cf402dc937234c90060255de010c5684ad89ffa86715e4569ba0d7b022a82d018cc00c448ca8438aac569f27698a7363fd28a8ab800842f8c1737d0d6c7aa5fe7469734a4475703d9bddc045205c8be168b1523a79f78deb00ef49bc451990227dbf71aa839234c4fb56cfd30e6482ca3d2d5b8bc27161b603e3612bd9d2440ef562acf2bdd3389a66883c3347f8ff609e4bd4f07d77db60215c8b69331e438198673b1dae7b7b4b2fd7d58a44c91a6c4e099ec1c42ee093ae89126f7e2a1f81e24fe19078a70d33638a1f52190ea1b1e49bdcc83bb5b4eb68b57611d4a1b1e1ecfa3334551cb703fcc50d4724bb34b24e92c9e1a19994184a03ac5557f5933298da203fa26ecd3728648d7690e7cd29992d207ed90d0d24e25a0bc4d1e672691bb0e5a77bdc5fd044a616bb6d0fa3b889fd6d7fb07691b4b790000000000000000000000000000000000000000000000000000000003091016181b";
let GENESIS_VP_TX_SIGNATURE = "5b6f94338430b15d5b1041459a840dc8ca05c9b50107fd54f5607adae2dbdcc6874dc0065a995c80d9459ede597f45c78e148cc5de837ecc451a49775eca6b49692faf73257bbeda4d666aadba9b91a8e3e20f403c2f681d0d74ac1d537000c8b7d11e79ca5dfb285d14f285920db61943d9849cbb5fbfd5a0c6dee8fb6046247030f5b8860e967f0f03bc27ba67fd0ffaddfc12c7e1aa9cbd817aea58e25bf6868cfa91d8bfc72eca902724032916863963c88e47797e68998810eabb67368ab7193d559fec1a7af1ca9295b6152819860d1de970e863e2767d083e10cdf175117234d4cae0b994e3af4701cea66ec9532c13546a790c2cf078b741fd27da38b4d342148c5e7ea6df5334911997af84259008d18f333505fce8245b096c98dfc2782011bd449a8b74e5a2d89595157477b5cb9589f96952565fd43ee75678e2ad72ec40f14750f40b4386fcbc05413cac1babb96df0883a329b9f8888dc79ed20a187ce7bae04377ce1b907c7ebabd128260bdac4f8b72fd9169614fd6905ce63c4188acd70abac30ac2b6f7b829158462e5152e8e2e2b6af40df1e17156be9784209a96b1fad3aa8e085d46ebe822aaa825b9c9fea5e58976de6d8cfb6dfc9f48aa69de224b855f043c8acbfbccc02e0abd1274bfc072c03255ef140977447027a452165ff356acf65bfc4b8551268938081afab8e93f3862ef21562211fac8c180c8d18223559b05ad34008fc61f72d7753d3241b75eb85ae40634b0ccfef3870cd1edf9a1f0340f719145aaf3c31543aa0c03e645e1c36b7edc4deab5db0665eee81101edf55d0aabae4a1e8ca13d6c4077a6e92fbc07a4cd8b8a114ecc5110818854940776e4bba13857291c6b60a83be15adcf7f958df3070c0f3a22f56006fe35a949f599eab7955bf0f88dfac668cd0bc37bcf23c311d78c46330b682a7ec8770b53246b9598814d250f542b94fd428bd0895fd3f79a6fdcdf29d48198beb751343fb81bca3f73a951d1426a578b7c05d5d3252daab663f14ad2ceb7bdc6e6ae1493068a91b60a488e0140a84577a1d2e0a28f7fb9740a8753d313b5e093580bd5dc77a7b13ebf42872a70013147ce9d3132e411deab12bcf1aa61f78f5e4ac0e7f864a7058e5256d60b82402e1a319de685feb05e7f9850ac887d23a433b00cdc0385ca51bcf6c02d32e00a9d9117f02fb2a984316b9af5eceedb56b0f1bee86aad46c0d8fa81079285beb2dd47f011509214c91ba0549b6b5d21c3fee2f18810049bc13e9a4b29e11d234452713178cf292b2ed0a58cf48afde453edd7b3e2b2cf587e0b6184eccd2f675418feba619f7c8f64f59a62d8d13ac0be8c189c3ed76b1a87da05b663eb3b73579bc78b181a5c536bc9fd8edf70ee8fe5c9490e47a8a66cb86138c844eec276344ec08efed69105274955bc96cf1d323eab5bfe9f6e43a453aef8e26c20253db5c1fd761e9c8edc0761e8b88affc306ceba0364f674afd491c6507aed107eaa98ec4e6a0caacb35bc139ec62510050ba65998adafbaac7141541b81a6d99e96f8e8a73febbea3c297cab82ada24c6f6a06f175c5ebd61a4b04adad4f54e87ee278e633eeafd55b066e6e6051a42e684ab3e245d8e8c374fca33190b5081cf9207552bbf8b28d9852a56b5ca0c24b05c6ddd5465bfa9d533f768ed3dd1a0a811e7a407d129f2b0b9e97b0b5de59fc2116bbfb45acc48eab669227250969d36cf1e9c5adb31ea4b814b40b350a617f6daa5c3d95fdefd6bd60c5c702aa6de10dbfe30067c9e22bc12d4a19df941c523d447410dc5a2fda9c320f26e4f7e3fdbbc3c42178f903442d045a170d6f8cc774b6154cc15947bea8c3cdc34777222a3966b997139d3491f28261a67ed7c52829a1aa525e172a48168a9ea57821d2d3126be90fc883c75e4a3338e2010958961c7e70fccd9611ff29e0257ade586182afc6680f5ba437170bce844af7f29e0cccc087008cb231d62bc5ebb74b64d7955f76095df08a8ea44b0ec8643276e37ee26e39181f668e242bfaf5440c40678dc8785abd7d95eda89e10ab3aab27c4696ae23577abda96f00f72c460489daec6b3579afb17c195acf89d45b60718dc9dfc8e9cc8c22d7db79a7d9ae84da902c88897250250587894378881c5006868951241f8307c2d82d4718122d2800f6a73b8426c85282dfe047df788fb95fa00156c4013a373f8cd71dca96f89417fd568ac0a764345e75e55fa5bddef06b7e6eccd2e207e1e2e9ae64751effbd34b44f63014b68cae11db5a018818dc3764567909b39198b40dbc0b8a1fb746f9fa27a8a7a6a517980c386035b189d9dd1e2c2ff59f0f3e1f2dc6dac3574a5ff54c7a91e4d6ae4f74eeba881b14bc3bb61bbc40c1f461e292a69b5e0b6bd161409a8447d049b709599d9ff3a74e51f77236ff516428b6231ba4b39c7b3bbb5c5f7ccebaf70fe97cfbd5f7cab9e5f2d611ca12c5956291757a4add04e4c58295038c84b9ece1dba90be4cd2dfd5f0b570579b0416bdca0c3bcb23cdccd72ce0fbd9f01f5cf04b30b20f1b269b2a2f57765f261f826c8a23ab27e679daab257114547a049d0441e31b06be23fdfbfd9328fcb05396ab81b38601b979e69b4c9dbaf453476d7decb36aa9ae723b6d531d4c6f17d694ca624d6cf803871aea823af65381f169bbc118363303d6d295dd785f33cf76391e59ffac2aac3c9af2bbcf67fc58486a73dd6e61c697b90c786d0c83c03131042edb948807cd9f226bf5eeb7a3cdc92bfd449698d06255251214abdefd259a9b2f72b4eca9b43f5ffbc1c85fcad91b77f076f69be7eebbd0f5bf522442463446067132c10a5e3f9a0d4b05120fb9a6af13d2a13aa9a04ff25d4fff6f167f47bcbf7d97815d05eaab4276d2aad39a68b6bddf666549125d72528aa4d95c71be61b34ef2cef800f333d825d0b606fd8d5fe11052b0e3ded2724fa4d143e0e686a23f6995849491ac65c13d582cd755c71d10351193ba0f5d488bd1ae0709bcf8996d211d2d3590b37d107af32c85e123d3a919e0e674bd88ad513294477bdc69aed25646b5425456c3fa77dbf45306a1f5c4684dc41bc1d271b48925b064f40cbfb7406fff81eeeac482e2abfe2b398ae68aeda01cf1416ef9603eb8462ded97a3b3db3b6a4a8ece07e559c9542440e26ad70cfb4b785a8f6829876f70848d330913b1ab1250e7970a09de53ae4bdcbc4fa4893926cdcef510ce58cce7ebe580cb8f8a59925f69a85f66ad672a06da9d771223efe16059da884d42e1aa3c2b07f74f36d86dba2010aff46d952a3f67ad4c4c0d72d59aab163775212420cd5c89190549372b53b89105f1360bd27358f3b9e49caed816f01c2c9bc3d0a9137b42bf577951d5fe26d775fb17ac76d07bd1c16ad66117a1a3daf75997cacd6943e25bd35c02a47e9be4820683c9c42f77e49229c3e80f59e02a744a3384d614a87888584fc29dd3c7ee172728bdacb7b7de6a2414141913e2ede3b16eba3975c6f2d07e189f5a6d5256c0b7da71cf32181388e358d383a4be18a283562feb964d3248eadedfcf6b5cada6edafa4edfd50482195e9f9d92914e91e750f9e9f7fbafd88e48a385e9d11b85cbc80d8b3f56334bf25c981420dee0f8bf8a725e8c46d929637c18c5bc31a3d2db44493c1d1a244eb29e100750bed7c137f9abe6191569f824786f71eec6f1bf7677acbc581e2e047f7ca47960e13f4102083e6eaffe8b9be1786243e5a9733038d73f1c2f5044db26209a846d4a7a733d03f1197c43a4a40834e742eaea6246a029ed9dd5610689808ddfe9db09e560e69663ec5becf9d16e9ba3d9a3d9de55a41bba79d967748c292b85b56cb4a1236971400986afe7d55c0aa2d95ff3b70ab98a3775f4ddb4081fe6063c18ecd894aafd565a05b11923b414d45eca6d55ac71e48e4094ef4030af31b4e658a79c968a9131e130fffc03566a1efbc6a5365bfc4691c935d0a0da7a00aa86aa135b9a192cc3da5b49d2ecb9c3d295b829f51e55e3ba4616a54836a2e3f0aedc4f8400b53f728460368f1db1ffc47fa8f47946d542b6603b1783d00ce639bf5cb9f45cc451d080a6acc4208749797cd63a4f1f817764004aa4eb7e0cb7d7be743ce3692261032c96575944b158048ae1d9ae077a12bc21fb2b915a3d45d6468c2c08ff01200e604f0932ef4594ab49890a3c39abaebf10cb4dc3d67d82f32f0da0c654fcc9afe028316ce065afa16e394c934f5ad808bf29bff37bdc2ee9d2c10b54da1688eb36cb335fbb31dd9680db3be4a01b546d5aa48cfd486048b0aa2931e80e799f699ef867f81b3776e4ea64cae4315052c025e82756632a5629ca07344d601fbbb60deaf39ae470abb32623f79ee37ad73697019fe0527d81c455f4878cea6e67e9027b168abee01b31a512e5193052cd61c96983b7ced0fb108c48f7c0b0e194ae75fc24a10e8d2b718eaf2aa2b31424e5acc121f198a120f68f52a25b7f2fbadfda45d513f9cf2afeaafcfee42e5bca2a5a0abc76d8ccc560e2c8a9c5d8f9a9cb55acfbdefe0cc20ede69528763bf33c2da781cc4e1b809c2760b9e64c83c8f5272a516190c5f0468793bfcd072e3255717986a1d0d30f13787c00000000000000000000000000000000000000000004080f141e22";

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
    genesis_hash:       GENESIS_HASH,
    canonical_hash:     shake256(canonicalJson(GENESIS_PAYLOAD)),
    signed_at:          new Date().toISOString(),
    signer_public_key:  devKey.publicKey,
    signature:          mldsaSign(GENESIS_HASH, devKey.privateKey),
    environment:        process.env.NODE_ENV || "development",
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
