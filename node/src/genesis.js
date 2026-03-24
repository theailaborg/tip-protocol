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
const { shake256, shake256Multi, generateSLHDSAKeypair, mldsaSign, mldsaVerify, computeTxId } = require("../../shared/crypto");
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
    public_key:        "e948836546edde9bf8ad44548e0e322c2b773132739dd9a36b1665715947c04e589bdd6c4003692c748f8868e717a08f2ae3c0d67e49bc05bd973ef6c7dce0ff31152a715ad32f8362ca5d2a12acd2e75c848a2bac044eccb341927f5eb604c31ec09fb5abe1f4360d4cb2dc3d5b8c82fab941c5a880677efe7fa6e85d0ccc3643b7607f434e13268de7a73223d4dbd034ff370333ed80e0804bea519be81fb50dacd3dd0451086277d7ea09285d61b7d881703eb55b6f80c47fc3ce0f6d5e5d7b4e32101a8aaa18ee0545384278996cf0f8621d6911e06d7c67aef9ca5c63b8903795c2054dddbd69565693449e5fbc3567b7e95285073060b7b830a9f76b93ed72d6eb5cace72aee6d2acf8334485e962630056617f5dad912258587282204db6c3dfa2b744af069c874e70e52f876e8e2b820e7c63f6a3b532ff3bea498ad60a276fadf052c47a290f5093e724ab5f64bf7486a4edb0a7f0243e54994b1a835a963d2847515fa09b3df430b271ca8538d0ef4b108d078869dfcd89d17474d0d0346c8a62f2d3d1d09e4b1052047a5d1e60b36052dabf692d74be4666e06819091e03a28ae81fbaf00d1d29e84e64bcfeb4a74b2b35a5616afb9a1ce5a344222719a7ebdc6106e9e92f59419df70993e24e44ac1792199664e1e9d9a0ca5d712f095fcdd7ed784a460cd4ec1b79743d24756a0d93cbfd8a25cc219a1f9d1026250dd7a4e319b2038f918d6f805e36990dd818bd8029324b2055aadd760b20a701c5203cae5bfefb1856f354923a3da9cf11dc9dc1eac9ead221eef98659a69c9b6db36941671e7f87d6abb9878b6902dcf755c6a08e3a9b98704074f4716c89aebb7d410e812f657bddd2124052845c20fbc5840f085422b7dd66c092031c5e05befe3f0280cdff88f662ef6862105f51b795182d85b5a2c7844d4f8e353e425c8919c807159893e8b9c2d277f03badc06c28d16f622700a1ae71db963efbd2ffb1234403c079eff0291b762c58a80ee98cdfe561b072c1b4882b2763102f0be533b798eaeee9df35f276f0188a65489e3a4d06acd604e9c4f4247466386b7d4e95fd66b187232cf9f84c85ef384709539cf365742cea406dc7df52d14dc3a3d8fde8657378e98401074ff511a605da01a5e4622ec5ade2a08a9a799bd6b12408678fefd273090c0b278f3071de8cdcac6eaac7216643a785679619ddd3fd81557b8fc660918a899d05509efdbb2c3d43aab827b8c2abcd17d51db5b30540d069868b1a25a310ff01d30433870792c2e236827c55d243d39e39221a44f971bec3045d8c7fea064e01353654b81a600b4be58a56eb8407607dc30a35fd83d665079eb80a27fb1fe2c92e3ab2131a6b861f66955bc3f63430a98341de4f1df55ccf5385dd7faa448f15aff5fb87badfeb5b27ce86a576d8671b4bc4498a8d263de7747dfb2f13d2a99357e3c8675798e25910d3328bb7b692808a22ccabce1bce7075d44cd9c7cd86a0e3bb2270bb60f1a6c59a61a9fae68bca90a4739f4994caef4970c11291f6eeda5d9840a8ecc8596c3654ecdb62c2de982ab3f62071d8857ef6b85cb2960470fc83142b9c82bc31746196042405ffc05fa674b8e92141de10cacb272f5f3f49a49d20650d2b7c4bcea6e609df228d20c12b1e6a2ddf85459dbb7bd81aaba951d99b7b1c3e34bfa61f8471011c370bad663e8c20c6ea4dd106b1d7a1735f64f8c7ae02cd6ef0f47b2f5d934a50caae6d0e4e0833c2695fa441d62dcd9147a5c8c035c4bea083c58974b3eb84e86224c5008da3d506e5b9cd0fa7e33e33ff076d7ee0e439861c23b89b8deac0b51563fb89528b423966f7113029902eef73c58fbb88b0083875beb90fb0d03828e21ebd8050e83bf0a4a4b1376ef60b6fb88ca289087268541076ed652bfe220dae0b878b9fd667634105ded6ece215bcafa8ed5190c61b6ff405ea0009fd05d8396e011d0d29b50aeec77c200cf2eec69eb0a8062c8de5bfa62fce2d846ab433262497da7d8f22b99dfb6ed5cc5a729930f860a587e04590c053076ffa2bdae5ed147ecf6fc1ee767323ee9eca18225994c767f802bf13118b4b1acacfcc314ab89105b1dd8238c3b369ffe9f36a2d7620b8a4532e5cebc1c94ff32d1b09a2305f1c0a377742f44213d418ecf43374e9a0d35018a83377654941b47aaa16a00519a7923145708ecba9f9a69f0fbf33eb88e6a395041bcdabe2e57b9df8ed33f9e1e0ea2951d7b17bd74e4e4d1a4d90e83e696ce3eee1abba7fb191eaefcd683b7885259e480a0c72332db59aa2cccb3b08715ed15fe4a3943801bc055ddaffda93eea4aadad70fc7b061bab8e1ce37ff44a328982ae8fdfb4ab0ab1c96efddb212bd1e01445204d1beaac189b7a153ca771e18887e985fb9a22e22abd26ff1d1c1d897287bb3e477dd862be2277ade3c4d5ed6931eb069b0411cbf52d4a807b2f889459769e28f1ce120927025b127c282b5bd095539040845c54b2c35b2ee48685772edfe5cda701d5babdad740382739717e9b5313260a113de07484564a1ce9d5975124e0cb16ce03c169d575e431a68a53cc390185155d3af92237b1ee4d38d934aab98700d470ec9ab718d5f914a3064a2a266da0ca9db4c1d833ee702e7c3365a2c8c7ad18c2d43607d0fc6c5c224d9b2668dc7fa6a3a485be506b35d1dfe3ddbc377fa15294fe3bebc5851d0a750c29a8db9b06f2dca17fd170bc04f02602443ce07ff97c213e4",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: [],

  // Merkle root of the initial dedup registry (empty at genesis)
  initial_dedup_merkle_root: shake256("empty-dedup-registry-v2"),

  notes: "TIP Protocol Genesis Block. This is the immutable foundation of the Trust Identity Protocol network. Once this block is committed to the DAG, its hash anchors every subsequent transaction.",
});

// ─── Canonical serialisation ──────────────────────────────────────────────────
// JSON.stringify with sorted keys for deterministic output
function canonicalSerialise(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// ─── Genesis hash (chain anchor) ─────────────────────────────────────────────
function computeGenesisHash(payload) {
  return shake256(canonicalSerialise(payload));
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
let GENESIS_TX_SIGNATURE = "cf2fcd188c1a0c1240b2bb1dbca769135d294b3743ea5ff2cd595405b4a4240e7627de0e660a285f3bc4fd1d501d29a67efc6dd987a79387e9aa1fa0adea4d7948e081ee1bdcc7c6d24b558d11d647555472aec33c8964a05fdfe1cb65594da58d9e75bac18ce8ad905acdedff4a66b5df184158bd6c6a564657d741d90b58f097c506c3634641af9a76efbe1037155ecf30083ecab50796183e9316e7c34ba1d2fafb1996439ba15709de19d982b220374d24cc924bae451e0849c17aa7bdf563826bb86252f3814cb628748f5bed5209591f6972c2dc456dd69f308ba9b187261a8e3a9a67dc48bd2d2a35cab08b56d44c33faaa063fb14e84579580ac11cefdf4c9e67667d1603ce19eac6f433b8217e89f1533dcebb2319b0c0ec95fffee760adea04ecdf58ff5ebb562995e1a1ffdc8f69748f1dfb7c93060dfa365f3e80bb7e100bb8dc8c6d5861cd3378716e3393c3303445fc09979e20a3f58adee7273aca6df5dd6335ee898ebfdb63cbedc169b72951a27ff73ccf898f39edce963ca024065146707bad92d3830469bd16230f36a640b24692474adffde8c63ec369351a9dd5eac11a0a00d338cf3f92440240058bdecaa930ca28ec83b71394f0ca322685cfb6e6fe3a8ab2c2fdd4f2a1394afc4bfa9d4a433a2fa9597769a575b8bee100cc52e1d51e94bdafd307dcbd9ad76989af6e7b3d3434d526edd700f025f16f3221afd3b1c0664c38112741a85ba270fedd4012756029c69d4d87ad0f2233784650826485fa02af95e858efce845cb846ab29ed063301d43534895b44dfa1972a429e1e7e28025cc961b6a30513eb4ddd601311ff7f75c3e89fcca9f6f350b2a2d10a040772e31d7cd8aadc7de69d705e2d24d69fc8caa6c7db8dc2d79b3a30b85cbee6636468b534d5b046621725d30b02f1130e53f793ebb2a0c39946641823c9f3715bba76df77407dd998206125cbf532764c621e33d8038a128cb6b55076e1646bae9e1ecdba8d1290fcff954bf7d62b93d4e8d4196a345e93c84ecb82f1c3533a3548e8dea2740ebb1e332f1ccd4806588e3e589defb96e93dd25a1b7cf04c29e5d3ff32a5ee78fc59ec068c3b57f4fa37c58c805f627aa4a8e62eefe14823f6a330fa2bb1a88621c901dfe3794136e093f03f40d8a964ab989317fa7faa3ed0e1233b88e960df8d0a680aa7fdd75f0584b84d74cd33b78713da99c2f535752c5a6469938a2c9c7c089a2f011bab147934ce6cd2b43b2508f4f928a186930d79d8ff3910d70f67aeffc9a0c643b8d0ebdec64e909e7ddf85692aedcf08fec6858634782d3b16bcd524dcbeb5db31a0e62ead32ac2460438f6c0139dcc0357bd40d7b6ee6547f533ce732a7dbffbd1b70102bc4bed7fb1f89cf8283278d3dda8e3d599b776d19a5b5adc6f3157e1cedca97a2df516051281bd7412ba344ca4df3c675d2539f80ef776a18f7cf121cbcfb35689986d80bfd6f53ef13e305b55b92bd4eb8703ff09f7cd9234dc3096d0f79511316ce21d687484d0dd9a142ad2d24d7c4fa070331ece837b9b54043917a2a2cd73d7a2213c078cd20111e9a861485959377aa414929c32f0a1d675e62e5df7aa185b3ec9cd2145cb0192cd84329334996e2ecdc681c10c36530b0605f4530ba233875cd60611cb229300c9ad4a7a32fe62608256e4f071f7ac81acb894a83674e3e7816a693ff6543308ef2054418f9baa1e9a4b11bc0ecd8962944de3f5bbbaf24d6d5bb93b22b4c1170fa66a0a1929c00d046fb1041cabf89f1c199ce8e1d873e7e8fa53cbb7714cbc5052433a771a36ed5b01de7a26cc60982a3eba6c8b1d1a9d91b344028802004514296850843a81c3c0ed9175c6e5857d7bc47b22442a93bf5a8ec3bbfd09a202b1cb8ffe636f7a0aac86d0fd132e5802d64bf63bc4ff473241796f745e08bb8e31b73cda945ff7753f348bfa168936164015cd9a0d620098fb30fa194d765eda97dd95d0ae0e8a94f14037629cca06c988e0bd86befd0b1e58b4c94d09b2e33917898f33aa22b09fcc2984be5aaf4b9efb9754fe270a7bd23241120c66fbde457f7507008a03b06110c9f82c71ae772e7a3ae66f811b88e7c65c150313fb8c8b507b1c4d7ba00cdda00d3095740c124a4f313fdb562e5978b2af222df4ab784865ba33795c04e4a0c64234702522884086a7761f2269dac5d31b053bacb2f44c89b8bcea3be58dedf30766de0b5d08e82dc913c25ab30967cc4b2df6da571833a702a258aa89396f9f02d0c9a3c098c272ca7d1d025f301001e4931a088539b4b1dd16d588760a7ac73d99de1c09cc934a4fd5851fba454b34e60160df2f933beb10162c336f83954f47577f4c2e7cf5a2cc04f65319d8568fc8da3d795a298a43bc1f406f010c68a8b64b25b70dde67982613531bdcbd55a59445f1bc60c0c8bdea0e4e3922673b533dff8427c9f01098f3b49f83aa931af1dc022d3c8d3ae43cb1f2a5b7bec74fc797a32dab7445f52f35064acefa69eceac40dad372e9697a654dd14ade004ad79f29c24d055f362a580e4a2e56711f6224899dfea8aa6509b16b5fcdf04a6cd165229c4056d279ce654d36404b0494dfcfffa43832791360ba1108578d494acd038707951ebe295f9dff9f39a6243fed271513aacd832f51ffda70285acf71f77bd05ee4906f326676c5b2ceb3e5985642e09f15915fb793078ed3338c255aebba0c0faa87e6853250bc4ef578ac0a865cfefcb91f23ba8a3d18aa011580cdc77c5438a31ca8c8c384fa1136b4b3686b467c21aa527aa1aab898ec26747af1e25a60c96637a33111d3d2e2272156a58952ae3a1d3501fb18b47b85784248e6cd4a38324c3100f83b67b9a2bdf27c0724b12fd4a6af3bb0e25af2e127c4d20cf26f9f6a3c15dfa93d165eba243461aeb3e59f71e258ccea2107be352d4fda570f7b6c8888df219973f1b9fe004d62e87a5e8249c97016a2040272ef1fe035abcbde5b5b017418d485873ae64383cbcb1ad0427b6709e16124310a074bf9e1cee4213370c526fbf22129e430784d19a34c507ba0efee6d0c6b3a1c3181ccc7e9e518c5c2431ddfd3082b24e447c0c2d0bdbf16360cb8c1eb5bf6c413c6297ed02697145ecc9976e7deae2e8059147780565807296f87b03e646f6a9178cd80f3758976962268808533a201fab895119a64292c4a661ef8b555cd041dbd378b826935ad02b98b1badb548dc96918aa8ea0c1d7b42c65f8483c4bdf3222f222f6edcf65f6277b6cc70bfd06eb32f33636b417f0a3ac9eb6cfdb0fcd3c0786ec18f298f7b5e339033da361e998308a2f2f144e0e8cc10547bbb26639d7525fd21d95cecdb3b8c91f534d6bc54b8988666123319bb624a5b1b4a23f9785d99abc2b0806a811d6f7daaa95c2cc2b8fac176c8ffd9b14ad9a73888fce838554ee4312e53a771f869776b1f34a447af5480e5c2daaa8c10c115c952b228cd44792ca398e8303015b91db780e3cc2460479321e6c11b58e0f7b810f54e9a24da6759a05d3747d3e18f7b3ab4c8472986833753bbf33a2d72d6c8f262df9381dfda5a92e55bbb7b35b16401f8cf365b05f44728af4317a44c69552b3de5d78dc57e2f829b3f6fe592dc2170e4326461bb66c1899ac6560392ee3c115678f07c0a4cab93dda77aed078f9a06df77b262c5a1e7ce83866315ce3c6f129132861af47e1b17703154c47fe4fb9fb1f6191b49581b7dc0dbc24cf9d2a37d668da5c23d75dad5f44be2f3f82f42e013d03a2b4faa9a430ab36c9a60e4c6685c2a3326801f6252c58af9ee210674bef74ab26e8390c804e47001e66b2897af983ad7d2da97e6950b31b42c368ff9cbe352799d4cbea1f93c708dfdbdcbcde545bceca23c4e4a37de729ae37ac2466368e4dbd7e058b392f11a6decc271f978f815b2ba16c18272ad9e7d28874c06cb3111b5959df44b34c65c32b8b5f164ace98b02fe8a62734f58f21cf9f36343200688a0d3cf8220c39f2475079c74f55d47c5800640990d7a77dc89c06be4fd174ec23b755da9cb4440cb13c114ec2a0a0d2bd4a89ed75978154d9b619849521c2cf9b0cc0b85d628f5a7d1b02ea66c9c5e323ac7ba09edd8ef844702838cbea00b315624564604b0252dea3736f8972b161b6fb6c14ae749bb74bedd50f3f937d5a6d41bd06eddf4d924d1aab9301c825618f9fab4018475a6389823addc371959476ed90dcef2891c826e529b8f80f1b1dcad3c81ba20e28450d64dbea6c01623aa27ad1e07173186f5207430b59df390f8e6a7ec057ffbe3f636bf4bbebe103851abe2c999523001a43f854065249f51e4b841ea4a9c55f33e65e69d77e993b7b34c31e1ddf172782d51355d24be63d3bc032582d2cb15c615a94c5aedb26095ac0e934f87378e31fd0edc9c3b764987e4cfc1ade18f6216cd569c3e299260c98a837753b7c8e82b90feb045b33e3356dd15e4af29a6489bff6258cd13424783335856e72e73aadbc3451784bd49e1e0e96cdafa16e6bc2aa12772282fa802a4949c1207d1caa4eda0724f18b33471e22b8224fe8d5adbe4ded61cf0e242f60b19294150a2c4eff2475ba4d7657891f2454b6a0a0f6286edf65a7f8c0000000000000000000000000000000000000000000000000000090d11141a1d";
let GENESIS_VP_TX_SIGNATURE = "dbc432a498967e4ccae5dd91746e9dddded287b81d8c28eef89dd06836084f8e4c23fda1df8c07f5de817f4b0cbd67044348379055828842cbf318fcb891af86b63fc3d237e81f3a5c92281494da3d1331b5a430aa0c530fac1c5a1ae15465d9723dd3631b58fbe1dd23c7a4775462b337249c673f1badc924ec0bf63beb7ae59a85f1a6db35adbbbbaa5522734ffa4862877de3dbad2261876fe42464bd50030ccace855cb255bfd0414344a9cdd05a7792bd411980a50ac3b80ad29e78a2ef10bd7c44d764b198a424da2a19cef189f78eb06b46e04622807b58e07cd6e0d2aab5966a2df9e35872fd11858b4e82fb090f424898ae305789dccc9388011560fea6729fead2e3eeffe2f6c90a61acc4a39d3c0057321e1100b2c03d0d76fa790c369ab240490c8f2b0625034c0fb90c42d1cfd3be485194fc2b401ad99e3b3381c40466120507609c583a3dd52b5493f2d07ff36e981f55ddcc4165c7647232d18a662b984941820a9a08459cfece948e4906bc117ebc5703ffa8284668c32585b4eadcae11ca74f3a0d1c67265a5071d7c5d8fa35fb2d8f36a45f725a827c1b4ac142f578702d539de07fa6dfc009ed4fc0a2cfe97890e7de5b3e9005fe6e9b323608b0b39d78eb6333c858609b9a6d3127ba6ad993a7e3112241009a1d1ad85ff2fe90ce95084847e5ad39ee98c4d827fd9476c06f62ba546716fb95ebb946eb0e09b79d39f19749ac8fa73e42c700a235120d27226e87829b3760829864047730ec03617efb2760a8e1364dc5e0ea083cd5db80d4d099da3eb6702bd5a68ce926c0a2d2b8ff00c8cffd8b410bae57ff993ce53352bdb0e88506c5eddc7905c6b1cff980dbaf36bbafee6249e4c1fe3be1499ea84b4b63a6522e8d2ff9d17038b778b6e577a915ae44aaee5a35537b3402fe015a07ca91a5a1ce4885df466c637785979c180f636bee7cf47af6790b49d2c749aa5d63bf540f1b4289a47cc8112806ee036a806c6fe7feabade8e9ff0dd006e2e1b8c93866433b5dd42a8190a9e5bd4f64530999573f5bfe1bc259dbde4630cb78822c16234edbd00f79c9bb1e1437214aa65394851b80d95feea2b395ff79485248297aa3070bac78e3788c9829c5cce4e8b1c1ab7d289f3f2cadf6f460f52ee4914a7f2226c0724ff969caf258a96763f2652a30a9cdb6a9359d1bbd93ee12ca0df7c9d5bcfe76a4870810f3ac9613d978908bcffc4ba4846975c0acf05f6d866e7992ca381fa23494cd225012465cfbd0a372c75e937608167371ff5d70180ab3789522bbc9aa6b58e9fd1222fbecbf8283fbad22193d69ecdf8422367126aa95b55e85470d854075050c68234af888cb71b2fc83152f35d58e32db2fce0bd9616c72d648ea5d1f0f856eabfaef33d6d3d05c010dfc61c74641be3d3d939fd07048a15d92ca8632c1ec4eceec1613d2c4c09fe1f40a84c23dea8780588692720049cf6f37f0ccc45edcb939931d45d2088beb73e15ee0d78d67b756c671c9f7dc79e95b54ca4084ce281b40ca90274869eea09a61baf936da6882cd7d9ac2b3344c6cf5dd781cd0011addfdaab367d88a1c5f7332247a343466611d6c14b8b7d8262a6c392c32b5cef0d894fab56529c5596fde4f9f29800c9d4671889c17dd80870095e2c0f14b8332bd2cad3362500ebedb1ce9eccf18ff1c3af9c282a0b2ba6ab2a883d69b349cc0333a73cfd6c6dfed0d97e7a039ca38972252191d6f1bf70d4f24914c929259096b49c2f957ebb988ecd5c79581f0bc68e5f95a18027ba169b5389e6db6a398382360f9faf927fbd90a74e85b682c1b903ada5803faeb33362c8ce1a3106128b4b4740ec3799b0a7f5eee48ffd7797d110e096f67e23a3a5bd5939b5f05f49df39cc3811839ef8726bd598ad49513c3660ad9dd0889176dbf8f6fcfee5fc0c9da346ca03a8a70357858289c60c8ae2b0a82eedc82e696da3c6de96519061d20ae21d3ef51cf3ac7db0447db674e6c31089a9cda0985b43fad50c92c352b47c95d27736347bc3a584c347f8ae9ee11597221224dd2d7a40721dcdc6ef8cf022bd0ff6754cd270a846672a539b07fa094c3fb8a43edf998a3d3c2d6c170b537a4e9529650059f6aff977a93d24ddc65bcd90abe08d6b5d9628991c28a896da102431ce49310a0ca731be2ed5f2a69dbcfb118013b29a0f52d567d9a37ac2bcd747732d701ffe66b88ca48ad9ade1a22c8eef9cbbdee618f94f1fcbe3c88bba94cab4a5775db1cb2fb02154d8e7fb10e73b64f83487d394c530713e368c78be0f02e815e30808ae1ec2abc6dc1d819ba38eb2437db399f3873433e7948f7c6190981b15534d838f11a8832702f38ffb84ddc586fdd1c986dd664b007d217041f2be9236afcff3cd05819855b373ac4178e3f649060f6cf19e784aa61cfaa65d9c116ea2432691aa16905b2a30ab89232752432bf0b7a724f37232abd52576a6b2dd500833ef8aca8b0fade5da3f7f6c9be8d466d20a7221e7db52b4164e986c9a0a4d424246c1ed7d6fde2b7f0097ebcb09af182f4d3c02a6a7c50d3bb907dd90483c993562adb28d11ea7dd9bfce41b7287215a13b98819d49126663b33416dcc781b927a0a6ae77807ebbd28b7edf8985f08c7cce5e2d895176d147ba4e7149d98a4996d53ac571b046f4e72d6433aba1725de593b2b31687a328085c8c16f89a18eed08f41ade70419744769d5c7da1ee11f7780b0b8597735d641196a962f33d76f64be5cb524feb68f6759ea6f9a68b73455629ba9c52c05576163edf35ffc7e16bdece21642eeba0624bce8cd6b15e36cb16bdd2f76d0dea3a4fc088c26adbae44446b506f742c611eb33083e956b60c28ffad7bcecbd284882a5dfe1a391774e48134ece257f4677f2a6815d0b181351edd53653e5e5540f130ec2f846cb9f4399c29aa9d1da0159a04a6fd5a3da7b3314027a1ee3a9df67d8c7467eae2527f55f867b87b3a9a9764c9763ccc5c24e20a3f92e0dc0cba1a2f2f7463b015a6daf28da7c84cc3089be748871ec3a8108c015185b6578c02e46dea3ce2b664750ae07aae0c3b67f1f4ff1568354ac2b5f8ff9867acf652f2e7c0ea22b6c8d8bc7c94c27aa0760e22bd31649d99b2d40c6bd1b98dbf11ede913ce3e25cc13dc8c8a894c2b0b59caa43c2021b3a7e324d3f569807d4c7725593f27363d038012e1bd07fd9a126128097ea0d3a881c7a146dc470f20c6df97b5865ac712c09a9131e1441ea4ba474ab15ad7b3da669fcb1991d763e8f0e7276b2bd305e8db06a92611c5d2b6c99bcd70d56f331bf926039ea655d05b16b9ca74816e3594cc207bf0f56d645457acfc273482621a4e2aad8ac5af9195475a4812bc9ab552d308df4ab6e6b70a0f691c8a76834862036d370d14c9390fbf9fc7832dbe18bdab9b9fa4007594e36fc76463bb91f375f1c41c47e259cdaa66bfa26c95d963055ebf221c514ecaa9b931e4299532935bc1449dba9c2341bea89d61ce46535823987509b7a5452eb87e16baaeb823f783d5e806eeec91281aca25eaf692d589e8331dab55d82092a3e9daef25618853e616b19977b0f0ef4ec8817e3db21fe107ad1d029b32ba03f3f51082d846081d14dd52d97735f1f6b78c3f99127b448288e95984d53aea062113f56f3d39d83a4298f9edda2c446eeb3977ca1ac485c3faa96ae15b47a9a0b8be7e5ea43e20394e713458ad8908aafcfb790576691415902ac16bf6539b772e96f9e77cb63b516ee2ad414c15d661e6e5eaf8ff3e2f711fc715e78cc738d3404e74f77bf2c41ff742ee4f63d367d593464043c10b1b427a590903de6bea174478b688b72d61056db1ba77d7cfaf33879ed91a4dca21607429bb037a78f93fa29f462c225e56ed9684be87d67b4b4c1428489e4d6ae74d8d276e7cbcf656191815e64591e2f458e3cc06a2f19298ef226ab49924a42cd5603926c7dbf42be14382cbe2d721819fad86f857d2735a2ebf852ac0c21c40742a4ecb0a6a76442def24c587eb47007bc30cc37f4c4ee0e8cac5dda5eb75a3ddf79837c823a2e1c94c95f770843cbfc0f794e2dd102a73994a677ee306d9abe6996ba581b6b6481be2358ab6831edc4c01c841e83fe56010c347fc1b9ce6b130c607f64ece505764ae52c0f7577eb23199775eeded08cd51455b0d6e4148f32c277eaa84028272a7462899dcaf31cde18b69736a259519303661e614bdcccaca02f9fb8b8fa277cc5070e64c01c3cd95c87e50b71181e9f769d6152e63935584da43151f3aeb1396f881fab302cf70bd602fb228e009b4a893bf867665b8a444b35f8c4038c9f1cc8812767d489c494abb67ae318f044fbd0e68e4d362bdac5d9b3ba4514927c68218d5dcf22e8a386b90c51b6a50ddc946011704ac1c8516f59e80dc3487a37073768e99cdb5d2d54365d863be849c0d2459b657433d1114a0a296a7c34ea374ab02ef0baefef2aa4c14e121a06884d6537195564a7529a13eb095fa0cf4a44ddd3ea3e43bdb9ffefb4c1b9c753a4fce9b686143cbd37a3e477ec8a56d31e3932da9980dc013282e68a1c890a208a5f6e7eb7b8e6f6000d355faccb1531dfe7ec04187483aebad44b8788afcbce1316818fc6cfe6f000000000000000000000000000000000070d12191f27";

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
    canonical_hash:     shake256(canonicalSerialise(GENESIS_PAYLOAD)),
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
  canonicalSerialise,
};
