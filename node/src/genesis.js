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
    public_key:        "9970c1232f47fe14117f3e62ebc0c4ec3556c15756a442bb67c4c8f7df384797c7b951a5f195bebe0f1423ab6300e66ec025f5f9b89a62228a8194a3ec00f6867c5a642f0a497ac760104804c0a0a13e9656ae08d5137abc7e0544cd678f9d410d328d8d440e1b2347f218d91eb5c9a525625af334728cfea8c4990232022222bd3712fe5b79f018cd59c376b81d0e75283570d8a79b3473c25a00376103429f24ad5667a370aae4fa3afe3947fe6b81d88570c2cd38cb2b2221300cab52d36a31d4da5c83f2a865bec5af28d76635d811859fba5fe61446893a281973dedcfbfd776bc1161f5cdb4313838fea8320f0c1842c45874c0ae8a437dc822a230cc94464ae07865d40a80552ad77e470429ff3cdd76ecae656f4caecce9a61915255454c8da761d8de8bb41931b94e140fd87ffd0897855c25fb1ce129bacbc1e0a8d87ff7f754bc00968335a92eb653c4920bd7fe8644e371c415bcbfc534a650c6854dffd68ba6d59e06c8b34b311da411e2ae53d9d84cdffaaa9d79859c1705432279716fde97d4fee6fb34f88f5d0968065cdbf5b3ab940c1ebdc69415969f65a655670529c6702dc31eeca96cdcba12fa2f8444913f81916bfd39ed17dd89ec43e00f6269b709064ea8f8bd31d2c3aa82ab5aa0ec40c2b5e95c7f10f9f30ee48a5133110150b4b3c2f0fafbd2558004c2d291b2cd7dd8012492ba7c862a397889caf3a12f3cd77bd5182c7ec8d0dfc83397794a514cbf559026a0c74a1b6079c6ce4c7c4b484a273a8fc5a82963851ee5cf5c46d21e22a699ce07485238c3f1b820b33ccdfebd3e55191a07c2eedef4ddc86403d958a54a1b13b66e42cf11657d1e00032cd4c21aa3763c60f8134e9e176583ef200dae19f821704fe80a74653119256938fee784c164ee18e67d22e631da2b75346415820492db053339e5ddf71b06f84d3bcecf0e7b95f329f7748fcc84923f616271c717e53ab0fa4d35ff2ff133d608c6b6c623bb86023882d5127bcc2948c939f2f1c4c29bfe91c2d2b00c9c92bbdb82f8a64f00e5dcfdc6878ed4367e999ccd05b788ac5a73709c8bf8700aed9814727538e17a5e6e4195223f464484284d8b433765634aad2f104490f7989e8ff2e103b1df2fc27264f2195498254337ea8356c058143dd7c65cf14f4049cfc6201e9317cf7bfc9fe3cff0cc6608dc841ef829be4d2b9859ce5ecea5c95bd88b0fbb444dfe07d0a873d3ce09fcc0d065ad5ff2e1f8efd4604da440a77db85fdb7b3e1e2787b6eaf167cef0b92bfdd2e6d47a156a528e4ad969c0698b88f39a7d5b317c121f5ab5152fc089f333657ce11a7b3c2f4284e1d0c0bd8f075bc2caa57002464a76ed2f412aa28a34cb741f606d13ea212cf18ef2d68f1f144306c55c4da831f05b8439f78d9092a7588d5ab18b0273af47b3b5394188a0ab9bc6f8cca735d63e8fcebdda44e27c4187d9aca504dbdc711e62e7787b2a6636aa02a985bda89d0969f6a91a641a12e5798a38a41dabe484bffdbffb26bbd48b335f785755f8869ff2bac0813f7ed535264609f10143aea6ef2440f47449a030226a948b8864ccf33a6d367021ae3322acc24ff7f34632dfc9fa1fd5f45662c27635912a76a3d0d580d18c6facbb95b90521e35c2bd5c27a798f9c0977991a63f1f969459adb7030311df0fb71f977ee2aba0d7cc348d61f340e5a76d7c45b8c3d52b10d1abcb977ebd73433464a6a554e65c654f72efd1956ed57fd4e456d299c24c8960e4c72b2d3d92b004bcf8d1d257dd3745a59a5f47dcd9f93f50ac9cdb2795d52f94a6d302e7e322fc2c11c08fcd7ce393797eb96665bc44744ce99d92088bdd97f3055e3d76cd4f2f29508e4d54824558f555c2d6cfc4e5c8b2832fbfea6f4212861972d11e03706bd4d676924eef91e93dc46839cdf38eefb6339143abdc79a659fc6e94161b8a4007ecd9e90fffbcb4a063ecd7e09f212f4955ddcd2bccc16f0c7309a8193d8c1a1b9c3c5d9e04c562dbc90215d6424afe6067c9a520f3340f3a3a887c91c583d56a4acf76cc53f8c96a76a47a525aeb7fce2f9f80a09d23c5de892f9d32b6e10e4a1a5f72785e9e23eec621366acf2adf3ec7505e40d93efcdcbaa9e3e28f79e19b722ec2d54d60458c94c6cae68e7b5dbc895da8ba3ee8a8e6cb7c6933b502631bfdf323c7070c3ff148c0bf9311561447ee704f6db1f98f155e203b890ff888e9d94fc993a2b6ad574ac6f9e3b40dc76c01565eb2ff8c4869d50229bc9831c54e1f54b30dcc9b042f39983fa76bf22ec76e2a103fc99b2d44643b32a4a436efa79f5f17a73af7c12b3f1ec3f116d206af50b124267b69a61a021d7b54797342a31db5ba6f62df1810f4a620e927edad065185a22e8d57b9b0618bf9fcabb7975116bfd25dbbcddbe77cfadaeb288a43965bdfb0a0754eec2f4a45ffcbbdcf42085d9cf59f4315ac4c082c5f57e42899bd49b23c00cd95e112b19c9e00fef4675a6535b688ad092f5ca416b95378b8c1645fc9a99a15837417eac91c232341ca62f141c57d92da1c1283dde3464b9efdd784c3cde8204676db2d37c659d5fcacab29261a8efa6a2697eeae5974cd2d0505ea72a9ae7210b77c5ca6c5b9b5521bfdd636b70613558f427bac48565ac1410ac63ba3e3e7de85e6b785696bb187f541157498ef8d3293ecc409082fbc8a88f52930615194d1df4608ff8972f48a0baceca47dc3785e41b9bb8717236e98f79c05ff1",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: ["tip://id/US-7dd93c5d4a2d5deb","tip://id/US-da4abc8937977a20","tip://id/US-19733f308df74ffa"],

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
let GENESIS_TX_SIGNATURE = "84dbab6c9e0396b0a2d276da105062fa67c89af4c6df3dfc2e3ed9b53166154700f057b0e021cd81b0ca4de7b06910abbc2d48761610f6c45f8d0db9379b047c224bcfb443b414e2eb46933dce65bfa5a5ca7310154e3842d3c957320f144b66c846072df8381b9720d2feaedb8c445b3eb6ea535051f794b9090ff7311a552ecf7979bc5ba56a2cfc4033f18a404364b4ea6c4aa2ab0f90842fd95d3573042cbc93aaf32f7e4dda1c3dffebf4fbef0a14b7be685fdddd63a70efdf0c9543b03e6a23f0b832f8b95d9548cec7946d0452a91bf6d9c45605dd426227544183acf077dbf6b5c2292a03a7994c16f773d8f347ff5291fc8bc6a153430128b6d5ce749943159c23285280ff0c16b722e6917a04f1c0d2265e676b13902ce5385f8a9653896334626113ef0ac34dcbbf7c34599d3650e22908ce2c477a195d98f0ffb96e3de2a16f505fdfb8687cab4a3e28f45fdbd951b5b3384c0982ce212eaa3881e30774f66072fee0c9bd5b6e2d21f7f4d10c808f62108a637dc9432416f15f283a7436cad3f77940a7558cbdebe651aa06e514841d4955883fc3aae33c8ecfd860c2664776cc0e80fa46e77dab86e203bf083465a4323f2c10f91c5a198702457f387b03f78f2d8b1e0ea37a5811621f1cb216a0608bfb8a8423214a2178f13b98774fd7e223f47ac0bdf8d14af1a47416f0eef3707eb0689fc58fcff59b168c3871177095c9e496cdc1dbe27fea6bf022e31b2fe7f246d838545f4aa3b951bd37a10aada2bcf09390046fafcda55cce928e326dfb7904c434b7ffe4f2a91c87e59b14f73177737a25a629fb6a4c3306db17ab194cf2e61b979972e3064579562bd412611e31dca8614aa5b2b091b233c5b9ef77ba5ea6827d7c7e8261b547c7821fe7eb03a8556f08bbcfd430681a200dfa7bed8ad206fdcac4cfeb50402b6628dea4ea33b44dbdd4e36086008af2179ddfd1f932ec2880aa0cde78147aea569d08cf5d247f6d779629ab3c5d7235feac6d675b6b25e26be799be72d038fc8368c6df7635b0acd5188e2ccf9adc24c56df681835f2383c583fea120e274eec8bef3690c650b387bf5001cdf4c66d9732ec0b6bb17fc281b52725bc55a088ca0161f11174bd5c22d6bf2c21355708e02a126a39ffffda11b19e805544bde3ad167af66f1d9ebaaedd6a67793776be986386edb7fea81096aa6a55b8f82634991e6bef38635d959cfd4b5ffd3ab08ea88e8d0d7cfacc5a9363eaed77bf550b3ab5a461158137c997baba90a044f46dd146effaad44841cc6d71ac7820b410d038ecb50414023701c6e9c5fe33438ff9909585f844dc10366b44e15625a5ab8ccc50d5c433c12df9fa8c2a76f1a5657f364f94ffe4063f3e0215ab6bdf5130d54e87fd53de4f782567eb9ea0e5e79646265988626bf605c3f5a11bc671e6e034adbdc164b68fb9d2ffd106b2efd8738dd89d9318644ffe377bd0baf9a1f75b3169600952fb509ea1f8d294071e673f566a6ebdf7bf5dfd7f941cb32fdd610f5ea172d55d9752224ce4b984e2edf6cc22204167c54f084b82b743c22de1c90e193a48ba72c0fa9dd04a4bfd2bbe9446190403aa689c1a98a26b1057d7bf0a6189d20b48a8aed42787b6710f163b08ef598fc54ef102a997e474b32fce0f5c2761158dfb67120f7546b9463254469d6d6ee8d77dc87dff86b8b4928f4b33ddeaf2b8c82e66c0a298c1f7278ac4631e9c56309d7ca3deab638a02a3be9883e9ce5683a034f24422a4d70e6853ad6049aa6a39f5b30f3eaf807229a2143725b69d8e5db4bed6e16f5c51e35fbf9deda97f118f44cb498e0605cbd7296b25df05473b587b21136e253018547a2ea9f11214124c65fbcf9c74222e0996ddfa8820ecbc080c449a329866d50deb1d725b6eb9eb4e2df9f85e4def9b30dac3469a492d733941e0dad4132adb3ef6d2064d20a270d2cfc0ebb5a840a3eb39b4a62d72e0b85d0f4cd64ef77aab3f1811e232bd4ad17c7694b32305be3cd34947345b1cd0936ff4d37cdb47eb776ec80fbcb5b08ddd16e09643f3cdf0f5982bf254c9b52c30ca7107932dddefb6600391467b46a1ceb19598479c3647da23675c7fa8e72f8251a6755667bc071a966cd837327456aeee0d9f2389a4e8f0e323f1a05b1f550bd8fc23f4fa50f6f805b1aa099eaa24c1bbfc4eb48f2e06f8d3e82b73be68dadcaa7d46c20c7865666ca3a2c0f66763c82b54b68d66b0e2e8d6ebbed14509f73e79e5a29309c7bbd2035cab4963a82cdef4dd271747c66a084cc880b64ee9b2358ab63225ffc3edde5833b0f552d804eb8b6ab6de73f2c9252221daff0410195d218c6e0823d9c78561cc6982c2741e716235741cb0f4779b05df058512fbd4341b1f583a90b717459f9190c0c9b1f53fb7d8f29c54e63789078261c42f7800d6f49fc8e80c596ffee963832d993f44a3086ba707b5593118c6d7f9322688da3c6ebba268e7bd754576d127aecdd37c7ddc0883c706dd24bc6ed56923c86b8f7ae1eb1bc1c57c246858161ca0f63b32c2d80c2c4aabec58798f419e0f83249cddd6aa253041bbd09dd65901a735d732b085cfbacd91c52cbf290957a0dbe353d6d7b265a2c7040b3045c49d9092a07d38d31ab6f832893533708fc3e1a1f16158900708faf98a9315db7b5e20cef43a11e48748731b8e58c209bd29edc973ec641886ffd376d06d44c4b8f0c4e498db652c11b116454b6e0700fabf318cefec06fe398a644d068a8fa455e810438e452152363089ad298e900a93a351f4108d99dd6b4d72aa75de592b1326af5c97b5579cd71d745468441f9a9a45a94dd145a5c89376a8536e5e19526b1ddf9445b75367c61fcb5a963a25928620163ed07d9b71c366f7184a44ed5860eccad7658dcc7b7d24841d3095965aee54f17d4ae69394a1f8d27672156f27a6f88b66213ddeca0ccb9f551742d4614db482e6edee59e90e3e67a3030ed814bca3626036e70412beef251730f0ecb521198ee23b3eb562dbee2787b0951f55e203e7b0727694cbda070cb313af33fcb0cb3aac871c2540714506a8ae286959a8cd95074df94560d115c9df8ea250cc1a65d3afe789c5f860ffd8753fdc3bb2054984642a87f2e2e8786b08ec8ef8a16f65444bc1dcaa42dc08505ad73c73b4e7ecd00ad24aacfd63c772183fb25e980f0b3d1d71fd4bf224befecddbaf43f058787f14d010e4c5440fd8898ab528b7c0e09ac37c711836b039a188b13ecfba95047c89cf084691945fc4e6db9558e6f8cd101cac4b3fb141539c193446a73ff0414ed0a326897afa4bfa975acc920418b1468e788dfcc4efb4749709e741eb277392f8be77e4fef761e6d9aa74a31acf47e77e31e938db28bec82ba091e4569b5c74b517d715e1a5497c8a6bf1983802e5b57486fb4b8e19d77fa27d7022a2d525154697ebc9d4404caef3faa20c1f62b06b920aa16f1022a671da4f3ceaaf99665c42023334ba8a41e8c0398d1ffbb82bec758866aff73689ef1974d55dca64626ae210f10b37bc2532b5092dcf3ddc50a6563b0a600951469d85026c216b3cd117bc5db34eb6d235081cbd6d645a57719afa5577acb8f6279826816d8a9dfef4301ce9a17be595b260c24ee35c63b7c24c7554f37d82a870601c225bb4a8c4e7909cb4a4f94865c2bb7a93479cdf766637b90a7fd0dc89bdaf8ec63da4ea9c1ad963588ce1d5bf967a6f1ae7e06de66ec96edbf73ba358d4a63c964af3a6698d548ecfcb2c4e547c3ffe8688be13257221809390c96d1b4cb3532e638969c3b32b4329210103e775ef56d0adc7915d068e5af7046fbcfff11dfd98b3710d1df23a53e7b6aa5964084182def285b3d7583c7604591e93ac6c01a903446d884e93b2c992d442bbf8b4d0fe7c5221881a0efc7873927388acd9ee5ac1a4a220a963a4325e07b81bff43646da7cff66449ce4793e0d5ca18acb668bffb7270ea394f221d338d453abe7e9805e354f34212b16e4fe2d6c7eccf35a1ad8f61ba58b517ca87417fa8789dc43f7f4a47f4e4a698ff732b8c24d586b4d7453da1409d38cb1d04551f830321e6fb4f10d14f294ec285c7c082e2d3178d559159c9ef9e3d1576c7a2b3524cdc461210d0cd25c7a34c96217561377c4d9ad34c0ba3d8a386b7d130fadf718e8ab27b7dd95af070ba3f00ee440edf8f9316410dfd6875b856eeb4f91512c21ab069215fab1baf2675e49ec4f411a51b8d5e75d719689d8cce8c6afc2f835de6565e76e1643301e95add6e9f43c61fda193f5a59923bbd6b0a36b9647c44ff853c3ff057a08e15ccdd51791692650aadb965b1a898af1d3a57ec88af76e729da237822e88f589411c9b182d060a0db32887a252760c954f2aea9e199d34e69d040f3c48610fbdde550489d77b845facaa314106760f0cbf01bd64e689f0b3c267ac6874569afc8e93923bb2112d6d79c43f92675ad9831f95e3cf24dba5c2223aae3c7dd48e2645b066f8e8945ce38b1f5a906c84f953c6ac7dd16d027a60979defb5973bce6fa69d052649e76af4ddb982b7169474467b4d6f681158eacec1294a647389cad4f1202250cdf222444a6492ccd90b18243f6799bae1f40b0d121e23519a9cc4e021242f78a5fb00000000000000000000080d141d272d";
let GENESIS_VP_TX_SIGNATURE = "ecac5427cf16b7bd216e2935243ff881aaf4dfcdabc96e30d5fdfd5f3e39ef72876ef52874a4980c9be7e6098a19a64d19df7adcc59afed7722641855d4336b0a16dec0ecc4095a20aa035d61d6de04c6c5a7602966e04013d0d18292e1914535cb4daf5297e4685488408daeca3295d8833d024a07270aa34b0ad3a4b0742213a23ab582f4d85e776416483c953dece8523c9713ff6cbe89bde2cf967018c85dce8c4f6eeb78e68637826c3753695368750d0346707147ee44c86093c9d54d546b57ad2c214589aa03a48ffa683c72f9ba7585eab89620dec60ff7670478e462375e5cbc9624eddbcaeca5f71fe036a66054518e7ad111f8b0acc4ab615a3d28835c34cb9fe3b3d68078cfe1b7be832ff68f0c1a4f20faa3f0a4ea0d9f5f384d659ad29b4f1921d1d0777dd124c4e53ff46b76ed9ad99813b9e993da1f7da7c78a607212eff62df01f3c6e5e1fd3f35911312a8ef7ebb903436c4b698b240bca69d9cc1bb298ff8492cea66cb72eab44518a44d9af96ced272e38729bd09e9133a798af6dd8852ce85eb5cf3599ed91b648535935a38e345f65e89fbe5cda92f88fa8b0433b083d7647c34412971e83eda258eeb74dcf276f548a44e107dd4b50dd5db04ae52481bd435978c779eb1a104b7c400fceb9b61764bee5802fec50198a4e0b59bfb229a472898489cdd764fcfcae1876da7fc25ebc6cd9734e3f2317a26f0acd06b19aa279b236fa9bf1d75690207e21d5fe36716f735d24bf99d7e034ec0f01ea436f2c697b5b2bd8693a7d0ceff3efbfd006b11e48ac9c4ad214fa2fd0a1357e9326d13e4a054638039986a03c741416f8a15fd197488379ee4287adabb200d715a4e1cbddb8ac3893139606c4ad0ddac9a4f71bb5d898ecb4bf503c6be03e0736bf3ac4b166f13b1aae94718609eddf3c852681e76cf2704fd8eae1d40484af63568cb2cca1b38391da6f974c80a2283fefd2673f79eea499714600ecc89c201c37590c7be08d86d0ba160681e783b1dbbbc9a191ddba647718c4b9bb8ba0f24ffd8166027ef1b636a2039207c75ee3e9ec5da3ee1211ce0a8342e6d78f0a54eff7bebd1f222fa303e3b7bac3f311e1bc2fced2714d793bfd8c7717d0f8bafa68dd18b000105e6854096e8846423d1c5b6a500656c9ef49bbfd25c31dec6283c1127e601ba16cb3a8da039cc7f6d665032be4a818401b8964abe7ae8765de0b94218a4eb6d947d6f3b52974b1b35f9b0c59ffba3c86d3d5c36602e82572703cda46fb9887a939a480ad2855b2aad3992c1941876c615b1b04900104f23f9b61bf84e920bda65d5b002b63e3537a8b2f44eaac16281cd128db87c10766237b20ba0eaad4272eef8ef3d65bf8169463e80027b8c22906e000465bb62cc0cbffa10be64857a4f983f5b62e9097238624a8ab2c96bdcd47bf0e2219b16a2bf01977025c09c5b151657c96c0e609a01ee415a66aadd8df8bed6cccb1f40f7a44e082f9800e34ee517489087bba2cc3984577e0253f34e42bbf49c3dbd90db7009f03b6915bacb0765520698b219b7241504102188513fcc03d5be1204020e7d714e31c02098fb21df9be3bb41aaff3f69fc706786c8133f6b42774352df7921a1049eeb5fea129bcb544738bb7a5b34c27ae1e7a54f0c3d091d1ffaac7dca04a74592a323dafbf7824026de026896db1d56acc58903d0c9e5859cda5f13c7be09f6fd0a96cc3f36a2ce74a2dc4e4cabc8cb5b73093bf4fad95143061eb965c9ed3e101253dd2ab0f8ab92438c1574317984d6fec8c75c4bc86ea690ac089ae8ff436f1709132033c81fe9be234855b378fca5bc42f610b3bfbd2578e334d7262d3410a188f849f2a376b3a768136d094bfcb867ae02e3408beb51606c76c0f893abb4e5c9f1d72d4c7fdfd91303d01f8ef2fcb42643041a151997b4f38ca8d67f22b00de66888aaffe173f127eb5d46a175a9bee501f140621cbd57cbf778622b0e65b495a3b5f572145757f509cda49d388bee5c45feb55ec2dea940dfa0409e3a2e05bc4849ac9cab378a4d569f3953ddd11a4c73a70d90cf9dd621ec151051ece52f876a2e9db1e23969e3114e61211b934c69d3ebee8a97865fb402366d73e3b679c51476ef3aa58911258f88774e6d25a613584b48a00b4c9a56f60c88f3a5a0179e152e7ce4426225adc9a65665b0b8218eab9e68720e7b5dc926ef0485f21d534933a0f52424a40499befce6e06808e470129405f870ffaee2ae52abccbe611a5eed18c19d323b1f9c54fc4f705b7940c64e9d33feb1aaf91d9e4ac6df6ccf36155860044cb81e317baaa290e7bb2704c7bbd5f06accd30d5e80780826342a8d0398ab9b5e92b14552283529eaf0ff221c21bb8e55fb0feb3c43568495edfb4d746197e03a6edeef43b571b6cca9fb84038205ffb701741a0514a010682971fbfbff63bab12038dc437b9a59c228fd555de7a3caea32a585cb721a61659002307c7e890c9e1389ed8a975f52476c6181e756ea887e5b58ed3c8acc2809074dfc1298fe008c2b00b32df523102b2533131476ec1564eef6af8d8b6750ef38d2887994c7579cf099e03e192521c3c5fd6dcf766674d1f9721b5e77252f54e131a9d5b29177470ba474a036143a85dd83d1145a57dddc1f90e87dfd4878fc5b1959ffb7b60930ecb2e4e450142082a4b5384244cb31c43455e73d9fb2b08af2a57f2b6c293e37ae708803c3694cef81d69359c4104372e4e5c4c9c5419dbc392637e3ad970954ccc249e46646b823b7675009e16fbf6d6f6389ecebfaa1f7f9b79588737e9ecaed0fa63f39afa286bda01bcde6d90efe00a23cd577a73e6f77435a2124f9d51a1a4d99f4f0ef2377cb59d7be57abee184a8dc93781aba4271d51c042d331d97d286ae02302e633c006e4c2c71685ed37aeaee1a9a28f8c9d904aa4a56bbd92dcec499b42e4610ac8e9c996fb0c3f4e5648d115e61aa243b7299ea2676dbd6e75c7b07eb399a14def231cd3a1bd14c0e53a841696db7a4089896094b3887a77b9747196938469c21b027ee8b50322a1b95e31ee42b7e6fdb6923d56d84279b6c750b6d3d113d1d1e8a85d4a2ccf4b787a095b39ffd353acb639715f1d55a8890de8c1a0d2aac3802f61acc3670d6e0ad0d3d7c7fe5f135ba7ecec2f47f668e222e9bf2f2d44d7ec2c87f1b5e7efae354d061cd2c09ac91dddafce86d3f4777986181214048a868ffeb371b6dd1fe32f56e1147572280f440b79b61bfc2943838ee500bb4f68c73e15f7278f27ceca21c26c0fbf7ba26b1be53575e178db3cba44eaaae7b1e7e75f833c376eef28922214a4c0486298e133dbc107fe3d553700833008e97a2c1d755f9630a0a73d2a045cc9e5ff099d53a7848706307546d4ba744388b32f49c7d36c0278076ea6e1dc91d553c6627e83ed3b799cf5386ac14c8b53157b5ceab07059edaf374bee964ab805d65780578accc5ff9f1f74247969b0b2a4d413d0a0ebdba961fc9cd7c282a776f9099987b14dd16d033da5a07f52c7c82ca92eeb7af38a7d24b64b737998df6c04382868593515ad0862d31004a97dbd90ed6548f5506972275323e33ccc63c3ef3dba29f4abed8b35d8cb816bbfba5a020529918626987d4b46bbda5b063c2765812beaf02b6b67d36b8fddf21b03c43ea79605ae3d9557393d951223ad4cd38470a567c058467b894d651ff9b2bfa39ba4a1c2c03f26ed2e8a6f9b727a72abbab54ba13327258c6479e02b73e50bb67059cffe491dc950973355c896045b0478e499ef44239ef35db48ff8a43ce11b12d3788a4143e1e1c8b01ed8eb870307bde5ce374855f46cddf5297f31eac927d54d8eb00c7414e2765a85225f7bfb9667fd39b3fa1b7903951b9d032aac6907606428cd656f1322817a0192352167681b3b69f51f57bea53c8ed70380b4caaac3e11ecac97f6b9fa21782a120d299e357d77b8276e5c6cbde5dd932b609969c222a2f0ffc595aad78d60d1b005692f6c7ac6185699ea9741844f0433e46c6b38d1bfb87d4b68d5203fe0400af6da20b6e08c80d9e2c45272c4b2783a34c75a79e227850f52933935502658473d50864e144c35e533df98092c280ad9a1019f78aeb5ecc79715aa09fd3004b4675824b005667ed218d8f24026d055f6c2a416bf53381762d33b9bdfbbd9011720f53a8a50d29d095cbf8121b7551e470bc22bdb74de150ee6a6fa22da382f14ed9a9436704d26fc1169170fdea16aaf0f8a5fdb84cf2279fcf9363a1afde8f07e19bba7c882aab1cecdfae6d85219248ea6fdb0422b5d2c792dd2dc9a05258f26bd81976f87a3774861a9fe369753368068ee8e4b68cfddc4b261986ff7bcaea904b93c0e0aab062995fa4829a0064119ef5a568ac00ff078ab937a7b1c5635f20cf40deb224c3caa9ffa4ba0840962a8e4abebc760180ee58fa76f6ed0446596ccb0fa0977f6874ad638d84df63f9fa00bbd1c0d145fb3697819ad557c0aab36359f238d060bb2629caa70373196cb9b2d26389f75f0bf3338b15c48cd3a536bd09ccb1db4d1803502d68ccd7849c92ac053557aad23ad071d406f8fb5ec006266811f57a1a8cdd7e03f448abaccf65c69ebf80000000000000000000000000000000000000000000000000002090d141a1e";

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
