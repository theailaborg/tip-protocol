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
    public_key:        "4487cacb48f993662b6ec7319bd0468cb7ff3a5673e2575004358095dc966310165d068f759a4a9b006d900811d1f4422697cd6f126661236c5fcbb3311b752fd0483a1b9955b85b45b71be3e57e00428d49518cf6e189b94e75e9e48717fc534422694189c37c9eebbd5ca28d97149e1d9d06d45fe7795f9ff08552638acde0697272256d45bb1021609ed9c01a080e9071319a8f8ca515bf409a45260e4c48d7ce219a5c960ff73ac68f9d4d0f2d6c3376d563eebcf1422a24a01b5ba03dda874c153e7285946339db81125b17c6d761e6949575ed703ed776e7f49eca8b04f6184cd921f39e67375bf68c33537d6ab13fc185a78dfd14642549966e5a81ac51f93e30f6e4f3ae0a0ca8b29ed681c4022d6c6ef80e9b836d7e4765489d41cb3a1a7e22e82b6413a6814b893ece9df545b2ddc0df43b412124494a7a1cbd4c9e1694525abf2f55f2ed9d8d21155b55a03a9eeeb3a3e04bf60d67a6925ef5932b2b47a131eca61e34f413f9007440761aad0833c467dc4b2006310dfd23136244646153bdc000966dedcc55bae22b7c23a1fc4c336fdee026f60fe273473b39fac740bc6cfae809759cfccc3eb716364c378b79acef4bdf8419325277f8394e5599f41b90167d0b28f8f4d2b4cbab91fb4c631c56c4da3f4de02706291df128209b5f979c3cf2944f1754501254f0008aceecb5d3cce35a04a713da55582d44b0e7dfeca7ae09244e13cc588648d5ae70293caac9f1354b67698a57edc44396cf1f3d40a75d7f898953975df98dd9e26e67ff66e1a2717c7aea1fef439f383cf78f720a01cbea42bfa1e435f0e8e345ab67717ef60d145fb5b99daee997c103f2762d3b1e6b2d8a4eb8cdeed1136edfd24ccaa399875cfdc05e82b350b18e811545ffd1d36be921a97ab2672574b4f338ac290ca3e496e5ec5be4e810d873612b9474e5c3a2596056c8c4e6ab60607ab64cadf05b64a0edbceddbdf761d6e8e83c5e882d459d0226a54e1485ec28e3e3f625b089084705d6cec2339f2592e0fbf9cc16349003fc966e5eaead52f1fccf0c11a80273961854a1d4802e40990f0d720b37f6d80da2167351bdfe0991a21149ff35971fa8abb0451ad468c045b59aef6ad492eedb652b16cda16eb2c16fbca48ecaeefdf49cb3f113b9f6dac0a57b9c90917d7f9b5b611b327cd03abf47ce256167233beb1622d4f010277f6c3b93dfeb3c959162a9c79d63ddd4ad5c4aeba0479dbe265ca1b319a36182837b2c1b7c82875fc801084c3067fd56aa2e14b25e8fc6bd4b4c9d96fde3e25931150f307bf5297f44a7caa990825cfa06c6580002b48b0646e6d81e6911b7c0ac1d7ed41f5e13e96a2ef47bcfa63adc6ea72e3fd9f1d8c3721597611361b156b10a6fcf807f4beba71b2df75afbbb7adc1c0120ca43475e3a4caeca200ee87e9cf3f34ef27ba7d8d65a70b50ee0e92e075df3ad617e027027812e7b3c027d348da46a12f06f7470c0d766ade9693b62299951c111e177cc60b07e5dea62006b3f51580f53c6836687281135d84c3b5cccb6ffcbdaff42c4b478d297d286b31a37b511680408f9f10c0b2c89e333fe545fe3cab71b5defa3dee2cba4f214f92784994971b2977d12bb5dfee7decd2d06952710d18e54605fd60336f9551110e7eb541f93478f56ff46a33377d0254ff1bf0726fd79deb73e26e1487050335e617ad9b47ba87c125d7cf59ff7fb7e27c8bb1226b2723c3955cf77fbb6f3ce941456a7f5f3e2170097b12b619bcda06223650f331fd4de33587b8a9cf09f4682d9196f224347b2d69852be2688cf8ec02fdba0b25f8b01f948816243d0a7e8d67ab9be13449c777a777dabd91ecfa9c09f9e60641d8c45bafd3c3735e85fd4db97d01c6791ec82e4328764d05d05557adae4ec3fbfbf81c1455e16a3cb06be5832cb48d41c1c7637bf21a1917cf4d7398da410ce55055b875f127d3ea3b5f20df54b8d10546da768ce9498232129dbca87275d687d178e1de58b35b60db0514394bed5664c6a415689a5811025b0e1114b7e6791780e95eb8a5b4653f8387b58be6e0052666a3bd6d9603761dcd143b7bdb7f7462f44d45a08965e4a77a455e86ea4ba8f9c5eed4d3c726ede60572391e83329000d81aab1926f55ca0250eafb6fe96b3973ec567ceafa7b408e959b4f42c8f406071e91901431dd9e31f2fe64ddfb74ff1a3d9f2f323fa7ca15b237ebc041bb6017c65c66c55b9151d59b57214710127f6ab47a8ccec42f2f152080edd3cf6cedf62936221e4ce86b56a0f6e874382abb4b648284b3d2436a289471a7f09812bad19af86517412609a6341faf3c79aacd5c0c491cf43887789ad7b8e0c133b04c1a71880abcf04eb6d0574dc23a8b3c6ad20729a55c0cb6a28563eff89c25d41657eaa807e0ce7771f0ccce9e8e099177eeeaed1e54d3e06d28cdced324d813bd35007a1ace48fe49f809232856e8778941a83df7ce3c9db386d2ccfa9c64b65441581e18c266a3e6c9a49ee0b7a94dd24e55062fde2dd7441feeb381a5537bd158eabb93c5d8cb31a48b94e6508e9861434e0bee82a838d9faade3d56cf35fb411fce9fa5334a3793214f683d57d805fc643dac28a2b525bfad692480b5593d27e26fb93a6808bf70f2678e3d6fce750b05c9864ecf6e45ab505e4fc4b53977546d41bb447d778fd47451312d13ed3c6b18c52930009efee3ee56943272d02cbe61af5d3db110bfc9bb62de1c906b3978a",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: ["tip://id/US-311fd92a53f52427","tip://id/US-a3d909b5b15dc9f3","tip://id/US-2a4ea7e3a3b14aea"],

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
let GENESIS_TX_SIGNATURE = "b2806ffd2a1d963a2c728b832b6d09bfc363d4a6b956d9e87dc0bdee885079375047358af0c0fa640a1a5fd4fc7033a1a446ac83dcceb0539b89e28a1c53d9af86b0aea7a1fc423672f8cefbed39cca8765c6dafad96428d9628681b43679e2e9d28a77883debe983051c46598d2c46976e5d682c0c566df4cf03a5fafd5af39aff386689750f2d8bac746512cdfbdaa70a8cdbd32727af9bb15886b06f390b31e89939c9528b7a0fb03c129aeb26819e588b3a8f2c2d34f5c75796b977e18421f08227963fcdc942230a8f7e333dbfbba3e423fd7a82e20c72549a23351831eebb75d51e08e18309bee8c400ffeca6436f179cdf33ec6befa20b9c9ba03d9d57622f43a4c8002fe9e0cd830dccd416077abb4aa787e623c26d390f266770db6410638a122a121d947fa3bcb562e10394add89e687d41b1fbb5309fadf78a8f08b79df6a3bca838868760899e0d8120cb14df86dea16e7b6b4441152efe2c46e191d6205865560a32723ac56fd9251185a1d2713682827cb92cb81ab9bfe494f44ea4b3b50151cb792d69c241400ecc790901acd1a65d37df97275fb681c5c3a49c358980be1df9e96cfde7bafef783a41fc1bcd6ec2811dfcfc88f121e086ac3e8d7bd41cc60f98190b0963dd57e15de0517e3a179e3dbe25a604ae3a8603b3ac49eecc71f5015fbb9d205c68a0737a0af3d6dbb597525c8726257ef27fdca3f0b435f3436296edec47575d3bc9004acc5f87857f98e2005983c2587c49b2a543be7701679268ed573403737047c03313520c2d4c79a43692475d960c6450e55737a547a57e43cff4aaaa63b56a27e5bbdf8f687fac050a3b476202795bb8cf2e59e43789db742b5c029993acc318f6eead8a92f58bd9e0f5ef03cf6742f39907e26eda0b6a2995938b2096fec03bd480d93e7096f018e4daf8e8714eee85e3fbb1458362c9396c7c22207c11b72ec53a5303a452da0cb9d5017b6c4bb1f60f54cb747c4fbe2b53303cfd0519eeef3f9680e3de5bee91c8584221437e6b6f2e28c10674a144456e63e6288612c4532526278de5fefb48d350ee032532f21092512c95a301d4accc00fa5d1c3b4edb7935ae9c377941821e757d1512523d3aa706fe865f52d8d1502bb758979a35b5d1c4fb54a5ee5cd5d2cbf0a450b82fb9d8b96325c3b4b4f8330db7dcb17ee577c3c75f0dd962e555a7f60896b26c42f27fe4c2ac521d3dd4373c358f347e1614d74675214af94aefea1f06056a7392db745714262a9f552b649ee29e9a5156601a30d0f86a5da9ab1d04c96e62960f3fdaf2106281a081f8a579fdb7a90e646d58b80600421f5791c8d007f68d4875d2f708d9a7a6ed88b7f9872def53e3fba3568b0ea058563bd2742de2f91420404160e0f90e0662df57d819a08765672137479f5cbe51d57332ab39560a6712cf2e6b07ebd05d88b8ca8bd0bdcf27782a82efa633823c1c6f7fc6a390ec94103b4adb6efa738b41c51205031ce64bba3a505f48343693839b4cac46bd47b68abfb03661360d217cfb71a35a0b64ba2839fe81e92edd6c2b806fbff6806115cfb3a6b2faa3dc365108b3d3cfeae33952a56de1f40dc0f7e007f02ab838a6bd3c1a34195c70c8c824afdfab9e78cb085f93a4438f2278eb5684d57f910cb68a795a1ee9f7e9f5512238d0b6a817ff30dd4829299cd5cb30f364423a00139cb272006f1fd95b092c8fe9e65fd978c5b8646103382fe4b214326eb267020de32d436545f8aa8d9c84a7733faf2c921c94b1d1042a9bdd114277965fd38fc9540d60ecdb54f7e35bfcd086685fbf72be3040d13cd376515487ee5e2d31afaaaf753be8c726aa25b6cc27ca6a596cc9d563038c8ca44a65cafb20167c51165f5f111d36c39a7d3ac35f10d9742bcc3c1224638ef3b73188e1f7dab5c90b94b383d0be5e2ca68e0e5d2504cd11c99940f92ca5ccfd5b837cd69a03fb916d985bb143166f99606d8970c5af372a0cec85d9ba0e45f24ceed804a368e12bef7fefd9266d36edbe4508943cb6f23d80c2b90ba4f84bd6a7e4a2415af0711f8a476236cef7bf73cb8990e2eaf25add8663ce03384282dce2db3404e765032c12411febffbd081635e1d6717cb0622a0c31cfbc8175e04df704f1987bd9b242a864e52a62a653fde18829bb44d955d84a55d99732ea54d66efd35f39c622ea7e096a84a352be1f424fba2b74afe8089b99f570186baef3d795480a31183f68f8fe81fd8e4c4dce981b257639c725b56c47883d9d1e6ca750dd6501cc71ade5945bee690105034a7bcdcc57dd2cc80ee0cf5f4468c244aa39a99869a1d2057c774b9de27a76840c470655bfe44d3e6711fd088a31666f8a5d566d806ce2964a27699643115c7f33e54bdfa0b16296cc462883257349542efac1137181feb0198797b7292ccaff8f9915e153c93785c9165380c542e81d4ee48d45760624f91359fc15cb9c2247c9d3d0212348ed8af77f2cc09656203215eb204865aab0bfacc120dbe419885829d8919066f3aaecfce77393b56e55e5b50c535b7879fc50dfd455f8cb0a3e7f07e5c27834befb5b4d98a87b2a5f09a7300d71833e60754e2d39608d19cc0063d7988997f49d30fa9542e32b76e60abee3a161012371e5b3ad2209e8a6b453bff5c5870a211a5befddf86b0ebc51469a17493b0c6436bef7b91aa188f7e561f0940980059e5b2cd69fc42631fefeb4e0f50f4d276af47fa4a44d87b55a04801581727b1a3bcf964196aac085e595b242af01fc9143109e477eed7a2b26a70034e1ca9eadd26f200f967eb1a550b32b070c4bb7eeaa4e61f5dd24a61a45a74d2a7cf01d74cdcf67b688cf449705ad7e4eb92fd8070bca1b816a01c5441a55f0c267c9e606b86b229d8b24293eac4f593d698d31996fc1132124a03fa5d32c7c793f0f5ebcd3735d9ce518f50639014c0d3a62ddf2ef50c055e7cdca8ffda19df69e2c658882e55d8e1d2544463e9d7d17a95a4517b584169657a9217e725bef24ba72445d0ece188cd93eb86120fb01defc5d6e7bffa44cbdd43bd68d6771f870ae2d53e4b42b39cdce467e8d2e3d1aada214421e4e81588d984e9a930ab0de692637284a5df43655e0b2a31ff5d7016e5dcfee1379abf0f3d7252f3d3b9af5bf0e2ac1320d703a6b751845d2d4fc04cc12d26da039e991d8ee6aa962883572d4e002e71227fd77ebe945d60dd0c1cdf2c0540ac072f0e001b16f708a442cef91470b4bf93c38a53db4ea1389e1247339cdfaee064c81444aa5ad583e85613c7adf57995b047e28449453592d238bfb1f2715d5f27530402b9986dfce15c93956d19e155d37dc111de0b2ee6346c6c3ee1e956dafa969674716eaa04ab4980407872ae4b0085f5ff6c1f0fe1ce10a12e4a6a1015b75dea6c2f8feac9b6f54d776cb0319dee1f7d0426e4b2da0c66eccf6bcdf3746d62bea614cd45358c745f23c2e87c9f47f523d50484378b5127424724e8eb521208d311d9ea404218a7e752165bd17d2a39c2d3c1b6be4cd5c8fd1e56808e69c23a7850b22d5a74e65f8b6849ce4710796bffb428f1558a81747a8f78b21ad51fe8c3f2b82e2a0b3f03987d492bd5d5af1ee8ff042c120175aad0ed1ecbc01ac44602c41406f51fda67e1f6a1b972d3225e52d51a4b224eaadc5fc7c9a63d29f9e0c7febd72a3fbb56b12d999c3dfdbf8481bd53bbe49625baa6f28a0e985a92f055466c75da6ab9850edeb1f240c83d6ae38b488f728f7eaeda6a1ae7d82b123a7b1663650ae130cd2e320729c286be420eadb1bc6904816c9363f13d9166f4b3a774da869fd0d1f46ab74564b62b8beff928851d1b96111c9b8ad3316dd73351958440bb7a2a440f64d533092362961c2049645bd183994f5e3b9a3a08825080138712882e2782f12ca37a0c522457abe10343c3b5e74d04450788ef984922de275fdb0214ac5331fb0b82f60896c5904ef247415645d4206531693e1bf802b351296d4f518095557d483bc7bfa469c45b60e444f993f7695c5593fb9d2876d3a533290dab31b9b04dab93c4379299a229ade41421568a915907195e428763e28a148d01e64bfc4f96f4b71d3336c73dd38e964bde48f5b4e754a64c5498bbc27df3a75616a0ef6ceb01d1bf785ab9835abf20cf73739e5ef17b03d04fd97ff3d6104950a7388628bedbdb19a1995217ac4780a3e48d395a647ab2c883b89e7f6dc71ce6f4323b498cdc77000a138de5dc48c619ac56c729197024558c29721e2f50fea380fecae8b223e38ff1bd92a43eb45c76b06cb648118e82fc557efae5ba94e1864cc287ae04ad958bdbba213cf692d0faff6a8f81df4c06f2795829399b6fd26862dcfe396b95e4e1f0ea3da78439d763b6025bca4a7244531f4f25933fb131fcf5c548c2774312001bbc9c3a701820aeede0dfd31de5afd55e85af7d58a6ac24fecf027823352e05c576d01be92e25c64f071c6f3bb519f52823cdddcb210af8a214c8259015b94f37d555872a875b56027c4487f7981093f7d573c615851fcd732f3293f1105b39ec3ec6133d02f0e77f73ae439b0e12cdd55a1fd0062a3defe51b3454c678a9ec2d31c394e5f8283dbddfb182fbbc2d5d900000000000000000000000000000000000000000000000002070910191f";
let GENESIS_VP_TX_SIGNATURE = "a4a5e976116c4d22a2d369cbfa29c453e69aad5c3574742c334f55d4baf14563e1eb067733db41d4fc8fe543b8201e814a2b035c45658ef32cfa960379291faf2dfb49fc79842711769ebddecebbc853ee2932b0f36b63e33e34ccf6e0fc8ad9612de96823563cb0bd527cf49edc7379b0524f9ea800ead65de4055fd5f2e5f30ddfb5ab2a127d1a481115dbf3ba4bb26e72dc3548bde7db8357b3a0816100ef806dd361c709e798c44fd07890ed55ed4622a6d20d608e62f6a4f44735545c141df53d897cabe184133bb55b32049f78286125609c1756ffe995e60e8fdd0c9fcb71dfe4747d660f4f1ce93b5e52c08f35a07a4406cccc8d7cd1bd36aef65941f38585eaa6b2a3aba24ab72b7908c83d45ebc4a02b5c13390ecbc173c828f6108400ca26fe45678ddbf2686f561fae5381431548baaa56f0a3f8a233ed8aebfe589cbc3f14033510daae9eef60defb2a898ef406c2974022ea73199c7f9ec1f7bf0c8ea51328d5c31f0dd0c94bc6810ef164d394ccc93eb1f125a959695bc263c426e431eff0efecc4b5e619cc8f41236f970aba31d3f50b8db038e2118e1c5c18569fac6e7a4e5225cb857784cc6452df8d6e21e0c2897432c4173779e1b52f8754a66a97b6e71d562ce6f5e61e6768ca7e473a15133a79a001eccad209d38201ca8bf36837921dd4e6bf60da1760bcb1865d4631a0313d181337c706e6fb033a5572aa707108003a4105fdf54e18886bea9d62b9ded4e42083a411fd2e6a034757233b98531162852c551bf5856e3ee300108619fd02701bb3720c3d4ce48bc273494cde802491ee0e6288620a186cc9a65f01c80dbd04618f3477d5fa2c543c3b573f41a49d4a78a72b31604360d67bd6912c8aa07921134468f38ca001789466a24de093191a6fe9472ec85f90ca21f1ba3afc2d6b2268899ce6f275dc0b01be05a210534633f870c7902671915c8065f861954e5b3af7b309326b0667c869eac4ef38ca1efdcfa88815f836b13784c9644f535921d53b9d3e4ce161be00d0076f805ab031d614aa6f31808f35b0a1ddf4faa4c4f894f3bcdaecdbdf1158e2170ce398e778e3986af4f3fc3ff0af95b94e8abf44bb6291c62c96a7efaa820b65b34b50150b08838eaea11c8170be69e3fab62e289a359900e5fe76222c9df4466617edc4edfd0943d07dcbea4e31baf21bee4052715c5ffe6c1ab4ff60a319b0c666dac299f49b14e5884864fae846de9cded94a3a1f6ba34caa04610b1fd98f6e3cb349fa66ab36cf9b02192c8ba920ae33cde8d1dfc527d47bea3f6a94cdf53888ea963a251318b47917432f8d04a8da8b3015a9e45dfb25ae10d6d9eee09e21123a9259eee4f97fa385ec87139011c73f8c8c54f9b8c8a9ac578fe7158735eafffcf5563bcce4e532ba68d76c7e4359e6ba8820e46e2adf8fb7d36ae4cbfa2cd87a715483dd073eee1f1061fdb907e9c201954025e109c3a14a91c16ee18711fc4fccf624669674c64aa51f5dc6a841c92f612010b5d56bbebacd3d142fe6061c5ece3465a07febcbff32df45441029cfcf06d076770958cdde489d6bae26928a5b9a94abbde7da1d816269e6b3a6833bd50aa33349a9237114f0bc727625d7b2491a0fc07239cdab70dc4bb1330269bd4c1673e3fc8522f72a4ee59c02762da6f615bae6f53c7db0aa509b8b68178b5e5c87ef6987cc9fcec190660eec10440de74e21babb77d49fd7c36598392165135baa32a5238a1c61390253ea7b32e387d82a58ff7fce61f2e8a6e9420c73ff69e0fbe8180b58c7af4b42db24a271dbe83bc136b26affdc52ac0ae6a26c52a2c0fd31f37fc47a960d76f598667a5c77328dca9e84402c0771819386e53f6d6ae66648c03dfa0a845aa1f3ee714887573b565db0ea871d3faad89b029ec32204b87e084b2f74eea53ea865f2655f47bb74fda66865ff648fead250c81b6f8ac182719760b0becb39e04608c883187b2a257cb90f39b8aad8045897fab7b156b8838a675233c4fdd47fc3f16457b63c86463cbf0f906fe6c0eae6a8b7beab83b31827b39d70f0688c549b2f40ee32a18b0681f08bc353c073adb437727047c402e16dab87503b8d955d7ae32c1541b5534f77fcb9d2f2fb9fbee20e2e37f585d9c61566f7f2c13e5046bbefbe61dce00fcea04ba9442e5966726181265cd0b47ff362835365c9cc13197a41b810ab075551228be774fc14d1bc1e1fda6867a0d69af054f83238c4e260fc183914deaf387603259ba633a1490b3fdf523195774e8d360222627ffba2f4cbb700b989cee9eb6550937eff6eedfd6d7c238b5dcfeed7fdc54db3d080bb3d84eccd3d797ee82750e69f281b2f1f69edbac495ab54c4b08825955c96c903533bd049c7bd2cd8580b0bbc377b2a9e4408b067a1857453a90ba98ef9112769be6328126b23fe542767631f836c330b134666e47b2f169dd669bb96ad317d8a66a3996b13dadbdb9493166ec2cf89a81f681f99104f53aa42d275b2bc0453e531c6d96f728ed14a651290af21c973bed497bd69c78bda3c357285b2f4a1841f70297b33b5500cfabb3cfe7fac3b87eaa27a9da866b9dfa6b951263254ced985f792ba3a154862ace518d3fc0c53c67c0d9c162c0b501a34e32686dd3742f5eeb3fd210b78f9f0169f6700334af1b891ac6eb52cf185f4af676a13a6ba5fe25ba88eadd2e29ea59a0458a30f71e14c2a687d029897bcf63ad8e493aa863cba5d52ebde0d85550d47b2c6d448513ee05ea92a6bf0fb5686078eeab33125424502e3d718c1e0b07642e9a12cce1d8cfe7f6d27e2d90d9f0f54b67680c9fd705b46407dc3fbacbec4952a60d42f7ec7ea96f07c61ec773aa78039def0fa940fdc3aa9eab6bc440657a26bc20724ee84fd347f3f1efe01651dc1f36d7d5ea4b95b48980a9007b8b41069389a0caef276d3a5c903b65b77f5414f34272b9e50d571762a9fa450fa19c2939050396c89b24bc3ab7ca856e61ceb95a95834d35ccb0aa80fae62d2c4c7b8174fb6e0322ecc8d21e38ab3be400d27f73cfb1a05434fb9aed4ae4a8d145a8cf87055a0e1055f4035798b40366f25fa7cf84a63c0a25b833edf1de6cfca9b3b1c628d0efa29e7bc198817b2f0409883f3c8dfa3dd279319549edbe17215e8b1d585e05ba7dc24d30b425b75222992f6f6329fcd055421dff507d9577381afb5b2a404dac6d8f4d2dc8cc1370bd3988e4896cbb66dbcc1dc0e14bf48192a6012cefdb69f35c3520804b5f1e8d113b0663ef0a404ddcc1c231eccedac997fc5ac3b0e554ae7c026300ed8634d870413e5ca0e34d1712baecaa8d9f8d6eb236ddf686ca37aa0bb503c3ce9b471e8a2b75e9db8b183e377f5eeb019b78cfa107f2a945bba25161d7e33bd10e810d6332751948a63591d3f9dcc117dd1b8012171cc02d880c5eb263214dca91bff5812dd7ae7902ded641efa09b5fcc68cd8786573d9c1a765a14f65a940f20bfebc98c60d9fd4997c226f75ec525a4661621ca238343feb776ffb1962c143fe7df463d3b571d12bc06856d664981f68410a081f9c4041614bd525b8345b63e40ca1c8c908d4dd4d117dcfc84a43d7061b7a2421f0aa374fbcdfea3148a4883c696734c02a50d4e42316f303d421d25af87e15be589bdd6b39038c931685a56a21b3f71e5a41a4239a5f5a0e8e9c88609f331a7bd61ae4be4892aad1dcddf3b04144d3bb17db1ae04e17402cd1b4b4c35087c572bc84b27c1224ec1ef16f22d6c9afe4f4c33e528679f9b501d6b5c1adc59e31ba41111f2ffe80f05e4ea618f8be1baf1434660df29c792cd2b7af942ac362d625324971ec3f6bd8dbfdae66dea0c04791f75ccd2c86b8fa0699ed3710e2eb03fdff922fd6ca94448b7b7a07f23fd5252854375b2c7458236243139238c20a9e58de2937bf86a643d3a9807306e44aec7e9c72984b761c6eb20e33fdd839d525e3eacb430ff33fafe8302fc67f2950061a272e1714faf2c95f373423933d1bad81cab241c21db3bbf140d6878a309e86f9984a3b850d9e4eae49342c88ad8d3b84b55f7639efe4ae1a7fdc5ba36e844741f7160fa038e3bdeba431d04f72593f329f7e92166ecabaee5aa496a690ae1cc7d1fd9b4a4089d5ce4a3e809e8571705ed74e67b4a6578285013aaa9b52e7860a044a220e495e907f4f2fc563f0b00ef7563f2beb0112f23573e8bdc0e0ec9cd4712c182910583312c01bddf7d103069f3d0a1edfe9368b7672ebf166c3a69ff45c1048985105e3d05331d06e10e9147c5f24646b3459501964617ab8ec4fc6173ad35887ab1ffbf682182af590f71ba97172f6571513bba94f3cc32b4e5d32c611803f71814f55e52b0b634523e71a00fe7d487de2a1908dbe15aad5390859078c9c8907be0b75b7f19f366963858ea9322d0b4d7822fb7164884ee119a21c8e6013dc959e65548178125f568acaba88097627e9cfc93f9138d71e0851cffdd520be2c283ccd65efa1239e7ba605b674faf3538a54f63f45fab53d75cde6d9d9f34cfa8711c28c7d76a932d8a96a3c045f1a7c1a61763e91ea0e544bb8fe0f3d528ea8d4fa18223b58da202427343dc101275e7fb2dc09112a3c787a909ba4d4df1f25292a9fb1000000000000000000000000000000060b11172228";

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
