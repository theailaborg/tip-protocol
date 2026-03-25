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
    public_key:        "57ad9f2a9a92aca3e88deca83b0123a9d79636ca768329e9f7af1ae5594d8c8b5b53a6aff0055b44e9558179cc58960751999a67fc8de55d9591701535f0fc9d72ebb949a8f453bf3da06cdcaa3532ed19747661247147d69a9853e48d1f324f1b2acd0da043a1bd9c593b7b92ad50ba0261afe650e0cc6a033820cd37fa23ad228e643189027845f35b5210fc4d14ad0bd5a5c29f6f0557ab11c24f27211014ddbf0e6a5317ea724ddea0d2c99a9298e7de08cb05990f03f9e4a4a561e51fa9ba592cea2a5f8bc5c2f02cb67124392ac240b2a551ca0156a123521fb2199c18e093b1ad582646c3ccfb90aef54743a7da5831e86f2ca81e4dc2574469aa644c18f897ad089f78053be81c42888647338d07a6ebaf119044775f49c81093ba1862a349f69f271fc3b7ac4c7354f3b63bcb62efe6c07202c3ac712b86dd7d6255be3dfcea1dfc89ec4894ac5e050e19b3bdc37776311bbf08475932577965bf0ff391f24d046a3b7c599530c158601a1458ad4656798268ca8a633e9cad514a8eae4247d78a92083a4b2ca01532063b19d536bc1c48f1bfeaf554a480e505f35f875bb0c7350480670ef3e0e068f68cc481db14cba2b9ad5797f52d9a2a9d6ce4de579ecfc8dd6194c8438f93c94e50a180c5a427f3f6a3321cfa53b5700ac306d278a560215414ffb22a82c853265623f670e2bf1a43690a377ee2090e39b0d865a13ab012b0a87a5daf2063f3b3065a55d3dd84f1a7801de735ceba2566388dcc91ea5704292acc0ea08c787edbf51ccc811ec82482a0571308e25111607aa4c1914d18c38cc69933a2fe68bdfc56fa1120a8f258f6413fd64fd411a1c091bdf0a89f243e1c951c722fe43532f120fa069146dc1953dfeb5054c899f9cc4c2262fd4c7a2e3a4539d661a87a56b1a1a9bde24e392e5c6310ef042031c18a582df02fd8befee97f656fc295c322ac061f658fbf57c30b05047892511ab716ae6e4961f633b35f6bdb50bbe336a8c919c5e2e60409b4d700ca55f7900fea3403432bbeca55b32d649c5ff94f1de75fe51c55f04354d8f3192baf0c4fc92e22bdb0f6c682c959d822343461328677a620a4ce76472aab7a50b02d3c86d8630c29ecb5611ea5ea56c224cb722653b680334457799b6778b57b5b2d171f0b9a0eb4ab93be621c274e83c8baadf2353fc7798d6caa53c21677027a877d87ad8dd2cad29f3011936b74f43fd27bb5a241a9296e397c5bddc1b67f3435aaf96412ea6da86520c9f01e6d2ad203b96eb682907291dc9a2e32679d05702b60e86c2549e908a8a9dad45e8e39a5eec1387b1ccf1c9def48ec34490d9ababbd3846a70b4a5e4614885339d9a2284455454684607ea4fccfd1230c8d656141d6a0f93f019836683507085d03e46a9e277fbb8dc57117bcac0d5b4355378e9854dabac66fc544b2728c5bdf985fb9607eb2e528f2f2e8e8d5094427e7763db9b75dc0468c0eebb42df469b26a892cb572064c1c0690f64ab4997e0ea961193c8fde32deb5084400e92fdcbf4e99803f99b2dba820ca614a8d5fa89e4fdc1d0f0f590ae65e8965a43bcd7dfbdc9dd4b010176f70013e5a9ff0cf457ac74b5e2b144060e800225564fbb52e6b9dfae11d5b613b26d29c9c29b9d8edfaf7684b7478eac7360120d5a3db49708cbf09fdefbb9f00ce1d929304b8764fe4563eff752cc03b51db38967ea1fb24d2d2851f8892c53e0ef68137b385bb5abace9ce5a74a7486de6766b93ce5ee2852ba7b32db32dd6b793cfb29d923b349756526b7d26bbe61227731f82e2b277d14f85a6011f2778ab1101aa1fe740271c8caba4fc468546df7e0b28191553ba4d4969ee14f551cd9f2bedfa0cde4b475fe7ecb4f40705ac05be81d6014c1cf2940f4e452e8d5af42a9c010784f57a72da1049bdbc5ffe575dd0e27c410a3cf2f680107a0aefa0b656ffafe95d1d2740d1bb7f54fd79ab2c76a98ebaf5cf8b4729500adccc133434df53438ab5da9144946d4fbc0f879b269058444ef761caf53f69c1a763e2533af177e383c40f30c31abd6038d9298c28a8a6cced4b6565e13f7215add21af620622d3a244fc9b672ff9a632b66b4947bf0541b1b12cd4f208c3536fbb1d2fcfe740761c1001e06072b18b617e664016b78211ba993b8734e2abbb250a61b593565a7e146e3f9f00cf0d0fbcd41a4a9b33ca57b347dd14243a1f094b3080336816dc024f0fb66859ed8859f969c6a1cd90d5cddebf4f3a9933005730630132ed88743e741ddae96921610c9add51a29efe1051a3d244f1fb2d04089670a0cd4b9149d3951dd96f473cfe424410b532e0e9091d911e10beb477e59a32db59fb10db2a270a49ecb3a6b375baa44c051b871f567878205147ea24e587c2340afba79ab2ef3f268e05be821e7f48de7cc804cbdc35a8ba6190af3a3e190a9537328696068b83cadea24adf7a41a81bad651df0787a78a1f3936f710a5b5ab9acdb7e95263b0d55f84a92c35426d06ecc092635c5c40c50ee2d1c0684c0e4f9ba4021051863c808025ec09d620e32472cbb486ebf5f179ff96756bb6a08b52b15edffb8b5f3b3adef55e7e2e56e9d936d307f305e2231ddd7922c2b33ceb4cf51589024a819b4a6f17b1373180ac2f16ee51a422d68be23f7805fdce43318acfebb091769a1b478791e92748491d2742ea4630e0854030212ca0608eb0b637ca7ba367bd0e77c69c708c2ec7f4fd9b88f68fe3923e0d8db9",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: ["tip://id/US-9bb82a1138aa1ba8","tip://id/US-cdfbe328f5f0036f","tip://id/US-0f029589184aa2f6"],

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
let GENESIS_TX_SIGNATURE = "38c3baf33b172637efa5a7220fa2065f2ecf6d9a3944d89d124925f4e6caa372fa9901dab53b31143c3f4ce442fdd25778a38fba8e38728702be1e4edc2450f4bc5f27061e17453d8d426a2ad716121736a1c85935806405d304f54d4d656abc9f8753c6979d64d7ff03e19b9b90541cff8f759e01f96219135e641a43d4e474bb7740dc20f5b2b3a54efd4dbf47c298cd41079353dd412bfeedee19dad1595482857ead14a8ac51e7679f5aa82bd5a7386b3a2f71eac008f61c884c344668e96d70ed61ecd55a75cea42df3bb26570c50fc5386d5f6727ae980bdd0c1aa4dd2c6f087a136876e71bf9707f8224f199333ed4f772e4b70dc458728513716b33a19da0b5b910a908dfa9941c5394cb0e214fb72bfe35691141fc3884e70b3a902bd3c603f99e8f9aa3cde8b85ad0a068ea84a24479ffa7a512bcc7880e85214028521471c53dddd50ddd72393d947feea117a69a40aefc14659fd14892f4ec08ebbc82b9a054eb2fbf6f6f60a8dc42aac772d868e6c62d15e8bbcc59d989fb590a312311ab51ee4cacb9722e492437e04e977e2597eacac42018df572d9d9f9d6d0ed61269b1e33533e1422ce38607928b404c757f4c07eaf7d3bba74070edb06992d8ca7221e880d55dfece3d81a2e4a16174009c4b342122c2aaf9c49574f62fe3f2cf88ac2280cd2252d5bf8add73e6a00312d39190c79dc1968cf3e047afae1af7ed9a7d7cfd49987274eec665df282b70340e8b62da49e850cac7606f63ede1f3f126efe1d5e835345c7c6161c4973358f7c9fefd97d2921d476f572b8d016444e0d0a693930d73817343caf3d391a0e4ba22083228edb0a5339317cf2958673f8f09fb6c7ad6e54ac6f9cda2579081ead8aad88601b19cae2501c4a925f0bb80f1e46f6aff441f5461a4498c2aa1bbd4d0012e5db1cec6b567435baf4d369f1a332626d401e9123c5718689842889fa60dec08e4f2373c35e9249118939034120b966e4ce863b2209994bc5b7fc6c5e253c172624dbeacacaa611ddaf1b8308a079107353b52b5844c7304e8aca404b58a4f2e6c47a1b62d0af396b7dd118ebf7e6d1f61f0faab2e96492d19acf4a6856844ff62eac559591cfbed0268f5c573f11c443c46b1ea142c29f4655a51f8e48bdd31fce8bfce735f3ff2aec67bc39a7eb7934223592e34d9c75d968756c37ee805e8a1794801c698d2c6ea5512817ad6bbf85790d66c0c217a54beddab810e1acdcbeba8a824dd7e7bd36959a9ca7164d6e29a9422c5b17dfa1b1265804b35dfc229f3e28da8b1285c7bbdc80c3fb07c101a910d2fbdd6a99151e82214cad6f9b0f1ab358ea2bb300e1b3cba98ff0b45c8f83bdd9dc4c579c14829091ab363c6d0093fb01b5e65f8a687a288a2a76e875512d69599a330bf18236db55368cd113cb60e8b2149650f731195ecadea855a3cb7966c3dbb9a5c3587e2e18cdcf2a94133e3d3d90c36cf0541b1916febd234798a006b19d7d750e4a4279a4140466a74fb82f883fd5c1931d1821264c9638a7de410f30d625331951e40542b0626956e0eaa8c19591710d6a87709543b53740bed43c491f8bd958733ac87f5165dec952a6dbcbafbceb612278c99a270c3e549c95a575b219726478e210b5df5dd6ccfcc917ffbbb6c5bc27d41c5252fb281573449ab12e215916864c6f98f759e770a1e3ed3f0e9772d62393ff9b0896373aa8d1d9e45817f3f22df9d881456fa329b9e03fd0e7795256d41489aa7d0630c8002436b647d96c67fa8fc0841bac6e811a37415b7c6c2c63e4fbe8e9cef9b5c31157e2cc2262d29deafcdfeac029a995b419318790d52eb90f7a7301731d74b92189fa8ed278ab88c32da8a8d6750b9747bb51046b7a6348a7b770bbf0a846652a1ed92093e3f80d43cd0ea7d59f410908d9c8fd6fa6fe5b6dd3f92f9ad9489596f03657a8d1031210dbb2489d175464494f89b5b64a5bca2135ecbd67cd65d84d3a7f2269c4db520d2f0709b3e9ebccd7eedcb0269cc2cf12975cf1a37ae71f783737838e0d54dae6836c6761475658b364d1cf438bd03c9c0e0e3ade16ccde6bb4fb2819206f645c47c3c01ae55312902f87d43953af99afa52391c78d9cf4827fa7fce69d1dfa8029bc96a2c4c4ec8ca3b774789462e9ddb4ee54bdba2c9f809658b93cd207641ef16ed5d11e9f62d88edf216f17d15e0f621779c26c2a453681e1be41896d3d4da054b28078dd3d5e760b55eb96a827dc10c1d328042ee8858af2dec9da3154b41dbe5044079c2bb069a7cd1ecb2187a1f060845e52cda7cef808c446cf3d25747a241fdfc86b998c42996d1d9b0273481775c8fb85c75b89e938ff16b54d569975968e0de8a8ceb80c08cb2fe53038c401dbc7bf3adaa163c8c39a21374fa8d3f9d32f9297e9bbf86d60da4dc7c87c62d1a2d00a65d43c51a2db00a66379f37460e99c383deab6e731e598e37bedaf02c524f179bc01642b62eb3015d95f05946e5cbcfb3db8db0c429dfc2e064ef2fea5e8759c78f10c65524840489251eae6c3029e19c6cadc334198e930e4eba9689ec0a174b8485f3b52949b1361aedaf180983fd25abeff4d3eb56dbae9c563620511c4e0e35923ad73e4a21867994217623e4552241bfd4295457ed4db9851fc006187d7c0c64ffd8bb1d31ccbad52cdbdcdbb4c35b3452443a2c1afa90a9504e191581bb895c36f58caffd663546283f6dc8fb807e45e411e108b1235f564e983902aaa950617bb0d8043a23850a7b651f230347812706928aff46380981797c57e4fcec573fefe906654b331386586a482bbd614723bf1ac8acad6234d59e0a7b4cc5328e587efcb889704db378912c26d1b4fb7d724121723e56dee8440749b5ed87c2bf2392d5dab3752ee4562989625fba07cd8367606f40d9efa75ce9f0bcd829fcd5fea811688af06f27705205dad6662ba4708325738bcdacf4dcf73d655861c9d962e1f8a03ce6e7e892aef78a2f375e258b1bb42f6ba98ab4e4e1e2b4761758e306c69d428d75ed64fdbfefaac2148bf86164fb00827ffa85739e8e0a7dde4d618451771e227fd778ce52c3df673cf5062dd9fe36698306dd19d5b131ec7f52a9888e5d6da477d758374bc07c17a793a5fca3a8cfe0ffff42c98901da070053a062e2b5e92c3d2b42b475680c52b0b4f7c5143b06b408b9da1f9bf7e6dfc357c62f07f9280b25aaf26f5beb90941892c4bdc6154c05ea2e6314b471d63e94c3fe2c6c8fd75c116eb64fc108c1f2a28e6d51cf27b0bc627b9ef421c04dffef6852c9d1563d56ca43ab1ef36b9e4dfc23f1f7ddebb01a016311aba89d7b053f27a4e14cdbccaede143e8abdc83e5b42ec1aaf454afcee5c09eecb92bf1a06ffb6c37d84e99647560dee636d1a35ad850a35786e68278f87d3c0b1577bf367421791b6ef11306307e1cf4acb126142b34599ceb0858c6ce31a6269d1c75f8dc873b3019d70a364450f01bab1811065f9a249b136445d894dffe820afc0a481e266912f63c957dbefc48f086fcfa8f86b1313db2f9240c8cb581e2824a1e0b8025e80682a5801f832fe2514f5198c28151181d6ff8952069a986e242a568e2c6b29e9251fd6050c5b2120de652fc941f9d87850d8824f1a9a1098c6ada3ce0828162d0616dbc5c3502796c7805713d2c25696a3ca263a4c9154c37fb134609bc92392a79d29e2332ed3e46f8d4f4122d3aadaa8874e1029074277eb8e0145ea3b855ab34e9ad388ddf6b4dd01d1569d8e340943a4f7d05f464b857c3578ad26d06a5834a7698c3ee07dbdce46a6fae3d407bd6e6e66256493a58bdbe7ecd1725383cd2642e3ec6e40494ad112928b39bb54e19995542e022292fcff207b5d86494b03bbe04d4d4b5a58a69cae0bfd8f8602ed37ebd4e7f6dd7560e3b17b53c1436482ad0a57d44494fbba64a5a738193a73dc9f8f6a6530dab3260e980ae84ed7a4eb42e84cfc469c0582b5b8d929beb7ba840964f36d547a985ad323b496b6b068d3a0bdf5a1f621b965c1023f8063807c057f992a7ca5aea032696a8f7fc9dd91ad5a8868ab4f092d5bce50831b2400f0f86b0324a90c2fdd3eb0cad70e1540f02e7976dbf1a4dd3b08738e74ad3869df10094832ce23da223d53d62b9debbd5a44830f5801527040b242a2e99f44f57733766bb47addd40053b100ad356cd41304f40117b107ffc4eb50c99a4afc375acaa4326c8d5befcbbd2c24d8ede5c279e00a6aa8a658c3de74bbd0e29dd72f5a7812df5aba3d850ffab768dc0be2acb3c54fdeb747f103f1dc48463405df64e87807a9fd0ab8b8b2b04336a3b01210e9cf9a5ac8cf23b2678052559aa6de2ff4b1af255ec6ebd5bb5c09b7643818a3ad2c0a76bde6ea5fd89d8b91f8e65f813ca96d24d885df1e4712cf94f1bf55f44f605a31bce09145eb68cca660ae973e3ca5f85ebe26c306836db88f17642a6e2876bc225b1c3bd5cf2fd0549194d32eef1b63b63c8fd1b5106b43b278801483e0a621b8300e15918be1f5be450bd69ede2e85a58f1c4e299e4f54802da8e3d742ee8a8d730ec510d784a1e274f29cf25476a8d91c12233537983b4d71d329cd1f72f607ae5eb07374c4d8590c5e1000000000000000000000000000000000000000000000000060d1213171f";
let GENESIS_VP_TX_SIGNATURE = "74503e0310104edd6e0b40d6f8aae2d5aed812595519518903c34afa173cc6a0d9a050b29b173749b5c4d2541a5eb34f052cde77016d4898bd7a4bc7fc84aa7c015f3fc2522bcb538610bbe926b98915f65d9c89301229f3cfffb07205213c90f2e3501fc3f5effad4f1bad0e53fc5e3041e2b5d7c8a5e2c1956bbc5d79b552e427bc8904924dfce5d0d82595fb866512a868e58e7b8175ad7976ea5bbcc8163bf1918e684d2fdb07d3ee1e3d1a874b28610d325aefa88f3f902bb7b665e8c441d6ad9df7cf3d68f803446414c2e0b415851f335cc92d270ed525610e103947821df3a2027406bacfae9fb466df5dd50fcb082aecaccb582dc11523eb8e50e03e1dce4841048fd3dd9ffcd4ba059a6c48829893912b42d03ff0d556ba54ae7c45b2e0e1d6787f5c588ea86042f060130dc322d0e0447c4f31cdf39f7c75dfdb4fb21d28ffc571d379bc3a39ba6d197e2d0a0c4194ed2faa02330752be01f1cce56cd7e7ef8369f798a1439a6bec0bba64452cd7d2deaa677c91902154727bc27628596d707937873fbf40842bf12da4c49bf0979dbc6603a7340d3886766b2bb7fc9a52df518f13d222fa8eaddd9990e728a0eb34e43502d9e0a870c1d5f6dd3034d1a637eca24f6b1fd169df967cdc86e152d9f71bbbba4ae4bdc8e62a1421ca91bffcac8d350214d99616c226030cc9eabb22558f2cd70e89e7ba706fd7e9a82baf4c2a3720007cb0d7184ff63e8d089c0dfc87a1eed6f3375941a8028dc287db0d264594db6c218b7d4c620a758994477a90be6c89d7dfa54a6089d20e433379f2e62500c49d3a9f8173f5f4e6c5bd90af49e3cd352d724afafcbb84a60a239b92b0f8e6dc93f19d0aad3d74449574e2a40355c1adc3ad18e4d5608ba5f902d6b715ac788ba1a8ba718e76a51a303b4aa28621d5956f1a5bda4518eb8bc78358e0326ae89815a1dbdafa6869fccb6c11c7ab8ff1328da5d5938d73046fa7235e341a6647b3f5ec4b0588c1a3d23c7d895ee86e51cea3ac5f8c3e8686a4f98d299096c79f2b25a7926ffdabc6eeefa33b159bab2d3879ae3d3fc57cd048330a1ae49e14672437ece0c9736a43288a716d0b35ebcb9002dfea40e2a698c5ac1a9e0c23f1457ba8e9c6dd911d652ad70cc78ed2e24d681a1fa50c965afee9b71f6e77d0d9d0105ad19f1645fb21e85c0290a2aa6e48531f06383fc2fc2674ba2f44cff58dcfbeef4565f1a9f24554c44094d66616520676637788d7561fc2618dd64de4f7f8ce006ac9c858cc3334c233a7cd968b0f0027eb505027cd90a7cf0a848a37a02181e167d70ba841bd3eb08509100d80ed99cf7da9ab9dff6c3ee4058c3b26fa065bb8f369bf6c32aea35603173c5888fda9728a4aef990b6df41100ad14212cc45488a984e0b86a1cf2ea8542c3ba5d81a0e71260ea61588999c0c99fcc251e8b1f860f3fad717b23e3e61916011520268f1a75950e085f1e5206ae965fbfa08c707853c3fe15addaea5346620a8b146e2598a6e81493344c3528fbaa8b887cd7694652f5d5a74dcfb3dc26520dc6a14d11334fffd7de8bfcf2b5e9ec270d3038c65b51eedda287feba00e35affed62a5bb12fce8e5c8e931ac44d3b68730761987890b783d991f3453c2bbda6ddcacf8dd46aa3fd572f29b05e667fdeadf9699ecec6d822b6835ad1bfb1e6792636090ac98b4e4d1e146329296f0bc70e39cfa6afd3ad168c605b63de5a386bfb8a16127bdb4804346363b92c65658f2bcb192d4c198568df442216b61a3fd6b4c9cc0a15dd12216d7779bef91e5a4e4344c6955e48f8aa59f5a285ac01313fec0c27d8cc9f49da21bebd9c642fa78d31b68020076d49a4f6317a559de60b1aea1446781592a3d7087f6b309718bdeabfe4b4ce272b505377dfd4c8a08fffb19dd2b54750181ad853205143778bfb1d0d476765f5a48ef3ddc40240958fdc6db4701ee80b76d1058f581e9c4e425dc5e8c4c248bbc7ef3de3aa26f7cf3c4b8a0bbd7908910cdae7a39741f7cd750830577841097619fcbc3edc95e3855441c7ac2374b09be0d5e02437a2d8eba06f80db3288b1be5e121204ddfd1910b81a6e13699bde2189f32a6cf36550ff7b16fd4f4c54d73ec98b9d8ffc0a15906a45d0e4f2838343aa6a8548e0648897861f8e2b3cea2f890ba399b7694b609a8860e75ac2dcc5137050ed444eae07aa2d81a6b77a0c05d53265069c56e9d670de65978914d81eb86314d7250ab2ba3579cdeea44b2b720059dfbd8c96e89f46c33205323ba50402ae24c939e691dbf0eb59285d45a7af285622602bf8f3ed9c1404dfe0eb0072032c781cef5570961dc427ec03c67998f902dc3d6723982b726718aa9804c2b45e97fcbe18b98e90b54f8e50cc245312de5f77e09b181a1d20bcd1f79d0ce7bcd8b11df3a3f4033cf834a2c5af7bbeb68ebeef42cb798a55b98e13a8bb78c389a91c5a8c34bd96532b0857c0a22c8a7bbc8b6b72fe0edbda6113a2498543bad04f37cbda111a7ca141d7d902659d85b0e198a8004d5138fd4251222fcf3aedc664c586d40bd7e58ad13c96f7ffc1e7c3675be1734246b5c9f6f33746ddf8c0868399ae790c9107b23c55a0543411de0cca96c022c14ec173fa90fb296887fac5adc85bee91db79d0b560656e2fc48100c78f43f889854afbc7004f2fd872460a03a6ae419023f48e714eac32f6cde0e239d2765fc061b8ba145876260e60fa829296b3c4eae48ea848fc3eee1603c26df5fd1e6eed6a6340f222187b850f64143d5daed5b46fe7e6414df01ab067efe33a5eaa54683ae2d95906682d8d4364650794393bc872a1e2519bfe4f0433407670cad35932084a77d5210dd02d1a62a70ba8ecbac3f629948544f7f9687e706a2ea5733351bb105f6a9fbe599a0a1d723aa730e7494a14ac29bc1abd6f1c8c788c459d8df571f1ab9574bef1bb692aba9afc2387de676edb2467d65adaa3e2191b1285f9dee3d11f1ae163735c5cd134a29a5ffa7120768a457aecf4f8729893bfb593eb5be6fe3d7d4b4c414589c2deef91b4281b084326bf79195eaa76ad05eaee28a3f3f4c75a8726d48f23e4f8b4ce1ecb67705694ab6f5c1aa97ed04cefe1c5aca0304b37d892764822e4905219b235b615a3ab67161b9284fd34d52cd4364e9f6e87e89c435d1c977c575abfc6a5f667e361836bf3e1a88b78a0e9b63821d6ed386160859197d2470f73d028c405d8cd141e538a1e9730734aeeb34d264d119b1e0ed8272bd2e5f1b689c5ce4eb02a6a2670f38ea1c11114d46e805be0c16e92cae830e145929e59456a2163c0abf2b91650f2c94301e89f615c70a97a9d2fbad932859518cea463a29e9e1e4db93a4a43a41d0fadef1f85d361234f345b7fdd337ac49a92efaf01eb558ad0aedfec16b870b4d04fd4e1e5377e5650625265009630b8f9a34634a9d61ec67396b27db88349c11f45e4ccb8aea46c14a7f820277320823fb23115663cb15b5e7889e4c68a00e19902ec47c0d18b15febae4ff0c3d189eef9b3e8a2ae69dfc7125d5836c94531cb223569f15e6fcd14e00b4343fff3d1663263e4c5b0e35d7a775edbd1dc1073cdfa31bbcc1364539d08173c2092df8846b69b558d94736fe034bb29df9872a11da137850cdcea57bcd1e11c29695019e4809de1bacfbc912874f2d84dc1fb3ab2934a21c8fef1d38ffc058e127ab1e621209fecafab3d330acf781564863713ab56a86091ee5bf2eeafd7acffabf685175eb1ccea91efeb5a43456119f80ea92ad59738eeaade68ce0a932291ed582cf47ea91850423eee1f0007d6cc02ee2c44be80330026652a5933889409b488ee86c45185ed93246306b2fc04ee489c6b8a1161bc601d448cea27931f5195e76d9e4732174f297366ec9cead8cc233acd97a41c0d9bcb3357de45fee669705d91c99f9f12bec15ea190b41beef851c7e1c82db84ec2b0d939c65f317fdf33954d7e8763ccd5ca7101b542d5c7970fbf273a560c821cc387d4c4e37d3ba0658ef338aeb944d7f2a9477e93422f0b499ed7b9eec2225f029f97e0a9754823275e48537fcfad1cea47c9e9572252f646f11d020baddda7b5a0fb1067e795040f4f76a6ae624dcccde1e3462432417f771790fcd0f1388c507c458c33b49651e4345ada4c8e1b242c9848c176979f9398d4321a1e51ca0a12dab1e45e2c70cc201e4d4820f5675acaa9599a79dcfb544dd16f4ff6333bb7bb9febf119a09f4e70434c161e34a5e365265037e1843f3b573d146aab926b70bc88c4d13c00f0de36735f2c467f45fa7b405c5a6498940916c5ba76c2fedfa77768b7c0e7f26182e89b47fe71b64c9be8c2915561954504101b83dfd1d12cbaaf68c88f4b0efcbfb78c8a2632a38c0a95b862be28a53213f25988eb6a06aaecbb94d1005cfaa6c5a41cb5847ba20cf7b8b4f14b25f4dd5e8069234e3e4926edbf4c891da803e5c54bbccbd6f10b6c5b97e7f35616d802ffd01681911454881920b8604343be98e3ca70d81262f778db710521de8e864c8f7b75391c927897ed79cae1dff7a83bd22637583ac0b03df0a3136444d6a7c8aa1bed1d7e40628369dc9d2d4e1f0182f5b7b91cb16304cf41d2c62668dc46f8399c0000000000000000000000000000d161c20262a";

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
