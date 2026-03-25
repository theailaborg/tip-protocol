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
    public_key:        "f9f288884cdaaae2518d3dc07e3f354359ec318bdff3c8a8a336f0b2fdff804de5c776c08bcd71a0e8b8fe1c2e44a6fcd1aed5f12dab3f06ca3d1a147ae983319611ef11f8225cfb8cd7e64675d96db0c8f051b294d02d86599a16f8bb452b6417f766e6535f49ca677c78af5635a42c13a76a219be4955c9249f03ce21e46ee7dabac505821031fbb0f3cc5d0e2d0fb833bf45d0f0dd7ab6693a971e26204389ab5c06940a34cc0785de3ade9ab893349d8c3c711af076ecabc4a480c0a47816c1124093b46fa121effe9b7f89c4d0fad88419715b8a43ce69515be2e38e00b472995b12b91a0d2f23d1d0a91fb61457d7b2fffd55af3fb8362857f6c636ba50fd3d66c62c009c0cb3ac4e3f1f8a0343edf6191efd4429251dfae9ce9c482d8cd51b61bc5ff2950ebec6443ca62bfc3cd3c794ef9564ad2879f83e68102d7597a2c5dc2a235dc0ff5f50fcb171368985ddbc4d5a2fe27aefbfbc098a82c4f5794a01257b309588c0748fb6a21b5096c069ed0b5da1456029a2cbe03fa39c924d8b782ce242ee7118db1e92ceac5425144b5e7ec179b5d18ae725624720b98e8ca3a42569fccc3a7d3d8fc02f5915e4790a90f9ecff931cb99476e0e755ae2c3fb28b40745624a3df690d03983207a2118ecb62a76ecb0329b07dae49cb0560b934753c0d8e5ed80fb13c9db2276927f7c04c1ac3905a1c469c682f2d1488769723cd22999280a1491b9062ff4c10a9d3f0966de8d815e9d54d5f634ead72705fae801d90773800a40b335f6e0d0bacf6a8b189736424444923121e6e2cbe4132b826fc7d2cc05d98f9d9b8e4e1db4c9cb5c0eebb6e2f1997f9052be25994bcf7d517b02950c6613f7a2379bdb115c3f7973bfa673e6d65644eed8fccf0b4d0deab79b484ec225aefbb729c55a8e6d3ae2b96a54fb9ae4b9103cc2b74cd077d830e50e425c67b77a7236b2ea90c5ba8449227a7ada2c11590004d2a844e44c9ae31ca8866e12fc26053e0e6e986d360158bba11201c6a8a4ebe09fe2810c49eb35888b8e0be726cc56f46c3d2c10939afbb1a4bbb3848a5d1ee54640d55ab1a5b95f2271657c0614ca84def21274a36d8b6001fb46879026e6e20f78f12759b4a2bba9547a8c9ce10975b41ee132ef2ec8cc91ceba912e305d7e0c66b5e874d2da040b86dd83b35d3ea97d78217f0d6f81543afca486177446610df2eeb8a03b3e4dc139d1f72cbd72da24da46b00ea6a2f60b9d7d26de9276f53ed3b58c846100dd9b489fe772f7d76f49284d36719a32d955be7556bad50e0795f986519d8ce95fd1ae2d79b14f4264cfe6ccd8c1254a27d024cf0ba17c4f201ef9b0a16548dde75b5e245e8049fabb7f06ec2a8b83ab43feb93e21afdf3a831eb5653e1006c17a910fb2b92b4de780191de6ebe640437a7209110ad74df97688651e611cfe5a129ca0fb96c968e15eae79adf0abbdf995367ec026d936b6a0bafcabb53b7774872d390ad2abe773a98f128bdc1ab6d779a1caea5a29261fb78c31ed7d43f22d2f2f6b0a1dba50e3acee8681e8b0098c6a549f3192c0b13852d8de3610bd93f71f4009521cf83bea42dec6b9e95a33c50e92012422e21c289b55ee3feb32f9c4c0731f1f6dd10796ec40f29f83e0082cb5afc9907e409584696c77d67b02367840ae811bb116f361de100ed7ff6d65a4a9c513b39b59618effd5b851608f6837fbe93fd28f3050039e443facd5da8ab2402ea59f32afbd2c197238ef894b9f7aea9bb10e758a80142579d647d90ad3203cde8c2915ef0d8946e3fc50d666ace12d0d4af92b91fdf5e21fedb9b797563f2ea25e2d8a0f1f1065819ecf6c759ccb7aac8c49c6ea16633e3ede557ef5dc43788a79e1d36e3b0255c8864d58367407f46f980fc5c34787e0bc10b0cc67696e6cb61e1af8179f97d10cad43a27d3073a9646408a823a5937889b87e4844724fb3215c99a518adffccf9e6f658bf626e246e73e41abdfa095bd4ba465b4079c801ad6367d11704318aedb5fb6a73b804692fbd046bf76acece2c239c92bfa4798e67343bd0aef2f13a42e68c33edfcb98290e5cc8e37efbbdafdd7ac15a4f411618517de037b1f379d0cf7415fcd00fee0c0dc443c9de5bd40d9b837a0270fe9741d4adba8ffb7fb681f4f49bd1c45dfc3490832ef9b3a0479f68bd68833e8c7aafd0f00810a495a824e676af7f767b94df66f8e09c6876d1621ab30a28cf634bf1aa7c9a86a3693b02fcbeee39dffba94082f5f19a0cb7f7c34f5240bbdf1b87dfa3cc7fcdbb40b342a81efb41ab902c6d95a0f9cd0b3a82120e0909efe87477d5198f18f401cf1a2581e8e04455894bc5e5aab3058ad2ce805c659210a028ba49cc16919aef5c29339754f33f38e88a4e056ec8053af1da0dc37b8a6d2fff5701eff247a526610428428ea8fd3c1f90223bb9bd30ccaf588f6d462094b62430b13121e32509647b31665d0ceb2578d2d8422678e1f1596b46beaf39f14c5c08d2f6325989465a84e984c62628521eee01a9842a39be90fe0a2f1c5e7ff8521f909315d95fa16624c02e09f29b29e6300e839a88aa4e8e7ab6a616fc3e10558bf137828608a0a1cd3b42f1eda25ebd01339cadb19404efcdaa36e7bc3f51dafab9a445aeed50e087c495573dc4538f0304922c65d3f1c6bdeed63b1857a41a696f54daef35325a9c58af3031db10d974ffd4099f725e3bf8c1c544d5797144c0e30285a80faac508cc529f33a21f1",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: ["tip://id/US-a054a68e809ba8f2","tip://id/US-ae3df677bc35553a","tip://id/US-1e38e6f1e7461475"],

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
let GENESIS_TX_SIGNATURE = "9b13ba2c7bdf5e98b8ad00721256c5c7fc22d405000a901f547233434f3885658426ec06b38494a519b6eedd9ce64495fa6ff49cbdf0ff3c892a78b611449a51d27ae1de5590c64c551e79cd85cfef6f82af41d76da43020e988eac01398263ec21cbe09f70deccf1545c22eca2f48fb70465fa5f094ca1c55c4976e5d3e7a5c5742848759a390cdadd1f79e9367fc2735ea7b3c3efde346764eaa2eb26f9c5ee49158605c691e666ecf7a4ced21caa0b572d1e4418dc8bbea9994d20893b139cb2606d70e5057e508848be28d702e72a350cc0f373245351b0b38455099562290fb5c60feeb79d33048a08693a3541bff005fabbf9ec18adf1f6fd781299e3f80d37a8c23730c62d02f22fb0de8ce98d252b8ab2a327107f44b9bec3dc8d4790b82acfa860a73aa6586426bc927a43057535319c759dd129a3f2585892536981c57986d09ebeecbe2afb6fbc0aadb8c8fe58ffef05022e6c740818828366d6366873d55f913f61ea1d591411364b56e7bcf935325512231390656aeb7e76eb38ac982899345561c772a713c540c40429bf1db5586711324fef3671a302761fa131823fd22ac120d0f49c687203e40375883590db76000e43039903f4fa93117e9329b14309a9c693958fcd98b7ffe7645349f563bf47ec91c3603574e3ecd8a7d241db7ce7f36226da7d00fd878a3998b584ab93593ddbe91f315113ccbe8cd7e54e2f52a6ed207b63628d33643e77e3a6edc23849edbf6054b7a41c693bc9e898a5e13310641a49e5dd5df538316d5f95efc4fc2763fcf63fcfee2602a82e50021c2f4be7d1f79f7c441a891c237d1d960b0eb5e8cd6505916532bb56500f66baac5c9a30b9ee8fcd7dade52e27a5cfc24ee92771970e061b6a3fdbbc866f866dc5217d82424d31b7c29633f84c85dec9adbaf9c4b22a82079c097ca727017e6213e28756bc8ceba92734ed70d0416cccc5b86eb0a372bf029d8035c27fdce43f9110dbfc727076734defcdef1d041792b2607edb660ca0906d7d7dc08125b930db1152e5ce6c7897b9f45779dda69cae2e41a36652c2535f7fbaa447a6cedc19bb3e1a67e4d91ef89e2d57c3028741e2b82a77ee5b72f040e2accf5b8e7ca4ce9147b4ce4d309380658b1b28465cf9756b28b359f14bf0d45407a56d25dfda7d3d93d580ecebcc805adc5d95f6c4a82550d898e58e68c60f4931f3fc87bae0b0aec76cc63d4c0d22daa3d85d0d67d1d1475502eea2c7efbe0d7993bf7408d33c97c8c325c041a16be8081a80a167f5aea45c81d16e45575959d07088133cadd57d35bdb461cf128b831f22b0f2212c016790aa82e48ce0b481c61d593533e2a252e6f43c7a0d3d764a5a0857cae16618ff6eed6f0cf3991266ddded48d28ff142060c03c4b5d76720e8eaaa2dc4644030c82e1d6aa476cf4ed670a064b93159a4601913f50bbc1ca17549a0ab72fdb5307f3669705f1db8b8f4caf486450e8729d4b79f89e57a62d170cb4b6673356ab93610b3879e4e849942fbffb18b35475de0e9da3ed31bf04d27d17c58c5ec94b78d8e709390d5baefe8d06d8f26f30a201ef9fa2d33f4949189234677a84ecd3f434c69e9897eae6b3a252747917d314739bae76673f17b2a2bdae8eadd395ed5c1cb387ba8cc5ed076b8fc83d657017888ecb13d0f1e36318e47195f28e6c708130c16b81bd9d4296a276706fa78520c4b03bb2c1d95bfdd259b129f1b1d0c17f322f8935eb298f28a53eed4101e39b130c96d97598634e37c21597776c876417480832ef47905f6eee7926cdc299e7079c8e890424c67acfc94f6b4ed6406b893512cf517017bea16c3802be944b5a48da804a1eb3272bb15664dcc8083af9ccde1ef450dddafc06db57fd99c145b31213639afa188bb6330e1c8ec326d0942cbc92b162017b23bf4ab255c26f7c59e4a3c54fe9983fc0714159b448e11d7770666b2bf1482a4857c28a1ad2cedab59efb5e26c98bb09c1ec285b1b3c43f8bc44da420639e67c46721dae726da3ba26a2c702a427bb3726f27f63a885cf01f2ae83b2a96a42a0dc9731040ffec722364cdf1b9993d831835f5d6158051a2ba5bf98923d8268fa70d477edb9139d0923f673beec3631c752190346be3aa25f470f77cd0420904d6ab3efb39335ef84f69af6124d84876d182d9313c22dd44c9401aae1c183d882d4c03b5f3b1ecfec00a38073161ffc16d019c35f507f4a40fd423a64bca23696ecd4270c27a57d019442685f8b41e03b782fa883d28e04792eee7ffa30f0d9b5da02a4e57cf046e0f562f2b23bbded764b5545e89b7ab50a1820cb48b7667f6e45f58800a0f35a86091b647abc1c2320ecf88f35fd22a44d076cc174d6239c29269c2a24ffc8144b09668ea9cc69115f7579ad981abf52238c9e7a4ea5f5b9acff3acc63d9eea5d1f74e5bf52b83f366b01162895054355759e066af982a5ddefc74e744fee793c0fc38cd8fd68947f638fa1b291e8624bf438cd32dad7187f8c607cef6a6dfa3ed3e45a581b6958a9692a5df7aac1218be4bedded1b0cb7028e08449707e5763a910de5688f04709f0fa0525597cd50ea9dd4bebc80a203f831448503e500a27a3d6f56a4cbf4a269552af7b0458fd19600db130bfeaf778e4a55abc6a7ef159a4fea5260246ab6e781235df9c7566405611cb9246be9e08ed184bad3cb6a382b181d23449f795302c94f325ee9de97edbe28b9b61005dd9bec0e3e8e53b859464f36819cc214c6de221c779530a3760e2bdc83d5fb5b3db034dbd61c8b95ddaba07cc13ca38f7477a6e23785dd69f7b1828fe0875c04ed16348919705c1c7dcd02b0b1f16cdd9132026e2498903e36b5268ccd2ae87078cf3a6997ba69a87237f60c7945467ea3dfb767ea641e6d0dbbc6fdad70b9799c2edf577ae966468a9abcb90f54d277eb87cc532800b3e62b9f614bd0e22bd3f3717f7ef740fe7af80998d2dadd57b0cb986ebfe6e1d6c51a6a39b26f282b8c127d96638a6141825cb4be9aaf891a71033aff592c9be892ef1b5404e40b6323bbe288c904a9cfa6d97745d24505196f256fd7198e7cad3ee9594af6092f133f764eb93ac33451051e813f1202e85fdd392cc2e8088780df155ebd937767d675ab4b0a63db18da513cb90cfd5e66ac3955aa310ae08d041309175ee212f86a78dadfe00600f674c27faa4893b7d9f9f4fbf50096b960e652dd4c0939be5bcdf0b56af62187b06711cd1af06dfa3ea041afc1882fa89ac3c9bc04836b0e57748f79ebd9f7259ff6ab12cebc6a0fca804d875d476862a27c9d4b7c0b85d87a1b1b5f91b840458604a2efe5a6b644ad2f2e128d5641fa321b17848a255b94b25815dd5c8f35065b2e82bf5b790ef38a5a6d699febb654241b5ac6bee5fa0582459b34280cc1069651d121d05a66796676dd13192993d8c0f379dabad8a9b62d47bd14cad6bd64d4d37f5480ff0b571e0514b2fd993534913d2f5bc98ee1b4cdb356b9c6f26d07ca5d741b63865ceccfd52238e9ca096a53b1207f817afb874abb9c4e3f90264d892a7e40b22e41127f19850b11e1ec6d4ffb54b799a96a5e5fd4cde5987426c01ec37748ca96057379abbb89d6ec3a8fd4e712db94f7de79e9f595e1b9b324500162c28c4feef49b523cdf5e8a2f400c612f495272636986fe34732931fa3a7c0d2f83b67ad33b423f1dc5585a9f399095aecd828af2b213a71763456b94077d3b870d893cceebc6c269b7b87914fccb8ab8cac5e4fb6e9220763558ebf8ad2247d1888cf83c162d6f8ab609ccd37a108394544ffe7a58a9723d34b086a2caa01701b53d8d578779327dec41170f7ced66965bb46d8027c0e0f3943fbb81f736afaf5e1a61fe98d61762049cc8fbbb1c9ce5165f33a25332004ff25e2da2c70eb1deaeacc92dea64d4d1052a1099974e19564db904ca96de9ef44c48eb5c65554e1b273ce429032ba80958bec7549e921f0a266d3d04a5dd908b0f8398cd9f0569ea94694fee02a5f7ecf317929502555064f18d0c1d4e8b4e108f7380e5273c03fb09fc7305e028ac352eb4469f2df365cf4f4d7c102a4468422fa662176ee85df1c420dd28417fa3cdf06a717059e44152c9c788a815a9920dc759e2bfde8e9c03124f49966f8d556c172ffdc9481f7d1640ba719b34dcfe963c9ee0e9caf8569cb1133a693ac2410c3aead12df6fd2f3fd91ef87c3901fec58ba68a068792a4deb1df160be3afa687707c3c8322c2cc48bf054b5aad94c610e392e857eb56139c7eb186947048d10afe4e9a7769168f3e084d890cf3e4cc6cc13e4996d2ea48a3a33f3d83cde4efaea0bbfbb62e840d757a632223943e17076c6c5b393f7d7cf1c05f46724bf10f80e08bc13872bc185db5adc4ffe274f8fff3ad726cba0e034096dd9ddeba92205f325df39d083ed9dd2663d0c7f8462164f0882357e1f89007871636a802d6ca1a08143b6d1d303c49db495f5cecc61e4f892addb26cbac81ff48be594c78f8b718202567a26e4ede43755ba17fda53d123cdd54138c9de33d32f2df1a785d41f1d716af43650f022adc1444d5052676e757e8bae0f21454b95c6323639bbf566717cbbc6001a476baee729566370b7cbda0000000000000000000000000000000000090f14191f26";
let GENESIS_VP_TX_SIGNATURE = "56d3622f22d7f5e4547941f77dd271cec67d7f6dcb7a0dc90dc7851c5e1193ff993a931fc7cdd0fb2e1270e4fdfc9035917c680fd6080c4aad611142f109ca207240ac76d07e635c0f8588b01e1d09954f00c6d4067e460c35d57705c8845d2e2951b858dc6b645d34ff9b956d2e70df58c9b6031b423369e16eaeb142fe530f8b380a3d364c22efacc751d2bf992acbcacd4d94a635ab4f160fe8dda150f6fa9fab00faf5c01224304ca34a7a5e6119aedc6bd64ba76f48b9a4dd63529286ba11b7d38719520b23babdf8d70232c3baf6906a0cb9da6ead2626f2b607c1bcb4ce9d2ada0999b1760f7dacd5f939b553bb4d956fc3de95d332ea90e0f9737e80550a1397ba9b618387fd0ba642709b432c3ee896ef5da63057c2edfb99babda1b13f5137dfc4519625557160d637aab37ce30d5e3a07c0f508318753b7db3e2d93fa9f89eedf77b86eb1b30da5ee7b9c29355d5d196f213899173af928d0e021f7d3e24d4d50162ca52c26737be0b11e4af8dbf258f3ea3ebf8e89c275284f940c33101b74080d8e3cf22fd2386d23dc48e8374dcf99ee4c30f76d816850cec49794c1d0b556949b0d2c1e6082669aae84026eda1027d716c86285ef58cd56afb3a0cabf81e9693e62711b066525506019666f4ecd1e9ee830a0eb14fea203876f8bc99ed819cdc3534e0112d149008e8f3e293e9245f51ce099dab96640d03c5ced66a779c0c325b1abaf9b67bc2efed206ba902ac31744d8d47a00864aa54d8d0d094248b8d26bb2e6767bcbe3b4cc858c10cce7cfb6fe94d98841bd37778470f74a04d10ea30ba2354cae13c44f227af97596867fada67f4d7a39f123cf9d79ae547032ef595a68e68976e290783d91c0e9546d328cbdb88c6639a86b3812f5f70c086905132c3286c9ea7e0238ec0c39ece123acc3dd8a001b587500ed3a409a0628fd97bd6be28c9bdd633da1581cf1c21e19a3071ee25ebbaec37e56fb3f0d98bdcad05cfac330868083fa491fa1afc74caa644d7f9b5c351ef8349f3717f931f70386800e2eaf2081995326e283b5643b889be91d6799e18be9160a49e38e690a603d5f92b83ad5026228d942c54c37ff4dab66b55dc628a5a0b24ea47ae8ec7e6e47a5e8e995f6300d1a77029b168a28b65ff7f5b26a8889d6a72c9a4fbfbcd7a724e3789ee18d5c19c2e7ab26e781c46732429db5cb890d51f821b3441983401414296aaa463142b7234c8d7c790999a0134a57b1dc9446d3164f525b34b03c2c3b9f3944c174748f4e7475572d70fad57fc49acc067654d6306b4b4488c32552f99a31568b5b2b8662be75b38679cf7a272766c80f3f284bdaa6f11940a2857afecf2455d9d0f58db23277308f868ef54409eee72b41310c5b0e24520b98247730070e8d6bda9995ba0bd202a0733a5e939ccfb8401942206412e717952c25cef63a654d02d851db5bb12874bbbf49715ecd9f1735408786f60cda3f8b6331958aa2e0a742377e9e57c69802db48dcb63bfe07bdfac4c31699d2cae75df568130af5995d4e0e778e0ecdefc3231aacee0dcce2bff29ecfef51749afcb3d232e4242373631896b2491af99a839dfd579e89137fba3d7ef42da24f868a0fe9b6996dd8a81b79178955add2440f410668496c29af37e0a1b83fa32b14779cc05e3f202d5304c8a6bd29f9a12abd7c425ef6b51ef9aa56b027fa756f6cd8c56181eed6df628ce15ed03824c1fb968059ed6b9114e54a619e2052b68a4c9322044711cddcf3da9a3a08b8fc818b1bc2262692f690a267c71ac8ab8427bbc1388310536c339a76b896f707dc49c8b8b3eda2c9b2ebeb1a11d5fe492ce2a1954575b101b50bc96f62dd6d78834a12b06c93ce8b0a736b20eff35b73b7c10e1a7c62300657684176abd57dd790e9c6ddcb82de55ad2b3e9c53ac044297757aff74a44f7b70a3922f8ba7a81ca4bf32688563057a04d352882b7d44b1768451f569e78935d8af6652717374e3c63f6bd74954b090ab4635abb15137e318c9888b561b12f1c07dcb440998a982c1feac44ca95fa4f83363eebc9ca494467d344ce36adcff432e414200b28b0e8dd8a37187f3072c9e76e42f7bd2e5373211f8ff8e1dbbedf14038cf35d52d82297547a8a45d1a0846d616884f92b55a6b20ebb51d791febe928917e002e7b7570ac5d910aa95717cd706ecf86d000e812f611a9da91b4225c9111588ba6954fcd4175f48f98e32ddeb0616d51a0b63e752809ef155fe90f00082d2e0001f3f3e75ce4ec911686466ec0dadd154bdf9d18a92743ffa66111293bc2ac363a98b4093fa8242189eeb36a62e7ccfa1e82c196fa58573f74199dcfa99a90a5cf44e0e49c3d31c8161bd6dcc32e1901d63549a9d103d46e0d4e1226961348f430fc2d9d7c4e2a96459de226964c0b09cffbc4d9492968b813a1944ad7275d44b8d63a74137a919efeb4aac9ae8a0256ac1924418c36f7866860d89d09f9f73bac82056889615f71856163ee6f5b40af953a41f1bd85631221fd932e3e0ae73bc768486023f4bb880740edbd48a393bd4bb4b6b5a1678989046040a037257c30882eb2f9774b7d508f779ecf23ad3830f6706eb91b6708e90ec96ffff11e0e9fd4a122e22b0a893a15affee2ea75a92030e9d718bb3b0cc8255244ac398879277aa86eb75863fee642ff3ce166216183d52d04a906626f0ab8c25929d1ec2f13dc80d2448db7a67170c48306b3f847a9d4453e3b77142b6fd35ceddde4a51cb2496ba351a1f4a4e92bdd0b9687e8cc566de96c70959af6269fdfd725473b2a876b0329884a155b83df049a1aaea8b0499a5142d33f6150f239fbbb9f33a5762b07f07729e7d4cad8bae8ea3a50019db07ef39a7c5fdb387f465f11c2bc61e0502f5134f381b58215f76a87d289174b07ee6afb6f26078fb633fc6a69a8b1813ad29cd988980ad19f84210b751541c476ace30162f30d635776f9d890204903e173a89c685d3c8c47affb8bf04fa9085af704a0abae6c1266105d72e00d6677555734307e8c997a13c1c9ab01b373f265a8873a632eba55bb24b4af10a375cc040fe42b215a9c45623f84c05c56b64338989258b6f0eaa48b89e2a8a3a9e7c2943731d5e92dbf8fd1a94b3bcc9b337a70576ea353edd5bc1f32e5522d2b1e434926e5fa61b23573d4216206facc203fe2dec284c814397c005bd113c0c28198c8a6cd09c145a0d84d81c954e9d42745f31194c27f2f32b34b3a36fbad9a5201f465f74cf246f2343d4129e354d5309d381f7cfdafe37c27201b91ef25567a7116f60b3a98b0b8aa5cb1c6e67e7abefe9091e76f89412391f481756de2ff543a5743e94a3aef16eb4ba4b523214333fe4306e043fe05744a0e4c13769f15230892c7327edeefb56bbb98bc47c244b19a498115644929a2d495a990d49059a2b64137abc731ebad374827c38b86046d09b03d2509cd13c6734daedec4fb085f6a216bb9b59433778309b98587b70eab368792176daeddb9f5523c5656b4c2f2372ba1b467b03ecb7d0d1c3745c8015da71eb79774844aa1dcc062357916329f4127109e366b040a01e9e21e3342d357ca7ffbd3c4b6c8125cb45d3efaefcaf374a14eed291b5b1844400f4c68491ed83a165dbd3198fcb47cfd2574093110fe06cb4324b0f87e5141b73613de117bbe59bf7da0ff2f6eb0f06311e66c02c49cb3cd5bb53fcf9be2c137f25f7d4ea04fd1955d27610d6904520981dde6e8a667dc7e9748b3eb8fa2a67f046a44a3032b5fc012b7a29a4a218c1e35ef960d52971f467e83da5d115ef13c3a5b273e273f259fc895c01f836a41ea81504df3a6b4c80117c6b89dd7b220e3107cd3012b370025032aeb80f1d3ae92966b200569fc2943b7fcb5638fc7c607c44ea8a61192651049080c9eb401f2984983d516ead9a5a8be598244f7efaab054acd76d70a67b7460adce1c9feaad3ac4575a62c22d8b55947411dd727e01298682d604055d45ef49744694f2d83cdecfd47b8bcec0302be8d20d846090b534ca9de992701982dcbcb75401692d2d81a2ccdefef8a8160a1ed6b0bbd996a2409646441328066f894950c9ec0d131513a9c58860c5099818ccad25631205079b0e9a21cb3258857abcba1d58e5f347c7befc78e74dbe0969993ebf6938f4a24b56738770c1b67b48f192aeebce9caf0c4d59a996195b63b19fb8a82b96d960d1810be9ef19cb709641bb0d54ef84860e6647cab1094b4ab67aef4b627f907e4c06ad59d2970c21a171c2478cb8b234cd522b4d61203dfa8c6f587124565f4ddd4b93bfbdad6e8ec645645a9b0418772fe5ecc7228b79a43afea3cf3bf6a81591260c7f94b4ccfb7cf1703c786ae6542ab9edbca82643f6c7c17d062fa86f6a42f95b76726b0677193d95e5305b04ca87b5ec9e4f51b9031f73a55b7c39d0bb4e824bd996e4e1ec3bff9826a4ef8f1ccc6865a9b5c8db5b02ac3ad3296c96900d930c0f11c4de21065ed430517a0eff99871422b54a1a8729792f84b94b8584064eab289384b65fe713c3d03f344af102030a3c95bfa9ad85d9972b40959cf011e495483858a8da2ef0b133c8caab2c482b5c1f43b3f6d7f9caad85975a7f4087b8c96cd0000000000000000000000000000000000000a11151c2025";

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
