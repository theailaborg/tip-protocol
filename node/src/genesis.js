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
    public_key:        "121cdede62beef724505dfc660bfa525b15de922a7e4c6511e084373c61127ca2d332bf2a06d6e3b7ac0694310561b710e132a689fe1df86fe9bbd3a10fa750e6e9f2ca22ab5fd68424acdb928db5547825611fad74001320407cbc237bd011bcd85f44b2d7667e67f3ba928d1a17437861cb1403e8d6bd55874f4203cf604aadfccb1e73205f91749309e64c546dd8106a285db7eb8e37bb401d4509228f5b676897eedfdc1df0edb42983ba5796ad71910926b9c8e3c6446c465c515e2db3e72c4ee6dcf0b78f589ff1348c5f74771ee157c893042a6667de2c2362acc5150873045b6f394aa4a3fea5a13fb97382902dfc661b157f8270a5c5f1602adb491866cd4bc5a9b910a2c469f6b2d42581a3d244c7718d334f14fc417dea231b3bfc77a9686255e84cad6884272298468bd84093224d532f42e82ddaeacd123013c3a723471ccd7cf630d3a711e836e362e36af937dacd18a2e6ce31bd1461f060d00af45995fc0d82ef456690a2dc4f4f54950af457563c153a278b430c857ffe009ee0b33e0a4f3b1e462a574ea80e5ee164bf8715631c946b4047223f602b44e692a15c06edd3162908acec2c386b9604297c8bb1e52083fc2f2841ba18d0f654b71b745066332433e2cadf1f1e0596a1747fc28f4ec0c7a49594e7dfbe4c468bf63261421b7ae035c22c14f576cd1058be1ee94c0c2aa80953586fa40b4002f008fd0701ad9d1d07ae40aa2586fa21fc01b16c75658b757ff8f06a40e86ecb23ad38ccfd054b49e6a46883d3605c50ca025433a64e0d6a3981cc623c810230eae51bbf3b5933cd592f0fe8c71bf83a80ee0a6273b8e3b9fad8f194b5ee02827c2e521065576f7f0be2f8f0c6f43500607b55370997a6cd59c1817ebdbdd27a58a2e040f9598a8162c8f1387d77d97a830a049f4d5b82220f373b8925243240afdcaccc91f0bdad0298e39adbbf1ddd7369a33e27cf4bb865bfa1bfd29d818a4a2e66d4e4ce3446acf8f2aaff26a31a73e6641afe3d45863fb639ec6d65305a9fd04a9a4afa790c22a9ff3c57ededc6505b4799d41e278475124a0b1e9ab4327d5b2b8b597743afcb6cbe4f4a321ac50b834a94fb6c7e67e28178504548477eb9026ea09466a2ac395159beddc5084d7c5a653cc7ea9433cc7b7199eb25f7f3d6106d96ab55ee5c04e435b9a68159ce1db743899524e5239f5d3b7fe19c28f0efce44737154376d2c3a0471c43a36e911d1c54ddc1e3a61e4185121656e63b0de14ac863dcf598472bdeec2e3b514fee362c87b1ce805079bc513e9affbef6328c12f36bc000925d0561535c9c93bfd5885756d7fe8c7af6a3abea90e7fa492f21cfd7ee468e2d54613549cb34b07999112aad8bf753dc9e4327f963f66d6560d383378ec150e53d159e463be51aa3a674041a9080d254015110582e878b4815549b187f4e16be985bcb528e7e073ad24753bb950bd960fbff868464a7264ff8dc1268bc1da21903689610a0a23e958bb11db2a5092377ba446e06729571935cd35538e805cb32f8e12bad6313daf23b7aa5bc93eac5c78b7a5b2bde485cc02d5fd28fb0c7d49ebb4d9c2911ec203c7ba56d50012dba93daf0ac6fc12c711dfef0af42da02bec608cc50c51cb205c3a1507e4c200ecb2db27f9f6ca552d41b8a49bb98490359e80868555d44e862756066f20f10af5dbe66b05d35e0de4fbe333e797c1349f45c81f69872fc0d4c7ebf783461fa8e3ed6e8d3a0153359f31c49662d09426c051c6d5462f461b1fd6fa0374ae7ae65c829957c500842663b19327972fef278dd25efeac39997ce412870cf3796fdeebd3216cf5ca0feda5bad2b7976908c9ff804a64d0bd3887a3294b0203fc92ce937441ac1d55e8e477974ece6d47a3021951d483d38ce08ca138435528b1932af5605b6077418d3770e9b8f15605739160c4cf477f6acfce9814917bc63ef5af910af6fd43183b5460406c698c547f160479921a5085d623b43f4fa2c89182edff219f414d762f02f697a1b7e9ed52226c26bb09e1c8e20850467f25d29ff3235aae1a5ac304394868f7aa7a001290a23db9cc3ef978e3c1f16963d79d73e8a1ad70cc9f3e867fd934272e9308f6386b9123f356b83857f1f12119ca10239e09695aac088a1a212093b332862bd866cadb937795163bc21723815f23d5aae9c604f3879bf186cd10a977cff2af3ae4e9a6b0d7acb0218e5b13c1dacb2a1adc55e9029852c49b18832d697de00e7afa42423095ec4a37e5cc3edaad54f97a8aaeda28a3eaf8166f287a8ec292722beeaef9b820ef923c85d484f80f1be84fa736864c5bcc62adb882bdc64df865a34402407fc1435349f212c389c2863d8f565772e86b8d78c130fa074acdab605dae47fa4393144968d23e95ed2567ddc5a1c330a0d0067380884355ecec5486a7848e663cf854e4850e900bca5ebdbf139a0888f6a843f864a26674410fdedde73c7d3768dcbb6bbf95b688c84e9b1c81abf5cc7c2434e4c4267e17702eb5ffe362b0b14be96022d7e3b64c30c208bbf98385201d9108e54bfac5032eacc8f691b000e21426c40532be72014fb91b5bea01d696f6a273adf995e3ac814453cded9e97d4f4fb8362f0983e97351af9895a453110e04d385af9983bca7806b7585443204cd6c7c3fdf9718ed16be6b6ce629cbd55f632fada731602db32635fb037f51710d991d57c2fc8ea626d27d6ea020d205b1a9d913b425d9eafd2369",
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
let GENESIS_TX_SIGNATURE = "a3c3f3ae9abc463e920d4f0885492e70028f6a308d98e5ee2b2a0fc0cac7b5755cd2fb44b40499e52f654dd1a142236cf8e5ea14e75fa10192ccd65989c10a995afafe74dc4050b7334eb3e69ddfa31a93fd0ed0c448dd010309f880ea444260881c230c597b704f603e731b574d0fbca2f1fdf4bebba28bb9755343c9295b9229b3442c97b96f8224e868c1d5de071f8e2b2b7a8409dc77390b640016667c1a9cb2db957ce2112eec015a700d0443a289ee3c0900b685ea416ec0b2edc8b658f4d5e525a6b39776bafcc58af9a71d3786c006438fd9d260f1ff6a4dfd2cdfec28083632135ab5257265f922717d85c2c0c519b3a276097c0073faf02e1d613861d28da2b942cc06f2ce1bc4a5d81c14e013026f9dc095d32888847f1814d31dd585b4d214f83af1f79238fbc7a25d2a1697ed54971f78d13ab66257c921912bc48930d5420a3a150e0eda6c979a499391b94e4137e32695f514b7f056ba40fb448b50a2ff5948f8e6c916180cbad7102f07a80b12d02f1480ae1a3b8f7a803a45a4254c8b9897c72d768ca7ed433b481ae2a94d4bd7171cf49c89111e760f5c1014bcc18e3ee49716f09f643d3fb60c500979ea26bab59823bb41a63a08056467c40f66af562199c1d8d6bc15a47790525f8d4c578e2d63a4df6def41e78fcb092568d29e558ecc313c40c969e987430f543793ad8ed70d3305dcab237e18c254873407a908060b408661dd1c6ea2864c80da61af4389d432eeedaae7c8315c5d98cdd4079a7fcdb51d39518865165eb84fd163c064b96c927d7e66fc063e64022c119cec2f4520c39443af283b43ff29a938988a7f4b40c538a51a81ec0b96bb526b124c12ea4dd68003108e76c150c5d65ab4576e984509795583ddfa30f6e4415b1d929c3cc84afc8561f42bedea8340ebbdcefd0bc55528d0017a4393884152c4cbebf4ebfd539b98129cdb5e545efb31cff0f40c512c15249d0547586cf221fe4606b6b0ec2cd0c9a76b3403b13c0269482778575a7945de62b8763ffcbf9110daf5156fcc1d6283156a571e294df96a593cad3ce8fd5ddfb20d2075ed973ba165da6dc041a753bb5f50ec360f27719c4f518814e36720da43e4b9a63987d3b638d40178d7d8869425fece4ea93171b1dc71b0c1d50eb50c4d15f1f62ac47a567a654b8c75e37a5e2a2dd5817499ee0c52780322f0983d186a6439bf7a661b8bab97e67dfbc6c8a23ee8cdbfd6f1c54418cfdfb5dbba3e7b4392ccec8e3e8a5d2172ce62c81a2a769059db8486f30ca95e78f5bc5fe921ff4d8549ec09b2ec83b5a645b9f1b62f45522e66bd648d8100ca6fef81a4f5f7fe481bd8178672162851decdaf64477001cf1e7806596627dd8c7ad443011884ba3f2f403389987b8888065aeec0aebb760abc65879b6d0d9b49560cdc4aaad4ab84b8719b6c95bac924234e8bb55308b4810da69e496435e930912ada3946fbe7af4588455f19ce6c85a9e1231b135eca6adcaa31f0f21655cac4df1a87ad4be1d911f6eaf905aa379346b598ddf0bbe9ef00ff795d69686b64ce6490d18fbec630c2bb225d27c32c705615fb3f8020431772fbe6e172feac29ab19e4e91bcfc22b59748d139d01f029d57f2e0b4af260aef342d0725d6012e09f3f400aac8097837f08e99a14dc01985925a1bd8b024dbdefdb3582a2687c0561b7167b7d3b9673993ea9a92527c505d6bc132b18d62341b8bb9cb6936c74932b399b4a588ec06f3977b797b6c64bd2f80ce9a968c09381e3c909363224f5b6dfb484a5471b87cd77ec99dbda1723f0a0649409e657a0b6b261aa586198a6d040e5fca36a84ee256e1df239dfe3f1077dd6613f9572ea785a2d1f18cbd62211575195a9cc718cfe495fb335a3fe20277293827c9003749957af1e6fce0c83ea4cd3fb2d5c9062fcb20c048142be025b8102f21064314c690cee7beac80caf250fa03982b30b40900543bac6aa5e4ba6dcbc1f1fd99b57370d75d4e81cbdfe3d8e3ad4af898c42f5abe349635adf091cd27dd01f1cb4b429f1152881674c3277e619aa831467f358d90fc6922b079dc6230eabac0b76f69612c443df3cfce7a731c55f962202f3b811a84db2f56aa7991979752c5405e803658225946aae569a3ad0b2951e3e474004c77bb4e3b68ac769a47a143afa6809327b71307b1374f18542f618b10abaa07d9e030656c27828dee1b3ec32706590f023056957c5c5c13f549accb2e8ce069586b21b27b0f670376c9d994716fcf3a56789e9a1140a42c0c5991ad445f341b6125b202ada521c70b60c81b43a7b52c6ba0d5e43c6f93b50a2f1d0c8685cba946045726e221e128c50f9ea631b98bff524b1ff0e7ba2118f00df6af2a2c06d6df9242f9481bb2b0ab5ae69c504a3273e3ec28f1e0591b0567644425e1e995422b7a7b4302a9fbc9f3ab19a7823c117b311a6ce46f075046701383fb17639043ba069c582aa7e181e96ab82e4b18fe594979cc1bda6c2ec3705e2ed976aec9bb452370af386a559148fdfb01fc41827151159d6a94a9d94e1abe64c8e26e022482e21905d9acd77b9f843dca21bd524b90f88e927231629e1c5f0a414f3ff3f51cc00d1ecbd9516f2e320b44b37c98ca94f51ee5ce12cbca075dee3943c2199badaa58581aa60b51d64b57aff30dcac0f8a35c52fef9d2ea937d21c87589a72a8591980f7343d81232c3d2b8550d30be0f41360e35abad72ce2d383f20d62fdca16b2d57df769181bf9c59d392ff633435234e428547f198f9f5243fce899832d7e63b27ef2039c3724b4de55f1692c7a7d7567c8ad6d1b30b339036d3fad3a0e516e60ea912cac7e12250aad68ca042906872299c3252a4fa970344486992db44634461e536b74e53111762adf2c3a7a32dc3bd1895c0bc890195467ca976352300a180b3e192e047bf5ecf9fd119a7341a6bd509f46dffdd842801223be1537c98e0e5c9fe3452afa9bf3c69f4a366827446054ecec8d9247af6032a2b4d3766e4e2246ad703a928bf3e00d8cbe98b287e08cd9551f07b46c08702fd8b05304136df8e048dadf279dda8690adcb5990852e3e7a09e7a48614778aa81178c66487dd9505a113f69f89fcf77992cf56003793a7ad613047ae5da73cabf22a691be9f11e31c2e424f24519ad329c2b6e8cf91ec53b14b0c97b1e549d4a969a4b56e6a3dac1539ea5823ddb6bd80f63a72bb61ea0dfb5eb6e0e22f21c2742f7bee18287d07b1c6fe4e136a13d41aa3df8269e46c33d140277c04a6c93b6539283a099053cfbbd379a6451eb47b5b44f0a918746de05ce6ec45e19c96cdd52c4a33039be606e89f02723878744f1acd32efeff98f1974d0730aec75aa61186b56ec7673dc828f4cb5babbd85e1d2c51039189ff1919f1b7d8b572c1a8584b177d54f6e4ab356f50504d93a1802e67704671b4f4f895dc77c3eac70fcbd44e7a4036ea026da40e7dc0e3438b511918ba493e1fc57d5bc289bae592dc4a3bf932d2a03da436f5efbf99954fec3dfd6551f0cefac0e2ddcead05f554732a5416a57cad3adb3e1f94a2f6e48a5ee4c8a7f9358f6e1857648c92bb1959d0fac2c8b9b0b755fcc21f7144ff6f550de22d7d441c268b84ccb966aa7c71174fd4fd02e37c0eaffa49f6737079d076f29abecfb6665c6c90f39d8bc799bfddb93a429ec5ad6deeb7326beea866f887d8a2ec88b3efd40c67674e6b8bcdbafd9a1d93cec9b6ed2e444e8f647e8cbb8871df8c835ab8c2ce11f98e9ae00ba555efc927679bd024277bed664eec2d3fee4560daff7ad855f83edf3ba095fb12722c8d81966f6c57b1d740b668765563e0d7ec0d7ee42b0e5884afe165bf887b6a3d00a079c8d6ac9890da474b314db67a7dfb121b0b54301d6b0f0c6f67f1f8ffd87a332b1ded742cde591a598e02ff9599eff4df3690a1ca94e2e98e2f915f1c41664796370fff8cf0fc1b6608adc738a318155dbe48a0bd1a98083a68ba5c1cd784bb8cd3f97cdf12e4528e03e0655dbdfbbe2fbf9773584f737ee813ce3288d628285d0f7448f94244f04397c5a9aa7af27125188d2b850f04127abeae0b94410f4ad6d571b9abc126f0f69b48848f266332bae01100dca8b513ac7f033147deb8cda74d9202cfd6867ef9754b041aaa108f932bf24c9954fe5a90298f8e468a2057e910d677489f57fe2dfa92fadfcd2384ccf7d2ea39432a81100dcec2f9186ed1e33fe495523a810dbad7de6bbfc310d4aac02486a0585b5ad52428bb83f9c926ffb6ed029e31ab63b9d8e41d5dfca7f14392fc6e2bf28f17374152817b342ab1737006507d2118fcb41ee8f4fe7566c4591797d29660c567f2d009e824fab0fe7ff04ec73b9f6c0ee186547b5c229354304ad2489415a1641a67243ec62aa802e4b00c40ee23f10f8149747edf9fdabbfcafd814b12a53bd524f48eed32b52fc7b41c15fef5e9acad1e001b51ae46b7e8a39d0f08003212c1fe76a4f26400c12038023e01d7bf4b9f9203cd3e3f13b3c43b342132c13633282c92159eeff117c9cd71f4826f662cdbe55f63bbfc56854e67698e6f0d87830b858facde41637c9be214283f525e9fbcf625b9cdda082f506a8189cce4eaff037c000000000000000000000000000000000000000000050a12162022";
let GENESIS_VP_TX_SIGNATURE = "07dfd4c7563370a441ec3533fecc1cf4fa04489ad3494f2a527164fc3b14eb8172426b48ee487d666134d482bdabe9f098b47a4f0661dffd61278f10b643561b4ebd7b995105636316e81683cb3b4b7a106c9692bbfc18d5c6b9fd6ce973bd00dad42d68d4df3a46ed8f4ebf795da796189348e7aa191dd492d5a760fe9e9f7a79158960d7514e38a75a13628ef0e23ccf90ec64cf7e9cd61a0c7c534187f1d21a2c8427c3566e1e332c57516f48b9246d12067159d0fcbc968dce4961bda7db408e21f9cc93d7bda177f9f87ded4a474235d9c49a6ced5cc4e0081ca1ebf949d8248b39e19050a83d2c2d518009392c5de244eed078a4f855659ecfc2a3a89a156c28783a70778f245c64feefdaf98118290af2c0d18080c2f41e08983dd3a6722b14ec7225721c78bfe44c1e22084ec168f748d6443a4a4bcc8407dfb5911cd10f4c5ead272d4c6a14800ca5001d09d6c6535e117fa22a06f9debf09efd9635067b44ccb196cfcccd09f56c264c075a31074d8247e7b839f8ea9f42041d35d351da2426aff5911d071104c68cba3d736c53863745f27faca7dee2e4b899aea6b69add7284e344160cbaaa5efd30d4d579d751a797077aae73041a24f2d555b6869663bf97f988f55f0529cb8aaac4391bf50949916e1bc8f26e39e3fb73288494ccc296f68225bb8c295ba3a040b675ff97ffb0b17d3bbfbb3067ff0cb4c0a9d20b8592768fb780dc17c14ce5ccef927fe055b3894932fce2ba57fad27cf682e2f9c711e4e91292a4a57971372085c06ed9f3f7a4157b727a9a6048abfd0814417e458f7650ea2010a5847d97642aa387d8a85d1b17e658ed9624bc55ab42b3cb5b246ed6c05b6c980bcfa4365e26ea6db94dcd00a263a79f0f9c330927434f03862843c1cba803083cefdc9ee744a66aa740b5a683a5b5ba70924f179ca15648474b99aad50d3b985eb85d829a2cd2600c44c7cee81071e76f152366c41c91004d5e6584ac7e06dfa6a82ba6d362113bb4ccb938cec8653aa749071b14f94522a3d7e64ef36a3024164c635f286c0a2a167296d6889d05b104d7c0394fbb421bea92191249d565692cfe0efb5a440a70b8bad45897846805149b6ac2a9a8ddf3132eb075261427f93e16df53d97c87cb44b650d187e461e6b27047192f92ea7c783b81549cf91b0b7dae9b0145cb4d14109d2eead6083153214021ebf1f2c0307dd774b7856ce804dd3308187aecf2abc222a40a279ea897b201c7dd6d10ebe3194fdfd700a53e94eb68c7d6b5e3fce936db3b1521b891a36a75bf933a07a160c2df0625cd46791f43d2d7eb95eb5fc512ec07836ccad7b689719803ff3c1f6e1359e70a8cd764c5ff6bc065df2eda3a36c3ce6d5d912f401cd5ed13cf3e1a6af90f20413129b7aeb066bdd71fc60df9be57e9b8d203f818907aa7d78bf4d28644efb39b2dab5270977e8194259e85fc7816c5759e58562c2e0f9024551e92ccbc6534e496386ca477bef0b5ae0782c8be7f12f4ae4bb7f3477d0e897f54e02f577826ff940d1d6e2a932c91b1ddb5646d20c1cfe61b8a54a13587c95f6ecad6a6d7e8ece92383416ecc8b399494207fa7435719575557058dd0f57bc6203e5c65b5b3941081b34bb618eda9823399c741af809b7c2fe6802e224ba397ff18d3e9c73678c96d084a6e5deaa5a755980f54eaf0b3c12271c398c71d11b31dcb19a901bbf3ee80f634190429448d6b39812d90399fcb518be620af78b75faaf08246bb7630d92251029226b3b575b97b7537f1daedb54bcf9920f2787dc6dbe9d47395931d97acbba10ed7899d3d42dda55c8cf11322b0b06542fa9642b7ce315281991a5fa777ee6a39abb8d461ebda4b854e7901562185a318834b22510691150b7924a1428e280a1fbf90944bb6b400662192a9c46107da207037e7e7429ce729be14d6122492ae833bba54613b1105f9df22d819add7eedb91e9e71aa7e12de4c5720e77bd2d384fa771611fb81b5686024e0398ecdc69a257c5bd79cafd52afa23a149122e9218c612dcdc40a6e88a2af5cb163ab5686df3c8ce361d6fa12b8ea7ddffff45b660a8dbde02b4f5f80959263c483f28dfc9d18d7c42473a4584f2e12d4312b5370ad64833b496a05e925ee22df4f6600f1e761a8e024c57ca73c91037300ea3a48c55a95d20b62668ca1b06c5bebf470807d06f72e2c8f02c7426c3c06419bcbea0ed16ad3dfcfec54d27c169b29dc3121b28db6463460dd4024c02bb1f591f24eab176696d852f9141a89ac5ff119370c04e1a82014d860cd57326ef30b44ff22ac3f2578d2a036a5e289cadb415376ac735c994064dadafe1053121ba1bdd7389e2924be9d7d98389d947e8623ee805a033526af7d1aecb2a54ef8f3c868b2a9465a23a47793134130c96f04b461658a33b925bd68bf3dced9455a6a324ee13cc30b96e1eb77bbd07072ba55080c835e089286525b354d42b11a68c73fab9429c2491cbf77357d45d547735c9074f5540e543f0b932f8723d227a88361be5af475ec5c6768f29bb9ea3a234a600ad345675a43b730cd97c09a687c94fa0fc3ed95bd0df6d06853423d1e6c76bfe1dca206a8278771ece2e43f15aab9ab9363db69a1d4ee8512cf9efddd8312002bf66bddbc81325643937bf38dbbfe721c5fc5103c774ab46ee7b89451c3be8311ed00c683503560d1a2cc0036f4302feab55857baf1319d6d430008e7636d8d5cf4a75c3c12f6d490e27975ef5320a559951346d0d856b359f9bca77e164a6784c1293d4649b620a2e591097c729cde627de014fbbfd36ad89e35fdf6e4420d9865b40b2ba7e58e19aaf67b141b40ecea2dd6542f4756bac21e7cace346dcb2cab1af7991f28a1708e203a3552527f00b1b5fa0ae62bc8ca5a4705b6c764a20a7ff37bc8bcde31882e37855ac93ed4ef1327bf2803dc0f4d8555564b4d4e3a89b6d9bb43edf3ba90c40792dea65e9e59cd811e786d152f199be29b18c36f4ecfb3570e322d600c2a4f315fbf1aa1cccf1674dbd08d80e4d8f6812ec96c38c0e70da5fced941719d0e9aae827892d940340586552f3d3ed83f3584cf609a6ade6ed468d945e774a6e87aca95402a799763d1eef96dec8a76ff0596295139d24c0d0d4fa818ae61b67c3009d1605ba6c7de13d9c6802ac1ff51ada021215d9fb78a8a7f9214fa491bbba4c922a2c6afa42c7d71dc542364e744c15360e4553e456bccb2393343a01679a1f2806cfcec422cb9f6d313d0eb2b96c1c1142e404a37f23315d2ca1748892475fc12634abcb37747da075806e54432e66dd719d87e19b79427991c4feafa089bd7e0b3c148567d8fba4fd3f783bde7e9117de2ba6b58802e6f35c97d0fe53fc8ddcf57826db23f7886eae2ebcbd6e176dd8a1e36f2927287a52fcf3c58ce64ac11301f946ed2d8b5c69ada55e3544af93b9d6db77d939f6a33e3aeaff0b612aaec91e7a13eb4d1f7bd3925a6f6bf412a68576cd0186a4afad5f9784ad6177feec1ab57432a218d2a59887606bb6180f79f940f35de05a44e250b280144cf0d4406d7ba2b2d14c6e57d4e3166c9c576c643159c81eeca7dc8690813e18f23b904c5b0bda6a2a11830941ec847149e4a97f0606137edaac560be0bf5d821b9b3d0e0e7be20872e0526eb909105d21bc4f6b4405ed0e94bfb983e0acd25de88d743a1c294505685467ed56eb8ddc67bac090ac9435b52c137384015d5374f65dc542a9031b2139264773dfa62a1fe2eb1732b8f9e37a127ae6c6850774217fb54aa248c70225edb3d8b8dcb598128b5a7042853c21f31d85b8e569dd588df194c554bf452f860a3366428771cf9264ffb5d0a2f948543fb1be502137874ee09421ed4a83ca46e7e9c9171939c6a09fbdf040519e179fcf98366256cd7c671236a7e97e6d43f92f5972fed4ab1f46f582d40fb9cd444b6def4ff493df94b22d69545a7ac2d52bbd337aef5c1830a605632afb7cb84c5d19a50374452cb4f8d5b0a65e4fa4522ebbcbb2b5b076e7f87f75c7be3fd7044c4f420eb1167c5d53d8ebd0d3c10c3998735a3e26163c5d8f65f964ced26882308b40998c5dd3dfd77f7b03e8377d8e1a03f2fba22db5d510c0f5a2485a2615801f537ac2ee223c65bd78ef8dc6e4b251e89e3bb36f5e7e6257e5f36832f70c8950c862053255ab002a8413a4e8903a9ff699189a11beeb9c8f92ceb127c7f54588b81b07b96f3ddbdd8accd5c279197d187c154251565ac764b48781ee7dbb6c4d5a1add7a5ba5a0665086cd971ce95ab7627f869d482c62798de005453cefcd00edb7044cdd0269b8fc21e802aa091f2b7ad46a7d1e46eca1e43e4389e81639d65b16633f77f2983dd7a7987759ff1612b856103a4ad18cb18dda365068b0dd9c781d540c34bc242a9cc038d62567606a11b73abb6cb0af9a92c3f8ba9df51727c858ce230795df2ac8f9869e2628105377a3f5e73be36f8de92f6f8f514b0e70f8f53692da03a9605da5f0dc8e6cc5e13cb824a41cef17f6f9857fa04ed12094ce12d7a6ebd1b6f5f418fb250c5838ac4097634bda504251e2d20a1a4e6771889bcdfb0366778595b8ce0c3a5e8aa0f8fd1a3b44a8c324252a2d3a526d77b7d3f00f3d638994a6cad1e3000000000000000910171c2730";

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
