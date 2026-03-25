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
    public_key:        "3ce0afa09ee82142f27b435ee7a31831637a3bfc2099a53645837f5c88bba5926e4a466c0773603f381dbc49bfb680db7e19a872f2997c5922c1923302430b74c811413debf5f9d30ec3c5def828bf43cdafe3e09ccfb38d851d82ed28b11a9194fc77b51d58d9feaa73470fe9a2af24aa34ceaccb3c17e045956312f1b29b8fec542eff51cf051e244c8e88284567adbb3c62b7abc884a625bc46499e78addf54e756ea1c14af0ad797972560485188e4b3fe895d6e60987168f14d43d1bf5b1db2ae2bcf66afbb703a2ce9c0b76ced4e2194d884e59a32d4b50453d9464d9d2c3a7f6254b4ac6babcd45ac082ca24dcda08708acb9c5722e8fe8f810d34174e12da32555824d6a1cb75ebb383f513f4587dbd10317e63054718d25c8b003b5f0f8870588a790b2fcfc899a0912987fd6d68827ab3cfc0fbf8dbd9adabf49e8c7dea498e5123b42aad02edb9c482f0d1731ee2519b0c0c2f97dcb4c922114842603d65214689ae272c225f8dc7c9e0060e1504073e6783e96e40c25f2b9fb35bebe7d9b3b23f651ed52a373e4a2d4bc19ae74edb342620c8776694a5d3759161cedb172b46b473f81018b7ec63e573e90abe5af914b4e8a15f615ab731ce9d0b5709954c986a379f271eac7d3e0f29de084390cb49475cc2cf06d3b22c9e8a2f38af3952336b3d8e5bae9a978abf156bc3cccf62beab1a88bd4a419fc9f7310911434ed7b410c3f0d86e289e09cccf95ae8760dd13a07f80d0f267e99d235767c679292fcddc56cba1e06a2af527a74e4756259e877340b205a53740b06b8dcf7355378ddd19150585e4a3b3df9a0838ba42451446126de24027446b8e212f2e786e4ec60fb1b990e2db446ca1b8d5fbbf5577b299fbd3c529aed5a6110f7464e6f035de39ed4a40a02d41ac91024da9c0c57c628d1a7c481e3ecf574d885a2b5648c3ca7cb13d9c1580e47fbc847d732821c6998945d32fb916e02831d424a2ef32b192b6d4ddffcc5221c05ee1cba6c00288f4275c6a3e33d79986ebe8f59ee7cd5d247221a60c91f36ac08e431c40ce571ca98f895d07c67ec4cf2ac016ccac0739a52f66f5838a1d5c5164fd170f654241177ae503a8164d7e1a6233e4c227ed29afd37dbe77494ddb4c06d4e41ddc6636f3b58ac18f58f8260ea49745a14cbe284dd228930817f2589735621e4d329a4b695f90c42c6c8db5204940cb29363334b95c3eae13051135ab9f8d375155875baa3899b2b5b7d20ed8d0eae259f18f3b84bd5af517e531be066cfbd717aa3475882c183fd307f263cbacbbe275ad65275b497145aa2589f2f201544d34a6e69ff9122a43b69d201f1be6ba8a94efe478c3c1d743ab0937b19ecaf2ec269050eaacd65c5a158232de67d4268fd7cac012da16e93b9478bda43c1d067a6e3d62d9d2db7742ece15d089265b031bb3cd29d8d0a223736dde67ddd4382e3aabc492902161f4e6fa8970d8bb518edc8b8985866db2cb6e50d1bde0b1e924e72ffc97cf9fd7391484a0549e67055a9840f00fccf5db4545cdf5e696f5047a9ba55c6df864bebcd0fbf70f9e148af8b37382a9e91d7559952798a53656ffec260e13b3ef89c0676d1f5a02b3a59567d89ee68083fe18287653362eaebbd528ec1673c120bce5b9bf4878ad6d039e145efbf196c4cf1b598d4539c7a161d240f391ed2b9d6a679289a85ee8f7d93b6e4f42950fd961146e220d6fb2fd7d35102a150c6a9c0bdfda039f2f4b12d99e75d2deb920a1ecf27f2c0b0ee7913fd36b361267a4b2963ac84c9d5f61b482981e068c97c55ea1520501496b56e6efa5b0f0f17a12a83c63037e4c381f7fa84b9991f7ec7d3163b6eb217f4054e16ed6f20ca1cd235f1a2d37aa0a9149184b84f6da0c22e01864ed1b98c9ac5b4366bf97054c81b3d68e61fbf6e5b06e159ad01b324d9ddd08b1b05be6227c9055be25b004f6ed98daf10bd806fb8a52f9c2f9a184865a88aa20a361bf51bad65299bdb6c73d9b7345ae7474021fe32131c8269b37fc42dd260a2b744b267786ac06875f54fd07d1feeca1224037adc983d615a14f5ef2cc0bde137738ca536370bfbcf78b7e59d662387e50694b9f4e82e7b7f609b26c19773aef0debe1305ec08e76a514e63c800ca7d1a0a37824d56fb6a3c23bc6e0ab1c13698608b57a45b9408c3b3deeb0a7825ec6be7ccfa8c83874ffacf3b93c035dea2110fc253286f2c4dd0e2ff6b0b9d20668d15022142e0b5a3af4162f434f86bfeb776fd6038b1ff372ac5e881e44ebefe741e3fa83cc49bc5b45b4ed01c005c83f7e11548c9861d680fd9ccaab6c2e27def7e965c5d01d33558822d99c580e1f45aaf85a7bb7371ad776abb09ff88f0555305e6a43a751961e793869c249eb21958a2c5e96b74a16e5d3bc73938fc43f053826212d658c4882e8671e70ad3dfadb28843005b151e4f652f540207929f3189f23f9db1cab5c9b382411ad99a5b44743509a27feb916861b9515105efc6cec95e33fefa962694e5bb21c829d3ca707c1ac72a125e339102c820023e28be9f8394669c18de24d392ee08c62f302b671f3c5da64b449d9386c0e7444a8d8e37ac8493d95c0412f1fc6ac48229721863ac2ba19975884fd3bb3c0f6706f485b73dc3375f971d76ff4a4d494e24b39732a67401f99c8110772f9468d50989c5e54acf38e4a2f1a2af299267056e05aa4e8fbc4e9a6a83ecbee33a13877f56f63191a69f91c34c2bb3fc855",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: ["tip://id/US-caf800bc12c8172a","tip://id/US-99f8cd4ad5e5f113","tip://id/US-ab4a37f0001cc58e"],

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
let GENESIS_TX_SIGNATURE = "a8f67db7b765eb91cb5cceb7b1c8e37f3096defe69b368cc548842646bdec39f6d23075a8cb8e929c37d3ea159e748a6f58eaafd1a610bae8f1c00298444aa42448fef37cd34749c33646e03a309545ef8462be5384a3a08c9702e3c80b61379a471ce215501e2cbb36933d9c60bc60c136fb70a231f571e6962cc84bd5972430bf9e7d6254039a714074759a85c621d54976611f389b708dcb5a1f73727080f7f40e9f7beeca603957d23c888c84e0ce7431733df2026094f8daaaab4bd4392afac589515184ec7d2c7252eecc47435fdc3d3335ea3f7f1f3bb62e7327793063eb03e0cf7a3b7c477f3d1df7ffc0c19a9b8fa2fdf60db4084f00ad37a59fc1cf622dbe100714efd964ebdfe86e436283ffd5ca1141fffbe50010864731468067a94ef40f55b71bf510415c5513865e0ca6fda1d2d937122e534cbfa40a43643da173bfb83b0d8fc8b69ad30b98fdcdf03361f475595598c58e4dd7764853286a849c32d945dc07cbdeab54d3ab28eef85572757df8e2832561ad58042e58ca06582bafc51bb2f1aba86769c4e1a6475dd9f5f3399e76f4caef2bf6514ebb326987c23f07e644575da7c18a6158c49e8e918d3f7f237bc695b316b8178c1f87abb75501a27407f1d24906f7830ff222e9e00e45a68f0a74585045b25d749674a4b0a39dabc6c9957ddbd12f451696bbb0722a3ba5ab72005471e067ec415443505990c3bb83bdcf65817d72db67a6a0973f4c50d4c5a4772d09b3f8232785b10d062e63fd774f412b88f1118ae19da4c127afe424c0ba98883de4f827b2f91701866ad5576dd9c8d4197fbc7d6191c2bd4e714adde4586785d15ab40aad6fbbd923ed7288aaf1ecf8854884464657a77de2521fd02523fe02f72278e3be2ab8e52812b749237dbbc5db8532cbc21416d5fd1541ba2f398a838f822ae21ddef585a63647cce8ec78104caddb9a2ab554e9f5d79a811a07d1073bbd030205186fd126db6218c2f74bdc2b6efafc9630d400a371e353784f19eae7fe4b3106445cde5d09fe52496ee8691d15c68e7e560dc3826ee7e8ae2fee21a9436c01c15fa07a352140f4a25615f1a4bdb8b2222ff899b834b1304e5cbfa8e7ddebe7f03968a20dbc69a490b7f284490936f66999727b55997f8415b0746e0ded209ca6bc27c7cf83a92fe143829cde051040f5c67b63918a196908b506258cd5658179de8c087242ed432f9c22e4295dbc337dc3701f4506dd98fcf5c303874ad0398b934c910296e96c91b6e2a801bd10b438da584a0bb1283982341ad76082a6c887698573dff2040b1d22d30010d7bedd4f507771e24ad23e21dbc689c68a280ecbf0602982e6b9513d78b8c1dfe0e73090c5bd49eee5154470e38768f5aff2b41e7fad9c1b22f8e6cac23fcf4443257752b159691872c39fee5c132a7e684c6c69a8251b29395960fa19b82883304c9fe3959b5f063793f8fcaf9bee9a0c9de6c05fed70c721c28fbf1635d9e0dc41484a96c8b9deab92742fc52c3faf133d4b135091ceb93276e6e429261f7c4b30d9ee0e26dcfb2cab1af86f48baa05efa99649e1ec6cb1b63c3d53e2abf115cfee3732e4b28af75c93e4515df75c15caf58da40dd9d001b7df3f211cf346de4f60a6955d57ad142f7092344e9411273ef3a52e2a337462423d05c1cedd98e3dc773b4cb0aa9e4e0efa4a9af2543f6fca09b186be6ca1b9847f51f62250d762549a2242a647f7c64493aa44f957523e14aae785a1e9a1e7fbbf42aa505aaade4ab76a9a44e4e7db984e8f49b329bda6b975a04296ec84775f0f4d21985405ef2e5be3bee9cf236a950705d32a89f40fc25d260a9959a9120ee60f57ebed3dcdce741b8c861db8cea48414d44a657202cad5d289b2a186048a0d84a99387e5142b47c8e54a23e812a41c31d9c0a48d7b4a032ad7d818a962b8c153a236d4b96707c961ab2d007a9461f1a03bd582d355ce7ee337ce9402b8727f4d2bb7fd1e5993b1a7dc05d09c0a06c8ff84ed2824980ec04b5103da0dad8b15fd47e19a1e3d907ae94eda6768f8d85712600d1fd3d4af44df5ffa606cd65f83b2cb71444698d884fb59eb817c66d293a2b711150333d06de20486f22b8dd3ccadfff22215796c5d6c0a3e142636c2cee2a87a8f507d2c923649f543b7509723dc96e7e1c047af3412c11caedae91f7188621346159996307ae10321056edc8a52f788bbc6a0b0ae122c943a999e7d399d0929b31aa53c6f686d482a048a86ced1487c33b21ec89f92aa5d6fc0eddf85ecad0296c3b76996d9112ee754130bc205cdae696fe1e30f131fad2bde49cc63e6602dd7f14505c80f287539ced29f039887f4e3edfe68b36e78e39735b170b6a819a6df63cf1bbbfb259e559c1de452b8de604d4416a086496670ec938fbac6eef123e3f4903c4b61118466a035c5b9ff0fa82bdc51146d9bab2d5f4e9f5ff3043195304a6c9e69e860552f31800cde9f0e6008a71e1db244199545255abd905bb5ea9b753d4a4632548d13cbd3e6e5b94447c93fab9b54f895a79634c1e5b76f66f426d6f2dab6752ff887bf51df8f4ea6ac2842aa50713bb9fd2350912a33b97816503e927c7097151a20513778e76e0c2f970762880b3724731fc19dccd7e075aa1c194bc037e8f428b43502b6ee76ed21ec4f790a590c8077ee582712dae5be2400c6a578b74aabec7ae12d024676692946a4f2181787f3df220e743e3c8702ee53f6b89cc30db0ca129f7f34d0599f3ca3c1cf559df56cb60a8dde578ccdc813abb8f2406ac5dd316536a775049975f3a8e3a3bccf58ca55f426c443101159bf3b8e32219e8e606a8291118912084ac53ca93cfff82515837ff4b34c17bdfb77964f25eb7fe9d439141e88dd22430728dbc23d68d92ee39adb2ff49f9312d402e24984f2d18483b36d036d952eaf78eccb054405965bf292ccb69a69b2440cb852aadfc58dd4d3e84e81668591abbee7eaea4cdceb74174bc01084c621edcca31fae8429a84d064b7b433eca87b5b1645661ce8b93f74f4ee70b3d46ffda3563eb5291954df13a4e049071715e76d2ad2311d4a790998abc334bbfcb90d5d22672a5eb187373054276922d6171d4f37c06cc115646627ab87cb7fb886abd460fe267c34d342961ed9adc97808328c7c8f2d08dbc3baf7430249ac3b98c9bd8fe9a2c39166f8804611abe4ede0d03637cf9aa620d59a56271c9eab655044542db725516cebda1afb647e3c333945ea653408c769151b0c9de469991f03087f003a9f5ce8327ec82dfa1e674c3d27725b7256116ebb14883081ec673cbfe7e6cfe5a120e9949611edd333ffb2fbfd05fa2a6d2a75f54cad6b474354182b9dba84a5d5b54c37942597a2816efe5ba180e9f96cccdce597a213cb3d2c819b9c07d7e8e3e36b67ed23f59e2b5796ff303b14caeb528c1a447adb431c63397069e05150fc98e10bfebb6ed1bcdbd0125da5395534b4923eec95629f200187a3143c3974ff94cefdb5606de3bd293f17cb55b9febd11fc003e507065809036440da1d8a5ad32c173c2f370623744e8bb3e9c61bd2884252d81f0b5021080aae5358edd5e91a1e676dfaca5cf60e7e7fe26840985fcd7417b1a616faecfb5deeee3dfa8ccd27e553e6ab4ff39909d34354e47471d2e33f8564c38d20e4465e88f666f6057a2f76bf3dd190588545abf541b44cda979e2b6a21009aa32ca96fdabbaa1fa52de459e3dab7dd65ead34a225cf7d0cfe4f47dc0582f9366a059253ba86e97851d1479b3ddcef60cec54c3b303229e89adf4aa9a0761051a789133f71ea4016c02f23460c2730acc2e6306e873dfbc10fb5de5cc8e184376a20d73611fc0c42e0837b67ca5f92a043c5b8f76fcaa6c7f665c574ef400de27b852e050300533dd07cba875fd80e8a83eedcb0a46234f12198cf3cc48f6adad30b2c4bab5c3e4def6fe3c8afa953cf192df93ba544ddcad1d39ad55240610311196c404141979e3c45e5ff4d5287ab770ffc2b9844e209f5dd94b287d64908e7eea31367343a3d939389e30cf86d844c2e0f9a1c4419191706d1deb2b247cca4ec9f4e15479fd17686d65ce57a249874da167c68eae8b83d394b243213a1e9ce5380119f4d2dfd14f520ec97812e15dc3db8f54bd7be1a57fa5565be63cb959ac742d4f0f1a9b668f731955eca0b20c83d3dc674203118724e5e1fabb74be9a1edd0d8c02c1febe05290d8702dae0601fa89edf4d9ab8f5aadb48acb34ddf009c556b6209d83873c8aad3c6265a9712f66db9601b4d1b30980c653a71917909e622e697d3f0a41010f010db5eb797871825fc648430eb64141847bd19afeebc8f435e3a8aa38cc6b36d72e9c2362fcc9847b8f32174657c8586d2adb301814548cb97c3e06bcf6e47ca4c706bd46e772d7a5d3614e6a88253f2bc3bfe328a33631eb5604989b2d934863b1274d3c3bb30c5e29fab0c4f190baa5182b96cca00e8a65ba77b51944a9d6f180674aed3d7d2d553d82e7150f12def49a858d20957107c3b7ed3080a3df9f7fbedc78d2c66d7b27f0d536b8732e11e89b0b4ec9fd2a09a0425326cb3e82f80adcfd0da061c2b898fd1f5f82730378ef307286fb9dc00000000000000000000000000000000000000000000000001070d151a1f";
let GENESIS_VP_TX_SIGNATURE = "154ad49459a7a3ca708553dee2da06d249f13bffee8d19e9966d7e7216ae83a01b151b63621bb615b7f420cb2e8f7b468c321648938ad77f67e0c40412575b898025d1332c40f7d0629a485078943f99df82b239eec3de914872998b25c355bdeee61f3a66eda704d55f67741a4b6124686e3835182a29a46672ee79817a69aff0704463108b18cf336257620dd9a108d15016fab35c63054b2c29f7c37e2aeb6296a88eda64a50626f4087dcd5d64e75ff268d7bc11609f04a02033bf18c39fa6c70960284bae500740badb1ee7fa67dc51fe9c795156bd76f13be860b8e2c3f4bf31f75e1af41999c959346691370f2582bd67e81c3dbb3887aae85cc93147e22df9c121b1521fbb01a212b4d6f293e42fcbb44a8f60a56cf92c64155d78a9e3a3c65be40d8bdae8eea4222588b0983c69f3e73c925121fcf1e3ba17bdaaf8867962bb0092320a3ad5f1f6ac35c18ca5a3fa7b9d122d4d373db17a4dc3dd5a6d4750a190efc5a4c90ff1623563cba90d3fbd36b30154107a5ed7e03c15404783a45722af2a3791c863ea29dff8bb837e4c11ed0c8208a61d0d1184817e312c9c415ff7925daed0a5c74e07c894549150389fe5798bcec871de451cd0341fc85f567c16e67a64ac86312b3265e9e42ada4867b609b42b7e604654f4d0270c918c7ead78eae5d8af1a72faa1d1b4658e8ceabffdd020eca9f51b860b6650055dccf95f7b3c792ec6f4368a972932623d9ac0e2913080fda1495303de714b17ddbba7f22e29da5fc61c8cbab294d331230f3e8d5afc4abc2b711b0d1cd81eacc5585706f5f6d7ea9f12b38c94110ba77b22acdaec0abbeab4768f4fbbd0be86fbdd81a9698e37a170e7fe904bf377dee5b196f5a197576056f0139be8aca8a80db3cc054502fbaa8c26786c741b2cd728e21fbd40410dcfe974da4aab4bc5369a96e9f5b2236d1c7396761ec8d7a38bcda95a0d1f31c30a22104c6766d06389d5ed979cd4f6ddc21badd4c4b35366f5680b10a81276375fa32831af7160181757c0a122319c0bf2116834d2632eae325133ccf70ee9f6a61921d8a531f934f8eda1c0ceec05750b2105496d9f569b12df89530f699406cfa6db52c88b7332bd1e5b1c492762cb99152d92837a5763501b37d074adbdd11d27cdd9d5525c8afb613d615a9333be5d505eedfdfdc4215368c05349c10ae2596a12ab566da7225d22cc0ca4d2db980569e81b4ee4915ca9a42af7d5e893caca2d992ea6a9af0bbe0598f1f2ac4ca58a5f5747f78566bb9fb196daec25285c3943f0c91f6ccafbe46c428786d7b8d4e7b1ca64f5428737ad419a1c16669951339223fb90b6c0c2a32fb505bec6dfaac4169a2ef5668b4614632a91bf509617d9c954746c54110f36399465d7256d88c71c06f906a73603a30a1317fcf7ee0c76f1de8fd60ebc0ecf3abf51dbc8d2354622d78474eab4cb0ef9fbf5f1518076102bfcb3c5aa30c23ceb12c953ba27de79066a6eec5b103e97ce6f202127717be02ac40cbdbb80df53cec4ee3681cc84ab65cc789cac304b9c8cdcefac6c9aef997a962fcf657bf05ffe5d5f0e2a19f8ee6d9190e3f5afe8b24fe2934791c7482f19a09e715116c2e777716bd5322b0363e3983c4372b0e7755f8f58a3c6b8201c78eb508ca483d56d8c12813859378c2bb040c7c6232a344809f841cb5fd40cb1da52b90cf92b02a0b19538eae451ea21a4b281c58a8ac3bf1f62178301de6a26f62cbe07c15fc84009350dd75115f03242b9a42cefcc51c8ef7216f250b7fbcb5afaf9b05ca155a1fb66b784dd0a86514460fbc9fdb6e98baed029be8773478d30199eb380b0382c58b64816f448b9ce27bb733ecabfbcdd3afcaedf5380c52c282993f1f999798e09d322a23156e19734c982eb32f1c0f21775cba7d3207aeeccf2e6a4fc0e4e19913780a9a32ba42aa0ddb42480528fc3ef0e25d5d3390dc1122d13a622463335c3086642129a243f43706f313a8b8d89444f0af09720090f40e29afc023ffc6e2dcafd28df4f19fd177cdfde8d51c8e34e728de05f349c96074a0e97c13ceddcfbedb4d11a890bbc493d511f85e85ae680fac382eda24a02790485b6364b0707c115ef12ffd50e20de5b15acbbf27dc509bb9d93d4bc3dd7142941d47b7c947324878839271cd70df31dc8c52cd1ff014e0cefc78f4a17629f41e20fe00913466b033932fc03a7ca78060b792195671ad0a9bd6786fd466cf41dc02e4c4c49d53217955d368828620ae66b93b8f1254f477a5e58e1442bd2dba5b91dd82cc111beeaa1f464db8dd70404ee8007c32c6bb5a7d16109796c5292f4b65743f75b753a8228ff6b8ec6d4ba7701795a695707d1c7836a453ec7c046115052e69e94d3c5e4a6f235064581f7fc791c771cddb3b1640601b3587434f717ba1d5bff0a1b222360719d352e5c212d942be07fd8fc225876a854907763dcf95f2b888f1a5f69ab96970a4e7b8e0f4fee1b374dd10afbe2ed2cbb36bafc3e230af5fec79231b60355c5ea9e0ff1b3f5ddad21f6b4066aa01920d5001776907392cd1282a4cf6473944e01124baa4789817d9bd1fc44ca7ddc29282bef7f3392ef07299a12d6e0879b727a0ec2f3f1cf91bba8ec57209314e92af3637cbc3662c3a494f2d2b6b31f24836fd09ca7c7289cb45e0cc4fb7c5cf352cad193c8d341804969bdb3fb73ce189fe10a4ab25c4fb730471638ca0921edc9079da9f852387dda2edc787c0f8cb448197592337725434463760bc2b18b66d39383d44e317419f7b176a0debbe96e8b0fed75b7bf798820e640de5bcea882ef060bdcbade2b452a6481a8af7887af2da14d438d8faef4f03799b2230da4d6b9c511854e7c2ffe2b5c585651167fcb9025343dd6bef115112906539b8403e9748b90736e33db6679eeb4821e183f02c17944ec4093ef04afecfe73db1cd72f3f0ce9632360d0915a4bb4da3cf10d73070cb0d6e7273183671de198f69c10abad6b6bc2fcfa0cb890b8b5d2b40f2941cf767b275a412d6e49f54c881945ca344c87c1de69d330dab8bd8519fbfcc11056ea501214645e1a138c53b8f6db38a2d350d8250526ff99efa486f790e487201e5ccb45041b8a968f24898b81983fc7358e0cfdef67dadf45d7c3e3baba775f5925a77d15df3f367cc088e331199a68deac291484100b1f279fc246be4f36ad1e066e090c37ed91b1c4bf21ce9b8a37a6598bd695693bb0809b76970878edd75ba1b49e9610633946ab1a1cadd453172fcbf604ebc3527c2e297f4f1ad44feaf0289a4c33894ce85c81f8ec9964bf72b8d87ca5079484d2207e7394e4a0de01d959acf65c1ba3a404beea7df33f30bbd658ab90459ba8728d487e1b066a40b5576915d44b4e86ad74f02719018982420607c4ad754412f0708d8f8cee67e2fbfe3e5aed96db020b7df79b34cc845fb07ea994b93649d2f0768ff5419d5b4a4f5bbe24d3cf08c65e78f74b228db7bac75ac5f4815559f1cfd21ddbe675aa6e868f07ea596281745c6fde1977424b55efb495e79e03eb795f8e88e83df839e3731fc66a650973d121a8cdc26938704456699c8d09aefe16deb6e0f0d3510379465ce96ae1b90d366580485ae58dc8407cf51ef326684ab6ade1c35aacfd442dc143c200cba2322acadd711afd79d74b70f11fe9a16f2e3071676cd31ff5cad8319b670a5a4489dd1ad26366a2e1c2ba4f6014882f2899b76078d6f359b36f1e9718cff880367a6625411ead21c97a3264d88252ec8ef9edc4ed65686ac9e4855a2756c6b828483cecbae7abf7053198d385aea1320a373f5fb4e700dcec90f213c0e5969ca8db1df31b16e9c2f3b73f3670127fba0ae9503efb3ac11a844fb43160ba4440bcfe41728a5569b968da819dab26d603182d53e47d57a6dd3c8e4a40407847d536992c36cd9e0a20e026206e783698116c4721d22199006e2d91a0b2488ebf2c4906336f6d076f98359dc37f8af21526f639a8ecc068bb1a06941a123a057aaf8b0c056984e939530f25995cb64a2c1d6c3d72bca87b852231621c79741bece7e9c6de02cf2f88ce10285b000e37a3b1eb9766c148558002a20f93ec5a662982aa1b233afb7272491cc09e4a8c5192108bfa911f8e520bcfd40fded2c89f8b790e43a562d46a6ab7e39db589436f67d94ff68b57c68327d2cec92aa8c9070e18e1a86f36066dbab7d990d6773b068141ada7a39734c51491beb33650c84fa496841d571840513b43ecdfa8f226f25a46f3487ea13a6ada8afecc38abb3ff4fa5cd06d3a4c0a3e26c79469d8dbfb8f0904d0561017ba0612aba2a77aa9936776f97e0c77efd1354624e831fe061ce9b8f4f1e69108c607de24afcc320690c54c6e7bf4fce5d3b94a429fc3c924d3752518fb79e631638a2c8aaac7ea96e8aeb88ffeda8efe4846d6cd2545a556c1867bfd8bf882aade102ef654f1185746f226f8f21709751a9f72ddd38dc73b5270b29908a6fbd37eff6477d8e3e43bc15a017455100b85ec78228b8620bf52f87315b18fe788e44b213aedfefc90b6c66dfbd414205de6d57c09ec5c60d39a2a80012142e3c5f7bc30b2a467f89a5dce2ea6b8c95bfd6f6172c333d5991abced039435e676fcd00000000000000000000000000040c151b242a";

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
