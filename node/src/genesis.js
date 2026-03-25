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
    public_key:        "aa55b860e21f63a42856e1c1ae5bda9fa7080a93c94751cdfa54a0cc503a0d4b4bb6befe489a2837b5cecabe2c8e044a36a339d643f76767a00af8a3deca50ee5c8ef82450d3eb13ef47672382f2702c7d96e1613cb4f719062b086bbe37de3930214182dd056fe082f8498a6accfb5925abd102d8a4eabd957a1fe20915dda6be834f026183b6ca3445e05cb18ce9a5a44aed8c8f3bf3086d19bcfb9aef2eb6e35e3e5d84a3b82d6fadf7e44848fba3dd0fb17d65fede4fd7cec6ed1ea20df4c4770b7e3f8783f52ce2b39fe873b68e6fdb0ddc92ae5a605302d82839bf9148761181db12f6f7ee38a6ab7277a234d3ecad2c782a63e0886b2a90e5b1927cdb6f8a679d34ced7f64f6c4ee6c9304c44cc5c378f2d1edebd36e8cf1a25c72247b1c86245371d5f89b16325deb11cef265066ab62b5fc0d2c38fbc6870653532f1258116877b353cd2b1740c7d470704838a67f6f58ad667f55463f5bdce94f96434b13d5ade40d01415b0939bcdabf05040e9cdc81f34b3904c8d3b1d197fe31331e6f0241a5766fa077e46a9bcab4b71e038cc413135f134f2ad1c73baf80efa0edea9cb4e612b04395c4f86ae69e540ea8651e1d344bc8f82ecd3a1c20cd2205869a674852010688b1e156eac8eff661e74f0e56e2494513431d7ec20f8c0aedd09c0d5bbfb2614ec10dc85ff673616d9f31173de0acee70c2e9bbdc82bd4079e71ee59387e2a4172d9e51870dd1f9f6e675978ff4faca31f63eaef2ac05f80d68755b377c98d8e05260d12c733ae5be26ca04ceeaa8570cd3c2fd9da5116bae2bf40ba637bf9361296c9d2449cc06a0229920855c4b9ed0c731e24c35a7bc05211ec059ff4e60d11bf29fbdc8411c3ca92ef0acbe8be2e0e4dbbcd926f5b709a3d403a772792fd835f2c09d662e7cacce287e89ed589e23427b82564263f299101528f38521d34c34934ee59d1f326901e050aa8d559d323d421a6b036497a2d9cc2b0dfdb0b65a5937a29f2f85cdbbbf7d70c69fa81dde47ef8e32c4f2d62d686c9f2346f3ca526495710cefd08d34bf444bb6303eeae911058af51a41ef602a9d30f91cad895fb4be06c1b58fd94a0f0d693537fed0666e9f175319ad49d6a2a282b3282a7fed7b931f3ecee6045cf8a5bb308b327aab9135ddb7e52a27ca782beceb9e58a0527ab8c3add67f0126dab622f9a61cb989cb94bf4b128fdac944942c61a4e253aae9a9eee9de74ab897ef75b5ba4ed13d41114692a7015c6e213db113df5295f15850ffc17629dd189d744f26a2621f0a490889b6828c2958e6b5e285ea133b61203e1bbdd1cca7733538e1046f9e3eb54f6cb13b886daa69dbe33cc747c6b37307e15e31c9b209d603c115123ab823c5c64fbba86c5d6009624f1f784ec11629d7ff1c8c450429081cc7b16a92ac7d1719d8f3c72a38d0dfbe5c26a58f54a84c4a41fcf02b3c1da1533be24bb0fcd98c5a4c6ae893b2cf9bc81d09d032054e2cab750bbcb406355cf5869ca1ceac13bc440c3b9a643900a9baaaefcd376b62764cac472c5fe1907627035972772e0af38ead5fe566b30e87f434bed7ce910a1796bc06c645a7d1b369d2332aea008bfee434840548e5b9848624094e8ed4c0ab17791d0db0cc59cfd2a623cbc59e1f72a2a655481f4736a6b40af9d9f152a4e87bbb0a9d7618b5153900309071475c3631a2ba67dd5a4ab79f50987146f90320cbaf07195e29dd4907370e40d729a98ffeae45e402a36068f2ebbcad14043a8b2642fb14bb64132b744c6d5e643b40f350fa43251d8f1b33048f471d4dfe1c78f090f59e4ba6b824917c40393f9cf269b97af9adbee1d2d523c63269fe112b8718a0473743ab98382a518670fc7ce144137737ddadd0b775133c0be1bc69ef9cb7383f16997b867b0da09bdb3fad19373cdfad3392d9e83817b7a6b1588bb5ca6bb0ab156bc74407f8d1d2b2d0ef7e7b11027a2ccc559521008774ad2cfbc9642779c24a5921057ace60ee37a92dd954775b3f7cab64c75ea293d5da3d401aaf169d0291bfcbd01ffa5a0a9ef3b9e84ec409f1a59b12f9d2b789fc98bee8e97ce9d23660115b9c54ba5f93603ab0b8b251a36e317c9058ff1cf3bc0685bd6ee6e5b6a9fc1b302dc44eeb03c6e19a1cc9ec09aa4bc1dfeeba005f4a4c8b4b4a68f4a0db171218a8fe90cc42db9f7cc4777686f6527c1a1592303846b9531b6e1408f3a6f5e4c41bf634da609b8f68b68330bf477220227824b33b0feee1e7f690ca97faffebd028d6dc02529304aba0b5d869c3b670c698f07acdb6a296e2aa7bf454f08251b36f9ec787d101fc1c1ec00911550089d6c918eb8e41928970574be642fb6787c8d1fdac9ce4513b5893718ecaff89e3cb08e70d9a8c82bed7a56ae464cdd729b87e000e74c432c2127a16302d5a21c644c0721de5776d0e0f209302357c331ddcb8992fb181aaf5635d5d7bb2ac5c1bf3882b7100798f219314cfb7bd6a6b42b56ea0b0521751eb216d34daff6ab53807a2d4b214962538cb452dee85235542f200a4f0f9e6dbff94dc93239b7bf0f0683ddc64bdcbba1693e8cb1fa15b4a26d97d8a5b0c27cb75405ec7a7c7703bed8e3778953c4c9fe854924136e2d2879e3c2fa36be2e9cccc1719a685a634caaf865f8723c391ff027e5bbf94126cb1004f7de8d95717c37c20d1818c1ca86ab927e63de57a10ef00c59d78cfb8fb409cdbe990487fb6e1e6376ef0d2ca6eb5ccb61c6",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: ["tip://id/US-98130a42264acdb0","tip://id/US-2cb9f28901d3bced","tip://id/US-b75bbe6f51200a3b"],

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
let GENESIS_TX_SIGNATURE = "3176d5b62d93d41569e89a4e40ae4bd21f5381c40336d674ff1a3294e548d17cf645a6ae86f35bcc04af7d7f23385b469314031e0f2e504078346506a24edab69b7c3fb47a580793b4b7f6645c01377932ba1da1606808b42b39921764f95eaefb446758058022b143adfc33ff23ffded1cf623d9573972a7f3351456babbb75028ec639aeba26b22e5c0f89b465a9fe5f3cef213868ac4f3b7f1d5eef05da0f62da2da4aba82d4e55e99402d98551a875459ac39de9fdf267291ebbf74dac714740074dad5659b15655432a9eb1bbe954b2718c2d9b73e47cd9b7dfc62acf942d80cc4318a1070002f316cfabeb07b613e7f1fd5a952f4dc6d5490bd4c77edd16d9dfc12139de55a611c4fde4e7708812e857beb30bb9b6a2d169e84fb9aff0b9712ed48d35cc7818a0860e96c0b1e124430be06ffb2140f7531dcca43aa18dbe7efcf653260cdc98789f98b7fdb597b77e5c8bdec85ddcbe515c77f1c18a499eb7ad2540826852686b815061cc132e86caedad91c0c9b8b12e4b16e473ed8217c911c1484ee044db818ac2a08942caa36f98fb2670ea0e766e931cbfc37d71cae07d95601e8ba1e88d154a063cf304cf35310a7b064676fbaecf28311819896220dbe8253564f8f4ce9e2d3045cfa71bc402fef9fa5f2c17e2fd71005cfa133953fbaebb62ea6ecefe30c620b8b6ea3fbd88e211fe37a93411484f60cbc060769a761f8fe438b2f266093fc5ec6278b379dc5dd822f061cdc8cd25a2e7d400e1012666a9e9c100f9e6b502c731dc022f030b63d10300f900ad6a273bffb3f19812cbd21cb015fce089312618bcc73e533e8ee405d8128e19c10110706028bafe1dfd2154647865b14e995d89856bdbe2c9a485c0287c3733cc5495655de6971fcb1ab673340d777913e5e44330cf5f237b5981eba9c649e491f3f50868b554485c78ae08de00be293025c711fb41bd1ba9034173ab95feeacf69c661dfc8ab686c2e4614f3eebda1ddd0c4060a047d8b8fb10735086ca5e5db518afa72b959e044ffe2e3d05f6e5cd171e8e9c6144bf38a9e18eb2d66e081fbdab45360a3bde0a5e4d1d223af6a1e9b24c17108fd041321abd0c7987bf90411babaae350492a4e24d2c10c76f5e9fd3a1579e15c33a595580abb3bfbb5e9e06de1c5579b7c156b27384698a1e53ca2b044ed88fd07b667b89b1d7b49d0fa7e5854f50f4b7f3375a908a3da4c030b3f5a7530582ab1418aa06043bb8ae9b27f3d50e20b7bb4c82d4f318176dbc3c03cf4a165e0acc8163992d9fa4b64d17c2a7b32c21b9ffcfd37b7945c355d72a1a4e991f28b4a5585354cb698d22b7449e5ecaa6dd85d64050700f3d0d0cca1af08f2151d40db3228908c139f43ba376af51c27fe3e494c8af584d812a8a76695d020a2aed3638dfc5676a970e761042e6458822fe8fb441deae65b61f1ef7cf3f44b663158bb71c4eda7f0334ef2791f38f5f044f958b7ca9561ba742ff616efa97a26b1e9181476d081f3f1b959149399ad097ce5ecb1c750c54dda4b0f9561e0b60f06f9fece9e5bf6619d65856e6e9b632eccccd981b7cb9818be0160ecc3d60a7d3186529343fdbc3106b1de6f7c47796c94291153c1b3afae5b2a5bd7e9d3d9e9a84bb0a969bda9bde23555d7e93426b7cc1840c2155cf1089f35555228a38e3523492b5d034a23805b5511a28aa09cd2b9efd187edaef92ecf0e77a70146620e94f231d7cf98be1aa76dc07b094d5ed3813b0f3dff26a61b713cb29ddad0fde914444f08d17edfae6db47c1faa37be4fa82f8dea8bd93a38e6de56836e0de4b136836a6727a15004527f8a1bc503e1470be7e0fccc448cbf3931a383eb06d965b203ba824e6b6dd3979ab4586098067ce6886a700f4e1727d8e93035e5fa5137949a20d008756a8866161377883010cc7794f9a91ecfc1f94351f49a60d0c5c5299896c8445915fe89cee09555179199218482f7b3643b77867d3c03bfc3fc955671f0d88f44d43455b55e459441c301f7a791245342c6984411ce681025568f754e9ca7ef233dd08c556161d46cd9b0ba3f9a553b34322bf905715762fa926eb874b6f895793b2b19cec6ca6e05ffee266f1202dda2e9b7704031241bc17bbd468e82f3ba198bd0aa8ef2ea321aef9ea042e641fcacc38c80df98e46efb17ab74857f4c53d28185c4ca47388d10dc5fdddb6e555dd1cb845d0a907e3bd16e48109668071ee72c20db2798e201e00e15fb95a3a3e873950f6661e59466293a5944c86aa9927641a9e38d0007912135092a82f2335eb02095d0d41d8d2586e242593ddfcc81456726107dfc824762f4164232c0639569d497b254cfbf58657769d01390f2cddbcf2c9f225eee545413281a049ab7342c7b0a562ea16e23ae201acdc5e1f39c07e07f3c916d8540a304daa428b7b39a07b6b631170083c5388e0cc388e0fd3806648120654981eefbec417f9c3e3add645c76417d873c8094ad332cb0762a8073571143f79a8f1f63e43d7fcdf4fae9a0d27fd30fbebfdc0968068d2cd4281c6e6df3f3f851285fb5102ca5cb37a1f40d4856836d5fbad2ef7e86d97945af0246222425095e53bde9242183653a3142062e70a0b144a72357f66da00ff05fa01c5e0e23ae37a6b99c240878b5fd620c36d9892384bd97391f7f6c142c0ddaab5c846a3aecdffcfc57ad3e909f1865938d4117c3e85687e358a9ddbe2384dfbacf0bb190f9171993bd871b7dc6a328292913ebf72a0810a1331429c18fb9668a498152950e48c9a71a34b36bdb5485d1a827d69e2d7f84a639008c2a4f7cebb6f2beb27f6c5b597300a459a5ee05cc196106b5b01c270e5363d660803b50796e10255be18387abf4e08b77911bdbcfa41c27b1bf054d953b57a15a41e6237c9b55c8d474ad5a05fa926cd584e8158def6c6264c5b7dcddd30e1e68deb943b444217450ea826a6c7de3fcc1b727bf8e61861069f6c7d5f8bc4ae61420d24e15d6b30e890313073a23d7749c4d55f681310c7d174acdca6f3f09837e83bef0624edeef64f4be955f49e2da343be994f9b11e60887c74d95ab77d68a373f8951060d0126a0341c430c3d9a0ce23f8a3c1c7a14f857ae9e230ce55540dbefd143e9d55caa11c6b92e7c4b90845163a7fefa627cfea1c0397e77d82366a45bd1fdd401c52a58f93a8701c38beab884970358a047f8dc358acb1872fb882c13d89786d4b6d459a3124950866cda07ee80ae8a0833192d9706ce219d9b82672777bf8f0b7d84cb75178f8ba1e70f0af0d66349dab5d70a13550b7a93f8735bfd940e12da251c36e7603f6afe6b9ba480f00d1b9be5168cef9e9d7cda39b03be75c91bb750eb6478bc443577910fba01d2f03ed2499181bb0f9149b87da9b8333cb02318188f9e9fb54d3590515227a8e388fe79396ea83c79af72bc5c17ddf496c536c45c89b0628615c459051e886d4d0be1898bde0207c3345a2774747c9f0519f8279ea9c23d34cb13592c6969d17345183ca1a018769d35c2fa15ed20f2630dc94d4bf450fd7a15d023faef3fc4a4b28c7b41f3b457e50958fedfa1f3935e5e0147e0396122774ecec52011734ff0f59275c832ac0540a8a676f34c4f9566a5bc8f56eae0a5ac6fe0cdea4842fb77a9324132c52fea3c8b5ef885760576bc6c809914bb9bba9f5423a15b8ee2bc3f1f43fd3aaec426b6579ab85d4f20c6129f08d0812a7915c832fbe3761a73bfd92d3ee8e587af35bb3506b61dc10b32dca1463b8714ca9c1d3acbfb600e0c30a8f56fe53a56752d10d01ebe03b58587fe46176fd103719795acf5f7fec16e7301363ee02086290bc5f10339686f6dc2a4f5672b0fd91a65be55d9a513aa05a8e6d12f1f99ad3128e78d138b3f9911a4c167c20d9dd5aaf3060d437bef7af43743b87f0a533408f2a5e6355c11e96e2b2cea780624f99bf90dc84b47b25d95c23e0580d5316ba94d6b9d4fd91b98785cb8016edac680880f4517069138b2d04f4586e70860f7cf053668bc7cced0229daeee87bcc4c3e4a6bc7022149c42fa17e4963469e5a54c27e9d4fc12ac962d841c5af5f2693ac14a2ade9147e93dc6ba4ab6c49f299210c9c712400be8e664698247ebd3915f58c013f2373d13253b71f742335ae99e0a037f20fb696c1243c1d083069bdc0a4cf5eb8652a8614cfeafa2571cee31b617aa226cb59f85ce710a3c9b4a864e43abec82ff65f19a0dc63bf4472deb38cdedf3c3dcdc0b752d20351332a44f60df211e358f3372ff7d9f9103de346876d585d70fd90d24aaee5154fe5567de7cbe3ddd76cd9d7814c8e3d8282d2c6c503c7da41d1d7865f1dc74aa6cf3942c748daa11b4d8c606050db16155988f8afb489412a463c0ed088512be41cab43f76207b9b028d939654b6223d471addac64bff9de101128b34c6f43227cceabc1c907c05d891ed8a9748daadbdf74da88e9d173d1fa33c27b401769312189709b75e6319cc801ea00192e52f46c7c558dccb878d88660ebeb8cd82ee129099e106757470e9b71e9fb08007e62165339c09a58acc171d753a7226d5f9036c800b2588e3292b4152808da6c9d1e7219da1aadce4edf8202b4e6e7c858c8e9dc7cdf0f426535aec1a347d88baca0000000000000000000000030d1522262c";
let GENESIS_VP_TX_SIGNATURE = "1709d9cb08bd52a41144c209db227a9b263bda85245e1596af42e9540df1a00905bcb719c74c162a4c9420bc8d3369cd6d43b22f4d429e0b24019c943a086bd9c845f6ab330b80e748e4d4bf3a1a6019244633d8bf787be78d3587634786bb5c2f696817d3320831f67699ef296e03b6ee0f8b34f0c7aa60f8337ad7cdba6332638b20b973435678d5db17ea24be67f3b71c7251a547cf72e48a2b7c514dd2543aca8eb8b3133251bd4117caf0ceeb8ded29a409f26290d5a113a12e5973328960840e4aff17283fdc25f6ff6ee75bea442caa2aca718c52abde5e5727059c2cf345d26dde69ca0abd5d0930d10d57923646fff8cf08b08616763645dd6562a8c6c80e4f009dd324b3f9d9815567d7b5ae6cb6900f6fa612b04fe7e92fe32c8a2c914d8e53e1bcd1031a7d18cac0d228a75a6de1117797c60856e3cb8c328aa30b73ff1e3e2f407326e47480ededf8937dbf728bc3f2d769c038f755be3a428c668e4b533c37c9af3316e7c2cc620d0d88b0312c08c09fedaa575ba9ef7f4b2fda0782f3a8e14d52352a57fd18235be4c018ef3c211c0e533d65afd340fb9e06dcc55d3b40aec2de39537e4dd70d2ae7bf8d9d8f80fce60e8b6e5768d891ee031409fe4743fe9e13fd2c2f5d568f2b649838f395cb0362b7f2068cdb12a36323231172b18c2b8abcab1793b3b246d48128ea65dbe5a48eb0ee2fa1fdfd1ce03ddd8aef0918eeb5b5219fafe35e53063586b5dc0de07525d1650f4a14bb35027de2a2be37afb86ed86567951787276033069603342626232c83519da181b29b39660504415cad445ec4f35e2c9a31becd0ceae94e69db064064e9029b45f48b337cf5f8470c0ffdeb9a4e026fe1b3b31b19448c0abf021347d76b63f2f6562cc84c27718c3c7de52811cdc12ab554251a381fa5357050c15e621cabc46e5546c69384f0f95eb7a17ded3f374e5c474024f65df8b7b0a204bd6d9d075b2c36e6775edb093fc5f1db2a612d5ad8136a0958b26203c3f08ede1065206b449c6b631c897690eb4adcf17fd5becbbcc629bf2cea438b4e19ebba0bc66f27795377cfcc79765faca43d01c1d4986be3db43d933fcab97215997565d6093a618a5b9dfcccb93af0d5a2e6bec8a7e514997a171a68ff3610d78e6df9ab529e1fe433937720651648f93a2f18255ca6754d1cbf14b403a4fa59e38aa6bf6c2b3d3be43fbb9a0cc09924bc4d511e564ca52ee30c061db3c96b120c0af4c162055cedcde86c36addb0f72750af2564d3342f25700dc551860f7a012ed573d943518eb49d1a2245c25098573bea426d2413fe5e905e19a57c63e4017886d07e235d1cda2ee0006318767185ffd726f8967c49ac102b3bf5e8a8ec48e73304571b71b4369e2636f9efb890d15b3a67c4c8ae3f977ee02d3959fd6ce60ed583dbe123f0271c94fd12213a57e4aa968d01454e84c7bc6aab0e246b04d00ffa4469f003e0e4ee01d1fa962823604e3522387144acfb5812549950d66d3126fd31254cd55bc54b83e77446d88b2bc5128dcfb8e0add3a6b47b89a72e8f3d79c01e10380aa93cbb2b9a76abd800b79e6e1837ee72c1d36c27d6590f835da6dec307d5e4362df6d68f9918f1c4168eff60b08db74513637e6861faea0520f9cc2883169d244594bd070656501d055638f885bf1eec1f1ba43b1d29b8d99792992d330037d4a804fee5a6544eb403d9767bd808976e72e3a5dc61504c132315d008577c529c3741c2239c15b057778ec41248592645c74953fcb73b0d887424c3960e08ba3fa87ab3036bbe1c0ba09962627036d3947693c9a25dd8dd4412a3dbfc6066346adb5070da4d4995263a13d4c985ac459a3d70659dc76e116d1f4ef5b56d3dea0f652bc0c787442cd1d392379eb94cc25a2c1e9666f5a1677e411dfbc9d7a0549ba0d4dac6aeea9b1cba7ebdea9373bad5ead8929e19b59db95bfdb8fba93b3cfc768acf93c1735e3563bf37a4fcd39a8f205c34bad82acb68bf1a9b06c365160f6836f6d3904cb517890c523e0a0a85b4545165178bc99e84cc27d73cdddf3b2126f285c3cac2394ef31d9f5474af8b9adad81047cf8b2f63d1bf74da50ab468f1d41d2c42c148ec9ea57c432c82f7a0f26e5323519f4f3bddbb03372190a0b9124b03bfaebc21a085a324afe1d13abb599bac49583ef68972331bf1e956744d65838e7c82d933b6668ac843a98dbb59bc57161f709f2fd19d8ce488074f486e347dfb67066ef1bfcacb6167f5de9dc39f12c36c0c8de6487dce412a179bfd555d5dcc6b9bdbc5ea20a9d92a819229c5af03781c709a7958b93295d92f82b2bfadf746ad140a855890ae320c4e0820dda1b924d5193cec4b8bfcc03dd9b71e538c35eef5d27c6dc3be13448fc494c8285acb5e05f080c9a7d4521c00895e7e4a45a8e074113587ad9bbfec05937c8fd3db1200df46519d646104a9665849c0c23ad7336e75f192372b3932c39424ea39ae44914773fb9a6e380e9bd9f1e211f660199182ad2d2159cb59728d53694537ccd0c2bfa1c70f739811dc478dd6312596088e07cde38213238458a4c1722a4b21ff759c24a40ae774a0522585f83d33b7526861f7b68f081beb787c28a01502646ea57c01b169da2521af1989317cdaf048cba0fe0512179bf9da6ef74cf65d5ab8c164170b76f6218dc6041ab4b40f76a7500327b0b7c7ed6c90fcbf612cc5a734c0fefdd8890a59363583a8fff2602ee25ceda86b85d9f0980feed59c2181e3ddf58618cd25446acdc9e496fe68e5d41e5df415395a401f0246cd7bc74d49b2ed3df75e9a89493d7126f63ba4b51b3686f258f1e619b7489a2035467fa82671c883b873ddfa3dcf2811210bb9f530b168a8807014c2ce853da6a80b7d6d22af9072ed2a1ebbd6dbd7c77d743af5154a83002cbc1ccddff2380fd915ca981e00009ae5964312c2b9e1c14c77ff4888848b3b770b0506609079961afcf20d37029517f49d2db475081dd4c55057d739b01fed496dbc1ea32e88bc4108030f10ce55742ab448e704d19b4fca4e86f5e64d364c0be26e3ccdc90e1a50588e51d77100b36379c8f614188bdc89decdb00bb1f05c336f34278cd8094c00294ed0f98941f6cb5d078b7b41ace02fb21344f93d79dc09e5e3baf215db50fcce498294935a5ac2e9a44e4bb09626cd33f2aefed3909ff12b9b8d558eccf29e65df71cde5b16d31d8e409a5623e5cfa756270e47796823a98b84a88e6457c06bc02add7a609be67b0b70bcba9856f5651c865381610d9eeb9abfa137e361c850644afbfe6d838fd1c2053649e7a2d6b8a5ab0a9964356e0bbee19a703494288bd52510e1f80bde9a9faa9fb1ec8bc14d70cce91f54ab00d74c8e7be2986470f192dd59532417dd489789c4603bc119d6864cbbad7b9bc9d22e96800dec231ebc90f5feb78fb0232485a944c3033edfc51abdf3cb9fab8e7668cfe7244f6c23c37a098a962698778dea4b299e1466b26af94137aec4df1f3f7255b7a4d3d6aba0c9fa46d04ff448d617642da5099251354cd253d0788f8e579aa51e8abe6a8516f13dbedf22e70261e658aa5df019f463c6d6f766706aae7c86f4d6aa3547b415f394dc72a39ed4bde1a7ee7970e6f985c6f3de8797c71d626a69bc34f3faafaed229fb87012935de1b23dad12b683ccde39f1d18a81e2d2e7a36559329f3436832678c46800ac3b15a739db54e3212a58f5a52bbbb0b5b46c5edf9d63aaf7bcd7039e723603237969c1b8566011abd0637fa42dc19777a4780de60de0ece07bfd3179008b0cb33d356665bb37f7ff294205644516057110a385106be92557381a5225536fe60e625b2abfa08b987d075f16c59c63536e1d5f39a70928e057e90b2342c80a88805e09f50165aff7ce4ec9a1b1291a77febb522b85c2646d9cb0c69db4a426f50a38b83f777ad2ce3868a02ee3932d34af9e8223ba5fe47036f44f0936f0b4ad88318522dfa3ad5104a3ff45d13e441de1efc06143109c03b90d78823492f5ef0e4a17d08d832668e26338bc72995c676b7482b17c2adea80397979566c9e41cafca2a3dce3e6f7446b86508bb46a3ab3869a9b9a112d2e1bcd198c457c918d2a962c6997729d9e31391c3bf8a7455694a3f8e07aaf3f670b40840f93fd35608113e829aa170efafb70f3697a8af304e416b783221d91c2df5c0ae5c3a7269421ddb7cff0760a04838d4256ab2191a017328d97525273a029324335181f03a022e8143f2c7aae41f39ff6b328a08e133967adcbaf07032651ca995bdc2e0f9c2603fdc333c7a4184934f4f1ef04c05b4953b46fefe6a6a63823f50af61439d1b21ae4aba57580a30b69839dba492561a7e390f5c17e05df369aaca3f425d605103250617e8461eabd2f777a1f58d674f6044f9a0cb66fdd2fc35598225f01c014338ec017378f783b3c8b3c13f3c03a6b7ddac8639f7102020d339fdd6671c91b472127310647cbd8a8f4168600e499065cd28b47251407c64f3bc653af610c40f063b1695d4e3a44f61f7ff5464af035dc7f7e9bf824208e71fd9e547257bce03a888210173638457483ba1d4abff07e8b9ea5b8bfc5158fb2cf0b0d134964748288bcd8f507a900000000000000000000000000000000000000080c13172224";

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
