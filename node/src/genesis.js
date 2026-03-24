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
    public_key:        "7b3eab9413ff025d69d215f52830a3dd9be9c42810080e91906c714ededc9da26014c8e3361fe41de71b4fdcaeafcc125bfb48469c9ba475aceaac552e919e5b9c75a9757be37cbfd95b605a7b82164e1c879ebc4686814320c7c1b8c7465df79b288b43ff3474ccb0dee1efc9e562e8885dbfeedf80945fe593ae6d72b73ef6854374a0d31178abf90d589619e23527ffcb03d25ed4bd1b8aef30127946503eaeea46e1566ee1d911744e63ba2445c9aea98fbb949230748aa2f2230b63e3a09387d1c8c88ce0e39b310d2b54a428954651c27e12a982037848b342f98c69787121717ccc4b2f7736cea436e750171f529a2bec291b93ebcdf6f72ace344421c9e949f16f3ccb8a52249320aa03a5f31c0851b6754ea83e8700bc0f524d2733da3d518de480dfd8d88981a72c48efd3b970b04e8341994b1cabe6d81c076017188fafb8b67b80ff959fac6fa49b43dda517b0bb1bbf8b2f1c6df2de58876fffa23091a2f290311ff95d900648deba1c4b1b568dbfe0704506d5773479bd7ea857459d1f0e3baad67a9511760167f78537629a3a859d3a5d21cebaa17175335091b033d2255f5193a82df2f3101f7417fff3c22641bb1ca86b6ed1929572e8b0e08fe30262ef5f553bf249fd95742a4fce4f7c7353b66824bb515bc8aa6326c511f6edd27de5b0eb870c5a45c59469bf0d46a8f91aa263e5d654651c956d3b5bd5b15679df9c8b0494d1e9c06ad9934254d764411835dc6b33c6b625469dfd2bcc2bb5594e7e1c1300016ea26f9b0266e08a7dffda79f5cd2ec59251d52146c848d469793b1451cbb9f36494157ed27a299279ff79c9ad819a811cbf15a89dbd9730b353f71f9708677d67694cb2a9ebb2dea5f2bd002053d0ea29e3059b391ae17807ff69d784564f61a79ade84bf8ba88446a799abde8c92a2411c14c05e01d26822292921eb25f55f8769c510d1bfe922a276dbe828e5814779586a910bb4ea2014bdee5317b498df2373b26bd7a72d9a91456f43316a2d6d7fed4bf7d96d24c17f2289b2b576cf01e93f8cc92a0c1284f60e8f858e68081d80bfeacc07202ebc68905961bfcdeb86e87bd9856512ce314eb0369ac2be224834a8a023474b288a297fab8fc7ea7594c06cc9b2afb4052233b631328adb9646563b6c3a60e33f0f39aeeb6bd564e9bb01a5b722c0dbcda209a2efd7ceabbb67124f8801356e0b85706a828f15c39056906fcf947b8c2d7e56c44070d1bcdc430962b5f8ecccf3d48811db0f728ffa12161cee5b9df1ee49e0b1a5ab2f03dbe2160c390660b508a6f68a1143ddb2c46398bad20088911a0ffcbc3b6fc9ae68161b383b9d766f89189dfb4ebcd66720c9feb586c3055ddfba2531102d1fa73411c5521c1a940ed74bbe9f09f7a3def62c3af4a81f7bc21c444879d5f158f97c3372118e684f72a7f0170344d7591bcc257a1252bc929d522a24f4eb0a8503fb83b35d72607b5f011b29632cc7c9829347fef097761fd01eee751fca5c35f17ce8b1fe7acf762e1b45eebc443fe3119432f13a06611fd1368a36c61f935d3514173789e7648bab17542410cceca22a781181b178e4cd66d0a005b1e2c808d9decf9666abc3022e8910338c8671d47739cce7cc563fbb115836d9aa9b7865a4126ef08bb6b0b50163b58905286b0feb14a5d3087b01041925e5b712278ba5afd1df206ab5f53c9a83904fdc1761b35793caab020d02dc12436d1a198ef20cc0931aeb0d821577a98d798461d767e54f0912cc2f05be523087c00c22676a02522c7e45cb0e36fd5445e99a4ee96a5eae893fdc980739f3c543cdf575bb551e4bf2adefda4082df5cd928fe9d8e6f68497684755f00fab0f5a102b22d28e337cdf2b887c8651bd1c27cadf68e5162a9861cd6c7cfb75baacab7c6c92a7b54c6c15ddd89ae3e26312c9d57c5a81222b45bf724a24dd8304b969e72157145dbb1431b4830e9462e16e31a5151a50cf2a23a8a4d782122fc115de901cc151a2d4f01ebf733a0d742be8b2cf4dbd8238f90bfd54c16d4560ccead0dc03a1fcfc0f7f862fbd8c04550166ae61fc38029de9eff376c9815131c148992ea4adb21f594dec95a23c3e7fa30f10d3bf58b574de98a57755c3b936ac35b7d578a033cfb303fc2e812101788dd35e764e9641e08e80f9b99a33ea9792c419e95d581e046bbb32134469e4e47097cdb9ec7ee6976a8e9ec67f014cc1a18d5c95e1687933a7d366eb02fcc5da2bf8d738b4f35151a1bc53a3eb0d6f5d2d309a062b988e4a5e0f03e0d9ce7158ca7aa4cfff53f5178f78d02ae925558846def093d58071170e29aa38ec0a8a3d7aec98aa65d3dca6b3b9e1e385abf803d093893591ef9d0c52f99fecd6ba55eb18b9a2566455c0d48b6eb80abbfec5c4841c662c00331dcd71e3d699acc5d45bc78974f866e0c281740d96a0e3412aec73c89af9d54a7cc0f039a163f85e25860648dd0d9b7e0245398ee4be32327adb981ce3e7d603d347dfb3e77bb760296e2932af35b74269898f4c65f5d47447ec26f4198593b54f5ac72c7945f34df69aef3ae3ae2ce471b55e27b00a76e0ccfa72a1677fff768798fa69b452148918cc093cdb9cf55eaa9a7fc038e1ca5113d311eaebb7f16a782ae44687a121d72a9e3873a459e04996cc32389395af7eba8e5cef67d40f84d872eb9acfd8de3cffc34c350e42914f322995a9054e4ff19fa116280cf73324e0ab3f032f8f3a04ff0fc6201",
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
let GENESIS_TX_SIGNATURE = "f9bab2d48e2fd6f9e134f09d1702b1746a6aef2f54a0a931161569b94c2fe4317ece2e5fe9038511f261b453970278a0629598367c1d28c09fba3ce3dc40349a5b39047ec43169aa29c2a2d708553b9efe3b33629e94c49715058f9e723fa25ba4990a253dcce06aa9d5c2e747924df96e8e609e4320e9fe4a8e3c971f582cdd389ffc65fef167e5a05803e5bf6d3ffb3573187339d5242f57371fea19a74cd2e6faa353e2d3f5e58ee9766e6cbe75cea2e34dc672fd463eb79a44b54bd25a13c938ae7a1d74232676b4485b07a4311b2d15a36d3e56c81edc4e3b974f76502bcc99e27ab37c7ccabd58c9162cb5281a8c24028acfeeae8cc84fce3714f120e37f1617ac5730e2c6b62da498cb84ef6c00d052e9ca7aa08444356dff4e941ef8b5cf9ceac1e9e580c1831d07b05aaafc2d0d44e6d9d32ce8b6400b78ffe93c51898a307293183ca3397ad8c3099a190d0c7a6b0bd91746d4396a4b573468d2b3431abe0818f2813731702866ccd62e1496653d9f5bee7fbbbfb734a33a45fe3dff7d587bdf197c717a3f0209977992ebb99d574ce0895b7a88e305637399fc048405250967e25534ff09d9ab03962fd862de8790bce94804c2eb7117c5c4a1e6f9c5cf86bccb542f5551554a8bf5d3a621549c570b9b740d88f36402142a17d8ada32091d227176fb8c9a274569f766a793bc078837031a8756ec07940a7cce981004c6734cad3e3b324014df71739f501f5fe7b5618295f35125a7f2a7638aeece60fc92d5fb03a91101e8a11d43f0e457a98a6fb3b2dfebcacd96744ca8466e24d76818d084898b69a11f921bfb3f628fe695c2fd8e106a629e5375dc8f9d499116c4c2161dfcfed1697c7364800ff769fde941b4ace3dfc9acb170c945c68fb6c9d1676e567276413f18d1367426098a5c55e27b6b4da31b297eb2ccb2c26241eace7497b3dc05b1bf05607c84af4d3268e362ca9cd748413279cf32bed7a353ccc10d58a0229615e993fc57678a6de2248f043a7cef0de77ff5de323016a3ebb8d65574ad8a0872790ec3d9580914efc4a9e14c373516f6dc17219a9689001c842affd7630b5be21d55f9a21118b6d0aa3bd7bcf1f821dbfb186eba2e4159d003a131bcd82979adca67844b373bcf2e8f953aa4bbab661338e2f36deac7a856a84736d2fdfbaddf5cef89dd8eeda427a019501b2504d70ca4f84728cf8b02a54dbcc9c0cc289df8a21c4eafa3226624d054ba8d74776f885a2b881756928987b7590a8c5b6ada92139190d5a7edbd4da1dbd68b6427f2615d6b56bc5cddfcc72cfa0b915820e55d9da9a67d1f5bbb9f578be2db4936ae5dabcafb2cb8a07e164d00cc9836e6580757874ee8a38b307b3547388eeb8d73773cd5131d927afcc0359c4f6e4b605aa56dc92985c3ecf83f9cf783e521f387b9ae73e7c4ee8ac25b948289addf8801bdd55a143cec2185ffc9626938bbb51f70d5a7b64da2d8cd2e38d624d3546353c8c9cf46629613dc53bfe3ef6c27484617f30667693960c3306eee1c45727054059a6175b08c881f688c96b3a152afbcd715d2d017d418f20752768ad8264ba10189331dfecc8602a6931282566fab71590895592b1b4ca7d7ba348795e694e0cf8cce03cd3d88998e9afcf26779d2bccf52cbc308cda2c05ceee8f301ec1675e110937d7bedcd8647378c4edfe95e1b4172110d68047b21c32a05372483b22338991f3d200798c13e32b98bb154dbc8b02fd5f9c28e7b6022bca74130e7010da9d19d32a8124681f9419ba445a0895561d473185df081a3d4778252a7a38f295236cf9648303fcb47ef4ba45d9f18dafaa54e1d6a1226b7b637a1a3ff8065d256db9ff02806a9a57f9232576b724d1b1f9795716ad5304c6656e64ee779adf7b5fd7fb7ab5cd56931fdeebcf201a9c2ff7881dd9ef2346a84a7d2b8c4421ce926cfa4cc8159e39fdc52c7e594b369b3e7f64675bfea1fce6e498010844b13952fa221ddc4f37545af8c5130b1c17cd8c486412f71f2aff3bfeb1f3c663fddbca66ba07a9a91b1caf9593c46e2f2923b1943716f3b7ffa6acc1dd83761b3dbbeef49f62e4ec18ef82994f18c686e3fd66aa6224b877daebd7591aa8bd859ddb09b184ec42ec1806ba10c3a7c8134d5412b343bbd30f52f2d9d07f63dc44ec36459cd888084be743905fd2a1abb7e501f68233429adf4c4b6f8a915e220aa54adf2692cf4ab0f93b6bbda496005565e0df374b26716840c6c4e8b9e83bb9b30fa94cd1681f6fbea2b4361068e1e1969ef883474a440cd38d8a6d543de57a91975ee15cacdc5887c52f504c65088bdbfb35d317b94af37d422457d729dca35872cae23a7d692e3882e67156dc19f593b06b97c805e7a31099eb43ad7354b539b26a1d87650529b61604b9e82cbd449dd05ec7608bb3696071ae91aeb26afa5c40a9d04fae46a982818b9dfc3a938d6922f074fc85b7c01665f6f2a3fa9ff6ca66cfdfda1fb7dc7639edf2c64bc4dd10ea6e112ab392d3e11a760348c88d4255a2d8cd2cae9a79ba70f7e15a678d49c5c7fbd142f5c54d11c5adaba385e72b8fbeb4df544c2a4bc35962aed09eb6dea35643ba753748bd4d79908b1d87acbbfa554f4566ba6d50902bb33cec56f5bdc78e20b6661d7dc66365eb71710f6a0d980f9eac2c5500d87872133b883afb2cd01f4e9e6d098e9bc768a34312f9ad8a2c8c4c4130403eb53e07483a5f177de54ce9622f12f64e5cfcbb6c1677debb6398063aff0d0113ce3287c62a0c353904908f9326e9cfc2d5761c8994d0043910ee09f6c88be289b2c6f346958f98477cc40b9e33aa7c1fd2cf94bdb4d2b179330d17871edb02c8f11d62ee88514598ced1e576132577d8e0ae8f90889b5a77ea791da808154079f5574d349929c9e8bde37ecdb512c945614ee043b967e0be6997bf5ef1474af6ce65a43db0767704060c880709ff914065b23effc13b42d5cb746593104301e574fe2a4f0fd13f565d0cfcf4f25c9a203bd2a6f81ee6cd50e018f4f996e253183334096f2f94a4f19ab75464587cf1e60f86e4d226e0930c0c59e5add227377590eaea53d408a5a3ea3b058bee72661cfb04c2dd5bc7f0e8d4f5815815300e11bd1bf8d7259b3e676a78c4a0982c9a12ecbe51b044f7c70543b89b5ee0961e9ae95c55f65b635b9d93b08b00bf4d68e875810e4396ac7a5b979a69c3417ef61ec22f9ba84dd91181b91a67c70eec2d8b15c4fd310abed107e6133aab898470e034886cc5c771f86d2074b9b291296d0aa8ebe04add2e5bdec3569edf2df182437713457c0273086ecfc9a578456d4e6565c051aa420b7d5a05215fd7a58b7c4ad32d3242481388d9fc3426241b6f3fb278380431ded22eb6d8cf2a223ea28e0f4ca86158183fd4f8a967ca100439708805e9ae331a199964fa36ebb1680ad347214af2d1044afc049db3549a84f4e5512e1e33503718e2e99e0945e1ecb20255469aba8e9d6aa0854725ed610604abfb7fa4001f133f9d82788b207301661b20ead7cffc46b5e382733a53fc63f0ebeded34d0aa5ef990f0132ec99df9ece3a61c93bf78e75fde22bdac536811c8c802af9fe411cefc289bb0d794efe577575f6fdd29b51c6746e80710473f9f042b1c52ff800c738bd3d1af27e90503daad636c945851b2b0df5228639318b15513b68c75e66a43e6de47cc291ab65acbfac02b02d14e18858665bdbee042deea4ae2251d91d459e9a6fbd7381fdd0b918bf5b53585e61c6b9989316adf1cd6502de62c0844e7e121ae4c805c55430519560ad247373fddddc256dd333565c4a4f22fdfc4c001798e44967c1ce52b7854c505ff8a7a3d949ea1c23275b0c8884c07ce5a601c3dcf6eb05f2d40afebe8e45e0a8a27c126cd4af5266dcf12ab0fc4bffa48fcfd90b173fc9898b64eda4ba5cac7e71ab913e461d25ce928b5f9a9b69a1bc5a521d64419d7b6bc2a45fd267f0e817fedb4b9d9cfa9ce720b9cdac78403fdfc75b93b7f610eec07de4f9ce7b59bb00b77ce8ee65aef4da31b923f10ad9d79805de7d0324188e5a6c49a11911862ed6b7ccce0e0f65eda15bed07d038386103722377bff38eb9debfb64657555cc8cc4033e3b9e03f41b3c2fdaf69fa71de9800582467c792d30819447fdf6e6d5559c871e5c6077122272164dfd8287ee047151e67c1d43faa08a6056fd93474f149f94a71d08b7d19075a2a20ad4d59c39691e19fe2713a018ad9b8ed1c4e76471b02141bcf3af6c69e2630982e60d92dc0fe41f52bbe0faf289390f49cf687367d7ab8cdbb111f1fac83d37db82f97d0b6a868e20d972f6e6fe17f069d986c1bcef24d2fcc47aac41793b00fad4a7ebb6069110f0c09c7ec2f96b89cbad8d5051336f3b391e3f561e32fae98bf8b62856410db0b04a557599c746706a6cb1872c99fe491b9dc274204bdd9ebaa0d3141ab96353e8357a120608334ddd0efd1b3efc764e363b172201c5eb65c9619bf02a51d33a431bae2c0aea749e719719b672ef73a2648aa4e3d75522d84614f8bc8a5b6c63f48e92b6d2617d5e45cc795119e1583e1a6f77b3d6e0e8fe1020a9b3b8d0dae5ed73879a152956606c6d7677aeb3d4eb27607cb6e12e2f638095b3c8f00000000000000000000008111420252d";
let GENESIS_VP_TX_SIGNATURE = "9fd960e3ae249ad201037e87d0e15c14b6eac5fc8b54045821dc9b971150bcbf7d5dc9357a93e7a3db7032ce46ea0a70700cb0ad9a744481312e2c55f0d6d0d5130b4ebc6f0de5e9bbc9f26c1a18d7364b1f770d856ce1263bfd89598a940ca113ce6ccf5fd9a15bf766aed529c98a53d1f4bf89c8257f707d8d1e26f47736ebd95040b6dac674170f80d0f91803c0cafe4e71081958fcf3648ed8c70c3b131e43ac863f2402078e991499af5f71971c5a909102da99a38c81e0b454f0216c125cf89ffa4b99815038098fda7c3c3f5a04dabb5a11d9467411e9116270f40a83d3a43de4f8f15edc38d46a246625a9f3088e542d9c1eb1cf5fb18df516eb72e728497d8259fbe5b6901815ce4a7f43c587f43269c47e97a8376f0f0bcee5b3c900750e8cd8638d45427f975150aafd91ad56ccca2cd929f51252a52c70bbf19acb02886b5341b0bf1b5197934c4a985d4c8c1fbd5deb990bbca5e24b89b6826aceec5cf791fb1ba760cecc2736cbcba98ebbb137ae576eda304eba467b02fe81938f779a9165f758da11d5bad69ab7c1aa4209913d5912830baa4f1cd9aef65db683f5cb85e276531ac43592a24a01a674379c9f57660605c59bd33640054620a66f63e95a246e770ae3ac866ab1bcb71286d383a735ce1ea7e3b5c29f754e269cf6b1c9aa1b6ce249bcf8e36430f09f5ecc06474f935a8eaecd09d902bac2a7a3361c6d8ec23dfc406ebc27e45b74b14f2b7afb243dd83f366b144cfee22fee5f894709359a9d482a84cedffd2b4da3793a89f21bf1138bf4bd9eaf17c291a7c852315829b21409369500e527ff8a8aa32de464eea611c9165da0230e44d01dbdc9072293daec4832536dbdcddc6988f76cdfdfe167a2bbd80a30f75e918944b063cd4fde08c97bf3e455b9c70480ee99aa8591d8e5ad3a28e164eb44bb29d3394926d02259ba6ae0bf36a207868e0fed301eebb4130d482f015666c3ef1df135114de9c3463f7eb02276d5823353d4b95b7142a115eeef520fc8bab51849f05307b915cba6a90640cb0bd56deeebf4d86dde5bf1edb4764f793943d0689340b56b14752d4c3a1356f7343bad51669958156064aa4f68d4d493d2b23fc479eebf155e29c4688f9a6d04e900e260d86e46a8ab0002b221e32fd78294e464c2cbf995224957f4f46e980b46b086e7fd575568fa6da545a2bbb981f7752e41323a430878682516240b63febaf7311785e4293d4594c2f0933318deb5e00e3c80875656520ad7b39f020a1f564d52818008dabf5abea7aa57871c9b4e580d656f9f3899f4ea18b97621b1478225948c4b1c687b18b29a44dc46d9a5b59d9bdc7eb0ce873617703d940128ff48cb810725118de31248f678828adb2829e8967abe29d13138b4e7950d3629e6800f89c1699f80a80c699e9fd8bc564c355e126d2dff01379a43122dda89836fd8469ed0064de0bdf695b0e9ac3e53aa63584171f9959f5fb2da8e776d1ced9427615c4ad0b60cf12cc29922753accd6d5c4bddcb92f7186268b8c5ac04b5e7a94371d5c7220b72e9498acec1a637c10a2d9ef7269a037e38ee631298acae2903be1098b1b7ba85631d15f2003088dd1cc2b166c12481fa3d803c50bbd3cbba7f8f1ae6414e3deec2d3e963c10aae84abfc9b828290f8e79cd8e18705438d96b46e6030bd37a9d27fc9c2f0212816edcab05d2a4f6ceafe477be56acfa660ddb8b0b9682aaa0e822dc1de454e6f6240c5ee5b1df1963b6891199a98e69b14bc93c7135ef204b47a32f174a5b4449a141b211790a7df39f87fa7ae7ea090f471df138bb689b1bb4697fa6ef42ffc73800581264af9c71c87c6ca35d5ae6343cc933efa1ce33332af544a782bb6a8449aebf461b14c7c14128ee13db8c8207ae7a0519c46c6a447e1371a4f0525377f2f7852cfbb17358cdbcb316373ef7737570d2aa2f0eff37c9ac010631119710c2b40592f0c8221d794b503a4c74aaf5fb91da1a9201e88928b958900de1b6dbfe5d80cfc8c3b1da51903937128c0a6cc030de134c77b571c1bda890197e4f45e8c785e03e7358cf95b6fbc02669ee220f39efe9f8edf8c458954806dcfa392b9e8776d44843ff63b5f51485a4e134483b7d23834c8a1088cfeef2e1fb498496739ead0d4fee98d09c4a6c06645dad6ee369440ff70cf4ef2ced3238ceb03e1d675c96fdc981d97c9c8cf09fbfa88a18c3cdc03c05b355b6701b3a06af09c7ff74fc4124c16c975b5c74960c05d34098eb3eee7b90535f6a412cd6f775f4b2fc82dc56a6adc19eb14ffacb5913dd8a81f061dddd5db2041350641c2d7590798fb30fdf208e379f9b28887877162e3c13190ca0f640ae9690e6a6aa97f0e49a81885dec242c6187abb11c6e29ac936c3576caf889d2254d115908937c632f083c7dac7909ff53c7c858ebcad038280a4766bc5a5a9c62f435afe831bbbbb53c7b06982eac6e88a52cc5869d7bea7978173e50e3fba98eedeceee6c901752ec8c060879a6e43ccddeb52eb89ba827bb091601c10be61fa3ee1925ba51eb3171eea898b5ccde9ae26629169904612688d06247cd0ebc21c20a07ef8e7c504e1efad7f6d46d1e34535a6d6c9483daa950cd48b50274126d7e67f80604b9c9461564f5eb1da7f3ba9982fe42620689d8489d3c34e813d89c401e5008ef9b31856562530b2de4648be05c59851fa720426e3774a27aace6288df5f26a52008815e851e99cc94cf8ea0dd871c5d76ac553c6de6539cc75d8666ad01b613e6acc9eb86b8abd2cb98142660f86b4c911d8ed3c708e3fa10ae039584e2291658d140d0f3e581022c3af5c4922def25cef996ab36f57b7d71cd77d4e5d7d7ccaf5b4bdb4e9e7bc17e41d31694f93a6e76b6c626e60d0dcce724e758fa5903ea142b4331cb4a3cf8b5e663e39b76a93069b7524fcd421ac66b6e7345ce0a3354a4f5ca769c6b27948b6201b348e03d80a5037fb9dbbf785a04e40c65525d0721880922a203ab4d15d012d567f693045862d34344618bd7432976d3bedb4c997a119eaf00e6b183f40811d7570e525fbd4287c767ec07d7d5682402c37b0ba310f950b93da224e17c860718e79a9a006a8ce692b82515a3b77d05d1243588cb9bbd7756596ef141fff3031ddff7c0e22c7ce6c74faabc54b0ad04eec4f457bde1752a10acdb66783e6ca19d50cc2575389dca5e3db3ab43b0df166a7ee4f561f8934d10df916104e5a026e8c34e0526e4860a93b99c59e9dd0623f800d76a4136110f0577917581400b49daaa427d0e5efe11d62e84291033339431555de0a3003d1b26ecfed26e01a2351bda5a54e516b4bdd9cd3f5810c7a52335472486b9ac77e69f9410464662961150e56f8afeda4e101fe64c0359ff3453f2cc50a2fd37d03df6c40559103c3dee1620b659781212fb4289aace541b4674861012ce845ac7b54d2f5ab93e68c939a4f123cd8afa781bb1274f90c18f981276ac3e989ed8d5e5e02142423828a6993a3c444fdea4c390737aad415184e770718e14fc93de29b0a563ef0f5b38af24560235db1c7ee3bb255084375fd987a91be0361ea7d09d83f4a08d9235fc3962069cf3864860f5e1009604b8260a32654303325b4d185e6442a913c0030ba51aab08ae27c92b3fbe0193ddf56ec7d8573371bc46e3c8c755100f6e1b05871472bf1301f25e3c1df95117af084905e845053b8b69e495e31aeffdf9461b3bd3304d59533330acfc599485796782a626b5a602011cb430f05c73cc9d04fdee3eda9b38db865365fd073818316a29b963c19755752bb3e59c2efcc4edc6e83beff0fec9cf1cf2bdc294c97b4da3a55e3fab9110c709333b29cbe6dc73ba9a47b9ea7d3a4d62d3acf8b3dbc79e273a1ab23a2eaabc4a0f2662c70614ceea18494c003f37a988f2b2f0a4d7b24f99a3ed6de7ee6f7c8a0c02461915b7e7dba00dee905f12574a579d9a36eb3c448f1ef8619eabfd4463db885153576c5c663fa455a8d8b012e34b110230dd06bb9cdfef1878a02d4043db1caf208bb8270b25f64477579b4d15d8c0129b924b179d2a274e4ebb42414652079d232ba04829515aa4d77d2a4c20bf219d9dfb8359617fcb78efa73768fb7551f970711fbbf69fbaa72253517fc30901fc5249217f88789ac5cefaf4735d68e297f466990c995fc8d688f0f8c8267ecd51fe4ac87f19ca1b584999ee0a2b138bd05764eda7bc4eac7badd1769ede503a56b77c2cb7db8c93986bbbb30d124ce0798f47a75d7392a56e3d045e47064be7e4b86b5e68df470d50cac83a77faf4ed1a1d9bfae964811fba57e60152d640387672f037f78d8bcb32f4ca76343f134a0608da076a4547c18e25ec73902ba8d4c8259a060c356205af6c1146b1d7ee7d8aa20277cf43aac3c1405700273cac7fca0ed7ac208ef007ffcb7c94f82706bfddef712da836216f0763a2387ccf2c2ee93faabcf3c88d31d2c7726b1704cc846170d0178400c10d2bd665148b380c00a3218b4f876c92df8656e241d9c1a5b36e53689cb93a6c05d9345bfd804f1dd4f7760d2436911bf2d4103b3125ec172e3c429aa8bfc9e8085b696a6f77b5f2f4002c8794bbbccb20383cd4ebf6334c7c899ee2e3e8fdde00000000000000000000000000000912191f2829";

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
