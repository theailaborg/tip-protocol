/**
 * @file tests/consensus/api-roundtrip.test.js
 * @description Consensus-path round-trip guard for every transaction type.
 *
 * For every transaction type, this drives the REAL service (which builds and
 * signs the tx) and the REAL commit-handler (`commitOrderedTxs`, no `submitTx`
 * mock that stuffs the tx straight into the DAG), then reads back the persisted
 * DAG row and asserts that every signed field the schema bound survives into
 * that row.
 *
 * The bug class this guards against: a service signs a field, but commit-handler
 * drops it from its persist call (or its signature verifier's field list). That
 * class caused three confirmed P1s when the consensus branch merged; the
 * schema-module migration structurally fixed the affected types by centralizing
 * the field list. This test is the regression net that keeps the property
 * "service signs -> commit-handler persists" true for every other tx type.
 *
 * How the guard works per case (see runRoundTrip):
 *   1. seed preconditions (identities, content, ...) into a fresh DAG
 *   2. call the actual service entry, it signs + queues the tx
 *   3. commit the queued tx(s) through the real commit-handler
 *   4. read back the persisted row
 *   5. for EVERY signed field (derived live from the schema's signing payload):
 *        - if it is in `notPersisted` (a documented verification-only field),
 *          skip it;
 *        - otherwise assert it appears in the row, equal to tx.data's value.
 *
 * Because the signed-field set is read from the schema at runtime, adding a new
 * signed field that commit-handler forgets to persist fails the round-trip
 * assertion automatically: the regression-guard property this suite enforces.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// Skip real ZK verification, circuit artifacts aren't present in the test env.
// Must be set before any service that reads it on the register path.
process.env.ZK_SKIP_VERIFY = "true";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, tipNormalize, signBody, canonicalJson,
} = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TIP_ID_TYPES, DOMAIN_BINDING_STATUS } = require(path.join(SHARED, "constants"));

const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));

const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createDomainService } = require(path.join(SRC, "services", "domain-service"));
const { createProfileService } = require(path.join(SRC, "services", "profile-service"));
const { createIdentityService } = require(path.join(SRC, "services", "identity-service"));
const { createKeyService } = require(path.join(SRC, "services", "key-service"));
const { createGovernanceService } = require(path.join(SRC, "services", "governance-service"));
const { createRevocationService } = require(path.join(SRC, "services", "revocation-service"));
const { createDisputeService } = require(path.join(SRC, "services", "dispute-service"));
const { createDisputeDetailsService } = require(path.join(SRC, "services", "dispute-details-service"));
const bioFetcher = require(path.join(SRC, "services", "bio-fetcher"));

const registerIdentitySchema = require(path.join(SRC, "schemas", "register-identity"));
const contentRegisterSchema = require(path.join(SRC, "schemas", "content-register"));
const registerDomainSchema = require(path.join(SRC, "schemas", "register-domain"));
const bindDomainSchema = require(path.join(SRC, "schemas", "bind-domain"));
const updateProfileSchema = require(path.join(SRC, "schemas", "update-profile"));
const registerSocialSchema = require(path.join(SRC, "schemas", "register-social"));
const linkPlatformSchema = require(path.join(SRC, "schemas", "link-platform"));
const unlinkPlatformSchema = require(path.join(SRC, "schemas", "unlink-platform"));
const interestRegisteredSchema = require(path.join(SRC, "schemas", "interest-registered"));
const keyRotatedSchema = require(path.join(SRC, "schemas", "key-rotated"));
const { REVOKE_CONTRACT, TX_SIGNATURE_REGISTRY } = require(path.join(SRC, "schemas", "_registry"));
const { signPayload } = require(path.join(SRC, "schemas", "_common"));
const { withTxId } = require(path.join(SRC, "services", "helpers"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";
const T0 = 1767225600000;

// Mock Groth16 proof, accepted when ZK_SKIP_VERIFY=true.
const MOCK_ZK_PROOF = {
  pi_a: ["1", "2", "3"], pi_b: [["1", "2"], ["3", "4"], ["5", "6"]],
  pi_c: ["1", "2", "3"], protocol: "groth16", curve: "bn128",
};

// ── shared helpers ──────────────────────────────────────────────────────────

// A unique 64-digit decimal dedup hash per seed (Poseidon-field-element shape,
// uniqueness is all the dedup guard needs when ZK verification is skipped).
function dedupHash(seed) {
  return (BigInt("0x" + shake256(seed)) % (10n ** 64n)).toString().padStart(64, "0");
}

function makeTipId(seed) {
  return `tip://id/US-${shake256(seed).slice(0, 16)}`;
}

// Domain verifier stub: simulates the DNS/HTTP probe the node would run so the
// test stays hermetic. Returns the observation the node "would have made".
function stubVerifier() {
  return {
    verify: async (method, domain, tipId) => ({
      verified: true, method, verified_at: nowMs(),
      evidence: { url: null, body: null, txt: [`tip-id=${tipId}`] }, error: null,
    }),
  };
}

// Seed a registered, active identity with a known keypair so signed requests
// from it verify against the DAG. `type` toggles personal/organization.
function seedIdentity(dag, tipId, kp, { score = 750, type = TIP_ID_TYPES.PERSONAL, creatorName = null } = {}) {
  dag.saveIdentity({
    tip_id: tipId, region: "US",
    public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", tip_id_type: type,
    founding: false, status: "active",
    reviewer_consent: false, juror_consent: false, expert_consent: false,
    registered_at: T0, tx_id: shake256(`id:${tipId}`),
    creator_name: creatorName,
  });
  dag.setScore(tipId, score, 0, T0);
}

// Build a CNA-2.2 content-register body the canonical way (per
// docs/CONTENT_SIGNING.md): sign the 9-field payload, attach content+signature.
function buildContentBody({ tipId, privKey, content, registered_urls = ["https://example.com/post/"], extras = {} }) {
  const contentHashFull = shake256(tipNormalize(content));
  const fields = {
    origin_code: "OH",
    registered_urls,
    extras,
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: tipId, tip_id_type: "personal" }],
    signer_tip_id: tipId,
    attribution_mode: "self",
  };
  const payload = contentRegisterSchema.buildSigningPayload(fields, contentHashFull);
  const signature = contentRegisterSchema.sign(payload, privKey);
  return {
    ...fields, cna_version: contentRegisterSchema.CURRENT_CNA_VERSION,
    content, content_type: "text", signature,
  };
}

// Register a piece of content through the real service + commit so a content
// row exists (created by the real commit-handler), then flip its prescan to
// completed, content lands PENDING_PRESCAN and the async worker isn't running
// in this harness, so we settle it the way PRESCAN_COMPLETED would. Returns the
// ctid for downstream lifecycle txs (verify / update-origin / retract).
async function seedRegisteredContent(h, { authorTipId, authorKp, content = "lifecycle seed content" }) {
  await h.services.content.register(buildContentBody({ tipId: authorTipId, privKey: authorKp.privateKey, content }));
  const regTx = h.submitted.find((t) => t.tx_type === "REGISTER_CONTENT");
  const ctid = regTx.data.ctid;
  h.commit();
  const rec = h.dag.getContent(ctid);
  h.dag.saveContent({
    ...rec, status: "registered", prescan_status: "completed",
    prescan_flagged: false, prescan_completed_at: rec.registered_at,
  });
  return ctid;
}

// Seed a disputed content plus a JURY_SUMMONS for one juror so the jury-vote
// services accept a commit/reveal. The dispute + summons are prerequisite state
// (the jury-vote tx is what's under test), so they're added directly. Deadlines
// are passed in: a commit needs commit_deadline in the future; a reveal needs it
// in the past (reveal window opens after commit closes).
async function seedDisputedWithSummons(h, { jurorTipId, commitDeadline, revealDeadline }) {
  const authorKp = generateMLDSAKeypair();
  const authorTipId = makeTipId(`jury-author-${jurorTipId}`);
  seedIdentity(h.dag, authorTipId, authorKp);
  const ctid = await seedRegisteredContent(h, { authorTipId, authorKp, content: `jury content ${jurorTipId}` });
  const rec = h.dag.getContent(ctid);
  h.dag.saveContent({ ...rec, status: "disputed" });
  const summons = withTxId({
    tx_type: "JURY_SUMMONS", timestamp: nowMs(), prev: h.dag.getRecentPrev(),
    data: {
      ctid, dispute_tx_id: shake256(`dispute:${ctid}`), juror_tip_id: jurorTipId,
      commit_deadline: commitDeadline, reveal_deadline: revealDeadline, identity_count: 7,
    },
  });
  h.dag.addTx(summons);
  return ctid;
}

// Stand up a fresh single-node harness: DAG + node + VP + all services wired to
// a buffered submit, plus a real commit-handler the test drives explicitly.
function makeHarness() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey,
    status: "active", registered_at: T0,
  });
  const vpKp = generateMLDSAKeypair();
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: vpKp.publicKey, status: "active", registered_at: T0,
  });

  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
    mediaLimits: { max_text_bytes: 1_000_000, max_image_bytes: 0, max_video_bytes: 0, max_audio_bytes: 0 },
  };
  const scoring = initScoring(dag, config);

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  const submitBatch = (txs) => { for (const t of txs) submitted.push(t); };

  const services = {
    content: createContentService({ dag, scoring, config, submitTx }),
    domain: createDomainService({ dag, config, submitTx, verifier: stubVerifier() }),
    profile: createProfileService({ dag, config, submitTx }),
    identity: createIdentityService({ dag, scoring, config, submitTx }),
    key: createKeyService({ dag, submitTx }),
    governance: createGovernanceService({ dag, scoring, config, submitTx }),
    revocation: createRevocationService({ dag, submitTx }),
    dispute: createDisputeService({
      dag, scoring, config, submitTx, submitBatch,
      disputeDetailsService: createDisputeDetailsService({ dag }),
    }),
  };

  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId: NODE_ID });
  let round = 0;
  const commit = () => {
    round += 1;
    return commitHandler.commitOrderedTxs(submitted.splice(0, submitted.length), round, { certTimestamp: nowMs() });
  };

  return { dag, scoring, config, nodeKp, vpKp, services, submitted, submitBatch, commit };
}

// ── the round-trip runner ─────────────────────────────────────────────────────
//
// Each case declares how to seed, submit, and read back one tx type, plus the
// `notPersisted` allowlist of signed fields that legitimately don't land on the
// row (verification-only inputs, or columns deferred to a later PR). Everything
// else the schema signs MUST equal the persisted row value.

function runRoundTrip(c) {
  test(`${c.txType}: ${c.name}`, async () => {
    const h = makeHarness();
    const ctx = (await c.setup(h)) || {};

    await c.submit(h, ctx);

    const tx = h.submitted.find((t) => t.tx_type === c.txType);
    expect(tx).toBeDefined();

    const res = h.commit();
    expect(res.committed).toBeGreaterThanOrEqual(1);

    // The SPECIFIC tx must have committed, not been dropped. A field-list
    // mismatch between what the service signs and what the commit-handler's
    // verifier rebuilds drops the tx here, this is the core guard for
    // record-style txs (verify / update-origin / retract) whose canonical
    // state IS the persisted tx.
    expect(h.dag.getTx(tx.tx_id)).toBeTruthy();

    const row = await c.readBack(h, ctx, tx);
    expect(row).toBeTruthy();

    // Signed-field completeness: derive the signed keys live from the schema so
    // a newly-added signed field is covered automatically.
    const signedKeys = c.signedKeysFn ? c.signedKeysFn(tx) : Object.keys(c.schema.buildSigningPayload(tx.data));
    const notPersisted = new Set(c.notPersisted || []);
    for (const key of signedKeys) {
      if (notPersisted.has(key)) continue;
      const rowField = (c.rename && c.rename[key]) || key;
      expect({ field: rowField, value: row[rowField] })
        .toEqual({ field: rowField, value: tx.data[key] });
    }

    // Commit-handler-derived fields (not signed, computed at commit): assert the
    // row carries them with the expected value.
    for (const [rowField, fn] of Object.entries(c.derived || {})) {
      expect(row[rowField]).toEqual(fn(tx, ctx, h));
    }

    // Bespoke cross-row assertions (e.g. a record-style tx whose derived state
    // lands on a different row than the one read back).
    if (c.extraAsserts) await c.extraAsserts(h, ctx, tx);
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// Round-trip cases, one (or more) per tx type
// ══════════════════════════════════════════════════════════════════════════════
//
// Coverage. Every tx type that carries a per-field signed payload (where the
// "service signs field X, commit-handler drops X" drift can occur) is exercised
// here across all four signing modes:
//
//   VP-attested body      : REGISTER_IDENTITY, INTEREST_REGISTERED, REVOKE_VOLUNTARY
//   node-attested body    : BIND_DOMAIN, LINK_PLATFORM
//   subject-signed body   : REGISTER_CONTENT, UPDATE_PROFILE, CONTENT_VERIFIED,
//                           UPDATE_ORIGIN, CONTENT_RETRACTED, CONTENT_DISPUTED,
//                           UNLINK_PLATFORM, JURY_VOTE_COMMIT, JURY_VOTE_REVEAL
//   old-key-signed body   : KEY_ROTATED
//
// REVOKE_VOLUNTARY stands in for the REVOKE_* family, all four share one
// contract (REVOKE_CONTRACT), so one case guards the whole field list.
//
// Deliberately NOT covered: the pure node-envelope tx types, SCORE_UPDATE,
// ADJUDICATION_RESULT, APPEAL_RESULT, JURY_SUMMONS, UNBIND_DOMAIN,
// PRESCAN_COMPLETED. They sign the whole tx envelope (NODE_ENVELOPE), not a
// per-field canonical payload, so there is no service-vs-commit-handler field
// list that can drift. The bug class this suite guards cannot occur for them.
// Their commit + derived-state behaviour is covered by the scoring and
// dispute-flow integration suites.

const CASES = [
  // ── REGISTER_IDENTITY ──────────────────────────────────────────────────────
  {
    txType: "REGISTER_IDENTITY",
    name: "VP-attested identity persists its signed fields on the identity row",
    schema: registerIdentitySchema,
    // dedup_hash + zk_proof are verification inputs, not state. social_attested
    // and algorithm have no identities column yet (algorithm column deferred to
    // the key-rotation PR); they ride the signed payload but aren't persisted.
    notPersisted: ["dedup_hash", "zk_proof", "social_attested", "algorithm"],
    setup: (h) => {
      const kp = generateMLDSAKeypair();
      const idFields = {
        public_key: kp.publicKey, dedup_hash: dedupHash("reg-identity"),
        zk_proof: MOCK_ZK_PROOF, vp_id: VP_ID, region: "US",
        verification_tier: "T1", tip_id_type: "personal",
      };
      const vp_signature = registerIdentitySchema.sign(
        registerIdentitySchema.buildSigningPayload(idFields), h.vpKp.privateKey,
      );
      return { body: { ...idFields, vp_signature } };
    },
    submit: (h, ctx) => h.services.identity.register(ctx.body),
    readBack: (h, _ctx, tx) => h.dag.getIdentity(tx.data.tip_id),
    // dedup_hash is classified notPersisted on the identity row, but it MUST
    // persist in the dedup registry (the replay/sybil guard). Asserting it here
    // proves the classification is "stored elsewhere", not a silent drop.
    extraAsserts: (h, _ctx, tx) => {
      expect(h.dag.getDedupRegistration(tx.data.dedup_hash)).toMatchObject({ tip_id: tx.data.tip_id });
    },
  },

  // ── REGISTER_CONTENT ───────────────────────────────────────────────────────
  {
    txType: "REGISTER_CONTENT",
    name: "CNA-2.2 content persists every signed field on the content row",
    signedKeysFn: (tx) => Object.keys(contentRegisterSchema.buildSigningPayload(tx.data, tx.data.content_hash)),
    notPersisted: [],
    setup: (h) => {
      const kp = generateMLDSAKeypair();
      const tipId = makeTipId("content-author");
      seedIdentity(h.dag, tipId, kp);
      return { body: buildContentBody({ tipId, privKey: kp.privateKey, content: "round-trip content body" }) };
    },
    submit: (h, ctx) => h.services.content.register(ctx.body),
    readBack: (h, _ctx, tx) => h.dag.getContent(tx.data.ctid),
  },

  // ── BIND_DOMAIN ────────────────────────────────────────────────────────────
  {
    txType: "BIND_DOMAIN",
    name: "node-attested domain binding persists every signed field on the binding row",
    schema: bindDomainSchema,
    notPersisted: [],
    setup: (h) => {
      const kp = generateMLDSAKeypair();
      const tipId = makeTipId("domain-org");
      seedIdentity(h.dag, tipId, kp, { type: TIP_ID_TYPES.ORGANIZATION, creatorName: "Acme News" });
      const domain = "acmenews.com";
      // Anchor claimed_at in the past so it precedes the verifier's verified_at.
      const claimed_at = nowMs() - 60_000;
      const payload = registerDomainSchema.buildSigningPayload({ claimed_at, domain, method: "auto", tip_id: tipId });
      const signature = registerDomainSchema.sign(payload, kp.privateKey);
      return { domain, claim: { tip_id: tipId, domain, method: "auto", claimed_at, signature } };
    },
    submit: async (h, ctx) => {
      h.services.domain.register(ctx.claim);
      return h.services.domain.verify({ domain: ctx.domain });
    },
    readBack: (h, ctx) => h.dag.getDomainBinding(ctx.domain),
    derived: { binding_state: () => DOMAIN_BINDING_STATUS.VERIFIED },
  },

  // ── UPDATE_PROFILE ─────────────────────────────────────────────────────────
  {
    txType: "UPDATE_PROFILE",
    name: "sparse consent update persists all three consent flags on the identity row",
    schema: updateProfileSchema,
    notPersisted: [],
    setup: (h) => {
      const kp = generateMLDSAKeypair();
      const tipId = makeTipId("profile-user");
      seedIdentity(h.dag, tipId, kp);
      const prefs = { reviewer_consent: true, juror_consent: true, expert_consent: true };
      const payload = updateProfileSchema.buildSigningPayload({ tip_id: tipId, ...prefs });
      const signature = updateProfileSchema.sign(payload, kp.privateKey);
      return { tipId, body: { ...prefs, signature } };
    },
    submit: (h, ctx) => h.services.profile.updateProfile(ctx.tipId, ctx.body),
    readBack: (h, _ctx, tx) => h.dag.getIdentity(tx.data.tip_id),
  },

  // ── LINK_PLATFORM ──────────────────────────────────────────────────────────
  {
    txType: "LINK_PLATFORM",
    name: "node-attested social link persists every signed field on the platform_links row",
    schema: linkPlatformSchema,
    // The row stores linked_at = verified_at; claimed_at (the user's claim time)
    // is signed for replay-binding but isn't a column on platform_links.
    notPersisted: ["claimed_at"],
    setup: (h) => {
      const kp = generateMLDSAKeypair();
      const tipId = makeTipId("link-user");
      seedIdentity(h.dag, tipId, kp);
      return { tipId, kp };
    },
    submit: async (h, ctx) => {
      const claimedAt = nowMs();
      const profileUrl = "https://medium.com/@alice";
      const claimSignature = registerSocialSchema.sign(
        registerSocialSchema.buildSigningPayload({ tip_id: ctx.tipId, platform: "medium", profile_url: profileUrl, claimed_at: claimedAt }),
        ctx.kp.privateKey,
      );
      // medium is a bio-check platform (not OAuth-required); stub the network
      // bio fetch so the link verifies hermetically.
      const orig = bioFetcher.verifyBio;
      bioFetcher.verifyBio = async () => ({ handle: "alice" });
      try {
        return await h.services.identity.linkPlatform({
          tipId: ctx.tipId, platform: "medium", profileUrl, claimSignature, claimedAt,
        });
      } finally { bioFetcher.verifyBio = orig; }
    },
    readBack: (h, _ctx, tx) => h.dag.getPlatformLink(tx.data.tip_id, tx.data.platform),
  },

  // ── INTEREST_REGISTERED ────────────────────────────────────────────────────
  {
    txType: "INTEREST_REGISTERED",
    name: "VP-approved interest persists every signed field on the interest row",
    schema: interestRegisteredSchema,
    notPersisted: [],
    // The approving VP is stored under the column registered_by_vp_id.
    rename: { approving_vp_id: "registered_by_vp_id" },
    setup: (h) => {
      const fields = { slug: "quantum-computing", label: "Quantum Computing", category: "tech", approving_vp_id: VP_ID };
      const signature = interestRegisteredSchema.sign(
        interestRegisteredSchema.buildSigningPayload(fields), h.vpKp.privateKey,
      );
      return { body: { ...fields, signature } };
    },
    submit: (h, ctx) => h.services.governance.addInterest(ctx.body),
    readBack: (h, _ctx, tx) => h.dag.getInterest(tx.data.slug),
  },

  // ── REVOKE_VOLUNTARY ───────────────────────────────────────────────────────
  {
    txType: "REVOKE_VOLUNTARY",
    name: "VP-attested voluntary revocation persists its signed fields on the revocation row",
    schema: { buildSigningPayload: REVOKE_CONTRACT.buildSigningPayload },
    // The revocations state row is intentionally minimal (tip_id, tx_type,
    // timestamp, tx_id). The VP attestation details ride the tx and stay
    // reachable via tx_id; they aren't duplicated into the state row.
    notPersisted: ["issuing_vp_id", "reason_code", "evidence_hash"],
    setup: (h) => {
      const kp = generateMLDSAKeypair();
      const tipId = makeTipId("revoke-target");
      seedIdentity(h.dag, tipId, kp);
      const data = { tx_type: "REVOKE_VOLUNTARY", tip_id: tipId, issuing_vp_id: VP_ID, reason_code: "user_request" };
      const signature = signPayload(REVOKE_CONTRACT.buildSigningPayload(data), h.vpKp.privateKey);
      return { body: { ...data, signature }, tipId };
    },
    submit: (h, ctx) => h.services.revocation.create(ctx.body),
    readBack: (h, ctx) => h.dag.getRevocation(ctx.tipId),
  },

  // ── CONTENT_VERIFIED ───────────────────────────────────────────────────────
  // Record-style tx: its canonical state IS the persisted tx (plus a paired
  // score delta). The guard is that the verifier's body signature over
  // [verifier_tip_id, ctid, verdict] is rebuilt identically at commit, so the
  // tx commits rather than being dropped.
  {
    txType: "CONTENT_VERIFIED",
    name: "verifier attestation commits and its signed fields persist on the tx",
    signedKeysFn: () => ["verifier_tip_id", "ctid", "verdict"],
    notPersisted: [],
    setup: async (h) => {
      const authorKp = generateMLDSAKeypair();
      const authorTipId = makeTipId("verify-author");
      seedIdentity(h.dag, authorTipId, authorKp);
      const verifierKp = generateMLDSAKeypair();
      const verifierTipId = makeTipId("verify-verifier");
      seedIdentity(h.dag, verifierTipId, verifierKp);
      const ctid = await seedRegisteredContent(h, { authorTipId, authorKp });
      return { ctid, authorTipId, verifierTipId, verifierKp };
    },
    submit: (h, ctx) => {
      const verdict = "ORIGIN_CONFIRMED";
      const signature = signPayload(
        { verifier_tip_id: ctx.verifierTipId, ctid: ctx.ctid, verdict }, ctx.verifierKp.privateKey,
      );
      return h.services.content.verify(ctx.ctid, { verifier_tip_id: ctx.verifierTipId, verdict, signature });
    },
    readBack: (h, _ctx, tx) => h.dag.getTx(tx.tx_id) && h.dag.getTx(tx.tx_id).data,
    // Derived state beyond the verification record: the author's score moves by
    // the verification's recorded weighted_delta (single-channel score effect).
    // This proves the commit actually applied state, not merely stored the tx.
    extraAsserts: (h, ctx, tx) => {
      expect(h.scoring.getScore(ctx.authorTipId).score - 750).toBe(tx.data.weighted_delta);
    },
  },

  // ── UPDATE_ORIGIN ──────────────────────────────────────────────────────────
  // The signed new_origin_code lands on the content row's origin_code column.
  {
    txType: "UPDATE_ORIGIN",
    name: "author origin correction persists the new origin on the content row",
    signedKeysFn: () => ["author_tip_id", "ctid", "new_origin_code"],
    notPersisted: [],
    rename: { new_origin_code: "origin_code" },
    setup: async (h) => {
      const authorKp = generateMLDSAKeypair();
      const authorTipId = makeTipId("update-author");
      seedIdentity(h.dag, authorTipId, authorKp);
      const ctid = await seedRegisteredContent(h, { authorTipId, authorKp });
      return { ctid, authorTipId, authorKp };
    },
    submit: (h, ctx) => {
      const new_origin_code = "AG"; // AI-generated, a valid origin distinct from the seeded OH
      const signature = signPayload(
        { author_tip_id: ctx.authorTipId, ctid: ctx.ctid, new_origin_code }, ctx.authorKp.privateKey,
      );
      return h.services.content.updateOrigin(ctx.ctid, { author_tip_id: ctx.authorTipId, new_origin_code, signature });
    },
    readBack: (h, ctx) => h.dag.getContent(ctx.ctid),
  },

  // ── CONTENT_RETRACTED ──────────────────────────────────────────────────────
  // Author retracts: the content row's status flips to retracted.
  {
    txType: "CONTENT_RETRACTED",
    name: "author retraction flips the content row status and persists its signed fields",
    signedKeysFn: () => ["author_tip_id", "ctid"],
    notPersisted: [],
    setup: async (h) => {
      const authorKp = generateMLDSAKeypair();
      const authorTipId = makeTipId("retract-author");
      seedIdentity(h.dag, authorTipId, authorKp);
      const ctid = await seedRegisteredContent(h, { authorTipId, authorKp });
      return { ctid, authorTipId, authorKp };
    },
    submit: (h, ctx) => {
      const signature = signPayload(
        { author_tip_id: ctx.authorTipId, ctid: ctx.ctid }, ctx.authorKp.privateKey,
      );
      return h.services.content.retract(ctx.ctid, { author_tip_id: ctx.authorTipId, signature });
    },
    readBack: (h, ctx) => h.dag.getContent(ctx.ctid),
    derived: { status: () => "retracted" },
  },

  // ── CONTENT_DISPUTED ───────────────────────────────────────────────────────
  // The P1 area: disputer signs [disputer_tip_id, reason, ctid, claimed_origin,
  // evidence_hash]; the same field-list must be rebuilt at commit. Record-style
  // tx, its signed fields persist on the tx, and the content row flips to
  // disputed as derived state.
  {
    txType: "CONTENT_DISPUTED",
    name: "disputer filing commits and its signed fields persist; content flips to disputed",
    signedKeysFn: () => ["disputer_tip_id", "reason", "ctid", "claimed_origin", "evidence_hash"],
    notPersisted: [],
    setup: async (h) => {
      const authorKp = generateMLDSAKeypair();
      const authorTipId = makeTipId("dispute-author");
      seedIdentity(h.dag, authorTipId, authorKp);
      const disputerKp = generateMLDSAKeypair();
      const disputerTipId = makeTipId("dispute-disputer");
      // Disputer floor is 550 (the dispute filing minimum score).
      seedIdentity(h.dag, disputerTipId, disputerKp, { score: 600 });
      const ctid = await seedRegisteredContent(h, { authorTipId, authorKp });
      return { ctid, disputerTipId, disputerKp };
    },
    submit: (h, ctx) => {
      const claimedOrigin = "AG";
      const payload = { description: "round-trip dispute evidence description" };
      const evidenceHash = shake256(canonicalJson(payload));
      const evidenceSig = signBody(payload, ctx.disputerKp.privateKey);
      const sigFields = {
        disputer_tip_id: ctx.disputerTipId, reason: "origin_mismatch",
        ctid: ctx.ctid, claimed_origin: claimedOrigin, evidence_hash: evidenceHash,
      };
      return h.services.dispute.fileDispute(ctx.ctid, {
        disputer_tip_id: ctx.disputerTipId, reason: "origin_mismatch",
        claimed_origin: claimedOrigin, evidence_hash: evidenceHash,
        signature: signBody(sigFields, ctx.disputerKp.privateKey),
        evidence: { payload, signature: evidenceSig },
      });
    },
    readBack: (h, _ctx, tx) => h.dag.getTx(tx.tx_id) && h.dag.getTx(tx.tx_id).data,
    extraAsserts: (h, ctx) => {
      expect(h.dag.getContent(ctx.ctid).status).toBe("disputed");
    },
  },

  // ── KEY_ROTATED ────────────────────────────────────────────────────────────
  // OLD key signs the rotation; commit-handler closes the OLD entity_keys row
  // and activates the NEW key. The new public key + algorithm land as the
  // active key.
  {
    txType: "KEY_ROTATED",
    name: "OLD-key-signed rotation activates the NEW key (effective_at -> valid_from_ts)",
    schema: keyRotatedSchema,
    // The rotation's effective_at lands as the new key row's valid_from_ts.
    rename: { new_public_key: "public_key", effective_at: "valid_from_ts" },
    // tip_id is the entity_id (the lookup key, not a column on the row
    // projection); old_key_fingerprint is the close-reference used to retire
    // the OLD row, it is not carried onto the NEW key.
    notPersisted: ["tip_id", "old_key_fingerprint"],
    setup: (h) => {
      const oldKp = generateMLDSAKeypair();
      const tipId = makeTipId("rotate-user");
      seedIdentity(h.dag, tipId, oldKp);
      const newKp = generateMLDSAKeypair();
      return { tipId, oldKp, newKp };
    },
    submit: (h, ctx) => {
      // effective_at must be >= the service's tx.timestamp (set at call time).
      const effective_at = nowMs() + 60_000;
      const fields = {
        tip_id: ctx.tipId, algorithm: "ml-dsa-65", new_public_key: ctx.newKp.publicKey,
        old_key_fingerprint: shake256(ctx.oldKp.publicKey).slice(0, 32), effective_at,
      };
      const signature = keyRotatedSchema.sign(keyRotatedSchema.buildSigningPayload(fields), ctx.oldKp.privateKey);
      return h.services.key.rotateKey({ ...fields, signature });
    },
    // The newly-activated key is the open row (valid_to_ts === null) in the
    // entity_keys chain; reading the full row lets us assert valid_from_ts too.
    readBack: (h, ctx) => h.dag.getEntityKeyHistory("identity", ctx.tipId).find((k) => k.valid_to_ts == null) || null,
  },

  // ── UNLINK_PLATFORM ────────────────────────────────────────────────────────
  // Subject-signed; the active platform_links row flips to unlinked.
  {
    txType: "UNLINK_PLATFORM",
    name: "subject-signed unlink flips the platform_links row to unlinked",
    schema: unlinkPlatformSchema,
    // link_tx_id + claimed_at are signed for replay-binding but aren't columns
    // on the platform_links row (the row already carries the link's own tx_id).
    notPersisted: ["link_tx_id", "claimed_at"],
    derived: { status: () => "unlinked" },
    setup: async (h) => {
      const kp = generateMLDSAKeypair();
      const tipId = makeTipId("unlink-user");
      seedIdentity(h.dag, tipId, kp);
      const profileUrl = "https://medium.com/@bob";
      const claimedAt = nowMs();
      const claimSignature = registerSocialSchema.sign(
        registerSocialSchema.buildSigningPayload({ tip_id: tipId, platform: "medium", profile_url: profileUrl, claimed_at: claimedAt }),
        kp.privateKey,
      );
      const orig = bioFetcher.verifyBio;
      bioFetcher.verifyBio = async () => ({ handle: "bob" });
      try {
        await h.services.identity.linkPlatform({ tipId, platform: "medium", profileUrl, claimSignature, claimedAt });
      } finally { bioFetcher.verifyBio = orig; }
      const linkTxId = h.submitted.find((t) => t.tx_type === "LINK_PLATFORM").tx_id;
      h.commit(); // settle the active link so it can be unlinked
      return { tipId, kp, platform: "medium", linkTxId };
    },
    submit: (h, ctx) => {
      const claimedAt = nowMs();
      const signature = unlinkPlatformSchema.sign(
        unlinkPlatformSchema.buildSigningPayload({ tip_id: ctx.tipId, platform: ctx.platform, link_tx_id: ctx.linkTxId, claimed_at: claimedAt }),
        ctx.kp.privateKey,
      );
      return h.services.identity.unlinkPlatform({ tipId: ctx.tipId, platform: ctx.platform, linkTxId: ctx.linkTxId, signature, claimedAt });
    },
    readBack: (h, ctx) => h.dag.getPlatformLink(ctx.tipId, ctx.platform),
  },

  // ── JURY_VOTE_COMMIT ───────────────────────────────────────────────────────
  // Summoned juror commits a sealed vote. Subject-signed over
  // [juror_tip_id, commitment, ctid, is_appeal]; commit-handler must rebuild
  // the same field list for the tx to commit.
  {
    txType: "JURY_VOTE_COMMIT",
    name: "summoned juror's vote commitment commits and persists its signed fields",
    signedKeysFn: (tx) => Object.keys(TX_SIGNATURE_REGISTRY.JURY_VOTE_COMMIT.buildSigningPayload(tx.data)),
    notPersisted: [],
    setup: async (h) => {
      const jurorKp = generateMLDSAKeypair();
      const jurorTipId = makeTipId("jury-commit-juror");
      seedIdentity(h.dag, jurorTipId, jurorKp);
      const ctid = await seedDisputedWithSummons(h, {
        jurorTipId, commitDeadline: nowMs() + 3_600_000, revealDeadline: nowMs() + 7_200_000,
      });
      return { ctid, jurorTipId, jurorKp };
    },
    submit: (h, ctx) => {
      const commitment = shake256("MATCH:salt-commit");
      const signature = signPayload(
        TX_SIGNATURE_REGISTRY.JURY_VOTE_COMMIT.buildSigningPayload({ juror_tip_id: ctx.jurorTipId, commitment, ctid: ctx.ctid, is_appeal: false }),
        ctx.jurorKp.privateKey,
      );
      return h.services.dispute.juryCommit(ctx.ctid, { juror_tip_id: ctx.jurorTipId, commitment, signature });
    },
    readBack: (h, _ctx, tx) => h.dag.getTx(tx.tx_id) && h.dag.getTx(tx.tx_id).data,
  },

  // ── JURY_VOTE_REVEAL ───────────────────────────────────────────────────────
  // Juror reveals the vote+salt behind a prior commitment (seeded). Subject-
  // signed over [juror_tip_id, vote, salt, ctid, is_appeal].
  {
    txType: "JURY_VOTE_REVEAL",
    name: "summoned juror's vote reveal commits and persists its signed fields",
    signedKeysFn: (tx) => Object.keys(TX_SIGNATURE_REGISTRY.JURY_VOTE_REVEAL.buildSigningPayload(tx.data)),
    notPersisted: [],
    setup: async (h) => {
      const jurorKp = generateMLDSAKeypair();
      const jurorTipId = makeTipId("jury-reveal-juror");
      seedIdentity(h.dag, jurorTipId, jurorKp);
      // Reveal window opens after the commit deadline → put commit_deadline in
      // the past, reveal_deadline in the future.
      const ctid = await seedDisputedWithSummons(h, {
        jurorTipId, commitDeadline: nowMs() - 3_600_000, revealDeadline: nowMs() + 3_600_000,
      });
      const vote = "MATCH";
      const salt = "salt-reveal";
      const commitment = shake256(`${vote}:${salt}`);
      // The juror's prior sealed commitment the reveal must match.
      h.dag.addTx(withTxId({
        tx_type: "JURY_VOTE_COMMIT", timestamp: nowMs() - 1_800_000, prev: h.dag.getRecentPrev(),
        data: { ctid, juror_tip_id: jurorTipId, commitment, is_appeal: false },
      }));
      return { ctid, jurorTipId, jurorKp, vote, salt };
    },
    submit: (h, ctx) => {
      const signature = signPayload(
        TX_SIGNATURE_REGISTRY.JURY_VOTE_REVEAL.buildSigningPayload({ juror_tip_id: ctx.jurorTipId, vote: ctx.vote, salt: ctx.salt, ctid: ctx.ctid, is_appeal: false }),
        ctx.jurorKp.privateKey,
      );
      return h.services.dispute.juryReveal(ctx.ctid, { juror_tip_id: ctx.jurorTipId, vote: ctx.vote, salt: ctx.salt, signature });
    },
    readBack: (h, _ctx, tx) => h.dag.getTx(tx.tx_id) && h.dag.getTx(tx.tx_id).data,
  },
];

describe("consensus-path round-trip: every signed field persists", () => {
  for (const c of CASES) runRoundTrip(c);
});
