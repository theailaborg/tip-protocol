/**
 * @file tests/integration/email-private-record.test.js
 * @description An email record stays private and carries no checked claim.
 *
 *   - It can register by its hash alone, so the node never sees the email.
 *   - It earns no registration credit (nobody could ever dispute it away).
 *   - From EMAIL_PRIVATE_ACTIVATION_MS: no links, no verify, no dispute, at
 *     API time and at commit (a tx sent straight to consensus).
 *   - Responses say its origin is self-declared.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// The gate is read once at module load; "1" means on for every real time.
// Saved and restored: --runInBand shares process.env with every later test file.
const _envBefore = { TIP_EMAIL_PRIVATE_ACTIVATION_MS: process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS };
process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS = "1";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, tipNormalize, computeTxId } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TX_TYPES, ORIGIN, MEDIA_LIMITS, REGISTER_CREDIT, ORIGIN_BASIS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createPrescanJobs } = require(path.join(SRC, "services", "prescan-jobs"));
const { createPrescanWorker } = require(path.join(SRC, "workers", "prescan-worker"));
const rules = require(path.join(SRC, "validators", "business-rules"));
const schema = require(path.join(SRC, "schemas", "content-register"));

const NODE_ID = "tip://node/n_email_private";
const VP_ID = "tip://vp/v1";
const AUTHOR = "tip://id/US-e2e2e2e2e2e2e2e2";
const OTHER = "tip://id/US-f3f3f3f3f3f3f3f3";
const EMAIL_TEXT = "Board notes\nThe acquisition price is 18.4 million, keep it private.";
const EMAIL_HASH = () => shake256(tipNormalize(EMAIL_TEXT));
const URL = "https://example.com/2026/11/post";

beforeAll(async () => { await initCrypto(); });
afterAll(() => {
  for (const [k, v] of Object.entries(_envBefore)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

// Fresh module copies (jest.isolateModules) start with protocol constants unset.
function initIsolatedConstants() {
  const PC = require(path.join(SHARED, "protocol-constants"));
  try { PC._resetForTesting(); } catch { /* not initialized yet */ }
  PC.init(require(path.join(SRC, "genesis")).getGenesisPayload().protocol_constants);
}

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const keys = { [AUTHOR]: generateMLDSAKeypair(), [OTHER]: generateMLDSAKeypair() };
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  for (const tipId of [AUTHOR, OTHER]) {
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: keys[tipId].publicKey, root_public_key: keys[tipId].publicKey,
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", reviewer_consent: false,
      registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
    });
  }
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, mediaLimits: MEDIA_LIMITS };
  const scoring = initScoring(dag, config);
  dag.setScore(AUTHOR, 700, 0, 1769904000000);
  dag.setScore(OTHER, 700, 0, 1769904000000);

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  let t = nowMs();
  const now = () => t;
  const prescanJobs = createPrescanJobs({ dag, now });
  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId: NODE_ID });
  const contentService = createContentService({ dag, scoring, config, submitTx, prescanJobs });
  const classifier = { prescan: jest.fn(), stage1: async () => ({}), providers: async () => ({}), health: async () => ({}) };
  const worker = createPrescanWorker({
    dag, jobs: prescanJobs, classifierClient: classifier, submitTx, config,
    log: { info: () => {}, warn: () => {}, error: () => {} }, now,
  });

  let round = 0;
  const commitDrain = () => {
    round += 1;
    t += 100;
    return commitHandler.commitOrderedTxs(submitted.splice(0), round, { certTimestamp: t });
  };

  // signedHash: what the signer signed over; content: sent text, or omitted for hash-only.
  function body({ content, contentHash, signedHash, extras = { email: { v: 1 } }, registered_urls = [], parent_url } = {}) {
    const fields = {
      origin_code: ORIGIN.OH, registered_urls, extras,
      authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR, tip_id_type: "personal" }],
      signer_tip_id: AUTHOR, attribution_mode: "self",
      ...(parent_url ? { parent_url } : {}),
    };
    const hash = signedHash || (content ? shake256(tipNormalize(content)) : EMAIL_HASH());
    const out = {
      ...fields, cna_version: schema.CURRENT_CNA_VERSION, content_type: "text",
      signature: schema.sign(schema.buildSigningPayload(fields, hash), keys[AUTHOR].privateKey),
    };
    if (content) out.content = content;
    else out.content_hash = contentHash || hash;
    return out;
  }

  // A REGISTER_CONTENT built by hand and sent straight to consensus, past every API check.
  function directRegisterTx({ extras, registered_urls, tag, ts }) {
    const data = {
      ctid: `tip://c/OH-${shake256(tag).slice(0, 14)}-0009`, origin_code: "OH", content_hash: shake256(tag),
      signer_tip_id: AUTHOR, registered_urls, attribution_mode: "self", extras,
      authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR, tip_id_type: "personal" }],
      cna_version: schema.CURRENT_CNA_VERSION,
    };
    data.signature = schema.sign(schema.buildSigningPayload(data, data.content_hash), keys[AUTHOR].privateKey);
    const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: ts, prev: dag.getRecentPrev(), data, signature: data.signature };
    tx.tx_id = computeTxId(tx);
    return tx;
  }

  function saveRecord({ ctid, extras }) {
    dag.saveContent({
      ctid, origin_code: "OH", content_hash: shake256(ctid), author_tip_id: AUTHOR, signer_tip_id: AUTHOR,
      authors: [], attribution_mode: "self", extras, cna_version: schema.CURRENT_CNA_VERSION,
      status: "registered", prescan_status: "completed", override: false, registered_at: 1790000000000,
      registered_urls: [], tx_id: `tx_${ctid}`,
    });
    return ctid;
  }

  return { dag, scoring, contentService, commitHandler, prescanJobs, worker, classifier, submitted, commitDrain, body, directRegisterTx, saveRecord };
}

const credits = (submitted) => submitted.filter((tx) => tx.tx_type === TX_TYPES.SCORE_UPDATE
  && String(tx.data.reason || "").startsWith(REGISTER_CREDIT.AWARD_REASON_PREFIX));

describe("hash-only email", () => {
  test("registers with only its hash: the node never sees the email, and the record is the one its text would make", async () => {
    const fx = setup();
    const r = await fx.contentService.register(fx.body());
    expect(r.ctid.startsWith(`tip://c/OH-${EMAIL_HASH().slice(0, 14)}-`)).toBe(true);

    const regTx = fx.submitted.find((tx) => tx.tx_type === TX_TYPES.REGISTER_CONTENT);
    expect(regTx.data.content_hash).toBe(EMAIL_HASH());
    expect(regTx.data).not.toHaveProperty("text_chars");
    const job = fx.prescanJobs.getByCtid(r.ctid);
    expect(job.payload).toMatchObject({ text: "", email: true, content_type: "text" });

    fx.commitDrain();
    expect((await fx.worker.tick()).outcome).toBe("completed");
    expect(fx.classifier.prescan).not.toHaveBeenCalled();
    fx.commitDrain();

    const rec = await fx.contentService.resolve(r.ctid);
    expect(rec).toMatchObject({ content_hash: EMAIL_HASH(), is_email: true, origin_basis: ORIGIN_BASIS.SELF_DECLARED, prescan_status: "completed" });

    // The same email sent with its text (older clients) lands on the same CTID.
    const withText = setup();
    expect((await withText.contentService.register(withText.body({ content: EMAIL_TEXT }))).ctid).toBe(r.ctid);
  });

  test("the signature covers the hash: a hash other than the signed one is refused", async () => {
    const fx = setup();
    await expect(fx.contentService.register(fx.body({ contentHash: shake256("another email") })))
      .rejects.toMatchObject({ status: 403, code: "signature_invalid" });
    expect(fx.submitted).toHaveLength(0);
  });

  test("a hash-only email carries nothing but the hash and seals", async () => {
    const fx = setup();
    const refused = { status: 400, code: "email_hash_only_invalid" };
    const tamper = async (patch) => fx.contentService.register({ ...fx.body(), ...patch });
    await expect(tamper({ content_hash: "ABC" })).rejects.toMatchObject(refused);
    await expect(tamper({ media: [{ media_id: "ab".repeat(32), mime: "image/png" }] })).rejects.toMatchObject(refused);
    await expect(tamper({ media_canonical_hash: "cd".repeat(32) })).rejects.toMatchObject(refused);
    await expect(tamper({ fingerprints: {}, fingerprint_commit: "ef".repeat(32) })).rejects.toMatchObject(refused);
    await expect(tamper({ content_type_hint: "image" })).rejects.toMatchObject(refused);
    // Only an email may register by hash.
    await expect(fx.contentService.register(fx.body({ extras: {} })))
      .rejects.toMatchObject({ status: 400, code: "content_required" });
    expect(fx.submitted).toHaveLength(0);
  });

  test("links are refused by the request schema itself, before any activation", () => {
    const fx = setup();
    for (const patch of [{ registered_urls: [URL] }, { parent_url: URL }]) {
      let err;
      try { schema.validateRequest({ ...fx.body(), ...patch }, { mediaLimits: MEDIA_LIMITS, dag: fx.dag }); } catch (e) { err = e; }
      expect(err).toMatchObject({ status: 400, code: "email_no_links" });
    }
  });
});

describe("registration credit", () => {
  test("an email earns none, with or without its text; any other registration still does", async () => {
    const fx = setup();
    await fx.contentService.register(fx.body());
    expect(credits(fx.submitted)).toHaveLength(0);
    fx.submitted.length = 0;

    const withText = setup();
    await withText.contentService.register(withText.body({ content: EMAIL_TEXT }));
    expect(credits(withText.submitted)).toHaveLength(0);

    const post = setup();
    await post.contentService.register(post.body({ content: "A public post about gardening", extras: {} }));
    expect(credits(post.submitted)).toHaveLength(1);
  });
});

describe("an email record has no links (from the activation)", () => {
  test("the API refuses an email with registered_urls or parent_url; the same post without the marker registers", async () => {
    const fx = setup();
    const noLinks = { status: 400, code: "email_no_links" };
    await expect(fx.contentService.register(fx.body({ registered_urls: [URL] }))).rejects.toMatchObject(noLinks);
    await expect(fx.contentService.register(fx.body({ content: EMAIL_TEXT, registered_urls: [URL] }))).rejects.toMatchObject(noLinks);
    await expect(fx.contentService.register(fx.body({ content: EMAIL_TEXT, parent_url: URL }))).rejects.toMatchObject(noLinks);
    expect(fx.submitted).toHaveLength(0);
    const r = await fx.contentService.register(fx.body({ content: EMAIL_TEXT, extras: {}, registered_urls: [URL] }));
    expect(r.ctid).toBeTruthy();
  });

  test("consensus drops an email with links sent straight to a peer; without the marker it commits", () => {
    const fx = setup();
    const ts = nowMs();
    const email = fx.directRegisterTx({ extras: { email: { v: 1 } }, registered_urls: [URL], tag: "direct-email", ts });
    expect(fx.commitHandler.commitOrderedTxs([email], 10, { certTimestamp: ts }).committed).toBe(0);
    expect(fx.dag.getContent(email.data.ctid)).toBeNull();
    const post = fx.directRegisterTx({ extras: {}, registered_urls: [URL], tag: "direct-post", ts });
    expect(fx.commitHandler.commitOrderedTxs([post], 11, { certTimestamp: ts }).committed).toBe(1);
  });

  test("before the activation an email with links is still allowed (no fork with older nodes)", () => {
    jest.isolateModules(() => {
      process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS = String(nowMs() + 365 * 86400000);
      initIsolatedConstants();
      const r = require(path.join(SRC, "validators", "business-rules"));
      const fx = setup();
      const args = { signer_tip_id: AUTHOR, ctid: null, origin_code: "OH", registered_urls: [URL], at_ms: nowMs(), extras: { email: { v: 1 } } };
      expect(r.canRegisterContent(fx.dag, args).valid).toBe(true);
      expect(r.canRegisterContent(fx.dag, { ...args, registered_urls: [], parent_url: URL }).valid).toBe(true);
    });
    process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS = "1";
  });

  test("links cannot be added to an email record later", () => {
    const fx = setup();
    const ctid = fx.saveRecord({ ctid: "tip://c/OH-aaaaaaaaaaaaaa-0001", extras: { email: { v: 1 } } });
    const r = rules.canUpdateRegisteredUrls(fx.dag, { ctid, author_tip_id: AUTHOR, registered_urls: [URL], at_ms: nowMs() });
    expect(r).toMatchObject({ valid: false, error: { status: 403, code: "email_no_links" } });
    const post = fx.saveRecord({ ctid: "tip://c/OH-bbbbbbbbbbbbbb-0001", extras: {} });
    expect(rules.canUpdateRegisteredUrls(fx.dag, { ctid: post, author_tip_id: AUTHOR, registered_urls: [URL], at_ms: nowMs() }).valid).toBe(true);
  });
});

describe("nobody can verify or dispute an email record (from the activation)", () => {
  test("verify and dispute are refused for an email record, not for a post", () => {
    const fx = setup();
    const email = fx.saveRecord({ ctid: "tip://c/OH-cccccccccccccc-0001", extras: { email: { v: 1 } } });
    const post = fx.saveRecord({ ctid: "tip://c/OH-dddddddddddddd-0001", extras: {} });
    const now = nowMs();

    expect(rules.canVerify(fx.dag, { ctid: email, verifier_tip_id: OTHER }, { now }))
      .toMatchObject({ valid: false, error: { status: 403, code: "email_not_verifiable" } });
    expect(rules.canDispute(fx.dag, fx.scoring, { ctid: email, disputer_tip_id: OTHER }, { now }))
      .toMatchObject({ valid: false, error: { status: 403, code: "email_not_disputable" } });
    expect(rules.canVerify(fx.dag, { ctid: post, verifier_tip_id: OTHER }, { now }).valid).toBe(true);
    expect(rules.canDispute(fx.dag, fx.scoring, { ctid: post, disputer_tip_id: OTHER }, { now }).valid).toBe(true);
  });

  test("before the activation both are still allowed", () => {
    jest.isolateModules(() => {
      process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS = String(nowMs() + 365 * 86400000);
      initIsolatedConstants();
      const r = require(path.join(SRC, "validators", "business-rules"));
      const fx = setup();
      const email = fx.saveRecord({ ctid: "tip://c/OH-eeeeeeeeeeeeee-0001", extras: { email: { v: 1 } } });
      expect(r.canVerify(fx.dag, { ctid: email, verifier_tip_id: OTHER }, { now: nowMs() }).valid).toBe(true);
      expect(r.canDispute(fx.dag, fx.scoring, { ctid: email, disputer_tip_id: OTHER }, { now: nowMs() }).valid).toBe(true);
    });
    process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS = "1";
  });
});

describe("origin_basis", () => {
  test("list rows and the record say self_declared for an email, open_to_review otherwise", async () => {
    const fx = setup();
    const email = fx.saveRecord({ ctid: "tip://c/OH-ffffffffffffff-0001", extras: { email: { v: 1 } } });
    const post = fx.saveRecord({ ctid: "tip://c/OH-99999999999999-0001", extras: {} });
    const rows = fx.contentService.list({ author: AUTHOR }).items;
    expect(rows.find((x) => x.ctid === email)).toMatchObject({ is_email: true, origin_basis: ORIGIN_BASIS.SELF_DECLARED });
    expect(rows.find((x) => x.ctid === post)).toMatchObject({ is_email: false, origin_basis: ORIGIN_BASIS.OPEN_TO_REVIEW });
    expect(await fx.contentService.resolve(post)).toMatchObject({ is_email: false, origin_basis: ORIGIN_BASIS.OPEN_TO_REVIEW });
  });
});
