/**
 * @file tests/integration/email-seals-required.test.js
 * @description From EMAIL_SEALS_REQUIRED_ACTIVATION_MS a new email record must seal
 * `from`, `recipients` or `all`, and `attachments`, and must not be empty text.
 * Checked through the API and at commit (a tx sent straight to consensus), after the
 * activation, before it, and backdated across it. A post is unaffected.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");
const { nowMs } = require(path.join(SHARED, "time"));

// Activation an hour ago, read once at module load; "before" is a past time.
const GATE = nowMs() - 60 * 60 * 1000;
const BEFORE = GATE - 10 * 60 * 1000;
const _envBefore = {
  TIP_EMAIL_PRIVATE_ACTIVATION_MS: process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS,
  TIP_EMAIL_SEALS_REQUIRED_ACTIVATION_MS: process.env.TIP_EMAIL_SEALS_REQUIRED_ACTIVATION_MS,
};
process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS = "1";
process.env.TIP_EMAIL_SEALS_REQUIRED_ACTIVATION_MS = String(GATE);

const { initCrypto, generateMLDSAKeypair, shake256, tipNormalize, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, ORIGIN, MEDIA_LIMITS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const schema = require(path.join(SRC, "schemas", "content-register"));

const NODE_ID = "tip://node/n_seals";
const VP_ID = "tip://vp/v1";
const AUTHOR = "tip://id/US-a7a7a7a7a7a7a7a7";
const S = { from: "f0".repeat(32), recipients: "5a".repeat(32), all: "a1".repeat(32), attachments: "c3".repeat(32) };
const FULL = { v: 1, ...S };

beforeAll(async () => { await initCrypto(); });
afterAll(() => {
  for (const [k, v] of Object.entries(_envBefore)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

function at(ms, fn) {
  const spy = jest.spyOn(Date, "now").mockReturnValue(ms);
  return Promise.resolve().then(fn).finally(() => spy.mockRestore());
}

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const authorKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  dag.saveIdentity({
    tip_id: AUTHOR, region: "US", public_key: authorKp.publicKey, root_public_key: authorKp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", reviewer_consent: false,
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: AUTHOR }),
  });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, mediaLimits: MEDIA_LIMITS };
  const scoring = initScoring(dag, config);
  const submitted = [];
  const contentService = createContentService({ dag, scoring, config, submitTx: (tx) => submitted.push(tx) });
  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId: NODE_ID });
  let round = 100;
  const commits = (tx, cert = nowMs()) => commitHandler.commitOrderedTxs([tx], ++round, { certTimestamp: cert }).committed;

  const extrasFor = (marker) => (marker && Object.keys(marker).length ? { email: marker } : {});
  const fields = (marker) => ({
    origin_code: ORIGIN.OH, registered_urls: [], extras: extrasFor(marker), signer_tip_id: AUTHOR, attribution_mode: "self",
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR, tip_id_type: "personal" }],
  });
  // An email by hash alone, or with its text when `content` is given.
  function email(extras, { content, hash: given, tag = Math.random().toString(36) } = {}) {
    const hash = given || (content !== undefined ? shake256(tipNormalize(content)) : shake256(`email ${tag}`));
    const f = fields(extras);
    const out = { ...f, cna_version: schema.CURRENT_CNA_VERSION, content_type: "text", signature: schema.sign(schema.buildSigningPayload(f, hash), authorKp.privateKey) };
    if (content !== undefined) out.content = content; else out.content_hash = hash;
    return out;
  }
  function directTx(marker, { tag, timestamp }) {
    const data = {
      ctid: `tip://c/OH-${shake256(tag).slice(0, 14)}-0009`, origin_code: "OH", content_hash: shake256(tag),
      signer_tip_id: AUTHOR, registered_urls: [], attribution_mode: "self", extras: extrasFor(marker),
      authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR, tip_id_type: "personal" }],
      cna_version: schema.CURRENT_CNA_VERSION,
    };
    data.signature = schema.sign(schema.buildSigningPayload(data, data.content_hash), authorKp.privateKey);
    const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp, prev: dag.getRecentPrev(), data, signature: data.signature };
    tx.tx_id = computeTxId(tx);
    return tx;
  }
  return { dag, contentService, submitted, commits, email, directTx };
}

const refused = (code, missing) => ({ status: 400, code, ...(missing ? { details: { missing } } : {}) });

describe("after the activation (API)", () => {
  test("a fully sealed email registers, with and without its text", async () => {
    const fx = setup();
    await expect(fx.contentService.register(fx.email(FULL))).resolves.toHaveProperty("ctid");
    await expect(fx.contentService.register(fx.email(FULL, { content: "Board notes\nPay EUR 1,250.50" }))).resolves.toHaveProperty("ctid");
  });

  test("a Bcc-only email (all, no recipients) registers", async () => {
    const fx = setup();
    const { recipients, ...bccOnly } = FULL;
    await expect(fx.contentService.register(fx.email(bccOnly))).resolves.toHaveProperty("ctid");
  });

  test.each([
    ["from", { v: 1, recipients: S.recipients, attachments: S.attachments }, ["from"]],
    ["attachments", { v: 1, from: S.from, recipients: S.recipients }, ["attachments"]],
    ["recipients and all", { v: 1, from: S.from, attachments: S.attachments }, ["recipients or all"]],
    ["every seal", { v: 1 }, ["from", "recipients or all", "attachments"]],
  ])("missing %s is refused, naming what is missing", async (_label, emailMarker, missing) => {
    const fx = setup();
    await expect(fx.contentService.register(fx.email(emailMarker))).rejects.toMatchObject(refused("email_seals_required", missing));
    expect(fx.submitted.filter((t) => t.tx_type === TX_TYPES.REGISTER_CONTENT)).toHaveLength(0);
  });

  test("an email with no subject or body is refused, by hash alone or with text that normalizes to nothing", async () => {
    const fx = setup();
    await expect(fx.contentService.register(fx.email(FULL, { hash: shake256("") }))).rejects.toMatchObject(refused("email_empty"));
    await expect(fx.contentService.register(fx.email(FULL, { content: "!!! ???" }))).rejects.toMatchObject(refused("email_empty"));
  });

  test("a post without the marker is unaffected", async () => {
    const fx = setup();
    const post = fx.email({}, { content: "An ordinary public post" });
    await expect(fx.contentService.register(post)).resolves.toHaveProperty("ctid");
  });
});

describe("before the activation", () => {
  test("an email missing seals still registers (older clients keep working until the date)", async () => {
    const fx = setup();
    await expect(at(BEFORE, () => fx.contentService.register(fx.email({ v: 1, recipients: S.recipients })))).resolves.toHaveProperty("ctid");
  });
});

describe("at commit (a tx sent straight to consensus)", () => {
  test("missing seals: dropped after the activation and when backdated across it; committed when certified before", () => {
    const fx = setup();
    const partial = { v: 1, recipients: S.recipients };
    expect(fx.commits(fx.directTx(partial, { tag: "after", timestamp: nowMs() }))).toBe(0);
    expect(fx.commits(fx.directTx(partial, { tag: "backdated", timestamp: BEFORE }))).toBe(0);
    expect(fx.commits(fx.directTx(partial, { tag: "before", timestamp: BEFORE }), BEFORE + 1000)).toBe(1);
    expect(fx.commits(fx.directTx(FULL, { tag: "full", timestamp: nowMs() }))).toBe(1);
    expect(fx.commits(fx.directTx({}, { tag: "post", timestamp: nowMs() }))).toBe(1);
  });
});
