/**
 * @file tests/integration/email-sign-limits.test.js
 * @description Signed emails a UTC month by plan (node 2.9.8, founder
 * 2026-11-13: Free 100, Plus 500, Pro 1,000, Max 5,000, a commercial licence
 * 5,000). The billing service gives the allowance; the node counts the
 * month's emails from its own records plus its mempool, and refuses with 429
 * email_sign_limit before anything is written. Posts are never counted, an
 * unreachable service or one whose limits have not started lets the email
 * through, and an unsigned request cannot probe a plan.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// The required-seals rule (2.9.5) has its own file; kept off here.
const _sealsGateBefore = process.env.TIP_EMAIL_SEALS_REQUIRED_ACTIVATION_MS;
process.env.TIP_EMAIL_SEALS_REQUIRED_ACTIVATION_MS = "4102444800000";
jest.resetModules();

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, tipNormalize } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TX_TYPES, ORIGIN, MEDIA_LIMITS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

try { PC._resetForTesting(); } catch { /* already initialized */ }
PC.init(getGenesisPayload().protocol_constants);

const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const schema = require(path.join(SRC, "schemas", "content-register"));

const NODE_ID = "tip://node/n_email_limits";
const VP_ID = "tip://vp/v1";
const AUTHOR = "tip://id/US-e2e2e2e2e2e2e2e2";
const RECIPIENTS = "5a".repeat(32);
const MSG2 = "This TIP-ID has signed 2 emails this month, all that its plan includes. " +
  "The count starts again on the 1st, or choose a plan with more emails at vp.theailab.org/plans.";

const NOV_10 = Date.UTC(2026, 10, 10, 12);       // 2026-11-10 12:00 UTC
const DEC_1 = Date.UTC(2026, 11, 1);              // 2026-12-01 00:00 UTC

beforeAll(async () => { await initCrypto(); });
afterAll(() => {
  if (_sealsGateBefore === undefined) delete process.env.TIP_EMAIL_SEALS_REQUIRED_ACTIVATION_MS;
  else process.env.TIP_EMAIL_SEALS_REQUIRED_ACTIVATION_MS = _sealsGateBefore;
});
afterEach(() => { jest.restoreAllMocks(); });

const at = (ms) => jest.spyOn(Date, "now").mockReturnValue(ms);
const billing = (answer) => ({ enabled: true, checkDocPages: jest.fn(async () => null), checkEmailSigns: jest.fn(async () => answer) });
const LIMIT_2 = { limit: 2, enforced: true, from: "2026-01-01", month: "2026-11", resets_at: DEC_1 / 1000, upgrade_url: "https://vp.theailab.org/plans#personal" };

function setup({ mediaQuota, signerKp } = {}) {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const authorKp = signerKp || generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  dag.saveIdentity({
    tip_id: AUTHOR, region: "US", public_key: authorKp.publicKey, root_public_key: authorKp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", reviewer_consent: false,
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: AUTHOR }),
  });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, mediaLimits: MEDIA_LIMITS };
  const scoring = initScoring(dag, config);
  dag.setScore(AUTHOR, 700, 0, 1769904000000);
  const submitted = [];
  // As the node does: a submitted tx waits in the mempool until it commits.
  const submitTx = (tx) => { submitted.push(tx); dag.saveMempoolTx(tx); };
  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId: NODE_ID });
  const contentService = createContentService({ dag, scoring, config, submitTx, mediaQuota });
  let round = 0;
  const commit = () => { round += 1; commitHandler.commitOrderedTxs(submitted.splice(0), round, { certTimestamp: nowMs() }); };

  function body({ content, email = true, privKey = authorKp.privateKey } = {}) {
    const fields = {
      origin_code: ORIGIN.OH,
      registered_urls: email ? [] : [`https://example.com/post/${shake256(content).slice(0, 8)}/`],
      extras: email ? { email: { v: 1, recipients: RECIPIENTS } } : {},
      authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR, tip_id_type: "personal" }],
      signer_tip_id: AUTHOR,
      attribution_mode: "self",
    };
    const payload = schema.buildSigningPayload(fields, shake256(tipNormalize(content)));
    return { ...fields, cna_version: schema.CURRENT_CNA_VERSION, content, content_type: "text", signature: schema.sign(payload, privKey) };
  }
  const regTxs = () => submitted.filter((t) => t.tx_type === TX_TYPES.REGISTER_CONTENT);
  return { dag, contentService, submitted, commit, body, regTxs };
}

describe("email sign limits", () => {
  test("at the limit: 429 email_sign_limit with used, limit and reset, before anything is written", async () => {
    const mediaQuota = billing(LIMIT_2);
    const fx = setup({ mediaQuota });
    at(NOV_10);
    await fx.contentService.register(fx.body({ content: "Email one\nHello" }));
    await fx.contentService.register(fx.body({ content: "Email two\nHello" }));
    fx.commit();
    const save = jest.spyOn(fx.dag, "saveMempoolTx");
    const err = await fx.contentService.register(fx.body({ content: "Email three\nHello" })).catch((e) => e);
    expect(err).toEqual({
      status: 429, error: MSG2, code: "email_sign_limit",
      details: { used: 2, limit: 2, resets_at: DEC_1 / 1000, upgrade_url: "https://vp.theailab.org/plans#personal" },
    });
    expect(save).not.toHaveBeenCalled();
    expect(fx.submitted).toEqual([]);
    expect(mediaQuota.checkEmailSigns).toHaveBeenLastCalledWith({ tip_id: AUTHOR });
  });

  test("under the limit: registers", async () => {
    const mediaQuota = billing(LIMIT_2);
    const fx = setup({ mediaQuota });
    at(NOV_10);
    const out = await fx.contentService.register(fx.body({ content: "Only email\nHello" }));
    expect(out.confirmation).toBe("proposed");
    expect(fx.regTxs()).toHaveLength(1);
  });

  test("emails still in the mempool count toward the month", async () => {
    const fx = setup({ mediaQuota: billing(LIMIT_2) });
    at(NOV_10);
    await fx.contentService.register(fx.body({ content: "Pending one\nHello" }));
    await fx.contentService.register(fx.body({ content: "Pending two\nHello" }));
    // Not committed: both wait in the mempool.
    await expect(fx.contentService.register(fx.body({ content: "Pending three\nHello" })))
      .rejects.toMatchObject({ status: 429, code: "email_sign_limit", details: { used: 2, limit: 2 } });
  });

  test("last month's emails do not count, and the count starts again at 00:00 UTC on the 1st", async () => {
    const fx = setup({ mediaQuota: billing(LIMIT_2) });
    at(DEC_1 - 60_000);                                   // 2026-11-30 23:59 UTC
    await fx.contentService.register(fx.body({ content: "November one\nHello" }));
    await fx.contentService.register(fx.body({ content: "November two\nHello" }));
    fx.commit();
    await expect(fx.contentService.register(fx.body({ content: "November three\nHello" })))
      .rejects.toMatchObject({ code: "email_sign_limit" });
    jest.restoreAllMocks();
    at(DEC_1);                                            // 2026-12-01 00:00 UTC
    const out = await fx.contentService.register(fx.body({ content: "December one\nHello" }));
    expect(out.confirmation).toBe("proposed");
  });

  test("posts never count and never ask billing", async () => {
    const mediaQuota = billing({ ...LIMIT_2, limit: 0 });
    const fx = setup({ mediaQuota });
    at(NOV_10);
    const out = await fx.contentService.register(fx.body({ content: "A public post", email: false }));
    expect(out.confirmation).toBe("proposed");
    expect(mediaQuota.checkEmailSigns).not.toHaveBeenCalled();
  });

  test("before the published start date the limit is never applied", async () => {
    const fx = setup({ mediaQuota: billing({ ...LIMIT_2, limit: 0, enforced: false, from: "2026-12-14" }) });
    at(NOV_10);
    const out = await fx.contentService.register(fx.body({ content: "Early email\nHello" }));
    expect(out.confirmation).toBe("proposed");
  });

  test("an unreachable billing service (null answer), a disabled client or an older client lets the email through", async () => {
    at(NOV_10);
    const down = billing(null);
    const disabled = { ...billing({ ...LIMIT_2, limit: 0 }), enabled: false };
    const older = { enabled: true, checkDocPages: jest.fn(async () => null) };   // no checkEmailSigns
    for (const [i, mediaQuota] of [down, disabled, older, null].entries()) {
      const fx = setup({ mediaQuota });
      const out = await fx.contentService.register(fx.body({ content: `Email ${i}\nHello` }));
      expect(out.confirmation).toBe("proposed");
    }
    expect(down.checkEmailSigns).toHaveBeenCalledTimes(1);
    expect(disabled.checkEmailSigns).not.toHaveBeenCalled();
  });

  test("an unsigned request cannot probe the plan: a bad signature is refused before billing is asked", async () => {
    const mediaQuota = billing({ ...LIMIT_2, limit: 0 });
    const fx = setup({ mediaQuota });
    at(NOV_10);
    const other = generateMLDSAKeypair();
    await expect(fx.contentService.register(fx.body({ content: "Forged\nHello", privKey: other.privateKey })))
      .rejects.toMatchObject({ status: 403, code: "signature_invalid" });
    expect(mediaQuota.checkEmailSigns).not.toHaveBeenCalled();
  });
});

// One pool for a licensed organization (node 2.9.10, founder 2026-11-19):
// 5,000 signed emails a month for the organization's TIP-ID and its active
// members together, each member held to 500. Here the pool is 3 and a member 2.
describe("a licensed organization's shared pool", () => {
  const ORG = "tip://id/US-0a0a0a0a0a0a0a0a";
  const OTHER = "tip://id/US-0b0b0b0b0b0b0b0b";
  const GONE = "tip://id/US-0c0c0c0c0c0c0c0c";
  const POOL_3 = { ...LIMIT_2, pool: { org_tip_id: ORG, limit: 3, member_limit: 2 } };
  let n = 0;
  function member(dag, tip, status = "active") {
    n += 1;
    dag.saveOrgMember({
      invite_tx_id: `tx_pool_${n}`, org_tip_id: ORG, member_tip_id: tip, role: "author",
      status, invited_at: NOV_10 - 1000, invited_claim: NOV_10 - 1000, accepted_at: NOV_10 - 500, add_tx_id: `tx_add_${n}`,
      removed_at: status === "removed" ? NOV_10 - 100 : null, remove_tx_id: null, removed_by: null,
    });
  }
  // The month's committed emails of every TIP-ID but the signer, as this node's summary reads them.
  function others(dag, counts) {
    const real = dag.summarizeContent.bind(dag);
    jest.spyOn(dag, "summarizeContent").mockImplementation((q) =>
      q && q.author in counts ? { months: [{ month: "2026-11", emails: counts[q.author] }] } : real(q));
  }

  test("the pool full: 429 email_sign_pool_limit, even with the member under 500", async () => {
    const fx = setup({ mediaQuota: billing(POOL_3) });
    member(fx.dag, AUTHOR); member(fx.dag, OTHER);
    at(NOV_10);
    others(fx.dag, { [ORG]: 2, [OTHER]: 1 });
    const save = jest.spyOn(fx.dag, "saveMempoolTx");
    const err = await fx.contentService.register(fx.body({ content: "Pool email\nHello" })).catch((e) => e);
    expect(err).toEqual({
      status: 429, code: "email_sign_pool_limit",
      error: "This organization has signed 3 emails this month, all that its license includes. The count starts again on the 1st.",
      details: { used: 3, limit: 3, org_tip_id: ORG, resets_at: DEC_1 / 1000, upgrade_url: "https://vp.theailab.org/plans#personal" },
    });
    expect(save).not.toHaveBeenCalled();
  });

  test("room in the pool: registers, and one member may use most of it", async () => {
    const fx = setup({ mediaQuota: billing({ ...POOL_3, pool: { ...POOL_3.pool, limit: 5 } }) });
    member(fx.dag, AUTHOR); member(fx.dag, OTHER);
    at(NOV_10);
    others(fx.dag, { [ORG]: 0, [OTHER]: 0 });
    await fx.contentService.register(fx.body({ content: "First\nHello" }));
    const out = await fx.contentService.register(fx.body({ content: "Second\nHello" }));
    expect(out.confirmation).toBe("proposed");
    // The member's own cap (2) still holds.
    await expect(fx.contentService.register(fx.body({ content: "Third\nHello" })))
      .rejects.toMatchObject({ status: 429, code: "email_sign_limit" });
  });

  test("a removed member's emails do not count toward the pool", async () => {
    const fx = setup({ mediaQuota: billing(POOL_3) });
    member(fx.dag, AUTHOR); member(fx.dag, GONE, "removed");
    at(NOV_10);
    others(fx.dag, { [ORG]: 1, [GONE]: 5 });
    const out = await fx.contentService.register(fx.body({ content: "Counted once\nHello" }));
    expect(out.confirmation).toBe("proposed");
  });

  test("a pool for an organization the signer is not on is ignored", async () => {
    const fx = setup({ mediaQuota: billing(POOL_3) });
    at(NOV_10);
    others(fx.dag, { [ORG]: 99 });
    const out = await fx.contentService.register(fx.body({ content: "Not a member\nHello" }));
    expect(out.confirmation).toBe("proposed");
  });

  test("a malformed pool is ignored", async () => {
    at(NOV_10);
    for (const [i, pool] of [{ org_tip_id: "nope", limit: 0 }, { org_tip_id: ORG, limit: "0" }, { org_tip_id: ORG }, null].entries()) {
      const fx = setup({ mediaQuota: billing({ ...LIMIT_2, pool }) });
      member(fx.dag, AUTHOR);
      others(fx.dag, { [ORG]: 99 });
      const out = await fx.contentService.register(fx.body({ content: `Malformed ${i}\nHello` }));
      expect(out.confirmation).toBe("proposed");
    }
  });
});
