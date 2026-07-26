/**
 * @file tests/integration/update-registered-urls.test.js
 * @description End-to-end coverage for the UPDATE_REGISTERED_URLS tx type:
 * an owner FULL-REPLACES the registered_urls array on already-registered
 * content. Mirrors the UPDATE_ORIGIN wiring (owner-signed, ctid-bound
 * signature) but is unlimited and does not mutate content status.
 *
 * Coverage:
 *   1. Owner full-replace → new array lands on the content row (E2E through
 *      the commit-handler apply path)
 *   2. Non-owner → 403 (service business-rule gate)
 *   3. Retracted content → 403 (service business-rule gate)
 *   4. A newly-added url already claimed by another content → dropped at
 *      commit (URL exclusivity, mirrors REGISTER_CONTENT)
 *   5. Signature over the wrong ctid → 403 (replay protection)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, signBody, computeTxId, shake256,
} = require(path.join(SHARED, "crypto"));
const { TX_TYPES, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const contentRegisterSchema = require(path.join(SRC, "schemas", "content-register"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/n1";
const VP_ID = "tip://vp/v1";
const AUTHOR_TIP_ID = "tip://id/US-1111111111111111";
const OTHER_TIP_ID = "tip://id/US-2222222222222222";

function _seedIdentity(dag, tipId, kp) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, 750, 0, 1767225600000);
}

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });

  const authorKp = generateMLDSAKeypair();
  const otherKp = generateMLDSAKeypair();
  _seedIdentity(dag, AUTHOR_TIP_ID, authorKp);
  _seedIdentity(dag, OTHER_TIP_ID, otherKp);

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); dag.addTx(tx); };
  const contentService = createContentService({ dag, scoring, config, submitTx });
  const handler = createCommitHandler({ dag, scoring, config });
  return { dag, scoring, config, contentService, handler, submitted, authorKp, otherKp };
}

// Build + sign a REGISTER_CONTENT tx the commit-handler can re-verify.
function _registerContentTx(fx, { ctid, urls, tag }) {
  const data = {
    ctid, origin_code: "OH", content_hash: shake256(tag),
    signer_tip_id: AUTHOR_TIP_ID, registered_urls: urls,
  };
  data.authors = [{ key_mode: "attribution", role: "byline", signed: false, tip_id: AUTHOR_TIP_ID, tip_id_type: "personal" }];
  data.attribution_mode = "self";
  data.extras = {};
  data.cna_version = contentRegisterSchema.CURRENT_CNA_VERSION;
  const payload = contentRegisterSchema.buildSigningPayload(data, data.content_hash);
  data.signature = contentRegisterSchema.sign(payload, fx.authorKp.privateKey);
  const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1777507200000, prev: fx.dag.getRecentPrev(), data, signature: data.signature };
  tx.tx_id = computeTxId(tx);
  return tx;
}

// Build + sign an UPDATE_REGISTERED_URLS tx. `signCtid` lets a test bind the
// signature to a different ctid than the tx targets (replay probe).
function _updateUrlsTx(fx, { ctid, urls, kp = fx.authorKp, authorTipId = AUTHOR_TIP_ID, signCtid = ctid }) {
  const signature = signBody({ author_tip_id: authorTipId, ctid: signCtid, registered_urls: urls }, kp.privateKey);
  const tx = {
    tx_type: TX_TYPES.UPDATE_REGISTERED_URLS, timestamp: 1777507300000, prev: fx.dag.getRecentPrev(),
    data: { ctid, registered_urls: urls, author_tip_id: authorTipId }, signature,
  };
  tx.tx_id = computeTxId(tx);
  return tx;
}

const CTID_A = "tip://c/OH-aaaaaaaaaaaaaa-0001";
const CTID_B = "tip://c/OH-bbbbbbbbbbbbbb-0002";

// ─── 1. Owner full-replace (E2E through commit-handler apply) ────────────────

describe("UPDATE_REGISTERED_URLS - owner full-replace", () => {
  test("replaces the registered_urls array on the committed content row", () => {
    const fx = _setup();
    const reg = _registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" });
    expect(fx.handler.commitOrderedTxs([reg], 10).committed).toBe(1);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/orig/"]);

    const upd = _updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/new-a/", "https://example.com/new-b"] });
    const res = fx.handler.commitOrderedTxs([upd], 11);
    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(0);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/new-a/", "https://example.com/new-b"]);
    // Status is untouched: UPDATE_REGISTERED_URLS is not a content-status mutator.
    expect(fx.dag.getContent(CTID_A).status).toBe(CONTENT_STATUS.REGISTERED);
  });

  test("unlimited: a second update on the same ctid also commits", () => {
    const fx = _setup();
    const reg = _registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" });
    fx.handler.commitOrderedTxs([reg], 10);
    fx.handler.commitOrderedTxs([_updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/one/"] })], 11);
    fx.handler.commitOrderedTxs([_updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/two/"] })], 12);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/two/"]);
  });
});

// ─── 2. Non-owner rejected ───────────────────────────────────────────────────

describe("UPDATE_REGISTERED_URLS - authorization", () => {
  test("non-owner update → 403 (service gate)", async () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" })], 10);
    const body = {
      author_tip_id: OTHER_TIP_ID,
      registered_urls: ["https://example.com/steal/"],
      signature: signBody({ author_tip_id: OTHER_TIP_ID, ctid: CTID_A, registered_urls: ["https://example.com/steal/"] }, fx.otherKp.privateKey),
    };
    expect(() => fx.contentService.updateRegisteredUrls(CTID_A, body))
      .toThrow(expect.objectContaining({ status: 403, error: expect.stringContaining("Only the content author") }));
  });

  test("non-owner update dropped at commit too (gossip bypass)", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" })], 10);
    const tx = _updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/steal/"], kp: fx.otherKp, authorTipId: OTHER_TIP_ID });
    const res = fx.handler.commitOrderedTxs([tx], 11);
    expect(res.committed).toBe(0);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/orig/"]);
  });
});

// ─── 3. Retracted / disputed content rejected ────────────────────────────────

describe("UPDATE_REGISTERED_URLS - content status gate", () => {
  test("update on retracted content → 403", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" })], 10);
    fx.dag.updateContentStatus(CTID_A, CONTENT_STATUS.RETRACTED);
    const body = {
      author_tip_id: AUTHOR_TIP_ID,
      registered_urls: ["https://example.com/new/"],
      signature: signBody({ author_tip_id: AUTHOR_TIP_ID, ctid: CTID_A, registered_urls: ["https://example.com/new/"] }, fx.authorKp.privateKey),
    };
    expect(() => fx.contentService.updateRegisteredUrls(CTID_A, body))
      .toThrow(expect.objectContaining({ status: 403, error: expect.stringContaining("content status is 'retracted'") }));
  });

  test("update on disputed content → 403", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" })], 10);
    fx.dag.updateContentStatus(CTID_A, CONTENT_STATUS.DISPUTED);
    const body = {
      author_tip_id: AUTHOR_TIP_ID,
      registered_urls: ["https://example.com/new/"],
      signature: signBody({ author_tip_id: AUTHOR_TIP_ID, ctid: CTID_A, registered_urls: ["https://example.com/new/"] }, fx.authorKp.privateKey),
    };
    expect(() => fx.contentService.updateRegisteredUrls(CTID_A, body))
      .toThrow(expect.objectContaining({ status: 403, error: expect.stringContaining("content status is 'disputed'") }));
  });

  test("empty registered_urls → 400 registered_urls_required; a 1+ url update succeeds", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" })], 10);
    const emptyBody = {
      author_tip_id: AUTHOR_TIP_ID,
      registered_urls: [],
      signature: signBody({ author_tip_id: AUTHOR_TIP_ID, ctid: CTID_A, registered_urls: [] }, fx.authorKp.privateKey),
    };
    expect(() => fx.contentService.updateRegisteredUrls(CTID_A, emptyBody))
      .toThrow(expect.objectContaining({ status: 400, code: "registered_urls_required" }));

    const okRes = fx.handler.commitOrderedTxs([_updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/one/"] })], 11);
    expect(okRes.committed).toBe(1);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/one/"]);
  });

  test("empty registered_urls dropped at commit too", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" })], 10);
    const res = fx.handler.commitOrderedTxs([_updateUrlsTx(fx, { ctid: CTID_A, urls: [] })], 11);
    expect(res.committed).toBe(0);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/orig/"]);
  });

  test("VERIFIED content can be updated", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" })], 10);
    fx.dag.updateContentStatus(CTID_A, CONTENT_STATUS.VERIFIED);
    const res = fx.handler.commitOrderedTxs([_updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/verified-add/"] })], 11);
    expect(res.committed).toBe(1);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/verified-add/"]);
  });
});

// ─── 4. URL exclusivity for newly-added urls ─────────────────────────────────

describe("UPDATE_REGISTERED_URLS - url exclusivity", () => {
  test("adding a url already live-claimed by another content is dropped at commit", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/a/"], tag: "c-a" })], 10);
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_B, urls: ["https://example.com/shared/"], tag: "c-b" })], 11);

    // Content A tries to add content B's url.
    const tx = _updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/a/", "https://example.com/shared/"] });
    const res = fx.handler.commitOrderedTxs([tx], 12);
    expect(res.committed).toBe(0);
    expect(res.dropped).toBe(1);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/a/"]);
  });

  test("a register claiming a url an earlier in-batch update just added is dropped", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/a/"], tag: "c-a" })], 10);

    // Same batch, update first: its url is not committed yet, so only the
    // register's in-batch scan can stop the url binding to two CTIDs.
    const upd = _updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/a/", "https://example.com/contested/"] });
    const reg = _registerContentTx(fx, { ctid: CTID_B, urls: ["https://example.com/contested/"], tag: "c-b" });
    const res = fx.handler.commitOrderedTxs([upd, reg], 11);

    expect(res.committed).toBe(1);
    expect(res.dropped).toBe(1);
    expect(fx.dag.getContent(CTID_A).registered_urls).toContain("https://example.com/contested/");
    expect(fx.dag.getContent(CTID_B)).toBeNull();
  });

  test("keeping a url already owned by this content (not newly-added) still commits", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/a/"], tag: "c-a" })], 10);
    // Re-declares its own url plus a brand-new one: neither is claimed elsewhere.
    const res = fx.handler.commitOrderedTxs([_updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/a/", "https://example.com/a2/"] })], 11);
    expect(res.committed).toBe(1);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/a/", "https://example.com/a2/"]);
  });
});

// ─── 5. Signature bound to the ctid (replay protection) ──────────────────────

describe("UPDATE_REGISTERED_URLS - signature is ctid-bound", () => {
  test("signature over a different ctid → 403 (service gate)", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" })], 10);
    const urls = ["https://example.com/new/"];
    const body = {
      author_tip_id: AUTHOR_TIP_ID,
      registered_urls: urls,
      // Signed over CTID_B, submitted against CTID_A.
      signature: signBody({ author_tip_id: AUTHOR_TIP_ID, ctid: CTID_B, registered_urls: urls }, fx.authorKp.privateKey),
    };
    expect(() => fx.contentService.updateRegisteredUrls(CTID_A, body))
      .toThrow(expect.objectContaining({ status: 403, code: "signature_invalid" }));
  });

  test("signature over a different ctid → dropped at commit", () => {
    const fx = _setup();
    fx.handler.commitOrderedTxs([_registerContentTx(fx, { ctid: CTID_A, urls: ["https://example.com/orig/"], tag: "c-a" })], 10);
    const tx = _updateUrlsTx(fx, { ctid: CTID_A, urls: ["https://example.com/new/"], signCtid: CTID_B });
    const res = fx.handler.commitOrderedTxs([tx], 11);
    expect(res.committed).toBe(0);
    expect(fx.dag.getContent(CTID_A).registered_urls).toEqual(["https://example.com/orig/"]);
  });
});
