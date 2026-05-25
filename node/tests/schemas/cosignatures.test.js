/**
 * @file tests/schemas/cosignatures.test.js
 * @description Direct unit tests for the cosignatures dispatcher helpers
 * in `schemas/_common.js` — exercises verifyCosignatures across success
 * + every error mode, plus sortCosignatures canonical ordering and the
 * signCosignature / verifyCosignatures round-trip.
 *
 * Schema-specific cosignature usage is covered in the per-tx_type
 * schema tests (bind-domain, etc). This file is layer-agnostic: pass a
 * synthetic tx + a fake dag and assert the dispatcher's return shape.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair,
} = require(path.join(SHARED, "crypto"));
const { SIGNED_BY_KIND } = require(path.join(SHARED, "constants"));
const {
  verifyCosignatures, sortCosignatures, signCosignature,
} = require(path.join(SRC, "schemas", "_common"));

beforeAll(async () => { await initCrypto(); });

const TIP_A = "tip://id/US-aaaaaaaaaaaaaaaa";
const TIP_B = "tip://id/US-bbbbbbbbbbbbbbbb";
const NODE_A = "tip://node/aaa";
const NODE_B = "tip://node/bbb";
const VP_A = "tip://vp/US-vp-aaaaaaaaaaaa";

// Fake dag mirroring the production lookup shape: getKeyValidAt /
// getActiveKey return {public_key, algorithm} or null.
function _fakeDag({ identities = {}, nodes = {}, vps = {} } = {}) {
  const lookup = (entity_type, entity_id) => {
    const map = entity_type === "node" ? nodes
      : entity_type === "vp" ? vps
        : identities;
    const rec = map[entity_id];
    return rec ? { public_key: rec.public_key, algorithm: rec.algorithm || "ml-dsa-65" } : null;
  };
  return {
    getActiveKey: lookup,
    getKeyValidAt: (entity_type, entity_id, _ts) => lookup(entity_type, entity_id),
  };
}

const TIMESTAMP = 1778580000000;

// ─── verifyCosignatures — empty / shape errors ─────────────────────────────

describe("verifyCosignatures — empty contract", () => {
  test("empty contract array returns ok regardless of tx.data.cosignatures", () => {
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [{ signer_kind: "subject", signer_ref: TIP_A, signature: "ab" }] } };
    expect(verifyCosignatures(tx, [], _fakeDag()).ok).toBe(true);
  });

  test("null/undefined contract returns ok (defensive)", () => {
    const tx = { timestamp: TIMESTAMP, data: {} };
    expect(verifyCosignatures(tx, null, _fakeDag()).ok).toBe(true);
    expect(verifyCosignatures(tx, undefined, _fakeDag()).ok).toBe(true);
  });
});

describe("verifyCosignatures — shape errors", () => {
  test("missing tx.data.cosignatures → cosignatures_missing", () => {
    const tx = { timestamp: TIMESTAMP, data: {} };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body: { foo: "bar" } }];
    const r = verifyCosignatures(tx, contract, _fakeDag());
    expect(r).toMatchObject({ ok: false, code: "cosignatures_missing" });
  });

  test("non-array tx.data.cosignatures → cosignatures_missing", () => {
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: "not-an-array" } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body: {} }];
    const r = verifyCosignatures(tx, contract, _fakeDag());
    expect(r).toMatchObject({ ok: false, code: "cosignatures_missing" });
  });

  test("length mismatch (contract=2, cosigs=1) → cosignatures_length_mismatch", () => {
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [{ signer_kind: "subject", signer_ref: TIP_A, signature: "ab" }] } };
    const contract = [
      { kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body: {} },
      { kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_B, body: {} },
    ];
    const r = verifyCosignatures(tx, contract, _fakeDag());
    expect(r).toMatchObject({ ok: false, code: "cosignatures_length_mismatch" });
  });

  test("unknown signer_kind in contract → cosignature_kind_invalid", () => {
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [{ signer_kind: "alien", signer_ref: TIP_A, signature: "ab" }] } };
    const contract = [{ kind: "alien", ref: TIP_A, body: {} }];
    const r = verifyCosignatures(tx, contract, _fakeDag());
    expect(r).toMatchObject({ ok: false, code: "cosignature_kind_invalid" });
  });

  test("no matching cosignature entry for contract (kind, ref) → cosignature_missing", () => {
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [{ signer_kind: "subject", signer_ref: TIP_B, signature: "ab" }] } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body: {} }];
    const kp = generateMLDSAKeypair();
    const dag = _fakeDag({ identities: { [TIP_A]: { public_key: kp.publicKey } } });
    const r = verifyCosignatures(tx, contract, dag);
    expect(r).toMatchObject({ ok: false, code: "cosignature_missing" });
  });

  test("empty signature string on matched entry → cosignature_invalid", () => {
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [{ signer_kind: "subject", signer_ref: TIP_A, signature: "" }] } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body: {} }];
    const kp = generateMLDSAKeypair();
    const dag = _fakeDag({ identities: { [TIP_A]: { public_key: kp.publicKey } } });
    const r = verifyCosignatures(tx, contract, dag);
    expect(r).toMatchObject({ ok: false, code: "cosignature_invalid" });
  });
});

// ─── verifyCosignatures — signer resolution ────────────────────────────────

describe("verifyCosignatures — signer resolution", () => {
  test("cosigner not registered → cosigner_unknown", () => {
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [{ signer_kind: "subject", signer_ref: TIP_A, signature: "ab".repeat(8) }] } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body: { x: 1 } }];
    const dag = _fakeDag({ identities: {} });   // TIP_A not in DAG
    const r = verifyCosignatures(tx, contract, dag);
    expect(r).toMatchObject({ ok: false, code: "cosigner_unknown" });
  });

  test("dag with neither getKeyValidAt nor getActiveKey → cosigner_unknown", () => {
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [{ signer_kind: "subject", signer_ref: TIP_A, signature: "ab".repeat(8) }] } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body: { x: 1 } }];
    const r = verifyCosignatures(tx, contract, {});
    expect(r).toMatchObject({ ok: false, code: "cosigner_unknown" });
  });

  test("dag without getKeyValidAt falls back to getActiveKey", () => {
    const kp = generateMLDSAKeypair();
    const body = { x: 1 };
    const sig = signCosignature(body, kp.privateKey, SIGNED_BY_KIND.SUBJECT, TIP_A).signature;
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [{ signer_kind: "subject", signer_ref: TIP_A, signature: sig }] } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body }];
    const dag = {
      getActiveKey: (et, id) => et === "identity" && id === TIP_A ? { public_key: kp.publicKey } : null,
    };
    expect(verifyCosignatures(tx, contract, dag).ok).toBe(true);
  });

  test("missing timestamp falls back to active key lookup", () => {
    const kp = generateMLDSAKeypair();
    const body = { x: 1 };
    const sig = signCosignature(body, kp.privateKey, SIGNED_BY_KIND.SUBJECT, TIP_A).signature;
    const tx = { /* no timestamp */ data: { cosignatures: [{ signer_kind: "subject", signer_ref: TIP_A, signature: sig }] } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body }];
    const dag = _fakeDag({ identities: { [TIP_A]: { public_key: kp.publicKey } } });
    expect(verifyCosignatures(tx, contract, dag).ok).toBe(true);
  });
});

// ─── verifyCosignatures — happy paths ──────────────────────────────────────

describe("verifyCosignatures — happy paths", () => {
  test("single subject cosignature verifies", () => {
    const kp = generateMLDSAKeypair();
    const body = { author_tip_id: TIP_A, ctid: "ct1", review_id: "rv1" };
    const entry = signCosignature(body, kp.privateKey, SIGNED_BY_KIND.SUBJECT, TIP_A);
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [entry] } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body }];
    const dag = _fakeDag({ identities: { [TIP_A]: { public_key: kp.publicKey } } });
    expect(verifyCosignatures(tx, contract, dag)).toEqual({ ok: true });
  });

  test("multiple cosigners (mixed kinds) verify; contract-order independent", () => {
    const kpSub = generateMLDSAKeypair();
    const kpNode = generateMLDSAKeypair();
    const kpVp = generateMLDSAKeypair();
    const bodySub = { kind: "sub" };
    const bodyNode = { kind: "node" };
    const bodyVp = { kind: "vp" };
    const eSub = signCosignature(bodySub, kpSub.privateKey, SIGNED_BY_KIND.SUBJECT, TIP_A);
    const eNode = signCosignature(bodyNode, kpNode.privateKey, SIGNED_BY_KIND.NODE, NODE_A);
    const eVp = signCosignature(bodyVp, kpVp.privateKey, SIGNED_BY_KIND.VP, VP_A);
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: sortCosignatures([eSub, eNode, eVp]) } };
    // Contract order intentionally different from wire order to prove
    // matching is by (kind, ref) not by index.
    const contract = [
      { kind: SIGNED_BY_KIND.VP, ref: VP_A, body: bodyVp },
      { kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body: bodySub },
      { kind: SIGNED_BY_KIND.NODE, ref: NODE_A, body: bodyNode },
    ];
    const dag = _fakeDag({
      identities: { [TIP_A]: { public_key: kpSub.publicKey } },
      nodes: { [NODE_A]: { public_key: kpNode.publicKey } },
      vps: { [VP_A]: { public_key: kpVp.publicKey } },
    });
    expect(verifyCosignatures(tx, contract, dag)).toEqual({ ok: true });
  });

  test("tampered body (signer signed body B, verifier checks body C) → cosignature_invalid", () => {
    const kp = generateMLDSAKeypair();
    const realBody = { x: 1 };
    const tamperedBody = { x: 2 };
    const entry = signCosignature(realBody, kp.privateKey, SIGNED_BY_KIND.SUBJECT, TIP_A);
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [entry] } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body: tamperedBody }];
    const dag = _fakeDag({ identities: { [TIP_A]: { public_key: kp.publicKey } } });
    expect(verifyCosignatures(tx, contract, dag)).toMatchObject({ ok: false, code: "cosignature_invalid" });
  });

  test("signature from wrong key (right tip_id but unrelated kp) → cosignature_invalid", () => {
    const real = generateMLDSAKeypair();
    const wrong = generateMLDSAKeypair();
    const body = { x: 1 };
    const entry = signCosignature(body, wrong.privateKey, SIGNED_BY_KIND.SUBJECT, TIP_A);
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [entry] } };
    const contract = [{ kind: SIGNED_BY_KIND.SUBJECT, ref: TIP_A, body }];
    const dag = _fakeDag({ identities: { [TIP_A]: { public_key: real.publicKey } } });
    expect(verifyCosignatures(tx, contract, dag)).toMatchObject({ ok: false, code: "cosignature_invalid" });
  });
});

// ─── sortCosignatures — canonical order ────────────────────────────────────

describe("sortCosignatures", () => {
  test("sorts by (signer_kind, signer_ref) ASC", () => {
    const input = [
      { signer_kind: "subject", signer_ref: TIP_B, signature: "b" },
      { signer_kind: "node", signer_ref: NODE_B, signature: "d" },
      { signer_kind: "subject", signer_ref: TIP_A, signature: "a" },
      { signer_kind: "node", signer_ref: NODE_A, signature: "c" },
    ];
    const sorted = sortCosignatures(input);
    // node < subject lexicographically; within each, refs sort ASC.
    expect(sorted.map(c => [c.signer_kind, c.signer_ref])).toEqual([
      ["node", NODE_A],
      ["node", NODE_B],
      ["subject", TIP_A],
      ["subject", TIP_B],
    ]);
  });

  test("idempotent on already-sorted input", () => {
    const sorted = [
      { signer_kind: "node", signer_ref: NODE_A, signature: "a" },
      { signer_kind: "subject", signer_ref: TIP_A, signature: "b" },
    ];
    expect(sortCosignatures(sorted)).toEqual(sorted);
  });

  test("non-array input returns empty array (defensive)", () => {
    expect(sortCosignatures(null)).toEqual([]);
    expect(sortCosignatures(undefined)).toEqual([]);
    expect(sortCosignatures("nope")).toEqual([]);
  });

  test("does not mutate input", () => {
    const input = [
      { signer_kind: "subject", signer_ref: TIP_B, signature: "b" },
      { signer_kind: "subject", signer_ref: TIP_A, signature: "a" },
    ];
    const snapshot = JSON.parse(JSON.stringify(input));
    sortCosignatures(input);
    expect(input).toEqual(snapshot);
  });
});

// ─── signCosignature — output shape ────────────────────────────────────────

describe("signCosignature", () => {
  test("produces {signer_kind, signer_ref, signature} triplet", () => {
    const kp = generateMLDSAKeypair();
    const entry = signCosignature({ x: 1 }, kp.privateKey, SIGNED_BY_KIND.SUBJECT, TIP_A);
    expect(Object.keys(entry).sort()).toEqual(["signature", "signer_kind", "signer_ref"]);
    expect(entry.signer_kind).toBe("subject");
    expect(entry.signer_ref).toBe(TIP_A);
    expect(typeof entry.signature).toBe("string");
    expect(entry.signature.length).toBeGreaterThan(100);
  });

  test("round-trips with verifyCosignatures", () => {
    const kp = generateMLDSAKeypair();
    const body = { foo: "bar", n: 42 };
    const entry = signCosignature(body, kp.privateKey, SIGNED_BY_KIND.NODE, NODE_A);
    const tx = { timestamp: TIMESTAMP, data: { cosignatures: [entry] } };
    const contract = [{ kind: SIGNED_BY_KIND.NODE, ref: NODE_A, body }];
    const dag = _fakeDag({ nodes: { [NODE_A]: { public_key: kp.publicKey } } });
    expect(verifyCosignatures(tx, contract, dag)).toEqual({ ok: true });
  });
});
