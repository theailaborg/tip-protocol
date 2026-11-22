/**
 * @file tests/db/knex-adapter-domain-attestations.test.js
 * @description domain_attestations through the KnexAdapter (the Postgres path):
 * a newer attestation from the same node replaces the row in the DB, the parity
 * probe agrees, and a restart hydrates the rows and the state root.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const { KnexAdapter } = require("../../src/db/knex-adapter");
const { computeStateMerkleRoot } = require("../../src/consensus/state-root");

const logStub = { info() { }, warn() { }, error() { } };
const T0 = 1794672650000;
const att = (node, verifiedAt, txChar) => ({
  domain: "a.example", node_id: node, tip_id: "tip://id/US-aaaaaaaaaaaaaaaa", claimed_at: T0,
  claimed_method: "dns", verified_at: verifiedAt, tx_id: txChar.repeat(64),
});

describe("domain_attestations on the KnexAdapter", () => {
  let tmpDir, dbFile, a;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-att-"));
    dbFile = path.join(tmpDir, "att.db");
    a = new KnexAdapter("better-sqlite3", { dbName: dbFile }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { a.close(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("a newer attestation from the same node replaces its row in the DB", async () => {
    a.saveDomainAttestation(att("tip://node/n1", T0 + 10, "1"));
    a.saveDomainAttestation(att("tip://node/n2", T0 + 20, "2"));
    a.saveDomainAttestation(att("tip://node/n1", T0 + 30, "3"));
    await a.flush();
    const rows = await a.knex("domain_attestations").orderBy("node_id").select("*");
    expect(rows.map(r => [r.node_id, Number(r.verified_at), r.tx_id])).toEqual([
      ["tip://node/n1", T0 + 30, "3".repeat(64)],
      ["tip://node/n2", T0 + 20, "2".repeat(64)],
    ]);
    expect(a.listDomainAttestations("a.example").map(r => r.node_id)).toEqual(["tip://node/n1", "tip://node/n2"]);
  });

  test("parity probe agrees on domain_attestations row counts", async () => {
    await a._ffChain;
    const exit = jest.spyOn(process, "exit").mockImplementation(() => { throw new Error("exit called"); });
    try {
      expect(a._paritySnapshot().domain_attestations).toBe(2);
      a._enqueueParityProbe();
      await a._ffChain;
      expect(exit).not.toHaveBeenCalled();
    } finally {
      exit.mockRestore();
    }
  });

  test("rows and the state root survive an adapter restart", async () => {
    await a.flush();
    const rootBefore = computeStateMerkleRoot(a);
    a.close();
    const b = new KnexAdapter("better-sqlite3", { dbName: dbFile }, logStub);
    await b.migrate();
    try {
      expect(b.getDomainAttestation("a.example", "tip://node/n1")).toEqual(att("tip://node/n1", T0 + 30, "3"));
      expect(computeStateMerkleRoot(b)).toBe(rootBefore);
    } finally {
      b.close();
    }
    a = new KnexAdapter("better-sqlite3", { dbName: dbFile }, logStub);
    await a.migrate();
  });
});
