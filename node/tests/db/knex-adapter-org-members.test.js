/**
 * @file tests/db/knex-adapter-org-members.test.js
 * @description org_members through the KnexAdapter, the path mainnet runs
 * (Postgres behind Knex): every write lands in the DB in the mirror's
 * canonical shape, the parity probe agrees, and a restart hydrates the
 * rows back so roster predicates and the state root survive a reboot.
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
const ORG = "tip://id/GB-400d3636845c06f2";
const ALICE = "tip://id/IND-1aeb5ec0aa16cb20";
const T0 = 1791266254000;

function inviteRow(id, member, over = {}) {
  return {
    invite_tx_id: id, org_tip_id: ORG, member_tip_id: member, role: "editor", status: "invited",
    invited_at: T0, invited_claim: T0 - 500, accepted_at: null, add_tx_id: null,
    removed_at: null, remove_tx_id: null, removed_by: null, ...over,
  };
}

describe("org_members on the KnexAdapter", () => {
  let tmpDir, dbFile, a;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-roster-"));
    dbFile = path.join(tmpDir, "roster.db");
    a = new KnexAdapter("better-sqlite3", { dbName: dbFile }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { a.close(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("writes land in the DB in canonical shape; a re-save merges the status change", async () => {
    a.saveOrgMember(inviteRow("inv-1", ALICE));
    a.saveOrgMember(inviteRow("inv-2", "tip://id/US-ed1c6dbddac62443", { invited_claim: null }));
    await a.flush();
    let rows = await a.knex("org_members").orderBy("invite_tx_id").select("*");
    expect(rows.map(r => [r.invite_tx_id, r.status, Number(r.invited_at), r.invited_claim == null ? null : Number(r.invited_claim)]))
      .toEqual([["inv-1", "invited", T0, T0 - 500], ["inv-2", "invited", T0, null]]);

    a.saveOrgMember({ ...a.getOrgMember("inv-1"), status: "active", accepted_at: T0 + 10, add_tx_id: "add-1" });
    await a.flush();
    rows = await a.knex("org_members").where({ invite_tx_id: "inv-1" }).select("*");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ status: "active", add_tx_id: "add-1" });
    expect(Number(rows[0].accepted_at)).toBe(T0 + 10);
    expect(a.getOrgMemberByAddTxId("add-1").invite_tx_id).toBe("inv-1");
    expect(a.getOrgMembersByOrg(ORG)).toHaveLength(2);
    expect(a.getOrgMembersByMember(ALICE).map(r => r.status)).toEqual(["active"]);
  });

  test("parity probe agrees on org_members row counts", async () => {
    await a._ffChain;
    const exit = jest.spyOn(process, "exit").mockImplementation(() => { throw new Error("exit called"); });
    try {
      expect(a._paritySnapshot().org_members).toBe(2);
      a._enqueueParityProbe();
      await a._ffChain;
      expect(exit).not.toHaveBeenCalled();
    } finally {
      exit.mockRestore();
    }
  });

  test("rows and the state root survive an adapter restart (hydration)", async () => {
    await a.flush();
    const rootBefore = computeStateMerkleRoot(a);
    const before = a.getOrgMembersByOrg(ORG).map(r => ({ ...r, invited_at: Number(r.invited_at) }));
    a.close();

    const b = new KnexAdapter("better-sqlite3", { dbName: dbFile }, logStub);
    await b.migrate();
    try {
      expect(b.getOrgMember("inv-1")).toMatchObject({ status: "active", add_tx_id: "add-1", member_tip_id: ALICE });
      expect(Number(b.getOrgMember("inv-1").invited_claim)).toBe(T0 - 500);
      expect(b.getOrgMember("inv-2").invited_claim == null).toBe(true);
      expect(b.getOrgMemberByAddTxId("add-1").invite_tx_id).toBe("inv-1");
      expect(b.getOrgMembersByOrg(ORG).map(r => ({ ...r, invited_at: Number(r.invited_at) }))).toEqual(expect.arrayContaining(before));
      expect(computeStateMerkleRoot(b)).toBe(rootBefore);
      expect(b._paritySnapshot().org_members).toBe(2);
    } finally {
      b.close();
    }
    a = new KnexAdapter("better-sqlite3", { dbName: dbFile }, logStub);
    await a.migrate();
  });

  test("clearCanonicalState and deleteCanonicalRow reach the DB", async () => {
    expect(a.deleteCanonicalRow("org_members", { invite_tx_id: "inv-2" })).toBe(true);
    await a.flush();
    expect(await a.knex("org_members").count({ n: "*" }).first().then(r => Number(r.n))).toBe(1);
    await a.runInTransaction(async () => { a.clearCanonicalState(); });
    await a.flush();
    expect(await a.knex("org_members").count({ n: "*" }).first().then(r => Number(r.n))).toBe(0);
    expect(a.getOrgMembersByOrg(ORG)).toEqual([]);
  });
});
