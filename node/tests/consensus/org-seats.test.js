/**
 * @file tests/consensus/org-seats.test.js
 * @description Team seats after the seat-ceiling activation. Two layers:
 * consensus enforces one fixed ceiling every node agrees on
 * (ORG_MEMBERS.MAX_MEMBER_LIMIT), and the API admits invites and acceptances
 * only within the org's allowance from the operator's billing service
 * (seat-allowance-client.js), ORG_MEMBERS.FREE_MEMBER_LIMIT without one.
 */
"use strict";

// Activated long ago, so every scenario below runs under the new ceiling.
// Must be set before _org-members loads.
const ACTIVATED_AT = 1_000_000_000_000;
process.env.TIP_ORG_SEATS_ACTIVATION_MS = String(ACTIVATED_AT);

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, computeTxId } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TX_TYPES, ORG_MEMBERS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createOrgMemberService } = require(path.join(SRC, "services", "org-member-service"));
const { createSeatAllowanceClient } = require(path.join(SRC, "services", "seat-allowance-client"));
const roster = require(path.join(SRC, "schemas", "_org-members"));
const invitedSchema = require(path.join(SRC, "schemas", "org-member-invited"));
const addedSchema = require(path.join(SRC, "schemas", "org-member-added"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-org-seats";
const ORG = "tip://id/GB-400d3636845c06f2";
const PEOPLE = Array.from({ length: 8 }, (_, i) => `tip://id/IN-${String(i + 1).padStart(16, "a")}`);
const BASE_TS = 1767225600000;
const UPGRADE = "https://vp.theailab.org/plans#team";

let round = 0;
let ts = nowMs() - 300_000;
const next = () => (ts += 1000);

function setup({ seatAllowance, holdCommits } = {}) {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const keys = {};
  for (const id of [ORG, ...PEOPLE]) keys[id] = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey, status: "active", registered_at: BASE_TS });
  for (const id of [ORG, ...PEOPLE]) {
    dag.saveIdentity({
      tip_id: id, region: id.slice(9, 11), public_key: keys[id].publicKey, root_public_key: "00",
      vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
      tip_id_type: id === ORG ? "organization" : "personal", registered_at: BASE_TS,
      tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: id }),
    });
    dag.setScore(id, 500, 0, BASE_TS);
  }
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, orgMembersActivationMs: 0 };
  const handler = createCommitHandler({ dag, scoring: initScoring(dag, config), config });
  // The service relays straight into consensus, so API admission and commit run together.
  // holdCommits: relayed txs wait in a queue (as in a real mempool) until flush().
  const queued = [];
  const submitTx = (tx) => (holdCommits ? queued.push(tx) : handler.commitOrderedTxs([tx], ++round));
  const flush = () => { const txs = queued.splice(0); for (const tx of txs) handler.commitOrderedTxs([tx], ++round); return txs.length; };
  const service = createOrgMemberService({ dag, config, submitTx, seatAllowance });
  return { dag, keys, handler, service, flush, queued };
}

const signed = (schema, data, key) => ({ ...data, signature: schema.sign(schema.buildSigningPayload(data), key.privateKey) });
const inviteBody = (ctx, member, at) =>
  signed(invitedSchema, { org_tip_id: ORG, member_tip_id: member, role: "author", invited_at: at }, ctx.keys[ORG]);
const acceptBody = (ctx, member, inviteTxId, at) =>
  signed(addedSchema, { org_tip_id: ORG, member_tip_id: member, invite_tx_id: inviteTxId, accepted_at: at }, ctx.keys[member]);

async function invite(ctx, member) {
  return ctx.service.invite({ urlTipId: ORG, body: inviteBody(ctx, member, next()) });
}
async function accept(ctx, member, inviteTxId) {
  return ctx.service.accept({ urlTipId: member, body: acceptBody(ctx, member, inviteTxId, next()) });
}
async function join(ctx, member) {
  const inv = await invite(ctx, member);
  return accept(ctx, member, inv.invite_tx_id);
}
async function refusal(promise) {
  try { await promise; return null; } catch (e) { return e; }
}
function fakeAllowance(answer) {
  return { calls: 0, async allowanceFor() { this.calls++; return answer; }, peek() { return answer; } };
}

describe("consensus ceiling: one fixed number every node agrees on", () => {
  test("1 before the activation, MAX_MEMBER_LIMIT from it, decided by the tx time only", () => {
    expect(ORG_MEMBERS.LEGACY_MEMBER_LIMIT).toBe(1);
    expect(ORG_MEMBERS.FREE_MEMBER_LIMIT).toBe(2);
    expect(ORG_MEMBERS.MAX_MEMBER_LIMIT).toBe(250);
    expect(roster.memberLimit(null, ORG, ACTIVATED_AT - 1)).toBe(1);
    expect(roster.memberLimit(null, ORG, ACTIVATED_AT)).toBe(250);
    expect(roster.openInviteLimit(null, ORG, ACTIVATED_AT)).toBe(250 * ORG_MEMBERS.OPEN_INVITE_MULTIPLIER);
    expect(roster.dayInviteLimit(null, ORG, ACTIVATED_AT - 1)).toBe(ORG_MEMBERS.INVITES_PER_DAY_MULTIPLIER);
  });

  test("the ceiling is not a plan: a third member commits when no API policy stands in front", () => {
    const ctx = setup();
    for (const member of PEOPLE.slice(0, 3)) {
      const at = next();
      const body = inviteBody(ctx, member, at);
      const { signature, ...data } = body;
      const inv = { tx_type: TX_TYPES.ORG_MEMBER_INVITED, timestamp: at, signature, prev: [], data };
      inv.prev = ctx.dag.prevFor(inv.tx_type, inv.data); inv.tx_id = computeTxId(inv);
      expect(ctx.handler.commitOrderedTxs([inv], ++round)).toMatchObject({ committed: 1 });
      const at2 = next();
      const ab = acceptBody(ctx, member, inv.tx_id, at2);
      const { signature: s2, ...d2 } = ab;
      const add = { tx_type: TX_TYPES.ORG_MEMBER_ADDED, timestamp: at2, signature: s2, prev: [], data: d2 };
      add.prev = ctx.dag.prevFor(add.tx_type, add.data); add.tx_id = computeTxId(add);
      expect(ctx.handler.commitOrderedTxs([add], ++round)).toMatchObject({ committed: 1 });
    }
    expect(roster.activeMembers(ctx.dag, ORG)).toHaveLength(3);
  });
});

describe("free: 2 team members, no billing service needed", () => {
  test("two people join; the third invite is refused with the plan and where to upgrade", async () => {
    const ctx = setup();
    await join(ctx, PEOPLE[0]);
    await join(ctx, PEOPLE[1]);
    const e = await refusal(invite(ctx, PEOPLE[2]));
    expect(e).toMatchObject({ status: 409, code: "member_limit_reached", details: { limit: 2, plan: "free" } });
    expect(roster.activeMembers(ctx.dag, ORG)).toHaveLength(2);
    expect(await ctx.service.listMembers(ORG)).toMatchObject({ limit: 2, plan: "free", upgrade_url: null });
  });

  test("invites wait without taking a seat, but the third acceptance is refused", async () => {
    const ctx = setup();
    const invs = [];
    for (const p of PEOPLE.slice(0, 3)) invs.push(await invite(ctx, p));
    await accept(ctx, PEOPLE[0], invs[0].invite_tx_id);
    await accept(ctx, PEOPLE[1], invs[1].invite_tx_id);
    const e = await refusal(accept(ctx, PEOPLE[2], invs[2].invite_tx_id));
    expect(e).toMatchObject({ code: "member_limit_reached", details: { limit: 2 } });
    expect(roster.activeMembers(ctx.dag, ORG)).toHaveLength(2);
  });

  test("open invites are capped at three per seat", async () => {
    const ctx = setup();
    for (const p of PEOPLE.slice(0, 6)) await invite(ctx, p);
    const e = await refusal(invite(ctx, PEOPLE[6]));
    expect(e).toMatchObject({ code: "invite_limit_reached" });
  });
});

describe("paid seats come from the operator's billing service", () => {
  test("a Team 5 org fills 5 seats; the sixth is refused with the upgrade link", async () => {
    const seats = fakeAllowance({ limit: 5, plan: "team_5_monthly", upgrade_url: UPGRADE });
    const ctx = setup({ seatAllowance: seats });
    for (const p of PEOPLE.slice(0, 5)) await join(ctx, p);
    const e = await refusal(invite(ctx, PEOPLE[5]));
    expect(e).toMatchObject({ code: "member_limit_reached", details: { limit: 5, plan: "team_5_monthly", upgrade_url: UPGRADE } });
    expect(await ctx.service.listMembers(ORG)).toMatchObject({ limit: 5, plan: "team_5_monthly", upgrade_url: UPGRADE });
    expect(seats.calls).toBeGreaterThan(0);
  });

  test("a licence holder gets its allowance, never more than the consensus ceiling", async () => {
    const ctx = setup({ seatAllowance: fakeAllowance({ limit: 10_000, plan: "licence", upgrade_url: UPGRADE }) });
    expect(await ctx.service.listMembers(ORG)).toMatchObject({ limit: ORG_MEMBERS.MAX_MEMBER_LIMIT, plan: "licence" });
  });

  test("a lapsed plan removes nobody; it only stops new members until the team is under the limit", async () => {
    const answer = { limit: 5, plan: "team_5_monthly", upgrade_url: UPGRADE };
    const ctx = setup({ seatAllowance: fakeAllowance(answer) });
    for (const p of PEOPLE.slice(0, 4)) await join(ctx, p);
    Object.assign(answer, { limit: 2, plan: "free" });
    expect(roster.activeMembers(ctx.dag, ORG)).toHaveLength(4);
    expect(await refusal(invite(ctx, PEOPLE[4]))).toMatchObject({ code: "member_limit_reached", details: { limit: 2 } });
  });
});

describe("several people accepting at once cannot overfill a team", () => {
  test("free: 6 open invites, 6 simultaneous accepts, exactly 2 are relayed and committed", async () => {
    const ctx = setup({ holdCommits: true });
    const invs = [];
    for (const p of PEOPLE.slice(0, 6)) { invs.push(await invite(ctx, p)); ctx.flush(); }
    const results = await Promise.all(PEOPLE.slice(0, 6).map((p, i) =>
      accept(ctx, p, invs[i].invite_tx_id).then(() => "ok", (e) => e.code)));
    expect(results.filter((r) => r === "ok")).toHaveLength(2);
    expect(results.filter((r) => r === "member_limit_reached")).toHaveLength(4);
    expect(ctx.flush()).toBe(2);
    expect(roster.activeMembers(ctx.dag, ORG)).toHaveLength(2);
  });

  test("Team 5 with a slow billing service: simultaneous accepts still stop at 5", async () => {
    const slow = { async allowanceFor() { await new Promise((r) => setTimeout(r, 5)); return { limit: 5, plan: "team_5_monthly", upgrade_url: UPGRADE }; },
      peek() { return { limit: 5 }; } };
    const ctx = setup({ seatAllowance: slow, holdCommits: true });
    const invs = [];
    for (const p of PEOPLE) { invs.push(await invite(ctx, p)); ctx.flush(); }
    const results = await Promise.all(PEOPLE.map((p, i) => accept(ctx, p, invs[i].invite_tx_id).then(() => "ok", (e) => e.code)));
    expect(results.filter((r) => r === "ok")).toHaveLength(5);
    ctx.flush();
    expect(roster.activeMembers(ctx.dag, ORG)).toHaveLength(5);
  });

  test("simultaneous invites respect the open-invite cap too", async () => {
    const ctx = setup({ holdCommits: true });
    const results = await Promise.all(PEOPLE.map((p) => invite(ctx, p).then(() => "ok", (e) => e.code)));
    expect(results.filter((r) => r === "ok")).toHaveLength(2 * ORG_MEMBERS.OPEN_INVITE_MULTIPLIER);
    expect(results.filter((r) => r === "invite_limit_reached")).toHaveLength(PEOPLE.length - 6);
  });

  test("a relay that never lands frees its seat after the hold", async () => {
    const ctx = setup({ holdCommits: true });
    const invs = [];
    for (const p of PEOPLE.slice(0, 3)) { invs.push(await invite(ctx, p)); ctx.flush(); }
    await accept(ctx, PEOPLE[0], invs[0].invite_tx_id);
    await accept(ctx, PEOPLE[1], invs[1].invite_tx_id);
    ctx.queued.splice(0);   // both relays lost, never committed
    expect(await refusal(accept(ctx, PEOPLE[2], invs[2].invite_tx_id))).toMatchObject({ code: "member_limit_reached" });
    const later = nowMs() + 121_000;
    const clock = jest.spyOn(Date, "now").mockReturnValue(later);   // past the 120 s hold
    try {
      expect(await refusal(accept(ctx, PEOPLE[2], invs[2].invite_tx_id))).toBeNull();   // the seat is free again
    } finally { clock.mockRestore(); }
  });
});

describe("seat-allowance-client", () => {
  const res = (status, body) => ({ ok: status < 400, status, text: async () => JSON.stringify(body) });
  const quiet = { warn() {} };

  test("disabled without a url and key: every org gets the free limit, no network", async () => {
    let calls = 0;
    const c = createSeatAllowanceClient({ url: "", key: "", fetch: async () => { calls++; }, log: quiet });
    expect(c.enabled).toBe(false);
    expect(await c.allowanceFor(ORG)).toEqual({ limit: 2, plan: "free", upgrade_url: null });
    expect(calls).toBe(0);
  });

  test("asks the billing service with the shared key and the org's TIP-ID", async () => {
    const seen = [];
    const c = createSeatAllowanceClient({ url: "https://vp.example/", key: "k1", log: quiet,
      fetch: async (u, init) => { seen.push({ u, init }); return res(200, { limit: 15, plan: "team_15_monthly", upgrade_url: UPGRADE }); } });
    expect(await c.allowanceFor(ORG)).toEqual({ limit: 15, plan: "team_15_monthly", upgrade_url: UPGRADE });
    expect(seen[0].u).toBe("https://vp.example/api/team-seats/check");
    expect(seen[0].init.method).toBe("POST");
    expect(seen[0].init.headers["X-TIP-Quota-Key"]).toBe("k1");
    expect(JSON.parse(seen[0].init.body)).toEqual({ org_tip_id: ORG });
  });

  test("never below the free limit, and a malformed answer counts as no answer", async () => {
    const answers = [{ limit: 1 }, { limit: "lots" }];
    const c = createSeatAllowanceClient({ url: "https://vp.example", key: "k", log: quiet, now: (() => { let t = 0; return () => (t += 120_000); })(),
      fetch: async () => res(200, answers.shift()) });
    expect((await c.allowanceFor(ORG)).limit).toBe(2);
    expect(await c.allowanceFor(ORG)).toMatchObject({ limit: 2 });   // malformed: last known (the free floor)
  });

  test("an answer is reused for a minute, then asked again", async () => {
    let t = 0, calls = 0;
    const c = createSeatAllowanceClient({ url: "https://vp.example", key: "k", log: quiet, now: () => t,
      fetch: async () => { calls++; return res(200, { limit: 5, plan: "team_5_monthly" }); } });
    await c.allowanceFor(ORG); t += 30_000; await c.allowanceFor(ORG);
    expect(calls).toBe(1);
    t += 31_000; await c.allowanceFor(ORG);
    expect(calls).toBe(2);
  });

  test("an outage never takes seats away: last known answer, else the free limit", async () => {
    let t = 0, up = true;
    const c = createSeatAllowanceClient({ url: "https://vp.example", key: "k", log: quiet, now: () => t,
      fetch: async () => { if (!up) throw new Error("ECONNREFUSED"); return res(200, { limit: 50, plan: "team_50_monthly" }); } });
    await c.allowanceFor(ORG);
    up = false; t += 120_000;
    expect(await c.allowanceFor(ORG)).toMatchObject({ limit: 50, plan: "team_50_monthly" });
    expect(await c.allowanceFor("tip://id/US-0e7db4040667073a")).toEqual({ limit: 2, plan: "free", upgrade_url: null });
    expect(c.peek(ORG).limit).toBe(50);
  });

  test("concurrent callers share one request", async () => {
    let calls = 0;
    const c = createSeatAllowanceClient({ url: "https://vp.example", key: "k", log: quiet,
      fetch: async () => { calls++; await new Promise((r) => setTimeout(r, 5)); return res(200, { limit: 15, plan: "team_15_monthly" }); } });
    const answers = await Promise.all([1, 2, 3, 4].map(() => c.allowanceFor(ORG)));
    expect(calls).toBe(1);
    expect(answers.every((a) => a.limit === 15)).toBe(true);
  });

  test("after a failure it answers from memory for 30 s instead of waiting out the timeout again", async () => {
    let t = 0, calls = 0;
    const c = createSeatAllowanceClient({ url: "https://vp.example", key: "k", log: quiet, now: () => t,
      fetch: async () => { calls++; throw new Error("timeout"); } });
    expect((await c.allowanceFor(ORG)).limit).toBe(2);
    t += 10_000; await c.allowanceFor(ORG);
    expect(calls).toBe(1);
    t += 25_000; await c.allowanceFor(ORG);
    expect(calls).toBe(2);
  });

  test("peek answers at once and refreshes in the background", async () => {
    let calls = 0;
    const c = createSeatAllowanceClient({ url: "https://vp.example", key: "k", log: quiet,
      fetch: async () => { calls++; return res(200, { limit: 50, plan: "team_50_monthly" }); } });
    expect(c.peek(ORG).limit).toBe(2);           // nothing known yet: free, and a refresh starts
    await new Promise((r) => setTimeout(r, 10));
    expect(calls).toBe(1);
    expect(c.peek(ORG).limit).toBe(50);
  });

  test("a 401 or 503 from the billing service is an outage, not a zero", async () => {
    const c = createSeatAllowanceClient({ url: "https://vp.example", key: "bad", log: quiet, fetch: async () => res(401, { detail: "Invalid quota key" }) });
    expect(await c.allowanceFor(ORG)).toEqual({ limit: 2, plan: "free", upgrade_url: null });
  });
});
