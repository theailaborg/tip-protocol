/**
 * @file tests/jury-consent.test.js
 * @description Adjudication opt-in gate on jury and expert selection.
 *
 * Coverage map:
 *   Back-compat (reviewer_consent drives all — pre-issue-#107 identities):
 *   1. selectJury excludes identities without reviewer_consent when
 *      juror_consent is absent (back-compat fallback).
 *   2. consent === 1 (legacy numeric column value) is accepted.
 *   3. All-non-consenting pool → insufficient:true.
 *   4. selectExperts applies the same back-compat gate.
 *
 *   Explicit role consent (issue #107 — dedicated fields):
 *   5. juror_consent=true admits to jury even when reviewer_consent=false.
 *   6. juror_consent=false excludes from jury even when reviewer_consent=true.
 *   7. expert_consent=true admits to expert panel even when reviewer_consent=false.
 *   8. expert_consent=false excludes from expert panel even when reviewer_consent=true.
 *   9. juror_consent gate is independent of expert_consent and vice-versa.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../src");
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { selectJury, selectExperts } = require(path.join(SRC, "jury"));

const AUTHOR = "tip://id/US-aaaaaaaaaaaaaaaa";
const DISPUTER = "tip://id/US-bbbbbbbbbbbbbbbb";
const DISPUTE_TX = "dispute-tx-1";
const APPEAL_TX = "appeal-tx-1";

function _setup({ poolSize = 12, consent = () => true } = {}) {
  const dag = initDAG({ dbPath: ":memory:" });
  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });

  const pool = [];
  for (let i = 0; i < poolSize; i++) {
    const tipId = `tip://id/US-pool${String(i).padStart(12, "0")}`;
    pool.push(tipId);
    dag.saveIdentity({
      tip_id: tipId, region: `R${i % 5}`, status: "active",
      reviewer_consent: consent(tipId, i),
      registered_at: 1767225600000, tx_id: `id:${i}`,
    });
    dag.setScore(tipId, 900, 0, 1767225600000);
  }
  for (const tipId of [AUTHOR, DISPUTER]) {
    dag.saveIdentity({
      tip_id: tipId, region: "US", status: "active", reviewer_consent: true,
      registered_at: 1767225600000, tx_id: `id:${tipId}`,
    });
    dag.setScore(tipId, 900, 0, 1767225600000);
  }
  return { dag, scoring, pool };
}

describe("selectJury — adjudication consent gate", () => {

  test("non-consenting identities are never seated", () => {
    const consenting = new Set();
    const { dag, scoring } = _setup({
      poolSize: 12,
      consent: (tipId, i) => {
        const ok = i % 2 === 0;
        if (ok) consenting.add(tipId);
        return ok;
      },
    });

    const { jurors } = selectJury(dag, scoring, DISPUTE_TX, AUTHOR, DISPUTER);
    expect(jurors.length).toBeGreaterThan(0);
    for (const juror of jurors) {
      expect(consenting.has(juror)).toBe(true);
    }
  });

  test("legacy numeric consent (1) is accepted", () => {
    const { dag, scoring, pool } = _setup({ poolSize: 8, consent: () => 1 });
    const { jurors, insufficient } = selectJury(dag, scoring, DISPUTE_TX, AUTHOR, DISPUTER);
    expect(insufficient).toBe(false);
    expect(jurors.every(j => pool.includes(j))).toBe(true);
  });

  test("an all-non-consenting pool returns insufficient instead of drafting anyone", () => {
    const { dag, scoring } = _setup({ poolSize: 12, consent: () => false });
    const { jurors, insufficient } = selectJury(dag, scoring, DISPUTE_TX, AUTHOR, DISPUTER);
    expect(insufficient).toBe(true);
    expect(jurors).toHaveLength(0);
  });
});

describe("selectExperts — adjudication consent gate", () => {

  test("non-consenting identities are never seated on the expert panel", () => {
    const consenting = new Set();
    const { dag, scoring } = _setup({
      poolSize: 12,
      consent: (tipId, i) => {
        const ok = i % 2 === 0;
        if (ok) consenting.add(tipId);
        return ok;
      },
    });

    const { experts } = selectExperts(dag, scoring, APPEAL_TX, AUTHOR, DISPUTER);
    expect(experts.length).toBeGreaterThan(0);
    for (const expert of experts) {
      expect(consenting.has(expert)).toBe(true);
    }
  });
});

// ── Issue #107 — Explicit role consent fields ──────────────────────────────

describe("selectJury — juror_consent field (issue #107)", () => {

  test("juror_consent=true admits to jury even when reviewer_consent=false", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
    for (let i = 0; i < 12; i++) {
      const tipId = `tip://id/US-juror${String(i).padStart(11, "0")}`;
      dag.saveIdentity({
        tip_id: tipId, region: `R${i % 5}`, status: "active",
        reviewer_consent: false,  // opted out of prescan reviewing
        juror_consent: true,       // but opted into jury duty
        registered_at: 1767225600000, tx_id: `id:${i}`,
      });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    for (const tipId of [AUTHOR, DISPUTER]) {
      dag.saveIdentity({ tip_id: tipId, region: "US", status: "active",
        reviewer_consent: false, registered_at: 1767225600000, tx_id: `id:${tipId}` });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    const { jurors, insufficient } = selectJury(dag, scoring, DISPUTE_TX, AUTHOR, DISPUTER);
    expect(insufficient).toBe(false);
    expect(jurors.length).toBe(7);
  });

  test("juror_consent=false excludes from jury even when reviewer_consent=true", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
    for (let i = 0; i < 12; i++) {
      const tipId = `tip://id/US-xjuror${String(i).padStart(10, "0")}`;
      dag.saveIdentity({
        tip_id: tipId, region: `R${i % 5}`, status: "active",
        reviewer_consent: true,   // opted into prescan reviewing
        juror_consent: false,      // but explicitly opted out of jury
        registered_at: 1767225600000, tx_id: `id:${i}`,
      });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    for (const tipId of [AUTHOR, DISPUTER]) {
      dag.saveIdentity({ tip_id: tipId, region: "US", status: "active",
        reviewer_consent: true, registered_at: 1767225600000, tx_id: `id:${tipId}` });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    const { jurors, insufficient } = selectJury(dag, scoring, DISPUTE_TX, AUTHOR, DISPUTER);
    expect(insufficient).toBe(true);
    expect(jurors).toHaveLength(0);
  });
});

describe("selectExperts — expert_consent field (issue #107)", () => {

  test("expert_consent=true admits to expert panel even when reviewer_consent=false", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
    for (let i = 0; i < 8; i++) {
      const tipId = `tip://id/US-expert${String(i).padStart(10, "0")}`;
      dag.saveIdentity({
        tip_id: tipId, region: `R${i % 5}`, status: "active",
        reviewer_consent: false,
        expert_consent: true,
        registered_at: 1767225600000, tx_id: `id:${i}`,
      });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    for (const tipId of [AUTHOR, DISPUTER]) {
      dag.saveIdentity({ tip_id: tipId, region: "US", status: "active",
        reviewer_consent: false, registered_at: 1767225600000, tx_id: `id:${tipId}` });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    const { experts, insufficient } = selectExperts(dag, scoring, APPEAL_TX, AUTHOR, DISPUTER);
    expect(insufficient).toBe(false);
    expect(experts.length).toBe(5); // expert_panel_size = 5 per genesis.js
  });

  test("expert_consent=false excludes from expert panel even when reviewer_consent=true", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
    for (let i = 0; i < 8; i++) {
      const tipId = `tip://id/US-xexpert${String(i).padStart(9, "0")}`;
      dag.saveIdentity({
        tip_id: tipId, region: `R${i % 5}`, status: "active",
        reviewer_consent: true,
        expert_consent: false,
        registered_at: 1767225600000, tx_id: `id:${i}`,
      });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    for (const tipId of [AUTHOR, DISPUTER]) {
      dag.saveIdentity({ tip_id: tipId, region: "US", status: "active",
        reviewer_consent: true, registered_at: 1767225600000, tx_id: `id:${tipId}` });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    const { experts, insufficient } = selectExperts(dag, scoring, APPEAL_TX, AUTHOR, DISPUTER);
    expect(insufficient).toBe(true);
    expect(experts).toHaveLength(0);
  });

  test("juror_consent and expert_consent are independent", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
    for (let i = 0; i < 12; i++) {
      const tipId = `tip://id/US-mixed${String(i).padStart(11, "0")}`;
      dag.saveIdentity({
        tip_id: tipId, region: `R${i % 5}`, status: "active",
        reviewer_consent: false,
        juror_consent: true,   // juror yes
        expert_consent: false,  // expert no
        registered_at: 1767225600000, tx_id: `id:${i}`,
      });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    for (const tipId of [AUTHOR, DISPUTER]) {
      dag.saveIdentity({ tip_id: tipId, region: "US", status: "active",
        reviewer_consent: false, registered_at: 1767225600000, tx_id: `id:${tipId}` });
      dag.setScore(tipId, 900, 0, 1767225600000);
    }
    const { jurors, insufficient: jInsufficient } = selectJury(dag, scoring, DISPUTE_TX, AUTHOR, DISPUTER);
    expect(jInsufficient).toBe(false);
    expect(jurors.length).toBe(7);

    const { experts, insufficient: eInsufficient } = selectExperts(dag, scoring, APPEAL_TX, AUTHOR, DISPUTER);
    expect(eInsufficient).toBe(true);
    expect(experts).toHaveLength(0);
  });
});
