/**
 * @file tests/jury-consent.test.js
 * @description Adjudication opt-in gate on jury and expert selection.
 *
 * Coverage map:
 *   1. selectJury excludes identities without reviewer_consent — the
 *      "I want to help adjudicate" toggle gates juror seats, not just
 *      reviewer assignments. Drafting non-consenting users seats
 *      unaware panelists and bleeds their score via no-commit
 *      penalties.
 *   2. consent === 1 (legacy numeric column value) is accepted, same
 *      contract as reviewer-selection.
 *   3. An all-non-consenting pool yields insufficient:true instead of
 *      drafting anyone — consent is a hard filter, never relaxed by
 *      the score/geo cascade.
 *   4. selectExperts applies the same gate.
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
