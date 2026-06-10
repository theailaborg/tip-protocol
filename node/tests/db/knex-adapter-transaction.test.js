/**
 * @file tests/db/knex-adapter-transaction.test.js
 * @description Unit tests for KnexAdapter.runInTransaction — C-2 known limitation.
 *
 * runInTransaction is currently a pass-through (`return fn()`). Wrapping in
 * knex.transaction() caused connection-pool exhaustion because the callback's
 * internal _ff() writes also acquire pool connections while the transaction
 * holds one open. True atomicity requires threading `trx` through every write
 * method (TODO C-2).
 *
 * These tests document the current behavior and guard the pass-through contract.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const { KnexAdapter } = require(path.join(SRC, "db", "knex-adapter"));

describe("KnexAdapter.runInTransaction", () => {
  let adapter;
  let realKnex;

  beforeEach(() => {
    adapter = new KnexAdapter("postgres", {
      dbHost: "127.0.0.1",
      dbPort: 5432,
      dbName: "tip_test",
      dbUser: "tip",
      dbPassword: "tip",
      dbPoolMin: 0,
      dbPoolMax: 1,
    });
    realKnex = adapter.knex;
  });

  afterEach(async () => {
    await realKnex.destroy().catch(() => {});
  });

  test("calls fn() directly and returns its result (pass-through)", async () => {
    const sentinel = Symbol("fn-result");
    const fn = jest.fn(() => sentinel);

    const result = adapter.runInTransaction(fn);

    expect(fn).toHaveBeenCalledTimes(1);
    expect(result).toBe(sentinel);
  });

  test("propagates synchronous throw from fn", () => {
    const err = new Error("inner failure");
    expect(() => adapter.runInTransaction(() => { throw err; })).toThrow(err);
  });
});
