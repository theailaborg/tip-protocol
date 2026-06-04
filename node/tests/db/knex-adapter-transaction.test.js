/**
 * @file tests/db/knex-adapter-transaction.test.js
 * @description Unit tests for KnexAdapter.runInTransaction — C-2 bug fix.
 *
 * These tests verify that runInTransaction delegates to knex.transaction(fn)
 * rather than calling fn() directly (the pre-fix no-op). A real DB connection
 * is not required: we replace adapter.knex with a stub after construction so
 * the pool never establishes a real connection.
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
      dbPoolMin: 0, // prevents eager connection attempts against a non-existent DB
      dbPoolMax: 1,
    });
    realKnex = adapter.knex;
  });

  afterEach(async () => {
    // Tear down the pool so idle-connection errors don't bleed into other tests.
    await realKnex.destroy().catch(() => {});
  });

  test("delegates to knex.transaction(fn) rather than calling fn() directly", async () => {
    const sentinel = Symbol("trx-result");
    adapter.knex = {
      transaction: jest.fn(() => Promise.resolve(sentinel)),
    };

    const fn = jest.fn();
    const result = await adapter.runInTransaction(fn);

    // With the pre-fix no-op `return fn()`, knex.transaction is never reached.
    // With the fix `return this.knex.transaction(fn)`, it is called with fn.
    expect(adapter.knex.transaction).toHaveBeenCalledTimes(1);
    expect(adapter.knex.transaction).toHaveBeenCalledWith(fn);
    expect(result).toBe(sentinel);
  });

  test("propagates the rejection from knex.transaction to the caller", async () => {
    const dbErr = new Error("DB connection lost");
    adapter.knex = {
      transaction: jest.fn(() => Promise.reject(dbErr)),
    };

    await expect(adapter.runInTransaction(() => {})).rejects.toBe(dbErr);
    expect(adapter.knex.transaction).toHaveBeenCalledTimes(1);
  });
});
