/**
 * @file tests/dag/sqlite-atomicity.test.js
 * @description Regression tests for C-3 and C-4 from the 2026-06-03 backend audit.
 *
 * C-3: SQLiteStore.addRevocation writes two statements (INSERT revocations +
 *      UPDATE identities) without a db.transaction() wrapper. A crash between
 *      them leaves revocations with the row but the identity still 'active' —
 *      self-healing is impossible.
 *
 * C-4: SQLiteStore._saveActiveEntityKey writes two statements (UPDATE
 *      closeActiveEntityKey + INSERT saveEntityKey) without a db.transaction()
 *      wrapper. A crash between them closes the old key but never opens the new
 *      one — the entity ends up with NO active key and all future signature
 *      verification fails.
 *
 * Test strategy: inject a SQLite trigger (via a second better-sqlite3
 * connection on the same file) that raises ABORT on the SECOND statement of
 * each pair. Without a wrapping transaction the first statement auto-commits
 * before the second fails. With the transaction fix both writes roll back.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path     = require("path");
const os       = require("os");
const Database = require("better-sqlite3");

const SRC    = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

const { initDAG }     = require(path.join(SRC, "dag"));

// ── Helpers ────────────────────────────────────────────────────────────────

function makeTmpDbPath() {
  return path.join(os.tmpdir(), `tip-atomicity-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
}

// Minimal identity record — SQLiteStore.saveIdentity handles all defaults.
function _identity(tip_id) {
  return {
    tip_id,
    region: "US",
    public_key: "pk_initial_0000000000000000",
    algorithm: "ml-dsa-65",
    registered_at: 1_000,
    tx_id: `tx_reg_${tip_id}`,
    vp_id: "tip://vp/US-vvvvvvvvvvvvvvvv",
    verification_tier: "T1",
    status: "active",
    founding: false,
    reviewer_consent: false,
  };
}

// ── C-3: addRevocation atomicity ────────────────────────────────────────────

describe("C-3 — addRevocation atomicity (SQLiteStore)", () => {

  test("rolls back revocations INSERT when identities UPDATE is aborted", () => {
    const dbPath = makeTmpDbPath();
    const dag = initDAG({ dbPath });

    const TIP = "tip://id/US-atomicity-c3-0000";

    // Seed the identity that will be revoked.
    dag.saveIdentity(_identity(TIP));
    expect(dag.getIdentity(TIP).status).toBe("active");

    // Inject a trigger (via a second connection) that aborts the
    // UPDATE identities SET status='revoked' statement.  The trigger
    // is added AFTER the initial saveIdentity so it doesn't interfere
    // with the INSERT OR REPLACE used by saveIdentity.
    const raw = new Database(dbPath);
    raw.exec(`
      CREATE TRIGGER _test_c3_fail_revoke_ident
      BEFORE UPDATE ON identities WHEN NEW.status = 'revoked'
      BEGIN
        SELECT RAISE(ABORT, 'simulated crash: revokeIdent');
      END
    `);
    raw.close();

    // addRevocation must throw because the trigger fires on the second statement.
    expect(() =>
      dag.addRevocation(TIP, "REVOKE_VOLUNTARY", 2_000, "tx_rev_1")
    ).toThrow();

    // ── Invariant ──────────────────────────────────────────────────────────
    // Pre-fix  (no transaction): addRevoc.run() auto-committed before the
    //   trigger fired → revocations row exists, identity is still 'active'
    //   → getRevocation returns the row → test FAILS (asserts null).
    //
    // Post-fix (db.transaction): the trigger causes a rollback of the whole
    //   transaction → addRevoc.run() insert is rolled back too
    //   → getRevocation is null, isRevoked is false → test PASSES.
    expect(dag.getRevocation(TIP)).toBeNull();
    expect(dag.isRevoked(TIP)).toBe(false);

    dag.close();
  });

  test("succeeds normally when no crash occurs (no regression)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const TIP = "tip://id/US-atomicity-c3-happy";

    dag.saveIdentity(_identity(TIP));
    dag.addRevocation(TIP, "REVOKE_VOLUNTARY", 2_000, "tx_rev_happy");

    expect(dag.isRevoked(TIP)).toBe(true);
    expect(dag.getRevocation(TIP)).not.toBeNull();
    expect(dag.getRevocation(TIP).tip_id).toBe(TIP);
    expect(dag.getIdentity(TIP).status).toBe("revoked");
  });

});

// ── C-4: _saveActiveEntityKey atomicity ──────────────────────────────────

describe("C-4 — _saveActiveEntityKey atomicity (SQLiteStore)", () => {

  test("rolls back closeActiveEntityKey UPDATE when saveEntityKey INSERT is aborted", () => {
    const dbPath = makeTmpDbPath();
    const dag = initDAG({ dbPath });

    const NODE_ID = "tip://node/atomicity-c4-0000";

    // Step 1: initial node registration — inserts first active entity_key row.
    dag.saveNode({
      node_id:      NODE_ID,
      name:         "test-node",
      public_key:   "pk_original_key_aaaa",
      algorithm:    "ml-dsa-65",
      registered_at: 1_000,
      tx_id:        "tx_node_reg",
    });
    const initialKey = dag.getActiveKey("node", NODE_ID);
    expect(initialKey).not.toBeNull();
    expect(initialKey.public_key).toBe("pk_original_key_aaaa");

    // Step 2: inject a trigger that aborts every INSERT INTO entity_keys.
    // Added AFTER the initial saveNode so the first INSERT succeeds.
    // The trigger simulates a crash during saveEntityKey (the second
    // statement in _saveActiveEntityKey when a prior key exists).
    const raw = new Database(dbPath);
    raw.exec(`
      CREATE TRIGGER _test_c4_fail_save_entity_key
      BEFORE INSERT ON entity_keys
      BEGIN
        SELECT RAISE(ABORT, 'simulated crash: saveEntityKey');
      END
    `);
    raw.close();

    // Step 3: key rotation — calls closeActiveEntityKey then saveEntityKey.
    // The INSERT trigger fires on saveEntityKey → throws.
    expect(() =>
      dag.saveNode({
        node_id:      NODE_ID,
        name:         "test-node",
        public_key:   "pk_rotated_key_bbbb",
        algorithm:    "ml-dsa-65",
        registered_at: 2_000,
        tx_id:        "tx_node_rotate",
      })
    ).toThrow();

    // ── Invariant ──────────────────────────────────────────────────────────
    // Pre-fix  (no transaction): closeActiveEntityKey.run() auto-committed
    //   (old key now has valid_to_ts=2000, no longer active),
    //   saveEntityKey.run() threw → entity has NO active key
    //   → getActiveKey returns null → test FAILS.
    //
    // Post-fix (db.transaction): trigger rollback undoes the UPDATE too
    //   → original key still has valid_to_ts IS NULL → still active
    //   → getActiveKey returns pk_original_key_aaaa → test PASSES.
    const keyAfter = dag.getActiveKey("node", NODE_ID);
    expect(keyAfter).not.toBeNull();
    expect(keyAfter.public_key).toBe("pk_original_key_aaaa");

    dag.close();
  });

  test("succeeds normally on key rotation when no crash occurs (no regression)", () => {
    const dag = initDAG({ dbPath: ":memory:" });

    const NODE_ID = "tip://node/atomicity-c4-happy";

    dag.saveNode({ node_id: NODE_ID, name: "n", public_key: "pk_v1", registered_at: 1_000, tx_id: "tx_1" });
    expect(dag.getActiveKey("node", NODE_ID).public_key).toBe("pk_v1");

    dag.saveNode({ node_id: NODE_ID, name: "n", public_key: "pk_v2", registered_at: 2_000, tx_id: "tx_2" });
    expect(dag.getActiveKey("node", NODE_ID).public_key).toBe("pk_v2");
  });

});
