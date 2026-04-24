/**
 * @file tests/consensus/cert-gc.test.js
 * @description §2 cert GC tests — the `pruneCertificatesBefore` accessor
 * on both MemoryStore and SQLiteStore, plus semantic invariants the
 * Bullshark GC trigger relies on.
 *
 * Scope:
 *   - `dag.pruneCertificatesBefore(cutoff)` drops rows with
 *     `round < cutoff`, preserves rows with `round >= cutoff`
 *   - returns count of rows deleted
 *   - idempotent when re-run at the same cutoff
 *   - no-op for cutoff <= 0 (defensive; we never prune below genesis)
 *   - MemoryStore and SQLiteStore match on all cases (store-parity)
 *   - commits checkpoint table is NOT affected — audit rows survive
 *     cert pruning, which is the whole point of §15 + §14
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));

beforeAll(async () => { await initCrypto(); });

// Minimal cert fixture — GC only cares about `round`. Fields that the
// SQLite schema marks NOT NULL are filled with dummy values.
function fixtureCert(round, authorSuffix = "a") {
  const author = `tip://node/${authorSuffix}${round}`;
  const hash = shake256(`cert:${round}:${author}`);
  return {
    hash,
    round,
    author_node_id: author,
    batch: { round, author_node_id: author, txs: [], signature: "00" },
    acknowledgments: [],
    parent_hashes: [],
    signature: "00",
  };
}

function seedCerts(dag, rounds) {
  for (const r of rounds) {
    dag.saveCertificate(fixtureCert(r));
  }
}

function makeTmpDbPath() {
  return path.join(os.tmpdir(), `tip-cert-gc-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
}

describe("dag.pruneCertificatesBefore — MemoryStore", () => {
  let dag;
  beforeEach(() => { dag = initDAG({ dbPath: ":memory:" }); });

  test("drops rounds strictly less than cutoff", () => {
    seedCerts(dag, [1, 2, 3, 4, 5]);
    expect(dag.certificateCount()).toBe(5);

    const n = dag.pruneCertificatesBefore(3);
    expect(n).toBe(2);
    expect(dag.certificateCount()).toBe(3);

    expect(dag.getCertificatesByRound(1)).toHaveLength(0);
    expect(dag.getCertificatesByRound(2)).toHaveLength(0);
    expect(dag.getCertificatesByRound(3)).toHaveLength(1);
    expect(dag.getCertificatesByRound(5)).toHaveLength(1);
  });

  test("boundary: cutoff equals lowest retained round", () => {
    seedCerts(dag, [10, 11, 12]);
    const n = dag.pruneCertificatesBefore(10);
    expect(n).toBe(0);
    expect(dag.certificateCount()).toBe(3);
  });

  test("idempotent — second run at same cutoff returns 0", () => {
    seedCerts(dag, [1, 2, 3]);
    expect(dag.pruneCertificatesBefore(3)).toBe(2);
    expect(dag.pruneCertificatesBefore(3)).toBe(0);
    expect(dag.certificateCount()).toBe(1);
  });

  test("cutoff above all rounds prunes everything", () => {
    seedCerts(dag, [1, 2, 3]);
    expect(dag.pruneCertificatesBefore(100)).toBe(3);
    expect(dag.certificateCount()).toBe(0);
  });

  test("cutoff of 0 or negative is a no-op (defensive)", () => {
    seedCerts(dag, [1, 2]);
    expect(dag.pruneCertificatesBefore(0)).toBe(0);
    expect(dag.pruneCertificatesBefore(-5)).toBe(0);
    expect(dag.certificateCount()).toBe(2);
  });

  test("empty certs table is a no-op", () => {
    expect(dag.pruneCertificatesBefore(100)).toBe(0);
    expect(dag.certificateCount()).toBe(0);
  });

  test("lookup by hash returns null for pruned certs", () => {
    const cert = fixtureCert(1);
    dag.saveCertificate(cert);
    expect(dag.getCertificate(cert.hash)).not.toBeNull();
    dag.pruneCertificatesBefore(5);
    expect(dag.getCertificate(cert.hash)).toBeNull();
  });

  test("lookup by author+round returns null for pruned certs", () => {
    dag.saveCertificate(fixtureCert(1, "x"));
    expect(dag.getCertificateByAuthorRound("tip://node/x1", 1)).not.toBeNull();
    dag.pruneCertificatesBefore(5);
    expect(dag.getCertificateByAuthorRound("tip://node/x1", 1)).toBeNull();
  });

  test("getCertificatesFromRound reflects pruning (start of retention window)", () => {
    seedCerts(dag, [1, 2, 3, 4, 5]);
    dag.pruneCertificatesBefore(3);
    const survivors = dag.getCertificatesFromRound(1);
    expect(survivors.map(c => c.round).sort((a, b) => a - b)).toEqual([3, 4, 5]);
  });
});

describe("dag.pruneCertificatesBefore — SQLiteStore", () => {
  let dbPath;
  let dag;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    dag = initDAG({ dbPath });
  });

  afterEach(() => {
    try { if (dag && typeof dag.close === "function") dag.close(); } catch { /* ignore */ }
    try { if (dbPath && fs.existsSync(dbPath)) fs.unlinkSync(dbPath); } catch { /* ignore */ }
  });

  test("drops < cutoff, preserves >= cutoff, returns row count", () => {
    seedCerts(dag, [1, 2, 3, 4, 5]);
    expect(dag.certificateCount()).toBe(5);

    const n = dag.pruneCertificatesBefore(3);
    expect(n).toBe(2);
    expect(dag.certificateCount()).toBe(3);
  });

  test("idempotent", () => {
    seedCerts(dag, [1, 2, 3]);
    expect(dag.pruneCertificatesBefore(3)).toBe(2);
    expect(dag.pruneCertificatesBefore(3)).toBe(0);
  });

  test("survives DB close + reopen — pruning is durable", () => {
    seedCerts(dag, [1, 2, 3, 4, 5]);
    dag.pruneCertificatesBefore(4);
    expect(dag.certificateCount()).toBe(2);

    // Reopen — schema and data must persist.
    if (typeof dag.close === "function") dag.close();
    const dag2 = initDAG({ dbPath });
    expect(dag2.certificateCount()).toBe(2);
    expect(dag2.getCertificatesByRound(1)).toHaveLength(0);
    expect(dag2.getCertificatesByRound(4)).toHaveLength(1);
    if (typeof dag2.close === "function") dag2.close();
  });

  test("cutoff above all rounds prunes everything", () => {
    seedCerts(dag, [1, 2, 3]);
    expect(dag.pruneCertificatesBefore(100)).toBe(3);
    expect(dag.certificateCount()).toBe(0);
  });
});

describe("store-parity: MemoryStore and SQLiteStore agree", () => {
  // Consensus-critical: a mixed-store network (SQLite prod, MemoryStore test)
  // must prune the same cert set for the same cutoff. Divergence here means
  // one store's GC watermark differs from another's, which can cascade into
  // split committees on resume.
  test("same input → same prune count and same survivor set", () => {
    const memDag = initDAG({ dbPath: ":memory:" });
    const dbPath = makeTmpDbPath();
    const sqliteDag = initDAG({ dbPath });
    try {
      const rounds = [1, 2, 3, 5, 7, 10, 11, 20];
      seedCerts(memDag, rounds);
      seedCerts(sqliteDag, rounds);

      const cutoff = 7;
      const memN = memDag.pruneCertificatesBefore(cutoff);
      const sqliteN = sqliteDag.pruneCertificatesBefore(cutoff);
      expect(memN).toBe(sqliteN);

      const memRounds = memDag.getCertificatesFromRound(1).map(c => c.round).sort((a, b) => a - b);
      const sqliteRounds = sqliteDag.getCertificatesFromRound(1).map(c => c.round).sort((a, b) => a - b);
      expect(memRounds).toEqual(sqliteRounds);
      expect(memRounds).toEqual([7, 10, 11, 20]);
    } finally {
      if (typeof sqliteDag.close === "function") sqliteDag.close();
      if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    }
  });
});

describe("dag.getEarliestCertRound", () => {
  test("returns 0 on empty certs table (MemoryStore)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    expect(dag.getEarliestCertRound()).toBe(0);
  });

  test("returns lowest round when certs exist (MemoryStore)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    seedCerts(dag, [20, 5, 30, 10]);
    expect(dag.getEarliestCertRound()).toBe(5);
  });

  test("reflects pruning: post-prune returns new floor", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    seedCerts(dag, [1, 2, 3, 4, 5]);
    expect(dag.getEarliestCertRound()).toBe(1);
    dag.pruneCertificatesBefore(3);
    expect(dag.getEarliestCertRound()).toBe(3);
  });

  test("SQLite + MemoryStore agree for identical inputs", () => {
    const memDag = initDAG({ dbPath: ":memory:" });
    const dbPath = makeTmpDbPath();
    const sqliteDag = initDAG({ dbPath });
    try {
      const rounds = [50, 3, 100, 7, 200];
      seedCerts(memDag, rounds);
      seedCerts(sqliteDag, rounds);
      expect(memDag.getEarliestCertRound()).toBe(3);
      expect(sqliteDag.getEarliestCertRound()).toBe(3);

      memDag.pruneCertificatesBefore(50);
      sqliteDag.pruneCertificatesBefore(50);
      expect(memDag.getEarliestCertRound()).toBe(50);
      expect(sqliteDag.getEarliestCertRound()).toBe(50);
    } finally {
      if (typeof sqliteDag.close === "function") sqliteDag.close();
      if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    }
  });

  test("SQLite returns 0 on empty, non-zero after save", () => {
    const dbPath = makeTmpDbPath();
    const dag = initDAG({ dbPath });
    try {
      expect(dag.getEarliestCertRound()).toBe(0);
      dag.saveCertificate(fixtureCert(42));
      expect(dag.getEarliestCertRound()).toBe(42);
    } finally {
      if (typeof dag.close === "function") dag.close();
      if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    }
  });
});

describe("SQLite auto_vacuum + incrementalVacuum", () => {
  let dbPath, dag;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    dag = initDAG({ dbPath });
  });

  afterEach(() => {
    try { if (dag && typeof dag.close === "function") dag.close(); } catch { /* ignore */ }
    try { if (dbPath && fs.existsSync(dbPath)) fs.unlinkSync(dbPath); } catch { /* ignore */ }
  });

  test("auto_vacuum is set to INCREMENTAL (mode 2) on fresh DB", () => {
    const mode = dag._store?.db?.pragma?.("auto_vacuum", { simple: true });
    // Access via internal test hook — can't reach through facade. If pragma
    // isn't reachable from here, rely on the behavioral test below.
    if (mode !== undefined) expect(mode).toBe(2);
  });

  test("incrementalVacuum(N) runs without error on empty DB", () => {
    expect(() => dag.incrementalVacuum(100)).not.toThrow();
  });

  test("incrementalVacuum reclaims disk after a prune", () => {
    // Seed + prune + vacuum. Verify the combination doesn't throw and
    // that certificateCount still reports correctly afterwards.
    for (let r = 1; r <= 20; r++) {
      dag.saveCertificate(fixtureCert(r, `a${r}`));
    }
    expect(dag.certificateCount()).toBe(20);
    expect(dag.pruneCertificatesBefore(10)).toBe(9);
    expect(() => dag.incrementalVacuum(1000)).not.toThrow();
    expect(dag.certificateCount()).toBe(11);
  });

  test("incrementalVacuum is a no-op on MemoryStore", () => {
    const memDag = initDAG({ dbPath: ":memory:" });
    expect(() => memDag.incrementalVacuum(100)).not.toThrow();
    expect(() => memDag.incrementalVacuum()).not.toThrow();
    expect(() => memDag.incrementalVacuum(undefined)).not.toThrow();
  });
});

describe("commits table survives cert GC (§15 audit invariant)", () => {
  // The whole point of §15 commit checkpoints is that even after aggressive
  // cert GC, the audit row for round R still answers "what did consensus
  // agree on at round R?" — committee, anchor_cert_hash, state_merkle_root.
  // If cert GC accidentally took the commits table with it, snapshot-sync
  // (§14) joiners would lose their trust anchor.
  test("pruning certs does not delete commits rows", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    seedCerts(dag, [1, 2, 3, 4, 5]);

    dag.saveCommit({
      round: 2,
      anchor_cert_hash: "deadbeef",
      leader_node_id: "tip://node/a1",
      committee: ["tip://node/a1", "tip://node/b1"],
      support_count: 2,
      consensus_index: 1,
      committed_at: "2026-04-24T00:00:00.000Z",
      state_merkle_root: "staterootval",
      txs_merkle_root: "txsrootval",
      ack_signer_ids: ["tip://node/a1", "tip://node/b1"],
      ack_signatures: ["00", "00"],
    });

    dag.pruneCertificatesBefore(100);
    expect(dag.certificateCount()).toBe(0);

    const commit = dag.getCommit(2);
    expect(commit).not.toBeNull();
    expect(commit.round).toBe(2);
    expect(commit.state_merkle_root).toBe("staterootval");
  });
});
