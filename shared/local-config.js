"use strict";

// Tier-3 local tunables — timing, capacity, retry knobs that do NOT feed into
// genesis_hash. Nodes may differ on these values without breaking consensus.
// Each env var overrides the protocol default for that node only.
//
// Defaults are the exact values that were removed from GENESIS_PAYLOAD.
// Changing a default here requires a code release, not a coordinated restart.

function _num(envVar, def) {
  const raw = process.env[envVar];
  if (raw === undefined || raw === "") return def;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`${envVar} must be a non-negative finite number, got: ${JSON.stringify(raw)}`);
  }
  return n;
}

const LOCAL_CONFIG = Object.freeze({
  // Timing
  ROUND_TIMEOUT_MS:                    _num("TIP_ROUND_TIMEOUT_MS",                    2000),
  BATCH_WAIT_MS:                       _num("TIP_BATCH_WAIT_MS",                       500),
  CONSENSUS_SUMMARY_INTERVAL_MS:       _num("TIP_CONSENSUS_SUMMARY_INTERVAL_MS",       60000),
  ANTI_ENTROPY_INTERVAL_MS:            _num("TIP_ANTI_ENTROPY_INTERVAL_MS",            4000),
  ANTI_ENTROPY_PEER_TIMEOUT_MS:        _num("TIP_ANTI_ENTROPY_PEER_TIMEOUT_MS",        2000),
  SYNC_RETRY_BASE_MS:                  _num("TIP_SYNC_RETRY_BASE_MS",                  1000),
  SNAPSHOT_BUSY_RETRY_MS:              _num("TIP_SNAPSHOT_BUSY_RETRY_MS",              5000),
  ACK_STREAM_TIMEOUT_MS:               _num("TIP_ACK_STREAM_TIMEOUT_MS",               3000),
  SYNC_DIVERGENCE_GRACE_MS:            _num("TIP_SYNC_DIVERGENCE_GRACE_MS",            30000),
  FRONTIER_RECONCILE_LOOKBACK_ROUNDS:  _num("TIP_FRONTIER_RECONCILE_LOOKBACK_ROUNDS",  200),
  ROTATION_COORD_REBROADCAST_INTERVAL_MS: _num("TIP_ROTATION_COORD_REBROADCAST_INTERVAL_MS", 1500),
  ROTATION_REPAIR_TIMEOUT_MS:          _num("TIP_ROTATION_REPAIR_TIMEOUT_MS",          5000),
  ROTATION_REPAIR_MAX_RESPONSE_BYTES:  _num("TIP_ROTATION_REPAIR_MAX_RESPONSE_BYTES",  1048576),
  PRODUCER_PAUSE_ESCALATE_MS:          _num("TIP_PRODUCER_PAUSE_ESCALATE_MS",          30000),
  HANDSHAKE_TIMEOUT_MS:                _num("TIP_HANDSHAKE_TIMEOUT_MS",                10000),
  HANDSHAKE_REHANDSHAKE_INTERVAL_MS:  _num("TIP_HANDSHAKE_REHANDSHAKE_INTERVAL_MS",  20000),
  HANDSHAKE_REAUTH_GRACE_MS:          _num("TIP_HANDSHAKE_REAUTH_GRACE_MS",          15000),
  SYNC_TOTAL_TIMEOUT_MS:               _num("TIP_SYNC_TOTAL_TIMEOUT_MS",               30000),
  MAX_ROUND_DURATION_MS:               _num("TIP_MAX_ROUND_DURATION_MS",               300000),

  // Capacity and limits
  MEMPOOL_MAX_SIZE:                    _num("TIP_MEMPOOL_MAX_SIZE",                    10000),
  MEMPOOL_TX_TTL_SECONDS:              _num("TIP_MEMPOOL_TX_TTL_SECONDS",              300),
  SYNC_BATCH_SIZE:                     _num("TIP_SYNC_BATCH_SIZE",                     100),
  // Lag within this many rounds heals via gossip + AE; only a larger gap (a real
  // joiner) warrants the heavy enterSyncMode path.
  SYNC_FROM_PEER_TOLERANCE_ROUNDS:     _num("TIP_SYNC_FROM_PEER_TOLERANCE_ROUNDS",     20),
  ORDERED_HASH_CACHE_SIZE:             _num("TIP_ORDERED_HASH_CACHE_SIZE",             10000),
  MAX_MSGS_PER_PEER_PER_SEC:           _num("TIP_MAX_MSGS_PER_PEER_PER_SEC",           100),
  SYNC_MAX_RESPONSE_BYTES:             _num("TIP_SYNC_MAX_RESPONSE_BYTES",             1073741824),

  // Retries
  SYNC_MAX_RETRIES:                    _num("TIP_SYNC_MAX_RETRIES",                    5),
  HANDSHAKE_MAX_RETRIES:               _num("TIP_HANDSHAKE_MAX_RETRIES",               3),
  GC_INTERVAL_COMMITS:                 _num("TIP_GC_INTERVAL_COMMITS",                 10),
  SNAPSHOT_BUSY_RETRY_ATTEMPTS:        _num("TIP_SNAPSHOT_BUSY_RETRY_ATTEMPTS",        1),
});

module.exports = LOCAL_CONFIG;
