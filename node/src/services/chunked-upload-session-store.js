/**
 * @file @tip-protocol/node/src/services/chunked-upload-session-store.js
 * @description Session stores for chunked uploads. In-memory default with an
 * optional Postgres backend via Knex.
 *
 * Sessions are node-local, ephemeral state (not consensus data). They bridge
 * a multi-request chunked upload so the node can verify the final full-file
 * hash before completing the S3 multipart upload.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { randomUUID } = require("crypto");
const { nowMs } = require("../../../shared/time");

const TABLE_NAME = "upload_sessions";

function _sessionFromRow(row) {
  if (!row) return null;
  return {
    session_id: row.session_id,
    upload_id: row.upload_id,
    s3_key: row.s3_key,
    content_hash: row.content_hash,
    mime: row.mime,
    size: Number(row.size),
    signer_tip_id: row.signer_tip_id,
    timestamp: Number(row.timestamp),
    signature: row.signature,
    parts: JSON.parse(row.parts_json || "[]"),
    completed_size: Number(row.completed_size),
    created_at: Number(row.created_at),
    expires_at: Number(row.expires_at),
  };
}

function _rowFromSession(s) {
  return {
    session_id: s.session_id,
    upload_id: s.upload_id,
    s3_key: s.s3_key,
    content_hash: s.content_hash,
    mime: s.mime,
    size: s.size,
    signer_tip_id: s.signer_tip_id,
    timestamp: s.timestamp,
    signature: s.signature,
    parts_json: JSON.stringify(s.parts || []),
    completed_size: s.completed_size || 0,
    created_at: s.created_at,
    expires_at: s.expires_at,
  };
}

class InMemoryUploadSessionStore {
  constructor({ ttlMs = 24 * 60 * 60 * 1000, logger = null } = {}) {
    this._sessions = new Map();
    this._ttlMs = ttlMs;
    this._logger = logger;
  }

  async create(session) {
    const row = _rowFromSession(session);
    this._sessions.set(session.session_id, row);
    return session;
  }

  async get(sessionId) {
    const row = this._sessions.get(sessionId);
    if (!row) return null;
    if (row.expires_at < nowMs()) {
      this._sessions.delete(sessionId);
      return null;
    }
    return _sessionFromRow(row);
  }

  async update(sessionId, patch) {
    const row = this._sessions.get(sessionId);
    if (!row) return null;
    for (const key of Object.keys(patch)) {
      if (key === "parts") {
        row.parts_json = JSON.stringify(patch.parts || []);
      } else if (row[key] !== undefined) {
        row[key] = patch[key];
      }
    }
    return _sessionFromRow(row);
  }

  async delete(sessionId) {
    this._sessions.delete(sessionId);
  }

  async cleanupExpired(beforeMs = nowMs()) {
    let removed = 0;
    for (const [id, row] of this._sessions) {
      if (row.expires_at < beforeMs) {
        this._sessions.delete(id);
        removed++;
      }
    }
    return removed;
  }

  generateId() {
    return randomUUID().replace(/-/g, "");
  }
}

class PostgresUploadSessionStore {
  constructor({ knex, ttlMs = 24 * 60 * 60 * 1000, logger = null }) {
    if (!knex) throw new Error("PostgresUploadSessionStore: knex required");
    this._knex = knex;
    this._ttlMs = ttlMs;
    this._logger = logger;
  }

  async create(session) {
    const row = _rowFromSession(session);
    await this._knex(TABLE_NAME).insert(row);
    return session;
  }

  async get(sessionId) {
    const row = await this._knex(TABLE_NAME).where({ session_id: sessionId }).first();
    if (!row) return null;
    if (row.expires_at < nowMs()) {
      await this.delete(sessionId);
      return null;
    }
    return _sessionFromRow(row);
  }

  async update(sessionId, patch) {
    const updates = {};
    for (const key of Object.keys(patch)) {
      if (key === "parts") {
        updates.parts_json = JSON.stringify(patch.parts || []);
      } else if (["completed_size", "expires_at"].includes(key)) {
        updates[key] = patch[key];
      }
    }
    if (Object.keys(updates).length === 0) {
      return this.get(sessionId);
    }
    const rows = await this._knex(TABLE_NAME)
      .where({ session_id: sessionId })
      .update(updates)
      .returning("*");
    return _sessionFromRow(rows && rows[0]);
  }

  async delete(sessionId) {
    await this._knex(TABLE_NAME).where({ session_id: sessionId }).del();
  }

  async cleanupExpired(beforeMs = nowMs()) {
    const removed = await this._knex(TABLE_NAME).where("expires_at", "<", beforeMs).del();
    return removed;
  }

  generateId() {
    return randomUUID().replace(/-/g, "");
  }
}

module.exports = {
  InMemoryUploadSessionStore,
  PostgresUploadSessionStore,
};
