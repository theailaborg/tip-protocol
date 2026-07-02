/**
 * @file scripts/genesis-backups.js
 * @description Lookup helpers for genesis-data/backups/*.tip.json, the single
 * on-disk source of genesis private keys (genesis.json carries the public side).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const path = require("path");

const BACKUP_DIR = path.resolve(__dirname, "../genesis-data/backups");

function loadBackups(dir = BACKUP_DIR) {
  if (!fs.existsSync(dir)) return [];
  const docs = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".tip.json")) continue;
    // An unreadable backup is skipped; seed mints fresh keys for that entity.
    try { docs.push(JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"))); }
    catch { /* ignore */ }
  }
  return docs;
}

// `tag` is the stable handle; (type, name) is the fallback for backups written
// before tags were embedded.
function findBackup(docs, { tag, type, name }) {
  return (tag && docs.find(d => d.tag === tag))
      || (name && docs.find(d => d.type === type && d.name === name))
      || null;
}

function loadVpBackup(dir = BACKUP_DIR) {
  const vp = loadBackups(dir).find(d => d.type === "vp");
  if (!vp?.public_key || !vp?.private_key) {
    throw new Error(`no VP backup (type "vp") in ${dir}: run scripts/seed.js first`);
  }
  return vp;
}

module.exports = { BACKUP_DIR, loadBackups, findBackup, loadVpBackup };
