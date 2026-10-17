/**
 * @file shared/key-file.js
 * @description .tip.json key files: the VP app's date-locked export (v2) and the
 * plaintext files seed.js writes for dev (v1).
 *
 * v2 is what the VP app downloads and imports: PBKDF2-SHA256 (200k) over the
 * date as MMDDYYYY digits, AES-256-GCM over the private key hex, and
 * `encrypted` = base64(salt[16] || iv[12] || ciphertext+tag). A file written
 * here imports into the VP app with the same date, and a VP download reads here.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const { KEY_FILE_EXPORT } = require("./constants");

const GCM_TAG_BYTES = 16;

// The VP app strips non-digits from a MM/DD/YYYY entry; an ISO date maps to the
// same 8 digits so both sides derive the same key.
function datePassword(isoDate) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(isoDate || "").trim());
  if (!m) throw new Error(`datePassword: expected YYYY-MM-DD, got "${isoDate}"`);
  return `${m[2]}${m[3]}${m[1]}`;
}

function _deriveKey(password, salt) {
  return crypto.pbkdf2Sync(
    Buffer.from(String(password), "utf8"), salt,
    KEY_FILE_EXPORT.PBKDF2_ITERATIONS, KEY_FILE_EXPORT.KEY_BYTES, KEY_FILE_EXPORT.PBKDF2_DIGEST,
  );
}

function encryptPrivateKey(privateKeyHex, password) {
  if (typeof privateKeyHex !== "string" || !privateKeyHex) throw new Error("encryptPrivateKey: private key hex required");
  if (typeof password !== "string" || !password) throw new Error("encryptPrivateKey: password required");
  const salt = crypto.randomBytes(KEY_FILE_EXPORT.SALT_BYTES);
  const iv = crypto.randomBytes(KEY_FILE_EXPORT.IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", _deriveKey(password, salt), iv);
  const ct = Buffer.concat([cipher.update(privateKeyHex, "utf8"), cipher.final(), cipher.getAuthTag()]);
  return Buffer.concat([salt, iv, ct]).toString("base64");
}

function decryptPrivateKey(encryptedB64, password) {
  const d = Buffer.from(String(encryptedB64 || ""), "base64");
  const header = KEY_FILE_EXPORT.SALT_BYTES + KEY_FILE_EXPORT.IV_BYTES;
  if (d.length < header + GCM_TAG_BYTES) throw new Error("key file is truncated");
  const salt = d.subarray(0, KEY_FILE_EXPORT.SALT_BYTES);
  const iv = d.subarray(KEY_FILE_EXPORT.SALT_BYTES, header);
  const ct = d.subarray(header, d.length - GCM_TAG_BYTES);
  const tag = d.subarray(d.length - GCM_TAG_BYTES);
  const decipher = crypto.createDecipheriv("aes-256-gcm", _deriveKey(password, salt), iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("wrong date for this key file");
  }
}

function isEncryptedKeyFile(doc) {
  return !!doc && doc.version === KEY_FILE_EXPORT.VERSION && typeof doc.encrypted === "string";
}

// Normalises either format to { tip_id, public_key, private_key, tip_id_type, doc }.
// v2 needs the date the file was locked with; v1 ignores it.
function readKeyFile(filePath, password) {
  let doc;
  try { doc = JSON.parse(fs.readFileSync(filePath, "utf8")); }
  catch (e) { throw new Error(`${filePath} is unreadable or not valid JSON: ${e.message}`); }
  if (isEncryptedKeyFile(doc)) {
    if (!password) throw new Error(`${filePath} is locked (${KEY_FILE_EXPORT.VERSION}); the incorporation date is required to open it`);
    return {
      tip_id: doc.tipId,
      public_key: doc.publicKey,
      private_key: decryptPrivateKey(doc.encrypted, password),
      tip_id_type: doc.tip_id_type || null,
      doc,
    };
  }
  if (!doc.private_key || !doc.public_key) throw new Error(`${filePath} is not a keypair file`);
  return {
    tip_id: doc.tip_id || doc.node_id || doc.vp_id || null,
    public_key: doc.public_key,
    private_key: doc.private_key,
    tip_id_type: doc.tip_id_type || null,
    doc,
  };
}

module.exports = {
  datePassword,
  encryptPrivateKey,
  decryptPrivateKey,
  isEncryptedKeyFile,
  readKeyFile,
};
