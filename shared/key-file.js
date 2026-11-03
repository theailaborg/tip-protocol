/**
 * @file shared/key-file.js
 * @description .tip.json key files: the phrase-locked export (v3), the VP app's
 * date-locked export (v2) and the plaintext files seed.js writes for dev (v1).
 *
 * v2 is what the VP app downloads and imports: PBKDF2-SHA256 (200k) over the
 * date as MMDDYYYY digits, AES-256-GCM over the private key hex, and
 * `encrypted` = base64(salt[16] || iv[12] || ciphertext+tag). A file written
 * here imports into the VP app with the same date, and a VP download reads here.
 *
 * v3 is the same layout with a different password. The password is a 12-word
 * recovery phrase (BIP39 English list, 128 random bits plus a 4-bit checksum),
 * written as the 12 lowercase words joined with single spaces. A date can be
 * guessed in seconds. The phrase cannot.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { KEY_FILE_EXPORT } = require("./constants");

const GCM_TAG_BYTES = 16;
const PHRASE_WORDS = 12;

// BIP39 English wordlist, MIT licence. sha256 of the file is
// 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda.
const WORDS = fs.readFileSync(path.join(__dirname, "bip39-english.txt"), "utf8").trim().split("\n");
if (WORDS.length !== 2048) throw new Error("bip39-english.txt must hold 2048 words");
const WORD_INDEX = new Map(WORDS.map((w, i) => [w, i]));

// 16 bytes become 12 words: 128 bits plus the first 4 bits of SHA-256(entropy),
// read as twelve 11-bit indices.
function entropyToPhrase(entropy) {
  if (!Buffer.isBuffer(entropy) || entropy.length !== 16) throw new Error("entropyToPhrase: 16 bytes required");
  let bits = "";
  for (const b of entropy) bits += b.toString(2).padStart(8, "0");
  bits += (crypto.createHash("sha256").update(entropy).digest()[0] >> 4).toString(2).padStart(4, "0");
  const words = [];
  for (let i = 0; i < PHRASE_WORDS; i++) words.push(WORDS[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]);
  return words.join(" ");
}

function generatePhrase() {
  return entropyToPhrase(crypto.randomBytes(16));
}

// Reads what a person types. Case, commas, line breaks and numbering are
// ignored, so "1. Legal, WINNER ..." works. Returns { ok: true, phrase } with
// the canonical form, or { ok: false, reason } where reason is "count",
// "unknown_word" (with position) or "checksum".
function checkPhrase(input) {
  const words = String(input == null ? "" : input).normalize("NFKD").toLowerCase()
    .replace(/[^a-z]+/g, " ").trim().split(" ").filter(Boolean);
  if (words.length !== PHRASE_WORDS) return { ok: false, reason: "count", count: words.length };
  let bits = "";
  for (let i = 0; i < PHRASE_WORDS; i++) {
    const idx = WORD_INDEX.get(words[i]);
    if (idx === undefined) return { ok: false, reason: "unknown_word", position: i + 1 };
    bits += idx.toString(2).padStart(11, "0");
  }
  const entropy = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) entropy[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const check = crypto.createHash("sha256").update(entropy).digest()[0] >> 4;
  if (check !== parseInt(bits.slice(128), 2)) return { ok: false, reason: "checksum" };
  return { ok: true, phrase: words.join(" ") };
}

// The error a person sees for each checkPhrase failure. The typed words are
// never echoed, since they are part of the secret.
function phraseError(result) {
  if (result.reason === "count") return `The recovery phrase must be ${PHRASE_WORDS} words, got ${result.count}.`;
  if (result.reason === "unknown_word") return `Word ${result.position} of the recovery phrase is not on the word list. Check its spelling.`;
  return "The recovery phrase words do not fit together. One word is wrong or out of order.";
}

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

// salt and iv are for test vectors only. Leave them out in real use.
function encryptPrivateKey(privateKeyHex, password, salt, iv) {
  if (typeof privateKeyHex !== "string" || !privateKeyHex) throw new Error("encryptPrivateKey: private key hex required");
  if (typeof password !== "string" || !password) throw new Error("encryptPrivateKey: password required");
  salt = salt || crypto.randomBytes(KEY_FILE_EXPORT.SALT_BYTES);
  iv = iv || crypto.randomBytes(KEY_FILE_EXPORT.IV_BYTES);
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

function isPhraseKeyFile(doc) {
  return !!doc && doc.version === KEY_FILE_EXPORT.PHRASE_VERSION && typeof doc.encrypted === "string";
}

function isEncryptedKeyFile(doc) {
  return isPhraseKeyFile(doc) || (!!doc && doc.version === KEY_FILE_EXPORT.VERSION && typeof doc.encrypted === "string");
}

// v3 is opened with the recovery phrase as typed. It is checked first, so a
// typo gets a clear message instead of a failed decrypt.
function _openWithPhrase(filePath, doc, phraseInput) {
  if (!phraseInput) throw new Error(`${filePath} is locked with a recovery phrase (${KEY_FILE_EXPORT.PHRASE_VERSION}). The 12 words are required to open it`);
  const checked = checkPhrase(phraseInput);
  if (!checked.ok) throw new Error(`${phraseError(checked)} (${filePath})`);
  try {
    return decryptPrivateKey(doc.encrypted, checked.phrase);
  } catch {
    throw new Error(`These words do not open ${filePath}. Check each word against what was written down.`);
  }
}

// Normalises any format to { tip_id, public_key, private_key, tip_id_type, doc }.
// The secret is the recovery phrase for v3 and the date password for v2.
// v1 ignores it.
function readKeyFile(filePath, password) {
  let doc;
  try { doc = JSON.parse(fs.readFileSync(filePath, "utf8")); }
  catch (e) { throw new Error(`${filePath} is unreadable or not valid JSON: ${e.message}`); }
  if (isEncryptedKeyFile(doc)) {
    if (!isPhraseKeyFile(doc) && !password) throw new Error(`${filePath} is locked (${KEY_FILE_EXPORT.VERSION}); the incorporation date is required to open it`);
    return {
      tip_id: doc.tipId,
      public_key: doc.publicKey,
      private_key: isPhraseKeyFile(doc) ? _openWithPhrase(filePath, doc, password) : decryptPrivateKey(doc.encrypted, password),
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
  entropyToPhrase,
  generatePhrase,
  checkPhrase,
  encryptPrivateKey,
  decryptPrivateKey,
  isEncryptedKeyFile,
  isPhraseKeyFile,
  readKeyFile,
};
