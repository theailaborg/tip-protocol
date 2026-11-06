/**
 * @file tests/shared/key-file.test.js
 * @description The org key file must open in the VP app with the incorporation
 * date, and a VP download must open here. The VP's own WebCrypto code
 * (get-verified.html _downloadBackupWithDob / signin.html decryptExportV2) is
 * reproduced below verbatim and run against our Node-crypto implementation in
 * both directions.
 *
 * The recovery phrase lock (tip-key-export-v3) must reproduce every entry of
 * the shared test vectors (fixtures/recovery-phrase-vectors.json), which every
 * port of the phrase code carries.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const SHARED = path.resolve(__dirname, "../../../shared");
const crypto = require("crypto");
const {
  datePassword, encryptPrivateKey, decryptPrivateKey, readKeyFile, isEncryptedKeyFile,
  entropyToPhrase, generatePhrase, checkPhrase, isPhraseKeyFile,
} = require(path.join(SHARED, "key-file"));
const { KEY_FILE_EXPORT } = require(path.join(SHARED, "constants"));
const VECTORS = require(path.resolve(__dirname, "../fixtures/recovery-phrase-vectors.json"));

const subtle = globalThis.crypto.subtle;
const PRIV_HEX = "ab".repeat(1952);
const DATE = "2025-11-11";
const PHRASE = VECTORS.lock.phrase;

// Verbatim VP app logic (browser WebCrypto), kept as the oracle.
async function vpEncrypt(privKey, dob) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const km = await subtle.importKey("raw", new TextEncoder().encode(dob), "PBKDF2", false, ["deriveKey"]);
  const aes = await subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, aes, new TextEncoder().encode(privKey));
  const combined = new Uint8Array(16 + 12 + ct.byteLength);
  combined.set(salt, 0); combined.set(iv, 16); combined.set(new Uint8Array(ct), 28);
  return btoa(String.fromCharCode.apply(null, combined));
}

async function vpDecrypt(encryptedB64, exportPassword) {
  const d = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
  const salt = d.slice(0, 16);
  const iv = d.slice(16, 28);
  const ct = d.slice(28);
  const km = await subtle.importKey("raw", new TextEncoder().encode(exportPassword), "PBKDF2", false, ["deriveKey"]);
  const aes = await subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
  const pt = await subtle.decrypt({ name: "AES-GCM", iv }, aes, ct);
  return new TextDecoder().decode(pt);
}

describe("datePassword", () => {
  test("maps an ISO date to the VP's MMDDYYYY digits", () => {
    expect(datePassword("2025-11-11")).toBe("11112025");
    expect(datePassword("2021-06-28")).toBe("06282021");
  });

  test("rejects anything that is not YYYY-MM-DD", () => {
    expect(() => datePassword("11/11/2025")).toThrow(/YYYY-MM-DD/);
    expect(() => datePassword("")).toThrow(/YYYY-MM-DD/);
  });
});

describe("encryptPrivateKey / decryptPrivateKey", () => {
  test("round-trips and never emits the same ciphertext twice", () => {
    const a = encryptPrivateKey(PRIV_HEX, datePassword(DATE));
    const b = encryptPrivateKey(PRIV_HEX, datePassword(DATE));
    expect(a).not.toBe(b);
    expect(decryptPrivateKey(a, datePassword(DATE))).toBe(PRIV_HEX);
    expect(decryptPrivateKey(b, datePassword(DATE))).toBe(PRIV_HEX);
  });

  test("layout is salt[16] || iv[12] || ciphertext || tag[16]", () => {
    const buf = Buffer.from(encryptPrivateKey(PRIV_HEX, "11112025"), "base64");
    expect(buf.length).toBe(KEY_FILE_EXPORT.SALT_BYTES + KEY_FILE_EXPORT.IV_BYTES + PRIV_HEX.length + 16);
  });

  test("a wrong date fails closed", () => {
    const enc = encryptPrivateKey(PRIV_HEX, "11112025");
    expect(() => decryptPrivateKey(enc, "11122025")).toThrow(/wrong date/);
    expect(() => decryptPrivateKey("AAAA", "11112025")).toThrow(/truncated/);
  });
});

describe("VP app interoperability", () => {
  test("a file we lock opens with the VP's decryptExportV2", async () => {
    const enc = encryptPrivateKey(PRIV_HEX, datePassword(DATE));
    await expect(vpDecrypt(enc, "11112025")).resolves.toBe(PRIV_HEX);
  });

  test("a VP download opens with decryptPrivateKey", async () => {
    const enc = await vpEncrypt(PRIV_HEX, "11112025");
    expect(decryptPrivateKey(enc, datePassword(DATE))).toBe(PRIV_HEX);
  });

  test("the VP rejects our file under a wrong date, as it does its own", async () => {
    const enc = encryptPrivateKey(PRIV_HEX, "11112025");
    await expect(vpDecrypt(enc, "11122025")).rejects.toThrow();
  });
});

describe("readKeyFile", () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-key-file-")); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  function write(name, doc) {
    const p = path.join(dir, name);
    fs.writeFileSync(p, JSON.stringify(doc));
    return p;
  }

  test("opens a v2 file with the date and exposes the VP field names normalised", () => {
    const p = write("org.tip.json", {
      version: KEY_FILE_EXPORT.VERSION,
      tipId: "tip://id/GB-0123456789abcdef",
      publicKey: "cd".repeat(8),
      encrypted: encryptPrivateKey(PRIV_HEX, datePassword(DATE)),
      tip_id_type: "organization",
    });
    const k = readKeyFile(p, datePassword(DATE));
    expect(k).toMatchObject({ tip_id: "tip://id/GB-0123456789abcdef", public_key: "cd".repeat(8), private_key: PRIV_HEX, tip_id_type: "organization" });
    expect(isEncryptedKeyFile(k.doc)).toBe(true);
  });

  test("refuses a v2 file without the date instead of guessing", () => {
    const p = write("org.tip.json", { version: KEY_FILE_EXPORT.VERSION, tipId: "x", publicKey: "y", encrypted: "zz" });
    expect(() => readKeyFile(p)).toThrow(/incorporation date is required/);
  });

  test("still opens v1 plaintext files (seed backups, node keys, VP keys)", () => {
    const p = write("vp.tip.json", { v: 1, type: "vp", vp_id: "tip://vp/US-1", public_key: "pk", private_key: "sk" });
    expect(readKeyFile(p)).toMatchObject({ tip_id: "tip://vp/US-1", public_key: "pk", private_key: "sk" });
    expect(readKeyFile(p, "ignored").private_key).toBe("sk");
  });

  test("rejects a file with no keypair", () => {
    const p = write("bad.tip.json", { v: 1, public_key: "pk" });
    expect(() => readKeyFile(p)).toThrow(/not a keypair file/);
  });
});

describe("recovery phrase vectors", () => {
  test("the wordlist is the published BIP39 English list", () => {
    const list = fs.readFileSync(path.join(SHARED, "bip39-english.txt"));
    expect(crypto.createHash("sha256").update(list).digest("hex")).toBe(VECTORS.wordlist_sha256);
  });

  test.each(VECTORS.phrases)("entropy $entropy gives its BIP39 phrase", ({ entropy, phrase }) => {
    expect(entropyToPhrase(Buffer.from(entropy, "hex"))).toBe(phrase);
    expect(checkPhrase(phrase)).toEqual({ ok: true, phrase });
  });

  test.each(VECTORS.checks)("checkPhrase($input)", ({ input, ok, phrase, reason }) => {
    const r = checkPhrase(input);
    expect(r.ok).toBe(ok);
    if (ok) expect(r.phrase).toBe(phrase);
    else expect(r.reason).toBe(reason);
  });

  test("the fixed salt and IV lock gives the exact vector bytes and opens again", () => {
    const { private_key_hex: priv, phrase, salt_hex: salt, iv_hex: iv, encrypted } = VECTORS.lock;
    expect(encryptPrivateKey(priv, phrase, Buffer.from(salt, "hex"), Buffer.from(iv, "hex"))).toBe(encrypted);
    expect(decryptPrivateKey(encrypted, phrase)).toBe(priv);
    expect(() => decryptPrivateKey(encrypted, VECTORS.phrases[1].phrase)).toThrow();
  });

  test("the VP's WebCrypto code opens the vector with the phrase", async () => {
    await expect(vpDecrypt(VECTORS.lock.encrypted, PHRASE)).resolves.toBe(VECTORS.lock.private_key_hex);
  });

  test("generatePhrase gives 12 valid words and a new phrase each time", () => {
    const a = generatePhrase();
    const b = generatePhrase();
    expect(a.split(" ")).toHaveLength(12);
    expect(checkPhrase(a)).toEqual({ ok: true, phrase: a });
    expect(a).not.toBe(b);
  });

  test("unknown_word reports the position and never echoes the word", () => {
    const r = checkPhrase(VECTORS.checks[3].input);
    expect(r).toEqual({ ok: false, reason: "unknown_word", position: 12 });
  });
});

describe("readKeyFile with a recovery phrase (v3)", () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-key-file-v3-")); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  function writeV3(encrypted = encryptPrivateKey(PRIV_HEX, PHRASE)) {
    const p = path.join(dir, "org.tip.json");
    fs.writeFileSync(p, JSON.stringify({
      version: KEY_FILE_EXPORT.PHRASE_VERSION,
      lock: KEY_FILE_EXPORT.PHRASE_LOCK,
      tipId: "tip://id/GB-0123456789abcdef",
      publicKey: "cd".repeat(8),
      encrypted,
      tip_id_type: "organization",
    }));
    return p;
  }

  test("opens with the phrase, however it is typed", () => {
    const p = writeV3();
    const numbered = PHRASE.toUpperCase().split(" ").map((w, i) => `${i + 1}. ${w}`).join("\n");
    for (const input of [PHRASE, numbered]) {
      const k = readKeyFile(p, input);
      expect(k).toMatchObject({ tip_id: "tip://id/GB-0123456789abcdef", private_key: PRIV_HEX, tip_id_type: "organization" });
      expect(isEncryptedKeyFile(k.doc)).toBe(true);
      expect(isPhraseKeyFile(k.doc)).toBe(true);
    }
  });

  test("opens a file the VP app locks with the phrase", async () => {
    const p = writeV3(await vpEncrypt(PRIV_HEX, PHRASE));
    expect(readKeyFile(p, PHRASE).private_key).toBe(PRIV_HEX);
  });

  test("asks for the 12 words when none are given", () => {
    expect(() => readKeyFile(writeV3())).toThrow(/recovery phrase .*12 words are required/);
  });

  test("a typo gives a clear message before any decrypt", () => {
    const p = writeV3();
    const words = PHRASE.split(" ");
    expect(() => readKeyFile(p, words.slice(0, 11).join(" "))).toThrow(/must be 12 words, got 11/);
    expect(() => readKeyFile(p, [...words.slice(0, 11), "abovee"].join(" "))).toThrow(/Word 12 .* not on the word list/);
    expect(() => readKeyFile(p, [...words.slice(0, 11), "zoo"].join(" "))).toThrow(/do not fit together/);
    expect(() => readKeyFile(p, "11112025")).toThrow(/must be 12 words, got 0/);
  });

  test("a valid phrase that is not this file's fails closed", () => {
    expect(() => readKeyFile(writeV3(), VECTORS.phrases[1].phrase)).toThrow(/These words do not open/);
  });

  test("v2 files still open with the date next to v3", () => {
    const p = path.join(dir, "old.tip.json");
    fs.writeFileSync(p, JSON.stringify({
      version: KEY_FILE_EXPORT.VERSION, tipId: "x", publicKey: "y",
      encrypted: encryptPrivateKey(PRIV_HEX, datePassword(DATE)),
    }));
    expect(isPhraseKeyFile(JSON.parse(fs.readFileSync(p, "utf8")))).toBe(false);
    expect(readKeyFile(p, datePassword(DATE)).private_key).toBe(PRIV_HEX);
  });
});
