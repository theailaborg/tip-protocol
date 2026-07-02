/**
 * @file tests/config-secret.test.js
 * @description Node signing key loaded from a mounted secret file
 * (`TIP_NODE_PRIVATE_KEY_FILE`) when set, else from the env value. The file
 * path wins so production can keep the key off the process environment
 * (Docker/K8s secrets), while dev keeps using the plain env value.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");
const PC = require(path.resolve(__dirname, "../../shared/protocol-constants"));
const { getGenesisPayload } = require(path.resolve(__dirname, "../src/genesis"));
const { loadConfig } = require(path.resolve(__dirname, "../src/config"));

const KEY = "TIP_NODE_PRIVATE_KEY";
let _n = 0;

// loadConfig reads CONTENT_LIMITS getters, which throw until ProtocolConstants
// is initialized from the genesis payload.
beforeAll(() => { PC.init(getGenesisPayload().protocol_constants); });

describe("node key: _FILE secret loading", () => {
  let tmp;
  afterEach(() => {
    delete process.env[KEY];
    delete process.env[`${KEY}_FILE`];
    if (tmp) { try { fs.unlinkSync(tmp); } catch { /* ignore */ } tmp = null; }
  });

  test("reads the key from TIP_NODE_PRIVATE_KEY_FILE, trimming file whitespace", () => {
    tmp = path.join(os.tmpdir(), `tip-secret-${process.pid}-${_n++}`);
    fs.writeFileSync(tmp, "  abc123\n");           // leading space + trailing newline
    process.env[`${KEY}_FILE`] = tmp;
    process.env[KEY] = "SHOULD_BE_IGNORED";        // file wins over env
    expect(loadConfig().nodePrivateKey).toBe("abc123");
  });

  test("falls back to the env value when _FILE is unset", () => {
    process.env[KEY] = "envKey";
    expect(loadConfig().nodePrivateKey).toBe("envKey");
  });

  test("null when neither _FILE nor the env value is set", () => {
    expect(loadConfig().nodePrivateKey).toBeNull();
  });

  test("throws a clear error when _FILE points at a missing file", () => {
    process.env[`${KEY}_FILE`] = "/no/such/secret/path";
    expect(() => loadConfig()).toThrow(/TIP_NODE_PRIVATE_KEY_FILE.*unreadable/);
  });
});

describe("node key: .tip.json credentials file", () => {
  let cred;
  afterEach(() => {
    delete process.env.TIP_NODE_CREDENTIALS_FILE;
    delete process.env[KEY];
    if (cred) { try { fs.unlinkSync(cred); } catch { /* ignore */ } cred = null; }
  });

  test("loads both keys from a .tip.json and ignores inline env", () => {
    cred = path.join(os.tmpdir(), `tip-cred-${process.pid}-${_n++}.tip.json`);
    fs.writeFileSync(cred, JSON.stringify({ private_key: "PRIVhex", public_key: "PUBhex" }));
    process.env.TIP_NODE_CREDENTIALS_FILE = cred;
    process.env[KEY] = "SHOULD_BE_IGNORED";      // credentials file wins
    const c = loadConfig();
    expect(c.nodePrivateKey).toBe("PRIVhex");
    expect(c.nodePublicKey).toBe("PUBhex");
  });

  test("throws a clear error when the credentials file is missing", () => {
    process.env.TIP_NODE_CREDENTIALS_FILE = "/no/such/tip.json";
    expect(() => loadConfig()).toThrow(/TIP_NODE_CREDENTIALS_FILE.*unreadable or not valid JSON/);
  });

  test("throws when the credentials file is not valid JSON", () => {
    cred = path.join(os.tmpdir(), `tip-cred-bad-${process.pid}-${_n++}.tip.json`);
    fs.writeFileSync(cred, "not json {{{");
    process.env.TIP_NODE_CREDENTIALS_FILE = cred;
    expect(() => loadConfig()).toThrow(/not valid JSON/);
  });
});
