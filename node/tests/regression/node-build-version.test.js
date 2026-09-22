/**
 * @file tests/regression/node-build-version.test.js
 * @description The protocol version is bound into the hashed genesis payload,
 * so it must never track the package version: bumping a release would change
 * genesis_hash and fail-stop every node at boot (2026-09-17). The node's own
 * build version is a separate value that is free to move every release.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");

const ROOT = path.resolve(__dirname, "../../..");
const { PROTOCOL } = require(path.join(ROOT, "shared/constants"));

describe("node build version is independent of the protocol version", () => {
  test("the protocol version is a frozen literal, not the package version", () => {
    const src = fs.readFileSync(path.join(ROOT, "shared/constants.js"), "utf8");
    const block = src.slice(src.indexOf("const PROTOCOL = Object.freeze("));
    const decl = block.slice(0, block.indexOf("});"));
    expect(decl).toMatch(/version:\s*"2\.0\.0"/);
    expect(decl).not.toMatch(/version:\s*require\(/);
    expect(PROTOCOL.version).toBe("2.0.0");
  });

  test("the genesis payload still hashes to the recorded genesis_hash", () => {
    const genesis = require(path.join(ROOT, "node/src/genesis"));
    const onDisk = JSON.parse(fs.readFileSync(path.join(ROOT, "genesis-data/genesis.json"), "utf8"));
    expect(genesis.getGenesisPayload().protocol.version).toBe("2.0.0");
    expect(genesis.validateGenesisBlock(onDisk)).toBe(true);
  });

  test("a release bump moves the node version and leaves the protocol version alone", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "node/package.json"), "utf8"));
    expect(pkg.version).not.toBe(PROTOCOL.version);
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+/);
  });

  test("TIP_BUILD_VERSION wins over the package version when the image carries one", () => {
    const configPath = path.join(ROOT, "node/src/config.js");
    const src = fs.readFileSync(configPath, "utf8");
    expect(src).toMatch(/nodeVersion:\s*process\.env\.TIP_BUILD_VERSION\s*\|\|/);
  });
});
