"use strict";

// Initialize protocol constants once per test file before any module that
// reads from backward-compat accessors (CONSENSUS, NETWORK, JURY, ...) is
// required. shared/protocol-constants.js no longer auto-loads on first
// access, so this must run before suite imports.

const path = require("path");
const PC = require(path.resolve(__dirname, "../../shared/protocol-constants"));
const { getGenesisPayload } = require(path.resolve(__dirname, "../src/genesis"));

PC.init(getGenesisPayload().protocol_constants);
