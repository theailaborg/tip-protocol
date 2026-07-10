/**
 * @file @tip-protocol/node/src/schemas/_schema-map.js
 * @description THE tx_type → schema-module map. Consumers that dispatch on
 * a tx's schema (commit-handler signature verification, tx-owner chain
 * resolution) import this one map; tx types absent here resolve through
 * TX_SIGNATURE_REGISTRY (see _registry.js , a contract lives in exactly
 * one of the two, never both).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES } = require("../../../shared/constants");

const SCHEMA_FOR_TX_TYPE = Object.freeze({
  [TX_TYPES.REGISTER_CONTENT]: require("./content-register"),
  [TX_TYPES.REGISTER_IDENTITY]: require("./register-identity"),
  [TX_TYPES.BIND_DOMAIN]: require("./bind-domain"),
  [TX_TYPES.UPDATE_PROFILE]: require("./update-profile"),
  [TX_TYPES.PRESCAN_REVIEW_TRIGGERED]: require("./prescan-review-triggered"),
  [TX_TYPES.PRESCAN_REVIEW_DISMISSED]: require("./prescan-review-dismissed"),
  [TX_TYPES.PRESCAN_REVIEW_CONFIRMED]: require("./prescan-review-confirmed"),
  [TX_TYPES.PRESCAN_REVIEW_RECUSED]: require("./prescan-review-recused"),
  [TX_TYPES.PRESCAN_COMPLETED]: require("./prescan-completed"),
  [TX_TYPES.KEY_ROTATED]: require("./key-rotated"),
  [TX_TYPES.KEY_RECOVERY]: require("./key-recovery"),
  [TX_TYPES.INTEREST_REGISTERED]: require("./interest-registered"),
  [TX_TYPES.LINK_PLATFORM]: require("./link-platform"),
  [TX_TYPES.UNLINK_PLATFORM]: require("./unlink-platform"),
});

module.exports = { SCHEMA_FOR_TX_TYPE };
