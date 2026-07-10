/**
 * @file @tip-protocol/node/src/consensus/tx-owner.js
 * @description Owner-chain resolution: every tx belongs to the chain of the
 * ENTITY THAT SIGNED IT. Derived from the same signature contracts the
 * dispatcher verifies against (schemas/_common resolveSignerEntity), so
 * ownership and signature verification can never disagree.
 *
 * tx.prev semantics (owner-chain model):
 *   prev[0] , the owner's chain head (STRICT: commit-validated)
 *   prev[1] , advisory anchor (subject/counterparty head; existence only)
 *
 * Special chains:
 *   COMMITTEE_ROTATION  -> the rotation chain (rotations already form a
 *                          chain-of-trust by rotation_number; prev[0]
 *                          formalizes it as the previous rotation tx)
 *   GENESIS             -> no owner (the root)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES } = require("../../../shared/constants");
const { resolveSignerEntity } = require("../schemas/_common");
const { SCHEMA_FOR_TX_TYPE } = require("../schemas/_schema-map");

const ROTATION_CHAIN = Object.freeze({ entityType: "rotation", entityId: "committee" });

/**
 * The chain a tx belongs to.
 * @param {Object} tx
 * @returns {{entityType: string, entityId: string}|null}  null = no owner
 *   (GENESIS, or a tx whose contract cannot resolve , the signature
 *   dispatcher rejects those independently).
 */
function ownerOf(tx) {
  const tt = tx?.tx_type;
  if (!tt || tt === "GENESIS") return null;   // genesis is the root, not in TX_TYPES
  if (tt === TX_TYPES.COMMITTEE_ROTATION) return ROTATION_CHAIN;
  return resolveSignerEntity(tx, SCHEMA_FOR_TX_TYPE[tt] ?? null);
}

/** Stable string key for head maps / the owner_heads canonical table. */
function ownerKey(owner) {
  return `${owner.entityType}:${owner.entityId}`;
}

module.exports = { ownerOf, ownerKey, ROTATION_CHAIN };
