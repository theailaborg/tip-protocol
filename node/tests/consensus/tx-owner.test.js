/**
 * @file tests/consensus/tx-owner.test.js
 * @description ownerOf(tx): every emittable tx type resolves to the chain
 * of its SIGNING entity, derived from the same contracts signature
 * verification uses. The table below is the protocol's ownership spec ,
 * a contract change that silently moves a type's owner breaks here.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { TX_TYPES } = require(path.resolve(__dirname, "../../../shared/constants"));
const { ownerOf, ownerKey, ROTATION_CHAIN } =
  require(path.resolve(__dirname, "../../src/consensus/tx-owner"));

const ID = "tip://id/US-aabbccddeeff0011";
const VP = "tip://vp/US-a47ca857e68d9b9f";
const NODE = "tip://node/1122334455667788";

// tx_type -> [data fixture, expected entityType, expected entityId]
const OWNER_SPEC = {
  [TX_TYPES.REGISTER_IDENTITY]: [{ vp_id: VP }, "vp", VP],
  [TX_TYPES.UPDATE_PROFILE]: [{ tip_id: ID }, "identity", ID],
  [TX_TYPES.LINK_PLATFORM]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.UNLINK_PLATFORM]: [{ tip_id: ID }, "identity", ID],
  [TX_TYPES.KEY_ROTATED]: [{ tip_id: ID }, "identity", ID],
  [TX_TYPES.KEY_RECOVERY]: [{ vp_id: VP }, "vp", VP],
  [TX_TYPES.PRESCAN_REVIEW_TRIGGERED]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.PRESCAN_REVIEW_DISMISSED]: [{ reviewer_tip_id: ID }, "identity", ID],
  [TX_TYPES.PRESCAN_REVIEW_CONFIRMED]: [{ reviewer_tip_id: ID }, "identity", ID],
  [TX_TYPES.PRESCAN_COMPLETED]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.BIND_DOMAIN]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.UNBIND_DOMAIN]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.REGISTER_CONTENT]: [{ signer_tip_id: ID }, "identity", ID],
  [TX_TYPES.UPDATE_ORIGIN]: [{ author_tip_id: ID }, "identity", ID],
  [TX_TYPES.CONTENT_RETRACTED]: [{ author_tip_id: ID }, "identity", ID],
  [TX_TYPES.CONTENT_VERIFIED]: [{ verifier_tip_id: ID }, "identity", ID],
  [TX_TYPES.AI_CLASSIFIER_RESULT]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.JURY_SUMMONS]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.JURY_VOTE_COMMIT]: [{ juror_tip_id: ID }, "identity", ID],
  [TX_TYPES.JURY_VOTE_REVEAL]: [{ juror_tip_id: ID }, "identity", ID],
  [TX_TYPES.ADJUDICATION_RESULT]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.APPEAL_RESULT]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.SCORE_UPDATE]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.REVOKE_VOLUNTARY]: [{ issuing_vp_id: VP }, "vp", VP],
  [TX_TYPES.REVOKE_VP]: [{ issuing_vp_id: VP }, "vp", VP],
  [TX_TYPES.REVOKE_DECEASED]: [{ issuing_vp_id: VP }, "vp", VP],
  [TX_TYPES.REVOKE_DEVICE]: [{ issuing_vp_id: VP }, "vp", VP],
  [TX_TYPES.VP_REGISTERED]: [{ approving_vp_id: VP }, "vp", VP],
  [TX_TYPES.NODE_REGISTERED]: [{ approving_vp_id: VP }, "vp", VP],
  [TX_TYPES.NODE_ENDPOINT_UPDATED]: [{ node_id: NODE }, "node", NODE],
  [TX_TYPES.INTEREST_REGISTERED]: [{ approving_vp_id: VP }, "vp", VP],
};

describe("ownerOf , the ownership spec", () => {
  for (const [txType, [data, entityType, entityId]] of Object.entries(OWNER_SPEC)) {
    test(`${txType} -> ${entityType}`, () => {
      expect(ownerOf({ tx_type: txType, data })).toEqual({ entityType, entityId });
    });
  }

  test("COMMITTEE_ROTATION -> the rotation chain, regardless of proposer", () => {
    expect(ownerOf({ tx_type: TX_TYPES.COMMITTEE_ROTATION, data: { node_id: NODE } }))
      .toEqual(ROTATION_CHAIN);
  });

  test("GENESIS has no owner", () => {
    expect(ownerOf({ tx_type: "GENESIS", data: {} })).toBeNull();
  });

  test("multi-mode APPEAL_FILED: user appeal -> appellant; auto-escalation -> node", () => {
    expect(ownerOf({ tx_type: TX_TYPES.APPEAL_FILED, data: { appellant_tip_id: ID } }))
      .toEqual({ entityType: "identity", entityId: ID });
    expect(ownerOf({ tx_type: TX_TYPES.APPEAL_FILED, data: { appellant_tip_id: "SYSTEM_AUTO_ESCALATION", node_id: NODE } }))
      .toEqual({ entityType: "node", entityId: NODE });
  });

  test("missing owner field -> null (signature dispatch rejects these independently)", () => {
    expect(ownerOf({ tx_type: TX_TYPES.REGISTER_CONTENT, data: {} })).toBeNull();
  });

  test("ownerKey is stable and collision-scoped by entity type", () => {
    expect(ownerKey({ entityType: "identity", entityId: ID })).toBe(`identity:${ID}`);
    expect(ownerKey(ROTATION_CHAIN)).toBe("rotation:committee");
  });
});
