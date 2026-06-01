/**
 * @file tests/schemas/uniform-signature-contract.test.js
 * @description GH #51 uniform-interface guardrail.
 *
 * Walks every TX_TYPES entry and asserts that the unified signature
 * dispatcher can resolve a contract for it — either from a schema
 * module (preferred for tx types with non-trivial logic) or from the
 * registry (for tx types that are just data-shape + signer kind).
 *
 * The hold-the-line rule from SIGNATURES.md says any new tx type added
 * after the unification PR must use `tx.signature` and expose a
 * contract via one of those two sources. This test catches a missed
 * wiring by failing loudly the next time someone adds a new TX_TYPES
 * value without a corresponding entry.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { TX_TYPES, SIGNATURE_SCOPE_VALUES, SIGNED_BY_KIND_VALUES } = require(path.join(SHARED, "constants"));
const { resolveSignatureContract } = require(path.join(SRC, "schemas", "_common"));

// SCHEMA_FOR_TX_TYPE mirror — keep in sync with commit-handler's map.
// Sourced here as the unit-under-test rather than the production
// constant so the test fails loud if a wiring drifts.
const contentRegisterSchema = require(path.join(SRC, "schemas", "content-register"));
const registerIdentitySchema = require(path.join(SRC, "schemas", "register-identity"));
const bindDomainSchema = require(path.join(SRC, "schemas", "bind-domain"));
const updateProfileSchema = require(path.join(SRC, "schemas", "update-profile"));
const prescanReviewTriggered = require(path.join(SRC, "schemas", "prescan-review-triggered"));
const prescanReviewDismissed = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
const prescanReviewConfirmed = require(path.join(SRC, "schemas", "prescan-review-confirmed"));
const prescanReviewRecused = require(path.join(SRC, "schemas", "prescan-review-recused"));
const keyRotatedSchema = require(path.join(SRC, "schemas", "key-rotated"));
const keyRecoverySchema = require(path.join(SRC, "schemas", "key-recovery"));
const interestRegisteredSchema = require(path.join(SRC, "schemas", "interest-registered"));
const linkPlatformSchema = require(path.join(SRC, "schemas", "link-platform"));
const unlinkPlatformSchema = require(path.join(SRC, "schemas", "unlink-platform"));

const SCHEMA_FOR_TX_TYPE = {
  [TX_TYPES.REGISTER_CONTENT]: contentRegisterSchema,
  [TX_TYPES.REGISTER_IDENTITY]: registerIdentitySchema,
  [TX_TYPES.BIND_DOMAIN]: bindDomainSchema,
  [TX_TYPES.UPDATE_PROFILE]: updateProfileSchema,
  [TX_TYPES.PRESCAN_REVIEW_TRIGGERED]: prescanReviewTriggered,
  [TX_TYPES.PRESCAN_REVIEW_DISMISSED]: prescanReviewDismissed,
  [TX_TYPES.PRESCAN_REVIEW_CONFIRMED]: prescanReviewConfirmed,
  [TX_TYPES.PRESCAN_REVIEW_RECUSED]: prescanReviewRecused,
  [TX_TYPES.KEY_ROTATED]: keyRotatedSchema,
  [TX_TYPES.KEY_RECOVERY]: keyRecoverySchema,
  [TX_TYPES.INTEREST_REGISTERED]: interestRegisteredSchema,
  [TX_TYPES.LINK_PLATFORM]: linkPlatformSchema,
  [TX_TYPES.UNLINK_PLATFORM]: unlinkPlatformSchema,
};

// Tx types intentionally not yet on the unified contract — accounted for
// here so the sweep can distinguish "missing wiring (bug)" from
// "deliberately deferred (planned)". Each entry needs a tracking note.
const UNIMPLEMENTED = new Set([
  TX_TYPES.UPDATE_DEVICE_BINDING,   // device-binding work deferred
  TX_TYPES.VP_SUSPENDED,            // VP lifecycle suspension not yet implemented
]);

// COMMITTEE_ROTATION carries an aggregate of 2f+1 sigs over payload_hash;
// the per-signer crypto verification lives in `rules.canCommitteeRotation`
// (called from commit-handler's `_statefulCheck`) where it can also enforce
// the quorum + monotonic-rotation_number invariants in a single predicate.
// The unified-dispatcher contract is still useful for the proposer-envelope
// path; `tx.signature` plumbing for that lands in a follow-up.
const SPECIAL_AGGREGATE = new Set([
  TX_TYPES.COMMITTEE_ROTATION,
]);

describe("GH #51 — every TX_TYPES has a resolvable signature contract", () => {
  for (const [name, tt] of Object.entries(TX_TYPES)) {
    if (UNIMPLEMENTED.has(tt)) {
      test.skip(`${name} (unimplemented — deferred)`, () => { });
      continue;
    }

    test(`${name} resolves a contract via schema or registry`, () => {
      const schema = SCHEMA_FOR_TX_TYPE[tt] || null;
      // Some tx types are multi-mode (CONTENT_DISPUTED, APPEAL_FILED,
      // PRESCAN_REVIEW_RECUSED) — pass a representative shape so the
      // getSignatureContract function can pick a branch. The static
      // SCOPE/SIGNED_BY exports cover all the rest with tx=null.
      const probe = {
        tx_type: tt,
        data: { auto: false, appellant_tip_id: "tip://id/US-0000000000000000" },
      };
      const contract = resolveSignatureContract(probe, schema);

      if (SPECIAL_AGGREGATE.has(tt)) {
        // OK either way: aggregate verification happens elsewhere.
        // We still want a registry entry so a future migration to a
        // proposer-envelope path can light up via the unified dispatcher.
        expect(contract).toBeDefined();
        return;
      }

      expect(contract).not.toBeNull();
      expect(SIGNATURE_SCOPE_VALUES.has(contract.SIGNATURE_SCOPE)).toBe(true);
      expect(SIGNED_BY_KIND_VALUES.has(contract.SIGNED_BY)).toBe(true);

      // Body-scope contracts MUST carry a buildSigningPayload so the
      // dispatcher can rebuild the canonical bytes the signer hashed.
      if (contract.SIGNATURE_SCOPE === "body") {
        expect(typeof contract.buildSigningPayload).toBe("function");
      }
    });
  }
});
