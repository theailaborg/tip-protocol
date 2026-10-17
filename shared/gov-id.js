/**
 * @file tip-protocol/shared/gov-id.js
 * @description Canonical form of a government / company registration identifier.
 *
 * One rule, shared by the ZK encoder and the org-registration validator. They
 * previously kept separate copies that disagreed on hyphens: a US EIN written
 * the way the IRS prints it (32-0727201) was refused by the validator while
 * hashing identically to its bare form.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// encodeGovId packs the canonical string into one BN128 field element, which
// caps it at 30 bytes. Anything longer is truncated there, so a caller able to
// refuse instead must use this bound rather than inventing its own.
const GOV_ID_MAX_CHARS = 30;

/** Uppercase, drop every separator: punctuation is presentation, not identity. */
function canonicalizeGovId(value) {
  return String(value).trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
}

module.exports = { canonicalizeGovId, GOV_ID_MAX_CHARS };
