/**
 * @file tip-protocol/shared/org-id-schemes.js
 * @description Which identifier IS a company's identity, per jurisdiction.
 *
 * Lives beside gov-id.js so the accepted shapes and the canonical form that
 * gets hashed are read from one place. Patterns match the CANONICAL value, so
 * a partner may paste the number however their certificate prints it.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { canonicalizeGovId, GOV_ID_MAX_CHARS } = require("./gov-id");

// The dedup hash is Poseidon(reg_no, incorporation_date, country). The circuit
// cannot tell a company number from a tax number, so "one company = one
// identity" only holds if every registration for a country derives reg_no the
// same way. One Indian company legitimately holds a CIN, a PAN and several
// GSTINs: each would mint a separate, permanent, un-reconcilable identity.
//
// So: exactly one accepted identifier per jurisdiction, and reject anything
// that does not match its shape. A wrong value here cannot be detected later
// (the hash is one-way) and cannot be corrected (the entry is committed).
const ORG_ID_SCHEMES = Object.freeze({
  GB: [{ key: "company", name: "company number (Companies House)", re: /^[A-Z0-9]{8}$/,
         hint: "8 characters, keep leading zeros (e.g. 01234567). Not the VAT or UTR number" }],
  IN: [{ key: "company", name: "CIN", re: /^[A-Z0-9]{21}$/,
         hint: "21 characters (e.g. U74999MH2020PTC123456)" },
       { key: "llp", name: "LLPIN", re: /^[A-Z0-9]{7}$/,
         hint: "7 characters; LLPs are never issued a CIN" }],
  US: [{ key: "company", name: "EIN (federal)", re: /^\d{9}$/,
         hint: "9 digits, IRS-issued. NOT a state entity number: state numbers repeat across states" },
       { key: "state", name: "namespaced state number", re: /^US[A-Z]{2}[A-Z0-9]+$/,
         hint: "only when no EIN exists, e.g. US-DE-1234567" }],
  AU: [{ key: "company", name: "ACN", re: /^\d{9}$/, hint: "9 digits" }],
  FR: [{ key: "company", name: "SIREN", re: /^\d{9}$/, hint: "9 digits" }],
  JP: [{ key: "company", name: "Corporate Number", re: /^\d{13}$/, hint: "13 digits" }],
  DE: [{ key: "company", name: "court-qualified HRB/HRA", re: /^DEHR[AB]\d+[A-Z]{2,5}$/,
         hint: "HRB alone is only unique per local court, e.g. DE-HRB-12345-MUC" }],
});

// Returns the matching scheme, or throws with what the jurisdiction expects.
// An unlisted country stops the run rather than guessing: adding a row is a
// deliberate act (confirm whether that country has ONE national registry).
function resolveIdScheme(country, regNumber) {
  const schemes = ORG_ID_SCHEMES[country];
  if (!schemes) {
    throw new Error(
      `no registration-number scheme defined for ${country}.\n` +
      `    Add it to ORG_ID_SCHEMES after confirming that country's single national\n` +
      `    company registry. Do not substitute a tax or state identifier.`);
  }
  const normalized = canonicalizeGovId(regNumber);
  // encodeGovId truncates past this bound. Two companies sharing the first
  // GOV_ID_MAX_CHARS characters would then collapse into one permanent
  // identity, so refuse the value rather than silently shortening it.
  if (normalized.length > GOV_ID_MAX_CHARS) {
    throw new Error(
      `"${regNumber}" normalises to ${normalized.length} characters for ${country}, ` +
      `maximum ${GOV_ID_MAX_CHARS}.\n` +
      `    Longer values are truncated when hashed, which would merge two distinct\n` +
      `    companies into a single permanent identity.`);
  }
  const hit = schemes.find(s => s.re.test(normalized));
  if (!hit) {
    const opts = schemes.map(s => `      ${s.name}: ${s.hint}`).join("\n");
    throw new Error(
      `"${regNumber}" is not a valid registration number for ${country}.\n` +
      `    ${country} accepts:\n${opts}`);
  }
  return { ...hit, normalized };
}

module.exports = { ORG_ID_SCHEMES, resolveIdScheme };
