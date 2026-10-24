/**
 * @file scripts/org-key-file.js
 * @description The two files register-org.js writes for an organization: the
 * key file that is delivered to the organization, and the registration record
 * that stays with the Lab.
 *
 * The key file is locked with the date of incorporation, so it must never carry
 * that date. An earlier revision wrote `incorporated` into the clear envelope
 * for audit, which put the unlock date next to the ciphertext: anyone holding
 * the file could open it without looking anything up. The dedup inputs still
 * have to stay auditable (they cannot be recovered from the hash), so they go
 * into a separate record that make-secure-bundle.sh never picks up (it only
 * stages org/*.tip.json).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { KEY_FILE_EXPORT } = require("../shared/constants");
const { datePassword, encryptPrivateKey } = require("../shared/key-file");

const RECORD_SUFFIX = ".registration.json";

// Every spelling of the date a reader could type into the unlock prompt.
function dateForms(isoDate) {
  const [y, m, d] = String(isoDate).split("-");
  return [`${y}-${m}-${d}`, `${m}/${d}/${y}`, `${m}-${d}-${y}`, `${d}/${m}/${y}`, `${d}-${m}-${y}`, datePassword(isoDate)];
}

/**
 * Throw if the delivered file carries the date that unlocks it: a date-named
 * field, or any field whose value is the date in one of the forms above.
 * Values are compared exactly, not searched as substrings: the key hex,
 * the ciphertext and an ISO `exportedAt` written on the incorporation day can
 * contain those digits by chance, and a false alarm here would fire after the
 * identity is already registered and lose the key.
 */
function assertNoUnlockDate(keyFile, isoDate) {
  const forms = new Set(dateForms(isoDate));
  for (const [k, v] of Object.entries(keyFile)) {
    if (/^(incorporated|incorporation_date|dob|date_of_incorporation)$/i.test(k)) {
      throw new Error(`org key file has a "${k}" field; it would carry its own unlock date`);
    }
    if (typeof v === "string" && forms.has(v.trim())) {
      throw new Error(`org key file field "${k}" holds its own unlock date`);
    }
  }
}

/**
 * Build the delivered key file (tip-key-export-v2, the VP app's format) and
 * the Lab-only registration record.
 *
 * @returns {{ keyFile: object, keyFileText: string, record: object, recordText: string }}
 */
function buildOrgKeyFiles({
  tipId, keypair, incorporated, vpId, orgName, region, scheme, regNumber,
  dedupHash, registeredAt, registeredOn, exportedAt,
}) {
  const keyFile = {
    version: KEY_FILE_EXPORT.VERSION,
    tipId,
    publicKey: keypair.publicKey,
    encrypted: encryptPrivateKey(keypair.privateKey, datePassword(incorporated)),
    algorithm: KEY_FILE_EXPORT.ALGORITHM,
    sigAlgorithm: KEY_FILE_EXPORT.SIG_ALGORITHM,
    tip_id_type: "organization",
    vp_id: vpId,
    display_name: orgName,
    region,
    registered_at: registeredAt,
    registered_on: registeredOn,
    exportedAt,
    warning: "Locked with the date of incorporation (MM/DD/YYYY, as registered). There is no recovery if it is lost.",
  };
  assertNoUnlockDate(keyFile, incorporated);
  const keyFileText = JSON.stringify(keyFile, null, 2);

  // Recorded so the dedup inputs stay auditable: they cannot be recovered from
  // the hash, and re-deriving them wrongly would mint a second identity. The
  // canonical value is what was hashed; the as-provided form is kept so a later
  // audit can read it back against the certificate it was copied from.
  const record = {
    lab_only: "Holds the date that unlocks the organization key file. Never deliver, attach or commit.",
    tip_id: tipId,
    display_name: orgName,
    region,
    registration_number: scheme.normalized,
    registration_number_as_provided: regNumber,
    registration_scheme: scheme.name,
    incorporated,
    dedup_hash: dedupHash,
    vp_id: vpId,
    registered_at: registeredAt,
    registered_on: registeredOn,
  };
  return { keyFile, keyFileText, record, recordText: JSON.stringify(record, null, 2) };
}

// <dir>/id-US-abc.tip.json -> <dir>/id-US-abc.registration.json
function recordPathFor(keyFilePath) {
  return String(keyFilePath).replace(/\.tip\.json$/, "") + RECORD_SUFFIX;
}

module.exports = { buildOrgKeyFiles, assertNoUnlockDate, recordPathFor, RECORD_SUFFIX };
