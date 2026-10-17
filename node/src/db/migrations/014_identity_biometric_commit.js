// `identities` is projected into state_merkle_root via _canonIdentity, which emits
// `biometric_commit` with STRIP-WHEN-ABSENT semantics (`|| undefined`): canonicalJson
// omits undefined keys, so an identity that never bound a commit canonicalizes
// byte-identically to the pre-feature bytes and its state_merkle_root leaf is
// UNCHANGED. Adding this nullable column is therefore a SAFE ROLLING UPGRADE on a
// live chain with existing identities (they stay null → omitted → same root); only
// identities that carry a commit contribute it. (See dag.js _canonIdentity. This is
// the same field-set/strip semantics as the signing-payload rule in
// register-identity.js — here applied to the canonical-state projection.)

"use strict";

const TABLE = "identities";
const COLUMN = "biometric_commit";

exports.up = async (knex) => {
  if (!(await knex.schema.hasColumn(TABLE, COLUMN))) {
    await knex.schema.alterTable(TABLE, t => {
      t.string(COLUMN, 64).nullable();
    });
  }
};

exports.down = async (knex) => {
  if (await knex.schema.hasColumn(TABLE, COLUMN)) {
    await knex.schema.alterTable(TABLE, t => {
      t.dropColumn(COLUMN);
    });
  }
};
