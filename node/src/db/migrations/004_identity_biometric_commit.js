// consensus-affecting: `identities` is projected into state_merkle_root via
// _canonIdentity, which emits `biometric_commit` for EVERY identity (null for
// rows registered before this field). Because canonicalJson keeps null values,
// this changes each identity's canonical leaf — and thus state_merkle_root —
// even for pre-existing rows. Roll out COORDINATED (all nodes together /
// genesis-gated), NOT as a rolling upgrade, or old-vs-new nodes will fork.
// (Distinct from the signing-payload strip-rule in register-identity.js, which
// IS byte-identical when biometric_commit is absent — do not conflate the two.)

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
