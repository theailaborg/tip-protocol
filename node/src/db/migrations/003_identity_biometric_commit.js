// consensus-affecting: `identities` is projected into state_merkle_root via
// _canonIdentity, so every node MUST apply this to carry biometric_commit on
// the canonical row. Optional nullable hex column — existing rows get NULL
// (strip-rule: identities registered without a biometric_commit still produce
// the same canonical bytes as before this column existed).

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
