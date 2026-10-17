// consensus-affecting: org_members.invited_claim is in the canonical row
// (strip-when-absent, so rows written before this column hash as before).
// It holds the org's signed invited_at, which the replay guard matches
// exactly; invited_at itself stays the invite tx's timestamp.

"use strict";

const TABLE_NAME = "org_members";
const COLUMN = "invited_claim";

exports.up = async (knex) => {
  if (!(await knex.schema.hasColumn(TABLE_NAME, COLUMN))) {
    await knex.schema.table(TABLE_NAME, t => { t.bigInteger(COLUMN).nullable(); });
  }
};

exports.down = async (knex) => {
  if (await knex.schema.hasColumn(TABLE_NAME, COLUMN)) {
    await knex.schema.table(TABLE_NAME, t => { t.dropColumn(COLUMN); });
  }
};
