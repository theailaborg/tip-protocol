// operated_by: the TIP-ID of the identity (person or organization) responsible
// for a node. Nullable because genesis members predate the field and carry no
// operator. The verification_providers column is reserved: the VP registration
// path does not write it yet, but adding both columns in one migration avoids a
// second schema change on a live chain.

"use strict";

const COLUMN_NAME = "operated_by";
const TABLES = ["nodes", "verification_providers"];

exports.up = async (knex) => {
  for (const table of TABLES) {
    if (!(await knex.schema.hasTable(table))) continue;
    if (await knex.schema.hasColumn(table, COLUMN_NAME)) continue;
    await knex.schema.table(table, t => {
      t.string(COLUMN_NAME, 512).nullable();
    });
  }
};

exports.down = async (knex) => {
  for (const table of TABLES) {
    if (!(await knex.schema.hasTable(table))) continue;
    if (!(await knex.schema.hasColumn(table, COLUMN_NAME))) continue;
    await knex.schema.table(table, t => {
      t.dropColumn(COLUMN_NAME);
    });
  }
};
