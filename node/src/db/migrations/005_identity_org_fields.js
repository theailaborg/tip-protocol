// org_type on identities: the legal form as the jurisdiction names it. Public
// registry data, unlike the registration number and incorporation date, which
// stay hashed into dedup_hash and never land on chain in the clear. Nullable:
// persons never carry it, and organizations registered before this migration
// have none.
//
// 128 rather than the 64 the validator enforces: widening a column later needs
// a migration, loosening the regex does not, so the headroom lives here.

"use strict";

const TABLE_NAME = "identities";
const COLUMNS = [
  { name: "org_type", length: 128 },
];

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  for (const col of COLUMNS) {
    if (await knex.schema.hasColumn(TABLE_NAME, col.name)) continue;
    await knex.schema.table(TABLE_NAME, t => {
      t.string(col.name, col.length).nullable();
    });
  }
};

exports.down = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  for (const col of COLUMNS) {
    if (!(await knex.schema.hasColumn(TABLE_NAME, col.name))) continue;
    await knex.schema.table(TABLE_NAME, t => {
      t.dropColumn(col.name);
    });
  }
};
