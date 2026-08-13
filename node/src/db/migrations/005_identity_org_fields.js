// org_type and lei on identities. Both are public registry data about an
// organization, unlike the registration number and incorporation date, which
// stay hashed into dedup_hash and never land on chain in the clear. Nullable:
// persons never carry them, and organizations registered before this migration
// have neither.
//
// org_type is 128 rather than the 64 the validator enforces: widening a column
// later needs a migration, loosening the regex does not, so the headroom lives
// here. lei is exactly 20 because ISO 17442 fixes it at 20.

"use strict";

const TABLE_NAME = "identities";
const COLUMNS = [
  { name: "org_type", length: 128 },
  { name: "lei", length: 20 },
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
