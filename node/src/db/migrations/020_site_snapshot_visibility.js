// consensus-affecting: site_snapshots is canonical state. visibility is set only
// on private snapshots ("private"); public rows keep null, and their canonical
// form (and state-root leaf) omits the column.

"use strict";

const TABLE_NAME = "site_snapshots";
const COLUMN_NAME = "visibility";

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  if (await knex.schema.hasColumn(TABLE_NAME, COLUMN_NAME)) return;
  await knex.schema.table(TABLE_NAME, t => {
    t.string(COLUMN_NAME, 16).nullable();
  });
};

exports.down = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  if (!(await knex.schema.hasColumn(TABLE_NAME, COLUMN_NAME))) return;
  await knex.schema.table(TABLE_NAME, t => {
    t.dropColumn(COLUMN_NAME);
  });
};
