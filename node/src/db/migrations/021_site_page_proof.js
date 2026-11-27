// Node-local, off-DAG. Each indexed page keeps its Merkle proof, built once on
// the pack worker, so a page read never rebuilds the snapshot's tree. Pages
// indexed before this column are dropped with their ingest state, so the
// ingest job re-indexes them (with proofs) from their packs.

"use strict";

const PAGE = "site_page";
const INGEST = "site_ingest";
const COLUMN_NAME = "proof";

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable(PAGE))) return;
  if (await knex.schema.hasColumn(PAGE, COLUMN_NAME)) return;
  await knex.schema.table(PAGE, t => {
    t.text(COLUMN_NAME).nullable();
  });
  await knex(PAGE).del();
  if (await knex.schema.hasTable(INGEST)) await knex(INGEST).del();
};

exports.down = async (knex) => {
  if (!(await knex.schema.hasTable(PAGE))) return;
  if (!(await knex.schema.hasColumn(PAGE, COLUMN_NAME))) return;
  await knex.schema.table(PAGE, t => {
    t.dropColumn(COLUMN_NAME);
  });
};
