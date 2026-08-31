// node-local: chunked-upload finalize outcome. The re-hash + promote after
// upload-complete outlives a proxied HTTP round-trip for large files, so the
// node tracks it on the session (uploading -> finalizing -> complete | failed)
// and keeps the media descriptor or the failure for the client to poll.

"use strict";

const TABLE_NAME = "upload_sessions";

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  if (!(await knex.schema.hasColumn(TABLE_NAME, "state"))) {
    await knex.schema.table(TABLE_NAME, t => {
      t.string("state", 16).notNullable().defaultTo("uploading");
    });
  }
  if (!(await knex.schema.hasColumn(TABLE_NAME, "result_json"))) {
    await knex.schema.table(TABLE_NAME, t => {
      t.text("result_json").nullable();
    });
  }
};

exports.down = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  for (const col of ["result_json", "state"]) {
    if (!(await knex.schema.hasColumn(TABLE_NAME, col))) continue;
    await knex.schema.table(TABLE_NAME, t => {
      t.dropColumn(col);
    });
  }
};
