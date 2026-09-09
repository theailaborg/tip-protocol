// node-local: a chunked-upload session opened in per-part checksum mode. S3
// fixes the checksum algorithm per multipart upload at creation, so the node
// must remember it to mint checksum-bound part URLs and to complete correctly.

"use strict";

const TABLE_NAME = "upload_sessions";

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  if (!(await knex.schema.hasColumn(TABLE_NAME, "checksum_algorithm"))) {
    await knex.schema.table(TABLE_NAME, t => {
      t.string("checksum_algorithm", 8).nullable();
    });
  }
};

exports.down = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  if (!(await knex.schema.hasColumn(TABLE_NAME, "checksum_algorithm"))) return;
  await knex.schema.table(TABLE_NAME, t => {
    t.dropColumn("checksum_algorithm");
  });
};
