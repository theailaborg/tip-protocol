// node-local: off-DAG document near-duplicate index (advisory, never in state_merkle_root).
// Owners per passage key are counted over document_passage at query time.

"use strict";

const TEXT = "document_text";
const PASSAGE = "document_passage";

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable(TEXT))) {
    await knex.schema.createTable(TEXT, (t) => {
      t.string("tip_ctid", 512).notNullable();
      t.integer("component_idx").notNullable();
      t.string("profile", 64).notNullable();
      t.string("text_hash", 64).notNullable();
      t.integer("chars").notNullable();
      t.text("text");
      t.primary(["tip_ctid", "component_idx"]);
      t.index(["profile", "text_hash"], "idx_document_text_hash");
    });
  }
  if (!(await knex.schema.hasTable(PASSAGE))) {
    await knex.schema.createTable(PASSAGE, (t) => {
      t.string("profile", 64).notNullable();
      t.string("passage_key", 16).notNullable();
      t.string("owner", 512).notNullable();
      t.string("tip_ctid", 512).notNullable();
      t.integer("component_idx").notNullable();
      t.integer("unit");
      t.primary(["profile", "passage_key", "owner", "tip_ctid", "component_idx"]);
    });
  }
};

exports.down = async (knex) => {
  await knex.schema.dropTableIfExists(PASSAGE);
  await knex.schema.dropTableIfExists(TEXT);
};
