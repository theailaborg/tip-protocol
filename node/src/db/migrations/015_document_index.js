// node-local: off-DAG document near-duplicate index (advisory, never in
// state_merkle_root), derived from stored cf-doc-1 fingerprints.
//
// document_text: one row per document component with text: its whole-text hash
// (same wording in any format) and its cf-text-3 fingerprint, which also feeds
// the shared text bands.
// document_passage: one row per distinct passage key per document component,
// with the record's owner, so the number of owners holding a key is a count over
// the key's rows.

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
