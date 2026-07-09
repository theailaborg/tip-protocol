// node-local (index-only DDL on `content`: no new columns, no data changes,
// state_merkle_root is unaffected — nodes can apply this independently)

"use strict";

// Register-time near-duplicate warning, step 0 (exact match): the register
// path looks up existing content by exact normalized content_hash to warn
// when byte-different but normalization-identical content is already
// registered ("I am Vishal" vs "i am VISHAL." both normalize to "iamvishal").
// The ctid primary key can't serve this lookup — the ctid embeds
// origin_code + signer, so the same content registered by a different
// author or under a different origin always has a different ctid.

exports.up = async (knex) => {
  await knex.schema.alterTable("content", t => {
    t.index(["content_hash"], "idx_content_content_hash");
  });
};

exports.down = async (knex) => {
  await knex.schema.alterTable("content", t => {
    t.dropIndex(["content_hash"], "idx_content_content_hash");
  });
};
