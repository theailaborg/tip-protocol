// node-local + consensus-affecting (full schema baseline)

"use strict";

// helpers (copied from knex-adapter.js — NOT imported)
function _id(t, col) { return t.string(col, 512); }
function _pk(t, col) { return t.string(col, 512).primary(); }

exports.up = async (knex) => {
  await knex.schema.createTable("transactions", t => {
    _pk(t, "tx_id");
    t.string("tx_type", 64).notNullable();
    t.text("data").notNullable();
    t.bigInteger("timestamp").notNullable();
    t.text("prev").notNullable().defaultTo("[]");
    t.text("signature").nullable();
    _id(t, "subject_tip_id").nullable();
    // local_inserted_at = this node's `nowMs()` when the row was written.
    // Per-node by design. NOT in canonicalTx / tx_id / state_merkle_root.
    // For chain-time use `transactions.timestamp` (the author-signed value
    // bound into tx_id). See `local_inserted_at` semantic in the file
    // header.
    t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
    t.index("tx_type", "idx_txs_type");
    t.index("timestamp", "idx_txs_ts");
    t.index("local_inserted_at", "idx_txs_local_inserted_at");
    t.index("subject_tip_id", "idx_txs_subject");
  });

  // GH #60: public_key + algorithm live in entity_keys (DID-style
  // single source of truth). root_public_key dropped (orphaned scaffold).
  await knex.schema.createTable("identities", t => {
    _pk(t, "tip_id");
    t.string("region", 8).notNullable().defaultTo("US");
    _id(t, "vp_id").nullable();
    t.string("verification_tier", 8).notNullable().defaultTo("T1");
    t.string("score_display_mode", 32).notNullable().defaultTo("TIER_ONLY");
    t.string("tip_id_type", 32).notNullable().defaultTo("personal");  // personal | organization
    t.integer("founding").notNullable().defaultTo(0);
    t.string("status", 32).notNullable().defaultTo("active");
    // Opt-in to be selected as an adjudicator across all protocol roles
    // (Protocol Review reviewer, Stage 2 jury, Stage 3 expert panel).
    // Runtime filters at selection time decide which role a consenting
    // user lands in (score, content category, conflict-of-interest).
    t.integer("reviewer_consent").notNullable().defaultTo(0);
    // Denormalised user-picked interest slugs (canonical sort, deduped).
    // Source of truth is the chain of UPDATE_PROFILE txs; this column
    // is the read-side projection for activity feed / discovery /
    // recommendation. JSON-encoded array of strings.
    t.text("interests").notNullable().defaultTo("[]");
    t.bigInteger("registered_at").notNullable();
    t.text("creator_name").nullable();
    _id(t, "tx_id").nullable();
    t.index("vp_id", "idx_id_vp");
    t.index("status", "idx_id_status");
    t.index("tip_id_type", "idx_id_type");
  });

  // GH #60 — entity_keys: single source of truth for (public_key,
  // algorithm) of every identity, node, and VP across all time. Same
  // pattern as W3C DID verificationMethod[] / X.509 cert chains /
  // WebAuthn credentials / JWKS keysets. Append-only with
  // valid_from_ts / valid_to_ts ranges; KEY_ROTATED / KEY_RECOVERY
  // close the active row and append a new one. Historical-signature
  // verification reads the row whose validity range covers
  // tx.timestamp; API-time verification reads the active row
  // (valid_to_ts IS NULL).
  await knex.schema.createTable("entity_keys", t => {
    t.string("entity_type", 32).notNullable();           // 'identity' | 'node' | 'vp'
    t.text("entity_id").notNullable();
    t.text("public_key").notNullable();
    t.string("algorithm", 64).notNullable().defaultTo("ml-dsa-65");
    t.bigInteger("valid_from_ts").notNullable();
    t.bigInteger("valid_to_ts").nullable();              // NULL = still active
    _id(t, "source_tx_id").notNullable();                // REGISTER_IDENTITY | KEY_ROTATED | KEY_RECOVERY | genesis:<id>
    t.primary(["entity_type", "entity_id", "valid_from_ts"], "pk_entity_keys");
    t.index(["entity_type", "entity_id", "valid_to_ts"], "idx_entity_keys_active");
    t.index(["entity_type", "entity_id", "valid_from_ts"], "idx_entity_keys_time");
  });

  await knex.schema.createTable("content", t => {
    // Column name is client-conditional:
    //   SQLite  → "ctid"     (no reserved-name conflict)
    //   Postgres → "tip_ctid" ("ctid" is a Postgres system column)
    const ctidCol = knex.client.config.client === "pg" ? "tip_ctid" : "ctid";
    t.string(ctidCol, 512).primary();
    t.string("origin_code", 8).notNullable();
    t.string("content_hash", 128).notNullable();
    t.string("perceptual_hash", 128).nullable();
    _id(t, "author_tip_id").notNullable();                       // = authors[0].tip_id (primary byline)
    _id(t, "signer_tip_id").notNullable();                       // the entity that produced the signature; differs from author in employed/hosted
    t.text("authors").nullable();                                 // JSON-encoded authors[] (5-key entries per CNA-2.2)
    t.string("attribution_mode", 32).notNullable().defaultTo("self");   // self / employed / hosted
    t.text("extras").nullable();                                  // JSON-encoded extension data
    t.string("cna_version", 32).notNullable();                    // CNA version this content was signed under
    t.string("status", 32).notNullable().defaultTo("verified");
    t.integer("dispute_count").notNullable().defaultTo(0);
    t.integer("verification_count").notNullable().defaultTo(0);
    t.integer("prescan_flagged").notNullable().defaultTo(0);
    t.float("prescan_probability").notNullable().defaultTo(0);          // raw classifier output
    t.string("prescan_tier", 16).notNullable().defaultTo("low");        // low|elevated|high|critical
    t.string("prescan_status", 16).notNullable().defaultTo("completed"); // 'pending' | 'completed'
    t.bigInteger("prescan_completed_at").nullable();                    // ms; null for legacy rows
    _id(t, "prescan_assigned_node_id").nullable();                      // node_reg_id of the API node that received the registration
    t.string("prescan_content_type", 16).nullable();                    // text|image|audio|video|multi; null until PRESCAN_COMPLETED
    t.integer("prescan_overall_degraded").notNullable().defaultTo(0);   // 1 if any modality reported error / disagreement / 0.5 neutral
    t.string("content_type_hint", 16).nullable();                       // publisher's signed declaration at register time
    t.integer("override").notNullable().defaultTo(0);                   // creator confirmed OH despite HIGH/CRITICAL warning
    t.bigInteger("registered_at").notNullable();
    t.text("registered_urls").nullable();                         // JSON-encoded string[]; index 0 is the canonical / primary URL
    t.text("media").nullable();                                   // JSON-encoded [{media_id, mime}, ...]; ordered (matches mch derivation)
    t.string("media_canonical_hash", 64).nullable();              // shake256 of media[].media_id concat; null when no media
    _id(t, "tx_id").nullable();
    t.index("author_tip_id", "idx_content_author");
    t.index("signer_tip_id", "idx_content_signer");
    t.index("origin_code", "idx_content_origin");
    t.index("status", "idx_content_status");
    t.index("prescan_status", "idx_content_prescan_status");
  });

  await knex.schema.createTable("scores", t => {
    _pk(t, "tip_id");
    t.integer("score").notNullable().defaultTo(500);
    t.integer("offense_count").notNullable().defaultTo(0);
    t.bigInteger("last_updated").notNullable();
  });

  await knex.schema.createTable("dedup_registry", t => {
    t.string("dedup_hash", 512).primary();
    t.bigInteger("created_at").notNullable();
    // Denormalized for fast hash→tip_id lookup (recovery pivot from
    // duplicate-registration; /v1/identity/by-dedup-hash endpoint).
    t.string("tip_id", 128);
  });

  await knex.schema.createTable("revocations", t => {
    _pk(t, "tip_id");
    t.string("tx_type", 64).notNullable();
    t.bigInteger("timestamp").notNullable();
    _id(t, "tx_id").notNullable();
  });

  // Domain bindings (org-only, canonical, in state_merkle_root).
  // expires_at + consecutive_failures are v2 renewal prep slots — set at
  // BIND commit to (verified_at + DOMAIN_HEALTHY_EXPIRY_MS, 0) and
  // untouched until the adaptive-expiry RENEW_DOMAIN scheduler ships.
  await knex.schema.createTable("domain_bindings", t => {
    t.string("domain", 253).primary();
    _id(t, "tip_id").notNullable();
    t.string("binding_state", 32).notNullable();
    t.string("method", 16).notNullable();
    t.bigInteger("claimed_at").notNullable();
    t.bigInteger("verified_at").notNullable();
    t.bigInteger("expires_at").notNullable();
    t.integer("consecutive_failures").notNullable().defaultTo(0);
    _id(t, "node_id").notNullable();
    t.text("claim_signature").notNullable();
    t.text("binding_signature").notNullable();
    _id(t, "tx_id").notNullable();
    t.index("tip_id", "idx_dom_bind_tip_id");
    t.index("binding_state", "idx_dom_bind_state");
    t.index("expires_at", "idx_dom_bind_expires");
  });

  // Platform links (canonical, in state_merkle_root). Signatures are
  // not stored on the row — reachable via tx_id from the transactions
  // table (user's claim cosig in tx.data.cosignatures[], node body sig
  // at tx.signature).
  // Final schema: unlinked_at / unlink_tx_id present;
  // expires_at / consecutive_failures absent (those were a hotfix,
  // dropped in the inline ALTER in _ensureSchema — baseline uses final shape).
  await knex.schema.createTable("platform_links", t => {
    _id(t, "id").primary();
    _id(t, "tip_id").notNullable();
    t.string("platform", 50).notNullable();
    t.string("handle", 255).nullable();
    t.text("profile_url").notNullable();
    t.string("status", 32).notNullable().defaultTo("active");
    t.bigInteger("linked_at").notNullable();
    t.bigInteger("verified_at").notNullable();
    t.bigInteger("unlinked_at").nullable();
    _id(t, "unlink_tx_id").nullable();
    _id(t, "node_id").notNullable();
    _id(t, "tx_id").notNullable();
    t.unique(["tip_id", "platform"], "idx_platform_links_tip_plat");
    t.index("tip_id", "idx_platform_links_tip_id");
    t.index("status", "idx_platform_links_status");
  });

  // Pending domain claims (NOT canonical; per-node storage between
  // POST /register and POST /verify).
  await knex.schema.createTable("pending_domain_claims", t => {
    t.string("domain", 253).primary();
    _id(t, "tip_id").notNullable();
    t.string("method", 16).notNullable();
    t.bigInteger("claimed_at").notNullable();
    t.text("signature").notNullable();
    t.bigInteger("received_at").notNullable();
    t.index("tip_id", "idx_pending_dom_tip_id");
  });

  // GH #60: public_key + algorithm live in entity_keys.
  await knex.schema.createTable("verification_providers", t => {
    _pk(t, "vp_id");
    t.string("name", 256).notNullable();
    t.string("jurisdiction", 8).notNullable().defaultTo("US");
    t.string("jurisdiction_tier", 16).notNullable().defaultTo("green");
    t.string("status", 32).notNullable().defaultTo("active");
    t.bigInteger("registered_at").notNullable();
  });

  // GH #60: public_key + algorithm live in entity_keys.
  await knex.schema.createTable("nodes", t => {
    _pk(t, "node_id");
    t.text("name").nullable();
    t.string("status", 32).notNullable().defaultTo("active");
    t.text("api_endpoint").nullable();   // public API origin; peers redirect reviewers here for this node's media
    t.bigInteger("registered_at").notNullable();
  });

  await knex.schema.createTable("certificates", t => {
    t.string("hash", 128).primary();
    t.integer("round").notNullable();
    _id(t, "author_node_id").notNullable();
    t.text("batch_data").notNullable();
    t.text("acknowledgments").notNullable();
    t.text("parent_hashes").notNullable();
    t.text("signature").notNullable();
    t.bigInteger("timestamp").notNullable().defaultTo(0);
    // local_inserted_at = node-local write time. Chain-time for a cert
    // is `certificates.timestamp` (BFT-Time = median of acks.signed_at).
    t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
    t.index("round", "idx_cert_round");
    t.index(["author_node_id", "round"], "idx_cert_author");
  });

  await knex.schema.createTable("commits", t => {
    t.integer("round").primary();
    t.string("anchor_cert_hash", 128).notNullable();
    _id(t, "leader_node_id").notNullable();
    t.text("committee").notNullable();
    t.integer("support_count").notNullable();
    t.integer("consensus_index").notNullable();
    t.bigInteger("committed_at").notNullable();
    t.string("state_merkle_root", 128).notNullable();
    t.string("txs_merkle_root", 128).notNullable();
    t.text("ack_signer_ids").notNullable();
    t.text("ack_signatures").notNullable();
    t.text("ack_signed_ats").notNullable().defaultTo("[]");
    t.bigInteger("cert_timestamp").notNullable().defaultTo(0);
    t.string("anchor_batch_hash", 128).nullable();
    // local_inserted_at = node-local write time. Chain-time for a
    // commit is `commits.committed_at` (= anchor cert's BFT-Time).
    t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
    t.unique(["consensus_index"], "idx_commits_index");
  });

  await knex.schema.createTable("votes_seen", t => {
    t.integer("round").notNullable();
    _id(t, "author").notNullable();
    t.string("batch_hash", 128).notNullable();
    // local_inserted_at = when this node first observed the vote.
    // Pure operational dedup table; not in any canonical projection.
    t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
    t.primary(["round", "author"]);
    t.index("round", "idx_votes_round");
  });

  await knex.schema.createTable("mempool", t => {
    t.string("tx_id", 128).primary();
    t.text("tx_data").notNullable();
    _id(t, "subject_tip_id").nullable();
    t.bigInteger("received_at").notNullable().defaultTo(0);
    t.index("subject_tip_id", "idx_mempool_subject");
  });

  await knex.schema.createTable("tx_rejections", t => {
    t.string("tx_id", 128).primary();
    t.string("reason", 64).notNullable();
    t.text("reason_detail").nullable();
    t.bigInteger("rejected_at_ms").notNullable();
    t.integer("rejected_at_round").nullable();
    _id(t, "dropper_node_id").notNullable();
    t.string("tx_type", 64).nullable();
    _id(t, "origin_node_id").nullable();
    t.text("tx_data").nullable();
    _id(t, "subject_tip_id").nullable();
    t.index("reason", "idx_tx_rej_reason");
    t.index("rejected_at_ms", "idx_tx_rej_at");
    t.index("origin_node_id", "idx_tx_rej_origin");
    t.index("subject_tip_id", "idx_tx_rej_subject");
  });

  await knex.schema.createTable("consensus_meta", t => {
    t.string("key", 128).primary();
    t.text("value").notNullable();
  });

  await knex.schema.createTable("committee_history", t => {
    t.integer("rotation_number").primary();
    t.integer("effective_round").notNullable();
    t.text("committee").notNullable();
    t.integer("prev_rotation").nullable();
    t.text("signer_node_ids").notNullable().defaultTo("[]");
    t.text("signatures").notNullable().defaultTo("[]");
    t.text("payload_hash").nullable();
    t.bigInteger("committed_at").notNullable();
    // local_inserted_at = node-local write time. Chain-time for the
    // rotation is `committee_history.committed_at` (= committing cert's
    // BFT-Time).
    t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
    t.index("effective_round", "idx_committee_history_round");
  });

  // Curated taxonomy of slugs users pick from on their profile.
  // Seeded at first boot from INITIAL_INTERESTS_SEED; extended at
  // runtime by INTEREST_REGISTERED txs (VP-attested). Slug PK enforces
  // uniqueness at the DB layer.
  await knex.schema.createTable("interests_registry", t => {
    t.string("slug", 40).primary();
    t.string("label", 80).notNullable();
    t.string("category", 32).notNullable();
    t.bigInteger("registered_at").notNullable();
    t.string("registered_by_vp_id", 128).nullable();
    t.string("tx_id", 128).nullable();
    t.bigInteger("local_inserted_at").notNullable().defaultTo(0);
    t.index("category", "idx_interests_registry_category");
  });

  // Prescan reviews (Phase 2 — human reviewing AI prescan flag).
  // See dag.js CREATE TABLE prescan_reviews for full schema rationale.
  await knex.schema.createTable("prescan_reviews", t => {
    t.string("review_id", 128).primary();
    // Column name is client-conditional (same pattern as `content` above):
    //   SQLite  → "ctid"
    //   Postgres → "tip_ctid"
    const ctidCol2 = knex.client.config.client === "pg" ? "tip_ctid" : "ctid";
    _id(t, ctidCol2).notNullable();
    _id(t, "creator_tip_id").notNullable();
    _id(t, "assigned_reviewer").nullable();
    t.integer("triggered_at_round").notNullable();
    t.bigInteger("triggered_at_ms").nullable();
    t.integer("decided_at_round").nullable();
    t.integer("confirmed_at_round").nullable();
    t.bigInteger("confirmed_at_ms").nullable();
    t.string("state", 32).notNullable().defaultTo("triggered");
    t.text("decision_note").nullable();
    t.string("suggested_origin", 8).nullable();
    t.index(ctidCol2, "idx_prescan_reviews_ctid");
    t.index("state", "idx_prescan_reviews_state");
    t.index("assigned_reviewer", "idx_prescan_reviews_reviewer");
  });

  await knex.schema.createTable("rotation_participation", t => {
    _id(t, "node_id").notNullable();
    t.integer("rotation_number").notNullable();
    t.integer("count").notNullable().defaultTo(0);
    t.primary(["node_id", "rotation_number"]);
  });

  // Off-chain dispute body store. Per-node, NOT consensus state — see
  // MemoryStore.saveDisputeDetails for the rationale. Excluded from
  // iterateCanonicalState / state_merkle_root.
  await knex.schema.createTable("dispute_details", t => {
    t.string("evidence_hash", 128).primary();
    _id(t, "disputer_tip_id").notNullable();
    t.text("payload_json").notNullable();
    t.text("signature").notNullable();
    // local_inserted_at = when this node received the evidence body.
    // Off-chain store by design; no chain-time exists for this row.
    t.bigInteger("local_inserted_at").notNullable();
  });

  // Prescan jobs — node-local async classifier queue. NOT consensus
  // state. Worker on the API node polls this table; result lands on
  // chain as a PRESCAN_COMPLETED tx that every node applies.
  await knex.schema.createTable("prescan_jobs", t => {
    t.string("job_id", 128).primary();
    // Column name is client-conditional (same pattern as `content`):
    //   SQLite  → "ctid"
    //   Postgres → "tip_ctid"
    const ctidCol3 = knex.client.config.client === "pg" ? "tip_ctid" : "ctid";
    t.string(ctidCol3, 512).notNullable().unique();
    t.binary("payload").notNullable();              // canonical JSON of classifier input
    t.string("status", 16).notNullable();           // 'queued' | 'claimed' | 'done' | 'failed'
    t.bigInteger("claimed_at").nullable();          // ms; null while queued
    t.string("claimed_by", 128).nullable();         // worker pid / node_reg_id
    t.integer("retries").notNullable().defaultTo(0);
    t.text("last_error").nullable();
    t.bigInteger("created_at").notNullable();
    t.bigInteger("completed_at").nullable();
    t.index(["status", "created_at"], "idx_prescan_jobs_status");
  });
};

exports.down = async (knex) => {
  await knex.schema.dropTableIfExists("prescan_jobs");
  await knex.schema.dropTableIfExists("prescan_reviews");
  await knex.schema.dropTableIfExists("rotation_participation");
  await knex.schema.dropTableIfExists("dispute_details");
  await knex.schema.dropTableIfExists("interests_registry");
  await knex.schema.dropTableIfExists("committee_history");
  await knex.schema.dropTableIfExists("consensus_meta");
  await knex.schema.dropTableIfExists("tx_rejections");
  await knex.schema.dropTableIfExists("mempool");
  await knex.schema.dropTableIfExists("votes_seen");
  await knex.schema.dropTableIfExists("commits");
  await knex.schema.dropTableIfExists("certificates");
  await knex.schema.dropTableIfExists("nodes");
  await knex.schema.dropTableIfExists("verification_providers");
  await knex.schema.dropTableIfExists("pending_domain_claims");
  await knex.schema.dropTableIfExists("platform_links");
  await knex.schema.dropTableIfExists("domain_bindings");
  await knex.schema.dropTableIfExists("revocations");
  await knex.schema.dropTableIfExists("dedup_registry");
  await knex.schema.dropTableIfExists("scores");
  await knex.schema.dropTableIfExists("content");
  await knex.schema.dropTableIfExists("entity_keys");
  await knex.schema.dropTableIfExists("identities");
  await knex.schema.dropTableIfExists("transactions");
};
