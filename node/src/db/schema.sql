-- GENERATED FILE. DO NOT EDIT.
-- Source of truth: src/db/migrations/*.js (Knex baseline).
-- Regenerate with: npm run gen:schema
-- Verified current by tests/db/migration-baseline-schema.test.js.

CREATE TABLE IF NOT EXISTS `audio_clip` (`clip_id` integer not null primary key autoincrement, `tip_ctid` varchar(512) not null, `component_idx` integer not null, `landmark_count` integer not null default '0');

CREATE TABLE IF NOT EXISTS `audio_landmark` (`profile` varchar(64) not null, `hash` integer not null, `clip_id` bigint not null, `t` integer not null, primary key (`profile`, `hash`, `clip_id`, `t`));

CREATE TABLE IF NOT EXISTS `certificates` (`hash` varchar(128), `round` integer not null, `author_node_id` varchar(512) not null, `batch_data` text not null, `acknowledgments` text not null, `parent_hashes` text not null, `signature` text not null, `timestamp` bigint not null default '0', `local_inserted_at` bigint not null default (unixepoch() * 1000), primary key (`hash`));

CREATE TABLE IF NOT EXISTS `commits` (`round` integer, `anchor_cert_hash` varchar(128) not null, `leader_node_id` varchar(512) not null, `committee` text not null, `support_count` integer not null, `consensus_index` integer not null, `committed_at` bigint not null, `state_merkle_root` varchar(128) not null, `txs_merkle_root` varchar(128) not null, `ack_signer_ids` text not null, `ack_signatures` text not null, `ack_signed_ats` text not null default '[]', `cert_timestamp` bigint not null default '0', `anchor_batch_hash` varchar(128) null, `local_inserted_at` bigint not null default (unixepoch() * 1000), primary key (`round`));

CREATE TABLE IF NOT EXISTS `committee_history` (`rotation_number` integer, `effective_round` integer not null, `committee` text not null, `prev_rotation` integer null, `signer_node_ids` text not null default '[]', `signatures` text not null default '[]', `payload_hash` text null, `committed_at` bigint not null, `local_inserted_at` bigint not null default (unixepoch() * 1000), primary key (`rotation_number`));

CREATE TABLE IF NOT EXISTS `consensus_meta` (`key` varchar(128), `value` text not null, primary key (`key`));

CREATE TABLE IF NOT EXISTS `content` (`tip_ctid` varchar(512), `origin_code` varchar(8) not null, `content_hash` varchar(128) not null, `author_tip_id` varchar(512) not null, `signer_tip_id` varchar(512) not null, `authors` text null, `attribution_mode` varchar(32) not null default 'self', `extras` text null, `cna_version` varchar(32) not null, `status` varchar(32) not null default 'verified', `dispute_count` integer not null default '0', `verification_count` integer not null default '0', `prescan_flagged` integer not null default '0', `prescan_probability` float not null default '0', `prescan_tier` varchar(16) not null default 'low', `prescan_status` varchar(16) not null default 'completed', `prescan_completed_at` bigint null, `prescan_assigned_node_id` varchar(512) null, `prescan_content_type` varchar(16) null, `prescan_overall_degraded` integer not null default '0', `content_type_hint` varchar(16) null, `override` integer not null default '0', `registered_at` bigint not null, `registered_urls` text null, `media` text null, `media_canonical_hash` varchar(64) null, `tx_id` varchar(512) null, primary key (`tip_ctid`));

CREATE TABLE IF NOT EXISTS `dedup_registry` (`dedup_hash` varchar(512), `created_at` bigint not null, `tip_id` varchar(128), primary key (`dedup_hash`));

CREATE TABLE IF NOT EXISTS `dispute_details` (`evidence_hash` varchar(128), `disputer_tip_id` varchar(512) not null, `payload_json` text not null, `signature` text not null, `local_inserted_at` bigint not null, primary key (`evidence_hash`));

CREATE TABLE IF NOT EXISTS `domain_bindings` (`domain` varchar(253), `tip_id` varchar(512) not null, `binding_state` varchar(32) not null, `method` varchar(16) not null, `claimed_at` bigint not null, `verified_at` bigint not null, `expires_at` bigint not null, `consecutive_failures` integer not null default '0', `node_id` varchar(512) not null, `claim_signature` text not null, `binding_signature` text not null, `tx_id` varchar(512) not null, primary key (`domain`));

CREATE TABLE IF NOT EXISTS `entity_keys` (`entity_type` varchar(32) not null, `entity_id` varchar(128) not null, `public_key` text not null, `algorithm` varchar(64) not null default 'ml-dsa-65', `valid_from_ts` bigint not null, `valid_to_ts` bigint null, `source_tx_id` varchar(512) not null, constraint `pk_entity_keys` primary key (`entity_type`, `entity_id`, `valid_from_ts`));

CREATE TABLE IF NOT EXISTS `identities` (`tip_id` varchar(512), `region` varchar(8) not null default 'US', `vp_id` varchar(512) null, `verification_tier` varchar(8) not null default 'T1', `score_display_mode` varchar(32) not null default 'TIER_ONLY', `tip_id_type` varchar(32) not null default 'personal', `founding` integer not null default '0', `status` varchar(32) not null default 'active', `reviewer_consent` integer not null default '0', `juror_consent` integer not null default '0', `expert_consent` integer not null default '0', `interests` text not null default '[]', `registered_at` bigint not null, `creator_name` text null, `tx_id` varchar(512) null, primary key (`tip_id`));

CREATE TABLE IF NOT EXISTS `interests_registry` (`slug` varchar(40), `label` varchar(80) not null, `category` varchar(32) not null, `registered_at` bigint not null, `registered_by_vp_id` varchar(128) null, `tx_id` varchar(128) null, `local_inserted_at` bigint not null default (unixepoch() * 1000), primary key (`slug`));

CREATE TABLE IF NOT EXISTS `mempool` (`tx_id` varchar(128), `tx_data` text not null, `subject_tip_id` varchar(512) null, `received_at` bigint not null default (unixepoch() * 1000), primary key (`tx_id`));

CREATE TABLE IF NOT EXISTS `minhash_band` (`profile` varchar(64) not null, `band_idx` integer not null, `band_hash` bigint not null, `tip_ctid` varchar(512) not null, primary key (`profile`, `band_idx`, `band_hash`, `tip_ctid`));

CREATE TABLE IF NOT EXISTS `nodes` (`node_id` varchar(512), `name` text null, `status` varchar(32) not null default 'active', `api_endpoint` text null, `updated_at` bigint null, `registered_at` bigint not null, primary key (`node_id`));

CREATE TABLE IF NOT EXISTS `pending_domain_claims` (`domain` varchar(253), `tip_id` varchar(512) not null, `method` varchar(16) not null, `claimed_at` bigint not null, `signature` text not null, `received_at` bigint not null, primary key (`domain`));

CREATE TABLE IF NOT EXISTS `perceptual_fingerprint` (`tip_ctid` varchar(512) not null, `component_idx` integer not null, `modality` varchar(16) not null, `profile` varchar(64) not null, `pipeline` text not null, `quality` integer, `fingerprint` text not null, `created_at` bigint not null, primary key (`tip_ctid`, `component_idx`));

CREATE TABLE IF NOT EXISTS `phash_code` (`tip_ctid` varchar(512) not null, `component_idx` integer not null, `frame` integer not null, `profile` varchar(64) not null, `modality` varchar(16) not null, `ts` float, `quality` integer not null, `pdq` varchar(64) not null, `c0` integer not null, `c1` integer not null, `c2` integer not null, `c3` integer not null, `c4` integer not null, `c5` integer not null, `c6` integer not null, `c7` integer not null, `c8` integer not null, `c9` integer not null, `c10` integer not null, `c11` integer not null, `c12` integer not null, `c13` integer not null, `c14` integer not null, `c15` integer not null, primary key (`tip_ctid`, `component_idx`, `frame`));

CREATE TABLE IF NOT EXISTS `platform_links` (`id` varchar(512), `tip_id` varchar(512) not null, `platform` varchar(50) not null, `handle` varchar(255) null, `profile_url` text not null, `status` varchar(32) not null default 'active', `linked_at` bigint not null, `verified_at` bigint not null, `unlinked_at` bigint null, `unlink_tx_id` varchar(512) null, `node_id` varchar(512) not null, `tx_id` varchar(512) not null, primary key (`id`));

CREATE TABLE IF NOT EXISTS `prescan_jobs` (`job_id` varchar(128), `tip_ctid` varchar(512) not null, `payload` blob not null, `status` varchar(16) not null, `claimed_at` bigint null, `claimed_by` varchar(128) null, `retries` integer not null default '0', `last_error` text null, `created_at` bigint not null, `completed_at` bigint null, primary key (`job_id`));

CREATE TABLE IF NOT EXISTS `prescan_reviews` (`review_id` varchar(128), `tip_ctid` varchar(512) not null, `creator_tip_id` varchar(512) not null, `assigned_reviewer` varchar(512) null, `triggered_at_round` integer not null, `triggered_at_ms` bigint null, `decided_at_round` integer null, `confirmed_at_round` integer null, `confirmed_at_ms` bigint null, `state` varchar(32) not null default 'triggered', `decision_note` text null, `suggested_origin` varchar(8) null, primary key (`review_id`));

CREATE TABLE IF NOT EXISTS `protocol_params` (`param_key` varchar(128) not null, `value` text not null, `effective_from_height` bigint not null, `update_tx_id` varchar(512) not null, primary key (`param_key`, `effective_from_height`));

CREATE TABLE IF NOT EXISTS `revocations` (`tip_id` varchar(512), `tx_type` varchar(64) not null, `timestamp` bigint not null, `tx_id` varchar(512) not null, primary key (`tip_id`));

CREATE TABLE IF NOT EXISTS `rotation_participation` (`node_id` varchar(512) not null, `rotation_number` integer not null, `bucket` integer not null default '0', `count` integer not null default '0', primary key (`node_id`, `rotation_number`, `bucket`));

CREATE TABLE IF NOT EXISTS `scores` (`tip_id` varchar(512), `score` integer not null default '500', `offense_count` integer not null default '0', `last_updated` bigint not null, primary key (`tip_id`));

CREATE TABLE IF NOT EXISTS `transactions` (`tx_id` varchar(512), `tx_type` varchar(64) not null, `data` text not null, `timestamp` bigint not null, `prev` text not null default '[]', `signature` text null, `subject_tip_id` varchar(512) null, `local_inserted_at` bigint not null default (unixepoch() * 1000), primary key (`tx_id`));

CREATE TABLE IF NOT EXISTS `tx_rejections` (`tx_id` varchar(128), `reason` varchar(64) not null, `reason_detail` text null, `rejected_at_ms` bigint not null, `rejected_at_round` integer null, `dropper_node_id` varchar(512) not null, `tx_type` varchar(64) null, `origin_node_id` varchar(512) null, `tx_data` text null, `subject_tip_id` varchar(512) null, primary key (`tx_id`));

CREATE TABLE IF NOT EXISTS `verification_providers` (`vp_id` varchar(512), `name` varchar(256) not null, `jurisdiction` varchar(8) not null default 'US', `jurisdiction_tier` varchar(16) not null default 'green', `status` varchar(32) not null default 'active', `registered_at` bigint not null, primary key (`vp_id`));

CREATE TABLE IF NOT EXISTS `votes_seen` (`round` integer not null, `author` varchar(512) not null, `batch_hash` varchar(128) not null, `local_inserted_at` bigint not null default (unixepoch() * 1000), primary key (`round`, `author`));

CREATE UNIQUE INDEX IF NOT EXISTS `idx_audio_clip_ctid` on `audio_clip` (`tip_ctid`, `component_idx`);

CREATE INDEX IF NOT EXISTS `idx_audio_landmark_lookup` on `audio_landmark` (`profile`, `hash`);

CREATE INDEX IF NOT EXISTS `idx_cert_author` on `certificates` (`author_node_id`, `round`);

CREATE INDEX IF NOT EXISTS `idx_cert_round` on `certificates` (`round`);

CREATE UNIQUE INDEX IF NOT EXISTS `idx_commits_index` on `commits` (`consensus_index`);

CREATE INDEX IF NOT EXISTS `idx_committee_history_round` on `committee_history` (`effective_round`);

CREATE INDEX IF NOT EXISTS `idx_content_author` on `content` (`author_tip_id`);

CREATE INDEX IF NOT EXISTS `idx_content_origin` on `content` (`origin_code`);

CREATE INDEX IF NOT EXISTS `idx_content_prescan_status` on `content` (`prescan_status`);

CREATE INDEX IF NOT EXISTS `idx_content_signer` on `content` (`signer_tip_id`);

CREATE INDEX IF NOT EXISTS `idx_content_status` on `content` (`status`);

CREATE INDEX IF NOT EXISTS `idx_dom_bind_expires` on `domain_bindings` (`expires_at`);

CREATE INDEX IF NOT EXISTS `idx_dom_bind_state` on `domain_bindings` (`binding_state`);

CREATE INDEX IF NOT EXISTS `idx_dom_bind_tip_id` on `domain_bindings` (`tip_id`);

CREATE INDEX IF NOT EXISTS `idx_entity_keys_active` on `entity_keys` (`entity_type`, `entity_id`, `valid_to_ts`);

CREATE INDEX IF NOT EXISTS `idx_id_status` on `identities` (`status`);

CREATE INDEX IF NOT EXISTS `idx_id_type` on `identities` (`tip_id_type`);

CREATE INDEX IF NOT EXISTS `idx_id_vp` on `identities` (`vp_id`);

CREATE INDEX IF NOT EXISTS `idx_interests_registry_category` on `interests_registry` (`category`);

CREATE INDEX IF NOT EXISTS `idx_minhash_band_lookup` on `minhash_band` (`profile`, `band_idx`, `band_hash`);

CREATE INDEX IF NOT EXISTS `idx_pending_dom_tip_id` on `pending_domain_claims` (`tip_id`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c0` on `phash_code` (`profile`, `modality`, `c0`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c1` on `phash_code` (`profile`, `modality`, `c1`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c10` on `phash_code` (`profile`, `modality`, `c10`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c11` on `phash_code` (`profile`, `modality`, `c11`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c12` on `phash_code` (`profile`, `modality`, `c12`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c13` on `phash_code` (`profile`, `modality`, `c13`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c14` on `phash_code` (`profile`, `modality`, `c14`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c15` on `phash_code` (`profile`, `modality`, `c15`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c2` on `phash_code` (`profile`, `modality`, `c2`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c3` on `phash_code` (`profile`, `modality`, `c3`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c4` on `phash_code` (`profile`, `modality`, `c4`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c5` on `phash_code` (`profile`, `modality`, `c5`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c6` on `phash_code` (`profile`, `modality`, `c6`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c7` on `phash_code` (`profile`, `modality`, `c7`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c8` on `phash_code` (`profile`, `modality`, `c8`);

CREATE INDEX IF NOT EXISTS `idx_phash_code_c9` on `phash_code` (`profile`, `modality`, `c9`);

CREATE INDEX IF NOT EXISTS `idx_platform_links_status` on `platform_links` (`status`);

CREATE INDEX IF NOT EXISTS `idx_platform_links_tip_id` on `platform_links` (`tip_id`);

CREATE UNIQUE INDEX IF NOT EXISTS `idx_platform_links_tip_plat` on `platform_links` (`tip_id`, `platform`);

CREATE INDEX IF NOT EXISTS `idx_prescan_jobs_status` on `prescan_jobs` (`status`, `created_at`);

CREATE INDEX IF NOT EXISTS `idx_prescan_reviews_ctid` on `prescan_reviews` (`tip_ctid`);

CREATE INDEX IF NOT EXISTS `idx_prescan_reviews_reviewer` on `prescan_reviews` (`assigned_reviewer`);

CREATE INDEX IF NOT EXISTS `idx_prescan_reviews_state` on `prescan_reviews` (`state`);

CREATE INDEX IF NOT EXISTS `idx_rotation_participation_rotation` on `rotation_participation` (`rotation_number`);

CREATE INDEX IF NOT EXISTS `idx_tx_rej_at` on `tx_rejections` (`rejected_at_ms`);

CREATE INDEX IF NOT EXISTS `idx_tx_rej_origin` on `tx_rejections` (`origin_node_id`);

CREATE INDEX IF NOT EXISTS `idx_tx_rej_reason` on `tx_rejections` (`reason`);

CREATE INDEX IF NOT EXISTS `idx_txs_local_inserted_at` on `transactions` (`local_inserted_at`);

CREATE INDEX IF NOT EXISTS `idx_txs_ts` on `transactions` (`timestamp`);

CREATE INDEX IF NOT EXISTS `idx_txs_type` on `transactions` (`tx_type`);

CREATE INDEX IF NOT EXISTS `idx_votes_round` on `votes_seen` (`round`);

CREATE UNIQUE INDEX IF NOT EXISTS `prescan_jobs_tip_ctid_unique` on `prescan_jobs` (`tip_ctid`);
