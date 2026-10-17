// node-local prescan queue: when a job may next be claimed, the classifier's own
// job id for a pre-scan it runs asynchronously, when that job was first accepted
// (the polling budget runs from there), and how many status polls have run.

"use strict";

const TABLE_NAME = "prescan_jobs";
const COLUMNS = ["retry_after", "classifier_job_id", "classifier_job_at", "classifier_polls"];

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  const missing = [];
  for (const c of COLUMNS) {
    if (!(await knex.schema.hasColumn(TABLE_NAME, c))) missing.push(c);
  }
  if (missing.length === 0) return;
  await knex.schema.table(TABLE_NAME, t => {
    if (missing.includes("retry_after")) t.bigInteger("retry_after").notNullable().defaultTo(0);
    if (missing.includes("classifier_job_id")) t.string("classifier_job_id", 128).nullable();
    if (missing.includes("classifier_job_at")) t.bigInteger("classifier_job_at").nullable();
    if (missing.includes("classifier_polls")) t.integer("classifier_polls").notNullable().defaultTo(0);
  });
};

exports.down = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  for (const c of [...COLUMNS].reverse()) {
    if (await knex.schema.hasColumn(TABLE_NAME, c)) {
      await knex.schema.table(TABLE_NAME, t => t.dropColumn(c));
    }
  }
};
