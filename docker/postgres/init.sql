-- TIP Protocol PostgreSQL initialization
-- Run automatically by docker-compose on first start.
-- Author: Dinesh Mendhe <chairman@theailab.org>
-- Copyright 2026 The AI Lab Intelligence Unobscured, Inc.

-- Create dedicated schema
CREATE SCHEMA IF NOT EXISTS tip;

-- Grant privileges to the tip user
GRANT ALL PRIVILEGES ON SCHEMA tip TO tip;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA tip TO tip;
ALTER DEFAULT PRIVILEGES IN SCHEMA tip GRANT ALL ON TABLES TO tip;

-- The actual table creation is handled by the node on first boot.
-- This file creates the schema and grants so the node can initialize cleanly.

-- Optional: add pg_stat_statements for query analysis
-- CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
