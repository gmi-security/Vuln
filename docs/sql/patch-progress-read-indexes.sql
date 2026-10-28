-- Required for bounded CrowdStrike ticket comparisons, including closed and
-- suppressed records. The existing open-only index cannot serve this query.
-- Explicit operator migration on the database owning spotlight_import_records.
-- Run outside a transaction; do not run from startup or a page request.
SET lock_timeout = '5s';
SET statement_timeout = '15min';
CREATE INDEX CONCURRENTLY IF NOT EXISTS spotlight_import_progress_pairs
  ON spotlight_import_records(run_id,tenant_key,company_id,cve,(raw->>'aid'));

-- Require both flags to be true before retrying failed comparisons. If an
-- interrupted build leaves an invalid index, inspect it before any retry;
-- IF NOT EXISTS does not repair an invalid index.
SELECT c.relname,i.indisvalid,i.indisready,pg_size_pretty(pg_relation_size(c.oid)) size
  FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
  WHERE c.relname='spotlight_import_progress_pairs';

-- Rollback, if needed, removes only this read index:
-- DROP INDEX CONCURRENTLY spotlight_import_progress_pairs;
