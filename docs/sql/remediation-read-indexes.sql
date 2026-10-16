-- Required read indexes for the Remediation CVE panel and patch preparation.
-- Explicit operator migration: never build these in a page request or startup.
-- Run each CONCURRENTLY statement outside a transaction on the database owning
-- its table. Verify pg_index.indisvalid after any interrupted creation.
CREATE INDEX CONCURRENTLY IF NOT EXISTS spotlight_import_customer_cve_open
  ON spotlight_import_records(run_id,tenant_key,company_id,cve,source_id)
  WHERE status IN ('open','reopen');

CREATE INDEX CONCURRENTLY IF NOT EXISTS patch_group_ticket_cves_gin
  ON patch_group_ticket_requests USING gin(cves jsonb_path_ops);

-- Run on each table's owning database after installation. Both indexes must
-- exist with indisvalid=true and indisready=true before enabling the workflow.
-- SELECT c.relname, i.indisvalid, i.indisready, pg_get_indexdef(i.indexrelid)
-- FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
-- WHERE c.relname IN ('spotlight_import_customer_cve_open','patch_group_ticket_cves_gin');

-- Rollback removes only these indexes; it never changes source or ticket rows.
-- DROP INDEX CONCURRENTLY IF EXISTS spotlight_import_customer_cve_open;
-- DROP INDEX CONCURRENTLY IF EXISTS patch_group_ticket_cves_gin;
