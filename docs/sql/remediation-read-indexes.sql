-- Candidate read indexes for the gated Remediation workflow.
-- Not an automatic migration. Validate timings and disk headroom before rollout.
-- Run each CONCURRENTLY statement outside a transaction on the database owning
-- its table. Verify pg_index.indisvalid after any interrupted creation.
CREATE INDEX CONCURRENTLY IF NOT EXISTS spotlight_import_customer_cve_open
  ON spotlight_import_records(run_id,tenant_key,company_id,cve,source_id)
  WHERE status IN ('open','reopen');

CREATE INDEX CONCURRENTLY IF NOT EXISTS patch_group_ticket_cves_gin
  ON patch_group_ticket_requests USING gin(cves jsonb_path_ops);

-- Rollback removes only these indexes; it never changes source or ticket rows.
-- DROP INDEX CONCURRENTLY IF EXISTS spotlight_import_customer_cve_open;
-- DROP INDEX CONCURRENTLY IF EXISTS patch_group_ticket_cves_gin;
