-- Explicit follow-up migration, after spotlight-source-summaries.sql.
-- No trigger, timer, automatic startup, source mutation or deletion.
BEGIN;
CREATE TABLE spotlight_summary_jobs (
  company_id TEXT NOT NULL, run_id UUID NOT NULL, model_version INT NOT NULL CHECK(model_version > 0),
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','retry','succeeded','failed','superseded')),
  attempts INT NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  lease_token UUID, lease_until TIMESTAMPTZ,
  source_rows BIGINT NOT NULL DEFAULT 0 CHECK(source_rows >= 0),
  last_error_code TEXT CHECK(last_error_code IN ('build-failed','lease-expired','worker-stopped')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ,
  PRIMARY KEY(company_id,run_id,model_version),
  CHECK((status='running' AND lease_token IS NOT NULL AND lease_until IS NOT NULL)
    OR (status<>'running' AND lease_token IS NULL AND lease_until IS NULL))
);
CREATE INDEX spotlight_summary_jobs_due ON spotlight_summary_jobs (model_version,available_at,created_at)
  WHERE status IN ('queued','retry');
CREATE INDEX spotlight_summary_jobs_customer ON spotlight_summary_jobs(company_id,created_at DESC);
COMMIT;
-- Rollback after stopping the dedicated worker: DROP TABLE spotlight_summary_jobs;
-- Prefer retaining job history during a code rollback. Existing imports, summaries and tickets remain intact.
