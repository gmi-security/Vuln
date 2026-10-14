-- Explicit additive migration after customer-reporting-sections.sql.
-- No source-table triggers, startup initializer or production scheduler.
CREATE TABLE customer_reporting_jobs (
  company_id text PRIMARY KEY,
  requested_revision integer NOT NULL CHECK (requested_revision > 0),
  requested_fingerprint text NOT NULL CHECK (requested_fingerprint ~ '^[a-f0-9]{64}$'),
  state text NOT NULL CHECK (state IN ('queued','running','retry','succeeded','failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  available_at timestamptz NOT NULL DEFAULT now(),
  claimed_revision integer,
  lease_token uuid,
  lease_until timestamptz,
  requested_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  succeeded_at timestamptz,
  last_error_code text CHECK (last_error_code IN ('build-failed','lease-expired','worker-stopped','source-changed')),
  CHECK ((state='running' AND claimed_revision IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)
    OR (state<>'running' AND claimed_revision IS NULL AND lease_token IS NULL AND lease_until IS NULL))
);
CREATE INDEX customer_reporting_jobs_due ON customer_reporting_jobs(available_at,requested_at)
  WHERE state IN ('queued','retry');
-- Rollback: stop the worker first; retain both derived tables during code rollback.
