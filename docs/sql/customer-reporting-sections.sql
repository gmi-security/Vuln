-- Explicit additive migration. No application initializer.
-- A replaceable derived report, never an authoritative finding/workflow store.
CREATE TABLE customer_reporting_sections (
  company_id text PRIMARY KEY,
  format_version integer NOT NULL CHECK (format_version = 1),
  snapshot_id uuid NOT NULL,
  source_fingerprint text NOT NULL CHECK (source_fingerprint ~ '^[a-f0-9]{64}$'),
  model_hash text NOT NULL CHECK (model_hash ~ '^[a-f0-9]{64}$'),
  captured_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  finding_count integer NOT NULL CHECK (finding_count >= 0),
  model jsonb NOT NULL CHECK (jsonb_typeof(model) = 'object' AND model->'company'->>'id' = company_id),
  built_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > captured_at)
);
