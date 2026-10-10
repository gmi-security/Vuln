-- Explicit additive migration after customer connector drafts and bindings.
-- This records review only. No source data, operational routing or reporting changes.
BEGIN;
DO $$ BEGIN
  IF to_regclass('public.customer_connector_bindings') IS NULL OR to_regclass('public.customer_connector_drafts') IS NULL THEN
    RAISE EXCEPTION 'Install connector drafts and bindings first';
  END IF;
END $$;
CREATE TABLE customer_source_selections (
  company_id TEXT PRIMARY KEY CHECK (company_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$'),
  revision INTEGER NOT NULL CHECK (revision>0),
  state TEXT NOT NULL CHECK (state IN ('reviewed','revoked')),
  bindings_fingerprint TEXT CHECK (bindings_fingerprint ~ '^[a-f0-9]{64}$'),
  mirrors JSONB NOT NULL CHECK (jsonb_typeof(mirrors)='array' AND jsonb_array_length(mirrors)<=100),
  sources JSONB NOT NULL CHECK (jsonb_typeof(sources)='array' AND jsonb_array_length(sources)<=1000),
  reviewed_by TEXT NOT NULL,
  reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((state='reviewed' AND bindings_fingerprint IS NOT NULL) OR (state='revoked' AND bindings_fingerprint IS NULL AND mirrors='[]'::jsonb))
);
CREATE TABLE customer_source_selection_audit (
  id BIGSERIAL PRIMARY KEY,
  company_id TEXT NOT NULL REFERENCES customer_source_selections(company_id),
  revision INTEGER NOT NULL CHECK (revision>0),
  actor TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('reviewed','revoked')),
  before_state JSONB,
  after_state JSONB NOT NULL,
  note TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(company_id,revision)
);
COMMIT;
-- Retain review and audit during rollback. No runtime initializer uses this file.
