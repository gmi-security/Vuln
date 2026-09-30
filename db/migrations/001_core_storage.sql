-- Staging schema for a lossless migration from vuln_store. No application
-- reads or writes use these tables until parity and cutover gates pass.
-- Foreign keys and required-field constraints are deferred until the legacy
-- orphan/missing-field inventory is complete. Payload retains the source.

CREATE TABLE app_companies (
  id TEXT PRIMARY KEY,
  name TEXT,
  kind TEXT CHECK (kind IN ('internal', 'client')),
  created_at TIMESTAMPTZ,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object')
);
CREATE INDEX app_companies_name_idx ON app_companies (lower(name));

CREATE TABLE app_folders (
  id TEXT PRIMARY KEY,
  company_id TEXT,
  name TEXT,
  created_at TIMESTAMPTZ,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object')
);
CREATE INDEX app_folders_company_idx ON app_folders (company_id);

CREATE TABLE app_scans (
  id TEXT PRIMARY KEY,
  company_id TEXT,
  folder_id TEXT,
  connector TEXT,
  status TEXT,
  external_ref TEXT,
  created_at TIMESTAMPTZ,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object')
);
CREATE INDEX app_scans_company_created_idx ON app_scans (company_id, created_at DESC, id);
CREATE INDEX app_scans_folder_idx ON app_scans (folder_id);
CREATE INDEX app_scans_external_idx ON app_scans (company_id, connector, external_ref)
  WHERE external_ref IS NOT NULL;

CREATE TABLE app_findings (
  id TEXT PRIMARY KEY,
  company_id TEXT,
  scan_id TEXT,
  connector TEXT,
  status TEXT,
  severity TEXT,
  cve TEXT,
  asset TEXT,
  real_risk INTEGER,
  last_seen TIMESTAMPTZ,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object')
);
CREATE INDEX app_findings_company_risk_idx ON app_findings
  (company_id, real_risk DESC, id);
CREATE INDEX app_findings_company_status_idx ON app_findings
  (company_id, status, severity, id);
CREATE INDEX app_findings_scan_idx ON app_findings (scan_id, id);
CREATE INDEX app_findings_company_cve_idx ON app_findings (company_id, cve, id);

CREATE TABLE app_assets (
  id TEXT PRIMARY KEY,
  company_id TEXT,
  identifier TEXT,
  source TEXT,
  external_id TEXT,
  last_synced TIMESTAMPTZ,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object')
);
CREATE INDEX app_assets_company_idx ON app_assets (company_id, id);
CREATE INDEX app_assets_identity_idx ON app_assets (company_id, lower(identifier));
CREATE INDEX app_assets_external_idx ON app_assets (company_id, source, external_id)
  WHERE external_id IS NOT NULL AND external_id <> '';

CREATE TABLE app_compensating_controls (
  id TEXT PRIMARY KEY,
  company_id TEXT,
  status TEXT,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object')
);
CREATE INDEX app_controls_company_idx ON app_compensating_controls (company_id, status);

CREATE TABLE app_identity_aliases (
  alias_key TEXT PRIMARY KEY,
  canonical_identifier TEXT NOT NULL
);

CREATE TABLE app_settings (
  key TEXT PRIMARY KEY,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object')
);

CREATE TABLE app_scheduler_state (
  key TEXT PRIMARY KEY,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app_id_sequences (
  prefix TEXT PRIMARY KEY,
  next_value BIGINT NOT NULL CHECK (next_value > 0)
);

CREATE TABLE app_migration_state (
  run_id UUID NOT NULL,
  bucket_key TEXT NOT NULL,
  source_checksum TEXT NOT NULL,
  row_count BIGINT NOT NULL CHECK (row_count >= 0),
  completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (run_id, bucket_key)
);
