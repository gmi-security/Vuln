-- Explicit, additive migration. No application initializer or automatic rollout.
BEGIN;
CREATE TABLE spotlight_summary_generations (
  company_id TEXT NOT NULL, run_id UUID NOT NULL, model_version INT NOT NULL CHECK(model_version > 0),
  source_completed_at TIMESTAMPTZ NOT NULL, source_rows BIGINT NOT NULL CHECK(source_rows >= 0),
  count_verification TEXT NOT NULL CHECK(count_verification IN ('import-count-reconciled','completion-marker-only')),
  summary JSONB NOT NULL CHECK(jsonb_typeof(summary)='object'),
  cve_count INT NOT NULL CHECK(cve_count >= 0), built_at TIMESTAMPTZ NOT NULL DEFAULT now(), built_by TEXT NOT NULL,
  PRIMARY KEY(company_id,run_id,model_version)
);
CREATE TABLE spotlight_summary_cves (
  company_id TEXT NOT NULL, run_id UUID NOT NULL, model_version INT NOT NULL,
  cve TEXT COLLATE "C" NOT NULL CHECK(cve ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN')),
  severity_rank SMALLINT GENERATED ALWAYS AS (CASE severity WHEN 'CRITICAL' THEN 6 WHEN 'HIGH' THEN 5
    WHEN 'MEDIUM' THEN 4 WHEN 'LOW' THEN 3 WHEN 'NONE' THEN 2 ELSE 1 END) STORED,
  cvss DOUBLE PRECISION CHECK(cvss >= 0 AND cvss <= 10),
  affected_devices BIGINT NOT NULL CHECK(affected_devices > 0),
  source_instances BIGINT NOT NULL CHECK(source_instances >= affected_devices),
  PRIMARY KEY(company_id,run_id,model_version,cve),
  FOREIGN KEY(company_id,run_id,model_version) REFERENCES spotlight_summary_generations ON DELETE CASCADE
);
CREATE INDEX spotlight_summary_cves_order ON spotlight_summary_cves
  (company_id,run_id,model_version,severity_rank DESC,affected_devices DESC,cve);
CREATE TABLE spotlight_summary_current (
  company_id TEXT PRIMARY KEY, run_id UUID NOT NULL, model_version INT NOT NULL,
  FOREIGN KEY(company_id,run_id,model_version) REFERENCES spotlight_summary_generations
);
COMMIT;
-- Rollback (only after switching consumers off):
-- DROP TABLE spotlight_summary_current,spotlight_summary_cves,spotlight_summary_generations;
-- Original imports and records are never deleted by this migration or rollback.
