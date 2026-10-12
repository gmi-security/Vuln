-- Explicit disposable-database migration only. No bootstrap or production caller.
CREATE TABLE defender_shadow_generations (
  company_id text NOT NULL,
  projection_id uuid NOT NULL,
  model_version integer NOT NULL CHECK (model_version=2),
  source_run text NOT NULL,
  snapshot_saved_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('building','verified','failed')),
  finding_count integer,
  started_at timestamptz NOT NULL DEFAULT now(),
  verified_at timestamptz,
  PRIMARY KEY (company_id,projection_id),
  CHECK ((state='verified') = (verified_at IS NOT NULL)),
  CHECK (state<>'verified' OR (finding_count IS NOT NULL AND finding_count>=0))
);
CREATE TABLE defender_shadow_findings (
  company_id text NOT NULL,
  projection_id uuid NOT NULL,
  finding_id text NOT NULL,
  issue_key text NOT NULL,
  asset_key text NOT NULL,
  connector text NOT NULL,
  legacy_order integer NOT NULL CHECK (legacy_order>=0),
  detail jsonb NOT NULL CHECK (jsonb_typeof(detail)='object'),
  PRIMARY KEY (company_id,projection_id,finding_id),
  FOREIGN KEY (company_id,projection_id) REFERENCES defender_shadow_generations(company_id,projection_id) ON DELETE CASCADE
);
CREATE INDEX defender_shadow_findings_issue ON defender_shadow_findings(company_id,projection_id,issue_key,finding_id);
CREATE TABLE defender_shadow_workflow (
  company_id text NOT NULL,
  projection_id uuid NOT NULL,
  finding_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('Open','In Remediation','Risk Accepted','False Positive','Resolved')),
  assignee text,
  first_seen text NOT NULL,
  last_seen text NOT NULL,
  resolved_at text,
  PRIMARY KEY (company_id,projection_id,finding_id),
  FOREIGN KEY (company_id,projection_id,finding_id) REFERENCES defender_shadow_findings(company_id,projection_id,finding_id) ON DELETE CASCADE
);
CREATE INDEX defender_shadow_workflow_status ON defender_shadow_workflow(company_id,projection_id,status,finding_id);
CREATE TABLE defender_shadow_assessments (
  company_id text NOT NULL,
  projection_id uuid NOT NULL,
  finding_id text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('Critical','High','Medium','Low','Info')),
  cvss double precision NOT NULL CHECK (cvss>=0 AND cvss<=10),
  real_risk double precision NOT NULL CHECK (real_risk>=0 AND real_risk<=100),
  risk_priority text NOT NULL CHECK (risk_priority IN ('Critical','High','Medium','Low','Info')),
  PRIMARY KEY (company_id,projection_id,finding_id),
  FOREIGN KEY (company_id,projection_id,finding_id) REFERENCES defender_shadow_findings(company_id,projection_id,finding_id) ON DELETE CASCADE
);
CREATE TABLE defender_shadow_evidence (
  company_id text NOT NULL,
  projection_id uuid NOT NULL,
  finding_id text NOT NULL,
  device_id text NOT NULL,
  issue_key text NOT NULL,
  source_run text NOT NULL,
  observed_at text NOT NULL,
  active boolean NOT NULL,
  source_cvss double precision CHECK (source_cvss>=0 AND source_cvss<=10),
  detail jsonb NOT NULL CHECK (jsonb_typeof(detail)='object'),
  PRIMARY KEY (company_id,projection_id,finding_id),
  UNIQUE (company_id,projection_id,device_id,issue_key),
  FOREIGN KEY (company_id,projection_id,finding_id) REFERENCES defender_shadow_findings(company_id,projection_id,finding_id) ON DELETE CASCADE
);
-- Asset keys are preserved legacy identifiers, not newly verified asset IDs.
-- No source-generation FK: retained older evidence can outlive source retention.
-- No active pointer, source-authority activation, or ticket/asset/history mutation.
