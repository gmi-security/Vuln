-- Disposable shadow projection v2 only; explicit install, no app bootstrap.
CREATE TABLE defender_shadow_read_summary (
  company_id text NOT NULL, projection_id uuid NOT NULL,
  read_version integer NOT NULL CHECK(read_version=1),
  finding_count integer NOT NULL CHECK(finding_count>=0),
  summary jsonb NOT NULL CHECK(jsonb_typeof(summary)='object'),
  built_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(company_id,projection_id),
  FOREIGN KEY(company_id,projection_id) REFERENCES defender_shadow_generations(company_id,projection_id) ON DELETE CASCADE
);
CREATE TABLE defender_shadow_priority (
  company_id text NOT NULL, projection_id uuid NOT NULL,
  position integer NOT NULL CHECK(position>0), finding_id text NOT NULL,
  status text NOT NULL CHECK(status IN('Open','In Remediation','Risk Accepted','False Positive','Resolved')),
  PRIMARY KEY(company_id,projection_id,position),
  UNIQUE(company_id,projection_id,finding_id),
  FOREIGN KEY(company_id,projection_id,finding_id) REFERENCES defender_shadow_findings(company_id,projection_id,finding_id) ON DELETE CASCADE
);
CREATE INDEX defender_shadow_priority_status ON defender_shadow_priority(company_id,projection_id,status,position);
CREATE INDEX defender_shadow_priority_open ON defender_shadow_priority(company_id,projection_id,position)
  WHERE status IN('Open','In Remediation');
CREATE TABLE defender_shadow_cve_pages (
  company_id text NOT NULL, projection_id uuid NOT NULL, position integer NOT NULL CHECK(position>0),
  cve text NOT NULL, severity text NOT NULL, affected_devices integer NOT NULL CHECK(affected_devices>0),
  findings integer NOT NULL CHECK(findings>0), cvss double precision NOT NULL, real_risk double precision NOT NULL,
  PRIMARY KEY(company_id,projection_id,position), UNIQUE(company_id,projection_id,cve),
  FOREIGN KEY(company_id,projection_id) REFERENCES defender_shadow_generations(company_id,projection_id) ON DELETE CASCADE
);
