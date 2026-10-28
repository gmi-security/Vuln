-- Explicit maintenance conversion; caller owns the transaction and DDL budget.
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='15min';
CREATE TABLE app_finding_publications (
 id uuid PRIMARY KEY,
 base_generation uuid,
 base_epoch bigint,
 base_revision bigint,
 plan_hash text UNIQUE CHECK(plan_hash IS NULL OR plan_hash ~ '^[a-f0-9]{64}$'),
 report_plan_hash text CHECK(report_plan_hash IS NULL OR report_plan_hash ~ '^[a-f0-9]{64}$'),
 phase text NOT NULL CHECK(phase IN ('writing','copying','deleting','reporting','ready','published','discarded')),
 write_offset integer NOT NULL DEFAULT 0 CHECK(write_offset>=0),
 copy_after text,
 delete_offset integer NOT NULL DEFAULT 0 CHECK(delete_offset>=0),
 record_count bigint,
 report_progress jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(report_progress)='object'),
 report_digests jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO app_finding_publications(id,phase) VALUES('00000000-0000-0000-0000-000000000000','published');
CREATE TABLE app_finding_head (
 id integer PRIMARY KEY CHECK(id=1),
 generation uuid NOT NULL REFERENCES app_finding_publications(id)
);
INSERT INTO app_finding_head VALUES(1,'00000000-0000-0000-0000-000000000000');

ALTER TABLE app_findings RENAME TO app_finding_versions;
ALTER TABLE app_finding_versions ADD COLUMN generation uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
ALTER TABLE app_finding_versions DROP CONSTRAINT app_findings_pkey;
ALTER TABLE app_finding_versions ADD PRIMARY KEY(generation,id);
DROP INDEX app_findings_company_risk_idx;
DROP INDEX app_findings_company_status_idx;
DROP INDEX app_findings_scan_idx;
DROP INDEX app_findings_company_cve_idx;
DROP INDEX app_findings_store_order_idx;
DROP INDEX app_findings_customer_stream_idx;
CREATE INDEX app_findings_company_risk_idx ON app_finding_versions(generation,company_id,real_risk DESC,id);
CREATE INDEX app_findings_company_status_idx ON app_finding_versions(generation,company_id,status,severity,id);
CREATE INDEX app_findings_scan_idx ON app_finding_versions(generation,scan_id,id);
CREATE INDEX app_findings_company_cve_idx ON app_finding_versions(generation,company_id,cve,id);
CREATE INDEX app_findings_store_order_idx ON app_finding_versions(generation,store_bucket,store_order,id);
CREATE INDEX app_findings_customer_stream_idx ON app_finding_versions(generation,company_id,store_bucket,store_order,id);
CREATE VIEW app_findings AS SELECT id,company_id,scan_id,connector,status,severity,cve,asset,real_risk,last_seen,payload,store_order,store_bucket,record_hash
 FROM app_finding_versions WHERE generation=(SELECT generation FROM app_finding_head WHERE id=1);
CREATE TRIGGER app_store_write_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON app_finding_head
 FOR EACH STATEMENT EXECUTE FUNCTION app_store_write_fence();
CREATE TRIGGER app_store_write_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON app_finding_publications
 FOR EACH STATEMENT EXECUTE FUNCTION app_store_write_fence();
SET LOCAL statement_timeout='60s';
