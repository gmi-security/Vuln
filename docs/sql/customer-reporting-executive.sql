-- Apply after customer-reporting-buckets.sql and customer-reporting-sections.sql.
-- Derived reports only. Republish inputs with the new writer before reading v3.
BEGIN;
ALTER TABLE customer_reporting_inputs DROP CONSTRAINT customer_reporting_inputs_format_version_check;
ALTER TABLE customer_reporting_inputs ADD CONSTRAINT customer_reporting_inputs_format_version_check CHECK(format_version IN (1,2,3));
ALTER TABLE customer_reporting_publication DROP CONSTRAINT customer_reporting_publication_format_version_check;
ALTER TABLE customer_reporting_publication ADD CONSTRAINT customer_reporting_publication_format_version_check CHECK(format_version IN (1,2,3));
ALTER TABLE customer_reporting_sections ADD COLUMN executive JSONB;
ALTER TABLE customer_reporting_sections ADD COLUMN executive_hash TEXT;
ALTER TABLE customer_reporting_sections ADD CONSTRAINT customer_reporting_executive_check CHECK (
 (executive IS NULL AND executive_hash IS NULL) OR
 (executive IS NOT NULL AND executive_hash IS NOT NULL AND executive_hash ~ '^[a-f0-9]{64}$'
  AND jsonb_typeof(executive)='object' AND executive->'company'->>'id'=company_id)
);
COMMIT;
