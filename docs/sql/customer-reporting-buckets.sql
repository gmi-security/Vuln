-- Explicit additive follow-up to customer-reporting-inputs.sql. No source data changes.
-- Version 1 rows remain stored but cannot be read as version 2 until republished.
BEGIN;
ALTER TABLE customer_reporting_inputs ADD COLUMN bucket_map JSONB;
ALTER TABLE customer_reporting_inputs DROP CONSTRAINT customer_reporting_inputs_format_version_check;
ALTER TABLE customer_reporting_inputs ADD CONSTRAINT customer_reporting_inputs_format_version_check CHECK(format_version IN (1,2));
ALTER TABLE customer_reporting_inputs ADD CONSTRAINT customer_reporting_inputs_bucket_map_check
 CHECK(format_version=1 OR (bucket_map IS NOT NULL AND jsonb_typeof(bucket_map)='array' AND jsonb_array_length(bucket_map) BETWEEN 1 AND 89));
ALTER TABLE customer_reporting_publication DROP CONSTRAINT customer_reporting_publication_format_version_check;
ALTER TABLE customer_reporting_publication ADD CONSTRAINT customer_reporting_publication_format_version_check CHECK(format_version IN (1,2));
COMMIT;
-- Read rollback: disable the SQL read flag and worker; retain both versions/tables.
