-- Explicit additive migration. Install BEFORE enabling VULN_REPORTING_INPUT_REVISIONS.
-- Derived freshness metadata only; vuln_store remains the current write authority.
BEGIN;
CREATE TABLE customer_reporting_inputs (
 company_id TEXT PRIMARY KEY CHECK(company_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$'),
 format_version INTEGER NOT NULL CHECK(format_version=1),
 revision BIGINT NOT NULL CHECK(revision>0),
 generation UUID NOT NULL,
 content_hash TEXT NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
 published_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE customer_reporting_publication (
 id INTEGER PRIMARY KEY CHECK(id=1),
 format_version INTEGER NOT NULL CHECK(format_version=1),
 manifest_hash TEXT NOT NULL CHECK(manifest_hash ~ '^[a-f0-9]{64}$'),
 published_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
COMMIT;
-- Disable saved Overview reads and the worker before disabling revision writes.
-- Keep these small derived tables on rollback; do not delete source data.
