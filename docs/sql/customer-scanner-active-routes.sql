-- Apply after customer-scanner-osint-routes.sql. No approvals are populated.
BEGIN;
ALTER TABLE customer_scanner_routes DROP CONSTRAINT customer_scanner_routes_provider_check;
ALTER TABLE customer_scanner_routes DROP CONSTRAINT customer_scanner_routes_source_scope_check;
ALTER TABLE customer_scanner_routes ADD CONSTRAINT customer_scanner_routes_provider_check
  CHECK(provider IN ('nessus','spiderfoot','artemis','zap','vulners'));
ALTER TABLE customer_scanner_routes ADD CONSTRAINT customer_scanner_routes_source_scope_check CHECK(
  (provider='nessus' AND source_scope ~ '^[1-9][0-9]*$') OR
  (provider IN ('spiderfoot','zap','vulners') AND source_scope ~ '^targets:[a-f0-9]{64}$') OR
  (provider='artemis' AND length(source_scope) BETWEEN 1 AND 160 AND source_scope=btrim(source_scope))
);
COMMIT;
-- Keep approvals and audit on rollback; drain scans before changing routing.
