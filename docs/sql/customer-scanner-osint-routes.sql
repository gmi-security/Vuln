-- Explicit additive extension after customer-scanner-routes.sql. No approvals populated.
BEGIN;
ALTER TABLE customer_scanner_routes DROP CONSTRAINT customer_scanner_routes_provider_check;
ALTER TABLE customer_scanner_routes DROP CONSTRAINT customer_scanner_routes_source_scope_check;
ALTER TABLE customer_scanner_routes ADD CONSTRAINT customer_scanner_routes_provider_check
  CHECK(provider IN ('nessus','spiderfoot','artemis'));
ALTER TABLE customer_scanner_routes ADD CONSTRAINT customer_scanner_routes_source_scope_check CHECK(
  (provider='nessus' AND source_scope ~ '^[1-9][0-9]*$') OR
  (provider='spiderfoot' AND source_scope ~ '^targets:[a-f0-9]{64}$') OR
  (provider='artemis' AND length(source_scope) BETWEEN 1 AND 160 AND source_scope=btrim(source_scope))
);
COMMIT;
-- Preserve route and audit records on rollback. Older binaries do not enforce OSINT routes.
