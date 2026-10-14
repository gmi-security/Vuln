-- Explicit additive migration after customer-connector-bindings.sql.
-- No routes are populated. Legacy proposal enabled=false constraints stay intact.
BEGIN;
CREATE TABLE customer_scanner_routes (
  candidate_id TEXT NOT NULL,
  company_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK(provider IN ('nessus')),
  source_scope TEXT NOT NULL CHECK(source_scope ~ '^[1-9][0-9]*$'),
  binding_revision INTEGER NOT NULL CHECK(binding_revision>0),
  candidate_hash TEXT NOT NULL CHECK(candidate_hash ~ '^[a-f0-9]{64}$'),
  revision INTEGER NOT NULL CHECK(revision>0),
  enabled BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(candidate_id,company_id),
  FOREIGN KEY(candidate_id,company_id) REFERENCES customer_connector_bindings(candidate_id,company_id)
);
CREATE UNIQUE INDEX customer_scanner_route_owner ON customer_scanner_routes(provider,source_scope) WHERE enabled;
CREATE TABLE customer_scanner_route_audit (
  id BIGSERIAL PRIMARY KEY,
  candidate_id TEXT NOT NULL,
  company_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  actor TEXT NOT NULL,
  before_state JSONB,
  after_state JSONB NOT NULL,
  note TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(candidate_id,company_id,revision),
  FOREIGN KEY(candidate_id,company_id) REFERENCES customer_scanner_routes(candidate_id,company_id)
);
COMMIT;
-- Retain approvals and audit on code rollback; do not delete source/platform data.
