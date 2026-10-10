-- Additive, explicit migration after customer-connector-drafts.sql.
-- Separate customer scope from shared connection evidence. No live activation.
BEGIN;
CREATE TABLE customer_connector_bindings (
  candidate_id TEXT NOT NULL REFERENCES customer_connector_drafts(id),
  company_id TEXT NOT NULL CHECK (company_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$'),
  candidate_hash TEXT NOT NULL CHECK (candidate_hash ~ '^[a-f0-9]{64}$'),
  proposal JSONB NOT NULL CHECK (jsonb_typeof(proposal)='object' AND proposal->>'companyId' IS NOT NULL AND proposal->>'companyId'=company_id),
  revision INTEGER NOT NULL CHECK (revision>0),
  review_state TEXT NOT NULL CHECK (review_state IN ('pending-review','reviewed','dismissed')),
  enabled BOOLEAN NOT NULL DEFAULT false CHECK (enabled=false),
  reviewed_by TEXT,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (candidate_id, company_id)
);
CREATE INDEX customer_connector_bindings_customer ON customer_connector_bindings(company_id,candidate_id);
CREATE TABLE customer_connector_binding_audit (
  id BIGSERIAL PRIMARY KEY,
  candidate_id TEXT NOT NULL,
  company_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('save-draft','reviewed','dismissed')),
  before_state JSONB,
  after_state JSONB NOT NULL,
  note TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (candidate_id,company_id) REFERENCES customer_connector_bindings(candidate_id,company_id),
  UNIQUE (candidate_id,company_id,revision)
);
COMMIT;
-- Retain bindings/audit during rollback. No source, tile or credential rows change.
