-- Explicit, additive migration on the application database. No startup hook.
-- This checkpoint stores proposals only. The database disallows activation.
BEGIN;
CREATE TABLE connector_registry_imports (
  id BIGSERIAL PRIMARY KEY,
  fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
  actor TEXT NOT NULL,
  candidate_count INTEGER NOT NULL CHECK (candidate_count BETWEEN 0 AND 10000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE customer_connector_drafts (
  id TEXT PRIMARY KEY CHECK (id ~ '^[a-f0-9]{64}$'),
  candidate JSONB NOT NULL CHECK (jsonb_typeof(candidate) = 'object'),
  candidate_hash TEXT NOT NULL CHECK (candidate_hash ~ '^[a-f0-9]{64}$'),
  source_evidence JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(source_evidence) = 'array'),
  proposal JSONB NOT NULL CHECK (jsonb_typeof(proposal) = 'object'),
  source_present BOOLEAN NOT NULL DEFAULT true,
  review_state TEXT NOT NULL DEFAULT 'pending-review'
    CHECK (review_state IN ('pending-review','reviewed','dismissed','needs-review')),
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
  enabled BOOLEAN NOT NULL DEFAULT false CHECK (enabled = false),
  last_seen_import BIGINT NOT NULL REFERENCES connector_registry_imports(id),
  reviewed_by TEXT,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX customer_connector_draft_company ON customer_connector_drafts ((proposal->>'companyId'), id);
CREATE TABLE customer_connector_audit (
  id BIGSERIAL PRIMARY KEY,
  draft_id TEXT NOT NULL REFERENCES customer_connector_drafts(id),
  import_id BIGINT REFERENCES connector_registry_imports(id),
  action TEXT NOT NULL CHECK (action IN ('imported','source-changed','source-missing','source-restored','edited','reviewed','dismissed')),
  actor TEXT NOT NULL,
  revision INTEGER NOT NULL,
  before_state JSONB,
  after_state JSONB NOT NULL,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (draft_id, revision)
);
COMMIT;

-- Rollback for this checkpoint is to leave these unused tables in place and
-- keep legacy readers active. Do not drop review/audit records to roll back code.
