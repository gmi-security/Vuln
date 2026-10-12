-- Explicit additive migration after customer inventory routes v1/v2 and the Spotlight source schema.
-- No routes are populated. Legacy proposal enabled=false constraints stay intact.
BEGIN;
CREATE TABLE customer_spotlight_routes (
  candidate_id TEXT NOT NULL,
  company_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK(provider IN ('crowdstrike')),
  source_scope TEXT NOT NULL CHECK(source_scope ~ '^[a-f0-9]{32}$'),
  binding_revision INTEGER NOT NULL CHECK(binding_revision>0),
  candidate_hash TEXT NOT NULL CHECK(candidate_hash ~ '^[a-f0-9]{64}$'),
  revision INTEGER NOT NULL CHECK(revision>0),
  enabled BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(candidate_id,company_id),
  FOREIGN KEY(candidate_id,company_id) REFERENCES customer_connector_bindings(candidate_id,company_id)
);
CREATE UNIQUE INDEX customer_spotlight_route_owner ON customer_spotlight_routes(provider,source_scope) WHERE enabled;
CREATE UNIQUE INDEX customer_spotlight_route_connection ON customer_spotlight_routes(candidate_id) WHERE enabled;
CREATE UNIQUE INDEX customer_spotlight_route_customer ON customer_spotlight_routes(company_id) WHERE enabled;
CREATE TABLE customer_spotlight_route_audit (
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
  FOREIGN KEY(candidate_id,company_id) REFERENCES customer_spotlight_routes(candidate_id,company_id)
);
-- Install after the existing Spotlight record schema. Version-4 runs alone use
-- these pins; legacy version-3 runs can never resume a reviewed generation.
CREATE TABLE spotlight_import_run_scopes (
  run_id UUID PRIMARY KEY REFERENCES spotlight_import_runs(id) ON DELETE CASCADE,
  binding_key TEXT NOT NULL CHECK(binding_key ~ '^[a-f0-9]{64}$'),
  company_id TEXT NOT NULL,
  cid TEXT NOT NULL CHECK(cid ~ '^[a-f0-9]{32}$')
);
-- Inventory and findings have independent approvals but must agree on source ownership.
-- The advisory lock also protects callers outside the operator command service.
CREATE FUNCTION enforce_falcon_route_ownership() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE conflict_found BOOLEAN;
BEGIN
  IF NOT NEW.enabled OR NEW.provider <> 'crowdstrike' THEN RETURN NEW; END IF;
  PERFORM pg_advisory_xact_lock(716301,1);
  IF TG_TABLE_NAME='customer_spotlight_routes' THEN
    SELECT EXISTS(SELECT 1 FROM customer_inventory_routes r WHERE r.enabled AND r.provider='crowdstrike' AND
      ((r.source_scope=NEW.source_scope AND r.company_id<>NEW.company_id) OR
       (r.candidate_id=NEW.candidate_id AND (r.company_id<>NEW.company_id OR r.source_scope<>NEW.source_scope)))) INTO conflict_found;
  ELSE
    SELECT EXISTS(SELECT 1 FROM customer_spotlight_routes r WHERE r.enabled AND
      ((r.source_scope=NEW.source_scope AND r.company_id<>NEW.company_id) OR
       (r.candidate_id=NEW.candidate_id AND (r.company_id<>NEW.company_id OR r.source_scope<>NEW.source_scope)))) INTO conflict_found;
  END IF;
  IF conflict_found THEN RAISE EXCEPTION 'CrowdStrike inventory and Spotlight ownership conflict' USING ERRCODE='23505'; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER spotlight_route_ownership BEFORE INSERT OR UPDATE ON customer_spotlight_routes
  FOR EACH ROW EXECUTE FUNCTION enforce_falcon_route_ownership();
CREATE TRIGGER inventory_spotlight_route_ownership BEFORE INSERT OR UPDATE ON customer_inventory_routes
  FOR EACH ROW EXECUTE FUNCTION enforce_falcon_route_ownership();
COMMIT;
-- Retain approvals and audit on code rollback; do not delete source/platform data.
