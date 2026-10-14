-- Explicit additive migration after bindings, inventory routes v1/v2 and Spotlight routes.
-- No routes are populated. Legacy proposal enabled=false constraints stay intact.
BEGIN;
CREATE TABLE customer_query_routes (
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
CREATE UNIQUE INDEX customer_query_route_owner ON customer_query_routes(provider,source_scope) WHERE enabled;
CREATE UNIQUE INDEX customer_query_route_customer ON customer_query_routes(company_id) WHERE enabled;
CREATE TABLE customer_query_route_audit (
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
  FOREIGN KEY(candidate_id,company_id) REFERENCES customer_query_routes(candidate_id,company_id)
);
-- Saved queries and imports may use different credentials, but a CID must
-- still have one customer owner. Existing inventory/Spotlight guards remain.
CREATE FUNCTION enforce_falcon_query_ownership() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE peer TEXT; conflict_found BOOLEAN;
BEGIN
  IF NOT NEW.enabled OR NEW.provider <> 'crowdstrike' THEN RETURN NEW; END IF;
  PERFORM pg_advisory_xact_lock(716301,1);
  FOREACH peer IN ARRAY ARRAY['customer_inventory_routes','customer_spotlight_routes','customer_query_routes'] LOOP
    IF peer = TG_TABLE_NAME THEN CONTINUE; END IF;
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM public.%I WHERE enabled AND provider=''crowdstrike'' AND source_scope=$1 AND company_id<>$2)',peer)
      INTO conflict_found USING NEW.source_scope,NEW.company_id;
    IF conflict_found THEN RAISE EXCEPTION 'CrowdStrike query and import ownership conflict' USING ERRCODE='23505'; END IF;
  END LOOP;
  RETURN NEW;
END;
$$;
CREATE TRIGGER query_route_cross_ownership BEFORE INSERT OR UPDATE ON customer_query_routes
  FOR EACH ROW EXECUTE FUNCTION enforce_falcon_query_ownership();
CREATE TRIGGER inventory_query_cross_ownership BEFORE INSERT OR UPDATE ON customer_inventory_routes
  FOR EACH ROW EXECUTE FUNCTION enforce_falcon_query_ownership();
CREATE TRIGGER spotlight_query_cross_ownership BEFORE INSERT OR UPDATE ON customer_spotlight_routes
  FOR EACH ROW EXECUTE FUNCTION enforce_falcon_query_ownership();
COMMIT;
-- Retain approvals and audit on code rollback; do not delete source/platform data.
