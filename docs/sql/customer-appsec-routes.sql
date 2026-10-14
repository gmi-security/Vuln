-- Additive operational AppSec approval after drafts/bindings. No approvals or
-- source findings are seeded; reviewing a binding is still not activation.
BEGIN;
CREATE FUNCTION valid_appsec_repositories(value TEXT) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE repos JSONB; n INTEGER; distinct_n INTEGER;
BEGIN
  repos := value::jsonb;
  IF jsonb_typeof(repos)<>'array' OR jsonb_array_length(repos) NOT BETWEEN 1 AND 100 THEN RETURN false; END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(repos) r WHERE jsonb_typeof(r)<>'string'
    OR (r #>> '{}') !~ '^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9_.-]{1,100}$' OR (r #>> '{}') ~ '/\.{1,2}$') THEN RETURN false; END IF;
  SELECT count(*),count(DISTINCT r) INTO n,distinct_n FROM jsonb_array_elements_text(repos) r;
  RETURN n=distinct_n;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
CREATE TABLE customer_appsec_routes (
  candidate_id TEXT NOT NULL,
  company_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK(provider='appsec'),
  source_scope TEXT NOT NULL CHECK(valid_appsec_repositories(source_scope)),
  binding_revision INTEGER NOT NULL CHECK(binding_revision>0),
  candidate_hash TEXT NOT NULL CHECK(candidate_hash ~ '^[a-f0-9]{64}$'),
  revision INTEGER NOT NULL CHECK(revision>0),
  enabled BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(candidate_id,company_id),
  FOREIGN KEY(candidate_id,company_id) REFERENCES customer_connector_bindings(candidate_id,company_id)
);
CREATE UNIQUE INDEX customer_appsec_route_customer ON customer_appsec_routes(company_id) WHERE enabled;
CREATE TABLE customer_appsec_route_audit (
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
  FOREIGN KEY(candidate_id,company_id) REFERENCES customer_appsec_routes(candidate_id,company_id)
);
CREATE FUNCTION enforce_appsec_repository_ownership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT NEW.enabled THEN RETURN NEW; END IF;
  PERFORM pg_advisory_xact_lock(716301,1);
  IF EXISTS(SELECT 1 FROM public.customer_appsec_routes r WHERE r.enabled AND r.company_id<>NEW.company_id
    AND r.source_scope::jsonb ?| ARRAY(SELECT jsonb_array_elements_text(NEW.source_scope::jsonb))) THEN
    RAISE EXCEPTION 'AppSec repository ownership conflict' USING ERRCODE='23505';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER appsec_repository_ownership BEFORE INSERT OR UPDATE ON customer_appsec_routes
  FOR EACH ROW EXECUTE FUNCTION enforce_appsec_repository_ownership();
COMMIT;
-- Keep approvals/audit on rollback. Disabling reviewed routing restores legacy
-- organization-wide access; it is not an emergency revocation mechanism.
