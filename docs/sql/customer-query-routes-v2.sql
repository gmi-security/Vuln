-- Add reviewed exact Elastic dataset approvals; preserve every CrowdStrike row,
-- revision, audit entry and ownership trigger. No approvals are seeded.
BEGIN;
ALTER TABLE customer_query_routes DROP CONSTRAINT customer_query_routes_provider_check;
ALTER TABLE customer_query_routes DROP CONSTRAINT customer_query_routes_source_scope_check;
ALTER TABLE customer_query_routes ADD CHECK(provider IN ('crowdstrike','elastic'));
CREATE FUNCTION valid_elastic_query_datasets(value TEXT) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE names JSONB; n INTEGER; distinct_n INTEGER;
BEGIN
  names := value::jsonb;
  IF jsonb_typeof(names) <> 'array' OR jsonb_array_length(names) NOT BETWEEN 1 AND 100 THEN RETURN false; END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(names) e WHERE jsonb_typeof(e) <> 'string'
    OR (e #>> '{}') !~ '^[a-z0-9][a-z0-9._-]{0,199}$') THEN RETURN false; END IF;
  SELECT count(*),count(DISTINCT e) INTO n,distinct_n FROM jsonb_array_elements_text(names) e;
  RETURN n=distinct_n;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
ALTER TABLE customer_query_routes ADD CONSTRAINT customer_query_routes_source_scope_check CHECK(
  (provider='crowdstrike' AND source_scope ~ '^[a-f0-9]{32}$') OR
  (provider='elastic' AND valid_elastic_query_datasets(source_scope)));
DROP INDEX customer_query_route_customer;
CREATE UNIQUE INDEX customer_query_route_customer ON customer_query_routes(provider,company_id) WHERE enabled;
CREATE FUNCTION enforce_elastic_query_ownership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT NEW.enabled OR NEW.provider <> 'elastic' THEN RETURN NEW; END IF;
  PERFORM pg_advisory_xact_lock(716301,1);
  IF EXISTS(SELECT 1 FROM public.customer_query_routes r WHERE r.enabled AND r.provider='elastic' AND r.company_id<>NEW.company_id
    AND r.source_scope::jsonb ?| ARRAY(SELECT jsonb_array_elements_text(NEW.source_scope::jsonb))) THEN
    RAISE EXCEPTION 'Elasticsearch dataset ownership conflict' USING ERRCODE='23505';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER query_elastic_cross_ownership BEFORE INSERT OR UPDATE ON customer_query_routes
  FOR EACH ROW EXECUTE FUNCTION enforce_elastic_query_ownership();
COMMIT;
-- Retain this schema and its audit on code rollback. Older code must run with
-- the old/empty switch; it cannot interpret an enabled Elastic provider.
