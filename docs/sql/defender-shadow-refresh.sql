-- Disposable recovery migration, after defender-shadow-publication.sql.
-- Candidate inventory is evidence only, not an authoritative inventory table.
CREATE TABLE defender_shadow_refresh_candidates (
  company_id text NOT NULL,
  projection_id uuid NOT NULL,
  baseline_run text,
  source_revision integer NOT NULL CHECK (source_revision>0),
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence)='object'),
  PRIMARY KEY(company_id,projection_id),
  FOREIGN KEY(company_id,projection_id) REFERENCES defender_shadow_generations(company_id,projection_id) ON DELETE CASCADE
);
CREATE FUNCTION defender_shadow_refresh_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE state text;
BEGIN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Refresh provenance is append-only'; END IF;
  SELECT g.state INTO state FROM defender_shadow_generations g WHERE g.company_id=NEW.company_id AND g.projection_id=NEW.projection_id FOR SHARE;
  IF state IS DISTINCT FROM 'building' THEN RAISE EXCEPTION 'Refresh provenance requires a building generation'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER defender_shadow_refresh_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_shadow_refresh_candidates
  FOR EACH ROW EXECUTE FUNCTION defender_shadow_refresh_guard();
CREATE TRIGGER defender_shadow_refresh_no_truncate BEFORE TRUNCATE ON defender_shadow_refresh_candidates
  FOR EACH STATEMENT EXECUTE FUNCTION defender_shadow_no_truncate();
