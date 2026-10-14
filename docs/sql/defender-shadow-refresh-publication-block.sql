-- Recovery targets only, after defender-shadow-refresh.sql.
-- The old RAM store has no durable workflow revision. Until live write fencing
-- exists, even an apparently fresh refresh candidate cannot be selected.
CREATE FUNCTION defender_shadow_refresh_publication_block() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM defender_shadow_refresh_candidates WHERE company_id=NEW.company_id AND projection_id=NEW.projection_id) THEN
    RAISE EXCEPTION 'Refresh candidates are comparison-only; live workflow fencing is not implemented' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER refresh_publication_block BEFORE INSERT OR UPDATE ON defender_shadow_publications
  FOR EACH ROW EXECUTE FUNCTION defender_shadow_refresh_publication_block();
