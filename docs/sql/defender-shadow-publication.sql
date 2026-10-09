-- Explicit disposable migration after base v2 and read-model v1 tables.
-- No production initializer. Verified generations are retained, including rollback targets.
ALTER TABLE defender_shadow_generations ADD COLUMN reads_sealed boolean NOT NULL DEFAULT false;
UPDATE defender_shadow_generations g SET reads_sealed=true WHERE EXISTS(
  SELECT 1 FROM defender_shadow_read_summary s WHERE s.company_id=g.company_id AND s.projection_id=g.projection_id);
CREATE FUNCTION defender_shadow_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Shadow records cannot be truncated' USING ERRCODE='55000'; END $$;

CREATE FUNCTION defender_shadow_generation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n bigint; relation text;
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.state<>'building' OR NEW.reads_sealed THEN RAISE EXCEPTION 'New shadow generation must be building' USING ERRCODE='55000'; END IF;
    RETURN NEW;
  END IF;
  -- Only the summary INSERT trigger may seal derived reads. Updating the
  -- parent row makes stale REPEATABLE READ writers fail with serialization
  -- errors rather than trusting an old snapshot without the summary marker.
  IF TG_OP='UPDATE' AND pg_trigger_depth()=2 AND OLD.state='verified' AND NOT OLD.reads_sealed AND NEW.reads_sealed
    AND (to_jsonb(OLD)-'reads_sealed')=(to_jsonb(NEW)-'reads_sealed') THEN RETURN NEW; END IF;
  IF OLD.state='verified' THEN RAISE EXCEPTION 'Verified shadow generation is immutable' USING ERRCODE='55000'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  IF OLD.company_id<>NEW.company_id OR OLD.projection_id<>NEW.projection_id OR OLD.state<>'building' THEN
    RAISE EXCEPTION 'Shadow generation identity or state is immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.state='verified' THEN
    IF current_setting('transaction_isolation')<>'read committed' THEN
      RAISE EXCEPTION 'Verification requires a fresh read-committed transaction' USING ERRCODE='55000';
    END IF;
    -- The UPDATE holds the generation row lock. Child writers take FOR SHARE,
    -- so no child transaction can slip through verification concurrently.
    FOREACH relation IN ARRAY ARRAY['findings','workflow','assessments','evidence'] LOOP
      EXECUTE format('SELECT count(*) FROM defender_shadow_%I WHERE company_id=$1 AND projection_id=$2',relation)
        INTO n USING NEW.company_id,NEW.projection_id;
      IF n IS DISTINCT FROM NEW.finding_count THEN RAISE EXCEPTION 'Incomplete shadow generation' USING ERRCODE='55000'; END IF;
    END LOOP;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER defender_shadow_generation_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_shadow_generations
  FOR EACH ROW EXECUTE FUNCTION defender_shadow_generation_guard();

CREATE FUNCTION defender_shadow_record_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner text; generation uuid; current_state text;
BEGIN
  IF TG_OP='DELETE' THEN owner:=OLD.company_id; generation:=OLD.projection_id;
  ELSE owner:=NEW.company_id; generation:=NEW.projection_id; END IF;
  IF TG_OP='UPDATE' AND (OLD.company_id<>NEW.company_id OR OLD.projection_id<>NEW.projection_id OR OLD.finding_id<>NEW.finding_id) THEN
    RAISE EXCEPTION 'Shadow finding identity is immutable' USING ERRCODE='55000';
  END IF;
  SELECT state INTO current_state FROM defender_shadow_generations WHERE company_id=owner AND projection_id=generation FOR SHARE;
  -- Cascaded deletion of a failed/building parent is permitted. A verified parent cannot be deleted.
  IF TG_OP='DELETE' AND NOT FOUND THEN RETURN OLD; END IF;
  IF current_state IS DISTINCT FROM 'building' THEN RAISE EXCEPTION 'Shadow records require a building generation' USING ERRCODE='55000'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;

CREATE FUNCTION defender_shadow_derived_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner text; generation uuid; g defender_shadow_generations%ROWTYPE;
BEGIN
  IF TG_OP='DELETE' THEN owner:=OLD.company_id; generation:=OLD.projection_id;
  ELSE owner:=NEW.company_id; generation:=NEW.projection_id; END IF;
  IF TG_OP='UPDATE' AND (OLD.company_id<>NEW.company_id OR OLD.projection_id<>NEW.projection_id) THEN
    RAISE EXCEPTION 'Derived shadow scope is immutable' USING ERRCODE='55000';
  END IF;
  -- Same lease as the existing derived builder, including direct SQL mutations.
  PERFORM pg_advisory_xact_lock(hashtextextended(owner||':'||generation::text,804247));
  SELECT * INTO g FROM defender_shadow_generations WHERE company_id=owner AND projection_id=generation FOR SHARE;
  IF g.state IS DISTINCT FROM 'verified' THEN RAISE EXCEPTION 'Derived data requires verified generation' USING ERRCODE='55000'; END IF;
  IF g.reads_sealed OR EXISTS(SELECT 1 FROM defender_shadow_read_summary WHERE company_id=owner AND projection_id=generation) THEN
    RAISE EXCEPTION 'Completed derived data is immutable' USING ERRCODE='55000';
  END IF;
  IF TG_TABLE_NAME='defender_shadow_read_summary' THEN
    IF TG_OP<>'INSERT' OR NEW.read_version<>1 OR NEW.finding_count<>g.finding_count OR
      (NEW.summary->>'records')::bigint IS DISTINCT FROM g.finding_count OR
      (SELECT count(*) FROM defender_shadow_priority WHERE company_id=owner AND projection_id=generation) IS DISTINCT FROM
        (SELECT sum(value::bigint) FROM jsonb_each_text(NEW.summary->'endpointByStatus')) OR
      (SELECT count(*) FROM defender_shadow_cve_pages WHERE company_id=owner AND projection_id=generation) IS DISTINCT FROM
        (NEW.summary->>'uniqueOpenCves')::bigint THEN
      RAISE EXCEPTION 'Incomplete derived shadow data' USING ERRCODE='55000';
    END IF;
    UPDATE defender_shadow_generations SET reads_sealed=true WHERE company_id=owner AND projection_id=generation;
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;

DO $$ DECLARE relation text; BEGIN
  FOREACH relation IN ARRAY ARRAY['findings','workflow','assessments','evidence'] LOOP
    EXECUTE format('CREATE TRIGGER shadow_record_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_shadow_%I FOR EACH ROW EXECUTE FUNCTION defender_shadow_record_guard()',relation);
  END LOOP;
  FOREACH relation IN ARRAY ARRAY['read_summary','priority','cve_pages'] LOOP
    EXECUTE format('CREATE TRIGGER shadow_derived_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_shadow_%I FOR EACH ROW EXECUTE FUNCTION defender_shadow_derived_guard()',relation);
  END LOOP;
  FOREACH relation IN ARRAY ARRAY['generations','findings','workflow','assessments','evidence','read_summary','priority','cve_pages'] LOOP
    EXECUTE format('CREATE TRIGGER shadow_no_truncate BEFORE TRUNCATE ON defender_shadow_%I EXECUTE FUNCTION defender_shadow_no_truncate()',relation);
  END LOOP;
END $$;

CREATE TABLE defender_shadow_publications (
  company_id text PRIMARY KEY, projection_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
  actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 120),reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
  published_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(company_id,projection_id) REFERENCES defender_shadow_generations(company_id,projection_id)
);
CREATE TABLE defender_shadow_publication_events (
  company_id text NOT NULL,revision bigint NOT NULL,from_projection uuid,projection_id uuid NOT NULL,
  actor text NOT NULL,reason text NOT NULL,published_at timestamptz NOT NULL,
  PRIMARY KEY(company_id,revision),
  FOREIGN KEY(company_id,projection_id) REFERENCES defender_shadow_generations(company_id,projection_id),
  FOREIGN KEY(company_id,from_projection) REFERENCES defender_shadow_generations(company_id,projection_id)
);
CREATE FUNCTION defender_shadow_publication_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Publication must be switched explicitly, not deleted' USING ERRCODE='55000'; END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.revision<>1 THEN RAISE EXCEPTION 'Initial publication revision must be one' USING ERRCODE='55000'; END IF;
  ELSE
    IF NEW.company_id<>OLD.company_id OR NEW.revision<>OLD.revision+1 OR NEW.projection_id=OLD.projection_id THEN
      RAISE EXCEPTION 'Invalid publication revision or identity' USING ERRCODE='55000';
    END IF;
  END IF;
  IF NOT EXISTS(SELECT 1 FROM defender_shadow_generations g JOIN defender_shadow_read_summary s USING(company_id,projection_id)
    WHERE g.company_id=NEW.company_id AND g.projection_id=NEW.projection_id AND g.state='verified' AND g.reads_sealed AND g.model_version=2
      AND s.read_version=1 AND s.finding_count=g.finding_count) THEN
    RAISE EXCEPTION 'Publication requires complete verified data and saved reads' USING ERRCODE='55000';
  END IF;
  NEW.published_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE FUNCTION defender_shadow_publication_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO defender_shadow_publication_events VALUES(NEW.company_id,NEW.revision,
    CASE WHEN TG_OP='UPDATE' THEN OLD.projection_id ELSE NULL END,NEW.projection_id,NEW.actor,NEW.reason,NEW.published_at);
  RETURN NEW;
END $$;
CREATE FUNCTION defender_shadow_publication_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP<>'INSERT' OR pg_trigger_depth()<>2 THEN RAISE EXCEPTION 'Publication history is append-only' USING ERRCODE='55000'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER publication_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_shadow_publications FOR EACH ROW EXECUTE FUNCTION defender_shadow_publication_guard();
CREATE TRIGGER publication_audit AFTER INSERT OR UPDATE ON defender_shadow_publications FOR EACH ROW EXECUTE FUNCTION defender_shadow_publication_audit();
CREATE TRIGGER publication_event_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_shadow_publication_events FOR EACH ROW EXECUTE FUNCTION defender_shadow_publication_event_guard();
CREATE TRIGGER publication_no_truncate BEFORE TRUNCATE ON defender_shadow_publications EXECUTE FUNCTION defender_shadow_no_truncate();
CREATE TRIGGER publication_event_no_truncate BEFORE TRUNCATE ON defender_shadow_publication_events EXECUTE FUNCTION defender_shadow_no_truncate();
