-- Offline recovery prototype only. Does not replace the app's memory writer.
CREATE TABLE defender_workflow_heads (
  company_id text PRIMARY KEY, revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0)
);
CREATE TABLE defender_workflow_edits (
  company_id text NOT NULL REFERENCES defender_workflow_heads(company_id),
  finding_id text NOT NULL, device_id text NOT NULL, cve text NOT NULL,
  revision bigint NOT NULL CHECK(revision>0), company_revision bigint NOT NULL CHECK(company_revision>0),
  patches jsonb NOT NULL CHECK(jsonb_typeof(patches)='object' AND patches<>'{}'::jsonb),
  actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 120),
  reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(company_id,finding_id)
);
CREATE TABLE defender_workflow_events (
  company_id text NOT NULL, finding_id text NOT NULL, revision bigint NOT NULL, company_revision bigint NOT NULL,
  before_state jsonb, after_state jsonb NOT NULL, actor text NOT NULL, reason text NOT NULL, recorded_at timestamptz NOT NULL,
  PRIMARY KEY(company_id,finding_id,revision), UNIQUE(company_id,company_revision)
);
CREATE FUNCTION defender_workflow_edit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE current_revision bigint;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Workflow records cannot be deleted'; END IF;
  SELECT revision INTO current_revision FROM defender_workflow_heads WHERE company_id=NEW.company_id FOR UPDATE;
  IF current_revision IS DISTINCT FROM NEW.company_revision THEN RAISE EXCEPTION 'Workflow customer revision mismatch'; END IF;
  IF TG_OP='INSERT' AND NEW.revision<>1 THEN RAISE EXCEPTION 'Initial workflow revision must be one'; END IF;
  IF TG_OP='UPDATE' AND (NEW.company_id<>OLD.company_id OR NEW.finding_id<>OLD.finding_id OR NEW.device_id<>OLD.device_id OR NEW.cve<>OLD.cve
    OR NEW.revision<>OLD.revision+1 OR NEW.company_revision<=OLD.company_revision) THEN RAISE EXCEPTION 'Invalid workflow identity or revision'; END IF;
  NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
CREATE FUNCTION defender_workflow_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO defender_workflow_events VALUES(NEW.company_id,NEW.finding_id,NEW.revision,NEW.company_revision,
    CASE WHEN TG_OP='UPDATE' THEN to_jsonb(OLD) ELSE NULL END,to_jsonb(NEW),NEW.actor,NEW.reason,NEW.updated_at);
  RETURN NEW;
END $$;
CREATE FUNCTION defender_workflow_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP<>'INSERT' OR pg_trigger_depth()<>2 THEN RAISE EXCEPTION 'Workflow audit is append-only and written by the state trigger'; END IF;
  RETURN NEW;
END $$;
CREATE FUNCTION defender_workflow_head_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Workflow head cannot be deleted'; END IF;
  IF TG_OP='UPDATE' AND (NEW.company_id<>OLD.company_id OR NEW.revision<>OLD.revision+1) THEN RAISE EXCEPTION 'Invalid workflow head revision'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_edit_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_workflow_edits FOR EACH ROW EXECUTE FUNCTION defender_workflow_edit_guard();
CREATE TRIGGER workflow_audit AFTER INSERT OR UPDATE ON defender_workflow_edits FOR EACH ROW EXECUTE FUNCTION defender_workflow_audit();
CREATE TRIGGER workflow_event_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_workflow_events FOR EACH ROW EXECUTE FUNCTION defender_workflow_event_guard();
CREATE TRIGGER workflow_head_guard BEFORE UPDATE OR DELETE ON defender_workflow_heads FOR EACH ROW EXECUTE FUNCTION defender_workflow_head_guard();
CREATE TRIGGER workflow_edits_no_truncate BEFORE TRUNCATE ON defender_workflow_edits FOR EACH STATEMENT EXECUTE FUNCTION defender_shadow_no_truncate();
CREATE TRIGGER workflow_events_no_truncate BEFORE TRUNCATE ON defender_workflow_events FOR EACH STATEMENT EXECUTE FUNCTION defender_shadow_no_truncate();
CREATE TRIGGER workflow_heads_no_truncate BEFORE TRUNCATE ON defender_workflow_heads FOR EACH STATEMENT EXECUTE FUNCTION defender_shadow_no_truncate();
