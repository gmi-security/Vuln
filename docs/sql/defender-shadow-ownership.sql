-- Disposable recovery prototype only; NOT a production writer switch.
CREATE TABLE defender_writer_ownership (
 company_id text PRIMARY KEY, revision bigint NOT NULL CHECK(revision>=0),
 epoch bigint NOT NULL CHECK(epoch>=0), phase text NOT NULL CHECK(phase IN ('legacy','draining','sql','reversing')),
 data jsonb NOT NULL CHECK(jsonb_typeof(data)='object'),
 actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 120), reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE defender_writer_ownership_audit (
 company_id text NOT NULL, revision bigint NOT NULL, before_state jsonb, after_state jsonb NOT NULL,
 PRIMARY KEY(company_id,revision)
);
CREATE FUNCTION defender_writer_ownership_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Ownership cannot be deleted'; END IF;
 IF TG_OP='INSERT' THEN
   IF NEW.revision<>0 OR NEW.epoch<>0 OR NEW.phase<>'legacy' THEN RAISE EXCEPTION 'Ownership must start at legacy epoch zero'; END IF;
 ELSE
   IF NEW.company_id<>OLD.company_id OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'Invalid ownership revision'; END IF;
   IF NEW.phase=OLD.phase THEN
     IF NEW.epoch<>OLD.epoch THEN RAISE EXCEPTION 'Invalid ownership epoch'; END IF;
   ELSE
     IF NEW.epoch<>OLD.epoch+1 OR NOT (
       (OLD.phase='legacy' AND NEW.phase='draining') OR (OLD.phase='sql' AND NEW.phase='reversing') OR
       (OLD.phase IN ('draining','reversing') AND NEW.phase IN ('legacy','sql'))
     ) THEN RAISE EXCEPTION 'Invalid ownership transition'; END IF;
   END IF;
 END IF;
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
CREATE FUNCTION defender_writer_ownership_audit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<>2 THEN RAISE EXCEPTION 'Ownership audit is append-only'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION defender_writer_ownership_audit_write() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO defender_writer_ownership_audit VALUES(NEW.company_id,NEW.revision,
   CASE WHEN TG_OP='UPDATE' THEN to_jsonb(OLD) ELSE NULL END,to_jsonb(NEW));
 RETURN NEW;
END $$;
CREATE TRIGGER ownership_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_writer_ownership FOR EACH ROW EXECUTE FUNCTION defender_writer_ownership_guard();
CREATE TRIGGER ownership_audit AFTER INSERT OR UPDATE ON defender_writer_ownership FOR EACH ROW EXECUTE FUNCTION defender_writer_ownership_audit_write();
CREATE TRIGGER ownership_audit_guard BEFORE INSERT OR UPDATE OR DELETE ON defender_writer_ownership_audit FOR EACH ROW EXECUTE FUNCTION defender_writer_ownership_audit_guard();
CREATE TRIGGER ownership_no_truncate BEFORE TRUNCATE ON defender_writer_ownership FOR EACH STATEMENT EXECUTE FUNCTION defender_shadow_no_truncate();
CREATE TRIGGER ownership_audit_no_truncate BEFORE TRUNCATE ON defender_writer_ownership_audit FOR EACH STATEMENT EXECUTE FUNCTION defender_shadow_no_truncate();
