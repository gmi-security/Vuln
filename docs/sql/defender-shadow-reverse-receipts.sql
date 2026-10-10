-- Offline recovery rehearsal only. Does not authorize reverse completion.
CREATE TABLE defender_reverse_exports (
 company_id text NOT NULL, attempt_id uuid NOT NULL,
 ownership_revision bigint NOT NULL, ownership_epoch bigint NOT NULL,
 projection_id uuid NOT NULL, workflow_revision bigint NOT NULL,
 digest_version smallint NOT NULL DEFAULT 2 CHECK(digest_version=2),
 artifact jsonb NOT NULL CHECK(octet_length(artifact::text)<=33554432),
 baseline_digest text NOT NULL, expected_digest text NOT NULL,
 source_identity jsonb NOT NULL, source_stamp jsonb NOT NULL,
 actor text NOT NULL, reason text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(company_id,attempt_id),
 FOREIGN KEY(company_id,projection_id) REFERENCES defender_shadow_generations(company_id,projection_id)
);
CREATE TABLE defender_reverse_receipts (
 company_id text NOT NULL, attempt_id uuid NOT NULL,
 restored_digest text NOT NULL, artifact_digest text NOT NULL,
 actor text NOT NULL, reason text NOT NULL,
 verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(company_id,attempt_id),
 FOREIGN KEY(company_id,attempt_id) REFERENCES defender_reverse_exports(company_id,attempt_id)
);
CREATE FUNCTION defender_reverse_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Reverse recovery evidence is append-only'; END $$;
CREATE TRIGGER reverse_exports_immutable BEFORE UPDATE OR DELETE ON defender_reverse_exports FOR EACH ROW EXECUTE FUNCTION defender_reverse_immutable();
CREATE TRIGGER reverse_receipts_immutable BEFORE UPDATE OR DELETE ON defender_reverse_receipts FOR EACH ROW EXECUTE FUNCTION defender_reverse_immutable();
CREATE TRIGGER reverse_exports_no_truncate BEFORE TRUNCATE ON defender_reverse_exports FOR EACH STATEMENT EXECUTE FUNCTION defender_shadow_no_truncate();
CREATE TRIGGER reverse_receipts_no_truncate BEFORE TRUNCATE ON defender_reverse_receipts FOR EACH STATEMENT EXECUTE FUNCTION defender_shadow_no_truncate();
