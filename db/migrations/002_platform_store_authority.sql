-- Additive, explicitly installed in the maintenance procedure. Existing source
-- generations, tickets, history and snapshot rows are retained unchanged.
CREATE TABLE app_store_authority (
 id integer PRIMARY KEY CHECK(id=1),
 mode text NOT NULL CHECK(mode IN ('legacy','sql')) DEFAULT 'legacy',
 enforced boolean NOT NULL DEFAULT false,
 epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(mode='legacy' OR enforced)
);
INSERT INTO app_store_authority(id) VALUES(1);
CREATE TABLE app_store_metadata (
 id integer PRIMARY KEY CHECK(id=1),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 record_hash text NOT NULL CHECK(record_hash ~ '^[a-f0-9]{64}$')
);
CREATE TABLE app_store_commits (
 id uuid PRIMARY KEY,
 epoch bigint NOT NULL,
 revision bigint NOT NULL,
 operation text NOT NULL CHECK(operation IN ('backfill','save','reverse')),
 actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 160),
 counts jsonb NOT NULL CHECK(jsonb_typeof(counts)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(epoch,revision)
);

ALTER TABLE app_findings ALTER COLUMN real_risk TYPE double precision;
DO $$
DECLARE relation text;
BEGIN
 FOREACH relation IN ARRAY ARRAY['app_companies','app_folders','app_scans','app_findings','app_assets'] LOOP
  EXECUTE format('ALTER TABLE %I ADD COLUMN store_order double precision NOT NULL DEFAULT 0, ADD COLUMN store_bucket integer NOT NULL DEFAULT 0, ADD COLUMN record_hash text',relation);
  EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK (store_order>=0 AND store_order<9007199254740991 AND store_bucket>=0 AND store_bucket<64 AND (record_hash IS NULL OR record_hash ~ ''^[a-f0-9]{64}$''))',relation,relation||'_store_shape');
  EXECUTE format('CREATE INDEX %I ON %I(store_bucket,store_order,id)',relation||'_store_order_idx',relation);
 END LOOP;
END $$;
CREATE INDEX app_findings_customer_stream_idx ON app_findings(company_id,store_bucket,store_order,id);
CREATE INDEX app_assets_customer_stream_idx ON app_assets(company_id,store_bucket,store_order,id);
CREATE INDEX app_scans_customer_stream_idx ON app_scans(company_id,store_bucket,store_order,id);

-- A stale process, including an older release that does not know this protocol,
-- cannot overwrite the selected authority after cutover. Database owners remain
-- trusted operators; this is a consistency fence, not an authorization system.
CREATE FUNCTION app_store_write_fence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner app_store_authority%ROWTYPE;
BEGIN
 SELECT * INTO STRICT owner FROM app_store_authority WHERE id=1 FOR SHARE;
 IF owner.enforced AND (
   current_setting('vuln2.store_epoch',true) IS DISTINCT FROM owner.epoch::text OR
   current_setting('vuln2.store_revision',true) IS DISTINCT FROM owner.revision::text
 ) THEN RAISE EXCEPTION 'Platform writer is stale or not registered for this authority' USING ERRCODE='40001'; END IF;
 IF TG_TABLE_NAME='vuln_store' AND owner.mode<>'legacy'
   AND current_setting('vuln2.store_operation',true) IS DISTINCT FROM 'reverse'
 THEN RAISE EXCEPTION 'Snapshot writes are disabled while SQL is authoritative' USING ERRCODE='55000'; END IF;
 IF TG_TABLE_NAME<>'vuln_store' AND owner.mode<>'sql'
   AND current_setting('vuln2.store_operation',true) IS DISTINCT FROM 'backfill'
 THEN RAISE EXCEPTION 'SQL store has not been selected as authoritative' USING ERRCODE='55000'; END IF;
 RETURN NULL;
END $$;
DO $$
DECLARE relation text;
BEGIN
 FOREACH relation IN ARRAY ARRAY['app_companies','app_folders','app_scans','app_findings','app_assets','app_store_metadata'] LOOP
  EXECUTE format('CREATE TRIGGER app_store_write_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION app_store_write_fence()',relation);
 END LOOP;
 IF to_regclass('public.vuln_store') IS NULL THEN
  RAISE EXCEPTION 'A retained legacy snapshot must exist before installing authority fences';
 END IF;
 CREATE TRIGGER app_store_write_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.vuln_store FOR EACH STATEMENT EXECUTE FUNCTION app_store_write_fence();
END $$;
