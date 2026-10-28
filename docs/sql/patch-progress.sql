-- Derived verification only. No changes to findings, source imports or tickets.
CREATE TABLE patch_progress_tickets (
 kind text NOT NULL CHECK(kind IN ('single','group')), request_id uuid NOT NULL,
 company_id text NOT NULL, ticket_id integer NOT NULL, scope_hash text NOT NULL,
 metadata jsonb NOT NULL, latest_evaluation uuid, last_attempt_at timestamptz,
 check_state text NOT NULL DEFAULT 'pending' CHECK(check_state IN ('pending','ready','failed','baseline-unavailable')),
 error text, PRIMARY KEY(kind,request_id)
);
CREATE INDEX patch_progress_customer ON patch_progress_tickets(company_id,ticket_id DESC,kind,request_id);
CREATE TABLE patch_progress_evaluations (
 id uuid PRIMARY KEY, kind text NOT NULL, request_id uuid NOT NULL, company_id text NOT NULL, scope_hash text NOT NULL,
 fingerprint text NOT NULL, summary jsonb NOT NULL, new_devices jsonb NOT NULL, source_times jsonb NOT NULL,
 expected_rows integer NOT NULL CHECK(expected_rows>=0 AND expected_rows<=100000),
 created_at timestamptz NOT NULL DEFAULT now(), source_captured_at timestamptz NOT NULL, completed_at timestamptz,
 UNIQUE(kind,request_id,company_id,scope_hash,fingerprint),
 FOREIGN KEY(kind,request_id) REFERENCES patch_progress_tickets ON DELETE CASCADE
);
CREATE TABLE patch_progress_observations (
 evaluation_id uuid NOT NULL REFERENCES patch_progress_evaluations ON DELETE CASCADE,
 ordinal integer NOT NULL, pair_key text NOT NULL, state text NOT NULL CHECK(state IN ('detected','clear','unknown')),
 observation jsonb NOT NULL, PRIMARY KEY(evaluation_id,ordinal), UNIQUE(evaluation_id,pair_key)
);
CREATE TABLE patch_progress_transitions (
 kind text NOT NULL, request_id uuid NOT NULL, scope_hash text NOT NULL, pair_key text NOT NULL,
 evaluation_id uuid NOT NULL REFERENCES patch_progress_evaluations ON DELETE CASCADE,
 state text NOT NULL, observed_at timestamptz, recorded_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(evaluation_id,pair_key)
);
CREATE INDEX patch_progress_prior_clear ON patch_progress_transitions(kind,request_id,scope_hash) WHERE state='clear';
CREATE TABLE patch_progress_trends (
 company_id text NOT NULL, source text NOT NULL, generation text NOT NULL,
 observed_at timestamptz NOT NULL, count bigint NOT NULL CHECK(count>=0), unit text NOT NULL,
 PRIMARY KEY(company_id,source,generation)
);
CREATE INDEX patch_progress_trends_customer ON patch_progress_trends(company_id,observed_at DESC);
CREATE TABLE patch_progress_worker (
 id integer PRIMARY KEY CHECK(id=1), lease_until timestamptz, lease_owner uuid,
 ticket_cursor text NOT NULL DEFAULT '', company_cursor text NOT NULL DEFAULT ''
);
INSERT INTO patch_progress_worker(id) VALUES(1);
