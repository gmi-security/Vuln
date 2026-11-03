-- Additive explicit migration. Run only with a backed-up, reviewed database.
-- Never installed automatically by the API or a scan worker.
CREATE TABLE public.external_scan_dispatch_events (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  claim_key text NOT NULL REFERENCES public.external_scan_dispatch_claims(claim_key),
  event_type text NOT NULL CHECK (event_type IN ('task-recorded','needs-reconciliation')),
  remote_task_id text,
  note text,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  CHECK (remote_task_id IS NULL OR length(remote_task_id) BETWEEN 1 AND 128),
  CHECK (note IS NULL OR length(note) BETWEEN 1 AND 500)
);
CREATE INDEX external_scan_dispatch_events_claim_time_idx
  ON public.external_scan_dispatch_events (claim_key, event_id DESC);
