-- EXPLICIT migration only. Do NOT install as part of app startup.
-- No external scan can be launched by this schema.
CREATE TABLE public.external_scan_dispatch_claims (
  claim_key text PRIMARY KEY CHECK (claim_key ~ '^[0-9a-f]{64}$'),
  company_id text NOT NULL CHECK (length(company_id) BETWEEN 1 AND 100),
  target text NOT NULL CHECK (length(target) BETWEEN 1 AND 253),
  nessus_scan_id bigint NOT NULL CHECK (nessus_scan_id > 0),
  nessus_occurrence_at timestamptz NOT NULL,
  UNIQUE (company_id, target, nessus_scan_id, nessus_occurrence_at),
  state text NOT NULL DEFAULT 'reserved'
    CHECK (state IN ('reserved','remote-created','running','done','failed','needs-reconciliation')),
  remote_task_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (remote_task_id IS NULL OR length(remote_task_id) BETWEEN 1 AND 128)
);
-- Exactly one global slot. Its claim survives restarts and operator sessions.
-- There is intentionally NO expiry or automatic takeover of uncertain work.
CREATE TABLE public.external_scan_dispatch_slot (
  slot_id smallint PRIMARY KEY CHECK (slot_id = 1),
  claim_key text UNIQUE REFERENCES public.external_scan_dispatch_claims(claim_key),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.external_scan_dispatch_slot (slot_id, claim_key)
VALUES (1, NULL)
ON CONFLICT (slot_id) DO NOTHING;
