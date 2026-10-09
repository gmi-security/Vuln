# Spotlight summary worker

Status: disabled local implementation on Vuln2.0. No production migration, process registration or reporting cutover is included.

## Purpose

Build a small saved summary from a customer's completed Spotlight import, once per customer/import/model version. Page readers can use that saved result instead of scanning millions of raw findings. The worker does not call CrowdStrike, import data, publish platform findings, create tickets, or change saved dashboard tiles.

The web app never starts this worker. Its dedicated CLI is `scripts/spotlight-summary-worker.mjs`; its library has no startup side effects. It uses the existing PostgreSQL source tables and four additive summary/job tables in the same database.

## Process and configuration

`npm run build:summary-worker` compiles the worker's isolated TypeScript dependency tree to `.worker-build/spotlight-summary`. `npm run worker:summary` starts the CLI with a 512 MiB JavaScript heap ceiling. This is not a total process or database memory limit. The regular Next build does not create the worker artifact; the artifact is ignored by Git and must be built for a separately approved deployment.

The CLI reads only its process environment; it does not load `.env.local`, the application singleton, or legacy schedulers.

| Variable | Behavior |
| --- | --- |
| `VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED` | Only the exact value `true` enables work. Absent or any other value exits successfully without loading pg or connecting. |
| `VULN_SPOTLIGHT_SUMMARY_CUSTOMERS` | Required when enabled. Comma-separated explicit application company IDs, 1–100 entries. Empty values and wildcards fail; there is no all-customers fallback. An allowlist is an operator instruction, not proof of approved upstream tenant authority. |
| `DATABASE_URL` | Required only when enabled. Passed to pg using its normal connection-string/TLS behavior. Keep credentials in the existing secure environment handoff, not commands, logs or this document. |

`npm run worker:summary -- --once` performs discovery and attempts at most one due job, then exits. It does not drain the queue or guarantee success: the structured tick state and durable job status must be checked. A handled build failure can exit normally after recording a retry; an infrastructure/startup error exits nonzero in once mode. Without `--once`, the process waits 60 seconds after each tick. Builds never overlap within the loop.

The pool has at most four connections and a distinct `vuln-spotlight-summary-worker` application name. One connection owns a singleton advisory lock; the builder uses separate source/read and publication connections, leaving capacity for lease updates. The build itself has an additional global advisory lock, so manual callers cannot overlap its memory-heavy scan. There is no PM2 configuration or permission change in this checkpoint.

## Explicit schema and readiness

An operator must separately review/apply `docs/sql/spotlight-source-summaries.sql`, followed by `docs/sql/spotlight-summary-jobs.sql`, before an enabled process can work. The code checks readiness and never initializes schema. These scripts are explicit one-time migrations, not idempotent startup scripts. Do not apply them to production as part of this checkpoint.

The existing source tables remain authoritative for the retained source generation:

- `spotlight_import_current`, `spotlight_import_runs`, `spotlight_import_records`: read only.
- `spotlight_summary_generations`, `spotlight_summary_cves`, `spotlight_summary_current`: completed derived results and their current pointer.
- `spotlight_summary_jobs`: durable execution status, attempts, progress, retry timing and lease ownership. No credentials or raw finding payloads are stored here.

## Job lifecycle

Discovery polls only allowlisted customers with a completed owned import and completion timestamp. It creates one job per customer/import/model version; repeating discovery does not add duplicates. A newer source pointer supersedes queued work for the old generation. A claimed job cannot silently build a different generation.

Jobs progress through `queued` → `running` → `succeeded`. A failed build or expired lease enters `retry`, with one minute before the second attempt and five minutes before the third. Three consumed attempts end in `failed`; ordinary polling does not reset failed jobs. A busy builder lock defers work for one minute without spending an attempt. There is no operator retry UI yet.

The running lease lasts 60 seconds and is renewed at checkpoints approximately every 15 seconds. Individual statements have a 15-second limit. The builder checks its five-minute total deadline between batches, so this is not a hard wall-clock cancellation timer. SIGTERM/SIGINT requests cooperative cancellation at a checkpoint; an already committed summary remains valid. A killed process leaves a running lease for the next process to recover after expiry and backoff.

Before publishing, the worker checks and locks its current lease inside the same transaction that writes the summary. A stale token cannot publish, acknowledge, or extend an expired lease. Failed publication rolls back all new summary rows and leaves the previous complete pointer intact. If the process dies after the summary commits but before acknowledging the job, discovery finds the completed summary and repairs the job status without rebuilding it.

Safe stored error codes are `build-failed`, `lease-expired`, and `worker-stopped`. The scoped status service returns the latest 50 jobs for one customer, without lease tokens. It is an internal service, not a new API or permission grant. General CLI errors use safe event codes instead of printing database connection strings or raw error stacks.

## Rollback and remaining gates

Stop the dedicated process before changing its code or migrations. Preserve job history and saved summaries during an ordinary code rollback; production source records and ticket state are independent. The migration files contain destructive removal instructions for an explicitly approved schema rollback, not normal deployment steps.

Before any recurring production use: choose retention and cleanup behavior, confirm database access and resource allocation alongside current imports, define failed-job operator recovery/monitoring, approve the customer/source bindings and migration, and wire authenticated read-only page consumers with pending/stale states. No retention deletion or production activation is implemented here.

## Validation

Build first, then run `node --test tests/spotlight-summary-worker.test.mjs` for off-by-default/configuration tests. The PostgreSQL scripts require the private recovery cluster's Unix socket and refuse a general production target:

- `tests/spotlight-summary-worker-postgres.mjs`: disposable fixture database, retries/leases/fencing, actual killed-process recovery and singleton behavior.
- `tests/spotlight-summary-postgres.mjs`: atomic summaries, customer scope, concurrent reads and supersession regressions.
- `tests/spotlight-summary-worker-restored.mjs`: dedicated CLI against the retained Atlas generation, exact comparison against the earlier independent aggregate baseline, saved reads and restart replay. Installs/removes only the four new tables; refuses existing ones.

The authoritative platform change proposal records measured results and remaining release gates. Restored-copy timing is not a production performance guarantee.
