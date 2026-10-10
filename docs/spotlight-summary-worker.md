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

## Model version 3: vendor evidence versus importer placeholders

Version 3 retains existing totals while classifying exact locally generated unresolved placeholders separately from vendor responses. The SQL builder checks stored ID/CVE/status and exact raw JSON equality; malformed lookalikes are not exempt. Every real vendor record still contributes tenant evidence, even if closed, suppressed or non-CVE. A placeholder-only generation cannot establish a tenant. Private scope metadata is version 2 and is never returned to the browser.

The worker discovers a new job for model v3 even if v1/v2 summaries exist. Build the isolated worker artifact with the reviewed candidate before an eventual enablement. Older summaries cannot satisfy the v3 reader; the reader never runs the expensive build on demand. Existing retention/version rules continue to protect current and active work. This update does not rewrite source rows or enable the worker.

The full retained recovery-copy build matched all 2,119,658 rows and all 11,710 CVE results against the independent original baseline. An independent read-only audit established 343 exact local placeholders, zero invalid CID rows outside those placeholders and no mixed recognized CID. The v3 guarded reader passed; build time was 83.99 seconds and saved reads 30.5-40.4 ms. Restart was idle with no duplicate job. These are private-copy source-summary measurements, not live whole-page latency.

## Job lifecycle

Discovery polls only allowlisted customers with a completed owned import and completion timestamp. It creates one job per customer/import/model version; repeating discovery does not add duplicates. A newer source pointer supersedes queued work for the old generation. A claimed job cannot silently build a different generation.

Jobs progress through `queued` → `running` → `succeeded`. A failed build or expired lease enters `retry`, with one minute before the second attempt and five minutes before the third. Three consumed attempts end in `failed`; ordinary polling does not reset failed jobs. A busy builder lock defers work for one minute without spending an attempt. There is no operator retry UI yet.

The running lease lasts 60 seconds and is renewed at checkpoints approximately every 15 seconds. Individual statements have a 15-second limit. The builder checks its five-minute total deadline between batches, so this is not a hard wall-clock cancellation timer. SIGTERM/SIGINT requests cooperative cancellation at a checkpoint; an already committed summary remains valid. A killed process leaves a running lease for the next process to recover after expiry and backoff.

Before publishing, the worker checks and locks its current lease inside the same transaction that writes the summary. A stale token cannot publish, acknowledge, or extend an expired lease. Failed publication rolls back all new summary rows and leaves the previous complete pointer intact. If the process dies after the summary commits but before acknowledging the job, discovery finds the completed summary and repairs the job status without rebuilding it.

Safe stored error codes are `build-failed`, `lease-expired`, and `worker-stopped`. The scoped status service returns the latest 50 jobs for one customer, without lease tokens. It is an internal service, not a new API or permission grant. General CLI errors use safe event codes instead of printing database connection strings or raw error stacks.

## Derived-summary retention

`lib/spotlight-summary-retention.ts` is an explicit maintenance service compiled alongside the worker. It is not called by the worker, a timer or a route. `run(companyId)` previews one bounded batch in a read-only transaction; `run(companyId, {apply: true})` reselects candidates under locks and applies that batch atomically. Preview IDs are never accepted as deletion instructions. The eventual caller must authorize the customer and record the returned candidate/deletion information.

Proposed configurable defaults for these new derived copies:

| Setting | Default / protection |
| --- | --- |
| Recent complete summaries | Keep up to 90 per customer. Generations beyond the 90 newest are eligible. Versions count toward the same customer limit. |
| Summary age | Older than 365 days is eligible even below that count. Age uses summary build time; original observation timestamps remain unchanged. |
| Permanent exceptions to those cutoffs | Protect the three newest summaries, the current published summary, any summary of the current source import, and summaries with queued/running/retry jobs, including expired running leases awaiting normal recovery. These protections can exceed the configured count or age targets. |
| Terminal job records | Retain up to 100 and expire after 90 days, except jobs for retained summaries or the current source import. Active jobs are never candidates. Current-import failures remain visible rather than being erased and automatically rediscovered. |
| Batch size | At most five generations and 100 terminal jobs per customer/call; each generation's CVE detail rows cascade with its header. A larger backlog needs further explicit calls. |

Summary and job selection occurs before deletion, so the job for a summary removed in this batch survives until at least a later pass. The service does not delete source imports, daily-history tables, saved-query results, tickets, connector state or enrichment. This policy does not promise 90 days of trend history: it keeps recent generated copies, and multiple imports on one day consume multiple positions. Existing trend history has separate retention and remains untouched.

Apply acquires the same global advisory lock as the builder, serializes job discovery/claims, and pins the selected customer's source pointer while selecting/deleting. A running build returns `busy` without cleanup. Current-summary foreign keys are an additional guard. The saved reader already uses repeatable-read transactions; PostgreSQL keeps the old rows visible to an in-flight reader even if a newer summary is published and the older one is pruned. This guarantee was tested for that reader; future consumers must preserve a consistent transaction rather than make unrelated reads across generations.

Statements have a 15-second timeout, lock waits a two-second timeout, and the service checks a 30-second batch deadline between deletions. A failed batch rolls back all its deletions. Physical disk use need not shrink immediately after deletion; database vacuum/space reuse and backup retention are separate operational work. At the measured Atlas summary size, 90 copies are approximately 298 MiB before bloat, backups and protected exceptions; this is a sizing illustration, not an enforced byte limit.

## Rollback and remaining gates

Stop the dedicated process before changing its code or migrations. Preserve job history and saved summaries during an ordinary code rollback; production source records and ticket state are independent. The migration files contain destructive removal instructions for an explicitly approved schema rollback, not normal deployment steps.

Before any recurring production use: approve the retention settings and wire cleanup/monitoring, confirm database access and resource allocation alongside current imports, define failed-job operator recovery, approve the customer/source bindings and migration, and wire authenticated read-only page consumers with pending/stale states. Cleanup has been exercised only in a disposable fixture database; there is no production activation. A code rollback cannot recreate previously pruned derived copies; raw-source availability or an appropriate backup is required to rebuild them. Current summaries and the protected rollback set are excluded from cleanup.

## Validation

Build first, then run `node --test tests/spotlight-summary-worker.test.mjs` for off-by-default/configuration tests. The PostgreSQL scripts require the private recovery cluster's Unix socket and refuse a general production target:

- `tests/spotlight-summary-worker-postgres.mjs`: disposable fixture database, retries/leases/fencing, actual killed-process recovery and singleton behavior.
- `tests/spotlight-summary-postgres.mjs`: atomic summaries, customer scope, concurrent reads and supersession regressions.
- `tests/spotlight-summary-worker-restored.mjs`: dedicated CLI against the retained Atlas generation, exact comparison against the earlier independent aggregate baseline, saved reads and restart replay. Installs/removes only the four new tables; refuses existing ones.
- `tests/spotlight-summary-retention-postgres.mjs`: disposable fixtures for scoped preview/apply, protected generations, builder contention, stale-preview revalidation, atomic rollback, count/age limits and an actual in-flight saved reader during pruning. `tests/spotlight-summary-retention.test.mjs` checks input bounds before any database connection.

The authoritative platform change proposal records measured results and remaining release gates. Restored-copy timing is not a production performance guarantee.
