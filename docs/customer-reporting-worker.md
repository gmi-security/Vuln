# Customer reporting refresh worker

## Status and scope

Checkpoint 53 connects the dedicated worker and saved report reader to customer-specific published input revisions and reviewed connector assignments. Everything remains disabled in production. Existing application writers remain authoritative. These reports and jobs are replaceable derived data.

The default verification mode still requires private recovery databases. Explicit `published` mode requires the additive migrations and uses the existing application database for source records, derived reports and jobs, with separate connections/transactions. No schema is initialized by the worker or page reader.

Remediation Overview requests `reporting?companyId=...&view=sections`. Opted-in customers read only the small saved report, current revision metadata and source-review evidence; this path does not hydrate the RAM store, poll scanners, enqueue refreshes or run a vendor query. A saved capture timestamp is visible. Stale, missing or unreviewed reports return a readable 503 instead of silently running the expensive fallback. Other customers and the original full reporting route retain existing behavior. The SQL-enabled customer picker uses saved company metadata without hydration. Existing authorization, the one customer selector and shared CVE patch panel are preserved.

## Refresh lifecycle

1. The dedicated process validates its explicit customer list and the selected storage contract. A PostgreSQL session lock excludes a second CLI worker.
2. It inspects only committed snapshot/history metadata. It does not poll CrowdStrike, Defender or scanners, hydrate the app, create tickets or request scans.
3. Changed input creates or updates one job per customer. Multiple changes are combined into the latest requested revision. Waiting jobs retain their place in the queue.
4. One job is claimed with a random lease token, claimed revision and a 120-second deadline. Builds renew ownership at checkpoints at least every 15 seconds when work is progressing.
5. The builder requires the expected source fingerprint. If the source changed before the build or a newer job revision arrives during it, old work cannot acknowledge the newer request.
6. Immediately before publication, the worker checks current ownership and acknowledges success in the same transaction as the saved report. Failure or interruption rolls back that replacement.
7. The loop waits 60 seconds after each tick. A tick builds at most one report; there are no overlapping timer callbacks. Expired jobs are recovered after a crash.

This polls committed database changes; only small input revisions are added to the existing save transaction. The expensive report build is separate. Published mode uses customer-specific report-input generations and source-review pins. Only the private comparison mode retains the conservative shared-bucket fingerprint. Job revisions are scheduling evidence; input generations track the current persisted report content, including workflow fields. Neither replaces the planned authoritative writer epoch or independently attests historical source ownership.

A successful unchanged report is queued again when it has five minutes or less before expiry. Building a recent cache does not mean the vendor data is recent: the original source observations remain in the report. Discovery failure never creates a clean or zero report.

## Failure and recovery

| Event | Result |
| --- | --- |
| Build fails | Previous complete report remains; the job retries after a bounded delay |
| Three attempts fail | Job remains failed for the same input; a restart does not reset this limit |
| Input changes | Requested revision advances and the retry budget resets for that new input |
| Worker is killed | Its uncommitted report rolls back; the expired claim can be recovered |
| Old worker returns late | Token, revision and lease checks prevent it from publishing or acknowledging a replacement claim |
| SIGTERM / SIGINT | Current build is cancelled at a checkpoint, ownership is released and the process exits |
| Source unavailable | Other explicitly configured customers can proceed; unavailable discovery is counted |
| One-shot failure | `--once` exits nonzero for unavailable discovery or unsuccessful claimed work |
| Saved report becomes stale | Reader returns a stale state; page reads never queue or perform a large rebuild |

Error codes stored in jobs are fixed values, not raw vendor, SQL or credential-bearing error messages. CLI output contains job state, customer identifier, aggregate counts/timing and peak memory, never database URLs or keys. Normal disabled startup does not load database configuration, pg, or the compiled accumulator.

## Files and configuration

| Item | Purpose |
| --- | --- |
| `docs/sql/customer-reporting-sections.sql` | Explicit derived-report migration |
| `docs/sql/customer-reporting-jobs.sql` | Explicit job/lease migration, applied after the report migration |
| `lib/db/customer-reporting-worker.mjs` | Discovery, claim, heartbeat, retry and atomic completion |
| `scripts/customer-reporting-worker.mjs` | Dedicated CLI lifecycle and single-process lock |
| `tsconfig.reporting-worker.json` | Compiles only the pure report accumulator and its dependencies |
| `VULN_REPORTING_WORKER_ENABLED` | Exact `true` enables the process; default is disabled |
| `VULN_REPORTING_WORKER_CUSTOMERS` | Explicit comma-separated customer IDs, at most 50; no wildcard or duplicate entries |
| `VULN_REPORTING_SOURCE_URL` | Explicit source connection; in published mode must equal `DATABASE_URL` |
| `VULN_REPORTING_DATABASE_URL` | Explicit derived-report/job connection; in published mode must equal `DATABASE_URL` |
| `VULN_REPORTING_STORAGE` | Omit for private verification; exact `published` for the explicit application-database contract |
| `VULN_REPORTING_INPUT_REVISIONS` | Exact `true` enables atomic revision writes in the app; required by published worker and SQL reads |
| `VULN_REPORTING_SQL_READS` | Exact `true` allows customer-scoped SQL Overview routing; default off |
| `VULN_REPORTING_SQL_CUSTOMERS` | Explicit comma-separated customer IDs, at most 50; no wildcard or duplicate entries |
| `docs/sql/customer-reporting-inputs.sql` | Explicit customer revision/publication marker migration |

The worker does not load `.env.local`. Its operator supplies environment variables to the separate process. No new member/admin controls or connector credentials have been added to the UI.

Build locally:

```powershell
npm.cmd run build:reporting-worker
```

In a prepared verification environment, with the explicit migrations and variables already configured:

```bash
npm run worker:reporting -- --once
npm run worker:reporting
```

To retry a failed job after fixing its cause, stop the active worker, inspect the current `requested_revision` in `customer_reporting_jobs`, and use the exact customer/revision:

```bash
node scripts/customer-reporting-worker.mjs --retry-failed CUSTOMER_ID REVISION
```

Only a configured customer in the failed state with that exact revision can be requeued. A changed revision is rejected. This is an operator command, not permission to reset job tables or source data. The published mode retains the same expected-revision and customer checks.

## Verification and remaining work

Real PostgreSQL tests include actual compiled CLI execution, overlapping processes, forced SIGKILL during an uncommitted report write, expiry/recovery, graceful termination, bounded retries and versioned manual retry. Killing the process is confined to the synthetic worker process in its disposable target; no PM2 process is touched.

The actual 512 MiB-heap worker also processed both retained customers, renewing its leases during the full builds. Final timings/memory and counts are in checkpoint 52 of the platform proposal. This measures the dedicated worker without the independent reference arrays used in checkpoint 51.

## Planned enable order for the combined release

These are preparation steps, not a claim that production is ready or a request to run them now.

1. Finish customer connector/source reviews and confirm the retained platform records belong to their assigned customer and sources. The worker requires current stored review; page reads additionally verify current connection metadata. Providers absent from the reviewed data roles fail the whole build. A role check cannot reconstruct missing historical tenant/target evidence.
2. Install the explicit drafts/bindings/source-selection migrations if absent, followed by `customer-reporting-inputs.sql`, `customer-reporting-sections.sql` and `customer-reporting-jobs.sql`. Use the application database; no second customer database is required.
3. Build/type-check before restarting anything. Enable revision writes on the single application writer and confirm a complete snapshot save succeeds. Existing populated storage must be hydrated before first publication so the writer has an observed manifest. Do not enable two competing RAM writers.
4. Compile the separate worker and provide its environment, including `VULN_REPORTING_STORAGE=published`, revision flag, application database URLs and explicit customer allowlist. The worker does not load `.env.local`. Use its own process, not the web request process.
5. Run it once per initial customer job; check job success, complete model parity and a current saved report. Worker customers must include all SQL-read customers. It builds one customer per tick, then waits 60 seconds; measure the chosen customer set against the 15-minute cache expiry before enabling a broad list.
6. Enable the SQL read flag and matching customer allowlist as part of the reviewed combined rollout. Verify the saved timestamp, scope, refresh failure behavior and CVE patch flow. Other core pages and the full executive report still use their established reads.

The publication marker detects older/untracked writes. The revision-aware writer takes a table write lock while committing and compares the current manifest with the one it loaded or last saved. On a mismatch, it fails instead of silently acknowledging stale RAM. Investigate competing writers and outstanding unsaved changes before restarting/reloading; this mechanism is not an automatic recovery handoff.

## Rollback

Disable `VULN_REPORTING_SQL_READS` first to restore the prior Overview read path. Stop the dedicated report worker. Revision writes may remain enabled while investigating, or be disabled after SQL reads and the worker are off. Keep all four small report/job/revision tables during rollback. No findings, history, connector configuration, tiles or tickets are deleted, and no resync/database restore is required for the read rollback.

The final normalized authoritative writer migration, reverse recovery, executive report/risk/SLA parity and live source acceptance remain unfinished. This local checkpoint does not claim a full platform cutover.
