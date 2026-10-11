# Customer reporting refresh worker

## Status and scope

Checkpoint 52 adds a disabled dedicated worker for the [saved report sections](customer-reporting-sections.md). It discovers committed snapshot changes, coalesces them into customer jobs, rebuilds bounded reports and commits the report with its successful job acknowledgement. Source data is read-only. Worker jobs and reports are replaceable derived data.

The worker still refuses storage outside the private recovery environment. It has not been deployed or connected to production processes. Runtime SQL reporting still requires approved customer/source and publication/workflow revisions. Existing application writers remain authoritative.

The Remediation Overview now requests `reporting?companyId=...&view=sections`, which skips the unused executive report and separate insights calculation. This response still reads the existing platform store. The original `/reporting` page and unqualified reporting API retain their full contract. Both routes use the existing authentication and customer-scope checks. A mismatched response is rejected, and late responses cannot replace another customer's report. Existing CVE links open the same patch panel.

## Refresh lifecycle

1. The dedicated process validates its explicit customer list and private databases. A PostgreSQL session lock excludes a second CLI worker.
2. It inspects only committed snapshot/history metadata. It does not poll CrowdStrike, Defender or scanners, hydrate the app, create tickets or request scans.
3. Changed input creates or updates one job per customer. Multiple changes are combined into the latest requested revision. Waiting jobs retain their place in the queue.
4. One job is claimed with a random lease token, claimed revision and a 120-second deadline. Builds renew ownership at checkpoints at least every 15 seconds when work is progressing.
5. The builder requires the expected source fingerprint. If the source changed before the build or a newer job revision arrives during it, old work cannot acknowledge the newer request.
6. Immediately before publication, the worker checks current ownership and acknowledges success in the same transaction as the saved report. Failure or interruption rolls back that replacement.
7. The loop waits 60 seconds after each tick. A tick builds at most one report; there are no overlapping timer callbacks. Expired jobs are recovered after a crash.

This is polling of committed database changes, not an application save hook. It avoids coupling a report rebuild to an import's save transaction. It still uses the conservative checkpoint-51 fingerprint: unrelated changes in shared buckets can invalidate a report. Replace this with accepted customer publication/workflow revisions before live read activation. The job revision is scheduling evidence, not proof of source ownership or a replacement for the authoritative finding revision.

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
| `VULN_REPORTING_SOURCE_URL` | Explicit private read-source connection |
| `VULN_REPORTING_DATABASE_URL` | Explicit private derived-report/job connection |

The worker does not load `.env.local`. Its operator supplies environment variables to the separate process. No new member/admin controls or connector credentials have been added to the UI.

Build locally:

```powershell
npm.cmd run build:reporting-worker
```

In a prepared private verification environment, with the explicit migrations and variables already configured:

```bash
npm run worker:reporting -- --once
npm run worker:reporting
```

To retry a failed job after fixing its cause, stop the active worker, inspect the current `requested_revision` in `customer_reporting_jobs`, and use the exact customer/revision:

```bash
node scripts/customer-reporting-worker.mjs --retry-failed CUSTOMER_ID REVISION
```

Only a configured customer in the failed state with that exact revision can be requeued. A changed revision is rejected. This is a private operator command, not permission to reset production job tables or source data.

## Verification and remaining work

Real PostgreSQL tests include actual compiled CLI execution, overlapping processes, forced SIGKILL during an uncommitted report write, expiry/recovery, graceful termination, bounded retries and versioned manual retry. Killing the process is confined to the synthetic worker process in its disposable target; no PM2 process is touched.

The actual 512 MiB-heap worker also processed both retained customers, renewing its leases during the full builds. Final timings/memory and counts are in checkpoint 52 of the platform proposal. This measures the dedicated worker without the independent reference arrays used in checkpoint 51.

Before rollout: bind the worker/reader to reviewed customer sources and accepted publication/workflow revisions, replace coarse invalidation, connect the reversible SQL Overview read, and complete executive-report and authoritative writer/recovery acceptance. Live connector checks and the combined release rehearsal remain required. The private database guards must not simply be removed to enable production.

Rollback at this stage means leaving the worker disabled and using the unchanged platform report data. Keep derived tables during an eventual code rollback; they contain no authoritative findings or ticket state. No source deletion, resync or database restore is needed for this local checkpoint.
