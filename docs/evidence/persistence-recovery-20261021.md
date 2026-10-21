# SQL publication timeout recovery — October 21, 2026

## Confirmed failure

Production was on `2d580d567f91e6c73abe3fbb8a3fa554a936bc33`. The database remained reachable, but platform writes were blocked. The last committed platform save was October 18 at 04:32 UTC (October 17 at 21:32 Arizona time).

The operator supplied the original failure:

```text
SQL save stopped: phase=write scope=delta elapsedMs=945864 writeMs=900001 reportingMs=0 code=none.
snapshot save failed: Error: SQL platform save timed out after 900000ms
```

This failure exhausted the 15-minute database-write budget before reporting began. It is different from the earlier reporting-phase timeout. Risk scoring was also active in the surrounding logs; those logs do not establish how much of the slowdown it caused. The completed Defender source import remained stored, while its platform generation marker still referred to the preceding import. Subsequent worker ticks could not recover because the strict store blocks after a failed save.

## Change

- Publications with at least 100,000 finding candidates/changes receive 30 minutes per attempt; ordinary saves retain five minutes. Per-statement and lock limits remain unchanged.
- Retry once after 30 seconds for a publication deadline, PostgreSQL statement cancellation, lock timeout, deadlock or serialization failure before COMMIT.
- Destroy the failed connection. Reuse the detached, frozen preparation on a fresh transaction; acquiring and verifying the original authority lock ensures an abandoned transaction cannot overlap writes and another committed writer cannot be overwritten.
- Keep cancellation state separate for each attempt. Later RAM changes remain dirty for the next save. Adopt hashes, authority and reporting state only after an acknowledged COMMIT.
- Do not retry uncertain COMMIT responses, transport failures, stale authority, validation errors or a second failure. These still fail closed.

No schema, customer assignment, permissions, scheduler, provider-download or ticket behavior changes.

## Validation before deployment

- New retry regression cases failed against the previous implementation and passed after the fix.
- 1,045 unit tests passed; seven optional database tests skipped; zero failures.
- 25 checks passed on an isolated PostgreSQL 18 cluster, including a 64,001-row publication and independent reporting-hash comparison.
- Real in-flight timeout: close the connection after an INSERT while a query is running; retry commits the frozen value exactly once; a later edit survives its following save.
- Real PostgreSQL statement timeout after an INSERT: rollback and automatic retry succeed without restarting the application.
- Actual COMMIT with a simulated lost acknowledgement: no retry or success acknowledgement; the stale writer is fenced; committed rows remain intact.
- Customer moves/deletions, publication-marker atomicity, rollback, restart, and unrelated-customer reporting remain covered.
- Production webpack and summary-worker builds passed. Independent review found no blocking issues.

## Operational limits

The large publication still writes many records. The increased budget and bounded retry address the observed timeout and recoverable failures; they do not make database throughput unlimited. A repeated or unsafe failure still intentionally blocks saving. Live recovery of the pending production publication must be verified after deployment; a successful daytime recovery does not prove every future overnight workload.
