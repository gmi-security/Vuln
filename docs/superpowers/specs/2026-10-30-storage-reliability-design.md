# Vuln storage reliability: proposed repair design

Status: investigation and proposed design only; no implementation or production restart authorized by this document. Requested outcome: determine the recurring failure's cause and prepare a plan to prevent it from disabling saving again.

## Evidence and remaining uncertainty

Production was inspected at checkout `ca61c6e8fe8e11bde70a62b7df75ac7f9d1387ae` on October 30, 2026. Relevant source copies, the initial report and raw checks are under `output/storage-diagnostic-20261030/`.

Confirmed chain:

1. A private publication of 856,751 finding changes stopped at its 195,000-row checkpoint. PostgreSQL reported `25P03`, an idle-in-transaction timeout, before any active-generation swap.
2. `lib/db/platform-publication.mjs` sets a 90-second idle-transaction timeout. This means a gap between statements, not a SQL query executing for 90 seconds. The latest stack maps to the writing batch.
3. `lib/persist.ts` does not classify `25P03` as a retryable private-preparation failure. `lib/store.ts` consequently sets its persistent blocked flag. Restored connectivity cannot clear that flag.
4. The borrowed clients in publication preparation have no application error listener. Installed `pg-pool` removes its idle-client listener when lending a client. An asynchronous connection error can therefore reach the process's uncaught-exception handling rather than the publication's controlled failure path.
5. A separate read-only diagnostic connection with a 250 ms session-local timeout reproduced `25P03`, then `Connection terminated unexpectedly`. Reusing it failed; a fresh connection succeeded. No application tables or global settings were modified. See `timeout-reproduction.txt`.
6. The active generation still contains 1,340,083 findings. Its pending replacement contains 195,000 rows and references the same active epoch/revision/base. Last platform commit: October 29, 23:52:11 Phoenix time.
7. The web child separately exhausted its 8 GiB heap and restarted. Its immutable reader retains the old complete view while constructing replacements, so overlapping generations and retained request/cache references must be measured. That architecture is a memory-risk mechanism; the exact OOM retaining path has not been proven.

The initiating 90-second gap cannot be attributed to a particular function from the available historical logs. Risk scoring was active concurrently, but that is correlation, not proof. Host samples show spare resources; they do not exclude a single-process event-loop pause or transport stall. The October 15 CPU profile predates the October 28 publication change and must not be treated as this incident's profile. No production load replay or heap snapshot was taken.

Primary references: [PostgreSQL timeout semantics](https://www.postgresql.org/docs/18/runtime-config-client.html), [node-postgres client error events](https://node-postgres.com/apis/client). Local installed code and the live reproduction support the client-lifecycle finding independently of documentation.

## Recommended approach and alternatives

Recommended: repair recovery within the existing single-writer, private-generation design; instrument and bound transaction work; then fix the demonstrated web memory path in a separate change. Keep current data contracts and atomic visibility. This is the assistant's proposed approach, not an implementation approval.

Raising the timeout or routinely restarting is not a sufficient repair: it leaves failed-connection handling, permanent blocking and memory crashes intact. Moving all writers or replacing the storage architecture immediately is broader than the evidence justifies. A targeted move of one CPU-heavy job, or a paged SQL reader, becomes justified only if profiling shows that smaller changes cannot satisfy the acceptance tests.

## Recovery contract

- Treat a known idle-transaction disconnect during private preparation as recoverable. Preserve the first meaningful connection error; a later generic error must not overwrite `25P03`.
- Observe borrowed-client errors throughout ownership, including gaps between queries and cleanup, for both private preparation clients and the separate final active-transaction client in `saveSnapshot`. Destroy failed connections; never return them as healthy or emit uncaught errors. An asynchronous final-client error must enter the controlled failure path even when no query promise is pending; error containment does not grant permission to retry an uncertain COMMIT.
- Retry the same immutable prepared plan on a fresh client after 5, 15 and 60 seconds, at most three automatic retries in that invocation. Before resuming, reacquire the advisory lock and validate authority, active base, plan hash and checkpoint. Do not hold a SQL transaction while backing off. After exhaustion, expose deferred recovery and use the existing later retry opportunity; never spin continuously.
- Reuse the frozen plan through these retries. Later RAM mutations remain dirty for a subsequent save. If a later invocation creates a different plan, existing checkpoint reconciliation may discard obsolete private work; do not promise that every restart preserves progress.
- A stale authority, corrupted checkpoint, bad input or uncertain active COMMIT remains blocked. Never replay an uncertain live commit as if it were a private batch failure. Keep platform writes serialized.
- No mutation may receive a successful durable-save acknowledgment before COMMIT succeeds. Read pages continue serving the last verified committed generation.

## Preventing long gaps

Add bounded, structured diagnostics before deciding which concurrent job to change. Record UTC timestamp, PID/role, publication ID, phase, batch offset, rows/bytes, SQL operation name (no SQL parameters), backend PID, query duration, gap since last query, transaction duration, first SQLSTATE, event-loop maximum delay and heap/RSS. Sample process metrics every 10 seconds; log batch aggregates at most every 30 seconds plus slow operations/failures. Reset histogram windows. Never log payloads, keys, URLs or tokens.

Keep all payload encoding outside BEGIN. Limit prepared write batches to 500 rows and a 4 MiB encoded parameter target; an individual valid large record may be a singleton up to the existing 16 MiB payload limit plus its small indexed fields. Validate identity/column shape before BEGIN. Checkpoint advancement and row insertion must remain in the same transaction. Do not put network calls, sleeps, full-store hashing or reporting preparation in that transaction.

Under isolated representative load, identify which job or serialization path creates the maximum gap. Add time-sliced yields or move only that proven CPU-heavy task to an existing auxiliary-worker pattern if yields cannot meet the budget. Preserve snapshot/version guards while yielding. Do not indiscriminately disable scanners or other scheduled jobs.

## Memory workstream

Investigate independently with production-scale synthetic or sanitized fixtures. Measure baseline, overlapping old/new generations, completed/aborted requests, reporting and repeated refreshes. Check the committed cache, request AsyncLocalStorage, memoized results and borrowed database clients for references to obsolete views.

Fix demonstrated retention/duplication without removing snapshot consistency or checksum validation. Prefer sharing unchanged immutable records and releasing finished-request references when that solves the measured issue. If a legitimate old+new view still exceeds the existing 8 GiB heap budget, the follow-on design must move the offending reads to bounded SQL projections/pagination rather than repeatedly increasing heap size. That larger redesign is a separate decision after evidence, not an unreviewed part of this patch.

## Health and operational behavior

Expose authenticated persistence state: healthy, publishing, retrying or blocked; last committed revision/time; phase; first error code/time; retry deadline and pending age. Anonymous health retains only readiness/storage booleans. The UI must distinguish automatic retry from a permanent block and must not imply unsaved edits are durable. Refresh the health state periodically instead of only on mount. Child crashes and stuck commits must be visible even if the PM2 launcher remains online. Alert through an existing configured monitoring path; do not introduce new recipients or send messages during this work.

## Acceptance and rollout constraints

- All fault-injection writes occur in a disposable PostgreSQL instance, never the live database.
- Reproduce an idle disconnect during a private batch and between queries; the failed batch rolls back, old data remains visible, fresh-client retry reaches one verified active publication, and no uncaught exception occurs.
- Exercise stale authority, failed checkpoint, reporting interruption and unknown live-COMMIT outcome; none may silently retry into an unsafe write.
- Replay at least 1.34 million active findings with at least 856,751 changed records plus concurrent representative jobs. No unintended write block, duplicate writer, corruption, missing acknowledgment, or unbounded retry.
- Proposed staging targets: maximum observed event-loop delay below 2 seconds, maximum client-side inter-statement idle gap below 10 seconds, ordinary batch p99 below 10 seconds, and web peak heap below 6 GiB under an 8 GiB cap. These are engineering acceptance targets, not measured current performance. If a target fails, investigate rather than relax it silently.
- Run two complete daily import/publication cycles in a 48-hour soak, with browser reads and injected connection interruptions; counts and revision checks must agree and obsolete views must not accumulate.
- Work from a fresh branch based on the current production-compatible source; the local working copy is older and has unrelated edits. Use PR review, build and isolated tests before rollout. No direct push to main.
- Before stopping the writer, confirm a recoverable database restore point and the durability/replayability of pending inputs, including non-import edits held only in memory. Preserve any non-replayable pending edits. Build before stopping the current service; keep one writer and a compatible prior release available for rollback. Never roll back the database just to match an application binary.

## Delivery boundary

The first implementation PR should repair connection handling/retry and add the diagnostics needed to finish causal attribution. Transaction-work changes follow the isolated trace. The memory fix is a separate PR. Do not label the recurrence problem solved on a unit test, a successful ping, or a one-time restart; require the load, failure and soak evidence above.

Builder review completed. Its substantive gap—error containment on the separate final-commit client—has been incorporated into the recovery contract and Task 1 of the plan. This review does not establish the still-unknown initiating workload or authorize implementation.
