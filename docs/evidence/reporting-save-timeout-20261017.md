# Bulk SQL publication timeout ? 17 October 2026

Production failed a 796,657-finding publication at the 900-second transaction deadline. The log identifies `phase=reporting`, 947,163 ms including preparation. This does not mean all 900 seconds were spent reporting: the former timer covered both SQL writes and reporting without separate durations. Database reachability and available host RAM were healthy during the subsequent inspection. Saving correctly remained blocked after the failed transaction; the last committed data stayed readable.

## Change

Bulk reporting now reuses the JSON-normalized, detached rows already written by the same transaction. PostgreSQL still supplies record membership and exact ordering. Unchanged records are fetched in bounded pages. Buckets with fewer than 500 prepared writes retain the existing reader. Deletes, customer reassignment, report hashes, authority fencing, transaction rollback and later queued mutations retain their previous semantics. No schema or hash-version change is required.

Committed and failed save logs now report write and reporting durations separately. Time limits and the protection against serving uncommitted data are unchanged.

## Verification

- Regression tests first failed because all bulk payloads were read again. They now pass for findings, assets and scans, including unchanged records, customer moves, deletions and equal-order IDs.
- 1,035 unit tests passed; seven optional database tests skipped; zero failed.
- 22 checks passed against an isolated PostgreSQL cluster. A 64,001-record scoped save exercised the new path: 3.6 seconds preparation, 7.6 seconds SQL writing, 1.8 seconds reporting, 12.9 seconds total. Full-generation hashes matched; rollback and restart persistence passed. These timings are synthetic, not production-import predictions.
- Read-only production-data replay rebuilt the selected customer's 847,104 reporting rows, with all 40 published customer fingerprints unchanged. Existing code took 102.8 seconds and returned 546.8 MB of row data. The revised replay, with 95% of rows supplied as frozen writes, took 38.3 seconds and returned 85.1 MB. Constructing that simulated frozen input took 55.7 seconds separately; real saves already own the prepared rows. Peak process RSS was about 1,006 MiB including this simulated input. This isolates reporting, not complete import performance.
- Production webpack build and summary-worker build passed. Default Turbopack staging build could not resolve the shared dependency symlink; webpack used the same source and dependencies successfully.
- Independent review found no blocking correctness or memory issues.

## Deployment verification still required

Confirm the retained completed Defender import is published without downloading it again; observe the full save duration and committed generation marker; verify read/write readiness, unchanged customer scoping and existing ticket visibility. The replay alone does not prove the failed import will finish under concurrent production load. Separate CrowdStrike upstream failures are outside this fix.
