# Storage recovery and release checks

## Failure and repair

The October 30 incident stopped a private finding publication at 195,000 rows.
PostgreSQL returned `25P03` (idle transaction timeout). Borrowed connections did
not retain their first asynchronous error, and private preparation did not
classify `25P03` as transient. The store consequently disabled subsequent saves.
The committed SQL generation remained readable.

The repair observes borrowed clients through release/close and retains the first
error. Private preparation retries the same detached plan on fresh connections
after 5, 15 and 60 seconds. Checkpoints, authority and advisory ownership are
rechecked. Exhaustion leaves work pending for the existing later retry path.
An uncertain final COMMIT, stale writer or invalid data still fails closed.

Publication batches are encoded before BEGIN, with a target of 500 rows and
4 MiB. One valid larger record is allowed as a singleton. The existing 16 MiB
payload limit, 90-second idle limit and 60-second statement limit remain.

## Before restarting a blocked writer

1. Record release/build, SQL epoch/revision, active generation, pending checkpoint,
   process roles, and RAM mutation version. Check for active imports and saves.
2. Preserve non-replayable RAM. Do not assume a source re-import preserves analyst
   edits or settings. Keep exports private, checksum them, and verify the mutation
   version did not change during export.
3. Back up and restore-test the affected SQL tables. Recovery touches `app_*` and
   `customer_reporting_*`; retain compatible schema/functions and the application
   artifact. A full backup can also preserve unrelated connector/history data.
4. Rehearse the repair against an isolated Unix-socket database. Never point the
   disposable test scripts at a production URL.
5. Recover the frozen pending data with exactly one writer and unchanged base
   authority. Do not clear the blocked flag merely because a database ping works.
   An inspector/SSH timeout is an unknown observation, not proof a save failed.
6. Independently compare committed payload hashes and metadata against the
   preserved capture; verify customer reporting digests and the new authority.
   Recheck RAM version immediately before restart. Counts alone are insufficient.
7. Deploy the reviewed compatible build, then confirm one writer, successful
   hydration, new durable save capability and committed reads. Preserve unrelated
   server edits. Roll back application artifacts only if compatible with current
   SQL; do not restore an old database merely to match an older binary.

For this incident a private, one-shot same-process recovery controller was
prepared under `/home/codex/vuln-recovery/storage-reliability-20261030/`. It imports
the repaired persistence code into the original blocked worker, preserves the
process-global store/index/pool, and uses synchronous capture guards plus SQL
authority fences. It keeps the old worker blocked until the repaired release
hydrates the verified commit. It is an incident tool, not an automatic startup
or recovery hook. Never rerun a failed/uncertain attempt without reconciliation.

The preserved worker had 1,340,277 findings versus 1,340,083 committed findings,
with mutation version 904592 and base epoch 2/revision 17989. Its export also
contains pending updates, metadata and settings. Recovery retains the last
durable derived KEV catalog and recomputes reporting against recovered records.

## Observability

- Authenticated health distinguishes healthy, publishing, retrying and blocked;
  unavailable worker/browser health reads must not imply active saving.
- Anonymous health exposes readiness/storage booleans only. A successful DB ping
  does not establish write readiness. Committed web reads can remain available
  while writes are unavailable.
- `publication-progress`, `publication-query-slow-or-failed` and
  `publication-attempt-finished` contain query/transaction durations, idle gaps,
  phase/offset and backend PID, without SQL parameters or payloads.
- `runtime-metrics` samples heap/RSS, GC and event-loop delay every 10 seconds and
  resets delay histograms. Supervisor lifecycle events have UTC timestamps;
  missing child heartbeats are observed outside the child loop.
- `persistence-stalled` means pending work has made no durable progress for five
  minutes. Quiet applications with no pending work do not trigger it.

These events are emitted to existing process logs. External alert ingestion and
routing must be verified separately; emitting an event is not proof an operator
will receive an alert. Do not restart a writer automatically from a heartbeat
warning or replay an uncertain mutation.

## Validation and remaining acceptance

Focused persistence, reader, health and supervisor regressions pass. PostgreSQL
18 fault tests cover real idle disconnects, private checkpoint recovery and lost
live-COMMIT acknowledgement. The built split application passes authenticated
mutation, committed-read and restart checks.

An isolated 1,340,083-row/856,751-change replay completed with concurrent pure
risk calculations and bounded scanner serialization. Recorded private attempts
had a maximum 5 ms idle gap and 894 ms transaction duration. This is a synthetic
workload, not proof of equivalence to every production import. Whole-run event
loop samples exceeded the proposed 2-second target during setup/full-data work;
the original production 90-second pause is not conclusively attributed.

Three full reader refresh cycles under an 8 GiB cap reached a measured 4.49 GiB
peak; quiescent heap stayed about 2.2 GiB and retired views were collectible after
request completion/abort. This does not cover every dashboard memo/response or
identify the earlier production OOM. No speculative memory patch or heap-limit
increase was made.

Keep the incident open until a 48-hour soak spans two daily import/publication
cycles with successful commits, bounded transaction gaps, stable memory and no
unexpected child exits. Production fault injection is excluded. A soak must be
recorded as running/pending until its actual observation window completes.
