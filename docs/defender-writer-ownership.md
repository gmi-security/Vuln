# Defender writer ownership: isolated protocol

Implemented October 10, 2026 on Vuln2.0. This is an offline protocol in disposable recovery SQL. It is not installed in production and does not activate the new data model. The existing refresh-publication block remains mandatory.

## State and transitions

| State | Admitted participating writer | Allowed next step |
| --- | --- | --- |
| `legacy` | Registered legacy process at the current epoch | Begin forward handoff to `draining` |
| `draining` | None | Finish to `sql` after all registered processes acknowledge; or abort to `legacy` |
| `sql` | Registered SQL process at the current epoch | Begin reverse handoff to `reversing` |
| `reversing` | None | Finish to `legacy` after drain and reverse-export evidence; or abort to `sql` |

`defender_writer_ownership` stores one customer row containing its phase, revision, epoch, registered processes, current attempt and acknowledgement evidence. `defender_writer_ownership_audit` automatically records each before/after change, including actor, reason and database timestamp from the state row. The explicit migration depends on the existing shadow schema; completion also requires the isolated workflow-head table.

A revision changes on every state update and is required for compare-and-set operations. An epoch changes whenever the phase changes. A write token binds the customer, owner type, process boot UUID and epoch. After a handoff, reversal or abort, old tokens no longer authorize writes. Processes must register again in a stable owner phase; restarting initialization cannot reset an existing ownership record to legacy.

## Registration, drain and completion

Registration requires inventory version 1 and all nine writer categories found in the prior audit: manual edits, Defender publication, scanner imports, scan lifecycle, assessment, company lifecycle, administrative reset, startup and persistence. Missing/duplicate categories or an incorrect owner are rejected. At most 64 participants are retained per customer in this prototype.

Beginning an attempt snapshots the registered process IDs and pauses admission. Every ID must acknowledge the same attempt with zero pending writes, a strict-save acknowledgement and a SHA-256 baseline digest. Completion requires matching digests from all processes, candidate digest evidence and a workflow revision matching the current SQL workflow head under a row lock. An unacknowledged crashed process cannot be silently ignored. There is deliberately no timeout that automatically returns ownership to legacy.

Reverse completion additionally requires a reverse-export digest matching the acknowledged baseline. This represents the required export of current SQL workflow back to a recoverable legacy baseline; it does not perform or independently verify that export yet. Aborting retains the previous owner type but increments the epoch and clears registration, so processes must re-register rather than reuse pre-attempt tokens.

## Transaction boundary

`withOwnershipWrite` holds a shared ownership-row lock for the entire admitted SQL callback. Transitions acquire an exclusive row lock, so a handoff waits for a transaction already writing under the current owner. After the transition commits, a waiting old token is rejected. Callback changes and transaction failures commit or roll back together. A preflight ownership read followed by an unlocked write would not provide this protection.

The helper is restricted to disposable target databases. Its callback is a same-database transaction operation, not a place for network calls, separate commits or nested transactions. The existing workflow editor and live snapshot writer are not wired through this helper yet. Cross-database snapshot saves and in-memory changes are not fenced by this row lock.

SQL triggers enforce monotonic revisions/epochs, basic permitted phase transitions and append-only audit. They prevent direct stable-owner jumps, deletion and truncation. Detailed acknowledgement/evidence validation lives in the trusted service, not a database security boundary: a database owner or unrestricted direct SQL writer could bypass the service's data checks. Production roles, authenticated actor/process registration and boot-time enforcement remain unimplemented.

## Evidence

The integrated PostgreSQL runner now passes 18 groups, including four ownership groups:

- Missing ownership, unknown customer and incomplete inventory refuse writes; initialization is restart-safe.
- A real active writer holds the transition waiting on a PostgreSQL lock; it commits before the phase advances. Old tokens then fail.
- Missing drain acknowledgements, wrong workflow revisions, admission during a pause and stale transition revisions are rejected. Two competing completions produce one winner.
- A fresh database client reads the durable paused phase and cannot use an old writer token. This is reconnection evidence, not a deployed application boot test.
- Terminating the backend after a reverse-transition update but before commit rolls back both state and audit. A retry succeeds from the retained paused state.
- Reversal requires export evidence; reversal/abort invalidate old tokens. Denied operations leave no fixture writes. Audit history remains continuous, and mutation/deletion/truncation tests are rejected.
- The real publication pointer is unchanged throughout. The simulated owner changes only govern a small fixture-write table, not production findings or ticket operations.

Forty-two local regression/contract tests and the Next.js production build, including its TypeScript check, passed. SQL evidence is private at `ownership-test-dDrsSfBF/fixture.log`. The deliberate snapshot failure logged earlier in that suite is from the prior handoff failure-injection test. Disposable databases were dropped and the private PostgreSQL cluster stopped. No live configuration, migrations, PM2 processes, API imports or tickets changed.

## What this does not prove yet

The service checks declarations and records evidence; it cannot discover an unregistered process or prove a caller actually installed every writer hook. A supplied digest is not independent proof that the candidate or reverse export matches data. Those proofs must come from the tested capture/comparison services, bound to an immutable generation and transaction. Acknowledgement caller identity is trusted here because there is no public endpoint. The real app still writes memory and does not consult ownership on startup. Setting an isolated row to `sql` is therefore not permission to remove the publication block.

The next step is to compose the ownership lock with the actual isolated workflow-edit transaction and bind completion evidence to verified candidate records from the handoff rehearsal. Test rollback without nested transactions, stale workflow evidence, new-process registration and continued publication refusal. Keep live routing disabled. Complete writer coverage, full-size new-import behavior, assets/scans/history and operational cutover/reversal remain separate gates.
