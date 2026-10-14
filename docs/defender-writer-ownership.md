# Defender writer ownership: isolated protocol

Implemented October 10, 2026 on Vuln2.0. This is an offline protocol in disposable recovery SQL. It is not installed in production and does not activate the new data model. The existing refresh-publication block remains mandatory.

## State and transitions

| State | Admitted participating writer | Allowed next step |
| --- | --- | --- |
| `legacy` | Registered legacy process at the current epoch | Begin forward handoff to `draining` |
| `draining` | None | Finish to `sql` after all registered processes acknowledge; or abort to `legacy` |
| `sql` | Registered SQL process at the current epoch | Begin reverse handoff to `reversing` |
| `reversing` | None | Abort to `sql`; reverse completion is blocked until a verified export service exists |

`defender_writer_ownership` stores one customer row containing its phase, revision, epoch, registered processes, current attempt and acknowledgement evidence. `defender_writer_ownership_audit` automatically records each before/after change, including actor, reason and database timestamp from the state row. The explicit migration depends on the existing shadow schema; completion also requires the isolated workflow-head table.

A revision changes on every state update and is required for compare-and-set operations. An epoch changes whenever the phase changes. A write token binds the customer, owner type, process boot UUID and epoch. After a handoff, reversal or abort, old tokens no longer authorize writes. Processes must register again in a stable owner phase; restarting initialization cannot reset an existing ownership record to legacy.

## Registration, drain and completion

Registration requires inventory version 1 and all nine writer categories found in the prior audit: manual edits, Defender publication, scanner imports, scan lifecycle, assessment, company lifecycle, administrative reset, startup and persistence. Missing/duplicate categories or an incorrect owner are rejected. At most 64 participants are retained per customer in this prototype.

Beginning an attempt snapshots the registered process IDs and pauses admission. Every ID must acknowledge the same attempt with zero pending writes, a strict-save acknowledgement and a SHA-256 baseline digest. Completion requires matching digests from all processes, candidate digest evidence and a workflow revision matching the current SQL workflow head under a row lock. An unacknowledged crashed process cannot be silently ignored. There is deliberately no timeout that automatically returns ownership to legacy.

The pure transition model defines reverse-export prerequisites, but the service still blocks reverse completion. A declared checksum or a point-in-time restore receipt is not sufficient to fence the real legacy writer. Aborting retains the previous owner type and last completed generation evidence, but increments the epoch and clears registration, so processes must re-register rather than reuse pre-attempt tokens.

## Transaction boundary

`withOwnershipWrite` holds a shared ownership-row lock for the entire admitted SQL callback. Transitions acquire an exclusive row lock, so a handoff waits for a transaction already writing under the current owner. After the transition commits, a waiting old token is rejected. Callback changes and transaction failures commit or roll back together. A preflight ownership read followed by an unlocked write would not provide this protection.

The helper is restricted to disposable target databases. Its callback is a same-database transaction operation, not a place for network calls, separate commits or nested transactions. `editOwnedDefenderWorkflow` now composes the actual isolated editor with this transaction: ownership, workflow revision, state and audit commit together. The edit core is private and does not start or commit a nested transaction. The older isolated entry point refuses customers with an ownership record. A customer-specific transaction advisory lock serializes the first ownership initialization with any previously admitted unguarded edit. The live snapshot writer remains unchanged; cross-database saves and memory changes are not fenced by this row lock.

## Verified forward completion

The coordinator accepts an explicit handoff attempt ID only with workflow snapshotting enabled. It records a versioned baseline digest, attempt ID and workflow revision in immutable candidate provenance. The digest is stable across PostgreSQL JSONB key order and snapshot bucket order; it includes the company, applied run, complete baseline findings, inventory and controls. Records are hashed individually rather than creating another whole-customer JSON string. The handoff rehearsal uses the same digest function for its detached memory capture.

`transitionWriterOwnership` no longer accepts `finish`. `completeVerifiedOwnership` takes a candidate UUID, refuses caller-supplied completion digests/revisions, and loads the scoped candidate evidence itself. It requires the current attempt, a verified model-v2 generation with sealed version-1 saved reads and matching counts, a matching workflow revision, and an unchanged source/baseline token checked against the private source database. The workflow head is locked through commit. The selected candidate ID and its stored record digest are retained in ownership audit/state.

This proves consistency against the candidate builder's immutable verification record; it does not rescan all candidate rows at completion or authenticate process drain acknowledgements. The source check is a point-in-time observation across separate databases, so it is not an atomic production handoff. The real publication block remains in force.

SQL triggers enforce monotonic revisions/epochs, basic permitted phase transitions and append-only audit. They prevent direct stable-owner jumps, deletion and truncation. Detailed acknowledgement/evidence validation lives in the trusted service, not a database security boundary: a database owner or unrestricted direct SQL writer could bypass the service's data checks. Production roles, authenticated actor/process registration and boot-time enforcement remain unimplemented.

## Evidence

The thirtieth checkpoint passed 18 groups, including four ownership groups:

- Missing ownership, unknown customer and incomplete inventory refuse writes; initialization is restart-safe.
- A real active writer holds the transition waiting on a PostgreSQL lock; it commits before the phase advances. Old tokens then fail.
- Missing drain acknowledgements, wrong workflow revisions, admission during a pause and stale transition revisions are rejected. Two competing completions produce one winner.
- A fresh database client reads the durable paused phase and cannot use an old writer token. This is reconnection evidence, not a deployed application boot test.
- Terminating the backend after a reverse-transition update but before commit rolls back both state and audit. A retry succeeds from the retained paused state.
- Reversal requires export evidence; reversal/abort invalidate old tokens. Denied operations leave no fixture writes. Audit history remains continuous, and mutation/deletion/truncation tests are rejected.
- The real publication pointer is unchanged throughout. The simulated owner changes only govern a small fixture-write table, not production findings or ticket operations.

Forty-two local regression/contract tests and the Next.js production build, including its TypeScript check, passed. SQL evidence is private at `ownership-test-dDrsSfBF/fixture.log`. The deliberate snapshot failure logged earlier in that suite is from the prior handoff failure-injection test. Disposable databases were dropped and the private PostgreSQL cluster stopped. No live configuration, migrations, PM2 processes, API imports or tickets changed.

## What this does not prove yet

The service cannot discover an unregistered process or prove that it installed every writer hook. Candidate completion evidence now comes from immutable saved records; a workflow-only reverse artifact is available for offline validation, but reverse completion remains blocked. Acknowledgement caller identity is still trusted because there is no public endpoint. The real app still writes memory and does not consult ownership on startup. Setting an isolated row to `sql` is therefore not permission to remove the publication block.

The thirty-first checkpoint passed 21 PostgreSQL groups, 44 local tests and build/type checks. It additionally tests initialization versus a pending unguarded edit, actual workflow edits under ownership, rollback of state/head/audit, old-entry-point bypass refusal, absence of nested transactions, stale source/workflow evidence, mismatched candidate/attempt and rejection of declared checksums. An ownership transition demonstrably waits for the actual workflow edit before invalidating its token. Evidence is private at `owned-edit-test-Cbelfrwd/fixture-final.log`; disposable databases were removed and the private cluster stopped. No production changes occurred.

## Workflow-only reverse artifact

`defender-workflow-export.mjs` collects one explicitly selected verified generation and the current workflow overlay. It requires matching current/applied source runs and exact non-workflow finding evidence. It permits only status, assignment and original resolution timestamp changes. Collection is limited to 500,000 records, 500-record batches, 16 MiB per batch, 512 MiB reconstructed data and a bounded deadline; the artifact is limited to 32 MiB. Source/baseline and workflow revision are checked again before return.

The pure apply helper verifies the checksum, exact customer baseline digest, finding identities and prior workflow values before producing a detached legacy snapshot. It preserves unrelated customer/scanner records and all other snapshot collections. The checksum provides integrity checking, not authentication. This small-fixture helper still clones the full supplied snapshot and must not be used as the full-size restore implementation. The export/receipt service now computes its expected result incrementally instead.

The thirty-second checkpoint passed 24 PostgreSQL groups, 47 local tests and build/type checks. Actual legacy snapshot persistence and a fresh reader reproduce the entire exported fixture, including original timestamps and unrelated records. Concurrent source/workflow changes, source-generation mismatch and altered artifacts are rejected. Failed saves retain the old snapshot and retry succeeds. Ownership and publication remain unchanged. Evidence is private at `reverse-export-test-XmmWvpdT/fixture.log`; disposable databases were removed and the private cluster stopped.

The standalone artifact is explicitly non-activating. The service below binds it to ownership evidence. It covers workflow-only changes within the same import, not newly imported findings, assets or scans. Reverse completion remains blocked.

## Ownership binding and restore receipts

`defender-reverse-receipt.mjs` and the explicit `defender-shadow-reverse-receipts.sql` migration add offline export/receipt records. Preparation accepts an attempt and expected ownership revision, derives the projection from `lastCompleted`, and requires every reverse participant to acknowledge the matching baseline. It stores the artifact, workflow/ownership versions, source database identity and source row versions, plus complete before/expected snapshot digests. Caller-declared digests and projection overrides are rejected. A repeated preparation cannot replace an existing export; changed ownership/workflow requires a new attempt.

Verification independently reads the known legacy bucket layout in a repeatable-read transaction. It includes all customers and metadata in the digest, tolerates Map/key reordering and preserves nested array order. Unknown/missing buckets and metadata overrides are refused. Limits are 32 MiB per bucket, 1 GiB total serialized data, two million Map entries and 180 seconds for the read. These limits do not represent peak heap consumption. The source database, completed import and transaction versions must match the prepared record. A follow-up source observation detects committed changes during verification; ownership and workflow locks cover receipt insertion. Append-only tables and one receipt per customer/attempt preserve history and make retry idempotent.

Digest format v2 hashes one record at a time and retains IDs/hashes rather than entire snapshots. Export preparation computes the baseline and expected digests in the same bucket traversal, checking each affected finding with the same identity/workflow rules as the pure helper. The collected artifact now includes its saved-baseline transaction fence; that fence must match the pinned digest-read snapshot before any expected result is accepted. Existing format-v1 receipt evidence is refused rather than treated as interchangeable. These schemas are still private prototypes; no production receipt migration has occurred.

The service does not write the legacy snapshot. The test harness uses the actual legacy writer, then compares both the fresh legacy reader and independent verifier. The thirty-third checkpoint passed 27 PostgreSQL groups, 50 local tests and build/type checks. A terminated receipt connection after its INSERT rolls back the receipt while preserving the already committed legacy save; a new connection verifies that save and records one receipt without rewriting it. Tests also reject incomplete/changed restores, source/workflow drift, supplied generations and obsolete attempts. Aborting retains the selected projection while old registrations remain invalid. Evidence is private at `reverse-receipt-test-6A0urpxu/fixture.log`; disposable databases were removed and the private cluster stopped.

A receipt records a point-in-time observation, not an atomic cross-database cutover. It cannot prevent unregistered memory writers or later legacy changes, so reverse completion remains rejected even with a receipt. Complete writer coverage, full-size new-import behavior, assets/scans/history and operational cutover/reversal remain separate gates.

## Full-size verification and memory boundary

The retained legacy snapshot contains 91 buckets totaling 972,609,195 bytes (927.6 MiB of JSON text); its largest bucket is 15,543,782 bytes (14.8 MiB). This made loading and copying the entire snapshot inappropriate for receipt preparation. The v2 incremental digest now reads one bucket at a time and retains entry IDs/hashes. The standalone pure snapshot-application helper is still limited to small fixtures; it is not a full-size restore writer.

In fresh Node processes against private recovery data, a same-import candidate covering all 288,878 Defender findings built in 176.2 seconds at 1,362.6 MiB peak RSS. A no-change export took 184.9 seconds at 1,228.9 MiB peak RSS and produced a 5,360-byte artifact. Independent verification read the complete legacy snapshot in 38.2 seconds at 508.4 MiB peak RSS and recorded one receipt. Export collection still loads the selected Defender cohort and source input; these timings belong to an offline maintenance operation, not a page request. RSS includes more than the JavaScript heap. The 1 GiB serialized-data ceiling has about 96.4 MiB of headroom on this retained snapshot; this measurement does not approve a higher limit or guarantee performance on current production data.

A one-assignment export passed in 190.9 seconds at 1,226.0 MiB peak RSS (5,631-byte artifact). Verification correctly rejected that unrestored change in 38.3 seconds at 502.6 MiB, leaving the earlier receipt count unchanged. The source database stayed read-only throughout. All five scale stages passed, together with 51 local tests, 27 PostgreSQL fixture groups and the production build/type check. Evidence is private at `reverse-scale-FVRWY1bR/reverse-scale-result.json` and `reverse-scale-FVRWY1bR/fixture.log`; the disposable target was dropped and the private cluster stopped.

This is full-size collection/verification evidence with zero or one changed finding, not bulk-edit performance or a full-size changed-data restore. The next bounded step is a transactionally checked, bucket-level restore writer in disposable storage, tested with the actual legacy reader and independent receipt service. It must leave real application write ownership and reverse completion blocked until complete writer fencing is in place.
