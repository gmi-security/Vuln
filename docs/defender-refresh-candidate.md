# Defender refresh candidate (offline prototype)

This is an isolated import-to-candidate path. It has no application route, scheduler, source API client, active publication call or production writer. Candidate writes refuse anything except a disposable database in the private recovery cluster. It does not replace `reconcileDefenderPlatform`.

## Flow

1. `readDefenderRefreshSource` reads the customer's completed current import in a repeatable-read, read-only transaction. It checks source revision, success state and retained row/device counts against the completed summary. It reads the same device/CVE aggregation used by the existing `platformSnapshot` method, without calling its schema initializer. The read snapshot survives concurrent pointer changes and source pruning.
2. `readDefenderRefreshBaseline` now collects company metadata, all of that customer's saved findings/inventory, applied run ID, saved compensating controls and completed source evidence in one read-only repeatable-read transaction. It reads only the relevant meta fields, not connector credentials. All 82 relevant snapshot rows plus source connection/run metadata are recorded as a change token using PostgreSQL row versions. Missing bucket sets, incompatible metadata and oversized inputs fail closed. This collector is restricted to the private recovery source databases.
3. `prepareDefenderRefreshCandidate` reuses the existing pure projection rules. It merges proposed changes over the baseline, retaining untouched Defender history. Other scanner findings participate in correlation, but records without Defender evidence are not copied into this Defender-only model. Candidate inventory is retained as evidence, not applied to the live inventory.
4. `captureDefenderRefreshAssessment` copies the relevant process KEV/ransomware flags and saved customer controls, records a digest/evidence copy and returns a scorer that is independent of subsequent cache/control mutations. It reuses the existing risk calculation and strongest-control rules. This captures the test process's threat state; it does not recreate an unpersisted production KEV overlay from the database restore.
5. `writeDefenderRefreshCandidate` writes a separate generation in batches of 500, reconstructs each batch and compares it with the persisted JSON representation. Optional `undefined` properties are omitted, as in existing JSON snapshot persistence. It records baseline/run/revision/context, inventory evidence and a record digest, refreshes database statistics and verifies the generation using the existing immutability guards. A failed build cannot be read as a completed generation.
6. `buildDefenderRefresh` coordinates collection, assessment capture, planning, a saved-state change check, candidate writes, saved-summary building and a final saved-state check. It returns `stale` or `comparison-only`, always with `publicationAllowed:false`. It does not hydrate the app or change the source/publication pointers. With explicit `withWorkflow:true`, it reads and overlays versioned decisions, returns `workflow-conflict` without writing if a decision conflicts, and checks the workflow revision before/after building.

## Isolated workflow edits

Apply `defender-shadow-workflow-edits.sql` only to the disposable target after the base migrations. `editDefenderWorkflow` requires a customer, finding, verified generation, expected finding revision, status/assignee patch, actor and reason. The per-customer head lock serializes writes; state, revision and automatic before/after audit commit together. Repeated identical edits are no-ops; stale revisions fail with 409. The service accepts only the private disposable target, and no application endpoint calls it. A future authenticated caller must derive the actor from the session rather than accepting client-supplied identity.

Only manual patches are stored. Each changed field retains its original basis; the status patch also records its source run and resolution timestamp. `applyDefenderWorkflow` overlays compatible decisions without changing source evidence. An assignment change does not freeze status. A newer active source observation conflicts with manual resolution; changed workflow bases, mismatched device/CVE identity and absent decided findings also conflict. Any conflict prevents all candidate writing. This is an intentionally conservative offline policy, not a change to the existing legacy reopen rule described below. Review/release controls for conflicts are still required.

Workflow snapshots are limited to 500,000 decisions and 32 MiB of patch JSON, with bounded SQL timeouts. Candidate provenance records the snapshot revision/count/digest. Revisions checked before/after builds detect committed workflow edits; they do not provide an atomic production cutover or capture unsaved legacy memory changes. The publication block remains mandatory. Customer-wide serialization and workflow snapshots have not been stress-tested at full scale.

## Publication restriction

Apply `defender-shadow-refresh-publication-block.sql` after the refresh migration in disposable targets. It blocks selecting any refresh candidate through either the existing publication service or direct SQL. Current production analyst edits live in memory before a later database flush. A SQL change token cannot see those pending changes, and a successful check is only a point-in-time observation, not an atomic handoff between two databases. Blocking publication is intentional until the authoritative workflow write protocol is implemented. Existing non-refresh snapshot comparisons remain separately usable.

The token includes all snapshot buckets, so another customer's saved change can conservatively invalidate a build. It does not claim to detect unsaved memory edits, arbitrary source-record edits that bypass the completed-import contract, or a production process's independent threat-cache refresh. Token checks are short-lived migration checks, not durable global revision numbers.

## Preserved behavior

| Condition | Candidate behavior |
| --- | --- |
| Same completed import already applied | Preserve the baseline unchanged; do not reopen later manual resolutions or rescore |
| New import still detects a resolved finding | Reopen it under the existing legacy rule, preserving its stable ID and assignee |
| Risk Accepted / False Positive | Preserve the workflow decision under existing projection rules |
| Device absent, stale or without a usable heartbeat | Retain the old finding and source evidence; absence alone is not patch confirmation |
| Fresh device no longer reports an open finding | Resolve eligible Defender-only findings |
| Another scanner still reports the finding | Remove active Defender evidence without closing the other scanner's finding |
| Shared scanner identity | Reuse the existing unambiguous correlation and stable finding/asset IDs |
| Ticket history | No ticket table is read or written by these new modules; stable identifiers are retained |
| Source revision or retained counts disagree | Refuse the source read, with no partial successful result |

Bounds: at most 1,000,000 raw source instances, 500,000 grouped/baseline/candidate findings, 100,000 devices/assets and 512 MiB of expanded source JSON. Reads have 15-second statement limits and a 120-second default total deadline. Candidate writes have a five-minute maximum deadline, 16 MiB batch payload limit and 32 MiB provenance limit. These are offline protection limits, not proven production sizing. The planner currently holds customer baseline and source arrays in memory; it must run outside page requests.

## Evidence

The consistent-baseline coordinator now passes seven PostgreSQL fixture groups and 25 relevant local contract/regression tests. New checks cover collection from one snapshot, detection of committed changes without timestamp updates, changes before/after writing, frozen assessment inputs and rejection of refresh publication through the service and direct SQL.

The full retained same-run build reconstructed and verified all 288,878 Defender findings, then matched 215,891 open findings and 10,229 unique open CVEs. It took 160,407 ms: 19,697 ms collecting inputs, 1,943 ms planning/check hooks, 107,145 ms writing/verifying the base generation, and about 31,622 ms building summaries and finishing checks. Peak process RSS was 1,028,260 KiB (about 1,004 MiB). The disposable database occupied 791,951,039 bytes (about 755 MiB), including its indexes and ordinary database overhead. These figures are for the retained dataset and already-applied run, not production capacity or a new-import rescore benchmark. The same-run rule deliberately preserves saved scores; fixture tests exercise actual new-run scoring and workflow transitions.

Evidence for this checkpoint is retained privately under `refresh-baseline-6jO0fL88` (`fixture.log`, `scale.log`, `refresh-scale-result.json`). The test databases were dropped and the private cluster stopped. No production process or data was changed.

Earlier component-level evidence:

- Four candidate contract tests compare actual existing projection/publication behavior, including same-run retries, analyst decisions, correlation, stale/missing devices and invalid input.
- Five PostgreSQL test groups compare source aggregation and candidate records to the actual legacy methods, test append-only provenance, repeated candidate content, a build interrupted after 500 of 501 records, publication preservation, rejection of source-database writes, concurrent source replacement/pruning and valid empty imports.
- The full retained source read processed 212,921 device/CVE pairs and 2,348 devices in 6,095 ms, with peak process RSS 282,064 KiB (about 275 MiB). This measured source reading only, without baseline hydration, candidate planning or full candidate writes. It is not a live count or end-to-end performance result.
- Production build/type checks and 51 local regression tests passed. Private SQL tests block outbound TCP and permit only the recovery PostgreSQL socket. No source APIs or real ticket actions occurred.

SQL fixture runner: `node --experimental-vm-modules tests/defender-refresh-postgres.mjs <private-socket-directory>`. It creates and drops its own source and target test databases. Migrations are applied only there, in base/read/publication/refresh order. `tests/defender-refresh-source-scale.mjs` reads only the retained recovery database.

## Remaining before activation

The isolated workflow contract passes 29 local tests and ten PostgreSQL fixture groups, plus build/type checks. Evidence is private under `workflow-test-ypMgtjLt/fixture.log`; the runner applies the workflow migration and uses competing target clients. Test databases were removed and the private cluster stopped. The earlier full-size measurements above did not include this workflow overlay.

The writer inventory and test-only handoff rehearsal are now documented in `docs/defender-workflow-handoff.md`. The expanded runner passes 14 PostgreSQL groups and 39 relevant local tests/type checks. It uses actual legacy edit/flush/persistence code, refuses failed or inconsistent saves and preserves pending workflow in comparison candidates. It does not install a live writer gate or authorize ownership transfer.

The ownership prototype now guards the actual isolated workflow editor. With `handoffAttemptId` and `withWorkflow:true`, the coordinator records baseline/attempt/workflow evidence alongside the candidate digest. Completion reads that immutable evidence and rechecks source/workflow state; declared digests are rejected. See `docs/defender-writer-ownership.md` for the 21 SQL groups and 44 local tests. Reverse completion remains blocked pending an independently verified export.

Next test a bounded reverse-export artifact against the legacy snapshot reader. Implement conflict review/release semantics and authenticated routing before activation; preserve inventory/scans/history consumers; add durable job leases/retries and source-authority checks; validate full-size new-import rescoring separately from same-run rebuilding; and test publication/rollback integration before removing the candidate publication block. Freeze a verified production threat context explicitly rather than assuming a new process shares the old process's cache. No production caller should be added until these are satisfied.
