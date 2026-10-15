# Connector save improvement plan

**Status:** Implementation and independent review complete on October 15, 2026, on `perf/connector-scoped-saves`. Ready for PR review. Production is unchanged; deployment, live response measurements and the next scheduled import cycle remain unverified.

**Date:** October 15, 2026

**Goal:** Reduce the CPU, memory and time needed to save connector imports, while preserving the same findings, customer ownership, reporting and ticket records.

**Architecture:** Reuse the existing PostgreSQL tables, single platform writer and explicit record-change mechanism. Improve the shared import functions so they identify the records they touch. Preserve the existing direct SQL import and cache paths.

**Technology:** Next.js, TypeScript, Node.js, PostgreSQL and the existing Node test harness. No new dependency or database is proposed.

**Design basis:** The design and acceptance rules below, the connector code reviewed against deployed commit `6967ab200fcd3221dedd2ce2f15b48e44ee6ae45`, and [the persistence recovery record](persistence-save-recovery.md).

## Why these changes are needed, in simple terms

Imagine updating one customer's folder, then checking every folder in the office to work out what changed. That is effectively what some imports still ask the application to do.

The database already writes only records whose contents changed. The expensive part is discovering those changes: older import functions tell the save process that something changed, without telling it which records changed. The application then compares the entire shared platform store, including unrelated customers and sources.

In the previously verified full production save, preparation took about **129 seconds**, while the remaining work took about **0.23 seconds**. These are observations from one save, not a guarantee for every import. They show why increasing database timeouts alone does not remove the main expense.

The recent fix moved that preparation outside the database transaction. This prevents the database transaction sitting idle while the application calculates comparisons. It does not remove the calculation itself.

The next improvement is to keep a list as an import works: "I updated these assets, added these findings and closed these findings." The save process can then compare that list instead of comparing everything.

For example, if an inventory sync changes 200 assets, it should save those assets and any findings whose scores or associations actually changed. It should not serialize and hash another customer's findings just to discover they are unchanged.

**Expected benefit:** less unnecessary processing during imports, fewer save retries caused by overlapping work, and more predictable responsiveness. Large source downloads, large customer imports and real database failures can still take time or fail. This plan does not claim to eliminate every cause of slowness.

## Recommended approach and alternatives

| Option | Benefit | Tradeoff | Decision |
| --- | --- | --- | --- |
| Extend the existing record-scoped save mechanism | Reuses working storage and removes unnecessary comparison across several connectors | Requires careful tracking of every changed record and metadata item | Recommended |
| Only increase heap and timeouts | May provide temporary headroom | Still performs the same work and can delay detection of a failure | Not the primary solution |
| Replace every connector with a new storage system | Could produce a uniform architecture | Much larger migration and regression surface than this performance problem needs | Defer |

## Current behavior and planned treatment

These are supported code paths, not a claim that every optional connector is currently enabled.

| Source or operation | Current behavior | Planned treatment |
| --- | --- | --- |
| Nessus completed imports | Shared findings and scans; can trigger full-platform comparison | Track imported, updated, closed and partially processed records explicitly |
| Nessus progress polling | Already uses scan IDs for narrow saves | Preserve and test alongside completed imports |
| Tidal, Automate, CrowdStrike device inventory and Intune | Shared asset updates and finding rescoring can trigger full comparison | Scope asset writes and rescore affected findings within the appropriate customers |
| SpiderFoot, Artemis, Vulners Bridge and ZAP | Shared scanner import and completion functions | Convert their complete mutation paths, including asynchronous completion and errors |
| Burp and Nmap | Shared findings/assets/scans through API or upload paths | Apply the same treatment; keep disabled connectors disabled |
| Defender | Source import tables plus explicit IDs for platform publication | Retain this design; verify large publications and remove avoidable unchanged candidates only where measured |
| CrowdStrike Spotlight vulnerabilities | Direct SQL batches and a completed import generation | Preserve generation promotion, resumability and customer scope; regression checks rather than rewriting the importer |
| Legacy Vulners/platform threat enrichment | Shared findings are updated and rescored | Track affected CVEs/findings and preserve cross-source scoring within a customer |
| MISP/OpenCTI/IntelOwl CVE enrichment and SQL risk records | Dedicated SQL cache/risk writes | Preserve; verify refresh and downstream reporting still work |
| Saved Elasticsearch/CrowdStrike query tiles | Dedicated cached results | Preserve existing refresh settings and result persistence |
| ConnectWise ticket tracking | Dedicated ticket and audit writes | Preserve manual draft creation, approval and tracked references |
| Elastic-backed AppSec views | Read configured Elastic streams | No platform-save conversion required; regression-check routing and reads |

Spotlight and Defender import tables use the application's PostgreSQL connection. Their separate tables do not mean separate physical databases. Other cache/ticket modules can have their own configured connection, which this plan does not change.

## Proposed data flow

```text
Fetch data for the configured customer and connector
    -> normalize and match existing records
    -> record touched asset, finding, scan, folder and company IDs
    -> compare those records with the last committed versions
    -> save changed rows, metadata and reporting revisions atomically
    -> refresh affected customer reporting from committed data
```

"Touched" means a candidate for comparison, not automatically a changed database row. A full customer snapshot may touch many records; matching hashes should still prevent unnecessary row writes. An observation timestamp may legitimately change even when the vulnerability itself has not changed.

API fetching and database saving are separate. Some providers will still require a complete customer snapshot. This plan improves what happens after retrieval; it does not assume every API supplies a reliable change feed.

## Boundaries and rules that must stay intact

- Keep the existing database schema, customer connector assignments, source ownership, CVE identity and matching rules.
- Keep scheduled connector syncs at their configured 24-hour cadence, with Elasticsearch excluded from the general connector import cycle. Preserve individual saved-tile refresh settings.
- Keep ticket creation manual. Do not restore automatic patch-draft generation or create test tickets in ConnectWise.
- Preserve findings, aliases, counters, source-generation markers, scan completion and partial-failure metadata. These are all part of a successful save.
- Missing records in a partial import must not be treated as resolved. Preserve each connector's evidence and coverage rules for closure.
- An inventory change may affect findings from several sources for the same customer. Restricting rescoring to the inventory connector's own findings would be incorrect.
- Preserve one SQL writer, authority/revision checks, committed-only web reads, atomic reporting publication and the blocked-write safeguard on genuine storage failures.
- Keep the safe full-comparison fallback for operations that cannot yet supply a complete change list, including broad administrative changes. Never silently treat an unknown scope as an empty scope.
- Do not enable currently disabled providers, add credentials or change routing as part of this work.

## Implementation order

Each stage must pass its checks before its change list is trusted. Use a task branch and reviewed PRs. The first stage is the shared save foundation, not a rewrite of all importers at once.

### Task 1: Improve shared mutation tracking and diagnostics

**Files:** `lib/store.ts`, `lib/persist.ts`; extend `tests/platform-prepared-save.test.mjs` and `tests/persist-frozen-capture.test.mjs`; add `tests/connector-mutation-scope.test.mjs`.

**Existing interfaces to reuse:** `PlatformChanges` contains ID arrays for `companies`, `folders`, `scans`, `findings` and `assets`; `markDirty(changes?)` merges pending changes; `nextId(s, prefix, collection?)` already supports a collection name; `saveSnapshot(data, { changes, guard, captureGuard })` chooses the persistence path. Metadata-only changes use `markDirty({})` under the existing contract.

- [x] Inventory every caller of asset upsert, finding correlation/rescoring, identity linking, stale closure and ID creation. Record where the caller mutates data after an `await`.
- [x] Add failing behavioral tests: one asset edit marks that asset; one finding rescore marks only the changed finding; new IDs retain the counter; aliases survive restart; a declared deletion persists; an unscoped mutation still promotes the save to full comparison.
- [x] Update the shared functions to declare the actual stored record IDs, including canonical asset IDs when multiple sources refer to one host. Keep their external behavior and matching rules.
- [x] Extend safe save diagnostics with candidate counts, compared-record counts, phase durations and an enumerated full-fallback reason. Do not log finding contents, hostnames or credentials.
- [x] Run the tests, inspect the diff and commit the passing foundation.

**Done when:** scope omissions are caught by tests and an unknown mutation still takes the safe path. A change to one record does not claim to have saved later mutations.

### Task 2: Convert inventory imports and narrow rescoring

**Files:** `lib/store.ts` (`upsertAsset`, `rescoreFinding`, `rescoreAllFindings`, `importTidalInventory`, `importFromAutomate`, `importEndpoints`, `importFromCrowdstrike`, `importFromIntune`); extend `tests/inventory-source-scopes.test.mjs`, `tests/customer-consolidation-asset-import.test.mjs` and the new scope tests.

**Interface rule:** reuse existing importer return types. Pass customer sets through existing scope arguments. Any additional changed-asset input stays internal to the store helpers.

- [x] Add tests with two customers and overlapping host/vendor IDs. Assert that an inventory import preserves ownership, source observations, aliases and affected finding scores while leaving the other customer unchanged.
- [x] Track asset candidates throughout each inventory path. Restrict risk recalculation to affected assets when the dependency is known; use the affected customer's complete finding set when an alias or customer-wide dependency makes a narrower set unsafe.
- [x] Avoid marking findings whose persisted score fields did not change. Preserve real observation timestamps and all existing risk calculations.
- [x] Verify both reviewed routing and supported legacy routing paths. Missing scope must not silently skip required work.
- [x] Compare old and new resulting records, run the relevant tests, then commit.

**Done when:** inventory saves no longer trigger full comparison through these paths, and scores match the original behavior for every affected finding.

### Task 3: Convert the complete Nessus import lifecycle

**Files:** `lib/store.ts` (`importVendorFindings`, `importFromNessus`, `closeStaleFindings`, polling/completion and resync paths); extend `tests/finding-correlation.test.mjs`, `tests/connector-import-result.test.mjs` and the new scope tests.

- [x] Add tests for new, changed, duplicate and reopened findings; stale closure; unchanged scans; partial failure; new-scan creation; and mutations arriving while a provider request is awaited.
- [x] Replace full dirty markers only after the complete findings/assets/scans/folders/metadata mutation set is known. Preserve the recent correlation lookup optimization.
- [x] Keep imported timestamps and completion markers consistent with the rows they describe. A saved completion marker must never acknowledge omitted finding changes.
- [x] Compare committed results and restarted state with the original path; run the Nessus and persistence tests, then commit.

**Done when:** both new scans and existing scan updates save complete results through scoped writes, with no regression in progress polling or closure behavior.

### Task 4: Convert remaining shared-store scanners and enrichment

**Files:** importer functions in `lib/store.ts` for SpiderFoot, Artemis, Vulners Bridge, ZAP, Burp, Nmap, Vulners enrichment and `enrichThreatIntel`; extend `tests/connector-import-ownership.test.mjs`, `tests/source-platform-semantics.test.mjs` and the scope tests.

- [x] Add a fixture for each path covering success, repeat import, partial provider failure and restart. Include asynchronous scanner callbacks and upload routes.
- [x] Declare all modified IDs and metadata. Keep scanner-specific rules for finding identity, suppression and closure.
- [x] For shared CVE enrichment, update every affected customer finding when required. A CVE can be shared across customers even though individual findings remain customer-owned.
- [x] Run each connector's behavior checks against the prior output and commit the verified group.

**Done when:** every listed shared-store path has a tested scope or an explicitly documented full-save reason. Disabled providers are covered by fixtures and remain disabled.

### Task 5: Verify large scoped saves and existing direct SQL paths

**Files:** `lib/db/platform-store.mjs`, `lib/persist.ts`, `lib/db/customer-reporting-revisions.mjs`; tests in `tests/platform-bulk-save.test.mjs`, `tests/platform-store-postgres.mjs`, `tests/defender-publication-persistence.test.mjs`, `tests/spotlight-resumable-import.test.mjs` and `tests/reporting-inputs.test.mjs`.

- [x] Test small edits and large customer publications with many unrelated platform records. Measure candidate preparation, map/index copying and process memory; record real SQL/reporting/commit time as a combined remainder. Reporting time and SQL time are not independently isolated by this measurement.
- [x] Preserve the existing direct SQL generation/cache/ticket writers. Test Defender publication, Spotlight resume/promotion, tile results and ticket references through restart; use mocked provider transport for external actions.
- [x] Verify that only affected reporting inputs change. Follow the existing reporting bucket/revision contract; do not force all customer summaries to rebuild.
- [x] If the large scoped path still spends substantial preparation time inside a transaction, extend the existing prepared-save mechanism to scoped captures before releasing that path. Freeze rows and metadata before SQL, recheck authority, and retain later mutations for the next save. Do not remove capture guards from live values.
- [x] Run real PostgreSQL rollback, stale-writer and restart tests in a disposable test database, then commit any required writer adjustment.

**Done when:** large scoped saves cannot recreate the long idle-transaction failure, and all paths retain identical committed data and reporting revisions.

The current delta writer still copies collection maps and examines index entries. Tracking IDs reduces payload comparison, but does not automatically make every part of a save proportional to the number of changed rows. Measure these costs before proposing further indexes or abstractions.

### Task 6: Compare performance and prepare the release

- [x] Compare full and scoped preparation on the same synthetic data: one asset edit, one scan-progress edit, a small inventory change and large Nessus-/Defender-shaped customer sets. Verify overlapping mutations separately with behavioral and real SQL tests. These are save-path comparisons, not end-to-end historical importer benchmarks.
- [x] Record candidates, compared/written rows, preparation time, index copy time, CPU, memory and event-loop delay; record the combined SQL/reporting/commit remainder separately. No live provider timing or production HTTP latency was measured.
- [x] Run the complete test suite, real PostgreSQL checks, TypeScript validation, both worker builds and a Linux production build. Record skipped checks separately from passes.
- [x] Complete independent review, reproduce findings and verify fixes. Review found and fixed duplicate unfinished Nessus scans and stale errors after successful retries; no findings remain outstanding.
- [ ] Open the reviewed PR with connector coverage and before/after measurements.

**Release checks still required after PR review:**

- [ ] Build the merged version before stopping the running service.
- [ ] At the authorized deployment, drain or safely stop active imports and preserve durable resume state. Restart with existing configuration, then verify health, a real successful scoped commit, customer totals, reporting and ticket references.
- [ ] Measure provider time and page/API response times during actual imports. Preparation benchmarks alone do not prove production responsiveness.
- [ ] Observe the next scheduled 24-hour cycle before declaring scheduled-import behavior verified. A manual test alone does not prove that cycle.

**Rollback:** use the prior application build and its existing full-save fallback after safely stopping the new writer. Keep the database and committed records in place; this plan requires no schema or data-format migration. Rollback must not start a second writer or discard pending durable import state.

## Review focus and acceptance checks

| Risk | Required proof | Owner stage |
| --- | --- | --- |
| A change list omits an alias, counter, closure or completion marker | Persist and restart; compare full relevant records and metadata against the original behavior | 1, 3, 4 |
| Inventory changes miss findings from another source for the same customer | Multi-source score parity, with the other customer unchanged | 2 |
| A save overlaps a later mutation | First commit contains one consistent capture; later changes remain queued and survive the next commit | 1, 5 |
| A partial import incorrectly closes absent findings | Failed/truncated source fixtures retain previously open findings without fabricated completion | 3, 4, 5 |
| A narrow save produces stale reports or excessive transaction work | Real SQL row/reporting parity, bounded transaction work and customer summary checks | 5, 6 |

Release acceptance is behavioral, not just a faster timing:

- The same input produces the same stored findings, ownership, associations, scores, closures and ticket links.
- Converted paths compare record payloads only for their declared candidates. Unrelated payloads are not serialized or hashed; residual map/index overhead is measured separately.
- Small scoped workloads are faster than the old full-comparison path on the same fixture. Large imports show their remaining costs explicitly; no unmeasured speedup is promised.
- No data is lost on rollback, write failure, overlap or app restart in the test scenarios.
- Reporting remains consistent with committed findings, and page responsiveness during imports is no worse than the measured baseline. Record remaining bottlenecks if it is still slow.
- Genuine storage failures still produce the blocked-write warning. Success means fixing unnecessary failures, not hiding the warning.

## Verification commands for implementation

Run the focused tests as each stage is built, followed by the broad checks below. Completed checks and their limitations are recorded in the next section.

```bash
node --experimental-vm-modules --test tests/connector-mutation-scope.test.mjs tests/platform-prepared-save.test.mjs tests/persist-frozen-capture.test.mjs tests/platform-bulk-save.test.mjs
node --experimental-vm-modules --test tests/*.test.mjs
npx tsc --noEmit
npm run build:summary-worker
npm run build:reporting-worker
npm run build
```

Run `tests/platform-store-postgres.mjs` separately using its guarded private Unix-socket test setup. It creates its own disposable database and refuses a normal application database target. Confirm its socket, port and lifecycle requirements before execution; do not point it at production or reuse an incomplete recovery database.

## Current position and next step

- [x] Trace connector save paths and document the design and risks.
- [x] Implement and verify stages 1 through 5 and the pre-release portion of stage 6.
- [x] Independently review the complete branch and fix both findings.
- [ ] Review and merge the PR, then perform the release checks above.

The next step is PR review. No production application, database, PM2 process, connector credentials, schedules or ticket settings were changed during this implementation.

### Verification evidence

| Check | Result | Scope and limitation |
| --- | --- | --- |
| Final local suite | 995 passed, 7 optional DB tests skipped, 0 failed (1,002 total) | Includes customer isolation, mutation scopes, partial imports, overlap, frozen captures, fallback, reporting, scanner behavior and mocked-provider regressions |
| Optional database suite | 51 passed, 0 skipped, 0 failed | The five test files containing all seven local DB skips were run with a fresh private PostgreSQL cluster: Defender, Defender risk, Elastic cache, ticket lifecycle and legacy snapshot persistence. 51 includes non-DB cases in those files; it is not 51 additional unique tests |
| Platform PostgreSQL checks | 21 passed | Synthetic source records, 30,001-row publication, exact reporting parity, actual transaction rollback, stale writers and restart |
| TypeScript and both workers | Passed | Final application type check plus summary and reporting worker builds |
| Linux production build | Passed | Final application code in an isolated build directory, without production configuration or provider jobs |
| Independent review | No outstanding critical, important or minor findings | Reviewer ran 60 focused checks initially and 36 after fixes; broader results are implementer evidence |
| Live provider and production performance | Not run | Existing credentials/schedules remain unchanged; require release observation |

The full-save oracle in connector fixtures runs the **current importer** with full comparison forced on. It verifies that scoped persistence omits no changes in those scenarios; it does not independently prove every behavior matches an older importer. Separate correlation/routing fixtures preserve existing behavior, including a new occurrence when a previously resolved CVE is detected again.

### Connector coverage

| Path | Implemented and checked | Evidence |
| --- | --- | --- |
| Tidal, Automate, CrowdStrike inventory, Intune | Actual asset IDs, customer-limited cross-source risk recalculation, alias metadata, repeats and restart | `connector-inventory-saves`, `connector-mutation-scope`, existing ownership/routing tests |
| Nessus | Findings, closure, scans, backfill, provider failure, partial application, completed-import retry, pending-scan reuse and restart | `connector-nessus-saves`, finding correlation, import-result and scanner routing tests |
| SpiderFoot, Artemis, Burp, Nmap | Scoped success/repeat/partial failure; assets, findings, scan totals and completion | `connector-scanner-saves`, existing ownership/source semantics tests |
| ZAP, Vulners Bridge | Scan creation, asynchronous progress/completion, failed targets and findings | `connector-scanner-saves`, existing bridge tests |
| Shared Vulners/threat enrichment | Finding provenance and scores; affected customers and KEV metadata, including empty findings | `connector-scanner-saves`, inventory/mutation scope tests |
| Defender | Existing SQL generation and explicit platform IDs retained; large publication, failure and restart | `defender-publication-persistence`, optional Defender DB suites, real platform PostgreSQL checks |
| CrowdStrike Spotlight | Direct SQL resume/promotion preserved | Existing resumable-import, source and reporting tests; provider transport mocked |
| Saved ES/CS tiles, SQL risk cache, ConnectWise | Existing dedicated writers preserved | Existing cache/risk/ticket tests plus real optional DB lifecycle checks; no external tickets sent |
| AppSec and disabled optional providers | Read/routing behavior preserved; disabled providers stay disabled | Existing routing/source checks; optional connectors exercised only with fixtures |
| Broad administration or unknown scope | Full comparison retained | Mutation fallback, full prepared-save and frozen-capture tests |

### Review decisions

- Keep full comparison when the changed-record list cannot be trusted. This preserves correctness but retains its CPU cost for those operations.
- Recalculate inventory-dependent risks across the imported customer's findings, including other finding sources. Shared threat refresh still owns changes that apply across customers.
- Retry completed but unimported Nessus results under the existing scan ID. Repeated unfinished scans stay on their existing polling path; successful retries clear obsolete errors.
- Freeze both full and scoped records before opening the database transaction. Mutations arriving afterward remain pending for the next save.
- No review findings were deferred. Production performance and the scheduled cycle are unverified release checks, not completed implementation tests.

> For agentic workers: use `superpowers:executing-plans` for task-by-task implementation, or `superpowers:subagent-driven-development` if parallel agent execution is explicitly selected. Re-read the actual branch and this plan before implementing; preserve the existing single-writer and mutation-capture contracts.

## Measured results and remaining limits - October 15, 2026

The reproducible [benchmark](../tests/connector-save-benchmark.mjs) used 100,000 synthetic findings plus 1,005 company, asset and scan rows, on Windows x64 / Node 24.18.0. Each case ran in a separate process. Both paths produced identical changed-row counts. These timings cover preparation only: full preparation includes reporting digests; scoped reporting is calculated from committed SQL buckets inside the transaction. They do not measure provider downloads or production page responsiveness.

| Workload | Full preparation | Scoped preparation | Payloads compared, full / scoped | Scoped index copy / record preparation |
| --- | ---: | ---: | ---: | ---: |
| One asset edit | 3,564 ms | 1 ms | 101,005 / 1 | 0 / 0 ms |
| One scan progress edit | 3,782 ms | 1 ms | 101,005 / 1 | 0 / 0 ms |
| 10 assets + 100 changed risk projections | 3,372 ms | 26 ms | 101,005 / 110 | 22 / 3 ms |
| 25,000 Nessus-shaped customer findings | 3,461 ms | 512 ms | 101,005 / 25,000 | 27 / 474 ms |
| 25,000 Defender-shaped customer findings | 4,256 ms | 645 ms | 101,005 / 25,000 | 46 / 577 ms |
| 25,000 unchanged customer findings | 4,009 ms | 661 ms | 101,005 / 25,000 | 38 / 602 ms |

[Raw measurements](evidence/connector-save-benchmark-20261015.json) include CPU time, heap change, peak process RSS and maximum sampled event-loop delay. Peak RSS includes constructing the fixture; heap changes include garbage-collection variation. These are single-run measurements, not performance guarantees.

In the isolated Linux PostgreSQL run, 30,001 synthetic new findings took **1,608 ms to prepare and 6,468 ms total**, including SQL writes, reporting publication and commit (about 4,860 ms after preparation). The run verified exact reporting digests and rollback after a real row write. An unchanged 31,403-record full save still took about 1,995 ms to prepare, demonstrating why unknown mutation paths retain a potentially expensive fallback.

Remaining costs: inventory risk recalculation can still inspect a whole affected customer; shared threat enrichment can affect all customers; copying a touched collection's hash index still depends on collection size; report bucket processing, downloads and genuine database outages are separate costs. No production latency improvement or next-day scheduled cycle has been claimed. Broad administrative operations retain full comparison. No database schema, provider credentials, schedules, tile intervals or ticket-creation workflow changed.
