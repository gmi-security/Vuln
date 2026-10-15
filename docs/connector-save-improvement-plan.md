# Connector save improvement plan

**Status:** Approved for implementation on October 15, 2026. Work is on `perf/connector-scoped-saves`; production remains unchanged pending validation and release.

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

- [ ] Add tests with two customers and overlapping host/vendor IDs. Assert that an inventory import preserves ownership, source observations, aliases and affected finding scores while leaving the other customer unchanged.
- [ ] Track asset candidates throughout each inventory path. Restrict risk recalculation to affected assets when the dependency is known; use the affected customer's complete finding set when an alias or customer-wide dependency makes a narrower set unsafe.
- [ ] Avoid marking findings whose persisted score fields did not change. Preserve real observation timestamps and all existing risk calculations.
- [ ] Verify both reviewed routing and supported legacy routing paths. Missing scope must not silently skip required work.
- [ ] Compare old and new resulting records, run the relevant tests, then commit.

**Done when:** inventory saves no longer trigger full comparison through these paths, and scores match the original behavior for every affected finding.

### Task 3: Convert the complete Nessus import lifecycle

**Files:** `lib/store.ts` (`importVendorFindings`, `importFromNessus`, `closeStaleFindings`, polling/completion and resync paths); extend `tests/finding-correlation.test.mjs`, `tests/connector-import-result.test.mjs` and the new scope tests.

- [ ] Add tests for new, changed, duplicate and reopened findings; stale closure; unchanged scans; partial failure; new-scan creation; and mutations arriving while a provider request is awaited.
- [ ] Replace full dirty markers only after the complete findings/assets/scans/folders/metadata mutation set is known. Preserve the recent correlation lookup optimization.
- [ ] Keep imported timestamps and completion markers consistent with the rows they describe. A saved completion marker must never acknowledge omitted finding changes.
- [ ] Compare committed results and restarted state with the original path; run the Nessus and persistence tests, then commit.

**Done when:** both new scans and existing scan updates save complete results through scoped writes, with no regression in progress polling or closure behavior.

### Task 4: Convert remaining shared-store scanners and enrichment

**Files:** importer functions in `lib/store.ts` for SpiderFoot, Artemis, Vulners Bridge, ZAP, Burp, Nmap, Vulners enrichment and `enrichThreatIntel`; extend `tests/connector-import-ownership.test.mjs`, `tests/source-platform-semantics.test.mjs` and the scope tests.

- [ ] Add a fixture for each path covering success, repeat import, partial provider failure and restart. Include asynchronous scanner callbacks and upload routes.
- [ ] Declare all modified IDs and metadata. Keep scanner-specific rules for finding identity, suppression and closure.
- [ ] For shared CVE enrichment, update every affected customer finding when required. A CVE can be shared across customers even though individual findings remain customer-owned.
- [ ] Run each connector's behavior checks against the prior output and commit the verified group.

**Done when:** every listed shared-store path has a tested scope or an explicitly documented full-save reason. Disabled providers are covered by fixtures and remain disabled.

### Task 5: Verify large scoped saves and existing direct SQL paths

**Files:** `lib/db/platform-store.mjs`, `lib/persist.ts`, `lib/db/customer-reporting-revisions.mjs`; tests in `tests/platform-bulk-save.test.mjs`, `tests/platform-store-postgres.mjs`, `tests/defender-publication-persistence.test.mjs`, `tests/spotlight-resumable-import.test.mjs` and `tests/reporting-inputs.test.mjs`.

- [ ] Test small edits and large customer publications with many unrelated platform records. Measure candidate serialization, map/index copying, reporting work, transaction duration and peak memory separately.
- [ ] Preserve the existing direct SQL generation/cache/ticket writers. Test Defender publication, Spotlight resume/promotion, tile results and ticket references through restart; use mocked provider transport for external actions.
- [ ] Verify that only affected reporting inputs change. Follow the existing reporting bucket/revision contract; do not force all customer summaries to rebuild.
- [ ] If the large scoped path still spends substantial preparation time inside a transaction, extend the existing prepared-save mechanism to scoped captures before releasing that path. Freeze rows and metadata before SQL, recheck authority, and retain later mutations for the next save. Do not remove capture guards from live values.
- [ ] Run real PostgreSQL rollback, stale-writer and restart tests in a disposable test database, then commit any required writer adjustment.

**Done when:** large scoped saves cannot recreate the long idle-transaction failure, and all paths retain identical committed data and reporting revisions.

The current delta writer still copies collection maps and examines index entries. Tracking IDs reduces payload comparison, but does not automatically make every part of a save proportional to the number of changed rows. Measure these costs before proposing further indexes or abstractions.

### Task 6: Compare performance and prepare the release

- [ ] Run old and new implementations against the same representative data: one asset edit, one scan-progress edit, a small inventory change, a full customer Nessus import, a large Defender publication and overlapping mutations.
- [ ] Record provider time separately from application preparation and SQL time. Record rows considered/compared/written, retries, memory, event-loop delay and page/API response times during the workload.
- [ ] Run the complete test suite, real PostgreSQL checks, TypeScript validation, both worker builds and a Linux production build. Record optional/skipped checks separately from passes.
- [ ] Open the reviewed PR with the connector coverage matrix and before/after measurements. Build the merged version before stopping the running service.
- [ ] At the authorized deployment, drain or safely stop active imports and preserve durable resume state. Restart with existing configuration, then verify health, a real successful scoped commit, customer totals, reporting and ticket references.
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

Run the focused tests as each stage is built, followed by the broad checks below. These commands are instructions for implementation; they were not run to claim this proposal is complete.

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

- [x] Trace connector save paths and identify shared full-comparison callers.
- [x] Document the proposed approach, justification, risk checks and rollout order.
- [ ] Implement and verify stages 1 through 6.

Stage 1 is implemented and verified locally: 957 tests passed, seven optional database checks skipped, and TypeScript passed. Shared helpers now declare asset/finding IDs, alias metadata and closures; save diagnostics report candidate and comparison counts. The next step is **stage 2: inventory imports and narrow rescoring**. Production remains unchanged; real PostgreSQL and release checks are still pending.

> For agentic workers: use `superpowers:executing-plans` for task-by-task implementation, or `superpowers:subagent-driven-development` if parallel agent execution is explicitly selected. Re-read the actual branch and this plan before implementing; preserve the existing single-writer and mutation-capture contracts.
