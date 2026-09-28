# Atlas Spotlight Record Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collect and retain every Atlas Spotlight source record without loading the complete tenant result into Node memory or changing reporting and tickets.

**Architecture:** Stream bounded CrowdStrike pages into transactional Postgres generations keyed by tenant and source vulnerability ID. Promote a generation only after the Atlas tenant finishes; a failed or interrupted run leaves the previous completed generation intact. Keep the current in-memory scanner store, reporting page, and ConnectWise pipeline as they are.

**Tech Stack:** Next.js 16, TypeScript, `pg`, Node test runner, PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-09-28-uncapped-spotlight-records-design.md`

## Global Constraints

- Preserve each CrowdStrike vulnerability ID as a separate row, even when host and CVE match.
- Select Atlas through its configured customer binding; do not query the unnamed primary tenant.
- Do not reintroduce an item or page cap or materialize all Atlas records in JS memory.
- Use `ELASTIC_VULN_DATABASE_URL` for record storage; leave `DATABASE_URL` snapshot content unchanged.
- Keep the previous completed generation visible throughout an interrupted or failed run.
- Do not change the reporting page, reporting calculations, ticket review, ConnectWise pipeline, connector page, or other scanner behavior.
- Local tests cannot depend on production credentials.

## Review Focus

- Missing source ID: reject the batch visibly instead of silently dropping or merging a record (Task 1 test).
- Same host/CVE with two source IDs: store two rows (Task 2 test).
- Atlas credentials move to another numbered slot: select by customer binding, never by slot (Task 3 test).
- No completed run yet: a partial first import does not become visible as complete (Task 2 test).
- Process fails after a stored batch: retry does not duplicate rows or hide the old completed run (Tasks 2 and 3 tests).

---

### Task 1: Preserve Source Identity and Stream Pages

**Files:** Modify `lib/crowdstrike.ts`; test `tests/crowdstrike-sync-resilience.test.mjs`.

**Interfaces:** Produce `spotlightFindingBatches(config: FalconTenant): AsyncGenerator<SpotlightFinding[]>`, where `SpotlightFinding` has required `id: string` and each yielded batch contains at most eight hydrated query pages. Keep `spotlightListFindings` as a compatibility collector while the importer is migrated.

- [ ] Add a failing test with two distinct IDs on one host/CVE and more than 80,000 mock query results; assert every ID is yielded once and no yield exceeds 3,200 records.
- [ ] Add a failing test for a hydrated record with no ID; assert an explicit source-identity error.
- [ ] Implement the generator using the current cursor checks and eight-page hydration concurrency; have the compatibility collector consume it.
- [ ] Run `node --experimental-vm-modules tests/crowdstrike-sync-resilience.test.mjs`; expect all tests to pass.
- [ ] Commit the adapter change.

### Task 2: Transactional Atlas Record Generations

**Files:** Create `lib/spotlight-record-store.ts`; modify `lib/elastic-dashboard-store.ts` only as needed to reuse its Postgres pool; test `tests/spotlight-record-store.test.mjs`.

**Interfaces:** Produce `beginSpotlightRun(tenantKey: string): Promise<string>`, `writeSpotlightBatch(runId: string, tenantKey: string, rows: SpotlightRecord[]): Promise<number>`, `completeSpotlightRun(runId: string, tenantKey: string): Promise<void>`, `failSpotlightRun(runId: string, error: string): Promise<void>`, `countCompletedSpotlightRecords(tenantKey: string): Promise<number>`, and a bounded internal `listCompletedSpotlightRecords` method. `SpotlightRecord` includes source ID, tenant key, Atlas company ID, host/IP/CVE/severity/status, description/remediation, and observed timestamp. A unique `(run_id, tenant_key, source_id)` constraint makes replay idempotent.

- [ ] Add failing disposable-Postgres tests for same host/CVE with distinct IDs, duplicate batch replay, and exclusion of an incomplete first run from completed reads.
- [ ] Add a failing test for promotion and for preserving the previous generation after failure.
- [ ] Implement the tables and indexes, bounded writes, completed-run pointer, and read/count methods. Validate every source ID before writing.
- [ ] Run the database tests against disposable Postgres; expect pass. If unavailable locally, keep tests runnable and record the missing gate for deployment.
- [ ] Commit the storage change.

### Task 3: Atlas-Only Background Import

**Files:** Modify `lib/store.ts` and `app/api/crowdstrike/spotlight-import/route.ts`; test `tests/spotlight-import.test.mjs`.

**Interfaces:** `importFromCrowdstrikeSpotlight` consumes Task 1's generator and Task 2's write methods. Extend the existing `CsSyncStatus` with `tenant`, `fetched`, and `stored` counters. An empty-body POST selects the sole named customer tenant (Atlas in the current configuration), never the unnamed primary tenant. If more than one named tenant exists, require `companyId` in the POST body and match it to exactly one configured customer. Do not add raw Spotlight rows to `s.findings` or snapshot scan rows.

- [ ] Add a failing test that multiple batches reach storage, progress advances, and status GET can answer between batches.
- [ ] Add a failing test that an Atlas run never calls the primary tenant and still selects Atlas after credential slot order changes.
- [ ] Add a failing test for a failed batch leaving the old completed generation in place, followed by a safe retry.
- [ ] Implement tenant selection, bounded batch writes, event-loop yields, and explicit error/progress state. Keep the connector page unchanged.
- [ ] Run the focused import/adapter tests and `npx tsc --noEmit`; expect pass.
- [ ] Commit the import change.

### Task 4: Scale and Deployment Gate

**Files:** Create `docs/spotlight-storage-release-gate.md`; add a scale fixture to `tests/spotlight-import.test.mjs`.

- [ ] Run a generated fixture above 80,000 records with repeated host/CVE pairs; assert exact source-row count, bounded batch size, and responsive status checks.
- [ ] Run `npm run build` and all relevant tests; record pass/fail and any missing local Postgres gate.
- [ ] Document table sizing, indexes, previous-generation retention/pruning, backup, and rollout checks. A completed Atlas run must match a same-run CrowdStrike query total; missing IDs or incomplete hydration fail the run rather than producing a smaller completed count. Confirm the primary tenant was not queried.
- [ ] Deploy through the selected branch workflow and verify the completed Atlas count before calling the uncapped data collection fixed. Do not alter reporting or ticket views as part of this gate.
- [ ] Commit the release documentation and deployed revision.
