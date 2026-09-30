# PostgreSQL Source-of-Truth Migration Plan

**Goal:** Replace Vuln's snapshot-backed in-memory core store with PostgreSQL as the authoritative store, while preserving customer reporting, connector imports, Atlas raw Spotlight records, review queue and ConnectWise tickets.

**Architecture:** Use `DATABASE_URL` for row-level core state. Keep existing `spotlight_import_*` and transactional dashboard/ticket tables in their verified current database. Introduce a repository boundary and versioned schema, migrate and compare data before a controlled one-way cutover, then retire the memory store. Use an explicit storage-mode gate with one writer owner at a time.

**Stack:** Next.js 16, TypeScript, `pg`, PostgreSQL 18 in the described deployment, PM2, Node test runner. No production credentials are required for local work.

**Design:** `docs/superpowers/specs/2026-09-29-postgres-source-of-truth-design.md`

## Phase 0: Production evidence and safety gate

**Deliverables:** `docs/db-migration-inventory.md` template and read-only inventory scripts. No live writes.

- [ ] Record the actual DB endpoints/databases used by `DATABASE_URL` and any dashboard URL without printing credentials. Confirm table ownership and migration privileges, Postgres version, free disk, connection limits, backup retention and the table location of `vuln_store`, Spotlight, jobs and tickets.
- [ ] Record whether App Platform and Droplet are both active, which process owns each scheduler, and whether an Atlas import or other connector run is active. Stop neither service merely to collect this inventory.
- [ ] Build a read-only snapshot inventory: collection counts, IDs, duplicate IDs, orphan references, max numeric suffix per ID prefix, per-company/connector/status/severity counts, `vuln_store` bucket count and snapshot timestamp. Read buckets one at a time.
- [ ] Verify a backup can be restored into an isolated database, including ticket and Spotlight tables. Record duration and restore size. A backup policy without a restore test does not satisfy this gate.
- [ ] Decide a short final write freeze window and the rollback owner; document exact service commands for this deployment only after confirming the real PM2/App Platform state.

## Phase 1: Schema and repository contracts

**Files:** Add `db/migrations/*`, `lib/db/*`; modify `lib/persist.ts` only to expose a safe shared pool/transaction helper, without changing legacy snapshot semantics. Add `tests/db-schema.test.mjs` and repository tests.

- [ ] Define a versioned migration runner with an advisory lock, `schema_migrations` table, fail-fast errors and a separate command from normal request handling. Run migrations against an empty disposable Postgres and an existing-schema fixture.
- [ ] Add core tables and indexes from the design. Preserve public IDs as text and allocate new suffixes transactionally. Add foreign keys only after the orphan inventory determines the safe migration order.
- [ ] Define async interfaces for company, folder, scan, finding, asset, control, identity, settings, scheduler state and aggregate/report queries. Keep domain types in `lib/types.ts`; separate pure risk/correlation logic from `StoreShape` plumbing.
- [ ] Add transaction and customer-scope tests, including concurrent ID generation and concurrent mutation of one finding. Verify `EXPLAIN` on company/status/risk pagination and key aggregate queries with a large generated fixture.
- [ ] Commit schema and repositories independently of API cutover. Legacy snapshot remains the production owner.

## Phase 2: Lossless snapshot import and parity

**Files:** Add `scripts/import-vuln-snapshot.*`, `scripts/compare-vuln-stores.*`, `lib/db/legacy-adapter.ts`; test with synthetic legacy snapshots, including older optional fields.

- [ ] Stream and validate each snapshot bucket into staging tables in bounded batches. Preserve raw entity JSON where needed and the exact public IDs, timestamps, company association, assignment, status, enrichment, scan references, identity links, settings and scheduler metadata.
- [ ] Store a migration run ID, source bucket key/hash, imported row count and completion marker. Retry or resume without duplicating rows; reject changed source buckets until a new consistent run begins.
- [ ] Build comparisons for exact IDs and key fields, company/connector/scan/status/severity counts, assets and aliases, plus report, risk, coverage and metrics outputs. Use a fixed snapshot revision for equality checks, because live writes otherwise create false mismatches.
- [ ] Test corrupt JSON, missing references, duplicate source IDs, interrupted batches and resume. Produce a redacted mismatch report and require zero unexplained differences before cutover.
- [ ] Backfill on a restored production copy, measure elapsed time, memory and DB growth, then repeat against production read-only snapshot data with the approved operational window.

## Phase 3: Convert core reads and writes by domain

**Files:** Split `lib/store.ts` into pure domain logic and async services in `lib/db/*`; update affected `app/api/*`, background jobs and tests. Use one implementation branch or PR per domain; each PR must include callers and contract tests.

1. **Companies, folders, settings, controls, aliases.** Convert synchronous exports and route callers to async. Ensure reporting selection still uses the app's `CO-*` companies. Preserve demo/internal classification and customer-scoped identity resolution.
2. **Assets and scans.** Persist scan state, external references, progress/checkpoints and inventory rows. Make scan actions and asset edits transactional. On restart, recover interrupted scans explicitly rather than advancing invisible in-memory timers.
3. **Normalized findings and connector imports.** Use stable source keys and bounded upserts; retain correlation policy and all user statuses/assignees. Separate scanner refresh fields from user-owned fields. Keep raw Atlas Spotlight rows in their existing table, retaining every CrowdStrike source ID.
4. **Aggregates, reports and queue.** Reimplement metrics, attack surface, priorities, compliance, SLA, executive report and reporting model with SQL-backed bounded queries. Preserve existing formulas with golden fixtures. Move `reporting-queue.ts` and ticket-preparation consumers to committed data; verify Atlas and non-Atlas customer switches, review queue, host/CVE scope, and ConnectWise duplicate protection.
5. **Schedulers and status.** Move scheduler metadata and job ownership to SQL. Use leases/advisory locks for connector/reporting/maintenance jobs. Health/status endpoints expose database availability, migration mode, import progress and worker owner without leaking credentials.

For each domain: write failing contract tests for current API output and mutation behavior; implement the SQL path; run targeted tests, typecheck and build; compare to the same frozen source fixture; deploy only when that domain has one authoritative writer. Do not keep a permanently divergent dual-write mode.

## Phase 4: Cutover rehearsal and production cutover

**Files:** Add `docs/postgres-cutover-runbook.md` with measured timings and rollback commands. Add restart/interruption tests and an end-to-end smoke script using test credentials/fixtures.

- [ ] Rehearse on a restored database with production-scale data. Prove query latency, bounded Node heap, exact counts, one worker owner, Atlas active generation continuity and ticket/review state continuity.
- [ ] On the production window, quiesce old App Platform and Droplet writers/schedulers, let active imports finish or checkpoint, flush the old snapshot, take a final backup and import final changes. Confirm no competing writer is active.
- [ ] Verify exact collection counts/checksums and representative IDs, Atlas raw-source count, company-specific reports, pending review queue, ticket tracking, scan actions and one safe connector import.
- [ ] Switch the Droplet to SQL mode, leaving legacy snapshot writes disabled. Restart PM2 and verify an acknowledged edit is present after another restart. Enable exactly one scheduler owner only after smoke checks.
- [ ] If any gate fails before SQL writes, restore the old service/snapshot. After SQL writes begin, roll back code against the SQL schema or use a tested reverse-migration tool; never blindly re-enable the old snapshot writer.

## Phase 5: Retirement and operations

- [ ] Remove full-store hydration, snapshot flusher, global mutable Maps and emergency seeded production fallback. Keep legacy snapshot tables read-only through a defined retention period.
- [ ] Monitor DB connections, slow queries, storage growth, vacuum/index health, import-run age, job lease age, failed transactions, and report/ticket consistency. Set alerts based on measured normal values.
- [ ] Document backup/restore, migrations, worker ownership, import recovery and deployment order. Test a clean Droplet rebuild from code, configuration and Postgres alone.

## Non-negotiable release gates

- No acknowledged write can disappear on process restart.
- No production read of core state depends on a complete JS Map or the `vuln_store` snapshot after cutover.
- No partial connector run appears complete; retries are idempotent and user edits survive refresh.
- Every selected customer reports from its own committed data; Atlas raw Spotlight source count and normalized finding count remain distinct.
- Existing review and ConnectWise ticket flows, uniqueness rules and audits pass their regression suite.
- A production backup restore, parity report, cutover rehearsal and post-restart smoke test are documented with actual results before decommissioning the old writer.

## First implementation branch

Start with Phase 0 and Phase 1 only: inventory tooling, schema migrations and repository contracts. That branch must not change the reporting page, switch production reads/writes, or run destructive migrations. Later phases should be separate reviewable PRs, because the `lib/store.ts` synchronous API has many consumers and the production service currently holds active connector data.
