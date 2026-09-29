# PostgreSQL as Vuln's Source of Truth

## Decision

Move the core application state from `globalThis.__vulnStore` and debounced `vuln_store` snapshots to transactional PostgreSQL rows behind `DATABASE_URL`. The Droplet remains compute; PostgreSQL owns durable application state. An in-process cache may later accelerate immutable or bounded reads, but it must never decide the authoritative value or acknowledge a write before commit.

Use an incremental migration with one owner for each collection at every stage. Do not make two processes write the same snapshot, and do not present a partially migrated collection as complete. This is a change to the storage contract, not a visual redesign.

## Verified current state in the repository

- `lib/store.ts` owns Maps for companies, folders, scans, findings, assets, compensating controls, identity aliases, plus settings, scheduler metadata and a shared ID counter. Most exported reads and mutations are synchronous. `listFindings` sorts the complete in-memory collection; reporting and metrics also traverse complete Maps.
- `ensureHydrated()` loads the full snapshot once, then a debounced flusher serializes the store. `lib/persist.ts` saves hash-bucket JSONB rows in `vuln_store`, plus legacy `vuln_snapshot`; this is persistence of the memory store, not row-level ownership.
- `lib/reporting-store.ts` still derives customer reporting from `getCompany`, `listFindings`, `listScans`, `listAssets`, and `computeExecReport`. The reporting review queue also reads core findings while storing its own run and ticket state in SQL.
- `lib/spotlight-record-store.ts` already stores Atlas source records in `spotlight_import_*` tables through `DATABASE_URL`. These rows retain individual CrowdStrike IDs and are separate from the normalized scanner findings. Keep that separation and preserve the completed-run pointer.
- The dashboard, consolidation queue, ConnectWise ticket requests, audits and jobs already use relational tables. Their data and workflows must survive this migration. They may use `ELASTIC_VULN_DATABASE_URL` when configured; do not force a new dashboard connection or silently move those tables between databases. Inventory the actual production URLs and table locations before any data migration.
- `instrumentation.ts` starts several background workers. `VULN_DISABLE_SCHEDULER` gates recurring jobs but startup backfills have their own behavior. A PM2 single process alone does not prevent an old App Platform instance from running concurrently.

## Target boundaries

| Domain | Authority after migration | Notes |
| --- | --- | --- |
| Companies and folders | PostgreSQL rows | Preserve `CO-*` and `FLD-*` IDs, company kind, demo filtering and reporting selection. |
| Scans and connector runs | PostgreSQL rows | Status, progress, source references, run metadata and retries survive process restarts. |
| Normalized findings | PostgreSQL rows | Preserve one normalized finding's current correlation semantics, status/assignee, risk fields, provenance and `VLN-*`/`FIND-*` IDs. This is distinct from every raw Spotlight source record. |
| Asset inventory and identity links | PostgreSQL rows | Keep customer-scoped identity and risk context; no cross-company matching. |
| Controls, settings and scheduler metadata | PostgreSQL rows | Use transactions and explicit singleton/lease records where appropriate. |
| Atlas raw Spotlight | Existing `spotlight_import_*` SQL tables | Preserve every source ID and completed generation; add indexes/read paths only when a consumer requires them. |
| Dashboard, review queue, ticket requests and audit | Existing SQL tables | Preserve IDs, state machines, uniqueness constraints, routing, attachments and audit trail. |
| Trend history | Existing `vuln_metrics_history` until read migration | Calculate from committed data; retain history. |

Do not duplicate millions of raw Spotlight records into normalized findings just to make them visible to reporting. Define any needed Atlas report projection explicitly, with source counts and normalization counts shown separately.

## Storage model

Create versioned SQL migrations, not runtime DDL hidden in request paths. Start with tables for `app_companies`, `app_folders`, `app_scans`, `app_findings`, `app_assets`, `app_compensating_controls`, `app_identity_aliases`, `app_settings`, `app_scheduler_state`, `app_id_sequences`, and `app_migration_state` (names can change in a reviewed migration). Keep typed, indexed columns for customer ID, status, severity, source, scan ID, external reference, CVE, asset key, risk sort, and time filters. Use JSONB only for connector-specific or evolving payload fields that do not need core filtering; retain the complete legacy object during initial migration if needed for lossless backfill. Foreign keys and unique constraints must match the current behavior, including safe handling of legacy inconsistent references.

Every write should commit within a bounded transaction and return only after commit. Use sequence allocation or database-generated IDs while preserving the existing public ID format. Mutations affecting a finding and its scan count, asset linkage, or audit record belong in one transaction. Connector imports should use bounded batches and stable source keys, with an import-run generation or checkpoint. A failed run must not make a partially imported replacement appear complete. User edits to finding status/assignee must not be overwritten by later connector refreshes.

Serve large collections with SQL filters, cursor pagination and aggregate queries. Customer and scan scope must be applied in SQL. Avoid loading all findings or Spotlight rows to compute a count, a table, a chart, or a ticket preview. Keep the current API fields stable where feasible; introduce paged endpoints or explicit summary/detail contracts where the old endpoint returns unbounded arrays. Existing metrics and report formulas must be characterized with fixtures before replacing in-memory loops with SQL.

## Migration and cutover

1. **Freeze and inventory.** Confirm the active production database URLs, connected roles, table owners, current schema, row counts, snapshot timestamp, running services and current Atlas import state. A description of the deployment is not proof of the live database layout. Capture a restorable Postgres backup and perform a restore drill in isolation. Record checksums/counts of each snapshot collection and Spotlight's active generation.
2. **Schema and read-only backfill.** Add versioned tables and an idempotent, resumable importer from `vuln_store`/`vuln_snapshot`. Import by bucket in bounded transactions, recording bucket checksum, row count and completion. Preserve IDs and all fields. Never infer success from a partially loaded bucket. No new tables serve production reads yet.
3. **Shadow verification.** Compare new SQL results to the live snapshot for counts by company, connector, scan, status and severity; sample exact records, risk calculations, report aggregates, asset coverage and identity links. Separate legitimate ongoing writes from mismatch by comparing a fixed snapshot revision or briefly pausing mutations for final reconciliation. Store mismatch reports without sensitive raw payloads.
4. **One-way cutover.** Stop the old App Platform writers and all relevant schedulers/imports, wait for Atlas and other active imports to finish or mark them resumable, flush and freeze the legacy store, take a final backup, apply the final delta and verify it. Switch the Droplet to SQL authority with an explicit feature flag/schema version. Do not enable legacy snapshot flushing in SQL mode. Start one worker owner after read/write smoke tests. If the old service must remain online as a rollback target, it must be read-only while SQL mode accepts writes.
5. **Rollback.** Before new SQL writes, the old snapshot can be restored. After new SQL writes, switching back to the old snapshot would discard data; rollback must either replay those writes into the legacy format with a tested tool or restore the SQL-backed app release. Prefer rolling back code while keeping SQL as authority once the cutover commits. Keep the snapshot frozen for audit until a defined retention date.
6. **Retire.** Remove hydration, global mutable Maps, snapshot flusher and legacy writes only after parity, restart and failure tests pass. Keep a read-only export/restore utility for a limited period. Do not delete `vuln_store` or `vuln_snapshot` in the first release.

The final operational path is browser → Nginx → Next.js under PM2 → `DATABASE_URL`, with connectors as outbound clients and relational jobs/tickets retained. A single PM2 process is fine initially; any future extra process needs database-backed worker claims or leases so it cannot duplicate a sync, report, backfill or ticket action.

## Required invariants and acceptance

- Restarting or replacing Node cannot lose an acknowledged company, scan, finding, asset, setting, review decision or ticket state.
- Database unavailability fails relevant reads/writes visibly; it never serves a seeded empty store as if it were production and never accepts a write that will only be flushed later.
- At least Atlas's active 2 million-plus raw Spotlight records remain individually addressable by source ID; the normalized finding count is not used as proof of raw-record completeness.
- Customer selection and reporting are driven by the selected `CO-*` company, with Atlas-specific sources and other customers' available connectors. Existing review queue and ConnectWise ticket cutting remain functional.
- Import replay, process interruption and concurrent trigger cannot duplicate records, regress customer edits or expose incomplete generations.
- The production cutover includes matched counts/checksums, bounded query plans for high-volume endpoints, a tested backup/restore path, and a documented rollback point.

## Scope and open decisions

This branch delivers a design and executable plan only. It must not change production schema, data, services, reporting UI or ticket behavior. The first implementation branch should build the migration foundation and read-only parity tooling. Production cutover is a later gated release, after live DB inventory and the currently running Atlas sync have completed or been safely checkpointed.

Before the cutover, confirm whether dashboard/ticket tables are in the same physical database as `DATABASE_URL` or in a separate database selected by `ELASTIC_VULN_DATABASE_URL`; the code supports separate connections. Also record the exact connector source-key rules and report formulas from production fixtures before choosing final unique indexes or SQL aggregation logic.
