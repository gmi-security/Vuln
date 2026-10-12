# Platform database authority and recovery

This is the combined-release write path. It is not enabled in production. The standalone Defender shadow/handoff experiments remain inactive; they are not another writer.

## What changes

The current application serializes its normalized companies, folders, scans, findings and assets into 91 JSON buckets in `vuln_store`. After an explicit maintenance transition, those same records live in `app_companies`, `app_folders`, `app_scans`, `app_findings` and `app_assets`. Indexed common columns support customer queries; the JSON payload preserves each provider's additional fields. Record identity, counting, correlation, scores, remediation text and source evidence are unchanged.

Settings, counters, aliases, compensating controls, publication markers and other small snapshot metadata remain together in `app_store_metadata`. Existing raw imports, dashboard tiles, source connections, daily history, threat enrichment and ConnectWise ticket/audit tables stay in their existing database tables. This is one application database, not a database per customer or a second raw-source copy.

The report worker reads the selected authority. In SQL mode it pages through that customer's indexed records. The Overview and executive report continue using the tested saved reports. Other established consumers initially hydrate a RAM compatibility cache from SQL on startup. This release does **not** claim that every page has been rewritten into a paginated SQL query or that RAM hydration has disappeared.

## Durable writes

- `app_store_authority` selects `legacy` or `sql`, with a global epoch and revision. The whole shared snapshot changes ownership together; customers cannot have competing writers.
- The writer loads a committed generation. Each later transaction must present that generation's epoch/revision. Database triggers reject an old process or writes to the inactive storage path.
- Explicit analyst mutation scopes compare only named records; unscoped imports and complex operations retain a full comparison. A single changed finding writes one row. Inserts, updates, deletions, metadata and report input revisions commit together.
- A capture changed during preparation is rolled back and retried up to three times. Persistent contention returns an error; it does not acknowledge an unverified generation.
- Successful core mutation responses wait for database confirmation in SQL mode. Source imports that call `flushNow` also receive save failures. Accepted background work is still an acceptance response, not a claim that its import completed.
- A failed SQL save blocks further cache reads and writes until restart/recovery. This avoids presenting unsaved RAM as committed data. Check external scan/ticket/email status before retrying an action; a database rollback cannot undo an external side effect.

There remains one application writer. This change does not make the old RAM business logic safe for multiple active web replicas. Persistence state, the pool and the loaded writer revision are process-global so Next.js route bundles share the same committed state. A changed database URL requires process restart. Each SQL save has a five-minute overall deadline as well as statement/lock limits; an uncertain failed save is never acknowledged as success.

Full-cache comparison still occurs for unscoped imports and complex mutations. Compatibility-page reads wait for pending saves, so a large publication can delay those pages. Saved SQL reporting bypasses that path. The retained RAM cache and full-comparison fallback are explicit release boundaries, not a claim that every consumer has become a direct SQL reader.

## Maintenance sequence

Run this sequence only for the concrete reviewed release. The candidate must build and pass the release checks **before stopping the running application**.

1. Reconcile the exact production commit and server-local changes. Keep a compatible rollback build and preserve the running PM2 configuration/environment privately. Do not reset over unreviewed server changes.
2. Put the site into maintenance and stop admitting mutations. Stop/drain **all** web writers, source import workers, risk jobs, independent scanner/export schedulers and the report worker. `VULN_DISABLE_SCHEDULER=true` alone is not sufficient. Confirm durable source checkpoints and no unfinished external ticket creation.
3. Capture and restore-test a fresh recovery baseline using `prepare-recovery-baseline.cjs` and `verify-recovery-baseline.cjs`. Preserve the current source and ticket databases; reinstalling connectors or rerunning ingestion is not a substitute for a backup.
4. Inspect `node scripts/install-platform-release-schema.mjs --plan`, then install the explicit reviewed release with `--apply --writers-stopped --env-file PATH`. It installs the connector/reporting/source-summary migration manifest with a checksum ledger and runs the versioned core migrations. It does not install the experimental Defender shadow schemas. Existing untracked/conflicting schemas stop installation for reconciliation. The authority schema starts in legacy mode without enforcement. Do not start the app between installation and the reviewed decision to transition or remain legacy.
5. With the existing environment loaded securely, inspect:

   ```bash
   node scripts/platform-store-transition.mjs --status
   ```

6. Substitute the **observed** epoch/revision into:

   ```bash
   node scripts/platform-store-transition.mjs --to-sql --writers-stopped --expect-epoch EPOCH --expect-revision REVISION
   ```

   This is one transaction. It validates all 91 legacy buckets, copies every record, compares every copied payload and its order, publishes report input revisions and changes authority. A failure rolls it all back. The legacy buckets remain as a frozen baseline; they are no longer current after new SQL edits.

7. Set `VULN_PLATFORM_STORE=sql` for the compatible application. Start the single application writer with the reviewed connector/scheduler flags. The program refuses to boot from the old buckets when the database says SQL is authoritative.
8. Start the report worker with its matching reviewed customer list, wait for fresh reports, then verify health, customer counts, CVE/patch preparation, saved tiles and a reversible analyst edit. Resume approved jobs deliberately and remove maintenance only after acceptance.

The migration CLI does not itself stop PM2 or prevent outside tickets/scans. `--writers-stopped` is an explicit operator assertion; the epoch fence is the additional consistency protection. Its output contains counts and revisions, not credentials or host details.

## Reverse recovery without losing newer edits

Rolling back Git alone after SQL cutover is unsafe: the legacy buckets are frozen. Use the compatible candidate's reverse command first.

1. Enter maintenance, drain/stop the same writers and preserve a fresh recovery point.
2. Run `--status`, then the exact current revision:

   ```bash
   node scripts/platform-store-transition.mjs --to-legacy --writers-stopped --expect-epoch EPOCH --expect-revision REVISION
   ```

3. The transaction checks every SQL payload hash, recreates all legacy buckets from the **current** SQL rows and metadata, republishes reporting revisions, then changes authority and epoch. Post-cutover inserts, edits and deletions are included. It retains the SQL tables and commit audit.
4. Set `VULN_PLATFORM_STORE=legacy` and start a **compatible fenced build**. Older builds without the authority protocol are deliberately blocked from overwriting the recovered snapshot. Do not drop the fence or restore the original frozen buckets merely to start an older binary.
5. Verify customer/workflow counts and reconcile external operations before resuming work.

## Validation status

Fourteen isolated PostgreSQL groups verify interrupted backfill, full payload preservation across eight source types, stale/old-writer rejection, atomic save failure, changed-row counts, no-op saves, concurrent MVCC reads and reverse recovery including new edits. They invoke the actual persistence implementation for SQL hydration, separately bundled modules, restart, report revision publication and rejection of a legacy-mode boot.

The retained-data rehearsal verified all 510,945 findings, 14,983 assets, 385 scans, 64 folders and 41 customer records (40 retained plus one empty fixture). Forward migration took 185.5 seconds; reverse migration took 103.4 seconds and restored all 91 legacy bucket checksums. Runtime hydration took 44.1 seconds; an unchanged scoped save took 63 ms and a one-row edit 1.6 seconds, with 1.5 GiB peak RSS in the isolated persistence process. This is not the full web process's memory footprint. The 41-customer worker cycle took 47.7 seconds at 258 MiB RSS. Complete retained Footprint/Atlas Overview, executive and history output matched the legacy calculations.

The built Linux application's HTTP rehearsal passed SQL report reads, an actual analyst PATCH, stale-report withholding, worker refresh, application restart and reverse-to-legacy restart while preserving the new edit. The network guard permitted only the private PostgreSQL socket; no real provider or ticket request was available. Source identities/reviews in this test were synthetic and do not approve production customers.

The combined release still requires live source assignments, the unavailable-service decision and the runtime/maintenance review. See [the release checklist and operator sequence](vuln2-combined-release.md).
