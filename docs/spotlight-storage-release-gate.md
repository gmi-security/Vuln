# Atlas Spotlight storage rollout

## Scope and prerequisites

This change stores each Atlas CrowdStrike Spotlight vulnerability ID as a separate row in the existing app Postgres database configured by `DATABASE_URL`. It does not change the reporting page, the existing in-memory scan and finding counts, or ticket cutting. The unnamed primary CrowdStrike tenant is excluded from this import. The Atlas customer name configured in `FALCON_CUSTOMER_N` must match the existing Atlas company (`CO-147284`).

The reported DigitalOcean database allocation is 16 GB RAM, 6 vCPU, and 300 GiB disk. That allocation is not a measured free-space value. Check actual free space, backups, and current database size before the first full import. Snapshot writes and the Spotlight import now share this database and its connection pool. A full generation and the previous completed generation coexist during refresh, so allow for at least two generations plus WAL, indexes, and vacuum headroom. Do not infer row size from the allocation; measure it after an initial batch and project the full size.

## Local verification

Run `node --experimental-vm-modules tests/crowdstrike-sync-resilience.test.mjs`, `node --experimental-vm-modules tests/spotlight-record-store.test.mjs`, `node --experimental-vm-modules tests/spotlight-import.test.mjs`, `npx tsc --noEmit`, and `npm run build`. The local database tests mock `pg` and verify SQL calls and transaction order; they cannot prove PostgreSQL execution because no disposable database or credentials are available locally. Run the database statements against a disposable Postgres instance before production rollout if one is available.

## First run

1. Remove the temporary `ELASTIC_VULN_DATABASE_URL` setting, deploy this storage change, and confirm the existing `DATABASE_URL` snapshot connection is healthy. The app must still have one instance. This change adds Spotlight tables beside the snapshot tables; it does not add records to `vuln_store`.
2. Check the Atlas debug count. Capture the query time and `spotlightFindingsAvailable`; it is a moving CrowdStrike count, so a later value may legitimately differ.
3. Trigger the existing Spotlight import action. The empty-body POST selects the sole named tenant; when multiple named tenants are configured, send `{ "companyId": "CO-147284" }` to `/api/crowdstrike/spotlight-import`.
4. Poll the Spotlight status. Confirm `tenant` is Atlas, `fetched` and `stored` advance, and the run ends with `phase: "Done"`, no error, and `findingsImported` matching the promoted database count. The import must not request the primary tenant. A hydration ID mismatch, incomplete page, or stored ID shortfall fails the run and keeps the previous completed generation.
5. Compare the completed count to a new bounded CrowdStrike count probe, allowing for records that opened or closed during the import. If the difference is material, investigate query timing and run completeness before treating the import as verified.

## Database checks

Use a read-only SQL session on the database behind `DATABASE_URL`:

```sql
SELECT r.id, r.status, r.started_at, r.finished_at,
       (SELECT COUNT(*) FROM spotlight_import_records v WHERE v.run_id = r.id) AS records
FROM spotlight_import_runs r
WHERE r.tenant_key = 'CO-147284'
ORDER BY r.started_at DESC LIMIT 5;

SELECT c.tenant_key, c.run_id, COUNT(v.source_id) AS completed_records
FROM spotlight_import_current c
JOIN spotlight_import_records v ON v.run_id = c.run_id AND v.tenant_key = c.tenant_key
WHERE c.tenant_key = 'CO-147284'
GROUP BY c.tenant_key, c.run_id;

SELECT pg_size_pretty(pg_total_relation_size('spotlight_import_records')) AS records_with_index,
       pg_size_pretty(pg_database_size(current_database())) AS database_size;

SELECT source_id, hostname, cve, raw
FROM spotlight_import_records
WHERE run_id = (SELECT run_id FROM spotlight_import_current WHERE tenant_key = 'CO-147284')
  AND tenant_key = 'CO-147284'
ORDER BY source_id LIMIT 5;
```

The primary key is `(run_id, tenant_key, source_id)`. The run ID prefix supports generation counts and batched cleanup; the stored host, CVE, severity, status, and raw JSON are for future read paths. There is no host/CVE index yet because this phase does not query by those fields. Add indexes with a measured future query need, accounting for their disk cost.

## Failure and recovery

A failed or interrupted run cannot move `spotlight_import_current`. The original importer started a replacement run and deleted old, noncurrent generations in 10,000-row chunks. The resumable behavior below supersedes that retry path: it keeps a version-2 partial generation and delays old-generation cleanup until after promotion. Keep normal DigitalOcean Postgres backups enabled. If storage pressure rises, stop new imports and inspect generation sizes before retrying; do not manually delete the current generation.

The old 80,000-row Atlas scan in the main in-memory store remains as it was. This release verifies durable source-record collection only. Reporting and ticket behavior require a separate, explicitly scoped migration to read these records.

## Resumable import rollout (2026-09-29 branch)

The new importer has two durable phases. It commits each Spotlight ID page with its continuation cursor to `spotlight_import_ids`, then hydrates that saved ID set into `spotlight_import_records` in batches. Each hydrated batch and the last processed ID commit together. A repeated POST resumes a failed or interrupted version-2 run at its saved phase. The previous active generation remains visible until exact ID and record counts match and the active pointer moves in one transaction. A PostgreSQL advisory lock prevents two web workers from importing the same tenant at once.

Before deploying this schema change, verify a restorable managed-Postgres backup and exercise the additive table/column changes against an isolated restore. The existing failed Atlas attempts are version-1 runs and have no durable discovery checkpoint, so the first version-2 POST starts a new run. Subsequent version-2 interruptions preserve completed ID pages and hydrated record batches. If CrowdStrike rejects a saved discovery cursor, that ID-only phase restarts in a new run; a completed discovery set does not depend on a CrowdStrike cursor during hydration. Do not run the unrelated core `app_*` migration merely to test Spotlight recovery.

After the new code is deployed, use the existing Atlas POST once. Poll `GET /api/crowdstrike/spotlight-import` or `GET /api/crowdstrike/debug`: `Discovering` counts staged IDs, `Hydrating` counts stored full records, and `Done` means promotion committed. If the process restarts, GET reports saved counts with `resumeAvailable: true`; POST again to resume. Do not start another POST while `running: true`. The read-only `scripts/spotlight-run-diagnostic.mjs` now reports checkpoint version, phase and counts without exposing the cursor value. On a successful run, confirm the same run ID appears in `spotlight_import_current`, `expected_count = hydrated_count`, and no missing/extra IDs were accepted by promotion. Compare its exact count to a fresh CrowdStrike probe, allowing for source changes during the long import.

The staged ID table and any old failed record generations consume disk until a successful generation is promoted and cleanup completes. Check actual free disk before starting the full Atlas import. After a web-process crash and restart, an operator must POST again to resume; no dedicated worker is introduced in this branch. Do not call a partial first run complete merely because the Postgres records table grew.
