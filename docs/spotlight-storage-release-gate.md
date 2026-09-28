# Atlas Spotlight storage rollout

## Scope and prerequisites

This change stores each Atlas CrowdStrike Spotlight vulnerability ID as a separate row in the Postgres database configured by `ELASTIC_VULN_DATABASE_URL`. It does not change the reporting page, the existing in-memory scan and finding counts, or ticket cutting. The unnamed primary CrowdStrike tenant is excluded from this import. The Atlas customer name configured in `FALCON_CUSTOMER_N` must match the existing Atlas company (`CO-147284`).

The reported DigitalOcean database allocation is 16 GB RAM, 6 vCPU, and 300 GiB disk. That allocation is not a measured free-space value. Check actual free space, backups, and current database size before the first full import. A full generation and the previous completed generation coexist during refresh, so allow for at least two generations plus WAL, indexes, and vacuum headroom. Do not infer row size from the allocation; measure it after an initial batch and project the full size.

## Local verification

Run `node --experimental-vm-modules tests/crowdstrike-sync-resilience.test.mjs`, `node --experimental-vm-modules tests/spotlight-record-store.test.mjs`, `node --experimental-vm-modules tests/spotlight-import.test.mjs`, `npx tsc --noEmit`, and `npm run build`. The local database tests mock `pg` and verify SQL calls and transaction order; they cannot prove PostgreSQL execution because no disposable database or credentials are available locally. Run the database statements against a disposable Postgres instance before production rollout if one is available.

## First run

1. Deploy the storage change to the intended branch. Confirm `ELASTIC_VULN_DATABASE_URL` points to the transactional database and the app still has one instance.
2. Check the Atlas debug count. Capture the query time and `spotlightFindingsAvailable`; it is a moving CrowdStrike count, so a later value may legitimately differ.
3. Trigger the existing Spotlight import action. The empty-body POST selects the sole named tenant; when multiple named tenants are configured, send `{ "companyId": "CO-147284" }` to `/api/crowdstrike/spotlight-import`.
4. Poll the Spotlight status. Confirm `tenant` is Atlas, `fetched` and `stored` advance, and the run ends with `phase: "Done"`, no error, and `findingsImported` matching the promoted database count. The import must not request the primary tenant. A hydration ID mismatch, incomplete page, or stored ID shortfall fails the run and keeps the previous completed generation.
5. Compare the completed count to a new bounded CrowdStrike count probe, allowing for records that opened or closed during the import. If the difference is material, investigate query timing and run completeness before treating the import as verified.

## Database checks

Use a read-only SQL session on the database behind `ELASTIC_VULN_DATABASE_URL`:

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

A failed or interrupted run cannot move `spotlight_import_current`. Starting a replacement run marks an interrupted run failed. Old, noncurrent generations are deleted in 10,000-row chunks before or after a run; cleanup never deletes the current or running generation. If an import fails, inspect the Spotlight status error and database run row, fix the cause, and trigger another import. Keep normal DigitalOcean Postgres backups enabled. If storage pressure rises, stop new imports and inspect generation sizes before retrying; do not manually delete the current generation.

The old 80,000-row Atlas scan in the main in-memory store remains as it was. This release verifies durable source-record collection only. Reporting and ticket behavior require a separate, explicitly scoped migration to read these records.
