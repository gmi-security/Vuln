# External scan global reservation — staging only

This adds the durable singleton reservation needed before GMI can safely automate external Greenbone scans. This checkpoint cannot start scans or update Vulners-v2.

## Contract

- SQL file: docs/sql/external-scan-dispatch-claims.sql. Explicit manual migration; not run on application startup.
- Library: lib/db/external-scan-claims.mjs. The caller supplies an existing PostgreSQL pool.
- The singleton row is locked with SELECT FOR UPDATE NOWAIT. In the same transaction the caller inserts an immutable claim and points the singleton slot at it.
- A claim survives process crashes. Another scan cannot take the slot while it is occupied. Duplicate occurrence keys remain blocked even after later reconciliation.
- There is deliberately no automatic expiry, background timer, scan launching, slot clearing, or retry.
- A timeout after a remote create request has uncertain outcome. Such a claim must remain held until an independent operator verifies the actual remote task state.

## Deployment gates still outstanding

1. Do not apply the migration until a verified application database backup and a real isolated PostgreSQL concurrency test succeed. Existing module tests use a fake database and do not prove real database locking.
2. Connect the current approved customer routing and actual completed Nessus scan evidence. A historical finding or a scheduled time alone is not authorization.
3. Obtain the customer-approved maintenance window. Recheck customer authorization and live scanner capacity after the durable reservation and again before remote create/start.
4. Build the dispatch worker, scanner API admission check, remote task ID persistence, terminal result collection, and an audited reconciliation/release protocol.
5. Test two processes racing, interrupted transactions, crash recovery, uncertain create response, stale approval, scan scope, negative-report completeness and scanner resource limits.
6. Perform a single authorized GMI test-host trial before enabling any external client targets.

Until those gates pass, keep VULNERS_BRIDGE_SCHEDULER_ENABLED=false and GMI_SCAN_ADMISSION_ENABLED=false. Never re-enable the legacy Bridge full-inventory sweep.

Rollback: This PR alone requires no database or runtime rollback. If the separate SQL migration is ever applied, retain its ledger for audit; do not drop the schema or clear an outstanding claim merely to restart scans.
