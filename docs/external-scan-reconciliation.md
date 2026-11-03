# External scan task recovery and reconciliation

This code extends the durable global reservation mechanism without enabling the legacy Bridge scheduler or admitting a remote scan.

## Safe state transitions

- After a future dispatcher receives a **confirmed** remote Greenbone task ID, `recordExternalScanRemoteTask(pool, claimKey, taskId)` atomically persists it in the current locked claim. The same ID is idempotent; a different ID is rejected.
- If create/start returns an uncertain outcome, `flagExternalScanReconciliation(pool, claimKey, reason)` marks the reserved claim as `needs-reconciliation`, retains any known task ID, and appends an audit event.
- The slot remains **occupied** after an uncertain outcome and across application restarts. No automatic retry, expiry, clearing, or release is implemented.
- `GET /api/admin/external-scan-slot` reads the current reservation and its most recent 20 events. It requires `ADMIN_TOKEN`; do not send that token in a URL or chat.
- Missing schema, lost DB connectivity, task-ID conflicts and unauthorized requests fail closed. The route does not hydrate platform findings or call the scanner.

## Migration

The additive `docs/sql/external-scan-dispatch-events.sql` assumes the existing `external_scan_dispatch_claims` schema. It must be reviewed and installed explicitly on the correct application database **after** a backup. GitHub merge does not apply SQL migrations or deploy this application.

The separate External Scan Reservation Safety workflow runs the original database-lock regression and new task-ID/reconciliation assertions on a disposable PostgreSQL service. The test's mock/ephemeral scanner IDs are not real scans.

## Still blocking production automation

The app does not yet have a dispatcher that:
1. loads current customer authorization, exact approved external host/IP and maintenance window,
2. confirms a completed Nessus run and that exact target's coverage,
3. acquires the global slot and rechecks actual Greenbone load,
4. creates/starts **one** authorized remote task and reliably persists its ID,
5. polls it, validates full report pagination/host/QoD, and reconciles outcomes,
6. releases the slot only after verified terminal status and an auditable decision.

Do not turn on `VULNERS_BRIDGE_SCHEDULER_ENABLED` or `GMI_SCAN_ADMISSION_ENABLED` merely because these code modules were merged. Do not install or alter firewall, SSH, or Docker services on Vulners-v2 for this change.
