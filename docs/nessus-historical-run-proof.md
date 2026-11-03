# Verify actual Nessus completion before an external Greenbone scan

## Scheduling decision

**Preserve the existing 60-minute offset** from a customer's scheduled Nessus occurrence. The offset is a *minimum* waiting period, not proof of execution.

After that minimum period, Greenbone may run **only** when the exact Nessus historical scan has completed, the intended exact customer target has an assessed host result, the approved maintenance window is open, scanner capacity is independently confirmed empty, and the durable global slot is acquired. If Nessus lasts longer than 60 minutes, Greenbone waits until it has completed. If the approved window closes, the job does not launch.

This PR does not enable scheduling, background workers, legacy offset scanning, or any production external scan.

## New proof loader

`nessusCompletedRunProof(candidate, reviewedFolderId, pinnedConfig)` is a read-only adapter, intentionally requiring an approved folder ID supplied by **current reviewed Nessus routing**, not a request parameter. It reads:

- `GET /scans?folder_id=...` and requires the scan to belong to that approved folder
- `GET /scans/{scan_id}` to select a unique completed historical occurrence
- `GET /scans/{scan_id}?history_id={history_id}` and requires evidence that the requested history was returned. Some Nessus versions omit root ID/UUID; in that case the adapter must verify an impossible ID is rejected, compare a different completed historical run, and reconcile each run's start with its history creation time. The latest run is **not** silently substituted
- `GET /scans/{scan_id}/hosts/{host_id}?history_id={history_id}` for complete assessment evidence for the approved host or IP

The proof rejects missing history identity, ambiguous runs, incomplete targets, missing host details, wrong folders/targets, out-of-window timestamps, stale runs, too many hosts/history entries, and failed reads. It emits an immutable run-specific UUID as the report identity, never the mutable scan schedule ID.

**Important:** The local Nessus edition/firmware has not yet been queried to verify whether its historical detail response includes `history_id`, `uuid`, `scan_start`, `scan_end`, and `incomplete_targets` at the expected paths. The proof intentionally fails closed if any required attestation is missing. Do not make up these values or loosen the check merely to make a scan execute; obtain sanitized live payload shape first, adapt and test appropriately.

The standard `nessusScanStatus` API and imported findings are not enough to authorize external scanning.

## Remaining rollout gates

- Deploy vetted app changes and explicitly install the two durable slot/event SQL migrations after a database backup. Neither the GitHub merge nor this PR installs anything remotely.
- Connect the historical proof reader to current reviewed Nessus routes, current approved customer window, and Greenbone capacity probe in a single protected worker.
- Add verified Greenbone terminal task/report reconciliation and safe slot release; preserve unknown tasks for manual investigation.
- Test against a fresh known GMI-only Nessus recurrence and its actual historical result; ensure the scanner's `/api/v1/scans/capacity` endpoint is still authenticated, complete, current and reachable.
- Test reboots, concurrent workers, scanner failures, timeout reconciliation and a GMI-only canary before considering client production activation.

Keep `GMI_SCAN_ADMISSION_ENABLED=false`, `VULN_EXTERNAL_SCAN_DISPATCH_ENABLED=false`, and `VULNERS_BRIDGE_SCHEDULER_ENABLED=false` until those gates are satisfied. The legacy scheduler is a full-inventory sweep and **must never be enabled as a shortcut**.
