# Controlled external Greenbone dispatch — staged code only

## Why this change matters

The legacy `vulnersBridgeStartScan()` creates and starts a remote task before the caller gets its task ID. If start times out after the scanner has accepted it, the app cannot reliably correlate the remote job. This PR adds a separate reserved-task API and orchestration that **persists the task ID before asking Greenbone to start scanning**.

## Integration and controls

- `vulnersBridgeCreateReservedTask(target, name, scope)` requires an exact approved host/IP and a live verifier; it only creates an inert Greenbone task.
- `vulnersBridgeStartReservedTask(taskId, scope)` requires a known task ID and repeats the live verifier before the start request.
- `dispatchOneAuthorizedExternalTarget(candidate, deps)` joins the admission policy from PR #112, durable singleton from PR #113, and audit/recovery from PR #114. It is not connected to an HTTP route, timer or production worker.
- Requires `VULN_EXTERNAL_SCAN_DISPATCH_ENABLED=true`, `GMI_SCAN_ADMISSION_ENABLED=true` and `VULNERS_BRIDGE_SCHEDULER_ENABLED` not true in its runtime.
- Receives proof **only from an internal trusted loader**, not from customer-supplied request JSON. On every phase it rechecks current authorization, approved customer maintenance window, completed exact Nessus run/host evidence, and fresh global scanner capacity. Proof changed or expired -> fail closed.
- Reserves the durable one-at-a-time slot, saves the returned task ID before calling start, and does **not** release the slot or automatically retry after a timeout. A disputed result becomes `needs-reconciliation` for an operator to inspect.

## Still required to activate in production

1. Install and verify the explicit claim/events migrations against the correct application database **only after a tested backup**. A GitHub merge does not deploy them.
2. Implement trusted live input adapters for exact approved windows and verified Nessus *run* results (not just scheduled start times). Validate actual API shapes.
3. Implement and test a trustworthy live Greenbone capacity reader. The existing `GET /api/v1/scans` endpoint previously returned only the final task rather than the full task roster; it must be repaired and retested before this input can authorize any launch.
4. Integrate a single worker; no REST endpoint accepting arbitrary proof data. Add task polling, complete report verification and audited terminal-state reconciliation, including safe global slot release only when remote state is known.
5. Fix Greenbone API admission rules and validate timeouts, auth, report pagination, QoD, targets and load on the existing approved GMI test host before any customer scan.
6. Approve exact customer target scopes and acceptable windows separately. Never enable the legacy full-inventory sweep as a shortcut.

**This PR does not restore automatic external scans** and does not touch production scanners, SSH, firewalls, Docker or databases. Existing flags remain disabled.
