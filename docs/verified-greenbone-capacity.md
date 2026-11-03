# Verified Greenbone global capacity contract

## Why this must be separate from the legacy scan-list endpoint

The live Vulners-v2 `GET /api/v1/scans` implementation has previously returned only the final Greenbone task because of a loop/indentation defect. Historically its database held more than **7,000** tasks. Reading a single `Done` row is not proof that no other task is running.

The new `readVerifiedGreenboneCapacity()` adapter deliberately requests `GET /api/v1/scans/capacity`. Until that scanner-side endpoint is **implemented and accepted against a real exhaustive GMP task query**, the adapter returns an error and external scan admission must stay denied. A GitHub merge does not create that endpoint or change Vulners-v2.

## Required response contract

The authenticated API response must have the following shape, with **all** status keys present, including zeros:

```json
{
  "source": "gvmd",
  "inventoryComplete": true,
  "scannerHealthy": true,
  "generatedAt": "2026-11-03T21:00:00.000Z",
  "totalTasks": 0,
  "statusCounts": {
    "New": 0,
    "Requested": 0,
    "Queued": 0,
    "Running": 0,
    "Stop Requested": 0,
    "Done": 0,
    "Stopped": 0,
    "Interrupted": 0
  }
}
```

The zero values are an **example shape only**, not observed production results. The real server should have thousands of historical tasks. Never return `inventoryComplete: true` merely because a default, filtered, truncated, or single-page `get_tasks` query succeeded.

The scanner-side implementation MUST:

- Use authenticated GMP and determine the authoritative total task count, including all historical states.
- Read every page, or use independently verifiable server-side aggregate counts over the complete inventory. Reject incomplete pages, malformed tasks, duplicate IDs, inconsistent totals, and unrecognized status values.
- Count `Running` and `Stop Requested` as active, `Requested` as requested, and `Queued` as queued. Unknown or newly introduced GVM statuses must fail closed and require review.
- Mark `scannerHealthy: true` only after verifying gvmd and the OSPD scanner subsystem are healthy enough to provide current task state. Do not invent health based on HTTP 200 alone.
- Generate the timestamp at the end of the complete query, not at request start.
- Require the existing X-API-Key authentication, avoid exposing task IDs/customer scopes in the summary, and disallow all mutating HTTP methods.
- Keep response time and memory bounded, and ensure the endpoint itself cannot start scans or refresh hundreds of tasks into RAM without constraints.
- Compare the resulting counts directly with an independent, unfiltered GMP tally on Vulners-v2 under real load and across a known active GMI-only scan before trusting it.

## Client behavior

The app requires a status count for all eight supported states, matching `totalTasks` exactly. It rejects partial/unknown status counts, stale timestamps older than 30 seconds, future timestamps, missing health/complete flags, and legacy task-list responses. Network timeouts, HTTP 404, malformed JSON or authentication failures also block admission.

`GET /api/admin/external-scan-capacity` is an **admin-token-authenticated, read-only diagnostic**. It returns HTTP 503 with a generic failure until complete capacity can be proven. It does not create tasks, update a database, bypass approvals, or enable scheduling.

**Do not turn on `VULNERS_BRIDGE_SCHEDULER_ENABLED`, `GMI_SCAN_ADMISSION_ENABLED`, or `VULN_EXTERNAL_SCAN_DISPATCH_ENABLED` in production based on this PR.** Additional trusted completed-Nessus-run evidence, live maintenance windows, completion/report ingestion, and controlled reconciliation are still required before a GMI-only canary.
