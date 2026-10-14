# Customer connector sync status

The customer Connectors page uses its existing customer selector. Its **Sync status** section is separate from connector assignment review.

| Operation | Status source | Manual action |
| --- | --- | --- |
| Microsoft Defender | Customer connection's last success and latest import run | Queue this customer's import; resume a queued job or replace an expired worker lease |
| CrowdStrike Spotlight | Customer's latest import run and current generation promotion time | Start/resume the existing customer-scoped Spotlight importer |
| Saved Elasticsearch/CrowdStrike query | That tile's success time, attempt, error, request flag and lease | Refresh this tile after checking its current customer owner |
| Shared inventory, scanners and other tools | No customer-specific sync timestamp is inferred | Open the existing shared tools; their operations can affect multiple customers |

Last successful sync is retained when a later attempt fails. The table distinguishes queued, running, failed, interrupted and unrecorded status. A completed source import is not a live connection test or a guarantee that every downstream report has finished publishing. Dates use the browser's time zone.

## Operation and boundaries

- `GET /api/elastic-dashboard/customer-sync?companyId=...` reads bounded metadata in read-only transactions. It does not fetch findings, hydrate the platform store, create tables, contact providers or start jobs.
- `POST` to the same URL accepts only `{ "id": "..." }`. It uses existing organization-member authentication and same-origin write checks, validates the selected customer, and rechecks operation availability.
- Defender claims, publication and risk refresh are scoped to the requested customer. Duplicate queued requests reuse the run. An expired lease is fenced before a replacement is queued.
- Saved-query ownership includes explicit tile ownership and the existing server-managed legacy assignments. Explicit unassignment remains authoritative. A durable refresh request flag is consumed atomically so queued/resume clicks do not run the same request twice. Manual work waits for preview capacity without holding a database connection.
- The existing general scheduler setting is preserved. While paused, manual Defender publication does not invoke the bulk patch-draft generator. A manual sync does not re-enable scheduled jobs.
- The browser polls metadata at ten-second intervals during active work and sixty-second intervals when idle. It stops polling when unmounted and skips reads while hidden. Failed reads retain previous status but disable sync until a successful read.
- Raw provider errors, credentials, query text and host records are not included in this status response. Import/query error details remain in their existing source views.

## Current limits

Shared sources do not have a reliable customer-level last-sync timestamp in the existing storage; the table says **Not recorded** and links to shared tools. There is no new global Sync All button or automatic scan launch.

Spotlight progress uses the current web process plus durable import metadata. The deployed single-process arrangement is supported. In a future multi-process deployment, a job owned by another process could appear interrupted; the existing database import lock still prevents concurrent imports. Central worker ownership would be needed for authoritative cross-process progress.

## Verification

Regression tests cover customer ownership, legacy assignment fallback, existing permission gates, failed-result retention, duplicate requests, paused worker recovery and query capacity. PostgreSQL checks run against fresh disposable databases with private Unix sockets and fixture provider responses. Browser checks use synthetic customers and intercept provider calls; no live import, scan or ticket is required.

Build the summary/reporting workers before running the full Node test suite. The local Windows worktree shares `node_modules` through a junction, so its production build uses `npm run build -- --webpack`; the default Turbopack build cannot resolve that external junction. No production build configuration is changed.
