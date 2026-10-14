# Top Fixes, manual tickets and scheduled imports

## Behavior

Top Fixes ranks recommended actions for the selected customer's open CVE findings by affected devices, then severity. It does not read the patch-draft queue. Platform findings use a revision-aware, bounded cache. Current CrowdStrike Spotlight generations use a compact summary prepared by a separate worker; page requests never scan the raw Spotlight table. Pending or incomplete source summaries are visible as notices, not zero findings.

An action stays associated with its CVE. Identical text on different CVEs does not prove that one patch resolves all of them. Device counts are deduplicated within each source/action; combined headline totals are labeled as source records rather than a deduplicated cross-source estate. CrowdStrike's recommended remediation is used, never a guessed minimum patch. Missing action/device evidence is reported.

Ticket workflow:

1. Click a CVE from a customer view.
2. Prepare a patch request and optionally download its host CSV.
3. Follow **Review on Tickets page**. The CVE panel closes and the customer stays selected.
4. Review and approve the draft, choose ConnectWise routing, then explicitly send it.
5. The platform retains the ticket reference and reads its status periodically, including closed-to-reopened changes made in ConnectWise.

Automatic draft generation and auto-create have been removed. The old auto-create endpoint returns HTTP 410 after authentication. Imports, risk refresh and server startup cannot generate, approve or send drafts. Automatic priority changes, ticket reopening and draft backfills are no longer started. Existing drafts, tickets, customer assignments and saved tiles are preserved. Explicit user-operated reconciliation/verification tools remain available.

## Scheduled processing

`VULN_DISABLE_SCHEDULER=false` restores the existing configured import cadence, dashboard query refresh, risk enrichment and ticket-status reads. `settings.schedule.autoSyncEnabled` and its interval still determine sync-all timing. Existing per-source settings remain in effect, including Defender daily scheduling. Sync-all deliberately staggers configured connectors by 25 minutes; an enabled scheduler does not mean every connector starts immediately.

The general scheduler, scanner export and Vulners Bridge timer guards now clear the same promise that they store. This fixes the previous one-tick-only behavior and still prevents overlapping ticks.

## CrowdStrike summary worker

Build with `npm run build:summary-worker`. Production must explicitly configure:

```dotenv
VULN_SPOTLIGHT_SUMMARY_CUSTOMERS=CO-147284
```

Run in a separate bounded process, with its own singleton database lock:

```sh
cd /opt/vuln
VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED=true node --max-old-space-size=512 scripts/spotlight-summary-worker.mjs --load-env --once
```

`--load-env` explicitly loads the application's production environment and uses its existing managed-Postgres TLS settings. Without that option, the CLI keeps its original externally supplied environment/database settings. A disabled worker does not load environment files or connect.

Deployment installs a dedicated `codex` cron entry every five minutes using `flock`, the command above and a private worker log. It processes only the explicit customer allowlist, discovers newly completed imports, reuses completed summaries, and uses bounded retries. It never calls ConnectWise or CrowdStrike. Cron is independent of the website process and survives a host restart. Remove the marked cron entry to pause this worker.

Summary model v4 adds recommended Top Fixes to the existing summary JSON; it needs no new database schema. The new reader continues to display existing v3 CVE metrics while the v4 worker catches up. Previous source generations remain unchanged.

## Deployment and recovery

Build and test before stopping the running app. Fast-forward the checkout while preserving uncommitted operator scripts, replace only the built artifacts, restore scheduled imports, restart the existing root-owned PM2 `vuln` process, and check health, logs, scheduler state and summary output.

Record any existing `spotlight_summary_current` pointers before the first v4 build. If reverting to a v3-only reader, pause the v4 worker and restore the recorded v3 pointers; that old reader does not follow v4 pointers. If there was no previous summary, disable saved-source reads rather than inventing a pointer. No raw imports or ticket records need deletion. Reverting code that still starts automatic draft jobs also requires pausing the general scheduler again.

## Validation

Regression checks cover customer isolation, source authority, incomplete summaries, device deduplication, cache invalidation, repeated timer execution, import-without-drafts, retired auto-create, GET-only ticket tracking and CVE-to-Tickets approval.

Real PostgreSQL validation in a private disposable cluster passed 14 summary checks and 9 worker lifecycle checks, including direct KEV score projection, recommended-only actions, v3 read compatibility, publication rollback, exclusive leases, interrupted worker recovery and isolation. No production records or real tickets were used by these tests.

Final local validation: production Webpack build and both dedicated worker builds passed; 848 automated tests passed, 7 optional database tests skipped, zero failures. The 12 Remediation browser checks passed with synthetic data, including draft preparation, Tickets-only approval/send, customer scope and empty-ticket-queue Top Fixes. No real tickets were sent.
