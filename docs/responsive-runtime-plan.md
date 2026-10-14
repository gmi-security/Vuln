# Responsive runtime and stable navigation

Approved scope: stabilize navigation, keep the last committed platform view available during imports, isolate background work, and prevent overlapping browser polling. Connector imports remain daily; saved tile schedules and manual ticket approval remain unchanged.

## Design

- A supervisor under the existing PM2 application starts a public web reader and a private worker. Only the worker schedules imports, enrichment, scanner polling and durable mutations. An authenticated private Unix socket carries mutation and process-local job requests; existing application authorization still runs.
- The web process reads a consistent PostgreSQL generation, verifies it and prepares a replacement cache before swapping it. Requests retain their original generation. Failed refreshes keep the previous committed view. Startup without a verified generation fails closed.
- Commit audit JSON records touched buckets. Readers reload only those buckets; older or incomplete audit evidence causes a full consistent reload. Metadata-only saves retain the findings cache. No database schema migration is required.
- Navigation is seeded with server feature flags. Transient capability errors retain valid navigation. Polling schedules its next request only after completion and aborts on teardown.
- Existing development/legacy startup remains available. Production enables the split explicitly. Runtime credentials and customer data are not recorded here.

## Implementation and verification

- [x] Navigation and nonoverlapping polling, including delayed/failed status responses.
- [x] Verified committed SQL reader, changed-bucket audits, atomic replacement and failure tests.
- [x] Reader store guards, request generation pinning, cached common aggregates and scanner polling in worker.
- [x] Supervisor, authenticated private forwarding, graceful shutdown and no automatic mutation retries.
- [x] Focused tests, full suite, TypeScript and production build; independent branch review.
- [ ] Branch/PR/merge, build-first deployment, live readiness and responsive read verification.

## Review focus

Customer isolation, mutations behind GETs, stale writer fencing, initializers that write, worker lifecycle, request authentication and cancellation, memory use during refresh, and reads remaining committed while a large save runs. A healthy HTTP listener alone is not data readiness.

## Decisions and progress

- Use the existing SQL authority and epoch fencing rather than introduce another datastore.
- Keep one writer process. Do not remove its uncommitted-data guard to make requests appear faster.
- Preserve the existing production operator files and existing tile refresh intervals.
- PostgreSQL integration: 18 checks passed. A reader retained its prior view during an open transaction, selectively refreshed updates/deletions/metadata after commit, and rejected corrupt replacement data.
- Actual built Next/Unix-socket application: 7 checks passed with 10,000 synthetic findings. Authorization remained enforced across the private forwarding hop; worker mutations became visible after commit and survived restart. Slowest page read during the held write was 14 ms. This is a test-dataset result, not a production latency guarantee.
- Read-only live-data reader probe: about 1.05 million findings loaded and verified in 114.2 seconds, RSS 2,447 MiB, maximum measured heartbeat delay 340 ms during hydration. No production writes or provider calls. Initial startup still waits for the first verified view; subsequent refreshes retain the previous view.
- Independent review covered authentication, customer isolation, committed reads, writer fencing and process lifecycle. Follow-up fixes distinguish read/write readiness, retain the web service when an already-running auxiliary worker exits successfully, and cover remaining browser pollers.
- Runtime split is opt-in with `VULN_RUNTIME_SPLIT=true` and SQL authority. Deployment builds Next and both auxiliary worker artifacts before stopping the existing service. Optional summary workers start only when their existing enable/scope settings are present.
- Production's existing 24 GiB Node heap allowance must not be inherited twice: use `VULN_WEB_HEAP_MB=8192` and `VULN_WORKER_HEAP_MB=16384`. These are maximum heap allowances, not reserved RAM; actual RSS also includes non-heap memory.
- Rollback: stop the supervisor and wait for its children to exit, disable `VULN_RUNTIME_SPLIT`, then restart the known-good build. There is no schema cutover in this change; legacy readers ignore the added commit-audit keys. Never start the legacy writer alongside the split worker.

## Release validation

- Local and Linux production builds passed, including the separate summary and reporting worker artifacts.
- Browser workflow: 10 checks passed, including full reload, failure retention, identity changes, slow sidebar/Companies/Scans polling and cancellation.
- Full suite: 931 passed, 7 optional database tests skipped; separate private PostgreSQL integration: 18 checks; actual Next split-process application: 7 checks.
- Production deployment is the remaining operator step after merge. Initial hydration may take a few minutes; verify both readReady and writeReady before restoring public access.
