# Ticket status on Prioritize — 2026-10-16

Both existing fix lists display saved ticket references. Remediations by severity and device impact has a Ticket status column; Top fixes shows the same status beneath each row. Draft and approved states are separate from sent tickets. Sending, uncertain, failed, closed, related-CVE and unavailable states remain explicit. Successful manual preparation refreshes the status display.

## Matching and limits

- Records must be explicitly linked to the selected platform customer and the current ConnectWise destination (or an unsent request without a destination).
- Grouped requests match an exact remediation action/version and source tenant. Current CrowdStrike action evidence can verify the union of open tickets against each current device/CVE membership. A device is fully covered only when all its CVEs in that action are covered.
- Older CVE/vendor groups may contain different action versions. They show related references, not complete coverage. Platform CVE/remediation matches show ticket references but leave current device coverage unverified.
- Customer-linked single-CVE requests are related references only. Their review location remains Query tiles → All patch tickets; that control requires the existing management permission. Unassigned historical requests are excluded.
- Status is the platform's last saved ConnectWise observation, not a fresh provider lookup. Ticket closure is not proof that vulnerabilities are fixed. Tickets made outside the platform are not discovered by this feature.
- A lookup error keeps the vulnerability rows and displays unavailable. No failure is converted into “No tracked request.” Five references are shown per row; additional references are indicated.

## Read path

Ticket metadata/scopes use the configured dashboard pool, including a separate `ELASTIC_VULN_DATABASE_URL`. Current Spotlight evidence uses the application database. The two read-only transactions are sequential and release their connections, allowing a shared pool with one connection. Pool access does not initialize tables or install default queries.

Limits: 500 matching requests across grouped and single-CVE records, 8 MiB per metadata/scope/evidence result, three-second SQL statements, 500 ms lock timeout and one shared one-million-comparison coverage budget. Missing or over-budget coverage remains unverified. The overlay changes neither cached summaries nor patch preparation and send guards.

No schema migration, source re-import, new summary version or provider calls on page load are required. No live drafts or tickets were created in testing.

## Validation

- 1,029 unit tests passed, seven optional database tests skipped, zero failures. Worker builds preceded tests that load compiled worker modules.
- 19 separate isolated PostgreSQL checks passed. New cases exercised real split databases, a shared one-connection pool, current-generation evidence, customer/destination isolation, customer-linked single-CVE requests and the combined request limit.
- 15 browser workflow checks passed against the production build, including draft refresh, approval, sending, uncertain outcome, open/partial/closed coverage, single-CVE navigation and unavailable status. Existing customer-switch, mobile and ticket workflow checks remained green. Used installed Edge for the final browser run; the initial default launch lacked its matching Playwright browser binary.
- Production and both worker builds passed. Independent code review found no remaining blockers after database separation, single-CVE inclusion and request-link fixes.
- Read-only live check at 22:16 UTC: Atlas's two 50-row lists were decorated in 228 ms. Ticket #2667550 matched 824/824 current devices for the exact .NET action. Other shared-CVE actions showed related references. Footprint's 100 rows took 65 ms and contained no Atlas ticket references. Finding counts were unchanged.

Private logs and synthetic browser artifacts remain outside Git. No customer host lists, credentials or ticket bodies are included here.
