# Customer reporting restoration: findings and design

## Goal

After choosing an app customer (`CO-*`), show all report data that is **verified to belong to that customer**. Restore the prior Atlas tiles without conflating live Falcon findings, retained Elasticsearch imports, and the app's connector findings. Keep the consolidation review queue and ticket tracker together and scoped to the selected customer. Before customer selection, show no report results.

The common report for customers without Atlas's direct sources is specified in `2026-09-27-connector-customer-reporting-design.md` and implemented by the companion connector customer reporting plan.

## What is established from this checkout

| Finding | Evidence | Effect |
| --- | --- | --- |
| The saved dashboard contains both Elasticsearch and CrowdStrike tile definitions and cached results. | `lib/elastic-dashboard-store.ts` stores `definition`, `result`, and refresh timestamps in `elastic_dashboard_queries`; `readDashboard` returns all active rows. | The old Atlas display was more than Elasticsearch. The recent changes do not delete these rows. Current production row contents remain unverified. |
| The page and dashboard API still return all saved tiles before customer selection. | `app/reporting/page.tsx` passes `readDashboard(...)` to the client; `app/api/elastic-dashboard/route.ts` also returns the global read. | Hiding the board in React does not make its data customer-scoped. Server responses must follow the selected customer. |
| The Atlas path now discards every saved tile whose source is `crowdstrike`. | `components/ElasticQueryDashboard.tsx`, `displayedQueries` filter. `docs/unique-cve-severity-tiles.md` says the unique-CVE tiles *supplement* the existing CrowdStrike finding-count tile. | Existing Atlas Falcon cards disappear from the normal Atlas view even if their saved results remain intact. |
| The saved tile board is gated by the success of an unrelated app-store report request. | `components/ReportingCustomer.tsx` sets `onCustomerReady(true)` only after `reporting?companyId=...` succeeds; `components/ElasticQueryDashboard.tsx` requires `customerReady` for `showQueryBoard`. | A slow or failed app store request hides cached Atlas source tiles. |
| The new customer scan views read only the app store. | `lib/reporting-store.ts` calls `computeExecReport`, `listFindings`, and `listScans`; `lib/reporting-insights.ts` derives connector totals and truncates detail lists to 25 findings and 12 scans. | These views cannot replace Falcon tile results or Elasticsearch retained-import results. Detail-list limits must be labeled; they are not total-count limits. |
| Saved query definitions do not carry an app customer ID. | `lib/elastic-dashboard-store.ts` table schema and `lib/elastic-dashboard.ts` definition type. | The current hardcoded Atlas condition does not prove which tenant a saved tile contains. |
| The documented Elasticsearch unique-CVE query has no company or tenant predicate. | `n8n/elastic/unique-open-cves-severity.esql`. | Scope relies on the contents of the index. Audit the index and every saved query before labeling a tile Atlas-only. |
| The review queue now filters `packet.appCompanyId`. | `lib/patch-group-ticket-store.ts`, `listGroupTickets`. | Historical CrowdStrike drafts without that field disappear from customer panels. Their tenant ID may permit verified backfill. |
| There is a separate asset-coverage snapshot table. | `lib/elastic-vuln-server.ts`, `elastic_query_snapshots`; `/elastic-vulnerabilities` now redirects to `/reporting`. | Any current snapshot there is not automatically part of the customer report. Whether production has such a snapshot is unverified. |
| The screenshot's exactly 80,000 open findings matches a documented former Falcon importer limit. | `lib/crowdstrike.ts` notes the old 200 pages × 400 IDs/page guard and its September 25 change to 5,000 pages; `lib/store.ts` imports these results. | The importer code no longer has the 80,000 guard, but stored Atlas findings may still reflect an older capped sync. Verify the last successful Atlas sync, its `truncatedTenants` result, and a fresh complete count before treating 80,000 as current. |
| The dashboard database can differ from the app database. | `lib/elastic-dashboard-store.ts` uses `ELASTIC_VULN_DATABASE_URL` or falls back to `DATABASE_URL`; `lib/elastic-vuln-server.ts` requires the former for snapshots; `lib/persist.ts` uses `DATABASE_URL`. | Production configuration and data location must be checked before claiming data was deleted or migrated. Staging configuration is not proof of production configuration. |

The September 25 validation in `docs/unique-cve-severity-tiles.md` recorded 11,287 unique open CVEs in retained Elasticsearch imports. That is historical evidence, not a current production total. Falcon severity cards count vulnerability instances; the app report counts stored correlated findings; neither number should be expected to equal the unique-CVE total.

## Production facts still needed

The checkout has no production credentials or `.env`. The live reporting page redirects to login in this session. A read-only, authorized production inventory must record:

1. The production values/presence of `DATABASE_URL`, `ELASTIC_VULN_DATABASE_URL`, `ELASTIC_VULN_ENABLED`, and `ELASTIC_VULN_SAMPLE_DATA` without revealing secrets; confirm which database holds each table.
2. For every active or soft-deleted saved tile: ID, source, title, query scope, result presence, refresh timestamp, last error, and owner tenant/index. Capture query definitions and result metadata before any write.
3. Whether `elastic_query_snapshots` has `asset-coverage` and whether it is still refreshed.
4. Atlas's app company record, scan connectors, finding counts, Falcon CID(s), Elasticsearch index boundaries, and any source credentials' scope; verify ownership before binding.
   Compare Atlas's 80,000 app finding count to the last successful Falcon sync and the Falcon source's own pagination total. Determine whether a post-fix sync completed and whether import/correlation caused a different count. Do not assume 80,000 is still a live pagination cap.
5. Historical review drafts and ticket rows with missing `appCompanyId`; map their tenant IDs to app companies only where independently verified.
6. The exact prior Atlas tiles and numbers the user expects, with screenshot or saved result timestamp for each. Compare like measures over like time windows.

Until these checks complete, the code proves display regressions but cannot prove the production data still exists, current totals, or that every previously global tile is Atlas-only.

## Required reporting behavior

- One customer selector uses the app's `CO-*` company list. No duplicate ConnectWise-company lookup for report selection. ConnectWise routing is checked only when creating a ticket.
- With no customer selected, render the selector and empty guidance, no customer results or shared source tiles.
- With no customer selected, do not serialize saved tile results into the page or return them from the customer report endpoint. The existing global dashboard management API must be separated from customer report reads and its organization-wide access made explicit.
- For Atlas, show every verified Atlas saved Falcon and Elasticsearch tile with its original result, source, measure, scope, and refresh time. Do not change the tile's query or stored result as part of the layout work.
- For another company, show its stored scanner findings and scans by connector. Show a direct source panel only when that source has an explicit, validated binding to the company. Never show an Atlas or global tile as that company's data.
- Source loads are independent. If the app store fails, cached eligible source tiles remain visible with an error on the failed app section; if a source fails, other sections still work. Never render stale results for the previously selected customer while the new one loads.
- Use distinct metric labels: app open correlated findings, Falcon open vulnerability instances, Elasticsearch unique open CVEs, assets, and scan totals. State population, time, exclusions, and whether details are top-N. Do not sum or reconcile unlike measures as though they should match.
- Show only a source's verified customer scope. A tile with unknown scope appears in an explicitly labeled admin audit view, never in a customer report.
- Existing `dashboardAccess` currently treats every signed-in organization member as a manager; do not rely on a nonexistent admin role. Define and enforce who may open the organization-wide source audit before shipping it.
- Keep consolidation review and ticket tracking adjacent. Backfill historical company identity only with verified tenant/company mapping; keep unresolved items discoverable in an unassigned admin view.
- Atlas's review queue must include both app stored-finding drafts already linked to `CO-147284` and verified Atlas Falcon consolidation drafts. Show their source and saved affected-asset/finding details, review state, and any resulting ConnectWise ticket. Do not merge distinct drafts merely because their CVE matches; flag likely overlap for human review before ticket submission.
- Do not send a ConnectWise ticket without human review and explicit submission.
- Preserve the existing shell, navigation, logo, dark palette, and table-oriented report layout.

## Release acceptance

1. No customer selected: zero report results or query tiles.
2. Atlas selected: prior verified tile IDs and cached result values are present; Falcon tiles do not vanish; failed app-store load cannot hide them.
3. A non-Atlas connector customer: only its own findings, scans, queue, and tickets appear; Atlas saved results do not leak.
4. Source counts and detail limits have correct labels, and historical values reconcile only within matching source and measure definitions.
   Atlas's 80,000 stored finding count is explained by sync history or by documented filtering/correlation, rather than assumed complete.
5. Old review drafts remain accessible; verified ones appear with the right customer, unverified ones are explicitly unassigned.
   Atlas's pending, approved, dismissed, and ticketed drafts remain discoverable with correct source labels and accurate total counts across pages.
6. Saved tile definitions/results and ticket records have a recoverable backup; post-deployment read-only checks match the baseline except for approved scope metadata/backfill.
