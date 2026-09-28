# Customer Reporting Restoration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore all verified Atlas reporting data and give every selected customer a complete, correctly scoped report across its available sources.

**Architecture:** Inventory and preserve production rows first. Add explicit app-company bindings for direct source tiles and tenant scopes, keep unbound saved tiles out of customer reports, and load app, Elasticsearch, and Falcon sections independently. Retain the current saved query and ticket stores; migrate only verified identity metadata.

**Tech Stack:** Next.js 16, React 19, TypeScript, PostgreSQL, Node test runner.

**Spec:** `docs/superpowers/specs/2026-09-27-customer-reporting-restoration-design.md`

**Companion plan:** `docs/superpowers/plans/2026-09-27-connector-customer-reporting.md` specifies the common connector-based report for all other customers. Complete its metric/source contract before integrating its UI with Atlas's direct-source sections.

## Global Constraints

- Report selection uses app `CO-*` customer IDs; ConnectWise identity is needed only for ticket routing.
- No report results before customer selection.
- No saved results serialized to the customer page or its endpoint before selection.
- Do not assign a source tile, Falcon CID, Elasticsearch index, or old ticket to a customer without verified ownership.
- Keep unlike measures separate and labeled with scope, source, and time.
- Do not delete or rewrite saved tile definitions/results during UI migration.
- Do not send a ConnectWise ticket without human review and explicit submission.
- Preserve the existing shell, navigation, logo, dark palette, and table-oriented layout.
- No `.env` or production credentials are available in this checkout; live verification is a release gate.

## Review Focus

- App report endpoint returns 503 while Atlas source cache is healthy: Atlas tiles remain visible with a section error. Test in Task 3.
- Selected customer changes while a previous response is in flight: no old customer data flashes. Test in Task 4.
- A saved tile has no verified owner: it stays off customer pages and is visible only in the authorized organization source audit. Test in Task 2.
- A historical draft lacks `appCompanyId`: it remains in the unassigned admin list until verified. Test in Task 5.
- A detail table reaches its row limit: total metric remains accurate and the table says it is truncated. Test in Task 6.

---

### Task 1: Read-only production baseline and source ownership

**Files:** Create `docs/reporting-production-baseline.md` from sanitized metadata; no application code changes.

**Interfaces:** Produces the approved mapping of `CO-*` company IDs to saved tile IDs, Falcon CID(s), Elasticsearch index/predicate, and historical draft tenant IDs for later tasks.

- [ ] Use authorized, read-only access to record environment variable *presence and target database identity* without printing secrets.
- [ ] Export or back up `elastic_dashboard_queries`, `elastic_query_snapshots`, relevant source connection metadata, and patch ticket rows before any schema/data change; verify row counts and restoration method.
- [ ] Inventory active/deleted tiles, cached result state, timestamps, errors, query scope, Atlas source credentials, and old review drafts. Compare to the last known Atlas tile list and user-observed values. Check whether the exactly 80,000 Atlas findings came from a pre-September-25 Falcon sync; compare last successful sync and `truncatedTenants` with a current complete source count.
- [ ] Mark each tile/scope `verified Atlas`, `verified other company`, or `unassigned`, citing evidence. Stop customer binding for uncertain rows and request the missing ownership evidence.
- [ ] Run the inventory a second time or review its captured output to ensure no row or database was omitted. Baseline passes when every visible prior Atlas tile has a disposition and the data location is confirmed.

### Task 2: Explicit source binding and scoped read contract

**Files:** Create `lib/reporting-source-bindings.ts`, `lib/reporting-source-contract.ts`, `tests/reporting-source-bindings.test.mjs`; modify `lib/elastic-dashboard-store.ts`, `app/api/elastic-dashboard/reporting/route.ts`, `app/reporting/page.tsx`, `app/api/elastic-dashboard/route.ts`, `lib/elastic-dashboard-http.ts`.

**Interfaces:** `listCustomerSourceTiles(companyId: string): Promise<DashboardQuery[]>` returns only tiles with verified, persisted bindings. `CustomerReportingSource` describes source, measure, population, scope, as-of time, status, and cached result. The organization source audit lists unbound tiles separately under explicit authorization.

- [ ] Write tests: a verified Atlas binding returns only its saved tiles; an unbound/global tile returns for no customer; a non-Atlas customer never receives Atlas tiles; bad `CO-*` ID is rejected.
- [ ] Run the focused tests and confirm they fail before implementation: `node --experimental-vm-modules --test tests/reporting-source-bindings.test.mjs`.
- [ ] Add a small additive Postgres binding table keyed by `(company_id, tile_id)` with source scope, saved definition revision/hash, and verification metadata. Validate the app company exists and the source/scope match the approved baseline; invalidate the binding if the query definition changes. Do not modify query definitions or result JSON.
- [ ] Implement the scoped read and source audit contract. Define and enforce which organization role may use the global management API; every authenticated organization member currently has `canManage=true`, so this cannot be assumed to mean admin. Populate bindings only for Task 1 verified rows; leave uncertain rows unbound.
- [ ] Stop server-rendering `readDashboard` results into `/reporting` before selection. Customer report responses must include only selected-company tiles; the global management API must not be used as a customer report feed.
- [ ] Rerun the focused tests and a TypeScript/build check. Commit the additive schema and scoped read as a self-contained change.

### Task 3: Independent source loading and Atlas restoration

**Files:** Modify `lib/reporting-store.ts`, `app/api/elastic-dashboard/reporting/route.ts`, `components/ReportingCustomer.tsx`, `components/ElasticQueryDashboard.tsx`; create `tests/reporting-source-availability.test.mjs`.

**Interfaces:** The selected `companyId` independently drives app insights and `listCustomerSourceTiles`. Each section has its own `loading | ready | error` state and displays the last successful scoped result with `refreshedAt` when a refresh fails.

- [ ] Write tests for the app endpoint failing while Atlas cached tiles load, the tile store failing while app scans load, and no selection yielding no report data.
- [ ] Run `node --experimental-vm-modules --test tests/reporting-source-availability.test.mjs` and confirm the new tests fail.
- [ ] Remove the `query.source !== "crowdstrike"` Atlas filter and the app request's `customerReady` gate on the tile board. Fetch only scoped tiles from Task 2 after selection. Keep the shared/unassigned audit behind the explicit organization role established in Task 2.
- [ ] Render per-source failure/freshness states. Never let a failure in one store blank a successful section.
- [ ] Rerun focused tests and build. Compare Atlas tile IDs and cached result metadata to Task 1 baseline before commit.

### Task 4: Customer-switch safety and connector report integration

**Files:** Modify `components/ReportingCustomer.tsx`, `components/CustomerScanViews.tsx`, `lib/reporting-insights.ts`, `tests/reporting-insights.test.mjs`.

**Interfaces:** Customer scan views keep current totals and connector grouping; detail arrays carry `shown/total` metadata and source/refresh labels. UI state is keyed by selected `companyId` and discards late responses for older IDs.

- [ ] Write tests for changing Atlas to a Nessus/Vulners customer while Atlas responses are pending, mixed connectors for one company, and another company's data remaining absent.
- [ ] Run the focused tests and confirm they fail.
- [ ] Implement the companion connector reporting plan's taxonomy, source-activity, summary, and UI tasks. Keep app findings/scans from `DATABASE_URL` as their own source sections; label correlated finding counts separately from direct Falcon counts. Make the 25-finding and 12-scan detail limits explicit or paginate.
- [ ] Render source and collection time on each section and an honest empty state for a customer with no scans. Preserve shell, navigation, logo, colors, and table layout.
- [ ] Rerun tests and build; inspect Atlas, a multi-connector customer, and a no-scan customer in a browser. Commit.

### Task 5: Review queue and ticket identity recovery

**Files:** Modify `lib/patch-group-ticket-store.ts`, `components/PatchReviewQueue.tsx`, `components/PatchTicketTracker.tsx`; add `tests/reporting-ticket-scope.test.mjs`.

**Interfaces:** Customer queue/ticket reads use validated `appCompanyId`; admin audit includes a separate count/list of unassigned historical drafts. Verified historical CID-to-company mappings from Task 1 are backfilled idempotently and logged.

- [ ] Write tests: Atlas lists both its `stored-findings` drafts and verified Falcon consolidation drafts across pages; pending, approved, dismissed, and ticketed states appear in the appropriate queue/tracker; an unknown-CID draft remains unassigned; other customers see neither Atlas source; review/submission rules remain unchanged. Assert the displayed totals represent all matching rows, not only the first 100 loaded.
- [ ] Run focused tests and confirm failure.
- [ ] Apply only approved historical Falcon CID-to-Atlas mapping; do not infer company from the ticket's display name. Return total counts alongside paginated rows, distinguish Falcon and app-store draft sources, and flag likely duplicate remediation scope for human review before ConnectWise submission. Keep consolidation queue and ticket tracker adjacent and make unassigned items visible in the authorized source audit.
- [ ] Rerun tests and compare Atlas draft/ticket row counts, states, source labels, and saved review details to Task 1 baseline. Commit.

### Task 6: Metric provenance, limits, and release checks

**Files:** Modify `components/ElasticQueryDashboard.tsx`, `components/CustomerScanViews.tsx`, `lib/reporting-insights.ts`; add `tests/reporting-metric-labels.test.mjs`; update `docs/reporting-production-baseline.md` with post-deployment read-only results.

**Interfaces:** Every metric declares its population (correlated app findings, Falcon instances, Elasticsearch unique CVEs, assets, or scans), source, last refresh, and any top-N row limit. No cross-source sum is presented as an exact comparable total.

- [ ] Write tests for source/measure labels, 100-row saved tile display limit versus full aggregate count, 25/12 app detail limits, importer truncation/freshness status, and unavailable/stale source badges.
- [ ] Run tests and confirm failure; implement only the labels and pagination/limit information the source actually supports.
- [ ] Run the reporting test suite, TypeScript/build, and visual checks at desktop and narrow widths. Do not claim live data correctness from local tests.
- [ ] Deploy only after Task 1 ownership/backup gates pass. Read back Atlas's prior tile IDs and result values, one other connector customer, no-customer state, source failure behavior, and review/ticket counts. Restore the previous release or bindings from backup if ownership or result parity fails.

## Self-review

- The spec's no-selection, Atlas restoration, non-Atlas isolation, independent loading, metric semantics, review queue, visual consistency, and recoverability requirements each have an owning task.
- Production ownership and database identity are explicit prerequisites, so this plan does not pretend the checkout establishes current live state.
- Implementer must verify the existing test harness and route response shape before writing tests; tests named above are proposed deliverables, not claims of current coverage.
