# Direct ES|QL dashboard

The user selected direct queries in GMI Vuln instead of n8n on 2026-09-24.
This is the current architecture; the earlier n8n workflow remains inactive and
is not required. Production release follows the user's previously authorized
direct-deployment workflow.

## Using the dashboard

Open **Elastic Dashboard** at `/elastic-vulnerabilities`. For daily diff history and background queries, see [the trend setup guide](elastic-trend-setup.md).

1. A signed-in organization member opens **Connection**, enters the Elasticsearch HTTPS
   endpoint and encoded read-only API key, and clicks **Test and save connection**.
   A Kibana `.kb.` address cannot be used as the Elasticsearch API address.
2. The supplied asset coverage query is already saved. Connection verification
   runs that query to check both authentication and access to its indices.
3. Click **Add query**, enter a title and ES|QL. **Preview (optional)** can check results before saving.
4. Choose **Automatic**, **Number cards**, **Table**, **Bar chart**, **Line chart**,
   or **Doughnut chart**, select a refresh interval,
   then **Add to dashboard**. The tile appears immediately and loads results in the background. Automatic turns a single numeric row into one number card per
   column; other shapes use a table. `_pct`, `_percent`, and `percentage` column
   suffixes render numeric values as percentages. Use ES|QL aliases for labels.
   For charts, enter the category and numeric column names, or preview to select
   them from the results. Two suitable columns are suggested after a preview.
   Editing the query clears mappings; enter its new columns or preview again.
5. Each saved query has **Edit**. Disabling its automatic-refresh checkbox pauses
   background refresh and leaves the last result visible. Editing/saving always
   requests one background run, including when automatic refresh is paused.
6. **Delete** beside Edit opens an inline confirmation. Confirming removes the
   shared tile and its saved history, stops refreshes, and clears its cached
   results. Source findings and credentials are unaffected. **CSV** exports the
   displayed cached rows from any completed tile.
7. Drag a tile by its grip to another tile's position. Move-up/down buttons work
   with keyboard or touch; the grip also supports Up/Down arrow keys. Order saves
   immediately for the shared dashboard. New tiles append after a saved layout;
   editing or refreshing a tile preserves its position.

Tables scroll vertically inside a maximum height of `min(28rem, 65vh)`, retain
horizontal scrolling and use sticky headings. Short tables keep their natural
height. The scroll area is focusable for keyboard use; CSV still exports all
displayed result rows, regardless of which rows are currently visible.

Related counts can share one query tile: return one numeric row with separate
ES|QL aggregate columns, such as `P1`, `P2`, and `P3`, and choose Number cards.
One metric fills the tile, two use two columns from 640px, and three use a single
row from 1280px (previously 1536px). Narrower screens wrap for readability.

Ordering uses same-origin member POST `/api/elastic-dashboard/order` with an
array of all active IDs. A transaction using the existing dashboard advisory lock
writes the additive `display_order` column. Duplicates, unknown IDs, missing IDs
and stale lists after add/delete are rejected without partial changes. Ordering
does not modify query definitions, revisions, refresh timing or results. Polling
cannot replace the optimistic layout during a drag/save; failed saves restore
the previous local order. Concurrent valid reorders use the last committed order.

Layout validation (September 24, 2026): all 28 tests passed without skips,
including reorder persistence, edits/new/deleted tiles, rejected stale lists,
unchanged results/revisions and client movement/rollback. Production build and
HTTP smoke passed in disabled, sample and disposable-database modes, including
authorization/CSRF on the order endpoint. Live authenticated drag/drop and visual
interaction remain unverified. Two separate design previews use sample data;
neither visual redesign is included in this functional release.

Layout release verification: commit `0efbded73f4b59392c4f30ea0dfb981fb4b9ad4d`
reached ACTIVE in DigitalOcean deployment
`f5ac0b7e-077e-4cef-b506-6b8e93ceb2c1` on September 24, 2026. Build and deploy
steps succeeded; live health returned `ok: true` and `dbReachable: true`.
Anonymous POST to the new order endpoint returned 401. The disposable layout
test database container was removed. Signed-in live drag/drop remains unverified;
next check is to move a tile, reload, and scroll a long patch worklist.

Tile deletion uses authenticated, same-origin DELETE
`/api/elastic-dashboard/queries/[id]`. A `deleted_at` tombstone prevents startup
seeding, stale forms and old jobs from recreating the tile. Deletion increments
its revision, invalidates associated jobs and deletes daily history in one
transaction. In-flight results cannot write over deletion. Deleted tiles do not
count toward the 24-tile limit. This removes the tile; it does not delete upstream
Elasticsearch/CrowdStrike data. There is no restore UI; add a new tile to replace it.

The first query counts managed/unmanaged assets, not vulnerabilities. It preserves
the user's exact 25-hour record window and seven-day last-seen filter. IDs observed
in both categories can count in both. The query is not rewritten to deduplicate
those categories. ES|QL distinct-count accuracy follows Elastic's aggregation.

All signed-in organization members can read this dashboard and configure
connections or queries. The admin-only restriction was removed at the user's
request on 2026-09-24. This is an organization-wide view,
not a customer portal. Customer-level authorization would need a separate design.

## Connection and persistence

Elasticsearch is called only by the Next.js backend through `POST /_query`.
API keys should have only `read` and, if required for metadata tooling,
`view_index_metadata` on the required index patterns, with no cluster management
or index write privileges. Use the encoded API key, without an `ApiKey` prefix.
The app does not create API keys or grant Elasticsearch permissions.

Connection details are encrypted with AES-256-GCM using a key derived from
`NEXTAUTH_SECRET`. Secrets never appear in API responses, client props, audit
records, or logs. Rotating NEXTAUTH_SECRET requires re-entering the connection.
Changing the endpoint requires re-entering its key; the app will not forward a
stored key to a different endpoint.

The dashboard uses four dashboard tables: `elastic_dashboard_connection`,
`elastic_dashboard_queries`, `elastic_dashboard_audit`, and `elastic_dashboard_jobs`. They use
`ELASTIC_VULN_DATABASE_URL` when set, otherwise the existing application database
pool. Scanner snapshot tables, existing settings, and connector data are not
changed. Tables are initialized automatically, with the default coverage query
inserted only if missing. The database role therefore needs CREATE/SELECT/INSERT/
UPDATE rights. The existing app database transport configuration is inherited.

## Execution and safeguards

- Browser API requests check response type before parsing JSON. HTML gateway
  pages, invalid JSON and login redirects produce readable recovery messages;
  HTML content is never shown. Background GET requests retry network/502/503/504
  failures once, with a 20-second deadline per attempt. Mutations are not replayed
  automatically because the server may already have committed them. Failed saves
  keep the editor open. Polling does not overlap, retains previous results on
  failure, and clears its own error after recovery without clearing a save error.

Response-handling investigation (September 24, 2026): the user saw an HTML
DOCTYPE parsed as JSON while editing a tile. Production logs showed process
startup at 21:11:10 UTC on the existing active deployment; live health and database
reachability were healthy. Restarted logs were empty, so neither the original
HTTP status nor the restart cause was established. A temporary proxy response
is consistent with this evidence, not confirmed. Four focused browser-client
tests cover HTML/malformed responses, session redirects, bounded GET retries
and non-replayed mutations. The production build passed. Live authenticated
reproduction remains unavailable; the clearer HTTP error enables follow-up if
the interruption recurs.

Release verification: commit `d809c8b4d42bab03be992f49133bad28c3ea744e` became
ACTIVE in deployment `0006d9a7-b0cb-490e-9764-4c1ebfe7d441` on September 24,
2026. Four focused tests, production build and no-database HTTP smoke in all
three modes passed. Live health and database reachability were true; anonymous
dashboard access returned 401. The original response status/restart cause and
the user's authenticated save remain unverified. Next step: retry the edit with
the new client and use its HTTP status if another interruption occurs.

- One in-process timer checks saved queries every minute, independent of browser
  traffic. Authenticated dashboard polling also nudges due work. Saved queries
  refresh at 5, 15, 30, 60 minutes, or daily.
- Claims are atomic in Postgres to avoid duplicate work across app instances.
  Connection/query revisions prevent stale in-flight results from overwriting
  edits. Failed refreshes preserve the last successful result and timestamp.
- Two outbound queries at a time per process; up to 24 saved queries. Member
  previews have a two-second throttle; forced refresh has a 30-second cooldown
  per query. Saving persists the definition immediately, independent of the
  preview job queue. A background refresh executes the saved query afterward.
- ES|QL source is limited to 16,000 characters. A final `LIMIT 101` bounds returned
  rows; the UI shows at most 100 and labels truncation. There is a 32-column limit,
  a 2 MiB response cap, and a 20-second HTTP request deadline. Preview jobs and scheduled refresh use async ES|QL with a five-minute execution budget; preview requests poll a private job record instead of holding a connection open. Large aggregations
  can still be expensive; use sensible index/time filters and Elastic-side limits.
- Warning-bearing or partial responses are rejected, preserving prior data.
  Table cell text is limited to 2,000 characters.
- TLS verification stays enabled. Redirects are not followed. Public IPv4 DNS
  results are pinned for each request, blocking loopback/private/link-local
  destinations and DNS rebinding. IPv6-only/private-network clusters are not
  supported by this first connection form.
- Mutation routes require both an organization member session and the expected Origin;
  credentials are never accepted in URLs. Audit records contain actor, action,
  query ID, and time only.
- `ELASTIC_VULN_ENABLED=false` hides the feature and stops automatic queries.
  `VULN_DISABLE_SCHEDULER=true` suppresses the timer in isolated test/staging apps.
  Sample mode retains the previous explicitly synthetic preview page.

## Validation

Production build / TypeScript checks passed. Contract tests cover query limits,
summary/table/null handling, incomplete results, public endpoint restrictions,
and encryption/tamper detection. A disposable local PostgreSQL 17 database was
used to verify persistence, no writes to scanner tables, retention after failure,
connection isolation, and in-flight edit races. HTTP smoke tests cover member/admin
authorization, cross-origin rejection, request size, feature flags, existing
dashboard/connectors routes, and the server-rendered query management controls.

Commands:

```text
npm run build
node --test tests/elastic-vuln.test.mjs
node --experimental-vm-modules --test tests/elastic-dashboard.test.mjs
node tests/elastic-vuln-smoke.mjs
```

Set `ELASTIC_TEST_DATABASE_URL` to a disposable loopback database named
`elastic_test` to include the PostgreSQL checks. The integration test drops its
own dashboard tables in that database and rejects non-loopback DB hosts.
Never point test commands at production.

Pending: a real API key is needed to verify the user's live query and reconcile
its numbers with Kibana. The app's HTTPS endpoint reachability was checked without
credentials, but authenticated Elastic results have not yet been verified.

References: [ES|QL REST API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-esql-query),
[Elastic API keys](https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys).

## Native charts (2026-09-24)

Native SVG bar, line, and doughnut charts use the existing ES|QL connection and
saved snapshots. No Kibana embedding or extra chart service is needed. Each query
can plot one numeric column against one category column. The optional `chart`
mapping is stored in the existing definition JSON; older cards/tables need no
migration and retain their display behavior.

- Return one row per category; duplicates and null category values are rejected.
  Aggregate explicitly with ES|QL `STATS ... BY`. Charts do not silently aggregate.
- Bar charts start at zero and support signed numbers. Line charts sort numeric
  and date axes and use proportional spacing; text categories retain query order.
  Null values remain missing and break lines. Doughnuts reject negative values
  and explain all-zero results. They show shares of the returned non-null values.
- Saved chart definitions and automatic refreshes validate the selected columns.
  Schema changes or invalid data preserve the last successful result with an error.
- Every chart includes an expandable data table, accessible SVG label, and point
  titles. Oversized bar charts/legends scroll. Truncated results are explicitly
  labeled as partial charts; the existing 100-row limit remains.
- For the supplied latest-open-finding priority query, replace the final
  P1-only aggregation with `STATS findings = COUNT(*) BY tier | SORT tier`, then
  choose `tier` and `findings` for a bar or doughnut chart. This shows P1/P2/P3
  because its preceding filter excludes Other. A single P1 count remains a card.
- Trend queries must return time buckets. The app does not infer historical
  open-finding totals from the latest snapshot or automatically store a trend.
- Validation includes SVG rendering, empty/null/negative/zero values, date order,
  duplicate/missing columns, and PostgreSQL persistence plus schema-change
  retention. Browser visual inspection was unavailable (no browser surface).
- Production commit `e169c2e9bab6a299397cba812b57f52d0ccb9c4d` deployed as
  `cd04b9cb-0e12-4ced-b760-bd92aed1a527` and reached ACTIVE on 2026-09-24.
  All nine contract/render/database tests, the production build, and three HTTP
  smoke modes passed. Live health returned 200 with database reachable; anonymous
  dashboard access redirected to login and its API returned 401.
- The disposable chart test database was removed. Automatic approval review
  blocked removal of `.next-before-native-charts-20260924115417`; this untracked
  local cache backup remains outside the release. No detailed reason was supplied.

## Production release evidence (2026-09-24)

- Production commit: `88292583598fe32dcb90b33eaeaa0de92a1dfa85` on
  `claude/vuln-site-design-vxswd6`; its tree matched the tested feature branch.
- DigitalOcean deployment `62e3ea1e-74bc-4749-975f-207af95b78f4` reached ACTIVE,
  with successful build and deploy steps.
- Live `/api/health` returned HTTP 200, `ok: true`, persistence enabled, and
  `dbReachable: true`. `/login` returned 200. The dashboard redirected anonymous
  requests to login (307), and its read API and connection mutation rejected
  anonymous requests (401).
- No dashboard refresh initialization errors appeared in the deployment's
  startup log. The disposable local test database container was removed.
- Signed-in browser interaction and authenticated live ES|QL results remain
  unverified. Next step: an organization member enters the read-only API key in
  Connection, tests/saves it, and compares the resulting coverage with Kibana.
- To roll back this release, revert the production commit through Git. Its three
  additive dashboard tables can remain; existing scanner tables were not migrated.

## Background query jobs (2026-09-24)

Preview returns 202 with an app job ID. GET `/api/elastic-dashboard/jobs/[id]`
requires the same organization member identity. Two active jobs maximum; jobs
expire after 15 minutes. Interrupted running jobs fail after seven minutes rather
than silently replaying a save. Queued jobs are picked up by a 15-second worker.
Connection and query revision checks prevent an older background save replacing
a newer edit. Refresh leases prevent overlapping automatic refreshes across app
instances. Completed results retain the existing last-success behavior.

### Immediate tile saving (2026-09-24)

POST `/api/elastic-dashboard/queries` now returns 201 with `{ saved: true, query }`
after the definition is committed. It does not execute a remote query or enqueue
a save job. Existing queued save jobs remain supported during deployment.
The form closes and the tile appears immediately; missing results show a loading
state, then data or a remote query error. Polling runs every three seconds while
new tiles await results and every 15 seconds otherwise.

Preview is optional, including for charts with manually entered column mappings.
**Stop waiting for preview** detaches UI polling; the bounded server preview may
still finish. It lets the user save without waiting for that preview. A saved tile
gets one initial background run even with automatic refresh off. Busy execution
slots leave the tile pending instead of reporting a query failure. Cosmetic edits
retain compatible cached results; query/population changes clear them. Revision
checks discard results from superseded definitions. Source connections and
existing dashboard tiles remain supported.

Validation: all 18 contract, mocked connector and disposable PostgreSQL tests
passed without skips. Added cases hold remote execution open while saving,
verify no save job is created, cover a paused tile's first run, busy execution
slots, cached cosmetic edits, superseded results, remote errors and CrowdStrike
history written only after collection. The production build and local HTTP
smoke checks passed in disabled, sample and database-backed modes. Authenticated
production browser interaction and live query duration remain unverified.

Release verification: production commit `f74046baf2c4d3ff49896d21edb6ec90dc16ae8e`
became ACTIVE in DigitalOcean deployment
`413e7947-d703-4231-a4d9-dee3345f521d` on September 24, 2026. Build and deploy
steps succeeded. Live health returned `ok: true` and `dbReachable: true`;
anonymous dashboard and private job APIs returned 401. The disposable test
database container was removed. Next check: a signed-in member adds a tile
without preview and observes its first live result or query error on the dashboard.

Elastic validation errors now include a bounded, key-redacted reason in private
responses; full response bodies and credentials are never logged. Connection tests
still use the small synchronous coverage query. The native chart editor includes
a 30-day last-known-open-status template and a Daily refresh option. Live external
query performance and data accuracy require the checks in the trend setup guide.

The user subsequently selected September 23, 2026 as the reporting start and
confirmed it was the last successful pull. The template therefore starts on that
date and uses September 24 midnight UTC as an exclusive cutoff. It initially
shows one daily point, deduplicates stable finding IDs, and uses earlier records
only for baseline state. Advance `report_end` after a verified later pull; the app
does not currently receive an import-completion watermark. See the setup guide.

### Background query release verification

- Async execution production commit `8a3d6a6cb057482306baa7e4cc0f7196e4b69a05`
  deployed as `39a06b65-2937-4f46-81c7-2ba738137c4d` and reached ACTIVE.
- September 23 template production commit
  `e7940f1e3f10aed7c20251e812bdb7a1f816d3c0` deployed as
  `7da3f039-f1b2-4bb2-898d-f505f74a8a99`; build and deployment succeeded and
  the deployment reached ACTIVE on 2026-09-24.
- All 11 contract, mocked Elastic protocol, and real PostgreSQL tests passed
  without skips. The production build and local HTTP smoke checks passed.
- After the final deployment, live health returned `ok: true` with the database
  reachable. Anonymous dashboard access returned 307; dashboard and private job
  APIs returned 401. The disposable test database was removed.
- Authenticated live ES|QL execution, source field compatibility, query duration,
  and reconciliation against CrowdStrike remain unverified. No signed-in browser
  surface was available. Complete the checks in `elastic-trend-setup.md` before
  treating the chart as an authoritative count.

## Modular query sources (2026-09-24)

The sidebar and page are now named Query Dashboard. The existing URL and Elastic
API routes remain compatible. A source registry dispatches Elastic ES|QL and
CrowdStrike FQL through the same jobs, saved tiles, refresh scheduler and charts.
Legacy definitions default to Elastic; CrowdStrike connection changes clear only
CrowdStrike caches, and Elastic connection changes clear only Elastic caches.

The first CrowdStrike dataset is Vulnerabilities. It supports finding counts,
unique CVEs, unique hosts, top groups and daily ungrouped history. See
[CrowdStrike setup and architecture](crowdstrike-dashboard.md) for scopes,
configuration, collection limits, priority rules, history semantics and validation.
The existing `ELASTIC_VULN_ENABLED` flag gates the combined dashboard; no production
environment change is required.

Rollback should preserve the source registry or hide CrowdStrike controls while
keeping its worker support. An older Elastic-only release cannot execute saved FQL
definitions. If a full code rollback is necessary, first back up and remove the
CrowdStrike query definitions/jobs from active dashboard tables, retaining their
snapshots and encrypted connection table for recovery. Do not feed FQL to Elastic.
