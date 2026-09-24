# Direct ES|QL dashboard

The user selected direct queries in GMI Vuln instead of n8n on 2026-09-24.
This is the current architecture; the earlier n8n workflow remains inactive and
is not required. Production release follows the user's previously authorized
direct-deployment workflow.

## Using the dashboard

Open **Elastic Dashboard** at `/elastic-vulnerabilities`.

1. A signed-in organization member opens **Connection**, enters the Elasticsearch HTTPS
   endpoint and encoded read-only API key, and clicks **Test and save connection**.
   A Kibana `.kb.` address cannot be used as the Elasticsearch API address.
2. The supplied asset coverage query is already saved. Connection verification
   runs that query to check both authentication and access to its indices.
3. Click **Add query**, enter a title and ES|QL, then **Preview results**.
4. Choose **Automatic**, **Number cards**, **Table**, **Bar chart**, **Line chart**,
   or **Doughnut chart**, select a refresh interval,
   then save. Automatic turns a single numeric row into one number card per
   column; other shapes use a table. `_pct`, `_percent`, and `percentage` column
   suffixes render numeric values as percentages. Use ES|QL aliases for labels.
   For charts, preview results and select **Category / X axis** and the numeric
   **Value / Y axis**. Two suitable columns are suggested automatically. Editing
   the query clears these mappings; preview again to choose its new columns.
5. Each saved query has **Edit**. Disabling its automatic-refresh checkbox pauses
   background refresh and leaves the last result visible. Editing/saving always
   validates the new query once, including when automatic refresh is paused.

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

The dashboard uses three new tables only: `elastic_dashboard_connection`,
`elastic_dashboard_queries`, and `elastic_dashboard_audit`. They use
`ELASTIC_VULN_DATABASE_URL` when set, otherwise the existing application database
pool. Scanner snapshot tables, existing settings, and connector data are not
changed. Tables are initialized automatically, with the default coverage query
inserted only if missing. The database role therefore needs CREATE/SELECT/INSERT/
UPDATE rights. The existing app database transport configuration is inherited.

## Execution and safeguards

- One in-process timer checks saved queries every minute, independent of browser
  traffic. Saved queries refresh at 5, 15, 30, or 60 minutes.
- Claims are atomic in Postgres to avoid duplicate work across app instances.
  Connection/query revisions prevent stale in-flight results from overwriting
  edits. Failed refreshes preserve the last successful result and timestamp.
- Two outbound queries at a time per process; up to 24 saved queries. Member
  previews/saves have a two-second throttle; forced refresh has a 30-second
  cooldown per query. Preview and save each execute the query.
- ES|QL source is limited to 16,000 characters. A final `LIMIT 101` bounds returned
  rows; the UI shows at most 100 and labels truncation. There is a 32-column limit,
  a 2 MiB response cap, and a 20-second HTTP request deadline. Large aggregations
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
