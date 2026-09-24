# CrowdStrike query tiles

The existing Query Dashboard now supports two sources: Elasticsearch ES|QL and
CrowdStrike FQL. Existing Elastic definitions without a source field continue to
use Elasticsearch. The URL remains `/elastic-vulnerabilities`; the sidebar label
is **Query Dashboard**. Existing scanner connectors are independent.

## Connect and create a tile

1. In Falcon's API Clients and Keys page, create a client with
   **Vulnerabilities: Read** (`spotlight-vulnerabilities:read`) and note its cloud
   region. The subscription must provide access to the vulnerability API.
2. Open Query Dashboard > Connection > CrowdStrike. Enter the region, client ID,
   and secret, then Test and save connection. This reads at most one finding to
   verify access. Credentials are encrypted and never returned by the dashboard.
3. Add query. Select CrowdStrike and the Vulnerabilities dataset.
4. Enter a one-line FQL filter, such as `status:['open','reopen']`.
5. Choose a measure, grouping and display, then Preview results and Save query.

Example tiles:

| Tile | Measure | Group by | Display |
| --- | --- | --- | --- |
| Open findings | Finding count | None | Number cards |
| Affected hosts | Unique affected hosts | None | Number cards |
| Top affected hosts | Finding count | Host, top 10 | Bar, host/findings |
| Open severity distribution | Finding count | Severity | Doughnut, severity/findings |
| Open priority distribution | Finding count | GMI priority | Bar, priority/findings |
| Open findings over time | Finding count, Save daily history | None | Line, day/findings |

FQL selects the records; the app aggregates the selected population. Counting
findings, CVEs and hosts gives different answers. All statuses returned by the
filter count; include open/reopen in the FQL when building open-finding tiles.
Suppression filtering is explicit, not silently imposed. Host groups are keyed
by tenant and host ID; labels include the hostname and IDs to distinguish devices
with the same name. Unique CVEs and hosts can occur in multiple groups, so grouped
unique counts must not be added to obtain the global unique count. Top-N is applied
after complete collection and aggregation, and the tile labels how many groups it
shows. There is no raw-finding browser or arbitrary endpoint field in this release.

## Daily history

Enable **Save daily history of the total** for an ungrouped measure. First preview
shows a candidate point but writes nothing. Save and subsequent successful
refreshes upsert the last observation per UTC day. The chart shows up to 90 days;
stored snapshots older than 365 days are pruned on a successful history write.
Missing days are null gaps, never zeros. Empty, fully collected result sets are
valid zero counts. Failed or incomplete pulls preserve the last good result and
do not create history. This measures observed state during collection, not an
atomic point-in-time inventory or every transition between collections.

History is isolated by tile ID, connection revision, and a hash of source,
dataset, filter, measure and grouping. Changing the population shows a separate
series; returning to a previously used filter can show its retained series.
Title, display and refresh changes preserve history. Replacing the connection
clears only CrowdStrike caches and starts a new series, including when merely
rotating credentials. Daily scheduling is 24 hours after completion; manual
Refresh can collect sooner. No manual Elastic report-end date is involved.

The direct API does not backfill September 23 history. Historical backfill needs
separately validated retained data; this implementation starts with the first
successful saved collection. A daily chart initially has one point.

## Connector architecture

- `lib/dashboard-query-connectors.ts`: source registry; each connector opens its
  own credential format and executes a query into the common `QueryResult`.
- `lib/crowdstrike-dashboard.ts`: dataset registry, normalizer, shared aggregation
  and GMI priority policy. Only Vulnerabilities is implemented. Future Hosts and
  Discover adapters require their endpoints, scopes, schemas and UI fields once;
  additional tiles on an existing dataset need only configuration.
- `lib/crowdstrike-dashboard-client.ts`: allowlisted Falcon cloud origins, OAuth,
  bounded response reads, pagination and errors. The browser never calls Falcon.
- Existing dashboard query tables, private job polling, revision checks, refresh
  leases and chart renderer are reused. Additive tables are
  `dashboard_source_connections` and `dashboard_daily_history`; existing scanner
  data and the Elastic connection are not migrated.
- Existing signed-in organization-member management and same-origin mutation
  checks apply to the new connection endpoint. Secrets use AES-256-GCM with a
  distinct HKDF context derived from `NEXTAUTH_SECRET`.

The first connector calls `GET /spotlight/combined/vulnerabilities/v1` with
`facet=cve,host_info`, limit 500 and the returned `after` cursor. It fetches full
matching current findings on each refresh, not daily diffs. No n8n is involved.
It deduplicates by tenant + finding ID and picks the later update when ordered
duplicates differ. Conflicting unordered duplicates fail rather than guessing.
The total-count check, missing cursor check, repeated cursor check, page errors,
oversize responses and limits reject partial results.

Collection has a five-minute budget, 20-second per-request deadline, 8 MiB maximum
response page, and caps of 500 pages / 250,000 received records. HTTP 429 and 5xx
responses retry up to twice with bounded waits (honoring Retry-After up to 30
seconds). Rate limits or larger populations require a narrower filter or a future
shared collection service. Each tile currently collects independently, so start
with Daily refresh and avoid many broad filters every five minutes. Opening the
dashboard reads cached results. Two jobs can be queued/running at once.

This version uses one shared CrowdStrike credential context. It does not enumerate
Flight Control child tenants or impersonate a member CID. Multi-tenant delegation
requires a separate adapter extension and explicit tenant selection.

## GMI priority policy v1

This mirrors the user's Elastic formula; it is not CrowdStrike's own priority.
Risk points: exploit status >=90/60/30 contributes 30/22/10; KEV adds 20; ExPRT
Critical/High/Medium/Low adds 20/15/7/2; CVSS contributes up to 15 (score x 1.5);
exploitability contributes up to 10 (score x 2.5); severity Critical/High/Medium
adds 5/3/1. The sum is rounded to one decimal.

- P1: exploit status >=90 or KEV.
- P2: ExPRT Critical, severity Critical, CVSS >=9, exploit >=60 with severity at
  least High or CVSS >=7, or risk >=65.
- P3: ExPRT High, severity High, CVSS >=7, exploit >=30 with exploitability >=3,
  or risk >=40.
- Otherwise Other. Rules are evaluated in that order. Missing risk fields
  contribute no points; an unknown severity remains UNKNOWN in severity grouping.

## Validation and rollout

Mocked API tests cover filter validation, fixed origins, credential encryption,
pagination, deduplication, counts, tenant separation, policy boundaries, incomplete
responses, rate-limit retry and redacted errors. Real disposable PostgreSQL tests
cover connection isolation, job ownership, queued saves, history upsert/gaps,
filter changes, stale-result retention and connection-change races.

Authenticated live CrowdStrike validation requires the organization to connect
its API client in the UI. Reconcile the first result with Falcon using the same
filter, tenant scope and suppression settings before relying on it. Live field
compatibility, account entitlement, scale and API rate limits cannot be certified
with mocked responses. No secret should be pasted into chat or committed.

References:
- https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/
- https://developer.crowdstrike.com/api-reference/falcon-query-language/
- https://github.com/CrowdStrike/CrowdStrike-Spotlight-Humio-Package-Integration

Next step: connect the read-only client in the app and validate a small open
findings tile, then the full open-findings count and daily history.

### Release checks, 2026-09-24

- All 18 tests passed with zero skips, including the disposable PostgreSQL tests.
- `npm run build` passed with TypeScript validation. OneDrive's local `.next`
  cache was locked, so validation used a temporary source copy with a clean
  `npm ci`; hashes of all changed runtime files matched the workspace afterward.
- Production-build HTTP smoke tests passed for disabled, sample and empty modes,
  covering session checks, organization members, same-origin mutations, existing
  routes, and the new CrowdStrike connection endpoint.
- No browser surface was available for interactive visual verification. No live
  CrowdStrike credentials were read, and account-specific collection remains to
  be verified after entering the API client in the connection form.
- Production commit `6de5790626178bba3c83e114eb51a2b9429c4b06` deployed as
  `beeba383-2510-4cda-b07a-e4dac4c742f5`; DigitalOcean build/deploy succeeded and
  the release reached ACTIVE on 2026-09-24.
- Post-deployment health returned `ok: true` and database reachable. Anonymous
  dashboard access returned 307; dashboard/job APIs and the new connection POST
  returned 401. Startup logs contained a ready marker and no dashboard worker
  failure messages. The disposable test database container was removed.
