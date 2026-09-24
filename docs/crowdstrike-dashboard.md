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
5. Choose a measure, grouping and display, then **Add to dashboard**. The tile is
   saved immediately and results load in the background. Preview is optional;
   charts accept column names without waiting for a preview.

Example tiles:

| Tile | Measure | Group by | Display |
| --- | --- | --- | --- |
| Open findings | Finding count | None | Number cards |
| Affected hosts | Unique affected hosts | None | Number cards |
| Top affected hosts | Finding count | Host, top 10 | Bar, host/findings |
| Open severity distribution | Finding count | Severity | Doughnut, severity/findings |
| Open priority distribution | Finding count | GMI priority | Bar, priority/findings |
| Open findings over time | Finding count, Save daily history | None | Line, day/findings |

## Severity count cards (2026-09-24)

Add tile > CrowdStrike > **Use severity counts** > Add to dashboard. The preset
uses `status:['open','reopen']`, Number cards and Daily refresh. It displays
Critical, High, Medium, Low, None and Unknown together using CrowdStrike CVSS
severity (`cve.severity`), not ExPRT or the custom GMI priority rules. It counts
vulnerability instances, not unique CVEs. Suppressed findings are included unless
the user adds `+suppression_info.is_suppressed:false` to the filter.

The `severity-counts` view calls `/spotlight/queries/vulnerabilities/v1` once per
documented severity, with `limit=1` and the user filter parenthesized before ANDing
the severity predicate. Each card uses `meta.pagination.total`; returned IDs are
not collected or counted. This avoids the local 250,000-record collection limit.
Each total must be a nonnegative safe integer. Missing metadata or any API failure
rejects the complete refresh and preserves the last successful result. The six
requests are separate observations during the refresh, not an atomic snapshot.
No grouped/history/unique-CVE/host options are supported in this view. Summary
charts and patch worklists continue to use complete collection and its limits.

The endpoint, scope, severity enum and pagination total are described by the
[Spotlight API reference](https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/),
[FalconPy filter guide](https://github.com/CrowdStrike/falconpy/wiki/Spotlight-Vulnerabilities)
and [FalconPy response guide](https://developer.crowdstrike.com/sdks/python/responses/).
Live account response compatibility and totals require verification after adding
the preset. No authenticated production browser was available for this release.

Validation: all 32 tests passed without skips, including real disposable
PostgreSQL checks, malformed/missing totals, a failed severity request, preserved
FQL OR grouping, zero counts and counts above 250,000. Production build and the
disabled/sample/database-backed HTTP smoke checks passed. Commit
`215d5f1278d8ad4c289cf19bb07f9ae0bc06cce6` reached ACTIVE in DigitalOcean deployment
`82ab2394-b3eb-4ad7-a6ee-312de89d9b21` on September 24, 2026. Live health and
database reachability passed. The disposable test container was removed.

The simultaneously reported Elastic tile loading issue remains unconfirmed:
startup logs show no refresh errors, health is good, but no signed-in browser
was available and the native CLI console could not obtain a terminal size.
The user was asked for the exact tile status/error. Saved refreshes are serial,
so long queries can delay later tiles; this is a possible contributor, not a
confirmed diagnosis. No production saved queries or connection settings changed.

## CVEs by affected devices (2026-09-24)

The user requested a saved table directly, not another Add tile preset. The new
`cve-devices` view supports one row per CVE with severity, unique affected devices,
open finding count, CVSS and CISA KEV. Devices are keyed by tenant and host ID;
multiple affected applications on a device count once for that CVE. Missing host
IDs fail the result; records without CVE identifiers are excluded and disclosed.
Rows sort Critical, High, Medium, Low, None, Unknown, then device count descending,
then CVE ID. The requested tile uses the top 100, open/reopened findings including
suppressed findings, and daily refresh. Existing internal scrolling and CSV apply.

To avoid collecting over two million records for a severity-first top 100, the
client completes one severity at a time with the CVE detail facet only. It stops
after a completed severity fills the requested row count; lower severities cannot
displace those rows. It never takes the first N findings as a CVE ranking. The
existing complete-pagination checks, per-severity 250,000-record cap, five-minute
budget and cached-result retention still apply. A finding moving between severity
groups fails the refresh. API pages are observations, not an atomic snapshot.

Live volume check: saved severity counts showed 74,912 Critical findings. A
read-only sample of 1,500 Critical findings already contained 123 distinct CVEs;
this confirms that a top-100 table is filled from the Critical group in that
observation, but is not itself the complete ranking. No new preset button was
added. A server-side edit option preserves the saved view during later edits.

## Patch worklist

Add query > CrowdStrike > **Use patch worklist** > **Add to dashboard**. Preview
is optional. The preset uses Table, top 25 findings, daily refresh, and this FQL:

```text
status:['open','reopen']+suppression_info.is_suppressed:false
```

The app applies the existing GMI P1/P2/P3 policy after collecting every matching
page. It orders open/reopened P1–P3 findings by priority, descending GMI risk
score, then descending affected devices for the CVE, with stable ID tie breaks.
Top 10/25/50/100 selects rows after ranking; it does not limit collection to an
arbitrary first page. Each row is a finding on a device, not a patch package or
a unique CVE. A single patch may resolve several rows.

Columns include priority, risk score, CVE, device, affected devices for the CVE,
severity, ExPRT, CVSS, KEV, exploit status, status, source update time, host ID,
tenant ID and finding ID. Device counts cover the eligible P1–P3 population in
the chosen filter, deduplicate multiple findings on a host, and distinguish
tenants. Missing KEV/CVSS/exploit values remain null. Missing host IDs fail the
worklist instead of producing ambiguous patch targets. Lower-priority and
closed findings are excluded by the worklist view even with a broader FQL.

Suppression exclusion is explicit in the preset FQL; editing it changes that
scope. No updated-time filter is imposed, so older open findings stay eligible.
The risk policy is GMI's policy, not a native CrowdStrike score. This view does
not fetch patch commands or remediation entities; use the CVE/finding ID to
check vendor remediation in Falcon. The existing API permissions suffice.

Use **CSV** on a completed tile to export its displayed rows for the patching
team. Exports contain the cached result and the same top-row limit, not the
entire matching population. Formula-like source strings are escaped for
spreadsheet safety. Broad filters still use complete pagination and the existing
five-minute collection budget; the tile saves immediately while collection runs.

The query fields and status values are documented in the official
[Spotlight API reference](https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/)
and [FalconPy filter guide](https://github.com/CrowdStrike/falconpy/wiki/Spotlight-Vulnerabilities).

FQL selects the records; the app aggregates the selected population. Counting
findings, CVEs and hosts gives different answers. All statuses returned by the
filter count; include open/reopen in the FQL when building open-finding tiles.
Suppression filtering is explicit, not silently imposed. Host groups are keyed
by tenant and host ID; labels include the hostname and IDs to distinguish devices
with the same name. Unique CVEs and hosts can occur in multiple groups, so grouped
unique counts must not be added to obtain the global unique count. Top-N is applied
after complete collection and aggregation, and the tile labels how many groups it
shows. The Patch worklist view adds ranked finding rows; arbitrary API endpoint
entry is not supported.

## Daily history

Enable **Save daily history of the total** for an ungrouped measure. First preview
shows a candidate point but writes nothing. The first successful background run and subsequent successful
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
`facet=cve&facet=host_info`, limit 500 and the returned `after` cursor. It fetches full
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
dashboard reads cached results and nudges due refreshes. Two preview jobs can be
queued/running at once; adding a tile does not wait for that queue. Remote failures
appear on the saved tile. Query execution itself can still take up to five minutes.

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

Facet encoding correction (September 24, 2026): production returned HTTP 400
"Unknown facet" because the connector sent `cve,host_info` as one facet value.
The connector now appends separate `facet=cve&facet=host_info` parameters on
every page. The one-record connection check requests the same facets. This
matches the `multi` collection format in the official
[Go SDK request serializer](https://github.com/CrowdStrike/gofalcon/blob/main/falcon/client/spotlight_vulnerabilities/combined_query_vulnerabilities_parameters.go).
The regression check failed before the fix; all 11 connector tests passed after
it, including pagination and worklist collection. The production build and HTTP
smoke passed in all three modes (no database configured for this smoke run).
No stored query, credential, or schema changes are needed. Retry a failed saved
tile with Refresh, or add the draft without preview. Authenticated live query
execution remains unverified from the development environment.

Facet fix release: commit `f221d3f0881e0739ff50bf553ebde67534e06c61` became ACTIVE
on September 24, 2026 in deployment `eab8f5da-cc40-4de4-bd6c-dca4333ba7ab`.
Build and deploy succeeded; live health and database reachability were true.
Anonymous dashboard API access remained 401. Next verification is a signed-in
retry of the user's failed CrowdStrike tile; no production credentials were read.

Patch worklist and tile deletion validation (September 24, 2026): all 21 tests
passed without skips, including full-page ranking, duplicate device counting,
tenant separation, missing fields, unchanged risk boundaries, CSV escaping,
delete-versus-refresh/save races, history cleanup and deleted default seeding.
The production build and local HTTP smoke passed in disabled, sample and
database-backed modes, including member authorization and same-origin deletion.
Live authenticated CrowdStrike execution and signed-in browser interaction
remain unverified; compare the first worklist with Falcon using the same filter.

Production commit `dcfe04d4a18f3d9cf79ba2b9519b0d0fb486fc74` became ACTIVE on
September 24, 2026 in DigitalOcean deployment
`77e39579-8d94-4fa4-99ba-3cce6bf53e54`. Build and deploy steps succeeded; live
health and database reachability were true. Anonymous dashboard GET and tile
DELETE requests returned 401. The disposable test database was removed. Next
step: create the preset in the signed-in dashboard and reconcile with Falcon;
the release does not create or delete any production tile automatically.

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
