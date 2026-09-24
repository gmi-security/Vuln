# Open-vulnerability trend with daily CrowdStrike diffs

## What is ready in GMI Vuln

Preview and Save enqueue background jobs and return immediately. The UI polls
their status every three seconds. Elasticsearch runs ES|QL through `/_query/async`
for up to five minutes; individual HTTP requests still have a 20-second limit.
Automatic refresh uses the same async client and keeps the previous successful
snapshot on failure. No n8n workflow or DigitalOcean environment change is needed.

The app retains at most two active preview/save jobs, with one worker per process.
Job records expire after 15 minutes. Interrupted running jobs fail after seven
minutes and can be retried; they are not silently resubmitted. Queued jobs resume
on the next worker tick after restart. Elasticsearch jobs are deleted on completion
or timeout and have a ten-minute expiry if cleanup cannot reach Elasticsearch.
Connection testing remains a synchronous execution of the small coverage query.

Open Elastic Dashboard, hard-refresh with Ctrl+Shift+R, then:

1. Add query > **Use daily open trend**.
2. Preview results and wait for the background query to finish.
3. Set Line chart, category `day`, and numeric value `open_vulns`.
4. Check the result table: investigate any nonzero `unknown_status` before treating
   the open count as complete. Unknown status is not assumed to mean closed.
5. Save. The template defaults to Daily refresh. The timer runs 24 hours after
   completion, not on a CrowdStrike import-complete signal. First save/refresh it
   after a successful daily import, or use manual Refresh after later imports.

The copyable query is in `queries/elastic/open-vulnerabilities-history.esql`.
It counts all severities, not only P1/P2/P3. It groups historical records into the
last change per finding per UTC day, collapses older records into a starting state,
and carries the last status forward. A finding closed and later reopened is counted
on the appropriate days, provided both changes exist in the retained source.
Today is measured as of query execution. Earlier points use the last state before
the next UTC day. No start/end parameters from Kibana are needed.

The graph means **last known status in the retained data**. Daily polling cannot
reconstruct intermediate transitions that happened between pulls and were never
delivered. Tied timestamps with conflicting statuses need an authoritative event
sequence; this query's string tie-break is not a substitute for one. Days before
the first known finding are omitted rather than invented as zero.

## What the Elastic/CrowdStrike owner needs to verify

These checks cannot be certified from the local app source or unauthenticated
cluster access. The app's saved key stays encrypted; do not paste it into chat.

### 1. Elasticsearch version and permissions

In Kibana > Dev Tools, run `GET /` and read `version.number`. ES|QL async APIs are
available from Elasticsearch 8.13. If the endpoint returns 403, ask the Elastic
administrator to check the version rather than broadening the dashboard key.

The dashboard API key needs `read` on these source patterns (adjust names if the
actual source differs). `view_index_metadata` permits the field checks below:

```json
{
  "cluster": [],
  "indices": [{
    "names": [
      "logs-crowdstrike.discover_asset-*",
      "logs-crowdstrike.vulnerability-*"
    ],
    "privileges": ["read", "view_index_metadata"]
  }]
}
```

This is a role descriptor to use when creating/restricting a key in Elastic,
not a command to paste into the dashboard. The same key submits, reads, and
deletes its own async queries; it does not need `manage`, `manage_transform`,
index write privileges, or cluster-wide cancellation privileges.

### 2. Field mappings and stable finding identity

Run this in Kibana Dev Tools:

```http
GET logs-crowdstrike.vulnerability-*/_field_caps?fields=@timestamp,event.id,crowdstrike.vulnerability.status
```

Confirm consistent date mappings for `@timestamp`, aggregatable keyword mappings
for `event.id`, and usable status mappings across the selected indices. Resolve
mapping conflicts in the source template/new indices with the Elastic owner.
Do not delete indices or change existing mappings as an initial troubleshooting step.

Check the collector configuration or a known finding's history:

- The user confirmed on 2026-09-24 that `event.id` is stable over time, so the
  supplied query keeps that grouping key. For multiple tenants, include tenant
  ID as well if finding IDs can collide between tenants.
- `@timestamp` orders status changes correctly. If it represents ingestion time,
  the graph is an observed-state trend. For an effective-time trend, use the
  verified source status-update timestamp consistently throughout the query.
- Each diff record includes its resulting status; `open`, `reopen`, and `closed`
  match the values the collector actually sends. Partial patches with omitted
  status require merging into maintained state before querying.
- Closure and reopen events are collected. Disappearance from a diff is not closure.

### 3. Baseline and retention

Confirm there is a retained full baseline plus subsequent changes for the whole
reporting period, including findings that were already open before it began.
An oldest-record date alone does not prove that the baseline is complete.

If the baseline is missing, use the CrowdStrike collector's documented full
inventory sync/export to establish current state with the same finding IDs, then
continue applying diffs. Do not reset a polling cursor blindly. The collector
owner must confirm its full-sync procedure; the current app does not control it.
Older history cannot be recovered from today's inventory alone. Recover retained
change archives or start reporting from the validated baseline date.

A latest-state index can preserve current state as raw diff logs expire, but it
does not by itself retain historical close/reopen intervals. For historical
reporting retain the event history or store daily count snapshots after confirmed
imports. Preserve unchanged open findings in that state index; do not apply a
last-seen retention rule that drops them merely because they have not changed.

### 4. Reconcile and tune

After the daily import finishes, compare today's total with CrowdStrike using
the same tenant scope, statuses, suppression rules, and finding identity. Compare
several known closed/reopened findings across dates. The app build/tests verify
execution mechanics, not the completeness of the external data.

If the 30-day query exceeds five minutes, try a seven-day copy: change `29 days`
to `6 days` and offsets to `[0,1,2,3,4,5,6]`. This reduces row expansion but still
reads the retained baseline. Never simply filter raw records to the last seven
days; that loses unchanged older open findings.

For sustained slow queries, ask the Elastic owner to inspect query/cluster load
and prepare a compact baseline plus daily status-change index or daily totals.
The app can consume that index once the key has read access. An exact transform
or backfill must be based on verified field mappings, update semantics, retention,
and stable IDs; a generic latest transform alone cannot recreate past intervals.

References:
- https://www.elastic.co/docs/api/doc/elasticsearch/v8/operation/operation-esql-async-query
- https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-esql-async-query-get
- https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-esql-async-query-delete
