# Customer-scoped Elasticsearch tiles

Checkpoint 47 adds optional runtime scoping for saved Elasticsearch tiles on `Vuln2.0`. Nothing here enables it in production. Existing tile definitions, results, permissions, source credentials and CrowdStrike routes are retained.

## What the customer sees

The current customer selector still owns new tiles and previews. Saving a tile remains immediate; it does not wait for a source query. When reviewed Elastic routing is enabled, a customer can query only its approved datasets. Customers without an approval cannot use the shared Elastic connection merely because it exists.

The server restricts each `FROM` pattern to that customer's approved dataset list. For example, `FROM logs-*` with approval for `logs-alpha` reads only `logs-alpha`. Every pattern must match at least one approved dataset; `FROM logs-*, foreign-index` fails. A result note explains this restriction. The saved query itself is not rewritten in the database.

Old results remain stored when approval changes, but are withheld from the dashboard and completed preview jobs until refreshed under the current approval. This does not erase historical data or imply an old count is zero. Revoking Elastic approval does not invalidate an independent CrowdStrike approval.

## Supported scope

- One existing encrypted saved dashboard Elastic connection, with a separate approval per customer.
- One to 100 exact, lowercase index or data stream names per approval. Each entire dataset must belong exclusively to that customer. No wildcard, alias, remote-cluster or backing-index names in approvals.
- `query-only` authority, with no tenant ID or target filter. This adapter cannot safely split a dataset containing several customers. Such sources need a reviewed document-filter contract or customer-restricted credentials and an appropriate adapter before activation.
- Elastic Stack deployments only. Serverless cross-project search is not supported by this adapter. The check uses the build flavor reported by the documented [cluster info API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-info).
- One `FROM`, optional metadata fields, and `WHERE`, `EVAL`, `STATS`, `KEEP`, `DROP`, `RENAME`, `SORT`, `LIMIT`, `MV_EXPAND`, `DISSECT` and `GROK` pipelines. Quoted pipes and line comments are handled. Joins, enrichment, subqueries, external sources, block comments, triple-quoted strings and other unsupported syntax fail before a vendor query runs. This is a deliberately restricted adapter, not a full ES|QL parser.

These restrictions preserve the bundled coverage and unique-CVE severity queries. A query using a shared index, a join or another unsupported feature stays saved and displays an explicit error; there is no unscoped fallback.

## How execution works

1. Resolve the selected/saved customer and current reviewed binding, operational approval and saved connection revision.
2. Validate the restricted pipeline and intersect the requested source patterns with the approved exact dataset names.
3. Check Elastic deployment metadata, then resolve the selected names. Reject missing datasets, aliases, remote identities, closed indexes, direct data-stream backing-index approvals and malformed/ambiguous responses.
4. Run the query against only the returned physical index names. A data stream cannot expand a second time during the query. Rollover after collection starts appears at the next refresh. Expansion is limited to 500 physical indexes and the existing 16,000-character query limit.
5. Retain existing result-size, partial-result, timeout and asynchronous cleanup safeguards. Recheck approval after collection; stamp the cached result with the approval identity.
6. Recheck the current proof when reading cached tiles and background results. No upstream metadata or data query is made merely to display a cached tile.

The implementation uses Elastic's documented [index resolution API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-indices-resolve-index), which requires `view_index_metadata`. The connection must also have the read permissions needed for the approved physical indexes. ES|QL's [FROM command](https://www.elastic.co/docs/reference/query-languages/esql/commands/from) can reference more source types than this adapter allows; those features are deliberately outside this first reviewed contract.

In reviewed mode the connection form tests deployment metadata before saving a replacement key; it no longer runs the Atlas coverage query as its credential test. This does **not** certify index permissions, dataset ownership or data completeness. Those must be checked before activation.

## Storage and operator preparation

| Item | Storage / purpose |
| --- | --- |
| Credential | Existing encrypted `elastic_dashboard_connection`, in the dashboard database. No new key copy. |
| Source evidence and review | Existing drafts/bindings in the application database. Connection changes invalidate the review. |
| Operational approval | Existing `customer_query_routes` and audit, extended by [v2 migration](sql/customer-query-routes-v2.sql). Exact datasets are private scope data. |
| Definitions and cached results | Existing `elastic_dashboard_queries`; original query text and old results are retained. |
| Preview jobs | Existing `elastic_dashboard_jobs`, with current scope-proof checks before returning results. |

Apply v2 only after the original query-route migrations. It preserves existing CrowdStrike approvals, proof identities and audit records. It changes the active-customer uniqueness rule to one approval per provider/customer and adds exact dataset validation plus overlapping-dataset rejection. It seeds no approvals and changes no finding or source data.

Use the existing registry import, customer binding export/assignment, `route-query` and `export-query-routes` commands. The Elastic candidate is the shared saved connection `dashboard:elastic_dashboard_connection:1`; use `authority: "query-only"`, `tenantId: null`, exact `datasets` and empty `targets`. Do not approve a tile candidate or the separate AppSec environment connection as if it were this source. Exports omit private dataset names and do not overwrite prior files.

`VULN_REVIEWED_QUERY_PROVIDERS` now accepts `elastic`, `crowdstrike`, or `crowdstrike,elastic`. Each provider is independent. Empty means legacy behavior; invalid nonempty values fail closed. Review alone does not turn a provider on. Existing permissions to edit connections and tiles are unchanged; no new customer selector or member configuration control is introduced.

Before production activation: verify actual dataset ownership and Elastic version/API behavior, test the key's metadata/read permissions, review every affected tile, drain jobs and automatic workers, preserve recovery evidence, then activate as part of the combined release. No live dataset approval was inferred from a name or tested in this checkpoint.

## Limits and recovery

Dataset ownership remains an operator assertion. Resolution proves that an approved name resolves to an index/data stream, not that every document belongs to the customer. Importers and Elastic administrators must keep those datasets exclusive. The guards are not a replacement for Elasticsearch security boundaries or controls on upstream administrators. Physical index deletion/recreation, credential/routing changes and query execution are not one distributed transaction; drain operations before ownership changes.

Turning the switch off restores legacy behavior and is not emergency revocation. Disable the relevant route while enforcement remains on to withhold new reviewed operations. Keep approvals, audit and cached data on rollback; do not reverse the schema by deleting records. Older code cannot interpret the new Elastic provider setting, so a code rollback requires reviewing the switch and legacy visibility.

A stale active route withholds that provider's reviewed route set until repaired or disabled. Non-selected providers remain independent. The original shared credential still exists; this does not introduce customer-specific key storage.

This checkpoint covers saved dashboard queries only. Elastic scanner export, organization AppSec, source authority/mirror deduplication, stored-platform CVE consumers, SQL reporting cutover and the authoritative writer handoff remain separate work. Query approval does not publish normalized findings or make mirrored Elastic/CrowdStrike counts additive. See the [platform change plan](platform-change-proposal.md) for validation and remaining release gates.
