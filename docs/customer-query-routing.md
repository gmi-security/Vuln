# Customer-scoped saved CrowdStrike queries and patch requests

For the checkpoint 47 Elasticsearch extension, see [customer dataset routing](customer-elastic-query-routing.md). Its provider switch can enable Elastic and CrowdStrike independently.

This is the checkpoint 46 implementation guide for Vuln2.0. It is not a production activation instruction. The new behavior is opt-in; existing credentials, roles, tiles, findings, tickets and source storage are preserved.

## What changes

The saved dashboard CrowdStrike connection previously determined API visibility, while a tile's customer assignment determined where it appeared. A customer label did not independently restrict the upstream FQL query.

With `VULN_REVIEWED_QUERY_PROVIDERS=crowdstrike`, the selected customer must have a current reviewed binding and a separate operational query approval. That approval identifies the saved connection revision and one exact CrowdStrike CID. The server wraps the user filter in a CID conjunction and rejects missing or foreign CIDs in returned entities. It never substitutes an environment Falcon credential or falls back to an unscoped query.

The existing customer selector supplies ownership for previews and single-CVE preparation. Saving a tile still saves immediately without waiting for vendor validation or a remote query. No additional customer selector or configuration permission is introduced.

## Sources and storage

| Data | Location and purpose |
| --- | --- |
| Saved CrowdStrike credentials | Existing encrypted `dashboard_source_connections` record, in the dashboard database. Revision changes invalidate the review. |
| Customer and connection evidence | Existing application metadata, `customer_connector_drafts` and `customer_connector_bindings`, in `DATABASE_URL`. |
| Query authorization | New `customer_query_routes` and `customer_query_route_audit`, in `DATABASE_URL`. Approvals and revisions are distinct from inventory and Spotlight import approvals. |
| Tile definitions and last results | Existing `elastic_dashboard_queries`; reviewed results receive a server-generated `scopeKey`. |
| Background results | Existing `elastic_dashboard_jobs`; approval is checked before returning newly collected results and again when a job is read. |
| Daily observations | Existing `dashboard_daily_history`; reviewed history signatures include customer and approval identity. Legacy signatures remain unchanged. |
| Prepared patch requests and tickets | Existing patch request/group tables. Live CrowdStrike packets carry customer, CID, connection revision and approval proof. |

The dashboard database can be `ELASTIC_VULN_DATABASE_URL` or the application database. Metadata reads release connections before acquiring another connection. No normalized platform writer or SQL reporting cutover occurs here.

## Query behavior

1. Resolve the tile's assigned customer, including existing explicit legacy tile mappings.
2. Check current source evidence, reviewed binding, separate query approval and saved connection revision.
3. Add `cid:'approved-cid'+(user-filter)` on the server. Balanced strings and grouping are required so the supplied filter cannot escape the conjunction.
4. Verify returned entity CIDs on every collected page, including severity/ExPRT ranking branches.
5. Recheck approval after collection and stamp the result with its approval identity.
6. Show a cached result only when its proof matches the current approval. Old results remain stored when an approval changes; the page shows an explicit waiting/review message instead.

Daily and severity totals use the combined vulnerability endpoint with a one-record page and its population total. This avoids collecting millions of entities just to count them. The one returned entity must match the CID; a zero total must return no entities. This sample is not independent proof of every counted record. Severity buckets remain separate API observations, not an atomic snapshot. The deployed API's filtering and count behavior still require live acceptance.

CrowdStrike documents the CID filter and combined endpoint in its [official Spotlight API reference](https://docs.falconpy.io/Service-Collections/Spotlight-Vulnerabilities.html). Public documentation is not verification of a customer's credentials, deployed response contract or tenant ownership.

## Patch and ticket behavior

Single-CVE and consolidation collection use the approved CID, even if the saved credential can see multiple tenants. A supplied CID must agree with the selected customer. Existing ticket jobs that supply an exact CID may resolve its one approved owner. Collected host identities and represented tenants must match that CID.

Prepared live packets retain the approval proof. New ticket creation checks that proof before queueing delivery and again before the ConnectWise creation POST. Fix verification also checks the packet, device scope and current approval, then rechecks after collection. Older unscoped live drafts must be prepared again when this mode is enabled. Existing ticket records, CSVs, attachment recovery, duplicate protection and references remain available.

Stored-platform/manual patch packets retain their existing source path and protections. This checkpoint does not claim those paths have migrated to the new query approval model. ConnectWise customer/board selection and delivery permissions are unchanged; this is a CrowdStrike source-scope guard, not a replacement for ConnectWise routing validation.

## Eventual operator workflow

Before activation, drain query/patch jobs and automatic ticket/verification workers, preserve recovery evidence, and verify every CID independently. Inspect the running environment as well as environment files.

1. Apply the existing draft/binding, inventory v1/v2 and Spotlight migrations, then [customer query routes](sql/customer-query-routes.sql) to the application database. No approvals are populated. The new triggers prevent query, inventory and Spotlight approvals from assigning the same CID to different customers.
2. Import fresh connection evidence with the existing registry command. Export that customer's bindings. Review the shared configuration candidate whose connection reference is `dashboard:dashboard_source_connections:crowdstrike`.
3. Assign the binding to that customer with `authority: "query-only"`, its verified 32-hex `tenantId`, and empty `targets` and `datasets`. This does not activate an import.
4. Use `route-query --input <private-file> --env-file <server-env>` through `scripts/customer-connector-registry.mjs`. The JSON must contain exactly `candidateId`, `companyId`, `bindingRevision`, `expectedRevision`, `enabled` and a non-secret `note`. Initial expected revision is zero. The command records the actual operator and commits approval plus audit together.
5. `export-query-routes --company <id> --output <new-private-file> --env-file <server-env>` exports current revisions without CIDs or credentials. It does not overwrite existing files. Review a new revision before approving a change.
6. Complete source acceptance and release checks before enabling the switch. Customer Connectors displays approval/activation status without implying source health or adding member controls.

Empty switch means legacy behavior. An invalid nonempty switch fails closed. Disabling a route with the switch still on prevents new reviewed operations; turning the switch off is a return to legacy routing, not emergency revocation.

## Recovery and limits

- Drain operations before changing ownership, credentials or switches. Checks are repeated but are not an atomic distributed fence across the application database, dashboard database and external APIs. A change immediately after the final check cannot recall an already-sent request.
- Preserve route/audit records and all existing data on rollback. Older code ignores these approvals. Reverting code or disabling the switch requires a review of legacy visibility.
- New approval identity starts a new history series; there is no automatic backfill or assertion that older unscoped observations belonged to the newly assigned CID.
- One saved dashboard connection is supported, with one CID per approved customer. This does not introduce per-customer credential records or merge several CIDs into one query approval.
- Route loading validates the active provider set together. A stale active route must be repaired or disabled before reviewed operations resume; one customer's status card alone does not attest that the full set is usable.
- Arbitrary ES|QL dataset filtering, stored-platform source authority, mirror deduplication and full consumer migration remain separate work. A query-only binding does not authorize publishing findings.
- Live tenant permissions, zero/count semantics and actual source behavior remain unverified. No live tickets, scans or imports were used for these checks. Existing Artemis/ZAP connectivity problems are outside this change.

Validation evidence and the next release gates are recorded in [the platform plan](platform-change-proposal.md) and [connector status](connector-rollout-status.md).
