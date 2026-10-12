# Customer AppSec repository routing

Checkpoint 48 adds reviewed customer ownership to AppSec on `Vuln2.0`. It is disabled by default and has not been activated in production. It does not import source records, change CI publishing, move device findings, change ticket routing or grant configuration permissions.

## What changes for a user

With `VULN_REVIEWED_APPSEC_PROVIDERS=appsec`, the AppSec page requires one customer selection. Only repositories approved for that customer contribute to its summary, trend and repository detail. Drilldown and return links retain the customer. The existing authenticated member access remains in place; this is customer data scoping, not a new user entitlement model.

A customer with no approval sees an explicit unavailable message. Missing tables, expired review, changed configuration, disabled approval or conflicting ownership cannot fall back to the organization-wide query. A refresh failure clears previously displayed AppSec results. Changing customers immediately replaces the result component, and late responses cannot populate the new customer's view.

Coverage uses the number of approved repositories as its denominator. A repository without a retained completed scan lowers coverage; it is not counted as scanned with zero findings. The trend retains existing scan-day semantics: it includes only repositories scanned that day and does not carry other repositories forward. Detail lists remain limited to the latest 25 scans and the first 100 current findings; reviewed reads request an extra finding to show a visible truncation notice.

## Source and storage

| Item | Location and purpose |
| --- | --- |
| Source credentials | Existing `APPSEC_ELASTIC_URL` and `APPSEC_ELASTIC_API_KEY` server environment variables; no additional key form |
| Scan source | `APPSEC_ELASTIC_SCAN_STREAM`, default `gmi-appsec-scans` |
| Finding source | `APPSEC_ELASTIC_FINDING_STREAM`, default `gmi-appsec-findings` |
| Repository identity | Exact scalar `gmi.appsec.repository`, qualified as `owner/repository`; the repository's current Trivy workflow supplies `$GITHUB_REPOSITORY` |
| Existing source review | Application PostgreSQL `customer_connector_drafts` and `customer_connector_bindings`; proposed dataset/repository scope and review revisions |
| Runtime approval | New application PostgreSQL `customer_appsec_routes`; customer, source evidence, normalized ownership scope, revision and enabled state |
| Approval audit | New `customer_appsec_route_audit`; before/after values, operator, reason and revision in the same transaction |
| Result data | Read from Elastic when AppSec is opened/refreshed. No new findings table or cached snapshot is created |

The original organization view uses the same environment connection. The separate saved dashboard Elastic connection is not substituted. Metadata reads use the application pool and saved company records without hydrating the full legacy findings store. AppSec pages still refresh once per minute; this checkpoint does not turn them into SQL summary reads.

## Approval contract

There is one active AppSec route per customer on the existing shared environment connection. The reviewed source must be the shared `environment:appsec` candidate with `query-only` authority, no tenant ID, exactly the two configured scan/finding dataset names, and one to 100 exact qualified repositories in `targets`.

An example scope for a synthetic customer is:

```json
{
  "companyId": "CO-EXAMPLE",
  "tenantId": null,
  "authority": "query-only",
  "datasets": ["gmi-appsec-scans", "gmi-appsec-findings"],
  "targets": ["example-org/example-repository"]
}
```

Use actual verified identities in deployment, not this example. Wildcards, short repository names, duplicates and overlapping repository ownership are rejected. Ownership conflicts are case-insensitive, while the actual query preserves the reviewed spelling for exact source matching. Repositories transferred, renamed or recased in GitHub require a scope review. This pass does not discover or automatically assign private repositories.

AppSec is a specific reviewed document-filter contract for its two shared streams. It does **not** loosen the separate saved-query rule that generic ES|QL tiles require exclusive customer datasets. The fixed AppSec queries cannot be replaced by arbitrary user ES|QL.

## Read flow and boundaries

1. Validate the selected application customer, current metadata, reviewed binding and operational approval. Unknown/demo customers are refused.
2. Pin the credential, configured streams and repository list for this request.
3. Restrict every fixed query before aggregation to a single repository identity in that approved list. Missing and multi-valued identities are excluded and the UI explains that scope. This is not an attestation that all source rows are correctly labeled.
4. Use the existing reviewed Elastic transport to verify an Elastic Stack deployment and resolve exact datasets to physical indexes. Aliases, unsupported Serverless sources and unsafe expansion are refused. Only the configured scan or finding stream is resolved for each query.
5. Check returned repository identities and, for findings, the selected scan ID. Warnings/incomplete responses retain the query client's refusal behavior. Scoped summary/trend truncation is treated as an error; findings truncation is labeled. Raw upstream error bodies are not returned in the reviewed response.
6. Recheck approval and the request's credential/configuration fingerprint before returning results. Changed/revoked routes withhold the whole response. The private fingerprint exists only for the request lifetime; keys or key hashes are not exported or saved to the registry.

Elasticsearch can group a multi-valued key into several groups, which is why the fixed query requires a scalar identity before grouping. See the official [STATS documentation](https://www.elastic.co/docs/reference/query-languages/esql/commands/stats-by) and [multivalue functions](https://www.elastic.co/docs/reference/query-languages/esql/functions-operators/mv-functions).

Repository ownership is an operator/source contract. It does not replace upstream Elastic security. Correct mappings, trusted CI producers and isolation of source administration are required. Missing or malformed identities and a wrong repository spelling can reduce reported coverage. Summary `LATEST` and scan-delta semantics, branch mixing and timestamp ties are inherited from the existing AppSec implementation; this change does not certify those as a complete remediation history. Source reads, approval checks and upstream index changes are not one distributed transaction. Drain requests before moving ownership. As with other reviewed routing, one stale active AppSec route withholds the reviewed route set until repaired or disabled.

## Preparing activation

These are release preparation steps, not changes already applied to production.

1. Preserve a recovery point and apply `docs/sql/customer-appsec-routes.sql` to the **application** database after the existing draft/binding migrations. The additive migration seeds no approvals and modifies no source records. There is no automatic schema initializer.
2. Use the existing connector preview/import and `export-bindings`/`assign` operator workflow to review the AppSec environment candidate for each customer. Verify actual repository ownership, spelling, retained field mappings, stream names and read/metadata permissions against the intended Elastic deployment.
3. Submit a separate operational approval with `node --experimental-vm-modules scripts/customer-connector-registry.mjs route-appsec --input <private-json-file> --env-file <server-env-file>`. The JSON has exactly `candidateId`, `companyId`, `bindingRevision`, `expectedRevision`, `enabled` and a non-secret `note`. Use the current reviewed binding revision; an initial approval has `expectedRevision: 0`. Later edits require the exported current route revision.
4. Inspect state using `export-appsec-routes --company <company-id> --output <new-private-file> --env-file <server-env-file>` on the same CLI. Route exports omit repository/dataset scope and credentials and refuse to overwrite an existing file. Keep the reviewed binding export separately for scope review.
5. During the combined release, set `VULN_REVIEWED_APPSEC_PROVIDERS=appsec` and restart using the validated deployment procedure. A blank value retains legacy mode; any other nonempty value fails closed. No existing query/scanner/inventory provider switch enables AppSec implicitly.
6. Validate each approved customer, an unapproved customer, repository links, coverage, failed source reads and revocation. Compare source-native AppSec totals. Do not treat these fixture tests as live customer acceptance.

The Connectors customer status shows whether approval is current and whether the AppSec switch is on. It hides private repository lists and does not claim live health. Endpoint/stream changes invalidate review. The registry deliberately fingerprints non-secret configuration, so a between-request key rotation alone does not renew ownership evidence; review the key's access and deployment before reuse.

## Recovery and remaining work

Disable a customer's route through `route-appsec` with its current revision while enforcement stays on to revoke new reviewed reads. A failed audit write rolls back the approval update. Disabled/stale approvals remain revocable without obtaining a successful vendor response.

Turning off the provider switch restores the previous organization-wide view. That is a compatibility rollback, **not** an emergency access revocation. Keep approvals and audit when reverting code; do not drop their tables. Do not activate an older process with the new switch until its behavior and legacy visibility are reviewed.

Validation is recorded in checkpoint 48 of the [platform plan](platform-change-proposal.md). Live repository ownership/mapping acceptance, source authority across stored platform consumers, mirrored-source decisions, SQL reporting cutover and authoritative writer handoff remain release gates. AppSec does not become device vulnerability data or gain automatic ConnectWise patch tickets through this change.
