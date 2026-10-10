# Customer saved-source read preview

This is a disabled Vuln2.0 read preview. It connects the verified saved-source services to Overview and Prioritize without replacing the existing report, risk model, source workers or ticket service. It adds no saved/default query tiles and does not activate connector registry proposals.

## Gates and scope

The page requires the existing dashboard access plus `VULN_REMEDIATION_UI=true`. The new preview also requires `VULN_SAVED_SOURCE_READS=true` and an explicit `VULN_SAVED_SOURCE_READ_CUSTOMERS` JSON object, for example:

```json
{"CO-EXAMPLE-A":["defender"],"CO-EXAMPLE-B":["crowdstrike"]}
```

This map is a temporary, server-controlled read-preview allowlist, not a new connector configuration system or proof of vendor tenant ownership. Do not populate production assignments until that scope is reviewed. Missing configuration exposes no saved sources. Unknown providers, duplicate providers, malformed IDs or malformed JSON fail closed. A request cannot select an unlisted source for a customer. Both sources can be reviewed separately for the same customer; their totals are never added together. The map contains no credentials and creates no database records.

There is no additional customer selector. The existing selector is reused; in preview mode its setup list comes from saved company metadata without hydrating the platform findings store. Original reporting and the existing source/risk/ticket panels continue to use their current services. Turning the new flag off restores the prior page composition and setup path. `/reporting` is unchanged regardless of this flag.

## Request path

### Reviewed registry selection

The additional server setting `VULN_SAVED_SOURCE_SELECTION=registry` replaces the temporary allowlist for this preview. It still requires both existing feature gates and authentication. The default remains `allowlist`; an unknown mode fails closed. Registry mode never falls back to the allowlist when assignments are missing or blocked, and it adds no configuration permissions.

The selector reads only the selected customer's binding rows, checks current source evidence against both imported and reviewed hashes, and requires a reviewed findings-primary assignment. Duplicate endpoint assignments, mirrors, stale reviews, conflicting customer ownership and additional target/dataset restrictions that the adapter cannot enforce are withheld with a short explanation. Inventory and query-only roles do not become endpoint findings. Private tenant IDs, hashes and proposals are not returned to the browser.

The first supported registry path is a saved Defender connection. Its customer, tenant and revision must match the assignment. The adapter checks that tenant/revision again inside the same read-only snapshot as the completed import; the import must also match the reviewed revision. A connection change between selection and reading cannot expose an old tenant's CVEs. Reviewing a new connection alone does not authorize its previous import. Normal freshness and missing-result states remain visible.

CrowdStrike registry preview now requires a reviewed customer-owned Falcon environment connection and a 32-character vendor CID. Spotlight summary model v3 records CID evidence from every actual vendor row, including closed, suppressed and non-CVE entries. It separately counts exact local unresolved placeholders created by the importer: stored status `closed`, stored CVE `CS-<source_id>`, and raw JSON exactly `{id: <source_id>, unresolved: true}`. These bookkeeping rows supply neither findings nor an invented tenant. Additional fields, different types or inconsistent identity do not qualify for this exception. Before reading CVE rows, the saved reader requires the summary to match the current import, have complete single-CID evidence and match the reviewed CID. Mixed, missing or invalid tenant evidence is withheld. An empty or placeholder-only generation cannot establish a tenant and is withheld in registry mode; it is not represented as a verified zero. Vendor scope stays server-side. Existing model v1/v2 summaries require an explicit v3 rebuild before this reader can use them; the disabled summary worker discovers the new version without altering raw imports. Existing allowlist mode is preserved but does not claim the registry guard. Saved Elastic/Falcon query tiles retain their separate existing customer-ownership path; this selector does not execute those queries or use them as fallback findings.

This is a read-preview bridge, not binding activation or authoritative platform routing. It leaves the registry's `enabled=false` constraints intact and does not select platform authority, change ingestion, sum multiple source counts, or replace legacy reports. Metadata collection and binding reads are separate snapshots; the Defender reader's guard covers the connection/import boundary and the Spotlight reader checks current-generation CID evidence. Live provider-side verification and environment credential versioning remain outstanding.

Verification for the bridge: 19 focused local tests plus 29 existing connector tests passed; 19 isolated PostgreSQL scenario groups passed, including actual binding assignment through SQL selection and the real Defender adapter. Ten browser groups passed with intercepted data, including blocked-source explanations and customer switching; the production build and type check passed. No live vendor calls or production database changes were used.

`GET /api/elastic-dashboard/customer-saved-sources` uses existing organization-member authentication and private/no-store responses. It has no mutation handler.

- `?setup=1`: bounded saved company metadata, excluding demo companies. It does not collect connector credentials or findings.
- `?companyId=...`: confirms an existing non-demo customer and returns that customer's allowlisted source names.
- `?companyId=...&source=defender|crowdstrike&offset=0`: validates scope, returns one saved source result and at most 50 CVEs. Offset is bounded to one million; a malformed offset is rejected.

The application database pool is reused without schema initialization. Company metadata follows the existing `vuln_store` meta/bucket precedence and `vuln_snapshot` fallback. CrowdStrike uses `spotlight_summary_*` plus import metadata; it never runs the slow full-generation reference aggregate. Defender uses completed `defender_import_runs` summaries and `defender_cves`. Neither saved-source request starts an import, summary build, cleanup, vendor call, platform publication or ticket request.

The shared company metadata extraction was factored out of the existing connector collector. That collector retains its behavior; the new helper avoids reading even the connector metadata when only company identity is needed. Invalid saved company data fails instead of falling back to an unrelated customer.

## What the user sees

Overview shows separate source summary panels. Prioritize adds a scrollable CVE table, ordered by source CVSS severity and affected devices, with previous/next pagination. These are source results, not GMI risk ranks. Counts distinguish source instances, device/CVE findings, unique CVEs and affected devices. Defender instances include software version; Spotlight instances retain their own finding definition and suppression qualifiers.

Every CVE uses the existing shared customer CVE panel and Prepare patch request flow. Opening details rechecks available customer evidence through the existing service; a saved list is not authorization to create a ticket and its count is not a frozen host export. No scoring rules, ticket routing, customer permissions or automatic delivery behavior change here.

Each panel displays import completion time, explicitly distinct from endpoint assessment time. The preview uses a 36-hour import-freshness window. Stale or unverifiable time, changed Defender connection revision, newer Spotlight summary pending, and latest-import failure/running states remain visible. Before the first complete result, counts are unavailable rather than zero. Corrupt totals are withheld. A failed refresh can retain the last successful result for that same customer/page with an error; changing customers unmounts old source panels and ignores late responses.

Refresh reads stored results only. It does not request upstream collection or rebuild an expensive summary. A completed empty import can legitimately display zero counts. A newer import awaiting summarization shows the previous completed generation with a pending explanation.

## Verification and limits

The service and route tests cover configuration rejection, authentication/feature gates before database access, explicit source selection, page bounds, demo/unknown customers and response-scope mismatch. Real PostgreSQL metadata tests cover storage precedence, read-only enforcement and avoiding credential/finding reads. Existing adapter parity tests remain the basis for the saved counts.

Browser fixtures exercise the real built UI, both with the preview disabled and enabled, including source CVE pagination, the shared patch panel, stale/pending/error states, late previous-customer responses and mobile layout. Fixture ticket delivery is intercepted; no real ticket is sent. The browser suite supports an installed Playwright module and optional `PLAYWRIGHT_CHANNEL` for a locally installed test browser.

This does not establish full-page performance: legacy reporting and prioritization sections still run alongside the preview. Remaining work includes authoritative connector bindings, cross-source overlap/deduplication, published-platform lifecycle/risk parity, and then a separately reviewed replacement of legacy reads. Worker/retention operation, actual tenant scope verification and end-to-end production rollout remain separate gates.

## October 10 all-connector follow-up

See [connector rollout status](connector-rollout-status.md) for current validation and operational limits. The shared binding checker now validates source identity, review freshness and role across all catalogued connector types. Only the Defender and Spotlight saved-result adapters consume these guards at runtime; it does not reroute legacy scanner imports, inventory, enrichment, AppSec or ticket delivery. Environment key rotation and provider-side scope remain separate verification requirements.
