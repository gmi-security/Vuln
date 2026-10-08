# Customer reporting isolation

## Current behavior

`/reporting` is a customer report. It does not load the global dashboard in its server-rendered payload or call the unscoped dashboard/refresh endpoints. Before selection, it shows the customer picker. Changing customers remounts every customer-bound panel and discards pending responses from the previous selection.

Existing customer summaries, Defender source detail, risk panels, top fixes, patch review and ticket tracking remain. No new standard tiles, aggregates or history series were added. Risk reads and ticket reads use the selected company. Organization-wide risk refresh and Atlas-wide ticket maintenance controls are available only in the shared management page.

`/query-tiles` retains the existing organization-wide query editor, connection settings, tile arrangement/deletion and global maintenance controls. It is clearly labelled as shared management and has no customer picker. Existing organization-member permissions are unchanged; this reporting boundary is not a new tenant authorization system.

## Saved connector tile assignments

Customer reports display saved Elasticsearch/Falcon tiles only after an operator verifies their data population and assigns the tile IDs. A globally configured source is not proof of customer ownership. Ordinary report reads use saved results; only the explicit connector refresh action executes those customer's assigned queries.

- Existing `ATLAS_REPORTING_TILE_IDS` remains supported for Atlas (`CO-147284`).
- `REPORTING_CUSTOMER_TILE_IDS` optionally supplies a JSON object from company IDs to arrays of verified saved tile IDs. An explicit array overrides the legacy Atlas list for that customer, including an empty array.
- Example using placeholder tile IDs: `REPORTING_CUSTOMER_TILE_IDS='{"CO-147284":["verified-atlas-tile"],"CO-OTHER":["verified-other-tile"]}'`.
- A tile can belong to only one customer. Malformed or ambiguous configuration fails closed. Missing assignments produce no custom connector tiles; they never fall back to the shared dashboard.
- Audit the query, its index/tenant restrictions, credentials and cached result before assigning it. A tile title is not ownership evidence. Re-audit the assignment whenever its query population or source connection changes. Arbitrary ES|QL/FQL is not automatically rewritten to add customer filters.
- Defender panels use the existing customer-bound Defender connection and source records, independently of these saved-query assignments. Imported scanner findings remain in the existing customer report sections.

There is no database migration and no automatic assignment of existing tiles. Unassigned definitions/results/history are preserved in shared management. Atlas saved tiles will be absent from customer reports until their IDs are explicitly configured. Source configuration and credential roles are unchanged.

Falcon ticket routing continues to use the existing verified `ATLAS_CROWDSTRIKE_TENANT_IDS` mapping; it is not modified by this PR.

## Read-only inventory

Run against the actual production `DATABASE_URL` and `ELASTIC_VULN_DATABASE_URL` targets, without printing connection strings or secrets. Record counts and metadata only; back up the relevant tables before any data migration. Do not store customer-identifying results in this repository.

```sql
SELECT id, definition->>'title' AS title,
       COALESCE(definition->>'source', 'elastic') AS source,
       result IS NOT NULL AS has_result, refreshed_at, last_error, deleted_at
FROM elastic_dashboard_queries
ORDER BY id;

SELECT query_id, collected_at FROM elastic_query_snapshots ORDER BY query_id;

SELECT tenant_id, COALESCE(packet->>'source', 'crowdstrike') AS source,
       packet->>'appCompanyId' AS app_company_id,
       state, review_state, COUNT(*) AS requests
FROM patch_group_ticket_requests
GROUP BY tenant_id, source, app_company_id, state, review_state
ORDER BY requests DESC;
```

Inspect each saved Elasticsearch query's index and tenant predicate, and each Falcon connection's effective tenant scope. Confirm every assigned direct tile belongs to its configured customer before release. This change does not validate production source completeness or recalculate imported findings.

## Acceptance checks

1. On `/reporting`, no customer selected means no summary, tile, review draft, or ticket result in the visible page or initial page payload.
2. Choose GCON, then Openworks. Each choice shows only its own `CO-*` app findings, source activity, scans, assets, review drafts, and tickets. Neither receives Atlas saved tiles.
3. Choose Atlas with verified tile assignments configured. Its existing app report loads; assigned Elasticsearch **and** Falcon tiles retain prior IDs/results and show their own timestamps. A failure in the app report does not hide cached source tiles, and a source failure does not hide the app report.
4. Atlas's queue includes app-generated drafts and new Falcon drafts. Once verified tenant IDs are configured, count historical Falcon drafts by state and compare to the pre-release inventory. Review details list affected assets/findings. Ticket tracking is beside the queue. No ticket is sent by loading the page.
5. Compare “Open remediation findings” with the company and executive reports using the same status/class filters. OSINT exposure is separate; source observation counts may overlap. A failed scan is not rendered as a clean scan, and absent history is not rendered as a zero trend.
6. Check an OSINT-only, a multi-connector, a no-scan, and a large customer. Verify focus links, small-screen tables, queue pagination, and no stale customer data during rapid switching.

## Current local verification

Validated this change with 37 targeted automated checks covering customer assignments, tenant scope, customer report models/review/source activity/metrics, and dashboard persistence/refresh. The persistence suite used a disposable local PostgreSQL database; scoped refresh left another customer's overdue tile untouched. `npm run build` passed.

A local Playwright browser check against the production build used synthetic source responses: no selection, Atlas, Footprint/Defender, multiple sources, no sources, delayed responses during customer switching, customer CSV/refresh/risk/ticket requests, and 390px mobile layout. No unscoped dashboard request occurred. These checks do not constitute production configuration validation.

To run the broader suite, use `node --experimental-vm-modules --test-isolation=none --test tests/*.test.mjs` and `npm run build`. The in-process test flag avoids a Windows sandbox child-process restriction. `npm run lint` currently fails before examining source because this repository has ESLint 9 but no `eslint.config.*`; address that project tooling issue separately.

Rollback is the previous deployed commit. This branch does not delete or rewrite saved tile results or historical ticket rows.
