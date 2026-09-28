# Reporting branch: production release gate

This branch implements the customer-scoped Reporting page and restores the two saved direct-source types for Atlas. It has no access to production databases or source credentials. The checks below are required before pushing to the DigitalOcean deployment branch.

## Implementation decisions and remaining limits

- The business rule supplied in this conversation says Atlas alone has direct Elasticsearch/Falcon dashboard data. The branch requires `ATLAS_REPORTING_TILE_IDS`, a comma-separated allowlist of verified saved tile IDs. No direct tiles appear until it is configured. Audit each tile before adding its ID.
- The branch does not guess Falcon tenant ownership. New and historical Falcon drafts load under Atlas only after verified CIDs are supplied through `ATLAS_CROWDSTRIKE_TENANT_IDS`. **Cost if left unset:** Falcon drafts remain outside the Atlas queue.
- The shared report uses current app-store scans/findings/assets and measured history. The production sample audit, authenticated visual inspection, and cross-page count reconciliation remain open because this checkout has no production credentials.

## Scope decision

The user confirmed that Atlas (`CO-147284`) is the only current customer with the separately saved Elasticsearch and Falcon dashboard data. The new `/api/elastic-dashboard/customer-tiles` route returns only allowlisted saved tile IDs for Atlas after selection. It preserves their saved definitions/results and does not change the queries. The old root dashboard GET also requires a customer selection and applies the same allowlist. This branch does **not** yet have persisted tile-by-tile ownership metadata; inspect the live saved definitions and credentials before release. Never allowlist a global tile or a tile belonging to another tenant.

New Falcon consolidation drafts carry Atlas's app company ID only when their tenant CID is verified in `ATLAS_CROWDSTRIKE_TENANT_IDS`. Historical Falcon drafts may lack the app ID. This variable can contain a comma-separated list of **verified** Falcon 32-character tenant CIDs to make those older drafts visible under Atlas. Leave it unset rather than guess. It is an identity mapping, not a secret. Older unmapped drafts remain available through the existing organization-wide ticket view.

Source connection and saved tile mutation routes still use the existing organization-member access rule. A distinct source-audit administrator role has not been implemented. This must be decided and enforced before enabling management in production if organization members should not share that authority.

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

Inspect each saved Elasticsearch query's index and tenant predicate, and each Falcon connection's effective tenant scope. Confirm every direct tile assigned to Atlas belongs to Atlas before release. The historic 80,000 app finding count matches an old importer guard; compare Atlas's last completed Spotlight sync and source total before claiming it is current.

## Acceptance checks

1. On `/reporting`, no customer selected means no summary, tile, review draft, or ticket result in the visible page or initial page payload.
2. Choose GCON, then Openworks. Each choice shows only its own `CO-*` app findings, source activity, scans, assets, review drafts, and tickets. Neither receives Atlas saved tiles.
3. Choose Atlas. Its common app report loads; saved Elasticsearch **and** Falcon tiles retain prior IDs/results and show their own timestamps. A failure in the app report does not hide cached source tiles, and a source failure does not hide the app report.
4. Atlas's queue includes app-generated drafts and new Falcon drafts. Once verified tenant IDs are configured, count historical Falcon drafts by state and compare to the pre-release inventory. Review details list affected assets/findings. Ticket tracking is beside the queue. No ticket is sent by loading the page.
5. Compare “Open remediation findings” with the company and executive reports using the same status/class filters. OSINT exposure is separate; source observation counts may overlap. A failed scan is not rendered as a clean scan, and absent history is not rendered as a zero trend.
6. Check an OSINT-only, a multi-connector, a no-scan, and a large customer. Verify focus links, small-screen tables, queue pagination, and no stale customer data during rapid switching.

## Current local verification

Use `node --experimental-vm-modules --test-isolation=none --test tests/*.test.mjs` and `npm run build`. The in-process test flag avoids a Windows sandbox child-process restriction. `npm run lint` currently fails before examining source because this repository has ESLint 9 but no `eslint.config.*`; address that project tooling issue separately.

Rollback is the previous deployed commit. This branch does not delete or rewrite saved tile results or historical ticket rows.
