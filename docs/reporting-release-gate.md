# Customer reporting isolation

## Current behavior

`/reporting` is a customer report. It does not load the global dashboard in its server-rendered payload or call the unscoped dashboard/refresh endpoints. Before selection, it shows the customer picker. Changing customers remounts every customer-bound panel and discards pending responses from the previous selection.

Existing customer summaries, Defender source detail, risk panels, top fixes, patch review and ticket tracking remain. No new standard tiles, aggregates or history series were added. Risk reads and ticket reads use the selected company. Organization-wide risk refresh and Atlas-wide ticket maintenance controls are available only in the shared management page.

`/query-tiles` retains the existing organization-wide query editor, connection settings, tile arrangement/deletion and global maintenance controls. It is clearly labelled as shared management and has no customer picker. Existing organization-member permissions are unchanged; this reporting boundary is not a new tenant authorization system.

## Saved connector tile assignments

Use the existing customer picker on `/reporting`. The inline **Add tile** and **Edit** form save to that selected company automatically. There is no second customer selector. Switching customers closes the form; any save already submitted retains the customer it was submitted for.

The association is persisted as `definition.companyId` in the existing `elastic_dashboard_queries` JSONB record, atomically with the query definition. No new database table, schema migration, environment edit or restart is needed to assign subsequent tiles. Customer report reads filter by ownership in SQL before loading cached results. Refresh, editing, deletion and tile ordering carry the selected customer; cross-customer tile edits/deletes/order requests are rejected. Shared management remains available with existing member permissions.

### Preserve existing tiles

Deployment does not delete, recreate or automatically assign any existing tile. In the selected customer's report, choose **Add existing tile**, pick an unassigned tile, and save it to that customer. This updates only ownership and revision metadata: the ID, query, cached result, successful timestamp and daily history remain intact. Titles/source labels are listed for unassigned tiles; their cached data is not loaded into the report before attachment. Already assigned tiles cannot be attached to another customer with this action. All definitions remain visible in shared management.

Audit the query population before attaching a tile. The customer association controls where results display; it does not rewrite arbitrary ES|QL/FQL or select new source credentials. New queries still use the existing shared source connections. Defender panels continue to use their customer-bound connection independently.

### Legacy environment compatibility

`ATLAS_REPORTING_TILE_IDS` and `REPORTING_CUSTOMER_TILE_IDS` are supported only for older definitions without a saved `companyId` property. Existing assignments remain visible; the next normal save persists the resolved customer to the definition. A database assignment (including explicit null for an unassigned tile) takes precedence over legacy settings. No new assignments require environment configuration. Invalid/ambiguous legacy configuration still fails closed.

Unassigned new tiles created in shared management remain unassigned until attached from a customer report. Older clients that omit `companyId` when editing an existing tile preserve its ownership. Existing automatic source refresh and ticket routing are unchanged; Falcon routing still uses the verified `ATLAS_CROWDSTRIKE_TENANT_IDS` mapping.

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
3. Choose Atlas with existing tiles attached or legacy assignments configured. Its existing app report loads; assigned Elasticsearch **and** Falcon tiles retain prior IDs/results and show their own timestamps. A failure in the app report does not hide cached source tiles, and a source failure does not hide the app report.
4. Atlas's queue includes app-generated drafts and new Falcon drafts. Once verified tenant IDs are configured, count historical Falcon drafts by state and compare to the pre-release inventory. Review details list affected assets/findings. Ticket tracking is beside the queue. No ticket is sent by loading the page.
5. Compare “Open remediation findings” with the company and executive reports using the same status/class filters. OSINT exposure is separate; source observation counts may overlap. A failed scan is not rendered as a clean scan, and absent history is not rendered as a zero trend.
6. Check an OSINT-only, a multi-connector, a no-scan, and a large customer. Verify focus links, small-screen tables, queue pagination, and no stale customer data during rapid switching.

## Current local verification

Validated database-backed assignments with 23 targeted automated checks across dashboard persistence, customer reads and ownership resolution. The PostgreSQL integration covers preserving every saved result/history row on attachment, scoped create/read/reorder, rejected cross-customer edits/deletes/attachments, older-client edits retaining ownership, and a refresh/assignment race. Production build and TypeScript passed.

A local Playwright check against the production build used synthetic data: create/edit/attach/reorder using the selected customer, preserved existing results, discarded unsaved forms when switching customers, delayed responses, scoped CSV/refresh/risk/tickets, no global dashboard requests, and 390px mobile layout. Production assignments and source query populations were not changed or verified.

To run the broader suite, use `node --experimental-vm-modules --test-isolation=none --test tests/*.test.mjs` and `npm run build`. The in-process test flag avoids a Windows sandbox child-process restriction. `npm run lint` currently fails before examining source because this repository has ESLint 9 but no `eslint.config.*`; address that project tooling issue separately.

Rollback is the previous deployed commit. This branch does not delete or rewrite saved tile results or historical ticket rows.
