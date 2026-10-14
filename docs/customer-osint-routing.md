# Reviewed customer routing for SpiderFoot and Artemis

Development on `Vuln2.0` only. Nothing was enabled in production and no real scan, source import or ticket was used as a test.

## What changes

Both integrations reuse the scanner approval and audit tables. The existing OSINT launch action, scheduler, import actions, finding classification and scoring remain. A reviewed binding alone does not activate anything: an independent operational approval and a provider entry in `VULN_REVIEWED_SCANNER_PROVIDERS` are required.

```text
Existing customer + saved source configuration
  -> reviewed source scope and exact scan roots
  -> separate audited scanner approval
  -> provider switch enabled at the reviewed release
  -> approved scan/analysis collection
  -> verify response identities and recheck current approval
  -> existing customer findings and attack-surface reporting
```

| Source | Binding fields | Operational behavior |
| --- | --- | --- |
| SpiderFoot | `tenantId: null`; explicit hostnames or IPs in `targets`; `authority: "findings-primary"`; empty `datasets` | The exact scan root selects one approved customer. Scan names do not select customers. A computed target-set digest is stored as the operational scope. Each normalized target can have only one owner in this configured SpiderFoot instance. |
| Artemis | Exact, case-sensitive source tag in `tenantId`; explicit hostnames or IPs in `targets`; `authority: "findings-primary"`; empty `datasets` | The approved tag selects the customer. Fetch analyses for that exact tag, then task results for each approved analysis ID. Each tag has one customer owner. No company-name aliases or guesses are used in reviewed mode. |

One binding per customer/provider is supported for each existing shared environment connection. SpiderFoot overlapping target sets are rejected during approval under the shared registry lock, and again on reads. Artemis tags remain case-sensitive; tag length is limited to 160 characters. Existing Nessus numeric-folder routing and approvals remain separate.

Targets are exact hostnames or IPv4/IPv6 addresses. Hostnames are case-insensitive and ignore a final dot; equivalent IP spellings share an identity. No wildcard domains, automatic suffix expansion, URLs, comma lists or CIDR ranges are accepted for OSINT launch roots. This scope grammar is deliberately narrower than Nessus. Actual scanner-version support must still be verified before activation.

## Collection checks and coverage

SpiderFoot requires the exact `FINISHED` state, valid unique scan IDs, a finished timestamp, and unchanged scan identity/target/status/count metadata around the export. Every raw export event must have the selected scan's target and name, including events later excluded by severity or false-positive filtering. Missing or foreign provenance rejects that scan's whole result. A malformed scan roster now reports an error instead of appearing empty, including in legacy mode.

Artemis uses its tag filter and per-analysis task-result filter. The collector validates unique analysis IDs, exact tags, approved root targets and task-result IDs/analysis IDs/tags. It imports observations only from analyses with zero pending tasks and no stopped flag, then checks their scope and state again. Pending/stopped analyses are counted in an explicit partial-import warning; their previous platform data stays available. Empty collected results do not prove an empty attack surface or complete assessment.

Artemis retains bounded collection: at most 1,000 analyses in the selected tag roster, 200 results per page, 25 pages per analysis and 5,000 returned results per customer collection. Truncation, repeated result IDs, foreign records and changed selected analyses reject that customer's collection. Independent valid customer tags can still succeed. These checks are not an atomic upstream snapshot; zero pending tasks does not prove every upstream module succeeded.

Both importers recheck the current customer, route revision, binding and connection before applying results. Existing scan ownership is retained; a new assignment cannot silently move historical scans. No existing findings, saved tiles, assets, history or tickets are deleted. SpiderFoot and Artemis retain their existing OSINT/attack-surface classification and scoring; this does not convert them into endpoint vulnerability counts or change their existing deduplication and closure behavior.

Discovered related hosts can belong to affiliates or third parties. Their event payload remains discovery evidence tied to the verified root scan/analysis, not proof that every related asset belongs to this customer. In reviewed mode, automatic OSINT-to-Nessus pivoting requires a separate reviewed Nessus route; Nessus then checks the actual requested targets. No reviewed Nessus route means no automatic pivot from that reviewed import. Existing explicit scan permissions and legacy routing behavior remain separate.

## Launch and preview

The existing OSINT preview and launch action use the same source-specific target plan. Reviewed providers use approved roots; providers whose switch is off keep the legacy derived-domain selection. Artemis submits the approved source tag, not the display name. Customer permissions, the single customer selector and source configuration screens are unchanged.

A stale or invalid opted-in route stops preview/launch planning. The page reports preview failure and disables launch until the preview is available again. Each reviewed launch rechecks approval before its vendor call. Adapter checks also reject targets outside the passed scope. Artemis validates the launch acknowledgement; an uncertain or partial acknowledgement reports failure and tells the operator to inspect the scanner before retrying, since a request might already have launched work.

No new automatic scan trigger was added. Existing scheduler timing and on-demand triggers remain. Disabling an approval or changing a flag does not stop work already running on a remote scanner.

## Database, migration and release preparation

All route and audit data uses the application `DATABASE_URL`:

- `customer_connector_drafts` and `customer_connector_bindings`: sanitized source evidence and reviewed scope.
- `customer_scanner_routes`: independent operational approval pinned to the binding revision/hash.
- `customer_scanner_route_audit`: operator, note and before/after approval state.
- Existing platform store/snapshot tables: scan records, exposure findings and workflow state.

Apply the existing draft/binding migrations, [scanner route migration](sql/customer-scanner-routes.sql), then the additive [OSINT extension](sql/customer-scanner-osint-routes.sql) during the eventual approved release. The extension preserves existing Nessus approvals and adds no OSINT approvals. It is not the authoritative platform database-write migration.

Use the existing registry import, binding assignment, `route-scanner` and `export-scanner-routes` commands described in the [scanner guide](customer-scanner-routing.md). Approval input still has exactly `candidateId`, `companyId`, `bindingRevision`, `expectedRevision`, `enabled`, and `note`; source scope is derived from the reviewed binding. Exports omit private targets, source tags and credentials and refuse to overwrite an existing file. Conflicts and failed audits roll back the approval. Stale routes can still be disabled without reapproving them.

Endpoint changes invalidate source review. SpiderFoot additionally fingerprints its TLS mode, configured user and use case; secrets are not copied into the registry. Credential rotation itself still needs operational verification. Turning the provider switch off restores legacy mapping and is not a source kill switch.

Before activation: independently verify customer root/tag ownership, confirm actual source response fields and filtering against deployed versions, resolve the previously observed Artemis connectivity problem, and drain relevant imports/launches before changing routes. Both providers use the existing mutable platform store. No distributed writer fence, immediate cancellation or atomic SQL findings publication is claimed.

Rollback requires a reviewed compatible build and drained operations. Preserve approval/audit and source/platform data. Older builds ignore the added provider approvals. An older code version does not make new reviewed mappings safe for legacy name-based routing automatically.

## Evidence and remaining work

Validation: **216 distinct local regression tests**, **39 isolated PostgreSQL groups**, **nine browser groups**, and a production build/TypeScript pass. The full regression run passed 215 tests; the final partial-coverage change passed 58 focused tests, including one additional test (reruns are not added twice). Database checks used disposable databases in the private recovery cluster; the databases were dropped and the cluster stopped. HTTP/browser tests used synthetic responses. Live source acceptance and full-scale collection cost remain unverified.

Protocol references used for implementation: the official [SpiderFoot export and scan-list implementation](https://github.com/smicallef/spiderfoot/blob/master/sfwebui.py), [Artemis API](https://github.com/CERT-Polska/Artemis/blob/main/artemis/api.py) and [Artemis data models](https://github.com/CERT-Polska/Artemis/blob/main/artemis/db.py). These references do not establish the deployed server versions or prove their current health.

Next: ZAP and Vulners runtime routing, FQL/patch consumers, live customer source verification, SQL reporting integration and authoritative writer handoff, then the combined release/recovery rehearsal. Burp, Nmap, Intune, IntelOwl and n8n remain available but disabled.
