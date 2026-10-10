# Customer connector registry: preview and disabled drafts

The Vuln2.0 registry has a read-only preview, transactional storage for disabled draft proposals, a gated customer status view, and an operator import/export/review command. It has not been deployed. It does not migrate credentials, change customer access, activate bindings or switch findings readers/workers to a new source. The latest plan prepares these capabilities for one coordinated production rollout.

## What is collected

| Existing location | Information retained | Meaning |
| --- | --- | --- |
| Application snapshot company collection | Company ID/name and demo exclusion | Existing customer identity; Map entry keys must agree with stored IDs |
| `defender_connections` | Customer, tenant and revision | Explicit saved mapping; reuse this credential reference |
| `FALCON_*` / `DEFENDER_*` environment configuration | Presence, customer match and Defender tenant | Suggested association; no credentials in output |
| Scanner connector definitions and inventory/threat environment keys | Configuration presence and capability category | Shared availability; customer targets and source ownership remain unassigned |
| Saved dashboard connections | Provider and revision | Reference to existing dashboard credential storage |
| Active `elastic_dashboard_queries` | Tile ID, provider, revision and customer ownership | Preserve saved assignment; does not establish upstream tenant/dataset scope |
| `spotlight_import_current` and run status | App company and generation reference | Historical observation only; not a Falcon tenant ID |

The collector never reads vulnerability payloads or cached tile result/query bodies. Deleted tiles are excluded from the preview and left untouched. Inventory, scans, enrichment and saved queries have distinct capabilities. No source receives authority to contribute findings, and mirrored Elastic/CrowdStrike counts are not combined.

Unconfigured connectors do not generate entries. This is configuration/binding evidence, not an inventory of every historical source or a health test. ConnectWise delivery settings and ticket records stay in their existing stores and are outside this source registry checkpoint.

## Run a preview

Run from a checkout containing this change with its dependencies installed. The operator needs read access to configuration and relevant database tables, plus write access to a private output directory. Use existing permissions; no role changes are required by this tool.

```sh
node --experimental-vm-modules scripts/preview-customer-connectors.mjs \
  --env-file /opt/vuln/.env.local \
  --output /home/codex/vuln-recovery/customer-connectors-review.json
```

This command uses `DATABASE_URL` for application metadata and `ELASTIC_VULN_DATABASE_URL` for dashboard metadata when configured, otherwise the application database. Values already in the shell override the supplied file. Omitting `--env-file` uses only the process environment. It does not read root PM2's environment, so reconcile runtime overrides separately before migration. Never paste credentials into the command or report.

The output path must be new. On Linux it is created with mode 0600; choose a private directory outside the website and repository. The report contains customer and tenant identifiers even though it excludes passwords, client secrets, stored ciphertext, endpoints and query text. Do not commit or publicly share the full report. Standard output contains only counts and a fingerprint.

The command opens read-only transactions and does not initialize schema. Missing optional tables are recorded in `coverage`. A failure to read a present table or a missing required companion table aborts. Company metadata, connection metadata and tiles are capped at 10,000 rows per read; a larger result fails without silent truncation. Application and dashboard snapshots are separate; recollect before any future import.

## Review the result

1. Confirm collection coverage, timestamp and environment origin. Verify that all expected customer records and configuration sources are represented.
2. Review explicit saved customer/tenant bindings first. Reuse existing connection references; do not copy secrets into the registry.
3. Resolve ambiguous/missing customer names, orphaned IDs, tenant conflicts and numbered Falcon gaps. An unnamed base Falcon connection remains unassigned in the preview even though older import code has an internal-company fallback.
4. Review saved tile ownership separately from query scope. Explicit null remains unassigned; persisted customer ownership wins over legacy environment mappings. Do not infer ownership from the title or reassign existing tiles automatically.
5. Verify source tenant/dataset/approved scanner targets and mirror authority before enabling future bindings. A shared MISP connection or a historical SpiderFoot finding does not enable a scanner for every customer.

Preview entries stay disabled and pending review. The fingerprint is deterministic for the sanitized metadata, not a credential revision or an authorization token. It deliberately excludes secret values, so changing an environment secret alone does not change it.

## Draft storage and review service

The explicit migration is `docs/sql/customer-connector-drafts.sql`. It creates three application-database tables: import batches, connector drafts and audit history. It is not an automatic migration and has only been run in disposable test databases. The operator command below can write these proposals when explicitly run with the database owner's existing access. There is no HTTP mutation endpoint. The read-only preview command above remains read-only.

`createConnectorDraftStore(db)` provides backend methods for a future authorized adapter:

- `importPreview(expectedFingerprint, actor, collect)`: recollect through a trusted server-side metadata collector, verify the reviewed fingerprint, and atomically record new/changed/missing evidence. Replaying the same current fingerprint creates no duplicate batch or audit entries. Do not supply an uploaded JSON file or client-controlled callback as the collector.
- `reviewDraft(input, actor, resolveCompany)`: save, mark reviewed or dismiss a proposal with the expected revision and source evidence hash. Resolve company IDs through an existing trusted customer service. Record scope, proposed authority and a review note. Do not put credentials into notes or scope fields.
- `reviewCurrentDraft(input, actor, collect)`: operator entry point. Recollect trusted source metadata under the registry transaction lock, verify the current candidate and connection-dependency hash, and resolve the proposed customer from that fresh preview before applying the review. Use this method for operator commands; the original method alone is not evidence that upstream metadata is still current.
- `listCustomerDrafts(companyId)`: return only proposals for an explicit customer, with a bounded result. Missing customer selection never becomes a global read. The future route must still perform the existing authentication and customer checks.

All mutation methods serialize on a registry-only transaction lock. Draft changes and audit writes commit together; an audit failure rolls back the change. Unknown credential fields are rejected, while existing credential references are retained. The service does not initialize schema, start a worker, test an API or alter source tables.

| Event | Draft outcome |
| --- | --- |
| First import | Disabled, pending review; proposed company/tenant retained only as evidence |
| Repeated current import | No-op; no duplicate records or audit entries |
| Changed source or connection dependency | Needs review; preserve the human proposal and prior reviewer history |
| Source missing | Mark absent and needs review; never delete history |
| Source returns | Reuse the same draft and require review |
| Save an edited proposal | Pending review with cleared current reviewer |
| Mark reviewed | Reviewed but still disabled; database prohibits activation |
| Dismiss | Retain proposal and audit; unchanged reimports retain dismissal |

Each saved tile retains its own ownership evidence plus the revision of its shared connection. Changing the connection invalidates dependent tile reviews. A Spotlight current-generation pointer has one stable evidence identity per customer; new daily generations do not create accumulating draft rows.

Review requires supported authority and an explicitly recorded vendor tenant, Elastic dataset or scanner targets as applicable. It rejects existing customer/tenant reassignment, configuration conflicts and historical-only pointers. These are proposal validation checks, not proof that the operator's entered scope is correct or vendor credentials can access it. Activation needs separate upstream verification, source-authority/mirror reconciliation, current credential versions and reader parity. In particular, environment secret rotation is not detected by the sanitized fingerprint.

No existing member/admin capabilities are changed: there is no UI or HTTP API through which accounts can mutate these drafts. The operator command requires existing server configuration/database access and derives its audit actor from the OS user and hostname; it is not a GitHub user identity. Future web wiring must use existing permissions and server-generated actor identity. Reviewed proposals cannot be treated as active sources; PostgreSQL currently enforces `enabled=false`. Roll back code by retaining unused draft/audit tables, not by dropping review history.

## Operator import, export and review

These commands are prepared for the reviewed rollout, not an instruction to run the migration on production now. First collect and inspect the read-only preview above. Source data is recollected by the tool; an uploaded report is never accepted as trusted source evidence. Use the resulting fingerprint for the explicitly global metadata import:

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs import \
  --env-file /opt/vuln/.env.local --fingerprint REVIEWED_PREVIEW_FINGERPRINT
```

This creates or updates inactive proposals for the collected existing connections, with audit history. It does not import findings or move secrets. A repeated current fingerprint is a no-op. Missing registry tables cause failure; no command installs schema automatically.

Export one customer's proposals, plus unassigned shared connections available for review, to a new private file:

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs export \
  --env-file /opt/vuln/.env.local --company CO-230784 \
  --output /home/codex/vuln-recovery/footprint-connector-proposals.json
```

No other customer's assigned proposal is exported. The file contains customer/vendor tenant IDs and scope fields, so retain it outside Git and the web root. The file is created exclusively with mode 0600 on Linux; existing paths are not overwritten. On Windows, use a directory with appropriate access controls. The export uses a read-only database connection and does not assign the shared connections it lists.

Copy a single `reviewRequest` object into a separate private JSON file. Verify `companyId`, vendor `tenantId`, `datasets`, `targets` and `authority` as applicable. Use `decision: "save-draft"`, `"reviewed"` or `"dismissed"` and add a short non-secret `note`. Keep the exported ID, revision and candidate hash. Do not add credentials, actor or activation fields.

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs review \
  --env-file /opt/vuln/.env.local \
  --input /home/codex/vuln-recovery/footprint-one-connector-review.json
```

The command rechecks current metadata, including separately stored saved-query connection revisions, before saving. Changed source metadata requires a fresh preview/import; an old editor revision requires a fresh export. A removed source can be dismissed after its absence has been imported. Review never tests vendor reachability or enables data collection. Environment secret rotation still is not represented by the sanitized fingerprint; activation needs credential-version and actual scope verification.

The command prints counts/review state only. Raw database errors and input contents are not echoed. A timeout or connection loss is an unconfirmed outcome: inspect a fresh export before retrying. Application and dashboard metadata are collected in separate read-only snapshots, not a globally atomic source snapshot. The command loads no application workers and never calls provider APIs or a ticket endpoint.

### Separate customer bindings for a shared connection

`docs/sql/customer-connector-bindings.sql` adds customer bindings and their audit records after the draft migration. This migration is explicit and has only been applied in disposable test databases. It does not rewrite existing drafts, credentials, tiles or findings.

Each binding is keyed by the source evidence ID and customer ID. The same shared connection can therefore have one independent scope, revision and review history for Alpha and another for Beta. Editing or dismissing Alpha does not change Beta or move the underlying shared evidence. Customer-owned connections and tiles cannot be assigned to a different customer. Historical import pointers cannot be converted into connections. A binding is still inactive even when reviewed.

The original `export`/`review` commands retain the old evidence proposal workflow. Use the new commands for customer assignments:

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs export-bindings \
  --env-file /opt/vuln/.env.local --company CO-230784 \
  --output /home/codex/vuln-recovery/footprint-bindings.json
```

Copy one `assignmentRequest` from the export into a new private JSON file. Confirm customer, tenant/dataset/targets and authority, add a non-secret note, and choose `save-draft`, `reviewed` or `dismissed`. Revision zero means no binding exists for that customer yet. The export includes available unassigned connections without automatically creating their bindings. It never includes another customer's assigned scope.

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs assign \
  --env-file /opt/vuln/.env.local \
  --input /home/codex/vuln-recovery/footprint-one-assignment.json
```

Source changes require reimporting a fresh preview before reviewing the changed assignment. Each customer's old review is independently stale until rechecked; a reviewed parent proposal does not grant all customers a binding. Concurrent edits accept only the expected revision. Assignment and audit commit together, and an audit failure rolls both back. All source/tenant/target review rules are shared with the existing draft validator.

The read-only Connectors status view now prefers a customer's binding when present and otherwise preserves the older proposal display. Tenant IDs, exact targets/datasets, credential references and audit notes remain outside its public response. Moved source ownership is shown as needing review without exposing the new owner's details. Missing binding tables preserve the existing view rather than creating schema during a request.

**Still required before activation:** actual vendor tenant/dataset/target verification; detection and resolution of overlapping customer scopes; primary-versus-mirror source decisions; credential-version tracking; and verified consumer/worker routing. The same connection may legitimately serve multiple customers, but recorded scopes alone do not prove isolation at the upstream provider. PostgreSQL still enforces `enabled=false` on these review tables. It does not claim the customer assignment migration is complete or launch any scans/imports.

Automate, Intune, Tidal and CrowdStrike host inventory now have a separate, optional [inventory import routing approval](customer-inventory-routing.md). It uses additive operational-route/audit tables and the `route-inventory` / `export-inventory-routes` commands. Customer review alone cannot create that approval or enable the provider switch. Actual imports check the approval's binding revision and current configuration before using the exact source identity. The v2 migration adds Tidal company IDs and CID-verified Falcon host imports; it does not activate Spotlight or FQL/patch routing. The Connectors view distinguishes reviewed proposals, operational approvals, a disabled switch and stale approvals without adding write controls. Other connector imports retain their existing routing. Intune remains disabled for this rollout.

## Customer status view

Under the disabled-by-default `VULN_REMEDIATION_UI` flag, `/connectors?companyId=...` shows saved configuration and inactive review proposals for that customer. It uses the same selector component as reporting, retains customer context when navigating to/from Remediation, and exposes no configuration or approval controls. Without the flag, the original Connectors page remains in place.

The read-only endpoint is `GET /api/elastic-dashboard/customer-connectors?companyId=...`; `?setup=1` returns only the persisted non-demo customer list. Both use the existing dashboard organization-member access check and UI flag. Missing customer selection never returns every customer's connector records. The service does not call the registry write methods or create missing tables.

The response omits raw vendor tenant values, credential references, target/dataset lists and audit notes. It distinguishes an absent registry migration from a failed database query and recognizes source/connection changes that invalidate an old review. Checking status does not save the changed evidence. The displayed check time is the metadata read time, not the last successful vendor import or a live connectivity test.

`Shared connector tools` opens `/connectors?view=shared` with a clear global-action notice. Those existing tools retain their existing behavior and permissions; the selected customer does not scope their actions. A return link restores the customer view. Treat these tools as operational controls, separate from inactive registry proposals.

Customer switching cancels and isolates earlier requests. Same-customer refresh failures retain prior results with a stale warning. The view never automatically syncs, scans or probes live connector health.

## Validation and next implementation

A disabled [registry-backed saved-result preview](customer-saved-source-reads.md#reviewed-registry-selection) now consumes reviewed customer bindings. It can select a saved Defender connection whose tenant and connection/import revision agree. Other scopes fail closed rather than using a global connection. This does not activate bindings, reroute imports or replace platform reporting; CrowdStrike preview now also checks whole-generation CID evidence in Spotlight summary v3. Live upstream verification and the wider authority migration remain pending.

```sh
node --experimental-vm-modules --test tests/customer-connector-preview.test.mjs
```

`tests/connector-metadata-postgres.mjs PRIVATE_RESTORE_SOCKET` creates and drops a disposable fixture database. It is guarded for the private recovery cluster and refuses normal network/production targets. Do not relax that guard to run it against production.

`tests/connector-drafts-postgres.mjs PRIVATE_RESTORE_SOCKET` tests the explicit migration, import/review transactions and audit rollback in a disposable fixture database. The optional `--with-restored-metadata` flag also reads metadata from the private `recovery_application` database and configuration presence from `/opt/vuln/.env.local`, then writes drafts only into that fixture database. Database addresses in the environment file are not used by this test. The fixture database is dropped on exit; the test does not approve real customer bindings.

Status tests: `node --experimental-vm-modules --test tests/customer-connector-status.test.mjs`. For the actual UI, build in a clean checkout without `.env` files, then run `node tests/customer-connectors-browser.mjs` with `PLAYWRIGHT_MODULE` pointing to an installed Playwright module. The browser test runs a credential-free local server with synthetic intercepted source data; it does not test live vendor connections.

Additional command checks: `node --experimental-vm-modules --test tests/customer-connector-registry.test.mjs`. The isolated integration test is `tests/connector-registry-command-postgres.mjs PRIVATE_RESTORE_SOCKET`; it exercises the actual command implementation against fixture source metadata and a disposable registry database, including stale-source rejection and private file export. It does not load production configuration.

`tests/connector-bindings-postgres.mjs PRIVATE_RESTORE_SOCKET` exercises the actual assignment/export commands, two customers sharing a scanner, optimistic edit conflicts, source changes, scope rules, transactional audit rollback and moved tile ownership in a disposable database. The source metadata is synthetic and provider APIs are never contacted.

Next: verified scope/authority and integration with the common customer-source readers. Actual scope verification and activation remain combined-release gates. Existing stores, schedulers, permissions and source routing remain authoritative.

## All-connector contracts and disabled integrations

The [connector status report](connector-rollout-status.md) covers all 20 integration types. A shared catalog describes findings, inventory, exposures, enrichment, saved queries, AppSec, ticket delivery and orchestration separately. It describes existing data paths and native identity evidence, not an implemented replacement schema. The customer status page includes a readable explanation of storage, lifecycle and routing readiness.

Environment evidence now includes a non-secret revision fingerprint for configured endpoints, cloud/tenant/client identity, and AppSec streams. Changing these fields invalidates review. Secrets never enter the fingerprint; secret rotation remains an explicit operational verification step. The collector also reads only the saved ConnectWise connection revision, preserving its existing credentials and routing.

Customer review can record inventory, enrichment and AppSec scopes independently. AppSec review requires datasets and repositories; scan roles require targets. Delivery and orchestration cannot claim findings authority. The common read-plan checker rejects missing, stale, wrong-customer or unsupported scope and overlapping same-provider data roles. It does not resolve cross-provider overlap, enforce upstream scan scope or activate workers. The registry still enforces `enabled=false`.

User decision, October 10: Burp, Nmap, Intune, IntelOwl and n8n remain available but disabled. Qualys remains planned. No missing credentials should be synthesized, and no active worker or scan should be created for these sources as part of rollout.


## Spotlight operational approval

The separate [Spotlight routing workflow](customer-spotlight-routing.md) adds `route-spotlight` and `export-spotlight-routes`. It requires a current primary-findings binding and an independent runtime switch. Inventory permission alone is insufficient. Review/assignment commands still cannot activate workers. The source pin, exact migration ordering, empty-result limit and compatible rollback requirement are documented in that workflow.
