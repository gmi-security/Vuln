# Customer connector registry: preview and disabled drafts

The Vuln2.0 registry now has a read-only preview and transactional storage for disabled draft proposals. No production service or page uses the new tables yet. It does not migrate credentials, change customer access, activate bindings or switch readers/workers to a new source.

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

The explicit migration is `docs/sql/customer-connector-drafts.sql`. It creates three application-database tables: import batches, connector drafts and audit history. It is not an automatic migration and has only been run in disposable test databases. There is no production write command or endpoint in this checkpoint. The read-only preview command above remains read-only.

`createConnectorDraftStore(db)` provides backend methods for a future authorized adapter:

- `importPreview(expectedFingerprint, actor, collect)`: recollect through a trusted server-side metadata collector, verify the reviewed fingerprint, and atomically record new/changed/missing evidence. Replaying the same current fingerprint creates no duplicate batch or audit entries. Do not supply an uploaded JSON file or client-controlled callback as the collector.
- `reviewDraft(input, actor, resolveCompany)`: save, mark reviewed or dismiss a proposal with the expected revision and source evidence hash. Resolve company IDs through an existing trusted customer service. Record scope, proposed authority and a review note. Do not put credentials into notes or scope fields.
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

No existing member/admin capabilities are changed: there is currently no UI or API through which accounts can mutate these drafts. Future wiring must use existing permissions and server-generated actor identity. Reviewed proposals cannot be treated as active sources; PostgreSQL currently enforces `enabled=false`. Roll back code by retaining unused draft/audit tables, not by dropping review history.

## Validation and next implementation

```sh
node --experimental-vm-modules --test tests/customer-connector-preview.test.mjs
```

`tests/connector-metadata-postgres.mjs PRIVATE_RESTORE_SOCKET` creates and drops a disposable fixture database. It is guarded for the private recovery cluster and refuses normal network/production targets. Do not relax that guard to run it against production.

`tests/connector-drafts-postgres.mjs PRIVATE_RESTORE_SOCKET` tests the explicit migration, import/review transactions and audit rollback in a disposable fixture database. The optional `--with-restored-metadata` flag also reads metadata from the private `recovery_application` database and configuration presence from `/opt/vuln/.env.local`, then writes drafts only into that fixture database. Database addresses in the environment file are not used by this test. The fixture database is dropped on exit; the test does not approve real customer bindings.

Next: a read-only, customer-scoped Connectors status/review view, followed by permission-preserving mutation adapters and read-model parity. Until those release gates pass, existing stores, schedulers, permissions, source routing and pages continue unchanged.
