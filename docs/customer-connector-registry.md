# Customer connector registry: import preview

This is the first backend checkpoint for the Vuln2.0 registry. It prepares evidence for review. It does not save bindings, migrate credentials, change customer access or switch any reader/worker to a new data source.

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

All entries stay disabled and pending review. The fingerprint is deterministic for the sanitized metadata, not a credential revision or an authorization token. It deliberately excludes secret values, so changing an environment secret alone does not change it.

## Validation and next implementation

```sh
node --experimental-vm-modules --test tests/customer-connector-preview.test.mjs
```

`tests/connector-metadata-postgres.mjs PRIVATE_RESTORE_SOCKET` creates and drops a disposable fixture database. It is guarded for the private recovery cluster and refuses normal network/production targets. Do not relax that guard to run it against production.

Next: transactional, idempotent import of reviewed candidates as disabled draft bindings with audit records. Activation will require approved scope/authority and current connection references. Until reader parity is proven, the existing stores, schedulers, permissions, source routing and pages continue to operate normally.
