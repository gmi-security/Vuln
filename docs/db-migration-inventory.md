# Database Migration Inventory

This is the evidence checklist for moving Vuln's core state from `vuln_store` snapshots to rows. The new schema remains unused by production application reads and writes until the later cutover.

## Read-only snapshot inventory

On the Droplet, in `/opt/vuln`, run the command below with the existing server configuration. It uses a read-only repeatable-read transaction, reads bucket lengths without transferring JSONB payloads, and prints no credentials:

```sh
node --env-file=.env.local scripts/inventory-db.mjs
```

Record the output, current UTC time, deployment commit, whether Atlas Spotlight import is active, and whether the old App Platform service is still running. The bucket counts are a first-pass size check, not proof that every ID and relationship is valid. Do not run schema migrations until a restorable database backup and an isolated restore have been verified.

## Production facts to record before backfill

| Check | Result |
| --- | --- |
| `DATABASE_URL` database name, host type, role (no secret) | Pending live inventory |
| Dashboard/ticket database selected by `ELASTIC_VULN_DATABASE_URL` or fallback | Pending live inventory |
| PostgreSQL version, free disk, connection limit | Pending live inventory |
| `vuln_store` update time and collection bucket counts | Pending live inventory |
| Atlas active Spotlight run ID and exact record count | Pending live inventory |
| Table owners and migration privileges | Pending live inventory |
| App Platform and Droplet worker/scheduler ownership | Pending live inventory |
| Backup timestamp, size, isolated restore result and duration | Pending live inventory |
| Duplicate IDs, orphan references, ID suffix maxima and per-company totals | Pending deeper read-only audit |

The inventory script is intentionally narrow. The deeper audit and full comparison tool belong to Phase 2 of the migration plan. A mismatch between the old and new stores must be resolved against one frozen snapshot revision; comparing two moving targets can produce false differences.

## Explicit schema command

The migration runner does not run at application startup. After the backup and restore gate, an operator can apply versioned migrations with:

```sh
node --env-file=.env.local scripts/migrate-db.mjs --apply
```

That command creates the `app_*` staging tables and records SQL checksums in `app_schema_migrations`. It does not copy the snapshot, change application reads or writes, or alter Spotlight and ticket tables. It should first be exercised against the isolated restored database. The script refuses a modified migration that was already applied.
