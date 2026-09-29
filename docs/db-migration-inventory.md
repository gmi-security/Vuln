# Database Migration Inventory

This is the evidence checklist for moving Vuln's core state from `vuln_store` snapshots to rows. The new schema remains unused by production application reads and writes until the later cutover.

## Read-only snapshot inventory

On the Droplet, in `/opt/vuln`, run the command below with the existing server configuration after this branch's files are available there. It uses a read-only repeatable-read transaction, reads bucket lengths without transferring JSONB payloads, and prints no credentials. The output also identifies the database, role, schema, PostgreSQL version, and relevant table owners and sizes:

```sh
node --env-file=.env.local scripts/inventory-db.mjs
```

Record the output, current UTC time, deployment commit, whether Atlas Spotlight import is active, and whether the old App Platform service is still running. The command now includes exact counts for active Spotlight generations and any in-progress import runs; this can take longer than the bucket count. The bucket counts are a first-pass size check, not proof that every ID and relationship is valid. Do not run schema migrations until a restorable database backup and an isolated restore have been verified.

## Observed production baseline (2026-09-29 17:54 UTC)

The operator ran the read-only command on `Vuln-NYC1` from `/opt/vuln-inventory` and provided its output. The connection reached the internal DigitalOcean managed PostgreSQL host on port 25060, database `gmi_vuln`, role `gmi_vuln`, schema `public`, PostgreSQL 18.6. Every reported app table has owner `gmi_vuln`.

The active snapshot source is sharded `vuln_store`, last updated at `2026-09-29T17:54:28.784Z`. It has 90 valid collection buckets and no malformed bucket keys. This matches the repository's fixed layout of 64 finding, 16 asset, 8 scan, 1 company and 1 folder buckets. Counts at that snapshot revision:

| Collection | Count |
| --- | ---: |
| Companies | 21 |
| Folders | 42 |
| Scans | 209 |
| Normalized findings | 208,946 |
| Assets | 10,803 |
| Compensating controls | 0 |
| Identity aliases | 0 |

`vuln_store` occupies 158,826,496 bytes including indexes/TOAST. The frozen legacy `vuln_snapshot` occupies 21,741,568 bytes. `spotlight_import_records` exists and occupies 832,913,408 bytes, but table size does not establish an exact active record count or a completed Atlas generation. The existing dashboard job/query, ticket request, reporting queue, trend and Spotlight tables are present in this same database. The inventory alone cannot prove whether the running dashboard is using the `DATABASE_URL` fallback or a dedicated URL pointing to the same database.

The operator later reported `spotlight.active: []` and `spotlight.running: []`. Thus no Spotlight generation is currently promoted and no database run is marked running, despite the records table occupying space. The next read-only diagnostic is the recent run history, including stored failure messages:

```sh
node --env-file=/opt/vuln/.env.local scripts/spotlight-run-diagnostic.mjs
```

Run this from `/opt/vuln-inventory` after updating that checkout. It does not count or expose record payloads and makes no database changes. Do not promote or remove any stored generation based on table size alone.

This is an observed baseline, not a cutover reconciliation. Snapshot contents may have changed since the command ran; the exact Spotlight active count, backup restore, ID/relationship audit, worker ownership and final write-freeze timing remain open.

## Production facts to record before backfill

| Check | Result |
| --- | --- |
| `DATABASE_URL` database name, host type, role (no secret) | Internal DO host, `gmi_vuln` database and role; confirmed 2026-09-29 |
| Dashboard/ticket database selected by `ELASTIC_VULN_DATABASE_URL` or fallback | Pending live inventory |
| PostgreSQL version, free disk, connection limit | Version 18.6 confirmed; free disk and connection limit pending |
| `vuln_store` update time and collection bucket counts | 2026-09-29T17:54:28.784Z; 90 buckets; counts above |
| Atlas active Spotlight run ID and exact record count | Pending live inventory |
| Table owners and migration privileges | `gmi_vuln` owns reported tables; explicit migration privilege test pending |
| App Platform and Droplet worker/scheduler ownership | Pending live inventory |
| Backup timestamp, size, isolated restore result and duration | Pending live inventory |
| Duplicate IDs, orphan references, ID suffix maxima and per-company totals | Audit tool ready; live/restore result pending |

The basic inventory is intentionally narrow. For a deeper read-only check, `scripts/audit-snapshot.mjs` reads one sharded bucket at a time in a consistent snapshot. It reports duplicate or malformed IDs, missing company/scan/folder references, maximum ID suffix, and per-company/source/status/severity totals. It transfers snapshot payloads to the one-off Node process but prints only IDs and aggregate counts. Prefer running it against an isolated restored copy before running it against the live database. With a securely supplied `RESTORE_DATABASE_URL` environment variable:

```sh
DATABASE_URL="$RESTORE_DATABASE_URL" node scripts/audit-snapshot.mjs
```

A mismatch between the old and new stores must be resolved against one frozen snapshot revision; comparing two moving targets can produce false differences. The full row-by-row parity tool belongs to Phase 2.

## Explicit schema command

The migration runner does not run at application startup. After the backup and restore gate, an operator can apply versioned migrations with:

```sh
node --env-file=.env.local scripts/migrate-db.mjs --apply
```

That command creates the `app_*` staging tables and records SQL checksums in `app_schema_migrations`. It does not copy the snapshot, change application reads or writes, or alter Spotlight and ticket tables. It should first be exercised against the isolated restored database. The script refuses a modified migration that was already applied.
