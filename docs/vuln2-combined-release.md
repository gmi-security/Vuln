# Vuln2.0 combined release

This is the release preparation document, not permission to deploy. Production has not been restarted, reconfigured or migrated. The last verified production and `origin/main` commit is `a6c485b`. The candidate is on `Vuln2.0`; the final commit will be recorded after the remaining checks.

## What the release changes

| Area | Result |
| --- | --- |
| Navigation | Remediation, Companies, AppSec, Scanner Telemetry, Connectors and Settings. Existing tools remain available. |
| Remediation | Overview, Prioritize and Tickets use one customer selector. CVE links share the detail/patch panel, host CSV and existing ticket references. |
| Connector assignments | Existing configuration is imported as review evidence. Customer, vendor tenant, dataset/repository and scanner targets are explicit. An unverified match is not automatically approved. |
| Threat enrichment | MISP/OpenCTI signals and their source evidence remain visible in Prioritize and CVE details. |
| Platform persistence | Companies, folders, scans, findings and inventory move from JSON buckets into indexed rows in the same application database. Provider-specific fields remain in each row's JSON payload. |
| Source storage | Existing Defender/Spotlight imports, tile caches, histories, configuration and ticket/audit tables are retained. This does not copy every raw source into another normalized store. |
| Writes | One authoritative writer, a database epoch/revision fence, atomic changed-row saves and explicit errors for failed persistence. Ordinary analyst edits wait for the database before returning success. |
| Reporting | Reviewed customers can read saved Overview/executive reports. A separate worker refreshes them from committed platform data. Missing/stale reports are shown as unavailable, never invented zero results. |
| Recovery | The compatible candidate can recreate legacy buckets from current SQL rows, including changes made after cutover. A Git reset alone is not recovery. |

Roles and connector configuration privileges are unchanged. Burp, Nmap, Intune, IntelOwl and n8n remain available but disabled. No new real ticket, scan or email is part of release testing.

## Boundaries that remain in this release

SQL becomes the durable authority, but established business logic still uses a RAM compatibility cache. Its measured retained-data startup was about 44 seconds and 1.5 GiB peak RSS in the isolated persistence process. That is not a promise about the complete web process's memory. The dedicated reporting worker used about 258 MiB RSS with a 512 MiB heap.

An ordinary one-row edit measured 1.6 seconds; an unchanged scoped save measured 63 ms. Bulk imports, company renames/deletes and unscoped reconciliation still compare the complete cache before writing changed rows. Compatibility-page reads wait for pending persistence, so bulk publication can still delay those pages. Saved reporting reads avoid that path. Multiple active web writers are not supported; a conflicting process is rejected rather than silently overwriting data.

Saved reports reflect their displayed capture time, with a maximum 15-minute lifetime. Freshly calculating a report does not make old vendor observations recent. Existing email generation and other unconverted consumers retain their established calculations. Disabled Defender shadow experiments are not installed or enabled by this release.

These retained paths must be included in the release review. The release does not claim that every page has become a direct paginated SQL query or that source ingestion is instantaneous.

## Evidence completed

- Full retained copy: 40 customers plus an empty fixture, 510,945 findings, 14,983 assets, 385 scans and 64 folders. Every copied payload/order was verified, not just Defender samples.
- Forward migration: 185.5 seconds. Reverse migration: 103.4 seconds. All 91 legacy bucket checksums matched after the reversible test edits were restored.
- All 41 reporting customers completed in 47.7 seconds. Full Footprint/Atlas Overview, executive output and history matched the legacy calculations. Saved reads measured 6–66 ms on the private server copy.
- SQL tests cover interrupted migration/save, stale writers, concurrent reads, inserts/updates/deletes and recovery with newer changes. The real built-application rehearsal is tracked separately below.
- The final Linux full suite passed 782 tests with no failures and seven optional database cases skipped. The separate database suite passed all 49 tests, covering those cases. These counts overlap and are not additive.
- Browser: 15 Remediation groups, 11 Connectors groups and seven AppSec groups passed with synthetic API responses and no real tickets. Desktop/mobile output was inspected. Local cold-start/navigation budgets were adjusted without increasing interaction assertion timeouts.
- The final isolated Linux production build/type check and reporting-worker build passed after the shared-persistence fix. Both worker builds and the earlier Windows build also passed.

The HTTP rehearsal detected separately bundled persistence modules losing the loaded writer state. Persistence now shares its pool, authority, hashes and committed revision across route bundles in the same process. The corrected combined API rehearsal passed: SQL customer reports, durable analyst edit, stale-report withholding and worker refresh, restart, and reverse migration with the edit retained. No provider/ticket traffic was possible. Fourteen separate SQL groups include the same-process module regression; three schema groups prove conflict/late-failure rollback, repeat installation and unchanged authority.

## Remaining release gates

- [x] Complete the final build, full regression and combined application recovery rehearsal after the shared-state fix.
- [x] Finish the optional database-suite rerun after correcting a test that incorrectly rejected a valid background-refreshed tile.
- [ ] Confirm live customer/tenant/dataset/repository/target assignments. Current metadata contains 28 proposals for 40 customers; shared credentials and historical names do not prove ownership.
- [ ] Resolve Artemis connection refusal and ZAP timeout, or obtain an explicit decision to keep them visibly unavailable while preserving their data.
- [ ] Review the root-owned PM2 runtime inventory, including other users' PM2 managers, actual environment overrides and all writer owners.
- [ ] Reconcile server-local files and record the immutable release commit plus compatible recovery build.
- [ ] Review the RAM compatibility/bulk-publication boundary above and the exact customer/provider activation list.

The saved settings explicitly associate Defender with Footprint (`CO-230784`) and one environment CrowdStrike connection with Atlas (`CO-147284`). The other CrowdStrike connection, shared dashboard scope, scanner targets and AppSec repository ownership must not be guessed. Existing tiles are preserved throughout review.

The latest live read-only checks reached both CrowdStrike connections, Defender, Elasticsearch, AppSec, ConnectWise board lookup, MISP, OpenCTI, Automate and Tidal. Nessus, SpiderFoot and Vulners were reachable. This proves the tested reads, not scanner-launch or ConnectWise ticket-creation permission. Artemis and ZAP remain the known service failures.

## Operator preparation

The following are templates until the release commit and runtime inventory are reviewed. Do not run them against production as an unreviewed batch.

1. Preserve the local modified `scripts/audit-unenriched-auto-tickets.mjs` and untracked `scripts/print-saved-connectwise-connection.mjs` privately. Do not reset them or copy their contents into Git/logs. Compare their intended purpose before choosing the final release directory.
2. Use a separate release directory for `npm ci`, `npm run build`, `npm run build:reporting-worker` and `npm run build:summary-worker`. Build without production configuration. Do not overwrite the active `.next` directory.
3. Capture actual PM2 ownership/settings from a root terminal:

   ```bash
   node /home/codex/vuln-recovery/collect-release-runtime.cjs
   ```

   This inspects existing managers only, prints a credential-free summary and saves Vuln process definitions under a private root-owned recovery directory. It does not start/restart processes. It does not replace the database backup or verify external cron/n8n orchestration.

4. Copy the existing environment and encryption keys securely into the prepared release. Review only the new flags below. Preserve existing connector keys and OAuth callback settings.
5. Inspect the additive schema manifest without connecting to a database:

   ```bash
   node scripts/install-platform-release-schema.mjs --plan
   ```

## Maintenance deployment sequence

1. Stop admitting user mutations, drain imports/ticket jobs and stop **every** application writer. The general scheduler flag does not stop all independent jobs. Confirm the runtime inventory and durable source checkpoints before stopping the process owner(s).
2. Capture a fresh maintenance recovery point with `prepare-recovery-baseline.cjs` and verify it with `verify-recovery-baseline.cjs`. Preserve both configured database roles, even if they currently resolve to one database, plus private environment/PM2 configuration. The private test cluster must be stopped before using its recovery port.
3. Install the release schema from the prepared candidate:

   ```bash
   node scripts/install-platform-release-schema.mjs --apply --writers-stopped --env-file /opt/vuln/.env.local
   ```

   The 19 connector/reporting/source-summary scripts use one transactional checksum ledger. Core migrations use the existing versioned ledger. A conflict or failure stops the command; keep maintenance active and investigate. Existing manually installed untracked schemas are not silently adopted. Installation creates no customer approvals and does not switch authority. The core and release-schema transactions are separate, so a core failure can leave the additive release schema installed safely for an explicit retry.
4. Apply/verify the two optional performance indexes in `docs/sql/remediation-read-indexes.sql` on each table's actual owning database. Check `pg_index.indisvalid`; `IF NOT EXISTS` alone does not certify an interrupted index. Never run `CONCURRENTLY` inside a transaction.
5. Import a **fresh** connector preview, then apply the reviewed customer bindings, source/mirror decisions and operational routes using `customer-connector-registry.mjs`. Do not use stale fingerprints or the synthetic test reviews. Keep provider switches off until those approvals exist.
6. Run `platform-store-transition.mjs --status` with the application environment securely loaded, then `--to-sql --writers-stopped --expect-epoch EPOCH --expect-revision REVISION`, substituting the observed values. The transition verifies all records before committing authority. See [the detailed write/recovery guide](platform-store-cutover.md).
7. Start the single compatible application writer with `VULN_PLATFORM_STORE=sql` and the reviewed flags. Start the reporting worker separately, wait for fresh reports, then verify customer counts, CVE/CSV preparation, saved tiles and a reversible analyst edit.
8. Resume only reviewed jobs. Open the site after data and workflow acceptance, not merely an HTTP 200. Anonymous `/api/health` is a liveness check and does not prove successful hydration or correct customer data.

## Flag plan

| Setting | Release rule |
| --- | --- |
| `VULN_REMEDIATION_UI=true` | Enables the new layout and shared CVE panel; existing dashboard access remains required. |
| `VULN_PLATFORM_STORE=sql` | Set only after the authority transition commits. |
| `VULN_REPORTING_STORAGE=published`, `VULN_REPORTING_INPUT_REVISIONS=true` | Uses application SQL records and committed report inputs. |
| `VULN_REPORTING_SQL_READS=true`, `VULN_REPORTING_EXECUTIVE_ENABLED=true` | Enable only with reviewed customers and a running/warmed worker. |
| `VULN_REPORTING_SQL_CUSTOMERS`, `VULN_REPORTING_WORKER_CUSTOMERS` | Same explicit approved customer list, at most 50; no wildcard. |
| `VULN_REPORTING_WORKER_ENABLED=true` | Separate process running `scripts/customer-reporting-worker.mjs` with a 512 MiB Node heap. |
| `VULN_REPORTING_SOURCE_URL`, `VULN_REPORTING_DATABASE_URL` | Both equal the securely supplied application `DATABASE_URL`; do not paste URLs into the runbook. |
| `VULN_REVIEWED_*_PROVIDERS` | Only providers whose actual scopes and operational approvals were reviewed. Never infer a customer from a shared key. |
| `VULN_SAVED_SOURCE_READS` | Optional separate-source display; requires its own summary worker/read configuration if enabled. It is not required for platform SQL authority. |
| `VULN_SHADOW_CVE_READS=false` | Leave the experimental comparison path off. |
| Existing scheduler/export/bridge flags | Preserve the reviewed runtime choices. Do not turn every background job on together. |

The separate report worker does not automatically load `.env.local`; its process configuration must supply the reviewed environment. The final PM2 command must use the confirmed process owner and release directory, not a guessed process ID.

## Recovery

For a UI-only problem, disable the new UI/read flags in the compatible build. Keep the manual-packet protections: the original pre-Vuln2.0 code can mishandle new manual-only drafts.

After SQL accepts writes, stop/drain writers and run the candidate's `--to-legacy` transition with the current epoch/revision before returning to legacy mode. It preserves new edits, inserts and deletions. Start a **compatible fenced build**, verify the data, then resume jobs. Do not remove the fence, restore frozen pre-cutover buckets or use `git reset --hard` as a substitute.

External tickets/scans cannot be undone by Git or PostgreSQL rollback. Reconcile their IDs before retrying uncertain actions. Retain the old buckets, SQL rows and recovery artifacts until retention is explicitly decided.
