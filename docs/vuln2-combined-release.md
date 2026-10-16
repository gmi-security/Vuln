# Vuln2.0 combined release

**October 14 revised rollout:** [Step-one readiness and current rollout scope](rollout-step-one.md) takes precedence over conflicting backup, customer-consolidation and initial worker/connector activation requirements below. The operator waived new backup/restore work and chose to preserve existing customer records for this rollout. Historical checks retain their actual pass/unverified status. This revision does not authorize merge or deployment.

This is the release preparation document, not permission to deploy. Production has not been restarted, reconfigured or migrated. The last verified production and `origin/main` commit is `a6c485b`. The verified application runtime is committed as `3e2357686f2140136b4923430c947c1ddf5ce865` on `Vuln2.0`. Subsequent release-review scripts/documentation do not change that runtime. The final archive and its checksum are recorded separately after those files are committed.

**October 11 publication direction:** The user supplied the root runtime inventory and authorized pushing the prepared commits to the existing `Vuln2.0` branch only. Do not merge into `main`, deploy, restart services, migrate production schemas or change production configuration as part of this push. The `89703cb` source archive remains an immutable earlier review artifact; this runtime-inventory documentation update is a later commit with no application changes.

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
- [x] Review the supplied root PM2 inventory, including the other users' existing PM2 managers.
- [ ] Reconcile application environment files, non-PM2/external jobs and in-flight writes for the maintenance window. Unset startup flags do not establish their effective application values.
- [ ] Reconcile server-local files and record the immutable release commit plus compatible recovery build.
- [ ] Review the RAM compatibility/bulk-publication boundary above and the exact customer/provider activation list.

The independent code/build/test preparation is complete. PM2 process ownership is now confirmed by the supplied inventory. The unresolved external inputs are the customer scope decisions and the two unavailable scanner services; effective configuration and job draining still belong to the final maintenance review. Do not claim deployment readiness until those inputs are reconciled; another generic regression run does not resolve them.

The saved settings explicitly associate Defender with Footprint (`CO-230784`) and one environment CrowdStrike connection with Atlas (`CO-147284`). The other CrowdStrike connection, shared dashboard scope, scanner targets and AppSec repository ownership must not be guessed. Existing tiles are preserved throughout review.

The latest live read-only checks reached both CrowdStrike connections, Defender, Elasticsearch, AppSec, ConnectWise board lookup, MISP, OpenCTI, Automate and Tidal. Nessus, SpiderFoot and Vulners were reachable. This proves the tested reads, not scanner-launch or ConnectWise ticket-creation permission. Artemis and ZAP remain the known service failures.

### Customer review artifact and current evidence

The additional read-only collection at `2026-10-11T06:18:36.855Z` found **40 customers, 421 recorded scans/imports and eight tiles without a saved customer owner**. The earlier retained-copy migration benchmark had 385 scans; these are different captures, not an assertion that production stayed frozen. Explicit saved ownership evidence was found for Footprint's Defender connection and Atlas's completed Spotlight pointer/two saved tiles. Environment-only connections and repository ownership require the separate connector preview; absence from this collection does not mean a source is unconfigured.

`scripts/collect-customer-assignment-review.mjs` performs bounded read-only queries without hydrating findings. `scripts/render-customer-assignment-review.mjs` turns its private JSON into a standalone searchable HTML file. The generated file contains customer/target information and must stay outside Git. The reviewed artifact is available in the local `Vuln2.0-release-review` folder beside the checkout as `Customer connector review.html`. Forty rows, customer filtering, expandable evidence and mobile fit were verified in the browser. The file makes no HTTP requests and cannot activate assignments.

```bash
node scripts/collect-customer-assignment-review.mjs --env-file /opt/vuln/.env.local --output /private/new-customer-review.json
node scripts/render-customer-assignment-review.mjs --input /private/new-customer-review.json --output /private/new-customer-review.html
```

Both output paths must be new files in an appropriate private directory. These commands do not approve ownership or change existing tiles.

A separate TCP-only check confirmed Artemis refuses connections on its configured remote port 5000; ZAP's configured remote port 8081 timed out after ten seconds. Both are on different hosts from the Vuln application. This narrows the failure to service/listener/network reachability before an API call, but does not determine whether the remote service, firewall or configured address needs correction. No scan or authenticated mutation was attempted.

The two server-local scripts were preserved in a private archive at `/home/codex/vuln-recovery/server-local-tools-20261011.tar.gz`, SHA-256 `25a8aad9f5becc7ebe7ebe69610f07f03c0f9f72ea783dcddc8f3839f5222e7b`. The tracked script has 25 added and 14 removed lines; the other is untracked. Their contents were not printed or added to Git. Production files remain untouched. Preserve this archive alongside the fresh maintenance recovery point and retain the original checkout when choosing a separate release directory.

## Operator preparation

### Runtime inventory supplied October 11

The user ran `collect-release-runtime.cjs` as root and supplied the result collected at `2026-10-11T15:00:01.810Z` (08:00 America/Phoenix). It recorded:

- Root's PM2 manager: one online process, `vuln`, PM2 ID `0`, working directory `/opt/vuln`, executable `/usr/bin/npm`, one instance in fork mode and seven recorded restarts.
- The `chuck` and `johngoff` PM2 managers: zero processes each. No additional Vuln process was found in those managers.
- The collector could read the process's initial environment. Every inspected release/scheduler flag was unset there. The app also loads environment files, so these values must not be interpreted as all features or jobs being disabled.
- No explicit heap value, kill timeout or memory restart value was reported by the inspected PM2/startup fields. The npm wrapper result does not establish the running Next.js child's effective V8 heap limit.
- The collector saved private PM2 recovery definitions under `/root/vuln-release-recovery/runtime-Wcy316`. Keep these private; the pasted summary contains no credentials.

This confirms the PM2 owner and process identity at collection time. It does not inventory cron/systemd/remote orchestration or prove imports/ticket jobs have drained. Use the root manager and process name `vuln` in the final reviewed deployment procedure; do not act on the other users' managers. No process action was performed as part of recording this evidence.

The following are templates until the release commit, effective configuration and activation scope are reviewed. Do not run them against production as an unreviewed batch.

1. Preserve the local modified `scripts/audit-unenriched-auto-tickets.mjs` and untracked `scripts/print-saved-connectwise-connection.mjs` privately. Do not reset them or copy their contents into Git/logs. Compare their intended purpose before choosing the final release directory.
2. Use a separate release directory for `npm ci`, `npm run build`, `npm run build:reporting-worker` and `npm run build:summary-worker`. Build without production configuration. Do not overwrite the active `.next` directory.
3. The root inventory above is captured. Refresh it from a root terminal immediately before the maintenance window if process ownership/settings may have changed:

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
4. Apply/verify the two **required CVE lookup indexes** in `docs/sql/remediation-read-indexes.sql` on each table's actual owning database before enabling Remediation. Check the index definition, `pg_index.indisvalid` and `indisready`; `IF NOT EXISTS` alone does not certify an interrupted index. Never run `CONCURRENTLY` inside a transaction. The source index keeps a single-CVE lookup from scanning a multi-million-row import; the grouped-ticket index supports CVE ticket references. Installation is an explicit operator step, not a startup migration.
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

The separate report worker does not automatically load `.env.local`; its process configuration must supply the reviewed environment. The application owner is confirmed as root with process name `vuln`; the final PM2 command must also use the reviewed release directory and environment. No separate reporting worker was present in the supplied inventory.

## Recovery

For a UI-only problem, disable the new UI/read flags in the compatible build. Keep the manual-packet protections: the original pre-Vuln2.0 code can mishandle new manual-only drafts.

After SQL accepts writes, stop/drain writers and run the candidate's `--to-legacy` transition with the current epoch/revision before returning to legacy mode. It preserves new edits, inserts and deletions. Start a **compatible fenced build**, verify the data, then resume jobs. Do not remove the fence, restore frozen pre-cutover buckets or use `git reset --hard` as a substitute.

External tickets/scans cannot be undone by Git or PostgreSQL rollback. Reconcile their IDs before retrying uncertain actions. Retain the old buckets, SQL rows and recovery artifacts until retention is explicitly decided.
