# Microsoft Defender customer ingestion

Defender imports feed the shared customer findings, inventory, reports, risk scoring and patch-review workflows. Source evidence remains in application PostgreSQL; lightweight device/CVE findings enter the existing scanner store. Page navigation reads saved data rather than starting new exports.

API endpoints in this release target Microsoft's commercial cloud. Government-cloud endpoints need a separate explicit configuration extension.

## Entering credentials

After this branch is merged and deployed:

1. Create the customer on **Companies** if it does not exist.
2. Open **Connectors → Microsoft Defender · Customer connections → Manage Defender connections** (`/defender`).
3. Configure `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET` and `DEFENDER_CUSTOMER` in the existing server environment, then restart the application. Use the secret value, not its ID. The customer must match one existing name or exact company ID; ambiguous names are rejected. No customer is created or guessed.
4. Select the customer and **Test connection**. It reads a small device page and vulnerability page using server credentials; it does not import data.
5. Select **Sync now**. Configuration and daily scheduling are read-only in the browser. Set `DEFENDER_DAILY=false` on the server for manual-only imports; otherwise daily imports begin after the first success.
6. Reconcile the first result with the customer's Defender portal using the same scope and observation time. Open **Companies**, **Findings**, or **Reporting** for the shared totals and patch-review queue.

Additional tenants use numbered prefixes such as `DEFENDER_2_TENANT_ID`, `DEFENDER_2_CLIENT_ID`, `DEFENDER_2_CLIENT_SECRET`, `DEFENDER_2_CUSTOMER`, and `DEFENDER_2_DAILY`. Each tenant/customer may occur only once. Existing encrypted bindings remain usable during migration; removing environment variables alone does not delete a saved connection.

The Entra application needs WindowsDefenderATP application permissions `Vulnerability.Read.All` and `Machine.Read.All`, with customer administrator consent. The customer must have the relevant Defender product entitlement. The API hostname is `api.security.microsoft.com`; token acquisition retains the documented `api.securitycenter.microsoft.com/.default` audience.

Credentials are encrypted with AES-256-GCM using a purpose-specific key derived from `NEXTAUTH_SECRET` (at least 32 characters). Credentials are never returned to the browser. Environment configuration synchronizes to encrypted storage without incrementing unchanged revisions. Browser save/draft-credential requests are rejected. Rotating the encryption secret requires reapplying server credentials. No roles or other connector permissions change.

No customer credentials are included in this repository. Browser mutation endpoints require a signed-in organization member and a matching Origin, consistent with the shared dashboard's current access model.

## Reading results

Results appear at `/defender`, in a Defender section on the selected **Company**, and on **Reporting** when that customer is selected. Views include:

- Open vulnerability instances and severity counts.
- Unique CVEs, ordered by worst reported severity, affected device count, then CVE.
- All matching software findings for a selected CVE, including update description, KB/update ID, recommendation reference, CVSS and source timestamps.
- Device inventory, using Defender device IDs rather than matching devices by shared IP or hostname.
- Daily observed counts. One latest successful observation per UTC day; missing days are not filled with zero.

Tables use server-side pages of 50 and a bounded scroll area. Navigation reads stored results only. Connection progress is polled every 10 seconds only while a queued/running import exists.

**Platform integration:** Completed imports feed shared findings, inventory/coverage, priorities, SLA, compliance, executive reports and subsequent daily metrics. RBVM/Swath uses configured weights and CVE enrichment. The existing remediation review, approval, routing, ConnectWise creation, tracking and CSV attachment workflow accepts Defender through stored-finding packets. Assets stay in the CSV rather than the ticket body. Automatic ticket creation retains its existing pilot/customer gates.

CrowdStrike/FQL and Elasticsearch/ES|QL tiles retain their explicitly selected sources. They are not silently converted to cross-source totals. Defender has no CrowdStrike ExPRT value. The customer/platform views provide integrated totals.

## Storage and import behavior

Defender and risk tables use `DATABASE_URL` through the application pool. Shared normalized findings are also persisted in `vuln_store`. The patch subsystem may use a separate configured database; no cross-database SQL joins were added.

| Table | Purpose |
| --- | --- |
| `defender_connections` | Customer-to-tenant binding, encrypted credentials, revision, daily setting and current successful generation |
| `defender_import_runs` | Durable queue, actor, revision, progress, error, lease and completed summary |
| `defender_devices` | Device inventory per generation |
| `defender_records` | Vulnerability instances and source evidence per generation |
| `defender_cves` | Materialized CVE aggregates for efficient sorted browsing |
| `defender_daily_history` | Successful daily count observations |

The tenant is unique across customer connections. After a baseline is published, changing that customer's tenant requires a separate explicit migration. A missing customer mapping never falls back to GMI.

The worker reads device inventory and `SoftwareVulnerabilitiesByMachine` pages. Vulnerability pagination follows `@odata.nextLink`; device pagination supports next links and explicit `$top`/`$skip`. Outbound page addresses are restricted to the expected Microsoft hosts and API paths; redirects are rejected. Requests have timeouts, bounded 429/5xx retries and token renewal on expiry/401. Pagination exhaustion throws rather than publishing partial results.

Each source identity includes device ID, vendor, software name, software version and CVE, within its customer generation. Repeated rows upsert; different affected software versions stay separate. Rows with no CVE are counted as skipped inventory rows. Malformed CVE/device identities stop publication.

Only one Defender run is processed at a time across app processes. Queue insertion is idempotent per customer. A database lease is renewed on each stored page. Expired workers are marked failed and cannot write or publish. After a restart, queued work is picked up; interrupted work retains the previous successful dataset and can be retried with Sync now. This first release restarts a failed full export rather than resuming an old Microsoft cursor.

Publication creates CVE aggregates, saves summary/history, and swaps the current pointer in one transaction. A complete empty export can publish zero source findings. Failed/incomplete exports cannot resolve findings by absence.

The platform projects one lightweight finding per stable device/CVE. Same-customer, unambiguous inventory/hostname matches can corroborate other scanners. Shared IPs and ambiguous hostnames do not merge Defender devices. Assignments, first-seen dates and accepted-risk/false-positive decisions survive refreshes. Remediation text retains distinct affected software versions and recommended updates.

Absence resolves a finding only when the device is still present and has reported since the previous observation. Missing/offline devices remain unresolved; findings corroborated by another source remain open. Reappearance reopens resolved findings. Defender-only tickets have a verification button that requires a complete import newer than ticket creation, less than 24 hours old, with fresh evidence for every scoped device. Mixed-source tickets retain manual verification.

Source counts can exceed platform counts because software versions and scanner corroboration are deduplicated. Platform counts can retain offline-device findings absent from the current export. Missing CVSS stays null in source/RBVM data; the legacy finding model keeps its existing zero-score convention. Newly discovered assets use default Internal/Normal context until configured; these defaults are not Defender exposure attestations.

Retention keeps the current and previous successful generations; older failed/completed generations are pruned in small batches after one day. Daily history retains 365 days and displays the most recent 90 observations.

The worker starts five minutes after server boot, then checks every minute. Daily scheduling begins after a successful manual baseline and permits one scheduled attempt per 24 hours. It honors `VULN_DISABLE_SCHEDULER=true`. Sync now and Sync all reconcile server configuration before queuing work. Existing completed imports are also published to shared findings without another Microsoft export.

The published-generation marker is persisted with common findings in `vuln_store`. Restart recovery replays a generation if its common snapshot was never saved. Projection reads grouped findings in keyset pages of 2,000; raw Microsoft payloads stay in PostgreSQL. The existing scanner architecture still holds normalized findings in RAM, so memory grows with distinct device/CVE counts.

### Publication save recovery

The October 7 publication recovery fix addresses shared snapshot timeouts being swallowed by `flushNow`, which previously allowed a misleading Defender "Published completed generation" log. It also repairs the snapshot flusher's promise guard: the guard compared two different promises and never cleared, preventing subsequent timer-driven saves and retries.

- Defender publication now requires a successful durable snapshot save. Failure clears the provisional generation marker, retains the completed source import, and retries on a later worker pass. The API reports publication as pending while the save is running.
- Hydration checks stored Defender generation markers against their assessment and active device/CVE finding counts. An incomplete projection is eligible for replay without another Microsoft export.
- Metadata is captured with the collection arrays; all database shards are read in one repeatable-read transaction. Concurrent saves cannot pair older findings with a newer publication marker.
- Hydration primes committed shard hashes so boot does not rewrite every unchanged shard. Snapshot hashing yields between batches and serialization yields between shards. Large atomic saves have a five-minute transaction budget, with individual statements limited to one minute and lock waits to ten seconds.

Deploy through the normal main-branch pull/build/restart process. No database migration, credential change or manual Defender resync is required. Allow the existing five-minute worker startup delay, then refresh the customer page. Confirm the publication log appears without a corresponding snapshot-save failure, and verify the customer's findings and executive report remain populated after a later routine restart. Source software-instance counts may exceed platform device/CVE counts.

Validation: 66 targeted checks passed with no skips, including disposable local PostgreSQL transactions, save failure/retry, concurrent hydration, generation repair, restart recovery, customer/global/asset/executive totals and reporting/patch regression coverage. The production build passed. Live publication and production performance still require verification after deployment; these checks do not establish the cause of every server slowdown.

RBVM stores scores under tenant key `defender:<companyId>`, using `finding_risk`, `risk_history` and `risk_snapshots`. Customer scores and active membership publish transactionally; interrupted passes keep prior scores. `finding_risk.source_open` defaults true for existing records. Reappearing Defender findings clear a verified state but preserve analyst Swath overrides. Patch storage stays in its existing configured database.

## Validation and rollout

- Run `node --experimental-vm-modules --test --test-force-exit tests/defender.test.mjs tests/defender-platform.test.mjs tests/defender-risk.test.mjs` and the affected reporting, risk and ticket regression suites.
- For database integration tests, set `DEFENDER_TEST_DATABASE_URL` to a disposable **localhost** PostgreSQL database. The tests refuse a remote host.
- Run the production build with schedulers disabled and no production credentials/database in the build environment.
- Browser checks cover server-managed configuration, no credential editing, test/sync, CVE pagination and drilldown, customer switching, reporting links and narrow screens.
- Merge the task PR into main before deployment. Deploy a successfully built release; retain the prior working release for rollback. No import should be started just by opening a page.
- First live acceptance: confirm tenant/customer, compare device and distinct CVE counts against the same Microsoft export, spot-check CVSS/remediation, repeat the import for idempotence, and verify page responsiveness during import. Live validation requires the customer's credentials and is not replaced by fixture tests.

## Remaining scope

Full snapshots are used. Delta imports need a durable watermark, replay overlap and periodic full baselines. Live validation requires the customer's API connection after deployment; fixture tests do not establish live ingestion success. Normalized scanner findings still use the existing RAM-backed common store; replacing that architecture is separate work.

Validation for the platform integration (October 7, 2026): 119 checks passed, including local PostgreSQL import/risk/ticket integration tests, with no skipped tests. Production build and browser checks passed using synthetic data. ESLint could not run because the repository has no ESLint 9 configuration file. No production imports, tickets, settings or server files were changed during validation.

References: [Microsoft app authentication](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp), [vulnerability export](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities), [device inventory](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines).
