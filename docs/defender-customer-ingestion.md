# Microsoft Defender customer ingestion

This first release adds customer-bound Defender for Endpoint / Vulnerability Management ingestion. It uses the application PostgreSQL database, with bounded batches and completed generations. It does not require Elasticsearch or n8n.

API endpoints in this release target Microsoft's commercial cloud. Government-cloud endpoints need a separate explicit configuration extension.

## Entering credentials

After this branch is merged and deployed:

1. Create the customer on **Companies** if it does not exist.
2. Open **Connectors → Microsoft Defender · Customer connections → Manage Defender connections** (`/defender`).
3. Select the customer. Enter the **Directory / tenant ID**, **Application / client ID**, and **Client secret value**. Use the secret's value, not its ID.
4. Select **Test connection**. It reads a small device page and vulnerability page; it does not import data or save credentials.
5. Select **Save connection**, then **Sync now**. Saving does not start an import.
6. Reconcile the first result with the customer's Defender portal using matching export scope and observation time. Then enable **Import daily** and save.

The Entra application needs WindowsDefenderATP application permissions `Vulnerability.Read.All` and `Machine.Read.All`, with customer administrator consent. The customer must have the relevant Defender product entitlement. The API hostname is `api.security.microsoft.com`; token acquisition retains the documented `api.securitycenter.microsoft.com/.default` audience.

Credentials are encrypted with AES-256-GCM using a purpose-specific key derived from `NEXTAUTH_SECRET`. That server secret must be at least 32 characters. Existing saved credential values are never returned to the browser. A blank secret preserves the saved secret; changing tenant/application IDs requires entering a secret again. Rotating `NEXTAUTH_SECRET` requires re-entering these connection credentials.

No customer credentials are included in this repository. Browser mutation endpoints require a signed-in organization member and a matching Origin, consistent with the shared dashboard's current access model.

## Reading results

Results appear at `/defender`, in a Defender section on the selected **Company**, and on **Reporting** when that customer is selected. Views include:

- Open vulnerability instances and severity counts.
- Unique CVEs, ordered by worst reported severity, affected device count, then CVE.
- All matching software findings for a selected CVE, including update description, KB/update ID, recommendation reference, CVSS and source timestamps.
- Device inventory, using Defender device IDs rather than matching devices by shared IP or hostname.
- Daily observed counts. One latest successful observation per UTC day; missing days are not filled with zero.

Tables use server-side pages of 50 and a bounded scroll area. Navigation reads stored results only. Connection progress is polled every 10 seconds only while a queued/running import exists.

**Current boundary:** Defender data is separately labeled. Existing scanner aggregates, risk/Swath scoring, executive reports, compliance outputs, CrowdStrike tiles and ConnectWise patch workflows do not yet include it. Follow-on work must add source-aware adapters to those pipelines before claiming combined coverage. This release does not fabricate CrowdStrike ExPRT values for Defender. Daily history is displayed as observations; a chart can reuse these stored values later.

## Storage and import behavior

All tables use `DATABASE_URL` through the existing application pool, not `ELASTIC_VULN_DATABASE_URL` or the RAM-backed `vuln_store`.

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

Publication creates CVE aggregates, saves summary/history, and swaps the current pointer in one transaction. A complete empty export can publish zero findings. Failed/incomplete exports cannot resolve findings by absence. Defender's current-generation replacement never changes findings owned by other sources.

Retention keeps the current and previous successful generations; older failed/completed generations are pruned in small batches after one day. Daily history retains 365 days and displays the most recent 90 observations.

The independent worker starts five minutes after server boot, then checks every minute. Daily scheduling begins only after a successful manual baseline and is limited to one scheduled attempt per 24 hours. It honors `VULN_DISABLE_SCHEDULER=true`. Manual Sync now and Sync all enqueue saved customer connections. There is no longer an implicit environment-only Defender import into GMI; legacy `DEFENDER_*` deployments must enter their customer connection in the new screen.

## Validation and rollout

- Run `node --experimental-vm-modules --test --test-force-exit tests/defender.test.mjs`.
- For database integration tests, set `DEFENDER_TEST_DATABASE_URL` to a disposable **localhost** PostgreSQL database. The tests refuse a remote host.
- Run the production build with schedulers disabled and no production credentials/database in the build environment.
- Browser checks should cover secret masking/clearing, test/save, CVE pagination and drilldown, switching customers, and narrow screens.
- Merge the task PR into main before deployment. Deploy a successfully built release; retain the prior working release for rollback. No import should be started just by opening a page.
- First live acceptance: confirm tenant/customer, compare device and distinct CVE counts against the same Microsoft export, spot-check CVSS/remediation, repeat the import for idempotence, and verify page responsiveness during import. Live validation requires the customer's credentials and is not replaced by fixture tests.

## Follow-on stages

Validation on October 7, 2026: production build passed; 65 Defender, PostgreSQL integration, Spotlight import, CrowdStrike dashboard and finding-correlation checks passed. Local browser checks passed for masked/cleared credentials, test/save, pagination, CVE drilldown, device view, customer switching and mobile width, with no browser errors. Browser data was synthetic; no customer API credentials have been tested and nothing has been imported into production.

1. Add source-aware risk/reporting adapters and explicit cross-source identity rules; do not sum overlapping scanner populations blindly.
2. Add Defender CSV/patch request and ConnectWise adapters, preserving per-software recommendations.
3. Add delta imports with a durable watermark, replay overlap and periodic full baselines. Microsoft limits delta lookback to 14 days; a longer gap needs a new baseline.

References: [Microsoft app authentication](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp), [vulnerability export](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities), [device inventory](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines).
