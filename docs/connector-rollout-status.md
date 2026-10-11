# Vuln2.0 connector rollout status

Updated October 10, 2026. Development branch: `Vuln2.0`. Production was not deployed, restarted or reconfigured by these checks.

## What is complete in this connector pass

- All 20 integration types have a documented data role, storage path, native identity and lifecycle contract.
- Customer assignment review handles scanner, inventory, enrichment, query and AppSec roles independently. Wrong-customer, stale and unsupported assignments are rejected. Shared connections can have separate customer scopes.
- Changes to non-secret endpoint, tenant/client/cloud and AppSec stream settings invalidate old reviews. Credential values are neither copied nor displayed.
- Defender saved reads enforce reviewed tenant and connection/import revision. CrowdStrike saved reads enforce whole-generation CID evidence, using summary model v3, with exact local unresolved placeholders accounted for separately.
- Customer Connectors shows how each source is used, without adding a second customer selector or configuration permissions.
- Saved CrowdStrike queries and live patch reports now have optional reviewed customer/CID routing and approval provenance. Changed approval withholds old query results and blocks new live ticket/verification operations from old packets. Existing results, history and ticket records are retained. Query-only approval does not publish platform findings.
- Saved Elasticsearch queries now have optional exact customer/dataset approvals. FROM patterns are restricted to approved exclusive datasets and resolved to physical indexes; unsupported sources fail explicitly. Caches/jobs require current approval, and adding tiles remains immediate. Actual dataset ownership and live acceptance remain pending.
- Automate, Intune, Tidal and CrowdStrike host inventory now have optional runtime routing by reviewed vendor identity. A separate audited approval and provider switch are required; review alone never activates an import. These paths were tested with fixtures and remain off in production; Intune remains disabled. Spotlight findings now have their own optional, separately approved CID routing; live scope verification and activation remain pending.
- Malformed Nessus, SpiderFoot, Artemis and ZAP import responses now fail instead of appearing empty. Intune and Automate reject truncated/malformed inventories; Intune pagination cannot send its token to another origin; Automate rejects invalid customer filters and explicitly conflicting customer IDs in returned rows.
- Existing reporting classifications, customer isolation, source-specific counting and manual patch packet behavior have regression coverage. Inventory and OSINT do not become patchable vulnerability counts. Tidal now reports failed/truncated roster and device pages, preserves separate customer sessions and retains its explicit partial-source error reporting. Artemis rejects truncated task-result imports. Tidal's existing first-page 400/403/404 unavailable-integration convention remains unchanged and does not prove absence of devices.

This completes the implemented connector catalog, review contracts and this regression pass. It does **not** complete live customer assignment activation or the authoritative platform database migration. Remaining stored-platform/source consumers still use legacy routing. Supported inventory, Spotlight, scanner and saved CrowdStrike/Elasticsearch query consumers enforce their specific reviewed scopes only when separately opted in. Live Elastic ownership, mixed-customer datasets, live AppSec acceptance, authority/mirror decisions and the final writer handoff remain release gates.

## Connector-by-connector status

"Configured" means configuration evidence exists, not that every request or customer scope is verified. The read-only inventory found 40 customers and 14 configured integration types. Configuration came from saved database metadata and the server environment file, not an attestation of the running PM2 environment. Historical source pointers and shared credentials alone do not establish current customer ownership.

| Connector | Data role | Evidence in this pass | Rollout state / remaining requirement |
| --- | --- | --- | --- |
| Microsoft Defender | Device/software vulnerabilities and inventory | Configured; saved SQL revision guard, import, risk and customer reporting fixtures | Preserve existing publication. Final authoritative SQL writer migration remains separate |
| CrowdStrike | Spotlight findings, device inventory, FQL results | Configured; separate reviewed inventory, Spotlight and saved-query CID guards, fixture coverage | Live FQL/patch collection checks query approval; saved CVE/manual patch and new delivery check completed reviewed Spotlight proof. Other stored-platform consumers and live scope verification/activation remain pending |
| Elasticsearch | Customer-owned queries and cached results | Configured; optional exact dataset approval, physical-index query restriction, cache/job proof and SQL overlap checks | Saved-query routing implemented but inactive; verify real datasets/permissions and CS mirrors. Shared datasets, AppSec and findings authority remain separate |
| Nessus | Scan findings and scanned-host coverage | Configured; optional reviewed folder/target routing tested with fixtures | Import, polling and native controls have reviewed ownership checks. Live folder/API validation and activation remain pending; no real scan launched |
| Vulners | Bridge scan findings and CVE enrichment | Configured; status reachable; bridge auth, targets and job fixtures | Status is not proof of every bridge or API permission; review each deployment/target mapping |
| SpiderFoot | OSINT and attack-surface observations | Configured; optional exact-root routing, export provenance and launch checks tested with fixtures | Existing scoring retained; live source/target verification and activation remain pending |
| Artemis | Attack-surface observations | Optional exact-tag/root/analysis routing, pagination and launch checks tested with fixtures | Pending/stopped analyses report partial coverage. Earlier live connectivity failure remains unresolved; source acceptance and activation pending |
| ZAP | Web findings | Configured; report/scope fixtures; live status timed out | Remote service/network must be repaired and rechecked |
| Tidal | Customer/device inventory | Configured; reviewed portal-company routing, actual adapter/session and CSV bypass checks | Runtime enforcement implemented behind empty switch. Verify live company IDs before activation. Reviewed mode requires live sync; name-only CSV is rejected |
| ConnectWise Automate | Customer/device inventory | Configured; actual adapter and import fixtures, reviewed client-ID routing, SQL approval/revocation checks | Runtime routing implemented behind an empty provider switch; live ownership review and activation pending. No live inventory pull |
| MISP | CVE threat enrichment | Configured; actual adapter response/failure and enrichment-role tests | Preserve existing signals; a sighting is not independently verified exploitation |
| OpenCTI | CVE threat enrichment | Configured; actual adapter response/failure and enrichment-role tests | Preserve existing signals; relationship presence alone does not prove exploitation |
| AppSec / Trivy via Elastic | Repository scans, findings and deltas | Optional reviewed repository routing, fixed filtered queries, SQL ownership/audit and API/UI isolation tests | Runtime implemented behind a blank opt-in; actual repository/mapping/key acceptance and activation remain pending. AppSec stays separate from device findings |
| ConnectWise PSA | Ticket delivery and tracking | Saved connection revision present; mock transport and ticket lifecycle checks | Existing board/company routing retained; no live ticket created; not a findings source |
| Burp | Web scan findings | Unconfigured; XML parser and assignment fixtures | Available but disabled, as requested |
| Nmap | Host/service discovery and observations | Unconfigured; XML/service and assignment fixtures | Available but disabled, as requested |
| Intune | Managed-device inventory | Unconfigured; adapter and import fixtures, reviewed tenant-ID routing, SQL approval/revocation checks | Routing implemented and tested with fixtures; remains available but disabled, as requested |
| IntelOwl | Threat analysis/enrichment | Unconfigured; adapter/enrichment-role fixtures | Available but disabled; no analysis job launched |
| n8n | Optional orchestration | Unconfigured; configuration and prohibited-findings-role checks | Available but disabled; no workflow invoked |
| Qualys | Planned connector | Planned state and unsupported-role rejection | No production adapter claimed or enabled |

## Operational problems confirmed

The scanner status audit completed at **2026-10-10 17:50:41 UTC** from the Vuln server using its existing adapter status functions:

- **Artemis: connection refused.** The configured destination rejected the connection before the API could respond. Check the Artemis service/container, listening port, configured address and network policy; this result cannot determine which is wrong by itself.
- **ZAP: timeout.** Its configured status request did not complete (about 10.5 seconds). Check the service/gateway and network path. Preserve the existing gateway Host header and API-key behavior while diagnosing.
- Nessus, SpiderFoot and Vulners reported reachable. This is reachability evidence, not complete import, credential-permission or tenant verification.

No scanner was launched, source import started, ticket sent or production setting modified. The private audit contains only classifications and timings, not credentials, raw vendor responses or customer findings. The app currently uses PostgreSQL TLS with certificate verification disabled; the metadata collector needed matching audit-process settings. This observation is not a change to production TLS configuration.

## Validation

- Local regression run: **195 passed, 3 optional database tests skipped**, no failures. The optional suites then passed separately on isolated databases: 15 ConnectWise tests, 17 Defender tests and one Defender risk test, with no skips and no live tickets. These counts overlap the local suite and are not additive.
- Private PostgreSQL: **60 distinct scenario groups passed** across summary building, metadata collection, registry drafts/commands/bindings, worker recovery and retention. Actual bindings were saved for two synthetic customers across scanner, inventory, enrichment and AppSec roles. No production tables were mutated.
- Browser: **13 groups passed**, covering customer Connectors, source explanations, Remediation/CVE/patch flow, pagination, failure states, switching customers and mobile layout. Vendor and ticket responses were fixtures; zero real tickets sent.
- Production build and TypeScript check passed in the local unconfigured checkout.

Private SQL evidence is under `all-connectors-s7l9EUbo` in the server recovery area. It is not public content. Disposable databases are removed and the private cluster stopped after tests. The source code remains local until the combined release is reviewed. A final focused connector run passed all 25 tests after the Tidal/Artemis completeness fixes.

## Full-size CrowdStrike result

The isolated recovery-copy rebuild matched **2,119,658 retained rows and all 11,710 CVE results** against the earlier independent baseline. Two builds took 143 seconds and 88.5 seconds; saved summary/page reads took 23.5-35.4 ms. Restart found no new work and created no duplicate job. These are source-summary measurements, not whole-page latency or current production totals.

The v2 guard initially withheld the generation because 343 rows had no CID. The follow-up audit traced **all 343 to exact local placeholders** generated by the importer when CrowdStrike omitted a previously discovered ID. These rows are closed bookkeeping records, not real vendor responses with missing tenant evidence. No actual vendor rows had missing/invalid CID; all recognized CIDs agreed.

Summary v3 now identifies that exact stored placeholder format, accounts for it separately and keeps the CID requirement on every real vendor row. Placeholder-only or malformed evidence still fails. The full v3 build took **83.99 seconds** and saved reads **30.5-40.4 ms**. **Every baseline count and all 11,710 CVE rows matched; the guarded reader passed.** Restart was idle with no extra job. Raw source records were not relabeled, dropped or mutated. This resolves the retained-generation blocker; it does not establish live credential ownership or activate customer routing.

## Import ownership follow-up

The actual store import paths now refuse ambiguous customer selection: tied name matches for SpiderFoot/Burp, conflicting inventory owners for Nmap, ambiguous Artemis tags/aliases, duplicate normalized names for Tidal/Automate/Falcon/Nessus, and multiple internal companies for Intune/Falcon/Automate. Existing Artemis/Nessus scans cannot be reused under another customer. Independent valid Falcon/Automate clients continue, and errors/skipped counts explain withheld imports.

This deliberately changes ambiguous imports from first-match assignment to a reported conflict. Existing records are preserved; unambiguous legacy mappings and scoring remain unchanged. This is an interim safeguard, **not reviewed-registry routing**: unique fuzzy names still do not prove customer ownership. Correct explicit source/target bindings remain necessary before activation. No role/configuration permissions change. Manual sync and sync-all summaries now report partial import errors, tenant failures and mapping conflicts as attention-needed, without embedding raw provider error text.

Validation for this follow-up: **113 local tests passed**, including seven groups invoking the actual store import entrypoints with mocked transports; **29 isolated PostgreSQL groups passed** (12 summary, nine worker, eight retention), plus the full retained-data comparison above. The local production build/TypeScript pass succeeded. Four customer-connector browser groups passed, including partial-import warning display, redaction and recovery to success. All vendor responses were intercepted fixtures. No live import, scan or ticket was executed; the private cluster was stopped after testing.

## Reviewed inventory routing checkpoint

The latest inventory routing checkpoint passed **106 distinct local tests**, **17 isolated PostgreSQL groups** (seven inventory-route and ten existing binding regression groups), a local production build/TypeScript pass and **five browser groups**. The one extra runtime-wrapper test was run after the initial 105-test suite; counts are distinct, not repeated-run totals. Screenshots were inspected. A first SQL assertion expected the wrong guard because the synthetic unknown customer used a nonzero route revision; the fixture was corrected and both suites then passed. Test databases were removed and the private cluster stopped. SQL evidence: `inventory-routing-result.log`, `inventory-bindings-regression.log` in the private recovery test directory.

The inventory change adds `customer_inventory_routes` and its audit table, exact binding-revision approval, optimistic concurrent edits, one active owner per source scope, current-metadata validation and customer-visible approval/switch state. Existing review-table `enabled=false` constraints are retained. It does not move historical assets, switch platform storage or cancel already running imports; drain jobs before changing ownership. An empty switch restores legacy routing, so it is **not a source kill switch**. See [inventory routing and rollback](customer-inventory-routing.md).

## Tidal and CrowdStrike inventory follow-up

Latest follow-up: **Tidal and CrowdStrike host inventory are now implemented against the same approval model.** Tidal keeps the exact case-sensitive portal company ID and only enters approved sessions. CrowdStrike selects the exact environment connection and verifies every host CID, discovered ID and complete batch before applying that tenant. SQL rejects a duplicate CID owner and one Falcon connection assigned to multiple destinations. Neither import falls back to customer-name guessing in reviewed mode.

**135 distinct local tests passed** (133 in the regression run plus two follow-up cases), **19 isolated PostgreSQL groups passed**, and the local build/TypeScript and **five browser groups passed**. Browser checks include Automate, Tidal and CrowdStrike approval states and no new controls. All vendor responses were intercepted fixtures; screenshots were inspected. No live import/scan/ticket or production change occurred. The private cluster was stopped after tests.

Limits: reviewed CrowdStrike inventory rejects the existing adapter's over-10,000 window and empty responses that cannot prove CID; it does not claim those tenants are fully imported. Tidal preserves its unavailable-integration convention; zero accessible devices is not proof of an empty estate. The CSV route returns an explicit conflict while reviewed routing is on. Spotlight findings, saved FQL tiles and patch collectors have not been rerouted by this host-inventory change. See [current inventory behavior and rollback](customer-inventory-routing.md).

## Remaining before the combined rollout

1. Restore Artemis and ZAP connectivity and repeat their read-only checks.
2. Reconcile actual runtime configuration and customer tenant/dataset/target mappings. Review shared-source ownership, Elastic mirrors and overlapping sources. Do not approve inferred mappings just to clear a checklist.
3. Wire reviewed scopes into the remaining runtime consumers/workers with enforcement tests; keep existing settings and permissions. Current registry proposals cannot activate themselves.
4. Finish the SQL reporting replacement and authoritative writer handoff/recovery work. The connector catalog is not that database migration.
5. Assemble the UI and backend candidate, reconcile server-local changes, verify a fresh recovery point, rehearse migration/rollback, then present the exact release for approval.

Burp, Nmap, Intune, IntelOwl and n8n do not require credentials for this rollout because the user chose to leave them disabled. Qualys remains planned. Existing customer records, saved tiles, tickets, schedules and source data must be preserved.


## Spotlight import routing follow-up

Spotlight now has its own operational approval and provider switch, requiring a findings-primary binding. Host inventory approval cannot authorize it. It selects the reviewed customer/configuration/CID, checks real source records and retains the previous completed results on failure. Customer Connectors reports these two approvals separately. No permissions changed.

Reviewed version-4 imports pin their source assignment so legacy generations or renewed assignments cannot be resumed into a mixed generation. Final publication checks current approval under the registry lock, company/CID/source identity, exact local placeholders and complete discovery counts. Empty or placeholder-only generations cannot prove CID ownership and are withheld. Concurrent discovery failure drains sibling requests before the worker lock is released.

Validation: **197 distinct local regression tests**, **18 isolated PostgreSQL groups** (eight Spotlight and ten existing binding checks), **six browser groups**, and a local production build/TypeScript pass. The 21 relevant tests were rerun after the final discovery-error handling change; they are included in 197, not added again. Tests used fixture source responses and disposable databases, not production data or live imports. The private cluster was stopped after database checks. Full-scale promotion cost remains unmeasured. See [operation, migration and rollback details](customer-spotlight-routing.md).

Next: remaining scanner/source consumers and FQL/patch routing, live customer scope verification, SQL reporting replacement and authoritative writer handoff, then the combined rollout and recovery rehearsal. Nothing in this checkpoint deploys or enables production routing. Burp, Nmap, Intune, IntelOwl and n8n remain available but disabled.


## Nessus routing and shared approval follow-up

Nessus now has a separately approved, opt-in route using the numeric scanner folder ID and exact hostname/IP/CIDR scope. Bulk imports validate the complete result before applying it; unexpected hosts and changed runs cannot resolve old findings. Native start/rescan, polling and controls check the reviewed customer/folder. Existing findings/scoring and snapshot storage remain. The Connectors page reports the approval without exposing targets or changing permissions.

Inventory, Spotlight and scanner approvals now share the same transaction/audit implementation, with their existing provider-specific rules and interfaces. Nessus endpoint/TLS changes require renewed review. Polling shares the new metadata lookup per pass and scan roster per folder; the existing four-second polling architecture is not replaced. Repeated reviewed syncs reuse pending records and select the latest observed run, preventing duplicate local scan records and repeated completed-run imports.

Validation: **207 distinct local regression tests**, **34 isolated PostgreSQL groups**, **seven browser groups**, and a local production build/TypeScript pass. Database checks ran in disposable databases on the private recovery cluster, then dropped them and stopped the cluster. Browser and HTTP tests used synthetic responses; no production setting, live source import, real scan or ticket was changed. See the [Nessus operation and rollback guide](customer-scanner-routing.md).

Next: remaining scanner consumers (SpiderFoot, Artemis, ZAP and Vulners), FQL/patch routing and live customer scope checks, then SQL reporting/write migration and combined release/recovery rehearsal. Native create-in-folder and run metadata still require verification against the deployed Nessus version before activation.

## SpiderFoot and Artemis routing follow-up

Both OSINT integrations now use separately approved customer routing. SpiderFoot selects an owner by the exact approved scan root and verifies every exported event's scan provenance. Artemis uses the exact approved tag and filters each analysis before collecting its task results. Pending/stopped analyses produce a partial-import warning, and incomplete or conflicting batches retain previous data. Names no longer choose the customer in reviewed mode.

The existing OSINT preview and launch action share the same source-specific target plan. Preview failure is visible and disables launch; each actual launch rechecks approval. Discovered related hosts remain attack-surface evidence and do not grant Nessus scan approval. Reviewed automatic pivots require a separate Nessus approval and its target checks. Customer permissions and scoring remain unchanged.

The additive OSINT route migration preserves Nessus approvals. Scanner approvals validate peers under the registry lock so overlapping SpiderFoot root sets cannot be approved; Artemis tags have one customer owner. No approvals or production switches were populated.

Validation: **216 distinct local regression tests**, **39 isolated PostgreSQL groups**, **nine browser groups**, and a production build/TypeScript pass. The full regression run passed 215 tests; the final partial-coverage change passed 58 focused tests, including one additional test (reruns are not added twice). All API transports were synthetic; SQL checks used disposable private-cluster databases which were removed, and the cluster was stopped. No real source import, remote scan, ticket, production configuration change or deployment occurred. See [operation and rollback](customer-osint-routing.md).

Next: ZAP/Vulners consumers, FQL/patch routing, actual source/customer verification, SQL reporting and authoritative writer handoff, then the combined release/recovery rehearsal. Live Artemis/ZAP connectivity still needs resolution. Burp, Nmap, Intune, IntelOwl and n8n stay disabled.


## ZAP and Vulners bridge routing follow-up

Both active scanners now use separately approved customer targets: whole origins for ZAP and exact hostnames/IPs for the bridge. Launch, polling and publication recheck ownership. ZAP context/report scope prevents loose URL-prefix matches; bridge result checks reject foreign hosts, malformed bodies and known incomplete responses. The migration preserves existing scanner approvals and audits. Vulners cloud enrichment stays separate from active bridge scanning.

Failed or incomplete targets no longer count as completed scans. Rescan starts a real newly checked job. Unsupported remote pause/resume/stop controls now report that they must be performed in the scanner console. Existing data and permissions remain. The bridge completeness contract is still unverified, so reviewed mode does not auto-resolve older findings; ZAP reports remain labeled retained session evidence.

Validation: **238 distinct local tests**, **43 isolated PostgreSQL groups**, **nine browser groups**, mobile visual review and production build/TypeScript checks passed. Disposable databases were removed and the private cluster stopped. No production configuration, import, remote scan, ticket, push or deployment occurred. See [operation, limitations and rollback](customer-active-scanner-routing.md).

Next: saved FQL/patch consumers, source authority and live customer/source verification, SQL reporting/write migration and combined release/recovery rehearsal. Earlier Artemis/ZAP connectivity failures still require resolution. Burp, Nmap, Intune, IntelOwl and n8n remain available but disabled.

## Saved FQL and live patch routing follow-up

Checkpoint 46 adds an explicit saved-query approval per customer/CID, tied to the saved CrowdStrike connection revision. The server scopes FQL, checks returned CIDs and repeats approval checks after collection. Totals use population metadata with a one-record CID check; the deployed API's count/filter contract still needs live acceptance. Query/import approvals cannot give the same CID to different customers.

Cached results, daily history and live patch packets carry provenance. An approval change withholds old results and prevents new live tickets or verification from old packets; stored definitions, history and ticket references remain. The existing customer selector supplies preview and patch ownership. Tile saving stays immediate. Stored-platform/manual packets retain existing behavior; their source-authority migration remains separate. Roles, scoring and ConnectWise routing were not changed.

Validation: **394 distinct local tests**, **51 isolated routing/binding SQL groups**, **28 dashboard/ticket SQL tests**, **16 browser groups**, production build/TypeScript and mobile visual review passed. Fixture-only SQL databases were removed and the private cluster stopped. No production mutation, source import, scan, ticket, push or deployment occurred. See [operation and recovery](customer-query-routing.md).

Next: remaining ES dataset/source authority and stored-platform consumer routing, live customer/source acceptance, SQL reporting integration and authoritative writer handoff, then combined release/recovery rehearsal. Repeated approval checks are not a distributed transaction fence; drain operations before routing changes. Earlier Artemis/ZAP connectivity issues and the five intentionally disabled integrations are unchanged.

## Follow-up: reviewed Elastic saved-query routing

Checkpoint 47 extends the query approval model to exact exclusive Elastic indexes/data streams. The existing customer selector determines ownership, and tile saving remains immediate. FROM patterns are narrowed to the approved list and resolved to physical indexes; aliases, remote sources, joins and unsupported syntax are withheld. Mixed-customer datasets cannot be approved as if they were exclusive. Cached results and job responses require current proof, while old data stays stored.

The additive v2 query-route migration preserves CrowdStrike approvals and audit, allows both query providers for a customer, and prevents overlapping Elastic dataset ownership. Empty provider switches still mean legacy behavior; no production activation occurred. See [the Elastic operation and recovery guide](customer-elastic-query-routing.md) and checkpoint 47 in the platform plan for verification evidence.

Next: remaining stored-platform/AppSec/source authority paths, actual customer/source acceptance, SQL reporting integration and authoritative writer handoff, then combined release/recovery rehearsal. Query-only approval does not publish findings or make mirrored sources additive. The earlier Artemis/ZAP connectivity issues and intentionally disabled integrations are unchanged.


## Follow-up: reviewed AppSec repository routing

Checkpoint 48 adds customer AppSec summary, scan-day trend and repository detail on the existing environment Elastic connection. A single customer selector and repository links preserve scope; missing/stale/revoked approvals cannot fall back to the organization view. Coverage uses approved repositories and capped findings are explicitly labeled. The fixed document-filter contract applies only to AppSec, not arbitrary shared-index saved queries.

The additive application-database migration and actual operator CLI passed eight isolated PostgreSQL groups, including overlapping repository ownership, concurrent revisions, audit failure and stale-route revocation. **301 local tests passed** (two existing database suites skipped locally), the final production build/TypeScript pass succeeded, and **seven AppSec browser groups passed**. The browser-discovered encoded repository drilldown was fixed; desktop/mobile screenshots were inspected. Evidence is recorded in checkpoint 48 of the plan. No live customer assignment, source query, source import, ticket, production change or deployment occurred. See [AppSec operation and recovery](customer-appsec-routing.md).

The blank AppSec switch retains legacy organization access. Turning it off is not revocation. Live repository/mapping/key acceptance, remaining stored-platform consumers, SQL reporting and authoritative writer recovery remain release gates.


## Follow-up: saved CrowdStrike CVE and patch ownership

Checkpoint 49 closes the saved-source path behind the existing Spotlight opt-in. CVE details and manual preparation require the approved customer/CID and a completed version-4 import pinned to that approval. Raw records must agree with indexed identity; mixed-source legacy assessments are withheld rather than guessed. New ticket sends recheck the saved proof through the existing pre-send hooks. Default-off behavior, unrelated Defender-only preparation, historical data and ticket references are preserved.

**337 distinct local tests passed**, along with **18 isolated PostgreSQL groups**, **28 existing dashboard/ticket tests with database coverage**, and production build/TypeScript. Two database suites skipped locally were exercised in the isolated SQL run. The SQL test loader was corrected after an initial dependency-link failure; the complete rerun passed. Disposable databases were removed and the private cluster stopped. No live source import, scan, ticket, push or production deployment occurred. See [saved CVE operation and recovery](customer-stored-cve-routing.md).

Activation now requires a completed reviewed Spotlight import before saved CrowdStrike CVE preparation can succeed. Renewed assignments or a newer completed generation require fresh drafts for sending. Existing draft/history records are retained; a concurrent revocation can leave a pending audited draft but cannot pass the subsequent proof check. No distributed transaction with ConnectWise is claimed.

Next: remaining stored-platform source authority and mirror/correlation decisions, live customer/source acceptance, SQL reporting integration and authoritative writer recovery, followed by the combined release rehearsal. The prior Artemis/ZAP issues and intentionally disabled integrations remain unchanged.


## Follow-up: customer primary-source and mirror review

Checkpoint 50 adds persisted source selection and an atomic review audit in the application database. Operator `export-sources` / `review-sources` commands derive decisions from current customer bindings. An Elastic mirror requires an explicit same-customer primary and mapping evidence reference; its existing query-only permission can remain intact. Changed bindings/configuration invalidate review, and separate endpoint primaries still require finding-level correlation before combined reporting. The Connectors page displays the selected customer's status without source identities, private notes or new controls.

**320 distinct local tests passed**, **18 isolated PostgreSQL groups passed**, **11 browser scenario groups passed**, and final production build/TypeScript passed. JSONB key-order stability was corrected after the first SQL run, and the final real database round trip passed. Mobile screenshots were inspected; test databases were removed and the private cluster stopped. See [source-selection review and limits](customer-source-selection-review.md).

This records review, not runtime reporting activation. The current report also includes workflow, scanners, web/OSINT, risk, inventory context and history; replacing it with a raw-source count would change behavior. Actual source/mirror ownership, overlapping-source correlation, compatible SQL report reads, writer/recovery handoff and combined release acceptance remain required. No live source, ticket, production configuration or database change occurred. Nothing was pushed or deployed.

## Follow-up: saved reporting sections across platform sources

Checkpoint 51 implements a compact SQL report for the full existing customer report sections, using saved normalized findings, scan state, inventory, enrichment/source activity and history. It preserves separate endpoint, web and OSINT semantics and all workflow statuses. Atomic replacement, customer scope, identity validation, stale-source detection and a content checksum protect the result. The builder and reader remain private-verification-only; no application route or worker uses them yet.

**23 distinct local tests passed**, **12 isolated PostgreSQL groups passed**, and production build/TypeScript passed. Full unchanged-model parity also passed on the retained Footprint and Atlas data: **369,180 findings** across Defender, CrowdStrike and SpiderFoot platform records. Final builds took 31.2 and 23.1 seconds once; subsequent reads took **6.0-7.7 ms**. Generated model JSON was 7,897 and 79,420 bytes. The 471 MiB restored-test peak includes independent reference arrays. These are historical-restore results, not new live provider or ownership acceptance.

The disposable databases were dropped and the private cluster stopped. No production change, push or deployment occurred. See [saved report sections and remaining integration](customer-reporting-sections.md).

Next: refresh these summaries after completed publication and related workflow/scan/asset/history changes, bind reads to current reviewed source and publication revisions, and connect the reversible Overview path. Executive risk/SLA compatibility, authoritative writer/recovery handoff, live source acceptance and the coordinated release rehearsal are still required. This does not enable the five unconfigured integrations or resolve the earlier Artemis/ZAP live failures.

## Follow-up: durable report refresh and Overview request

Checkpoint 52 adds a disabled dedicated reporting worker with coalesced customer jobs, renewable ownership, source-revision fencing, atomic report/job completion, retry limits and explicit versioned manual retry. No page builds reports or calls vendors through this worker. The real Remediation Overview now requests only its report sections, skipping unused executive/insights aggregation; it still uses the existing platform data. Original reporting, permissions, the customer selector and CVE patch flow remain intact.

**53 local tests**, **21 isolated PostgreSQL groups**, **10 browser groups**, authenticated HTTP with the UI flag off/on, production build/TypeScript and worker compilation passed. Actual CLI interruption and recovery were tested. Under a 512 MiB Node heap limit, retained Footprint and Atlas builds took **32.1 / 25.2 seconds** and peaked at **228 / 244 MiB RSS**, with lease renewal during both builds. These are private historical-data tests, not renewed live connector acceptance. No real ticket was sent.

The SQL reader is still not connected to the page. Next: accepted customer source/publication/workflow revisions, less conservative invalidation and the reversible saved Overview read, then executive-report compatibility, authoritative writer recovery and combined-release acceptance. The private-only guards remain. The test databases were dropped and private cluster stopped. Production, the five disabled integrations and the earlier Artemis/ZAP issues are unchanged; nothing was pushed or deployed. See [worker operation and recovery](customer-reporting-worker.md).

### Checkpoint 53 - SQL Overview connected to customer publication and review

- Added atomic per-customer report input generations and a committed snapshot marker. Changed workflow/scans/assets/history invalidate their customer; unrelated tracked customer/bookkeeping changes no longer invalidate everyone. A mismatched older writer cannot silently mark stale output current.
- Added explicit application-database worker mode and an opt-in customer SQL Overview route. Current connector review and stored review revisions are required. Unknown source roles fail the whole build. Missing/stale/unreviewed reports produce a readable unavailable state without page-time aggregation. A capture timestamp is shown; the original full report and shared CVE patch flow remain.
- Passed 58 local tests, 33 PostgreSQL checks, ten browser groups, authenticated HTTP smoke and production/worker builds. Tested the real persistence module, binding review stores, worker CLI and SQL reader. Private fixtures only; no provider scans or real tickets.
- Read-only hashing benchmark: 40 retained customers, 972.6 MB serialized input, 10.434 seconds initial report hashing and 2 ms with unchanged cached buckets; separate existing checksums 3.075 / 3.275 seconds. Peak isolated process RSS 404 / 428 MiB. This does not measure live import latency or prove all historic source ownership.
- No production flags/configuration, database, PM2 or permissions changed; no push/deploy. See [worker enable order/rollback](customer-reporting-worker.md) and checkpoint 53 in the [platform proposal](platform-change-proposal.md).

Next is the complete published-read/customer-review cohort check, executive compatibility, authoritative writer/reverse recovery and combined release rehearsal. Burp, Nmap, Intune, IntelOwl and n8n remain available but disabled. Earlier Artemis/ZAP live failures remain open acceptance items.

### Checkpoint 54 - Published reporting capacity and retained inventory

- Added verified customer bucket maps and consecutive queue processing. Empty/small customers no longer scan all shared data; large customers still require their relevant buckets. A new explicit additive migration and fresh input publication are required before SQL reads. Invalid/old maps fail closed; source rows are retained.
- The complete published path matched every report field for retained Footprint and Atlas plus an empty fixture. Source reviews also included the retained **Tidal and Automate inventory**; omitting these correctly rejected the initial fixture. Actual customer/tenant/target ownership still needs acceptance. Fixture reviews do not approve live sources.
- Background builds: **31.628 seconds Footprint**, **22.215 seconds Atlas**, **9 ms empty fixture**. Saved SQL reads: **4.3-22.2 ms**. Three consecutive refreshes: **54.207 seconds**, peak worker RSS **247 MiB** under a 512 MiB JavaScript heap. These are historical private-database measurements, not current HTTP latency or all-customer capacity.
- **37 local tests, 36 PostgreSQL checks, full retained-report parity, production build/TypeScript and worker compilation passed.** No UI change or new browser claim. Disposable databases were removed; the private cluster was stopped. No production changes, push or deployment.
- Next: actual source-review inventory, full enabled-customer capacity, executive compatibility, authoritative writer/reverse recovery and combined-release rehearsal. The five disabled integrations and outstanding Artemis/ZAP live checks remain unchanged. See checkpoint 54 in the [platform proposal](platform-change-proposal.md).

### Checkpoint 55 - Executive report compatibility connected

- Existing executive reporting now uses a single-pass pure calculation. Every executive field matched retained Footprint and Atlas data, including their inventory contributors, configured SLA, compliance, SSVC ranking, attack-surface and financial fields. Customer email preparation remains compatible; no mail was sent.
- Isolated calculation times: Footprint **6.786 s to 1.227-1.322 s**; Atlas **2.160 s to 0.430-0.527 s**. These exclude database collection and are not live page timings. The report still reads the current RAM store; no source writer changed.
- **53 local tests**, full retained-output comparison, production build/TypeScript and separate worker compilation passed. The private cluster was stopped. No production change, push or deployment.
- Executive saved SQL reads still need policy/catalog/clock-aware freshness. The authoritative writer/reverse recovery, actual source acceptance, full customer capacity and combined rollout rehearsal remain unfinished. The existing disabled connectors and Artemis/ZAP live issues are unchanged. See [executive calculation](executive-report-calculation.md) and checkpoint 55 in the platform proposal.

### Checkpoint 56 - Saved executive reporting

- Executive and Overview outputs now share the background build, committed customer inputs, saved SLA/KEV policy and atomic publication. The opt-in executive API/print reader avoids hydration; its capture time is visible and results expire within 15 minutes.
- Full retained Footprint/Atlas/empty-cohort executive and history parity passed. The three-job cycle was 63.051 s at 264 MiB worker RSS; saved reads were 6.5-21.6 ms. Thirty-six PostgreSQL scenario groups passed. This is retained-data testing with synthetic reviews, not live tenant acceptance.
- Fresh read-only production inventory: 40 customers, 28 connector candidates. Fixed missing managed-Postgres TLS configuration in new operator/worker clients. Nessus, SpiderFoot and Vulners respond; Artemis refuses connections and ZAP times out. The rollout treatment for those services is pending the operator's decision.
- Authoritative database writes/recovery, full-customer load, actual source acceptance and combined rollout remain in progress. No production rollout occurred.
