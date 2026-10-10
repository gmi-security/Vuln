# Vuln2.0 connector rollout status

Updated October 10, 2026. Development branch: `Vuln2.0`. Production was not deployed, restarted or reconfigured by these checks.

## What is complete in this connector pass

- All 20 integration types have a documented data role, storage path, native identity and lifecycle contract.
- Customer assignment review handles scanner, inventory, enrichment, query and AppSec roles independently. Wrong-customer, stale and unsupported assignments are rejected. Shared connections can have separate customer scopes.
- Changes to non-secret endpoint, tenant/client/cloud and AppSec stream settings invalidate old reviews. Credential values are neither copied nor displayed.
- Defender saved reads enforce reviewed tenant and connection/import revision. CrowdStrike saved reads enforce whole-generation CID evidence, using summary model v3, with exact local unresolved placeholders accounted for separately.
- Customer Connectors shows how each source is used, without adding a second customer selector or configuration permissions.
- Automate, Intune, Tidal and CrowdStrike host inventory now have optional runtime routing by reviewed vendor identity. A separate audited approval and provider switch are required; review alone never activates an import. These paths were tested with fixtures and remain off in production; Intune remains disabled. CrowdStrike Spotlight findings still need their own consumer handoff.
- Malformed Nessus, SpiderFoot, Artemis and ZAP import responses now fail instead of appearing empty. Intune and Automate reject truncated/malformed inventories; Intune pagination cannot send its token to another origin; Automate rejects invalid customer filters and explicitly conflicting customer IDs in returned rows.
- Existing reporting classifications, customer isolation, source-specific counting and manual patch packet behavior have regression coverage. Inventory and OSINT do not become patchable vulnerability counts. Tidal now reports failed/truncated roster and device pages, preserves separate customer sessions and retains its explicit partial-source error reporting. Artemis rejects truncated task-result imports. Tidal's existing first-page 400/403/404 unavailable-integration convention remains unchanged and does not prove absence of devices.

This completes the implemented connector catalog, review contracts and this regression pass. It does **not** complete live customer assignment activation or the authoritative platform database migration. Other source/scanner consumers still use their legacy customer-routing paths. The common review checker is not an upstream API filter or an authorization layer for those importers. The four inventory consumers explicitly enforce their supported reviewed scopes only when opted in.

## Connector-by-connector status

"Configured" means configuration evidence exists, not that every request or customer scope is verified. The read-only inventory found 40 customers and 14 configured integration types. Configuration came from saved database metadata and the server environment file, not an attestation of the running PM2 environment. Historical source pointers and shared credentials alone do not establish current customer ownership.

| Connector | Data role | Evidence in this pass | Rollout state / remaining requirement |
| --- | --- | --- | --- |
| Microsoft Defender | Device/software vulnerabilities and inventory | Configured; saved SQL revision guard, import, risk and customer reporting fixtures | Preserve existing publication. Final authoritative SQL writer migration remains separate |
| CrowdStrike | Spotlight findings, device inventory, FQL results | Configured; saved generation CID guard plus optional CID-verified host import routing | Host inventory now enforces reviewed connection/CID/customer. Spotlight, FQL and patch consumers still need separate routing checks; live scope verification and activation remain pending |
| Elasticsearch | Customer-owned queries and cached results | Configured; saved tile ownership/revision and scanner-export regression checks | Preserve tiles; review datasets and CS mirrors before making any findings-authority decision |
| Nessus | Scan findings and scanned-host coverage | Configured; status reachable; real parser fixtures include clean hosts and multi-CVE plugins | Ambiguous folder names and conflicting saved scan ownership now block import. Review target mappings; no scan launched |
| Vulners | Bridge scan findings and CVE enrichment | Configured; status reachable; bridge auth, targets and job fixtures | Status is not proof of every bridge or API permission; review each deployment/target mapping |
| SpiderFoot | OSINT and attack-surface exposure | Configured; status reachable; event import, false-positive and malformed-response fixtures | Tied legacy name matches now skip import. Review target mappings; an unambiguous name remains a heuristic, not verified ownership |
| Artemis | Attack-surface observations | Configured; mapping, import completeness and scope fixtures; live status connection refused | Remote service/network must be repaired and rechecked |
| ZAP | Web findings | Configured; report/scope fixtures; live status timed out | Remote service/network must be repaired and rechecked |
| Tidal | Customer/device inventory | Configured; reviewed portal-company routing, actual adapter/session and CSV bypass checks | Runtime enforcement implemented behind empty switch. Verify live company IDs before activation. Reviewed mode requires live sync; name-only CSV is rejected |
| ConnectWise Automate | Customer/device inventory | Configured; actual adapter and import fixtures, reviewed client-ID routing, SQL approval/revocation checks | Runtime routing implemented behind an empty provider switch; live ownership review and activation pending. No live inventory pull |
| MISP | CVE threat enrichment | Configured; actual adapter response/failure and enrichment-role tests | Preserve existing signals; a sighting is not independently verified exploitation |
| OpenCTI | CVE threat enrichment | Configured; actual adapter response/failure and enrichment-role tests | Preserve existing signals; relationship presence alone does not prove exploitation |
| AppSec / Trivy via Elastic | Repository scans, findings and deltas | Configured; summary/trend result fixtures and dataset/repository review checks | Existing organization AppSec path retained; customer-scoped AppSec reader not activated |
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
