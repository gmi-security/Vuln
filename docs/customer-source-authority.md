# Customer source selection and reporting compatibility

Status: offline decision model and regression fixtures on Vuln2.0. No active connector assignments, production routing, scoring or database records change here.

## Selection rules

Each customer can have several connectors. Their roles apply to a particular data domain; one connector is not automatically the owner of every fact about the customer.

| Configuration | Endpoint findings decision |
| --- | --- |
| One verified Defender source | Propose the Defender saved reader for comparison with current platform behavior. |
| One verified CrowdStrike source | Propose the Spotlight saved summary reader for comparison. |
| CrowdStrike plus Elasticsearch mirroring that same dataset | Propose CrowdStrike once. Exclude the declared mirror from combined endpoint totals; retain separately scoped query tiles. |
| Two independent vulnerability sources | Keep both observations. Require record-level identity/correlation before calculating combined counts. Never add unique-CVE or affected-device counts. |
| Duplicate primary bindings to the same origin | Require review rather than treating the duplicate configurations as independent coverage. |
| Elasticsearch with independent findings | Require a supported saved import/read contract with stable record identity and lifecycle semantics. An arbitrary ES|QL total is not an individual-finding store. |
| Inventory, web findings, exposures, enrichment or query-only data | Keep its distinct role/domain. It does not automatically become endpoint vulnerability findings or assessed coverage. |
| Selected source unavailable or newer summary pending | Report the source state and retain an appropriately labelled completed result where allowed. Do not switch to another tenant, mirror or global connection. |

`lib/customer-source-authority.ts` implements these endpoint selection checks as a pure function. It takes one explicit customer, a bounded collection of trusted scope/review evidence, and optional saved-source observations. It produces a preview with proposed sources, mirror exclusions, unselected domain evidence, issues and observation freshness. It never returns a summed platform finding count and always returns `canActivate: false`.

Supported endpoint comparison readers in this checkpoint are `defender-saved-v1` and `spotlight-summary-v1`. Other providers require their own compatible reader; this is not a claim that existing legacy connectors are unavailable. They continue operating on their current paths. The preview does not choose inventory, web, exposure or enrichment authority yet.

## Evidence and review

The input is a future trusted collector/reviewer contract, not an uploaded JSON format, active binding table, or HTTP request. A source-selection fingerprint covers customer, provider, domain, role, origin identity, mirror target, configuration fingerprint and reader. Changing those fields invalidates the recorded review. Missing configuration/source evidence, unverified customer scope, unsupported readers, and saved evidence known to use an earlier connection revision block a complete selection.

A mirror must reference a primary binding for the same customer and the same verified origin. Self references, cycles, missing targets, other-customer targets and different origins cannot establish mirror authority. That relationship must come from a reviewed source mapping; matching counts, names or CVEs is not proof of mirroring.

The function does not contact vendors or prove that a `scopeVerified` declaration is true. That evidence still needs a collector/operator verification process. Nor does an existing reviewed-but-disabled connector draft become active: no bridge from drafts or the temporary read-preview map is implemented here. Existing configuration fingerprints may not detect environment secret rotation; runtime revision/scope reconciliation is still required before activation.

Customer/source observations retain available/unavailable state, generation ID, freshness, known revision mismatch, pending summary and latest-attempt state. Unknown revision evidence remains null. “Ready for comparison” means a proposed endpoint source selection has no declared selection conflict; it is not proof of fresh data, full coverage, numerical parity or production readiness.

## Why the current platform and saved source counts differ

The existing source adapters and platform reporting answer different questions. Replacing the report's number with a faster source count would change behavior unless these differences are preserved or explicitly reviewed.

| Case | Saved source view | Current platform behavior | Required migration treatment |
| --- | --- | --- | --- |
| Software-instance duplicates | Defender counts device/CVE/software-version instances; the saved view also supplies grouped device/CVE counts. Spotlight retains its own source-finding units. | Publication/correlation operates on grouped findings. | Preserve original instances and grouped identity separately. Compare like units. |
| Device disappears or is offline | Latest import may contain no finding for the device. | `planDefenderProjection` retains the prior finding when there is no sufficiently recent device heartbeat to support closure. | Keep observation absence distinct from verified resolution. A zero source result must not auto-close retained findings. |
| Analyst accepts risk | Source can continue to report the vulnerability. | Existing status and assignee survive publication; reporting open totals include Open and In Remediation, not Risk Accepted. | Preserve workflow state separately from source presence. |
| More than one scanner reports a CVE | Each source has its own severity and remediation. | Correlation can retain the more severe assessment and source provenance. Defender cannot resolve evidence still retained by another scanner. | Preserve source observations, merged finding identity and versioned assessment policy. Do not overwrite GMI risk with one source's CVSS. |
| Web findings | Endpoint CVE summaries do not include scanner-specific web findings. | `buildReportingMetrics` includes web findings in its remediation/open vulnerability total, while also reporting web findings separately. | Explicitly name and reconcile endpoint, web and combined remediation metrics before replacing existing tiles. |
| OSINT exposure | Not an endpoint CVE observation. | SpiderFoot/Artemis are separated into attack-surface counts. | Keep exposures separate; do not turn an inventory or exposure count into vulnerability assessment coverage. |
| Missing severity or CVSS | Saved source readers preserve unknown severity and nullable CVSS. | Defender projection currently maps unrecognized severity to Info and missing numeric CVSS to zero for the legacy finding shape. | Retain original evidence; review any display/score semantic changes separately. |

The relevant current implementations are `lib/defender-projection.ts`, `lib/finding-correlation.ts`, `lib/reporting-metrics.ts`, `lib/reporting-customer-model.ts`, and the Open/In Remediation filter in `lib/store.ts`. No changes to those functions are part of this checkpoint.

Device identity also requires care. The legacy general correlation graph uses customer-scoped aliases; Defender's projection additionally uses stable device IDs and constrained hostname corroboration. These are existing policies, not proof that arbitrary equal hostnames/IPs identify the same device. A new model must measure the effect of its identity rules, preserve proven mappings and avoid silently merging or splitting findings/tickets.

## Verification and next step

Nine decision-model tests cover single-source proposals, mirror exclusions and invalid mirrors, multiple scanners, duplicate origins, review invalidation, separate domains, unsupported readers, unavailable/stale observations, known connection mismatch and customer isolation. Six additional tests execute the actual legacy projection and reporting functions with synthetic records to reproduce offline-device retention, accepted-risk exclusion, stricter corroborating severity, other-source closure protection, web-versus-OSINT totals and distinct Defender devices sharing a hostname/IP.

These fixtures prove the behavior of those code paths, not customer-by-customer production parity. The next comparison must pin retained source generation IDs and the published platform snapshot together, classify differences by source identity, grouping, workflow status, observation freshness and assessment policy, and verify the scoped risk/ticket references before changing any readers. Start on the private restore with bounded reads; do not run an unrestricted whole-database comparison in the production web process.
