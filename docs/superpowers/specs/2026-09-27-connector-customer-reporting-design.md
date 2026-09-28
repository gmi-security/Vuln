# Connector customer reporting design

## Purpose and scope

The Reporting page must produce a useful report for every selected, non-demo client even when that client has no Elasticsearch or direct CrowdStrike dashboard connection. Atlas (`CO-147284`) alone has the separately saved Elasticsearch and Falcon tile sections. All customers, including Atlas, can have findings, scans, asset inventory, and review work in the app store. The report must adapt to the data actually observed for the selected `CO-*` company, not to globally configured connector credentials.

This is one reusable Reporting page, not a separately coded page per customer. The selector resolves the chosen app company's `CO-*` ID, and every summary, detail request, source panel, queue, and ticket list is scoped to that ID. A customer's name is display text, not a routing key. Atlas's ID is used only to enable its additional verified direct-source bindings; the common report uses the same path as every other client.

This design complements `2026-09-27-customer-reporting-restoration-design.md`. It covers the common report and the connector-only experience. It does not infer that a customer uses a connector merely because the integration is configured for the organization.

## Verified model and gaps

- `Company`, `Scan`, `Finding`, and `InventoryAsset` already carry `companyId`; `Finding.seenBy` records corroborating connectors; `Scan` carries status, timestamps, `findingsCount`, and `hostsScanned` (`lib/types.ts`). The app store persists its state through `DATABASE_URL` (`lib/persist.ts`).
- `reportingCustomer` currently uses `computeExecReport`, `listFindings`, and `listScans` (`lib/reporting-store.ts`). `buildCustomerInsights` currently counts *all* open findings, then emits top 25 findings and latest 12 scans (`lib/reporting-insights.ts`). Its source rows count a corroborated finding once under each observing connector.
- `computeExecReport` uses `computeMetrics`, whose vulnerability posture excludes OSINT (`lib/store.ts`). Thus the report's top “Open findings” card can disagree with the “Scans and findings” total today even with correct data. The former is remediation findings; the latter currently includes OSINT. This requires a metric-contract fix, not a cosmetic relabel.
- `computeExecReport` also estimates annualized loss (`financial.ale`) from all open findings, including OSINT, while its posture totals exclude OSINT. Decide and document the financial model's population before showing the estimate beside vulnerability-only numbers; do not silently change historical projections.
- The app distinguishes `vuln`, `osint`, and `pentest` via `findingClass`; `CONNECTOR_CLASS` currently defaults unmapped connectors to `vuln`. Burp is `pentest`, SpiderFoot/Artemis are `osint`, but ZAP and Nmap lack an explicit class mapping. Confirm their intended treatment against their imported findings before changing the mapping; never count synthetic service identifiers as CVEs.
- Nessus imports scans and plugin findings; Vulners cloud enriches existing CVEs without creating an independent scan, whereas Vulners Bridge creates scans/findings (`lib/store.ts`). Defender is a vulnerability sync; SpiderFoot/Artemis contribute exposure findings; Burp/ZAP contribute web-app test findings; Nmap contributes asset/port evidence and risky-service findings. Qualys is marked planned in `lib/connectors.ts`.
- Vulners cloud currently changes EPSS/CVSS/exploit fields in place without storing a per-finding enrichment source or timestamp. Historical enrichment cannot be asserted for a specific customer from the present model. Record provenance for future updates; label older enriched values as unknown source unless independent evidence exists.
- `listAssets({companyId})` can supply inventory rows, but the current `companyCoverage` logic treats an asset as scanned when it appears in a finding. A clean scan can have no finding, so that figure must not be labeled as a measured scan-coverage percentage without a different denominator/evidence source.
- `InventoryAsset.openFindings` currently counts all open classes matched to that asset. In a vulnerability-only asset table, recompute/count only remediation findings or label the broader population explicitly.
- Per-company `vuln_metrics_history` snapshots exist and `/api/report/[companyId]` already reads 180 days (`lib/persist.ts`, `app/api/report/[companyId]/route.ts`). `computeMetrics` also constructs a 14-day apparent trend from first-seen/resolved dates. The report should favor persisted observations for an actual time series and label gaps rather than present reconstructed history as measured snapshots.
- `buildStoredFindingGroups` currently groups every open finding by `cve` and remediation text without checking finding class or whether the identifier is a real CVE (`lib/reporting-consolidation.ts`). That can produce automatic patch drafts from OSINT or non-CVE service findings. Require a valid CVE and remediation-eligible class for automatic patch grouping; retain other findings in the report for manual triage.
- The current `/api/findings` supports `companyId`, `kind`, `connector`, `status`, `severity`, search, offset, and `total`, with a maximum page size of 1,000. The report's detail links must keep the selected company and class/filter. The reporting summary must not transmit all finding rows.

## Data contract

One selected-company summary should return these sections, each with `status` (`ready`, `empty`, `unavailable`, `stale`, or `loading` in the client), an observation timestamp where the source has one, and a source explanation. Mark a source `stale` only when its verified expected cadence or freshness policy is known and the last successful observation exceeds it; otherwise display the observation time without inventing a universal expiry:

1. **Customer header:** app ID/name, report generation time, latest completed scan/import per source, and a clear overall freshness notice. Generation time is not presented as scan time.
2. **Vulnerability posture:** actionable open/in-remediation findings, Critical/High, KEV/exploitable counts, severity and status distributions, asset impact, and risk/SLA priorities. A correlated company/CVE/asset finding counts once in the overall total; connector observation counts can overlap and must say so. Risk and exposure scores are bounded 0–100 indexes, not finding totals.
3. **Source activity:** one table row per *observed* connector with scan/import type, latest completed activity, running/failed scan state, number of recorded scans, count of observed open findings, and source-specific data quality. A Vulners cloud enrichment badge appears only when stored provenance proves it; Vulners Bridge appears as a scan when a scan record exists. Globally configured but unused integrations do not appear as customer data.
4. **Findings worklist:** table with finding/CVE or source identifier, title, asset, severity, real risk, status, source evidence (`seenBy`), last seen, and review link. Server-side pagination and filters by class, connector, severity, status, and text. Never imply the first 25 are the full population; preserve a readable top-priority shortlist if useful.
5. **Scans:** latest completed, running, and failed scans with targets/hosts when stored, source, completion date, and imported finding count. Distinguish a failed/unfinished scan from zero findings. Link to the selected scan details.
6. **Assets and context:** known inventory count, source provenance, top affected assets, criticality/exposure where recorded, and unknown-context count. Inventory coverage means the share of relevant findings using authoritative context, not the percentage of assets scanned. Do not offer an asset scan-coverage percentage until scan-target evidence supports it.
7. **Attack surface:** SpiderFoot/Artemis exposure totals and top exposed assets/issue categories, only when such findings exist. Keep separate from actionable vulnerability totals. Nmap ports/services may appear as discovery evidence; risky-service findings use the class established by the taxonomy audit.
8. **Web testing:** Burp/ZAP issues, affected applications, last test, and prioritized remediation when recorded. Do not show a web-testing panel for customers without this evidence.
9. **History:** observed per-company metrics snapshots with timestamp and gaps, not a fabricated chart. No history yields a useful empty state and current metrics remain available.
10. **Review and tickets:** table-oriented consolidation queue and adjacent ticket tracking scoped to the same customer. Generate automatic patch drafts only for remediation-eligible, CVE-identified open findings; keep OSINT and non-CVE issues in the findings worklist for manual triage. Inspect saved draft details and require human approval before ConnectWise creation. No direct Falcon/Elastic dependency for connector-only customers.

The API must define exact metric names and filters in one place. The executive report, Reporting page, downloadable report, and queue should use the same definition where they show the same label. The current executive report includes financial and compliance projections; those remain separately labeled estimates/framework calculations and should not be fabricated from absent source observations.

## Page layout and interaction

Use the existing `VulnShell` navigation, logo, dark palette, typography, and compact table language. Preserve the same order and layout for Atlas and other customers; optional source sections appear only where there is verified data. Suggested order:

1. Customer selector and last-observed-source strip; no results before selection.
2. Four to six primary posture metrics with source/measure descriptions. In the absence of vulnerability findings, show a truthful zero only when a completed relevant scan exists; otherwise show “No vulnerability assessment recorded.”
3. Vulnerability distribution and trend (when measured), followed by source activity table.
4. Filterable findings worklist and scan history.
5. Optional attack-surface, web-testing, asset-context, and Atlas direct-source sections.
6. Consolidation review queue and ticket tracker side by side on wide screens, stacked in sequence on narrow screens.

The source activity table is the main adaptation mechanism; the page should not swap to an unrelated design per customer. Source badges identify evidence, not decoration. Empty, loading, stale, and failed states belong to each section so one slow connector cannot blank the whole report. Switching customers must clear the old customer's visible data immediately and ignore late responses. Keyboard navigation, headings, table captions, contrast, focus indicators, and readable narrow-screen tables are required.

## Customer examples to validate

| Customer data | Expected report |
| --- | --- |
| Atlas with app scans plus verified Falcon/Elasticsearch tiles | Common report, then both preserved direct-source sections with their distinct counting rules and timestamps. |
| Nessus-only customer | Posture, source activity, findings, scans, assets/history where present; no Elastic/Falcon section. |
| Nessus plus Vulners cloud enrichment | One underlying finding population; show Vulners enrichment only when new provenance records prove it, and do not invent a second Vulners scan or double-count the total. |
| Vulners Bridge plus Nessus | Both observed scan sources, one correlated total, per-source observation counts that may overlap. |
| SpiderFoot/Artemis only | Attack-surface findings and activity; vulnerability posture marked unassessed rather than “all clear.” |
| Burp/ZAP only | Web-testing issues and test activity; no claim of network vulnerability scan coverage. |
| Company record with no scans/findings | Customer identity, no-assessment state, available known inventory if present, empty review queue; no zero-risk/100% compliance claim. |
| Failed or running scan | Visible scan state and last successful observation; no “zero findings” inference. |
| Switch GCON → Openworks → Atlas | The same page replaces all summary, source, detail, queue, and ticket content on each selection. GCON and Openworks each show only their own observed connector data; Atlas shows its app data, verified Elasticsearch/Falcon sections, and its saved review queue from both app and verified Falcon drafts. No prior customer's values flash or persist. |

## Validation and release gates

- Inspect a read-only production sample for at least one non-Atlas client per actually used connector combination; record counts, timestamps, and expected refresh cadence where configured, without exposing customer data in repository fixtures.
- Reconcile `CO-*` totals against `/companies/<id>`, `/findings?companyId=<id>`, scan history, and `/api/report/<id>` after agreeing the metric class and status filters. Explain source observation overlap.
- Verify all four customer data states (data, no data, stale, source failure) and switching between Atlas and a connector-only customer.
- Measure summary latency with the largest customer; keep detail fetching paginated and avoid requesting all finding rows in the browser. Do not make global direct-source dashboard storage a prerequisite for connector-only report rendering.
- Verify no Atlas tile appears in a non-Atlas page payload or customer API response, and no unselected customer result is serialized into the initial HTML.
- Preserve review/ticket approval and ConnectWise routing safeguards; validate draft counts before/after deployment.
