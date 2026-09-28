# Connector Customer Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a complete, adaptive Reporting page for customers whose evidence comes from app scan connectors rather than Atlas's direct Elasticsearch and CrowdStrike dashboard sources.

**Architecture:** The app's `CO-*` company ID is the reporting key. A server-side reporting model summarizes company-scoped scans, findings, inventory, and stored history into named sections with precise measure/source/time metadata; paginated existing APIs supply detail tables. The page renders a stable shared layout with optional sections driven by observed customer evidence. Atlas adds its separately verified direct-source sections through the restoration plan.

**Tech Stack:** Next.js 16, React 19, TypeScript, PostgreSQL, Node test runner, existing `VulnShell` and CSS modules.

**Spec:** `docs/superpowers/specs/2026-09-27-connector-customer-reporting-design.md`

## Global Constraints

- Atlas (`CO-147284`) alone has direct Elasticsearch/Falcon tile sections; other customers render app connector data unless a separately verified binding is explicitly approved later.
- No report results before a customer is selected; no other customer's data in the page payload.
- Use observed per-customer scans, findings, assets, and history to select sections; global connector configuration is not customer evidence.
- Keep vulnerability, OSINT, and web-testing populations separate. Correlated findings count once overall; per-source observations may overlap.
- No zero-risk or complete-coverage claim from missing, failed, or running scans.
- Keep the existing shell, logo, navigation, dark palette, and table-oriented visual language.
- Review drafts and ticket tracking remain adjacent; ConnectWise submission remains an explicit human action.
- No production `.env` or credentials are present; read-only production sample checks are required before declaring live accuracy.

## Review Focus

- OSINT-only customer: vulnerability posture says unassessed, and OSINT total is not counted as a vulnerability. Test in Task 2.
- Nessus finding corroborated by Vulners Bridge: one overall finding, two source observations, and no double-counted total. Test in Task 3.
- Vulners cloud enrichment without Bridge scan: enrichment label appears only with stored provenance, never as an invented scan. Test in Task 3.
- A clean completed scan versus a failed scan: first can report zero observed findings, second cannot imply zero risk. Test in Task 4.
- Atlas-to-other-customer switch with delayed responses: no Atlas data enters the new customer's payload or UI. Test in Task 7.
- GCON → Openworks → Atlas switch: all common sections, source activity, details, queue, and ticket tracking change to the selected `CO-*` ID; only Atlas gains verified direct-source tiles. Test in Task 7.

---

### Task 1: Production connector inventory and report baseline

**Files:** Create `docs/reporting-connector-baseline.md` with sanitized counts and source metadata; no application code.

**Interfaces:** A reviewed table of actual customer/connector combinations, latest completed activity, store totals by class/status, history presence, asset counts, and queue counts. The report features in later tasks are checked against this baseline.

- [ ] With authorized read-only access, choose one representative non-Atlas customer per observed connector combination, including empty and failed-scan customers. Record `CO-*` IDs privately where necessary; put only sanitized identifiers/aggregates in the repo.
- [ ] Compare each sampled customer with its company page, findings list, scan list, executive report, and source import status. Note whether source rows are scans, enrichment, or asset-only data, and record the configured refresh cadence when one exists.
- [ ] Check whether any non-Atlas company has stored CrowdStrike/Elasticsearch evidence despite the stated Atlas-only scope. Quarantine and clarify any mismatch before rendering it as a customer result.
- [ ] Confirm the largest customer size and measure current reporting response time so Task 6 has a concrete performance target and test case.

### Task 2: Common metric contract and finding taxonomy

**Files:** Create `lib/reporting-metrics.ts`, `tests/reporting-metrics.test.mjs`; modify `lib/store.ts` only where taxonomy or existing report definitions must be reconciled.

**Interfaces:** `buildReportingMetrics(companyId: string, findings: Finding[], scans: Scan[]): ReportingMetrics` returns separate remediation, OSINT, and web-test totals; severity/status/KEV/SLA subsets; and explicit `assessed`, `lastObservedAt`, and `measure` metadata.

- [ ] Write failing tests for vuln-only, OSINT-only, web-test-only, mixed, no-scan, failed-scan, completed zero-finding Nessus scan, and completed zero-finding OSINT-only scan. Assert matching metric labels mean matching class/status filters across the Reporting page and `computeExecReport`.
- [ ] Run `node --experimental-vm-modules --test tests/reporting-metrics.test.mjs` and confirm the intended failures.
- [ ] Audit Nmap and ZAP imported finding shapes; explicitly classify them in `CONNECTOR_CLASS` if needed, and distinguish non-CVE service identifiers from CVEs. Retain the existing remediation rules unless the audited data requires a deliberate change.
- [ ] Define one shared open-remediation metric as `companyId` match, `Open`/`In Remediation`, and `isRemediationFinding`; OSINT is separate. Change `buildCustomerInsights` or its successor so its totals no longer contradict the executive report under the same label. Audit the executive report's annualized-loss population before choosing whether to relabel or revise it.
- [ ] Run the focused tests and existing `tests/reporting-insights.test.mjs` and `tests/reporting-consolidation.test.mjs`; commit the contract.

### Task 3: Observed source registry and provenance

**Files:** Create `lib/reporting-source-activity.ts`, `tests/reporting-source-activity.test.mjs`; modify `lib/reporting-store.ts`, `lib/types.ts`, `lib/store.ts`.

**Interfaces:** `buildSourceActivity(companyId: string, scans: Scan[], findings: Finding[], assets: InventoryAsset[]): SourceActivity[]` returns rows for sources actually observed for the customer, including scan count, completed/running/failed state, last successful observation, open finding observations, evidence kind, and freshness status.

- [ ] Write failing tests for Nessus-only, Nessus+Vulners enrichment with and without provenance, Nessus+Vulners Bridge correlation, asset-only Nmap/Intune/Tidal evidence, and a globally configured connector unused by that customer.
- [ ] Run `node --experimental-vm-modules --test tests/reporting-source-activity.test.mjs` and confirm failure.
- [ ] Build rows from company-scoped store evidence. Treat `seenBy` as source corroboration, not duplicate total findings. Add optional per-finding Vulners cloud enrichment source/time on future successful updates; do not retroactively attribute old fields. Mark verified enrichment separately from Bridge scan evidence; never derive customer use from `getConnectors().configured` alone.
- [ ] Carry observed scan/import timestamps and status. Mark stale only against a verified source cadence; otherwise display last observation without a stale verdict. If there is no reliable source timestamp, state that instead of substituting report generation time.
- [ ] Rerun tests; compare source rows for Task 1 sampled customers; commit.

### Task 4: Summary, scan, asset, and history sections

**Files:** Create `lib/reporting-customer-model.ts`, `tests/reporting-customer-model.test.mjs`; modify `lib/reporting-store.ts`, `app/api/elastic-dashboard/reporting/route.ts`; reuse `loadMetricsHistory` from `lib/persist.ts`.

**Interfaces:** `buildCustomerReportingModel(companyId: string): Promise<CustomerReportingModel>` composes Tasks 2–3 plus a bounded findings shortlist, recent scans, inventory context, and observed history. The response includes total counts and `shown` counts for every bounded list, independent section states, and no raw full finding collection.

- [ ] Write failing tests for completed zero-finding scan, failed scan, no assessment, missing history, stale history, inventory without scanned-target proof, and an OSINT-only company.
- [ ] Run the focused test and confirm failure.
- [ ] Reuse company-scoped `listFindings`, `listScans`, `listAssets`, and `loadMetricsHistory(companyId, 180)`. Keep asset inventory coverage distinct from scan coverage; do not infer a clean asset was unscanned because it has no finding. Do not reuse `InventoryAsset.openFindings` as a vulnerability-only count without class filtering.
- [ ] Return measured history points with timestamps and gaps. Avoid building a false source-specific open-finding trend from scan counts or the reconstructed 14-day series.
- [ ] Keep response size bounded; record summary latency for the largest fixture/customer and compare with Task 1 baseline. Rerun tests and commit.

### Task 5: Source-aware report workspace and empty states

**Files:** Modify `components/ReportingCustomer.tsx`, `components/CustomerScanViews.tsx`, `components/QueryDashboard.module.css`; create focused section components under `components/reporting/` for source activity, worklist, scans, assets, and optional exposure/web panels.

**Interfaces:** `ReportingCustomer` receives the selected company ID and renders `CustomerReportingModel` sections in a stable order. Optional panels render from observed evidence; the layout and headings remain consistent across customers.

- [ ] Write component/browser checks for no selection, Nessus-only, OSINT-only, web-test-only, mixed connector, empty, loading, stale, and failed states. Record the exact text that distinguishes “no findings” from “not assessed.”
- [ ] Implement the selector, freshness strip, posture metrics, severity/status view, source-activity table, findings shortlist, scan history, asset context, and optional attack-surface/web-test panels in the existing shell. Keep Atlas's separately bound direct-source panels in the same information hierarchy.
- [ ] Preserve table captions, keyboard focus, small-screen horizontal overflow/stacking, and meaningful source labels. Keep consolidation review and ticket tracking adjacent on desktop and sequential on narrow screens.
- [ ] Run browser checks at desktop and narrow widths; confirm no section invents data or displays a global connector as the customer's source. Commit.

### Task 6: Full details, filters, and consistency with the executive report

**Files:** Modify `components/reporting/` worklist/scan components, `components/VulnExecReport.tsx`, `app/api/report/[companyId]/route.ts` only as needed; extend `tests/reporting-metrics.test.mjs`.

**Interfaces:** Drilldowns retain `companyId`, class, connector, status, and severity. Existing `/api/findings` handles server-side pagination and returns `total`, `limit`, and `offset`; the Reporting page shows `shown/total` and does not download all findings.

- [ ] Write tests for 25+ findings, 12+ scans, overlapping `seenBy`, filtered totals, and same-label agreement between executive and workspace reports. Verify the selected company survives navigation to details.
- [ ] Add pagination or explicit top-N controls and correct scoped links. Do not display an executive report number beside a differently filtered number under the same label.
- [ ] For history, use the established per-company persisted snapshots where present; show “No recorded history” otherwise. If export/email remains available, ensure it uses the same metric definitions and does not imply source completeness that has not been assessed.
- [ ] Run focused tests, TypeScript/build, and a large-customer response-size check. Commit.

### Task 7: Integration with Atlas restoration and review workflow

**Files:** Modify `components/ElasticQueryDashboard.tsx`, `components/ReportingCustomer.tsx`, `components/PatchReviewQueue.tsx`, `components/PatchTicketTracker.tsx`, `lib/reporting-consolidation.ts`; add `tests/reporting-customer-switch.test.mjs`, extend `tests/reporting-consolidation.test.mjs`.

**Interfaces:** Selected `companyId` drives all common sections and the adjacent queue/tracker. The Atlas-only direct-source loader from `2026-09-27-customer-reporting-restoration.md` is independent; a connector-only customer never calls it or receives its cached results.

- [ ] Write tests for GCON → Openworks → Atlas and Atlas → GCON switches with responses arriving out of order, independent app/source failures, and correct queue/ticket scope. Assert all summary/detail/source sections change with the selected `CO-*` ID, only Atlas gets its verified direct tiles, OSINT and non-CVE service findings do not create automatic patch drafts, and valid CVE remediation findings do.
- [ ] Run the focused tests and confirm failure.
- [ ] Integrate the sections behind customer selection. Clear previous results immediately on selection change; ignore stale responses. Keep direct-source sections Atlas-only and source-verified, with no global dashboard results serialized into the customer page. Restrict automatic stored-finding patch groups to open remediation findings with valid CVE identifiers; leave excluded findings available for manual review in the worklist.
- [ ] Rerun the focused tests and review/ticket tests; commit.

### Task 8: Production reconciliation and release

**Files:** Update `docs/reporting-connector-baseline.md` with sanitized post-release comparisons; code only for defects uncovered by the gates.

**Interfaces:** A signed-off release checklist with source/metric reconciliation and rollback reference.

- [ ] Run the reporting test suite and production build; inspect desktop, narrow, and print views with safe fixtures. Compare Atlas and every Task 1 connector combination against the baseline.
- [ ] After deployment, use read-only checks to compare counts by class/status, source activity, newest scan timestamps, history, assets, and review queue for each sampled customer. Verify the app and direct-source sections fail independently.
- [ ] In the live page, select GCON, then Openworks, then Atlas; confirm each selection replaces all customer-scoped content and Atlas restores verified Elasticsearch/Falcon results plus its app and verified Falcon review drafts beside ticket tracking. Record chosen app IDs, expected source/metric values, and draft/ticket counts in the private release checklist.
- [ ] Verify empty/unassessed, failed/running scan, history gap, source-only enrichment, and customer switching in production. Check no Atlas result in a non-Atlas response or initial unselected page.
- [ ] If counts or scope fail reconciliation, revert the release while retaining the pre-change saved results and source bindings; document the discrepancy before another attempt.

## Self-review

- The connector-only page has defined data sources and UI for vulnerability, exposure, web testing, scans, assets, source activity, history, detail, queue, and empty states.
- Every section is conditional on actual company evidence, so Atlas-only sources are never a prerequisite for other customers.
- The plan separates verified code facts from production facts that still require authorized observation.
