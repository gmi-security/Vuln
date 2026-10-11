# Executive report calculation

## Implemented locally

`lib/executive-report.ts` calculates the existing executive report in a single pass over findings, followed by scans and inventory. `computeExecReport` in `lib/store.ts` calls it after the existing scan-state tick and customer lookup. Its exported type and response remain compatible with the report API, reporting page and customer email preparation.

The accumulator has no application-store import, SQL, provider request, scheduler, email or ticket write. It retains five ranked rows and distinct remediation/exposure asset identifiers. Memory therefore grows with distinct assets, not a full copy or sort of every finding. The current runtime still iterates the existing RAM store; this change does not eliminate hydration or make executive reports SQL-only. The independent reporting worker build now compiles the pure executive module, but its jobs do not yet store or serve this report.

## Preserved behavior

| Input or rule | Existing behavior retained |
| --- | --- |
| Customer | Only the requested customer contributes; public company output includes id, name and industry |
| Findings and severity | Open and In Remediation remediation findings; OSINT excluded from these counts |
| SSVC and top risks | Existing decision and due-date functions; decision, overdue, real risk and days-left order; stable ties; all findings counted before the top five are selected |
| SLA | Configured severity thresholds; Info has no overdue clock; exact deadline boundary preserved; MTTR uses findings resolved during the last 90 days |
| Coverage in composite score | Historical remediation finding assets match inventory identifier, hostname or IP aliases; OSINT-only observations do not establish coverage |
| Compliance | Existing framework evaluators and scan-age behavior, including completed timestamps on failed/stopped scans |
| KEV | Most report sections use saved finding flags; compliance uses the catalog lookup supplied by the caller, as it did previously |
| Financial estimate | Existing severity loss assumptions and annual-rate formula, including open OSINT in this legacy estimate |
| Attack surface | Existing non-Resolved OSINT scope includes accepted/false-positive exposures; categories and unique exposed assets retained |
| Report timestamps | Calculation uses one explicit observation time. API/email callers still set generatedAt as before |

These are compatibility rules, not an endorsement of the existing compliance or financial assumptions. Any change to those meanings should be explicit and reviewed separately. The single observation time avoids sections crossing different SLA boundaries during a long calculation; all policy comparisons are made against that same time.

## Verification

The frozen pre-refactor orchestration is in `tests/fixtures/legacy-executive-report.ts`, based on `store.ts` at `66c3655`. It calls the unchanged legacy metrics, priorities, attack-surface and compliance implementations as an independent reference. Tests run real application code inside a fixed-time VM with no credentials, provider calls or timers. Cases include every provider class, workflow states, more than 5,000 open findings, exact SLA/MTTR boundaries, source flag/catalog disagreement, inventory aliases, cross-customer rows, ties, missing customers, metadata minimization and email preparation without delivery.

On the read-only October 9 retained snapshot, all executive output fields matched for both customers at the same observation time, retained SLA policy and offline catalog context:

| Customer cohort | Platform findings | Open remediation findings | Legacy calculation | Connected calculation, three runs |
| --- | --- | --- | --- | --- |
| Footprint: Defender; Defender/Tidal/Automate inventory | 288,878 | 215,891 | 6.786 s | 1.227, 1.263, 1.322 s |
| Atlas: CrowdStrike/SpiderFoot; CrowdStrike/Automate inventory | 80,302 | 80,000 | 2.160 s | 0.527, 0.430, 0.433 s |

Timings exclude SQL collection and do not represent production HTTP/browser latency. The comparison process retained reference data and both calculation paths and peaked at 710 MiB RSS; this is not a measurement of isolated accumulator memory or a new production heap requirement. No claim is made about the freshness/completeness of the retained source records or current vendor threat intelligence. No mail or ticket was sent.

## Still required for saved SQL executive reports

1. Publish executive-specific input revisions for the required finding, inventory-alias, company-industry and scan fields. The existing Overview input digest omits several of these fields and must not be reused unchanged.
2. Include configured SLA policy and a durable, identified KEV catalog snapshot in report freshness. An in-memory catalog callback alone is insufficient for a saved report worker.
3. Define saved observation time and expiry for SLA deadlines, rounded days-left ranking, scan age and the 90-day resolution window. Source-record changes alone do not cover these clock-driven changes.
4. Save complete executive reports atomically, check current customer/source review, then opt customers into the reader with explicit stale/missing behavior and a reversible flag.
5. Verify report API, printable/browser output and email packet compatibility against the same committed generation before enabling that read path.

The authoritative normalized database writer/reverse recovery, actual source ownership approvals, full customer capacity and combined rollout rehearsal remain separate outstanding release requirements. No production setting or data changes are needed to review this local calculation change.
