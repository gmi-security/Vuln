# Reviewed customer routing for ZAP and the Vulners bridge

Development on `Vuln2.0` only. No production setting, source import, remote scan, ticket or deployment was used for validation.

## How the routing works

```text
Existing source configuration + existing customer ID
  -> reviewed source binding and exact targets
  -> separate audited scanner approval
  -> explicit provider switch at the reviewed release
  -> check approval and launch a scoped remote job
  -> wait for actual completion; validate returned evidence
  -> recheck current approval before adding/updating customer findings
  -> existing reporting, scoring and ticket preparation
```

The existing customer selector, scan permissions, manual/scheduled launch entry points and platform store remain. Review alone does not activate a connector. The same `customer_scanner_routes` and audit service used for Nessus/OSINT now accepts `zap` and `vulners`. `VULN_REVIEWED_SCANNER_PROVIDERS` is still empty by default; approved names must be explicitly added at release. Removing a name restores legacy routing and is not emergency revocation.

| Provider | Reviewed scope | Restrictions |
| --- | --- | --- |
| ZAP | Whole HTTP(S) origins in `targets`, such as `https://app.example` | Scheme, host and port are significant. No credentials, paths, query strings, fragments or wildcards in approved roots. One origin can belong to only one customer in this shared ZAP instance. Path-shared customer applications are not supported by this routing contract. |
| Vulners bridge | Exact hostnames or IP addresses in `targets` | No URL, network range or wildcard. Each normalized target can belong to only one customer in the configured bridge. Hostname results that return only an unrelated IP cannot be accepted as equivalent without independently reviewed identity evidence; use verified explicit IP targets where appropriate. |

Both use `tenantId: null`, `authority: "findings-primary"` and empty `datasets`. The source-scope value is a digest of normalized approved targets. One binding per customer/provider is supported. Overlapping sets are rejected inside the approval transaction, even when the overall target-set digests differ. Different providers retain separate source roles; this does not settle primary/mirror authority across overlapping vulnerability feeds.

## ZAP behavior

Each reviewed launch creates its own context, includes only the approved origin with an anchored escaped URL pattern, and passes that context to both spider and active scan calls. The existing gateway `Host: zap` header and API key remain required. Configuration is pinned to the run; redirects from the API endpoint are rejected. The scanner's context is an application scope control, not a network firewall or independent proof of domain ownership.

Spider and active scan IDs must be valid and progress must be an integer from 0 through 100. Polling exhaustion is a failure, not completion, and an unfinished crawl cannot start the active scan. The existing polling budgets remain: 60 crawl polls and 120 active-scan polls, with five-second intervals. Source request times and approval checks add to elapsed time.

Report selection compares parsed origins exactly. It cannot match `app.example.evil`, a different scheme or another port. Every selected alert must have instance URL evidence within the selected origin; a missing target site or conflicting evidence withholds that target's results. Other sites in the shared report are ignored. Legacy report filtering also now uses exact origin comparison instead of loose string prefixes.

**The JSON report is retained ZAP session evidence, not a fresh per-job snapshot.** It can include older active/passive alerts for the approved origin; reviewed findings state that in their description. Successful collection means the requested crawl/active phases completed and scoped report evidence was obtained, not that every passive task, authenticated page or web test completed. No old ZAP findings are automatically resolved from an empty report. Before ownership changes, operators must reconcile retained source-session evidence as well as historical platform ownership.

A context is removed only after a completed scan and a validated report. Failed or uncertain launches leave source context/job evidence for operator inspection. The application does not automatically retry or cancel uncertain remote jobs. Deployed ZAP API permissions, context behavior and report fields still need live acceptance; the earlier ZAP timeout remains unresolved.

## Vulners bridge behavior

The preferred complete credential pair is `GMI_SCANNER_URL` / `GMI_SCANNER_API_KEY`; otherwise the complete `VULNERS_BRIDGE_URL` / `VULNERS_BRIDGE_API_KEY` pair is used. A URL from one deployment is never combined with the other deployment's key. Source review fingerprints both configured endpoints and the selected deployment mode, so adding the preferred key can invalidate a review without storing the key itself. Secret-only rotation within the same mode is not registry versioning; running reviewed jobs additionally compare their pinned configuration before publishing.

Reviewed create/start calls use one approved target. Approval is checked again between creation and start. Polls and result reads remain on that pinned configuration, validate the returned job identity and completion before/after collection, and check every raw finding's host and CVE/score shape. Missing findings arrays, known truncation markers, inconsistent totals or more than 10,000 raw rows are rejected. Malformed findings arrays fail in legacy mode too, rather than appearing as a clean scan.

**Full bridge-report completeness is not yet proven against the deployed API.** These checks use the existing repository's create/start/status/findings contract and synthetic responses. They cannot detect undisclosed server-side caps. Reviewed imports therefore add/update findings but do not automatically resolve prior bridge findings. Verify deployed pagination/total/completion semantics before restoring closure reconciliation. Existing legacy closure behavior is retained for valid legacy results.

The bulk inventory sweep selects only targets assigned to the asset's approved customer and rechecks approval for each job and result. An unapproved customer cannot win through insertion order. In legacy mode, a literal inventory IP claimed by different customers is withheld rather than assigned to the first customer. The Nessus-offset scheduler and manual bridge paths already call the same guarded `startScan` function.

Cloud Vulners CVE enrichment remains independent. A cloud-only configuration cannot approve active bridge scanning; this change does not alter the existing enrichment cadence, threat scores or enrichment consumer routing.

## Failures, controls and storage

ZAP and bridge jobs now report failed targets explicitly, count only completed targets and retain successful independent target results. A partial job is marked `Failed` with completion/failure counts, rather than reporting a successful zero-finding scan. Stale approvals, source configuration changes and removed customers withhold results. These checks do not cancel already-running remote work or implement a distributed writer fence.

Pause/resume/stop previously changed only local state for these remote jobs. They now return a clear unsupported-control message directing the operator to the scanner console. Active local records cannot be deleted or relaunched through the page. Rescan creates a real new job through `startScan`, checking current routing and keeping the earlier scan record. Inspect uncertain remote jobs before retrying a locally failed job. A process restart can still interrupt these in-process workers; durable job recovery is not added here.

Application `DATABASE_URL` stores source drafts/bindings, `customer_scanner_routes` and `customer_scanner_route_audit`. Findings, scan records and workflow state still use the existing platform store/snapshot persistence. No normalized SQL writer cutover occurs in this checkpoint. Existing data, saved tiles, history, ticket references, source classifications, scores and role permissions are retained.

## Eventual migration and rollback

Do not activate production routing from this document alone.

1. Preserve recovery evidence and drain imports, scans and automatic launchers. Reconcile outstanding remote jobs.
2. Install the existing draft/binding migrations, [scanner routes](sql/customer-scanner-routes.sql), [OSINT extension](sql/customer-scanner-osint-routes.sql), then the additive [active-scanner extension](sql/customer-scanner-active-routes.sql). Existing approvals/audits remain; no new approvals are populated.
3. Import fresh registry evidence and independently verify each customer target and deployment. Use the existing binding assignment and `route-scanner` / `export-scanner-routes` commands in the [scanner guide](customer-scanner-routing.md). Operational approval input still has exactly `candidateId`, `companyId`, `bindingRevision`, `expectedRevision`, `enabled` and `note`.
4. Complete actual source acceptance, including connectivity, permitted context/scan actions, job identities, filtering, report limits and retained-history ownership. Add the reviewed provider names only in the approved release configuration.
5. Roll back with drained operations and a reviewed compatible build. Preserve source/platform data and route/audit records. Older code ignores these approvals; reverting to its legacy routing is not automatically safe for the new ownership assignments.

## Validation and remaining work

**238 distinct local tests** passed: 233 in the broad regression run and five bridge authentication/status regressions. The latter test now uses the same VM TypeScript resolution as other application fixtures because the adapter gained a scope-module dependency. **43 isolated PostgreSQL groups** passed (16 scanner, 10 binding, nine inventory, eight Spotlight), including preservation of prior migrations, approval conflicts, audits and deployment changes. All disposable databases were removed and the private recovery cluster stopped. **Nine browser groups**, a visual check of the mobile connector status, and the production build/TypeScript checks passed. Every source response was synthetic; no real remote action occurred.

ZAP parameters were checked against the official [ZAP API reference](https://www.zaproxy.org/docs/api/) and [Spider API definition](https://github.com/zaproxy/zaproxy/wiki/ApiGen_spider). These documents do not establish the deployed gateway version, permissions or health. Bridge payload checks are grounded in the existing adapter and its recorded-response fixtures, not a new live contract inspection.

Next: customer-scoped saved FQL/patch consumers and source authority, live scope/connector verification, SQL reporting integration and authoritative writer handoff, then the combined release/recovery rehearsal. Artemis and ZAP still need live connectivity resolution. Burp, Nmap, Intune, IntelOwl and n8n remain available but disabled.
