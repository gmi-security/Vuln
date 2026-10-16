# Additional remediation worklist and action variants

## Behavior

- Keep the existing device-ranked Top fixes table.
- Add a separate, scrollable table below it, ordered by highest severity, then unique affected devices. Risk breaks ties within a source.
- CrowdStrike rows combine CVEs only when the tenant, vendor remediation ID and normalized action details match. Different target versions remain separate. Devices count once within an action.
- Platform findings without a shared vendor patch identity remain grouped within a single CVE. Matching generic remediation wording is not evidence that one patch resolves multiple CVEs.
- CVE lists expand one row at a time with 50-item pagination and open the existing customer-scoped patch-request panel. The table identifies opportunities; it does not filter out existing tickets or automatically prepare/send anything.

## Confirmed error cause

A read-only check of the completed CrowdStrike import found two remediation IDs with different action/reference versions within CVE-2026-62897. The previous consolidation keyed only by tenant/remediation ID and rejected differing serialized remediation objects.

Preparation now uses a stable SHA-256 identity over the vendor ID and normalized action metadata. Application recommendation roles do not change an action's identity. The original vendor ID is retained separately. CSVs and scores stay associated with the correct action's findings.

Matching pending legacy drafts can be reused; active legacy/variant ticket checks work in both directions and require matching action metadata, target, tenant, company and device scope. Existing tickets and other drafts are retained. Approval and manual sending remain required.

## Read path and upgrade

The existing isolated Spotlight summary worker builds the additional aggregate during its existing generation traversal. Summary model v5 stores both tables in the existing summary database. Page requests read saved summaries; they do not rescan CrowdStrike source rows, download provider data or generate ticket packets.

The old v4 Top fixes summary stays readable while v5 builds. Existing v3/v4 source-count summaries also remain readable. Publication is atomic, generation-pinned and customer-scoped. The worklist shows pending status until its matching completed-import summary exists.

The platform aggregation retains a second bounded top-50 ranking in its existing pass/cache; it does not perform another whole-platform scan. Devices across sources are not claimed to be a deduplicated estate.

## Verification

- Initial regression run: five failures reproduced the old conflict and missing new worklist.
- Full Linux suite: 1,015 passed, seven optional database tests skipped, zero failures.
- Separate isolated PostgreSQL runs: 11 customer-CVE checks, 16 summary checks, nine summary-worker checks and eight retention checks passed. Includes legacy draft reuse, distinct version preservation, old-summary compatibility, transaction rollback and scope/generation fencing.
- TypeScript, both worker builds, Linux production webpack build and local production build passed.
- Browser fixture: 13 workflow checks passed. Existing Top fixes remains visible; collapsed CVE lists mount no CVE buttons; the expanded list pages 50 then 11 entries; customer-scoped CVE preparation/review still works.
- Independent review: 47 focused tests passed; reverse legacy matching and bounded CVE rendering findings were addressed.
- Current-source read-only preparation check: CVE-2026-62897 processed 1,771 eligible findings into 13 action groups and preserved exactly 1,301 unique device/CVE pairs. CVE-2023-44487 processed 43 findings into four action groups and preserved 35 device/CVE pairs.

No live drafts or ConnectWise tickets were created during testing. Production-scale v5 summary completion and post-deployment latency must be recorded separately after release.
